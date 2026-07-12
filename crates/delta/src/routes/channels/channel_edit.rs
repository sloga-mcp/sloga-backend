use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    voice::{delete_voice_channel, UserVoiceChannel, VoiceClient},
    Channel, Database, File, PartialChannel, SystemMessage, User, AMQP,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Edit Channel
///
/// Edit a channel object by its id.
#[openapi(tag = "Channel Information")]
#[patch("/<target>", data = "<data>")]
pub async fn edit(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataEditChannel>,
) -> Result<Json<v0::Channel>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let mut channel = target.as_channel(db).await?;

    // Threads delegate their permission calculus to the parent text channel;
    // resolve it BEFORE constructing the query. A thread's creator may edit
    // their own thread without ManageChannel.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;

    let is_own_thread = matches!(&channel, Channel::Thread { creator, .. } if creator == &user.id);
    if !is_own_thread {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
    } else {
        // Thread creators still need to be able to view the parent channel.
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    }

    if data.name.is_none()
        && data.description.is_none()
        && data.icon.is_none()
        && data.nsfw.is_none()
        && data.owner.is_none()
        && data.voice.is_none()
        && data.slowmode.is_none()
        && data.archived.is_none()
        && data.tags.is_none()
        && data.require_tag.is_none()
        && data.default_sort.is_none()
        && data.applied_tags.is_none()
        && data.remove.is_empty()
    {
        return Ok(Json(channel.into()));
    }

    // Forum configuration fields only ever apply to forum channels; reject
    // them anywhere else (mirrors the group-only owner rejection below)
    // instead of silently dropping them.
    if (data.tags.is_some() || data.require_tag.is_some() || data.default_sort.is_some())
        && !matches!(channel, Channel::Forum { .. })
    {
        return Err(create_error!(InvalidOperation));
    }

    // Applied tags only make sense on forum-post threads.
    if data.applied_tags.is_some() && !matches!(channel, Channel::Thread { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    // The shared DataEditChannel validator allows names up to 100 characters
    // so forum post titles stay editable; every other channel type keeps the
    // 32-character limit.
    if let Some(name) = &data.name {
        let is_forum_post = matches!(&channel, Channel::Thread { .. })
            && matches!(&permission_channel, Channel::Forum { .. });
        if !is_forum_post && name.chars().count() > 32 {
            return Err(create_error!(FailedValidation {
                error: "name: length must be at most 32".to_string(),
            }));
        }
    }

    let mut partial: PartialChannel = Default::default();

    // Transfer group ownership
    if let Some(new_owner) = data.owner {
        if let Channel::Group {
            owner, recipients, ..
        } = &mut channel
        {
            // Make sure we are the owner of this group
            if owner != &user.id {
                return Err(create_error!(NotOwner));
            }

            // Ensure user is part of group
            if !recipients.contains(&new_owner) {
                return Err(create_error!(NotInGroup));
            }

            // Transfer ownership
            partial.owner = Some(new_owner.to_string());
            let old_owner = std::mem::replace(owner, new_owner.to_string());

            // Notify clients
            SystemMessage::ChannelOwnershipChanged {
                from: old_owner,
                to: new_owner,
            }
        } else {
            return Err(create_error!(InvalidOperation));
        }
        .into_message(channel.id().to_string())
        .send(
            db,
            Some(amqp),
            user.as_author_for_system(),
            None,
            None,
            &channel,
            false,
        )
        .await
        .ok();
    }

    match &mut channel {
        Channel::Group {
            id,
            name,
            description,
            icon,
            nsfw,
            voice,
            ..
        } => {
            if data.remove.contains(&v0::FieldsChannel::Icon) {
                if let Some(icon) = &icon {
                    db.mark_attachment_as_deleted(&icon.id).await?;
                }
            }

            for field in &data.remove {
                match field {
                    v0::FieldsChannel::Description => {
                        description.take();
                    }
                    v0::FieldsChannel::Icon => {
                        icon.take();
                    }
                    v0::FieldsChannel::Voice => {
                        voice.take();
                    }
                    _ => {}
                }
            }

            if let Some(icon_id) = data.icon {
                partial.icon = Some(File::use_channel_icon(db, &icon_id, id, &user.id).await?);
                *icon = partial.icon.clone();
            }

            if let Some(new_name) = data.name {
                *name = new_name.clone();
                partial.name = Some(new_name);
            }

            if let Some(new_description) = data.description {
                partial.description = Some(new_description);
                *description = partial.description.clone();
            }

            if let Some(new_nsfw) = data.nsfw {
                *nsfw = new_nsfw;
                partial.nsfw = Some(new_nsfw);
            }

            if let Some(new_voice) = data.voice {
                *voice = Some(new_voice.clone().into());
                partial.voice = Some(new_voice.into());
            }

            // Send out mutation system messages.
            if let Some(name) = &partial.name {
                SystemMessage::ChannelRenamed {
                    name: name.to_string(),
                    by: user.id.clone(),
                }
                .into_message(channel.id().to_string())
                .send(
                    db,
                    Some(amqp),
                    user.as_author_for_system(),
                    None,
                    None,
                    &channel,
                    false,
                )
                .await
                .ok();
            }

            if partial.description.is_some() {
                SystemMessage::ChannelDescriptionChanged {
                    by: user.id.clone(),
                }
                .into_message(channel.id().to_string())
                .send(
                    db,
                    Some(amqp),
                    user.as_author_for_system(),
                    None,
                    None,
                    &channel,
                    false,
                )
                .await
                .ok();
            }

            if partial.icon.is_some() {
                SystemMessage::ChannelIconChanged {
                    by: user.id.clone(),
                }
                .into_message(channel.id().to_string())
                .send(
                    db,
                    Some(amqp),
                    user.as_author_for_system(),
                    None,
                    None,
                    &channel,
                    false,
                )
                .await
                .ok();
            }
        }
        Channel::TextChannel {
            id,
            name,
            description,
            icon,
            nsfw,
            voice,
            slowmode,
            ..
        } => {
            if data.remove.contains(&v0::FieldsChannel::Icon) {
                if let Some(icon) = &icon {
                    db.mark_attachment_as_deleted(&icon.id).await?;
                }
            }

            for field in &data.remove {
                match field {
                    v0::FieldsChannel::Description => {
                        description.take();
                    }
                    v0::FieldsChannel::Icon => {
                        icon.take();
                    }
                    v0::FieldsChannel::Voice => {
                        voice.take();
                    }
                    _ => {}
                }
            }

            if let Some(icon_id) = data.icon {
                partial.icon = Some(File::use_channel_icon(db, &icon_id, id, &user.id).await?);
                *icon = partial.icon.clone();
            }

            if let Some(new_name) = data.name {
                *name = new_name.clone();
                partial.name = Some(new_name);
            }

            if let Some(new_description) = data.description {
                partial.description = Some(new_description);
                *description = partial.description.clone();
            }

            if let Some(new_nsfw) = data.nsfw {
                *nsfw = new_nsfw;
                partial.nsfw = Some(new_nsfw);
            }

            if let Some(new_voice) = data.voice {
                *voice = Some(new_voice.clone().into());
                partial.voice = Some(new_voice.into());
            }

            if let Some(new_slowmode) = data.slowmode {
                *slowmode = Some(new_slowmode);
                partial.slowmode = Some(new_slowmode);
            }
        }
        Channel::Thread {
            name,
            archived,
            archived_timestamp,
            applied_tags,
            ..
        } => {
            if let Some(new_name) = data.name {
                *name = new_name.clone();
                partial.name = Some(new_name);
            }

            if let Some(new_archived) = data.archived {
                if *archived != new_archived {
                    *archived = new_archived;
                    partial.archived = Some(new_archived);

                    // Records when the archive state last changed (set on both
                    // archive and unarchive, since partial updates cannot
                    // clear fields).
                    let timestamp = iso8601_timestamp::Timestamp::now_utc().to_string();
                    archived_timestamp.replace(timestamp.clone());
                    partial.archived_timestamp = Some(timestamp);
                }
            }

            if let Some(new_applied_tags) = data.applied_tags {
                // Applied tags are validated against the parent forum's tag
                // definitions (permission_channel IS the parent).
                let Channel::Forum {
                    tags, require_tag, ..
                } = &permission_channel
                else {
                    return Err(create_error!(InvalidOperation));
                };

                crate::util::threads::validate_applied_tags(
                    tags,
                    &new_applied_tags,
                    *require_tag,
                    &permissions,
                )?;

                *applied_tags = new_applied_tags.clone();
                partial.applied_tags = Some(new_applied_tags);
            }
        }
        Channel::Forum {
            id,
            name,
            description,
            icon,
            nsfw,
            tags,
            require_tag,
            default_sort,
            ..
        } => {
            if data.remove.contains(&v0::FieldsChannel::Icon) {
                if let Some(icon) = &icon {
                    db.mark_attachment_as_deleted(&icon.id).await?;
                }
            }

            for field in &data.remove {
                match field {
                    v0::FieldsChannel::Description => {
                        description.take();
                    }
                    v0::FieldsChannel::Icon => {
                        icon.take();
                    }
                    v0::FieldsChannel::Tags => {
                        tags.clear();
                    }
                    _ => {}
                }
            }

            if let Some(icon_id) = data.icon {
                partial.icon = Some(File::use_channel_icon(db, &icon_id, id, &user.id).await?);
                *icon = partial.icon.clone();
            }

            if let Some(new_name) = data.name {
                *name = new_name.clone();
                partial.name = Some(new_name);
            }

            if let Some(new_description) = data.description {
                partial.description = Some(new_description);
                *description = partial.description.clone();
            }

            if let Some(new_nsfw) = data.nsfw {
                *nsfw = new_nsfw;
                partial.nsfw = Some(new_nsfw);
            }

            if let Some(new_tags) = data.tags {
                let new_tags = validate_forum_tags(tags, new_tags)?;
                *tags = new_tags.clone();
                partial.tags = Some(new_tags);
            }

            if let Some(new_require_tag) = data.require_tag {
                *require_tag = new_require_tag;
                partial.require_tag = Some(new_require_tag);
            }

            if let Some(new_default_sort) = data.default_sort {
                *default_sort = new_default_sort.clone().into();
                partial.default_sort = Some(new_default_sort.into());
            }
        }
        _ => return Err(create_error!(InvalidOperation)),
    };

    channel
        .update(
            db,
            partial,
            data.remove.into_iter().map(|f| f.into()).collect(),
        )
        .await?;

    if channel.voice().is_none() {
        delete_voice_channel(voice_client, &UserVoiceChannel::from_channel(&channel)).await?;
    }

    Ok(Json(channel.into()))
}

/// Validate a submitted forum tag set against the forum's current tags and
/// resolve it into stored tags (existing ids must reference current tags; new
/// tags get server-assigned ids).
fn validate_forum_tags(
    current: &[revolt_database::ForumTag],
    submitted: Vec<v0::DataForumTag>,
) -> Result<Vec<revolt_database::ForumTag>> {
    if submitted.len() > crate::util::threads::MAX_FORUM_TAGS {
        return Err(create_error!(InvalidProperty));
    }

    let mut resolved: Vec<revolt_database::ForumTag> = Vec::with_capacity(submitted.len());
    for tag in submitted {
        let name = tag.name.trim().to_string();
        if name.is_empty() || name.chars().count() > 32 {
            return Err(create_error!(InvalidProperty));
        }

        if let Some(emoji) = &tag.emoji {
            if emoji.is_empty() || emoji.chars().count() > 128 {
                return Err(create_error!(InvalidProperty));
            }
        }

        if resolved
            .iter()
            .any(|existing| existing.name.eq_ignore_ascii_case(&name))
        {
            return Err(create_error!(InvalidProperty));
        }

        let id = match tag.id {
            Some(id) => {
                // Must reference a tag that exists, exactly once.
                if !current.iter().any(|existing| existing.id == id)
                    || resolved.iter().any(|existing| existing.id == id)
                {
                    return Err(create_error!(InvalidProperty));
                }
                id
            }
            None => ulid::Ulid::new().to_string(),
        };

        resolved.push(revolt_database::ForumTag {
            id,
            name,
            emoji: tag.emoji,
            moderated: tag.moderated,
        });
    }

    Ok(resolved)
}
