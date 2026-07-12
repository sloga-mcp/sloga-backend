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
        && data.remove.is_empty()
    {
        return Ok(Json(channel.into()));
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
