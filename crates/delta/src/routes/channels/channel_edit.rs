use revolt_database::{
    client_gate_is_set,
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    voice::{delete_voice_channel, UserVoiceChannel, VoiceClient},
    Channel, Database, File, PartialChannel, Server, SystemMessage, User, AMQP,
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

        // A creator who can no longer post may not pin their thread open (or
        // otherwise retune when it auto-archives). Creators who also hold
        // ManageChannel (e.g. moderators in a read-only forum) are exempt:
        // they may make this edit on anyone's thread anyway.
        if data.auto_archive_minutes.is_some()
            && !permissions.has_channel_permission(ChannelPermission::ManageChannel)
        {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;
        }
    }

    if data.name.is_none()
        && data.description.is_none()
        && data.icon.is_none()
        && data.nsfw.is_none()
        && data.spoiler.is_none()
        && data.owner.is_none()
        && data.voice.is_none()
        && data.slowmode.is_none()
        && data.archived.is_none()
        && data.tags.is_none()
        && data.require_tag.is_none()
        && data.default_sort.is_none()
        && data.force_sort.is_none()
        && data.default_auto_archive_minutes.is_none()
        && data.auto_archive_minutes.is_none()
        && data.applied_tags.is_none()
        && data.announcement.is_none()
        && data.remove.is_empty()
    {
        return Ok(Json(channel.into()));
    }

    // The announcement flag only ever applies to plain server text channels
    // (never voice-flavoured text channels).
    if data.announcement.is_some()
        && !matches!(channel, Channel::TextChannel { voice: None, .. })
    {
        return Err(create_error!(InvalidOperation));
    }

    // Forum configuration fields only ever apply to forum channels; reject
    // them anywhere else (mirrors the group-only owner rejection below)
    // instead of silently dropping them.
    if (data.tags.is_some()
        || data.require_tag.is_some()
        || data.default_sort.is_some()
        || data.force_sort.is_some())
        && !matches!(channel, Channel::Forum { .. })
    {
        return Err(create_error!(InvalidOperation));
    }

    // Applied tags only make sense on forum-post threads.
    if data.applied_tags.is_some() && !matches!(channel, Channel::Thread { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    // The per-forum default auto-archive duration only exists on forums.
    if data.default_auto_archive_minutes.is_some() && !matches!(channel, Channel::Forum { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    // A concrete auto-archive duration only exists on threads / forum posts.
    if data.auto_archive_minutes.is_some() && !matches!(channel, Channel::Thread { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    // Auto-archive durations must fall in the accepted range, 0 meaning never
    // (validated before any write).
    for minutes in [data.auto_archive_minutes, data.default_auto_archive_minutes]
        .iter()
        .flatten()
    {
        if !Channel::is_valid_auto_archive_minutes(*minutes) {
            return Err(create_error!(InvalidProperty));
        }
    }

    // The spoiler flag exists on groups, text channels and forums; reject it
    // elsewhere instead of silently dropping it.
    if data.spoiler.is_some()
        && !matches!(
            channel,
            Channel::Group { .. } | Channel::TextChannel { .. } | Channel::Forum { .. }
        )
    {
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

    // The server's AFK channel may not be put behind a client gate (age,
    // spoiler or password): the idle sweep moves members into it without
    // asking, including members who were never let past the gate, and
    // `Server::validate_afk_channel` refuses to designate a gated channel for
    // the same reason. The designation has to be removed first, through
    // `server_edit`, which re-syncs the call. Clearing it here instead would
    // leave everyone in the call hard-muted with no re-sync, because gating a
    // channel does not tear its room down.
    //
    // Only an edit that makes the channel a gated, enabled voice channel when
    // it was not one is refused: turning a gate ON while it stays an enabled
    // voice channel, or turning its voice back on while it is gated.
    // Removing a gate, and every edit that does neither, always goes
    // through. An edit that also removes or disables voice is left to the
    // de-voice path below, which clears the designation. This is a hard gate
    // on the edit, not a permission: the owner is refused too. It runs
    // before anything is written.
    if let Channel::TextChannel { server, id, .. } = &channel {
        if gates_turned_on(&channel, &data) && voice_after_edit(&channel, &data) {
            let designated = db.fetch_server(server).await?.afk_channel_id;
            if designated.as_deref() == Some(id.as_str()) {
                return Err(create_error!(InvalidOperation));
            }
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
            spoiler,
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
                        // Resetting returns the group to the default (calling
                        // on, no limit). Write that as an explicit empty
                        // configuration instead of clearing the field, because
                        // clients treat a cleared `voice` as "no calls here".
                        *voice = Some(Default::default());
                        partial.voice = Some(Default::default());
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

            if let Some(new_spoiler) = data.spoiler {
                *spoiler = new_spoiler;
                partial.spoiler = Some(new_spoiler);
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
            spoiler,
            voice,
            slowmode,
            announcement,
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

            if let Some(new_spoiler) = data.spoiler {
                *spoiler = new_spoiler;
                partial.spoiler = Some(new_spoiler);
            }

            if let Some(new_voice) = data.voice {
                *voice = Some(new_voice.clone().into());
                partial.voice = Some(new_voice.into());
            }

            if let Some(new_slowmode) = data.slowmode {
                *slowmode = Some(new_slowmode);
                partial.slowmode = Some(new_slowmode);
            }

            if let Some(new_announcement) = data.announcement {
                *announcement = Some(new_announcement);
                partial.announcement = Some(new_announcement);
            }
        }
        Channel::Thread {
            name,
            archived,
            archived_timestamp,
            auto_archive_minutes,
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

            if let Some(new_auto_archive_minutes) = data.auto_archive_minutes {
                *auto_archive_minutes = new_auto_archive_minutes;
                partial.auto_archive_minutes = Some(new_auto_archive_minutes);
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
            spoiler,
            tags,
            require_tag,
            default_sort,
            force_sort,
            default_auto_archive_minutes,
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

            if let Some(new_spoiler) = data.spoiler {
                *spoiler = new_spoiler;
                partial.spoiler = Some(new_spoiler);
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

            if let Some(new_force_sort) = data.force_sort {
                *force_sort = new_force_sort;
                partial.force_sort = Some(new_force_sort);
            }

            if let Some(new_default_auto_archive_minutes) = data.default_auto_archive_minutes {
                *default_auto_archive_minutes = new_default_auto_archive_minutes;
                partial.default_auto_archive_minutes = Some(new_default_auto_archive_minutes);
            }
        }
        _ => return Err(create_error!(InvalidOperation)),
    };

    // A group's voice reset was written as a default configuration above, so
    // it must not also be cleared.
    let is_group = matches!(channel, Channel::Group { .. });
    channel
        .update(
            db,
            partial,
            data.remove
                .into_iter()
                .filter(|field| !(is_group && matches!(field, v0::FieldsChannel::Voice)))
                .map(|f| f.into())
                .collect(),
        )
        .await?;

    if channel.voice().is_none() {
        // Pointer integrity: this PATCH may have just removed the channel's
        // voice information (remove: ["Voice"]) or disabled calling on it
        // (voice.disabled) - Channel::voice() returns None for both - which
        // tears the room down while Server.afk_channel_id may still point
        // here. This route never touches the server document, so without the
        // clear the designation survives as a pointer to what is now a plain
        // text channel. This block also runs for channels that never had
        // voice, so the clear is conditional: the helper compares the server's
        // current pointer and no-ops unless it is this channel.
        //
        // Ordered BEFORE the teardown on purpose. channel.update above has
        // already committed the voice removal, so the stale window is open
        // from that point and clearing first closes it as early as possible.
        // The reverse ordering would, on a teardown failure, leave the
        // designation pointing at a channel whose room is already destroyed -
        // exactly the defect being closed.
        if let Channel::TextChannel { server, id, .. } = &channel {
            Server::clear_afk_channel_if_pointing_at(db, server, id).await?;
        }

        delete_voice_channel(db, voice_client, &UserVoiceChannel::from_channel(&channel)).await?;
    }

    Ok(Json(channel.into()))
}

/// Whether this edit leaves a server text channel behind a client gate (see
/// `client_gate_is_set`) that does not already hold it as an enabled voice
/// channel: gated after the edit, and not both gated and an enabled voice
/// channel before it. Together with `voice_after_edit` that is exactly an
/// edit that makes the channel a gated, enabled voice channel when it was
/// not one (wave BG audit BGA-1). On an enabled voice channel it is the plain
/// transition, no gate before and at least one after. On a gated channel
/// whose voice is disabled or absent it is any edit that keeps a gate, so an
/// edit that also turns the voice back on counts as putting the gate on.
///
/// The values after the edit follow the route's in-memory order in the
/// `TextChannel` arm: `remove` runs first, then the body's fields, so here a
/// `description` in the body wins over a `Description` in `remove`. The
/// stored result of that conflict is driver-dependent: the Reference driver
/// applies the body and unsets last, so the removal wins there, and MongoDB
/// rejects an update that sets and unsets the same field. Reading the
/// in-memory order can only refuse an edit that would not have stored a
/// gate, never let one through. Any other channel type answers `false`; only
/// a `TextChannel` can be a voice channel, and so an AFK channel.
fn gates_turned_on(channel: &Channel, data: &v0::DataEditChannel) -> bool {
    let Channel::TextChannel {
        description,
        nsfw,
        spoiler,
        voice,
        ..
    } = channel
    else {
        return false;
    };

    let description_after = match &data.description {
        Some(description) => Some(description.as_str()),
        None if data.remove.contains(&v0::FieldsChannel::Description) => None,
        None => description.as_deref(),
    };

    let gated_voice_before = client_gate_is_set(*nsfw, *spoiler, description.as_deref())
        && voice.as_ref().is_some_and(|voice| !voice.disabled);

    !gated_voice_before
        && client_gate_is_set(
            data.nsfw.unwrap_or(*nsfw),
            data.spoiler.unwrap_or(*spoiler),
            description_after,
        )
}

/// Whether a server text channel is still an enabled voice channel once this
/// edit lands (`Channel::voice()` on the result: voice information present
/// and not disabled). Same in-memory order as above: a `voice` in the body
/// wins over a `Voice` in `remove` here, and the stored result of that
/// conflict is driver-dependent in the same way. Any other channel type
/// answers `false`.
fn voice_after_edit(channel: &Channel, data: &v0::DataEditChannel) -> bool {
    let Channel::TextChannel { voice, .. } = channel else {
        return false;
    };

    match &data.voice {
        Some(voice) => !voice.disabled,
        None if data.remove.contains(&v0::FieldsChannel::Voice) => false,
        None => voice.as_ref().is_some_and(|voice| !voice.disabled),
    }
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

#[cfg(test)]
mod tests {
    use crate::util::test::TestHarness;
    use revolt_models::v0;
    use rocket::http::{ContentType, Status};

    #[test]
    fn spoiler_only_edit_is_not_a_no_op() {
        crate::util::test::rt().block_on(spoiler_only_edit_is_not_a_no_op_case())
    }

    async fn spoiler_only_edit_is_not_a_no_op_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        // A request that ONLY flips the spoiler flag must be applied — this
        // guards the early no-op return at the top of the route.
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .patch(format!("/channels/{}", channel.id()))
                .header(ContentType::JSON)
                .body(json!({ "spoiler": true }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        let edited = response.into_json::<v0::Channel>().await.expect("channel");
        assert!(matches!(edited, v0::Channel::TextChannel { spoiler: true, .. }));

        // And it persisted, not just echoed.
        let stored = harness
            .db
            .fetch_channel(channel.id())
            .await
            .expect("channel");
        assert!(matches!(
            stored,
            revolt_database::Channel::TextChannel { spoiler: true, .. }
        ));
    }

    /// A server (owned by `owner`) with a forum, a plain member `creator`
    /// who authored one post in it, and a second plain member `outsider`.
    struct ForumFixture {
        harness: TestHarness,
        server: revolt_database::Server,
        owner_session: revolt_database::Session,
        forum: revolt_database::Channel,
        creator_session: revolt_database::Session,
        post: revolt_database::Channel,
        outsider_session: revolt_database::Session,
    }

    async fn forum_fixture() -> ForumFixture {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, creator_session, creator) = harness.new_user().await;
        let (_, outsider_session, outsider) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&owner).await;

        revolt_database::Member::create(&harness.db, &server, &creator, None)
            .await
            .expect("creator joins");
        revolt_database::Member::create(&harness.db, &server, &outsider, None)
            .await
            .expect("outsider joins");

        let forum = revolt_database::Channel::create_server_channel(
            &harness.db,
            &mut server,
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Forum,
                name: "forum".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("forum created");

        let post = revolt_database::Channel::create_forum_post(
            &harness.db,
            &forum,
            &creator,
            "a post".to_string(),
            vec![],
            None,
        )
        .await
        .expect("post created");

        ForumFixture {
            harness,
            server,
            owner_session,
            forum,
            creator_session,
            post,
            outsider_session,
        }
    }

    /// Give `user_id` a server role granting ManageChannel.
    async fn grant_manage_channel(fx: &ForumFixture, user_id: &str) {
        let role = fx
            .harness
            .new_role(
                &fx.server,
                1,
                Some(revolt_permissions::OverrideField {
                    a: revolt_permissions::ChannelPermission::ManageChannel as i64,
                    d: 0,
                }),
            )
            .await;
        let mut member = fx
            .harness
            .db
            .fetch_member(&fx.server.id, user_id)
            .await
            .expect("member");
        member
            .update(
                &fx.harness.db,
                revolt_database::PartialMember {
                    roles: Some(vec![role.id.clone()]),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("grant ManageChannel role");
    }

    /// Make the forum read-only: SendMessage denied for everyone by default.
    async fn deny_send_message_on_forum(fx: &ForumFixture) {
        let mut forum = fx.forum.clone();
        forum
            .update(
                &fx.harness.db,
                revolt_database::PartialChannel {
                    default_permissions: Some(revolt_permissions::OverrideField {
                        a: 0,
                        d: revolt_permissions::ChannelPermission::SendMessage as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny SendMessage on the forum");
    }

    async fn patch<'a>(
        harness: &'a TestHarness,
        session: &revolt_database::Session,
        channel_id: &str,
        body: serde_json::Value,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        TestHarness::with_session(
            session.clone(),
            harness
                .client
                .patch(format!("/channels/{}", channel_id))
                .header(ContentType::JSON)
                .body(body.to_string()),
        )
        .await
    }

    async fn assert_error(
        response: rocket::local::asynchronous::LocalResponse<'_>,
        status: Status,
        needle: &str,
    ) {
        assert_eq!(response.status(), status);
        let body = response.into_string().await.unwrap_or_default();
        assert!(body.contains(needle), "expected {}, got {}", needle, body);
    }

    async fn stored_post_minutes(harness: &TestHarness, id: &str) -> u32 {
        match harness.db.fetch_channel(id).await.expect("post") {
            revolt_database::Channel::Thread {
                auto_archive_minutes,
                ..
            } => auto_archive_minutes,
            other => panic!("expected a thread, got {:?}", other),
        }
    }

    async fn stored_forum_default(harness: &TestHarness, id: &str) -> u32 {
        match harness.db.fetch_channel(id).await.expect("forum") {
            revolt_database::Channel::Forum {
                default_auto_archive_minutes,
                ..
            } => default_auto_archive_minutes,
            other => panic!("expected a forum, got {:?}", other),
        }
    }

    /// (a) + (g): the post's creator can pin their own post open with a body
    /// carrying ONLY `auto_archive_minutes` (not swallowed by the no-op check);
    /// it persists and fans out in the ChannelUpdate partial.
    #[test]
    fn creator_sets_auto_archive_on_own_post() {
        crate::util::test::rt().block_on(creator_sets_auto_archive_on_own_post_case())
    }

    async fn creator_sets_auto_archive_on_own_post_case() {
        let mut fx = forum_fixture().await;
        assert_ne!(
            stored_post_minutes(&fx.harness, fx.post.id()).await,
            0,
            "fixture must not already be Never"
        );

        let response = patch(
            &fx.harness,
            &fx.creator_session,
            fx.post.id(),
            json!({ "auto_archive_minutes": 0 }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let edited = response.into_json::<v0::Channel>().await.expect("channel");
        assert!(matches!(
            edited,
            v0::Channel::Thread {
                auto_archive_minutes: 0,
                ..
            }
        ));

        assert_eq!(stored_post_minutes(&fx.harness, fx.post.id()).await, 0);

        let post_id = fx.post.id().to_string();
        fx.harness
            .wait_for_event(&fx.server.id, |event| {
                matches!(
                    event,
                    revolt_database::events::client::EventV1::ChannelUpdate { id, data, .. }
                        if id == &post_id && data.auto_archive_minutes == Some(0)
                )
            })
            .await;
    }

    /// (b): a creator who lost SendMessage may not retune auto-archive.
    #[test]
    fn creator_without_send_message_cannot_set_auto_archive() {
        crate::util::test::rt()
            .block_on(creator_without_send_message_cannot_set_auto_archive_case())
    }

    async fn creator_without_send_message_cannot_set_auto_archive_case() {
        let fx = forum_fixture().await;
        deny_send_message_on_forum(&fx).await;

        let before = stored_post_minutes(&fx.harness, fx.post.id()).await;
        let response = patch(
            &fx.harness,
            &fx.creator_session,
            fx.post.id(),
            json!({ "auto_archive_minutes": 0 }),
        )
        .await;
        assert_error(response, Status::Forbidden, "MissingPermission").await;
        assert_eq!(stored_post_minutes(&fx.harness, fx.post.id()).await, before);

        // The creator can still perform other own-thread edits (rename).
        let response = patch(
            &fx.harness,
            &fx.creator_session,
            fx.post.id(),
            json!({ "name": "renamed" }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
    }

    /// (c): a non-creator without ManageChannel cannot touch the post.
    #[test]
    fn non_creator_cannot_set_auto_archive() {
        crate::util::test::rt().block_on(non_creator_cannot_set_auto_archive_case())
    }

    async fn non_creator_cannot_set_auto_archive_case() {
        let fx = forum_fixture().await;
        let before = stored_post_minutes(&fx.harness, fx.post.id()).await;
        let response = patch(
            &fx.harness,
            &fx.outsider_session,
            fx.post.id(),
            json!({ "auto_archive_minutes": 0 }),
        )
        .await;
        assert_error(response, Status::Forbidden, "MissingPermission").await;
        assert_eq!(stored_post_minutes(&fx.harness, fx.post.id()).await, before);
    }

    /// (d): the forum default is ManageChannel-gated.
    #[test]
    fn forum_default_auto_archive_requires_manage_channel() {
        crate::util::test::rt().block_on(forum_default_auto_archive_requires_manage_channel_case())
    }

    async fn forum_default_auto_archive_requires_manage_channel_case() {
        let fx = forum_fixture().await;

        // Plain members (including a post creator) cannot change it.
        for session in [&fx.outsider_session, &fx.creator_session] {
            let response = patch(
                &fx.harness,
                session,
                fx.forum.id(),
                json!({ "default_auto_archive_minutes": 129600 }),
            )
            .await;
            assert_error(response, Status::Forbidden, "MissingPermission").await;
        }
        assert_ne!(
            stored_forum_default(&fx.harness, fx.forum.id()).await,
            129600
        );

        let response = patch(
            &fx.harness,
            &fx.owner_session,
            fx.forum.id(),
            json!({ "default_auto_archive_minutes": 129600 }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            stored_forum_default(&fx.harness, fx.forum.id()).await,
            129600
        );
    }

    /// (e): values outside the allowlist are rejected before any write.
    #[test]
    fn auto_archive_outside_allowlist_is_rejected() {
        crate::util::test::rt().block_on(auto_archive_outside_allowlist_is_rejected_case())
    }

    async fn auto_archive_outside_allowlist_is_rejected_case() {
        let fx = forum_fixture().await;
        let before = stored_post_minutes(&fx.harness, fx.post.id()).await;

        let response = patch(
            &fx.harness,
            &fx.creator_session,
            fx.post.id(),
            json!({ "auto_archive_minutes": 30 }),
        )
        .await;
        assert_error(response, Status::BadRequest, "InvalidProperty").await;
        assert_eq!(stored_post_minutes(&fx.harness, fx.post.id()).await, before);

        let forum_before = stored_forum_default(&fx.harness, fx.forum.id()).await;
        let response = patch(
            &fx.harness,
            &fx.owner_session,
            fx.forum.id(),
            json!({ "default_auto_archive_minutes": 30 }),
        )
        .await;
        assert_error(response, Status::BadRequest, "InvalidProperty").await;
        assert_eq!(
            stored_forum_default(&fx.harness, fx.forum.id()).await,
            forum_before
        );
    }

    /// (f): each field is rejected on the wrong channel type.
    #[test]
    fn auto_archive_fields_rejected_on_wrong_channel_type() {
        crate::util::test::rt().block_on(auto_archive_fields_rejected_on_wrong_channel_type_case())
    }

    async fn auto_archive_fields_rejected_on_wrong_channel_type_case() {
        let fx = forum_fixture().await;

        // Forum default on a post.
        let response = patch(
            &fx.harness,
            &fx.owner_session,
            fx.post.id(),
            json!({ "default_auto_archive_minutes": 60 }),
        )
        .await;
        assert_error(response, Status::BadRequest, "InvalidOperation").await;

        // Concrete duration on the forum itself.
        let response = patch(
            &fx.harness,
            &fx.owner_session,
            fx.forum.id(),
            json!({ "auto_archive_minutes": 60 }),
        )
        .await;
        assert_error(response, Status::BadRequest, "InvalidOperation").await;

        // Concrete duration on a plain text channel.
        let text = fx.harness.new_channel(&fx.server).await;
        let response = patch(
            &fx.harness,
            &fx.owner_session,
            text.id(),
            json!({ "auto_archive_minutes": 60 }),
        )
        .await;
        assert_error(response, Status::BadRequest, "InvalidOperation").await;

        // (j) Forum default on a plain text channel.
        let response = patch(
            &fx.harness,
            &fx.owner_session,
            text.id(),
            json!({ "default_auto_archive_minutes": 60 }),
        )
        .await;
        assert_error(response, Status::BadRequest, "InvalidOperation").await;
    }

    /// (h): in a read-only forum (SendMessage denied for everyone), a post
    /// creator who holds ManageChannel may still retune their own post.
    #[test]
    fn creator_with_manage_channel_is_exempt_from_send_message_gate() {
        crate::util::test::rt()
            .block_on(creator_with_manage_channel_is_exempt_from_send_message_gate_case())
    }

    async fn creator_with_manage_channel_is_exempt_from_send_message_gate_case() {
        let fx = forum_fixture().await;
        grant_manage_channel(&fx, &fx.creator_session.user_id).await;
        deny_send_message_on_forum(&fx).await;

        let response = patch(
            &fx.harness,
            &fx.creator_session,
            fx.post.id(),
            json!({ "auto_archive_minutes": 0 }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(stored_post_minutes(&fx.harness, fx.post.id()).await, 0);
    }

    /// (i): a non-creator holding ManageChannel may set a post's duration.
    #[test]
    fn manager_can_set_auto_archive_on_others_post() {
        crate::util::test::rt().block_on(manager_can_set_auto_archive_on_others_post_case())
    }

    async fn manager_can_set_auto_archive_on_others_post_case() {
        let fx = forum_fixture().await;
        grant_manage_channel(&fx, &fx.outsider_session.user_id).await;

        let response = patch(
            &fx.harness,
            &fx.outsider_session,
            fx.post.id(),
            json!({ "auto_archive_minutes": 43200 }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(stored_post_minutes(&fx.harness, fx.post.id()).await, 43200);
    }

    // ---- AFK pointer integrity on de-voice (AFK Stage 6 F-B6) -------------

    /// The braced block opening at byte `open` of `text` (inclusive).
    fn braced(text: &str, open: usize) -> &str {
        let mut depth = 0usize;
        for (i, ch) in text[open..].char_indices() {
            match ch {
                '\u{7b}' => depth += 1,
                '\u{7d}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &text[open..=open + i];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced braces from byte {}", open);
    }

    /// `edit`'s body, comment lines dropped and whitespace collapsed.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("channel_edit.rs");
        let at = SOURCE
            .find("pub async fn edit(")
            .expect("the route is defined");
        let open = at + SOURCE[at..].find('\u{7b}').expect("a body");
        braced(SOURCE, open)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// A PATCH that removes or disables a channel's voice tears the room
    /// down, and this route never touches the server document - so the
    /// server's AFK designation has to be cleared here, or it survives as a
    /// pointer to what is now a plain text channel. The clear sits INSIDE the
    /// de-voice block (it must not run on every edit) and BEFORE
    /// `delete_voice_channel(` (a failed teardown must not leave the pointer
    /// behind). Mutations: the clear deleted, or the two swapped.
    #[test]
    fn devoicing_clears_the_afk_designation_before_the_teardown() {
        const DEVOICE: &str = "if channel.voice().is_none() \u{7b}";
        const CLEAR: &str = "if let Channel::TextChannel \u{7b} server, id, .. \u{7d} = &channel \
             \u{7b} Server::clear_afk_channel_if_pointing_at(db, server, id).await?; \u{7d}";
        const TEARDOWN: &str = "delete_voice_channel(db, voice_client, \
             &UserVoiceChannel::from_channel(&channel)).await?;";

        let body = route_body();
        assert_eq!(body.matches(DEVOICE).count(), 1, "{body}");
        assert_eq!(
            body.matches("clear_afk_channel_if_pointing_at(").count(),
            1,
            "the route clears the designation in exactly one place: {body}"
        );

        let block = braced(
            &body,
            body.find(DEVOICE).expect("counted above") + DEVOICE.len() - 1,
        );
        let clear = block
            .find(CLEAR)
            .unwrap_or_else(|| panic!("the de-voice block lost the AFK clear: {}", block));
        let teardown = block
            .find(TEARDOWN)
            .unwrap_or_else(|| panic!("the de-voice block lost the teardown: {}", block));
        assert!(
            clear < teardown,
            "the AFK clear must precede `delete_voice_channel(`: {}",
            block
        );
    }

    // ---- The AFK channel behind a client gate (wave BG) ---------------------

    /// A password line as the client writes it, after `before`.
    fn password_description(before: &str) -> String {
        [
            before,
            revolt_database::CHANNEL_PASSWORD_PREFIX,
            "0123abcd",
            revolt_database::CHANNEL_PASSWORD_SUFFIX,
        ]
        .concat()
    }

    fn text_channel(
        nsfw: bool,
        spoiler: bool,
        description: Option<String>,
        voice: Option<revolt_database::VoiceInformation>,
    ) -> revolt_database::Channel {
        revolt_database::Channel::TextChannel {
            id: "C".to_string(),
            server: "S".to_string(),
            name: "voice".to_string(),
            description,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: Default::default(),
            nsfw,
            spoiler,
            voice,
            slowmode: None,
            announcement: None,
        }
    }

    fn enabled() -> Option<revolt_database::VoiceInformation> {
        Some(Default::default())
    }

    fn edit_body(body: serde_json::Value) -> v0::DataEditChannel {
        serde_json::from_value(body).expect("`DataEditChannel`")
    }

    /// Only the transition from no gate to some gate counts. Controls: the
    /// "no gate before" half dropped (the already-gated rows go red), and the
    /// remove-then-set order reversed (the same-edit row goes red).
    #[test]
    fn gates_turned_on_cases() {
        use super::gates_turned_on;

        let password = password_description("");
        let open = text_channel(false, false, None, enabled());
        for body in [
            json!({ "nsfw": true }),
            json!({ "spoiler": true }),
            json!({ "description": password }),
            json!({ "description": password_description("Welcome\n") }),
            // `remove` runs first, then the body's description lands.
            json!({ "remove": ["Description"], "description": password }),
        ] {
            assert!(gates_turned_on(&open, &edit_body(body.clone())), "{}", body);
        }

        for body in [
            json!({ "name": "renamed" }),
            json!({ "nsfw": false, "spoiler": false }),
            json!({ "description": "Welcome" }),
            // Not the last line, so no password.
            json!({ "description": password_description("") + "\nWelcome" }),
            json!({ "remove": ["Description"] }),
        ] {
            assert!(
                !gates_turned_on(&open, &edit_body(body.clone())),
                "{}",
                body
            );
        }

        // Already gated: nothing is turned ON, whatever the edit does.
        let gated = [
            text_channel(true, false, None, enabled()),
            text_channel(false, true, None, enabled()),
            text_channel(false, false, Some(password.clone()), enabled()),
        ];
        for channel in &gated {
            for body in [
                json!({ "nsfw": true, "spoiler": true }),
                json!({ "name": "renamed" }),
                json!({ "nsfw": false, "spoiler": false }),
                json!({ "remove": ["Description"] }),
            ] {
                assert!(
                    !gates_turned_on(channel, &edit_body(body.clone())),
                    "{} on {:?}",
                    body,
                    channel
                );
            }
        }

        // Only a server text channel answers.
        let group = revolt_database::Channel::Group {
            id: "G".to_string(),
            name: "group".to_string(),
            owner: "O".to_string(),
            description: None,
            recipients: vec![],
            icon: None,
            last_message_id: None,
            permissions: None,
            nsfw: false,
            spoiler: false,
            voice: None,
        };
        assert!(!gates_turned_on(
            &group,
            &edit_body(json!({ "nsfw": true }))
        ));
    }

    /// Whether the channel is still an enabled voice channel once the edit
    /// lands. Controls: the body's `voice` ignored when `remove` also names
    /// Voice, and `disabled` ignored.
    #[test]
    fn voice_after_edit_cases() {
        use super::voice_after_edit;

        let voice = text_channel(false, false, None, enabled());
        assert!(voice_after_edit(
            &voice,
            &edit_body(json!({ "nsfw": true }))
        ));
        assert!(!voice_after_edit(
            &voice,
            &edit_body(json!({ "remove": ["Voice"] }))
        ));
        assert!(!voice_after_edit(
            &voice,
            &edit_body(json!({ "voice": { "disabled": true } }))
        ));
        assert!(voice_after_edit(
            &voice,
            &edit_body(json!({ "remove": ["Voice"], "voice": { "max_users": 5 } }))
        ));

        let disabled = text_channel(
            false,
            false,
            None,
            Some(revolt_database::VoiceInformation {
                max_users: None,
                disabled: true,
            }),
        );
        assert!(!voice_after_edit(&disabled, &edit_body(json!({}))));
        assert!(voice_after_edit(
            &disabled,
            &edit_body(json!({ "voice": { "disabled": false } }))
        ));

        let text = text_channel(false, false, None, None);
        assert!(!voice_after_edit(
            &text,
            &edit_body(json!({ "nsfw": true }))
        ));
    }

    /// The refusal comes after the permission check (a caller who may not
    /// edit the channel learns nothing about the designation) and before
    /// anything is written or announced. It reads the server's designation
    /// itself and refuses with `InvalidOperation`. Control: the block moved
    /// below `let mut partial`.
    #[test]
    fn the_afk_gate_refusal_precedes_every_write() {
        const REFUSAL: &str =
            "if gates_turned_on(&channel, &data) && voice_after_edit(&channel, &data) \u{7b}";

        let body = route_body();
        assert_eq!(body.matches(REFUSAL).count(), 1, "{body}");
        let refusal = body.find(REFUSAL).expect("counted above");

        let permission = body
            .find("permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;")
            .expect("the permission check");
        assert!(permission < refusal, "{}", body);

        for needle in [
            "let mut partial",
            "db.mark_attachment_as_deleted(",
            "File::use_channel_icon(",
            "SystemMessage::",
            "channel .update(",
        ] {
            let at = body
                .find(needle)
                .unwrap_or_else(|| panic!("the route lost `{}`: {}", needle, body));
            assert!(
                refusal < at,
                "the refusal must precede `{}`: {}",
                needle,
                body
            );
        }

        let block = braced(&body, refusal + REFUSAL.len() - 1);
        assert!(
            block.contains("db.fetch_server(server).await?.afk_channel_id"),
            "{}",
            block
        );
        assert!(
            block.contains("return Err(create_error!(InvalidOperation));"),
            "{}",
            block
        );
    }

    async fn new_voice_channel(
        harness: &TestHarness,
        server: &revolt_database::Server,
        body: serde_json::Value,
    ) -> revolt_database::Channel {
        let mut data: v0::DataCreateServerChannel =
            serde_json::from_value(body).expect("`DataCreateServerChannel`");
        data.channel_type = v0::LegacyServerChannelType::Voice;
        revolt_database::Channel::create_server_channel(
            &harness.db,
            &mut server.clone(),
            data,
            true,
        )
        .await
        .expect("voice channel")
    }

    async fn designate(harness: &TestHarness, server: &mut revolt_database::Server, id: &str) {
        server
            .update(
                &harness.db,
                revolt_database::PartialServer {
                    afk_channel_id: Some(id.to_string()),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("designate the AFK channel");
    }

    async fn designated(harness: &TestHarness, server_id: &str) -> Option<String> {
        harness
            .db
            .fetch_server(server_id)
            .await
            .expect("server")
            .afk_channel_id
    }

    /// (nsfw, spoiler, description, voice present) as stored.
    async fn stored_gates(harness: &TestHarness, id: &str) -> (bool, bool, Option<String>, bool) {
        match harness.db.fetch_channel(id).await.expect("channel") {
            revolt_database::Channel::TextChannel {
                nsfw,
                spoiler,
                description,
                voice,
                ..
            } => (nsfw, spoiler, description, voice.is_some()),
            other => panic!("expected a text channel, got {:?}", other),
        }
    }

    /// Putting any gate on the designated AFK channel is refused, and nothing
    /// is written. The actor is the server OWNER: the permission calculus
    /// grants the owner everything before it reads anything, so a refusal
    /// written as a permission check would let this through. Control: the
    /// refusal deleted.
    #[test]
    fn gating_the_afk_channel_is_refused_even_for_the_owner() {
        crate::util::test::rt()
            .block_on(gating_the_afk_channel_is_refused_even_for_the_owner_case())
    }

    async fn gating_the_afk_channel_is_refused_even_for_the_owner_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&owner).await;
        let afk = new_voice_channel(&harness, &server, json!({ "name": "AFK" })).await;
        designate(&harness, &mut server, afk.id()).await;

        for body in [
            json!({ "nsfw": true }),
            json!({ "spoiler": true }),
            json!({ "description": password_description("Welcome\n") }),
            json!({ "remove": ["Description"], "description": password_description("") }),
            json!({ "name": "Idle", "nsfw": true }),
        ] {
            let response = patch(&harness, &session, afk.id(), body.clone()).await;
            assert_error(response, Status::BadRequest, "InvalidOperation").await;

            assert_eq!(
                stored_gates(&harness, afk.id()).await,
                (false, false, None, true),
                "{body} must write nothing"
            );
            assert_eq!(
                designated(&harness, &server.id).await.as_deref(),
                Some(afk.id())
            );
        }
        assert!(matches!(
            harness.db.fetch_channel(afk.id()).await.expect("channel"),
            revolt_database::Channel::TextChannel { name, .. } if name == "AFK"
        ));
    }

    /// The refusal is scoped to the designated channel: gating any other
    /// voice channel in the same server goes through. Control: the
    /// designation comparison dropped.
    #[test]
    fn gating_another_voice_channel_is_allowed() {
        crate::util::test::rt().block_on(gating_another_voice_channel_is_allowed_case())
    }

    async fn gating_another_voice_channel_is_allowed_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&owner).await;
        let afk = new_voice_channel(&harness, &server, json!({ "name": "AFK" })).await;
        designate(&harness, &mut server, afk.id()).await;

        for (body, want) in [
            (json!({ "nsfw": true }), (true, false, None, true)),
            (json!({ "spoiler": true }), (false, true, None, true)),
            (
                json!({ "description": password_description("") }),
                (false, false, Some(password_description("")), true),
            ),
        ] {
            let lounge = new_voice_channel(&harness, &server, json!({ "name": "Lounge" })).await;
            let response = patch(&harness, &session, lounge.id(), body.clone()).await;
            assert_eq!(response.status(), Status::Ok, "{body}");
            assert_eq!(stored_gates(&harness, lounge.id()).await, want, "{body}");
        }

        assert_eq!(
            designated(&harness, &server.id).await.as_deref(),
            Some(afk.id())
        );
    }

    /// A designated channel that is ALREADY gated can only arise from a race
    /// between two admins, but it must never be locked: unrelated edits and
    /// removing gates go through, one gate at a time. Control: refusing on
    /// "gated after the edit" alone, without "not gated before" (the rename
    /// and the partial un-gate go red).
    #[test]
    fn a_gated_afk_channel_can_still_be_edited_and_ungated() {
        crate::util::test::rt().block_on(a_gated_afk_channel_can_still_be_edited_and_ungated_case())
    }

    async fn a_gated_afk_channel_can_still_be_edited_and_ungated_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&owner).await;
        // Seeded straight through the model, past every route check.
        let afk = new_voice_channel(
            &harness,
            &server,
            json!({
                "name": "AFK", "nsfw": true, "spoiler": true,
                "description": password_description("")
            }),
        )
        .await;
        designate(&harness, &mut server, afk.id()).await;

        for (body, want) in [
            (
                json!({ "name": "Idle" }),
                (true, true, Some(password_description("")), true),
            ),
            (
                json!({ "spoiler": false }),
                (true, false, Some(password_description("")), true),
            ),
            (
                json!({ "remove": ["Description"] }),
                (true, false, None, true),
            ),
            (json!({ "nsfw": false }), (false, false, None, true)),
        ] {
            let response = patch(&harness, &session, afk.id(), body.clone()).await;
            assert_eq!(response.status(), Status::Ok, "{body}");
            assert_eq!(stored_gates(&harness, afk.id()).await, want, "{body}");
        }

        assert_eq!(
            designated(&harness, &server.id).await.as_deref(),
            Some(afk.id())
        );
    }

    /// Gating and de-voicing in one edit is not refused: the channel stops
    /// being a voice channel, and the existing de-voice path clears the
    /// designation. Both de-voice shapes.
    #[test]
    fn gating_while_devoicing_takes_the_devoice_path() {
        crate::util::test::rt().block_on(gating_while_devoicing_takes_the_devoice_path_case())
    }

    async fn gating_while_devoicing_takes_the_devoice_path_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&owner).await;

        for body in [
            json!({ "nsfw": true, "remove": ["Voice"] }),
            json!({ "spoiler": true, "voice": { "disabled": true } }),
        ] {
            let afk = new_voice_channel(&harness, &server, json!({ "name": "AFK" })).await;
            designate(&harness, &mut server, afk.id()).await;

            let response = patch(&harness, &session, afk.id(), body.clone()).await;
            assert_eq!(response.status(), Status::Ok, "{body}");

            let stored = harness.db.fetch_channel(afk.id()).await.expect("channel");
            assert!(stored.voice().is_none(), "{}", body);
            assert!(stored.has_client_gate(), "{}", body);
            assert_eq!(designated(&harness, &server.id).await, None, "{body}");
        }
    }

    // ---- Entering the gated voice state by its voice (BG audit BGA-1) -------

    /// The route's condition, `gates_turned_on && voice_after_edit`: the edit
    /// makes the channel a gated, enabled voice channel when it was not one.
    /// A gated channel whose voice is disabled or absent enters that state
    /// when its voice is turned (back) on, whichever gate it carries.
    /// Control: `gates_turned_on` back to the gate-only transition (the
    /// re-enable rows go red). This test spells the condition itself, so
    /// `voice_after_edit` dropped from the ROUTE's condition is caught by
    /// `the_afk_gate_refusal_precedes_every_write` and
    /// `gating_while_devoicing_takes_the_devoice_path` instead.
    #[test]
    fn turning_the_voice_on_behind_a_gate_enters_the_gated_voice_state() {
        use super::{gates_turned_on, voice_after_edit};

        let enters = |channel: &revolt_database::Channel, body: &serde_json::Value| {
            let data = edit_body(body.clone());
            gates_turned_on(channel, &data) && voice_after_edit(channel, &data)
        };
        let disabled = || {
            Some(revolt_database::VoiceInformation {
                max_users: None,
                disabled: true,
            })
        };

        let password = password_description("");
        for voice in [disabled(), None] {
            let gated = [
                text_channel(true, false, None, voice.clone()),
                text_channel(false, true, None, voice.clone()),
                text_channel(false, false, Some(password.clone()), voice.clone()),
            ];
            for channel in &gated {
                for body in [
                    json!({ "voice": { "disabled": false } }),
                    json!({ "voice": {} }),
                    json!({ "name": "Idle", "voice": { "max_users": 5 } }),
                ] {
                    assert!(enters(channel, &body), "{} on {:?}", body, channel);
                }
                for body in [
                    // The voice stays off: not a voice channel after the edit.
                    json!({ "name": "Idle" }),
                    json!({ "voice": { "disabled": true } }),
                    json!({ "remove": ["Voice"] }),
                    // Every gate removed in the same edit.
                    json!({
                        "nsfw": false, "spoiler": false, "remove": ["Description"],
                        "voice": { "disabled": false }
                    }),
                ] {
                    assert!(!enters(channel, &body), "{} on {:?}", body, channel);
                }
            }
        }

        // Already a gated, enabled voice channel: nothing is entered.
        let gated_voice = text_channel(true, false, None, enabled());
        for body in [
            json!({ "voice": { "disabled": false } }),
            json!({ "name": "Idle" }),
            json!({ "spoiler": true }),
        ] {
            assert!(!enters(&gated_voice, &body), "{}", body);
        }

        // An ungated channel with its voice off: turning the voice on alone
        // enters nothing, turning it on together with a gate does.
        let open = text_channel(false, false, None, disabled());
        assert!(!enters(&open, &json!({ "voice": { "disabled": false } })));
        assert!(enters(
            &open,
            &json!({ "nsfw": true, "voice": { "disabled": false } })
        ));
    }

    /// (nsfw, spoiler, description, voice) exactly as stored.
    async fn stored_voice_channel(
        harness: &TestHarness,
        id: &str,
    ) -> (
        bool,
        bool,
        Option<String>,
        Option<revolt_database::VoiceInformation>,
    ) {
        match harness.db.fetch_channel(id).await.expect("channel") {
            revolt_database::Channel::TextChannel {
                nsfw,
                spoiler,
                description,
                voice,
                ..
            } => (nsfw, spoiler, description, voice),
            other => panic!("expected a text channel, got {:?}", other),
        }
    }

    /// BGA-1: a designated channel that is gated with its voice disabled can
    /// only arise from a race or from older data, but turning its voice back
    /// on would make the AFK channel a gated voice channel all the same, so
    /// that edit is refused like the gating one, owner included, and nothing
    /// is written. A designated channel that is gated with its voice enabled
    /// can still be renamed. Control: `gates_turned_on` back to the
    /// gate-only transition (the re-enable goes through).
    #[test]
    fn enabling_the_voice_of_a_gated_afk_channel_is_refused() {
        crate::util::test::rt()
            .block_on(enabling_the_voice_of_a_gated_afk_channel_is_refused_case())
    }

    async fn enabling_the_voice_of_a_gated_afk_channel_is_refused_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&owner).await;

        let off = revolt_database::VoiceInformation {
            max_users: None,
            disabled: true,
        };
        // Seeded straight through the model, past every route check.
        let mut afk = new_voice_channel(
            &harness,
            &server,
            json!({
                "name": "AFK", "nsfw": true,
                "description": password_description("")
            }),
        )
        .await;
        afk.update(
            &harness.db,
            revolt_database::PartialChannel {
                voice: Some(off.clone()),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("disable the voice");
        designate(&harness, &mut server, afk.id()).await;

        let seeded = (true, false, Some(password_description("")), Some(off));
        assert_eq!(stored_voice_channel(&harness, afk.id()).await, seeded);

        for body in [
            json!({ "voice": { "disabled": false } }),
            json!({ "voice": {} }),
            json!({ "name": "Idle", "voice": { "max_users": 5 } }),
        ] {
            let response = patch(&harness, &session, afk.id(), body.clone()).await;
            assert_error(response, Status::BadRequest, "InvalidOperation").await;
            assert_eq!(
                stored_voice_channel(&harness, afk.id()).await,
                seeded,
                "{body} must write nothing"
            );
            assert_eq!(
                designated(&harness, &server.id).await.as_deref(),
                Some(afk.id())
            );
        }
        assert!(matches!(
            harness.db.fetch_channel(afk.id()).await.expect("channel"),
            revolt_database::Channel::TextChannel { name, .. } if name == "AFK"
        ));

        // The same channel with its voice enabled: a rename goes through.
        let gated = new_voice_channel(
            &harness,
            &server,
            json!({ "name": "Gated", "spoiler": true }),
        )
        .await;
        designate(&harness, &mut server, gated.id()).await;
        let response = patch(&harness, &session, gated.id(), json!({ "name": "Idle" })).await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            stored_gates(&harness, gated.id()).await,
            (false, true, None, true)
        );
        assert!(matches!(
            harness.db.fetch_channel(gated.id()).await.expect("channel"),
            revolt_database::Channel::TextChannel { name, voice: Some(voice), .. }
                if name == "Idle" && !voice.disabled
        ));
        assert_eq!(
            designated(&harness, &server.id).await.as_deref(),
            Some(gated.id())
        );
    }
}
