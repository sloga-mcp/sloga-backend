use std::collections::HashSet;

use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    voice::{sync_voice_permissions, VoiceClient},
    Database, File, PartialServer, Server, User, ValidatedTicket,
};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Edit Server
///
/// Edit a server by its id.
#[openapi(tag = "Server Information")]
#[patch("/<target>", data = "<data>")]
pub async fn edit(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataEditServer>,
    validated_ticket: Option<ValidatedTicket>,
) -> Result<Json<v0::Server>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let mut server = target.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    let permissions = calculate_server_permissions(&mut query).await;

    // Check permissions
    if data.name.is_none()
        && data.description.is_none()
        && data.icon.is_none()
        && data.banner.is_none()
        && data.system_messages.is_none()
        && data.categories.is_none()
        // && data.nsfw.is_none()
        && data.flags.is_none()
        && data.analytics.is_none()
        && data.discoverable.is_none()
        && data.discovery_requested.is_none()
        && data.voice_region.is_none()
        && data.afk_channel_id.is_none()
        && data.afk_timeout.is_none()
        && data.owner.is_none()
        && data.remove.is_empty()
    {
        return Ok(Json(server.into()));
    } else if data.name.is_some()
        || data.description.is_some()
        || data.icon.is_some()
        || data.banner.is_some()
        || data.system_messages.is_some()
        || data.analytics.is_some()
        || data.voice_region.is_some()
        || data.afk_channel_id.is_some()
        || data.afk_timeout.is_some()
        || !data.remove.is_empty()
    {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageServer)?;
    }

    // A voice region must name a configured LiveKit node; "Auto" is expressed
    // by removing the field, never by a sentinel value.
    if let Some(voice_region) = &data.voice_region {
        if !revolt_config::config()
            .await
            .api
            .livekit
            .nodes
            .contains_key(voice_region)
        {
            return Err(create_error!(UnknownNode));
        }
    }

    // The AFK designation must resolve to a voice channel in THIS server.
    // Validated here, before the destructure, mirroring the voice_region check
    // directly above. The resolved channel is kept so the A5 re-sync at the end
    // of this route does not have to fetch it a second time.
    let incoming_afk_channel = if let Some(afk_channel_id) = &data.afk_channel_id {
        Some(Server::validate_afk_channel(db, &server.id, afk_channel_id).await?)
    } else {
        None
    };

    // Idle timeout is a closed preset set, in SECONDS. Never clamped, so a
    // rejected value can never land as a silently different one.
    if let Some(afk_timeout) = data.afk_timeout {
        Server::validate_afk_timeout(afk_timeout)?;
    }

    // Captured BEFORE the update mutates `server`, so the A5 re-sync below can
    // still reach the OUTGOING channel. Note clearing never travels in the
    // partial: `Server` derives OptionalStruct with opt_some_priority and these
    // fields are already Option<T>, so the generated assigner is a `replace()`
    // and writing `afk_channel_id: None` into the partial is a silent no-op.
    // A clear must arrive as FieldsServer::AfkChannel in `remove`.
    let previous_afk_channel_id = server.afk_channel_id.clone();

    // Check we are the server owner or privileged if changing sensitive fields
    if data.owner.is_some() {
        if user.id != server.owner && !user.privileged {
            return Err(create_error!(NotOwner));
        }

        if validated_ticket.is_none() {
            return Err(create_error!(InvalidCredentials));
        }
    }

    // Check we are privileged if changing sensitive fields
    if data.flags.is_some() /*|| data.nsfw.is_some()*/ && !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    // Discovery gating, fail closed. server_edit has NO membership
    // precondition, so every arm must reject explicitly:
    // - listing (`discoverable: true`) is admin approval — privileged only
    // - delisting (`discoverable: false`) — owner or privileged, so an owner
    //   can withdraw public exposure without an admin round-trip
    // - `discovery_requested` (any value) — owner or privileged (privileged
    //   path is admin rejection); NOT ManageServer: publicly listing a
    //   community is an owner-level decision
    let is_owner_or_privileged = user.id == server.owner || user.privileged;
    match data.discoverable {
        Some(true) if !user.privileged => return Err(create_error!(NotPrivileged)),
        Some(false) if !is_owner_or_privileged => return Err(create_error!(NotPrivileged)),
        _ => {}
    }
    if data.discovery_requested.is_some() && !is_owner_or_privileged {
        return Err(create_error!(NotPrivileged));
    }

    // Changing categories requires manage channel
    if data.categories.is_some() {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
    }

    let v0::DataEditServer {
        name,
        description,
        icon,
        banner,
        categories,
        system_messages,
        flags,
        // nsfw,
        discoverable,
        discovery_requested,
        analytics,
        voice_region,
        afk_channel_id,
        afk_timeout,
        owner,
        remove,
    } = data;

    // Any explicit transition of `discoverable` clears the pending request:
    // approval consumes it, delisting withdraws it. Set server-side, never
    // trusting the client to couple the two.
    let discovery_requested = if discoverable.is_some() {
        Some(false)
    } else {
        discovery_requested
    };

    let mut partial = PartialServer {
        name,
        description,
        categories: categories.map(|v| v.into_iter().map(Into::into).collect()),
        system_messages: system_messages.map(Into::into),
        flags,
        // nsfw,
        discoverable,
        discovery_requested,
        analytics,
        voice_region,
        afk_channel_id,
        afk_timeout,
        owner: owner.clone(),
        ..Default::default()
    };

    // 1. Remove fields from object
    if remove.contains(&v0::FieldsServer::Banner) {
        if let Some(banner) = &server.banner {
            db.mark_attachment_as_deleted(&banner.id).await?;
        }
    }

    if remove.contains(&v0::FieldsServer::Icon) {
        if let Some(icon) = &server.icon {
            db.mark_attachment_as_deleted(&icon.id).await?;
        }
    }

    // 2. Validate changes
    if let Some(system_messages) = &partial.system_messages {
        for id in system_messages.clone().into_channel_ids() {
            if !server.channels.contains(&id) {
                return Err(create_error!(NotFound));
            }
        }
    }

    if let Some(categories) = &mut partial.categories {
        let mut channel_ids = HashSet::new();
        for category in categories {
            for channel in &category.channels {
                if channel_ids.contains(channel) {
                    return Err(create_error!(InvalidOperation));
                }

                channel_ids.insert(channel.to_string());
            }

            category
                .channels
                .retain(|item| server.channels.contains(item));
        }
    }

    // 3. Apply new icon
    if let Some(icon) = icon {
        partial.icon = Some(File::use_server_icon(db, &icon, &server.id, &user.id).await?);
        server.icon = partial.icon.clone();
    }

    // 4. Apply new banner
    if let Some(banner) = banner {
        partial.banner = Some(File::use_server_banner(db, &banner, &server.id, &user.id).await?);
        server.banner = partial.banner.clone();
    }

    // 5. Transfer ownership
    if let Some(owner) = owner {
        let owner_reference = Reference::from_unchecked(&owner);
        // Check if member exists
        owner_reference.as_member(db, &server.id).await?;
        let owner_user = owner_reference.as_user(db).await?;

        if owner_user.bot.is_some() {
            return Err(create_error!(InvalidOperation));
        }

        server.owner = owner;
        partial.owner = Some(server.owner.clone());
    }

    server
        .update(db, partial, remove.into_iter().map(Into::into).collect())
        .await?;

    // A5: re-sync voice permissions on BOTH sides of a designation change.
    // Without this, flagging an already-occupied channel is inert until some
    // unrelated role or permission edit happens to trigger a sync.
    //
    // `role_id: None` means every member currently in the room, which is what a
    // server-level designation change affects.
    //
    // This is a no-op for AFK purposes until the publish gate lands:
    // `sync_user_voice_permissions` derives its state from permission bits, and
    // the AFK designation is deliberately kept outside the permission system.
    // Wired now so the gate is live the moment it exists.

    // Outgoing - the channel that is no longer AFK. Resolve-then-check: the
    // stored pointer may already be stale (channel deleted, or it has since
    // lost its voice information) and the designation change is already
    // committed, so a channel that will not resolve is skipped rather than
    // turned into a late failure on a write that already succeeded.
    if let Some(previous) = &previous_afk_channel_id {
        if server.afk_channel_id.as_ref() != Some(previous) {
            if let Ok(channel) = db.fetch_channel(previous).await {
                sync_voice_permissions(db, voice_client, &channel, Some(&server), None).await?;
            }
        }
    }

    // Incoming - already resolved and validated above.
    if let Some(channel) = &incoming_afk_channel {
        if previous_afk_channel_id.as_deref() != Some(channel.id()) {
            sync_voice_permissions(db, voice_client, channel, Some(&server), None).await?;
        }
    }

    Ok(Json(server.into()))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{Member, PartialUser, Server, Session};
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};

    async fn edit(
        harness: &TestHarness,
        server_id: &str,
        session: &Session,
        body: serde_json::Value,
    ) -> Status {
        harness
            .client
            .patch(format!("/servers/{}", server_id))
            .header(ContentType::JSON)
            .body(body.to_string())
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await
            .status()
    }

    /// Audit MAJOR 5: server_edit has no membership precondition, so every
    /// discovery arm must fail closed on its own.
    #[test]
    fn discovery_gating_fail_closed() {
        crate::util::test::rt().block_on(discovery_gating_fail_closed_case())
    }

    async fn discovery_gating_fail_closed_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member_user) = harness.new_user().await;
        let (_, outsider_session, _) = harness.new_user().await;
        let (_, admin_session, mut admin) = harness.new_user().await;

        admin
            .update(
                &harness.db,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("privileged admin");

        let (server, _) = Server::create(
            &harness.db,
            v0::DataCreateServer {
                name: "Gated".to_string(),
                ..Default::default()
            },
            &owner,
            true,
        )
        .await
        .expect("`Server`");

        Member::create(&harness.db, &server, &member_user, None)
            .await
            .expect("`Member`");

        // Non-owner member: every discovery field is rejected.
        for body in [
            json!({ "discovery_requested": true }),
            json!({ "discovery_requested": false }),
            json!({ "discoverable": true }),
            json!({ "discoverable": false }),
        ] {
            assert_eq!(
                edit(&harness, &server.id, &member_session, body).await,
                Status::Forbidden
            );
        }

        // Non-member authenticated user: same, fail closed.
        for body in [
            json!({ "discovery_requested": true }),
            json!({ "discovery_requested": false }),
            json!({ "discoverable": true }),
            json!({ "discoverable": false }),
        ] {
            assert_eq!(
                edit(&harness, &server.id, &outsider_session, body).await,
                Status::Forbidden
            );
        }

        // Owner cannot list their own server (admin approval required)...
        assert_eq!(
            edit(
                &harness,
                &server.id,
                &owner_session,
                json!({ "discoverable": true })
            )
            .await,
            Status::Forbidden
        );

        // ...but can request a listing...
        assert_eq!(
            edit(
                &harness,
                &server.id,
                &owner_session,
                json!({ "discovery_requested": true })
            )
            .await,
            Status::Ok
        );
        let fetched = harness.db.fetch_server(&server.id).await.unwrap();
        assert!(fetched.discovery_requested);
        assert!(!fetched.discoverable);

        // ...and privileged approval flips discoverable AND consumes the
        // pending request server-side.
        assert_eq!(
            edit(
                &harness,
                &server.id,
                &admin_session,
                json!({ "discoverable": true })
            )
            .await,
            Status::Ok
        );
        let fetched = harness.db.fetch_server(&server.id).await.unwrap();
        assert!(fetched.discoverable);
        assert!(!fetched.discovery_requested);

        // Owner can instantly delist without an admin round-trip.
        assert_eq!(
            edit(
                &harness,
                &server.id,
                &owner_session,
                json!({ "discoverable": false })
            )
            .await,
            Status::Ok
        );
        let fetched = harness.db.fetch_server(&server.id).await.unwrap();
        assert!(!fetched.discoverable);
        assert!(!fetched.discovery_requested);
    }
}
