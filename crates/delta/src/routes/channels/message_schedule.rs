use std::time::{SystemTime, UNIX_EPOCH};

use revolt_config::config;
use revolt_database::util::antispam;
use revolt_database::util::idempotency::IdempotencyKey;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{
    events::client::EventV1, Channel, Database, File, Interactions, Message, ScheduledMessage,
    ScheduledMessageStatus, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use ulid::Ulid;
use validator::Validate;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// # Schedule Message
///
/// Schedules a message for later delivery to the given channel.
///
/// The composed payload is stored server-side and sent through the normal
/// message path when due (with up to ~30s of tick jitter). Permissions are
/// checked BOTH now and again at fire time — scheduling is never a way to
/// outlive a revoked permission. Slowmode does not apply to the delivery
/// (it fires as the daemon, not as a user request burst).
///
/// Pending scheduled messages are strictly private to their author.
#[openapi(tag = "Messaging")]
#[post("/<target>/scheduled_messages", data = "<data>")]
pub async fn message_schedule(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataScheduleMessage>,
    idempotency: IdempotencyKey,
) -> Result<Json<v0::ScheduledMessage>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let config = config().await;
    let limits = user.limits().await;

    let v0::DataScheduleMessage {
        message: mut payload,
        scheduled_at,
    } = data;

    // Delivery window: between 30 seconds and 30 days out.
    let now = now_ms();
    if scheduled_at < now + v0::MIN_SCHEDULE_LEAD_MS
        || scheduled_at > now + v0::MAX_SCHEDULE_HORIZON_MS
    {
        return Err(create_error!(FailedValidation {
            error: "scheduled_at must be between 30 seconds and 30 days from now".to_string()
        }));
    }

    // Same shape validation as a live send.
    Message::validate_sum(
        &payload.content,
        payload.embeds.as_deref().unwrap_or_default(),
        limits.message_length,
    )?;

    if (payload.content.as_ref().is_none_or(|v| v.is_empty()))
        && (payload.attachments.as_ref().is_none_or(|v| v.is_empty()))
        && (payload.embeds.as_ref().is_none_or(|v| v.is_empty()))
        && (payload.sticker_ids.as_ref().is_none_or(|v| v.is_empty()))
    {
        return Err(create_error!(EmptyMessage));
    }

    // Same client-flag boundary as the live send path.
    if payload.flags.as_ref().is_some_and(|flags| *flags > 7) {
        return Err(create_error!(InvalidProperty));
    }

    if payload
        .replies
        .as_ref()
        .is_some_and(|replies| replies.len() > config.features.limits.global.message_replies)
    {
        return Err(create_error!(TooManyReplies {
            max: config.features.limits.global.message_replies,
        }));
    }

    if payload
        .attachments
        .as_ref()
        .is_some_and(|v| v.len() > limits.message_attachments)
    {
        return Err(create_error!(TooManyAttachments {
            max: limits.message_attachments,
        }));
    }

    if payload
        .embeds
        .as_ref()
        .is_some_and(|v| v.len() > config.features.limits.global.message_embeds)
    {
        return Err(create_error!(TooManyEmbeds {
            max: config.features.limits.global.message_embeds,
        }));
    }

    // Components are bot-only on the live path; a user scheduling them
    // would only discover the rejection at fire time — fail fast instead.
    if payload.components.is_some() && user.bot.is_none() {
        return Err(create_error!(IsNotBot));
    }

    // Ensure we have permission to send in this channel, now.
    let channel = target.as_channel(db).await?;

    // Forum channels have no message stream of their own.
    if matches!(channel, Channel::Forum { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    // NOTE: E2EE exclusion (scheduled messages are stored plaintext) is
    // enforced client-side by the composer, matching message_send — the
    // server cannot reliably know a conversation's encryption state.

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    if let Some(masq) = &payload.masquerade {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::Masquerade)?;

        if masq.colour.is_some() {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageRole)?;
        }
    }

    if payload.embeds.as_ref().is_some_and(|v| !v.is_empty()) {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::SendEmbeds)?;
    }

    if payload.attachments.as_ref().is_some_and(|v| !v.is_empty()) {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::UploadFiles)?;
    }

    if let Some(interactions) = &payload.interactions {
        let interactions: Interactions = interactions.clone().into();
        interactions.validate(db, &permissions).await?;
    }

    // A paused account may not queue DMs to strangers who never wrote
    // back. Checked before the nonce, attachments or row are touched;
    // delivery checks again, as a pause can start in between.
    if let Channel::DirectMessage { recipients, .. } = &channel {
        if let Some(peer) = recipients.iter().find(|id| *id != &user.id) {
            antispam::dm_send_allowed(db, &config.features.antispam, &user, channel.id(), peer)
                .await?;
        }
    }

    // Pending caps (per channel and overall).
    let per_channel = config.features.limits.global.scheduled_messages_per_channel;
    if db
        .count_pending_scheduled_messages(&user.id, Some(channel.id()))
        .await?
        >= per_channel
    {
        return Err(create_error!(TooManyScheduledMessages { max: per_channel }));
    }

    let per_user = config.features.limits.global.scheduled_messages_per_user;
    if db
        .count_pending_scheduled_messages(&user.id, None)
        .await?
        >= per_user
    {
        return Err(create_error!(TooManyScheduledMessages { max: per_user }));
    }

    let mut idempotency = idempotency;
    idempotency
        .consume_nonce(payload.nonce.take())
        .await
        .map_err(|_| create_error!(InvalidOperation))?;

    let row_id = Ulid::new().to_string();

    // Claim attachments against the ROW id now: unclaimed files are swept
    // by the dangling-file pruner after an hour, which would eat anything
    // scheduled further out. Delivery retargets them to the real message.
    let mut claimed: Vec<String> = Vec::new();
    for attachment_id in payload.attachments.as_deref().unwrap_or_default() {
        match File::use_attachment(db, attachment_id, &row_id, &user.id).await {
            Ok(_) => claimed.push(attachment_id.clone()),
            Err(error) => {
                // Release anything claimed so far into the deletion sweep.
                if !claimed.is_empty() {
                    db.mark_attachments_as_deleted(&claimed).await.ok();
                }
                return Err(error);
            }
        }
    }

    let server = match &channel {
        Channel::TextChannel { server, .. }
        | Channel::Thread { server, .. }
        | Channel::Forum { server, .. } => Some(server.clone()),
        _ => None,
    };

    let row = ScheduledMessage {
        id: row_id,
        author: user.id.clone(),
        channel: channel.id().to_string(),
        server,
        scheduled_at,
        data: payload,
        status: ScheduledMessageStatus::Pending,
        failure_reason: None,
    };

    if let Err(error) = db.insert_scheduled_message(&row).await {
        // Never leave claimed files pointing at a row that doesn't exist.
        if !claimed.is_empty() {
            db.mark_attachments_as_deleted(&claimed).await.ok();
        }
        return Err(error);
    }

    let model = row.into_model();

    EventV1::MessageScheduled {
        message: model.clone(),
    }
    .private(user.id.clone())
    .await;

    Ok(Json(model))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use iso8601_timestamp::Timestamp;
    use revolt_database::{Channel, DmGuard, Member, Message, User};
    use revolt_models::v0;
    use revolt_result::{Error, ErrorType};
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::LocalResponse;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};
    use ulid::Ulid;

    fn in_ms(offset: i64) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
            + offset
    }

    #[test]
    fn schedule_inserts_pending_row() {
        crate::util::test::rt().block_on(schedule_inserts_pending_row_case())
    }

    async fn schedule_inserts_pending_row_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let response = harness
            .client
            .post(format!("/channels/{}/scheduled_messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "content": "see you tomorrow",
                    "scheduled_at": in_ms(60 * 60 * 1000)
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);

        let scheduled: v0::ScheduledMessage = response.into_json().await.expect("row");
        assert_eq!(scheduled.author, user.id);
        assert_eq!(scheduled.channel, channel.id());
        assert!(matches!(
            scheduled.status,
            v0::ScheduledMessageStatus::Pending
        ));
        assert_eq!(scheduled.data.content.as_deref(), Some("see you tomorrow"));

        // Present in the author's pending list
        let rows = harness
            .db
            .fetch_scheduled_messages_by_author(channel.id(), &user.id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn schedule_rejects_bad_windows_and_shapes() {
        crate::util::test::rt().block_on(schedule_rejects_bad_windows_and_shapes_case())
    }

    async fn schedule_rejects_bad_windows_and_shapes_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        for body in [
            // Too soon
            json!({ "content": "x", "scheduled_at": in_ms(1_000) }),
            // In the past
            json!({ "content": "x", "scheduled_at": in_ms(-60_000) }),
            // Too far out (31 days)
            json!({ "content": "x", "scheduled_at": in_ms(31 * 24 * 60 * 60 * 1000) }),
            // Empty message
            json!({ "scheduled_at": in_ms(60 * 60 * 1000) }),
            // Forged high flag bits
            json!({ "content": "x", "flags": 64, "scheduled_at": in_ms(60 * 60 * 1000) }),
        ] {
            let response = harness
                .client
                .post(format!("/channels/{}/scheduled_messages", channel.id()))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
                .await;

            assert_ne!(response.status(), Status::Ok, "should be rejected: {body}");
        }
    }

    #[test]
    fn schedule_enforces_pending_caps() {
        crate::util::test::rt().block_on(schedule_enforces_pending_caps_case())
    }

    async fn schedule_enforces_pending_caps_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let per_channel = revolt_config::config()
            .await
            .features
            .limits
            .global
            .scheduled_messages_per_channel;

        // Seed the cap directly (the route's own ratelimit bucket is
        // tighter than the cap, so filling it via HTTP would 429 first).
        for i in 0..per_channel {
            harness
                .db
                .insert_scheduled_message(&revolt_database::ScheduledMessage {
                    id: format!("01CAPSEED0000000000000000{i:02}"),
                    author: user.id.clone(),
                    channel: channel.id().to_string(),
                    server: None,
                    scheduled_at: in_ms(60 * 60 * 1000),
                    data: v0::DataMessageSend {
                        nonce: None,
                        content: Some(format!("n{i}")),
                        attachments: None,
                        replies: None,
                        embeds: None,
                        masquerade: None,
                        interactions: None,
                        components: None,
                        sticker_ids: None,
                        encrypted: None,
                        flags: None,
                    },
                    status: revolt_database::ScheduledMessageStatus::Pending,
                    failure_reason: None,
                })
                .await
                .expect("seed row");
        }

        // One over the per-channel cap
        let response = harness
            .client
            .post(format!("/channels/{}/scheduled_messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "content": "over cap",
                    "scheduled_at": in_ms(60 * 60 * 1000)
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
    }

    /// An author whose DMs to strangers are paused, a stranger they share a
    /// server with (so the DM itself is permitted) who never wrote back, and
    /// the DM between them. Returns the author's session token, the author,
    /// the stranger and the DM.
    async fn paused_author_and_silent_stranger(
        harness: &TestHarness,
    ) -> (String, User, User, Channel) {
        let (_, session, author) = harness.new_user().await;
        let (_, _, stranger) = harness.new_user().await;
        let (server, _) = harness.new_server(&author).await;
        Member::create(&harness.db, &server, &stranger, None)
            .await
            .expect("stranger member");

        let dm = Channel::create_dm(&harness.db, &author, &stranger)
            .await
            .expect("dm");
        assert!(matches!(dm, Channel::DirectMessage { .. }), "a real DM");

        // The route loads the author from the session on every request,
        // so the guard is picked up without re-fetching here.
        let claimed = harness
            .db
            .claim_dm_guard(
                &author.id,
                &DmGuard {
                    report_id: Ulid::new().to_string(),
                    flagged_at: Timestamp::now_utc(),
                    paused: true,
                    cleared_at: None,
                    recipients: 3,
                    fingerprint: "test".into(),
                },
                Timestamp::now_utc(),
            )
            .await
            .expect("claim");
        assert!(claimed, "guard set");

        (session.token.to_string(), author, stranger, dm)
    }

    async fn schedule_into<'a>(
        harness: &'a TestHarness,
        token: &str,
        channel_id: &str,
        nonce: &str,
    ) -> LocalResponse<'a> {
        harness
            .client
            .post(format!("/channels/{channel_id}/scheduled_messages"))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "content": "can I use your profile picture for an art project, I'll pay you",
                    "nonce": nonce,
                    "scheduled_at": in_ms(60 * 60 * 1000)
                })
                .to_string(),
            )
            .dispatch()
            .await
    }

    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_schedule_paused_refused() {
        crate::util::test::rt().block_on(antispam_route_schedule_paused_refused_case())
    }

    async fn antispam_route_schedule_paused_refused_case() {
        assert!(
            revolt_config::config()
                .await
                .features
                .antispam
                .dm_dupe_enabled,
            "run with REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"
        );

        let harness = TestHarness::new().await;
        let (token, author, stranger, dm) = paused_author_and_silent_stranger(&harness).await;
        let nonce = Ulid::new().to_string();

        // A paused author cannot queue a DM to a stranger who never wrote
        let response = schedule_into(&harness, &token, dm.id(), &nonce).await;
        assert_eq!(response.status(), Status::Forbidden);
        assert!(matches!(
            response.into_json::<Error>().await.unwrap().error_type,
            ErrorType::DirectMessagesPaused
        ));

        // Nothing was queued
        assert_eq!(
            harness
                .db
                .count_pending_scheduled_messages(&author.id, None)
                .await
                .unwrap(),
            0
        );

        // Once the stranger has written in the DM it is a real
        // conversation and scheduling works; the same nonce is accepted,
        // so the refusal consumed nothing.
        harness
            .db
            .insert_message(&Message {
                id: Ulid::new().to_string(),
                channel: dm.id().to_string(),
                author: stranger.id.clone(),
                content: Some("sure, who is this?".to_string()),
                ..Default::default()
            })
            .await
            .expect("reply");

        let response = schedule_into(&harness, &token, dm.id(), &nonce).await;
        assert_eq!(response.status(), Status::Ok);
        drop(response);
        let rows = harness
            .db
            .fetch_scheduled_messages_by_author(dm.id(), &author.id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn schedule_into_dm_allowed_while_antispam_off() {
        crate::util::test::rt().block_on(schedule_into_dm_allowed_while_antispam_off_case())
    }

    async fn schedule_into_dm_allowed_while_antispam_off_case() {
        // The switched-off detector lifts the pause everywhere (the kill
        // switch); this cannot be checked with it on.
        assert!(
            !revolt_config::config()
                .await
                .features
                .antispam
                .dm_dupe_enabled,
            "run without REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED"
        );

        let harness = TestHarness::new().await;
        let (token, author, _, dm) = paused_author_and_silent_stranger(&harness).await;

        let response = schedule_into(&harness, &token, dm.id(), &Ulid::new().to_string()).await;
        assert_eq!(response.status(), Status::Ok);
        let scheduled: v0::ScheduledMessage = response.into_json().await.expect("row");
        assert_eq!(scheduled.channel, dm.id());

        let rows = harness
            .db
            .fetch_scheduled_messages_by_author(dm.id(), &author.id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
    }
}
