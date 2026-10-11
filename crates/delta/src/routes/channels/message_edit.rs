use iso8601_timestamp::Timestamp;
use revolt_config::config;
use revolt_database::{
    tasks,
    util::{antispam, permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, Message, PartialMessage, User,
};
use revolt_models::v0::{self, Embed};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Edit Message
///
/// Edits a message that you've previously sent.
#[openapi(tag = "Messaging")]
#[patch("/<target>/messages/<msg>", data = "<edit>")]
pub async fn edit(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
    edit: Json<v0::DataEditMessage>,
) -> Result<Json<v0::Message>> {
    let edit = edit.into_inner();
    edit.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    Message::validate_sum(
        &edit.content,
        edit.embeds.as_deref().unwrap_or_default(),
        user.limits().await.message_length,
    )?;

    // Ensure we have permissions to send a message
    let channel = target.as_channel(db).await?;
    // Threads inherit their parent channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // Archived/locked threads reject participation.
    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    let mut message = msg.as_message_in_channel(db, channel.id()).await?;
    if message.author != user.id {
        return Err(create_error!(CannotEditMessage));
    }

    // Anti-spam: an edit puts new text in front of the DM peer just like a
    // send does ("hi" to many strangers, then each one edited into the scam),
    // so a DM edit that brings new content or embeds faces the same pause
    // gate, checked before any side effect (embed media is claimed below).
    let antispam_config = config().await.features.antispam.clone();
    let dm_peer = match &channel {
        Channel::DirectMessage { recipients, .. }
            if edit.content.is_some() || edit.embeds.is_some() =>
        {
            recipients.iter().find(|id| *id != &user.id).cloned()
        }
        _ => None,
    };

    if let Some(peer) = &dm_peer {
        antispam::dm_send_allowed(db, &antispam_config, &user, channel.id(), peer).await?;
    }

    message.edited = Some(Timestamp::now_utc());
    let mut partial = PartialMessage {
        edited: message.edited,
        ..Default::default()
    };

    // 1. Handle content update
    if let Some(content) = &edit.content {
        partial.content = Some(content.clone());
    }

    // 2. Clear any auto generated embeds
    let mut new_embeds: Vec<Embed> = vec![];
    if let Some(embeds) = &message.embeds {
        for embed in embeds {
            if let Embed::Text(embed) = embed {
                new_embeds.push(Embed::Text(embed.clone()))
            }
        }
    }

    // 3. Replace if we are given new embeds
    if let Some(embeds) = edit.embeds {
        // Ensure we have permissions to send embeds
        permissions.throw_if_lacking_channel_permission(ChannelPermission::SendEmbeds)?;

        new_embeds.clear();

        for embed in embeds {
            new_embeds.push(message.create_embed(db, embed).await?);
        }
    }

    partial.embeds = Some(new_embeds);

    message.update(db, partial, vec![]).await?;

    // Observe the edited text (best-effort, never fails or delays the
    // request). `update` applied the partial, so `message` already carries
    // the new content and embeds.
    if let Some(peer) = dm_peer {
        let (db, user, message, cfg, channel_id) = (
            db.inner().clone(),
            user.clone(),
            message.clone(),
            antispam_config,
            channel.id().to_string(),
        );
        tokio::spawn(async move {
            antispam::observe_dm_message(&db, &cfg, &user, &channel_id, &peer, &message).await;
        });
    }

    // Queue up a task for processing embeds if the we have sufficient permissions
    if permissions.has_channel_permission(ChannelPermission::SendEmbeds) {
        if let Some(content) = edit.content {
            tasks::process_embeds::queue(
                message.channel.to_string(),
                message.id.to_string(),
                content,
            )
            .await;
        }
    }

    Ok(Json(message.into_model(None, None)))
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_config::config;
    use revolt_database::{
        util::antispam, Channel, DmGuard, Member, Report, Session, SYSTEM_USER_ID,
    };
    use revolt_models::v0::{self, ReportedContent};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    /// Exempt from the detector: far below the minimum length once normalized
    const GREETING: &str = "hi";

    /// What the greetings get edited into
    const SCAM: &str = "Hi! I love your profile picture, can I use it for an art project for my client? I'll pay you and credit you.";

    async fn assert_detector_on() {
        assert!(
            config().await.features.antispam.dm_dupe_enabled,
            "run with REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"
        );
    }

    async fn send(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        content: &str,
    ) -> v0::Message {
        let response = harness
            .client
            .post(format!("/channels/{channel_id}/messages"))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "content": content }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok, "send to {channel_id}");
        response.into_json().await.expect("`Message`")
    }

    async fn edit(
        harness: &TestHarness,
        session: &Session,
        message: &v0::Message,
        body: Value,
    ) -> (Status, String) {
        let response = harness
            .client
            .patch(format!(
                "/channels/{}/messages/{}",
                message.channel, message.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    async fn system_reports_about(harness: &TestHarness, user_id: &str) -> Vec<Report> {
        harness
            .db
            .fetch_reports(None)
            .await
            .expect("reports")
            .into_iter()
            .filter(|report| {
                report.author_id == SYSTEM_USER_ID
                    && matches!(&report.content, ReportedContent::User { id, .. } if id == user_id)
            })
            .collect()
    }

    /// The observer runs spawned, off the request: poll until the author
    /// holds a guard AND a system report about them exists, or time out
    async fn wait_for_flag(harness: &TestHarness, user_id: &str) -> (DmGuard, Vec<Report>) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let guard = harness.db.fetch_user(user_id).await.expect("user").dm_guard;
            let reports = system_reports_about(harness, user_id).await;
            if let Some(guard) = &guard {
                if !reports.is_empty() {
                    return (guard.clone(), reports);
                }
            }

            assert!(
                Instant::now() < deadline,
                "the edits never flagged {user_id}: guard {guard:?}, {} system report(s)",
                reports.len()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_edit_into_scam_text_flags() {
        crate::util::test::rt().block_on(antispam_route_edit_into_scam_text_flags_case())
    }

    /// "hi" to three silent strangers is exempt, so the sends alone flag
    /// nothing; editing each greeting into the same text does. The observer
    /// sees the EDITED message (the guard carries its fingerprint), files one
    /// system report with an edited message as evidence, and pauses the
    /// author.
    async fn antispam_route_edit_into_scam_text_flags_case() {
        assert_detector_on().await;
        let harness = TestHarness::new().await;
        let (_, session, spammer) = harness.new_user().await;
        let (server, _) = harness.new_server(&spammer).await;

        let mut greetings = Vec::new();
        for _ in 0..3 {
            let (_, _, stranger) = harness.new_user().await;
            Member::create(&harness.db, &server, &stranger, None)
                .await
                .expect("member");
            let dm = Channel::create_dm(&harness.db, &spammer, &stranger)
                .await
                .expect("dm");
            greetings.push(send(&harness, &session, dm.id(), GREETING).await);
        }

        // Give the send path's observer time to (wrongly) count a greeting
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            harness
                .db
                .fetch_user(&spammer.id)
                .await
                .expect("user")
                .dm_guard
                .is_none(),
            "greetings are exempt"
        );
        assert!(system_reports_about(&harness, &spammer.id).await.is_empty());

        for greeting in &greetings {
            let (status, body) =
                edit(&harness, &session, greeting, json!({ "content": SCAM })).await;
            assert_eq!(status, Status::Ok, "{body}");
        }

        let (guard, reports) = wait_for_flag(&harness, &spammer.id).await;
        let antispam_config = config().await.features.antispam.clone();
        assert_eq!(guard.paused, antispam_config.dm_dupe_pause);
        assert!(guard.cleared_at.is_none());
        assert_eq!(guard.recipients, 3);
        assert_eq!(
            Some(guard.fingerprint.clone()),
            antispam::fingerprint(SCAM, antispam_config.min_chars()),
            "the observer fingerprinted the edited text"
        );

        assert_eq!(reports.len(), 1, "one report");
        let report = &reports[0];
        assert_eq!(report.id, guard.report_id);
        match &report.content {
            ReportedContent::User {
                message_id: Some(message_id),
                ..
            } => assert!(
                greetings.iter().any(|greeting| &greeting.id == message_id),
                "an edited message is the evidence"
            ),
            content => panic!("expected a user report with a message, got {:?}", content),
        }
    }

    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_paused_edit_refused() {
        crate::util::test::rt().block_on(antispam_route_paused_edit_refused_case())
    }

    /// A paused account may not edit its message in a DM with a stranger who
    /// never wrote back, neither the content nor the embeds, and the refused
    /// edit changes nothing. A DM where the peer did write back is a
    /// conversation and stays editable.
    async fn antispam_route_paused_edit_refused_case() {
        assert_detector_on().await;
        let harness = TestHarness::new().await;
        let (_, session, spammer) = harness.new_user().await;
        let (_, _, stranger) = harness.new_user().await;
        let (_, replier_session, replier) = harness.new_user().await;
        let (server, _) = harness.new_server(&spammer).await;
        for member in [&stranger, &replier] {
            Member::create(&harness.db, &server, member, None)
                .await
                .expect("member");
        }

        let silent_dm = Channel::create_dm(&harness.db, &spammer, &stranger)
            .await
            .expect("dm");
        let replied_dm = Channel::create_dm(&harness.db, &spammer, &replier)
            .await
            .expect("dm");
        let to_stranger = send(&harness, &session, silent_dm.id(), GREETING).await;
        let to_replier = send(&harness, &session, replied_dm.id(), GREETING).await;
        send(
            &harness,
            &replier_session,
            replied_dm.id(),
            "hey, who is this?",
        )
        .await;

        // The route loads the user per request, so the pause applies at once
        let claimed = harness
            .db
            .claim_dm_guard(
                &spammer.id,
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
        assert!(claimed, "paused");

        for body in [
            json!({ "content": SCAM }),
            json!({ "embeds": [{ "description": SCAM }] }),
        ] {
            let (status, response) = edit(&harness, &session, &to_stranger, body).await;
            assert_eq!(status, Status::Forbidden, "{response}");
            let error: Value = serde_json::from_str(&response).expect("error body");
            assert_eq!(error["type"], "DirectMessagesPaused");
        }

        let stored = harness
            .db
            .fetch_message(&to_stranger.id)
            .await
            .expect("message");
        assert_eq!(stored.content.as_deref(), Some(GREETING), "untouched");
        assert!(stored.edited.is_none(), "not marked edited");

        let (status, response) = edit(
            &harness,
            &session,
            &to_replier,
            json!({ "content": "sorry, wrong person" }),
        )
        .await;
        assert_eq!(status, Status::Ok, "{response}");
    }
}
