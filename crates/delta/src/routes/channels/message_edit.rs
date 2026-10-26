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

    // Protected messages are never edited (design 7.4). Refused after the
    // permission and author checks (decision 18), before any embed claim,
    // write or event. A thread under a protected parent is refused as the
    // send route refuses it.
    if channel.is_protected()
        || message.encrypted.is_some()
        || (matches!(channel, Channel::Thread { .. }) && permission_channel.is_protected())
    {
        return Err(create_error!(ChannelProtected));
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

    use crate::{rocket, util::test::TestHarness};
    use iso8601_timestamp::Timestamp;
    use revolt_config::config;
    use revolt_database::{
        events::client::EventV1, util::antispam, Channel, Database, DmGuard, File, Member, Message,
        Metadata, PartialChannel, Report, Session, User, SYSTEM_USER_ID,
    };
    use revolt_models::v0::{self, ReportedContent};
    use revolt_permissions::{ChannelPermission, OverrideField};
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

    /// The route's full answer: status and body
    async fn edit_message(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        message_id: &str,
        data: &Value,
    ) -> (Status, String) {
        let response = harness
            .client
            .patch(format!("/channels/{channel_id}/messages/{message_id}"))
            .header(Header::new("x-session-token", session.token.clone()))
            .header(ContentType::JSON)
            .body(data.to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    #[track_caller]
    fn body(answer: &(Status, String)) -> Value {
        serde_json::from_str(&answer.1).unwrap_or_else(|_| panic!("not JSON: {:?}", answer))
    }

    /// An edit that would claim `attachment` for an embed
    fn edit_with_embed(attachment: &str) -> Value {
        json!({
            "content": "edited",
            "embeds": [{ "title": "embed", "media": attachment }]
        })
    }

    /// The stored row, whole
    async fn stored(harness: &TestHarness, message_id: &str) -> Value {
        serde_json::to_value(
            harness
                .db
                .fetch_message(message_id)
                .await
                .expect("the stored message"),
        )
        .expect("message JSON")
    }

    /// Whether `attachment` has been claimed by anything
    async fn is_claimed(harness: &TestHarness, attachment: &str) -> bool {
        harness
            .db
            .fetch_attachment("attachments", attachment)
            .await
            .expect("the attachment")
            .used_for
            .is_some()
    }

    /// An unclaimed file in the `attachments` bucket, as Autumn leaves an
    /// upload
    async fn upload_attachment(harness: &TestHarness, uploader: &User) -> String {
        let id = Ulid::new().to_string();
        harness
            .db
            .insert_attachment(&File {
                id: id.clone(),
                tag: "attachments".to_string(),
                filename: "embed.png".to_string(),
                hash: None,
                uploaded_at: Some(Timestamp::now_utc()),
                uploader_id: Some(uploader.id.clone()),
                used_for: None,
                deleted: None,
                reported: None,
                metadata: Metadata::File,
                content_type: "application/octet-stream".to_string(),
                size: 10,
                message_id: None,
                user_id: None,
                server_id: None,
                object_id: None,
            })
            .await
            .expect("insert attachment");
        id
    }

    /// A plaintext row by `author` in `channel_id`, stored through the driver
    async fn insert_plaintext(db: &Database, channel_id: &str, author: &str) -> Message {
        let message = Message {
            id: Ulid::new().to_string(),
            channel: channel_id.to_string(),
            author: author.to_string(),
            content: Some("Test message".to_string()),
            ..Default::default()
        };
        db.insert_message(&message)
            .await
            .expect("Failed to store test plaintext message");
        message
    }

    /// A plaintext row by `author` in thread `channel_id`, stored raw past
    /// the driver's floor (which judges a thread by its protected parent),
    /// as only a failed thread clean-up could leave one behind
    async fn insert_plaintext_raw(db: &Database, channel_id: &str, author: &str) -> Message {
        let message = Message {
            id: Ulid::new().to_string(),
            channel: channel_id.to_string(),
            author: author.to_string(),
            content: Some("Test message".to_string()),
            ..Default::default()
        };
        match db {
            Database::Reference(reference) => {
                reference
                    .messages
                    .lock()
                    .await
                    .insert(message.id.clone(), message.clone());
            }
            Database::MongoDb(mongo) => {
                mongo
                    .col::<Message>("messages")
                    .insert_one(&message)
                    .await
                    .expect("raw message row");
            }
        }
        message
    }

    /// Mark `channel_id` protected under its stored plaintext rows, raw, as
    /// the R15 compensation window can leave a stray behind
    async fn protect_under_stored_rows(db: &Database, channel_id: &str) {
        match db {
            Database::Reference(reference) => {
                match reference.channels.lock().await.get_mut(channel_id) {
                    Some(Channel::TextChannel { protected, .. }) => *protected = true,
                    other => panic!("expected a text channel, got {:?}", other),
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let result = mongo
                    .col::<Document>("channels")
                    .update_one(
                        doc! { "_id": channel_id },
                        doc! { "$set": { "protected": true } },
                    )
                    .await
                    .expect("raw protect");
                assert_eq!(result.matched_count, 1);
            }
        }

        assert!(db
            .fetch_channel(channel_id)
            .await
            .expect("channel")
            .is_protected());
    }

    /// A thread under `parent`, stored through the driver
    async fn insert_thread(db: &Database, parent: &Channel, creator: &User) -> Channel {
        let server = match parent {
            Channel::TextChannel { server, .. } => server.clone(),
            other => panic!("expected a text channel, got {:?}", other),
        };
        let thread = Channel::Thread {
            id: Ulid::new().to_string(),
            server,
            parent_channel: parent.id().to_string(),
            name: "Thread".to_string(),
            creator: creator.id.clone(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: 0,
            locked: false,
            applied_tags: vec![],
        };
        db.insert_channel(&thread).await.expect("thread");
        thread
    }

    async fn deny(harness: &TestHarness, channel_id: &str, permission: ChannelPermission) {
        let mut channel = harness
            .db
            .fetch_channel(channel_id)
            .await
            .expect("the channel");
        channel
            .update(
                &harness.db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: permission as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny");
    }

    /// Publish a marker `ChannelAck` on `user`'s private topic and wait for
    /// it: redis pub/sub is FIFO on the harness's one subscription, so
    /// anything the edit published before it is buffered once it is seen
    async fn flush_with_marker(harness: &mut TestHarness, user: &str, channel_id: &str) {
        let marker = Ulid::new().to_string();

        EventV1::ChannelAck {
            id: channel_id.to_string(),
            user: user.to_string(),
            message_id: marker.clone(),
        }
        .private(user.to_string())
        .await;

        harness
            .wait_for_event(&format!("{user}!"), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &marker,
                _ => false,
            })
            .await;
    }

    /// `author`'s edit of their own message is refused with
    /// `ChannelProtected` from this route, and leaves no trace: the row is
    /// unchanged, the embed's attachment unclaimed, no `MessageUpdate`
    async fn assert_refused_untouched(
        harness: &mut TestHarness,
        session: &Session,
        author: &User,
        channel_id: &str,
        message_id: &str,
    ) {
        let before = stored(harness, message_id).await;
        let attachment = upload_attachment(harness, author).await;

        let answer = edit_message(
            harness,
            session,
            channel_id,
            message_id,
            &edit_with_embed(&attachment),
        )
        .await;
        assert_eq!(answer.0, Status::BadRequest, "{:?}", answer);
        let value = body(&answer);
        assert_eq!(value["type"], "ChannelProtected", "{}", answer.1);
        assert!(
            value.get("location").is_none(),
            "the body must not carry the error location: {}",
            answer.1
        );

        assert_eq!(stored(harness, message_id).await, before, "row changed");
        assert!(
            !is_claimed(harness, &attachment).await,
            "the embed's attachment was claimed"
        );

        flush_with_marker(harness, &author.id, channel_id).await;
        harness.assert_no_buffered_event(channel_id, |event| match event {
            EventV1::MessageUpdate { id, .. } => id == message_id,
            _ => false,
        });
    }

    #[test]
    fn protected_edit_of_an_encrypted_message_is_refused() {
        crate::util::test::rt().block_on(protected_edit_of_an_encrypted_message_is_refused_case())
    }

    async fn protected_edit_of_an_encrypted_message_is_refused_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;

        let protected = harness.new_protected_channel(&owner, &session, &[]).await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let message = harness
            .new_encrypted_message(&protected.channel, &protected.owner_device, &group)
            .await;
        assert_eq!(message.author, owner.id);

        assert_refused_untouched(
            &mut harness,
            &session,
            &owner,
            protected.channel.id(),
            &message.id,
        )
        .await;
    }

    #[test]
    fn protected_edit_of_a_plaintext_stray_is_refused() {
        crate::util::test::rt().block_on(protected_edit_of_a_plaintext_stray_is_refused_case())
    }

    async fn protected_edit_of_a_plaintext_stray_is_refused_case() {
        // R15: a plaintext row left in a channel protected after it was
        // stored is not editable either
        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;

        let (_, channel) = harness.new_protectable_channel(&owner).await;
        let stray = insert_plaintext(&harness.db, channel.id(), &owner.id).await;
        protect_under_stored_rows(&harness.db, channel.id()).await;

        assert_refused_untouched(&mut harness, &session, &owner, channel.id(), &stray.id).await;
    }

    #[test]
    fn protected_edit_in_a_thread_under_a_protected_parent_is_refused() {
        crate::util::test::rt()
            .block_on(protected_edit_in_a_thread_under_a_protected_parent_is_refused_case())
    }

    async fn protected_edit_in_a_thread_under_a_protected_parent_is_refused_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;

        let protected = harness.new_protected_channel(&owner, &session, &[]).await;
        let thread = insert_thread(&harness.db, &protected.channel, &owner).await;
        let message = insert_plaintext_raw(&harness.db, thread.id(), &owner.id).await;

        assert_refused_untouched(&mut harness, &session, &owner, thread.id(), &message.id).await;
    }

    #[test]
    fn edit_in_an_unprotected_channel_is_applied() {
        crate::util::test::rt().block_on(edit_in_an_unprotected_channel_is_applied_case())
    }

    async fn edit_in_an_unprotected_channel_is_applied_case() {
        // The positive control for the refusals above: the same request
        // edits an ordinary message, claims the attachment and fans out
        let mut harness = TestHarness::new().await;
        let (_, session, author) = harness.new_user().await;

        let (server, channels) = harness.new_server(&author).await;
        let (channel, _, message) = harness.new_message(&author, &server, channels).await;
        assert!(!channel.is_protected());
        let attachment = upload_attachment(&harness, &author).await;

        let answer = edit_message(
            &harness,
            &session,
            channel.id(),
            &message.id,
            &edit_with_embed(&attachment),
        )
        .await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        assert_eq!(body(&answer)["content"], "edited", "{}", answer.1);

        let row = stored(&harness, &message.id).await;
        assert_eq!(row["content"], "edited");
        assert!(row["edited"].is_string(), "{}", row);
        assert!(is_claimed(&harness, &attachment).await);

        harness
            .wait_for_event(channel.id(), |event| match event {
                EventV1::MessageUpdate { id, .. } => id == &message.id,
                _ => false,
            })
            .await;
    }

    #[test]
    fn unauthorized_editors_get_the_same_answer_protected_or_not() {
        crate::util::test::rt()
            .block_on(unauthorized_editors_get_the_same_answer_protected_or_not_case())
    }

    async fn unauthorized_editors_get_the_same_answer_protected_or_not_case() {
        // Decision 18 (W2): a caller who fails the route's authorization
        // (SendMessage, then authorship) gets the pre-W2 answer, whatever
        // the channel's protection or the row's shape
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, session, member) = harness.new_user().await;

        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[])
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let encrypted = harness
            .new_encrypted_message(&protected.channel, &protected.owner_device, &group)
            .await;

        let flipped = harness.new_channel(&protected.server).await;
        let stray = insert_plaintext(&harness.db, flipped.id(), &owner.id).await;
        protect_under_stored_rows(&harness.db, flipped.id()).await;

        let thread = insert_thread(&harness.db, &protected.channel, &owner).await;
        let threaded = insert_plaintext_raw(&harness.db, thread.id(), &owner.id).await;

        let unprotected = harness.new_channel(&protected.server).await;
        let plaintext = insert_plaintext(&harness.db, unprotected.id(), &owner.id).await;

        harness.join_server(&protected.server, &member).await;

        let data = json!({ "content": "edited" });
        let cases = [
            ("encrypted", protected.channel.id(), &encrypted.id),
            ("stray", flipped.id(), &stray.id),
            ("thread", thread.id(), &threaded.id),
        ];

        // Not the author
        let baseline =
            edit_message(&harness, &session, unprotected.id(), &plaintext.id, &data).await;
        assert_ne!(baseline.0, Status::Ok, "{:?}", baseline);
        assert_eq!(
            body(&baseline)["type"],
            "CannotEditMessage",
            "{}",
            baseline.1
        );
        for (case, channel_id, message_id) in cases {
            let answer = edit_message(&harness, &session, channel_id, message_id, &data).await;
            assert_eq!(answer, baseline, "not the author: {}", case);
        }

        // No SendMessage (a thread takes its parent's permissions)
        for channel_id in [protected.channel.id(), flipped.id(), unprotected.id()] {
            deny(&harness, channel_id, ChannelPermission::SendMessage).await;
        }
        let baseline =
            edit_message(&harness, &session, unprotected.id(), &plaintext.id, &data).await;
        assert_eq!(baseline.0, Status::Forbidden, "{:?}", baseline);
        assert_eq!(
            body(&baseline)["type"],
            "MissingPermission",
            "{}",
            baseline.1
        );
        for (case, channel_id, message_id) in cases {
            let answer = edit_message(&harness, &session, channel_id, message_id, &data).await;
            assert_eq!(answer, baseline, "no SendMessage: {}", case);
        }

        // Nothing above reached a row
        for (case, _, message_id) in cases {
            let row = stored(&harness, message_id).await;
            assert!(row["edited"].is_null(), "{}: {}", case, row);
        }
    }
}
