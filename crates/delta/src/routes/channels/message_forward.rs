use iso8601_timestamp::Timestamp;
use revolt_config::config;
use revolt_database::events::client::EventV1;
use revolt_database::util::antispam;
use revolt_database::util::idempotency::IdempotencyKey;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{
    Channel, Database, File, FileUsedFor, FileUsedForType, ForwardedSnapshot, Message, User, AMQP,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionQuery};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use ulid::Ulid;
use validator::Validate;

/// # Forward Message
///
/// Forwards a message to another channel as a new message carrying an
/// immutable, server-copied snapshot of the original.
///
/// The forwarder must be able to actually READ the source (ViewChannel +
/// ReadMessageHistory on the source channel) and send in the destination.
/// The `forwarded` snapshot is absent from the regular send/edit payloads,
/// so it can only ever be constructed here — a message carrying it is
/// guaranteed-authentic provenance (same mechanism as the DiceRoll flag).
#[openapi(tag = "Messaging")]
#[post("/<target>/messages/<msg>/forward", data = "<data>")]
pub async fn message_forward(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
    data: Json<v0::DataMessageForward>,
    idempotency: IdempotencyKey,
) -> Result<Json<v0::Message>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Resolve the source and verify the forwarder can actually read it —
    // this is the provenance check. Threads inherit their parent channel's
    // permission overrides.
    let source_channel = target.as_channel(db).await?;
    let source_message = msg.as_message_in_channel(db, source_channel.id()).await?;

    let source_permission_channel = source_channel.permission_target(db).await?.into_owned();
    let mut source_query =
        DatabasePermissionQuery::new(db, &user).channel(&source_permission_channel);
    let source_permissions = calculate_channel_permissions(&mut source_query).await;
    source_permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    source_permissions
        .throw_if_lacking_channel_permission(ChannelPermission::ReadMessageHistory)?;

    // System messages and polls don't forward (poll state wouldn't travel
    // with the snapshot; system messages are channel-local narration).
    if source_message.system.is_some() || source_message.poll.is_some() {
        return Err(create_error!(InvalidOperation));
    }

    // Resolve the destination and run the same gates as sending a message.
    // (Forwarding into the source channel itself is allowed — it's a plain
    // re-post and all gates apply uniformly.)
    let destination = Reference::from_unchecked(&data.destination)
        .as_channel(db)
        .await?;

    // Forum channels have no message stream of their own — fail closed like
    // message_send.
    if matches!(destination, Channel::Forum { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    let permission_channel = destination.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // Archived or locked threads reject forwards exactly like normal
    // messages.
    crate::util::threads::ensure_thread_writable(&destination, &permissions)?;

    // An account paused for copy-paste DMs cannot forward into a DM with a
    // stranger who never wrote back either, exactly like a live send.
    // Checked before any side effect (slowmode, nonce, minted files).
    let antispam_config = config().await.features.antispam.clone();
    let dm_peer = if let Channel::DirectMessage { recipients, .. } = &destination {
        recipients.iter().find(|id| *id != &user.id).cloned()
    } else {
        None
    };

    if let Some(peer) = &dm_peer {
        antispam::dm_send_allowed(db, &antispam_config, &user, destination.id(), peer).await?;
    }

    crate::util::slowmode::enforce_slowmode(&user, &destination, &permissions).await?;

    // Forward-of-forward keeps FIRST-hop provenance (Discord semantics):
    // copy the original snapshot rather than snapshotting the forward.
    let (base_content, base_attachments, origin_message_id, origin_channel_id, origin_server_id, origin_author_id, original_sent_at) =
        if let Some(original) = source_message.forwarded {
            (
                original.content,
                original.attachments,
                original.message_id,
                original.channel_id,
                original.server_id,
                original.author_id,
                original.original_sent_at,
            )
        } else {
            let server_id = match &source_channel {
                Channel::TextChannel { server, .. }
                | Channel::Thread { server, .. }
                | Channel::Forum { server, .. } => Some(server.clone()),
                _ => None,
            };

            // Webhook-authored messages have no user author to attribute.
            let author_id = if source_message.webhook.is_some() {
                None
            } else {
                Some(source_message.author.clone())
            };

            let sent_at = Ulid::from_string(&source_message.id)
                .map(|ulid| ulid.timestamp_ms() as i64)
                .unwrap_or_default();

            (
                source_message.content,
                source_message.attachments.unwrap_or_default(),
                source_message.id,
                source_message.channel,
                server_id,
                author_id,
                sent_at,
            )
        };

    // Nothing to carry — embed-only or component-only sources don't
    // snapshot meaningfully.
    if base_content.as_ref().is_none_or(|content| content.is_empty())
        && base_attachments.is_empty()
    {
        return Err(create_error!(InvalidOperation));
    }

    if !base_attachments.is_empty() {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::UploadFiles)?;
    }

    let mut idempotency = idempotency;
    idempotency
        .consume_nonce(data.nonce)
        .await
        .map_err(|_| create_error!(InvalidOperation))?;

    let forward_message_id = Ulid::new().to_string();

    // Mint NEW file documents for the snapshot rather than sharing the
    // source's: `used_for` is single-owner, so sharing would make deleting
    // either message S3-delete what the other still displays. Fresh docs +
    // hash refcounting keep the object alive while either side references
    // it.
    let mut snapshot_attachments = Vec::with_capacity(base_attachments.len());
    for source_file in &base_attachments {
        let file = File {
            id: Ulid::new().to_string(),
            tag: source_file.tag.clone(),
            filename: source_file.filename.clone(),
            hash: source_file.hash.clone(),
            uploaded_at: Some(Timestamp::now_utc()),
            uploader_id: Some(user.id.clone()),
            used_for: Some(FileUsedFor {
                object_type: FileUsedForType::Message,
                id: forward_message_id.clone(),
            }),
            deleted: None,
            reported: None,
            metadata: source_file.metadata.clone(),
            content_type: source_file.content_type.clone(),
            size: source_file.size,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        };

        db.insert_attachment(&file).await?;
        snapshot_attachments.push(file);
    }

    // Build author objects for the event fan-out
    let author: v0::User = user.clone().into(db, Some(&user)).await;

    // Make sure we have server member (edge case if server owner)
    query.are_we_a_member().await;

    let model_user = user
        .clone()
        .into_known_static(revolt_presence::is_online(&user.id).await)
        .await;

    let model_member: Option<v0::Member> = query
        .member_ref()
        .as_ref()
        .map(|member| member.clone().into_owned().into());

    let mut message = Message {
        id: forward_message_id,
        channel: destination.id().to_string(),
        author: user.id.clone(),
        forwarded: Some(ForwardedSnapshot {
            message_id: origin_message_id,
            channel_id: origin_channel_id,
            server_id: origin_server_id,
            author_id: origin_author_id,
            content: base_content,
            attachments: snapshot_attachments,
            original_sent_at,
        }),
        nonce: Some(idempotency.into_key()),
        ..Default::default()
    };

    if let Err(error) = message
        .send(
            db,
            Some(amqp),
            v0::MessageAuthor::User(&author),
            Some(model_user.clone()),
            model_member.clone(),
            &destination,
            false,
        )
        .await
    {
        // Never leave minted file copies pointing at a message that was
        // never persisted — they carry `used_for`, so no pruner would
        // ever collect them.
        if let Some(snapshot) = &message.forwarded {
            let minted: Vec<String> = snapshot
                .attachments
                .iter()
                .map(|file| file.id.clone())
                .collect();
            if !minted.is_empty() {
                db.mark_attachments_as_deleted(&minted).await.ok();
            }
        }
        return Err(error);
    }

    // Count the forwarded text toward copy-paste DM detection (it lives in
    // `forwarded.content`, which `dm_text` reads). Spawned so it never fails
    // or delays the forward. A forward is always a server-built plaintext
    // snapshot, never an end-to-end encrypted envelope.
    if let Some(peer) = dm_peer {
        let (db, user, message, channel_id) = (
            db.inner().clone(),
            user.clone(),
            message.clone(),
            destination.id().to_string(),
        );

        tokio::spawn(async move {
            antispam::observe_dm_message(
                &db,
                &antispam_config,
                &user,
                &channel_id,
                &peer,
                &message,
            )
            .await;
        });
    }

    // Forwarding into a thread joins you to it, exactly like a live send
    // (Discord parity — you start receiving its notifications).
    if let Channel::Thread { server, .. } = &destination {
        if db
            .join_thread_if_absent(destination.id(), &user.id)
            .await?
        {
            EventV1::ThreadMemberJoin {
                id: destination.id().to_string(),
                user: user.id.clone(),
            }
            .p(server.clone())
            .await;
        }
    }

    Ok(Json(message.into_model(Some(model_user), model_member)))
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use crate::{rocket, util::test::TestHarness};
    use revolt_config::config;
    use revolt_database::iso8601_timestamp::Timestamp;
    use revolt_database::{
        Channel, DmGuard, Member, MessageFilter, MessageQuery, MessageTimePeriod, Session, User,
        SYSTEM_USER_ID,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    #[test]
    fn forward_carries_snapshot_and_requires_source_read() {
        crate::util::test::rt().block_on(forward_carries_snapshot_and_requires_source_read_case())
    }

    async fn forward_carries_snapshot_and_requires_source_read_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, channels) = harness.new_server(&user).await;
        let destination = harness.new_channel(&server).await;
        let (_, _, message) = harness.new_message(&user, &server, channels.clone()).await;
        let source_channel = &channels[0];

        let response = harness
            .client
            .post(format!(
                "/channels/{}/messages/{}/forward",
                source_channel.id(),
                message.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "destination": destination.id() }).to_string())
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);

        let forwarded: v0::Message = response.into_json().await.expect("`Message`");
        assert_eq!(forwarded.author, user.id);
        assert_eq!(forwarded.channel, destination.id());
        assert!(forwarded.content.is_none());

        let snapshot = forwarded.forwarded.expect("snapshot");
        assert_eq!(snapshot.message_id, message.id);
        assert_eq!(snapshot.channel_id, source_channel.id());
        assert_eq!(snapshot.author_id.as_deref(), Some(user.id.as_str()));
        assert_eq!(snapshot.content, message.content);
        assert!(snapshot.original_sent_at > 0);
    }

    #[test]
    fn forward_of_forward_keeps_first_hop_provenance() {
        crate::util::test::rt().block_on(forward_of_forward_keeps_first_hop_provenance_case())
    }

    async fn forward_of_forward_keeps_first_hop_provenance_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, channels) = harness.new_server(&user).await;
        let hop1 = harness.new_channel(&server).await;
        let hop2 = harness.new_channel(&server).await;
        let (_, _, original) = harness.new_message(&user, &server, channels.clone()).await;
        let source_channel = &channels[0];

        let response = harness
            .client
            .post(format!(
                "/channels/{}/messages/{}/forward",
                source_channel.id(),
                original.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "destination": hop1.id() }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let first: v0::Message = response.into_json().await.expect("`Message`");

        // Forward the forward
        let response = harness
            .client
            .post(format!(
                "/channels/{}/messages/{}/forward",
                hop1.id(),
                first.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "destination": hop2.id() }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let second: v0::Message = response.into_json().await.expect("`Message`");

        // Provenance still points at the ORIGINAL message, not the forward
        let snapshot = second.forwarded.expect("snapshot");
        assert_eq!(snapshot.message_id, original.id);
        assert_eq!(snapshot.channel_id, source_channel.id());
    }

    #[test]
    fn forward_denied_without_source_visibility() {
        crate::util::test::rt().block_on(forward_denied_without_source_visibility_case())
    }

    async fn forward_denied_without_source_visibility_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, other_session, other_user) = harness.new_user().await;
        let (server, channels) = harness.new_server(&owner).await;
        let (_, _, message) = harness.new_message(&owner, &server, channels.clone()).await;
        let source_channel = &channels[0];

        // A destination the outsider CAN send to: their own group.
        let group = revolt_database::Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: "Test Group".to_string(),
                ..Default::default()
            },
            other_user.id.clone(),
        )
        .await
        .expect("Failed to create group");

        // The outsider is not a member of the server, so they cannot read
        // the source channel — the forward must be denied.
        let response = harness
            .client
            .post(format!(
                "/channels/{}/messages/{}/forward",
                source_channel.id(),
                message.id
            ))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .header(ContentType::JSON)
            .body(json!({ "destination": group.id() }).to_string())
            .dispatch()
            .await;

        assert_ne!(
            response.status(),
            Status::Ok,
            "forward must require read access on the source"
        );
    }

    #[test]
    fn regular_send_cannot_forge_forwarded_snapshot() {
        crate::util::test::rt().block_on(regular_send_cannot_forge_forwarded_snapshot_case())
    }

    async fn regular_send_cannot_forge_forwarded_snapshot_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        // Attempt to send a normal message with a `forwarded` field — the
        // field is not part of DataMessageSend, so serde ignores it and no
        // snapshot may appear on the resulting message.
        let response = harness
            .client
            .post(format!("/channels/{}/messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "content": "fake forward",
                    "forwarded": {
                        "message_id": "01FAKE00000000000000000000",
                        "channel_id": "01FAKE00000000000000000000",
                        "original_sent_at": 0
                    }
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let message: v0::Message = response.into_json().await.expect("`Message`");
        assert!(
            message.forwarded.is_none(),
            "regular send must not accept a forwarded snapshot"
        );
    }

    /// Long enough to fingerprint: the copy-paste scam the detector targets
    const SCAM: &str = "Hi! I love your profile picture, can I use it for an art project for my client? I'll pay you and credit you.";

    struct ForwardFixture {
        session: Session,
        sender: User,
        /// Server channel holding the message to forward
        source: Channel,
        message_id: String,
        /// Users who share only the server with the sender (so DMs are
        /// allowed, but they are not friends), each with their session and
        /// their DM with the sender
        strangers: Vec<(Session, User, Channel)>,
    }

    async fn forward_fixture(harness: &TestHarness, strangers: usize) -> ForwardFixture {
        let (_, session, sender) = harness.new_user().await;
        let (server, channels) = harness.new_server(&sender).await;
        Member::create(&harness.db, &server, &sender, Some(channels.clone()))
            .await
            .expect("sender membership");
        let source = channels[0].clone();

        let response = harness
            .client
            .post(format!("/channels/{}/messages", source.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "content": SCAM }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let message: v0::Message = response.into_json().await.expect("`Message`");

        let mut dms = Vec::with_capacity(strangers);
        for _ in 0..strangers {
            let (_, stranger_session, stranger) = harness.new_user().await;
            Member::create(&harness.db, &server, &stranger, None)
                .await
                .expect("stranger membership");
            let dm = Channel::create_dm(&harness.db, &sender, &stranger)
                .await
                .expect("DM channel");
            dms.push((stranger_session, stranger, dm));
        }

        ForwardFixture {
            session,
            sender,
            source,
            message_id: message.id,
            strangers: dms,
        }
    }

    async fn forward_to(
        harness: &TestHarness,
        fixture: &ForwardFixture,
        destination: &str,
    ) -> (Status, serde_json::Value) {
        let response = harness
            .client
            .post(format!(
                "/channels/{}/messages/{}/forward",
                fixture.source.id(),
                fixture.message_id
            ))
            .header(Header::new(
                "x-session-token",
                fixture.session.token.to_string(),
            ))
            .header(ContentType::JSON)
            .body(json!({ "destination": destination }).to_string())
            .dispatch()
            .await;

        let status = response.status();
        let body = response
            .into_json::<serde_json::Value>()
            .await
            .unwrap_or_default();
        (status, body)
    }

    async fn messages_in(harness: &TestHarness, channel_id: &str, author: &str) -> usize {
        harness
            .db
            .fetch_messages(MessageQuery {
                limit: Some(10),
                filter: MessageFilter {
                    channel: Some(channel_id.to_string()),
                    author: Some(author.to_string()),
                    ..Default::default()
                },
                time_period: MessageTimePeriod::Absolute {
                    before: None,
                    after: None,
                    sort: None,
                },
            })
            .await
            .expect("messages")
            .len()
    }

    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_forward_paused_refused() {
        crate::util::test::rt().block_on(antispam_route_forward_paused_refused_case())
    }

    async fn antispam_route_forward_paused_refused_case() {
        assert!(
            config().await.features.antispam.dm_dupe_enabled,
            "run with REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"
        );

        let harness = TestHarness::new().await;
        let fixture = forward_fixture(&harness, 2).await;
        let (_, _, silent_dm) = &fixture.strangers[0];
        let (replier_session, _, replier_dm) = &fixture.strangers[1];

        // The second stranger wrote first: a real conversation
        let response = harness
            .client
            .post(format!("/channels/{}/messages", replier_dm.id()))
            .header(Header::new(
                "x-session-token",
                replier_session.token.to_string(),
            ))
            .header(ContentType::JSON)
            .body(json!({ "content": "hello there" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // Pause the sender directly; the route re-reads the user per request
        let now = Timestamp::now_utc();
        let claimed = harness
            .db
            .claim_dm_guard(
                &fixture.sender.id,
                &DmGuard {
                    report_id: ulid::Ulid::new().to_string(),
                    flagged_at: now,
                    paused: true,
                    cleared_at: None,
                    recipients: 3,
                    fingerprint: "test".into(),
                },
                now,
            )
            .await
            .expect("claim");
        assert!(claimed);

        // Silent stranger: refused, and nothing was written into the DM
        let (status, body) = forward_to(&harness, &fixture, silent_dm.id()).await;
        assert_eq!(status, Status::Forbidden, "body: {body}");
        assert_eq!(body["type"], "DirectMessagesPaused", "body: {body}");
        assert_eq!(
            messages_in(&harness, silent_dm.id(), &fixture.sender.id).await,
            0
        );

        // A stranger who wrote back stays reachable
        let (status, body) = forward_to(&harness, &fixture, replier_dm.id()).await;
        assert_eq!(status, Status::Ok, "body: {body}");
        assert_eq!(
            messages_in(&harness, replier_dm.id(), &fixture.sender.id).await,
            1
        );

        // The pause is about DMs only: a server channel still takes forwards
        let (status, body) = forward_to(&harness, &fixture, fixture.source.id()).await;
        assert_eq!(status, Status::Ok, "body: {body}");
    }

    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_forward_counts_toward_flag() {
        crate::util::test::rt().block_on(antispam_route_forward_counts_toward_flag_case())
    }

    async fn antispam_route_forward_counts_toward_flag_case() {
        assert!(
            config().await.features.antispam.dm_dupe_enabled,
            "run with REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"
        );

        let harness = TestHarness::new().await;
        let fixture = forward_fixture(&harness, 4).await;

        // Forward the same text into three silent strangers' DMs
        for (_, _, dm) in &fixture.strangers[..3] {
            let (status, body) = forward_to(&harness, &fixture, dm.id()).await;
            assert_eq!(status, Status::Ok, "body: {body}");
        }

        // The observer is spawned: wait for the guard it claims
        let deadline = Instant::now() + Duration::from_secs(15);
        let guard = loop {
            let sender = harness
                .db
                .fetch_user(&fixture.sender.id)
                .await
                .expect("sender");
            if let Some(guard) = sender.dm_guard {
                break guard;
            }

            assert!(
                Instant::now() < deadline,
                "no DM guard after forwarding into 3 silent strangers' DMs"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(guard.recipients, 3);
        assert!(guard.cleared_at.is_none());

        // The system report behind the guard is in the staff queue. The
        // observer claims the guard BEFORE it files the report, so the report
        // can lag the guard: wait for it too
        let deadline = Instant::now() + Duration::from_secs(15);
        let report = loop {
            if let Ok(report) = harness.db.fetch_report(&guard.report_id).await {
                break report;
            }

            assert!(
                Instant::now() < deadline,
                "no system report {} behind the DM guard",
                guard.report_id
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(report.author_id, SYSTEM_USER_ID);
        let v0::ReportedContent::User { id, .. } = &report.content else {
            panic!("report must name a user: {:?}", report.content);
        };
        assert_eq!(id, &fixture.sender.id);

        // With pausing configured, the next silent stranger is refused
        if guard.paused {
            let (_, _, fourth_dm) = &fixture.strangers[3];
            let (status, body) = forward_to(&harness, &fixture, fourth_dm.id()).await;
            assert_eq!(status, Status::Forbidden, "body: {body}");
            assert_eq!(body["type"], "DirectMessagesPaused", "body: {body}");
        }
    }
}
