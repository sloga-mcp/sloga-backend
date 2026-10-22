use revolt_config::config;
use revolt_database::util::antispam;
use revolt_database::util::idempotency::IdempotencyKey;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Channel, Database, Message, MessageFlagsValue, Poll, User, AMQP};
use revolt_models::v0::{self, MessageFlags};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionQuery};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use ulid::Ulid;
use validator::Validate;

use crate::util::polls::now_ms;

/// # Create Poll
///
/// Creates a poll and sends the message carrying it to the given channel.
///
/// The result message carries the `Poll` flag and the embedded immutable
/// definition. The regular message send path rejects client-supplied flag
/// values above 7 and has no `poll` field, so a flagged poll message is
/// guaranteed to be a server-counted poll that cannot be spoofed.
#[openapi(tag = "Polls")]
#[post("/<target>/polls", data = "<data>")]
pub async fn poll_create(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataPollCreate>,
    idempotency: IdempotencyKey,
) -> Result<Json<v0::Message>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Per-answer constraints (the validator version in use cannot combine
    // `length` with nested validation on the same field).
    for answer in &data.answers {
        answer.validate().map_err(|error| {
            create_error!(FailedValidation {
                error: error.to_string()
            })
        })?;
    }

    // Same gate as sending a normal message
    let channel = target.as_channel(db).await?;

    // Forum channels have no message stream of their own — fail closed like
    // message_send.
    if matches!(channel, Channel::Forum { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    // Threads inherit their parent channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // Polls are server-counted plaintext, so a protected channel (or a thread
    // under one) refuses them here. This runs after the SendMessage check, so
    // a caller who cannot view the channel gets the same answer for a
    // protected channel as for any other (decision 18 (W2)), and before
    // slowmode and the nonce, which both claim at check time. Elsewhere
    // (DMs, groups) the composer still keeps polls out of encrypted chats.
    if channel.is_protected() || permission_channel.is_protected() {
        return Err(create_error!(ChannelProtected));
    }

    // Archived or locked threads reject polls exactly like normal messages.
    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    // A poll is a plaintext message too, so a paused account must not reach
    // strangers with one. Checked before anything is written (slowmode,
    // nonce, poll row, message).
    let antispam = config().await.features.antispam.clone();
    let dm_peer = if let Channel::DirectMessage { recipients, .. } = &channel {
        recipients.iter().find(|id| *id != &user.id).cloned()
    } else {
        None
    };

    if let Some(peer) = &dm_peer {
        antispam::dm_send_allowed(db, &antispam, &user, channel.id(), peer).await?;
    }

    crate::util::slowmode::enforce_slowmode(&user, &channel, &permissions).await?;

    let mut idempotency = idempotency;
    idempotency
        .consume_nonce(data.nonce)
        .await
        .map_err(|_| create_error!(InvalidOperation))?;

    // Assemble the immutable definition: answer ids are positional.
    let answers: Vec<v0::PollAnswer> = data
        .answers
        .into_iter()
        .enumerate()
        .map(|(index, answer)| v0::PollAnswer {
            id: index as u8,
            text: answer.text,
            emoji: answer.emoji,
        })
        .collect();

    let duration_hours = data
        .duration_hours
        .unwrap_or(v0::DEFAULT_POLL_DURATION_HOURS);
    let expires_at = now_ms() + (duration_hours as i64) * 60 * 60 * 1000;

    let server = match &channel {
        Channel::TextChannel { server, .. }
        | Channel::Thread { server, .. }
        | Channel::Forum { server, .. } => Some(server.clone()),
        _ => None,
    };

    let poll = Poll {
        id: Ulid::new().to_string(),
        message: Ulid::new().to_string(),
        channel: channel.id().to_string(),
        server,
        author: user.id.clone(),
        question: data.question,
        answers,
        allow_multiselect: data.allow_multiselect,
        expires_at,
        closed: false,
        counts: Default::default(),
        total_votes: 0,
    };

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

    let mut flags = MessageFlagsValue(0);
    flags.set(MessageFlags::Poll, true);

    // The poll row is inserted BEFORE the message is sent so any client
    // that reacts to the Message event can immediately fetch poll state.
    db.insert_poll(&poll).await?;

    let mut message = Message {
        id: poll.message.clone(),
        channel: channel.id().to_string(),
        author: user.id.clone(),
        // Mandatory fallback: legacy clients and the push-notification
        // path render content, so a poll must never be an empty message.
        content: Some(format!("📊 {}", poll.question)),
        flags: Some(flags.0),
        poll: Some(poll.definition()),
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
            &channel,
            false,
        )
        .await
    {
        // Best-effort: never leave a poll row without its carrying message
        // (crond would otherwise publish PollClose for a message that never
        // existed).
        let _ = db.delete_polls_for_messages(std::slice::from_ref(&poll.message)).await;
        return Err(error);
    }

    // Best-effort copy-paste detection on the stored message; never fails or
    // delays the request.
    if let Some(peer) = dm_peer {
        let (db, user, stored, channel_id) = (
            db.inner().clone(),
            user.clone(),
            message.clone(),
            channel.id().to_string(),
        );
        tokio::spawn(async move {
            antispam::observe_dm_message(&db, &antispam, &user, &channel_id, &peer, &stored)
                .await;
        });
    }

    Ok(Json(message.into_model(Some(model_user), model_member)))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use iso8601_timestamp::Timestamp;
    use revolt_config::config;
    use revolt_database::{
        Channel, DmGuard, Member, Message, MessageFilter, MessageFlagsValue, MessageQuery,
        MessageTimePeriod,
    };
    use revolt_models::v0::{self, MessageFlags};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;
    use ulid::Ulid;

    #[test]
    fn create_poll_creates_flagged_message_with_definition() {
        crate::util::test::rt().block_on(create_poll_creates_flagged_message_with_definition_case())
    }

    async fn create_poll_creates_flagged_message_with_definition_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let response = harness
            .client
            .post(format!("/channels/{}/polls", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "question": "Best crab?",
                    "answers": [
                        { "text": "Ferris" },
                        { "text": "Sebastian" }
                    ]
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);

        let message: v0::Message = response.into_json().await.expect("`Message`");
        assert_eq!(message.author, user.id);

        // Message carries the Poll flag and the embedded definition
        let flags = MessageFlagsValue(message.flags);
        assert!(flags.has(MessageFlags::Poll), "Poll flag not set");

        let poll = message.poll.expect("poll definition");
        assert_eq!(poll.question, "Best crab?");
        assert_eq!(poll.answers.len(), 2);
        assert_eq!(poll.answers[0].id, 0);
        assert_eq!(poll.answers[1].id, 1);
        assert!(!poll.allow_multiselect);

        // Fallback content for legacy clients / push notifications
        let content = message.content.expect("fallback content");
        assert!(content.contains("Best crab?"), "unexpected content: {content}");
    }

    #[test]
    fn create_poll_rejects_invalid_shapes() {
        crate::util::test::rt().block_on(create_poll_rejects_invalid_shapes_case())
    }

    async fn create_poll_rejects_invalid_shapes_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        for body in [
            // Too few answers
            json!({ "question": "?", "answers": [{ "text": "a" }] }),
            // Empty question
            json!({ "question": "", "answers": [{ "text": "a" }, { "text": "b" }] }),
            // Empty answer text
            json!({ "question": "?", "answers": [{ "text": "" }, { "text": "b" }] }),
            // Duration out of range
            json!({
                "question": "?",
                "answers": [{ "text": "a" }, { "text": "b" }],
                "duration_hours": 1000
            }),
        ] {
            let response = harness
                .client
                .post(format!("/channels/{}/polls", channel.id()))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
                .await;

            assert_ne!(response.status(), Status::Ok, "body should be rejected: {body}");
        }
    }

    #[test]
    fn regular_send_cannot_forge_poll_flag() {
        crate::util::test::rt().block_on(regular_send_cannot_forge_poll_flag_case())
    }

    async fn regular_send_cannot_forge_poll_flag_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        // Attempt to send a normal message carrying the Poll flag bit
        let response = harness
            .client
            .post(format!("/channels/{}/messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "content": "📊 fake poll",
                    "flags": 64
                })
                .to_string(),
            )
            .dispatch()
            .await;

        // The send path rejects flags > 7 outright
        assert_ne!(
            response.status(),
            Status::Ok,
            "regular send must not accept the Poll flag"
        );
    }

    async fn create_dm_poll<'a>(
        harness: &'a TestHarness,
        token: &str,
        channel_id: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .post(format!("/channels/{channel_id}/polls"))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "question": "Can I use your profile picture for an art project?",
                    "answers": [{ "text": "Yes" }, { "text": "No" }]
                })
                .to_string(),
            )
            .dispatch()
            .await
    }

    async fn messages_in(harness: &TestHarness, channel_id: &str) -> Vec<Message> {
        harness
            .db
            .fetch_messages(MessageQuery {
                limit: Some(10),
                filter: MessageFilter {
                    channel: Some(channel_id.to_string()),
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
    }

    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_poll_paused_refused() {
        crate::util::test::rt().block_on(antispam_route_poll_paused_refused_case())
    }

    async fn antispam_route_poll_paused_refused_case() {
        assert!(
            config().await.features.antispam.dm_dupe_enabled,
            "run with REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"
        );

        let harness = TestHarness::new().await;
        let (_, session, sender) = harness.new_user().await;
        let (_, _, stranger) = harness.new_user().await;

        // A shared server lets the sender DM the stranger without being
        // friends, the way the reported spammer reached its targets.
        let (server, _) = harness.new_server(&sender).await;
        Member::create(&harness.db, &server, &stranger, None)
            .await
            .expect("`Member`");

        let dm = Channel::create_dm(&harness.db, &sender, &stranger)
            .await
            .expect("dm");
        assert!(matches!(dm, Channel::DirectMessage { .. }), "not a DM");

        // Pause the sender directly; the session guard loads the user afresh
        // on every request.
        let guard = DmGuard {
            report_id: Ulid::new().to_string(),
            flagged_at: Timestamp::now_utc(),
            paused: true,
            cleared_at: None,
            recipients: 3,
            fingerprint: "test".into(),
        };
        assert!(
            harness
                .db
                .claim_dm_guard(&sender.id, &guard, Timestamp::now_utc())
                .await
                .expect("claim"),
            "guard not claimed"
        );

        // The stranger never wrote here: refused, with nothing written.
        let response = create_dm_poll(&harness, &session.token, dm.id()).await;
        assert_eq!(response.status(), Status::Forbidden);
        let error = response
            .into_json::<serde_json::Value>()
            .await
            .expect("error body");
        assert_eq!(error["type"], "DirectMessagesPaused");

        assert!(
            messages_in(&harness, dm.id()).await.is_empty(),
            "a refused poll stored a message"
        );
        assert!(
            harness
                .db
                .fetch_expired_open_polls(i64::MAX)
                .await
                .expect("polls")
                .iter()
                .all(|poll| poll.channel != dm.id()),
            "a refused poll stored a poll row"
        );

        // Once the stranger has written in the DM it is a real conversation,
        // and the same poll goes through.
        harness
            .db
            .insert_message(&Message {
                id: Ulid::new().to_string(),
                channel: dm.id().to_string(),
                author: stranger.id.clone(),
                content: Some("hello".into()),
                ..Default::default()
            })
            .await
            .expect("reply");

        let response = create_dm_poll(&harness, &session.token, dm.id()).await;
        assert_eq!(response.status(), Status::Ok);
    }
}

/// Protected channels (W2): polls are refused after the SendMessage check
/// and before any side effect
#[cfg(test)]
mod protected_test {
    use revolt_database::events::client::EventV1;
    use revolt_database::{
        Channel, Database, MessageFilter, MessageQuery, MessageTimePeriod, PartialChannel, Session,
        User,
    };
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    use crate::util::test::{ProtectedChannel, TestHarness};

    struct Fixture {
        harness: TestHarness,
        protected: ProtectedChannel,
        /// An unprotected channel of the same server
        ordinary: Channel,
        owner: User,
        /// A seated member without `BypassSlowmode`
        member: User,
        member_session: Session,
    }

    async fn fixture() -> Fixture {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let ordinary = harness.new_channel(&protected.server).await;

        Fixture {
            harness,
            protected,
            ordinary,
            owner,
            member,
            member_session,
        }
    }

    /// POST a poll; returns the status and the JSON body (`Null` when there
    /// is none)
    async fn post_poll(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        nonce: &str,
    ) -> (Status, Value) {
        let response = harness
            .client
            .post(format!("/channels/{channel_id}/polls"))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "nonce": nonce,
                    "question": "Best crab?",
                    "answers": [{ "text": "Ferris" }, { "text": "Sebastian" }]
                })
                .to_string(),
            )
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }

    fn assert_refused(answer: &(Status, Value), status: Status, error: &str, case: &str) {
        assert_eq!(answer.0, status, "{case}: {}", answer.1);
        assert_eq!(answer.1["type"], error, "{case}: {}", answer.1);
    }

    fn assert_created(answer: &(Status, Value), case: &str) {
        assert_eq!(answer.0, Status::Ok, "{case}: {}", answer.1);
        assert!(answer.1["poll"].is_object(), "{case}: {}", answer.1);
    }

    async fn stored_messages(harness: &TestHarness, channel_id: &str) -> usize {
        harness
            .db
            .fetch_messages(MessageQuery {
                limit: Some(10),
                filter: MessageFilter {
                    channel: Some(channel_id.to_string()),
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

    /// Poll rows of `channel_id`, read straight from the driver's storage
    async fn stored_polls(harness: &TestHarness, channel_id: &str) -> usize {
        match &harness.db {
            Database::Reference(reference) => reference
                .polls
                .lock()
                .await
                .values()
                .filter(|poll| poll.channel == channel_id)
                .count(),
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                mongo
                    .col::<Document>("polls")
                    .count_documents(doc! { "channel": channel_id })
                    .await
                    .expect("count polls") as usize
            }
        }
    }

    /// Publish a marker `ChannelAck` on `user`'s private topic and wait for
    /// it: the harness reads every topic through one subscription and redis
    /// pub/sub is FIFO on it, so anything the request published before the
    /// marker is then in the buffer for `assert_no_buffered_event`
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

    async fn set_slowmode(harness: &TestHarness, channel: &Channel) {
        channel
            .clone()
            .update(
                &harness.db,
                PartialChannel {
                    slowmode: Some(600),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("slowmode");
    }

    fn thread_under(parent: &Channel, server_id: &str, creator: &User) -> Channel {
        Channel::Thread {
            id: Ulid::new().to_string(),
            server: server_id.to_string(),
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
        }
    }

    async fn deny_view(harness: &TestHarness, channel: &Channel) {
        channel
            .clone()
            .update(
                &harness.db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ViewChannel as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny view");
    }

    /// A protected channel refuses a poll with `ChannelProtected`: no poll
    /// row, no message, no `Message` event, no slowmode slot (its
    /// `UserSlowmodes` event) and no consumed nonce
    #[test]
    fn protected_poll_is_refused_before_any_side_effect() {
        crate::util::test::rt().block_on(Box::pin(
            protected_poll_is_refused_before_any_side_effect_case(),
        ))
    }

    async fn protected_poll_is_refused_before_any_side_effect_case() {
        let f = fixture().await;
        let mut h = f.harness;
        let channel_id = f.protected.channel.id().to_string();
        set_slowmode(&h, &f.protected.channel).await;
        let nonce = Ulid::new().to_string();

        assert_refused(
            &post_poll(&h, &f.member_session, &channel_id, &nonce).await,
            Status::BadRequest,
            "ChannelProtected",
            "a poll in a protected channel",
        );
        assert_eq!(stored_messages(&h, &channel_id).await, 0, "message row");
        assert_eq!(stored_polls(&h, &channel_id).await, 0, "poll row");

        flush_with_marker(&mut h, &f.member.id, &channel_id).await;
        h.assert_no_buffered_event(&format!("{}!", f.member.id), |event| {
            matches!(event, EventV1::UserSlowmodes { .. })
        });
        h.assert_no_buffered_event(&channel_id, |event| matches!(event, EventV1::Message(_)));

        // The nonce was never consumed: the same request succeeds elsewhere
        assert_created(
            &post_poll(&h, &f.member_session, f.ordinary.id(), &nonce).await,
            "the refused poll's nonce in an ordinary channel",
        );
    }

    /// A thread under a protected parent refuses a poll; one under an
    /// ordinary parent accepts it
    #[test]
    fn protected_poll_in_a_thread_under_a_protected_parent_is_refused() {
        crate::util::test::rt().block_on(Box::pin(
            protected_poll_in_a_thread_under_a_protected_parent_is_refused_case(),
        ))
    }

    async fn protected_poll_in_a_thread_under_a_protected_parent_is_refused_case() {
        let f = fixture().await;
        let h = &f.harness;
        let server_id = &f.protected.server.id;

        // No such thread can exist (2.5 "Race closure"): inserted raw
        let protected_thread = thread_under(&f.protected.channel, server_id, &f.owner);
        h.db.insert_channel(&protected_thread)
            .await
            .expect("thread");
        let ordinary_thread = thread_under(&f.ordinary, server_id, &f.owner);
        h.db.insert_channel(&ordinary_thread).await.expect("thread");

        assert_refused(
            &post_poll(
                h,
                &f.member_session,
                protected_thread.id(),
                &Ulid::new().to_string(),
            )
            .await,
            Status::BadRequest,
            "ChannelProtected",
            "a thread under a protected parent",
        );
        assert_eq!(stored_polls(h, protected_thread.id()).await, 0, "poll row");
        assert_created(
            &post_poll(
                h,
                &f.member_session,
                ordinary_thread.id(),
                &Ulid::new().to_string(),
            )
            .await,
            "a thread under an ordinary parent",
        );
    }

    /// Positive control: the same member's same request in an unprotected
    /// channel (slowmode on) of the same server creates the poll
    #[test]
    fn protected_poll_positive_control_in_an_ordinary_channel() {
        crate::util::test::rt().block_on(Box::pin(
            protected_poll_positive_control_in_an_ordinary_channel_case(),
        ))
    }

    async fn protected_poll_positive_control_in_an_ordinary_channel_case() {
        let f = fixture().await;
        let h = &f.harness;
        set_slowmode(h, &f.ordinary).await;

        assert_created(
            &post_poll(
                h,
                &f.member_session,
                f.ordinary.id(),
                &Ulid::new().to_string(),
            )
            .await,
            "a poll in an ordinary channel",
        );
        assert_eq!(stored_messages(h, f.ordinary.id()).await, 1, "message row");
        assert_eq!(stored_polls(h, f.ordinary.id()).await, 1, "poll row");
    }

    /// Decision 18 (W2): a caller who cannot view the channel gets the
    /// pre-W2 answer, byte-identical (incl. `location`) for a protected and
    /// an ordinary channel
    #[test]
    fn protected_poll_non_viewer_gets_the_pre_w2_error() {
        crate::util::test::rt().block_on(Box::pin(
            protected_poll_non_viewer_gets_the_pre_w2_error_case(),
        ))
    }

    async fn protected_poll_non_viewer_gets_the_pre_w2_error_case() {
        let f = fixture().await;
        let h = &f.harness;
        deny_view(h, &f.protected.channel).await;
        deny_view(h, &f.ordinary).await;

        let protected = post_poll(
            h,
            &f.member_session,
            f.protected.channel.id(),
            &Ulid::new().to_string(),
        )
        .await;
        let ordinary = post_poll(
            h,
            &f.member_session,
            f.ordinary.id(),
            &Ulid::new().to_string(),
        )
        .await;

        assert_refused(
            &ordinary,
            Status::Forbidden,
            "MissingPermission",
            "a non-viewer",
        );
        assert!(ordinary.1.get("location").is_none(), "{}", ordinary.1);
        assert_eq!(protected, ordinary, "protected vs ordinary");
    }
}
