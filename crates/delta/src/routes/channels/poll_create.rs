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

    // NOTE: E2EE exclusion (polls are server-counted plaintext) is enforced
    // client-side by the composer, matching message_send — the server cannot
    // reliably know a conversation's encryption state.

    // Threads inherit their parent channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // Archived or locked threads reject polls exactly like normal messages.
    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

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

    Ok(Json(message.into_model(Some(model_user), model_member)))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::MessageFlagsValue;
    use revolt_models::v0::{self, MessageFlags};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

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
}
