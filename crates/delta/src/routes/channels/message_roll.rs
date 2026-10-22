use revolt_database::util::idempotency::IdempotencyKey;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Channel, Database, Message, MessageFlagsValue, User, AMQP};
use revolt_models::v0::{self, MessageFlags};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionQuery};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use ulid::Ulid;
use validator::Validate;

use crate::util::dice;

/// # Roll Dice
///
/// Rolls dice server-side and sends the result to the given channel
/// as a message authored by the caller.
///
/// The result message carries the `DiceRoll` flag. The regular message
/// send path rejects client-supplied flag values above 7, so this flag
/// is only ever set by this endpoint — a flagged message is a
/// guaranteed-authentic server roll that cannot be spoofed.
#[openapi(tag = "Messaging")]
#[post("/<target>/roll", data = "<data>")]
pub async fn message_roll(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataMessageRoll>,
    idempotency: IdempotencyKey,
) -> Result<Json<v0::Message>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

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

    // A roll is a plaintext message, which a protected channel never takes
    // (nor a thread under one, defense in depth like message_send). Refused
    // after the SendMessage check, so a caller who cannot send gets the same
    // answer either way (decision 18 (W2)), and before slowmode and the
    // nonce, so a refused roll claims neither.
    if channel.is_protected() || permission_channel.is_protected() {
        return Err(create_error!(ChannelProtected));
    }

    // Archived or locked threads reject rolls exactly like normal messages.
    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    crate::util::slowmode::enforce_slowmode(&user, &channel, &permissions).await?;

    // Roll server-side — this is the only place dice results are generated
    let outcome = dice::roll_notation(&data.notation)
        .map_err(|error| create_error!(FailedValidation { error }))?;
    let content = dice::format_roll(&outcome);

    let mut idempotency = idempotency;
    idempotency
        .consume_nonce(data.nonce)
        .await
        .map_err(|_| create_error!(InvalidOperation))?;

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
    flags.set(MessageFlags::DiceRoll, true);

    let mut message = Message {
        id: Ulid::new().to_string(),
        channel: channel.id().to_string(),
        author: user.id.clone(),
        content: Some(content),
        flags: Some(flags.0),
        nonce: Some(idempotency.into_key()),
        ..Default::default()
    };

    message
        .send(
            db,
            Some(amqp),
            v0::MessageAuthor::User(&author),
            Some(model_user.clone()),
            model_member.clone(),
            &channel,
            false,
        )
        .await?;

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
    fn roll_dice_creates_flagged_message() {
        crate::util::test::rt().block_on(roll_dice_creates_flagged_message_case())
    }

    async fn roll_dice_creates_flagged_message_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let response = harness
            .client
            .post(format!("/channels/{}/roll", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "notation": "2d6+3"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);

        let message: v0::Message = response.into_json().await.expect("`Message`");
        assert_eq!(message.author, user.id);

        // Message carries the DiceRoll flag
        let flags = MessageFlagsValue(message.flags);
        assert!(flags.has(MessageFlags::DiceRoll), "DiceRoll flag not set");

        // Content is the formatted server roll
        let content = message.content.expect("roll content");
        assert!(content.starts_with("🎲 `2d6+3` →"), "unexpected content: {content}");

        // Total in range: 2d6+3 => 5..=15
        let total: i64 = content
            .split("**")
            .nth(1)
            .expect("total in content")
            .parse()
            .expect("numeric total");
        assert!((5..=15).contains(&total), "total out of range: {total}");
    }

    #[test]
    fn roll_dice_rejects_invalid_notation() {
        crate::util::test::rt().block_on(roll_dice_rejects_invalid_notation_case())
    }

    async fn roll_dice_rejects_invalid_notation_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        for notation in ["garbage", "999d999", "0d6", ""] {
            let response = harness
                .client
                .post(format!("/channels/{}/roll", channel.id()))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(json!({ "notation": notation }).to_string())
                .dispatch()
                .await;

            assert_ne!(
                response.status(),
                Status::Ok,
                "notation '{notation}' should be rejected"
            );
        }
    }

    #[test]
    fn regular_send_cannot_forge_dice_flag() {
        crate::util::test::rt().block_on(regular_send_cannot_forge_dice_flag_case())
    }

    async fn regular_send_cannot_forge_dice_flag_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        // Attempt to send a normal message carrying the DiceRoll flag bit
        let response = harness
            .client
            .post(format!("/channels/{}/messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "content": "🎲 `1d20` → [20] = **20** — Natural 20! 🎉",
                    "flags": 16
                })
                .to_string(),
            )
            .dispatch()
            .await;

        // The send path rejects flags > 7 outright
        assert_ne!(
            response.status(),
            Status::Ok,
            "regular send must not accept the DiceRoll flag"
        );
    }
}

/// Protected channels (W2): a roll is refused after the SendMessage check
/// and before slowmode and the nonce (decision 18)
#[cfg(test)]
mod protected {
    use redis_kiss::{get_connection, AsyncCommands};
    use revolt_database::events::client::EventV1;
    use revolt_database::{
        Channel, MessageFilter, MessageQuery, MessageTimePeriod, PartialChannel, Session, User,
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
        /// Seated, no bypass of slowmode
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
            member,
            member_session,
        }
    }

    /// POST a roll; the status and the JSON body (`Null` when there is none)
    async fn roll(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        nonce: &str,
    ) -> (Status, Value) {
        let response = harness
            .client
            .post(format!("/channels/{channel_id}/roll"))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "notation": "1d20", "nonce": nonce }).to_string())
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
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
            .expect("the channel's messages")
            .len()
    }

    async fn slowmode_slot_held(user: &User, channel_id: &str) -> bool {
        let mut conn = get_connection().await.expect("redis").into_inner();
        conn.exists(format!("slowmode:{}:{}", user.id, channel_id))
            .await
            .expect("EXISTS")
    }

    /// Publish a marker on `user`'s private topic and wait for it: the
    /// harness reads every topic through one FIFO subscription, so anything
    /// the roll published before it is in the event buffer afterwards.
    async fn flush_with_marker(harness: &mut TestHarness, user: &User, channel_id: &str) {
        let marker = Ulid::new().to_string();
        EventV1::ChannelAck {
            id: channel_id.to_string(),
            user: user.id.clone(),
            message_id: marker.clone(),
        }
        .private(user.id.clone())
        .await;
        harness
            .wait_for_event(&format!("{}!", user.id), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &marker,
                _ => false,
            })
            .await;
    }

    /// A roll into a protected channel is the route's own `ChannelProtected`,
    /// with no message, no `Message` event, no slowmode slot and no nonce
    /// consumed
    #[test]
    fn protected_roll_is_refused_without_side_effects() {
        crate::util::test::rt().block_on(Box::pin(
            protected_roll_is_refused_without_side_effects_case(),
        ))
    }

    async fn protected_roll_is_refused_without_side_effects_case() {
        let mut f = fixture().await;
        let channel_id = f.protected.channel.id().to_string();
        set_slowmode(&f.harness, &f.protected.channel).await;
        let nonce = Ulid::new().to_string();

        let (status, body) = roll(&f.harness, &f.member_session, &channel_id, &nonce).await;
        assert_eq!(status, Status::BadRequest, "{body}");
        assert_eq!(body["type"], "ChannelProtected", "{body}");
        // The body never carries the error's `location`, so it cannot tell
        // the route's refusal from the database floor's
        assert!(
            body.get("location").is_none(),
            "the body must not carry the error location: {}",
            body
        );

        assert!(
            !slowmode_slot_held(&f.member, &channel_id).await,
            "a refused roll claimed a slowmode slot"
        );
        assert_eq!(stored_messages(&f.harness, &channel_id).await, 0);

        flush_with_marker(&mut f.harness, &f.member, &channel_id).await;
        f.harness
            .assert_no_buffered_event(&channel_id, |event| matches!(event, EventV1::Message(_)));
        f.harness
            .assert_no_buffered_event(&format!("{}!", f.member.id), |event| {
                matches!(event, EventV1::UserSlowmodes { .. })
            });

        // The nonce is still unused
        let (status, body) = roll(&f.harness, &f.member_session, f.ordinary.id(), &nonce).await;
        assert_eq!(
            status,
            Status::Ok,
            "the refused roll consumed its nonce: {body}"
        );
    }

    /// The same roll into an ordinary channel of the same server is sent
    #[test]
    fn ordinary_roll_beside_a_protected_channel_is_sent() {
        crate::util::test::rt().block_on(Box::pin(
            ordinary_roll_beside_a_protected_channel_is_sent_case(),
        ))
    }

    async fn ordinary_roll_beside_a_protected_channel_is_sent_case() {
        let f = fixture().await;
        let channel_id = f.ordinary.id().to_string();
        set_slowmode(&f.harness, &f.ordinary).await;

        let nonce = Ulid::new().to_string();
        let (status, body) = roll(&f.harness, &f.member_session, &channel_id, &nonce).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(body["author"], f.member.id.as_str(), "{body}");
        assert_eq!(stored_messages(&f.harness, &channel_id).await, 1);
        assert!(slowmode_slot_held(&f.member, &channel_id).await);
    }

    /// Decision 18 (W2): a caller who cannot send gets the pre-W2 answer,
    /// byte-identical for a protected and an ordinary channel
    #[test]
    fn protected_roll_non_sender_gets_the_pre_w2_error() {
        crate::util::test::rt().block_on(Box::pin(
            protected_roll_non_sender_gets_the_pre_w2_error_case(),
        ))
    }

    async fn protected_roll_non_sender_gets_the_pre_w2_error_case() {
        let f = fixture().await;
        deny_view(&f.harness, &f.protected.channel).await;
        deny_view(&f.harness, &f.ordinary).await;

        let protected = roll(
            &f.harness,
            &f.member_session,
            f.protected.channel.id(),
            &Ulid::new().to_string(),
        )
        .await;
        let ordinary = roll(
            &f.harness,
            &f.member_session,
            f.ordinary.id(),
            &Ulid::new().to_string(),
        )
        .await;
        assert_eq!(ordinary.0, Status::Forbidden, "{}", ordinary.1);
        assert_eq!(ordinary.1["type"], "MissingPermission", "{}", ordinary.1);
        assert!(ordinary.1.get("location").is_none(), "{}", ordinary.1);
        assert_eq!(protected, ordinary);
    }
}
