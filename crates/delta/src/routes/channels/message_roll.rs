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

    #[rocket::async_test]
    async fn roll_dice_creates_flagged_message() {
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

    #[rocket::async_test]
    async fn roll_dice_rejects_invalid_notation() {
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

    #[rocket::async_test]
    async fn regular_send_cannot_forge_dice_flag() {
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
