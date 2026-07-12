use std::time::{SystemTime, UNIX_EPOCH};

use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{
    Channel, Database, InteractionKind, Message, MessageFlagsValue, MessageInteraction, User, AMQP,
};
use revolt_models::v0::{self, MessageFlags};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionQuery};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use ulid::Ulid;
use validator::Validate;

/// # Respond to Interaction
///
/// Respond to an interaction as its target bot. Requires the bot's session
/// (bot token) AND the interaction's single-use response token; the response
/// window closes 15 minutes after invocation.
///
/// The reply is a regular channel message carrying the unforgeable
/// `Interaction` flag and `command_context` ("used /cmd") — the regular send
/// path rejects both, so their presence proves authenticity.
#[openapi(tag = "Interactions")]
#[post("/<target>/respond", data = "<data>")]
pub async fn interaction_respond(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataInteractionRespond>,
) -> Result<Json<v0::Message>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Only bots respond to interactions.
    if user.bot.is_none() {
        return Err(create_error!(IsNotBot));
    }

    let interaction = db.fetch_interaction(target.id).await?;

    // Wrong-bot probes get NotFound (no existence leak), and the token check
    // is constant-time — the two combined defeat cross-bot response forgery.
    if interaction.bot_id != user.id {
        return Err(create_error!(NotFound));
    }
    interaction.assert_token(&data.token)?;

    if !matches!(interaction.kind, InteractionKind::Command) {
        return Err(create_error!(InvalidOperation));
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    if interaction.is_expired(now_ms) {
        return Err(create_error!(InteractionExpired));
    }

    // Re-check the bot's standing NOW, not at invoke time: in the 15-minute
    // window the bot can be kicked, lose SendMessage, or the channel can be
    // deleted — a stale interaction must not bypass any of that.
    let channel = db
        .fetch_channel(&interaction.channel_id)
        .await
        .map_err(|_| create_error!(NotFound))?;

    if let Channel::Group { recipients, .. } = &channel {
        if !recipients.contains(&user.id) {
            return Err(create_error!(NotFound));
        }
    }

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // A thread archived/locked since invocation rejects the response too.
    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    // Single-use: atomically claim the response slot (replay defence).
    if !db.try_claim_interaction_response(&interaction.id).await? {
        return Err(create_error!(InteractionAlreadyResponded));
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

    // Exact DiceRoll pattern: the flag is set here, server-side, and the
    // regular send path rejects client-supplied flag values above 7.
    let mut flags = MessageFlagsValue(0);
    flags.set(MessageFlags::Interaction, true);

    let mut message = Message {
        id: Ulid::new().to_string(),
        channel: channel.id().to_string(),
        author: user.id.clone(),
        content: Some(data.content),
        flags: Some(flags.0),
        command_context: Some(MessageInteraction {
            id: interaction.id.clone(),
            user_id: interaction.user_id.clone(),
            command_name: interaction.command_name.clone().unwrap_or_default(),
        }),
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
    use revolt_database::{Bot, Interaction, InteractionKind, Member, MessageFlagsValue, Server, User};
    use revolt_models::v0::{self, MessageFlags};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    async fn setup_bot(
        harness: &TestHarness,
        owner: &User,
        server: &Server,
    ) -> (Bot, User) {
        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), owner, None)
            .await
            .expect("`Bot`");
        let bot_user = harness.db.fetch_user(&bot.id).await.expect("bot user");
        Member::create(&harness.db, server, &bot_user, None)
            .await
            .expect("bot member");
        (bot, bot_user)
    }

    fn interaction_row(
        id: String,
        token: &str,
        bot_id: &str,
        user_id: &str,
        channel_id: &str,
    ) -> Interaction {
        Interaction {
            id,
            kind: InteractionKind::Command,
            token: token.to_string(),
            bot_id: bot_id.to_string(),
            user_id: user_id.to_string(),
            channel_id: channel_id.to_string(),
            message_id: None,
            command_id: Some("01COMMAND000000000000000000".to_string()),
            command_name: Some("ping".to_string()),
            options: Default::default(),
            responded: false,
        }
    }

    #[rocket::async_test]
    async fn respond_flow_token_replay_and_expiry() {
        let harness = TestHarness::new().await;
        let (_, _session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let (bot, _) = setup_bot(&harness, &user, &server).await;
        let (other_bot, _) = setup_bot(&harness, &user, &server).await;

        let interaction = interaction_row(
            ulid::Ulid::new().to_string(),
            "sekrit-token",
            &bot.id,
            &user.id,
            channel.id(),
        );
        harness
            .db
            .insert_interaction(&interaction)
            .await
            .expect("interaction");

        // Wrong token → 401 (constant-time compare, same NotAuthenticated)
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "wrong", "content": "Pong!" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized);

        // Another bot with the right token → 404 (no existence leak)
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-bot-token", other_bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "sekrit-token", "content": "Pong!" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // A regular user session cannot respond at all
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-session-token", _session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "token": "sekrit-token", "content": "Pong!" }).to_string())
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok);

        // Right bot + right token → 200 with unforgeable context
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "sekrit-token", "content": "Pong!" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let message: v0::Message = response.into_json().await.expect("`Message`");
        assert_eq!(message.author, bot.id);
        assert!(
            MessageFlagsValue(message.flags).has(MessageFlags::Interaction),
            "Interaction flag not set"
        );
        let context = message.command_context.expect("command context");
        assert_eq!(context.id, interaction.id);
        assert_eq!(context.user_id, user.id);
        assert_eq!(context.command_name, "ping");

        // Replay → 409 (single-use responded flip)
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "sekrit-token", "content": "Pong again!" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Conflict);

        // Expired interaction (stale ULID clock) → 410
        let stale = interaction_row(
            ulid::Ulid::from_parts(1_000_000, 42).to_string(),
            "sekrit-token",
            &bot.id,
            &user.id,
            channel.id(),
        );
        harness.db.insert_interaction(&stale).await.expect("stale");

        let response = harness
            .client
            .post(format!("/interactions/{}/respond", stale.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "sekrit-token", "content": "Too late" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Gone);
    }

    #[rocket::async_test]
    async fn respond_rechecks_bot_standing_at_response_time() {
        let harness = TestHarness::new().await;
        let (_, _session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let (bot, bot_user) = setup_bot(&harness, &user, &server).await;

        let interaction = interaction_row(
            ulid::Ulid::new().to_string(),
            "sekrit-token",
            &bot.id,
            &user.id,
            channel.id(),
        );
        harness
            .db
            .insert_interaction(&interaction)
            .await
            .expect("interaction");

        // Kick the bot between invoke and respond.
        let member = harness
            .db
            .fetch_member(&server.id, &bot_user.id)
            .await
            .expect("member");
        member
            .remove(
                &harness.db,
                &server,
                revolt_database::RemovalIntention::Kick,
                false,
            )
            .await
            .expect("kick bot");

        // The stale interaction must not let the kicked bot post.
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "sekrit-token", "content": "I was kicked" }).to_string())
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "kicked bot must not respond into the channel"
        );
    }

    #[rocket::async_test]
    async fn regular_send_cannot_forge_interaction_flag() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        // Attempt to send a normal message carrying the Interaction flag bit
        // (bit 5 → value 32). The send path rejects flags > 7 outright.
        let response = harness
            .client
            .post(format!("/channels/{}/messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "content": "totally used /ping",
                    "flags": 32
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "regular send must not accept the Interaction flag"
        );

        // And the context field is not accepted from clients either: it is
        // not part of DataMessageSend, so a message sent with it comes back
        // without any command_context.
        let response = harness
            .client
            .post(format!("/channels/{}/messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "content": "sneaky",
                    "command_context": {
                        "id": "01FAKE000000000000000000000",
                        "user_id": user.id,
                        "command_name": "ping"
                    }
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let message: v0::Message = response.into_json().await.expect("`Message`");
        assert!(
            message.command_context.is_none(),
            "client-supplied command_context must be stripped"
        );
    }
}
