use std::time::{SystemTime, UNIX_EPOCH};

use iso8601_timestamp::Timestamp;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{
    Channel, Database, InteractionKind, Message, MessageFlagsValue, MessageInteraction,
    PartialMessage, User, AMQP,
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

    // Command (slice 1) and Component (slice 2) interactions accept message
    // responses; autocomplete / modal kinds are later slices.
    if !matches!(
        interaction.kind,
        InteractionKind::Command | InteractionKind::Component
    ) {
        return Err(create_error!(InvalidOperation));
    }

    if let Some(components) = &data.components {
        // On the edit path an explicit empty array means "remove the rows"
        // (one-shot flows must be able to retire their buttons); everywhere
        // else components must be structurally valid, which implies
        // non-empty.
        if !(data.edit && components.is_empty()) {
            v0::ActionRow::validate_structure(components)
                .map_err(|error| create_error!(FailedValidation { error }))?;
        }
    }

    // Editing is only meaningful for component interactions — it targets the
    // message the clicked component lives on.
    if data.edit
        && (!matches!(interaction.kind, InteractionKind::Component)
            || interaction.message_id.is_none())
    {
        return Err(create_error!(InvalidOperation));
    }

    // A response must change something: a new message needs content or
    // components; an edit needs at least one of the two to replace.
    if data.content.is_none() && data.components.is_none() {
        return Err(create_error!(FailedValidation {
            error: "response must carry content or components".to_string()
        }));
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

    // Edit path: fetch and verify the component's host message BEFORE
    // claiming the single-use slot, so a deleted message doesn't burn it.
    let mut edit_target = None;
    if data.edit {
        let Some(message_id) = interaction.message_id.clone() else {
            return Err(create_error!(InvalidOperation));
        };
        let message = db
            .fetch_message(&message_id)
            .await
            .map_err(|_| create_error!(NotFound))?;

        // Bots only ever edit their own component message, in the channel
        // the interaction was created in.
        if message.author != user.id || message.channel != interaction.channel_id {
            return Err(create_error!(InvalidOperation));
        }

        edit_target = Some(message);
    }

    // Single-use: atomically claim the response slot (replay defence).
    // A transient send/update failure AFTER this point burns the slot —
    // accepted trade-off (slice-1 LOW-11, Discord-comparable): the claim
    // must precede the side effect or replays could double-post.
    if !db.try_claim_interaction_response(&interaction.id).await? {
        return Err(create_error!(InteractionAlreadyResponded));
    }

    if let Some(mut message) = edit_target {
        // Component-driven update of the original bot message; fans out as
        // a regular MessageUpdate on the channel topic.
        let mut partial = PartialMessage {
            edited: Some(Timestamp::now_utc()),
            ..Default::default()
        };
        let mut remove = Vec::new();
        if let Some(content) = data.content {
            partial.content = Some(content);
        }
        if let Some(components) = data.components {
            if components.is_empty() {
                // Explicit empty array retires the rows entirely
                remove.push(revolt_database::FieldsMessage::Components);
            } else {
                partial.components = Some(components);
            }
        }

        message.update(db, partial, remove).await?;

        return Ok(Json(message.into_model(None, None)));
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

    let mut message = match interaction.kind {
        InteractionKind::Command => {
            // Exact DiceRoll pattern: the flag is set here, server-side, and
            // the regular send path rejects client-supplied flag values
            // above 7 — flag + command_context prove "used /cmd".
            let mut flags = MessageFlagsValue(0);
            flags.set(MessageFlags::Interaction, true);

            Message {
                flags: Some(flags.0),
                command_context: Some(MessageInteraction {
                    id: interaction.id.clone(),
                    user_id: interaction.user_id.clone(),
                    command_name: interaction.command_name.clone().unwrap_or_default(),
                }),
                ..Default::default()
            }
        }
        // Component follow-ups are plain bot messages; provenance comes
        // from replying to the message the component lives on ("used /cmd"
        // is reserved for actual command invocations).
        InteractionKind::Component => Message {
            replies: interaction.message_id.clone().map(|id| vec![id]),
            ..Default::default()
        },
        // Rejected above.
        _ => return Err(create_error!(InvalidOperation)),
    };

    message.id = Ulid::new().to_string();
    message.channel = channel.id().to_string();
    message.author = user.id.clone();
    message.content = data.content;
    message.components = data.components;

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
    use revolt_database::{
        Bot, Interaction, InteractionKind, Member, Message, MessageFlagsValue, Server, User,
    };
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
            custom_id: None,
            values: Vec::new(),
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
    fn component_message(channel_id: &str, author_id: &str) -> Message {
        Message {
            id: ulid::Ulid::new().to_string(),
            channel: channel_id.to_string(),
            author: author_id.to_string(),
            content: Some("pick something".to_string()),
            components: Some(vec![v0::ActionRow {
                components: vec![v0::Component::Button {
                    custom_id: "btn_a".to_string(),
                    label: "Click me".to_string(),
                    style: v0::ButtonStyle::Primary,
                    disabled: false,
                }],
            }]),
            ..Default::default()
        }
    }

    fn component_interaction_row(
        token: &str,
        bot_id: &str,
        user_id: &str,
        channel_id: &str,
        message_id: &str,
    ) -> Interaction {
        Interaction {
            id: ulid::Ulid::new().to_string(),
            kind: InteractionKind::Component,
            token: token.to_string(),
            bot_id: bot_id.to_string(),
            user_id: user_id.to_string(),
            channel_id: channel_id.to_string(),
            message_id: Some(message_id.to_string()),
            command_id: None,
            command_name: None,
            custom_id: Some("btn_a".to_string()),
            values: Vec::new(),
            options: Default::default(),
            responded: false,
        }
    }

    #[rocket::async_test]
    async fn component_respond_edit_and_followup_paths() {
        let harness = TestHarness::new().await;
        let (_, _session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let (bot, _) = setup_bot(&harness, &user, &server).await;

        let message = component_message(channel.id(), &bot.id);
        harness.db.insert_message(&message).await.expect("message");

        // Edit path: the bot updates the message the component lives on
        let interaction =
            component_interaction_row("tok-edit", &bot.id, &user.id, channel.id(), &message.id);
        harness
            .db
            .insert_interaction(&interaction)
            .await
            .expect("interaction");

        let new_components = json!([
            { "components": [
                { "type": "Button", "custom_id": "btn_b", "label": "Next", "style": "Secondary" }
            ] }
        ]);
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "token": "tok-edit",
                    "content": "updated!",
                    "components": new_components,
                    "edit": true
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let updated = harness
            .db
            .fetch_message(&message.id)
            .await
            .expect("message");
        assert_eq!(updated.content.as_deref(), Some("updated!"));
        assert!(updated.edited.is_some(), "edit must stamp the timestamp");
        let rows = updated.components.expect("components");
        assert_eq!(rows[0].components[0].custom_id(), "btn_b");

        // The single-use slot still applies to edits (replay defence)
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "tok-edit", "content": "again", "edit": true }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Conflict);

        // Follow-up path: a component response WITHOUT edit is a plain bot
        // message replying to the component's host message — no Interaction
        // flag, no command_context ("used /cmd" is reserved for commands).
        let followup =
            component_interaction_row("tok-new", &bot.id, &user.id, channel.id(), &message.id);
        harness
            .db
            .insert_interaction(&followup)
            .await
            .expect("interaction");

        let response = harness
            .client
            .post(format!("/interactions/{}/respond", followup.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "tok-new", "content": "you clicked!" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let reply: v0::Message = response.into_json().await.expect("`Message`");
        assert_eq!(reply.replies, Some(vec![message.id.clone()]));
        assert!(
            !MessageFlagsValue(reply.flags).has(MessageFlags::Interaction),
            "component follow-ups are not command responses"
        );
        assert!(reply.command_context.is_none());

        // Editing is meaningless for Command interactions
        let command_interaction = interaction_row(
            ulid::Ulid::new().to_string(),
            "tok-cmd",
            &bot.id,
            &user.id,
            channel.id(),
        );
        harness
            .db
            .insert_interaction(&command_interaction)
            .await
            .expect("interaction");
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", command_interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "tok-cmd", "content": "nope", "edit": true }).to_string())
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "edit must be rejected for Command interactions"
        );

        // Retiring the rows: an edit with an explicit empty array clears
        // the message's components entirely (one-shot flows must be able
        // to take their buttons out of service).
        let clear = component_interaction_row(
            "tok-clear",
            &bot.id,
            &user.id,
            channel.id(),
            &message.id,
        );
        harness.db.insert_interaction(&clear).await.expect("row");
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", clear.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(
                json!({ "token": "tok-clear", "edit": true, "components": [] }).to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let retired = harness
            .db
            .fetch_message(&message.id)
            .await
            .expect("message");
        assert!(
            retired.components.is_none(),
            "an empty array on the edit path must clear components"
        );

        // A response must change something
        let empty = component_interaction_row(
            "tok-empty",
            &bot.id,
            &user.id,
            channel.id(),
            &message.id,
        );
        harness.db.insert_interaction(&empty).await.expect("row");
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", empty.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "tok-empty" }).to_string())
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "a response with neither content nor components is rejected"
        );
    }

    #[rocket::async_test]
    async fn component_edit_of_deleted_message_does_not_burn_the_slot() {
        let harness = TestHarness::new().await;
        let (_, _session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let (bot, _) = setup_bot(&harness, &user, &server).await;

        // Interaction points at a message that no longer exists
        let interaction = component_interaction_row(
            "tok-gone",
            &bot.id,
            &user.id,
            channel.id(),
            "01DELETED000000000000000000",
        );
        harness
            .db
            .insert_interaction(&interaction)
            .await
            .expect("interaction");

        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "tok-gone", "content": "edit me", "edit": true }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // The failed edit must not have consumed the single-use slot: the
        // bot can still answer with a plain follow-up message.
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "tok-gone", "content": "fallback" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn component_edit_rechecks_bot_standing_at_response_time() {
        let harness = TestHarness::new().await;
        let (_, _session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let (bot, bot_user) = setup_bot(&harness, &user, &server).await;

        let message = component_message(channel.id(), &bot.id);
        harness.db.insert_message(&message).await.expect("message");

        let interaction = component_interaction_row(
            "tok-kicked",
            &bot.id,
            &user.id,
            channel.id(),
            &message.id,
        );
        harness
            .db
            .insert_interaction(&interaction)
            .await
            .expect("interaction");

        // Kick the bot between click and respond — the permission re-check
        // must reject the EDIT path too, not just new-message responses.
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

        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(
                json!({ "token": "tok-kicked", "content": "still here", "edit": true })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "a kicked bot must not edit its component message"
        );

        let untouched = harness
            .db
            .fetch_message(&message.id)
            .await
            .expect("message");
        assert_eq!(
            untouched.content.as_deref(),
            Some("pick something"),
            "the message must be untouched after the rejected edit"
        );
    }
}
