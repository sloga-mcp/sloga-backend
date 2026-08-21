use revolt_database::events::client::EventV1;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Channel, Database, Interaction, InteractionKind, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use ulid::Ulid;

/// # Invoke Command
///
/// Invoke a slash command in this channel. Creates a transient interaction
/// addressed to the command's bot; the bot receives it (with a single-use
/// response token) on its private topic and replies via
/// `POST /interactions/{id}/respond`.
///
/// Structurally excluded from DMs and saved messages (E2EE fail-closed):
/// the bot must be a group recipient or a member of the channel's server.
#[openapi(tag = "Interactions")]
#[post("/<target>/interactions", data = "<data>")]
pub async fn interaction_create(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataCreateInteraction>,
) -> Result<Json<v0::CreateInteractionResponse>> {
    let data = data.into_inner();

    // Bots don't invoke commands on other bots.
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let channel = target.as_channel(db).await?;

    // Forum containers have no message stream — fail closed like
    // message_send; DMs / saved messages are structurally excluded.
    match &channel {
        Channel::Forum { .. }
        | Channel::DirectMessage { .. }
        | Channel::SavedMessages { .. } => {
            return Err(create_error!(InvalidOperation));
        }
        _ => {}
    }

    // Same gate as sending a normal message. Threads inherit their parent
    // channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // Archived or locked threads reject invocations exactly like messages.
    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    crate::util::slowmode::enforce_slowmode(&user, &channel, &permissions).await?;

    let command = db.fetch_command(&data.command_id).await?;

    // Scope rule: a server-scoped command is only invocable in that server.
    // Presence rule: the bot must actually be party to this channel.
    match &channel {
        Channel::Group { recipients, .. } => {
            if command.server.is_some() {
                return Err(create_error!(NotFound));
            }
            if !recipients.contains(&command.bot_id) {
                return Err(create_error!(NotFound));
            }
        }
        Channel::TextChannel { server, .. } | Channel::Thread { server, .. } => {
            if let Some(scope) = &command.server {
                if scope != server {
                    return Err(create_error!(NotFound));
                }
            }
            db.fetch_member(server, &command.bot_id)
                .await
                .map_err(|_| create_error!(NotFound))?;
        }
        // Already rejected above.
        _ => return Err(create_error!(InvalidOperation)),
    }

    // Validate supplied options against the command's typed schema.
    for option in &command.options {
        let wire_option: v0::CommandOption = option.clone().into();
        match data.options.get(&wire_option.name) {
            Some(value) => wire_option
                .validate_value(value)
                .map_err(|error| create_error!(FailedValidation { error }))?,
            None if wire_option.required => {
                return Err(create_error!(FailedValidation {
                    error: format!("missing required option `{}`", wire_option.name)
                }));
            }
            None => {}
        }
    }
    for name in data.options.keys() {
        if !command.options.iter().any(|option| &option.name == name) {
            return Err(create_error!(FailedValidation {
                error: format!("unknown option `{name}`")
            }));
        }
    }

    // Fail fast if the bot has no live session — nothing would ever answer.
    if !revolt_presence::is_online(&command.bot_id).await {
        return Err(create_error!(BotOffline));
    }

    let interaction = Interaction {
        id: Ulid::new().to_string(),
        kind: InteractionKind::Command,
        // Response token: secret between server and bot. 64 chars of the
        // nanoid alphabet ≈ 384 bits of OS-CSPRNG entropy.
        token: nanoid::nanoid!(64),
        bot_id: command.bot_id.clone(),
        user_id: user.id.clone(),
        channel_id: channel.id().to_string(),
        message_id: None,
        command_id: Some(command.id.clone()),
        command_name: Some(command.name.clone()),
        custom_id: None,
        values: Vec::new(),
        options: data.options,
        focused_option: None,
        modal: None,
        submitted_values: Vec::new(),
        submitted: false,
        responded: false,
    };

    db.insert_interaction(&interaction).await?;

    let interaction_id = interaction.id.clone();
    let bot_id = interaction.bot_id.clone();

    // Private topic ONLY — the payload carries the response token.
    EventV1::InteractionCreate {
        interaction: interaction.into_wire(),
    }
    .private(bot_id)
    .await;

    // Invoking a command in a thread joins you to it (same rule as sending
    // a message there) — otherwise the bot's reply could never notify you.
    if let Channel::Thread { id, server, .. } = &channel {
        if db.join_thread_if_absent(id, &user.id).await? {
            EventV1::ThreadMemberJoin {
                id: id.clone(),
                user: user.id.clone(),
            }
            .p(server.clone())
            .await;
        }
    }

    Ok(Json(v0::CreateInteractionResponse { interaction_id }))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{Bot, Channel, Member};
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    async fn register_command(
        harness: &TestHarness,
        session_token: &str,
        bot_id: &str,
        body: serde_json::Value,
    ) -> v0::ApplicationCommand {
        let response = harness
            .client
            .post(format!("/bots/{bot_id}/commands"))
            .header(Header::new("x-session-token", session_token.to_string()))
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        response.into_json().await.expect("`Command`")
    }

    #[test]
    fn invoke_rejects_saved_messages_and_offline_bot() {
        crate::util::test::rt().block_on(invoke_rejects_saved_messages_and_offline_bot_case())
    }

    async fn invoke_rejects_saved_messages_and_offline_bot_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");
        let bot_user = harness.db.fetch_user(&bot.id).await.expect("bot user");
        Member::create(&harness.db, &server, &bot_user, None)
            .await
            .expect("bot member");

        let command = register_command(
            &harness,
            &session.token,
            &bot.id,
            json!({ "name": "ping", "description": "Ping" }),
        )
        .await;

        // Structural exclusion: saved-messages channels reject invocations
        // outright (E2EE fail-closed rule).
        let notes = Channel::SavedMessages {
            id: ulid::Ulid::new().to_string(),
            user: user.id.clone(),
        };
        harness.db.insert_channel(&notes).await.expect("notes");

        let response = harness
            .client
            .post(format!("/channels/{}/interactions", notes.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "command_id": command.id }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // A bot with no live session fails fast with BotOffline.
        let response = harness
            .client
            .post(format!("/channels/{}/interactions", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "command_id": command.id }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
        let error: serde_json::Value = response.into_json().await.expect("error body");
        assert_eq!(error["type"], "BotOffline");
    }

    #[test]
    fn invoke_enforces_scope_membership_and_option_schema() {
        crate::util::test::rt().block_on(invoke_enforces_scope_membership_and_option_schema_case())
    }

    async fn invoke_enforces_scope_membership_and_option_schema_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        // Bot is NOT a member of this server.
        let (stranger_bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");
        let stranger_command = register_command(
            &harness,
            &session.token,
            &stranger_bot.id,
            json!({ "name": "lurk", "description": "Lurk" }),
        )
        .await;

        let response = harness
            .client
            .post(format!("/channels/{}/interactions", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "command_id": stranger_command.id }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // Member bot with a typed option schema.
        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");
        let bot_user = harness.db.fetch_user(&bot.id).await.expect("bot user");
        Member::create(&harness.db, &server, &bot_user, None)
            .await
            .expect("bot member");

        let command = register_command(
            &harness,
            &session.token,
            &bot.id,
            json!({
                "name": "add",
                "description": "Add a number",
                "options": [
                    { "name": "count", "description": "How many", "kind": "Integer", "required": true }
                ]
            }),
        )
        .await;

        // Missing required option
        let response = harness
            .client
            .post(format!("/channels/{}/interactions", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "command_id": command.id }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Type mismatch
        let response = harness
            .client
            .post(format!("/channels/{}/interactions", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "command_id": command.id, "options": { "count": "not-a-number" } }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Unknown option
        let response = harness
            .client
            .post(format!("/channels/{}/interactions", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "command_id": command.id, "options": { "count": "3", "extra": "x" } }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Well-formed invocation passes every gate up to the presence check
        // (no live bot session in the harness → BotOffline, not a 4xx from
        // scope/membership/options).
        let response = harness
            .client
            .post(format!("/channels/{}/interactions", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "command_id": command.id, "options": { "count": "3" } }).to_string())
            .dispatch()
            .await;
        let error: serde_json::Value = response.into_json().await.expect("error body");
        assert_eq!(error["type"], "BotOffline");
    }

    #[test]
    fn invoke_in_thread_auto_joins_invoker() {
        crate::util::test::rt().block_on(invoke_in_thread_auto_joins_invoker_case())
    }

    async fn invoke_in_thread_auto_joins_invoker_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");
        let bot_user = harness.db.fetch_user(&bot.id).await.expect("bot user");
        Member::create(&harness.db, &server, &bot_user, None)
            .await
            .expect("bot member");

        let command = register_command(
            &harness,
            &session.token,
            &bot.id,
            json!({ "name": "ping", "description": "Ping" }),
        )
        .await;

        // Create a thread, then leave it — invoking must re-join us.
        let response = harness
            .client
            .post(format!("/channels/{}/threads", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "name": "cmd thread" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let thread: serde_json::Value = response.into_json().await.expect("thread");
        let thread_id = thread["_id"].as_str().expect("thread id").to_string();

        harness
            .db
            .leave_thread(&thread_id, &user.id)
            .await
            .expect("leave");

        // Give the bot a live presence session so the invoke goes through.
        let (_, presence_session) = revolt_presence::create_session(&bot.id, 0).await;

        let response = harness
            .client
            .post(format!("/channels/{thread_id}/interactions"))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "command_id": command.id }).to_string())
            .dispatch()
            .await;

        revolt_presence::delete_session(&bot.id, presence_session).await;

        assert_eq!(response.status(), Status::Ok);

        // Invoking a command in a thread joins you to it (message_send parity)
        let members = harness
            .db
            .fetch_thread_members(&thread_id)
            .await
            .expect("members");
        assert!(
            members.iter().any(|member| member.id.user == user.id),
            "invoker should be auto-joined to the thread"
        );
    }
}
