use revolt_database::util::reference::Reference;
use revolt_database::{
    ApplicationCommand, Database, PartialApplicationCommand, User, MAX_GLOBAL_COMMANDS,
    MAX_SERVER_COMMANDS,
};
use revolt_models::v0::{self, CommandOption};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use ulid::Ulid;
use validator::Validate;

/// Resolve a bot reference and enforce ownership (same pattern as bots/edit.rs:
/// non-owners get NotFound, not Forbidden, to avoid existence leaks).
///
/// A bot may also manage its OWN commands: with `x-bot-token` auth the
/// `User` guard resolves to the bot's user (id == bot id), so hosted bots
/// can self-sync their command set without holding the owner's session.
async fn owned_bot(
    db: &Database,
    user: &User,
    bot_id: &Reference<'_>,
) -> Result<revolt_database::Bot> {
    let bot = bot_id.as_bot(db).await?;
    if bot.owner != user.id && bot.id != user.id {
        return Err(create_error!(NotFound));
    }
    Ok(bot)
}

/// Structural validation shared by create and edit.
fn validate_options(options: &[CommandOption]) -> Result<()> {
    CommandOption::validate_structure(options)
        .map_err(|error| create_error!(FailedValidation { error }))
}

/// # Register Command
///
/// Register a new slash command for a bot. Commands are unique per
/// (bot, scope, name); scope is a server id or global when omitted.
#[openapi(tag = "Interactions")]
#[post("/<bot_id>/commands", data = "<data>")]
pub async fn create_command(
    db: &State<Database>,
    user: User,
    bot_id: Reference<'_>,
    data: Json<v0::DataCreateCommand>,
) -> Result<Json<v0::ApplicationCommand>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;
    validate_options(&data.options)?;

    let bot = owned_bot(db, &user, &bot_id).await?;

    // Scoped commands must point at a real server. Deliberately NOT gated
    // on the bot being a member yet: registration commonly precedes invites,
    // and non-membership rows are inert (the picker filters by membership
    // and the invoke route re-checks it).
    if let Some(server) = &data.server {
        db.fetch_server(server).await?;
    }

    // Per-scope cap
    let max = if data.server.is_some() {
        MAX_SERVER_COMMANDS
    } else {
        MAX_GLOBAL_COMMANDS
    };
    if db.count_commands(&bot.id, data.server.as_deref()).await? >= max {
        return Err(create_error!(TooManyCommands { max }));
    }

    // Friendly duplicate-name error; the unique index is the backstop for
    // a concurrent create/create race on MongoDB.
    if db
        .fetch_command_by_name(&bot.id, data.server.as_deref(), &data.name)
        .await?
        .is_some()
    {
        return Err(create_error!(InvalidOperation));
    }

    let command = ApplicationCommand {
        id: Ulid::new().to_string(),
        bot_id: bot.id,
        server: data.server,
        name: data.name,
        description: data.description,
        options: data.options.into_iter().map(Into::into).collect(),
    };

    db.insert_command(&command).await?;
    Ok(Json(command.into()))
}

/// # Fetch Commands
///
/// Fetch all commands registered by a bot you own.
#[openapi(tag = "Interactions")]
#[get("/<bot_id>/commands")]
pub async fn fetch_commands(
    db: &State<Database>,
    user: User,
    bot_id: Reference<'_>,
) -> Result<Json<Vec<v0::ApplicationCommand>>> {
    let bot = owned_bot(db, &user, &bot_id).await?;
    Ok(Json(
        db.fetch_commands_by_bot(&bot.id)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

/// # Edit Command
///
/// Edit a registered slash command (name, description or options).
#[openapi(tag = "Interactions")]
#[patch("/<bot_id>/commands/<command_id>", data = "<data>")]
pub async fn edit_command(
    db: &State<Database>,
    user: User,
    bot_id: Reference<'_>,
    command_id: &str,
    data: Json<v0::DataEditCommand>,
) -> Result<Json<v0::ApplicationCommand>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;
    if let Some(options) = &data.options {
        validate_options(options)?;
    }

    let bot = owned_bot(db, &user, &bot_id).await?;

    let mut command = db.fetch_command(command_id).await?;
    if command.bot_id != bot.id {
        return Err(create_error!(NotFound));
    }

    // Renames must stay unique within the command's scope.
    if let Some(name) = &data.name {
        if name != &command.name
            && db
                .fetch_command_by_name(&bot.id, command.server.as_deref(), name)
                .await?
                .is_some()
        {
            return Err(create_error!(InvalidOperation));
        }
    }

    let partial = PartialApplicationCommand {
        name: data.name,
        description: data.description,
        options: data
            .options
            .map(|options| options.into_iter().map(Into::into).collect()),
        ..Default::default()
    };

    db.update_command(&command.id, &partial).await?;
    command.apply_options(partial);
    Ok(Json(command.into()))
}

/// # Delete Command
///
/// Delete a registered slash command.
#[openapi(tag = "Interactions")]
#[delete("/<bot_id>/commands/<command_id>")]
pub async fn delete_command(
    db: &State<Database>,
    user: User,
    bot_id: Reference<'_>,
    command_id: &str,
) -> Result<()> {
    let bot = owned_bot(db, &user, &bot_id).await?;

    let command = db.fetch_command(command_id).await?;
    if command.bot_id != bot.id {
        return Err(create_error!(NotFound));
    }

    db.delete_command(&command.id).await
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::Bot;
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    #[test]
    fn command_crud_and_ownership() {
        crate::util::test::rt().block_on(command_crud_and_ownership_case())
    }

    async fn command_crud_and_ownership_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, other_session, _) = harness.new_user().await;

        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");

        // Owner registers a command
        let response = harness
            .client
            .post(format!("/bots/{}/commands", bot.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "name": "ping",
                    "description": "Ping the bot",
                    "options": [
                        { "name": "target", "description": "Who to ping", "kind": "User", "required": true }
                    ]
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let command: v0::ApplicationCommand = response.into_json().await.expect("`Command`");
        assert_eq!(command.name, "ping");

        // Duplicate name in the same scope is rejected
        let response = harness
            .client
            .post(format!("/bots/{}/commands", bot.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "name": "ping", "description": "again" }).to_string())
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok);

        // Invalid name charset is rejected
        let response = harness
            .client
            .post(format!("/bots/{}/commands", bot.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "name": "Not Valid!", "description": "nope" }).to_string())
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok);

        // A non-owner cannot see or touch the bot's commands
        let response = harness
            .client
            .get(format!("/bots/{}/commands", bot.id))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        let response = harness
            .client
            .delete(format!("/bots/{}/commands/{}", bot.id, command.id))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // Owner edits then deletes
        let response = harness
            .client
            .patch(format!("/bots/{}/commands/{}", bot.id, command.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "description": "Updated" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let updated: v0::ApplicationCommand = response.into_json().await.expect("`Command`");
        assert_eq!(updated.description, "Updated");

        let response = harness
            .client
            .delete(format!("/bots/{}/commands/{}", bot.id, command.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
    }

    /// A bot may manage its OWN commands with its bot token (hosted bots
    /// self-sync on boot); other bots' tokens and non-owner sessions stay
    /// locked out.
    #[test]
    fn bot_manages_own_commands() {
        crate::util::test::rt().block_on(bot_manages_own_commands_case())
    }

    async fn bot_manages_own_commands_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, other_session, other_user) = harness.new_user().await;

        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("`Bot`");
        let (other_bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &other_user, None)
            .await
            .expect("`Bot`");

        // The bot registers a command for itself.
        let response = harness
            .client
            .post(format!("/bots/{}/commands", bot.id))
            .header(Header::new("x-bot-token", bot.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "name": "selfsync", "description": "Registered by the bot" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let command: v0::ApplicationCommand = response.into_json().await.expect("`Command`");

        // It can list its own commands.
        let response = harness
            .client
            .get(format!("/bots/{}/commands", bot.id))
            .header(Header::new("x-bot-token", bot.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let commands: Vec<v0::ApplicationCommand> =
            response.into_json().await.expect("`Commands`");
        assert!(commands.iter().any(|c| c.id == command.id));

        // Another bot's token gets NotFound, exactly like a non-owner.
        let response = harness
            .client
            .get(format!("/bots/{}/commands", bot.id))
            .header(Header::new("x-bot-token", other_bot.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        let response = harness
            .client
            .delete(format!("/bots/{}/commands/{}", bot.id, command.id))
            .header(Header::new("x-bot-token", other_bot.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // Non-owner user sessions stay locked out (regression).
        let response = harness
            .client
            .get(format!("/bots/{}/commands", bot.id))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // The bot edits then deletes its own command.
        let response = harness
            .client
            .patch(format!("/bots/{}/commands/{}", bot.id, command.id))
            .header(Header::new("x-bot-token", bot.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "description": "Updated by the bot" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let response = harness
            .client
            .delete(format!("/bots/{}/commands/{}", bot.id, command.id))
            .header(Header::new("x-bot-token", bot.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
    }
}
