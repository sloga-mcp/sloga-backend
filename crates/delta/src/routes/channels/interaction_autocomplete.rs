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

/// # Autocomplete Command Option
///
/// Ask a command's bot to suggest values for the option currently being
/// typed. Creates a short-lived interaction which the bot answers via
/// `POST /interactions/{id}/autocomplete`; the suggestions come back to the
/// caller alone, on their private topic.
///
/// Nothing is ever posted to the channel, so this is not a message send: it
/// does not spend slowmode, and it does not join you to a thread.
#[openapi(tag = "Interactions")]
#[post("/<target>/interactions/autocomplete", data = "<data>")]
pub async fn interaction_autocomplete(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataCreateAutocomplete>,
) -> Result<Json<v0::CreateInteractionResponse>> {
    let data = data.into_inner();

    // Bots don't type.
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let channel = target.as_channel(db).await?;

    // Same structural exclusion as invoking a command: no forum containers,
    // and no DMs or saved messages (E2EE fail-closed).
    match &channel {
        Channel::Forum { .. } | Channel::DirectMessage { .. } | Channel::SavedMessages { .. } => {
            return Err(create_error!(InvalidOperation));
        }
        _ => {}
    }

    // Gated on being able to send here: suggestions are only useful to
    // someone who could go on to run the command, and probing a bot from a
    // channel you cannot speak in should not be possible either.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    let command = db.fetch_command(&data.command_id).await?;

    // Scope and bot-presence rules, identical to invocation.
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

    // The focused option must exist and must have opted into autocomplete.
    // Without that second check this route would be a way to wake any bot
    // on every keystroke for options it never asked to be consulted about.
    let focused = command
        .options
        .iter()
        .find(|option| option.name == data.focused_option)
        .ok_or_else(|| {
            create_error!(FailedValidation {
                error: format!("unknown option `{}`", data.focused_option)
            })
        })?;

    if !focused.autocomplete {
        return Err(create_error!(FailedValidation {
            error: format!("`{}` does not use autocomplete", focused.name)
        }));
    }

    // Supplied values are mid-typing and deliberately NOT schema-checked: an
    // Integer option reads "-" for a keystroke, and a partial string matches
    // no fixed choice. Only option names and the length cap are enforced.
    for (name, value) in &data.options {
        if !command.options.iter().any(|option| &option.name == name) {
            return Err(create_error!(FailedValidation {
                error: format!("unknown option `{name}`")
            }));
        }

        if value.len() > v0::MAX_OPTION_VALUE_LENGTH {
            return Err(create_error!(FailedValidation {
                error: format!("value for `{name}` too long")
            }));
        }
    }

    // Fail fast if the bot has no live session — nothing would ever answer.
    if !revolt_presence::is_online(&command.bot_id).await {
        return Err(create_error!(BotOffline));
    }

    let interaction = Interaction {
        id: Ulid::new().to_string(),
        kind: InteractionKind::Autocomplete,
        // Response token: secret between server and bot, same shape as a
        // command invocation.
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
        focused_option: Some(data.focused_option),
        modal: None,
        submitted_values: Vec::new(),
        submitted: false,
        responded: false,
    };

    // Persist WITHOUT the typed fragments. They exist to be handed to the bot
    // in the event below and are never read back off the row, so storing them
    // would mean up to 10 x 2000 characters per keystroke burst kept for
    // nothing — on the one interaction kind a user generates by typing.
    let mut stored = interaction.clone();
    stored.options = Default::default();
    db.insert_interaction(&stored).await?;

    let interaction_id = interaction.id.clone();
    let bot_id = interaction.bot_id.clone();

    // Private topic ONLY — the payload carries the response token.
    EventV1::InteractionCreate {
        interaction: interaction.into_wire(),
    }
    .private(bot_id)
    .await;

    Ok(Json(v0::CreateInteractionResponse { interaction_id }))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{Bot, Member};
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    #[test]
    fn autocomplete_requires_an_opted_in_option() {
        crate::util::test::rt().block_on(autocomplete_requires_an_opted_in_option_case())
    }

    async fn autocomplete_requires_an_opted_in_option_case() {
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

        let response = harness
            .client
            .post(format!("/bots/{}/commands", bot.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "name": "play",
                    "description": "Play a track",
                    "options": [
                        {
                            "name": "track",
                            "description": "Which track",
                            "kind": "String",
                            "autocomplete": true
                        },
                        {
                            "name": "volume",
                            "description": "How loud",
                            "kind": "Integer"
                        }
                    ]
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let command: v0::ApplicationCommand = response.into_json().await.expect("`Command`");

        let url = format!("/channels/{}/interactions/autocomplete", channel.id());

        // An option the command does not have
        let response = harness
            .client
            .post(&url)
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({ "command_id": command.id, "focused_option": "nope" }).to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // A real option that never opted into autocomplete: this must not be
        // a way to wake the bot on every keystroke.
        let response = harness
            .client
            .post(&url)
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({ "command_id": command.id, "focused_option": "volume" }).to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // The opted-in option gets past validation and stops at the offline
        // bot — proving partial values are NOT schema-checked on the way
        // through ("12x" would never parse as the Integer it belongs to).
        let response = harness
            .client
            .post(&url)
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "command_id": command.id,
                    "focused_option": "track",
                    "options": { "track": "blu", "volume": "12x" }
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
        let error: serde_json::Value = response.into_json().await.expect("error body");
        assert_eq!(error["type"], "BotOffline");

        // Unknown option names are still rejected, partial or not
        let response = harness
            .client
            .post(&url)
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "command_id": command.id,
                    "focused_option": "track",
                    "options": { "smuggled": "x" }
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
        let error: serde_json::Value = response.into_json().await.expect("error body");
        assert_eq!(error["type"], "FailedValidation");
    }

    #[test]
    fn autocomplete_rejects_choices_and_autocomplete_together() {
        crate::util::test::rt()
            .block_on(autocomplete_rejects_choices_and_autocomplete_together_case())
    }

    async fn autocomplete_rejects_choices_and_autocomplete_together_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");

        // A fixed choice list is already the complete answer; registering
        // both would leave the client with two competing sources.
        let response = harness
            .client
            .post(format!("/bots/{}/commands", bot.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "name": "play",
                    "description": "Play a track",
                    "options": [{
                        "name": "track",
                        "description": "Which track",
                        "kind": "String",
                        "autocomplete": true,
                        "choices": [{ "name": "One", "value": "1" }]
                    }]
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Autocomplete is meaningless on a kind the client picks for you
        let response = harness
            .client
            .post(format!("/bots/{}/commands", bot.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "name": "mute",
                    "description": "Mute someone",
                    "options": [{
                        "name": "who",
                        "description": "Target",
                        "kind": "User",
                        "autocomplete": true
                    }]
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
    }
}
