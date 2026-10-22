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

    // A protected channel never wakes a bot: refused before the interaction
    // row and the event below. Not before the permission check, so a caller
    // who cannot send here learns nothing about the channel's protection.
    crate::util::interactions::ensure_interactions_allowed(&channel)?;

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
    use revolt_database::events::client::EventV1;
    use revolt_database::{Bot, Member, Server, User};
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

    /// A bot owned by `owner`, joined to `server`, with one command whose
    /// only option opted into autocomplete. Returns the bot and command ids.
    async fn autocomplete_bot(
        harness: &TestHarness,
        owner: &User,
        owner_token: &str,
        server: &Server,
    ) -> (String, String) {
        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), owner, None)
            .await
            .expect("`Bot`");
        let bot_user = harness.db.fetch_user(&bot.id).await.expect("bot user");
        harness.join_server(server, &bot_user).await;

        let response = harness
            .client
            .post(format!("/bots/{}/commands", bot.id))
            .header(Header::new("x-session-token", owner_token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "name": "play",
                    "description": "Play a track",
                    "options": [{
                        "name": "track",
                        "description": "Which track",
                        "kind": "String",
                        "autocomplete": true
                    }]
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let command: v0::ApplicationCommand = response.into_json().await.expect("`Command`");
        (bot.id, command.id)
    }

    /// Ask for suggestions on `track`; returns the status and the raw body.
    async fn request_autocomplete(
        harness: &TestHarness,
        token: &str,
        channel_id: &str,
        command_id: &str,
    ) -> (Status, String) {
        let response = harness
            .client
            .post(format!("/channels/{channel_id}/interactions/autocomplete"))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "command_id": command_id,
                    "focused_option": "track",
                    "options": { "track": "blu" }
                })
                .to_string(),
            )
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        (status, body)
    }

    /// Publish a marker on `user_id`'s private topic and wait for it. The
    /// harness reads every topic through one subscription and redis pub/sub
    /// is FIFO on it, so once the marker is seen, anything the request
    /// published to that topic is in the buffer for `assert_no_buffered_event`.
    async fn flush_with_marker(harness: &mut TestHarness, user_id: &str) {
        let marker = ulid::Ulid::new().to_string();

        EventV1::ChannelAck {
            id: ulid::Ulid::new().to_string(),
            user: user_id.to_string(),
            message_id: marker.clone(),
        }
        .private(user_id.to_string())
        .await;

        harness
            .wait_for_event(&format!("{user_id}!"), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &marker,
                _ => false,
            })
            .await;
    }

    #[test]
    fn autocomplete_refused_in_protected_channel() {
        crate::util::test::rt().block_on(autocomplete_refused_in_protected_channel_case())
    }

    async fn autocomplete_refused_in_protected_channel_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let protected = harness.new_protected_channel(&owner, &session, &[]).await;
        let channel_id = protected.channel.id().to_string();
        let (bot_id, command_id) =
            autocomplete_bot(&harness, &owner, &session.token, &protected.server).await;

        // The bot is online, so without the refusal this request would get
        // all the way to the interaction row and the event to the bot.
        let (_, presence_session) = revolt_presence::create_session(&bot_id, 0).await;
        let (status, body) =
            request_autocomplete(&harness, &session.token, &channel_id, &command_id).await;
        revolt_presence::delete_session(&bot_id, presence_session).await;

        assert_eq!(status, Status::BadRequest, "{}", body);
        let error: serde_json::Value = serde_json::from_str(&body).expect("error body");
        assert_eq!(error["type"], "ChannelProtected", "{}", body);

        // No event reached the bot
        flush_with_marker(&mut harness, &bot_id).await;
        harness.assert_no_buffered_event(&format!("{bot_id}!"), |event| {
            matches!(event, EventV1::InteractionCreate { .. })
        });
    }

    #[test]
    fn autocomplete_reaches_bot_in_unprotected_channel() {
        crate::util::test::rt().block_on(autocomplete_reaches_bot_in_unprotected_channel_case())
    }

    async fn autocomplete_reaches_bot_in_unprotected_channel_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&owner).await;
        let channel_id = channel.id().to_string();
        let (bot_id, command_id) =
            autocomplete_bot(&harness, &owner, &session.token, &server).await;

        let (_, presence_session) = revolt_presence::create_session(&bot_id, 0).await;
        let (status, body) =
            request_autocomplete(&harness, &session.token, &channel_id, &command_id).await;
        revolt_presence::delete_session(&bot_id, presence_session).await;

        assert_eq!(status, Status::Ok, "{}", body);
        let created: v0::CreateInteractionResponse =
            serde_json::from_str(&body).expect("`CreateInteractionResponse`");

        harness
            .db
            .fetch_interaction(&created.interaction_id)
            .await
            .expect("the interaction row");

        let event = harness
            .wait_for_event(&format!("{bot_id}!"), |event| match event {
                EventV1::InteractionCreate { interaction } => {
                    interaction.id == created.interaction_id
                }
                _ => false,
            })
            .await;
        match event {
            EventV1::InteractionCreate { interaction } => {
                assert_eq!(interaction.channel_id, channel_id)
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn autocomplete_outsider_error_hides_protection() {
        crate::util::test::rt().block_on(autocomplete_outsider_error_hides_protection_case())
    }

    async fn autocomplete_outsider_error_hides_protection_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[])
            .await;
        let (other_server, unprotected) = harness.new_protectable_channel(&owner).await;
        let (_, protected_command) =
            autocomplete_bot(&harness, &owner, &owner_session.token, &protected.server).await;
        autocomplete_bot(&harness, &owner, &owner_session.token, &other_server).await;

        // Not a member of either server: fails the permission check first,
        // with the same error whether or not the channel is protected.
        let (_, session, _) = harness.new_user().await;
        let (protected_status, protected_body) = request_autocomplete(
            &harness,
            &session.token,
            protected.channel.id(),
            &protected_command,
        )
        .await;
        let (unprotected_status, unprotected_body) = request_autocomplete(
            &harness,
            &session.token,
            unprotected.id(),
            &protected_command,
        )
        .await;

        assert!(
            protected_status.class().is_client_error(),
            "{}",
            protected_body
        );
        assert_eq!(protected_status, unprotected_status);
        assert_eq!(protected_body, unprotected_body);
        let error: serde_json::Value = serde_json::from_str(&protected_body).expect("error body");
        assert_ne!(error["type"], "ChannelProtected", "{}", protected_body);
    }
}
