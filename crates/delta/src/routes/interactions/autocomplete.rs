use std::time::{SystemTime, UNIX_EPOCH};

use revolt_database::events::client::EventV1;
use revolt_database::util::reference::Reference;
use revolt_database::{Database, InteractionKind, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;
use validator::Validate;

/// # Answer Autocomplete
///
/// Return suggestions for the option a user is typing. Requires the bot's
/// session (bot token) AND the interaction's single-use token, like any
/// other interaction response.
///
/// Autocomplete interactions expire in one minute rather than fifteen: by
/// then the caret has moved on and the suggestions are worthless.
#[openapi(tag = "Interactions")]
#[post("/<target>/autocomplete", data = "<data>")]
pub async fn interaction_autocomplete_respond(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataInteractionAutocomplete>,
) -> Result<EmptyResponse> {
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

    // Wrong-bot probes get NotFound (no existence leak), and the token
    // check is constant-time.
    if interaction.bot_id != user.id {
        return Err(create_error!(NotFound));
    }
    interaction.assert_token(&data.token)?;

    if !matches!(interaction.kind, InteractionKind::Autocomplete) {
        return Err(create_error!(InvalidOperation));
    }

    v0::CommandChoice::validate_list(&data.choices)
        .map_err(|error| create_error!(FailedValidation { error }))?;

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    if interaction.is_expired(now_ms) {
        return Err(create_error!(InteractionExpired));
    }

    // No channel permission re-check, unlike a message response: this
    // publishes nothing to the channel. The payload is a list of strings
    // going back to the one user who asked for it, and they already passed
    // a permission check to ask.
    if !db.try_claim_interaction_response(&interaction.id).await? {
        return Err(create_error!(InteractionAlreadyResponded));
    }

    EventV1::InteractionAutocompleteResult {
        interaction_id: interaction.id.clone(),
        choices: data.choices,
    }
    .private(interaction.user_id)
    .await;

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{
        Bot, Interaction, InteractionKind, Member, Server, User, AUTOCOMPLETE_TTL_MS,
    };
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    async fn setup_bot(harness: &TestHarness, owner: &User, server: &Server) -> (Bot, User) {
        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), owner, None)
            .await
            .expect("`Bot`");
        let bot_user = harness.db.fetch_user(&bot.id).await.expect("bot user");
        Member::create(&harness.db, server, &bot_user, None)
            .await
            .expect("bot member");
        (bot, bot_user)
    }

    fn autocomplete_row(
        id: String,
        token: &str,
        bot_id: &str,
        user_id: &str,
        channel_id: &str,
    ) -> Interaction {
        Interaction {
            id,
            kind: InteractionKind::Autocomplete,
            token: token.to_string(),
            bot_id: bot_id.to_string(),
            user_id: user_id.to_string(),
            channel_id: channel_id.to_string(),
            message_id: None,
            command_id: Some("01COMMAND000000000000000000".to_string()),
            command_name: Some("play".to_string()),
            custom_id: None,
            values: Vec::new(),
            options: Default::default(),
            focused_option: Some("track".to_string()),
            modal: None,
            submitted_values: Vec::new(),
            submitted: false,
            responded: false,
        }
    }

    #[test]
    fn autocomplete_response_is_single_use_and_short_lived() {
        crate::util::test::rt().block_on(autocomplete_response_is_single_use_and_short_lived_case())
    }

    async fn autocomplete_response_is_single_use_and_short_lived_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let (bot, _) = setup_bot(&harness, &user, &server).await;
        let (other_bot, _) = setup_bot(&harness, &user, &server).await;

        let interaction = autocomplete_row(
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

        let url = format!("/interactions/{}/autocomplete", interaction.id);
        let choices = json!({
            "token": "sekrit-token",
            "choices": [{ "name": "Blue Monday", "value": "track_1" }]
        });

        // Wrong token → 401
        let response = harness
            .client
            .post(&url)
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "wrong", "choices": [] }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized);

        // Another bot holding the right token → 404
        let response = harness
            .client
            .post(&url)
            .header(Header::new("x-bot-token", other_bot.token.clone()))
            .header(ContentType::JSON)
            .body(choices.to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // A user session cannot answer autocomplete
        let response = harness
            .client
            .post(&url)
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(choices.to_string())
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::NoContent);

        // Over the choice cap
        let too_many: Vec<serde_json::Value> = (0..26)
            .map(|index| json!({ "name": format!("n{index}"), "value": format!("v{index}") }))
            .collect();
        let response = harness
            .client
            .post(&url)
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "sekrit-token", "choices": too_many }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // The real answer
        let response = harness
            .client
            .post(&url)
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(choices.to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);

        // Answering twice loses
        let response = harness
            .client
            .post(&url)
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(choices.to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Conflict);

        // A message reply is not a valid answer to an autocomplete, and an
        // autocomplete answer is not valid for a command interaction.
        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "sekrit-token", "content": "hi" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Autocomplete runs on a one-minute clock, not the fifteen-minute
        // one: a row already older than that window is gone.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        let stale = autocomplete_row(
            ulid::Ulid::from_parts(now_ms - AUTOCOMPLETE_TTL_MS - 5_000, 7).to_string(),
            "sekrit-token",
            &bot.id,
            &user.id,
            channel.id(),
        );
        harness
            .db
            .insert_interaction(&stale)
            .await
            .expect("stale interaction");

        let response = harness
            .client
            .post(format!("/interactions/{}/autocomplete", stale.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(choices.to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Gone);
    }
}
