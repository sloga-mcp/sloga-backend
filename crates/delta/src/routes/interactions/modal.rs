use std::time::{SystemTime, UNIX_EPOCH};

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
use validator::Validate;

/// # Open a Modal
///
/// Answer an interaction by asking the invoking user to fill in a form.
/// This consumes the interaction's single response slot, so it is an
/// alternative to replying with a message rather than something you can do
/// as well as replying.
///
/// A fresh interaction is created for the submission, with its own token and
/// its own 15-minute window. Its id is returned here and also delivered to
/// the user; its token stays server-side until they submit, at which point
/// the filled-in form arrives as an ordinary `InteractionCreate` of kind
/// `ModalSubmit`.
#[openapi(tag = "Interactions")]
#[post("/<target>/modal", data = "<data>")]
pub async fn interaction_modal(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataInteractionModal>,
) -> Result<Json<v0::CreateInteractionResponse>> {
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

    if interaction.bot_id != user.id {
        return Err(create_error!(NotFound));
    }
    interaction.assert_token(&data.token)?;

    // A command invocation or a component click can be answered with a
    // form. A modal submission cannot — chaining forms would let a bot hold
    // a user in a dialog loop they never asked to enter — and autocomplete
    // is answered with suggestions, not UI.
    if !matches!(
        interaction.kind,
        InteractionKind::Command | InteractionKind::Component
    ) {
        return Err(create_error!(InvalidOperation));
    }

    data.modal
        .validate_structure()
        .map_err(|error| create_error!(FailedValidation { error }))?;

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    if interaction.is_expired(now_ms) {
        return Err(create_error!(InteractionExpired));
    }

    // Re-check the bot's standing NOW, exactly as the message-response path
    // does. Opening a form is not itself a channel write, but the response
    // to the submission is — better to refuse the dialog than to collect
    // someone's typing and then fail to do anything with it.
    let channel = db
        .fetch_channel(&interaction.channel_id)
        .await
        .map_err(|_| create_error!(NotFound))?;

    // Restated rather than inherited from whoever created the source
    // interaction: this route re-resolves the channel precisely because state
    // moves underneath it, and the structural rule is the one check a
    // permission query cannot stand in for.
    crate::util::interactions::ensure_interactions_allowed(&channel)?;

    if let Channel::Group { recipients, .. } = &channel {
        if !recipients.contains(&user.id) {
            return Err(create_error!(NotFound));
        }
    }

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    // The submission is its own interaction. Its token is generated here but
    // NOT sent anywhere yet: the user authenticates their submission with
    // their own session, and the bot only learns this token once the form
    // comes back to it.
    let submission = Interaction {
        id: Ulid::new().to_string(),
        kind: InteractionKind::ModalSubmit,
        token: nanoid::nanoid!(64),
        bot_id: user.id.clone(),
        user_id: interaction.user_id.clone(),
        channel_id: interaction.channel_id.clone(),
        // Carried forward so the submission can still edit the message the
        // click came from, and still attribute to the command that was run.
        message_id: interaction.message_id.clone(),
        command_id: interaction.command_id.clone(),
        command_name: interaction.command_name.clone(),
        custom_id: Some(data.modal.custom_id.clone()),
        values: Vec::new(),
        options: Default::default(),
        focused_option: None,
        modal: Some(data.modal.clone()),
        submitted_values: Vec::new(),
        submitted: false,
        responded: false,
    };

    // Insert BEFORE claiming: the row is inert until it is both published and
    // submitted, so a failed write costs nothing — whereas claiming first and
    // then failing to write would spend the source's only response on a form
    // that does not exist, leaving the command permanently unanswerable.
    db.insert_interaction(&submission).await?;

    // Single-use: claim the source's response slot, so a replayed request
    // cannot pop a second dialog.
    if !db.try_claim_interaction_response(&interaction.id).await? {
        return Err(create_error!(InteractionAlreadyResponded));
    }

    let interaction_id = submission.id.clone();

    EventV1::InteractionModalOpen {
        interaction_id: submission.id,
        source_id: interaction.id,
        modal: data.modal,
    }
    .private(interaction.user_id)
    .await;

    Ok(Json(v0::CreateInteractionResponse { interaction_id }))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{Bot, Interaction, InteractionKind, Member, Server, User};
    use revolt_models::v0;
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

    fn command_row(token: &str, bot_id: &str, user_id: &str, channel_id: &str) -> Interaction {
        Interaction {
            id: ulid::Ulid::new().to_string(),
            kind: InteractionKind::Command,
            token: token.to_string(),
            bot_id: bot_id.to_string(),
            user_id: user_id.to_string(),
            channel_id: channel_id.to_string(),
            message_id: None,
            command_id: Some("01COMMAND000000000000000000".to_string()),
            command_name: Some("report".to_string()),
            custom_id: None,
            values: Vec::new(),
            options: Default::default(),
            focused_option: None,
            modal: None,
            submitted_values: Vec::new(),
            submitted: false,
            responded: false,
        }
    }

    fn modal_body(token: &str) -> serde_json::Value {
        json!({
            "token": token,
            "modal": {
                "custom_id": "report",
                "title": "Report a problem",
                "inputs": [
                    {
                        "custom_id": "summary",
                        "label": "What happened?",
                        "style": "Short",
                        "required": true,
                        "max_length": 40
                    },
                    {
                        "custom_id": "detail",
                        "label": "Any details",
                        "style": "Paragraph"
                    }
                ]
            }
        })
    }

    #[test]
    fn modal_open_claims_the_response_slot() {
        crate::util::test::rt().block_on(modal_open_claims_the_response_slot_case())
    }

    async fn modal_open_claims_the_response_slot_case() {
        let harness = TestHarness::new().await;
        let (_, _session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let (bot, _) = setup_bot(&harness, &user, &server).await;
        let (other_bot, _) = setup_bot(&harness, &user, &server).await;

        let interaction = command_row("sekrit-token", &bot.id, &user.id, channel.id());
        harness
            .db
            .insert_interaction(&interaction)
            .await
            .expect("interaction");

        // Wrong token → 401
        let response = harness
            .client
            .post(format!("/interactions/{}/modal", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(modal_body("wrong").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized);

        // Another bot holding the right token → 404, no existence leak
        let response = harness
            .client
            .post(format!("/interactions/{}/modal", interaction.id))
            .header(Header::new("x-bot-token", other_bot.token.clone()))
            .header(ContentType::JSON)
            .body(modal_body("sekrit-token").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // A malformed form is rejected before anything is claimed
        let response = harness
            .client
            .post(format!("/interactions/{}/modal", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "token": "sekrit-token",
                    "modal": { "custom_id": "x", "title": "No fields", "inputs": [] }
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // The real thing
        let response = harness
            .client
            .post(format!("/interactions/{}/modal", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(modal_body("sekrit-token").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let opened: v0::CreateInteractionResponse =
            response.into_json().await.expect("`CreateInteractionResponse`");

        // The submission is a DIFFERENT interaction, with its own token
        assert_ne!(opened.interaction_id, interaction.id);
        let submission = harness
            .db
            .fetch_interaction(&opened.interaction_id)
            .await
            .expect("submission row");
        assert_ne!(submission.token, interaction.token);
        assert_eq!(submission.bot_id, bot.id);
        assert_eq!(submission.user_id, user.id);
        assert_eq!(submission.command_name.as_deref(), Some("report"));
        assert!(!submission.submitted);

        // Opening a form spends the original interaction's one response, so
        // a second attempt — and an ordinary message reply — both lose.
        let response = harness
            .client
            .post(format!("/interactions/{}/modal", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(modal_body("sekrit-token").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Conflict);

        let response = harness
            .client
            .post(format!("/interactions/{}/respond", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "token": "sekrit-token", "content": "hi" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Conflict);

        // A form cannot be opened from a form submission
        let response = harness
            .client
            .post(format!("/interactions/{}/modal", submission.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(modal_body(&submission.token).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
    }

    #[test]
    fn modal_submission_is_validated_and_single_use() {
        crate::util::test::rt().block_on(modal_submission_is_validated_and_single_use_case())
    }

    async fn modal_submission_is_validated_and_single_use_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, outsider_session, _) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let (bot, _) = setup_bot(&harness, &user, &server).await;

        let interaction = command_row("sekrit-token", &bot.id, &user.id, channel.id());
        harness
            .db
            .insert_interaction(&interaction)
            .await
            .expect("interaction");

        let response = harness
            .client
            .post(format!("/interactions/{}/modal", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(modal_body("sekrit-token").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let opened: v0::CreateInteractionResponse =
            response.into_json().await.expect("`CreateInteractionResponse`");
        let submit_url = format!("/interactions/{}/modal-submit", opened.interaction_id);

        // Somebody else's form is not submittable, and does not confirm it exists
        let response = harness
            .client
            .post(&submit_url)
            .header(Header::new(
                "x-session-token",
                outsider_session.token.to_string(),
            ))
            .header(ContentType::JSON)
            .body(json!({ "values": { "summary": "mine now" } }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // A missing required field is refused
        let response = harness
            .client
            .post(&submit_url)
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "values": { "detail": "no summary" } }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // So is a field the form never declared
        let response = harness
            .client
            .post(&submit_url)
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "values": { "summary": "ok", "admin": "true" } }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // And so is a value longer than the form allowed
        let response = harness
            .client
            .post(&submit_url)
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "values": { "summary": "x".repeat(41) } }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Nothing above should have consumed the submission
        let submission = harness
            .db
            .fetch_interaction(&opened.interaction_id)
            .await
            .expect("submission row");
        assert!(!submission.submitted);

        // The bot has no live session in tests, so a valid submission fails
        // fast rather than burning the one submit slot.
        let response = harness
            .client
            .post(&submit_url)
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "values": { "summary": "the button did nothing" } }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        let submission = harness
            .db
            .fetch_interaction(&opened.interaction_id)
            .await
            .expect("submission row");
        assert!(
            !submission.submitted,
            "an offline bot must not consume the submit slot"
        );
    }

    #[test]
    fn kicked_bot_never_receives_the_submission() {
        crate::util::test::rt().block_on(kicked_bot_never_receives_the_submission_case())
    }

    async fn kicked_bot_never_receives_the_submission_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let (bot, bot_user) = setup_bot(&harness, &user, &server).await;

        let interaction = command_row("sekrit-token", &bot.id, &user.id, channel.id());
        harness
            .db
            .insert_interaction(&interaction)
            .await
            .expect("interaction");

        let response = harness
            .client
            .post(format!("/interactions/{}/modal", interaction.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(modal_body("sekrit-token").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let opened: v0::CreateInteractionResponse =
            response.into_json().await.expect("`CreateInteractionResponse`");

        // The form is on the user's screen; now the bot is removed from the
        // server. Whatever they type must not reach it.
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
            .post(format!(
                "/interactions/{}/modal-submit",
                opened.interaction_id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "values": { "summary": "sensitive report text" } }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // And the slot survives, so the rejection is not also a data loss if
        // the bot is later re-added.
        let submission = harness
            .db
            .fetch_interaction(&opened.interaction_id)
            .await
            .expect("submission row");
        assert!(!submission.submitted);
        assert!(submission.submitted_values.is_empty());
    }
}
