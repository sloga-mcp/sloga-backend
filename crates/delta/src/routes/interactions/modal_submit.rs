use std::time::{SystemTime, UNIX_EPOCH};

use revolt_database::events::client::EventV1;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Channel, Database, InteractionKind, ModalValue, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Submit a Modal
///
/// Send a filled-in form back to the bot that asked for it. Authenticated as
/// the user the form was shown to — there is no bot token involved, and no
/// other account can submit someone else's form.
///
/// Submissions are validated against the definition stored when the modal
/// was opened, never against anything the client echoes back.
#[openapi(tag = "Interactions")]
#[post("/<target>/modal-submit", data = "<data>")]
pub async fn interaction_modal_submit(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataModalSubmit>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();

    // A bot is never the audience for its own form.
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let mut interaction = db.fetch_interaction(target.id).await?;

    // The form belongs to exactly one user. Anyone else — including someone
    // who guessed the id — gets NotFound rather than a permission error, so
    // the route leaks nothing about which ids exist.
    if interaction.user_id != user.id {
        return Err(create_error!(NotFound));
    }

    if !matches!(interaction.kind, InteractionKind::ModalSubmit) {
        return Err(create_error!(InvalidOperation));
    }

    let Some(modal) = interaction.modal.clone() else {
        return Err(create_error!(InvalidOperation));
    };

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    if interaction.is_expired(now_ms) {
        return Err(create_error!(InteractionExpired));
    }

    modal
        .validate_submission(&data.values)
        .map_err(|error| create_error!(FailedValidation { error }))?;

    // Re-check the SUBMITTER's standing: submitting is what causes the bot
    // to post, so someone who has since lost the right to speak here must
    // not be able to trigger that through a form left open.
    let channel = db
        .fetch_channel(&interaction.channel_id)
        .await
        .map_err(|_| create_error!(NotFound))?;

    // Restated rather than inherited: for saved messages in particular the
    // owner holds SendMessage, so the permission check below would fail OPEN
    // if a future producer ever created an interaction there.
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

    // A thread is judged by its parent: a thread under a protected channel
    // takes no bot traffic either
    crate::util::interactions::ensure_interactions_allowed_in(&channel, &permission_channel)?;

    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    // The bot must ALSO still be party to the conversation. This route is the
    // one place in the chain that carries the user's own typed words to the
    // bot, so a kick between opening the form and submitting it has to stop
    // delivery — otherwise a removed bot still receives whatever was typed
    // into a dialog it left on screen.
    match &channel {
        Channel::Group { recipients, .. } => {
            if !recipients.contains(&interaction.bot_id) {
                return Err(create_error!(NotFound));
            }
        }
        Channel::TextChannel { server, .. } | Channel::Thread { server, .. } => {
            db.fetch_member(server, &interaction.bot_id)
                .await
                .map_err(|_| create_error!(NotFound))?;
        }
        _ => return Err(create_error!(InvalidOperation)),
    }

    let bot_user = db
        .fetch_user(&interaction.bot_id)
        .await
        .map_err(|_| create_error!(NotFound))?;
    let mut bot_query = DatabasePermissionQuery::new(db, &bot_user).channel(&permission_channel);
    calculate_channel_permissions(&mut bot_query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    // Checked BEFORE the claim: a bot that is briefly away should cost the
    // user a retry, not the form they just filled in.
    if !revolt_presence::is_online(&interaction.bot_id).await {
        return Err(create_error!(BotOffline));
    }

    // Built from the form's own field list, in its declared order, so fields
    // it never declared cannot reach the bot even if validation were somehow
    // bypassed. An omitted optional field arrives as an empty string rather
    // than as an absent key: the bot asked for it, so it gets an answer, and
    // indexing the map never needs a guard.
    let values: Vec<ModalValue> = modal
        .inputs
        .iter()
        .map(|input| ModalValue {
            custom_id: input.custom_id.clone(),
            value: data
                .values
                .get(&input.custom_id)
                .cloned()
                .unwrap_or_default(),
        })
        .collect();

    // Single-use, atomically: a double submit loses the claim rather than
    // sending the bot a second copy.
    if !db.try_submit_modal(&interaction.id, &values).await? {
        return Err(create_error!(InteractionAlreadyResponded));
    }

    interaction.submitted_values = values;
    interaction.submitted = true;

    let bot_id = interaction.bot_id.clone();

    // Private topic ONLY — this is where the bot finally receives the
    // submission's response token.
    EventV1::InteractionCreate {
        interaction: interaction.into_wire(),
    }
    .private(bot_id)
    .await;

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::events::client::EventV1;
    use revolt_database::{
        Bot, Channel, Database, Interaction, InteractionKind, Member, PartialChannel, Server, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
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

    /// A thread under `parent`, stored directly. With the parent protected
    /// afterwards it stands for the thread `create_thread` leaves behind when
    /// its delete after a refused hold fails (W2 audit B1).
    async fn thread_under(harness: &TestHarness, parent: &Channel, creator: &str) -> Channel {
        let thread = Channel::Thread {
            id: ulid::Ulid::new().to_string(),
            server: parent.server().expect("a server channel").to_string(),
            parent_channel: parent.id().to_string(),
            name: "Thread".to_string(),
            creator: creator.to_string(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: 0,
            locked: false,
            applied_tags: vec![],
        };
        harness.db.insert_channel(&thread).await.expect("thread");
        thread
    }

    /// Set `protected` on a stored TextChannel, raw, under the interactions
    /// already stored for its threads
    async fn protect_raw(db: &Database, channel_id: &str) {
        match db {
            Database::Reference(reference) => {
                match reference.channels.lock().await.get_mut(channel_id) {
                    Some(Channel::TextChannel { protected, .. }) => *protected = true,
                    other => panic!("expected a text channel, got {:?}", other),
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let result = mongo
                    .col::<Document>("channels")
                    .update_one(
                        doc! { "_id": channel_id },
                        doc! { "$set": { "protected": true } },
                    )
                    .await
                    .expect("raw protect");
                assert_eq!(result.matched_count, 1);
            }
        }

        assert!(db
            .fetch_channel(channel_id)
            .await
            .expect("channel")
            .is_protected());
    }

    /// A form opened through the modal route on a fresh command interaction
    /// of `user` in `channel_id`; returns the submission's id
    async fn opened_form(
        harness: &TestHarness,
        bot: &Bot,
        user: &User,
        channel_id: &str,
    ) -> String {
        let source = Interaction {
            id: ulid::Ulid::new().to_string(),
            kind: InteractionKind::Command,
            token: "tok-form".to_string(),
            bot_id: bot.id.clone(),
            user_id: user.id.clone(),
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
        };
        harness
            .db
            .insert_interaction(&source)
            .await
            .expect("interaction");

        let response = harness
            .client
            .post(format!("/interactions/{}/modal", source.id))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "token": "tok-form",
                    "modal": {
                        "custom_id": "report",
                        "title": "Report a problem",
                        "inputs": [{
                            "custom_id": "summary",
                            "label": "What happened?",
                            "style": "Short",
                            "required": true
                        }]
                    }
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let opened: v0::CreateInteractionResponse = response
            .into_json()
            .await
            .expect("`CreateInteractionResponse`");
        opened.interaction_id
    }

    async fn submit(harness: &TestHarness, token: &str, submission_id: &str) -> (Status, String) {
        let response = harness
            .client
            .post(format!("/interactions/{submission_id}/modal-submit"))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "values": { "summary": "typed into a form" } }).to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// W2 audit B1 (re-review L1): a thread is judged by its parent. A form
    /// opened in a thread whose parent is protected since is refused at
    /// submit with `ChannelProtected`, after the submitter's permission
    /// check: the slot stays unsubmitted and no `InteractionCreate` reaches
    /// the bot, which is online, so without the refusal the typed values
    /// would be delivered.
    ///
    /// Control: the `ensure_interactions_allowed_in` line removed → the
    /// submission is delivered (204).
    #[test]
    fn modal_submit_in_a_thread_under_a_protected_parent_is_refused() {
        crate::util::test::rt()
            .block_on(modal_submit_in_a_thread_under_a_protected_parent_is_refused_case())
    }

    async fn modal_submit_in_a_thread_under_a_protected_parent_is_refused_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, parent) = harness.new_protectable_channel(&user).await;
        let orphan = thread_under(&harness, &parent, &user.id).await;
        let (bot, _) = setup_bot(&harness, &user, &server).await;

        let submission_id = opened_form(&harness, &bot, &user, orphan.id()).await;
        protect_raw(&harness.db, parent.id()).await;

        let (_, presence_session) = revolt_presence::create_session(&bot.id, 0).await;
        let refused = submit(&harness, &session.token, &submission_id).await;
        revolt_presence::delete_session(&bot.id, presence_session).await;

        assert_eq!(refused.0, Status::BadRequest, "{:?}", refused);
        let error: serde_json::Value = serde_json::from_str(&refused.1).expect("JSON");
        assert_eq!(error["type"], "ChannelProtected", "{}", refused.1);

        let stored = harness
            .db
            .fetch_interaction(&submission_id)
            .await
            .expect("submission row");
        assert!(!stored.submitted);
        assert!(stored.submitted_values.is_empty());

        // Marker on the bot's private topic: once seen, anything the refused
        // submit published there is buffered too
        let marker = ulid::Ulid::new().to_string();
        EventV1::ChannelAck {
            id: ulid::Ulid::new().to_string(),
            user: bot.id.clone(),
            message_id: marker.clone(),
        }
        .private(bot.id.clone())
        .await;
        harness
            .wait_for_event(&format!("{}!", bot.id), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &marker,
                _ => false,
            })
            .await;
        harness.assert_no_buffered_event(&format!("{}!", bot.id), |event| match event {
            EventV1::InteractionCreate { interaction } => interaction.id == submission_id,
            _ => false,
        });
    }

    /// Decision 18 (W2): a submitter who can no longer view the parent gets
    /// the pre-W2 answer, byte-identical (type, status, body) for a thread
    /// under a protected parent and one under an open parent.
    #[test]
    fn modal_submit_without_view_is_identical_protected_or_not() {
        crate::util::test::rt()
            .block_on(modal_submit_without_view_is_identical_protected_or_not_case())
    }

    async fn modal_submit_without_view_is_identical_protected_or_not_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, session, member) = harness.new_user().await;
        let (server, protected_parent) = harness.new_protectable_channel(&owner).await;
        harness.join_server(&server, &member).await;
        let open_parent = harness.new_channel(&server).await;
        let (bot, _) = setup_bot(&harness, &owner, &server).await;

        let mut forms = Vec::new();
        for parent in [&protected_parent, &open_parent] {
            let thread = thread_under(&harness, parent, &owner.id).await;
            forms.push(opened_form(&harness, &bot, &member, thread.id()).await);
        }
        protect_raw(&harness.db, protected_parent.id()).await;
        for parent in [&protected_parent, &open_parent] {
            let mut parent = harness
                .db
                .fetch_channel(parent.id())
                .await
                .expect("the parent");
            parent
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

        let on_protected = submit(&harness, &session.token, &forms[0]).await;
        let on_open = submit(&harness, &session.token, &forms[1]).await;
        assert_eq!(on_open.0, Status::Forbidden, "{:?}", on_open);
        assert!(on_open.1.contains("MissingPermission"), "{}", on_open.1);
        assert_eq!(on_protected, on_open);
    }
}
