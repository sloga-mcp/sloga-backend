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

/// # Interact with Component
///
/// Click a button or submit a select on a bot message. Creates a transient
/// Component interaction addressed to the message's bot; the bot receives it
/// (with a single-use response token) on its private topic and replies via
/// `POST /interactions/{id}/respond` — with a new message, or `edit: true`
/// to update the message the component lives on.
///
/// Requires only ViewChannel + ReadMessageHistory: users who cannot send
/// messages may still click components (the bot's own response is
/// permission-checked separately at respond time).
#[openapi(tag = "Interactions")]
#[post("/<target>/messages/<msg>/interact", data = "<data>")]
pub async fn message_interact(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
    data: Json<v0::DataMessageInteract>,
) -> Result<Json<v0::CreateInteractionResponse>> {
    let data = data.into_inner();

    // Bots don't click other bots' buttons.
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let channel = target.as_channel(db).await?;

    // Same structural exclusions as invoking a command (E2EE fail-closed):
    // no forums, DMs or saved messages.
    match &channel {
        Channel::Forum { .. }
        | Channel::DirectMessage { .. }
        | Channel::SavedMessages { .. } => {
            return Err(create_error!(InvalidOperation));
        }
        _ => {}
    }

    // Threads inherit their parent channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ReadMessageHistory)?;

    // Archived / locked threads are read-only: clicking would create an
    // interaction whose response is guaranteed to be rejected — fail early.
    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    let message = msg.as_message_in_channel(db, channel.id()).await?;

    // Find the clicked component on the message — a custom_id the message
    // doesn't carry must not fan anything out to the bot.
    let component = message
        .components
        .as_deref()
        .unwrap_or_default()
        .iter()
        .flat_map(|row| row.components.iter())
        .find(|component| component.custom_id() == data.custom_id)
        .ok_or_else(|| create_error!(NotFound))?;

    if component.is_disabled() {
        return Err(create_error!(InvalidOperation));
    }

    // Validate the submitted values against the component's shape: buttons
    // carry none; selects submit exactly one of their declared options.
    match component {
        v0::Component::Button { .. } => {
            if !data.values.is_empty() {
                return Err(create_error!(FailedValidation {
                    error: "buttons do not accept values".to_string()
                }));
            }
        }
        v0::Component::StringSelect { options, .. } => {
            let [value] = data.values.as_slice() else {
                return Err(create_error!(FailedValidation {
                    error: "selects require exactly one value".to_string()
                }));
            };
            if !options.iter().any(|option| &option.value == value) {
                return Err(create_error!(FailedValidation {
                    error: "value is not one of the select's options".to_string()
                }));
            }
        }
    }

    // Only bot messages carry components (the send path enforces this), but
    // the bot must ALSO still be party to the conversation — a kicked bot's
    // stale buttons must not fan out.
    let bot_id = message.author.clone();
    let bot_user = db.fetch_user(&bot_id).await.map_err(|_| create_error!(NotFound))?;
    if bot_user.bot.is_none() {
        return Err(create_error!(InvalidOperation));
    }

    match &channel {
        Channel::Group { recipients, .. } => {
            if !recipients.contains(&bot_id) {
                return Err(create_error!(NotFound));
            }
        }
        Channel::TextChannel { server, .. } | Channel::Thread { server, .. } => {
            db.fetch_member(server, &bot_id)
                .await
                .map_err(|_| create_error!(NotFound))?;
        }
        // Already rejected above.
        _ => return Err(create_error!(InvalidOperation)),
    }

    // Fail fast if the bot has no live session — nothing would ever answer.
    if !revolt_presence::is_online(&bot_id).await {
        return Err(create_error!(BotOffline));
    }

    let interaction = Interaction {
        id: Ulid::new().to_string(),
        kind: InteractionKind::Component,
        // Response token: secret between server and bot (same shape as
        // command invocations).
        token: nanoid::nanoid!(64),
        bot_id: bot_id.clone(),
        user_id: user.id.clone(),
        channel_id: channel.id().to_string(),
        message_id: Some(message.id.clone()),
        command_id: None,
        command_name: None,
        custom_id: Some(data.custom_id),
        values: data.values,
        options: Default::default(),
        responded: false,
    };

    db.insert_interaction(&interaction).await?;

    let interaction_id = interaction.id.clone();

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
    use revolt_database::{
        Bot, Interaction, InteractionKind, Member, Message, PartialChannel, Server, User,
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

    fn component_rows() -> Vec<v0::ActionRow> {
        vec![
            v0::ActionRow {
                components: vec![
                    v0::Component::Button {
                        custom_id: "btn_a".to_string(),
                        label: "Click me".to_string(),
                        style: v0::ButtonStyle::Primary,
                        disabled: false,
                    },
                    v0::Component::Button {
                        custom_id: "btn_off".to_string(),
                        label: "Disabled".to_string(),
                        style: v0::ButtonStyle::Secondary,
                        disabled: true,
                    },
                ],
            },
            v0::ActionRow {
                components: vec![v0::Component::StringSelect {
                    custom_id: "sel_a".to_string(),
                    options: vec![
                        v0::SelectOption {
                            label: "Option X".to_string(),
                            value: "x".to_string(),
                        },
                        v0::SelectOption {
                            label: "Option Y".to_string(),
                            value: "y".to_string(),
                        },
                    ],
                    placeholder: None,
                    disabled: false,
                }],
            },
        ]
    }

    async fn insert_bot_message(
        harness: &TestHarness,
        channel_id: &str,
        author_id: &str,
    ) -> Message {
        let message = Message {
            id: ulid::Ulid::new().to_string(),
            channel: channel_id.to_string(),
            author: author_id.to_string(),
            content: Some("pick something".to_string()),
            components: Some(component_rows()),
            ..Default::default()
        };
        harness
            .db
            .insert_message(&message)
            .await
            .expect("message");
        message
    }

    #[rocket::async_test]
    async fn interact_validates_and_fans_out() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let (bot, _) = setup_bot(&harness, &user, &server).await;
        let message = insert_bot_message(&harness, channel.id(), &bot.id).await;

        let interact = |body: serde_json::Value| {
            harness
                .client
                .post(format!(
                    "/channels/{}/messages/{}/interact",
                    channel.id(),
                    message.id
                ))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(body.to_string())
        };

        // A custom_id the message does not carry must not fan out
        let response = interact(json!({ "custom_id": "nope" })).dispatch().await;
        assert_eq!(response.status(), Status::NotFound);

        // Buttons take no values; selects take exactly one of their options
        let response = interact(json!({ "custom_id": "btn_a", "values": ["x"] }))
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok);
        let response = interact(json!({ "custom_id": "sel_a" })).dispatch().await;
        assert_ne!(response.status(), Status::Ok);
        let response = interact(json!({ "custom_id": "sel_a", "values": ["z"] }))
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok);

        // Disabled components reject interaction
        let response = interact(json!({ "custom_id": "btn_off" })).dispatch().await;
        assert_ne!(response.status(), Status::Ok);

        // Offline bot fails fast — nothing would ever answer
        let response = interact(json!({ "custom_id": "btn_a" })).dispatch().await;
        assert_ne!(response.status(), Status::Ok);

        // With a live bot session the click goes through
        let (_, presence_session) = revolt_presence::create_session(&bot.id, 0).await;

        let response = interact(json!({ "custom_id": "btn_a" })).dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let created: v0::CreateInteractionResponse = response
            .into_json()
            .await
            .expect("`CreateInteractionResponse`");

        let row: Interaction = harness
            .db
            .fetch_interaction(&created.interaction_id)
            .await
            .expect("interaction row");
        assert!(matches!(row.kind, InteractionKind::Component));
        assert_eq!(row.bot_id, bot.id);
        assert_eq!(row.user_id, user.id);
        assert_eq!(row.message_id.as_deref(), Some(message.id.as_str()));
        assert_eq!(row.custom_id.as_deref(), Some("btn_a"));
        assert!(row.values.is_empty());

        // Select clicks record the submitted value
        let response = interact(json!({ "custom_id": "sel_a", "values": ["y"] }))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let created: v0::CreateInteractionResponse = response
            .into_json()
            .await
            .expect("`CreateInteractionResponse`");
        let row = harness
            .db
            .fetch_interaction(&created.interaction_id)
            .await
            .expect("interaction row");
        assert_eq!(row.values, vec!["y".to_string()]);

        revolt_presence::delete_session(&bot.id, presence_session).await;
    }

    #[rocket::async_test]
    async fn interact_rejects_non_bot_targets_and_kicked_bots() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        // A components-bearing message from a NON-bot author (inserted
        // directly, bypassing the send path bot-only rule) must not fan
        // out interactions.
        let forged = insert_bot_message(&harness, channel.id(), &user.id).await;
        let response = harness
            .client
            .post(format!(
                "/channels/{}/messages/{}/interact",
                channel.id(),
                forged.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "custom_id": "btn_a" }).to_string())
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok);

        // A kicked bot has stale buttons — they must not fan out either
        let (bot, bot_user) = setup_bot(&harness, &user, &server).await;
        let message = insert_bot_message(&harness, channel.id(), &bot.id).await;

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
                "/channels/{}/messages/{}/interact",
                channel.id(),
                message.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "custom_id": "btn_a" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);
    }

    #[rocket::async_test]
    async fn components_are_bot_only_on_send() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let (bot, _) = setup_bot(&harness, &user, &server).await;

        let components = json!([
            { "components": [
                { "type": "Button", "custom_id": "b", "label": "Hi", "style": "Primary" }
            ] }
        ]);

        // Regular users cannot attach components
        let response = harness
            .client
            .post(format!("/channels/{}/messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "content": "mine", "components": components }).to_string())
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "non-bot senders must not attach components"
        );

        // Bots can — and the field round-trips
        let response = harness
            .client
            .post(format!("/channels/{}/messages", channel.id()))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "content": "bots may", "components": components }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let message: v0::Message = response.into_json().await.expect("`Message`");
        let rows = message.components.expect("components");
        assert_eq!(rows.len(), 1);

        // Structural limits are enforced on the send path too (6 rows)
        let six_rows: Vec<serde_json::Value> = (0..6)
            .map(|i| {
                json!({ "components": [
                    { "type": "Button", "custom_id": format!("b{i}"), "label": "Hi", "style": "Primary" }
                ] })
            })
            .collect();
        let response = harness
            .client
            .post(format!("/channels/{}/messages", channel.id()))
            .header(Header::new("x-bot-token", bot.token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "content": "too many", "components": six_rows }).to_string())
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "structural limits must apply to the send path"
        );
    }

    #[rocket::async_test]
    async fn interact_requires_view_channel() {
        let harness = TestHarness::new().await;
        let (_, _owner_session, owner) = harness.new_user().await;
        let (_, viewer_session, viewer) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let mut channel = harness.new_channel(&server).await;

        let (bot, _) = setup_bot(&harness, &owner, &server).await;
        let message = insert_bot_message(&harness, channel.id(), &bot.id).await;

        Member::create(&harness.db, &server, &viewer, None)
            .await
            .expect("member");

        // Deny ViewChannel by default — a plain member with no roles must
        // not be able to fan interactions out of a channel they can't see.
        channel
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

        let response = harness
            .client
            .post(format!(
                "/channels/{}/messages/{}/interact",
                channel.id(),
                message.id
            ))
            .header(Header::new(
                "x-session-token",
                viewer_session.token.to_string(),
            ))
            .header(ContentType::JSON)
            .body(json!({ "custom_id": "btn_a" }).to_string())
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "a member denied ViewChannel must not interact"
        );
    }
}
