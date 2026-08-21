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
