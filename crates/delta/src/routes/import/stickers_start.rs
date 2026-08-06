//! Start the optional sticker-import step after a template import finished.
//! POST /import/discord/jobs/<job_id>/stickers
//!
//! Requires the importer bot to have been added to the source guild by the
//! user (the client walks them through it). This route has NO body at all —
//! the guild id, server id and ownership are all resolved server-side from
//! the owner-scoped parent job row, so there is nothing for a client to
//! spoof.

use revolt_config::config;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::{Database, DiscordImportJob, ImportJobKind, ImportStatus, User};
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;

use super::dto::ImportJobResponse;

/// # Import Stickers From Discord
///
/// Queues a sticker import from the Discord guild a finished template import
/// came from. Returns the NEW job to follow; progress streams over the same
/// private WebSocket topic as the template import.
#[openapi(tag = "Import")]
#[post("/discord/jobs/<job_id>/stickers")]
pub async fn import_discord_stickers(
    db: &State<Database>,
    user: User,
    job_id: &str,
) -> Result<Json<ImportJobResponse>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let config = config().await;
    if !config.api.import.discord.stickers_enabled() {
        return Err(create_error!(OperationFailed));
    }

    let parent = db.fetch_discord_import_job(job_id).await?;

    // Owner-scoped: someone else's job must be indistinguishable from one
    // that doesn't exist.
    if parent.user_id != user.id {
        return Err(create_error!(NotFound));
    }

    // Only a successfully finished TEMPLATE import can seed a sticker run.
    // `source_guild_id` is absent on jobs that predate this slice — those
    // clients never see the offer, but reject it here too rather than
    // queueing a job the worker can only fail.
    if !matches!(parent.kind, ImportJobKind::Template)
        || !matches!(parent.status, ImportStatus::Completed)
        || parent.server_id.is_none()
        || parent.source_guild_id.is_none()
    {
        return Err(create_error!(InvalidOperation));
    }

    // The sticker step is sugar over the sticker CRUD, so it demands exactly
    // the permission the CRUD demands (`sticker_create.rs`). This also covers
    // "the user gave the server away or left it after importing" — and 404s
    // (server deleted) surface here as-is. The worker re-checks at run time.
    let server = db
        .fetch_server(parent.server_id.as_deref().expect("checked above"))
        .await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageCustomisation)?;

    // Friendly early exit; the storage-layer partial unique index is the
    // real guard (two concurrent posts → the second insert 409s).
    if db
        .fetch_active_discord_import_job_for_user(&user.id)
        .await?
        .is_some()
    {
        return Err(create_error!(ImportAlreadyInProgress));
    }

    let job = DiscordImportJob::new_stickers(&parent);
    db.insert_discord_import_job(&job).await?;

    Ok(Json(job.into()))
}
