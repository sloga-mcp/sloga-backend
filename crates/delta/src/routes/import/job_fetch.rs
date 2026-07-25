//! Poll the status of a server import.
//! GET /import/discord/jobs/<job_id>
//!
//! Progress is pushed over the user's private WebSocket topic; this endpoint
//! is the reconnect-safe fallback for a client that missed those events.

use revolt_database::{Database, User};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;

use super::dto::ImportJobResponse;

/// # Fetch Import Job
///
/// Returns the current state of one of your import jobs.
#[openapi(tag = "Import")]
#[get("/discord/jobs/<job_id>")]
pub async fn fetch_import_job(
    db: &State<Database>,
    user: User,
    job_id: &str,
) -> Result<Json<ImportJobResponse>> {
    let job = db.fetch_discord_import_job(job_id).await?;

    // Owner-scoped: someone else's job must be indistinguishable from one that
    // doesn't exist.
    if job.user_id != user.id {
        return Err(create_error!(NotFound));
    }

    Ok(Json(job.into()))
}
