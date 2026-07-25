//! Fetch the caller's in-flight import, if any.
//! GET /import/discord/active
//!
//! Recovery path: progress normally arrives over the WebSocket and the client
//! holds the job id from `POST /import/discord/template`. If the user dismisses
//! the modal or reloads mid-import, that id is gone — without this route the
//! finished import's invite code would be unreachable, which is the entire
//! payload of the feature ("paste this link in your Discord").

use revolt_database::{Database, User};
use revolt_result::Result;
use rocket::serde::json::Json;
use rocket::State;

use super::dto::ImportJobResponse;

/// # Fetch Active Import
///
/// Returns your currently queued or running import job, or `null` if you have
/// none.
#[openapi(tag = "Import")]
#[get("/discord/active")]
pub async fn fetch_active_import_job(
    db: &State<Database>,
    user: User,
) -> Result<Json<Option<ImportJobResponse>>> {
    Ok(Json(
        db.fetch_active_discord_import_job_for_user(&user.id)
            .await?
            .map(Into::into),
    ))
}
