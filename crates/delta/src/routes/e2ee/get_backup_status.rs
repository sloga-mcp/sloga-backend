use revolt_database::{Database, E2EEIdentity, Session, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Fetch E2EE Key Backup Status
///
/// Metadata only (no header, no ciphertext) for the settings card and the
/// no-backup nag (design §5, §7.1): per device, the stored generation, last
/// refresh time, and approximate size. Zero key egress.
///
/// Requires a device-bound session (any of the user's devices). Note (design
/// §4.5 H3): this response is webview-couriered and unauthenticated, so it
/// drives the nag against an HONEST server but is NOT a defense against a
/// compromised webview — that residual is carried risk #1.
#[openapi(tag = "E2EE")]
#[get("/backup/status")]
pub async fn get_backup_status(
    db: &State<Database>,
    user: User,
    session: Session,
) -> Result<Json<v0::ResponseE2EEBackupStatus>> {
    super::require_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    E2EEIdentity::require_device_bound_session(db, &user.id, &session.id).await?;

    let backups = db
        .fetch_e2ee_backups(&user.id)
        .await?
        .into_iter()
        .map(|backup| v0::E2EEBackupStatus {
            device_id: backup.device_id,
            generation: backup.generation,
            updated_at: backup.updated_at.to_string(),
            // Approximate decoded size from the base64 ciphertext length
            size: (backup.ciphertext.len() / 4 * 3) as u64,
        })
        .collect();

    Ok(Json(v0::ResponseE2EEBackupStatus { backups }))
}
