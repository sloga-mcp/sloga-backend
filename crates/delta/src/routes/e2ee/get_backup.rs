use revolt_database::{Database, User, ValidatedTicket};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Fetch E2EE Key Backups (restore)
///
/// The restore path (design §5, §6.1). Returns every backup blob the
/// authenticated user holds — one per device — so the native layer can try
/// the entered recovery code against each.
///
/// A restoring device has NO key material yet, so a device-bound session is
/// impossible by construction; this route is gated by a fresh, validated MFA
/// ticket instead (the first-key-publication pattern). The ticket is bound to
/// the authenticated user (a session holder who has not completed the
/// account's own MFA cannot pass someone else's ticket), single-use, and
/// consumed by the guard. Own-account only; an empty list is an honest 200.
///
/// The blobs are opaque ciphertext under the recovery code the server never
/// sees — this route egresses no readable key material.
#[openapi(tag = "E2EE")]
#[get("/backup")]
pub async fn get_backup(
    db: &State<Database>,
    user: User,
    ticket: ValidatedTicket,
) -> Result<Json<v0::ResponseFetchE2EEBackups>> {
    super::require_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // M8: the ValidatedTicket proves SOME account did MFA; bind it to this
    // user so a stolen session cannot restore with the attacker's own ticket
    if ticket.account_id != user.id {
        return Err(create_error!(InvalidToken));
    }

    let backups = db
        .fetch_e2ee_backups(&user.id)
        .await?
        .into_iter()
        .map(|backup| v0::E2EEBackup {
            device_id: backup.device_id,
            header: backup.header,
            ciphertext: backup.ciphertext,
            generation: backup.generation,
            updated_at: backup.updated_at.to_string(),
        })
        .collect();

    Ok(Json(v0::ResponseFetchE2EEBackups { backups }))
}
