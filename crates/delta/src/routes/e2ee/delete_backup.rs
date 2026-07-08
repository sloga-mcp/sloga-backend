use revolt_database::{Database, User, ValidatedTicket};
use revolt_result::{create_error, Result};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Delete E2EE Key Backup
///
/// Delete one device's key-backup blob (design §5). MFA-gated (the explicit
/// "delete my backup" settings action), bound to the authenticated user
/// (M8). Own-user scope only.
///
/// This is the ONLY explicit deletion path. Device revocation deliberately
/// does NOT delete the backup (a lost device must keep its recovery path);
/// the only other removal is the account-deletion cascade.
#[openapi(tag = "E2EE")]
#[delete("/backup/<device_id>")]
pub async fn delete_backup(
    db: &State<Database>,
    user: User,
    ticket: ValidatedTicket,
    device_id: String,
) -> Result<EmptyResponse> {
    super::require_e2ee_enabled().await?;

    // M8: bind the MFA ticket to this user
    if ticket.account_id != user.id {
        return Err(create_error!(InvalidToken));
    }

    // Scoped to the session's user: only your own backup can be deleted.
    // Idempotent — a missing backup is a successful no-op (the desired
    // end-state is "no backup for this device").
    db.delete_e2ee_backup(&user.id, &device_id).await?;

    Ok(EmptyResponse)
}
