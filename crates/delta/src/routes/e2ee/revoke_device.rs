use revolt_database::{Database, E2EEIdentity, User, ValidatedTicket};
use revolt_result::{create_error, Result};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Revoke E2EE Device
///
/// Revoke one of the current user's E2EE devices: removes its identity,
/// remaining one-time keys and queued envelopes, and notifies the account's
/// other devices and DM peers so they tear down sessions.
///
/// MFA-gated. Revocation is server-side only — it does NOT remotely wipe the
/// device; a revoked device that reconnects must perform a local wipe.
#[openapi(tag = "E2EE")]
#[delete("/keys/<device_id>")]
pub async fn revoke_device(
    db: &State<Database>,
    user: User,
    _ticket: ValidatedTicket,
    device_id: String,
) -> Result<EmptyResponse> {
    super::require_e2ee_enabled().await?;

    // Scoped to the session's user: only your own devices can be revoked
    if E2EEIdentity::revoke_device(db, &user.id, &device_id).await? {
        Ok(EmptyResponse)
    } else {
        Err(create_error!(NotFound))
    }
}
