use iso8601_timestamp::Timestamp;
use revolt_database::{Database, E2EEIdentity, E2EERemovedDevice, User, ValidatedTicket};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Revoke E2EE Device
///
/// Revoke one of the current user's E2EE devices: removes its identity,
/// remaining one-time keys and queued envelopes, and notifies the account's
/// other devices and DM peers so they tear down sessions. The device id is
/// tombstoned: it can never be published again.
///
/// Returns how many of the user's devices remain after the removal.
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
) -> Result<Json<v0::ResponseRevokeE2EEDevice>> {
    super::require_e2ee_enabled().await?;

    // Scoped to the session's user: only your own devices can be revoked.
    // An id that is none of them gets no tombstone
    db.fetch_e2ee_identity(&user.id, &device_id).await?;

    // Explicit removal only (multi-device D8): session revocation goes
    // through `E2EEIdentity::revoke_device` without this, so a device that
    // logged out can still re-enroll. Written BEFORE the delete: a failed
    // write removes nothing, where the other order would leave a deleted
    // device that its install can publish again
    db.upsert_e2ee_removed_device(&E2EERemovedDevice::new(
        &user.id,
        &device_id,
        Timestamp::now_utc(),
    ))
    .await?;

    if !E2EEIdentity::revoke_device(db, &user.id, &device_id).await? {
        return Err(create_error!(NotFound));
    }

    // Counted after the delete: the client clears the account-wide
    // `e2ee_enabled` flag only when no device is left (plan D7)
    let remaining_devices = db.fetch_e2ee_identities(&user.id).await?.len() as u32;

    Ok(Json(v0::ResponseRevokeE2EEDevice { remaining_devices }))
}
