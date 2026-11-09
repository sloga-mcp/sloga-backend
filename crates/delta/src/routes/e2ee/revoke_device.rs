use iso8601_timestamp::Timestamp;
use revolt_database::{
    e2ee_claim_lock::{self, RevokeFacts, RevokeLock},
    Database, E2EEIdentity, E2EERemovedDevice, PartialUser, Session, User, ValidatedTicket,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};

/// # Revoke E2EE Device
///
/// Revoke one of the current user's E2EE devices: removes its identity,
/// remaining one-time keys and queued envelopes, and notifies the account's
/// other devices and DM peers so they tear down sessions. The device id is
/// tombstoned: it can never be published again.
///
/// Only the session live on the device, a session live on another of the
/// account's devices, or (with the device offline) the session it is bound
/// to may remove it; anyone else gets `E2EEDeviceHeldElsewhere` and nothing
/// is removed.
///
/// Returns how many of the user's devices remain after the removal.
///
/// MFA-gated. Revocation is server-side only — it does NOT remotely wipe the
/// device; a revoked device that reconnects must perform a local wipe.
#[openapi(tag = "E2EE")]
#[delete("/keys/<device_id>")]
pub async fn revoke_device(
    db: &State<Database>,
    mut user: User,
    session: Session,
    _ticket: ValidatedTicket,
    device_id: String,
) -> Result<Json<v0::ResponseRevokeE2EEDevice>> {
    super::require_e2ee_enabled().await?;

    // Scoped to the session's user: only your own devices can be revoked.
    // An id that is none of them gets no tombstone
    let target = db.fetch_e2ee_identity(&user.id, &device_id).await?;

    // Who may remove it (multi-device addendum A1), decided before anything
    // is written
    if !may_revoke(db, &user.id, &session.id, &target).await? {
        log::info!(
            "E2EE device removal refused (held_elsewhere): user={} device={} session={}",
            user.id,
            device_id,
            session.id
        );
        reassert_e2ee_enabled(db, &mut user).await;
        return Err(create_error!(E2EEDeviceHeldElsewhere));
    }

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

/// Gather what [`e2ee_claim_lock::decide_revoke`] needs, reading only:
/// the target's lock (none at all with `[features.e2ee] claim_lock` off),
/// the other own devices' locks (only when the target's was readable), the
/// account's device rows and the target's bound session
async fn may_revoke(
    db: &Database,
    user_id: &str,
    session_id: &str,
    target: &E2EEIdentity,
) -> Result<bool> {
    let claim_lock = revolt_config::config().await.features.e2ee.claim_lock;
    let lock = e2ee_claim_lock::read_for_revoke(
        claim_lock,
        &e2ee_claim_lock::lock_key(user_id, &target.device_id),
    )
    .await;

    let devices = db.fetch_e2ee_identities(user_id).await?;
    let others: Vec<&E2EEIdentity> = devices
        .iter()
        .filter(|device| device.device_id != target.device_id)
        .collect();
    let other_ids: Vec<&str> = others
        .iter()
        .map(|device| device.device_id.as_str())
        .collect();

    let caller_holds_another_lock = lock.is_readable()
        && e2ee_claim_lock::session_holds_any(user_id, other_ids, session_id).await;

    // A session that cannot be looked up for another reason counts as alive
    let bound = target.last_session_id.as_str();
    let bound_session_exists = !bound.is_empty()
        && (bound == session_id
            || !matches!(
                db.fetch_session(bound).await,
                Err(err) if matches!(err.error_type, ErrorType::UnknownUser)
            ));

    if matches!(lock, RevokeLock::Unreadable) {
        log::warn!(
            "E2EE claim lock unreadable, device removal decided from the database: user={} device={} session={}",
            user_id,
            target.device_id,
            session_id
        );
    }

    Ok(e2ee_claim_lock::decide_revoke(&RevokeFacts {
        caller_session: session_id,
        lock,
        bound_session: bound,
        bound_session_exists,
        caller_holds_another_lock,
        another_row_bound_to_caller: others
            .iter()
            .any(|device| device.last_session_id == session_id),
    }))
}

/// A refused removal re-asserts the account's `e2ee_enabled` while it still
/// has a device: an older client clears the flag just before its removal
/// call. Best effort; a failure is logged and the refusal stands
async fn reassert_e2ee_enabled(db: &Database, user: &mut User) {
    if user.e2ee_enabled {
        return;
    }

    match db.fetch_e2ee_identities(&user.id).await {
        Ok(devices) if !devices.is_empty() => {
            let partial = PartialUser {
                e2ee_enabled: Some(true),
                ..Default::default()
            };
            if let Err(err) = user.update(db, partial, vec![]).await {
                log::warn!(
                    "Could not re-assert e2ee_enabled after a refused device removal: user={}: {:?}",
                    user.id,
                    err
                );
            }
        }
        Ok(_) => {}
        Err(err) => log::warn!(
            "Could not count devices after a refused device removal: user={}: {:?}",
            user.id,
            err
        ),
    }
}
