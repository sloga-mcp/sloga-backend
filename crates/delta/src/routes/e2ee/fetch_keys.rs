use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, E2EEIdentity, Session, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_user_permissions, UserPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Fetch E2EE Key Bundle
///
/// Fetch a key bundle for every registered device of a user, consuming one
/// one-time key per device. At one-time-key exhaustion the fallback key is
/// still served — a registered device ALWAYS yields a usable bundle; "no
/// bundle" is never the answer for an opted-in peer.
///
/// Gated by the same eligibility check as opening a DM: blocked users can
/// neither fetch bundles nor count devices. Fetching your own bundle (for
/// own-device fan-out) is always permitted.
///
/// Clients MUST verify the identity self-signature and every key signature
/// before establishing a session, and MUST pin identity keys: a later bundle
/// absence or key change is an alert, never a silent downgrade.
///
/// Requires a device-bound session (design §8): only a session that has
/// proven possession of one of the caller's device identity keys may consume
/// key material. Web session tokens are refused.
#[openapi(tag = "E2EE")]
#[get("/keys/<target>")]
pub async fn fetch_keys(
    db: &State<Database>,
    user: User,
    session: Session,
    target: Reference<'_>,
) -> Result<Json<v0::E2EEKeyBundle>> {
    super::require_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    E2EEIdentity::require_device_bound_session(db, &user.id, &session.id).await?;

    let target = target.as_user(db).await?;

    if target.id != user.id {
        let mut query = DatabasePermissionQuery::new(db, &user).user(&target);
        calculate_user_permissions(&mut query)
            .await
            .throw_if_lacking_user_permission(UserPermission::SendMessage)?;
    }

    let mut devices = vec![];
    for identity in db.fetch_e2ee_identities(&target.id).await? {
        let one_time_key = db
            .consume_e2ee_one_time_key(&target.id, &identity.device_id)
            .await?;

        let one_time_keys_remaining = db
            .count_e2ee_one_time_keys(&target.id, &identity.device_id)
            .await?;

        devices.push(v0::E2EEDeviceKeys {
            device_id: identity.device_id,
            protocol_version: identity.protocol_version,
            ed25519_key: identity.ed25519_key,
            curve25519_key: identity.curve25519_key,
            signature: identity.signature,
            one_time_key: one_time_key.map(|key| v0::E2EESignedKey {
                key_id: key.key_id,
                key: key.key,
                signature: key.signature,
            }),
            fallback_key: identity.fallback_key.into(),
            one_time_keys_remaining,
        });
    }

    Ok(Json(v0::E2EEKeyBundle {
        user_id: target.id,
        devices,
    }))
}
