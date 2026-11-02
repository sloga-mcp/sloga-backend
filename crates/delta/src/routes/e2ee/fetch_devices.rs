use std::collections::HashMap;

use revolt_database::{util::reference::Reference, Database, E2EEIdentity, Session, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # List E2EE Devices
///
/// List a user's registered E2EE devices without consuming any key material.
/// Used for device-list reconciliation on connect and for the own-device
/// management UI.
///
/// For your own devices the listing includes registration/last-seen times and
/// the remaining one-time key count (drives replenishment), the current and
/// previous fallback keys and the bound session's name; for peers only
/// the device id, protocol version and identity key are returned.
///
/// Peer listings require a device-bound session (design §8) — only an
/// E2EE-capable device has any use for them. Listing your OWN devices is
/// allowed from any session: the web device-management UI needs it (e.g. to
/// revoke a lost desktop, which stays MFA-gated).
#[openapi(tag = "E2EE")]
#[get("/devices/<target>")]
pub async fn fetch_devices(
    db: &State<Database>,
    user: User,
    session: Session,
    target: Reference<'_>,
) -> Result<Json<Vec<v0::E2EEDeviceInfo>>> {
    super::require_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let target = target.as_user(db).await?;
    let own = target.id == user.id;

    if !own {
        E2EEIdentity::require_device_bound_session(db, &user.id, &session.id).await?;

        // Friend-eligible OR shared-group co-member; blocked pairs refused
        // on the FETCH path even inside a shared group (design §2.6)
        super::require_e2ee_fetch_eligible(db, &user, &target).await?;
    }

    // Own listing only: the name of each device's bound session, from one
    // lookup of the user's sessions (a row bound to "" or to a session that
    // is gone has none)
    let session_names: HashMap<String, String> = if own {
        db.fetch_sessions(&user.id)
            .await?
            .into_iter()
            .filter(|session| session.user_id == user.id && !session.name.is_empty())
            .map(|session| (session.id, session.name))
            .collect()
    } else {
        HashMap::new()
    };

    let mut devices = vec![];
    for identity in db.fetch_e2ee_identities(&target.id).await? {
        let one_time_key_count = if own {
            Some(
                db.count_e2ee_one_time_keys(&target.id, &identity.device_id)
                    .await?,
            )
        } else {
            None
        };

        let created_at = own.then(|| identity.created_at.to_string());
        let last_seen_at = own.then(|| identity.last_seen_at.to_string());

        // Own listing only (multi-device D6): the public fallback keys let
        // an install tell its own keys from a twin's
        let (fallback_key, previous_fallback_key, session_name) = if own {
            (
                Some(identity.fallback_key.into()),
                identity.previous_fallback_key.map(Into::into),
                session_names.get(&identity.last_session_id).cloned(),
            )
        } else {
            (None, None, None)
        };

        devices.push(v0::E2EEDeviceInfo {
            created_at,
            last_seen_at,
            device_id: identity.device_id,
            protocol_version: identity.protocol_version,
            ed25519_key: identity.ed25519_key,
            curve25519_key: identity.curve25519_key,
            signature: identity.signature,
            one_time_key_count,
            fallback_key,
            previous_fallback_key,
            session_name,
        });
    }

    Ok(Json(devices))
}
