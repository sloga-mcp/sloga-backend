use iso8601_timestamp::Timestamp;
use revolt_database::{
    events::client::EventV1, is_valid_device_id, Database, E2EEIdentity, E2EEOneTimeKey,
    Session, User, ValidatedTicket, E2EE_PROTOCOL_VERSION,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use super::{MAX_KEY_ID_LENGTH, MAX_KEY_LENGTH, MAX_ONE_TIME_KEYS, MAX_SIGNATURE_LENGTH};

fn check_signed_key(key: &v0::E2EESignedKey) -> Result<()> {
    if key.key_id.is_empty()
        || key.key_id.len() > MAX_KEY_ID_LENGTH
        || key.key.len() > MAX_KEY_LENGTH
        || key.signature.len() > MAX_SIGNATURE_LENGTH
    {
        return Err(create_error!(FailedValidation {
            error: "invalid key encoding".to_string()
        }));
    }

    Ok(())
}

/// # Publish E2EE Keys
///
/// Publish (or replenish) the key bundle for one of the current user's
/// devices.
///
/// The first publication from a new device binds `(user, device_id)` and
/// requires a validated MFA ticket. Identity keys are immutable once bound —
/// republishing may only rotate the fallback key and add one-time keys; a
/// fresh identity requires revoking the device and enrolling a new one.
///
/// All signatures are verified server-side as a hygiene check; clients MUST
/// still verify them on fetch — the server is outside the trust boundary.
#[openapi(tag = "E2EE")]
#[put("/keys", data = "<data>")]
pub async fn publish_keys(
    db: &State<Database>,
    user: User,
    session: Session,
    ticket: Option<ValidatedTicket>,
    data: Json<v0::DataPublishE2EEKeys>,
) -> Result<Json<v0::ResponsePublishE2EEKeys>> {
    super::require_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();

    // Structural validation before any crypto
    if !is_valid_device_id(&data.device_id) {
        return Err(create_error!(FailedValidation {
            error: "device_id must be 128 bits of lowercase hex".to_string()
        }));
    }

    if data.protocol_version != E2EE_PROTOCOL_VERSION {
        return Err(create_error!(FailedValidation {
            error: format!("unsupported protocol version (expected {E2EE_PROTOCOL_VERSION})")
        }));
    }

    if data.ed25519_key.len() > MAX_KEY_LENGTH
        || data.curve25519_key.len() > MAX_KEY_LENGTH
        || data.signature.len() > MAX_SIGNATURE_LENGTH
        || data.one_time_keys.len() > MAX_ONE_TIME_KEYS
    {
        return Err(create_error!(FailedValidation {
            error: "invalid bundle encoding".to_string()
        }));
    }

    check_signed_key(&data.fallback_key)?;
    let mut seen_key_ids = std::collections::HashSet::new();
    for key in &data.one_time_keys {
        check_signed_key(key)?;
        if !seen_key_ids.insert(key.key_id.as_str()) {
            return Err(create_error!(FailedValidation {
                error: "duplicate one-time key ids".to_string()
            }));
        }
    }

    let existing = db.fetch_e2ee_identity(&user.id, &data.device_id).await.ok();

    let mut identity = E2EEIdentity {
        id: E2EEIdentity::composite_id(&user.id, &data.device_id),
        // Scope is always the authenticated session's user — a session can
        // never touch another user's (or another device's) rows
        user_id: user.id.clone(),
        device_id: data.device_id.clone(),
        protocol_version: data.protocol_version,
        ed25519_key: data.ed25519_key,
        curve25519_key: data.curve25519_key,
        signature: data.signature,
        fallback_key: data.fallback_key.into(),
        previous_fallback_key: None,
        created_at: Timestamp::now_utc(),
        last_seen_at: Timestamp::now_utc(),
        last_session_id: session.id.clone(),
    };

    // Verify the identity self-signature and fallback-key signature;
    // fails closed on any structural or signature error
    identity.verify()?;

    let one_time_keys: Vec<E2EEOneTimeKey> = data
        .one_time_keys
        .into_iter()
        .map(|key| E2EEOneTimeKey {
            id: E2EEOneTimeKey::composite_id(&user.id, &identity.device_id, &key.key_id),
            user_id: user.id.clone(),
            device_id: identity.device_id.clone(),
            key_id: key.key_id,
            key: key.key,
            signature: key.signature,
        })
        .collect();

    for key in &one_time_keys {
        key.verify(&identity)?;
    }

    if let Some(existing) = existing {
        // Identity keys are immutable per device: a differing key is a
        // substitution attempt (or a reinstall that must enroll fresh)
        if existing.ed25519_key != identity.ed25519_key
            || existing.curve25519_key != identity.curve25519_key
        {
            return Err(create_error!(FailedValidation {
                error: "identity keys are immutable; revoke this device and enroll a new one"
                    .to_string()
            }));
        }

        // Retain the previous fallback key across rotation so in-flight
        // prekey messages remain decryptable
        identity.created_at = existing.created_at;
        if existing.fallback_key.key_id != identity.fallback_key.key_id {
            identity.previous_fallback_key = Some(existing.fallback_key);
        } else {
            identity.previous_fallback_key = existing.previous_fallback_key;
        }

        db.replace_e2ee_identity(&identity).await?;
    } else {
        // First publication from a new device requires MFA
        if ticket.is_none() {
            return Err(create_error!(InvalidToken));
        }

        // Uniqueness of (user_id, device_id) is index-enforced; a concurrent
        // duplicate publish loses the race here
        db.insert_e2ee_identity(&identity).await?;

        // Device-list changes are loud: notify the account's other devices
        // and DM peers
        E2EEIdentity::broadcast_device_change(
            db,
            &user.id,
            EventV1::E2EEDeviceCreate {
                user_id: user.id.clone(),
                device_id: identity.device_id.clone(),
            },
        )
        .await;
    }

    let current = db
        .count_e2ee_one_time_keys(&user.id, &identity.device_id)
        .await?;

    // Inserts upsert by key id, so a replenish reusing key ids replaces in
    // place — only genuinely new ids count toward the cap
    let key_ids: Vec<String> = one_time_keys
        .iter()
        .map(|key| key.key_id.clone())
        .collect();
    let already_stored = db
        .count_e2ee_one_time_keys_among(&user.id, &identity.device_id, &key_ids)
        .await?;

    if current + one_time_keys.len() as u64 - already_stored > MAX_ONE_TIME_KEYS as u64 {
        return Err(create_error!(FailedValidation {
            error: format!("at most {MAX_ONE_TIME_KEYS} one-time keys may be stored")
        }));
    }

    db.insert_e2ee_one_time_keys(&one_time_keys).await?;

    let one_time_key_count = db
        .count_e2ee_one_time_keys(&user.id, &identity.device_id)
        .await?;

    Ok(Json(v0::ResponsePublishE2EEKeys { one_time_key_count }))
}
