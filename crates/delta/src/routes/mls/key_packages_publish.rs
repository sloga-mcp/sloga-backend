use iso8601_timestamp::{Duration, Timestamp};
use revolt_database::{
    is_valid_device_id, is_valid_key_package_ref, mls_credential_binding_payload, Database,
    MlsKeyPackage, Session, User, ValidatedTicket,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use crate::routes::e2ee::{MAX_KEY_LENGTH, MAX_SIGNATURE_LENGTH};

use super::{
    encoded_len, KEY_PACKAGE_LIFETIME_DAYS, LAST_RESORT_LIFETIME_DAYS, MAX_KEY_PACKAGES,
    MAX_KEY_PACKAGE_RAW_SIZE,
};

fn check_upload(upload: &v0::MlsKeyPackageUpload) -> Result<()> {
    if !is_valid_key_package_ref(&upload.key_package_ref) {
        return Err(create_error!(FailedValidation {
            error: "invalid key package reference".to_string()
        }));
    }

    if upload.key_package.is_empty()
        || upload.key_package.len() > encoded_len(MAX_KEY_PACKAGE_RAW_SIZE)
    {
        return Err(create_error!(FailedValidation {
            error: "invalid key package encoding".to_string()
        }));
    }

    Ok(())
}

/// # Publish MLS KeyPackages
///
/// Publish (or replenish) MLS KeyPackages for one of the current user's
/// E2EE devices (media E2EE).
///
/// The credential binding signature — Ed25519 by the device identity key
/// over the canonical `acutest:e2ee:mls-credential:v1` payload — is verified
/// server-side, exactly like one-time-key publish. Clients MUST still verify
/// the credential inside each KeyPackage at Welcome time; the server is
/// outside the trust boundary.
///
/// The first publication for a device requires a validated MFA ticket;
/// replenishment requires the session bound to the device. The MLS signature
/// key is immutable while any package for the device is stored.
#[openapi(tag = "MLS")]
#[put("/key_packages", data = "<data>")]
pub async fn publish_key_packages(
    db: &State<Database>,
    user: User,
    session: Session,
    ticket: Option<ValidatedTicket>,
    data: Json<v0::DataPublishMlsKeyPackages>,
) -> Result<Json<v0::ResponsePublishMlsKeyPackages>> {
    super::require_media_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let v0::DataPublishMlsKeyPackages {
        device_id,
        mls_signature_key,
        binding_signature,
        key_packages,
        last_resort,
    } = data.into_inner();

    // Structural validation before any crypto
    if !is_valid_device_id(&device_id) {
        return Err(create_error!(FailedValidation {
            error: "device_id must be 128 bits of lowercase hex".to_string()
        }));
    }

    if mls_signature_key.len() > MAX_KEY_LENGTH
        || binding_signature.len() > MAX_SIGNATURE_LENGTH
        || key_packages.len() > MAX_KEY_PACKAGES
    {
        return Err(create_error!(FailedValidation {
            error: "invalid bundle encoding".to_string()
        }));
    }

    // The MLS signature key is interpolated into the canonical credential
    // binding payload, so it must be structurally valid (exactly 32 bytes of
    // unpadded base64) — the same constraint every other interpolated input
    // carries; a free-form string could inject payload line boundaries
    // (crypto gate finding, slice 6.1)
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    if !STANDARD_NO_PAD
        .decode(&mls_signature_key)
        .map(|bytes| bytes.len() == 32)
        .unwrap_or(false)
    {
        return Err(create_error!(FailedValidation {
            error: "invalid MLS signature key encoding".to_string()
        }));
    }

    if key_packages.is_empty() && last_resort.is_none() {
        return Err(create_error!(FailedValidation {
            error: "nothing to publish".to_string()
        }));
    }

    let mut seen_refs = std::collections::HashSet::new();
    for upload in key_packages.iter().chain(last_resort.iter()) {
        check_upload(upload)?;
        if !seen_refs.insert(upload.key_package_ref.as_str()) {
            return Err(create_error!(FailedValidation {
                error: "duplicate key package references".to_string()
            }));
        }
    }

    // The publishing device must be a registered E2EE device of the caller,
    // and the calling session must be bound to it (web/stolen session
    // tokens cannot act as an E2EE device — design §8)
    let identity = db
        .fetch_e2ee_identity(&user.id, &device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "publishing device is not registered".to_string()
            })
        })?;
    identity.assert_bound_session(&session.id)?;

    // Verify the credential binding: the payload the native layer signed
    // with the vodozemac identity key (plan §1.3; byte-for-byte mirror of
    // e2ee-core's canonical builder)
    let payload = mls_credential_binding_payload(
        &user.id,
        &device_id,
        &mls_signature_key,
        &identity.ed25519_key,
    );
    if !identity.verify_payload(&payload, &binding_signature) {
        return Err(create_error!(FailedValidation {
            error: "invalid credential binding signature".to_string()
        }));
    }

    // MLS signature-key immutability (v1: rotation is deferred, plan §1.3):
    // while any package is stored, the key must not change — a differing key
    // is a substitution attempt or a state loss that must re-enroll
    let existing = db
        .fetch_one_mls_key_package(&user.id, &device_id)
        .await?;

    if let Some(existing) = existing {
        if existing.mls_signature_key != mls_signature_key {
            return Err(create_error!(FailedValidation {
                error:
                    "MLS signature key is immutable while packages are stored; republish after they expire or revoke the device"
                        .to_string()
            }));
        }
    } else {
        // First MLS publication for this device requires MFA, mirroring the
        // first E2EE key publish. (A device offline long enough for ALL its
        // packages to expire re-enrolls through MFA too — deliberate.)
        if ticket.is_none() {
            return Err(create_error!(InvalidToken));
        }
    }

    let now = Timestamp::now_utc();

    // Cap accounting is upsert-aware: republishing an already-stored ref
    // replaces in place and must not double-count
    let current = db
        .count_mls_key_packages(&user.id, &device_id)
        .await?;
    let refs: Vec<String> = key_packages
        .iter()
        .map(|upload| upload.key_package_ref.clone())
        .collect();
    let already_stored = db
        .count_mls_key_packages_among(&user.id, &device_id, &refs)
        .await?;

    if current + key_packages.len() as u64 - already_stored > MAX_KEY_PACKAGES as u64 {
        return Err(create_error!(FailedValidation {
            error: format!("at most {MAX_KEY_PACKAGES} key packages may be stored")
        }));
    }

    let build = |upload: v0::MlsKeyPackageUpload, last_resort: bool, lifetime_days: i64| {
        MlsKeyPackage {
            id: MlsKeyPackage::composite_id(&user.id, &device_id, &upload.key_package_ref),
            user_id: user.id.clone(),
            device_id: device_id.clone(),
            key_package_ref: upload.key_package_ref,
            key_package: upload.key_package,
            mls_signature_key: mls_signature_key.clone(),
            binding_signature: binding_signature.clone(),
            last_resort,
            expires_at: now
                .checked_add(Duration::days(lifetime_days))
                .expect("lifetime addition cannot overflow"),
            created_at: now,
        }
    };

    let packages: Vec<MlsKeyPackage> = key_packages
        .into_iter()
        .map(|upload| build(upload, false, KEY_PACKAGE_LIFETIME_DAYS))
        .collect();

    db.insert_mls_key_packages(&packages).await?;

    if let Some(last_resort) = last_resort {
        // Replaces any previous last-resort package; the native layer
        // zeroizes the replaced init key (plan §2.2.1)
        db.replace_mls_last_resort_key_package(&build(
            last_resort,
            true,
            LAST_RESORT_LIFETIME_DAYS,
        ))
        .await?;
    }

    let key_package_count = db
        .count_mls_key_packages(&user.id, &device_id)
        .await?;

    Ok(Json(v0::ResponsePublishMlsKeyPackages { key_package_count }))
}
