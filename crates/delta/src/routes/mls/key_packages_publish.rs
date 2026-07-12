use iso8601_timestamp::{Duration, Timestamp};
use revolt_database::{
    is_valid_device_id, is_valid_key_package_ref, mls_credential_binding_payload, Database,
    MlsKeyPackage, Session, User,
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
/// Every publication (first and replenish) requires the session bound to the
/// device plus a valid credential binding — the device identity behind that
/// binding was itself MFA-gated at enrollment, so no publish-time MFA ticket
/// is demanded (publish-UX plan §3.1; a stray `X-MFA-Ticket` header from an
/// older client is simply ignored). The MLS signature key is immutable while
/// any package for the device is stored.
#[openapi(tag = "MLS")]
#[put("/key_packages", data = "<data>")]
pub async fn publish_key_packages(
    db: &State<Database>,
    user: User,
    session: Session,
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
    if let Some(existing) = db
        .fetch_one_mls_key_package(&user.id, &device_id)
        .await?
    {
        if existing.mls_signature_key != mls_signature_key {
            return Err(create_error!(FailedValidation {
                error:
                    "MLS signature key is immutable while packages are stored; republish after they expire or revoke the device"
                        .to_string()
            }));
        }
    }

    let now = Timestamp::now_utc();

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

    // Capped upsert: a batch that would overflow the directory prunes the
    // device's oldest packages instead of 400-ing, so a fresh-start client
    // (watermark 0 → full regen) can never wedge itself (publish-UX plan
    // §3.4). The returned count is the client's replenish watermark.
    let key_package_count = db
        .insert_mls_key_packages_capped(&user.id, &device_id, &packages, MAX_KEY_PACKAGES)
        .await?;

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

    Ok(Json(v0::ResponsePublishMlsKeyPackages { key_package_count }))
}
