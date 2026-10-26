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

/// The KeyPackage directory is shared by Call and Text groups (W2 decision
/// 3, protected-channels design §7.1), so publishing needs `e2ee_enabled &&
/// (media_e2ee_enabled || protected_channels.enabled)`. With E2EE off the
/// answer is `FeatureDisabled { e2ee }`; with E2EE on and both planes off it
/// is the media gate's own `FeatureDisabled { media_e2ee }`, the answer Call
/// clients got before Text groups existed.
async fn require_publish_enabled() -> Result<()> {
    super::require_protected_available().await?;
    let features = revolt_config::config().await.features;
    if features.protected_channels.enabled {
        return Ok(());
    }

    super::require_media_e2ee_enabled().await
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
    require_publish_enabled().await?;

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

/// The publish gate's flag matrix (W2 decision 3). Every flag case is its
/// own `#[test]`: `overwrite_config` runs once per process, BEFORE the
/// harness primes the config cache, so these need nextest (one process per
/// test). The test config has every flag on.
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use revolt_database::mls_credential_binding_payload;
    use revolt_models::v0;
    use revolt_result::Error;
    use rocket::http::{ContentType, Header, Status};

    use crate::routes::mls::{require_media_e2ee_enabled, require_protected_available};
    use crate::util::test::TestHarness;

    enum Expected {
        Published,
        /// The gate's own error: the route's body must be its serialized
        /// form (type and feature; the body carries no `location`)
        Refused(Error, &'static str),
    }

    fn upload(key_package_ref: &str) -> v0::MlsKeyPackageUpload {
        v0::MlsKeyPackageUpload {
            key_package_ref: key_package_ref.to_string(),
            key_package: STANDARD_NO_PAD.encode(b"opaque key package bytes"),
        }
    }

    /// A valid publish from a bound device, so the only thing that can
    /// refuse it is the gate; a refusal must store nothing
    async fn publish(expected: Expected) {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let device = harness.new_e2ee_device(&user, &session.id, 41).await;
        let mls_signature_key = STANDARD_NO_PAD.encode([7u8; 32]);
        let payload = mls_credential_binding_payload(
            &user.id,
            &device.device_id,
            &mls_signature_key,
            &device.identity_key(),
        );
        let body = v0::DataPublishMlsKeyPackages {
            device_id: device.device_id.clone(),
            mls_signature_key,
            binding_signature: device.sign(&payload),
            key_packages: vec![upload("kp0")],
            last_resort: Some(upload("kplast")),
        };

        let response = harness
            .client
            .put("/mls/key_packages")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .body(serde_json::to_string(&body).expect("JSON"))
            .dispatch()
            .await;
        let status = response.status();
        let text = response.into_string().await.expect("a body");
        let answer: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        let stored = harness
            .db
            .fetch_one_mls_key_package(&user.id, &device.device_id)
            .await
            .expect("the directory read");

        match expected {
            Expected::Published => {
                assert_eq!(status, Status::Ok, "{}", text);
                assert_eq!(answer["key_package_count"], 1, "{}", text);
                assert!(stored.is_some(), "the packages must be stored");
            }
            Expected::Refused(error, feature) => {
                assert_eq!(status, Status::BadRequest, "{}", text);
                assert_eq!(answer["type"], "FeatureDisabled", "{}", text);
                assert_eq!(answer["feature"], feature, "{}", text);
                assert_eq!(
                    answer,
                    serde_json::to_value(error).expect("JSON"),
                    "the body must be the gate's own answer"
                );
                assert!(stored.is_none(), "a refusal must store nothing");
            }
        }
    }

    #[test]
    fn publish_with_every_flag_on() {
        crate::util::test::rt().block_on(publish(Expected::Published))
    }

    #[test]
    fn publish_with_media_on_and_protected_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            publish(Expected::Published).await
        })
    }

    /// Decision 3: while protected channels are on, the media flag no
    /// longer stops publish (Text groups claim from the same directory)
    #[test]
    fn publish_with_media_off_and_protected_on() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            publish(Expected::Published).await
        })
    }

    /// Both planes off: the media gate's answer, byte-identical to the one
    /// Call clients got before Text groups existed
    #[test]
    fn publish_with_media_and_protected_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
                settings.features.protected_channels.enabled = false;
            })
            .await;
            let error = require_media_e2ee_enabled()
                .await
                .expect_err("the media gate is closed");
            publish(Expected::Refused(error, "media_e2ee")).await
        })
    }

    /// E2EE off refuses whatever the media and protected flags say (both
    /// stay on here), with the availability gate's `e2ee` answer
    #[test]
    fn publish_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            let error = require_protected_available()
                .await
                .expect_err("the availability gate is closed");
            publish(Expected::Refused(error, "e2ee")).await
        })
    }
}
