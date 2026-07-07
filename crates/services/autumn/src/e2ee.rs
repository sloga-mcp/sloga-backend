//! Opaque-blob transit storage for E2EE attachments (implementation plan,
//! slice 3.5).
//!
//! Blobs are client-side AES-256-GCM ciphertext; the per-file key travels
//! INSIDE the message envelope ciphertext and never reaches the server. The
//! server therefore does NO probing, processing, thumbnailing, metadata
//! stripping or virus scanning here — the bytes are opaque by construction
//! and served back exactly as uploaded (clients verify a digest of the
//! ciphertext before use, so a swapped or truncated blob fails closed).
//!
//! Lifecycle mirrors the envelope queue — transit storage, not history:
//! deleted once every declared recipient device has fetched it, with a
//! size-tiered TTL backstop swept by crond (`prune_e2ee_blobs`).

use axum::{
    extract::{Path, State},
    http::header,
    response::{IntoResponse, Response},
    Json,
};
use axum_typed_multipart::{FieldData, TryFromMultipart, TypedMultipart};
use revolt_config::config;
use revolt_database::{
    Database, E2EEBlob, E2EEBlobRecipient, Session, User, E2EE_MAX_BLOB_RECIPIENTS,
};
use revolt_files::{delete_from_s3, fetch_from_s3, upload_to_s3};
use revolt_permissions::{calculate_user_permissions, UserPermission};
use revolt_result::{create_error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Read;
use tempfile::NamedTempFile;
use utoipa::ToSchema;

use revolt_database::util::permissions::DatabasePermissionQuery;

/// Maximum ciphertext size per blob: 20 MiB of plaintext (attachment
/// parity) plus headroom for the streaming-AEAD header and per-chunk
/// authentication tags.
pub const MAX_E2EE_BLOB_SIZE: usize = 21 * 1024 * 1024;

/// Body limit for the upload route (multipart overhead on top of the blob)
pub const E2EE_BLOB_BODY_LIMIT: usize = MAX_E2EE_BLOB_SIZE + 64 * 1024;

/// A recipient device declared at upload
#[derive(Deserialize, Debug)]
pub struct BlobRecipient {
    pub user_id: String,
    pub device_id: String,
}

/// Request body for a blob upload
#[derive(ToSchema, TryFromMultipart)]
pub struct BlobUploadPayload {
    /// Client-side encrypted file bytes (opaque to the server)
    #[schema(format = Binary)]
    #[form_data(limit = "unlimited")] // handled by axum's body limit
    file: FieldData<NamedTempFile>,
    /// JSON array of recipient devices:
    /// `[{"user_id": "...", "device_id": "..."}, ...]`
    recipients: String,
}

/// Successful blob upload response
#[derive(Serialize, Debug, ToSchema)]
pub struct BlobUploadResponse {
    /// Blob id to embed (with key + digest) inside the message envelope
    id: String,
}

/// Resolve the caller's device-bound E2EE device id: the device whose
/// identity is bound to THIS session (design §8 / int-H3 — web session
/// tokens have no bound device and are refused). This is the same binding
/// rule as `E2EEIdentity::require_device_bound_session`, but it returns the
/// device id because blob fetch tracking is per recipient device.
async fn require_bound_device_id(db: &Database, user: &User, session: &Session) -> Result<String> {
    for identity in db.fetch_e2ee_identities(&user.id).await? {
        if identity.last_session_id == session.id {
            return Ok(identity.device_id);
        }
    }

    Err(create_error!(NotAuthenticated))
}

/// Parse + validate a declared recipient set: well-formed ids only, no
/// duplicates, between 1 and the fan-out cap.
fn parse_recipients(raw: &str) -> Result<Vec<BlobRecipient>> {
    let recipients: Vec<BlobRecipient> = serde_json::from_str(raw).map_err(|_| {
        create_error!(FailedValidation {
            error: "recipients must be a JSON array of {user_id, device_id}".to_string()
        })
    })?;

    if recipients.is_empty() || recipients.len() > E2EE_MAX_BLOB_RECIPIENTS {
        return Err(create_error!(FailedValidation {
            error: format!("between 1 and {E2EE_MAX_BLOB_RECIPIENTS} recipients per blob")
        }));
    }

    let mut seen = HashSet::new();
    for recipient in &recipients {
        if !revolt_database::is_valid_device_id(&recipient.device_id)
            || recipient.user_id.len() != 26
        {
            return Err(create_error!(FailedValidation {
                error: "invalid recipient".to_string()
            }));
        }

        if !seen.insert((recipient.user_id.clone(), recipient.device_id.clone())) {
            return Err(create_error!(FailedValidation {
                error: "duplicate recipient".to_string()
            }));
        }
    }

    Ok(recipients)
}

/// All blob routes sit behind the operator feature flag (parity with the
/// delta E2EE routes)
async fn require_e2ee_enabled() -> Result<()> {
    if !config().await.features.e2ee_enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "e2ee".to_string()
        }));
    }

    Ok(())
}

/// Upload an E2EE attachment blob
///
/// Accepts an opaque ciphertext blob plus the declared recipient devices
/// (the server would learn the same set from the message envelopes, so this
/// adds nothing to the accepted metadata). No processing of any kind is
/// performed on the bytes. Requires a device-bound session.
#[utoipa::path(
    post,
    path = "/e2ee",
    responses(
        (status = 200, description = "Upload was successful", body = BlobUploadResponse)
    ),
    request_body(content_type = "multipart/form-data", content = BlobUploadPayload),
    security(("session_token" = []))
)]
pub async fn upload_blob(
    State(db): State<Database>,
    user: User,
    session: Session,
    TypedMultipart(BlobUploadPayload {
        mut file,
        recipients,
    }): TypedMultipart<BlobUploadPayload>,
) -> Result<Json<BlobUploadResponse>> {
    require_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let uploader_device_id = require_bound_device_id(&db, &user, &session).await?;

    let recipients = parse_recipients(&recipients)?;

    // Every distinct recipient user must be DM-eligible (mirrors the
    // envelope relay: a blocked sender can neither deliver nor probe);
    // the sender's own devices are always permitted
    let recipient_user_ids: HashSet<&String> = recipients
        .iter()
        .map(|recipient| &recipient.user_id)
        .filter(|id| **id != user.id)
        .collect();

    for recipient_id in recipient_user_ids {
        let recipient = db.fetch_user(recipient_id).await?;

        let mut query = DatabasePermissionQuery::new(&db, &user).user(&recipient);
        calculate_user_permissions(&mut query)
            .await
            .throw_if_lacking_user_permission(UserPermission::SendMessage)?;
    }

    // Read the ciphertext; size caps are the ONLY content inspection
    let mut buf = Vec::<u8>::new();
    file.contents
        .read_to_end(&mut buf)
        .map_err(|_| create_error!(InternalError))?;

    if buf.is_empty() {
        return Err(create_error!(FileTooSmall));
    }

    if buf.len() > MAX_E2EE_BLOB_SIZE {
        return Err(create_error!(FileTooLarge {
            max: MAX_E2EE_BLOB_SIZE
        }));
    }

    let id = ulid::Ulid::new().to_string();
    let bucket_id = config().await.files.s3.default_bucket;

    // Upload to S3 first, then commit the record — an orphaned S3 object is
    // recoverable garbage, an orphaned record is a broken fetch
    let iv = upload_to_s3(&bucket_id, &E2EEBlob::s3_path(&id), &buf).await?;

    db.insert_e2ee_blob(&E2EEBlob {
        id: id.clone(),
        uploader_user_id: user.id,
        uploader_device_id,
        size: buf.len() as isize,
        bucket_id,
        iv,
        recipients: recipients
            .into_iter()
            .map(|recipient| E2EEBlobRecipient {
                user_id: recipient.user_id,
                device_id: recipient.device_id,
                fetched: false,
            })
            .collect(),
    })
    .await?;

    Ok(Json(BlobUploadResponse { id }))
}

/// Fetch an E2EE attachment blob
///
/// Serves the ciphertext exactly as uploaded. Only a declared recipient
/// device (proven by its device-bound session) may fetch; the fetch is
/// tracked per device and the blob is deleted once every recipient has
/// fetched it. A missing/expired blob is a 404 — clients surface it as
/// "attachment expired before delivery" (honesty about loss), never a
/// silent gap.
#[utoipa::path(
    get,
    path = "/e2ee/{blob_id}",
    responses(
        (status = 200, description = "Blob ciphertext", body = Vec<u8>)
    ),
    params(
        ("blob_id" = String, Path, description = "Blob identifier")
    ),
    security(("session_token" = []))
)]
pub async fn fetch_blob(
    State(db): State<Database>,
    user: User,
    session: Session,
    Path(blob_id): Path<String>,
) -> Result<Response> {
    require_e2ee_enabled().await?;

    let device_id = require_bound_device_id(&db, &user, &session).await?;

    let blob = db.fetch_e2ee_blob(&blob_id).await?;

    // Authorization: declared recipients only. NotFound (not Forbidden) so
    // non-recipients cannot distinguish "exists" from "expired".
    if !blob.authorizes_fetch(&user.id, &device_id) {
        return Err(create_error!(NotFound));
    }

    // No shared in-memory cache for blobs: each is fetched approximately
    // once per device and deleted afterwards; caching ciphertext would only
    // extend its lifetime in RAM
    let data = fetch_from_s3(&blob.bucket_id, &E2EEBlob::s3_path(&blob.id), &blob.iv).await?;

    // Track the fetch; delete the blob once every recipient has it. The
    // record is only removed after the S3 object is gone — otherwise the
    // object would be orphaned with nothing left to point the TTL sweep
    // at it. On S3 failure the record stays and the sweep retries both.
    let updated = db
        .mark_e2ee_blob_fetched(&blob.id, &user.id, &device_id)
        .await?;

    if updated.fully_fetched() {
        match delete_from_s3(&blob.bucket_id, &E2EEBlob::s3_path(&blob.id)).await {
            Ok(()) => {
                db.delete_e2ee_blob(&blob.id).await?;
            }
            Err(error) => {
                tracing::warn!(
                    "failed to delete fully-fetched blob {} from S3 (TTL sweep will retry): {error:?}",
                    blob.id
                );
            }
        }
    }

    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (header::CONTENT_DISPOSITION, "attachment".to_owned()),
            // Ciphertext in transit storage: never cache on shared
            // infrastructure, never persist beyond this response
            (header::CACHE_CONTROL, "private, no-store".to_owned()),
        ],
        data,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipients_json(count: usize) -> String {
        let entries: Vec<String> = (0..count)
            .map(|i| {
                format!(
                    r#"{{"user_id":"01USERAAAAAAAAAAAAAAAA{i:04}","device_id":"{:032x}"}}"#,
                    i
                )
            })
            .collect();
        format!("[{}]", entries.join(","))
    }

    #[test]
    fn recipients_validation() {
        // Well-formed set accepted
        assert_eq!(parse_recipients(&recipients_json(3)).unwrap().len(), 3);

        // Empty, over-cap, malformed JSON all rejected
        assert!(parse_recipients("[]").is_err());
        assert!(parse_recipients(&recipients_json(E2EE_MAX_BLOB_RECIPIENTS + 1)).is_err());
        assert!(parse_recipients("not json").is_err());

        // Bad device id (not 128-bit lowercase hex) rejected
        assert!(parse_recipients(
            r#"[{"user_id":"01USERAAAAAAAAAAAAAAAA0000","device_id":"../escape"}]"#
        )
        .is_err());

        // Bad user id length rejected
        assert!(parse_recipients(
            r#"[{"user_id":"short","device_id":"00000000000000000000000000000000"}]"#
        )
        .is_err());

        // Duplicate recipient rejected
        let duplicate = format!(
            "[{entry},{entry}]",
            entry = r#"{"user_id":"01USERAAAAAAAAAAAAAAAA0000","device_id":"00000000000000000000000000000000"}"#
        );
        assert!(parse_recipients(&duplicate).is_err());
    }

    #[test]
    fn blob_size_cap_covers_stream_overhead() {
        // 20 MiB of plaintext in 1 MiB STREAM chunks: 20 tags + header
        let plaintext_cap: usize = 20 * 1024 * 1024;
        let worst_case = 12 + plaintext_cap + plaintext_cap.div_ceil(1024 * 1024) * 16;
        assert!(worst_case <= MAX_E2EE_BLOB_SIZE);
        assert!(MAX_E2EE_BLOB_SIZE < E2EE_BLOB_BODY_LIMIT);
    }
}
