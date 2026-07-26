//! Chunked/resumable uploads: S3 multipart driven across separate HTTP
//! requests via a persisted `UploadSession`.
//!
//! Every chunk stays under Cloudflare's ~100 MB edge body cap (the entire
//! reason this exists), autumn never holds more than one chunk in RAM, and a
//! dropped connection resumes from the recorded part set instead of zero.
//! See docs/chunked-uploads-implementation-plan.md.
//!
//! Ciphertext is the segmented STREAM format (`FileHash.format_version = 2`):
//! part boundaries align with 1 MiB AEAD segments, making each part's
//! encryption a pure function of `(server key, nonce prefix, part index)` —
//! out-of-order-safe, restart-safe, deterministic. The flip side: a re-PUT
//! with DIFFERENT bytes is AES-GCM nonce reuse and is rejected by content
//! hash, never overwritten.

use std::io::Write;

use axum::{
    body::Bytes,
    extract::{Path, State},
    Json,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use revolt_config::{config, report_internal_error};
use revolt_database::{
    iso8601_timestamp::{Duration, Timestamp},
    Database, FileHash, Metadata, UploadPartRecord, UploadSession, UploadSessionState, User,
    UPLOAD_PART_CLAIM_TTL_MINUTES,
};
use revolt_result::{create_error, Result};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use utoipa::ToSchema;

use crate::api::{Tag, UploadResponse};

/// Per-user cap on concurrently open (`Pending`/`Completing`) sessions — a
/// resource guard against parking unbounded un-completed parts in S3
const MAX_ACTIVE_SESSIONS_PER_USER: u64 = 5;

/// Bytes of part 1 kept for the magic-byte mime sniff at `complete`
const HEAD_SNIFF_SIZE: usize = 8 * 1024;

/// Slack over the chunk size for the part route's body limit
pub const PART_BODY_LIMIT: usize = revolt_files::CHUNK_SIZE + 64 * 1024;

/// Request body for `create`
#[derive(Deserialize, Debug, ToSchema)]
pub struct CreateUploadPayload {
    /// Filename to mint the `File` with
    pub filename: String,
    /// Total plaintext size in bytes
    pub total_size: i64,
    /// Declared content type (fallback if magic-byte sniffing fails)
    #[serde(default)]
    pub content_type: Option<String>,
}

/// Successful `create` response
#[derive(Serialize, Debug, ToSchema)]
pub struct CreateUploadResponse {
    /// Session id for all subsequent requests
    pub session_id: String,
    /// Required plaintext size of every part except the last
    pub chunk_size: i64,
    /// Number of parts the declared size divides into
    pub total_parts: i64,
    /// When the session (and its parts) will be reaped
    pub expires_at: String,
}

/// Session status, the client's resume source of truth
#[derive(Serialize, Debug, ToSchema)]
pub struct UploadSessionStatus {
    pub state: &'static str,
    pub chunk_size: i64,
    pub total_size: i64,
    pub total_parts: i64,
    /// Part numbers already recorded (upload the rest)
    pub parts: Vec<i32>,
    pub expires_at: String,
    /// Minted file id, once `Completed`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
}

fn assert_attachments_tag(tag: &Tag) -> Result<()> {
    // Every other tag REQUIRES the image pipeline (validation, thumbnails,
    // strip) that chunked uploads deliberately skip — an opaque multi-GB
    // "icon" must not exist
    if matches!(tag, Tag::attachments) {
        Ok(())
    } else {
        Err(create_error!(FileTypeNotAllowed))
    }
}

/// Fetch a session and check the caller owns it. NotFound for both a missing
/// row and someone else's row — existence of other users' sessions is not
/// disclosed.
async fn fetch_owned_session(db: &Database, id: &str, user: &User) -> Result<UploadSession> {
    let session = db.fetch_upload_session(id).await?;
    if session.uploader_id != user.id {
        return Err(create_error!(NotFound));
    }
    Ok(session)
}

/// Begin a chunked upload
#[utoipa::path(
    post,
    path = "/{tag}/upload/create",
    responses(
        (status = 200, description = "Session created", body = CreateUploadResponse)
    ),
    params(("tag" = Tag, Path, description = "Tag to upload to (attachments only)")),
    request_body(content_type = "application/json", content = CreateUploadPayload),
    security(("session_token" = []), ("bot_token" = []))
)]
pub async fn create_upload(
    State(db): State<Database>,
    user: User,
    Path(tag): Path<Tag>,
    Json(payload): Json<CreateUploadPayload>,
) -> Result<Json<CreateUploadResponse>> {
    let config = config().await;
    assert_attachments_tag(&tag)?;

    let chunk_size = revolt_files::CHUNK_SIZE as i64;

    // Floor: below one chunk, single-POST works and MUST be used — it is the
    // path with virus scanning, EXIF stripping and validation. The chunked
    // pipeline exemption exists only where the CDN wall makes single-POST
    // physically impossible.
    if payload.total_size <= chunk_size {
        return Err(create_error!(FileTooSmall));
    }

    let limits = user.limits().await;
    let tag_str: &'static str = tag.clone().into();
    let size_limit = *limits.file_upload_size_limit.get(tag_str).expect("size limit");
    if payload.total_size > size_limit as i64 {
        return Err(create_error!(FileTooLarge { max: size_limit }));
    }

    // 150 parts at 5 GB; S3's ceiling is 10,000
    if (payload.total_size + chunk_size - 1) / chunk_size > 10_000 {
        return Err(create_error!(FileTooLarge { max: size_limit }));
    }

    // Resource guard, enforced again here after the ratelimiter: open
    // sessions can each hold gigabytes of un-completed parts
    let active = db.count_active_upload_sessions_for_user(&user.id).await?;
    if active >= MAX_ACTIVE_SESSIONS_PER_USER {
        return Err(create_error!(TooManyUploadSessions {
            max: MAX_ACTIVE_SESSIONS_PER_USER as usize
        }));
    }

    let prefix = revolt_files::SegmentedStreamCipher::generate_prefix();
    let mut session = UploadSession::new(
        user.id.clone(),
        tag_str.to_owned(),
        payload.filename,
        payload
            .content_type
            .unwrap_or_else(|| "application/octet-stream".to_owned()),
        payload.total_size,
        chunk_size,
        config.files.s3.default_bucket.clone(),
        String::new(), // upload id assigned below, once S3 knows the key
        BASE64_STANDARD.encode(prefix),
    );

    session.s3_upload_id =
        revolt_files::create_multipart_in_s3(&session.bucket_id, &session.path).await?;

    db.insert_upload_session(&session).await?;

    Ok(Json(CreateUploadResponse {
        chunk_size,
        total_parts: session.total_parts(),
        expires_at: session.expires_at.format().to_string(),
        session_id: session.id,
    }))
}

/// Upload one part (raw bytes)
///
/// Idempotent for IDENTICAL bytes: re-uploading a recorded part with the
/// same content hash succeeds without re-storing. DIFFERENT bytes for a
/// recorded part are rejected 409 — the only way onward is abort + recreate.
#[utoipa::path(
    put,
    path = "/{tag}/upload/{session_id}/part/{part_number}",
    responses((status = 200, description = "Part stored")),
    params(
        ("tag" = Tag, Path, description = "Tag uploaded to"),
        ("session_id" = String, Path, description = "Upload session"),
        ("part_number" = i32, Path, description = "1-based part number")
    ),
    request_body(content_type = "application/octet-stream", content = Vec<u8>),
    security(("session_token" = []), ("bot_token" = []))
)]
pub async fn upload_part(
    State(db): State<Database>,
    user: User,
    Path((tag, session_id, part_number)): Path<(Tag, String, i32)>,
    body: Bytes,
) -> Result<()> {
    assert_attachments_tag(&tag)?;
    let session = fetch_owned_session(&db, &session_id, &user).await?;

    if !matches!(session.state, UploadSessionState::Pending) {
        return Err(create_error!(UploadSessionConflict));
    }

    // A changed CHUNK_SIZE constant must not corrupt an in-flight session's
    // part->segment mapping; such a session can only be aborted
    if session.chunk_size != revolt_files::CHUNK_SIZE as i64 {
        return Err(create_error!(UploadSessionConflict));
    }

    let Some(expected_size) = session.expected_part_size(part_number) else {
        return Err(create_error!(InvalidOperation));
    };
    if body.len() as i64 != expected_size {
        return Err(create_error!(InvalidOperation));
    }

    let sha256 = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&body);
        format!("{:02x}", hasher.finalize())
    };

    let part_key = UploadSession::part_key(part_number);

    // Fast path for retries of an already-recorded part: identical bytes are
    // success (deterministic encryption produced the identical S3 part);
    // divergent bytes are nonce reuse and can NEVER be accepted
    if let Some(recorded) = session.parts.get(&part_key) {
        return if recorded.sha256 == sha256 {
            Ok(())
        } else {
            Err(create_error!(UploadSessionConflict))
        };
    }

    // Politeness lock: one in-flight PUT per index. A stale claim (crashed
    // PUT) is stealable after the TTL.
    let now = Timestamp::now_utc();
    let claimed = db
        .try_claim_upload_part(
            &session_id,
            &part_key,
            now,
            now - Duration::minutes(UPLOAD_PART_CLAIM_TTL_MINUTES),
        )
        .await?;
    let Some(session) = claimed else {
        return Err(create_error!(UploadSessionConflict));
    };

    // Re-check the record under the claim (a racing PUT may have recorded
    // between our fetch and the claim)
    if let Some(recorded) = session.parts.get(&part_key) {
        let identical = recorded.sha256 == sha256;
        db.release_upload_part_claim(&session_id, &part_key).await?;
        return if identical {
            Ok(())
        } else {
            Err(create_error!(UploadSessionConflict))
        };
    }

    let result = store_part(&db, &session, part_number, &part_key, &sha256, &body).await;
    if result.is_err() {
        // Best-effort: a leaked claim ages out via the TTL anyway
        let _ = db.release_upload_part_claim(&session_id, &part_key).await;
    }
    result
}

/// Encrypt, store to S3 and record one claimed part
async fn store_part(
    db: &Database,
    session: &UploadSession,
    part_number: i32,
    part_key: &str,
    sha256: &str,
    body: &Bytes,
) -> Result<()> {
    let prefix_bytes = report_internal_error!(BASE64_STANDARD.decode(&session.nonce_prefix))?;
    let mut prefix = [0u8; revolt_files::STREAM_NONCE_PREFIX_SIZE];
    if prefix_bytes.len() != prefix.len() {
        return Err(create_error!(InternalError));
    }
    prefix.copy_from_slice(&prefix_bytes);

    let cipher = revolt_files::SegmentedStreamCipher::from_config(prefix).await;
    let is_final_part = part_number as i64 == session.total_parts();
    let ciphertext =
        report_internal_error!(cipher.encrypt_part(part_number as u32, is_final_part, body))?;

    let etag = revolt_files::upload_part_to_s3(
        &session.bucket_id,
        &session.path,
        &session.s3_upload_id,
        part_number,
        ciphertext,
    )
    .await?;

    let head_b64 = (part_number == 1)
        .then(|| BASE64_STANDARD.encode(&body[..usize::min(HEAD_SNIFF_SIZE, body.len())]));

    let recorded = db
        .record_upload_part(
            &session.id,
            part_key,
            &UploadPartRecord {
                size: body.len() as i64,
                etag,
                sha256: sha256.to_owned(),
            },
            head_b64.as_deref(),
        )
        .await?;

    // The session left `Pending` while we were writing to S3 (abort or a
    // raced complete) — the part was NOT recorded; surface the conflict
    if !recorded {
        return Err(create_error!(UploadSessionConflict));
    }

    Ok(())
}

/// Fetch session status (resume source of truth)
#[utoipa::path(
    get,
    path = "/{tag}/upload/{session_id}",
    responses(
        (status = 200, description = "Session status", body = UploadSessionStatus)
    ),
    params(
        ("tag" = Tag, Path, description = "Tag uploaded to"),
        ("session_id" = String, Path, description = "Upload session")
    ),
    security(("session_token" = []), ("bot_token" = []))
)]
pub async fn get_upload_session(
    State(db): State<Database>,
    user: User,
    Path((tag, session_id)): Path<(Tag, String)>,
) -> Result<Json<UploadSessionStatus>> {
    assert_attachments_tag(&tag)?;
    let session = fetch_owned_session(&db, &session_id, &user).await?;

    let mut parts: Vec<i32> = session
        .parts
        .keys()
        .filter_map(|key| key.parse().ok())
        .collect();
    parts.sort_unstable();

    Ok(Json(UploadSessionStatus {
        state: session.state.as_variant_str(),
        chunk_size: session.chunk_size,
        total_size: session.total_size,
        total_parts: session.total_parts(),
        parts,
        expires_at: session.expires_at.format().to_string(),
        file_id: session.file_id,
    }))
}

/// Assemble the upload and mint the claim-once `File`
///
/// Idempotent: retrying after a lost response returns the same file id.
/// Re-entrant while `Completing`: a crash mid-complete is resolved by the
/// retry via the persisted composite hash (see `resolve_completing`).
#[utoipa::path(
    post,
    path = "/{tag}/upload/{session_id}/complete",
    responses(
        (status = 200, description = "Upload complete", body = UploadResponse)
    ),
    params(
        ("tag" = Tag, Path, description = "Tag uploaded to"),
        ("session_id" = String, Path, description = "Upload session")
    ),
    security(("session_token" = []), ("bot_token" = []))
)]
pub async fn complete_upload(
    State(db): State<Database>,
    user: User,
    Path((tag, session_id)): Path<(Tag, String)>,
) -> Result<Json<UploadResponse>> {
    assert_attachments_tag(&tag)?;
    let session = fetch_owned_session(&db, &session_id, &user).await?;

    match session.state {
        // Lost-response retry: hand back the already-minted id
        UploadSessionState::Completed => {
            let id = session.file_id.clone().ok_or_else(|| create_error!(InternalError))?;
            return Ok(Json(UploadResponse { id }));
        }
        UploadSessionState::Aborted => return Err(create_error!(NotFound)),
        UploadSessionState::Completing => {
            // Crash-recovery re-entry — composite already persisted
            return resolve_completing(&db, session, &user).await.map(Json);
        }
        UploadSessionState::Pending => {}
    }

    if !session.is_part_set_complete() {
        return Err(create_error!(UploadIncomplete));
    }

    let composite = composite_hash(&session)?;

    let Some(session) = db.begin_upload_session_complete(&session.id, &composite).await? else {
        // CAS refused: in-flight PUTs, or someone else's complete won. Look
        // again and either join the winner or report the conflict.
        let session = fetch_owned_session(&db, &session_id, &user).await?;
        return match session.state {
            UploadSessionState::Completed => {
                let id = session.file_id.clone().ok_or_else(|| create_error!(InternalError))?;
                Ok(Json(UploadResponse { id }))
            }
            UploadSessionState::Completing => resolve_completing(&db, session, &user).await.map(Json),
            _ => Err(create_error!(UploadSessionConflict)),
        };
    };

    resolve_completing(&db, session, &user).await.map(Json)
}

/// The composite dedupe hash: a domain-separated digest over the layout and
/// every part's plaintext sha256, computable from the recorded part set
/// alone (no sequential whole-file hash state to persist)
fn composite_hash(session: &UploadSession) -> Result<String> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"sloga-chunked-v2");
    hasher.update(session.chunk_size.to_le_bytes());
    hasher.update(session.total_size.to_le_bytes());
    for part_number in 1..=session.total_parts() {
        let record = session
            .parts
            .get(&UploadSession::part_key(part_number as i32))
            .ok_or_else(|| create_error!(UploadIncomplete))?;
        hasher.update(record.sha256.as_bytes());
    }
    Ok(format!("{:02x}", hasher.finalize()))
}

/// Drive a `Completing` session to `Completed`, from any starting point:
/// a fresh CAS, an owner retry after a crash, or a retry after a lost
/// response. Every step is safe to repeat.
async fn resolve_completing(
    db: &Database,
    session: UploadSession,
    user: &User,
) -> Result<UploadResponse> {
    let config = config().await;
    let composite = session
        .composite_hash
        .clone()
        .ok_or_else(|| create_error!(InternalError))?;

    // Plain hit/miss dedupe — deliberately NOT the single-POST path's
    // stale-video reprocessing branch: every v2 chunked video legitimately
    // has `Metadata::File`, and "reprocessing" it would delete a live hash
    // row out from under its object
    if let Ok(existing) = db.fetch_attachment_hash(&composite).await {
        if !existing.iv.is_empty() {
            // The just-uploaded parts are redundant; drop them (a missing
            // upload — lifecycle already reaped it — is success)
            revolt_files::abort_multipart_in_s3(
                &session.bucket_id,
                &session.path,
                &session.s3_upload_id,
            )
            .await?;
            return mint_file(db, &session, &existing, user).await;
        }
    }

    // Assemble in S3 unless a previous attempt already did (crash between
    // S3-complete and the DB writes) — never re-drive a completed MPU
    if !revolt_files::object_exists_in_s3(&session.bucket_id, &session.path).await? {
        revolt_files::complete_multipart_in_s3(
            &session.bucket_id,
            &session.path,
            &session.s3_upload_id,
            &session.completed_part_list(),
        )
        .await?;
    }

    // Sniff the mime from part 1's magic bytes; opaque store, no pipeline
    let mime_type = sniff_mime(&session);
    if config.files.blocked_mime_types.iter().any(|m| m == &mime_type) {
        return Err(create_error!(FileTypeNotAllowed));
    }

    let file_hash = FileHash {
        id: composite.clone(),
        processed_hash: composite.clone(),
        created_at: Timestamp::now_utc(),
        bucket_id: session.bucket_id.clone(),
        path: session.path.clone(),
        iv: session.nonce_prefix.clone(),
        format_version: Some(2),
        metadata: Metadata::File,
        content_type: mime_type,
        size: session.total_size as isize,
    };

    if let Err(insert_error) = db.insert_attachment_hash(&file_hash).await {
        // Two identical uploads completing concurrently: the loser adopts
        // the winner's row and drops its own (now redundant) object
        if let Ok(existing) = db.fetch_attachment_hash(&composite).await {
            if !existing.iv.is_empty() {
                revolt_files::delete_from_s3(&session.bucket_id, &session.path).await?;
                return mint_file(db, &session, &existing, user).await;
            }
        }
        return Err(insert_error);
    }

    mint_file(db, &session, &file_hash, user).await
}

/// Mint the claim-once `File` (`used_for = None` — the message send claims
/// it via the existing attachment path, untouched) and finalize the session
async fn mint_file(
    db: &Database,
    session: &UploadSession,
    hash: &FileHash,
    user: &User,
) -> Result<UploadResponse> {
    let id = nanoid::nanoid!(42);
    db.insert_attachment(&hash.into_file(
        id.clone(),
        session.tag.clone(),
        session.filename.clone(),
        user.id.clone(),
    ))
    .await?;

    db.set_upload_session_completed(&session.id, &id).await?;
    Ok(UploadResponse { id })
}

/// Magic-byte sniff over the stored head of part 1, falling back to the
/// declared type
fn sniff_mime(session: &UploadSession) -> String {
    if let Ok(head) = BASE64_STANDARD.decode(&session.head_b64) {
        if !head.is_empty() {
            if let Ok(mut file) = tempfile::NamedTempFile::new() {
                if file.write_all(&head).is_ok() {
                    let sniffed =
                        crate::mime_type::determine_mime_type(&mut file, &session.filename);
                    // The sniffer's last resort is octet-stream; prefer the
                    // declared type over that
                    if sniffed != "application/octet-stream" {
                        return sniffed.to_owned();
                    }
                }
            }
        }
    }
    session.declared_content_type.clone()
}

/// Cancel an upload
///
/// Flips the session to `Aborted` (killing further PUTs instantly); the
/// cleanup sweep performs the S3 abort with its retry semantics — doing the
/// abort here would lose the retry row if it failed, and an in-flight PUT
/// racing it could resurrect parts.
#[utoipa::path(
    delete,
    path = "/{tag}/upload/{session_id}",
    responses((status = 200, description = "Upload aborted")),
    params(
        ("tag" = Tag, Path, description = "Tag uploaded to"),
        ("session_id" = String, Path, description = "Upload session")
    ),
    security(("session_token" = []), ("bot_token" = []))
)]
pub async fn abort_upload(
    State(db): State<Database>,
    user: User,
    Path((tag, session_id)): Path<(Tag, String)>,
) -> Result<()> {
    assert_attachments_tag(&tag)?;
    let session = fetch_owned_session(&db, &session_id, &user).await?;

    if db.set_upload_session_aborted(&session.id).await? {
        return Ok(());
    }

    match session.state {
        // Aborting an aborted session is idempotent success
        UploadSessionState::Aborted => Ok(()),
        // Completing cannot be cancelled (the object may already exist);
        // Completed is too late
        _ => Err(create_error!(UploadSessionConflict)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State};
    use revolt_database::{Database, UploadSession};

    /// All tests share one scratch bucket so the cached global config (first
    /// loader wins) is consistent; objects are small and the bucket is not
    /// the prod one
    fn test_env() {
        std::env::set_var("REVOLT_FILES__S3__DEFAULT_BUCKET", "autumn-upload-tests");
    }

    fn db() -> Database {
        Database::Reference(Default::default())
    }

    fn test_user() -> User {
        User {
            // limits() parses the id as a ULID, so it must be a real one
            id: ulid::Ulid::new().to_string(),
            ..Default::default()
        }
    }

    async fn ensure_bucket() {
        use revolt_files::{EncryptionKey, FileStorageRepository, S3Storage};
        let storage = S3Storage::from_config(EncryptionKey::from_config().await).await;
        // Already-exists is fine
        let _ = storage.create_bucket("autumn-upload-tests").await;
    }

    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    #[tokio::test]
    async fn create_rejects_small_files_wrong_tags_and_caps_sessions() {
        test_env();
        ensure_bucket().await;
        let db = db();
        let user = test_user();

        // Floor: single-POST territory must use single-POST (that path has
        // the scan/strip pipeline)
        let result = create_upload(
            State(db.clone()),
            user.clone(),
            Path(Tag::attachments),
            Json(CreateUploadPayload {
                filename: "small.bin".into(),
                total_size: revolt_files::CHUNK_SIZE as i64,
                content_type: None,
            }),
        )
        .await;
        assert!(result.is_err(), "at-or-below one chunk must be rejected");

        // Non-attachment tags are image-pipeline territory
        let result = create_upload(
            State(db.clone()),
            user.clone(),
            Path(Tag::icons),
            Json(CreateUploadPayload {
                filename: "icon.png".into(),
                total_size: revolt_files::CHUNK_SIZE as i64 + 1,
                content_type: None,
            }),
        )
        .await;
        assert!(result.is_err(), "non-attachments tags must be rejected");

        // Per-user cap on open sessions
        for _ in 0..MAX_ACTIVE_SESSIONS_PER_USER {
            let session = UploadSession::new(
                user.id.clone(),
                "attachments".into(),
                "f.bin".into(),
                "application/octet-stream".into(),
                revolt_files::CHUNK_SIZE as i64 + 1,
                revolt_files::CHUNK_SIZE as i64,
                "autumn-upload-tests".into(),
                "fake-upload-id".into(),
                "bm9uY2U3Nzc=".into(),
            );
            db.insert_upload_session(&session).await.unwrap();
        }
        let result = create_upload(
            State(db.clone()),
            user.clone(),
            Path(Tag::attachments),
            Json(CreateUploadPayload {
                filename: "big.bin".into(),
                total_size: revolt_files::CHUNK_SIZE as i64 + 1,
                content_type: None,
            }),
        )
        .await;
        assert!(result.is_err(), "6th open session must be rejected");
    }

    /// The full life of a chunked upload, exercised through the real
    /// handlers against live MinIO: out-of-order parts, idempotent and
    /// divergent re-PUTs, complete, complete-retry idempotency, dedupe of a
    /// second identical upload, and abort of a pending session.
    #[tokio::test]
    async fn chunked_upload_end_to_end() {
        test_env();
        ensure_bucket().await;
        let db = db();
        let user = test_user();

        let tail = 1000usize;
        let total = revolt_files::CHUNK_SIZE + tail;
        let part_1 = pseudo_random(revolt_files::CHUNK_SIZE, 7);
        let part_2 = pseudo_random(tail, 8);

        let created = create_upload(
            State(db.clone()),
            user.clone(),
            Path(Tag::attachments),
            Json(CreateUploadPayload {
                filename: "movie.bin".into(),
                total_size: total as i64,
                content_type: Some("application/x-test".into()),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(created.total_parts, 2);
        let sid = created.session_id.clone();

        // Out of order: the tail goes up first
        upload_part(
            State(db.clone()),
            user.clone(),
            Path((Tag::attachments, sid.clone(), 2)),
            Bytes::from(part_2.clone()),
        )
        .await
        .unwrap();

        // Wrong-size part is rejected
        assert!(upload_part(
            State(db.clone()),
            user.clone(),
            Path((Tag::attachments, sid.clone(), 1)),
            Bytes::from(vec![0u8; 5]),
        )
        .await
        .is_err());

        // Someone else's session is invisible
        assert!(upload_part(
            State(db.clone()),
            test_user(),
            Path((Tag::attachments, sid.clone(), 1)),
            Bytes::from(part_1.clone()),
        )
        .await
        .is_err());

        upload_part(
            State(db.clone()),
            user.clone(),
            Path((Tag::attachments, sid.clone(), 1)),
            Bytes::from(part_1.clone()),
        )
        .await
        .unwrap();

        // Identical re-PUT is idempotent success (no re-store)
        upload_part(
            State(db.clone()),
            user.clone(),
            Path((Tag::attachments, sid.clone(), 2)),
            Bytes::from(part_2.clone()),
        )
        .await
        .unwrap();

        // Divergent re-PUT is nonce reuse — MUST be rejected
        let mut divergent = part_2.clone();
        divergent[0] ^= 1;
        assert!(upload_part(
            State(db.clone()),
            user.clone(),
            Path((Tag::attachments, sid.clone(), 2)),
            Bytes::from(divergent),
        )
        .await
        .is_err());

        // Status shows both parts recorded
        let status = get_upload_session(
            State(db.clone()),
            user.clone(),
            Path((Tag::attachments, sid.clone())),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(status.parts, vec![1, 2]);
        assert_eq!(status.state, "Pending");

        let completed = complete_upload(
            State(db.clone()),
            user.clone(),
            Path((Tag::attachments, sid.clone())),
        )
        .await
        .unwrap()
        .0;

        // Retry returns the same id (lost-response idempotency)
        let retried = complete_upload(
            State(db.clone()),
            user.clone(),
            Path((Tag::attachments, sid.clone())),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(completed.id, retried.id);

        // The minted File is claim-once and points at a v2 hash
        let file = db
            .fetch_attachment("attachments", &completed.id)
            .await
            .unwrap();
        assert!(file.used_for.is_none());
        assert_eq!(file.size as usize, total);
        let hash = file.as_hash(&db).await.unwrap();
        assert_eq!(hash.format_version, Some(2));
        assert!(!hash.iv.is_empty());
        assert_eq!(hash.size as usize, total);

        // The assembled object really exists
        assert!(
            revolt_files::object_exists_in_s3(&hash.bucket_id, &hash.path)
                .await
                .unwrap()
        );

        // Second identical upload dedupes onto the same hash and drops its
        // own parts
        let created_2 = create_upload(
            State(db.clone()),
            user.clone(),
            Path(Tag::attachments),
            Json(CreateUploadPayload {
                filename: "movie-again.bin".into(),
                total_size: total as i64,
                content_type: Some("application/x-test".into()),
            }),
        )
        .await
        .unwrap()
        .0;
        let sid_2 = created_2.session_id.clone();
        for (n, bytes) in [(1, part_1.clone()), (2, part_2.clone())] {
            upload_part(
                State(db.clone()),
                user.clone(),
                Path((Tag::attachments, sid_2.clone(), n)),
                Bytes::from(bytes),
            )
            .await
            .unwrap();
        }
        let completed_2 = complete_upload(
            State(db.clone()),
            user.clone(),
            Path((Tag::attachments, sid_2.clone())),
        )
        .await
        .unwrap()
        .0;
        assert_ne!(completed.id, completed_2.id, "files are distinct");
        let file_2 = db
            .fetch_attachment("attachments", &completed_2.id)
            .await
            .unwrap();
        assert_eq!(file.hash, file_2.hash, "content dedupes to one hash");
        let session_2 = db.fetch_upload_session(&sid_2).await.unwrap();
        assert!(
            !revolt_files::object_exists_in_s3("autumn-upload-tests", &session_2.path)
                .await
                .unwrap(),
            "dedupe hit must not assemble a second object"
        );

        // Abort of a fresh pending session flips state; PUTs then bounce
        let created_3 = create_upload(
            State(db.clone()),
            user.clone(),
            Path(Tag::attachments),
            Json(CreateUploadPayload {
                filename: "cancelled.bin".into(),
                total_size: total as i64,
                content_type: None,
            }),
        )
        .await
        .unwrap()
        .0;
        abort_upload(
            State(db.clone()),
            user.clone(),
            Path((Tag::attachments, created_3.session_id.clone())),
        )
        .await
        .unwrap();
        assert!(upload_part(
            State(db.clone()),
            user.clone(),
            Path((Tag::attachments, created_3.session_id.clone(), 1)),
            Bytes::from(part_1.clone()),
        )
        .await
        .is_err());
    }
}
