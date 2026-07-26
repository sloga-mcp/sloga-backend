use std::collections::HashMap;

use iso8601_timestamp::{Duration, Timestamp};

/// How long a session (and therefore its S3 multipart upload) may live.
///
/// The primary reaper is the crond sweep over `expires_at`; MinIO's
/// server-level `stale_uploads_expiry` (set to 72 h in prod) is the backstop
/// and MUST stay strictly longer than this, or the store aborts still-active
/// resumable uploads out from under their sessions.
pub const UPLOAD_SESSION_TTL_HOURS: i64 = 48;

/// How long a part-index claim may sit before another PUT may steal it.
///
/// Generous on purpose: it must exceed worst-case legitimate part processing
/// (a 32 MiB body read + encrypt + S3 PUT on a congested box). Divergent
/// re-uploads are rejected by content hash regardless, so this claim is only
/// a politeness lock against concurrent same-index uploads.
pub const UPLOAD_PART_CLAIM_TTL_MINUTES: i64 = 10;

auto_derived!(
    /// Lifecycle state of a chunked upload session.
    ///
    /// `Pending` accepts part PUTs. `Completing` means the composite hash is
    /// persisted and assembly is (or was) in progress — re-entered freely by
    /// the owner retrying `complete`, resolved by the sweep if orphaned.
    /// `Completed` and `Aborted` are terminal; `Completed` rows are kept
    /// until `expires_at` so a retried `complete` whose response was lost
    /// can return the same `file_id` instead of an error.
    pub enum UploadSessionState {
        Pending,
        Completing,
        Completed,
        Aborted,
    }

    /// One recorded part of a chunked upload.
    pub struct UploadPartRecord {
        /// Plaintext size of the part as uploaded
        pub size: i64,
        /// ETag S3 returned for the encrypted part — required by
        /// `complete_multipart_upload`
        pub etag: String,
        /// SHA-256 of the part's PLAINTEXT, hex-encoded.
        ///
        /// Feeds the composite dedupe hash at `complete`, and rejects
        /// divergent re-uploads of an already-recorded part — accepting
        /// different bytes under the same part index would be AES-GCM nonce
        /// reuse (the segment nonces are a pure function of the index).
        pub sha256: String,
    }

    /// A chunked/resumable upload in progress — the persisted state that
    /// lets S3's create/part/complete multipart phases span separate HTTP
    /// requests (and autumn restarts).
    ///
    /// All authoritative state lives here; autumn holds nothing in memory.
    /// A reconnecting client asks `GET /:tag/upload/:session_id` for the
    /// recorded part set and re-uploads whatever is missing.
    pub struct UploadSession {
        /// Unique Id — a ULID, so it doubles as the creation clock
        #[serde(rename = "_id")]
        pub id: String,
        /// User who opened the session; every route checks this
        pub uploader_id: String,
        /// Target tag — `attachments` only (other tags need the image
        /// pipeline that chunked uploads deliberately skip)
        pub tag: String,
        /// Client-declared filename, carried into the minted `File`
        pub filename: String,
        /// Client-declared content type — a fallback only; `complete`
        /// sniffs magic bytes from the head of part 1
        pub declared_content_type: String,
        /// Declared total plaintext size; every part's size is validated
        /// against it and `complete` verifies the recorded sum
        pub total_size: i64,
        /// Part size frozen at create (an input of the composite hash —
        /// a changed constant must not corrupt in-flight sessions)
        pub chunk_size: i64,
        /// Bucket the object is assembled in
        pub bucket_id: String,
        /// Final object key (`chunked/{id}`) — the object is assembled in
        /// place; nothing is ever renamed
        pub path: String,
        /// S3 multipart upload id — the heart of the feature
        pub s3_upload_id: String,
        /// Base64 of the 7-byte STREAM nonce prefix; copied into
        /// `FileHash.iv` at complete
        pub nonce_prefix: String,
        /// Recorded parts, keyed by STRINGIFIED part number ("1"..) — BSON
        /// rejects integer map keys, and atomic `$set {"parts.5": …}`
        /// updates produce string field names anyway
        pub parts: HashMap<String, UploadPartRecord>,
        /// In-flight part claims (politeness locks), same key scheme.
        /// A claim older than [`UPLOAD_PART_CLAIM_TTL_MINUTES`] is stealable.
        pub in_flight: HashMap<String, Timestamp>,
        /// Base64 of the first bytes of part 1, for the magic-byte mime
        /// sniff at complete (base64 rather than a byte array: BSON encodes
        /// `Vec<u8>` as an int32 array, ~5x the size)
        pub head_b64: String,
        /// Lifecycle state
        pub state: UploadSessionState,
        /// Composite dedupe hash, persisted by the `Pending -> Completing`
        /// CAS so a crashed `complete` can be resolved by anyone (owner
        /// retry or sweep) without re-reading parts
        #[serde(skip_serializing_if = "Option::is_none")]
        pub composite_hash: Option<String>,
        /// Minted file id, set on `Completed` — a retried `complete`
        /// returns this instead of failing
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file_id: Option<String>,
        /// When the session was opened
        pub created_at: Timestamp,
        /// When the sweep may reap this session (terminal rows included —
        /// `Completed` rows are kept for complete-idempotency until then)
        pub expires_at: Timestamp,
    }
);

impl UploadSessionState {
    /// The serde-serialized variant name as stored in the `state` field —
    /// Mongo query filters MUST use this (`auto_derived!` external tagging
    /// stores unit variants as their bare name).
    pub fn as_variant_str(&self) -> &'static str {
        match self {
            UploadSessionState::Pending => "Pending",
            UploadSessionState::Completing => "Completing",
            UploadSessionState::Completed => "Completed",
            UploadSessionState::Aborted => "Aborted",
        }
    }
}

impl UploadSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uploader_id: String,
        tag: String,
        filename: String,
        declared_content_type: String,
        total_size: i64,
        chunk_size: i64,
        bucket_id: String,
        s3_upload_id: String,
        nonce_prefix: String,
    ) -> UploadSession {
        let id = ulid::Ulid::new().to_string();
        UploadSession {
            path: format!("chunked/{id}"),
            id,
            uploader_id,
            tag,
            filename,
            declared_content_type,
            total_size,
            chunk_size,
            bucket_id,
            s3_upload_id,
            nonce_prefix,
            parts: HashMap::new(),
            in_flight: HashMap::new(),
            head_b64: String::new(),
            state: UploadSessionState::Pending,
            composite_hash: None,
            file_id: None,
            created_at: Timestamp::now_utc(),
            expires_at: Timestamp::now_utc() + Duration::hours(UPLOAD_SESSION_TTL_HOURS),
        }
    }

    /// The map key for a part number
    pub fn part_key(part_number: i32) -> String {
        part_number.to_string()
    }

    /// Total number of parts the declared size divides into
    pub fn total_parts(&self) -> i64 {
        // Manual ceil-div: `i64::div_ceil` is unstable on this toolchain
        (self.total_size + self.chunk_size - 1) / self.chunk_size
    }

    /// The exact plaintext size part `n` must have — full chunks except the
    /// tail. Divergence is rejected, not tolerated: the part->segment
    /// mapping depends on it.
    pub fn expected_part_size(&self, part_number: i32) -> Option<i64> {
        let total_parts = self.total_parts();
        let part_number = part_number as i64;
        if part_number < 1 || part_number > total_parts {
            return None;
        }
        Some(if part_number == total_parts {
            self.total_size - (total_parts - 1) * self.chunk_size
        } else {
            self.chunk_size
        })
    }

    /// Whether every part is recorded and the sizes sum to `total_size`
    pub fn is_part_set_complete(&self) -> bool {
        let total_parts = self.total_parts();
        if self.parts.len() as i64 != total_parts {
            return false;
        }
        let mut sum = 0i64;
        for part_number in 1..=total_parts {
            match self.parts.get(&Self::part_key(part_number as i32)) {
                Some(record) => sum += record.size,
                None => return false,
            }
        }
        sum == self.total_size
    }

    /// Recorded parts as `(part_number, etag)` ascending — the shape
    /// `complete_multipart_upload` wants
    pub fn completed_part_list(&self) -> Vec<(i32, String)> {
        let mut parts: Vec<(i32, String)> = self
            .parts
            .iter()
            .filter_map(|(key, record)| {
                key.parse::<i32>().ok().map(|n| (n, record.etag.clone()))
            })
            .collect();
        parts.sort_by_key(|(n, _)| *n);
        parts
    }

    /// Non-terminal — counts against the per-user open-session cap
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            UploadSessionState::Pending | UploadSessionState::Completing
        )
    }
}
