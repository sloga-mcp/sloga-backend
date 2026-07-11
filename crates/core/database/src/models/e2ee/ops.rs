use revolt_result::Result;

use crate::{E2EEBackup, E2EEBlob, E2EEEnvelope, E2EEIdentity, E2EEOneTimeKey};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractE2EE: Sync + Send {
    /// Fetch a device identity
    async fn fetch_e2ee_identity(&self, user_id: &str, device_id: &str) -> Result<E2EEIdentity>;

    /// Fetch all device identities for a user
    async fn fetch_e2ee_identities(&self, user_id: &str) -> Result<Vec<E2EEIdentity>>;

    /// Insert a new device identity
    ///
    /// Must fail with a database error if a row for (user_id, device_id)
    /// already exists — uniqueness is index-enforced, not code-path-enforced.
    async fn insert_e2ee_identity(&self, identity: &E2EEIdentity) -> Result<()>;

    /// Replace an existing device identity (key replenishment / fallback
    /// rotation). Callers must enforce identity-key immutability first.
    async fn replace_e2ee_identity(&self, identity: &E2EEIdentity) -> Result<()>;

    /// Update session bookkeeping after a proven device claim
    async fn update_e2ee_identity_session(
        &self,
        user_id: &str,
        device_id: &str,
        session_id: &str,
        at: iso8601_timestamp::Timestamp,
    ) -> Result<()>;

    /// Delete a device: identity, one-time keys and queued envelopes.
    /// Idempotent; returns whether the identity existed.
    async fn delete_e2ee_device(&self, user_id: &str, device_id: &str) -> Result<bool>;

    /// Delete all devices for a user (account deletion cascade).
    /// Returns the ids of the devices that were removed.
    async fn delete_all_e2ee_devices(&self, user_id: &str) -> Result<Vec<String>>;

    /// Insert (or overwrite by id) a batch of one-time keys
    async fn insert_e2ee_one_time_keys(&self, keys: &[E2EEOneTimeKey]) -> Result<()>;

    /// Delete ALL stored one-time keys for a device (restore's
    /// replace-and-republish, design §5/§6.3). Idempotent; returns how many
    /// were removed. Scoped strictly to (user_id, device_id) — never touches
    /// another device's or user's keys.
    async fn delete_e2ee_one_time_keys(&self, user_id: &str, device_id: &str) -> Result<usize>;

    /// Count remaining one-time keys for a device
    async fn count_e2ee_one_time_keys(&self, user_id: &str, device_id: &str) -> Result<u64>;

    /// Count how many of the given key ids are already stored for a device.
    /// Inserts upsert by id, so cap accounting must not double-count a
    /// replenish that reuses key ids.
    async fn count_e2ee_one_time_keys_among(
        &self,
        user_id: &str,
        device_id: &str,
        key_ids: &[String],
    ) -> Result<u64>;

    /// Atomically consume one one-time key for a device; None at exhaustion
    /// (callers then serve the fallback key — "no bundle" is never the
    /// answer for a registered device)
    async fn consume_e2ee_one_time_key(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<E2EEOneTimeKey>>;

    /// Queue envelopes for delivery
    async fn insert_e2ee_envelopes(&self, envelopes: &[E2EEEnvelope]) -> Result<()>;

    /// Count queued envelopes for a device (queue-depth cap)
    async fn count_e2ee_envelopes(&self, recipient_user_id: &str, recipient_device_id: &str)
        -> Result<u64>;

    /// Sum the ENCODED ciphertext bytes queued for a device (the per-device
    /// queue BYTE budget — media-E2EE plan §2.2.4: welcome-sized envelopes
    /// must not multiply the abuse ceiling the depth cap was sized for)
    async fn sum_e2ee_envelope_bytes(
        &self,
        recipient_user_id: &str,
        recipient_device_id: &str,
    ) -> Result<u64>;

    /// Fetch queued envelopes for a device, ordered by id ascending
    async fn fetch_e2ee_envelopes(
        &self,
        recipient_user_id: &str,
        recipient_device_id: &str,
        limit: i64,
    ) -> Result<Vec<E2EEEnvelope>>;

    /// Acknowledge (delete) a delivered envelope. Scoped to the recipient:
    /// deletes only if (recipient_user_id, recipient_device_id) match.
    /// Idempotent; returns whether an envelope was deleted.
    async fn delete_e2ee_envelope(
        &self,
        id: &str,
        recipient_user_id: &str,
        recipient_device_id: &str,
    ) -> Result<bool>;

    /// TTL sweep: delete envelopes with id (ULID) older than the threshold
    async fn delete_e2ee_envelopes_before(&self, threshold_id: &str) -> Result<usize>;

    /// Insert an encrypted attachment blob record
    async fn insert_e2ee_blob(&self, blob: &E2EEBlob) -> Result<()>;

    /// Fetch a blob record
    async fn fetch_e2ee_blob(&self, id: &str) -> Result<E2EEBlob>;

    /// Atomically mark a blob fetched by one recipient device and return
    /// the updated record. NotFound when the blob does not exist or the
    /// (user, device) pair is not a declared recipient.
    async fn mark_e2ee_blob_fetched(
        &self,
        id: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<E2EEBlob>;

    /// Delete a blob record. Idempotent; returns whether it existed.
    /// (Callers delete the S3 object — the record carries bucket/path/iv.)
    async fn delete_e2ee_blob(&self, id: &str) -> Result<bool>;

    /// TTL sweep candidates: blobs with id (ULID) older than the threshold
    /// and ciphertext size strictly greater than `min_size` bytes. Returns
    /// the records so the caller can delete the S3 objects too.
    async fn fetch_expired_e2ee_blobs(
        &self,
        threshold_id: &str,
        min_size: isize,
    ) -> Result<Vec<E2EEBlob>>;

    /// Fetch one device's key-backup blob, if present (design §5).
    async fn fetch_e2ee_backup(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<E2EEBackup>>;

    /// Fetch ALL of a user's key-backup blobs, one per device (the restore
    /// path — the caller tries the entered recovery code against each).
    async fn fetch_e2ee_backups(&self, user_id: &str) -> Result<Vec<E2EEBackup>>;

    /// Insert or replace a device's key-backup blob (upsert by composite id).
    /// Generation monotonicity is enforced by the caller BEFORE this call
    /// (design §5); this is a plain last-writer-wins upsert.
    async fn upsert_e2ee_backup(&self, backup: &E2EEBackup) -> Result<()>;

    /// Delete a device's key-backup blob. Idempotent; returns whether it
    /// existed. Only ever reached from the MFA-gated DELETE route or the
    /// account-deletion cascade — NOT from device revocation (design §5).
    async fn delete_e2ee_backup(&self, user_id: &str, device_id: &str) -> Result<bool>;

    /// Delete ALL of a user's key-backup blobs (account-deletion cascade).
    async fn delete_all_e2ee_backups(&self, user_id: &str) -> Result<usize>;
}
