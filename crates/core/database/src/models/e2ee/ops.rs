use revolt_result::Result;

use crate::{E2EEEnvelope, E2EEIdentity, E2EEOneTimeKey};

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

    /// Count remaining one-time keys for a device
    async fn count_e2ee_one_time_keys(&self, user_id: &str, device_id: &str) -> Result<u64>;

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
}
