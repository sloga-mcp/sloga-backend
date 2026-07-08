auto_derived!(
    /// A signed Curve25519 public key (fallback or one-time)
    ///
    /// The signature is Ed25519 by the owning device's identity key over the
    /// canonical domain-separated payload; `protocol_version` and `device_id`
    /// are inside the signed payload. Clients MUST verify before use.
    pub struct E2EESignedKey {
        /// Key id, unique per device
        pub key_id: String,
        /// Curve25519 public key, unpadded standard base64
        pub key: String,
        /// Ed25519 signature over the canonical payload
        pub signature: String,
    }

    /// Data to publish an E2EE key bundle for the current device
    pub struct DataPublishE2EEKeys {
        /// Device id: 128-bit lowercase hex, generated in the native layer
        pub device_id: String,
        /// Protocol version this device speaks
        pub protocol_version: i32,
        /// Ed25519 (signing) identity key, unpadded standard base64
        pub ed25519_key: String,
        /// Curve25519 (Diffie-Hellman) identity key, unpadded standard base64
        pub curve25519_key: String,
        /// Ed25519 self-signature over the canonical identity payload
        pub signature: String,
        /// Current fallback key
        pub fallback_key: E2EESignedKey,
        /// One-time keys to add
        #[serde(default)]
        pub one_time_keys: Vec<E2EESignedKey>,
        /// Replace ALL of this device's stored one-time keys with the batch
        /// in this request (key-backup restore, slice 5.5 §6.3). Honored only
        /// on a device-bound republish AND only with a non-empty batch, so a
        /// compromised webview cannot strip a live device's keys. Defaults to
        /// additive replenishment.
        #[serde(default)]
        pub replace_one_time_keys: bool,
    }

    /// Response to publishing keys
    pub struct ResponsePublishE2EEKeys {
        /// One-time keys remaining on the server for this device (drives
        /// client replenishment)
        pub one_time_key_count: u64,
    }

    /// A device's identity within a fetched key bundle
    pub struct E2EEDeviceKeys {
        /// Device id
        pub device_id: String,
        /// Protocol version
        pub protocol_version: i32,
        /// Ed25519 identity key
        pub ed25519_key: String,
        /// Curve25519 identity key
        pub curve25519_key: String,
        /// Ed25519 self-signature over the canonical identity payload
        pub signature: String,
        /// One-time key, consumed atomically by this fetch; absent at
        /// exhaustion (use the fallback key — a registered device ALWAYS
        /// yields a usable bundle)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub one_time_key: Option<E2EESignedKey>,
        /// Fallback key, served when one-time keys are exhausted
        pub fallback_key: E2EESignedKey,
        /// One-time keys remaining on the server after this fetch
        pub one_time_keys_remaining: u64,
    }

    /// Key bundle for a user: one entry per registered device
    pub struct E2EEKeyBundle {
        /// User id these bundles belong to
        pub user_id: String,
        /// Per-device bundles
        pub devices: Vec<E2EEDeviceKeys>,
    }

    /// Listing of a user's E2EE devices (nothing consumed by this call).
    ///
    /// Used for device-list reconciliation on connect. The timestamp and
    /// key-count fields are only present when listing one's own devices.
    pub struct E2EEDeviceInfo {
        /// Device id
        pub device_id: String,
        /// Protocol version
        pub protocol_version: i32,
        /// Ed25519 identity key (lets clients detect key substitution
        /// without consuming a one-time key)
        pub ed25519_key: String,
        /// Curve25519 identity key — together with `signature` lets clients
        /// verify the full identity binding without consuming a one-time key
        pub curve25519_key: String,
        /// Ed25519 self-signature over the canonical identity payload
        pub signature: String,
        /// When the device first published keys (own devices only)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub created_at: Option<String>,
        /// Last time the device published keys or proved a device claim
        /// (own devices only)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub last_seen_at: Option<String>,
        /// One-time keys remaining (own devices only; drives replenishment)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub one_time_key_count: Option<u64>,
    }

    /// An encrypted envelope submitted for relay
    pub struct DataE2EEEnvelope {
        /// Recipient user
        pub recipient_user_id: String,
        /// Recipient device
        pub recipient_device_id: String,
        /// Per-session sequence number (lets recipients detect TTL losses)
        pub sequence: u64,
        /// Opaque ciphertext, unpadded standard base64
        pub ciphertext: String,
    }

    /// Data to submit E2EE envelopes (fan-out: one per recipient device)
    pub struct DataSendE2EEMessages {
        /// Sending device id (must be a registered device of the sender)
        pub device_id: String,
        /// Protocol version of the payloads
        pub protocol_version: i32,
        /// Envelopes to relay
        pub envelopes: Vec<DataE2EEEnvelope>,
    }

    /// Delivery status for one submitted envelope
    #[serde(tag = "status")]
    pub enum E2EEDeliveryStatus {
        /// Queued for delivery
        Queued {
            /// Server-assigned envelope id (ULID)
            id: String,
        },
        /// Recipient device is not registered (revoked or never existed);
        /// senders should tear down sessions to this device
        UnknownDevice,
        /// Recipient device's queue is full
        QueueFull,
    }

    /// Per-device delivery result
    pub struct E2EEDeliveryReceipt {
        /// Recipient user
        pub recipient_user_id: String,
        /// Recipient device
        pub recipient_device_id: String,
        /// Outcome for this envelope
        #[serde(flatten)]
        pub status: E2EEDeliveryStatus,
    }

    /// Response to submitting envelopes
    pub struct ResponseSendE2EEMessages {
        /// One receipt per submitted envelope, in submission order
        pub receipts: Vec<E2EEDeliveryReceipt>,
    }

    /// Data to upload (upsert) this device's key-backup blob (slice 5.5 §5).
    pub struct DataPutE2EEBackup {
        /// Device this backup belongs to (must be a bound device of the
        /// authenticated session)
        pub device_id: String,
        /// Opaque canonical header (KDF params, salt, nonce, user_id,
        /// device_id, generation, created_at). Server-visible AAD; the server
        /// parses it ONLY to range-check KDF params and cross-check the
        /// generation.
        pub header: String,
        /// Opaque ciphertext, standard base64 (≤ 8 MiB decoded)
        pub ciphertext: String,
        /// Monotonic generation; must strictly exceed the stored generation
        /// AND equal the header's bound generation.
        pub generation: i64,
    }

    /// Response to uploading a key backup
    pub struct ResponsePutE2EEBackup {
        /// The generation now stored server-side (echoed for the caller's
        /// optimistic bookkeeping; a hostile webview can fake this, so it is
        /// not a durability proof — design §4.5)
        pub generation: i64,
    }

    /// One device's key-backup blob returned on the restore path (§5, §6.1)
    pub struct E2EEBackup {
        /// Device this backup belongs to
        pub device_id: String,
        /// Opaque header (the restoring client derives per-blob from this)
        pub header: String,
        /// Opaque ciphertext, standard base64
        pub ciphertext: String,
        /// Stored generation
        pub generation: i64,
        /// When it was last refreshed (ISO8601)
        pub updated_at: String,
    }

    /// Response to fetching key backups (restore): all of the user's device
    /// blobs; the native layer tries the entered recovery code against each.
    pub struct ResponseFetchE2EEBackups {
        /// One entry per device that has a backup (possibly empty)
        pub backups: Vec<E2EEBackup>,
    }

    /// Metadata for one device's backup (status card / nag — no key material)
    pub struct E2EEBackupStatus {
        /// Device this backup belongs to
        pub device_id: String,
        /// Stored generation
        pub generation: i64,
        /// When it was last refreshed (ISO8601)
        pub updated_at: String,
        /// Approximate ciphertext size in bytes
        pub size: u64,
    }

    /// Response to fetching backup status (metadata only)
    pub struct ResponseE2EEBackupStatus {
        /// One entry per device that has a backup (possibly empty)
        pub backups: Vec<E2EEBackupStatus>,
    }

    /// An encrypted envelope delivered to a device
    pub struct E2EEMessage {
        /// Envelope id (ULID): delivery ordering + client dedup key
        pub id: String,
        /// Recipient user
        pub recipient_user_id: String,
        /// Recipient device
        pub recipient_device_id: String,
        /// Sender user (server-stamped from the sender's session; treat the
        /// ratchet identity as the real authenticator)
        pub sender_user_id: String,
        /// Sender device
        pub sender_device_id: String,
        /// Protocol version
        pub protocol_version: i32,
        /// Per-session sequence number
        pub sequence: u64,
        /// Opaque ciphertext
        pub ciphertext: String,
    }
);
