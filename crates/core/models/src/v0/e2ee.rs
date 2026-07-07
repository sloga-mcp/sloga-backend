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
