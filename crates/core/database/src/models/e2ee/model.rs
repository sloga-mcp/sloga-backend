use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{events::client::EventV1, Database};

/// Current (and minimum accepted) E2EE protocol version.
///
/// Version 1 = Olm (vodozemac) with classical X25519 handshake. Bumped when a
/// post-quantum capable handshake ships; servers reject anything below the
/// floor rather than silently accommodating it.
pub const E2EE_PROTOCOL_VERSION: i32 = 1;

/// Length of a device id: 128 bits as lowercase hex.
pub const E2EE_DEVICE_ID_LENGTH: usize = 32;

/// Signature scheme note (amends design §9a "signed bundle format"):
///
/// A fetching client receives the identity, the fallback key and AT MOST ONE
/// one-time key — never the full one-time key batch — so a single signature
/// over the whole batch would be unverifiable by recipients. Instead every
/// independently-served unit carries its own Ed25519 signature (Matrix-style):
///
/// - the identity is self-signed (`E2EE_SIGN_CONTEXT_IDENTITY`),
/// - the fallback key is signed (`E2EE_SIGN_CONTEXT_FALLBACK`),
/// - each one-time key is signed (`E2EE_SIGN_CONTEXT_ONE_TIME`).
///
/// All payloads are domain-separated (a fallback key cannot be replayed as a
/// one-time key or vice versa) and carry `protocol_version` and `device_id`
/// INSIDE the signed payload, so the server cannot strip protocol capability
/// or graft keys onto another device. Keys and signatures are unpadded
/// standard base64 (vodozemac's encoding). These canonical payload builders
/// are the single source of truth for what clients must sign.
pub const E2EE_SIGN_CONTEXT_IDENTITY: &str = "acutest:e2ee:identity";
pub const E2EE_SIGN_CONTEXT_FALLBACK: &str = "acutest:e2ee:fallback";
pub const E2EE_SIGN_CONTEXT_ONE_TIME: &str = "acutest:e2ee:one-time";

auto_derived!(
    /// A signed Curve25519 public key (fallback or one-time)
    pub struct E2EESignedKey {
        /// Key id, unique per device (vodozemac key id encoding)
        pub key_id: String,
        /// Curve25519 public key, unpadded standard base64
        pub key: String,
        /// Ed25519 signature by the device identity key over the canonical
        /// payload for this key's context
        pub signature: String,
    }
);

auto_derived!(
    /// E2EE device identity
    ///
    /// One row per (user_id, device_id). This is the complete accepted
    /// server-side metadata set for a device — nothing else about a device
    /// is stored (design invariant: the accepted-metadata set is what is
    /// listed here and nothing more).
    pub struct E2EEIdentity {
        /// Composite id: `{user_id}:{device_id}`
        #[serde(rename = "_id")]
        pub id: String,
        /// User this device belongs to (always taken from the authenticated
        /// session, never from a payload)
        pub user_id: String,
        /// Random 128-bit device id, lowercase hex, generated in the client's
        /// native layer (deliberately NOT a ULID: must not leak creation time)
        pub device_id: String,
        /// Protocol version this device speaks (inside the signed payload)
        pub protocol_version: i32,
        /// Ed25519 (signing) identity key, unpadded standard base64
        pub ed25519_key: String,
        /// Curve25519 (Diffie-Hellman) identity key, unpadded standard base64
        pub curve25519_key: String,
        /// Ed25519 self-signature over the canonical identity payload
        pub signature: String,
        /// Current fallback key (Olm's stand-in for a signed prekey); served
        /// when one-time keys are exhausted so a bundle is always available
        pub fallback_key: E2EESignedKey,
        /// Previous fallback key, retained after rotation so in-flight prekey
        /// messages remain decryptable (rotation itself lands in slice 2)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub previous_fallback_key: Option<E2EESignedKey>,
        /// When this device first published keys
        pub created_at: Timestamp,
        /// Last time this device published keys or proved a device claim
        pub last_seen_at: Timestamp,
        /// Session that most recently published keys or proved possession of
        /// this device's identity key
        pub last_session_id: String,
    }
);

auto_derived!(
    /// A one-time prekey awaiting consumption
    pub struct E2EEOneTimeKey {
        /// Composite id: `{user_id}:{device_id}:{key_id}`
        #[serde(rename = "_id")]
        pub id: String,
        /// User this key belongs to
        pub user_id: String,
        /// Device this key belongs to
        pub device_id: String,
        /// Key id, unique per device
        pub key_id: String,
        /// Curve25519 public key, unpadded standard base64
        pub key: String,
        /// Ed25519 signature by the device identity key
        pub signature: String,
    }
);

auto_derived!(
    /// What an envelope's ciphertext contains — routing-opaque, but clients
    /// dispatch on it and size caps differ per type (media-E2EE plan §2.2.4).
    /// MLS envelope types are only ever minted SERVER-SIDE by the `/mls`
    /// commit fan-out; the client envelope-submission route is olm-only.
    #[derive(Copy, Default)]
    #[serde(rename_all = "snake_case")]
    pub enum E2EEContentType {
        /// An Olm message (text E2EE, the slice-1..5 default)
        #[default]
        Olm,
        /// An MLS commit (opaque MLS PrivateMessage), fanned out per member
        /// device on epoch arbitration
        MlsCommit,
        /// An MLS Welcome, delivered to a newly added device
        MlsWelcome,
        /// An MLS application message (opaque MLS PrivateMessage) — the
        /// media-E2EE §3.4 downgrade ctl-announce, fanned out to the roster
        /// minus the sender. Never advances an epoch; no per-group ordering
        MlsCtl,
    }
);

auto_derived!(
    /// An encrypted envelope awaiting delivery
    ///
    /// Deleted on acknowledged delivery; swept by TTL for dead devices. The
    /// fields below are the complete accepted server-side metadata for an
    /// E2EE message.
    pub struct E2EEEnvelope {
        /// ULID, server-generated: delivery ordering + client dedup key
        #[serde(rename = "_id")]
        pub id: String,
        /// Recipient user
        pub recipient_user_id: String,
        /// Recipient device
        pub recipient_device_id: String,
        /// Sender user — ALWAYS stamped server-side from the authenticated
        /// session (recipients treat the ratchet identity as the real
        /// authenticator; this field is routing metadata)
        pub sender_user_id: String,
        /// Sender device — asserted by the sender, verified to be a
        /// registered device of the authenticated sender
        pub sender_device_id: String,
        /// Protocol version of the payload
        pub protocol_version: i32,
        /// Per-session sequence number assigned by the sender; lets the
        /// recipient detect TTL-created gaps ("messages were lost", not
        /// silence)
        pub sequence: u64,
        /// Opaque ciphertext, unpadded standard base64. The server never
        /// interprets this. Inner structure (e.g. Olm message type) is
        /// client-defined.
        pub ciphertext: String,
        /// Server-stamped submission time
        pub timestamp: Timestamp,
        /// What the ciphertext contains (routing-opaque; clients dispatch on
        /// it, and per-type size caps apply — media-E2EE plan §2.2.4).
        /// Defaults to `olm` so pre-slice-6 rows deserialize unchanged.
        #[serde(default)]
        pub content_type: E2EEContentType,
        /// MLS group this envelope belongs to (mls_* content only) — opaque
        /// to routing; clients order commits per group by `epoch`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub group_id: Option<String>,
        /// MLS epoch this envelope establishes (mls_commit/mls_welcome only)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub epoch: Option<i64>,
    }
);

/// Ciphertext blobs above this size expire 24 hours after upload; smaller
/// blobs follow the 30-day envelope TTL (slice 3.5, blob lifecycle).
pub const E2EE_LARGE_BLOB_SIZE: isize = 10 * 1024 * 1024;

/// Maximum recipient devices per blob (mirrors the envelope fan-out cap)
pub const E2EE_MAX_BLOB_RECIPIENTS: usize = 128;

auto_derived!(
    /// A recipient device of an encrypted attachment blob
    pub struct E2EEBlobRecipient {
        /// Recipient user
        pub user_id: String,
        /// Recipient device
        pub device_id: String,
        /// Whether this device has fetched the blob
        pub fetched: bool,
    }
);

auto_derived!(
    /// An end-to-end encrypted attachment blob in TRANSIT storage
    ///
    /// The server stores an opaque ciphertext (encrypted client-side with a
    /// per-file key that travels INSIDE the message envelope ciphertext) plus
    /// the minimum routing metadata below — mirroring the envelope queue:
    /// blobs are transit storage, not history. Deleted once every declared
    /// recipient device has fetched it, with a size-tiered TTL backstop
    /// (see `E2EE_LARGE_BLOB_SIZE`) swept by crond.
    ///
    /// The recipient set is declared by the uploader at upload time; the
    /// server would learn the same set from the message envelopes anyway, so
    /// this adds nothing to the accepted metadata set.
    pub struct E2EEBlob {
        /// ULID, server-generated — creation time drives the TTL sweep
        #[serde(rename = "_id")]
        pub id: String,
        /// Uploading user (always from the authenticated session)
        pub uploader_user_id: String,
        /// Uploading device (the session's device-bound identity)
        pub uploader_device_id: String,
        /// Ciphertext size in bytes
        pub size: isize,
        /// S3 bucket holding the ciphertext
        pub bucket_id: String,
        /// At-rest encryption nonce from the S3 upload layer
        pub iv: String,
        /// Devices that may fetch this blob, with per-device fetch tracking
        pub recipients: Vec<E2EEBlobRecipient>,
    }
);

impl E2EEBlob {
    /// S3 object path for a blob id (prefixed so blob objects can never
    /// collide with content-hash file paths in the same bucket)
    pub fn s3_path(id: &str) -> String {
        format!("e2ee_{id}")
    }

    /// Whether every declared recipient device has fetched this blob
    pub fn fully_fetched(&self) -> bool {
        self.recipients.iter().all(|recipient| recipient.fetched)
    }

    /// Whether the given (user, device) may fetch this blob
    pub fn authorizes_fetch(&self, user_id: &str, device_id: &str) -> bool {
        self.recipients
            .iter()
            .any(|recipient| recipient.user_id == user_id && recipient.device_id == device_id)
    }
}

/// Maximum decoded ciphertext size of a key-backup blob (design §4.4). Fits
/// a MongoDB document with comfortable headroom; S3 offload is the escape
/// hatch if this is ever raised.
pub const E2EE_MAX_BACKUP_SIZE: usize = 8 * 1024 * 1024;

/// Maximum size of a backup blob header (the plaintext, server-visible AAD).
pub const E2EE_MAX_BACKUP_HEADER_SIZE: usize = 1024;

/// Accepted Argon2id memory-cost bounds (KiB) for a backup header. The
/// restoring client runs Argon2id on these params BEFORE the AEAD check, so
/// an unbounded header is a resource-exhaustion DoS (design §4.1 M1). The
/// server range-checks as defense in depth; the client clamps authoritatively.
pub const E2EE_BACKUP_KDF_M_MIN_KIB: u64 = 8 * 1024; // 8 MiB
pub const E2EE_BACKUP_KDF_M_MAX_KIB: u64 = 512 * 1024; // 512 MiB
/// Accepted Argon2id time-cost (iterations) bounds.
pub const E2EE_BACKUP_KDF_T_MIN: u64 = 1;
pub const E2EE_BACKUP_KDF_T_MAX: u64 = 10;
/// Accepted Argon2id parallelism bounds.
pub const E2EE_BACKUP_KDF_P_MIN: u64 = 1;
pub const E2EE_BACKUP_KDF_P_MAX: u64 = 4;

auto_derived!(
    /// A key-backup blob for one (user, device) — the recovery-code-encrypted
    /// identity + history export (slice 5.5, design §4/§5).
    ///
    /// The server stores an OPAQUE `header` (plaintext AAD: KDF salt/params +
    /// user/device/generation binding) and an OPAQUE `ciphertext`
    /// (XChaCha20-Poly1305 under a key the server never sees). It parses the
    /// header ONLY to range-check KDF params and to cross-check the
    /// header-bound `generation` against the row (`validate_header`); it can
    /// never read the backed-up keys or history. This is the feature's first
    /// deliberate key-egress artifact; its confidentiality rests entirely on
    /// the client-side recovery code.
    pub struct E2EEBackup {
        /// Composite id: `{user_id}:{device_id}`
        #[serde(rename = "_id")]
        pub id: String,
        /// Owning user (always from the authenticated session)
        pub user_id: String,
        /// Device this backup belongs to
        pub device_id: String,
        /// Opaque canonical header bytes (JSON): KDF params, salt, nonce,
        /// user_id, device_id, generation, created_at. AAD of the ciphertext.
        pub header: String,
        /// Opaque ciphertext, standard base64 (≤ `E2EE_MAX_BACKUP_SIZE` decoded)
        pub ciphertext: String,
        /// Monotonic generation — must strictly increase on every upsert;
        /// never resets, even across recovery-code rotation (design §4.5).
        pub generation: i64,
        /// When this device's backup was first created
        pub created_at: Timestamp,
        /// When it was last refreshed
        pub updated_at: Timestamp,
    }
);

impl E2EEBackup {
    /// Composite row id for a backup
    pub fn composite_id(user_id: &str, device_id: &str) -> String {
        format!("{user_id}:{device_id}")
    }

    /// Parse and validate a backup header for a PUT (design §5, M1 + M2).
    ///
    /// Fails closed on: oversized/unparseable header; wrong KDF alg;
    /// out-of-range KDF params (DoS guard); a header `generation`/`user_id`/
    /// `device_id` that disagrees with the request. The header's own bound
    /// copies of user/device/generation must match the authenticated request
    /// so the two deliberately-duplicated copies (header vs column) can never
    /// diverge — a compromised webview cannot poison the column while the
    /// AAD-bound header says otherwise.
    pub fn validate_header(
        header: &str,
        expected_user_id: &str,
        expected_device_id: &str,
        body_generation: i64,
    ) -> Result<()> {
        if header.len() > E2EE_MAX_BACKUP_HEADER_SIZE {
            return Err(create_error!(FailedValidation {
                error: "backup header too large".to_string()
            }));
        }

        let parsed: serde_json::Value = serde_json::from_str(header).map_err(|_| {
            create_error!(FailedValidation {
                error: "backup header is not valid JSON".to_string()
            })
        })?;

        let bad = |what: &str| {
            create_error!(FailedValidation {
                error: format!("backup header: {what}")
            })
        };

        if parsed.get("v").and_then(|v| v.as_u64()) != Some(1) {
            return Err(bad("unsupported version"));
        }

        let kdf = parsed.get("kdf").ok_or_else(|| bad("missing kdf"))?;
        if kdf.get("alg").and_then(|v| v.as_str()) != Some("argon2id") {
            return Err(bad("unsupported kdf alg"));
        }

        let m_kib = kdf.get("m_kib").and_then(|v| v.as_u64());
        let t = kdf.get("t").and_then(|v| v.as_u64());
        let p = kdf.get("p").and_then(|v| v.as_u64());
        match (m_kib, t, p) {
            (Some(m), Some(t), Some(p))
                if (E2EE_BACKUP_KDF_M_MIN_KIB..=E2EE_BACKUP_KDF_M_MAX_KIB).contains(&m)
                    && (E2EE_BACKUP_KDF_T_MIN..=E2EE_BACKUP_KDF_T_MAX).contains(&t)
                    && (E2EE_BACKUP_KDF_P_MIN..=E2EE_BACKUP_KDF_P_MAX).contains(&p) => {}
            _ => return Err(bad("kdf params out of range")),
        }

        // The header's bound copies MUST match the authenticated request
        if parsed.get("user_id").and_then(|v| v.as_str()) != Some(expected_user_id) {
            return Err(bad("user_id mismatch"));
        }
        if parsed.get("device_id").and_then(|v| v.as_str()) != Some(expected_device_id) {
            return Err(bad("device_id mismatch"));
        }

        // M2: header generation must equal the body generation (the two
        // copies can never diverge). serde_json numbers are i64-representable
        // here (client emits a small counter).
        let header_generation = parsed
            .get("generation")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| bad("missing generation"))?;
        if header_generation != body_generation {
            return Err(bad("generation mismatch"));
        }

        Ok(())
    }
}

/// Decode an unpadded standard base64 field of an exact byte length
fn decode_exact(value: &str, length: usize) -> Option<Vec<u8>> {
    STANDARD_NO_PAD
        .decode(value)
        .ok()
        .filter(|bytes| bytes.len() == length)
}

/// Validate a client-supplied device id: exactly 128 bits of lowercase hex
pub fn is_valid_device_id(device_id: &str) -> bool {
    device_id.len() == E2EE_DEVICE_ID_LENGTH
        && device_id
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Canonical signed payload for a Curve25519 key in a given context
fn signed_key_payload(
    context: &str,
    protocol_version: i32,
    device_id: &str,
    key_id: &str,
    key: &str,
) -> String {
    format!("{context}\nprotocol_version:{protocol_version}\ndevice_id:{device_id}\nkey_id:{key_id}\nkey:{key}")
}

/// Verify an Ed25519 signature over a canonical payload
fn verify_signature(verifying_key: &VerifyingKey, payload: &str, signature: &str) -> bool {
    let Some(bytes) = decode_exact(signature, 64) else {
        return false;
    };

    let signature = Signature::from_slice(&bytes).expect("64 bytes checked above");
    verifying_key
        .verify_strict(payload.as_bytes(), &signature)
        .is_ok()
}

impl E2EEIdentity {
    /// Composite row id for a device
    pub fn composite_id(user_id: &str, device_id: &str) -> String {
        format!("{user_id}:{device_id}")
    }

    /// Canonical payload covered by the identity self-signature
    pub fn signed_payload(
        protocol_version: i32,
        device_id: &str,
        ed25519_key: &str,
        curve25519_key: &str,
    ) -> String {
        format!("{E2EE_SIGN_CONTEXT_IDENTITY}\nprotocol_version:{protocol_version}\ndevice_id:{device_id}\ned25519:{ed25519_key}\ncurve25519:{curve25519_key}")
    }

    /// Parse and structurally validate this identity's Ed25519 key
    pub fn verifying_key(&self) -> Option<VerifyingKey> {
        let bytes = decode_exact(&self.ed25519_key, 32)?;
        VerifyingKey::from_bytes(&bytes.try_into().expect("32 bytes checked above")).ok()
    }

    /// Verify the identity self-signature and every signed key attached to
    /// this identity. Fails closed: any structural or signature failure is
    /// a rejection.
    pub fn verify(&self) -> Result<()> {
        let Some(verifying_key) = self.verifying_key() else {
            return Err(create_error!(FailedValidation {
                error: "invalid Ed25519 identity key".to_string()
            }));
        };

        if decode_exact(&self.curve25519_key, 32).is_none() {
            return Err(create_error!(FailedValidation {
                error: "invalid Curve25519 identity key".to_string()
            }));
        }

        let payload = Self::signed_payload(
            self.protocol_version,
            &self.device_id,
            &self.ed25519_key,
            &self.curve25519_key,
        );

        if !verify_signature(&verifying_key, &payload, &self.signature) {
            return Err(create_error!(FailedValidation {
                error: "invalid identity signature".to_string()
            }));
        }

        self.fallback_key.verify(
            &verifying_key,
            E2EE_SIGN_CONTEXT_FALLBACK,
            self.protocol_version,
            &self.device_id,
        )?;

        if let Some(previous) = &self.previous_fallback_key {
            previous.verify(
                &verifying_key,
                E2EE_SIGN_CONTEXT_FALLBACK,
                self.protocol_version,
                &self.device_id,
            )?;
        }

        Ok(())
    }

    /// Verify an Ed25519 signature by this device's identity key over an
    /// arbitrary canonical payload. Used by the MLS delivery service (media
    /// E2EE): credential binding at KeyPackage publish and join-intent
    /// signatures — the canonical builders live in `models/mls/model.rs`.
    pub fn verify_payload(&self, payload: &str, signature: &str) -> bool {
        let Some(verifying_key) = self.verifying_key() else {
            return false;
        };

        verify_signature(&verifying_key, payload, signature)
    }

    /// Verify a signed device-claim challenge: proof of possession of this
    /// device's Ed25519 identity key by a connecting session. The nonce is
    /// server-generated; the session id is bound into the payload so a
    /// captured proof cannot be replayed on another connection.
    pub fn verify_claim(&self, nonce: &str, session_id: &str, signature: &str) -> bool {
        let Some(verifying_key) = self.verifying_key() else {
            return false;
        };

        let payload = Self::claim_payload(&self.device_id, session_id, nonce);
        verify_signature(&verifying_key, &payload, signature)
    }

    /// Canonical payload for a device-claim proof
    pub fn claim_payload(device_id: &str, session_id: &str, nonce: &str) -> String {
        format!("acutest:e2ee:device-claim\ndevice_id:{device_id}\nsession_id:{session_id}\nnonce:{nonce}")
    }

    /// Require that the calling session is bound to THIS device (design §8,
    /// assumption int-H3: web session tokens are refused on E2EE routes).
    ///
    /// A session becomes device-bound in exactly two ways: the MFA-gated
    /// first key publish from that session, or a bonfire device-claim proof
    /// (an Ed25519 signature over a session-bound nonce that only the
    /// holder of the device identity key can produce). Web sessions have no
    /// key material, so they can never satisfy this check — a stolen web
    /// token cannot act as an E2EE device. Defense in depth on top of key
    /// absence; the client's native layer remains the real boundary.
    pub fn assert_bound_session(&self, session_id: &str) -> Result<()> {
        if self.last_session_id != session_id {
            return Err(create_error!(NotAuthenticated));
        }

        Ok(())
    }

    /// Require that the calling session is bound to ANY of the user's
    /// registered devices (see [`Self::assert_bound_session`]). Gates E2EE
    /// routes that act as "an E2EE-capable device of this user" without
    /// naming a specific device (bundle fetch, peer device listing).
    pub async fn require_device_bound_session(
        db: &Database,
        user_id: &str,
        session_id: &str,
    ) -> Result<()> {
        for identity in db.fetch_e2ee_identities(user_id).await? {
            if identity.last_session_id == session_id {
                return Ok(());
            }
        }

        Err(create_error!(NotAuthenticated))
    }

    /// Broadcast a device-list change to the account's other devices (private
    /// topic) and to DM peers (each direct-message channel topic) — device
    /// changes are loud, both add and remove
    pub async fn broadcast_device_change(db: &Database, user_id: &str, event: EventV1) {
        event.clone().private(user_id.to_string()).await;

        if let Ok(channels) = db.find_direct_messages(user_id).await {
            for channel in channels {
                event.clone().p(channel.id().to_string()).await;
            }
        }
    }

    /// Revoke a device: delete its identity, one-time keys and queued
    /// envelopes, then notify. Idempotent; returns whether the device existed.
    ///
    /// Wired into: `DELETE /e2ee/keys/{device}`, session revocation/logout
    /// (`Session::delete`) and the account-deletion cascade (`User::delete`).
    pub async fn revoke_device(db: &Database, user_id: &str, device_id: &str) -> Result<bool> {
        let existed = db.delete_e2ee_device(user_id, device_id).await?;

        // A revoked device's MLS KeyPackages must leave the directory with
        // it — a claim against a dead device would brick the joiner's
        // Welcome (media E2EE, slice 6)
        db.delete_mls_key_packages(user_id, device_id).await?;

        if existed {
            Self::broadcast_device_change(
                db,
                user_id,
                EventV1::E2EEDeviceDelete {
                    user_id: user_id.to_string(),
                    device_id: device_id.to_string(),
                },
            )
            .await;
        }

        Ok(existed)
    }

    /// Revoke every device bound to a given session (session revoked, token
    /// invalidated or user logged out — the device dies with its session)
    pub async fn revoke_devices_for_session(
        db: &Database,
        user_id: &str,
        session_id: &str,
    ) -> Result<()> {
        for identity in db.fetch_e2ee_identities(user_id).await? {
            if identity.last_session_id == session_id {
                Self::revoke_device(db, user_id, &identity.device_id).await?;
            }
        }

        Ok(())
    }

    /// Same-session predecessor sweep (device-lifecycle fixes design §2,
    /// rev 2): one session = one client install = one native store, so any
    /// OTHER identity row still bound to `session_id` is a provably wiped
    /// predecessor — its private keys were destroyed when this install
    /// minted the device it is now proving/publishing. Revoke them: loud
    /// (the existing E2EEDeviceDelete broadcast), best-effort (a failure
    /// leaves the status quo ante — callers never fail the publish/claim
    /// on it), and recurring (runs on first publication AND on every
    /// accepted device claim, so a crash between insert and sweep
    /// self-heals on the next connect).
    ///
    /// Named assumption (reviewer, rev 2): "one session = one install" is
    /// not server-enforced. A COPIED session token that enables E2EE on a
    /// second install revokes the first install's device — loud and
    /// recoverable; token sharing is outside the supported model.
    pub async fn revoke_same_session_predecessors(
        db: &Database,
        user_id: &str,
        session_id: &str,
        keep_device_id: &str,
    ) {
        let Ok(identities) = db.fetch_e2ee_identities(user_id).await else {
            // Best-effort: an unreadable listing = no sweep this cycle
            return;
        };

        for identity in identities {
            if identity.device_id != keep_device_id
                && identity.last_session_id == session_id
            {
                // Best-effort per row; the broadcast inside revoke_device
                // keeps every successful removal loud
                let _ = Self::revoke_device(db, user_id, &identity.device_id).await;
            }
        }
    }
}

impl E2EESignedKey {
    /// Verify this key's signature in the given context
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        context: &str,
        protocol_version: i32,
        device_id: &str,
    ) -> Result<()> {
        if decode_exact(&self.key, 32).is_none() {
            return Err(create_error!(FailedValidation {
                error: "invalid Curve25519 key".to_string()
            }));
        }

        let payload =
            signed_key_payload(context, protocol_version, device_id, &self.key_id, &self.key);

        if !verify_signature(verifying_key, &payload, &self.signature) {
            return Err(create_error!(FailedValidation {
                error: "invalid key signature".to_string()
            }));
        }

        Ok(())
    }
}

impl E2EEOneTimeKey {
    /// Composite row id for a one-time key
    pub fn composite_id(user_id: &str, device_id: &str, key_id: &str) -> String {
        format!("{user_id}:{device_id}:{key_id}")
    }

    /// Verify this key's signature against the owning device's identity
    pub fn verify(&self, identity: &E2EEIdentity) -> Result<()> {
        let Some(verifying_key) = identity.verifying_key() else {
            return Err(create_error!(FailedValidation {
                error: "invalid Ed25519 identity key".to_string()
            }));
        };

        if decode_exact(&self.key, 32).is_none() {
            return Err(create_error!(FailedValidation {
                error: "invalid Curve25519 key".to_string()
            }));
        }

        let payload = signed_key_payload(
            E2EE_SIGN_CONTEXT_ONE_TIME,
            identity.protocol_version,
            &self.device_id,
            &self.key_id,
            &self.key,
        );

        if !verify_signature(&verifying_key, &payload, &self.signature) {
            return Err(create_error!(FailedValidation {
                error: "invalid one-time key signature".to_string()
            }));
        }

        Ok(())
    }
}
