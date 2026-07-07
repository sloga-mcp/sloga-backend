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
    }
);

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
