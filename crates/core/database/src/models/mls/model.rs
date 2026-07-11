//! MLS delivery-service models (media E2EE, slice 6).
//!
//! The server is a BLIND delivery service: KeyPackages, commits and Welcomes
//! are opaque ciphertext/binary blobs. The only plaintext the server handles
//! is arbitration metadata — `(group_id, epoch)`, channel binding, and the
//! committer-asserted fan-out device lists. The complete accepted
//! server-visible metadata set is documented in the slice-6 plan §5.6 and
//! must not grow silently.
//!
//! ## Canonical payload parity (6.1 ∥ 6.2 contract)
//!
//! The canonical payload builders below are the SERVER-SIDE MIRRORS of the
//! builders the native layer (`e2ee-core/src/canonical.rs`) signs with the
//! vodozemac identity Ed25519 key. They must match byte-for-byte — a
//! divergence breaks KeyPackage publish / join intents loudly. Plan §1.3.

use iso8601_timestamp::Timestamp;

/// Roster ceiling for an E2EE call group (plan A3/Q5: the Welcome
/// envelope-budget ceiling, user-decided 2026-07-09; 6.4 churn measurements
/// may lower it). Enforced inside the commit arbitration — it bounds commit
/// fan-out and Welcome size.
pub const MAX_MLS_GROUP_MEMBERS: usize = 100;

/// Domain-separation context for the MLS leaf-credential binding: the
/// payload signed by the device identity key that binds an MLS signature
/// public key to a slice-5 device identity.
pub const CONTEXT_MLS_CREDENTIAL: &str = "acutest:e2ee:mls-credential:v1";

/// Domain-separation context for a signed join intent (plan §1.4 join step 1)
pub const CONTEXT_MLS_JOIN: &str = "acutest:e2ee:mls-join:v1";

/// Canonical payload covered by an MLS credential binding signature
/// (plan §1.3: newline-delimited, charset-constrained inputs)
pub fn mls_credential_binding_payload(
    user_id: &str,
    device_id: &str,
    mls_signature_key: &str,
    identity_ed25519_key: &str,
) -> String {
    format!("{CONTEXT_MLS_CREDENTIAL}\n{user_id}\n{device_id}\n{mls_signature_key}\n{identity_ed25519_key}")
}

/// Canonical payload covered by a join-intent signature: binds the intent to
/// the joining device, the exact group and a fresh KeyPackage reference
pub fn mls_join_intent_payload(
    user_id: &str,
    device_id: &str,
    group_id: &str,
    key_package_ref: &str,
) -> String {
    format!("{CONTEXT_MLS_JOIN}\n{user_id}\n{device_id}\n{group_id}\n{key_package_ref}")
}

/// A group id is a client-derived 32-byte hash (plan §1.2:
/// `hash(channel_id || call_start_ulid)`), transported as 64 lowercase hex
/// chars. Charset-constrained so it can never break composite ids or
/// canonical payloads (no `:`, no newline).
pub fn is_valid_group_id(group_id: &str) -> bool {
    group_id.len() == 64
        && group_id
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// A KeyPackage reference (OpenMLS KeyPackageRef hash, client-encoded as
/// unpadded standard base64). Charset-constrained: base64 alphabet only, so
/// it can never break composite ids or canonical payloads.
pub fn is_valid_key_package_ref(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 64
        && reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
}

auto_derived!(
    /// A (user, device) pair — the unit of MLS group membership and envelope
    /// fan-out. Frame keys are derived per (user, device); the delivery
    /// service enforces at most one device per user per group (plan §1.5).
    #[derive(Hash)]
    pub struct MlsMemberDevice {
        pub user_id: String,
        pub device_id: String,
    }
);

auto_derived!(
    /// A published MLS KeyPackage awaiting claim (mirrors `e2ee_prekeys`).
    ///
    /// The KeyPackage itself is opaque to the server. The binding signature
    /// is the credential binding (plan §1.3) — an Ed25519 signature by the
    /// device identity key over [`mls_credential_binding_payload`] — verified
    /// at publish exactly like one-time-key publish. Clients re-verify the
    /// credential inside the KeyPackage at Welcome time; the server check is
    /// defense in depth and keeps garbage out of the directory.
    pub struct MlsKeyPackage {
        /// Composite id: `{user_id}:{device_id}:{key_package_ref}`
        #[serde(rename = "_id")]
        pub id: String,
        /// Owning user (always from the authenticated session)
        pub user_id: String,
        /// Owning device
        pub device_id: String,
        /// KeyPackage reference (client-computed OpenMLS KeyPackageRef,
        /// unpadded standard base64)
        pub key_package_ref: String,
        /// Opaque KeyPackage bytes, unpadded standard base64. Never parsed.
        pub key_package: String,
        /// MLS Ed25519 signature PUBLIC key bound to this device, unpadded
        /// standard base64 (constant across a device's packages in v1 —
        /// MLS signature-key rotation is deferred)
        pub mls_signature_key: String,
        /// Ed25519 signature by the device identity key over the canonical
        /// credential binding payload
        pub binding_signature: String,
        /// Whether this is the device's reusable last-resort package —
        /// served (not consumed) at one-time exhaustion. Deliberately
        /// short-lived: reuse weakens Welcome forward secrecy (plan §5.6).
        pub last_resort: bool,
        /// When the crond sweep removes this package
        pub expires_at: Timestamp,
        /// Server-stamped publish time
        pub created_at: Timestamp,
    }
);

impl MlsKeyPackage {
    /// Composite row id for a KeyPackage
    pub fn composite_id(user_id: &str, device_id: &str, key_package_ref: &str) -> String {
        format!("{user_id}:{device_id}:{key_package_ref}")
    }
}

auto_derived!(
    /// A per-call MLS group registered with the delivery service.
    ///
    /// This collection is a documented metadata extension (plan §5.6): the
    /// server learns that a call in `channel_id` has an E2EE group, its
    /// epoch counter, and the (user, device) membership set asserted by
    /// committers — never group secrets or cryptographic roster structure.
    ///
    /// At most ONE open group exists per channel at any time (partial unique
    /// index on `channel_id` where `open` — the create-race arbitration,
    /// plan §1.2/A5). The successor flow (poisoned-epoch recovery, §1.4)
    /// closes the old group and creates the new one in one driver call.
    pub struct MlsGroup {
        /// Client-derived group id (64 lowercase hex chars)
        #[serde(rename = "_id")]
        pub id: String,
        /// Channel whose call this group belongs to — every route authorizes
        /// against this channel with the existing permission machinery
        pub channel_id: String,
        /// Whether this group is the channel's open (live) group. Mirrors
        /// `closed_at == None`; exists because the Mongo partial unique
        /// index needs an equality-testable field.
        pub open: bool,
        /// Creating device (server-stamped from the session)
        pub created_by: MlsMemberDevice,
        /// Server-stamped creation time
        pub created_at: Timestamp,
        /// Highest arbitrated epoch (0 = creation; commits must arrive with
        /// exactly `current_epoch + 1`)
        pub current_epoch: i64,
        /// Committer-asserted (user, device) membership mirror. Used for
        /// commit fan-out, the one-device-per-user rule and envelope
        /// eligibility. AVAILABILITY-TRUST ONLY (plan T-19): a lying
        /// committer can desync targets, never read anything.
        pub members: Vec<MlsMemberDevice>,
        /// When this group was closed (call ended / superseded)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub closed_at: Option<Timestamp>,
        /// Successor group id when closed via the poisoned-epoch flow
        #[serde(skip_serializing_if = "Option::is_none")]
        pub superseded_by: Option<String>,
    }
);

impl MlsGroup {
    /// Whether a (user, device) is currently a member of this group
    pub fn has_member(&self, user_id: &str, device_id: &str) -> bool {
        self.members
            .iter()
            .any(|member| member.user_id == user_id && member.device_id == device_id)
    }

    /// The member entry for a user, if any device of theirs is in the group
    pub fn member_device_of(&self, user_id: &str) -> Option<&MlsMemberDevice> {
        self.members.iter().find(|member| member.user_id == user_id)
    }
}

auto_derived!(
    /// An arbitrated (winning) commit for one epoch of a group.
    ///
    /// The unique composite `_id` IS the epoch arbitration: exactly one
    /// insert per `{group_id}:{epoch}` succeeds; the loser receives the
    /// winning commit ciphertext in the conflict outcome and rebases
    /// (plan §2.2.3).
    pub struct MlsCommit {
        /// Composite id: `{group_id}:{epoch}`
        #[serde(rename = "_id")]
        pub id: String,
        /// Group this commit belongs to
        pub group_id: String,
        /// Epoch this commit establishes (`previous + 1`, never skipped)
        pub epoch: i64,
        /// Committing device — ALWAYS stamped server-side from the
        /// authenticated session (text invariant 5)
        pub committer: MlsMemberDevice,
        /// Opaque commit ciphertext (MLS PrivateMessage), unpadded standard
        /// base64. Never parsed; retained for gap refetch until the group
        /// is swept.
        pub commit: String,
        /// Raw (decoded) ciphertext size in bytes
        pub size: i64,
        /// Committer-asserted devices ADDED by this commit (fan-out +
        /// roster-mirror metadata; availability-trust only, T-19)
        pub added: Vec<MlsMemberDevice>,
        /// Committer-asserted devices REMOVED by this commit
        pub removed: Vec<MlsMemberDevice>,
        /// Server-stamped submission time
        pub created_at: Timestamp,
    }
);

impl MlsCommit {
    /// Composite row id for a commit
    pub fn composite_id(group_id: &str, epoch: i64) -> String {
        format!("{group_id}:{epoch}")
    }
}

auto_derived!(
    /// A stored signed join intent (plan §1.4 join step 1).
    ///
    /// The signature (over [`mls_join_intent_payload`], by the device
    /// identity key) is verified server-side as defense in depth; the REAL
    /// trust decision is the admitting member's client-side re-verification
    /// against its pinned identity for this (user, device). Storage exists
    /// for dedup/rate-limiting of re-broadcasts; admitters act on the
    /// fanned-out event.
    pub struct MlsJoinIntent {
        /// Composite id: `{group_id}:{user_id}:{device_id}`
        #[serde(rename = "_id")]
        pub id: String,
        /// Target group
        pub group_id: String,
        /// Joining user (server-stamped from the session)
        pub user_id: String,
        /// Joining device
        pub device_id: String,
        /// Fresh KeyPackage reference the joiner nominated
        pub key_package_ref: String,
        /// Ed25519 signature by the device identity key over the canonical
        /// join-intent payload
        pub signature: String,
        /// Server-stamped submission time (rate-limit anchor)
        pub created_at: Timestamp,
    }
);

impl MlsJoinIntent {
    /// Composite row id for a join intent
    pub fn composite_id(group_id: &str, user_id: &str, device_id: &str) -> String {
        format!("{group_id}:{user_id}:{device_id}")
    }
}

auto_derived!(
    /// Outcome of a group-create attempt (channel-scoped arbitration §1.2)
    pub enum MlsGroupCreateOutcome {
        /// This creator won: the group is registered and open
        Created,
        /// Another open group already exists for the channel — the caller
        /// falls into the join path for THAT group (the 409 body carries it)
        Conflict {
            /// The channel's existing open group id
            open_group_id: String,
            /// The channel_id the existing open group is bound to — sourced
            /// from the group RECORD, not echoed from the request, so the
            /// client's T-15 guard has an independent DS assertion to compare
            /// its route-truth channel against (plan §1.4 / slice-6.4 audit H2)
            channel_id: String,
        },
    }
);

auto_derived!(
    /// Outcome of a commit submission (epoch arbitration §2.2.3)
    pub enum MlsCommitOutcome {
        /// This committer won epoch N
        Won,
        /// Another commit already won this epoch; the loser rebases onto it
        Lost {
            /// The winning commit (opaque ciphertext — only members can
            /// read it)
            winning: MlsCommit,
        },
    }
);
