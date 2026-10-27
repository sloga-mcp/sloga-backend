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

/// Leaf ceiling for a protected-channel Text group, counting every device
/// (protected channels design §2.5). Derived from the same Welcome budget
/// as [`MAX_MLS_GROUP_MEMBERS`]; raising it is S10.
pub const MAX_MLS_TEXT_GROUP_MEMBERS: usize = 100;

/// How old a stored rejoin intent may be and still justify a rule-6
/// (rejoin) Remove inside the Text commit transaction (design §3.12.2).
/// Mirrors the route constant `REJOIN_OUTSTANDING_WINDOW_SECONDS` in
/// `delta/src/routes/mls/mod.rs`; the two must stay equal.
pub const MLS_REJOIN_OUTSTANDING_WINDOW_SECONDS: i64 = 30;

/// Enforced per-user device cap for a Text group (design §2.5, W0-fix3):
/// `min(signed-list device_cap, effective entitlement cap)` where `0` means
/// unlimited in EITHER operand, so `min(0, x) = x` and only `min(0, 0) = 0`
/// (unlimited, still bounded by [`MAX_MLS_TEXT_GROUP_MEMBERS`]).
pub fn mls_text_enforced_device_cap(signed: u32, entitlement: u32) -> u32 {
    match (signed, entitlement) {
        (0, other) | (other, 0) => other,
        (signed, entitlement) => signed.min(entitlement),
    }
}

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
    /// What an MLS group secures (protected channels design §2.5).
    /// Serialized as `"Call"` / `"Text"`. A stored group without the field
    /// (written before it existed) is a Call group.
    #[derive(Default, Copy, Hash)]
    pub enum MlsGroupKind {
        /// Per-call media E2EE group (slice 6)
        #[default]
        Call,
        /// Protected text channel group (protected channels S1)
        Text,
    }
);

auto_derived!(
    /// A user whose devices must leave a Text group (server-forced removal
    /// or owner unseat, design §2.5 / §6.3). While any entry exists, Add
    /// commits are refused (`pending_removal`).
    pub struct MlsPendingRemoval {
        /// User whose member devices are to be removed
        pub user_id: String,
        /// When the pending removal was recorded
        pub created_at: Timestamp,
    }
);

auto_derived!(
    /// When a member device of a Text group was last added (design §2.5,
    /// W0-fix5). Rule 6 (rejoin) of the Remove rule only counts an intent
    /// created AFTER `at`; a device with no entry can never be evicted
    /// under rule 6.
    pub struct MlsMemberAdded {
        /// Added user
        pub user_id: String,
        /// Added device
        pub device_id: String,
        /// Epoch the Add established (0 = the creator at group create)
        pub epoch: i64,
        /// Server-stamped time of the Add
        pub at: Timestamp,
    }
);

auto_derived!(
    /// A single member device that must leave a Text group (design §2.5,
    /// S2-D17a). A separate list from `pending_removals`, so an older binary
    /// ignores it instead of reading it as user-wide.
    pub struct MlsPendingDeviceRemoval {
        /// User of the device
        pub user_id: String,
        /// Device to be removed
        pub device_id: String,
        /// When the pending removal was recorded
        pub created_at: Timestamp,
    }
);

auto_derived!(
    /// Why the current seat list's signer device is lost, AS STORED (design
    /// §2.5, #222). Only `device_revoked` is ever stored; the v0
    /// `account_unavailable` is derived at read time from the signer user's
    /// account flags and never written.
    #[derive(Copy, Hash)]
    #[serde(rename_all = "snake_case")]
    pub enum MlsSignerLostCause {
        /// The signer device was revoked
        DeviceRevoked,
    }
);

auto_derived!(
    /// The device that signed the channel's current seat list is lost
    /// (design §2.5, S2-D17d). Copied into every successor created while
    /// set; cleared only by the 4.3 step-7 seat-list write.
    pub struct MlsSignerLost {
        /// Signer user
        pub user_id: String,
        /// Signer device
        pub device_id: String,
        /// Why it is lost
        pub cause: MlsSignerLostCause,
        /// When it was recorded
        pub at: Timestamp,
    }
);

auto_derived!(
    /// A device evicted under rule 6 (rejoin) whose re-Add counts as
    /// recovery (design §2.5, S2-D32). Written by the eviction, consumed by
    /// that device's re-Add.
    pub struct MlsRejoinReadd {
        /// Evicted user
        pub user_id: String,
        /// Evicted device
        pub device_id: String,
        /// When the eviction was recorded
        pub at: Timestamp,
    }
);

auto_derived!(
    /// Which Remove rule (design §3.12.2) admitted a removed device of a
    /// Text commit, as the route found it. Stored and served snake_case.
    /// ADVISORY ONLY: it never changes admission, and receivers decide from
    /// signed material (the server is untrusted)
    #[derive(Copy, Hash)]
    #[serde(rename_all = "snake_case")]
    pub enum MlsRemovalReason {
        /// Rule 2: the committer's own user
        OwnUser,
        /// Rule 3: the device's user is pending removal
        PendingRemoval,
        /// Rule 5: the device's user is off the newest seat list and the
        /// committer is the list signer's device
        OffList,
        /// Rule 4: the device has no registered identity
        Revoked,
        /// Rule 6: the device's own outstanding rejoin intent
        Rejoin,
        /// Rule 3a (S2): the device itself is pending removal
        PendingDevice,
        /// [S2b] Rule 7: the device has been idle past the configured window
        Idle,
        /// A value this build does not know (#219), so a row written by a
        /// newer binary still decodes. Decode-only: never stamped
        #[serde(other)]
        Unknown,
    }
);

auto_derived!(
    /// The advisory reason for one device a Text commit removed: the
    /// STRONGEST rule that admitted it (S1 order: `pending_removal` >
    /// `off_list` > `revoked` > `own_user` > `rejoin`; design §6.1 gives
    /// the S2 order, adopted by the submit route in W2)
    pub struct MlsRemovedReason {
        /// Removed user
        pub user_id: String,
        /// Removed device
        pub device_id: String,
        /// The strongest admitting rule
        pub reason: MlsRemovalReason,
    }
);

auto_derived!(
    /// An MLS group registered with the delivery service: a per-call media
    /// group (`kind: Call`) or a protected text channel group (`kind: Text`).
    ///
    /// This collection is a documented metadata extension (plan §5.6): the
    /// server learns that a call in `channel_id` has an E2EE group, its
    /// epoch counter, and the (user, device) membership set asserted by
    /// committers — never group secrets or cryptographic roster structure.
    ///
    /// At most ONE open group of each kind exists per channel at any time
    /// (partial unique index on `(channel_id, kind)` where `open` — the
    /// create-race arbitration, plan §1.2/A5, design §2.7). The successor
    /// flow (poisoned-epoch recovery, §1.4) closes the old group and
    /// creates the new one in one driver call.
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
        /// Call or Text. Every write path keys open-group lookups by
        /// `(channel_id, kind)`; Call paths never touch Text groups.
        #[serde(default)]
        pub kind: MlsGroupKind,
        /// Text only: the group-id generation (design §3.1). `Some(g)` on
        /// every Text group, `None` on Call groups.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generation: Option<u32>,
        /// Text only: [`crate::SeatList::commit_ad_sha256`] (lowercase hex
        /// SHA-256 of the `commit_ad`) of the channel's newest stored seat
        /// list, the single source of truth for this value.
        /// `Some` on every open Text group; written in the same transaction
        /// as every seat-list row change; the Text commit transaction
        /// filters its group update on it (design §3.12.2).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub seat_list_ad_sha256: Option<String>,
        /// Text only: users whose devices must be removed. Add commits are
        /// refused while non-empty; an entry is cleared by the commit that
        /// leaves the user with no member device.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub pending_removals: Vec<MlsPendingRemoval>,
        /// Text only: when each member device was last added (rule 6).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub member_added: Vec<MlsMemberAdded>,
        /// Text only (S2): single devices that must be removed (rule 3a).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub pending_device_removals: Vec<MlsPendingDeviceRemoval>,
        /// Text only (S2): the current list's signer device is lost.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub signer_lost: Option<MlsSignerLost>,
        /// Text only (S2): rule-6 evictions whose re-Add is recovery.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub rejoin_readd: Vec<MlsRejoinReadd>,
    }
);

impl MlsGroup {
    /// Whether a (user, device) is currently a member of this group
    pub fn has_member(&self, user_id: &str, device_id: &str) -> bool {
        self.members
            .iter()
            .any(|member| member.user_id == user_id && member.device_id == device_id)
    }

    /// The member entry for a user, if any device of theirs is in the group.
    /// Call groups only hold one device per user; on a Text group this is
    /// only the FIRST device — use [`MlsGroup::member_devices_of`] there.
    pub fn member_device_of(&self, user_id: &str) -> Option<&MlsMemberDevice> {
        self.members.iter().find(|member| member.user_id == user_id)
    }

    /// Every member device of a user (Text groups allow several)
    pub fn member_devices_of<'a>(
        &'a self,
        user_id: &'a str,
    ) -> impl Iterator<Item = &'a MlsMemberDevice> + 'a {
        self.members
            .iter()
            .filter(move |member| member.user_id == user_id)
    }

    /// Whether this is a protected-channel Text group
    pub fn is_text(&self) -> bool {
        self.kind == MlsGroupKind::Text
    }

    /// Whether a user has a pending removal on this group
    pub fn has_pending_removal(&self, user_id: &str) -> bool {
        self.pending_removals
            .iter()
            .any(|pending| pending.user_id == user_id)
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
        /// Text only: copies of the stored signed join intents that
        /// justified a rule-6 (rejoin) Remove in this commit (design §2.5,
        /// W0-fix4). Filled by the driver inside the Text commit
        /// transaction, never taken from the submitter; always empty on
        /// Call commits.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub rejoin_intents: Vec<MlsJoinIntent>,
        /// Text only: one advisory reason per removed device, stamped by
        /// the submit route (B48). Never read for admission; always empty
        /// on Call commits, so a Call row keeps its earlier shape, and a row
        /// written before the field existed reads as empty.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub removed_reasons: Vec<MlsRemovedReason>,
        /// Text only (S2-D29): the commit's Welcome, unpadded standard
        /// base64, stored on commits with `added`. NEVER part of
        /// `MlsCommitInfo` or the commit fetch; only the Welcome route
        /// serves it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub welcome: Option<String>,
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
        /// Text join payload only (design §3.13): the signed generation
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generation: Option<u32>,
        /// Text join payload only (design §3.13): the signed issue time (ms)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued_at: Option<i64>,
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

#[cfg(test)]
mod removed_reasons_shape_tests {
    use iso8601_timestamp::Timestamp;

    use super::{MlsCommit, MlsMemberDevice, MlsRemovalReason, MlsRemovedReason};

    fn device(user_id: &str, fill: &str) -> MlsMemberDevice {
        MlsMemberDevice {
            user_id: user_id.to_string(),
            device_id: fill.repeat(32),
        }
    }

    fn call_row() -> MlsCommit {
        let group_id = format!("{}1", "0".repeat(63));
        MlsCommit {
            id: MlsCommit::composite_id(&group_id, 2),
            group_id,
            epoch: 2,
            committer: device("01JA00000000000000000USERA", "a"),
            commit: "Y29tbWl0".to_string(),
            size: 6,
            added: vec![],
            removed: vec![device("01JA00000000000000000USERB", "b")],
            created_at: Timestamp::UNIX_EPOCH,
            rejoin_intents: vec![],
            removed_reasons: vec![],
            welcome: None,
        }
    }

    /// B48: a row without reasons (every Call row) stores no
    /// `removed_reasons` key; a Text row stores them snake_case; a row
    /// written before the field existed reads as empty
    #[test]
    fn removed_reasons_are_stored_only_when_present() {
        let call = call_row();
        let document = bson::to_document(&call).unwrap();
        assert!(!document.contains_key("removed_reasons"));
        assert_eq!(bson::from_document::<MlsCommit>(document).unwrap(), call);

        let text = MlsCommit {
            removed_reasons: vec![MlsRemovedReason {
                user_id: "01JA00000000000000000USERB".to_string(),
                device_id: "b".repeat(32),
                reason: MlsRemovalReason::PendingRemoval,
            }],
            ..call_row()
        };
        let mut document = bson::to_document(&text).unwrap();
        let stored = document
            .get_array("removed_reasons")
            .expect("the reasons are stored");
        assert_eq!(
            stored[0].as_document().unwrap().get_str("reason").unwrap(),
            "pending_removal"
        );
        assert_eq!(
            bson::from_document::<MlsCommit>(document.clone()).unwrap(),
            text
        );

        assert!(document.remove("removed_reasons").is_some());
        assert_eq!(bson::from_document::<MlsCommit>(document).unwrap(), call);
    }
}

#[cfg(test)]
mod s2_shape_tests {
    use iso8601_timestamp::Timestamp;

    use super::{
        MlsCommit, MlsGroup, MlsJoinIntent, MlsPendingDeviceRemoval, MlsRejoinReadd,
        MlsRemovalReason, MlsSignerLost, MlsSignerLostCause,
    };

    /// A Text group exactly as an S1 build (dafb3433) stores it
    const GROUP_S1: &str = r#"{"_id":"0000000000000000000000000000000000000000000000000000000000000001","channel_id":"01JA0000000000000000CHANNEL","open":true,"created_by":{"user_id":"01JA00000000000000000USERA","device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"created_at":"2026-10-04T12:00:00.000Z","current_epoch":7,"members":[{"user_id":"01JA00000000000000000USERA","device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"kind":"Text","generation":2,"seat_list_ad_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","pending_removals":[{"user_id":"01JA00000000000000000USERB","created_at":"2026-10-04T12:00:00.000Z"}],"member_added":[{"user_id":"01JA00000000000000000USERA","device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","epoch":5,"at":"2026-10-04T12:00:00.000Z"}]}"#;

    /// A Text commit exactly as an S1 build (dafb3433) stores it
    const COMMIT_S1: &str = r#"{"_id":"0000000000000000000000000000000000000000000000000000000000000001:8","group_id":"0000000000000000000000000000000000000000000000000000000000000001","epoch":8,"committer":{"user_id":"01JA00000000000000000USERA","device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"commit":"Y29tbWl0","size":6,"added":[{"user_id":"01JA00000000000000000USERC","device_id":"cccccccccccccccccccccccccccccccc"}],"removed":[],"created_at":"2026-10-04T12:00:00.000Z"}"#;

    /// A join intent exactly as an S1 build (dafb3433) stores it
    const INTENT_S1: &str = r#"{"_id":"0000000000000000000000000000000000000000000000000000000000000001:01JA00000000000000000USERC:cccccccccccccccccccccccccccccccc","group_id":"0000000000000000000000000000000000000000000000000000000000000001","user_id":"01JA00000000000000000USERC","device_id":"cccccccccccccccccccccccccccccccc","key_package_ref":"a3ByZWY","signature":"c2ln","created_at":"2026-10-04T12:00:00.000Z"}"#;

    fn at() -> Timestamp {
        serde_json::from_str(r#""2026-10-04T13:00:00.000Z""#).unwrap()
    }

    /// Decodes `s1`, checks it is byte-identical on re-encode (JSON) and
    /// has the same keys as a BSON document, and returns it
    fn s1_round_trip<T>(s1: &str) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let parsed: T = serde_json::from_str(s1).expect("an S1 row decodes");
        assert_eq!(serde_json::to_string(&parsed).unwrap(), s1);

        let expected: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(s1).unwrap();
        let document = bson::to_document(&parsed).unwrap();
        assert_eq!(
            document.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "the stored BSON keys are the S1 keys"
        );
        assert_eq!(bson::from_document::<T>(document).unwrap(), parsed);
        parsed
    }

    /// S2 group fields: an S1 row decodes with them empty and re-encodes
    /// byte-identical; when set they are stored under their exact keys
    #[test]
    fn group_s2_fields_are_absent_when_empty() {
        let group: MlsGroup = s1_round_trip(GROUP_S1);
        assert!(group.pending_device_removals.is_empty());
        assert_eq!(group.signer_lost, None);
        assert!(group.rejoin_readd.is_empty());

        let s2 = MlsGroup {
            pending_device_removals: vec![MlsPendingDeviceRemoval {
                user_id: "01JA00000000000000000USERB".to_string(),
                device_id: "b".repeat(32),
                created_at: at(),
            }],
            signer_lost: Some(MlsSignerLost {
                user_id: "01JA00000000000000000USERA".to_string(),
                device_id: "a".repeat(32),
                cause: MlsSignerLostCause::DeviceRevoked,
                at: at(),
            }),
            rejoin_readd: vec![MlsRejoinReadd {
                user_id: "01JA00000000000000000USERC".to_string(),
                device_id: "c".repeat(32),
                at: at(),
            }],
            ..group.clone()
        };
        let value = serde_json::to_value(&s2).unwrap();
        assert_eq!(
            value["pending_device_removals"][0]["device_id"],
            "b".repeat(32)
        );
        assert_eq!(value["signer_lost"]["cause"], "device_revoked");
        assert_eq!(value["rejoin_readd"][0]["device_id"], "c".repeat(32));
        assert_eq!(serde_json::from_value::<MlsGroup>(value).unwrap(), s2);

        let document = bson::to_document(&s2).unwrap();
        for key in ["pending_device_removals", "signer_lost", "rejoin_readd"] {
            assert!(document.contains_key(key), "{key} is stored when set");
        }
        assert_eq!(bson::from_document::<MlsGroup>(document).unwrap(), s2);
    }

    /// `welcome`: an S1 commit row decodes with none and re-encodes
    /// byte-identical; a stored Welcome round-trips
    #[test]
    fn commit_welcome_is_absent_when_empty() {
        let commit: MlsCommit = s1_round_trip(COMMIT_S1);
        assert_eq!(commit.welcome, None);

        let with = MlsCommit {
            welcome: Some("d2VsY29tZQ".to_string()),
            ..commit
        };
        let document = bson::to_document(&with).unwrap();
        assert_eq!(document.get_str("welcome").unwrap(), "d2VsY29tZQ");
        assert_eq!(bson::from_document::<MlsCommit>(document).unwrap(), with);
    }

    /// Join intent `generation` / `issued_at`: an S1 row decodes with none
    /// and re-encodes byte-identical; set values round-trip
    #[test]
    fn join_intent_text_fields_are_absent_when_empty() {
        let intent: MlsJoinIntent = s1_round_trip(INTENT_S1);
        assert_eq!(intent.generation, None);
        assert_eq!(intent.issued_at, None);

        let text = MlsJoinIntent {
            generation: Some(0),
            issued_at: Some(1_790_812_800_000),
            ..intent
        };
        let value = serde_json::to_value(&text).unwrap();
        assert_eq!(value["generation"], 0);
        assert_eq!(value["issued_at"], 1_790_812_800_000i64);
        let document = bson::to_document(&text).unwrap();
        assert_eq!(
            bson::from_document::<MlsJoinIntent>(document).unwrap(),
            text
        );
    }

    /// Every reason the server can stamp, and its stored value
    const KNOWN_REASONS: [(MlsRemovalReason, &str); 7] = [
        (MlsRemovalReason::OwnUser, "own_user"),
        (MlsRemovalReason::PendingRemoval, "pending_removal"),
        (MlsRemovalReason::OffList, "off_list"),
        (MlsRemovalReason::Revoked, "revoked"),
        (MlsRemovalReason::Rejoin, "rejoin"),
        (MlsRemovalReason::PendingDevice, "pending_device"),
        (MlsRemovalReason::Idle, "idle"),
    ];

    /// #219: every known reason round-trips; a value this build does not
    /// know decodes as `Unknown` instead of failing the commit row
    #[test]
    fn removal_reasons_round_trip_and_unknown_decodes() {
        for (reason, wire) in KNOWN_REASONS {
            assert_eq!(serde_json::to_value(reason).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<MlsRemovalReason>(serde_json::json!(wire)).unwrap(),
                reason
            );
        }

        for unknown in ["user_removed", "PendingDevice", ""] {
            assert_eq!(
                serde_json::from_value::<MlsRemovalReason>(serde_json::json!(unknown)).unwrap(),
                MlsRemovalReason::Unknown,
                "{unknown:?}"
            );
        }

        let with_future = COMMIT_S1.replace(
            r#""removed":[]"#,
            r#""removed":[],"removed_reasons":[{"user_id":"01JA00000000000000000USERB","device_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","reason":"from_the_future"}]"#,
        );
        let commit: MlsCommit = serde_json::from_str(&with_future).unwrap();
        assert_eq!(commit.removed_reasons[0].reason, MlsRemovalReason::Unknown);
        let document = bson::to_document(&commit).unwrap();
        let commit = bson::from_document::<MlsCommit>(document).unwrap();
        assert_eq!(commit.removed_reasons[0].reason, MlsRemovalReason::Unknown);
    }

    /// #222: the stored signer-lost cause is `device_revoked` only
    #[test]
    fn signer_lost_cause_is_snake_case() {
        assert_eq!(
            serde_json::to_value(MlsSignerLostCause::DeviceRevoked).unwrap(),
            "device_revoked"
        );
        assert_eq!(
            serde_json::from_value::<MlsSignerLostCause>(serde_json::json!("device_revoked"))
                .unwrap(),
            MlsSignerLostCause::DeviceRevoked
        );
    }
}
