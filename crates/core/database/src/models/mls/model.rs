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
use revolt_models::v0::HistoryLinkWire;

/// Roster ceiling for an E2EE call group (plan A3/Q5: the Welcome
/// envelope-budget ceiling, user-decided 2026-07-09; 6.4 churn measurements
/// may lower it). Enforced inside the commit arbitration — it bounds commit
/// fan-out and Welcome size.
pub const MAX_MLS_GROUP_MEMBERS: usize = 100;

/// Leaf ceiling for a protected-channel Text group, counting every device
/// (protected channels design §2.5). Derived from the same Welcome budget
/// as [`MAX_MLS_GROUP_MEMBERS`]; raising it is S10.
pub const MAX_MLS_TEXT_GROUP_MEMBERS: usize = 100;

/// The Call rejoin window (design §3.12.2): how old a stored Call rejoin
/// intent may be. Mirrors the route constant
/// `REJOIN_OUTSTANDING_WINDOW_SECONDS` in `delta/src/routes/mls/mod.rs`;
/// the two must stay equal. Also the floor of the Text window
/// ([`mls_text_rejoin_window_seconds`]).
pub const MLS_REJOIN_OUTSTANDING_WINDOW_SECONDS: i64 = 30;

/// The default Text rejoin window (design §6.1 "S2 additions", S2-D28):
/// a Text join or rejoin intent stays outstanding 24 h, in the route and
/// in the Text commit transaction's rule 6. The configured value is
/// `features.protected_channels.text_rejoin_window_secs`, whose default
/// must equal this.
pub const TEXT_REJOIN_OUTSTANDING_WINDOW_SECONDS: i64 = 86400;

/// The minimum text protocol a client must claim on a channel whose stored
/// seat list is v2 (S4, plan appendix (2) "minimum text protocol"); below
/// it, or absent, is `ProtectedClientOutdated { min }`
pub const MIN_TEXT_PROTOCOL_V2: u32 = 2;

/// The most decoded ciphertext bytes one history link may carry (design
/// §2.8, planner ruling #300)
pub const HISTORY_LINK_MAX_CIPHERTEXT: usize = 40960;

/// The most writer users (candidates) one holder epoch keeps (design §2.8,
/// §3.14.7)
pub const HISTORY_LINK_MAX_CANDIDATES: usize = 5;

/// The Text rule-6 window for a configured `text_rejoin_window_secs`,
/// clamped to at least the Call window (30 s)
pub fn mls_text_rejoin_window_seconds(configured: u64) -> i64 {
    i64::try_from(configured)
        .unwrap_or(i64::MAX)
        .max(MLS_REJOIN_OUTSTANDING_WINDOW_SECONDS)
}

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
    /// Text commit, as the commit transaction found it. Stored and served
    /// snake_case.
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

/// Rank of a Remove rule for the advisory `removed_reasons` (design §6.1
/// "S2 additions", RR#S2-4): the highest-ranked admitting rule is stamped,
/// `pending_removal` > `rejoin` > `own_user` > `pending_device` >
/// `revoked` > `idle` > `off_list`. `Unknown` is decode-only and never wins.
pub fn removal_reason_rank(reason: MlsRemovalReason) -> u8 {
    match reason {
        MlsRemovalReason::PendingRemoval => 7,
        MlsRemovalReason::Rejoin => 6,
        MlsRemovalReason::OwnUser => 5,
        MlsRemovalReason::PendingDevice => 4,
        MlsRemovalReason::Revoked => 3,
        MlsRemovalReason::Idle => 2,
        MlsRemovalReason::OffList => 1,
        MlsRemovalReason::Unknown => 0,
    }
}

auto_derived!(
    /// The advisory reason for one device a Text commit removed: the
    /// highest-ranked rule that admitted it ([`removal_reason_rank`]),
    /// stamped inside the Text commit transaction from its own reads
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
        /// Text only: users whose devices must be removed. An Add commit
        /// must remove every member device of every entry (S2
        /// Add-clears-pending); an entry is cleared by the commit that
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
        /// Text only (S4, design §2.5 "S4"): the visibility of epoch 0 (for
        /// a successor, of its bridge transition), from the seat list the
        /// create binds: `Some(true)` for a v2 list with `history:visible`,
        /// else `Some(false)`. `None` only on groups created before S4.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub history_visible_at_create: Option<bool>,
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
        /// the Text commit transaction (B48; S2 replaces the route-time
        /// view, #222). Never read for admission; always empty on Call
        /// commits, so a Call row keeps its earlier shape, and a row
        /// written before the field existed reads as empty.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub removed_reasons: Vec<MlsRemovedReason>,
        /// Text only (S2-D29): the commit's Welcome, unpadded standard
        /// base64, stored on commits with `added`. NEVER part of
        /// `MlsCommitInfo` or the commit fetch; only the Welcome route
        /// serves it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub welcome: Option<String>,
        /// Text only (S4, design §2.5 "S4"): the visibility of the
        /// transition INTO this row's epoch, from the AD the commit route
        /// parses: `Some(true)` for a v2 list with `history:visible`, else
        /// `Some(false)`; `None` on rows written before S4 and on Call
        /// rows. Read by the history-link PUT only. NEVER part of
        /// `MlsCommitInfo` or any envelope.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub history_visible: Option<bool>,
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
        /// Text only (S4): the text protocol the joining client claimed
        /// (CLIENT-CLAIMED, not signed; the minimum text protocol). `None`
        /// on intents stored before S4 and on clients that send none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protocol: Option<u32>,
    }
);

impl MlsJoinIntent {
    /// Composite row id for a join intent
    pub fn composite_id(group_id: &str, user_id: &str, device_id: &str) -> String {
        format!("{group_id}:{user_id}:{device_id}")
    }
}

auto_derived!(
    /// One stored history link (design §2.8, §3.14.5): one row per (holder
    /// group, holder epoch, writer USER). The server never reads the
    /// ciphertext; it checks shapes, stores and serves.
    pub struct MlsHistoryLink {
        /// Composite id: `{group_id}:{epoch}:{writer_user_id}`
        #[serde(rename = "_id")]
        pub id: String,
        /// The holder group G' (64 lowercase hex chars)
        pub group_id: String,
        /// The holder epoch e', `0 ..= current_epoch(G')`
        pub epoch: i64,
        /// G; equal to `group_id` when `epoch >= 1`
        pub prev_group_id: String,
        /// e; equal to `epoch - 1` when `epoch >= 1`
        pub prev_epoch: i64,
        /// b64 of the 24-byte nonce
        pub nonce: String,
        /// b64 of the ciphertext with its tag (decoded `17 ..= 40960` bytes)
        pub ciphertext: String,
        /// The writer user
        pub writer_user_id: String,
        /// The writer device
        pub writer_device_id: String,
        /// b64 of the 64-byte Ed25519 signature (design §3.14.5)
        pub signature: String,
        /// The decoded ciphertext length, for the byte caps
        pub size: i64,
        /// Server-stamped insert time: the candidate order (§3.14.7)
        pub created_at: Timestamp,
    }
);

impl MlsHistoryLink {
    /// Composite row id for a history link
    pub fn composite_id(group_id: &str, epoch: i64, writer_user_id: &str) -> String {
        format!("{group_id}:{epoch}:{writer_user_id}")
    }
}

/// Outcome of `insert_mls_history_link` (design §2.8)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The row was written
    Inserted,
    /// A byte-identical row already exists (every field but `created_at`
    /// and `size` equal); nothing was written
    Identical,
}

/// First line of the history-link signature payload (design 3.14.5)
pub const CONTEXT_HISTORY_LINK_SIG: &str = "sloga-text-history-link-sig-v1";

/// Decoded nonce length of a history link (XChaCha20-Poly1305)
pub const HISTORY_LINK_NONCE_BYTES: usize = 24;

/// Decoded signature length of a history link (Ed25519)
pub const HISTORY_LINK_SIG_BYTES: usize = 64;

/// Smallest decoded ciphertext of a history link: one plaintext byte plus
/// the 16-byte tag
pub const HISTORY_LINK_MIN_CIPHERTEXT: usize = 17;

/// Unpadded b64 length of [`HISTORY_LINK_MAX_CIPHERTEXT`] bytes. The
/// encoded length is checked against it before anything is decoded
/// (design 6.1 "S4")
pub const HISTORY_LINK_MAX_CIPHERTEXT_ENCODED: usize = 54614;

/// Largest epoch a history link may name (the JSON-safe integer range, as
/// `EncryptedPayload::MAX_EPOCH`)
pub const HISTORY_LINK_MAX_EPOCH: i64 = (1 << 53) - 1;

/// Fewest rows one history-link page may be asked for (design 2.8); a
/// smaller `limit` is raised to it
pub const HISTORY_LINK_PAGE_MIN: i64 = 5;

/// Most rows one history-link page may hold (design 2.8); a larger `limit`
/// is lowered to it
pub const HISTORY_LINK_PAGE_MAX: i64 = 200;

/// The fields of one history link, borrowed from the wire or from a row, so
/// the shape check and the signature payload have one implementation
struct HistoryLinkFields<'a> {
    group_id: &'a str,
    epoch: i64,
    prev_group_id: &'a str,
    prev_epoch: i64,
    nonce: &'a str,
    ciphertext: &'a str,
    writer_user_id: &'a str,
    writer_device_id: &'a str,
    signature: &'a str,
}

impl<'a> From<&'a HistoryLinkWire> for HistoryLinkFields<'a> {
    fn from(wire: &'a HistoryLinkWire) -> Self {
        HistoryLinkFields {
            group_id: &wire.group_id,
            epoch: wire.epoch,
            prev_group_id: &wire.prev_group_id,
            prev_epoch: wire.prev_epoch,
            nonce: &wire.nonce,
            ciphertext: &wire.ciphertext,
            writer_user_id: &wire.writer_user_id,
            writer_device_id: &wire.writer_device_id,
            signature: &wire.signature,
        }
    }
}

impl<'a> From<&'a MlsHistoryLink> for HistoryLinkFields<'a> {
    fn from(link: &'a MlsHistoryLink) -> Self {
        HistoryLinkFields {
            group_id: &link.group_id,
            epoch: link.epoch,
            prev_group_id: &link.prev_group_id,
            prev_epoch: link.prev_epoch,
            nonce: &link.nonce,
            ciphertext: &link.ciphertext,
            writer_user_id: &link.writer_user_id,
            writer_device_id: &link.writer_device_id,
            signature: &link.signature,
        }
    }
}

/// Canonical unpadded standard base64 of exactly `length` bytes (design
/// 0.1): the encoded length is checked before decoding, and
/// `STANDARD_NO_PAD` refuses padding, whitespace, the URL-safe alphabet and
/// non-canonical trailing bits
fn history_link_b64_exact(value: &str, length: usize) -> bool {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

    value.len() == (length * 4).div_ceil(3)
        && STANDARD_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == length)
}

impl HistoryLinkFields<'_> {
    /// Design 3.14.5 "Signature": exactly 9 lines, no trailing LF
    fn signature_payload(&self) -> String {
        format!(
            "{CONTEXT_HISTORY_LINK_SIG}\ngroup:{}\nepoch:{}\nprev_group:{}\nprev_epoch:{}\n\
             writer_user:{}\nwriter_device:{}\nnonce:{}\nciphertext:{}",
            self.group_id,
            self.epoch,
            self.prev_group_id,
            self.prev_epoch,
            self.writer_user_id,
            self.writer_device_id,
            self.nonce,
            self.ciphertext
        )
    }

    /// The shape rules; returns the decoded ciphertext length
    fn check(&self) -> revolt_result::Result<i64> {
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

        let invalid = |error: &str| {
            Err(create_error!(FailedValidation {
                error: format!("history_link.{error}")
            }))
        };

        if !is_valid_group_id(self.group_id) {
            return invalid("group_id must be 64 lowercase hex");
        }
        if !(0..=HISTORY_LINK_MAX_EPOCH).contains(&self.epoch) {
            return invalid("epoch out of range");
        }
        if !is_valid_group_id(self.prev_group_id) {
            return invalid("prev_group_id must be 64 lowercase hex");
        }
        if !(0..=HISTORY_LINK_MAX_EPOCH).contains(&self.prev_epoch) {
            return invalid("prev_epoch out of range");
        }
        // Both ids land in the composite `_id` and in the signature payload:
        // their charsets keep `:` and LF out of either
        if !crate::is_valid_ulid_id(self.writer_user_id) {
            return invalid("writer_user_id must be a ULID");
        }
        if !crate::is_valid_device_id(self.writer_device_id) {
            return invalid("writer_device_id must be 32 lowercase hex");
        }
        if !history_link_b64_exact(self.nonce, HISTORY_LINK_NONCE_BYTES) {
            return invalid("nonce must be b64 of 24 bytes");
        }

        // Encoded length first, so an oversized ciphertext is never decoded
        if self.ciphertext.len() > HISTORY_LINK_MAX_CIPHERTEXT_ENCODED {
            return invalid("ciphertext too large");
        }
        let size = match STANDARD_NO_PAD.decode(self.ciphertext) {
            Ok(bytes)
                if (HISTORY_LINK_MIN_CIPHERTEXT..=HISTORY_LINK_MAX_CIPHERTEXT)
                    .contains(&bytes.len()) =>
            {
                bytes.len()
            }
            Ok(_) => return invalid("ciphertext length out of range"),
            Err(_) => return invalid("ciphertext must be b64"),
        };

        if !history_link_b64_exact(self.signature, HISTORY_LINK_SIG_BYTES) {
            return invalid("signature must be b64 of 64 bytes");
        }

        Ok(size as i64)
    }
}

/// The history-link signature payload (design 3.14.5) of a wire link: the
/// bytes the writer device signed. The route verifies the wire signature
/// over it under the writer device's directory identity key (design 6.1
/// "S4"). Only meaningful on a wire that passed
/// [`check_history_link_wire`].
pub fn history_link_signature_payload(wire: &HistoryLinkWire) -> String {
    HistoryLinkFields::from(wire).signature_payload()
}

/// Shape check of a wire history link (design 2.8, 3.14.5, 6.1 "S4"
/// request validation), `FailedValidation` on the first failure: both group
/// ids 64 lowercase hex; both epochs in `0 ..= 2^53 - 1`; `writer_user_id` a
/// ULID and `writer_device_id` 32 lowercase hex; `nonce` b64 of 24 bytes;
/// `ciphertext` b64 of `17 ..= 40960` bytes, its ENCODED length checked
/// before it is decoded; `signature` b64 of 64 bytes (canonical unpadded
/// standard b64 throughout). Returns the decoded ciphertext length, the
/// row's `size`.
///
/// Not checked here (route rules, in the 6.1 order): the body's `group_id`
/// and `epoch` against the path, `prev_group_id`/`prev_epoch` against the
/// holder, the writer against the caller and its session, membership,
/// visibility and the signature itself.
pub fn check_history_link_wire(wire: &HistoryLinkWire) -> revolt_result::Result<i64> {
    HistoryLinkFields::from(wire).check()
}

impl MlsHistoryLink {
    /// The signature payload of a stored link (design 3.14.5), as
    /// [`history_link_signature_payload`]
    pub fn signature_payload(&self) -> String {
        HistoryLinkFields::from(self).signature_payload()
    }

    /// The shape rules of [`check_history_link_wire`] on a row; returns
    /// the decoded ciphertext length
    pub fn check_shape(&self) -> revolt_result::Result<i64> {
        HistoryLinkFields::from(self).check()
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
            history_visible: None,
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
        InsertOutcome, MlsCommit, MlsGroup, MlsHistoryLink, MlsJoinIntent, MlsPendingDeviceRemoval,
        MlsRejoinReadd, MlsRemovalReason, MlsSignerLost, MlsSignerLostCause,
        HISTORY_LINK_MAX_CANDIDATES, HISTORY_LINK_MAX_CIPHERTEXT, MIN_TEXT_PROTOCOL_V2,
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

    /// S4 (design §2.5 "S4"): `history_visible_at_create` and
    /// `history_visible` are absent on an older row, which re-encodes
    /// byte-identical, and stored under their exact keys when set; the
    /// intent's `protocol` likewise
    ///
    /// Control: `skip_serializing_if` dropped from any of the three.
    #[test]
    fn s4_fields_are_absent_when_empty() {
        let group: MlsGroup = s1_round_trip(GROUP_S1);
        assert_eq!(group.history_visible_at_create, None);
        let visible = MlsGroup {
            history_visible_at_create: Some(false),
            ..group
        };
        let document = bson::to_document(&visible).unwrap();
        assert!(!document.get_bool("history_visible_at_create").unwrap());
        assert_eq!(bson::from_document::<MlsGroup>(document).unwrap(), visible);

        let commit: MlsCommit = s1_round_trip(COMMIT_S1);
        assert_eq!(commit.history_visible, None);
        let visible = MlsCommit {
            history_visible: Some(true),
            ..commit
        };
        let document = bson::to_document(&visible).unwrap();
        assert!(document.get_bool("history_visible").unwrap());
        assert_eq!(bson::from_document::<MlsCommit>(document).unwrap(), visible);

        let intent: MlsJoinIntent = s1_round_trip(INTENT_S1);
        assert_eq!(intent.protocol, None);
        let v2 = MlsJoinIntent {
            protocol: Some(2),
            ..intent
        };
        let document = bson::to_document(&v2).unwrap();
        assert!(document.contains_key("protocol"));
        assert_eq!(bson::from_document::<MlsJoinIntent>(document).unwrap(), v2);
    }

    /// Design §2.8: the stored link's keys, its composite `_id`, and a
    /// BSON round trip
    #[test]
    fn history_link_row_shape() {
        let link = MlsHistoryLink {
            id: MlsHistoryLink::composite_id(&"6".repeat(64), 8, "01HZXBBBBBBBBBBBBBBBBBBBBB"),
            group_id: "6".repeat(64),
            epoch: 8,
            prev_group_id: "6".repeat(64),
            prev_epoch: 7,
            nonce: "bm9uY2U".to_string(),
            ciphertext: "Y2lwaGVy".to_string(),
            writer_user_id: "01HZXBBBBBBBBBBBBBBBBBBBBB".to_string(),
            writer_device_id: "f".repeat(32),
            signature: "c2ln".to_string(),
            size: 6,
            created_at: at(),
        };
        assert_eq!(
            link.id,
            format!("{}:8:01HZXBBBBBBBBBBBBBBBBBBBBB", "6".repeat(64))
        );
        let document = bson::to_document(&link).unwrap();
        assert_eq!(
            document.keys().collect::<Vec<_>>(),
            [
                "_id",
                "group_id",
                "epoch",
                "prev_group_id",
                "prev_epoch",
                "nonce",
                "ciphertext",
                "writer_user_id",
                "writer_device_id",
                "signature",
                "size",
                "created_at"
            ]
        );
        assert_eq!(
            bson::from_document::<MlsHistoryLink>(document).unwrap(),
            link
        );
    }

    /// The S4 constants (design §2.8, plan appendix (2))
    #[test]
    fn s4_constants() {
        assert_eq!(MIN_TEXT_PROTOCOL_V2, 2);
        assert_eq!(HISTORY_LINK_MAX_CIPHERTEXT, 40960);
        assert_eq!(HISTORY_LINK_MAX_CANDIDATES, 5);
        assert_ne!(InsertOutcome::Inserted, InsertOutcome::Identical);
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

#[cfg(test)]
mod s2_rule_tests {
    use super::{
        mls_text_rejoin_window_seconds, removal_reason_rank, MlsRemovalReason,
        MLS_REJOIN_OUTSTANDING_WINDOW_SECONDS, TEXT_REJOIN_OUTSTANDING_WINDOW_SECONDS,
    };

    /// Design §6.1 (RR#S2-4): `pending_removal` > `rejoin` > `own_user` >
    /// `pending_device` > `revoked` > `idle` > `off_list`, and `Unknown`
    /// below all of them
    #[test]
    fn removal_reason_rank_is_the_s2_order() {
        let order = [
            MlsRemovalReason::PendingRemoval,
            MlsRemovalReason::Rejoin,
            MlsRemovalReason::OwnUser,
            MlsRemovalReason::PendingDevice,
            MlsRemovalReason::Revoked,
            MlsRemovalReason::Idle,
            MlsRemovalReason::OffList,
            MlsRemovalReason::Unknown,
        ];
        for pair in order.windows(2) {
            assert!(
                removal_reason_rank(pair[0]) > removal_reason_rank(pair[1]),
                "{:?} must outrank {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    /// The Text window is the configured value, never below the Call
    /// window, and its default is the config default
    #[test]
    fn text_rejoin_window_is_clamped_to_the_call_window() {
        assert_eq!(mls_text_rejoin_window_seconds(0), 30);
        assert_eq!(mls_text_rejoin_window_seconds(29), 30);
        assert_eq!(mls_text_rejoin_window_seconds(31), 31);
        assert_eq!(mls_text_rejoin_window_seconds(86400), 86400);
        assert_eq!(mls_text_rejoin_window_seconds(u64::MAX), i64::MAX);
        assert_eq!(MLS_REJOIN_OUTSTANDING_WINDOW_SECONDS, 30);
        assert_eq!(
            revolt_config::ProtectedChannelFeatures::default().text_rejoin_window_secs,
            TEXT_REJOIN_OUTSTANDING_WINDOW_SECONDS as u64
        );
    }
}

#[cfg(test)]
mod history_link_wire_tests {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use iso8601_timestamp::Timestamp;
    use revolt_models::v0::HistoryLinkWire;
    use revolt_result::ErrorType;

    use super::{
        check_history_link_wire, history_link_signature_payload, MlsHistoryLink,
        CONTEXT_HISTORY_LINK_SIG, HISTORY_LINK_MAX_CIPHERTEXT, HISTORY_LINK_MAX_CIPHERTEXT_ENCODED,
    };

    /// The committed design document: every vector below is read from it,
    /// so these tests follow the doc byte for byte
    const DESIGN: &str = include_str!("../../../../../../docs/protected-channels-design.md");

    /// A `tv4:NAME` block (design 5.9 reading rule): its lines joined by LF,
    /// no trailing LF
    fn tv4(name: &str) -> String {
        let marker = format!("<!-- tv4:{name} -->\n```text\n");
        let start = DESIGN.find(&marker).expect("vector present") + marker.len();
        let end = start + DESIGN[start..].find("\n```").expect("vector closed");
        DESIGN[start..end].to_string()
    }

    /// A `NAME_seed_hex = ...` input of `tv:inputs` (design 5.2)
    fn seed(name: &str) -> SigningKey {
        let marker = format!("\n{name}_seed_hex = ");
        let start = DESIGN.find(&marker).expect("seed present") + marker.len();
        let hex = &DESIGN[start..start + 64];
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex");
        }
        SigningKey::from_bytes(&bytes)
    }

    fn wire(name: &str) -> HistoryLinkWire {
        serde_json::from_str(&tv4(name)).expect("wire vector decodes")
    }

    fn refusal(wire: &HistoryLinkWire) -> String {
        match check_history_link_wire(wire) {
            Err(error) => match error.error_type {
                ErrorType::FailedValidation { error } => error,
                other => panic!("expected FailedValidation, got {other:?}"),
            },
            Ok(size) => panic!("expected a refusal, got size {size}"),
        }
    }

    /// Design 5.9: the payload of both vectors is `tv4:*_sig_input` byte
    /// for byte, and the vector signature verifies over it under the
    /// writer's key (member for the link, owner for the bridge)
    #[test]
    fn signature_payload_matches_the_vectors() {
        for (prefix, writer) in [("link", "member"), ("bridge", "owner")] {
            let wire = wire(&format!("{prefix}_wire_json"));
            let payload = history_link_signature_payload(&wire);
            assert_eq!(payload, tv4(&format!("{prefix}_sig_input")), "{prefix}");
            assert_eq!(payload.lines().count(), 9);
            assert!(payload.starts_with(CONTEXT_HISTORY_LINK_SIG));
            assert!(!payload.ends_with('\n'));

            assert_eq!(wire.signature, tv4(&format!("{prefix}_signature")));
            let signature: [u8; 64] = STANDARD_NO_PAD
                .decode(&wire.signature)
                .unwrap()
                .try_into()
                .unwrap();
            seed(writer)
                .verifying_key()
                .verify(payload.as_bytes(), &Signature::from_bytes(&signature))
                .expect("vector signature verifies over the payload");

            // A row built from the wire signs the same bytes
            let row = MlsHistoryLink::from_wire(wire.clone(), 1, Timestamp::now_utc());
            assert_eq!(row.signature_payload(), payload);
        }
    }

    /// Design 5.9: both wire vectors pass the shape check, which returns the
    /// decoded ciphertext length (469 and 470 bytes)
    #[test]
    fn wire_vectors_pass_and_report_their_size() {
        let link = wire("link_wire_json");
        assert_eq!(check_history_link_wire(&link).unwrap(), 469);
        assert_eq!(link.ciphertext, tv4("link_ciphertext_b64"));
        let bridge = wire("bridge_wire_json");
        assert_eq!(check_history_link_wire(&bridge).unwrap(), 470);

        let row = MlsHistoryLink::from_wire(link, 469, Timestamp::now_utc());
        assert_eq!(row.check_shape().unwrap(), 469);
    }

    /// Design 2.8 / 6.1 "S4": every shape rule refuses, the ciphertext
    /// bounds are inclusive, and an oversized ciphertext is refused on its
    /// ENCODED length before any decode
    #[test]
    fn wire_shape_rules_refuse() {
        assert_eq!(
            HISTORY_LINK_MAX_CIPHERTEXT_ENCODED,
            (HISTORY_LINK_MAX_CIPHERTEXT * 4).div_ceil(3)
        );

        let good = wire("link_wire_json");
        let with = |edit: &dyn Fn(&mut HistoryLinkWire)| {
            let mut wire = good.clone();
            edit(&mut wire);
            wire
        };

        let cases: Vec<(HistoryLinkWire, &str)> = vec![
            (
                with(&|w| w.group_id = w.group_id.to_uppercase()),
                "history_link.group_id must be 64 lowercase hex",
            ),
            (
                with(&|w| w.group_id = w.group_id[..63].to_string()),
                "history_link.group_id must be 64 lowercase hex",
            ),
            (with(&|w| w.epoch = -1), "history_link.epoch out of range"),
            (
                with(&|w| w.epoch = 1 << 53),
                "history_link.epoch out of range",
            ),
            (
                with(&|w| w.prev_group_id = format!("{}:", &w.prev_group_id[..63])),
                "history_link.prev_group_id must be 64 lowercase hex",
            ),
            (
                with(&|w| w.prev_epoch = -1),
                "history_link.prev_epoch out of range",
            ),
            (
                with(&|w| w.writer_user_id = "01HZXBBBBBBBBBBBBBBBBBBB:B".to_string()),
                "history_link.writer_user_id must be a ULID",
            ),
            (
                with(&|w| w.writer_user_id = "01hzxbbbbbbbbbbbbbbbbbbbbb".to_string()),
                "history_link.writer_user_id must be a ULID",
            ),
            (
                with(&|w| w.writer_device_id = "FFEEDDCCBBAA99887766554433221100".to_string()),
                "history_link.writer_device_id must be 32 lowercase hex",
            ),
            (
                with(&|w| w.nonce = STANDARD_NO_PAD.encode([7u8; 23])),
                "history_link.nonce must be b64 of 24 bytes",
            ),
            (
                with(&|w| w.nonce = format!("{}==", STANDARD_NO_PAD.encode([7u8; 23]))),
                "history_link.nonce must be b64 of 24 bytes",
            ),
            (
                with(&|w| w.ciphertext = STANDARD_NO_PAD.encode([7u8; 16])),
                "history_link.ciphertext length out of range",
            ),
            (
                with(&|w| w.ciphertext = STANDARD_NO_PAD.encode(vec![7u8; 40961])),
                "history_link.ciphertext too large",
            ),
            (
                // Not b64 at all, but over the encoded cap: refused on its
                // length, never decoded
                with(&|w| w.ciphertext = "!".repeat(HISTORY_LINK_MAX_CIPHERTEXT_ENCODED + 1)),
                "history_link.ciphertext too large",
            ),
            (
                with(&|w| w.ciphertext = format!("{}=", w.ciphertext)),
                "history_link.ciphertext must be b64",
            ),
            (
                with(&|w| w.signature = STANDARD_NO_PAD.encode([7u8; 63])),
                "history_link.signature must be b64 of 64 bytes",
            ),
            (
                with(&|w| w.signature = w.signature.replace('+', "-")),
                "history_link.signature must be b64 of 64 bytes",
            ),
        ];
        for (wire, expected) in cases {
            assert_eq!(refusal(&wire), expected);
        }

        // Both ciphertext bounds are inclusive
        for bytes in [17usize, HISTORY_LINK_MAX_CIPHERTEXT] {
            let wire = with(&|w| w.ciphertext = STANDARD_NO_PAD.encode(vec![7u8; bytes]));
            assert_eq!(check_history_link_wire(&wire).unwrap(), bytes as i64);
        }
        // Epoch 0 (a bridge) and the top of the range pass
        let wire = with(&|w| {
            w.epoch = 0;
            w.prev_epoch = (1 << 53) - 1;
        });
        assert!(check_history_link_wire(&wire).is_ok());
    }
}
