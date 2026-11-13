//! Protected channels: entitlements, seats and the owner-signed seat list
//! (`docs/protected-channels-design.md` sections 2.2 to 2.5, 4.1, 4.3, 3.12.1).
//! S2 adds the v2 formats (4.1.1 list, 4.10 authority, 4.11 succession, 3.13
//! Text join payload, 3.1.1 group id, 3.12.1 AD v2) and the pure 4.3 "S2
//! additions" rule checks.
//!
//! The server is not the trust anchor for any of this. Members trust the
//! owner-signed seat list under the owner key pinned on their devices. The
//! server keeps the seat registry (the slot cap is enforced here, atomically)
//! and relays the newest signed list. Every seat-list row change also writes
//! `seat_list_ad_sha256` (and, on unseat, `pending_removals`) of the channel's
//! open Text group in the SAME transaction (2.5 (c)), so the Text commit
//! transaction can test the commit's `authenticated_data` against the newest
//! list with a field filter on the group document (3.12.2).
//!
//! Everything a driver decides is decided by the pure planners at the bottom
//! of this file (`plan_seat_list_write`, `prepare_text_group`,
//! `check_text_successor`). Both drivers read their state inside their
//! atomicity primitive, hand it to the planner, and write the plan. That
//! keeps the two drivers from drifting apart on any rule.

use std::collections::BTreeSet;

use base64::Engine as _;
use iso8601_timestamp::{Duration, Timestamp};
use revolt_result::Result;
use sha2::{Digest, Sha256};

use crate::{
    is_valid_group_id, is_valid_key_package_ref, Channel, HistoryWipe, MlsGroup, MlsGroupKind,
    MlsMemberAdded, MlsPendingDeviceRemoval, MlsPendingRemoval, MlsSignerLost, MlsSignerLostCause,
    ProtectedHistory,
};

/// How long a released seat keeps counting against the slot cap (2.3)
pub const SEAT_COOLDOWN_DAYS: i64 = 14;

/// Upper bound of an entitlement's `slot_cap` (2.2: the S1 group leaf cap)
pub const MAX_CHANNEL_SLOT_CAP: u32 = 100;

/// Most seats one signed list may carry (4.1, both sides)
pub const MAX_SEAT_LIST_SEATS: usize = 100;

/// Longest stored handover chain (2.4, 4.3 step 8)
pub const MAX_SEAT_LIST_HANDOVERS: usize = 16;

/// Byte limit of a seat-list body inside the commit AD (3.12.1)
pub const MAX_SEAT_LIST_BODY_LEN: usize = 4096;

/// Byte limit of a handover body inside the commit AD (3.12.1)
pub const MAX_HANDOVER_BODY_LEN: usize = 1024;

/// Byte limit of the whole commit AD: the largest length a 2-byte MLS
/// varint can carry (3.12.1, W0-fix3)
pub const MAX_COMMIT_AD_LEN: usize = 16383;

/// Highest Text group generation (3.1, 6.1): S2 replaces the S1 cap of 63
/// with 65535 on both sides (S2-D33, #204)
pub const MAX_TEXT_GROUP_GENERATION: u32 = 65_535;

/// The v2 formats' name for [`MAX_TEXT_GROUP_GENERATION`] (3.1.1, 3.13):
/// one cap since S2 raised it, so the two can never disagree
pub const MAX_TEXT_GROUP_GENERATION_V2: u32 = MAX_TEXT_GROUP_GENERATION;

/// Byte limit of a channel authority body (4.10)
pub const MAX_CHANNEL_AUTHORITY_LEN: usize = 3072;

/// Byte limit of an owner succession statement (4.11)
pub const MAX_SUCCESSION_BODY_LEN: usize = 1024;

/// `owner_devices` entries of an authority, `1..=5` (4.10)
pub const MAX_AUTHORITY_OWNER_DEVICES: usize = 5;

/// `delegates` entries of an authority, `0..=10` (4.10)
pub const MAX_AUTHORITY_DELEGATES: usize = 10;

/// `successors` entries of an authority, `0..=10` (4.10)
pub const MAX_AUTHORITY_SUCCESSORS: usize = 10;

/// Distinct users among an authority's `successors`, ranks `1..=5` (4.10)
pub const MAX_AUTHORITY_SUCCESSOR_USERS: usize = 5;

/// `2^53 - 1`: the bound on every canonical integer that must survive JSON (0.2)
pub const MAX_CANONICAL_INT: i64 = 9_007_199_254_740_991;

/// Seat-list body context line (0.4, WIRE FORMAT, never rename)
pub const CONTEXT_SEAT_LIST: &str = "sloga-seat-list-v1";

/// Owner handover statement context line (0.4, WIRE FORMAT, never rename)
pub const CONTEXT_HANDOVER: &str = "sloga-owner-handover-v1";

/// Commit `authenticated_data` context field (3.12.1, WIRE FORMAT, never rename)
pub const CONTEXT_COMMIT_AD: &str = "sloga-text-commit-ad-v1";

/// Seat-list body v2 context line (0.4, 4.1.1, WIRE FORMAT, never rename)
pub const CONTEXT_SEAT_LIST_V2: &str = "sloga-seat-list-v2";

/// Text group id v2 derivation context (0.4, 3.1.1, WIRE FORMAT, never rename)
pub const CONTEXT_TEXT_GROUP_V2: &str = "sloga-text-group-v2";

/// Channel authority context line (0.4, 4.10, WIRE FORMAT, never rename)
pub const CONTEXT_CHANNEL_AUTHORITY: &str = "sloga-channel-authority-v1";

/// Commit AD v2 context field (0.4, 3.12.1, WIRE FORMAT, never rename)
pub const CONTEXT_COMMIT_AD_V2: &str = "sloga-text-commit-ad-v2";

/// Text join payload context line (0.4, 3.13, WIRE FORMAT, never rename)
pub const CONTEXT_TEXT_JOIN: &str = "sloga-text-join-v1";

/// Owner succession statement context line (0.4, 4.11, WIRE FORMAT, never
/// rename)
pub const CONTEXT_OWNER_SUCCESSION: &str = "sloga-owner-succession-v1";

/// `ProtectedChannelChanged.scope` item: the seat list or seats changed (7.5)
pub const PROTECTED_SCOPE_SEATS: &str = "seats";

/// `ProtectedChannelChanged.scope` item: the open Text group changed (7.5)
pub const PROTECTED_SCOPE_TEXT_GROUP: &str = "text_group";

/// `ProtectedChannelChanged.scope` item: a history link was contested
/// (7.5 "S4", fix F9)
pub const PROTECTED_SCOPE_HISTORY: &str = "history";

/// Length of an Ed25519 signature in unpadded b64 (0.1)
const SIGNATURE_B64_LEN: usize = 86;

/// Length of an Ed25519 public key in unpadded b64 (0.1)
const IDENTITY_KEY_B64_LEN: usize = 43;

auto_derived!(
    /// Where a channel entitlement came from (2.2). S1 mints `AdminGrant`
    /// only; the others are reserved for S5 so their rows need no migration.
    pub enum ChannelEntitlementSource {
        AdminGrant,
        Prot,
        Crowdfund,
    }

    /// Lifecycle state of a channel entitlement (2.2). S1 uses `Active`
    /// only; the others are reserved for S5.
    pub enum ChannelEntitlementState {
        Active,
        Grace,
        Frozen,
        Deleted,
    }

    /// The admin-granted right to protect one channel (2.2,
    /// `channel_entitlements`; unique index on `channel_id`)
    pub struct ChannelEntitlement {
        /// Unique id (ULID)
        #[serde(rename = "_id")]
        pub id: String,
        /// Channel this entitlement belongs to (unique)
        pub channel_id: String,
        /// Server the channel belongs to
        pub server_id: String,
        /// How the entitlement was obtained
        pub source: ChannelEntitlementSource,
        /// Most seats in use (active + cooling) at once, `1..=100`
        pub slot_cap: u32,
        /// Per-user device cap; `None` = the configured default, `0` = unlimited
        /// (still bounded by the 100-leaf cap)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub device_cap: Option<u32>,
        /// Lifecycle state
        pub state: ChannelEntitlementState,
        /// Privileged user that granted it
        pub granted_by: String,
        /// When it was first granted
        pub created_at: Timestamp,
    }

    /// One user's seat in one protected channel (2.3, `channel_seats`)
    pub struct ChannelSeat {
        /// `{channel_id}:{user_id}`
        #[serde(rename = "_id")]
        pub id: String,
        /// Channel id (indexed)
        pub channel_id: String,
        /// User id (indexed)
        pub user_id: String,
        /// Last time the seat became active
        pub seated_at: Timestamp,
        /// Set when the seat is released
        #[serde(skip_serializing_if = "Option::is_none")]
        pub released_at: Option<Timestamp>,
        /// `released_at + 14 days`; the seat counts against the cap until then
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cooldown_until: Option<Timestamp>,
        /// S2: why the seat was last released (2.3)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub release_cause: Option<SeatReleaseCause>,
        /// S2: when the user's first device was added to the Text group (2.3).
        /// A re-seat while the seat is still cooling keeps it, or sets it to
        /// `released_at` when it was `None` (`reactivate`, #233)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys_received_at: Option<Timestamp>,
    }

    /// Why a seat was released (2.3, S2). Stored snake_case.
    #[derive(Copy, Hash)]
    #[serde(rename_all = "snake_case")]
    pub enum SeatReleaseCause {
        /// The owner's seat list unseated the user
        OwnerUnseat,
        /// A server-forced path (kick, ban, leave, account deletion)
        ServerRemoval,
        /// The reconciler found the user lost access to the channel
        AccessLost,
        /// Released before any of the user's devices received the keys
        DeviceNeverJoined,
    }

    /// An owner handover statement and its signature (2.4, 4.6)
    pub struct SignedHandover {
        /// Exact canonical handover body (4.6)
        pub body: String,
        /// b64 Ed25519 signature by the `from` device
        pub signature: String,
    }

    /// A channel authority and its signature (2.4, 4.10, S2)
    pub struct SignedAuthority {
        /// Exact canonical authority body (4.10)
        pub body: String,
        /// b64 Ed25519 signature over `body`
        pub signature: String,
    }

    /// The channel's newest owner-signed seat list (2.4,
    /// `channel_seat_lists`; newest only, `_id = channel_id`)
    pub struct SeatList {
        /// Channel id
        #[serde(rename = "_id")]
        pub id: String,
        /// The body's version, `>= 1`
        pub version: i64,
        /// Exact canonical body (4.1), byte-for-byte as signed
        pub body: String,
        /// Equals the body's `signer_user_id`
        pub signer_user_id: String,
        /// Equals the body's `signer_device_id`
        pub signer_device_id: String,
        /// b64 Ed25519 signature over `body`
        pub signature: String,
        /// Append-only owner handover chain, at most 16 entries
        #[serde(default)]
        pub handovers: Vec<SignedHandover>,
        /// When this row was last written
        pub updated_at: Timestamp,
        /// S2: the channel authority a v2 body names (2.4); never on a v1 row
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authority: Option<SignedAuthority>,
    }
);

/// Pinned alias (W1 lane contract) for the doc's `ChannelEntitlementState`
pub type EntitlementState = ChannelEntitlementState;

/// Pinned alias (W1 lane contract) for the doc's `ChannelEntitlementSource`
pub type EntitlementSource = ChannelEntitlementSource;

/// A seat list as submitted to protect or `PUT .../seats` (the database-side
/// shape of the route's `DataSeatList`, 7.2). Signature and authorization
/// checks (4.3 steps 2, 3, 5, 6, 8 signature and key checks) are the
/// route's; the driver re-parses the body itself so the stored version,
/// signer and seats can never disagree with the signed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatListSubmission {
    /// Exact canonical body (4.1)
    pub body: String,
    /// b64 Ed25519 signature over `body`
    pub signature: String,
    /// Must equal the body's `signer_device_id`
    pub signer_device_id: String,
    /// Handover statement to append (already verified by the route, 4.3 step 8)
    pub handover: Option<SignedHandover>,
    /// S2: the channel authority of a v2 list (4.3 step 3b)
    pub authority: Option<SignedAuthority>,
}

/// What a protect or seat PUT did
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatListWriteOutcome {
    /// The stored row after the write
    pub list: SeatList,
    /// A byte-identical re-PUT of the stored row: nothing was written (4.3 step 4)
    pub unchanged: bool,
    /// Users whose seat became active (sorted)
    pub claimed: Vec<String>,
    /// Users whose seat was released, cooldown started (sorted)
    pub released: Vec<String>,
    /// Users added to the open Text group's `pending_removals` (sorted)
    pub pending_removals_added: Vec<String>,
    /// S2: the write cleared the open Text group's `signer_lost` (4.3 step 7)
    pub signer_lost_cleared: bool,
}

/// The seat list together with the channel's open Text group, read in ONE
/// snapshot (7.2 `GET .../seats`, W0-fix4)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatListSnapshot {
    /// Newest stored seat list (`None`: the channel is not protected)
    pub list: Option<SeatList>,
    /// The channel's open Text group, if any (`as_of_epoch`, `as_of_group_id`)
    pub text_group: Option<MlsGroup>,
}

fn invalid(error: &str) -> revolt_result::Error {
    create_error!(FailedValidation {
        error: error.to_string()
    })
}

impl ChannelEntitlement {
    /// Whether seats may be claimed under it (S1: `Active` only)
    pub fn is_active(&self) -> bool {
        self.state == ChannelEntitlementState::Active
    }
}

impl ChannelSeat {
    /// `{channel_id}:{user_id}`
    pub fn composite_id(channel_id: &str, user_id: &str) -> String {
        format!("{channel_id}:{user_id}")
    }

    /// A seat is active when it has not been released (2.3)
    pub fn is_active(&self) -> bool {
        self.released_at.is_none()
    }

    /// A released seat is cooling while `now < cooldown_until` (2.3)
    pub fn is_cooling(&self, now: Timestamp) -> bool {
        self.released_at.is_some() && self.cooldown_until.is_some_and(|until| now < until)
    }

    /// Seats used = active + cooling (2.3)
    pub fn counts_against_cap(&self, now: Timestamp) -> bool {
        self.is_active() || self.is_cooling(now)
    }

    /// Whether the user's keys count as received for the 2.3 no-cooldown
    /// rule: `keys_received_at` is set, or (a pre-S2 seat, or a commit that
    /// has not stamped it) `in_text_group`, the user holds or per
    /// `member_added` ever held a device in one of the channel's Text groups
    /// (`text_group_user_ids`)
    pub fn keys_received(&self, in_text_group: bool) -> bool {
        self.keys_received_at.is_some() || in_text_group
    }

    /// Release this seat at `now` for `cause` (2.3). A seat whose user never
    /// received the keys (`keys_received`) frees at once (S2-D21): the cause
    /// becomes `DeviceNeverJoined` and no cooldown starts. Otherwise the
    /// 14-day cooldown starts, whatever the cause (O-4).
    pub fn release(
        &mut self,
        now: Timestamp,
        cause: SeatReleaseCause,
        in_text_group: bool,
    ) -> Result<()> {
        let (cause, cooldown_until) =
            seat_release_terms(self.keys_received(in_text_group), cause, now)?;
        self.released_at = Some(now);
        self.cooldown_until = cooldown_until;
        self.release_cause = Some(cause);
        Ok(())
    }

    /// Make this seat active again at `now`. A re-seat overwrites the last
    /// release's cause (2.3): the audit log is the history.
    ///
    /// The keys stamp depends on the seat (S2-W1 wave audit F-1). A seat
    /// still cooling at `now` was released with the keys received (only
    /// that release cools) and comes back on the slot it already used (the
    /// planner counts no new one), so it stays received: the stamp is kept,
    /// or set to the release time when the release cooled on the
    /// `text_group_user_ids` fallback alone, which a later Remove commit can
    /// empty. Its next release cools again; clearing here would let one slot
    /// rotate among any number of users, each unseat freeing it at once. A
    /// seat whose release did not cool, or whose cooldown has ended, is a new
    /// slot use and starts unstamped.
    pub fn reactivate(&mut self, now: Timestamp) {
        self.keys_received_at = if self.is_cooling(now) {
            self.keys_received_at.or(self.released_at)
        } else {
            None
        };
        self.seated_at = now;
        self.released_at = None;
        self.cooldown_until = None;
        self.release_cause = None;
    }
}

/// The stored `(release_cause, cooldown_until)` of a release at `now` (2.3):
/// `cause` and `now + 14 days` once the keys were received, else
/// `DeviceNeverJoined` and no cooldown (S2-D21). `ChannelSeat::release` and
/// the Mongo filtered releases both take it from here.
pub fn seat_release_terms(
    keys_received: bool,
    cause: SeatReleaseCause,
    now: Timestamp,
) -> Result<(SeatReleaseCause, Option<Timestamp>)> {
    if keys_received {
        Ok((cause, Some(seat_cooldown_until(now)?)))
    } else {
        Ok((SeatReleaseCause::DeviceNeverJoined, None))
    }
}

/// The users that hold, or per `member_added` ever held, a device in any
/// Text group (open or closed) of `channel_id`: the 2.3 pre-S2 fallback of
/// `ChannelSeat::keys_received`. Closed generations count so a user who has
/// not rejoined a successor yet still cools (the fail-safe direction).
pub fn text_group_user_ids<'a>(
    groups: impl IntoIterator<Item = &'a MlsGroup>,
    channel_id: &str,
) -> BTreeSet<String> {
    groups
        .into_iter()
        .filter(|group| group.channel_id == channel_id && group.kind == MlsGroupKind::Text)
        .flat_map(|group| {
            group
                .members
                .iter()
                .map(|member| member.user_id.clone())
                .chain(group.member_added.iter().map(|added| added.user_id.clone()))
        })
        .collect()
}

/// What a release primitive does to the channel's open Text group for the
/// user it released (2.5 S2-D15, 6.3)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseGroupEffect {
    /// The user has no member device, or the group already carries the
    /// entry (or `signer_lost`)
    Nothing,
    /// Append this user-level pending removal
    PendingRemoval(MlsPendingRemoval),
    /// The user signed the current list: set `signer_lost` (never an entry)
    SignerLost(MlsSignerLost),
}

/// 2.5 "Release primitives never queue the signer" (S2-D15), the user-level
/// half shared by the forced release and `release_channel_seat`: a released
/// user with a member device in the open group gets one pending removal,
/// unless the user signed the stored list (`signer`, its user and device),
/// whose entry would wedge every send and Add (rule 1 lets the signer device
/// go only in the rejoin case). That group gets `signer_lost` instead, naming
/// the list's signer device. The stored cause is `DeviceRevoked`, the only
/// one S2a stores (the doc's user-level cause is [S2b]); the 4.3 step-7
/// recovery clears it exactly as for a revoked device.
pub fn plan_release_group_effect(
    group: &MlsGroup,
    user_id: &str,
    signer: Option<(&str, &str)>,
    now: Timestamp,
) -> ReleaseGroupEffect {
    if !group.members.iter().any(|member| member.user_id == user_id) {
        return ReleaseGroupEffect::Nothing;
    }
    match signer {
        Some((signer_user, signer_device)) if signer_user == user_id => {
            if group.signer_lost.is_some() {
                ReleaseGroupEffect::Nothing
            } else {
                ReleaseGroupEffect::SignerLost(MlsSignerLost {
                    user_id: signer_user.to_string(),
                    device_id: signer_device.to_string(),
                    cause: MlsSignerLostCause::DeviceRevoked,
                    at: now,
                })
            }
        }
        _ => {
            if group
                .pending_removals
                .iter()
                .any(|pending| pending.user_id == user_id)
            {
                ReleaseGroupEffect::Nothing
            } else {
                ReleaseGroupEffect::PendingRemoval(MlsPendingRemoval {
                    user_id: user_id.to_string(),
                    created_at: now,
                })
            }
        }
    }
}

/// What `add_pending_device_removal` does to one open Text group (6.3
/// "Device revocation", S2-D15, #222). `signer` is the stored list's signer
/// (user, device), read in the same claimed transaction. The device that
/// signed the current list sets `signer_lost` (if not already set) whether
/// or not it still holds a leaf, never an entry; any other device that holds
/// a leaf gets one `pending_device_removals` entry (idempotent).
pub fn plan_device_removal_effect(
    group: &MlsGroup,
    user_id: &str,
    device_id: &str,
    signer: Option<(&str, &str)>,
    now: Timestamp,
) -> Option<DeviceRemovalEffect> {
    if signer == Some((user_id, device_id)) {
        return group.signer_lost.is_none().then(|| {
            DeviceRemovalEffect::SignerLost(MlsSignerLost {
                user_id: user_id.to_string(),
                device_id: device_id.to_string(),
                cause: MlsSignerLostCause::DeviceRevoked,
                at: now,
            })
        });
    }
    let already = group
        .pending_device_removals
        .iter()
        .any(|pending| pending.user_id == user_id && pending.device_id == device_id);
    (group.has_member(user_id, device_id) && !already).then(|| {
        DeviceRemovalEffect::Pending(MlsPendingDeviceRemoval {
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            created_at: now,
        })
    })
}

/// A write `plan_device_removal_effect` asks for
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceRemovalEffect {
    /// Append to `pending_device_removals`
    Pending(MlsPendingDeviceRemoval),
    /// Set `signer_lost`
    SignerLost(MlsSignerLost),
}

/// Log and report (ids only) a `signer_lost` a release or revocation set
/// (2.5, S2-D15)
pub fn report_signer_lost(path: &str, channel_id: &str, lost: &MlsSignerLost) {
    let message = format!(
        "protected channel signer lost: path={path} channel={channel_id} user={} device={}",
        lost.user_id, lost.device_id
    );
    log::warn!("{message}");
    revolt_config::capture_message(&message, revolt_config::Level::Warning);
}

/// `now + SEAT_COOLDOWN_DAYS`
pub fn seat_cooldown_until(now: Timestamp) -> Result<Timestamp> {
    now.checked_add(Duration::days(SEAT_COOLDOWN_DAYS))
        .ok_or_else(|| create_error!(InternalError))
}

/// Seats used (active + cooling) among `seats` at `now` (2.3)
pub fn channel_seats_used(seats: &[ChannelSeat], now: Timestamp) -> usize {
    seats
        .iter()
        .filter(|seat| seat.counts_against_cap(now))
        .count()
}

// ---------------------------------------------------------------------------
// Canonical seat-list body (4.1)
// ---------------------------------------------------------------------------

/// A parsed seat-list body (4.1, and 4.1.1 when `v2` is set)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatListBody {
    pub channel_id: String,
    pub version: i64,
    pub device_cap: u32,
    pub issued_at: i64,
    pub signer_user_id: String,
    pub signer_device_id: String,
    /// Sorted ascending by byte value, unique, contains the signer
    pub seats: Vec<String>,
    /// S2: the five v2 lines; `None` is a v1 body (4.1.1)
    pub v2: Option<SeatListV2Lines>,
}

/// The `history:` line of a v2 seat list (4.1.1; S4's, carried in S2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatListHistory {
    Visible,
    Hidden,
}

/// The `pre_history:` line of a v2 seat list (4.1.1; S4's, carried in S2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatListPreHistory {
    Kept,
    Wiped,
}

/// Lines 10 to 14 of a v2 seat-list body (4.1.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatListV2Lines {
    /// Lowercase hex SHA-256 of the channel authority body (4.10); `None`
    /// for an empty `authority:` line
    pub authority_sha256: Option<String>,
    pub history: SeatListHistory,
    /// A message id (ULID); `None` for an empty line
    pub history_boundary: Option<String>,
    pub pre_history: SeatListPreHistory,
    /// 64 lowercase hex (32 bytes), the 3.1.1 group id salt
    pub group_salt: String,
}

impl SeatListHistory {
    fn as_str(self) -> &'static str {
        match self {
            SeatListHistory::Visible => "visible",
            SeatListHistory::Hidden => "hidden",
        }
    }
}

impl SeatListPreHistory {
    fn as_str(self) -> &'static str {
        match self {
            SeatListPreHistory::Kept => "kept",
            SeatListPreHistory::Wiped => "wiped",
        }
    }
}

/// ULID, Crockford base32, uppercase, 26 chars (0.1)
pub fn is_valid_ulid_id(value: &str) -> bool {
    value.len() == 26
        && value.bytes().all(|byte| {
            matches!(byte, b'0'..=b'9' | b'A'..=b'H' | b'J' | b'K' | b'M' | b'N' | b'P'..=b'T' | b'V'..=b'Z')
        })
}

/// Crockford base32, the ULID alphabet (no `I`, `L`, `O`, `U`)
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The 48-bit millisecond time of a ULID (4.1.1 "S4", fix F15, #299): the
/// first 10 characters of an UPPERCASE canonical Crockford ULID whose first
/// character is `0` to `7`, so the time fits 48 bits. Any other spelling
/// (lowercase, `I`, `L`, `O`, `U`, a first character above `7`, another
/// length) is malformed, `FailedValidation` (vector 5.9 `boundary_ulid_time`).
pub fn ulid_time(id: &str) -> Result<u64> {
    if !is_valid_ulid_id(id) || !matches!(id.as_bytes()[0], b'0'..=b'7') {
        return Err(invalid("malformed ULID"));
    }
    let mut time = 0u64;
    for byte in &id.as_bytes()[..10] {
        let digit = CROCKFORD_ALPHABET
            .iter()
            .position(|letter| letter == byte)
            .ok_or_else(|| invalid("malformed ULID"))?;
        time = (time << 5) | digit as u64;
    }
    Ok(time)
}

/// Device id: 32 lowercase hex chars (0.1)
pub fn is_valid_device_id_hex(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Canonical ASCII decimal: digits only, no sign, no leading zeros (0.2)
fn parse_canonical_decimal(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if value.len() > 1 && value.starts_with('0') {
        return None;
    }
    value.parse::<u64>().ok()
}

fn labeled<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    line.strip_prefix(label)?.strip_prefix(':')
}

/// `len` lowercase hex chars
fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Lowercase hex SHA-256 of `bytes`
fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

/// Whether a canonical body's first line is `context` (format dispatch only;
/// the strict parser of that format decides validity)
fn has_context(body: &str, context: &str) -> bool {
    body.split('\n').next() == Some(context)
}

impl SeatListBody {
    /// Strict, VERSION-DISPATCHING parse: the context line picks the format
    /// (4.1 or 4.1.1) and that format's parser is strict. Every reader of a
    /// stored body uses this, so a v2 row keeps working wherever only the
    /// shared lines (seats, `device_cap`, signer) are read. Which format a
    /// WRITE may carry is 4.3 step 1 (`check_seat_list_format`).
    pub fn parse(body: &str) -> Result<SeatListBody> {
        if has_context(body, CONTEXT_SEAT_LIST_V2) {
            SeatListBody::parse_v2(body)
        } else {
            SeatListBody::parse_v1(body)
        }
    }

    /// Strict v1 parse (4.1, including the W0-fix3 bounds). Refuses anything
    /// that is not the one valid byte string for its content: nothing is
    /// trimmed, normalized or re-sorted.
    pub fn parse_v1(body: &str) -> Result<SeatListBody> {
        let lines = seat_list_lines(body, 9)?;
        if lines[0] != CONTEXT_SEAT_LIST || lines[1] != "v:1" {
            return Err(invalid("seat list context or format version"));
        }
        parse_seat_list_shared(&lines)
    }

    /// Strict v2 parse (4.1.1): the nine v1 lines under the v2 context and
    /// `v:2`, then `authority`, `history`, `history_boundary`,
    /// `pre_history` and `group_salt`. `wiped` with an empty boundary is
    /// malformed (4.1.1, 4.4.1 rule 3), and so is a boundary that is not an
    /// uppercase canonical ULID with a first character `0` to `7`, or whose
    /// `ulid_time` is later than the list's own `issued_at` (4.1.1 "S4", fix
    /// F15, S4-PA-1; 4.3 "S4" step 1). A boundary and `wiped` are otherwise
    /// format-valid; whether a write may carry them is 4.3 step 4c.
    pub fn parse_v2(body: &str) -> Result<SeatListBody> {
        let lines = seat_list_lines(body, 14)?;
        if lines[0] != CONTEXT_SEAT_LIST_V2 || lines[1] != "v:2" {
            return Err(invalid("seat list context or format version"));
        }
        let mut parsed = parse_seat_list_shared(&lines)?;

        let field = |index: usize, label: &str| {
            labeled(lines[index], label).ok_or_else(|| invalid("seat list label"))
        };

        let authority_sha256 = match field(9, "authority")? {
            "" => None,
            hash if is_lower_hex(hash, 64) => Some(hash.to_string()),
            _ => return Err(invalid("seat list authority")),
        };
        let history = match field(10, "history")? {
            "visible" => SeatListHistory::Visible,
            "hidden" => SeatListHistory::Hidden,
            _ => return Err(invalid("seat list history")),
        };
        let history_boundary = match field(11, "history_boundary")? {
            "" => None,
            boundary => {
                let time =
                    ulid_time(boundary).map_err(|_| invalid("seat list history_boundary"))?;
                if time > parsed.issued_at as u64 {
                    return Err(invalid(
                        "seat list history_boundary is later than issued_at",
                    ));
                }
                Some(boundary.to_string())
            }
        };
        let pre_history = match field(12, "pre_history")? {
            "kept" => SeatListPreHistory::Kept,
            "wiped" => SeatListPreHistory::Wiped,
            _ => return Err(invalid("seat list pre_history")),
        };
        if pre_history == SeatListPreHistory::Wiped && history_boundary.is_none() {
            return Err(invalid("seat list pre_history wiped without a boundary"));
        }
        let group_salt = field(13, "group_salt")?;
        if !is_lower_hex(group_salt, 64) {
            return Err(invalid("seat list group_salt"));
        }

        parsed.v2 = Some(SeatListV2Lines {
            authority_sha256,
            history,
            history_boundary,
            pre_history,
            group_salt: group_salt.to_string(),
        });
        Ok(parsed)
    }

    /// Canonical builder: v1 (4.1) when `v2` is `None`, else v2 (4.1.1).
    /// Sorts and de-duplicates `seats`, then re-parses its own output so it
    /// can never emit a body `parse` refuses.
    pub fn build(&self) -> Result<String> {
        if self.v2.is_some() {
            return self.build_v2();
        }

        let body = format!("{CONTEXT_SEAT_LIST}\nv:1\n{}", self.shared_lines());

        SeatListBody::parse_v1(&body)?;
        Ok(body)
    }

    /// Canonical v2 builder (4.1.1); refuses a body without `v2` lines
    pub fn build_v2(&self) -> Result<String> {
        let Some(lines) = &self.v2 else {
            return Err(invalid("seat list v2 lines missing"));
        };

        let body = format!(
            "{CONTEXT_SEAT_LIST_V2}\nv:2\n{}\nauthority:{}\nhistory:{}\nhistory_boundary:{}\npre_history:{}\ngroup_salt:{}",
            self.shared_lines(),
            lines.authority_sha256.as_deref().unwrap_or_default(),
            lines.history.as_str(),
            lines.history_boundary.as_deref().unwrap_or_default(),
            lines.pre_history.as_str(),
            lines.group_salt
        );

        SeatListBody::parse_v2(&body)?;
        Ok(body)
    }

    /// Lines 3 to 9, shared by both formats, with `seats` sorted and unique
    fn shared_lines(&self) -> String {
        let mut seats = self.seats.clone();
        seats.sort();
        seats.dedup();

        format!(
            "channel_id:{}\nversion:{}\ndevice_cap:{}\nissued_at:{}\nsigner_user_id:{}\nsigner_device_id:{}\nseats:{}",
            self.channel_id,
            self.version,
            self.device_cap,
            self.issued_at,
            self.signer_user_id,
            self.signer_device_id,
            seats.join(",")
        )
    }
}

/// Size, CR and line-count checks shared by both seat-list formats
fn seat_list_lines(body: &str, count: usize) -> Result<Vec<&str>> {
    if body.len() > MAX_SEAT_LIST_BODY_LEN {
        return Err(invalid("seat list body too long"));
    }
    if body.contains('\r') {
        return Err(invalid("seat list body contains CR"));
    }

    let lines: Vec<&str> = body.split('\n').collect();
    if lines.len() != count {
        return Err(invalid(if count == 9 {
            "seat list body must have exactly 9 lines"
        } else {
            "seat list body must have exactly 14 lines"
        }));
    }
    Ok(lines)
}

/// Lines 3 to 9 (4.1), identical in both formats
fn parse_seat_list_shared(lines: &[&str]) -> Result<SeatListBody> {
    let field = |index: usize, label: &str| {
        labeled(lines[index], label).ok_or_else(|| invalid("seat list label"))
    };

    let channel_id = field(2, "channel_id")?;
    if !is_valid_ulid_id(channel_id) {
        return Err(invalid("seat list channel_id"));
    }

    let version = parse_canonical_decimal(field(3, "version")?)
        .filter(|version| (1..=MAX_CANONICAL_INT as u64).contains(version))
        .ok_or_else(|| invalid("seat list version"))? as i64;

    let device_cap = parse_canonical_decimal(field(4, "device_cap")?)
        .and_then(|cap| u32::try_from(cap).ok())
        .ok_or_else(|| invalid("seat list device_cap"))?;

    let issued_at = parse_canonical_decimal(field(5, "issued_at")?)
        .filter(|at| *at <= MAX_CANONICAL_INT as u64)
        .ok_or_else(|| invalid("seat list issued_at"))? as i64;

    let signer_user_id = field(6, "signer_user_id")?;
    if !is_valid_ulid_id(signer_user_id) {
        return Err(invalid("seat list signer_user_id"));
    }

    let signer_device_id = field(7, "signer_device_id")?;
    if !is_valid_device_id_hex(signer_device_id) {
        return Err(invalid("seat list signer_device_id"));
    }

    let seats_line = field(8, "seats")?;
    if seats_line.is_empty() {
        return Err(invalid("seat list has no seats"));
    }
    let seats: Vec<String> = seats_line.split(',').map(str::to_string).collect();
    if seats.len() > MAX_SEAT_LIST_SEATS {
        return Err(invalid("seat list has too many seats"));
    }
    if !seats.iter().all(|seat| is_valid_ulid_id(seat)) {
        return Err(invalid("seat list seat id"));
    }
    // Strictly ascending by byte value = sorted AND unique
    if !seats
        .windows(2)
        .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
    {
        return Err(invalid("seat list seats not sorted and unique"));
    }
    if !seats.iter().any(|seat| seat == signer_user_id) {
        return Err(invalid("seat list signer is not seated"));
    }

    Ok(SeatListBody {
        channel_id: channel_id.to_string(),
        version,
        device_cap,
        issued_at,
        signer_user_id: signer_user_id.to_string(),
        signer_device_id: signer_device_id.to_string(),
        seats,
        v2: None,
    })
}

// ---------------------------------------------------------------------------
// Canonical owner handover statement (4.6)
// ---------------------------------------------------------------------------

/// A parsed owner handover statement body (4.6). The `v:1` format line is
/// checked by `parse` and not kept, as in `SeatListBody`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverBody {
    pub channel_id: String,
    pub from_user_id: String,
    pub from_device_id: String,
    /// b64 Ed25519 public key of the signing (`from`) device
    pub from_identity_key: String,
    pub to_user_id: String,
    pub to_device_id: String,
    /// b64 Ed25519 public key of the successor (`to`) device
    pub to_identity_key: String,
    pub issued_at: i64,
}

/// Ed25519 public key: canonical unpadded b64 of 32 bytes (0.1)
fn is_valid_identity_key_b64(value: &str) -> bool {
    value.len() == IDENTITY_KEY_B64_LEN
        && base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(value)
            .is_ok_and(|raw| raw.len() == 32)
}

impl HandoverBody {
    /// Strict parse (4.6, including the W0-fix4 `issued_at` bound). Exactly
    /// 10 lines in order, no trailing LF, no CR; nothing is trimmed or
    /// normalized. The S1 rule `to_user_id == from_user_id` is a trust rule
    /// for the route and clients, not a format rule, so it is not checked
    /// here.
    pub fn parse(body: &str) -> Result<HandoverBody> {
        if body.len() > MAX_HANDOVER_BODY_LEN {
            return Err(invalid("handover body too long"));
        }
        if body.contains('\r') {
            return Err(invalid("handover body contains CR"));
        }

        let lines: Vec<&str> = body.split('\n').collect();
        if lines.len() != 10 {
            return Err(invalid("handover body must have exactly 10 lines"));
        }
        if lines[0] != CONTEXT_HANDOVER || lines[1] != "v:1" {
            return Err(invalid("handover context or format version"));
        }

        let field = |index: usize, label: &str| {
            labeled(lines[index], label).ok_or_else(|| invalid("handover label"))
        };
        let ulid = |index: usize, label: &str| {
            field(index, label).and_then(|value| {
                if is_valid_ulid_id(value) {
                    Ok(value.to_string())
                } else {
                    Err(invalid("handover user or channel id"))
                }
            })
        };
        let device = |index: usize, label: &str| {
            field(index, label).and_then(|value| {
                if is_valid_device_id_hex(value) {
                    Ok(value.to_string())
                } else {
                    Err(invalid("handover device id"))
                }
            })
        };
        let key = |index: usize, label: &str| {
            field(index, label).and_then(|value| {
                if is_valid_identity_key_b64(value) {
                    Ok(value.to_string())
                } else {
                    Err(invalid("handover identity key"))
                }
            })
        };

        let channel_id = ulid(2, "channel_id")?;
        let from_user_id = ulid(3, "from_user_id")?;
        let from_device_id = device(4, "from_device_id")?;
        let from_identity_key = key(5, "from_identity_key")?;
        let to_user_id = ulid(6, "to_user_id")?;
        let to_device_id = device(7, "to_device_id")?;
        let to_identity_key = key(8, "to_identity_key")?;
        let issued_at = parse_canonical_decimal(field(9, "issued_at")?)
            .filter(|at| *at <= MAX_CANONICAL_INT as u64)
            .ok_or_else(|| invalid("handover issued_at"))? as i64;

        Ok(HandoverBody {
            channel_id,
            from_user_id,
            from_device_id,
            from_identity_key,
            to_user_id,
            to_device_id,
            to_identity_key,
            issued_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Canonical channel authority (4.10, S2)
// ---------------------------------------------------------------------------

/// An `owner_devices` entry: `device_id "." b64 identity key` (4.10)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityOwnerDevice {
    pub device_id: String,
    pub identity_key: String,
}

/// A `delegates` or `successors` entry:
/// `user_id "." device_id "." b64 identity key` (4.10)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityUserDevice {
    pub user_id: String,
    pub device_id: String,
    pub identity_key: String,
}

/// A parsed channel authority body (4.10). The `v:1` format line and the
/// fixed `delegate_scope:seat` line are checked by `parse` and not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAuthorityBody {
    pub channel_id: String,
    pub version: i64,
    pub owner_user_id: String,
    /// The `owner_devices` entry whose key signs this authority
    pub signer_device_id: String,
    pub issued_at: i64,
    /// `1..=5` entries, sorted by the bytes of the whole entry
    pub owner_devices: Vec<AuthorityOwnerDevice>,
    /// `0..=10` entries, sorted by the bytes of the whole entry
    pub delegates: Vec<AuthorityUserDevice>,
    pub delegate_max_device_cap: u32,
    /// `0..=10` entries in RANK order (at most 5 users, each user's entries
    /// contiguous and sorted by device id)
    pub successors: Vec<AuthorityUserDevice>,
    /// Lowercase hex SHA-256 of the previous authority body; `None` exactly
    /// when `version` is 1
    pub prev: Option<String>,
}

/// The channel authority format (4.10): parse, build and hash
pub struct ChannelAuthority;

impl AuthorityOwnerDevice {
    fn entry(&self) -> String {
        format!("{}.{}", self.device_id, self.identity_key)
    }
}

impl AuthorityUserDevice {
    fn entry(&self) -> String {
        format!("{}.{}.{}", self.user_id, self.device_id, self.identity_key)
    }
}

/// Split a `,`-joined entry line; an empty line has no entries, and an
/// empty entry is malformed
fn authority_entries(line: &str) -> Result<Vec<&str>> {
    if line.is_empty() {
        return Ok(vec![]);
    }
    let entries: Vec<&str> = line.split(',').collect();
    if entries.iter().any(|entry| entry.is_empty()) {
        return Err(invalid("authority empty entry"));
    }
    Ok(entries)
}

/// Parse a `user_id.device_id.key` line (delegates, successors): charsets,
/// at most `max` entries, no device id twice, no entry for the owner user
fn authority_user_devices(
    line: &str,
    max: usize,
    owner_user_id: &str,
) -> Result<Vec<AuthorityUserDevice>> {
    let entries = authority_entries(line)?;
    if entries.len() > max {
        return Err(invalid("authority has too many entries"));
    }

    let mut parsed: Vec<AuthorityUserDevice> = Vec::with_capacity(entries.len());
    for entry in entries {
        let parts: Vec<&str> = entry.split('.').collect();
        let [user_id, device_id, identity_key] = parts[..] else {
            return Err(invalid("authority entry shape"));
        };
        if !is_valid_ulid_id(user_id)
            || !is_valid_device_id_hex(device_id)
            || !is_valid_identity_key_b64(identity_key)
        {
            return Err(invalid("authority entry charset"));
        }
        if user_id == owner_user_id {
            return Err(invalid(
                "authority names the owner as delegate or successor",
            ));
        }
        if parsed.iter().any(|other| other.device_id == device_id) {
            return Err(invalid("authority device id twice in one line"));
        }
        parsed.push(AuthorityUserDevice {
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            identity_key: identity_key.to_string(),
        });
    }
    Ok(parsed)
}

/// Strictly ascending by the bytes of the whole entry: sorted, no duplicate
fn entries_strictly_sorted(entries: &[String]) -> bool {
    entries
        .windows(2)
        .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
}

impl ChannelAuthority {
    /// Strict parse (4.10): exactly 13 lines in order, no trailing LF, no
    /// CR, at most 3072 bytes, and every format rule: charsets; `owner_devices`
    /// non-empty, sorted, with no device id or identity key twice and an
    /// entry for `signer_device_id`; `delegates` sorted with no device id
    /// twice; no delegate or successor entry for the owner user;
    /// `delegate_scope` exactly `seat`; `successors` naming at most 5
    /// distinct users, each user's entries contiguous and sorted by device
    /// id; `prev` empty exactly when `version` is 1.
    pub fn parse(body: &str) -> Result<ChannelAuthorityBody> {
        if body.len() > MAX_CHANNEL_AUTHORITY_LEN {
            return Err(invalid("authority body too long"));
        }
        if body.contains('\r') {
            return Err(invalid("authority body contains CR"));
        }

        let lines: Vec<&str> = body.split('\n').collect();
        if lines.len() != 13 {
            return Err(invalid("authority body must have exactly 13 lines"));
        }
        if lines[0] != CONTEXT_CHANNEL_AUTHORITY || lines[1] != "v:1" {
            return Err(invalid("authority context or format version"));
        }

        let field = |index: usize, label: &str| {
            labeled(lines[index], label).ok_or_else(|| invalid("authority label"))
        };

        let channel_id = field(2, "channel_id")?;
        if !is_valid_ulid_id(channel_id) {
            return Err(invalid("authority channel_id"));
        }
        let version = parse_canonical_decimal(field(3, "version")?)
            .filter(|version| (1..=MAX_CANONICAL_INT as u64).contains(version))
            .ok_or_else(|| invalid("authority version"))? as i64;
        let owner_user_id = field(4, "owner_user_id")?;
        if !is_valid_ulid_id(owner_user_id) {
            return Err(invalid("authority owner_user_id"));
        }
        let signer_device_id = field(5, "signer_device_id")?;
        if !is_valid_device_id_hex(signer_device_id) {
            return Err(invalid("authority signer_device_id"));
        }
        let issued_at = parse_canonical_decimal(field(6, "issued_at")?)
            .filter(|at| *at <= MAX_CANONICAL_INT as u64)
            .ok_or_else(|| invalid("authority issued_at"))? as i64;

        // owner_devices
        let entries = authority_entries(field(7, "owner_devices")?)?;
        if entries.is_empty() || entries.len() > MAX_AUTHORITY_OWNER_DEVICES {
            return Err(invalid("authority owner_devices count"));
        }
        let mut owner_devices: Vec<AuthorityOwnerDevice> = Vec::with_capacity(entries.len());
        for entry in &entries {
            let parts: Vec<&str> = entry.split('.').collect();
            let [device_id, identity_key] = parts[..] else {
                return Err(invalid("authority entry shape"));
            };
            if !is_valid_device_id_hex(device_id) || !is_valid_identity_key_b64(identity_key) {
                return Err(invalid("authority entry charset"));
            }
            if owner_devices
                .iter()
                .any(|other| other.device_id == device_id)
            {
                return Err(invalid("authority device id twice in one line"));
            }
            if owner_devices
                .iter()
                .any(|other| other.identity_key == identity_key)
            {
                return Err(invalid("authority owner identity key twice"));
            }
            owner_devices.push(AuthorityOwnerDevice {
                device_id: device_id.to_string(),
                identity_key: identity_key.to_string(),
            });
        }
        if !entries_strictly_sorted(&owner_devices.iter().map(|d| d.entry()).collect::<Vec<_>>()) {
            return Err(invalid("authority owner_devices not sorted"));
        }
        if !owner_devices
            .iter()
            .any(|device| device.device_id == signer_device_id)
        {
            return Err(invalid(
                "authority signer_device_id has no owner_devices entry",
            ));
        }

        // delegates
        let delegates = authority_user_devices(
            field(8, "delegates")?,
            MAX_AUTHORITY_DELEGATES,
            owner_user_id,
        )?;
        if !entries_strictly_sorted(&delegates.iter().map(|d| d.entry()).collect::<Vec<_>>()) {
            return Err(invalid("authority delegates not sorted"));
        }

        if field(9, "delegate_scope")? != "seat" {
            return Err(invalid("authority delegate_scope"));
        }

        let delegate_max_device_cap =
            parse_canonical_decimal(field(10, "delegate_max_device_cap")?)
                .and_then(|cap| u32::try_from(cap).ok())
                .ok_or_else(|| invalid("authority delegate_max_device_cap"))?;

        // successors: rank order of users; within a user, contiguous and
        // sorted by device id
        let successors = authority_user_devices(
            field(11, "successors")?,
            MAX_AUTHORITY_SUCCESSORS,
            owner_user_id,
        )?;
        let mut ranked_users: Vec<&str> = Vec::new();
        for (index, entry) in successors.iter().enumerate() {
            let previous = index.checked_sub(1).map(|prev| &successors[prev]);
            match previous {
                Some(previous) if previous.user_id == entry.user_id => {
                    if previous.device_id.as_bytes() >= entry.device_id.as_bytes() {
                        return Err(invalid("authority successor devices not sorted"));
                    }
                }
                _ => {
                    if ranked_users.contains(&entry.user_id.as_str()) {
                        return Err(invalid("authority successor entries not contiguous"));
                    }
                    ranked_users.push(&entry.user_id);
                }
            }
        }
        if ranked_users.len() > MAX_AUTHORITY_SUCCESSOR_USERS {
            return Err(invalid("authority names more than 5 successor users"));
        }

        let prev = match field(12, "prev")? {
            "" => None,
            hash if is_lower_hex(hash, 64) => Some(hash.to_string()),
            _ => return Err(invalid("authority prev")),
        };
        if prev.is_none() != (version == 1) {
            return Err(invalid("authority prev must be empty exactly at version 1"));
        }

        Ok(ChannelAuthorityBody {
            channel_id: channel_id.to_string(),
            version,
            owner_user_id: owner_user_id.to_string(),
            signer_device_id: signer_device_id.to_string(),
            issued_at,
            owner_devices,
            delegates,
            delegate_max_device_cap,
            successors,
            prev,
        })
    }

    /// Canonical builder (4.10): sorts `owner_devices` and `delegates` by
    /// their entry bytes, keeps `successors` in the given RANK order, then
    /// re-parses its own output so it can never emit a body `parse` refuses.
    pub fn build(authority: &ChannelAuthorityBody) -> Result<String> {
        let mut owner_devices: Vec<String> = authority
            .owner_devices
            .iter()
            .map(AuthorityOwnerDevice::entry)
            .collect();
        owner_devices.sort();
        let mut delegates: Vec<String> = authority
            .delegates
            .iter()
            .map(AuthorityUserDevice::entry)
            .collect();
        delegates.sort();
        let successors: Vec<String> = authority
            .successors
            .iter()
            .map(AuthorityUserDevice::entry)
            .collect();

        let body = format!(
            "{CONTEXT_CHANNEL_AUTHORITY}\nv:1\nchannel_id:{}\nversion:{}\nowner_user_id:{}\nsigner_device_id:{}\nissued_at:{}\nowner_devices:{}\ndelegates:{}\ndelegate_scope:seat\ndelegate_max_device_cap:{}\nsuccessors:{}\nprev:{}",
            authority.channel_id,
            authority.version,
            authority.owner_user_id,
            authority.signer_device_id,
            authority.issued_at,
            owner_devices.join(","),
            delegates.join(","),
            authority.delegate_max_device_cap,
            successors.join(","),
            authority.prev.as_deref().unwrap_or_default()
        );

        ChannelAuthority::parse(&body)?;
        Ok(body)
    }

    /// Lowercase hex SHA-256 of the exact body bytes: the value of a v2
    /// list's `authority:` line and of the next authority's `prev`
    pub fn sha256(body: &str) -> String {
        sha256_hex(body.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Canonical owner succession statement (4.11, [S2b] format only)
// ---------------------------------------------------------------------------

/// A parsed owner succession statement (4.11). S2a never emits, appends or
/// walks one; the format is pinned here so one bump covers S2b.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessionStatement {
    pub channel_id: String,
    pub from_user_id: String,
    /// b64 Ed25519 public key of the owner being succeeded
    pub from_identity_key: String,
    pub to_user_id: String,
    pub to_device_id: String,
    /// b64 Ed25519 public key of the successor device (the signer)
    pub to_identity_key: String,
    /// Lowercase hex SHA-256 of the authority naming the successor
    pub authority_sha256: String,
    /// `1..=5`
    pub rank: u8,
    pub issued_at: i64,
}

impl SuccessionStatement {
    /// Strict parse (4.11): exactly 11 lines, no trailing LF, no CR, at most
    /// 1024 bytes
    pub fn parse(body: &str) -> Result<SuccessionStatement> {
        if body.len() > MAX_SUCCESSION_BODY_LEN {
            return Err(invalid("succession body too long"));
        }
        if body.contains('\r') {
            return Err(invalid("succession body contains CR"));
        }

        let lines: Vec<&str> = body.split('\n').collect();
        if lines.len() != 11 {
            return Err(invalid("succession body must have exactly 11 lines"));
        }
        if lines[0] != CONTEXT_OWNER_SUCCESSION || lines[1] != "v:1" {
            return Err(invalid("succession context or format version"));
        }

        let field = |index: usize, label: &str| {
            labeled(lines[index], label).ok_or_else(|| invalid("succession label"))
        };
        let ulid = |index: usize, label: &str| {
            field(index, label).and_then(|value| {
                if is_valid_ulid_id(value) {
                    Ok(value.to_string())
                } else {
                    Err(invalid("succession user or channel id"))
                }
            })
        };
        let key = |index: usize, label: &str| {
            field(index, label).and_then(|value| {
                if is_valid_identity_key_b64(value) {
                    Ok(value.to_string())
                } else {
                    Err(invalid("succession identity key"))
                }
            })
        };

        let channel_id = ulid(2, "channel_id")?;
        let from_user_id = ulid(3, "from_user_id")?;
        let from_identity_key = key(4, "from_identity_key")?;
        let to_user_id = ulid(5, "to_user_id")?;
        let to_device_id = field(6, "to_device_id")?;
        if !is_valid_device_id_hex(to_device_id) {
            return Err(invalid("succession device id"));
        }
        let to_identity_key = key(7, "to_identity_key")?;
        let authority_sha256 = field(8, "authority_sha256")?;
        if !is_lower_hex(authority_sha256, 64) {
            return Err(invalid("succession authority_sha256"));
        }
        let rank = parse_canonical_decimal(field(9, "rank")?)
            .filter(|rank| (1..=MAX_AUTHORITY_SUCCESSOR_USERS as u64).contains(rank))
            .ok_or_else(|| invalid("succession rank"))? as u8;
        let issued_at = parse_canonical_decimal(field(10, "issued_at")?)
            .filter(|at| *at <= MAX_CANONICAL_INT as u64)
            .ok_or_else(|| invalid("succession issued_at"))? as i64;

        Ok(SuccessionStatement {
            channel_id,
            from_user_id,
            from_identity_key,
            to_user_id,
            to_device_id: to_device_id.to_string(),
            to_identity_key,
            authority_sha256: authority_sha256.to_string(),
            rank,
            issued_at,
        })
    }

    /// Canonical builder (4.11); re-parses its own output
    pub fn build(&self) -> Result<String> {
        let body = format!(
            "{CONTEXT_OWNER_SUCCESSION}\nv:1\nchannel_id:{}\nfrom_user_id:{}\nfrom_identity_key:{}\nto_user_id:{}\nto_device_id:{}\nto_identity_key:{}\nauthority_sha256:{}\nrank:{}\nissued_at:{}",
            self.channel_id,
            self.from_user_id,
            self.from_identity_key,
            self.to_user_id,
            self.to_device_id,
            self.to_identity_key,
            self.authority_sha256,
            self.rank,
            self.issued_at
        );

        SuccessionStatement::parse(&body)?;
        Ok(body)
    }
}

// ---------------------------------------------------------------------------
// Text join payload (3.13, S2) and Text group id v2 (3.1.1, S2)
// ---------------------------------------------------------------------------

/// The signed fields of a Text join or rejoin intent on a v2 channel (3.13).
/// Ed25519 by the joining device's identity key; the route verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextJoinPayload {
    pub user_id: String,
    pub device_id: String,
    pub channel_id: String,
    /// `0..=65535`
    pub generation: u32,
    /// 64 lowercase hex
    pub group_id: String,
    /// 1 to 64 chars of `[A-Za-z0-9+/]` (`is_valid_key_package_ref`)
    pub key_package_ref: String,
    /// Milliseconds, `0..=2^53 - 1`
    pub issued_at: i64,
}

impl TextJoinPayload {
    /// The exact payload bytes (9 labeled lines, no trailing LF). Refuses
    /// any out-of-charset or out-of-bounds input; nothing is escaped.
    pub fn build(&self) -> Result<String> {
        if !is_valid_ulid_id(&self.user_id) || !is_valid_ulid_id(&self.channel_id) {
            return Err(invalid("text join user or channel id"));
        }
        if !is_valid_device_id_hex(&self.device_id) {
            return Err(invalid("text join device id"));
        }
        if self.generation > MAX_TEXT_GROUP_GENERATION_V2 {
            return Err(invalid("text join generation"));
        }
        if !is_valid_group_id(&self.group_id) {
            return Err(invalid("text join group id"));
        }
        if !is_valid_key_package_ref(&self.key_package_ref) {
            return Err(invalid("text join key_package_ref"));
        }
        if !(0..=MAX_CANONICAL_INT).contains(&self.issued_at) {
            return Err(invalid("text join issued_at"));
        }

        Ok(format!(
            "{CONTEXT_TEXT_JOIN}\nv:1\nuser_id:{}\ndevice_id:{}\nchannel_id:{}\ngeneration:{}\ngroup_id:{}\nkey_package_ref:{}\nissued_at:{}",
            self.user_id,
            self.device_id,
            self.channel_id,
            self.generation,
            self.group_id,
            self.key_package_ref,
            self.issued_at
        ))
    }
}

/// The 91-byte hash input of `text_group_id_v2` (3.1.1):
/// `field("sloga-text-group-v2") || field(channel_id) || u64_be(g) ||
/// field(salt)`, `field(x) = u16_be(len(x)) || x`, the salt being the 32 raw
/// bytes the list's `group_salt:` line encodes
pub fn text_group_id_v2_input(
    channel_id: &str,
    generation: u32,
    group_salt_hex: &str,
) -> Result<Vec<u8>> {
    if !is_valid_ulid_id(channel_id) {
        return Err(invalid("text group channel id"));
    }
    if generation > MAX_TEXT_GROUP_GENERATION_V2 {
        return Err(invalid("text group generation"));
    }
    if !is_lower_hex(group_salt_hex, 64) {
        return Err(invalid("text group salt"));
    }
    let salt: Vec<u8> = (0..32)
        .map(|index| u8::from_str_radix(&group_salt_hex[index * 2..index * 2 + 2], 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| invalid("text group salt"))?;

    let mut input = Vec::with_capacity(91);
    push_ad_field(&mut input, CONTEXT_TEXT_GROUP_V2.as_bytes())?;
    push_ad_field(&mut input, channel_id.as_bytes())?;
    input.extend_from_slice(&u64::from(generation).to_be_bytes());
    push_ad_field(&mut input, &salt)?;
    Ok(input)
}

/// Text group id v2 (3.1.1, S2-D1b): lowercase hex SHA-256 of
/// `text_group_id_v2_input`. The v1 derivation (3.1) is untouched; a
/// group's derivation is fixed by the list format its channel holds when it
/// is created.
pub fn text_group_id_v2(channel_id: &str, generation: u32, group_salt_hex: &str) -> Result<String> {
    Ok(sha256_hex(&text_group_id_v2_input(
        channel_id,
        generation,
        group_salt_hex,
    )?))
}

/// Decode a b64 (standard alphabet, unpadded, canonical) Ed25519 signature
/// to its raw 64 bytes (0.1). Refuses padding, whitespace, the URL-safe
/// alphabet and non-canonical trailing bits.
pub fn decode_signature_b64(signature: &str) -> Result<Vec<u8>> {
    if signature.len() != SIGNATURE_B64_LEN {
        return Err(invalid("signature length"));
    }
    let raw = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(signature)
        .map_err(|_| invalid("signature encoding"))?;
    if raw.len() != 64 {
        return Err(invalid("signature length"));
    }
    Ok(raw)
}

fn push_ad_field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| invalid("commit ad field too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Lowercase hex
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl SeatList {
    /// Whether the stored body is a v2 body (4.1.1), by its context line
    pub fn is_v2(&self) -> bool {
        has_context(&self.body, CONTEXT_SEAT_LIST_V2)
    }

    /// The commit `authenticated_data` every Text commit must carry while
    /// this row is the newest list (3.12.1). DISPATCHES by the body's
    /// format: a v2 row gets `commit_ad_v2`; a v1 row gets the v1 AD,
    /// byte-identical to S1: context, body, raw signature, `u16_be` handover
    /// count, then each handover body and raw signature, every field
    /// `u16_be(len) || bytes`. A v1 row never carries an authority (2.4).
    pub fn commit_ad(&self) -> Result<Vec<u8>> {
        if self.is_v2() {
            return self.commit_ad_v2();
        }
        if self.authority.is_some() {
            return Err(invalid("a v1 seat list carries no authority"));
        }
        self.commit_ad_with(CONTEXT_COMMIT_AD)
    }

    /// The v2 commit AD (3.12.1 "AD v2", S2-D3): the v1 layout under the v2
    /// context, then `field(authority body) || field(raw authority
    /// signature)`, both empty when the list's `authority:` line is empty.
    /// Refuses a body that is not a strict v2 body, one empty and one
    /// non-empty authority side, an authority whose SHA-256 is not the
    /// line, and an AD over 16383 bytes.
    pub fn commit_ad_v2(&self) -> Result<Vec<u8>> {
        let line = SeatListBody::parse_v2(&self.body)?
            .v2
            .and_then(|lines| lines.authority_sha256);

        let mut out = self.commit_ad_with(CONTEXT_COMMIT_AD_V2)?;
        match (line, &self.authority) {
            (None, None) => {
                push_ad_field(&mut out, &[])?;
                push_ad_field(&mut out, &[])?;
            }
            (Some(line), Some(authority)) => {
                if authority.body.len() > MAX_CHANNEL_AUTHORITY_LEN {
                    return Err(invalid("authority body too long"));
                }
                if ChannelAuthority::sha256(&authority.body) != line {
                    return Err(invalid("authority does not match the seat list"));
                }
                push_ad_field(&mut out, authority.body.as_bytes())?;
                push_ad_field(&mut out, &decode_signature_b64(&authority.signature)?)?;
            }
            _ => return Err(invalid("seat list authority line and authority disagree")),
        }

        if out.len() > MAX_COMMIT_AD_LEN {
            return Err(invalid("commit ad too long"));
        }
        Ok(out)
    }

    /// The layout both AD versions share: `context`, body, raw signature,
    /// `u16_be` chain count, then each chain entry body and raw signature.
    /// Checks the 16383-byte total for what it built.
    fn commit_ad_with(&self, context: &str) -> Result<Vec<u8>> {
        if self.body.len() > MAX_SEAT_LIST_BODY_LEN {
            return Err(invalid("seat list body too long"));
        }
        if self.handovers.len() > MAX_SEAT_LIST_HANDOVERS {
            return Err(invalid("handover chain too long"));
        }

        let mut out = Vec::new();
        push_ad_field(&mut out, context.as_bytes())?;
        push_ad_field(&mut out, self.body.as_bytes())?;
        push_ad_field(&mut out, &decode_signature_b64(&self.signature)?)?;
        out.extend_from_slice(&(self.handovers.len() as u16).to_be_bytes());
        for handover in &self.handovers {
            if handover.body.len() > MAX_HANDOVER_BODY_LEN {
                return Err(invalid("handover body too long"));
            }
            push_ad_field(&mut out, handover.body.as_bytes())?;
            push_ad_field(&mut out, &decode_signature_b64(&handover.signature)?)?;
        }

        if out.len() > MAX_COMMIT_AD_LEN {
            return Err(invalid("commit ad too long"));
        }
        Ok(out)
    }

    /// Lowercase hex SHA-256 of `commit_ad()`: the open Text group's
    /// `seat_list_ad_sha256` while this row is the newest list (2.5); the v2
    /// bytes for a v2 row (3.12.1)
    pub fn commit_ad_sha256(&self) -> Result<String> {
        Ok(sha256_hex(&self.commit_ad()?))
    }
}

// ---------------------------------------------------------------------------
// Planners (pure; both drivers call them inside their atomicity primitive)
// ---------------------------------------------------------------------------

/// Which seat-list write is being planned
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatListWriteKind {
    /// Genesis list on `PUT .../protect` (version 1, no stored list)
    Protect,
    /// `PUT .../seats` (version = stored + 1, or a byte-identical re-PUT)
    Put,
    /// S4 `POST .../history_wipe` (4.3 "S4", S4-PA-6): the next list, which
    /// moves `pre_history` from `kept` to `wiped` and keeps every other
    /// line; no growth gate and no seat claims (version = stored + 1, or a
    /// byte-identical re-POST)
    Wipe,
}

/// Everything the planner reads, as the driver read it inside its
/// transaction / under its locks
pub struct SeatListWriteInput<'a> {
    pub kind: SeatListWriteKind,
    pub channel_id: &'a str,
    pub submission: &'a SeatListSubmission,
    /// The channel's stored seat-list row
    pub stored: Option<&'a SeatList>,
    /// The channel's entitlement
    pub entitlement: Option<&'a ChannelEntitlement>,
    /// Every `channel_seats` row of the channel
    pub seats: &'a [ChannelSeat],
    /// The channel's OPEN Text group, if any
    pub text_group: Option<&'a MlsGroup>,
    /// Whether the list may claim seats (the growth flag, decision 5 (W2));
    /// protect always passes `true`, its route is growth-gated
    pub allow_claims: bool,
    /// S2 `formats_v2` (7.1, #218): whether this write may ENTER v2 (a v2
    /// genesis, a v1-to-v2 upgrade). A channel whose stored list is v2 keeps
    /// v2 whatever it says (4.3 step 1).
    pub formats_v2: bool,
    /// S4 `history_setting` (7.1 "S4"), read from the configuration by the
    /// driver: a protect genesis with a boundary or `wiped`, and the wipe
    /// write, need it. While it is off, S2's "until S4" refusals of a
    /// non-empty boundary and of `wiped` apply on every path (4.1.1 "S4").
    pub history_setting: bool,
    /// Protect only: the request's `wipe_history` flag (7.2 "S4"); `None`
    /// takes the signed `pre_history` line. Every other write passes `None`.
    pub wipe_history: Option<bool>,
    /// `text_group_user_ids` of the channel (the 2.3 no-cooldown fallback)
    pub text_group_users: &'a BTreeSet<String>,
    /// The PUT's `X-Audit-Log-Reason` (4.3 step 4d, S2-D20), already
    /// sanitized by the route; protect passes `None` (a genesis releases
    /// nobody)
    pub removal_reason: Option<&'a str>,
    pub now: Timestamp,
}

/// The writes a seat-list change consists of; a driver applies all of them
/// in one transaction or none
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatListWritePlan {
    /// New `channel_seat_lists` row
    pub row: SeatList,
    /// `channel_seats` rows to upsert (only the changed ones, sorted by id)
    pub seat_rows: Vec<ChannelSeat>,
    pub claimed: Vec<String>,
    pub released: Vec<String>,
    /// Entries to append to the open Text group's `pending_removals`
    pub pending_added: Vec<MlsPendingRemoval>,
    /// New `seat_list_ad_sha256` for the open Text group
    pub seat_list_ad_sha256: String,
    /// The open Text group's whole new `pending_device_removals` when it
    /// changes (2.5 "Clearing", 4.3 step 7); `None` leaves the field as is
    pub pending_device_removals: Option<Vec<MlsPendingDeviceRemoval>>,
    /// Unset the open Text group's `signer_lost` (4.3 step 7)
    pub clear_signer_lost: bool,
    /// S4 (2.1 "S4"): the channel's `protected_history` this write sets in
    /// the same transaction. Protect: the boundary and the wipe state of the
    /// signed genesis (`None` for a genesis without a boundary). Wipe: the
    /// request (`HistoryWipe::Requested`), which the driver writes only over
    /// `HistoryWipe::None` (the state only moves forward). A seat PUT: `None`.
    pub protected_history: Option<ProtectedHistory>,
}

impl SeatListWritePlan {
    /// The outcome reported once the plan has been written
    pub fn outcome(&self) -> SeatListWriteOutcome {
        SeatListWriteOutcome {
            list: self.row.clone(),
            unchanged: false,
            claimed: self.claimed.clone(),
            released: self.released.clone(),
            pending_removals_added: self
                .pending_added
                .iter()
                .map(|pending| pending.user_id.clone())
                .collect(),
            signer_lost_cleared: self.clear_signer_lost,
        }
    }
}

/// Planner verdict
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeatListWriteDecision {
    /// Byte-identical re-PUT of the stored row: stored success, no writes
    Unchanged(SeatList),
    /// Write everything in the plan, atomically
    Apply(SeatListWritePlan),
}

impl SeatListWriteDecision {
    /// Outcome for a decision whose writes (if any) have been committed
    pub fn outcome(&self) -> SeatListWriteOutcome {
        match self {
            SeatListWriteDecision::Unchanged(list) => SeatListWriteOutcome {
                list: list.clone(),
                unchanged: true,
                claimed: vec![],
                released: vec![],
                pending_removals_added: vec![],
                signer_lost_cleared: false,
            },
            SeatListWriteDecision::Apply(plan) => plan.outcome(),
        }
    }
}

/// Plan a protect (genesis) or seat PUT: the database-side parts of 4.3.
///
/// Order (4.3, W0-fix8): parse (step 1) first, with the S2 format rule
/// (`check_seat_list_format`) and the authority structure (step 3b,
/// `check_seat_list_authority`); then the version rule (step 4), where a
/// byte-identical re-PUT returns the stored row IMMEDIATELY, before the S2
/// immutable and one-way lines (4c, `check_seat_list_v2_lines`), the
/// signer-leaf check (5b), the seat claims (7) and the handover append (8);
/// only then the removed-users refusal (C1, `seat_list_removed_users`), 5b,
/// the growth flag (decision 5 (W2)), 7 and 8. Route-side checks
/// (authorization, session binding, signature, the authority's signer key
/// and signature, bots and staff, the `device_cap` ceiling) are not repeated
/// here. Server membership of every user in `claimed` and, on protect, the
/// owner are claimed by the driver in the same transaction (decision 13
/// (W2)).
///
/// Step 7 (S2) is wired: the `signer_lost` resolution (`resolve_signer_lost`,
/// refusing before any claim), every release's `release_cause` and the 2.3
/// no-cooldown rule (`ChannelSeat::release`), and the 2.5 "Clearing" of the
/// open group's `pending_device_removals`. So is 4d (`check_removal_reason`):
/// a plan that releases anyone without `removal_reason` is refused before
/// any write, after the step-4 retry return.
///
/// S4 (4.3 "S4"): 4c reads `history_setting` (`check_seat_list_history_lines`);
/// a protect genesis also runs `check_protect_genesis_history`, whose
/// `protected_history` the plan carries; the wipe write (`Wipe`) is planned
/// as a seat PUT with 4c turned around, refuses any seat change, and carries
/// the `Requested` wipe.
pub fn plan_seat_list_write(input: &SeatListWriteInput<'_>) -> Result<SeatListWriteDecision> {
    let submission = input.submission;
    let now = input.now;

    // Step 1: strict parse; the route channel and the declared signer
    // device must match the signed body
    let body = SeatListBody::parse(&submission.body)?;
    if body.channel_id != input.channel_id {
        return Err(invalid("seat list channel_id does not match the channel"));
    }
    if body.signer_device_id != submission.signer_device_id {
        return Err(invalid(
            "signer_device_id does not match the seat list body",
        ));
    }
    decode_signature_b64(&submission.signature)?;

    // Step 1 (S2, #218): which format this write may carry
    check_seat_list_format(input.kind, &body, input.stored, input.formats_v2)?;

    // Step 3b (S2): the authority's structure, `version`, `prev` and signer
    // device; the route verifies its signer key and signature
    let authority_change =
        check_seat_list_authority(&body, submission.authority.as_ref(), input.stored)?;

    // Step 4: version rule
    match (input.kind, input.stored) {
        (SeatListWriteKind::Protect, Some(_)) => {
            return Err(invalid("channel already has a seat list"));
        }
        (SeatListWriteKind::Protect, None) => {
            if body.version != 1 {
                return Err(invalid("genesis seat list must be version 1"));
            }
        }
        (SeatListWriteKind::Put | SeatListWriteKind::Wipe, None) => {
            return Err(invalid("channel has no seat list"));
        }
        (SeatListWriteKind::Put | SeatListWriteKind::Wipe, Some(stored)) => {
            if body.version == stored.version
                && submission.body == stored.body
                && submission.signature == stored.signature
            {
                // Lost-response retry (4.9): stored success, no side effects
                return Ok(SeatListWriteDecision::Unchanged(stored.clone()));
            }
            if Some(body.version) != stored.version.checked_add(1) {
                return Err(invalid("seat list version must be stored version + 1"));
            }
        }
    }

    // Step 4c (S2, with the S4 semantics): immutable and one-way v2 lines,
    // after the retry return; turned around for the wipe write
    check_seat_list_history_lines(input.kind, &body, input.stored, input.history_setting)?;

    // S4 (2.1 "S4"): what this write sets as the channel's
    // `protected_history`, from the signed lines alone
    let protected_history = match input.kind {
        SeatListWriteKind::Protect => {
            check_protect_genesis_history(&body, input.history_setting, input.wipe_history, now)?
        }
        SeatListWriteKind::Wipe => {
            // 4c made sure the list carries the (stored) boundary
            let boundary = body
                .v2
                .as_ref()
                .and_then(|lines| lines.history_boundary.clone())
                .ok_or_else(|| create_error!(InternalError))?;
            Some(ProtectedHistory {
                boundary,
                wipe: HistoryWipe::Requested {
                    at: now,
                    by: body.signer_user_id.clone(),
                },
            })
        }
        SeatListWriteKind::Put => None,
    };

    // C1 (W2 audit, decision 2): a list that still names a user the server
    // removed since the stored list is refused before any claim, whatever
    // the growth flag says (see `seat_list_removed_users`). A genesis list
    // has no stored list, so protect never answers it.
    let removed = seat_list_removed_users(&body, input.stored, input.seats)?;
    if !removed.is_empty() {
        return Err(create_error!(SeatListNamesRemovedUsers { users: removed }));
    }

    // Step 5b: when the channel has an open Text group, the signer device
    // must hold a leaf in it (genesis exempt: no group can exist yet; the
    // wipe write is not, 4.3 "S4")
    if input.kind != SeatListWriteKind::Protect {
        if let Some(group) = input.text_group {
            if !group.has_member(&body.signer_user_id, &body.signer_device_id) {
                return Err(invalid("seat list signer device holds no leaf"));
            }
        }
    }

    // Step 7 (S2, #222): while the open group carries `signer_lost`, only a
    // list from another device with an authority change omitting the lost
    // device lands; any other is refused here, before anything is planned
    let signer_lost = resolve_signer_lost(
        input.text_group,
        &body,
        authority_change.as_ref().map(|change| &change.authority),
        now,
    )?;

    // Step 7: claims and releases, reconciling the seat rows to the list
    let desired: BTreeSet<&str> = body.seats.iter().map(String::as_str).collect();
    let mut seat_rows = Vec::new();
    let mut claimed = Vec::new();
    let mut released = Vec::new();
    let mut new_slots = 0usize;

    for user_id in &desired {
        match input.seats.iter().find(|seat| seat.user_id == *user_id) {
            Some(seat) if seat.is_active() => {}
            Some(seat) => {
                // A cooling seat is reactivated without consuming another
                // slot (2.3 DECISION (W0)) and stays keys-received, so its
                // next release cools (`reactivate`, F-1); an expired one is
                // a new slot
                if !seat.is_cooling(now) {
                    new_slots += 1;
                }
                let mut seat = seat.clone();
                seat.reactivate(now);
                seat_rows.push(seat);
                claimed.push(user_id.to_string());
            }
            None => {
                new_slots += 1;
                seat_rows.push(ChannelSeat {
                    id: ChannelSeat::composite_id(input.channel_id, user_id),
                    channel_id: input.channel_id.to_string(),
                    user_id: user_id.to_string(),
                    seated_at: now,
                    released_at: None,
                    cooldown_until: None,
                    release_cause: None,
                    keys_received_at: None,
                });
                claimed.push(user_id.to_string());
            }
        }
    }

    for seat in input.seats {
        if seat.is_active() && !desired.contains(seat.user_id.as_str()) {
            let mut seat = seat.clone();
            let in_text_group = input.text_group_users.contains(&seat.user_id);
            seat.release(now, SeatReleaseCause::OwnerUnseat, in_text_group)?;
            released.push(seat.user_id.clone());
            seat_rows.push(seat);
        }
    }

    // 4.3 "S4" (S4-PA-6): the wipe write claims and releases no seat. Its
    // list names exactly the stored list's seats, so a seat row that would
    // change here is a state the wipe must not paper over (the signer's own
    // released seat, say, which only the step-7 recovery list reactivates).
    if input.kind == SeatListWriteKind::Wipe && (!claimed.is_empty() || !released.is_empty()) {
        return Err(invalid("the history wipe changes no seat"));
    }

    // Step 4d (S2-D20): a list that releases anyone carries a reason. Here,
    // after the step-4 retry return, so the retry of a list that landed
    // succeeds without the header.
    check_removal_reason(&released, input.removal_reason)?;

    // Decision 5 (W2): with the growth flag off, a list that claims or
    // reactivates a seat is refused; a removal-only or `device_cap`-only
    // list still lands. This runs after the byte-identical return of step
    // 4, so the retry of a list that landed while the flag was on keeps
    // succeeding (W0-fix8).
    if !input.allow_claims && !claimed.is_empty() {
        return Err(create_error!(FeatureDisabled {
            feature: "protected_channels".to_string()
        }));
    }

    if !claimed.is_empty() {
        let entitlement = input
            .entitlement
            .filter(|entitlement| entitlement.is_active())
            .ok_or_else(|| create_error!(InvalidOperation))?;

        // Count check only when slots are consumed, so a removal-only list
        // (or a pure reactivation) is never refused by an over-cap state
        if new_slots > 0 {
            let used = channel_seats_used(input.seats, now);
            if used + new_slots > entitlement.slot_cap as usize {
                return Err(create_error!(SeatCapReached {
                    max: entitlement.slot_cap as usize
                }));
            }
        }
    } else if input.kind == SeatListWriteKind::Protect {
        // Unreachable (the signer is always seated), kept fail-closed
        return Err(create_error!(InvalidOperation));
    }

    // Each dropped user with at least one device in the open Text group
    // becomes a pending removal (4.3 step 7)
    let mut pending_added = Vec::new();
    if let Some(group) = input.text_group {
        // Dropped = (previous list's seats + active seat rows) - new list.
        // A stored row that no longer parses is corrupt data: fail closed.
        let mut dropped: BTreeSet<String> = input
            .seats
            .iter()
            .filter(|seat| seat.is_active())
            .map(|seat| seat.user_id.clone())
            .collect();
        if let Some(stored) = input.stored {
            dropped.extend(SeatListBody::parse(&stored.body)?.seats);
        }

        for user_id in &dropped {
            if desired.contains(user_id.as_str()) {
                continue;
            }
            let has_device = group
                .members
                .iter()
                .any(|member| member.user_id == *user_id);
            let already = group
                .pending_removals
                .iter()
                .any(|pending| pending.user_id == *user_id);
            if has_device && !already {
                pending_added.push(MlsPendingRemoval {
                    user_id: user_id.to_string(),
                    created_at: now,
                });
            }
        }
    }

    // 2.5 "Clearing" (#224) in every seat-list write, then the step-7
    // resolution: clear `signer_lost` and queue the lost device only if it
    // holds a leaf (`resolve_signer_lost` decided that)
    let mut pending_device_removals = None;
    let clear_signer_lost = matches!(signer_lost, SignerLostResolution::Clear { .. });
    if let Some(group) = input.text_group {
        let mut cleared = group.clone();
        retain_member_pending_device_removals(&mut cleared);
        if let SignerLostResolution::Clear {
            pending_device: Some(pending),
        } = signer_lost
        {
            cleared.pending_device_removals.push(pending);
        }
        if cleared.pending_device_removals != group.pending_device_removals {
            pending_device_removals = Some(cleared.pending_device_removals);
        }
    }

    // Step 8: handover append (route verified the statement itself)
    let mut handovers = input
        .stored
        .map(|stored| stored.handovers.clone())
        .unwrap_or_default();
    if let Some(handover) = &submission.handover {
        if handover.body.len() > MAX_HANDOVER_BODY_LEN {
            return Err(invalid("handover body too long"));
        }
        decode_signature_b64(&handover.signature)?;
        handovers.push(handover.clone());
    }
    if handovers.len() > MAX_SEAT_LIST_HANDOVERS {
        return Err(invalid("handover chain too long"));
    }

    let row = SeatList {
        id: input.channel_id.to_string(),
        version: body.version,
        body: submission.body.clone(),
        signer_user_id: body.signer_user_id.clone(),
        signer_device_id: body.signer_device_id.clone(),
        signature: submission.signature.clone(),
        handovers,
        updated_at: now,
        // Step 3b passed: present exactly when the body's `authority:` line
        // is non-empty, and its hash is that line
        authority: submission.authority.clone(),
    };
    // AD size (3.12.1): `commit_ad` refuses a row whose AD would exceed
    // 16383 bytes, before any write
    let seat_list_ad_sha256 = row.commit_ad_sha256()?;

    seat_rows.sort_by(|a, b| a.id.cmp(&b.id));
    claimed.sort();
    released.sort();

    Ok(SeatListWriteDecision::Apply(SeatListWritePlan {
        row,
        seat_rows,
        claimed,
        released,
        pending_added,
        seat_list_ad_sha256,
        pending_device_removals,
        clear_signer_lost,
        protected_history,
    }))
}

/// C1 (W2 audit; decision 2, confirmed by the user 2026-10-04: a removed or
/// re-invited member is not re-seated until the owner re-seats them): the
/// users `body` names whose seat the SERVER released since the stored list
/// landed, sorted. A server-forced release (kick, ban, leaving the server,
/// account deletion: `release_channel_seats_for_user`, 6.3) never edits the
/// signed list, so the owner's client keeps naming the user; without this
/// check its next list (adding someone else, say) would reactivate that seat
/// silently once the user rejoins. Such a list is refused with
/// `SeatListNamesRemovedUsers { users }`: the client lands a list without
/// them first, and adding one back later is an ordinary claim (the growth
/// path, with its dialog).
///
/// Why the release is read from the rows and not stored on them: every list
/// write reconciles the seat rows to the list, so a seat the planner
/// releases (the owner's own unseat) is off that list, and a later list
/// naming the user again reactivates the seat. A RELEASED seat whose user
/// the STORED list still names was therefore released by the forced
/// primitive after that list landed, and by nothing else. That also holds
/// when the removal commits between a seat PUT's snapshot and its commit
/// (the PUT writes no row of a user it keeps), where comparing a release
/// time with the list's time would not. Cooldown expiry changes nothing:
/// an expired seat whose user the stored list names is still removed.
///
/// A listed user with NO seat row is reported too (re-review L3): a landed
/// list has an active row for every user it names (genesis claims them
/// all, and a list naming a new user lands only by claiming it), so a
/// missing row can only mean the row was removed after the removal, by a
/// future released or expired seat sweep, say. Treating it as "never
/// seated" would make the no-row branch of step 7 a fresh claim and undo
/// this check silently. Only an ACTIVE row clears a listed user.
///
/// The signer is never reported: the signer is always seated (4.1), so
/// refusing it would wedge every later list, and the signer naming itself is
/// the owner's own act. A stored body that no longer parses is corrupt data
/// and fails closed.
pub fn seat_list_removed_users(
    body: &SeatListBody,
    stored: Option<&SeatList>,
    seats: &[ChannelSeat],
) -> Result<Vec<String>> {
    let Some(stored) = stored else {
        return Ok(vec![]);
    };
    let still_listed: BTreeSet<String> = SeatListBody::parse(&stored.body)?
        .seats
        .into_iter()
        .collect();

    // `body.seats` is sorted and unique (4.1), so the result is too
    Ok(body
        .seats
        .iter()
        .filter(|user_id| **user_id != body.signer_user_id && still_listed.contains(*user_id))
        .filter(|user_id| {
            !seats
                .iter()
                .any(|seat| seat.user_id == **user_id && seat.is_active())
        })
        .cloned()
        .collect())
}

// ---------------------------------------------------------------------------
// 4.3 "S2 additions": pure rule checks
// ---------------------------------------------------------------------------

/// 4.3 step 1, S2 (#218): `formats_v2` governs only ENTRY into v2. Over a
/// stored v2 list only a v2 body is accepted, whatever the flag says (so a
/// removal-only PUT keeps working with the flag off); over a stored v1 list
/// a v2 body (the upgrade) needs the flag. Protect takes a v2 genesis only
/// while the flag is on and a v1 genesis only while it is off. The S4 wipe
/// write needs a v2 list over a stored v2 list (only v2 carries
/// `pre_history`). Every refusal is `FailedValidation`.
pub fn check_seat_list_format(
    kind: SeatListWriteKind,
    body: &SeatListBody,
    stored: Option<&SeatList>,
    formats_v2: bool,
) -> Result<()> {
    let submitted_v2 = body.v2.is_some();
    match (kind, stored) {
        (SeatListWriteKind::Protect, _) => {
            if submitted_v2 && !formats_v2 {
                return Err(invalid("a v2 genesis list needs formats_v2"));
            }
            if !submitted_v2 && formats_v2 {
                return Err(invalid("a genesis list must be v2 while formats_v2 is on"));
            }
        }
        (SeatListWriteKind::Wipe, Some(stored)) if stored.is_v2() && submitted_v2 => {}
        (SeatListWriteKind::Wipe, _) => {
            return Err(invalid("the history wipe needs a v2 seat list"));
        }
        (SeatListWriteKind::Put, Some(stored)) if stored.is_v2() => {
            if !submitted_v2 {
                return Err(invalid("a v1 seat list cannot replace a v2 list"));
            }
        }
        (SeatListWriteKind::Put, _) => {
            if submitted_v2 && !formats_v2 {
                return Err(invalid("a v2 seat list over a v1 list needs formats_v2"));
            }
        }
    }
    Ok(())
}

/// A CHANGED channel authority accepted by 4.3 step 3b, for the route to
/// finish: `signer_identity_key` (the `owner_devices` entry of the PUT's
/// signer device) must be that device's directory key, and the authority's
/// signature must verify under it (`verify_payload`, as for step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAuthorityChange {
    pub authority: ChannelAuthorityBody,
    pub signer_identity_key: String,
}

/// 4.3 step 3b (S2; #215, #225), the structural half. The `authority:` line
/// and the carried authority come together: a non-empty line without an
/// authority, an authority without a line (a v1 body included), and an
/// empty line over a stored non-empty authority are refused. A carried
/// authority parses (4.10), hashes to the line, names the route channel and
/// the list's signer user. If it is byte-identical (body and signature) to
/// the stored one it is no change and is not re-verified (`Ok(None)`): a
/// list from another listed owner device may carry it unchanged. Otherwise
/// it is a change: its `signer_device_id` is the list's signer device, its
/// `version` the stored one's + 1 (1 when none is stored; so never lower),
/// and its `prev` the stored body's SHA-256 (empty when none). The change is
/// returned for the route's key and signature checks. Signer ELIGIBILITY is
/// the members' decision (4.4.1, #210 (e)). Every refusal is
/// `FailedValidation`; a stored authority that no longer parses fails
/// closed.
pub fn check_seat_list_authority(
    body: &SeatListBody,
    submitted: Option<&SignedAuthority>,
    stored: Option<&SeatList>,
) -> Result<Option<ChannelAuthorityChange>> {
    let line = body
        .v2
        .as_ref()
        .and_then(|lines| lines.authority_sha256.as_deref());
    let stored_authority = stored.and_then(|stored| stored.authority.as_ref());

    let (line, submitted) = match (line, submitted) {
        (None, None) => {
            if stored_authority.is_some() {
                return Err(invalid("seat list drops the stored authority"));
            }
            return Ok(None);
        }
        (None, Some(_)) => return Err(invalid("authority without a seat list authority line")),
        (Some(_), None) => return Err(invalid("seat list authority line without an authority")),
        (Some(line), Some(submitted)) => (line, submitted),
    };

    let authority = ChannelAuthority::parse(&submitted.body)?;
    decode_signature_b64(&submitted.signature)?;
    if ChannelAuthority::sha256(&submitted.body) != line {
        return Err(invalid(
            "authority does not match the seat list authority line",
        ));
    }
    if authority.channel_id != body.channel_id {
        return Err(invalid("authority channel_id does not match the channel"));
    }
    if authority.owner_user_id != body.signer_user_id {
        return Err(invalid("authority owner is not the seat list signer"));
    }

    if stored_authority == Some(submitted) {
        return Ok(None);
    }

    // A change (#225: only a change names the PUT's signer device)
    if authority.signer_device_id != body.signer_device_id {
        return Err(invalid(
            "a changed authority must be signed by the list's signer device",
        ));
    }
    let (expected_version, expected_prev) = match stored_authority {
        Some(stored) => (
            ChannelAuthority::parse(&stored.body)?
                .version
                .checked_add(1),
            Some(ChannelAuthority::sha256(&stored.body)),
        ),
        None => (Some(1), None),
    };
    if Some(authority.version) != expected_version {
        return Err(invalid("authority version must be the stored version + 1"));
    }
    if authority.prev != expected_prev {
        return Err(invalid("authority prev must name the stored authority"));
    }

    let signer_identity_key = authority
        .owner_devices
        .iter()
        .find(|device| device.device_id == body.signer_device_id)
        .map(|device| device.identity_key.clone())
        .ok_or_else(|| invalid("authority signer_device_id has no owner_devices entry"))?;
    Ok(Some(ChannelAuthorityChange {
        authority,
        signer_identity_key,
    }))
}

/// 4.3 step 4c as S2 calls it, unchanged: [`check_seat_list_history_lines`]
/// for a genesis (`stored == None`) or a seat PUT with `history_setting`
/// OFF, so S2's "until S4" refusals of a non-empty `history_boundary` and of
/// `pre_history:wiped` apply on every path. The route's pre-transaction
/// validation (`protected_seat_validation.rs`) still calls this; until it
/// moves to [`check_seat_list_history_lines`] with the configured flag (W2),
/// the route refuses every boundary and `wiped` before a driver sees them,
/// which fails closed.
pub fn check_seat_list_v2_lines(body: &SeatListBody, stored: Option<&SeatList>) -> Result<()> {
    let kind = if stored.is_some() {
        SeatListWriteKind::Put
    } else {
        SeatListWriteKind::Protect
    };
    check_seat_list_history_lines(kind, body, stored, false)
}

/// 4.3 step 4c with the 4.1.1 "S4" semantics: the immutable and one-way
/// lines of a v2 list of kind `kind`.
///
/// Against a stored v2 list (S2, whatever the flag): `group_salt` and
/// `history_boundary` equal, and `pre_history` never `wiped` to `kept`. A
/// stored v1 list counts as the 4.1.1 predecessor `{ authority: empty,
/// history: hidden, history_boundary: empty, pre_history: kept }`, so the
/// first v2 list may pick any salt and any `history` (#222) but sets no
/// boundary. `history` is free either way. Then:
///
/// - `history_setting` off: S2's "until S4" refusals, keyed on the flag,
///   on every path (4.1.1 "S4"): a non-empty boundary and `wiped` are
///   refused, protect and the wipe write included. A channel protected with
///   a boundary while the flag was on is therefore refused every list while
///   it is off (the doc's "every path").
/// - On, a seat PUT: `kept -> wiped` is refused (only the wipe write and a
///   protect genesis set it), and a boundary over a stored v1 list is
///   refused (the predecessor has none).
/// - On, protect: the genesis may set both; its own rules are
///   [`check_protect_genesis_history`].
/// - The wipe write: [`check_seat_list_wipe_lines`].
///
/// Not here, each enforced once elsewhere: a v1 body over a stored v2 list
/// (step 1, `check_seat_list_format`), the authority never emptied nor
/// lowered (step 3b, `check_seat_list_authority`), and the boundary's own
/// format and future rule (step 1, `SeatListBody::parse_v2`). Every refusal
/// is `FailedValidation`; a stored v2 body that no longer parses fails
/// closed.
pub fn check_seat_list_history_lines(
    kind: SeatListWriteKind,
    body: &SeatListBody,
    stored: Option<&SeatList>,
    history_setting: bool,
) -> Result<()> {
    if kind == SeatListWriteKind::Wipe {
        if !history_setting {
            return Err(invalid("pre_history wiped is refused until S4"));
        }
        return check_seat_list_wipe_lines(body, stored);
    }

    let Some(lines) = &body.v2 else {
        return Ok(());
    };

    // Against a stored v2 list. Genesis and the v1 predecessor have no salt
    // and no boundary to keep and are `kept`, so nothing here applies.
    let previous = match stored.filter(|stored| stored.is_v2()) {
        Some(stored) => Some(
            SeatListBody::parse_v2(&stored.body)?
                .v2
                .ok_or_else(|| create_error!(InternalError))?,
        ),
        None => None,
    };
    if let Some(previous) = &previous {
        if previous.pre_history == SeatListPreHistory::Wiped
            && lines.pre_history == SeatListPreHistory::Kept
        {
            return Err(invalid("pre_history cannot go from wiped to kept"));
        }
        if lines.group_salt != previous.group_salt {
            return Err(invalid("group_salt is immutable"));
        }
        if lines.history_boundary != previous.history_boundary {
            return Err(invalid("history_boundary is immutable"));
        }
    }

    // S2's "until S4" rules, now keyed on `history_setting`: a signed
    // `wiped` with no wipe behind it would be false, and no path may carry a
    // boundary
    if !history_setting {
        if lines.pre_history == SeatListPreHistory::Wiped {
            return Err(invalid("pre_history wiped is refused until S4"));
        }
        if lines.history_boundary.is_some() {
            return Err(invalid("history_boundary is refused until S4"));
        }
        return Ok(());
    }

    if kind == SeatListWriteKind::Put {
        let stored_wiped = previous
            .as_ref()
            .is_some_and(|previous| previous.pre_history == SeatListPreHistory::Wiped);
        if lines.pre_history == SeatListPreHistory::Wiped && !stored_wiped {
            return Err(invalid(
                "pre_history goes from kept to wiped only through the history wipe",
            ));
        }
        if previous.is_none() && lines.history_boundary.is_some() {
            return Err(invalid("history_boundary is immutable"));
        }
    }
    Ok(())
}

/// 4.3 "S4" step 4c turned around, for the wipe write (S4-PA-6): over a
/// stored v2 list, `pre_history` MUST go from `kept` to `wiped`, and every
/// line but `version`, `issued_at` and the two signer lines MUST equal the
/// stored list's: `seats`, `device_cap`, `authority`, `history`, the
/// boundary and the salt (`channel_id` is step 1's). A wipe list therefore
/// carries the stored, non-empty boundary (`wiped` without one is
/// malformed). Every refusal is `FailedValidation`; a stored v2 body that no
/// longer parses fails closed.
pub fn check_seat_list_wipe_lines(body: &SeatListBody, stored: Option<&SeatList>) -> Result<()> {
    let (Some(lines), Some(stored)) = (&body.v2, stored.filter(|stored| stored.is_v2())) else {
        return Err(invalid("the history wipe needs a v2 seat list"));
    };
    let previous = SeatListBody::parse_v2(&stored.body)?;
    let previous_lines = previous
        .v2
        .as_ref()
        .ok_or_else(|| create_error!(InternalError))?;

    if previous_lines.pre_history != SeatListPreHistory::Kept {
        return Err(invalid("pre_history is already wiped"));
    }
    if lines.pre_history != SeatListPreHistory::Wiped {
        return Err(invalid("the history wipe must set pre_history wiped"));
    }
    if body.seats != previous.seats
        || body.device_cap != previous.device_cap
        || lines.authority_sha256 != previous_lines.authority_sha256
        || lines.history != previous_lines.history
        || lines.history_boundary != previous_lines.history_boundary
        || lines.group_salt != previous_lines.group_salt
    {
        return Err(invalid("the history wipe changes only pre_history"));
    }
    Ok(())
}

/// How far after the server's clock a protect boundary's `ulid_time` may be
/// (4.3 "S4", ruled in #283 (e)): B is server-minted, but delta instances'
/// clocks differ, so the server allows the signer's 2 minutes
pub const MAX_BOUNDARY_CLOCK_SKEW_MS: u64 = 120_000;

/// 4.3 "S4", protect: the genesis's history lines against the server's
/// rules, and the `protected_history` the protect transaction writes with
/// the flag (2.1 "S4"); `None` for a genesis without a boundary (a channel
/// protected while empty, a v1 list), which writes none.
///
/// - `wipe_history`, when present, equals the signed `pre_history` (`true`
///   for `wiped`; a list without a boundary is `kept`), S4-PA-7;
/// - a boundary needs `history_setting` (4.1.1 "S4", 7.1 "S4");
/// - a genesis with a boundary seats ONLY its signer (S4-D13, S4-PA-10);
/// - `ulid_time(B) <= now + 2 min` by the server's clock (#283 (e));
/// - the wipe state comes from the SIGNED line alone: `kept` gives
///   `HistoryWipe::None`, `wiped` gives `Requested { at: now, by: signer }`.
///
/// Every refusal is `FailedValidation`. The parse already refused a
/// boundary that is not a canonical ULID or is later than `issued_at`.
/// Both drivers run this before the in-transaction message probe, so a
/// refused genesis never answers `ProtectHistoryMoved`, and the planner runs
/// it again for the plan.
pub fn check_protect_genesis_history(
    body: &SeatListBody,
    history_setting: bool,
    wipe_history: Option<bool>,
    now: Timestamp,
) -> Result<Option<ProtectedHistory>> {
    let (boundary, wiped) = match &body.v2 {
        Some(lines) => (
            lines.history_boundary.as_deref(),
            lines.pre_history == SeatListPreHistory::Wiped,
        ),
        None => (None, false),
    };
    if wipe_history.is_some_and(|flag| flag != wiped) {
        return Err(invalid(
            "wipe_history disagrees with the signed pre_history",
        ));
    }
    // `wiped` needs a boundary (the parse refuses it without one)
    let Some(boundary) = boundary else {
        return Ok(None);
    };
    if !history_setting {
        return Err(invalid("history_boundary is refused until S4"));
    }
    if !(body.seats.len() == 1 && body.seats[0] == body.signer_user_id) {
        return Err(invalid("a genesis with a boundary seats only its signer"));
    }
    let now_ms = now
        .duration_since(Timestamp::UNIX_EPOCH)
        .whole_milliseconds();
    if i128::from(ulid_time(boundary)?) > now_ms + i128::from(MAX_BOUNDARY_CLOCK_SKEW_MS) {
        return Err(invalid("history_boundary is in the future"));
    }

    Ok(Some(ProtectedHistory {
        boundary: boundary.to_string(),
        wipe: if wiped {
            HistoryWipe::Requested {
                at: now,
                by: body.signer_user_id.clone(),
            }
        } else {
            HistoryWipe::None
        },
    }))
}

/// 4.3 step 4d (S2-D20): a seat write whose planner releases anyone needs a
/// non-empty `X-Audit-Log-Reason` (a whitespace-only one counts as empty),
/// else `RemovalReasonRequired`. Checked against the planner's `released`
/// set AFTER step 4, so the retry of a list that landed (an `Unchanged`
/// decision, nothing released) succeeds without the header.
/// `plan_seat_list_write` runs it on `SeatListWriteInput.removal_reason`.
pub fn check_removal_reason(released: &[String], reason: Option<&str>) -> Result<()> {
    if !released.is_empty() && reason.is_none_or(|reason| reason.trim().is_empty()) {
        return Err(create_error!(RemovalReasonRequired));
    }
    Ok(())
}

/// What a seat-list write does to the open Text group's `signer_lost`
/// (4.3 step 7, S2-D17d)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerLostResolution {
    /// No open Text group, or it carries no `signer_lost`: nothing to do
    NotLost,
    /// Clear `signer_lost` in the same transaction and append
    /// `pending_device` (if any) to `pending_device_removals`
    Clear {
        /// The lost device, ONLY if it still holds a leaf in the open group
        /// and is not already pending (#224)
        pending_device: Option<MlsPendingDeviceRemoval>,
    },
}

/// 4.3 step 7 additions (S2-D17d; #222, #224). While the open Text group
/// carries `signer_lost`, a list signed by ANOTHER device clears it only
/// when it carries an authority CHANGE (`authority_change`, step 3b's
/// result: a version above the stored one) whose `owner_devices` omits the
/// lost device; the lost device is then queued for removal only if it holds
/// a leaf in the open group (a recovery successor never contains it, and an
/// entry nobody can remove would freeze every send). Any other list is
/// refused with `ProtectedChannelResecuring { reason: "owner_device_lost" }`
/// and nothing is written: landing it would leave `signer_lost` set under a
/// live signer. That includes a list signed by the lost device itself,
/// which the doc does not name: the device was revoked, so the route never
/// lets it sign, and refusing here fails closed if one gets through.
/// `plan_seat_list_write` runs it after step 5b and the drivers write the
/// resolution in the list's transaction.
pub fn resolve_signer_lost(
    text_group: Option<&MlsGroup>,
    body: &SeatListBody,
    authority_change: Option<&ChannelAuthorityBody>,
    now: Timestamp,
) -> Result<SignerLostResolution> {
    let Some(group) = text_group else {
        return Ok(SignerLostResolution::NotLost);
    };
    let Some(lost) = &group.signer_lost else {
        return Ok(SignerLostResolution::NotLost);
    };

    let another_device =
        body.signer_user_id != lost.user_id || body.signer_device_id != lost.device_id;
    let omits_lost = authority_change.is_some_and(|authority| {
        !authority
            .owner_devices
            .iter()
            .any(|device| device.device_id == lost.device_id)
    });
    if !another_device || !omits_lost {
        return Err(create_error!(ProtectedChannelResecuring {
            reason: "owner_device_lost".to_string()
        }));
    }

    let holds_leaf = group.has_member(&lost.user_id, &lost.device_id);
    let already = group
        .pending_device_removals
        .iter()
        .any(|pending| pending.user_id == lost.user_id && pending.device_id == lost.device_id);
    Ok(SignerLostResolution::Clear {
        pending_device: (holds_leaf && !already).then(|| MlsPendingDeviceRemoval {
            user_id: lost.user_id.clone(),
            device_id: lost.device_id.clone(),
            created_at: now,
        }),
    })
}

/// 2.5 "Clearing" (#224): drop every `pending_device_removals` entry whose
/// device holds no leaf in `group`. An entry for a device that is not a
/// member is one no commit can satisfy, and rule 3a would refuse every Add
/// behind it. Every write that changes `members` or the list calls this in
/// the same transaction.
pub fn retain_member_pending_device_removals(group: &mut MlsGroup) {
    let pending = std::mem::take(&mut group.pending_device_removals);
    group.pending_device_removals = pending
        .into_iter()
        .filter(|pending| group.has_member(&pending.user_id, &pending.device_id))
        .collect();
}

/// Who a Text group create may name as its creator (6.1). The route decides
/// it from its own reads; [`prepare_text_group`] re-checks it against the
/// newest list the create's transaction read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextGroupCreator {
    /// The rule (6.1, DECISION (W0-fix)): the device that signed the newest
    /// stored list
    SignerDevice,
    /// The S2-D17d recovery exception (6.1, #213): another device of the
    /// signer USER creates a successor while the open group carries
    /// `signer_lost` or the stored list's signer device has no registered
    /// identity. `lost_device_id` is the signer device the route found
    /// lost: a list naming another signer device has landed since, so the
    /// premise no longer holds and the create is refused.
    SignerUserRecovery { lost_device_id: String },
}

/// Validate a Text group create request against the newest seat list and
/// fill in the server-owned Text fields (2.5, 6.1): `kind = Text`,
/// `seat_list_ad_sha256` from `list`, no pending removals of either kind,
/// no `signer_lost` and no `rejoin_readd` (S2; a successor create copies
/// the superseded group's `signer_lost` itself, #213), and the creator's
/// `member_added` entry at epoch 0. `creator` names the 6.1 creator rule
/// the route applied; a recovery create is never a first group.
///
/// S4 (2.5 "S4", fix F3, #287): `history_visible_at_create`, the
/// visibility of the group's epoch 0, from the list this create binds, for
/// EVERY Text create (a first group too): `seat_list_history_visible`.
pub fn prepare_text_group(
    group: &MlsGroup,
    list: &SeatList,
    creator: &TextGroupCreator,
) -> Result<MlsGroup> {
    match group.generation {
        Some(generation) if generation <= MAX_TEXT_GROUP_GENERATION => {}
        _ => return Err(invalid("text group generation")),
    }
    if !group.open
        || group.current_epoch != 0
        || group.closed_at.is_some()
        || group.superseded_by.is_some()
    {
        return Err(invalid("text group must be created open at epoch 0"));
    }
    if group.members != vec![group.created_by.clone()] {
        return Err(invalid("text group must start with its creator only"));
    }
    let by_signer_user = group.created_by.user_id == list.signer_user_id;
    match creator {
        TextGroupCreator::SignerDevice => {
            if !by_signer_user || group.created_by.device_id != list.signer_device_id {
                return Err(invalid(
                    "only the current seat list signer device may create",
                ));
            }
        }
        TextGroupCreator::SignerUserRecovery { lost_device_id } => {
            if !by_signer_user
                || group.generation == Some(0)
                || list.signer_device_id != *lost_device_id
                || group.created_by.device_id == *lost_device_id
            {
                return Err(invalid(
                    "only a device of the seat list signer may create a recovery successor",
                ));
            }
        }
    }

    let mut prepared = group.clone();
    prepared.kind = MlsGroupKind::Text;
    prepared.seat_list_ad_sha256 = Some(list.commit_ad_sha256()?);
    prepared.pending_removals = vec![];
    prepared.pending_device_removals = vec![];
    prepared.signer_lost = None;
    prepared.rejoin_readd = vec![];
    prepared.history_visible_at_create =
        Some(seat_list_history_visible(&SeatListBody::parse(&list.body)?));
    prepared.member_added = vec![MlsMemberAdded {
        user_id: group.created_by.user_id.clone(),
        device_id: group.created_by.device_id.clone(),
        epoch: 0,
        at: group.created_at,
    }];
    Ok(prepared)
}

/// The history visibility a seat list gives a transition (2.5 "S4", O-2):
/// `true` only for a v2 list with `history:visible`; a v2 `hidden` list and
/// every v1 list (which promised nothing) give `false`
pub fn seat_list_history_visible(body: &SeatListBody) -> bool {
    body.v2
        .as_ref()
        .is_some_and(|lines| lines.history == SeatListHistory::Visible)
}

/// Successor rule (6.1): the superseded group is a Text group of the same
/// channel, and the new generation is its generation + 1
pub fn check_text_successor(superseded: &MlsGroup, successor: &MlsGroup) -> Result<()> {
    if superseded.channel_id != successor.channel_id {
        return Err(invalid("superseded group belongs to another channel"));
    }
    if superseded.kind != MlsGroupKind::Text {
        return Err(invalid("superseded group is not a text group"));
    }
    let expected = superseded
        .generation
        .and_then(|generation| generation.checked_add(1));
    if expected.is_none() || expected != successor.generation {
        return Err(invalid(
            "successor generation must be superseded generation + 1",
        ));
    }
    Ok(())
}

/// N3 (#128 as amended by decision 4 (W2)): whether a protect is the
/// byte-identical retry of a protect that already landed, i.e. its genesis
/// list (`body`, `signature`, the declared signer device, no handover) is
/// the stored list and that list is still version 1. The driver decides this
/// inside the protect transaction BEFORE any write and before the protect
/// preconditions, which the landed protect itself made false; once the
/// stored list has moved past version 1 it is never a retry.
pub fn is_genesis_reprotect(submission: &SeatListSubmission, stored: &SeatList) -> bool {
    stored.version == 1
        && submission.body == stored.body
        && submission.signature == stored.signature
        && submission.signer_device_id == stored.signer_device_id
        && submission.handover.is_none()
}

/// The server of a channel that can hold a seat list (a server
/// `TextChannel`); `None` for every other kind
pub fn seat_list_channel_server(channel: &Channel) -> Option<&str> {
    match channel {
        Channel::TextChannel { server, .. } => Some(server.as_str()),
        _ => None,
    }
}

/// The `history_boundary` a submitted list carries, read leniently: `None`
/// when the body does not parse (the strict parse that follows refuses it)
/// or has no boundary. Lets the protect preconditions run before the strict
/// parse, in their S1 order.
pub fn submitted_history_boundary(submission: &SeatListSubmission) -> Option<String> {
    SeatListBody::parse(&submission.body)
        .ok()
        .and_then(|body| body.v2)
        .and_then(|lines| lines.history_boundary)
}

/// Protect preconditions the driver re-checks inside the protect
/// transaction, so a racing message or edit cannot slip between the route's
/// checks and the flag write (7.2 protect): a server `TextChannel`, not yet
/// protected, no `voice`, not an announcement channel. With an EMPTY
/// `boundary` also no messages as far as `last_message_id` tells (S1); with
/// a boundary B the channel may hold messages and the driver's
/// in-transaction probe alone decides (no row newer than B, 7.2 "S4": the
/// four S1 refusals of a non-empty channel change together).
pub fn check_channel_protectable(channel: Option<&Channel>, boundary: Option<&str>) -> Result<()> {
    match channel {
        None => Err(create_error!(NotFound)),
        Some(Channel::TextChannel {
            protected: false,
            last_message_id,
            voice: None,
            announcement,
            ..
        }) if *announcement != Some(true) && (boundary.is_some() || last_message_id.is_none()) => {
            Ok(())
        }
        Some(_) => Err(create_error!(InvalidOperation)),
    }
}

/// 4.3 "S4", the wipe write's channel, re-read inside its transaction: a
/// protected server `TextChannel` whose `protected_history` carries the
/// list's boundary `boundary`, else `InvalidOperation` (the route's answer
/// for a channel without a boundary; `NotFound` when it is gone). `true`
/// when the wipe still has to be requested (`HistoryWipe::None`); a wipe
/// already `Requested` or `Done` is never written again (2.1 "S4": the
/// state only moves `None -> Requested -> Done`).
pub fn check_channel_wipeable(channel: Option<&Channel>, boundary: &str) -> Result<bool> {
    match channel {
        None => Err(create_error!(NotFound)),
        Some(Channel::TextChannel {
            protected: true,
            protected_history: Some(history),
            ..
        }) if history.boundary == boundary => Ok(matches!(history.wipe, HistoryWipe::None)),
        Some(_) => Err(create_error!(InvalidOperation)),
    }
}

/// A first Text group (no `supersedes`) is generation 0 (6.1)
pub fn check_text_first_generation(group: &MlsGroup) -> Result<()> {
    if group.generation != Some(0) {
        return Err(invalid("first text group must be generation 0"));
    }
    Ok(())
}
