//! Protected channels: entitlements, seats and the owner-signed seat list
//! (`docs/protected-channels-design.md` sections 2.2 to 2.5, 4.1, 4.3, 3.12.1).
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

use crate::{Channel, MlsGroup, MlsGroupKind, MlsMemberAdded, MlsPendingRemoval};

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

/// Highest Text group generation (6.1)
pub const MAX_TEXT_GROUP_GENERATION: u32 = 63;

/// `2^53 - 1`: the bound on every canonical integer that must survive JSON (0.2)
pub const MAX_CANONICAL_INT: i64 = 9_007_199_254_740_991;

/// Seat-list body context line (0.4, WIRE FORMAT, never rename)
pub const CONTEXT_SEAT_LIST: &str = "sloga-seat-list-v1";

/// Commit `authenticated_data` context field (3.12.1, WIRE FORMAT, never rename)
pub const CONTEXT_COMMIT_AD: &str = "sloga-text-commit-ad-v1";

/// Length of an Ed25519 signature in unpadded b64 (0.1)
const SIGNATURE_B64_LEN: usize = 86;

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
    }

    /// An owner handover statement and its signature (2.4, 4.6)
    pub struct SignedHandover {
        /// Exact canonical handover body (4.6)
        pub body: String,
        /// b64 Ed25519 signature by the `from` device
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

    /// Release this seat at `now`, starting the 14-day cooldown
    pub fn release(&mut self, now: Timestamp) -> Result<()> {
        self.released_at = Some(now);
        self.cooldown_until = Some(seat_cooldown_until(now)?);
        Ok(())
    }

    /// Make this seat active again at `now`
    pub fn reactivate(&mut self, now: Timestamp) {
        self.seated_at = now;
        self.released_at = None;
        self.cooldown_until = None;
    }
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

/// A parsed seat-list body (4.1)
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
}

/// ULID, Crockford base32, uppercase, 26 chars (0.1)
pub fn is_valid_ulid_id(value: &str) -> bool {
    value.len() == 26
        && value.bytes().all(|byte| {
            matches!(byte, b'0'..=b'9' | b'A'..=b'H' | b'J' | b'K' | b'M' | b'N' | b'P'..=b'T' | b'V'..=b'Z')
        })
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

impl SeatListBody {
    /// Strict parse (4.1, including the W0-fix3 bounds). Refuses anything
    /// that is not the one valid byte string for its content: nothing is
    /// trimmed, normalized or re-sorted.
    pub fn parse(body: &str) -> Result<SeatListBody> {
        if body.len() > MAX_SEAT_LIST_BODY_LEN {
            return Err(invalid("seat list body too long"));
        }
        if body.contains('\r') {
            return Err(invalid("seat list body contains CR"));
        }

        let lines: Vec<&str> = body.split('\n').collect();
        if lines.len() != 9 {
            return Err(invalid("seat list body must have exactly 9 lines"));
        }
        if lines[0] != CONTEXT_SEAT_LIST || lines[1] != "v:1" {
            return Err(invalid("seat list context or format version"));
        }

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
        })
    }

    /// Canonical builder (4.1): sorts and de-duplicates `seats`, then
    /// re-parses its own output so it can never emit a body `parse` refuses.
    pub fn build(&self) -> Result<String> {
        let mut seats = self.seats.clone();
        seats.sort();
        seats.dedup();

        let body = format!(
            "{CONTEXT_SEAT_LIST}\nv:1\nchannel_id:{}\nversion:{}\ndevice_cap:{}\nissued_at:{}\nsigner_user_id:{}\nsigner_device_id:{}\nseats:{}",
            self.channel_id,
            self.version,
            self.device_cap,
            self.issued_at,
            self.signer_user_id,
            self.signer_device_id,
            seats.join(",")
        );

        SeatListBody::parse(&body)?;
        Ok(body)
    }
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
    /// The commit `authenticated_data` every Text commit must carry while
    /// this row is the newest list (3.12.1): context, body, raw signature,
    /// `u16_be` handover count, then each handover body and raw signature,
    /// every field `u16_be(len) || bytes`.
    pub fn commit_ad(&self) -> Result<Vec<u8>> {
        if self.body.len() > MAX_SEAT_LIST_BODY_LEN {
            return Err(invalid("seat list body too long"));
        }
        if self.handovers.len() > MAX_SEAT_LIST_HANDOVERS {
            return Err(invalid("handover chain too long"));
        }

        let mut out = Vec::new();
        push_ad_field(&mut out, CONTEXT_COMMIT_AD.as_bytes())?;
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
    /// `seat_list_ad_sha256` while this row is the newest list (2.5)
    pub fn commit_ad_sha256(&self) -> Result<String> {
        Ok(to_hex(&Sha256::digest(self.commit_ad()?)))
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
            },
            SeatListWriteDecision::Apply(plan) => plan.outcome(),
        }
    }
}

/// Plan a protect (genesis) or seat PUT: the database-side parts of 4.3.
///
/// Order (4.3, W0-fix8): parse (step 1) first; then the version rule
/// (step 4), where a byte-identical re-PUT returns the stored row
/// IMMEDIATELY, before the signer-leaf check (5b), the seat claims (7) and
/// the handover append (8); only then 5b, 7 and 8. Route-side checks
/// (authorization, session binding, signature, server membership, bots and
/// staff, the `device_cap` ceiling) are not repeated here.
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
        (SeatListWriteKind::Put, None) => {
            return Err(invalid("channel has no seat list"));
        }
        (SeatListWriteKind::Put, Some(stored)) => {
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

    // Step 5b: when the channel has an open Text group, the signer device
    // must hold a leaf in it (genesis exempt: no group can exist yet)
    if input.kind == SeatListWriteKind::Put {
        if let Some(group) = input.text_group {
            if !group.has_member(&body.signer_user_id, &body.signer_device_id) {
                return Err(invalid("seat list signer device holds no leaf"));
            }
        }
    }

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
                // slot (2.3 DECISION (W0)); an expired one is a new slot
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
                });
                claimed.push(user_id.to_string());
            }
        }
    }

    for seat in input.seats {
        if seat.is_active() && !desired.contains(seat.user_id.as_str()) {
            let mut seat = seat.clone();
            seat.release(now)?;
            released.push(seat.user_id.clone());
            seat_rows.push(seat);
        }
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
    };
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
    }))
}

/// Validate a Text group create request against the newest seat list and
/// fill in the server-owned Text fields (2.5, 6.1): `kind = Text`,
/// `seat_list_ad_sha256` from `list`, no pending removals, and the
/// creator's `member_added` entry at epoch 0.
pub fn prepare_text_group(group: &MlsGroup, list: &SeatList) -> Result<MlsGroup> {
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
    if group.created_by.user_id != list.signer_user_id
        || group.created_by.device_id != list.signer_device_id
    {
        return Err(invalid(
            "only the current seat list signer device may create",
        ));
    }

    let mut prepared = group.clone();
    prepared.kind = MlsGroupKind::Text;
    prepared.seat_list_ad_sha256 = Some(list.commit_ad_sha256()?);
    prepared.pending_removals = vec![];
    prepared.member_added = vec![MlsMemberAdded {
        user_id: group.created_by.user_id.clone(),
        device_id: group.created_by.device_id.clone(),
        epoch: 0,
        at: group.created_at,
    }];
    Ok(prepared)
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

/// Protect preconditions the driver re-checks inside the protect
/// transaction, so a racing message or edit cannot slip between the route's
/// checks and the flag write (7.2 protect): a server `TextChannel`, not yet
/// protected, no `voice`, not an announcement channel, no messages
pub fn check_channel_protectable(channel: Option<&Channel>) -> Result<()> {
    match channel {
        None => Err(create_error!(NotFound)),
        Some(Channel::TextChannel {
            protected: false,
            last_message_id: None,
            voice: None,
            announcement,
            ..
        }) if *announcement != Some(true) => Ok(()),
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
