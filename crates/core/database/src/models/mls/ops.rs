use std::collections::HashSet;

use iso8601_timestamp::{Duration, Timestamp};
use revolt_result::Result;

use crate::{
    mls_text_enforced_device_cap, removal_reason_rank, retain_member_pending_device_removals,
    E2EEIdentity, InsertOutcome, MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupCreateOutcome,
    MlsGroupKind, MlsHistoryLink, MlsJoinIntent, MlsKeyPackage, MlsMemberAdded, MlsMemberDevice,
    MlsPendingDeviceRemoval, MlsRejoinReadd, MlsRemovalReason, MlsRemovedReason, SeatList,
    SeatListBody, HISTORY_LINK_MAX_CANDIDATES, HISTORY_LINK_PAGE_MAX, HISTORY_LINK_PAGE_MIN,
    MAX_MLS_TEXT_GROUP_MEMBERS,
};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[cfg(all(test, feature = "mongodb"))]
pub(crate) use mongodb::{HISTORY_LINK_RETRIES, TEXT_COMMIT_RETRIES};

#[async_trait]
pub trait AbstractMls: Sync + Send {
    /// Insert (or overwrite by id) a batch of one-time KeyPackages
    async fn insert_mls_key_packages(&self, packages: &[MlsKeyPackage]) -> Result<()>;

    /// Count remaining ONE-TIME KeyPackages for a device (the last-resort
    /// package lives outside the cap)
    async fn count_mls_key_packages(&self, user_id: &str, device_id: &str) -> Result<u64>;

    /// Upsert a batch of one-time KeyPackages, then prune the device's
    /// OLDEST one-time packages down to `max` so a replenish can never be
    /// refused for a full directory (publish-UX plan §3.4).
    ///
    /// Prune ordering is `created_at` ascending, tie-broken by id ascending
    /// — identical in both drivers. The prune NEVER touches the last-resort
    /// row (outside the cap) or the INVOKING call's own refs (a concurrent
    /// same-device publish may still prune this batch as "oldest" — ≤ cap
    /// and a correct count either way; packages are fungible consumables).
    /// Pruned entries just stop being claimable; the Welcome acceptance
    /// gate keys on group_id, not a specific ref.
    ///
    /// Returns the device's resulting one-time count (the client's
    /// replenish watermark).
    async fn insert_mls_key_packages_capped(
        &self,
        user_id: &str,
        device_id: &str,
        packages: &[MlsKeyPackage],
        max: usize,
    ) -> Result<u64>;

    /// Atomically consume one ONE-TIME KeyPackage for a device; None at
    /// exhaustion (callers then serve the last-resort package, flagged
    /// reusable, or fail loudly if there is none)
    async fn consume_mls_key_package(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<MlsKeyPackage>>;

    /// Fetch (WITHOUT consuming) any one stored package for a device —
    /// one-time or last-resort. Serves the MLS signature-key immutability
    /// check at publish.
    async fn fetch_one_mls_key_package(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<MlsKeyPackage>>;

    /// Fetch (WITHOUT consuming) the device's last-resort package, if any
    async fn fetch_mls_last_resort_key_package(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<MlsKeyPackage>>;

    /// Replace the device's last-resort package: removes any previous
    /// last-resort rows for the device, then stores the new one
    async fn replace_mls_last_resort_key_package(&self, package: &MlsKeyPackage) -> Result<()>;

    /// Delete ALL KeyPackages for a device (revocation cascade). Idempotent;
    /// returns how many were removed.
    async fn delete_mls_key_packages(&self, user_id: &str, device_id: &str) -> Result<usize>;

    /// TTL sweep: delete KeyPackages whose `expires_at` has passed
    async fn delete_expired_mls_key_packages(&self, now: Timestamp) -> Result<usize>;

    /// Register a group — the channel-scoped create arbitration (plan §1.2).
    ///
    /// At most one OPEN group OF EACH KIND may exist per channel (partial
    /// unique index on `(channel_id, kind)` / single-Mutex contains-check),
    /// so a channel's Call and Text groups coexist. A racing second creator
    /// of the same kind gets `Conflict { open_group_id }` carrying the
    /// winner so it can fall into the join path. With `supersedes`
    /// (poisoned-epoch recovery §1.4) the named group, which must be of the
    /// same channel AND kind, is atomically closed (with `superseded_by`
    /// back-pointer) and the successor created; if the named group is not
    /// the channel's open group of that kind the call conflicts with the
    /// actual open group instead.
    ///
    /// CALL GROUPS ONLY: a group with `kind: Text` is refused
    /// (`InvalidOperation`). Text groups are created only through
    /// `AbstractProtectedChannels::create_text_mls_group`, which reads the
    /// seat list and sets the server-owned Text fields in one transaction.
    async fn create_mls_group(
        &self,
        group: &MlsGroup,
        supersedes: Option<&str>,
    ) -> Result<MlsGroupCreateOutcome>;

    /// Fetch a group by id
    async fn fetch_mls_group(&self, group_id: &str) -> Result<MlsGroup>;

    /// Fetch the channel's open group of `kind`, if any. A Call lookup also
    /// matches a stored group with no `kind` field (pre-migration rows are
    /// Call groups), so Call callers behave exactly as before.
    async fn fetch_open_mls_group_for_channel(
        &self,
        channel_id: &str,
        kind: MlsGroupKind,
    ) -> Result<Option<MlsGroup>>;

    /// Close a group (call ended / room_finished). Idempotent; returns
    /// whether the group was open.
    ///
    /// CALL GROUPS ONLY: a Text group is refused (`InvalidOperation`) and
    /// left untouched, so a kind-blind caller (room_finished, reconcile, the
    /// join-intent sole-member close) can never close a protected channel's
    /// group, and a route bug fails loudly instead of silently. Text groups
    /// are closed only by supersession
    /// (`AbstractProtectedChannels::create_text_mls_group` with
    /// `supersedes`) and by the channel delete cascade
    /// (`delete_protected_channel_data`), both in the protected-channels
    /// models (design §2.5 "Close paths touch Call groups only", §6.3).
    async fn close_mls_group(&self, group_id: &str) -> Result<bool>;

    /// Submit a commit for epoch `commit.epoch` — the one-winner-per-epoch
    /// arbitration (plan §2.2.3).
    ///
    /// Enforced here, per driver, under its atomicity primitive:
    /// - the group must be open,
    /// - `commit.epoch` must be exactly `current_epoch + 1` (no skip-ahead,
    ///   invariant 10),
    /// - the one-device-per-user rule (plan §1.5): an added (user, device)
    ///   must not collide with a live leaf of the same user on a different
    ///   device,
    /// - unique insert on `{group_id}:{epoch}` — the CAS; the loser gets
    ///   `Lost { winning }` with the stored winner to rebase onto,
    /// - on win: `current_epoch` bumped and the roster mirror updated from
    ///   the asserted added/removed lists, by a FIELD-LEVEL write of
    ///   `current_epoch` and `members` only (design §2.5 (b)): no other
    ///   field of the group document is ever rewritten.
    ///
    /// CALL GROUPS ONLY. A Text group is refused (`InvalidOperation`): Text
    /// commits go through [`AbstractMls::insert_mls_text_commit`], and the
    /// Mongo repair loop never applies effects to a Text group.
    async fn insert_mls_commit(&self, commit: &MlsCommit) -> Result<MlsCommitOutcome>;

    /// Submit a commit to a protected-channel TEXT group (design §2.5
    /// "Commit transaction", §3.12.2, §6.1). One atomic unit per driver
    /// (Mongo multi-document transaction retried on
    /// `TransientTransactionError` / `UnknownTransactionCommitResult`, at
    /// most 5 attempts; Reference under the lock order
    /// `channel_seat_lists -> channel_seats -> mls_groups -> mls_commits ->
    /// mls_join_intents -> e2ee_identities`). In order:
    ///
    /// 0. a TEXT-MARKED commit row already at `{group}:{epoch}` returns
    ///    `Lost { winning }` BEFORE any validity check (idempotent
    ///    resubmit). The route's ACCESS checks must already have run. An
    ///    unmarked row at that id is not this plane's (R22: a Call-plane
    ///    stray left by a squat at the derived id) and never answers here;
    ///    see step 3.
    /// 1. read the group (`kind: Text`), the channel's newest seat list,
    ///    the removed devices' stored join intents and E2EE identities, and
    ///    CLAIM the added devices' E2EE identities (S2-D17c; Mongo: `$inc
    ///    txn_serial` on each identity document, so a concurrent revocation
    ///    write-conflicts with the Add);
    /// 2. validity: open; committer is a member (`ProtectedChannelResecuring
    ///    { reason: "not_member" }`); `epoch == current_epoch + 1`;
    ///    `seat_list_ad_sha256 == ad_sha256` (`stale_seat_list`); while
    ///    `signer_lost` is set, an Add of any user but the signer user
    ///    (`owner_device_lost`); Add-clears-pending: an Add must remove every
    ///    member device either pending list names (`pending_removal`); the
    ///    Remove rule (rules 1 to 6 and 3a, the Text rule-6 window from
    ///    `text_rejoin_window_secs`); every added device not already a
    ///    member, not also removed, its user's `channel_seats` row ACTIVE
    ///    (`NotSeated`; Mongo: a conditional write on that row, so a racing
    ///    seat release write-conflicts), on the newest seat list, and its
    ///    identity present (`FailedValidation`); the enforced device cap
    ///    `min(signed, entitlement_device_cap)` over every post-commit leaf;
    ///    the [`MAX_MLS_TEXT_GROUP_MEMBERS`] leaf cap;
    /// 3. delete an unmarked row at `{group}:{epoch}` (R22 stray; logged as
    ///    `AUDIT mls_text_stray_replaced`, ids only), then insert the commit
    ///    row (with `rejoin_intents` and `removed_reasons` filled, `welcome`
    ///    as given) Text-marked. The marker is storage-level, not a field
    ///    of [`MlsCommit`]: Mongo stores `kind: "Text"` on the document,
    ///    Reference keys the row under `text:{group}:{epoch}`;
    /// 4. field-level group update filtered on `{ _id, open, kind: Text,
    ///    current_epoch: e - 1, seat_list_ad_sha256: ad_sha256 }`: `$set`
    ///    `current_epoch`, `members`, `member_added`, and `rejoin_readd`
    ///    when it changes (a rule-6 eviction writes an entry, the device's
    ///    re-Add consumes it); `$pull` every pending removal whose user has
    ///    no member device left and every pending device entry whose device
    ///    holds no leaf (2.5 "Clearing"); `keys_received_at` set on each
    ///    added user's active seat row that has none;
    /// 5. delete the join intents of every added device and of every
    ///    rule-6-consumed intent.
    ///
    /// `ad_sha256` is [`crate::SeatList::commit_ad_sha256`] of the stored
    /// seat-list row whose `commit_ad()` the route byte-compared with the
    /// commit's received `authenticated_data` (§3.12.2 pre-check), i.e. the
    /// lowercase hex SHA-256 of the received AD. That helper is the single
    /// source of truth for the hash, shared with every seat-list write.
    /// Mongo retries back off with jitter between attempts (the
    /// protected-channels `run_transaction!` pattern).
    /// `entitlement_device_cap` is the channel's effective entitlement
    /// device cap (`0` = unlimited). `commit.created_at`
    /// is "now" for the rejoin window, `member_added.at`, `rejoin_readd`
    /// and `keys_received_at`. The submitted `commit.rejoin_intents` and
    /// `commit.removed_reasons` are ignored and replaced.
    async fn insert_mls_text_commit(
        &self,
        commit: &MlsCommit,
        ad_sha256: &str,
        entitlement_device_cap: u32,
    ) -> Result<MlsCommitOutcome>;

    /// Gap refetch: stored winning commits with epoch >= `from_epoch`,
    /// ascending, bounded by `limit`. Every row under the group id, marked
    /// or not: the CALL plane's read. Text routes use
    /// [`AbstractMls::fetch_mls_text_commits_from`].
    async fn fetch_mls_commits_from(
        &self,
        group_id: &str,
        from_epoch: i64,
        limit: i64,
    ) -> Result<Vec<MlsCommit>>;

    /// Text-group gap refetch and existing-row read (design §2.5 step 0,
    /// §6.1 "Commit fetch"): as [`AbstractMls::fetch_mls_commits_from`],
    /// but ONLY rows [`AbstractMls::insert_mls_text_commit`] wrote
    /// (Text-marked). An unmarked row under a Text group's id (R22: a
    /// Call-plane stray, or a Text row written before the marker existed)
    /// is never served.
    async fn fetch_mls_text_commits_from(
        &self,
        group_id: &str,
        from_epoch: i64,
        limit: i64,
    ) -> Result<Vec<MlsCommit>>;

    /// The Welcome route's read (design §7.2, S2-D29): the NEWEST
    /// Text-marked commit row of the group whose `added` holds `(user_id,
    /// device_id)`, Welcome included, or `None`. The route still checks
    /// that the device is a member whose `member_added.epoch` is that
    /// row's epoch. Nothing but the Welcome route may serve the row's
    /// `welcome`.
    async fn fetch_mls_text_welcome(
        &self,
        group_id: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<MlsCommit>>;

    /// The oldest stored Text-marked commit epoch of the group (design
    /// §6.1 "Commit fetch", S2-D30), or `None` when it has none
    async fn fetch_mls_text_oldest_epoch(&self, group_id: &str) -> Result<Option<i64>>;

    /// Store (or refresh) a join intent, keyed by (group, user, device).
    /// Returns the previous intent for the key, if any (rate-limit anchor).
    async fn upsert_mls_join_intent(
        &self,
        intent: &MlsJoinIntent,
    ) -> Result<Option<MlsJoinIntent>>;

    /// Fetch every stored join intent for a group. Serves the dual-reload
    /// close check (rejoin plan §5): admission consumes a device's intent
    /// row (`insert_mls_commit` deletes intents for added devices), so an
    /// intent held by a CURRENT member means that device is mid-rejoin.
    async fn fetch_mls_join_intents_for_group(&self, group_id: &str)
        -> Result<Vec<MlsJoinIntent>>;

    /// Sweep CALL groups closed before `closed_threshold` or created before
    /// `created_threshold` (call groups are ephemeral — plan §2.5), along
    /// with their commits and join intents. Returns how many groups went.
    /// Never closes or deletes a Text group (design §2.5).
    async fn sweep_mls_groups(
        &self,
        closed_threshold: Timestamp,
        created_threshold: Timestamp,
    ) -> Result<usize>;

    /// Commit retention for Text groups (design §2.5, R9): delete the
    /// `mls_commits` rows of Text groups (open or closed) whose
    /// `created_at < older_than`. Call commits are never touched. Returns
    /// how many rows went.
    async fn prune_mls_text_commits(&self, older_than: Timestamp) -> Result<u64>;

    /// Store one history link (design 2.8, 3.14.6). The row is keyed by
    /// its SLOT `{group_id}:{epoch}:{writer_user_id}`, derived here (the
    /// given `link.id` is not trusted), so each writer USER holds at most
    /// one candidate per holder epoch, whichever of its devices wrote it.
    /// In one atomic unit (Mongo: a transaction whose FIRST write claims
    /// the holder group document, `$inc txn_serial`, the #143 pattern;
    /// Reference: `mls_groups -> mls_history_links`):
    ///
    /// 1. the shape rules of [`crate::check_history_link_wire`], and `size`
    ///    must be the decoded ciphertext length (`FailedValidation`);
    /// 2. the holder group must be a Text group, open or closed (else
    ///    `NotFound`);
    /// 3. a row in the slot: every field but `created_at` and `size` equal
    ///    is `Identical` (nothing written, the first `created_at` kept),
    ///    anything else `HistoryLinkExists`;
    /// 4. [`crate::HISTORY_LINK_MAX_CANDIDATES`] rows at the holder epoch
    ///    already: `HistoryLinkExists`;
    /// 5. the byte caps of `features.protected_channels`, over the stored
    ///    `size`s of the holder group's rows, refused only when the sum
    ///    plus `size` exceeds the cap: for the group
    ///    (`history_link_group_cap_bytes`) and for the writer user in that
    ///    group (`history_link_user_cap_bytes`) (`FailedValidation`).
    ///
    /// Route rules (6.1 "S4": access, the writer, membership, epochs,
    /// visibility, the signature) are the caller's and must already have
    /// run.
    async fn insert_mls_history_link(&self, link: &MlsHistoryLink) -> Result<InsertOutcome>;

    /// One page of holder group `group_id`'s history links (design 2.8):
    /// the rows with `epoch < before` (every epoch when `None`), sorted by
    /// `epoch` descending, then `created_at` ascending (millisecond
    /// precision on both drivers), then `writer_user_id`. `limit` is
    /// clamped to [`crate::HISTORY_LINK_PAGE_MIN`] ..=
    /// [`crate::HISTORY_LINK_PAGE_MAX`] and caps ROWS; a holder epoch is
    /// never split: a trailing epoch that does not fit whole is dropped,
    /// so every candidate of an epoch arrives on one page.
    async fn fetch_mls_history_links(
        &self,
        group_id: &str,
        before: Option<i64>,
        limit: i64,
    ) -> Result<Vec<MlsHistoryLink>>;

    /// Delete every history link held by `group_id` (design 2.8).
    /// Idempotent.
    async fn delete_mls_history_links_for_group(&self, group_id: &str) -> Result<()>;
}

/// The byte caps a history-link insert enforces (design 7.1 "S4")
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HistoryLinkCaps {
    /// Per holder group, over every writer
    pub group_bytes: u64,
    /// Per writer user per holder group
    pub user_bytes: u64,
}

impl HistoryLinkCaps {
    /// The configured caps (`features.protected_channels`)
    pub(crate) async fn configured() -> Self {
        let protected = revolt_config::config().await.features.protected_channels;
        HistoryLinkCaps {
            group_bytes: protected.history_link_group_cap_bytes,
            user_bytes: protected.history_link_user_cap_bytes,
        }
    }
}

/// What a holder group already stores, read inside the insert's atomic unit
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HistoryLinkUsage {
    /// Rows at the inserted link's holder epoch (one per writer user)
    pub epoch_writers: u64,
    /// Sum of `size` over the group's rows
    pub group_bytes: u64,
    /// Sum of `size` over the group's rows of the inserted link's writer
    pub user_bytes: u64,
}

/// The slot (row id) of a history link: one per (holder group, holder
/// epoch, writer USER), design 3.14.6 "Slots" (S4-RR-1: never per device)
pub(crate) fn history_link_slot_id(link: &MlsHistoryLink) -> String {
    MlsHistoryLink::composite_id(&link.group_id, link.epoch, &link.writer_user_id)
}

/// The row an insert stores: the shape rules, `size` equal to the decoded
/// ciphertext length (the caps sum it, so it is never taken on trust), and
/// the slot id
pub(crate) fn prepare_history_link_row(link: &MlsHistoryLink) -> Result<MlsHistoryLink> {
    let decoded = link.check_shape()?;
    if link.size != decoded {
        return Err(failed(
            "history link size must be the decoded ciphertext length",
        ));
    }
    Ok(MlsHistoryLink {
        id: history_link_slot_id(link),
        ..link.clone()
    })
}

/// A slot already holds `stored`: byte-identical (every field but
/// `created_at` and `size`) is `Identical`, anything else
/// `HistoryLinkExists` (first write wins per writer user)
pub(crate) fn history_link_existing_outcome(
    stored: &MlsHistoryLink,
    row: &MlsHistoryLink,
) -> Result<InsertOutcome> {
    let identical = stored.group_id == row.group_id
        && stored.epoch == row.epoch
        && stored.prev_group_id == row.prev_group_id
        && stored.prev_epoch == row.prev_epoch
        && stored.nonce == row.nonce
        && stored.ciphertext == row.ciphertext
        && stored.writer_user_id == row.writer_user_id
        && stored.writer_device_id == row.writer_device_id
        && stored.signature == row.signature;
    if identical {
        Ok(InsertOutcome::Identical)
    } else {
        Err(create_error!(HistoryLinkExists))
    }
}

/// Whether a new row fits: a free candidate slot at its holder epoch, then
/// both byte caps (refused only when `sum + size > cap`)
pub(crate) fn check_history_link_room(
    row: &MlsHistoryLink,
    usage: &HistoryLinkUsage,
    caps: HistoryLinkCaps,
) -> Result<()> {
    if usage.epoch_writers >= HISTORY_LINK_MAX_CANDIDATES as u64 {
        return Err(create_error!(HistoryLinkExists));
    }
    // `prepare_history_link_row` bounds `size` to 17 ..= 40960
    let size = u64::try_from(row.size).map_err(|_| failed("history link size out of range"))?;
    if usage.group_bytes.saturating_add(size) > caps.group_bytes {
        return Err(failed("history link group byte cap reached"));
    }
    if usage.user_bytes.saturating_add(size) > caps.user_bytes {
        return Err(failed("history link user byte cap reached"));
    }
    Ok(())
}

/// The stored usage of `row`'s holder group, from its rows (the Reference
/// driver; Mongo sums the same three values in one aggregation). A
/// negative stored `size` can only be a corrupt row: fail closed.
pub(crate) fn history_link_usage<'a>(
    rows: impl Iterator<Item = &'a MlsHistoryLink>,
    row: &MlsHistoryLink,
) -> Result<HistoryLinkUsage> {
    let (mut epoch_writers, mut group_bytes, mut user_bytes) = (0u64, 0i64, 0i64);
    for stored in rows.filter(|stored| stored.group_id == row.group_id) {
        group_bytes = group_bytes.saturating_add(stored.size);
        if stored.writer_user_id == row.writer_user_id {
            user_bytes = user_bytes.saturating_add(stored.size);
        }
        if stored.epoch == row.epoch {
            epoch_writers += 1;
        }
    }
    let unsigned = |sum: i64| {
        u64::try_from(sum).map_err(|_| create_database_error!("sum", "mls_history_links"))
    };
    Ok(HistoryLinkUsage {
        epoch_writers,
        group_bytes: unsigned(group_bytes)?,
        user_bytes: unsigned(user_bytes)?,
    })
}

/// A requested page size clamped to `HISTORY_LINK_PAGE_MIN ..=
/// HISTORY_LINK_PAGE_MAX` (design 2.8)
pub(crate) fn history_link_page_limit(limit: i64) -> usize {
    limit.clamp(HISTORY_LINK_PAGE_MIN, HISTORY_LINK_PAGE_MAX) as usize
}

/// Cut a page without splitting a holder epoch. `rows` are in page order
/// and the driver fetched up to `limit + 1` of them: the extra row tells
/// whether the epoch at the cut continues past it, and if it does that
/// whole epoch is dropped. At most five rows share an epoch and `limit` is
/// at least five, so a page with more rows behind it is never empty.
pub(crate) fn trim_history_link_page(
    mut rows: Vec<MlsHistoryLink>,
    limit: usize,
) -> Vec<MlsHistoryLink> {
    if rows.len() <= limit {
        return rows;
    }
    let next_epoch = rows[limit].epoch;
    rows.truncate(limit);
    rows.retain(|row| row.epoch != next_epoch);
    rows
}

/// Unix milliseconds of a timestamp: the precision Mongo stores
/// `created_at` at, used by the Reference driver's page order
pub(crate) fn history_link_created_ms(at: &Timestamp) -> i64 {
    at.duration_since(Timestamp::UNIX_EPOCH)
        .whole_milliseconds() as i64
}

/// The effects of an accepted Text commit, computed from ONE consistent read
/// inside the driver's atomic unit (design §2.5 steps 3 to 5)
#[derive(Debug)]
pub(crate) struct MlsTextCommitPlan {
    /// The row to insert (`rejoin_intents` filled from the stored intents)
    pub stored: MlsCommit,
    /// The roster after the commit
    pub members: Vec<MlsMemberDevice>,
    /// `member_added` after the commit
    pub member_added: Vec<MlsMemberAdded>,
    /// Pending-removal users to clear (no member device left)
    pub cleared_pending: Vec<String>,
    /// `pending_device_removals` after the commit (2.5 "Clearing", #224)
    pub pending_device_removals: Vec<MlsPendingDeviceRemoval>,
    /// The pending device entries the clearing dropped (Mongo `$pull`s them)
    pub cleared_pending_devices: Vec<MlsMemberDevice>,
    /// `rejoin_readd` after the commit, `Some` only when the commit
    /// changes it (S2-D32)
    pub rejoin_readd: Option<Vec<MlsRejoinReadd>>,
    /// The added users, once each: their active seat row gets
    /// `keys_received_at` when it has none (design §2.3)
    pub keys_received_users: Vec<String>,
    /// Join-intent row ids to delete (added devices + rule-6 consumed)
    pub consumed_intent_ids: Vec<String>,
}

fn failed(error: &str) -> revolt_result::Error {
    create_error!(FailedValidation {
        error: error.to_string()
    })
}

fn resecuring(reason: &str) -> revolt_result::Error {
    create_error!(ProtectedChannelResecuring {
        reason: reason.to_string()
    })
}

/// Text commit validity checks (design §2.5 step 2, §3.12.2, §6.1) and the
/// effects to apply, as ONE pure function shared by both drivers so they
/// cannot diverge. The existing-row check (step 0) is the caller's and has
/// already run.
///
/// - `seat_list`: the channel's newest stored seat-list row (read inside
///   the atomic unit);
/// - `stored_intents`: the stored join-intent rows of the REMOVED devices
///   (any subset; looked up by composite id inside the atomic unit);
/// - `revoked_identities`: `E2EEIdentity` composite ids of the removed
///   devices whose identity row was looked up inside the atomic unit and
///   found ABSENT (rule 4). Positive evidence of revocation: a device the
///   caller did not look up is never treated as revoked (fails closed).
/// - `active_seat_users`: the ADDED users whose `channel_seats` row is
///   ACTIVE (`released_at` unset) inside the atomic unit. Positive evidence
///   again: a user the caller did not check counts as not seated. The
///   driver must make this check conflict with a concurrent seat release
///   (Mongo: a conditional write on the seat row; Reference: the
///   `channel_seats` lock), because a forced release leaves the user on
///   the SIGNED list and writes no document the commit otherwise writes.
/// - `added_identities`: `E2EEIdentity` composite ids of the ADDED devices
///   whose identity row was found PRESENT (and, on Mongo, claimed) inside
///   the atomic unit (S2-D17c). Positive evidence: a device the caller did
///   not look up counts as unregistered.
/// - `rejoin_window_seconds`: the Text rule-6 window
///   ([`crate::mls_text_rejoin_window_seconds`] of the configured
///   `text_rejoin_window_secs`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_mls_text_commit(
    group: &MlsGroup,
    commit: &MlsCommit,
    ad_sha256: &str,
    seat_list: Option<&SeatList>,
    entitlement_device_cap: u32,
    stored_intents: &[MlsJoinIntent],
    revoked_identities: &HashSet<String>,
    active_seat_users: &HashSet<String>,
    added_identities: &HashSet<String>,
    rejoin_window_seconds: i64,
) -> Result<MlsTextCommitPlan> {
    if group.kind != MlsGroupKind::Text {
        return Err(create_error!(InvalidOperation));
    }

    if commit.group_id != group.id {
        return Err(failed("commit targets another group"));
    }

    if !group.open {
        return Err(failed("group is closed"));
    }

    // Committer membership. A device that lost its leaf takes the
    // wipe-and-rejoin path on this reason (design §2.5)
    if !group.has_member(&commit.committer.user_id, &commit.committer.device_id) {
        return Err(resecuring("not_member"));
    }

    // Epoch. An epoch at or below the current one whose row is gone (the
    // existing-row check found nothing) was pruned: 404 = desync
    if commit.epoch <= group.current_epoch {
        return Err(create_error!(NotFound));
    }
    if commit.epoch != group.current_epoch + 1 {
        return Err(failed("commit epoch must be exactly current_epoch + 1"));
    }

    // Seat-list binding: the AD must be the newest stored list's commit_ad
    if group.seat_list_ad_sha256.as_deref() != Some(ad_sha256) {
        return Err(resecuring("stale_seat_list"));
    }

    // The newest stored list, through the one canonical strict parser
    // (design §4.1). Its absence or corruption on an open Text group can
    // only be a broken invariant: fail closed
    let seat_list = seat_list.ok_or_else(|| failed("channel has no seat list"))?;
    let signed = SeatListBody::parse(&seat_list.body)
        .map_err(|_| failed("stored seat list is malformed"))?;
    if signed.channel_id != group.channel_id
        || seat_list.id != group.channel_id
        || signed.signer_user_id != seat_list.signer_user_id
        || signed.signer_device_id != seat_list.signer_device_id
    {
        return Err(failed(
            "stored seat list does not match its channel or signer",
        ));
    }
    let seated = |user_id: &str| signed.seats.iter().any(|seat| seat == user_id);

    // Declarations: no device twice, no device both added and removed
    // (no same-commit Remove + re-Add, W0-fix7)
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    for device in commit.added.iter().chain(commit.removed.iter()) {
        if !seen.insert((device.user_id.as_str(), device.device_id.as_str())) {
            let error = if commit.added.contains(device) && commit.removed.contains(device) {
                "device is both added and removed"
            } else {
                "duplicate device in fan-out lists"
            };
            return Err(failed(error));
        }
    }

    let removes = |user_id: &str, device_id: &str| {
        commit
            .removed
            .iter()
            .any(|removed| removed.user_id == user_id && removed.device_id == device_id)
    };

    if !commit.added.is_empty() {
        // While the list signer's device is lost, only the signer USER's
        // devices may be added (S2-D17d): growth stays frozen while the lost
        // device still holds a leaf and receives every new epoch's secrets
        if let Some(lost) = &group.signer_lost {
            if commit
                .added
                .iter()
                .any(|added| added.user_id != lost.user_id)
            {
                return Err(resecuring("owner_device_lost"));
            }
        }

        // Add-clears-pending (S2-D17b): an Add must remove, in the same
        // commit, every member device that either pending list names, so a
        // joiner never receives a roster with a device that must go. A
        // partial clear is refused. An entry naming no member is satisfied
        // (the clearing rule drops it)
        let users_cleared = group.pending_removals.iter().all(|pending| {
            group
                .member_devices_of(&pending.user_id)
                .all(|device| removes(&device.user_id, &device.device_id))
        });
        let devices_cleared = group.pending_device_removals.iter().all(|pending| {
            !group.has_member(&pending.user_id, &pending.device_id)
                || removes(&pending.user_id, &pending.device_id)
        });
        if !users_cleared || !devices_cleared {
            return Err(resecuring("pending_removal"));
        }
    }

    // Remove rule (design §3.12.2, rule 3a of §6.1 "S2 additions"). Every
    // admitting rule is evaluated and the highest-ranked one is stamped as
    // the advisory reason, from THIS transaction's reads (#222)
    let committer = &commit.committer;
    let committer_is_signer = committer.user_id == signed.signer_user_id
        && committer.device_id == signed.signer_device_id;
    let window_start = commit
        .created_at
        .checked_sub(Duration::seconds(rejoin_window_seconds))
        .ok_or_else(|| failed("invalid commit time"))?;

    let mut rejoin_intents: Vec<MlsJoinIntent> = Vec::new();
    let mut removed_reasons: Vec<MlsRemovedReason> = Vec::with_capacity(commit.removed.len());
    for removed in &commit.removed {
        if !group.has_member(&removed.user_id, &removed.device_id) {
            return Err(failed("removed device is not a member"));
        }

        if removed.user_id == committer.user_id && removed.device_id == committer.device_id {
            return Err(failed("a device cannot remove itself"));
        }

        let is_signer_device = removed.user_id == signed.signer_user_id
            && removed.device_id == signed.signer_device_id;

        // Rules 2 to 5 and 3a never apply to the current list signer's
        // device (rule 1)
        let mut admitting: Vec<MlsRemovalReason> = Vec::new();
        if !is_signer_device {
            if group.has_pending_removal(&removed.user_id) {
                admitting.push(MlsRemovalReason::PendingRemoval);
            }
            if removed.user_id == committer.user_id {
                admitting.push(MlsRemovalReason::OwnUser);
            }
            if group.pending_device_removals.iter().any(|pending| {
                pending.user_id == removed.user_id && pending.device_id == removed.device_id
            }) {
                admitting.push(MlsRemovalReason::PendingDevice);
            }
            if revoked_identities.contains(&E2EEIdentity::composite_id(
                &removed.user_id,
                &removed.device_id,
            )) {
                admitting.push(MlsRemovalReason::Revoked);
            }
            if committer_is_signer && !seated(&removed.user_id) {
                admitting.push(MlsRemovalReason::OffList);
            }
        }

        // Rule 6 (rejoin), for every device: a stored intent signed by THIS
        // device, outstanding (within the Text window) and created strictly
        // after the device's latest Add. No `member_added` entry = refused
        // (never "added at time zero"). An admitting intent is copied into
        // the row and consumed, so it evicts exactly once
        let intent_id =
            MlsJoinIntent::composite_id(&group.id, &removed.user_id, &removed.device_id);
        let added_at = group
            .member_added
            .iter()
            .find(|entry| entry.user_id == removed.user_id && entry.device_id == removed.device_id)
            .map(|entry| entry.at);
        let intent = stored_intents.iter().find(|intent| {
            intent.id == intent_id
                && intent.group_id == group.id
                && intent.user_id == removed.user_id
                && intent.device_id == removed.device_id
        });
        if let (Some(intent), Some(added_at)) = (intent, added_at) {
            if intent.created_at >= window_start && intent.created_at > added_at {
                admitting.push(MlsRemovalReason::Rejoin);
                rejoin_intents.push(intent.clone());
            }
        }

        let reason = admitting
            .into_iter()
            .max_by_key(|reason| removal_reason_rank(*reason))
            .ok_or_else(|| failed("removal not permitted"))?;
        removed_reasons.push(MlsRemovedReason {
            user_id: removed.user_id.clone(),
            device_id: removed.device_id.clone(),
            reason,
        });
    }

    // Add rules (design §6.1 "Commit with added"). ViewChannel and
    // "registered device" are route checks (W2). "Seated" is checked HERE,
    // inside the atomic unit, on the seat ROW: a forced release (kick, ban,
    // leave) releases the row but leaves the user on the signed list, so
    // the list alone would admit a just-released user. The list check
    // stays as well (an Add must match the list the AD embeds).
    for added in &commit.added {
        if group.has_member(&added.user_id, &added.device_id) {
            return Err(failed("added device is already a member"));
        }
        if !active_seat_users.contains(&added.user_id) {
            return Err(create_error!(NotSeated));
        }
        if !seated(&added.user_id) {
            return Err(failed("added user is not seated"));
        }
        // The added-identity claim (S2-D17c): with the revocation's second
        // pending pass, every ordering of a revocation and an Add ends with
        // no member or a pending entry
        if !added_identities.contains(&E2EEIdentity::composite_id(
            &added.user_id,
            &added.device_id,
        )) {
            return Err(failed("added device is not registered"));
        }
    }

    // The roster after the commit
    let mut members: Vec<MlsMemberDevice> = group
        .members
        .iter()
        .filter(|member| !commit.removed.contains(member))
        .cloned()
        .collect();
    members.extend(commit.added.iter().cloned());

    // The same typed errors the submit route answers for the same checks
    // (A5), so a race that only this re-check catches looks the same
    if members.len() > MAX_MLS_TEXT_GROUP_MEMBERS {
        return Err(create_error!(MlsCallFull {
            max: MAX_MLS_TEXT_GROUP_MEMBERS
        }));
    }

    // Enforced device cap, for every user this commit adds a device for,
    // over EVERY post-commit leaf of that user (#212: no exclusion, exactly
    // as every receiver counts; a lost signer device still counts)
    let cap = mls_text_enforced_device_cap(signed.device_cap, entitlement_device_cap);
    if cap != 0 {
        for added in &commit.added {
            let devices = members
                .iter()
                .filter(|member| member.user_id == added.user_id)
                .count();
            if devices > cap as usize {
                return Err(create_error!(DeviceCapReached { max: cap as usize }));
            }
        }
    }

    // member_added: removed entries dropped, added entries inserted (a
    // remove and re-add of one device in one commit was refused above, so
    // the two never overlap)
    let mut member_added: Vec<MlsMemberAdded> = group
        .member_added
        .iter()
        .filter(|entry| {
            !commit.removed.iter().any(|removed| {
                removed.user_id == entry.user_id && removed.device_id == entry.device_id
            })
        })
        .cloned()
        .collect();
    member_added.extend(commit.added.iter().map(|added| MlsMemberAdded {
        user_id: added.user_id.clone(),
        device_id: added.device_id.clone(),
        epoch: commit.epoch,
        at: commit.created_at,
    }));

    // Every pending entry whose user has no member device left
    let cleared_pending: Vec<String> = group
        .pending_removals
        .iter()
        .filter(|pending| {
            !members
                .iter()
                .any(|member| member.user_id == pending.user_id)
        })
        .map(|pending| pending.user_id.clone())
        .collect();

    // Clearing (2.5, #224): every pending device entry whose device holds
    // no leaf after this commit goes
    let mut after = MlsGroup {
        members: members.clone(),
        ..group.clone()
    };
    retain_member_pending_device_removals(&mut after);
    let pending_device_removals = after.pending_device_removals;
    let cleared_pending_devices: Vec<MlsMemberDevice> = group
        .pending_device_removals
        .iter()
        .filter(|pending| !pending_device_removals.contains(pending))
        .map(|pending| MlsMemberDevice {
            user_id: pending.user_id.clone(),
            device_id: pending.device_id.clone(),
        })
        .collect();

    // rejoin_readd (S2-D32): a device's re-Add consumes its entry; a rule-6
    // eviction writes one (an added device is never also removed, so the
    // two never touch the same device)
    let mut rejoin_readd = group.rejoin_readd.clone();
    rejoin_readd.retain(|entry| {
        !commit
            .added
            .iter()
            .any(|added| added.user_id == entry.user_id && added.device_id == entry.device_id)
    });
    for intent in &rejoin_intents {
        rejoin_readd.retain(|entry| {
            !(entry.user_id == intent.user_id && entry.device_id == intent.device_id)
        });
        rejoin_readd.push(MlsRejoinReadd {
            user_id: intent.user_id.clone(),
            device_id: intent.device_id.clone(),
            at: commit.created_at,
        });
    }
    let rejoin_readd = (rejoin_readd != group.rejoin_readd).then_some(rejoin_readd);

    let mut keys_received_users: Vec<String> = Vec::new();
    for added in &commit.added {
        if !keys_received_users.contains(&added.user_id) {
            keys_received_users.push(added.user_id.clone());
        }
    }

    let mut consumed_intent_ids: Vec<String> = commit
        .added
        .iter()
        .map(|added| MlsJoinIntent::composite_id(&group.id, &added.user_id, &added.device_id))
        .collect();
    consumed_intent_ids.extend(rejoin_intents.iter().map(|intent| intent.id.clone()));

    // The Welcome is stored as given (S2-D29); the declarations the
    // transaction derives replace the submitted ones
    let mut stored = commit.clone();
    stored.id = MlsCommit::composite_id(&commit.group_id, commit.epoch);
    stored.rejoin_intents = rejoin_intents;
    stored.removed_reasons = removed_reasons;

    Ok(MlsTextCommitPlan {
        stored,
        members,
        member_added,
        cleared_pending,
        pending_device_removals,
        cleared_pending_devices,
        rejoin_readd,
        keys_received_users,
        consumed_intent_ids,
    })
}
