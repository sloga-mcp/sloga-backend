use std::collections::HashSet;

use iso8601_timestamp::{Duration, Timestamp};
use revolt_result::Result;

use crate::{
    mls_text_enforced_device_cap, MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupCreateOutcome,
    MlsGroupKind, MlsJoinIntent, MlsKeyPackage, MlsMemberAdded, MlsMemberDevice, SeatList,
    SeatListBody, MAX_MLS_TEXT_GROUP_MEMBERS, MLS_REJOIN_OUTSTANDING_WINDOW_SECONDS,
};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[cfg(all(test, feature = "mongodb"))]
pub(crate) use mongodb::TEXT_COMMIT_RETRIES;

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
    /// 0. a commit row already at `{group}:{epoch}` returns
    ///    `Lost { winning }` BEFORE any validity check (idempotent
    ///    resubmit). The route's ACCESS checks must already have run.
    /// 1. read the group (`kind: Text`), the channel's newest seat list,
    ///    the removed devices' stored join intents and E2EE identities;
    /// 2. validity: open; committer is a member (`ProtectedChannelResecuring
    ///    { reason: "not_member" }`); `epoch == current_epoch + 1`;
    ///    `seat_list_ad_sha256 == ad_sha256` (`stale_seat_list`); the
    ///    Remove rule; Adds refused while `pending_removals` is non-empty
    ///    (`pending_removal`), every added device not already a member, not
    ///    also removed, its user's `channel_seats` row ACTIVE (`NotSeated`;
    ///    Mongo: a conditional write on that row, so a racing seat release
    ///    write-conflicts) and on the newest seat list; the enforced device
    ///    cap `min(signed, entitlement_device_cap)`; the
    ///    [`MAX_MLS_TEXT_GROUP_MEMBERS`] leaf cap;
    /// 3. insert the commit row (with `rejoin_intents` filled);
    /// 4. field-level group update filtered on `{ _id, open, kind: Text,
    ///    current_epoch: e - 1, seat_list_ad_sha256: ad_sha256 }`: `$set`
    ///    `current_epoch`, `members`, `member_added`; `$pull` every pending
    ///    removal whose user has no member device left;
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
    /// is "now" for the rejoin window and `member_added.at`. The submitted
    /// `commit.rejoin_intents` is ignored and replaced.
    async fn insert_mls_text_commit(
        &self,
        commit: &MlsCommit,
        ad_sha256: &str,
        entitlement_device_cap: u32,
    ) -> Result<MlsCommitOutcome>;

    /// Gap refetch: stored winning commits with epoch >= `from_epoch`,
    /// ascending, bounded by `limit`
    async fn fetch_mls_commits_from(
        &self,
        group_id: &str,
        from_epoch: i64,
        limit: i64,
    ) -> Result<Vec<MlsCommit>>;

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

    // Adds are refused while any removal is pending (W0-fix3), so a joiner
    // never receives a roster with an unseated user
    if !commit.added.is_empty() && !group.pending_removals.is_empty() {
        return Err(resecuring("pending_removal"));
    }

    // Remove rule (design §3.12.2)
    let committer = &commit.committer;
    let committer_is_signer = committer.user_id == signed.signer_user_id
        && committer.device_id == signed.signer_device_id;
    let window_start = commit
        .created_at
        .checked_sub(Duration::seconds(MLS_REJOIN_OUTSTANDING_WINDOW_SECONDS))
        .ok_or_else(|| failed("invalid commit time"))?;

    let mut rejoin_intents: Vec<MlsJoinIntent> = Vec::new();
    for removed in &commit.removed {
        if !group.has_member(&removed.user_id, &removed.device_id) {
            return Err(failed("removed device is not a member"));
        }

        if removed.user_id == committer.user_id && removed.device_id == committer.device_id {
            return Err(failed("a device cannot remove itself"));
        }

        let is_signer_device = removed.user_id == signed.signer_user_id
            && removed.device_id == signed.signer_device_id;

        // Rules 2 to 5 never apply to the current list signer's device
        let other_rule = !is_signer_device
            && (removed.user_id == committer.user_id
                || group.has_pending_removal(&removed.user_id)
                || revoked_identities.contains(&crate::E2EEIdentity::composite_id(
                    &removed.user_id,
                    &removed.device_id,
                ))
                || (committer_is_signer && !seated(&removed.user_id)));

        if other_rule {
            continue;
        }

        // Rule 6 (rejoin): a stored intent signed by THIS device, outstanding
        // (<= 30 s old) and created strictly after the device's latest Add.
        // No `member_added` entry = refused (never "added at time zero")
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

        match (intent, added_at) {
            (Some(intent), Some(added_at))
                if intent.created_at >= window_start && intent.created_at > added_at =>
            {
                rejoin_intents.push(intent.clone());
            }
            _ => return Err(failed("removal not permitted")),
        }
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
    }

    // The roster after the commit
    let mut members: Vec<MlsMemberDevice> = group
        .members
        .iter()
        .filter(|member| !commit.removed.contains(member))
        .cloned()
        .collect();
    members.extend(commit.added.iter().cloned());

    if members.len() > MAX_MLS_TEXT_GROUP_MEMBERS {
        return Err(failed("group is at the E2EE roster ceiling"));
    }

    // Enforced device cap, for every user this commit adds a device for
    let cap = mls_text_enforced_device_cap(signed.device_cap, entitlement_device_cap);
    if cap != 0 {
        for added in &commit.added {
            let devices = members
                .iter()
                .filter(|member| member.user_id == added.user_id)
                .count();
            if devices > cap as usize {
                return Err(failed("user is at the device cap"));
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

    let mut consumed_intent_ids: Vec<String> = commit
        .added
        .iter()
        .map(|added| MlsJoinIntent::composite_id(&group.id, &added.user_id, &added.device_id))
        .collect();
    consumed_intent_ids.extend(rejoin_intents.iter().map(|intent| intent.id.clone()));

    let mut stored = commit.clone();
    stored.id = MlsCommit::composite_id(&commit.group_id, commit.epoch);
    stored.rejoin_intents = rejoin_intents;

    Ok(MlsTextCommitPlan {
        stored,
        members,
        member_added,
        cleared_pending,
        consumed_intent_ids,
    })
}
