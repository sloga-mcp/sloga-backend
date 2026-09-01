use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{
    MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupCreateOutcome, MlsJoinIntent, MlsKeyPackage,
};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

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
    /// At most one OPEN group may exist per channel (partial unique index /
    /// single-Mutex contains-check). A racing second creator gets
    /// `Conflict { open_group_id }` carrying the winner so it can fall into
    /// the join path. With `supersedes` (poisoned-epoch recovery §1.4) the
    /// named group is atomically closed (with `superseded_by` back-pointer)
    /// and the successor created; if the named group is not the channel's
    /// open group the call conflicts with the actual open group instead.
    async fn create_mls_group(
        &self,
        group: &MlsGroup,
        supersedes: Option<&str>,
    ) -> Result<MlsGroupCreateOutcome>;

    /// Fetch a group by id
    async fn fetch_mls_group(&self, group_id: &str) -> Result<MlsGroup>;

    /// Fetch the channel's open group, if any
    async fn fetch_open_mls_group_for_channel(&self, channel_id: &str)
        -> Result<Option<MlsGroup>>;

    /// Close a group (call ended / room_finished). Idempotent; returns
    /// whether the group was open.
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
    ///   the asserted added/removed lists.
    async fn insert_mls_commit(&self, commit: &MlsCommit) -> Result<MlsCommitOutcome>;

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

    /// Sweep groups closed before `closed_threshold` or created before
    /// `created_threshold` (call groups are ephemeral — plan §2.5), along
    /// with their commits and join intents. Returns how many groups went.
    async fn sweep_mls_groups(
        &self,
        closed_threshold: Timestamp,
        created_threshold: Timestamp,
    ) -> Result<usize>;
}
