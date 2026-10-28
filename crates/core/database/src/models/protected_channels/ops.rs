use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{
    ChannelEntitlement, ChannelSeat, MlsGroup, MlsGroupCreateOutcome, SeatList, SeatListSnapshot,
    SeatListSubmission, SeatListWriteOutcome,
};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

/// Protected-channel data (design 2.2 to 2.5).
///
/// Atomicity: every method that writes more than one document does so in
/// ONE multi-document Mongo transaction (retried as a whole on
/// `TransientTransactionError` within a time budget, the commit retried on
/// `UnknownTransactionCommitResult` at most 5 times; see `ops/mongodb.rs`),
/// or, in the Reference driver, while holding its collection locks in the
/// order `channels -> messages -> channel_entitlements -> servers ->
/// server_members -> channel_seat_lists -> channel_seats -> mls_groups ->
/// mls_commits -> mls_join_intents -> e2ee_identities -> e2ee_queue` (the
/// 2.5 (d) order with five collections prefixed and one appended; see
/// `ops/reference.rs`). On Mongo, a
/// transaction that only READS a document it depends on also writes it
/// (`txn_serial`), so the dependency cannot write-skew: Text create writes
/// the seat-list row it binds, and a seat claim writes the entitlement whose
/// `slot_cap` it checked.
///
/// Claim order (decision 13 (W2)): protect and the seat PUT write the
/// documents they depend on in the order `mls_groups` (the open Text group)
/// -> `servers` (protect only: the owner) -> `server_members` (every newly
/// claimed or reactivated user, sorted by user id) -> the seat-list row and
/// `channel_seats`. A kick that lands first makes the member claim match
/// nothing (refused); one that lands after waits for the claim's commit and
/// is followed by the kick's second release (design 6.3). An ownership
/// transfer that lands first makes the owner claim match nothing; one that
/// lands after is the accepted R16 order. The Text commit transaction takes
/// no member claim: its conditional seat-row write already refuses an Add
/// once a kick's release lands.
#[async_trait]
pub trait AbstractProtectedChannels: Sync + Send {
    /// Grant or update a channel's entitlement (7.2 admin grant). Upsert by
    /// `channel_id`: an existing row keeps its id, server, source, state and
    /// `created_at`, and takes the new `slot_cap`, `device_cap` and
    /// `granted_by`. A `slot_cap` below the seats in use at `now` (active +
    /// cooling) is `SeatCapReached { max: slot_cap }`; outside `1..=100` it
    /// is `FailedValidation`. Returns the stored row.
    async fn upsert_channel_entitlement(
        &self,
        entitlement: &ChannelEntitlement,
        now: Timestamp,
    ) -> Result<ChannelEntitlement>;

    /// The channel's entitlement, if any
    async fn fetch_channel_entitlement(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelEntitlement>>;

    /// The channel ids of every entitlement whose `server_id` is
    /// `server_id`, sorted and unique (C4, W2 audit). Mongo reads them
    /// through a `channel_id` projection, so an undecodable entitlement row
    /// does not fail it (the WA#6 pattern); a row whose `channel_id` is not
    /// a string does (`DatabaseError`), because a caller that enumerates a
    /// server's protected channels must never skip one. `Server::delete`
    /// and the ownership-transfer refusal walk these ids together with
    /// `server.channels`, so a protected channel missing from that list is
    /// neither left behind nor transferable.
    async fn fetch_entitled_channel_ids(&self, server_id: &str) -> Result<Vec<String>>;

    /// Every seat row of a channel (active, cooling and expired)
    async fn fetch_channel_seats(&self, channel_id: &str) -> Result<Vec<ChannelSeat>>;

    /// Every seat row of a user, across channels
    async fn fetch_channel_seats_for_user(&self, user_id: &str) -> Result<Vec<ChannelSeat>>;

    /// The channel's newest seat list, if any (no snapshot; use
    /// `fetch_seat_list_snapshot` for `GET .../seats`)
    async fn fetch_seat_list(&self, channel_id: &str) -> Result<Option<SeatList>>;

    /// The newest seat list and the channel's open Text group, read in ONE
    /// snapshot (7.2, W0-fix4), so `(list.version, as_of_epoch,
    /// as_of_group_id)` is always a consistent triple under a racing PUT
    async fn fetch_seat_list_snapshot(&self, channel_id: &str) -> Result<SeatListSnapshot>;

    /// Protect a channel with its genesis seat list (7.2 protect), in one
    /// transaction.
    ///
    /// FIRST, before any write: a byte-identical retry of a protect that
    /// landed (the stored list is this genesis list, still version 1, and
    /// its signer still owns the server) returns `unchanged: true` and
    /// writes nothing (N3, #128 as amended by decision 4 (W2)).
    ///
    /// Otherwise: the channel must be a server `TextChannel` that is not
    /// protected, has no `voice`, is not an announcement channel, has no
    /// threads and has no messages (no stored message in the channel, not
    /// just `last_message_id` unset, which lags), else `InvalidOperation`;
    /// the list's signer must own the server (`NotOwner`; the server
    /// document is claimed, decision 13 (W2)); the entitlement must be
    /// `Active` and belong to the channel's server (else
    /// `InvalidOperation`); the list is planned per 4.3 (version 1, no
    /// stored list); every seated user must be a member of the server (its
    /// membership is claimed, else `FailedValidation`); then the list row is
    /// stored, the seats are claimed under the slot cap, and the channel's
    /// `protected` flag is set.
    async fn protect_channel(
        &self,
        channel_id: &str,
        submission: &SeatListSubmission,
        now: Timestamp,
    ) -> Result<SeatListWriteOutcome>;

    /// Store a new seat list (`PUT .../seats`, 4.3 database-side steps 4,
    /// 5b, 7 and 8) in one transaction with the seat claims and releases,
    /// the open Text group's `seat_list_ad_sha256` and its new
    /// `pending_removals`. A byte-identical re-PUT of the stored row returns
    /// `unchanged: true` before any other check and writes nothing.
    ///
    /// After that return, and before the growth flag is looked at: a list
    /// that still names a user the server removed since the stored list
    /// (C1, see `seat_list_removed_users`) is refused with
    /// `SeatListNamesRemovedUsers` naming them, and writes nothing.
    ///
    /// Then: with `allow_claims == false` (the growth flag is
    /// off, decision 5 (W2)) a list that claims or reactivates any seat is
    /// `FeatureDisabled { feature: "protected_channels" }`, while a
    /// removal-only or `device_cap`-only list still lands. Every newly
    /// claimed or reactivated user must be a member of the entitlement's
    /// server (its membership is claimed, else `FailedValidation`;
    /// decision 13 (W2)).
    async fn put_seat_list(
        &self,
        channel_id: &str,
        submission: &SeatListSubmission,
        allow_claims: bool,
        now: Timestamp,
    ) -> Result<SeatListWriteOutcome>;

    /// Create a Text group (or a Text successor), in one transaction with
    /// the read of the newest seat list whose AD hash it stores (2.5 (c)).
    ///
    /// The creator must be the current list signer's device; the group's
    /// `kind`, `seat_list_ad_sha256`, `pending_removals` and `member_added`
    /// are server-owned and set here. Without `supersedes` the generation
    /// must be 0; with it, the superseded group must be a Text group of the
    /// same channel and the generation its generation + 1, and the
    /// superseded group is closed with a `superseded_by` back-pointer. At
    /// most one open Text group per channel: a racing creator gets
    /// `Conflict` with the open Text group. A Call squat at the derived id
    /// (M9) is evicted in the same unit with its commits, join intents and
    /// queued E2EE envelopes (`group_id` = that id; A6, W2 audit).
    async fn create_text_mls_group(
        &self,
        group: &MlsGroup,
        supersedes: Option<&str>,
    ) -> Result<MlsGroupCreateOutcome>;

    /// Server-forced removal (kick, ban, leave, account deletion; 6.3):
    /// release the user's active seats and add a pending removal on each
    /// open Text group where the user has a device, in one transaction.
    /// `server_id = Some` limits it to that server's channels (by the
    /// entitlement's `server_id`); `None` covers every channel. Idempotent.
    /// Returns the affected channel ids (sorted).
    ///
    /// The release never decodes a whole seat or group document (C9, W2
    /// audit): Mongo reads only `channel_id` through a projection and
    /// writes with `update_many` on the same filter, so a row carrying a
    /// field no typed read decodes still releases (and the user can still
    /// be kicked, banned or join). A row whose `channel_id` is not a string
    /// fails it closed. A list that still names a user released here is
    /// refused (`SeatListNamesRemovedUsers`, see `seat_list_removed_users`).
    async fn release_channel_seats_for_user(
        &self,
        user_id: &str,
        server_id: Option<&str>,
        now: Timestamp,
    ) -> Result<Vec<String>>;

    /// Delete cascade (7.5): remove the channel's entitlement, seats and
    /// seat list, and every Text group of the channel (open or closed) with
    /// its commits and join intents, in one transaction. The Text group rows
    /// are deleted, not only closed (C7, W2 audit): the channel goes with
    /// this cascade and its Text group ids derive from its id, so no row is
    /// ever read again.
    async fn delete_protected_channel_data(&self, channel_id: &str) -> Result<()>;
}
