//! Protected channels: the permission-loss reconciler
//! (`docs/protected-channels-design.md` 6.3 "Reconciler", S2-D9 to S2-D16;
//! #201, #222).
//!
//! One predicate, [`seat_holder_lacks_access`], decides whether the holder
//! of an active seat may keep it. `GET .../seats` reads it for
//! `seated_without_access` and the reconcilers release on it, so the owner
//! UI and the reconciler never disagree.
//!
//! The reconcilers read the seat list, the active seats, the channel, its
//! server, the holders' users and memberships fresh, then release each seat
//! whose holder lacks access through the per-seat compare-and-set
//! `release_channel_seat` (cause `AccessLost`, against the `seated_at` they
//! read), so a stale reconcile never undoes an owner re-seat. They never
//! release the current list signer user (#222) and never re-seat anyone
//! (S2-D16).
//!
//! Events and audit live HERE, not in the callers: every release that lands
//! records its `ProtectedSeatRelease` entry (7.5), and a channel with at
//! least one release gets ONE `ProtectedChannelChanged { scope: ["seats"] }`
//! on its channel topic (viewers only). So every caller (the hook routes,
//! the crond sweep, the post-claim recheck of protect and the seat PUT)
//! emits the same events and entries, and the returned ids are only for the
//! caller's own bookkeeping.
//!
//! Nothing here is gated on `protected_channels.enabled`, `formats_v2` or
//! the entitlement state: removal always works (6.3 "Sweep").
//!
//! Errors: a failed read before any release returns at once (nothing was
//! written). A channel or server row that is not found is nothing to
//! reconcile, not an error. A failed release does not stop the others:
//! every seat and every channel is still tried, events and entries go out
//! for what landed, and the FIRST error is returned at the end. Callers keep
//! it and, once their own follow-ups ran, return it unchanged (6.3 "Hooks":
//! after the voice sync; in practice 500).

use std::collections::BTreeSet;

use iso8601_timestamp::Timestamp;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{Error, ErrorType, Result};

use crate::{
    events::client::EventV1, seat_list_channel_server, util::permissions::perms, AuditLogAction,
    AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Channel, Database, Member,
    SeatReleaseCause, Server, User, PROTECTED_SCOPE_SEATS,
};

/// Whether the holder of an active seat in `channel` lacks access to it
/// (6.3 "Reconciler"): true for a missing user (`user` is `None`), a
/// non-member (`member` is `None`), a bot, a privileged (staff) account, or
/// a member without ViewChannel on `channel`. A suspended or disabled
/// account is NOT in it (R17): nothing but the account's flags changes.
///
/// Callers batch-read the rows (`fetch_users`, `fetch_members`) and pass
/// `None` for an id the read did not return. `member` must be `user`'s
/// membership of `server` and `channel` a server text channel of `server`;
/// rows that do not belong together count as lacking access.
///
/// The bot and privileged checks come before the permission calculus,
/// which grants everything to a privileged account before it reads any
/// override (`GrantAllSafe`). Timeouts keep ViewChannel (`ALLOW_IN_TIMEOUT`).
pub async fn seat_holder_lacks_access(
    db: &Database,
    user: Option<&User>,
    member: Option<&Member>,
    channel: &Channel,
    server: &Server,
) -> bool {
    let (Some(user), Some(member)) = (user, member) else {
        return true;
    };
    if user.bot.is_some() || user.privileged {
        return true;
    }
    if member.id.user != user.id
        || member.id.server != server.id
        || seat_list_channel_server(channel) != Some(server.id.as_str())
    {
        return true;
    }

    let mut query = perms(db, user)
        .channel(channel)
        .server(server)
        .member(member);
    !calculate_channel_permissions(&mut query)
        .await
        .has_channel_permission(ChannelPermission::ViewChannel)
}

/// Release every active seat of `channel_id` whose holder lacks access
/// (6.3 "Reconciler"), except the list signer's. Returns the released user
/// ids (sorted); a channel without a seat list (not protected) or without
/// active seats returns an empty list and writes nothing. Records one
/// `ProtectedSeatRelease` entry per release and publishes one
/// `ProtectedChannelChanged { scope: ["seats"] }` when anything was released.
pub async fn reconcile_channel(db: &Database, channel_id: &str) -> Result<Vec<String>> {
    let mut changed = Changed::new();
    let result =
        reconcile_channel_at(db, channel_id, None, Timestamp::now_utc(), &mut changed).await;
    publish(changed).await;
    result
}

/// [`reconcile_channel`] for every protected channel of `server_id` (the
/// channels of its entitlements: protect needs one, and the delete cascade
/// removes it with the seats). Returns `(channel_id, released user ids)`
/// for each channel that released someone, in channel id order.
pub async fn reconcile_server(
    db: &Database,
    server_id: &str,
) -> Result<Vec<(String, Vec<String>)>> {
    let mut changed = Changed::new();
    let result = reconcile_server_at(db, server_id, Timestamp::now_utc(), &mut changed).await;
    publish(changed).await;
    result
}

/// [`reconcile_channel`] limited to `user_id`'s active seats in the
/// protected channels of `server_id` (a member's roles changed). Returns
/// the channel ids where that seat was released (sorted).
pub async fn reconcile_member_in_server(
    db: &Database,
    server_id: &str,
    user_id: &str,
) -> Result<Vec<String>> {
    let mut changed = Changed::new();
    let result =
        reconcile_member_in_server_at(db, server_id, user_id, Timestamp::now_utc(), &mut changed)
            .await;
    publish(changed).await;
    result
}

/// The stored snake_case name of `cause` (2.3), also the `cause` value of a
/// `ProtectedSeatRelease` audit entry (7.5)
pub fn seat_release_cause_name(cause: SeatReleaseCause) -> &'static str {
    match cause {
        SeatReleaseCause::OwnerUnseat => "owner_unseat",
        SeatReleaseCause::ServerRemoval => "server_removal",
        SeatReleaseCause::AccessLost => "access_lost",
        SeatReleaseCause::DeviceNeverJoined => "device_never_joined",
    }
}

/// The `ProtectedSeatRelease` entry of one release (7.5, the mapping on
/// `AuditLogAction::ProtectedSeatRelease`): the system as the actor, the
/// released user as the target, the channel, and its cause. `cause` is the
/// reason the caller released for; the seat row may store
/// `DeviceNeverJoined` instead (2.3), which only says the slot freed at once.
pub fn seat_release_audit(
    server_id: &str,
    channel_id: &str,
    user_id: &str,
    cause: SeatReleaseCause,
) -> AuditLogDraft {
    AuditLogDraft {
        server: server_id.to_string(),
        actor: None,
        action: AuditLogAction::ProtectedSeatRelease,
        target: Some(user_id.to_string()),
        channel: Some(channel_id.to_string()),
        changes: vec![AuditLogChange::new(
            "cause",
            None,
            Some(AuditValue::String(
                seat_release_cause_name(cause).to_string(),
            )),
        )],
        count: None,
        reason: None,
    }
}

/// The `ProtectedChannelChanged` events a reconcile owes, with their
/// channel topics. Production publishes them once the pass is over; the
/// tests read them.
type Changed = Vec<(String, EventV1)>;

async fn publish(changed: Changed) {
    for (topic, event) in changed {
        event.p(topic).await;
    }
}

/// What a channel reconcile read: the seats to release, each with the
/// `seated_at` it was read with (the compare-and-set value)
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleasePlan {
    channel_id: String,
    server_id: String,
    seats: Vec<(String, Timestamp)>,
}

async fn reconcile_channel_at(
    db: &Database,
    channel_id: &str,
    only_user: Option<&str>,
    now: Timestamp,
    changed: &mut Changed,
) -> Result<Vec<String>> {
    match plan_channel(db, channel_id, only_user).await? {
        Some(plan) => apply_release_plan(db, plan, now, changed).await,
        None => Ok(Vec::new()),
    }
}

async fn reconcile_server_at(
    db: &Database,
    server_id: &str,
    now: Timestamp,
    changed: &mut Changed,
) -> Result<Vec<(String, Vec<String>)>> {
    let mut results = Vec::new();
    let mut first_error = None;
    for channel_id in db.fetch_entitled_channel_ids(server_id).await? {
        match reconcile_channel_at(db, &channel_id, None, now, changed).await {
            Ok(released) if released.is_empty() => {}
            Ok(released) => results.push((channel_id, released)),
            Err(error) => {
                error!("protected channel reconcile failed: server={server_id} channel={channel_id}: {error:?}");
                first_error.get_or_insert(error);
            }
        }
    }
    finish(results, first_error)
}

async fn reconcile_member_in_server_at(
    db: &Database,
    server_id: &str,
    user_id: &str,
    now: Timestamp,
    changed: &mut Changed,
) -> Result<Vec<String>> {
    let entitled: BTreeSet<String> = db
        .fetch_entitled_channel_ids(server_id)
        .await?
        .into_iter()
        .collect();
    let channels: BTreeSet<String> = db
        .fetch_channel_seats_for_user(user_id)
        .await?
        .into_iter()
        .filter(|seat| seat.is_active() && entitled.contains(&seat.channel_id))
        .map(|seat| seat.channel_id)
        .collect();

    let mut results = Vec::new();
    let mut first_error = None;
    for channel_id in channels {
        match reconcile_channel_at(db, &channel_id, Some(user_id), now, changed).await {
            Ok(released) if released.is_empty() => {}
            Ok(_) => results.push(channel_id),
            Err(error) => {
                error!("protected channel reconcile failed: server={server_id} channel={channel_id} user={user_id}: {error:?}");
                first_error.get_or_insert(error);
            }
        }
    }
    finish(results, first_error)
}

fn finish<T>(value: T, first_error: Option<Error>) -> Result<T> {
    match first_error {
        Some(error) => Err(error),
        None => Ok(value),
    }
}

/// `Ok(None)` for a read that answered `NotFound`; every other error
/// unchanged
fn found<T>(read: Result<T>) -> Result<Option<T>> {
    match read {
        Ok(value) => Ok(Some(value)),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Fresh reads of one channel and the seats to release (`only_user`: that
/// user's seat only). `None`: no seat list (not protected), no active seat
/// in scope, or no channel or server row (deleted under the pass, or a
/// legacy row): a permission edit never answers 404 for it.
async fn plan_channel(
    db: &Database,
    channel_id: &str,
    only_user: Option<&str>,
) -> Result<Option<ReleasePlan>> {
    let Some(list) = db.fetch_seat_list(channel_id).await? else {
        return Ok(None);
    };
    let seats: Vec<_> = db
        .fetch_channel_seats(channel_id)
        .await?
        .into_iter()
        .filter(|seat| seat.is_active() && only_user.is_none_or(|user| seat.user_id == user))
        .collect();
    if seats.is_empty() {
        return Ok(None);
    }

    let Some(channel) = found(db.fetch_channel(channel_id).await)? else {
        warn!("protected channel reconcile: no channel row, nothing to reconcile: channel={channel_id}");
        return Ok(None);
    };
    let Some(server_id) = seat_list_channel_server(&channel) else {
        // Protect only takes a server text channel (2.1): a seat list on
        // anything else is corrupt data, so this fails loud
        error!("protected channel reconcile: seat list on a non-server channel {channel_id}");
        return Err(create_error!(InternalError));
    };
    let Some(server) = found(db.fetch_server(server_id).await)? else {
        warn!("protected channel reconcile: no server row, nothing to reconcile: server={server_id} channel={channel_id}");
        return Ok(None);
    };

    let holders: Vec<String> = seats.iter().map(|seat| seat.user_id.clone()).collect();
    let users = db.fetch_users(&holders).await?;
    let members = db.fetch_members(&server.id, &holders).await?;

    let mut release = Vec::new();
    for seat in seats {
        let user = users.iter().find(|user| user.id == seat.user_id);
        let member = members
            .iter()
            .find(|member| member.id.server == server.id && member.id.user == seat.user_id);
        if !seat_holder_lacks_access(db, user, member, &channel, &server).await {
            continue;
        }
        // #222: releasing the signer would wedge the channel (a staff flag
        // set on the owner after protect matches the predicate)
        if seat.user_id == list.signer_user_id {
            report_signer_kept(channel_id, &seat.user_id);
            continue;
        }
        release.push((seat.user_id, seat.seated_at));
    }

    Ok(Some(ReleasePlan {
        channel_id: channel_id.to_string(),
        server_id: server.id,
        seats: release,
    }))
}

/// Release the planned seats through the compare-and-set, recording an
/// entry per release that landed and owing one event if any did
async fn apply_release_plan(
    db: &Database,
    plan: ReleasePlan,
    now: Timestamp,
    changed: &mut Changed,
) -> Result<Vec<String>> {
    let cause = SeatReleaseCause::AccessLost;
    let mut released = Vec::new();
    let mut first_error = None;
    for (user_id, seated_at) in plan.seats {
        match db
            .release_channel_seat(&plan.channel_id, &user_id, seated_at, cause, now)
            .await
        {
            Ok(true) => {
                AuditLogEntry::record(
                    db,
                    seat_release_audit(&plan.server_id, &plan.channel_id, &user_id, cause),
                )
                .await;
                released.push(user_id);
            }
            // Re-seated or released since the read: not ours to release
            Ok(false) => {}
            Err(error) => {
                error!(
                    "protected channel reconcile: release failed: channel={} user={user_id}: {error:?}",
                    plan.channel_id
                );
                first_error.get_or_insert(error);
            }
        }
    }

    if !released.is_empty() {
        changed.push((
            plan.channel_id.clone(),
            EventV1::ProtectedChannelChanged {
                id: plan.channel_id,
                scope: vec![PROTECTED_SCOPE_SEATS.to_string()],
            },
        ));
    }
    released.sort();
    finish(released, first_error)
}

/// Log and report (ids only) a list signer the reconciler kept although
/// they lack access (#222)
fn report_signer_kept(channel_id: &str, user_id: &str) {
    let message = format!(
        "protected channel reconcile kept the list signer's seat: channel={channel_id} user={user_id}"
    );
    warn!("{message}");
    revolt_config::capture_message(&message, revolt_config::Level::Warning);
}

#[cfg(test)]
mod tests {
    //! `database_test!` tests: run under BOTH `TEST_DB=REFERENCE` and
    //! `TEST_DB=MONGODB` (never without `TEST_DB`: that is production).

    use std::collections::HashMap;

    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_models::v0::UserFlags;
    use revolt_permissions::{ChannelPermission, OverrideField, DEFAULT_PERMISSION_SERVER};

    use super::{
        apply_release_plan, plan_channel, reconcile_channel_at, reconcile_member_in_server_at,
        reconcile_server_at, seat_holder_lacks_access, seat_release_cause_name, Changed,
    };
    use crate::{
        AuditLogAction, AuditLogChange, AuditValue, BotInformation, Channel, ChannelEntitlement,
        ChannelEntitlementSource, ChannelEntitlementState, ChannelSeat, Database, Member,
        MemberCompositeKey, PartialMember, PartialUser, Role, SeatListBody, SeatListSubmission,
        SeatReleaseCause, Server, User, SEAT_COOLDOWN_DAYS,
    };

    const SERVER: &str = "01HZXSERVERSERVERSERVERSER";
    const OTHER_SERVER: &str = "01HZXOTHERSERVEROTHERSERVE";
    const CHANNEL: &str = "01J9Z3K4M5N6P7Q8R9S0T1V2W3";
    const CHANNEL_2: &str = "01J9Z3K4M5N6P7Q8R9S0T1V2W4";
    const UNPROTECTED: &str = "01J9Z3K4M5N6P7Q8R9S0T1V2W5";
    /// Server owner and list signer
    const USER_A: &str = "01HZXAAAAAAAAAAAAAAAAAAAAA";
    /// Holds `ROLE_HIDDEN` (denied View on `CHANNEL` only)
    const USER_B: &str = "01HZXBBBBBBBBBBBBBBBBBBBBB";
    /// A plain member: keeps View
    const USER_C: &str = "01HZXCCCCCCCCCCCCCCCCCCCCC";
    /// Holds `ROLE_BLIND` (denied View server-wide)
    const USER_D: &str = "01HZXDDDDDDDDDDDDDDDDDDDDD";
    /// A member with no user row (a missing user)
    const USER_E: &str = "01HZXEEEEEEEEEEEEEEEEEEEEE";
    const DEVICE_A: &str = "00112233445566778899aabbccddeeff";
    const ROLE_HIDDEN: &str = "01HZXR0LEH1DDEN00000000000";
    const ROLE_BLIND: &str = "01HZXR0LEB11ND000000000000";

    /// Fixed whole-millisecond time (Mongo stores Int64 milliseconds)
    fn at(days: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(Duration::milliseconds(1_790_812_800_000))
            .and_then(|base| base.checked_add(Duration::days(days)))
            .unwrap()
    }

    fn view() -> i64 {
        ChannelPermission::ViewChannel as i64
    }

    fn user(id: &str) -> User {
        User {
            id: id.to_string(),
            username: format!("user{}", &id[20..]),
            discriminator: "0001".to_string(),
            ..Default::default()
        }
    }

    fn member(server: &str, user: &str, roles: &[&str]) -> Member {
        Member {
            id: MemberCompositeKey {
                server: server.to_string(),
                user: user.to_string(),
            },
            roles: roles.iter().map(|role| role.to_string()).collect(),
            ..Default::default()
        }
    }

    fn role(id: &str, rank: i64, deny: i64) -> Role {
        Role {
            id: id.to_string(),
            name: id.to_string(),
            permissions: OverrideField { a: 0, d: deny },
            colour: None,
            hoist: false,
            rank,
            icon: None,
        }
    }

    /// `SERVER` owned by A: every member may view by default; `ROLE_BLIND`
    /// denies View server-wide
    fn server() -> Server {
        let mut server: Server = serde_json::from_value(serde_json::json!({
            "_id": SERVER,
            "owner": USER_A,
            "name": "protected",
            "channels": [CHANNEL, CHANNEL_2, UNPROTECTED],
            "default_permissions": *DEFAULT_PERMISSION_SERVER as i64,
        }))
        .unwrap();
        server.roles = HashMap::from([
            (ROLE_HIDDEN.to_string(), role(ROLE_HIDDEN, 1, 0)),
            (ROLE_BLIND.to_string(), role(ROLE_BLIND, 2, view())),
        ]);
        server
    }

    /// A text channel of `server`; `hidden` adds the `ROLE_HIDDEN` override
    /// that denies View
    fn channel(id: &str, server: &str, hidden: bool) -> Channel {
        let mut role_permissions = HashMap::new();
        if hidden {
            role_permissions.insert(ROLE_HIDDEN.to_string(), OverrideField { a: 0, d: view() });
        }
        Channel::TextChannel {
            id: id.to_string(),
            server: server.to_string(),
            name: "protected".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions,
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected: false,
        }
    }

    fn submission(channel_id: &str, version: i64, seats: &[&str]) -> SeatListSubmission {
        SeatListSubmission {
            body: SeatListBody {
                channel_id: channel_id.to_string(),
                version,
                device_cap: 5,
                issued_at: 1_790_812_800_000,
                signer_user_id: USER_A.to_string(),
                signer_device_id: DEVICE_A.to_string(),
                seats: seats.iter().map(|seat| seat.to_string()).collect(),
                v2: None,
            }
            .build()
            .unwrap(),
            // The DB layer checks the encoding only; the route verifies it
            signature: format!("B{}", "A".repeat(85)),
            signer_device_id: DEVICE_A.to_string(),
            handover: None,
            authority: None,
        }
    }

    /// Users A to D (E has no user row), all five members of `SERVER` (B
    /// with `ROLE_HIDDEN`, D with `ROLE_BLIND`), `CHANNEL` (hidden from
    /// `ROLE_HIDDEN`) and `CHANNEL_2` (not) protected with `seated`, and
    /// `UNPROTECTED` entitled but not protected
    async fn world(db: &Database, seated: &[&str]) {
        for id in [USER_A, USER_B, USER_C, USER_D] {
            db.insert_user(&user(id)).await.unwrap();
        }
        db.insert_server(&server()).await.unwrap();
        for (id, roles) in [
            (USER_A, vec![]),
            (USER_B, vec![ROLE_HIDDEN]),
            (USER_C, vec![]),
            (USER_D, vec![ROLE_BLIND]),
            (USER_E, vec![]),
        ] {
            db.insert_or_merge_member(&member(SERVER, id, &roles))
                .await
                .unwrap();
        }
        for (id, hidden) in [(CHANNEL, true), (CHANNEL_2, false), (UNPROTECTED, true)] {
            db.insert_channel(&channel(id, SERVER, hidden))
                .await
                .unwrap();
            db.upsert_channel_entitlement(
                &ChannelEntitlement {
                    id: ulid::Ulid::new().to_string(),
                    channel_id: id.to_string(),
                    server_id: SERVER.to_string(),
                    source: ChannelEntitlementSource::AdminGrant,
                    slot_cap: 10,
                    device_cap: None,
                    state: ChannelEntitlementState::Active,
                    granted_by: "admin".to_string(),
                    created_at: at(0),
                },
                at(0),
            )
            .await
            .unwrap();
        }
        for id in [CHANNEL, CHANNEL_2] {
            db.protect_channel(id, &submission(id, 1, seated), at(0))
                .await
                .unwrap();
        }
    }

    async fn seat_of(db: &Database, channel_id: &str, user_id: &str) -> ChannelSeat {
        db.fetch_channel_seats(channel_id)
            .await
            .unwrap()
            .into_iter()
            .find(|seat| seat.user_id == user_id)
            .expect("a seat row")
    }

    /// Test-only stamp of `keys_received_at` on both drivers (the Text
    /// commit that really writes it belongs to another lane)
    async fn stamp_keys(db: &Database, channel_id: &str, user_id: &str) {
        let id = ChannelSeat::composite_id(channel_id, user_id);
        match db {
            Database::Reference(reference) => {
                reference
                    .channel_seats
                    .lock()
                    .await
                    .get_mut(&id)
                    .expect("seat")
                    .keys_received_at = Some(at(0));
            }
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                let collection = mongo.col::<ChannelSeat>("channel_seats");
                let mut seat = collection
                    .find_one(doc! { "_id": &id })
                    .await
                    .unwrap()
                    .expect("seat");
                seat.keys_received_at = Some(at(0));
                let result = collection
                    .replace_one(doc! { "_id": &id }, &seat)
                    .await
                    .unwrap();
                assert_eq!(result.matched_count, 1);
            }
        }
    }

    async fn edit_user(db: &Database, id: &str, partial: PartialUser) {
        db.update_user(id, &partial, vec![]).await.unwrap();
    }

    /// The `ProtectedSeatRelease` entries of `SERVER` as sorted
    /// `(target, channel)` pairs (ids minted in one millisecond do not sort
    /// by time); every one checked for the 7.5 mapping
    async fn release_entries(db: &Database) -> Vec<(String, String)> {
        let entries = db
            .fetch_audit_log(
                SERVER,
                None,
                100,
                Some(AuditLogAction::ProtectedSeatRelease),
                None,
            )
            .await
            .unwrap();
        let mut pairs: Vec<(String, String)> = entries
            .into_iter()
            .map(|entry| {
                assert_eq!(entry.server, SERVER);
                assert_eq!(entry.actor, None, "the system releases");
                assert_eq!(
                    entry.changes,
                    vec![AuditLogChange::new(
                        "cause",
                        None,
                        Some(AuditValue::String("access_lost".to_string()))
                    )]
                );
                assert_eq!(entry.reason, None);
                assert_eq!(entry.count, None);
                (
                    entry.target.expect("target = the user"),
                    entry.channel.expect("channel"),
                )
            })
            .collect();
        pairs.sort();
        pairs
    }

    /// The owed events as JSON, to compare with the exact wire shape
    fn events(changed: &Changed) -> Vec<(String, serde_json::Value)> {
        changed
            .iter()
            .map(|(topic, event)| (topic.clone(), serde_json::to_value(event).unwrap()))
            .collect()
    }

    fn seats_changed(channel_id: &str) -> (String, serde_json::Value) {
        (
            channel_id.to_string(),
            serde_json::json!({
                "type": "ProtectedChannelChanged",
                "id": channel_id,
                "scope": ["seats"],
            }),
        )
    }

    /// 6.3 predicate: who lacks access, and who does not (R17: suspension
    /// is not in it; a timeout keeps View). Controls: drop the ViewChannel
    /// check; treat a suspended account as lacking access.
    #[tokio::test]
    async fn the_predicate_matrix() {
        database_test!(|db| async move {
            let server = server();
            let target = channel(CHANNEL, SERVER, true);
            let open = channel(CHANNEL_2, SERVER, false);
            let lacks = |user: Option<User>, member: Option<Member>, of: Channel| {
                let db = db.clone();
                let server = server.clone();
                async move {
                    seat_holder_lacks_access(&db, user.as_ref(), member.as_ref(), &of, &server)
                        .await
                }
            };
            let plain = || Some(member(SERVER, USER_C, &[]));

            // Keep access
            assert!(!lacks(Some(user(USER_C)), plain(), target.clone()).await);
            assert!(
                !lacks(
                    Some(user(USER_A)),
                    Some(member(SERVER, USER_A, &[ROLE_BLIND])),
                    target.clone()
                )
                .await,
                "the server owner"
            );
            assert!(
                !lacks(
                    Some(user(USER_B)),
                    Some(member(SERVER, USER_B, &[ROLE_HIDDEN])),
                    open.clone()
                )
                .await,
                "the override is per channel"
            );
            let mut suspended = user(USER_C);
            suspended.flags = Some(UserFlags::SuspendedUntil as i32);
            suspended.suspended_until = Some(at(30));
            assert!(
                !lacks(Some(suspended), plain(), target.clone()).await,
                "R17: a suspended account keeps access"
            );
            let mut timed_out = member(SERVER, USER_C, &[]);
            timed_out.timeout = Timestamp::now_utc().checked_add(Duration::days(1));
            assert!(
                !lacks(Some(user(USER_C)), Some(timed_out), target.clone()).await,
                "a timeout keeps ViewChannel"
            );

            // Lack access
            assert!(lacks(None, plain(), target.clone()).await, "missing user");
            assert!(
                lacks(Some(user(USER_C)), None, target.clone()).await,
                "non-member"
            );
            let mut bot = user(USER_C);
            bot.bot = Some(BotInformation {
                owner: USER_A.to_string(),
            });
            assert!(lacks(Some(bot), plain(), target.clone()).await, "bot");
            let mut staff = user(USER_C);
            staff.privileged = true;
            assert!(
                lacks(Some(staff), plain(), target.clone()).await,
                "privileged"
            );
            assert!(
                lacks(
                    Some(user(USER_B)),
                    Some(member(SERVER, USER_B, &[ROLE_HIDDEN])),
                    target.clone()
                )
                .await,
                "View denied by a channel role override"
            );
            assert!(
                lacks(
                    Some(user(USER_D)),
                    Some(member(SERVER, USER_D, &[ROLE_BLIND])),
                    open.clone()
                )
                .await,
                "View denied by a server role"
            );
            let mut denied = target.clone();
            if let Channel::TextChannel {
                default_permissions,
                ..
            } = &mut denied
            {
                *default_permissions = Some(OverrideField { a: 0, d: view() });
            }
            assert!(
                lacks(Some(user(USER_C)), plain(), denied).await,
                "View denied by the channel default"
            );
            assert!(
                lacks(
                    Some(user(USER_C)),
                    Some(member(OTHER_SERVER, USER_C, &[])),
                    target.clone()
                )
                .await,
                "a membership of another server"
            );
            assert!(
                lacks(
                    Some(user(USER_C)),
                    Some(member(SERVER, USER_B, &[])),
                    target.clone()
                )
                .await,
                "another user's membership"
            );
            assert!(
                lacks(
                    Some(user(USER_C)),
                    plain(),
                    channel(CHANNEL, OTHER_SERVER, false)
                )
                .await,
                "a channel of another server"
            );
        });
    }

    /// 6.3: the reconciler releases every seat whose holder lacks access
    /// with `AccessLost` and the 14-day cooldown once the keys were
    /// received, `DeviceNeverJoined` and no cooldown otherwise (2.3); one
    /// entry per release and ONE event; a second run releases and emits
    /// nothing; regaining access does not re-seat (S2-D16). Control: ignore
    /// the compare-and-set result.
    #[tokio::test]
    async fn reconcile_releases_holders_without_access_once() {
        database_test!(|db| async move {
            world(&db, &[USER_A, USER_B, USER_C, USER_D, USER_E]).await;
            stamp_keys(&db, CHANNEL, USER_B).await;

            let mut changed = Changed::new();
            let released = reconcile_channel_at(&db, CHANNEL, None, at(1), &mut changed)
                .await
                .unwrap();
            assert_eq!(released, vec![USER_B, USER_D, USER_E]);

            let b = seat_of(&db, CHANNEL, USER_B).await;
            assert_eq!(b.released_at, Some(at(1)));
            assert_eq!(b.release_cause, Some(SeatReleaseCause::AccessLost));
            assert_eq!(b.cooldown_until, Some(at(1 + SEAT_COOLDOWN_DAYS)));
            for never_joined in [USER_D, USER_E] {
                let seat = seat_of(&db, CHANNEL, never_joined).await;
                assert_eq!(seat.released_at, Some(at(1)), "{never_joined}");
                assert_eq!(
                    seat.release_cause,
                    Some(SeatReleaseCause::DeviceNeverJoined),
                    "{never_joined}"
                );
                assert_eq!(seat.cooldown_until, None, "{never_joined}");
            }
            assert!(seat_of(&db, CHANNEL, USER_A).await.is_active());
            assert!(seat_of(&db, CHANNEL, USER_C).await.is_active());
            // The other channel is not touched by a channel reconcile
            assert!(seat_of(&db, CHANNEL_2, USER_D).await.is_active());

            assert_eq!(
                release_entries(&db).await,
                vec![
                    (USER_B.to_string(), CHANNEL.to_string()),
                    (USER_D.to_string(), CHANNEL.to_string()),
                    (USER_E.to_string(), CHANNEL.to_string()),
                ]
            );
            assert_eq!(events(&changed), vec![seats_changed(CHANNEL)]);

            // Idempotent: nothing released, recorded or emitted
            let mut again = Changed::new();
            assert!(reconcile_channel_at(&db, CHANNEL, None, at(2), &mut again)
                .await
                .unwrap()
                .is_empty());
            assert!(again.is_empty());
            assert_eq!(release_entries(&db).await.len(), 3);

            // B regains View: still released, still cooling
            db.update_member(
                &MemberCompositeKey {
                    server: SERVER.to_string(),
                    user: USER_B.to_string(),
                },
                &PartialMember {
                    roles: Some(vec![]),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();
            let mut regained = Changed::new();
            assert!(
                reconcile_channel_at(&db, CHANNEL, None, at(3), &mut regained)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(regained.is_empty());
            let b = seat_of(&db, CHANNEL, USER_B).await;
            assert_eq!(b.released_at, Some(at(1)));
            assert!(b.is_cooling(at(3)));
        });
    }

    /// #222: the list signer is never released, even when they match the
    /// predicate (a staff flag set on the owner after protect); the others
    /// still are. Control: no signer skip.
    #[tokio::test]
    async fn reconcile_never_releases_the_list_signer() {
        database_test!(|db| async move {
            world(&db, &[USER_A, USER_B, USER_C]).await;
            edit_user(
                &db,
                USER_A,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
            )
            .await;

            let mut changed = Changed::new();
            let released = reconcile_channel_at(&db, CHANNEL, None, at(1), &mut changed)
                .await
                .unwrap();
            assert_eq!(released, vec![USER_B]);
            assert!(seat_of(&db, CHANNEL, USER_A).await.is_active());
            assert_eq!(
                release_entries(&db).await,
                vec![(USER_B.to_string(), CHANNEL.to_string())]
            );

            // Alone it is no release and no event
            let mut alone = Changed::new();
            assert!(
                reconcile_channel_at(&db, CHANNEL_2, Some(USER_A), at(1), &mut alone)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(alone.is_empty());
            assert!(seat_of(&db, CHANNEL_2, USER_A).await.is_active());
        });
    }

    /// R17: a suspended member who can still view keeps the seat. Control:
    /// treat suspension as lacking access.
    #[tokio::test]
    async fn reconcile_keeps_a_suspended_members_seat() {
        database_test!(|db| async move {
            world(&db, &[USER_A, USER_C]).await;
            edit_user(
                &db,
                USER_C,
                PartialUser {
                    flags: Some(UserFlags::SuspendedUntil as i32),
                    suspended_until: Some(at(30)),
                    ..Default::default()
                },
            )
            .await;

            let mut changed = Changed::new();
            assert!(
                reconcile_channel_at(&db, CHANNEL, None, at(1), &mut changed)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(changed.is_empty());
            assert!(seat_of(&db, CHANNEL, USER_C).await.is_active());
            assert!(release_entries(&db).await.is_empty());
        });
    }

    /// The `seated_at` compare-and-set: the owner re-seats a user between
    /// the reconcile's read and its release, so the stale release writes,
    /// records and emits nothing; a fresh reconcile reads the new seat.
    /// Control: ignore the compare-and-set result.
    #[tokio::test]
    async fn a_stale_reconcile_never_undoes_an_owner_reseat() {
        database_test!(|db| async move {
            world(&db, &[USER_A, USER_B, USER_C]).await;

            let plan = plan_channel(&db, CHANNEL, None).await.unwrap().unwrap();
            assert_eq!(plan.seats, vec![(USER_B.to_string(), at(0))]);

            // The owner unseats and re-seats B
            db.put_seat_list(
                CHANNEL,
                &submission(CHANNEL, 2, &[USER_A, USER_C]),
                true,
                at(1),
                Some("unseat B"),
            )
            .await
            .unwrap();
            db.put_seat_list(
                CHANNEL,
                &submission(CHANNEL, 3, &[USER_A, USER_B, USER_C]),
                true,
                at(2),
                None,
            )
            .await
            .unwrap();

            let mut changed = Changed::new();
            assert!(apply_release_plan(&db, plan, at(3), &mut changed)
                .await
                .unwrap()
                .is_empty());
            assert!(changed.is_empty());
            assert!(release_entries(&db).await.is_empty());
            let b = seat_of(&db, CHANNEL, USER_B).await;
            assert!(b.is_active());
            assert_eq!(b.seated_at, at(2));

            // B still lacks access: a fresh reconcile releases the new seat
            let mut fresh = Changed::new();
            assert_eq!(
                reconcile_channel_at(&db, CHANNEL, None, at(4), &mut fresh)
                    .await
                    .unwrap(),
                vec![USER_B]
            );
            assert_eq!(events(&fresh), vec![seats_changed(CHANNEL)]);
        });
    }

    /// Not protected, unknown or without anyone to release: no write and no
    /// event
    #[tokio::test]
    async fn reconcile_of_a_channel_without_seats_writes_nothing() {
        database_test!(|db| async move {
            world(&db, &[USER_A, USER_C]).await;
            let mut changed = Changed::new();
            for channel_id in [UNPROTECTED, "01J9Z3K4M5N6P7Q8R9S0T1V2W9", CHANNEL] {
                assert!(
                    reconcile_channel_at(&db, channel_id, None, at(1), &mut changed)
                        .await
                        .unwrap()
                        .is_empty(),
                    "{channel_id}"
                );
            }
            assert!(changed.is_empty());
            assert!(release_entries(&db).await.is_empty());
        });
    }

    /// The server pass covers every protected channel with one event each;
    /// the member pass releases only that member's seats, in that server
    #[tokio::test]
    async fn server_and_member_passes_cover_their_scope() {
        database_test!(|db| async move {
            world(&db, &[USER_A, USER_B, USER_C, USER_D]).await;

            // Another server's member pass touches nothing here
            let mut changed = Changed::new();
            assert!(
                reconcile_member_in_server_at(&db, OTHER_SERVER, USER_B, at(1), &mut changed)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(changed.is_empty());

            // B only: hidden from CHANNEL, not from CHANNEL_2; D untouched
            assert_eq!(
                reconcile_member_in_server_at(&db, SERVER, USER_B, at(1), &mut changed)
                    .await
                    .unwrap(),
                vec![CHANNEL]
            );
            assert_eq!(events(&changed), vec![seats_changed(CHANNEL)]);
            assert!(seat_of(&db, CHANNEL_2, USER_B).await.is_active());
            assert!(seat_of(&db, CHANNEL, USER_D).await.is_active());

            // The server: D in both channels, one event per channel
            let mut changed = Changed::new();
            assert_eq!(
                reconcile_server_at(&db, SERVER, at(2), &mut changed)
                    .await
                    .unwrap(),
                vec![
                    (CHANNEL.to_string(), vec![USER_D.to_string()]),
                    (CHANNEL_2.to_string(), vec![USER_D.to_string()]),
                ]
            );
            assert_eq!(
                events(&changed),
                vec![seats_changed(CHANNEL), seats_changed(CHANNEL_2)]
            );
            assert_eq!(
                release_entries(&db).await,
                vec![
                    (USER_B.to_string(), CHANNEL.to_string()),
                    (USER_D.to_string(), CHANNEL.to_string()),
                    (USER_D.to_string(), CHANNEL_2.to_string()),
                ]
            );

            let mut changed = Changed::new();
            assert!(reconcile_server_at(&db, SERVER, at(3), &mut changed)
                .await
                .unwrap()
                .is_empty());
            assert!(changed.is_empty());
        });
    }

    /// Remove a `channels` or `servers` row straight from the store, its
    /// seat list, seats and entitlements left behind (a delete under the
    /// pass, or a legacy row)
    async fn drop_row(db: &Database, collection: &str, id: &str) {
        match db {
            Database::Reference(reference) => {
                let removed = match collection {
                    "channels" => reference.channels.lock().await.remove(id).is_some(),
                    "servers" => reference.servers.lock().await.remove(id).is_some(),
                    _ => unreachable!("{collection}"),
                };
                assert!(removed, "the {collection} row {id}");
            }
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                let result = mongo
                    .col::<bson::Document>(collection)
                    .delete_one(doc! { "_id": id })
                    .await
                    .unwrap();
                assert_eq!(result.deleted_count, 1, "the {collection} row {id}");
            }
        }
    }

    /// MINOR-1: a protected channel whose channel row is gone is nothing to
    /// reconcile, so the hooks answer 200, never 404: Ok, no release, no
    /// entry, no event, and the server's other channel is still reconciled.
    /// Control: pass the `NotFound` through.
    #[tokio::test]
    async fn a_missing_channel_row_is_nothing_to_reconcile() {
        database_test!(|db| async move {
            world(&db, &[USER_A, USER_B, USER_C, USER_D]).await;
            drop_row(&db, "channels", CHANNEL).await;

            let mut changed = Changed::new();
            assert!(
                reconcile_channel_at(&db, CHANNEL, None, at(1), &mut changed)
                    .await
                    .unwrap()
                    .is_empty()
            );
            // B's seats: CHANNEL (no row) and CHANNEL_2 (keeps View)
            assert!(
                reconcile_member_in_server_at(&db, SERVER, USER_B, at(1), &mut changed)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(changed.is_empty());

            assert_eq!(
                reconcile_server_at(&db, SERVER, at(2), &mut changed)
                    .await
                    .unwrap(),
                vec![(CHANNEL_2.to_string(), vec![USER_D.to_string()])]
            );
            assert_eq!(events(&changed), vec![seats_changed(CHANNEL_2)]);
            assert_eq!(
                release_entries(&db).await,
                vec![(USER_D.to_string(), CHANNEL_2.to_string())]
            );
            for holder in [USER_B, USER_D] {
                assert!(seat_of(&db, CHANNEL, holder).await.is_active(), "{holder}");
            }
        });
    }

    /// MINOR-1: the same for a channel whose server row is gone. Controls:
    /// pass the `NotFound` through; map it for the channel read only.
    #[tokio::test]
    async fn a_missing_server_row_is_nothing_to_reconcile() {
        database_test!(|db| async move {
            world(&db, &[USER_A, USER_B, USER_C, USER_D]).await;
            drop_row(&db, "servers", SERVER).await;

            let mut changed = Changed::new();
            assert!(
                reconcile_channel_at(&db, CHANNEL, None, at(1), &mut changed)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                reconcile_member_in_server_at(&db, SERVER, USER_D, at(1), &mut changed)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(reconcile_server_at(&db, SERVER, at(1), &mut changed)
                .await
                .unwrap()
                .is_empty());
            assert!(changed.is_empty());
            for channel_id in [CHANNEL, CHANNEL_2] {
                for holder in [USER_B, USER_D] {
                    assert!(
                        seat_of(&db, channel_id, holder).await.is_active(),
                        "{channel_id} {holder}"
                    );
                }
            }
        });
    }

    /// The audit `cause` names are the stored snake_case names (2.3)
    #[test]
    fn cause_names_are_the_stored_names() {
        for cause in [
            SeatReleaseCause::OwnerUnseat,
            SeatReleaseCause::ServerRemoval,
            SeatReleaseCause::AccessLost,
            SeatReleaseCause::DeviceNeverJoined,
        ] {
            assert_eq!(
                serde_json::to_value(cause).unwrap(),
                seat_release_cause_name(cause)
            );
        }
    }
}
