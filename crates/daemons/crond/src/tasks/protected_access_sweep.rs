//! Protected-access sweep (protected channels design 6.3 "Sweep", S2-D14;
//! #201, #202, RR#S2-9).
//!
//! Every `[features.protected_channels] reconcile_sweep_secs` (300), page
//! through the channels holding an active seat
//! (`fetch_channels_with_active_seats`) and run `reconcile_channel` on each:
//! the backstop for a hook route whose reconcile failed, and for access lost
//! with no hook at all (a deleted user, a staff flag). `reconcile_sweep_secs
//! = 0` disables the sweep; the hooks still run.
//!
//! It runs whatever `protected_channels.enabled`, `formats_v2` and the
//! entitlement state say, so removal always works: nothing here gates on
//! the first or the last, and `reconcile_channel` reads none of the three.
//!
//! While `formats_v2` is on it is also the repair path of a device
//! revocation (6.3 "Device revocation"). `Session::delete` deletes the
//! session before revoking its devices, so a revocation that fails there
//! leaves an identity bound to a dead session, and a revocation that ran
//! while the flag was off queued nothing. Every member device of an open
//! Text group whose identity row is absent, whose bound session no longer
//! exists, or which a newer identity on the same session superseded gets
//! `add_pending_device_removal`, as the revocation's pending pass would
//! have done (the device that signed the list gets `signer_lost` instead,
//! S2-D15). Only the open Text groups of channels with an active seat are
//! looked at: no query lists open Text groups on their own.
//!
//! Multi-replica safety: crond has no leader election, so every replica
//! sweeps. No claim is needed: a release is a compare-and-set on the seat's
//! `seated_at`, and a pending entry is only added where none is, so two
//! sweeps at once release and queue each thing once.
//!
//! One channel failing is logged and the sweep goes on with the rest; the
//! first failure of a run goes to Sentry, and the run ends with a summary.
//! A page that cannot be read ends the run, and the next one starts over.
//!
//! The reconciler's report of a list signer it kept (#222) repeats on every
//! sweep for as long as that signer lacks access. It is kept as it is: it is
//! written inside `reconcile_channel`, so this task cannot throttle it
//! without throttling the reconcile.
//!
//! The config is frozen into the process at first access, so a change takes
//! a crond restart.

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    time::Duration,
};

use iso8601_timestamp::Timestamp;
use log::{debug, error, info, warn};
use revolt_config::ProtectedChannelFeatures;
use revolt_database::{
    events::client::EventV1, util::protected_access::reconcile_channel, Database, E2EEIdentity,
    MlsGroup, MlsGroupKind, AMQP, PROTECTED_SCOPE_TEXT_GROUP,
};
use revolt_result::{ErrorType, Result};
use tokio::time::sleep;

/// Channel ids read per page
const PAGE: i64 = 200;

/// How long a disabled sweep sleeps before it reads its config again. The
/// config is frozen into the process, so this only keeps the task alive.
const DISABLED_RECHECK: Duration = Duration::from_secs(300);

/// What one sweep did
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Counts {
    /// Channels visited
    channels: u64,
    /// Seats released
    released: u64,
    /// Dead devices whose pending pass wrote a group (an entry, or
    /// `signer_lost` for the list's signer device)
    queued: u64,
    /// Channels whose reconcile or device repair failed
    failed: u64,
}

/// What one tick did
#[derive(Debug, PartialEq, Eq)]
enum Tick {
    /// `reconcile_sweep_secs = 0`: nothing was read
    Disabled,
    /// Every channel with an active seat was visited
    Swept(Counts),
    /// A page could not be read; the channels after it wait for the next run
    PageFailed(Counts),
}

/// Why a member device is queued for removal
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeadDevice {
    /// No identity row: revoked, but no pending pass ran (it failed, or the
    /// revocation ran while `formats_v2` was off)
    NoIdentity,
    /// The session the identity is bound to no longer exists
    DeadSession,
    /// A newer identity of the same user is bound to the same session (the
    /// same-session predecessor sweep did not finish)
    Superseded,
}

/// Whether a session id names a session, for one sweep. A deleted session
/// never comes back (ids are not reused), so "gone" holds; one that exists
/// may be deleted during the sweep, and the next sweep finds that.
type SessionCache = HashMap<String, bool>;

/// Sweep every `reconcile_sweep_secs`. Never returns: with the sweep
/// disabled each tick is a no-op.
pub async fn task(db: Database, _: AMQP) -> Result<()> {
    let mut disabled_logged = false;

    loop {
        let features = revolt_config::config()
            .await
            .features
            .protected_channels
            .clone();

        if tick(&db, &features, PAGE).await == Tick::Disabled && !disabled_logged {
            info!("protected-access sweep is disabled (reconcile_sweep_secs = 0)");
            disabled_logged = true;
        }

        sleep(period(&features)).await;
    }
}

/// The time between two ticks
fn period(features: &ProtectedChannelFeatures) -> Duration {
    match features.reconcile_sweep_secs {
        0 => DISABLED_RECHECK,
        secs => Duration::from_secs(secs),
    }
}

/// One tick: every channel with an active seat, reconciled, and while
/// `formats_v2` is on its dead member devices queued. `enabled` is never
/// read. Every failure is logged here; nothing propagates out of the loop.
async fn tick(db: &Database, features: &ProtectedChannelFeatures, page: i64) -> Tick {
    if features.reconcile_sweep_secs == 0 {
        debug!("protected-access sweep skipped, reconcile_sweep_secs = 0");
        return Tick::Disabled;
    }

    let outcome = sweep_with(db, page, features.formats_v2, |channel_id| async move {
        reconcile_channel(db, &channel_id).await
    })
    .await;

    match &outcome {
        Tick::Swept(counts) if counts.failed > 0 => error!(
            "protected-access sweep: {} channels, {} seats released, {} devices queued, \
             {} channels failed and are retried next sweep",
            counts.channels, counts.released, counts.queued, counts.failed
        ),
        Tick::Swept(counts) if counts.released > 0 || counts.queued > 0 => info!(
            "protected-access sweep: {} channels, {} seats released, {} devices queued",
            counts.channels, counts.released, counts.queued
        ),
        Tick::Swept(counts) => debug!(
            "protected-access sweep: {} channels, nothing to release",
            counts.channels
        ),
        Tick::PageFailed(counts) => error!(
            "protected-access sweep stopped early: {} channels, {} seats released, \
             {} devices queued, {} channels failed; the rest wait for the next sweep",
            counts.channels, counts.released, counts.queued, counts.failed
        ),
        Tick::Disabled => {}
    }

    outcome
}

/// Page through every channel with an active seat in channel id order and
/// hand each to `reconcile` (tests inject one), then, with
/// `repair_devices`, queue its dead member devices. A failed channel is
/// logged and the sweep goes on; only the first failure of a run is sent to
/// Sentry, so one systematic fault does not report once per channel.
async fn sweep_with<F, Fut>(db: &Database, page: i64, repair_devices: bool, reconcile: F) -> Tick
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<Vec<String>>>,
{
    let mut after: Option<String> = None;
    let mut counts = Counts::default();
    let mut sessions = SessionCache::new();

    loop {
        let channel_ids = match db
            .fetch_channels_with_active_seats(after.clone(), page)
            .await
        {
            Ok(channel_ids) => channel_ids,
            Err(error) => {
                error!("PROTECTED_ACCESS_SWEEP_PAGE_FAILED after={after:?}: {error:?}");
                revolt_config::capture_error(&error);
                return Tick::PageFailed(counts);
            }
        };

        let Some(last) = channel_ids.last().cloned() else {
            return Tick::Swept(counts);
        };

        // A page that does not move past its cursor would be read forever
        if after.as_deref().is_some_and(|after| last.as_str() <= after) {
            error!("PROTECTED_ACCESS_SWEEP_PAGE_FAILED after={after:?}: the page did not advance");
            return Tick::PageFailed(counts);
        }

        for channel_id in channel_ids {
            counts.channels += 1;
            let mut failure = None;

            match reconcile(channel_id.clone()).await {
                Ok(released) => counts.released += released.len() as u64,
                Err(error) => {
                    error!(
                        "PROTECTED_ACCESS_RECONCILE_FAILED channel={channel_id}, retrying next \
                         sweep: {error:?}"
                    );
                    failure = Some(error);
                }
            }

            if repair_devices {
                match repair_dead_devices(db, &channel_id, &mut sessions).await {
                    Ok(queued) => counts.queued += queued,
                    Err(error) => {
                        error!(
                            "PROTECTED_ACCESS_DEVICE_REPAIR_FAILED channel={channel_id}, \
                             retrying next sweep: {error:?}"
                        );
                        failure.get_or_insert(error);
                    }
                }
            }

            if let Some(error) = failure {
                if counts.failed == 0 {
                    revolt_config::capture_error(&error);
                }
                counts.failed += 1;
            }
        }

        after = Some(last);
    }
}

/// Queue every dead member device of `channel_id`'s open Text group (6.3
/// "Sweep"); returns how many pending passes wrote a group. Every device is
/// tried and the first error is returned at the end.
///
/// The group is read before the identities: the commit transaction refuses
/// an Add whose identity is absent, so a device in the group read had its
/// identity when it was added, and an identity read made after the group
/// read that misses its row means the device was revoked, never that it is
/// too new to be seen.
async fn repair_dead_devices(
    db: &Database,
    channel_id: &str,
    sessions: &mut SessionCache,
) -> Result<u64> {
    let Some(group) = db
        .fetch_open_mls_group_for_channel(channel_id, MlsGroupKind::Text)
        .await?
    else {
        return Ok(0);
    };

    let mut queued = 0;
    let mut first_error = None;
    for (user_id, devices) in devices_to_check(&group) {
        let identities = match db.fetch_e2ee_identities(user_id).await {
            Ok(identities) => identities,
            Err(error) => {
                error!("protected-access sweep: identities of {user_id} unreadable: {error:?}");
                first_error.get_or_insert(error);
                continue;
            }
        };

        for device_id in devices {
            let dead = match dead_device(db, &identities, device_id, sessions).await {
                Ok(Some(dead)) => dead,
                Ok(None) => continue,
                Err(error) => {
                    error!(
                        "protected-access sweep: session of {user_id}/{device_id} unreadable: \
                         {error:?}"
                    );
                    first_error.get_or_insert(error);
                    continue;
                }
            };

            match db
                .add_pending_device_removal(user_id, device_id, Timestamp::now_utc())
                .await
            {
                // Queued since the group was read (another replica, or the
                // revocation itself)
                Ok(channels) if channels.is_empty() => {}
                Ok(channels) => {
                    warn!(
                        "protected-access sweep queued a dead device: user={user_id} \
                         device={device_id} cause={dead:?} channels={channels:?}"
                    );
                    queued += 1;
                    publish_text_group_changed(channels).await;
                }
                Err(error) => {
                    error!(
                        "protected-access sweep: queueing {user_id}/{device_id} failed: \
                         {error:?}"
                    );
                    first_error.get_or_insert(error);
                }
            }
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(queued),
    }
}

/// The member devices of `group` worth a look, by user: not already
/// pending removal, and not the lost signer device (`signer_lost` names it
/// already, so a pass would write nothing)
fn devices_to_check(group: &MlsGroup) -> BTreeMap<&str, Vec<&str>> {
    let mut devices: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for member in &group.members {
        let pending = group.pending_device_removals.iter().any(|pending| {
            pending.user_id == member.user_id && pending.device_id == member.device_id
        });
        let lost = group.signer_lost.as_ref().is_some_and(|lost| {
            lost.user_id == member.user_id && lost.device_id == member.device_id
        });
        if !pending && !lost {
            devices
                .entry(member.user_id.as_str())
                .or_default()
                .push(member.device_id.as_str());
        }
    }
    devices
}

/// Whether the member device `device_id` is dead, given every identity row
/// of its user, and why
async fn dead_device(
    db: &Database,
    identities: &[E2EEIdentity],
    device_id: &str,
    sessions: &mut SessionCache,
) -> Result<Option<DeadDevice>> {
    let Some(identity) = identities
        .iter()
        .find(|identity| identity.device_id == device_id)
    else {
        return Ok(Some(DeadDevice::NoIdentity));
    };

    if !session_exists(db, &identity.last_session_id, sessions).await? {
        return Ok(Some(DeadDevice::DeadSession));
    }

    Ok(superseded(identities, identity).then_some(DeadDevice::Superseded))
}

/// Whether the session still exists. An identity bound to no session (an
/// empty id) is bound to a dead one.
async fn session_exists(
    db: &Database,
    session_id: &str,
    sessions: &mut SessionCache,
) -> Result<bool> {
    if session_id.is_empty() {
        return Ok(false);
    }
    if let Some(exists) = sessions.get(session_id) {
        return Ok(*exists);
    }

    let exists = match db.fetch_session(session_id).await {
        Ok(_) => true,
        // Both drivers answer a missing session `UnknownUser`
        Err(error) if matches!(error.error_type, ErrorType::UnknownUser) => false,
        Err(error) => return Err(error),
    };
    sessions.insert(session_id.to_string(), exists);
    Ok(exists)
}

/// Whether another identity of the same user is bound to the same session
/// and is newer: it published keys or proved a device claim later
/// (`last_seen_at`, then `created_at`). One session is one install (the
/// same-session predecessor sweep's assumption), so the older row is a wiped
/// predecessor whose revocation did not finish. A tie supersedes neither.
fn superseded(identities: &[E2EEIdentity], identity: &E2EEIdentity) -> bool {
    identities.iter().any(|other| {
        other.device_id != identity.device_id
            && other.last_session_id == identity.last_session_id
            && (&other.last_seen_at, &other.created_at)
                > (&identity.last_seen_at, &identity.created_at)
    })
}

/// `ProtectedChannelChanged { scope: ["text_group"] }` on each channel a
/// pending pass wrote, as the revocation sends it (7.5; viewers only)
async fn publish_text_group_changed(channels: Vec<String>) {
    for channel_id in channels {
        EventV1::ProtectedChannelChanged {
            id: channel_id.clone(),
            scope: vec![PROTECTED_SCOPE_TEXT_GROUP.to_string()],
        }
        .p(channel_id)
        .await;
    }
}

#[cfg(test)]
mod tests {
    //! Database tests run on the driver `TEST_DB` names, REFERENCE and
    //! MONGODB (never without it: `DatabaseInfo::Test` panics rather than
    //! reach the configured database).

    use std::sync::Mutex;

    use iso8601_timestamp::Duration as TimeDuration;
    use revolt_database::{
        test_teardown::TestDatabaseGuard, AuditLogAction, Channel, ChannelEntitlement,
        ChannelEntitlementSource, ChannelEntitlementState, ChannelSeat, DatabaseInfo,
        E2EESignedKey, Member, MemberCompositeKey, MlsMemberDevice, PartialMember, Role,
        SeatListBody, SeatListSubmission, Server, Session, User,
    };
    use revolt_permissions::{ChannelPermission, OverrideField, DEFAULT_PERMISSION_SERVER};
    use revolt_result::create_error;

    use super::*;

    const SERVER: &str = "01HZXSERVERSERVERSERVERSER";
    /// Hidden from `ROLE_HIDDEN`
    const CHANNEL: &str = "01J9Z3K4M5N6P7Q8R9S0T1V2W3";
    const CHANNEL_2: &str = "01J9Z3K4M5N6P7Q8R9S0T1V2W4";
    /// Server owner and list signer
    const USER_A: &str = "01HZXAAAAAAAAAAAAAAAAAAAAA";
    const USER_B: &str = "01HZXBBBBBBBBBBBBBBBBBBBBB";
    const USER_C: &str = "01HZXCCCCCCCCCCCCCCCCCCCCC";
    const USER_D: &str = "01HZXDDDDDDDDDDDDDDDDDDDDD";
    /// The device that signed both lists
    const DEVICE_A: &str = "00112233445566778899aabbccddeeff";
    /// Denies View on `CHANNEL` only (a channel override)
    const ROLE_HIDDEN: &str = "01HZXR0LEH1DDEN00000000000";
    /// Denies View server-wide
    const ROLE_BLIND: &str = "01HZXR0LEB11ND000000000000";
    const SESSION_A: &str = "01HZXSESS10NAAAAAAAAAAAAAA";
    const SESSION_C: &str = "01HZXSESS10NCCCCCCCCCCCCCC";
    /// Never stored: a deleted session
    const SESSION_GONE: &str = "01HZXSESS10NG0NE0000000000";

    /// Fixed whole-millisecond time (Mongo stores Int64 milliseconds)
    fn at(days: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(TimeDuration::milliseconds(1_790_812_800_000))
            .and_then(|base| base.checked_add(TimeDuration::days(days)))
            .unwrap()
    }

    fn view() -> i64 {
        ChannelPermission::ViewChannel as i64
    }

    fn features(
        reconcile_sweep_secs: u64,
        enabled: bool,
        formats_v2: bool,
    ) -> ProtectedChannelFeatures {
        ProtectedChannelFeatures {
            enabled,
            formats_v2,
            reconcile_sweep_secs,
            ..Default::default()
        }
    }

    /// A fresh, migrated database on the driver `TEST_DB` names, in the
    /// harness name shape the guard drops when the test ends, panics
    /// included
    async fn test_db() -> (Database, TestDatabaseGuard) {
        let suffix = 1_000_000 + (ulid::Ulid::new().random() % 9_000_000);
        let db = DatabaseInfo::Test(format!("revolt_test_{suffix}"))
            .connect()
            .await
            .expect("test database");
        let guard = TestDatabaseGuard::arm(&db).await;
        db.migrate_database().await.expect("schema");
        (db, guard)
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

    fn server() -> Server {
        let mut server: Server = serde_json::from_value(serde_json::json!({
            "_id": SERVER,
            "owner": USER_A,
            "name": "protected",
            "channels": [CHANNEL, CHANNEL_2],
            "default_permissions": *DEFAULT_PERMISSION_SERVER as i64,
        }))
        .unwrap();
        server.roles = HashMap::from([
            (ROLE_HIDDEN.to_string(), role(ROLE_HIDDEN, 1, 0)),
            (ROLE_BLIND.to_string(), role(ROLE_BLIND, 2, view())),
        ]);
        server
    }

    fn channel(id: &str, hidden: bool) -> Channel {
        let mut role_permissions = HashMap::new();
        if hidden {
            role_permissions.insert(ROLE_HIDDEN.to_string(), OverrideField { a: 0, d: view() });
        }
        Channel::TextChannel {
            id: id.to_string(),
            server: SERVER.to_string(),
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

    fn submission(channel_id: &str, seats: &[&str]) -> SeatListSubmission {
        SeatListSubmission {
            body: SeatListBody {
                channel_id: channel_id.to_string(),
                version: 1,
                device_cap: 5,
                issued_at: 1_790_812_800_000,
                signer_user_id: USER_A.to_string(),
                signer_device_id: DEVICE_A.to_string(),
                seats: seats.iter().map(|seat| seat.to_string()).collect(),
                v2: None,
            }
            .build()
            .unwrap(),
            // The database checks the encoding only; the route verifies it
            signature: format!("B{}", "A".repeat(85)),
            signer_device_id: DEVICE_A.to_string(),
            handover: None,
            authority: None,
        }
    }

    /// Users A to D, every one a member of `SERVER` with no role (so every
    /// one may view both channels), and `CHANNEL` and `CHANNEL_2` protected
    /// (v1 genesis) with `seated`
    #[allow(clippy::disallowed_methods)]
    async fn world(db: &Database, seated: &[&str]) {
        for id in [USER_A, USER_B, USER_C, USER_D] {
            db.insert_user(&User {
                id: id.to_string(),
                username: format!("user{}", &id[20..]),
                discriminator: "0001".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        db.insert_server(&server()).await.unwrap();
        for id in [USER_A, USER_B, USER_C, USER_D] {
            db.insert_or_merge_member(&Member {
                id: MemberCompositeKey {
                    server: SERVER.to_string(),
                    user: id.to_string(),
                },
                ..Default::default()
            })
            .await
            .unwrap();
        }
        for (id, hidden) in [(CHANNEL, true), (CHANNEL_2, false)] {
            db.insert_channel(&channel(id, hidden)).await.unwrap();
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
            db.protect_channel(id, &submission(id, seated), at(0))
                .await
                .unwrap();
        }
    }

    /// The injected permission change: `user_id`'s roles become `roles`
    async fn set_roles(db: &Database, user_id: &str, roles: &[&str]) {
        db.update_member(
            &MemberCompositeKey {
                server: SERVER.to_string(),
                user: user_id.to_string(),
            },
            &PartialMember {
                roles: Some(roles.iter().map(|role| role.to_string()).collect()),
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();
    }

    async fn seat_of(db: &Database, channel_id: &str, user_id: &str) -> ChannelSeat {
        db.fetch_channel_seats(channel_id)
            .await
            .unwrap()
            .into_iter()
            .find(|seat| seat.user_id == user_id)
            .expect("a seat row")
    }

    /// The `ProtectedSeatRelease` entries of `SERVER` as sorted
    /// `(target, channel)` pairs
    async fn release_entries(db: &Database) -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = db
            .fetch_audit_log(
                SERVER,
                None,
                100,
                Some(AuditLogAction::ProtectedSeatRelease),
                None,
            )
            .await
            .unwrap()
            .into_iter()
            .map(|entry| {
                (
                    entry.target.expect("target = the user"),
                    entry.channel.expect("channel"),
                )
            })
            .collect();
        pairs.sort();
        pairs
    }

    fn device(byte: &str) -> String {
        byte.repeat(16)
    }

    fn identity(user_id: &str, device_id: &str, session_id: &str, last_seen: i64) -> E2EEIdentity {
        E2EEIdentity {
            id: format!("{user_id}:{device_id}"),
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            protocol_version: 1,
            ed25519_key: "A".repeat(43),
            curve25519_key: "B".repeat(43),
            signature: "C".repeat(86),
            fallback_key: E2EESignedKey {
                key_id: "AAAAAAAAAAA".to_string(),
                key: "D".repeat(43),
                signature: "E".repeat(86),
            },
            previous_fallback_key: None,
            created_at: at(0),
            last_seen_at: at(last_seen),
            last_session_id: session_id.to_string(),
        }
    }

    async fn save_session(db: &Database, id: &str, user_id: &str) {
        db.save_session(&Session {
            id: id.to_string(),
            user_id: user_id.to_string(),
            token: format!("token-{id}"),
            name: "test".to_string(),
            last_seen: at(0),
            origin: None,
            subscription: None,
        })
        .await
        .unwrap();
    }

    /// An open Text group of `channel_id` holding `members`
    fn text_group(id_byte: &str, channel_id: &str, members: &[(&str, String)]) -> MlsGroup {
        MlsGroup {
            id: id_byte.repeat(32),
            channel_id: channel_id.to_string(),
            open: true,
            created_by: MlsMemberDevice {
                user_id: USER_A.to_string(),
                device_id: DEVICE_A.to_string(),
            },
            created_at: at(0),
            current_epoch: 1,
            members: members
                .iter()
                .map(|(user_id, device_id)| MlsMemberDevice {
                    user_id: user_id.to_string(),
                    device_id: device_id.clone(),
                })
                .collect(),
            closed_at: None,
            superseded_by: None,
            kind: MlsGroupKind::Text,
            generation: Some(0),
            seat_list_ad_sha256: Some("ab".repeat(32)),
            pending_removals: vec![],
            member_added: vec![],
            pending_device_removals: vec![],
            signer_lost: None,
            rejoin_readd: vec![],
        }
    }

    /// Store a Text group directly: the real create path needs a signed
    /// request and the route; the pending pass reads only the group's
    /// kind, `open`, members and channel, and the stored signer. Typed
    /// writes, so Mongo stores it exactly as the driver's own inserts do.
    async fn seed_group(db: &Database, group: &MlsGroup) {
        match db {
            Database::Reference(reference) => {
                reference
                    .mls_groups
                    .lock()
                    .await
                    .insert(group.id.clone(), group.clone());
            }
            Database::MongoDb(mongo) => {
                mongo
                    .col::<MlsGroup>("mls_groups")
                    .insert_one(group)
                    .await
                    .expect("text group");
            }
        }
    }

    /// The group's pending device entries, sorted `(user, device)`
    async fn pending_devices(db: &Database, group_id: &str) -> Vec<(String, String)> {
        let mut pending: Vec<(String, String)> = db
            .fetch_mls_group(group_id)
            .await
            .unwrap()
            .pending_device_removals
            .into_iter()
            .map(|pending| (pending.user_id, pending.device_id))
            .collect();
        pending.sort();
        pending
    }

    fn swept(counts: &Tick) -> Counts {
        match counts {
            Tick::Swept(counts) => counts.clone(),
            other => panic!("expected a full sweep, got {other:?}"),
        }
    }

    /// 6.3 "Sweep": a seated member who loses View after being seated is
    /// released by the next sweep, with its audit entry; nobody else is,
    /// and a second sweep releases nothing. Control: the reconcile call
    /// dropped from the tick.
    #[tokio::test]
    async fn the_sweep_releases_a_holder_who_lost_view() {
        let (db, _guard) = test_db().await;
        world(&db, &[USER_A, USER_B, USER_C]).await;
        let on = features(300, true, true);

        // Everyone can view: nothing to release (the release below is the
        // injected change's, not the fixture's)
        let first = swept(&tick(&db, &on, PAGE).await);
        assert_eq!((first.channels, first.released, first.failed), (2, 0, 0));

        set_roles(&db, USER_B, &[ROLE_HIDDEN]).await;
        let counts = swept(&tick(&db, &on, PAGE).await);
        assert_eq!(
            counts,
            Counts {
                channels: 2,
                released: 1,
                queued: 0,
                failed: 0
            }
        );
        assert!(seat_of(&db, CHANNEL, USER_B).await.released_at.is_some());
        assert!(seat_of(&db, CHANNEL_2, USER_B).await.is_active(), "the override is per channel");
        for user in [USER_A, USER_C] {
            assert!(seat_of(&db, CHANNEL, user).await.is_active(), "{user}");
        }
        assert_eq!(
            release_entries(&db).await,
            vec![(USER_B.to_string(), CHANNEL.to_string())]
        );

        let again = swept(&tick(&db, &on, PAGE).await);
        assert_eq!((again.released, again.failed), (0, 0));
        assert_eq!(release_entries(&db).await.len(), 1);
    }

    /// Removal always works: with `enabled` and `formats_v2` both off the
    /// sweep still releases (here a member denied View server-wide, in both
    /// channels). Control: gate the tick on `enabled`.
    #[tokio::test]
    async fn the_sweep_runs_with_both_flags_off() {
        let (db, _guard) = test_db().await;
        world(&db, &[USER_A, USER_C, USER_D]).await;
        set_roles(&db, USER_D, &[ROLE_BLIND]).await;

        let counts = swept(&tick(&db, &features(300, false, false), 1).await);
        assert_eq!(
            counts,
            Counts {
                channels: 2,
                released: 2,
                queued: 0,
                failed: 0
            }
        );
        assert_eq!(
            release_entries(&db).await,
            vec![
                (USER_D.to_string(), CHANNEL.to_string()),
                (USER_D.to_string(), CHANNEL_2.to_string()),
            ]
        );
    }

    /// `reconcile_sweep_secs = 0` disables the sweep (L1k): nothing is
    /// read or released, and the task only rechecks. The same database
    /// with the default period releases, so the first half is not vacuous.
    /// Control: the zero check removed.
    #[tokio::test]
    async fn zero_seconds_disables_the_sweep() {
        let (db, _guard) = test_db().await;
        world(&db, &[USER_A, USER_B]).await;
        set_roles(&db, USER_B, &[ROLE_HIDDEN]).await;

        assert_eq!(tick(&db, &features(0, true, true), PAGE).await, Tick::Disabled);
        assert!(seat_of(&db, CHANNEL, USER_B).await.is_active());
        assert!(release_entries(&db).await.is_empty());

        assert_eq!(period(&features(0, true, true)), DISABLED_RECHECK);
        assert_eq!(period(&features(60, true, true)), Duration::from_secs(60));
        assert_eq!(
            period(&ProtectedChannelFeatures::default()),
            Duration::from_secs(300)
        );

        let counts = swept(&tick(&db, &features(300, true, true), PAGE).await);
        assert_eq!(counts.released, 1);
        assert!(seat_of(&db, CHANNEL, USER_B).await.released_at.is_some());
    }

    /// Replicas sweeping at once converge: the seat is released once, with
    /// one audit entry, and the dead device gets one pending entry (the
    /// `seated_at` compare-and-set and "already pending"). Four sweeps on a
    /// multi-thread runtime, so the drivers really interleave. Control (it
    /// bites only when two sweeps read the seat before either releases it,
    /// which every Mongo round trip makes likely): count a lost
    /// compare-and-set as a release.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_sweeps_converge() {
        let (db, _guard) = test_db().await;
        world(&db, &[USER_A, USER_B, USER_C]).await;
        set_roles(&db, USER_B, &[ROLE_HIDDEN]).await;
        save_session(&db, SESSION_A, USER_A).await;
        db.insert_e2ee_identity(&identity(USER_A, DEVICE_A, SESSION_A, 0))
            .await
            .unwrap();
        // C's device has no identity row: revoked without a pending pass
        let group = text_group(
            "bb",
            CHANNEL_2,
            &[(USER_A, DEVICE_A.to_string()), (USER_C, device("c1"))],
        );
        seed_group(&db, &group).await;

        let on = features(300, true, true);
        let sweeps: Vec<_> = (0..4)
            .map(|_| {
                let db = db.clone();
                let on = on.clone();
                tokio::spawn(async move { tick(&db, &on, 1).await })
            })
            .collect();
        let mut all = Vec::new();
        for sweep in sweeps {
            all.push(swept(&sweep.await.expect("the sweep task")));
        }

        assert!(all.iter().all(|counts| counts.failed == 0), "{all:?}");
        assert_eq!(all.iter().map(|counts| counts.released).sum::<u64>(), 1, "{all:?}");
        assert_eq!(all.iter().map(|counts| counts.queued).sum::<u64>(), 1, "{all:?}");
        assert!(seat_of(&db, CHANNEL, USER_B).await.released_at.is_some());
        assert_eq!(
            release_entries(&db).await,
            vec![(USER_B.to_string(), CHANNEL.to_string())]
        );
        assert_eq!(
            pending_devices(&db, &group.id).await,
            vec![(USER_C.to_string(), device("c1"))]
        );
    }

    /// 6.3 "Device revocation", RR#S2-9: while `formats_v2` is on, a member
    /// device with no identity row (c1), one bound to a deleted session
    /// (c2) and one a newer identity on the same session superseded (c3)
    /// are queued; the live device on that session (c4) and the signer's
    /// live device are not, and a repeat writes nothing. With the flag off
    /// nothing is queued. Controls: the repair run with the flag off; a
    /// missing session read as live; an absent identity read as live; the
    /// supersession compared the wrong way.
    #[tokio::test]
    async fn the_dead_device_repair_runs_only_while_formats_v2_is_on() {
        let (db, _guard) = test_db().await;
        world(&db, &[USER_A, USER_C]).await;
        save_session(&db, SESSION_A, USER_A).await;
        save_session(&db, SESSION_C, USER_C).await;
        for row in [
            identity(USER_A, DEVICE_A, SESSION_A, 0),
            identity(USER_C, &device("c2"), SESSION_GONE, 0),
            identity(USER_C, &device("c3"), SESSION_C, 1),
            identity(USER_C, &device("c4"), SESSION_C, 2),
        ] {
            db.insert_e2ee_identity(&row).await.unwrap();
        }
        let group = text_group(
            "aa",
            CHANNEL,
            &[
                (USER_A, DEVICE_A.to_string()),
                (USER_C, device("c1")),
                (USER_C, device("c2")),
                (USER_C, device("c3")),
                (USER_C, device("c4")),
            ],
        );
        seed_group(&db, &group).await;

        let off = swept(&tick(&db, &features(300, true, false), PAGE).await);
        assert_eq!((off.queued, off.failed), (0, 0));
        assert!(pending_devices(&db, &group.id).await.is_empty());

        let on = swept(&tick(&db, &features(300, true, true), PAGE).await);
        assert_eq!((on.queued, on.released, on.failed), (3, 0, 0));
        assert_eq!(
            pending_devices(&db, &group.id).await,
            vec![
                (USER_C.to_string(), device("c1")),
                (USER_C.to_string(), device("c2")),
                (USER_C.to_string(), device("c3")),
            ]
        );
        let stored = db.fetch_mls_group(&group.id).await.unwrap();
        assert_eq!(stored.signer_lost, None, "the signer's device is live");

        let again = swept(&tick(&db, &features(300, true, true), PAGE).await);
        assert_eq!((again.queued, again.failed), (0, 0));
        assert_eq!(pending_devices(&db, &group.id).await.len(), 3);
    }

    /// One channel's failed reconcile is counted and logged, and the sweep
    /// carries on with the next page: the member denied View is still
    /// released in the second channel. Control: the first error returns.
    #[tokio::test]
    async fn one_failed_channel_does_not_stop_the_sweep() {
        let (db, _guard) = test_db().await;
        world(&db, &[USER_A, USER_D]).await;
        set_roles(&db, USER_D, &[ROLE_BLIND]).await;

        let visited = Mutex::new(Vec::new());
        let db_ref = &db;
        let outcome = sweep_with(&db, 1, false, |channel_id: String| {
            visited.lock().unwrap().push(channel_id.clone());
            async move {
                if channel_id == CHANNEL {
                    Err(create_error!(InternalError))
                } else {
                    reconcile_channel(db_ref, &channel_id).await
                }
            }
        })
        .await;

        assert_eq!(
            outcome,
            Tick::Swept(Counts {
                channels: 2,
                released: 1,
                queued: 0,
                failed: 1
            })
        );
        assert_eq!(visited.into_inner().unwrap(), vec![CHANNEL, CHANNEL_2]);
        assert!(seat_of(&db, CHANNEL, USER_D).await.is_active());
        assert!(seat_of(&db, CHANNEL_2, USER_D).await.released_at.is_some());
    }

    const MAIN: &str = include_str!("../main.rs");

    /// A merge that drops the registration leaves the sweep dark with every
    /// other test green. Deleting the registration AND `pub mod
    /// protected_access_sweep;` deletes this test with the module, so the
    /// gate reads the test count as well.
    #[test]
    fn the_sweep_is_registered_inside_join() {
        let start = MAIN.find("join!(").expect("main.rs has a join!(");
        let end = start + MAIN[start..].find(");").expect("join!( is closed");
        let registration =
            "cron_task_wrapper(protected_access_sweep::task, db.clone(), amqp.clone()),";

        assert_eq!(
            MAIN[start..end]
                .lines()
                .filter(|line| line.trim() == registration)
                .count(),
            1,
            "main.rs must register the protected-access sweep exactly once inside join!("
        );
        assert_eq!(MAIN.matches("protected_access_sweep::task").count(), 1);
    }
}
