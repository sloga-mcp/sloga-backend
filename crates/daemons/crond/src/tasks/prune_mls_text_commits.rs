//! Commit retention for protected-channel Text MLS groups (design R9, §2.5,
//! §7.1, decisions #125 and #147).
//!
//! Once a day, Text commits older than
//! `[features.protected_channels] commit_retention_days` are deleted through
//! `prune_mls_text_commits`. A device offline longer than the window cannot
//! catch up from the stored commits and must rejoin. Call commits are never
//! touched here: Call groups age out whole through `prune_mls_groups`.
//!
//! `commit_retention_days = 0` means NEVER prune: the primitive is not called
//! at all, because a cutoff of `now - 0` would delete every commit and strand
//! every catch-up. Pruning does not look at `e2ee_enabled` or
//! `protected_channels.enabled`: it keeps running with either one off (#147).
//! The config is frozen into the process at first access, so a change takes
//! a crond restart.
//!
//! Multi-replica safety: crond has no leader election or lock, so every
//! replica runs this sweep. No claim is needed. The delete is idempotent: two
//! replicas pruning at once only repeat each other's work, and nothing at or
//! after the cutoff is ever touched.

use std::{future::Future, time::Duration};

use iso8601_timestamp::Timestamp;
use revolt_database::{Database, AMQP};
use revolt_result::Result;
use tokio::time::sleep;

/// Time between sweeps. Retention is measured in days, so a daily sweep
/// overshoots the window by at most a day.
const TICK: Duration = Duration::from_secs(24 * 60 * 60);

/// What one sweep did
#[derive(Debug, PartialEq, Eq)]
pub enum Pruned {
    /// `commit_retention_days = 0`: pruning is disabled and the prune
    /// primitive was not called
    Disabled,
    /// The window reaches past the earliest representable time, so nothing
    /// can be older than the cutoff; the prune primitive was not called
    BeyondTime,
    /// The prune ran and deleted this many Text commits
    Deleted(u64),
}

/// Prune Text commits once a day, for as long as crond runs.
pub async fn task(db: Database, _: AMQP) -> Result<()> {
    loop {
        let days = revolt_config::config()
            .await
            .features
            .protected_channels
            .commit_retention_days;

        run_once(&db, days, Timestamp::now_utc()).await?;

        sleep(TICK).await
    }
}

/// One sweep at `now` with a retention window of `days`
pub async fn run_once(db: &Database, days: u32, now: Timestamp) -> Result<Pruned> {
    run_once_with(days, now, |cutoff| db.prune_mls_text_commits(cutoff)).await
}

/// [`run_once`] with the prune primitive injected, so a test can prove it
/// is never called for `days = 0`
async fn run_once_with<F, Fut>(days: u32, now: Timestamp, prune: F) -> Result<Pruned>
where
    F: FnOnce(Timestamp) -> Fut,
    Fut: Future<Output = Result<u64>>,
{
    if days == 0 {
        log::info!("Text MLS commit pruning is disabled (commit_retention_days = 0)");
        return Ok(Pruned::Disabled);
    }

    let Some(cutoff) = now.checked_sub(iso8601_timestamp::Duration::days(i64::from(days))) else {
        log::warn!(
            "commit_retention_days = {days} reaches past the earliest representable time; \
             no Text MLS commit is old enough to prune"
        );
        return Ok(Pruned::BeyondTime);
    };

    let deleted = prune(cutoff).await?;
    log::info!("Pruned {deleted} Text MLS commits older than {days} days");
    Ok(Pruned::Deleted(deleted))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use revolt_database::test_teardown::TestDatabaseGuard;
    use revolt_database::{
        DatabaseInfo, MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupCreateOutcome, MlsGroupKind,
        MlsMemberDevice,
    };

    use super::*;

    fn days_before(now: Timestamp, days: i64) -> Timestamp {
        now.checked_sub(iso8601_timestamp::Duration::days(days))
            .unwrap()
    }

    /// A fresh test database on the driver `TEST_DB` names (which must be
    /// set: `DatabaseInfo::Test` panics without it rather than reach the
    /// configured database). The name has the harness shape
    /// `is_throwaway_test_database` allows, so the guard drops it when the
    /// test ends, panics included.
    async fn test_db() -> (Database, TestDatabaseGuard) {
        let suffix = 1_000_000 + (ulid::Ulid::new().random() % 9_000_000);
        let db = DatabaseInfo::Test(format!("revolt_test_{suffix}"))
            .connect()
            .await
            .expect("test database");
        let guard = TestDatabaseGuard::arm(&db).await;
        (db, guard)
    }

    fn device(user: &str) -> MlsMemberDevice {
        MlsMemberDevice {
            user_id: user.to_string(),
            device_id: "0a".repeat(16),
        }
    }

    fn group(id_byte: &str, channel_id: &str, kind: MlsGroupKind, now: Timestamp) -> MlsGroup {
        let creator = device("01ALICE00000000000000000000");
        MlsGroup {
            id: id_byte.repeat(32),
            channel_id: channel_id.to_string(),
            open: true,
            created_by: creator.clone(),
            created_at: days_before(now, 60),
            current_epoch: 0,
            members: vec![creator],
            closed_at: None,
            superseded_by: None,
            kind,
            generation: (kind == MlsGroupKind::Text).then_some(0),
            seat_list_ad_sha256: (kind == MlsGroupKind::Text).then(|| "ab".repeat(32)),
            pending_removals: vec![],
            member_added: vec![],
        }
    }

    fn commit(group: &MlsGroup, epoch: i64, created_at: Timestamp) -> MlsCommit {
        let payload = format!("commit_{epoch}");
        MlsCommit {
            id: MlsCommit::composite_id(&group.id, epoch),
            group_id: group.id.clone(),
            epoch,
            committer: group.created_by.clone(),
            size: payload.len() as i64,
            commit: payload,
            added: vec![],
            removed: vec![],
            created_at,
            rejoin_intents: vec![],
            removed_reasons: vec![],
        }
    }

    /// Store a Text group and its commits directly. The prune reads only the
    /// group kind and the commit `group_id` / `created_at`, and the real Text
    /// paths (`create_text_mls_group`, `insert_mls_text_commit`) need a seat
    /// list, seats and identities this crate has no fixtures for. Typed
    /// writes, so Mongo stores `created_at` as Int64 milliseconds exactly as
    /// the driver's own inserts do.
    async fn seed_text(db: &Database, group: &MlsGroup, commits: &[MlsCommit]) {
        match db {
            Database::Reference(reference) => {
                reference
                    .mls_groups
                    .lock()
                    .await
                    .insert(group.id.clone(), group.clone());
                let mut stored = reference.mls_commits.lock().await;
                for commit in commits {
                    stored.insert(commit.id.clone(), commit.clone());
                }
            }
            Database::MongoDb(mongo) => {
                mongo
                    .col::<MlsGroup>("mls_groups")
                    .insert_one(group)
                    .await
                    .expect("text group");
                for commit in commits {
                    mongo
                        .col::<MlsCommit>("mls_commits")
                        .insert_one(commit)
                        .await
                        .expect("text commit");
                }
            }
        }
    }

    /// A Call group with one 40-day-old commit, through the real Call paths
    async fn seed_call(db: &Database, now: Timestamp) -> MlsGroup {
        let call = group("cc", "01CALLCHANNEL0000000000000", MlsGroupKind::Call, now);
        assert!(matches!(
            db.create_mls_group(&call, None).await.unwrap(),
            MlsGroupCreateOutcome::Created
        ));
        assert!(matches!(
            db.insert_mls_commit(&commit(&call, 1, days_before(now, 40)))
                .await
                .unwrap(),
            MlsCommitOutcome::Won
        ));
        call
    }

    async fn epochs(db: &Database, group: &MlsGroup) -> Vec<i64> {
        db.fetch_mls_commits_from(&group.id, 0, 100)
            .await
            .unwrap()
            .iter()
            .map(|commit| commit.epoch)
            .collect()
    }

    /// `0` means never prune: the primitive is not even called (#125)
    #[tokio::test]
    async fn zero_days_never_calls_the_prune() {
        let calls = RefCell::new(Vec::new());
        let outcome = run_once_with(0, Timestamp::now_utc(), |cutoff| {
            calls.borrow_mut().push(cutoff);
            async { Ok::<u64, revolt_result::Error>(0) }
        })
        .await
        .unwrap();

        assert_eq!(outcome, Pruned::Disabled);
        assert!(calls.borrow().is_empty(), "days = 0 called the prune");
    }

    /// The cutoff handed to the primitive is exactly now minus the window
    #[tokio::test]
    async fn the_cutoff_is_now_minus_the_window() {
        let now = Timestamp::now_utc();
        let calls = RefCell::new(Vec::new());
        let outcome = run_once_with(30, now, |cutoff| {
            calls.borrow_mut().push(cutoff);
            async { Ok::<u64, revolt_result::Error>(7) }
        })
        .await
        .unwrap();

        assert_eq!(outcome, Pruned::Deleted(7));
        assert_eq!(calls.into_inner(), vec![days_before(now, 30)]);
    }

    /// A window no clock can subtract prunes nothing and does not panic
    #[tokio::test]
    async fn a_window_past_the_earliest_time_prunes_nothing() {
        let calls = RefCell::new(Vec::new());
        let outcome = run_once_with(u32::MAX, Timestamp::now_utc(), |cutoff| {
            calls.borrow_mut().push(cutoff);
            async { Ok::<u64, revolt_result::Error>(0) }
        })
        .await
        .unwrap();

        assert_eq!(outcome, Pruned::BeyondTime);
        assert!(calls.borrow().is_empty());
    }

    /// A failed prune is an error out of the sweep (the wrapper logs it,
    /// reports it and restarts the task), never a silent success
    #[tokio::test]
    async fn a_failed_prune_is_an_error() {
        let outcome = run_once_with(30, Timestamp::now_utc(), |_| async {
            Err::<u64, _>(revolt_result::create_error!(InternalError))
        })
        .await;

        assert!(outcome.is_err());
    }

    /// `0` on a real database: every Text commit survives, however old,
    /// including one a second old (a cutoff of `now - 0` would take it)
    #[tokio::test]
    async fn zero_days_keeps_every_text_commit() {
        let (db, _guard) = test_db().await;
        let now = Timestamp::now_utc();

        let text = group("aa", "01TEXTCHANNEL0000000000000", MlsGroupKind::Text, now);
        let one_second_ago = now
            .checked_sub(iso8601_timestamp::Duration::seconds(1))
            .unwrap();
        seed_text(
            &db,
            &text,
            &[
                commit(&text, 1, days_before(now, 400)),
                commit(&text, 2, days_before(now, 40)),
                commit(&text, 3, one_second_ago),
            ],
        )
        .await;
        assert_eq!(epochs(&db, &text).await, vec![1, 2, 3]);

        assert_eq!(run_once(&db, 0, now).await.unwrap(), Pruned::Disabled);
        assert_eq!(epochs(&db, &text).await, vec![1, 2, 3]);
    }

    /// `N` days: only Text commits older than the cutoff go; younger Text
    /// commits stay, and Call commits stay however old
    #[tokio::test]
    async fn n_days_prunes_only_text_commits_older_than_the_cutoff() {
        let (db, _guard) = test_db().await;
        let now = Timestamp::now_utc();

        let text = group("aa", "01TEXTCHANNEL0000000000000", MlsGroupKind::Text, now);
        let one_second = iso8601_timestamp::Duration::seconds(1);
        let cutoff = days_before(now, 30);
        seed_text(
            &db,
            &text,
            &[
                commit(&text, 1, days_before(now, 40)),
                commit(&text, 2, cutoff.checked_sub(one_second).unwrap()),
                commit(&text, 3, cutoff.checked_add(one_second).unwrap()),
                commit(&text, 4, days_before(now, 1)),
            ],
        )
        .await;
        let call = seed_call(&db, now).await;

        assert_eq!(epochs(&db, &text).await, vec![1, 2, 3, 4]);
        // Not vacuous: the stored Call commit really is past the cutoff
        let stored_call = db.fetch_mls_commits_from(&call.id, 0, 100).await.unwrap();
        assert_eq!(stored_call.len(), 1);
        assert!(stored_call[0].created_at < cutoff);

        assert_eq!(run_once(&db, 30, now).await.unwrap(), Pruned::Deleted(2));
        assert_eq!(epochs(&db, &text).await, vec![3, 4]);
        assert_eq!(
            epochs(&db, &call).await,
            vec![1],
            "Call commits are untouched"
        );

        // A second sweep at the same instant has nothing left to do
        assert_eq!(run_once(&db, 30, now).await.unwrap(), Pruned::Deleted(0));
        assert_eq!(epochs(&db, &text).await, vec![3, 4]);
    }

    const MAIN: &str = include_str!("../main.rs");

    /// A merge that drops the registration leaves retention dark with every
    /// other test green
    #[test]
    fn the_prune_is_registered_inside_join() {
        let start = MAIN.find("join!(").expect("main.rs has a join!(");
        let end = start + MAIN[start..].find(");").expect("join!( is closed");
        let registration =
            "cron_task_wrapper(prune_mls_text_commits::task, db.clone(), amqp.clone()),";

        assert_eq!(
            MAIN[start..end]
                .lines()
                .filter(|line| line.trim() == registration)
                .count(),
            1,
            "main.rs must register the Text commit prune exactly once inside join!("
        );
        assert_eq!(MAIN.matches("prune_mls_text_commits::task").count(), 1);
    }
}
