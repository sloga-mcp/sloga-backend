//! Hourly Cipher Prot sweep (D2): while features.boosts.protection.enabled AND cipher_grants_enabled,
//! page through every Cipher membership and run the upward sync; logs PROT_CIPHER_OVERPOSTED.
//! Multi-replica safe: each sync is one transaction keyed by the ledger's unique key and the membership version.
//!
//! A Cipher grant is posted right after its order is fulfilled; this sweep is
//! the backstop for everything that hook missed: memberships bought before
//! grants were turned on, a fulfil hook that failed, and a membership whose
//! dispute was won since the last run (no upward posting while a dispute is
//! listed). It runs for as long as grants are on, not once.
//!
//! Every membership, revoked or not, is handed to
//! `revolt_payments::engine::prot::sync_cipher_prot`, which decides what to
//! do: only an active, undisputed membership that is owed Prot posts, and the
//! database's read-only pre-check returns without opening a transaction for
//! every other one, so an hour with nothing owed costs one read per
//! membership. A membership that holds more than its target is logged by the
//! engine as `PROT_CIPHER_OVERPOSTED` and never clawed here.
//!
//! Two replicas sweeping at once is safe: a grant's ledger key is unique and
//! the posting bumps the membership version in the same transaction, so a
//! racing sync either finds the row already applied or retries on the new
//! state. One membership failing is logged and the sweep goes on; a page
//! that cannot be read ends this run, and the next tick starts over.
//!
//! The config is frozen into the process at first access, so turning grants
//! on or off takes a crond restart. While they are off each tick only logs at
//! debug level and sleeps.

use std::{future::Future, time::Duration};

use log::{debug, error, info};
use revolt_database::{Database, AMQP};
use revolt_payments::{engine, settings::ProtSalesSettings};
use revolt_result::Result;
use tokio::time::sleep;

/// Time between sweeps
const TICK: Duration = Duration::from_secs(60 * 60);

/// Memberships read per page
const PAGE: i64 = 200;

/// What one tick did
#[derive(Debug, PartialEq, Eq)]
enum Tick {
    /// Cipher grants are off (or the Prot config did not validate); nothing ran
    Off,
    /// Every membership was handed to the sync
    Swept { synced: u64, failed: u64 },
    /// A page could not be read; the memberships after it wait for the next tick
    PageFailed { synced: u64, failed: u64 },
}

/// Run the sweep every [`TICK`] while Cipher grants are on. Never returns:
/// while grants are off each tick is a no-op.
pub async fn task(db: Database, _: AMQP) -> Result<()> {
    loop {
        // Logs PROT_CONFIG_INVALID and reads as closed (grants off) when the
        // Prot config does not validate
        let ps = ProtSalesSettings::load_or_closed().await;
        tick(&db, &ps, PAGE).await;

        sleep(TICK).await;
    }
}

/// One tick: gate on the settings, then sync every membership once
///
/// Every failure is logged here and the next tick tries again; nothing
/// propagates out of the loop.
async fn tick(db: &Database, ps: &ProtSalesSettings, page: i64) -> Tick {
    if !ps.grants_active() {
        debug!("Cipher Prot sweep skipped, Cipher grants are off");
        return Tick::Off;
    }

    let outcome = sweep_with(db, page, |user_id| async move {
        engine::prot::sync_cipher_prot(db, ps, &user_id, revolt_database::now_ms()).await
    })
    .await;

    match &outcome {
        Tick::Swept { synced, failed } => {
            info!("Cipher Prot sweep: {synced} memberships synced, {failed} failed")
        }
        Tick::PageFailed { synced, failed } => error!(
            "Cipher Prot sweep stopped early: {synced} memberships synced, {failed} failed, \
             the rest wait for the next tick"
        ),
        Tick::Off => {}
    }

    outcome
}

/// Page through every membership in user id order and hand each to `sync`
/// (tests inject one). A failed sync is logged and the sweep goes on; only
/// the first failure of a run is sent to Sentry, so one systematic fault
/// does not report once per membership every hour.
async fn sweep_with<F, Fut>(db: &Database, page: i64, sync: F) -> Tick
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let mut after: Option<String> = None;
    let mut synced = 0_u64;
    let mut failed = 0_u64;

    loop {
        let rows = match db
            .fetch_cipher_memberships_page(after.as_deref(), page)
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                error!("PROT_CIPHER_SWEEP_PAGE_FAILED after={after:?}: {err:?}");
                revolt_config::capture_error(&err);
                return Tick::PageFailed { synced, failed };
            }
        };

        let Some(last) = rows.last().map(|m| m.user_id.clone()) else {
            return Tick::Swept { synced, failed };
        };

        // A page that does not move past its cursor would be read forever
        if after.as_deref().is_some_and(|after| last.as_str() <= after) {
            error!("PROT_CIPHER_SWEEP_PAGE_FAILED after={after:?}: the page did not advance");
            return Tick::PageFailed { synced, failed };
        }

        for m in rows {
            match sync(m.user_id.clone()).await {
                Ok(()) => synced += 1,
                Err(err) => {
                    error!(
                        "PROT_CIPHER_SYNC_FAILED user={} source=sweep, retrying next tick: {err:?}",
                        m.user_id
                    );
                    if failed == 0 {
                        revolt_config::capture_error(&err);
                    }
                    failed += 1;
                }
            }
        }

        after = Some(last);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use revolt_config::{FeaturePayments, ProtectionFeatures};
    use revolt_database::{prot_user_account, CipherMembership, CipherRevokeReason, User};
    use revolt_models::v0::{CipherTier, UserFlags};
    use revolt_result::create_error;

    use super::*;

    fn reference_db() -> Database {
        Database::Reference(Default::default())
    }

    fn prot(enabled: bool, cipher_grants_enabled: bool) -> ProtSalesSettings {
        let protection = ProtectionFeatures {
            enabled,
            cipher_grants_enabled,
            ..ProtectionFeatures::default()
        };
        ProtSalesSettings::from_parts(&FeaturePayments::default(), &protection).unwrap()
    }

    fn membership(user_id: &str, number: u32) -> CipherMembership {
        CipherMembership {
            user_id: user_id.to_string(),
            number,
            tier: CipherTier::T99,
            prot_grant: 16_500,
            orders: vec![format!("order-{user_id}")],
            disputed_orders: vec![],
            granted_at: 1_000,
            revoked_at: None,
            revoke_reason: None,
            prot_posted_at: None,
            version: 0,
        }
    }

    async fn insert_membership(db: &Database, m: &CipherMembership) {
        assert!(db.insert_cipher_membership(m).await.unwrap());
    }

    #[allow(clippy::disallowed_methods)]
    async fn insert_user(db: &Database, id: &str, deleted: bool) {
        db.insert_user(&User {
            id: id.to_string(),
            username: id.to_string(),
            discriminator: "0001".to_string(),
            flags: deleted.then_some(UserFlags::Deleted as i32),
            ..Default::default()
        })
        .await
        .unwrap();
    }

    async fn balance(db: &Database, user_id: &str) -> i64 {
        db.fetch_prot_account(&prot_user_account(user_id))
            .await
            .unwrap()
            .map_or(0, |account| account.balance)
    }

    async fn account_version(db: &Database, user_id: &str) -> u64 {
        db.fetch_prot_account(&prot_user_account(user_id))
            .await
            .unwrap()
            .map_or(0, |account| account.version)
    }

    async fn membership_version(db: &Database, user_id: &str) -> u64 {
        db.fetch_cipher_membership(user_id)
            .await
            .unwrap()
            .expect("membership exists")
            .version
    }

    async fn grant_rows(db: &Database, user_id: &str) -> usize {
        db.fetch_prot_entries_by_membership(&format!("order-{user_id}"))
            .await
            .unwrap()
            .len()
    }

    /// Five memberships, one of them revoked and one disputed: the sweep
    /// hands them all over and leaves the decision to the sync
    async fn five_memberships(db: &Database) -> Vec<String> {
        let ids: Vec<String> = ["u1", "u2", "u3", "u4", "u5"]
            .iter()
            .map(|id| id.to_string())
            .collect();
        for (number, id) in (1_u32..).zip(&ids) {
            let mut m = membership(id, number);
            if id == "u2" {
                m.revoked_at = Some(2_000);
                m.revoke_reason = Some(CipherRevokeReason::Refund);
            }
            if id == "u4" {
                m.disputed_orders = m.orders.clone();
            }
            insert_membership(db, &m).await;
        }
        ids
    }

    /// Grants off (either switch) is a no-op: the sync is never called, so
    /// a membership owed Prot gets nothing
    #[tokio::test]
    async fn grants_off_is_a_no_op() {
        let db = reference_db();
        insert_user(&db, "u1", false).await;
        insert_membership(&db, &membership("u1", 1)).await;

        for ps in [
            ProtSalesSettings::closed(),
            prot(false, false),
            prot(true, false),
            prot(false, true),
        ] {
            assert!(!ps.grants_active(), "{ps:?}");
            assert_eq!(tick(&db, &ps, PAGE).await, Tick::Off, "{ps:?}");
        }

        assert_eq!(balance(&db, "u1").await, 0);
        assert_eq!(grant_rows(&db, "u1").await, 0);
        assert_eq!(membership_version(&db, "u1").await, 0);
    }

    #[tokio::test]
    async fn an_empty_database_sweeps_nothing() {
        let db = reference_db();
        assert_eq!(
            tick(&db, &prot(true, true), PAGE).await,
            Tick::Swept {
                synced: 0,
                failed: 0
            }
        );
    }

    /// Pages smaller than the membership count still visit every membership
    /// exactly once, in user id order, revoked and disputed ones included
    #[tokio::test]
    async fn the_sweep_visits_every_membership_once_across_pages() {
        let db = reference_db();
        let ids = five_memberships(&db).await;

        for page in [1, 2, 4, 5, PAGE] {
            let visited = Mutex::new(Vec::new());
            let outcome = sweep_with(&db, page, |user_id| {
                visited.lock().unwrap().push(user_id);
                std::future::ready(Ok(()))
            })
            .await;

            assert_eq!(
                outcome,
                Tick::Swept {
                    synced: 5,
                    failed: 0
                },
                "page = {page}"
            );
            assert_eq!(visited.into_inner().unwrap(), ids, "page = {page}");
        }
    }

    /// One failing membership is counted and the sweep carries on with the
    /// rest, including the pages after it
    #[tokio::test]
    async fn one_failed_sync_does_not_stop_the_sweep() {
        let db = reference_db();
        let ids = five_memberships(&db).await;

        let visited = Mutex::new(Vec::new());
        let outcome = sweep_with(&db, 2, |user_id| {
            let fail = user_id == "u2";
            visited.lock().unwrap().push(user_id);
            std::future::ready(if fail {
                Err(create_error!(InternalError))
            } else {
                Ok(())
            })
        })
        .await;

        assert_eq!(
            outcome,
            Tick::Swept {
                synced: 4,
                failed: 1
            }
        );
        assert_eq!(visited.into_inner().unwrap(), ids);
    }

    /// The control for the no-op test, through the real engine sync: with
    /// grants on, only the live, active, undisputed members are credited
    /// their grant; a revoked or disputed member gets nothing, and a deleted
    /// member's credit is forfeited at once (contracts 11.3). A second tick
    /// posts nothing more and leaves every version alone.
    #[tokio::test]
    async fn grants_on_credits_each_owed_membership_once() {
        let db = reference_db();
        let ids = five_memberships(&db).await;
        for id in &ids {
            insert_user(&db, id, id == "u5").await;
        }
        let ps = prot(true, true);

        assert_eq!(
            tick(&db, &ps, 2).await,
            Tick::Swept {
                synced: 5,
                failed: 0
            }
        );

        let grant = 16_500;
        assert_eq!(balance(&db, "u1").await, grant);
        assert_eq!(balance(&db, "u3").await, grant);
        assert_eq!(balance(&db, "u2").await, 0, "revoked");
        assert_eq!(balance(&db, "u4").await, 0, "disputed");
        assert_eq!(balance(&db, "u5").await, 0, "deleted");
        assert_eq!(grant_rows(&db, "u1").await, 1);
        assert_eq!(grant_rows(&db, "u3").await, 1);
        assert_eq!(grant_rows(&db, "u2").await, 0);
        assert_eq!(grant_rows(&db, "u4").await, 0);

        let mut before = Vec::new();
        for id in &ids {
            before.push((
                account_version(&db, id).await,
                membership_version(&db, id).await,
            ));
        }

        assert_eq!(
            tick(&db, &ps, 2).await,
            Tick::Swept {
                synced: 5,
                failed: 0
            }
        );

        assert_eq!(balance(&db, "u1").await, grant);
        assert_eq!(balance(&db, "u3").await, grant);
        assert_eq!(balance(&db, "u5").await, 0, "deleted");
        assert_eq!(grant_rows(&db, "u1").await, 1);
        assert_eq!(grant_rows(&db, "u3").await, 1);
        for (id, before) in ids.iter().zip(before) {
            let after = (
                account_version(&db, id).await,
                membership_version(&db, id).await,
            );
            assert_eq!(after, before, "{id}: a tick with nothing owed wrote");
        }
    }

    const MAIN: &str = include_str!("../main.rs");

    /// A merge that drops the registration leaves the sweep dark with every
    /// other test green
    #[test]
    fn the_sweep_is_registered_inside_join() {
        let start = MAIN.find("join!(").expect("main.rs has a join!(");
        let end = start + MAIN[start..].find(");").expect("join!( is closed");
        let registration =
            "cron_task_wrapper(prot_cipher_backfill::task, db.clone(), amqp.clone()),";

        assert_eq!(
            MAIN[start..end]
                .lines()
                .filter(|line| line.trim() == registration)
                .count(),
            1,
            "main.rs must register the Cipher Prot sweep exactly once inside join!("
        );
        assert_eq!(MAIN.matches("prot_cipher_backfill::task").count(), 1);
    }
}
