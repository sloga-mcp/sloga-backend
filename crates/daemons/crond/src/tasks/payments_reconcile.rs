//! Payments reconcile sweep (plan "crond payments_reconcile").
//!
//! Every 10 minutes, while `features.payments.enabled` is on, this hands the
//! sweep to `revolt_payments::dispatch::reconcile`: stale unpaid orders are
//! expired, pending orders are checked against Stripe, stranded fulfilments
//! and reversals are resumed, and failed or stranded webhook events are
//! fetched again and re-handled.
//!
//! `reconcile` does not look at `enabled` itself, so the gate here is the only
//! thing that keeps a disabled install from calling Stripe. The config is
//! frozen into the process at first access, so flipping the flag takes a
//! crond restart.
//!
//! crond has no leader election. Two replicas running the sweep at once is
//! safe because every order write in `dispatch` goes through the order lease,
//! and a re-driven event goes back through `handle_event`, whose order writes
//! take the same lease. At worst both replicas fetch the same event from
//! Stripe and count one extra attempt against it.
//!
//! The Stripe secret key is only handed to the client; it is never logged.

use std::time::Duration;

use log::{debug, error, info};
use revolt_database::{Database, AMQP};
use revolt_payments::{dispatch, settings::PaymentsSettings, stripe::ReqwestStripe};
use revolt_result::Result;
use tokio::time::sleep;

/// Time between sweeps
const TICK: Duration = Duration::from_secs(10 * 60);

/// What one tick did
#[derive(Debug, PartialEq, Eq)]
enum Tick {
    /// The payments config did not validate; nothing ran
    BadConfig,
    /// Payments are off; nothing ran
    Disabled,
    /// The sweep ran (its summary is logged)
    Ran,
    /// The sweep returned an error (logged)
    Failed,
}

/// Run the reconcile sweep every [`TICK`], while payments are enabled.
pub async fn task(db: Database, _: AMQP) -> Result<()> {
    loop {
        let loaded = PaymentsSettings::load().await;
        tick(&db, loaded, revolt_database::now_ms()).await;

        sleep(TICK).await;
    }
}

/// One tick: gate on the loaded settings, then run the sweep once
///
/// Every failure is logged here and the next tick tries again; nothing
/// propagates out of the loop.
async fn tick(db: &Database, loaded: Result<PaymentsSettings>, now_ms: i64) -> Tick {
    let settings = match loaded {
        Ok(settings) => settings,
        Err(err) => {
            // `PaymentsSettings::from_parts` has already logged which field
            // is wrong; the error itself carries no config values
            error!("Payments reconcile skipped, the payments config is invalid: {err:?}");
            return Tick::BadConfig;
        }
    };

    if !settings.enabled {
        debug!("Payments reconcile skipped, payments are disabled");
        return Tick::Disabled;
    }

    let stripe = ReqwestStripe::new(settings.secret_key.clone());

    match dispatch::reconcile(db, &stripe, &settings, now_ms).await {
        Ok(summary) => {
            info!("Payments reconcile: {summary}");
            Tick::Ran
        }
        Err(err) => {
            error!("Payments reconcile failed, retrying next tick: {err:?}");
            revolt_config::capture_error(&err);
            Tick::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revolt_config::{ApiStripe, FeaturePayments};
    use revolt_result::create_error;

    /// 2027-01-15T08:00:00Z
    const NOW_MS: i64 = 1_800_000_000_000;

    fn reference_db() -> Database {
        Database::Reference(Default::default())
    }

    fn settings(enabled: bool) -> PaymentsSettings {
        let payments = FeaturePayments {
            enabled,
            ..FeaturePayments::default()
        };

        PaymentsSettings::from_parts(&payments, &ApiStripe::default()).unwrap()
    }

    #[tokio::test]
    async fn disabled_config_is_a_no_op() {
        let db = reference_db();
        assert_eq!(tick(&db, Ok(settings(false)), NOW_MS).await, Tick::Disabled);
    }

    #[tokio::test]
    async fn invalid_config_is_a_no_op() {
        let db = reference_db();
        assert_eq!(
            tick(&db, Err(create_error!(InternalError)), NOW_MS).await,
            Tick::BadConfig
        );
    }

    /// The control for the two tests above: an enabled config does reach the
    /// sweep. The database is empty and the key is unset, so nothing touches
    /// the network.
    #[tokio::test]
    async fn enabled_config_runs_the_sweep() {
        let db = reference_db();
        assert_eq!(tick(&db, Ok(settings(true)), NOW_MS).await, Tick::Ran);
    }

    const MAIN: &str = include_str!("../main.rs");

    /// A merge that drops the registration leaves the sweep dark with every
    /// other test green
    #[test]
    fn the_sweep_is_registered_inside_join() {
        let start = MAIN.find("join!(").expect("main.rs has a join!(");
        let end = start + MAIN[start..].find(");").expect("join!( is closed");
        let registration = "cron_task_wrapper(payments_reconcile::task, db.clone(), amqp.clone()),";

        assert_eq!(
            MAIN[start..end]
                .lines()
                .filter(|line| line.trim() == registration)
                .count(),
            1,
            "main.rs must register the payments reconcile exactly once inside join!("
        );
        assert_eq!(MAIN.matches("payments_reconcile::task").count(), 1);
    }
}
