//! Payments reconcile sweep (plan "crond payments_reconcile").
//!
//! Every 10 minutes, while a Stripe secret key is configured
//! (`[api.stripe] secret_key`), this hands the sweep to
//! `revolt_payments::dispatch::reconcile`: stale unpaid orders are expired,
//! pending orders are checked against Stripe, stranded fulfilments and
//! reversals are resumed, open disputes are re-read, and failed or stranded
//! webhook events are fetched again and re-handled.
//!
//! The gate is the key, NOT `features.payments.enabled`. That switch stops
//! new checkouts; the sweep never starts a sale, it only settles money that
//! was already taken (a paid order is fulfilled or refunded, a refund or a
//! dispute is applied, a void waiting on a dispute is finished). Gating it on
//! `enabled` would strand those orders the moment the kill switch is
//! flipped. Without a key there is nothing at Stripe to settle with, so the
//! tick does nothing. The config is frozen into the process at first access,
//! so a change takes a crond restart.
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
    /// No Stripe secret key is configured; nothing ran
    NotConfigured,
    /// The sweep ran (its summary is logged)
    Ran,
    /// The sweep returned an error (logged)
    Failed,
}

/// Run the reconcile sweep every [`TICK`], while a Stripe key is configured.
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

    // Not `settings.enabled`: see the module docs
    if settings.secret_key.is_empty() {
        debug!("Payments reconcile skipped, no Stripe secret key is configured");
        return Tick::NotConfigured;
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

    /// A key-shaped value, built at runtime. The client is handed it, but
    /// with an empty database the sweep makes no Stripe call.
    fn configured_key() -> String {
        ["sk", "test", "reconcile", "tick", "placeholder"].join("_")
    }

    fn settings(enabled: bool, secret_key: String) -> PaymentsSettings {
        let payments = FeaturePayments {
            enabled,
            ..FeaturePayments::default()
        };
        let stripe = ApiStripe {
            secret_key,
            ..ApiStripe::default()
        };

        PaymentsSettings::from_parts(&payments, &stripe).unwrap()
    }

    /// Without a key there is nothing to settle with, whatever `enabled` says
    #[tokio::test]
    async fn no_secret_key_is_a_no_op() {
        let db = reference_db();
        for enabled in [false, true] {
            assert_eq!(
                tick(&db, Ok(settings(enabled, String::new())), NOW_MS).await,
                Tick::NotConfigured,
                "enabled = {enabled}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_config_is_a_no_op() {
        let db = reference_db();
        assert_eq!(
            tick(&db, Err(create_error!(InternalError)), NOW_MS).await,
            Tick::BadConfig
        );
    }

    /// The kill switch stops checkouts, never the settling of money already
    /// taken: a configured key runs the sweep with payments disabled. The
    /// control for the two tests above. The database is empty, so nothing
    /// touches the network.
    #[tokio::test]
    async fn disabled_but_configured_runs_the_sweep() {
        let db = reference_db();
        assert_eq!(
            tick(&db, Ok(settings(false, configured_key())), NOW_MS).await,
            Tick::Ran
        );
    }

    #[tokio::test]
    async fn enabled_and_configured_runs_the_sweep() {
        let db = reference_db();
        assert_eq!(
            tick(&db, Ok(settings(true, configured_key())), NOW_MS).await,
            Tick::Ran
        );
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
