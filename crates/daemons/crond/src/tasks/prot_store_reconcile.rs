//! In-app Prot reconcile (S6), every 10 minutes while store credentials are configured (NOT gated on the open
//! flags): Play RTDN pull (ack after commit), consume retries, daily voidedpurchases from the cursor, hourly Apple
//! Notification History from the cursor (2 h overlap), Held → Credited when unpaused, expire intents, alerts.
//! Multi-replica safe: ledger keys + row version CAS + cursor CAS + alert claims.
//!
//! Every step is `revolt_payments::engine::prot_store::reconcile_store`
//! (prot-s6-contracts section 16); this task builds the two store clients
//! once, runs the pass every [`TICK`] and keeps the count R52 needs.
//!
//! The gate is the credentials, never a store's open switch. Closing a store
//! stops new intents only: purchases already paid are still credited from
//! RTDN, consumed before Play refunds them, clawed back when refunded and
//! released from Held when the credit pause ends. With no credentials there
//! is nothing to ask either store, so the tick only logs at debug level. The
//! task never returns: `cron_task_wrapper` treats a returning task as a
//! failure and restarts it every 60 s with an error each time, so an early
//! return is not a no-op (prune_expired_boosts.rs).
//!
//! A failed step (a store call, one row) is logged by the engine and retried
//! on the next tick. A Pub/Sub pull that times out on an idle subscription is
//! an empty answer, not a failure (R55); a server or network error on it is
//! counted in the report's `failed` like any other. One failing tick is not
//! an alert (R52): only after [`FAILED_TICKS_ALERT_AT`] ticks in a row with a
//! failure (about an hour) does this task raise `PROT_STORE_ALERT
//! kind=reconcile_failing`, once per run of failing ticks. That alert is
//! log-only, like `verify_failures`: there is no purchase row to claim it on,
//! so each replica counts its own ticks, and the staff mail is worded for a
//! purchase work item.
//!
//! crond has no leader election. Two replicas reconciling at once is safe:
//! every credit and clawback has a unique ledger key and moves its row by a
//! version CAS, a cursor moves by CAS (the loser skips), and a row alert is
//! sent only by the replica that claims it.
//!
//! The config is frozen into the process at first access, so adding
//! credentials or flipping a switch takes a crond restart. The credentials go
//! to the clients only; nothing here logs them, a purchase token or a JWS.

use std::time::Duration;

use log::{debug, warn};
use revolt_database::{util::prot_store_alert::send_ops_alert, Database, AMQP};
use revolt_payments::{
    engine::prot_store::{reconcile_store, StoreReconcileReport},
    settings::{ProtSalesSettings, ProtStoreSettings},
    store::{AppleStoreApi, PlayStoreApi, ReqwestAppleStore, ReqwestPlayStore},
};
use revolt_result::Result;
use tokio::time::sleep;

/// Time between passes
const TICK: Duration = Duration::from_secs(10 * 60);

/// R52: ticks in a row with a failed step before the alert (about an hour)
const FAILED_TICKS_ALERT_AT: u32 = 6;

/// R52's alert kind, and the id its line names (no purchase row)
const ALERT_RECONCILE_FAILING: &str = "reconcile_failing";
const ALERT_RECONCILE_ID: &str = "crond:prot_store_reconcile";

/// What one tick did
#[derive(Debug, PartialEq, Eq)]
enum Tick {
    /// Neither store client has credentials; nothing ran
    NotConfigured,
    /// The pass ran (the engine logs what it did); `alerted` when this tick
    /// raised R52's alert
    Ran {
        report: StoreReconcileReport,
        alerted: bool,
    },
}

/// Ticks in a row whose pass had a failed step (R52)
#[derive(Debug, Default)]
struct FailedTicks {
    run: u32,
}

impl FailedTicks {
    /// Count one pass; a pass with no failed step ends the run. Returns the
    /// length of the current run.
    fn record(&mut self, failed: bool) -> u32 {
        self.run = if failed {
            self.run.saturating_add(1)
        } else {
            0
        };
        self.run
    }
}

/// Run the reconcile every [`TICK`]. Never returns: without credentials each
/// tick is a no-op.
pub async fn task(db: Database, _: AMQP) -> Result<()> {
    // Each logs its CONFIG_INVALID line and reads as closed, with no
    // credentials, when its config does not validate
    let ps = ProtSalesSettings::load_or_closed().await;
    let st = ProtStoreSettings::load_or_closed().await;
    // Built once, so the App Store JWT and the Google access token they
    // cache outlive a tick
    let apple = ReqwestAppleStore::new(st.apple.clone());
    let play = ReqwestPlayStore::new(st.play.clone());
    let mut failing = FailedTicks::default();

    loop {
        tick(
            &db,
            &ps,
            &st,
            &apple,
            &play,
            &mut failing,
            revolt_database::now_ms(),
        )
        .await;
        sleep(TICK).await;
    }
}

/// One tick: gate on the store clients, run the pass, count a failing pass
///
/// Every failure is logged (by the engine, or here) and the next tick tries
/// again; nothing propagates out of the loop.
async fn tick(
    db: &Database,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    apple: &dyn AppleStoreApi,
    play: &dyn PlayStoreApi,
    failing: &mut FailedTicks,
    now_ms: i64,
) -> Tick {
    // The managed clients (audit N4), never the open switches: see the
    // module docs
    if !apple.configured() && !play.configured() {
        debug!("Prot store reconcile skipped, no store credentials are configured");
        return Tick::NotConfigured;
    }

    let report = reconcile_store(db, ps, st, apple, play, now_ms).await;

    let run = failing.record(report.failed > 0);
    let alerted = run == FAILED_TICKS_ALERT_AT;
    if alerted {
        raise_failing_alert(run).await;
    } else if run > 0 {
        // R52: one failing tick (a store hiccup) is not an alert; the
        // engine has logged the step
        debug!(
            "Prot store reconcile: {} failed step(s), {run} failing tick(s) in a row",
            report.failed
        );
    }

    Tick::Ran { report, alerted }
}

/// R52's alert through the section 19 helper, with no mailbox: the pinned
/// `PROT_STORE_ALERT kind=reconcile_failing` line (the helper never panics)
async fn raise_failing_alert(run: u32) {
    warn!(
        "PROT_STORE_RECONCILE_FAILING ticks={run}: each of the last {run} store reconcile passes \
         had a failed step (the payments lines above name them); retried every tick"
    );
    let config = revolt_config::config().await;
    if let Err(err) = send_ops_alert(
        &config.api.smtp,
        "",
        ALERT_RECONCILE_FAILING,
        ALERT_RECONCILE_ID,
    )
    .await
    {
        warn!("Could not raise the store reconcile alert: {err:?}");
    }
}

#[cfg(test)]
mod tests {
    use revolt_config::{ApiAppStore, ApiGooglePlay, FeaturePayments, ProtectionFeatures};
    use revolt_database::test_teardown::TestDatabaseGuard;
    use revolt_database::util::prot_store_alert::{
        PROT_STORE_NEEDS_HELD, PROT_STORE_NEEDS_UNCONSUMED,
    };
    use revolt_database::{
        prot_store_key_clawback, prot_store_key_purchase, prot_user_account, DatabaseInfo,
        ProtStoreIntent, ProtStorePurchase, User, PROT_STORE_CURSOR_APPLE, PROT_STORE_CURSOR_PLAY,
    };
    use revolt_models::v0;
    use revolt_payments::engine::prot_store::verify_store_purchase;
    use revolt_payments::settings::{AppleStoreConfig, PlayStoreConfig};
    use revolt_payments::store::{
        MockAppleStore, MockPlayStore, PlayLineItem, PlayOfferDetails, PlayPurchase,
        PlayStateContext, PlayVoided, PlayVoidedPage, PubSubMessage, StoreApiError,
        PLAY_CONSUMPTION_STATE_CONSUMED, PLAY_CONSUMPTION_STATE_YET_TO_BE_CONSUMED,
        PLAY_PURCHASE_STATE_CANCELLED, PLAY_PURCHASE_STATE_PURCHASED,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;

    /// 2027-01-15T08:00:00Z
    const NOW: i64 = 1_800_000_000_000;
    const MINUTE: i64 = 60_000;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;

    const PACKAGE: &str = "gg.sloga.app";
    const P25: &str = "gg.sloga.prot.p25";
    /// What one P25 credits under the default product table
    const P25_PROT: i64 = 2_600;
    const BUYER: &str = "01HZS6L2H0000000000BUYER01";

    const SOURCE: &str = include_str!("prot_store_reconcile.rs");
    const MAIN: &str = include_str!("../main.rs");

    /// This file without its tests
    fn shipped() -> &'static str {
        &SOURCE[..SOURCE.find("#[cfg(test)]").expect("the tests")]
    }

    /// The code of the item that starts at `head`, up to its closing brace
    /// at column 0, without comment lines
    fn item(head: &str) -> String {
        let code = shipped();
        let start = code
            .find(head)
            .unwrap_or_else(|| panic!("`{head}` is in the file"));
        let len = code[start..]
            .find("\n}\n")
            .unwrap_or_else(|| panic!("`{head}` is closed"));
        code[start..start + len]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A fresh test database on the driver `TEST_DB` names (which must be
    /// set: `DatabaseInfo::Test` panics without it rather than reach the
    /// configured database). Migrated, so MongoDB has the Prot ledger and
    /// Prot store indexes. The guard drops it when the test ends, panics
    /// included.
    async fn migrated_test_db() -> (Database, TestDatabaseGuard) {
        let suffix = 1_000_000 + (ulid::Ulid::new().random() % 9_000_000);
        let db = DatabaseInfo::Test(format!("revolt_test_{suffix}"))
            .connect()
            .await
            .expect("test database");
        let guard = TestDatabaseGuard::arm(&db).await;
        db.migrate_database().await.expect("schema");
        (db, guard)
    }

    fn prot_settings() -> ProtSalesSettings {
        ProtSalesSettings::from_parts(
            &FeaturePayments {
                prot_sales_open: true,
                ..Default::default()
            },
            &ProtectionFeatures {
                enabled: true,
                ..Default::default()
            },
        )
        .expect("the Prot defaults validate")
    }

    /// The shipped switches (both stores closed, credits not paused) with
    /// credentials on both stores. Nothing reaches a network: the tests hand
    /// the pass the mocks.
    fn store_settings() -> ProtStoreSettings {
        let mut st = ProtStoreSettings::from_parts(
            &FeaturePayments::default(),
            &ApiAppStore::default(),
            &ApiGooglePlay::default(),
        )
        .expect("the store defaults validate");
        st.apple = Some(AppleStoreConfig {
            issuer_id: "ISSUER".to_string(),
            key_id: "KEYID".to_string(),
            private_key: String::new(),
            bundle_id: PACKAGE.to_string(),
            app_apple_id: 6_809_989_506,
            environment: v0::ProtStoreEnvironment::Production,
            root_g3_sha256: [0; 32],
        });
        st.play = Some(PlayStoreConfig {
            package_name: PACKAGE.to_string(),
            client_email: "play@sloga-test.iam.gserviceaccount.com".to_string(),
            private_key: String::new(),
            token_uri: "https://oauth2.test/token".to_string(),
            pubsub_subscription: "projects/p/subscriptions/s".to_string(),
        });
        st
    }

    struct Harness {
        db: Database,
        _guard: TestDatabaseGuard,
        ps: ProtSalesSettings,
        st: ProtStoreSettings,
        apple: MockAppleStore,
        play: MockPlayStore,
    }

    #[allow(clippy::disallowed_methods)]
    async fn harness() -> Harness {
        let (db, guard) = migrated_test_db().await;
        db.insert_user(&User {
            id: BUYER.to_string(),
            username: "storebuyer".to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
        Harness {
            db,
            _guard: guard,
            ps: prot_settings(),
            st: store_settings(),
            apple: MockAppleStore::new(),
            play: MockPlayStore::new(),
        }
    }

    /// One tick that must run the pass: its report, and whether it alerted
    async fn pass(
        h: &Harness,
        st: &ProtStoreSettings,
        failing: &mut FailedTicks,
        at: i64,
    ) -> (StoreReconcileReport, bool) {
        match tick(&h.db, &h.ps, st, &h.apple, &h.play, failing, at).await {
            Tick::Ran { report, alerted } => (report, alerted),
            Tick::NotConfigured => panic!("the pass did not run"),
        }
    }

    /// The intent token a test binds Play purchase `token` with
    fn bound(token: &str) -> String {
        format!("intent-{token}")
    }

    /// An Open Play P25 intent of the buyer with token `token`; its id
    async fn intent(db: &Database, token: &str, created_at: i64) -> String {
        let id = ulid::Ulid::new().to_string();
        db.insert_prot_store_intent(&ProtStoreIntent {
            id: id.clone(),
            user_id: Some(BUYER.to_string()),
            store: v0::ProtStore::Play,
            product_id: P25.to_string(),
            prot: P25_PROT,
            token: token.to_string(),
            state: v0::ProtStoreIntentState::Open,
            purchase_id: None,
            created_at,
            expires_at: created_at + DAY,
        })
        .await
        .unwrap();
        id
    }

    /// A P25 purchase as productsv2 answers it
    fn play_found(account: Option<&str>, state: &str, consumption: &str) -> PlayPurchase {
        PlayPurchase {
            product_line_item: vec![PlayLineItem {
                product_id: P25.to_string(),
                product_offer_details: PlayOfferDetails {
                    quantity: Some(1),
                    refundable_quantity: Some(1),
                    consumption_state: Some(consumption.to_string()),
                },
            }],
            purchase_state_context: PlayStateContext {
                purchase_state: state.to_string(),
            },
            test_purchase_context: None,
            order_id: Some("GPA.3300-0000-0000-00000".to_string()),
            obfuscated_external_account_id: account.map(str::to_string),
            region_code: Some("US".to_string()),
            purchase_completion_time: None,
            acknowledgement_state: None,
        }
    }

    /// The buyer's P25 Play purchase `token`, bound to a fresh intent, Play
    /// answering PURCHASED, verified at `at` under `st`: its purchase id and
    /// the answer's status
    async fn bought(
        h: &Harness,
        st: &ProtStoreSettings,
        token: &str,
        at: i64,
    ) -> (String, v0::ProtStoreVerifyStatus) {
        intent(&h.db, &bound(token), at - MINUTE).await;
        h.play.set_purchase(
            token,
            Ok(play_found(
                Some(&bound(token)),
                PLAY_PURCHASE_STATE_PURCHASED,
                PLAY_CONSUMPTION_STATE_YET_TO_BE_CONSUMED,
            )),
        );
        let data = v0::DataProtStoreVerify {
            store: v0::ProtStore::Play,
            signed_transaction: None,
            product_id: Some(P25.to_string()),
            purchase_token: Some(token.to_string()),
        };
        let answer = verify_store_purchase(&h.db, &h.ps, st, &h.apple, &h.play, BUYER, &data, at)
            .await
            .expect("Play answered");
        (
            answer.purchase_id.clone().expect("a purchase row"),
            answer.status,
        )
    }

    /// The RTDN of a PURCHASED one-time product, as Pub/Sub delivers it
    fn purchased_rtdn(token: &str) -> Vec<u8> {
        json!({
            "version": "1.0",
            "packageName": PACKAGE,
            "eventTimeMillis": NOW.to_string(),
            "oneTimeProductNotification": {
                "version": "1.0",
                "notificationType": 1,
                "purchaseToken": token,
                "sku": P25,
            },
        })
        .to_string()
        .into_bytes()
    }

    /// The RTDN of a voided one-time product
    fn voided_rtdn(token: &str, at: i64) -> Vec<u8> {
        json!({
            "version": "1.0",
            "packageName": PACKAGE,
            "eventTimeMillis": at.to_string(),
            "voidedPurchaseNotification": {
                "purchaseToken": token,
                "orderId": "GPA.3300-0000-0000-00000",
                "productType": 2,
                "refundType": 1,
            },
        })
        .to_string()
        .into_bytes()
    }

    async fn row(db: &Database, id: &str) -> ProtStorePurchase {
        db.fetch_prot_store_purchase(id)
            .await
            .unwrap()
            .expect("the purchase row exists")
    }

    async fn balance(db: &Database) -> i64 {
        db.fetch_prot_account(&prot_user_account(BUYER))
            .await
            .unwrap()
            .map_or(0, |account| account.balance)
    }

    async fn has_entry(db: &Database, key: &str) -> bool {
        db.fetch_prot_entry_by_key(key).await.unwrap().is_some()
    }

    async fn cursor(db: &Database, id: &str) -> Option<i64> {
        db.fetch_prot_store_cursor(id)
            .await
            .unwrap()
            .map(|cursor| cursor.cursor.parse().expect("epoch ms"))
    }

    fn sha256_hex(value: &str) -> String {
        Sha256::digest(value.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The purchase id of Play purchase `token` (section 4)
    fn play_id(token: &str) -> String {
        format!("play:{}", sha256_hex(token))
    }

    /// How often the mock was asked to `op` purchase `token`
    fn play_calls(play: &MockPlayStore, op: &str, token: &str) -> usize {
        let call = format!("{op} {}", sha256_hex(token));
        play.calls().iter().filter(|line| **line == call).count()
    }

    /// A merge that drops the registration leaves the reconcile dark with
    /// every other test green
    #[test]
    fn the_store_reconcile_is_registered_inside_join() {
        let start = MAIN.find("join!(").expect("main.rs has a join!(");
        let end = start + MAIN[start..].find(");").expect("join!( is closed");
        let registration =
            "cron_task_wrapper(prot_store_reconcile::task, db.clone(), amqp.clone()),";

        assert_eq!(
            MAIN[start..end]
                .lines()
                .filter(|line| line.trim() == registration)
                .count(),
            1,
            "main.rs must register the store reconcile exactly once inside join!("
        );
        assert_eq!(MAIN.matches("prot_store_reconcile::task").count(), 1);
    }

    /// Closing a store stops new intents, never the settling of purchases
    /// already paid: with both stores closed and credentials configured the
    /// pass runs (the RTDN queue is pulled, an overdue intent expires). The
    /// shape is pinned in the text too: `task` is a sleep-in-loop with no
    /// way out, and nothing in this task reads a store's open switch.
    #[tokio::test]
    async fn reconcile_runs_while_stores_are_closed() {
        let h = harness().await;
        assert!(!h.st.apple_open && !h.st.play_open && !h.st.credit_paused);
        let id = intent(&h.db, "intent-overdue", NOW - 2 * DAY).await;
        let mut failing = FailedTicks::default();

        let (report, alerted) = pass(&h, &h.st, &mut failing, NOW).await;
        assert_eq!(report.intents_expired, 1, "{report:?}");
        assert_eq!(report.failed, 0, "{report:?}");
        assert!(!alerted);
        let stored =
            h.db.fetch_prot_store_intent(&id)
                .await
                .unwrap()
                .expect("the intent exists");
        assert_eq!(stored.state, v0::ProtStoreIntentState::Expired);
        assert!(
            h.play
                .calls()
                .iter()
                .any(|call| call.as_str() == "pull 100"),
            "{:?}",
            h.play.calls()
        );

        let task = item("pub async fn task(");
        let flat: String = task.split_whitespace().collect();
        assert!(task.contains("loop {"), "{task}");
        assert!(
            flat.contains("tick(&db,&ps,&st,&apple,&play,&mutfailing,revolt_database::now_ms()"),
            "{task}"
        );
        assert!(task.contains("sleep(TICK).await;"), "{task}");
        for exit in ["return", "break", "continue", "?", "if "] {
            assert!(
                !task.contains(exit),
                "`{exit}` in task: the reconcile loop must run every tick, whatever the \
                 switches say, and never end\n{task}"
            );
        }
        for switch in ["apple_open", "play_open", "store_offered_to"] {
            assert!(
                !shipped().contains(switch),
                "the reconcile reads `{switch}`: closing a store must not stop it"
            );
        }
        assert_eq!(TICK, Duration::from_secs(10 * 60));
    }

    /// Without credentials there is nothing to ask either store: the tick
    /// returns before the pass, so not even an overdue intent is touched,
    /// whatever the settings hold (the gate is the managed clients)
    #[tokio::test]
    async fn an_unconfigured_tick_touches_nothing() {
        let h = harness().await;
        let id = intent(&h.db, "intent-overdue", NOW - 2 * DAY).await;
        h.apple.unconfigured();
        h.play.unconfigured();
        let mut failing = FailedTicks::default();

        for st in [ProtStoreSettings::closed(), h.st.clone()] {
            assert_eq!(
                tick(&h.db, &h.ps, &st, &h.apple, &h.play, &mut failing, NOW).await,
                Tick::NotConfigured
            );
        }

        assert!(h.apple.calls().is_empty(), "{:?}", h.apple.calls());
        assert!(h.play.calls().is_empty(), "{:?}", h.play.calls());
        let stored =
            h.db.fetch_prot_store_intent(&id)
                .await
                .unwrap()
                .expect("the intent exists");
        assert_eq!(stored.state, v0::ProtStoreIntentState::Open);
        assert_eq!(failing.run, 0);
    }

    /// R52's counter: the run grows with every failing pass and a clean pass
    /// ends it, so the alert (at exactly the sixth) fires once per run
    #[test]
    fn failed_ticks_count_runs() {
        let mut failing = FailedTicks::default();
        let runs: Vec<u32> = [true, true, true, true, true, true, true, false, true]
            .into_iter()
            .map(|failed| failing.record(failed))
            .collect();

        assert_eq!(runs, [1, 2, 3, 4, 5, 6, 7, 0, 1]);
        assert_eq!(FAILED_TICKS_ALERT_AT, 6);
    }

    /// R52: a store failing on one tick (here the voided list) is retried
    /// quietly. The sixth failing tick in a row raises the alert, once; a
    /// clean tick ends the run, and its complete scan moves the voided cursor
    /// to the scan's own time less the hour of overlap (R58).
    #[tokio::test]
    async fn six_failed_ticks_in_a_row_raise_one_alert() {
        let h = harness().await;
        h.play.set_voided(
            (0..7)
                .map(|_| Err(StoreApiError::Transient("timed out".to_string())))
                .collect(),
        );
        let mut failing = FailedTicks::default();

        for n in 1..=7_i64 {
            let (report, alerted) =
                pass(&h, &h.st, &mut failing, NOW + (n - 1) * 10 * MINUTE).await;
            assert!(report.failed > 0, "tick {n}: {report:?}");
            assert_eq!(alerted, n == 6, "tick {n}: {report:?}");
        }

        // Play answers again: the run is over
        let (report, alerted) = pass(&h, &h.st, &mut failing, NOW + 70 * MINUTE).await;
        assert_eq!(report.failed, 0, "{report:?}");
        assert!(!alerted);
        assert_eq!(failing.run, 0);
        assert_eq!(
            cursor(&h.db, PROT_STORE_CURSOR_PLAY).await,
            Some(NOW + 70 * MINUTE - HOUR)
        );
    }

    /// 16 step 2. A consume Play refuses is read again: a purchase Play
    /// already consumed is recorded consumed, one Play cancelled is revoked
    /// (its Prot clawed back). A consume that keeps failing is retried every
    /// tick; a day after its credit the row becomes a work item first, then
    /// the alert is claimed, once.
    #[tokio::test]
    async fn refused_consumes_are_read_again_and_stuck_ones_alerted() {
        let h = harness().await;
        let consumed = "play-token-consumed.AO-J1Oz";
        let cancelled = "play-token-cancelled.AO-J1Oz";
        let stuck = "play-token-stuck.AO-J1Oz";
        h.play
            .fail_consume(consumed, StoreApiError::Rejected { status: 400 });
        h.play
            .fail_consume(cancelled, StoreApiError::Rejected { status: 400 });
        h.play
            .fail_consume(stuck, StoreApiError::Transient("timed out".to_string()));

        let mut ids = Vec::new();
        for token in [consumed, cancelled, stuck] {
            let (id, status) = bought(&h, &h.st, token, NOW).await;
            assert_eq!(status, v0::ProtStoreVerifyStatus::Credited, "{token}");
            assert_eq!(row(&h.db, &id).await.unconsumed, Some(true), "{token}");
            ids.push(id);
        }
        assert_eq!(balance(&h.db).await, 3 * P25_PROT);

        h.play.set_purchase(
            consumed,
            Ok(play_found(
                Some(&bound(consumed)),
                PLAY_PURCHASE_STATE_PURCHASED,
                PLAY_CONSUMPTION_STATE_CONSUMED,
            )),
        );
        h.play.set_purchase(
            cancelled,
            Ok(play_found(
                Some(&bound(cancelled)),
                PLAY_PURCHASE_STATE_CANCELLED,
                PLAY_CONSUMPTION_STATE_YET_TO_BE_CONSUMED,
            )),
        );
        let mut failing = FailedTicks::default();

        let (report, _) = pass(&h, &h.st, &mut failing, NOW + MINUTE).await;
        assert_eq!(report.consumed, 1, "{report:?}");
        assert_eq!(report.voided, 1, "{report:?}");
        assert_eq!(report.alerts, 0, "{report:?}");

        let row_consumed = row(&h.db, &ids[0]).await;
        assert_eq!(row_consumed.state, v0::ProtStoreState::Credited);
        assert_eq!(row_consumed.unconsumed, None, "{row_consumed:?}");
        assert!(
            row_consumed
                .play
                .as_ref()
                .is_some_and(|play| play.consumed_at.is_some()),
            "{row_consumed:?}"
        );

        let row_cancelled = row(&h.db, &ids[1]).await;
        assert_eq!(row_cancelled.state, v0::ProtStoreState::Revoked);
        assert_eq!(row_cancelled.unconsumed, None, "{row_cancelled:?}");
        assert!(has_entry(&h.db, &prot_store_key_clawback(&ids[1], 1)).await);
        assert_eq!(balance(&h.db).await, 2 * P25_PROT);

        let row_stuck = row(&h.db, &ids[2]).await;
        assert_eq!(row_stuck.unconsumed, Some(true), "{row_stuck:?}");
        assert_eq!(row_stuck.needs_action, None, "{row_stuck:?}");

        // A day after its credit the stuck one is a work item, alerted once
        let (report, _) = pass(&h, &h.st, &mut failing, NOW + DAY + HOUR).await;
        assert_eq!(report.alerts, 1, "{report:?}");
        let row_stuck = row(&h.db, &ids[2]).await;
        assert_eq!(
            row_stuck.needs_action.as_deref(),
            Some(PROT_STORE_NEEDS_UNCONSUMED),
            "{row_stuck:?}"
        );
        assert!(
            row_stuck
                .alerted
                .iter()
                .any(|kind| kind == PROT_STORE_NEEDS_UNCONSUMED),
            "{row_stuck:?}"
        );

        let (report, _) = pass(&h, &h.st, &mut failing, NOW + DAY + 2 * HOUR).await;
        assert_eq!(report.alerts, 0, "{report:?}");
        assert_eq!(row(&h.db, &ids[2]).await.unconsumed, Some(true));
        // verify's consume, then one per tick
        assert_eq!(play_calls(&h.play, &format!("consume {P25}"), stuck), 4);
        assert_eq!(balance(&h.db).await, 2 * P25_PROT);
    }

    /// 16 step 3 and its replays: the first voided read starts 30 days less
    /// an hour back, claws the voided purchase and moves the cursor to the
    /// scan's time less an hour (R58, not to the void). A day later the read
    /// starts an hour before the cursor, so Play lists the same void again,
    /// and its RTDN is redelivered: nothing moves a second time, and the
    /// message is still acknowledged.
    #[tokio::test]
    async fn voided_purchases_claw_once_however_often_they_are_replayed() {
        let h = harness().await;
        let token = "play-token-voided.AO-J1Oz";
        let (id, status) = bought(&h, &h.st, token, NOW).await;
        assert_eq!(status, v0::ProtStoreVerifyStatus::Credited);
        assert_eq!(balance(&h.db).await, P25_PROT);

        let voided_at = NOW + HOUR;
        let page = || PlayVoidedPage {
            voided: vec![PlayVoided {
                purchase_token: token.to_string(),
                order_id: Some("GPA.3300-0000-0000-00000".to_string()),
                voided_time_ms: voided_at,
            }],
            next_page_token: None,
        };
        let mut failing = FailedTicks::default();

        h.play.set_voided(vec![Ok(page())]);
        let first = NOW + 2 * HOUR;
        let (report, _) = pass(&h, &h.st, &mut failing, first).await;
        assert_eq!(report.voided, 1, "{report:?}");
        assert_eq!(report.failed, 0, "{report:?}");
        let call = format!("voided_purchases {} -", first - 30 * DAY + HOUR);
        assert!(h.play.calls().contains(&call), "{:?}", h.play.calls());

        let clawed = row(&h.db, &id).await;
        assert_eq!(clawed.state, v0::ProtStoreState::Revoked, "{clawed:?}");
        assert_eq!(clawed.refund_gen, 1, "{clawed:?}");
        assert_eq!(balance(&h.db).await, 0);
        assert!(has_entry(&h.db, &prot_store_key_clawback(&id, 1)).await);
        assert_eq!(
            cursor(&h.db, PROT_STORE_CURSOR_PLAY).await,
            Some(first - HOUR)
        );
        let entries = h.db.fetch_prot_entries_by_order(&id).await.unwrap().len();

        h.play.set_voided(vec![Ok(page())]);
        h.play.push_message(PubSubMessage {
            ack_id: "ack-void".to_string(),
            data: voided_rtdn(token, NOW + 3 * HOUR),
            message_id: "msg-void".to_string(),
        });
        let replay = first + DAY;
        let (report, _) = pass(&h, &h.st, &mut failing, replay).await;
        assert_eq!(report.failed, 0, "{report:?}");
        let call = format!("voided_purchases {} -", first - 2 * HOUR);
        assert!(first - 2 * HOUR < voided_at);
        assert!(h.play.calls().contains(&call), "{:?}", h.play.calls());
        assert_eq!(h.play.acked(), ["ack-void"]);
        assert_eq!(
            cursor(&h.db, PROT_STORE_CURSOR_PLAY).await,
            Some(replay - HOUR)
        );

        let replayed = row(&h.db, &id).await;
        assert_eq!(replayed.state, v0::ProtStoreState::Revoked, "{replayed:?}");
        assert_eq!(replayed.refund_gen, 1, "{replayed:?}");
        assert_eq!(balance(&h.db).await, 0);
        assert!(!has_entry(&h.db, &prot_store_key_clawback(&id, 2)).await);
        assert_eq!(
            h.db.fetch_prot_entries_by_order(&id).await.unwrap().len(),
            entries
        );
    }

    /// 16 step 5 (audit N3): while credits are paused nothing Held is read
    /// or credited. Once they are not, every Held row is looked up at Play
    /// again first: a purchase still bought is credited (and consumed), one
    /// Play cancelled meanwhile is revoked with nothing credited, and one
    /// Play cannot answer for stays Held for the next tick.
    #[tokio::test]
    async fn held_purchases_are_looked_up_again_before_they_are_credited() {
        let h = harness().await;
        let mut paused = h.st.clone();
        paused.credit_paused = true;

        let live = "play-token-held-live.AO-J1Oz";
        let cancelled = "play-token-held-cancelled.AO-J1Oz";
        let unanswered = "play-token-held-unanswered.AO-J1Oz";
        let tokens = [live, cancelled, unanswered];
        let mut ids = Vec::new();
        for token in tokens {
            let (id, status) = bought(&h, &paused, token, NOW).await;
            assert_eq!(status, v0::ProtStoreVerifyStatus::Pending, "{token}");
            assert_eq!(row(&h.db, &id).await.state, v0::ProtStoreState::Held);
            ids.push(id);
        }
        assert_eq!(balance(&h.db).await, 0);
        let mut failing = FailedTicks::default();

        let (report, _) = pass(&h, &paused, &mut failing, NOW + MINUTE).await;
        assert_eq!(report.held_credited, 0, "{report:?}");
        for (token, id) in tokens.iter().zip(&ids) {
            assert_eq!(row(&h.db, id).await.state, v0::ProtStoreState::Held);
            assert_eq!(play_calls(&h.play, "product_purchase", token), 1, "{token}");
        }
        assert_eq!(balance(&h.db).await, 0);

        // Play's answers change while the pause lasts
        h.play.set_purchase(
            cancelled,
            Ok(play_found(
                Some(&bound(cancelled)),
                PLAY_PURCHASE_STATE_CANCELLED,
                PLAY_CONSUMPTION_STATE_YET_TO_BE_CONSUMED,
            )),
        );
        h.play.set_purchase(
            unanswered,
            Err(StoreApiError::Transient("timed out".to_string())),
        );

        let (report, _) = pass(&h, &h.st, &mut failing, NOW + HOUR).await;
        assert_eq!(report.held_credited, 1, "{report:?}");
        assert!(report.failed > 0, "{report:?}");
        for token in tokens {
            assert_eq!(play_calls(&h.play, "product_purchase", token), 2, "{token}");
        }

        let credited = row(&h.db, &ids[0]).await;
        assert_eq!(credited.state, v0::ProtStoreState::Credited, "{credited:?}");
        assert!(
            credited
                .play
                .as_ref()
                .is_some_and(|play| play.consumed_at.is_some()),
            "{credited:?}"
        );
        assert!(has_entry(&h.db, &prot_store_key_purchase(&ids[0])).await);
        assert_eq!(balance(&h.db).await, P25_PROT);

        let revoked = row(&h.db, &ids[1]).await;
        assert_eq!(revoked.state, v0::ProtStoreState::Revoked, "{revoked:?}");
        assert!(!has_entry(&h.db, &prot_store_key_purchase(&ids[1])).await);

        assert_eq!(row(&h.db, &ids[2]).await.state, v0::ProtStoreState::Held);
    }

    /// R59 (owner Q2): while credits stay paused, a Play purchase held for
    /// more than a day (Play refunds an unconsumed purchase after 3 days)
    /// becomes the `play_held_24h` work item and its staff alert is claimed
    /// once, however many ticks follow; no store call is made for it. The
    /// first tick after the pause credits it and clears the work item.
    #[tokio::test]
    async fn a_play_purchase_held_over_a_day_is_alerted_once() {
        let h = harness().await;
        let mut paused = h.st.clone();
        paused.credit_paused = true;
        let token = "play-token-held-long.AO-J1Oz";
        let (id, status) = bought(&h, &paused, token, NOW).await;
        assert_eq!(status, v0::ProtStoreVerifyStatus::Pending);
        let mut failing = FailedTicks::default();

        // Under a day: no work item yet
        let (report, _) = pass(&h, &paused, &mut failing, NOW + 23 * HOUR).await;
        assert_eq!(report.alerts, 0, "{report:?}");
        assert_eq!(row(&h.db, &id).await.needs_action, None);

        let mut alerts = 0;
        for at in [NOW + DAY + HOUR, NOW + DAY + 2 * HOUR, NOW + 2 * DAY] {
            let (report, _) = pass(&h, &paused, &mut failing, at).await;
            assert_eq!(report.failed, 0, "{report:?}");
            assert_eq!(report.held_credited, 0, "{report:?}");
            alerts += report.alerts;
        }
        assert_eq!(alerts, 1);

        let held = row(&h.db, &id).await;
        assert_eq!(held.state, v0::ProtStoreState::Held, "{held:?}");
        assert_eq!(
            held.needs_action.as_deref(),
            Some(PROT_STORE_NEEDS_HELD),
            "{held:?}"
        );
        assert_eq!(
            held.alerted
                .iter()
                .filter(|kind| kind.as_str() == PROT_STORE_NEEDS_HELD)
                .count(),
            1,
            "{held:?}"
        );
        // verify's lookup only
        assert_eq!(play_calls(&h.play, "product_purchase", token), 1);
        assert_eq!(balance(&h.db).await, 0);

        let (report, _) = pass(&h, &h.st, &mut failing, NOW + 2 * DAY + HOUR).await;
        assert_eq!(report.held_credited, 1, "{report:?}");
        let credited = row(&h.db, &id).await;
        assert_eq!(credited.state, v0::ProtStoreState::Credited, "{credited:?}");
        assert_eq!(credited.needs_action, None, "{credited:?}");
        assert_eq!(balance(&h.db).await, P25_PROT);
    }

    /// 16 step 1: an RTDN is acknowledged only after it was handled. The
    /// same PURCHASED notification delivered twice credits once (both are
    /// acknowledged); one whose purchase Play cannot read now is left for
    /// redelivery and pulled again on the next tick.
    #[tokio::test]
    async fn rtdn_is_acknowledged_after_the_commit_and_credits_once() {
        let h = harness().await;
        let token = "play-token-rtdn.AO-J1Oz";
        let stalled = "play-token-rtdn-stalled.AO-J1Oz";
        intent(&h.db, &bound(token), NOW - MINUTE).await;
        h.play.set_purchase(
            token,
            Ok(play_found(
                Some(&bound(token)),
                PLAY_PURCHASE_STATE_PURCHASED,
                PLAY_CONSUMPTION_STATE_YET_TO_BE_CONSUMED,
            )),
        );
        h.play.set_purchase(
            stalled,
            Err(StoreApiError::Transient("timed out".to_string())),
        );
        for (n, purchase) in [(1, token), (2, token), (3, stalled)] {
            h.play.push_message(PubSubMessage {
                ack_id: format!("ack-{n}"),
                data: purchased_rtdn(purchase),
                message_id: format!("msg-{n}"),
            });
        }
        let mut failing = FailedTicks::default();

        let (report, _) = pass(&h, &h.st, &mut failing, NOW).await;
        assert_eq!(report.rtdn, 2, "{report:?}");
        assert!(report.failed > 0, "{report:?}");
        assert_eq!(h.play.acked(), ["ack-1", "ack-2"]);

        let id = play_id(token);
        let credited = row(&h.db, &id).await;
        assert_eq!(credited.state, v0::ProtStoreState::Credited, "{credited:?}");
        assert_eq!(credited.user_id.as_deref(), Some(BUYER));
        assert!(has_entry(&h.db, &prot_store_key_purchase(&id)).await);
        assert_eq!(balance(&h.db).await, P25_PROT);

        let (report, _) = pass(&h, &h.st, &mut failing, NOW + 10 * MINUTE).await;
        assert_eq!(report.rtdn, 0, "{report:?}");
        assert!(report.failed > 0, "{report:?}");
        assert_eq!(h.play.acked(), ["ack-1", "ack-2"]);
        assert_eq!(
            h.play
                .calls()
                .iter()
                .filter(|call| call.as_str() == "pull 100")
                .count(),
            2
        );
        assert_eq!(balance(&h.db).await, P25_PROT);
    }

    /// 16 step 4: Notification History is read hourly from two hours before
    /// the cursor (the first read three days back), and the cursor moves only
    /// after a complete read, so a read that failed is repeated from the same
    /// start on the next tick. Sandbox is read only while testers are listed.
    /// (Each signed payload's replay through 9.5 needs the signed test chain;
    /// the engine's tests cover it.)
    #[tokio::test]
    async fn apple_history_is_replayed_from_the_cursor_with_overlap() {
        let h = harness().await;
        h.play.unconfigured();
        let mut failing = FailedTicks::default();
        let history =
            |start: i64, end: i64| format!("notification_history Production {start} {end} -");

        let (report, _) = pass(&h, &h.st, &mut failing, NOW).await;
        assert_eq!(report.failed, 0, "{report:?}");
        assert_eq!(h.apple.calls(), [history(NOW - 3 * DAY, NOW)]);
        assert_eq!(cursor(&h.db, PROT_STORE_CURSOR_APPLE).await, Some(NOW));

        // Within the hour: not read
        pass(&h, &h.st, &mut failing, NOW + 30 * MINUTE).await;
        assert_eq!(h.apple.calls().len(), 1);

        let later = NOW + HOUR;
        pass(&h, &h.st, &mut failing, later).await;
        assert_eq!(
            h.apple.calls().last(),
            Some(&history(NOW - 2 * HOUR, later))
        );
        assert_eq!(cursor(&h.db, PROT_STORE_CURSOR_APPLE).await, Some(later));

        h.apple
            .set_history(vec![Err(StoreApiError::Transient("timed out".to_string()))]);
        let failed_at = later + HOUR;
        let (report, _) = pass(&h, &h.st, &mut failing, failed_at).await;
        assert!(report.failed > 0, "{report:?}");
        assert_eq!(
            h.apple.calls().last(),
            Some(&history(later - 2 * HOUR, failed_at))
        );
        assert_eq!(cursor(&h.db, PROT_STORE_CURSOR_APPLE).await, Some(later));

        let retry = failed_at + 10 * MINUTE;
        let (report, _) = pass(&h, &h.st, &mut failing, retry).await;
        assert_eq!(report.failed, 0, "{report:?}");
        assert_eq!(
            h.apple.calls().last(),
            Some(&history(later - 2 * HOUR, retry))
        );
        assert_eq!(cursor(&h.db, PROT_STORE_CURSOR_APPLE).await, Some(retry));
        assert!(!h.apple.calls().iter().any(|call| call.contains("Sandbox")));
    }
}
