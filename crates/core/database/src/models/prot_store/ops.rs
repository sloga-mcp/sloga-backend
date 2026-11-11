#[cfg(feature = "mongodb")]
pub mod mongodb;
pub mod reference;

use revolt_models::v0;
use revolt_result::Result;

use crate::{ProtStoreCursor, ProtStoreIntent, ProtStorePurchase};

/// Store intents, purchase rows and reconcile cursors (prot-s6-contracts 7.5).
/// Every write that moves Prot, a row's state or an intent to Used goes through
/// `AbstractProtLedger::apply_store_purchase_move`; these are reads and
/// bookkeeping, and every write to a purchase row bumps its `version`.
#[async_trait]
pub trait AbstractProtStore: Sync + Send {
    async fn insert_prot_store_intent(&self, intent: &ProtStoreIntent) -> Result<()>;
    async fn fetch_prot_store_intent(&self, id: &str) -> Result<Option<ProtStoreIntent>>;
    /// By token, any state (lowercase compare is the caller's job: Apple tokens are stored lowercase)
    async fn fetch_prot_store_intent_by_token(
        &self,
        token: &str,
    ) -> Result<Option<ProtStoreIntent>>;
    /// The user's intents in state Open with expires_at > now
    async fn fetch_open_prot_store_intents(
        &self,
        user_id: &str,
        now: i64,
    ) -> Result<Vec<ProtStoreIntent>>;
    /// Open → Expired for expires_at <= now, at most `limit`; returns how many moved
    async fn expire_prot_store_intents(&self, now: i64, limit: i64) -> Result<u64>;
    async fn fetch_prot_store_purchase(&self, id: &str) -> Result<Option<ProtStorePurchase>>;
    /// Rows with needs_action set, newest updated first, limit clamped 1..=100
    async fn fetch_prot_store_needs_action(&self, limit: i64) -> Result<Vec<ProtStorePurchase>>;
    /// Rows in `state` for `store`, oldest created first (crond: Held rows)
    async fn fetch_prot_store_purchases_by_state(
        &self,
        store: v0::ProtStore,
        state: v0::ProtStoreState,
        limit: i64,
    ) -> Result<Vec<ProtStorePurchase>>;
    /// Play rows with unconsumed == true, oldest credited first
    async fn fetch_unconsumed_play_purchases(&self, limit: i64) -> Result<Vec<ProtStorePurchase>>;
    /// unconsumed: unset, play.consumed_at = at, clears needs_action iff it is `play_unconsumed_24h`, version += 1,
    /// iff version == expected; Ok(false) when it moved (audit 5)
    async fn mark_prot_store_consumed(
        &self,
        id: &str,
        expected_version: u64,
        at: i64,
    ) -> Result<bool>;
    /// $set needs_action = kind, updated_at, version += 1 (N2); Ok(true) when it changed
    async fn set_prot_store_needs_action(&self, id: &str, kind: &str, now: i64) -> Result<bool>;
    /// Unset needs_action iff it equals `kind`, version += 1; Ok(true) when it changed (admin resolve, 12.6)
    async fn clear_prot_store_needs_action(&self, id: &str, kind: &str, now: i64) -> Result<bool>;
    /// $addToSet alerted kind iff absent, version += 1; Ok(true) only for the caller that added it (dedupe)
    async fn claim_prot_store_alert(&self, id: &str, kind: &str) -> Result<bool>;
    /// Σ prot of the user's Play rows with unconsumed == true in Credited/Reinstated and credited_at < before_ms
    async fn sum_unconsumed_play_prot(&self, user_id: &str, before_ms: i64) -> Result<i64>;
    /// Users' own intent cancel (12.1): Open → Expired iff `user_id` matches; Ok(None) when absent or not theirs
    async fn cancel_prot_store_intent(
        &self,
        id: &str,
        user_id: &str,
    ) -> Result<Option<ProtStoreIntent>>;
    /// Delete Expired intents with no purchase_id and expires_at < before_ms, at most `limit` (16 step 8)
    async fn delete_stale_prot_store_intents(&self, before_ms: i64, limit: i64) -> Result<u64>;
    /// Σ prot of the user's Sandbox rows in Credited, Reinstated or Held (E4 cap)
    async fn sum_sandbox_prot_store(&self, user_id: &str) -> Result<i64>;
    /// Σ prot of the user's Held rows (the cap counts them, R5)
    async fn sum_held_prot_store(&self, user_id: &str) -> Result<i64>;
    /// Account deletion: unset user_id on every intent (Open → Expired) and purchase of the user (each purchase
    /// row's version += 1, N2). Idempotent.
    async fn unlink_prot_store_user(&self, user_id: &str) -> Result<()>;
    async fn fetch_prot_store_cursor(&self, id: &str) -> Result<Option<ProtStoreCursor>>;
    /// Insert (expected None) or CAS on version; Ok(false) when another replica moved it
    async fn put_prot_store_cursor(
        &self,
        cursor: &ProtStoreCursor,
        expected_version: Option<u64>,
    ) -> Result<bool>;
}

/// The S6 DB layer through both drivers (`database_test!`): the one-transaction
/// move of `apply_store_purchase_move` driven the way the engine drives it
/// (read, `plan_store_move`, build the row, move, re-plan on Conflict), the
/// held figure, and the bookkeeping methods above. The MongoDB runs install
/// the real migration indexes (revisions 76, 78 and 81).
#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use futures::future::join_all;
    use revolt_models::v0;

    use crate::{
        plan_store_move, prot_hold_account, prot_key_admin, prot_key_clawback_hold,
        prot_key_pledge, prot_store_key_clawback, prot_store_key_purchase,
        prot_store_key_reinstate, prot_store_refund_gen_of, prot_tank_account,
        prot_tank_target_key, prot_user_account, prot_utc_day, Database, ProtAmount,
        ProtContributeInput, ProtGoal, ProtLedgerEntry, ProtPledge, ProtPledgeInput, ProtPosting,
        ProtRef, ProtStoreAnswer, ProtStoreCursor, ProtStoreEvent, ProtStoreIntent,
        ProtStoreLedger, ProtStoreMove, ProtStoreMoveOutcome, ProtStoreMovePlan, ProtStorePurchase,
        ProtStoreVerdict, ProtTank, ProtTankRules, ProtTankTarget, ReferenceDb,
        PROT_STORE_INTENT_TTL_MS, PROT_STORE_MOVE_RETRIES, PROT_SYS_ADJUST, PROT_SYS_CLAWED,
    };

    use std::collections::HashMap;

    use crate::{
        build_store_move, prot_store_refund_base, ProtStoreRefund, PROT_ACTOR_STORE,
        PROT_SYS_FORFEITED, PROT_SYS_ISSUED,
    };

    use super::super::model::test_support::{row_after, seed};
    use super::super::model::PROT_STORE_MOVE_CRASH;

    const HOUR: i64 = 3_600_000;
    const DAY: i64 = 86_400_000;
    /// 2027-01-15T08:00:00Z
    const NOW: i64 = 1_800_000_000_000;
    const ADMIN: &str = "01ADMINS6L1C00000000000000";
    const SERVER: &str = "01HZXS6L1C0000000000SERVER";
    const OWNER: &str = "01HZXS6L1C00000000000OWNER";

    fn user(n: u32) -> String {
        format!("01HZXS6L1C0000000000000{n:03}")
    }

    fn apple(n: u64) -> String {
        format!("apple:prod:{}", 2_000_000_000_000_000_u64 + n)
    }

    fn play(n: u8) -> String {
        format!("play:{}", format!("{n:02x}").repeat(32))
    }

    /// Install the S5a, S5b and S6 indexes on MongoDB with the migration's
    /// own helpers and create every collection up front, so no transaction
    /// has to create one. The reference driver needs no setup.
    async fn install_indexes(db: &Database) {
        match db {
            Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                for collection in crate::PROT_COLLECTIONS
                    .iter()
                    .chain(crate::PROT_TANK_COLLECTIONS.iter())
                    .chain(crate::PROT_STORE_COLLECTIONS.iter())
                {
                    mongo.db().create_collection(*collection).await.ok();
                }
                crate::create_prot_indexes(&mongo.db())
                    .await
                    .expect("failed to create the Prot ledger indexes");
                crate::create_prot_tank_indexes(&mongo.db())
                    .await
                    .expect("failed to create the Prot tank indexes");
                crate::create_prot_store_indexes(&mongo.db())
                    .await
                    .expect("failed to create the Prot store indexes");
            }
        }
    }

    fn is_error(result: &revolt_result::Result<impl std::fmt::Debug>, expected: &str) -> bool {
        match result {
            Err(error) => format!("{:?}", error.error_type).starts_with(expected),
            Ok(_) => false,
        }
    }

    async fn wallet(db: &Database, user_id: &str) -> i64 {
        db.fetch_prot_account(&prot_user_account(user_id))
            .await
            .unwrap()
            .map_or(0, |account| account.balance)
    }

    async fn entry(db: &Database, key: &str) -> Option<ProtLedgerEntry> {
        db.fetch_prot_entry_by_key(key).await.unwrap()
    }

    async fn stored(db: &Database, id: &str) -> ProtStorePurchase {
        db.fetch_prot_store_purchase(id)
            .await
            .unwrap()
            .expect("the purchase row exists")
    }

    /// An admin adjustment: credit (`amount > 0`) or debit a wallet
    async fn adjust(db: &Database, user_id: &str, nonce: &str, amount: i64, at: i64) {
        let wallet = prot_user_account(user_id);
        let (debit, credit) = if amount > 0 {
            (PROT_SYS_ADJUST.to_string(), wallet)
        } else {
            (wallet, PROT_SYS_ADJUST.to_string())
        };
        db.apply_prot_posting(&ProtPosting {
            key: prot_key_admin(ADMIN, nonce),
            kind: v0::ProtEntryKind::AdminAdjust,
            debit,
            credit,
            amount: ProtAmount::Exact(amount.abs()),
            debit_floor: 0,
            actor: ADMIN.to_string(),
            reference: ProtRef::default(),
            reason: Some("test".to_string()),
            created_at: at,
        })
        .await
        .unwrap();
    }

    fn intent(id: &str, user_id: Option<&str>, state: v0::ProtStoreIntentState) -> ProtStoreIntent {
        ProtStoreIntent {
            id: id.to_string(),
            user_id: user_id.map(str::to_string),
            store: v0::ProtStore::Apple,
            product_id: "gg.sloga.prot.p25".to_string(),
            prot: 2_600,
            token: format!("token-{id}"),
            state,
            purchase_id: None,
            created_at: NOW - HOUR,
            expires_at: NOW - HOUR + PROT_STORE_INTENT_TTL_MS,
        }
    }

    fn credit(user_id: &str, intent_id: &str) -> ProtStoreEvent {
        ProtStoreEvent::Seen(ProtStoreVerdict::Credit {
            user_id: user_id.to_string(),
            intent_id: intent_id.to_string(),
        })
    }

    fn revoke(date: i64, buyer_live: bool) -> ProtStoreEvent {
        ProtStoreEvent::Revoke {
            revocation_date: date,
            reason: Some("1".to_string()),
            user_hint: None,
            intent_id: None,
            buyer_live,
        }
    }

    /// 8.3: what generation `row.refund_gen` clawed, from the ledger
    async fn reinstate_amount(
        db: &Database,
        row: Option<&ProtStorePurchase>,
        event: &ProtStoreEvent,
    ) -> i64 {
        let (Some(row), ProtStoreEvent::Reverse { .. }) = (row, event) else {
            return 0;
        };
        db.fetch_prot_entries_by_order(&row.id)
            .await
            .unwrap()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.kind,
                    v0::ProtEntryKind::Clawback | v0::ProtEntryKind::ClawbackHold
                ) && prot_store_refund_gen_of(&entry.key, &row.id) == Some(row.refund_gen)
            })
            .map(|entry| entry.amount)
            .sum()
    }

    /// What the engine's run_store_move does (9.2): read, plan, build the move
    /// with `build_store_move`, apply; re-read and re-plan on Conflict
    async fn run_move(
        db: &Database,
        seeded: &ProtStorePurchase,
        event: &ProtStoreEvent,
        now: i64,
    ) -> (ProtStoreAnswer, Option<ProtStorePurchase>) {
        for _ in 0..PROT_STORE_MOVE_RETRIES {
            let row = db.fetch_prot_store_purchase(&seeded.id).await.unwrap();
            let amount = reinstate_amount(db, row.as_ref(), event).await;
            let plan = plan_store_move(row.as_ref(), event, amount);
            let answer = match &plan {
                ProtStoreMovePlan::Answer(answer) => return (answer.clone(), row),
                ProtStoreMovePlan::Move { answer, .. } => answer.clone(),
            };

            let m = build_store_move(row.as_ref(), seeded, event, &plan, amount, now).unwrap();
            match db.apply_store_purchase_move(&m).await.unwrap() {
                ProtStoreMoveOutcome::Applied { row, .. } => return (answer, Some(row)),
                ProtStoreMoveOutcome::Conflict => {}
            }
        }
        panic!("the store move of {} kept conflicting", seeded.id);
    }

    /// The move the engine would build now for `event` (read, plan, build)
    async fn next_move(
        db: &Database,
        seeded: &ProtStorePurchase,
        event: &ProtStoreEvent,
        now: i64,
    ) -> ProtStoreMove {
        let row = db.fetch_prot_store_purchase(&seeded.id).await.unwrap();
        let amount = reinstate_amount(db, row.as_ref(), event).await;
        let plan = plan_store_move(row.as_ref(), event, amount);
        build_store_move(row.as_ref(), seeded, event, &plan, amount, now).expect("the plan moves")
    }

    /// A store credit of `prot` to `user_id` at `at`, through a fresh Open intent
    async fn store_credit(
        db: &Database,
        id: &str,
        user_id: &str,
        prot: i64,
        at: i64,
    ) -> ProtStorePurchase {
        let store = if id.starts_with("play:") {
            v0::ProtStore::Play
        } else {
            v0::ProtStore::Apple
        };
        let intent_id = format!("intent-{id}");
        let issued = ProtStoreIntent {
            store,
            ..intent(&intent_id, Some(user_id), v0::ProtStoreIntentState::Open)
        };
        db.insert_prot_store_intent(&issued).await.unwrap();

        let seeded = seed(id, store, prot);
        let (answer, row) = run_move(db, &seeded, &credit(user_id, &intent_id), at).await;
        assert_eq!(answer, ProtStoreAnswer::Credited);
        row.unwrap()
    }

    fn rules() -> ProtTankRules {
        ProtTankRules::from_config(&revolt_config::ProtectionFeatures::default())
            .expect("the default Prot config is valid")
    }

    fn goal(id: &str, target: i64, pledged: i64) -> ProtGoal {
        ProtGoal {
            id: id.to_string(),
            kind: v0::ProtGoalKind::Launch,
            server_id: SERVER.to_string(),
            channel_id: None,
            tank_id: None,
            created_by: OWNER.to_string(),
            create_nonce: format!("create-{id}"),
            slots: 10,
            days: Some(30),
            daily_cost: 40,
            base_daily_cost: None,
            target_prot: target,
            pledged_total: pledged,
            state: v0::ProtGoalState::Funding,
            deadline_at: NOW + 14 * DAY,
            funded_at: None,
            launch_deadline_at: None,
            launched_at: None,
            closed_at: None,
            refund7_done: false,
            open_key: Some(format!("launch:{id}")),
            version: 3,
            created_at: NOW - 2 * DAY,
            updated_at: NOW - DAY,
        }
    }

    async fn insert_goal(db: &Database, goal: &ProtGoal) {
        match db {
            Database::Reference(reference) => {
                reference
                    .prot_goals
                    .lock()
                    .await
                    .insert(goal.id.clone(), goal.clone());
            }
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                mongo
                    .col::<ProtGoal>("prot_goals")
                    .insert_one(goal)
                    .await
                    .unwrap();
            }
        }
    }

    /// A Held pledge as `pledge_prot` leaves it: its PledgeHold row moved
    /// `amount` from the wallet into the goal's hold, and the pledge document
    async fn hold_pledge(
        db: &Database,
        id: &str,
        goal_id: &str,
        user_id: &str,
        amount: i64,
    ) -> ProtPledge {
        db.apply_prot_posting(&ProtPosting {
            key: prot_key_pledge(user_id, goal_id, id),
            kind: v0::ProtEntryKind::PledgeHold,
            debit: prot_user_account(user_id),
            credit: prot_hold_account(goal_id),
            amount: ProtAmount::Exact(amount),
            debit_floor: 0,
            actor: user_id.to_string(),
            reference: ProtRef {
                goal_id: Some(goal_id.to_string()),
                pledge_id: Some(id.to_string()),
                ..Default::default()
            },
            reason: None,
            created_at: NOW - DAY,
        })
        .await
        .unwrap();

        let pledge = ProtPledge {
            id: id.to_string(),
            goal_id: goal_id.to_string(),
            server_id: SERVER.to_string(),
            user_id: user_id.to_string(),
            kind: v0::ProtGoalKind::Launch,
            amount,
            remaining: amount,
            state: v0::ProtPledgeState::Held,
            captured: 0,
            launch_returned: 0,
            version: 1,
            created_at: NOW - DAY,
            updated_at: NOW - DAY,
        };
        match db {
            Database::Reference(reference) => {
                reference
                    .prot_pledges
                    .lock()
                    .await
                    .insert(pledge.id.clone(), pledge.clone());
            }
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                mongo
                    .col::<ProtPledge>("prot_pledges")
                    .insert_one(&pledge)
                    .await
                    .unwrap();
            }
        }
        pledge
    }

    /// An Active channel tank with a funded account, as a launch leaves it
    async fn insert_tank(db: &Database, id: &str, channel_id: &str) {
        let tank = ProtTank {
            id: id.to_string(),
            target: ProtTankTarget::Channel {
                channel_id: channel_id.to_string(),
            },
            target_key: prot_tank_target_key(channel_id),
            server_id: SERVER.to_string(),
            created_by: OWNER.to_string(),
            plan: v0::ProtPlan::Channel,
            slot_tier: 10,
            pending_slot_tier: None,
            daily_cost: 40,
            rate_card: "40/90/160/280".to_string(),
            stage: v0::ProtTankStage::Active,
            exhausted_at: None,
            next_burn_day: Some(prot_utc_day(NOW)),
            launched_at: Some(NOW - 10 * DAY),
            final_warning_at: None,
            warnings_epoch: 0,
            pause_shift_for: None,
            settle_cause: None,
            ended_at: None,
            terminated_by: None,
            purged_at: None,
            purge_passes: 0,
            version: 1,
            created_at: NOW - 20 * DAY,
            updated_at: NOW - DAY,
        };
        match db {
            Database::Reference(reference) => {
                reference
                    .prot_tanks
                    .lock()
                    .await
                    .insert(tank.id.clone(), tank);
            }
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                mongo
                    .col::<ProtTank>("prot_tanks")
                    .insert_one(&tank)
                    .await
                    .unwrap();
            }
        }
        db.apply_prot_posting(&ProtPosting {
            key: prot_key_admin(ADMIN, &format!("fund-{id}")),
            kind: v0::ProtEntryKind::AdminAdjust,
            debit: PROT_SYS_ADJUST.to_string(),
            credit: prot_tank_account(id),
            amount: ProtAmount::Exact(400),
            debit_floor: 0,
            actor: ADMIN.to_string(),
            reference: ProtRef::default(),
            reason: Some("test".to_string()),
            created_at: NOW - 10 * DAY,
        })
        .await
        .unwrap();
    }

    fn contribute_input(
        user_id: &str,
        tank_id: &str,
        amount: i64,
        nonce: &str,
    ) -> ProtContributeInput {
        ProtContributeInput {
            user_id: user_id.to_string(),
            tank_id: tank_id.to_string(),
            amount,
            nonce: nonce.to_string(),
            rules: rules(),
            now: NOW,
        }
    }

    fn pledge_input(user_id: &str, goal_id: &str, amount: i64, nonce: &str) -> ProtPledgeInput {
        ProtPledgeInput {
            user_id: user_id.to_string(),
            goal_id: goal_id.to_string(),
            amount,
            nonce: nonce.to_string(),
            rules: rules(),
            now: NOW,
        }
    }

    /// A first-sight credit move as the builder makes it, with `use_intent`
    /// in place of the intent it would use (None: a move with no intent)
    fn first_credit(
        id: &str,
        user_id: &str,
        intent_id: &str,
        use_intent: Option<&str>,
    ) -> ProtStoreMove {
        let seeded = seed(id, v0::ProtStore::Apple, 2_600);
        let event = credit(user_id, intent_id);
        let plan = plan_store_move(None, &event, 0);
        ProtStoreMove {
            use_intent: use_intent.map(str::to_string),
            ..build_store_move(None, &seeded, &event, &plan, 0, NOW).unwrap()
        }
    }

    // --- the one-transaction move --------------------------------------------

    /// Section 7 / plan audit BLOCKER 2: a failure between the postings and
    /// the row write leaves neither (no row, no `purchase:` row, no Prot, the
    /// intent still Open). Control (28): write the row outside the
    /// transaction, after the commit, and the credit survives the crash.
    #[tokio::test]
    async fn store_move_credit_is_one_transaction() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(1);
            let id = apple(1);
            let intent_id = "01INTS6L1C0000000000000001";
            db.insert_prot_store_intent(&intent(
                intent_id,
                Some(&buyer),
                v0::ProtStoreIntentState::Open,
            ))
            .await
            .unwrap();
            let m = first_credit(&id, &buyer, intent_id, Some(intent_id));

            PROT_STORE_MOVE_CRASH.lock().unwrap().push(id.clone());
            let crashed = db.apply_store_purchase_move(&m).await;
            PROT_STORE_MOVE_CRASH
                .lock()
                .unwrap()
                .retain(|armed| *armed != id);
            assert!(is_error(&crashed, "InternalError"), "{crashed:?}");

            assert_eq!(db.fetch_prot_store_purchase(&id).await.unwrap(), None);
            assert_eq!(entry(&db, &prot_store_key_purchase(&id)).await, None);
            assert_eq!(wallet(&db, &buyer).await, 0);
            let issued = db
                .fetch_prot_store_intent(intent_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(issued.state, v0::ProtStoreIntentState::Open);
            assert_eq!(issued.purchase_id, None);

            // The same move once the store answers again: both, together
            let ProtStoreMoveOutcome::Applied { row, entries } =
                db.apply_store_purchase_move(&m).await.unwrap()
            else {
                panic!("the credit conflicted");
            };
            assert_eq!(row.state, v0::ProtStoreState::Credited);
            assert_eq!(row.version, 0);
            assert_eq!(row, stored(&db, &id).await);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].key, prot_store_key_purchase(&id));
            assert_eq!(entries[0].amount, 2_600);
            assert_eq!(entries[0].actor, "sys:store");
            assert_eq!(entries[0].reference.order_id.as_deref(), Some(id.as_str()));
            assert_eq!(
                entry(&db, &prot_store_key_purchase(&id)).await,
                Some(entries[0].clone())
            );
            assert_eq!(wallet(&db, &buyer).await, 2_600);
            let used = db
                .fetch_prot_store_intent(intent_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(used.state, v0::ProtStoreIntentState::Used);
            assert_eq!(used.purchase_id.as_deref(), Some(id.as_str()));

            // A replay of the committed move: the row exists, nothing written
            assert_eq!(
                db.apply_store_purchase_move(&m).await.unwrap(),
                ProtStoreMoveOutcome::Conflict
            );
            assert_eq!(db.fetch_prot_entries_by_order(&id).await.unwrap().len(), 1);
            assert_eq!(wallet(&db, &buyer).await, 2_600);
        });
    }

    /// Plan audit #1: a refund seen before the charge leaves a tombstone, and
    /// the charge seen afterwards is answered refunded and credits nothing.
    /// Control (28): plan Revoked × Seen as a credit.
    #[tokio::test]
    async fn refund_then_charge_never_credits() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(2);
            let id = apple(2);
            let intent_id = "01INTS6L1C0000000000000002";
            db.insert_prot_store_intent(&intent(
                intent_id,
                Some(&buyer),
                v0::ProtStoreIntentState::Open,
            ))
            .await
            .unwrap();
            let seeded = seed(&id, v0::ProtStore::Apple, 2_600);

            let tombstone = ProtStoreEvent::Revoke {
                revocation_date: NOW - HOUR,
                reason: Some("0".to_string()),
                user_hint: Some(buyer.clone()),
                intent_id: None,
                buyer_live: true,
            };
            let (answer, row) = run_move(&db, &seeded, &tombstone, NOW - HOUR).await;
            assert_eq!(answer, ProtStoreAnswer::Revoked);
            let row = row.unwrap();
            assert_eq!(row.state, v0::ProtStoreState::Revoked);
            assert_eq!((row.refund_gen, row.refunds.len()), (0, 1));
            assert_eq!(row.refunds[0].revocation_date, NOW - HOUR);

            for event in [
                credit(&buyer, intent_id),
                ProtStoreEvent::Seen(ProtStoreVerdict::Hold {
                    user_id: buyer.clone(),
                    intent_id: intent_id.to_string(),
                }),
            ] {
                let (answer, after) = run_move(&db, &seeded, &event, NOW).await;
                assert_eq!(answer, ProtStoreAnswer::Refunded);
                assert_eq!(after.as_ref(), Some(&row));
            }

            assert_eq!(entry(&db, &prot_store_key_purchase(&id)).await, None);
            assert!(db
                .fetch_prot_entries_by_order(&id)
                .await
                .unwrap()
                .is_empty());
            assert_eq!(wallet(&db, &buyer).await, 0);
            assert_eq!(stored(&db, &id).await, row);
            let issued = db
                .fetch_prot_store_intent(intent_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(issued.state, v0::ProtStoreIntentState::Open);
        });
    }

    /// R53: a refund seen before the charge writes its tombstone with the
    /// intent its token resolved to, so the intent is Used and no longer
    /// counts against the open-intent cap. A refund whose token resolves to
    /// no intent still writes its tombstone, with none. Control (43): drop
    /// the intent from the tombstone and it stays Open.
    #[tokio::test]
    async fn refund_before_credit_marks_the_intent_used() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(38);
            let id = apple(38);
            let intent_id = "01INTS6L1C0000000000000038";
            db.insert_prot_store_intent(&intent(
                intent_id,
                Some(&buyer),
                v0::ProtStoreIntentState::Open,
            ))
            .await
            .unwrap();
            assert_eq!(
                db.fetch_open_prot_store_intents(&buyer, NOW)
                    .await
                    .unwrap()
                    .len(),
                1
            );

            let seeded = seed(&id, v0::ProtStore::Apple, 2_600);
            let refund = ProtStoreEvent::Revoke {
                revocation_date: NOW - HOUR,
                reason: None,
                user_hint: Some(buyer.clone()),
                intent_id: Some(intent_id.to_string()),
                buyer_live: true,
            };
            let (answer, row) = run_move(&db, &seeded, &refund, NOW - HOUR).await;
            assert_eq!(answer, ProtStoreAnswer::Revoked);
            let row = row.unwrap();
            assert_eq!(row.state, v0::ProtStoreState::Revoked);
            assert_eq!(row.intent_id.as_deref(), Some(intent_id));
            assert_eq!(row.user_id.as_deref(), Some(buyer.as_str()));
            let used = db
                .fetch_prot_store_intent(intent_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(used.state, v0::ProtStoreIntentState::Used);
            assert_eq!(used.purchase_id.as_deref(), Some(id.as_str()));
            assert!(db
                .fetch_open_prot_store_intents(&buyer, NOW)
                .await
                .unwrap()
                .is_empty());

            // The charge seen afterwards: refunded, nothing credited
            let (answer, _) = run_move(&db, &seeded, &credit(&buyer, intent_id), NOW).await;
            assert_eq!(answer, ProtStoreAnswer::Refunded);
            assert_eq!(wallet(&db, &buyer).await, 0);

            // No resolvable token: the tombstone is written with no intent
            let other = apple(39);
            let bare = ProtStoreEvent::Revoke {
                revocation_date: NOW - HOUR,
                reason: None,
                user_hint: None,
                intent_id: None,
                buyer_live: true,
            };
            let (answer, row) = run_move(
                &db,
                &seed(&other, v0::ProtStore::Apple, 2_600),
                &bare,
                NOW - HOUR,
            )
            .await;
            assert_eq!(answer, ProtStoreAnswer::Revoked);
            let row = row.unwrap();
            assert_eq!((row.intent_id, row.user_id), (None, None));
            assert_eq!(stored(&db, &other).await.state, v0::ProtStoreState::Revoked);
        });
    }

    /// Plan audit #3: REFUND → REVERSED → REFUND claws twice, under
    /// `clawback:{id}` then `clawback:{id}:r2`, and re-credits in between
    /// under `reinstate:{id}:1`. Replays of either REFUND move nothing.
    /// Control (28): build gen 2's key without its generation.
    #[tokio::test]
    async fn two_refund_generations_claw_twice() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(3);
            let id = apple(3);
            let seeded = store_credit(&db, &id, &buyer, 2_600, NOW - 5 * DAY).await;

            let (answer, row) =
                run_move(&db, &seeded, &revoke(NOW - 2 * DAY, true), NOW - 2 * DAY).await;
            assert_eq!(answer, ProtStoreAnswer::Revoked);
            let row = row.unwrap();
            assert_eq!(
                (row.state, row.refund_gen),
                (v0::ProtStoreState::Revoked, 1)
            );
            assert_eq!(wallet(&db, &buyer).await, 0);
            let first = entry(&db, &prot_store_key_clawback(&id, 1)).await.unwrap();
            assert_eq!(
                (first.amount, first.requested, first.shortfall),
                (2_600, Some(2_600), Some(0))
            );
            assert_eq!(first.debit, prot_user_account(&buyer));
            assert_eq!(first.credit, PROT_SYS_CLAWED);
            assert_eq!(first.actor, "sys:store");
            assert_eq!(
                (
                    row.refunds[0].gen,
                    row.refunds[0].clawed,
                    row.refunds[0].shortfall
                ),
                (1, 2_600, 0)
            );

            let (answer, row) = run_move(
                &db,
                &seeded,
                &ProtStoreEvent::Reverse { buyer_live: true },
                NOW,
            )
            .await;
            assert_eq!(answer, ProtStoreAnswer::Reinstated);
            assert_eq!(row.unwrap().state, v0::ProtStoreState::Reinstated);
            let reinstated = entry(&db, &prot_store_key_reinstate(&id, 1)).await.unwrap();
            assert_eq!(reinstated.kind, v0::ProtEntryKind::Purchase);
            assert_eq!(reinstated.amount, 2_600);
            assert_eq!(wallet(&db, &buyer).await, 2_600);

            // The first REFUND replayed after its reversal claws nothing
            let (answer, after) = run_move(&db, &seeded, &revoke(NOW - 2 * DAY, true), NOW).await;
            assert_eq!(answer, ProtStoreAnswer::Revoked);
            assert_eq!(after.unwrap().state, v0::ProtStoreState::Reinstated);
            assert_eq!(entry(&db, &prot_store_key_clawback(&id, 2)).await, None);
            assert_eq!(wallet(&db, &buyer).await, 2_600);

            let (answer, row) = run_move(&db, &seeded, &revoke(NOW + HOUR, true), NOW + HOUR).await;
            assert_eq!(answer, ProtStoreAnswer::Revoked);
            let row = row.unwrap();
            assert_eq!(row.refund_gen, 2);
            let second = entry(&db, &prot_store_key_clawback(&id, 2)).await.unwrap();
            assert_eq!(second.key, format!("clawback:{id}:r2"));
            assert_eq!(second.amount, 2_600);
            assert_eq!((row.refunds[1].gen, row.refunds[1].clawed), (2, 2_600));
            assert_eq!(wallet(&db, &buyer).await, 0);

            // Replays of both refunds: answered, nothing moves
            for date in [NOW - 2 * DAY, NOW + HOUR] {
                let (answer, after) =
                    run_move(&db, &seeded, &revoke(date, true), NOW + 2 * HOUR).await;
                assert_eq!(answer, ProtStoreAnswer::Revoked);
                assert_eq!(after.as_ref(), Some(&row));
            }
            // purchase, clawback, reinstate, clawback:r2
            assert_eq!(db.fetch_prot_entries_by_order(&id).await.unwrap().len(), 4);
            assert_conserved(&db, &[&buyer], &[]).await;
        });
    }

    /// E6 / audit 18: a generation that clawed nothing (the buyer had spent
    /// it) is reinstated with no ledger row, and the next REFUND claws again
    #[tokio::test]
    async fn reinstate_of_nothing_then_refund_claws_again() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(4);
            let id = apple(4);
            let seeded = store_credit(&db, &id, &buyer, 2_600, NOW - 5 * DAY).await;
            adjust(&db, &buyer, "spend-4", -2_600, NOW - 4 * DAY).await;

            let (_, row) =
                run_move(&db, &seeded, &revoke(NOW - 2 * DAY, true), NOW - 2 * DAY).await;
            let row = row.unwrap();
            let clawed = entry(&db, &prot_store_key_clawback(&id, 1)).await.unwrap();
            assert_eq!((clawed.amount, clawed.shortfall), (0, Some(2_600)));
            assert_eq!(
                (row.refunds[0].clawed, row.refunds[0].shortfall),
                (0, 2_600)
            );

            let (answer, row) = run_move(
                &db,
                &seeded,
                &ProtStoreEvent::Reverse { buyer_live: true },
                NOW,
            )
            .await;
            assert_eq!(answer, ProtStoreAnswer::Reinstated);
            assert_eq!(row.unwrap().state, v0::ProtStoreState::Reinstated);
            assert_eq!(entry(&db, &prot_store_key_reinstate(&id, 1)).await, None);
            assert_eq!(wallet(&db, &buyer).await, 0);

            adjust(&db, &buyer, "fund-4", 500, NOW).await;
            let (answer, row) = run_move(&db, &seeded, &revoke(NOW + HOUR, true), NOW + HOUR).await;
            assert_eq!(answer, ProtStoreAnswer::Revoked);
            assert_eq!(row.unwrap().refund_gen, 2);
            let again = entry(&db, &prot_store_key_clawback(&id, 2)).await.unwrap();
            assert_eq!((again.amount, again.shortfall), (500, Some(2_100)));
            assert_eq!(wallet(&db, &buyer).await, 0);
            assert_conserved(&db, &[&buyer], &[]).await;
        });
    }

    /// R4 / 7.3: a store refund drains the buyer's held pledges through
    /// S5b's drain, under the generation's key base:
    /// `clawback-hold:{id}:{pledge}` then `clawback-hold:{id}:r2:{pledge}`
    #[tokio::test]
    async fn clawback_drains_held_pledges_for_a_store_row() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(5);
            let id = apple(5);
            let first_goal = "01GOALS6L1C000000000000051";
            let second_goal = "01GOALS6L1C000000000000052";
            let seeded = store_credit(&db, &id, &buyer, 2_600, NOW - 5 * DAY).await;

            insert_goal(&db, &goal(first_goal, 5_000, 2_000)).await;
            let first =
                hold_pledge(&db, "01PLGS6L1C0000000000000051", first_goal, &buyer, 2_000).await;
            assert_eq!(wallet(&db, &buyer).await, 600);

            let (_, row) =
                run_move(&db, &seeded, &revoke(NOW - 2 * DAY, true), NOW - 2 * DAY).await;
            let row = row.unwrap();
            let wallet_row = entry(&db, &prot_store_key_clawback(&id, 1)).await.unwrap();
            assert_eq!((wallet_row.amount, wallet_row.shortfall), (600, Some(0)));
            let held = entry(&db, &prot_key_clawback_hold(&id, &first.id))
                .await
                .unwrap();
            assert_eq!(held.kind, v0::ProtEntryKind::ClawbackHold);
            assert_eq!(held.amount, 2_000);
            assert_eq!(held.reference.order_id.as_deref(), Some(id.as_str()));
            assert_eq!(prot_store_refund_gen_of(&held.key, &id), Some(1));
            assert_eq!(
                (row.refunds[0].clawed, row.refunds[0].shortfall),
                (2_600, 0)
            );
            assert_eq!(db.sum_held_prot_pledges(&buyer).await.unwrap(), 0);

            // The reversal re-credits what the generation took from both
            let (answer, _) = run_move(
                &db,
                &seeded,
                &ProtStoreEvent::Reverse { buyer_live: true },
                NOW,
            )
            .await;
            assert_eq!(answer, ProtStoreAnswer::Reinstated);
            assert_eq!(
                entry(&db, &prot_store_key_reinstate(&id, 1))
                    .await
                    .unwrap()
                    .amount,
                2_600
            );
            assert_eq!(wallet(&db, &buyer).await, 2_600);

            insert_goal(&db, &goal(second_goal, 5_000, 1_000)).await;
            let second = hold_pledge(
                &db,
                "01PLGS6L1C0000000000000052",
                second_goal,
                &buyer,
                1_000,
            )
            .await;
            let (_, row) = run_move(&db, &seeded, &revoke(NOW + HOUR, true), NOW + HOUR).await;
            let row = row.unwrap();
            let held = entry(
                &db,
                &prot_key_clawback_hold(&format!("{id}:r2"), &second.id),
            )
            .await
            .unwrap();
            assert_eq!(held.key, format!("clawback-hold:{id}:r2:{}", second.id));
            assert_eq!(held.amount, 1_000);
            assert_eq!(prot_store_refund_gen_of(&held.key, &id), Some(2));
            assert_eq!(
                (row.refunds[1].clawed, row.refunds[1].shortfall),
                (2_600, 0)
            );
            assert_eq!(wallet(&db, &buyer).await, 0);
            assert_eq!(
                db.fetch_prot_account(&prot_hold_account(second_goal))
                    .await
                    .unwrap()
                    .map(|account| account.balance),
                Some(0)
            );
            assert_conserved(&db, &[&buyer], &[first_goal, second_goal]).await;
        });
    }

    /// 7.2 step 2: an intent is used once, from Open or Expired, by its own
    /// user. Control (28): accept Used in the intent CAS.
    #[tokio::test]
    async fn reused_intent_is_conflict() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(6);
            let intent_id = "01INTS6L1C0000000000000006";
            db.insert_prot_store_intent(&intent(
                intent_id,
                Some(&buyer),
                v0::ProtStoreIntentState::Open,
            ))
            .await
            .unwrap();
            let first = apple(61);
            assert!(matches!(
                db.apply_store_purchase_move(&first_credit(
                    &first,
                    &buyer,
                    intent_id,
                    Some(intent_id)
                ))
                .await
                .unwrap(),
                ProtStoreMoveOutcome::Applied { .. }
            ));

            // A second purchase naming the Used intent writes nothing
            let second = apple(62);
            assert_eq!(
                db.apply_store_purchase_move(&first_credit(
                    &second,
                    &buyer,
                    intent_id,
                    Some(intent_id)
                ))
                .await
                .unwrap(),
                ProtStoreMoveOutcome::Conflict
            );
            assert_eq!(db.fetch_prot_store_purchase(&second).await.unwrap(), None);
            assert_eq!(entry(&db, &prot_store_key_purchase(&second)).await, None);
            assert_eq!(wallet(&db, &buyer).await, 2_600);
            let used = db
                .fetch_prot_store_intent(intent_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(used.purchase_id.as_deref(), Some(first.as_str()));

            // Another user's intent is not this row's
            let theirs = "01INTS6L1C0000000000000016";
            db.insert_prot_store_intent(&intent(
                theirs,
                Some(&user(16)),
                v0::ProtStoreIntentState::Open,
            ))
            .await
            .unwrap();
            assert_eq!(
                db.apply_store_purchase_move(&first_credit(
                    &apple(63),
                    &buyer,
                    theirs,
                    Some(theirs)
                ))
                .await
                .unwrap(),
                ProtStoreMoveOutcome::Conflict
            );

            // An Expired intent still binds a late purchase
            let late = "01INTS6L1C0000000000000026";
            db.insert_prot_store_intent(&intent(
                late,
                Some(&buyer),
                v0::ProtStoreIntentState::Expired,
            ))
            .await
            .unwrap();
            assert!(matches!(
                db.apply_store_purchase_move(&first_credit(&apple(64), &buyer, late, Some(late)))
                    .await
                    .unwrap(),
                ProtStoreMoveOutcome::Applied { .. }
            ));
            assert_eq!(
                db.fetch_prot_store_intent(late)
                    .await
                    .unwrap()
                    .unwrap()
                    .state,
                v0::ProtStoreIntentState::Used
            );
            assert_eq!(wallet(&db, &buyer).await, 5_200);
        });
    }

    /// Audits 2+19: a second purchase carrying an already-Used token is an
    /// unbound purchase. Its row is written with `use_intent` None, and the
    /// first intent keeps its purchase. Control (28): pass `use_intent` for
    /// the Reject{Unbound} and the row is never written.
    #[tokio::test]
    async fn unbound_row_on_a_used_intent_is_written() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(7);
            let intent_id = "01INTS6L1C0000000000000007";
            db.insert_prot_store_intent(&intent(
                intent_id,
                Some(&buyer),
                v0::ProtStoreIntentState::Open,
            ))
            .await
            .unwrap();
            let first = apple(71);
            let first_seed = seed(&first, v0::ProtStore::Apple, 2_600);
            run_move(&db, &first_seed, &credit(&buyer, intent_id), NOW).await;

            // The engine resolves the token to a Used intent of another
            // purchase: Reject{Unbound}, no user; the row records the
            // intent the token matched, and the builder never uses it
            let second = apple(72);
            let unbound = ProtStoreEvent::Seen(ProtStoreVerdict::Reject {
                reason: v0::ProtStoreRejectReason::Unbound,
                user_id: None,
                intent_id: Some(intent_id.to_string()),
            });
            let (answer, row) = run_move(
                &db,
                &seed(&second, v0::ProtStore::Apple, 2_600),
                &unbound,
                NOW,
            )
            .await;
            assert_eq!(
                answer,
                ProtStoreAnswer::Rejected(v0::ProtStoreRejectReason::Unbound)
            );
            let row = row.unwrap();
            assert_eq!(row, stored(&db, &second).await);
            assert_eq!(row.state, v0::ProtStoreState::Rejected);
            assert_eq!(row.user_id, None);
            assert_eq!(row.needs_action.as_deref(), Some("unbound"));
            assert_eq!(row.intent_id.as_deref(), Some(intent_id));
            assert_eq!(entry(&db, &prot_store_key_purchase(&second)).await, None);

            let used = db
                .fetch_prot_store_intent(intent_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(used.state, v0::ProtStoreIntentState::Used);
            assert_eq!(used.purchase_id.as_deref(), Some(first.as_str()));
            assert_eq!(wallet(&db, &buyer).await, 2_600);

            // And the driver refuses an intent on such a row outright
            let plan = plan_store_move(None, &unbound, 0);
            let next = row_after(
                None,
                &seed(&apple(73), v0::ProtStore::Apple, 2_600),
                &unbound,
                &plan,
                NOW,
            )
            .unwrap();
            let refused = db
                .apply_store_purchase_move(&ProtStoreMove {
                    row: next,
                    expected_version: None,
                    use_intent: Some(intent_id.to_string()),
                    ledger: ProtStoreLedger::None,
                })
                .await;
            assert!(is_error(&refused, "InternalError"), "{refused:?}");
            assert_eq!(
                db.fetch_prot_store_purchase(&apple(73)).await.unwrap(),
                None
            );
        });
    }

    /// Apply every move at once, each on its own task
    async fn race(db: &Database, moves: Vec<ProtStoreMove>) -> Vec<ProtStoreMoveOutcome> {
        let handles: Vec<_> = moves
            .into_iter()
            .map(|m| {
                let db = db.clone();
                tokio::spawn(async move { db.apply_store_purchase_move(&m).await })
            })
            .collect();
        tokio::time::timeout(Duration::from_secs(60), join_all(handles))
            .await
            .expect("the racing moves never settled")
            .into_iter()
            .map(|joined| {
                joined
                    .expect("a racing move panicked")
                    .expect("a racing move failed")
            })
            .collect()
    }

    fn applied(outcomes: &[ProtStoreMoveOutcome]) -> usize {
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ProtStoreMoveOutcome::Applied { .. }))
            .count()
    }

    /// W1 audit MINOR 5: every move planned on the same read before any
    /// applies, then applied at once on a multi-threaded runtime. Twenty
    /// verifies of one purchase: one credit, the rest Conflict and then
    /// already_credited. Ten unpauses and ten refunds of one Held row: one
    /// lands, and the row and the ledger agree. Control (40): drop the version
    /// check and a stale refund overwrites the credited row.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_moves_credit_once() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(8);
            let id = apple(8);
            let intent_id = "01INTS6L1C0000000000000008";
            db.insert_prot_store_intent(&intent(
                intent_id,
                Some(&buyer),
                v0::ProtStoreIntentState::Open,
            ))
            .await
            .unwrap();
            let seeded = seed(&id, v0::ProtStore::Apple, 2_600);
            let event = credit(&buyer, intent_id);

            let first = next_move(&db, &seeded, &event, NOW).await;
            let outcomes = race(&db, vec![first; 20]).await;
            assert_eq!(applied(&outcomes), 1, "{outcomes:?}");
            let answers = join_all((0..20).map(|i| run_move(&db, &seeded, &event, NOW + i))).await;
            assert!(
                answers
                    .iter()
                    .all(|(answer, _)| *answer == ProtStoreAnswer::AlreadyCredited),
                "{answers:?}"
            );
            assert_eq!(db.fetch_prot_entries_by_order(&id).await.unwrap().len(), 1);
            assert_eq!(wallet(&db, &buyer).await, 2_600);
            assert_eq!(stored(&db, &id).await.version, 0);

            // A Held row: unpauses and refunds, all planned on one copy
            let held_id = apple(81);
            let held_intent = "01INTS6L1C0000000000000081";
            db.insert_prot_store_intent(&intent(
                held_intent,
                Some(&buyer),
                v0::ProtStoreIntentState::Open,
            ))
            .await
            .unwrap();
            let held_seed = seed(&held_id, v0::ProtStore::Apple, 1_000);
            let hold = ProtStoreEvent::Seen(ProtStoreVerdict::Hold {
                user_id: buyer.clone(),
                intent_id: held_intent.to_string(),
            });
            run_move(&db, &held_seed, &hold, NOW).await;
            let mut moves = Vec::new();
            for k in 1..=10 {
                let unpause = ProtStoreEvent::Unpause { buyer_live: true };
                moves.push(next_move(&db, &held_seed, &unpause, NOW + k).await);
                moves.push(next_move(&db, &held_seed, &revoke(NOW + k, true), NOW + k).await);
            }
            let outcomes = race(&db, moves).await;
            assert_eq!(applied(&outcomes), 1, "{outcomes:?}");

            let row = stored(&db, &held_id).await;
            assert_eq!(row.version, 1);
            let credited = entry(&db, &prot_store_key_purchase(&held_id))
                .await
                .is_some();
            assert_eq!(credited, row.state == v0::ProtStoreState::Credited);
            assert_eq!(credited, row.refunds.is_empty());
            assert!(row.refunds.len() <= 1);
            assert_eq!(
                wallet(&db, &buyer).await,
                2_600 + if credited { 1_000 } else { 0 }
            );
        });
    }

    /// Sections 0 and 6: a Credited row always has its `purchase:{id}` row,
    /// the key already_credited is answered from. A move that would make a
    /// row Credited without that posting is refused, and a Credited row
    /// that somehow lacks it is never credited by a later move either.
    /// Control (28): drop `check_store_credit` and a Credited row lands with
    /// no ledger key.
    #[tokio::test]
    async fn already_credited_needs_the_ledger_key() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(9);
            let id = apple(9);

            // A Credited row with no posting: refused, nothing written
            let mut bare = first_credit(&id, &buyer, "01INTS6L1C0000000000000009", None);
            bare.ledger = ProtStoreLedger::None;
            let refused = db.apply_store_purchase_move(&bare).await;
            assert!(is_error(&refused, "InternalError"), "{refused:?}");
            assert_eq!(db.fetch_prot_store_purchase(&id).await.unwrap(), None);

            // The real credit: its entries carry the key, and the key reads back
            let ProtStoreMoveOutcome::Applied { row, entries } = db
                .apply_store_purchase_move(&first_credit(
                    &id,
                    &buyer,
                    "01INTS6L1C0000000000000009",
                    None,
                ))
                .await
                .unwrap()
            else {
                panic!("the credit conflicted");
            };
            assert_eq!(entries.len(), 1);
            assert_eq!(
                entry(&db, &prot_store_key_purchase(&id)).await,
                Some(entries[0].clone())
            );

            // Seen again: the planner answers AlreadyCredited and the key is there
            assert_eq!(
                plan_store_move(Some(&row), &credit(&buyer, "x"), 0),
                ProtStoreMovePlan::Answer(ProtStoreAnswer::AlreadyCredited)
            );
            // A stale or a first-sight credit of the same row never lands twice
            for expected_version in [None, Some(row.version + 1)] {
                let mut again = first_credit(&id, &buyer, "01INTS6L1C0000000000000009", None);
                again.expected_version = expected_version;
                assert_eq!(
                    db.apply_store_purchase_move(&again).await.unwrap(),
                    ProtStoreMoveOutcome::Conflict
                );
            }
            assert_eq!(db.fetch_prot_entries_by_order(&id).await.unwrap().len(), 1);
            assert_eq!(wallet(&db, &buyer).await, 2_600);
        });
    }

    // --- R50: every posting is bounded by the stored row ---------------------

    /// A forged move is refused whole: InternalError, the stored row and the
    /// purchase's ledger rows as they were
    async fn assert_refused(db: &Database, m: &ProtStoreMove) {
        let row = db.fetch_prot_store_purchase(&m.row.id).await.unwrap();
        let rows = db.fetch_prot_entries_by_order(&m.row.id).await.unwrap();
        let refused = db.apply_store_purchase_move(m).await;
        assert!(is_error(&refused, "InternalError"), "{refused:?}");
        assert_eq!(db.fetch_prot_store_purchase(&m.row.id).await.unwrap(), row);
        assert_eq!(
            db.fetch_prot_entries_by_order(&m.row.id).await.unwrap(),
            rows
        );
    }

    /// The Exact credit a forged move posts (shaped as 8.2's, so only the
    /// bound against the stored row can refuse it)
    fn forged_credit(row: &ProtStorePurchase, key: String, amount: i64) -> ProtStoreLedger {
        ProtStoreLedger::Credit(ProtPosting {
            key,
            kind: v0::ProtEntryKind::Purchase,
            debit: PROT_SYS_ISSUED.to_string(),
            credit: prot_user_account(row.user_id.as_deref().unwrap_or_default()),
            amount: ProtAmount::Exact(amount),
            debit_floor: 0,
            actor: PROT_ACTOR_STORE.to_string(),
            reference: ProtRef {
                order_id: Some(row.id.clone()),
                ..Default::default()
            },
            reason: None,
            created_at: NOW,
        })
    }

    /// The generation-`gen` clawback a forged move posts
    fn forged_clawback(row: &ProtStorePurchase, gen: u32) -> ProtStoreLedger {
        let user_id = row.user_id.clone().unwrap_or_default();
        ProtStoreLedger::Clawback {
            posting: ProtPosting {
                key: prot_store_key_clawback(&row.id, gen),
                kind: v0::ProtEntryKind::Clawback,
                debit: prot_user_account(&user_id),
                credit: PROT_SYS_CLAWED.to_string(),
                amount: ProtAmount::UpTo(row.prot),
                debit_floor: 0,
                actor: PROT_ACTOR_STORE.to_string(),
                reference: ProtRef {
                    order_id: Some(row.id.clone()),
                    ..Default::default()
                },
                reason: None,
                created_at: NOW,
            },
            user_id,
            key_base: prot_store_refund_base(&row.id, gen),
        }
    }

    /// A move of the stored row to `row`, CAS on its current version
    fn forged(
        stored: &ProtStorePurchase,
        row: ProtStorePurchase,
        ledger: ProtStoreLedger,
    ) -> ProtStoreMove {
        ProtStoreMove {
            row,
            expected_version: Some(stored.version),
            use_intent: None,
            ledger,
        }
    }

    fn refund_entry(gen: u32) -> ProtStoreRefund {
        ProtStoreRefund {
            gen,
            at: NOW,
            revocation_date: NOW + i64::from(gen),
            clawed: 0,
            shortfall: 0,
            reason: None,
        }
    }

    /// R50: a reinstate re-credits exactly what its generation clawed (2,000
    /// of the 2,600 here: 600 was spent before the refund). Control (40):
    /// drop the amount check and a 1,999 or 2,600 reinstate lands.
    #[tokio::test]
    async fn reinstate_must_re_credit_what_its_generation_clawed() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(30);
            let id = apple(30);
            let seeded = store_credit(&db, &id, &buyer, 2_600, NOW - 5 * DAY).await;
            adjust(&db, &buyer, "spend-30", -600, NOW - 4 * DAY).await;
            run_move(&db, &seeded, &revoke(NOW - 2 * DAY, true), NOW - 2 * DAY).await;
            assert_eq!(
                entry(&db, &prot_store_key_clawback(&id, 1))
                    .await
                    .unwrap()
                    .amount,
                2_000
            );

            let reverse = ProtStoreEvent::Reverse { buyer_live: true };
            let honest = next_move(&db, &seeded, &reverse, NOW).await;
            for amount in [1_999, 2_001, 2_600] {
                let mut m = honest.clone();
                m.ledger = forged_credit(&m.row, prot_store_key_reinstate(&id, 1), amount);
                assert_refused(&db, &m).await;
            }

            assert!(matches!(
                db.apply_store_purchase_move(&honest).await.unwrap(),
                ProtStoreMoveOutcome::Applied { .. }
            ));
            assert_eq!(
                entry(&db, &prot_store_key_reinstate(&id, 1))
                    .await
                    .unwrap()
                    .amount,
                2_000
            );
            assert_eq!(wallet(&db, &buyer).await, 2_000);
            assert_conserved(&db, &[&buyer], &[]).await;
        });
    }

    /// R50: a reinstate needs the Revoked row of its own generation: never a
    /// row that was not refunded, never an earlier generation
    #[tokio::test]
    async fn reinstate_needs_the_revoked_row_of_its_generation() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(31);
            let id = apple(31);
            let seeded = store_credit(&db, &id, &buyer, 2_600, NOW - 5 * DAY).await;

            let credited = stored(&db, &id).await;
            let row = ProtStorePurchase {
                state: v0::ProtStoreState::Reinstated,
                refund_gen: 1,
                ..credited.clone()
            };
            let ledger = forged_credit(&row, prot_store_key_reinstate(&id, 1), 2_600);
            assert_refused(&db, &forged(&credited, row, ledger)).await;

            // Generation 2 is Revoked; generation 1's reversal is settled
            run_move(&db, &seeded, &revoke(NOW - 2 * DAY, true), NOW - 2 * DAY).await;
            let reverse = ProtStoreEvent::Reverse { buyer_live: true };
            run_move(&db, &seeded, &reverse, NOW - 36 * HOUR).await;
            run_move(&db, &seeded, &revoke(NOW - DAY, true), NOW - DAY).await;
            let revoked = stored(&db, &id).await;
            assert_eq!(
                (revoked.state, revoked.refund_gen),
                (v0::ProtStoreState::Revoked, 2)
            );
            let row = ProtStorePurchase {
                state: v0::ProtStoreState::Reinstated,
                refund_gen: 1,
                ..revoked.clone()
            };
            let ledger = forged_credit(&row, prot_store_key_reinstate(&id, 1), 2_600);
            assert_refused(&db, &forged(&revoked, row, ledger)).await;
            assert_eq!(wallet(&db, &buyer).await, 0);
        });
    }

    /// R50: a clawback takes the next generation of a Credited or Reinstated
    /// row: never a skipped generation, never a second claw of a Revoked row
    #[tokio::test]
    async fn clawback_needs_the_next_generation_of_a_credited_row() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(32);
            let id = apple(32);
            let seeded = store_credit(&db, &id, &buyer, 2_600, NOW - 5 * DAY).await;

            let credited = stored(&db, &id).await;
            let mut row = credited.clone();
            row.state = v0::ProtStoreState::Revoked;
            row.refund_gen = 2;
            row.refunds.push(refund_entry(2));
            let ledger = forged_clawback(&row, 2);
            assert_refused(&db, &forged(&credited, row, ledger)).await;
            assert_eq!(wallet(&db, &buyer).await, 2_600);

            adjust(&db, &buyer, "fund-32", 2_600, NOW - 3 * DAY).await;
            run_move(&db, &seeded, &revoke(NOW - DAY, true), NOW - DAY).await;
            let revoked = stored(&db, &id).await;
            let mut row = revoked.clone();
            row.refund_gen = 2;
            row.refunds.push(refund_entry(2));
            let ledger = forged_clawback(&row, 2);
            assert_refused(&db, &forged(&revoked, row, ledger)).await;
            assert_eq!(wallet(&db, &buyer).await, 2_600);
        });
    }

    /// R50: a `purchase:` credit lands only on an uncredited row (absent,
    /// Held, Rejected(Unbound)): never on a tombstone or a test purchase
    #[tokio::test]
    async fn purchase_credit_needs_an_uncredited_row() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(33);
            let tombstone = ProtStoreEvent::Revoke {
                revocation_date: NOW - HOUR,
                reason: None,
                user_hint: Some(buyer.clone()),
                intent_id: None,
                buyer_live: true,
            };
            run_move(
                &db,
                &seed(&apple(33), v0::ProtStore::Apple, 2_600),
                &tombstone,
                NOW - HOUR,
            )
            .await;
            let test = ProtStoreEvent::Seen(ProtStoreVerdict::Reject {
                reason: v0::ProtStoreRejectReason::TestPurchase,
                user_id: Some(buyer.clone()),
                intent_id: None,
            });
            run_move(
                &db,
                &seed(&apple(34), v0::ProtStore::Apple, 2_600),
                &test,
                NOW,
            )
            .await;

            for id in [apple(33), apple(34)] {
                let before = stored(&db, &id).await;
                let row = ProtStorePurchase {
                    state: v0::ProtStoreState::Credited,
                    reject_reason: None,
                    credited_at: Some(NOW),
                    ..before.clone()
                };
                let ledger = forged_credit(&row, prot_store_key_purchase(&id), 2_600);
                assert_refused(&db, &forged(&before, row, ledger)).await;
            }
            assert_eq!(wallet(&db, &buyer).await, 0);

            // An unbound purchase is assignable (E10)
            let unbound_seed = seed(&apple(35), v0::ProtStore::Apple, 2_600);
            let unbound = ProtStoreEvent::Seen(ProtStoreVerdict::Reject {
                reason: v0::ProtStoreRejectReason::Unbound,
                user_id: None,
                intent_id: None,
            });
            run_move(&db, &unbound_seed, &unbound, NOW).await;
            let assign = ProtStoreEvent::Assign {
                user_id: buyer.clone(),
                admin_id: ADMIN.to_string(),
                paused: false,
            };
            let (answer, row) = run_move(&db, &unbound_seed, &assign, NOW + 1).await;
            assert_eq!(answer, ProtStoreAnswer::Credited);
            let row = row.unwrap();
            assert_eq!(row.user_id.as_deref(), Some(buyer.as_str()));
            assert_eq!(row.assigned_by.as_deref(), Some(ADMIN));
            assert_eq!(row.needs_action, None);
            assert_eq!(wallet(&db, &buyer).await, 2_600);
        });
    }

    /// R50: a CAS never changes what was bought (prot, store, environment,
    /// product, quantity, first sight)
    #[tokio::test]
    async fn a_cas_never_changes_what_was_bought() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(36);
            let id = apple(36);
            let intent_id = format!("intent-{id}");
            db.insert_prot_store_intent(&intent(
                &intent_id,
                Some(&buyer),
                v0::ProtStoreIntentState::Open,
            ))
            .await
            .unwrap();
            let seeded = seed(&id, v0::ProtStore::Apple, 2_600);
            let hold = ProtStoreEvent::Seen(ProtStoreVerdict::Hold {
                user_id: buyer.clone(),
                intent_id,
            });
            run_move(&db, &seeded, &hold, NOW - HOUR).await;

            let unpause = ProtStoreEvent::Unpause { buyer_live: true };
            let honest = next_move(&db, &seeded, &unpause, NOW).await;
            let edits: [fn(&mut ProtStorePurchase); 6] = [
                |row| row.prot = 9_999,
                |row| row.store = v0::ProtStore::Play,
                |row| row.environment = v0::ProtStoreEnvironment::Sandbox,
                |row| row.product_id = "gg.sloga.prot.p100".to_string(),
                |row| row.quantity = 2,
                |row| row.created_at += 1,
            ];
            for edit in edits {
                let mut m = honest.clone();
                edit(&mut m.row);
                m.ledger = forged_credit(&m.row, prot_store_key_purchase(&id), m.row.prot);
                assert_refused(&db, &m).await;
            }
            assert!(matches!(
                db.apply_store_purchase_move(&honest).await.unwrap(),
                ProtStoreMoveOutcome::Applied { .. }
            ));
            assert_eq!(wallet(&db, &buyer).await, 2_600);
        });
    }

    /// W1 audit MINOR 4: a `purchase:` credit records its own instant
    #[tokio::test]
    async fn purchase_credit_records_when_it_was_credited() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(37);
            let id = apple(37);
            for credited_at in [None, Some(NOW - 1)] {
                let mut m = first_credit(&id, &buyer, "01INTS6L1C0000000000000037", None);
                m.row.credited_at = credited_at;
                assert_refused(&db, &m).await;
            }
            let ProtStoreMoveOutcome::Applied { row, entries } = db
                .apply_store_purchase_move(&first_credit(
                    &id,
                    &buyer,
                    "01INTS6L1C0000000000000037",
                    None,
                ))
                .await
                .unwrap()
            else {
                panic!("the credit conflicted");
            };
            assert_eq!(row.credited_at, Some(entries[0].created_at));
        });
    }

    /// S5b's `assert_conserved` (tanks.rs): every tracked account equals its
    /// rows and is never below 0, the ledger sums to 0 over the tracked and
    /// system sides, and each goal's hold equals its Held pledges and its
    /// `pledged_total`
    async fn assert_conserved(db: &Database, users: &[&str], goals: &[&str]) {
        let sys = [
            PROT_SYS_ISSUED,
            PROT_SYS_ADJUST,
            PROT_SYS_CLAWED,
            PROT_SYS_FORFEITED,
        ];
        let accounts: Vec<String> = users
            .iter()
            .map(|user_id| prot_user_account(user_id))
            .chain(goals.iter().map(|goal_id| prot_hold_account(goal_id)))
            .collect();
        let mut rows: HashMap<String, ProtLedgerEntry> = HashMap::new();
        for account in accounts.iter().map(String::as_str).chain(sys) {
            let mut before: Option<String> = None;
            loop {
                let page = db
                    .fetch_prot_entries_by_account(account, before.as_deref(), 100)
                    .await
                    .unwrap();
                let full = page.len() == 100;
                before = page.last().map(|row| row.id.clone());
                rows.extend(page.into_iter().map(|row| (row.id.clone(), row)));
                if !full {
                    break;
                }
            }
        }
        let signed = |account: &str| -> i64 {
            rows.values()
                .map(|row| {
                    (if row.credit == account { row.amount } else { 0 })
                        - (if row.debit == account { row.amount } else { 0 })
                })
                .sum()
        };

        let mut total = 0;
        for account in &accounts {
            let cached = db
                .fetch_prot_account(account)
                .await
                .unwrap()
                .map_or(0, |account| account.balance);
            assert_eq!(cached, signed(account), "{account} != its rows");
            assert!(cached >= 0, "{account} below 0 ({cached})");
            total += cached;
        }
        let system: i64 = sys.iter().map(|side| signed(side)).sum();
        assert_eq!(total + system, 0, "the ledger does not sum to 0");

        for goal_id in goals {
            let goal = db
                .fetch_prot_goal(goal_id)
                .await
                .unwrap()
                .expect("the goal exists");
            let held: i64 = db
                .fetch_prot_pledges_by_goal(goal_id)
                .await
                .unwrap()
                .iter()
                .filter(|pledge| pledge.state == v0::ProtPledgeState::Held)
                .map(|pledge| pledge.remaining)
                .sum();
            let hold = db
                .fetch_prot_account(&prot_hold_account(goal_id))
                .await
                .unwrap()
                .map_or(0, |account| account.balance);
            assert_eq!((hold, goal.pledged_total), (held, held), "{goal_id}");
        }
    }

    // --- the held figure --------------------------------------------------------

    /// 7.4 / R8: a Play credit the server has not consumed stays held after
    /// the 72 h window (Play refunds unconsumed purchases), in `/@me`'s figure
    /// (also at hold 0) and in S5b's contribute and pledge floors, until
    /// `mark_prot_store_consumed`. Control (28): drop the unconsumed term.
    #[tokio::test]
    async fn unconsumed_play_credit_stays_held_after_the_window() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(10);
            let id = play(10);
            let tank_id = "01TANKS6L1C000000000000010";
            let goal_id = "01GOALS6L1C000000000000010";
            let row = store_credit(&db, &id, &buyer, 2_600, NOW - 4 * DAY).await;
            assert_eq!(row.unconsumed, Some(true));
            insert_tank(&db, tank_id, "01CHANS6L1C000000000000010").await;
            insert_goal(&db, &goal(goal_id, 5_000, 0)).await;

            let window = NOW - 72 * HOUR;
            assert_eq!(db.held_purchase_prot(&buyer, window).await.unwrap(), 2_600);
            // Hold 0: the cutoff is now, and the credit still counts
            assert_eq!(db.held_purchase_prot(&buyer, NOW).await.unwrap(), 2_600);
            assert_eq!(
                db.sum_unconsumed_play_prot(&buyer, i64::MAX).await.unwrap(),
                2_600
            );
            assert_eq!(
                db.sum_unconsumed_play_prot(&buyer, NOW - 5 * DAY)
                    .await
                    .unwrap(),
                0
            );

            let amount = rules().min_contribution;
            assert!(amount <= 1_000);
            let contributed = db
                .contribute_prot(&contribute_input(&buyer, tank_id, amount, "c-1"))
                .await;
            assert!(
                is_error(&contributed, "InsufficientProt"),
                "{contributed:?}"
            );
            let pledged = db
                .pledge_prot(&pledge_input(&buyer, goal_id, amount, "p-1"))
                .await;
            assert!(is_error(&pledged, "InsufficientProt"), "{pledged:?}");

            // A stale version is refused; the current one consumes it
            assert!(!db
                .mark_prot_store_consumed(&id, row.version + 1, NOW)
                .await
                .unwrap());
            assert!(db
                .mark_prot_store_consumed(&id, row.version, NOW)
                .await
                .unwrap());
            let consumed = stored(&db, &id).await;
            assert_eq!(consumed.unconsumed, None);
            assert_eq!(consumed.play.as_ref().unwrap().consumed_at, Some(NOW));
            assert_eq!(consumed.version, row.version + 1);
            assert!(db
                .fetch_unconsumed_play_purchases(10)
                .await
                .unwrap()
                .is_empty());

            assert_eq!(db.held_purchase_prot(&buyer, window).await.unwrap(), 0);
            let contributed = db
                .contribute_prot(&contribute_input(&buyer, tank_id, amount, "c-2"))
                .await;
            assert!(contributed.is_ok(), "{contributed:?}");
            let pledged = db
                .pledge_prot(&pledge_input(&buyer, goal_id, amount, "p-2"))
                .await;
            assert!(pledged.is_ok(), "{pledged:?}");
            assert_eq!(wallet(&db, &buyer).await, 2_600 - 2 * amount);
        });
    }

    /// Audit N1: reinstated Prot is held 72 h again. Credit 2,600 at T-5 d,
    /// REFUND at T-2 d, REVERSED at T: 2,600 held; a gen-2 REFUND at T+1 h:
    /// 0 held. Control (28): restore S5b's untimed clawback subtraction.
    #[tokio::test]
    async fn reinstate_is_held_72h() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(11);
            let id = apple(11);
            let seeded = store_credit(&db, &id, &buyer, 2_600, NOW - 5 * DAY).await;
            assert_eq!(
                db.held_purchase_prot(&buyer, NOW - 72 * HOUR)
                    .await
                    .unwrap(),
                0
            );

            run_move(&db, &seeded, &revoke(NOW - 2 * DAY, true), NOW - 2 * DAY).await;
            let (answer, _) = run_move(
                &db,
                &seeded,
                &ProtStoreEvent::Reverse { buyer_live: true },
                NOW,
            )
            .await;
            assert_eq!(answer, ProtStoreAnswer::Reinstated);
            assert_eq!(wallet(&db, &buyer).await, 2_600);
            assert_eq!(
                db.held_purchase_prot(&buyer, NOW - 72 * HOUR)
                    .await
                    .unwrap(),
                2_600
            );

            run_move(&db, &seeded, &revoke(NOW + HOUR, true), NOW + HOUR).await;
            assert_eq!(
                db.held_purchase_prot(&buyer, NOW + HOUR - 72 * HOUR)
                    .await
                    .unwrap(),
                0
            );
        });
    }

    // --- account deletion and versions ------------------------------------------

    /// 17: an unlinked user's rows and intents are kept without a user;
    /// Open intents expire; the unlink is idempotent and leaves other users'
    /// rows alone
    #[tokio::test]
    async fn unlink_keeps_rows_without_a_user() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let gone = user(12);
            let other = user(13);
            let credited = store_credit(&db, &apple(121), &gone, 2_600, NOW - DAY).await;
            let held_seed = seed(&apple(122), v0::ProtStore::Apple, 1_000);
            let held_intent = "01INTS6L1C0000000000000122";
            db.insert_prot_store_intent(&intent(
                held_intent,
                Some(&gone),
                v0::ProtStoreIntentState::Open,
            ))
            .await
            .unwrap();
            let hold = ProtStoreEvent::Seen(ProtStoreVerdict::Hold {
                user_id: gone.clone(),
                intent_id: held_intent.to_string(),
            });
            let (_, held) = run_move(&db, &held_seed, &hold, NOW).await;
            let held = held.unwrap();
            let open = "01INTS6L1C0000000000000123";
            db.insert_prot_store_intent(&intent(open, Some(&gone), v0::ProtStoreIntentState::Open))
                .await
                .unwrap();
            let theirs = store_credit(&db, &apple(131), &other, 2_600, NOW - DAY).await;
            assert_eq!(db.sum_held_prot_store(&gone).await.unwrap(), 1_000);

            db.unlink_prot_store_user(&gone).await.unwrap();
            for before in [&credited, &held] {
                let after = stored(&db, &before.id).await;
                assert_eq!(after.user_id, None);
                assert_eq!(after.state, before.state);
                assert_eq!(after.version, before.version + 1);
                assert_ne!(after.updated_at, before.updated_at);
            }
            let after = db.fetch_prot_store_intent(open).await.unwrap().unwrap();
            assert_eq!(
                (after.user_id, after.state),
                (None, v0::ProtStoreIntentState::Expired)
            );
            let after = db
                .fetch_prot_store_intent(held_intent)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                (after.user_id, after.state),
                (None, v0::ProtStoreIntentState::Used)
            );
            assert_eq!(stored(&db, &theirs.id).await, theirs);
            assert_eq!(db.sum_held_prot_store(&gone).await.unwrap(), 0);
            assert!(db
                .fetch_open_prot_store_intents(&gone, NOW)
                .await
                .unwrap()
                .is_empty());

            // Again: nothing of the user's is left to change
            db.unlink_prot_store_user(&gone).await.unwrap();
            assert_eq!(
                stored(&db, &credited.id).await.version,
                credited.version + 1
            );
        });
    }

    /// N2: an unlink between a move's read and its write bumps the version,
    /// so the move gets Conflict; the re-plan sees no user (a no-buyer
    /// refund), and the stored row ends unlinked. Control (28): let the
    /// unlink skip the version bump and the stale move writes the user back.
    #[tokio::test]
    async fn unlink_racing_a_move_stays_unlinked() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(14);
            let id = apple(14);
            let seeded = store_credit(&db, &id, &buyer, 2_600, NOW - DAY).await;

            // The engine reads the row and plans a clawback for its live buyer
            let read = stored(&db, &id).await;
            let event = revoke(NOW, true);
            let plan = plan_store_move(Some(&read), &event, 0);
            let stale = build_store_move(Some(&read), &seeded, &event, &plan, 0, NOW).unwrap();

            // ...and the account is deleted before it writes
            db.unlink_prot_store_user(&buyer).await.unwrap();
            assert_eq!(
                db.apply_store_purchase_move(&stale).await.unwrap(),
                ProtStoreMoveOutcome::Conflict
            );
            assert_eq!(entry(&db, &prot_store_key_clawback(&id, 1)).await, None);

            // The re-plan: the row has no user, so no buyer
            let (answer, row) = run_move(&db, &seeded, &revoke(NOW, false), NOW).await;
            assert_eq!(answer, ProtStoreAnswer::Revoked);
            let row = row.unwrap();
            assert_eq!(row.user_id, None);
            assert_eq!(stored(&db, &id).await.user_id, None);
            assert_eq!(entry(&db, &prot_store_key_clawback(&id, 1)).await, None);
        });
    }

    /// Audits 3+4: a refund of a credited row whose buyer is gone records the
    /// generation (reason "no_buyer") and posts nothing (S5's forfeit already
    /// took the wallet)
    #[tokio::test]
    async fn no_buyer_refund_records_a_generation() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(15);
            let id = apple(15);
            let seeded = store_credit(&db, &id, &buyer, 2_600, NOW - DAY).await;
            db.unlink_prot_store_user(&buyer).await.unwrap();

            let (answer, row) = run_move(&db, &seeded, &revoke(NOW, false), NOW).await;
            assert_eq!(answer, ProtStoreAnswer::Revoked);
            let row = row.unwrap();
            assert_eq!(
                (row.state, row.refund_gen),
                (v0::ProtStoreState::Revoked, 1)
            );
            assert_eq!(row.refunds.len(), 1);
            assert_eq!(row.refunds[0].reason.as_deref(), Some("no_buyer"));
            assert_eq!((row.refunds[0].clawed, row.refunds[0].shortfall), (0, 0));
            assert_eq!(entry(&db, &prot_store_key_clawback(&id, 1)).await, None);
            // Only the purchase row
            assert_eq!(db.fetch_prot_entries_by_order(&id).await.unwrap().len(), 1);
            assert_eq!(wallet(&db, &buyer).await, 2_600);
        });
    }

    /// N2 for every bookkeeping write: each bumps the version, so a move
    /// planned before it misses its CAS
    #[tokio::test]
    async fn bookkeeping_bumps_the_version_and_a_stale_move_conflicts() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let buyer = user(17);
            let id = play(17);
            let row = store_credit(&db, &id, &buyer, 2_600, NOW - 2 * DAY).await;
            let mut version = row.version;

            assert!(db
                .set_prot_store_needs_action(&id, "play_unconsumed_24h", NOW)
                .await
                .unwrap());
            // The same kind again changes nothing
            assert!(!db
                .set_prot_store_needs_action(&id, "play_unconsumed_24h", NOW)
                .await
                .unwrap());
            version += 1;
            assert_eq!(stored(&db, &id).await.version, version);
            assert!(db
                .claim_prot_store_alert(&id, "play_unconsumed_24h")
                .await
                .unwrap());
            version += 1;
            let listed = db.fetch_prot_store_needs_action(100).await.unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].version, version);

            // A move planned on the copy before the bookkeeping
            let event = revoke(NOW, true);
            let plan = plan_store_move(Some(&row), &event, 0);
            let stale = build_store_move(Some(&row), &row, &event, &plan, 0, NOW).unwrap();
            assert_eq!(
                db.apply_store_purchase_move(&stale).await.unwrap(),
                ProtStoreMoveOutcome::Conflict
            );

            // Consuming clears the unconsumed work item, not another kind
            assert!(db
                .mark_prot_store_consumed(&id, version, NOW)
                .await
                .unwrap());
            version += 1;
            let consumed = stored(&db, &id).await;
            assert_eq!((consumed.needs_action, consumed.version), (None, version));
            assert!(db
                .set_prot_store_needs_action(&id, "chargeback_review", NOW + 1)
                .await
                .unwrap());
            assert!(!db
                .clear_prot_store_needs_action(&id, "reversed_unpaid", NOW + 2)
                .await
                .unwrap());
            assert!(db
                .clear_prot_store_needs_action(&id, "chargeback_review", NOW + 2)
                .await
                .unwrap());
            version += 2;
            let cleared = stored(&db, &id).await;
            assert_eq!(
                (cleared.needs_action, cleared.version, cleared.updated_at),
                (None, version, NOW + 2)
            );
            assert!(db
                .fetch_prot_store_needs_action(100)
                .await
                .unwrap()
                .is_empty());

            // An Apple row has nothing to consume
            let apple_row = store_credit(&db, &apple(17), &buyer, 1_000, NOW).await;
            assert!(!db
                .mark_prot_store_consumed(&apple_row.id, apple_row.version, NOW)
                .await
                .unwrap());
            assert_eq!(stored(&db, &apple_row.id).await, apple_row);
        });
    }

    #[tokio::test]
    async fn alert_claim_has_one_winner() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let id = play(18);
            let row = store_credit(&db, &id, &user(18), 2_600, NOW).await;

            let claims =
                join_all((0..20).map(|_| db.claim_prot_store_alert(&id, "unbound_play"))).await;
            let won = claims
                .iter()
                .filter(|claim| matches!(claim, Ok(true)))
                .count();
            assert_eq!(won, 1, "{claims:?}");
            assert!(claims.iter().all(Result::is_ok));
            let after = stored(&db, &id).await;
            assert_eq!(after.alerted, vec!["unbound_play".to_string()]);
            assert_eq!(after.version, row.version + 1);
            assert_ne!(after.updated_at, row.updated_at);

            assert!(db
                .claim_prot_store_alert(&id, "play_unconsumed_24h")
                .await
                .unwrap());
            assert!(!db
                .claim_prot_store_alert(&apple(18), "unbound_play")
                .await
                .unwrap());
        });
    }

    #[tokio::test]
    async fn cursor_cas_has_one_winner() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let cursor = |value: &str| ProtStoreCursor {
                id: crate::PROT_STORE_CURSOR_APPLE.to_string(),
                cursor: value.to_string(),
                version: 7,
                updated_at: NOW,
            };

            let inserts = join_all((0..20).map(|i| {
                let db = &db;
                let next = cursor(&format!("{}", 1_000 + i));
                async move { db.put_prot_store_cursor(&next, None).await }
            }))
            .await;
            assert_eq!(
                inserts.iter().filter(|put| matches!(put, Ok(true))).count(),
                1,
                "{inserts:?}"
            );
            assert!(inserts.iter().all(Result::is_ok));
            let first = db
                .fetch_prot_store_cursor(crate::PROT_STORE_CURSOR_APPLE)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first.version, 0);

            let moves = join_all((0..20).map(|i| {
                let db = &db;
                let next = cursor(&format!("{}", 2_000 + i));
                async move { db.put_prot_store_cursor(&next, Some(0)).await }
            }))
            .await;
            assert_eq!(
                moves.iter().filter(|put| matches!(put, Ok(true))).count(),
                1,
                "{moves:?}"
            );
            let second = db
                .fetch_prot_store_cursor(crate::PROT_STORE_CURSOR_APPLE)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(second.version, 1);
            assert!(second.cursor.starts_with('2'));

            // A replica still on version 0 loses
            assert!(!db
                .put_prot_store_cursor(&cursor("3000"), Some(0))
                .await
                .unwrap());
            assert!(db
                .fetch_prot_store_cursor(crate::PROT_STORE_CURSOR_PLAY)
                .await
                .unwrap()
                .is_none());
        });
    }

    /// The intent methods (7.5, 9.3, 12.1, 16 steps 6 and 8)
    #[tokio::test]
    async fn store_intents_open_expire_cancel_and_purge() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let owner = user(19);
            let other = user(20);
            let open = intent(
                "01INTS6L1C0000000000000191",
                Some(&owner),
                v0::ProtStoreIntentState::Open,
            );
            let due = ProtStoreIntent {
                expires_at: NOW - 1,
                ..intent(
                    "01INTS6L1C0000000000000192",
                    Some(&owner),
                    v0::ProtStoreIntentState::Open,
                )
            };
            let used = ProtStoreIntent {
                expires_at: NOW - 40 * DAY,
                purchase_id: Some(apple(19)),
                ..intent(
                    "01INTS6L1C0000000000000193",
                    Some(&owner),
                    v0::ProtStoreIntentState::Used,
                )
            };
            let stale = ProtStoreIntent {
                expires_at: NOW - 40 * DAY,
                ..intent(
                    "01INTS6L1C0000000000000194",
                    Some(&other),
                    v0::ProtStoreIntentState::Expired,
                )
            };
            for issued in [&open, &due, &used, &stale] {
                db.insert_prot_store_intent(issued).await.unwrap();
            }

            // The token is unique
            let clash = ProtStoreIntent {
                id: "01INTS6L1C0000000000000199".to_string(),
                ..open.clone()
            };
            assert!(db.insert_prot_store_intent(&clash).await.is_err());
            assert_eq!(db.fetch_prot_store_intent(&clash.id).await.unwrap(), None);
            assert_eq!(
                db.fetch_prot_store_intent_by_token(&open.token)
                    .await
                    .unwrap(),
                Some(open.clone())
            );

            // Only unexpired Open intents count against the cap
            assert_eq!(
                db.fetch_open_prot_store_intents(&owner, NOW).await.unwrap(),
                vec![open.clone()]
            );
            assert_eq!(db.expire_prot_store_intents(NOW, 500).await.unwrap(), 1);
            assert_eq!(
                db.fetch_prot_store_intent(&due.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .state,
                v0::ProtStoreIntentState::Expired
            );
            assert_eq!(db.expire_prot_store_intents(NOW, 500).await.unwrap(), 0);

            // Cancel: only the owner's, Open → Expired; reported, never moved, after
            assert_eq!(
                db.cancel_prot_store_intent(&open.id, &other).await.unwrap(),
                None
            );
            assert_eq!(
                db.cancel_prot_store_intent("01INTS6L1C0000000000000000", &owner)
                    .await
                    .unwrap(),
                None
            );
            let cancelled = db
                .cancel_prot_store_intent(&open.id, &owner)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(cancelled.state, v0::ProtStoreIntentState::Expired);
            assert_eq!(
                db.cancel_prot_store_intent(&used.id, &owner)
                    .await
                    .unwrap()
                    .unwrap()
                    .state,
                v0::ProtStoreIntentState::Used
            );
            assert!(db
                .fetch_open_prot_store_intents(&owner, NOW)
                .await
                .unwrap()
                .is_empty());

            // The 30-day purge: Expired, no purchase, expired before the cutoff
            assert_eq!(
                db.delete_stale_prot_store_intents(NOW - 30 * DAY, 500)
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(db.fetch_prot_store_intent(&stale.id).await.unwrap(), None);
            assert!(db
                .fetch_prot_store_intent(&used.id)
                .await
                .unwrap()
                .is_some());
            assert!(db.fetch_prot_store_intent(&due.id).await.unwrap().is_some());
            assert_eq!(
                db.delete_stale_prot_store_intents(NOW - 30 * DAY, 500)
                    .await
                    .unwrap(),
                0
            );
        });
    }

    /// The cap and reconcile reads: Held and Sandbox sums, Held rows by store
    #[tokio::test]
    async fn store_sums_and_lists_read_their_rows() {
        database_test!(|db| async move {
            install_indexes(&db).await;
            let tester = user(21);
            let hold = |intent_id: &str| {
                ProtStoreEvent::Seen(ProtStoreVerdict::Hold {
                    user_id: tester.clone(),
                    intent_id: intent_id.to_string(),
                })
            };
            for (n, intent_id) in [
                (211_u64, "01INTS6L1C0000000000000211"),
                (212, "01INTS6L1C0000000000000212"),
            ] {
                db.insert_prot_store_intent(&intent(
                    intent_id,
                    Some(&tester),
                    v0::ProtStoreIntentState::Open,
                ))
                .await
                .unwrap();
                let seeded = seed(&apple(n), v0::ProtStore::Apple, 500);
                run_move(&db, &seeded, &hold(intent_id), NOW + n as i64).await;
            }
            let sandbox = format!("apple:sandbox:{}", 3_000_000_000_000_000_u64 + 21);
            store_credit(&db, &sandbox, &tester, 1_000, NOW).await;
            store_credit(&db, &apple(213), &tester, 2_600, NOW).await;

            assert_eq!(db.sum_held_prot_store(&tester).await.unwrap(), 1_000);
            assert_eq!(db.sum_sandbox_prot_store(&tester).await.unwrap(), 1_000);
            let held = db
                .fetch_prot_store_purchases_by_state(
                    v0::ProtStore::Apple,
                    v0::ProtStoreState::Held,
                    100,
                )
                .await
                .unwrap();
            assert_eq!(
                held.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
                vec![apple(211), apple(212)]
            );
            assert_eq!(
                db.fetch_prot_store_purchases_by_state(
                    v0::ProtStore::Apple,
                    v0::ProtStoreState::Held,
                    1
                )
                .await
                .unwrap()
                .len(),
                1
            );
            assert!(db
                .fetch_prot_store_purchases_by_state(
                    v0::ProtStore::Play,
                    v0::ProtStoreState::Held,
                    100
                )
                .await
                .unwrap()
                .is_empty());

            // Held → Credited when unpaused: the Held rows leave both sums
            for n in [211_u64, 212] {
                let (answer, _) = run_move(
                    &db,
                    &seed(&apple(n), v0::ProtStore::Apple, 500),
                    &ProtStoreEvent::Unpause { buyer_live: true },
                    NOW + DAY,
                )
                .await;
                assert_eq!(answer, ProtStoreAnswer::Credited);
            }
            assert_eq!(db.sum_held_prot_store(&tester).await.unwrap(), 0);
            assert_eq!(wallet(&db, &tester).await, 1_000 + 2_600 + 1_000);
        });
    }

    // --- the Reference lock order -----------------------------------------------

    /// What the lock-order racers share
    struct LockRace {
        rules: ProtTankRules,
        tank_id: String,
        goal_id: String,
    }

    const LOCK_RACERS: usize = 50;
    const LOCK_TANK: &str = "01TANKS6L1C0000000000LOCK1";
    const LOCK_PLEDGE_GOAL: &str = "01GOALS6L1C0000000000LOCK2";

    /// One racer of `store_lock_order_never_deadlocks`. Store moves take the
    /// ledger maps then intents then purchases; contribute and pledge take
    /// the ledger maps then purchases; held_purchase_prot takes the ledger
    /// then purchases; the unlink takes intents then purchases; the other
    /// store methods take one store map each.
    async fn lock_racer(db: Database, race: Arc<LockRace>, kind: usize, i: usize) {
        let n = i as u64;
        let buyer = user(500 + (i % 5) as u32);
        match kind {
            // A store credit through an intent, then its refund (the move
            // holds prot_pledges and prot_goals for the drain either way)
            0 => {
                let id = apple(5_000 + n);
                let row = store_credit(&db, &id, &buyer, 100, NOW - DAY).await;
                run_move(&db, &row, &revoke(NOW + i as i64, true), NOW).await;
            }
            1 => {
                let amount = race.rules.min_contribution;
                db.contribute_prot(&ProtContributeInput {
                    rules: race.rules.clone(),
                    ..contribute_input(&user(600), &race.tank_id, amount, &format!("lock-{i}"))
                })
                .await
                .unwrap();
            }
            2 => {
                let amount = race.rules.min_contribution;
                db.pledge_prot(&ProtPledgeInput {
                    rules: race.rules.clone(),
                    ..pledge_input(&user(601), &race.goal_id, amount, &format!("lock-{i}"))
                })
                .await
                .unwrap();
            }
            3 => {
                db.clawback_prot_purchase(
                    &user(602),
                    &format!("01ORDS6L1C00000000000{i:05}"),
                    10,
                    NOW,
                )
                .await
                .unwrap();
            }
            4 => {
                db.held_purchase_prot(&buyer, NOW - 72 * HOUR)
                    .await
                    .unwrap();
            }
            // The unlink of an account with rows and intents of its own
            5 => {
                db.unlink_prot_store_user(&user(700 + (i % 3) as u32))
                    .await
                    .unwrap();
            }
            6 => {
                db.expire_prot_store_intents(NOW, 10).await.unwrap();
                db.delete_stale_prot_store_intents(NOW, 10).await.unwrap();
                db.fetch_open_prot_store_intents(&buyer, NOW).await.unwrap();
            }
            _ => {
                let id = apple(5_000 + n);
                db.set_prot_store_needs_action(&id, "chargeback_review", NOW)
                    .await
                    .unwrap();
                db.claim_prot_store_alert(&id, "chargeback_review")
                    .await
                    .unwrap();
                db.sum_unconsumed_play_prot(&buyer, NOW).await.unwrap();
            }
        }
    }

    const LOCK_KINDS: usize = 8;

    /// The S6 Reference lock order (2.3): 50 tasks each of a store credit
    /// and refund (with a pledge drain), S5b's `contribute_prot` and
    /// `pledge_prot` (which now take `prot_store_purchases` last), S5b's
    /// `clawback_prot_purchase`, `held_purchase_prot`, the unlink (intents
    /// then purchases) and the intent and bookkeeping methods. A cycle hangs
    /// it and the timeout fails it. Controls (28 + the W1 orchestrator):
    /// take `prot_store_purchases` before `prot_ledger` in the store move, or
    /// take purchases before intents in the unlink, and it times out
    /// (timing-dependent: repeated passes of a control are inconclusive).
    ///
    /// A ReferenceDb of its own (no database connection, the same under
    /// either `TEST_DB`), on a multi-threaded runtime: on a current-thread
    /// runtime a Reference method never yields between two uncontended
    /// `lock().await`s, so no cycle could form.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn store_lock_order_never_deadlocks() {
        let db = Database::Reference(ReferenceDb::default());
        let race = Arc::new(LockRace {
            rules: rules(),
            tank_id: LOCK_TANK.to_string(),
            goal_id: LOCK_PLEDGE_GOAL.to_string(),
        });

        // A funded contributor and pledger, Stripe-style purchases to claw
        // back, and the unlinked accounts' rows and intents
        insert_tank(&db, LOCK_TANK, "01CHANS6L1C0000000000LOCK1").await;
        insert_goal(&db, &goal(LOCK_PLEDGE_GOAL, 100_000_000, 0)).await;
        adjust(
            &db,
            &user(600),
            "lock-contributor",
            1_000_000,
            NOW - 5 * DAY,
        )
        .await;
        adjust(&db, &user(601), "lock-pledger", 1_000_000, NOW - 5 * DAY).await;
        for i in 0..LOCK_RACERS {
            let order = format!("01ORDS6L1C00000000000{i:05}");
            db.apply_prot_posting(&ProtPosting {
                key: crate::prot_key_purchase(&order),
                kind: v0::ProtEntryKind::Purchase,
                debit: crate::PROT_SYS_ISSUED.to_string(),
                credit: prot_user_account(&user(602)),
                amount: ProtAmount::Exact(10),
                debit_floor: 0,
                actor: crate::PROT_ACTOR_PAYMENTS.to_string(),
                reference: ProtRef {
                    order_id: Some(order.clone()),
                    ..Default::default()
                },
                reason: None,
                created_at: NOW - 5 * DAY,
            })
            .await
            .unwrap();
        }
        for u in 0..3 {
            let gone = user(700 + u);
            store_credit(&db, &apple(7_000 + u64::from(u)), &gone, 100, NOW - DAY).await;
            db.insert_prot_store_intent(&intent(
                &format!("01INTS6L1C0000000000LOCK{u}"),
                Some(&gone),
                v0::ProtStoreIntentState::Open,
            ))
            .await
            .unwrap();
        }

        let (open_gate, gate) = futures::channel::oneshot::channel::<()>();
        let gate = futures::FutureExt::shared(gate);
        let mut handles = Vec::with_capacity(LOCK_RACERS * LOCK_KINDS);
        for i in 0..LOCK_RACERS {
            for kind in 0..LOCK_KINDS {
                let db = db.clone();
                let gate = gate.clone();
                let race = race.clone();
                handles.push(tokio::spawn(async move {
                    gate.await.ok();
                    lock_racer(db, race, kind, i).await;
                }));
            }
        }
        open_gate.send(()).expect("the racers hold the gate");

        let joined = tokio::time::timeout(Duration::from_secs(30), join_all(handles))
            .await
            .expect("the Reference store lock order deadlocked: a racer never finished");
        for result in joined {
            result.expect("a racer panicked");
        }

        // Every refund drained what it could and every row is settled
        for i in 0..LOCK_RACERS as u64 {
            let row = stored(&db, &apple(5_000 + i)).await;
            assert_eq!(
                (row.state, row.refund_gen),
                (v0::ProtStoreState::Revoked, 1)
            );
            assert!(entry(&db, &prot_store_key_clawback(&row.id, 1))
                .await
                .is_some());
        }
        for u in 0..3 {
            assert_eq!(stored(&db, &apple(7_000 + u)).await.user_id, None);
        }
    }
}
