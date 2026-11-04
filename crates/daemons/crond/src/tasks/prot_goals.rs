//! Goal sweep (S5b), every 10 minutes while enabled (self_serve not required, so goals created while it was on
//! still end): Funding past deadline → Expired (returns); Funded Launch past launch_deadline_at → Cancelled
//! (returns); Launching: channel protected → capture (backstop), else past launch_deadline_at → Cancelled
//! (entitlement + tank removed); Launched + due → 7-day returns; Funded Upgrade → apply, or past its
//! launch_deadline_at (funded_at + launch_window_days) → Cancelled with full returns (8.7 exit).
//! Each step claims its goal by a state CAS (the scheduled_messages.rs pattern), so replicas never double-act.
//!
//! Every step is `revolt_payments::engine::tank::goals_tick` (contracts
//! 13.2), which loads the Prot rules itself; this task runs it every
//! [`TICK`] while `[features.boosts.protection] enabled` is on.
//!
//! While Prot is off each tick only logs at debug level and sleeps. Goals keep
//! their state meanwhile (no pledge comes back while Prot is off); the first
//! tick after it is back on ends every goal whose date passed. The task never
//! returns: `cron_task_wrapper` treats a returning task as a failure and
//! restarts it every 60 s with an error each time, so an early return is not
//! a no-op (prune_expired_boosts.rs).
//!
//! The config is frozen into the process at first access, so turning Prot on
//! or off takes a crond restart.

use std::{future::Future, time::Duration};

use log::debug;
use revolt_database::{Database, AMQP};
use revolt_payments::engine;
use revolt_result::Result;
use tokio::time::sleep;

/// Time between sweeps
const TICK: Duration = Duration::from_secs(10 * 60);

/// What one tick did
#[derive(Debug, PartialEq, Eq)]
enum Tick {
    /// Prot is off; nothing ran
    Off,
    /// The engine swept the due goals (it logs what it did, and every
    /// failure, itself)
    Swept,
}

/// Run the sweep every [`TICK`]. Never returns: while Prot is off each tick
/// is a no-op.
pub async fn task(db: Database, _: AMQP) -> Result<()> {
    let db = &db;
    run(TICK, move || async move {
        let config = revolt_config::config().await;
        let enabled = config.features.boosts.protection.enabled;
        sweep(db, enabled, revolt_database::now_ms()).await;
    })
    .await
}

/// Call `tick`, then sleep `period`, forever. Nothing leaves the loop: the
/// tick handles its own failures.
async fn run<F, Fut>(period: Duration, mut tick: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    loop {
        tick().await;
        sleep(period).await;
    }
}

/// One tick: gate on `enabled`, then hand the due goals to the engine
async fn sweep(db: &Database, enabled: bool, now_ms: i64) -> Tick {
    if !enabled {
        debug!("Prot goal sweep skipped, Prot is off");
        return Tick::Off;
    }

    engine::tank::goals_tick(db, now_ms).await;
    Tick::Swept
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::HashMap;

    use iso8601_timestamp::Timestamp;
    use revolt_config::ProtectionFeatures;
    use revolt_database::test_teardown::TestDatabaseGuard;
    use revolt_database::{
        prot_hold_account, prot_key_admin, prot_key_pledge_return, prot_key_tier,
        prot_tank_account, prot_upgrade_goal_price, prot_user_account, Channel, DatabaseInfo,
        Member, MemberCompositeKey, ProtAmount, ProtGoal, ProtLaunchInput, ProtPledge,
        ProtPledgeInput, ProtPosting, ProtRef, ProtTankRules, SeatListBody, SeatListSubmission,
        Server, User, PROT_SYS_ADJUST,
    };
    use revolt_models::v0;

    use super::*;

    const DAY: i64 = 86_400_000;

    const SERVER: &str = "01HZX000000000000000006000";
    const CHANNEL: &str = "01J9Z3K4M5N6P7Q8R9S0T60000";
    const OWNER: &str = "01HZX000000000000000006001";
    const OWNER_DEVICE: &str = "00112233445566778899aabbccddeeff";
    const BACKER_A: &str = "01HZX000000000000000006002";
    const BACKER_B: &str = "01HZX000000000000000006003";
    const ADMIN: &str = "01ADMIN0000000000000000000";

    /// What every test wallet starts with
    const WALLET: i64 = 5_000;
    /// Backer B's share of the upgrade goal; backer A pledges the rest
    const SHARE_B: i64 = 300;

    const SOURCE: &str = include_str!("prot_goals.rs");

    /// The upgrade goal and the tank it upgrades
    struct Seeded {
        goal_id: String,
        tank_id: String,
    }

    /// The code of the item that starts at `head`, up to its closing brace
    /// at column 0, without comment lines
    fn item(head: &str) -> String {
        let start = SOURCE
            .find(head)
            .unwrap_or_else(|| panic!("`{head}` is in the file"));
        let len = SOURCE[start..]
            .find("\n}\n")
            .unwrap_or_else(|| panic!("`{head}` is closed"));
        SOURCE[start..start + len]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A fresh test database on the driver `TEST_DB` names (which must be
    /// set: `DatabaseInfo::Test` panics without it rather than reach the
    /// configured database). Migrated, so MongoDB has the Prot ledger and
    /// tank indexes. The guard drops it when the test ends, panics included.
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

    /// The rules the seed writes with (the sweep loads its own)
    fn rules() -> ProtTankRules {
        ProtTankRules {
            self_serve: true,
            burning: true,
            deletion_enabled: true,
            ..ProtTankRules::from_config(&ProtectionFeatures::default())
                .expect("the default Prot config is valid")
        }
    }

    fn timestamp(ms: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(iso8601_timestamp::Duration::milliseconds(ms))
            .unwrap()
    }

    /// The genesis list seating only the owner (the database checks the
    /// signature's encoding only; the route verifies it)
    fn seat_list(issued_at: i64) -> SeatListSubmission {
        SeatListSubmission {
            body: SeatListBody {
                channel_id: CHANNEL.to_string(),
                version: 1,
                device_cap: 5,
                issued_at,
                signer_user_id: OWNER.to_string(),
                signer_device_id: OWNER_DEVICE.to_string(),
                seats: vec![OWNER.to_string()],
            }
            .build()
            .unwrap(),
            signature: format!("B{}", "A".repeat(85)),
            signer_device_id: OWNER_DEVICE.to_string(),
            handover: None,
        }
    }

    /// [`WALLET`] Prot in `user_id`'s wallet that is not held (an admin
    /// credit, D17)
    fn admin_credit(user_id: &str, at: i64) -> ProtPosting {
        ProtPosting {
            key: prot_key_admin(ADMIN, &format!("seed-{user_id}")),
            kind: v0::ProtEntryKind::AdminAdjust,
            debit: PROT_SYS_ADJUST.to_string(),
            credit: prot_user_account(user_id),
            amount: ProtAmount::Exact(WALLET),
            debit_floor: 0,
            actor: ADMIN.to_string(),
            reference: ProtRef::default(),
            reason: Some("goal sweep test".to_string()),
            created_at: at,
        }
    }

    fn pledge_input(user_id: &str, goal_id: &str, amount: i64, now: i64) -> ProtPledgeInput {
        ProtPledgeInput {
            user_id: user_id.to_string(),
            goal_id: goal_id.to_string(),
            amount,
            nonce: format!("sweep-{user_id}"),
            rules: rules(),
            now,
        }
    }

    async fn balance(db: &Database, account_id: &str) -> i64 {
        db.fetch_prot_account(account_id)
            .await
            .unwrap()
            .map_or(0, |account| account.balance)
    }

    async fn goal(db: &Database, goal_id: &str) -> ProtGoal {
        db.fetch_prot_goal(goal_id)
            .await
            .unwrap()
            .expect("the goal exists")
    }

    async fn pledges(db: &Database, goal_id: &str) -> Vec<ProtPledge> {
        let pledges = db.fetch_prot_pledges_by_goal(goal_id).await.unwrap();
        assert_eq!(pledges.len(), 2, "{pledges:?}");
        pledges
    }

    /// A launched 10-slot channel whose owner funded the launch goal alone
    /// (so its 7-day return owes nobody), with a 10 -> 25 slot upgrade goal
    /// that two backers funded at `funded_at`
    #[allow(clippy::disallowed_methods)]
    async fn seed(db: &Database, funded_at: i64) -> Seeded {
        let rules = rules();
        let start = funded_at - 60_000;

        for user in [OWNER, BACKER_A, BACKER_B] {
            db.insert_user(&User {
                id: user.to_string(),
                username: format!("sweep{}", &user[user.len() - 4..]),
                discriminator: "0001".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
            db.apply_prot_posting(&admin_credit(user, start))
                .await
                .unwrap();
        }

        let server: Server = serde_json::from_value(serde_json::json!({
            "_id": SERVER,
            "owner": OWNER,
            "name": "goal sweep",
            "channels": [CHANNEL],
            "default_permissions": 0,
        }))
        .unwrap();
        db.insert_server(&server).await.unwrap();
        for user in [OWNER, BACKER_A, BACKER_B] {
            db.insert_or_merge_member(&Member {
                id: MemberCompositeKey {
                    server: SERVER.to_string(),
                    user: user.to_string(),
                },
                ..Default::default()
            })
            .await
            .unwrap();
        }
        db.insert_channel(&Channel::TextChannel {
            id: CHANNEL.to_string(),
            server: SERVER.to_string(),
            name: "goal sweep".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: HashMap::new(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected: false,
        })
        .await
        .unwrap();

        // The launch: the owner funds a 30-day goal, launches it, protects
        // the channel and the capture makes the tank Active
        let daily_cost = rules.daily_cost(10).expect("10 is a slot tier");
        let launch = db
            .create_prot_goal(&ProtGoal {
                id: ulid::Ulid::new().to_string(),
                kind: v0::ProtGoalKind::Launch,
                server_id: SERVER.to_string(),
                channel_id: None,
                tank_id: None,
                created_by: OWNER.to_string(),
                create_nonce: "sweep-launch".to_string(),
                slots: 10,
                days: Some(30),
                daily_cost,
                base_daily_cost: None,
                target_prot: 30 * daily_cost,
                pledged_total: 0,
                state: v0::ProtGoalState::Funding,
                deadline_at: start + 30 * DAY,
                funded_at: None,
                launch_deadline_at: None,
                launched_at: None,
                closed_at: None,
                refund7_done: false,
                open_key: Some(format!("launch:{SERVER}")),
                version: 0,
                created_at: start,
                updated_at: start,
            })
            .await
            .unwrap();
        let funded = db
            .pledge_prot(&pledge_input(
                OWNER,
                &launch.id,
                launch.target_prot,
                start + 1_000,
            ))
            .await
            .unwrap();
        assert_eq!(funded.goal.state, v0::ProtGoalState::Funded);
        db.launch_prot_goal(&ProtLaunchInput {
            goal_id: launch.id.clone(),
            channel_id: CHANNEL.to_string(),
            owner_id: OWNER.to_string(),
            rules: rules.clone(),
            now: start + 2_000,
        })
        .await
        .unwrap();
        db.protect_channel(CHANNEL, &seat_list(start + 3_000), timestamp(start + 3_000))
            .await
            .unwrap();
        let tank = db
            .capture_launch_pledges(CHANNEL, start + 4_000, &rules)
            .await
            .unwrap()
            .expect("the capture ran");
        assert_eq!(tank.stage, v0::ProtTankStage::Active);

        // The upgrade goal, priced as 8.7 prices it, funded by both backers
        let new_cost = rules.daily_cost(25).expect("25 is a slot tier");
        let tank_balance = balance(db, &prot_tank_account(&tank.id)).await;
        let target = prot_upgrade_goal_price(tank.daily_cost, new_cost, tank_balance);
        assert!(target > SHARE_B + rules.min_contribution, "target {target}");
        let upgrade = db
            .create_prot_goal(&ProtGoal {
                id: ulid::Ulid::new().to_string(),
                kind: v0::ProtGoalKind::Upgrade,
                channel_id: Some(CHANNEL.to_string()),
                tank_id: Some(tank.id.clone()),
                create_nonce: "sweep-upgrade".to_string(),
                slots: 25,
                days: None,
                daily_cost: new_cost,
                base_daily_cost: Some(tank.daily_cost),
                target_prot: target,
                open_key: Some(format!("upgrade:{}", tank.id)),
                created_at: start + 5_000,
                updated_at: start + 5_000,
                // The rest as a new goal has it
                ..launch
            })
            .await
            .unwrap();
        db.pledge_prot(&pledge_input(
            BACKER_A,
            &upgrade.id,
            target - SHARE_B,
            funded_at - 1_000,
        ))
        .await
        .unwrap();
        let funded = db
            .pledge_prot(&pledge_input(BACKER_B, &upgrade.id, SHARE_B, funded_at))
            .await
            .unwrap();
        assert!(funded.funded_now);
        assert_eq!(funded.goal.state, v0::ProtGoalState::Funded);
        assert_eq!(funded.goal.funded_at, Some(funded_at));
        assert_eq!(
            funded.goal.launch_deadline_at,
            Some(funded_at + i64::from(rules.launch_window_days) * DAY)
        );

        Seeded {
            goal_id: upgrade.id,
            tank_id: tank.id,
        }
    }

    /// The upgrade goal is Cancelled, every backer has the whole pledge back
    /// (one `pledge-return:` row each, out of the hold), and the tank kept
    /// its tier with no `tier:` row for the goal
    async fn assert_upgrade_cancelled(db: &Database, seeded: &Seeded) {
        let goal = goal(db, &seeded.goal_id).await;
        assert_eq!(goal.state, v0::ProtGoalState::Cancelled, "{goal:?}");
        assert_eq!(goal.open_key, None, "{goal:?}");
        assert!(goal.closed_at.is_some(), "{goal:?}");

        for pledge in pledges(db, &seeded.goal_id).await {
            assert_eq!(pledge.state, v0::ProtPledgeState::Returned, "{pledge:?}");
            assert_eq!(pledge.remaining, 0, "{pledge:?}");
            let row = db
                .fetch_prot_entry_by_key(&prot_key_pledge_return(&pledge.id))
                .await
                .unwrap()
                .expect("a pledge-return row");
            assert_eq!(row.amount, pledge.amount, "{row:?}");
            assert_eq!(row.debit, prot_hold_account(&seeded.goal_id), "{row:?}");
            assert_eq!(row.credit, prot_user_account(&pledge.user_id), "{row:?}");
        }
        for user in [BACKER_A, BACKER_B] {
            assert_eq!(
                balance(db, &prot_user_account(user)).await,
                WALLET,
                "{user}"
            );
        }
        assert_eq!(balance(db, &prot_hold_account(&seeded.goal_id)).await, 0);

        let tank = db
            .fetch_prot_tank(&seeded.tank_id)
            .await
            .unwrap()
            .expect("the tank exists");
        assert_eq!(tank.slot_tier, 10, "{tank:?}");
        let tier_key = prot_key_tier(&seeded.tank_id, &format!("goal-{}", seeded.goal_id));
        assert!(db
            .fetch_prot_entry_by_key(&tier_key)
            .await
            .unwrap()
            .is_none());
    }

    /// The loop runs tick after tick and never returns, with Prot off (each
    /// tick a no-op) and on (each tick the engine sweep, here over an empty
    /// database)
    #[tokio::test]
    async fn the_goal_sweep_loop_never_returns() {
        let db = Database::Reference(Default::default());

        for enabled in [false, true] {
            let ticks = Cell::new(0_u32);
            let (db, counter) = (&db, &ticks);
            let outcome = tokio::time::timeout(
                Duration::from_millis(500),
                run(Duration::from_millis(10), move || async move {
                    let expected = if enabled { Tick::Swept } else { Tick::Off };
                    assert_eq!(
                        sweep(db, enabled, revolt_database::now_ms()).await,
                        expected
                    );
                    counter.set(counter.get() + 1);
                }),
            )
            .await;

            assert!(
                outcome.is_err(),
                "enabled = {enabled}: the sweep loop returned: {outcome:?}"
            );
            assert!(
                ticks.get() >= 3,
                "enabled = {enabled}: only {} ticks in 500 ms",
                ticks.get()
            );
        }
    }

    /// The shape the wrapper needs, pinned in the text: `task` reads the
    /// flag on every tick and hands it to `sweep`, and `run` is a
    /// sleep-in-loop with no way out (prune_expired_boosts.rs). An early
    /// `return Ok(())` when Prot is disabled, in either function, fails it.
    #[test]
    fn the_goal_task_is_a_sleep_in_loop() {
        let task = item("pub async fn task(");
        let run = item("async fn run<");

        assert!(
            task.contains("config.features.boosts.protection.enabled;"),
            "{task}"
        );
        assert!(
            task.contains("sweep(db, enabled, revolt_database::now_ms()).await;"),
            "{task}"
        );
        assert!(task.contains("run(TICK,"), "{task}");
        assert!(run.contains("loop {"), "{run}");
        assert!(run.contains("tick().await;"), "{run}");
        assert!(run.contains("sleep(period).await;"), "{run}");

        for (name, code) in [("task", &task), ("run", &run)] {
            for exit in ["return", "break", "continue", "?", "if "] {
                assert!(
                    !code.contains(exit),
                    "`{exit}` in {name}: the sweep loop must never end\n{code}"
                );
            }
        }

        assert_eq!(TICK, Duration::from_secs(10 * 60));
    }

    /// 8.7's exit, through the task's tick: a Funded upgrade goal that was
    /// not applied within launch_window_days of its funding (7 by default)
    /// is cancelled with every pledge returned in full, so pledges are never
    /// held forever. A second tick changes nothing.
    #[tokio::test]
    async fn funded_upgrade_goal_exits_after_seven_days() {
        let (db, _guard) = migrated_test_db().await;
        let now = revolt_database::now_ms();
        let seeded = seed(&db, now - 8 * DAY).await;

        assert_eq!(sweep(&db, true, now).await, Tick::Swept);
        assert_upgrade_cancelled(&db, &seeded).await;

        assert_eq!(sweep(&db, true, now + 1_000).await, Tick::Swept);
        assert_upgrade_cancelled(&db, &seeded).await;
    }

    /// The other side of the exit: inside its window the sweep applies the
    /// goal (the backstop for the apply after the funding pledge), so the
    /// exit is the date, not every Funded upgrade goal
    #[tokio::test]
    async fn funded_upgrade_goal_inside_its_window_is_applied() {
        let (db, _guard) = migrated_test_db().await;
        let now = revolt_database::now_ms();
        let seeded = seed(&db, now - 60_000).await;
        let target = goal(&db, &seeded.goal_id).await.target_prot;

        assert_eq!(sweep(&db, true, now).await, Tick::Swept);

        let goal = goal(&db, &seeded.goal_id).await;
        assert_eq!(goal.state, v0::ProtGoalState::Applied, "{goal:?}");
        for pledge in pledges(&db, &seeded.goal_id).await {
            assert_eq!(pledge.state, v0::ProtPledgeState::Captured, "{pledge:?}");
            assert_eq!(pledge.remaining, 0, "{pledge:?}");
        }
        let tank = db
            .fetch_prot_tank(&seeded.tank_id)
            .await
            .unwrap()
            .expect("the tank exists");
        assert_eq!(tank.slot_tier, 25, "{tank:?}");
        assert_eq!(
            balance(&db, &prot_user_account(BACKER_A)).await,
            WALLET - (target - SHARE_B)
        );
        assert_eq!(
            balance(&db, &prot_user_account(BACKER_B)).await,
            WALLET - SHARE_B
        );
        assert_eq!(balance(&db, &prot_hold_account(&seeded.goal_id)).await, 0);
    }

    /// While Prot is off nothing is swept: the overdue goal stays Funded and
    /// its pledges stay held. The control for the exit test, through the
    /// gate the task applies on every tick.
    #[tokio::test]
    async fn prot_off_leaves_due_goals_alone() {
        let (db, _guard) = migrated_test_db().await;
        let now = revolt_database::now_ms();
        let seeded = seed(&db, now - 8 * DAY).await;
        let before = goal(&db, &seeded.goal_id).await;

        assert_eq!(sweep(&db, false, now).await, Tick::Off);

        let after = goal(&db, &seeded.goal_id).await;
        assert_eq!(after.state, v0::ProtGoalState::Funded, "{after:?}");
        assert_eq!(after.version, before.version, "{after:?}");
        for pledge in pledges(&db, &seeded.goal_id).await {
            assert_eq!(pledge.state, v0::ProtPledgeState::Held, "{pledge:?}");
            assert_eq!(pledge.remaining, pledge.amount, "{pledge:?}");
        }
        assert_eq!(
            balance(&db, &prot_user_account(BACKER_A)).await,
            WALLET - (before.target_prot - SHARE_B)
        );
        assert_eq!(
            balance(&db, &prot_user_account(BACKER_B)).await,
            WALLET - SHARE_B
        );
        assert_eq!(
            balance(&db, &prot_hold_account(&seeded.goal_id)).await,
            before.target_prot
        );
    }
}
