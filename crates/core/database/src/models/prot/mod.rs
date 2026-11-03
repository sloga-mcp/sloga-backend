//! Prot: the ledger (S5a) and the fuel tanks, goals and pledges (S5b).
//!
//! REFERENCE LOCK ORDER (complete): every Reference path that holds more
//! than one collection lock takes them in this order:
//!
//! `channels -> messages -> channel_entitlements -> servers ->
//!  server_members -> channel_seat_lists -> channel_seats -> mls_groups ->
//!  mls_commits -> mls_join_intents -> e2ee_identities -> e2ee_queue ->
//!  cipher_memberships -> prot_ledger -> prot_accounts -> prot_pledges ->
//!  prot_goals -> prot_tanks -> prot_runtime -> prot_notices ->
//!  prot_contributor_prefs`
//!
//! S1's documented order (`protected_channels/ops/reference.rs`) comes
//! first, then S5a's (`cipher_memberships -> prot_ledger -> prot_accounts`,
//! `ops/reference.rs`), then the S5b maps. Every S1 path and every S5a
//! method takes a subsequence of this order, so none of them changes. A
//! path takes every map it needs at its start, in this order, holds them to
//! its end and never re-takes one; it never calls a trait method while
//! holding one (the mutex is not re-entrant), and every check runs before
//! its first mutation. `tests::reference_lock_order_never_deadlocks` races
//! the paths that share these maps on one channel.

mod entitlement;
mod lifecycle;
mod model;
mod ops;
mod tank_model;
mod tanks;

pub use lifecycle::*;
pub use model::*;
pub use ops::AbstractProtLedger;
pub use tank_model::*;
pub use tanks::AbstractProtTanks;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use futures::FutureExt;
    use iso8601_timestamp::Timestamp;
    use revolt_models::v0;
    use revolt_result::{ErrorType, Result};

    use crate::{
        prot_key_admin, prot_key_clawback, prot_next_day, prot_user_account, prot_utc_day, Channel,
        CipherMembership, Database, Member, MemberCompositeKey, ProtAmount, ProtContributeInput,
        ProtGoal, ProtLaunchInput, ProtPledgeInput, ProtPosting, ProtRef, ProtTankRules,
        ReferenceDb, SeatListBody, SeatListSubmission, Server, PROT_SYS_ADJUST,
    };

    const DAY: i64 = 86_400_000;
    /// 2026-10-01T13:00:00Z (11 hours left in the UTC day)
    const NOW: i64 = 1_790_812_800_000 + 13 * 3_600_000;
    /// Tasks per racing method
    const RACERS: usize = 50;

    const SERVER: &str = "01HZX000000000000000005000";
    const CHANNEL: &str = "01J9Z3K4M5N6P7Q8R9S0T50000";
    const OWNER: &str = "01HZX000000000000000005001";
    const OWNER_DEVICE: &str = "00112233445566778899aabbccddeeff";
    /// Pledges half the launch goal
    const BACKER: &str = "01HZX000000000000000005002";
    /// Pledges the other half, then loses its Cipher upgrade: the clawback
    /// drains that held pledge
    const CLAWER: &str = "01HZX000000000000000005003";
    /// Pledges into the tank's upgrade goal
    const PLEDGER: &str = "01HZX000000000000000005004";
    /// Tops the tank up
    const CONTRIBUTOR: &str = "01HZX000000000000000005005";
    const ADMIN: &str = "01ADMIN0000000000000000000";
    const BASE_ORDER: &str = "01LOCKBASE0000000000000000";
    const UPGRADE_ORDER: &str = "01LOCKUPGRADE0000000000000";

    /// The racing methods. Capture, Close, Apply and Pledge are the ones that
    /// hold both `prot_goals` and `prot_tanks`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum Racer {
        Capture,
        Contribute,
        Close,
        Burn,
        Apply,
        PutSeatList,
        Pledge,
        Clawback,
    }

    const RACE_ORDER: [Racer; 8] = [
        Racer::Capture,
        Racer::Contribute,
        Racer::Close,
        Racer::Burn,
        Racer::Apply,
        Racer::PutSeatList,
        Racer::Pledge,
        Racer::Clawback,
    ];

    /// What every racer needs to know about the seeded channel
    struct Race {
        tank_id: String,
        launch_goal_id: String,
        upgrade_goal_id: String,
        /// The day the launch-day capture leaves as `next_burn_day`
        tomorrow: String,
        rules: ProtTankRules,
    }

    fn rules() -> ProtTankRules {
        ProtTankRules {
            self_serve: true,
            burning: true,
            deletion_enabled: true,
            ..ProtTankRules::from_config(&revolt_config::ProtectionFeatures::default())
                .expect("the default Prot config is valid")
        }
    }

    fn timestamp(ms: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(iso8601_timestamp::Duration::milliseconds(ms))
            .unwrap()
    }

    /// A canonical unpadded b64 encoding of 64 bytes (the DB layer only
    /// checks the encoding; signatures are verified by the route)
    fn signature(n: i64) -> String {
        let alphabet = b"BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        format!(
            "{}{}",
            alphabet[n as usize % alphabet.len()] as char,
            "A".repeat(85)
        )
    }

    /// A list seating only the owner, signed by the owner's device
    fn seat_list(version: i64, issued_at: i64) -> SeatListSubmission {
        SeatListSubmission {
            body: SeatListBody {
                channel_id: CHANNEL.to_string(),
                version,
                device_cap: 5,
                issued_at,
                signer_user_id: OWNER.to_string(),
                signer_device_id: OWNER_DEVICE.to_string(),
                seats: vec![OWNER.to_string()],
            }
            .build()
            .unwrap(),
            signature: signature(issued_at),
            signer_device_id: OWNER_DEVICE.to_string(),
            handover: None,
        }
    }

    /// An admin adjustment of `user_id`'s wallet (a debit when negative)
    fn admin_posting(user_id: &str, nonce: &str, amount: i64) -> ProtPosting {
        let wallet = prot_user_account(user_id);
        let (debit, credit, n) = if amount >= 0 {
            (PROT_SYS_ADJUST.to_string(), wallet, amount)
        } else {
            (wallet, PROT_SYS_ADJUST.to_string(), -amount)
        };
        ProtPosting {
            key: prot_key_admin(ADMIN, nonce),
            kind: v0::ProtEntryKind::AdminAdjust,
            debit,
            credit,
            amount: ProtAmount::Exact(n),
            debit_floor: 0,
            actor: ADMIN.to_string(),
            reference: ProtRef::default(),
            reason: Some("lock order test".to_string()),
            created_at: NOW - 1_000,
        }
    }

    fn membership(tier: v0::CipherTier, prot_grant: u32, orders: &[&str]) -> CipherMembership {
        CipherMembership {
            user_id: CLAWER.to_string(),
            number: 77,
            tier,
            prot_grant,
            orders: orders.iter().map(|order| order.to_string()).collect(),
            disputed_orders: vec![],
            granted_at: NOW - 10_000,
            revoked_at: None,
            revoke_reason: None,
            prot_posted_at: None,
            version: 0,
        }
    }

    /// A 10-slot, 30-day launch goal of `SERVER`
    fn launch_goal(rules: &ProtTankRules) -> ProtGoal {
        let daily_cost = rules.daily_cost(10).expect("10 is a slot tier");
        ProtGoal {
            id: ulid::Ulid::new().to_string(),
            kind: v0::ProtGoalKind::Launch,
            server_id: SERVER.to_string(),
            channel_id: None,
            tank_id: None,
            created_by: OWNER.to_string(),
            create_nonce: "lock-order-launch".to_string(),
            slots: 10,
            days: Some(30),
            daily_cost,
            base_daily_cost: None,
            target_prot: 30 * daily_cost,
            pledged_total: 0,
            state: v0::ProtGoalState::Funding,
            deadline_at: NOW + 30 * DAY,
            funded_at: None,
            launch_deadline_at: None,
            launched_at: None,
            closed_at: None,
            refund7_done: false,
            open_key: Some(format!("launch:{SERVER}")),
            version: 0,
            created_at: NOW - 5_000,
            updated_at: NOW - 5_000,
        }
    }

    /// A 10 -> 25 slot upgrade goal of the tank, funded by ten 50 Prot pledges
    fn upgrade_goal(tank_id: &str, rules: &ProtTankRules) -> ProtGoal {
        ProtGoal {
            id: ulid::Ulid::new().to_string(),
            kind: v0::ProtGoalKind::Upgrade,
            server_id: SERVER.to_string(),
            channel_id: Some(CHANNEL.to_string()),
            tank_id: Some(tank_id.to_string()),
            created_by: OWNER.to_string(),
            create_nonce: "lock-order-upgrade".to_string(),
            slots: 25,
            days: None,
            daily_cost: rules.daily_cost(25).expect("25 is a slot tier"),
            base_daily_cost: rules.daily_cost(10),
            target_prot: 500,
            pledged_total: 0,
            state: v0::ProtGoalState::Funding,
            deadline_at: NOW + 30 * DAY,
            funded_at: None,
            launch_deadline_at: None,
            launched_at: None,
            closed_at: None,
            refund7_done: false,
            open_key: Some(format!("upgrade:{tank_id}")),
            version: 0,
            created_at: NOW - 1_000,
            updated_at: NOW - 1_000,
        }
    }

    fn pledge_input(
        user_id: &str,
        goal_id: &str,
        amount: i64,
        nonce: &str,
        rules: &ProtTankRules,
    ) -> ProtPledgeInput {
        ProtPledgeInput {
            user_id: user_id.to_string(),
            goal_id: goal_id.to_string(),
            amount,
            nonce: nonce.to_string(),
            rules: rules.clone(),
            now: NOW,
        }
    }

    /// One protected channel whose tank is Launching: its launch goal is
    /// Launching with two held pledges (one of them the clawback's target),
    /// the tank has an open upgrade goal, the owner signed the genesis list,
    /// and three wallets are funded for the racers
    #[allow(clippy::disallowed_methods)]
    async fn seed(db: &Database) -> Race {
        let rules = rules();

        let server: Server = serde_json::from_value(serde_json::json!({
            "_id": SERVER,
            "owner": OWNER,
            "name": "lock order",
            "channels": [CHANNEL],
            "default_permissions": 0,
        }))
        .unwrap();
        db.insert_server(&server).await.unwrap();
        for user in [OWNER, BACKER, CLAWER, PLEDGER, CONTRIBUTOR] {
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
            name: "lock order".to_string(),
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

        for (user, amount) in [(BACKER, 600), (PLEDGER, 5_000), (CONTRIBUTOR, 5_000)] {
            db.apply_prot_posting(&admin_posting(user, &format!("seed-{user}"), amount))
                .await
                .unwrap();
        }

        // The clawer's wallet: founding grant, then a Cipher upgrade (33,000)
        let mut m = membership(v0::CipherTier::T99, 16_500, &[BASE_ORDER]);
        assert!(db.insert_cipher_membership(&m).await.unwrap());
        db.sync_cipher_prot(CLAWER, NOW - 9_000).await.unwrap();
        m.tier = v0::CipherTier::T149;
        m.prot_grant = 33_000;
        m.orders.push(UPGRADE_ORDER.to_string());
        assert!(db.update_cipher_membership_if_version(&m, 1).await.unwrap());
        db.sync_cipher_prot(CLAWER, NOW - 8_000).await.unwrap();

        // Launch goal: half from the clawer, half from the backer
        let goal = db.create_prot_goal(&launch_goal(&rules)).await.unwrap();
        let half = goal.target_prot / 2;
        db.pledge_prot(&pledge_input(
            CLAWER,
            &goal.id,
            half,
            "launch-clawer",
            &rules,
        ))
        .await
        .unwrap();
        let funded = db
            .pledge_prot(&pledge_input(
                BACKER,
                &goal.id,
                goal.target_prot - half,
                "launch-backer",
                &rules,
            ))
            .await
            .unwrap();
        assert_eq!(funded.goal.state, v0::ProtGoalState::Funded);

        // The clawer spends the rest of its wallet, then the upgrade is
        // refunded: the clawback can only be recovered from the held pledge
        let rest = db
            .fetch_prot_account(&prot_user_account(CLAWER))
            .await
            .unwrap()
            .expect("the clawer has a wallet")
            .balance;
        db.apply_prot_posting(&admin_posting(CLAWER, "spend-clawer", -rest))
            .await
            .unwrap();
        m.tier = v0::CipherTier::T99;
        m.prot_grant = 16_500;
        m.orders = vec![BASE_ORDER.to_string()];
        assert!(db.update_cipher_membership_if_version(&m, 3).await.unwrap());

        let (goal, tank) = db
            .launch_prot_goal(&ProtLaunchInput {
                goal_id: goal.id.clone(),
                channel_id: CHANNEL.to_string(),
                owner_id: OWNER.to_string(),
                rules: rules.clone(),
                now: NOW,
            })
            .await
            .unwrap();
        assert_eq!(goal.state, v0::ProtGoalState::Launching);
        assert_eq!(tank.stage, v0::ProtTankStage::Launching);

        // Protect landed, capture not run yet (what on_protect_landed races)
        db.protect_channel(CHANNEL, &seat_list(1, NOW), timestamp(NOW))
            .await
            .unwrap();

        let upgrade = db
            .create_prot_goal(&upgrade_goal(&tank.id, &rules))
            .await
            .unwrap();

        Race {
            tank_id: tank.id,
            launch_goal_id: goal.id,
            upgrade_goal_id: upgrade.id,
            tomorrow: prot_next_day(&prot_utc_day(NOW)).unwrap(),
            rules,
        }
    }

    /// One call of `racer`. Ok(true) when the call wrote what it is for
    /// (the capture, the landed list, a new pledge); refusals are expected
    /// while the state moves under the race.
    async fn race(db: &Database, racer: Racer, i: i64, seeded: &Race) -> Result<bool> {
        let rules = &seeded.rules;
        match racer {
            Racer::Capture => db
                .capture_launch_pledges(CHANNEL, NOW, rules)
                .await
                .map(|tank| tank.is_some()),
            Racer::Contribute => db
                .contribute_prot(&ProtContributeInput {
                    user_id: CONTRIBUTOR.to_string(),
                    tank_id: seeded.tank_id.clone(),
                    amount: 50,
                    nonce: format!("contribute-{i}"),
                    rules: rules.clone(),
                    now: NOW,
                })
                .await
                .map(|_| true),
            Racer::Close => db
                .close_prot_goal(&seeded.launch_goal_id, v0::ProtGoalState::Cancelled, NOW)
                .await
                .map(|_| true),
            Racer::Burn => db
                .burn_prot_tank_day(&seeded.tank_id, &seeded.tomorrow, None, NOW, rules)
                .await
                .map(|_| true),
            Racer::Apply => db
                .apply_prot_upgrade_goal(&seeded.upgrade_goal_id, NOW, rules)
                .await
                .map(|tank| tank.is_some()),
            Racer::PutSeatList => db
                .put_seat_list(CHANNEL, &seat_list(2, NOW + 1 + i), true, timestamp(NOW))
                .await
                .map(|outcome| !outcome.unchanged),
            Racer::Pledge => db
                .pledge_prot(&pledge_input(
                    PLEDGER,
                    &seeded.upgrade_goal_id,
                    50,
                    &format!("pledge-{i}"),
                    rules,
                ))
                .await
                .map(|outcome| !outcome.already_applied),
            Racer::Clawback => db
                .clawback_cipher_prot(CLAWER, UPGRADE_ORDER, NOW)
                .await
                .map(|_| true),
        }
    }

    /// The Reference driver's complete lock order (S5b contracts 2.4): 50
    /// tasks each of a top-up, a burn, an S1 seat-list PUT, a Cipher clawback
    /// that drains a held pledge, and the methods that hold both
    /// `prot_goals` and `prot_tanks` (capture, close from Launching, upgrade
    /// apply, a pledge into the tank's upgrade goal), all on one channel. A
    /// lock-order cycle hangs it, and the timeout fails it.
    ///
    /// Runs on a ReferenceDb of its own (no database connection, so it is
    /// the same under either `TEST_DB`). The runtime is multi-threaded on
    /// purpose: on a current-thread runtime a Reference method never yields
    /// between two uncontended `lock().await`s, so the racers would run one
    /// after another and no cycle could ever form.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn reference_lock_order_never_deadlocks() {
        let db = Database::Reference(ReferenceDb::default());
        let race_state = Arc::new(seed(&db).await);

        // Every racer waits at the gate, so they all start together
        let (open_gate, gate) = futures::channel::oneshot::channel::<()>();
        let gate = gate.shared();
        let mut handles = Vec::with_capacity(RACERS * RACE_ORDER.len());
        for i in 0..RACERS as i64 {
            for racer in RACE_ORDER {
                let db = db.clone();
                let gate = gate.clone();
                let race_state = race_state.clone();
                handles.push(tokio::spawn(async move {
                    gate.await.ok();
                    (racer, race(&db, racer, i, &race_state).await)
                }));
            }
        }
        open_gate.send(()).expect("the racers hold the gate");

        let joined =
            tokio::time::timeout(Duration::from_secs(30), futures::future::join_all(handles))
                .await
                .expect("the Reference lock order deadlocked: a racer never finished");

        let mut outcomes: HashMap<Racer, Vec<Result<bool>>> = HashMap::new();
        for result in joined {
            let (racer, outcome) = result.expect("a racer panicked");
            outcomes.entry(racer).or_default().push(outcome);
        }
        for racer in RACE_ORDER {
            assert_eq!(outcomes[&racer].len(), RACERS, "{racer:?}");
        }

        // The capture is the only racer that can end a protected Launching
        // goal: it ran its write path exactly once, and no close got through
        let captures = &outcomes[&Racer::Capture];
        assert!(captures.iter().all(Result::is_ok), "{captures:?}");
        let captured = captures
            .iter()
            .filter(|outcome| matches!(outcome, Ok(true)))
            .count();
        assert_eq!(captured, 1, "{captures:?}");
        let closes = &outcomes[&Racer::Close];
        assert!(closes.iter().all(Result::is_err), "{closes:?}");

        let burns = &outcomes[&Racer::Burn];
        assert!(burns.iter().all(Result::is_ok), "{burns:?}");
        let clawbacks = &outcomes[&Racer::Clawback];
        assert!(clawbacks.iter().all(Result::is_ok), "{clawbacks:?}");
        let pledges = &outcomes[&Racer::Pledge];
        assert!(
            pledges.iter().any(|outcome| matches!(outcome, Ok(true))),
            "{pledges:?}"
        );

        // Racing version-2 lists: one lands, the others lose the version
        let puts = &outcomes[&Racer::PutSeatList];
        let landed = puts
            .iter()
            .filter(|outcome| matches!(outcome, Ok(true)))
            .count();
        assert_eq!(landed, 1, "{puts:?}");
        for outcome in puts {
            if let Err(error) = outcome {
                assert!(
                    matches!(error.error_type, ErrorType::FailedValidation { .. }),
                    "a racing PUT must lose on the version, got {error:?}"
                );
            }
        }

        let goal = db
            .fetch_prot_goal(&race_state.launch_goal_id)
            .await
            .unwrap()
            .expect("the launch goal");
        assert_eq!(goal.state, v0::ProtGoalState::Launched);
        let tank = db
            .fetch_prot_tank(&race_state.tank_id)
            .await
            .unwrap()
            .expect("the tank");
        assert_ne!(tank.stage, v0::ProtTankStage::Launching);
        assert!(tank.launched_at.is_some());
        assert!(db
            .fetch_prot_entry_by_key(&prot_key_clawback(UPGRADE_ORDER))
            .await
            .unwrap()
            .is_some());
        let list = db.fetch_seat_list(CHANNEL).await.unwrap().expect("a list");
        assert_eq!(list.version, 2);
    }
}
