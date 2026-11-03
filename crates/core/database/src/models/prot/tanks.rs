//! Prot fuel tanks, goals and pledges (S5b, contracts section 5.2): the
//! driver trait. Every write is ONE transaction (MongoDB, S5a's
//! `run_prot_transaction`) or ONE lock section (Reference, the lock order in
//! `prot/mod.rs`); every transaction that touches a tank writes the tank
//! document (`version += 1`), so the tank is the serialization point between
//! burns, contributions, tier changes, settlements and terminations.
//!
//! Return values the contracts leave open, pinned here for both drivers:
//! - `burn_prot_tank_day`: a Grace day whose clamped amount is 0 (the tank
//!   sits at its floor, 7.0 "Advance") is `EnteredGrace { entry: None }`, never
//!   `NotDue`, so the clock's catch-up keeps going day by day.
//! - `apply_prot_upgrade_goal`: `Some(tank)` only when the goal was Applied;
//!   `None` when there was nothing to do (not a Funded Upgrade goal, the tank
//!   still Launching) and when the goal was closed `Cancelled` with full
//!   returns instead (8.7).
//! - `withdraw_prot_pledge`, `close_prot_goal`, `capture_launch_pledges`,
//!   the upgrade apply and settlement: a pledge leaving its hold ends with
//!   `remaining = 0`.

pub mod mongodb;
pub mod reference;

use revolt_models::v0;
use revolt_result::Result;

use crate::{
    ProtBurnOutcome, ProtContributeInput, ProtContributeOutcome, ProtContributorPref, ProtGoal,
    ProtGoalCloseOutcome, ProtLaunchInput, ProtLedgerEntry, ProtNoticeKind, ProtPledge,
    ProtPledgeInput, ProtPledgeOutcome, ProtPurgeCounts, ProtRuntime, ProtSettleCause,
    ProtSettlement, ProtTank, ProtTankRules, ProtTermination, ProtTierChangeInput,
};

#[async_trait]
pub trait AbstractProtTanks: Sync + Send {
    // ---- reads (no transaction, no replica-set check)
    async fn fetch_prot_tank(&self, tank_id: &str) -> Result<Option<ProtTank>>;
    async fn fetch_prot_tank_by_channel(&self, channel_id: &str) -> Result<Option<ProtTank>>; // target_key
    async fn fetch_prot_tanks_by_server(&self, server_id: &str) -> Result<Vec<ProtTank>>; // any stage, by _id
    async fn fetch_prot_goal(&self, goal_id: &str) -> Result<Option<ProtGoal>>;
    async fn fetch_open_prot_goals_by_server(&self, server_id: &str) -> Result<Vec<ProtGoal>>; // PROT_OPEN_GOAL_STATES
    async fn fetch_open_prot_goals_by_tank(&self, tank_id: &str) -> Result<Vec<ProtGoal>>;
    async fn fetch_prot_pledge(&self, pledge_id: &str) -> Result<Option<ProtPledge>>;
    async fn fetch_prot_pledges_by_goal(&self, goal_id: &str) -> Result<Vec<ProtPledge>>; // oldest first
    async fn fetch_held_prot_pledges_by_user(&self, user_id: &str) -> Result<Vec<ProtPledge>>; // newest first
    /// Rows with ref.tank_id == tank_id, oldest first (_id ascending)
    async fn fetch_prot_entries_by_tank(&self, tank_id: &str) -> Result<Vec<ProtLedgerEntry>>;
    async fn fetch_prot_contributor_prefs(
        &self,
        server_id: &str,
        user_ids: &[String],
    ) -> Result<Vec<ProtContributorPref>>;
    async fn fetch_prot_runtime(&self) -> Result<Option<ProtRuntime>>;
    /// S2 seam (19.2)
    ///
    /// Net Prot `user_id` put into `tank_id` with created_at >= since_ms: Contribution rows (debit user:{uid}) +
    /// PledgeCapture rows of the user's pledges - LaunchReturn rows of those pledges; 0 if none. Index
    /// prot_ledger_tank_debit_created + prot_pledges_user_state.
    async fn recent_contribution(&self, user_id: &str, tank_id: &str, since_ms: i64)
        -> Result<i64>;
    /// S2 seam (19.2)
    ///
    /// The user with the largest such net total since since_ms, skipping hidden contributors (prefs of the tank's
    /// server) and deleted users; ties -> the user whose first counted row is oldest; None if nobody qualifies.
    async fn top_contributor(&self, tank_id: &str, since_ms: i64) -> Result<Option<String>>;
    /// stage in {Active, Grace} and next_burn_day <= today, by (next_burn_day, _id), at most `limit`
    async fn fetch_prot_tanks_due_burn(&self, today: &str, limit: i64) -> Result<Vec<ProtTank>>;
    /// stage in `stages`, `_id > after_id`, by _id, at most `limit` (paging for the clock's stage pass)
    async fn fetch_prot_tanks_by_stage(
        &self,
        stages: &[v0::ProtTankStage],
        after_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ProtTank>>;
    /// stage in {Deleted, Terminated} and purge_passes < 2 (7.1 step 7, NIT 22), by _id, at most `limit`
    async fn fetch_prot_tanks_to_purge(
        &self,
        after_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ProtTank>>;
    /// Funding with deadline_at <= now; Funded/Launching with launch_deadline_at <= now; Launching (any
    /// time, for the capture backstop); Launched Launch goals with !refund7_done and launched_at +
    /// launch_seat_window_days <= now; Funded Upgrade goals (apply, or cancel past launch_deadline_at, 8.7). By _id,
    /// at most `limit`.
    async fn fetch_prot_goals_due(
        &self,
        now: i64,
        launch_seat_window_ms: i64,
        limit: i64,
    ) -> Result<Vec<ProtGoal>>;

    // ---- writes (each ONE transaction; ensure_replica_set first on Mongo)
    async fn set_prot_contributor_pref(
        &self,
        server_id: &str,
        user_id: &str,
        hidden: bool,
        now: i64,
    ) -> Result<()>;
    async fn contribute_prot(&self, input: &ProtContributeInput) -> Result<ProtContributeOutcome>; // 8.8
    async fn create_prot_goal(&self, goal: &ProtGoal) -> Result<ProtGoal>; // 8.2
    async fn pledge_prot(&self, input: &ProtPledgeInput) -> Result<ProtPledgeOutcome>; // 8.3
    async fn withdraw_prot_pledge(
        &self,
        pledge_id: &str,
        user_id: &str,
        now: i64,
        cutoff_ms: i64,
    ) -> Result<ProtPledge>; // 8.4
    async fn close_prot_goal(
        &self,
        goal_id: &str,
        to: v0::ProtGoalState,
        now: i64,
    ) -> Result<ProtGoalCloseOutcome>; // 8.5
    async fn launch_prot_goal(&self, input: &ProtLaunchInput) -> Result<(ProtGoal, ProtTank)>; // 8.6
    async fn capture_launch_pledges(
        &self,
        channel_id: &str,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<Option<ProtTank>>; // 8.6
    async fn return_unseated_launch_pledges(
        &self,
        goal_id: &str,
        now: i64,
    ) -> Result<Vec<ProtLedgerEntry>>; // 8.6
    async fn apply_prot_upgrade_goal(
        &self,
        goal_id: &str,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<Option<ProtTank>>; // 8.7
    async fn change_prot_tier(&self, input: &ProtTierChangeInput) -> Result<ProtTank>; // 8.9
    async fn apply_pending_prot_tier(
        &self,
        tank_id: &str,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<Option<ProtTank>>;
    /// `paused` = runtime.burn_paused_at as the tick read it (7.0: NotDue unless the tank was shifted for it)
    async fn burn_prot_tank_day(
        &self,
        tank_id: &str,
        day: &str,
        paused: Option<i64>,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<ProtBurnOutcome>; // 7.2
    /// Inserts the notice row (`_id` = key); false when it exists. For Final, sets the tank's
    /// final_warning_at = now in the same transaction (CAS on warnings_epoch).
    async fn record_prot_notice(
        &self,
        tank_id: &str,
        epoch: u64,
        kind: ProtNoticeKind,
        delivered: bool,
        now: i64,
    ) -> Result<bool>;
    async fn set_prot_burn_paused(&self, at: i64) -> Result<bool>; // only when absent
    async fn clear_prot_burn_paused(&self, expected: i64) -> Result<bool>; // CAS on the value
    async fn shift_prot_tank_for_pause(
        &self,
        tank_id: &str,
        paused_at: i64,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<bool>; // 7.4
    async fn begin_prot_settlement(
        &self,
        tank_id: &str,
        cause: ProtSettleCause,
        now: i64,
    ) -> Result<Option<ProtTank>>; // 9.1
    async fn settle_prot_tank(&self, tank_id: &str, now: i64) -> Result<ProtSettlement>; // 9.2
    async fn terminate_prot_tank(
        &self,
        tank_id: &str,
        admin_id: &str,
        reason: &str,
        now: i64,
    ) -> Result<ProtTermination>; // 9.5
    async fn purge_protected_channel_content(&self, channel_id: &str) -> Result<ProtPurgeCounts>; // 6.5
    async fn mark_prot_tank_purged(&self, tank_id: &str, now: i64) -> Result<()>; // purge_passes += 1
}

/// Driver-agnostic tests: every `database_test!` here runs under BOTH
/// `TEST_DB=REFERENCE` and `TEST_DB=MONGODB` (never without `TEST_DB`: that
/// is production). Times are fixed epoch milliseconds from `DAY0`, so the
/// UTC days, the pro rata hours and the stored values are the same on both
/// drivers.
#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::future::Future;
    use std::pin::Pin;

    use iso8601_timestamp::{Duration, Timestamp};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use revolt_models::v0;
    use revolt_result::Result;

    use crate::{
        prot_hold_account, prot_key_admin, prot_key_burn, prot_key_forfeit_tank, prot_key_purchase,
        prot_key_tier, prot_key_writeoff, prot_next_day, prot_tank_account,
        prot_upgrade_goal_price, prot_user_account, prot_utc_day, Channel, Database,
        E2EEContentType, E2EEEnvelope, EncryptedPayload, Member, MemberCompositeKey, Message,
        MlsCommit, MlsGroup, MlsGroupKind, MlsJoinIntent, MlsMemberDevice, ProtAmount,
        ProtBurnOutcome, ProtContributeInput, ProtContributeOutcome, ProtGoal, ProtLaunchInput,
        ProtLedgerEntry, ProtNoticeKind, ProtPledgeInput, ProtPledgeOutcome, ProtPosting, ProtRef,
        ProtSettleCause, ProtTank, ProtTankRules, ProtTankTarget, ProtTierChangeInput, ReferenceDb,
        SeatListBody, SeatListSubmission, Server, User, E2EE_PROTOCOL_VERSION, PROT_ACTOR_PAYMENTS,
        PROT_OPEN_GOAL_STATES, PROT_SLOT_TIERS, PROT_SYS_ADJUST, PROT_SYS_BURNED, PROT_SYS_CLAWED,
        PROT_SYS_FORFEITED, PROT_SYS_ISSUED, PROT_SYS_WRITEOFF,
    };

    const DAY: i64 = 86_400_000;
    const HOUR: i64 = 3_600_000;
    /// 2026-10-01T00:00:00Z: day 0 of every scenario
    const DAY0: i64 = 1_790_812_800_000;

    const SERVER: &str = "01HZX000000000000000006000";
    const OTHER_SERVER: &str = "01HZX000000000000000006900";
    const CHANNEL: &str = "01J9Z3K4M5N6P7Q8R9S0T60000";
    const CHANNEL_2: &str = "01J9Z3K4M5N6P7Q8R9S0T60001";
    const OWNER: &str = "01HZX000000000000000006001";
    const A: &str = "01HZX000000000000000006002";
    const B: &str = "01HZX000000000000000006003";
    const C: &str = "01HZX000000000000000006004";
    /// Tops tanks up
    const D: &str = "01HZX000000000000000006005";
    const ADMIN: &str = "01ADMIN0000000000000000000";
    const OWNER_DEVICE: &str = "00112233445566778899aabbccddeeff";
    const USERS: [&str; 5] = [OWNER, A, B, C, D];
    const RACE_ITERATIONS: u32 = 50;
    /// At least 500 (contracts 5.3)
    const CONSERVATION_STEPS: usize = 520;

    fn at(day: i64, hour: i64) -> i64 {
        DAY0 + day * DAY + hour * HOUR
    }

    fn day(n: i64) -> String {
        prot_utc_day(at(n, 0))
    }

    fn timestamp(ms: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(Duration::milliseconds(ms))
            .unwrap()
    }

    fn channel_id(n: u32) -> String {
        format!("01J9Z3K4M5N6P7Q8R9S0T{n:05}")
    }

    fn user_id(n: u32) -> String {
        format!("01HZX0000000000000000{n:05}")
    }

    fn nonce() -> String {
        ulid::Ulid::new().to_string()
    }

    /// A structurally valid protected-channel message (S1 design 2.6): the
    /// insert guard refuses plaintext in a protected channel. `seed` varies
    /// the AEAD nonce; the client message id is a fresh ULID.
    fn ciphertext_message(channel_id: &str, author: &str, seed: u8) -> Message {
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

        let id = nonce();
        Message {
            nonce: Some(id.clone()),
            id,
            channel: channel_id.to_string(),
            author: author.to_string(),
            encrypted: Some(EncryptedPayload {
                v: EncryptedPayload::VERSION,
                group_id: "ab".repeat(32),
                epoch: 0,
                sender_device_id: "cd".repeat(16),
                nonce: STANDARD_NO_PAD.encode([seed; EncryptedPayload::NONCE_BYTES]),
                ciphertext: STANDARD_NO_PAD.encode([seed; EncryptedPayload::CIPHERTEXT_MIN_BYTES]),
                sig: STANDARD_NO_PAD.encode([seed; EncryptedPayload::SIG_BYTES]),
                franking: None,
            }),
            ..Default::default()
        }
    }

    /// The default rules with every switch on (contracts 8.0)
    fn rules() -> ProtTankRules {
        ProtTankRules {
            self_serve: true,
            burning: true,
            deletion_enabled: true,
            ..ProtTankRules::from_config(&revolt_config::ProtectionFeatures::default())
                .expect("the default Prot config is valid")
        }
    }

    fn is_error<T: std::fmt::Debug>(result: &Result<T>, expected: &str) -> bool {
        match result {
            Err(error) => format!("{:?}", error.error_type).starts_with(expected),
            Ok(_) => false,
        }
    }

    /// Install the Prot indexes of revisions 76 and 78 with the migration's
    /// own helpers (`database_test!` hands out an unmigrated database). The
    /// Reference driver enforces its unique keys in code.
    async fn setup(db: &Database) {
        match db {
            Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                for collection in crate::PROT_COLLECTIONS
                    .into_iter()
                    .chain(crate::PROT_TANK_COLLECTIONS)
                {
                    mongo.db().create_collection(collection).await.ok();
                }
                crate::create_prot_indexes(&mongo.db())
                    .await
                    .expect("failed to create the Prot ledger indexes");
                crate::create_prot_tank_indexes(&mongo.db())
                    .await
                    .expect("failed to create the Prot tank indexes");
            }
        }
    }

    async fn insert_member(db: &Database, server_id: &str, user_id: &str) {
        db.insert_or_merge_member(&Member {
            id: MemberCompositeKey {
                server: server_id.to_string(),
                user: user_id.to_string(),
            },
            ..Default::default()
        })
        .await
        .unwrap();
    }

    /// A server owned by OWNER with every test user as a member
    #[allow(clippy::disallowed_methods)]
    async fn insert_server(db: &Database, server_id: &str) {
        let server: Server = serde_json::from_value(serde_json::json!({
            "_id": server_id,
            "owner": OWNER,
            "name": "tanks",
            "channels": [],
            "default_permissions": 0,
        }))
        .unwrap();
        db.insert_server(&server).await.unwrap();
        for user in USERS {
            insert_member(db, server_id, user).await;
        }
    }

    #[allow(clippy::disallowed_methods)]
    async fn insert_channel(db: &Database, channel_id: &str, server_id: &str) {
        db.insert_channel(&Channel::TextChannel {
            id: channel_id.to_string(),
            server: server_id.to_string(),
            name: "tank".to_string(),
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
    }

    #[allow(clippy::disallowed_methods)]
    async fn insert_user(db: &Database, id: &str, flags: Option<i32>) {
        db.insert_user(&User {
            id: id.to_string(),
            username: format!("tank{}", &id[id.len() - 5..]),
            discriminator: "0001".to_string(),
            flags,
            ..Default::default()
        })
        .await
        .unwrap();
    }

    fn admin_posting(debit: String, credit: String, amount: i64, debit_floor: i64) -> ProtPosting {
        ProtPosting {
            key: prot_key_admin(ADMIN, &nonce()),
            kind: v0::ProtEntryKind::AdminAdjust,
            debit,
            credit,
            amount: ProtAmount::Exact(amount),
            debit_floor,
            actor: ADMIN.to_string(),
            reference: ProtRef::default(),
            reason: Some("tank test".to_string()),
            created_at: at(-30, 0),
        }
    }

    /// Prot in `user_id`'s wallet that is not held (an admin credit, D17)
    async fn fund(db: &Database, user_id: &str, amount: i64) {
        db.apply_prot_posting(&admin_posting(
            PROT_SYS_ADJUST.to_string(),
            prot_user_account(user_id),
            amount,
            0,
        ))
        .await
        .unwrap();
    }

    fn purchase(user_id: &str, order_id: &str, amount: i64, now: i64) -> ProtPosting {
        ProtPosting {
            key: prot_key_purchase(order_id),
            kind: v0::ProtEntryKind::Purchase,
            debit: PROT_SYS_ISSUED.to_string(),
            credit: prot_user_account(user_id),
            amount: ProtAmount::Exact(amount),
            debit_floor: 0,
            actor: PROT_ACTOR_PAYMENTS.to_string(),
            reference: ProtRef {
                order_id: Some(order_id.to_string()),
                ..Default::default()
            },
            reason: None,
            created_at: now,
        }
    }

    async fn balance(db: &Database, account_id: &str) -> i64 {
        db.fetch_prot_account(account_id)
            .await
            .unwrap()
            .map_or(0, |account| account.balance)
    }

    /// Move Prot between the tank and sys:adjust until the tank holds
    /// `target`: a test-only shortcut to a stage (these rows carry no
    /// ref.tank_id, so no scenario using it settles the tank)
    async fn set_tank_balance(db: &Database, tank_id: &str, target: i64) {
        let account = prot_tank_account(tank_id);
        let current = balance(db, &account).await;
        let posting = match current.cmp(&target) {
            std::cmp::Ordering::Equal => return,
            std::cmp::Ordering::Greater => admin_posting(
                account,
                PROT_SYS_ADJUST.to_string(),
                current - target,
                target.min(0),
            ),
            std::cmp::Ordering::Less => {
                admin_posting(PROT_SYS_ADJUST.to_string(), account, target - current, 0)
            }
        };
        db.apply_prot_posting(&posting).await.unwrap();
    }

    async fn tank(db: &Database, tank_id: &str) -> ProtTank {
        db.fetch_prot_tank(tank_id)
            .await
            .unwrap()
            .expect("the tank exists")
    }

    async fn goal(db: &Database, goal_id: &str) -> ProtGoal {
        db.fetch_prot_goal(goal_id)
            .await
            .unwrap()
            .expect("the goal exists")
    }

    async fn entitlement_state(
        db: &Database,
        channel_id: &str,
    ) -> Option<crate::ChannelEntitlementState> {
        db.fetch_channel_entitlement(channel_id)
            .await
            .unwrap()
            .map(|entitlement| entitlement.state)
    }

    fn channel_of(tank: &ProtTank) -> String {
        match &tank.target {
            ProtTankTarget::Channel { channel_id } => channel_id.clone(),
            ProtTankTarget::Server { .. } => panic!("a channel tank"),
        }
    }

    async fn row(db: &Database, key: &str) -> Option<ProtLedgerEntry> {
        db.fetch_prot_entry_by_key(key).await.unwrap()
    }

    async fn rows_of_kind(
        db: &Database,
        tank_id: &str,
        kind: v0::ProtEntryKind,
    ) -> Vec<ProtLedgerEntry> {
        db.fetch_prot_entries_by_tank(tank_id)
            .await
            .unwrap()
            .into_iter()
            .filter(|row| row.kind == kind)
            .collect()
    }

    /// Every row naming the account, read through the paged fetch
    async fn all_entries(db: &Database, account_id: &str) -> Vec<ProtLedgerEntry> {
        let mut rows: Vec<ProtLedgerEntry> = Vec::new();
        loop {
            let before = rows.last().map(|row| row.id.clone());
            let page = db
                .fetch_prot_entries_by_account(account_id, before.as_deref(), 100)
                .await
                .unwrap();
            let done = page.len() < 100;
            rows.extend(page);
            if done {
                return rows;
            }
        }
    }

    fn launch_goal(server_id: &str, slots: u32, target: i64, created_at: i64) -> ProtGoal {
        ProtGoal {
            id: nonce(),
            kind: v0::ProtGoalKind::Launch,
            server_id: server_id.to_string(),
            channel_id: None,
            tank_id: None,
            created_by: OWNER.to_string(),
            create_nonce: nonce(),
            slots,
            days: Some(30),
            daily_cost: rules().daily_cost(slots).expect("a slot tier"),
            base_daily_cost: None,
            target_prot: target,
            pledged_total: 0,
            state: v0::ProtGoalState::Funding,
            deadline_at: created_at + 30 * DAY,
            funded_at: None,
            launch_deadline_at: None,
            launched_at: None,
            closed_at: None,
            refund7_done: false,
            open_key: Some(format!("launch:{server_id}")),
            version: 0,
            created_at,
            updated_at: created_at,
        }
    }

    fn upgrade_goal(tank: &ProtTank, slots: u32, target: i64, created_at: i64) -> ProtGoal {
        ProtGoal {
            kind: v0::ProtGoalKind::Upgrade,
            server_id: tank.server_id.clone(),
            channel_id: Some(channel_of(tank)),
            tank_id: Some(tank.id.clone()),
            days: None,
            base_daily_cost: Some(tank.daily_cost),
            open_key: Some(format!("upgrade:{}", tank.id)),
            ..launch_goal(&tank.server_id, slots, target, created_at)
        }
    }

    async fn pledge(
        db: &Database,
        user_id: &str,
        goal_id: &str,
        amount: i64,
        now: i64,
    ) -> Result<ProtPledgeOutcome> {
        db.pledge_prot(&ProtPledgeInput {
            user_id: user_id.to_string(),
            goal_id: goal_id.to_string(),
            amount,
            nonce: nonce(),
            rules: rules(),
            now,
        })
        .await
    }

    async fn contribute(
        db: &Database,
        user_id: &str,
        tank_id: &str,
        amount: i64,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<ProtContributeOutcome> {
        db.contribute_prot(&ProtContributeInput {
            user_id: user_id.to_string(),
            tank_id: tank_id.to_string(),
            amount,
            nonce: nonce(),
            rules: rules.clone(),
            now,
        })
        .await
    }

    async fn change_tier(
        db: &Database,
        tank_id: &str,
        slots: u32,
        change_id: &str,
        now: i64,
    ) -> Result<ProtTank> {
        db.change_prot_tier(&ProtTierChangeInput {
            tank_id: tank_id.to_string(),
            slots,
            change_id: change_id.to_string(),
            rules: rules(),
            now,
        })
        .await
    }

    /// A canonical unpadded b64 encoding of 64 bytes (the DB layer only
    /// checks the encoding; signatures are verified by the route)
    fn signature(n: i64) -> String {
        let alphabet = b"BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        format!(
            "{}{}",
            alphabet[n.rem_euclid(alphabet.len() as i64) as usize] as char,
            "A".repeat(85)
        )
    }

    /// A list signed by the owner's device
    fn seat_list(
        channel_id: &str,
        version: i64,
        seats: &[&str],
        issued_at: i64,
    ) -> SeatListSubmission {
        let mut seats: Vec<String> = seats.iter().map(|seat| seat.to_string()).collect();
        seats.sort();
        seats.dedup();
        SeatListSubmission {
            body: SeatListBody {
                channel_id: channel_id.to_string(),
                version,
                device_cap: 5,
                issued_at,
                signer_user_id: OWNER.to_string(),
                signer_device_id: OWNER_DEVICE.to_string(),
                seats,
            }
            .build()
            .unwrap(),
            signature: signature(version),
            signer_device_id: OWNER_DEVICE.to_string(),
            handover: None,
        }
    }

    /// A Launching goal of `channel_id`: funded by `pledges`, launched one
    /// second before `at`, protect not landed yet
    async fn launching(
        db: &Database,
        server_id: &str,
        channel_id: &str,
        slots: u32,
        pledges: &[(&str, i64)],
        at: i64,
        rules: &ProtTankRules,
    ) -> (ProtGoal, ProtTank) {
        insert_channel(db, channel_id, server_id).await;
        let total: i64 = pledges.iter().map(|(_, amount)| amount).sum();
        let created = at - DAY;
        let goal = db
            .create_prot_goal(&launch_goal(server_id, slots, total, created))
            .await
            .unwrap();
        for (user, amount) in pledges {
            fund(db, user, *amount).await;
            pledge(db, user, &goal.id, *amount, created + 1_000)
                .await
                .unwrap();
        }
        db.launch_prot_goal(&ProtLaunchInput {
            goal_id: goal.id.clone(),
            channel_id: channel_id.to_string(),
            owner_id: OWNER.to_string(),
            rules: rules.clone(),
            now: at - 2_000,
        })
        .await
        .unwrap()
    }

    /// A launched tank of `channel_id`, funded by `pledges` and captured at
    /// `capture_at` (protect landed just before)
    async fn launched(
        db: &Database,
        server_id: &str,
        channel_id: &str,
        slots: u32,
        pledges: &[(&str, i64)],
        capture_at: i64,
        rules: &ProtTankRules,
    ) -> (ProtGoal, ProtTank) {
        let (goal, _) =
            launching(db, server_id, channel_id, slots, pledges, capture_at, rules).await;
        db.protect_channel(
            channel_id,
            &seat_list(channel_id, 1, &[OWNER], capture_at - 1_000),
            timestamp(capture_at - 1_000),
        )
        .await
        .unwrap();
        let tank = db
            .capture_launch_pledges(channel_id, capture_at, rules)
            .await
            .unwrap()
            .expect("the capture ran");
        (self::goal(db, &goal.id).await, tank)
    }

    /// The clock's burn of day `n`, one minute after its midnight
    async fn burn(db: &Database, tank_id: &str, n: i64, rules: &ProtTankRules) -> ProtBurnOutcome {
        db.burn_prot_tank_day(tank_id, &day(n), None, at(n, 0) + 60_000, rules)
            .await
            .unwrap()
    }

    /// A 10-slot tank of CHANNEL captured at day 0 13:00 (1,200 - 19 = 1,181)
    /// whose day-1 burn found 30: Grace at -10, exhausted at day 1's start
    async fn grace_tank(db: &Database, rules: &ProtTankRules) -> ProtTank {
        insert_server(db, SERVER).await;
        let (_, tank) = launched(
            db,
            SERVER,
            CHANNEL,
            10,
            &[(A, 600), (B, 600)],
            at(0, 13),
            rules,
        )
        .await;
        assert_eq!(balance(db, &prot_tank_account(&tank.id)).await, 1_181);
        set_tank_balance(db, &tank.id, 30).await;
        let outcome = burn(db, &tank.id, 1, rules).await;
        assert!(
            matches!(&outcome, ProtBurnOutcome::EnteredGrace { entry: Some(entry), .. } if entry.amount == 40),
            "{outcome:?}"
        );
        self::tank(db, &tank.id).await
    }

    /// The Grace tank frozen on day 6 at -170 (5 days of borrowed grace)
    async fn frozen_tank(db: &Database, rules: &ProtTankRules) -> ProtTank {
        let tank = grace_tank(db, rules).await;
        for n in 2..=5 {
            let outcome = burn(db, &tank.id, n, rules).await;
            assert!(
                matches!(outcome, ProtBurnOutcome::Burned { .. }),
                "day {n}: {outcome:?}"
            );
        }
        let outcome = burn(db, &tank.id, 6, rules).await;
        assert!(
            matches!(outcome, ProtBurnOutcome::Froze { .. }),
            "{outcome:?}"
        );
        self::tank(db, &tank.id).await
    }

    // -----------------------------------------------------------------------
    // 7.2 burns, 7.0 clamps
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn grace_burns_down_to_the_floor_then_freezes() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = grace_tank(&db, &rules).await;
            let account = prot_tank_account(&tank.id);
            assert_eq!(tank.stage, v0::ProtTankStage::Grace);
            assert_eq!(tank.exhausted_at, Some(at(1, 0)));
            assert_eq!(tank.next_burn_day, Some(day(2)));
            assert_eq!(balance(&db, &account).await, -10);
            assert_eq!(
                entitlement_state(&db, CHANNEL).await,
                Some(crate::ChannelEntitlementState::Grace)
            );

            for (n, expected) in [(2, -50), (3, -90), (4, -130), (5, -170)] {
                let outcome = burn(&db, &tank.id, n, &rules).await;
                assert!(matches!(outcome, ProtBurnOutcome::Burned { .. }), "day {n}");
                assert_eq!(balance(&db, &account).await, expected, "day {n}");
                assert!(balance(&db, &account).await >= rules.floor(40));
            }
            // Day 6 starts at exhausted_at + 5 days: Freeze, checked first
            let outcome = burn(&db, &tank.id, 6, &rules).await;
            let ProtBurnOutcome::Froze { tank: frozen } = outcome else {
                panic!("expected Froze, got {outcome:?}");
            };
            assert_eq!(frozen.stage, v0::ProtTankStage::Frozen);
            assert_eq!(frozen.next_burn_day, Some(day(6)));
            assert_eq!(balance(&db, &account).await, -170);
            assert!(row(&db, &prot_key_burn(&tank.id, &day(6))).await.is_none());
            assert_eq!(
                entitlement_state(&db, CHANNEL).await,
                Some(crate::ChannelEntitlementState::Frozen)
            );
        });
    }

    #[tokio::test]
    async fn frozen_days_are_never_billed() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = frozen_tank(&db, &rules).await;
            for n in 6..=12 {
                let outcome = db
                    .burn_prot_tank_day(&tank.id, &day(n), None, at(n, 1), &rules)
                    .await
                    .unwrap();
                assert!(matches!(outcome, ProtBurnOutcome::NotDue { .. }), "day {n}");
                assert!(row(&db, &prot_key_burn(&tank.id, &day(n))).await.is_none());
            }
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, -170);
        });
    }

    #[tokio::test]
    async fn burn_is_idempotent_across_two_replicas() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;

            let now = at(1, 0) + 60_000;
            let burn_day = day(1);
            let (first, second) = futures::join!(
                db.burn_prot_tank_day(&tank.id, &burn_day, None, now, &rules),
                db.burn_prot_tank_day(&tank.id, &burn_day, None, now, &rules),
            );
            let burned = [&first, &second]
                .iter()
                .filter(|outcome| matches!(outcome, Ok(ProtBurnOutcome::Burned { .. })))
                .count();
            assert_eq!(burned, 1, "{first:?} {second:?}");

            assert_eq!(
                rows_of_kind(&db, &tank.id, v0::ProtEntryKind::Burn)
                    .await
                    .len(),
                2
            );
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 1_181 - 40);
            assert_eq!(self::tank(&db, &tank.id).await.next_burn_day, Some(day(2)));
        });
    }

    #[tokio::test]
    async fn ten_day_outage_bills_with_the_missed_day_exhausted_at() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            set_tank_balance(&db, &tank.id, 100).await;

            // Nothing ran from day 1 to day 11: the clock catches up day by day
            let now = at(11, 1);
            let today = prot_utc_day(now);
            let mut next = tank.next_burn_day.clone().unwrap();
            let mut outcomes = Vec::new();
            while next <= today {
                let outcome = db
                    .burn_prot_tank_day(&tank.id, &next, None, now, &rules)
                    .await
                    .unwrap();
                if matches!(outcome, ProtBurnOutcome::NotDue { .. }) {
                    break;
                }
                outcomes.push(outcome);
                next = prot_next_day(&next).unwrap();
            }

            // 100 pays days 1-2, day 3 borrows (exhausted at day 3's start,
            // not at the catch-up's now), days 4-7 borrow, day 8 freezes
            assert_eq!(outcomes.len(), 8);
            assert!(matches!(
                outcomes[2],
                ProtBurnOutcome::EnteredGrace { entry: Some(_), .. }
            ));
            assert!(matches!(outcomes[7], ProtBurnOutcome::Froze { .. }));
            let tank = self::tank(&db, &tank.id).await;
            assert_eq!(tank.exhausted_at, Some(at(3, 0)));
            assert_eq!(tank.stage, v0::ProtTankStage::Frozen);
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, -180);
            for n in 1..=11 {
                assert_eq!(
                    row(&db, &prot_key_burn(&tank.id, &day(n))).await.is_some(),
                    n <= 7,
                    "day {n}"
                );
            }
        });
    }

    #[tokio::test]
    async fn grace_downgrade_below_the_new_floor_still_advances_and_freezes() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            // 25 slots: 90 a day, floor -450
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                25,
                &[(A, 1_000), (B, 1_000)],
                at(0, 13),
                &rules,
            )
            .await;
            set_tank_balance(&db, &tank.id, 50).await;
            let outcome = burn(&db, &tank.id, 1, &rules).await;
            assert!(
                matches!(outcome, ProtBurnOutcome::EnteredGrace { .. }),
                "{outcome:?}"
            );
            set_tank_balance(&db, &tank.id, -300).await;

            // Down to 10 slots in Grace: floor -200, above the balance
            let down = change_tier(&db, &tank.id, 10, "owner-down", at(1, 14))
                .await
                .unwrap();
            assert_eq!((down.slot_tier, down.daily_cost), (10, 40));

            for n in 2..=5 {
                let outcome = burn(&db, &tank.id, n, &rules).await;
                assert!(
                    matches!(&outcome, ProtBurnOutcome::EnteredGrace { entry: None, tank } if tank.next_burn_day == Some(day(n + 1))),
                    "day {n}: {outcome:?}"
                );
            }
            let outcome = burn(&db, &tank.id, 6, &rules).await;
            assert!(
                matches!(outcome, ProtBurnOutcome::Froze { .. }),
                "{outcome:?}"
            );
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, -300);
            for n in 2..=6 {
                assert!(row(&db, &prot_key_burn(&tank.id, &day(n))).await.is_none());
            }
        });
    }

    #[tokio::test]
    async fn no_pro_rata_burn_while_burning_is_off() {
        database_test!(|db| async move {
            setup(&db).await;
            let off = ProtTankRules {
                burning: false,
                ..rules()
            };
            insert_server(&db, SERVER).await;

            // Capture: no launch-day row, and today stays unbilled
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &off,
            )
            .await;
            assert_eq!(tank.stage, v0::ProtTankStage::Active);
            assert_eq!(tank.next_burn_day, Some(day(0)));
            assert!(rows_of_kind(&db, &tank.id, v0::ProtEntryKind::Burn)
                .await
                .is_empty());
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 1_200);
            let outcome = db
                .burn_prot_tank_day(&tank.id, &day(0), None, at(0, 14), &off)
                .await
                .unwrap();
            assert!(matches!(outcome, ProtBurnOutcome::NotDue { .. }));

            // Reactivation from Frozen: no row either
            let (_, second) = launched(
                &db,
                SERVER,
                CHANNEL_2,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules(),
            )
            .await;
            set_tank_balance(&db, &second.id, 30).await;
            for n in 1..=6 {
                burn(&db, &second.id, n, &rules()).await;
            }
            assert_eq!(
                self::tank(&db, &second.id).await.stage,
                v0::ProtTankStage::Frozen
            );
            fund(&db, D, 500).await;
            let outcome = contribute(&db, D, &second.id, 500, at(8, 13), &off)
                .await
                .unwrap();
            let ProtContributeOutcome::Applied {
                tank: active,
                stage_changed,
                ..
            } = outcome
            else {
                panic!("expected Applied");
            };
            assert!(stage_changed);
            assert_eq!(active.stage, v0::ProtTankStage::Active);
            assert_eq!(active.next_burn_day, Some(day(8)));
            assert!(row(&db, &prot_key_burn(&second.id, &day(8)))
                .await
                .is_none());
        });
    }

    #[tokio::test]
    async fn pro_rata_burns_clamp_at_the_floor() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = grace_tank(&db, &rules).await;
            set_tank_balance(&db, &tank.id, -190).await;

            let paused = at(2, 6);
            assert!(db.set_prot_burn_paused(paused).await.unwrap());
            // 19 Prot due for the rest of day 4; 10 above the floor
            assert!(db
                .shift_prot_tank_for_pause(&tank.id, paused, at(4, 13), &rules)
                .await
                .unwrap());
            let entry = row(&db, &prot_key_burn(&tank.id, &day(4)))
                .await
                .expect("today's pro rata");
            assert_eq!(entry.amount, 10);
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, -200);
            assert_eq!(self::tank(&db, &tank.id).await.next_burn_day, Some(day(5)));
        });
    }

    // -----------------------------------------------------------------------
    // 7.4 pause and resume
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn a_pause_bills_nothing_and_shifts_the_clocks() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = grace_tank(&db, &rules).await;
            assert!(db
                .record_prot_notice(
                    &tank.id,
                    tank.warnings_epoch,
                    ProtNoticeKind::Final,
                    true,
                    at(1, 12)
                )
                .await
                .unwrap());

            let paused = at(2, 6);
            assert!(db.set_prot_burn_paused(paused).await.unwrap());
            for n in 2..=4 {
                let outcome = db
                    .burn_prot_tank_day(&tank.id, &day(n), Some(paused), at(n, 1), &rules)
                    .await
                    .unwrap();
                assert!(matches!(outcome, ProtBurnOutcome::NotDue { .. }), "day {n}");
            }

            let resumed = at(5, 13);
            let shift = resumed - paused;
            assert!(db
                .shift_prot_tank_for_pause(&tank.id, paused, resumed, &rules)
                .await
                .unwrap());
            // Once per pause
            assert!(!db
                .shift_prot_tank_for_pause(&tank.id, paused, resumed + HOUR, &rules)
                .await
                .unwrap());

            let shifted = self::tank(&db, &tank.id).await;
            assert_eq!(shifted.pause_shift_for, Some(paused));
            assert_eq!(shifted.exhausted_at, Some(at(1, 0) + shift));
            assert_eq!(shifted.final_warning_at, Some(at(1, 12) + shift));
            for n in 2..=4 {
                assert!(row(&db, &prot_key_burn(&tank.id, &day(n))).await.is_none());
            }
            // Only the rest of day 5 (11 hours): 40 x 11 / 24 -> 19
            assert_eq!(
                row(&db, &prot_key_burn(&tank.id, &day(5)))
                    .await
                    .unwrap()
                    .amount,
                19
            );
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, -29);
            assert_eq!(shifted.next_burn_day, Some(day(6)));
        });
    }

    #[tokio::test]
    async fn resume_charges_only_the_rest_of_today() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            burn(&db, &tank.id, 1, &rules).await;

            let paused = at(1, 20);
            assert!(db.set_prot_burn_paused(paused).await.unwrap());
            assert!(db
                .shift_prot_tank_for_pause(&tank.id, paused, at(4, 13), &rules)
                .await
                .unwrap());

            // ULIDs minted in one millisecond do not sort by time: compare
            // the billed days as a set
            let burns = rows_of_kind(&db, &tank.id, v0::ProtEntryKind::Burn).await;
            let mut days: Vec<Option<String>> =
                burns.iter().map(|row| row.reference.day.clone()).collect();
            days.sort();
            assert_eq!(days, vec![Some(day(0)), Some(day(1)), Some(day(4))]);
            assert_eq!(
                row(&db, &prot_key_burn(&tank.id, &day(4)))
                    .await
                    .unwrap()
                    .amount,
                19
            );
            assert_eq!(
                balance(&db, &prot_tank_account(&tank.id)).await,
                1_181 - 40 - 19
            );
            let shifted = self::tank(&db, &tank.id).await;
            assert_eq!(shifted.stage, v0::ProtTankStage::Active);
            assert_eq!(shifted.next_burn_day, Some(day(5)));
        });
    }

    #[tokio::test]
    async fn step_two_skips_tanks_not_yet_shifted_for_the_pause() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, first) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            let (_, second) = launched(
                &db,
                SERVER,
                CHANNEL_2,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;

            let paused = at(0, 20);
            assert!(db.set_prot_burn_paused(paused).await.unwrap());
            assert!(db
                .shift_prot_tank_for_pause(&first.id, paused, at(3, 13), &rules)
                .await
                .unwrap());

            // Still recorded: the shifted tank is billed, the other is not
            let shifted = db
                .burn_prot_tank_day(&first.id, &day(4), Some(paused), at(4, 1), &rules)
                .await
                .unwrap();
            assert!(
                matches!(shifted, ProtBurnOutcome::Burned { .. }),
                "{shifted:?}"
            );
            let waiting = db
                .burn_prot_tank_day(&second.id, &day(1), Some(paused), at(4, 1), &rules)
                .await
                .unwrap();
            assert!(
                matches!(waiting, ProtBurnOutcome::NotDue { .. }),
                "{waiting:?}"
            );
            assert_eq!(
                rows_of_kind(&db, &second.id, v0::ProtEntryKind::Burn)
                    .await
                    .len(),
                1,
                "only the launch day"
            );
        });
    }

    #[tokio::test]
    async fn resume_of_a_grace_tank_at_its_floor_still_clears_the_pause() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = grace_tank(&db, &rules).await;
            set_tank_balance(&db, &tank.id, -200).await;

            let paused = at(2, 6);
            assert!(db.set_prot_burn_paused(paused).await.unwrap());
            assert!(db
                .shift_prot_tank_for_pause(&tank.id, paused, at(3, 13), &rules)
                .await
                .unwrap());
            assert!(row(&db, &prot_key_burn(&tank.id, &day(3))).await.is_none());
            assert_eq!(
                self::tank(&db, &tank.id).await.pause_shift_for,
                Some(paused)
            );

            assert!(db.clear_prot_burn_paused(paused).await.unwrap());
            assert_eq!(
                db.fetch_prot_runtime()
                    .await
                    .unwrap()
                    .and_then(|runtime| runtime.burn_paused_at),
                None
            );
        });
    }

    #[tokio::test]
    async fn burn_pause_is_set_once_and_cleared_by_value() {
        database_test!(|db| async move {
            setup(&db).await;
            assert!(db.fetch_prot_runtime().await.unwrap().is_none());
            assert!(db.set_prot_burn_paused(1_000).await.unwrap());
            assert!(!db.set_prot_burn_paused(2_000).await.unwrap());
            assert_eq!(
                db.fetch_prot_runtime()
                    .await
                    .unwrap()
                    .unwrap()
                    .burn_paused_at,
                Some(1_000)
            );
            assert!(!db.clear_prot_burn_paused(2_000).await.unwrap());
            assert!(db.clear_prot_burn_paused(1_000).await.unwrap());
            assert!(!db.clear_prot_burn_paused(1_000).await.unwrap());
            assert_eq!(
                db.fetch_prot_runtime()
                    .await
                    .unwrap()
                    .and_then(|runtime| runtime.burn_paused_at),
                None
            );
            // A new pause after the clear
            assert!(db.set_prot_burn_paused(3_000).await.unwrap());
        });
    }

    // -----------------------------------------------------------------------
    // 7.3 reactivation, 8.8 contributions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reactivation_threshold_matches_the_plan_example() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = grace_tank(&db, &rules).await;
            fund(&db, D, 1_000).await;
            let burns_before = rows_of_kind(&db, &tank.id, v0::ProtEntryKind::Burn)
                .await
                .len();

            // -120 + 150 = 30 < 40: the debt is repaid, the stage stays
            set_tank_balance(&db, &tank.id, -120).await;
            let outcome = contribute(&db, D, &tank.id, 150, at(1, 15), &rules)
                .await
                .unwrap();
            let ProtContributeOutcome::Applied {
                tank: stays,
                stage_changed,
                ..
            } = outcome
            else {
                panic!("expected Applied");
            };
            assert!(!stage_changed);
            assert_eq!(stays.stage, v0::ProtTankStage::Grace);
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 30);

            // -120 + 200 = 80 >= 40: Active again, warnings re-armed
            set_tank_balance(&db, &tank.id, -120).await;
            let outcome = contribute(&db, D, &tank.id, 200, at(1, 16), &rules)
                .await
                .unwrap();
            let ProtContributeOutcome::Applied {
                tank: active,
                stage_changed,
                ..
            } = outcome
            else {
                panic!("expected Applied");
            };
            assert!(stage_changed);
            assert_eq!(active.stage, v0::ProtTankStage::Active);
            assert_eq!(active.exhausted_at, None);
            assert_eq!(active.warnings_epoch, tank.warnings_epoch + 1);
            assert_eq!(active.next_burn_day, Some(day(2)));
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 80);
            assert_eq!(
                entitlement_state(&db, CHANNEL).await,
                Some(crate::ChannelEntitlementState::Active)
            );
            // From Grace nothing more is billed today
            assert_eq!(
                rows_of_kind(&db, &tank.id, v0::ProtEntryKind::Burn)
                    .await
                    .len(),
                burns_before
            );
        });
    }

    #[tokio::test]
    async fn reactivation_never_bills_frozen_days() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = frozen_tank(&db, &rules).await;
            fund(&db, D, 500).await;

            let outcome = contribute(&db, D, &tank.id, 500, at(12, 13), &rules)
                .await
                .unwrap();
            let ProtContributeOutcome::Applied {
                tank: active,
                stage_changed,
                ..
            } = outcome
            else {
                panic!("expected Applied");
            };
            assert!(stage_changed);
            assert_eq!(active.stage, v0::ProtTankStage::Active);
            assert_eq!(active.next_burn_day, Some(day(13)));
            // Today's pro rata only (11 hours: 19), no frozen day
            assert_eq!(
                row(&db, &prot_key_burn(&tank.id, &day(12)))
                    .await
                    .unwrap()
                    .amount,
                19
            );
            for n in 6..=11 {
                assert!(
                    row(&db, &prot_key_burn(&tank.id, &day(n))).await.is_none(),
                    "day {n}"
                );
            }
            assert_eq!(
                balance(&db, &prot_tank_account(&tank.id)).await,
                -170 + 500 - 19
            );
            assert_eq!(
                entitlement_state(&db, CHANNEL).await,
                Some(crate::ChannelEntitlementState::Active)
            );
        });
    }

    #[tokio::test]
    async fn borrowed_grace_is_repaid_by_a_top_up() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = grace_tank(&db, &rules).await;
            burn(&db, &tank.id, 2, &rules).await;
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, -50);
            fund(&db, D, 50).await;

            let outcome = contribute(&db, D, &tank.id, 50, at(2, 10), &rules)
                .await
                .unwrap();
            let ProtContributeOutcome::Applied {
                tank: after,
                stage_changed,
                ..
            } = outcome
            else {
                panic!("expected Applied");
            };
            assert!(!stage_changed);
            assert_eq!(after.stage, v0::ProtTankStage::Grace);
            assert_eq!(after.exhausted_at, Some(at(1, 0)));
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 0);
        });
    }

    #[tokio::test]
    async fn contribution_replays_and_refusals_write_nothing() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            fund(&db, D, 1_000).await;

            let input = ProtContributeInput {
                user_id: D.to_string(),
                tank_id: tank.id.clone(),
                amount: 300,
                nonce: "top-up".to_string(),
                rules: rules.clone(),
                now: at(0, 15),
            };
            let first = db.contribute_prot(&input).await.unwrap();
            let second = db.contribute_prot(&input).await.unwrap();
            let (
                ProtContributeOutcome::Applied { entry, .. },
                ProtContributeOutcome::AlreadyApplied { entry: stored, .. },
            ) = (first, second)
            else {
                panic!("expected Applied then AlreadyApplied");
            };
            assert_eq!(entry, stored);
            assert_eq!(balance(&db, &prot_user_account(D)).await, 700);

            // A tank that has not launched takes nothing
            let (_, pending) = launching(
                &db,
                SERVER,
                CHANNEL_2,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            let refused = contribute(&db, D, &pending.id, 100, at(0, 15), &rules).await;
            assert!(is_error(&refused, "InvalidOperation"), "{refused:?}");

            // Nor does a settling or deleted one
            db.begin_prot_settlement(&tank.id, ProtSettleCause::OwnerDelete, at(0, 16))
                .await
                .unwrap();
            let refused = contribute(&db, D, &tank.id, 100, at(0, 16), &rules).await;
            assert!(is_error(&refused, "InvalidOperation"), "{refused:?}");
            assert_eq!(balance(&db, &prot_user_account(D)).await, 700);
            db.settle_prot_tank(&tank.id, at(0, 17)).await.unwrap();
            // D's lot is the newest, so the launch-day burn never reached it
            assert_eq!(balance(&db, &prot_user_account(D)).await, 1_000);
            let refused = contribute(&db, D, &tank.id, 100, at(0, 17), &rules).await;
            assert!(is_error(&refused, "InvalidOperation"), "{refused:?}");
            assert_eq!(balance(&db, &prot_user_account(D)).await, 1_000);
        });
    }

    // -----------------------------------------------------------------------
    // 8.3 pledges, 8.4 withdrawals, 8.5 closes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pledge_is_capped_at_the_target_and_flips_funded() {
        database_test!(|db| async move {
            setup(&db).await;
            insert_server(&db, SERVER).await;
            fund(&db, A, 1_000).await;
            fund(&db, B, 1_000).await;
            let now = at(0, 10);
            let goal = db
                .create_prot_goal(&launch_goal(SERVER, 10, 1_200, now))
                .await
                .unwrap();

            let first = pledge(&db, A, &goal.id, 1_000, now + 1).await.unwrap();
            assert!(!first.funded_now);
            assert_eq!(first.goal.state, v0::ProtGoalState::Funding);

            let last = pledge(&db, B, &goal.id, 500, now + 2).await.unwrap();
            assert!(last.funded_now);
            assert_eq!(last.pledge.amount, 200);
            assert_eq!(last.pledge.remaining, 200);
            assert_eq!(last.entry.amount, 200);
            assert_eq!(last.goal.state, v0::ProtGoalState::Funded);
            assert_eq!(last.goal.pledged_total, 1_200);
            assert_eq!(last.goal.funded_at, Some(now + 2));
            assert_eq!(last.goal.launch_deadline_at, Some(now + 2 + 7 * DAY));
            assert_eq!(balance(&db, &prot_user_account(B)).await, 800);
            assert_eq!(balance(&db, &prot_hold_account(&goal.id)).await, 1_200);

            let closed = pledge(&db, B, &goal.id, 100, now + 3).await;
            assert!(is_error(&closed, "ProtGoalClosed"), "{closed:?}");
        });
    }

    #[tokio::test]
    async fn completing_pledge_below_50_is_allowed() {
        database_test!(|db| async move {
            setup(&db).await;
            insert_server(&db, SERVER).await;
            fund(&db, A, 2_000).await;
            fund(&db, B, 100).await;
            let now = at(0, 10);
            let goal = db
                .create_prot_goal(&launch_goal(SERVER, 10, 1_200, now))
                .await
                .unwrap();

            pledge(&db, A, &goal.id, 1_100, now + 1).await.unwrap();
            // 30 of the 100 still open: below the minimum and not completing
            let short = pledge(&db, B, &goal.id, 30, now + 2).await;
            assert!(is_error(&short, "FailedValidation"), "{short:?}");
            pledge(&db, A, &goal.id, 70, now + 3).await.unwrap();
            // 30 completes it
            let last = pledge(&db, B, &goal.id, 30, now + 4).await.unwrap();
            assert!(last.funded_now);
            assert_eq!(last.pledge.amount, 30);
        });
    }

    #[tokio::test]
    async fn held_purchase_cannot_be_pledged() {
        database_test!(|db| async move {
            setup(&db).await;
            insert_server(&db, SERVER).await;
            let now = at(10, 10);
            let goal = db
                .create_prot_goal(&launch_goal(SERVER, 10, 2_000, now - HOUR))
                .await
                .unwrap();
            db.apply_prot_posting(&purchase(
                A,
                "01ORDERHELD000000000000000",
                1_000,
                now - HOUR,
            ))
            .await
            .unwrap();
            fund(&db, A, 300).await;

            // 1,000 of the 1,300 was bought an hour ago (D17)
            let refused = pledge(&db, A, &goal.id, 301, now).await;
            assert!(is_error(&refused, "InsufficientProt"), "{refused:?}");
            assert!(db
                .fetch_prot_pledges_by_goal(&goal.id)
                .await
                .unwrap()
                .is_empty());
            assert_eq!(self::goal(&db, &goal.id).await.pledged_total, 0);
            assert_eq!(balance(&db, &prot_user_account(A)).await, 1_300);

            pledge(&db, A, &goal.id, 300, now).await.unwrap();
            // After the hold window the purchase is free Prot
            pledge(&db, A, &goal.id, 1_000, now + 73 * HOUR)
                .await
                .unwrap();
            assert_eq!(balance(&db, &prot_user_account(A)).await, 0);
            assert_eq!(self::goal(&db, &goal.id).await.pledged_total, 1_300);
        });
    }

    #[tokio::test]
    async fn pledge_replay_returns_the_stored_pledge() {
        database_test!(|db| async move {
            setup(&db).await;
            insert_server(&db, SERVER).await;
            fund(&db, A, 1_000).await;
            let now = at(0, 10);
            let goal = db
                .create_prot_goal(&launch_goal(SERVER, 10, 1_200, now))
                .await
                .unwrap();
            let input = ProtPledgeInput {
                user_id: A.to_string(),
                goal_id: goal.id.clone(),
                amount: 400,
                nonce: "pledge-1".to_string(),
                rules: rules(),
                now,
            };
            let first = db.pledge_prot(&input).await.unwrap();
            let replay = db
                .pledge_prot(&ProtPledgeInput {
                    now: now + 5_000,
                    ..input.clone()
                })
                .await
                .unwrap();
            assert!(!first.already_applied);
            assert!(replay.already_applied);
            assert!(!replay.funded_now);
            assert_eq!(replay.pledge, first.pledge);
            assert_eq!(replay.entry, first.entry);
            assert_eq!(
                db.fetch_prot_pledges_by_goal(&goal.id).await.unwrap().len(),
                1
            );
            assert_eq!(balance(&db, &prot_user_account(A)).await, 600);
            assert_eq!(self::goal(&db, &goal.id).await.pledged_total, 400);
        });
    }

    #[tokio::test]
    async fn concurrent_same_nonce_pledges_write_one_pledge() {
        database_test!(|db| async move {
            setup(&db).await;
            insert_server(&db, SERVER).await;
            fund(&db, A, 1_000).await;
            let now = at(0, 10);
            let goal = db
                .create_prot_goal(&launch_goal(SERVER, 10, 1_200, now))
                .await
                .unwrap();
            let input = ProtPledgeInput {
                user_id: A.to_string(),
                goal_id: goal.id.clone(),
                amount: 400,
                nonce: "same".to_string(),
                rules: rules(),
                now,
            };
            let (first, second) = futures::join!(db.pledge_prot(&input), db.pledge_prot(&input));
            let first = first.unwrap();
            let second = second.unwrap();
            assert_eq!(
                [first.already_applied, second.already_applied]
                    .iter()
                    .filter(|applied| !**applied)
                    .count(),
                1
            );
            assert_eq!(first.pledge.id, second.pledge.id);
            assert_eq!(
                db.fetch_prot_pledges_by_goal(&goal.id).await.unwrap().len(),
                1
            );
            assert_eq!(balance(&db, &prot_user_account(A)).await, 600);
            assert_eq!(self::goal(&db, &goal.id).await.pledged_total, 400);
        });
    }

    /// The last Prot of the goal (C, 1: allowed only while it completes the
    /// goal), then launch, protect and capture, as the owner and
    /// on_protect_landed would. Ok(true) when the capture ran.
    async fn complete_and_capture(
        db: &Database,
        goal_id: &str,
        channel_id: &str,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<bool> {
        if pledge(db, C, goal_id, 1, now).await.is_err() {
            return Ok(false);
        }
        db.launch_prot_goal(&ProtLaunchInput {
            goal_id: goal_id.to_string(),
            channel_id: channel_id.to_string(),
            owner_id: OWNER.to_string(),
            rules: rules.clone(),
            now,
        })
        .await?;
        db.protect_channel(
            channel_id,
            &seat_list(channel_id, 1, &[OWNER], now),
            timestamp(now),
        )
        .await?;
        Ok(db
            .capture_launch_pledges(channel_id, now, rules)
            .await?
            .is_some())
    }

    /// One racing call: (whether it is the side under test, its result)
    type Racer<'a, T> = Pin<Box<dyn Future<Output = (bool, Result<T>)> + 'a>>;

    async fn withdraw_racer(
        db: &Database,
        pledge_id: &str,
        now: i64,
        cutoff: i64,
    ) -> (bool, Result<bool>) {
        (
            true,
            db.withdraw_prot_pledge(pledge_id, A, now, cutoff)
                .await
                .map(|_| true),
        )
    }

    async fn capture_racer(
        db: &Database,
        goal_id: &str,
        channel_id: &str,
        now: i64,
        rules: &ProtTankRules,
    ) -> (bool, Result<bool>) {
        (
            false,
            complete_and_capture(db, goal_id, channel_id, now, rules).await,
        )
    }

    async fn abandon_racer(db: &Database, goal_id: &str, now: i64) -> (bool, Result<()>) {
        (
            true,
            db.close_prot_goal(goal_id, v0::ProtGoalState::Cancelled, now)
                .await
                .map(|_| ()),
        )
    }

    async fn protect_racer(db: &Database, channel_id: &str, now: i64) -> (bool, Result<()>) {
        (
            false,
            db.protect_channel(
                channel_id,
                &seat_list(channel_id, 1, &[OWNER], now),
                timestamp(now),
            )
            .await
            .map(|_| ()),
        )
    }

    #[tokio::test]
    async fn withdraw_racing_capture_exactly_one_wins() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            for user in [A, B, C] {
                fund(&db, user, 100_000).await;
            }
            let cutoff = i64::from(rules.withdraw_cutoff_hours) * HOUR;

            for i in 0..RACE_ITERATIONS {
                let channel = channel_id(1_000 + i);
                insert_channel(&db, &channel, SERVER).await;
                let now = at(1, 10) + i64::from(i) * 10_000;
                let goal = db
                    .create_prot_goal(&launch_goal(SERVER, 10, 1_200, now - 5_000))
                    .await
                    .unwrap();
                // A's pledge is the one both sides want; one Prot is open
                let wanted = pledge(&db, A, &goal.id, 600, now - 4_000)
                    .await
                    .unwrap()
                    .pledge;
                pledge(&db, B, &goal.id, 599, now - 3_000).await.unwrap();
                let wallet = balance(&db, &prot_user_account(A)).await;

                // Two withdrawals of the same pledge and the capture chain,
                // in a rotating order
                let mut racers: Vec<Racer<'_, bool>> = vec![
                    Box::pin(withdraw_racer(&db, &wanted.id, now, cutoff)),
                    Box::pin(withdraw_racer(&db, &wanted.id, now, cutoff)),
                    Box::pin(capture_racer(&db, &goal.id, &channel, now, &rules)),
                ];
                racers.rotate_left((i % 3) as usize);
                let results = futures::future::join_all(racers).await;

                let withdrawn = results
                    .iter()
                    .filter(|(is_withdraw, result)| *is_withdraw && matches!(result, Ok(true)))
                    .count();
                let stored = db.fetch_prot_pledge(&wanted.id).await.unwrap().unwrap();
                let captured = stored.state == v0::ProtPledgeState::Captured;
                assert_eq!(
                    withdrawn + usize::from(captured),
                    1,
                    "iteration {i}: {results:?}"
                );
                assert_eq!(stored.remaining, 0);
                if captured {
                    assert_eq!(stored.captured, 600);
                    assert_eq!(balance(&db, &prot_user_account(A)).await, wallet);
                } else {
                    assert_eq!(stored.state, v0::ProtPledgeState::Withdrawn);
                    assert_eq!(balance(&db, &prot_user_account(A)).await, wallet + 600);
                }

                // The next iteration needs the server's launch slot
                let after = self::goal(&db, &goal.id).await;
                assert_eq!(
                    balance(&db, &prot_hold_account(&goal.id)).await,
                    if PROT_OPEN_GOAL_STATES.contains(&after.state) {
                        after.pledged_total
                    } else {
                        0
                    }
                );
                if PROT_OPEN_GOAL_STATES.contains(&after.state) {
                    db.close_prot_goal(&goal.id, v0::ProtGoalState::Cancelled, now)
                        .await
                        .unwrap();
                }
            }
        });
    }

    #[tokio::test]
    async fn abandon_racing_protect_never_strands() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;

            for i in 0..RACE_ITERATIONS {
                let channel = channel_id(2_000 + i);
                let now = at(1, 10) + i64::from(i) * 10_000;
                let (goal, tank) = launching(
                    &db,
                    SERVER,
                    &channel,
                    10,
                    &[(A, 600), (B, 600)],
                    now,
                    &rules,
                )
                .await;
                let wallets = (
                    balance(&db, &prot_user_account(A)).await,
                    balance(&db, &prot_user_account(B)).await,
                );

                let mut racers: Vec<Racer<'_, ()>> = vec![
                    Box::pin(abandon_racer(&db, &goal.id, now)),
                    Box::pin(protect_racer(&db, &channel, now)),
                ];
                racers.rotate_left((i % 2) as usize);
                let results = futures::future::join_all(racers).await;
                // What on_protect_landed (or the sweep) runs next
                db.capture_launch_pledges(&channel, now + 1, &rules)
                    .await
                    .unwrap();

                let protected = db.fetch_channel(&channel).await.unwrap().is_protected();
                let entitlement = db.fetch_channel_entitlement(&channel).await.unwrap();
                let stored_tank = db.fetch_prot_tank(&tank.id).await.unwrap();
                let after = self::goal(&db, &goal.id).await;
                let pledges = db.fetch_prot_pledges_by_goal(&goal.id).await.unwrap();
                assert_eq!(
                    balance(&db, &prot_hold_account(&goal.id)).await,
                    0,
                    "iteration {i}"
                );
                if protected {
                    // Protected and captured
                    assert!(entitlement.is_some(), "iteration {i}: {results:?}");
                    assert_eq!(after.state, v0::ProtGoalState::Launched, "iteration {i}");
                    let stored_tank = stored_tank.expect("the tank stays");
                    assert_eq!(stored_tank.stage, v0::ProtTankStage::Active);
                    assert!(pledges
                        .iter()
                        .all(|pledge| pledge.state == v0::ProtPledgeState::Captured));
                    assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 1_200 - 24);
                } else {
                    // Not protected and returned
                    assert!(entitlement.is_none(), "iteration {i}: {results:?}");
                    assert!(stored_tank.is_none(), "iteration {i}");
                    assert_eq!(after.state, v0::ProtGoalState::Cancelled);
                    assert!(pledges
                        .iter()
                        .all(|pledge| pledge.state == v0::ProtPledgeState::Returned));
                    assert_eq!(balance(&db, &prot_user_account(A)).await, wallets.0 + 600);
                    assert_eq!(balance(&db, &prot_user_account(B)).await, wallets.1 + 600);
                }
            }
        });
    }

    #[tokio::test]
    async fn expiry_and_cancel_return_everything() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            fund(&db, A, 2_000).await;
            fund(&db, B, 2_000).await;
            let now = at(0, 10);

            // Funding -> Expired
            let first = db
                .create_prot_goal(&launch_goal(SERVER, 10, 1_200, now))
                .await
                .unwrap();
            pledge(&db, A, &first.id, 300, now + 1).await.unwrap();
            pledge(&db, B, &first.id, 200, now + 2).await.unwrap();
            let outcome = db
                .close_prot_goal(&first.id, v0::ProtGoalState::Expired, now + 3)
                .await
                .unwrap();
            assert_eq!(outcome.returned.len(), 2);
            assert!(outcome.removed_tank.is_none());
            assert_eq!(outcome.goal.state, v0::ProtGoalState::Expired);
            assert_eq!(outcome.goal.open_key, None);
            assert_eq!(outcome.goal.closed_at, Some(now + 3));
            assert_eq!(balance(&db, &prot_user_account(A)).await, 2_000);
            assert_eq!(balance(&db, &prot_user_account(B)).await, 2_000);
            assert_eq!(balance(&db, &prot_hold_account(&first.id)).await, 0);
            for stored in db.fetch_prot_pledges_by_goal(&first.id).await.unwrap() {
                assert_eq!(stored.state, v0::ProtPledgeState::Returned);
                assert_eq!(stored.remaining, 0);
            }
            let again = db
                .close_prot_goal(&first.id, v0::ProtGoalState::Cancelled, now + 4)
                .await;
            assert!(is_error(&again, "ProtGoalClosed"), "{again:?}");

            // Funded -> Cancelled (never Expired)
            let second = db
                .create_prot_goal(&launch_goal(SERVER, 10, 1_200, now))
                .await
                .unwrap();
            pledge(&db, A, &second.id, 1_200, now + 5).await.unwrap();
            let expired = db
                .close_prot_goal(&second.id, v0::ProtGoalState::Expired, now + 6)
                .await;
            assert!(is_error(&expired, "ProtGoalClosed"), "{expired:?}");
            db.close_prot_goal(&second.id, v0::ProtGoalState::Cancelled, now + 6)
                .await
                .unwrap();
            assert_eq!(balance(&db, &prot_user_account(A)).await, 2_000);

            // Launching, protect never landed: the launch is undone
            let (third, tank) = launching(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                now + DAY,
                &rules,
            )
            .await;
            let outcome = db
                .close_prot_goal(&third.id, v0::ProtGoalState::Cancelled, now + DAY)
                .await
                .unwrap();
            assert_eq!(
                outcome.removed_tank.map(|removed| removed.id),
                Some(tank.id.clone())
            );
            assert!(db
                .fetch_prot_tank_by_channel(CHANNEL)
                .await
                .unwrap()
                .is_none());
            assert!(db
                .fetch_channel_entitlement(CHANNEL)
                .await
                .unwrap()
                .is_none());
            assert!(db
                .fetch_prot_account(&prot_tank_account(&tank.id))
                .await
                .unwrap()
                .is_none());
            assert_eq!(balance(&db, &prot_hold_account(&third.id)).await, 0);
        });
    }

    // -----------------------------------------------------------------------
    // 8.6 launch, capture, 7-day returns
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn launch_refuses_another_servers_channel_a_protected_channel_a_non_owner_and_a_channel_with_a_message(
    ) {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            insert_server(&db, OTHER_SERVER).await;
            fund(&db, A, 1_200).await;
            let now = at(0, 10);
            let goal = db
                .create_prot_goal(&launch_goal(SERVER, 10, 1_200, now))
                .await
                .unwrap();
            pledge(&db, A, &goal.id, 1_200, now + 1).await.unwrap();

            let launch = |channel_id: String, owner_id: &'static str| ProtLaunchInput {
                goal_id: goal.id.clone(),
                channel_id,
                owner_id: owner_id.to_string(),
                rules: rules.clone(),
                now: now + 10,
            };

            let foreign = channel_id(3_001);
            insert_channel(&db, &foreign, OTHER_SERVER).await;
            let with_message = channel_id(3_002);
            insert_channel(&db, &with_message, SERVER).await;
            db.insert_message(&Message {
                id: nonce(),
                channel: with_message.clone(),
                author: A.to_string(),
                content: Some("hello".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
            let granted = channel_id(3_003);
            insert_channel(&db, &granted, SERVER).await;
            db.upsert_channel_entitlement(
                &crate::ChannelEntitlement {
                    id: nonce(),
                    channel_id: granted.clone(),
                    server_id: SERVER.to_string(),
                    source: crate::ChannelEntitlementSource::AdminGrant,
                    slot_cap: 10,
                    device_cap: None,
                    state: crate::ChannelEntitlementState::Active,
                    granted_by: ADMIN.to_string(),
                    created_at: timestamp(now),
                },
                timestamp(now),
            )
            .await
            .unwrap();
            db.protect_channel(
                &granted,
                &seat_list(&granted, 1, &[OWNER], now),
                timestamp(now),
            )
            .await
            .unwrap();
            let clean = channel_id(3_004);
            insert_channel(&db, &clean, SERVER).await;

            for (input, case) in [
                (launch(foreign.clone(), OWNER), "another server's channel"),
                (
                    launch(with_message.clone(), OWNER),
                    "a channel with a message",
                ),
                (launch(granted.clone(), OWNER), "a protected channel"),
                (launch(clean.clone(), A), "a non-owner"),
                (launch(channel_id(3_999), OWNER), "a missing channel"),
            ] {
                let refused = db.launch_prot_goal(&input).await;
                assert!(refused.is_err(), "{case} was launched");
                assert!(
                    db.fetch_prot_tank_by_channel(&input.channel_id)
                        .await
                        .unwrap()
                        .is_none(),
                    "{case}"
                );
                assert_eq!(
                    self::goal(&db, &goal.id).await.state,
                    v0::ProtGoalState::Funded
                );
            }
            assert!(db
                .fetch_channel_entitlement(&clean)
                .await
                .unwrap()
                .is_none());

            let (started, tank) = db
                .launch_prot_goal(&launch(clean.clone(), OWNER))
                .await
                .unwrap();
            assert_eq!(started.state, v0::ProtGoalState::Launching);
            assert_eq!(started.tank_id.as_deref(), Some(tank.id.as_str()));
            assert_eq!(started.channel_id.as_deref(), Some(clean.as_str()));
            assert_eq!(tank.stage, v0::ProtTankStage::Launching);
            assert_eq!(
                (tank.slot_tier, tank.daily_cost, tank.next_burn_day.clone()),
                (10, 40, None)
            );
            let entitlement = db.fetch_channel_entitlement(&clean).await.unwrap().unwrap();
            assert_eq!(
                entitlement.source,
                crate::ChannelEntitlementSource::Crowdfund
            );
            assert_eq!(entitlement.slot_cap, 10);
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 0);
            // Pledges stay held until the capture
            assert_eq!(balance(&db, &prot_hold_account(&goal.id)).await, 1_200);
            // A capture before protect lands captures nothing
            assert!(db
                .capture_launch_pledges(&clean, now + 20, &rules)
                .await
                .unwrap()
                .is_none());
        });
    }

    #[tokio::test]
    async fn seven_day_return_example_tank_720() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            // Captured at midnight: the launch day is a full day (40)
            let (goal, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(OWNER, 600), (A, 400), (C, 200)],
                at(0, 0),
                &rules,
            )
            .await;
            assert_eq!(goal.state, v0::ProtGoalState::Launched);
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 1_160);
            db.put_seat_list(
                CHANNEL,
                &seat_list(CHANNEL, 2, &[OWNER, A], at(0, 1)),
                true,
                timestamp(at(0, 1)),
            )
            .await
            .unwrap();
            for n in 1..=6 {
                burn(&db, &tank.id, n, &rules).await;
            }
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 920);

            // C has no seat; A is seated and the owner is exempt
            let returned = db
                .return_unseated_launch_pledges(&goal.id, at(7, 1))
                .await
                .unwrap();
            assert_eq!(returned.len(), 1);
            assert_eq!(returned[0].credit, prot_user_account(C));
            assert_eq!(returned[0].amount, 200);
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 720);
            assert!(self::goal(&db, &goal.id).await.refund7_done);
            let c_pledge = db
                .fetch_prot_pledges_by_goal(&goal.id)
                .await
                .unwrap()
                .into_iter()
                .find(|pledge| pledge.user_id == C)
                .unwrap();
            assert_eq!(c_pledge.launch_returned, 200);

            // Once
            assert!(db
                .return_unseated_launch_pledges(&goal.id, at(8, 1))
                .await
                .unwrap()
                .is_empty());
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 720);
        });
    }

    #[tokio::test]
    async fn seven_day_return_scaled_b_67_c_33() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (goal, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(OWNER, 600), (B, 400), (C, 200)],
                at(0, 13),
                &rules,
            )
            .await;
            set_tank_balance(&db, &tank.id, 100).await;

            let returned = db
                .return_unseated_launch_pledges(&goal.id, at(7, 14))
                .await
                .unwrap();
            let mut paid: Vec<(String, i64)> = returned
                .iter()
                .map(|row| (row.credit.clone(), row.amount))
                .collect();
            paid.sort();
            let mut expected = vec![(prot_user_account(B), 67), (prot_user_account(C), 33)];
            expected.sort();
            assert_eq!(paid, expected);
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 0);
        });
    }

    // -----------------------------------------------------------------------
    // 8.7 upgrade goals, 8.9 tier changes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn upgrade_price_example_and_apply() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            set_tank_balance(&db, &tank.id, 1_200).await;
            // 10 -> 25 slots at 1,200 (30 days): (90 - 40) x 30
            let price = prot_upgrade_goal_price(40, 90, 1_200);
            assert_eq!(price, 1_500);

            let now = at(0, 13) + 1_000;
            let upgrade = db
                .create_prot_goal(&upgrade_goal(&tank, 25, price, now))
                .await
                .unwrap();
            fund(&db, A, 1_000).await;
            fund(&db, C, 500).await;
            pledge(&db, A, &upgrade.id, 1_000, now).await.unwrap();
            let funded = pledge(&db, C, &upgrade.id, 500, now).await.unwrap();
            assert!(funded.funded_now);

            let applied = db
                .apply_prot_upgrade_goal(&upgrade.id, now, &rules)
                .await
                .unwrap()
                .expect("applied");
            assert_eq!((applied.slot_tier, applied.daily_cost), (25, 90));
            assert_eq!(applied.rate_card, "40/90/160/280");
            // 11 hours left: (90 - 40) x 11 / 24 -> 23
            let tier = row(
                &db,
                &prot_key_tier(&tank.id, &format!("goal-{}", upgrade.id)),
            )
            .await
            .expect("the tier charge");
            assert_eq!(tier.amount, 23);
            assert_eq!(tier.credit, PROT_SYS_BURNED);
            assert_eq!(
                balance(&db, &prot_tank_account(&tank.id)).await,
                1_200 + 1_500 - 23
            );
            assert_eq!(balance(&db, &prot_hold_account(&upgrade.id)).await, 0);
            let applied_goal = self::goal(&db, &upgrade.id).await;
            assert_eq!(applied_goal.state, v0::ProtGoalState::Applied);
            assert_eq!(applied_goal.open_key, None);
            assert!(db
                .fetch_prot_pledges_by_goal(&upgrade.id)
                .await
                .unwrap()
                .iter()
                .all(
                    |pledge| pledge.state == v0::ProtPledgeState::Captured && pledge.remaining == 0
                ));
            assert_eq!(
                db.fetch_channel_entitlement(CHANNEL)
                    .await
                    .unwrap()
                    .unwrap()
                    .slot_cap,
                25
            );
            // Once
            assert!(db
                .apply_prot_upgrade_goal(&upgrade.id, now, &rules)
                .await
                .unwrap()
                .is_none());
        });
    }

    #[tokio::test]
    async fn upgrade_apply_in_grace_posts_no_tier_row_and_reactivates_at_the_new_cost() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = grace_tank(&db, &rules).await;
            let now = at(1, 13);
            let upgrade = db
                .create_prot_goal(&upgrade_goal(&tank, 25, 500, now))
                .await
                .unwrap();
            fund(&db, C, 500).await;
            pledge(&db, C, &upgrade.id, 500, now).await.unwrap();

            let applied = db
                .apply_prot_upgrade_goal(&upgrade.id, now, &rules)
                .await
                .unwrap()
                .expect("applied");
            // -10 + 500 = 490 >= 1 day at the NEW cost (90)
            assert_eq!(applied.stage, v0::ProtTankStage::Active);
            assert_eq!(applied.daily_cost, 90);
            assert_eq!(applied.warnings_epoch, tank.warnings_epoch + 1);
            assert_eq!(applied.next_burn_day, Some(day(2)));
            assert!(rows_of_kind(&db, &tank.id, v0::ProtEntryKind::TierUpgrade)
                .await
                .is_empty());
            assert_eq!(
                rows_of_kind(&db, &tank.id, v0::ProtEntryKind::Burn)
                    .await
                    .len(),
                2
            );
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 490);
            let entitlement = db
                .fetch_channel_entitlement(CHANNEL)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(entitlement.state, crate::ChannelEntitlementState::Active);
            assert_eq!(entitlement.slot_cap, 25);
        });
    }

    #[tokio::test]
    async fn upgrade_apply_from_frozen_charges_today_once() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = frozen_tank(&db, &rules).await;
            let now = at(8, 13);
            let upgrade = db
                .create_prot_goal(&upgrade_goal(&tank, 25, 500, now))
                .await
                .unwrap();
            fund(&db, C, 500).await;
            pledge(&db, C, &upgrade.id, 500, now).await.unwrap();

            let applied = db
                .apply_prot_upgrade_goal(&upgrade.id, now, &rules)
                .await
                .unwrap()
                .expect("applied");
            assert_eq!(applied.stage, v0::ProtTankStage::Active);
            assert_eq!(applied.next_burn_day, Some(day(9)));
            // The only charge for today: the new cost pro rata, 90 x 11 / 24 -> 42
            assert!(rows_of_kind(&db, &tank.id, v0::ProtEntryKind::TierUpgrade)
                .await
                .is_empty());
            assert_eq!(
                row(&db, &prot_key_burn(&tank.id, &day(8)))
                    .await
                    .unwrap()
                    .amount,
                42
            );
            assert!(row(&db, &prot_key_burn(&tank.id, &day(7))).await.is_none());
            assert_eq!(
                balance(&db, &prot_tank_account(&tank.id)).await,
                -170 + 500 - 42
            );
        });
    }

    #[tokio::test]
    async fn an_upgrade_goal_whose_tier_moved_or_tank_ended_returns_everything() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            let now = at(0, 14);
            let upgrade = db
                .create_prot_goal(&upgrade_goal(&tank, 25, 300, now))
                .await
                .unwrap();
            fund(&db, C, 300).await;
            pledge(&db, C, &upgrade.id, 300, now).await.unwrap();

            // The owner's deletion is under way: pledgers never pay for it
            db.begin_prot_settlement(&tank.id, ProtSettleCause::OwnerDelete, now + 1)
                .await
                .unwrap();
            assert!(db
                .apply_prot_upgrade_goal(&upgrade.id, now + 2, &rules)
                .await
                .unwrap()
                .is_none());
            assert_eq!(
                self::goal(&db, &upgrade.id).await.state,
                v0::ProtGoalState::Cancelled
            );
            assert_eq!(balance(&db, &prot_user_account(C)).await, 300);
            assert_eq!(self::tank(&db, &tank.id).await.slot_tier, 10);
        });
    }

    #[tokio::test]
    async fn tier_change_refused_while_an_upgrade_goal_is_open() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            let now = at(0, 14);
            let upgrade = db
                .create_prot_goal(&upgrade_goal(&tank, 25, 300, now))
                .await
                .unwrap();

            for (slots, case) in [(50, "upgrade"), (10, "same")] {
                let refused =
                    change_tier(&db, &tank.id, slots, &format!("owner-{case}"), now).await;
                assert!(
                    is_error(&refused, "InvalidOperation"),
                    "{case}: {refused:?}"
                );
            }
            fund(&db, C, 300).await;
            pledge(&db, C, &upgrade.id, 300, now).await.unwrap();
            let refused = change_tier(&db, &tank.id, 50, "owner-funded", now).await;
            assert!(is_error(&refused, "InvalidOperation"), "{refused:?}");

            db.apply_prot_upgrade_goal(&upgrade.id, now, &rules)
                .await
                .unwrap();
            let upgraded = change_tier(&db, &tank.id, 50, "owner-after", now)
                .await
                .unwrap();
            assert_eq!(upgraded.slot_tier, 50);
        });
    }

    #[tokio::test]
    async fn mid_day_tier_upgrade_charges_ceil_pro_rata() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            let now = at(0, 13) + 1_000;

            let upgraded = change_tier(&db, &tank.id, 25, "owner-n1", now)
                .await
                .unwrap();
            assert_eq!((upgraded.slot_tier, upgraded.daily_cost), (25, 90));
            let charge = row(&db, &prot_key_tier(&tank.id, "owner-n1"))
                .await
                .unwrap();
            // 10 -> 25 with 11 hours left: (90 - 40) x 11 / 24 -> 23
            assert_eq!(charge.amount, 23);
            assert_eq!(charge.actor, OWNER);
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 1_181 - 23);
            assert_eq!(
                db.fetch_channel_entitlement(CHANNEL)
                    .await
                    .unwrap()
                    .unwrap()
                    .slot_cap,
                25
            );

            // A replay changes nothing
            let replay = change_tier(&db, &tank.id, 25, "owner-n1", now)
                .await
                .unwrap();
            assert_eq!(replay.version, upgraded.version);
            assert_eq!(
                rows_of_kind(&db, &tank.id, v0::ProtEntryKind::TierUpgrade)
                    .await
                    .len(),
                1
            );

            // A manual upgrade never borrows: 70 x 11 / 24 -> 33 > 10
            set_tank_balance(&db, &tank.id, 10).await;
            let refused = change_tier(&db, &tank.id, 50, "owner-n2", now).await;
            assert!(is_error(&refused, "InsufficientProt"), "{refused:?}");
            assert_eq!(self::tank(&db, &tank.id).await.slot_tier, 25);
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 10);
        });
    }

    #[tokio::test]
    async fn downgrade_with_cooling_seats_is_pending() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                25,
                &[(A, 1_000), (B, 1_000)],
                at(0, 13),
                &rules,
            )
            .await;
            let members: Vec<String> = (0..11).map(|n| user_id(7_000 + n)).collect();
            for member in &members {
                insert_member(&db, SERVER, member).await;
            }
            let mut seated: Vec<&str> = members.iter().map(String::as_str).collect();
            seated.push(OWNER);
            db.put_seat_list(
                CHANNEL,
                &seat_list(CHANNEL, 2, &seated, at(0, 14)),
                true,
                timestamp(at(0, 14)),
            )
            .await
            .unwrap();
            // Seven released: they cool for 14 days and still count
            let kept: Vec<&str> = seated
                .iter()
                .copied()
                .filter(|user| {
                    *user == OWNER || members[..4].iter().any(|member| member.as_str() == *user)
                })
                .collect();
            assert_eq!(kept.len(), 5);
            db.put_seat_list(
                CHANNEL,
                &seat_list(CHANNEL, 3, &kept, at(0, 15)),
                true,
                timestamp(at(0, 15)),
            )
            .await
            .unwrap();

            let pending = change_tier(&db, &tank.id, 10, "owner-down", at(0, 16))
                .await
                .unwrap();
            assert_eq!(pending.pending_slot_tier, Some(10));
            assert_eq!((pending.slot_tier, pending.daily_cost), (25, 90));
            assert_eq!(
                db.fetch_channel_entitlement(CHANNEL)
                    .await
                    .unwrap()
                    .unwrap()
                    .slot_cap,
                25
            );

            assert!(db
                .apply_pending_prot_tier(&tank.id, at(5, 0), &rules)
                .await
                .unwrap()
                .is_none());
            let applied = db
                .apply_pending_prot_tier(&tank.id, at(15, 1), &rules)
                .await
                .unwrap()
                .expect("the cooldowns ended");
            assert_eq!(
                (
                    applied.slot_tier,
                    applied.daily_cost,
                    applied.pending_slot_tier
                ),
                (10, 40, None)
            );
            assert_eq!(
                db.fetch_channel_entitlement(CHANNEL)
                    .await
                    .unwrap()
                    .unwrap()
                    .slot_cap,
                10
            );
        });
    }

    // -----------------------------------------------------------------------
    // 9.1-9.2 settlement, 7.5 expiry recovery, 6.5 purge, 9.5 termination
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn d7_settlement_returns_fifo_through_the_driver() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            // O 600, A 400, C 200 captured together at t0 (midnight: day 0 is
            // a full 40)
            let (goal, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(OWNER, 600), (A, 400), (C, 200)],
                at(0, 0),
                &rules,
            )
            .await;
            db.put_seat_list(
                CHANNEL,
                &seat_list(CHANNEL, 2, &[OWNER, A], at(0, 1)),
                true,
                timestamp(at(0, 1)),
            )
            .await
            .unwrap();
            for n in 1..=19 {
                burn(&db, &tank.id, n, &rules).await;
                if n == 7 {
                    // C's 200 back by the 7-day rule
                    db.return_unseated_launch_pledges(&goal.id, at(7, 1))
                        .await
                        .unwrap();
                }
            }
            burn(&db, &tank.id, 20, &rules).await;
            fund(&db, D, 300).await;
            contribute(&db, D, &tank.id, 300, at(20, 12), &rules)
                .await
                .unwrap();
            for n in 21..=24 {
                burn(&db, &tank.id, n, &rules).await;
            }
            // 25 burns of 40 = 1,000; 1,200 - 1,000 - 200 + 300 = 300
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 300);

            db.begin_prot_settlement(&tank.id, ProtSettleCause::OwnerDelete, at(24, 12))
                .await
                .unwrap();
            let settlement = db.settle_prot_tank(&tank.id, at(24, 13)).await.unwrap();
            let returns: Vec<(String, i64)> = settlement
                .returns
                .iter()
                .map(|row| (row.credit.clone(), row.amount))
                .collect();
            // The burn consumed the t0 lots; lifetime totals would give O 139, A 92, D 69
            assert_eq!(returns, vec![(prot_user_account(D), 300)]);
            assert!(settlement.writeoff.is_none());
            assert_eq!(settlement.tank.stage, v0::ProtTankStage::Deleted);
            assert_eq!(settlement.tank.ended_at, Some(at(24, 13)));
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 0);
            assert_eq!(
                entitlement_state(&db, CHANNEL).await,
                Some(crate::ChannelEntitlementState::Deleted)
            );
            // The channel is never unprotected (never plaintext)
            assert!(db.fetch_channel(CHANNEL).await.unwrap().is_protected());
        });
    }

    #[tokio::test]
    async fn a_negative_settlement_is_written_off() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = frozen_tank(&db, &rules).await;
            db.begin_prot_settlement(&tank.id, ProtSettleCause::Expiry, at(36, 1))
                .await
                .unwrap();
            let settlement = db.settle_prot_tank(&tank.id, at(36, 2)).await.unwrap();
            assert!(settlement.returns.is_empty());
            let writeoff = settlement.writeoff.expect("the grace debt");
            assert_eq!(writeoff.amount, 170);
            assert_eq!(writeoff.debit, PROT_SYS_WRITEOFF);
            assert_eq!(writeoff.key, prot_key_writeoff(&tank.id));
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 0);
        });
    }

    #[tokio::test]
    async fn expiry_resumes_after_a_crash_between_begin_and_settle() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = frozen_tank(&db, &rules).await;
            // An upgrade goal still holds C's pledge
            let upgrade = db
                .create_prot_goal(&upgrade_goal(&tank, 25, 900, at(10, 1)))
                .await
                .unwrap();
            fund(&db, C, 200).await;
            pledge(&db, C, &upgrade.id, 200, at(10, 2)).await.unwrap();

            let begun = db
                .begin_prot_settlement(&tank.id, ProtSettleCause::Expiry, at(36, 1))
                .await
                .unwrap()
                .expect("begun");
            assert_eq!(begun.stage, v0::ProtTankStage::Settling);
            assert_eq!(
                entitlement_state(&db, CHANNEL).await,
                Some(crate::ChannelEntitlementState::Frozen)
            );

            // The process died here. The clock finds it by stage and resumes:
            // begin again is the stored state, then the goals, then settle
            let settling = db
                .fetch_prot_tanks_by_stage(&[v0::ProtTankStage::Settling], None, 10)
                .await
                .unwrap();
            assert_eq!(
                settling
                    .iter()
                    .map(|tank| tank.id.clone())
                    .collect::<Vec<_>>(),
                vec![tank.id.clone()]
            );
            let again = db
                .begin_prot_settlement(&tank.id, ProtSettleCause::Expiry, at(37, 1))
                .await
                .unwrap()
                .expect("resumed");
            assert_eq!(again.version, begun.version);
            for open in db.fetch_open_prot_goals_by_tank(&tank.id).await.unwrap() {
                db.close_prot_goal(&open.id, v0::ProtGoalState::Cancelled, at(37, 2))
                    .await
                    .unwrap();
            }
            assert_eq!(balance(&db, &prot_user_account(C)).await, 200);
            let settlement = db.settle_prot_tank(&tank.id, at(37, 3)).await.unwrap();
            assert_eq!(settlement.tank.stage, v0::ProtTankStage::Deleted);
            assert_eq!(settlement.tank.settle_cause, Some(ProtSettleCause::Expiry));

            // A racing (or retried) settle finds it settled: the stored outcome
            let retried = db.settle_prot_tank(&tank.id, at(37, 4)).await.unwrap();
            assert_eq!(retried.returns, settlement.returns);
            assert_eq!(retried.writeoff, settlement.writeoff);
            assert!(db
                .begin_prot_settlement(&tank.id, ProtSettleCause::Expiry, at(37, 5))
                .await
                .unwrap()
                .is_none());
        });
    }

    #[tokio::test]
    async fn expiry_resumes_after_a_crash_between_settle_and_purge() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = frozen_tank(&db, &rules).await;
            db.begin_prot_settlement(&tank.id, ProtSettleCause::Expiry, at(36, 1))
                .await
                .unwrap();
            db.settle_prot_tank(&tank.id, at(36, 2)).await.unwrap();

            // The process died before the purge: step 7 finds purge_passes 0
            let due = db.fetch_prot_tanks_to_purge(None, 10).await.unwrap();
            assert_eq!(due.len(), 1);
            assert_eq!(
                (due[0].id.clone(), due[0].purge_passes),
                (tank.id.clone(), 0)
            );
            db.purge_protected_channel_content(CHANNEL).await.unwrap();
            db.mark_prot_tank_purged(&tank.id, at(36, 3)).await.unwrap();
            let once = self::tank(&db, &tank.id).await;
            assert_eq!((once.purge_passes, once.purged_at), (1, Some(at(36, 3))));

            // The second pass, an hour later, and then never again
            assert_eq!(
                db.fetch_prot_tanks_to_purge(None, 10).await.unwrap().len(),
                1
            );
            db.purge_protected_channel_content(CHANNEL).await.unwrap();
            db.mark_prot_tank_purged(&tank.id, at(36, 4)).await.unwrap();
            assert!(db
                .fetch_prot_tanks_to_purge(None, 10)
                .await
                .unwrap()
                .is_empty());
            assert!(db.fetch_channel(CHANNEL).await.unwrap().is_protected());
            assert_eq!(
                entitlement_state(&db, CHANNEL).await,
                Some(crate::ChannelEntitlementState::Deleted)
            );
        });
    }

    /// Text-plane rows written directly (their own routes need a full MLS
    /// handshake); `kind` decides the group's plane
    async fn insert_group_rows(
        db: &Database,
        group: &MlsGroup,
        commit: Option<&MlsCommit>,
        intent: Option<&MlsJoinIntent>,
    ) {
        match db {
            Database::Reference(reference) => {
                reference
                    .mls_groups
                    .lock()
                    .await
                    .insert(group.id.clone(), group.clone());
                if let Some(commit) = commit {
                    reference
                        .mls_commits
                        .lock()
                        .await
                        .insert(commit.id.clone(), commit.clone());
                }
                if let Some(intent) = intent {
                    reference
                        .mls_join_intents
                        .lock()
                        .await
                        .insert(intent.id.clone(), intent.clone());
                }
            }
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                mongo.insert_one("mls_groups", group.clone()).await.unwrap();
                if let Some(commit) = commit {
                    mongo
                        .insert_one("mls_commits", commit.clone())
                        .await
                        .unwrap();
                }
                if let Some(intent) = intent {
                    mongo
                        .insert_one("mls_join_intents", intent.clone())
                        .await
                        .unwrap();
                }
            }
        }
    }

    fn group(id_byte: u8, kind: MlsGroupKind, open: bool) -> MlsGroup {
        let owner = MlsMemberDevice {
            user_id: OWNER.to_string(),
            device_id: OWNER_DEVICE.to_string(),
        };
        MlsGroup {
            id: format!("{id_byte:02x}").repeat(32),
            channel_id: CHANNEL.to_string(),
            open,
            created_by: owner.clone(),
            created_at: timestamp(at(0, 14)),
            current_epoch: 1,
            members: vec![owner],
            closed_at: None,
            superseded_by: None,
            kind,
            generation: Some(0),
            seat_list_ad_sha256: None,
            pending_removals: vec![],
            member_added: vec![],
        }
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn purge_keeps_protected_and_the_tombstone_and_leaves_no_messages() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;

            for (seed, author) in [(1, OWNER), (2, A), (3, OWNER)] {
                db.insert_message(&ciphertext_message(CHANNEL, author, seed))
                    .await
                    .unwrap();
            }
            let elsewhere = nonce();
            db.insert_message(&Message {
                id: elsewhere.clone(),
                channel: CHANNEL_2.to_string(),
                author: A.to_string(),
                content: Some("elsewhere".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();

            let owner = MlsMemberDevice {
                user_id: OWNER.to_string(),
                device_id: OWNER_DEVICE.to_string(),
            };
            let text = group(0x0a, MlsGroupKind::Text, true);
            // A superseded generation goes too
            let old_text = group(0x0b, MlsGroupKind::Text, false);
            let call = group(0x0c, MlsGroupKind::Call, true);
            insert_group_rows(
                &db,
                &text,
                Some(&MlsCommit {
                    id: MlsCommit::composite_id(&text.id, 1),
                    group_id: text.id.clone(),
                    epoch: 1,
                    committer: owner.clone(),
                    commit: "b3BhcXVl".to_string(),
                    size: 6,
                    added: vec![],
                    removed: vec![],
                    created_at: timestamp(at(0, 14)),
                    rejoin_intents: vec![],
                    removed_reasons: vec![],
                }),
                Some(&MlsJoinIntent {
                    id: MlsJoinIntent::composite_id(&text.id, A, OWNER_DEVICE),
                    group_id: text.id.clone(),
                    user_id: A.to_string(),
                    device_id: OWNER_DEVICE.to_string(),
                    key_package_ref: "ref".to_string(),
                    signature: signature(1),
                    created_at: timestamp(at(0, 14)),
                }),
            )
            .await;
            insert_group_rows(&db, &old_text, None, None).await;
            insert_group_rows(&db, &call, None, None).await;
            db.insert_e2ee_envelopes(&[E2EEEnvelope {
                id: nonce(),
                recipient_user_id: A.to_string(),
                recipient_device_id: OWNER_DEVICE.to_string(),
                sender_user_id: OWNER.to_string(),
                sender_device_id: OWNER_DEVICE.to_string(),
                protocol_version: E2EE_PROTOCOL_VERSION,
                sequence: 0,
                ciphertext: "b3BhcXVl".to_string(),
                timestamp: timestamp(at(0, 14)),
                content_type: E2EEContentType::MlsCommit,
                group_id: Some(text.id.clone()),
                epoch: Some(1),
                committer: None,
                added: vec![],
                removed: vec![],
                rejoin_intents: vec![],
                removed_reasons: vec![],
            }])
            .await
            .unwrap();

            set_tank_balance(&db, &tank.id, 0).await;
            db.begin_prot_settlement(&tank.id, ProtSettleCause::Expiry, at(1, 1))
                .await
                .unwrap();
            db.settle_prot_tank(&tank.id, at(1, 2)).await.unwrap();
            let seats_before = db.fetch_channel_seats(CHANNEL).await.unwrap();
            assert!(!seats_before.is_empty());

            let counts = db.purge_protected_channel_content(CHANNEL).await.unwrap();
            assert_eq!(
                (
                    counts.messages,
                    counts.groups,
                    counts.commits,
                    counts.join_intents,
                    counts.envelopes
                ),
                (3, 2, 1, 1, 1)
            );

            // Kept: the flag, the tombstone, the seats, the list, the Call
            // plane and every other channel's messages
            assert!(db.fetch_channel(CHANNEL).await.unwrap().is_protected());
            assert_eq!(
                entitlement_state(&db, CHANNEL).await,
                Some(crate::ChannelEntitlementState::Deleted)
            );
            assert_eq!(db.fetch_channel_seats(CHANNEL).await.unwrap(), seats_before);
            assert!(db.fetch_seat_list(CHANNEL).await.unwrap().is_some());
            assert!(db.fetch_mls_group(&call.id).await.is_ok());
            assert!(db.fetch_message(&elsewhere).await.is_ok());
            assert!(db.fetch_mls_group(&text.id).await.is_err());
            assert!(db.fetch_mls_group(&old_text.id).await.is_err());

            // The second pass finds nothing left
            let counts = db.purge_protected_channel_content(CHANNEL).await.unwrap();
            assert_eq!(
                (
                    counts.messages,
                    counts.groups,
                    counts.commits,
                    counts.join_intents,
                    counts.envelopes
                ),
                (0, 0, 0, 0, 0)
            );
        });
    }

    /// The Reference driver refuses a purge without a Deleted tombstone
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn reference_purge_refuses_a_channel_that_still_carries_traffic() {
        let db = Database::Reference(ReferenceDb::default());
        let rules = rules();
        insert_server(&db, SERVER).await;
        launched(
            &db,
            SERVER,
            CHANNEL,
            10,
            &[(A, 600), (B, 600)],
            at(0, 13),
            &rules,
        )
        .await;
        db.insert_message(&ciphertext_message(CHANNEL, OWNER, 1))
            .await
            .unwrap();
        let refused = db.purge_protected_channel_content(CHANNEL).await;
        assert!(is_error(&refused, "InvalidOperation"), "{refused:?}");
        assert!(db.purge_protected_channel_content(CHANNEL_2).await.is_err());
    }

    #[tokio::test]
    async fn termination_forfeits_the_tank_and_returns_held_pledges() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            let upgrade = db
                .create_prot_goal(&upgrade_goal(&tank, 25, 900, at(0, 14)))
                .await
                .unwrap();
            fund(&db, C, 200).await;
            pledge(&db, C, &upgrade.id, 200, at(0, 15)).await.unwrap();

            let termination = db
                .terminate_prot_tank(&tank.id, ADMIN, "abuse report 7", at(0, 16))
                .await
                .unwrap();
            let forfeit = termination.forfeit.expect("the positive balance");
            assert_eq!(forfeit.key, prot_key_forfeit_tank(&tank.id));
            assert_eq!(forfeit.amount, 1_181);
            assert_eq!(forfeit.credit, PROT_SYS_FORFEITED);
            assert_eq!(forfeit.actor, ADMIN);
            assert!(termination.writeoff.is_none());
            assert_eq!(termination.tank.stage, v0::ProtTankStage::Terminated);
            assert_eq!(termination.tank.terminated_by.as_deref(), Some(ADMIN));
            assert_eq!(termination.tank.purge_passes, 0);
            assert_eq!(balance(&db, &prot_tank_account(&tank.id)).await, 0);
            // Held pledges go back (D11), the channel stays protected
            assert_eq!(termination.closed_goals.len(), 1);
            assert_eq!(balance(&db, &prot_user_account(C)).await, 200);
            assert_eq!(
                self::goal(&db, &upgrade.id).await.state,
                v0::ProtGoalState::Cancelled
            );
            assert!(db.fetch_channel(CHANNEL).await.unwrap().is_protected());
            assert_eq!(
                entitlement_state(&db, CHANNEL).await,
                Some(crate::ChannelEntitlementState::Deleted)
            );
            assert_eq!(
                db.fetch_prot_tanks_to_purge(None, 10).await.unwrap().len(),
                1
            );

            // A Grace tank's debt is written off instead
            let (_, second) = launched(
                &db,
                SERVER,
                CHANNEL_2,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            set_tank_balance(&db, &second.id, 30).await;
            burn(&db, &second.id, 1, &rules).await;
            let termination = db
                .terminate_prot_tank(&second.id, ADMIN, "abuse report 8", at(1, 2))
                .await
                .unwrap();
            assert!(termination.forfeit.is_none());
            assert_eq!(termination.writeoff.expect("the grace debt").amount, 10);
            assert_eq!(balance(&db, &prot_tank_account(&second.id)).await, 0);
        });
    }

    #[tokio::test]
    async fn a_second_termination_returns_the_stored_outcome() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            let first = db
                .terminate_prot_tank(&tank.id, ADMIN, "abuse", at(0, 16))
                .await
                .unwrap();
            let second = db
                .terminate_prot_tank(&tank.id, ADMIN, "abuse", at(0, 17))
                .await
                .unwrap();
            assert_eq!(second.forfeit, first.forfeit);
            assert_eq!(second.tank.version, first.tank.version);
            assert!(second.closed_goals.is_empty());
            assert_eq!(all_entries(&db, PROT_SYS_FORFEITED).await.len(), 1);
        });
    }

    #[tokio::test]
    async fn termination_of_an_unlaunched_tank_captures_or_returns() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;

            // Protect never landed: the launch is undone with full returns
            let (goal, tank) = launching(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(A, 600), (B, 600)],
                at(0, 13),
                &rules,
            )
            .await;
            let refused = db
                .terminate_prot_tank(&tank.id, ADMIN, "abuse", at(0, 14))
                .await;
            assert!(is_error(&refused, "NotFound"), "{refused:?}");
            assert!(db.fetch_prot_tank(&tank.id).await.unwrap().is_none());
            assert_eq!(
                self::goal(&db, &goal.id).await.state,
                v0::ProtGoalState::Cancelled
            );
            assert_eq!(balance(&db, &prot_user_account(A)).await, 600);

            // Protect landed: captured first (no launch-day burn), then forfeited
            let (goal, tank) = launching(
                &db,
                SERVER,
                CHANNEL_2,
                10,
                &[(A, 600), (B, 600)],
                at(1, 13),
                &rules,
            )
            .await;
            db.protect_channel(
                CHANNEL_2,
                &seat_list(CHANNEL_2, 1, &[OWNER], at(1, 13)),
                timestamp(at(1, 13)),
            )
            .await
            .unwrap();
            let termination = db
                .terminate_prot_tank(&tank.id, ADMIN, "abuse", at(1, 14))
                .await
                .unwrap();
            assert_eq!(
                self::goal(&db, &goal.id).await.state,
                v0::ProtGoalState::Launched
            );
            assert_eq!(termination.forfeit.expect("forfeited").amount, 1_200);
            assert!(rows_of_kind(&db, &tank.id, v0::ProtEntryKind::Burn)
                .await
                .is_empty());
            assert_eq!(termination.tank.stage, v0::ProtTankStage::Terminated);
        });
    }

    // -----------------------------------------------------------------------
    // 12.2 notices, 19.2 S2 seams
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn notices_dedupe_and_final_sets_final_warning_at() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let tank = frozen_tank(&db, &rules).await;
            let epoch = tank.warnings_epoch;

            assert!(db
                .record_prot_notice(&tank.id, epoch, ProtNoticeKind::Warn(7), true, at(6, 1))
                .await
                .unwrap());
            assert!(!db
                .record_prot_notice(&tank.id, epoch, ProtNoticeKind::Warn(7), true, at(6, 2))
                .await
                .unwrap());
            assert!(db
                .record_prot_notice(&tank.id, epoch, ProtNoticeKind::Freeze, false, at(6, 1))
                .await
                .unwrap());
            assert_eq!(self::tank(&db, &tank.id).await.final_warning_at, None);

            // A Final computed from an older epoch records nothing
            assert!(!db
                .record_prot_notice(&tank.id, epoch + 1, ProtNoticeKind::Final, true, at(21, 1))
                .await
                .unwrap());
            assert_eq!(self::tank(&db, &tank.id).await.final_warning_at, None);
            assert!(db
                .record_prot_notice(&tank.id, epoch, ProtNoticeKind::Final, true, at(21, 1))
                .await
                .unwrap());
            assert_eq!(
                self::tank(&db, &tank.id).await.final_warning_at,
                Some(at(21, 1))
            );
            assert!(!db
                .record_prot_notice(&tank.id, epoch, ProtNoticeKind::Final, true, at(22, 1))
                .await
                .unwrap());
            assert_eq!(
                self::tank(&db, &tank.id).await.final_warning_at,
                Some(at(21, 1))
            );
        });
    }

    #[tokio::test]
    async fn recent_contribution_and_top_contributor_skip_hidden_and_deleted() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            insert_server(&db, SERVER).await;
            for user in [OWNER, B, C, D] {
                insert_user(&db, user, None).await;
            }
            insert_user(&db, A, Some(v0::UserFlags::Deleted as i32)).await;

            let (_, tank) = launched(
                &db,
                SERVER,
                CHANNEL,
                10,
                &[(OWNER, 600), (A, 400), (C, 200)],
                at(0, 13),
                &rules,
            )
            .await;
            fund(&db, D, 300).await;
            fund(&db, B, 100).await;
            contribute(&db, D, &tank.id, 300, at(0, 15), &rules)
                .await
                .unwrap();
            contribute(&db, B, &tank.id, 100, at(0, 16), &rules)
                .await
                .unwrap();

            let since = at(0, 0);
            assert_eq!(
                db.recent_contribution(OWNER, &tank.id, since)
                    .await
                    .unwrap(),
                600
            );
            assert_eq!(
                db.recent_contribution(D, &tank.id, since).await.unwrap(),
                300
            );
            assert_eq!(
                db.recent_contribution(C, &tank.id, since).await.unwrap(),
                200
            );
            assert_eq!(
                db.recent_contribution(D, &tank.id, at(0, 16))
                    .await
                    .unwrap(),
                0
            );
            assert_eq!(
                db.recent_contribution(B, &tank.id, at(0, 16))
                    .await
                    .unwrap(),
                100
            );

            assert_eq!(
                db.top_contributor(&tank.id, since)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(OWNER)
            );
            // Hidden even from S2's prompt; A (400) is a deleted user
            db.set_prot_contributor_pref(SERVER, OWNER, true, at(0, 17))
                .await
                .unwrap();
            assert_eq!(
                db.top_contributor(&tank.id, since)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(D)
            );
            let prefs = db
                .fetch_prot_contributor_prefs(SERVER, &[OWNER.to_string(), D.to_string()])
                .await
                .unwrap();
            assert_eq!(prefs.len(), 1);
            assert!(prefs[0].hidden);
            db.set_prot_contributor_pref(SERVER, OWNER, false, at(0, 18))
                .await
                .unwrap();
            assert_eq!(
                db.top_contributor(&tank.id, since)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(OWNER)
            );
            assert_eq!(
                db.top_contributor(&tank.id, at(0, 16))
                    .await
                    .unwrap()
                    .as_deref(),
                Some(B)
            );
            assert_eq!(db.top_contributor(&tank.id, at(1, 0)).await.unwrap(), None);
        });
    }

    // -----------------------------------------------------------------------
    // 5.3 conservation (audit 17)
    // -----------------------------------------------------------------------

    /// Every account and document the conservation test checks
    #[derive(Default)]
    struct Tracked {
        accounts: BTreeSet<String>,
        goals: Vec<String>,
        tanks: Vec<String>,
        /// The largest daily cost a tank ever had: its lowest floor
        max_cost: HashMap<String, i64>,
    }

    /// The 5.3 invariants: every account with a document holds the sum of
    /// its rows; the ledger sums to 0 with the sys: sides as signed totals;
    /// a hold holds exactly its Held pledges' remaining (= the goal's
    /// pledged_total while open, 0 once closed); no wallet or hold below 0,
    /// no tank below the lowest floor it ever had
    async fn assert_conserved(
        db: &Database,
        tracked: &mut Tracked,
        rules: &ProtTankRules,
        step: usize,
    ) {
        let sys = [
            PROT_SYS_ISSUED,
            PROT_SYS_ADJUST,
            PROT_SYS_BURNED,
            PROT_SYS_CLAWED,
            PROT_SYS_FORFEITED,
            PROT_SYS_WRITEOFF,
        ];
        let mut rows: HashMap<String, ProtLedgerEntry> = HashMap::new();
        let accounts: Vec<String> = tracked
            .accounts
            .iter()
            .cloned()
            .chain(sys.iter().map(|side| side.to_string()))
            .collect();
        for account in &accounts {
            for row in all_entries(db, account).await {
                rows.insert(row.id.clone(), row);
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
        for account in &tracked.accounts {
            let cached = balance(db, account).await;
            assert_eq!(
                cached,
                signed(account.as_str()),
                "step {step}: {account} != its rows"
            );
            if !account.starts_with("tank:") {
                assert!(cached >= 0, "step {step}: {account} below 0 ({cached})");
            }
            total += cached;
        }
        let system: i64 = sys.into_iter().map(&signed).sum();
        assert_eq!(
            total + system,
            0,
            "step {step}: the ledger does not sum to 0"
        );

        for goal_id in &tracked.goals {
            let stored = goal(db, goal_id).await;
            let held: i64 = db
                .fetch_prot_pledges_by_goal(goal_id)
                .await
                .unwrap()
                .iter()
                .filter(|pledge| pledge.state == v0::ProtPledgeState::Held)
                .map(|pledge| pledge.remaining)
                .sum();
            let hold = balance(db, &prot_hold_account(goal_id)).await;
            assert_eq!(
                hold, held,
                "step {step}: hold of {goal_id} != its Held pledges"
            );
            if PROT_OPEN_GOAL_STATES.contains(&stored.state) {
                assert_eq!(
                    stored.pledged_total, hold,
                    "step {step}: pledged_total of {goal_id}"
                );
            } else {
                assert_eq!(
                    hold, 0,
                    "step {step}: a closed goal {goal_id} still holds Prot"
                );
            }
        }

        for tank_id in &tracked.tanks {
            let Some(stored) = db.fetch_prot_tank(tank_id).await.unwrap() else {
                continue;
            };
            let max_cost = tracked
                .max_cost
                .entry(tank_id.clone())
                .or_insert(stored.daily_cost);
            *max_cost = (*max_cost).max(stored.daily_cost);
            let tank_balance = balance(db, &prot_tank_account(tank_id)).await;
            assert!(
                tank_balance >= rules.floor(*max_cost),
                "step {step}: tank {tank_id} below its floor ({tank_balance})"
            );
        }
    }

    /// The clock for one tank: burns with catch-up, expiry of a Frozen tank
    /// at its deadline (guards are the engine's), pending downgrades
    async fn clock(db: &Database, tank_id: &str, now: i64, rules: &ProtTankRules) -> usize {
        let mut ran = 0;
        let today = prot_utc_day(now);
        let Some(stored) = db.fetch_prot_tank(tank_id).await.unwrap() else {
            return ran;
        };
        if let Some(mut next) = stored.next_burn_day.clone() {
            for _ in 0..400 {
                if next > today {
                    break;
                }
                let outcome = db
                    .burn_prot_tank_day(tank_id, &next, None, now, rules)
                    .await
                    .unwrap();
                if matches!(outcome, ProtBurnOutcome::NotDue { .. }) {
                    break;
                }
                ran += 1;
                next = prot_next_day(&next).unwrap();
            }
        }

        let stored = tank(db, tank_id).await;
        let window = i64::from(rules.grace_days + rules.freeze_days) * DAY;
        if stored.stage == v0::ProtTankStage::Frozen
            && stored.exhausted_at.is_some_and(|at| at + window <= now)
        {
            db.begin_prot_settlement(tank_id, ProtSettleCause::Expiry, now)
                .await
                .unwrap();
            for open in db.fetch_open_prot_goals_by_tank(tank_id).await.unwrap() {
                db.close_prot_goal(&open.id, v0::ProtGoalState::Cancelled, now)
                    .await
                    .unwrap();
            }
            db.settle_prot_tank(tank_id, now).await.unwrap();
            db.purge_protected_channel_content(&channel_of(&stored))
                .await
                .unwrap();
            db.mark_prot_tank_purged(tank_id, now).await.unwrap();
            ran += 1;
        }
        if stored.pending_slot_tier.is_some() {
            db.apply_pending_prot_tier(tank_id, now, rules)
                .await
                .unwrap();
        }
        ran
    }

    fn pick<'a, T>(rng: &mut StdRng, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            None
        } else {
            Some(&items[rng.gen_range(0..items.len())])
        }
    }

    #[tokio::test]
    async fn prot_tank_ledger_is_conserved() {
        database_test!(|db| async move {
            setup(&db).await;
            let rules = rules();
            let cutoff = i64::from(rules.withdraw_cutoff_hours) * HOUR;
            insert_server(&db, SERVER).await;
            let mut tracked = Tracked::default();
            for user in USERS {
                tracked.accounts.insert(prot_user_account(user));
                fund(&db, user, 3_000).await;
            }
            let mut rng = StdRng::seed_from_u64(0x5442_4e4b);
            let mut orders: Vec<(String, String, i64, bool)> = Vec::new();
            let mut deleted: HashSet<&str> = HashSet::new();
            let mut counts: HashMap<&'static str, (usize, usize)> = HashMap::new();
            let mut channels = 0_u32;
            let mut now = at(0, 9);

            // A purchase pledged and then refunded: the clawback can only be
            // recovered from the held pledge of an open goal (10.1)
            let order = "01ORDERPREFIX0000000000000".to_string();
            db.apply_prot_posting(&purchase(B, &order, 1_000, now))
                .await
                .unwrap();
            orders.push((B.to_string(), order.clone(), 1_000, true));
            let first = db
                .create_prot_goal(&launch_goal(SERVER, 10, 4_000, now))
                .await
                .unwrap();
            tracked.goals.push(first.id.clone());
            tracked.accounts.insert(prot_hold_account(&first.id));
            now = at(4, 9);
            pledge(&db, B, &first.id, 3_500, now).await.unwrap();
            db.apply_prot_posting(&admin_posting(
                prot_user_account(B),
                PROT_SYS_ADJUST.to_string(),
                500,
                0,
            ))
            .await
            .unwrap();
            db.clawback_prot_purchase(B, &order, 1_000, now)
                .await
                .unwrap();
            assert_conserved(&db, &mut tracked, &rules, 0).await;

            for step in 1..=CONSERVATION_STEPS {
                let live: Vec<&str> = USERS
                    .iter()
                    .copied()
                    .filter(|user| !deleted.contains(user))
                    .collect();
                let user = *pick(&mut rng, &live).unwrap();
                let open_goals = db.fetch_open_prot_goals_by_server(SERVER).await.unwrap();
                let mut tanks = Vec::new();
                for tank_id in &tracked.tanks {
                    if let Some(stored) = db.fetch_prot_tank(tank_id).await.unwrap() {
                        tanks.push(stored);
                    }
                }
                let running: Vec<ProtTank> = tanks
                    .iter()
                    .filter(|tank| {
                        matches!(
                            tank.stage,
                            v0::ProtTankStage::Active
                                | v0::ProtTankStage::Grace
                                | v0::ProtTankStage::Frozen
                        )
                    })
                    .cloned()
                    .collect();
                let in_state =
                    |state: v0::ProtGoalState, kind: Option<v0::ProtGoalKind>| -> Vec<ProtGoal> {
                        open_goals
                            .iter()
                            .filter(|goal| {
                                goal.state == state && kind.is_none_or(|kind| goal.kind == kind)
                            })
                            .cloned()
                            .collect()
                    };

                let (name, outcome): (&'static str, Option<Result<()>>) = match rng
                    .gen_range(0..100)
                {
                    0..=7 => {
                        let order = format!("01ORDER{step:019}");
                        let amount = rng.gen_range(100..2_000);
                        orders.push((user.to_string(), order.clone(), amount, false));
                        (
                            "purchase",
                            Some(
                                db.apply_prot_posting(&purchase(user, &order, amount, now))
                                    .await
                                    .map(|_| ()),
                            ),
                        )
                    }
                    8..=11 => {
                        fund(&db, user, rng.gen_range(50..1_000)).await;
                        ("credit", Some(Ok(())))
                    }
                    12..=21 => match pick(&mut rng, &running).cloned() {
                        Some(target) => {
                            clock(&db, &target.id, now, &rules).await;
                            let amount = rng.gen_range(50..500);
                            (
                                "contribute",
                                Some(
                                    contribute(&db, user, &target.id, amount, now, &rules)
                                        .await
                                        .map(|_| ()),
                                ),
                            )
                        }
                        None => ("contribute", None),
                    },
                    22..=33 => {
                        let mut ran = 0;
                        for tank_id in tracked.tanks.clone() {
                            ran += clock(&db, &tank_id, now, &rules).await;
                        }
                        for goal_id in tracked.goals.clone() {
                            let stored = goal(&db, &goal_id).await;
                            if stored.state == v0::ProtGoalState::Launched
                                && !stored.refund7_done
                                && stored.launched_at.is_some_and(|at| at + 7 * DAY <= now)
                            {
                                db.return_unseated_launch_pledges(&goal_id, now)
                                    .await
                                    .unwrap();
                                ran += 1;
                            }
                        }
                        ("clock", Some(Ok(())).filter(|_: &Result<()>| ran > 0))
                    }
                    34..=39 => {
                        if open_goals
                            .iter()
                            .any(|goal| goal.kind == v0::ProtGoalKind::Launch)
                        {
                            ("create launch goal", None)
                        } else {
                            let days = rng.gen_range(2..=10_i64);
                            let created = db
                                .create_prot_goal(&launch_goal(SERVER, 10, days * 40, now))
                                .await;
                            if let Ok(created) = &created {
                                tracked.goals.push(created.id.clone());
                                tracked.accounts.insert(prot_hold_account(&created.id));
                            }
                            ("create launch goal", Some(created.map(|_| ())))
                        }
                    }
                    40..=51 => match pick(&mut rng, &in_state(v0::ProtGoalState::Funding, None))
                        .cloned()
                    {
                        Some(target) => {
                            let amount = rng.gen_range(50..600);
                            (
                                "pledge",
                                Some(pledge(&db, user, &target.id, amount, now).await.map(|_| ())),
                            )
                        }
                        None => ("pledge", None),
                    },
                    52..=56 => {
                        let mut held = Vec::new();
                        for funding in in_state(v0::ProtGoalState::Funding, None) {
                            held.extend(
                                db.fetch_prot_pledges_by_goal(&funding.id)
                                    .await
                                    .unwrap()
                                    .into_iter()
                                    .filter(|pledge| {
                                        pledge.state == v0::ProtPledgeState::Held
                                            && !deleted.contains(pledge.user_id.as_str())
                                    }),
                            );
                        }
                        match pick(&mut rng, &held).cloned() {
                            Some(target) => (
                                "withdraw",
                                Some(
                                    db.withdraw_prot_pledge(
                                        &target.id,
                                        &target.user_id,
                                        now,
                                        cutoff,
                                    )
                                    .await
                                    .map(|_| ()),
                                ),
                            ),
                            None => ("withdraw", None),
                        }
                    }
                    57..=61 => match pick(
                        &mut rng,
                        &in_state(v0::ProtGoalState::Funded, Some(v0::ProtGoalKind::Launch)),
                    )
                    .cloned()
                    {
                        Some(target) => {
                            channels += 1;
                            let channel = channel_id(10_000 + channels);
                            insert_channel(&db, &channel, SERVER).await;
                            let launched = db
                                .launch_prot_goal(&ProtLaunchInput {
                                    goal_id: target.id.clone(),
                                    channel_id: channel,
                                    owner_id: OWNER.to_string(),
                                    rules: rules.clone(),
                                    now,
                                })
                                .await;
                            if let Ok((_, tank)) = &launched {
                                tracked.tanks.push(tank.id.clone());
                                tracked.accounts.insert(prot_tank_account(&tank.id));
                            }
                            ("launch", Some(launched.map(|_| ())))
                        }
                        None => ("launch", None),
                    },
                    62..=65 => match pick(&mut rng, &in_state(v0::ProtGoalState::Launching, None))
                        .cloned()
                    {
                        Some(target) => {
                            let channel = target.channel_id.clone().unwrap();
                            let landed = db
                                .protect_channel(
                                    &channel,
                                    &seat_list(&channel, 1, &[OWNER], now),
                                    timestamp(now),
                                )
                                .await;
                            ("protect", Some(landed.map(|_| ())))
                        }
                        None => ("protect", None),
                    },
                    66..=69 => match pick(&mut rng, &in_state(v0::ProtGoalState::Launching, None))
                        .cloned()
                    {
                        Some(target) => {
                            let captured = db
                                .capture_launch_pledges(
                                    target.channel_id.as_deref().unwrap(),
                                    now,
                                    &rules,
                                )
                                .await;
                            match captured {
                                Ok(Some(_)) => ("capture", Some(Ok(()))),
                                Ok(None) => ("capture", None),
                                Err(error) => ("capture", Some(Err(error))),
                            }
                        }
                        None => ("capture", None),
                    },
                    70..=72 => match pick(&mut rng, &in_state(v0::ProtGoalState::Launching, None))
                        .cloned()
                    {
                        Some(target) => (
                            "abandon",
                            Some(
                                db.close_prot_goal(&target.id, v0::ProtGoalState::Cancelled, now)
                                    .await
                                    .map(|_| ()),
                            ),
                        ),
                        None => ("abandon", None),
                    },
                    73..=75 => {
                        let mut closable = in_state(v0::ProtGoalState::Funding, None);
                        closable.extend(in_state(v0::ProtGoalState::Funded, None));
                        match pick(&mut rng, &closable).cloned() {
                            Some(target) => {
                                let to = if target.state == v0::ProtGoalState::Funding
                                    && now >= target.deadline_at
                                {
                                    v0::ProtGoalState::Expired
                                } else {
                                    v0::ProtGoalState::Cancelled
                                };
                                (
                                    "close",
                                    Some(db.close_prot_goal(&target.id, to, now).await.map(|_| ())),
                                )
                            }
                            None => ("close", None),
                        }
                    }
                    76..=80 => {
                        let open: Vec<usize> = (0..orders.len())
                            .filter(|index| {
                                !orders[*index].3 && !deleted.contains(orders[*index].0.as_str())
                            })
                            .collect();
                        match pick(&mut rng, &open).copied() {
                            Some(index) => {
                                let (buyer, order, amount, _) = orders[index].clone();
                                let clawed =
                                    db.clawback_prot_purchase(&buyer, &order, amount, now).await;
                                if clawed.is_ok() {
                                    orders[index].3 = true;
                                }
                                ("clawback", Some(clawed.map(|_| ())))
                            }
                            None => ("clawback", None),
                        }
                    }
                    81..=84 => match pick(&mut rng, &running).cloned() {
                        Some(target) => {
                            clock(&db, &target.id, now, &rules).await;
                            let slots = *pick(&mut rng, &PROT_SLOT_TIERS).unwrap();
                            (
                                "tier",
                                Some(
                                    change_tier(
                                        &db,
                                        &target.id,
                                        slots,
                                        &format!("owner-{step}"),
                                        now,
                                    )
                                    .await
                                    .map(|_| ()),
                                ),
                            )
                        }
                        None => ("tier", None),
                    },
                    85..=87 => {
                        let candidates: Vec<ProtTank> = running
                            .iter()
                            .filter(|tank| {
                                tank.stage == v0::ProtTankStage::Active && tank.slot_tier < 100
                            })
                            .cloned()
                            .collect();
                        match pick(&mut rng, &candidates).cloned() {
                            Some(target)
                                if !open_goals.iter().any(|goal| {
                                    goal.tank_id.as_deref() == Some(target.id.as_str())
                                }) =>
                            {
                                let slots = PROT_SLOT_TIERS
                                    .iter()
                                    .copied()
                                    .find(|tier| *tier > target.slot_tier)
                                    .unwrap();
                                let created = db
                                    .create_prot_goal(&upgrade_goal(
                                        &target,
                                        slots,
                                        rng.gen_range(100..800),
                                        now,
                                    ))
                                    .await;
                                if let Ok(created) = &created {
                                    tracked.goals.push(created.id.clone());
                                    tracked.accounts.insert(prot_hold_account(&created.id));
                                }
                                ("create upgrade goal", Some(created.map(|_| ())))
                            }
                            _ => ("create upgrade goal", None),
                        }
                    }
                    88..=90 => match pick(
                        &mut rng,
                        &in_state(v0::ProtGoalState::Funded, Some(v0::ProtGoalKind::Upgrade)),
                    )
                    .cloned()
                    {
                        Some(target) => (
                            "apply",
                            Some(
                                db.apply_prot_upgrade_goal(&target.id, now, &rules)
                                    .await
                                    .map(|_| ()),
                            ),
                        ),
                        None => ("apply", None),
                    },
                    91..=92 => match pick(&mut rng, &running).cloned() {
                        Some(target) => {
                            // Channel::delete's settlement of a launched tank (9.4)
                            db.begin_prot_settlement(&target.id, ProtSettleCause::OwnerDelete, now)
                                .await
                                .unwrap();
                            for open in db.fetch_open_prot_goals_by_tank(&target.id).await.unwrap()
                            {
                                db.close_prot_goal(&open.id, v0::ProtGoalState::Cancelled, now)
                                    .await
                                    .unwrap();
                            }
                            (
                                "settle",
                                Some(db.settle_prot_tank(&target.id, now).await.map(|_| ())),
                            )
                        }
                        None => ("settle", None),
                    },
                    93 => match pick(&mut rng, &running).cloned() {
                        Some(target) => (
                            "terminate",
                            Some(
                                db.terminate_prot_tank(&target.id, ADMIN, "abuse", now)
                                    .await
                                    .map(|_| ()),
                            ),
                        ),
                        None => ("terminate", None),
                    },
                    94 => {
                        if deleted.len() >= 2 || user == OWNER {
                            ("delete account", None)
                        } else {
                            let forfeits =
                                db.forfeit_held_prot_pledges(user, now).await.map(|_| ());
                            let wallet = db.forfeit_prot_wallet(user, now).await.map(|_| ());
                            deleted.insert(user);
                            ("delete account", Some(forfeits.and(wallet)))
                        }
                    }
                    _ => {
                        now += rng.gen_range(1..=3) * DAY;
                        ("wait", None)
                    }
                };

                let count = counts.entry(name).or_insert((0, 0));
                match outcome {
                    Some(Ok(())) => count.0 += 1,
                    Some(Err(error)) => {
                        // Refusals are expected while the state moves; a
                        // driver fault never is
                        let shown = format!("{:?}", error.error_type);
                        assert!(
                            !shown.starts_with("InternalError")
                                && !shown.starts_with("DatabaseError"),
                            "step {step} {name}: {error:?}"
                        );
                        count.1 += 1;
                    }
                    None => {}
                }
                now += rng.gen_range(0..6 * HOUR);
                assert_conserved(&db, &mut tracked, &rules, step).await;
            }

            for name in [
                "contribute",
                "pledge",
                "withdraw",
                "launch",
                "capture",
                "clock",
                "close",
            ] {
                assert!(
                    counts.get(name).is_some_and(|count| count.0 > 0),
                    "{name} never ran: {counts:?}"
                );
            }
            assert!(all_entries(&db, PROT_SYS_CLAWED)
                .await
                .iter()
                .any(|row| row.kind == v0::ProtEntryKind::ClawbackHold));
            let mut ended = 0;
            for tank_id in &tracked.tanks {
                if let Some(stored) = db.fetch_prot_tank(tank_id).await.unwrap() {
                    if matches!(
                        stored.stage,
                        v0::ProtTankStage::Deleted | v0::ProtTankStage::Terminated
                    ) {
                        ended += 1;
                    }
                }
            }
            assert!(ended > 0, "no tank was ever settled or terminated");
        });
    }
}
