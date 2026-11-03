//! Prot fuel tanks on the delete paths (S5b contracts 9.3, 9.4): a deleted
//! channel's tank is settled and a deleted server's open goals are closed
//! with returns, before S1's protected cascade erases the entitlements.
//!
//! Money rules this module keeps:
//! - no tank and no goal: nothing is written (every S1 delete runs through
//!   here, on any driver, replica set or not)
//! - a never-launched (Launching) tank is captured when its channel is
//!   protected and settled like a launched one; otherwise its goal is
//!   closed with full returns and the tank removed
//! - a launched tank: settlement begins (the stage write is the claim a
//!   retry or the clock resumes from), its open goals are closed with
//!   returns, and the balance goes back FIFO (9.2)
//! - Prot credited to a deleted or missing account is forfeited right after
//!   the commit (the S5a second pass), never handed to anyone else
//! - none of it depends on a flag: settling Prot already taken never does

use std::collections::BTreeSet;

use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};

use crate::events::client::EventV1;
use crate::{
    prot_tank_account, prot_tank_summary, prot_user_account, Database, ProtLedgerEntry,
    ProtSettleCause, ProtTank, ProtTankRules, ProtTankTarget,
};

/// Rounds of capture-or-abandon for a never-launched tank: each round loses
/// only to a racing write that moved the launch on (a protect, a capture, an
/// abandon), so a third round finds it settled one way or the other
const PROT_LAUNCH_ATTEMPTS: usize = 3;

/// Channels whose settlement fails on purpose (tests only), so a test can
/// show that a settlement error aborts `Channel::delete` before its cascade
#[cfg(test)]
static FAIL_SETTLEMENT_FOR_TESTS: std::sync::Mutex<BTreeSet<String>> =
    std::sync::Mutex::new(BTreeSet::new());

/// Users whose second pass fails on purpose (tests only), so a test can show
/// that a retry after a settlement committed still forfeits a gone share
#[cfg(test)]
static FAIL_WALLET_PASS_FOR_TESTS: std::sync::Mutex<BTreeSet<String>> =
    std::sync::Mutex::new(BTreeSet::new());

/// Current epoch milliseconds
fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Channel::delete. No tank (or Deleted/Terminated): Ok. Launching tank
/// (audit 8): channel protected -> capture_launch_pledges first, then as a
/// launched tank; not protected -> close its Launching goal Cancelled
/// (returns, tank removed) and stop. Launched tank: begin (OwnerDelete) ->
/// close its open goals with returns -> settle -> publish (wallets,
/// ProtTankUpdate with tank: None) -> second passes.
///
/// A Launching tank begins settling (9.1) before its capture, so the
/// capture posts no launch-day burn (8.6) and a crash after the begin is
/// resumed by a retry or the clock (7.1 step 4) like any other.
pub async fn prot_settle_channel_on_delete(db: &Database, channel_id: &str) -> Result<()> {
    let now = now_ms();
    let mut credited = BTreeSet::new();
    let settled = settle_channel(db, channel_id, now, &mut credited).await;
    // Returns that committed before an error still get their second pass
    let passes = settle_wallets(db, &credited, now).await;
    settled.and(passes)
}

/// Server::delete: every open goal of the server closed Cancelled (returns;
/// a Launching goal with a protected channel is captured first and settled
/// with its channel below), then prot_settle_channel_on_delete for each id
/// in `channel_ids`
pub async fn prot_settle_server_on_delete(
    db: &Database,
    server_id: &str,
    channel_ids: &BTreeSet<String>,
) -> Result<()> {
    let now = now_ms();
    let mut credited = BTreeSet::new();
    let settled = settle_server(db, server_id, channel_ids, now, &mut credited).await;
    let passes = settle_wallets(db, &credited, now).await;
    settled.and(passes)
}

/// Publish the wallet's balance and version to its owner only, read after
/// the posting committed (S5a `publish_balance` twin). A failed read
/// publishes nothing (the client refetches `/@me`).
pub async fn prot_publish_wallet(db: &Database, user_id: &str) {
    match db.fetch_prot_account(&prot_user_account(user_id)).await {
        Ok(Some(account)) => {
            EventV1::ProtBalanceUpdate {
                balance: account.balance,
                version: account.version,
            }
            .private(user_id.to_string())
            .await
        }
        // A posting that named the wallet created its account
        Ok(None) => log::warn!(
            "prot: the Prot wallet of {user_id} has no account after a posting; nothing published"
        ),
        Err(err) => {
            log::warn!("prot: could not read the Prot wallet of {user_id} to publish it: {err:?}")
        }
    }
}

/// `ProtTankUpdate` with the tank's summary on its channel's topic (its
/// viewers only, 12.1). A server tank (S10) has no channel topic; a failed
/// read publishes nothing (clients refetch on open and every 5 minutes).
pub async fn prot_publish_tank(db: &Database, tank: &ProtTank) {
    let channel_id = match &tank.target {
        ProtTankTarget::Channel { channel_id } => channel_id.clone(),
        ProtTankTarget::Server { .. } => return,
    };
    let rules = match ProtTankRules::load().await {
        Ok(rules) => rules,
        Err(err) => {
            log::warn!(
                "prot: tank {} not published, the rules did not load: {err:?}",
                tank.id
            );
            return;
        }
    };
    let account = match db.fetch_prot_account(&prot_tank_account(&tank.id)).await {
        Ok(account) => account,
        Err(err) => {
            log::warn!(
                "prot: could not read tank {} to publish it: {err:?}",
                tank.id
            );
            return;
        }
    };

    EventV1::ProtTankUpdate {
        channel: channel_id.clone(),
        tank: Some(prot_tank_summary(tank, account.as_ref(), &rules, now_ms())),
    }
    .p(channel_id)
    .await;
}

/// The second pass (9.3): after Prot credited to the wallet of `user_id`
/// has committed, a deleted (or missing) account has its wallet forfeited.
/// Checked after the write, so either the deletion's own forfeit sees the
/// credit, or this sees the deletion.
pub async fn prot_forfeit_if_gone(db: &Database, user_id: &str, now: i64) -> Result<()> {
    if user_is_live(db, user_id).await? {
        return Ok(());
    }
    forfeit_wallet(db, user_id, now).await
}

/// Whether `user_id` names an account that exists and is not deleted. Any
/// other read failure is an error (never "gone": a wallet is only ever
/// forfeited for an account known to be deleted or missing).
async fn user_is_live(db: &Database, user_id: &str) -> Result<bool> {
    match db.fetch_user(user_id).await {
        Ok(user) => Ok(user.flags.unwrap_or_default() & v0::UserFlags::Deleted as i32 == 0),
        Err(err) if matches!(err.error_type, ErrorType::NotFound) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Forfeit the whole wallet of a gone account (S5a `forfeit_prot_wallet`)
async fn forfeit_wallet(db: &Database, user_id: &str, now: i64) -> Result<()> {
    if let Some(outcome) = db.forfeit_prot_wallet(user_id, now).await? {
        let entry = outcome.entry();
        log::warn!(
            "prot: Prot credited to deleted account {user_id} was forfeited ({} Prot, key {})",
            entry.amount,
            entry.key
        );
    }
    Ok(())
}

/// Every user whose wallet one of `entries` credited
fn note_credits(entries: &[ProtLedgerEntry], credited: &mut BTreeSet<String>) {
    for entry in entries {
        if let Some(user_id) = entry.credit.strip_prefix("user:") {
            credited.insert(user_id.to_string());
        }
    }
}

/// After the delete's postings: a live recipient gets its balance, a gone
/// one has its wallet forfeited (its share is never handed to the others).
/// Every user is tried; the first failure is returned, so the delete fails
/// closed and the log names the wallet left to forfeit.
async fn settle_wallets(db: &Database, credited: &BTreeSet<String>, now: i64) -> Result<()> {
    let mut first_error = None;
    for user_id in credited {
        #[cfg(test)]
        let forced_to_fail = FAIL_WALLET_PASS_FOR_TESTS
            .lock()
            .expect("the test hook")
            .contains(user_id);
        #[cfg(not(test))]
        let forced_to_fail = false;

        let pass = if forced_to_fail {
            Err(create_error!(InternalError))
        } else {
            match user_is_live(db, user_id).await {
                Ok(true) => {
                    prot_publish_wallet(db, user_id).await;
                    Ok(())
                }
                Ok(false) => forfeit_wallet(db, user_id, now).await,
                Err(err) => Err(err),
            }
        };
        if let Err(err) = pass {
            log::error!("PROT_FORFEIT_DEFERRED user={user_id}: {err:?}");
            if first_error.is_none() {
                first_error = Some(err);
            }
        }
    }
    match first_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// The channel's tank is gone from its viewers' point of view: the delete
/// removes the channel (or an abandon removed the tank)
async fn publish_tank_removed(channel_id: &str) {
    EventV1::ProtTankUpdate {
        channel: channel_id.to_string(),
        tank: None,
    }
    .p(channel_id.to_string())
    .await;
}

/// Close one open goal Cancelled with full returns. A goal that ended in
/// between (a racing close, apply or capture) has nothing left to return.
async fn close_open_goal(
    db: &Database,
    goal_id: &str,
    now: i64,
    credited: &mut BTreeSet<String>,
) -> Result<()> {
    match db
        .close_prot_goal(goal_id, v0::ProtGoalState::Cancelled, now)
        .await
    {
        Ok(outcome) => {
            note_credits(&outcome.returned, credited);
            Ok(())
        }
        Err(err) if matches!(err.error_type, ErrorType::ProtGoalClosed) => Ok(()),
        Err(err) => Err(err),
    }
}

/// What became of a never-launched tank
enum Launch {
    /// The pledges are in the tank (captured now or by a racing capture), or
    /// its goal already ended without removing it: settle it
    Landed,
    /// The goal was closed with returns and the tank removed
    Removed,
}

/// Rules for capturing a Settling tank. Such a capture never burns (8.6),
/// so they come from the built-in defaults with burning off and never from
/// the config: an invalid Prot config must not block a delete (or an
/// account deletion through `Server::delete`).
fn settling_capture_rules() -> Result<ProtTankRules> {
    Ok(ProtTankRules {
        burning: false,
        ..ProtTankRules::from_config(&revolt_config::ProtectionFeatures::default())?
    })
}

/// A never-launched tank, already Settling: a protected channel has its
/// pledges captured (no launch-day burn for a Settling tank, 8.6); an
/// unprotected one has its Launching goal closed with returns, which
/// removes the tank and its entitlement. Abandon re-reads `protected` in its
/// transaction, so a protect that lands in between makes the close refuse
/// and the next round captures (BR2).
async fn land_or_abandon(
    db: &Database,
    tank: &ProtTank,
    channel_id: &str,
    now: i64,
    credited: &mut BTreeSet<String>,
) -> Result<Launch> {
    let rules = settling_capture_rules()?;

    for _ in 0..PROT_LAUNCH_ATTEMPTS {
        if db
            .capture_launch_pledges(channel_id, now, &rules)
            .await?
            .is_some()
        {
            return Ok(Launch::Landed);
        }

        // Not captured: the channel is not protected, or a racing write
        // moved the launch on
        match db.fetch_prot_tank(&tank.id).await? {
            None => return Ok(Launch::Removed),
            Some(current) if current.launched_at.is_some() => return Ok(Launch::Landed),
            Some(_) => {}
        }

        let goal = db
            .fetch_open_prot_goals_by_tank(&tank.id)
            .await?
            .into_iter()
            .find(|goal| {
                goal.kind == v0::ProtGoalKind::Launch && goal.state == v0::ProtGoalState::Launching
            });
        let Some(goal) = goal else {
            // Nothing holds the pledges any more: whatever the tank holds
            // goes back FIFO like any settlement
            log::warn!(
                "prot: tank {} of channel {channel_id} never launched and has no Launching goal; \
                 settling it",
                tank.id
            );
            return Ok(Launch::Landed);
        };

        match db
            .close_prot_goal(&goal.id, v0::ProtGoalState::Cancelled, now)
            .await
        {
            Ok(outcome) => {
                note_credits(&outcome.returned, credited);
                if outcome.removed_tank.is_some() {
                    return Ok(Launch::Removed);
                }
            }
            // Protected after all (a protect landed): capture next round.
            // Or a racing close or capture ended the goal: look again.
            Err(err)
                if matches!(
                    err.error_type,
                    ErrorType::InvalidOperation | ErrorType::ProtGoalClosed
                ) => {}
            Err(err) => return Err(err),
        }
    }

    log::error!(
        "PROT_DELETE_UNSETTLED channel={channel_id} tank={}: the launch kept moving",
        tank.id
    );
    Err(create_error!(InternalError))
}

/// A tank that is already over: the recipients of its Settlement rows get
/// their second pass again (9.3). A retry of a delete whose settlement
/// committed but whose second pass failed would otherwise find the tank
/// Deleted and leave a gone recipient's share in its wallet. Reads only for
/// a tank that was never settled (a Terminated one) or whose passes ran: a
/// live wallet is republished, an emptied gone one is left as it is.
async fn note_settled_recipients(
    db: &Database,
    tank_id: &str,
    credited: &mut BTreeSet<String>,
) -> Result<()> {
    let settled: Vec<ProtLedgerEntry> = db
        .fetch_prot_entries_by_tank(tank_id)
        .await?
        .into_iter()
        .filter(|entry| entry.kind == v0::ProtEntryKind::Settlement)
        .collect();
    note_credits(&settled, credited);
    Ok(())
}

/// Settle the tank of one channel (9.4). Every write is idempotent or a CAS,
/// so a retry of a delete that failed part way resumes it, and the clock
/// (7.1 step 4) finishes a Settling tank nobody retries.
async fn settle_channel(
    db: &Database,
    channel_id: &str,
    now: i64,
    credited: &mut BTreeSet<String>,
) -> Result<()> {
    let tank = match db.fetch_prot_tank_by_channel(channel_id).await? {
        Some(tank) => tank,
        None => return Ok(()),
    };
    if matches!(
        tank.stage,
        v0::ProtTankStage::Deleted | v0::ProtTankStage::Terminated
    ) {
        return note_settled_recipients(db, &tank.id, credited).await;
    }

    #[cfg(test)]
    {
        let fail = FAIL_SETTLEMENT_FOR_TESTS
            .lock()
            .expect("the test hook")
            .contains(channel_id);
        if fail {
            return Err(create_error!(InternalError));
        }
    }

    // Launching, Active, Grace or Frozen -> Settling; already Settling ->
    // resume; ended in between -> only the second passes are left
    let tank = match db
        .begin_prot_settlement(&tank.id, ProtSettleCause::OwnerDelete, now)
        .await?
    {
        Some(tank) => tank,
        None => return note_settled_recipients(db, &tank.id, credited).await,
    };

    if tank.launched_at.is_none() {
        if let Launch::Removed = land_or_abandon(db, &tank, channel_id, now, credited).await? {
            publish_tank_removed(channel_id).await;
            return Ok(());
        }
    }

    for goal in db.fetch_open_prot_goals_by_tank(&tank.id).await? {
        close_open_goal(db, &goal.id, now, credited).await?;
    }

    let settlement = db.settle_prot_tank(&tank.id, now).await?;
    note_credits(&settlement.returns, credited);
    log::info!(
        "prot: tank {} of deleted channel {channel_id} settled ({} returns, write-off {})",
        tank.id,
        settlement.returns.len(),
        settlement
            .writeoff
            .as_ref()
            .map_or(0, |writeoff| writeoff.amount)
    );

    publish_tank_removed(channel_id).await;
    Ok(())
}

/// Close the server's open goals, then settle each channel's tank (9.4).
/// A Launching goal is left to its channel's settlement (capture or
/// abandon there), so its channel joins the ids; so does the channel of any
/// tank of the server that is not over yet (never expected: every tank has
/// an entitlement, whose channel the caller already lists).
async fn settle_server(
    db: &Database,
    server_id: &str,
    channel_ids: &BTreeSet<String>,
    now: i64,
    credited: &mut BTreeSet<String>,
) -> Result<()> {
    let mut channels = channel_ids.clone();

    for goal in db.fetch_open_prot_goals_by_server(server_id).await? {
        if goal.state == v0::ProtGoalState::Launching {
            if let Some(channel_id) = &goal.channel_id {
                channels.insert(channel_id.clone());
                continue;
            }
        }
        close_open_goal(db, &goal.id, now, credited).await?;
    }

    for tank in db.fetch_prot_tanks_by_server(server_id).await? {
        if let ProtTankTarget::Channel { channel_id } = &tank.target {
            if !matches!(
                tank.stage,
                v0::ProtTankStage::Deleted | v0::ProtTankStage::Terminated
            ) {
                channels.insert(channel_id.clone());
            }
        }
    }

    for channel_id in &channels {
        settle_channel(db, channel_id, now, credited).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use iso8601_timestamp::Timestamp;
    use revolt_models::v0;
    use revolt_result::ErrorType;
    use ulid::Ulid;

    use super::{
        prot_settle_channel_on_delete, prot_settle_server_on_delete, FAIL_SETTLEMENT_FOR_TESTS,
        FAIL_WALLET_PASS_FOR_TESTS,
    };
    use crate::{
        prot_key_admin, prot_key_forfeit, prot_key_pledge_capture, prot_key_pledge_return,
        prot_key_settle, prot_tank_account, prot_user_account, Channel, Database, Member,
        MemberCompositeKey, ProtAmount, ProtGoal, ProtLaunchInput, ProtLedgerEntry,
        ProtPledgeInput, ProtPosting, ProtRef, ProtSettleCause, ProtTank, ProtTankRules,
        SeatListBody, SeatListSubmission, Server, User, PROT_SYS_ADJUST, PROT_SYS_FORFEITED,
    };

    const DAY: i64 = 86_400_000;
    const HOUR: i64 = 3_600_000;
    const ADMIN: &str = "01ADMIN0000000000000000000";
    /// The owner's device, the signer of every genesis list below
    const DEVICE: &str = "00112233445566778899aabbccddeeff";
    /// A 10-slot, 30-day launch goal at the default 40 Prot a day
    const TARGET: i64 = 1_200;

    fn rules() -> ProtTankRules {
        ProtTankRules {
            self_serve: true,
            // No launch-day burn: every tank below holds exactly its pledges
            burning: false,
            deletion_enabled: true,
            ..ProtTankRules::from_config(&revolt_config::ProtectionFeatures::default())
                .expect("the default Prot config is valid")
        }
    }

    /// An hour ago, on the real clock the delete paths read
    fn seeded_at() -> i64 {
        super::now_ms() - HOUR
    }

    fn timestamp(ms: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(iso8601_timestamp::Duration::milliseconds(ms))
            .unwrap()
    }

    /// The Prot collections and the migration's own indexes (revisions 76
    /// and 79). `database_test!` hands out an unmigrated database; the
    /// collections are created up front, as the migration does, so no
    /// transaction has to create one.
    async fn install_prot(db: &Database) {
        match db {
            Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                for collection in crate::PROT_COLLECTIONS {
                    mongo.db().create_collection(collection).await.ok();
                }
                for collection in crate::PROT_TANK_COLLECTIONS {
                    mongo.db().create_collection(collection).await.ok();
                }
                crate::create_prot_indexes(&mongo.db())
                    .await
                    .expect("failed to create the revision 76 indexes");
                crate::create_prot_tank_indexes(&mongo.db())
                    .await
                    .expect("failed to create the revision 79 indexes");
            }
        }
    }

    /// A live account, or one with the Deleted flag
    #[allow(clippy::disallowed_methods)]
    async fn user(db: &Database, deleted: bool) -> String {
        let id = Ulid::new().to_string();
        db.insert_user(&User {
            id: id.clone(),
            username: id.clone(),
            discriminator: "0001".to_string(),
            flags: deleted.then_some(v0::UserFlags::Deleted as i32),
            ..Default::default()
        })
        .await
        .expect("`User`");
        id
    }

    /// One server, its owner and its TextChannels
    struct Fixture {
        server: String,
        owner: String,
        channels: Vec<String>,
    }

    /// A server of a live owner listing `channels` fresh TextChannels, with
    /// the owner and every one of `members` as members (protect claims the
    /// owner's membership)
    #[allow(clippy::disallowed_methods)]
    async fn fixture(db: &Database, channels: usize, members: &[&String]) -> Fixture {
        let owner = user(db, false).await;
        let server_id = Ulid::new().to_string();
        let channels: Vec<String> = (0..channels).map(|_| Ulid::new().to_string()).collect();

        let server: Server = serde_json::from_value(serde_json::json!({
            "_id": server_id,
            "owner": owner,
            "name": "lifecycle",
            "channels": channels,
            "default_permissions": 0,
        }))
        .unwrap();
        db.insert_server(&server).await.expect("`Server`");
        for member in members
            .iter()
            .map(|member| member.as_str())
            .chain([owner.as_str()])
        {
            db.insert_or_merge_member(&Member {
                id: MemberCompositeKey {
                    server: server_id.clone(),
                    user: member.to_string(),
                },
                ..Default::default()
            })
            .await
            .expect("`Member`");
        }
        for channel_id in &channels {
            db.insert_channel(&Channel::TextChannel {
                id: channel_id.clone(),
                server: server_id.clone(),
                name: "lifecycle".to_string(),
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
            .expect("`Channel`");
        }

        Fixture {
            server: server_id,
            owner,
            channels,
        }
    }

    /// An admin credit to the wallet of `user_id`
    async fn fund(db: &Database, user_id: &str, amount: i64, now: i64) {
        db.apply_prot_posting(&ProtPosting {
            key: prot_key_admin(ADMIN, &format!("fund-{}", Ulid::new())),
            kind: v0::ProtEntryKind::AdminAdjust,
            debit: PROT_SYS_ADJUST.to_string(),
            credit: prot_user_account(user_id),
            amount: ProtAmount::Exact(amount),
            debit_floor: 0,
            actor: ADMIN.to_string(),
            reference: ProtRef::default(),
            reason: Some("lifecycle test".to_string()),
            created_at: now - 1_000,
        })
        .await
        .expect("fund");
    }

    async fn balance(db: &Database, account: &str) -> i64 {
        db.fetch_prot_account(account)
            .await
            .expect("account")
            .map_or(0, |account| account.balance)
    }

    async fn row(db: &Database, key: &str) -> ProtLedgerEntry {
        db.fetch_prot_entry_by_key(key)
            .await
            .expect("row")
            .unwrap_or_else(|| panic!("no ledger row {key}"))
    }

    async fn tank(db: &Database, tank_id: &str) -> ProtTank {
        db.fetch_prot_tank(tank_id)
            .await
            .expect("tank")
            .expect("the tank row")
    }

    /// A 10-slot, 30-day launch goal of the fixture's server (1,200 Prot)
    async fn launch_goal(db: &Database, f: &Fixture, now: i64) -> ProtGoal {
        let rules = rules();
        let daily_cost = rules.daily_cost(10).expect("10 is a slot tier");
        assert_eq!(30 * daily_cost, TARGET);
        db.create_prot_goal(&ProtGoal {
            id: Ulid::new().to_string(),
            kind: v0::ProtGoalKind::Launch,
            server_id: f.server.clone(),
            channel_id: None,
            tank_id: None,
            created_by: f.owner.clone(),
            create_nonce: Ulid::new().to_string(),
            slots: 10,
            days: Some(30),
            daily_cost,
            base_daily_cost: None,
            target_prot: TARGET,
            pledged_total: 0,
            state: v0::ProtGoalState::Funding,
            deadline_at: now + 30 * DAY,
            funded_at: None,
            launch_deadline_at: None,
            launched_at: None,
            closed_at: None,
            refund7_done: false,
            open_key: Some(format!("launch:{}", f.server)),
            version: 0,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("launch goal")
    }

    /// A 10 -> 25 slot upgrade goal of a launched tank
    async fn upgrade_goal(db: &Database, f: &Fixture, launched: &ProtTank, now: i64) -> ProtGoal {
        let rules = rules();
        db.create_prot_goal(&ProtGoal {
            id: Ulid::new().to_string(),
            kind: v0::ProtGoalKind::Upgrade,
            server_id: f.server.clone(),
            channel_id: Some(f.channels[0].clone()),
            tank_id: Some(launched.id.clone()),
            created_by: f.owner.clone(),
            create_nonce: Ulid::new().to_string(),
            slots: 25,
            days: None,
            daily_cost: rules.daily_cost(25).expect("25 is a slot tier"),
            base_daily_cost: rules.daily_cost(10),
            target_prot: 500,
            pledged_total: 0,
            state: v0::ProtGoalState::Funding,
            deadline_at: now + 30 * DAY,
            funded_at: None,
            launch_deadline_at: None,
            launched_at: None,
            closed_at: None,
            refund7_done: false,
            open_key: Some(format!("upgrade:{}", launched.id)),
            version: 0,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("upgrade goal")
    }

    /// Fund `user_id` with exactly `amount` and pledge all of it; the
    /// pledge id
    async fn pledge(db: &Database, user_id: &str, goal_id: &str, amount: i64, now: i64) -> String {
        fund(db, user_id, amount, now).await;
        let outcome = db
            .pledge_prot(&ProtPledgeInput {
                user_id: user_id.to_string(),
                goal_id: goal_id.to_string(),
                amount,
                nonce: format!("pledge-{user_id}"),
                rules: rules(),
                now,
            })
            .await
            .expect("pledge");
        assert_eq!(outcome.pledge.amount, amount);
        outcome.pledge.id
    }

    /// The genesis list of `channel_id`, seating only `owner` (the database
    /// layer checks the signature's encoding only)
    fn genesis(channel_id: &str, owner: &str, now: i64) -> SeatListSubmission {
        SeatListSubmission {
            body: SeatListBody {
                channel_id: channel_id.to_string(),
                version: 1,
                device_cap: 5,
                issued_at: now,
                signer_user_id: owner.to_string(),
                signer_device_id: DEVICE.to_string(),
                seats: vec![owner.to_string()],
            }
            .build()
            .unwrap(),
            signature: format!("B{}", "A".repeat(85)),
            signer_device_id: DEVICE.to_string(),
            handover: None,
        }
    }

    /// A funded launch goal launched on `channel_id` (tank Launching);
    /// `protect` then signs the genesis list (capture not run). The goal, the
    /// tank and the pledge ids, in the order of `pledges`.
    async fn launch(
        db: &Database,
        f: &Fixture,
        channel_id: &str,
        pledges: &[(&String, i64)],
        protect: bool,
        now: i64,
    ) -> (ProtGoal, ProtTank, Vec<String>) {
        let goal = launch_goal(db, f, now).await;
        let mut pledge_ids = vec![];
        for (user_id, amount) in pledges {
            pledge_ids.push(pledge(db, user_id, &goal.id, *amount, now).await);
        }
        let (goal, launched) = db
            .launch_prot_goal(&ProtLaunchInput {
                goal_id: goal.id.clone(),
                channel_id: channel_id.to_string(),
                owner_id: f.owner.clone(),
                rules: rules(),
                now,
            })
            .await
            .expect("launch");
        assert_eq!(goal.state, v0::ProtGoalState::Launching);
        assert_eq!(launched.stage, v0::ProtTankStage::Launching);

        if protect {
            db.protect_channel(
                channel_id,
                &genesis(channel_id, &f.owner, now),
                timestamp(now),
            )
            .await
            .expect("protect");
        }
        (goal, launched, pledge_ids)
    }

    /// A launched (Active) tank on `channel_id` holding exactly the pledges
    async fn launched(
        db: &Database,
        f: &Fixture,
        channel_id: &str,
        pledges: &[(&String, i64)],
        now: i64,
    ) -> ProtTank {
        let (_, launching, _) = launch(db, f, channel_id, pledges, true, now).await;
        let captured = db
            .capture_launch_pledges(channel_id, now, &rules())
            .await
            .expect("capture")
            .expect("a protected Launching tank is captured");
        assert_eq!(captured.id, launching.id);
        assert_eq!(captured.stage, v0::ProtTankStage::Active);
        assert_eq!(
            balance(db, &prot_tank_account(&captured.id)).await,
            pledges.iter().map(|(_, amount)| amount).sum::<i64>()
        );
        captured
    }

    /// Every S1 delete runs through settlement (S1's delete tests, and
    /// `User::delete` through `Server::delete`): with no tank and no goal it
    /// writes nothing, on any driver (on MongoDB a write would also need a
    /// replica set). Control: any Prot write before the lookups (e.g.
    /// `db.set_prot_burn_paused(now).await?;` first in
    /// `prot_settle_channel_on_delete`) fails it.
    #[tokio::test]
    async fn no_tank_and_no_goal_writes_nothing() {
        database_test!(|db| async move {
            let f = fixture(&db, 1, &[]).await;
            let channel_id = f.channels[0].clone();
            let entitlement = db
                .upsert_channel_entitlement(
                    &crate::ChannelEntitlement {
                        id: Ulid::new().to_string(),
                        channel_id: channel_id.clone(),
                        server_id: f.server.clone(),
                        source: crate::ChannelEntitlementSource::AdminGrant,
                        slot_cap: 10,
                        device_cap: None,
                        state: crate::ChannelEntitlementState::Active,
                        granted_by: "admin".to_string(),
                        created_at: timestamp(seeded_at()),
                    },
                    timestamp(seeded_at()),
                )
                .await
                .expect("entitlement");

            prot_settle_channel_on_delete(&db, &channel_id)
                .await
                .expect("channel");
            let ids: BTreeSet<String> = [channel_id.clone(), Ulid::new().to_string()].into();
            prot_settle_server_on_delete(&db, &f.server, &ids)
                .await
                .expect("server");

            assert_eq!(
                db.fetch_channel_entitlement(&channel_id)
                    .await
                    .expect("entitlement")
                    .as_ref(),
                Some(&entitlement)
            );
            match &db {
                Database::Reference(reference) => {
                    assert!(reference.prot_ledger.lock().await.is_empty());
                    assert!(reference.prot_accounts.lock().await.is_empty());
                    assert!(reference.prot_pledges.lock().await.is_empty());
                    assert!(reference.prot_goals.lock().await.is_empty());
                    assert!(reference.prot_tanks.lock().await.is_empty());
                    assert!(reference.prot_runtime.lock().await.is_empty());
                    assert!(reference.prot_notices.lock().await.is_empty());
                    assert!(reference.prot_contributor_prefs.lock().await.is_empty());
                }
                #[cfg(feature = "mongodb")]
                Database::MongoDb(mongo) => {
                    // Nothing installed the Prot collections: any write
                    // would have created one
                    let names = mongo
                        .db()
                        .list_collection_names()
                        .await
                        .expect("collections");
                    assert!(
                        !names.iter().any(|name| name.starts_with("prot_")),
                        "{names:?}"
                    );
                }
            }
        });
    }

    /// 9.3: each pledger's share is settled to that pledger; the shares of
    /// a deleted account and of a missing one are forfeited right after the
    /// settlement, and the live pledger receives exactly its own share.
    /// Control: the gone recipients' shares handed to the live one (or
    /// their forfeit skipped) fails it.
    #[tokio::test]
    async fn a_deleted_contributor_share_is_forfeited() {
        database_test!(|db| async move {
            install_prot(&db).await;
            let now = seeded_at();
            let live = user(&db, false).await;
            let deleted = user(&db, true).await;
            // No user document at all
            let missing = Ulid::new().to_string();
            let f = fixture(&db, 1, &[&live, &deleted, &missing]).await;
            let channel_id = f.channels[0].clone();
            let settled = launched(
                &db,
                &f,
                &channel_id,
                &[(&live, 600), (&deleted, 400), (&missing, 200)],
                now,
            )
            .await;

            prot_settle_channel_on_delete(&db, &channel_id)
                .await
                .expect("settle");

            // Every share went back to its own pledger first...
            for (user_id, share) in [(&live, 600), (&deleted, 400), (&missing, 200)] {
                let settle = row(&db, &prot_key_settle(&settled.id, user_id)).await;
                assert_eq!(settle.amount, share, "{user_id}");
                assert_eq!(settle.credit, prot_user_account(user_id));
            }
            // ...and the gone ones' shares left to sys:forfeited, not to anyone
            for (user_id, share) in [(&deleted, 400), (&missing, 200)] {
                let forfeit = row(&db, &prot_key_forfeit(user_id, 1)).await;
                assert_eq!(forfeit.amount, share, "{user_id}");
                assert_eq!(forfeit.debit, prot_user_account(user_id));
                assert_eq!(forfeit.credit, PROT_SYS_FORFEITED);
                assert_eq!(balance(&db, &prot_user_account(user_id)).await, 0);
            }
            assert_eq!(balance(&db, &prot_user_account(&live)).await, 600);
            assert!(db
                .fetch_prot_entry_by_key(&prot_key_forfeit(&live, 1))
                .await
                .expect("row")
                .is_none());

            let settled = tank(&db, &settled.id).await;
            assert_eq!(settled.stage, v0::ProtTankStage::Deleted);
            assert_eq!(balance(&db, &prot_tank_account(&settled.id)).await, 0);
        });
    }

    /// 9.3 (W4 audit F1): the settlement commits but the deleted recipient's
    /// second pass fails, so the delete aborts; the retry finds the tank
    /// already Deleted and still forfeits that share, without settling
    /// anything twice. Control: the Deleted early return in
    /// `settle_channel` back to `return Ok(());` (the retry leaves 400 in the
    /// deleted wallet).
    #[tokio::test]
    async fn a_retry_after_a_failed_second_pass_forfeits_the_deleted_share() {
        database_test!(|db| async move {
            install_prot(&db).await;
            let now = seeded_at();
            let live = user(&db, false).await;
            let deleted = user(&db, true).await;
            let f = fixture(&db, 1, &[&live, &deleted]).await;
            let channel_id = f.channels[0].clone();
            let settled =
                launched(&db, &f, &channel_id, &[(&live, 800), (&deleted, 400)], now).await;

            FAIL_WALLET_PASS_FOR_TESTS
                .lock()
                .unwrap()
                .insert(deleted.clone());
            let error = prot_settle_channel_on_delete(&db, &channel_id)
                .await
                .expect_err("a failed second pass aborts the delete");
            FAIL_WALLET_PASS_FOR_TESTS.lock().unwrap().remove(&deleted);
            assert!(
                matches!(error.error_type, ErrorType::InternalError),
                "{error:?}"
            );

            // The settlement committed; the deleted share is still in its wallet
            assert_eq!(
                tank(&db, &settled.id).await.stage,
                v0::ProtTankStage::Deleted
            );
            assert_eq!(balance(&db, &prot_user_account(&deleted)).await, 400);
            assert!(db
                .fetch_prot_entry_by_key(&prot_key_forfeit(&deleted, 1))
                .await
                .expect("row")
                .is_none());
            let rows = db
                .fetch_prot_entries_by_tank(&settled.id)
                .await
                .expect("rows")
                .len();

            prot_settle_channel_on_delete(&db, &channel_id)
                .await
                .expect("the retry");

            let forfeit = row(&db, &prot_key_forfeit(&deleted, 1)).await;
            assert_eq!(forfeit.amount, 400);
            assert_eq!(forfeit.credit, PROT_SYS_FORFEITED);
            assert_eq!(balance(&db, &prot_user_account(&deleted)).await, 0);
            assert_eq!(balance(&db, &prot_user_account(&live)).await, 800);
            assert_eq!(
                db.fetch_prot_entries_by_tank(&settled.id)
                    .await
                    .expect("rows")
                    .len(),
                rows
            );

            // A further retry writes nothing more
            prot_settle_channel_on_delete(&db, &channel_id)
                .await
                .expect("a second retry");
            assert!(db
                .fetch_prot_entry_by_key(&prot_key_forfeit(&deleted, 2))
                .await
                .expect("row")
                .is_none());
            assert_eq!(balance(&db, &prot_user_account(&live)).await, 800);
        });
    }

    /// W4 audit F2: capturing a never-launched tank on the delete path reads
    /// no config (an invalid Prot config must not block a delete). The
    /// config is a process-wide cache, so a test cannot make it invalid;
    /// this pins the source instead. Control: `land_or_abandon` back to
    /// `ProtTankRules::load().await?` fails it.
    #[test]
    fn deleting_a_never_launched_tank_reads_no_config() {
        const SOURCE: &str = include_str!("lifecycle.rs");

        let body = |signature: &str| -> &'static str {
            let at = SOURCE.find(signature).expect("the fn");
            let end = at + SOURCE[at..].find("\n}\n").expect("the end of the fn");
            &SOURCE[at..end]
        };
        let land = body("async fn land_or_abandon(");
        let rules = body("fn settling_capture_rules() -> Result<ProtTankRules> {");

        assert!(!land.contains("load()"), "{land}");
        assert!(
            land.contains("let rules = settling_capture_rules()?;"),
            "{land}"
        );
        assert!(!rules.contains("load()"), "{rules}");
        assert!(rules.contains("burning: false,"), "{rules}");
        assert!(rules.contains("ProtectionFeatures::default()"), "{rules}");
    }

    /// 9.4, audit 8: deleting the channel of a never-launched tank. A
    /// protected channel has its pledges captured (no launch-day burn) and
    /// settled back in full; an unprotected one has its goal closed with
    /// returns and the tank and its entitlement removed. Control: the
    /// Launching branch skipped (the protected tank settles nothing, the
    /// unprotected one keeps its pledges held).
    #[tokio::test]
    async fn delete_of_a_launching_tank_captures_or_returns() {
        database_test!(|db| async move {
            install_prot(&db).await;
            let now = seeded_at();

            for protect in [true, false] {
                let (a, b) = (user(&db, false).await, user(&db, false).await);
                let f = fixture(&db, 1, &[&a, &b]).await;
                let channel_id = f.channels[0].clone();
                let (goal, launching, pledge_ids) =
                    launch(&db, &f, &channel_id, &[(&a, 700), (&b, 500)], protect, now).await;

                prot_settle_channel_on_delete(&db, &channel_id)
                    .await
                    .expect("settle");

                assert_eq!(balance(&db, &prot_user_account(&a)).await, 700, "{protect}");
                assert_eq!(balance(&db, &prot_user_account(&b)).await, 500, "{protect}");
                let goal = db
                    .fetch_prot_goal(&goal.id)
                    .await
                    .expect("goal")
                    .expect("the goal row");
                if protect {
                    for pledge_id in &pledge_ids {
                        row(&db, &prot_key_pledge_capture(pledge_id)).await;
                    }
                    assert_eq!(
                        row(&db, &prot_key_settle(&launching.id, &a)).await.amount,
                        700
                    );
                    assert_eq!(
                        row(&db, &prot_key_settle(&launching.id, &b)).await.amount,
                        500
                    );
                    assert_eq!(goal.state, v0::ProtGoalState::Launched);
                    let settled = tank(&db, &launching.id).await;
                    assert_eq!(settled.stage, v0::ProtTankStage::Deleted);
                    assert_eq!(balance(&db, &prot_tank_account(&settled.id)).await, 0);
                    // Captured while Settling: nothing burned
                    let burned = db
                        .fetch_prot_entries_by_tank(&settled.id)
                        .await
                        .expect("rows")
                        .into_iter()
                        .filter(|row| row.kind == v0::ProtEntryKind::Burn)
                        .count();
                    assert_eq!(burned, 0);
                } else {
                    for pledge_id in &pledge_ids {
                        row(&db, &prot_key_pledge_return(pledge_id)).await;
                    }
                    assert_eq!(goal.state, v0::ProtGoalState::Cancelled);
                    assert!(db
                        .fetch_prot_tank(&launching.id)
                        .await
                        .expect("tank")
                        .is_none());
                    assert!(db
                        .fetch_prot_tank_by_channel(&channel_id)
                        .await
                        .expect("tank")
                        .is_none());
                    assert!(db
                        .fetch_channel_entitlement(&channel_id)
                        .await
                        .expect("entitlement")
                        .is_none());
                }
            }
        });
    }

    /// 9.4: a delete that stopped after beginning the settlement (the tank
    /// Settling, an upgrade goal still holding a pledge) is finished by the
    /// retry, and a further retry writes nothing. Control: a Settling tank
    /// treated as already settled (the retry returns early) fails it.
    #[tokio::test]
    async fn owner_delete_settlement_resumes_after_a_crash() {
        database_test!(|db| async move {
            install_prot(&db).await;
            let now = seeded_at();
            let (a, b, upgrader) = (
                user(&db, false).await,
                user(&db, false).await,
                user(&db, false).await,
            );
            let f = fixture(&db, 1, &[&a, &b, &upgrader]).await;
            let channel_id = f.channels[0].clone();
            let launched = launched(&db, &f, &channel_id, &[(&a, 600), (&b, 600)], now).await;
            let upgrade = upgrade_goal(&db, &f, &launched, now).await;
            let upgrade_pledge = pledge(&db, &upgrader, &upgrade.id, 100, now).await;

            // The crash: the settlement began, nothing after it ran
            let begun = db
                .begin_prot_settlement(&launched.id, ProtSettleCause::OwnerDelete, now)
                .await
                .expect("begin")
                .expect("an Active tank begins settling");
            assert_eq!(begun.stage, v0::ProtTankStage::Settling);

            prot_settle_channel_on_delete(&db, &channel_id)
                .await
                .expect("the retry resumes");

            assert_eq!(
                row(&db, &prot_key_pledge_return(&upgrade_pledge))
                    .await
                    .amount,
                100
            );
            assert_eq!(balance(&db, &prot_user_account(&upgrader)).await, 100);
            for user_id in [&a, &b] {
                assert_eq!(
                    row(&db, &prot_key_settle(&launched.id, user_id))
                        .await
                        .amount,
                    600
                );
                assert_eq!(balance(&db, &prot_user_account(user_id)).await, 600);
            }
            let settled = tank(&db, &launched.id).await;
            assert_eq!(settled.stage, v0::ProtTankStage::Deleted);
            assert_eq!(settled.settle_cause, Some(ProtSettleCause::OwnerDelete));
            let upgrade = db
                .fetch_prot_goal(&upgrade.id)
                .await
                .expect("goal")
                .expect("the goal row");
            assert_eq!(upgrade.state, v0::ProtGoalState::Cancelled);

            let rows = db
                .fetch_prot_entries_by_tank(&launched.id)
                .await
                .expect("rows")
                .len();
            prot_settle_channel_on_delete(&db, &channel_id)
                .await
                .expect("a second retry");
            assert_eq!(
                db.fetch_prot_entries_by_tank(&launched.id)
                    .await
                    .expect("rows")
                    .len(),
                rows
            );
            for user_id in [&a, &b] {
                assert_eq!(balance(&db, &prot_user_account(user_id)).await, 600);
            }
        });
    }

    /// 26: on the `Channel::delete` path the settlement runs BEFORE
    /// `delete_protected_channel_data`. A settlement that fails leaves the
    /// channel, its entitlement, its seat list and its tank exactly as they
    /// were; once it succeeds the tank is settled and the cascade has run.
    /// Control: in `Channel::delete`, the settlement call moved below
    /// `db.delete_protected_channel_data(&id).await?;` (the first delete
    /// erases the entitlement and the seat list) or removed (no settlement).
    #[tokio::test]
    async fn channel_delete_settles_before_the_protected_cascade() {
        database_test!(|db| async move {
            install_prot(&db).await;
            let now = seeded_at();
            let backer = user(&db, false).await;
            let f = fixture(&db, 1, &[&backer]).await;
            let channel_id = f.channels[0].clone();
            let launched = launched(&db, &f, &channel_id, &[(&backer, TARGET)], now).await;

            FAIL_SETTLEMENT_FOR_TESTS
                .lock()
                .unwrap()
                .insert(channel_id.clone());
            let error = db
                .fetch_channel(&channel_id)
                .await
                .expect("channel")
                .delete(&db)
                .await
                .expect_err("a failed settlement aborts the delete");
            FAIL_SETTLEMENT_FOR_TESTS
                .lock()
                .unwrap()
                .remove(&channel_id);
            assert!(
                matches!(error.error_type, ErrorType::InternalError),
                "{error:?}"
            );

            // Nothing the cascade removes is gone, and nothing was settled
            db.fetch_channel(&channel_id)
                .await
                .expect("the channel survives");
            let entitlement = db
                .fetch_channel_entitlement(&channel_id)
                .await
                .expect("entitlement")
                .expect("the entitlement survives");
            assert_eq!(entitlement.state, crate::ChannelEntitlementState::Active);
            assert!(db
                .fetch_seat_list(&channel_id)
                .await
                .expect("list")
                .is_some());
            assert!(!db
                .fetch_channel_seats(&channel_id)
                .await
                .expect("seats")
                .is_empty());
            assert_eq!(
                tank(&db, &launched.id).await.stage,
                v0::ProtTankStage::Active
            );
            assert_eq!(balance(&db, &prot_user_account(&backer)).await, 0);

            db.fetch_channel(&channel_id)
                .await
                .expect("channel")
                .delete(&db)
                .await
                .expect("delete");

            assert_eq!(
                row(&db, &prot_key_settle(&launched.id, &backer))
                    .await
                    .amount,
                TARGET
            );
            assert_eq!(balance(&db, &prot_user_account(&backer)).await, TARGET);
            assert_eq!(
                tank(&db, &launched.id).await.stage,
                v0::ProtTankStage::Deleted
            );
            assert!(db
                .fetch_channel_entitlement(&channel_id)
                .await
                .expect("entitlement")
                .is_none());
            assert!(db
                .fetch_seat_list(&channel_id)
                .await
                .expect("list")
                .is_none());
            let gone = db.fetch_channel(&channel_id).await;
            assert!(
                matches!(&gone, Err(error) if matches!(error.error_type, ErrorType::NotFound)),
                "{gone:?}"
            );
        });
    }

    /// 9.4 on `Server::delete`: an upgrade goal's pledge is returned, a
    /// launched tank is settled, and a Launching tank on a protected channel
    /// is captured and settled with its channel. Control: the open goals of
    /// the server left open (the upgrade pledge stays held).
    #[tokio::test]
    async fn server_delete_returns_open_goals_and_settles_every_tank() {
        database_test!(|db| async move {
            install_prot(&db).await;
            let now = seeded_at();
            let (first, upgrader, second) = (
                user(&db, false).await,
                user(&db, false).await,
                user(&db, false).await,
            );
            let f = fixture(&db, 2, &[&first, &upgrader, &second]).await;
            let active = launched(&db, &f, &f.channels[0], &[(&first, TARGET)], now).await;
            let upgrade = upgrade_goal(&db, &f, &active, now).await;
            let upgrade_pledge = pledge(&db, &upgrader, &upgrade.id, 100, now).await;
            // The first launch goal is Launched, so the server may open another
            let (_, launching, second_pledges) =
                launch(&db, &f, &f.channels[1], &[(&second, TARGET)], true, now).await;

            db.fetch_server(&f.server)
                .await
                .expect("server")
                .delete(&db)
                .await
                .expect("delete");

            assert_eq!(
                row(&db, &prot_key_pledge_return(&upgrade_pledge))
                    .await
                    .amount,
                100
            );
            assert_eq!(balance(&db, &prot_user_account(&upgrader)).await, 100);
            row(&db, &prot_key_pledge_capture(&second_pledges[0])).await;
            for (settled, backer) in [(&active, &first), (&launching, &second)] {
                assert_eq!(
                    row(&db, &prot_key_settle(&settled.id, backer)).await.amount,
                    TARGET
                );
                assert_eq!(balance(&db, &prot_user_account(backer)).await, TARGET);
                assert_eq!(
                    tank(&db, &settled.id).await.stage,
                    v0::ProtTankStage::Deleted
                );
                assert_eq!(balance(&db, &prot_tank_account(&settled.id)).await, 0);
            }
            assert!(db
                .fetch_open_prot_goals_by_server(&f.server)
                .await
                .expect("goals")
                .is_empty());
            for channel_id in &f.channels {
                assert!(db
                    .fetch_channel_entitlement(channel_id)
                    .await
                    .expect("entitlement")
                    .is_none());
            }
        });
    }

    /// 9.4 on `Server::delete` with a goal still Funding (no channel, no
    /// tank): its pledges are returned and it ends Cancelled. Control: the
    /// server's open goals not closed.
    #[tokio::test]
    async fn server_delete_returns_a_funding_launch_goal() {
        database_test!(|db| async move {
            install_prot(&db).await;
            let now = seeded_at();
            let backer = user(&db, false).await;
            let f = fixture(&db, 1, &[&backer]).await;
            let goal = launch_goal(&db, &f, now).await;
            let pledge_id = pledge(&db, &backer, &goal.id, 300, now).await;
            assert_eq!(balance(&db, &prot_user_account(&backer)).await, 0);

            db.fetch_server(&f.server)
                .await
                .expect("server")
                .delete(&db)
                .await
                .expect("delete");

            assert_eq!(
                row(&db, &prot_key_pledge_return(&pledge_id)).await.amount,
                300
            );
            assert_eq!(balance(&db, &prot_user_account(&backer)).await, 300);
            let goal = db
                .fetch_prot_goal(&goal.id)
                .await
                .expect("goal")
                .expect("the goal row");
            assert_eq!(goal.state, v0::ProtGoalState::Cancelled);
        });
    }

    /// 9.3, 9.6: the owner's account deletion deletes the owned server,
    /// whose tank is settled back FIFO (the owner's own share included) and
    /// whose returns the deletion's wallet forfeit then takes, so no Prot is
    /// left in the tank or in the dead wallet. Control: the settlement call
    /// removed from `Server::delete` (the tank keeps its balance).
    #[tokio::test]
    async fn owner_account_deletion_with_a_funded_tank_leaves_no_orphan_balance() {
        database_test!(|db| async move {
            install_prot(&db).await;
            let now = seeded_at();
            let backer = user(&db, false).await;
            let f = fixture(&db, 1, &[&backer]).await;
            let funded = launched(
                &db,
                &f,
                &f.channels[0],
                &[(&f.owner, 500), (&backer, 700)],
                now,
            )
            .await;

            let mut owner = db.fetch_user(&f.owner).await.expect("owner");
            owner.delete(&db).await.expect("account deletion");
            // What crond's account deletion runs after the cascade (S5a)
            db.forfeit_prot_wallet(&f.owner, now)
                .await
                .expect("forfeit");

            assert_eq!(balance(&db, &prot_tank_account(&funded.id)).await, 0);
            assert_eq!(
                tank(&db, &funded.id).await.stage,
                v0::ProtTankStage::Deleted
            );
            assert_eq!(
                row(&db, &prot_key_settle(&funded.id, &f.owner))
                    .await
                    .amount,
                500
            );
            assert_eq!(balance(&db, &prot_user_account(&f.owner)).await, 0);
            assert_eq!(row(&db, &prot_key_forfeit(&f.owner, 1)).await.amount, 500);
            assert_eq!(balance(&db, &prot_user_account(&backer)).await, 700);
        });
    }

    /// 19.1: settlement is triggered only by deleting the channel or its
    /// server. `Channel::delete` and `Server::delete` each call it once;
    /// `User::delete` never calls it and reaches it only through the owned
    /// servers' `Server::delete` (so once S2's succession keeps a server
    /// alive, nothing settles). Control: a settlement call added to
    /// `User::delete`.
    #[test]
    fn settlement_runs_only_on_a_delete_path() {
        const CHANNELS: &str = include_str!("../channels/model.rs");
        const SERVERS: &str = include_str!("../servers/model.rs");
        const USERS: &str = include_str!("../users/model.rs");

        let body = |source: &'static str, signature: &str| -> &'static str {
            let at = source.find(signature).expect("the delete fn");
            let end = at
                + source[at..]
                    .find("\n    }\n")
                    .expect("the end of the delete fn");
            &source[at..end]
        };
        let channel_delete = body(
            CHANNELS,
            "pub async fn delete(&self, db: &Database) -> Result<()> {",
        );
        let server_delete = body(
            SERVERS,
            "pub async fn delete(self, db: &Database) -> Result<()> {",
        );
        let user_delete = body(
            USERS,
            "pub async fn delete(&mut self, db: &Database) -> Result<()> {",
        );

        assert_eq!(
            channel_delete
                .matches("crate::prot_settle_channel_on_delete(db, &id).await?;")
                .count(),
            1,
            "{channel_delete}"
        );
        assert_eq!(channel_delete.matches("prot_settle_").count(), 1);
        assert_eq!(
            server_delete
                .matches(
                    "crate::prot_settle_server_on_delete(db, &self.id, &protected_ids).await?;"
                )
                .count(),
            1,
            "{server_delete}"
        );
        assert_eq!(server_delete.matches("prot_settle_").count(), 1);
        assert!(
            user_delete.contains("server.delete(db).await?;"),
            "{user_delete}"
        );
        assert!(!USERS.contains("prot_settle_"));
    }
}
