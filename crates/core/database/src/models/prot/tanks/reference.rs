//! Reference driver for the Prot fuel tanks (S5b).
//!
//! Lock order: the complete order in `prot/mod.rs` (S5b contracts 2.4). Every
//! method takes every map it needs at its start, in that order, holds them to
//! its end and never re-takes one; no trait method is called while a map is
//! held (`terminate_prot_tank` and `top_contributor` run their steps one
//! after another, each with its own locks).
//!
//! A body that writes several postings stages the ledger and the accounts
//! (`Book`) and edits copies of the documents it changes; nothing lands in the
//! maps until the whole body has succeeded, so a refusal part way changes
//! nothing. That is this driver's transaction.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use iso8601_timestamp::{Duration, Timestamp};
use revolt_models::v0;
use revolt_result::Result;

use crate::{
    channel_seats_used, check_channel_protectable, plan_prot_settlement, plan_tank_day,
    plan_unseated_returns, prot_burn_amount, prot_day_start_ms, prot_hold_account, prot_hours_left,
    prot_key_burn, prot_key_contrib, prot_key_forfeit_tank, prot_key_launch_return,
    prot_key_pledge, prot_key_pledge_capture, prot_key_pledge_return, prot_key_pledge_withdraw,
    prot_key_settle, prot_key_tier, prot_key_writeoff, prot_next_day, prot_notice_key,
    prot_payload_hash, prot_pro_rata, prot_tank_account, prot_tank_target_key, prot_user_account,
    prot_utc_day, seat_list_channel_server, Channel, ChannelEntitlement, ChannelEntitlementSource,
    ChannelEntitlementState, ChannelSeat, MlsGroupKind, ProtAccount, ProtAmount, ProtBurnOutcome,
    ProtContributeInput, ProtContributeOutcome, ProtContributorPref, ProtDayPlan, ProtGoal,
    ProtGoalCloseOutcome, ProtLaunchInput, ProtLedgerEntry, ProtLot, ProtNotice, ProtNoticeKind,
    ProtPledge, ProtPledgeInput, ProtPledgeOutcome, ProtPosting, ProtPurgeCounts, ProtRef,
    ProtRuntime, ProtSettleCause, ProtSettlement, ProtTank, ProtTankRules, ProtTankTarget,
    ProtTermination, ProtTierChangeInput, ReferenceDb, PROT_ACTOR_CLOCK, PROT_ACTOR_GOALS,
    PROT_ACTOR_SETTLEMENT, PROT_OPEN_GOAL_STATES, PROT_RUNTIME_ID, PROT_SYS_BURNED,
    PROT_SYS_FORFEITED, PROT_SYS_WRITEOFF,
};

use super::super::ops::reference::{
    commit_locked, held_purchase_prot_locked, prepare_locked, Prepared,
};
use super::super::ops::{duplicate_outcome, state_retries_exhausted, validate_prot_posting};
use super::AbstractProtTanks;

const DAY_MS: i64 = 86_400_000;

/// The ledger and the accounts of one body, staged: postings go to these
/// copies, which replace the locked maps only when the body has succeeded
struct Book {
    ledger: HashMap<String, ProtLedgerEntry>,
    accounts: HashMap<String, ProtAccount>,
}

/// What one staged posting did
enum Posted {
    Applied(ProtLedgerEntry),
    /// A row already has the key (payload not compared)
    Stored(ProtLedgerEntry),
}

impl Book {
    fn stage(
        ledger: &HashMap<String, ProtLedgerEntry>,
        accounts: &HashMap<String, ProtAccount>,
    ) -> Book {
        Book {
            ledger: ledger.clone(),
            accounts: accounts.clone(),
        }
    }

    /// Balance of an account with a document; None without one
    fn balance(&self, account_id: &str) -> Option<i64> {
        self.accounts.get(account_id).map(|account| account.balance)
    }

    fn row(&self, key: &str) -> Option<&ProtLedgerEntry> {
        self.ledger.get(key)
    }

    fn post(&mut self, posting: &ProtPosting) -> Result<Posted> {
        validate_prot_posting(posting)?;
        let payload_hash = prot_payload_hash(posting);
        Ok(
            match prepare_locked(&self.ledger, &self.accounts, posting, &payload_hash)? {
                Prepared::Duplicate(stored) => Posted::Stored(stored),
                Prepared::New(prepared) => Posted::Applied(commit_locked(
                    &mut self.ledger,
                    &mut self.accounts,
                    prepared,
                )),
            },
        )
    }

    /// A posting the body checked is new. A taken key means a racing run
    /// committed from another state (MongoDB re-runs the body; under these
    /// locks a re-run reads the same maps), so the body is refused.
    fn post_new(
        &mut self,
        posting: &ProtPosting,
        operation: &str,
        id: &str,
    ) -> Result<ProtLedgerEntry> {
        match self.post(posting)? {
            Posted::Applied(entry) => Ok(entry),
            Posted::Stored(stored) => {
                log::error!(
                    "PROT_TANK_KEY_TAKEN op={operation} key={:?} stored={:?}",
                    posting.key,
                    stored.id
                );
                Err(state_retries_exhausted(operation, id, None))
            }
        }
    }

    fn land(
        self,
        ledger: &mut HashMap<String, ProtLedgerEntry>,
        accounts: &mut HashMap<String, ProtAccount>,
    ) {
        *ledger = self.ledger;
        *accounts = self.accounts;
    }
}

/// An Exact posting with debit floor 0, actor sys:goals and no references;
/// callers override the rest with struct update syntax
fn posting(
    key: String,
    kind: v0::ProtEntryKind,
    debit: String,
    credit: String,
    amount: i64,
    now: i64,
) -> ProtPosting {
    ProtPosting {
        key,
        kind,
        debit,
        credit,
        amount: ProtAmount::Exact(amount),
        debit_floor: 0,
        actor: PROT_ACTOR_GOALS.to_string(),
        reference: ProtRef::default(),
        reason: None,
        created_at: now,
    }
}

fn tank_ref(tank_id: &str) -> ProtRef {
    ProtRef {
        tank_id: Some(tank_id.to_string()),
        ..Default::default()
    }
}

fn pledge_ref(goal_id: &str, pledge_id: &str, tank_id: Option<&str>) -> ProtRef {
    ProtRef {
        goal_id: Some(goal_id.to_string()),
        pledge_id: Some(pledge_id.to_string()),
        tank_id: tank_id.map(str::to_string),
        ..Default::default()
    }
}

/// `burn:{tank}:{day}` (7.2): tank -> sys:burned down to the tank's floor
fn burn_posting(tank_id: &str, day: &str, amount: i64, floor: i64, now: i64) -> ProtPosting {
    ProtPosting {
        debit_floor: floor,
        actor: PROT_ACTOR_CLOCK.to_string(),
        reference: ProtRef {
            tank_id: Some(tank_id.to_string()),
            day: Some(day.to_string()),
            ..Default::default()
        },
        ..posting(
            prot_key_burn(tank_id, day),
            v0::ProtEntryKind::Burn,
            prot_tank_account(tank_id),
            PROT_SYS_BURNED.to_string(),
            amount,
            now,
        )
    }
}

fn timestamp_of(ms: i64) -> Result<Timestamp> {
    Timestamp::UNIX_EPOCH
        .checked_add(Duration::milliseconds(ms))
        .ok_or_else(|| create_error!(InternalError))
}

fn days_ms(days: u32) -> i64 {
    i64::from(days).saturating_mul(DAY_MS)
}

fn tank_channel(tank: &ProtTank) -> Option<&str> {
    match &tank.target {
        ProtTankTarget::Channel { channel_id } => Some(channel_id.as_str()),
        ProtTankTarget::Server { .. } => None,
    }
}

fn is_protected(channels: &HashMap<String, Channel>, channel_id: Option<&str>) -> bool {
    channel_id
        .and_then(|channel_id| channels.get(channel_id))
        .is_some_and(|channel| {
            matches!(
                channel,
                Channel::TextChannel {
                    protected: true,
                    ..
                }
            )
        })
}

fn is_open(goal: &ProtGoal) -> bool {
    PROT_OPEN_GOAL_STATES.contains(&goal.state)
}

/// Every tank has an account document from its launch (10.3)
fn tank_without_account(tank_id: &str) -> revolt_result::Error {
    log::error!("PROT_TANK_WITHOUT_ACCOUNT tank={tank_id}");
    create_error!(InternalError)
}

fn tank_balance(accounts: &HashMap<String, ProtAccount>, tank_id: &str) -> Result<i64> {
    accounts
        .get(&prot_tank_account(tank_id))
        .map(|account| account.balance)
        .ok_or_else(|| tank_without_account(tank_id))
}

/// The tank-backed entitlement of a channel (source Prot or Crowdfund; an
/// AdminGrant row is never an S5 row)
fn tank_entitlement<'a>(
    entitlements: &'a HashMap<String, ChannelEntitlement>,
    channel_id: &str,
) -> Option<&'a ChannelEntitlement> {
    entitlements.values().find(|entitlement| {
        entitlement.channel_id == channel_id
            && matches!(
                entitlement.source,
                ChannelEntitlementSource::Prot | ChannelEntitlementSource::Crowdfund
            )
    })
}

/// The tank-backed entitlement after a stage or tier write (6.1), or None when
/// there is none to write. A Deleted tombstone never moves (never plaintext).
fn entitlement_after(
    entitlements: &HashMap<String, ChannelEntitlement>,
    tank: &ProtTank,
    state: Option<ChannelEntitlementState>,
    slot_cap: Option<u32>,
) -> Option<ChannelEntitlement> {
    let mut row = tank_entitlement(entitlements, tank_channel(tank)?)?.clone();
    if row.state == ChannelEntitlementState::Deleted {
        return None;
    }
    if let Some(state) = state {
        row.state = state;
    }
    if let Some(slot_cap) = slot_cap {
        row.slot_cap = slot_cap;
    }
    Some(row)
}

fn land_entitlement(
    entitlements: &mut HashMap<String, ChannelEntitlement>,
    row: Option<ChannelEntitlement>,
) {
    if let Some(row) = row {
        entitlements.insert(row.id.clone(), row);
    }
}

fn land_pledges(pledges: &mut HashMap<String, ProtPledge>, changed: Vec<ProtPledge>) {
    for pledge in changed {
        pledges.insert(pledge.id.clone(), pledge);
    }
}

/// The goal's Held pledges, oldest first
fn held_pledges(pledges: &HashMap<String, ProtPledge>, goal_id: &str) -> Vec<ProtPledge> {
    let mut held: Vec<ProtPledge> = pledges
        .values()
        .filter(|pledge| pledge.goal_id == goal_id && pledge.state == v0::ProtPledgeState::Held)
        .cloned()
        .collect();
    held.sort_by(|a, b| a.id.cmp(&b.id));
    held
}

/// 8.5: every Held pledge goes back to its pledger (`pledge-return:`; one with
/// nothing left is Returned without a row) and the goal ends in `to`
fn close_goal_locked(
    goal: &ProtGoal,
    to: v0::ProtGoalState,
    pledges: &HashMap<String, ProtPledge>,
    book: &mut Book,
    now: i64,
) -> Result<(ProtGoal, Vec<ProtPledge>, Vec<ProtLedgerEntry>)> {
    let hold = prot_hold_account(&goal.id);
    let mut changed = Vec::new();
    let mut returned = Vec::new();
    for pledge in held_pledges(pledges, &goal.id) {
        if pledge.remaining > 0 {
            returned.push(book.post_new(
                &ProtPosting {
                    reference: pledge_ref(&goal.id, &pledge.id, None),
                    ..posting(
                        prot_key_pledge_return(&pledge.id),
                        v0::ProtEntryKind::PledgeReturn,
                        hold.clone(),
                        prot_user_account(&pledge.user_id),
                        pledge.remaining,
                        now,
                    )
                },
                "close_prot_goal",
                &goal.id,
            )?);
        }
        changed.push(ProtPledge {
            state: v0::ProtPledgeState::Returned,
            remaining: 0,
            version: pledge.version + 1,
            updated_at: now,
            ..pledge
        });
    }

    let goal = ProtGoal {
        state: to,
        open_key: None,
        closed_at: Some(now),
        version: goal.version + 1,
        updated_at: now,
        ..goal.clone()
    };
    Ok((goal, changed, returned))
}

/// 8.6 / 8.7: every Held pledge of the goal moves into the tank
/// (`pledge-capture:`; one with nothing left is Captured without a row)
fn capture_goal_locked(
    goal: &ProtGoal,
    tank_id: &str,
    pledges: &HashMap<String, ProtPledge>,
    book: &mut Book,
    operation: &str,
    now: i64,
) -> Result<Vec<ProtPledge>> {
    let hold = prot_hold_account(&goal.id);
    let mut changed = Vec::new();
    for pledge in held_pledges(pledges, &goal.id) {
        if pledge.remaining > 0 {
            book.post_new(
                &ProtPosting {
                    reference: pledge_ref(&goal.id, &pledge.id, Some(tank_id)),
                    ..posting(
                        prot_key_pledge_capture(&pledge.id),
                        v0::ProtEntryKind::PledgeCapture,
                        hold.clone(),
                        prot_tank_account(tank_id),
                        pledge.remaining,
                        now,
                    )
                },
                operation,
                &goal.id,
            )?;
        }
        changed.push(ProtPledge {
            state: v0::ProtPledgeState::Captured,
            captured: pledge.captured.saturating_add(pledge.remaining),
            remaining: 0,
            version: pledge.version + 1,
            updated_at: now,
            ..pledge
        });
    }
    Ok(changed)
}

/// Today's pro rata from `now` to midnight (capture, D16 resume), through the
/// 7.0 clamp: an Active tank short of a full day enters Grace from today's
/// start. `next_burn_day` becomes tomorrow. Ok(true) when it entered Grace.
fn burn_rest_of_today(
    tank: &mut ProtTank,
    book: &mut Book,
    now: i64,
    rules: &ProtTankRules,
    operation: &str,
) -> Result<bool> {
    let balance = book
        .balance(&prot_tank_account(&tank.id))
        .ok_or_else(|| tank_without_account(&tank.id))?;
    let today = prot_utc_day(now);
    let floor = rules.floor(tank.daily_cost);
    let amount = prot_burn_amount(
        prot_pro_rata(tank.daily_cost, prot_hours_left(now)),
        balance,
        floor,
    );
    // A row for today means today is already paid
    if amount > 0 && book.row(&prot_key_burn(&tank.id, &today)).is_none() {
        book.post_new(
            &burn_posting(&tank.id, &today, amount, floor, now),
            operation,
            &tank.id,
        )?;
    }

    let grace = tank.stage == v0::ProtTankStage::Active && balance < tank.daily_cost;
    if grace {
        tank.stage = v0::ProtTankStage::Grace;
        tank.exhausted_at = Some(prot_day_start_ms(&today)?);
    }
    tank.next_burn_day = Some(prot_next_day(&today)?);
    Ok(grace)
}

/// 7.3 after a credit (`balance` = the tank's balance now, `daily_cost` the
/// tank's CURRENT cost): Grace or Frozen with at least min_reactivation_days
/// of Prot goes back to Active and re-arms its warnings; from Frozen today is
/// billed pro rata (frozen days never are). Ok(true) when it reactivated.
fn reactivate_locked(
    tank: &mut ProtTank,
    book: &mut Book,
    balance: i64,
    now: i64,
    rules: &ProtTankRules,
    operation: &str,
) -> Result<bool> {
    let from_frozen = match tank.stage {
        v0::ProtTankStage::Grace => false,
        v0::ProtTankStage::Frozen => true,
        _ => return Ok(false),
    };
    let threshold = i64::from(rules.min_reactivation_days).saturating_mul(tank.daily_cost);
    if balance < threshold {
        // Smaller top-ups repay debt only
        return Ok(false);
    }

    tank.stage = v0::ProtTankStage::Active;
    tank.exhausted_at = None;
    tank.final_warning_at = None;
    tank.warnings_epoch = tank.warnings_epoch.saturating_add(1);

    // From Grace nothing more: today was charged at 00:00 and next_burn_day is
    // already tomorrow
    if from_frozen {
        let today = prot_utc_day(now);
        if rules.burning {
            let floor = rules.floor(tank.daily_cost);
            let amount = prot_burn_amount(
                prot_pro_rata(tank.daily_cost, prot_hours_left(now)),
                balance,
                floor,
            );
            if amount > 0 && book.row(&prot_key_burn(&tank.id, &today)).is_none() {
                book.post_new(
                    &burn_posting(&tank.id, &today, amount, floor, now),
                    operation,
                    &tank.id,
                )?;
            }
            tank.next_burn_day = Some(prot_next_day(&today)?);
        } else {
            // 7.0: no row while burning is off; the resume pass bills the rest
            tank.next_burn_day = Some(today);
        }
    }
    Ok(true)
}

/// A user id from a `user:{id}` account
fn wallet_user(account_id: &str) -> Option<&str> {
    account_id.strip_prefix("user:")
}

/// Per user: (net Prot put into the tank since `since_ms`, (created_at, _id)
/// of the first counted row). Contributions + captures of the user's pledges
/// - launch returns of those captured pledges (19.2).
fn tank_contributions_since(
    ledger: &HashMap<String, ProtLedgerEntry>,
    pledges: &HashMap<String, ProtPledge>,
    tank_id: &str,
    since_ms: i64,
) -> BTreeMap<String, (i64, (i64, String))> {
    let account = prot_tank_account(tank_id);
    let mut rows: Vec<&ProtLedgerEntry> = ledger
        .values()
        .filter(|row| row.reference.tank_id.as_deref() == Some(tank_id))
        .collect();
    rows.sort_by(|a, b| a.id.cmp(&b.id));

    let mut totals: BTreeMap<String, (i64, (i64, String))> = BTreeMap::new();
    let mut counted: HashMap<String, String> = HashMap::new();
    for row in rows.iter().filter(|row| row.created_at >= since_ms) {
        let user_id = match row.kind {
            v0::ProtEntryKind::Contribution if row.credit == account => {
                wallet_user(&row.debit).map(str::to_string)
            }
            v0::ProtEntryKind::PledgeCapture if row.credit == account => row
                .reference
                .pledge_id
                .as_deref()
                .and_then(|pledge_id| pledges.get(pledge_id))
                .map(|pledge| {
                    counted.insert(pledge.id.clone(), pledge.user_id.clone());
                    pledge.user_id.clone()
                }),
            _ => None,
        };
        if let Some(user_id) = user_id {
            let first = (row.created_at, row.id.clone());
            let total = totals.entry(user_id).or_insert((0, first.clone()));
            total.0 = total.0.saturating_add(row.amount);
            if first < total.1 {
                total.1 = first;
            }
        }
    }
    for row in &rows {
        if row.kind != v0::ProtEntryKind::LaunchReturn || row.debit != account {
            continue;
        }
        let user_id = row
            .reference
            .pledge_id
            .as_deref()
            .and_then(|pledge_id| counted.get(pledge_id));
        if let Some(total) = user_id.and_then(|user_id| totals.get_mut(user_id)) {
            total.0 = total.0.saturating_sub(row.amount);
        }
    }
    totals
}

fn page<T>(mut rows: Vec<T>, limit: i64) -> Vec<T> {
    rows.truncate(usize::try_from(limit.max(1)).unwrap_or(usize::MAX));
    rows
}

impl ReferenceDb {
    /// `capture_launch_pledges` (8.6). `burn`: the rules of the launch-day
    /// burn; None posts none (a termination captures only to forfeit).
    async fn capture_launch_pledges_locked(
        &self,
        channel_id: &str,
        now: i64,
        burn: Option<&ProtTankRules>,
    ) -> Result<Option<ProtTank>> {
        let channels = self.channels.lock().await;
        let mut entitlements = self.channel_entitlements.lock().await;
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut pledges = self.prot_pledges.lock().await;
        let mut goals = self.prot_goals.lock().await;
        let mut tanks = self.prot_tanks.lock().await;

        let target_key = prot_tank_target_key(channel_id);
        let Some(tank) = tanks
            .values()
            .find(|tank| tank.target_key == target_key)
            .cloned()
        else {
            return Ok(None);
        };
        // A Settling tank that never launched: a delete in progress (9.4)
        let settling = match tank.stage {
            v0::ProtTankStage::Launching => false,
            v0::ProtTankStage::Settling if tank.launched_at.is_none() => true,
            _ => return Ok(None),
        };
        let Some(goal) = goals
            .values()
            .find(|goal| {
                goal.tank_id.as_deref() == Some(tank.id.as_str())
                    && goal.kind == v0::ProtGoalKind::Launch
                    && goal.state == v0::ProtGoalState::Launching
            })
            .cloned()
        else {
            return Ok(None);
        };
        // Capture only once protect has landed (BR2)
        if !is_protected(&channels, Some(channel_id)) {
            return Ok(None);
        }

        let mut book = Book::stage(&ledger, &accounts);
        let changed = capture_goal_locked(
            &goal,
            &tank.id,
            &pledges,
            &mut book,
            "capture_launch_pledges",
            now,
        )?;
        let goal = ProtGoal {
            state: v0::ProtGoalState::Launched,
            launched_at: Some(now),
            open_key: None,
            version: goal.version + 1,
            updated_at: now,
            ..goal
        };

        let mut next = ProtTank {
            launched_at: Some(now),
            version: tank.version + 1,
            updated_at: now,
            ..tank
        };
        let mut entitlement = None;
        // A Settling tank keeps Settling: no launch-day burn and no
        // next_burn_day; the captured Prot goes back FIFO in full (N5)
        if !settling {
            next.stage = v0::ProtTankStage::Active;
            match burn {
                Some(rules) if rules.burning => {
                    if burn_rest_of_today(
                        &mut next,
                        &mut book,
                        now,
                        rules,
                        "capture_launch_pledges",
                    )? {
                        entitlement = entitlement_after(
                            &entitlements,
                            &next,
                            Some(ChannelEntitlementState::Grace),
                            None,
                        );
                    }
                }
                // 7.0: no row while burning is off
                _ => next.next_burn_day = Some(prot_utc_day(now)),
            }
        }

        book.land(&mut ledger, &mut accounts);
        land_pledges(&mut pledges, changed);
        goals.insert(goal.id.clone(), goal);
        land_entitlement(&mut entitlements, entitlement);
        tanks.insert(next.id.clone(), next.clone());
        Ok(Some(next))
    }

    /// Transaction 1 of a termination (9.5): Active/Grace/Frozen ->
    /// Terminated, entitlement -> Deleted, a negative balance written off and
    /// a positive one forfeited. An already Terminated tank returns its stored
    /// rows (resume).
    async fn terminate_prot_tank_locked(
        &self,
        tank_id: &str,
        admin_id: &str,
        reason: &str,
        now: i64,
    ) -> Result<(ProtTank, Option<ProtLedgerEntry>, Option<ProtLedgerEntry>)> {
        let mut entitlements = self.channel_entitlements.lock().await;
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut tanks = self.prot_tanks.lock().await;

        let tank = tanks
            .get(tank_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        match tank.stage {
            v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen => {}
            v0::ProtTankStage::Terminated => {
                let forfeit = ledger.get(&prot_key_forfeit_tank(tank_id)).cloned();
                let writeoff = ledger.get(&prot_key_writeoff(tank_id)).cloned();
                return Ok((tank, forfeit, writeoff));
            }
            _ => return Err(create_error!(InvalidOperation)),
        }

        let balance = tank_balance(&accounts, tank_id)?;
        let account = prot_tank_account(tank_id);
        let reason = Some(reason.to_string()).filter(|reason| !reason.is_empty());
        let mut book = Book::stage(&ledger, &accounts);
        let mut forfeit = None;
        let mut writeoff = None;
        if balance < 0 {
            writeoff = Some(book.post_new(
                &ProtPosting {
                    actor: admin_id.to_string(),
                    reference: tank_ref(tank_id),
                    reason: reason.clone(),
                    ..posting(
                        prot_key_writeoff(tank_id),
                        v0::ProtEntryKind::WriteOff,
                        PROT_SYS_WRITEOFF.to_string(),
                        account.clone(),
                        balance.saturating_neg(),
                        now,
                    )
                },
                "terminate_prot_tank",
                tank_id,
            )?);
        } else if balance > 0 {
            // BR15: Exact(balance), never All (the tank floor is negative)
            forfeit = Some(book.post_new(
                &ProtPosting {
                    actor: admin_id.to_string(),
                    reference: tank_ref(tank_id),
                    reason,
                    ..posting(
                        prot_key_forfeit_tank(tank_id),
                        v0::ProtEntryKind::ForfeitTank,
                        account,
                        PROT_SYS_FORFEITED.to_string(),
                        balance,
                        now,
                    )
                },
                "terminate_prot_tank",
                tank_id,
            )?);
        }

        let next = ProtTank {
            stage: v0::ProtTankStage::Terminated,
            settle_cause: Some(ProtSettleCause::Termination),
            terminated_by: Some(admin_id.to_string()),
            ended_at: Some(now),
            purge_passes: 0,
            version: tank.version + 1,
            updated_at: now,
            ..tank
        };
        let entitlement = entitlement_after(
            &entitlements,
            &next,
            Some(ChannelEntitlementState::Deleted),
            None,
        );

        book.land(&mut ledger, &mut accounts);
        land_entitlement(&mut entitlements, entitlement);
        tanks.insert(next.id.clone(), next.clone());
        Ok((next, forfeit, writeoff))
    }
}

#[async_trait]
impl AbstractProtTanks for ReferenceDb {
    async fn fetch_prot_tank(&self, tank_id: &str) -> Result<Option<ProtTank>> {
        let tanks = self.prot_tanks.lock().await;
        Ok(tanks.get(tank_id).cloned())
    }

    async fn fetch_prot_tank_by_channel(&self, channel_id: &str) -> Result<Option<ProtTank>> {
        let target_key = prot_tank_target_key(channel_id);
        let tanks = self.prot_tanks.lock().await;
        Ok(tanks
            .values()
            .find(|tank| tank.target_key == target_key)
            .cloned())
    }

    async fn fetch_prot_tanks_by_server(&self, server_id: &str) -> Result<Vec<ProtTank>> {
        let tanks = self.prot_tanks.lock().await;
        let mut rows: Vec<ProtTank> = tanks
            .values()
            .filter(|tank| tank.server_id == server_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }

    async fn fetch_prot_goal(&self, goal_id: &str) -> Result<Option<ProtGoal>> {
        let goals = self.prot_goals.lock().await;
        Ok(goals.get(goal_id).cloned())
    }

    async fn fetch_open_prot_goals_by_server(&self, server_id: &str) -> Result<Vec<ProtGoal>> {
        let goals = self.prot_goals.lock().await;
        let mut rows: Vec<ProtGoal> = goals
            .values()
            .filter(|goal| goal.server_id == server_id && is_open(goal))
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }

    async fn fetch_open_prot_goals_by_tank(&self, tank_id: &str) -> Result<Vec<ProtGoal>> {
        let goals = self.prot_goals.lock().await;
        let mut rows: Vec<ProtGoal> = goals
            .values()
            .filter(|goal| goal.tank_id.as_deref() == Some(tank_id) && is_open(goal))
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }

    async fn fetch_prot_pledge(&self, pledge_id: &str) -> Result<Option<ProtPledge>> {
        let pledges = self.prot_pledges.lock().await;
        Ok(pledges.get(pledge_id).cloned())
    }

    async fn fetch_prot_pledges_by_goal(&self, goal_id: &str) -> Result<Vec<ProtPledge>> {
        let pledges = self.prot_pledges.lock().await;
        let mut rows: Vec<ProtPledge> = pledges
            .values()
            .filter(|pledge| pledge.goal_id == goal_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }

    async fn fetch_held_prot_pledges_by_user(&self, user_id: &str) -> Result<Vec<ProtPledge>> {
        let pledges = self.prot_pledges.lock().await;
        let mut rows: Vec<ProtPledge> = pledges
            .values()
            .filter(|pledge| pledge.user_id == user_id && pledge.state == v0::ProtPledgeState::Held)
            .cloned()
            .collect();
        rows.sort_by(|a, b| b.id.cmp(&a.id));
        Ok(rows)
    }

    async fn fetch_prot_entries_by_tank(&self, tank_id: &str) -> Result<Vec<ProtLedgerEntry>> {
        let ledger = self.prot_ledger.lock().await;
        let mut rows: Vec<ProtLedgerEntry> = ledger
            .values()
            .filter(|row| row.reference.tank_id.as_deref() == Some(tank_id))
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }

    async fn fetch_prot_contributor_prefs(
        &self,
        server_id: &str,
        user_ids: &[String],
    ) -> Result<Vec<ProtContributorPref>> {
        let prefs = self.prot_contributor_prefs.lock().await;
        Ok(user_ids
            .iter()
            .filter_map(|user_id| prefs.get(&format!("{server_id}:{user_id}")).cloned())
            .collect())
    }

    async fn fetch_prot_runtime(&self) -> Result<Option<ProtRuntime>> {
        let runtime = self.prot_runtime.lock().await;
        Ok(runtime.get(PROT_RUNTIME_ID).cloned())
    }

    async fn recent_contribution(
        &self,
        user_id: &str,
        tank_id: &str,
        since_ms: i64,
    ) -> Result<i64> {
        let ledger = self.prot_ledger.lock().await;
        let pledges = self.prot_pledges.lock().await;
        Ok(
            tank_contributions_since(&ledger, &pledges, tank_id, since_ms)
                .get(user_id)
                .map_or(0, |(net, _)| (*net).max(0)),
        )
    }

    async fn top_contributor(&self, tank_id: &str, since_ms: i64) -> Result<Option<String>> {
        // Ranked under the Prot locks; the deleted-user check takes `users`
        // afterwards, on its own (it is not in the Prot lock order)
        let ranked: Vec<String> = {
            let ledger = self.prot_ledger.lock().await;
            let pledges = self.prot_pledges.lock().await;
            let tanks = self.prot_tanks.lock().await;
            let prefs = self.prot_contributor_prefs.lock().await;

            let Some(tank) = tanks.get(tank_id) else {
                return Ok(None);
            };
            let mut candidates: Vec<(String, i64, (i64, String))> =
                tank_contributions_since(&ledger, &pledges, tank_id, since_ms)
                    .into_iter()
                    .filter(|(_, (net, _))| *net > 0)
                    .filter(|(user_id, _)| {
                        !prefs
                            .get(&format!("{}:{user_id}", tank.server_id))
                            .is_some_and(|pref| pref.hidden)
                    })
                    .map(|(user_id, (net, first))| (user_id, net, first))
                    .collect();
            candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.cmp(&b.2)));
            candidates
                .into_iter()
                .map(|(user_id, _, _)| user_id)
                .collect()
        };

        let users = self.users.lock().await;
        Ok(ranked.into_iter().find(|user_id| {
            users.get(user_id).is_some_and(|user| {
                user.flags
                    .is_none_or(|flags| flags & (v0::UserFlags::Deleted as i32) == 0)
            })
        }))
    }

    async fn fetch_prot_tanks_due_burn(&self, today: &str, limit: i64) -> Result<Vec<ProtTank>> {
        let tanks = self.prot_tanks.lock().await;
        let mut rows: Vec<ProtTank> = tanks
            .values()
            .filter(|tank| {
                matches!(
                    tank.stage,
                    v0::ProtTankStage::Active | v0::ProtTankStage::Grace
                ) && tank
                    .next_burn_day
                    .as_deref()
                    .is_some_and(|day| day <= today)
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.next_burn_day
                .cmp(&b.next_burn_day)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(page(rows, limit))
    }

    async fn fetch_prot_tanks_by_stage(
        &self,
        stages: &[v0::ProtTankStage],
        after_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ProtTank>> {
        let tanks = self.prot_tanks.lock().await;
        let mut rows: Vec<ProtTank> = tanks
            .values()
            .filter(|tank| stages.contains(&tank.stage))
            .filter(|tank| after_id.is_none_or(|after| tank.id.as_str() > after))
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(page(rows, limit))
    }

    async fn fetch_prot_tanks_to_purge(
        &self,
        after_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ProtTank>> {
        let tanks = self.prot_tanks.lock().await;
        let mut rows: Vec<ProtTank> = tanks
            .values()
            .filter(|tank| {
                matches!(
                    tank.stage,
                    v0::ProtTankStage::Deleted | v0::ProtTankStage::Terminated
                ) && tank.purge_passes < 2
            })
            .filter(|tank| after_id.is_none_or(|after| tank.id.as_str() > after))
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(page(rows, limit))
    }

    async fn fetch_prot_goals_due(
        &self,
        now: i64,
        launch_seat_window_ms: i64,
        limit: i64,
    ) -> Result<Vec<ProtGoal>> {
        let goals = self.prot_goals.lock().await;
        let mut rows: Vec<ProtGoal> = goals
            .values()
            .filter(|goal| match goal.state {
                v0::ProtGoalState::Funding => goal.deadline_at <= now,
                v0::ProtGoalState::Funded => {
                    goal.kind == v0::ProtGoalKind::Upgrade
                        || goal.launch_deadline_at.is_some_and(|at| at <= now)
                }
                v0::ProtGoalState::Launching => true,
                v0::ProtGoalState::Launched => {
                    goal.kind == v0::ProtGoalKind::Launch
                        && !goal.refund7_done
                        && goal
                            .launched_at
                            .is_some_and(|at| at.saturating_add(launch_seat_window_ms) <= now)
                }
                _ => false,
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(page(rows, limit))
    }

    async fn set_prot_contributor_pref(
        &self,
        server_id: &str,
        user_id: &str,
        hidden: bool,
        now: i64,
    ) -> Result<()> {
        let mut prefs = self.prot_contributor_prefs.lock().await;
        let id = format!("{server_id}:{user_id}");
        prefs.insert(
            id.clone(),
            ProtContributorPref {
                id,
                hidden,
                updated_at: now,
            },
        );
        Ok(())
    }

    async fn contribute_prot(&self, input: &ProtContributeInput) -> Result<ProtContributeOutcome> {
        let rules = &input.rules;
        let now = input.now;

        let mut entitlements = self.channel_entitlements.lock().await;
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut tanks = self.prot_tanks.lock().await;
        let runtime = self.prot_runtime.lock().await;

        let tank = tanks
            .get(&input.tank_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        let wallet = prot_user_account(&input.user_id);
        let account = prot_tank_account(&tank.id);
        let mut contribution = ProtPosting {
            actor: input.user_id.clone(),
            reference: tank_ref(&tank.id),
            ..posting(
                prot_key_contrib(&input.user_id, &tank.id, &input.nonce),
                v0::ProtEntryKind::Contribution,
                wallet.clone(),
                account.clone(),
                input.amount,
                now,
            )
        };
        validate_prot_posting(&contribution)?;

        // A replay is decided before the stage (S5a: a duplicate key is
        // decided before the floor)
        if let Some(stored) = ledger.get(&contribution.key) {
            let outcome = duplicate_outcome(
                &contribution.key,
                &prot_payload_hash(&contribution),
                Some(stored.clone()),
            )?;
            return Ok(ProtContributeOutcome::AlreadyApplied {
                entry: outcome.entry().clone(),
                tank,
            });
        }

        let burnable = match tank.stage {
            v0::ProtTankStage::Active | v0::ProtTankStage::Grace => true,
            v0::ProtTankStage::Frozen => false,
            // NIT 23: ProtGoalClosed reads "goal"
            _ => return Err(create_error!(InvalidOperation)),
        };
        // A midnight crossed since the engine's catch-up (8.8). A tank still
        // waiting for its pause shift is not stale: its missed days are
        // paused days (7.4, N4)
        let paused = runtime
            .get(PROT_RUNTIME_ID)
            .and_then(|runtime| runtime.burn_paused_at);
        let waiting_for_shift = paused.is_some() && tank.pause_shift_for != paused;
        let today = prot_utc_day(now);
        if rules.burning
            && burnable
            && !waiting_for_shift
            && tank
                .next_burn_day
                .as_deref()
                .is_some_and(|day| day < today.as_str())
        {
            log::error!("PROT_TANK_STALE tank={}", tank.id);
            return Err(create_error!(InternalError));
        }

        // D17 (BR8): Prot bought within the hold window stays in the wallet
        let wallet_balance = accounts.get(&wallet).map_or(0, |wallet| wallet.balance);
        let held = held_purchase_prot_locked(&ledger, &input.user_id, now - rules.hold_ms())
            .min(wallet_balance)
            .max(0);
        contribution.debit_floor = held;

        let before = tank_balance(&accounts, &tank.id)?;
        let mut book = Book::stage(&ledger, &accounts);
        let entry = book.post_new(&contribution, "contribute_prot", &tank.id)?;
        let balance = book
            .balance(&account)
            .ok_or_else(|| tank_without_account(&tank.id))?;

        let mut next = tank.clone();
        let reactivated =
            reactivate_locked(&mut next, &mut book, balance, now, rules, "contribute_prot")?;
        // BR13: lifting the days left above the largest warn day re-arms the
        // warnings, so a second dip is warned again
        if !reactivated && next.stage == v0::ProtTankStage::Active && next.daily_cost > 0 {
            if let Some(largest) = rules.warn_days.iter().copied().max() {
                let largest = i64::from(largest);
                if before.div_euclid(next.daily_cost) <= largest
                    && balance.div_euclid(next.daily_cost) > largest
                {
                    next.warnings_epoch = next.warnings_epoch.saturating_add(1);
                }
            }
        }
        next.version += 1;
        next.updated_at = now;
        let entitlement = if reactivated {
            entitlement_after(
                &entitlements,
                &next,
                Some(ChannelEntitlementState::Active),
                None,
            )
        } else {
            None
        };

        book.land(&mut ledger, &mut accounts);
        land_entitlement(&mut entitlements, entitlement);
        tanks.insert(next.id.clone(), next.clone());
        Ok(ProtContributeOutcome::Applied {
            entry,
            tank: next,
            stage_changed: reactivated,
        })
    }

    async fn create_prot_goal(&self, goal: &ProtGoal) -> Result<ProtGoal> {
        let mut accounts = self.prot_accounts.lock().await;
        let mut goals = self.prot_goals.lock().await;

        if goal.state != v0::ProtGoalState::Funding
            || goal.pledged_total != 0
            || goal.open_key.is_none()
            || goal.target_prot <= 0
        {
            log::error!("PROT_GOAL_INVALID goal={}", goal.id);
            return Err(create_error!(InternalError));
        }

        // The unique open_key: one open launch goal per server, one open
        // upgrade goal per tank (BR14)
        if let Some(open) = goals
            .values()
            .find(|existing| existing.open_key.is_some() && existing.open_key == goal.open_key)
        {
            return if open.created_by == goal.created_by && open.create_nonce == goal.create_nonce {
                Ok(open.clone())
            } else {
                Err(create_error!(ProtGoalClosed))
            };
        }
        if goals.contains_key(&goal.id) {
            log::error!("PROT_GOAL_ID_TAKEN goal={}", goal.id);
            return Err(create_error!(InternalError));
        }

        let hold = prot_hold_account(&goal.id);
        accounts.entry(hold.clone()).or_insert_with(|| ProtAccount {
            id: hold,
            currency: v0::ProtCurrency::Prot,
            balance: 0,
            version: 0,
            updated_at: goal.created_at,
        });
        goals.insert(goal.id.clone(), goal.clone());
        Ok(goal.clone())
    }

    async fn pledge_prot(&self, input: &ProtPledgeInput) -> Result<ProtPledgeOutcome> {
        let rules = &input.rules;
        let now = input.now;
        if input.amount < 1 {
            return Err(create_error!(FailedValidation {
                error: "amount must be at least 1".to_string()
            }));
        }

        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut pledges = self.prot_pledges.lock().await;
        let mut goals = self.prot_goals.lock().await;

        let key = prot_key_pledge(&input.user_id, &input.goal_id, &input.nonce);
        let wallet = prot_user_account(&input.user_id);
        let hold = prot_hold_account(&input.goal_id);

        // A replay (also a concurrent request with the same nonce) returns
        // the stored pledge. The capped amount may differ, so the payload
        // hash is not compared: debit, credit and goal are (audit 27)
        if let Some(stored) = ledger.get(&key) {
            if stored.debit != wallet
                || stored.credit != hold
                || stored.reference.goal_id.as_deref() != Some(input.goal_id.as_str())
            {
                log::warn!("PROT_IDEMPOTENCY_CONFLICT key={key:?}");
                return Err(create_error!(ProtIdempotencyConflict));
            }
            let pledge = stored
                .reference
                .pledge_id
                .as_deref()
                .and_then(|pledge_id| pledges.get(pledge_id))
                .cloned()
                .ok_or_else(|| {
                    log::error!("PROT_PLEDGE_ROW_WITHOUT_PLEDGE key={key:?}");
                    create_error!(InternalError)
                })?;
            let goal = goals
                .get(&input.goal_id)
                .cloned()
                .ok_or_else(|| create_error!(NotFound))?;
            return Ok(ProtPledgeOutcome {
                pledge,
                goal,
                entry: stored.clone(),
                already_applied: true,
                funded_now: false,
            });
        }

        let goal = goals
            .get(&input.goal_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        if goal.state != v0::ProtGoalState::Funding || now >= goal.deadline_at {
            return Err(create_error!(ProtGoalClosed));
        }
        let open = goal.target_prot - goal.pledged_total;
        if open <= 0 {
            return Err(create_error!(ProtGoalClosed));
        }
        // Capped at the target; a pledge that completes the goal may be
        // below the minimum
        let amount = input.amount.min(open);
        if amount < rules.min_contribution && amount != open {
            return Err(create_error!(FailedValidation {
                error: "below the minimum".to_string()
            }));
        }

        // D17 (BR8), read under the same locks as the debit
        let wallet_balance = accounts.get(&wallet).map_or(0, |wallet| wallet.balance);
        let held = held_purchase_prot_locked(&ledger, &input.user_id, now - rules.hold_ms())
            .min(wallet_balance)
            .max(0);

        let pledge_id = ulid::Ulid::new().to_string();
        let mut book = Book::stage(&ledger, &accounts);
        let entry = book.post_new(
            &ProtPosting {
                debit_floor: held,
                actor: input.user_id.clone(),
                reference: pledge_ref(&goal.id, &pledge_id, None),
                ..posting(
                    key,
                    v0::ProtEntryKind::PledgeHold,
                    wallet,
                    hold,
                    amount,
                    now,
                )
            },
            "pledge_prot",
            &goal.id,
        )?;

        let pledge = ProtPledge {
            id: pledge_id,
            goal_id: goal.id.clone(),
            server_id: goal.server_id.clone(),
            user_id: input.user_id.clone(),
            kind: goal.kind,
            amount,
            remaining: amount,
            state: v0::ProtPledgeState::Held,
            captured: 0,
            launch_returned: 0,
            version: 0,
            created_at: now,
            updated_at: now,
        };
        let mut goal = ProtGoal {
            pledged_total: goal.pledged_total + amount,
            version: goal.version + 1,
            updated_at: now,
            ..goal
        };
        let funded_now = goal.pledged_total >= goal.target_prot;
        if funded_now {
            // For an Upgrade goal this is the apply deadline (8.7)
            goal.state = v0::ProtGoalState::Funded;
            goal.funded_at = Some(now);
            goal.launch_deadline_at = Some(now.saturating_add(days_ms(rules.launch_window_days)));
        }

        book.land(&mut ledger, &mut accounts);
        pledges.insert(pledge.id.clone(), pledge.clone());
        goals.insert(goal.id.clone(), goal.clone());
        Ok(ProtPledgeOutcome {
            pledge,
            goal,
            entry,
            already_applied: false,
            funded_now,
        })
    }

    async fn withdraw_prot_pledge(
        &self,
        pledge_id: &str,
        user_id: &str,
        now: i64,
        cutoff_ms: i64,
    ) -> Result<ProtPledge> {
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut pledges = self.prot_pledges.lock().await;
        let mut goals = self.prot_goals.lock().await;

        let pledge = pledges
            .get(pledge_id)
            .filter(|pledge| pledge.user_id == user_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        let goal = goals
            .get(&pledge.goal_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        if goal.state != v0::ProtGoalState::Funding
            || now > goal.deadline_at.saturating_sub(cutoff_ms)
        {
            return Err(create_error!(ProtGoalClosed));
        }
        // The pledge-state CAS: only a pledge still in the hold can leave it
        if pledge.state != v0::ProtPledgeState::Held {
            return Err(create_error!(InvalidOperation));
        }

        let mut book = Book::stage(&ledger, &accounts);
        if pledge.remaining > 0 {
            book.post_new(
                &ProtPosting {
                    actor: user_id.to_string(),
                    reference: pledge_ref(&goal.id, &pledge.id, None),
                    ..posting(
                        prot_key_pledge_withdraw(&pledge.id),
                        v0::ProtEntryKind::PledgeWithdraw,
                        prot_hold_account(&goal.id),
                        prot_user_account(user_id),
                        pledge.remaining,
                        now,
                    )
                },
                "withdraw_prot_pledge",
                &pledge.id,
            )?;
        }
        let goal = ProtGoal {
            pledged_total: goal.pledged_total - pledge.remaining,
            version: goal.version + 1,
            updated_at: now,
            ..goal
        };
        let pledge = ProtPledge {
            state: v0::ProtPledgeState::Withdrawn,
            remaining: 0,
            version: pledge.version + 1,
            updated_at: now,
            ..pledge
        };

        book.land(&mut ledger, &mut accounts);
        pledges.insert(pledge.id.clone(), pledge.clone());
        goals.insert(goal.id.clone(), goal);
        Ok(pledge)
    }

    async fn close_prot_goal(
        &self,
        goal_id: &str,
        to: v0::ProtGoalState,
        now: i64,
    ) -> Result<ProtGoalCloseOutcome> {
        let channels = self.channels.lock().await;
        let mut entitlements = self.channel_entitlements.lock().await;
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut pledges = self.prot_pledges.lock().await;
        let mut goals = self.prot_goals.lock().await;
        let mut tanks = self.prot_tanks.lock().await;

        let goal = goals
            .get(goal_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        let allowed = match (goal.state, to) {
            (v0::ProtGoalState::Funding, v0::ProtGoalState::Expired)
            | (v0::ProtGoalState::Funding, v0::ProtGoalState::Cancelled)
            | (v0::ProtGoalState::Funded, v0::ProtGoalState::Cancelled)
            | (v0::ProtGoalState::Launching, v0::ProtGoalState::Cancelled) => true,
            (_, v0::ProtGoalState::Expired) | (_, v0::ProtGoalState::Cancelled) => false,
            (_, to) => {
                log::error!("PROT_GOAL_CLOSE_INVALID goal={goal_id} to={}", to.as_str());
                return Err(create_error!(InternalError));
            }
        };
        if !allowed {
            return Err(create_error!(ProtGoalClosed));
        }

        // An abandoned launch (BR2): the channel is read under the same locks
        // as the entitlement delete, so abandon and protect serialize. Once
        // protect has landed only a capture may end the goal.
        let mut removed_tank = None;
        let mut removed_entitlements = Vec::new();
        if goal.state == v0::ProtGoalState::Launching {
            if is_protected(&channels, goal.channel_id.as_deref()) {
                return Err(create_error!(InvalidOperation));
            }
            if let Some(tank) = goal
                .tank_id
                .as_deref()
                .and_then(|tank_id| tanks.get(tank_id))
            {
                let never_launched = tank.launched_at.is_none()
                    && matches!(
                        tank.stage,
                        v0::ProtTankStage::Launching | v0::ProtTankStage::Settling
                    );
                let balance = accounts
                    .get(&prot_tank_account(&tank.id))
                    .map_or(0, |account| account.balance);
                if !never_launched || balance != 0 {
                    log::error!(
                        "PROT_ABANDON_REFUSED goal={goal_id} tank={} stage={} balance={balance}",
                        tank.id,
                        tank.stage.as_str()
                    );
                    return Err(create_error!(InternalError));
                }
                removed_tank = Some(tank.clone());
            }
            if let Some(channel_id) = goal.channel_id.as_deref() {
                removed_entitlements = entitlements
                    .values()
                    .filter(|entitlement| {
                        entitlement.channel_id == channel_id
                            && entitlement.source == ChannelEntitlementSource::Crowdfund
                    })
                    .map(|entitlement| entitlement.id.clone())
                    .collect();
            }
        }

        let mut book = Book::stage(&ledger, &accounts);
        let (goal, changed, returned) = close_goal_locked(&goal, to, &pledges, &mut book, now)?;

        book.land(&mut ledger, &mut accounts);
        land_pledges(&mut pledges, changed);
        goals.insert(goal.id.clone(), goal.clone());
        if let Some(tank) = &removed_tank {
            tanks.remove(&tank.id);
            accounts.remove(&prot_tank_account(&tank.id));
        }
        for id in removed_entitlements {
            entitlements.remove(&id);
        }
        Ok(ProtGoalCloseOutcome {
            goal,
            returned,
            removed_tank,
        })
    }

    async fn launch_prot_goal(&self, input: &ProtLaunchInput) -> Result<(ProtGoal, ProtTank)> {
        let now = input.now;
        let channels = self.channels.lock().await;
        let messages = self.messages.lock().await;
        let mut entitlements = self.channel_entitlements.lock().await;
        let servers = self.servers.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut goals = self.prot_goals.lock().await;
        let mut tanks = self.prot_tanks.lock().await;

        let goal = goals
            .get(&input.goal_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        if goal.kind != v0::ProtGoalKind::Launch {
            return Err(create_error!(InvalidOperation));
        }
        if goal.state != v0::ProtGoalState::Funded
            || goal.launch_deadline_at.is_none_or(|at| now > at)
        {
            return Err(create_error!(ProtGoalClosed));
        }
        // Authority is the server's owner at call time (11.3)
        let server = servers
            .get(&goal.server_id)
            .ok_or_else(|| create_error!(NotFound))?;
        if server.owner != input.owner_id {
            return Err(create_error!(NotOwner));
        }
        // Another server's channel looks absent (IDOR)
        let channel = channels
            .get(&input.channel_id)
            .filter(|channel| seat_list_channel_server(channel) == Some(goal.server_id.as_str()))
            .ok_or_else(|| create_error!(NotFound))?;
        check_channel_protectable(Some(channel))?;
        // `last_message_id` lags stored messages: ask the messages themselves
        if messages
            .values()
            .any(|message| message.channel == input.channel_id)
        {
            return Err(create_error!(InvalidOperation));
        }
        if entitlements
            .values()
            .any(|entitlement| entitlement.channel_id == input.channel_id)
        {
            return Err(create_error!(InvalidOperation));
        }
        let target_key = prot_tank_target_key(&input.channel_id);
        if tanks.values().any(|tank| tank.target_key == target_key) {
            return Err(create_error!(InvalidOperation));
        }

        let entitlement = ChannelEntitlement {
            id: ulid::Ulid::new().to_string(),
            channel_id: input.channel_id.clone(),
            server_id: goal.server_id.clone(),
            source: ChannelEntitlementSource::Crowdfund,
            slot_cap: goal.slots,
            device_cap: None,
            state: ChannelEntitlementState::Active,
            granted_by: input.owner_id.clone(),
            created_at: timestamp_of(now)?,
        };
        let tank = ProtTank {
            id: ulid::Ulid::new().to_string(),
            target: ProtTankTarget::Channel {
                channel_id: input.channel_id.clone(),
            },
            target_key,
            server_id: goal.server_id.clone(),
            created_by: input.owner_id.clone(),
            plan: v0::ProtPlan::Channel,
            slot_tier: goal.slots,
            pending_slot_tier: None,
            // The goal's snapshot: a config edit never moves a date
            daily_cost: goal.daily_cost,
            rate_card: input.rules.rate_card(),
            stage: v0::ProtTankStage::Launching,
            exhausted_at: None,
            next_burn_day: None,
            launched_at: None,
            final_warning_at: None,
            warnings_epoch: 0,
            pause_shift_for: None,
            settle_cause: None,
            ended_at: None,
            terminated_by: None,
            purged_at: None,
            purge_passes: 0,
            version: 0,
            created_at: now,
            updated_at: now,
        };
        let goal = ProtGoal {
            state: v0::ProtGoalState::Launching,
            channel_id: Some(input.channel_id.clone()),
            tank_id: Some(tank.id.clone()),
            version: goal.version + 1,
            updated_at: now,
            ..goal
        };

        let account = prot_tank_account(&tank.id);
        accounts.insert(
            account.clone(),
            ProtAccount {
                id: account,
                currency: v0::ProtCurrency::Prot,
                balance: 0,
                version: 0,
                updated_at: now,
            },
        );
        entitlements.insert(entitlement.id.clone(), entitlement);
        tanks.insert(tank.id.clone(), tank.clone());
        goals.insert(goal.id.clone(), goal.clone());
        Ok((goal, tank))
    }

    async fn capture_launch_pledges(
        &self,
        channel_id: &str,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<Option<ProtTank>> {
        self.capture_launch_pledges_locked(channel_id, now, Some(rules))
            .await
    }

    async fn return_unseated_launch_pledges(
        &self,
        goal_id: &str,
        now: i64,
    ) -> Result<Vec<ProtLedgerEntry>> {
        let servers = self.servers.lock().await;
        let seats = self.channel_seats.lock().await;
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut pledges = self.prot_pledges.lock().await;
        let mut goals = self.prot_goals.lock().await;
        let mut tanks = self.prot_tanks.lock().await;

        let goal = goals
            .get(goal_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        // Once (the refund7_done CAS), for a launched Launch goal only
        if goal.kind != v0::ProtGoalKind::Launch
            || goal.state != v0::ProtGoalState::Launched
            || goal.refund7_done
        {
            return Ok(Vec::new());
        }
        let done = ProtGoal {
            refund7_done: true,
            version: goal.version + 1,
            updated_at: now,
            ..goal.clone()
        };

        let tank = goal
            .tank_id
            .as_deref()
            .and_then(|tank_id| tanks.get(tank_id))
            .filter(|tank| {
                matches!(
                    tank.stage,
                    v0::ProtTankStage::Active
                        | v0::ProtTankStage::Grace
                        | v0::ProtTankStage::Frozen
                )
            })
            .cloned();
        let Some((tank, channel_id)) = tank.and_then(|tank| {
            let channel_id = tank_channel(&tank)?.to_string();
            Some((tank, channel_id))
        }) else {
            goals.insert(done.id.clone(), done);
            return Ok(Vec::new());
        };

        // The owner is exempt; everyone else needs an ACTIVE seat now
        let owner = servers
            .get(&goal.server_id)
            .map(|server| server.owner.clone());
        let mut captured: Vec<&ProtPledge> = pledges
            .values()
            .filter(|pledge| {
                pledge.goal_id == goal.id
                    && pledge.kind == v0::ProtGoalKind::Launch
                    && pledge.state == v0::ProtPledgeState::Captured
                    && pledge.captured > 0
                    && owner.as_deref() != Some(pledge.user_id.as_str())
                    && !seats
                        .get(&ChannelSeat::composite_id(&channel_id, &pledge.user_id))
                        .is_some_and(|seat| seat.is_active())
            })
            .collect();
        captured.sort_by(|a, b| a.id.cmp(&b.id));
        let due: Vec<(String, i64)> = captured
            .iter()
            .map(|pledge| (pledge.id.clone(), pledge.captured))
            .collect();
        let balance = tank_balance(&accounts, &tank.id)?;

        let mut book = Book::stage(&ledger, &accounts);
        let mut entries = Vec::new();
        let mut changed = Vec::new();
        for (pledge_id, amount) in plan_unseated_returns(&due, balance) {
            let Some(pledge) = pledges.get(&pledge_id) else {
                continue;
            };
            entries.push(book.post_new(
                &ProtPosting {
                    reference: pledge_ref(&goal.id, &pledge.id, Some(&tank.id)),
                    ..posting(
                        prot_key_launch_return(&pledge.id),
                        v0::ProtEntryKind::LaunchReturn,
                        prot_tank_account(&tank.id),
                        prot_user_account(&pledge.user_id),
                        amount,
                        now,
                    )
                },
                "return_unseated_launch_pledges",
                &goal.id,
            )?);
            changed.push(ProtPledge {
                launch_returned: amount,
                version: pledge.version + 1,
                updated_at: now,
                ..pledge.clone()
            });
        }

        book.land(&mut ledger, &mut accounts);
        land_pledges(&mut pledges, changed);
        goals.insert(done.id.clone(), done);
        if !entries.is_empty() {
            tanks.insert(
                tank.id.clone(),
                ProtTank {
                    version: tank.version + 1,
                    updated_at: now,
                    ..tank
                },
            );
        }
        Ok(entries)
    }

    async fn apply_prot_upgrade_goal(
        &self,
        goal_id: &str,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<Option<ProtTank>> {
        let mut entitlements = self.channel_entitlements.lock().await;
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut pledges = self.prot_pledges.lock().await;
        let mut goals = self.prot_goals.lock().await;
        let mut tanks = self.prot_tanks.lock().await;

        let goal = goals
            .get(goal_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        if goal.kind != v0::ProtGoalKind::Upgrade || goal.state != v0::ProtGoalState::Funded {
            return Ok(None);
        }
        let tank = goal
            .tank_id
            .as_deref()
            .and_then(|tank_id| tanks.get(tank_id))
            .cloned();

        let apply = match &tank {
            // Still launching: the capture comes first
            Some(tank) if tank.stage == v0::ProtTankStage::Launching => return Ok(None),
            // The tier moved anyway: pledgers never pay for an upgrade they
            // don't get
            Some(tank) if goal.slots <= tank.slot_tier => false,
            Some(tank) => matches!(
                tank.stage,
                v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen
            ),
            None => false,
        };
        let mut book = Book::stage(&ledger, &accounts);
        let (Some(tank), true) = (tank, apply) else {
            // Settling / Deleted / Terminated (or no tank): full returns
            let (goal, changed, _) = close_goal_locked(
                &goal,
                v0::ProtGoalState::Cancelled,
                &pledges,
                &mut book,
                now,
            )?;
            book.land(&mut ledger, &mut accounts);
            land_pledges(&mut pledges, changed);
            goals.insert(goal.id.clone(), goal);
            return Ok(None);
        };

        let changed = capture_goal_locked(
            &goal,
            &tank.id,
            &pledges,
            &mut book,
            "apply_prot_upgrade_goal",
            now,
        )?;
        let balance = book
            .balance(&prot_tank_account(&tank.id))
            .ok_or_else(|| tank_without_account(&tank.id))?;
        let new_cost = goal.daily_cost;

        let mut next = tank.clone();
        if tank.stage == v0::ProtTankStage::Active && rules.burning {
            // The apply clamps at 0 (a manual upgrade refuses instead, N5)
            let charge = prot_burn_amount(
                prot_pro_rata(new_cost - tank.daily_cost, prot_hours_left(now)),
                balance,
                0,
            );
            if charge > 0 {
                book.post_new(
                    &ProtPosting {
                        reference: tank_ref(&tank.id),
                        ..posting(
                            prot_key_tier(&tank.id, &format!("goal-{}", goal.id)),
                            v0::ProtEntryKind::TierUpgrade,
                            prot_tank_account(&tank.id),
                            PROT_SYS_BURNED.to_string(),
                            charge,
                            now,
                        )
                    },
                    "apply_prot_upgrade_goal",
                    &goal.id,
                )?;
            }
        }
        next.slot_tier = goal.slots;
        next.daily_cost = new_cost;
        next.rate_card = rules.rate_card();
        next.pending_slot_tier = None;
        // Grace / Frozen: no tier row (today was charged at the old cost, or
        // not at all while frozen); reactivation at the NEW cost
        let reactivated = reactivate_locked(
            &mut next,
            &mut book,
            balance,
            now,
            rules,
            "apply_prot_upgrade_goal",
        )?;
        next.version += 1;
        next.updated_at = now;
        let entitlement = entitlement_after(
            &entitlements,
            &next,
            reactivated.then_some(ChannelEntitlementState::Active),
            Some(goal.slots),
        );
        let goal = ProtGoal {
            state: v0::ProtGoalState::Applied,
            open_key: None,
            closed_at: Some(now),
            version: goal.version + 1,
            updated_at: now,
            ..goal
        };

        book.land(&mut ledger, &mut accounts);
        land_pledges(&mut pledges, changed);
        goals.insert(goal.id.clone(), goal);
        land_entitlement(&mut entitlements, entitlement);
        tanks.insert(next.id.clone(), next.clone());
        Ok(Some(next))
    }

    async fn change_prot_tier(&self, input: &ProtTierChangeInput) -> Result<ProtTank> {
        let rules = &input.rules;
        let now = input.now;

        let mut entitlements = self.channel_entitlements.lock().await;
        let servers = self.servers.lock().await;
        let seats = self.channel_seats.lock().await;
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let goals = self.prot_goals.lock().await;
        let mut tanks = self.prot_tanks.lock().await;

        let tank = tanks
            .get(&input.tank_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        let Some(cost) = rules.daily_cost(input.slots) else {
            return Err(create_error!(FailedValidation {
                error: "slots must be 10, 25, 50 or 100".to_string()
            }));
        };
        let key = prot_key_tier(&tank.id, &input.change_id);
        // A replay of an applied upgrade
        if ledger.contains_key(&key) {
            return Ok(tank);
        }
        // 8.7: the tier cannot move under an open upgrade goal
        if goals.values().any(|goal| {
            goal.tank_id.as_deref() == Some(tank.id.as_str())
                && goal.kind == v0::ProtGoalKind::Upgrade
                && is_open(goal)
        }) {
            return Err(create_error!(InvalidOperation));
        }
        if !matches!(
            tank.stage,
            v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen
        ) {
            return Err(create_error!(InvalidOperation));
        }

        let mut next = tank.clone();
        let mut book = Book::stage(&ledger, &accounts);
        let mut slot_cap = None;
        if input.slots == tank.slot_tier {
            // The current tier: a pending downgrade is called off
            if tank.pending_slot_tier.is_none() {
                return Ok(tank);
            }
            next.pending_slot_tier = None;
        } else if input.slots > tank.slot_tier {
            if tank.stage != v0::ProtTankStage::Active {
                return Err(create_error!(InvalidOperation));
            }
            let charge = if rules.burning {
                prot_pro_rata(cost - tank.daily_cost, prot_hours_left(now))
            } else {
                0
            };
            let balance = tank_balance(&accounts, &tank.id)?;
            // A manual upgrade never borrows: it refuses (N5)
            if balance - charge < 0 {
                return Err(create_error!(InsufficientProt {
                    needed: charge,
                    available: balance.max(0)
                }));
            }
            if charge > 0 {
                let owner = servers
                    .get(&tank.server_id)
                    .map_or_else(|| tank.created_by.clone(), |server| server.owner.clone());
                book.post_new(
                    &ProtPosting {
                        actor: owner,
                        reference: tank_ref(&tank.id),
                        ..posting(
                            key,
                            v0::ProtEntryKind::TierUpgrade,
                            prot_tank_account(&tank.id),
                            PROT_SYS_BURNED.to_string(),
                            charge,
                            now,
                        )
                    },
                    "change_prot_tier",
                    &tank.id,
                )?;
            }
            next.slot_tier = input.slots;
            next.daily_cost = cost;
            next.rate_card = rules.rate_card();
            next.pending_slot_tier = None;
            slot_cap = Some(input.slots);
        } else {
            let channel_id = tank_channel(&tank).unwrap_or_default();
            let channel_seats: Vec<ChannelSeat> = seats
                .values()
                .filter(|seat| seat.channel_id == channel_id)
                .cloned()
                .collect();
            let used = channel_seats_used(&channel_seats, timestamp_of(now)?);
            if used <= input.slots as usize {
                // The new cost from the next burn; today is not refunded and
                // the lower floor is the 7.0 clamp's
                next.slot_tier = input.slots;
                next.daily_cost = cost;
                next.rate_card = rules.rate_card();
                next.pending_slot_tier = None;
                slot_cap = Some(input.slots);
            } else {
                // Applied by the clock once cooldowns free the seats
                next.pending_slot_tier = Some(input.slots);
            }
        }
        next.version += 1;
        next.updated_at = now;
        let entitlement = slot_cap
            .and_then(|slot_cap| entitlement_after(&entitlements, &next, None, Some(slot_cap)));

        book.land(&mut ledger, &mut accounts);
        land_entitlement(&mut entitlements, entitlement);
        tanks.insert(next.id.clone(), next.clone());
        Ok(next)
    }

    async fn apply_pending_prot_tier(
        &self,
        tank_id: &str,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<Option<ProtTank>> {
        let mut entitlements = self.channel_entitlements.lock().await;
        let seats = self.channel_seats.lock().await;
        let mut tanks = self.prot_tanks.lock().await;

        let tank = tanks
            .get(tank_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        let Some(pending) = tank.pending_slot_tier else {
            return Ok(None);
        };
        if !matches!(
            tank.stage,
            v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen
        ) {
            return Ok(None);
        }
        let mut next = ProtTank {
            version: tank.version + 1,
            updated_at: now,
            ..tank.clone()
        };
        let mut slot_cap = None;
        match rules.daily_cost(pending) {
            Some(cost) if pending < tank.slot_tier => {
                let channel_id = tank_channel(&tank).unwrap_or_default();
                let channel_seats: Vec<ChannelSeat> = seats
                    .values()
                    .filter(|seat| seat.channel_id == channel_id)
                    .cloned()
                    .collect();
                if channel_seats_used(&channel_seats, timestamp_of(now)?) > pending as usize {
                    return Ok(None);
                }
                next.slot_tier = pending;
                next.daily_cost = cost;
                next.rate_card = rules.rate_card();
                slot_cap = Some(pending);
            }
            // Not a downgrade (or not a tier) any more: nothing to apply
            _ => log::warn!(
                "PROT_PENDING_TIER_DROPPED tank={tank_id} pending={pending} tier={}",
                tank.slot_tier
            ),
        }
        next.pending_slot_tier = None;
        let entitlement = slot_cap
            .and_then(|slot_cap| entitlement_after(&entitlements, &next, None, Some(slot_cap)));

        land_entitlement(&mut entitlements, entitlement);
        tanks.insert(next.id.clone(), next.clone());
        Ok(Some(next))
    }

    async fn burn_prot_tank_day(
        &self,
        tank_id: &str,
        day: &str,
        paused: Option<i64>,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<ProtBurnOutcome> {
        let mut entitlements = self.channel_entitlements.lock().await;
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut tanks = self.prot_tanks.lock().await;

        let tank = tanks
            .get(tank_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        // 7.0: nothing is billed while burning is off, and while a pause is
        // recorded only a tank already shifted for it is billed
        if !rules.burning
            || !matches!(
                tank.stage,
                v0::ProtTankStage::Active | v0::ProtTankStage::Grace
            )
            || tank.next_burn_day.as_deref() != Some(day)
            || paused.is_some_and(|paused| tank.pause_shift_for != Some(paused))
        {
            return Ok(ProtBurnOutcome::NotDue { tank });
        }

        let balance = tank_balance(&accounts, tank_id)?;
        let floor = rules.floor(tank.daily_cost);
        let plan = plan_tank_day(&tank, balance, day, rules)?;

        let mut book = Book::stage(&ledger, &accounts);
        let amount = match plan {
            ProtDayPlan::Burn { amount } | ProtDayPlan::EnterGrace { amount, .. } => amount,
            ProtDayPlan::Freeze | ProtDayPlan::Advance => 0,
        };
        let entry = if amount > 0 {
            Some(book.post_new(
                &burn_posting(tank_id, day, amount, floor, now),
                "burn_prot_tank_day",
                tank_id,
            )?)
        } else {
            None
        };

        let mut next = ProtTank {
            version: tank.version + 1,
            updated_at: now,
            ..tank
        };
        let mut state = None;
        match plan {
            ProtDayPlan::Burn { .. } | ProtDayPlan::Advance => {
                next.next_burn_day = Some(prot_next_day(day)?);
            }
            ProtDayPlan::EnterGrace { exhausted_at, .. } => {
                next.next_burn_day = Some(prot_next_day(day)?);
                next.stage = v0::ProtTankStage::Grace;
                next.exhausted_at = Some(exhausted_at);
                state = Some(ChannelEntitlementState::Grace);
            }
            // Frozen days are never billed: next_burn_day stays
            ProtDayPlan::Freeze => {
                next.stage = v0::ProtTankStage::Frozen;
                state = Some(ChannelEntitlementState::Frozen);
            }
        }
        let entitlement =
            state.and_then(|state| entitlement_after(&entitlements, &next, Some(state), None));

        book.land(&mut ledger, &mut accounts);
        land_entitlement(&mut entitlements, entitlement);
        tanks.insert(next.id.clone(), next.clone());
        Ok(match (plan, entry) {
            (ProtDayPlan::Burn { .. }, Some(entry)) => {
                ProtBurnOutcome::Burned { entry, tank: next }
            }
            (ProtDayPlan::Freeze, _) => ProtBurnOutcome::Froze { tank: next },
            // EnterGrace, and a Grace day clamped to 0 at the floor (Advance):
            // the tank is in Grace and the catch-up goes on
            (_, entry) => ProtBurnOutcome::EnteredGrace { entry, tank: next },
        })
    }

    async fn record_prot_notice(
        &self,
        tank_id: &str,
        epoch: u64,
        kind: ProtNoticeKind,
        delivered: bool,
        now: i64,
    ) -> Result<bool> {
        let mut tanks = self.prot_tanks.lock().await;
        let mut notices = self.prot_notices.lock().await;

        let key = prot_notice_key(tank_id, epoch, kind);
        if notices.contains_key(&key) {
            return Ok(false);
        }
        // The Final notice dates the deletion guard (7.5): only for the epoch
        // it was computed from
        let final_warning = if kind == ProtNoticeKind::Final {
            let tank = tanks
                .get(tank_id)
                .cloned()
                .ok_or_else(|| create_error!(NotFound))?;
            if tank.warnings_epoch != epoch {
                return Ok(false);
            }
            Some(ProtTank {
                final_warning_at: Some(now),
                version: tank.version + 1,
                updated_at: now,
                ..tank
            })
        } else {
            None
        };

        notices.insert(
            key.clone(),
            ProtNotice {
                id: key,
                tank_id: tank_id.to_string(),
                sent_at: now,
                delivered,
            },
        );
        if let Some(tank) = final_warning {
            tanks.insert(tank.id.clone(), tank);
        }
        Ok(true)
    }

    async fn set_prot_burn_paused(&self, at: i64) -> Result<bool> {
        let mut runtime = self.prot_runtime.lock().await;
        let row = runtime
            .entry(PROT_RUNTIME_ID.to_string())
            .or_insert_with(|| ProtRuntime {
                id: PROT_RUNTIME_ID.to_string(),
                burn_paused_at: None,
                version: 0,
            });
        if row.burn_paused_at.is_some() {
            return Ok(false);
        }
        row.burn_paused_at = Some(at);
        row.version += 1;
        Ok(true)
    }

    async fn clear_prot_burn_paused(&self, expected: i64) -> Result<bool> {
        let mut runtime = self.prot_runtime.lock().await;
        match runtime.get_mut(PROT_RUNTIME_ID) {
            Some(row) if row.burn_paused_at == Some(expected) => {
                row.burn_paused_at = None;
                row.version += 1;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn shift_prot_tank_for_pause(
        &self,
        tank_id: &str,
        paused_at: i64,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<bool> {
        let mut entitlements = self.channel_entitlements.lock().await;
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut tanks = self.prot_tanks.lock().await;

        let tank = tanks
            .get(tank_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        // The resume pass runs only while burning is back on (7.1 step 1)
        if !rules.burning
            || tank.pause_shift_for == Some(paused_at)
            || !matches!(
                tank.stage,
                v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen
            )
        {
            return Ok(false);
        }

        // Grace and Frozen deadlines move with the pause
        let shift = now.saturating_sub(paused_at).max(0);
        let mut next = ProtTank {
            exhausted_at: tank.exhausted_at.map(|at| at.saturating_add(shift)),
            final_warning_at: tank.final_warning_at.map(|at| at.saturating_add(shift)),
            pause_shift_for: Some(paused_at),
            version: tank.version + 1,
            updated_at: now,
            ..tank
        };

        let mut book = Book::stage(&ledger, &accounts);
        let mut entered_grace = false;
        let today = prot_utc_day(now);
        let due = matches!(
            next.stage,
            v0::ProtTankStage::Active | v0::ProtTankStage::Grace
        ) && next
            .next_burn_day
            .as_deref()
            .is_some_and(|day| day <= today.as_str());
        if due {
            let grace_over = next.stage == v0::ProtTankStage::Grace
                && next.exhausted_at.is_some_and(|at| {
                    prot_day_start_ms(&today)
                        .is_ok_and(|start| start >= at.saturating_add(days_ms(rules.grace_days)))
                });
            if grace_over {
                // Not billed: today's burn freezes it (7.2 checks Freeze first)
                next.next_burn_day = Some(today);
            } else {
                // BR12: the rest of today only; the days in between are never
                // billed. A clamped 0 writes no row and the shift still lands.
                entered_grace = burn_rest_of_today(
                    &mut next,
                    &mut book,
                    now,
                    rules,
                    "shift_prot_tank_for_pause",
                )?;
            }
        }
        let entitlement = if entered_grace {
            entitlement_after(
                &entitlements,
                &next,
                Some(ChannelEntitlementState::Grace),
                None,
            )
        } else {
            None
        };

        book.land(&mut ledger, &mut accounts);
        land_entitlement(&mut entitlements, entitlement);
        tanks.insert(next.id.clone(), next);
        Ok(true)
    }

    async fn begin_prot_settlement(
        &self,
        tank_id: &str,
        cause: ProtSettleCause,
        now: i64,
    ) -> Result<Option<ProtTank>> {
        let mut entitlements = self.channel_entitlements.lock().await;
        let mut tanks = self.prot_tanks.lock().await;

        let Some(tank) = tanks.get(tank_id).cloned() else {
            return Ok(None);
        };
        let traffic_stops = match tank.stage {
            v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen => {
                true
            }
            // A delete of a never-launched tank: the entitlement is left to
            // the goal close or the capture (9.4)
            v0::ProtTankStage::Launching => false,
            // Resume
            v0::ProtTankStage::Settling => return Ok(Some(tank)),
            v0::ProtTankStage::Deleted | v0::ProtTankStage::Terminated => return Ok(None),
        };
        let next = ProtTank {
            stage: v0::ProtTankStage::Settling,
            settle_cause: Some(cause),
            version: tank.version + 1,
            updated_at: now,
            ..tank
        };
        let entitlement = if traffic_stops {
            entitlement_after(
                &entitlements,
                &next,
                Some(ChannelEntitlementState::Frozen),
                None,
            )
        } else {
            None
        };

        land_entitlement(&mut entitlements, entitlement);
        tanks.insert(next.id.clone(), next.clone());
        Ok(Some(next))
    }

    async fn settle_prot_tank(&self, tank_id: &str, now: i64) -> Result<ProtSettlement> {
        let mut entitlements = self.channel_entitlements.lock().await;
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let pledges = self.prot_pledges.lock().await;
        let goals = self.prot_goals.lock().await;
        let mut tanks = self.prot_tanks.lock().await;

        let tank = tanks
            .get(tank_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))?;
        let account = prot_tank_account(tank_id);
        match tank.stage {
            v0::ProtTankStage::Settling => {}
            // A racing run settled it: the stored outcome, never a conflict
            v0::ProtTankStage::Deleted => {
                let mut returns: Vec<ProtLedgerEntry> = ledger
                    .values()
                    .filter(|row| row.kind == v0::ProtEntryKind::Settlement && row.debit == account)
                    .cloned()
                    .collect();
                returns.sort_by(|a, b| a.id.cmp(&b.id));
                let writeoff = ledger.get(&prot_key_writeoff(tank_id)).cloned();
                return Ok(ProtSettlement {
                    tank,
                    returns,
                    writeoff,
                });
            }
            _ => return Err(create_error!(InvalidOperation)),
        }
        // Held pledges of an open goal would be stranded by a Deleted tank:
        // the caller closes (or captures) the tank's goals first (7.5, 9.4)
        if goals
            .values()
            .any(|goal| goal.tank_id.as_deref() == Some(tank_id) && is_open(goal))
        {
            log::error!("PROT_SETTLE_WITH_OPEN_GOAL tank={tank_id}");
            return Err(create_error!(InvalidOperation));
        }

        // D7: FIFO lots from the tank's rows, in the same lock section
        let mut rows: Vec<&ProtLedgerEntry> = ledger
            .values()
            .filter(|row| row.reference.tank_id.as_deref() == Some(tank_id))
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        let mut lots: Vec<ProtLot> = Vec::new();
        let mut lot_of_pledge: HashMap<String, usize> = HashMap::new();
        let mut burned: i64 = 0;
        for row in &rows {
            match row.kind {
                v0::ProtEntryKind::Contribution if row.credit == account => {
                    let user_id = wallet_user(&row.debit).ok_or_else(|| {
                        log::error!("PROT_SETTLE_BAD_LOT row={}", row.id);
                        create_error!(InternalError)
                    })?;
                    lots.push(ProtLot {
                        key: row.id.clone(),
                        user_id: user_id.to_string(),
                        created_at: row.created_at,
                        amount: row.amount,
                    });
                }
                v0::ProtEntryKind::PledgeCapture if row.credit == account => {
                    let pledge = row
                        .reference
                        .pledge_id
                        .as_deref()
                        .and_then(|pledge_id| pledges.get(pledge_id))
                        .ok_or_else(|| {
                            log::error!("PROT_SETTLE_BAD_LOT row={}", row.id);
                            create_error!(InternalError)
                        })?;
                    lot_of_pledge.insert(pledge.id.clone(), lots.len());
                    lots.push(ProtLot {
                        key: row.id.clone(),
                        user_id: pledge.user_id.clone(),
                        created_at: row.created_at,
                        amount: row.amount,
                    });
                }
                v0::ProtEntryKind::Burn | v0::ProtEntryKind::TierUpgrade
                    if row.debit == account =>
                {
                    burned = burned.saturating_add(row.amount);
                }
                _ => {}
            }
        }
        // A launch return reduces the lot of the SAME pledge (C is never
        // paid twice)
        for row in &rows {
            if row.kind != v0::ProtEntryKind::LaunchReturn || row.debit != account {
                continue;
            }
            if let Some(index) = row
                .reference
                .pledge_id
                .as_deref()
                .and_then(|pledge_id| lot_of_pledge.get(pledge_id))
            {
                lots[*index].amount = lots[*index].amount.saturating_sub(row.amount);
            }
        }
        let balance = tank_balance(&accounts, tank_id)?;
        let plan = plan_prot_settlement(&lots, burned, balance);
        if plan.mismatch {
            log::error!("PROT_SETTLE_MISMATCH tank={tank_id} balance={balance} burned={burned}");
        }

        let mut book = Book::stage(&ledger, &accounts);
        let mut returns = Vec::new();
        for (user_id, amount) in &plan.returns {
            returns.push(book.post_new(
                &ProtPosting {
                    actor: PROT_ACTOR_SETTLEMENT.to_string(),
                    reference: tank_ref(tank_id),
                    ..posting(
                        prot_key_settle(tank_id, user_id),
                        v0::ProtEntryKind::Settlement,
                        account.clone(),
                        prot_user_account(user_id),
                        *amount,
                        now,
                    )
                },
                "settle_prot_tank",
                tank_id,
            )?);
        }
        let writeoff = if plan.writeoff > 0 {
            Some(book.post_new(
                &ProtPosting {
                    actor: PROT_ACTOR_SETTLEMENT.to_string(),
                    reference: tank_ref(tank_id),
                    ..posting(
                        prot_key_writeoff(tank_id),
                        v0::ProtEntryKind::WriteOff,
                        PROT_SYS_WRITEOFF.to_string(),
                        account.clone(),
                        plan.writeoff,
                        now,
                    )
                },
                "settle_prot_tank",
                tank_id,
            )?)
        } else {
            None
        };

        let next = ProtTank {
            stage: v0::ProtTankStage::Deleted,
            ended_at: Some(now),
            version: tank.version + 1,
            updated_at: now,
            ..tank
        };
        let entitlement = entitlement_after(
            &entitlements,
            &next,
            Some(ChannelEntitlementState::Deleted),
            None,
        );

        book.land(&mut ledger, &mut accounts);
        land_entitlement(&mut entitlements, entitlement);
        tanks.insert(next.id.clone(), next.clone());
        Ok(ProtSettlement {
            tank: next,
            returns,
            writeoff,
        })
    }

    async fn terminate_prot_tank(
        &self,
        tank_id: &str,
        admin_id: &str,
        reason: &str,
        now: i64,
    ) -> Result<ProtTermination> {
        // A tank that never launched (audit 8): protect landed -> capture
        // first (no launch-day burn: the Prot is forfeited next); not
        // protected -> the launch is abandoned with full returns, and the tank
        // no longer exists
        let tank = self
            .fetch_prot_tank(tank_id)
            .await?
            .ok_or_else(|| create_error!(NotFound))?;
        if tank.launched_at.is_none()
            && matches!(
                tank.stage,
                v0::ProtTankStage::Launching | v0::ProtTankStage::Settling
            )
        {
            let channel_id = tank_channel(&tank).map(str::to_string);
            let protected = {
                let channels = self.channels.lock().await;
                is_protected(&channels, channel_id.as_deref())
            };
            match (protected, channel_id) {
                (true, Some(channel_id)) => {
                    self.capture_launch_pledges_locked(&channel_id, now, None)
                        .await?;
                }
                _ => {
                    for goal in self.fetch_open_prot_goals_by_tank(tank_id).await? {
                        if goal.state == v0::ProtGoalState::Launching {
                            self.close_prot_goal(&goal.id, v0::ProtGoalState::Cancelled, now)
                                .await?;
                        }
                    }
                    log::info!("AUDIT prot_terminate_unlaunched: actor={admin_id} tank={tank_id}");
                    return Err(create_error!(NotFound));
                }
            }
        }

        let (tank, forfeit, writeoff) = self
            .terminate_prot_tank_locked(tank_id, admin_id, reason, now)
            .await?;

        // Held pledges of the tank's open goals go back (D11), each close its
        // own lock section; a crash here is finished by the clock (7.1 step 7)
        let mut closed_goals = Vec::new();
        for goal in self.fetch_open_prot_goals_by_tank(tank_id).await? {
            closed_goals.push(
                self.close_prot_goal(&goal.id, v0::ProtGoalState::Cancelled, now)
                    .await?,
            );
        }
        Ok(ProtTermination {
            tank,
            forfeit,
            writeoff,
            closed_goals,
        })
    }

    async fn purge_protected_channel_content(&self, channel_id: &str) -> Result<ProtPurgeCounts> {
        let mut messages = self.messages.lock().await;
        let entitlements = self.channel_entitlements.lock().await;
        let mut groups = self.mls_groups.lock().await;
        let mut commits = self.mls_commits.lock().await;
        let mut intents = self.mls_join_intents.lock().await;
        let mut queue = self.e2ee_queue.lock().await;

        // Only behind a Deleted tombstone: a purge never touches a channel
        // that can still carry traffic
        if !entitlements.values().any(|entitlement| {
            entitlement.channel_id == channel_id
                && entitlement.state == ChannelEntitlementState::Deleted
        }) {
            log::error!("PROT_PURGE_REFUSED channel={channel_id} (no Deleted entitlement)");
            return Err(create_error!(InvalidOperation));
        }

        let before = messages.len();
        messages.retain(|_, message| message.channel != channel_id);
        let message_count = before - messages.len();

        // The Text plane only; the entitlement tombstone, the seats, the seat
        // list and `channel.protected` all stay
        let text_group_ids: BTreeSet<String> = groups
            .values()
            .filter(|group| group.channel_id == channel_id && group.kind == MlsGroupKind::Text)
            .map(|group| group.id.clone())
            .collect();
        let before = commits.len();
        commits.retain(|_, commit| !text_group_ids.contains(&commit.group_id));
        let commit_count = before - commits.len();
        let before = intents.len();
        intents.retain(|_, intent| !text_group_ids.contains(&intent.group_id));
        let intent_count = before - intents.len();
        let before = queue.len();
        queue.retain(|_, envelope| {
            !envelope
                .group_id
                .as_ref()
                .is_some_and(|group_id| text_group_ids.contains(group_id))
        });
        let envelope_count = before - queue.len();
        groups.retain(|id, _| !text_group_ids.contains(id));

        Ok(ProtPurgeCounts {
            messages: message_count as u64,
            groups: text_group_ids.len() as u64,
            commits: commit_count as u64,
            join_intents: intent_count as u64,
            envelopes: envelope_count as u64,
        })
    }

    async fn mark_prot_tank_purged(&self, tank_id: &str, now: i64) -> Result<()> {
        let mut tanks = self.prot_tanks.lock().await;
        let tank = tanks
            .get_mut(tank_id)
            .ok_or_else(|| create_error!(NotFound))?;
        if !matches!(
            tank.stage,
            v0::ProtTankStage::Deleted | v0::ProtTankStage::Terminated
        ) {
            return Err(create_error!(InvalidOperation));
        }
        tank.purge_passes = tank.purge_passes.saturating_add(1);
        tank.purged_at = Some(now);
        tank.version += 1;
        tank.updated_at = now;
        Ok(())
    }
}
