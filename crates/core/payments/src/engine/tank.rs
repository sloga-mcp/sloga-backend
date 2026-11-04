//! Prot fuel tanks, goals and pledges (S5b): the rules over the data layer
//! (`revolt_database::AbstractProtTanks`), the hourly clock, the goal sweep
//! and the tank notices
//!
//! Every Prot movement is one driver transaction; this module decides who may
//! ask for it, with what amount, and what happens after it commits. Money
//! rules it keeps:
//! - an amount a caller names is checked here before any driver call
//!   (`min_contribution..=PROT_MAX_AMOUNT`; a driver answers 500 on a
//!   non-positive amount)
//! - Prot bought within the hold window never funds a tank or a pledge: the
//!   driver uses the held figure as the debit floor, and its refusal is
//!   answered as `ProtHeldPurchase`
//! - every credit to a wallet gets the second pass (a deleted account is
//!   forfeited, never handed to anyone else); live wallets are published
//! - the clock is the only place that deletes, and only with deletion on,
//!   the clock burning, the tank shifted for any recorded pause, and a Final
//!   notice recorded `final_notice_days` earlier; a paused clock never
//!   advances a deadline (N1)
//! - nothing here unprotects a channel: a deleted or terminated tank keeps
//!   `channel.protected` and the entitlement tombstone
//!
//! The routes (`routes/prot`) are thin wrappers: they refuse bots, check
//! `[features.boosts.protection] enabled` for writes and pass
//! `ProtTankRules::load()` through. Everything else (visibility, self-serve,
//! owner, eligibility, amounts) is decided here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

use async_trait::async_trait;
use revolt_database::events::client::EventV1;
use revolt_database::iso8601_timestamp::{Duration as TimestampDuration, Timestamp};
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::prot_email::{send_prot_owner_email, ProtEmailKind};
use revolt_database::{
    channel_seats_used, prot_key_contrib, prot_notice_due, prot_tank_account, prot_tank_summary,
    prot_user_account, prot_utc_day, Channel, Database, Member, ProtBurnOutcome,
    ProtContributeInput, ProtContributeOutcome, ProtGoal, ProtLaunchInput, ProtLedgerEntry,
    ProtNoticeKind, ProtPledge, ProtPledgeInput, ProtSettleCause, ProtTank, ProtTankRules,
    ProtTankTarget, ProtTierChangeInput, Server, User, AMQP, PROT_MAX_AMOUNT, PROT_SLOT_TIERS,
};
use revolt_models::v0::{self, PROT_SEAT_NOTICE};
use revolt_permissions::{
    calculate_channel_permissions, calculate_server_permissions, ChannelPermission,
};
use revolt_result::{create_error, Error, ErrorType, Result};
use ulid::Ulid;

use super::prot::{forfeit_if_deleted, publish_balance};

const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;

/// Tanks read per page by the clock's passes
const PROT_TANK_PAGE: i64 = 200;

/// Days one tank is billed per tick at most; a longer outage finishes on the
/// next tick
const PROT_CATCH_UP_DAYS: usize = 400;

/// Goals read per page by the sweep
const PROT_GOAL_PAGE: i64 = 500;

/// Pages one pass reads before it yields to the next tick
const PROT_MAX_PAGES: usize = 50;

/// Rounds of capture-or-abandon for a never-launched Settling tank: each
/// round loses only to a racing write that moved the launch on
const PROT_LAUNCH_ATTEMPTS: usize = 3;

/// Longest client nonce, in bytes (the routes' validator bound)
const PROT_NONCE_MAX: usize = 64;

/// At most one coalesced `ProtTankUpdate` per tank per window (12.1)
pub const PROT_TANK_UPDATE_WINDOW_MS: i64 = 10_000;

/// Coalescer entries kept before old ones are dropped
const PROT_COALESCE_PRUNE_AT: usize = 4_096;

/// Push title of every tank notice (12.3)
pub const PROT_PUSH_TITLE: &str = "Protected channel";
/// Push text of a Warn notice
pub const PROT_PUSH_WARN: &str = "A Protected channel you're in needs Prot to stay active.";
/// Push text of the Grace notice
pub const PROT_PUSH_GRACE: &str = concat!(
    "A Protected channel you're in has run out of Prot. ",
    "New members can't be added until it's topped up."
);
/// Push text of the Freeze notice
pub const PROT_PUSH_FREEZE: &str =
    "A Protected channel you're in is frozen. Messages can't be sent until it's topped up.";
/// Push text of the Deleted notice (expiry only)
pub const PROT_PUSH_DELETED: &str = concat!(
    "A Protected channel you were in was deleted from Sloga's servers ",
    "because it ran out of Prot."
);

/// Every contribution publishes through this, per process (12.1)
static TANK_UPDATES: ProtTankUpdateCoalescer =
    ProtTankUpdateCoalescer::new(PROT_TANK_UPDATE_WINDOW_MS);

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn days_ms(days: u32) -> i64 {
    i64::from(days).saturating_mul(DAY_MS)
}

/// `ms` as a Timestamp (the epoch for a value it cannot hold)
fn timestamp_of(ms: i64) -> Timestamp {
    Timestamp::UNIX_EPOCH
        .checked_add(TimestampDuration::milliseconds(ms))
        .unwrap_or(Timestamp::UNIX_EPOCH)
}

/// The wall clock, for work that outlives the request (a trailing publish)
fn wall_clock_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn is_not_found(err: &Error) -> bool {
    matches!(err.error_type, ErrorType::NotFound)
}

fn invalid(error: &str) -> Error {
    create_error!(FailedValidation {
        error: error.to_string()
    })
}

fn refuse_bot(user: &User) -> Result<()> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }
    Ok(())
}

/// 8.0: goal create/launch/cancel and tier changes need self-serve, for
/// every caller (staff included: S1 refuses a privileged protect)
fn refuse_without_self_serve(rules: &ProtTankRules) -> Result<()> {
    if !rules.self_serve {
        return Err(create_error!(ProtDisabled));
    }
    Ok(())
}

/// 11.3: the server's owner at call time (S2 succession moves it; nothing
/// caches it)
fn require_owner(server: &Server, user: &User) -> Result<()> {
    if server.owner != user.id {
        return Err(create_error!(NotOwner));
    }
    Ok(())
}

fn check_nonce(nonce: &str) -> Result<()> {
    if nonce.is_empty() || nonce.len() > PROT_NONCE_MAX {
        return Err(invalid("nonce must be 1 to 64 bytes"));
    }
    Ok(())
}

/// 8.1 / N-6: a contribution is `min_contribution..=PROT_MAX_AMOUNT`,
/// checked before the driver (which answers 500 on a non-positive amount)
fn check_contribution_amount(amount: i64, rules: &ProtTankRules) -> Result<()> {
    if !(rules.min_contribution.max(1)..=PROT_MAX_AMOUNT).contains(&amount) {
        return Err(invalid("amount is outside the allowed range"));
    }
    Ok(())
}

/// A pledge may be below the minimum when it completes its goal (8.3; the
/// driver decides that against the open amount), never below 1 or above the
/// maximum
fn check_pledge_amount(amount: i64) -> Result<()> {
    if !(1..=PROT_MAX_AMOUNT).contains(&amount) {
        return Err(invalid("amount is outside the allowed range"));
    }
    Ok(())
}

/// The user id of a `user:{id}` wallet account
fn wallet_user(account: &str) -> Option<String> {
    account.strip_prefix("user:").map(str::to_string)
}

/// The channel a tank pays for (None for an S10 server tank)
fn tank_channel(tank: &ProtTank) -> Option<&str> {
    match &tank.target {
        ProtTankTarget::Channel { channel_id } => Some(channel_id.as_str()),
        ProtTankTarget::Server { .. } => None,
    }
}

fn is_deleted_user(user: &User) -> bool {
    user.flags.unwrap_or_default() & v0::UserFlags::Deleted as i32 != 0
}

/// The wallet balance of `user_id` (0 when it has no account)
async fn wallet_balance(db: &Database, user_id: &str) -> Result<i64> {
    Ok(db
        .fetch_prot_account(&prot_user_account(user_id))
        .await?
        .map_or(0, |account| account.balance))
}

/// The tank account's balance (0 when it has none)
async fn tank_balance(db: &Database, tank_id: &str) -> Result<i64> {
    Ok(db
        .fetch_prot_account(&prot_tank_account(tank_id))
        .await?
        .map_or(0, |account| account.balance))
}

/// 11.6: an `InsufficientProt` from a debit whose floor is the held figure
/// is a held purchase when the wallet itself covers the amount
async fn held_refusal(db: &Database, user_id: &str, needed: i64, err: Error) -> Error {
    if !matches!(err.error_type, ErrorType::InsufficientProt { .. }) {
        return err;
    }
    match wallet_balance(db, user_id).await {
        Ok(balance) if balance >= needed => create_error!(ProtHeldPurchase),
        _ => err,
    }
}

// ---------------------------------------------------------------------------
// Visibility and eligibility
// ---------------------------------------------------------------------------

/// The caller's member row, if any (any other read failure is an error)
async fn member_of(db: &Database, server_id: &str, user_id: &str) -> Result<Option<Member>> {
    match db.fetch_member(server_id, user_id).await {
        Ok(member) => Ok(Some(member)),
        Err(err) if is_not_found(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

async fn can_view_channel(
    db: &Database,
    user: &User,
    channel: &Channel,
    server: &Server,
    member: &Member,
) -> bool {
    let mut query = DatabasePermissionQuery::new(db, user)
        .channel(channel)
        .server(server)
        .member(member);
    calculate_channel_permissions(&mut query)
        .await
        .has_channel_permission(ChannelPermission::ViewChannel)
}

async fn can_view_server(db: &Database, user: &User, server: &Server, member: &Member) -> bool {
    let mut query = DatabasePermissionQuery::new(db, user)
        .server(server)
        .member(member);
    calculate_server_permissions(&mut query)
        .await
        .has_channel_permission(ChannelPermission::ViewChannel)
}

/// What the caller may see
struct Viewed {
    server: Server,
    /// The goal's or tank's channel; None for a server-level launch goal
    channel: Option<Channel>,
}

/// A server TextChannel the caller sees, with an explicit member row (staff
/// without one are refused, 11.3). Anything else is `NotFound`, the answer a
/// missing channel gets (11.1).
async fn visible_channel(db: &Database, user: &User, channel_id: &str) -> Result<Viewed> {
    let channel = db.fetch_channel(channel_id).await?;
    let server_id = match &channel {
        Channel::TextChannel { server, .. } => server.clone(),
        _ => return Err(create_error!(NotFound)),
    };
    let server = db.fetch_server(&server_id).await?;
    let Some(member) = member_of(db, &server_id, &user.id).await? else {
        return Err(create_error!(NotFound));
    };
    if !can_view_channel(db, user, &channel, &server, &member).await {
        return Err(create_error!(NotFound));
    }
    Ok(Viewed {
        server,
        channel: Some(channel),
    })
}

/// A server the caller is a member of and sees (server-level ViewChannel)
async fn visible_server(db: &Database, user: &User, server_id: &str) -> Result<Viewed> {
    let server = db.fetch_server(server_id).await?;
    let Some(member) = member_of(db, server_id, &user.id).await? else {
        return Err(create_error!(NotFound));
    };
    if !can_view_server(db, user, &server, &member).await {
        return Err(create_error!(NotFound));
    }
    Ok(Viewed {
        server,
        channel: None,
    })
}

/// A goal is seen through its channel once it has one, else through its
/// server (a Funding launch goal)
async fn visible_goal(db: &Database, user: &User, goal: &ProtGoal) -> Result<Viewed> {
    match &goal.channel_id {
        Some(channel_id) => {
            let viewed = visible_channel(db, user, channel_id).await?;
            if viewed.server.id != goal.server_id {
                return Err(create_error!(NotFound));
            }
            Ok(viewed)
        }
        None => visible_server(db, user, &goal.server_id).await,
    }
}

/// D6 (8.1): not a bot; not suspended, deleted or banned; an explicit member
/// row (a staff permission bypass does not count); not timed out;
/// ViewChannel on `channel`, or at server level without one (a launch goal).
/// Every refusal is `ProtNotEligible`.
pub async fn prot_eligibility(
    db: &Database,
    user: &User,
    server: &Server,
    channel: Option<&Channel>,
) -> Result<()> {
    if user.bot.is_some() {
        return Err(create_error!(ProtNotEligible));
    }
    let barred = v0::UserFlags::SuspendedUntil as i32
        | v0::UserFlags::Deleted as i32
        | v0::UserFlags::Banned as i32;
    if user.flags.unwrap_or_default() & barred != 0 {
        return Err(create_error!(ProtNotEligible));
    }
    let Some(member) = member_of(db, &server.id, &user.id).await? else {
        return Err(create_error!(ProtNotEligible));
    };
    if member.in_timeout() {
        return Err(create_error!(ProtNotEligible));
    }
    let sees = match channel {
        Some(channel) => can_view_channel(db, user, channel, server, &member).await,
        None => can_view_server(db, user, server, &member).await,
    };
    if !sees {
        return Err(create_error!(ProtNotEligible));
    }
    Ok(())
}

/// Eligibility as a flag for the views; a read failure is still an error
async fn is_eligible(
    db: &Database,
    user: &User,
    server: &Server,
    channel: Option<&Channel>,
) -> Result<bool> {
    match prot_eligibility(db, user, server, channel).await {
        Ok(()) => Ok(true),
        Err(err) if matches!(err.error_type, ErrorType::ProtNotEligible) => Ok(false),
        Err(err) => Err(err),
    }
}

// ---------------------------------------------------------------------------
// Wallets and events
// ---------------------------------------------------------------------------

/// Every user whose wallet one of `entries` credited
fn credited_users(entries: &[ProtLedgerEntry]) -> BTreeSet<String> {
    entries
        .iter()
        .filter_map(|entry| wallet_user(&entry.credit))
        .collect()
}

/// After credits to these wallets committed: the second pass (a deleted
/// account is forfeited), then the balance to its owner. A failed pass is
/// logged; the account deletion's own forfeit runs after its cascade.
async fn settle_users(db: &Database, users: &BTreeSet<String>, now_ms: i64) {
    for user_id in users {
        if let Err(err) = forfeit_if_deleted(db, user_id, now_ms).await {
            log::error!("PROT_FORFEIT_DEFERRED user={user_id}: {err:?}");
        }
        publish_balance(db, user_id).await;
    }
}

async fn settle_credited(db: &Database, entries: &[ProtLedgerEntry], now_ms: i64) {
    settle_users(db, &credited_users(entries), now_ms).await;
}

/// The pledgers whose pledges of `goal_id` went back (a close the driver
/// reported without its rows: an upgrade apply that cancelled)
async fn returned_pledgers(db: &Database, goal_id: &str) -> Result<BTreeSet<String>> {
    Ok(db
        .fetch_prot_pledges_by_goal(goal_id)
        .await?
        .into_iter()
        .filter(|pledge| pledge.state == v0::ProtPledgeState::Returned)
        .map(|pledge| pledge.user_id)
        .collect())
}

/// `ProtTankUpdate` with the tank's summary on its channel's topic (its
/// viewers only, 12.1). A failed read publishes nothing: clients refetch on
/// open and every 5 minutes.
async fn publish_tank(db: &Database, tank: &ProtTank, rules: &ProtTankRules, now_ms: i64) {
    let Some(channel_id) = tank_channel(tank) else {
        return;
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
        channel: channel_id.to_string(),
        tank: Some(prot_tank_summary(tank, account.as_ref(), rules, now_ms)),
    }
    .p(channel_id.to_string())
    .await;
}

/// The channel's tank row is gone (an abandoned launch)
async fn publish_tank_removed(channel_id: &str) {
    EventV1::ProtTankUpdate {
        channel: channel_id.to_string(),
        tank: None,
    }
    .p(channel_id.to_string())
    .await;
}

/// What the coalescer decided for one contribution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtTankUpdatePlan {
    /// Publish now; a window opens
    Now,
    /// Inside a window: one trailing publish at `at_ms` (schedule it)
    Trailing { at_ms: i64 },
    /// A trailing publish is already scheduled and will read the tank then
    Absorbed,
}

#[derive(Debug, Clone, Copy)]
struct CoalesceSlot {
    published_at: i64,
    trailing_at: Option<i64>,
}

/// At most one `ProtTankUpdate` per tank per window for contributions
/// (12.1); a contribution inside the window gets ONE trailing publish at the
/// window's end, which re-reads the tank. Pure and clock-injected: the
/// caller passes the time and schedules what it is told to.
pub struct ProtTankUpdateCoalescer {
    window_ms: i64,
    slots: Mutex<BTreeMap<String, CoalesceSlot>>,
}

impl ProtTankUpdateCoalescer {
    pub const fn new(window_ms: i64) -> Self {
        ProtTankUpdateCoalescer {
            window_ms,
            slots: Mutex::new(BTreeMap::new()),
        }
    }

    /// A contribution to `tank_id` at `now_ms`
    pub fn admit(&self, tank_id: &str, now_ms: i64) -> ProtTankUpdatePlan {
        let mut slots = self.slots.lock().unwrap_or_else(|err| err.into_inner());
        if slots.len() > PROT_COALESCE_PRUNE_AT {
            let window_ms = self.window_ms;
            slots.retain(|_, slot| {
                slot.trailing_at.is_some() || now_ms.saturating_sub(slot.published_at) < window_ms
            });
        }
        match slots.get_mut(tank_id) {
            Some(slot) if slot.trailing_at.is_some() => ProtTankUpdatePlan::Absorbed,
            Some(slot) if now_ms.saturating_sub(slot.published_at) < self.window_ms => {
                let at_ms = slot.published_at.saturating_add(self.window_ms);
                slot.trailing_at = Some(at_ms);
                ProtTankUpdatePlan::Trailing { at_ms }
            }
            _ => {
                slots.insert(
                    tank_id.to_string(),
                    CoalesceSlot {
                        published_at: now_ms,
                        trailing_at: None,
                    },
                );
                ProtTankUpdatePlan::Now
            }
        }
    }

    /// A publish that did not go through `admit` (a stage change publishes
    /// at once): it opens a window, a scheduled trailing publish stays
    pub fn note_published(&self, tank_id: &str, now_ms: i64) {
        let mut slots = self.slots.lock().unwrap_or_else(|err| err.into_inner());
        let slot = slots.entry(tank_id.to_string()).or_insert(CoalesceSlot {
            published_at: now_ms,
            trailing_at: None,
        });
        slot.published_at = now_ms;
    }

    /// The trailing publish of `tank_id` goes out at `now_ms`
    pub fn fire(&self, tank_id: &str, now_ms: i64) {
        let mut slots = self.slots.lock().unwrap_or_else(|err| err.into_inner());
        slots.insert(
            tank_id.to_string(),
            CoalesceSlot {
                published_at: now_ms,
                trailing_at: None,
            },
        );
    }
}

/// A contribution's tank event, coalesced (12.1)
async fn publish_contribution(db: &Database, tank: &ProtTank, rules: &ProtTankRules, now_ms: i64) {
    match TANK_UPDATES.admit(&tank.id, now_ms) {
        ProtTankUpdatePlan::Now => publish_tank(db, tank, rules, now_ms).await,
        ProtTankUpdatePlan::Absorbed => {}
        ProtTankUpdatePlan::Trailing { at_ms } => {
            let db = db.clone();
            let rules = rules.clone();
            let tank_id = tank.id.clone();
            let wait = u64::try_from(at_ms.saturating_sub(now_ms)).unwrap_or(0);
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
                let now = wall_clock_ms();
                TANK_UPDATES.fire(&tank_id, now);
                match db.fetch_prot_tank(&tank_id).await {
                    Ok(Some(tank)) => publish_tank(&db, &tank, &rules, now).await,
                    Ok(None) => {}
                    Err(err) => {
                        log::warn!("prot: trailing publish of tank {tank_id} failed: {err:?}")
                    }
                }
            });
        }
    }
}

/// A stage change (or launch, capture, tier change) publishes at once
async fn publish_tank_now(db: &Database, tank: &ProtTank, rules: &ProtTankRules, now_ms: i64) {
    TANK_UPDATES.note_published(&tank.id, now_ms);
    publish_tank(db, tank, rules, now_ms).await;
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/// One contributor's net Prot and the first row (or pledge) that counted it
struct Contribution {
    user_id: String,
    amount: i64,
    first: String,
}

/// Net per user, > 0 only, by amount descending then first row id (11.2)
fn rank_contributions(totals: BTreeMap<String, (i64, String)>) -> Vec<Contribution> {
    let mut list: Vec<Contribution> = totals
        .into_iter()
        .filter(|(_, (amount, _))| *amount > 0)
        .map(|(user_id, (amount, first))| Contribution {
            user_id,
            amount,
            first,
        })
        .collect();
    list.sort_by(|a, b| b.amount.cmp(&a.amount).then_with(|| a.first.cmp(&b.first)));
    list
}

/// A tank's contributors: contributions + captures - launch returns
async fn tank_contributions(db: &Database, tank: &ProtTank) -> Result<Vec<Contribution>> {
    let rows = db.fetch_prot_entries_by_tank(&tank.id).await?;
    let account = prot_tank_account(&tank.id);

    // A capture row names the hold, not the user: the pledge says whose
    let goal_ids: BTreeSet<String> = rows
        .iter()
        .filter(|row| row.kind == v0::ProtEntryKind::PledgeCapture)
        .filter_map(|row| row.reference.goal_id.clone())
        .collect();
    let mut pledge_users: HashMap<String, String> = HashMap::new();
    for goal_id in goal_ids {
        for pledge in db.fetch_prot_pledges_by_goal(&goal_id).await? {
            pledge_users.insert(pledge.id, pledge.user_id);
        }
    }

    let mut totals: BTreeMap<String, (i64, String)> = BTreeMap::new();
    for row in &rows {
        let (user_id, delta) = match row.kind {
            v0::ProtEntryKind::Contribution if row.credit == account => {
                (wallet_user(&row.debit), row.amount)
            }
            v0::ProtEntryKind::PledgeCapture if row.credit == account => (
                row.reference
                    .pledge_id
                    .as_ref()
                    .and_then(|pledge_id| pledge_users.get(pledge_id))
                    .cloned(),
                row.amount,
            ),
            v0::ProtEntryKind::LaunchReturn if row.debit == account => {
                (wallet_user(&row.credit), row.amount.saturating_neg())
            }
            _ => continue,
        };
        let Some(user_id) = user_id else {
            continue;
        };
        let total = totals.entry(user_id).or_insert((0, row.id.clone()));
        total.0 = total.0.saturating_add(delta);
    }
    Ok(rank_contributions(totals))
}

/// A goal's contributors: what each pledger still has in it (Held:
/// remaining; Captured: captured - launch returned)
fn goal_contributions(pledges: &[ProtPledge]) -> Vec<Contribution> {
    let mut totals: BTreeMap<String, (i64, String)> = BTreeMap::new();
    for pledge in pledges {
        let net = match pledge.state {
            v0::ProtPledgeState::Held => pledge.remaining,
            v0::ProtPledgeState::Captured => pledge.captured.saturating_sub(pledge.launch_returned),
            _ => 0,
        };
        let total = totals
            .entry(pledge.user_id.clone())
            .or_insert((0, pledge.id.clone()));
        total.0 = total.0.saturating_add(net);
    }
    rank_contributions(totals)
}

/// Hidden contributors (prefs of the server) and deleted ones never show an
/// id, not even to the owner (BR10, NIT 25); `you` marks the caller's line
async fn contributor_views(
    db: &Database,
    server_id: &str,
    viewer_id: &str,
    list: Vec<Contribution>,
) -> Result<Vec<v0::ProtContributorView>> {
    if list.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<String> = list.iter().map(|line| line.user_id.clone()).collect();
    let prefix = format!("{server_id}:");
    let hidden: BTreeSet<String> = db
        .fetch_prot_contributor_prefs(server_id, &ids)
        .await?
        .into_iter()
        .filter(|pref| pref.hidden)
        .filter_map(|pref| pref.id.strip_prefix(&prefix).map(str::to_string))
        .collect();
    let live: BTreeSet<String> = db
        .fetch_users(&ids)
        .await?
        .into_iter()
        .filter(|user| !is_deleted_user(user))
        .map(|user| user.id)
        .collect();

    Ok(list
        .into_iter()
        .map(|line| {
            let deleted = !live.contains(&line.user_id);
            let hidden = hidden.contains(&line.user_id);
            v0::ProtContributorView {
                user_id: (!deleted && !hidden).then(|| line.user_id.clone()),
                amount: line.amount,
                hidden,
                deleted,
                you: line.user_id == viewer_id,
            }
        })
        .collect())
}

fn pledge_view(pledge: &ProtPledge) -> v0::ProtPledgeView {
    v0::ProtPledgeView {
        id: pledge.id.clone(),
        goal_id: pledge.goal_id.clone(),
        amount: pledge.amount,
        remaining: pledge.remaining,
        state: pledge.state,
        created_at: pledge.created_at,
    }
}

async fn goal_view(
    db: &Database,
    viewer_id: &str,
    goal: &ProtGoal,
    rules: &ProtTankRules,
) -> Result<v0::ProtGoalView> {
    let pledges = db.fetch_prot_pledges_by_goal(&goal.id).await?;
    let contributors =
        contributor_views(db, &goal.server_id, viewer_id, goal_contributions(&pledges)).await?;
    let your_pledges = pledges
        .iter()
        .filter(|pledge| pledge.user_id == viewer_id)
        .map(pledge_view)
        .collect();

    Ok(v0::ProtGoalView {
        id: goal.id.clone(),
        kind: goal.kind,
        server_id: goal.server_id.clone(),
        channel_id: goal.channel_id.clone(),
        tank_id: goal.tank_id.clone(),
        slots: goal.slots,
        days: goal.days,
        daily_cost: goal.daily_cost,
        target_prot: goal.target_prot,
        pledged_total: goal.pledged_total,
        state: goal.state,
        deadline_at: goal.deadline_at,
        withdraw_until: goal
            .deadline_at
            .saturating_sub(i64::from(rules.withdraw_cutoff_hours).saturating_mul(HOUR_MS)),
        funded_at: goal.funded_at,
        launch_deadline_at: goal.launch_deadline_at,
        launched_at: goal.launched_at,
        contributors,
        your_pledges,
        notice: PROT_SEAT_NOTICE.to_string(),
    })
}

async fn summary_of(
    db: &Database,
    tank: &ProtTank,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<v0::ProtTankSummary> {
    let account = db.fetch_prot_account(&prot_tank_account(&tank.id)).await?;
    Ok(prot_tank_summary(tank, account.as_ref(), rules, now_ms))
}

/// The tank of a channel the caller sees (NotFound when it has none: an
/// AdminGrant channel and an abandoned launch look like a non-viewer's
/// answer, audit 16)
async fn tank_of_channel(db: &Database, channel_id: &str) -> Result<ProtTank> {
    db.fetch_prot_tank_by_channel(channel_id)
        .await?
        .ok_or_else(|| create_error!(NotFound))
}

// ---------------------------------------------------------------------------
// Route bodies (11.7)
// ---------------------------------------------------------------------------

/// `GET /prot/channels/<channel_id>/tank`
pub async fn fetch_prot_tank(
    db: &Database,
    user: &User,
    channel_id: &str,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<v0::ProtTankView> {
    refuse_bot(user)?;
    let viewed = visible_channel(db, user, channel_id).await?;
    let tank = tank_of_channel(db, channel_id).await?;

    let summary = summary_of(db, &tank, rules, now_ms).await?;
    let contributions = tank_contributions(db, &tank).await?;
    let you_contributed = contributions
        .iter()
        .find(|line| line.user_id == user.id)
        .map_or(0, |line| line.amount);
    let contributors = contributor_views(db, &tank.server_id, &user.id, contributions).await?;
    let mut goals = Vec::new();
    for goal in db.fetch_open_prot_goals_by_tank(&tank.id).await? {
        goals.push(goal_view(db, &user.id, &goal, rules).await?);
    }
    let takes_top_ups = matches!(
        tank.stage,
        v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen
    );
    let can_contribute =
        takes_top_ups && is_eligible(db, user, &viewed.server, viewed.channel.as_ref()).await?;
    let seats = db.fetch_channel_seats(channel_id).await?;

    Ok(v0::ProtTankView {
        tank: summary,
        contributors,
        goals,
        you_contributed,
        can_contribute,
        is_owner: viewed.server.owner == user.id,
        seats_used: u32::try_from(channel_seats_used(&seats, timestamp_of(now_ms)))
            .unwrap_or(u32::MAX),
        notice: PROT_SEAT_NOTICE.to_string(),
    })
}

/// `POST /prot/channels/<channel_id>/contribute` (8.8): D6, the amount, the
/// replay read, the catch-up of a tank the clock has not billed yet today,
/// then ONE driver transaction (held figure as the floor, reactivation)
pub async fn contribute_prot(
    db: &Database,
    user: &User,
    channel_id: &str,
    data: v0::DataProtContribute,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<v0::ProtContributionResponse> {
    refuse_bot(user)?;
    let viewed = visible_channel(db, user, channel_id).await?;
    let tank = tank_of_channel(db, channel_id).await?;
    let tank_id = tank.id.clone();
    prot_eligibility(db, user, &viewed.server, viewed.channel.as_ref()).await?;
    check_contribution_amount(data.amount, rules)?;
    check_nonce(&data.nonce)?;

    // A replay is decided by the driver from the stored row, never re-planned
    let key = prot_key_contrib(&user.id, &tank.id, &data.nonce);
    if db.fetch_prot_entry_by_key(&key).await?.is_none() {
        // Reactivation must not decide on stale state (audit 10). A tank
        // still waiting for its pause shift is not caught up: its missed
        // days are paused days (7.4, N4)
        let paused = db
            .fetch_prot_runtime()
            .await?
            .and_then(|runtime| runtime.burn_paused_at);
        let today = prot_utc_day(now_ms);
        let behind = tank
            .next_burn_day
            .as_deref()
            .is_some_and(|day| day < today.as_str());
        if behind {
            burn_due_days(db, tank, paused, rules, now_ms).await?;
        }
    }

    let outcome = match db
        .contribute_prot(&ProtContributeInput {
            user_id: user.id.clone(),
            tank_id,
            amount: data.amount,
            nonce: data.nonce.clone(),
            rules: rules.clone(),
            now: now_ms,
        })
        .await
    {
        Ok(outcome) => outcome,
        Err(err) => return Err(held_refusal(db, &user.id, data.amount, err).await),
    };

    let (entry, tank, already_applied) = match outcome {
        ProtContributeOutcome::Applied {
            entry,
            tank,
            stage_changed,
        } => {
            publish_balance(db, &user.id).await;
            if stage_changed {
                publish_tank_now(db, &tank, rules, now_ms).await;
            } else {
                publish_contribution(db, &tank, rules, now_ms).await;
            }
            (entry, tank, false)
        }
        ProtContributeOutcome::AlreadyApplied { entry, tank } => (entry, tank, true),
    };

    Ok(v0::ProtContributionResponse {
        entry_id: entry.id,
        tank: summary_of(db, &tank, rules, now_ms).await?,
        balance: wallet_balance(db, &user.id).await?,
        already_applied,
        notice: PROT_SEAT_NOTICE.to_string(),
    })
}

/// `PUT /prot/channels/<channel_id>/tier` (8.9; owner, self-serve)
pub async fn change_prot_tier(
    db: &Database,
    user: &User,
    channel_id: &str,
    data: v0::DataProtTier,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<v0::ProtTankSummary> {
    refuse_bot(user)?;
    let viewed = visible_channel(db, user, channel_id).await?;
    let tank = tank_of_channel(db, channel_id).await?;
    refuse_without_self_serve(rules)?;
    require_owner(&viewed.server, user)?;
    check_nonce(&data.nonce)?;
    if !PROT_SLOT_TIERS.contains(&data.slots) {
        return Err(invalid("slots must be 10, 25, 50 or 100"));
    }
    // Today is billed at the old price first: the upgrade charges only the
    // difference for the hours left
    catch_up_before_pricing(db, &tank.id, rules, now_ms).await?;

    let changed = db
        .change_prot_tier(&ProtTierChangeInput {
            tank_id: tank.id.clone(),
            slots: data.slots,
            // Goal applies use "goal-{goal_id}" (NIT 24): never the same key
            change_id: format!("owner-{}", data.nonce),
            rules: rules.clone(),
            now: now_ms,
        })
        .await?;
    publish_tank_now(db, &changed, rules, now_ms).await;
    summary_of(db, &changed, rules, now_ms).await
}

/// `POST /prot/channels/<channel_id>/goals` (8.7; owner, self-serve)
pub async fn create_prot_upgrade_goal(
    db: &Database,
    user: &User,
    channel_id: &str,
    data: v0::DataProtUpgradeGoal,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<v0::ProtGoalView> {
    refuse_bot(user)?;
    let viewed = visible_channel(db, user, channel_id).await?;
    let tank = tank_of_channel(db, channel_id).await?;
    refuse_without_self_serve(rules)?;
    require_owner(&viewed.server, user)?;
    check_nonce(&data.nonce)?;
    let Some(new_cost) = rules.daily_cost(data.slots) else {
        return Err(invalid("slots must be 10, 25, 50 or 100"));
    };
    if tank.stage != v0::ProtTankStage::Active
        || tank.pending_slot_tier.is_some()
        || data.slots <= tank.slot_tier
        || tank.daily_cost <= 0
    {
        return Err(create_error!(InvalidOperation));
    }
    let balance = tank_balance(db, &tank.id).await?;
    if balance.div_euclid(tank.daily_cost) < 1 {
        return Err(create_error!(InvalidOperation));
    }
    let target_prot = revolt_database::prot_upgrade_goal_price(tank.daily_cost, new_cost, balance);
    if target_prot <= 0 {
        return Err(create_error!(InvalidOperation));
    }

    let goal = db
        .create_prot_goal(&ProtGoal {
            id: Ulid::new().to_string(),
            kind: v0::ProtGoalKind::Upgrade,
            server_id: tank.server_id.clone(),
            channel_id: Some(channel_id.to_string()),
            tank_id: Some(tank.id.clone()),
            created_by: user.id.clone(),
            create_nonce: data.nonce.clone(),
            slots: data.slots,
            days: None,
            daily_cost: new_cost,
            base_daily_cost: Some(tank.daily_cost),
            target_prot,
            pledged_total: 0,
            state: v0::ProtGoalState::Funding,
            deadline_at: now_ms.saturating_add(days_ms(rules.launch_goal_deadline_days)),
            funded_at: None,
            launch_deadline_at: None,
            launched_at: None,
            closed_at: None,
            refund7_done: false,
            open_key: Some(format!("upgrade:{}", tank.id)),
            version: 0,
            created_at: now_ms,
            updated_at: now_ms,
        })
        .await?;
    goal_view(db, &user.id, &goal, rules).await
}

/// `GET /prot/servers/<server_id>/goals`: the server's open launch goals
pub async fn fetch_prot_server_goals(
    db: &Database,
    user: &User,
    server_id: &str,
    rules: &ProtTankRules,
    _now_ms: i64,
) -> Result<Vec<v0::ProtGoalView>> {
    refuse_bot(user)?;
    visible_server(db, user, server_id).await?;
    let mut views = Vec::new();
    for goal in db.fetch_open_prot_goals_by_server(server_id).await? {
        if goal.kind == v0::ProtGoalKind::Launch {
            views.push(goal_view(db, &user.id, &goal, rules).await?);
        }
    }
    Ok(views)
}

/// `POST /prot/servers/<server_id>/goals` (8.2; owner, self-serve)
pub async fn create_prot_launch_goal(
    db: &Database,
    user: &User,
    server_id: &str,
    data: v0::DataProtLaunchGoal,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<v0::ProtGoalView> {
    refuse_bot(user)?;
    let viewed = visible_server(db, user, server_id).await?;
    refuse_without_self_serve(rules)?;
    require_owner(&viewed.server, user)?;
    check_nonce(&data.nonce)?;
    let Some(daily_cost) = rules.daily_cost(data.slots) else {
        return Err(invalid("slots must be 10, 25, 50 or 100"));
    };
    if data.days < rules.min_launch_goal_days || data.days > rules.max_launch_goal_days {
        return Err(invalid("days is outside the allowed range"));
    }

    let goal = db
        .create_prot_goal(&ProtGoal {
            id: Ulid::new().to_string(),
            kind: v0::ProtGoalKind::Launch,
            server_id: server_id.to_string(),
            channel_id: None,
            tank_id: None,
            created_by: user.id.clone(),
            create_nonce: data.nonce.clone(),
            slots: data.slots,
            days: Some(data.days),
            daily_cost,
            base_daily_cost: None,
            target_prot: i64::from(data.days).saturating_mul(daily_cost),
            pledged_total: 0,
            state: v0::ProtGoalState::Funding,
            deadline_at: now_ms.saturating_add(days_ms(rules.launch_goal_deadline_days)),
            funded_at: None,
            launch_deadline_at: None,
            launched_at: None,
            closed_at: None,
            refund7_done: false,
            // BR14: one open launch goal per server
            open_key: Some(format!("launch:{server_id}")),
            version: 0,
            created_at: now_ms,
            updated_at: now_ms,
        })
        .await?;
    goal_view(db, &user.id, &goal, rules).await
}

/// `PUT /prot/servers/<server_id>/contributor` (BR10: per server)
pub async fn set_prot_contributor_prefs(
    db: &Database,
    user: &User,
    server_id: &str,
    data: v0::DataProtContributorPrefs,
    now_ms: i64,
) -> Result<()> {
    refuse_bot(user)?;
    visible_server(db, user, server_id).await?;
    db.set_prot_contributor_pref(server_id, &user.id, data.hidden, now_ms)
        .await
}

/// `GET /prot/goals/<goal_id>`
pub async fn fetch_prot_goal(
    db: &Database,
    user: &User,
    goal_id: &str,
    rules: &ProtTankRules,
    _now_ms: i64,
) -> Result<v0::ProtGoalView> {
    refuse_bot(user)?;
    let goal = db
        .fetch_prot_goal(goal_id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    visible_goal(db, user, &goal).await?;
    goal_view(db, &user.id, &goal, rules).await
}

/// `POST /prot/goals/<goal_id>/pledges` (8.3). A pledge that funds an
/// Upgrade goal applies it right away (8.7; the sweep is the backstop).
pub async fn pledge_prot(
    db: &Database,
    user: &User,
    goal_id: &str,
    data: v0::DataProtContribute,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<v0::ProtPledgeResponse> {
    refuse_bot(user)?;
    let goal = db
        .fetch_prot_goal(goal_id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    let viewed = visible_goal(db, user, &goal).await?;
    prot_eligibility(db, user, &viewed.server, viewed.channel.as_ref()).await?;
    check_pledge_amount(data.amount)?;
    check_nonce(&data.nonce)?;

    let outcome = match db
        .pledge_prot(&ProtPledgeInput {
            user_id: user.id.clone(),
            goal_id: goal_id.to_string(),
            amount: data.amount,
            nonce: data.nonce.clone(),
            rules: rules.clone(),
            now: now_ms,
        })
        .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            let open = goal.target_prot.saturating_sub(goal.pledged_total).max(0);
            return Err(held_refusal(db, &user.id, data.amount.min(open), err).await);
        }
    };

    if !outcome.already_applied {
        publish_balance(db, &user.id).await;
    }
    if outcome.funded_now && outcome.goal.kind == v0::ProtGoalKind::Upgrade {
        if let Err(err) = apply_upgrade(db, &outcome.goal.id, rules, now_ms).await {
            log::warn!("PROT_APPLY_DEFERRED goal={}: {err:?}", outcome.goal.id);
        }
    }

    let goal = db.fetch_prot_goal(goal_id).await?.unwrap_or(outcome.goal);
    let pledge = db
        .fetch_prot_pledge(&outcome.pledge.id)
        .await?
        .unwrap_or(outcome.pledge);
    Ok(v0::ProtPledgeResponse {
        pledge: pledge_view(&pledge),
        goal: goal_view(db, &user.id, &goal, rules).await?,
        balance: wallet_balance(db, &user.id).await?,
        already_applied: outcome.already_applied,
        notice: PROT_SEAT_NOTICE.to_string(),
    })
}

/// `DELETE /prot/goals/<goal_id>/pledges/<pledge_id>` (8.4, D10)
pub async fn withdraw_prot_pledge(
    db: &Database,
    user: &User,
    goal_id: &str,
    pledge_id: &str,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<v0::ProtPledgeView> {
    refuse_bot(user)?;
    let goal = db
        .fetch_prot_goal(goal_id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    visible_goal(db, user, &goal).await?;
    // Another goal's pledge looks absent (the driver checks the pledger)
    let pledge = db
        .fetch_prot_pledge(pledge_id)
        .await?
        .filter(|pledge| pledge.goal_id == goal_id && pledge.user_id == user.id)
        .ok_or_else(|| create_error!(NotFound))?;

    let withdrawn = db
        .withdraw_prot_pledge(
            &pledge.id,
            &user.id,
            now_ms,
            i64::from(rules.withdraw_cutoff_hours).saturating_mul(HOUR_MS),
        )
        .await?;
    settle_users(db, &BTreeSet::from([user.id.clone()]), now_ms).await;
    Ok(pledge_view(&withdrawn))
}

/// `POST /prot/goals/<goal_id>/cancel` (8.5; owner, self-serve). A Launching
/// goal whose channel is already protected is refused (`InvalidOperation`):
/// only its capture may end it.
pub async fn cancel_prot_goal(
    db: &Database,
    user: &User,
    goal_id: &str,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<v0::ProtGoalView> {
    refuse_bot(user)?;
    let goal = db
        .fetch_prot_goal(goal_id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    let viewed = visible_goal(db, user, &goal).await?;
    refuse_without_self_serve(rules)?;
    require_owner(&viewed.server, user)?;

    let outcome = db
        .close_prot_goal(goal_id, v0::ProtGoalState::Cancelled, now_ms)
        .await?;
    settle_credited(db, &outcome.returned, now_ms).await;
    if let Some(channel_id) = outcome.removed_tank.as_ref().and_then(tank_channel) {
        publish_tank_removed(channel_id).await;
    }
    goal_view(db, &user.id, &outcome.goal, rules).await
}

/// `POST /prot/goals/<goal_id>/launch` (8.6; owner, self-serve): the tank is
/// created Launching; protect (S1) lands the channel and the capture follows
/// (`on_protect_landed`, the sweep)
pub async fn launch_prot_goal(
    db: &Database,
    user: &User,
    goal_id: &str,
    data: v0::DataProtGoalLaunch,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<v0::ProtGoalView> {
    refuse_bot(user)?;
    let goal = db
        .fetch_prot_goal(goal_id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    let viewed = visible_goal(db, user, &goal).await?;
    refuse_without_self_serve(rules)?;
    require_owner(&viewed.server, user)?;
    if goal.kind != v0::ProtGoalKind::Launch {
        return Err(create_error!(InvalidOperation));
    }
    if goal.state != v0::ProtGoalState::Funded
        || goal.launch_deadline_at.is_none_or(|at| now_ms > at)
    {
        return Err(create_error!(ProtGoalClosed));
    }
    // Another server's channel looks absent (IDOR); the driver repeats every
    // check (protectable, no message, no entitlement, no tank) in its
    // transaction
    let channel = match db.fetch_channel(&data.channel_id).await {
        Ok(channel) => channel,
        Err(err) if is_not_found(&err) => return Err(create_error!(NotFound)),
        Err(err) => return Err(err),
    };
    match &channel {
        Channel::TextChannel { server, .. } if *server == goal.server_id => {}
        _ => return Err(create_error!(NotFound)),
    }

    let (goal, tank) = db
        .launch_prot_goal(&ProtLaunchInput {
            goal_id: goal_id.to_string(),
            channel_id: data.channel_id.clone(),
            owner_id: user.id.clone(),
            rules: rules.clone(),
            now: now_ms,
        })
        .await?;
    publish_tank_now(db, &tank, rules, now_ms).await;
    goal_view(db, &user.id, &goal, rules).await
}

/// 6.7: called by the protect route after every successful protect (also
/// an unchanged one). Captures a Launching tank's pledges; never fails the
/// route (the goal sweep is the backstop).
pub async fn on_protect_landed(db: &Database, channel_id: &str) {
    let rules = match ProtTankRules::load().await {
        Ok(rules) => rules,
        Err(err) => {
            log::warn!("PROT_CAPTURE_DEFERRED channel={channel_id}: {err:?}");
            return;
        }
    };
    if let Err(err) = land_protect(db, channel_id, &rules, wall_clock_ms()).await {
        log::warn!("PROT_CAPTURE_DEFERRED channel={channel_id}: {err:?}");
    }
}

/// The capture behind `on_protect_landed` and the sweep's backstop
async fn land_protect(
    db: &Database,
    channel_id: &str,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<Option<ProtTank>> {
    let captured = db.capture_launch_pledges(channel_id, now_ms, rules).await?;
    if let Some(tank) = &captured {
        publish_tank_now(db, tank, rules, now_ms).await;
    }
    Ok(captured)
}

/// The pledgers still in the hold of the tank's open goals (a never-launched
/// tank's abandon returns to them without reporting its rows)
async fn held_pledgers_of_tank(db: &Database, tank_id: &str) -> Result<BTreeSet<String>> {
    let mut users = BTreeSet::new();
    for goal in db.fetch_open_prot_goals_by_tank(tank_id).await? {
        for pledge in db.fetch_prot_pledges_by_goal(&goal.id).await? {
            if pledge.state == v0::ProtPledgeState::Held {
                users.insert(pledge.user_id);
            }
        }
    }
    Ok(users)
}

/// Abuse termination (9.5, admin route 11.4; the route checks privilege,
/// the ticket and the reason). The positive balance is forfeited, a negative
/// one written off, held pledges of open goals go back (D11), then purge
/// pass 1. A crash after the driver's first transaction is finished by the
/// clock (7.1 step 7). A never-launched, unprotected tank is abandoned with
/// full returns and answered `NotFound`. `reason` is the audit reason the
/// route validated (an owned or borrowed string).
pub async fn terminate_prot_tank(
    db: &Database,
    admin_id: &str,
    tank_id: &str,
    reason: impl AsRef<str>,
    now_ms: i64,
) -> Result<v0::ProtTankSummary> {
    let before = db
        .fetch_prot_tank(tank_id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    let pledgers = held_pledgers_of_tank(db, tank_id).await?;

    let termination = match db
        .terminate_prot_tank(tank_id, admin_id, reason.as_ref(), now_ms)
        .await
    {
        Ok(termination) => termination,
        Err(err) => {
            if is_not_found(&err) {
                settle_users(db, &pledgers, now_ms).await;
                if let Some(channel_id) = tank_channel(&before) {
                    if matches!(db.fetch_prot_tank(tank_id).await, Ok(None)) {
                        publish_tank_removed(channel_id).await;
                    }
                }
            }
            return Err(err);
        }
    };

    let mut credited = BTreeSet::new();
    for closed in &termination.closed_goals {
        credited.extend(credited_users(&closed.returned));
    }
    settle_users(db, &credited, now_ms).await;

    let mut tank = termination.tank;
    if tank.purge_passes == 0 {
        match purge_tank_content(db, &tank, now_ms).await {
            Ok(()) => {
                if let Some(purged) = db.fetch_prot_tank(tank_id).await? {
                    tank = purged;
                }
            }
            // The clock's step 7 purges it
            Err(err) => log::error!("PROT_PURGE_DEFERRED tank={tank_id}: {err:?}"),
        }
    }

    // The summary of a Terminated tank carries no date the rules decide; an
    // invalid config must not hide a termination that committed
    let rules = match ProtTankRules::load().await {
        Ok(rules) => rules,
        Err(_) => ProtTankRules::from_config(&revolt_config::ProtectionFeatures::default())?,
    };
    publish_tank_now(db, &tank, &rules, now_ms).await;
    summary_of(db, &tank, &rules, now_ms).await
}

// ---------------------------------------------------------------------------
// Notices (12)
// ---------------------------------------------------------------------------

/// Where tank notices go: the generic push path and the owner's email.
/// `AMQP` is the production one; tests record.
#[async_trait]
pub trait ProtNotifier: Sync + Send {
    /// One push on the generic path (no online suppression, 12.3)
    async fn push(&self, user: &User, title: &str, body: &str);

    /// The owner's email (12.4) for a Grace, Freeze, Final or Deleted notice.
    /// Must not wait for the send: the notice row is already recorded, and
    /// the clock never waits on SMTP (the production one spawns it).
    async fn email_owner(
        &self,
        db: &Database,
        owner_id: &str,
        kind: ProtNoticeKind,
        date_ms: Option<i64>,
    );
}

#[async_trait]
impl ProtNotifier for AMQP {
    async fn push(&self, user: &User, title: &str, body: &str) {
        if let Err(err) = self
            .generic_message(user, title.to_string(), body.to_string(), None)
            .await
        {
            log::warn!("PROT_PUSH_FAILED user={}: {err:?}", user.id);
        }
    }

    async fn email_owner(
        &self,
        db: &Database,
        owner_id: &str,
        kind: ProtNoticeKind,
        date_ms: Option<i64>,
    ) {
        let kind = match kind {
            ProtNoticeKind::Grace => ProtEmailKind::Grace,
            ProtNoticeKind::Freeze => ProtEmailKind::Freeze,
            ProtNoticeKind::Final => ProtEmailKind::Final,
            ProtNoticeKind::Deleted => ProtEmailKind::Deleted,
            ProtNoticeKind::Warn(_) => return,
        };
        // A send can take minutes (SMTP timeouts): it runs on its own task
        // and the clock goes on. The notice row is already in, so a lost
        // email is never sent twice.
        let db = db.clone();
        let owner_id = owner_id.to_string();
        tokio::spawn(async move {
            match send_prot_owner_email(&db, &owner_id, kind, date_ms).await {
                Ok(true) => {}
                Ok(false) => log::info!("prot: owner email {kind:?} to {owner_id} not sent"),
                // The wrapper logged PROT_EMAIL_FAILED
                Err(err) => {
                    log::warn!("prot: owner email {kind:?} to {owner_id} failed: {err:?}")
                }
            }
        });
    }
}

/// The push text of a notice (12.3): no server or channel name, no amount
pub fn prot_push_body(kind: ProtNoticeKind, rules: &ProtTankRules) -> String {
    match kind {
        ProtNoticeKind::Warn(_) => PROT_PUSH_WARN.to_string(),
        ProtNoticeKind::Grace => PROT_PUSH_GRACE.to_string(),
        ProtNoticeKind::Freeze => PROT_PUSH_FREEZE.to_string(),
        // NIT 26: the configured count, never a hard-coded 10
        ProtNoticeKind::Final => format!(
            "A frozen Protected channel you're in may be deleted from Sloga's servers in {} \
             days unless it's topped up.",
            rules.final_notice_days()
        ),
        ProtNoticeKind::Deleted => PROT_PUSH_DELETED.to_string(),
    }
}

/// The date an owner email carries (12.4): Grace = grace end; Freeze = the
/// earliest deletion (only while deletion is on); Final = the earliest
/// deletion the guard allows; Deleted = when it ended
fn email_date(
    tank: &ProtTank,
    kind: ProtNoticeKind,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Option<i64> {
    let window = days_ms(rules.grace_days.saturating_add(rules.freeze_days));
    match kind {
        ProtNoticeKind::Grace => tank
            .exhausted_at
            .map(|at| at.saturating_add(days_ms(rules.grace_days))),
        ProtNoticeKind::Freeze if rules.deletion_enabled => {
            tank.exhausted_at.map(|at| at.saturating_add(window))
        }
        ProtNoticeKind::Final => tank.exhausted_at.map(|at| {
            at.saturating_add(window)
                .max(now_ms.saturating_add(days_ms(rules.final_notice_days())))
        }),
        ProtNoticeKind::Deleted => tank.ended_at.or(Some(now_ms)),
        ProtNoticeKind::Freeze | ProtNoticeKind::Warn(_) => None,
    }
}

/// Record the due notices of `tank` and deliver the most severe (12.2).
/// The others are recorded `delivered: false` and never sent late. A row is
/// inserted BEFORE sending (at most once); an existing row sends nothing.
/// `Final` dates the deletion guard in the same driver transaction.
pub async fn send_prot_notices(
    db: &Database,
    amqp: &dyn ProtNotifier,
    tank: &ProtTank,
    kinds: &[ProtNoticeKind],
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<()> {
    let Some(most) = kinds.iter().copied().max() else {
        return Ok(());
    };
    for kind in kinds.iter().copied().filter(|kind| *kind != most) {
        db.record_prot_notice(&tank.id, tank.warnings_epoch, kind, false, now_ms)
            .await?;
    }
    if !db
        .record_prot_notice(&tank.id, tank.warnings_epoch, most, true, now_ms)
        .await?
    {
        return Ok(());
    }
    deliver_notice(db, amqp, tank, most, rules, now_ms).await;
    Ok(())
}

/// Push to the owner and every user with an ACTIVE seat (bots and deleted
/// accounts skipped, each once); email the owner for Grace, Freeze, Final and
/// Deleted (the notifier never waits for the send). Failures are logged: the
/// notice row is already in.
async fn deliver_notice(
    db: &Database,
    amqp: &dyn ProtNotifier,
    tank: &ProtTank,
    kind: ProtNoticeKind,
    rules: &ProtTankRules,
    now_ms: i64,
) {
    let owner = match db.fetch_server(&tank.server_id).await {
        Ok(server) => Some(server.owner),
        Err(err) => {
            log::warn!(
                "prot: notice {} of tank {} has no owner: {err:?}",
                kind.key_segment(),
                tank.id
            );
            None
        }
    };
    let mut ids: BTreeSet<String> = owner.iter().cloned().collect();
    if let Some(channel_id) = tank_channel(tank) {
        match db.fetch_channel_seats(channel_id).await {
            Ok(seats) => ids.extend(
                seats
                    .into_iter()
                    .filter(|seat| seat.is_active())
                    .map(|seat| seat.user_id),
            ),
            Err(err) => {
                log::warn!("prot: seats of channel {channel_id} unread for a notice: {err:?}")
            }
        }
    }
    let ids: Vec<String> = ids.into_iter().collect();
    let users = match db.fetch_users(&ids).await {
        Ok(users) => users,
        Err(err) => {
            log::warn!(
                "prot: notice recipients of tank {} unread: {err:?}",
                tank.id
            );
            return;
        }
    };

    let body = prot_push_body(kind, rules);
    let mut owner_live = false;
    for user in users
        .iter()
        .filter(|user| user.bot.is_none() && !is_deleted_user(user))
    {
        owner_live |= owner.as_deref() == Some(user.id.as_str());
        amqp.push(user, PROT_PUSH_TITLE, &body).await;
    }

    let emailed = matches!(
        kind,
        ProtNoticeKind::Grace
            | ProtNoticeKind::Freeze
            | ProtNoticeKind::Final
            | ProtNoticeKind::Deleted
    );
    if let (true, true, Some(owner_id)) = (emailed, owner_live, owner.as_deref()) {
        amqp.email_owner(db, owner_id, kind, email_date(tank, kind, rules, now_ms))
            .await;
    }
}

// ---------------------------------------------------------------------------
// Settlement, purge, expiry (7.5, 9)
// ---------------------------------------------------------------------------

/// Close one open goal Cancelled with full returns. A goal that ended in
/// between has nothing left to return.
async fn close_with_returns(db: &Database, goal_id: &str, now_ms: i64) -> Result<()> {
    match db
        .close_prot_goal(goal_id, v0::ProtGoalState::Cancelled, now_ms)
        .await
    {
        Ok(outcome) => {
            settle_credited(db, &outcome.returned, now_ms).await;
            if let Some(channel_id) = outcome.removed_tank.as_ref().and_then(tank_channel) {
                publish_tank_removed(channel_id).await;
            }
            Ok(())
        }
        Err(err) if matches!(err.error_type, ErrorType::ProtGoalClosed) => Ok(()),
        Err(err) => Err(err),
    }
}

/// What became of a never-launched Settling tank
enum Launch {
    /// The pledges are in the tank: settle it
    Landed,
    /// The goal was closed with returns and the tank removed
    Removed,
}

/// A never-launched Settling tank (a delete in progress, 9.4): a protected
/// channel has its pledges captured (no launch-day burn for a Settling tank,
/// N5); otherwise its Launching goal is closed with returns, which removes
/// the tank. The close re-reads `protected` in its transaction (BR2).
async fn land_or_abandon(
    db: &Database,
    tank: &ProtTank,
    channel_id: &str,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<Launch> {
    for _ in 0..PROT_LAUNCH_ATTEMPTS {
        if db
            .capture_launch_pledges(channel_id, now_ms, rules)
            .await?
            .is_some()
        {
            return Ok(Launch::Landed);
        }
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
            return Ok(Launch::Landed);
        };
        match db
            .close_prot_goal(&goal.id, v0::ProtGoalState::Cancelled, now_ms)
            .await
        {
            Ok(outcome) => {
                settle_credited(db, &outcome.returned, now_ms).await;
                if outcome.removed_tank.is_some() {
                    return Ok(Launch::Removed);
                }
            }
            // Protect landed (capture next round), or a racing close or
            // capture ended the goal (look again)
            Err(err)
                if matches!(
                    err.error_type,
                    ErrorType::InvalidOperation | ErrorType::ProtGoalClosed
                ) => {}
            Err(err) => return Err(err),
        }
    }
    log::error!(
        "PROT_SETTLE_UNLANDED channel={channel_id} tank={}: the launch kept moving",
        tank.id
    );
    Err(create_error!(InternalError))
}

/// One purge pass of an ended tank's channel (6.5), then `purge_passes += 1`.
/// A channel the owner deleted (gone, or an owner delete that erased the
/// entitlement with `delete_protected_channel_data`) has nothing left to
/// purge: the channel delete removed its content, so the pass is only
/// counted (contracts 26). Any other channel is purged behind its Deleted
/// tombstone; the purge refuses without one, and the pass is not counted.
async fn purge_tank_content(db: &Database, tank: &ProtTank, now_ms: i64) -> Result<()> {
    if let Some(channel_id) = tank_channel(tank) {
        let channel_gone = match db.fetch_channel(channel_id).await {
            Ok(_) => false,
            Err(err) if is_not_found(&err) => true,
            Err(err) => return Err(err),
        };
        let tombstone = if channel_gone {
            None
        } else {
            db.fetch_channel_entitlement(channel_id).await?
        };
        let owner_deleted = tank.settle_cause == Some(ProtSettleCause::OwnerDelete);
        if channel_gone || (owner_deleted && tombstone.is_none()) {
            log::info!(
                "prot: tank {} purge pass {} counted without a purge (channel {channel_id} \
                 deleted by its owner)",
                tank.id,
                tank.purge_passes + 1
            );
        } else {
            let counts = db.purge_protected_channel_content(channel_id).await?;
            log::info!(
                "prot: tank {} purge pass {}: {} messages, {} groups, {} commits, {} join \
                 intents, {} envelopes",
                tank.id,
                tank.purge_passes + 1,
                counts.messages,
                counts.groups,
                counts.commits,
                counts.join_intents,
                counts.envelopes
            );
        }
    }
    db.mark_prot_tank_purged(&tank.id, now_ms).await
}

/// Finish a Settling tank (7.5, 7.1 step 4): a never-launched one is landed
/// or abandoned first (N3), then its open goals are closed with returns, the
/// balance is settled FIFO (9.2), the wallets get their second pass, an
/// Expiry or OwnerDelete tank gets purge pass 1, the event goes out and an
/// Expiry sends the Deleted notice. Every step is idempotent or a CAS, so a
/// crash between two is finished by the next tick.
async fn finish_settlement(
    db: &Database,
    amqp: &dyn ProtNotifier,
    tank: ProtTank,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<()> {
    if tank.launched_at.is_none() {
        if let Some(channel_id) = tank_channel(&tank) {
            // A Settling capture never burns (8.6): no rules can bill here
            let capture_rules = ProtTankRules {
                burning: false,
                ..rules.clone()
            };
            if let Launch::Removed =
                land_or_abandon(db, &tank, channel_id, &capture_rules, now_ms).await?
            {
                publish_tank_removed(channel_id).await;
                return Ok(());
            }
        }
    }

    for goal in db.fetch_open_prot_goals_by_tank(&tank.id).await? {
        close_with_returns(db, &goal.id, now_ms).await?;
    }
    let settlement = db.settle_prot_tank(&tank.id, now_ms).await?;
    settle_credited(db, &settlement.returns, now_ms).await;

    let mut settled = settlement.tank;
    let purged = matches!(
        settled.settle_cause,
        Some(ProtSettleCause::Expiry) | Some(ProtSettleCause::OwnerDelete)
    );
    if purged && settled.purge_passes == 0 {
        purge_tank_content(db, &settled, now_ms).await?;
        if let Some(current) = db.fetch_prot_tank(&settled.id).await? {
            settled = current;
        }
    }
    publish_tank_now(db, &settled, rules, now_ms).await;
    if settled.settle_cause == Some(ProtSettleCause::Expiry) {
        send_prot_notices(
            db,
            amqp,
            &settled,
            &[ProtNoticeKind::Deleted],
            rules,
            now_ms,
        )
        .await?;
    }
    Ok(())
}

/// What the 7.5 deletion guard says about a tank now
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpiryCheck {
    /// Not Frozen, or before `exhausted_at + grace_days + freeze_days`
    NotDue,
    /// Past its deadline while deletion is off (logged only)
    DryRun,
    /// Past its deadline without a Final notice `final_notice_days` old
    Postponed,
    Delete,
}

/// The 7.5 deletion guard: a Frozen tank past its deadline is deleted only
/// while deletion is on AND a Final notice was recorded
/// `final_notice_days` earlier. The Frozen pass decides with it, and
/// `delete_for_expiry` asks again on its fresh read.
fn expiry_check(tank: &ProtTank, rules: &ProtTankRules, now_ms: i64) -> ExpiryCheck {
    let window = days_ms(rules.grace_days.saturating_add(rules.freeze_days));
    let past_deadline = tank.stage == v0::ProtTankStage::Frozen
        && tank
            .exhausted_at
            .is_some_and(|at| now_ms >= at.saturating_add(window));
    if !past_deadline {
        return ExpiryCheck::NotDue;
    }
    if !rules.deletion_enabled {
        return ExpiryCheck::DryRun;
    }
    let warned = tank.final_warning_at.is_some_and(|warned_at| {
        warned_at.saturating_add(days_ms(rules.final_notice_days())) <= now_ms
    });
    if !warned {
        return ExpiryCheck::Postponed;
    }
    ExpiryCheck::Delete
}

/// 7.5: delete a Frozen tank whose deadline passed. The clock decided on
/// `tank` as it read it; the fresh read must be the same version and pass
/// the deletion guard again (a top-up that reactivated it, or a config
/// change, leaves it for the next tick to decide). Then begin (Frozen ->
/// Settling, cause Expiry) and finish: goals, FIFO settlement, purge pass 1,
/// event, Deleted notice. A tank already settling for another cause (an
/// owner delete in progress) is left to that settlement: an expiry never
/// finishes it. `channel.protected` stays true.
pub async fn delete_for_expiry(
    db: &Database,
    amqp: &dyn ProtNotifier,
    tank: &ProtTank,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<()> {
    match db.fetch_prot_tank(&tank.id).await? {
        Some(current)
            if current.version == tank.version
                && expiry_check(&current, rules, now_ms) == ExpiryCheck::Delete => {}
        _ => {
            log::info!(
                "prot: tank {} no longer due for deletion; decided again next tick",
                tank.id
            );
            return Ok(());
        }
    }
    let Some(begun) = db
        .begin_prot_settlement(&tank.id, ProtSettleCause::Expiry, now_ms)
        .await?
    else {
        return Ok(());
    };
    if begun.settle_cause != Some(ProtSettleCause::Expiry) {
        log::info!(
            "prot: tank {} is settling for {:?}; the expiry leaves it to that settlement",
            tank.id,
            begun.settle_cause
        );
        return Ok(());
    }
    log::info!("AUDIT prot_expiry_delete: tank={} at={now_ms}", tank.id);
    finish_settlement(db, amqp, begun, rules, now_ms).await
}

// ---------------------------------------------------------------------------
// The clock (7)
// ---------------------------------------------------------------------------

/// The tanks one paged read returned
struct TankRead {
    tanks: Vec<ProtTank>,
    /// Every tank in the stages was read (false: the page cap stopped it)
    complete: bool,
}

/// Every tank in `stages`, paged by `{stage, _id}`, at most
/// `PROT_MAX_PAGES` pages per tick (the rest next tick; logged)
async fn tanks_in(db: &Database, stages: &[v0::ProtTankStage]) -> Result<TankRead> {
    let mut tanks = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..PROT_MAX_PAGES {
        let page = db
            .fetch_prot_tanks_by_stage(stages, after.as_deref(), PROT_TANK_PAGE)
            .await?;
        let full = i64::try_from(page.len()).unwrap_or(i64::MAX) >= PROT_TANK_PAGE;
        after = page.last().map(|tank| tank.id.clone());
        tanks.extend(page);
        if !full || after.is_none() {
            return Ok(TankRead {
                tanks,
                complete: true,
            });
        }
    }
    log::warn!(
        "PROT_CLOCK_TRUNCATED stages={:?} read={}: the rest waits for the next tick",
        stages,
        tanks.len()
    );
    Ok(TankRead {
        tanks,
        complete: false,
    })
}

const LIVE_STAGES: [v0::ProtTankStage; 3] = [
    v0::ProtTankStage::Active,
    v0::ProtTankStage::Grace,
    v0::ProtTankStage::Frozen,
];

/// N1: while a pause is recorded, only a tank already shifted for it may
/// move a clock (burn, deadline, notice)
fn shifted_for(tank: &ProtTank, paused: Option<i64>) -> bool {
    paused.is_none() || tank.pause_shift_for == paused
}

/// Bill every due day of `tank` up to today, day by day (7.2 catch-up), so
/// `exhausted_at` is the missed day's start and Grace -> Frozen happens on
/// the right day after an outage. N-4: an event only when the stage moved
/// (a Grace day clamped at the floor answers EnteredGrace every day).
async fn burn_due_days(
    db: &Database,
    mut tank: ProtTank,
    paused: Option<i64>,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<ProtTank> {
    let today = prot_utc_day(now_ms);
    for _ in 0..PROT_CATCH_UP_DAYS {
        let Some(day) = tank.next_burn_day.clone() else {
            break;
        };
        if day.as_str() > today.as_str() {
            break;
        }
        let stage_before = tank.stage;
        let (next, stop) = match db
            .burn_prot_tank_day(&tank.id, &day, paused, now_ms, rules)
            .await?
        {
            ProtBurnOutcome::NotDue { tank } | ProtBurnOutcome::Froze { tank } => (tank, true),
            ProtBurnOutcome::Burned { tank, .. } | ProtBurnOutcome::EnteredGrace { tank, .. } => {
                (tank, false)
            }
        };
        if next.stage != stage_before {
            publish_tank_now(db, &next, rules, now_ms).await;
        }
        tank = next;
        // A day that did not move the clock would repeat
        if stop || tank.next_burn_day.as_deref() == Some(day.as_str()) {
            break;
        }
    }
    Ok(tank)
}

/// Before a write that prices today (a manual tier change, an upgrade-goal
/// apply), bill every day the clock has not billed yet, TODAY INCLUDED
/// (`next_burn_day <= today`): between 00:00 UTC and the clock's first
/// tick today is still unbilled, and a tier charge for the hours left
/// followed by the clock billing the whole day at the new price would charge
/// the new price twice. Burning today here is what the clock does at its
/// tick (the day's burn is the 00:00 charge, 7.2). Only while burning, only
/// Active/Grace, and never a tank still waiting for its pause shift (its
/// missed days are paused days, N4: the driver answers NotDue).
async fn catch_up_before_pricing(
    db: &Database,
    tank_id: &str,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<()> {
    if !rules.burning {
        return Ok(());
    }
    let Some(tank) = db.fetch_prot_tank(tank_id).await? else {
        return Ok(());
    };
    let today = prot_utc_day(now_ms);
    let due = matches!(
        tank.stage,
        v0::ProtTankStage::Active | v0::ProtTankStage::Grace
    ) && tank
        .next_burn_day
        .as_deref()
        .is_some_and(|day| day <= today.as_str());
    if !due {
        return Ok(());
    }
    let paused = db
        .fetch_prot_runtime()
        .await?
        .and_then(|runtime| runtime.burn_paused_at);
    burn_due_days(db, tank, paused, rules, now_ms).await?;
    Ok(())
}

/// Step 1, burning on with a pause recorded: shift every live tank (7.4),
/// then clear the pause after a COMPLETE pass finds every one shifted (a
/// second pass verifies, so a tank captured during the first is not missed)
async fn resume_pass(db: &Database, paused_at: i64, rules: &ProtTankRules, now_ms: i64) {
    for _ in 0..2 {
        let read = match tanks_in(db, &LIVE_STAGES).await {
            Ok(read) => read,
            Err(err) => {
                log::error!("PROT_CLOCK_FAILED tank=- step=shift: {err:?}");
                return;
            }
        };
        // A truncated read never clears the pause: an unseen tank may still
        // be unshifted
        let mut all_shifted = read.complete;
        for tank in read.tanks {
            if tank.pause_shift_for == Some(paused_at) {
                continue;
            }
            all_shifted = false;
            match db
                .shift_prot_tank_for_pause(&tank.id, paused_at, now_ms, rules)
                .await
            {
                Ok(_) => {
                    // The resume pro rata may have moved it into Grace
                    if let Ok(Some(shifted)) = db.fetch_prot_tank(&tank.id).await {
                        if shifted.stage != tank.stage {
                            publish_tank_now(db, &shifted, rules, now_ms).await;
                        }
                    }
                }
                Err(err) => log::error!("PROT_CLOCK_FAILED tank={} step=shift: {err:?}", tank.id),
            }
        }
        if all_shifted {
            if let Err(err) = db.clear_prot_burn_paused(paused_at).await {
                log::error!("PROT_CLOCK_FAILED tank=- step=clear_pause: {err:?}");
            }
            return;
        }
    }
}

/// Step 2: the due tanks, oldest day first, each caught up day by day
async fn burn_pass(db: &Database, paused: Option<i64>, rules: &ProtTankRules, now_ms: i64) {
    let today = prot_utc_day(now_ms);
    let mut seen = BTreeSet::new();
    for _ in 0..PROT_MAX_PAGES {
        let due = match db.fetch_prot_tanks_due_burn(&today, PROT_TANK_PAGE).await {
            Ok(due) => due,
            Err(err) => {
                log::error!("PROT_CLOCK_FAILED tank=- step=burn: {err:?}");
                return;
            }
        };
        let fresh: Vec<ProtTank> = due
            .into_iter()
            .filter(|tank| seen.insert(tank.id.clone()))
            .collect();
        if fresh.is_empty() {
            return;
        }
        for tank in fresh {
            let tank_id = tank.id.clone();
            if let Err(err) = burn_due_days(db, tank, paused, rules, now_ms).await {
                log::error!("PROT_CLOCK_FAILED tank={tank_id} step=burn: {err:?}");
            }
        }
    }
}

/// Step 3 (burning only, shifted tanks only, N1): a Frozen tank past
/// `exhausted_at + grace_days + freeze_days` is deleted only while deletion
/// is on AND a Final notice was recorded `final_notice_days` earlier (7.5);
/// otherwise the deletion is a logged dry run or postponed
async fn frozen_pass(
    db: &Database,
    amqp: &dyn ProtNotifier,
    paused: Option<i64>,
    rules: &ProtTankRules,
    now_ms: i64,
) {
    let tanks = match tanks_in(db, &[v0::ProtTankStage::Frozen]).await {
        Ok(read) => read.tanks,
        Err(err) => {
            log::error!("PROT_CLOCK_FAILED tank=- step=frozen: {err:?}");
            return;
        }
    };
    for tank in tanks {
        if !shifted_for(&tank, paused) {
            continue;
        }
        if tank.exhausted_at.is_none() {
            log::error!(
                "PROT_CLOCK_FAILED tank={} step=frozen: no exhausted_at",
                tank.id
            );
            continue;
        }
        match expiry_check(&tank, rules, now_ms) {
            ExpiryCheck::NotDue => {}
            ExpiryCheck::DryRun => log::info!("PROT_DELETION_DRY_RUN tank={}", tank.id),
            ExpiryCheck::Postponed => log::info!("PROT_DELETION_POSTPONED tank={}", tank.id),
            ExpiryCheck::Delete => {
                if let Err(err) = delete_for_expiry(db, amqp, &tank, rules, now_ms).await {
                    log::error!("PROT_CLOCK_FAILED tank={} step=delete: {err:?}", tank.id);
                }
            }
        }
    }
}

/// Step 4 (always, audit MAJOR 5): a Settling tank untouched for an hour is
/// a crashed or abandoned settlement; finish it
async fn settling_pass(db: &Database, amqp: &dyn ProtNotifier, rules: &ProtTankRules, now_ms: i64) {
    let tanks = match tanks_in(db, &[v0::ProtTankStage::Settling]).await {
        Ok(read) => read.tanks,
        Err(err) => {
            log::error!("PROT_CLOCK_FAILED tank=- step=settle: {err:?}");
            return;
        }
    };
    for tank in tanks {
        if tank.updated_at > now_ms.saturating_sub(HOUR_MS) {
            continue;
        }
        let tank_id = tank.id.clone();
        if let Err(err) = finish_settlement(db, amqp, tank, rules, now_ms).await {
            log::error!("PROT_CLOCK_FAILED tank={tank_id} step=settle: {err:?}");
        }
    }
}

/// Step 5: pending downgrades whose cooling seats have freed up (8.9)
async fn pending_tier_pass(db: &Database, rules: &ProtTankRules, now_ms: i64) {
    let tanks = match tanks_in(db, &LIVE_STAGES).await {
        Ok(read) => read.tanks,
        Err(err) => {
            log::error!("PROT_CLOCK_FAILED tank=- step=tier: {err:?}");
            return;
        }
    };
    for tank in tanks.iter().filter(|tank| tank.pending_slot_tier.is_some()) {
        match db.apply_pending_prot_tier(&tank.id, now_ms, rules).await {
            Ok(Some(changed)) => publish_tank_now(db, &changed, rules, now_ms).await,
            Ok(None) => {}
            Err(err) => log::error!("PROT_CLOCK_FAILED tank={} step=tier: {err:?}", tank.id),
        }
    }
}

async fn notify_tank(
    db: &Database,
    amqp: &dyn ProtNotifier,
    tank: &ProtTank,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<()> {
    let balance = tank_balance(db, &tank.id).await?;
    let kinds = prot_notice_due(tank, balance, rules, now_ms);
    send_prot_notices(db, amqp, tank, &kinds, rules, now_ms).await
}

/// Step 6 (burning only, shifted tanks only, N1): the notices of live tanks,
/// and the Deleted notice of a tank that ran out of Prot in the last day
/// (never an owner delete or a termination, audit 9)
async fn notice_pass(
    db: &Database,
    amqp: &dyn ProtNotifier,
    paused: Option<i64>,
    rules: &ProtTankRules,
    now_ms: i64,
) {
    let live = match tanks_in(db, &LIVE_STAGES).await {
        Ok(read) => read.tanks,
        Err(err) => {
            log::error!("PROT_CLOCK_FAILED tank=- step=notice: {err:?}");
            return;
        }
    };
    for tank in live.iter().filter(|tank| shifted_for(tank, paused)) {
        if let Err(err) = notify_tank(db, amqp, tank, rules, now_ms).await {
            log::error!("PROT_CLOCK_FAILED tank={} step=notice: {err:?}", tank.id);
        }
    }

    let deleted = match tanks_in(db, &[v0::ProtTankStage::Deleted]).await {
        Ok(read) => read.tanks,
        Err(err) => {
            log::error!("PROT_CLOCK_FAILED tank=- step=notice: {err:?}");
            return;
        }
    };
    let since = now_ms.saturating_sub(DAY_MS);
    for tank in deleted.iter().filter(|tank| {
        tank.settle_cause == Some(ProtSettleCause::Expiry)
            && tank.ended_at.is_some_and(|ended| ended >= since)
    }) {
        if let Err(err) = notify_tank(db, amqp, tank, rules, now_ms).await {
            log::error!("PROT_CLOCK_FAILED tank={} step=notice: {err:?}", tank.id);
        }
    }
}

/// Step 7 (always, audit MAJOR 5): ended tanks with fewer than two purge
/// passes. Pass 0: close any still-open goal with returns (a termination
/// that crashed after its first transaction), then purge pass 1. Pass 1: the
/// second purge an hour after the first, which catches a send that read the
/// state before the stage CAS.
async fn purge_pass(db: &Database, now_ms: i64) {
    let mut after: Option<String> = None;
    for _ in 0..PROT_MAX_PAGES {
        let page = match db
            .fetch_prot_tanks_to_purge(after.as_deref(), PROT_TANK_PAGE)
            .await
        {
            Ok(page) => page,
            Err(err) => {
                log::error!("PROT_CLOCK_FAILED tank=- step=purge: {err:?}");
                return;
            }
        };
        let full = i64::try_from(page.len()).unwrap_or(i64::MAX) >= PROT_TANK_PAGE;
        after = page.last().map(|tank| tank.id.clone());
        for tank in &page {
            if let Err(err) = purge_ended_tank(db, tank, now_ms).await {
                log::error!("PROT_CLOCK_FAILED tank={} step=purge: {err:?}", tank.id);
            }
        }
        if !full || after.is_none() {
            return;
        }
    }
}

async fn purge_ended_tank(db: &Database, tank: &ProtTank, now_ms: i64) -> Result<()> {
    match tank.purge_passes {
        0 => {
            for goal in db.fetch_open_prot_goals_by_tank(&tank.id).await? {
                close_with_returns(db, &goal.id, now_ms).await?;
            }
            purge_tank_content(db, tank, now_ms).await
        }
        1 if tank
            .purged_at
            .is_some_and(|at| at <= now_ms.saturating_sub(HOUR_MS)) =>
        {
            purge_tank_content(db, tank, now_ms).await
        }
        _ => Ok(()),
    }
}

/// One tick of the clock (7.1) with the rules it was given. Errors are
/// logged per tank and step; the tick goes on.
async fn run_clock(db: &Database, amqp: &dyn ProtNotifier, rules: &ProtTankRules, now_ms: i64) {
    // `None`: the runtime row could not be read, so nothing that depends on
    // the pause runs this tick (no burn, deadline or notice)
    let paused = match db.fetch_prot_runtime().await {
        Ok(runtime) => Some(runtime.and_then(|runtime| runtime.burn_paused_at)),
        Err(err) => {
            log::error!("PROT_CLOCK_FAILED tank=- step=runtime: {err:?}");
            None
        }
    };

    // 1-3. A paused clock (burning off) only records the pause: no burn, no
    // resume, no Frozen pass, no notice, so it never advances a deadline (N1)
    if let Some(paused) = paused {
        if !rules.burning {
            if let Err(err) = db.set_prot_burn_paused(now_ms).await {
                log::error!("PROT_CLOCK_FAILED tank=- step=pause: {err:?}");
            }
        } else {
            if let Some(paused_at) = paused {
                resume_pass(db, paused_at, rules, now_ms).await;
            }
            burn_pass(db, paused, rules, now_ms).await;
            frozen_pass(db, amqp, paused, rules, now_ms).await;
        }
    }

    // 4. Always: finish settlements that already started
    settling_pass(db, amqp, rules, now_ms).await;

    // 5. Pending downgrades
    pending_tier_pass(db, rules, now_ms).await;

    // 6. Notices, only from a burning clock and shifted tanks (N1)
    if let (true, Some(paused)) = (rules.burning, paused) {
        notice_pass(db, amqp, paused, rules, now_ms).await;
    }

    // 7. Always: purge passes of ended tanks
    purge_pass(db, now_ms).await;
}

/// The crond body of `prot_tank_clock` (13.1): one tick at `now_ms`. Reads
/// the Prot config itself (an invalid one is logged `PROT_TANK_CONFIG_INVALID`
/// and the tick does nothing). Runs whatever the flags say: with burning off
/// it records the pause (D16) and still finishes settlements and purges.
pub async fn clock_tick(db: &Database, amqp: &AMQP, now_ms: i64) {
    let rules = match ProtTankRules::load().await {
        Ok(rules) => rules,
        // `from_config` logged the offending key
        Err(_) => return,
    };
    run_clock(db, amqp, &rules, now_ms).await;
}

// ---------------------------------------------------------------------------
// The goal sweep (13.2)
// ---------------------------------------------------------------------------

/// Apply a Funded upgrade goal (8.7): Applied: the tank's event; closed
/// Cancelled instead (the tier moved, the tank ended): the pledgers' wallets
async fn apply_upgrade(
    db: &Database,
    goal_id: &str,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<()> {
    // Today is billed at the old price before the apply charges the
    // difference for the hours left (the pledge route and the sweep)
    if let Some(tank_id) = db
        .fetch_prot_goal(goal_id)
        .await?
        .filter(|goal| {
            goal.kind == v0::ProtGoalKind::Upgrade && goal.state == v0::ProtGoalState::Funded
        })
        .and_then(|goal| goal.tank_id)
    {
        catch_up_before_pricing(db, &tank_id, rules, now_ms).await?;
    }
    match db.apply_prot_upgrade_goal(goal_id, now_ms, rules).await? {
        Some(tank) => publish_tank_now(db, &tank, rules, now_ms).await,
        None => {
            let cancelled = db
                .fetch_prot_goal(goal_id)
                .await?
                .is_some_and(|goal| goal.state == v0::ProtGoalState::Cancelled);
            if cancelled {
                settle_users(db, &returned_pledgers(db, goal_id).await?, now_ms).await;
            }
        }
    }
    Ok(())
}

/// One due goal. Every step claims the goal by a state CAS in its driver
/// transaction, so two replicas never act twice.
async fn sweep_goal(
    db: &Database,
    goal: &ProtGoal,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Result<()> {
    let past_launch_deadline = goal.launch_deadline_at.is_some_and(|at| at <= now_ms);
    match (goal.kind, goal.state) {
        (_, v0::ProtGoalState::Funding) if goal.deadline_at <= now_ms => {
            match db
                .close_prot_goal(&goal.id, v0::ProtGoalState::Expired, now_ms)
                .await
            {
                Ok(outcome) => settle_credited(db, &outcome.returned, now_ms).await,
                Err(err) if matches!(err.error_type, ErrorType::ProtGoalClosed) => {}
                Err(err) => return Err(err),
            }
        }
        (v0::ProtGoalKind::Launch, v0::ProtGoalState::Funded) if past_launch_deadline => {
            close_with_returns(db, &goal.id, now_ms).await?;
        }
        (v0::ProtGoalKind::Launch, v0::ProtGoalState::Launching) => {
            let Some(channel_id) = goal.channel_id.as_deref() else {
                return Ok(());
            };
            // Protect landed: capture (the backstop of on_protect_landed)
            if land_protect(db, channel_id, rules, now_ms).await?.is_none() && past_launch_deadline
            {
                // Abandoned: entitlement and tank removed, pledges returned.
                // A protect that lands in between makes the close refuse;
                // the next sweep captures.
                match close_with_returns(db, &goal.id, now_ms).await {
                    Ok(()) => {}
                    Err(err) if matches!(err.error_type, ErrorType::InvalidOperation) => {}
                    Err(err) => return Err(err),
                }
            }
        }
        (v0::ProtGoalKind::Launch, v0::ProtGoalState::Launched) => {
            let window = days_ms(rules.launch_seat_window_days);
            let due = !goal.refund7_done
                && goal
                    .launched_at
                    .is_some_and(|at| at.saturating_add(window) <= now_ms);
            if due {
                let returned = db.return_unseated_launch_pledges(&goal.id, now_ms).await?;
                settle_credited(db, &returned, now_ms).await;
                if !returned.is_empty() {
                    if let Some(tank_id) = &goal.tank_id {
                        if let Some(tank) = db.fetch_prot_tank(tank_id).await? {
                            publish_tank_now(db, &tank, rules, now_ms).await;
                        }
                    }
                }
            }
        }
        (v0::ProtGoalKind::Upgrade, v0::ProtGoalState::Funded) => {
            // 8.7 exit: never Applied by funded_at + launch_window_days ->
            // full returns, so pledges are never held forever
            if past_launch_deadline {
                close_with_returns(db, &goal.id, now_ms).await?;
            } else {
                apply_upgrade(db, &goal.id, rules, now_ms).await?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn run_goals(db: &Database, rules: &ProtTankRules, now_ms: i64) {
    let window = days_ms(rules.launch_seat_window_days);
    let mut seen = BTreeSet::new();
    for _ in 0..PROT_MAX_PAGES {
        let due = match db
            .fetch_prot_goals_due(now_ms, window, PROT_GOAL_PAGE)
            .await
        {
            Ok(due) => due,
            Err(err) => {
                log::error!("PROT_GOALS_FAILED goal=- : {err:?}");
                return;
            }
        };
        let fresh: Vec<ProtGoal> = due
            .into_iter()
            .filter(|goal| seen.insert(goal.id.clone()))
            .collect();
        if fresh.is_empty() {
            return;
        }
        for goal in &fresh {
            if let Err(err) = sweep_goal(db, goal, rules, now_ms).await {
                log::error!("PROT_GOALS_FAILED goal={}: {err:?}", goal.id);
            }
        }
    }
}

/// The crond body of `prot_goals` (13.2): one sweep at `now_ms`. The task
/// checks `enabled`; self-serve is not needed (goals created while it was on
/// still end, and Funded upgrade goals still apply). Reads its own rules; an
/// invalid config is logged and the sweep does nothing.
pub async fn goals_tick(db: &Database, now_ms: i64) {
    let rules = match ProtTankRules::load().await {
        Ok(rules) => rules,
        Err(_) => return,
    };
    run_goals(db, &rules, now_ms).await;
}

/// Engine tests. Every database test runs on the driver `TEST_DB` names
/// (`REFERENCE` or `MONGODB`; unset panics, so they never reach production);
/// the gate runs the suite under both. Times are fixed epoch milliseconds
/// from `DAY0`, so the UTC days and the pro rata hours are the same on both.
#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex as StdMutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use revolt_database::test_teardown::TestDatabaseGuard;
    use revolt_database::{
        prot_key_admin, prot_key_burn, prot_key_forfeit_tank, prot_key_purchase, prot_key_tier,
        prot_key_writeoff, BotInformation, ChannelEntitlementState, DatabaseInfo, EncryptedPayload,
        MemberCompositeKey, Message, ProtAmount, ProtPosting, ProtRef, SeatListBody,
        SeatListSubmission, PROT_ACTOR_PAYMENTS, PROT_SYS_ADJUST, PROT_SYS_ISSUED,
    };

    use super::*;

    /// 2026-10-01T00:00:00Z: day 0 of every scenario
    const DAY0: i64 = 1_790_812_800_000;
    const ADMIN: &str = "01ADMIN0000000000000000000";
    /// The owner's device, the signer of every genesis list below
    const DEVICE: &str = "00112233445566778899aabbccddeeff";
    /// Names no push may carry (12.3)
    const SERVER_NAME: &str = "Secret Hideout";
    const CHANNEL_NAME: &str = "secret-plans";

    // Its own range, so no database name here repeats one another engine
    // test module picks in the same process
    static NEXT_DB: AtomicU64 = AtomicU64::new(950_000);

    fn at(day: i64, hour: i64) -> i64 {
        DAY0 + day * DAY_MS + hour * HOUR_MS
    }

    fn day(n: i64) -> String {
        prot_utc_day(at(n, 0))
    }

    /// The shipped defaults (40 Prot a day for 10 slots, 5 grace days, 25
    /// freeze days, the Final on day 20, so 10 days of notice) with every
    /// switch on (contracts 8.0)
    fn rules() -> ProtTankRules {
        ProtTankRules {
            self_serve: true,
            burning: true,
            deletion_enabled: true,
            ..ProtTankRules::from_config(&revolt_config::ProtectionFeatures::default())
                .expect("the default Prot config is valid")
        }
    }

    /// A throwaway database plus the guard that drops it (Mongo) if the test
    /// panics before its own `drop_db`
    struct TestDb {
        db: Database,
        guard: StdMutex<Option<TestDatabaseGuard>>,
    }

    impl Deref for TestDb {
        type Target = Database;

        fn deref(&self) -> &Database {
            &self.db
        }
    }

    /// Mongo: named `revolt_test_<digits>` so `scripts/drop-test-databases.sh`
    /// sweeps one a panicking test leaves; the migration installs the Prot
    /// indexes (revisions 76 and 79)
    async fn test_db() -> TestDb {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or_default();
        let name = format!(
            "revolt_test_{}{:09}{}",
            std::process::id(),
            nanos,
            NEXT_DB.fetch_add(1, Ordering::SeqCst)
        );
        let db = DatabaseInfo::Test(name)
            .connect()
            .await
            .expect("database connection");
        let guard = TestDatabaseGuard::arm(&db).await;
        db.migrate_database().await.expect("schema");
        TestDb {
            db,
            guard: StdMutex::new(Some(guard)),
        }
    }

    async fn drop_db(db: &TestDb) {
        if let Database::MongoDb(mongo) = &db.db {
            assert!(mongo.1.starts_with("revolt_test_"));
            mongo.db().drop().await.ok();
        }
        let guard = db.guard.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(guard) = guard {
            guard.disarm();
        }
    }

    /// (recipient, title, body)
    type Push = (String, String, String);
    /// (owner, notice, date)
    type Email = (String, ProtNoticeKind, Option<i64>);

    /// Records what the clock would push and email
    #[derive(Default)]
    struct Recorder {
        pushes: StdMutex<Vec<Push>>,
        emails: StdMutex<Vec<Email>>,
    }

    #[async_trait]
    impl ProtNotifier for Recorder {
        async fn push(&self, user: &User, title: &str, body: &str) {
            self.pushes.lock().unwrap().push((
                user.id.clone(),
                title.to_string(),
                body.to_string(),
            ));
        }

        async fn email_owner(
            &self,
            _db: &Database,
            owner_id: &str,
            kind: ProtNoticeKind,
            date_ms: Option<i64>,
        ) {
            self.emails
                .lock()
                .unwrap()
                .push((owner_id.to_string(), kind, date_ms));
        }
    }

    impl Recorder {
        /// The pushed bodies since the last call
        fn take_bodies(&self) -> Vec<String> {
            std::mem::take(&mut *self.pushes.lock().unwrap())
                .into_iter()
                .map(|(_, title, body)| {
                    assert_eq!(title, PROT_PUSH_TITLE);
                    body
                })
                .collect()
        }

        fn take_emails(&self) -> Vec<Email> {
            std::mem::take(&mut *self.emails.lock().unwrap())
        }
    }

    fn error_type<T: std::fmt::Debug>(result: Result<T>) -> ErrorType {
        result.expect_err("expected an error").error_type
    }

    #[allow(clippy::disallowed_methods)]
    async fn person(db: &Database, configure: impl FnOnce(&mut User)) -> User {
        let id = Ulid::new().to_string();
        let mut user = User {
            id: id.clone(),
            username: id.clone(),
            discriminator: "0001".to_string(),
            ..Default::default()
        };
        configure(&mut user);
        db.insert_user(&user).await.expect("user");
        user
    }

    async fn live(db: &Database) -> User {
        person(db, |_| {}).await
    }

    async fn join(db: &Database, server_id: &str, user_id: &str, timeout: Option<Timestamp>) {
        db.insert_or_merge_member(&Member {
            id: MemberCompositeKey {
                server: server_id.to_string(),
                user: user_id.to_string(),
            },
            timeout,
            ..Default::default()
        })
        .await
        .expect("member");
    }

    /// One server whose members may see its channels, its owner, a member
    /// with Prot to spend (`backer`) and one TextChannel
    struct World {
        server: String,
        channel: String,
        owner: User,
        backer: User,
    }

    #[allow(clippy::disallowed_methods)]
    async fn add_channel(db: &Database, server_id: &str) -> String {
        let channel_id = Ulid::new().to_string();
        db.insert_channel(&Channel::TextChannel {
            id: channel_id.clone(),
            server: server_id.to_string(),
            name: CHANNEL_NAME.to_string(),
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
        .expect("channel");
        channel_id
    }

    #[allow(clippy::disallowed_methods)]
    async fn world_owned_by(db: &Database, owner: User) -> World {
        let backer = live(db).await;
        let server_id = Ulid::new().to_string();
        let view = ChannelPermission::ViewChannel as i64;
        let server: Server = serde_json::from_value(serde_json::json!({
            "_id": server_id,
            "owner": owner.id,
            "name": SERVER_NAME,
            "channels": [],
            "default_permissions": view,
        }))
        .unwrap();
        db.insert_server(&server).await.expect("server");
        join(db, &server_id, &owner.id, None).await;
        join(db, &server_id, &backer.id, None).await;
        let channel = add_channel(db, &server_id).await;
        World {
            server: server_id,
            channel,
            owner,
            backer,
        }
    }

    async fn world(db: &Database) -> World {
        let owner = live(db).await;
        world_owned_by(db, owner).await
    }

    /// An admin credit (never held, D17)
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
            reason: Some("tank engine test".to_string()),
            created_at: now - 1_000,
        })
        .await
        .expect("fund");
    }

    /// A Prot purchase at `at` (held for `contribute_hold_hours`, D17)
    async fn buy(db: &Database, user_id: &str, amount: i64, at: i64) {
        let order_id = Ulid::new().to_string();
        db.apply_prot_posting(&ProtPosting {
            key: prot_key_purchase(&order_id),
            kind: v0::ProtEntryKind::Purchase,
            debit: PROT_SYS_ISSUED.to_string(),
            credit: prot_user_account(user_id),
            amount: ProtAmount::Exact(amount),
            debit_floor: 0,
            actor: PROT_ACTOR_PAYMENTS.to_string(),
            reference: ProtRef {
                order_id: Some(order_id),
                ..Default::default()
            },
            reason: None,
            created_at: at,
        })
        .await
        .expect("purchase");
    }

    fn contribution(amount: i64) -> v0::DataProtContribute {
        v0::DataProtContribute {
            amount,
            nonce: Ulid::new().to_string(),
        }
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

    /// A launched (Active) tank on the world's channel: the owner creates a
    /// 10-slot, 30-day goal (1,200 Prot), pledges all of it (the owner is
    /// exempt from the 7-day returns), launches, protects, and the protect
    /// hook captures. At 00:00 with burning on, the launch day costs a full
    /// 40: the tank holds 1,160 and next bills day 1.
    async fn active_tank(db: &Database, w: &World, rules: &ProtTankRules, now: i64) -> ProtTank {
        let goal = create_prot_launch_goal(
            db,
            &w.owner,
            &w.server,
            v0::DataProtLaunchGoal {
                slots: 10,
                days: 30,
                nonce: Ulid::new().to_string(),
            },
            rules,
            now,
        )
        .await
        .expect("launch goal");
        assert_eq!(goal.target_prot, 1_200);
        fund(db, &w.owner.id, 1_200, now).await;
        let pledged = pledge_prot(db, &w.owner, &goal.id, contribution(1_200), rules, now)
            .await
            .expect("pledge");
        assert_eq!(pledged.goal.state, v0::ProtGoalState::Funded);
        launch_prot_goal(
            db,
            &w.owner,
            &goal.id,
            v0::DataProtGoalLaunch {
                channel_id: w.channel.clone(),
            },
            rules,
            now,
        )
        .await
        .expect("launch");
        db.protect_channel(
            &w.channel,
            &genesis(&w.channel, &w.owner.id, now),
            timestamp_of(now),
        )
        .await
        .expect("protect");
        land_protect(db, &w.channel, rules, now)
            .await
            .expect("capture")
            .expect("a protected Launching tank is captured")
    }

    async fn tank(db: &Database, tank_id: &str) -> ProtTank {
        db.fetch_prot_tank(tank_id)
            .await
            .expect("tank")
            .expect("the tank row")
    }

    async fn balance_of(db: &Database, account: &str) -> i64 {
        db.fetch_prot_account(account)
            .await
            .expect("account")
            .map_or(0, |account| account.balance)
    }

    async fn row(db: &Database, key: &str) -> Option<ProtLedgerEntry> {
        db.fetch_prot_entry_by_key(key).await.expect("row")
    }

    async fn entitlement_state(db: &Database, channel_id: &str) -> Option<ChannelEntitlementState> {
        db.fetch_channel_entitlement(channel_id)
            .await
            .expect("entitlement")
            .map(|entitlement| entitlement.state)
    }

    /// `n` zero bytes, base64 without padding
    fn zeros(n: usize) -> String {
        "A".repeat(4 * (n / 3) + [0, 2, 3][n % 3])
    }

    /// A structurally valid protected-channel message (the insert guard
    /// refuses plaintext in a protected channel); its id
    #[allow(clippy::disallowed_methods)]
    async fn ciphertext_message(db: &Database, channel_id: &str, author: &str) -> String {
        let id = Ulid::new().to_string();
        db.insert_message(&Message {
            nonce: Some(id.clone()),
            id: id.clone(),
            channel: channel_id.to_string(),
            author: author.to_string(),
            encrypted: Some(EncryptedPayload {
                v: EncryptedPayload::VERSION,
                group_id: "ab".repeat(32),
                epoch: 0,
                sender_device_id: "cd".repeat(16),
                nonce: zeros(EncryptedPayload::NONCE_BYTES),
                ciphertext: zeros(EncryptedPayload::CIPHERTEXT_MIN_BYTES),
                sig: zeros(EncryptedPayload::SIG_BYTES),
                franking: None,
            }),
            ..Default::default()
        })
        .await
        .expect("message");
        id
    }

    async fn message_exists(db: &Database, id: &str) -> bool {
        match db.fetch_message(id).await {
            Ok(_) => true,
            Err(err) if is_not_found(&err) => false,
            Err(err) => panic!("message read failed: {err:?}"),
        }
    }

    async fn still_protected(db: &Database, channel_id: &str) -> bool {
        match db.fetch_channel(channel_id).await.expect("channel") {
            Channel::TextChannel { protected, .. } => protected,
            other => panic!("not a TextChannel: {other:?}"),
        }
    }

    fn final_text(rules: &ProtTankRules) -> String {
        prot_push_body(ProtNoticeKind::Final, rules)
    }

    // -----------------------------------------------------------------------
    // 12.1 coalescer, 12.3 push text
    // -----------------------------------------------------------------------

    /// 12.1: at most one publish per tank per window; one trailing publish
    /// for everything inside it. Control: a window of 0 publishes every
    /// contribution and fails the burst count.
    #[test]
    fn coalescer_publishes_at_most_once_per_ten_seconds() {
        let coalescer = ProtTankUpdateCoalescer::new(PROT_TANK_UPDATE_WINDOW_MS);
        let t0 = 1_000_000;
        assert_eq!(coalescer.admit("t", t0), ProtTankUpdatePlan::Now);
        assert_eq!(
            coalescer.admit("t", t0 + 1_000),
            ProtTankUpdatePlan::Trailing { at_ms: t0 + 10_000 }
        );
        assert_eq!(
            coalescer.admit("t", t0 + 9_999),
            ProtTankUpdatePlan::Absorbed
        );
        // Per tank
        assert_eq!(coalescer.admit("u", t0 + 2_000), ProtTankUpdatePlan::Now);
        coalescer.fire("t", t0 + 10_000);
        assert_eq!(
            coalescer.admit("t", t0 + 10_500),
            ProtTankUpdatePlan::Trailing { at_ms: t0 + 20_000 }
        );
        coalescer.fire("t", t0 + 20_000);
        assert_eq!(coalescer.admit("t", t0 + 30_000), ProtTankUpdatePlan::Now);
        // A stage change published outside the coalescer opens a window too
        coalescer.note_published("v", t0);
        assert_eq!(
            coalescer.admit("v", t0 + 1),
            ProtTankUpdatePlan::Trailing { at_ms: t0 + 10_000 }
        );

        // A contribution every 250 ms for a minute
        let start = 5_000_000;
        let mut publishes: Vec<i64> = Vec::new();
        let mut trailing: Option<i64> = None;
        for step in 0..240 {
            let now = start + step * 250;
            if let Some(at_ms) = trailing.filter(|at_ms| *at_ms <= now) {
                coalescer.fire("burst", at_ms);
                publishes.push(at_ms);
                trailing = None;
            }
            match coalescer.admit("burst", now) {
                ProtTankUpdatePlan::Now => publishes.push(now),
                ProtTankUpdatePlan::Trailing { at_ms } => trailing = Some(at_ms),
                ProtTankUpdatePlan::Absorbed => {}
            }
        }
        assert_eq!(publishes.len(), 6, "{publishes:?}");
        assert!(
            publishes.windows(2).all(|pair| pair[1] - pair[0] >= 10_000),
            "{publishes:?}"
        );
    }

    /// 12.3: the pinned texts, no server or channel name, no amount; the
    /// Final's day count is the config's (NIT 26). End to end, the clock
    /// pushes only these.
    #[tokio::test]
    async fn prot_push_text_has_no_names_or_amounts() {
        let defaults = rules();
        assert_eq!(PROT_PUSH_TITLE, "Protected channel");
        let expected = [
            (
                ProtNoticeKind::Warn(7),
                "A Protected channel you're in needs Prot to stay active.",
            ),
            (
                ProtNoticeKind::Grace,
                "A Protected channel you're in has run out of Prot. New members can't be added \
                 until it's topped up.",
            ),
            (
                ProtNoticeKind::Freeze,
                "A Protected channel you're in is frozen. Messages can't be sent until it's \
                 topped up.",
            ),
            (
                ProtNoticeKind::Final,
                "A frozen Protected channel you're in may be deleted from Sloga's servers in 10 \
                 days unless it's topped up.",
            ),
            (
                ProtNoticeKind::Deleted,
                "A Protected channel you were in was deleted from Sloga's servers because it ran \
                 out of Prot.",
            ),
        ];
        for (kind, text) in expected {
            let body = prot_push_body(kind, &defaults);
            assert_eq!(body, text, "{kind:?}");
            let digits: String = body.chars().filter(char::is_ascii_digit).collect();
            let allowed = if kind == ProtNoticeKind::Final {
                "10"
            } else {
                ""
            };
            assert_eq!(digits, allowed, "{kind:?}");
        }
        let custom = ProtTankRules {
            final_warning_day: 18,
            ..rules()
        };
        assert!(final_text(&custom).contains(" in 12 days "));

        let db = test_db().await;
        let w = world(&db).await;
        let launched = active_tank(&db, &w, &defaults, at(0, 0)).await;
        let rec = Recorder::default();
        // Day 25 billed: 160 left, 4 days: the 7-day warning
        run_clock(&db, &rec, &defaults, at(25, 1)).await;
        assert_eq!(rec.take_bodies(), vec![PROT_PUSH_WARN.to_string()]);
        assert!(rec.take_emails().is_empty(), "no email for a warning");
        run_clock(&db, &rec, &defaults, at(61, 1)).await;
        run_clock(&db, &rec, &defaults, at(71, 1)).await;
        assert_eq!(
            tank(&db, &launched.id).await.stage,
            v0::ProtTankStage::Deleted
        );
        let bodies = rec.take_bodies();
        assert_eq!(
            bodies,
            vec![final_text(&defaults), PROT_PUSH_DELETED.to_string()]
        );
        for body in &bodies {
            for secret in [SERVER_NAME, CHANNEL_NAME, "1160", "1,160", "200", "40"] {
                assert!(!body.contains(secret), "{body:?} carries {secret:?}");
            }
        }
        drop_db(&db).await;
    }

    // -----------------------------------------------------------------------
    // 7.1 / 7.5 deletion guards (N1)
    // -----------------------------------------------------------------------

    /// 7.5: a single tick after a long outage bills the whole history, but
    /// never deletes in it: the Final is recorded in that tick and the
    /// deletion waits `final_notice_days` from then. Control: drop the
    /// `final_warning_at` check (`if !warned`) in `expiry_check`, the guard
    /// `frozen_pass` decides with -> the first tick deletes.
    #[tokio::test]
    async fn catch_up_never_deletes_without_warning() {
        let db = test_db().await;
        let rules = rules();
        let w = world(&db).await;
        let launched = active_tank(&db, &w, &rules, at(0, 0)).await;
        assert_eq!(
            balance_of(&db, &prot_tank_account(&launched.id)).await,
            1_160
        );
        let rec = Recorder::default();

        // 61 days without a tick: days 1-29 burn the tank to 0, day 30 is
        // the first it cannot pay (Grace), day 35 freezes it, and the
        // deadline (day 60) is behind
        run_clock(&db, &rec, &rules, at(61, 1)).await;
        let frozen = tank(&db, &launched.id).await;
        assert_eq!(frozen.stage, v0::ProtTankStage::Frozen);
        assert_eq!(frozen.exhausted_at, Some(at(30, 0)));
        assert_eq!(frozen.final_warning_at, Some(at(61, 1)));
        assert_eq!(
            balance_of(&db, &prot_tank_account(&launched.id)).await,
            -200
        );
        assert_eq!(
            entitlement_state(&db, &w.channel).await,
            Some(ChannelEntitlementState::Frozen)
        );
        // Catch-up suppression: only the most severe notice goes out
        assert_eq!(rec.take_bodies(), vec![final_text(&rules)]);
        assert_eq!(
            rec.take_emails(),
            vec![(w.owner.id.clone(), ProtNoticeKind::Final, Some(at(71, 1)))]
        );

        run_clock(&db, &rec, &rules, at(71, 0)).await;
        assert_eq!(
            tank(&db, &launched.id).await.stage,
            v0::ProtTankStage::Frozen
        );
        assert!(rec.take_bodies().is_empty());

        run_clock(&db, &rec, &rules, at(71, 1)).await;
        let deleted = tank(&db, &launched.id).await;
        assert_eq!(deleted.stage, v0::ProtTankStage::Deleted);
        assert_eq!(deleted.settle_cause, Some(ProtSettleCause::Expiry));
        assert_eq!(rec.take_bodies(), vec![PROT_PUSH_DELETED.to_string()]);
        drop_db(&db).await;
    }

    /// 7.5: no deletion (and no Final, no date promised) while deletion is
    /// off; switched on, the Final comes first and the deletion exactly
    /// `final_notice_days` later: settled (the grace debt written off),
    /// entitlement tombstone, content purged, `channel.protected` kept
    #[tokio::test]
    async fn deletion_needs_deletion_enabled_and_a_final_warning_ten_days_earlier() {
        let db = test_db().await;
        let on = rules();
        let off = ProtTankRules {
            deletion_enabled: false,
            ..rules()
        };
        let w = world(&db).await;
        let launched = active_tank(&db, &w, &on, at(0, 0)).await;
        let message = ciphertext_message(&db, &w.channel, &w.owner.id).await;
        let rec = Recorder::default();

        run_clock(&db, &rec, &off, at(61, 1)).await;
        let frozen = tank(&db, &launched.id).await;
        assert_eq!(frozen.stage, v0::ProtTankStage::Frozen);
        assert_eq!(frozen.final_warning_at, None);
        assert_eq!(rec.take_bodies(), vec![PROT_PUSH_FREEZE.to_string()]);
        // No deletion date while deletion is off (NIT 32)
        assert_eq!(
            rec.take_emails(),
            vec![(w.owner.id.clone(), ProtNoticeKind::Freeze, None)]
        );

        run_clock(&db, &rec, &off, at(90, 0)).await;
        assert_eq!(
            tank(&db, &launched.id).await.stage,
            v0::ProtTankStage::Frozen
        );
        assert!(rec.take_bodies().is_empty());

        // Deletion on: the Final first (the deletion pass runs before the
        // notices, so this tick only warns)
        run_clock(&db, &rec, &on, at(90, 1)).await;
        let warned = tank(&db, &launched.id).await;
        assert_eq!(warned.stage, v0::ProtTankStage::Frozen);
        assert_eq!(warned.final_warning_at, Some(at(90, 1)));
        assert_eq!(rec.take_bodies(), vec![final_text(&on)]);
        rec.take_emails();

        run_clock(&db, &rec, &on, at(100, 0)).await;
        assert_eq!(
            tank(&db, &launched.id).await.stage,
            v0::ProtTankStage::Frozen
        );
        assert!(message_exists(&db, &message).await);

        run_clock(&db, &rec, &on, at(100, 1)).await;
        let deleted = tank(&db, &launched.id).await;
        assert_eq!(deleted.stage, v0::ProtTankStage::Deleted);
        assert_eq!(deleted.settle_cause, Some(ProtSettleCause::Expiry));
        assert_eq!(deleted.purge_passes, 1);
        assert_eq!(
            entitlement_state(&db, &w.channel).await,
            Some(ChannelEntitlementState::Deleted)
        );
        assert!(still_protected(&db, &w.channel).await);
        assert!(!message_exists(&db, &message).await);
        let writeoff = row(&db, &prot_key_writeoff(&launched.id))
            .await
            .expect("the grace debt is written off");
        assert_eq!(writeoff.amount, 200);
        assert_eq!(balance_of(&db, &prot_tank_account(&launched.id)).await, 0);
        assert_eq!(rec.take_bodies(), vec![PROT_PUSH_DELETED.to_string()]);
        assert_eq!(
            rec.take_emails(),
            vec![(
                w.owner.id.clone(),
                ProtNoticeKind::Deleted,
                Some(at(100, 1))
            )]
        );

        // The second purge pass an hour later; then the tank is never read
        // again
        run_clock(&db, &rec, &on, at(100, 3)).await;
        assert_eq!(tank(&db, &launched.id).await.purge_passes, 2);
        assert!(db
            .fetch_prot_tanks_to_purge(None, 10)
            .await
            .unwrap()
            .is_empty());
        drop_db(&db).await;
    }

    /// N1: while burning is off the clock records the pause and nothing
    /// else: a Frozen tank past its deadline with a Final ten days old is not
    /// deleted, and a Frozen tank whose Final falls due gets no Final row and
    /// no `final_warning_at`. After the resume, an unshifted tank is neither
    /// deleted nor warned until its shift commits, and then only by the
    /// shifted dates. Control: run `frozen_pass` regardless of
    /// `rules.burning` in `run_clock` -> the paused tick deletes P.
    #[tokio::test]
    async fn a_pause_never_deletes_or_sends_final() {
        let db = test_db().await;
        let on = rules();
        let paused_rules = ProtTankRules {
            burning: false,
            ..rules()
        };
        let p_world = world(&db).await;
        let q_world = world(&db).await;
        // P: Grace from day 30, Frozen from day 35, Final due on day 50.
        // Q: launched on day 10: Grace from day 40, Frozen from day 45,
        // Final due on day 60, deadline day 70.
        let p = active_tank(&db, &p_world, &on, at(0, 0)).await;
        let q = active_tank(&db, &q_world, &on, at(10, 0)).await;
        let rec = Recorder::default();

        run_clock(&db, &rec, &on, at(55, 0)).await;
        let p_frozen = tank(&db, &p.id).await;
        assert_eq!(p_frozen.stage, v0::ProtTankStage::Frozen);
        assert_eq!(p_frozen.final_warning_at, Some(at(55, 0)));
        let q_frozen = tank(&db, &q.id).await;
        assert_eq!(q_frozen.stage, v0::ProtTankStage::Frozen);
        assert_eq!(q_frozen.exhausted_at, Some(at(40, 0)));
        assert_eq!(q_frozen.final_warning_at, None);
        rec.take_bodies();
        rec.take_emails();

        // Burning off. P is past its deadline (day 60) and its Final + 10
        // days (day 65); Q's Final is due (day 60)
        run_clock(&db, &rec, &paused_rules, at(66, 0)).await;
        run_clock(&db, &rec, &paused_rules, at(75, 0)).await;
        assert_eq!(tank(&db, &p.id).await.stage, v0::ProtTankStage::Frozen);
        assert_eq!(tank(&db, &q.id).await.final_warning_at, None);
        assert!(rec.take_bodies().is_empty());
        assert!(rec.take_emails().is_empty());
        let runtime = db.fetch_prot_runtime().await.unwrap().expect("runtime");
        assert_eq!(runtime.burn_paused_at, Some(at(66, 0)));

        // Burning back on, but neither tank shifted yet: the deadline and
        // notice passes skip them
        let paused = Some(at(66, 0));
        frozen_pass(&db, &rec, paused, &on, at(80, 0)).await;
        notice_pass(&db, &rec, paused, &on, at(80, 0)).await;
        assert_eq!(tank(&db, &p.id).await.stage, v0::ProtTankStage::Frozen);
        assert_eq!(tank(&db, &q.id).await.final_warning_at, None);
        assert!(rec.take_bodies().is_empty());

        // The resume tick shifts every clock by the 14 paused days. P was
        // already deletable when the pause began, so it still is; Q's
        // Final is now due on day 74 and its deadline is day 84.
        run_clock(&db, &rec, &on, at(80, 0)).await;
        let p_deleted = tank(&db, &p.id).await;
        assert_eq!(p_deleted.stage, v0::ProtTankStage::Deleted);
        assert_eq!(p_deleted.exhausted_at, Some(at(44, 0)));
        assert_eq!(p_deleted.final_warning_at, Some(at(69, 0)));
        let q_warned = tank(&db, &q.id).await;
        assert_eq!(q_warned.stage, v0::ProtTankStage::Frozen);
        assert_eq!(q_warned.exhausted_at, Some(at(54, 0)));
        assert_eq!(q_warned.final_warning_at, Some(at(80, 0)));
        let runtime = db.fetch_prot_runtime().await.unwrap().expect("runtime");
        assert_eq!(runtime.burn_paused_at, None);

        run_clock(&db, &rec, &on, at(89, 23)).await;
        assert_eq!(tank(&db, &q.id).await.stage, v0::ProtTankStage::Frozen);
        run_clock(&db, &rec, &on, at(90, 0)).await;
        assert_eq!(tank(&db, &q.id).await.stage, v0::ProtTankStage::Deleted);
        drop_db(&db).await;
    }

    /// 7.1 step 4: an expiry that died after its begin is finished by the
    /// clock once it has been untouched for an hour
    #[tokio::test]
    async fn clock_resumes_an_expiry_crashed_between_begin_and_settle() {
        let db = test_db().await;
        let rules = rules();
        let w = world(&db).await;
        let launched = active_tank(&db, &w, &rules, at(0, 0)).await;
        let rec = Recorder::default();
        run_clock(&db, &rec, &rules, at(40, 1)).await;
        assert_eq!(
            tank(&db, &launched.id).await.stage,
            v0::ProtTankStage::Frozen
        );
        rec.take_bodies();

        db.begin_prot_settlement(&launched.id, ProtSettleCause::Expiry, at(70, 0))
            .await
            .unwrap()
            .expect("begun");
        run_clock(&db, &rec, &rules, at(70, 0) + 30 * 60_000).await;
        assert_eq!(
            tank(&db, &launched.id).await.stage,
            v0::ProtTankStage::Settling
        );

        run_clock(&db, &rec, &rules, at(70, 2)).await;
        let deleted = tank(&db, &launched.id).await;
        assert_eq!(deleted.stage, v0::ProtTankStage::Deleted);
        assert_eq!(deleted.purge_passes, 1);
        assert_eq!(
            entitlement_state(&db, &w.channel).await,
            Some(ChannelEntitlementState::Deleted)
        );
        assert_eq!(rec.take_bodies(), vec![PROT_PUSH_DELETED.to_string()]);
        drop_db(&db).await;
    }

    /// 7.1 step 7: an expiry that died after its settlement is purged by
    /// the next tick, which also sends the Deleted notice it never sent
    #[tokio::test]
    async fn clock_resumes_an_expiry_crashed_between_settle_and_purge() {
        let db = test_db().await;
        let rules = rules();
        let w = world(&db).await;
        let launched = active_tank(&db, &w, &rules, at(0, 0)).await;
        let message = ciphertext_message(&db, &w.channel, &w.owner.id).await;
        let rec = Recorder::default();
        run_clock(&db, &rec, &rules, at(40, 1)).await;
        rec.take_bodies();

        db.begin_prot_settlement(&launched.id, ProtSettleCause::Expiry, at(70, 0))
            .await
            .unwrap()
            .expect("begun");
        db.settle_prot_tank(&launched.id, at(70, 0)).await.unwrap();
        assert!(message_exists(&db, &message).await);

        run_clock(&db, &rec, &rules, at(70, 1)).await;
        let purged = tank(&db, &launched.id).await;
        assert_eq!(purged.purge_passes, 1);
        assert!(!message_exists(&db, &message).await);
        assert!(still_protected(&db, &w.channel).await);
        assert_eq!(rec.take_bodies(), vec![PROT_PUSH_DELETED.to_string()]);

        // Never twice
        run_clock(&db, &rec, &rules, at(70, 2)).await;
        assert!(rec.take_bodies().is_empty());
        drop_db(&db).await;
    }

    /// Contracts 26: an owner delete erases the entitlement (or the whole
    /// channel), so there is no tombstone to purge behind; step 7 counts the
    /// passes without a purge instead of retrying the tank every tick
    #[tokio::test]
    async fn owner_delete_tank_is_marked_purged_without_a_tombstone() {
        let db = test_db().await;
        let rules = rules();
        let kept = world(&db).await;
        let gone = world(&db).await;
        let kept_tank = active_tank(&db, &kept, &rules, at(0, 0)).await;
        let gone_tank = active_tank(&db, &gone, &rules, at(0, 0)).await;

        // `Channel::delete`: settlement, then the protected cascade; one
        // channel document stays (a delete that stopped after the cascade)
        for w in [&kept, &gone] {
            revolt_database::prot_settle_channel_on_delete(&db, &w.channel)
                .await
                .expect("settled");
            db.delete_protected_channel_data(&w.channel)
                .await
                .expect("cascade");
        }
        let channel = db.fetch_channel(&gone.channel).await.unwrap();
        db.delete_channel(&channel).await.expect("channel deleted");
        for id in [&kept_tank.id, &gone_tank.id] {
            let settled = tank(&db, id).await;
            assert_eq!(settled.stage, v0::ProtTankStage::Deleted);
            assert_eq!(settled.settle_cause, Some(ProtSettleCause::OwnerDelete));
            assert_eq!(settled.purge_passes, 0);
        }

        let now = revolt_database::now_ms();
        let rec = Recorder::default();
        run_clock(&db, &rec, &rules, now).await;
        for id in [&kept_tank.id, &gone_tank.id] {
            assert_eq!(tank(&db, id).await.purge_passes, 1);
        }
        run_clock(&db, &rec, &rules, now + 2 * HOUR_MS).await;
        for id in [&kept_tank.id, &gone_tank.id] {
            assert_eq!(tank(&db, id).await.purge_passes, 2);
        }
        assert!(db
            .fetch_prot_tanks_to_purge(None, 10)
            .await
            .unwrap()
            .is_empty());
        // An owner delete never gets the "ran out of Prot" notice
        assert!(rec.take_bodies().is_empty());
        drop_db(&db).await;
    }

    /// 9.5 / 7.1 step 7: a termination that crashed after its first
    /// transaction (goals left open, nothing purged) is finished by the
    /// clock: held pledges go back, the content is purged twice
    #[tokio::test]
    async fn termination_resumes_after_a_crash_after_its_first_transaction() {
        let db = test_db().await;
        let rules = rules();
        let w = world(&db).await;
        let launched = active_tank(&db, &w, &rules, at(0, 0)).await;
        let message = ciphertext_message(&db, &w.channel, &w.owner.id).await;

        // The driver's termination without the engine's purge
        let terminated = db
            .terminate_prot_tank(&launched.id, ADMIN, "abuse", at(0, 2))
            .await
            .expect("terminated");
        assert_eq!(terminated.tank.stage, v0::ProtTankStage::Terminated);
        assert_eq!(terminated.tank.purge_passes, 0);
        let forfeit = row(&db, &prot_key_forfeit_tank(&launched.id))
            .await
            .expect("the balance is forfeited");
        assert_eq!(forfeit.amount, 1_160);
        // A goal the crash left open, holding the backer's Prot
        let goal = db
            .create_prot_goal(&ProtGoal {
                id: Ulid::new().to_string(),
                kind: v0::ProtGoalKind::Upgrade,
                server_id: w.server.clone(),
                channel_id: Some(w.channel.clone()),
                tank_id: Some(launched.id.clone()),
                created_by: w.owner.id.clone(),
                create_nonce: Ulid::new().to_string(),
                slots: 25,
                days: None,
                daily_cost: 90,
                base_daily_cost: Some(40),
                target_prot: 1_450,
                pledged_total: 0,
                state: v0::ProtGoalState::Funding,
                deadline_at: at(30, 0),
                funded_at: None,
                launch_deadline_at: None,
                launched_at: None,
                closed_at: None,
                refund7_done: false,
                open_key: Some(format!("upgrade:{}", launched.id)),
                version: 0,
                created_at: at(0, 2),
                updated_at: at(0, 2),
            })
            .await
            .expect("goal");
        fund(&db, &w.backer.id, 300, at(0, 2)).await;
        db.pledge_prot(&ProtPledgeInput {
            user_id: w.backer.id.clone(),
            goal_id: goal.id.clone(),
            amount: 300,
            nonce: Ulid::new().to_string(),
            rules: rules.clone(),
            now: at(0, 2),
        })
        .await
        .expect("pledge");
        assert_eq!(balance_of(&db, &prot_user_account(&w.backer.id)).await, 0);

        let rec = Recorder::default();
        run_clock(&db, &rec, &rules, at(0, 3)).await;
        assert_eq!(
            db.fetch_prot_goal(&goal.id).await.unwrap().unwrap().state,
            v0::ProtGoalState::Cancelled
        );
        assert_eq!(balance_of(&db, &prot_user_account(&w.backer.id)).await, 300);
        assert!(!message_exists(&db, &message).await);
        assert_eq!(tank(&db, &launched.id).await.purge_passes, 1);
        assert!(still_protected(&db, &w.channel).await);

        run_clock(&db, &rec, &rules, at(0, 5)).await;
        assert_eq!(tank(&db, &launched.id).await.purge_passes, 2);
        assert!(rec.take_bodies().is_empty());
        drop_db(&db).await;
    }

    // -----------------------------------------------------------------------
    // 8.0 self-serve, 8.1 eligibility
    // -----------------------------------------------------------------------

    /// 8.0 (N2): with self-serve off, goal create (both kinds), launch,
    /// cancel and tier changes answer `ProtDisabled` and write nothing, for
    /// an owner and a privileged owner alike; pledges and contributions into
    /// what exists still work. Control: drop the self-serve check in
    /// `create_prot_launch_goal` -> the open second goal answers
    /// `ProtGoalClosed` instead.
    #[tokio::test]
    async fn goal_and_tier_writes_refused_while_self_serve_is_off() {
        let db = test_db().await;
        let on = rules();
        let off = ProtTankRules {
            self_serve: false,
            ..rules()
        };
        for privileged in [false, true] {
            let owner = person(&db, |user| user.privileged = privileged).await;
            let w = world_owned_by(&db, owner).await;
            let launched = active_tank(&db, &w, &on, at(0, 0)).await;
            let upgrade = create_prot_upgrade_goal(
                &db,
                &w.owner,
                &w.channel,
                v0::DataProtUpgradeGoal {
                    slots: 25,
                    nonce: Ulid::new().to_string(),
                },
                &on,
                at(0, 1),
            )
            .await
            .expect("upgrade goal");
            assert_eq!(upgrade.target_prot, 1_450);
            let second = create_prot_launch_goal(
                &db,
                &w.owner,
                &w.server,
                v0::DataProtLaunchGoal {
                    slots: 10,
                    days: 30,
                    nonce: Ulid::new().to_string(),
                },
                &on,
                at(0, 1),
            )
            .await
            .expect("second launch goal");
            fund(&db, &w.backer.id, 1_200, at(0, 1)).await;
            pledge_prot(
                &db,
                &w.backer,
                &second.id,
                contribution(1_200),
                &on,
                at(0, 1),
            )
            .await
            .expect("pledge");
            let other_channel = add_channel(&db, &w.server).await;

            let tank_before = tank(&db, &launched.id).await;
            let goals_before = db.fetch_open_prot_goals_by_server(&w.server).await.unwrap();
            let now = at(0, 2);

            let refusals = [
                error_type(
                    create_prot_launch_goal(
                        &db,
                        &w.owner,
                        &w.server,
                        v0::DataProtLaunchGoal {
                            slots: 10,
                            days: 30,
                            nonce: Ulid::new().to_string(),
                        },
                        &off,
                        now,
                    )
                    .await,
                ),
                error_type(
                    create_prot_upgrade_goal(
                        &db,
                        &w.owner,
                        &w.channel,
                        v0::DataProtUpgradeGoal {
                            slots: 50,
                            nonce: Ulid::new().to_string(),
                        },
                        &off,
                        now,
                    )
                    .await,
                ),
                error_type(
                    launch_prot_goal(
                        &db,
                        &w.owner,
                        &second.id,
                        v0::DataProtGoalLaunch {
                            channel_id: other_channel.clone(),
                        },
                        &off,
                        now,
                    )
                    .await,
                ),
                error_type(cancel_prot_goal(&db, &w.owner, &second.id, &off, now).await),
                error_type(cancel_prot_goal(&db, &w.owner, &upgrade.id, &off, now).await),
                error_type(
                    change_prot_tier(
                        &db,
                        &w.owner,
                        &w.channel,
                        v0::DataProtTier {
                            slots: 25,
                            nonce: Ulid::new().to_string(),
                        },
                        &off,
                        now,
                    )
                    .await,
                ),
            ];
            for (index, refusal) in refusals.iter().enumerate() {
                assert!(
                    matches!(refusal, ErrorType::ProtDisabled),
                    "privileged={privileged} write {index}: {refusal:?}"
                );
            }
            assert_eq!(tank(&db, &launched.id).await, tank_before);
            assert_eq!(
                db.fetch_open_prot_goals_by_server(&w.server).await.unwrap(),
                goals_before
            );
            assert!(db
                .fetch_prot_tank_by_channel(&other_channel)
                .await
                .unwrap()
                .is_none());

            // The clock and the sweep keep running, and so does funding
            // what already exists
            fund(&db, &w.backer.id, 500, now).await;
            let pledged = pledge_prot(&db, &w.backer, &upgrade.id, contribution(100), &off, now)
                .await
                .expect("pledge with self-serve off");
            assert_eq!(pledged.goal.pledged_total, 100);
            let topped = contribute_prot(&db, &w.backer, &w.channel, contribution(100), &off, now)
                .await
                .expect("contribution with self-serve off");
            assert_eq!(topped.tank.balance, 1_260);
        }
        drop_db(&db).await;
    }

    /// 8.1 (D6): bots, non-members, staff without a member row, timed-out,
    /// suspended and banned accounts are not eligible; below the minimum is
    /// refused before the driver (N-6); nothing is written
    #[tokio::test]
    async fn eligibility_refusals() {
        let db = test_db().await;
        let rules = rules();
        let w = world(&db).await;
        let launched = active_tank(&db, &w, &rules, at(0, 0)).await;
        let server = db.fetch_server(&w.server).await.unwrap();
        let channel = db.fetch_channel(&w.channel).await.unwrap();
        let in_a_day = Timestamp::now_utc()
            .checked_add(TimestampDuration::days(1))
            .unwrap();

        let owner_id = w.owner.id.clone();
        let bot = person(&db, |user| {
            user.bot = Some(BotInformation { owner: owner_id })
        })
        .await;
        join(&db, &w.server, &bot.id, None).await;
        let outsider = live(&db).await;
        let staff = person(&db, |user| user.privileged = true).await;
        let timed_out = live(&db).await;
        join(&db, &w.server, &timed_out.id, Some(in_a_day)).await;
        let suspended = person(&db, |user| {
            user.flags = Some(v0::UserFlags::SuspendedUntil as i32)
        })
        .await;
        join(&db, &w.server, &suspended.id, None).await;
        let banned = person(&db, |user| user.flags = Some(v0::UserFlags::Banned as i32)).await;
        join(&db, &w.server, &banned.id, None).await;

        for (name, user) in [
            ("bot", &bot),
            ("non-member", &outsider),
            ("staff without a member row", &staff),
            ("timed out", &timed_out),
            ("suspended", &suspended),
            ("banned", &banned),
        ] {
            let refusal = error_type(prot_eligibility(&db, user, &server, Some(&channel)).await);
            assert!(
                matches!(refusal, ErrorType::ProtNotEligible),
                "{name}: {refusal:?}"
            );
            let refusal = error_type(prot_eligibility(&db, user, &server, None).await);
            assert!(
                matches!(refusal, ErrorType::ProtNotEligible),
                "{name}: {refusal:?}"
            );
        }
        prot_eligibility(&db, &w.backer, &server, Some(&channel))
            .await
            .expect("a member who sees the channel");

        // The route answers: a bot is a bot, a non-viewer sees nothing
        let now = at(0, 2);
        for user in [&bot, &outsider, &staff, &timed_out, &suspended] {
            fund(&db, &user.id, 500, now).await;
        }
        assert!(matches!(
            error_type(
                contribute_prot(&db, &bot, &w.channel, contribution(100), &rules, now).await
            ),
            ErrorType::IsBot
        ));
        for user in [&outsider, &staff] {
            assert!(matches!(
                error_type(
                    contribute_prot(&db, user, &w.channel, contribution(100), &rules, now).await
                ),
                ErrorType::NotFound
            ));
        }
        // Both still see the channel (a timeout keeps ViewChannel,
        // ALLOW_IN_TIMEOUT): the refusal is the eligibility one
        for user in [&timed_out, &suspended] {
            assert!(matches!(
                error_type(
                    contribute_prot(&db, user, &w.channel, contribution(100), &rules, now).await
                ),
                ErrorType::ProtNotEligible
            ));
        }
        // < 50 (and > the maximum, and non-positive) never reach the driver
        fund(&db, &w.backer.id, 49, now).await;
        for amount in [49, 0, -5, PROT_MAX_AMOUNT + 1] {
            assert!(matches!(
                error_type(
                    contribute_prot(
                        &db,
                        &w.backer,
                        &w.channel,
                        contribution(amount),
                        &rules,
                        now
                    )
                    .await
                ),
                ErrorType::FailedValidation { .. }
            ));
        }
        for user in [&bot, &outsider, &staff, &timed_out, &suspended] {
            assert_eq!(balance_of(&db, &prot_user_account(&user.id)).await, 500);
        }
        assert_eq!(balance_of(&db, &prot_user_account(&w.backer.id)).await, 49);
        assert_eq!(
            balance_of(&db, &prot_tank_account(&launched.id)).await,
            1_160
        );
        drop_db(&db).await;
    }

    // -----------------------------------------------------------------------
    // 8.8 contributions
    // -----------------------------------------------------------------------

    /// D17 (BR8): Prot bought within the hold window cannot go into a tank;
    /// the refusal is `ProtHeldPurchase` while the wallet covers the amount
    /// and `InsufficientProt` when it does not. Control: answer the driver's
    /// `InsufficientProt` as is -> the first assertion fails.
    #[tokio::test]
    async fn held_purchase_cannot_be_contributed() {
        let db = test_db().await;
        let rules = rules();
        let w = world(&db).await;
        let launched = active_tank(&db, &w, &rules, at(0, 0)).await;
        let buyer = &w.backer;
        let account = prot_tank_account(&launched.id);

        buy(&db, &buyer.id, 500, at(0, 1)).await;
        assert!(matches!(
            error_type(
                contribute_prot(&db, buyer, &w.channel, contribution(100), &rules, at(0, 2)).await
            ),
            ErrorType::ProtHeldPurchase
        ));
        assert_eq!(balance_of(&db, &prot_user_account(&buyer.id)).await, 500);
        assert_eq!(balance_of(&db, &account).await, 1_160);

        // 300 unheld beside the 500 held: up to 300 goes in
        fund(&db, &buyer.id, 300, at(0, 2)).await;
        assert!(matches!(
            error_type(
                contribute_prot(&db, buyer, &w.channel, contribution(400), &rules, at(0, 3)).await
            ),
            ErrorType::ProtHeldPurchase
        ));
        contribute_prot(&db, buyer, &w.channel, contribution(300), &rules, at(0, 3))
            .await
            .expect("the unheld part");
        assert_eq!(balance_of(&db, &account).await, 1_460);

        // Short of the amount altogether: not a hold
        let poor = live(&db).await;
        join(&db, &w.server, &poor.id, None).await;
        fund(&db, &poor.id, 30, at(0, 3)).await;
        assert!(matches!(
            error_type(
                contribute_prot(&db, &poor, &w.channel, contribution(100), &rules, at(0, 4)).await
            ),
            ErrorType::InsufficientProt { .. }
        ));

        // After the 72-hour hold the purchase is spendable (the tank is
        // caught up first: days 1-3)
        let response = contribute_prot(&db, buyer, &w.channel, contribution(100), &rules, at(3, 2))
            .await
            .expect("after the hold");
        assert!(!response.already_applied);
        assert_eq!(response.balance, 400);
        assert_eq!(response.notice, PROT_SEAT_NOTICE);
        assert_eq!(balance_of(&db, &account).await, 1_460 - 120 + 100);
        drop_db(&db).await;
    }

    /// 8.8 (audit 10): a top-up the morning after days the clock never
    /// billed bills them first, so the stale check never refuses it
    #[tokio::test]
    async fn top_up_after_midnight_catches_the_tank_up_first() {
        let db = test_db().await;
        let rules = rules();
        let w = world(&db).await;
        let launched = active_tank(&db, &w, &rules, at(0, 0)).await;
        fund(&db, &w.backer.id, 1_000, at(0, 1)).await;

        let response = contribute_prot(
            &db,
            &w.backer,
            &w.channel,
            contribution(100),
            &rules,
            at(3, 5),
        )
        .await
        .expect("top-up");
        for n in 1..=3 {
            let burn = row(&db, &prot_key_burn(&launched.id, &day(n)))
                .await
                .unwrap_or_else(|| panic!("day {n} billed first"));
            assert_eq!(burn.amount, 40);
        }
        assert!(row(&db, &prot_key_burn(&launched.id, &day(4)))
            .await
            .is_none());
        assert_eq!(response.tank.balance, 1_160 - 120 + 100);
        assert_eq!(tank(&db, &launched.id).await.next_burn_day, Some(day(4)));

        // A replay is the stored outcome, never billed or applied again
        let nonce = Ulid::new().to_string();
        let first = contribute_prot(
            &db,
            &w.backer,
            &w.channel,
            v0::DataProtContribute {
                amount: 100,
                nonce: nonce.clone(),
            },
            &rules,
            at(3, 6),
        )
        .await
        .expect("top-up");
        let replay = contribute_prot(
            &db,
            &w.backer,
            &w.channel,
            v0::DataProtContribute { amount: 100, nonce },
            &rules,
            at(5, 6),
        )
        .await
        .expect("replay");
        assert!(replay.already_applied);
        assert_eq!(replay.entry_id, first.entry_id);
        assert_eq!(balance_of(&db, &prot_user_account(&w.backer.id)).await, 800);
        drop_db(&db).await;
    }

    /// N4: right after burning comes back on, before the clock has shifted
    /// a tank for the pause, a top-up is neither refused as stale nor used
    /// to bill the paused days; the shift then bills only the rest of today
    #[tokio::test]
    async fn top_up_right_after_a_resume_is_not_refused_as_stale() {
        let db = test_db().await;
        let on = rules();
        let paused_rules = ProtTankRules {
            burning: false,
            ..rules()
        };
        let w = world(&db).await;
        let launched = active_tank(&db, &w, &on, at(0, 0)).await;
        let rec = Recorder::default();
        run_clock(&db, &rec, &paused_rules, at(2, 5)).await;
        fund(&db, &w.backer.id, 1_000, at(2, 6)).await;

        contribute_prot(&db, &w.backer, &w.channel, contribution(100), &on, at(5, 3))
            .await
            .expect("not stale while waiting for the shift");
        assert_eq!(
            balance_of(&db, &prot_tank_account(&launched.id)).await,
            1_260
        );
        for n in 1..=5 {
            assert!(row(&db, &prot_key_burn(&launched.id, &day(n)))
                .await
                .is_none());
        }

        // The resume: today's remaining 20 hours, ceil(40 x 20 / 24) = 34
        run_clock(&db, &rec, &on, at(5, 4)).await;
        for n in 1..=4 {
            assert!(row(&db, &prot_key_burn(&launched.id, &day(n)))
                .await
                .is_none());
        }
        let resumed = row(&db, &prot_key_burn(&launched.id, &day(5)))
            .await
            .expect("the rest of today");
        assert_eq!(resumed.amount, 34);
        assert_eq!(tank(&db, &launched.id).await.next_burn_day, Some(day(6)));
        drop_db(&db).await;
    }

    /// 8.8 / 7.3: Active takes top-ups; Grace repays debt and reactivates at
    /// one day's cost; Frozen reactivates and pays only the rest of today; a
    /// terminated tank takes nothing (`InvalidOperation`, NIT 23)
    #[tokio::test]
    async fn top_up_in_each_stage() {
        let db = test_db().await;
        let rules = rules();
        let w = world(&db).await;
        let launched = active_tank(&db, &w, &rules, at(0, 0)).await;
        let account = prot_tank_account(&launched.id);
        let rec = Recorder::default();
        fund(&db, &w.backer.id, 2_000, at(0, 1)).await;

        let active = contribute_prot(
            &db,
            &w.backer,
            &w.channel,
            contribution(50),
            &rules,
            at(0, 2),
        )
        .await
        .expect("Active");
        assert_eq!(active.tank.stage, v0::ProtTankStage::Active);
        assert_eq!(active.tank.balance, 1_210);

        // 1,210 pays days 1-30 (10 left); day 31 cannot be paid: Grace, -30
        run_clock(&db, &rec, &rules, at(31, 1)).await;
        let grace = tank(&db, &launched.id).await;
        assert_eq!(grace.stage, v0::ProtTankStage::Grace);
        assert_eq!(balance_of(&db, &account).await, -30);

        // -30 + 50 = 20 < 40: debt repaid, still Grace
        let partial = contribute_prot(
            &db,
            &w.backer,
            &w.channel,
            contribution(50),
            &rules,
            at(31, 2),
        )
        .await
        .expect("Grace");
        assert_eq!(partial.tank.stage, v0::ProtTankStage::Grace);
        assert_eq!(partial.tank.balance, 20);
        // 20 + 50 = 70 >= 40: Active, nothing billed for today again
        let reactivated = contribute_prot(
            &db,
            &w.backer,
            &w.channel,
            contribution(50),
            &rules,
            at(31, 3),
        )
        .await
        .expect("Grace -> Active");
        assert_eq!(reactivated.tank.stage, v0::ProtTankStage::Active);
        assert_eq!(reactivated.tank.balance, 70);
        assert_eq!(
            entitlement_state(&db, &w.channel).await,
            Some(ChannelEntitlementState::Active)
        );

        // Day 32 burns to 30, day 33 enters Grace (-10), days 34-37 reach
        // -170, day 38 freezes
        run_clock(&db, &rec, &rules, at(38, 1)).await;
        assert_eq!(
            tank(&db, &launched.id).await.stage,
            v0::ProtTankStage::Frozen
        );
        assert_eq!(balance_of(&db, &account).await, -170);

        // -170 + 300 = 130: Active, then the 12 hours left today: 20
        let thawed = contribute_prot(
            &db,
            &w.backer,
            &w.channel,
            contribution(300),
            &rules,
            at(38, 12),
        )
        .await
        .expect("Frozen -> Active");
        assert_eq!(thawed.tank.stage, v0::ProtTankStage::Active);
        assert_eq!(thawed.tank.balance, 110);
        assert_eq!(
            row(&db, &prot_key_burn(&launched.id, &day(38)))
                .await
                .expect("today's pro rata")
                .amount,
            20
        );
        assert_eq!(tank(&db, &launched.id).await.next_burn_day, Some(day(39)));

        terminate_prot_tank(&db, ADMIN, &launched.id, "abuse", at(38, 13))
            .await
            .expect("terminated");
        assert!(matches!(
            error_type(
                contribute_prot(
                    &db,
                    &w.backer,
                    &w.channel,
                    contribution(50),
                    &rules,
                    at(38, 14)
                )
                .await
            ),
            ErrorType::InvalidOperation
        ));
        drop_db(&db).await;
    }

    /// W5 audit 1: a tier upgrade (manual, or an upgrade goal applied by its
    /// funding pledge) between 00:00 UTC and the clock's first tick bills
    /// today at the OLD price first and then charges only the difference for
    /// the hours left; the tick that follows bills nothing more for today.
    /// Control: drop the `catch_up_before_pricing` call in
    /// `change_prot_tier` -> day 1 is billed at 90 after a 48 charge.
    #[tokio::test]
    async fn tier_upgrade_before_the_clocks_first_tick_is_not_double_charged() {
        let db = test_db().await;
        let rules = rules();
        let rec = Recorder::default();
        // 01:00 on day 1: 23 hours left, (90 - 40) x 23 / 24 rounded up = 48
        let early = at(1, 1);

        // A manual upgrade by the owner
        let manual = world(&db).await;
        let manual_tank = active_tank(&db, &manual, &rules, at(0, 0)).await;
        let nonce = Ulid::new().to_string();
        let summary = change_prot_tier(
            &db,
            &manual.owner,
            &manual.channel,
            v0::DataProtTier {
                slots: 25,
                nonce: nonce.clone(),
            },
            &rules,
            early,
        )
        .await
        .expect("tier upgrade");
        assert_eq!(summary.slot_tier, 25);
        let day_one = row(&db, &prot_key_burn(&manual_tank.id, &day(1)))
            .await
            .expect("day 1 billed before the charge");
        assert_eq!(day_one.amount, 40);
        let charge = row(
            &db,
            &prot_key_tier(&manual_tank.id, &format!("owner-{nonce}")),
        )
        .await
        .expect("the tier charge");
        assert_eq!(charge.amount, 48);
        assert_eq!(summary.balance, 1_160 - 40 - 48);

        // An upgrade goal applied by the pledge that funds it
        let funded = world(&db).await;
        let funded_tank = active_tank(&db, &funded, &rules, at(0, 0)).await;
        let goal = create_prot_upgrade_goal(
            &db,
            &funded.owner,
            &funded.channel,
            v0::DataProtUpgradeGoal {
                slots: 25,
                nonce: Ulid::new().to_string(),
            },
            &rules,
            at(0, 1),
        )
        .await
        .expect("upgrade goal");
        assert_eq!(goal.target_prot, 1_450);
        fund(&db, &funded.backer.id, 1_450, at(0, 1)).await;
        let pledged = pledge_prot(
            &db,
            &funded.backer,
            &goal.id,
            contribution(1_450),
            &rules,
            early,
        )
        .await
        .expect("funding pledge");
        assert_eq!(pledged.goal.state, v0::ProtGoalState::Applied);
        assert_eq!(
            row(&db, &prot_key_burn(&funded_tank.id, &day(1)))
                .await
                .expect("day 1 billed before the apply")
                .amount,
            40
        );
        assert_eq!(
            row(
                &db,
                &prot_key_tier(&funded_tank.id, &format!("goal-{}", goal.id))
            )
            .await
            .expect("the apply charge")
            .amount,
            48
        );

        // The clock's first tick of the day finds day 1 billed
        run_clock(&db, &rec, &rules, at(1, 2)).await;
        assert_eq!(
            row(&db, &prot_key_burn(&manual_tank.id, &day(1)))
                .await
                .expect("day 1")
                .amount,
            40
        );
        assert_eq!(
            balance_of(&db, &prot_tank_account(&manual_tank.id)).await,
            1_072
        );
        assert_eq!(
            balance_of(&db, &prot_tank_account(&funded_tank.id)).await,
            1_160 - 40 + 1_450 - 48
        );
        for id in [&manual_tank.id, &funded_tank.id] {
            let upgraded = tank(&db, id).await;
            assert_eq!(upgraded.slot_tier, 25);
            assert_eq!(upgraded.next_burn_day, Some(day(2)));
        }
        drop_db(&db).await;
    }

    // -----------------------------------------------------------------------
    // 8.7 the upgrade goal exit
    // -----------------------------------------------------------------------

    /// 8.7: a Funded upgrade goal never Applied by its launch_deadline_at
    /// (funded_at + launch_window_days) is closed with full returns by the
    /// sweep; before that the sweep applies it. Control: drop the exit in
    /// `sweep_goal` -> the first goal is applied and the pledger pays.
    #[tokio::test]
    async fn funded_upgrade_goal_exits_after_seven_days() {
        let db = test_db().await;
        let rules = rules();
        let w = world(&db).await;
        let launched = active_tank(&db, &w, &rules, at(0, 0)).await;

        // 1,160 at 40 a day = 29 days; 10 -> 25 slots costs 50 more a day
        let mut goals = Vec::new();
        for created in [at(0, 1), at(7, 2)] {
            let goal = create_prot_upgrade_goal(
                &db,
                &w.owner,
                &w.channel,
                v0::DataProtUpgradeGoal {
                    slots: 25,
                    nonce: Ulid::new().to_string(),
                },
                &rules,
                created,
            )
            .await
            .expect("upgrade goal");
            assert_eq!(goal.target_prot, 1_450);
            fund(&db, &w.backer.id, 1_450, created).await;
            // The driver's pledge: funded, not applied (the engine's pledge
            // route would apply it at once)
            let pledged = db
                .pledge_prot(&ProtPledgeInput {
                    user_id: w.backer.id.clone(),
                    goal_id: goal.id.clone(),
                    amount: 1_450,
                    nonce: Ulid::new().to_string(),
                    rules: rules.clone(),
                    now: created,
                })
                .await
                .expect("pledge");
            assert!(pledged.funded_now);
            assert_eq!(pledged.goal.launch_deadline_at, Some(created + 7 * DAY_MS));
            goals.push(goal.id);

            if goals.len() == 1 {
                run_goals(&db, &rules, at(7, 1)).await;
                let exited = db.fetch_prot_goal(&goals[0]).await.unwrap().unwrap();
                assert_eq!(exited.state, v0::ProtGoalState::Cancelled);
                assert_eq!(
                    balance_of(&db, &prot_user_account(&w.backer.id)).await,
                    1_450
                );
                assert_eq!(tank(&db, &launched.id).await.slot_tier, 10);
            }
        }
        run_goals(&db, &rules, at(7, 3)).await;
        let applied = db.fetch_prot_goal(&goals[1]).await.unwrap().unwrap();
        assert_eq!(applied.state, v0::ProtGoalState::Applied);
        let upgraded = tank(&db, &launched.id).await;
        assert_eq!(upgraded.slot_tier, 25);
        assert_eq!(upgraded.daily_cost, 90);
        assert_eq!(
            balance_of(&db, &prot_user_account(&w.backer.id)).await,
            1_450
        );
        drop_db(&db).await;
    }
}
