//! Prot fuel tanks (S5b): stored types, driver inputs and outcomes, key
//! builders, actors, the tank rules and the pure planners (contracts section 4).
//!
//! Nothing here does I/O. Both drivers and the engine read their state, hand it
//! to a planner and write the plan, so the two drivers cannot drift apart on a
//! rule (the S1 `plan_seat_list_write` pattern).

use std::cmp::{Ordering, Reverse};
use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use revolt_models::v0;
use revolt_result::Result;

use crate::{ChannelEntitlementState, ProtAccount, ProtLedgerEntry};

// Private on purpose: the crate root already exports a `DAY_MS` (referrals),
// and a second glob export of the same name would make `crate::DAY_MS` ambiguous
const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;

auto_derived!(
    /// What a tank pays for
    #[serde(tag = "type")]
    pub enum ProtTankTarget {
        Channel { channel_id: String },
        Server { server_id: String },
    }

    /// Why a tank is being settled
    #[derive(Copy)]
    pub enum ProtSettleCause {
        OwnerDelete,
        Expiry,
        Termination,
    }

    /// `prot_tanks`
    pub struct ProtTank {
        /// ULID
        #[serde(rename = "_id")]
        pub id: String,
        pub target: ProtTankTarget,
        /// "channel:{channel_id}" ("server:{server_id}" in S10); UNIQUE
        pub target_key: String,
        pub server_id: String,
        /// Server owner who launched it (audit only; authority is always server.owner at call time)
        pub created_by: String,
        pub plan: v0::ProtPlan,
        pub slot_tier: u32,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub pending_slot_tier: Option<u32>,
        /// Snapshot at launch / last tier change; a config edit never moves a date
        pub daily_cost: i64,
        /// The cost table at the snapshot, "40/90/160/280" (audit only)
        pub rate_card: String,
        pub stage: v0::ProtTankStage,
        /// Start of the first day the balance could not pay (catch-up: that missed day)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub exhausted_at: Option<i64>,
        /// Next unbilled UTC day; None while Launching
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub next_burn_day: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub launched_at: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub final_warning_at: Option<i64>,
        #[serde(default)]
        pub warnings_epoch: u64,
        /// D16: the `burn_paused_at` this tank was already shifted for
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub pause_shift_for: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub settle_cause: Option<ProtSettleCause>,
        /// Deleted / Terminated time
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub ended_at: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub terminated_by: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub purged_at: Option<i64>,
        #[serde(default)]
        pub purge_passes: u32,
        #[serde(default)]
        pub version: u64,
        pub created_at: i64,
        pub updated_at: i64,
    }

    /// `prot_goals`
    pub struct ProtGoal {
        #[serde(rename = "_id")]
        pub id: String,
        pub kind: v0::ProtGoalKind,
        pub server_id: String,
        /// Set at launch (Launch) / creation (Upgrade)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub channel_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub tank_id: Option<String>,
        pub created_by: String,
        pub create_nonce: String,
        pub slots: u32,
        /// Launch only (>= min_launch_goal_days)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub days: Option<u32>,
        /// Launch: cost(slots); Upgrade: cost(new slots). Snapshot at creation.
        pub daily_cost: i64,
        /// Upgrade: the tank's daily_cost at creation
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub base_daily_cost: Option<i64>,
        pub target_prot: i64,
        pub pledged_total: i64,
        pub state: v0::ProtGoalState,
        pub deadline_at: i64,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub funded_at: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub launch_deadline_at: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub launched_at: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub closed_at: Option<i64>,
        #[serde(default)]
        pub refund7_done: bool,
        /// "launch:{server_id}" / "upgrade:{tank_id}" while Funding|Funded|Launching, unset after; UNIQUE partial
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub open_key: Option<String>,
        #[serde(default)]
        pub version: u64,
        pub created_at: i64,
        pub updated_at: i64,
    }

    /// `prot_pledges` (audit BLOCKER 1): every way out of a hold CASes state/remaining in the
    /// same transaction as its ledger row
    pub struct ProtPledge {
        /// ULID = pledge_id
        #[serde(rename = "_id")]
        pub id: String,
        pub goal_id: String,
        pub server_id: String,
        pub user_id: String,
        pub kind: v0::ProtGoalKind,
        pub amount: i64,
        /// Still in the hold
        pub remaining: i64,
        pub state: v0::ProtPledgeState,
        /// Moved to the tank at capture
        #[serde(default)]
        pub captured: i64,
        /// Returned by the 7-day rule (D8)
        #[serde(default)]
        pub launch_returned: i64,
        #[serde(default)]
        pub version: u64,
        pub created_at: i64,
        pub updated_at: i64,
    }

    /// `prot_notices`: dedupe of pushes and emails, `_id` = key (12.2)
    pub struct ProtNotice {
        #[serde(rename = "_id")]
        pub id: String,
        pub tank_id: String,
        pub sent_at: i64,
        /// false = recorded without sending (catch-up suppression)
        #[serde(default)]
        pub delivered: bool,
    }

    /// `prot_contributor_prefs`: `_id` = "{server_id}:{user_id}" (BR10)
    pub struct ProtContributorPref {
        #[serde(rename = "_id")]
        pub id: String,
        pub hidden: bool,
        pub updated_at: i64,
    }

    /// `prot_runtime`: singleton `_id` = "runtime" (D16)
    pub struct ProtRuntime {
        #[serde(rename = "_id")]
        pub id: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub burn_paused_at: Option<i64>,
        #[serde(default)]
        pub version: u64,
    }
);

/// `_id` of the `prot_runtime` singleton
pub const PROT_RUNTIME_ID: &str = "runtime";

/// Goal states that hold an `open_key` (and Prot in the hold)
pub const PROT_OPEN_GOAL_STATES: [v0::ProtGoalState; 3] = [
    v0::ProtGoalState::Funding,
    v0::ProtGoalState::Funded,
    v0::ProtGoalState::Launching,
];

/// Burns, stage write-offs, pause shifts
pub const PROT_ACTOR_CLOCK: &str = "sys:clock";
/// Captures, returns on expiry/abandon, launch returns, upgrade apply
pub const PROT_ACTOR_GOALS: &str = "sys:goals";
/// settle: and writeoff: on owner delete / expiry
pub const PROT_ACTOR_SETTLEMENT: &str = "sys:settlement";

/// Slot tiers a tank (and a goal) may have
pub const PROT_SLOT_TIERS: [u32; 4] = [10, 25, 50, 100];
/// Most Prot one contribution / pledge may move
pub const PROT_MAX_AMOUNT: i64 = 1_000_000;

/// Contribution / top-up
pub fn prot_key_contrib(user_id: &str, tank_id: &str, nonce: &str) -> String {
    format!("contrib:{user_id}:{tank_id}:{nonce}")
}

/// Tier upgrade pro rata; `change_id` is "owner-{nonce}" or "goal-{goal_id}"
pub fn prot_key_tier(tank_id: &str, change_id: &str) -> String {
    format!("tier:{tank_id}:{change_id}")
}

/// Pledge into a goal's hold
pub fn prot_key_pledge(user_id: &str, goal_id: &str, nonce: &str) -> String {
    format!("pledge:{user_id}:{goal_id}:{nonce}")
}

/// Hold to tank at launch / upgrade apply
pub fn prot_key_pledge_capture(pledge_id: &str) -> String {
    format!("pledge-capture:{pledge_id}")
}

/// Hold back to the pledger (expiry, cancel, abandon)
pub fn prot_key_pledge_return(pledge_id: &str) -> String {
    format!("pledge-return:{pledge_id}")
}

/// Hold back to the pledger on their own withdrawal
pub fn prot_key_pledge_withdraw(pledge_id: &str) -> String {
    format!("pledge-withdraw:{pledge_id}")
}

/// 7-day return of an unseated pledger's capture (D8)
pub fn prot_key_launch_return(pledge_id: &str) -> String {
    format!("launch-return:{pledge_id}")
}

/// One day's burn; the key is the clock's lock
pub fn prot_key_burn(tank_id: &str, day: &str) -> String {
    format!("burn:{tank_id}:{day}")
}

/// FIFO settlement share of one user
pub fn prot_key_settle(tank_id: &str, user_id: &str) -> String {
    format!("settle:{tank_id}:{user_id}")
}

/// Grace-debt write-off
pub fn prot_key_writeoff(tank_id: &str) -> String {
    format!("writeoff:{tank_id}")
}

/// A purchase reversal drained from one held pledge
pub fn prot_key_clawback_hold(order_id: &str, pledge_id: &str) -> String {
    format!("clawback-hold:{order_id}:{pledge_id}")
}

/// Account deletion: one held pledge forfeited
pub fn prot_key_forfeit_hold(pledge_id: &str) -> String {
    format!("forfeit-hold:{pledge_id}")
}

/// Abuse termination: the tank's positive balance forfeited
pub fn prot_key_forfeit_tank(tank_id: &str) -> String {
    format!("forfeit-tank:{tank_id}")
}

/// Notice dedupe key (`prot_notices._id`)
pub fn prot_notice_key(tank_id: &str, epoch: u64, kind: ProtNoticeKind) -> String {
    format!("warn:{tank_id}:{epoch}:{}", kind.key_segment())
}

/// `ProtTank.target_key` of a channel tank
pub fn prot_tank_target_key(channel_id: &str) -> String {
    format!("channel:{channel_id}")
}

/// A tank notice (12.2). Not stored: its key segment is.
///
/// Ordered by severity: Deleted > Final > Freeze > Grace > Warn(smaller n) >
/// Warn(larger n), so `max()` over the due kinds is the one to deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtNoticeKind {
    /// `n` days of Prot left, one per entry of `warn_days`
    Warn(u32),
    Grace,
    Freeze,
    Final,
    Deleted,
}

impl ProtNoticeKind {
    /// "warn{n}", "grace", "freeze", "final", "deleted"
    pub fn key_segment(&self) -> String {
        match self {
            ProtNoticeKind::Warn(n) => format!("warn{n}"),
            ProtNoticeKind::Grace => "grace".to_string(),
            ProtNoticeKind::Freeze => "freeze".to_string(),
            ProtNoticeKind::Final => "final".to_string(),
            ProtNoticeKind::Deleted => "deleted".to_string(),
        }
    }

    fn severity(&self) -> (u8, Reverse<u32>) {
        match self {
            ProtNoticeKind::Warn(n) => (0, Reverse(*n)),
            ProtNoticeKind::Grace => (1, Reverse(0)),
            ProtNoticeKind::Freeze => (2, Reverse(0)),
            ProtNoticeKind::Final => (3, Reverse(0)),
            ProtNoticeKind::Deleted => (4, Reverse(0)),
        }
    }
}

impl Ord for ProtNoticeKind {
    fn cmp(&self, other: &Self) -> Ordering {
        self.severity().cmp(&other.severity())
    }
}

impl PartialOrd for ProtNoticeKind {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The tank rules, built from `[features.boosts.protection]` and validated once
/// (4.3). Every engine function takes them as an argument and never re-reads the
/// config itself, so a test can pass any combination of switches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtTankRules {
    pub channel_daily_cost: revolt_config::ProtTierCosts,
    pub grace_days: u32,
    pub freeze_days: u32,
    pub final_warning_day: u32,
    pub warn_days: Vec<u32>,
    pub min_reactivation_days: u32,
    pub launch_goal_deadline_days: u32,
    pub launch_window_days: u32,
    pub launch_seat_window_days: u32,
    pub min_contribution: i64,
    pub min_launch_goal_days: u32,
    pub max_launch_goal_days: u32,
    pub withdraw_cutoff_hours: u32,
    pub contribute_hold_hours: u32,
    /// enabled && burn_enabled: no burn or tier row of any kind is written while false (7.0, D16)
    pub burning: bool,
    /// deletion_enabled: the Final notice, `deletes_at` and deletion copy exist only while true (12.2)
    pub deletion_enabled: bool,
    /// self_serve_enabled (8.0)
    pub self_serve: bool,
}

/// Refuse a tank config: logged once with the offending key
fn invalid_tank_config(key: &str) -> revolt_result::Error {
    log::error!("PROT_TANK_CONFIG_INVALID key={key}");
    create_error!(InternalError)
}

impl ProtTankRules {
    /// Err(InternalError) logged `PROT_TANK_CONFIG_INVALID key=..` when: a cost <= 0 or the table is not strictly
    /// increasing; grace_days < 1; freeze_days < 1; !(grace_days < final_warning_day < grace_days + freeze_days);
    /// a warn day is 0 or warn_days is not strictly decreasing; min_reactivation_days < 1; min_contribution < 1;
    /// !(1 <= min_launch_goal_days <= max_launch_goal_days <= 3650); launch windows < 1; withdraw_cutoff_hours >=
    /// launch_goal_deadline_days * 24
    pub fn from_config(p: &revolt_config::ProtectionFeatures) -> Result<Self> {
        let costs = p.channel_daily_cost;
        if costs.t10 <= 0
            || costs.t10 >= costs.t25
            || costs.t25 >= costs.t50
            || costs.t50 >= costs.t100
        {
            return Err(invalid_tank_config("channel_daily_cost"));
        }
        if p.grace_days < 1 {
            return Err(invalid_tank_config("grace_days"));
        }
        if p.freeze_days < 1 {
            return Err(invalid_tank_config("freeze_days"));
        }
        let window = u64::from(p.grace_days) + u64::from(p.freeze_days);
        if p.final_warning_day <= p.grace_days || u64::from(p.final_warning_day) >= window {
            return Err(invalid_tank_config("final_warning_day"));
        }
        if p.warn_days.contains(&0) || p.warn_days.windows(2).any(|pair| pair[0] <= pair[1]) {
            return Err(invalid_tank_config("warn_days"));
        }
        if p.min_reactivation_days < 1 {
            return Err(invalid_tank_config("min_reactivation_days"));
        }
        if p.min_contribution < 1 {
            return Err(invalid_tank_config("min_contribution"));
        }
        if p.min_launch_goal_days < 1 {
            return Err(invalid_tank_config("min_launch_goal_days"));
        }
        if p.max_launch_goal_days < p.min_launch_goal_days {
            return Err(invalid_tank_config("max_launch_goal_days"));
        }
        if p.max_launch_goal_days > 3650 {
            return Err(invalid_tank_config("max_launch_goal_days"));
        }
        if p.launch_goal_deadline_days < 1 {
            return Err(invalid_tank_config("launch_goal_deadline_days"));
        }
        if p.launch_window_days < 1 {
            return Err(invalid_tank_config("launch_window_days"));
        }
        if p.launch_seat_window_days < 1 {
            return Err(invalid_tank_config("launch_seat_window_days"));
        }
        if u64::from(p.withdraw_cutoff_hours) >= u64::from(p.launch_goal_deadline_days) * 24 {
            return Err(invalid_tank_config("withdraw_cutoff_hours"));
        }

        Ok(ProtTankRules {
            channel_daily_cost: costs,
            grace_days: p.grace_days,
            freeze_days: p.freeze_days,
            final_warning_day: p.final_warning_day,
            warn_days: p.warn_days.clone(),
            min_reactivation_days: p.min_reactivation_days,
            launch_goal_deadline_days: p.launch_goal_deadline_days,
            launch_window_days: p.launch_window_days,
            launch_seat_window_days: p.launch_seat_window_days,
            min_contribution: p.min_contribution,
            min_launch_goal_days: p.min_launch_goal_days,
            max_launch_goal_days: p.max_launch_goal_days,
            withdraw_cutoff_hours: p.withdraw_cutoff_hours,
            contribute_hold_hours: p.contribute_hold_hours,
            burning: p.enabled && p.burn_enabled,
            deletion_enabled: p.deletion_enabled,
            self_serve: p.self_serve_enabled,
        })
    }

    /// from_config(&config().await.features.boosts.protection)
    pub async fn load() -> Result<Self> {
        let config = revolt_config::config().await;
        Self::from_config(&config.features.boosts.protection)
    }

    /// Channel table; None unless slots in PROT_SLOT_TIERS
    pub fn daily_cost(&self, slots: u32) -> Option<i64> {
        let costs = &self.channel_daily_cost;
        match slots {
            10 => Some(costs.t10),
            25 => Some(costs.t25),
            50 => Some(costs.t50),
            100 => Some(costs.t100),
            _ => None,
        }
    }

    /// -(grace_days x daily_cost): the lowest balance a tank may burn down to
    pub fn floor(&self, daily_cost: i64) -> i64 {
        i64::from(self.grace_days)
            .saturating_mul(daily_cost)
            .saturating_neg()
    }

    /// contribute_hold_hours in ms (the D17 window)
    pub fn hold_ms(&self) -> i64 {
        i64::from(self.contribute_hold_hours) * HOUR_MS
    }

    /// "40/90/160/280"
    pub fn rate_card(&self) -> String {
        let costs = &self.channel_daily_cost;
        format!("{}/{}/{}/{}", costs.t10, costs.t25, costs.t50, costs.t100)
    }

    /// grace_days + freeze_days - final_warning_day (the "deleted in N days" of the Final notice; 10 by default)
    pub fn final_notice_days(&self) -> u32 {
        self.grace_days
            .saturating_add(self.freeze_days)
            .saturating_sub(self.final_warning_day)
    }
}

/// `contribute_prot` (8.8)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtContributeInput {
    pub user_id: String,
    pub tank_id: String,
    pub amount: i64,
    pub nonce: String,
    pub rules: ProtTankRules,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtContributeOutcome {
    Applied {
        entry: ProtLedgerEntry,
        tank: ProtTank,
        stage_changed: bool,
    },
    AlreadyApplied {
        entry: ProtLedgerEntry,
        tank: ProtTank,
    },
}

/// `pledge_prot` (8.3)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtPledgeInput {
    pub user_id: String,
    pub goal_id: String,
    pub amount: i64,
    pub nonce: String,
    pub rules: ProtTankRules,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtPledgeOutcome {
    pub pledge: ProtPledge,
    pub goal: ProtGoal,
    pub entry: ProtLedgerEntry,
    pub already_applied: bool,
    pub funded_now: bool,
}

/// `launch_prot_goal` (8.6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtLaunchInput {
    pub goal_id: String,
    pub channel_id: String,
    pub owner_id: String,
    pub rules: ProtTankRules,
    pub now: i64,
}

/// `change_prot_tier` (8.9)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtTierChangeInput {
    pub tank_id: String,
    pub slots: u32,
    pub change_id: String,
    pub rules: ProtTankRules,
    pub now: i64,
}

/// `burn_prot_tank_day` (7.2)
// One value per burned day, never collected; the variants without a row are
// the rare ones
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtBurnOutcome {
    Burned {
        entry: ProtLedgerEntry,
        tank: ProtTank,
    },
    EnteredGrace {
        entry: Option<ProtLedgerEntry>,
        tank: ProtTank,
    },
    Froze {
        tank: ProtTank,
    },
    NotDue {
        tank: ProtTank,
    },
}

/// `close_prot_goal` (8.5)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtGoalCloseOutcome {
    pub goal: ProtGoal,
    pub returned: Vec<ProtLedgerEntry>,
    pub removed_tank: Option<ProtTank>,
}

/// `settle_prot_tank` (9.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtSettlement {
    pub tank: ProtTank,
    pub returns: Vec<ProtLedgerEntry>,
    pub writeoff: Option<ProtLedgerEntry>,
}

/// `terminate_prot_tank` (9.5)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtTermination {
    pub tank: ProtTank,
    pub forfeit: Option<ProtLedgerEntry>,
    pub writeoff: Option<ProtLedgerEntry>,
    pub closed_goals: Vec<ProtGoalCloseOutcome>,
}

/// `purge_protected_channel_content` (6.5)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtPurgeCounts {
    pub messages: u64,
    pub groups: u64,
    pub commits: u64,
    pub join_intents: u64,
    pub envelopes: u64,
}

/// One FIFO lot of a tank (9.2): a contribution, or a capture net of its launch return
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtLot {
    /// Ledger row `_id`
    pub key: String,
    pub user_id: String,
    pub created_at: i64,
    pub amount: i64,
}

/// What `plan_prot_settlement` decided
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtSettlementPlan {
    /// (user id, Prot), each > 0
    pub returns: Vec<(String, i64)>,
    pub writeoff: i64,
    pub mismatch: bool,
}

/// What `plan_tank_day` decided for one day (7.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtDayPlan {
    Burn { amount: i64 },
    EnterGrace { amount: i64, exhausted_at: i64 },
    Freeze,
    Advance,
}

/// A stored day, strictly "YYYY-MM-DD" (a value that does not format back to
/// itself is malformed)
fn parse_prot_day(day: &str) -> Result<NaiveDate> {
    NaiveDate::parse_from_str(day, "%Y-%m-%d")
        .ok()
        .filter(|date| date.format("%Y-%m-%d").to_string() == day)
        .ok_or_else(|| {
            log::error!("PROT_DAY_MALFORMED day={day:?}");
            create_error!(InternalError)
        })
}

/// The UTC calendar day of `ms`, "YYYY-MM-DD"
pub fn prot_utc_day(ms: i64) -> String {
    let at = DateTime::<Utc>::from_timestamp_millis(ms).unwrap_or(if ms < 0 {
        DateTime::<Utc>::MIN_UTC
    } else {
        DateTime::<Utc>::MAX_UTC
    });
    at.format("%Y-%m-%d").to_string()
}

/// 00:00:00.000 UTC of `day`; InternalError on a malformed day
pub fn prot_day_start_ms(day: &str) -> Result<i64> {
    Ok(parse_prot_day(day)?
        .and_time(NaiveTime::MIN)
        .and_utc()
        .timestamp_millis())
}

/// The UTC day after `day`
pub fn prot_next_day(day: &str) -> Result<String> {
    parse_prot_day(day)?
        .succ_opt()
        .map(|next| next.format("%Y-%m-%d").to_string())
        .ok_or_else(|| {
            log::error!("PROT_DAY_MALFORMED day={day:?} (no next day)");
            create_error!(InternalError)
        })
}

/// The next UTC midnight strictly after `now_ms` (midnight itself is the start
/// of its day, so its next midnight is a day later)
pub fn prot_next_midnight_ms(now_ms: i64) -> i64 {
    now_ms
        .div_euclid(DAY_MS)
        .saturating_add(1)
        .saturating_mul(DAY_MS)
}

/// Whole hours left in the UTC day, rounded UP, 1..=24 (15:20 -> 9; 13:00:00.000 -> 11; 23:59 -> 1; 00:00:00.000 -> 24)
pub fn prot_hours_left(now_ms: i64) -> i64 {
    // 1..=DAY_MS
    let left = DAY_MS - now_ms.rem_euclid(DAY_MS);
    let hours = left / HOUR_MS;
    if left % HOUR_MS == 0 {
        hours
    } else {
        hours + 1
    }
}

/// ceil(cost * hours / 24) (orchestrator ruling R12): 40 x 9 -> 15; 40 x 11 -> 19; (90-40) x 11 -> 23; (90-40) x 12 -> 25
pub fn prot_pro_rata(daily_cost: i64, hours: i64) -> i64 {
    if daily_cost <= 0 || hours <= 0 {
        return 0;
    }
    let total = i128::from(daily_cost) * i128::from(hours);
    let whole = total / 24;
    let rounded = if total % 24 == 0 { whole } else { whole + 1 };
    i64::try_from(rounded).unwrap_or(i64::MAX)
}

/// max(0, min(want, balance - floor)) - every burn posting goes through it; 0 = write no row (7.0)
pub fn prot_burn_amount(want: i64, balance: i64, floor: i64) -> i64 {
    std::cmp::max(0, std::cmp::min(want, balance.saturating_sub(floor)))
}

/// next midnight + floor(balance / daily_cost) days; None when balance < 0 or daily_cost <= 0
pub fn prot_protected_until(now_ms: i64, balance: i64, daily_cost: i64) -> Option<i64> {
    if balance < 0 || daily_cost <= 0 {
        return None;
    }
    Some(
        prot_next_midnight_ms(now_ms).saturating_add((balance / daily_cost).saturating_mul(DAY_MS)),
    )
}

/// D13: (new_cost - old_cost) * floor(balance / old_cost); 10->25 slots at 1,200 (30 days) = 1,500
pub fn prot_upgrade_goal_price(old_cost: i64, new_cost: i64, balance: i64) -> i64 {
    if old_cost <= 0 || new_cost <= old_cost || balance <= 0 {
        return 0;
    }
    (new_cost - old_cost).saturating_mul(balance / old_cost)
}

/// Floor of total * w / sum(w) per entry, then the leftover units one each to the largest fractional remainders,
/// ties by key ascending; the result sums to exactly min(total, sum(w)) and no entry exceeds its weight.
///
/// The result keeps the order of `weights`. A negative total or weight counts as 0.
pub fn prot_largest_remainder(total: i64, weights: &[(String, i64)]) -> Vec<(String, i64)> {
    let clamped: Vec<i128> = weights
        .iter()
        .map(|(_, weight)| i128::from(std::cmp::max(*weight, 0)))
        .collect();
    let sum: i128 = clamped.iter().sum();
    if sum == 0 {
        return weights.iter().map(|(key, _)| (key.clone(), 0)).collect();
    }
    let total = std::cmp::min(i128::from(std::cmp::max(total, 0)), sum);

    let mut shares: Vec<i128> = clamped.iter().map(|weight| total * weight / sum).collect();
    let remainders: Vec<i128> = clamped.iter().map(|weight| total * weight % sum).collect();
    let mut leftover = total - shares.iter().sum::<i128>();

    // The leftover is sum(remainders) / sum, so it never exceeds the number of
    // entries with a remainder, and each of those has room for one more unit
    let mut order: Vec<usize> = (0..weights.len())
        .filter(|index| remainders[*index] > 0)
        .collect();
    order.sort_by(|a, b| {
        remainders[*b]
            .cmp(&remainders[*a])
            .then_with(|| weights[*a].0.cmp(&weights[*b].0))
    });
    for index in order {
        if leftover == 0 {
            break;
        }
        shares[index] += 1;
        leftover -= 1;
    }

    weights
        .iter()
        .zip(shares)
        .map(|((key, _), share)| (key.clone(), i64::try_from(share).unwrap_or(i64::MAX)))
        .collect()
}

/// The tank state every viewer of the channel may see (3.1)
pub fn prot_tank_summary(
    tank: &ProtTank,
    account: Option<&ProtAccount>,
    rules: &ProtTankRules,
    now_ms: i64,
) -> v0::ProtTankSummary {
    let balance = account.map(|account| account.balance).unwrap_or(0);
    let days_ms = |days: u32| i64::from(days) * DAY_MS;

    let protected_until = match tank.stage {
        v0::ProtTankStage::Active => prot_protected_until(now_ms, balance, tank.daily_cost),
        _ => None,
    };
    let grace_ends_at = match tank.stage {
        v0::ProtTankStage::Grace => tank
            .exhausted_at
            .map(|at| at.saturating_add(days_ms(rules.grace_days))),
        _ => None,
    };
    // No deletion date is promised while deletion is off (NIT 32)
    let deletes_at = match tank.stage {
        v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen if rules.deletion_enabled => {
            tank.exhausted_at.map(|at| {
                at.saturating_add(days_ms(rules.grace_days.saturating_add(rules.freeze_days)))
            })
        }
        _ => None,
    };
    let channel_id = match &tank.target {
        ProtTankTarget::Channel { channel_id } => channel_id.clone(),
        // S10: a server tank has no channel
        ProtTankTarget::Server { .. } => String::new(),
    };

    v0::ProtTankSummary {
        tank_id: tank.id.clone(),
        channel_id,
        stage: tank.stage,
        slot_tier: tank.slot_tier,
        pending_slot_tier: tank.pending_slot_tier,
        daily_cost: tank.daily_cost,
        balance,
        protected_until,
        grace_ends_at,
        deletes_at,
        launched_at: tank.launched_at,
        version: tank.version,
        balance_version: account.map(|account| account.version).unwrap_or(0),
    }
}

/// One day of the clock for a tank in Active or Grace (7.2). The Grace -> Frozen
/// check runs BEFORE the amount, so a tank clamped at its floor still freezes on
/// time. Any other stage, a Grace tank without `exhausted_at`, a non-positive
/// cost or a malformed day is an InternalError (never billed).
pub fn plan_tank_day(
    tank: &ProtTank,
    balance: i64,
    day: &str,
    rules: &ProtTankRules,
) -> Result<ProtDayPlan> {
    let day_start = prot_day_start_ms(day)?;
    if tank.daily_cost <= 0 {
        log::error!(
            "PROT_TANK_DAY_REFUSED tank={} daily_cost={}",
            tank.id,
            tank.daily_cost
        );
        return Err(create_error!(InternalError));
    }
    let floor = rules.floor(tank.daily_cost);

    match tank.stage {
        v0::ProtTankStage::Grace => {
            let Some(exhausted_at) = tank.exhausted_at else {
                log::error!(
                    "PROT_TANK_DAY_REFUSED tank={} grace without exhausted_at",
                    tank.id
                );
                return Err(create_error!(InternalError));
            };
            let grace_end = exhausted_at.saturating_add(i64::from(rules.grace_days) * DAY_MS);
            if day_start >= grace_end {
                return Ok(ProtDayPlan::Freeze);
            }
            let amount = prot_burn_amount(tank.daily_cost, balance, floor);
            Ok(if amount > 0 {
                ProtDayPlan::Burn { amount }
            } else {
                ProtDayPlan::Advance
            })
        }
        v0::ProtTankStage::Active => Ok(if balance >= tank.daily_cost {
            ProtDayPlan::Burn {
                amount: tank.daily_cost,
            }
        } else {
            ProtDayPlan::EnterGrace {
                amount: prot_burn_amount(tank.daily_cost, balance, floor),
                exhausted_at: day_start,
            }
        }),
        stage => {
            log::error!(
                "PROT_TANK_DAY_REFUSED tank={} stage={}",
                tank.id,
                stage.as_str()
            );
            Err(create_error!(InternalError))
        }
    }
}

/// FIFO settlement (D7, 9.2). `lots` are the tank's contributions and captures
/// (each capture already reduced by its launch return); `burned` is every Burn
/// and TierUpgrade row debiting the tank.
///
/// balance <= 0 is a write-off of -balance and no returns. Otherwise the burn
/// consumes lots oldest first (created_at, then key); a group of lots with the
/// same created_at that the remaining burn only partly covers is consumed pro
/// rata inside the group (largest remainder, so the consumed sum is exact). The
/// unconsumed lots go back per user. When they do not sum to the balance the
/// plan is a mismatch (logged `PROT_SETTLE_MISMATCH`) and the balance is split
/// over them by largest remainder, so it never pays out more than the balance.
/// Returns are > 0 only, by user id ascending.
pub fn plan_prot_settlement(lots: &[ProtLot], burned: i64, balance: i64) -> ProtSettlementPlan {
    if balance <= 0 {
        return ProtSettlementPlan {
            returns: Vec::new(),
            writeoff: balance.saturating_neg(),
            mismatch: false,
        };
    }

    let mut ordered: Vec<&ProtLot> = lots.iter().collect();
    ordered.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.key.cmp(&b.key))
    });

    let mut to_burn = std::cmp::max(burned, 0);
    let mut remaining: BTreeMap<String, i64> = BTreeMap::new();
    let mut start = 0;
    while start < ordered.len() {
        let mut end = start + 1;
        while end < ordered.len() && ordered[end].created_at == ordered[start].created_at {
            end += 1;
        }
        let group = &ordered[start..end];
        let amounts: Vec<(String, i64)> = group
            .iter()
            .map(|lot| (lot.key.clone(), std::cmp::max(lot.amount, 0)))
            .collect();
        let group_total = amounts
            .iter()
            .fold(0_i64, |total, (_, amount)| total.saturating_add(*amount));

        let consumed: Vec<i64> = if to_burn >= group_total {
            to_burn -= group_total;
            amounts.iter().map(|(_, amount)| *amount).collect()
        } else if to_burn > 0 {
            let shares = prot_largest_remainder(to_burn, &amounts);
            to_burn = 0;
            shares.into_iter().map(|(_, share)| share).collect()
        } else {
            vec![0; amounts.len()]
        };

        for ((lot, (_, amount)), used) in group.iter().zip(&amounts).zip(consumed) {
            let left = remaining.entry(lot.user_id.clone()).or_insert(0);
            *left = left.saturating_add(amount - used);
        }
        start = end;
    }

    let unconsumed = remaining
        .values()
        .fold(0_i64, |total, amount| total.saturating_add(*amount));
    if unconsumed == balance {
        return ProtSettlementPlan {
            returns: remaining.into_iter().filter(|(_, x)| *x > 0).collect(),
            writeoff: 0,
            mismatch: false,
        };
    }

    log::error!("PROT_SETTLE_MISMATCH unconsumed={unconsumed} balance={balance}");
    let weights: Vec<(String, i64)> = remaining.into_iter().collect();
    ProtSettlementPlan {
        returns: prot_largest_remainder(balance, &weights)
            .into_iter()
            .filter(|(_, x)| *x > 0)
            .collect(),
        writeoff: 0,
        mismatch: true,
    }
}

/// The 7-day returns (D8, 8.6): `due` is (pledge id, captured) of every unseated
/// pledger. T = max(0, tank_balance); T >= sum(due) pays each in full, else T is
/// split by largest remainder (ties by pledge id). Entries > 0 only, in the order
/// of `due`.
pub fn plan_unseated_returns(due: &[(String, i64)], tank_balance: i64) -> Vec<(String, i64)> {
    let due: Vec<(String, i64)> = due
        .iter()
        .map(|(pledge_id, amount)| (pledge_id.clone(), std::cmp::max(*amount, 0)))
        .collect();
    let total = due
        .iter()
        .fold(0_i64, |total, (_, amount)| total.saturating_add(*amount));
    let available = std::cmp::max(tank_balance, 0);

    let planned = if available >= total {
        due
    } else {
        prot_largest_remainder(available, &due)
    };
    planned.into_iter().filter(|(_, x)| *x > 0).collect()
}

/// The notices due for a tank now (12.2), least severe first:
/// Active -> `Warn(n)` for the smallest n in warn_days with floor(balance / daily_cost) <= n;
/// Grace -> `Grace`; Frozen -> `Freeze`, plus `Final` once now >= exhausted_at + final_warning_day days and ONLY
/// while deletion is enabled; Deleted -> `Deleted` only for an Expiry that ended in the last 24 h. The caller
/// delivers the most severe (`max()`) and records the rest undelivered.
pub fn prot_notice_due(
    tank: &ProtTank,
    balance: i64,
    rules: &ProtTankRules,
    now_ms: i64,
) -> Vec<ProtNoticeKind> {
    match tank.stage {
        v0::ProtTankStage::Active => {
            if tank.daily_cost <= 0 {
                return Vec::new();
            }
            let days_left = balance.div_euclid(tank.daily_cost);
            rules
                .warn_days
                .iter()
                .copied()
                .filter(|n| days_left <= i64::from(*n))
                .min()
                .map(ProtNoticeKind::Warn)
                .into_iter()
                .collect()
        }
        v0::ProtTankStage::Grace => vec![ProtNoticeKind::Grace],
        v0::ProtTankStage::Frozen => {
            let mut due = vec![ProtNoticeKind::Freeze];
            let final_at = |at: i64| at.saturating_add(i64::from(rules.final_warning_day) * DAY_MS);
            if rules.deletion_enabled && tank.exhausted_at.is_some_and(|at| now_ms >= final_at(at))
            {
                due.push(ProtNoticeKind::Final);
            }
            due
        }
        v0::ProtTankStage::Deleted => {
            let expired = tank.settle_cause == Some(ProtSettleCause::Expiry);
            let recent = tank
                .ended_at
                .is_some_and(|ended| ended >= now_ms.saturating_sub(DAY_MS));
            if expired && recent {
                vec![ProtNoticeKind::Deleted]
            } else {
                Vec::new()
            }
        }
        v0::ProtTankStage::Launching
        | v0::ProtTankStage::Settling
        | v0::ProtTankStage::Terminated => Vec::new(),
    }
}

/// The entitlement state a tank stage writes in the same transaction (6.1):
/// Launching/Active -> Active, Grace -> Grace, Frozen/Settling -> Frozen,
/// Deleted/Terminated -> Deleted (tombstone; BR4)
pub fn stage_entitlement_state(stage: v0::ProtTankStage) -> ChannelEntitlementState {
    match stage {
        v0::ProtTankStage::Launching | v0::ProtTankStage::Active => ChannelEntitlementState::Active,
        v0::ProtTankStage::Grace => ChannelEntitlementState::Grace,
        v0::ProtTankStage::Frozen | v0::ProtTankStage::Settling => ChannelEntitlementState::Frozen,
        v0::ProtTankStage::Deleted | v0::ProtTankStage::Terminated => {
            ChannelEntitlementState::Deleted
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use revolt_config::ProtectionFeatures;

    /// 2026-11-01T00:00:00.000Z
    const NOV_1: i64 = 1_793_491_200_000;
    const MINUTE_MS: i64 = 60_000;

    fn at(hours: i64, minutes: i64) -> i64 {
        NOV_1 + hours * HOUR_MS + minutes * MINUTE_MS
    }

    fn days(n: i64) -> i64 {
        n * DAY_MS
    }

    /// The default rules with every switch on (the DB-level tests do the same)
    fn rules() -> ProtTankRules {
        ProtTankRules {
            burning: true,
            deletion_enabled: true,
            self_serve: true,
            ..ProtTankRules::from_config(&ProtectionFeatures::default()).unwrap()
        }
    }

    fn tank(stage: v0::ProtTankStage) -> ProtTank {
        ProtTank {
            id: "01TANK".to_string(),
            target: ProtTankTarget::Channel {
                channel_id: "01CHANNEL".to_string(),
            },
            target_key: prot_tank_target_key("01CHANNEL"),
            server_id: "01SERVER".to_string(),
            created_by: "01OWNER".to_string(),
            plan: v0::ProtPlan::Channel,
            slot_tier: 10,
            pending_slot_tier: None,
            daily_cost: 40,
            rate_card: "40/90/160/280".to_string(),
            stage,
            exhausted_at: None,
            next_burn_day: Some("2026-11-01".to_string()),
            launched_at: Some(NOV_1 - days(3)),
            final_warning_at: None,
            warnings_epoch: 0,
            pause_shift_for: None,
            settle_cause: None,
            ended_at: None,
            terminated_by: None,
            purged_at: None,
            purge_passes: 0,
            version: 3,
            created_at: NOV_1 - days(10),
            updated_at: NOV_1 - days(1),
        }
    }

    fn account(balance: i64, version: u64) -> ProtAccount {
        ProtAccount {
            id: crate::prot_tank_account("01TANK"),
            currency: v0::ProtCurrency::Prot,
            balance,
            version,
            updated_at: NOV_1,
        }
    }

    fn weights(pairs: &[(&str, i64)]) -> Vec<(String, i64)> {
        pairs
            .iter()
            .map(|(key, weight)| (key.to_string(), *weight))
            .collect()
    }

    fn lot(key: &str, user_id: &str, created_at: i64, amount: i64) -> ProtLot {
        ProtLot {
            key: key.to_string(),
            user_id: user_id.to_string(),
            created_at,
            amount,
        }
    }

    #[test]
    fn pro_rata_rounds_hours_and_prot_up() {
        assert_eq!(prot_hours_left(at(15, 20)), 9);
        assert_eq!(prot_hours_left(at(13, 0)), 11);
        assert_eq!(prot_hours_left(at(23, 59)), 1);
        assert_eq!(prot_hours_left(NOV_1), 24);
        assert_eq!(prot_hours_left(NOV_1 - 1), 1);
        assert_eq!(prot_hours_left(NOV_1 + 1), 24);

        assert_eq!(prot_pro_rata(40, 9), 15);
        assert_eq!(prot_pro_rata(40, 11), 19);
        assert_eq!(prot_pro_rata(90 - 40, 11), 23);
        assert_eq!(prot_pro_rata(90 - 40, 12), 25);
        // 00:00 bills the full day
        assert_eq!(prot_pro_rata(40, prot_hours_left(NOV_1)), 40);
        assert_eq!(prot_pro_rata(40, prot_hours_left(at(15, 20))), 15);

        assert_eq!(prot_pro_rata(0, 11), 0);
        assert_eq!(prot_pro_rata(-40, 11), 0);
        assert_eq!(prot_pro_rata(40, 0), 0);
    }

    #[test]
    fn protected_until_is_next_midnight_plus_whole_days() {
        let now = at(15, 20);
        assert_eq!(prot_next_midnight_ms(now), NOV_1 + days(1));
        // midnight is the start of its day
        assert_eq!(prot_next_midnight_ms(NOV_1), NOV_1 + days(1));
        assert_eq!(prot_next_midnight_ms(NOV_1 - 1), NOV_1);

        assert_eq!(
            prot_protected_until(now, 1_000, 40),
            Some(NOV_1 + days(1) + days(25))
        );
        assert_eq!(prot_protected_until(now, 1_039, 40), Some(NOV_1 + days(26)));
        assert_eq!(prot_protected_until(now, 39, 40), Some(NOV_1 + days(1)));
        assert_eq!(prot_protected_until(now, -1, 40), None);
        assert_eq!(prot_protected_until(now, 1_000, 0), None);
    }

    #[test]
    fn upgrade_price_is_1500() {
        let rules = rules();
        let old = rules.daily_cost(10).unwrap();
        let new = rules.daily_cost(25).unwrap();
        assert_eq!(prot_upgrade_goal_price(old, new, 1_200), 1_500);
        // whole days only
        assert_eq!(prot_upgrade_goal_price(old, new, 1_239), 1_500);
        assert_eq!(prot_upgrade_goal_price(old, new, 0), 0);
        assert_eq!(prot_upgrade_goal_price(new, old, 1_200), 0);
    }

    #[test]
    fn largest_remainder_gives_b_67_c_33() {
        assert_eq!(
            prot_largest_remainder(100, &weights(&[("B", 400), ("C", 200)])),
            weights(&[("B", 67), ("C", 33)])
        );
    }

    #[test]
    fn largest_remainder_ties_go_to_the_smaller_key() {
        assert_eq!(
            prot_largest_remainder(1, &weights(&[("u3", 1), ("u1", 1), ("u2", 1)])),
            weights(&[("u3", 0), ("u1", 1), ("u2", 0)])
        );
        assert_eq!(
            prot_largest_remainder(2, &weights(&[("u3", 1), ("u1", 1), ("u2", 1)])),
            weights(&[("u3", 0), ("u1", 1), ("u2", 1)])
        );
        // more than the weights: each gets its weight, never more
        assert_eq!(
            prot_largest_remainder(1_000, &weights(&[("a", 3), ("b", 4)])),
            weights(&[("a", 3), ("b", 4)])
        );
        assert_eq!(
            prot_largest_remainder(-5, &weights(&[("a", 3)])),
            weights(&[("a", 0)])
        );
        assert!(prot_largest_remainder(10, &[]).is_empty());
    }

    #[test]
    fn largest_remainder_sums_exactly() {
        // xorshift64*, fixed seed: reproducible "random" cases
        let mut state: u64 = 0x5DEE_CE66_D1CE_4E5B;
        let mut next = move |bound: u64| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D) % bound
        };

        for case in 0..1_000 {
            let count = 1 + next(8) as usize;
            let list: Vec<(String, i64)> = (0..count)
                .map(|index| {
                    (
                        format!("k{}", next(5) * 10 + index as u64),
                        next(1_000) as i64,
                    )
                })
                .collect();
            let total = next(3_000) as i64 - 10;
            let sum: i64 = list.iter().map(|(_, weight)| weight).sum();

            let shares = prot_largest_remainder(total, &list);
            assert_eq!(shares.len(), list.len(), "case {case}");
            let given: i64 = shares.iter().map(|(_, share)| share).sum();
            assert_eq!(
                given,
                total.clamp(0, sum),
                "case {case}: {list:?} total {total}"
            );
            for ((key, weight), (share_key, share)) in list.iter().zip(&shares) {
                assert_eq!(key, share_key, "case {case}: order kept");
                assert!(*share >= 0, "case {case}: {key} {share} < 0");
                assert!(share <= weight, "case {case}: {key} {share} > {weight}");
                if sum > 0 {
                    let floor =
                        i128::from(total.clamp(0, sum)) * i128::from(*weight) / i128::from(sum);
                    assert!(
                        i128::from(*share) >= floor,
                        "case {case}: below its floor share"
                    );
                }
            }
        }
    }

    #[test]
    fn burn_amount_clamps_at_the_floor_and_never_goes_negative() {
        let floor = rules().floor(40);
        assert_eq!(floor, -200);
        assert_eq!(prot_burn_amount(40, 30, floor), 40);
        assert_eq!(prot_burn_amount(40, -170, floor), 30);
        assert_eq!(prot_burn_amount(40, -200, floor), 0);
        // a downgrade raised the floor above the balance: 0, never a negative amount
        assert_eq!(prot_burn_amount(40, -250, -100), 0);
        assert_eq!(prot_burn_amount(-5, 100, 0), 0);
        // apply clamps with floor 0
        assert_eq!(prot_burn_amount(23, 10, 0), 10);
    }

    /// D7: O 600, A 400, C 200 at t0 (C launch-returned 200), D 300 on day 20,
    /// burned 1,000, balance 300 -> D 300, O 0, A 0 (lifetime totals would give
    /// O 139, A 92, D 69)
    #[test]
    fn d7_settlement_example() {
        let t0 = NOV_1;
        let lots = [
            lot("r1", "O", t0, 600),
            lot("r2", "A", t0, 400),
            // C's 200 capture net of its 200 launch return
            lot("r3", "C", t0, 0),
            lot("r4", "D", t0 + days(20), 300),
        ];
        assert_eq!(
            plan_prot_settlement(&lots, 1_000, 300),
            ProtSettlementPlan {
                returns: weights(&[("D", 300)]),
                writeoff: 0,
                mismatch: false,
            }
        );
    }

    /// O 600 + A 400 at t0, D 300 later, burned 500, balance 800: the t0 group is
    /// consumed pro rata (O 300, A 200)
    #[test]
    fn fifo_ties_split_pro_rata() {
        let lots = [
            lot("r3", "D", NOV_1 + days(4), 300),
            lot("r1", "O", NOV_1, 600),
            lot("r2", "A", NOV_1, 400),
        ];
        assert_eq!(
            plan_prot_settlement(&lots, 500, 800),
            ProtSettlementPlan {
                returns: weights(&[("A", 200), ("D", 300), ("O", 300)]),
                writeoff: 0,
                mismatch: false,
            }
        );
    }

    /// Lots 1/1/1 at t0, burned 1, balance 2: the burn lands on the first key (u1)
    #[test]
    fn settlement_rounding_places_the_burn_by_largest_remainder() {
        let lots = [
            lot("r2", "u2", NOV_1, 1),
            lot("r1", "u1", NOV_1, 1),
            lot("r3", "u3", NOV_1, 1),
        ];
        let plan = plan_prot_settlement(&lots, 1, 2);
        assert_eq!(plan.returns, weights(&[("u2", 1), ("u3", 1)]));
        assert_eq!(plan.returns.iter().map(|(_, x)| x).sum::<i64>(), 2);
        assert!(!plan.mismatch);
    }

    #[test]
    fn settlement_of_a_negative_balance_is_a_writeoff() {
        let lots = [lot("r1", "O", NOV_1, 600)];
        assert_eq!(
            plan_prot_settlement(&lots, 800, -200),
            ProtSettlementPlan {
                returns: Vec::new(),
                writeoff: 200,
                mismatch: false,
            }
        );
        assert_eq!(plan_prot_settlement(&lots, 600, 0).writeoff, 0);
    }

    #[test]
    fn settlement_mismatch_never_pays_more_than_the_balance() {
        // the lots say 400 is left, the account holds 100
        let lots = [lot("r1", "B", NOV_1, 400), lot("r2", "C", NOV_1 + 1, 200)];
        let plan = plan_prot_settlement(&lots, 200, 100);
        assert!(plan.mismatch);
        assert_eq!(plan.returns, weights(&[("B", 50), ("C", 50)]));

        // more balance than lots: never more than each user's remaining lots
        let plan = plan_prot_settlement(&lots, 0, 1_000);
        assert!(plan.mismatch);
        assert_eq!(plan.returns, weights(&[("B", 400), ("C", 200)]));
    }

    #[test]
    fn unseated_returns_pay_in_full_when_the_tank_covers_them() {
        // 1,200 captured, 7 burns of 40: C (200) unseated -> C 200, tank 720
        let balance = 1_200 - 7 * 40;
        let returns = plan_unseated_returns(&weights(&[("pC", 200)]), balance);
        assert_eq!(returns, weights(&[("pC", 200)]));
        assert_eq!(balance - 200, 720);
    }

    #[test]
    fn unseated_returns_scale_b_67_c_33() {
        assert_eq!(
            plan_unseated_returns(&weights(&[("pB", 400), ("pC", 200)]), 100),
            weights(&[("pB", 67), ("pC", 33)])
        );
        assert!(plan_unseated_returns(&weights(&[("pB", 400)]), -50).is_empty());
        assert!(plan_unseated_returns(&weights(&[("pB", 0)]), 50).is_empty());
    }

    /// 40/day, balance 30: d0 enters Grace (-10), d1-d4 burn to -170, d5 freezes;
    /// never below -200
    #[test]
    fn plan_tank_day_grace_burns_to_the_floor_then_freezes() {
        let rules = rules();
        let mut tank = tank(v0::ProtTankStage::Active);
        let mut balance = 30;
        let mut day = "2026-11-01".to_string();
        let mut plans = Vec::new();

        for _ in 0..8 {
            let plan = plan_tank_day(&tank, balance, &day, &rules).unwrap();
            match &plan {
                ProtDayPlan::Burn { amount } => balance -= amount,
                ProtDayPlan::EnterGrace {
                    amount,
                    exhausted_at,
                } => {
                    balance -= amount;
                    tank.stage = v0::ProtTankStage::Grace;
                    tank.exhausted_at = Some(*exhausted_at);
                }
                ProtDayPlan::Freeze => break,
                ProtDayPlan::Advance => {}
            }
            assert!(balance >= rules.floor(40));
            plans.push((day.clone(), plan, balance));
            day = prot_next_day(&day).unwrap();
        }

        assert_eq!(
            plans[0],
            (
                "2026-11-01".to_string(),
                ProtDayPlan::EnterGrace {
                    amount: 40,
                    exhausted_at: NOV_1,
                },
                -10
            )
        );
        assert_eq!(plans.len(), 5);
        assert_eq!(plans[4].2, -170);
        assert_eq!(day, "2026-11-06");
        assert_eq!(
            plan_tank_day(&tank, balance, &day, &rules).unwrap(),
            ProtDayPlan::Freeze
        );
    }

    #[test]
    fn plan_tank_day_checks_the_freeze_before_the_amount() {
        let rules = rules();
        let mut grace = tank(v0::ProtTankStage::Grace);
        grace.exhausted_at = Some(NOV_1);

        // at the floor inside the grace window: no row, the day advances
        assert_eq!(
            plan_tank_day(&grace, -200, "2026-11-03", &rules).unwrap(),
            ProtDayPlan::Advance
        );
        // clamped near the floor
        assert_eq!(
            plan_tank_day(&grace, -190, "2026-11-03", &rules).unwrap(),
            ProtDayPlan::Burn { amount: 10 }
        );
        // a downgrade left the balance below the new floor: still an Advance
        let mut downgraded = grace.clone();
        downgraded.daily_cost = 10;
        assert_eq!(
            plan_tank_day(&downgraded, -170, "2026-11-04", &rules).unwrap(),
            ProtDayPlan::Advance
        );
        // ... and it still freezes on time
        assert_eq!(
            plan_tank_day(&downgraded, -170, "2026-11-06", &rules).unwrap(),
            ProtDayPlan::Freeze
        );
        // a full balance in Grace still freezes on day 5 (the check runs first)
        assert_eq!(
            plan_tank_day(&grace, 10_000, "2026-11-06", &rules).unwrap(),
            ProtDayPlan::Freeze
        );

        let active = tank(v0::ProtTankStage::Active);
        assert_eq!(
            plan_tank_day(&active, 40, "2026-11-01", &rules).unwrap(),
            ProtDayPlan::Burn { amount: 40 }
        );
        assert_eq!(
            plan_tank_day(&active, 0, "2026-11-02", &rules).unwrap(),
            ProtDayPlan::EnterGrace {
                amount: 40,
                exhausted_at: NOV_1 + days(1),
            }
        );
    }

    #[test]
    fn plan_tank_day_refuses_other_stages_and_malformed_days() {
        let rules = rules();
        for stage in [
            v0::ProtTankStage::Launching,
            v0::ProtTankStage::Frozen,
            v0::ProtTankStage::Settling,
            v0::ProtTankStage::Deleted,
            v0::ProtTankStage::Terminated,
        ] {
            assert!(plan_tank_day(&tank(stage), 1_000, "2026-11-01", &rules).is_err());
        }
        // Grace without its exhaustion time
        assert!(plan_tank_day(&tank(v0::ProtTankStage::Grace), 0, "2026-11-01", &rules).is_err());
        assert!(
            plan_tank_day(&tank(v0::ProtTankStage::Active), 1_000, "2026-11-1", &rules).is_err()
        );
        let mut free = tank(v0::ProtTankStage::Active);
        free.daily_cost = 0;
        assert!(plan_tank_day(&free, 1_000, "2026-11-01", &rules).is_err());
    }

    #[test]
    fn utc_days_and_midnights() {
        assert_eq!(prot_utc_day(0), "1970-01-01");
        assert_eq!(prot_utc_day(NOV_1), "2026-11-01");
        assert_eq!(prot_utc_day(NOV_1 - 1), "2026-10-31");
        assert_eq!(prot_utc_day(at(23, 59)), "2026-11-01");
        assert_eq!(prot_day_start_ms("2026-11-01").unwrap(), NOV_1);
        assert_eq!(prot_day_start_ms("1970-01-01").unwrap(), 0);
        assert_eq!(prot_next_day("2026-11-01").unwrap(), "2026-11-02");
        assert_eq!(prot_next_day("2026-12-31").unwrap(), "2027-01-01");
        assert_eq!(prot_next_day("2028-02-28").unwrap(), "2028-02-29");
        for bad in [
            "",
            "2026-11-1",
            "2026-13-01",
            "2026-02-30",
            "2026-11-01T00",
            "26-11-01",
        ] {
            assert!(prot_day_start_ms(bad).is_err(), "{bad:?}");
            assert!(prot_next_day(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn default_rules_are_valid_and_carry_the_config() {
        let defaults = ProtTankRules::from_config(&ProtectionFeatures::default()).unwrap();
        assert!(!defaults.burning);
        assert!(!defaults.deletion_enabled);
        assert!(!defaults.self_serve);
        assert_eq!(defaults.max_launch_goal_days, 365);
        assert_eq!(defaults.min_launch_goal_days, 30);
        assert_eq!(defaults.warn_days, [7, 3, 1]);

        assert_eq!(defaults.daily_cost(10), Some(40));
        assert_eq!(defaults.daily_cost(25), Some(90));
        assert_eq!(defaults.daily_cost(50), Some(160));
        assert_eq!(defaults.daily_cost(100), Some(280));
        for slots in [0, 1, 20, 99, 101] {
            assert_eq!(defaults.daily_cost(slots), None);
        }
        for slots in PROT_SLOT_TIERS {
            assert!(defaults.daily_cost(slots).is_some());
        }
        assert_eq!(defaults.floor(40), -200);
        assert_eq!(defaults.floor(280), -1_400);
        assert_eq!(defaults.hold_ms(), 72 * HOUR_MS);
        assert_eq!(defaults.rate_card(), "40/90/160/280");
        assert_eq!(defaults.final_notice_days(), 10);

        // burning needs both switches
        let burn_only = ProtectionFeatures {
            burn_enabled: true,
            ..Default::default()
        };
        assert!(!ProtTankRules::from_config(&burn_only).unwrap().burning);
        let both = ProtectionFeatures {
            enabled: true,
            burn_enabled: true,
            deletion_enabled: true,
            self_serve_enabled: true,
            ..Default::default()
        };
        let on = ProtTankRules::from_config(&both).unwrap();
        assert!(on.burning && on.deletion_enabled && on.self_serve);
    }

    #[test]
    fn invalid_rules_are_refused() {
        type Mutation = fn(&mut ProtectionFeatures);
        let cases: [(&str, Mutation); 18] = [
            ("zero cost", |p| p.channel_daily_cost.t10 = 0),
            ("flat table", |p| {
                p.channel_daily_cost.t25 = p.channel_daily_cost.t10
            }),
            ("falling table", |p| p.channel_daily_cost.t100 = 100),
            ("no grace", |p| p.grace_days = 0),
            ("no freeze", |p| p.freeze_days = 0),
            ("final in grace", |p| p.final_warning_day = 5),
            ("final at deletion", |p| p.final_warning_day = 30),
            ("warn day 0", |p| p.warn_days = vec![7, 0]),
            ("warn days rising", |p| p.warn_days = vec![1, 3, 7]),
            ("warn day twice", |p| p.warn_days = vec![3, 3]),
            ("no reactivation", |p| p.min_reactivation_days = 0),
            ("no minimum", |p| p.min_contribution = 0),
            ("goal of 0 days", |p| p.min_launch_goal_days = 0),
            ("max below min", |p| p.max_launch_goal_days = 29),
            ("max over ten years", |p| p.max_launch_goal_days = 3651),
            ("no launch window", |p| p.launch_window_days = 0),
            ("no seat window", |p| p.launch_seat_window_days = 0),
            ("cutoff past the deadline", |p| {
                p.withdraw_cutoff_hours = 30 * 24
            }),
        ];
        for (name, mutate) in cases {
            let mut p = ProtectionFeatures::default();
            mutate(&mut p);
            assert!(ProtTankRules::from_config(&p).is_err(), "{name}");
        }

        // the edges that are allowed
        let edges = ProtectionFeatures {
            final_warning_day: 29,
            max_launch_goal_days: 3650,
            withdraw_cutoff_hours: 30 * 24 - 1,
            warn_days: Vec::new(),
            ..Default::default()
        };
        assert!(ProtTankRules::from_config(&edges).is_ok());
    }

    #[test]
    fn key_builders_are_the_pinned_strings() {
        assert_eq!(prot_key_contrib("u1", "t1", "n1"), "contrib:u1:t1:n1");
        assert_eq!(prot_key_tier("t1", "owner-n1"), "tier:t1:owner-n1");
        assert_eq!(prot_key_pledge("u1", "g1", "n1"), "pledge:u1:g1:n1");
        assert_eq!(prot_key_pledge_capture("p1"), "pledge-capture:p1");
        assert_eq!(prot_key_pledge_return("p1"), "pledge-return:p1");
        assert_eq!(prot_key_pledge_withdraw("p1"), "pledge-withdraw:p1");
        assert_eq!(prot_key_launch_return("p1"), "launch-return:p1");
        assert_eq!(prot_key_burn("t1", "2026-11-01"), "burn:t1:2026-11-01");
        assert_eq!(prot_key_settle("t1", "u1"), "settle:t1:u1");
        assert_eq!(prot_key_writeoff("t1"), "writeoff:t1");
        assert_eq!(prot_key_clawback_hold("o1", "p1"), "clawback-hold:o1:p1");
        assert_eq!(prot_key_forfeit_hold("p1"), "forfeit-hold:p1");
        assert_eq!(prot_key_forfeit_tank("t1"), "forfeit-tank:t1");
        assert_eq!(prot_tank_target_key("c1"), "channel:c1");
        assert_eq!(
            prot_notice_key("t1", 2, ProtNoticeKind::Warn(7)),
            "warn:t1:2:warn7"
        );
        assert_eq!(
            prot_notice_key("t1", 0, ProtNoticeKind::Final),
            "warn:t1:0:final"
        );

        assert_eq!(PROT_ACTOR_CLOCK, "sys:clock");
        assert_eq!(PROT_ACTOR_GOALS, "sys:goals");
        assert_eq!(PROT_ACTOR_SETTLEMENT, "sys:settlement");
        assert_eq!(PROT_RUNTIME_ID, "runtime");
        assert_eq!(PROT_SLOT_TIERS, [10, 25, 50, 100]);
        assert_eq!(PROT_MAX_AMOUNT, 1_000_000);
        assert_eq!(
            PROT_OPEN_GOAL_STATES,
            [
                v0::ProtGoalState::Funding,
                v0::ProtGoalState::Funded,
                v0::ProtGoalState::Launching
            ]
        );
    }

    #[test]
    fn notice_kinds_have_their_segments_and_severity() {
        let segments = [
            (ProtNoticeKind::Warn(7), "warn7"),
            (ProtNoticeKind::Warn(3), "warn3"),
            (ProtNoticeKind::Warn(1), "warn1"),
            (ProtNoticeKind::Grace, "grace"),
            (ProtNoticeKind::Freeze, "freeze"),
            (ProtNoticeKind::Final, "final"),
            (ProtNoticeKind::Deleted, "deleted"),
        ];
        for (kind, segment) in segments {
            assert_eq!(kind.key_segment(), segment);
        }
        // the table above is in ascending severity
        for pair in segments.windows(2) {
            assert!(pair[0].0 < pair[1].0, "{:?} < {:?}", pair[0].0, pair[1].0);
        }
        assert_eq!(
            [
                ProtNoticeKind::Freeze,
                ProtNoticeKind::Final,
                ProtNoticeKind::Grace
            ]
            .into_iter()
            .max(),
            Some(ProtNoticeKind::Final)
        );
    }

    #[test]
    fn notice_due_follows_the_stage() {
        let rules = rules();
        let now = at(10, 0);

        // Active: the smallest warn day that covers the days left
        let active = tank(v0::ProtTankStage::Active);
        assert!(prot_notice_due(&active, 40 * 8, &rules, now).is_empty());
        assert_eq!(
            prot_notice_due(&active, 40 * 7, &rules, now),
            [ProtNoticeKind::Warn(7)]
        );
        assert_eq!(
            prot_notice_due(&active, 40 * 3 + 39, &rules, now),
            [ProtNoticeKind::Warn(3)]
        );
        assert_eq!(
            prot_notice_due(&active, 39, &rules, now),
            [ProtNoticeKind::Warn(1)]
        );

        let mut grace = tank(v0::ProtTankStage::Grace);
        grace.exhausted_at = Some(NOV_1 - days(2));
        assert_eq!(
            prot_notice_due(&grace, -80, &rules, now),
            [ProtNoticeKind::Grace]
        );

        // Frozen: Final from exhausted_at + 20 days, and only while deletion is on
        let mut frozen = tank(v0::ProtTankStage::Frozen);
        frozen.exhausted_at = Some(now - days(20));
        assert_eq!(
            prot_notice_due(&frozen, -200, &rules, now),
            [ProtNoticeKind::Freeze, ProtNoticeKind::Final]
        );
        assert_eq!(
            prot_notice_due(&frozen, -200, &rules, now - 1),
            [ProtNoticeKind::Freeze]
        );
        let deletion_off = ProtTankRules {
            deletion_enabled: false,
            ..rules.clone()
        };
        assert_eq!(
            prot_notice_due(&frozen, -200, &deletion_off, now),
            [ProtNoticeKind::Freeze]
        );

        // Deleted: an Expiry of the last 24 h only
        let mut deleted = tank(v0::ProtTankStage::Deleted);
        deleted.settle_cause = Some(ProtSettleCause::Expiry);
        deleted.ended_at = Some(now - days(1));
        assert_eq!(
            prot_notice_due(&deleted, 0, &rules, now),
            [ProtNoticeKind::Deleted]
        );
        deleted.ended_at = Some(now - days(1) - 1);
        assert!(prot_notice_due(&deleted, 0, &rules, now).is_empty());
        deleted.ended_at = Some(now);
        for cause in [ProtSettleCause::OwnerDelete, ProtSettleCause::Termination] {
            deleted.settle_cause = Some(cause);
            assert!(prot_notice_due(&deleted, 0, &rules, now).is_empty());
        }

        for stage in [
            v0::ProtTankStage::Launching,
            v0::ProtTankStage::Settling,
            v0::ProtTankStage::Terminated,
        ] {
            assert!(prot_notice_due(&tank(stage), -200, &rules, now).is_empty());
        }
    }

    #[test]
    fn tank_summary_dates_follow_the_stage() {
        let rules = rules();
        let now = at(15, 20);

        let active = prot_tank_summary(
            &tank(v0::ProtTankStage::Active),
            Some(&account(1_000, 12)),
            &rules,
            now,
        );
        assert_eq!(
            active,
            v0::ProtTankSummary {
                tank_id: "01TANK".to_string(),
                channel_id: "01CHANNEL".to_string(),
                stage: v0::ProtTankStage::Active,
                slot_tier: 10,
                pending_slot_tier: None,
                daily_cost: 40,
                balance: 1_000,
                protected_until: Some(NOV_1 + days(26)),
                grace_ends_at: None,
                deletes_at: None,
                launched_at: Some(NOV_1 - days(3)),
                version: 3,
                balance_version: 12,
            }
        );

        let mut grace = tank(v0::ProtTankStage::Grace);
        grace.exhausted_at = Some(NOV_1);
        let summary = prot_tank_summary(&grace, Some(&account(-40, 2)), &rules, now);
        assert_eq!(summary.balance, -40);
        assert_eq!(summary.protected_until, None);
        assert_eq!(summary.grace_ends_at, Some(NOV_1 + days(5)));
        assert_eq!(summary.deletes_at, Some(NOV_1 + days(30)));

        let mut frozen = grace.clone();
        frozen.stage = v0::ProtTankStage::Frozen;
        let summary = prot_tank_summary(&frozen, Some(&account(-200, 7)), &rules, now);
        assert_eq!(summary.grace_ends_at, None);
        assert_eq!(summary.deletes_at, Some(NOV_1 + days(30)));

        // no deletion date while deletion is off
        let deletion_off = ProtTankRules {
            deletion_enabled: false,
            ..rules.clone()
        };
        assert_eq!(
            prot_tank_summary(&frozen, Some(&account(-200, 7)), &deletion_off, now).deletes_at,
            None
        );
        assert_eq!(
            prot_tank_summary(&grace, None, &deletion_off, now).deletes_at,
            None
        );

        // no account document yet: balance 0, version 0
        let launching = prot_tank_summary(&tank(v0::ProtTankStage::Launching), None, &rules, now);
        assert_eq!((launching.balance, launching.balance_version), (0, 0));
        assert_eq!(launching.protected_until, None);
    }

    #[test]
    fn stored_tank_omits_absent_options_and_tags_the_target() {
        let mut stored = tank(v0::ProtTankStage::Launching);
        stored.next_burn_day = None;
        stored.launched_at = None;
        let value = serde_json::to_value(&stored).unwrap();
        assert_eq!(
            value["target"],
            serde_json::json!({ "type": "Channel", "channel_id": "01CHANNEL" })
        );
        assert_eq!(value["_id"], "01TANK");
        assert_eq!(value["stage"], "Launching");
        assert_eq!(value["plan"], "Channel");
        for key in [
            "pending_slot_tier",
            "exhausted_at",
            "next_burn_day",
            "launched_at",
            "final_warning_at",
            "pause_shift_for",
            "settle_cause",
            "ended_at",
            "terminated_by",
            "purged_at",
        ] {
            assert!(value.get(key).is_none(), "{key} is stored as null");
        }

        // counters absent on an old row read as 0
        let mut object = value.as_object().unwrap().clone();
        for key in ["warnings_epoch", "purge_passes", "version"] {
            object.remove(key);
        }
        let read: ProtTank = serde_json::from_value(serde_json::Value::Object(object)).unwrap();
        assert_eq!(
            (read.warnings_epoch, read.purge_passes, read.version),
            (0, 0, 0)
        );
        assert_eq!(read.target, stored.target);

        assert_eq!(
            serde_json::to_value(ProtSettleCause::OwnerDelete).unwrap(),
            serde_json::json!("OwnerDelete")
        );
    }
}
