//! S6 stored types, the purchase-row state machine, the store's ledger keys
//! and the pure folds both drivers share (prot-s6-contracts sections 5-8).
//!
//! Nothing here does I/O. The engine reads the row, hands it to
//! `plan_store_move`, builds the row the plan describes and hands it to
//! `apply_store_purchase_move`, so the two drivers and the engine cannot drift
//! apart on a transition.

use std::collections::HashMap;

use revolt_models::v0;

use crate::{
    prot_key_clawback, prot_key_purchase, prot_user_account, ProtAmount, ProtLedgerEntry,
    ProtPosting, ProtRef, PROT_SYS_CLAWED, PROT_SYS_ISSUED,
};

auto_derived!(
    /// One app-store purchase (`prot_store_purchases`). `prot` is stamped at first sight and never re-derived.
    pub struct ProtStorePurchase {
        #[serde(rename = "_id")]
        pub id: String,
        pub store: v0::ProtStore,
        /// The intent's user; None when unbound, or once unlinked by account deletion
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub user_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub intent_id: Option<String>,
        pub product_id: String,
        /// product prot x quantity at first sight (0 for an unknown product)
        pub prot: i64,
        pub quantity: u32,
        pub environment: v0::ProtStoreEnvironment,
        /// As the store sent it: Apple alpha-3, Play alpha-2
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub storefront: Option<String>,
        /// ISO alpha-2 when known (store_country_alpha2, section 8)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub country: Option<String>,
        pub state: v0::ProtStoreState,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub reject_reason: Option<v0::ProtStoreRejectReason>,
        /// Why a Held row is held (R63): set on every move into Held, cleared on every move out. A Held row
        /// with None is a legacy credit-pause hold (= Paused). No migration (optional field, no index)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub hold_reason: Option<v0::ProtStoreHoldReason>,
        /// Refund generations applied (0 = never refunded)
        #[serde(default)]
        pub refund_gen: u32,
        /// One entry per refund generation, written in the clawback's transaction
        #[serde(default)]
        pub refunds: Vec<ProtStoreRefund>,
        /// REFUND_REVERSED notifications that re-credited nothing (buyer gone, or a tombstone; R14)
        #[serde(default)]
        pub unreinstated_reversals: u32,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub apple: Option<ProtStoreApple>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub play: Option<ProtStorePlay>,
        /// When the `purchase:` posting committed
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub credited_at: Option<i64>,
        /// Some(true) from a Play credit until the server consumed it; unset at consume (partial index, R7)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub unconsumed: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub revoked_at: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub revocation_reason: Option<String>,
        /// Admin id of an E10 assign
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub assigned_by: Option<String>,
        /// Staff work item: one of PROT_STORE_NEEDS_* (section 19). One kind at a time; a later set
        /// overwrites (the alert trail is `alerted` + the log lines)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub needs_action: Option<String>,
        /// Alert kinds already sent for this row (dedupe)
        #[serde(default)]
        pub alerted: Vec<String>,
        pub created_at: i64,
        pub updated_at: i64,
        /// +1 on EVERY write to the row: moves AND bookkeeping (needs_action set/clear, alert claim,
        /// consumed mark, unlink). A move CASes on it, so it never overwrites a newer copy (audit N2)
        #[serde(default)]
        pub version: u64,
    }

    pub struct ProtStoreApple {
        pub transaction_id: String,
        pub original_transaction_id: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub app_account_token: Option<String>,
        pub signed_date: i64,
        pub purchase_date: i64,
    }

    pub struct ProtStorePlay {
        /// Full token (needed for consume and lookups)
        pub purchase_token: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub order_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub obfuscated_account_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub consumed_at: Option<i64>,
        /// productsv2 `testPurchaseContext` present
        #[serde(default)]
        pub test: bool,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub region_code: Option<String>,
    }

    /// One entry per refund generation; EVERY generation has one (the engine builds it, the driver fills
    /// `clawed`/`shortfall` from the rows it wrote for a Clawback; 0/0 when nothing was posted)
    pub struct ProtStoreRefund {
        pub gen: u32,
        pub at: i64,
        /// The store's revocation instant (Apple `revocationDate`, Play `voidedTimeMillis` or the RTDN
        /// `eventTimeMillis`): a Revoke whose date equals any stored entry's is a replay (audit 1)
        pub revocation_date: i64,
        /// Wallet + held-pledge Prot this generation took (sum of its Clawback + ClawbackHold rows)
        pub clawed: i64,
        pub shortfall: i64,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub reason: Option<String>,
    }

    /// A purchase intent (`prot_store_intents`)
    pub struct ProtStoreIntent {
        /// ULID
        #[serde(rename = "_id")]
        pub id: String,
        /// None once unlinked by account deletion
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub user_id: Option<String>,
        pub store: v0::ProtStore,
        pub product_id: String,
        /// Prot per unit stamped at issue (informational; the row stamps from config at first sight)
        pub prot: i64,
        /// Random, unique: Apple UUID v4 lowercase hyphenated; Play 32 random bytes base64url no pad (43 chars)
        pub token: String,
        pub state: v0::ProtStoreIntentState,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub purchase_id: Option<String>,
        pub created_at: i64,
        /// created_at + 24 h
        pub expires_at: i64,
    }

    /// One reconcile cursor (`prot_store_cursors`)
    pub struct ProtStoreCursor {
        /// "apple-history" | "play-voided"
        #[serde(rename = "_id")]
        pub id: String,
        /// Epoch ms as decimal string (Apple: last complete endDate; Play: last voidedTimeMillis seen)
        pub cursor: String,
        #[serde(default)]
        pub version: u64,
        pub updated_at: i64,
    }
);

pub const PROT_STORE_CURSOR_APPLE: &str = "apple-history";
pub const PROT_STORE_CURSOR_PLAY: &str = "play-voided";
pub const PROT_STORE_INTENT_TTL_MS: i64 = 24 * 3_600_000;
pub const PROT_STORE_MAX_OPEN_INTENTS: u64 = 3;
/// Actor of store credits, clawbacks and reinstates
pub const PROT_ACTOR_STORE: &str = "sys:store";

// The work-item kinds the planner sets and clears: the PROT_STORE_NEEDS_*
// strings of util/prot_store_alert.rs (section 19).
pub(super) use crate::util::prot_store_alert::PROT_STORE_NEEDS_UNCONSUMED as NEEDS_UNCONSUMED;
use crate::util::prot_store_alert::{
    PROT_STORE_NEEDS_OVER_CAP as NEEDS_OVER_CAP,
    PROT_STORE_NEEDS_REVERSED_UNPAID as NEEDS_REVERSED_UNPAID,
    PROT_STORE_NEEDS_UNBOUND as NEEDS_UNBOUND,
};

/// Every move to Revoked clears these (audit 5, 6; R63: a refunded over-cap
/// hold has nothing left to review)
const CLEARED_BY_REVOKE: &[&str] = &[NEEDS_UNBOUND, NEEDS_UNCONSUMED, NEEDS_OVER_CAP];
/// An E10 assign clears the unbound work item
const CLEARED_BY_ASSIGN: &[&str] = &[NEEDS_UNBOUND];
/// A staff release of an over-cap hold clears its review item (R63)
const CLEARED_BY_RELEASE: &[&str] = &[NEEDS_OVER_CAP];

/// Whether a Held row waits for staff (R63): no automatic credit moves it
fn held_over_cap(row: &ProtStorePurchase) -> bool {
    row.hold_reason == Some(v0::ProtStoreHoldReason::OverCap)
}

// --- Section 6: the purchase-row state machine ------------------------------

/// What the engine decided about a verified, not-revoked store purchase (binding, environment, product, test cap,
/// pause), BEFORE looking at the row. The engine builds it; the planner never does I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtStoreVerdict {
    Credit {
        user_id: String,
        intent_id: String,
    },
    /// Recorded Held: credits are paused, or (R63) crediting it would take the wallet past its cap
    Hold {
        user_id: String,
        intent_id: String,
        reason: v0::ProtStoreHoldReason,
    },
    Reject {
        reason: v0::ProtStoreRejectReason,
        user_id: Option<String>,
        intent_id: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtStoreEvent {
    /// verify / Apple ONE_TIME_CHARGE / History replay / Play RTDN PURCHASED / reconcile
    Seen(ProtStoreVerdict),
    /// A CURRENT revocation (Apple: the fresh Get Transaction Info shows `revocationDate`; Play: a void or
    /// purchaseState CANCELLED). `buyer_live` = the row's user is set, exists and is not deleted
    Revoke {
        revocation_date: i64,
        reason: Option<String>,
        user_hint: Option<String>,
        /// The intent the refund's token (Apple `appAccountToken`, Play `obfuscatedExternalAccountId`) resolved
        /// to, if any. A tombstone written on a row's first write uses it (R53); any other row ignores it
        intent_id: Option<String>,
        buyer_live: bool,
    },
    /// Apple: a REFUND / REFUND_REVERSED notification whose fresh lookup shows NO revocationDate (9.5)
    Reverse { buyer_live: bool },
    /// crond: credit pause is off, AND a fresh store lookup showed the purchase not revoked (a revoked one is
    /// fed as Revoke instead; audit N3)
    Unpause { buyer_live: bool },
    /// E10 admin assign (after a fresh lookup shows the purchase not revoked)
    Assign {
        user_id: String,
        admin_id: String,
        paused: bool,
    },
    /// R63 staff release of an over-cap hold (after a fresh lookup shows the purchase not revoked): credits it
    /// ignoring the cap. Anything but a Held(OverCap) row is not releasable
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtStoreLedgerPlan {
    None,
    /// `purchase:{id}`, Exact(row.prot)
    Credit,
    /// Refund generation `gen` (1-based): wallet UpTo(total) + held-pledge drain
    Clawback {
        gen: u32,
    },
    /// `reinstate:{id}:{gen}`, Exact(that generation's clawed)
    Reinstate {
        gen: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtStoreAnswer {
    Credited,
    AlreadyCredited,
    Held,
    Rejected(v0::ProtStoreRejectReason),
    Refunded,
    Revoked,
    Reinstated,
    /// Logged, nothing written
    Ignored,
    /// Admin assign refused (row not Rejected{Unbound}, revoked, test purchase…)
    NotAssignable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtStoreMovePlan {
    Answer(ProtStoreAnswer),
    Move {
        to: v0::ProtStoreState,
        /// The row's reject_reason after the move (a move to Revoked from Rejected(r) keeps r)
        reject_reason: Option<v0::ProtStoreRejectReason>,
        /// Some(..) sets the row's user (first sight, assign); None keeps it
        user_id: Option<String>,
        intent_id: Option<String>,
        ledger: ProtStoreLedgerPlan,
        /// None = KEEP the row's needs_action; Some(kind) = set it (audit 5)
        needs_action: Option<&'static str>,
        /// Kinds this move clears if the row holds one of them
        clear_needs: &'static [&'static str],
        /// Some(true) on a Credit of a Play row; Some(false) = unset (every move to Revoked; audit 6); None = keep.
        /// On first sight (no row) the planner cannot know the store, so it says None and the engine stamps
        /// Some(true) on a Play row it credits.
        unconsumed: Option<bool>,
        answer: ProtStoreAnswer,
    },
}

/// The event's name in log lines
fn event_name(event: &ProtStoreEvent) -> &'static str {
    match event {
        ProtStoreEvent::Seen(ProtStoreVerdict::Credit { .. }) => "seen_credit",
        ProtStoreEvent::Seen(ProtStoreVerdict::Hold { .. }) => "seen_hold",
        ProtStoreEvent::Seen(ProtStoreVerdict::Reject { .. }) => "seen_reject",
        ProtStoreEvent::Revoke { .. } => "revoke",
        ProtStoreEvent::Reverse { .. } => "reverse",
        ProtStoreEvent::Unpause { .. } => "unpause",
        ProtStoreEvent::Assign { .. } => "assign",
        ProtStoreEvent::Release => "release",
    }
}

/// An event no table row covers: logged, nothing written
fn ignored(row: Option<&ProtStorePurchase>, event: &ProtStoreEvent) -> ProtStoreMovePlan {
    log::info!(
        "PROT_STORE_EVENT_IGNORED id={} state={} event={}",
        row.map_or("-", |row| row.id.as_str()),
        row.map_or("none", |row| row.state.as_str()),
        event_name(event)
    );
    ProtStoreMovePlan::Answer(ProtStoreAnswer::Ignored)
}

/// Some(true) when a credit of `row` leaves a Play purchase to consume
fn unconsumed_after_credit(row: &ProtStorePurchase) -> Option<bool> {
    (row.store == v0::ProtStore::Play).then_some(true)
}

/// A credit of an existing row (Held -> Credited, or an assign)
fn credit_of(
    row: &ProtStorePurchase,
    user_id: Option<String>,
    clear_needs: &'static [&'static str],
) -> ProtStoreMovePlan {
    ProtStoreMovePlan::Move {
        to: v0::ProtStoreState::Credited,
        reject_reason: None,
        user_id,
        intent_id: None,
        ledger: ProtStoreLedgerPlan::Credit,
        needs_action: None,
        clear_needs,
        unconsumed: unconsumed_after_credit(row),
        answer: ProtStoreAnswer::Credited,
    }
}

/// A move to Revoked (or a stay in it). It clears `unbound` and `play_unconsumed_24h` and unsets `unconsumed`
/// (audit 5, 6); `reject_reason` is the row's (a Rejected row keeps its reason)
fn to_revoked(
    row: Option<&ProtStorePurchase>,
    user_id: Option<String>,
    ledger: ProtStoreLedgerPlan,
    needs_action: Option<&'static str>,
    answer: ProtStoreAnswer,
) -> ProtStoreMovePlan {
    ProtStoreMovePlan::Move {
        to: v0::ProtStoreState::Revoked,
        reject_reason: row.and_then(|row| row.reject_reason),
        user_id,
        intent_id: None,
        ledger,
        needs_action,
        clear_needs: CLEARED_BY_REVOKE,
        unconsumed: Some(false),
        answer,
    }
}

/// The first sight of a purchase (no row yet)
fn plan_first_sight(event: &ProtStoreEvent) -> ProtStoreMovePlan {
    match event {
        ProtStoreEvent::Seen(ProtStoreVerdict::Credit { user_id, intent_id }) => {
            ProtStoreMovePlan::Move {
                to: v0::ProtStoreState::Credited,
                reject_reason: None,
                user_id: Some(user_id.clone()),
                intent_id: Some(intent_id.clone()),
                ledger: ProtStoreLedgerPlan::Credit,
                needs_action: None,
                clear_needs: &[],
                unconsumed: None,
                answer: ProtStoreAnswer::Credited,
            }
        }
        ProtStoreEvent::Seen(ProtStoreVerdict::Hold {
            user_id,
            intent_id,
            reason,
        }) => ProtStoreMovePlan::Move {
            to: v0::ProtStoreState::Held,
            reject_reason: None,
            user_id: Some(user_id.clone()),
            intent_id: Some(intent_id.clone()),
            ledger: ProtStoreLedgerPlan::None,
            // R63: an over-cap hold is staff work from the start
            needs_action: (*reason == v0::ProtStoreHoldReason::OverCap).then_some(NEEDS_OVER_CAP),
            clear_needs: &[],
            unconsumed: None,
            answer: ProtStoreAnswer::Held,
        },
        ProtStoreEvent::Seen(ProtStoreVerdict::Reject {
            reason,
            user_id,
            intent_id,
        }) => ProtStoreMovePlan::Move {
            to: v0::ProtStoreState::Rejected,
            reject_reason: Some(*reason),
            user_id: user_id.clone(),
            intent_id: intent_id.clone(),
            ledger: ProtStoreLedgerPlan::None,
            needs_action: (*reason == v0::ProtStoreRejectReason::Unbound).then_some(NEEDS_UNBOUND),
            clear_needs: &[],
            unconsumed: None,
            answer: ProtStoreAnswer::Rejected(*reason),
        },
        // A refund before any credit: the tombstone that keeps a later charge from crediting
        ProtStoreEvent::Revoke {
            user_hint,
            intent_id,
            ..
        } => {
            let mut plan = to_revoked(
                None,
                user_hint.clone(),
                ProtStoreLedgerPlan::None,
                None,
                ProtStoreAnswer::Revoked,
            );
            // It marks the intent its token resolved to Used (R53)
            if let ProtStoreMovePlan::Move {
                intent_id: tombstone_intent,
                ..
            } = &mut plan
            {
                *tombstone_intent = intent_id.clone();
            }
            plan
        }
        ProtStoreEvent::Assign { .. } | ProtStoreEvent::Release => {
            ProtStoreMovePlan::Answer(ProtStoreAnswer::NotAssignable)
        }
        ProtStoreEvent::Reverse { .. } | ProtStoreEvent::Unpause { .. } => ignored(None, event),
    }
}

/// A REFUND_REVERSED on a Revoked row (the last five rows of the table)
fn plan_reversal(
    row: &ProtStorePurchase,
    event: &ProtStoreEvent,
    buyer_live: bool,
    reinstate_amount: i64,
) -> ProtStoreMovePlan {
    // A reversal of a clawed generation with the buyer still there: re-credit
    // what that generation took (E6; nothing when it took nothing, audit 18)
    if row.refund_gen >= 1 && buyer_live {
        return ProtStoreMovePlan::Move {
            to: v0::ProtStoreState::Reinstated,
            reject_reason: row.reject_reason,
            user_id: None,
            intent_id: None,
            ledger: if reinstate_amount > 0 {
                ProtStoreLedgerPlan::Reinstate {
                    gen: row.refund_gen,
                }
            } else {
                ProtStoreLedgerPlan::None
            },
            needs_action: None,
            clear_needs: &[],
            unconsumed: None,
            answer: ProtStoreAnswer::Reinstated,
        };
    }

    // The row stays Revoked and counts the reversal once; a History replay
    // of the same reversal never moves it again (nor re-opens a resolved
    // `reversed_unpaid`)
    if row.unreinstated_reversals != 0 {
        return ignored(Some(row), event);
    }
    let needs_action = if row.refund_gen >= 1 {
        // The buyer is gone: S5's forfeit already took the wallet
        None
    } else if row.reject_reason == Some(v0::ProtStoreRejectReason::TestPurchase)
        || row.environment == v0::ProtStoreEnvironment::Sandbox
    {
        log::info!("PROT_STORE_SANDBOX_REVERSAL id={}", row.id);
        None
    } else {
        // A tombstone whose refund was reversed: the buyer paid and holds
        // nothing; staff credit it by hand (owner Q1)
        Some(NEEDS_REVERSED_UNPAID)
    };
    to_revoked(
        Some(row),
        None,
        ProtStoreLedgerPlan::None,
        needs_action,
        ProtStoreAnswer::Ignored,
    )
}

/// THE transition function. Both drivers' tests, the engine and the admin route all go through it.
pub fn plan_store_move(
    row: Option<&ProtStorePurchase>,
    event: &ProtStoreEvent,
    reinstate_amount: i64,
) -> ProtStoreMovePlan {
    use v0::ProtStoreState as State;
    use ProtStoreEvent as Event;
    use ProtStoreMovePlan::Answer;

    // A replayed REFUND (the date of a recorded generation) never moves,
    // whatever the row's state: checked before every other Revoke row
    if let (
        Some(row),
        Event::Revoke {
            revocation_date, ..
        },
    ) = (row, event)
    {
        if row
            .refunds
            .iter()
            .any(|refund| refund.revocation_date == *revocation_date)
        {
            return Answer(ProtStoreAnswer::Revoked);
        }
    }

    let Some(row) = row else {
        return plan_first_sight(event);
    };

    match (row.state, event) {
        // Held: credit paused when it was seen, or (R63) over the wallet cap.
        // An over-cap hold is never credited automatically: only a staff
        // release (or a refund) moves it.
        (State::Held, Event::Seen(ProtStoreVerdict::Credit { .. }))
        | (State::Held, Event::Unpause { buyer_live: true })
            if !held_over_cap(row) =>
        {
            credit_of(row, None, &[])
        }
        (State::Held, Event::Release) if held_over_cap(row) => {
            credit_of(row, None, CLEARED_BY_RELEASE)
        }
        (State::Held, Event::Release) => Answer(ProtStoreAnswer::NotAssignable),
        // R63: a pause hold found over the cap becomes an over-cap hold
        (
            State::Held,
            Event::Seen(ProtStoreVerdict::Hold {
                reason: v0::ProtStoreHoldReason::OverCap,
                ..
            }),
        ) if !held_over_cap(row) => ProtStoreMovePlan::Move {
            to: State::Held,
            reject_reason: None,
            user_id: None,
            intent_id: None,
            ledger: ProtStoreLedgerPlan::None,
            needs_action: Some(NEEDS_OVER_CAP),
            clear_needs: &[],
            unconsumed: None,
            answer: ProtStoreAnswer::Held,
        },
        (State::Held, Event::Seen(_)) | (State::Held, Event::Unpause { buyer_live: true }) => {
            Answer(ProtStoreAnswer::Held)
        }
        (State::Held, Event::Unpause { buyer_live: false }) => ProtStoreMovePlan::Move {
            to: State::Rejected,
            reject_reason: Some(v0::ProtStoreRejectReason::NoBuyer),
            user_id: None,
            intent_id: None,
            ledger: ProtStoreLedgerPlan::None,
            needs_action: None,
            clear_needs: &[],
            unconsumed: None,
            answer: ProtStoreAnswer::Rejected(v0::ProtStoreRejectReason::NoBuyer),
        },
        (State::Held, Event::Revoke { .. }) => to_revoked(
            Some(row),
            None,
            ProtStoreLedgerPlan::None,
            None,
            ProtStoreAnswer::Revoked,
        ),
        (State::Held, Event::Assign { .. }) => Answer(ProtStoreAnswer::NotAssignable),
        (State::Held, Event::Reverse { .. }) => ignored(Some(row), event),

        // Rejected: an allow-list or binding change never re-opens a row
        (State::Rejected, Event::Seen(_)) => match row.reject_reason {
            Some(reason) => Answer(ProtStoreAnswer::Rejected(reason)),
            None => ignored(Some(row), event),
        },
        (
            State::Rejected,
            Event::Assign {
                user_id, paused, ..
            },
        ) if row.reject_reason == Some(v0::ProtStoreRejectReason::Unbound) => {
            if *paused {
                // R16: the pause wins
                ProtStoreMovePlan::Move {
                    to: State::Held,
                    reject_reason: None,
                    user_id: Some(user_id.clone()),
                    intent_id: None,
                    ledger: ProtStoreLedgerPlan::None,
                    needs_action: None,
                    clear_needs: CLEARED_BY_ASSIGN,
                    unconsumed: None,
                    answer: ProtStoreAnswer::Held,
                }
            } else {
                credit_of(row, Some(user_id.clone()), CLEARED_BY_ASSIGN)
            }
        }
        (State::Rejected, Event::Assign { .. } | Event::Release) => {
            Answer(ProtStoreAnswer::NotAssignable)
        }
        (State::Rejected, Event::Revoke { .. }) => to_revoked(
            Some(row),
            None,
            ProtStoreLedgerPlan::None,
            None,
            ProtStoreAnswer::Revoked,
        ),
        (State::Rejected, Event::Reverse { .. } | Event::Unpause { .. }) => {
            ignored(Some(row), event)
        }

        // Credited / Reinstated: the engine then REQUIRES `purchase:{id}` in
        // the ledger before it answers already_credited (audit 7)
        (State::Credited | State::Reinstated, Event::Seen(_)) => {
            Answer(ProtStoreAnswer::AlreadyCredited)
        }
        (
            State::Credited | State::Reinstated,
            Event::Revoke {
                buyer_live: true, ..
            },
        ) => match row.refund_gen.checked_add(1) {
            Some(gen) => to_revoked(
                Some(row),
                None,
                ProtStoreLedgerPlan::Clawback { gen },
                None,
                ProtStoreAnswer::Revoked,
            ),
            None => ignored(Some(row), event),
        },
        // The buyer is gone: S5's forfeit already took the wallet, so the
        // generation is recorded and nothing is posted (audit 3+4)
        (
            State::Credited | State::Reinstated,
            Event::Revoke {
                buyer_live: false, ..
            },
        ) => to_revoked(
            Some(row),
            None,
            ProtStoreLedgerPlan::None,
            None,
            ProtStoreAnswer::Revoked,
        ),
        (State::Credited | State::Reinstated, Event::Assign { .. } | Event::Release) => {
            Answer(ProtStoreAnswer::NotAssignable)
        }
        (State::Credited | State::Reinstated, Event::Reverse { .. } | Event::Unpause { .. }) => {
            ignored(Some(row), event)
        }

        // Revoked: never a credit path
        (State::Revoked, Event::Seen(_)) => Answer(ProtStoreAnswer::Refunded),
        // Already revoked: no second claw without a reversal in between
        (State::Revoked, Event::Revoke { .. }) => Answer(ProtStoreAnswer::Revoked),
        (State::Revoked, Event::Assign { .. } | Event::Release) => {
            Answer(ProtStoreAnswer::NotAssignable)
        }
        (State::Revoked, Event::Reverse { buyer_live }) => {
            plan_reversal(row, event, *buyer_live, reinstate_amount)
        }
        (State::Revoked, Event::Unpause { .. }) => ignored(Some(row), event),
    }
}

// --- Section 7.1: the one-transaction move ----------------------------------

pub const PROT_STORE_MOVE_RETRIES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtStoreMove {
    /// The row exactly as it must be stored after the move (`version` is ignored: the driver writes
    /// expected_version + 1, or 0 on insert)
    pub row: ProtStorePurchase,
    /// None = insert (no row may exist); Some(v) = CAS on `{_id, version: v}`
    pub expected_version: Option<u64>,
    /// Mark this intent Used (purchase_id = row.id) in the same transaction. Accepted from Open or Expired only,
    /// and only while its user_id still equals row.user_id; anything else is Conflict.
    /// Some(i) ONLY on the row's FIRST write (expected_version None) when the verdict resolved an Open or Expired
    /// intent: Credit, Hold, Reject{TestPurchase | UnknownProduct | BadPayload}, a tombstone whose token resolved.
    /// ALWAYS None for Reject{Unbound | NoBuyer} (a Used or unlinked intent) and for every CAS on an existing row
    /// (Held → Credited, Assign, Revoke, Reverse, Unpause) (audit 2+19).
    pub use_intent: Option<String>,
    pub ledger: ProtStoreLedger,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtStoreLedger {
    None,
    /// `purchase:{id}` or `reinstate:{id}:{gen}`: one Exact posting, sys:issued → user, kind Purchase
    Credit(ProtPosting),
    /// One refund generation: `posting` is the wallet part (kind Clawback, UpTo(total), user → sys:clawed,
    /// key `clawback:{key_base}`); the held-pledge drain then writes `clawback-hold:{key_base}:{pledge_id}`
    /// rows with ref.order_id = row.id (S5b's drain, section 7.3)
    Clawback {
        user_id: String,
        posting: ProtPosting,
        key_base: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum ProtStoreMoveOutcome {
    Applied {
        row: ProtStorePurchase,
        entries: Vec<ProtLedgerEntry>,
    },
    Conflict,
}

/// Test hook of `store_move_credit_is_one_transaction`: a store move of a row
/// whose id is listed here fails after its postings and before its row write,
/// in both drivers. Never armed outside the tests.
#[cfg(test)]
pub(in crate::models) static PROT_STORE_MOVE_CRASH: std::sync::Mutex<Vec<String>> =
    std::sync::Mutex::new(Vec::new());

/// Whether the test hook is armed for this row
#[cfg(test)]
pub(in crate::models) fn prot_store_move_crashes(id: &str) -> bool {
    PROT_STORE_MOVE_CRASH
        .lock()
        .map(|ids| ids.iter().any(|armed| armed == id))
        .unwrap_or(false)
}

/// Whether the test hook is armed for this row: never outside the tests
#[cfg(not(test))]
#[inline(always)]
pub(in crate::models) fn prot_store_move_crashes(_id: &str) -> bool {
    false
}

// --- Section 7.4: unconsumed Play credits in the held figure ----------------

/// Σ `prot` of the user's Play rows with `unconsumed: true` in Credited or
/// Reinstated whose `credited_at < since_ms` (newer ones are already in S5b's
/// ledger fold; R8). Saturating, never below 0.
pub(in crate::models) fn unconsumed_play_prot<'a>(
    rows: impl IntoIterator<Item = &'a ProtStorePurchase>,
    user_id: &str,
    since_ms: i64,
) -> i64 {
    rows.into_iter()
        .filter(|row| {
            row.store == v0::ProtStore::Play
                && row.unconsumed == Some(true)
                && matches!(
                    row.state,
                    v0::ProtStoreState::Credited | v0::ProtStoreState::Reinstated
                )
                && row.user_id.as_deref() == Some(user_id)
                && row.credited_at.is_some_and(|at| at < since_ms)
        })
        .fold(0_i64, |total, row| total.saturating_add(row.prot.max(0)))
        .max(0)
}

/// The Reference held-figure term (S5b's contribute and pledge lock sections
/// and the trait's `held_purchase_prot` add it)
pub(in crate::models) fn held_store_unconsumed_locked(
    purchases: &HashMap<String, ProtStorePurchase>,
    user_id: &str,
    since_ms: i64,
) -> i64 {
    unconsumed_play_prot(purchases.values(), user_id, since_ms)
}

/// The Mongo filter of the same rows (uses `prot_store_purchases_unconsumed`)
#[cfg(feature = "mongodb")]
pub(in crate::models) fn unconsumed_play_filter(user_id: &str, before_ms: i64) -> bson::Document {
    doc! {
        "unconsumed": true,
        "user_id": user_id,
        "store": v0::ProtStore::Play.as_str(),
        "state": {
            "$in": [
                v0::ProtStoreState::Credited.as_str(),
                v0::ProtStoreState::Reinstated.as_str()
            ]
        },
        "credited_at": { "$lt": before_ms }
    }
}

// --- Section 8: keys, generations, ids, countries ---------------------------

/// Store purchase credit: S5a's builder with the store id
pub fn prot_store_key_purchase(id: &str) -> String {
    prot_key_purchase(id)
}

/// Key base of refund generation `gen` (1-based): gen 1 = id, gen n >= 2 = "{id}:r{n}"
pub fn prot_store_refund_base(id: &str, gen: u32) -> String {
    if gen >= 2 {
        format!("{id}:r{gen}")
    } else {
        id.to_string()
    }
}

/// Wallet part of generation `gen`: prot_key_clawback(&prot_store_refund_base(id, gen))
pub fn prot_store_key_clawback(id: &str, gen: u32) -> String {
    prot_key_clawback(&prot_store_refund_base(id, gen))
}

/// Apple REFUND_REVERSED of generation `gen`
pub fn prot_store_key_reinstate(id: &str, gen: u32) -> String {
    format!("reinstate:{id}:{gen}")
}

/// A pledge id as the drain keys carry it: a 26-character ULID
fn is_ulid_like(value: &str) -> bool {
    value.len() == 26 && !value.starts_with('r') && value.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// A generation number as `:r{n}` carries it: n >= 2, decimal, no leading zero
fn generation_number(value: &str) -> Option<u32> {
    if value.is_empty() || value.starts_with('0') || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse::<u32>().ok().filter(|n| *n >= 2)
}

/// The refund generation of a `clawback:` / `clawback-hold:` row of purchase `id` (8.3): strip the prefix,
/// then `id`; remainder `""` or `":{ULID}"` → Some(1); `":r{n}"` or `":r{n}:{ULID}"` (n >= 2) → Some(n);
/// anything else None
pub fn prot_store_refund_gen_of(key: &str, id: &str) -> Option<u32> {
    let rest = key
        .strip_prefix("clawback:")
        .or_else(|| key.strip_prefix("clawback-hold:"))?
        .strip_prefix(id)?;
    if rest.is_empty() {
        return Some(1);
    }

    let rest = rest.strip_prefix(':')?;
    match rest.strip_prefix('r') {
        Some(numbered) => match numbered.split_once(':') {
            Some((n, pledge)) if is_ulid_like(pledge) => generation_number(n),
            Some(_) => None,
            None => generation_number(numbered),
        },
        None => is_ulid_like(rest).then_some(1),
    }
}

/// A store transaction id: 1..=20 ASCII digits that fit a UInt64
fn is_transaction_id(value: &str) -> bool {
    (1..=20).contains(&value.len())
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u64>().is_ok()
}

/// Exactly `apple:prod:{transactionId}`, `apple:sandbox:{transactionId}` or `play:{sha256hex}` (section 4)
pub fn is_store_purchase_id(id: &str) -> bool {
    if let Some(transaction_id) = id
        .strip_prefix("apple:prod:")
        .or_else(|| id.strip_prefix("apple:sandbox:"))
    {
        return is_transaction_id(transaction_id);
    }
    id.strip_prefix("play:").is_some_and(|hash| {
        hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Every two-letter uppercase pair in order (AA, AB, …, ZZ), so a Play region
/// code passes through as a `&'static str`
static ALPHA2_PAIRS: [u8; 26 * 26 * 2] = alpha2_pairs();

const fn alpha2_pairs() -> [u8; 26 * 26 * 2] {
    let mut pairs = [0_u8; 26 * 26 * 2];
    let mut i = 0;
    while i < 26 * 26 {
        pairs[2 * i] = b'A' + (i / 26) as u8;
        pairs[2 * i + 1] = b'A' + (i % 26) as u8;
        i += 1;
    }
    pairs
}

/// Apple storefront alpha-3 → alpha-2: exactly E1's 31 countries + US + BR (R6)
const APPLE_STOREFRONTS: [(&str, &str); 33] = [
    ("AUT", "AT"),
    ("BEL", "BE"),
    ("BGR", "BG"),
    ("HRV", "HR"),
    ("CYP", "CY"),
    ("CZE", "CZ"),
    ("DNK", "DK"),
    ("EST", "EE"),
    ("FIN", "FI"),
    ("FRA", "FR"),
    ("DEU", "DE"),
    ("GRC", "GR"),
    ("HUN", "HU"),
    ("IRL", "IE"),
    ("ITA", "IT"),
    ("LVA", "LV"),
    ("LTU", "LT"),
    ("LUX", "LU"),
    ("MLT", "MT"),
    ("NLD", "NL"),
    ("POL", "PL"),
    ("PRT", "PT"),
    ("ROU", "RO"),
    ("SVK", "SK"),
    ("SVN", "SI"),
    ("ESP", "ES"),
    ("SWE", "SE"),
    ("GBR", "GB"),
    ("NOR", "NO"),
    ("ISL", "IS"),
    ("LIE", "LI"),
    ("USA", "US"),
    ("BRA", "BR"),
];

/// ISO alpha-2 of a storefront: Play values (2 uppercase letters) pass through; Apple alpha-3 maps by the
/// 33-entry table; anything else None (R6)
pub fn store_country_alpha2(storefront: &str) -> Option<&'static str> {
    let bytes = storefront.as_bytes();
    if bytes.len() == 2 && bytes.iter().all(u8::is_ascii_uppercase) {
        let i = usize::from(bytes[0] - b'A') * 26 + usize::from(bytes[1] - b'A');
        return std::str::from_utf8(&ALPHA2_PAIRS[2 * i..2 * i + 2]).ok();
    }
    APPLE_STOREFRONTS
        .iter()
        .find(|(alpha3, _)| *alpha3 == storefront)
        .map(|(_, alpha2)| *alpha2)
}

// --- R49: the one move builder ----------------------------------------------

/// The row a Move plan stores (sections 6, 7.1): the plan's fields, plus what
/// the event carries (assigned_by, the refunds entry of every generation it
/// moves into, `unreinstated_reversals`) and `credited_at` / a first-sight
/// Play row's `unconsumed` on a credit
fn store_row_after(
    row: Option<&ProtStorePurchase>,
    seed: &ProtStorePurchase,
    event: &ProtStoreEvent,
    plan: &ProtStoreMovePlan,
    now: i64,
) -> Option<ProtStorePurchase> {
    let ProtStoreMovePlan::Move {
        to,
        reject_reason,
        user_id,
        intent_id,
        ledger,
        needs_action,
        clear_needs,
        unconsumed,
        ..
    } = plan
    else {
        return None;
    };

    let before = row.map(|row| row.state);
    let mut next = match row {
        Some(row) => row.clone(),
        None => ProtStorePurchase {
            created_at: now,
            version: 0,
            ..seed.clone()
        },
    };
    next.state = *to;
    next.reject_reason = *reject_reason;
    // R63: a move into Held records why (a verdict's reason; an assign while
    // paused is a pause hold, R16); every move out of Held clears it
    next.hold_reason = match (*to, event) {
        (v0::ProtStoreState::Held, ProtStoreEvent::Seen(ProtStoreVerdict::Hold { reason, .. })) => {
            Some(*reason)
        }
        (v0::ProtStoreState::Held, ProtStoreEvent::Assign { .. }) => {
            Some(v0::ProtStoreHoldReason::Paused)
        }
        (v0::ProtStoreState::Held, _) => next.hold_reason,
        _ => None,
    };
    if let Some(user_id) = user_id {
        next.user_id = Some(user_id.clone());
    }
    if let Some(intent_id) = intent_id {
        next.intent_id = Some(intent_id.clone());
    }
    if next
        .needs_action
        .as_deref()
        .is_some_and(|kind| clear_needs.contains(&kind))
    {
        next.needs_action = None;
    }
    if let Some(kind) = needs_action {
        next.needs_action = Some(kind.to_string());
    }
    match unconsumed {
        Some(true) => next.unconsumed = Some(true),
        Some(false) => next.unconsumed = None,
        None => {}
    }
    if matches!(ledger, ProtStoreLedgerPlan::Credit) {
        next.credited_at = Some(now);
        // First sight: the planner cannot know the store (R46)
        if row.is_none() && next.store == v0::ProtStore::Play {
            next.unconsumed = Some(true);
        }
    }

    match event {
        ProtStoreEvent::Assign { admin_id, .. } => next.assigned_by = Some(admin_id.clone()),
        ProtStoreEvent::Revoke {
            revocation_date,
            reason,
            buyer_live,
            ..
        } => {
            next.revoked_at = Some(now);
            next.revocation_reason = reason.clone();
            // A credited row moves into the next generation (clawed, or
            // `no_buyer` when the buyer is gone); anything else leaves the
            // gen-0 tombstone entry
            let generation = matches!(
                before,
                Some(v0::ProtStoreState::Credited | v0::ProtStoreState::Reinstated)
            );
            let gen = if generation {
                next.refund_gen.checked_add(1)?
            } else {
                0
            };
            next.refund_gen = next.refund_gen.max(gen);
            next.refunds.push(ProtStoreRefund {
                gen,
                at: now,
                revocation_date: *revocation_date,
                clawed: 0,
                shortfall: 0,
                reason: if generation && !buyer_live {
                    Some("no_buyer".to_string())
                } else {
                    reason.clone()
                },
            });
        }
        ProtStoreEvent::Reverse { .. } if *to == v0::ProtStoreState::Revoked => {
            next.unreinstated_reversals = next.unreinstated_reversals.saturating_add(1);
        }
        _ => {}
    }
    next.updated_at = now;
    Some(next)
}

/// One Exact credit to the row's user (8.2: `purchase:` and `reinstate:`)
fn store_credit_posting(
    key: String,
    row: &ProtStorePurchase,
    amount: i64,
    now: i64,
) -> ProtPosting {
    ProtPosting {
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
        created_at: now,
    }
}

/// The ledger part of a plan for the row it stores (8.2)
fn store_ledger_for(
    next: &ProtStorePurchase,
    plan: ProtStoreLedgerPlan,
    reinstate_amount: i64,
    now: i64,
) -> ProtStoreLedger {
    match plan {
        ProtStoreLedgerPlan::None => ProtStoreLedger::None,
        ProtStoreLedgerPlan::Credit => ProtStoreLedger::Credit(store_credit_posting(
            prot_store_key_purchase(&next.id),
            next,
            next.prot,
            now,
        )),
        ProtStoreLedgerPlan::Reinstate { gen } => ProtStoreLedger::Credit(store_credit_posting(
            prot_store_key_reinstate(&next.id, gen),
            next,
            reinstate_amount,
            now,
        )),
        ProtStoreLedgerPlan::Clawback { gen } => {
            let user_id = next.user_id.clone().unwrap_or_default();
            ProtStoreLedger::Clawback {
                // 8.2: total_n = row.prot (the engine asserts it first)
                posting: ProtPosting {
                    key: prot_store_key_clawback(&next.id, gen),
                    kind: v0::ProtEntryKind::Clawback,
                    debit: prot_user_account(&user_id),
                    credit: PROT_SYS_CLAWED.to_string(),
                    amount: ProtAmount::UpTo(next.prot),
                    debit_floor: 0,
                    actor: PROT_ACTOR_STORE.to_string(),
                    reference: ProtRef {
                        order_id: Some(next.id.clone()),
                        ..Default::default()
                    },
                    reason: None,
                    created_at: now,
                },
                user_id,
                key_base: prot_store_refund_base(&next.id, gen),
            }
        }
    }
}

/// THE move builder (R49): the move a plan describes, for `apply_store_purchase_move`. The engine and the tests
/// both call it; nothing builds a move by hand. It stamps `credited_at`, a first-sight Play credit's `unconsumed`,
/// `refund_gen` and the refunds entry of every generation (the gen-0 tombstone, `no_buyer`),
/// `unreinstated_reversals`, `assigned_by`, `hold_reason` (R63), and builds every posting (8.2). `seed` is the
/// purchase as first seen (store, product, prot, environment, store payloads; read only when `row` is None);
/// `reinstate_amount` is what
/// the row's latest generation clawed (8.3). `use_intent` is the plan's intent on a row's first write, never for
/// Reject{Unbound | NoBuyer} (audit 2+19). None for an Answer plan.
pub fn build_store_move(
    row: Option<&ProtStorePurchase>,
    seed: &ProtStorePurchase,
    event: &ProtStoreEvent,
    plan: &ProtStoreMovePlan,
    reinstate_amount: i64,
    now: i64,
) -> Option<ProtStoreMove> {
    let ProtStoreMovePlan::Move {
        ledger, intent_id, ..
    } = plan
    else {
        return None;
    };
    let next = store_row_after(row, seed, event, plan, now)?;

    let unbound = matches!(
        next.reject_reason,
        Some(v0::ProtStoreRejectReason::Unbound | v0::ProtStoreRejectReason::NoBuyer)
    );
    let use_intent = if row.is_none() && !unbound {
        intent_id.clone()
    } else {
        None
    };

    Some(ProtStoreMove {
        ledger: store_ledger_for(&next, *ledger, reinstate_amount, now),
        expected_version: row.map(|row| row.version),
        use_intent,
        row: next,
    })
}

/// Purchases as the tests first see them, and the row a plan stores
#[cfg(test)]
pub(super) mod test_support {
    use revolt_models::v0;

    use super::{
        build_store_move, ProtStoreApple, ProtStoreEvent, ProtStoreMovePlan, ProtStorePlay,
        ProtStorePurchase,
    };

    /// A purchase as first seen, before any plan stamps its state and user
    pub fn seed(id: &str, store: v0::ProtStore, prot: i64) -> ProtStorePurchase {
        let transaction_id = id.rsplit(':').next().unwrap_or_default().to_string();
        ProtStorePurchase {
            id: id.to_string(),
            store,
            user_id: None,
            intent_id: None,
            product_id: "gg.sloga.prot.p25".to_string(),
            prot,
            quantity: 1,
            environment: if id.starts_with("apple:sandbox:") {
                v0::ProtStoreEnvironment::Sandbox
            } else {
                v0::ProtStoreEnvironment::Production
            },
            storefront: None,
            country: None,
            state: v0::ProtStoreState::Rejected,
            reject_reason: None,
            hold_reason: None,
            refund_gen: 0,
            refunds: vec![],
            unreinstated_reversals: 0,
            apple: (store == v0::ProtStore::Apple).then(|| ProtStoreApple {
                transaction_id: transaction_id.clone(),
                original_transaction_id: transaction_id.clone(),
                app_account_token: None,
                signed_date: 0,
                purchase_date: 0,
            }),
            play: (store == v0::ProtStore::Play).then(|| ProtStorePlay {
                purchase_token: format!("token-{transaction_id}"),
                order_id: None,
                obfuscated_account_id: None,
                consumed_at: None,
                test: false,
                region_code: None,
            }),
            credited_at: None,
            unconsumed: None,
            revoked_at: None,
            revocation_reason: None,
            assigned_by: None,
            needs_action: None,
            alerted: vec![],
            created_at: 0,
            updated_at: 0,
            version: 0,
        }
    }

    /// The row `build_store_move` stores for a plan; None for an Answer
    pub fn row_after(
        row: Option<&ProtStorePurchase>,
        seed: &ProtStorePurchase,
        event: &ProtStoreEvent,
        plan: &ProtStoreMovePlan,
        now: i64,
    ) -> Option<ProtStorePurchase> {
        build_store_move(row, seed, event, plan, 0, now).map(|m| m.row)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rand::{rngs::StdRng, Rng, SeedableRng};
    use revolt_models::v0;

    use super::test_support::{row_after, seed};
    use super::*;

    const APPLE_ID: &str = "apple:prod:2000000000000001";
    const USER: &str = "01HZXS6W1L1C00000000000001";
    const OTHER: &str = "01HZXS6W1L1C00000000000002";
    const INTENT: &str = "01HZXS6W1L1C0000000000INT1";
    const ADMIN: &str = "01HZXS6W1L1C0000000000ADM1";

    fn row(state: v0::ProtStoreState) -> ProtStorePurchase {
        ProtStorePurchase {
            state,
            user_id: Some(USER.to_string()),
            intent_id: Some(INTENT.to_string()),
            ..seed(APPLE_ID, v0::ProtStore::Apple, 2_600)
        }
    }

    fn rejected(reason: v0::ProtStoreRejectReason) -> ProtStorePurchase {
        ProtStorePurchase {
            reject_reason: Some(reason),
            ..row(v0::ProtStoreState::Rejected)
        }
    }

    /// A Revoked row after `gen` clawed generations
    fn revoked(gen: u32) -> ProtStorePurchase {
        ProtStorePurchase {
            refund_gen: gen,
            refunds: (0..=gen)
                .skip(usize::from(gen > 0))
                .map(|g| ProtStoreRefund {
                    gen: g,
                    at: 100 + i64::from(g),
                    revocation_date: 50 + i64::from(g),
                    clawed: 0,
                    shortfall: 0,
                    reason: None,
                })
                .collect(),
            ..row(v0::ProtStoreState::Revoked)
        }
    }

    fn credit() -> ProtStoreEvent {
        ProtStoreEvent::Seen(ProtStoreVerdict::Credit {
            user_id: USER.to_string(),
            intent_id: INTENT.to_string(),
        })
    }

    fn hold() -> ProtStoreEvent {
        ProtStoreEvent::Seen(ProtStoreVerdict::Hold {
            user_id: USER.to_string(),
            intent_id: INTENT.to_string(),
            reason: v0::ProtStoreHoldReason::Paused,
        })
    }

    /// R63: a hold because the credit would take the wallet past its cap
    fn over_cap() -> ProtStoreEvent {
        ProtStoreEvent::Seen(ProtStoreVerdict::Hold {
            user_id: USER.to_string(),
            intent_id: INTENT.to_string(),
            reason: v0::ProtStoreHoldReason::OverCap,
        })
    }

    fn reject(reason: v0::ProtStoreRejectReason) -> ProtStoreEvent {
        ProtStoreEvent::Seen(ProtStoreVerdict::Reject {
            reason,
            user_id: Some(USER.to_string()),
            intent_id: None,
        })
    }

    fn revoke(date: i64, buyer_live: bool) -> ProtStoreEvent {
        ProtStoreEvent::Revoke {
            revocation_date: date,
            reason: Some("1".to_string()),
            user_hint: Some(OTHER.to_string()),
            intent_id: None,
            buyer_live,
        }
    }

    fn assign(paused: bool) -> ProtStoreEvent {
        ProtStoreEvent::Assign {
            user_id: OTHER.to_string(),
            admin_id: ADMIN.to_string(),
            paused,
        }
    }

    fn answer(plan: &ProtStoreMovePlan) -> ProtStoreAnswer {
        match plan {
            ProtStoreMovePlan::Answer(answer) => answer.clone(),
            ProtStoreMovePlan::Move { answer, .. } => answer.clone(),
        }
    }

    /// The (state, ledger) of a Move; None for an Answer
    fn moved(plan: &ProtStoreMovePlan) -> Option<(v0::ProtStoreState, ProtStoreLedgerPlan)> {
        match plan {
            ProtStoreMovePlan::Move { to, ledger, .. } => Some((*to, *ledger)),
            ProtStoreMovePlan::Answer(_) => None,
        }
    }

    fn is_answer(plan: &ProtStoreMovePlan, expected: ProtStoreAnswer) -> bool {
        *plan == ProtStoreMovePlan::Answer(expected)
    }

    /// Every move to Revoked clears both work items and unsets `unconsumed`
    fn assert_revoke_shape(
        plan: &ProtStoreMovePlan,
        reject_reason: Option<v0::ProtStoreRejectReason>,
    ) {
        let ProtStoreMovePlan::Move {
            to,
            reject_reason: kept,
            clear_needs,
            unconsumed,
            ..
        } = plan
        else {
            panic!("{plan:?}");
        };
        assert_eq!(*to, v0::ProtStoreState::Revoked);
        assert_eq!(*kept, reject_reason);
        assert_eq!(*clear_needs, CLEARED_BY_REVOKE);
        assert_eq!(*unconsumed, Some(false));
    }

    // --- one test per table row ---------------------------------------------

    #[test]
    fn none_seen_credit_credits_the_intents_user() {
        let plan = plan_store_move(None, &credit(), 0);
        assert_eq!(
            plan,
            ProtStoreMovePlan::Move {
                to: v0::ProtStoreState::Credited,
                reject_reason: None,
                user_id: Some(USER.to_string()),
                intent_id: Some(INTENT.to_string()),
                ledger: ProtStoreLedgerPlan::Credit,
                needs_action: None,
                clear_needs: &[],
                unconsumed: None,
                answer: ProtStoreAnswer::Credited,
            }
        );
    }

    #[test]
    fn none_seen_hold_records_a_held_row() {
        let plan = plan_store_move(None, &hold(), 0);
        assert_eq!(
            plan,
            ProtStoreMovePlan::Move {
                to: v0::ProtStoreState::Held,
                reject_reason: None,
                user_id: Some(USER.to_string()),
                intent_id: Some(INTENT.to_string()),
                ledger: ProtStoreLedgerPlan::None,
                needs_action: None,
                clear_needs: &[],
                unconsumed: None,
                answer: ProtStoreAnswer::Held,
            }
        );
    }

    #[test]
    fn none_seen_reject_records_the_reason_and_unbound_needs_action() {
        for reason in [
            v0::ProtStoreRejectReason::TestPurchase,
            v0::ProtStoreRejectReason::Unbound,
            v0::ProtStoreRejectReason::UnknownProduct,
            v0::ProtStoreRejectReason::BadPayload,
            v0::ProtStoreRejectReason::NoBuyer,
        ] {
            let plan = plan_store_move(None, &reject(reason), 0);
            let unbound = reason == v0::ProtStoreRejectReason::Unbound;
            assert_eq!(
                plan,
                ProtStoreMovePlan::Move {
                    to: v0::ProtStoreState::Rejected,
                    reject_reason: Some(reason),
                    user_id: Some(USER.to_string()),
                    intent_id: None,
                    ledger: ProtStoreLedgerPlan::None,
                    needs_action: unbound.then_some("unbound"),
                    clear_needs: &[],
                    unconsumed: None,
                    answer: ProtStoreAnswer::Rejected(reason),
                },
                "{reason:?}"
            );
        }
    }

    #[test]
    fn none_revoke_writes_a_tombstone_for_the_hinted_user() {
        let plan = plan_store_move(None, &revoke(70, true), 0);
        assert_revoke_shape(&plan, None);
        let ProtStoreMovePlan::Move {
            user_id,
            ledger,
            answer,
            ..
        } = &plan
        else {
            unreachable!()
        };
        assert_eq!(user_id.as_deref(), Some(OTHER));
        assert_eq!(*ledger, ProtStoreLedgerPlan::None);
        assert_eq!(*answer, ProtStoreAnswer::Revoked);

        // The row the engine stores: a gen-0 refunds entry, refund_gen 0
        let seeded = seed(APPLE_ID, v0::ProtStore::Apple, 2_600);
        let stored = row_after(None, &seeded, &revoke(70, true), &plan, 1_000).unwrap();
        assert_eq!(stored.refund_gen, 0);
        assert_eq!(stored.refunds.len(), 1);
        assert_eq!(
            (stored.refunds[0].gen, stored.refunds[0].revocation_date),
            (0, 70)
        );
    }

    #[test]
    fn none_reverse_unpause_and_assign_write_nothing() {
        for event in [
            ProtStoreEvent::Reverse { buyer_live: true },
            ProtStoreEvent::Unpause { buyer_live: true },
        ] {
            assert!(is_answer(
                &plan_store_move(None, &event, 0),
                ProtStoreAnswer::Ignored
            ));
        }
        assert!(is_answer(
            &plan_store_move(None, &assign(false), 0),
            ProtStoreAnswer::NotAssignable
        ));
    }

    #[test]
    fn held_seen_credit_and_unpause_credit_it() {
        let held = row(v0::ProtStoreState::Held);
        for event in [credit(), ProtStoreEvent::Unpause { buyer_live: true }] {
            let plan = plan_store_move(Some(&held), &event, 0);
            assert_eq!(
                plan,
                ProtStoreMovePlan::Move {
                    to: v0::ProtStoreState::Credited,
                    reject_reason: None,
                    user_id: None,
                    intent_id: None,
                    ledger: ProtStoreLedgerPlan::Credit,
                    needs_action: None,
                    clear_needs: &[],
                    unconsumed: None,
                    answer: ProtStoreAnswer::Credited,
                },
                "{event:?}"
            );
        }

        // A Play row is left to consume
        let play = ProtStorePurchase {
            store: v0::ProtStore::Play,
            ..held
        };
        let ProtStoreMovePlan::Move { unconsumed, .. } = plan_store_move(Some(&play), &credit(), 0)
        else {
            panic!()
        };
        assert_eq!(unconsumed, Some(true));
    }

    #[test]
    fn held_seen_hold_or_reject_stays_held() {
        let held = row(v0::ProtStoreState::Held);
        for event in [hold(), reject(v0::ProtStoreRejectReason::Unbound)] {
            assert!(is_answer(
                &plan_store_move(Some(&held), &event, 0),
                ProtStoreAnswer::Held
            ));
        }
    }

    #[test]
    fn held_unpause_without_a_buyer_is_rejected_no_buyer() {
        let plan = plan_store_move(
            Some(&row(v0::ProtStoreState::Held)),
            &ProtStoreEvent::Unpause { buyer_live: false },
            0,
        );
        assert_eq!(
            moved(&plan),
            Some((v0::ProtStoreState::Rejected, ProtStoreLedgerPlan::None))
        );
        let ProtStoreMovePlan::Move {
            reject_reason,
            answer,
            ..
        } = &plan
        else {
            unreachable!()
        };
        assert_eq!(*reject_reason, Some(v0::ProtStoreRejectReason::NoBuyer));
        assert_eq!(
            *answer,
            ProtStoreAnswer::Rejected(v0::ProtStoreRejectReason::NoBuyer)
        );
    }

    #[test]
    fn held_assign_is_not_assignable() {
        for paused in [false, true] {
            assert!(is_answer(
                &plan_store_move(Some(&row(v0::ProtStoreState::Held)), &assign(paused), 0),
                ProtStoreAnswer::NotAssignable
            ));
        }
    }

    #[test]
    fn held_revoke_writes_a_tombstone() {
        let plan = plan_store_move(Some(&row(v0::ProtStoreState::Held)), &revoke(70, true), 0);
        assert_revoke_shape(&plan, None);
        assert_eq!(moved(&plan).unwrap().1, ProtStoreLedgerPlan::None);
        assert_eq!(answer(&plan), ProtStoreAnswer::Revoked);
    }

    #[test]
    fn rejected_seen_answers_its_reason() {
        for reason in [
            v0::ProtStoreRejectReason::TestPurchase,
            v0::ProtStoreRejectReason::Unbound,
            v0::ProtStoreRejectReason::NoBuyer,
        ] {
            for event in [
                credit(),
                hold(),
                reject(v0::ProtStoreRejectReason::BadPayload),
            ] {
                assert!(is_answer(
                    &plan_store_move(Some(&rejected(reason)), &event, 0),
                    ProtStoreAnswer::Rejected(reason)
                ));
            }
        }
    }

    #[test]
    fn rejected_unbound_assign_credits_the_assigned_user() {
        let plan = plan_store_move(
            Some(&rejected(v0::ProtStoreRejectReason::Unbound)),
            &assign(false),
            0,
        );
        assert_eq!(
            plan,
            ProtStoreMovePlan::Move {
                to: v0::ProtStoreState::Credited,
                reject_reason: None,
                user_id: Some(OTHER.to_string()),
                intent_id: None,
                ledger: ProtStoreLedgerPlan::Credit,
                needs_action: None,
                clear_needs: &["unbound"],
                unconsumed: None,
                answer: ProtStoreAnswer::Credited,
            }
        );
    }

    #[test]
    fn rejected_unbound_assign_while_paused_records_held() {
        let plan = plan_store_move(
            Some(&rejected(v0::ProtStoreRejectReason::Unbound)),
            &assign(true),
            0,
        );
        assert_eq!(
            plan,
            ProtStoreMovePlan::Move {
                to: v0::ProtStoreState::Held,
                reject_reason: None,
                user_id: Some(OTHER.to_string()),
                intent_id: None,
                ledger: ProtStoreLedgerPlan::None,
                needs_action: None,
                clear_needs: &["unbound"],
                unconsumed: None,
                answer: ProtStoreAnswer::Held,
            }
        );
    }

    #[test]
    fn rejected_other_assign_is_not_assignable() {
        for reason in [
            v0::ProtStoreRejectReason::TestPurchase,
            v0::ProtStoreRejectReason::UnknownProduct,
            v0::ProtStoreRejectReason::BadPayload,
            v0::ProtStoreRejectReason::NoBuyer,
        ] {
            assert!(is_answer(
                &plan_store_move(Some(&rejected(reason)), &assign(false), 0),
                ProtStoreAnswer::NotAssignable
            ));
        }
    }

    #[test]
    fn rejected_revoke_keeps_the_reject_reason() {
        for reason in [
            v0::ProtStoreRejectReason::TestPurchase,
            v0::ProtStoreRejectReason::Unbound,
        ] {
            let plan = plan_store_move(Some(&rejected(reason)), &revoke(70, true), 0);
            assert_revoke_shape(&plan, Some(reason));
            assert_eq!(answer(&plan), ProtStoreAnswer::Revoked);
        }
    }

    #[test]
    fn credited_or_reinstated_seen_is_already_credited() {
        for state in [v0::ProtStoreState::Credited, v0::ProtStoreState::Reinstated] {
            for event in [credit(), hold(), reject(v0::ProtStoreRejectReason::Unbound)] {
                assert!(is_answer(
                    &plan_store_move(Some(&row(state)), &event, 0),
                    ProtStoreAnswer::AlreadyCredited
                ));
            }
        }
    }

    #[test]
    fn credited_revoke_with_a_buyer_claws_the_next_generation() {
        let first = plan_store_move(
            Some(&row(v0::ProtStoreState::Credited)),
            &revoke(70, true),
            0,
        );
        assert_revoke_shape(&first, None);
        assert_eq!(
            moved(&first).unwrap().1,
            ProtStoreLedgerPlan::Clawback { gen: 1 }
        );

        let reinstated = ProtStorePurchase {
            refund_gen: 1,
            ..row(v0::ProtStoreState::Reinstated)
        };
        let second = plan_store_move(Some(&reinstated), &revoke(80, true), 0);
        assert_eq!(
            moved(&second).unwrap().1,
            ProtStoreLedgerPlan::Clawback { gen: 2 }
        );
        assert_eq!(answer(&second), ProtStoreAnswer::Revoked);
    }

    #[test]
    fn credited_revoke_without_a_buyer_records_a_generation_and_posts_nothing() {
        let credited = ProtStorePurchase {
            user_id: None,
            ..row(v0::ProtStoreState::Credited)
        };
        let event = revoke(70, false);
        let plan = plan_store_move(Some(&credited), &event, 0);
        assert_revoke_shape(&plan, None);
        assert_eq!(moved(&plan).unwrap().1, ProtStoreLedgerPlan::None);

        let stored = row_after(Some(&credited), &credited, &event, &plan, 1_000).unwrap();
        assert_eq!(stored.refund_gen, 1);
        assert_eq!(stored.refunds[0].reason.as_deref(), Some("no_buyer"));
    }

    #[test]
    fn credited_reverse_unpause_and_assign_write_nothing() {
        for state in [v0::ProtStoreState::Credited, v0::ProtStoreState::Reinstated] {
            for event in [
                ProtStoreEvent::Reverse { buyer_live: true },
                ProtStoreEvent::Unpause { buyer_live: true },
            ] {
                assert!(is_answer(
                    &plan_store_move(Some(&row(state)), &event, 0),
                    ProtStoreAnswer::Ignored
                ));
            }
            assert!(is_answer(
                &plan_store_move(Some(&row(state)), &assign(false), 0),
                ProtStoreAnswer::NotAssignable
            ));
        }
    }

    #[test]
    fn revoked_seen_is_refunded_never_credited() {
        for gen in [0, 1, 2] {
            for event in [credit(), hold(), reject(v0::ProtStoreRejectReason::Unbound)] {
                assert!(is_answer(
                    &plan_store_move(Some(&revoked(gen)), &event, 0),
                    ProtStoreAnswer::Refunded
                ));
            }
        }
    }

    #[test]
    fn replayed_refund_is_a_no_op() {
        // Every state with a recorded date: the same date never moves
        let mut credited = row(v0::ProtStoreState::Credited);
        credited.refund_gen = 1;
        credited.refunds = revoked(1).refunds;
        // A REFUND replayed after its reversal must not claw a second time
        let reinstated = ProtStorePurchase {
            state: v0::ProtStoreState::Reinstated,
            ..revoked(2)
        };
        let mut rows = vec![revoked(0), revoked(1), revoked(2), credited, reinstated];
        for state in [v0::ProtStoreState::Held, v0::ProtStoreState::Rejected] {
            let mut tombstoned = row(state);
            tombstoned.refunds = revoked(0).refunds;
            rows.push(tombstoned);
        }
        for stored in &rows {
            for refund in &stored.refunds {
                for buyer_live in [true, false] {
                    let plan = plan_store_move(
                        Some(stored),
                        &revoke(refund.revocation_date, buyer_live),
                        0,
                    );
                    assert!(
                        is_answer(&plan, ProtStoreAnswer::Revoked),
                        "{stored:?} {plan:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn revoked_revoke_with_a_new_date_is_already_revoked() {
        for gen in [0, 1] {
            assert!(is_answer(
                &plan_store_move(Some(&revoked(gen)), &revoke(999, true), 0),
                ProtStoreAnswer::Revoked
            ));
        }
    }

    #[test]
    fn revoked_assign_is_not_assignable() {
        let mut unbound = revoked(0);
        unbound.reject_reason = Some(v0::ProtStoreRejectReason::Unbound);
        for stored in [revoked(0), revoked(1), unbound] {
            assert!(is_answer(
                &plan_store_move(Some(&stored), &assign(false), 0),
                ProtStoreAnswer::NotAssignable
            ));
        }
    }

    #[test]
    fn revoked_reverse_with_a_buyer_reinstates_what_was_clawed() {
        let plan = plan_store_move(
            Some(&revoked(2)),
            &ProtStoreEvent::Reverse { buyer_live: true },
            2_600,
        );
        assert_eq!(
            moved(&plan),
            Some((
                v0::ProtStoreState::Reinstated,
                ProtStoreLedgerPlan::Reinstate { gen: 2 }
            ))
        );
        assert_eq!(answer(&plan), ProtStoreAnswer::Reinstated);
    }

    #[test]
    fn revoked_reverse_of_a_generation_that_clawed_nothing_reinstates_with_no_ledger() {
        let plan = plan_store_move(
            Some(&revoked(1)),
            &ProtStoreEvent::Reverse { buyer_live: true },
            0,
        );
        assert_eq!(
            moved(&plan),
            Some((v0::ProtStoreState::Reinstated, ProtStoreLedgerPlan::None))
        );
        assert_eq!(answer(&plan), ProtStoreAnswer::Reinstated);
    }

    #[test]
    fn revoked_reverse_without_a_buyer_counts_once_and_stays_revoked() {
        let event = ProtStoreEvent::Reverse { buyer_live: false };
        let stored = revoked(1);
        let plan = plan_store_move(Some(&stored), &event, 2_600);
        assert_revoke_shape(&plan, None);
        let ProtStoreMovePlan::Move {
            ledger,
            needs_action,
            answer,
            ..
        } = &plan
        else {
            unreachable!()
        };
        assert_eq!(*ledger, ProtStoreLedgerPlan::None);
        assert_eq!(*needs_action, None);
        assert_eq!(*answer, ProtStoreAnswer::Ignored);

        let next = row_after(Some(&stored), &stored, &event, &plan, 1_000).unwrap();
        assert_eq!(next.unreinstated_reversals, 1);
        assert!(is_answer(
            &plan_store_move(Some(&next), &event, 2_600),
            ProtStoreAnswer::Ignored
        ));
    }

    #[test]
    fn sandbox_tombstone_reversal_counts_once_without_a_work_item() {
        let event = ProtStoreEvent::Reverse { buyer_live: true };
        let mut sandbox = revoked(0);
        sandbox.environment = v0::ProtStoreEnvironment::Sandbox;
        let mut test = revoked(0);
        test.reject_reason = Some(v0::ProtStoreRejectReason::TestPurchase);
        for stored in [sandbox, test] {
            let plan = plan_store_move(Some(&stored), &event, 0);
            assert_revoke_shape(&plan, stored.reject_reason);
            let ProtStoreMovePlan::Move {
                needs_action,
                answer,
                ..
            } = &plan
            else {
                unreachable!()
            };
            assert_eq!(*needs_action, None);
            assert_eq!(*answer, ProtStoreAnswer::Ignored);

            let next = row_after(Some(&stored), &stored, &event, &plan, 1_000).unwrap();
            assert_eq!(next.unreinstated_reversals, 1);
            assert!(is_answer(
                &plan_store_move(Some(&next), &event, 0),
                ProtStoreAnswer::Ignored
            ));
        }
    }

    #[test]
    fn tombstone_reversal_opens_reversed_unpaid_once() {
        for buyer_live in [true, false] {
            let event = ProtStoreEvent::Reverse { buyer_live };
            let stored = revoked(0);
            let plan = plan_store_move(Some(&stored), &event, 0);
            assert_revoke_shape(&plan, None);
            let ProtStoreMovePlan::Move {
                needs_action,
                answer,
                ..
            } = &plan
            else {
                unreachable!()
            };
            assert_eq!(*needs_action, Some("reversed_unpaid"));
            assert_eq!(*answer, ProtStoreAnswer::Ignored);

            // Staff resolve the work item; a History replay of the same
            // reversal never re-opens it
            let mut next = row_after(Some(&stored), &stored, &event, &plan, 1_000).unwrap();
            assert_eq!(next.needs_action.as_deref(), Some("reversed_unpaid"));
            next.needs_action = None;
            assert!(is_answer(
                &plan_store_move(Some(&next), &event, 0),
                ProtStoreAnswer::Ignored
            ));
        }
    }

    #[test]
    fn revoked_unpause_writes_nothing() {
        assert!(is_answer(
            &plan_store_move(
                Some(&revoked(1)),
                &ProtStoreEvent::Unpause { buyer_live: true },
                0
            ),
            ProtStoreAnswer::Ignored
        ));
    }

    #[test]
    fn every_move_to_revoked_clears_both_work_items() {
        let mut unbound = rejected(v0::ProtStoreRejectReason::Unbound);
        unbound.needs_action = Some("unbound".to_string());
        let event = revoke(70, true);
        let plan = plan_store_move(Some(&unbound), &event, 0);
        let next = row_after(Some(&unbound), &unbound, &event, &plan, 1_000).unwrap();
        assert_eq!(next.needs_action, None);

        let mut play = row(v0::ProtStoreState::Credited);
        play.store = v0::ProtStore::Play;
        play.unconsumed = Some(true);
        play.needs_action = Some("play_unconsumed_24h".to_string());
        let plan = plan_store_move(Some(&play), &event, 0);
        let next = row_after(Some(&play), &play, &event, &plan, 1_000).unwrap();
        assert_eq!((next.needs_action, next.unconsumed), (None, None));

        // Another kind stays (one kind at a time; staff clear it)
        let mut review = row(v0::ProtStoreState::Credited);
        review.needs_action = Some("chargeback_review".to_string());
        let plan = plan_store_move(Some(&review), &event, 0);
        let next = row_after(Some(&review), &review, &event, &plan, 1_000).unwrap();
        assert_eq!(next.needs_action.as_deref(), Some("chargeback_review"));
    }

    // --- R63: over-cap holds -------------------------------------------------

    /// A Held row as `build_store_move` first writes it for `event`
    fn first_held(event: &ProtStoreEvent) -> ProtStorePurchase {
        let seeded = seed(APPLE_ID, v0::ProtStore::Apple, 2_600);
        let plan = plan_store_move(None, event, 0);
        row_after(None, &seeded, event, &plan, 1_000).expect("a Held row")
    }

    #[test]
    fn over_cap_hold_is_staff_work_that_no_automatic_credit_moves() {
        let plan = plan_store_move(None, &over_cap(), 0);
        assert_eq!(
            plan,
            ProtStoreMovePlan::Move {
                to: v0::ProtStoreState::Held,
                reject_reason: None,
                user_id: Some(USER.to_string()),
                intent_id: Some(INTENT.to_string()),
                ledger: ProtStoreLedgerPlan::None,
                needs_action: Some("over_cap_review"),
                clear_needs: &[],
                unconsumed: None,
                answer: ProtStoreAnswer::Held,
            }
        );
        let held = first_held(&over_cap());
        assert_eq!(held.state, v0::ProtStoreState::Held);
        assert_eq!(held.hold_reason, Some(v0::ProtStoreHoldReason::OverCap));
        assert_eq!(held.needs_action.as_deref(), Some("over_cap_review"));
        assert_eq!(held.credited_at, None);

        // A pause hold records its reason and is no staff work
        let paused = first_held(&hold());
        assert_eq!(paused.hold_reason, Some(v0::ProtStoreHoldReason::Paused));
        assert_eq!(paused.needs_action, None);

        // Nothing automatic credits it: a verify or replay that would now fit
        // the cap, the end of a pause, another verdict
        for event in [
            credit(),
            ProtStoreEvent::Unpause { buyer_live: true },
            over_cap(),
            hold(),
        ] {
            let plan = plan_store_move(Some(&held), &event, 0);
            assert!(
                is_answer(&plan, ProtStoreAnswer::Held),
                "{event:?}: {plan:?}"
            );
        }
        assert!(is_answer(
            &plan_store_move(Some(&held), &assign(false), 0),
            ProtStoreAnswer::NotAssignable
        ));
        assert!(is_answer(
            &plan_store_move(
                Some(&held),
                &ProtStoreEvent::Reverse { buyer_live: true },
                0
            ),
            ProtStoreAnswer::Ignored
        ));
    }

    #[test]
    fn release_credits_only_an_over_cap_hold() {
        let held = first_held(&over_cap());
        let plan = plan_store_move(Some(&held), &ProtStoreEvent::Release, 0);
        assert_eq!(
            moved(&plan),
            Some((v0::ProtStoreState::Credited, ProtStoreLedgerPlan::Credit))
        );
        let ProtStoreMovePlan::Move { clear_needs, .. } = &plan else {
            panic!("{plan:?}");
        };
        assert_eq!(*clear_needs, CLEARED_BY_RELEASE);
        let m = build_store_move(
            Some(&held),
            &held,
            &ProtStoreEvent::Release,
            &plan,
            0,
            2_000,
        )
        .expect("a move");
        assert_eq!(m.row.state, v0::ProtStoreState::Credited);
        assert_eq!(m.row.hold_reason, None);
        assert_eq!(m.row.needs_action, None);
        assert_eq!(m.row.credited_at, Some(2_000));
        assert_eq!(m.row.user_id.as_deref(), Some(USER));
        assert_eq!(m.expected_version, Some(held.version));
        assert_eq!(m.use_intent, None);
        let ProtStoreLedger::Credit(posting) = &m.ledger else {
            panic!("{:?}", m.ledger);
        };
        assert_eq!(posting.key, prot_store_key_purchase(APPLE_ID));
        assert_eq!(posting.amount, ProtAmount::Exact(2_600));
        assert_eq!(posting.credit, prot_user_account(USER));

        // A pause hold (and a legacy one), and every other state: not releasable
        let paused = first_held(&hold());
        let legacy = ProtStorePurchase {
            hold_reason: None,
            ..paused.clone()
        };
        for row in [
            paused,
            legacy,
            row(v0::ProtStoreState::Credited),
            row(v0::ProtStoreState::Reinstated),
            rejected(v0::ProtStoreRejectReason::Unbound),
            revoked(1),
        ] {
            assert!(
                is_answer(
                    &plan_store_move(Some(&row), &ProtStoreEvent::Release, 0),
                    ProtStoreAnswer::NotAssignable
                ),
                "{:?} {:?}",
                row.state,
                row.hold_reason
            );
        }
        assert!(is_answer(
            &plan_store_move(None, &ProtStoreEvent::Release, 0),
            ProtStoreAnswer::NotAssignable
        ));
    }

    #[test]
    fn pause_hold_over_the_cap_becomes_an_over_cap_hold() {
        let mut paused = first_held(&hold());
        paused.needs_action = Some("play_held_24h".to_string());
        let legacy = ProtStorePurchase {
            hold_reason: None,
            needs_action: None,
            ..paused.clone()
        };
        for row in [paused.clone(), legacy] {
            let plan = plan_store_move(Some(&row), &over_cap(), 0);
            assert_eq!(
                moved(&plan),
                Some((v0::ProtStoreState::Held, ProtStoreLedgerPlan::None))
            );
            let m = build_store_move(Some(&row), &row, &over_cap(), &plan, 0, 3_000).unwrap();
            assert_eq!(m.row.hold_reason, Some(v0::ProtStoreHoldReason::OverCap));
            assert_eq!(m.row.needs_action.as_deref(), Some("over_cap_review"));
            assert_eq!(m.row.user_id, row.user_id);
            assert_eq!(m.row.intent_id, row.intent_id);
            assert_eq!(m.row.credited_at, None);
            assert_eq!(m.ledger, ProtStoreLedger::None);
            assert_eq!(m.use_intent, None);
        }

        // Under the cap a pause hold still credits, and leaves Held
        let plan = plan_store_move(Some(&paused), &credit(), 0);
        let next = row_after(Some(&paused), &paused, &credit(), &plan, 3_000).unwrap();
        assert_eq!(next.state, v0::ProtStoreState::Credited);
        assert_eq!(next.hold_reason, None);
    }

    #[test]
    fn refund_of_an_over_cap_hold_clears_its_review_and_credits_nothing() {
        let held = first_held(&over_cap());
        let event = revoke(80, true);
        let plan = plan_store_move(Some(&held), &event, 0);
        assert_revoke_shape(&plan, None);
        let m = build_store_move(Some(&held), &held, &event, &plan, 0, 4_000).unwrap();
        assert_eq!(m.row.state, v0::ProtStoreState::Revoked);
        assert_eq!(m.row.hold_reason, None);
        assert_eq!(m.row.needs_action, None);
        assert_eq!(m.ledger, ProtStoreLedger::None);
        assert_eq!(m.row.refund_gen, 0);
    }

    #[test]
    fn assign_while_paused_records_a_pause_hold() {
        let unbound = rejected(v0::ProtStoreRejectReason::Unbound);
        let plan = plan_store_move(Some(&unbound), &assign(true), 0);
        let next = row_after(Some(&unbound), &unbound, &assign(true), &plan, 5_000).unwrap();
        assert_eq!(next.state, v0::ProtStoreState::Held);
        assert_eq!(next.hold_reason, Some(v0::ProtStoreHoldReason::Paused));

        let plan = plan_store_move(Some(&unbound), &assign(false), 0);
        let next = row_after(Some(&unbound), &unbound, &assign(false), &plan, 5_000).unwrap();
        assert_eq!(next.state, v0::ProtStoreState::Credited);
        assert_eq!(next.hold_reason, None);
    }

    // --- property tests -----------------------------------------------------

    fn random_event(rng: &mut StdRng, dates: &[i64]) -> ProtStoreEvent {
        let user = if rng.gen_bool(0.5) { USER } else { OTHER };
        match rng.gen_range(0..9) {
            0 => credit(),
            1 => hold(),
            2 => reject(match rng.gen_range(0..5) {
                0 => v0::ProtStoreRejectReason::TestPurchase,
                1 => v0::ProtStoreRejectReason::Unbound,
                2 => v0::ProtStoreRejectReason::UnknownProduct,
                3 => v0::ProtStoreRejectReason::BadPayload,
                _ => v0::ProtStoreRejectReason::NoBuyer,
            }),
            3 | 4 => {
                // Replays of recorded dates half of the time
                let date = if !dates.is_empty() && rng.gen_bool(0.5) {
                    dates[rng.gen_range(0..dates.len())]
                } else {
                    rng.gen_range(1..1_000_000)
                };
                ProtStoreEvent::Revoke {
                    revocation_date: date,
                    reason: None,
                    user_hint: Some(user.to_string()),
                    intent_id: None,
                    buyer_live: rng.gen_bool(0.8),
                }
            }
            5 | 6 => ProtStoreEvent::Reverse {
                buyer_live: rng.gen_bool(0.8),
            },
            7 => ProtStoreEvent::Unpause {
                buyer_live: rng.gen_bool(0.8),
            },
            _ => ProtStoreEvent::Assign {
                user_id: user.to_string(),
                admin_id: ADMIN.to_string(),
                paused: rng.gen_bool(0.3),
            },
        }
    }

    /// Random sequences through the planner and the engine's row rule: a row
    /// that was ever Revoked is never planned a `Credit` again, a generation
    /// is clawed at most once, and a replayed Revoke never moves
    #[test]
    fn no_event_sequence_credits_a_revoked_row_or_claws_a_generation_twice() {
        let mut rng = StdRng::seed_from_u64(0x56_31_4c_31_63);
        for _ in 0..2_000 {
            let seeded = seed(APPLE_ID, v0::ProtStore::Apple, 2_600);
            let mut stored: Option<ProtStorePurchase> = None;
            let mut ever_revoked = false;
            let mut clawed: HashSet<u32> = HashSet::new();

            for step in 0..30 {
                let dates: Vec<i64> = stored
                    .iter()
                    .flat_map(|row| row.refunds.iter().map(|refund| refund.revocation_date))
                    .collect();
                let event = random_event(&mut rng, &dates);
                let amount = if rng.gen_bool(0.5) { 2_600 } else { 0 };
                let plan = plan_store_move(stored.as_ref(), &event, amount);

                if let ProtStoreEvent::Revoke {
                    revocation_date, ..
                } = &event
                {
                    if dates.contains(revocation_date) {
                        assert!(
                            is_answer(&plan, ProtStoreAnswer::Revoked),
                            "{event:?} {plan:?}"
                        );
                    }
                }
                if let Some((_, ledger)) = moved(&plan) {
                    match ledger {
                        ProtStoreLedgerPlan::Credit => {
                            assert!(
                                !ever_revoked,
                                "credit after a revocation: {stored:?} {event:?}"
                            )
                        }
                        ProtStoreLedgerPlan::Clawback { gen } => {
                            assert!(clawed.insert(gen), "generation {gen} clawed twice")
                        }
                        _ => {}
                    }
                }

                if let Some(next) = row_after(stored.as_ref(), &seeded, &event, &plan, 1_000 + step)
                {
                    ever_revoked |= next.state == v0::ProtStoreState::Revoked;
                    stored = Some(next);
                }
            }
        }
    }

    // --- keys, generations, ids, countries ------------------------------------

    #[test]
    fn store_keys_name_each_generation() {
        let id = format!("play:{}", "ab".repeat(32));
        assert_eq!(prot_store_key_purchase(&id), format!("purchase:{id}"));
        assert_eq!(prot_store_refund_base(&id, 1), id);
        assert_eq!(prot_store_refund_base(&id, 2), format!("{id}:r2"));
        assert_eq!(prot_store_key_clawback(&id, 1), format!("clawback:{id}"));
        assert_eq!(prot_store_key_clawback(&id, 3), format!("clawback:{id}:r3"));
        assert_eq!(
            prot_store_key_reinstate(&id, 2),
            format!("reinstate:{id}:2")
        );

        // 8.4: the longest key fits S5a's 255 bytes
        let longest = crate::prot_key_clawback_hold(
            &prot_store_refund_base(&id, 9),
            "01HZXS6W1L1C00000000000000",
        );
        assert_eq!(longest.len(), 113);
    }

    #[test]
    fn refund_gen_of_reads_the_generation_from_the_key() {
        let id = APPLE_ID;
        let pledge = "01HZXS6W1L1C0000000000PLG1";
        let hold = |base: &str| crate::prot_key_clawback_hold(base, pledge);
        assert_eq!(
            prot_store_refund_gen_of(&prot_store_key_clawback(id, 1), id),
            Some(1)
        );
        assert_eq!(prot_store_refund_gen_of(&hold(id), id), Some(1));
        assert_eq!(
            prot_store_refund_gen_of(&prot_store_key_clawback(id, 2), id),
            Some(2)
        );
        assert_eq!(
            prot_store_refund_gen_of(&prot_store_key_clawback(id, 12), id),
            Some(12)
        );
        assert_eq!(
            prot_store_refund_gen_of(&hold(&prot_store_refund_base(id, 3)), id),
            Some(3)
        );

        for key in [
            prot_store_key_purchase(id),
            prot_store_key_reinstate(id, 1),
            format!("clawback:{id}:r1"),
            format!("clawback:{id}:r02"),
            format!("clawback:{id}:r"),
            format!("clawback:{id}:rx"),
            format!("clawback:{id}:r2:short"),
            format!("clawback:{id}:extra"),
            format!("clawback:{id}9"),
            "clawback:apple:prod:2000000000000002".to_string(),
            format!("forfeit:{id}"),
        ] {
            assert_eq!(prot_store_refund_gen_of(&key, id), None, "{key}");
        }
    }

    #[test]
    fn store_purchase_ids_have_exactly_three_shapes() {
        for id in [
            "apple:prod:1",
            "apple:prod:18446744073709551615",
            "apple:sandbox:2000000000000001",
            &format!("play:{}", "0123456789abcdef".repeat(4)),
        ] {
            assert!(is_store_purchase_id(id), "{id}");
        }
        for id in [
            "apple:prod:",
            "apple:prod:18446744073709551616",
            "apple:prod:123456789012345678901",
            "apple:prod:12a",
            "apple:xcode:1",
            "apple:1",
            &format!("play:{}", "0123456789ABCDEF".repeat(4)),
            &format!("play:{}", "ab".repeat(31)),
            "01ORDS6W1L1C00000000000000",
            "",
        ] {
            assert!(!is_store_purchase_id(id), "{id}");
        }
    }

    #[test]
    fn storefronts_map_to_alpha2() {
        assert_eq!(APPLE_STOREFRONTS.len(), 33);
        assert_eq!(store_country_alpha2("DEU"), Some("DE"));
        assert_eq!(store_country_alpha2("USA"), Some("US"));
        assert_eq!(store_country_alpha2("BRA"), Some("BR"));
        assert_eq!(store_country_alpha2("LIE"), Some("LI"));
        assert_eq!(store_country_alpha2("CHE"), None);
        assert_eq!(store_country_alpha2("deu"), None);
        // Play region codes pass through
        assert_eq!(store_country_alpha2("DE"), Some("DE"));
        assert_eq!(store_country_alpha2("AA"), Some("AA"));
        assert_eq!(store_country_alpha2("ZZ"), Some("ZZ"));
        assert_eq!(store_country_alpha2("de"), None);
        assert_eq!(store_country_alpha2("D"), None);
        assert_eq!(store_country_alpha2(""), None);

        let mut seen = HashSet::new();
        for (alpha3, alpha2) in APPLE_STOREFRONTS {
            assert!(seen.insert(alpha3), "{alpha3} twice");
            assert_eq!(store_country_alpha2(alpha2), Some(alpha2));
        }
    }

    /// R49: the one builder stamps the row and builds every posting
    #[test]
    fn build_store_move_stamps_the_row_and_its_postings() {
        let apple_seed = seed(APPLE_ID, v0::ProtStore::Apple, 2_600);

        // First sight: the intent goes with the first write, credited_at
        // is the posting's instant
        let event = credit();
        let plan = plan_store_move(None, &event, 0);
        let m = build_store_move(None, &apple_seed, &event, &plan, 0, 1_000).unwrap();
        assert_eq!(m.expected_version, None);
        assert_eq!(m.use_intent.as_deref(), Some(INTENT));
        assert_eq!((m.row.created_at, m.row.credited_at), (1_000, Some(1_000)));
        assert_eq!(m.row.unconsumed, None);
        let ProtStoreLedger::Credit(posting) = &m.ledger else {
            panic!("{m:?}");
        };
        assert_eq!(posting.key, prot_store_key_purchase(APPLE_ID));
        assert_eq!(posting.amount, crate::ProtAmount::Exact(2_600));
        assert_eq!(posting.created_at, 1_000);
        assert_eq!(posting.actor, PROT_ACTOR_STORE);
        assert_eq!(posting.credit, crate::prot_user_account(USER));

        // A first-sight Play credit is left to consume
        let play_id = format!("play:{}", "c".repeat(64));
        let play_seed = seed(&play_id, v0::ProtStore::Play, 2_600);
        let m = build_store_move(None, &play_seed, &event, &plan, 0, 1_000).unwrap();
        assert_eq!(m.row.unconsumed, Some(true));

        // An unbound purchase records the intent its token matched, never uses it
        let unbound = ProtStoreEvent::Seen(ProtStoreVerdict::Reject {
            reason: v0::ProtStoreRejectReason::Unbound,
            user_id: None,
            intent_id: Some(INTENT.to_string()),
        });
        let plan = plan_store_move(None, &unbound, 0);
        let m = build_store_move(None, &apple_seed, &unbound, &plan, 0, 1_000).unwrap();
        assert_eq!(
            (m.use_intent, m.row.intent_id.as_deref()),
            (None, Some(INTENT))
        );

        // A refund of a credited row: the next generation, its entry, its clawback
        let credited = ProtStorePurchase {
            version: 4,
            ..row(v0::ProtStoreState::Credited)
        };
        let event = revoke(70, true);
        let plan = plan_store_move(Some(&credited), &event, 0);
        let m = build_store_move(Some(&credited), &credited, &event, &plan, 0, 2_000).unwrap();
        assert_eq!((m.expected_version, m.use_intent.as_ref()), (Some(4), None));
        assert_eq!((m.row.refund_gen, m.row.refunds.len()), (1, 1));
        assert_eq!(m.row.refunds[0].revocation_date, 70);
        let ProtStoreLedger::Clawback {
            user_id,
            posting,
            key_base,
        } = &m.ledger
        else {
            panic!("{m:?}");
        };
        assert_eq!(user_id, USER);
        assert_eq!(posting.key, prot_store_key_clawback(APPLE_ID, 1));
        assert_eq!(*key_base, prot_store_refund_base(APPLE_ID, 1));
        assert_eq!(posting.amount, crate::ProtAmount::UpTo(2_600));

        // Its reversal re-credits what the generation clawed
        let reverse = ProtStoreEvent::Reverse { buyer_live: true };
        let plan = plan_store_move(Some(&m.row), &reverse, 1_900);
        let back =
            build_store_move(Some(&m.row), &credited, &reverse, &plan, 1_900, 3_000).unwrap();
        assert_eq!(back.row.state, v0::ProtStoreState::Reinstated);
        let ProtStoreLedger::Credit(posting) = &back.ledger else {
            panic!("{back:?}");
        };
        assert_eq!(posting.key, prot_store_key_reinstate(APPLE_ID, 1));
        assert_eq!(posting.amount, crate::ProtAmount::Exact(1_900));

        // An Answer builds nothing
        let plan = plan_store_move(Some(&credited), &credit(), 0);
        assert_eq!(
            build_store_move(Some(&credited), &credited, &credit(), &plan, 0, 1),
            None
        );
    }

    /// R53: a tombstone uses the intent its refund's token resolved to; an
    /// existing row never does, and no resolvable token means no intent
    #[test]
    fn tombstone_carries_the_resolved_intent() {
        let apple_seed = seed(APPLE_ID, v0::ProtStore::Apple, 2_600);
        let event = ProtStoreEvent::Revoke {
            revocation_date: 70,
            reason: None,
            user_hint: Some(USER.to_string()),
            intent_id: Some(INTENT.to_string()),
            buyer_live: true,
        };
        let plan = plan_store_move(None, &event, 0);
        let m = build_store_move(None, &apple_seed, &event, &plan, 0, 1_000).unwrap();
        assert_eq!(m.use_intent.as_deref(), Some(INTENT));
        assert_eq!(m.row.state, v0::ProtStoreState::Revoked);
        assert_eq!(m.row.intent_id.as_deref(), Some(INTENT));
        assert_eq!(m.row.user_id.as_deref(), Some(USER));

        let held = row(v0::ProtStoreState::Held);
        let plan = plan_store_move(Some(&held), &event, 0);
        let m = build_store_move(Some(&held), &held, &event, &plan, 0, 1_000).unwrap();
        assert_eq!(m.use_intent, None);

        let bare = revoke(70, true);
        let plan = plan_store_move(None, &bare, 0);
        let m = build_store_move(None, &apple_seed, &bare, &plan, 0, 1_000).unwrap();
        assert_eq!((m.use_intent, m.row.intent_id), (None, None));
    }

    #[test]
    fn unconsumed_play_prot_counts_only_old_unconsumed_play_credits() {
        let since = 10_000;
        let play =
            |id: &str, state, unconsumed, credited_at: Option<i64>, user: &str| ProtStorePurchase {
                state,
                unconsumed,
                credited_at,
                user_id: Some(user.to_string()),
                ..seed(&format!("play:{id}"), v0::ProtStore::Play, 1_000)
            };
        let credited = v0::ProtStoreState::Credited;
        let rows = vec![
            play(&"a".repeat(64), credited, Some(true), Some(9_999), USER),
            play(
                &"b".repeat(64),
                v0::ProtStoreState::Reinstated,
                Some(true),
                Some(1),
                USER,
            ),
            // In the window: already in S5b's ledger fold
            play(&"c".repeat(64), credited, Some(true), Some(10_000), USER),
            // Consumed, revoked, another user's
            play(&"d".repeat(64), credited, None, Some(1), USER),
            play(
                &"e".repeat(64),
                v0::ProtStoreState::Revoked,
                Some(true),
                Some(1),
                USER,
            ),
            play(&"f".repeat(64), credited, Some(true), Some(1), OTHER),
            ProtStorePurchase {
                unconsumed: Some(true),
                credited_at: Some(1),
                user_id: Some(USER.to_string()),
                ..row(credited)
            },
        ];
        assert_eq!(unconsumed_play_prot(&rows, USER, since), 2_000);
        assert_eq!(unconsumed_play_prot(&rows, OTHER, since), 1_000);
        assert_eq!(unconsumed_play_prot(&rows, USER, i64::MAX), 3_000);
        assert_eq!(unconsumed_play_prot(&rows, USER, 1), 0);

        let map: HashMap<String, ProtStorePurchase> =
            rows.into_iter().map(|row| (row.id.clone(), row)).collect();
        assert_eq!(held_store_unconsumed_locked(&map, USER, since), 2_000);
    }
}
