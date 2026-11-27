//! In-app Prot (S6): App Store and Google Play purchases
//! (prot-s6-contracts section 9)
//!
//! Every store purchase is one row of `prot_store_purchases`, moved only by
//! the state machine of `plan_store_move`. The engine verifies with the store,
//! decides a verdict (binding, environment, product, pause) or a revocation,
//! reads the row, plans, builds the move with `build_store_move` (never by
//! hand, R49) and applies it with `apply_store_purchase_move`: the row and its
//! ledger postings in ONE transaction, re-read and re-planned on a Conflict.
//! Money rules it keeps:
//! - a purchase is credited once, under `purchase:{id}`, with the Prot stamped
//!   on its row at first sight (a later config edit never re-prices it)
//! - a refund claws the whole purchase back once per refund generation; a
//!   reversal re-credits what that generation took (E6)
//! - a refund seen before any credit leaves a tombstone no later charge credits
//! - an Apple JWS signed more than 10 minutes ago, or dated ahead, is never
//!   trusted alone: the transaction is read from Apple first (R37)
//! - REFUND and REFUND_REVERSED act on the store's CURRENT answer, never on
//!   the notification type
//! - verify never writes for another account's purchase (wrong_account), and
//!   the caller-less paths credit the intent's user (R11)
//! - a Play purchase is consumed only after its credit committed

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex, PoisonError};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use revolt_database::util::prot_store_alert::{
    send_ops_alert, PROT_STORE_LOG_UNDECODABLE_NOTIFICATION, PROT_STORE_NEEDS_CHARGEBACK,
    PROT_STORE_NEEDS_HELD, PROT_STORE_NEEDS_OVER_CAP, PROT_STORE_NEEDS_REVERSED_UNPAID,
    PROT_STORE_NEEDS_UNBOUND, PROT_STORE_NEEDS_UNCONSUMED,
};
use revolt_database::{
    build_store_move, is_store_purchase_id, plan_store_move, prot_store_key_purchase,
    prot_store_refund_gen_of, prot_user_account, store_country_alpha2, Database, OrderState,
    PaymentOrder, ProtLedgerEntry, ProtStoreAnswer, ProtStoreApple, ProtStoreCursor,
    ProtStoreEvent, ProtStoreIntent, ProtStoreLedgerPlan, ProtStoreMoveOutcome, ProtStoreMovePlan,
    ProtStorePlay, ProtStorePurchase, ProtStoreVerdict, PROT_STORE_CURSOR_APPLE,
    PROT_STORE_CURSOR_PLAY, PROT_STORE_INTENT_TTL_MS, PROT_STORE_MAX_OPEN_INTENTS,
    PROT_STORE_MOVE_RETRIES,
};
use revolt_models::v0::{self, ProductFamily, ProtEntryKind};
use revolt_result::{create_error, ErrorType, Result};
use serde::Deserialize;
use ulid::Ulid;

use super::prot::{after_store_posting, purchase_applied};
use super::{buyer_is_live, is_deleted};
use crate::catalog;
use crate::settings::{AppleStoreConfig, PaymentsSettings, ProtSalesSettings, ProtStoreSettings};
use crate::store::apple_jws::verify_apple_jws;
use crate::store::{
    play_purchase_id, sha256_hex, AppleNotification, AppleStoreApi, AppleTransaction, PlayPurchase,
    PlayStoreApi, StoreApiError, PLAY_CONSUMPTION_STATE_CONSUMED, PLAY_PURCHASE_STATE_CANCELLED,
    PLAY_PURCHASE_STATE_PENDING, PLAY_PURCHASE_STATE_PURCHASED,
};

const MINUTE_MS: i64 = 60_000;
const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;

/// R37: an Apple JWS signed longer ago than this is read again from Apple
const APPLE_JWS_FRESH_MS: i64 = 10 * MINUTE_MS;
/// R37: an Apple JWS dated further ahead than this is not fresh either
const APPLE_JWS_AHEAD_MS: i64 = 5 * MINUTE_MS;

/// Section 19: verify failures of one user in an hour above which the
/// per-process alert line is written (once per hour per user per replica)
const VERIFY_FAILURES_ALERT_OVER: u32 = 20;
/// Log-only alert kinds (no row, no mail; section 19, section 42)
const ALERT_VERIFY_FAILURES: &str = "verify_failures";
const ALERT_WRONG_ACCOUNT_PLAY: &str = "wrong_account_play";
/// Row alert of a Play purchase no intent binds, a day after it was seen
const ALERT_UNBOUND_PLAY: &str = "unbound_play";
/// Most entries the per-process alert memories keep before starting over
const ALERT_MEMORY_MAX: usize = 10_000;

/// Rows one reconcile step works on per tick (store calls and claims)
const RECONCILE_BATCH: i64 = 100;
/// Rows one reconcile step reads to choose them from: the batch moves
/// through these tick by tick (MINOR 6), so old stuck rows never starve
/// newer ones
const RECONCILE_SCAN: i64 = 10_000;
/// A Play purchase held while credits are paused gets a work item and an
/// alert this long after it was seen (R59: Play refunds an unconsumed
/// purchase after 3 days)
const PLAY_HELD_ALERT_MS: i64 = DAY_MS;
/// Intents one reconcile expires or purges
const INTENT_SWEEP_BATCH: i64 = 500;
/// Expired, never-used intents are deleted this long after they expired
const INTENT_PURGE_AFTER_MS: i64 = 30 * DAY_MS;
/// Pages one store scan reads before it stops (and retries next tick)
const STORE_PAGES_MAX: usize = 50;
/// Pub/Sub messages one pull asks for
const RTDN_PULL_MAX: u32 = 100;
/// A Play credit still unconsumed this long after it is a work item
const PLAY_UNCONSUMED_ALERT_MS: i64 = DAY_MS;
/// A Play purchase no intent binds is alerted this long after it was seen
const PLAY_UNBOUND_ALERT_MS: i64 = DAY_MS;
/// voidedpurchases is read once a day, from an hour before the cursor but
/// never further back than 30 days less an hour (Play keeps 30 days; R58)
const PLAY_VOIDED_EVERY_MS: i64 = DAY_MS;
const PLAY_VOIDED_OVERLAP_MS: i64 = HOUR_MS;
const PLAY_VOIDED_KEPT_MS: i64 = 30 * DAY_MS;
/// Notification History is read hourly, two hours back from the cursor; the
/// first read goes back three days
const APPLE_HISTORY_EVERY_MS: i64 = HOUR_MS;
const APPLE_HISTORY_OVERLAP_MS: i64 = 2 * HOUR_MS;
const APPLE_HISTORY_FIRST_MS: i64 = 3 * DAY_MS;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The wallet balance of `user_id` (0 when it has no account)
async fn wallet_balance(db: &Database, user_id: &str) -> Result<i64> {
    Ok(db
        .fetch_prot_account(&prot_user_account(user_id))
        .await?
        .map_or(0, |account| account.balance))
}

/// The pinned alert line of a log-only kind (`send_ops_alert`'s line, with no
/// mailbox and no row; section 42)
fn log_only_alert(kind: &str, id: &str) {
    log::warn!("PROT_STORE_ALERT kind={kind} id={id}");
}

/// Play purchase ids already alerted as `wrong_account_play` by this process
static WRONG_ACCOUNT_PLAY: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Verify failures per user in the current hour, per process (R15)
static VERIFY_FAILURES: LazyLock<Mutex<HashMap<String, FailureWindow>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct FailureWindow {
    since: i64,
    count: u32,
    alerted: bool,
}

/// A Play purchase verified from another account: logged once per purchase
/// id per process (9.4 step 4)
fn note_wrong_account_play(purchase_id: &str) {
    let mut seen = WRONG_ACCOUNT_PLAY
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if seen.len() >= ALERT_MEMORY_MAX {
        seen.clear();
    }
    if seen.insert(purchase_id.to_string()) {
        log_only_alert(ALERT_WRONG_ACCOUNT_PLAY, purchase_id);
    }
}

/// A verify refused as unverifiable, logged; past 20 in an hour for one user
/// the alert line is written once for that hour (R15). `why` names the check,
/// never the JWS or a token.
fn note_verify_failure(user_id: &str, why: &str, now_ms: i64) {
    log::warn!("PROT_STORE_VERIFY_FAILED user={user_id} why={why}");
    let mut failures = VERIFY_FAILURES
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    failures.retain(|_, window| now_ms.saturating_sub(window.since) < HOUR_MS);
    if failures.len() >= ALERT_MEMORY_MAX {
        failures.clear();
    }
    let window = failures
        .entry(user_id.to_string())
        .or_insert(FailureWindow {
            since: now_ms,
            count: 0,
            alerted: false,
        });
    window.count = window.count.saturating_add(1);
    if window.count > VERIFY_FAILURES_ALERT_OVER && !window.alerted {
        window.alerted = true;
        log_only_alert(ALERT_VERIFY_FAILURES, &format!("user:{user_id}"));
    }
}

/// A row alert: claimed first, so only one replica sends it (section 19).
/// Ok(true) when this call won the claim. A failed mail is not retried; the
/// work item and the log line remain.
async fn alert_row(db: &Database, st: &ProtStoreSettings, id: &str, kind: &str) -> Result<bool> {
    if !db.claim_prot_store_alert(id, kind).await? {
        return Ok(false);
    }
    let config = revolt_config::config().await;
    if let Err(err) = send_ops_alert(&config.api.smtp, &st.ops_alert_email, kind, id).await {
        log::warn!("PROT_STORE_ALERT_MAIL_FAILED kind={kind} id={id}: {err:?}");
    }
    Ok(true)
}

/// A store revocation: the store's instant (replay detection keys on it) and
/// its reason
#[derive(Debug, Clone, PartialEq, Eq)]
struct Revocation {
    date: i64,
    reason: Option<String>,
}

/// What a purchase credits (9.4 step 6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Priced {
    /// Product Prot x quantity (E11)
    Known(i64),
    /// Not on the server's product table: credited nothing (owner Q3)
    Unknown,
    /// Quantity 0, or a product that overflows: refused as a bad payload
    BadQuantity,
}

fn price(st: &ProtStoreSettings, store: v0::ProtStore, product_id: &str, quantity: u32) -> Priced {
    let Some(product) = st.product(store, product_id) else {
        return Priced::Unknown;
    };
    if quantity == 0 {
        return Priced::BadQuantity;
    }
    product
        .prot
        .checked_mul(i64::from(quantity))
        .map_or(Priced::BadQuantity, Priced::Known)
}

/// A purchase as the store reported it, before any row decision
struct SeenPurchase {
    /// The row a first move stores (state, user and intent are stamped by
    /// `build_store_move`); ignored once a row exists
    seed: ProtStorePurchase,
    /// The intent token the purchase carries (Apple `appAccountToken`
    /// lowercased, Play `obfuscatedExternalAccountId`)
    token: Option<String>,
    priced: Priced,
    /// Apple `type == "Consumable"` (Play: always)
    consumable: bool,
    /// `wallet_cap` of the Prot settings the purchase was seen under: an
    /// automatic credit past it is held for staff (R63)
    wallet_cap: i64,
}

/// What a store reports about a purchase
#[derive(Debug, Clone, PartialEq, Eq)]
enum StoreAction {
    /// Bought and not revoked
    Seen,
    /// Revoked now (a refund, a void, a cancelled purchase)
    Revoke(Revocation),
    /// Apple: a refund notification whose fresh lookup shows no revocation
    Reverse,
}

/// The first-sight row of a purchase (`build_store_move` stamps the rest)
#[allow(clippy::too_many_arguments)]
fn seed_row(
    ps: &ProtSalesSettings,
    id: String,
    store: v0::ProtStore,
    product_id: String,
    prot: i64,
    quantity: u32,
    environment: v0::ProtStoreEnvironment,
    storefront: Option<String>,
    apple: Option<ProtStoreApple>,
    play: Option<ProtStorePlay>,
    now_ms: i64,
) -> ProtStorePurchase {
    let country = storefront
        .as_deref()
        .and_then(store_country_alpha2)
        .map(str::to_string);
    // E1: credited anyway, logged
    if let Some(country) = country.as_deref().filter(|c| ps.region_blocked(c)) {
        log::info!("payments: PROT_STORE_BLOCKED_STOREFRONT id={id} country={country}");
    }
    ProtStorePurchase {
        id,
        store,
        user_id: None,
        intent_id: None,
        product_id,
        prot,
        quantity,
        environment,
        storefront,
        country,
        state: v0::ProtStoreState::Rejected,
        reject_reason: None,
        hold_reason: None,
        refund_gen: 0,
        refunds: Vec::new(),
        unreinstated_reversals: 0,
        apple,
        play,
        credited_at: None,
        unconsumed: None,
        revoked_at: None,
        revocation_reason: None,
        assigned_by: None,
        needs_action: None,
        alerted: Vec::new(),
        created_at: now_ms,
        updated_at: now_ms,
        version: 0,
    }
}

fn priced_prot(priced: Priced) -> i64 {
    match priced {
        Priced::Known(prot) => prot,
        Priced::Unknown | Priced::BadQuantity => 0,
    }
}

// ---------------------------------------------------------------------------
// Binding and verdict (9.4 steps 3, 5-7)
// ---------------------------------------------------------------------------

enum Binding {
    Bound {
        user_id: String,
        intent_id: String,
    },
    Unbound,
    /// The intent's user was deleted before the purchase was seen (R12)
    NoBuyer {
        intent_id: String,
    },
}

/// The intent a purchase's token resolves to. None, another store or
/// product, or an intent already Used by another purchase: unbound.
async fn resolve_binding(
    db: &Database,
    seed: &ProtStorePurchase,
    token: Option<&str>,
) -> Result<Binding> {
    let Some(token) = token.filter(|token| !token.is_empty()) else {
        return Ok(Binding::Unbound);
    };
    let Some(intent) = db.fetch_prot_store_intent_by_token(token).await? else {
        return Ok(Binding::Unbound);
    };
    if intent.store != seed.store || intent.product_id != seed.product_id {
        return Ok(Binding::Unbound);
    }
    if intent.state == v0::ProtStoreIntentState::Used
        && intent.purchase_id.as_deref() != Some(seed.id.as_str())
    {
        return Ok(Binding::Unbound);
    }
    Ok(match intent.user_id {
        Some(user_id) => Binding::Bound {
            user_id,
            intent_id: intent.id,
        },
        None => Binding::NoBuyer {
            intent_id: intent.id,
        },
    })
}

/// The intent token a purchase carries (Apple `appAccountToken`, stored
/// lowercased; Play `obfuscatedExternalAccountId`)
fn seed_token(seed: &ProtStorePurchase) -> Option<&str> {
    match seed.store {
        v0::ProtStore::Apple => seed.apple.as_ref()?.app_account_token.as_deref(),
        v0::ProtStore::Play => seed.play.as_ref()?.obfuscated_account_id.as_deref(),
    }
}

/// R5's Stripe term: the Prot of the user's Paid Prot orders not credited
/// yet (they will be, whatever the cap says then). `orders` may hold orders
/// in any state; only Paid ones count.
async fn uncredited_stripe_prot(db: &Database, orders: &[PaymentOrder]) -> Result<i64> {
    let mut uncredited = 0_i64;
    for order in orders
        .iter()
        .filter(|o| o.state == OrderState::Paid && o.sku.family() == ProductFamily::Prot)
    {
        if !purchase_applied(db, &order.id).await? {
            uncredited = uncredited.saturating_add(catalog::sku_prot(&order.sku).unwrap_or(0));
        }
    }
    Ok(uncredited)
}

/// R63: whether an AUTOMATIC credit of `prot` to `user_id` would take the
/// wallet past `wallet_cap`, in R5's terms: the balance (S5b's `held` is part
/// of it), uncredited Stripe Prot, every OTHER Held store row of the user
/// (any hold reason; `own_row` is left out), the user's live intents (R62)
/// except the purchase's own bound intent, and this purchase. Read outside
/// the move's transaction: two concurrent credits may both pass (soft cap,
/// R25).
async fn over_wallet_cap(
    db: &Database,
    wallet_cap: i64,
    user_id: &str,
    own_row: Option<&ProtStorePurchase>,
    own_intent: Option<&str>,
    prot: i64,
    now_ms: i64,
) -> Result<bool> {
    let orders = db
        .fetch_payment_orders_by_user(user_id, &[OrderState::Paid])
        .await?;
    let uncredited = uncredited_stripe_prot(db, &orders).await?;
    let own_held = own_row
        .filter(|row| {
            row.state == v0::ProtStoreState::Held && row.user_id.as_deref() == Some(user_id)
        })
        .map_or(0, |row| row.prot.max(0));
    let held = db
        .sum_held_prot_store(user_id)
        .await?
        .saturating_sub(own_held)
        .max(0);
    let intents = db
        .fetch_live_prot_store_intents(user_id, now_ms)
        .await?
        .iter()
        .filter(|intent| Some(intent.id.as_str()) != own_intent)
        .fold(0_i64, |total, intent| total.saturating_add(intent.prot));
    let committed = wallet_balance(db, user_id)
        .await?
        .saturating_add(uncredited)
        .saturating_add(held)
        .saturating_add(intents)
        .saturating_add(prot);
    Ok(committed > wallet_cap)
}

/// The verdict on a verified, not-revoked purchase (9.4 steps 3, 5-7),
/// decided before the row is looked at. Read again on every move attempt, so
/// a re-plan after a Conflict sees an intent that was used or unlinked since.
/// `row` is the purchase's row as this attempt read it (the cap leaves it
/// out of the held sum, R63).
async fn seen_verdict(
    db: &Database,
    st: &ProtStoreSettings,
    purchase: &SeenPurchase,
    row: Option<&ProtStorePurchase>,
    now_ms: i64,
) -> Result<ProtStoreVerdict> {
    use revolt_models::v0::ProtStoreRejectReason as Reason;

    let (user_id, intent_id) =
        match resolve_binding(db, &purchase.seed, purchase.token.as_deref()).await? {
            Binding::Unbound => {
                return Ok(ProtStoreVerdict::Reject {
                    reason: Reason::Unbound,
                    user_id: None,
                    intent_id: None,
                })
            }
            Binding::NoBuyer { intent_id } => {
                return Ok(ProtStoreVerdict::Reject {
                    reason: Reason::NoBuyer,
                    user_id: None,
                    intent_id: Some(intent_id),
                })
            }
            Binding::Bound { user_id, intent_id } => (user_id, intent_id),
        };
    let reject = |reason: Reason| ProtStoreVerdict::Reject {
        reason,
        user_id: Some(user_id.clone()),
        intent_id: Some(intent_id.clone()),
    };

    if !purchase.consumable || purchase.priced == Priced::BadQuantity {
        return Ok(reject(Reason::BadPayload));
    }

    // E4, on every deployment: a sandbox or test purchase is credited only to
    // a listed tester, up to the test cap
    if purchase.seed.environment == v0::ProtStoreEnvironment::Sandbox {
        let allowed = st.is_tester(&user_id)
            && db
                .sum_sandbox_prot_store(&user_id)
                .await?
                .saturating_add(priced_prot(purchase.priced))
                <= st.test_max_prot;
        if !allowed {
            return Ok(reject(Reason::TestPurchase));
        }
    }

    if purchase.priced == Priced::Unknown {
        return Ok(reject(Reason::UnknownProduct));
    }

    if st.credit_paused {
        return Ok(ProtStoreVerdict::Hold {
            user_id,
            intent_id,
            reason: v0::ProtStoreHoldReason::Paused,
        });
    }

    // R63 (owner, "hold over-cap credits"): money that arrived is never
    // refused; a credit that would take the wallet past its cap is held for
    // staff instead. Sandbox purchases too (the tester cap stays as well).
    if over_wallet_cap(
        db,
        purchase.wallet_cap,
        &user_id,
        row,
        Some(&intent_id),
        priced_prot(purchase.priced),
        now_ms,
    )
    .await?
    {
        return Ok(ProtStoreVerdict::Hold {
            user_id,
            intent_id,
            reason: v0::ProtStoreHoldReason::OverCap,
        });
    }

    Ok(ProtStoreVerdict::Credit { user_id, intent_id })
}

// ---------------------------------------------------------------------------
// The move loop (9.2 run_store_move)
// ---------------------------------------------------------------------------

/// The event a move is planned on; the parts read from the database (the
/// verdict, `buyer_live`) are read again on every attempt
enum StoreEvent<'a> {
    Seen(&'a SeenPurchase),
    /// The intent and its user are resolved from the purchase's token on a
    /// first sight (R53)
    Revoke {
        revocation: Revocation,
    },
    Reverse,
    /// The end of a credit pause; a pause hold that would take the wallet
    /// past `wallet_cap` becomes an over-cap hold instead (R63)
    Unpause {
        wallet_cap: i64,
    },
    Assign {
        user_id: String,
        admin_id: String,
        paused: bool,
    },
    /// R63: a staff release of an over-cap hold
    Release,
}

/// The row's user is set, exists and is not deleted
async fn buyer_live(db: &Database, row: Option<&ProtStorePurchase>) -> Result<bool> {
    match row.and_then(|row| row.user_id.as_deref()) {
        Some(user_id) => buyer_is_live(db, user_id).await,
        None => Ok(false),
    }
}

async fn plan_event(
    db: &Database,
    st: &ProtStoreSettings,
    seed: &ProtStorePurchase,
    event: &StoreEvent<'_>,
    row: Option<&ProtStorePurchase>,
    now_ms: i64,
) -> Result<ProtStoreEvent> {
    Ok(match event {
        StoreEvent::Seen(purchase) => {
            ProtStoreEvent::Seen(seen_verdict(db, st, purchase, row, now_ms).await?)
        }
        StoreEvent::Revoke { revocation } => {
            // R53: a refund seen before any row is a tombstone that marks the
            // intent its token resolved to Used (and names its user); an
            // existing row ignores both
            let (user_hint, intent_id) = match row {
                Some(_) => (None, None),
                None => match resolve_binding(db, seed, seed_token(seed)).await? {
                    Binding::Bound { user_id, intent_id } => (Some(user_id), Some(intent_id)),
                    Binding::NoBuyer { intent_id } => (None, Some(intent_id)),
                    Binding::Unbound => (None, None),
                },
            };
            ProtStoreEvent::Revoke {
                revocation_date: revocation.date,
                reason: revocation.reason.clone(),
                user_hint,
                intent_id,
                buyer_live: buyer_live(db, row).await?,
            }
        }
        StoreEvent::Reverse => ProtStoreEvent::Reverse {
            buyer_live: buyer_live(db, row).await?,
        },
        StoreEvent::Unpause { wallet_cap } => {
            let live = buyer_live(db, row).await?;
            let mut planned = ProtStoreEvent::Unpause { buyer_live: live };
            // R63: the end of a pause is an automatic credit, so the cap
            // applies (the row's own Prot is left out of the held sum). An
            // over-cap hold is never unpaused (reconcile skips it and the
            // planner refuses it).
            let pause_hold =
                row.filter(|row| live && row.hold_reason != Some(v0::ProtStoreHoldReason::OverCap));
            if let Some((row, user_id)) =
                pause_hold.and_then(|row| Some((row, row.user_id.as_deref()?)))
            {
                if over_wallet_cap(
                    db,
                    *wallet_cap,
                    user_id,
                    Some(row),
                    row.intent_id.as_deref(),
                    row.prot,
                    now_ms,
                )
                .await?
                {
                    planned = ProtStoreEvent::Seen(ProtStoreVerdict::Hold {
                        user_id: user_id.to_string(),
                        // An assigned row has no intent; the planner's move
                        // of an existing row never reads it
                        intent_id: row.intent_id.clone().unwrap_or_default(),
                        reason: v0::ProtStoreHoldReason::OverCap,
                    });
                }
            }
            planned
        }
        StoreEvent::Release => ProtStoreEvent::Release,
        StoreEvent::Assign {
            user_id,
            admin_id,
            paused,
        } => ProtStoreEvent::Assign {
            user_id: user_id.clone(),
            admin_id: admin_id.clone(),
            paused: *paused,
        },
    })
}

/// The `purchase:{id}` row a Credited or Reinstated store row must have
/// (R48: `already_credited` is answered only when the ledger key exists)
async fn credited_entry(db: &Database, id: &str) -> Result<ProtLedgerEntry> {
    match db
        .fetch_prot_entry_by_key(&prot_store_key_purchase(id))
        .await?
    {
        Some(entry) => Ok(entry),
        None => {
            log::error!(
                "payments: PROT_STORE_ROW_WITHOUT_LEDGER id={id}: a credited store row has no \
                 purchase ledger row"
            );
            Err(create_error!(InternalError))
        }
    }
}

/// The generation of a `reinstate:{id}:{gen}` key of purchase `id`
fn reinstate_gen_of(key: &str, id: &str) -> Option<u32> {
    key.strip_prefix("reinstate:")?
        .strip_prefix(id)?
        .strip_prefix(':')?
        .parse()
        .ok()
}

/// 8.3: what the row's latest refund generation clawed, from the ledger (the
/// row's own record must agree; on a mismatch the ledger wins, logged)
async fn reinstate_amount(db: &Database, row: &ProtStorePurchase) -> Result<i64> {
    let gen = row.refund_gen;
    let ledger = db
        .fetch_prot_entries_by_order(&row.id)
        .await?
        .iter()
        .filter(|entry| {
            matches!(
                entry.kind,
                ProtEntryKind::Clawback | ProtEntryKind::ClawbackHold
            ) && prot_store_refund_gen_of(&entry.key, &row.id) == Some(gen)
        })
        .fold(0_i64, |total, entry| total.saturating_add(entry.amount));
    if let Some(recorded) = row
        .refunds
        .iter()
        .find(|refund| refund.gen == gen)
        .map(|refund| refund.clawed)
    {
        if recorded != ledger {
            log::warn!(
                "payments: PROT_STORE_REFUND_MISMATCH id={} gen={gen} row={recorded} \
                 ledger={ledger}: the ledger is used",
                row.id
            );
        }
    }
    Ok(ledger)
}

/// 8.2: refund generation `gen` claws `total_n = prot - clawed before +
/// reinstated before`, which must be the whole purchase and more than 0
async fn check_generation_total(db: &Database, row: &ProtStorePurchase, gen: u32) -> Result<()> {
    let (mut clawed, mut reinstated) = (0_i64, 0_i64);
    for entry in db.fetch_prot_entries_by_order(&row.id).await? {
        match entry.kind {
            ProtEntryKind::Clawback | ProtEntryKind::ClawbackHold
                if prot_store_refund_gen_of(&entry.key, &row.id).is_some_and(|g| g < gen) =>
            {
                clawed = clawed.saturating_add(entry.amount);
            }
            ProtEntryKind::Purchase
                if reinstate_gen_of(&entry.key, &row.id).is_some_and(|g| g < gen) =>
            {
                reinstated = reinstated.saturating_add(entry.amount);
            }
            _ => {}
        }
    }
    let total = row.prot.saturating_sub(clawed).saturating_add(reinstated);
    if total != row.prot || total <= 0 {
        log::error!(
            "payments: PROT_STORE_GENERATION_MISMATCH id={} gen={gen} total={total} prot={}: \
             nothing moved",
            row.id,
            row.prot
        );
        return Err(create_error!(InternalError));
    }
    Ok(())
}

/// What one store move did
struct MoveResult {
    answer: ProtStoreAnswer,
    /// The row after the move (the row as read for an answer without a move)
    row: Option<ProtStorePurchase>,
    /// A ledger row was written by this move
    posted: bool,
}

/// Read, plan, build (`build_store_move`), apply; on a Conflict read and plan
/// again, at most `PROT_STORE_MOVE_RETRIES` times. `seed` is the purchase as
/// first seen (used only when no row exists). After a move that wrote a
/// ledger row the balance is published and the second pass runs.
async fn run_store_move(
    db: &Database,
    st: &ProtStoreSettings,
    seed: &ProtStorePurchase,
    event: &StoreEvent<'_>,
    now_ms: i64,
) -> Result<MoveResult> {
    let id = seed.id.as_str();
    for _ in 0..PROT_STORE_MOVE_RETRIES {
        let row = db.fetch_prot_store_purchase(id).await?;
        let planned = plan_event(db, st, seed, event, row.as_ref(), now_ms).await?;
        let reinstate = match (&row, &planned) {
            (Some(row), ProtStoreEvent::Reverse { .. })
                if row.state == v0::ProtStoreState::Revoked && row.refund_gen >= 1 =>
            {
                reinstate_amount(db, row).await?
            }
            _ => 0,
        };

        let plan = plan_store_move(row.as_ref(), &planned, reinstate);
        let (answer, ledger) = match &plan {
            ProtStoreMovePlan::Answer(answer) => {
                if *answer == ProtStoreAnswer::AlreadyCredited {
                    credited_entry(db, id).await?;
                }
                return Ok(MoveResult {
                    answer: answer.clone(),
                    row,
                    posted: false,
                });
            }
            ProtStoreMovePlan::Move { answer, ledger, .. } => (answer.clone(), *ledger),
        };

        if let (ProtStoreLedgerPlan::Clawback { gen }, Some(row)) = (ledger, row.as_ref()) {
            check_generation_total(db, row, gen).await?;
        }

        let Some(m) = build_store_move(row.as_ref(), seed, &planned, &plan, reinstate, now_ms)
        else {
            log::error!("payments: PROT_STORE_MOVE_UNBUILT id={id}: the planned move has no row");
            return Err(create_error!(InternalError));
        };

        match db.apply_store_purchase_move(&m).await? {
            ProtStoreMoveOutcome::Conflict => continue,
            ProtStoreMoveOutcome::Applied {
                row: stored,
                entries,
            } => {
                let before = row.as_ref().map(|row| row.state);
                log::info!(
                    "payments: PROT_STORE_MOVE id={id} from={} to={} answer={answer:?} \
                     postings={}",
                    before.map_or("none", |state| state.as_str()),
                    stored.state.as_str(),
                    entries.len()
                );
                let stored =
                    after_move(db, st, row.as_ref(), &stored, &planned, ledger, now_ms).await?;
                return Ok(MoveResult {
                    answer,
                    row: Some(stored),
                    posted: !entries.is_empty(),
                });
            }
        }
    }

    log::error!(
        "payments: PROT_STORE_MOVE_CONFLICT id={id}: the row still moved after \
         {PROT_STORE_MOVE_RETRIES} tries"
    );
    Err(create_error!(InternalError))
}

/// After a committed move: publish and the second pass when it posted, the
/// pinned log lines, the `reversed_unpaid` alert, the `play_held_24h` clear.
/// Returns the row as it now is.
async fn after_move(
    db: &Database,
    st: &ProtStoreSettings,
    before: Option<&ProtStorePurchase>,
    stored: &ProtStorePurchase,
    planned: &ProtStoreEvent,
    ledger: ProtStoreLedgerPlan,
    now_ms: i64,
) -> Result<ProtStorePurchase> {
    let id = stored.id.as_str();
    if ledger != ProtStoreLedgerPlan::None {
        if let Some(user_id) = stored.user_id.as_deref() {
            after_store_posting(db, user_id, now_ms).await?;
        }
    }

    match (ledger, planned) {
        (ProtStoreLedgerPlan::Clawback { gen }, _) => {
            if let Some(refund) = stored.refunds.iter().find(|refund| refund.gen == gen) {
                if refund.shortfall > 0 {
                    log::warn!(
                        "payments: PROT_CLAWBACK_SHORTFALL order={id} gen={gen} clawed={} \
                         shortfall={}",
                        refund.clawed,
                        refund.shortfall
                    );
                }
            }
        }
        (ProtStoreLedgerPlan::None, ProtStoreEvent::Revoke { .. })
            if before.is_some_and(|row| {
                matches!(
                    row.state,
                    v0::ProtStoreState::Credited | v0::ProtStoreState::Reinstated
                )
            }) =>
        {
            // Section 17: the buyer is gone; S5's forfeit already took the wallet
            log::info!(
                "payments: PROT_STORE_REFUND_NO_BUYER id={id} gen={}",
                stored.refund_gen
            );
        }
        _ => {}
    }

    let newly_unpaid = stored.needs_action.as_deref() == Some(PROT_STORE_NEEDS_REVERSED_UNPAID)
        && before.and_then(|row| row.needs_action.as_deref())
            != Some(PROT_STORE_NEEDS_REVERSED_UNPAID);
    if newly_unpaid {
        if let Err(err) = alert_row(db, st, id, PROT_STORE_NEEDS_REVERSED_UNPAID).await {
            log::warn!("payments: could not claim the reversed_unpaid alert of {id}: {err:?}");
        }
    }

    // R63: a purchase that just entered an over-cap hold (first sight, or a
    // pause hold found over the cap) is staff work, mailed once
    let over_cap = |row: &ProtStorePurchase| {
        row.state == v0::ProtStoreState::Held
            && row.hold_reason == Some(v0::ProtStoreHoldReason::OverCap)
    };
    if over_cap(stored) && !before.is_some_and(over_cap) {
        log::warn!(
            "payments: PROT_STORE_OVER_CAP_HELD id={id} user={} prot={}",
            stored.user_id.as_deref().unwrap_or("-"),
            stored.prot
        );
        if let Err(err) = alert_row(db, st, id, PROT_STORE_NEEDS_OVER_CAP).await {
            log::warn!("payments: could not claim the over_cap_review alert of {id}: {err:?}");
        }
    }

    // R59: a purchase that leaves Held (credited after the pause, revoked,
    // no buyer) has its paused-credit work item done. The clear bumps the
    // row's version, so the row is read again for the caller (a consume
    // records itself on that version).
    let left_held = before.is_some_and(|row| row.state == v0::ProtStoreState::Held)
        && stored.state != v0::ProtStoreState::Held
        && stored.needs_action.as_deref() == Some(PROT_STORE_NEEDS_HELD);
    if left_held
        && db
            .clear_prot_store_needs_action(id, PROT_STORE_NEEDS_HELD, now_ms)
            .await?
    {
        if let Some(row) = db.fetch_prot_store_purchase(id).await? {
            return Ok(row);
        }
    }
    Ok(stored.clone())
}

/// 9.4 step 9: consume a Play purchase whose credit committed. A failure is
/// logged; crond retries (16 step 2). Never waits for anything else.
async fn consume_after_credit(
    db: &Database,
    play: &dyn PlayStoreApi,
    row: &ProtStorePurchase,
    now_ms: i64,
) {
    let Some(info) = row.play.as_ref() else {
        return;
    };
    match play.consume(&row.product_id, &info.purchase_token).await {
        Ok(()) => match db
            .mark_prot_store_consumed(&row.id, row.version, now_ms)
            .await
        {
            Ok(true) => log::info!("payments: PROT_STORE_CONSUMED id={}", row.id),
            // The row moved since: crond's next consume reads it CONSUMED
            Ok(false) => log::info!(
                "payments: consumed {} at Play; the row moved since, crond records it",
                row.id
            ),
            Err(err) => log::warn!(
                "payments: consumed {} at Play but could not record it: {err:?}",
                row.id
            ),
        },
        Err(err) => log::warn!(
            "payments: PROT_STORE_CONSUME_FAILED id={}: {err}; crond retries",
            row.id
        ),
    }
}

/// How a purchase seen by a store path ended
#[allow(clippy::large_enum_variant)]
enum Settled {
    /// The caller is not the purchase's account: nothing written
    WrongAccount,
    /// The row was Revoked before the caller was compared (9.4 step 4)
    AlreadyRevoked,
    Moved(MoveResult),
}

/// 9.4 steps 3-9 for a verified purchase. `caller`: verify's session user
/// (step 4 runs, before any write); None on the notification, RTDN and
/// reconcile paths, which credit the intent's user (R11). `play`: consume
/// after a committed Play credit.
async fn settle(
    db: &Database,
    st: &ProtStoreSettings,
    play: Option<&dyn PlayStoreApi>,
    purchase: &SeenPurchase,
    action: &StoreAction,
    caller: Option<&str>,
    now_ms: i64,
) -> Result<Settled> {
    let id = purchase.seed.id.as_str();

    // The binding names the intent's user: the caller check of a first sight
    let bound_user = match resolve_binding(db, &purchase.seed, purchase.token.as_deref()).await? {
        Binding::Bound { user_id, .. } => Some(user_id),
        Binding::Unbound | Binding::NoBuyer { .. } => None,
    };

    if let Some(caller) = caller {
        match db.fetch_prot_store_purchase(id).await? {
            Some(row) if row.state == v0::ProtStoreState::Revoked => {
                return Ok(Settled::AlreadyRevoked)
            }
            Some(row) => {
                if row.user_id.as_deref().is_some_and(|user| user != caller) {
                    return Ok(Settled::WrongAccount);
                }
            }
            None => {
                if bound_user.as_deref().is_some_and(|user| user != caller) {
                    return Ok(Settled::WrongAccount);
                }
            }
        }
    }

    let event = match action {
        StoreAction::Seen => StoreEvent::Seen(purchase),
        StoreAction::Revoke(revocation) => StoreEvent::Revoke {
            revocation: revocation.clone(),
        },
        StoreAction::Reverse => StoreEvent::Reverse,
    };
    let result = run_store_move(db, st, &purchase.seed, &event, now_ms).await?;

    if let (Some(play), Some(row)) = (play, result.row.as_ref()) {
        if row.store == v0::ProtStore::Play
            && result.answer == ProtStoreAnswer::Credited
            && result.posted
        {
            consume_after_credit(db, play, row, now_ms).await;
        }
    }
    Ok(Settled::Moved(result))
}

// ---------------------------------------------------------------------------
// Intents (9.3) and the user's cancel (12.1)
// ---------------------------------------------------------------------------

/// A fresh one-time intent token: Apple a lowercase UUID v4 (its
/// `appAccountToken`), Play 32 random bytes base64url without padding (43
/// characters, its `obfuscatedAccountId`)
fn new_intent_token(store: v0::ProtStore) -> String {
    match store {
        v0::ProtStore::Apple => uuid::Uuid::new_v4().hyphenated().to_string(),
        v0::ProtStore::Play => URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
    }
}

/// Start an in-app purchase: the intent whose token the app passes to the
/// store, binding the purchase to this account. Gates, in this order, all
/// before any write (9.3):
/// 1. payments off → `PaymentsDisabled`; Prot off → `ProtDisabled`; a bot →
///    `IsBot`
/// 2. the managed client of the store not configured (Play also needs RTDN,
///    `pubsub_configured`) → `ProtStoreUnavailable`
/// 3. the store not offered to the user (closed and not on preview) →
///    `ProtStoreClosed`
/// 4. the request country blocked for Prot → `ProtRegionUnavailable`
/// 5. a live payment of the user under dispute → `ProtNotEligible`
/// 6. the product not on sale → `ProtStoreProductUnknown`
/// 7. three open intents already → `PaymentPending`
/// 8. the wallet cap (R5): balance, uncredited Stripe Prot, Held store rows,
///    live intents (Open, and cancelled ones not yet expired, which still
///    bind a late purchase; R62) and this product, summed, > `wallet_cap` →
///    `ProtWalletCap`
// The pinned contract signature (section 9.2)
#[allow(clippy::too_many_arguments)]
pub async fn create_store_intent(
    db: &Database,
    s: &PaymentsSettings,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    play: &dyn PlayStoreApi,
    apple: &dyn AppleStoreApi,
    user_id: &str,
    data: &v0::DataProtStoreIntent,
    country: Option<&str>,
    now_ms: i64,
) -> Result<v0::ProtStoreIntentResponse> {
    let tokens = [new_intent_token(data.store), new_intent_token(data.store)];
    issue_store_intent(
        db, s, ps, st, play, apple, user_id, data, country, now_ms, tokens,
    )
    .await
}

/// [`create_store_intent`] with its two tokens given: the first, and the one
/// a failed insert retries with (R47: a duplicate token is an ordinary
/// database error in both drivers, so ANY insert error retries once)
#[allow(clippy::too_many_arguments)]
async fn issue_store_intent(
    db: &Database,
    s: &PaymentsSettings,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    play: &dyn PlayStoreApi,
    apple: &dyn AppleStoreApi,
    user_id: &str,
    data: &v0::DataProtStoreIntent,
    country: Option<&str>,
    now_ms: i64,
    tokens: [String; 2],
) -> Result<v0::ProtStoreIntentResponse> {
    if !s.enabled {
        return Err(create_error!(PaymentsDisabled));
    }
    if !ps.enabled {
        return Err(create_error!(ProtDisabled));
    }
    if db.fetch_user(user_id).await?.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // The MANAGED client, never the config (audit N4). RTDN is the only
    // backstop that credits a Play purchase whose verify never arrives.
    let store = data.store;
    let configured = match store {
        v0::ProtStore::Apple => apple.configured(),
        v0::ProtStore::Play => play.configured() && play.pubsub_configured(),
    };
    if !configured {
        return Err(create_error!(ProtStoreUnavailable));
    }
    if !st.store_offered_to(store, user_id, configured) {
        return Err(create_error!(ProtStoreClosed));
    }
    // Advisory (E1): the store's own storefront decides the sale
    if country.is_some_and(|country| ps.region_blocked(country)) {
        return Err(create_error!(ProtRegionUnavailable));
    }

    // The S5 checkout's dispute gate, re-implemented
    let orders = db
        .fetch_payment_orders_by_user(
            user_id,
            &[
                OrderState::Creating,
                OrderState::Pending,
                OrderState::Paid,
                OrderState::Fulfilled,
            ],
        )
        .await?;
    if orders.iter().any(|order| !order.open_disputes.is_empty()) {
        return Err(create_error!(ProtNotEligible));
    }

    let Some(product) = st.product(store, &data.product_id) else {
        return Err(create_error!(ProtStoreProductUnknown));
    };

    // The three slots count Open intents only, so backing out of the store
    // sheet (a cancel) frees a slot
    let open = db.fetch_open_prot_store_intents(user_id, now_ms).await?;
    if open.len() as u64 >= PROT_STORE_MAX_OPEN_INTENTS {
        return Err(create_error!(PaymentPending));
    }

    // R5. `held` (S5b) is part of the balance, so it is not added again. A
    // Paid Stripe order not credited yet will be, whatever the cap says then.
    let uncredited = uncredited_stripe_prot(db, &orders).await?;
    // R62: a cancelled intent still binds a late purchase until it expires
    // (E9), so the cap counts it; counting Open only let intent → cancel →
    // intent buy past the cap
    let intents = db
        .fetch_live_prot_store_intents(user_id, now_ms)
        .await?
        .iter()
        .fold(0_i64, |total, intent| total.saturating_add(intent.prot));
    let committed = wallet_balance(db, user_id)
        .await?
        .saturating_add(uncredited)
        .saturating_add(db.sum_held_prot_store(user_id).await?)
        .saturating_add(intents)
        .saturating_add(product.prot);
    if committed > ps.wallet_cap {
        return Err(create_error!(ProtWalletCap { max: ps.wallet_cap }));
    }

    let mut intent = ProtStoreIntent {
        id: Ulid::new().to_string(),
        user_id: Some(user_id.to_string()),
        store,
        product_id: product.product_id.clone(),
        prot: product.prot,
        token: String::new(),
        state: v0::ProtStoreIntentState::Open,
        purchase_id: None,
        created_at: now_ms,
        expires_at: now_ms.saturating_add(PROT_STORE_INTENT_TTL_MS),
    };
    for (attempt, token) in tokens.into_iter().enumerate() {
        intent.token = token;
        match db.insert_prot_store_intent(&intent).await {
            Ok(()) => {
                log::info!(
                    "payments: store intent {} for {user_id} ({} {})",
                    intent.id,
                    store.as_str(),
                    intent.product_id
                );
                return Ok(v0::ProtStoreIntentResponse {
                    intent_id: intent.id,
                    token: intent.token,
                    prot: intent.prot,
                    product_id: intent.product_id,
                    expires_at: intent.expires_at,
                });
            }
            // Never the token in a log line
            Err(err) => log::warn!(
                "payments: store intent {} of {user_id} not stored (attempt {}): {:?}",
                intent.id,
                attempt + 1,
                err.error_type
            ),
        }
    }
    log::error!("payments: PROT_STORE_INTENT_FAILED user={user_id}: two inserts failed");
    Err(create_error!(InternalError))
}

/// The caller's own intent, Open → Expired (an Expired intent still binds a
/// late purchase, so a cancel never refuses money that arrives anyway; it
/// frees the slot, but its Prot counts toward the cap until it expires,
/// R62). Absent, malformed or another user's →
/// `NotFound`; Used → `InvalidOperation`; already Expired → Ok.
pub async fn cancel_store_intent(db: &Database, user_id: &str, intent_id: &str) -> Result<()> {
    if Ulid::from_string(intent_id).is_err() {
        return Err(create_error!(NotFound));
    }
    match db.cancel_prot_store_intent(intent_id, user_id).await? {
        None => Err(create_error!(NotFound)),
        Some(intent) if intent.state == v0::ProtStoreIntentState::Used => {
            Err(create_error!(InvalidOperation))
        }
        Some(_) => Ok(()),
    }
}

/// `GET /payments/prot/@me` `store_preview` (15.2)
pub fn store_preview(st: &ProtStoreSettings, user_id: &str) -> bool {
    st.is_preview(user_id)
}

// ---------------------------------------------------------------------------
// Apple: the shared transaction checks (9.4 step 2, N7)
// ---------------------------------------------------------------------------

/// When an Apple transaction is read again from Apple
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Freshness {
    /// R37: only a JWS signed more than 10 minutes ago or more than 5
    /// minutes ahead; a revocation in either JWS counts
    Rule,
    /// Always (a Notification History replay); a revocation in either counts
    Forced,
    /// Always, and only the CURRENT answer says whether it is revoked
    /// (REFUND / REFUND_REVERSED, never the notification type; audit 1)
    Current,
}

/// A verified Apple transaction, as acted on
struct AppleChecked {
    /// The fresh lookup's transaction when there was one
    tx: AppleTransaction,
    environment: v0::ProtStoreEnvironment,
    purchase_id: String,
    revocation: Option<Revocation>,
}

enum AppleCheckError {
    /// Signature, chain, payload kind, bundle or environment: no row
    Refused(String),
    /// Get Transaction Info failed: nothing written
    Lookup {
        purchase_id: String,
        error: StoreApiError,
    },
}

fn apple_purchase_id(environment: v0::ProtStoreEnvironment, transaction_id: &str) -> String {
    let env = match environment {
        v0::ProtStoreEnvironment::Production => "prod",
        v0::ProtStoreEnvironment::Sandbox => "sandbox",
    };
    format!("apple:{env}:{transaction_id}")
}

fn revocation_of(tx: &AppleTransaction) -> Option<Revocation> {
    tx.revocation_date.map(|date| Revocation {
        date,
        reason: tx.revocation_reason.map(|reason| reason.to_string()),
    })
}

/// Verify one Apple transaction JWS against the pinned root and decode it.
/// The typed decode refuses another kind of signed payload (an
/// AppTransaction, renewal info, a notification; R38). Then: the bundle, no
/// Xcode transactions, and a Sandbox deployment refuses Production ones
/// (R23). Returns the transaction, its environment and its `signedDate`.
fn decode_apple_transaction(
    cfg: &AppleStoreConfig,
    jws: &str,
) -> std::result::Result<(AppleTransaction, v0::ProtStoreEnvironment, i64), String> {
    let verified = verify_apple_jws(jws, &cfg.root_g3_sha256).map_err(|err| format!("{err:?}"))?;
    let tx: AppleTransaction =
        serde_json::from_slice(&verified.payload).map_err(|_| "payload".to_string())?;
    if tx.bundle_id != cfg.bundle_id {
        return Err("bundle".to_string());
    }
    let environment = match tx.environment.as_str() {
        "Production" => v0::ProtStoreEnvironment::Production,
        "Sandbox" => v0::ProtStoreEnvironment::Sandbox,
        "Xcode" => return Err("xcode".to_string()),
        _ => return Err("environment".to_string()),
    };
    if cfg.environment == v0::ProtStoreEnvironment::Sandbox
        && environment == v0::ProtStoreEnvironment::Production
    {
        log::warn!(
            "payments: PROT_STORE_ENV_MISMATCH transaction={}: a Production transaction on a \
             Sandbox deployment",
            tx.transaction_id
        );
        return Err("env_mismatch".to_string());
    }
    Ok((tx, environment, verified.signed_date_ms))
}

/// `apple_transaction_checks` (N7): the checks verify and the notification
/// paths share. The transaction is read again from Apple (Get Transaction
/// Info, on the transaction's own environment) as `freshness` says; that
/// answer is verified the same way and must be the same transaction.
async fn apple_transaction_checks(
    cfg: &AppleStoreConfig,
    apple: &dyn AppleStoreApi,
    jws: &str,
    freshness: Freshness,
    now_ms: i64,
) -> std::result::Result<AppleChecked, AppleCheckError> {
    let (tx, environment, signed_date) =
        decode_apple_transaction(cfg, jws).map_err(AppleCheckError::Refused)?;
    let purchase_id = apple_purchase_id(environment, &tx.transaction_id);
    if !is_store_purchase_id(&purchase_id) {
        return Err(AppleCheckError::Refused("transaction_id".to_string()));
    }

    // R37: a future-dated JWS is not fresh
    let stale = signed_date > now_ms.saturating_add(APPLE_JWS_AHEAD_MS)
        || now_ms.saturating_sub(signed_date) > APPLE_JWS_FRESH_MS;
    if freshness == Freshness::Rule && !stale {
        return Ok(AppleChecked {
            revocation: revocation_of(&tx),
            tx,
            environment,
            purchase_id,
        });
    }

    let current = apple
        .transaction_info(environment, &tx.transaction_id)
        .await
        .map_err(|error| AppleCheckError::Lookup {
            purchase_id: purchase_id.clone(),
            error,
        })?;
    let (fresh, fresh_environment, _) = decode_apple_transaction(cfg, &current)
        .map_err(|why| AppleCheckError::Refused(format!("lookup_{why}")))?;
    if fresh.transaction_id != tx.transaction_id || fresh_environment != environment {
        return Err(AppleCheckError::Refused("lookup_mismatch".to_string()));
    }

    let revocation = match freshness {
        Freshness::Current => revocation_of(&fresh),
        Freshness::Rule | Freshness::Forced => revocation_of(&fresh).or_else(|| revocation_of(&tx)),
    };
    Ok(AppleChecked {
        tx: fresh,
        environment,
        purchase_id,
        revocation,
    })
}

/// The purchase an Apple transaction describes
fn apple_purchase(
    st: &ProtStoreSettings,
    ps: &ProtSalesSettings,
    checked: &AppleChecked,
    now_ms: i64,
) -> SeenPurchase {
    let tx = &checked.tx;
    let priced = price(st, v0::ProtStore::Apple, &tx.product_id, tx.quantity);
    let token = tx
        .app_account_token
        .as_deref()
        .map(|token| token.to_ascii_lowercase());
    let seed = seed_row(
        ps,
        checked.purchase_id.clone(),
        v0::ProtStore::Apple,
        tx.product_id.clone(),
        priced_prot(priced),
        tx.quantity,
        checked.environment,
        tx.storefront.clone(),
        Some(ProtStoreApple {
            transaction_id: tx.transaction_id.clone(),
            original_transaction_id: tx.original_transaction_id.clone(),
            app_account_token: token.clone(),
            signed_date: tx.signed_date,
            purchase_date: tx.purchase_date,
        }),
        None,
        now_ms,
    );
    SeenPurchase {
        seed,
        token,
        priced,
        consumable: tx.r#type == "Consumable",
        wallet_cap: ps.wallet_cap,
    }
}

/// The action an Apple transaction asks for (refunds and reversals choose
/// between Revoke and Reverse themselves)
fn apple_action(checked: &AppleChecked) -> StoreAction {
    match &checked.revocation {
        Some(revocation) => StoreAction::Revoke(revocation.clone()),
        None => StoreAction::Seen,
    }
}

// ---------------------------------------------------------------------------
// Play: the purchase a productsv2 answer describes
// ---------------------------------------------------------------------------

/// None when the answer does not hold exactly one line item
fn play_purchase(
    st: &ProtStoreSettings,
    ps: &ProtSalesSettings,
    purchase_token: &str,
    found: &PlayPurchase,
    now_ms: i64,
) -> Option<SeenPurchase> {
    let [item] = found.product_line_item.as_slice() else {
        return None;
    };
    let quantity = item.product_offer_details.quantity_or_one();
    let priced = price(st, v0::ProtStore::Play, &item.product_id, quantity);
    // R10: a test purchase is the sandbox of Play
    let test = found.test_purchase_context.is_some();
    let environment = if test {
        v0::ProtStoreEnvironment::Sandbox
    } else {
        v0::ProtStoreEnvironment::Production
    };
    let seed = seed_row(
        ps,
        play_purchase_id(purchase_token),
        v0::ProtStore::Play,
        item.product_id.clone(),
        priced_prot(priced),
        quantity,
        environment,
        found.region_code.clone(),
        None,
        Some(ProtStorePlay {
            purchase_token: purchase_token.to_string(),
            order_id: found.order_id.clone(),
            obfuscated_account_id: found.obfuscated_external_account_id.clone(),
            consumed_at: None,
            test,
            region_code: found.region_code.clone(),
        }),
        now_ms,
    );
    Some(SeenPurchase {
        seed,
        token: found.obfuscated_external_account_id.clone(),
        priced,
        consumable: true,
        wallet_cap: ps.wallet_cap,
    })
}

/// The row a Play revocation of a purchase never seen leaves: what Play
/// still tells about it, else only its token (a tombstone needs no more)
fn play_tombstone_seed(
    st: &ProtStoreSettings,
    ps: &ProtSalesSettings,
    purchase_token: &str,
    found: Option<&PlayPurchase>,
    order_id: Option<String>,
    now_ms: i64,
) -> ProtStorePurchase {
    if let Some(purchase) =
        found.and_then(|found| play_purchase(st, ps, purchase_token, found, now_ms))
    {
        return purchase.seed;
    }
    seed_row(
        ps,
        play_purchase_id(purchase_token),
        v0::ProtStore::Play,
        String::new(),
        0,
        1,
        v0::ProtStoreEnvironment::Production,
        None,
        None,
        Some(ProtStorePlay {
            purchase_token: purchase_token.to_string(),
            order_id,
            obfuscated_account_id: None,
            consumed_at: None,
            test: false,
            region_code: None,
        }),
        now_ms,
    )
}

// ---------------------------------------------------------------------------
// Verify (9.4)
// ---------------------------------------------------------------------------

fn verify_response(
    status: v0::ProtStoreVerifyStatus,
    reason: Option<v0::ProtStoreVerifyReason>,
    purchase_id: Option<String>,
) -> v0::ProtStoreVerifyResponse {
    v0::ProtStoreVerifyResponse {
        status,
        reason,
        purchase_id,
        balance: None,
        ledger_id: None,
    }
}

fn rejected(
    reason: v0::ProtStoreVerifyReason,
    purchase_id: Option<String>,
) -> v0::ProtStoreVerifyResponse {
    verify_response(
        v0::ProtStoreVerifyStatus::Rejected,
        Some(reason),
        purchase_id,
    )
}

/// Verify a store purchase the app reports and credit it to the caller
/// (9.4). Works whether or not the store is open (E9). Answers 200 with
/// `credited` / `already_credited` (balance and ledger row), `pending` (Play
/// PENDING, or recorded Held while credits are paused; with reason
/// `over_cap` when held for staff over the wallet cap, R63) or `rejected` with a
/// reason (`wrong_account` writes nothing). Errors: `IsBot`;
/// `ProtStoreUnavailable` (store client not configured);
/// `FailedValidation` (body shape); `ProtStoreVerifyFailed` (signature,
/// chain, bundle, environment, a Play token Play does not know, a bad
/// payload); `InternalError` (a store lookup failed: retry).
// The pinned contract signature (section 9.2)
#[allow(clippy::too_many_arguments)]
pub async fn verify_store_purchase(
    db: &Database,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    apple: &dyn AppleStoreApi,
    play: &dyn PlayStoreApi,
    user_id: &str,
    data: &v0::DataProtStoreVerify,
    now_ms: i64,
) -> Result<v0::ProtStoreVerifyResponse> {
    if db.fetch_user(user_id).await?.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let (purchase, action) = match data.store {
        v0::ProtStore::Apple => {
            if !apple.configured() {
                return Err(create_error!(ProtStoreUnavailable));
            }
            let (Some(jws), None) = (data.signed_transaction.as_deref(), &data.purchase_token)
            else {
                return Err(create_error!(FailedValidation {
                    error: "an App Store purchase is verified by its signed_transaction"
                        .to_string()
                }));
            };
            let Some(cfg) = st.apple.as_ref() else {
                log::error!(
                    "payments: PROT_STORE_UNCONFIGURED: the App Store client is configured but \
                     [api.appstore] is not"
                );
                return Err(create_error!(ProtStoreUnavailable));
            };

            let checked =
                match apple_transaction_checks(cfg, apple, jws, Freshness::Rule, now_ms).await {
                    Ok(checked) => checked,
                    Err(AppleCheckError::Refused(why)) => {
                        note_verify_failure(user_id, &why, now_ms);
                        return Err(create_error!(ProtStoreVerifyFailed));
                    }
                    // Nothing is written on a stale JWS that could not be read
                    // again; a refunded purchase still answers refunded
                    Err(AppleCheckError::Lookup { purchase_id, error }) => {
                        log::warn!(
                        "payments: PROT_STORE_LOOKUP_FAILED id={purchase_id}: {error}; the app \
                         retries"
                    );
                        return match db.fetch_prot_store_purchase(&purchase_id).await? {
                            Some(row) if row.state == v0::ProtStoreState::Revoked => Ok(rejected(
                                v0::ProtStoreVerifyReason::Refunded,
                                Some(purchase_id),
                            )),
                            _ => Err(create_error!(InternalError)),
                        };
                    }
                };
            (
                apple_purchase(st, ps, &checked, now_ms),
                apple_action(&checked),
            )
        }
        v0::ProtStore::Play => {
            if !play.configured() {
                return Err(create_error!(ProtStoreUnavailable));
            }
            let (None, Some(product_id), Some(token)) = (
                &data.signed_transaction,
                data.product_id.as_deref(),
                data.purchase_token.as_deref(),
            ) else {
                return Err(create_error!(FailedValidation {
                    error: "a Google Play purchase is verified by its product_id and \
                            purchase_token"
                        .to_string()
                }));
            };

            // Always read live from Play (R51: an unknown token is NotFound)
            let found = match play.product_purchase(token).await {
                Ok(found) => found,
                Err(StoreApiError::NotFound) => {
                    note_verify_failure(user_id, "play_not_found", now_ms);
                    return Err(create_error!(ProtStoreVerifyFailed));
                }
                Err(StoreApiError::NotConfigured) => {
                    return Err(create_error!(ProtStoreUnavailable))
                }
                Err(err @ (StoreApiError::Transient(_) | StoreApiError::Rejected { .. })) => {
                    log::warn!(
                        "payments: PROT_STORE_LOOKUP_FAILED id={}: {err}; the app retries",
                        play_purchase_id(token)
                    );
                    return Err(create_error!(InternalError));
                }
            };
            let Some(purchase) = play_purchase(st, ps, token, &found, now_ms) else {
                note_verify_failure(user_id, "play_line_items", now_ms);
                return Err(create_error!(ProtStoreVerifyFailed));
            };
            if purchase.seed.product_id != product_id {
                note_verify_failure(user_id, "play_product", now_ms);
                return Err(create_error!(ProtStoreVerifyFailed));
            }
            let action = match found.purchase_state_context.purchase_state.as_str() {
                PLAY_PURCHASE_STATE_PURCHASED => StoreAction::Seen,
                // Not paid yet: nothing is written; the app verifies again
                PLAY_PURCHASE_STATE_PENDING => {
                    return Ok(verify_response(
                        v0::ProtStoreVerifyStatus::Pending,
                        None,
                        None,
                    ))
                }
                // No void time is known yet
                PLAY_PURCHASE_STATE_CANCELLED => StoreAction::Revoke(Revocation {
                    date: now_ms,
                    reason: Some("cancelled".to_string()),
                }),
                _ => {
                    note_verify_failure(user_id, "play_state", now_ms);
                    return Err(create_error!(ProtStoreVerifyFailed));
                }
            };
            (purchase, action)
        }
    };

    let purchase_id = purchase.seed.id.clone();
    let result = match settle(
        db,
        st,
        Some(play),
        &purchase,
        &action,
        Some(user_id),
        now_ms,
    )
    .await?
    {
        Settled::WrongAccount => {
            if purchase.seed.store == v0::ProtStore::Play {
                note_wrong_account_play(&purchase_id);
            }
            log::info!("payments: PROT_STORE_WRONG_ACCOUNT id={purchase_id} caller={user_id}");
            return Ok(rejected(v0::ProtStoreVerifyReason::WrongAccount, None));
        }
        Settled::AlreadyRevoked => {
            return Ok(rejected(
                v0::ProtStoreVerifyReason::Refunded,
                Some(purchase_id),
            ))
        }
        Settled::Moved(result) => result,
    };

    verify_answer(
        db,
        user_id,
        &purchase_id,
        &result.answer,
        result.row.as_ref(),
        now_ms,
    )
    .await
}

/// 9.4 step 8: the answer of a verify. `row` is the purchase's row after the
/// move (as read, when nothing moved): a Held row held over the cap answers
/// `pending` with reason `over_cap` (R63); a pause hold, `pending` alone.
async fn verify_answer(
    db: &Database,
    user_id: &str,
    purchase_id: &str,
    answer: &ProtStoreAnswer,
    row: Option<&ProtStorePurchase>,
    now_ms: i64,
) -> Result<v0::ProtStoreVerifyResponse> {
    use revolt_models::v0::{
        ProtStoreRejectReason as Reject, ProtStoreVerifyReason as Reason,
        ProtStoreVerifyStatus as Status,
    };

    let id = Some(purchase_id.to_string());
    Ok(match answer {
        ProtStoreAnswer::Credited | ProtStoreAnswer::AlreadyCredited => {
            let entry = credited_entry(db, purchase_id).await?;
            v0::ProtStoreVerifyResponse {
                status: if *answer == ProtStoreAnswer::Credited {
                    Status::Credited
                } else {
                    Status::AlreadyCredited
                },
                reason: None,
                purchase_id: id,
                balance: Some(wallet_balance(db, user_id).await?),
                ledger_id: Some(entry.id),
            }
        }
        ProtStoreAnswer::Held => {
            let over_cap =
                row.is_some_and(|row| row.hold_reason == Some(v0::ProtStoreHoldReason::OverCap));
            verify_response(Status::Pending, over_cap.then_some(Reason::OverCap), id)
        }
        ProtStoreAnswer::Rejected(Reject::TestPurchase) => rejected(Reason::Test, id),
        ProtStoreAnswer::Rejected(Reject::Unbound) => rejected(Reason::Unbound, id),
        ProtStoreAnswer::Rejected(Reject::UnknownProduct) => rejected(Reason::UnknownProduct, id),
        ProtStoreAnswer::Rejected(Reject::NoBuyer) => rejected(Reason::NoBuyer, id),
        ProtStoreAnswer::Rejected(Reject::BadPayload) => {
            note_verify_failure(user_id, "bad_payload", now_ms);
            return Err(create_error!(ProtStoreVerifyFailed));
        }
        ProtStoreAnswer::Refunded | ProtStoreAnswer::Revoked => rejected(Reason::Refunded, id),
        ProtStoreAnswer::Reinstated | ProtStoreAnswer::Ignored | ProtStoreAnswer::NotAssignable => {
            log::error!(
                "payments: PROT_STORE_VERIFY_UNEXPECTED id={purchase_id} answer={answer:?}"
            );
            return Err(create_error!(InternalError));
        }
    })
}

// ---------------------------------------------------------------------------
// App Store Server Notifications (9.5)
// ---------------------------------------------------------------------------

/// What the notification route answers: `Handled` / `Ignored` 200,
/// `BadSignature` 400, `Retry` 500 (Apple sends it again)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleNotificationOutcome {
    Handled,
    Ignored,
    BadSignature,
    Retry,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppleNotificationBody {
    signed_payload: String,
}

/// An App Store Server Notification V2, the body exactly as received
/// (`{"signedPayload": "<JWS>"}`)
pub async fn handle_apple_notification(
    db: &Database,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    apple: &dyn AppleStoreApi,
    body: &[u8],
    now_ms: i64,
) -> AppleNotificationOutcome {
    let Ok(body) = serde_json::from_slice::<AppleNotificationBody>(body) else {
        log::warn!("payments: PROT_STORE_NOTIFICATION_REFUSED why=body");
        return AppleNotificationOutcome::BadSignature;
    };
    handle_signed_notification(db, ps, st, apple, &body.signed_payload, false, now_ms).await
}

/// One signed notification: a live one, or a Notification History replay
/// (`replay`: the freshness lookup is forced)
async fn handle_signed_notification(
    db: &Database,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    apple: &dyn AppleStoreApi,
    signed_payload: &str,
    replay: bool,
    now_ms: i64,
) -> AppleNotificationOutcome {
    let Some(cfg) = st.apple.as_ref() else {
        log::error!(
            "payments: PROT_STORE_UNCONFIGURED: an App Store notification without [api.appstore]"
        );
        return AppleNotificationOutcome::Retry;
    };
    let verified = match verify_apple_jws(signed_payload, &cfg.root_g3_sha256) {
        Ok(verified) => verified,
        Err(err) => {
            log::warn!("payments: PROT_STORE_NOTIFICATION_REFUSED why={err:?}");
            return AppleNotificationOutcome::BadSignature;
        }
    };
    let Ok(notification) = serde_json::from_slice::<AppleNotification>(&verified.payload) else {
        // Signed by Apple yet not a notification we can read: a shape change
        // at Apple or a bug here, so staff must look (R61; log-only, never
        // mailed). Named by its hash, never by the JWS.
        let id = format!("jws:{}", sha256_hex(signed_payload));
        log::error!(
            "PROT_STORE_ALERT kind={PROT_STORE_LOG_UNDECODABLE_NOTIFICATION} id={id}: a \
             verified notification payload does not decode; ignored"
        );
        return AppleNotificationOutcome::Ignored;
    };
    let uuid = notification.notification_uuid.as_str();
    let kind = notification.notification_type.as_str();
    let Some(data) = notification.data.as_ref() else {
        log::info!("payments: PROT_STORE_NOTIFICATION_IGNORED uuid={uuid} type={kind} why=no_data");
        return AppleNotificationOutcome::Ignored;
    };
    if data.bundle_id != cfg.bundle_id || data.app_apple_id.is_some_and(|id| id != cfg.app_apple_id)
    {
        log::info!("payments: PROT_STORE_NOTIFICATION_IGNORED uuid={uuid} type={kind} why=app");
        return AppleNotificationOutcome::Ignored;
    }

    let freshness = match kind {
        "ONE_TIME_CHARGE" if replay => Freshness::Forced,
        "ONE_TIME_CHARGE" => Freshness::Rule,
        "REFUND" | "REFUND_REVERSED" => Freshness::Current,
        // REFUND_DECLINED, CONSUMPTION_REQUEST (E7: not answered), TEST, ...
        _ => {
            log::info!("payments: PROT_STORE_NOTIFICATION_IGNORED uuid={uuid} type={kind}");
            return AppleNotificationOutcome::Ignored;
        }
    };
    let Some(jws) = data.signed_transaction_info.as_deref() else {
        log::info!(
            "payments: PROT_STORE_NOTIFICATION_IGNORED uuid={uuid} type={kind} why=no_transaction"
        );
        return AppleNotificationOutcome::Ignored;
    };

    let checked = match apple_transaction_checks(cfg, apple, jws, freshness, now_ms).await {
        Ok(checked) => checked,
        // R61: Apple's own lookup answer did not verify or is not this
        // transaction: a store-side fault, never a reason to drop a refund.
        // Apple sends it again (and the history replay retries it).
        Err(AppleCheckError::Refused(why)) if why.starts_with("lookup_") => {
            log::warn!("payments: PROT_STORE_NOTIFICATION_RETRY uuid={uuid} type={kind} why={why}");
            return AppleNotificationOutcome::Retry;
        }
        Err(AppleCheckError::Refused(why)) => {
            log::warn!(
                "payments: PROT_STORE_NOTIFICATION_IGNORED uuid={uuid} type={kind} why={why}"
            );
            return AppleNotificationOutcome::Ignored;
        }
        Err(AppleCheckError::Lookup { purchase_id, error }) => {
            log::warn!(
                "payments: PROT_STORE_LOOKUP_FAILED id={purchase_id} uuid={uuid}: {error}; \
                 Apple retries"
            );
            return AppleNotificationOutcome::Retry;
        }
    };

    // Refunds act on the CURRENT state: revoked now → Revoke (a recorded
    // date is a replay, a no-op), not revoked now → Reverse
    let action = match (freshness, apple_action(&checked)) {
        (Freshness::Current, StoreAction::Seen) => StoreAction::Reverse,
        (_, action) => action,
    };
    let purchase = apple_purchase(st, ps, &checked, now_ms);
    match settle(db, st, None, &purchase, &action, None, now_ms).await {
        Ok(_) => AppleNotificationOutcome::Handled,
        Err(err) => {
            log::warn!(
                "payments: PROT_STORE_NOTIFICATION_RETRY id={} uuid={uuid}: {err:?}",
                purchase.seed.id
            );
            AppleNotificationOutcome::Retry
        }
    }
}

// ---------------------------------------------------------------------------
// Play real-time developer notifications (9.6, crond)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlayRtdn {
    package_name: Option<String>,
    /// A decimal string in Play's messages; a number is accepted too
    event_time_millis: Option<serde_json::Value>,
    one_time_product_notification: Option<PlayRtdnOneTime>,
    voided_purchase_notification: Option<PlayRtdnVoided>,
    pending_refund_review_notification: Option<PlayRtdnRefundReview>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlayRtdnOneTime {
    notification_type: Option<i64>,
    purchase_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlayRtdnVoided {
    purchase_token: Option<String>,
    order_id: Option<String>,
    /// 1 subscription, 2 one-time product
    product_type: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlayRtdnRefundReview {
    purchase_token: Option<String>,
}

/// `oneTimeProductNotification.notificationType` PURCHASED
const RTDN_ONE_TIME_PURCHASED: i64 = 1;
/// `voidedPurchaseNotification.productType` one-time product
const RTDN_VOIDED_ONE_TIME: i64 = 2;

fn rtdn_millis(value: &serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::String(text) => text.parse().ok(),
        serde_json::Value::Number(number) => number.as_i64(),
        _ => None,
    }
}

/// A Play revocation (a void, a cancelled purchase): the row, or a tombstone
/// built from what Play still tells about the purchase
#[allow(clippy::too_many_arguments)]
async fn play_revoke(
    db: &Database,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    play: &dyn PlayStoreApi,
    purchase_token: &str,
    order_id: Option<String>,
    revocation: Revocation,
    now_ms: i64,
) -> Result<MoveResult> {
    let id = play_purchase_id(purchase_token);
    let seed = match db.fetch_prot_store_purchase(&id).await? {
        Some(row) => row,
        None => {
            let found = match play.product_purchase(purchase_token).await {
                Ok(found) => Some(found),
                Err(StoreApiError::NotFound) => None,
                Err(err) => {
                    log::warn!("payments: PROT_STORE_LOOKUP_FAILED id={id}: {err}");
                    return Err(create_error!(InternalError));
                }
            };
            play_tombstone_seed(st, ps, purchase_token, found.as_ref(), order_id, now_ms)
        }
    };
    let event = StoreEvent::Revoke { revocation };
    run_store_move(db, st, &seed, &event, now_ms).await
}

/// A PURCHASED hint: read the purchase from Play and settle it with no caller
async fn play_seen_from_store(
    db: &Database,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    play: &dyn PlayStoreApi,
    purchase_token: &str,
    now_ms: i64,
) -> Result<()> {
    let id = play_purchase_id(purchase_token);
    let found = match play.product_purchase(purchase_token).await {
        Ok(found) => found,
        Err(StoreApiError::NotFound) => {
            log::warn!("payments: PROT_STORE_RTDN_UNKNOWN id={id}: Play does not know it");
            return Ok(());
        }
        Err(err) => {
            log::warn!("payments: PROT_STORE_LOOKUP_FAILED id={id}: {err}");
            return Err(create_error!(InternalError));
        }
    };
    let Some(purchase) = play_purchase(st, ps, purchase_token, &found, now_ms) else {
        log::warn!("payments: PROT_STORE_RTDN_IGNORED id={id} why=line_items");
        return Ok(());
    };
    let action = match found.purchase_state_context.purchase_state.as_str() {
        PLAY_PURCHASE_STATE_PURCHASED => StoreAction::Seen,
        PLAY_PURCHASE_STATE_CANCELLED => StoreAction::Revoke(Revocation {
            date: now_ms,
            reason: Some("cancelled".to_string()),
        }),
        // PENDING: its PURCHASED notification comes later
        _ => return Ok(()),
    };
    settle(db, st, Some(play), &purchase, &action, None, now_ms).await?;
    Ok(())
}

/// One RTDN (the Pub/Sub message's decoded bytes). Every message is a hint:
/// the purchase is read again from Play. Ok = acknowledge; Err = leave it
/// for redelivery. A message that does not parse, or names another package,
/// is acknowledged and logged (redelivery would never change it).
pub async fn handle_play_rtdn(
    db: &Database,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    play: &dyn PlayStoreApi,
    data: &[u8],
    now_ms: i64,
) -> Result<()> {
    let Some(cfg) = st.play.as_ref() else {
        log::error!("payments: PROT_STORE_UNCONFIGURED: an RTDN without [api.googleplay]");
        return Err(create_error!(InternalError));
    };
    let Ok(message) = serde_json::from_slice::<PlayRtdn>(data) else {
        log::warn!("payments: PROT_STORE_RTDN_UNREADABLE: acknowledged without action");
        return Ok(());
    };
    if message.package_name.as_deref() != Some(cfg.package_name.as_str()) {
        log::warn!("payments: PROT_STORE_RTDN_OTHER_PACKAGE: acknowledged without action");
        return Ok(());
    }
    let event_ms = message
        .event_time_millis
        .as_ref()
        .and_then(rtdn_millis)
        .unwrap_or(now_ms);

    if let Some(voided) = message.voided_purchase_notification {
        // Any void of a one-time product, full or quantity-partial, claws the
        // whole purchase; Play has no reversal
        let Some(token) = voided.purchase_token.filter(|token| !token.is_empty()) else {
            return Ok(());
        };
        if voided.product_type != Some(RTDN_VOIDED_ONE_TIME) {
            // Sloga sells no subscriptions: an absent or other product type
            // is worth a look (NIT 9)
            log::warn!(
                "payments: PROT_STORE_RTDN_VOID_IGNORED id={} product_type={:?}",
                play_purchase_id(&token),
                voided.product_type
            );
            return Ok(());
        }
        let revocation = Revocation {
            date: event_ms,
            reason: Some("voided".to_string()),
        };
        play_revoke(
            db,
            ps,
            st,
            play,
            &token,
            voided.order_id,
            revocation,
            now_ms,
        )
        .await?;
        return Ok(());
    }

    if let Some(one_time) = message.one_time_product_notification {
        let Some(token) = one_time.purchase_token.filter(|token| !token.is_empty()) else {
            return Ok(());
        };
        // CANCELED (2) changes nothing: a paid purchase is not cancelled
        if one_time.notification_type == Some(RTDN_ONE_TIME_PURCHASED) {
            play_seen_from_store(db, ps, st, play, &token, now_ms).await?;
        }
        return Ok(());
    }

    if let Some(review) = message.pending_refund_review_notification {
        let Some(token) = review.purchase_token.filter(|token| !token.is_empty()) else {
            return Ok(());
        };
        let id = play_purchase_id(&token);
        if db.fetch_prot_store_purchase(&id).await?.is_none() {
            log::warn!("payments: PROT_STORE_RTDN_REVIEW id={id}: no such purchase row");
            return Ok(());
        }
        db.set_prot_store_needs_action(&id, PROT_STORE_NEEDS_CHARGEBACK, now_ms)
            .await?;
        alert_row(db, st, &id, PROT_STORE_NEEDS_CHARGEBACK).await?;
        return Ok(());
    }

    // testNotification, subscriptions, anything else
    Ok(())
}

// ---------------------------------------------------------------------------
// The fresh store lookup (16 step 5, 12.6 assign; audit N3)
// ---------------------------------------------------------------------------

enum FreshState {
    /// Bought and not revoked now
    Live,
    Revoked(Revocation),
    /// The store does not know it
    Missing,
    /// Neither (a Play purchase still pending)
    Unsettled,
}

enum FreshError {
    Api(StoreApiError),
    /// The store's answer did not verify or is not this purchase
    Refused(String),
}

/// What the store says about a row's purchase NOW
async fn fresh_store_state(
    st: &ProtStoreSettings,
    apple: &dyn AppleStoreApi,
    play: &dyn PlayStoreApi,
    row: &ProtStorePurchase,
    now_ms: i64,
) -> std::result::Result<FreshState, FreshError> {
    match row.store {
        v0::ProtStore::Apple => {
            let Some(cfg) = st.apple.as_ref() else {
                return Err(FreshError::Api(StoreApiError::NotConfigured));
            };
            let Some(info) = row.apple.as_ref() else {
                return Err(FreshError::Refused("no_apple_payload".to_string()));
            };
            let jws = match apple
                .transaction_info(row.environment, &info.transaction_id)
                .await
            {
                Ok(jws) => jws,
                Err(StoreApiError::NotFound) => return Ok(FreshState::Missing),
                Err(err) => return Err(FreshError::Api(err)),
            };
            let (tx, environment, _) =
                decode_apple_transaction(cfg, &jws).map_err(FreshError::Refused)?;
            if tx.transaction_id != info.transaction_id || environment != row.environment {
                return Err(FreshError::Refused("lookup_mismatch".to_string()));
            }
            Ok(match revocation_of(&tx) {
                Some(revocation) => FreshState::Revoked(revocation),
                None => FreshState::Live,
            })
        }
        v0::ProtStore::Play => {
            let Some(info) = row.play.as_ref() else {
                return Err(FreshError::Refused("no_play_payload".to_string()));
            };
            let found = match play.product_purchase(&info.purchase_token).await {
                Ok(found) => found,
                Err(StoreApiError::NotFound) => return Ok(FreshState::Missing),
                Err(err) => return Err(FreshError::Api(err)),
            };
            Ok(match found.purchase_state_context.purchase_state.as_str() {
                PLAY_PURCHASE_STATE_PURCHASED => FreshState::Live,
                PLAY_PURCHASE_STATE_CANCELLED => FreshState::Revoked(Revocation {
                    date: now_ms,
                    reason: Some("cancelled".to_string()),
                }),
                _ => FreshState::Unsettled,
            })
        }
    }
}

fn fresh_error_text(err: &FreshError) -> String {
    match err {
        FreshError::Api(err) => err.to_string(),
        FreshError::Refused(why) => format!("refused: {why}"),
    }
}

// ---------------------------------------------------------------------------
// Reconcile (16; crond, every 10 minutes while credentials are configured)
// ---------------------------------------------------------------------------

/// What one reconcile pass did
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StoreReconcileReport {
    /// RTDN messages handled (and acknowledged)
    pub rtdn: u64,
    /// Play purchases recorded consumed
    pub consumed: u64,
    /// Play revocations applied (voids, cancelled purchases)
    pub voided: u64,
    /// Notification History payloads handled
    pub apple_replayed: u64,
    /// Held rows credited after the pause ended
    pub held_credited: u64,
    pub intents_expired: u64,
    /// Row alerts this replica claimed
    pub alerts: u64,
    /// Steps or items that failed (retried next tick)
    pub failed: u64,
}

/// One reconcile pass (16). Not gated on the open flags. Multi-replica safe:
/// ledger keys, the row version CAS, the cursor CAS and the alert claims.
pub async fn reconcile_store(
    db: &Database,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    apple: &dyn AppleStoreApi,
    play: &dyn PlayStoreApi,
    now_ms: i64,
) -> StoreReconcileReport {
    let mut report = StoreReconcileReport::default();

    if play.configured() {
        reconcile_rtdn(db, ps, st, play, now_ms, &mut report).await;
        reconcile_unconsumed(db, st, play, now_ms, &mut report).await;
        reconcile_play_voided(db, ps, st, play, now_ms, &mut report).await;
    }
    if apple.configured() && st.apple.is_some() {
        reconcile_apple_history(db, ps, st, apple, now_ms, &mut report).await;
    }
    if st.credit_paused {
        reconcile_paused_play(db, st, now_ms, false, &mut report).await;
    } else {
        reconcile_held(db, ps, st, apple, play, now_ms, &mut report).await;
        // R63: an over-cap Play hold is not credited when a pause ends, so
        // the 24 h Play alert covers it while credits run too
        reconcile_paused_play(db, st, now_ms, true, &mut report).await;
    }

    match db
        .expire_prot_store_intents(now_ms, INTENT_SWEEP_BATCH)
        .await
    {
        Ok(expired) => report.intents_expired = expired,
        Err(err) => {
            report.failed += 1;
            log::warn!("payments: could not expire store intents: {err:?}");
        }
    }

    reconcile_unbound_play(db, st, now_ms, &mut report).await;

    match db
        .delete_stale_prot_store_intents(
            now_ms.saturating_sub(INTENT_PURGE_AFTER_MS),
            INTENT_SWEEP_BATCH,
        )
        .await
    {
        Ok(0) => {}
        Ok(deleted) => log::info!("payments: deleted {deleted} stale store intents"),
        Err(err) => {
            report.failed += 1;
            log::warn!("payments: could not delete stale store intents: {err:?}");
        }
    }

    if report != StoreReconcileReport::default() {
        log::info!("payments: store reconcile {report:?}");
    }
    report
}

/// 16 step 1: pull RTDN, handle each, acknowledge the handled ones once.
/// Any pull error counts in `failed` (crond raises R52's alert after 6 failed
/// ticks in a row); an idle subscription is an empty `Ok` (R55).
async fn reconcile_rtdn(
    db: &Database,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    play: &dyn PlayStoreApi,
    now_ms: i64,
    report: &mut StoreReconcileReport,
) {
    if !play.pubsub_configured() {
        return;
    }
    let messages = match play.pull(RTDN_PULL_MAX).await {
        Ok(messages) => messages,
        // Under R55 a `Transient` pull is a real failure (server error,
        // network), never an idle subscription
        Err(err) => {
            report.failed += 1;
            log::warn!("payments: PROT_STORE_RTDN_PULL_FAILED: {err}");
            return;
        }
    };

    let mut acked = Vec::new();
    for message in messages {
        match handle_play_rtdn(db, ps, st, play, &message.data, now_ms).await {
            Ok(()) => {
                report.rtdn += 1;
                acked.push(message.ack_id);
            }
            Err(err) => {
                report.failed += 1;
                log::warn!(
                    "payments: RTDN {} left for redelivery: {err:?}",
                    message.message_id
                );
            }
        }
    }
    if !acked.is_empty() {
        if let Err(err) = play.acknowledge(&acked).await {
            report.failed += 1;
            log::warn!(
                "payments: could not acknowledge {} RTDN: {err}",
                acked.len()
            );
        }
    }
}

/// Where the next tick's share of each rotating reconcile step starts (per
/// process; replicas rotate independently, which is safe: every write CASes)
static UNCONSUMED_TURN: AtomicUsize = AtomicUsize::new(0);
static HELD_APPLE_TURN: AtomicUsize = AtomicUsize::new(0);
static HELD_PLAY_TURN: AtomicUsize = AtomicUsize::new(0);

/// MINOR 6: this tick's share of a step's rows (oldest first, up to
/// `RECONCILE_SCAN`): at most `batch` of them, starting where the previous
/// tick stopped and wrapping round, so a head of old stuck rows never starves
/// the rows behind it. Every row gets a turn within `len / batch + 1` ticks.
fn this_ticks_share<T>(mut rows: Vec<T>, turn: &AtomicUsize, batch: usize) -> Vec<T> {
    let len = rows.len();
    if len <= batch {
        turn.store(0, Ordering::Relaxed);
        return rows;
    }
    let start = turn.load(Ordering::Relaxed) % len;
    rows.rotate_left(start);
    rows.truncate(batch);
    turn.store((start + batch) % len, Ordering::Relaxed);
    rows
}

/// 16 step 2: consume what was credited and not consumed yet. A consume Play
/// refuses: read the purchase (consumed already → record it; cancelled →
/// revoke; else retry next tick). Still unconsumed a day after the credit:
/// the work item first, then the claimed alert. Rows rotate (MINOR 6).
async fn reconcile_unconsumed(
    db: &Database,
    st: &ProtStoreSettings,
    play: &dyn PlayStoreApi,
    now_ms: i64,
    report: &mut StoreReconcileReport,
) {
    let rows = match db.fetch_unconsumed_play_purchases(RECONCILE_SCAN).await {
        Ok(rows) => this_ticks_share(rows, &UNCONSUMED_TURN, RECONCILE_BATCH as usize),
        Err(err) => {
            report.failed += 1;
            log::warn!("payments: could not read unconsumed Play purchases: {err:?}");
            return;
        }
    };

    for row in rows {
        let Some(info) = row.play.as_ref() else {
            continue;
        };
        let mut consumed = false;
        match play.consume(&row.product_id, &info.purchase_token).await {
            Ok(()) => consumed = true,
            Err(StoreApiError::Rejected { .. } | StoreApiError::NotFound) => {
                match play.product_purchase(&info.purchase_token).await {
                    Ok(found)
                        if found.purchase_state_context.purchase_state
                            == PLAY_PURCHASE_STATE_CANCELLED =>
                    {
                        let event = StoreEvent::Revoke {
                            revocation: Revocation {
                                date: now_ms,
                                reason: Some("cancelled".to_string()),
                            },
                        };
                        match run_store_move(db, st, &row, &event, now_ms).await {
                            Ok(_) => report.voided += 1,
                            Err(err) => {
                                report.failed += 1;
                                log::warn!("payments: could not revoke {}: {err:?}", row.id);
                            }
                        }
                        continue;
                    }
                    Ok(found) => {
                        consumed = found.product_line_item.iter().any(|item| {
                            item.product_offer_details.consumption_state.as_deref()
                                == Some(PLAY_CONSUMPTION_STATE_CONSUMED)
                        });
                    }
                    Err(err) => log::warn!(
                        "payments: PROT_STORE_LOOKUP_FAILED id={}: {err}; retried next tick",
                        row.id
                    ),
                }
            }
            Err(err) => log::warn!(
                "payments: PROT_STORE_CONSUME_FAILED id={}: {err}; retried next tick",
                row.id
            ),
        }

        if consumed {
            match db
                .mark_prot_store_consumed(&row.id, row.version, now_ms)
                .await
            {
                Ok(true) => report.consumed += 1,
                // Moved since: the next tick reads it again
                Ok(false) => {}
                Err(err) => {
                    report.failed += 1;
                    log::warn!("payments: could not record {} consumed: {err:?}", row.id);
                }
            }
            continue;
        }

        let overdue = row
            .credited_at
            .is_some_and(|at| now_ms.saturating_sub(at) > PLAY_UNCONSUMED_ALERT_MS);
        if overdue {
            let alerted = async {
                db.set_prot_store_needs_action(&row.id, PROT_STORE_NEEDS_UNCONSUMED, now_ms)
                    .await?;
                alert_row(db, st, &row.id, PROT_STORE_NEEDS_UNCONSUMED).await
            }
            .await;
            match alerted {
                Ok(true) => report.alerts += 1,
                Ok(false) => {}
                Err(err) => {
                    report.failed += 1;
                    log::warn!(
                        "payments: could not raise the unconsumed item of {}: {err:?}",
                        row.id
                    );
                }
            }
        }
    }
}

/// The epoch-ms value of a cursor (None when absent or unreadable)
fn cursor_ms(cursor: Option<&ProtStoreCursor>) -> Option<i64> {
    cursor.and_then(|cursor| cursor.cursor.parse().ok())
}

/// Move a cursor (CAS on its version); the loser of a race skips
async fn advance_cursor(
    db: &Database,
    id: &str,
    current: Option<&ProtStoreCursor>,
    value: i64,
    now_ms: i64,
) -> Result<()> {
    let next = ProtStoreCursor {
        id: id.to_string(),
        cursor: value.to_string(),
        version: 0,
        updated_at: now_ms,
    };
    if !db
        .put_prot_store_cursor(&next, current.map(|cursor| cursor.version))
        .await?
    {
        log::info!("payments: the {id} cursor was moved by another replica");
    }
    Ok(())
}

/// The `startTime` of a voidedpurchases scan (R58): an hour before the
/// cursor, but never earlier than 30 days less an hour ago (Play keeps 30
/// days and refuses an older start); the first scan starts there too
fn play_voided_start(cursor: Option<&ProtStoreCursor>, now_ms: i64) -> i64 {
    let oldest = now_ms
        .saturating_sub(PLAY_VOIDED_KEPT_MS)
        .saturating_add(PLAY_VOIDED_OVERLAP_MS);
    match cursor_ms(cursor) {
        Some(mark) => mark.saturating_sub(PLAY_VOIDED_OVERLAP_MS).max(oldest),
        None => oldest,
    }
}

/// 16 step 3: once a day, every void from `play_voided_start`; when every
/// page was read and every void applied, the cursor moves to this scan's
/// query time less the hour of overlap (R58: never to the latest
/// `voidedTimeMillis`, which a quiet month would leave behind Play's window)
async fn reconcile_play_voided(
    db: &Database,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    play: &dyn PlayStoreApi,
    now_ms: i64,
    report: &mut StoreReconcileReport,
) {
    let cursor = match db.fetch_prot_store_cursor(PROT_STORE_CURSOR_PLAY).await {
        Ok(cursor) => cursor,
        Err(err) => {
            report.failed += 1;
            log::warn!("payments: could not read the Play voided cursor: {err:?}");
            return;
        }
    };
    if cursor
        .as_ref()
        .is_some_and(|c| now_ms.saturating_sub(c.updated_at) < PLAY_VOIDED_EVERY_MS)
    {
        return;
    }

    let start = play_voided_start(cursor.as_ref(), now_ms);
    let mut page_token: Option<String> = None;
    let mut complete = false;
    let mut all_applied = true;
    for _ in 0..STORE_PAGES_MAX {
        let page = match play.voided_purchases(start, page_token.as_deref()).await {
            Ok(page) => page,
            Err(err) => {
                report.failed += 1;
                log::warn!("payments: PROT_STORE_VOIDED_FAILED: {err}");
                break;
            }
        };
        for voided in page.voided {
            let revocation = Revocation {
                date: voided.voided_time_ms,
                reason: Some("voided".to_string()),
            };
            match play_revoke(
                db,
                ps,
                st,
                play,
                &voided.purchase_token,
                voided.order_id,
                revocation,
                now_ms,
            )
            .await
            {
                Ok(_) => report.voided += 1,
                Err(err) => {
                    all_applied = false;
                    report.failed += 1;
                    log::warn!(
                        "payments: could not apply a Play void ({}): {err:?}",
                        play_purchase_id(&voided.purchase_token)
                    );
                }
            }
        }
        match page.next_page_token {
            Some(token) if !token.is_empty() => page_token = Some(token),
            _ => {
                complete = true;
                break;
            }
        }
    }

    if complete && all_applied {
        let mark = now_ms.saturating_sub(PLAY_VOIDED_OVERLAP_MS);
        if let Err(err) =
            advance_cursor(db, PROT_STORE_CURSOR_PLAY, cursor.as_ref(), mark, now_ms).await
        {
            report.failed += 1;
            log::warn!("payments: could not move the Play voided cursor: {err:?}");
        }
    }
}

/// 16 step 4: hourly, Notification History from two hours before the cursor
/// (Sandbox too when testers are listed), each payload through 9.5 with the
/// freshness lookup forced; the cursor moves to now only when all of it was
/// read and nothing asked for a retry
async fn reconcile_apple_history(
    db: &Database,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    apple: &dyn AppleStoreApi,
    now_ms: i64,
    report: &mut StoreReconcileReport,
) {
    let cursor = match db.fetch_prot_store_cursor(PROT_STORE_CURSOR_APPLE).await {
        Ok(cursor) => cursor,
        Err(err) => {
            report.failed += 1;
            log::warn!("payments: could not read the Apple history cursor: {err:?}");
            return;
        }
    };
    if cursor
        .as_ref()
        .is_some_and(|c| now_ms.saturating_sub(c.updated_at) < APPLE_HISTORY_EVERY_MS)
    {
        return;
    }

    let start = match cursor_ms(cursor.as_ref()) {
        Some(mark) => mark.saturating_sub(APPLE_HISTORY_OVERLAP_MS),
        None => now_ms.saturating_sub(APPLE_HISTORY_FIRST_MS),
    };
    let mut environments = vec![v0::ProtStoreEnvironment::Production];
    if !st.test_user_ids.is_empty() {
        environments.push(v0::ProtStoreEnvironment::Sandbox);
    }

    let mut all_done = true;
    for environment in environments {
        let mut page_token: Option<String> = None;
        let mut complete = false;
        for _ in 0..STORE_PAGES_MAX {
            let page = match apple
                .notification_history(environment, start, now_ms, page_token.as_deref())
                .await
            {
                Ok(page) => page,
                Err(err) => {
                    report.failed += 1;
                    log::warn!("payments: PROT_STORE_HISTORY_FAILED: {err}");
                    break;
                }
            };
            for payload in &page.signed_payloads {
                match handle_signed_notification(db, ps, st, apple, payload, true, now_ms).await {
                    AppleNotificationOutcome::Handled => report.apple_replayed += 1,
                    AppleNotificationOutcome::Ignored | AppleNotificationOutcome::BadSignature => {}
                    AppleNotificationOutcome::Retry => {
                        all_done = false;
                        report.failed += 1;
                    }
                }
            }
            match page.pagination_token {
                Some(token) if page.has_more && !token.is_empty() => page_token = Some(token),
                _ => {
                    complete = true;
                    break;
                }
            }
        }
        all_done &= complete;
    }

    if all_done {
        if let Err(err) =
            advance_cursor(db, PROT_STORE_CURSOR_APPLE, cursor.as_ref(), now_ms, now_ms).await
        {
            report.failed += 1;
            log::warn!("payments: could not move the Apple history cursor: {err:?}");
        }
    }
}

/// 16 step 5: credit pause off → every pause hold is looked up at the store
/// again (audit N3): revoked → Revoke; bought → Unpause, or (R63) an
/// over-cap hold when the credit would take the wallet past `wallet_cap`; a
/// failed lookup waits for the next tick. A Play credit is then consumed.
/// An over-cap hold is never unpaused: it waits for staff or a refund. Rows
/// rotate (MINOR 6).
async fn reconcile_held(
    db: &Database,
    ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    apple: &dyn AppleStoreApi,
    play: &dyn PlayStoreApi,
    now_ms: i64,
    report: &mut StoreReconcileReport,
) {
    for store in [v0::ProtStore::Apple, v0::ProtStore::Play] {
        let configured = match store {
            v0::ProtStore::Apple => apple.configured() && st.apple.is_some(),
            v0::ProtStore::Play => play.configured(),
        };
        if !configured {
            continue;
        }
        let turn = match store {
            v0::ProtStore::Apple => &HELD_APPLE_TURN,
            v0::ProtStore::Play => &HELD_PLAY_TURN,
        };
        let rows = match db
            .fetch_prot_store_purchases_by_state(store, v0::ProtStoreState::Held, RECONCILE_SCAN)
            .await
        {
            Ok(rows) => this_ticks_share(rows, turn, RECONCILE_BATCH as usize),
            Err(err) => {
                report.failed += 1;
                log::warn!(
                    "payments: could not read Held {} rows: {err:?}",
                    store.as_str()
                );
                continue;
            }
        };

        for row in rows {
            if row.hold_reason == Some(v0::ProtStoreHoldReason::OverCap) {
                continue;
            }
            let event = match fresh_store_state(st, apple, play, &row, now_ms).await {
                Ok(FreshState::Live) => StoreEvent::Unpause {
                    wallet_cap: ps.wallet_cap,
                },
                Ok(FreshState::Revoked(revocation)) => StoreEvent::Revoke { revocation },
                Ok(FreshState::Missing | FreshState::Unsettled) => {
                    log::warn!(
                        "payments: Held {} is not settled at the store; kept",
                        row.id
                    );
                    continue;
                }
                Err(err) => {
                    report.failed += 1;
                    log::warn!(
                        "payments: PROT_STORE_LOOKUP_FAILED id={}: {}; retried next tick",
                        row.id,
                        fresh_error_text(&err)
                    );
                    continue;
                }
            };
            match run_store_move(db, st, &row, &event, now_ms).await {
                Ok(result) => {
                    if result.answer == ProtStoreAnswer::Credited {
                        report.held_credited += 1;
                        if let Some(moved) = result.row.as_ref().filter(|_| result.posted) {
                            if moved.store == v0::ProtStore::Play {
                                consume_after_credit(db, play, moved, now_ms).await;
                            }
                        }
                    }
                }
                Err(err) => {
                    report.failed += 1;
                    log::warn!("payments: could not settle Held {}: {err:?}", row.id);
                }
            }
        }
    }
}

/// R59: while credits are paused, every Play purchase held longer than a day
/// gets the `play_held_24h` work item, then the claimed (mailed) alert: Play
/// refunds an unconsumed purchase after 3 days (owner Q2). Leaving Held
/// clears it (`after_move`). No store call is made; nothing moves.
/// R63: an over-cap Play hold gets the same day alert, paused or not
/// (`over_cap_only` while credits run), and keeps its `over_cap_review` work
/// item (the item its release clears).
async fn reconcile_paused_play(
    db: &Database,
    st: &ProtStoreSettings,
    now_ms: i64,
    over_cap_only: bool,
    report: &mut StoreReconcileReport,
) {
    let rows = match db
        .fetch_prot_store_purchases_by_state(
            v0::ProtStore::Play,
            v0::ProtStoreState::Held,
            RECONCILE_SCAN,
        )
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            report.failed += 1;
            log::warn!("payments: could not read Held Play rows: {err:?}");
            return;
        }
    };
    let held_over_cap =
        |row: &ProtStorePurchase| row.hold_reason == Some(v0::ProtStoreHoldReason::OverCap);
    for row in rows.iter().filter(|row| {
        now_ms.saturating_sub(row.created_at) > PLAY_HELD_ALERT_MS
            && (!over_cap_only || held_over_cap(row))
    }) {
        let raised = async {
            if !held_over_cap(row) && row.needs_action.as_deref() != Some(PROT_STORE_NEEDS_HELD) {
                db.set_prot_store_needs_action(&row.id, PROT_STORE_NEEDS_HELD, now_ms)
                    .await?;
            }
            if row.alerted.iter().any(|kind| kind == PROT_STORE_NEEDS_HELD) {
                return Ok(false);
            }
            alert_row(db, st, &row.id, PROT_STORE_NEEDS_HELD).await
        }
        .await;
        match raised {
            Ok(true) => report.alerts += 1,
            Ok(false) => {}
            Err(err) => {
                report.failed += 1;
                log::warn!(
                    "payments: could not raise the held item of {}: {err:?}",
                    row.id
                );
            }
        }
    }
}

/// 16 step 7: a Play purchase no intent binds, a day after it was seen →
/// the claimed `unbound_play` alert (E10). Read by kind: the Play rows
/// Rejected with the `unbound` work item (MINOR 6: never the newest 100
/// work items of all kinds, which other kinds could fill)
async fn reconcile_unbound_play(
    db: &Database,
    st: &ProtStoreSettings,
    now_ms: i64,
    report: &mut StoreReconcileReport,
) {
    let rows = match db
        .fetch_prot_store_purchases_by_state(
            v0::ProtStore::Play,
            v0::ProtStoreState::Rejected,
            RECONCILE_SCAN,
        )
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            report.failed += 1;
            log::warn!("payments: could not read the rejected Play rows: {err:?}");
            return;
        }
    };
    for row in rows.iter().filter(|row| {
        row.store == v0::ProtStore::Play
            && row.needs_action.as_deref() == Some(PROT_STORE_NEEDS_UNBOUND)
            && now_ms.saturating_sub(row.created_at) > PLAY_UNBOUND_ALERT_MS
            && !row.alerted.iter().any(|kind| kind == ALERT_UNBOUND_PLAY)
    }) {
        match alert_row(db, st, &row.id, ALERT_UNBOUND_PLAY).await {
            Ok(true) => report.alerts += 1,
            Ok(false) => {}
            Err(err) => {
                report.failed += 1;
                log::warn!(
                    "payments: could not raise the unbound alert of {}: {err:?}",
                    row.id
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Admin (12.6)
// ---------------------------------------------------------------------------

fn purchase_view(row: &ProtStorePurchase) -> v0::ProtStorePurchaseView {
    v0::ProtStorePurchaseView {
        id: row.id.clone(),
        store: row.store,
        user_id: row.user_id.clone(),
        product_id: row.product_id.clone(),
        prot: row.prot,
        quantity: row.quantity,
        environment: row.environment,
        state: row.state,
        reject_reason: row.reject_reason,
        hold_reason: row.hold_reason,
        refund_gen: row.refund_gen,
        storefront: row.storefront.clone(),
        needs_action: row.needs_action.clone(),
        assigned_by: row.assigned_by.clone(),
        consumed: row.play.as_ref().map(|play| play.consumed_at.is_some()),
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

/// One ledger row of a purchase, signed from the buyer's side: a credit
/// (`purchase:`, `reinstate:`) +, a clawback (wallet or held pledge) -
fn purchase_ledger_view(row: ProtLedgerEntry) -> v0::ProtLedgerView {
    let amount = if row.kind == ProtEntryKind::Purchase {
        row.amount
    } else {
        row.amount.saturating_neg()
    };
    v0::ProtLedgerView {
        id: row.id,
        kind: row.kind,
        amount,
        created_at: row.created_at,
        order_id: row.reference.order_id,
    }
}

/// One store purchase for support: the row, every ledger row of it (oldest
/// first) and the buyer's balance. NotFound for an id that is not a store
/// purchase id or names no row.
pub async fn admin_store_purchase(db: &Database, id: &str) -> Result<v0::ProtStoreAdminPurchase> {
    if !is_store_purchase_id(id) {
        return Err(create_error!(NotFound));
    }
    let row = db
        .fetch_prot_store_purchase(id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;

    let mut entries = db.fetch_prot_entries_by_order(id).await?;
    entries.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    let unspent = match row.user_id.as_deref() {
        Some(user_id) => Some(wallet_balance(db, user_id).await?),
        None => None,
    };
    Ok(v0::ProtStoreAdminPurchase {
        purchase: purchase_view(&row),
        ledger: entries.into_iter().map(purchase_ledger_view).collect(),
        unspent,
    })
}

/// The staff work list: rows with a work item, newest first (at most 100)
pub async fn admin_store_needs_action(db: &Database) -> Result<Vec<v0::ProtStorePurchaseView>> {
    Ok(db
        .fetch_prot_store_needs_action(100)
        .await?
        .iter()
        .map(purchase_view)
        .collect())
}

/// E10: credit an unbound purchase to the account support identified. The
/// target must exist, not be deleted, not be a bot, and not be the acting
/// admin (owner Q4). The purchase is looked up at the store first: unknown
/// there, revoked (which is applied to the row) or cancelled →
/// `InvalidOperation`; a failed lookup → `InternalError`; no credentials →
/// `ProtStoreUnavailable`. Only a `Rejected{Unbound}` row of a priced
/// production purchase moves; while credits are paused it is recorded Held
/// (R16). A Play credit is consumed after it commits.
// The pinned contract signature (section 9.2)
#[allow(clippy::too_many_arguments)]
pub async fn admin_assign_store_purchase(
    db: &Database,
    _ps: &ProtSalesSettings,
    st: &ProtStoreSettings,
    apple: &dyn AppleStoreApi,
    play: &dyn PlayStoreApi,
    admin_id: &str,
    id: &str,
    target_user_id: &str,
    now_ms: i64,
) -> Result<v0::ProtStoreAdminPurchase> {
    if !is_store_purchase_id(id) {
        return Err(create_error!(NotFound));
    }
    if target_user_id == admin_id {
        return Err(create_error!(InvalidOperation));
    }
    let target = match db.fetch_user(target_user_id).await {
        Ok(user) => user,
        Err(err) if matches!(err.error_type, ErrorType::NotFound) => {
            return Err(create_error!(NotFound))
        }
        Err(err) => return Err(err),
    };
    if target.bot.is_some() || is_deleted(&target) {
        return Err(create_error!(InvalidOperation));
    }

    let row = db
        .fetch_prot_store_purchase(id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    // Only an unbound production purchase of a known product (a test
    // purchase is never credited by hand; an unknown product has no Prot)
    let assignable = row.state == v0::ProtStoreState::Rejected
        && row.reject_reason == Some(v0::ProtStoreRejectReason::Unbound)
        && row.revoked_at.is_none()
        && row.environment == v0::ProtStoreEnvironment::Production
        && row.prot > 0;
    if !assignable {
        return Err(create_error!(InvalidOperation));
    }

    match fresh_store_state(st, apple, play, &row, now_ms).await {
        Ok(FreshState::Live) => {}
        Ok(FreshState::Revoked(revocation)) => {
            let event = StoreEvent::Revoke { revocation };
            run_store_move(db, st, &row, &event, now_ms).await?;
            return Err(create_error!(InvalidOperation));
        }
        Ok(FreshState::Missing | FreshState::Unsettled) => {
            return Err(create_error!(InvalidOperation))
        }
        Err(FreshError::Api(StoreApiError::NotConfigured)) => {
            return Err(create_error!(ProtStoreUnavailable))
        }
        Err(err) => {
            log::warn!(
                "payments: PROT_STORE_LOOKUP_FAILED id={id}: {}",
                fresh_error_text(&err)
            );
            return Err(create_error!(InternalError));
        }
    }

    let event = StoreEvent::Assign {
        user_id: target_user_id.to_string(),
        admin_id: admin_id.to_string(),
        paused: st.credit_paused,
    };
    let result = run_store_move(db, st, &row, &event, now_ms).await?;
    match result.answer {
        ProtStoreAnswer::Credited => {
            if let Some(moved) = result.row.as_ref().filter(|_| result.posted) {
                if moved.store == v0::ProtStore::Play {
                    consume_after_credit(db, play, moved, now_ms).await;
                }
            }
        }
        ProtStoreAnswer::Held => {}
        _ => return Err(create_error!(InvalidOperation)),
    }
    log::info!(
        "payments: store purchase {id} assigned to {target_user_id} by {admin_id} ({:?})",
        result.answer
    );
    admin_store_purchase(db, id).await
}

/// R63: staff release of a purchase held over the wallet cap: credit it to
/// its buyer, ignoring the cap. Only a `Held` row whose `hold_reason` is
/// `over_cap` moves; anything else → `InvalidOperation`. The buyer must
/// exist, not be deleted, not be a bot, and not be the acting admin. While
/// store credits are paused nothing is released (`InvalidOperation`; the
/// pause wins, as for assign, R16). The purchase is looked up at the store
/// first: revoked → the normal Revoke move (nothing credited) and
/// `InvalidOperation`; unknown or unsettled → `InvalidOperation`; a failed
/// lookup → `InternalError`; no credentials → `ProtStoreUnavailable`. A Play
/// credit is consumed after it commits. Clears `over_cap_review`.
pub async fn admin_release_store_purchase(
    db: &Database,
    st: &ProtStoreSettings,
    apple: &dyn AppleStoreApi,
    play: &dyn PlayStoreApi,
    admin_id: &str,
    id: &str,
    now_ms: i64,
) -> Result<v0::ProtStoreAdminPurchase> {
    if !is_store_purchase_id(id) {
        return Err(create_error!(NotFound));
    }
    let row = db
        .fetch_prot_store_purchase(id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    if row.state != v0::ProtStoreState::Held
        || row.hold_reason != Some(v0::ProtStoreHoldReason::OverCap)
    {
        return Err(create_error!(InvalidOperation));
    }
    // The buyer: never the acting admin, never a bot, deleted or gone account
    let Some(buyer_id) = row.user_id.as_deref() else {
        return Err(create_error!(InvalidOperation));
    };
    if buyer_id == admin_id {
        return Err(create_error!(InvalidOperation));
    }
    let buyer = match db.fetch_user(buyer_id).await {
        Ok(user) => user,
        Err(err) if matches!(err.error_type, ErrorType::NotFound) => {
            return Err(create_error!(InvalidOperation))
        }
        Err(err) => return Err(err),
    };
    if buyer.bot.is_some() || is_deleted(&buyer) {
        return Err(create_error!(InvalidOperation));
    }
    if st.credit_paused {
        return Err(create_error!(InvalidOperation));
    }

    match fresh_store_state(st, apple, play, &row, now_ms).await {
        Ok(FreshState::Live) => {}
        Ok(FreshState::Revoked(revocation)) => {
            let event = StoreEvent::Revoke { revocation };
            run_store_move(db, st, &row, &event, now_ms).await?;
            return Err(create_error!(InvalidOperation));
        }
        Ok(FreshState::Missing | FreshState::Unsettled) => {
            return Err(create_error!(InvalidOperation))
        }
        Err(FreshError::Api(StoreApiError::NotConfigured)) => {
            return Err(create_error!(ProtStoreUnavailable))
        }
        Err(err) => {
            log::warn!(
                "payments: PROT_STORE_LOOKUP_FAILED id={id}: {}",
                fresh_error_text(&err)
            );
            return Err(create_error!(InternalError));
        }
    }

    let result = run_store_move(db, st, &row, &StoreEvent::Release, now_ms).await?;
    if result.answer != ProtStoreAnswer::Credited {
        return Err(create_error!(InvalidOperation));
    }
    if let Some(moved) = result.row.as_ref().filter(|_| result.posted) {
        if moved.store == v0::ProtStore::Play {
            consume_after_credit(db, play, moved, now_ms).await;
        }
    }
    log::info!(
        "payments: PROT_STORE_RELEASED id={id} user={buyer_id} prot={} by {admin_id}",
        row.prot
    );
    admin_store_purchase(db, id).await
}

/// Clear a staff work item: `reversed_unpaid` or `chargeback_review`, and
/// only the kind the row holds; anything else → `InvalidOperation`. No
/// ledger effect.
pub async fn admin_resolve_store_purchase(
    db: &Database,
    admin_id: &str,
    id: &str,
    kind: &str,
    now_ms: i64,
) -> Result<v0::ProtStoreAdminPurchase> {
    if !is_store_purchase_id(id) {
        return Err(create_error!(NotFound));
    }
    if kind != PROT_STORE_NEEDS_REVERSED_UNPAID && kind != PROT_STORE_NEEDS_CHARGEBACK {
        return Err(create_error!(InvalidOperation));
    }
    let row = db
        .fetch_prot_store_purchase(id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    if row.needs_action.as_deref() != Some(kind)
        || !db.clear_prot_store_needs_action(id, kind, now_ms).await?
    {
        return Err(create_error!(InvalidOperation));
    }
    log::info!("payments: store work item {kind} of {id} resolved by {admin_id}");
    admin_store_purchase(db, id).await
}

/// The engine through both drivers: the database is the one `TEST_DB` names
/// (REFERENCE or MONGODB; the tests panic when it is unset, so they never
/// reach production), the stores are L2b's mocks, and every Apple JWS is
/// signed by a test chain built here (the verifier is pinned to its root).
#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::engine::general_purpose::STANDARD;
    use const_oid::{AssociatedOid, ObjectIdentifier};
    use der::asn1::{BitString, OctetString, UtcTime};
    use der::{Any, DateTime, Encode};
    use ecdsa::signature::{hazmat::PrehashSigner, Signer};
    use revolt_config::{
        ApiAppStore, ApiGooglePlay, ApiStripe, FeaturePayments, ProtectionFeatures,
    };
    use revolt_database::test_teardown::TestDatabaseGuard;
    use revolt_database::{
        prot_key_admin, prot_store_key_clawback, prot_store_key_reinstate, BotInformation,
        DatabaseInfo, PaymentOrder, PaymentProvider, ProtAmount, ProtPosting, ProtRef, User,
        PROT_SYS_ADJUST, PROT_SYS_CLAWED, PROT_SYS_FORFEITED, PROT_SYS_ISSUED,
    };
    use revolt_models::v0::Sku;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256, Sha384};
    use x509_cert::{
        ext::{pkix::BasicConstraints, Extension},
        name::Name,
        serial_number::SerialNumber,
        spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
        time::{Time, Validity},
        Certificate, TbsCertificate, Version,
    };

    use super::*;
    use crate::engine::prot::{forfeit_wallet_on_deletion, prot_me};
    use crate::engine::unlink_account_payments;
    use crate::settings::PlayStoreConfig;
    use crate::store::{
        sha256_hex, AppleHistoryPage, MockAppleStore, MockPlayStore, PlayLineItem,
        PlayOfferDetails, PlayStateContext, PlayVoided, PlayVoidedPage, PubSubMessage,
        PLAY_CONSUMPTION_STATE_YET_TO_BE_CONSUMED,
    };

    use revolt_models::v0::ProtStoreVerifyReason as Reason;
    use revolt_models::v0::ProtStoreVerifyStatus as Status;

    /// 2027-01-15T08:00:00Z, inside the test chain's validity
    const NOW: i64 = 1_800_000_000_000;
    const MINUTE: i64 = 60_000;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;

    const BUNDLE: &str = "gg.sloga.app";
    const APP_APPLE_ID: u64 = 6_809_989_506;
    const PACKAGE: &str = "gg.sloga.app";
    const P5: &str = "gg.sloga.prot.p5";
    const P10: &str = "gg.sloga.prot.p10";
    const P25: &str = "gg.sloga.prot.p25";
    const P100: &str = "gg.sloga.prot.p100";
    const TX_BASE: u64 = 2_000_000_000_000_000;

    const A: &str = "01HZS6L2C00000000000USERA1";
    const B: &str = "01HZS6L2C00000000000USERB1";
    const C: &str = "01HZS6L2C00000000000USERC1";
    const BOT: &str = "01HZS6L2C00000000000BOTUS1";
    const ADMIN: &str = "01HZS6L2C0000000000ADMIN01";

    // --- the test chain (keys derived from labels; nothing committed) -------

    const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    const OID_P256: &str = "1.2.840.10045.3.1.7";
    const OID_P384: &str = "1.3.132.0.34";
    const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
    const OID_RECEIPT_SIGNER: &str = "1.2.840.113635.100.6.11.1";
    const OID_WWDR: &str = "1.2.840.113635.100.6.2.1";
    const ROOT_DN: &str = "CN=Sloga Engine Test Root,O=Sloga Test";
    const INTERMEDIATE_DN: &str = "CN=Sloga Engine Test WWDR,O=Sloga Test";
    const LEAF_DN: &str = "CN=Sloga Engine Test Receipt Signer,O=Sloga Test";

    fn p256_key(label: &str) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&Sha256::digest(label.as_bytes()))
            .expect("the label hashes to a P-256 scalar")
    }

    fn p384_key(label: &str) -> p384::ecdsa::SigningKey {
        p384::ecdsa::SigningKey::from_slice(&Sha384::digest(label.as_bytes()))
            .expect("the label hashes to a P-384 scalar")
    }

    fn ec_spki(curve: &str, point: &[u8]) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap(OID_EC_PUBLIC_KEY),
                parameters: Some(
                    Any::encode_from(&ObjectIdentifier::new_unwrap(curve)).expect("OID encodes"),
                ),
            },
            subject_public_key: BitString::from_bytes(point).expect("point"),
        }
    }

    fn january_1(year: u16) -> Time {
        let at = DateTime::new(year, 1, 1, 0, 0, 0).expect("a calendar date");
        Time::UtcTime(UtcTime::from_unix_duration(at.unix_duration()).expect("UTCTime range"))
    }

    /// One certificate, signed by a P-384 key with ecdsa-with-SHA384
    fn certificate(
        subject: &str,
        issuer: &str,
        spki: SubjectPublicKeyInfoOwned,
        signer: &p384::ecdsa::SigningKey,
        ca: bool,
        marker: Option<&str>,
        serial: u8,
    ) -> Vec<u8> {
        let mut extensions = Vec::new();
        if ca {
            extensions.push(Extension {
                extn_id: BasicConstraints::OID,
                critical: true,
                extn_value: OctetString::new(
                    BasicConstraints {
                        ca: true,
                        path_len_constraint: None,
                    }
                    .to_der()
                    .expect("basicConstraints encodes"),
                )
                .expect("octet string"),
            });
        }
        if let Some(oid) = marker {
            extensions.push(Extension {
                extn_id: ObjectIdentifier::new_unwrap(oid),
                critical: false,
                extn_value: OctetString::new(vec![0x05, 0x00]).expect("octet string"),
            });
        }
        let algorithm = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap(OID_ECDSA_SHA384),
            parameters: None,
        };
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[serial]).expect("serial"),
            signature: algorithm.clone(),
            issuer: Name::from_str(issuer).expect("issuer DN"),
            validity: Validity {
                not_before: january_1(2020),
                not_after: january_1(2049),
            },
            subject: Name::from_str(subject).expect("subject DN"),
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: (!extensions.is_empty()).then_some(extensions),
        };
        let signature: p384::ecdsa::Signature = signer
            .sign_prehash(&Sha384::digest(tbs.to_der().expect("TBS encodes")))
            .expect("P-384 signs");
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: algorithm,
            signature: BitString::from_bytes(signature.to_der().as_bytes()).expect("signature"),
        }
        .to_der()
        .expect("certificate encodes")
    }

    /// `[leaf, intermediate, root]`, as Apple's x5c carries them
    fn chain() -> &'static [Vec<u8>; 3] {
        static CHAIN: OnceLock<[Vec<u8>; 3]> = OnceLock::new();
        CHAIN.get_or_init(|| {
            let root_key = p384_key("s6-engine-root");
            let intermediate_key = p384_key("s6-engine-intermediate");
            let leaf_key = p256_key("s6-engine-leaf");
            let point384 = |key: &p384::ecdsa::SigningKey| {
                key.verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec()
            };
            let leaf_point = leaf_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();

            let root = certificate(
                ROOT_DN,
                ROOT_DN,
                ec_spki(OID_P384, &point384(&root_key)),
                &root_key,
                true,
                None,
                1,
            );
            let intermediate = certificate(
                INTERMEDIATE_DN,
                ROOT_DN,
                ec_spki(OID_P384, &point384(&intermediate_key)),
                &root_key,
                true,
                Some(OID_WWDR),
                2,
            );
            let leaf = certificate(
                LEAF_DN,
                INTERMEDIATE_DN,
                ec_spki(OID_P256, &leaf_point),
                &intermediate_key,
                false,
                Some(OID_RECEIPT_SIGNER),
                3,
            );
            [leaf, intermediate, root]
        })
    }

    fn root_sha256() -> [u8; 32] {
        let mut out = [0_u8; 32];
        out.copy_from_slice(&Sha256::digest(&chain()[2]));
        out
    }

    /// A compact JWS over `payload`, ES256 with the test leaf
    fn jws(payload: &Value) -> String {
        let x5c: Vec<String> = chain().iter().map(|der| STANDARD.encode(der)).collect();
        let header = json!({ "alg": "ES256", "x5c": x5c }).to_string();
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload.to_string())
        );
        let signature: p256::ecdsa::Signature = p256_key("s6-engine-leaf").sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    /// A StoreKit 2 transaction (`JWSTransactionDecodedPayload`)
    #[derive(Clone)]
    struct Tx {
        id: u64,
        product: &'static str,
        token: Option<String>,
        signed: i64,
        environment: &'static str,
        kind: &'static str,
        quantity: u32,
        bundle: &'static str,
        revoked: Option<i64>,
    }

    fn tx(id: u64, token: Option<&str>) -> Tx {
        Tx {
            id,
            product: P25,
            token: token.map(str::to_string),
            signed: NOW,
            environment: "Production",
            kind: "Consumable",
            quantity: 1,
            bundle: BUNDLE,
            revoked: None,
        }
    }

    impl Tx {
        fn transaction_id(&self) -> String {
            (TX_BASE + self.id).to_string()
        }

        fn purchase_id(&self) -> String {
            let env = if self.environment == "Sandbox" {
                "sandbox"
            } else {
                "prod"
            };
            format!("apple:{env}:{}", self.transaction_id())
        }

        fn signed_at(mut self, at: i64) -> Self {
            self.signed = at;
            self
        }

        fn revoked_at(mut self, at: i64) -> Self {
            self.revoked = Some(at);
            self
        }

        fn jws(&self) -> String {
            jws(&json!({
                "transactionId": self.transaction_id(),
                "originalTransactionId": self.transaction_id(),
                "bundleId": self.bundle,
                "productId": self.product,
                "type": self.kind,
                "quantity": self.quantity,
                "purchaseDate": self.signed - MINUTE,
                "signedDate": self.signed,
                "environment": self.environment,
                "appAccountToken": self.token,
                "storefront": "USA",
                "inAppOwnershipType": "PURCHASED",
                "revocationDate": self.revoked,
                "revocationReason": self.revoked.map(|_| 1),
            }))
        }
    }

    /// An App Store Server Notification V2 signed at `at`
    fn notification_jws(kind: &str, transaction: &str, at: i64) -> String {
        jws(&json!({
            "notificationType": kind,
            "notificationUUID": format!("{kind}-{at}"),
            "data": {
                "appAppleId": APP_APPLE_ID,
                "bundleId": BUNDLE,
                "environment": "Production",
                "signedTransactionInfo": transaction,
            },
            "signedDate": at,
        }))
    }

    fn play_found(product: &str, token: Option<&str>, state: &str) -> PlayPurchase {
        PlayPurchase {
            product_line_item: vec![PlayLineItem {
                product_id: product.to_string(),
                product_offer_details: PlayOfferDetails {
                    quantity: Some(1),
                    refundable_quantity: Some(1),
                    consumption_state: Some(PLAY_CONSUMPTION_STATE_YET_TO_BE_CONSUMED.to_string()),
                },
            }],
            purchase_state_context: PlayStateContext {
                purchase_state: state.to_string(),
            },
            test_purchase_context: None,
            order_id: Some("GPA.3300-0000-0000-00000".to_string()),
            obfuscated_external_account_id: token.map(str::to_string),
            region_code: Some("US".to_string()),
            purchase_completion_time: None,
            acknowledgement_state: None,
        }
    }

    fn rtdn(body: Value) -> Vec<u8> {
        body.to_string().into_bytes()
    }

    fn rtdn_purchased(token: &str) -> Vec<u8> {
        rtdn(json!({
            "version": "1.0",
            "packageName": PACKAGE,
            "eventTimeMillis": NOW.to_string(),
            "oneTimeProductNotification": {
                "version": "1.0",
                "notificationType": 1,
                "purchaseToken": token,
                "sku": P25,
            },
        }))
    }

    fn rtdn_voided(token: &str, at: i64) -> Vec<u8> {
        rtdn(json!({
            "version": "1.0",
            "packageName": PACKAGE,
            "eventTimeMillis": at.to_string(),
            "voidedPurchaseNotification": {
                "purchaseToken": token,
                "orderId": "GPA.3300-0000-0000-00000",
                "productType": 2,
                "refundType": 1,
            },
        }))
    }

    // --- database and settings ----------------------------------------------

    // Its own range, so no database name here repeats one the other payments
    // tests pick in the same process
    static NEXT_DB: AtomicU64 = AtomicU64::new(970_000);

    struct TestDb {
        db: Database,
        guard: Mutex<Option<TestDatabaseGuard>>,
    }

    impl Deref for TestDb {
        type Target = Database;

        fn deref(&self) -> &Database {
            &self.db
        }
    }

    /// Mongo: named `revolt_test_<digits>`, swept by
    /// `scripts/drop-test-databases.sh` if a test panics; a fresh database
    /// runs init (the payments, Prot and Prot store indexes)
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
            guard: Mutex::new(Some(guard)),
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

    fn user(id: &str) -> User {
        User {
            id: id.to_string(),
            username: id.to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        }
    }

    #[allow(clippy::disallowed_methods)]
    async fn insert_account(db: &Database, user: User) {
        db.insert_user(&user).await.unwrap();
    }

    fn payments_settings() -> PaymentsSettings {
        PaymentsSettings::from_parts(
            &FeaturePayments {
                enabled: true,
                ..Default::default()
            },
            &ApiStripe::default(),
        )
        .expect("the payments defaults validate")
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

    /// The shipped products with both stores open, and store credentials whose
    /// App Store pin is the test root
    fn store_settings() -> ProtStoreSettings {
        let mut st = ProtStoreSettings::from_parts(
            &FeaturePayments {
                prot_store_apple_open: true,
                prot_store_play_open: true,
                ..Default::default()
            },
            &ApiAppStore::default(),
            &ApiGooglePlay::default(),
        )
        .expect("the store defaults validate");
        st.apple = Some(AppleStoreConfig {
            issuer_id: "ISSUER".to_string(),
            key_id: "KEYID".to_string(),
            private_key: String::new(),
            bundle_id: BUNDLE.to_string(),
            app_apple_id: APP_APPLE_ID,
            environment: v0::ProtStoreEnvironment::Production,
            root_g3_sha256: root_sha256(),
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
        db: TestDb,
        s: PaymentsSettings,
        ps: ProtSalesSettings,
        st: ProtStoreSettings,
        apple: MockAppleStore,
        play: MockPlayStore,
    }

    async fn harness() -> Harness {
        let db = test_db().await;
        for id in [A, B, C, ADMIN] {
            insert_account(&db, user(id)).await;
        }
        Harness {
            db,
            s: payments_settings(),
            ps: prot_settings(),
            st: store_settings(),
            apple: MockAppleStore::new(),
            play: MockPlayStore::new(),
        }
    }

    async fn done(h: Harness) {
        drop_db(&h.db).await;
    }

    fn intent_data(store: v0::ProtStore, product: &str) -> v0::DataProtStoreIntent {
        v0::DataProtStoreIntent {
            store,
            product_id: product.to_string(),
        }
    }

    async fn intent_with(
        h: &Harness,
        ps: &ProtSalesSettings,
        st: &ProtStoreSettings,
        user: &str,
        store: v0::ProtStore,
        product: &str,
    ) -> Result<v0::ProtStoreIntentResponse> {
        create_store_intent(
            &h.db,
            &h.s,
            ps,
            st,
            &h.play,
            &h.apple,
            user,
            &intent_data(store, product),
            None,
            NOW,
        )
        .await
    }

    async fn new_intent(
        h: &Harness,
        user: &str,
        store: v0::ProtStore,
        product: &str,
    ) -> v0::ProtStoreIntentResponse {
        intent_with(h, &h.ps, &h.st, user, store, product)
            .await
            .expect("the intent is issued")
    }

    async fn verify_apple(
        h: &Harness,
        st: &ProtStoreSettings,
        user: &str,
        signed: &str,
        now: i64,
    ) -> Result<v0::ProtStoreVerifyResponse> {
        let data = v0::DataProtStoreVerify {
            store: v0::ProtStore::Apple,
            signed_transaction: Some(signed.to_string()),
            product_id: None,
            purchase_token: None,
        };
        verify_store_purchase(&h.db, &h.ps, st, &h.apple, &h.play, user, &data, now).await
    }

    async fn verify_play(
        h: &Harness,
        st: &ProtStoreSettings,
        user: &str,
        product: &str,
        token: &str,
        now: i64,
    ) -> Result<v0::ProtStoreVerifyResponse> {
        let data = v0::DataProtStoreVerify {
            store: v0::ProtStore::Play,
            signed_transaction: None,
            product_id: Some(product.to_string()),
            purchase_token: Some(token.to_string()),
        };
        verify_store_purchase(&h.db, &h.ps, st, &h.apple, &h.play, user, &data, now).await
    }

    async fn notify(
        h: &Harness,
        kind: &str,
        transaction: &str,
        at: i64,
    ) -> AppleNotificationOutcome {
        let body = json!({ "signedPayload": notification_jws(kind, transaction, at) }).to_string();
        handle_apple_notification(&h.db, &h.ps, &h.st, &h.apple, body.as_bytes(), at).await
    }

    async fn reconcile(h: &Harness, st: &ProtStoreSettings, at: i64) -> StoreReconcileReport {
        reconcile_store(&h.db, &h.ps, st, &h.apple, &h.play, at).await
    }

    fn answer(response: &v0::ProtStoreVerifyResponse) -> (Status, Option<Reason>) {
        (response.status, response.reason)
    }

    fn error_of<T: std::fmt::Debug>(result: Result<T>) -> ErrorType {
        result.expect_err("expected an error").error_type
    }

    async fn row(db: &Database, id: &str) -> Option<ProtStorePurchase> {
        db.fetch_prot_store_purchase(id).await.unwrap()
    }

    async fn stored(db: &Database, id: &str) -> ProtStorePurchase {
        row(db, id).await.expect("the purchase row exists")
    }

    async fn balance(db: &Database, user: &str) -> i64 {
        wallet_balance(db, user).await.unwrap()
    }

    async fn entry(db: &Database, key: &str) -> Option<ProtLedgerEntry> {
        db.fetch_prot_entry_by_key(key).await.unwrap()
    }

    fn consumes(play: &MockPlayStore) -> Vec<String> {
        play.calls()
            .into_iter()
            .filter(|call| call.starts_with("consume "))
            .collect()
    }

    fn lookups(apple: &MockAppleStore, t: &Tx) -> usize {
        let call = format!("transaction_info Production {}", t.transaction_id());
        apple.calls().iter().filter(|line| **line == call).count()
    }

    /// A wallet adjustment by staff (credit `amount > 0`, else debit)
    async fn adjust(db: &Database, user: &str, nonce: &str, amount: i64) {
        let wallet = prot_user_account(user);
        let (debit, credit) = if amount > 0 {
            (PROT_SYS_ADJUST.to_string(), wallet)
        } else {
            (wallet, PROT_SYS_ADJUST.to_string())
        };
        db.apply_prot_posting(&ProtPosting {
            key: prot_key_admin(ADMIN, nonce),
            kind: ProtEntryKind::AdminAdjust,
            debit,
            credit,
            amount: ProtAmount::Exact(amount.abs()),
            debit_floor: 0,
            actor: ADMIN.to_string(),
            reference: ProtRef::default(),
            reason: Some("test".to_string()),
            created_at: NOW,
        })
        .await
        .unwrap();
    }

    /// A row stored as it is, past the move (a broken row the engine must
    /// refuse to trust)
    async fn put_row(db: &Database, row: ProtStorePurchase) {
        match db {
            Database::Reference(reference) => {
                reference
                    .prot_store_purchases
                    .lock()
                    .await
                    .insert(row.id.clone(), row);
            }
            Database::MongoDb(mongo) => {
                mongo
                    .col::<ProtStorePurchase>("prot_store_purchases")
                    .insert_one(row)
                    .await
                    .expect("raw row");
            }
        }
    }

    /// Conservation (S5b's check): every wallet equals its rows and is never
    /// below 0, and the wallets plus the system sides sum to 0
    async fn assert_conserved(db: &Database, users: &[&str]) {
        let sys = [
            PROT_SYS_ISSUED,
            PROT_SYS_ADJUST,
            PROT_SYS_CLAWED,
            PROT_SYS_FORFEITED,
        ];
        let accounts: Vec<String> = users.iter().map(|user| prot_user_account(user)).collect();
        let mut rows: HashMap<String, ProtLedgerEntry> = HashMap::new();
        for account in accounts.iter().map(String::as_str).chain(sys) {
            for entry in db
                .fetch_prot_entries_by_account(account, None, 100)
                .await
                .unwrap()
            {
                rows.insert(entry.id.clone(), entry);
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
    }

    async fn assign(h: &Harness, id: String, target: &str) -> Result<v0::ProtStoreAdminPurchase> {
        admin_assign_store_purchase(
            &h.db, &h.ps, &h.st, &h.apple, &h.play, ADMIN, &id, target, NOW,
        )
        .await
    }

    async fn assign_with(
        h: &Harness,
        st: &ProtStoreSettings,
        id: String,
        target: &str,
    ) -> Result<v0::ProtStoreAdminPurchase> {
        admin_assign_store_purchase(&h.db, &h.ps, st, &h.apple, &h.play, ADMIN, &id, target, NOW)
            .await
    }

    async fn notify_raw(h: &Harness, body: Vec<u8>) -> AppleNotificationOutcome {
        handle_apple_notification(&h.db, &h.ps, &h.st, &h.apple, &body, NOW + HOUR).await
    }

    async fn gate(
        h: &Harness,
        s: PaymentsSettings,
        ps: ProtSalesSettings,
        st: ProtStoreSettings,
        user: &str,
        data: v0::DataProtStoreIntent,
        country: Option<&str>,
    ) -> Result<v0::ProtStoreIntentResponse> {
        create_store_intent(
            &h.db, &s, &ps, &st, &h.play, &h.apple, user, &data, country, NOW,
        )
        .await
    }

    // --- verify: binding, environment, freshness -----------------------------

    /// 9.4 step 4 (control 28: skip the account-token binding): A's purchase
    /// verified by B writes nothing and credits nobody, before and after A is
    /// credited; on Play too
    #[tokio::test]
    async fn wrong_account_credits_nothing() {
        let h = harness().await;
        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        let t = tx(1, Some(&intent.token));

        let by_b = verify_apple(&h, &h.st, B, &t.jws(), NOW).await.unwrap();
        assert_eq!(
            answer(&by_b),
            (Status::Rejected, Some(Reason::WrongAccount))
        );
        assert_eq!(by_b.purchase_id, None);
        assert!(row(&h.db, &t.purchase_id()).await.is_none());
        assert!(entry(&h.db, &prot_store_key_purchase(&t.purchase_id()))
            .await
            .is_none());
        assert_eq!((balance(&h.db, A).await, balance(&h.db, B).await), (0, 0));

        let by_a = verify_apple(&h, &h.st, A, &t.jws(), NOW).await.unwrap();
        assert_eq!(answer(&by_a), (Status::Credited, None));
        assert_eq!(by_a.balance, Some(2600));

        let again = verify_apple(&h, &h.st, B, &t.jws(), NOW).await.unwrap();
        assert_eq!(
            answer(&again),
            (Status::Rejected, Some(Reason::WrongAccount))
        );
        assert_eq!(
            (balance(&h.db, A).await, balance(&h.db, B).await),
            (2600, 0)
        );

        let play_intent = new_intent(&h, A, v0::ProtStore::Play, P25).await;
        h.play.set_purchase(
            "tok-wrong-1",
            Ok(play_found(
                P25,
                Some(&play_intent.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        let by_b = verify_play(&h, &h.st, B, P25, "tok-wrong-1", NOW)
            .await
            .unwrap();
        assert_eq!(
            answer(&by_b),
            (Status::Rejected, Some(Reason::WrongAccount))
        );
        assert!(row(&h.db, &play_purchase_id("tok-wrong-1")).await.is_none());
        assert!(consumes(&h.play).is_empty());

        assert_conserved(&h.db, &[A, B]).await;
        done(h).await;
    }

    /// E4 (control 28: accept Sandbox for any user): a sandbox purchase of an
    /// account not on the test list is recorded Rejected(test) and credits
    /// nothing; a Play test purchase likewise, and is never consumed
    #[tokio::test]
    async fn sandbox_purchase_refused_for_a_non_tester() {
        let h = harness().await;
        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        let t = Tx {
            environment: "Sandbox",
            ..tx(2, Some(&intent.token))
        };

        let response = verify_apple(&h, &h.st, A, &t.jws(), NOW).await.unwrap();
        assert_eq!(answer(&response), (Status::Rejected, Some(Reason::Test)));
        assert_eq!(response.purchase_id, Some(t.purchase_id()));
        let rejected = stored(&h.db, &t.purchase_id()).await;
        assert_eq!(rejected.state, v0::ProtStoreState::Rejected);
        assert_eq!(
            rejected.reject_reason,
            Some(v0::ProtStoreRejectReason::TestPurchase)
        );
        assert_eq!(rejected.environment, v0::ProtStoreEnvironment::Sandbox);
        assert_eq!(balance(&h.db, A).await, 0);
        // The intent is spent: it bound this purchase
        let spent =
            h.db.fetch_prot_store_intent(&intent.intent_id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(spent.state, v0::ProtStoreIntentState::Used);

        let play_intent = new_intent(&h, A, v0::ProtStore::Play, P25).await;
        let mut test_purchase =
            play_found(P25, Some(&play_intent.token), PLAY_PURCHASE_STATE_PURCHASED);
        test_purchase.test_purchase_context = Some(json!({ "fopType": "TEST" }));
        h.play.set_purchase("tok-test-1", Ok(test_purchase));
        let response = verify_play(&h, &h.st, A, P25, "tok-test-1", NOW)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Rejected, Some(Reason::Test)));
        assert_eq!(balance(&h.db, A).await, 0);
        assert!(consumes(&h.play).is_empty());
        done(h).await;
    }

    /// E4: a listed tester's sandbox purchases are credited up to
    /// `test_max_prot` (counting what sandbox already credited), then refused
    #[tokio::test]
    async fn test_purchases_are_credited_to_a_tester_within_the_cap() {
        let h = harness().await;
        let mut st = h.st.clone();
        st.test_user_ids = vec![A.to_string(), B.to_string()];
        st.test_max_prot = 5200;

        let sandbox = |id: u64, token: &str| Tx {
            environment: "Sandbox",
            ..tx(id, Some(token))
        };
        for (id, expected) in [
            (3, (Status::Credited, None)),
            (4, (Status::Credited, None)),
            (5, (Status::Rejected, Some(Reason::Test))),
        ] {
            let intent = intent_with(&h, &h.ps, &st, A, v0::ProtStore::Apple, P25)
                .await
                .unwrap();
            let response = verify_apple(&h, &st, A, &sandbox(id, &intent.token).jws(), NOW)
                .await
                .unwrap();
            assert_eq!(answer(&response), expected, "purchase {id}");
        }
        assert_eq!(balance(&h.db, A).await, 5200);

        // Over the cap a production purchase is credited as usual
        let intent = intent_with(&h, &h.ps, &st, A, v0::ProtStore::Apple, P25)
            .await
            .unwrap();
        let response = verify_apple(&h, &st, A, &tx(6, Some(&intent.token)).jws(), NOW)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Credited, None));
        assert_eq!(balance(&h.db, A).await, 7800);

        // The cap is per account
        let intent = intent_with(&h, &h.ps, &st, B, v0::ProtStore::Apple, P25)
            .await
            .unwrap();
        let response = verify_apple(&h, &st, B, &sandbox(7, &intent.token).jws(), NOW)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Credited, None));
        assert_conserved(&h.db, &[A, B]).await;
        done(h).await;
    }

    /// Control 28 (re-derive Prot from config on retry): the Prot is stamped
    /// on the row at first sight; a re-priced product never changes what a
    /// Held row is credited, nor a re-verify of a credited one
    #[tokio::test]
    async fn config_edit_between_retries_keeps_the_stamped_amount() {
        let h = harness().await;
        let mut paused = h.st.clone();
        paused.credit_paused = true;
        let mut repriced = h.st.clone();
        for product in repriced
            .products
            .iter_mut()
            .filter(|product| product.product_id == P25)
        {
            product.prot = 3000;
        }

        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        let t = tx(8, Some(&intent.token));
        let held = verify_apple(&h, &paused, A, &t.jws(), NOW).await.unwrap();
        assert_eq!(answer(&held), (Status::Pending, None));
        assert_eq!(held.purchase_id, Some(t.purchase_id()));
        let row_held = stored(&h.db, &t.purchase_id()).await;
        assert_eq!(
            (row_held.state, row_held.prot),
            (v0::ProtStoreState::Held, 2600)
        );
        assert_eq!(balance(&h.db, A).await, 0);

        let credited = verify_apple(&h, &repriced, A, &t.jws(), NOW + MINUTE)
            .await
            .unwrap();
        assert_eq!(answer(&credited), (Status::Credited, None));
        assert_eq!(credited.balance, Some(2600));
        let purchase = entry(&h.db, &prot_store_key_purchase(&t.purchase_id()))
            .await
            .unwrap();
        assert_eq!(purchase.amount, 2600);
        assert_eq!(credited.ledger_id, Some(purchase.id.clone()));

        let again = verify_apple(&h, &repriced, A, &t.jws(), NOW + 2 * MINUTE)
            .await
            .unwrap();
        assert_eq!(answer(&again), (Status::AlreadyCredited, None));
        assert_eq!(again.balance, Some(2600));
        assert_eq!(again.ledger_id, Some(purchase.id));

        // A Held row the reconcile credits keeps its stamp too
        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        let t2 = tx(9, Some(&intent.token));
        verify_apple(&h, &paused, A, &t2.jws(), NOW).await.unwrap();
        h.apple
            .set_transaction_info(&t2.transaction_id(), Ok(t2.jws()));
        let report = reconcile(&h, &repriced, NOW + 3 * MINUTE).await;
        assert_eq!(report.held_credited, 1);
        assert_eq!(
            entry(&h.db, &prot_store_key_purchase(&t2.purchase_id()))
                .await
                .unwrap()
                .amount,
            2600
        );
        assert_eq!(balance(&h.db, A).await, 5200);
        assert_conserved(&h.db, &[A]).await;
        done(h).await;
    }

    /// 9.4 step 2 (control 28: skip the freshness lookup): a JWS signed an
    /// hour ago is read again from Apple, which shows it refunded: nothing is
    /// credited and the refund leaves a tombstone. Refund-then-charge: a
    /// fresh JWS of the same purchase, and its ONE_TIME_CHARGE, never credit
    #[tokio::test]
    async fn stale_jws_after_refund_is_refused() {
        let h = harness().await;
        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        let t = tx(10, Some(&intent.token)).signed_at(NOW - HOUR);
        let refunded_at = NOW - 30 * MINUTE;
        h.apple.set_transaction_info(
            &t.transaction_id(),
            Ok(t.clone().signed_at(NOW).revoked_at(refunded_at).jws()),
        );

        let response = verify_apple(&h, &h.st, A, &t.jws(), NOW).await.unwrap();
        assert_eq!(
            answer(&response),
            (Status::Rejected, Some(Reason::Refunded))
        );
        assert_eq!(lookups(&h.apple, &t), 1);
        let tombstone = stored(&h.db, &t.purchase_id()).await;
        assert_eq!(tombstone.state, v0::ProtStoreState::Revoked);
        assert_eq!(tombstone.refund_gen, 0);
        assert_eq!(tombstone.user_id.as_deref(), Some(A));
        assert_eq!(
            tombstone
                .refunds
                .iter()
                .map(|refund| (refund.gen, refund.revocation_date))
                .collect::<Vec<_>>(),
            vec![(0, refunded_at)]
        );
        assert!(entry(&h.db, &prot_store_key_purchase(&t.purchase_id()))
            .await
            .is_none());

        let fresh = t.clone().signed_at(NOW);
        let response = verify_apple(&h, &h.st, A, &fresh.jws(), NOW).await.unwrap();
        assert_eq!(
            answer(&response),
            (Status::Rejected, Some(Reason::Refunded))
        );
        assert_eq!(
            notify(&h, "ONE_TIME_CHARGE", &fresh.jws(), NOW).await,
            AppleNotificationOutcome::Handled
        );
        assert_eq!(
            stored(&h.db, &t.purchase_id()).await.state,
            v0::ProtStoreState::Revoked
        );
        assert_eq!(balance(&h.db, A).await, 0);
        assert!(entry(&h.db, &prot_store_key_purchase(&t.purchase_id()))
            .await
            .is_none());
        done(h).await;
    }

    /// R37: a JWS dated ahead is not fresh: Apple is asked (a failed lookup
    /// writes nothing and answers 500); a JWS within 5 minutes ahead is fresh
    #[tokio::test]
    async fn future_dated_jws_forces_the_lookup() {
        let h = harness().await;
        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        let t = tx(11, Some(&intent.token)).signed_at(NOW + DAY);

        h.apple.set_transaction_info(
            &t.transaction_id(),
            Err(StoreApiError::Transient("unavailable".to_string())),
        );
        let failed = verify_apple(&h, &h.st, A, &t.jws(), NOW).await;
        assert!(matches!(error_of(failed), ErrorType::InternalError));
        assert!(row(&h.db, &t.purchase_id()).await.is_none());

        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(t.clone().signed_at(NOW).jws()));
        let response = verify_apple(&h, &h.st, A, &t.jws(), NOW).await.unwrap();
        assert_eq!(answer(&response), (Status::Credited, None));
        assert_eq!(lookups(&h.apple, &t), 2);

        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        let near = tx(12, Some(&intent.token)).signed_at(NOW + 4 * MINUTE);
        let response = verify_apple(&h, &h.st, A, &near.jws(), NOW).await.unwrap();
        assert_eq!(answer(&response), (Status::Credited, None));
        assert_eq!(lookups(&h.apple, &near), 0);
        done(h).await;
    }

    /// R38: a correctly signed JWS of another kind (an AppTransaction, renewal
    /// info, a notification), another app's transaction and an Xcode one are
    /// refused with nothing written; a non-consumable is recorded as a bad
    /// payload and refused
    #[tokio::test]
    async fn wrong_kind_jws_is_refused() {
        let h = harness().await;
        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;

        let app_transaction = jws(&json!({
            "bundleId": BUNDLE,
            "appAppleId": APP_APPLE_ID,
            "environment": "Production",
            "applicationVersion": "70",
            "originalApplicationVersion": "1",
            "originalPurchaseDate": NOW - DAY,
            "receiptType": "Production",
            "receiptCreationDate": NOW,
            "requestDate": NOW,
            "signedDate": NOW,
        }));
        let renewal_info = jws(&json!({
            "originalTransactionId": (TX_BASE + 13).to_string(),
            "autoRenewProductId": P25,
            "productId": P25,
            "autoRenewStatus": 1,
            "environment": "Production",
            "recentSubscriptionStartDate": NOW - DAY,
            "renewalDate": NOW + DAY,
            "signedDate": NOW,
        }));
        let notification = notification_jws("TEST", "", NOW);
        let other_app = Tx {
            bundle: "com.example.other",
            ..tx(14, Some(&intent.token))
        };
        let xcode = Tx {
            environment: "Xcode",
            ..tx(15, Some(&intent.token))
        };
        for signed in [
            app_transaction,
            renewal_info,
            notification,
            other_app.jws(),
            xcode.jws(),
            "a.b.c".to_string(),
        ] {
            let refused = verify_apple(&h, &h.st, A, &signed, NOW).await;
            assert!(matches!(
                error_of(refused),
                ErrorType::ProtStoreVerifyFailed
            ));
        }
        assert!(row(&h.db, &other_app.purchase_id()).await.is_none());
        assert!(row(&h.db, &xcode.purchase_id()).await.is_none());

        let non_consumable = Tx {
            kind: "Non-Consumable",
            ..tx(16, Some(&intent.token))
        };
        let refused = verify_apple(&h, &h.st, A, &non_consumable.jws(), NOW).await;
        assert!(matches!(
            error_of(refused),
            ErrorType::ProtStoreVerifyFailed
        ));
        let recorded = stored(&h.db, &non_consumable.purchase_id()).await;
        assert_eq!(
            recorded.reject_reason,
            Some(v0::ProtStoreRejectReason::BadPayload)
        );
        assert_eq!(balance(&h.db, A).await, 0);
        done(h).await;
    }

    /// E11: quantity credits every unit; quantity 0 is a bad payload
    #[tokio::test]
    async fn quantity_credits_each_unit() {
        let h = harness().await;
        let intent = new_intent(&h, A, v0::ProtStore::Apple, P5).await;
        let three = Tx {
            product: P5,
            quantity: 3,
            ..tx(17, Some(&intent.token))
        };
        let response = verify_apple(&h, &h.st, A, &three.jws(), NOW).await.unwrap();
        assert_eq!(answer(&response), (Status::Credited, None));
        assert_eq!(response.balance, Some(1500));
        let credited = stored(&h.db, &three.purchase_id()).await;
        assert_eq!((credited.quantity, credited.prot), (3, 1500));

        let intent = new_intent(&h, A, v0::ProtStore::Apple, P5).await;
        let none = Tx {
            product: P5,
            quantity: 0,
            ..tx(18, Some(&intent.token))
        };
        let refused = verify_apple(&h, &h.st, A, &none.jws(), NOW).await;
        assert!(matches!(
            error_of(refused),
            ErrorType::ProtStoreVerifyFailed
        ));
        let recorded = stored(&h.db, &none.purchase_id()).await;
        assert_eq!(
            (recorded.reject_reason, recorded.prot),
            (Some(v0::ProtStoreRejectReason::BadPayload), 0)
        );
        assert_eq!(balance(&h.db, A).await, 1500);
        done(h).await;
    }

    /// Unbound purchases (no token, or a token no intent has) are recorded for
    /// support; an E10 assign looks the purchase up first, refuses self,
    /// unknown targets, revoked purchases and a second assign
    #[tokio::test]
    async fn unbound_purchase_is_kept_for_support_and_assigned() {
        let h = harness().await;
        let unbound = tx(19, None);
        let response = verify_apple(&h, &h.st, A, &unbound.jws(), NOW)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Rejected, Some(Reason::Unbound)));
        let recorded = stored(&h.db, &unbound.purchase_id()).await;
        assert_eq!(recorded.user_id, None);
        assert_eq!(
            recorded.needs_action.as_deref(),
            Some(PROT_STORE_NEEDS_UNBOUND)
        );

        let stray = tx(20, Some("00000000-0000-4000-8000-000000000000"));
        let response = verify_apple(&h, &h.st, A, &stray.jws(), NOW).await.unwrap();
        assert_eq!(answer(&response), (Status::Rejected, Some(Reason::Unbound)));
        assert_eq!(admin_store_needs_action(&h.db).await.unwrap().len(), 2);

        h.apple
            .set_transaction_info(&unbound.transaction_id(), Ok(unbound.jws()));
        assert!(matches!(
            error_of(assign(&h, unbound.purchase_id(), ADMIN).await),
            ErrorType::InvalidOperation
        ));
        assert!(matches!(
            error_of(assign(&h, unbound.purchase_id(), "01HZS6L2C0000000000NOSUCH1").await),
            ErrorType::NotFound
        ));

        let view = assign(&h, unbound.purchase_id(), B).await.unwrap();
        assert_eq!(view.purchase.state, v0::ProtStoreState::Credited);
        assert_eq!(view.purchase.user_id.as_deref(), Some(B));
        assert_eq!(view.purchase.assigned_by.as_deref(), Some(ADMIN));
        assert_eq!(view.purchase.needs_action, None);
        assert_eq!(
            view.ledger.iter().map(|row| row.amount).collect::<Vec<_>>(),
            vec![2600]
        );
        assert_eq!(view.unspent, Some(2600));
        assert!(matches!(
            error_of(assign(&h, unbound.purchase_id(), C).await),
            ErrorType::InvalidOperation
        ));
        assert_eq!(balance(&h.db, C).await, 0);

        h.apple.set_transaction_info(
            &stray.transaction_id(),
            Ok(stray.clone().revoked_at(NOW - MINUTE).jws()),
        );
        assert!(matches!(
            error_of(assign(&h, stray.purchase_id(), C).await),
            ErrorType::InvalidOperation
        ));
        assert_eq!(
            stored(&h.db, &stray.purchase_id()).await.state,
            v0::ProtStoreState::Revoked
        );
        assert!(admin_store_needs_action(&h.db).await.unwrap().is_empty());
        assert_eq!(balance(&h.db, C).await, 0);
        assert_conserved(&h.db, &[A, B, C]).await;
        done(h).await;
    }

    /// R48: a Credited row without its `purchase:` ledger row is never
    /// answered already_credited
    #[tokio::test]
    async fn credited_row_without_ledger_is_an_error() {
        let h = harness().await;
        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        let t = tx(21, Some(&intent.token));
        let checked = AppleChecked {
            tx: serde_json::from_slice(
                &verify_apple_jws(&t.jws(), &root_sha256()).unwrap().payload,
            )
            .unwrap(),
            environment: v0::ProtStoreEnvironment::Production,
            purchase_id: t.purchase_id(),
            revocation: None,
        };
        let mut broken = apple_purchase(&h.st, &h.ps, &checked, NOW).seed;
        broken.state = v0::ProtStoreState::Credited;
        broken.user_id = Some(A.to_string());
        broken.credited_at = Some(NOW);
        put_row(&h.db, broken).await;

        let refused = verify_apple(&h, &h.st, A, &t.jws(), NOW).await;
        assert!(matches!(error_of(refused), ErrorType::InternalError));
        assert_eq!(balance(&h.db, A).await, 0);
        done(h).await;
    }

    // --- Play ------------------------------------------------------------------

    /// 9.4 step 9 (control 28: consume before the credit commits): a Held
    /// purchase and a purchase whose credit fails are never consumed; a
    /// credited one is consumed after its `purchase:` row exists
    #[tokio::test]
    async fn play_is_consumed_only_after_the_credit() {
        let h = harness().await;
        let mut paused = h.st.clone();
        paused.credit_paused = true;

        let held = new_intent(&h, A, v0::ProtStore::Play, P25).await;
        h.play.set_purchase(
            "tok-held",
            Ok(play_found(
                P25,
                Some(&held.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        let response = verify_play(&h, &paused, A, P25, "tok-held", NOW)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Pending, None));
        assert!(consumes(&h.play).is_empty());

        // A credited row the ledger does not back: refused, so not consumed
        let found = play_found(P25, Some("no-intent"), PLAY_PURCHASE_STATE_PURCHASED);
        h.play.set_purchase("tok-broken", Ok(found.clone()));
        let mut broken = play_purchase(&h.st, &h.ps, "tok-broken", &found, NOW)
            .unwrap()
            .seed;
        broken.state = v0::ProtStoreState::Credited;
        broken.user_id = Some(A.to_string());
        broken.credited_at = Some(NOW);
        broken.unconsumed = Some(true);
        put_row(&h.db, broken).await;
        let refused = verify_play(&h, &h.st, A, P25, "tok-broken", NOW).await;
        assert!(matches!(error_of(refused), ErrorType::InternalError));
        assert!(consumes(&h.play).is_empty());

        let intent = new_intent(&h, A, v0::ProtStore::Play, P25).await;
        h.play.set_purchase(
            "tok-ok",
            Ok(play_found(
                P25,
                Some(&intent.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        let response = verify_play(&h, &h.st, A, P25, "tok-ok", NOW).await.unwrap();
        assert_eq!(answer(&response), (Status::Credited, None));
        assert!(
            entry(&h.db, &prot_store_key_purchase(&play_purchase_id("tok-ok")))
                .await
                .is_some()
        );
        assert_eq!(
            consumes(&h.play),
            vec![format!("consume {P25} {}", sha256_hex("tok-ok"))]
        );
        let consumed = stored(&h.db, &play_purchase_id("tok-ok")).await;
        assert_eq!(consumed.unconsumed, None);
        assert!(consumed
            .play
            .as_ref()
            .is_some_and(|play| play.consumed_at.is_some()));
        done(h).await;
    }

    /// 9.4 step 2: PENDING writes nothing; Play's error mapping (R51 NotFound
    /// → verify failed; transient or refused → 500; unconfigured → 503); the
    /// product must match; the body must be Play's
    #[tokio::test]
    async fn play_pending_and_lookup_errors_write_nothing() {
        let h = harness().await;
        let intent = new_intent(&h, A, v0::ProtStore::Play, P25).await;
        h.play.set_purchase(
            "tok-pending",
            Ok(play_found(
                P25,
                Some(&intent.token),
                PLAY_PURCHASE_STATE_PENDING,
            )),
        );
        let response = verify_play(&h, &h.st, A, P25, "tok-pending", NOW)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Pending, None));
        assert_eq!(response.purchase_id, None);
        assert!(row(&h.db, &play_purchase_id("tok-pending")).await.is_none());

        let unknown = verify_play(&h, &h.st, A, P25, "tok-unknown", NOW).await;
        assert!(matches!(
            error_of(unknown),
            ErrorType::ProtStoreVerifyFailed
        ));
        h.play.set_purchase(
            "tok-flaky",
            Err(StoreApiError::Transient("timeout".to_string())),
        );
        let flaky = verify_play(&h, &h.st, A, P25, "tok-flaky", NOW).await;
        assert!(matches!(error_of(flaky), ErrorType::InternalError));
        h.play
            .set_purchase("tok-denied", Err(StoreApiError::Rejected { status: 403 }));
        let denied = verify_play(&h, &h.st, A, P25, "tok-denied", NOW).await;
        assert!(matches!(error_of(denied), ErrorType::InternalError));

        let other_product = verify_play(&h, &h.st, A, P5, "tok-pending", NOW).await;
        assert!(matches!(
            error_of(other_product),
            ErrorType::ProtStoreVerifyFailed
        ));
        let mut two_items = play_found(P25, Some(&intent.token), PLAY_PURCHASE_STATE_PURCHASED);
        two_items
            .product_line_item
            .push(two_items.product_line_item[0].clone());
        h.play.set_purchase("tok-two", Ok(two_items));
        let two = verify_play(&h, &h.st, A, P25, "tok-two", NOW).await;
        assert!(matches!(error_of(two), ErrorType::ProtStoreVerifyFailed));

        let mixed = v0::DataProtStoreVerify {
            store: v0::ProtStore::Play,
            signed_transaction: Some("a.b.c".to_string()),
            product_id: Some(P25.to_string()),
            purchase_token: Some("tok-pending".to_string()),
        };
        let shape =
            verify_store_purchase(&h.db, &h.ps, &h.st, &h.apple, &h.play, A, &mixed, NOW).await;
        assert!(matches!(
            error_of(shape),
            ErrorType::FailedValidation { .. }
        ));

        let unconfigured = MockPlayStore::new();
        unconfigured.unconfigured();
        let data = v0::DataProtStoreVerify {
            store: v0::ProtStore::Play,
            signed_transaction: None,
            product_id: Some(P25.to_string()),
            purchase_token: Some("tok-pending".to_string()),
        };
        let unavailable =
            verify_store_purchase(&h.db, &h.ps, &h.st, &h.apple, &unconfigured, A, &data, NOW)
                .await;
        assert!(matches!(
            error_of(unavailable),
            ErrorType::ProtStoreUnavailable
        ));
        assert_eq!(balance(&h.db, A).await, 0);
        assert!(consumes(&h.play).is_empty());
        done(h).await;
    }

    /// R46 + 16 step 2 + 7.4: a Play credit stays unconsumed (and held, at
    /// hold 0 too) until the server consumes it; crond retries, raises the
    /// work item a day later (claimed once), records a consume Play already
    /// did, and revokes a purchase Play cancelled before its consume
    #[tokio::test]
    async fn play_consume_retry_and_the_unconsumed_work_item() {
        let h = harness().await;
        let no_hold = ProtSalesSettings {
            contribute_hold_hours: 0,
            ..h.ps.clone()
        };
        let intent = new_intent(&h, A, v0::ProtStore::Play, P25).await;
        h.play.set_purchase(
            "tok-c1",
            Ok(play_found(
                P25,
                Some(&intent.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        h.play.fail_consume(
            "tok-c1",
            StoreApiError::Transient("unavailable".to_string()),
        );
        let id = play_purchase_id("tok-c1");

        let response = verify_play(&h, &h.st, A, P25, "tok-c1", NOW).await.unwrap();
        assert_eq!(answer(&response), (Status::Credited, None));
        assert_eq!(stored(&h.db, &id).await.unconsumed, Some(true));
        assert_eq!(prot_me(&h.db, &no_hold, A, NOW).await.unwrap().held, 2600);

        let report = reconcile(&h, &h.st, NOW + 2 * HOUR).await;
        assert_eq!((report.consumed, report.alerts), (0, 0));
        assert_eq!(stored(&h.db, &id).await.needs_action, None);

        let report = reconcile(&h, &h.st, NOW + 25 * HOUR).await;
        assert_eq!(report.alerts, 1);
        let overdue = stored(&h.db, &id).await;
        assert_eq!(
            overdue.needs_action.as_deref(),
            Some(PROT_STORE_NEEDS_UNCONSUMED)
        );
        assert!(overdue
            .alerted
            .iter()
            .any(|kind| kind == PROT_STORE_NEEDS_UNCONSUMED));
        assert_eq!(
            reconcile(&h, &h.st, NOW + 25 * HOUR + MINUTE).await.alerts,
            0
        );

        // Play consumed it already: the refused consume reads CONSUMED
        h.play
            .fail_consume("tok-c1", StoreApiError::Rejected { status: 400 });
        let mut consumed_at_play =
            play_found(P25, Some(&intent.token), PLAY_PURCHASE_STATE_PURCHASED);
        consumed_at_play.product_line_item[0]
            .product_offer_details
            .consumption_state = Some(PLAY_CONSUMPTION_STATE_CONSUMED.to_string());
        h.play.set_purchase("tok-c1", Ok(consumed_at_play));
        let report = reconcile(&h, &h.st, NOW + 26 * HOUR).await;
        assert_eq!(report.consumed, 1);
        let settled = stored(&h.db, &id).await;
        assert_eq!((settled.unconsumed, settled.needs_action), (None, None));
        assert_eq!(
            prot_me(&h.db, &no_hold, A, NOW + 26 * HOUR)
                .await
                .unwrap()
                .held,
            0
        );

        // Cancelled at Play before the consume: revoked and clawed back
        let intent = new_intent(&h, A, v0::ProtStore::Play, P25).await;
        h.play.set_purchase(
            "tok-c2",
            Ok(play_found(
                P25,
                Some(&intent.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        h.play.fail_consume(
            "tok-c2",
            StoreApiError::Transient("unavailable".to_string()),
        );
        verify_play(&h, &h.st, A, P25, "tok-c2", NOW + 26 * HOUR)
            .await
            .unwrap();
        assert_eq!(balance(&h.db, A).await, 5200);
        h.play
            .fail_consume("tok-c2", StoreApiError::Rejected { status: 400 });
        h.play.set_purchase(
            "tok-c2",
            Ok(play_found(
                P25,
                Some(&intent.token),
                PLAY_PURCHASE_STATE_CANCELLED,
            )),
        );
        let report = reconcile(&h, &h.st, NOW + 27 * HOUR).await;
        assert_eq!(report.voided, 1);
        let revoked = stored(&h.db, &play_purchase_id("tok-c2")).await;
        assert_eq!(
            (revoked.state, revoked.unconsumed),
            (v0::ProtStoreState::Revoked, None)
        );
        assert_eq!(balance(&h.db, A).await, 2600);
        assert_conserved(&h.db, &[A]).await;
        done(h).await;
    }

    /// 9.6: RTDN through the reconcile pull: a PURCHASED hint credits the
    /// intent's user (no caller) and is acknowledged, as is another
    /// package's message; a void claws the whole purchase; a void of a
    /// purchase never seen leaves a tombstone its PURCHASED cannot credit
    #[tokio::test]
    async fn play_rtdn_credits_voids_and_acknowledges() {
        let h = harness().await;
        let intent = new_intent(&h, A, v0::ProtStore::Play, P25).await;
        h.play.set_purchase(
            "tok-r1",
            Ok(play_found(
                P25,
                Some(&intent.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        h.play.push_message(PubSubMessage {
            ack_id: "ack-1".to_string(),
            data: rtdn_purchased("tok-r1"),
            message_id: "m-1".to_string(),
        });
        h.play.push_message(PubSubMessage {
            ack_id: "ack-2".to_string(),
            data: rtdn(json!({ "packageName": "com.example.other", "testNotification": {} })),
            message_id: "m-2".to_string(),
        });
        let report = reconcile(&h, &h.st, NOW + MINUTE).await;
        assert_eq!(report.rtdn, 2);
        assert_eq!(
            h.play.acked(),
            vec!["ack-1".to_string(), "ack-2".to_string()]
        );
        assert_eq!(balance(&h.db, A).await, 2600);
        assert_eq!(consumes(&h.play).len(), 1);

        h.play.push_message(PubSubMessage {
            ack_id: "ack-3".to_string(),
            data: rtdn_voided("tok-r1", NOW + HOUR),
            message_id: "m-3".to_string(),
        });
        let report = reconcile(&h, &h.st, NOW + 2 * HOUR).await;
        assert_eq!(report.rtdn, 1);
        let voided = stored(&h.db, &play_purchase_id("tok-r1")).await;
        assert_eq!(
            (voided.state, voided.refund_gen),
            (v0::ProtStoreState::Revoked, 1)
        );
        assert_eq!(
            entry(&h.db, &prot_store_key_clawback(&voided.id, 1))
                .await
                .unwrap()
                .amount,
            2600
        );
        assert_eq!(balance(&h.db, A).await, 0);

        let intent = new_intent(&h, A, v0::ProtStore::Play, P25).await;
        h.play.set_purchase(
            "tok-r2",
            Ok(play_found(
                P25,
                Some(&intent.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        handle_play_rtdn(
            &h.db,
            &h.ps,
            &h.st,
            &h.play,
            &rtdn_voided("tok-r2", NOW),
            NOW,
        )
        .await
        .unwrap();
        handle_play_rtdn(&h.db, &h.ps, &h.st, &h.play, &rtdn_purchased("tok-r2"), NOW)
            .await
            .unwrap();
        let tombstone = stored(&h.db, &play_purchase_id("tok-r2")).await;
        assert_eq!(
            (tombstone.state, tombstone.refund_gen),
            (v0::ProtStoreState::Revoked, 0)
        );
        assert_eq!(balance(&h.db, A).await, 0);

        handle_play_rtdn(&h.db, &h.ps, &h.st, &h.play, b"not json", NOW)
            .await
            .unwrap();
        assert_conserved(&h.db, &[A]).await;
        done(h).await;
    }

    // --- refunds and reversals ---------------------------------------------

    /// Credit, then three Apple notifications acted on the fresh lookup
    async fn apple_credit(h: &Harness, id: u64) -> Tx {
        let intent = new_intent(h, A, v0::ProtStore::Apple, P25).await;
        let t = tx(id, Some(&intent.token));
        let response = verify_apple(h, &h.st, A, &t.jws(), NOW).await.unwrap();
        assert_eq!(answer(&response), (Status::Credited, None));
        t
    }

    /// Control 28 (reuse S5's `clawback_purchase`, which stops at an existing
    /// `clawback:{id}`): REFUND claws, REFUND_REVERSED re-credits what it
    /// clawed, a second REFUND claws again under generation 2; a replay of
    /// that REFUND moves nothing
    #[tokio::test]
    async fn refund_reinstate_refund_claws_twice() {
        let h = harness().await;
        let t = apple_credit(&h, 30).await;
        let id = t.purchase_id();

        let first = t.clone().revoked_at(NOW + HOUR);
        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(first.jws()));
        assert_eq!(
            notify(&h, "REFUND", &first.jws(), NOW + 2 * HOUR).await,
            AppleNotificationOutcome::Handled
        );
        let revoked = stored(&h.db, &id).await;
        assert_eq!(
            (revoked.state, revoked.refund_gen),
            (v0::ProtStoreState::Revoked, 1)
        );
        assert_eq!(
            entry(&h.db, &prot_store_key_clawback(&id, 1))
                .await
                .unwrap()
                .amount,
            2600
        );
        assert_eq!(balance(&h.db, A).await, 0);

        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(t.jws()));
        assert_eq!(
            notify(&h, "REFUND_REVERSED", &t.jws(), NOW + 3 * HOUR).await,
            AppleNotificationOutcome::Handled
        );
        assert_eq!(
            stored(&h.db, &id).await.state,
            v0::ProtStoreState::Reinstated
        );
        assert_eq!(
            entry(&h.db, &prot_store_key_reinstate(&id, 1))
                .await
                .unwrap()
                .amount,
            2600
        );
        assert_eq!(balance(&h.db, A).await, 2600);

        let second = t.clone().revoked_at(NOW + 4 * HOUR);
        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(second.jws()));
        notify(&h, "REFUND", &second.jws(), NOW + 5 * HOUR).await;
        let revoked = stored(&h.db, &id).await;
        assert_eq!(
            (revoked.state, revoked.refund_gen),
            (v0::ProtStoreState::Revoked, 2)
        );
        assert_eq!(
            entry(&h.db, &prot_store_key_clawback(&id, 2))
                .await
                .unwrap()
                .amount,
            2600
        );
        assert_eq!(balance(&h.db, A).await, 0);

        assert_eq!(
            notify(&h, "REFUND", &second.jws(), NOW + 6 * HOUR).await,
            AppleNotificationOutcome::Handled
        );
        assert_eq!(stored(&h.db, &id).await.refund_gen, 2);
        assert_eq!(balance(&h.db, A).await, 0);
        assert_conserved(&h.db, &[A]).await;
        done(h).await;
    }

    /// E6 / audit 18: a refund that took nothing (the Prot was spent) is
    /// reversed with nothing given back, and a later refund claws again
    #[tokio::test]
    async fn reinstate_of_nothing_then_refund_claws_again() {
        let h = harness().await;
        let t = apple_credit(&h, 31).await;
        let id = t.purchase_id();
        adjust(&h.db, A, "spend", -2600).await;

        let first = t.clone().revoked_at(NOW + HOUR);
        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(first.jws()));
        notify(&h, "REFUND", &first.jws(), NOW + 2 * HOUR).await;
        let clawed = entry(&h.db, &prot_store_key_clawback(&id, 1))
            .await
            .unwrap();
        assert_eq!((clawed.amount, clawed.shortfall), (0, Some(2600)));

        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(t.jws()));
        notify(&h, "REFUND_REVERSED", &t.jws(), NOW + 3 * HOUR).await;
        assert_eq!(
            stored(&h.db, &id).await.state,
            v0::ProtStoreState::Reinstated
        );
        assert!(entry(&h.db, &prot_store_key_reinstate(&id, 1))
            .await
            .is_none());
        assert_eq!(balance(&h.db, A).await, 0);

        adjust(&h.db, A, "topup", 100).await;
        let second = t.clone().revoked_at(NOW + 4 * HOUR);
        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(second.jws()));
        notify(&h, "REFUND", &second.jws(), NOW + 5 * HOUR).await;
        assert_eq!(stored(&h.db, &id).await.refund_gen, 2);
        assert_eq!(
            entry(&h.db, &prot_store_key_clawback(&id, 2))
                .await
                .unwrap()
                .amount,
            100
        );
        assert_eq!(balance(&h.db, A).await, 0);
        assert_conserved(&h.db, &[A]).await;
        done(h).await;
    }

    /// Control 28 (act on the REFUND type instead of the fresh lookup): a
    /// REFUND notification that arrives after Apple reversed that refund
    /// carries a revocationDate, but Apple's current answer has none: nothing
    /// is clawed
    #[tokio::test]
    async fn reversal_replayed_as_refund_is_not_clawed() {
        let h = harness().await;
        let t = apple_credit(&h, 32).await;
        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(t.jws()));

        let late_refund = t.clone().revoked_at(NOW + HOUR);
        assert_eq!(
            notify(&h, "REFUND", &late_refund.jws(), NOW + 2 * HOUR).await,
            AppleNotificationOutcome::Handled
        );
        let row = stored(&h.db, &t.purchase_id()).await;
        assert_eq!(
            (row.state, row.refund_gen),
            (v0::ProtStoreState::Credited, 0)
        );
        assert!(entry(&h.db, &prot_store_key_clawback(&t.purchase_id(), 1))
            .await
            .is_none());
        assert_eq!(balance(&h.db, A).await, 2600);
        done(h).await;
    }

    /// 16 step 4: a REFUND missed live is replayed from Notification History
    /// with the lookup forced; the cursor moves
    #[tokio::test]
    async fn apple_history_replays_a_missed_refund() {
        let h = harness().await;
        let t = apple_credit(&h, 33).await;
        let refunded = t.clone().revoked_at(NOW + HOUR);
        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(refunded.jws()));
        h.apple.set_history(vec![Ok(AppleHistoryPage {
            signed_payloads: vec![notification_jws("REFUND", &refunded.jws(), NOW + HOUR)],
            has_more: false,
            pagination_token: None,
        })]);

        let report = reconcile(&h, &h.st, NOW + 2 * HOUR).await;
        assert_eq!(report.apple_replayed, 1);
        assert_eq!(
            stored(&h.db, &t.purchase_id()).await.state,
            v0::ProtStoreState::Revoked
        );
        assert_eq!(balance(&h.db, A).await, 0);
        let cursor =
            h.db.fetch_prot_store_cursor(PROT_STORE_CURSOR_APPLE)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(cursor.cursor, (NOW + 2 * HOUR).to_string());
        assert_conserved(&h.db, &[A]).await;
        done(h).await;
    }

    /// 9.5: a body that is not a notification, or not signed by the pinned
    /// chain, is 400; another app or bundle, or an unhandled type, is
    /// ignored; a refund whose lookup fails is retried
    #[tokio::test]
    async fn apple_notification_checks_the_signature_and_the_app() {
        let h = harness().await;
        let t = apple_credit(&h, 34).await;

        assert_eq!(
            notify_raw(&h, b"{}".to_vec()).await,
            AppleNotificationOutcome::BadSignature
        );
        assert_eq!(
            notify_raw(
                &h,
                json!({ "signedPayload": "a.b.c" }).to_string().into_bytes()
            )
            .await,
            AppleNotificationOutcome::BadSignature
        );

        let refunded = t.clone().revoked_at(NOW);
        let other_app = jws(&json!({
            "notificationType": "REFUND",
            "notificationUUID": "other-app",
            "data": {
                "appAppleId": APP_APPLE_ID + 1,
                "bundleId": BUNDLE,
                "environment": "Production",
                "signedTransactionInfo": refunded.jws(),
            },
            "signedDate": NOW,
        }));
        let other_bundle = jws(&json!({
            "notificationType": "REFUND",
            "notificationUUID": "other-bundle",
            "data": {
                "bundleId": "com.example.other",
                "environment": "Production",
                "signedTransactionInfo": refunded.jws(),
            },
            "signedDate": NOW,
        }));
        for signed in [
            other_app,
            other_bundle,
            notification_jws("REFUND_DECLINED", &refunded.jws(), NOW),
            notification_jws("CONSUMPTION_REQUEST", &refunded.jws(), NOW),
        ] {
            assert_eq!(
                notify_raw(
                    &h,
                    json!({ "signedPayload": signed }).to_string().into_bytes()
                )
                .await,
                AppleNotificationOutcome::Ignored
            );
        }

        h.apple.set_transaction_info(
            &t.transaction_id(),
            Err(StoreApiError::Transient("unavailable".to_string())),
        );
        assert_eq!(
            notify(&h, "REFUND", &refunded.jws(), NOW + HOUR).await,
            AppleNotificationOutcome::Retry
        );
        assert_eq!(
            stored(&h.db, &t.purchase_id()).await.state,
            v0::ProtStoreState::Credited
        );
        assert_eq!(balance(&h.db, A).await, 2600);
        done(h).await;
    }

    /// Control 28 (Unpause without the fresh lookup; audit N3): a purchase
    /// held while credits were paused and refunded in the meantime is not
    /// credited when the pause ends; one still bought is
    #[tokio::test]
    async fn held_row_refunded_while_paused_is_not_credited() {
        let h = harness().await;
        let mut paused = h.st.clone();
        paused.credit_paused = true;

        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        let refunded = tx(40, Some(&intent.token));
        verify_apple(&h, &paused, A, &refunded.jws(), NOW)
            .await
            .unwrap();
        h.apple.set_transaction_info(
            &refunded.transaction_id(),
            Ok(refunded.clone().revoked_at(NOW + HOUR).jws()),
        );

        // Still paused: nothing happens to it
        let report = reconcile(&h, &paused, NOW + 2 * HOUR).await;
        assert_eq!(report.held_credited, 0);
        assert_eq!(
            stored(&h.db, &refunded.purchase_id()).await.state,
            v0::ProtStoreState::Held
        );

        let report = reconcile(&h, &h.st, NOW + 3 * HOUR).await;
        assert_eq!(report.held_credited, 0);
        assert_eq!(
            stored(&h.db, &refunded.purchase_id()).await.state,
            v0::ProtStoreState::Revoked
        );
        assert!(
            entry(&h.db, &prot_store_key_purchase(&refunded.purchase_id()))
                .await
                .is_none()
        );
        assert_eq!(balance(&h.db, A).await, 0);

        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        let bought = tx(41, Some(&intent.token));
        verify_apple(&h, &paused, A, &bought.jws(), NOW)
            .await
            .unwrap();
        h.apple
            .set_transaction_info(&bought.transaction_id(), Ok(bought.jws()));
        let report = reconcile(&h, &h.st, NOW + 4 * HOUR).await;
        assert_eq!(report.held_credited, 1);
        assert_eq!(balance(&h.db, A).await, 2600);
        assert_conserved(&h.db, &[A]).await;
        done(h).await;
    }

    /// Section 17: account deletion unlinks the rows and intents; a late
    /// refund of a purchase the deleted account was credited records a
    /// no-buyer generation and takes nothing (the forfeit took the wallet);
    /// a late purchase on an unlinked intent has no buyer
    #[tokio::test]
    async fn account_deletion_unlinks_store_rows_and_a_late_refund_takes_nothing() {
        let h = harness().await;
        let t = apple_credit(&h, 42).await;
        let open = new_intent(&h, A, v0::ProtStore::Play, P25).await;

        forfeit_wallet_on_deletion(&h.db, A, NOW + MINUTE)
            .await
            .unwrap();
        unlink_account_payments(&h.db, A).await.unwrap();
        assert_eq!(stored(&h.db, &t.purchase_id()).await.user_id, None);
        let unlinked =
            h.db.fetch_prot_store_intent(&open.intent_id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            (unlinked.user_id, unlinked.state),
            (None, v0::ProtStoreIntentState::Expired)
        );
        assert_eq!(balance(&h.db, A).await, 0);

        let refunded = t.clone().revoked_at(NOW + HOUR);
        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(refunded.jws()));
        assert_eq!(
            notify(&h, "REFUND", &refunded.jws(), NOW + 2 * HOUR).await,
            AppleNotificationOutcome::Handled
        );
        let row = stored(&h.db, &t.purchase_id()).await;
        assert_eq!(
            (row.state, row.refund_gen),
            (v0::ProtStoreState::Revoked, 1)
        );
        assert_eq!(row.refunds[0].reason.as_deref(), Some("no_buyer"));
        assert!(entry(&h.db, &prot_store_key_clawback(&t.purchase_id(), 1))
            .await
            .is_none());

        h.play.set_purchase(
            "tok-late",
            Ok(play_found(
                P25,
                Some(&open.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        handle_play_rtdn(
            &h.db,
            &h.ps,
            &h.st,
            &h.play,
            &rtdn_purchased("tok-late"),
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(
            stored(&h.db, &play_purchase_id("tok-late"))
                .await
                .reject_reason,
            Some(v0::ProtStoreRejectReason::NoBuyer)
        );
        assert!(consumes(&h.play).is_empty());
        assert_conserved(&h.db, &[A]).await;
        done(h).await;
    }

    // --- intents ---------------------------------------------------------------

    /// 9.3, gates in order; a preview account sees a closed store
    #[tokio::test]
    async fn store_intent_gates_in_order() {
        let h = harness().await;
        insert_account(
            &h.db,
            User {
                bot: Some(BotInformation {
                    owner: A.to_string(),
                }),
                ..user(BOT)
            },
        )
        .await;
        let apple = intent_data(v0::ProtStore::Apple, P25);

        let off = PaymentsSettings {
            enabled: false,
            ..h.s.clone()
        };
        let refused = gate(&h, off, h.ps.clone(), h.st.clone(), A, apple.clone(), None).await;
        assert!(matches!(error_of(refused), ErrorType::PaymentsDisabled));
        let prot_off = ProtSalesSettings {
            enabled: false,
            ..h.ps.clone()
        };
        let refused = gate(
            &h,
            h.s.clone(),
            prot_off,
            h.st.clone(),
            A,
            apple.clone(),
            None,
        )
        .await;
        assert!(matches!(error_of(refused), ErrorType::ProtDisabled));
        let refused = gate(
            &h,
            h.s.clone(),
            h.ps.clone(),
            h.st.clone(),
            BOT,
            apple.clone(),
            None,
        )
        .await;
        assert!(matches!(error_of(refused), ErrorType::IsBot));

        let closed = ProtStoreSettings {
            apple_open: false,
            ..h.st.clone()
        };
        let refused = gate(
            &h,
            h.s.clone(),
            h.ps.clone(),
            closed.clone(),
            A,
            apple.clone(),
            None,
        )
        .await;
        assert!(matches!(error_of(refused), ErrorType::ProtStoreClosed));
        let preview = ProtStoreSettings {
            preview_user_ids: vec![A.to_string()],
            ..closed
        };
        assert!(gate(
            &h,
            h.s.clone(),
            h.ps.clone(),
            preview,
            A,
            apple.clone(),
            None
        )
        .await
        .is_ok());

        let refused = gate(
            &h,
            h.s.clone(),
            h.ps.clone(),
            h.st.clone(),
            A,
            apple.clone(),
            Some("DE"),
        )
        .await;
        assert!(matches!(
            error_of(refused),
            ErrorType::ProtRegionUnavailable
        ));
        assert!(gate(
            &h,
            h.s.clone(),
            h.ps.clone(),
            h.st.clone(),
            A,
            apple.clone(),
            Some("US")
        )
        .await
        .is_ok());

        let sku = Sku::ProtPack {
            pack: "p25".to_string(),
            prot: 2600,
            cents: 2500,
        };
        h.db.insert_payment_order(&PaymentOrder {
            id: Ulid::new().to_string(),
            user_id: Some(C.to_string()),
            provider: PaymentProvider::Stripe,
            amount_cents: catalog::sku_cents(&sku).unwrap(),
            sku,
            currency: "usd".to_string(),
            checkout_session_id: None,
            checkout_url: None,
            session_expires_at: None,
            payment_intent_id: None,
            state: OrderState::Fulfilled,
            void_reason: None,
            region_blocked_country: None,
            reversal_pending: None,
            refund_settling_since: None,
            open_disputes: vec!["dp_s6_test".to_string()],
            lease_until: None,
            version: 0,
            created_at: NOW - DAY,
            paid_at: Some(NOW - DAY),
            fulfilled_at: Some(NOW - DAY),
            reversed_at: None,
        })
        .await
        .unwrap();
        let refused = gate(
            &h,
            h.s.clone(),
            h.ps.clone(),
            h.st.clone(),
            C,
            apple.clone(),
            None,
        )
        .await;
        assert!(matches!(error_of(refused), ErrorType::ProtNotEligible));

        let unknown = intent_data(v0::ProtStore::Apple, "gg.sloga.prot.p1");
        let refused = gate(
            &h,
            h.s.clone(),
            h.ps.clone(),
            h.st.clone(),
            B,
            unknown,
            None,
        )
        .await;
        assert!(matches!(
            error_of(refused),
            ErrorType::ProtStoreProductUnknown
        ));

        let unconfigured = MockAppleStore::new();
        unconfigured.unconfigured();
        let refused = create_store_intent(
            &h.db,
            &h.s,
            &h.ps,
            &h.st,
            &h.play,
            &unconfigured,
            B,
            &apple,
            None,
            NOW,
        )
        .await;
        assert!(matches!(error_of(refused), ErrorType::ProtStoreUnavailable));
        done(h).await;
    }

    /// Control 28 (drop the `pubsub_configured()` gate): no Play intent
    /// without RTDN; Apple is unaffected
    #[tokio::test]
    async fn play_intent_needs_rtdn() {
        let h = harness().await;
        h.play.no_pubsub();
        let refused = intent_with(&h, &h.ps, &h.st, A, v0::ProtStore::Play, P25).await;
        assert!(matches!(error_of(refused), ErrorType::ProtStoreUnavailable));
        assert!(h
            .db
            .fetch_open_prot_store_intents(A, NOW)
            .await
            .unwrap()
            .is_empty());
        assert!(intent_with(&h, &h.ps, &h.st, A, v0::ProtStore::Apple, P25)
            .await
            .is_ok());
        done(h).await;
    }

    /// R53: an Apple REFUND and a Play void that arrive before any verify,
    /// carrying the token of an issued intent, leave tombstones that mark the
    /// intent Used: its slot of the three and its share of the cap are freed.
    /// Control: drop `intent_id` from the Revoke event → this test fails.
    #[tokio::test]
    async fn refund_before_credit_marks_the_intent_used_and_frees_it() {
        let h = harness().await;
        let mut open = Vec::new();
        for _ in 0..3 {
            open.push(new_intent(&h, B, v0::ProtStore::Apple, P5).await);
        }
        let refused = intent_with(&h, &h.ps, &h.st, B, v0::ProtStore::Apple, P5).await;
        assert!(matches!(error_of(refused), ErrorType::PaymentPending));

        let refunded = Tx {
            product: P5,
            ..tx(60, Some(&open[0].token))
        }
        .revoked_at(NOW - MINUTE);
        h.apple
            .set_transaction_info(&refunded.transaction_id(), Ok(refunded.jws()));
        assert_eq!(
            notify(&h, "REFUND", &refunded.jws(), NOW).await,
            AppleNotificationOutcome::Handled
        );
        let tombstone = stored(&h.db, &refunded.purchase_id()).await;
        assert_eq!(
            (tombstone.state, tombstone.refund_gen),
            (v0::ProtStoreState::Revoked, 0)
        );
        assert_eq!(tombstone.user_id.as_deref(), Some(B));
        assert_eq!(
            tombstone.intent_id.as_deref(),
            Some(open[0].intent_id.as_str())
        );
        let used =
            h.db.fetch_prot_store_intent(&open[0].intent_id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(used.state, v0::ProtStoreIntentState::Used);
        assert_eq!(used.purchase_id, Some(refunded.purchase_id()));
        assert!(intent_with(&h, &h.ps, &h.st, B, v0::ProtStore::Apple, P5)
            .await
            .is_ok());

        // Play: the void frees the intent's share of the cap
        let capped = ProtSalesSettings {
            wallet_cap: 3000,
            ..h.ps.clone()
        };
        let play_intent = intent_with(&h, &capped, &h.st, C, v0::ProtStore::Play, P25)
            .await
            .unwrap();
        let refused = intent_with(&h, &capped, &h.st, C, v0::ProtStore::Play, P5).await;
        assert!(matches!(
            error_of(refused),
            ErrorType::ProtWalletCap { max: 3000 }
        ));
        h.play.set_purchase(
            "tok-void-first",
            Ok(play_found(
                P25,
                Some(&play_intent.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        handle_play_rtdn(
            &h.db,
            &h.ps,
            &h.st,
            &h.play,
            &rtdn_voided("tok-void-first", NOW),
            NOW,
        )
        .await
        .unwrap();
        let tombstone = stored(&h.db, &play_purchase_id("tok-void-first")).await;
        assert_eq!(tombstone.state, v0::ProtStoreState::Revoked);
        assert_eq!(tombstone.user_id.as_deref(), Some(C));
        assert_eq!(
            h.db.fetch_prot_store_intent(&play_intent.intent_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            v0::ProtStoreIntentState::Used
        );
        assert!(intent_with(&h, &capped, &h.st, C, v0::ProtStore::Play, P5)
            .await
            .is_ok());
        assert_eq!((balance(&h.db, B).await, balance(&h.db, C).await), (0, 0));
        done(h).await;
    }

    // --- W2 audit fix round (section 48) -------------------------------------

    /// R58 (control: drop the 30-day floor, or move the cursor to the latest
    /// void time): the voided scan never starts further back than Play keeps,
    /// and the cursor follows the scan's query time, voids or none
    #[tokio::test]
    async fn play_voided_scan_stays_within_plays_window() {
        let h = harness().await;
        let call = |start: i64| format!("voided_purchases {start} -");
        async fn cursor(h: &Harness) -> String {
            h.db.fetch_prot_store_cursor(PROT_STORE_CURSOR_PLAY)
                .await
                .unwrap()
                .expect("the voided cursor")
                .cursor
        }

        reconcile(&h, &h.st, NOW).await;
        assert!(h.play.calls().contains(&call(NOW - 30 * DAY + HOUR)));
        assert_eq!(cursor(&h).await, (NOW - HOUR).to_string());

        // Forty quiet days later the scan still starts inside Play's window,
        // and an old void it reports does not pull the cursor back
        let later = NOW + 40 * DAY;
        h.play.set_voided(vec![Ok(PlayVoidedPage {
            voided: vec![PlayVoided {
                purchase_token: "tok-voided-old".to_string(),
                order_id: None,
                voided_time_ms: NOW - 20 * DAY,
            }],
            next_page_token: None,
        })]);
        let report = reconcile(&h, &h.st, later).await;
        assert_eq!(report.voided, 1);
        assert!(h.play.calls().contains(&call(later - 30 * DAY + HOUR)));
        assert_eq!(cursor(&h).await, (later - HOUR).to_string());

        // A day on, the overlap applies again
        reconcile(&h, &h.st, later + DAY).await;
        assert!(h.play.calls().contains(&call(later - 2 * HOUR)));
        assert_eq!(cursor(&h).await, (later + DAY - HOUR).to_string());
        assert_eq!(play_voided_start(None, NOW), NOW - 30 * DAY + HOUR);
        done(h).await;
    }

    /// R59 (control: no paused branch): while credits are paused, a Play
    /// purchase held for over a day gets the `play_held_24h` work item and one
    /// claimed alert; when the pause ends it is credited, consumed, cleared
    #[tokio::test]
    async fn paused_play_purchase_gets_a_work_item_after_a_day() {
        let h = harness().await;
        let mut paused = h.st.clone();
        paused.credit_paused = true;
        let intent = new_intent(&h, C, v0::ProtStore::Play, P25).await;
        h.play.set_purchase(
            "tok-held-24",
            Ok(play_found(
                P25,
                Some(&intent.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        let id = play_purchase_id("tok-held-24");
        let response = verify_play(&h, &paused, C, P25, "tok-held-24", NOW)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Pending, None));

        assert_eq!(reconcile(&h, &paused, NOW + 2 * HOUR).await.alerts, 0);
        assert_eq!(stored(&h.db, &id).await.needs_action, None);

        assert_eq!(reconcile(&h, &paused, NOW + 25 * HOUR).await.alerts, 1);
        let flagged = stored(&h.db, &id).await;
        assert_eq!(flagged.needs_action.as_deref(), Some(PROT_STORE_NEEDS_HELD));
        assert!(flagged
            .alerted
            .iter()
            .any(|kind| kind == PROT_STORE_NEEDS_HELD));
        assert_eq!(reconcile(&h, &paused, NOW + 26 * HOUR).await.alerts, 0);
        assert!(consumes(&h.play).is_empty());

        h.play.set_purchase(
            "tok-held-24",
            Ok(play_found(
                P25,
                Some(&intent.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        let report = reconcile(&h, &h.st, NOW + 27 * HOUR).await;
        assert_eq!(report.held_credited, 1);
        let credited = stored(&h.db, &id).await;
        assert_eq!(credited.state, v0::ProtStoreState::Credited);
        assert_eq!((credited.needs_action, credited.unconsumed), (None, None));
        assert_eq!(consumes(&h.play).len(), 1);
        assert_eq!(balance(&h.db, C).await, 2600);
        assert_conserved(&h.db, &[C]).await;
        done(h).await;
    }

    /// R61 (control: map `lookup_*` to Ignored): a verified notification whose
    /// fresh lookup Apple answers with another transaction is retried, live and
    /// in the history replay (cursor kept); a verified payload that does not
    /// decode is ignored (logged at error, never mailed)
    #[tokio::test]
    async fn notification_with_a_refused_lookup_is_retried() {
        let h = harness().await;
        let t = apple_credit(&h, 70).await;
        let refunded = t.clone().revoked_at(NOW);
        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(tx(71, None).revoked_at(NOW).jws()));

        assert_eq!(
            notify(&h, "REFUND", &refunded.jws(), NOW + HOUR).await,
            AppleNotificationOutcome::Retry
        );
        assert_eq!(
            stored(&h.db, &t.purchase_id()).await.state,
            v0::ProtStoreState::Credited
        );

        h.apple.set_history(vec![Ok(AppleHistoryPage {
            signed_payloads: vec![notification_jws("REFUND", &refunded.jws(), NOW + HOUR)],
            has_more: false,
            pagination_token: None,
        })]);
        let report = reconcile(&h, &h.st, NOW + 2 * HOUR).await;
        assert_eq!(report.apple_replayed, 0);
        assert!(report.failed >= 1);
        assert!(h
            .db
            .fetch_prot_store_cursor(PROT_STORE_CURSOR_APPLE)
            .await
            .unwrap()
            .is_none());
        assert_eq!(balance(&h.db, A).await, 2600);

        let undecodable = jws(&json!({ "signedDate": NOW }));
        assert_eq!(
            notify_raw(
                &h,
                json!({ "signedPayload": undecodable })
                    .to_string()
                    .into_bytes()
            )
            .await,
            AppleNotificationOutcome::Ignored
        );
        done(h).await;
    }

    /// MINOR 5 + R16 (control: hard-code `paused: false`): an assign while
    /// credits are paused records the purchase Held for the target, with no
    /// ledger row and no consume; the end of the pause credits and consumes it
    #[tokio::test]
    async fn assign_while_paused_holds_then_unpause_credits_and_consumes() {
        let h = harness().await;
        let mut paused = h.st.clone();
        paused.credit_paused = true;
        h.play.set_purchase(
            "tok-assign-held",
            Ok(play_found(P25, None, PLAY_PURCHASE_STATE_PURCHASED)),
        );
        let response = verify_play(&h, &h.st, A, P25, "tok-assign-held", NOW)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Rejected, Some(Reason::Unbound)));
        let id = play_purchase_id("tok-assign-held");

        let view = assign_with(&h, &paused, id.clone(), B).await.unwrap();
        assert_eq!(view.purchase.state, v0::ProtStoreState::Held);
        assert_eq!(view.purchase.user_id.as_deref(), Some(B));
        assert!(view.ledger.is_empty());
        assert_eq!(balance(&h.db, B).await, 0);
        assert!(consumes(&h.play).is_empty());

        let report = reconcile(&h, &h.st, NOW + HOUR).await;
        assert_eq!(report.held_credited, 1);
        assert_eq!(balance(&h.db, B).await, 2600);
        assert_eq!(
            consumes(&h.play),
            vec![format!("consume {P25} {}", sha256_hex("tok-assign-held"))]
        );
        assert_eq!(stored(&h.db, &id).await.unconsumed, None);
        assert_conserved(&h.db, &[A, B]).await;
        done(h).await;
    }

    /// MINOR 5: a Sandbox purchase and a purchase of a product with no Prot
    /// are never assigned (refused before any store lookup)
    #[tokio::test]
    async fn assign_refuses_sandbox_and_unpriced_purchases() {
        let h = harness().await;
        let sandbox = Tx {
            environment: "Sandbox",
            ..tx(80, None)
        };
        let unpriced = Tx {
            product: "gg.sloga.prot.p1",
            ..tx(81, None)
        };
        for t in [&sandbox, &unpriced] {
            let response = verify_apple(&h, &h.st, A, &t.jws(), NOW).await.unwrap();
            assert_eq!(answer(&response), (Status::Rejected, Some(Reason::Unbound)));
            h.apple
                .set_transaction_info(&t.transaction_id(), Ok(t.jws()));
            assert!(matches!(
                error_of(assign(&h, t.purchase_id(), B).await),
                ErrorType::InvalidOperation
            ));
            assert_eq!(
                stored(&h.db, &t.purchase_id()).await.state,
                v0::ProtStoreState::Rejected
            );
        }
        assert_eq!(stored(&h.db, &unpriced.purchase_id()).await.prot, 0);
        assert_eq!(lookups(&h.apple, &unpriced), 0);
        assert_eq!(balance(&h.db, B).await, 0);
        done(h).await;
    }

    /// MINOR 6 (control: always start at the head): each tick takes the next
    /// share of a step's rows, so every row gets a turn
    #[test]
    fn each_tick_takes_the_next_share_of_the_rows() {
        let turn = AtomicUsize::new(0);
        let mut seen = HashSet::new();
        for _ in 0..3 {
            let share = this_ticks_share((0..250).collect::<Vec<u32>>(), &turn, 100);
            assert!(share.len() <= 100);
            seen.extend(share);
        }
        assert_eq!(seen.len(), 250);
        assert_eq!(this_ticks_share(vec![1, 2, 3], &turn, 100), vec![1, 2, 3]);
        assert_eq!(turn.load(Ordering::Relaxed), 0);
    }

    /// MINOR 6 (control: read the newest 100 work items of all kinds): an
    /// unbound Play purchase is alerted even when more than 100 newer work
    /// items of another kind exist
    #[tokio::test]
    async fn unbound_play_alert_is_not_starved_by_newer_work_items() {
        let h = harness().await;
        h.play.set_purchase(
            "tok-stray-play",
            Ok(play_found(P25, None, PLAY_PURCHASE_STATE_PURCHASED)),
        );
        verify_play(&h, &h.st, A, P25, "tok-stray-play", NOW - 2 * DAY)
            .await
            .unwrap();
        let stray = stored(&h.db, &play_purchase_id("tok-stray-play")).await;
        for n in 0..101_i64 {
            put_row(
                &h.db,
                ProtStorePurchase {
                    id: format!("play:{n:064x}"),
                    state: v0::ProtStoreState::Credited,
                    user_id: Some(A.to_string()),
                    needs_action: Some(PROT_STORE_NEEDS_CHARGEBACK.to_string()),
                    created_at: NOW - DAY,
                    updated_at: NOW + n,
                    ..stray.clone()
                },
            )
            .await;
        }

        let report = reconcile(&h, &h.st, NOW).await;
        assert_eq!(report.alerts, 1);
        assert!(stored(&h.db, &stray.id)
            .await
            .alerted
            .iter()
            .any(|kind| kind == ALERT_UNBOUND_PLAY));
        done(h).await;
    }

    /// R5 + R19: the cap counts the balance, Held store rows, open intents
    /// and the new product; at most three open intents (a cancel frees one)
    #[tokio::test]
    async fn store_intent_cap_and_open_limit() {
        let h = harness().await;
        let capped = ProtSalesSettings {
            wallet_cap: 12_000,
            ..h.ps.clone()
        };
        let mut paused = h.st.clone();
        paused.credit_paused = true;

        let intent = intent_with(&h, &capped, &h.st, C, v0::ProtStore::Apple, P100)
            .await
            .unwrap();
        let held = Tx {
            product: P100,
            ..tx(50, Some(&intent.token))
        };
        let response = verify_apple(&h, &paused, C, &held.jws(), NOW)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Pending, None));
        // 11,000 held + 500 = 11,500 <= 12,000
        intent_with(&h, &capped, &h.st, C, v0::ProtStore::Apple, P5)
            .await
            .unwrap();
        // 11,000 held + 500 open + 1,000 = 12,500 > 12,000
        let refused = intent_with(&h, &capped, &h.st, C, v0::ProtStore::Apple, P10).await;
        assert!(matches!(
            error_of(refused),
            ErrorType::ProtWalletCap { max: 12_000 }
        ));

        let mut open = Vec::new();
        for _ in 0..3 {
            open.push(new_intent(&h, B, v0::ProtStore::Apple, P5).await);
        }
        let refused = intent_with(&h, &h.ps, &h.st, B, v0::ProtStore::Apple, P5).await;
        assert!(matches!(error_of(refused), ErrorType::PaymentPending));
        cancel_store_intent(&h.db, B, &open[0].intent_id)
            .await
            .unwrap();
        assert!(intent_with(&h, &h.ps, &h.st, B, v0::ProtStore::Apple, P5)
            .await
            .is_ok());
        done(h).await;
    }

    /// R62: a cancelled intent still binds a late purchase (E9), so its Prot
    /// counts toward the cap until it expires: intent → cancel → intent stops
    /// at the cap, while a cancel still frees one of the three slots.
    /// Control: fold the open intents only again → this test fails.
    #[tokio::test]
    async fn cancelled_intents_still_count_toward_the_cap() {
        let h = harness().await;
        let capped = ProtSalesSettings {
            wallet_cap: 3000,
            ..h.ps.clone()
        };

        // 1,000 each: three fit (3,000 <= 3,000), the fourth does not
        let mut issued = 0;
        let refused = loop {
            match intent_with(&h, &capped, &h.st, A, v0::ProtStore::Apple, P10).await {
                Ok(intent) => {
                    issued += 1;
                    assert!(issued <= 3, "intent → cancel bought past the cap");
                    cancel_store_intent(&h.db, A, &intent.intent_id)
                        .await
                        .unwrap();
                }
                Err(err) => break err.error_type,
            }
        };
        assert_eq!(issued, 3);
        // Every slot is free (all three were cancelled): the cap refuses,
        // never the three-slot limit
        assert!(
            matches!(refused, ErrorType::ProtWalletCap { max: 3000 }),
            "{refused:?}"
        );
        assert!(h
            .db
            .fetch_open_prot_store_intents(A, NOW)
            .await
            .unwrap()
            .is_empty());

        // Once the cancelled intents expire, they stop counting
        create_store_intent(
            &h.db,
            &h.s,
            &capped,
            &h.st,
            &h.play,
            &h.apple,
            A,
            &intent_data(v0::ProtStore::Apple, P10),
            None,
            NOW + PROT_STORE_INTENT_TTL_MS,
        )
        .await
        .expect("expired intents leave the cap");

        // Under the default cap, a fourth intent after three cancels is issued
        for _ in 0..3 {
            let intent = new_intent(&h, B, v0::ProtStore::Apple, P5).await;
            cancel_store_intent(&h.db, B, &intent.intent_id)
                .await
                .unwrap();
        }
        intent_with(&h, &h.ps, &h.st, B, v0::ProtStore::Apple, P5)
            .await
            .expect("a cancel frees its slot");
        done(h).await;
    }

    /// 12.1: only the owner cancels; Open → Expired, idempotent; a Used
    /// intent cannot be cancelled
    #[tokio::test]
    async fn store_intent_cancel() {
        let h = harness().await;
        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        assert!(matches!(
            error_of(cancel_store_intent(&h.db, B, &intent.intent_id).await),
            ErrorType::NotFound
        ));
        assert!(matches!(
            error_of(cancel_store_intent(&h.db, A, "not-an-intent").await),
            ErrorType::NotFound
        ));
        cancel_store_intent(&h.db, A, &intent.intent_id)
            .await
            .unwrap();
        cancel_store_intent(&h.db, A, &intent.intent_id)
            .await
            .unwrap();
        assert_eq!(
            h.db.fetch_prot_store_intent(&intent.intent_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            v0::ProtStoreIntentState::Expired
        );

        let used = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        verify_apple(&h, &h.st, A, &tx(51, Some(&used.token)).jws(), NOW)
            .await
            .unwrap();
        assert!(matches!(
            error_of(cancel_store_intent(&h.db, A, &used.intent_id).await),
            ErrorType::InvalidOperation
        ));
        done(h).await;
    }

    /// E9 + 16 steps 6 and 8: an expired intent still binds a late purchase;
    /// expired, never-used intents are deleted 30 days later, used ones kept
    #[tokio::test]
    async fn expired_intent_binds_a_late_purchase_and_stale_ones_are_purged() {
        let h = harness().await;
        let late = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        let unused = new_intent(&h, A, v0::ProtStore::Apple, P5).await;

        let report = reconcile(&h, &h.st, NOW + 25 * HOUR).await;
        assert_eq!(report.intents_expired, 2);

        let t = tx(52, Some(&late.token)).signed_at(NOW + 25 * HOUR);
        let response = verify_apple(&h, &h.st, A, &t.jws(), NOW + 25 * HOUR)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Credited, None));

        reconcile(&h, &h.st, NOW + 25 * HOUR + 31 * DAY).await;
        assert!(h
            .db
            .fetch_prot_store_intent(&unused.intent_id)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            h.db.fetch_prot_store_intent(&late.intent_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            v0::ProtStoreIntentState::Used
        );
        done(h).await;
    }

    /// 9.3 tokens, and R47: an insert that fails retries once with the
    /// second token, then fails 500
    #[tokio::test]
    async fn intent_tokens_are_fresh_and_a_failed_insert_retries_once() {
        let h = harness().await;
        let apple = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        assert_eq!(apple.token.len(), 36);
        assert_eq!(apple.token, apple.token.to_ascii_lowercase());
        assert_eq!(apple.token.as_bytes()[14], b'4', "a UUID v4");
        let play = new_intent(&h, A, v0::ProtStore::Play, P5).await;
        assert_eq!(play.token.len(), 43);
        assert!(play
            .token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_eq!(play.prot, 500);
        assert_eq!(play.expires_at, NOW + PROT_STORE_INTENT_TTL_MS);

        let data = intent_data(v0::ProtStore::Apple, P5);
        let retried = issue_store_intent(
            &h.db,
            &h.s,
            &h.ps,
            &h.st,
            &h.play,
            &h.apple,
            B,
            &data,
            None,
            NOW,
            [apple.token.clone(), "s6-l2c-fresh-token".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(retried.token, "s6-l2c-fresh-token");

        let failed = issue_store_intent(
            &h.db,
            &h.s,
            &h.ps,
            &h.st,
            &h.play,
            &h.apple,
            C,
            &data,
            None,
            NOW,
            [apple.token.clone(), play.token.clone()],
        )
        .await;
        assert!(matches!(error_of(failed), ErrorType::InternalError));
        assert!(h
            .db
            .fetch_open_prot_store_intents(C, NOW)
            .await
            .unwrap()
            .is_empty());
        done(h).await;
    }

    /// 9.4 step 1, 15.2: verify needs the store client, its config and the
    /// store's body shape; bots never verify; `store_preview` follows E3
    #[tokio::test]
    async fn verify_needs_the_store_and_a_well_formed_body() {
        let h = harness().await;
        insert_account(
            &h.db,
            User {
                bot: Some(BotInformation {
                    owner: A.to_string(),
                }),
                ..user(BOT)
            },
        )
        .await;
        let t = tx(53, None);

        let bot = verify_apple(&h, &h.st, BOT, &t.jws(), NOW).await;
        assert!(matches!(error_of(bot), ErrorType::IsBot));

        let no_config = ProtStoreSettings {
            apple: None,
            ..h.st.clone()
        };
        let refused = verify_apple(&h, &no_config, A, &t.jws(), NOW).await;
        assert!(matches!(error_of(refused), ErrorType::ProtStoreUnavailable));

        let unconfigured = MockAppleStore::new();
        unconfigured.unconfigured();
        let data = v0::DataProtStoreVerify {
            store: v0::ProtStore::Apple,
            signed_transaction: Some(t.jws()),
            product_id: None,
            purchase_token: None,
        };
        let refused =
            verify_store_purchase(&h.db, &h.ps, &h.st, &unconfigured, &h.play, A, &data, NOW).await;
        assert!(matches!(error_of(refused), ErrorType::ProtStoreUnavailable));

        let mixed = v0::DataProtStoreVerify {
            purchase_token: Some("tok".to_string()),
            ..data
        };
        let refused =
            verify_store_purchase(&h.db, &h.ps, &h.st, &h.apple, &h.play, A, &mixed, NOW).await;
        assert!(matches!(
            error_of(refused),
            ErrorType::FailedValidation { .. }
        ));
        assert!(row(&h.db, &t.purchase_id()).await.is_none());

        let preview = ProtStoreSettings {
            preview_user_ids: vec![A.to_string()],
            ..h.st.clone()
        };
        assert!(store_preview(&preview, A));
        assert!(!store_preview(&preview, B));
        done(h).await;
    }

    /// 12.6 resolve: only the kind the row holds, and only the two staff kinds
    #[tokio::test]
    async fn resolve_clears_only_the_named_work_item() {
        let h = harness().await;
        let t = apple_credit(&h, 54).await;
        let id = t.purchase_id();
        h.db.set_prot_store_needs_action(&id, PROT_STORE_NEEDS_CHARGEBACK, NOW)
            .await
            .unwrap();

        for kind in [
            PROT_STORE_NEEDS_REVERSED_UNPAID,
            PROT_STORE_NEEDS_UNBOUND,
            "other",
        ] {
            assert!(matches!(
                error_of(admin_resolve_store_purchase(&h.db, ADMIN, &id, kind, NOW).await),
                ErrorType::InvalidOperation
            ));
        }
        assert!(matches!(
            error_of(
                admin_resolve_store_purchase(
                    &h.db,
                    ADMIN,
                    "01NOTASTOREID",
                    PROT_STORE_NEEDS_CHARGEBACK,
                    NOW
                )
                .await
            ),
            ErrorType::NotFound
        ));
        let view =
            admin_resolve_store_purchase(&h.db, ADMIN, &id, PROT_STORE_NEEDS_CHARGEBACK, NOW)
                .await
                .unwrap();
        assert_eq!(view.purchase.needs_action, None);
        assert_eq!(
            admin_store_purchase(&h.db, &id).await.unwrap().ledger.len(),
            1
        );
        done(h).await;
    }

    // --- R63: over-cap holds ----------------------------------------------------

    /// The Prot settings with `wallet_cap` = `cap`
    fn capped(h: &Harness, cap: i64) -> ProtSalesSettings {
        ProtSalesSettings {
            wallet_cap: cap,
            ..h.ps.clone()
        }
    }

    async fn verify_apple_under(
        h: &Harness,
        ps: &ProtSalesSettings,
        st: &ProtStoreSettings,
        user: &str,
        signed: &str,
        now: i64,
    ) -> v0::ProtStoreVerifyResponse {
        let data = v0::DataProtStoreVerify {
            store: v0::ProtStore::Apple,
            signed_transaction: Some(signed.to_string()),
            product_id: None,
            purchase_token: None,
        };
        verify_store_purchase(&h.db, ps, st, &h.apple, &h.play, user, &data, now)
            .await
            .expect("verified")
    }

    async fn verify_play_under(
        h: &Harness,
        ps: &ProtSalesSettings,
        user: &str,
        product: &str,
        token: &str,
        now: i64,
    ) -> v0::ProtStoreVerifyResponse {
        let data = v0::DataProtStoreVerify {
            store: v0::ProtStore::Play,
            signed_transaction: None,
            product_id: Some(product.to_string()),
            purchase_token: Some(token.to_string()),
        };
        verify_store_purchase(&h.db, ps, &h.st, &h.apple, &h.play, user, &data, now)
            .await
            .expect("verified")
    }

    async fn release(
        h: &Harness,
        st: &ProtStoreSettings,
        admin: &str,
        id: &str,
        at: i64,
    ) -> Result<v0::ProtStoreAdminPurchase> {
        admin_release_store_purchase(&h.db, st, &h.apple, &h.play, admin, id, at).await
    }

    /// The row is held over the cap for staff: reason, work item, alert
    fn assert_over_cap_hold(row: &ProtStorePurchase) {
        assert_eq!(row.state, v0::ProtStoreState::Held, "{}", row.id);
        assert_eq!(
            row.hold_reason,
            Some(v0::ProtStoreHoldReason::OverCap),
            "{}",
            row.id
        );
        assert_eq!(
            row.needs_action.as_deref(),
            Some(PROT_STORE_NEEDS_OVER_CAP),
            "{}",
            row.id
        );
        assert!(
            row.alerted
                .iter()
                .any(|kind| kind == PROT_STORE_NEEDS_OVER_CAP),
            "{}",
            row.id
        );
        assert_eq!(row.credited_at, None, "{}", row.id);
    }

    /// An over-cap Apple hold of `P10` for `user`, whose wallet holds
    /// `balance` under a 3,000 cap; Apple answers the fresh lookup "bought"
    async fn apple_over_cap(h: &Harness, n: u64, user: &str, balance: i64) -> Tx {
        if balance > 0 {
            adjust(&h.db, user, &format!("r63-fill-{n}"), balance).await;
        }
        let intent = new_intent(h, user, v0::ProtStore::Apple, P10).await;
        let t = Tx {
            product: P10,
            ..tx(n, Some(&intent.token))
        };
        let response = verify_apple_under(h, &capped(h, 3000), &h.st, user, &t.jws(), NOW).await;
        assert_eq!(answer(&response), (Status::Pending, Some(Reason::OverCap)));
        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(t.jws()));
        assert_over_cap_hold(&stored(&h.db, &t.purchase_id()).await);
        t
    }

    /// A pause hold of `P10` for `user` (credits paused when it was seen);
    /// Apple answers the fresh lookup "bought"
    async fn pause_hold(
        h: &Harness,
        ps: &ProtSalesSettings,
        paused: &ProtStoreSettings,
        user: &str,
        n: u64,
    ) -> Tx {
        let intent = new_intent(h, user, v0::ProtStore::Apple, P10).await;
        let t = Tx {
            product: P10,
            ..tx(n, Some(&intent.token))
        };
        let response = verify_apple_under(h, ps, paused, user, &t.jws(), NOW).await;
        assert_eq!(answer(&response), (Status::Pending, None));
        let row = stored(&h.db, &t.purchase_id()).await;
        assert_eq!(row.hold_reason, Some(v0::ProtStoreHoldReason::Paused));
        assert_eq!(row.needs_action, None);
        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(t.jws()));
        t
    }

    /// An App Store notification handled under the Prot settings `ps`
    async fn notify_under(
        h: &Harness,
        ps: &ProtSalesSettings,
        kind: &str,
        transaction: &str,
        at: i64,
    ) -> AppleNotificationOutcome {
        let body = json!({ "signedPayload": notification_jws(kind, transaction, at) }).to_string();
        handle_apple_notification(&h.db, ps, &h.st, &h.apple, body.as_bytes(), at).await
    }

    /// R63 (control: drop the first-sight cap check). R62's residual: under a
    /// 3,000 cap, three 1,000-Prot intents are issued and cancelled (a
    /// cancelled intent still binds a late purchase) and a fourth is issued
    /// once they expired; a purchase lands on every token. Credits stop at the
    /// cap and the rest is held over it for staff (work item, alert), never
    /// credited; verify answers pending/over_cap, also when asked again
    /// under a roomier cap
    #[tokio::test]
    async fn issue_cancel_then_buy_lands_the_excess_in_hold() {
        let h = harness().await;
        let ps = capped(&h, 3000);

        let mut tokens = Vec::new();
        for _ in 0..3 {
            let intent = intent_with(&h, &ps, &h.st, A, v0::ProtStore::Apple, P10)
                .await
                .unwrap();
            cancel_store_intent(&h.db, A, &intent.intent_id)
                .await
                .unwrap();
            tokens.push(intent.token);
        }
        let later = NOW + PROT_STORE_INTENT_TTL_MS;
        let fourth = create_store_intent(
            &h.db,
            &h.s,
            &ps,
            &h.st,
            &h.play,
            &h.apple,
            A,
            &intent_data(v0::ProtStore::Apple, P10),
            None,
            later,
        )
        .await
        .expect("the cancelled intents expired");
        // The app buys on the live intent; the three cancelled ones bind the
        // late purchases that arrive after it
        tokens.insert(0, fourth.token);

        let at = later + MINUTE;
        let mut credited = Vec::new();
        let mut held = Vec::new();
        for (n, token) in tokens.iter().enumerate() {
            let t = Tx {
                product: P10,
                ..tx(110 + n as u64, Some(token))
            }
            .signed_at(at);
            let response = verify_apple_under(&h, &ps, &h.st, A, &t.jws(), at).await;
            match answer(&response) {
                (Status::Credited, None) => credited.push(t),
                (Status::Pending, Some(Reason::OverCap)) => {
                    assert_eq!(response.purchase_id, Some(t.purchase_id()));
                    held.push(t);
                }
                other => panic!("purchase {n}: {other:?}"),
            }
            assert!(
                balance(&h.db, A).await <= 3000,
                "purchase {n} took the wallet past the cap"
            );
        }
        assert_eq!((credited.len(), held.len()), (3, 1));
        assert_eq!(balance(&h.db, A).await, 3000);

        for t in &held {
            let id = t.purchase_id();
            assert_over_cap_hold(&stored(&h.db, &id).await);
            assert!(entry(&h.db, &prot_store_key_purchase(&id)).await.is_none());
            // Asked again, even where the wallet has room: still held
            h.apple
                .set_transaction_info(&t.transaction_id(), Ok(t.jws()));
            for again in [&ps, &h.ps] {
                let response = verify_apple_under(&h, again, &h.st, A, &t.jws(), at + HOUR).await;
                assert_eq!(answer(&response), (Status::Pending, Some(Reason::OverCap)));
            }
            assert_eq!(
                admin_store_purchase(&h.db, &id)
                    .await
                    .unwrap()
                    .purchase
                    .hold_reason,
                Some(v0::ProtStoreHoldReason::OverCap)
            );
        }
        assert_eq!(h.db.sum_held_prot_store(A).await.unwrap(), 1000);
        assert_eq!(balance(&h.db, A).await, 3000);
        assert_conserved(&h.db, &[A]).await;
        done(h).await;
    }

    /// R63 (control: let reconcile_held Unpause over-cap holds): a purchase
    /// held over the cap is not credited when credits run, not even once the
    /// wallet has room again; it is not even looked up, and its work item
    /// stays
    #[tokio::test]
    async fn over_cap_hold_is_not_credited_when_the_pause_ends() {
        let h = harness().await;
        let mut paused = h.st.clone();
        paused.credit_paused = true;
        let t = apple_over_cap(&h, 120, B, 2500).await;
        let id = t.purchase_id();
        // The wallet is spent: a credit would fit any cap now
        adjust(&h.db, B, "r63-spent", -2500).await;
        assert_eq!(balance(&h.db, B).await, 0);

        let before = stored(&h.db, &id).await;
        for (st, at) in [(&paused, NOW + HOUR), (&h.st, NOW + 2 * HOUR)] {
            let report = reconcile(&h, st, at).await;
            assert_eq!(report.held_credited, 0);
        }
        let after = stored(&h.db, &id).await;
        assert_eq!(after, before);
        assert_over_cap_hold(&after);
        assert_eq!(lookups(&h.apple, &t), 0);
        assert!(entry(&h.db, &prot_store_key_purchase(&id)).await.is_none());
        assert_eq!(balance(&h.db, B).await, 0);

        let response = verify_apple(&h, &h.st, B, &t.jws(), NOW + 3 * HOUR)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Pending, Some(Reason::OverCap)));
        assert_eq!(balance(&h.db, B).await, 0);
        assert_conserved(&h.db, &[B]).await;
        done(h).await;
    }

    /// R63: a purchase held while credits were paused is cap-checked when the
    /// pause ends: over the cap it becomes an over-cap hold (work item,
    /// alert) and nothing is credited; under it, it is credited as before
    #[tokio::test]
    async fn pause_hold_over_the_cap_becomes_over_cap_when_the_pause_ends() {
        let h = harness().await;
        let ps = capped(&h, 3000);
        let mut paused = h.st.clone();
        paused.credit_paused = true;

        let over = pause_hold(&h, &ps, &paused, C, 130).await;
        let under = pause_hold(&h, &ps, &paused, A, 131).await;
        // While paused, C's wallet filled up
        adjust(&h.db, C, "r63-filled", 2500).await;

        let report = reconcile_store(&h.db, &ps, &h.st, &h.apple, &h.play, NOW + HOUR).await;
        assert_eq!(report.held_credited, 1);

        let row = stored(&h.db, &over.purchase_id()).await;
        assert_over_cap_hold(&row);
        assert!(entry(&h.db, &prot_store_key_purchase(&over.purchase_id()))
            .await
            .is_none());
        assert_eq!(balance(&h.db, C).await, 2500);
        let response = verify_apple(&h, &h.st, C, &over.jws(), NOW + 2 * HOUR)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Pending, Some(Reason::OverCap)));

        let credited = stored(&h.db, &under.purchase_id()).await;
        assert_eq!(credited.state, v0::ProtStoreState::Credited);
        assert_eq!(credited.hold_reason, None);
        assert_eq!(balance(&h.db, A).await, 1000);

        // The next tick leaves the over-cap hold alone
        let report = reconcile_store(&h.db, &ps, &h.st, &h.apple, &h.play, NOW + 2 * HOUR).await;
        assert_eq!(report.held_credited, 0);
        assert_eq!(
            stored(&h.db, &over.purchase_id()).await.version,
            row.version
        );
        assert_conserved(&h.db, &[A, C]).await;
        done(h).await;
    }

    /// R63: staff release an over-cap Play hold: credited past the cap,
    /// consumed after the credit, the work item cleared; verify then answers
    /// already_credited and a second release is refused. Before it, the day
    /// alert covers the Play hold while credits run (Play refunds an
    /// unconsumed purchase after 3 days)
    #[tokio::test]
    async fn release_credits_an_over_cap_hold_and_consumes_play() {
        let h = harness().await;
        let ps = capped(&h, 3000);
        let token = "tok-r63-release";
        adjust(&h.db, B, "r63-play", 2500).await;
        let intent = new_intent(&h, B, v0::ProtStore::Play, P10).await;
        h.play.set_purchase(
            token,
            Ok(play_found(
                P10,
                Some(&intent.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        let response = verify_play_under(&h, &ps, B, P10, token, NOW).await;
        assert_eq!(answer(&response), (Status::Pending, Some(Reason::OverCap)));
        let id = play_purchase_id(token);
        let held = stored(&h.db, &id).await;
        assert_over_cap_hold(&held);
        assert_eq!(held.unconsumed, None);
        assert!(consumes(&h.play).is_empty());

        // A day on, with credits running: the Play day alert, the work item kept
        let report = reconcile_store(&h.db, &ps, &h.st, &h.apple, &h.play, NOW + 25 * HOUR).await;
        assert_eq!((report.alerts, report.held_credited), (1, 0));
        let flagged = stored(&h.db, &id).await;
        assert_over_cap_hold(&flagged);
        assert!(flagged
            .alerted
            .iter()
            .any(|kind| kind == PROT_STORE_NEEDS_HELD));
        assert!(consumes(&h.play).is_empty());

        let view = release(&h, &h.st, ADMIN, &id, NOW + 26 * HOUR)
            .await
            .unwrap();
        assert_eq!(view.purchase.state, v0::ProtStoreState::Credited);
        assert_eq!(view.purchase.hold_reason, None);
        assert_eq!(view.purchase.needs_action, None);
        assert_eq!(view.purchase.user_id.as_deref(), Some(B));
        assert_eq!(view.purchase.consumed, Some(true));
        assert_eq!(view.ledger.len(), 1, "{:?}", view.ledger);
        assert_eq!(view.ledger[0].amount, 1000);
        assert_eq!(view.unspent, Some(3500));
        assert_eq!(balance(&h.db, B).await, 3500);
        assert_eq!(
            consumes(&h.play),
            vec![format!("consume {P10} {}", sha256_hex(token))]
        );
        assert_eq!(stored(&h.db, &id).await.unconsumed, None);

        let response = verify_play_under(&h, &ps, B, P10, token, NOW + 27 * HOUR).await;
        assert_eq!(answer(&response), (Status::AlreadyCredited, None));
        assert!(matches!(
            error_of(release(&h, &h.st, ADMIN, &id, NOW + 28 * HOUR).await),
            ErrorType::InvalidOperation
        ));
        assert_eq!(balance(&h.db, B).await, 3500);
        assert_eq!(consumes(&h.play).len(), 1);
        assert_conserved(&h.db, &[B]).await;
        done(h).await;
    }

    /// R63: only an over-cap hold is released: a pause hold, a credited row
    /// and ids that name no purchase are refused before any store lookup
    #[tokio::test]
    async fn release_refuses_a_paused_hold_and_a_credited_row() {
        let h = harness().await;
        let mut paused = h.st.clone();
        paused.credit_paused = true;

        let intent = new_intent(&h, A, v0::ProtStore::Apple, P25).await;
        let pause_hold = tx(140, Some(&intent.token));
        let response = verify_apple(&h, &paused, A, &pause_hold.jws(), NOW)
            .await
            .unwrap();
        assert_eq!(answer(&response), (Status::Pending, None));
        h.apple
            .set_transaction_info(&pause_hold.transaction_id(), Ok(pause_hold.jws()));
        let before = stored(&h.db, &pause_hold.purchase_id()).await;
        assert!(matches!(
            error_of(release(&h, &h.st, ADMIN, &pause_hold.purchase_id(), NOW).await),
            ErrorType::InvalidOperation
        ));
        assert_eq!(stored(&h.db, &pause_hold.purchase_id()).await, before);
        assert_eq!(lookups(&h.apple, &pause_hold), 0);

        let credited = apple_credit(&h, 141).await;
        h.apple
            .set_transaction_info(&credited.transaction_id(), Ok(credited.jws()));
        assert!(matches!(
            error_of(release(&h, &h.st, ADMIN, &credited.purchase_id(), NOW).await),
            ErrorType::InvalidOperation
        ));
        assert_eq!(lookups(&h.apple, &credited), 0);
        assert_eq!(balance(&h.db, A).await, 2600);

        for id in ["01NOTASTOREID", "apple:prod:2000000000009999"] {
            assert!(matches!(
                error_of(release(&h, &h.st, ADMIN, id, NOW).await),
                ErrorType::NotFound
            ));
        }
        assert_conserved(&h.db, &[A]).await;
        done(h).await;
    }

    /// R63: never to the acting admin, a bot, a deleted or a missing account,
    /// and nothing while credits are paused; each refused before any lookup
    #[tokio::test]
    async fn release_refuses_self_bots_deleted_buyers_and_the_pause() {
        let h = harness().await;
        insert_account(
            &h.db,
            User {
                bot: Some(BotInformation {
                    owner: A.to_string(),
                }),
                ..user(BOT)
            },
        )
        .await;
        let gone = "01HZS6L2C00000000000GONE01";
        insert_account(
            &h.db,
            User {
                flags: Some(v0::UserFlags::Deleted as i32),
                ..user(gone)
            },
        )
        .await;

        let own = apple_over_cap(&h, 150, ADMIN, 2500).await;
        assert!(matches!(
            error_of(release(&h, &h.st, ADMIN, &own.purchase_id(), NOW).await),
            ErrorType::InvalidOperation
        ));

        // The same hold, as if its buyer were a bot, deleted, or missing
        let template = stored(&h.db, &own.purchase_id()).await;
        for (n, buyer) in [
            (151_u64, BOT),
            (152, gone),
            (153, "01HZS6L2C0000000000MISSING"),
        ] {
            let id = tx(n, None).purchase_id();
            put_row(
                &h.db,
                ProtStorePurchase {
                    id: id.clone(),
                    user_id: Some(buyer.to_string()),
                    ..template.clone()
                },
            )
            .await;
            assert!(matches!(
                error_of(release(&h, &h.st, A, &id, NOW).await),
                ErrorType::InvalidOperation
            ));
            assert_eq!(stored(&h.db, &id).await.state, v0::ProtStoreState::Held);
        }

        // Another admin may release the first hold, but not while paused
        let mut paused = h.st.clone();
        paused.credit_paused = true;
        assert!(matches!(
            error_of(release(&h, &paused, A, &own.purchase_id(), NOW).await),
            ErrorType::InvalidOperation
        ));
        assert_eq!(lookups(&h.apple, &own), 0);
        assert_over_cap_hold(&stored(&h.db, &own.purchase_id()).await);
        let view = release(&h, &h.st, A, &own.purchase_id(), NOW + HOUR)
            .await
            .unwrap();
        assert_eq!(view.purchase.state, v0::ProtStoreState::Credited);
        assert_eq!(balance(&h.db, ADMIN).await, 3500);
        done(h).await;
    }

    /// R63 (control: release without the fresh lookup): a held purchase the
    /// store shows refunded or voided is recorded Revoked by the release,
    /// which credits nothing and refuses; the hold and its review item go
    #[tokio::test]
    async fn release_of_a_revoked_purchase_credits_nothing() {
        let h = harness().await;
        let t = apple_over_cap(&h, 160, B, 2500).await;
        let id = t.purchase_id();
        h.apple.set_transaction_info(
            &t.transaction_id(),
            Ok(t.clone().revoked_at(NOW + HOUR).jws()),
        );
        assert!(matches!(
            error_of(release(&h, &h.st, ADMIN, &id, NOW + 2 * HOUR).await),
            ErrorType::InvalidOperation
        ));
        assert_eq!(lookups(&h.apple, &t), 1);
        let revoked = stored(&h.db, &id).await;
        assert_eq!(revoked.state, v0::ProtStoreState::Revoked);
        assert_eq!(
            (
                revoked.hold_reason,
                revoked.needs_action,
                revoked.refund_gen
            ),
            (None, None, 0)
        );
        assert!(entry(&h.db, &prot_store_key_purchase(&id)).await.is_none());
        assert!(entry(&h.db, &prot_store_key_clawback(&id, 1))
            .await
            .is_none());
        assert_eq!(balance(&h.db, B).await, 2500);
        assert!(matches!(
            error_of(release(&h, &h.st, ADMIN, &id, NOW + 3 * HOUR).await),
            ErrorType::InvalidOperation
        ));

        // Play: voided by the time staff release it
        let token = "tok-r63-voided";
        let intent = new_intent(&h, B, v0::ProtStore::Play, P10).await;
        h.play.set_purchase(
            token,
            Ok(play_found(
                P10,
                Some(&intent.token),
                PLAY_PURCHASE_STATE_PURCHASED,
            )),
        );
        let response = verify_play_under(&h, &capped(&h, 3000), B, P10, token, NOW).await;
        assert_eq!(answer(&response), (Status::Pending, Some(Reason::OverCap)));
        h.play.set_purchase(
            token,
            Ok(play_found(
                P10,
                Some(&intent.token),
                PLAY_PURCHASE_STATE_CANCELLED,
            )),
        );
        let play_id = play_purchase_id(token);
        assert!(matches!(
            error_of(release(&h, &h.st, ADMIN, &play_id, NOW + 2 * HOUR).await),
            ErrorType::InvalidOperation
        ));
        let voided = stored(&h.db, &play_id).await;
        assert_eq!(voided.state, v0::ProtStoreState::Revoked);
        assert_eq!((voided.hold_reason, voided.needs_action), (None, None));
        assert!(consumes(&h.play).is_empty());
        assert_eq!(balance(&h.db, B).await, 2500);
        assert_conserved(&h.db, &[B]).await;
        done(h).await;
    }

    /// R63: the cap binds automatic credits only. An E10 assign and the
    /// re-credit of a reversed refund land past it
    #[tokio::test]
    async fn reinstate_and_assign_are_exempt_from_the_cap() {
        let h = harness().await;
        let ps = capped(&h, 3000);

        // Assign: an unbound purchase to a wallet already at the cap
        adjust(&h.db, B, "r63-at-cap", 3000).await;
        let token = "tok-r63-assign";
        h.play.set_purchase(
            token,
            Ok(play_found(P10, None, PLAY_PURCHASE_STATE_PURCHASED)),
        );
        let response = verify_play_under(&h, &ps, A, P10, token, NOW).await;
        assert_eq!(answer(&response), (Status::Rejected, Some(Reason::Unbound)));
        let id = play_purchase_id(token);
        let view =
            admin_assign_store_purchase(&h.db, &ps, &h.st, &h.apple, &h.play, ADMIN, &id, B, NOW)
                .await
                .unwrap();
        assert_eq!(view.purchase.state, v0::ProtStoreState::Credited);
        assert_eq!(balance(&h.db, B).await, 4000);

        // Reinstate: a refund, then its reversal on a wallet at the cap
        let t = apple_credit(&h, 170).await;
        let refunded = t.clone().revoked_at(NOW + HOUR);
        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(refunded.jws()));
        assert_eq!(
            notify_under(&h, &ps, "REFUND", &refunded.jws(), NOW + 2 * HOUR).await,
            AppleNotificationOutcome::Handled
        );
        assert_eq!(balance(&h.db, A).await, 0);
        adjust(&h.db, A, "r63-refilled", 3000).await;
        h.apple
            .set_transaction_info(&t.transaction_id(), Ok(t.jws()));
        assert_eq!(
            notify_under(&h, &ps, "REFUND_REVERSED", &t.jws(), NOW + 3 * HOUR).await,
            AppleNotificationOutcome::Handled
        );
        assert_eq!(
            stored(&h.db, &t.purchase_id()).await.state,
            v0::ProtStoreState::Reinstated
        );
        assert_eq!(balance(&h.db, A).await, 5600);
        assert_conserved(&h.db, &[A, B]).await;
        done(h).await;
    }
}
