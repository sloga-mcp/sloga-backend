//! Provider-neutral order state machine: checkout, fulfil, reverse, expire
//!
//! Every order write happens under the order's lease: acquire it, mutate the
//! order the acquire returned, write it with `update_payment_order_if_state`
//! (fenced on state, version, lease and buyer), release it. A worker whose
//! lease ran out and was taken over can no longer write.
//!
//! Membership writes do NOT rely on the order lease (two orders of one user
//! hold different leases): every change is read → modify → compare-and-swap
//! on the membership version, retried a bounded number of times.
//!
//! Money rules this module keeps:
//! - prices come from [`crate::catalog`] only; the client names a tier
//! - a completed session is applied only when it matches the order exactly
//!   (session id, order id, amount, currency, livemode). A session that is
//!   not provably the order's (or not in our mode) is ignored; the order's
//!   own session paid in another amount or currency is refunded and the
//!   order voided (`AmountMismatch`)
//! - a resumed fulfil never refunds or re-numbers an order it already
//!   applied: the "already applied?" check runs before any precondition
//! - our own refunds use the idempotency key `void-{order_id}`, and a
//!   payment lost in a dispute is never refunded by us
//! - a void records its reason on the order before it refunds, so a worker
//!   that stops between the refund and the Voided write leaves the void to
//!   be finished, never the refunded order to be applied
//! - a reversal only touches a membership when the order is Fulfilled and
//!   listed in that membership, so the refund of a voided order is a no-op
//! - every open dispute is recorded on the order by its id
//!   (`open_disputes`) before and after fulfilment, and a close removes only
//!   its own id; fulfilment adds a disputed order to the membership already
//!   listed in `disputed_orders`, so its badge is never published
//! - a paid order is never refunded by us while a dispute on it is open:
//!   the void waits until the dispute is won (then refunds) or lost (then
//!   voids without a refund). The wait is durable (the order stays Paid)
//!   and the reconcile resume re-reads the disputes it waits on, so a close
//!   event that never arrives cannot strand it
//! - a refund or lost dispute recorded before fulfilment voids the order
//!   instead of applying it: no number is claimed and no badge published
//! - a full refund made within [`REFUND_RELEASE_WINDOW_MS`] (plus
//!   [`REFUND_GRACE_MS`]) of the refunded order's payment undoes it: the
//!   latest upgrade is rolled back to its `from` tier (the number is kept),
//!   a new purchase deletes the membership and puts its number back in the
//!   pool. A release is recorded on the number row before anything else,
//!   so any later reversal of the order or the reconcile sweep finishes
//!   it. Any other refund, and every lost dispute, revokes the membership
//!   and retires the number (see `window_refund_plan` for the exact rule)
//! - a refund is acted on only once Stripe reports it `succeeded`
//!   ([`RefundFacts::status`]): a pending refund can still fail. One seen
//!   still settling marks the order ([`mark_refund_settling`]), and the
//!   reconcile sweep re-reads its refunds until it has settled, so a lost
//!   update event never leaves it unapplied
//! - a release refunds every paid upgrade on the membership (idempotency
//!   key `release-upgrade-{order_id}`) and deletes the membership only once
//!   each of them is recorded Refunded, so the 14-day refund gives back the
//!   whole Cipher purchase. No new checkout is started while a release
//!   runs, a new purchase paid during one (a session opened before it) is
//!   voided and refunded at once (`ReleasePending`), and a dispute lost
//!   during one drops it (the number stays retired)
//! - Cipher is not sold to `cipher_blocked_countries` (the EU and the UK):
//!   checkout refuses a request Cloudflare places there (the route) and a
//!   buyer refunded for that reason in the last 30 days while that country
//!   is still blocked ([`REGION_REFUSAL_MS`]), and a payment whose billing
//!   country, or whose card's issuing country, is there is voided and
//!   refunded (`RegionUnavailable`) before any number is claimed. A card
//!   country Stripe permanently refuses to report is waited on for
//!   [`CARD_COUNTRY_WAIT_MS`] after payment, then the billing country alone
//!   decides (logged `CARD_COUNTRY_UNAVAILABLE`)

use revolt_database::{
    CipherMembership, CipherRevokeReason, Database, FieldsUser, OrderState, PartialUser,
    PaymentOrder, PaymentProvider, ReversalPending, User, VoidReason,
};
use revolt_models::v0::{
    CipherMe, CipherMembershipView, CipherPendingView, CipherReturnTo, CipherStats, CipherTier,
    Sku, UserFlags,
};
use revolt_result::{create_error, ErrorType, Result};
use ulid::Ulid;

use crate::catalog;
use crate::dispatch::{dispute_kind, refund_facts};
use crate::settings::PaymentsSettings;
use crate::stripe::{CheckoutSession, CheckoutSessionParams, StripeApi, StripeError};

/// How long a worker holds an order; longer than the worst-case chain of
/// Stripe calls (each has a 10 s timeout)
pub const LEASE_MS: i64 = 120_000;

/// Lifetime of a Stripe Checkout Session, from the order's creation
pub const SESSION_TTL_SECS: i64 = 35 * 60;

/// The buyer's no-questions refund period (14 days, the Terms): a FULL
/// refund of an order made within this long (plus [`REFUND_GRACE_MS`]) of
/// its payment is undone rather than punished. A refunded upgrade rolls the
/// membership back to its previous tier; a refunded new purchase puts its
/// Cipher number back in the pool. Measured from the refunded order's own
/// `paid_at` to when the refund was made ([`RefundFacts::refunded_at_ms`],
/// Stripe's `created` of the refund event, so a late or re-driven delivery
/// is judged by when the owner refunded, not when we processed it),
/// inclusive. A later or partial refund, or any lost dispute, revokes the
/// membership and retires the number for good.
pub const REFUND_RELEASE_WINDOW_MS: i64 = 14 * 24 * 3600 * 1000;

/// Operator grace on top of [`REFUND_RELEASE_WINDOW_MS`] (3 days). The
/// owner's runbook: a refund request received within the 14 days is
/// refunded from the Stripe Dashboard within 3 days of receiving it, so a
/// request made on day 14 still counts as made in time.
pub const REFUND_GRACE_MS: i64 = 3 * 24 * 3600 * 1000;

/// What the provider said about a refund (a Refund reversal only)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefundFacts {
    /// When the refund was made (epoch ms): Stripe's `created` of the
    /// refund, never later than the time it is processed
    pub refunded_at_ms: i64,
    /// Whether the charge is now refunded in full; only a full refund is
    /// undone (a partial one revokes and retires)
    pub full: bool,
    /// Where the refund stands. Only a `Succeeded` one reverses anything.
    pub status: RefundStatus,
}

/// Where a payment's refunds stand at Stripe
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundStatus {
    /// Every refund is settled and at least one `succeeded`: the money is
    /// back
    Succeeded,
    /// A refund is `pending` or `requires_action` (or in a status we do not
    /// know): it can still fail, so nothing is reversed yet
    Pending,
    /// Every refund `failed` or was `canceled`: no money went back
    Failed,
}

/// Bounded retries of a membership compare-and-swap
const MEMBERSHIP_RETRIES: usize = 5;

/// Bounded write-then-verify rounds of the public badge
const BADGE_SYNC_RETRIES: usize = 5;

/// A Creating order younger than this is a checkout request still in
/// flight, and blocks a second one; an older one was stranded by a crash
const CREATING_BLOCKS_MS: i64 = 2 * 60 * 1000;

/// Stripe's error code for refunding a charge that is already refunded
const CHARGE_ALREADY_REFUNDED: &str = "charge_already_refunded";

/// How long after its payment ([`PaymentOrder::paid_at`]) an order waits on
/// a card country Stripe permanently refuses to report (a key without the
/// permission, a request Stripe calls invalid, a response we cannot decode).
/// Until then the order stays Paid and is retried; after it, the billing
/// country alone decides, logged at error level as
/// `CARD_COUNTRY_UNAVAILABLE`. A transport error, a 5xx or a 429 is never
/// permanent: those keep the order waiting however long it takes.
pub const CARD_COUNTRY_WAIT_MS: i64 = 30 * 60 * 1000;

/// For how long after a `RegionUnavailable` void (its `reversed_at`, or
/// its `paid_at` while the void is still finishing) checkout refuses that
/// buyer, and only while the void's country is still blocked
pub const REGION_REFUSAL_MS: i64 = 30 * 24 * 3600 * 1000;

/// Result of [`fulfil_order`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FulfilOutcome {
    /// Applied now (or finished after a crash)
    Fulfilled,
    /// Already fulfilled earlier (a duplicate delivery)
    AlreadyFulfilled,
    /// Another worker holds the order; it finishes the job
    LeaseHeld,
    /// Paid but not applicable; the payment was refunded (or already was)
    Voided(VoidReason),
    /// Paid but not applicable, and a dispute on the payment is open: not
    /// refunded and not voided yet. The order stays Paid, which is durable:
    /// the reconcile resume re-reads its open disputes every sweep, and once
    /// they are won the void refunds, once one is lost the void goes ahead
    /// without a refund. The event that led here is settled.
    VoidDeferred(VoidReason),
    /// The session is ours but not paid
    NotPaid,
    /// The session does not match the order; nothing was changed
    Ignored,
}

/// A reversal reported by the provider.
///
/// `DisputeOpened` and `DisputeWon` always name the dispute they are about
/// (see [`reverse_dispute`]), because one payment can carry more than one
/// dispute; [`reverse_order`] refuses them. `DisputeLost` may come without
/// one: a lost dispute recorded before fulfilment is applied later from the
/// order's `reversal_pending`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReverseKind {
    /// The payment was refunded (in full or in part)
    Refund,
    /// A dispute was opened on the payment
    DisputeOpened,
    /// A dispute was closed in our favor (`won` or `warning_closed`)
    DisputeWon,
    /// A dispute was lost
    DisputeLost,
}

/// Result of [`reverse_order`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReverseOutcome {
    /// The membership (and the order) changed
    Applied,
    /// The order is not fulfilled yet; the reversal (or the dispute's
    /// status) is recorded on the order and fulfilment honours it
    RecordedPending,
    /// Nothing to do (voided or already reversed, or not applied to any
    /// membership)
    NoOp,
    /// Another worker holds the order; the caller retries later
    Busy,
}

/// An order held under its lease. `until` is the fencing token passed back
/// on release.
struct Leased {
    order: PaymentOrder,
    until: i64,
}

/// Take the lease on an order. Ok(None) when another worker holds it;
/// Err(NotFound) when there is no such order.
async fn acquire(db: &Database, order_id: &str, now_ms: i64) -> Result<Option<Leased>> {
    let until = now_ms.saturating_add(LEASE_MS);
    match db
        .acquire_payment_order_lease(order_id, now_ms, until)
        .await?
    {
        Some(order) => Ok(Some(Leased { order, until })),
        None => match db.fetch_payment_order(order_id).await? {
            Some(_) => Ok(None),
            None => Err(create_error!(NotFound)),
        },
    }
}

/// Release a lease we took. The release is fenced on `until`, so a lease
/// that was taken over is left alone; a failure only means the lease runs
/// out on its own.
async fn release(db: &Database, leased: &Leased) {
    if let Err(err) = db
        .release_payment_order_lease(&leased.order.id, leased.until)
        .await
    {
        log::warn!(
            "payments: could not release the lease on order {}: {err:?}",
            leased.order.id
        );
    }
}

/// Write the leased order with `change` applied, conditional on its current
/// state. On success the local copy carries the version the store now holds,
/// so a second write in the same lease is fenced correctly.
///
/// A refused write (lease taken over, buyer unlinked by an account deletion,
/// a concurrent version bump) is an error: the caller stops and the order is
/// picked up again under a fresh lease.
async fn write(
    db: &Database,
    leased: &mut Leased,
    change: impl FnOnce(&mut PaymentOrder),
) -> Result<()> {
    let expected = leased.order.state.clone();
    let mut next = leased.order.clone();
    change(&mut next);

    if db.update_payment_order_if_state(&next, expected).await? {
        next.version += 1;
        leased.order = next;
        return Ok(());
    }

    // Ok(false) does not say which check failed; read the order for the log
    let stored = db.fetch_payment_order(&next.id).await.ok().flatten();
    log::error!(
        "payments: write of order {} refused (state, version, lease or buyer moved); stored = {:?}",
        next.id,
        stored.map(|o| (o.state, o.version, o.lease_until, o.user_id.is_some()))
    );
    Err(create_error!(InternalError))
}

/// Idempotency key of our own refund of an order
fn void_key(order_id: &str) -> String {
    format!("void-{order_id}")
}

/// Idempotency key of our refund of an upgrade whose membership a release
/// deletes
fn release_upgrade_key(order_id: &str) -> String {
    format!("release-upgrade-{order_id}")
}

/// How a refund we asked Stripe for stands
enum RefundAsked {
    /// `succeeded`: the money is back
    Done,
    /// Stripe answered `charge_already_refunded`: the payment's refunds
    /// already add up to its amount, but one of them can still be settling
    /// (Stripe counts a `pending` refund too)
    AlreadyRefunded,
    /// Accepted but not settled (`pending`, `requires_action`, or no status)
    Unsettled { refund_id: String, status: String },
    /// Stripe reports it `failed` or `canceled`: nothing went back
    Refused { refund_id: String, status: String },
}

/// Ask Stripe to refund `payment_intent` in full under `key`. A payment
/// that is already refunded (`charge_already_refunded`) is
/// [`RefundAsked::AlreadyRefunded`].
/// Err (logged) when the call itself fails; the caller retries with the
/// same key.
async fn ask_refund(
    stripe: &dyn StripeApi,
    payment_intent: &str,
    key: &str,
    order_id: &str,
) -> Result<RefundAsked> {
    match stripe.create_refund(payment_intent, key).await {
        Ok(refund) => Ok(match refund.status.as_deref() {
            Some(status @ ("failed" | "canceled")) => RefundAsked::Refused {
                refund_id: refund.id,
                status: status.to_string(),
            },
            Some("succeeded") => RefundAsked::Done,
            status => RefundAsked::Unsettled {
                status: status.unwrap_or("of unknown status").to_string(),
                refund_id: refund.id,
            },
        }),
        Err(StripeError::Api {
            code: Some(code), ..
        }) if code == CHARGE_ALREADY_REFUNDED => {
            log::info!("payments: order {order_id} was already refunded at Stripe");
            Ok(RefundAsked::AlreadyRefunded)
        }
        Err(err) => {
            log::error!("payments: refund of order {order_id} failed: {err}");
            Err(create_error!(PaymentProviderError))
        }
    }
}

/// Refund `payment_intent` for an order we are voiding. Ok(true) once the
/// money is back or on its way; a payment that is already refunded counts
/// as done. Ok(false), logged, when Stripe reports the refund `failed` or
/// `canceled`: nothing went back, so the order is not voided and the caller
/// retries. Err when the call itself failed (its outcome is unknown).
///
/// Operator note: a refund Stripe reports `pending` (or `requires_action`)
/// is accepted and the order is voided, but the money has not moved yet.
/// A later `charge.refund.updated` on a Voided order changes nothing, so
/// every such refund is logged at error level ("refund ... is pending"); an
/// operator must check those refunds in the Stripe dashboard and refund by
/// hand any that end `failed`.
async fn refund_for_void(
    stripe: &dyn StripeApi,
    payment_intent: &str,
    order_id: &str,
) -> Result<bool> {
    match ask_refund(stripe, payment_intent, &void_key(order_id), order_id).await? {
        RefundAsked::Refused { refund_id, status } => {
            log::error!(
                "payments: refund {refund_id} of order {order_id} is {status}; the order stays \
                 unvoided"
            );
            Ok(false)
        }
        // Already refunded: the money is back or on its way, like a pending
        // refund of ours below
        RefundAsked::Done | RefundAsked::AlreadyRefunded => Ok(true),
        RefundAsked::Unsettled { refund_id, status } => {
            // Not settled yet (see the operator note above)
            log::error!(
                "payments: refund {refund_id} of order {order_id} is {status}; the order is \
                 voided, but the refund must be watched in the Stripe dashboard until it succeeds"
            );
            Ok(true)
        }
    }
}

/// Map a Stripe failure to the API error, logging it (StripeError text is
/// scrubbed of secrets by the client)
fn provider_error(context: &str, err: StripeError) -> revolt_result::Error {
    log::error!("payments: {context}: {err}");
    create_error!(PaymentProviderError)
}

/// Whether a failed read of a payment's charge is one retrying cannot fix
/// (see [`CARD_COUNTRY_WAIT_MS`]): a 4xx Stripe answers with
/// `permission_error` or `invalid_request_error` (never a 429), or a
/// response that does not decode (e.g. `latest_charge` not expanded).
/// A transport error, a 5xx, a 429 and any other 4xx are not.
fn card_country_unreadable(err: &StripeError) -> bool {
    match err {
        StripeError::Api { status, kind, .. } => {
            (400..500).contains(status)
                && *status != 429
                && matches!(
                    kind.as_deref(),
                    Some("permission_error" | "invalid_request_error")
                )
        }
        StripeError::Decode(_) => true,
        StripeError::Transport(_) => false,
    }
}

/// Whether the account has been deleted
fn is_deleted(user: &User) -> bool {
    user.flags.unwrap_or_default() & UserFlags::Deleted as i32 != 0
}

/// Whether `user_id` names an account that exists and is not deleted
/// (`User::mark_deleted` sets the Deleted flag). Any other read failure is
/// an error, so the caller retries rather than guessing.
async fn buyer_is_live(db: &Database, user_id: &str) -> Result<bool> {
    match db.fetch_user(user_id).await {
        Ok(user) => Ok(!is_deleted(&user)),
        Err(err) if matches!(err.error_type, ErrorType::NotFound) => Ok(false),
        Err(err) => Err(err),
    }
}

fn pending_kind(pending: &ReversalPending) -> ReverseKind {
    match pending {
        ReversalPending::Refund => ReverseKind::Refund,
        ReversalPending::DisputeLost => ReverseKind::DisputeLost,
    }
}

/// Whether the order belongs in its membership's `disputed_orders`: a
/// dispute on its payment is open, or a lost one is still to be applied
/// (the lost dispute's id is gone from `open_disputes`, but the badge must
/// stay hidden until the reversal revokes the membership)
fn is_disputed(order: &PaymentOrder) -> bool {
    !order.open_disputes.is_empty() || order.reversal_pending == Some(ReversalPending::DisputeLost)
}

/// The order's open disputes once `kind` on `dispute` is applied: an opened
/// dispute adds its id (once), a won or lost one removes only its own id.
/// A kind without a dispute id changes nothing.
fn disputes_after(order: &PaymentOrder, kind: ReverseKind, dispute: Option<&str>) -> Vec<String> {
    let mut open = order.open_disputes.clone();
    match (kind, dispute) {
        (ReverseKind::DisputeOpened, Some(id)) => {
            if !open.iter().any(|known| known == id) {
                open.push(id.to_string());
            }
        }
        (ReverseKind::DisputeWon | ReverseKind::DisputeLost, Some(id)) => {
            open.retain(|known| known != id)
        }
        _ => {}
    }
    open
}

/// Why a completed session cannot be applied to its order
#[derive(Debug)]
enum SessionMismatch {
    /// Not provably the order's own session (another session or order,
    /// another payment or buyer, or the other livemode): nothing about it
    /// is ours to settle, so it is ignored
    NotOurs(String),
    /// The order's own session (its stored id, or none stored, and our
    /// metadata naming this order) in our mode, but in another amount or
    /// currency; names the field that differs
    Terms(&'static str),
}

/// Why a completed session cannot be applied to this order, if it cannot.
/// The session is what Stripe reports (a signed event or an API read).
/// Every identity check runs before the amount and currency, so a `Terms`
/// mismatch is only ever reported for the order's own session.
fn session_mismatch(
    order: &PaymentOrder,
    session: &CheckoutSession,
    s: &PaymentsSettings,
) -> Option<SessionMismatch> {
    use SessionMismatch::{NotOurs, Terms};

    match &order.checkout_session_id {
        Some(id) if *id != session.id => {
            return Some(NotOurs(format!(
                "session {} is not the order's session {id}",
                session.id
            )))
        }
        Some(_) => {}
        // The session id was never stored (a crash between Stripe's answer
        // and the Pending write): bind on the order id we put in metadata
        None if session.metadata_order_id.as_deref() != Some(order.id.as_str()) => {
            return Some(NotOurs(format!(
                "order has no stored session and session {} names another order",
                session.id
            )))
        }
        None => {}
    }

    if let Some(named) = &session.metadata_order_id {
        if *named != order.id {
            return Some(NotOurs(format!("session metadata names order {named}")));
        }
    }

    if session.livemode != s.expect_livemode {
        return Some(NotOurs(format!(
            "session livemode {} but expect_livemode {}",
            session.livemode, s.expect_livemode
        )));
    }

    if let (Some(stored), Some(reported)) = (&order.payment_intent_id, &session.payment_intent) {
        if stored != reported {
            return Some(NotOurs(format!(
                "session payment intent {reported} but the order is paid by {stored}"
            )));
        }
    }

    if let (Some(user_id), Some(reference)) = (&order.user_id, &session.client_reference_id) {
        if user_id != reference {
            return Some(NotOurs(
                "session client_reference_id names another user".to_string(),
            ));
        }
    }

    let field = if session.amount_total != Some(order.amount_cents) {
        "amount"
    } else if order.currency != "usd"
        || session.currency.as_deref() != Some(order.currency.as_str())
    {
        "currency"
    } else {
        return None;
    };

    // Ours only when our own metadata names the order: a session without
    // it is never settled on its id alone
    if session.metadata_order_id.as_deref() == Some(order.id.as_str()) {
        Some(Terms(field))
    } else {
        Some(NotOurs(format!(
            "session {} has the wrong {field} and no metadata naming the order",
            session.id
        )))
    }
}

// ---------------------------------------------------------------------------
// Checkout
// ---------------------------------------------------------------------------

/// Whether `order` is a `RegionUnavailable` void that still keeps its buyer
/// out of checkout: its country is on the current list, and it was voided
/// (or, still finishing, paid) less than [`REGION_REFUSAL_MS`] ago. A void
/// recorded before its country was kept blocks nothing.
fn region_refusal_holds(s: &PaymentsSettings, order: &PaymentOrder, now_ms: i64) -> bool {
    order.void_reason == Some(VoidReason::RegionUnavailable)
        && order
            .region_blocked_country
            .as_deref()
            .is_some_and(|country| s.region_blocked(country))
        && order
            .reversed_at
            .or(order.paid_at)
            .is_some_and(|at| now_ms.saturating_sub(at) < REGION_REFUSAL_MS)
}

/// Checkout: enabled + sales_open_at(now); quote(); refuse upgrade while
/// disputed; one live Pending order per user (unexpired → return its stored
/// checkout_url); Creating → create session (idempotency key = order id) →
/// Pending, or SessionFailed + Err(PaymentProviderError).
///
/// The amount is taken from the catalog and nothing else. A live Pending
/// order for the same SKU returns its URL; one for a different SKU (or a
/// checkout request still in flight) is `PaymentPending`, so a buyer never
/// holds two payable sessions at once.
pub async fn create_cipher_checkout(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    user_id: &str,
    tier: CipherTier,
    return_to: CipherReturnTo,
    now_ms: i64,
) -> Result<String> {
    if !s.enabled {
        return Err(create_error!(PaymentsDisabled));
    }

    if !s.sales_open_at(now_ms) {
        return Err(create_error!(CipherSalesClosed));
    }

    // A buyer recently refunded because the payment came from a country
    // Cipher is not sold to gets no new checkout while that country is
    // still blocked: each one would be paid, voided and refunded again, at
    // a Stripe fee each time. A void of that kind still finishing (Paid,
    // the reason recorded) counts too. Not with an empty list (nothing is
    // blocked), and not for long: see `region_refusal_holds`.
    if !s.blocked_countries.is_empty()
        && db
            .fetch_payment_orders_by_user(user_id, &[OrderState::Voided, OrderState::Paid])
            .await?
            .iter()
            .any(|o| region_refusal_holds(s, o, now_ms))
    {
        return Err(create_error!(CipherRegionUnavailable));
    }

    let row = db.fetch_cipher_membership(user_id).await?;
    // The release of the buyer's number is still running (its upgrades are
    // being refunded): no new order until it has finished, so a purchase
    // never lands next to the row being released
    if let Some(m) = &row {
        if number_release_pending(db, m).await? {
            return Err(create_error!(PaymentPending));
        }
    }
    let membership = row.filter(CipherMembership::is_active);
    let sku = catalog::quote(membership.as_ref().map(|m| m.tier), tier)?;

    match &sku {
        Sku::CipherUpgrade { .. } => {
            // An upgrade while a payment is under dispute would be voided
            // at fulfilment anyway; refuse it before the buyer pays
            if membership
                .as_ref()
                .is_some_and(|m| !m.disputed_orders.is_empty())
            {
                return Err(create_error!(CipherTierInvalid));
            }
        }
        Sku::CipherNew { .. } => {
            // Advisory: a race past this check is voided SoldOut at fulfilment
            if db.count_claimed_cipher_numbers().await? >= s.cap {
                return Err(create_error!(CipherSoldOut));
            }
        }
    }

    // One live order per user. SessionFailed, Expired and stale Creating
    // orders never block.
    let live = db
        .fetch_payment_orders_by_user(user_id, &[OrderState::Creating, OrderState::Pending])
        .await?;
    for order in live.iter().rev() {
        match order.state {
            OrderState::Pending if order.session_expires_at.is_some_and(|at| at > now_ms) => {
                return match &order.checkout_url {
                    Some(url) if order.sku == sku => Ok(url.clone()),
                    _ => Err(create_error!(PaymentPending)),
                };
            }
            OrderState::Creating
                if now_ms.saturating_sub(order.created_at) < CREATING_BLOCKS_MS =>
            {
                return Err(create_error!(PaymentPending));
            }
            _ => {}
        }
    }

    let order = PaymentOrder {
        id: Ulid::new().to_string(),
        user_id: Some(user_id.to_string()),
        provider: PaymentProvider::Stripe,
        amount_cents: catalog::sku_cents(&sku)?,
        sku,
        currency: "usd".to_string(),
        checkout_session_id: None,
        checkout_url: None,
        session_expires_at: None,
        payment_intent_id: None,
        state: OrderState::Creating,
        void_reason: None,
        region_blocked_country: None,
        reversal_pending: None,
        refund_settling_since: None,
        open_disputes: vec![],
        lease_until: None,
        version: 0,
        created_at: now_ms,
        paid_at: None,
        fulfilled_at: None,
        reversed_at: None,
    };
    db.insert_payment_order(&order).await?;

    let Some(mut leased) = acquire(db, &order.id, now_ms).await? else {
        // Nobody else knows this order id yet
        log::error!("payments: lease on new order {} was already held", order.id);
        return Err(create_error!(InternalError));
    };
    let result = start_session(db, stripe, s, &mut leased, return_to).await;
    release(db, &leased).await;
    result
}

/// Create the Stripe session for a leased Creating order and move it to
/// Pending (or SessionFailed)
async fn start_session(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    leased: &mut Leased,
    return_to: CipherReturnTo,
) -> Result<String> {
    let order = &leased.order;
    let Some(user_id) = order.user_id.clone() else {
        return Err(create_error!(InternalError));
    };

    // Derived from the stored order, so a retry sends identical params
    let expires_at_secs = order.created_at.div_euclid(1000) + SESSION_TTL_SECS;
    let (success_url, cancel_url) = match return_to {
        CipherReturnTo::Web => (s.success_url_web.clone(), s.cancel_url_web.clone()),
        CipherReturnTo::Shell => (s.success_url_shell.clone(), s.cancel_url_shell.clone()),
    };
    let params = CheckoutSessionParams {
        order_id: order.id.clone(),
        user_id,
        amount_cents: order.amount_cents,
        currency: order.currency.clone(),
        product_name: catalog::sku_product_name(&order.sku),
        success_url,
        cancel_url,
        expires_at_secs,
        automatic_tax: s.automatic_tax,
    };
    let order_id = order.id.clone();

    let problem = match stripe.create_checkout_session(&params, &order_id).await {
        Ok(session) => match &session.url {
            // A session in the wrong mode would complete into events we
            // ignore: the buyer would pay and get nothing. Fail closed.
            Some(_) if session.livemode != s.expect_livemode => format!(
                "session {} has livemode {} but expect_livemode is {}",
                session.id, session.livemode, s.expect_livemode
            ),
            Some(_)
                if session
                    .amount_total
                    .is_some_and(|a| a != params.amount_cents) =>
            {
                format!(
                    "session {} amount {:?} differs from the order amount {}",
                    session.id, session.amount_total, params.amount_cents
                )
            }
            Some(url) => {
                let url = url.clone();
                let expires_ms = session
                    .expires_at
                    .unwrap_or(expires_at_secs)
                    .saturating_mul(1000);
                let session_id = session.id.clone();
                let stored_url = url.clone();
                write(db, leased, move |o| {
                    o.state = OrderState::Pending;
                    o.checkout_session_id = Some(session_id);
                    o.checkout_url = Some(stored_url);
                    o.session_expires_at = Some(expires_ms);
                })
                .await?;
                return Ok(url);
            }
            None => format!("session {} has no url", session.id),
        },
        Err(err) => format!("{err}"),
    };

    log::error!("payments: checkout session for order {order_id} failed: {problem}");
    if let Err(err) = write(db, leased, |o| o.state = OrderState::SessionFailed).await {
        // Left Creating: the reconcile sweep expires it
        log::error!("payments: could not mark order {order_id} SessionFailed: {err:?}");
    }
    Err(create_error!(PaymentProviderError))
}

// ---------------------------------------------------------------------------
// Fulfil
// ---------------------------------------------------------------------------

/// Plan "Fulfil" steps 1–7 given the completed session as Stripe reports it.
pub async fn fulfil_order(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    order_id: &str,
    session: &CheckoutSession,
    now_ms: i64,
) -> Result<FulfilOutcome> {
    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        return Ok(FulfilOutcome::LeaseHeld);
    };
    let outcome = fulfil_locked(db, stripe, s, &mut leased, session, now_ms).await;
    release(db, &leased).await;
    outcome
}

/// Resume a Paid (not Fulfilled) order: re-fetch the session via stripe,
/// re-read the disputes it still lists as open, then fulfil it. Also
/// finishes a Fulfilled order's recorded reversal.
pub async fn resume_order(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    order_id: &str,
    now_ms: i64,
) -> Result<FulfilOutcome> {
    // Read only to find the session; every write happens under the lease
    let order = db
        .fetch_payment_order(order_id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    let Some(session_id) = order.checkout_session_id else {
        log::error!("payments: cannot resume order {order_id}: no checkout session");
        return Err(create_error!(InternalError));
    };

    let session = stripe
        .get_checkout_session(&session_id)
        .await
        .map_err(|err| provider_error(&format!("fetching session of order {order_id}"), err))?;

    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        return Ok(FulfilOutcome::LeaseHeld);
    };
    let outcome = resume_locked(db, stripe, s, &mut leased, &session, now_ms).await;
    release(db, &leased).await;
    outcome
}

/// [`resume_order`] under the lease. A Paid order that lists open disputes
/// is usually a void waiting on them ([`FulfilOutcome::VoidDeferred`]):
/// their close event may never come (or came while the order ignored it),
/// so where they are now is read first. A failed read fails closed: the
/// disputes stay open as recorded and the next sweep reads them again.
async fn resume_locked(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    leased: &mut Leased,
    session: &CheckoutSession,
    now_ms: i64,
) -> Result<FulfilOutcome> {
    if leased.order.state == OrderState::Paid && !leased.order.open_disputes.is_empty() {
        if let Err(err) = recheck_open_disputes(db, stripe, s, leased, now_ms).await {
            log::warn!(
                "payments: could not re-read the open disputes of order {}; resuming with them \
                 as recorded: {err:?}",
                leased.order.id
            );
        }
    }

    fulfil_locked(db, stripe, s, leased, session, now_ms).await
}

/// Whether a membership step finished or the order has to be voided
enum Applied {
    Done,
    Void(VoidReason),
}

async fn fulfil_locked(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    leased: &mut Leased,
    session: &CheckoutSession,
    now_ms: i64,
) -> Result<FulfilOutcome> {
    match leased.order.state {
        OrderState::Fulfilled => {
            // A duplicate delivery, or a resume after the final write
            finish_fulfilled(db, stripe, leased, now_ms).await?;
            return Ok(FulfilOutcome::AlreadyFulfilled);
        }
        OrderState::Refunded => return Ok(FulfilOutcome::AlreadyFulfilled),
        OrderState::Voided => {
            return void_late_payment(db, stripe, s, leased, session, now_ms).await
        }
        OrderState::Creating
        | OrderState::Pending
        | OrderState::SessionFailed
        | OrderState::Expired
        | OrderState::Paid => {}
    }

    let wrong_terms = match session_mismatch(&leased.order, session, s) {
        None => None,
        Some(SessionMismatch::NotOurs(why)) => {
            log::warn!(
                "payments: ignoring session {} for order {}: {why}",
                session.id,
                leased.order.id
            );
            return Ok(FulfilOutcome::Ignored);
        }
        Some(SessionMismatch::Terms(field)) => Some(field),
    };

    if session.payment_status.as_deref() != Some("paid") {
        if let Some(field) = wrong_terms {
            // Nothing was taken, so there is nothing to settle
            log::warn!(
                "payments: ignoring unpaid session {} for order {}: wrong {field}",
                session.id,
                leased.order.id
            );
            return Ok(FulfilOutcome::Ignored);
        }
        return Ok(FulfilOutcome::NotPaid);
    }

    let Some(payment_intent) = session.payment_intent.clone() else {
        // A paid payment-mode session always has one, whichever Dashboard
        // method paid it; without it nothing can be refunded, so leave the
        // event to be retried and looked at
        log::error!(
            "payments: paid session {} of order {} has no payment intent",
            session.id,
            leased.order.id
        );
        return Err(create_error!(PaymentProviderError));
    };

    // 1. Pending → Paid
    if leased.order.state != OrderState::Paid {
        let session_id = session.id.clone();
        let paid_by = payment_intent.clone();
        write(db, leased, move |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some(paid_by);
            o.paid_at = Some(now_ms);
            if o.checkout_session_id.is_none() {
                o.checkout_session_id = Some(session_id);
            }
        })
        .await?;
    }

    // Our own session, paid, but not what the order costs: the buyer is
    // refunded and nothing is granted
    if let Some(field) = wrong_terms {
        log::error!(
            "payments: session {} of order {} was paid by {payment_intent} with the wrong {field}; \
             voiding and refunding it",
            session.id,
            leased.order.id
        );
        return void_paid(db, stripe, leased, VoidReason::AmountMismatch, now_ms).await;
    }

    // Voided before it was paid, then paid with a dispute on record (see
    // `void_late_payment`): it is never applied, whatever the buyer's
    // account looks like now; the void finishes once the disputes allow
    if let Some(reason) = leased.order.void_reason.clone() {
        return void_paid(db, stripe, leased, reason, now_ms).await;
    }

    // The buyer deleted their account before fulfilment. Our session names
    // them, which finds a membership a fulfilment racing the deletion left.
    let Some(user_id) = leased.order.user_id.clone() else {
        let buyer = session.client_reference_id.clone();
        return void_for_deleted_account(db, stripe, leased, buyer.as_deref(), now_ms).await;
    };

    // Still linked, but the account is deleted (or gone): the deletion's
    // payments cascade failed or never ran. Exactly like an unlinked buyer:
    // voided and refunded, nothing granted.
    if !buyer_is_live(db, &user_id).await? {
        log::warn!(
            "payments: order {} is still linked to deleted account {user_id}; voiding it",
            leased.order.id
        );
        return void_for_deleted_account(db, stripe, leased, Some(&user_id), now_ms).await;
    }

    // 2. Already applied? (a resume after a crash must neither refund nor
    //    re-number, so this runs before the preconditions)
    let membership = db.fetch_cipher_membership(&user_id).await?;
    let applied = membership
        .as_ref()
        .is_some_and(|m| m.orders.contains(&leased.order.id));

    if applied {
        // Applied by a worker that crashed. The order's disputes are the
        // truth: every dispute event since was recorded on the order first.
        set_dispute_listing(db, &user_id, &leased.order.id, is_disputed(&leased.order)).await?;
    } else {
        // Not sold to the buyer's billing country: refunded, no number
        // claimed. No country reported (a session completed without the
        // billing address) is fulfilled; checkout requires the address, so
        // that is logged for a look.
        match session.billing_country.as_deref() {
            Some(country) if s.region_blocked(country) => {
                log::warn!(
                    "payments: order {} was paid from billing country {country}, where Cipher \
                     is not sold; voiding and refunding it",
                    leased.order.id
                );
                let country = country.to_string();
                return void_for_region(db, stripe, leased, country, now_ms).await;
            }
            Some(_) => {}
            None => log::warn!(
                "payments: session {} of order {} reports no billing country; fulfilling it",
                session.id,
                leased.order.id
            ),
        }

        // Nor to a card issued there, whatever billing address was typed
        // in (Apple Pay, Google Pay and Link included). Any other method,
        // or a card Stripe reports no country for, is judged on the billing
        // country alone. A failed read is an error: nothing is claimed, and
        // the event (or the reconcile resume) tries again. Only a failure
        // that retrying cannot fix, still there [`CARD_COUNTRY_WAIT_MS`]
        // after the payment, lets the billing country decide alone.
        if !s.blocked_countries.is_empty() {
            match stripe.get_payment_charge(&payment_intent).await {
                Ok(charge) => {
                    if let Some(country) = charge
                        .card_country
                        .filter(|country| s.region_blocked(country))
                    {
                        log::warn!(
                            "payments: order {} was paid with a card issued in {country}, where \
                             Cipher is not sold; voiding and refunding it",
                            leased.order.id
                        );
                        return void_for_region(db, stripe, leased, country, now_ms).await;
                    }
                }
                Err(err)
                    if card_country_unreadable(&err)
                        && leased
                            .order
                            .paid_at
                            .is_some_and(|at| now_ms.saturating_sub(at) > CARD_COUNTRY_WAIT_MS) =>
                {
                    log::error!(
                        "payments: CARD_COUNTRY_UNAVAILABLE order {}: the card country of its \
                         payment still cannot be read ({err}); fulfilling it on its billing \
                         country alone",
                        leased.order.id
                    );
                }
                Err(err) => {
                    return Err(provider_error(
                        &format!("reading the charge of order {}", leased.order.id),
                        err,
                    ))
                }
            }
        }

        // A new purchase paid while the release of the buyer's old number
        // is still running would replace that row, and the upgrades on it
        // not refunded yet would go with it. Checkout refuses to start one
        // then, so only a session opened before the release reaches this:
        // it is voided and refunded at once rather than holding the money
        // for as long as the release takes
        if matches!(leased.order.sku, Sku::CipherNew { .. }) {
            if let Some(m) = &membership {
                if number_release_pending(db, m).await? {
                    log::warn!(
                        "payments: order {} was paid while the release of number {} of \
                         {user_id} is still running; voiding and refunding it",
                        leased.order.id,
                        m.number
                    );
                    return void_paid(db, stripe, leased, VoidReason::ReleasePending, now_ms).await;
                }
            }
        }

        // 3. Preconditions
        if let Some(reason) = precondition_failure(s, &leased.order, membership.as_ref()) {
            return void_paid(db, stripe, leased, reason, now_ms).await;
        }

        // A refund or a lost dispute arrived before the order was applied:
        // the money is (partly) gone, so nothing is granted. No number is
        // claimed and no badge is published; the void refunds what is left
        // of a refund, and nothing at all after a lost dispute.
        if let Some(pending) = &leased.order.reversal_pending {
            log::warn!(
                "payments: order {} has a {pending:?} recorded before it was applied; voiding \
                 it instead of applying it",
                leased.order.id
            );
            return void_paid(db, stripe, leased, VoidReason::Reversed, now_ms).await;
        }

        // 4. + 5. Number and membership
        if let Applied::Void(reason) =
            apply_membership(db, s, &leased.order, &user_id, now_ms).await?
        {
            return void_paid(db, stripe, leased, reason, now_ms).await;
        }
    }

    // 6. Public badge, only if the order is still ours as we read it
    publish_badge(db, leased, &user_id).await?;

    // 7. Fulfilled, then any reversal that arrived first
    write(db, leased, move |o| {
        o.state = OrderState::Fulfilled;
        o.fulfilled_at = Some(now_ms);
    })
    .await?;

    // A recorded reversal names no dispute: a lost dispute's id already
    // left `open_disputes` when it was recorded
    if let Some(pending) = leased.order.reversal_pending.clone() {
        reverse_locked(
            db,
            stripe,
            leased,
            pending_kind(&pending),
            None,
            None,
            now_ms,
        )
        .await?;
    }

    Ok(FulfilOutcome::Fulfilled)
}

/// Fulfil step 6: publish the badge from the membership, but only while
/// the lease still holds and nobody wrote the order since this worker read
/// it.
///
/// The membership step used the leased copy of the order. A worker that
/// stalled past its lease can have written the membership after a dispute
/// handler (holding the lease it took over) recorded a dispute on the order
/// and found the order not in the membership yet; that membership then
/// lacks the listing, and publishing from it would show the badge during
/// the dispute. So first a write fenced on the lease and the version: if it
/// is refused, the stored order decides. When it is disputed, the order is
/// listed in the membership; either way nothing is published here, and the
/// error leaves the order to the next holder (a retried event or the
/// reconcile resume), which publishes from the corrected membership.
async fn publish_badge(db: &Database, leased: &mut Leased, user_id: &str) -> Result<()> {
    if let Err(err) = write(db, leased, |_| {}).await {
        let order_id = leased.order.id.clone();
        match db.fetch_payment_order(&order_id).await {
            Ok(Some(stored)) if is_disputed(&stored) => {
                if let Err(list_err) = set_dispute_listing(db, user_id, &order_id, true).await {
                    log::error!(
                        "payments: could not list disputed order {order_id} after losing its \
                         lease: {list_err:?}"
                    );
                }
            }
            Ok(_) => {}
            Err(read_err) => log::error!(
                "payments: could not re-read order {order_id} after losing its lease: {read_err:?}"
            ),
        }
        return Err(err);
    }

    sync_user_badge(db, user_id).await
}

/// A Fulfilled order seen again: re-assert the badge and apply a reversal
/// recorded before a crash
async fn finish_fulfilled(
    db: &Database,
    stripe: &dyn StripeApi,
    leased: &mut Leased,
    now_ms: i64,
) -> Result<()> {
    if let Some(user_id) = leased.order.user_id.clone() {
        // Only ever adds the listing (fails closed): clearing it is the
        // job of the dispute's own won/closed event
        if is_disputed(&leased.order) {
            set_dispute_listing(db, &user_id, &leased.order.id, true).await?;
        }
        sync_user_badge(db, &user_id).await?;
    }

    // As in fulfil: a recorded reversal names no dispute
    if let Some(pending) = leased.order.reversal_pending.clone() {
        reverse_locked(
            db,
            stripe,
            leased,
            pending_kind(&pending),
            None,
            None,
            now_ms,
        )
        .await?;
    }

    Ok(())
}

/// A completed session for a Voided order. An order voided before it was
/// paid (account deletion while the session was open) is refunded now;
/// one voided after payment was refunded then.
///
/// Unless a dispute on the payment is recorded: refunding then could pay
/// the buyer twice. The order goes back to Paid, keeping its void reason
/// (so it is never applied), and the void runs from there: it refunds once
/// every dispute is won, never once one is lost, and waits in between
/// ([`FulfilOutcome::VoidDeferred`]), where the reconcile resume re-reads
/// the disputes every sweep.
async fn void_late_payment(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    leased: &mut Leased,
    session: &CheckoutSession,
    now_ms: i64,
) -> Result<FulfilOutcome> {
    let reason = leased
        .order
        .void_reason
        .clone()
        .unwrap_or(VoidReason::Stale);

    if leased.order.payment_intent_id.is_some() {
        return Ok(FulfilOutcome::Voided(reason));
    }

    // The order's own session paid in the wrong amount or currency is
    // refunded like any other late payment of a voided order
    if let Some(SessionMismatch::NotOurs(why)) = session_mismatch(&leased.order, session, s) {
        log::warn!(
            "payments: ignoring session {} for voided order {}: {why}",
            session.id,
            leased.order.id
        );
        return Ok(FulfilOutcome::Ignored);
    }

    if session.payment_status.as_deref() != Some("paid") {
        return Ok(FulfilOutcome::Voided(reason));
    }

    let Some(payment_intent) = session.payment_intent.clone() else {
        log::error!(
            "payments: paid session {} of voided order {} has no payment intent",
            session.id,
            leased.order.id
        );
        return Err(create_error!(PaymentProviderError));
    };

    if is_disputed(&leased.order) {
        log::warn!(
            "payments: voided order {} was paid with a dispute on record; not refunding until \
             the dispute is settled",
            leased.order.id
        );
        let session_id = session.id.clone();
        write(db, leased, move |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some(payment_intent);
            o.paid_at = Some(now_ms);
            if o.checkout_session_id.is_none() {
                o.checkout_session_id = Some(session_id);
            }
        })
        .await?;

        // Disputes on a Voided order were not followed: read where they
        // are now before deciding (a failed read fails closed)
        if let Err(err) = recheck_open_disputes(db, stripe, s, leased, now_ms).await {
            log::warn!(
                "payments: could not re-read the open disputes of order {}: {err:?}",
                leased.order.id
            );
        }
        return void_paid(db, stripe, leased, reason, now_ms).await;
    }

    if !refund_for_void(stripe, &payment_intent, &leased.order.id).await? {
        return Err(create_error!(PaymentProviderError));
    }
    let session_id = session.id.clone();
    write(db, leased, move |o| {
        o.payment_intent_id = Some(payment_intent);
        o.paid_at = Some(now_ms);
        if o.checkout_session_id.is_none() {
            o.checkout_session_id = Some(session_id);
        }
    })
    .await?;

    Ok(FulfilOutcome::Voided(reason))
}

/// Whether a refund decided to release the number of membership `m` and
/// the release has not finished (the row of the purchase that holds the
/// number carries `release_pending_at`)
async fn number_release_pending(db: &Database, m: &CipherMembership) -> Result<bool> {
    for order_id in &m.orders {
        if let Some(row) = db.fetch_cipher_number_row_by_order(order_id).await? {
            if row.number == m.number && row.release_pending_at.is_some() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Plan Fulfil step 3: why a paid order no longer applies, if it does not.
/// The sale close is judged on when the order was created, not now.
fn precondition_failure(
    s: &PaymentsSettings,
    order: &PaymentOrder,
    membership: Option<&CipherMembership>,
) -> Option<VoidReason> {
    if s.close_at_ms.is_some_and(|close| order.created_at >= close) {
        return Some(VoidReason::SalesClosed);
    }

    match &order.sku {
        // A revoked row does not block a new purchase (it is replaced)
        Sku::CipherNew { .. } => membership
            .filter(|m| m.is_active())
            .map(|_| VoidReason::Stale),
        Sku::CipherUpgrade { from, .. } => match membership {
            Some(m) if m.is_active() && m.tier == *from => {
                (!m.disputed_orders.is_empty()).then_some(VoidReason::DisputeOpen)
            }
            _ => Some(VoidReason::Stale),
        },
    }
}

/// Plan Fulfil steps 4 and 5: the number (new purchases only) and the
/// membership write, re-checking the preconditions against every re-read
async fn apply_membership(
    db: &Database,
    s: &PaymentsSettings,
    order: &PaymentOrder,
    user_id: &str,
    now_ms: i64,
) -> Result<Applied> {
    match &order.sku {
        Sku::CipherNew { tier } => {
            let number = match db.fetch_cipher_number_by_order(&order.id).await? {
                Some(number) => number,
                None => {
                    // Read again right before claiming: a membership another
                    // order of this buyer made active since the preconditions
                    // were checked makes this one Stale, and no number is
                    // retired for it
                    if db
                        .fetch_cipher_membership(user_id)
                        .await?
                        .is_some_and(|m| m.is_active() && !m.orders.contains(&order.id))
                    {
                        return Ok(Applied::Void(VoidReason::Stale));
                    }

                    match db.claim_cipher_number(&order.id, s.cap).await? {
                        Some(number) => number,
                        None => {
                            // Sold out only if the table was seeded to the
                            // cap; an empty or short table is a deployment
                            // error
                            let seeded = db.count_cipher_numbers().await?;
                            if seeded < s.cap {
                                log::error!(
                                    "payments: cipher_numbers holds {seeded} rows, fewer than \
                                     cipher_cap {}; not selling order {} as sold out",
                                    s.cap,
                                    order.id
                                );
                                return Err(create_error!(InternalError));
                            }
                            return Ok(Applied::Void(VoidReason::SoldOut));
                        }
                    }
                }
            };

            // A dispute opened before fulfilment is listed in the same write
            // that adds the order, so no badge is published for it
            let fresh = CipherMembership {
                user_id: user_id.to_string(),
                number,
                tier: *tier,
                prot_grant: catalog::tier_prot(*tier),
                orders: vec![order.id.clone()],
                disputed_orders: if is_disputed(order) {
                    vec![order.id.clone()]
                } else {
                    vec![]
                },
                granted_at: now_ms,
                revoked_at: None,
                revoke_reason: None,
                prot_posted_at: None,
                version: 0,
            };

            for _ in 0..MEMBERSHIP_RETRIES {
                if db.insert_cipher_membership(&fresh).await? {
                    return Ok(Applied::Done);
                }

                match db.fetch_cipher_membership(user_id).await? {
                    // Deleted in between: insert again
                    None => {}
                    Some(m) if m.orders.contains(&order.id) => return Ok(Applied::Done),
                    // Another order made the user a member meanwhile; the
                    // number just claimed stays retired
                    Some(m) if m.is_active() => return Ok(Applied::Void(VoidReason::Stale)),
                    // A revoked row: replaced by the fresh membership with
                    // the new number (the old number stays retired)
                    Some(m) => {
                        if db
                            .update_cipher_membership_if_version(&fresh, m.version)
                            .await?
                        {
                            return Ok(Applied::Done);
                        }
                    }
                }
            }

            log::error!(
                "payments: membership of order {} did not settle after {MEMBERSHIP_RETRIES} tries",
                order.id
            );
            Err(create_error!(InternalError))
        }
        Sku::CipherUpgrade { from, to } => {
            for _ in 0..MEMBERSHIP_RETRIES {
                let Some(m) = db.fetch_cipher_membership(user_id).await? else {
                    return Ok(Applied::Void(VoidReason::Stale));
                };
                if m.orders.contains(&order.id) {
                    return Ok(Applied::Done);
                }
                if !m.is_active() || m.tier != *from {
                    return Ok(Applied::Void(VoidReason::Stale));
                }
                if !m.disputed_orders.is_empty() {
                    return Ok(Applied::Void(VoidReason::DisputeOpen));
                }

                // The membership's own payments are undisputed (checked
                // above); an upgrade whose payment is disputed still applies
                // and keeps the number, listed as disputed in this same
                // write, so the badge stays hidden until the dispute is won
                let mut next = m.clone();
                next.tier = *to;
                next.prot_grant = catalog::tier_prot(*to);
                next.orders.push(order.id.clone());
                if is_disputed(order) {
                    next.disputed_orders.push(order.id.clone());
                }
                if db
                    .update_cipher_membership_if_version(&next, m.version)
                    .await?
                {
                    return Ok(Applied::Done);
                }
            }

            log::error!(
                "payments: upgrade of order {} did not settle after {MEMBERSHIP_RETRIES} tries",
                order.id
            );
            Err(create_error!(InternalError))
        }
    }
}

/// Void a Paid order: refund it (unless a dispute on it was lost), then
/// record Voided with `reason`
///
/// A recorded owner refund does not skip ours: it may have been partial,
/// and when nothing is left Stripe answers `charge_already_refunded`, which
/// counts as done. A lost dispute already took the money back.
///
/// While a dispute on the payment is open nothing is refunded or written:
/// a refund then could pay the buyer twice if the dispute is lost. The
/// order stays Paid and the outcome is [`FulfilOutcome::VoidDeferred`]; a
/// later attempt refunds once the dispute is won, or voids without a refund
/// once it is lost.
async fn void_paid(
    db: &Database,
    stripe: &dyn StripeApi,
    leased: &mut Leased,
    reason: VoidReason,
    now_ms: i64,
) -> Result<FulfilOutcome> {
    let lost = leased.order.reversal_pending == Some(ReversalPending::DisputeLost);
    if !lost && !leased.order.open_disputes.is_empty() {
        log::warn!(
            "payments: order {} is to be voided ({reason:?}), but {} dispute(s) on its payment \
             are open; not refunding until they close",
            leased.order.id,
            leased.order.open_disputes.len()
        );
        return Ok(FulfilOutcome::VoidDeferred(reason));
    }

    if !lost {
        let Some(payment_intent) = leased.order.payment_intent_id.clone() else {
            log::error!(
                "payments: cannot refund order {}: no payment intent",
                leased.order.id
            );
            return Err(create_error!(InternalError));
        };

        // The reason goes on the order before the refund. A worker that
        // stops after Stripe refunded, before the Voided write below, leaves
        // the order Paid with its reason, and the next attempt finishes this
        // void (fulfilment reads `void_reason` first) instead of judging the
        // order again, maybe once what voided it is gone (a release that
        // has finished since), and applying a refunded payment.
        let previous = leased.order.void_reason.clone();
        let marked_now = previous.as_ref() != Some(&reason);
        if marked_now {
            let marked = reason.clone();
            write(db, leased, move |o| o.void_reason = Some(marked)).await?;
        }
        if !refund_for_void(stripe, &payment_intent, &leased.order.id).await? {
            // Refused: no money moved, so nothing is committed yet; the next
            // attempt judges the order afresh
            if marked_now {
                write(db, leased, move |o| o.void_reason = previous).await?;
            }
            return Err(create_error!(PaymentProviderError));
        }
    }

    let stored_reason = reason.clone();
    write(db, leased, move |o| {
        o.state = OrderState::Voided;
        o.void_reason = Some(stored_reason);
        o.reversed_at = Some(now_ms);
        o.reversal_pending = None;
    })
    .await?;

    log::info!("payments: order {} voided ({reason:?})", leased.order.id);
    Ok(FulfilOutcome::Voided(reason))
}

/// Void a Paid order of a deleted account (AccountDeleted). A fulfilment
/// that held the lease while the account was deleted can have written the
/// membership after the deletion removed it; a membership of `buyer` that
/// lists this order is deleted here. Only a row listing this order is
/// touched, so a wrong `buyer` deletes nothing.
async fn void_for_deleted_account(
    db: &Database,
    stripe: &dyn StripeApi,
    leased: &mut Leased,
    buyer: Option<&str>,
    now_ms: i64,
) -> Result<FulfilOutcome> {
    if let Some(user_id) = buyer {
        let holds_order = db
            .fetch_cipher_membership(user_id)
            .await?
            .is_some_and(|m| m.orders.contains(&leased.order.id));
        if holds_order {
            db.delete_cipher_membership(user_id).await?;
            log::warn!(
                "payments: deleted the membership of deleted account {user_id}, which order {} \
                 was applied to after the deletion",
                leased.order.id
            );
        }
    }

    void_paid(db, stripe, leased, VoidReason::AccountDeleted, now_ms).await
}

/// Void a Paid order from `country`, where Cipher is not sold
/// (RegionUnavailable). The country goes on the order with the reason:
/// every write of [`void_paid`] (the reason's mark before the refund, then
/// Voided) carries it, so checkout refuses the buyer only while it is still
/// blocked (`region_refusal_holds`).
async fn void_for_region(
    db: &Database,
    stripe: &dyn StripeApi,
    leased: &mut Leased,
    country: String,
    now_ms: i64,
) -> Result<FulfilOutcome> {
    leased.order.region_blocked_country = Some(country);
    void_paid(db, stripe, leased, VoidReason::RegionUnavailable, now_ms).await
}

/// List `order_id` in the membership's `disputed_orders` when `open`, or
/// take it out when not, if the membership holds that order.
/// Compare-and-swap on the membership version, retried a bounded number of
/// times; nothing is written when the listing already matches.
/// Ok(true) when the membership holds the order.
async fn set_dispute_listing(
    db: &Database,
    user_id: &str,
    order_id: &str,
    open: bool,
) -> Result<bool> {
    for _ in 0..MEMBERSHIP_RETRIES {
        let Some(m) = db.fetch_cipher_membership(user_id).await? else {
            return Ok(false);
        };
        if !m.orders.iter().any(|id| id == order_id) {
            return Ok(false);
        }
        if m.disputed_orders.iter().any(|id| id == order_id) == open {
            return Ok(true);
        }

        let mut next = m.clone();
        if open {
            next.disputed_orders.push(order_id.to_string());
        } else {
            next.disputed_orders.retain(|id| id != order_id);
        }
        if db
            .update_cipher_membership_if_version(&next, m.version)
            .await?
        {
            return Ok(true);
        }
    }

    log::error!(
        "payments: dispute listing of order {order_id} did not settle after {MEMBERSHIP_RETRIES} tries"
    );
    Err(create_error!(InternalError))
}

// ---------------------------------------------------------------------------
// Reverse
// ---------------------------------------------------------------------------

/// Apply a refund, or a lost dispute recorded on the order earlier, to an
/// order. Acts on a membership only when the order is Fulfilled and listed
/// in that membership. A full refund made inside the release window rolls
/// an upgrade back or releases a new purchase's number instead of revoking
/// (see `window_refund_plan`); `refund` is what the provider said about the
/// refund (None: nothing known, so it revokes and retires as before). A
/// refund that has not `succeeded` changes nothing (`NoOp`): it can still
/// fail, and every reversal it would cause is irreversible.
///
/// An opened or won dispute is refused (`InternalError`): it must name its
/// dispute, so it goes through [`reverse_dispute`].
pub async fn reverse_order(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    order_id: &str,
    kind: ReverseKind,
    refund: Option<RefundFacts>,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    // Reversals never read the sale settings. Stripe is called only by a
    // number release, to refund the upgrades on the membership it deletes.
    let _ = s;

    if let Some(facts) = refund.filter(|facts| facts.status != RefundStatus::Succeeded) {
        log::warn!(
            "payments: refund of order {order_id} is {:?}; nothing is reversed until it succeeds",
            facts.status
        );
        return Ok(ReverseOutcome::NoOp);
    }

    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        return Ok(ReverseOutcome::Busy);
    };
    let mut outcome = reverse_locked(db, stripe, &mut leased, kind, None, refund, now_ms).await;
    // The refund succeeded and is acted on: the reconcile sweep stops
    // re-reading it ([`mark_refund_settling`])
    if kind == ReverseKind::Refund && leased.order.refund_settling_since.is_some() {
        if let Ok(done) = outcome {
            outcome = write(db, &mut leased, |o| o.refund_settling_since = None)
                .await
                .map(|()| done);
        }
    }
    release(db, &leased).await;
    outcome
}

/// A refund of the order's payment is still settling at the provider: mark
/// the order (`refund_settling_since`, the first time seen kept), so the
/// reconcile sweep re-reads its refunds until it has succeeded (then it is
/// reversed through [`reverse_order`], which clears the mark) or failed
/// (then [`clear_refund_settling`]). An order already Voided or Refunded is
/// not marked (`NoOp`): a refund changes nothing there. `RecordedPending`
/// when marked (now or before), `Busy` when another worker holds the order.
pub async fn mark_refund_settling(
    db: &Database,
    order_id: &str,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        return Ok(ReverseOutcome::Busy);
    };
    let result = if matches!(
        leased.order.state,
        OrderState::Voided | OrderState::Refunded
    ) {
        Ok(ReverseOutcome::NoOp)
    } else if leased.order.refund_settling_since.is_some() {
        Ok(ReverseOutcome::RecordedPending)
    } else {
        write(db, &mut leased, move |o| {
            o.refund_settling_since = Some(now_ms)
        })
        .await
        .map(|()| ReverseOutcome::RecordedPending)
    };
    release(db, &leased).await;
    result
}

/// Every refund of the order's payment failed or was canceled: clear its
/// [`mark_refund_settling`] mark, nothing reversed. `NoOp` once clear (or
/// when it was), `Busy` when another worker holds the order.
pub async fn clear_refund_settling(
    db: &Database,
    order_id: &str,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        return Ok(ReverseOutcome::Busy);
    };
    let result = if leased.order.refund_settling_since.is_some() {
        write(db, &mut leased, |o| o.refund_settling_since = None)
            .await
            .map(|()| ReverseOutcome::NoOp)
    } else {
        Ok(ReverseOutcome::NoOp)
    };
    release(db, &leased).await;
    result
}

/// Apply a dispute as Stripe reports it now. The dispute is read INSIDE the
/// order's lease, so of two deliveries handled one after the other the
/// later one always applies the newer status. The dispute must be on this
/// order's payment; a failed or inconsistent lookup is an error (the caller
/// retries), never a guess.
pub async fn reverse_dispute(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    order_id: &str,
    dispute_id: &str,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        return Ok(ReverseOutcome::Busy);
    };
    let outcome = match current_dispute_kind(stripe, s, &leased.order, dispute_id).await {
        Ok(kind) => {
            reverse_locked(
                db,
                stripe,
                &mut leased,
                kind,
                Some(dispute_id),
                None,
                now_ms,
            )
            .await
        }
        Err(err) => Err(err),
    };
    release(db, &leased).await;
    outcome
}

/// Re-read every dispute the leased order still lists as open and apply
/// where it is now, under the caller's lease: a won or lost dispute whose
/// close event never arrived (or arrived while the order was in a state
/// that ignores it) is applied here, so it can neither hide a badge nor
/// hold back a deferred void for good. Stops once the order is Voided or
/// Refunded (a lost dispute on a Fulfilled order refunds it). A failed or
/// inconsistent lookup is an error, and the disputes not read yet stay as
/// recorded (fail closed).
async fn recheck_open_disputes(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    leased: &mut Leased,
    now_ms: i64,
) -> Result<()> {
    for dispute_id in leased.order.open_disputes.clone() {
        if matches!(
            leased.order.state,
            OrderState::Voided | OrderState::Refunded
        ) {
            break;
        }
        let kind = current_dispute_kind(stripe, s, &leased.order, &dispute_id).await?;
        reverse_locked(db, stripe, leased, kind, Some(&dispute_id), None, now_ms).await?;
    }
    Ok(())
}

/// The reconcile sweep's check of an order that lists open disputes (a
/// Fulfilled one; Paid ones are re-read by [`resume_order`]): see
/// `recheck_open_disputes`. `Applied` when the order changed (a dispute
/// closed, the order reversed), `NoOp` when every dispute is still open,
/// `Busy` when another worker holds the order.
pub async fn recheck_disputes(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    order_id: &str,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        return Ok(ReverseOutcome::Busy);
    };
    let (state_before, open_before) = (
        leased.order.state.clone(),
        leased.order.open_disputes.clone(),
    );
    let result = recheck_open_disputes(db, stripe, s, &mut leased, now_ms).await;
    release(db, &leased).await;
    result?;

    let changed = leased.order.state != state_before || leased.order.open_disputes != open_before;
    Ok(if changed {
        ReverseOutcome::Applied
    } else {
        ReverseOutcome::NoOp
    })
}

/// The reversal a dispute's current status calls for, once the dispute is
/// shown to be on `order`'s payment
async fn current_dispute_kind(
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    order: &PaymentOrder,
    dispute_id: &str,
) -> Result<ReverseKind> {
    let dispute = stripe.get_dispute(dispute_id).await.map_err(|err| {
        provider_error(
            &format!("fetching dispute {dispute_id} of order {}", order.id),
            err,
        )
    })?;
    if dispute.id != dispute_id {
        log::error!(
            "payments: asked for dispute {dispute_id} of order {}, got {}",
            order.id,
            dispute.id
        );
        return Err(create_error!(PaymentProviderError));
    }
    let Some(disputed) = dispute.payment_intent.as_deref() else {
        log::error!(
            "payments: dispute {dispute_id} of order {} names no payment",
            order.id
        );
        return Err(create_error!(PaymentProviderError));
    };

    match order.payment_intent_id.as_deref() {
        Some(paid_by) if paid_by == disputed => {}
        Some(paid_by) => {
            log::error!(
                "payments: dispute {dispute_id} is on {disputed}, but order {} was paid by {paid_by}",
                order.id
            );
            return Err(create_error!(PaymentProviderError));
        }
        // Not marked paid on our side yet: the disputed payment must name
        // this order in the metadata we set at checkout
        None => {
            let intent = stripe.get_payment_intent(disputed).await.map_err(|err| {
                provider_error(
                    &format!("fetching the payment of dispute {dispute_id}"),
                    err,
                )
            })?;
            if intent.id != disputed
                || intent.livemode != s.expect_livemode
                || intent.metadata_order_id.as_deref() != Some(order.id.as_str())
            {
                log::error!(
                    "payments: dispute {dispute_id} is on {disputed}, which is not order {}'s payment",
                    order.id
                );
                return Err(create_error!(PaymentProviderError));
            }
        }
    }

    Ok(dispute_kind(dispute.status.as_deref()))
}

/// [`reverse_order`] on an order whose lease the caller already holds
/// (fulfil applies a recorded reversal this way; leases are not re-entrant).
/// `dispute` names the dispute an opened, won or lost status is about; an
/// opened or won one without it is refused, so a dispute is never opened
/// or closed by anything but its own id. `refund` is only read for a
/// Refund.
async fn reverse_locked(
    db: &Database,
    stripe: &dyn StripeApi,
    leased: &mut Leased,
    kind: ReverseKind,
    dispute: Option<&str>,
    refund: Option<RefundFacts>,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    if dispute.is_none() && matches!(kind, ReverseKind::DisputeOpened | ReverseKind::DisputeWon) {
        log::error!(
            "payments: {kind:?} on order {} names no dispute; refused",
            leased.order.id
        );
        return Err(create_error!(InternalError));
    }

    match leased.order.state {
        OrderState::Refunded if kind == ReverseKind::DisputeLost => {
            dispute_lost_after_refund(db, leased).await
        }
        // Includes the charge.refunded of our own void refund
        OrderState::Voided | OrderState::Refunded => Ok(ReverseOutcome::NoOp),
        // Not fulfilled (yet). Expired is included: a session paid after the
        // order expired is still fulfilled, and must honour what came first.
        OrderState::Creating
        | OrderState::Pending
        | OrderState::SessionFailed
        | OrderState::Expired
        | OrderState::Paid => record_before_fulfilment(db, leased, kind, dispute).await,
        OrderState::Fulfilled => {
            reverse_fulfilled(db, stripe, leased, kind, dispute, refund, now_ms).await
        }
    }
}

/// A dispute lost on an order already Refunded (refunded in part, or after
/// its window, so its membership was revoked for the refund): the revoke
/// reason becomes `DisputeLost`, so a later full refund of the purchase
/// inside its window never puts the number back in the pool (a lost
/// dispute always retires it, see `window_refund_plan`). Only a membership
/// that lists the order and is revoked for a refund is changed.
async fn dispute_lost_after_refund(db: &Database, leased: &mut Leased) -> Result<ReverseOutcome> {
    let Some(user_id) = leased.order.user_id.clone() else {
        return Ok(ReverseOutcome::NoOp);
    };
    let order_id = &leased.order.id;
    for _ in 0..MEMBERSHIP_RETRIES {
        let Some(m) = db.fetch_cipher_membership(&user_id).await? else {
            return Ok(ReverseOutcome::NoOp);
        };
        if !m.orders.contains(order_id) || m.revoke_reason != Some(CipherRevokeReason::Refund) {
            return Ok(ReverseOutcome::NoOp);
        }

        let mut next = m.clone();
        next.revoke_reason = Some(CipherRevokeReason::DisputeLost);
        if db
            .update_cipher_membership_if_version(&next, m.version)
            .await?
        {
            log::info!(
                "payments: dispute lost on refunded order {order_id}; the membership of \
                 {user_id} is now revoked for it and number {} stays retired",
                m.number
            );
            return Ok(ReverseOutcome::Applied);
        }
    }

    log::error!(
        "payments: lost dispute on refunded order {order_id} did not settle after \
         {MEMBERSHIP_RETRIES} tries"
    );
    Err(create_error!(InternalError))
}

/// A reversal or dispute status for an order that is not fulfilled yet:
/// recorded on the order, under the lease. Fulfilment lists a disputed
/// order as disputed in the write that adds it to the membership, and
/// applies a recorded reversal as its last step.
async fn record_before_fulfilment(
    db: &Database,
    leased: &mut Leased,
    kind: ReverseKind,
    dispute: Option<&str>,
) -> Result<ReverseOutcome> {
    let order = &leased.order;
    let pending = match kind {
        ReverseKind::Refund => order
            .reversal_pending
            .clone()
            .or(Some(ReversalPending::Refund)),
        // A lost dispute outranks a recorded refund (the money is already
        // gone, so we must not refund it). Its id leaves `open_disputes`,
        // but the pending lost reversal keeps the order listed as disputed
        // until it revokes the membership, so no badge is published in
        // between (see `is_disputed`)
        ReverseKind::DisputeLost => Some(ReversalPending::DisputeLost),
        ReverseKind::DisputeOpened | ReverseKind::DisputeWon => order.reversal_pending.clone(),
    };
    let open = disputes_after(order, kind, dispute);

    if pending != order.reversal_pending || open != order.open_disputes {
        write(db, leased, move |o| {
            o.reversal_pending = pending;
            o.open_disputes = open;
        })
        .await?;
    }

    // A worker that died after its membership write (the order is still
    // Paid) may already have published the badge: mirror the disputes into
    // that membership now rather than at the resume
    if let Some(user_id) = leased.order.user_id.clone() {
        let listed = is_disputed(&leased.order);
        if set_dispute_listing(db, &user_id, &leased.order.id, listed).await? {
            sync_user_badge(db, &user_id).await?;
        }
    }
    Ok(ReverseOutcome::RecordedPending)
}

async fn reverse_fulfilled(
    db: &Database,
    stripe: &dyn StripeApi,
    leased: &mut Leased,
    kind: ReverseKind,
    dispute: Option<&str>,
    refund: Option<RefundFacts>,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    // The order records the dispute first: if the membership write below
    // fails, the event is retried, and a redelivered completion re-adds the
    // listing from the order (it never clears one). It also comes before
    // the release below, so a dispute opened while a release is pending is
    // kept, and keeps the number retired (`finish_number_release_locked`).
    let open = disputes_after(&leased.order, kind, dispute);
    if open != leased.order.open_disputes {
        write(db, leased, move |o| o.open_disputes = open).await?;
    }

    // A lost dispute always retires the number (the refund rule), even one
    // first seen already lost while a release a refund decided is still
    // pending: that release is dropped, and the dispute is applied below
    // like any other (revoked for it, the order Refunded)
    if kind == ReverseKind::DisputeLost {
        drop_release_for_lost_dispute(db, leased).await?;
    }

    // A release a refund decided earlier and did not finish (a crash, a
    // failed write, an upgrade refund still settling) is finished first,
    // whatever else this reversal is, so it never leaves the number held
    // by a revoked row
    // Boxed (here and below): the release adds several awaits to every
    // reversal, and inline they deepen the poll stack enough to overflow
    // a 2 MiB thread in debug builds.
    if let Some(outcome) =
        Box::pin(finish_number_release_locked(db, stripe, leased, now_ms)).await?
    {
        return Ok(outcome);
    }

    // Unlinked by an account deletion: the membership is gone with it
    let Some(user_id) = leased.order.user_id.clone() else {
        return no_membership_to_reverse(db, leased).await;
    };
    let order_id = leased.order.id.clone();

    // A full refund inside the window is undone instead (rolled back, or
    // the number released); None falls through to revoke + retire
    if kind == ReverseKind::Refund {
        if let Some(outcome) = Box::pin(refund_within_window(
            db, stripe, leased, &user_id, refund, now_ms,
        ))
        .await?
        {
            return Ok(outcome);
        }
    }

    // Another dispute on the same payment can still be open after this one
    // closes: the order stays listed until the last one does. A lost
    // dispute being applied now no longer counts (it revokes below).
    let listed = match kind {
        ReverseKind::DisputeLost => !leased.order.open_disputes.is_empty(),
        _ => is_disputed(&leased.order),
    };

    let mut settled = false;
    for _ in 0..MEMBERSHIP_RETRIES {
        let Some(m) = db.fetch_cipher_membership(&user_id).await? else {
            return unlisted_reversal(db, leased, kind, &user_id, now_ms).await;
        };
        if !m.orders.contains(&order_id) {
            log::warn!(
                "payments: {kind:?} on order {order_id}, which is not part of the membership; \
                 no membership change"
            );
            return unlisted_reversal(db, leased, kind, &user_id, now_ms).await;
        }

        let mut next = m.clone();
        if matches!(kind, ReverseKind::Refund | ReverseKind::DisputeLost) && next.is_active() {
            next.revoked_at = Some(now_ms);
            next.revoke_reason = Some(match kind {
                ReverseKind::Refund => CipherRevokeReason::Refund,
                _ => CipherRevokeReason::DisputeLost,
            });
        }
        // A lost dispute on a row a refund revoked already is recorded too,
        // so a later refund inside the window never releases its number
        if kind == ReverseKind::DisputeLost
            && next.revoke_reason == Some(CipherRevokeReason::Refund)
        {
            next.revoke_reason = Some(CipherRevokeReason::DisputeLost);
        }
        // A refund leaves the listing as the disputes left it
        if kind != ReverseKind::Refund {
            let was_listed = next.disputed_orders.contains(&order_id);
            if listed && !was_listed {
                next.disputed_orders.push(order_id.clone());
            } else if !listed && was_listed {
                next.disputed_orders.retain(|id| *id != order_id);
            }
        }

        if next == m
            || db
                .update_cipher_membership_if_version(&next, m.version)
                .await?
        {
            settled = true;
            break;
        }
    }

    if !settled {
        log::error!(
            "payments: {kind:?} on order {order_id} did not settle after {MEMBERSHIP_RETRIES} tries"
        );
        return Err(create_error!(InternalError));
    }

    sync_user_badge(db, &user_id).await?;

    if matches!(kind, ReverseKind::Refund | ReverseKind::DisputeLost) {
        write(db, leased, move |o| {
            o.state = OrderState::Refunded;
            o.reversed_at = Some(now_ms);
            o.reversal_pending = None;
        })
        .await?;
        log::info!("payments: order {order_id} reversed ({kind:?}); membership revoked");
    }

    Ok(ReverseOutcome::Applied)
}

/// A reversal of a Fulfilled order that no membership lists (deleted with
/// the account, or replaced after a revoke): nothing to change, but a
/// recorded reversal is cleared so the reconcile sweep stops resuming it
async fn no_membership_to_reverse(db: &Database, leased: &mut Leased) -> Result<ReverseOutcome> {
    if leased.order.reversal_pending.is_some() {
        write(db, leased, |o| o.reversal_pending = None).await?;
    }
    Ok(ReverseOutcome::NoOp)
}

/// A refund or lost dispute of a Fulfilled order of a live buyer whose
/// membership does not list the order: the membership is gone (a refund
/// inside the window deleted it to release its number), or holds the order
/// no more (an upgrade rolled back by its refund, or a row replaced by a
/// new purchase after a revoke). No membership changes, but the money went
/// back, so the order is recorded Refunded; this is also how a reversal
/// that stopped after its membership write (a crash, a failed write) is
/// finished when the event is delivered again. Any other kind only clears
/// a recorded reversal.
async fn unlisted_reversal(
    db: &Database,
    leased: &mut Leased,
    kind: ReverseKind,
    user_id: &str,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    if !matches!(kind, ReverseKind::Refund | ReverseKind::DisputeLost) {
        return no_membership_to_reverse(db, leased).await;
    }

    sync_user_badge(db, user_id).await?;
    write(db, leased, move |o| {
        o.state = OrderState::Refunded;
        o.reversed_at = Some(now_ms);
        o.reversal_pending = None;
    })
    .await?;
    log::info!(
        "payments: order {} reversed ({kind:?}); no membership lists it",
        leased.order.id
    );
    Ok(ReverseOutcome::NoOp)
}

/// What a full refund inside the release window does instead of revoking
/// the membership
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowRefund {
    /// Roll the membership back to the upgrade's `from` tier
    Downgrade { from: CipherTier },
    /// Delete the membership and put its number back in the pool
    Release,
    /// An upgrade with another one stacked on top: the membership is left
    /// as it is and only the order is recorded Refunded (manual handling)
    RefundOnly,
}

/// The refund rule (owner decision 2026-10-18; the Terms promise a full
/// refund within 14 days). For a Refund of `order`, a Fulfilled order
/// listed in membership `m`, with what the provider said about it:
///
/// - Nothing known about the refund, or a partial refund: None, i.e.
///   revoke + retire as before (a partial refund is logged).
/// - `prot_posted_at` is set (Prot was credited), or the order has a
///   dispute on record: None. Refunds after Prot is credited are handled
///   by hand.
/// - The refund was made (Stripe's `created` of the refund event, never
///   later than now) more than [`REFUND_RELEASE_WINDOW_MS`] plus
///   [`REFUND_GRACE_MS`] after the order was paid: None.
/// - A `CipherUpgrade { from, to }` on an active membership that is its
///   latest upgrade (last in `orders`, and the tier is still `to`):
///   [`WindowRefund::Downgrade`] (tier and Prot back to `from`, the order
///   leaves the membership, the number is kept). An older upgrade with
///   another stacked on top: [`WindowRefund::RefundOnly`].
/// - The `CipherNew` order (the one holding the membership's number), with
///   no dispute listed on the membership, and the membership active or
///   revoked by a refund (never one revoked for a lost dispute or by
///   staff): [`WindowRefund::Release`] (the membership is deleted, upgrades
///   included, and the number goes back to the pool). A dispute lost on any
///   of its orders, even one refunded before, sets the revoke reason to
///   `DisputeLost` (`reverse_fulfilled`, `dispute_lost_after_refund`), so
///   it is refused here.
///
/// A lost dispute never comes here: it always revokes and retires.
async fn window_refund_plan(
    db: &Database,
    order: &PaymentOrder,
    m: &CipherMembership,
    refund: Option<RefundFacts>,
) -> Result<Option<WindowRefund>> {
    if !m.orders.contains(&order.id) {
        return Ok(None);
    }
    let Some(refund) = refund else {
        return Ok(None);
    };
    if !refund.full {
        log::warn!(
            "payments: order {} was refunded in part; revoking the membership of {} and \
             retiring number {} (only a full refund is undone)",
            order.id,
            m.user_id,
            m.number
        );
        return Ok(None);
    }
    if let Some(posted) = m.prot_posted_at {
        log::warn!(
            "payments: order {} is refunded, but Prot was credited to the membership of {} at \
             {posted}; revoking and retiring number {} (handle the refund by hand)",
            order.id,
            m.user_id,
            m.number
        );
        return Ok(None);
    }
    if is_disputed(order) {
        return Ok(None);
    }
    let Some(paid_at) = order.paid_at else {
        log::warn!(
            "payments: fulfilled order {} has no paid_at; its refund revokes",
            order.id
        );
        return Ok(None);
    };
    if refund.refunded_at_ms.saturating_sub(paid_at) > REFUND_RELEASE_WINDOW_MS + REFUND_GRACE_MS {
        return Ok(None);
    }

    match order.sku {
        Sku::CipherUpgrade { to, from } => {
            if !m.is_active() {
                return Ok(None);
            }
            if m.tier != to || m.orders.last() != Some(&order.id) {
                return Ok(Some(WindowRefund::RefundOnly));
            }
            Ok(Some(WindowRefund::Downgrade { from }))
        }
        Sku::CipherNew { .. } => {
            let revoked_by_refund = m.revoke_reason == Some(CipherRevokeReason::Refund);
            // Revoked for a lost dispute or by staff: the number stays
            // retired
            if !m.disputed_orders.is_empty() || (!m.is_active() && !revoked_by_refund) {
                return Ok(None);
            }
            match db.fetch_cipher_number_by_order(&order.id).await? {
                Some(number) if number == m.number => Ok(Some(WindowRefund::Release)),
                held => {
                    log::error!(
                        "payments: order {} holds number {held:?}, but its membership has {}; \
                         not releasing it",
                        order.id,
                        m.number
                    );
                    Ok(None)
                }
            }
        }
    }
}

/// Record the leased order Refunded (state, `reversed_at`, no reversal
/// pending, and no refund left settling: on a Refunded order a refund
/// changes nothing, so the reconcile sweep has nothing to re-read)
async fn mark_refunded(db: &Database, leased: &mut Leased, now_ms: i64) -> Result<()> {
    write(db, leased, move |o| {
        o.state = OrderState::Refunded;
        o.reversed_at = Some(now_ms);
        o.reversal_pending = None;
        o.refund_settling_since = None;
    })
    .await
}

/// A full Refund inside the window ([`window_refund_plan`]), applied in
/// full: Some(outcome), or None when the rule says revoke + retire (the
/// caller does that). Every membership write is a compare-and-swap
/// re-checked against the plan on each read.
async fn refund_within_window(
    db: &Database,
    stripe: &dyn StripeApi,
    leased: &mut Leased,
    user_id: &str,
    refund: Option<RefundFacts>,
    now_ms: i64,
) -> Result<Option<ReverseOutcome>> {
    let order_id = leased.order.id.clone();
    for _ in 0..MEMBERSHIP_RETRIES {
        let Some(m) = db.fetch_cipher_membership(user_id).await? else {
            return Ok(None);
        };
        match window_refund_plan(db, &leased.order, &m, refund).await? {
            None => return Ok(None),
            Some(WindowRefund::RefundOnly) => {
                log::error!(
                    "payments: upgrade order {order_id} (payment {:?}) was refunded within the \
                     window, but another upgrade is stacked on it in the membership of \
                     {user_id} (orders {:?}); the membership is left as it is and the order \
                     recorded Refunded; handle by hand",
                    leased.order.payment_intent_id,
                    m.orders
                );
                mark_refunded(db, leased, now_ms).await?;
                return Ok(Some(ReverseOutcome::NoOp));
            }
            Some(WindowRefund::Release) => {
                // Still ours (the `publish_badge` fence): a worker that
                // stalled past its lease since the plan's reads, while
                // another recorded a dispute or applied a lost one, stops
                // here instead of marking
                write(db, leased, |_| {}).await?;
                // The decision is recorded on the number row first: from
                // here on, any reversal of this order or the reconcile sweep
                // finishes the release, whatever happens to the membership
                if !db.mark_cipher_number_release(&order_id, now_ms).await? {
                    log::error!(
                        "payments: order {order_id} lost its number while being refunded; not \
                         releasing anything"
                    );
                    return Ok(None);
                }
                return Box::pin(finish_number_release_locked(db, stripe, leased, now_ms)).await;
            }
            Some(WindowRefund::Downgrade { from }) => {
                // One write: a retry after it finds the order unlisted and
                // only records it Refunded (`unlisted_reversal`)
                let mut next = m.clone();
                next.tier = from;
                next.prot_grant = catalog::tier_prot(from);
                next.orders.retain(|id| *id != order_id);
                next.disputed_orders.retain(|id| *id != order_id);
                if !db
                    .update_cipher_membership_if_version(&next, m.version)
                    .await?
                {
                    continue;
                }

                sync_user_badge(db, user_id).await?;
                mark_refunded(db, leased, now_ms).await?;
                log::info!(
                    "payments: upgrade order {order_id} refunded within the window; the \
                     membership of {user_id} is back to {from:?} and keeps number {}",
                    m.number
                );
                return Ok(Some(ReverseOutcome::Applied));
            }
        }
    }

    log::error!(
        "payments: refund of order {order_id} did not settle after {MEMBERSHIP_RETRIES} tries"
    );
    Err(create_error!(InternalError))
}

/// Finish the number release a refund decided for the leased order (its
/// number row carries `release_pending_at`), if it did: None when there is
/// nothing to finish. The steps after the decision run in this order, each
/// idempotent, so stopping after any of them and running again (any
/// reversal of the order, or the reconcile sweep) finishes the job:
///
/// 1. revoke the membership that lists the order (reason Refund) and clear
///    the badge;
/// 2. refund every paid upgrade on that membership and record it Refunded
///    ([`refund_release_upgrades`]); until each one is, the release waits
///    (`RecordedPending`) with its mark kept, and the next run (the sweep,
///    or any reversal of the order) carries on from here;
/// 3. delete that membership, compare-and-swap on the version read, so a
///    row the buyer replaced meanwhile (a new purchase) is never deleted;
/// 4. record the order Refunded (if it is still Fulfilled);
/// 5. release the number (`release_cipher_number` unsets `order_id` and the
///    mark together, and touches only this order's row), only once no
///    membership row holds it, whoever's it is. An order unlinked by an
///    account deletion that has not deleted the membership yet is an
///    error, so the next run tries again.
///
/// The membership goes before the number, so a number is never free while
/// a membership row still holds it (the unique `number` index). The order
/// is written before the release, so the mark the sweep looks for is the
/// last thing to go. The upgrade refunds, the delete and the order write
/// are fenced on the lease: a worker that stalled past it does none of
/// them.
///
/// A membership revoked by staff or for a lost dispute, with Prot credited,
/// or listing a disputed order, or an order with a dispute open on it,
/// keeps its row and its number (the revoke + retire rule): the decision is
/// dropped instead ([`keep_number_retired`]).
async fn finish_number_release_locked(
    db: &Database,
    stripe: &dyn StripeApi,
    leased: &mut Leased,
    now_ms: i64,
) -> Result<Option<ReverseOutcome>> {
    if !matches!(leased.order.sku, Sku::CipherNew { .. }) {
        return Ok(None);
    }
    let order_id = leased.order.id.clone();
    let Some(row) = db.fetch_cipher_number_row_by_order(&order_id).await? else {
        return Ok(None);
    };
    if row.release_pending_at.is_none() {
        return Ok(None);
    }

    // Unlinked by an account deletion: its cascade deletes the membership
    // (unlink first, then delete), and step 5 waits for that
    if let Some(user_id) = leased.order.user_id.clone() {
        let mut settled = false;
        for _ in 0..MEMBERSHIP_RETRIES {
            let Some(m) = db.fetch_cipher_membership(&user_id).await? else {
                settled = true;
                break;
            };
            if !m.orders.contains(&order_id) {
                // Replaced by a new purchase: nothing of this order's left.
                // Any upgrade of the replaced row not refunded by then went
                // with it (fulfil and checkout refuse a new purchase while
                // the release runs, so this is only ever a race)
                log_upgrades_left_unrefunded(db, &leased.order, &m).await?;
                settled = true;
                break;
            }

            if m.is_active() {
                // 1. Revoke; the badge goes at once
                let mut next = m.clone();
                next.revoked_at = Some(now_ms);
                next.revoke_reason = Some(CipherRevokeReason::Refund);
                if db
                    .update_cipher_membership_if_version(&next, m.version)
                    .await?
                {
                    sync_user_badge(db, &user_id).await?;
                }
                continue;
            }

            // Revoked by staff or for a lost dispute, Prot credited, or a
            // dispute opened on one of its orders (an upgrade, recorded
            // under that order's lease; or this order, recorded on it by
            // `reverse_fulfilled`), since the decision: the number stays
            // retired
            if m.prot_posted_at.is_some()
                || m.revoke_reason != Some(CipherRevokeReason::Refund)
                || !m.disputed_orders.is_empty()
                || is_disputed(&leased.order)
            {
                return keep_number_retired(db, leased, &m, now_ms).await.map(Some);
            }

            // 2. Every paid upgrade refunded and recorded first, while
            //    still ours: the row is never deleted with one unrefunded
            write(db, leased, |_| {}).await?;
            if !Box::pin(refund_release_upgrades(db, stripe, &m, &order_id, now_ms)).await? {
                return Ok(Some(ReverseOutcome::RecordedPending));
            }

            // 3. Delete the row that holds the number, while still ours
            write(db, leased, |_| {}).await?;
            if db
                .delete_cipher_membership_if_version(&user_id, m.version)
                .await?
            {
                settled = true;
                break;
            }
        }

        if !settled {
            log::error!(
                "payments: release of the number of order {order_id} did not settle after \
                 {MEMBERSHIP_RETRIES} tries"
            );
            return Err(create_error!(InternalError));
        }
        sync_user_badge(db, &user_id).await?;
    }

    // 4. The order
    if leased.order.state == OrderState::Fulfilled {
        mark_refunded(db, leased, now_ms).await?;
    }

    // 5. The number back to the pool, once no row holds it
    if let Some(holder) = db.fetch_cipher_membership_by_number(row.number).await? {
        log::error!(
            "payments: number {} of refunded order {order_id} is still held by the membership \
             of {}; not releasing it until that row is gone",
            row.number,
            holder.user_id
        );
        return Err(create_error!(InternalError));
    }
    let released = db.release_cipher_number(&order_id).await?;
    log::info!(
        "payments: order {order_id} refunded within the window; number {} is back in the pool \
         (released now: {released})",
        row.number
    );
    Ok(Some(ReverseOutcome::Applied))
}

/// A dispute lost on the leased order (a new purchase) while the release
/// of its number is still pending: the release is dropped (fenced on the
/// lease) and the number stays retired. Nothing to do when no release is
/// pending.
async fn drop_release_for_lost_dispute(db: &Database, leased: &mut Leased) -> Result<()> {
    let order_id = leased.order.id.clone();
    let pending = db
        .fetch_cipher_number_row_by_order(&order_id)
        .await?
        .is_some_and(|row| row.release_pending_at.is_some());
    if !pending {
        return Ok(());
    }

    write(db, leased, |_| {}).await?;
    log::error!(
        "payments: a dispute on order {order_id} was lost while the release of its number was \
         pending; the release is dropped and the number stays retired, check the refund by hand"
    );
    db.cancel_cipher_number_release(&order_id).await?;
    Ok(())
}

/// A release whose membership row was replaced by a new purchase of the
/// buyer (`current`) before the release refunded every upgrade on the old
/// row: such upgrades (Paid or Fulfilled, ordered after `released`, the
/// purchase whose number is released, and not on `current`) are logged at
/// error level, to be refunded by hand
async fn log_upgrades_left_unrefunded(
    db: &Database,
    released: &PaymentOrder,
    current: &CipherMembership,
) -> Result<()> {
    let Some(user_id) = released.user_id.as_deref() else {
        return Ok(());
    };
    let left: Vec<String> = db
        .fetch_payment_orders_by_user(user_id, &[OrderState::Paid, OrderState::Fulfilled])
        .await?
        .into_iter()
        .filter(|o| {
            matches!(o.sku, Sku::CipherUpgrade { .. })
                && o.created_at >= released.created_at
                && !current.orders.contains(&o.id)
        })
        .map(|o| o.id)
        .collect();
    if !left.is_empty() {
        log::error!(
            "payments: the membership of {user_id} released by order {} was replaced by a new \
             purchase before upgrade orders {left:?} on it were refunded; refund them by hand",
            released.id
        );
    }
    Ok(())
}

/// Drop the release decided for the leased order: since the decision, its
/// membership `m` was revoked by staff or for a lost dispute, had Prot
/// credited, or had a dispute listed, or a dispute opened on the order
/// itself, and such a number stays retired (the refund rule). The order is
/// recorded Refunded first (fenced on the lease), then the mark is cleared,
/// so a stop in between is finished by the next run.
async fn keep_number_retired(
    db: &Database,
    leased: &mut Leased,
    m: &CipherMembership,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    let order_id = leased.order.id.clone();
    log::error!(
        "payments: the release of number {} decided for order {order_id} is dropped: the \
         membership of {} was revoked ({:?}), had Prot credited ({:?}) or had disputed orders \
         ({:?}), or the order has open disputes ({:?}), since; the number stays retired, check \
         the refund by hand",
        m.number,
        m.user_id,
        m.revoke_reason,
        m.prot_posted_at,
        m.disputed_orders,
        leased.order.open_disputes
    );
    if leased.order.state == OrderState::Fulfilled {
        mark_refunded(db, leased, now_ms).await?;
    }
    db.cancel_cipher_number_release(&order_id).await?;
    Ok(ReverseOutcome::Applied)
}

/// Release step 2: the 14-day refund is a full refund of the Cipher
/// purchase, so before membership `m` is deleted every paid upgrade on it
/// (each order in `m.orders` but `released_by`, the purchase whose number
/// is released) is refunded in full by us, under its own idempotency key
/// ([`release_upgrade_key`]), and recorded Refunded under its own lease.
///
/// Ok(true) once every one of them is Refunded (or Voided, or missing).
/// Ok(false) while any is not: its refund is still settling (its
/// `charge.refund.updated` records it once it succeeds), Stripe says it
/// is already refunded but the refunds that succeeded do not add up to
/// its amount yet (one is still settling), the call failed
/// or Stripe refused it (logged at error level; the next run asks again
/// with the same key, and Stripe answers a refused one with the same
/// refusal until the key expires after 24 hours), its lease is held (its
/// holder or the next run records it), or a dispute on it is open (its
/// dispute events decide; a refund now could pay the buyer twice). A
/// database error is an error.
async fn refund_release_upgrades(
    db: &Database,
    stripe: &dyn StripeApi,
    m: &CipherMembership,
    released_by: &str,
    now_ms: i64,
) -> Result<bool> {
    let mut waiting = false;
    for id in m.orders.iter().filter(|id| *id != released_by) {
        let Some(upgrade) = db.fetch_payment_order(id).await? else {
            log::error!(
                "payments: the membership of {} lists order {id}, which does not exist; nothing \
                 of it to refund before the release of order {released_by}",
                m.user_id
            );
            continue;
        };
        if matches!(upgrade.state, OrderState::Refunded | OrderState::Voided) {
            continue;
        }

        let Some(payment_intent) = upgrade.payment_intent_id.clone() else {
            log::error!(
                "payments: upgrade order {id} on the membership of {} has no payment to refund; \
                 the release of order {released_by} waits, handle by hand",
                m.user_id
            );
            waiting = true;
            continue;
        };
        if is_disputed(&upgrade) {
            log::warn!(
                "payments: upgrade order {id} is disputed; not refunding it, and the release of \
                 order {released_by} waits for its disputes"
            );
            waiting = true;
            continue;
        }

        let recorded = match ask_refund(stripe, &payment_intent, &release_upgrade_key(id), id).await
        {
            Ok(RefundAsked::Done) => record_upgrade_refunded(db, id, now_ms).await?,
            // Refunded before (our refund once its key expired, or one made
            // in the Dashboard): recorded only once the refunds that have
            // succeeded add up to what the upgrade cost
            Ok(RefundAsked::AlreadyRefunded) => {
                if refunded_in_full(stripe, &payment_intent, upgrade.amount_cents, id).await {
                    record_upgrade_refunded(db, id, now_ms).await?
                } else {
                    log::warn!(
                        "payments: upgrade order {id} is already refunded at Stripe, but its \
                         refunds have not all succeeded; the release of order {released_by} \
                         waits until they have"
                    );
                    false
                }
            }
            Ok(RefundAsked::Unsettled { refund_id, status }) => {
                log::warn!(
                    "payments: refund {refund_id} of upgrade order {id} is {status}; the release \
                     of order {released_by} waits until it succeeds"
                );
                false
            }
            Ok(RefundAsked::Refused { refund_id, status }) => {
                log::error!(
                    "payments: refund {refund_id} of upgrade order {id} is {status}; the release \
                     of order {released_by} stays pending and asks again next time"
                );
                false
            }
            // The failure itself is logged by `ask_refund`
            Err(_) => {
                log::error!(
                    "payments: the release of order {released_by} stays pending until upgrade \
                     order {id} is refunded"
                );
                false
            }
        };
        if recorded {
            log::info!(
                "payments: upgrade order {id} refunded and recorded for the release of order \
                 {released_by}"
            );
        } else {
            waiting = true;
        }
    }
    Ok(!waiting)
}

/// Whether the refunds of `payment_intent` that have `succeeded` add up to
/// at least `amount_cents`, as Stripe lists them now. A failed lookup is
/// "not yet" (logged); the next run asks again.
async fn refunded_in_full(
    stripe: &dyn StripeApi,
    payment_intent: &str,
    amount_cents: i64,
    order_id: &str,
) -> bool {
    match stripe.list_refunds(payment_intent).await {
        // Only `full` is read, so the dates passed are never used
        Ok(refunds) => refund_facts(&refunds, amount_cents, 0, 0).is_some_and(|facts| facts.full),
        Err(err) => {
            log::error!("payments: listing the refunds of order {order_id} failed: {err}");
            false
        }
    }
}

/// Record upgrade order `order_id` Refunded under its own lease, once our
/// refund of it is done. Ok(false) when its lease is held: the holder (its
/// own refund event, most likely) or the next run records it.
async fn record_upgrade_refunded(db: &Database, order_id: &str, now_ms: i64) -> Result<bool> {
    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        return Ok(false);
    };
    let result = match leased.order.state {
        OrderState::Refunded | OrderState::Voided => Ok(true),
        _ => mark_refunded(db, &mut leased, now_ms).await.map(|()| true),
    };
    release(db, &leased).await;
    result
}

/// The reconcile sweep's step for a number whose release was decided but
/// not finished ([`finish_number_release_locked`]), under the order's
/// lease. `Applied` when finished now, `RecordedPending` while it waits on
/// an upgrade refund, `NoOp` when there was nothing to finish, `Busy` when
/// another worker holds the order.
pub async fn finish_number_release(
    db: &Database,
    stripe: &dyn StripeApi,
    order_id: &str,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        return Ok(ReverseOutcome::Busy);
    };
    let outcome = finish_number_release_locked(db, stripe, &mut leased, now_ms).await;
    release(db, &leased).await;
    Ok(outcome?.unwrap_or(ReverseOutcome::NoOp))
}

// ---------------------------------------------------------------------------
// Expiry, views, badge, account deletion
// ---------------------------------------------------------------------------

/// Creating | Pending | SessionFailed → Expired (under the lease). Any other
/// state is left as it is. Ok(false) when another worker holds the lease
/// (nothing was looked at); the caller decides whether to try again.
pub async fn expire_order(db: &Database, order_id: &str, now_ms: i64) -> Result<bool> {
    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        log::debug!("payments: not expiring order {order_id}: its lease is held");
        return Ok(false);
    };

    let result = match leased.order.state {
        OrderState::Creating | OrderState::Pending | OrderState::SessionFailed => {
            write(db, &mut leased, |o| o.state = OrderState::Expired).await
        }
        _ => Ok(()),
    };
    release(db, &leased).await;
    result.map(|()| true)
}

/// The session user's Cipher standing: the active membership (with the
/// owner-only `disputed` flag) and the newest unexpired checkout
pub async fn cipher_me(db: &Database, user_id: &str, now_ms: i64) -> Result<CipherMe> {
    let membership = db
        .fetch_cipher_membership(user_id)
        .await?
        .filter(CipherMembership::is_active)
        .map(|m| CipherMembershipView {
            number: m.number,
            tier: m.tier,
            disputed: !m.disputed_orders.is_empty(),
            prot_grant: m.prot_grant,
        });

    let pending = db
        .fetch_payment_orders_by_user(user_id, &[OrderState::Pending])
        .await?
        .into_iter()
        .filter_map(|o| {
            let expires_at = o.session_expires_at?;
            (expires_at > now_ms && o.checkout_url.is_some()).then_some(CipherPendingView {
                order_id: o.id,
                sku: o.sku,
                expires_at,
            })
        })
        .next_back();

    Ok(CipherMe {
        membership,
        pending,
    })
}

/// Public sale counter; `claimed` counts retired numbers too
pub async fn cipher_stats(db: &Database, s: &PaymentsSettings, now_ms: i64) -> Result<CipherStats> {
    Ok(CipherStats {
        claimed: db.count_claimed_cipher_numbers().await?,
        cap: s.cap,
        open: s.sales_open_at(now_ms),
        closes_at: s.close_at_ms,
    })
}

/// Recompute + publish the public badge from the membership (None when
/// absent/revoked/disputed) via User::update / FieldsUser::Cipher removal
///
/// Write, then verify: two syncs for one user can interleave (each read the
/// membership before the other's write), so after writing, the membership is
/// read again and a badge that no longer matches is rewritten. A deleted
/// account never gets a badge. Nothing is published when nothing changes.
pub async fn sync_user_badge(db: &Database, user_id: &str) -> Result<()> {
    for _ in 0..BADGE_SYNC_RETRIES {
        let badge = db
            .fetch_cipher_membership(user_id)
            .await?
            .and_then(|m| m.public_badge());

        let mut user = match db.fetch_user(user_id).await {
            Ok(user) => user,
            Err(err) if matches!(err.error_type, ErrorType::NotFound) => return Ok(()),
            Err(err) => return Err(err),
        };

        let badge = if is_deleted(&user) { None } else { badge };
        if user.cipher == badge {
            return Ok(());
        }

        match badge {
            Some(badge) => {
                user.update(
                    db,
                    PartialUser {
                        cipher: Some(badge),
                        ..Default::default()
                    },
                    vec![],
                )
                .await?
            }
            None => {
                user.update(db, PartialUser::default(), vec![FieldsUser::Cipher])
                    .await?
            }
        }
    }

    log::error!(
        "payments: badge of user {user_id} did not settle after {BADGE_SYNC_RETRIES} rounds"
    );
    Err(create_error!(InternalError))
}

/// Account deletion: void + refund Paid, void Creating/Pending/SessionFailed
/// (AccountDeleted), unlink orders, delete membership
///
/// The voids are best-effort: a failure (Stripe down, a lease held, even
/// the listing of the orders) is logged, not returned. Unlinking the orders
/// and deleting the membership must succeed ([`unlink_account_payments`]):
/// their error is returned, and the caller must not delete the account
/// then, so its next run tries again.
///
/// Every void failure heals itself once the orders are unlinked (a Paid
/// order left behind is voided and refunded
/// by the reconcile resume, because fulfil voids an order with no buyer, or
/// with a buyer whose account is deleted or gone, so even an order this
/// cascade never unlinked is refunded; a session paid after deletion is
/// refunded by fulfil; a Creating order expires). An order whose lease is
/// held is left to its holder, whose next write is fenced off by the
/// unlink; if that holder wrote the membership after the delete below, the
/// resume that voids the order deletes it (the session's
/// `client_reference_id` names the buyer). Fulfilled orders are not
/// refunded.
pub async fn on_account_deleted(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    user_id: &str,
    now_ms: i64,
) -> Result<()> {
    let _ = s;

    let open = match db
        .fetch_payment_orders_by_user(
            user_id,
            &[
                OrderState::Creating,
                OrderState::Pending,
                OrderState::SessionFailed,
                OrderState::Paid,
            ],
        )
        .await
    {
        Ok(open) => open,
        Err(err) => {
            log::warn!(
                "payments: account deletion of {user_id} could not list its open orders, so \
                 none is voided now: {err:?}"
            );
            vec![]
        }
    };

    for order in open {
        match acquire(db, &order.id, now_ms).await {
            Ok(Some(mut leased)) => {
                let result = void_for_deletion(db, stripe, &mut leased, now_ms).await;
                release(db, &leased).await;
                if let Err(err) = result {
                    log::warn!(
                        "payments: account deletion could not void order {}: {err:?}",
                        order.id
                    );
                }
            }
            Ok(None) => log::warn!(
                "payments: account deletion skipped order {}: its lease is held",
                order.id
            ),
            Err(err) => log::warn!(
                "payments: account deletion could not lease order {}: {err:?}",
                order.id
            ),
        }
    }

    // After the voids: their writes are fenced on the buyer still being set
    unlink_account_payments(db, user_id).await
}

/// The part of the account-deletion cascade that must succeed before the
/// account is deleted: unlink every order from the user, then delete the
/// Cipher membership. No Stripe call, so it also runs when no payments
/// config is usable. Both steps are idempotent, so a retry is safe.
pub async fn unlink_account_payments(db: &Database, user_id: &str) -> Result<()> {
    db.unlink_payment_orders_by_user(user_id).await?;
    db.delete_cipher_membership(user_id).await?;
    Ok(())
}

async fn void_for_deletion(
    db: &Database,
    stripe: &dyn StripeApi,
    leased: &mut Leased,
    now_ms: i64,
) -> Result<()> {
    match leased.order.state {
        OrderState::Paid => {
            let buyer = leased.order.user_id.clone();
            void_for_deleted_account(db, stripe, leased, buyer.as_deref(), now_ms).await?;
            Ok(())
        }
        OrderState::Creating | OrderState::Pending | OrderState::SessionFailed => {
            write(db, leased, move |o| {
                o.state = OrderState::Voided;
                o.void_reason = Some(VoidReason::AccountDeleted);
                o.reversed_at = Some(now_ms);
            })
            .await
        }
        // Moved on since it was listed
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use revolt_database::test_teardown::TestDatabaseGuard;
    use revolt_database::DatabaseInfo;
    use revolt_models::v0::UserCipher;

    use super::*;
    use crate::catalog::CIPHER_CAP_MAX;
    use crate::dispatch::{handle_event, reconcile, EventOutcome};
    use crate::stripe::{Dispute, MockStripe, PaymentCharge, PaymentIntent, Refund, StripeEvent};

    const NOW: i64 = 1_760_000_000_000;
    /// After a dead worker's lease has run out
    const LATER: i64 = NOW + LEASE_MS + 1;
    const MINUTE: i64 = 60_000;
    const DAY: i64 = 24 * 60 * MINUTE;
    /// The first moment a refund of an order paid at NOW is past the
    /// release window
    const AFTER_WINDOW: i64 = NOW + REFUND_RELEASE_WINDOW_MS + REFUND_GRACE_MS + 1;

    static NEXT_DB: AtomicU64 = AtomicU64::new(0);

    /// A throwaway database on the driver `TEST_DB` names (it panics when
    /// unset, so these tests never reach production). Mongo: named
    /// `revolt_test_<digits>` like `DatabaseInfo::Auto`'s, so
    /// `scripts/drop-test-databases.sh` sweeps one a panicking test leaves.
    /// `seeded`: the schema (indexes) and the 1..=1000 cipher_numbers seed.
    /// A throwaway database plus the guard that drops it (Mongo) if the
    /// test panics before its own `drop_db`
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

    async fn connect(seeded: bool) -> TestDb {
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

        if seeded {
            // Mongo: a fresh database runs init (payments indexes + seed);
            // reference: no-op, so seed by hand (a no-op on Mongo after init)
            db.migrate_database().await.expect("schema");
            db.seed_cipher_numbers(CIPHER_CAP_MAX).await.unwrap();
        }
        TestDb {
            db,
            guard: Mutex::new(Some(guard)),
        }
    }

    async fn test_db() -> TestDb {
        connect(true).await
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

    fn settings() -> PaymentsSettings {
        PaymentsSettings {
            enabled: true,
            sales_open: true,
            cap: CIPHER_CAP_MAX,
            close_at_ms: None,
            expect_livemode: false,
            tolerance_secs: 300,
            automatic_tax: false,
            // The shipped list (the EU and the UK)
            blocked_countries: revolt_config::FeaturePayments::default().cipher_blocked_countries,
            secret_key: String::new(),
            webhook_secret: String::new(),
            success_url_web: "https://app.test/settings?cipher=success".to_string(),
            cancel_url_web: "https://app.test/settings?cipher=cancel".to_string(),
            success_url_shell: "https://site.test/cipher/thanks/".to_string(),
            cancel_url_shell: "https://site.test/cipher/".to_string(),
        }
    }

    #[allow(clippy::disallowed_methods)]
    async fn insert_user(db: &Database, id: &str) {
        db.insert_user(&User {
            id: id.to_string(),
            username: id.to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    }

    async fn order(db: &Database, id: &str) -> PaymentOrder {
        db.fetch_payment_order(id).await.unwrap().unwrap()
    }

    async fn membership(db: &Database, user: &str) -> CipherMembership {
        db.fetch_cipher_membership(user).await.unwrap().unwrap()
    }

    async fn badge(db: &Database, user: &str) -> Option<UserCipher> {
        db.fetch_user(user).await.unwrap().cipher
    }

    fn badge_of(number: u32, tier: CipherTier) -> Option<UserCipher> {
        Some(UserCipher { number, tier })
    }

    fn error_type<T: std::fmt::Debug>(result: Result<T>) -> ErrorType {
        result.expect_err("expected an error").error_type
    }

    /// Start a checkout at `now`; the Pending order it created
    async fn checkout(
        db: &Database,
        stripe: &MockStripe,
        s: &PaymentsSettings,
        user: &str,
        tier: CipherTier,
        now: i64,
    ) -> PaymentOrder {
        let url = create_cipher_checkout(db, stripe, s, user, tier, CipherReturnTo::Web, now)
            .await
            .unwrap();
        db.fetch_payment_orders_by_user(user, &[OrderState::Pending])
            .await
            .unwrap()
            .into_iter()
            .find(|o| o.checkout_url.as_deref() == Some(url.as_str()))
            .expect("the checkout's Pending order")
    }

    /// The buyer pays: the order's session becomes complete + paid by
    /// `payment_intent`, as Stripe then reports it
    fn pay(stripe: &MockStripe, order: &PaymentOrder, payment_intent: &str) -> CheckoutSession {
        let id = order.checkout_session_id.clone().expect("session id");
        let mut session = stripe.session(&id).expect("session at Stripe");
        session.status = Some("complete".to_string());
        session.payment_status = Some("paid".to_string());
        session.payment_intent = Some(payment_intent.to_string());
        stripe.set_session(session.clone());
        session
    }

    /// Checkout, pay and fulfil; the Fulfilled order
    async fn buy(
        db: &Database,
        stripe: &MockStripe,
        s: &PaymentsSettings,
        user: &str,
        tier: CipherTier,
        payment_intent: &str,
        now: i64,
    ) -> PaymentOrder {
        let pending = checkout(db, stripe, s, user, tier, now).await;
        let session = pay(stripe, &pending, payment_intent);
        assert_eq!(
            fulfil_order(db, stripe, s, &pending.id, &session, now)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        let fulfilled = order(db, &pending.id).await;
        assert_eq!(fulfilled.state, OrderState::Fulfilled);
        fulfilled
    }

    /// A worker that took the lease at NOW, wrote `change`, then died
    /// holding the lease (it runs out at LATER - 1)
    async fn crash_after(db: &Database, id: &str, change: impl FnOnce(&mut PaymentOrder)) {
        let mut leased = db
            .acquire_payment_order_lease(id, NOW, NOW + LEASE_MS)
            .await
            .unwrap()
            .expect("lease");
        let expected = leased.state.clone();
        change(&mut leased);
        assert!(db
            .update_payment_order_if_state(&leased, expected)
            .await
            .unwrap());
    }

    /// Apply `kind` for dispute `dispute_id` the way [`reverse_dispute`]
    /// does once Stripe has told it the dispute's status (that lookup has
    /// its own tests)
    async fn on_dispute(
        db: &Database,
        order_id: &str,
        dispute_id: &str,
        kind: ReverseKind,
        at: i64,
    ) -> Result<ReverseOutcome> {
        let Some(mut leased) = acquire(db, order_id, at).await? else {
            return Ok(ReverseOutcome::Busy);
        };
        let stripe = MockStripe::new();
        let outcome =
            reverse_locked(db, &stripe, &mut leased, kind, Some(dispute_id), None, at).await;
        release(db, &leased).await;
        outcome
    }

    fn refund_keys(stripe: &MockStripe) -> Vec<(String, Option<String>)> {
        stripe
            .calls()
            .into_iter()
            .filter(|(method, _, _)| method == "create_refund")
            .map(|(_, payment_intent, key)| (payment_intent, key))
            .collect()
    }

    // --- happy paths --------------------------------------------------

    #[tokio::test]
    async fn new_purchase_then_upgrade_keeps_the_number_and_charges_the_difference() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_new", NOW).await;
        assert_eq!(first.amount_cents, 9_900);
        assert_eq!(first.payment_intent_id.as_deref(), Some("pi_new"));
        assert_eq!(first.fulfilled_at, Some(NOW));
        assert!(first.lease_until.is_none(), "the lease is released");

        let m = membership(&db, "u1").await;
        assert_eq!(
            (m.number, m.tier, m.prot_grant),
            (1, CipherTier::T99, 16_500)
        );
        assert_eq!(m.orders, vec![first.id.clone()]);
        assert!(m.is_active());
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));

        // The session was built from the stored order only
        let params = stripe.checkout_params();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].order_id, first.id);
        assert_eq!(params[0].user_id, "u1");
        assert_eq!(params[0].amount_cents, 9_900);
        assert_eq!(params[0].currency, "usd");
        assert_eq!(params[0].expires_at_secs, NOW / 1000 + SESSION_TTL_SECS);
        assert_eq!(params[0].success_url, s.success_url_web);
        assert!(stripe.calls().contains(&(
            "create_checkout_session".to_string(),
            first.id.clone(),
            Some(first.id.clone())
        )));

        // Upgrade 99 → 299: charged the difference, same number
        let later = NOW + 10 * MINUTE;
        let upgrade = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", later).await;
        assert_eq!(
            upgrade.sku,
            Sku::CipherUpgrade {
                from: CipherTier::T99,
                to: CipherTier::T299
            }
        );
        assert_eq!(upgrade.amount_cents, 20_000);
        let params = stripe.checkout_params();
        assert_eq!(params[1].amount_cents, 20_000);
        assert_eq!(params[1].product_name, "Cipher upgrade ($99 to $299)");

        let m = membership(&db, "u1").await;
        assert_eq!(
            (m.number, m.tier, m.prot_grant),
            (1, CipherTier::T299, 75_000)
        );
        assert_eq!(m.orders, vec![first.id.clone(), upgrade.id.clone()]);
        assert_eq!(m.granted_at, NOW, "an upgrade keeps the original grant");
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T299));

        // An upgrade never claims a number
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);
        assert_eq!(stripe.refund_count(), 0);

        let me = cipher_me(&db, "u1", later).await.unwrap();
        assert_eq!(
            me.membership,
            Some(CipherMembershipView {
                number: 1,
                tier: CipherTier::T299,
                disputed: false,
                prot_grant: 75_000
            })
        );
        assert_eq!(me.pending, None);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn duplicate_and_concurrent_fulfils_claim_one_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T149, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");

        // Two deliveries at once: one applies, the other finds the lease
        // held (or, if it ran second, the order fulfilled). Only MONGODB
        // interleaves the two: the reference driver's calls never yield
        // mid-step, so there the second simply runs after the first.
        let (a, b) = tokio::join!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW),
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW)
        );
        let outcomes = [a.unwrap(), b.unwrap()];
        assert!(
            outcomes.contains(&FulfilOutcome::Fulfilled),
            "one fulfils: {outcomes:?}"
        );
        assert!(
            outcomes.contains(&FulfilOutcome::LeaseHeld)
                || outcomes.contains(&FulfilOutcome::AlreadyFulfilled),
            "the other does not: {outcomes:?}"
        );

        // A redelivery later
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + MINUTE)
                .await
                .unwrap(),
            FulfilOutcome::AlreadyFulfilled
        );

        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);
        assert_eq!(membership(&db, "u1").await.orders, vec![pending.id.clone()]);
        assert_eq!(stripe.refund_count(), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_held_lease_defers_to_its_holder() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");
        let held = db
            .acquire_payment_order_lease(&pending.id, NOW, NOW + LEASE_MS)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 1)
                .await
                .unwrap(),
            FulfilOutcome::LeaseHeld
        );
        assert_eq!(
            reverse_order(
                &db,
                &stripe,
                &s,
                &pending.id,
                ReverseKind::Refund,
                None,
                NOW + 1
            )
            .await
            .unwrap(),
            ReverseOutcome::Busy
        );
        let untouched = order(&db, &pending.id).await;
        assert_eq!(untouched.state, OrderState::Pending);
        assert!(untouched.reversal_pending.is_none());
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);

        db.release_payment_order_lease(&pending.id, held.lease_until.unwrap())
            .await
            .unwrap();
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 2)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        drop_db(&db).await;
    }

    // --- crash + resume -----------------------------------------------

    #[tokio::test]
    async fn resume_after_a_crash_at_each_step_keeps_the_number_and_never_refunds() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();

        // Another buyer holds #1, so a re-claim would show as #3
        insert_user(&db, "first").await;
        buy(&db, &stripe, &s, "first", CipherTier::T99, "pi_first", NOW).await;

        for (step, user) in ["paid", "claimed", "member", "badged"]
            .iter()
            .zip(["a", "b", "c", "d"])
        {
            insert_user(&db, user).await;
            let pending = checkout(&db, &stripe, &s, user, CipherTier::T149, NOW).await;
            let session = pay(&stripe, &pending, &format!("pi_{user}"));

            // Step 1 done, then death while holding the lease
            crash_after(&db, &pending.id, |o| {
                o.state = OrderState::Paid;
                o.payment_intent_id = session.payment_intent.clone();
                o.paid_at = Some(NOW);
            })
            .await;

            // Steps 4, 5 and 6 done as the dead worker would have
            let mut number = None;
            if *step != "paid" {
                number = db.claim_cipher_number(&pending.id, s.cap).await.unwrap();
            }
            if *step == "member" || *step == "badged" {
                assert!(db
                    .insert_cipher_membership(&CipherMembership {
                        user_id: user.to_string(),
                        number: number.unwrap(),
                        tier: CipherTier::T149,
                        prot_grant: 33_000,
                        orders: vec![pending.id.clone()],
                        disputed_orders: vec![],
                        granted_at: NOW,
                        revoked_at: None,
                        revoke_reason: None,
                        prot_posted_at: None,
                        version: 0,
                    })
                    .await
                    .unwrap());
            }
            if *step == "badged" {
                sync_user_badge(&db, user).await.unwrap();
            }
            let claimed_before = db.count_claimed_cipher_numbers().await.unwrap();

            // While the dead worker's lease lasts, nobody else acts
            assert_eq!(
                resume_order(&db, &stripe, &s, &pending.id, NOW + 1)
                    .await
                    .unwrap(),
                FulfilOutcome::LeaseHeld,
                "{step}"
            );

            // Once it ran out, the resume finishes the job
            assert_eq!(
                resume_order(&db, &stripe, &s, &pending.id, LATER)
                    .await
                    .unwrap(),
                FulfilOutcome::Fulfilled,
                "{step}"
            );

            let m = membership(&db, user).await;
            assert!(m.is_active(), "{step}");
            assert_eq!(m.orders, vec![pending.id.clone()], "{step}");
            if let Some(number) = number {
                assert_eq!(m.number, number, "{step}: the claimed number is kept");
            }
            assert_eq!(
                db.fetch_cipher_number_by_order(&pending.id).await.unwrap(),
                Some(m.number),
                "{step}"
            );
            let expected_claimed = if *step == "paid" {
                claimed_before + 1
            } else {
                claimed_before
            };
            assert_eq!(
                db.count_claimed_cipher_numbers().await.unwrap(),
                expected_claimed,
                "{step}: no number burned"
            );
            assert_eq!(
                badge(&db, user).await,
                badge_of(m.number, CipherTier::T149),
                "{step}"
            );
            assert_eq!(
                order(&db, &pending.id).await.state,
                OrderState::Fulfilled,
                "{step}"
            );
        }

        // Numbers 2..=5 went to a..d in order; nothing was refunded
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 5);
        assert_eq!(stripe.refund_count(), 0);
        assert_eq!(stripe.call_count("create_refund"), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn resume_of_an_applied_upgrade_is_not_judged_stale() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_new", NOW).await;

        let upgrade = checkout(&db, &stripe, &s, "u1", CipherTier::T299, NOW).await;
        let session = pay(&stripe, &upgrade, "pi_up");
        crash_after(&db, &upgrade.id, |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some("pi_up".to_string());
            o.paid_at = Some(NOW);
        })
        .await;

        // The dead worker's membership CAS landed: tier is now `to`, so a
        // precondition check before the "already applied?" check would
        // read the upgrade as stale and refund it
        let mut m = membership(&db, "u1").await;
        let version = m.version;
        m.tier = CipherTier::T299;
        m.prot_grant = 75_000;
        m.orders.push(upgrade.id.clone());
        assert!(db
            .update_cipher_membership_if_version(&m, version)
            .await
            .unwrap());

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &upgrade.id, &session, LATER)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        let m = membership(&db, "u1").await;
        assert_eq!((m.number, m.tier), (1, CipherTier::T299));
        assert_eq!(m.orders, vec![first.id, upgrade.id]);
        assert_eq!(stripe.call_count("create_refund"), 0);
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T299));
        drop_db(&db).await;
    }

    // --- voids --------------------------------------------------------

    #[tokio::test]
    async fn the_cap_reached_voids_sold_out_with_one_refund() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = PaymentsSettings {
            cap: 1,
            ..settings()
        };
        insert_user(&db, "a").await;
        insert_user(&db, "b").await;
        insert_user(&db, "c").await;

        // Both start before either is fulfilled
        let a = checkout(&db, &stripe, &s, "a", CipherTier::T99, NOW).await;
        let b = checkout(&db, &stripe, &s, "b", CipherTier::T99, NOW).await;
        let session_a = pay(&stripe, &a, "pi_a");
        let session_b = pay(&stripe, &b, "pi_b");

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &a.id, &session_a, NOW)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &b.id, &session_b, NOW)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::SoldOut)
        );

        let voided = order(&db, &b.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.void_reason, Some(VoidReason::SoldOut));
        assert_eq!(voided.reversed_at, Some(NOW));
        assert_eq!(stripe.refund_count_for("pi_b"), 1);
        assert_eq!(
            refund_keys(&stripe),
            vec![("pi_b".to_string(), Some(format!("void-{}", b.id)))]
        );
        assert!(db.fetch_cipher_membership("b").await.unwrap().is_none());
        assert_eq!(badge(&db, "b").await, None);

        // A redelivery neither refunds again nor claims
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &b.id, &session_b, NOW + MINUTE)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::SoldOut)
        );
        assert_eq!(stripe.call_count("create_refund"), 1);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);

        // New checkouts are refused up front now
        assert!(matches!(
            error_type(
                create_cipher_checkout(
                    &db,
                    &stripe,
                    &s,
                    "c",
                    CipherTier::T99,
                    CipherReturnTo::Web,
                    NOW
                )
                .await
            ),
            ErrorType::CipherSoldOut
        ));
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn an_empty_number_table_is_an_error_not_sold_out() {
        let db = connect(false).await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        assert_eq!(db.count_cipher_numbers().await.unwrap(), 0);

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");
        assert!(fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW)
            .await
            .is_err());

        // Paid and kept for a retry once seeded; never refunded or voided
        let stored = order(&db, &pending.id).await;
        assert_eq!(stored.state, OrderState::Paid);
        assert!(stored.lease_until.is_none());
        assert_eq!(stripe.call_count("create_refund"), 0);

        db.seed_cipher_numbers(CIPHER_CAP_MAX).await.unwrap();
        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, NOW + MINUTE)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        assert_eq!(membership(&db, "u1").await.number, 1);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_stale_upgrade_is_refunded_and_its_refund_leaves_the_membership_intact() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_new", NOW).await;

        // Upgrade to 149 paid, but its event is delayed past the session
        // lifetime; meanwhile a 99 → 299 upgrade goes through
        let stale = checkout(&db, &stripe, &s, "u1", CipherTier::T149, NOW).await;
        let stale_session = pay(&stripe, &stale, "pi_stale");
        let later = NOW + (SESSION_TTL_SECS + 60) * 1000;
        let fresh = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_fresh", later).await;

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &stale.id, &stale_session, later)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::Stale)
        );
        assert_eq!(
            refund_keys(&stripe),
            vec![("pi_stale".to_string(), Some(format!("void-{}", stale.id)))]
        );

        // Our own refund comes back as charge.refunded on the voided order
        assert_eq!(
            reverse_order(
                &db,
                &stripe,
                &s,
                &stale.id,
                ReverseKind::Refund,
                None,
                later + 1
            )
            .await
            .unwrap(),
            ReverseOutcome::NoOp
        );
        let m = membership(&db, "u1").await;
        assert!(m.is_active());
        assert_eq!((m.number, m.tier), (1, CipherTier::T299));
        assert_eq!(m.orders, vec![first.id.clone(), fresh.id.clone()]);
        assert_eq!(order(&db, &first.id).await.state, OrderState::Fulfilled);
        assert_eq!(order(&db, &fresh.id).await.state, OrderState::Fulfilled);
        assert_eq!(order(&db, &stale.id).await.state, OrderState::Voided);
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T299));
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn the_sale_close_is_judged_on_when_the_order_was_created() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        insert_user(&db, "a").await;
        insert_user(&db, "b").await;

        // Created a second before the close, paid after it: fulfilled
        let s = PaymentsSettings {
            close_at_ms: Some(NOW + 1_000),
            ..settings()
        };
        let a = checkout(&db, &stripe, &s, "a", CipherTier::T99, NOW).await;
        let session_a = pay(&stripe, &a, "pi_a");
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &a.id, &session_a, NOW + 10 * MINUTE)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        assert!(!cipher_stats(&db, &s, NOW + 10 * MINUTE).await.unwrap().open);

        // No checkout starts after the close
        assert!(matches!(
            error_type(
                create_cipher_checkout(
                    &db,
                    &stripe,
                    &s,
                    "b",
                    CipherTier::T99,
                    CipherReturnTo::Web,
                    NOW + 1_000
                )
                .await
            ),
            ErrorType::CipherSalesClosed
        ));

        // The close date moved before an order's creation: voided + refunded
        let b = checkout(&db, &stripe, &s, "b", CipherTier::T99, NOW).await;
        let session_b = pay(&stripe, &b, "pi_b");
        let moved = PaymentsSettings {
            close_at_ms: Some(NOW),
            ..settings()
        };
        assert_eq!(
            fulfil_order(&db, &stripe, &moved, &b.id, &session_b, NOW + MINUTE)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::SalesClosed)
        );
        assert_eq!(stripe.refund_count_for("pi_b"), 1);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);

        // The master switch
        let off = PaymentsSettings {
            enabled: false,
            ..settings()
        };
        assert!(matches!(
            error_type(
                create_cipher_checkout(
                    &db,
                    &stripe,
                    &off,
                    "b",
                    CipherTier::T99,
                    CipherReturnTo::Web,
                    NOW
                )
                .await
            ),
            ErrorType::PaymentsDisabled
        ));
        drop_db(&db).await;
    }

    // --- reversals ----------------------------------------------------

    /// A refund that arrives before the completion is handled: the order is
    /// voided instead of applied (m4). No number is claimed and no badge is
    /// published, even for a moment; the void asks Stripe for whatever is
    /// left of the payment (a partial refund), which is nothing here.
    #[tokio::test]
    async fn a_refund_before_completion_voids_the_order_instead_of_applying_it() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T149, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");

        // The owner refunds at Stripe before the completion is handled
        stripe.create_refund("pi_1", "owner-refund").await.unwrap();
        assert_eq!(
            reverse_order(
                &db,
                &stripe,
                &s,
                &pending.id,
                ReverseKind::Refund,
                None,
                NOW
            )
            .await
            .unwrap(),
            ReverseOutcome::RecordedPending
        );
        let recorded = order(&db, &pending.id).await;
        assert_eq!(recorded.state, OrderState::Pending);
        assert_eq!(recorded.reversal_pending, Some(ReversalPending::Refund));

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 1)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::Reversed)
        );
        let voided = order(&db, &pending.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.void_reason, Some(VoidReason::Reversed));
        assert_eq!(voided.reversal_pending, None);
        assert_eq!(voided.payment_intent_id.as_deref(), Some("pi_1"));
        assert!(voided.lease_until.is_none());

        // Never applied: no membership, no badge, no number retired
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        assert_eq!(badge(&db, "u1").await, None);
        assert_eq!(
            cipher_me(&db, "u1", NOW + 2).await.unwrap().membership,
            None
        );
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);

        // The void asked for the rest under its own key; Stripe had nothing
        // left (charge_already_refunded), so one refund exists
        assert_eq!(
            refund_keys(&stripe),
            vec![
                ("pi_1".to_string(), Some("owner-refund".to_string())),
                ("pi_1".to_string(), Some(format!("void-{}", pending.id))),
            ]
        );
        assert_eq!(stripe.refund_count_for("pi_1"), 1);

        // A redelivered completion changes nothing
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 2)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::Reversed)
        );
        assert_eq!(stripe.refund_count_for("pi_1"), 1);
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        drop_db(&db).await;
    }

    /// The refund we have no record of yet (only the order's) is refunded
    /// by the void itself: a buyer refunded in part gets the rest back
    #[tokio::test]
    async fn a_recorded_refund_before_completion_refunds_what_is_left() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay(&stripe, &pending, "pi_part");

        // A partial refund at Stripe (the mock keeps no partial refunds, so
        // only the event is seen): the rest is still with us
        assert_eq!(
            reverse_order(
                &db,
                &stripe,
                &s,
                &pending.id,
                ReverseKind::Refund,
                None,
                NOW
            )
            .await
            .unwrap(),
            ReverseOutcome::RecordedPending
        );
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 1)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::Reversed)
        );
        assert_eq!(
            refund_keys(&stripe),
            vec![("pi_part".to_string(), Some(format!("void-{}", pending.id)))]
        );
        assert_eq!(stripe.refund_count_for("pi_part"), 1);
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_void_after_a_recorded_refund_refunds_only_what_is_left() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = PaymentsSettings {
            cap: 1,
            ..settings()
        };
        insert_user(&db, "a").await;
        insert_user(&db, "b").await;

        let a = checkout(&db, &stripe, &s, "a", CipherTier::T99, NOW).await;
        let b = checkout(&db, &stripe, &s, "b", CipherTier::T99, NOW).await;
        let session_a = pay(&stripe, &a, "pi_a");
        let session_b = pay(&stripe, &b, "pi_b");
        fulfil_order(&db, &stripe, &s, &a.id, &session_a, NOW)
            .await
            .unwrap();

        // b's payment was refunded in full by the owner at Stripe before its
        // completion was handled
        stripe.create_refund("pi_b", "owner-refund").await.unwrap();
        assert_eq!(
            reverse_order(&db, &stripe, &s, &b.id, ReverseKind::Refund, None, NOW)
                .await
                .unwrap(),
            ReverseOutcome::RecordedPending
        );
        // Voided for the recorded refund before any number is claimed (m4),
        // so the sold-out claim is never even tried
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &b.id, &session_b, NOW + 1)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::Reversed)
        );
        // The recorded refund may have been partial, so the void still asks
        // for the rest; Stripe has nothing left (charge_already_refunded),
        // which counts as done, and no second refund exists
        assert_eq!(
            refund_keys(&stripe),
            vec![
                ("pi_b".to_string(), Some("owner-refund".to_string())),
                ("pi_b".to_string(), Some(format!("void-{}", b.id))),
            ]
        );
        assert_eq!(stripe.refund_count_for("pi_b"), 1);
        let voided = order(&db, &b.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.reversal_pending, None);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_void_after_a_lost_dispute_never_refunds() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = PaymentsSettings {
            cap: 1,
            ..settings()
        };
        insert_user(&db, "a").await;
        insert_user(&db, "b").await;

        let a = checkout(&db, &stripe, &s, "a", CipherTier::T99, NOW).await;
        let b = checkout(&db, &stripe, &s, "b", CipherTier::T99, NOW).await;
        let session_a = pay(&stripe, &a, "pi_a");
        let session_b = pay(&stripe, &b, "pi_b");
        fulfil_order(&db, &stripe, &s, &a.id, &session_a, NOW)
            .await
            .unwrap();

        // A refund recorded, then the dispute lost: the lost dispute wins
        for kind in [ReverseKind::Refund, ReverseKind::DisputeLost] {
            assert_eq!(
                reverse_order(&db, &stripe, &s, &b.id, kind, None, NOW)
                    .await
                    .unwrap(),
                ReverseOutcome::RecordedPending
            );
        }
        assert_eq!(
            order(&db, &b.id).await.reversal_pending,
            Some(ReversalPending::DisputeLost)
        );
        // Voided for the lost dispute before any number is claimed (m4)
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &b.id, &session_b, NOW + 1)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::Reversed)
        );
        assert_eq!(stripe.call_count("create_refund"), 0);
        assert_eq!(order(&db, &b.id).await.reversal_pending, None);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_failed_or_canceled_void_refund_leaves_the_order_unvoided() {
        for status in ["failed", "canceled"] {
            let db = test_db().await;
            let stripe = MockStripe::new();
            let s = PaymentsSettings {
                cap: 1,
                ..settings()
            };
            insert_user(&db, "a").await;
            insert_user(&db, "b").await;

            // Both start before either is fulfilled; a takes the last number
            let a = checkout(&db, &stripe, &s, "a", CipherTier::T99, NOW).await;
            let b = checkout(&db, &stripe, &s, "b", CipherTier::T99, NOW).await;
            let session_a = pay(&stripe, &a, "pi_a");
            let session_b = pay(&stripe, &b, "pi_b");
            assert_eq!(
                fulfil_order(&db, &stripe, &s, &a.id, &session_a, NOW)
                    .await
                    .unwrap(),
                FulfilOutcome::Fulfilled
            );
            stripe.set_refund_status(status);
            assert!(matches!(
                error_type(fulfil_order(&db, &stripe, &s, &b.id, &session_b, NOW).await),
                ErrorType::PaymentProviderError
            ));

            // Paid, not voided, lease released: the next attempt retries
            let kept = order(&db, &b.id).await;
            assert_eq!(kept.state, OrderState::Paid, "{status}");
            assert_eq!(kept.void_reason, None, "{status}");
            assert!(kept.lease_until.is_none(), "{status}");
            assert_eq!(stripe.refund_count_for("pi_b"), 0, "{status}");
            assert!(db.fetch_cipher_membership("b").await.unwrap().is_none());

            // Stripe replays the same refund under the same key: still not
            // voided (the money never came back)
            assert!(resume_order(&db, &stripe, &s, &b.id, NOW + 1)
                .await
                .is_err());
            assert_eq!(order(&db, &b.id).await.state, OrderState::Paid);
            assert_eq!(stripe.call_count("create_refund"), 2, "{status}");
            drop_db(&db).await;
        }
    }

    #[tokio::test]
    async fn disputes_hide_the_badge_and_a_lost_one_revokes() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let bought = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_1", NOW).await;
        let reverse = |kind, at| on_dispute(&db, &bought.id, "dp_1", kind, at);

        assert_eq!(
            reverse(ReverseKind::DisputeOpened, NOW + 1).await.unwrap(),
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u1").await;
        assert!(m.is_active());
        assert_eq!(m.disputed_orders, vec![bought.id.clone()]);
        assert_eq!(badge(&db, "u1").await, None, "a dispute is never broadcast");
        let me = cipher_me(&db, "u1", NOW + 1).await.unwrap();
        assert!(me.membership.unwrap().disputed, "the owner sees it");

        // A redelivery changes nothing
        assert_eq!(
            reverse(ReverseKind::DisputeOpened, NOW + 2).await.unwrap(),
            ReverseOutcome::Applied
        );
        assert_eq!(membership(&db, "u1").await.disputed_orders.len(), 1);

        // Won (or warning_closed): the badge is back
        assert_eq!(
            reverse(ReverseKind::DisputeWon, NOW + 3).await.unwrap(),
            ReverseOutcome::Applied
        );
        assert!(membership(&db, "u1").await.disputed_orders.is_empty());
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T299));
        assert_eq!(order(&db, &bought.id).await.state, OrderState::Fulfilled);

        // Opened again and lost: revoked, order refunded, badge gone
        reverse(ReverseKind::DisputeOpened, NOW + 4).await.unwrap();
        assert_eq!(
            reverse(ReverseKind::DisputeLost, NOW + 5).await.unwrap(),
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u1").await;
        assert!(!m.is_active());
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::DisputeLost));
        assert_eq!(m.revoked_at, Some(NOW + 5));
        let lost = order(&db, &bought.id).await;
        assert_eq!(lost.state, OrderState::Refunded);
        assert_eq!(lost.reversed_at, Some(NOW + 5));
        assert_eq!(badge(&db, "u1").await, None);
        assert_eq!(
            cipher_me(&db, "u1", NOW + 5).await.unwrap().membership,
            None
        );

        // Anything after that is a no-op
        assert_eq!(
            reverse(ReverseKind::Refund, NOW + 6).await.unwrap(),
            ReverseOutcome::NoOp
        );
        assert_eq!(stripe.call_count("create_refund"), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn an_upgrade_is_refused_while_a_dispute_is_open() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_new", NOW).await;

        // Upgrade checkout started before the dispute, paid after it opened
        let upgrade = checkout(&db, &stripe, &s, "u1", CipherTier::T299, NOW).await;
        let session = pay(&stripe, &upgrade, "pi_up");
        assert_eq!(
            on_dispute(&db, &first.id, "dp_1", ReverseKind::DisputeOpened, NOW + 1)
                .await
                .unwrap(),
            ReverseOutcome::Applied
        );

        // At checkout
        let later = NOW + (SESSION_TTL_SECS + 60) * 1000;
        assert!(matches!(
            error_type(
                create_cipher_checkout(
                    &db,
                    &stripe,
                    &s,
                    "u1",
                    CipherTier::T149,
                    CipherReturnTo::Web,
                    later
                )
                .await
            ),
            ErrorType::CipherTierInvalid
        ));

        // At fulfilment
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &upgrade.id, &session, NOW + 2)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::DisputeOpen)
        );
        assert_eq!(
            refund_keys(&stripe),
            vec![("pi_up".to_string(), Some(format!("void-{}", upgrade.id)))]
        );
        let m = membership(&db, "u1").await;
        assert_eq!(m.tier, CipherTier::T99);
        assert_eq!(m.orders, vec![first.id]);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_dispute_on_a_paid_unfulfilled_order_is_recorded_and_never_badged() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");
        crash_after(&db, &pending.id, |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some("pi_1".to_string());
        })
        .await;
        let reverse = |kind, at| on_dispute(&db, &pending.id, "dp_1", kind, at);

        // Recorded on the Paid order under the lease
        assert_eq!(
            reverse(ReverseKind::DisputeOpened, LATER).await.unwrap(),
            ReverseOutcome::RecordedPending
        );
        let recorded = order(&db, &pending.id).await;
        assert_eq!(recorded.state, OrderState::Paid);
        assert_eq!(recorded.open_disputes, ["dp_1"]);
        assert_eq!(badge(&db, "u1").await, None);

        // Fulfilment adds the order already listed as disputed
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, LATER + 1)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        let m = membership(&db, "u1").await;
        assert!(m.is_active());
        assert_eq!(m.orders, vec![pending.id.clone()]);
        assert_eq!(m.disputed_orders, vec![pending.id.clone()]);
        assert_eq!(badge(&db, "u1").await, None);
        assert!(
            cipher_me(&db, "u1", LATER + 1)
                .await
                .unwrap()
                .membership
                .unwrap()
                .disputed
        );

        // A redelivery of the opening changes nothing
        assert_eq!(
            reverse(ReverseKind::DisputeOpened, LATER + 2)
                .await
                .unwrap(),
            ReverseOutcome::Applied
        );
        assert_eq!(membership(&db, "u1").await.disputed_orders.len(), 1);
        assert_eq!(badge(&db, "u1").await, None);

        // Won: the badge appears
        assert_eq!(
            reverse(ReverseKind::DisputeWon, LATER + 3).await.unwrap(),
            ReverseOutcome::Applied
        );
        assert!(order(&db, &pending.id).await.open_disputes.is_empty());
        assert!(membership(&db, "u1").await.disputed_orders.is_empty());
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_dispute_before_completion_keeps_the_badge_hidden_at_every_step() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T149, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");
        let reverse = |kind, at| on_dispute(&db, &pending.id, "dp_1", kind, at);

        // Opened while the order is still Pending
        assert_eq!(
            reverse(ReverseKind::DisputeOpened, NOW + 1).await.unwrap(),
            ReverseOutcome::RecordedPending
        );
        let recorded = order(&db, &pending.id).await;
        assert_eq!(recorded.state, OrderState::Pending);
        assert_eq!(recorded.open_disputes, ["dp_1"]);
        assert!(recorded.reversal_pending.is_none());
        assert_eq!(badge(&db, "u1").await, None);

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 2)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        let m = membership(&db, "u1").await;
        assert_eq!((m.number, m.tier), (1, CipherTier::T149));
        assert_eq!(m.disputed_orders, vec![pending.id.clone()]);
        assert_eq!(badge(&db, "u1").await, None);

        // A duplicate completion re-asserts the badge: still hidden
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 3)
                .await
                .unwrap(),
            FulfilOutcome::AlreadyFulfilled
        );
        assert_eq!(badge(&db, "u1").await, None);

        assert_eq!(
            reverse(ReverseKind::DisputeWon, NOW + 4).await.unwrap(),
            ReverseOutcome::Applied
        );
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T149));
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_dispute_won_before_completion_badges_normally() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");
        for kind in [ReverseKind::DisputeOpened, ReverseKind::DisputeWon] {
            assert_eq!(
                on_dispute(&db, &pending.id, "dp_1", kind, NOW)
                    .await
                    .unwrap(),
                ReverseOutcome::RecordedPending
            );
            assert_eq!(badge(&db, "u1").await, None);
        }
        assert!(order(&db, &pending.id).await.open_disputes.is_empty());

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 1)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        assert!(membership(&db, "u1").await.disputed_orders.is_empty());
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));
        drop_db(&db).await;
    }

    /// A lost dispute before the completion: voided instead of applied
    /// (m4), never refunded (the money is already back with the buyer), no
    /// number claimed and no badge, ever
    #[tokio::test]
    async fn a_dispute_lost_before_completion_voids_without_a_refund_or_a_badge() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");
        // Opened, then lost before the completion
        for kind in [ReverseKind::DisputeOpened, ReverseKind::DisputeLost] {
            assert_eq!(
                on_dispute(&db, &pending.id, "dp_1", kind, NOW)
                    .await
                    .unwrap(),
                ReverseOutcome::RecordedPending
            );
        }
        let recorded = order(&db, &pending.id).await;
        // The lost dispute is closed, but its pending reversal keeps the
        // order disputed until the membership is revoked
        assert!(recorded.open_disputes.is_empty());
        assert!(is_disputed(&recorded));
        assert_eq!(
            recorded.reversal_pending,
            Some(ReversalPending::DisputeLost)
        );

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 1)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::Reversed)
        );
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        let voided = order(&db, &pending.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.void_reason, Some(VoidReason::Reversed));
        assert_eq!(voided.reversal_pending, None);
        assert_eq!(badge(&db, "u1").await, None);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        assert_eq!(stripe.call_count("create_refund"), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_disputed_upgrade_keeps_the_number_and_hides_the_badge_until_won() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_new", NOW).await;
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));

        // The upgrade's own payment is disputed before its completion
        let upgrade = checkout(&db, &stripe, &s, "u1", CipherTier::T299, NOW).await;
        let session = pay(&stripe, &upgrade, "pi_up");
        let reverse = |kind, at| on_dispute(&db, &upgrade.id, "dp_1", kind, at);
        assert_eq!(
            reverse(ReverseKind::DisputeOpened, NOW + 1).await.unwrap(),
            ReverseOutcome::RecordedPending
        );
        // The existing badge is untouched until the upgrade applies
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &upgrade.id, &session, NOW + 2)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        let m = membership(&db, "u1").await;
        assert_eq!((m.number, m.tier), (1, CipherTier::T299));
        assert_eq!(m.orders, vec![first.id.clone(), upgrade.id.clone()]);
        assert_eq!(m.disputed_orders, vec![upgrade.id.clone()]);
        assert_eq!(badge(&db, "u1").await, None);
        assert_eq!(stripe.call_count("create_refund"), 0);

        assert_eq!(
            reverse(ReverseKind::DisputeWon, NOW + 3).await.unwrap(),
            ReverseOutcome::Applied
        );
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T299));
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_dispute_after_a_crashed_membership_write_hides_the_badge_at_once() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        pay(&stripe, &pending, "pi_1");
        // A worker marked it Paid, wrote the membership (undisputed then),
        // published the badge and died holding the lease
        crash_after(&db, &pending.id, |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some("pi_1".to_string());
        })
        .await;
        let number = db
            .claim_cipher_number(&pending.id, s.cap)
            .await
            .unwrap()
            .unwrap();
        assert!(db
            .insert_cipher_membership(&CipherMembership {
                user_id: "u1".to_string(),
                number,
                tier: CipherTier::T99,
                prot_grant: 16_500,
                orders: vec![pending.id.clone()],
                disputed_orders: vec![],
                granted_at: NOW,
                revoked_at: None,
                revoke_reason: None,
                prot_posted_at: None,
                version: 0,
            })
            .await
            .unwrap());
        sync_user_badge(&db, "u1").await.unwrap();
        assert_eq!(badge(&db, "u1").await, badge_of(number, CipherTier::T99));

        // The dispute opens on the Paid order once the lease ran out: it is
        // recorded on the order and mirrored into the membership at once
        assert_eq!(
            on_dispute(&db, &pending.id, "dp_1", ReverseKind::DisputeOpened, LATER)
                .await
                .unwrap(),
            ReverseOutcome::RecordedPending
        );
        assert_eq!(order(&db, &pending.id).await.open_disputes, ["dp_1"]);
        assert_eq!(
            membership(&db, "u1").await.disputed_orders,
            vec![pending.id.clone()]
        );
        assert_eq!(badge(&db, "u1").await, None);

        // The resume finds the order applied and keeps it listed
        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, LATER + 1)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        assert_eq!(
            membership(&db, "u1").await.disputed_orders,
            vec![pending.id.clone()]
        );
        assert_eq!(badge(&db, "u1").await, None);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_dispute_is_read_inside_the_lease_and_must_be_on_the_orders_payment() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");
        let dispute = |payment_intent: &str, status: &str| Dispute {
            id: "dp_1".to_string(),
            status: Some(status.to_string()),
            payment_intent: Some(payment_intent.to_string()),
        };
        let intent_naming = |order_id: &str| PaymentIntent {
            id: "pi_1".to_string(),
            metadata_order_id: Some(order_id.to_string()),
            ..Default::default()
        };

        // Not paid on our side yet: the disputed payment must name the order
        stripe.set_dispute(dispute("pi_1", "needs_response"));
        stripe.set_payment_intent(intent_naming("01OTHERORDER00000000000000"));
        assert!(reverse_dispute(&db, &stripe, &s, &pending.id, "dp_1", NOW)
            .await
            .is_err());
        let untouched = order(&db, &pending.id).await;
        assert!(untouched.open_disputes.is_empty());
        assert!(untouched.lease_until.is_none());

        stripe.set_payment_intent(intent_naming(&pending.id));
        assert_eq!(
            reverse_dispute(&db, &stripe, &s, &pending.id, "dp_1", NOW + 1)
                .await
                .unwrap(),
            ReverseOutcome::RecordedPending
        );
        assert_eq!(order(&db, &pending.id).await.open_disputes, ["dp_1"]);

        // A held lease: Busy, and Stripe is not asked
        let lookups = stripe.call_count("get_dispute");
        let held = db
            .acquire_payment_order_lease(&pending.id, NOW + 2, NOW + 2 + LEASE_MS)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            reverse_dispute(&db, &stripe, &s, &pending.id, "dp_1", NOW + 3)
                .await
                .unwrap(),
            ReverseOutcome::Busy
        );
        assert_eq!(stripe.call_count("get_dispute"), lookups);
        db.release_payment_order_lease(&pending.id, held.lease_until.unwrap())
            .await
            .unwrap();

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 4)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        assert_eq!(badge(&db, "u1").await, None);

        // Paid: the stored payment must be the disputed one
        stripe.set_dispute(dispute("pi_other", "won"));
        assert!(
            reverse_dispute(&db, &stripe, &s, &pending.id, "dp_1", NOW + 5)
                .await
                .is_err()
        );
        assert_eq!(badge(&db, "u1").await, None);

        // Unknown at Stripe: an error, never a guess
        assert!(
            reverse_dispute(&db, &stripe, &s, &pending.id, "dp_unknown", NOW + 6)
                .await
                .is_err()
        );
        assert_eq!(badge(&db, "u1").await, None);

        stripe.set_dispute(dispute("pi_1", "won"));
        assert_eq!(
            reverse_dispute(&db, &stripe, &s, &pending.id, "dp_1", NOW + 7)
                .await
                .unwrap(),
            ReverseOutcome::Applied
        );
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn an_opened_or_won_dispute_without_its_id_is_refused() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let bought = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        on_dispute(&db, &bought.id, "dp_1", ReverseKind::DisputeOpened, NOW + 1)
            .await
            .unwrap();

        // Nothing can close (or open) a dispute without naming it
        for kind in [ReverseKind::DisputeWon, ReverseKind::DisputeOpened] {
            assert!(matches!(
                error_type(reverse_order(&db, &stripe, &s, &bought.id, kind, None, NOW + 2).await),
                ErrorType::InternalError
            ));
        }
        assert_eq!(order(&db, &bought.id).await.open_disputes, ["dp_1"]);
        assert_eq!(
            membership(&db, "u1").await.disputed_orders,
            vec![bought.id.clone()]
        );
        assert_eq!(badge(&db, "u1").await, None);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn two_disputes_before_completion_are_closed_by_their_own_id() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");
        let dispute = |id: &'static str, kind, at| on_dispute(&db, &pending.id, id, kind, at);

        // An inquiry and a chargeback on the same payment, then the inquiry
        // closes in our favor
        dispute("dp_inquiry", ReverseKind::DisputeOpened, NOW + 1)
            .await
            .unwrap();
        dispute("dp_chargeback", ReverseKind::DisputeOpened, NOW + 2)
            .await
            .unwrap();
        assert_eq!(
            order(&db, &pending.id).await.open_disputes,
            ["dp_inquiry", "dp_chargeback"]
        );
        dispute("dp_inquiry", ReverseKind::DisputeWon, NOW + 3)
            .await
            .unwrap();
        assert_eq!(
            order(&db, &pending.id).await.open_disputes,
            ["dp_chargeback"]
        );

        // Fulfilled while the chargeback is open: listed, no badge
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 4)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        assert_eq!(
            membership(&db, "u1").await.disputed_orders,
            vec![pending.id.clone()]
        );
        assert_eq!(badge(&db, "u1").await, None);

        // A late repeat of the inquiry's close changes nothing
        dispute("dp_inquiry", ReverseKind::DisputeWon, NOW + 5)
            .await
            .unwrap();
        assert_eq!(badge(&db, "u1").await, None);

        // The chargeback is won: the badge appears
        dispute("dp_chargeback", ReverseKind::DisputeWon, NOW + 6)
            .await
            .unwrap();
        assert!(order(&db, &pending.id).await.open_disputes.is_empty());
        assert!(membership(&db, "u1").await.disputed_orders.is_empty());
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_void_waits_while_a_dispute_is_open_and_refunds_once_it_is_won() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = PaymentsSettings {
            cap: 1,
            ..settings()
        };
        insert_user(&db, "a").await;
        insert_user(&db, "b").await;

        // a takes the last number; b paid too and is disputed before its
        // completion is handled
        let a = checkout(&db, &stripe, &s, "a", CipherTier::T99, NOW).await;
        let b = checkout(&db, &stripe, &s, "b", CipherTier::T99, NOW).await;
        let session_a = pay(&stripe, &a, "pi_a");
        let session_b = pay(&stripe, &b, "pi_b");
        fulfil_order(&db, &stripe, &s, &a.id, &session_a, NOW)
            .await
            .unwrap();
        on_dispute(&db, &b.id, "dp_b", ReverseKind::DisputeOpened, NOW)
            .await
            .unwrap();

        // Sold out, but not refunded while the dispute is open
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &b.id, &session_b, NOW + 1)
                .await
                .unwrap(),
            FulfilOutcome::VoidDeferred(VoidReason::SoldOut)
        );
        assert_eq!(
            resume_order(&db, &stripe, &s, &b.id, NOW + 2)
                .await
                .unwrap(),
            FulfilOutcome::VoidDeferred(VoidReason::SoldOut)
        );
        let waiting = order(&db, &b.id).await;
        assert_eq!(waiting.state, OrderState::Paid);
        assert_eq!(waiting.void_reason, None);
        assert!(waiting.lease_until.is_none());
        assert_eq!(stripe.call_count("create_refund"), 0);
        assert!(db.fetch_cipher_membership("b").await.unwrap().is_none());

        // Won: the next attempt voids and refunds, once
        on_dispute(&db, &b.id, "dp_b", ReverseKind::DisputeWon, NOW + 3)
            .await
            .unwrap();
        assert_eq!(
            resume_order(&db, &stripe, &s, &b.id, NOW + 4)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::SoldOut)
        );
        assert_eq!(
            refund_keys(&stripe),
            vec![("pi_b".to_string(), Some(format!("void-{}", b.id)))]
        );
        assert_eq!(stripe.refund_count_for("pi_b"), 1);
        assert_eq!(order(&db, &b.id).await.state, OrderState::Voided);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_void_waiting_on_a_dispute_that_is_lost_never_refunds() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = PaymentsSettings {
            cap: 1,
            ..settings()
        };
        insert_user(&db, "a").await;
        insert_user(&db, "b").await;

        let a = checkout(&db, &stripe, &s, "a", CipherTier::T99, NOW).await;
        let b = checkout(&db, &stripe, &s, "b", CipherTier::T99, NOW).await;
        let session_a = pay(&stripe, &a, "pi_a");
        let session_b = pay(&stripe, &b, "pi_b");
        fulfil_order(&db, &stripe, &s, &a.id, &session_a, NOW)
            .await
            .unwrap();

        // An inquiry and a chargeback on b's payment
        for id in ["dp_inquiry", "dp_chargeback"] {
            on_dispute(&db, &b.id, id, ReverseKind::DisputeOpened, NOW)
                .await
                .unwrap();
        }
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &b.id, &session_b, NOW + 1)
                .await
                .unwrap(),
            FulfilOutcome::VoidDeferred(VoidReason::SoldOut)
        );

        // The chargeback is lost (the inquiry is still open): the money is
        // already back with the buyer, so the void goes ahead unrefunded
        on_dispute(
            &db,
            &b.id,
            "dp_chargeback",
            ReverseKind::DisputeLost,
            NOW + 2,
        )
        .await
        .unwrap();
        // The lost dispute is now recorded: voided for it (m4), before the
        // sold-out claim
        assert_eq!(
            resume_order(&db, &stripe, &s, &b.id, NOW + 3)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::Reversed)
        );
        assert_eq!(stripe.call_count("create_refund"), 0);
        let voided = order(&db, &b.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.reversal_pending, None);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_fulfil_that_lost_its_lease_never_publishes_a_badge_from_a_stale_read() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        pay(&stripe, &pending, "pi_1");

        // Worker A leases the order and marks it Paid, then stalls
        let mut a = acquire(&db, &pending.id, NOW).await.unwrap().unwrap();
        write(&db, &mut a, |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some("pi_1".to_string());
        })
        .await
        .unwrap();

        // Its lease runs out; a dispute handler takes the order over and
        // records the dispute. The membership does not hold the order yet,
        // so there is nothing to list.
        assert_eq!(
            on_dispute(&db, &pending.id, "dp_1", ReverseKind::DisputeOpened, LATER)
                .await
                .unwrap(),
            ReverseOutcome::RecordedPending
        );
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());

        // A wakes up and writes the membership from its stale copy, which
        // knows of no dispute: unlisted
        assert!(matches!(
            apply_membership(&db, &s, &a.order, "u1", LATER + 1)
                .await
                .unwrap(),
            Applied::Done
        ));
        assert!(membership(&db, "u1").await.disputed_orders.is_empty());

        // Publishing is refused, and the stored order's dispute is listed
        assert!(matches!(
            error_type(publish_badge(&db, &mut a, "u1").await),
            ErrorType::InternalError
        ));
        assert_eq!(
            membership(&db, "u1").await.disputed_orders,
            vec![pending.id.clone()]
        );
        assert_eq!(badge(&db, "u1").await, None);

        // The resume finishes it, still hidden; the win shows the badge
        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, LATER + 2)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        assert_eq!(badge(&db, "u1").await, None);
        on_dispute(&db, &pending.id, "dp_1", ReverseKind::DisputeWon, LATER + 3)
            .await
            .unwrap();
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_refund_on_an_expired_order_is_honoured_by_a_late_fulfil() {
        // The late fulfil voids it rather than applying it (m4)
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");
        expire_order(&db, &pending.id, NOW + 1).await.unwrap();
        assert_eq!(order(&db, &pending.id).await.state, OrderState::Expired);

        assert_eq!(
            reverse_order(
                &db,
                &stripe,
                &s,
                &pending.id,
                ReverseKind::Refund,
                None,
                NOW + 2
            )
            .await
            .unwrap(),
            ReverseOutcome::RecordedPending
        );
        assert_eq!(
            order(&db, &pending.id).await.reversal_pending,
            Some(ReversalPending::Refund)
        );

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 3)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::Reversed)
        );
        assert_eq!(order(&db, &pending.id).await.state, OrderState::Voided);
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        assert_eq!(badge(&db, "u1").await, None);
        drop_db(&db).await;
    }

    /// m3: a membership another order made active after the preconditions
    /// were read is seen right before the claim, so no number is retired
    /// for an order that is then voided Stale
    #[tokio::test]
    async fn a_membership_that_appears_before_the_claim_is_stale_without_a_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_first", NOW).await;
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);

        // A second new purchase of u1 that passed its preconditions while
        // the first was still being applied
        let second = PaymentOrder {
            id: Ulid::new().to_string(),
            sku: Sku::CipherNew {
                tier: CipherTier::T149,
            },
            amount_cents: 14_900,
            checkout_session_id: None,
            checkout_url: None,
            payment_intent_id: Some("pi_second".to_string()),
            state: OrderState::Paid,
            ..first.clone()
        };
        assert!(matches!(
            apply_membership(&db, &s, &second, "u1", NOW + 1)
                .await
                .unwrap(),
            Applied::Void(VoidReason::Stale)
        ));
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);
        assert_eq!(
            db.fetch_cipher_number_by_order(&second.id).await.unwrap(),
            None
        );
        let m = membership(&db, "u1").await;
        assert_eq!(m.orders, vec![first.id.clone()]);
        assert_eq!(m.tier, CipherTier::T99);

        // Control: the same order for a buyer without a membership claims
        insert_user(&db, "u2").await;
        let fresh = PaymentOrder {
            id: Ulid::new().to_string(),
            user_id: Some("u2".to_string()),
            ..second.clone()
        };
        assert!(matches!(
            apply_membership(&db, &s, &fresh, "u2", NOW + 2)
                .await
                .unwrap(),
            Applied::Done
        ));
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 2);
        drop_db(&db).await;
    }

    /// m7: a voided order paid late with a dispute on record is not
    /// refunded (a refund then could pay the buyer twice). It goes back to
    /// Paid with its void reason, waits, and the resume refunds it once the
    /// dispute is won at Stripe, with no close event delivered.
    #[tokio::test]
    async fn a_late_payment_of_a_voided_order_waits_on_its_dispute_then_refunds_once() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay(&stripe, &pending, "pi_late");
        stripe.set_payment_intent(PaymentIntent {
            id: "pi_late".to_string(),
            livemode: false,
            metadata_order_id: Some(pending.id.clone()),
            ..Default::default()
        });
        let dispute = |status: &str| Dispute {
            id: "dp_late".to_string(),
            status: Some(status.to_string()),
            payment_intent: Some("pi_late".to_string()),
        };

        // Disputed before its completion is handled, then the buyer's
        // account is deleted, which voids the unpaid-looking order
        assert_eq!(
            on_dispute(
                &db,
                &pending.id,
                "dp_late",
                ReverseKind::DisputeOpened,
                NOW + 1
            )
            .await
            .unwrap(),
            ReverseOutcome::RecordedPending
        );
        on_account_deleted(&db, &stripe, &s, "u1", NOW + 2)
            .await
            .unwrap();
        let voided = order(&db, &pending.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.void_reason, Some(VoidReason::AccountDeleted));

        // The completion arrives while the dispute is open: not refunded
        stripe.set_dispute(dispute("needs_response"));
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 3)
                .await
                .unwrap(),
            FulfilOutcome::VoidDeferred(VoidReason::AccountDeleted)
        );
        let waiting = order(&db, &pending.id).await;
        assert_eq!(waiting.state, OrderState::Paid);
        assert_eq!(waiting.void_reason, Some(VoidReason::AccountDeleted));
        assert_eq!(waiting.payment_intent_id.as_deref(), Some("pi_late"));
        assert_eq!(waiting.open_disputes, ["dp_late"]);
        assert!(waiting.lease_until.is_none());
        assert_eq!(stripe.call_count("create_refund"), 0);

        // Still open at the next resume: still waiting
        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, NOW + 4)
                .await
                .unwrap(),
            FulfilOutcome::VoidDeferred(VoidReason::AccountDeleted)
        );
        assert_eq!(stripe.call_count("create_refund"), 0);

        // Won at Stripe; its close event never arrives. The resume reads it
        // and refunds, once.
        stripe.set_dispute(dispute("won"));
        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, NOW + 5)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert_eq!(
            refund_keys(&stripe),
            vec![("pi_late".to_string(), Some(format!("void-{}", pending.id)))]
        );
        let done = order(&db, &pending.id).await;
        assert_eq!(done.state, OrderState::Voided);
        assert!(done.open_disputes.is_empty());
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());

        // A redelivered completion changes nothing
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 6)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert_eq!(stripe.refund_count_for("pi_late"), 1);
        drop_db(&db).await;
    }

    /// m7, the other way: the dispute on the late payment is lost, so the
    /// money is back with the buyer and the void never refunds
    #[tokio::test]
    async fn a_late_payment_of_a_voided_order_whose_dispute_is_lost_never_refunds() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay(&stripe, &pending, "pi_lost");
        stripe.set_payment_intent(PaymentIntent {
            id: "pi_lost".to_string(),
            livemode: false,
            metadata_order_id: Some(pending.id.clone()),
            ..Default::default()
        });
        on_dispute(
            &db,
            &pending.id,
            "dp_lost",
            ReverseKind::DisputeOpened,
            NOW + 1,
        )
        .await
        .unwrap();
        on_account_deleted(&db, &stripe, &s, "u1", NOW + 2)
            .await
            .unwrap();

        // Already lost by the time the completion is handled
        stripe.set_dispute(Dispute {
            id: "dp_lost".to_string(),
            status: Some("lost".to_string()),
            payment_intent: Some("pi_lost".to_string()),
        });
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 3)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert_eq!(stripe.call_count("create_refund"), 0);
        let voided = order(&db, &pending.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.reversal_pending, None);
        drop_db(&db).await;
    }

    /// Planned 2: until the owner sets a Terms of Service URL in the
    /// Dashboard, Stripe refuses a session that asks for Terms consent.
    /// The checkout fails cleanly: PaymentProviderError, the order
    /// SessionFailed (not stuck Creating), and the next checkout is free to
    /// go once Stripe accepts it.
    #[tokio::test]
    async fn a_session_stripe_refuses_fails_the_checkout_and_never_blocks_the_next() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        stripe.fail_next(
            "create_checkout_session",
            StripeError::Api {
                status: 400,
                code: None,
                kind: Some("invalid_request_error".to_string()),
                message: "You must set a Terms of Service URL in your public business details \
                          to collect terms of service consent."
                    .to_string(),
            },
        );
        assert!(matches!(
            error_type(
                create_cipher_checkout(
                    &db,
                    &stripe,
                    &s,
                    "u1",
                    CipherTier::T99,
                    CipherReturnTo::Web,
                    NOW
                )
                .await
            ),
            ErrorType::PaymentProviderError
        ));

        let failed = db
            .fetch_payment_orders_by_user("u1", &[OrderState::SessionFailed])
            .await
            .unwrap();
        assert_eq!(failed.len(), 1);
        assert!(failed[0].checkout_url.is_none());
        assert!(failed[0].lease_until.is_none());
        assert!(db
            .fetch_payment_orders_by_user("u1", &[OrderState::Creating, OrderState::Pending])
            .await
            .unwrap()
            .is_empty());
        assert_eq!(cipher_me(&db, "u1", NOW).await.unwrap().pending, None);

        // Stripe accepts the next one: the failed order never blocks it
        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW + 1).await;
        assert_ne!(pending.id, failed[0].id);
        assert!(cipher_me(&db, "u1", NOW + 1)
            .await
            .unwrap()
            .pending
            .is_some());
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_revoked_member_who_buys_again_gets_a_new_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;
        // Refunded after the release window: revoked, number retired
        assert_eq!(
            reverse_order(
                &db,
                &stripe,
                &s,
                &first.id,
                ReverseKind::Refund,
                full_refund(AFTER_WINDOW),
                AFTER_WINDOW
            )
            .await
            .unwrap(),
            ReverseOutcome::Applied
        );
        assert_eq!(badge(&db, "u1").await, None);

        // The revoked row does not block a new purchase, and is not an upgrade
        let again = buy(
            &db,
            &stripe,
            &s,
            "u1",
            CipherTier::T149,
            "pi_3",
            AFTER_WINDOW + 1,
        )
        .await;
        assert_eq!(
            again.sku,
            Sku::CipherNew {
                tier: CipherTier::T149
            }
        );
        let m = membership(&db, "u1").await;
        assert!(m.is_active());
        assert_eq!((m.number, m.tier), (3, CipherTier::T149));
        assert_eq!(m.orders, vec![again.id.clone()]);
        assert_eq!(m.granted_at, AFTER_WINDOW + 1);
        assert_eq!(m.revoke_reason, None);
        assert_eq!(badge(&db, "u1").await, badge_of(3, CipherTier::T149));

        // #1 stays retired and counted
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 3);
        assert_eq!(order(&db, &first.id).await.state, OrderState::Refunded);
        assert_eq!(stripe.call_count("create_refund"), 0);
        drop_db(&db).await;
    }

    // --- checkout -----------------------------------------------------

    #[tokio::test]
    async fn one_live_checkout_per_user_and_failed_sessions_never_block() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let start = |tier, at| {
            create_cipher_checkout(&db, &stripe, &s, "u1", tier, CipherReturnTo::Shell, at)
        };

        // A provider failure leaves the order SessionFailed
        stripe.fail_next(
            "create_checkout_session",
            StripeError::Transport("timeout".to_string()),
        );
        assert!(matches!(
            error_type(start(CipherTier::T99, NOW).await),
            ErrorType::PaymentProviderError
        ));
        let failed = db
            .fetch_payment_orders_by_user("u1", &[OrderState::SessionFailed])
            .await
            .unwrap();
        assert_eq!(failed.len(), 1);
        assert!(failed[0].lease_until.is_none());

        // ... and does not block the retry
        let url = start(CipherTier::T99, NOW + 1).await.unwrap();
        assert_eq!(
            stripe.checkout_params().last().unwrap().success_url,
            s.success_url_shell
        );

        // The same tier again returns the live session; another tier waits
        assert_eq!(start(CipherTier::T99, NOW + 2).await.unwrap(), url);
        assert!(matches!(
            error_type(start(CipherTier::T299, NOW + 3).await),
            ErrorType::PaymentPending
        ));
        assert_eq!(stripe.checkout_params().len(), 1);

        let me = cipher_me(&db, "u1", NOW + 3).await.unwrap();
        let pending = me.pending.expect("pending checkout");
        assert_eq!(
            pending.sku,
            Sku::CipherNew {
                tier: CipherTier::T99
            }
        );
        assert_eq!(pending.expires_at, (NOW / 1000 + SESSION_TTL_SECS) * 1000);

        // Once the session has expired, a new checkout starts
        let after = pending.expires_at + 1;
        let next = start(CipherTier::T299, after).await.unwrap();
        assert_ne!(next, url);
        assert_eq!(stripe.checkout_params().len(), 2);
        assert_eq!(stripe.checkout_params()[1].amount_cents, 29_900);

        // Expiry of the newest one
        let newest = db
            .fetch_payment_orders_by_user("u1", &[OrderState::Pending])
            .await
            .unwrap()
            .pop()
            .unwrap();
        expire_order(&db, &newest.id, after + 1).await.unwrap();
        assert_eq!(order(&db, &newest.id).await.state, OrderState::Expired);
        assert_eq!(cipher_me(&db, "u1", after + 1).await.unwrap().pending, None);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_checkout_in_flight_blocks_a_second_one() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        db.insert_payment_order(&PaymentOrder {
            id: "01INFLIGHT0000000000000000".to_string(),
            user_id: Some("u1".to_string()),
            provider: PaymentProvider::Stripe,
            sku: Sku::CipherNew {
                tier: CipherTier::T99,
            },
            amount_cents: 9_900,
            currency: "usd".to_string(),
            checkout_session_id: None,
            checkout_url: None,
            session_expires_at: None,
            payment_intent_id: None,
            state: OrderState::Creating,
            void_reason: None,
            region_blocked_country: None,
            reversal_pending: None,
            refund_settling_since: None,
            open_disputes: vec![],
            lease_until: None,
            version: 0,
            created_at: NOW,
            paid_at: None,
            fulfilled_at: None,
            reversed_at: None,
        })
        .await
        .unwrap();

        assert!(matches!(
            error_type(
                create_cipher_checkout(
                    &db,
                    &stripe,
                    &s,
                    "u1",
                    CipherTier::T99,
                    CipherReturnTo::Web,
                    NOW + MINUTE
                )
                .await
            ),
            ErrorType::PaymentPending
        ));
        // A Creating order stranded by a crash does not block for long
        create_cipher_checkout(
            &db,
            &stripe,
            &s,
            "u1",
            CipherTier::T99,
            CipherReturnTo::Web,
            NOW + 3 * MINUTE,
        )
        .await
        .unwrap();
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_session_in_the_wrong_mode_is_never_handed_out() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        // A live key in a test-mode config: the buyer would pay into events
        // we ignore
        stripe.set_livemode(true);
        assert!(matches!(
            error_type(
                create_cipher_checkout(
                    &db,
                    &stripe,
                    &s,
                    "u1",
                    CipherTier::T99,
                    CipherReturnTo::Web,
                    NOW
                )
                .await
            ),
            ErrorType::PaymentProviderError
        ));
        assert_eq!(
            db.fetch_payment_orders_by_user("u1", &[OrderState::SessionFailed])
                .await
                .unwrap()
                .len(),
            1
        );
        drop_db(&db).await;
    }

    // --- session checks -----------------------------------------------

    #[tokio::test]
    async fn a_mismatched_or_unpaid_session_changes_nothing() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T149, NOW).await;
        let paid = pay(&stripe, &pending, "pi_1");

        // Not provably ours (the wrong amount or currency on our own paid
        // session is refunded instead: see the AmountMismatch tests)
        let cases = [
            CheckoutSession {
                livemode: true,
                ..paid.clone()
            },
            // The other livemode outranks a wrong amount: not ours to settle
            CheckoutSession {
                livemode: true,
                currency: Some("eur".to_string()),
                ..paid.clone()
            },
            // Wrong amount and no metadata naming the order
            CheckoutSession {
                amount_total: Some(100),
                metadata_order_id: None,
                ..paid.clone()
            },
            // Our session, the wrong amount, but nothing was paid
            CheckoutSession {
                amount_total: Some(100),
                payment_status: Some("unpaid".to_string()),
                ..paid.clone()
            },
            CheckoutSession {
                id: "cs_test_other".to_string(),
                ..paid.clone()
            },
            CheckoutSession {
                metadata_order_id: Some("01OTHERORDER00000000000000".to_string()),
                ..paid.clone()
            },
            CheckoutSession {
                client_reference_id: Some("someone_else".to_string()),
                ..paid.clone()
            },
        ];
        for (i, session) in cases.iter().enumerate() {
            assert_eq!(
                fulfil_order(&db, &stripe, &s, &pending.id, session, NOW)
                    .await
                    .unwrap(),
                FulfilOutcome::Ignored,
                "case {i}"
            );
        }

        let unpaid = CheckoutSession {
            payment_status: Some("unpaid".to_string()),
            ..paid.clone()
        };
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &unpaid, NOW)
                .await
                .unwrap(),
            FulfilOutcome::NotPaid
        );

        let stored = order(&db, &pending.id).await;
        assert_eq!(stored.state, OrderState::Pending);
        assert!(stored.payment_intent_id.is_none());
        assert!(stored.lease_until.is_none());
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        assert_eq!(stripe.call_count("create_refund"), 0);

        // The real one still applies
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &paid, NOW)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );

        // A different payment intent for the now-paid order is not ours
        let other_intent = CheckoutSession {
            payment_intent: Some("pi_other".to_string()),
            ..paid
        };
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &other_intent, NOW)
                .await
                .unwrap(),
            FulfilOutcome::AlreadyFulfilled
        );
        assert_eq!(
            order(&db, &pending.id).await.payment_intent_id.as_deref(),
            Some("pi_1")
        );
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn our_session_paid_in_another_currency_is_voided_and_refunded_once() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T149, NOW).await;
        let mut session = pay(&stripe, &pending, "pi_eur");
        // Stripe converted the price (e.g. Adaptive Pricing): settled in EUR
        session.currency = Some("eur".to_string());
        session.amount_total = Some(13_700);
        stripe.set_session(session.clone());

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AmountMismatch)
        );
        let voided = order(&db, &pending.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.void_reason, Some(VoidReason::AmountMismatch));
        assert_eq!(voided.payment_intent_id.as_deref(), Some("pi_eur"));
        assert!(voided.lease_until.is_none());
        assert_eq!(
            refund_keys(&stripe),
            vec![("pi_eur".to_string(), Some(format!("void-{}", pending.id)))]
        );
        assert_eq!(stripe.refund_count_for("pi_eur"), 1);
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        assert_eq!(badge(&db, "u1").await, None);

        // Redelivered, and resumed from Stripe's copy: no second refund
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + MINUTE)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AmountMismatch)
        );
        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, NOW + 2 * MINUTE)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AmountMismatch)
        );
        assert_eq!(stripe.call_count("create_refund"), 1);
        assert_eq!(stripe.refund_count(), 1);

        // Our own refund comes back as charge.refunded: nothing to do
        assert_eq!(
            reverse_order(
                &db,
                &stripe,
                &s,
                &pending.id,
                ReverseKind::Refund,
                None,
                NOW + 3 * MINUTE
            )
            .await
            .unwrap(),
            ReverseOutcome::NoOp
        );
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn our_session_paid_in_another_amount_is_voided_and_refunded() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let mut session = pay(&stripe, &pending, "pi_short");
        session.amount_total = Some(100);
        stripe.set_session(session.clone());

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AmountMismatch)
        );
        assert_eq!(stripe.refund_count_for("pi_short"), 1);
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        drop_db(&db).await;
    }

    // --- account deletion, stats, badge -------------------------------

    #[tokio::test]
    async fn account_deletion_voids_unlinks_and_deletes_the_membership() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        // u1: a fulfilled purchase and an open upgrade checkout
        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let open = checkout(&db, &stripe, &s, "u1", CipherTier::T299, NOW).await;

        // u2: paid, fulfilment died before applying it
        let paid = checkout(&db, &stripe, &s, "u2", CipherTier::T99, NOW).await;
        let paid_session = pay(&stripe, &paid, "pi_2");
        crash_after(&db, &paid.id, |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some("pi_2".to_string());
        })
        .await;

        on_account_deleted(&db, &stripe, &s, "u1", LATER)
            .await
            .unwrap();
        on_account_deleted(&db, &stripe, &s, "u2", LATER)
            .await
            .unwrap();

        // Fulfilled stays (it is the payment record), unlinked, not refunded
        let kept = order(&db, &first.id).await;
        assert_eq!(kept.state, OrderState::Fulfilled);
        assert!(kept.user_id.is_none());
        assert_eq!(stripe.refund_count_for("pi_1"), 0);

        let voided = order(&db, &open.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.void_reason, Some(VoidReason::AccountDeleted));
        assert!(voided.user_id.is_none());

        let refunded = order(&db, &paid.id).await;
        assert_eq!(refunded.state, OrderState::Voided);
        assert_eq!(refunded.void_reason, Some(VoidReason::AccountDeleted));
        assert_eq!(
            refund_keys(&stripe),
            vec![("pi_2".to_string(), Some(format!("void-{}", paid.id)))]
        );

        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        for user in ["u1", "u2"] {
            assert!(db
                .fetch_payment_orders_by_user(
                    user,
                    &[
                        OrderState::Creating,
                        OrderState::Pending,
                        OrderState::SessionFailed,
                        OrderState::Paid,
                        OrderState::Fulfilled,
                        OrderState::Voided,
                    ]
                )
                .await
                .unwrap()
                .is_empty());
        }
        // The number stays retired
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);

        // The open session was still payable at Stripe: a late payment is
        // refunded, not kept
        let late = pay(&stripe, &open, "pi_late");
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &open.id, &late, LATER + 1)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert_eq!(stripe.refund_count_for("pi_late"), 1);
        assert_eq!(
            order(&db, &open.id).await.payment_intent_id.as_deref(),
            Some("pi_late")
        );

        // A redelivery for the voided Paid order changes nothing
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &paid.id, &paid_session, LATER + 2)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert_eq!(stripe.refund_count(), 2);

        // mark_deleted clears the stored badge
        let mut user = db.fetch_user("u1").await.unwrap();
        assert!(user.cipher.is_some());
        user.mark_deleted(&db).await.unwrap();
        assert_eq!(badge(&db, "u1").await, None);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_paid_order_of_an_unlinked_buyer_is_voided_and_refunded() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        pay(&stripe, &pending, "pi_1");
        // The worker leasing it during the deletion died; the deletion only
        // unlinked it
        crash_after(&db, &pending.id, |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some("pi_1".to_string());
        })
        .await;
        on_account_deleted(&db, &stripe, &s, "u1", NOW + 1)
            .await
            .unwrap();
        assert_eq!(order(&db, &pending.id).await.state, OrderState::Paid);

        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, LATER)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert_eq!(stripe.refund_count_for("pi_1"), 1);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_paid_order_still_linked_to_a_deleted_or_missing_buyer_is_voided_and_refunded() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        // u1: paid, fulfilment died before applying it; the account is then
        // deleted, but its payments cascade failed, so the order stays
        // linked and Paid
        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");
        crash_after(&db, &pending.id, |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some("pi_1".to_string());
        })
        .await;
        let mut user = db.fetch_user("u1").await.unwrap();
        user.mark_deleted(&db).await.unwrap();
        assert_eq!(
            order(&db, &pending.id).await.user_id.as_deref(),
            Some("u1"),
            "the order is still linked"
        );

        // The reconcile resume voids and refunds it, and grants nothing
        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, LATER)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        let voided = order(&db, &pending.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.void_reason, Some(VoidReason::AccountDeleted));
        assert_eq!(
            refund_keys(&stripe),
            vec![("pi_1".to_string(), Some(format!("void-{}", pending.id)))]
        );
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        assert_eq!(badge(&db, "u1").await, None);

        // A redelivery refunds nothing more
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, LATER + 1)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert_eq!(stripe.refund_count_for("pi_1"), 1);

        // A buyer with no user row at all is treated the same
        let ghost = checkout(&db, &stripe, &s, "ghost", CipherTier::T99, NOW).await;
        let ghost_session = pay(&stripe, &ghost, "pi_ghost");
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &ghost.id, &ghost_session, NOW)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert_eq!(stripe.refund_count_for("pi_ghost"), 1);
        assert!(db.fetch_cipher_membership("ghost").await.unwrap().is_none());
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_membership_written_by_a_fulfil_racing_the_deletion_is_deleted() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;
        let other = buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_other", NOW).await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T149, NOW).await;
        pay(&stripe, &pending, "pi_1");
        // A fulfilment holds the lease while the account is deleted: the
        // deletion skips the order, unlinks it and deletes the membership
        crash_after(&db, &pending.id, |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some("pi_1".to_string());
        })
        .await;
        on_account_deleted(&db, &stripe, &s, "u1", NOW + 1)
            .await
            .unwrap();
        assert!(order(&db, &pending.id).await.user_id.is_none());

        // ... and only then does that fulfilment's membership write land
        let number = db
            .claim_cipher_number(&pending.id, s.cap)
            .await
            .unwrap()
            .unwrap();
        assert!(db
            .insert_cipher_membership(&CipherMembership {
                user_id: "u1".to_string(),
                number,
                tier: CipherTier::T149,
                prot_grant: 33_000,
                orders: vec![pending.id.clone()],
                disputed_orders: vec![],
                granted_at: NOW + 1,
                revoked_at: None,
                revoke_reason: None,
                prot_posted_at: None,
                version: 0,
            })
            .await
            .unwrap());

        // The resume voids and refunds the order and removes that row
        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, LATER)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        assert_eq!(stripe.refund_count_for("pi_1"), 1);
        let voided = order(&db, &pending.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.void_reason, Some(VoidReason::AccountDeleted));

        // Another member is untouched
        assert_eq!(membership(&db, "u2").await.orders, vec![other.id]);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_session_naming_another_member_never_touches_that_membership() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;
        buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_other", NOW).await;
        let before = membership(&db, "u2").await;
        let badge_before = badge(&db, "u2").await;
        assert!(badge_before.is_some());

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T149, NOW).await;
        pay(&stripe, &pending, "pi_1");
        crash_after(&db, &pending.id, |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some("pi_1".to_string());
        })
        .await;
        on_account_deleted(&db, &stripe, &s, "u1", NOW + 1)
            .await
            .unwrap();

        // The session's client_reference_id names u2, a member whose
        // membership does not list this order
        let session_id = pending.checkout_session_id.clone().unwrap();
        let mut session = stripe.session(&session_id).unwrap();
        session.client_reference_id = Some("u2".to_string());
        stripe.set_session(session);

        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, LATER)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert_eq!(stripe.refund_count_for("pi_1"), 1);
        // u2's membership and badge are exactly as they were
        assert_eq!(membership(&db, "u2").await, before);
        assert_eq!(badge(&db, "u2").await, badge_before);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_late_wrong_amount_payment_of_a_voided_order_is_refunded_once() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        // Voided before anyone paid (the buyer deleted their account while
        // the session was open)
        let open = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        on_account_deleted(&db, &stripe, &s, "u1", NOW + 1)
            .await
            .unwrap();
        let voided = order(&db, &open.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert!(voided.payment_intent_id.is_none());

        // The open session is then paid, in the wrong amount
        let mut late = pay(&stripe, &open, "pi_short");
        late.amount_total = Some(100);
        stripe.set_session(late.clone());

        assert_eq!(
            fulfil_order(&db, &stripe, &s, &open.id, &late, NOW + 2)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert_eq!(
            order(&db, &open.id).await.payment_intent_id.as_deref(),
            Some("pi_short")
        );

        // Redelivered and resumed: refunded exactly once
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &open.id, &late, NOW + 3)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert_eq!(
            resume_order(&db, &stripe, &s, &open.id, NOW + 4)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        assert_eq!(
            refund_keys(&stripe),
            vec![("pi_short".to_string(), Some(format!("void-{}", open.id)))]
        );
        assert_eq!(stripe.refund_count_for("pi_short"), 1);
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_pending_void_refund_is_accepted_and_logged_for_watching() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let mut session = pay(&stripe, &pending, "pi_short");
        session.amount_total = Some(100);
        stripe.set_session(session.clone());
        stripe.set_refund_status("pending");

        // Not failed: the order is voided (the operator watches the refund)
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AmountMismatch)
        );
        assert_eq!(order(&db, &pending.id).await.state, OrderState::Voided);
        assert_eq!(stripe.call_count("create_refund"), 1);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_deleted_account_never_gets_a_badge() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;

        let mut user = db.fetch_user("u1").await.unwrap();
        user.update(
            &db,
            PartialUser {
                flags: Some(UserFlags::Deleted as i32),
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();

        // The membership is still active, but the account is deleted
        sync_user_badge(&db, "u1").await.unwrap();
        assert_eq!(badge(&db, "u1").await, None);

        // A user that does not exist is not an error
        sync_user_badge(&db, "nobody").await.unwrap();
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn claimed_counts_retired_numbers() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        // After the release window: #1 is retired
        reverse_order(
            &db,
            &stripe,
            &s,
            &first.id,
            ReverseKind::Refund,
            full_refund(AFTER_WINDOW),
            AFTER_WINDOW,
        )
        .await
        .unwrap();
        buy(
            &db,
            &stripe,
            &s,
            "u2",
            CipherTier::T99,
            "pi_2",
            AFTER_WINDOW + 1,
        )
        .await;

        assert_eq!(
            cipher_stats(&db, &s, AFTER_WINDOW + 2).await.unwrap(),
            CipherStats {
                claimed: 2,
                cap: CIPHER_CAP_MAX,
                open: true,
                closes_at: None
            }
        );
        assert_eq!(membership(&db, "u2").await.number, 2);
        drop_db(&db).await;
    }

    // --- refunds inside the release window ------------------------------

    async fn maybe_membership(db: &Database, user: &str) -> Option<CipherMembership> {
        db.fetch_cipher_membership(user).await.unwrap()
    }

    /// A full refund made at `at`
    fn full_refund(at: i64) -> Option<RefundFacts> {
        Some(RefundFacts {
            refunded_at_ms: at,
            full: true,
            status: RefundStatus::Succeeded,
        })
    }

    /// Apply a refund made (`refunded_at_ms`) at `made`, processed at `now`
    async fn refund_with(
        db: &Database,
        order_id: &str,
        facts: Option<RefundFacts>,
        now: i64,
    ) -> ReverseOutcome {
        reverse_order(
            db,
            &MockStripe::new(),
            &settings(),
            order_id,
            ReverseKind::Refund,
            facts,
            now,
        )
        .await
        .unwrap()
    }

    /// A full refund made and processed at `at`
    async fn refund(db: &Database, order_id: &str, at: i64) -> ReverseOutcome {
        refund_with(db, order_id, full_refund(at), at).await
    }

    /// A worker that decided the release at `at` and stopped right after
    /// recording it (and, with `revoked`, after revoking the membership)
    async fn release_decided(db: &Database, user: &str, order_id: &str, at: i64, revoked: bool) {
        assert!(db.mark_cipher_number_release(order_id, at).await.unwrap());
        if revoked {
            change_membership(db, user, revoked_for_refund(at)).await;
        }
    }

    /// Write the membership the way a worker that stopped mid-reversal left
    /// it
    async fn change_membership(
        db: &Database,
        user: &str,
        change: impl FnOnce(&mut CipherMembership),
    ) {
        let mut m = membership(db, user).await;
        let read = m.version;
        change(&mut m);
        assert!(db
            .update_cipher_membership_if_version(&m, read)
            .await
            .unwrap());
    }

    fn revoked_for_refund(at: i64) -> impl FnOnce(&mut CipherMembership) {
        move |m| {
            m.revoked_at = Some(at);
            m.revoke_reason = Some(CipherRevokeReason::Refund);
        }
    }

    #[tokio::test]
    async fn a_refund_within_the_window_releases_the_number_to_the_next_buyer() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3"] {
            insert_user(&db, user).await;
        }

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T149, "pi_1", NOW).await;
        buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T149));

        // Day 3: the owner refunds u1 from the Dashboard
        let at = NOW + 3 * DAY;
        assert_eq!(refund(&db, &first.id, at).await, ReverseOutcome::Applied);

        // The membership is gone (not kept revoked), the number is free
        assert_eq!(maybe_membership(&db, "u1").await, None);
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            None
        );
        assert_eq!(badge(&db, "u1").await, None);
        assert_eq!(cipher_me(&db, "u1", at).await.unwrap().membership, None);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);
        assert_eq!(
            cipher_stats(&db, &s, at).await.unwrap().claimed,
            1,
            "the counter drops by one"
        );
        // The order is kept for the accounts
        let refunded = order(&db, &first.id).await;
        assert_eq!(refunded.state, OrderState::Refunded);
        assert_eq!(refunded.reversed_at, Some(at));
        // u2 is untouched
        assert_eq!(badge(&db, "u2").await, badge_of(2, CipherTier::T99));

        // A redelivery changes nothing
        assert_eq!(refund(&db, &first.id, at + 1).await, ReverseOutcome::NoOp);

        // A new buyer gets #1 (the unique number index allows it, because
        // the refunded row is deleted, not kept revoked)
        let third = buy(&db, &stripe, &s, "u3", CipherTier::T99, "pi_3", at + 2).await;
        assert_eq!(membership(&db, "u3").await.number, 1);
        assert_eq!(badge(&db, "u3").await, badge_of(1, CipherTier::T99));
        assert_eq!(
            db.fetch_cipher_number_by_order(&third.id).await.unwrap(),
            Some(1)
        );

        // u1 can buy again normally: the lowest free number
        buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_4", at + 3).await;
        assert_eq!(membership(&db, "u1").await.number, 3);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 3);

        // Our own refunds were never involved
        assert_eq!(stripe.call_count("create_refund"), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn the_window_is_inclusive_and_a_later_refund_retires_the_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3"] {
            insert_user(&db, user).await;
        }

        let late = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let edge = buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;

        // One millisecond past the window: today's rule, revoke + retire
        assert_eq!(
            refund(&db, &late.id, AFTER_WINDOW).await,
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u1").await;
        assert!(!m.is_active());
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::Refund));
        assert_eq!(m.number, 1);
        assert_eq!(
            db.fetch_cipher_number_by_order(&late.id).await.unwrap(),
            Some(1)
        );
        assert_eq!(badge(&db, "u1").await, None);
        assert_eq!(order(&db, &late.id).await.state, OrderState::Refunded);

        // Exactly at the end of the window: released
        assert_eq!(
            refund(
                &db,
                &edge.id,
                NOW + REFUND_RELEASE_WINDOW_MS + REFUND_GRACE_MS
            )
            .await,
            ReverseOutcome::Applied
        );
        assert_eq!(maybe_membership(&db, "u2").await, None);
        assert_eq!(
            db.fetch_cipher_number_by_order(&edge.id).await.unwrap(),
            None
        );

        // #1 stays retired; the next buyer gets the released #2
        buy(
            &db,
            &stripe,
            &s,
            "u3",
            CipherTier::T99,
            "pi_3",
            AFTER_WINDOW + 1,
        )
        .await;
        assert_eq!(membership(&db, "u3").await.number, 2);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 2);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_lost_dispute_within_the_window_retires_the_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        let bought = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        on_dispute(
            &db,
            &bought.id,
            "dp_1",
            ReverseKind::DisputeOpened,
            NOW + DAY,
        )
        .await
        .unwrap();
        assert_eq!(
            on_dispute(
                &db,
                &bought.id,
                "dp_1",
                ReverseKind::DisputeLost,
                NOW + 2 * DAY
            )
            .await
            .unwrap(),
            ReverseOutcome::Applied
        );

        let m = membership(&db, "u1").await;
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::DisputeLost));
        assert_eq!(
            db.fetch_cipher_number_by_order(&bought.id).await.unwrap(),
            Some(1)
        );

        // A refund arriving after it changes nothing
        assert_eq!(
            refund(&db, &bought.id, NOW + 3 * DAY).await,
            ReverseOutcome::NoOp
        );
        assert!(maybe_membership(&db, "u1").await.is_some());

        buy(
            &db,
            &stripe,
            &s,
            "u2",
            CipherTier::T99,
            "pi_2",
            NOW + 4 * DAY,
        )
        .await;
        assert_eq!(membership(&db, "u2").await.number, 2);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_refund_while_a_dispute_is_listed_retires_the_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let bought = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        on_dispute(
            &db,
            &bought.id,
            "dp_1",
            ReverseKind::DisputeOpened,
            NOW + DAY,
        )
        .await
        .unwrap();
        assert_eq!(
            refund(&db, &bought.id, NOW + 2 * DAY).await,
            ReverseOutcome::Applied
        );

        let m = membership(&db, "u1").await;
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::Refund));
        assert_eq!(
            db.fetch_cipher_number_by_order(&bought.id).await.unwrap(),
            Some(1)
        );
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_release_stopped_after_its_decision_is_finished_by_the_redelivery() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3", "u4"] {
            insert_user(&db, user).await;
        }

        // u1: stopped right after recording the decision; u2: after the
        // revoke as well
        let a = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let b = buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;
        release_decided(&db, "u1", &a.id, NOW + DAY, false).await;
        release_decided(&db, "u2", &b.id, NOW + DAY, true).await;

        // Until it is finished the numbers stay claimed: nobody else gets
        // them, so no membership can collide with the old rows
        buy(
            &db,
            &stripe,
            &s,
            "u3",
            CipherTier::T99,
            "pi_3",
            NOW + DAY + 1,
        )
        .await;
        assert_eq!(membership(&db, "u3").await.number, 3);

        // Redelivered long after the window: the recorded decision stands
        let late = AFTER_WINDOW + 5 * DAY;
        for (user, order_id) in [("u1", &a.id), ("u2", &b.id)] {
            assert_eq!(refund(&db, order_id, late).await, ReverseOutcome::Applied);
            assert_eq!(maybe_membership(&db, user).await, None);
            assert_eq!(badge(&db, user).await, None);
            assert_eq!(
                db.fetch_cipher_number_by_order(order_id).await.unwrap(),
                None
            );
            assert_eq!(order(&db, order_id).await.state, OrderState::Refunded);
        }
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());

        buy(&db, &stripe, &s, "u4", CipherTier::T99, "pi_4", late + 1).await;
        assert_eq!(membership(&db, "u4").await.number, 1);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 2);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_release_stopped_at_any_later_step_is_finished_by_the_redelivery() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3"] {
            insert_user(&db, user).await;
        }

        // u1: stopped after deleting the membership, before the release
        let a = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        release_decided(&db, "u1", &a.id, NOW + DAY, true).await;
        let read = membership(&db, "u1").await.version;
        assert!(db
            .delete_cipher_membership_if_version("u1", read)
            .await
            .unwrap());
        // u2: stopped after the release, before the order was recorded
        let b = buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;
        release_decided(&db, "u2", &b.id, NOW + DAY, true).await;
        let read = membership(&db, "u2").await.version;
        assert!(db
            .delete_cipher_membership_if_version("u2", read)
            .await
            .unwrap());
        assert!(db.release_cipher_number(&b.id).await.unwrap());

        assert_eq!(
            refund(&db, &a.id, NOW + DAY + 1).await,
            ReverseOutcome::Applied
        );
        assert_eq!(db.fetch_cipher_number_by_order(&a.id).await.unwrap(), None);
        assert_eq!(order(&db, &a.id).await.state, OrderState::Refunded);

        // Nothing left to change in a membership; the order is recorded
        assert_eq!(
            refund(&db, &b.id, NOW + DAY + 1).await,
            ReverseOutcome::NoOp
        );
        assert_eq!(order(&db, &b.id).await.state, OrderState::Refunded);
        assert_eq!(badge(&db, "u2").await, None);

        // Both numbers are back
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        buy(
            &db,
            &stripe,
            &s,
            "u3",
            CipherTier::T99,
            "pi_3",
            NOW + 2 * DAY,
        )
        .await;
        assert_eq!(membership(&db, "u3").await.number, 1);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_lost_dispute_after_a_stopped_release_keeps_the_number_retired() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3"] {
            insert_user(&db, user).await;
        }

        // Two releases stopped after their decision: u1's after the revoke,
        // u2's before it
        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let second = buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;
        release_decided(&db, "u1", &first.id, NOW + DAY, true).await;
        release_decided(&db, "u2", &second.id, NOW + DAY, false).await;

        // The refund events never come back; a dispute on each purchase,
        // already lost when first seen, does. A lost dispute always retires
        // the number: each release is dropped, the row revoked for it
        for (user, id, number) in [("u1", &first.id, 1), ("u2", &second.id, 2)] {
            assert_eq!(
                on_dispute(&db, id, "dp_1", ReverseKind::DisputeLost, NOW + 2 * DAY)
                    .await
                    .unwrap(),
                ReverseOutcome::Applied
            );
            let m = membership(&db, user).await;
            assert_eq!(
                (m.number, m.revoke_reason),
                (number, Some(CipherRevokeReason::DisputeLost))
            );
            assert_eq!(badge(&db, user).await, None);
            assert_eq!(
                db.fetch_cipher_number_by_order(id).await.unwrap(),
                Some(number)
            );
            assert_eq!(order(&db, id).await.state, OrderState::Refunded);
        }
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());

        // The sweep has nothing to release, and the next buyer gets #3
        reconcile(&db, &stripe, &s, NOW + 2 * DAY + 2 * MINUTE)
            .await
            .unwrap();
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 2);
        buy(
            &db,
            &stripe,
            &s,
            "u3",
            CipherTier::T99,
            "pi_3",
            NOW + 3 * DAY,
        )
        .await;
        assert_eq!(membership(&db, "u3").await.number, 3);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn no_new_purchase_is_taken_while_a_release_runs() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        // Refunded in part (revoked), then the buyer opens a new checkout,
        // then the rest is refunded within the window (the release is
        // decided) before the buyer pays it
        change_membership(&db, "u1", revoked_for_refund(NOW + DAY)).await;
        let late = checkout(&db, &stripe, &s, "u1", CipherTier::T149, NOW + DAY).await;
        assert!(matches!(late.sku, Sku::CipherNew { .. }));
        release_decided(&db, "u1", &first.id, NOW + DAY + 1, false).await;

        // No new checkout while the release runs (not even the open one's
        // URL again)
        assert!(matches!(
            error_type(
                create_cipher_checkout(
                    &db,
                    &stripe,
                    &s,
                    "u1",
                    CipherTier::T149,
                    CipherReturnTo::Web,
                    NOW + DAY + 2
                )
                .await
            ),
            ErrorType::PaymentPending
        ));

        // The open one is paid: it is voided and refunded at once (the
        // money is never held while the release runs), and the row being
        // released is left alone
        let session = pay(&stripe, &late, "pi_late");
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &late.id, &session, NOW + DAY + 3)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::ReleasePending)
        );
        let voided = order(&db, &late.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.void_reason, Some(VoidReason::ReleasePending));
        assert_eq!(
            refund_keys(&stripe),
            vec![("pi_late".to_string(), Some(format!("void-{}", late.id)))]
        );
        assert_eq!(membership(&db, "u1").await.orders, vec![first.id.clone()]);
        assert_eq!(
            db.fetch_cipher_number_by_order(&late.id).await.unwrap(),
            None
        );

        // A redelivery refunds nothing more
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &late.id, &session, NOW + DAY + 4)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::ReleasePending)
        );
        assert_eq!(stripe.refund_count(), 1);

        // The sweep finishes the release; nothing is left to resume
        assert_eq!(
            reconcile(&db, &stripe, &s, NOW + DAY + 2 * MINUTE)
                .await
                .unwrap(),
            "expired=0, resumed=0, reversed=1, redriven=0, errors=0"
        );
        assert_eq!(maybe_membership(&db, "u1").await, None);
        assert_eq!(order(&db, &first.id).await.state, OrderState::Refunded);

        // Then the buyer can buy again, and gets #1 back
        buy(
            &db,
            &stripe,
            &s,
            "u1",
            CipherTier::T149,
            "pi_again",
            NOW + DAY + 3 * MINUTE,
        )
        .await;
        let m = membership(&db, "u1").await;
        assert!(m.is_active());
        assert_eq!((m.number, m.tier), (1, CipherTier::T149));
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T149));
        assert_eq!(stripe.refund_count(), 1);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn no_checkout_starts_while_the_release_of_a_revoked_row_runs() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        // Decided and revoked (the badge is gone), the row not deleted yet
        release_decided(&db, "u1", &first.id, NOW + DAY, true).await;
        assert!(!membership(&db, "u1").await.is_active());

        for tier in [CipherTier::T99, CipherTier::T149, CipherTier::T299] {
            assert!(matches!(
                error_type(
                    create_cipher_checkout(
                        &db,
                        &stripe,
                        &s,
                        "u1",
                        tier,
                        CipherReturnTo::Web,
                        NOW + DAY + 1
                    )
                    .await
                ),
                ErrorType::PaymentPending
            ));
        }
        assert_eq!(stripe.call_count("create_checkout_session"), 1);

        // Once the sweep has finished the release, checkout works again
        assert_eq!(
            reconcile(&db, &stripe, &s, NOW + DAY + 2 * MINUTE)
                .await
                .unwrap(),
            "expired=0, resumed=0, reversed=1, redriven=0, errors=0"
        );
        checkout(
            &db,
            &stripe,
            &s,
            "u1",
            CipherTier::T99,
            NOW + DAY + 3 * MINUTE,
        )
        .await;
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_purchase_paid_after_a_dropped_release_gets_a_new_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        // Refunded in part (revoked), a new checkout opened, then the rest
        // refunded in the window (the release is decided)...
        change_membership(&db, "u1", revoked_for_refund(NOW + DAY)).await;
        let late = checkout(&db, &stripe, &s, "u1", CipherTier::T149, NOW + DAY).await;
        release_decided(&db, "u1", &first.id, NOW + DAY + 1, false).await;
        // ...then Prot was credited, so the sweep drops the release
        // (keep_number_retired): #1 stays retired on the old row
        change_membership(&db, "u1", |m| m.prot_posted_at = Some(NOW + DAY + 2)).await;
        assert_eq!(
            reconcile(&db, &stripe, &s, NOW + DAY + 2 * MINUTE)
                .await
                .unwrap(),
            "expired=0, resumed=0, reversed=1, redriven=0, errors=0"
        );
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(order(&db, &first.id).await.state, OrderState::Refunded);

        // The open session is paid now: no release runs, so it is applied
        // (not voided ReleasePending), on a new number
        let session = pay(&stripe, &late, "pi_late");
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &late.id, &session, NOW + DAY + 3 * MINUTE)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        let m = membership(&db, "u1").await;
        assert!(m.is_active());
        assert_eq!(
            (m.number, m.tier, m.orders.clone()),
            (2, CipherTier::T149, vec![late.id.clone()])
        );
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1)
        );
        assert_eq!(badge(&db, "u1").await, badge_of(2, CipherTier::T149));
        assert_eq!(stripe.refund_count(), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn the_window_is_judged_when_the_refund_was_made_with_a_grace() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3", "u4"] {
            insert_user(&db, user).await;
        }
        let a = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let b = buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;
        let c = buy(&db, &stripe, &s, "u3", CipherTier::T99, "pi_3", NOW).await;
        buy(&db, &stripe, &s, "u4", CipherTier::T99, "pi_4", NOW).await;
        let up = buy(&db, &stripe, &s, "u4", CipherTier::T299, "pi_5", NOW).await;

        // Made on day 13, processed on day 15 (a re-drive): released
        assert_eq!(
            refund_with(&db, &a.id, full_refund(NOW + 13 * DAY), NOW + 15 * DAY).await,
            ReverseOutcome::Applied
        );
        assert_eq!(maybe_membership(&db, "u1").await, None);

        // Made on day 16 (inside the grace), processed on day 19 (past it):
        // released, because the refund was made in time
        assert_eq!(
            refund_with(&db, &b.id, full_refund(NOW + 16 * DAY), NOW + 19 * DAY).await,
            ReverseOutcome::Applied
        );
        assert_eq!(maybe_membership(&db, "u2").await, None);
        assert_eq!(db.fetch_cipher_number_by_order(&b.id).await.unwrap(), None);

        // Made on day 18: past the 14 days and the 3-day grace, retired
        assert_eq!(
            refund_with(&db, &c.id, full_refund(NOW + 18 * DAY), NOW + 18 * DAY).await,
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u3").await;
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::Refund));
        assert_eq!(
            db.fetch_cipher_number_by_order(&c.id).await.unwrap(),
            Some(3)
        );

        // An upgrade refund made on day 16, processed on day 19: rolled back
        assert_eq!(
            refund_with(&db, &up.id, full_refund(NOW + 16 * DAY), NOW + 19 * DAY).await,
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u4").await;
        assert!(m.is_active());
        assert_eq!((m.number, m.tier), (4, CipherTier::T99));
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_partial_or_unknown_refund_inside_the_window_revokes_and_retires() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3"] {
            insert_user(&db, user).await;
        }

        // A partial refund of a new purchase on day 1
        let a = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let partial = Some(RefundFacts {
            refunded_at_ms: NOW + DAY,
            full: false,
            status: RefundStatus::Succeeded,
        });
        assert_eq!(
            refund_with(&db, &a.id, partial, NOW + DAY).await,
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u1").await;
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::Refund));
        assert_eq!(
            db.fetch_cipher_number_by_order(&a.id).await.unwrap(),
            Some(1)
        );

        // A partial refund of an upgrade: revoked, not rolled back
        buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;
        let up = buy(&db, &stripe, &s, "u2", CipherTier::T299, "pi_3", NOW).await;
        assert_eq!(
            refund_with(&db, &up.id, partial, NOW + DAY).await,
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u2").await;
        assert!(!m.is_active());
        assert_eq!(m.tier, CipherTier::T299);

        // Nothing known about the refund (a recorded reversal): the same
        let c = buy(&db, &stripe, &s, "u3", CipherTier::T99, "pi_4", NOW).await;
        assert_eq!(
            refund_with(&db, &c.id, None, NOW + DAY).await,
            ReverseOutcome::Applied
        );
        assert!(!membership(&db, "u3").await.is_active());
        assert_eq!(
            db.fetch_cipher_number_by_order(&c.id).await.unwrap(),
            Some(3)
        );
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 3);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_membership_revoked_by_staff_or_a_lost_dispute_keeps_its_number_retired() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        // Revoked by staff, then the purchase is refunded on day 1
        let a = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        change_membership(&db, "u1", |m| {
            m.revoked_at = Some(NOW + 1);
            m.revoke_reason = Some(CipherRevokeReason::Admin);
        })
        .await;
        assert_eq!(refund(&db, &a.id, NOW + DAY).await, ReverseOutcome::Applied);
        let m = membership(&db, "u1").await;
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::Admin));
        assert_eq!(
            db.fetch_cipher_number_by_order(&a.id).await.unwrap(),
            Some(1)
        );
        assert_eq!(order(&db, &a.id).await.state, OrderState::Refunded);

        // Revoked for a dispute lost on its upgrade, then the purchase is
        // refunded on day 2
        let b = buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;
        let up = buy(&db, &stripe, &s, "u2", CipherTier::T299, "pi_3", NOW).await;
        on_dispute(&db, &up.id, "dp_1", ReverseKind::DisputeOpened, NOW + DAY)
            .await
            .unwrap();
        on_dispute(&db, &up.id, "dp_1", ReverseKind::DisputeLost, NOW + DAY + 1)
            .await
            .unwrap();
        assert_eq!(
            membership(&db, "u2").await.revoke_reason,
            Some(CipherRevokeReason::DisputeLost)
        );
        assert_eq!(
            refund(&db, &b.id, NOW + 2 * DAY).await,
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u2").await;
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::DisputeLost));
        assert_eq!(
            db.fetch_cipher_number_by_order(&b.id).await.unwrap(),
            Some(2)
        );
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 2);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn credited_prot_keeps_the_old_rule() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        // A new purchase whose Prot was credited: revoked + retired
        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        change_membership(&db, "u1", |m| m.prot_posted_at = Some(NOW + 1)).await;
        assert_eq!(
            refund(&db, &first.id, NOW + DAY).await,
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u1").await;
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::Refund));
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1)
        );

        // An upgrade on a credited membership: revoked, not rolled back
        buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;
        let up = buy(&db, &stripe, &s, "u2", CipherTier::T299, "pi_3", NOW + DAY).await;
        change_membership(&db, "u2", |m| m.prot_posted_at = Some(NOW + DAY + 1)).await;
        assert_eq!(
            refund(&db, &up.id, NOW + 2 * DAY).await,
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u2").await;
        assert!(!m.is_active());
        assert_eq!(m.tier, CipherTier::T299);
        assert_eq!(m.number, 2);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 2);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn an_upgrade_refunded_within_its_window_rolls_back_and_keeps_the_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        // Bought on day 1 and refunded on day 3; the purchase itself is
        // long out of its own window by then, which does not matter
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW + DAY).await;
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T299));

        assert_eq!(
            refund(&db, &up.id, NOW + 3 * DAY).await,
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u1").await;
        assert!(m.is_active());
        assert_eq!(
            (m.number, m.tier, m.prot_grant),
            (1, CipherTier::T99, catalog::tier_prot(CipherTier::T99))
        );
        assert_eq!(m.orders, vec![first.id.clone()]);
        assert_eq!(m.granted_at, NOW);
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));
        assert_eq!(order(&db, &up.id).await.state, OrderState::Refunded);
        assert_eq!(order(&db, &first.id).await.state, OrderState::Fulfilled);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);

        // A redelivery changes nothing
        assert_eq!(
            refund(&db, &up.id, NOW + 3 * DAY + 1).await,
            ReverseOutcome::NoOp
        );
        assert_eq!(membership(&db, "u1").await.tier, CipherTier::T99);

        // The buyer can upgrade again
        let again = buy(
            &db,
            &stripe,
            &s,
            "u1",
            CipherTier::T149,
            "pi_up2",
            NOW + 4 * DAY,
        )
        .await;
        assert_eq!(
            again.sku,
            Sku::CipherUpgrade {
                from: CipherTier::T99,
                to: CipherTier::T149
            }
        );
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T149));
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_rollback_stopped_after_its_membership_write_is_finished_by_the_redelivery() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW + DAY).await;

        // The rollback was written, then the worker died: the badge and the
        // order were never updated
        change_membership(&db, "u1", |m| {
            m.tier = CipherTier::T99;
            m.prot_grant = catalog::tier_prot(CipherTier::T99);
            m.orders = vec![first.id.clone()];
        })
        .await;
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T299));

        assert_eq!(
            refund(&db, &up.id, NOW + 2 * DAY).await,
            ReverseOutcome::NoOp
        );
        assert_eq!(order(&db, &up.id).await.state, OrderState::Refunded);
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));
        assert!(membership(&db, "u1").await.is_active());
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn an_upgrade_refunded_after_its_window_revokes_and_retires() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW).await;

        // Day 20
        assert_eq!(
            refund(&db, &up.id, NOW + 20 * DAY).await,
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u1").await;
        assert!(!m.is_active());
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::Refund));
        assert_eq!((m.number, m.tier), (1, CipherTier::T299));
        assert_eq!(badge(&db, "u1").await, None);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);
        assert_eq!(order(&db, &up.id).await.state, OrderState::Refunded);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn only_the_latest_of_stacked_upgrades_rolls_back() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        // u1: 99 → 149 → 299, then the OLDER upgrade is refunded: the
        // membership is left as it is, the order is recorded Refunded and
        // the case is logged for manual handling
        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let older = buy(&db, &stripe, &s, "u1", CipherTier::T149, "pi_2", NOW + DAY).await;
        let latest = buy(
            &db,
            &stripe,
            &s,
            "u1",
            CipherTier::T299,
            "pi_3",
            NOW + 2 * DAY,
        )
        .await;
        let before = membership(&db, "u1").await;
        assert_eq!(
            refund(&db, &older.id, NOW + 3 * DAY).await,
            ReverseOutcome::NoOp
        );
        assert_eq!(membership(&db, "u1").await, before, "untouched");
        assert!(before.is_active());
        assert_eq!(
            before.orders,
            vec![first.id.clone(), older.id.clone(), latest.id.clone()]
        );
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T299));
        assert_eq!(order(&db, &older.id).await.state, OrderState::Refunded);
        assert_eq!(order(&db, &latest.id).await.state, OrderState::Fulfilled);
        // A redelivery changes nothing
        assert_eq!(
            refund(&db, &older.id, NOW + 3 * DAY + 1).await,
            ReverseOutcome::NoOp
        );
        assert_eq!(membership(&db, "u1").await, before);

        // u2: the same stack, refunded latest first: each one rolls back
        buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_4", NOW).await;
        let mid = buy(&db, &stripe, &s, "u2", CipherTier::T149, "pi_5", NOW + DAY).await;
        let top = buy(
            &db,
            &stripe,
            &s,
            "u2",
            CipherTier::T299,
            "pi_6",
            NOW + 2 * DAY,
        )
        .await;
        assert_eq!(
            refund(&db, &top.id, NOW + 3 * DAY).await,
            ReverseOutcome::Applied
        );
        assert_eq!(badge(&db, "u2").await, badge_of(2, CipherTier::T149));
        assert_eq!(
            refund(&db, &mid.id, NOW + 3 * DAY).await,
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u2").await;
        assert!(m.is_active());
        assert_eq!((m.number, m.tier), (2, CipherTier::T99));
        assert_eq!(m.orders.len(), 1);
        assert_eq!(badge(&db, "u2").await, badge_of(2, CipherTier::T99));
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_refunded_purchase_takes_its_upgrades_with_it() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW + DAY).await;

        assert_eq!(
            refund(&db, &first.id, NOW + 2 * DAY).await,
            ReverseOutcome::Applied
        );
        assert_eq!(maybe_membership(&db, "u1").await, None);
        assert_eq!(badge(&db, "u1").await, None);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);

        // The release refunded the upgrade and recorded it, so the event of
        // that refund changes nothing
        assert_eq!(order(&db, &up.id).await.state, OrderState::Refunded);
        assert_eq!(
            refund(&db, &up.id, NOW + 2 * DAY + 1).await,
            ReverseOutcome::NoOp
        );
        assert_eq!(order(&db, &up.id).await.state, OrderState::Refunded);

        buy(
            &db,
            &stripe,
            &s,
            "u2",
            CipherTier::T99,
            "pi_2",
            NOW + 3 * DAY,
        )
        .await;
        assert_eq!(membership(&db, "u2").await.number, 1);
        drop_db(&db).await;
    }

    /// The order as leased at `at` by a worker whose lease then ran out and
    /// was taken over (and given back) by another: its writes are refused
    async fn stale_lease(db: &Database, order_id: &str, at: i64) -> Leased {
        let stale = acquire(db, order_id, at).await.unwrap().expect("lease");
        let taken = acquire(db, order_id, at + LEASE_MS + 1)
            .await
            .unwrap()
            .expect("taken over");
        release(db, &taken).await;
        stale
    }

    /// Delete the membership the way a release that stopped right after
    /// its delete left it
    async fn delete_membership(db: &Database, user: &str) {
        let read = membership(db, user).await.version;
        assert!(db
            .delete_cipher_membership_if_version(user, read)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn a_release_waits_for_a_half_done_account_deletion() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3"] {
            insert_user(&db, user).await;
        }

        let bought = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        release_decided(&db, "u1", &bought.id, NOW + DAY, true).await;

        // The account deletion unlinks the orders, then stops before it
        // deletes the membership: #1 is not released while that row holds it
        db.unlink_payment_orders_by_user("u1").await.unwrap();
        assert!(matches!(
            error_type(finish_number_release(&db, &stripe, &bought.id, NOW + DAY + 1).await),
            ErrorType::InternalError
        ));
        assert_eq!(
            db.fetch_cipher_number_by_order(&bought.id).await.unwrap(),
            Some(1)
        );
        assert_eq!(membership(&db, "u1").await.number, 1);
        assert_eq!(
            db.fetch_cipher_numbers_release_pending(10)
                .await
                .unwrap()
                .len(),
            1
        );

        // So the next buyer gets #2, and their membership is written
        buy(
            &db,
            &stripe,
            &s,
            "u2",
            CipherTier::T99,
            "pi_2",
            NOW + DAY + 2,
        )
        .await;
        assert_eq!(membership(&db, "u2").await.number, 2);

        // The cascade runs again and deletes the row; the sweep releases #1
        db.delete_cipher_membership("u1").await.unwrap();
        reconcile(&db, &stripe, &s, NOW + DAY + 2 * MINUTE)
            .await
            .unwrap();
        assert_eq!(
            db.fetch_cipher_number_by_order(&bought.id).await.unwrap(),
            None
        );
        assert_eq!(order(&db, &bought.id).await.state, OrderState::Refunded);
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());
        buy(
            &db,
            &stripe,
            &s,
            "u3",
            CipherTier::T99,
            "pi_3",
            NOW + DAY + 3 * MINUTE,
        )
        .await;
        assert_eq!(membership(&db, "u3").await.number, 1);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_release_stopped_after_its_order_write_is_finished_by_the_sweep() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        // u1: stopped between the order write and the release
        let a = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        release_decided(&db, "u1", &a.id, NOW + DAY, true).await;
        delete_membership(&db, "u1").await;
        let mut leased = acquire(&db, &a.id, NOW + DAY).await.unwrap().unwrap();
        mark_refunded(&db, &mut leased, NOW + DAY).await.unwrap();
        release(&db, &leased).await;

        // u2: the worker lost its lease after the delete, so its order write
        // is refused, and nothing after it may run: #2 stays claimed
        let b = buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;
        release_decided(&db, "u2", &b.id, NOW + DAY, true).await;
        delete_membership(&db, "u2").await;
        let mut stale = stale_lease(&db, &b.id, NOW + DAY).await;
        assert!(matches!(
            error_type(finish_number_release_locked(&db, &stripe, &mut stale, NOW + DAY).await),
            ErrorType::InternalError
        ));
        assert_eq!(
            db.fetch_cipher_number_by_order(&b.id).await.unwrap(),
            Some(2)
        );
        assert_eq!(order(&db, &b.id).await.state, OrderState::Fulfilled);

        // The sweep finds both marks and finishes both
        reconcile(&db, &stripe, &s, NOW + DAY + LEASE_MS + 2 * MINUTE)
            .await
            .unwrap();
        for id in [&a.id, &b.id] {
            assert_eq!(db.fetch_cipher_number_by_order(id).await.unwrap(), None);
            assert_eq!(order(&db, id).await.state, OrderState::Refunded);
        }
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_worker_that_lost_its_lease_never_marks_or_deletes() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3"] {
            insert_user(&db, user).await;
        }
        let a = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let b = buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;

        // Before the mark: the plan says release, but the lease is gone
        let mut stale = stale_lease(&db, &a.id, NOW + DAY).await;
        assert!(matches!(
            error_type(
                refund_within_window(
                    &db,
                    &stripe,
                    &mut stale,
                    "u1",
                    full_refund(NOW + DAY),
                    NOW + DAY
                )
                .await
            ),
            ErrorType::InternalError
        ));
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());
        assert!(membership(&db, "u1").await.is_active());
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));

        // Before the delete: decided and revoked by a worker that stopped,
        // then a stale one wakes up
        release_decided(&db, "u2", &b.id, NOW + DAY, true).await;
        let mut stale = stale_lease(&db, &b.id, NOW + DAY).await;
        assert!(matches!(
            error_type(finish_number_release_locked(&db, &stripe, &mut stale, NOW + DAY).await),
            ErrorType::InternalError
        ));
        assert_eq!(membership(&db, "u2").await.number, 2);
        assert_eq!(
            db.fetch_cipher_number_by_order(&b.id).await.unwrap(),
            Some(2)
        );

        // The next buyer never gets a number an old row still holds
        buy(
            &db,
            &stripe,
            &s,
            "u3",
            CipherTier::T99,
            "pi_3",
            NOW + DAY + 1,
        )
        .await;
        assert_eq!(membership(&db, "u3").await.number, 3);

        // The sweep finishes u2's release
        reconcile(&db, &stripe, &s, NOW + DAY + LEASE_MS + 2 * MINUTE)
            .await
            .unwrap();
        assert_eq!(maybe_membership(&db, "u2").await, None);
        assert_eq!(db.fetch_cipher_number_by_order(&b.id).await.unwrap(), None);
        assert_eq!(order(&db, &b.id).await.state, OrderState::Refunded);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_release_dropped_for_a_staff_revoke_or_credited_prot_keeps_the_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3"] {
            insert_user(&db, user).await;
        }
        let a = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let b = buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;

        // u1: decided, then revoked by staff before it finished
        release_decided(&db, "u1", &a.id, NOW + DAY, false).await;
        change_membership(&db, "u1", |m| {
            m.revoked_at = Some(NOW + DAY + 1);
            m.revoke_reason = Some(CipherRevokeReason::Admin);
        })
        .await;
        // u2: decided, then Prot was credited before it finished
        release_decided(&db, "u2", &b.id, NOW + DAY, false).await;
        change_membership(&db, "u2", |m| m.prot_posted_at = Some(NOW + DAY + 1)).await;

        reconcile(&db, &stripe, &s, NOW + DAY + 2 * MINUTE)
            .await
            .unwrap();

        // Both rows kept, both numbers retired, both orders recorded
        let m = membership(&db, "u1").await;
        assert_eq!(
            (m.number, m.revoke_reason),
            (1, Some(CipherRevokeReason::Admin))
        );
        let m = membership(&db, "u2").await;
        assert_eq!(
            (m.number, m.revoke_reason),
            (2, Some(CipherRevokeReason::Refund))
        );
        assert_eq!(badge(&db, "u2").await, None);
        for (id, number) in [(&a.id, 1), (&b.id, 2)] {
            assert_eq!(
                db.fetch_cipher_number_by_order(id).await.unwrap(),
                Some(number)
            );
            assert_eq!(order(&db, id).await.state, OrderState::Refunded);
        }
        // The decisions are gone, so nothing comes back to them
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            refund(&db, &a.id, NOW + DAY + 3 * MINUTE).await,
            ReverseOutcome::NoOp
        );

        buy(
            &db,
            &stripe,
            &s,
            "u3",
            CipherTier::T99,
            "pi_3",
            NOW + DAY + 4 * MINUTE,
        )
        .await;
        assert_eq!(membership(&db, "u3").await.number, 3);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_release_dropped_for_a_dispute_lost_on_an_upgrade_keeps_the_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW).await;

        // Decided and revoked, then a dispute on the upgrade opens and is
        // lost (under the upgrade's lease) before the release finished
        release_decided(&db, "u1", &first.id, NOW + DAY, true).await;
        for kind in [ReverseKind::DisputeOpened, ReverseKind::DisputeLost] {
            on_dispute(&db, &up.id, "dp_up", kind, NOW + DAY + 1)
                .await
                .unwrap();
        }
        let m = membership(&db, "u1").await;
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::DisputeLost));
        assert!(m.disputed_orders.is_empty());

        assert_eq!(
            finish_number_release(&db, &stripe, &first.id, NOW + DAY + 2 * MINUTE)
                .await
                .unwrap(),
            ReverseOutcome::Applied
        );

        // The row kept, the number retired, the purchase recorded, and the
        // upgrade (lost in its dispute) never refunded by us
        let m = membership(&db, "u1").await;
        assert_eq!(
            (m.number, m.revoke_reason),
            (1, Some(CipherRevokeReason::DisputeLost))
        );
        assert_eq!(stripe.call_count("create_refund"), 0);
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1)
        );
        assert_eq!(order(&db, &first.id).await.state, OrderState::Refunded);
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_release_dropped_for_a_dispute_opened_on_an_upgrade_keeps_the_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;
        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW).await;

        // The purchase is refunded in its window: decided and revoked, then
        // the worker stops. A dispute opens on the upgrade (under the
        // upgrade's lease) before the sweep finishes the release
        release_decided(&db, "u1", &first.id, NOW + DAY, true).await;
        on_dispute(
            &db,
            &up.id,
            "dp_up",
            ReverseKind::DisputeOpened,
            NOW + DAY + 1,
        )
        .await
        .unwrap();
        let m = membership(&db, "u1").await;
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::Refund));
        assert_eq!(m.disputed_orders, vec![up.id.clone()]);

        assert_eq!(
            finish_number_release(&db, &stripe, &first.id, NOW + DAY + 2 * MINUTE)
                .await
                .unwrap(),
            ReverseOutcome::Applied
        );

        // The row kept with its dispute, the number retired, the purchase
        // recorded, and the disputed upgrade never refunded by us
        let m = membership(&db, "u1").await;
        assert_eq!(
            (m.number, m.revoke_reason),
            (1, Some(CipherRevokeReason::Refund))
        );
        assert_eq!(m.disputed_orders, vec![up.id.clone()]);
        assert_eq!(stripe.call_count("create_refund"), 0);
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1)
        );
        assert_eq!(order(&db, &first.id).await.state, OrderState::Refunded);
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());

        buy(
            &db,
            &stripe,
            &s,
            "u2",
            CipherTier::T99,
            "pi_2",
            NOW + DAY + 3 * MINUTE,
        )
        .await;
        assert_eq!(membership(&db, "u2").await.number, 2);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_dispute_lost_after_a_refund_keeps_the_purchase_number_retired() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;
        let partial = Some(RefundFacts {
            refunded_at_ms: NOW + DAY,
            full: false,
            status: RefundStatus::Succeeded,
        });

        // u1: the upgrade is refunded in part (revoked for the refund, the
        // upgrade Refunded), then a dispute on it is lost
        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW).await;
        refund_with(&db, &up.id, partial, NOW + DAY).await;
        assert_eq!(
            membership(&db, "u1").await.revoke_reason,
            Some(CipherRevokeReason::Refund)
        );
        assert_eq!(
            on_dispute(&db, &up.id, "dp_1", ReverseKind::DisputeLost, NOW + DAY + 1)
                .await
                .unwrap(),
            ReverseOutcome::Applied
        );
        assert_eq!(
            membership(&db, "u1").await.revoke_reason,
            Some(CipherRevokeReason::DisputeLost)
        );

        // u2: revoked by a partial refund of one upgrade, then a dispute
        // lost on another (still Fulfilled) one
        let second = buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW).await;
        let mid = buy(&db, &stripe, &s, "u2", CipherTier::T149, "pi_3", NOW).await;
        let top = buy(&db, &stripe, &s, "u2", CipherTier::T299, "pi_4", NOW).await;
        refund_with(&db, &top.id, partial, NOW + DAY).await;
        on_dispute(
            &db,
            &mid.id,
            "dp_2",
            ReverseKind::DisputeLost,
            NOW + DAY + 1,
        )
        .await
        .unwrap();
        assert_eq!(
            membership(&db, "u2").await.revoke_reason,
            Some(CipherRevokeReason::DisputeLost)
        );

        // A full refund of either purchase inside its window now retires
        for (user, id, number) in [("u1", &first.id, 1), ("u2", &second.id, 2)] {
            assert_eq!(
                refund(&db, id, NOW + 2 * DAY).await,
                ReverseOutcome::Applied
            );
            assert_eq!(membership(&db, user).await.number, number);
            assert_eq!(
                db.fetch_cipher_number_by_order(id).await.unwrap(),
                Some(number)
            );
        }
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 2);
        drop_db(&db).await;
    }

    /// Apply a full refund made at `at` through `stripe` (whose calls the
    /// test then reads)
    async fn refund_via(
        db: &Database,
        stripe: &MockStripe,
        order_id: &str,
        at: i64,
    ) -> ReverseOutcome {
        reverse_order(
            db,
            stripe,
            &settings(),
            order_id,
            ReverseKind::Refund,
            full_refund(at),
            at,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn the_sweep_refunds_the_upgrades_before_it_deletes_a_released_membership() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW + DAY).await;
        release_decided(&db, "u1", &first.id, NOW + 2 * DAY, true).await;

        assert_eq!(
            reconcile(&db, &stripe, &s, NOW + 2 * DAY + 2 * MINUTE)
                .await
                .unwrap(),
            "expired=0, resumed=0, reversed=1, redriven=0, errors=0"
        );
        assert_eq!(
            refund_keys(&stripe),
            vec![(
                "pi_up".to_string(),
                Some(format!("release-upgrade-{}", up.id))
            )]
        );
        assert_eq!(order(&db, &up.id).await.state, OrderState::Refunded);
        assert_eq!(maybe_membership(&db, "u1").await, None);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_release_holds_the_number_until_its_upgrade_refund_is_recorded() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW + DAY).await;

        // The purchase is refunded in its window; our refund of the upgrade
        // is accepted by Stripe but still settling
        stripe.set_refund_status("pending");
        let at = NOW + 2 * DAY;
        assert_eq!(
            refund_via(&db, &stripe, &first.id, at).await,
            ReverseOutcome::RecordedPending
        );
        assert_eq!(
            refund_keys(&stripe),
            vec![(
                "pi_up".to_string(),
                Some(format!("release-upgrade-{}", up.id))
            )]
        );

        // Revoked (no badge), but the row and #1 stay until the upgrade's
        // refund is recorded
        let m = membership(&db, "u1").await;
        assert_eq!(
            (m.number, m.revoke_reason),
            (1, Some(CipherRevokeReason::Refund))
        );
        assert_eq!(badge(&db, "u1").await, None);
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1)
        );
        assert_eq!(order(&db, &first.id).await.state, OrderState::Fulfilled);
        assert_eq!(order(&db, &up.id).await.state, OrderState::Fulfilled);
        assert_eq!(
            db.fetch_cipher_numbers_release_pending(10)
                .await
                .unwrap()
                .len(),
            1
        );

        // A sweep meanwhile asks again under the same key and keeps waiting
        assert_eq!(
            reconcile(&db, &stripe, &s, at + 2 * MINUTE).await.unwrap(),
            "expired=0, resumed=0, reversed=0, redriven=0, errors=0"
        );
        assert_eq!(stripe.refund_count_for("pi_up"), 1);
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1)
        );
        // Nobody else gets #1 meanwhile
        buy(
            &db,
            &stripe,
            &s,
            "u2",
            CipherTier::T99,
            "pi_2",
            at + 3 * MINUTE,
        )
        .await;
        assert_eq!(membership(&db, "u2").await.number, 2);

        // The upgrade's refund succeeds: its charge.refund.updated records
        // it Refunded (the membership is revoked, so nothing rolls back)
        assert_eq!(
            refund_via(&db, &stripe, &up.id, at + 4 * MINUTE).await,
            ReverseOutcome::Applied
        );
        assert_eq!(order(&db, &up.id).await.state, OrderState::Refunded);
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1),
            "still claimed until the release runs again"
        );

        // The sweep finishes the release
        assert_eq!(
            reconcile(&db, &stripe, &s, at + 5 * MINUTE).await.unwrap(),
            "expired=0, resumed=0, reversed=1, redriven=0, errors=0"
        );
        assert_eq!(maybe_membership(&db, "u1").await, None);
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            None
        );
        assert_eq!(order(&db, &first.id).await.state, OrderState::Refunded);
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(stripe.refund_count_for("pi_up"), 1);
        assert_eq!(stripe.refund_count_for("pi_1"), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_failed_upgrade_refund_keeps_the_release_pending_and_the_sweep_retries() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T149, "pi_up", NOW + DAY).await;

        // Stripe is unreachable when the release asks for the refund
        stripe.fail_next(
            "create_refund",
            StripeError::Transport("connection reset".to_string()),
        );
        let at = NOW + 2 * DAY;
        assert_eq!(
            refund_via(&db, &stripe, &first.id, at).await,
            ReverseOutcome::RecordedPending
        );
        assert_eq!(stripe.refund_count(), 0);
        assert_eq!(order(&db, &up.id).await.state, OrderState::Fulfilled);
        assert_eq!(membership(&db, "u1").await.number, 1);
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1)
        );

        // Stripe refuses it next (a failed refund)
        stripe.set_refund_status("failed");
        assert_eq!(
            finish_number_release(&db, &stripe, &first.id, at + MINUTE)
                .await
                .unwrap(),
            ReverseOutcome::RecordedPending
        );
        assert_eq!(stripe.refund_count(), 0);
        assert!(maybe_membership(&db, "u1").await.is_some());

        // Stripe answers that key with the same refusal for 24 hours; a
        // day later (a mock with no replay cached) the sweep's refund goes
        // through, the upgrade is recorded and the release finishes
        let mock = MockStripe::new();
        assert_eq!(
            reconcile(&db, &mock, &s, at + DAY).await.unwrap(),
            "expired=0, resumed=0, reversed=1, redriven=0, errors=0"
        );
        assert_eq!(
            refund_keys(&mock),
            vec![(
                "pi_up".to_string(),
                Some(format!("release-upgrade-{}", up.id))
            )]
        );
        assert_eq!(order(&db, &up.id).await.state, OrderState::Refunded);
        assert_eq!(maybe_membership(&db, "u1").await, None);
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            None
        );
        assert_eq!(order(&db, &first.id).await.state, OrderState::Refunded);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_dispute_opened_while_a_release_is_pending_keeps_the_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        release_decided(&db, "u1", &first.id, NOW + DAY, true).await;

        // A dispute on the purchase opens before the release finished: it
        // is recorded on the order, and the number stays retired
        assert_eq!(
            on_dispute(
                &db,
                &first.id,
                "dp_1",
                ReverseKind::DisputeOpened,
                NOW + DAY + 1
            )
            .await
            .unwrap(),
            ReverseOutcome::Applied
        );
        let o = order(&db, &first.id).await;
        assert_eq!(o.open_disputes, vec!["dp_1".to_string()]);
        assert_eq!(o.state, OrderState::Refunded);
        let m = membership(&db, "u1").await;
        assert_eq!(
            (m.number, m.revoke_reason),
            (1, Some(CipherRevokeReason::Refund))
        );
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1)
        );
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());

        // A later lost dispute records it on the kept row
        on_dispute(
            &db,
            &first.id,
            "dp_1",
            ReverseKind::DisputeLost,
            NOW + DAY + 2,
        )
        .await
        .unwrap();
        assert_eq!(
            membership(&db, "u1").await.revoke_reason,
            Some(CipherRevokeReason::DisputeLost)
        );

        buy(
            &db,
            &stripe,
            &s,
            "u2",
            CipherTier::T99,
            "pi_2",
            NOW + DAY + 3,
        )
        .await;
        assert_eq!(membership(&db, "u2").await.number, 2);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_refund_that_has_not_succeeded_reverses_nothing() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let before = membership(&db, "u1").await;
        for status in [RefundStatus::Pending, RefundStatus::Failed] {
            for full in [true, false] {
                let facts = Some(RefundFacts {
                    refunded_at_ms: NOW + DAY,
                    full,
                    status,
                });
                assert_eq!(
                    refund_with(&db, &first.id, facts, NOW + DAY).await,
                    ReverseOutcome::NoOp,
                    "{status:?} full={full}"
                );
            }
        }
        assert_eq!(membership(&db, "u1").await, before);
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));
        assert_eq!(order(&db, &first.id).await.state, OrderState::Fulfilled);
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());

        // Once it succeeds, the refund made on day 1 releases the number
        assert_eq!(
            refund_with(&db, &first.id, full_refund(NOW + DAY), AFTER_WINDOW).await,
            ReverseOutcome::Applied
        );
        assert_eq!(maybe_membership(&db, "u1").await, None);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_rolled_back_upgrade_keeps_the_badge_hidden_while_another_order_is_disputed() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW + DAY).await;
        on_dispute(
            &db,
            &first.id,
            "dp_1",
            ReverseKind::DisputeOpened,
            NOW + DAY + 1,
        )
        .await
        .unwrap();
        assert_eq!(badge(&db, "u1").await, None);

        assert_eq!(
            refund(&db, &up.id, NOW + 2 * DAY).await,
            ReverseOutcome::Applied
        );
        let m = membership(&db, "u1").await;
        assert!(m.is_active());
        assert_eq!(m.tier, CipherTier::T99);
        assert_eq!(m.orders, vec![first.id.clone()]);
        assert_eq!(m.disputed_orders, vec![first.id.clone()]);
        assert_eq!(badge(&db, "u1").await, None);

        // Won: the badge comes back at the rolled-back tier
        on_dispute(
            &db,
            &first.id,
            "dp_1",
            ReverseKind::DisputeWon,
            NOW + 3 * DAY,
        )
        .await
        .unwrap();
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));
        drop_db(&db).await;
    }

    /// Our refund of `up`'s payment (`pi_up`) as Stripe lists it now
    fn upgrade_refund(id: &str, up: &PaymentOrder, status: &str, made: i64) -> Refund {
        Refund {
            id: id.to_string(),
            status: Some(status.to_string()),
            amount: Some(up.amount_cents),
            payment_intent: Some("pi_up".to_string()),
            created: Some(made / 1000),
        }
    }

    #[tokio::test]
    async fn a_settling_upgrade_refund_whose_update_is_lost_still_finishes_the_release() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW + DAY).await;

        // The purchase is refunded in its window; our refund of the upgrade
        // is accepted but still settling
        stripe.set_refund_status("pending");
        let at = NOW + 2 * DAY;
        assert_eq!(
            refund_via(&db, &stripe, &first.id, at).await,
            ReverseOutcome::RecordedPending
        );
        stripe.set_refund(upgrade_refund("re_test_1", &up, "pending", at));

        // Its charge.refunded arrives while it is still pending: nothing is
        // reversed, the upgrade is marked, and the release keeps waiting
        let refunded = StripeEvent {
            id: "evt_up".to_string(),
            event_type: "charge.refunded".to_string(),
            livemode: false,
            created: at / 1000,
            object: serde_json::json!({
                "id": "ch_up",
                "object": "charge",
                "payment_intent": "pi_up"
            }),
        };
        assert_eq!(
            handle_event(&db, &stripe, &s, &refunded, at + MINUTE)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        let o = order(&db, &up.id).await;
        assert_eq!(o.state, OrderState::Fulfilled);
        assert_eq!(o.refund_settling_since, Some(at + MINUTE));
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1)
        );
        assert!(maybe_membership(&db, "u1").await.is_some());

        // It succeeds and its charge.refund.updated is lost: one sweep reads
        // it, records the upgrade Refunded and finishes the release
        stripe.set_refund(upgrade_refund("re_test_1", &up, "succeeded", at));
        assert_eq!(
            reconcile(&db, &stripe, &s, at + 10 * MINUTE).await.unwrap(),
            "expired=0, resumed=0, reversed=2, redriven=0, errors=0"
        );
        let o = order(&db, &up.id).await;
        assert_eq!(o.state, OrderState::Refunded);
        assert_eq!(o.refund_settling_since, None);
        assert_eq!(maybe_membership(&db, "u1").await, None);
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            None
        );
        assert_eq!(order(&db, &first.id).await.state, OrderState::Refunded);
        assert_eq!(stripe.refund_count_for("pi_up"), 1);
        assert_eq!(stripe.refund_count_for("pi_1"), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn an_upgrade_already_refunded_is_recorded_only_once_its_refunds_succeed() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW + DAY).await;

        // The upgrade was refunded before (here in the Dashboard; also our
        // own refund once its key expired), and that refund is pending
        stripe.set_refund_status("pending");
        let earlier = StripeApi::create_refund(&stripe, "pi_up", "dashboard-up")
            .await
            .unwrap();
        stripe.set_refund_status("succeeded");
        stripe.set_refund(upgrade_refund(&earlier.id, &up, "pending", NOW + DAY));

        // Stripe answers our refund with charge_already_refunded, but the
        // money is not back yet: the release waits
        let at = NOW + 2 * DAY;
        assert_eq!(
            refund_via(&db, &stripe, &first.id, at).await,
            ReverseOutcome::RecordedPending
        );
        assert_eq!(order(&db, &up.id).await.state, OrderState::Fulfilled);
        assert!(maybe_membership(&db, "u1").await.is_some());
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1)
        );

        // It succeeds: the next run records the upgrade and finishes
        stripe.set_refund(upgrade_refund(&earlier.id, &up, "succeeded", NOW + DAY));
        assert_eq!(
            finish_number_release(&db, &stripe, &first.id, at + MINUTE)
                .await
                .unwrap(),
            ReverseOutcome::Applied
        );
        assert_eq!(order(&db, &up.id).await.state, OrderState::Refunded);
        assert_eq!(maybe_membership(&db, "u1").await, None);
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            None
        );
        assert_eq!(stripe.refund_count_for("pi_up"), 1);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_disputed_charge_refused_for_our_upgrade_refund_keeps_the_release_pending() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW + DAY).await;

        // The upgrade's payment is under a dispute we have not heard of yet:
        // Stripe refuses our refund of it
        let disputed = || StripeError::Api {
            status: 400,
            code: Some("charge_disputed".to_string()),
            kind: Some("invalid_request_error".to_string()),
            message: "This charge has been charged back.".to_string(),
        };
        stripe.fail_next("create_refund", disputed());
        let at = NOW + 2 * DAY;
        assert_eq!(
            refund_via(&db, &stripe, &first.id, at).await,
            ReverseOutcome::RecordedPending
        );

        // Revoked, but the row and #1 stay, and the release stays pending
        let m = membership(&db, "u1").await;
        assert_eq!(
            (m.number, m.revoke_reason),
            (1, Some(CipherRevokeReason::Refund))
        );
        assert_eq!(badge(&db, "u1").await, None);
        assert_eq!(order(&db, &up.id).await.state, OrderState::Fulfilled);
        assert_eq!(order(&db, &first.id).await.state, OrderState::Fulfilled);
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1)
        );
        assert_eq!(
            db.fetch_cipher_numbers_release_pending(10)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(stripe.refund_count(), 0);

        // Refused again at the next run: still waiting
        stripe.fail_next("create_refund", disputed());
        assert_eq!(
            finish_number_release(&db, &stripe, &first.id, at + MINUTE)
                .await
                .unwrap(),
            ReverseOutcome::RecordedPending
        );
        assert!(maybe_membership(&db, "u1").await.is_some());
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            Some(1)
        );
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn an_upgrade_the_release_records_refunded_is_no_longer_marked_settling() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_up", NOW + DAY).await;

        // The upgrade was refunded in the Dashboard; the refund is pending,
        // and its charge.refunded marked the upgrade settling
        stripe.set_refund_status("pending");
        let earlier = StripeApi::create_refund(&stripe, "pi_up", "dashboard-up")
            .await
            .unwrap();
        stripe.set_refund_status("succeeded");
        stripe.set_refund(upgrade_refund(&earlier.id, &up, "pending", NOW + DAY));
        assert_eq!(
            mark_refund_settling(&db, &up.id, NOW + DAY + MINUTE)
                .await
                .unwrap(),
            ReverseOutcome::RecordedPending
        );

        // The purchase is refunded in its window: the release waits for the
        // upgrade's refund
        let at = NOW + 2 * DAY;
        assert_eq!(
            refund_via(&db, &stripe, &first.id, at).await,
            ReverseOutcome::RecordedPending
        );

        // It succeeds, and the release (not the upgrade's own event)
        // records the upgrade Refunded: the mark goes with it
        stripe.set_refund(upgrade_refund(&earlier.id, &up, "succeeded", NOW + DAY));
        assert_eq!(
            finish_number_release(&db, &stripe, &first.id, at + MINUTE)
                .await
                .unwrap(),
            ReverseOutcome::Applied
        );
        let o = order(&db, &up.id).await;
        assert_eq!(o.state, OrderState::Refunded);
        assert_eq!(o.refund_settling_since, None);
        assert!(db
            .fetch_payment_orders_refund_settling(at + 2 * MINUTE, 0)
            .await
            .unwrap()
            .is_empty());
        drop_db(&db).await;
    }

    // --- regions Cipher is not sold to --------------------------------

    /// The buyer pays with a billing address in `country`
    fn pay_from(
        stripe: &MockStripe,
        order: &PaymentOrder,
        payment_intent: &str,
        country: Option<&str>,
    ) -> CheckoutSession {
        let mut session = pay(stripe, order, payment_intent);
        session.billing_country = country.map(str::to_string);
        stripe.set_session(session.clone());
        session
    }

    #[tokio::test]
    async fn a_payment_billed_to_a_blocked_country_is_voided_and_refunded() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3", "u4"] {
            insert_user(&db, user).await;
        }

        // Blocked, in any case Stripe reports it: refunded under the void
        // key, no number claimed, no membership, no badge
        for (user, country, pi) in [("u1", "DE", "pi_de"), ("u2", "gb", "pi_gb")] {
            let pending = checkout(&db, &stripe, &s, user, CipherTier::T149, NOW).await;
            let session = pay_from(&stripe, &pending, pi, Some(country));
            assert_eq!(
                fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW)
                    .await
                    .unwrap(),
                FulfilOutcome::Voided(VoidReason::RegionUnavailable)
            );
            let voided = order(&db, &pending.id).await;
            assert_eq!(voided.state, OrderState::Voided);
            assert_eq!(voided.void_reason, Some(VoidReason::RegionUnavailable));
            assert_eq!(
                db.fetch_cipher_number_by_order(&pending.id).await.unwrap(),
                None
            );
            assert_eq!(maybe_membership(&db, user).await, None);
            assert_eq!(badge(&db, user).await, None);
            assert!(refund_keys(&stripe)
                .contains(&(pi.to_string(), Some(format!("void-{}", pending.id)))));

            // A redelivery refunds nothing more
            assert_eq!(
                fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 1)
                    .await
                    .unwrap(),
                FulfilOutcome::Voided(VoidReason::RegionUnavailable)
            );
        }
        assert_eq!(stripe.refund_count(), 2);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);

        // Not blocked, or no country reported: fulfilled as usual (u1 is
        // refused a new checkout, see
        // `a_buyer_refunded_for_their_region_gets_no_new_checkout`)
        for (user, country, pi) in [("u3", Some("US"), "pi_us"), ("u4", None, "pi_none")] {
            let pending = checkout(&db, &stripe, &s, user, CipherTier::T99, NOW + 2).await;
            let session = pay_from(&stripe, &pending, pi, country);
            assert_eq!(
                fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 2)
                    .await
                    .unwrap(),
                FulfilOutcome::Fulfilled
            );
        }
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 2);
        assert_eq!(stripe.refund_count(), 2);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn an_upgrade_billed_to_a_blocked_country_is_refunded_and_the_tier_kept() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        let up = checkout(&db, &stripe, &s, "u1", CipherTier::T299, NOW + DAY).await;
        assert!(matches!(up.sku, Sku::CipherUpgrade { .. }));
        let session = pay_from(&stripe, &up, "pi_up", Some("FR"));
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &up.id, &session, NOW + DAY)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::RegionUnavailable)
        );
        let m = membership(&db, "u1").await;
        assert_eq!((m.number, m.tier), (1, CipherTier::T99));
        assert!(!m.orders.contains(&up.id));
        assert_eq!(badge(&db, "u1").await, badge_of(1, CipherTier::T99));
        assert_eq!(
            refund_keys(&stripe),
            vec![("pi_up".to_string(), Some(format!("void-{}", up.id)))]
        );
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn the_region_rule_never_undoes_an_applied_order() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        // A worker applied the order (no country reported then), then
        // crashed before writing it Fulfilled; the session read on resume
        // reports a blocked country. The applied order is finished, never
        // refunded or re-numbered.
        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay_from(&stripe, &pending, "pi_1", None);
        crash_after(&db, &pending.id, |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some("pi_1".to_string());
            o.paid_at = Some(NOW);
        })
        .await;
        let leased = acquire(&db, &pending.id, LATER).await.unwrap().unwrap();
        assert!(matches!(
            apply_membership(&db, &s, &leased.order, "u1", LATER)
                .await
                .unwrap(),
            Applied::Done
        ));
        release(&db, &leased).await;

        let blocked = pay_from(&stripe, &pending, "pi_1", Some("DE"));
        assert_ne!(blocked, session);
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &blocked, LATER + 1)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        assert_eq!(membership(&db, "u1").await.number, 1);
        assert_eq!(stripe.refund_count(), 0);
        drop_db(&db).await;
    }

    /// Paid by `method`, issued in `country`
    fn paid_by(payment_intent: &str, method: &str, country: Option<&str>) -> PaymentCharge {
        PaymentCharge {
            payment_intent: payment_intent.to_string(),
            method: Some(method.to_string()),
            card_country: country.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn a_buyer_refunded_for_their_region_gets_no_new_checkout() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3"] {
            insert_user(&db, user).await;
        }

        // u1: voided and refunded for the billing country
        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay_from(&stripe, &pending, "pi_de", Some("DE"));
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::RegionUnavailable)
        );

        // u2: the same void, stopped after the refund (Stripe acted, its
        // answer was lost): Paid, the reason recorded
        let stopped = checkout(&db, &stripe, &s, "u2", CipherTier::T99, NOW).await;
        let session = pay_from(&stripe, &stopped, "pi_gb", Some("GB"));
        stripe.fail_next_after_effect(
            "create_refund",
            StripeError::Transport("timeout".to_string()),
        );
        assert!(matches!(
            error_type(fulfil_order(&db, &stripe, &s, &stopped.id, &session, NOW).await),
            ErrorType::PaymentProviderError
        ));
        let paid = order(&db, &stopped.id).await;
        assert_eq!(paid.state, OrderState::Paid);
        assert_eq!(paid.void_reason, Some(VoidReason::RegionUnavailable));

        // Neither gets a new checkout, of any tier: no order, no session
        let sessions = stripe.call_count("create_checkout_session");
        for user in ["u1", "u2"] {
            for tier in [CipherTier::T99, CipherTier::T299] {
                assert!(matches!(
                    error_type(
                        create_cipher_checkout(
                            &db,
                            &stripe,
                            &s,
                            user,
                            tier,
                            CipherReturnTo::Web,
                            NOW + DAY
                        )
                        .await
                    ),
                    ErrorType::CipherRegionUnavailable
                ));
            }
            assert!(db
                .fetch_payment_orders_by_user(user, &[OrderState::Creating, OrderState::Pending])
                .await
                .unwrap()
                .is_empty());
        }
        assert_eq!(stripe.call_count("create_checkout_session"), sessions);
        assert_eq!(stripe.refund_count(), 2);

        // Another void reason blocks nothing
        let other = checkout(&db, &stripe, &s, "u3", CipherTier::T99, NOW).await;
        crash_after(&db, &other.id, |o| {
            o.state = OrderState::Voided;
            o.void_reason = Some(VoidReason::SoldOut);
        })
        .await;
        buy(&db, &stripe, &s, "u3", CipherTier::T99, "pi_us", LATER).await;
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_void_stopped_after_its_refund_is_finished_even_once_its_cause_is_gone() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        // A purchase opened before a release of the buyer's number, paid
        // while it runs: voided (ReleasePending). The refund goes through,
        // then the worker stops before writing the order Voided.
        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        change_membership(&db, "u1", revoked_for_refund(NOW + DAY)).await;
        let late = checkout(&db, &stripe, &s, "u1", CipherTier::T149, NOW + DAY).await;
        release_decided(&db, "u1", &first.id, NOW + DAY + 1, false).await;
        let session = pay(&stripe, &late, "pi_late");
        stripe.fail_next_after_effect(
            "create_refund",
            StripeError::Transport("timeout".to_string()),
        );
        assert!(matches!(
            error_type(fulfil_order(&db, &stripe, &s, &late.id, &session, NOW + DAY + 3).await),
            ErrorType::PaymentProviderError
        ));
        let stopped = order(&db, &late.id).await;
        assert_eq!(stopped.state, OrderState::Paid);
        assert_eq!(stopped.void_reason, Some(VoidReason::ReleasePending));
        assert!(stopped.lease_until.is_none());
        assert_eq!(stripe.refund_count_for("pi_late"), 1);

        // The release finishes before anything picks the order up again
        assert_eq!(
            finish_number_release(&db, &stripe, &first.id, NOW + DAY + MINUTE)
                .await
                .unwrap(),
            ReverseOutcome::Applied
        );
        assert_eq!(maybe_membership(&db, "u1").await, None);

        // The resume finishes the void: the refunded payment is never
        // applied (no number, no membership, no badge), nor refunded twice
        assert_eq!(
            resume_order(&db, &stripe, &s, &late.id, NOW + DAY + 2 * MINUTE)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::ReleasePending)
        );
        let voided = order(&db, &late.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.void_reason, Some(VoidReason::ReleasePending));
        assert_eq!(
            db.fetch_cipher_number_by_order(&late.id).await.unwrap(),
            None
        );
        assert_eq!(maybe_membership(&db, "u1").await, None);
        assert_eq!(badge(&db, "u1").await, None);
        assert_eq!(stripe.refund_count_for("pi_late"), 1);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_card_issued_in_a_blocked_country_is_voided_whatever_the_billing_address() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();

        // A card (a wallet too) or a Link card issued in a blocked country,
        // billed to the US: refunded under the void key, nothing claimed
        for (user, pi, method, country) in [
            ("u1", "pi_card_de", "card", "DE"),
            ("u2", "pi_link_fr", "link", "fr"),
        ] {
            insert_user(&db, user).await;
            let pending = checkout(&db, &stripe, &s, user, CipherTier::T149, NOW).await;
            let session = pay_from(&stripe, &pending, pi, Some("US"));
            stripe.set_payment_charge(paid_by(pi, method, Some(country)));
            assert_eq!(
                fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW)
                    .await
                    .unwrap(),
                FulfilOutcome::Voided(VoidReason::RegionUnavailable)
            );
            let voided = order(&db, &pending.id).await;
            assert_eq!(voided.state, OrderState::Voided);
            assert_eq!(voided.void_reason, Some(VoidReason::RegionUnavailable));
            assert_eq!(
                db.fetch_cipher_number_by_order(&pending.id).await.unwrap(),
                None
            );
            assert_eq!(maybe_membership(&db, user).await, None);
            assert_eq!(badge(&db, user).await, None);
            assert!(refund_keys(&stripe)
                .contains(&(pi.to_string(), Some(format!("void-{}", pending.id)))));
        }
        assert_eq!(stripe.refund_count(), 2);

        // A US card billed to the US, and a method with no card country
        // billed to the US: fulfilled
        for (user, pi, method, country) in [
            ("u3", "pi_card_us", "card", Some("US")),
            ("u4", "pi_cashapp_us", "cashapp", None),
        ] {
            insert_user(&db, user).await;
            let pending = checkout(&db, &stripe, &s, user, CipherTier::T99, NOW + 1).await;
            let session = pay_from(&stripe, &pending, pi, Some("US"));
            stripe.set_payment_charge(paid_by(pi, method, country));
            assert_eq!(
                fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 1)
                    .await
                    .unwrap(),
                FulfilOutcome::Fulfilled
            );
            assert!(membership(&db, user).await.is_active());
        }

        // A method with no card country is judged on the billing country
        // alone: billed to a blocked one, it is voided before the charge is
        // read at all
        insert_user(&db, "u5").await;
        let pending = checkout(&db, &stripe, &s, "u5", CipherTier::T99, NOW + 2).await;
        let session = pay_from(&stripe, &pending, "pi_cashapp_de", Some("DE"));
        stripe.set_payment_charge(paid_by("pi_cashapp_de", "cashapp", None));
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 2)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::RegionUnavailable)
        );

        assert_eq!(stripe.refund_count(), 3);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 2);
        assert_eq!(stripe.call_count("get_payment_charge"), 4);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_charge_that_cannot_be_read_applies_nothing_until_it_is_read() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay_from(&stripe, &pending, "pi_1", Some("US"));
        stripe.set_payment_charge(paid_by("pi_1", "card", Some("DE")));
        stripe.fail_next(
            "get_payment_charge",
            StripeError::Transport("timeout".to_string()),
        );
        assert!(matches!(
            error_type(fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW).await),
            ErrorType::PaymentProviderError
        ));
        let kept = order(&db, &pending.id).await;
        assert_eq!(kept.state, OrderState::Paid);
        assert_eq!(kept.void_reason, None);
        assert!(kept.lease_until.is_none());
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        assert_eq!(stripe.refund_count(), 0);

        // The next attempt reads the charge and voids
        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, NOW + 1)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::RegionUnavailable)
        );
        assert_eq!(stripe.refund_count_for("pi_1"), 1);
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        drop_db(&db).await;
    }

    // --- card country Stripe will not report ----------------------------

    /// Error-level log lines of this test binary, so a test can assert an
    /// operator alert was raised (each test filters by its own order id)
    static ERROR_LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    struct ErrorLog;

    impl log::Log for ErrorLog {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() <= log::Level::Error
        }

        fn log(&self, record: &log::Record) {
            if self.enabled(record.metadata()) {
                ERROR_LINES
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(record.args().to_string());
            }
        }

        fn flush(&self) {}
    }

    /// Start capturing error-level log lines (once per test binary). Panics
    /// if another logger is installed: the assertions would see nothing.
    fn capture_error_log() {
        static LOGGER: ErrorLog = ErrorLog;
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            log::set_logger(&LOGGER).expect("no other logger in this test binary");
            log::set_max_level(log::LevelFilter::Error);
        });
    }

    /// Captured `CARD_COUNTRY_UNAVAILABLE` alerts naming `order_id`
    fn card_country_alerts(order_id: &str) -> usize {
        ERROR_LINES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|line| {
                line.starts_with("payments: CARD_COUNTRY_UNAVAILABLE ") && line.contains(order_id)
            })
            .count()
    }

    fn api_error(status: u16, kind: &str) -> StripeError {
        StripeError::Api {
            status,
            code: None,
            kind: Some(kind.to_string()),
            message: format!("a {kind}"),
        }
    }

    #[test]
    fn only_a_refusal_retrying_cannot_fix_lets_the_card_country_go_unread() {
        for (err, unreadable) in [
            (api_error(403, "permission_error"), true),
            (api_error(400, "invalid_request_error"), true),
            (api_error(404, "invalid_request_error"), true),
            (
                StripeError::Decode("latest_charge is not expanded".to_string()),
                true,
            ),
            (api_error(429, "rate_limit_error"), false),
            (api_error(429, "invalid_request_error"), false),
            (api_error(500, "api_error"), false),
            (api_error(503, "invalid_request_error"), false),
            (api_error(401, "authentication_error"), false),
            (api_error(402, "card_error"), false),
            (api_error(400, "idempotency_error"), false),
            (
                StripeError::Api {
                    status: 403,
                    code: None,
                    kind: None,
                    message: "HTTP 403 without a Stripe error body".to_string(),
                },
                false,
            ),
            (
                StripeError::Transport("request timed out".to_string()),
                false,
            ),
        ] {
            assert_eq!(card_country_unreadable(&err), unreadable, "{err:?}");
        }
    }

    #[tokio::test]
    async fn a_card_country_stripe_refuses_for_good_is_waited_on_then_the_billing_country_decides()
    {
        capture_error_log();
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        // Paid at NOW, billed to the US; the key may not read charges
        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay_from(&stripe, &pending, "pi_1", Some("US"));
        stripe.fail_next("get_payment_charge", api_error(403, "permission_error"));
        assert!(matches!(
            error_type(fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW).await),
            ErrorType::PaymentProviderError
        ));

        // Still within the wait: an error, the order kept Paid, nothing
        // claimed, no alert
        stripe.fail_next("get_payment_charge", api_error(403, "permission_error"));
        let at = NOW + CARD_COUNTRY_WAIT_MS;
        assert!(matches!(
            error_type(resume_order(&db, &stripe, &s, &pending.id, at).await),
            ErrorType::PaymentProviderError
        ));
        let kept = order(&db, &pending.id).await;
        assert_eq!(kept.state, OrderState::Paid);
        assert_eq!(kept.paid_at, Some(NOW));
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        assert_eq!(card_country_alerts(&pending.id), 0);

        // Past it: fulfilled on the billing country alone, and alerted
        stripe.fail_next("get_payment_charge", api_error(403, "permission_error"));
        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, at + 1)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        assert!(membership(&db, "u1").await.is_active());
        assert_eq!(stripe.refund_count(), 0);
        assert_eq!(stripe.call_count("get_payment_charge"), 3);
        assert_eq!(card_country_alerts(&pending.id), 1);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_card_country_read_failing_for_a_passing_reason_never_falls_back() {
        capture_error_log();
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        // A card issued in a blocked country, billed to the US
        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay_from(&stripe, &pending, "pi_1", Some("US"));
        stripe.set_payment_charge(paid_by("pi_1", "card", Some("DE")));
        stripe.fail_next("get_payment_charge", api_error(500, "api_error"));
        assert!(matches!(
            error_type(fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW).await),
            ErrorType::PaymentProviderError
        ));

        // However long after the payment: fail closed, every time
        let past = NOW + CARD_COUNTRY_WAIT_MS + 1;
        for (i, err) in [
            api_error(500, "api_error"),
            // A 5xx whatever type it names
            api_error(503, "invalid_request_error"),
            api_error(429, "rate_limit_error"),
            api_error(429, "invalid_request_error"),
            api_error(401, "authentication_error"),
            StripeError::Transport("request timed out".to_string()),
        ]
        .into_iter()
        .enumerate()
        {
            stripe.fail_next("get_payment_charge", err.clone());
            let at = past + i as i64 * DAY;
            assert!(
                matches!(
                    error_type(resume_order(&db, &stripe, &s, &pending.id, at).await),
                    ErrorType::PaymentProviderError
                ),
                "{err:?}"
            );
            let kept = order(&db, &pending.id).await;
            assert_eq!(kept.state, OrderState::Paid);
            assert_eq!(kept.void_reason, None);
        }
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        assert_eq!(maybe_membership(&db, "u1").await, None);
        assert_eq!(card_country_alerts(&pending.id), 0);

        // Once it reads, the card's country decides
        assert_eq!(
            resume_order(&db, &stripe, &s, &pending.id, past + 10 * DAY)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::RegionUnavailable)
        );
        assert_eq!(stripe.refund_count_for("pi_1"), 1);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_charge_that_never_decodes_falls_back_to_the_billing_country_after_the_wait() {
        capture_error_log();
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();

        for (user, pi, err) in [
            (
                "u1",
                "pi_1",
                StripeError::Decode("latest_charge is not expanded".to_string()),
            ),
            ("u2", "pi_2", api_error(404, "invalid_request_error")),
        ] {
            insert_user(&db, user).await;
            let pending = checkout(&db, &stripe, &s, user, CipherTier::T99, NOW).await;
            let session = pay_from(&stripe, &pending, pi, Some("US"));
            stripe.fail_next("get_payment_charge", err.clone());
            assert!(matches!(
                error_type(fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW).await),
                ErrorType::PaymentProviderError
            ));
            assert_eq!(order(&db, &pending.id).await.state, OrderState::Paid);

            stripe.fail_next("get_payment_charge", err);
            assert_eq!(
                resume_order(
                    &db,
                    &stripe,
                    &s,
                    &pending.id,
                    NOW + CARD_COUNTRY_WAIT_MS + 1
                )
                .await
                .unwrap(),
                FulfilOutcome::Fulfilled
            );
            assert!(membership(&db, user).await.is_active());
            assert_eq!(card_country_alerts(&pending.id), 1);
        }
        assert_eq!(stripe.refund_count(), 0);
        drop_db(&db).await;
    }

    // --- how long a region void refuses checkout -------------------------

    async fn try_checkout(
        db: &Database,
        stripe: &MockStripe,
        s: &PaymentsSettings,
        user: &str,
        at: i64,
    ) -> Result<String> {
        create_cipher_checkout(
            db,
            stripe,
            s,
            user,
            CipherTier::T99,
            CipherReturnTo::Web,
            at,
        )
        .await
    }

    #[tokio::test]
    async fn a_region_refusal_holds_only_while_its_country_is_blocked_and_for_30_days() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        for user in ["u1", "u2", "u3"] {
            insert_user(&db, user).await;
        }

        // u1: voided at NOW for the billing country, which is kept
        let billed = checkout(&db, &stripe, &s, "u1", CipherTier::T99, NOW).await;
        let session = pay_from(&stripe, &billed, "pi_de", Some("DE"));
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &billed.id, &session, NOW)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::RegionUnavailable)
        );
        let voided = order(&db, &billed.id).await;
        assert_eq!(voided.region_blocked_country.as_deref(), Some("DE"));
        assert_eq!(voided.reversed_at, Some(NOW));

        // u2: a card issued in FR, billed to the US, the void stopped after
        // the refund: Paid at NOW, reason and country recorded
        let carded = checkout(&db, &stripe, &s, "u2", CipherTier::T99, NOW).await;
        let session = pay_from(&stripe, &carded, "pi_fr", Some("US"));
        stripe.set_payment_charge(paid_by("pi_fr", "card", Some("FR")));
        stripe.fail_next_after_effect(
            "create_refund",
            StripeError::Transport("timeout".to_string()),
        );
        assert!(matches!(
            error_type(fulfil_order(&db, &stripe, &s, &carded.id, &session, NOW).await),
            ErrorType::PaymentProviderError
        ));
        let stopped = order(&db, &carded.id).await;
        assert_eq!(stopped.state, OrderState::Paid);
        assert_eq!(stopped.void_reason, Some(VoidReason::RegionUnavailable));
        assert_eq!(stopped.region_blocked_country.as_deref(), Some("FR"));

        // u3: a region void recorded before the country was kept
        let legacy = checkout(&db, &stripe, &s, "u3", CipherTier::T99, NOW).await;
        crash_after(&db, &legacy.id, |o| {
            o.state = OrderState::Voided;
            o.void_reason = Some(VoidReason::RegionUnavailable);
            o.reversed_at = Some(NOW);
        })
        .await;

        // Listed and recent: refused, to the last millisecond
        let last = NOW + REGION_REFUSAL_MS - 1;
        for user in ["u1", "u2"] {
            assert!(matches!(
                error_type(try_checkout(&db, &stripe, &s, user, last).await),
                ErrorType::CipherRegionUnavailable
            ));
        }
        // No country on record: never refused
        try_checkout(&db, &stripe, &s, "u3", NOW + DAY)
            .await
            .unwrap();

        // DE taken off the list: u1 is let in, u2 (FR) is not
        let without_de = PaymentsSettings {
            blocked_countries: s
                .blocked_countries
                .iter()
                .filter(|country| country.as_str() != "DE")
                .cloned()
                .collect(),
            ..settings()
        };
        assert!(without_de.region_blocked("FR"));
        try_checkout(&db, &stripe, &without_de, "u1", NOW + DAY)
            .await
            .unwrap();
        assert!(matches!(
            error_type(try_checkout(&db, &stripe, &without_de, "u2", NOW + DAY).await),
            ErrorType::CipherRegionUnavailable
        ));

        // Nothing blocked at all: let in
        let open = PaymentsSettings {
            blocked_countries: vec![],
            ..settings()
        };
        try_checkout(&db, &stripe, &open, "u2", NOW + 2 * DAY)
            .await
            .unwrap();

        // 30 days on, on the full list: both let in
        for user in ["u1", "u2"] {
            try_checkout(&db, &stripe, &s, user, NOW + REGION_REFUSAL_MS)
                .await
                .unwrap();
        }
        drop_db(&db).await;
    }
}
