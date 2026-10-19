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
use crate::dispatch::dispute_kind;
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
    /// When the refund was made (epoch ms): the refund event's signed
    /// `created`, never later than the time it is processed
    pub refunded_at_ms: i64,
    /// Whether the charge is now refunded in full; only a full refund is
    /// undone (a partial one revokes and retires)
    pub full: bool,
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

/// Refund `payment_intent` for an order we are voiding. A payment that is
/// already refunded counts as done (the money is back either way). A refund
/// Stripe reports `failed` or `canceled` returned nothing: that is an error,
/// so the order is not voided and the caller retries.
///
/// Operator note: a refund Stripe reports `pending` (or `requires_action`)
/// is accepted and the order is voided, but the money has not moved yet,
/// and nothing here hears about it again: a later failure arrives as
/// `refund.failed` / `charge.refund.updated`, which this crate does not
/// handle. Every such refund is logged at error level ("refund ... is
/// pending"); an operator must check those refunds in the Stripe dashboard
/// and refund by hand any that end `failed`.
async fn refund_for_void(
    stripe: &dyn StripeApi,
    payment_intent: &str,
    order_id: &str,
) -> Result<()> {
    match stripe
        .create_refund(payment_intent, &void_key(order_id))
        .await
    {
        Ok(refund) => match refund.status.as_deref() {
            Some(status @ ("failed" | "canceled")) => {
                log::error!(
                    "payments: refund {} of order {order_id} is {status}; the order stays unvoided",
                    refund.id
                );
                Err(create_error!(PaymentProviderError))
            }
            Some("succeeded") => Ok(()),
            status => {
                // Not settled yet, and a later failure is not handled here
                // (see the operator note above)
                log::error!(
                    "payments: refund {} of order {order_id} is {}; the order is voided, but the \
                     refund must be watched in the Stripe dashboard until it succeeds",
                    refund.id,
                    status.unwrap_or("of unknown status")
                );
                Ok(())
            }
        },
        Err(StripeError::Api {
            code: Some(code), ..
        }) if code == CHARGE_ALREADY_REFUNDED => {
            log::info!("payments: order {order_id} was already refunded at Stripe");
            Ok(())
        }
        Err(err) => {
            log::error!("payments: refund of order {order_id} failed: {err}");
            Err(create_error!(PaymentProviderError))
        }
    }
}

/// Map a Stripe failure to the API error, logging it (StripeError text is
/// scrubbed of secrets by the client)
fn provider_error(context: &str, err: StripeError) -> revolt_result::Error {
    log::error!("payments: {context}: {err}");
    create_error!(PaymentProviderError)
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

    let membership = db
        .fetch_cipher_membership(user_id)
        .await?
        .filter(CipherMembership::is_active);
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
        reversal_pending: None,
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
            finish_fulfilled(db, leased, now_ms).await?;
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
        // A paid card session always has one; without it nothing can be
        // refunded, so leave the event to be retried and looked at
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
        reverse_locked(db, leased, pending_kind(&pending), None, None, now_ms).await?;
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
async fn finish_fulfilled(db: &Database, leased: &mut Leased, now_ms: i64) -> Result<()> {
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
        reverse_locked(db, leased, pending_kind(&pending), None, None, now_ms).await?;
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

    refund_for_void(stripe, &payment_intent, &leased.order.id).await?;
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
        refund_for_void(stripe, &payment_intent, &leased.order.id).await?;
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
/// refund (None: nothing known, so it revokes and retires as before).
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
    // Reversals never call Stripe or read the sale settings
    let _ = (stripe, s);

    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        return Ok(ReverseOutcome::Busy);
    };
    let outcome = reverse_locked(db, &mut leased, kind, None, refund, now_ms).await;
    release(db, &leased).await;
    outcome
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
        Ok(kind) => reverse_locked(db, &mut leased, kind, Some(dispute_id), None, now_ms).await,
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
        reverse_locked(db, leased, kind, Some(&dispute_id), None, now_ms).await?;
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
        // Includes the charge.refunded of our own void refund
        OrderState::Voided | OrderState::Refunded => Ok(ReverseOutcome::NoOp),
        // Not fulfilled (yet). Expired is included: a session paid after the
        // order expired is still fulfilled, and must honour what came first.
        OrderState::Creating
        | OrderState::Pending
        | OrderState::SessionFailed
        | OrderState::Expired
        | OrderState::Paid => record_before_fulfilment(db, leased, kind, dispute).await,
        OrderState::Fulfilled => reverse_fulfilled(db, leased, kind, dispute, refund, now_ms).await,
    }
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
    leased: &mut Leased,
    kind: ReverseKind,
    dispute: Option<&str>,
    refund: Option<RefundFacts>,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    // A release a refund decided earlier and did not finish (a crash, a
    // failed write) is finished first, whatever this reversal is: a lost
    // dispute or anything else arriving now must not leave the number held
    // by a revoked row
    // Boxed (here and below): the release adds several awaits to every
    // reversal, and inline they deepen the poll stack enough to overflow
    // a 2 MiB thread in debug builds
    if let Some(outcome) = Box::pin(finish_number_release_locked(db, leased, now_ms)).await? {
        return Ok(outcome);
    }

    // The order records the dispute first: if the membership write below
    // fails, the event is retried, and a redelivered completion re-adds the
    // listing from the order (it never clears one)
    let open = disputes_after(&leased.order, kind, dispute);
    if open != leased.order.open_disputes {
        write(db, leased, move |o| o.open_disputes = open).await?;
    }

    // Unlinked by an account deletion: the membership is gone with it
    let Some(user_id) = leased.order.user_id.clone() else {
        return no_membership_to_reverse(db, leased).await;
    };
    let order_id = leased.order.id.clone();

    // A full refund inside the window is undone instead (rolled back, or
    // the number released); None falls through to revoke + retire
    if kind == ReverseKind::Refund {
        if let Some(outcome) =
            Box::pin(refund_within_window(db, leased, &user_id, refund, now_ms)).await?
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
///   included, and the number goes back to the pool).
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
/// pending)
async fn mark_refunded(db: &Database, leased: &mut Leased, now_ms: i64) -> Result<()> {
    write(db, leased, move |o| {
        o.state = OrderState::Refunded;
        o.reversed_at = Some(now_ms);
        o.reversal_pending = None;
    })
    .await
}

/// A full Refund inside the window ([`window_refund_plan`]), applied in
/// full: Some(outcome), or None when the rule says revoke + retire (the
/// caller does that). Every membership write is a compare-and-swap
/// re-checked against the plan on each read.
async fn refund_within_window(
    db: &Database,
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
                return Box::pin(finish_number_release_locked(db, leased, now_ms)).await;
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
/// 2. delete that membership, compare-and-swap on the version read, so a
///    row the buyer replaced meanwhile (a new purchase) is never deleted;
/// 3. release the number (`release_cipher_number` unsets `order_id` and the
///    mark together, and touches only this order's row);
/// 4. record the order Refunded (if it is still Fulfilled).
///
/// The membership goes before the number, so a number is never free while
/// a membership row still holds it (the unique `number` index).
async fn finish_number_release_locked(
    db: &Database,
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

    // Unlinked by an account deletion: the membership went with it
    if let Some(user_id) = leased.order.user_id.clone() {
        let mut settled = false;
        for _ in 0..MEMBERSHIP_RETRIES {
            let Some(m) = db.fetch_cipher_membership(&user_id).await? else {
                settled = true;
                break;
            };
            if !m.orders.contains(&order_id) {
                // Replaced by a new purchase: nothing of this order's left
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

            // 2. Delete the row that holds the number
            if db
                .delete_cipher_membership_if_version(&user_id, m.version)
                .await?
            {
                warn_unrefunded_upgrades(db, &m, &order_id).await;
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

    // 3. The number back to the pool
    let released = db.release_cipher_number(&order_id).await?;
    log::info!(
        "payments: order {order_id} refunded within the window; number {} is back in the pool \
         (released now: {released})",
        row.number
    );

    // 4. The order
    if leased.order.state == OrderState::Fulfilled {
        mark_refunded(db, leased, now_ms).await?;
    }
    Ok(Some(ReverseOutcome::Applied))
}

/// A membership deleted by a release can still list upgrades nobody
/// refunded: the buyer paid for them and lost them with the number. Logged
/// at warn level with their payments, so the owner refunds them.
async fn warn_unrefunded_upgrades(db: &Database, m: &CipherMembership, released_by: &str) {
    let mut unrefunded = Vec::new();
    for id in m.orders.iter().filter(|id| *id != released_by) {
        match db.fetch_payment_order(id).await {
            Ok(Some(order)) if order.state != OrderState::Refunded => unrefunded.push(format!(
                "{} (payment {:?})",
                order.id, order.payment_intent_id
            )),
            Ok(_) => {}
            Err(err) => unrefunded.push(format!("{id} (could not be read: {err:?})")),
        }
    }
    if !unrefunded.is_empty() {
        log::warn!(
            "payments: the membership of {} was deleted by the refund of order {released_by}, \
             but these upgrades of it are not refunded; refund them: {}",
            m.user_id,
            unrefunded.join(", ")
        );
    }
}

/// The reconcile sweep's step for a number whose release was decided but
/// not finished ([`finish_number_release_locked`]), under the order's
/// lease. `Applied` when finished now, `NoOp` when there was nothing to
/// finish, `Busy` when another worker holds the order.
pub async fn finish_number_release(
    db: &Database,
    order_id: &str,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        return Ok(ReverseOutcome::Busy);
    };
    let outcome = finish_number_release_locked(db, &mut leased, now_ms).await;
    release(db, &leased).await;
    Ok(outcome?.unwrap_or(ReverseOutcome::NoOp))
}

// ---------------------------------------------------------------------------
// Expiry, views, badge, account deletion
// ---------------------------------------------------------------------------

/// Creating | Pending | SessionFailed → Expired (under the lease). Any other
/// state, or a lease held by a worker that is moving the order on, is left
/// as it is.
pub async fn expire_order(db: &Database, order_id: &str, now_ms: i64) -> Result<()> {
    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        log::debug!("payments: not expiring order {order_id}: its lease is held");
        return Ok(());
    };

    let result = match leased.order.state {
        OrderState::Creating | OrderState::Pending | OrderState::SessionFailed => {
            write(db, &mut leased, |o| o.state = OrderState::Expired).await
        }
        _ => Ok(()),
    };
    release(db, &leased).await;
    result
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
    use crate::dispatch::reconcile;
    use crate::stripe::{Dispute, MockStripe, PaymentIntent};

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
        let outcome = reverse_locked(db, &mut leased, kind, Some(dispute_id), None, at).await;
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
            reversal_pending: None,
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
    async fn a_lost_dispute_after_a_stopped_release_finishes_the_release() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        let bought = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        release_decided(&db, "u1", &bought.id, NOW + DAY, true).await;

        // The refund event never comes back; a lost dispute does. It must
        // not leave #1 held by a revoked row (or claimed for good)
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
        assert_eq!(maybe_membership(&db, "u1").await, None);
        assert_eq!(
            db.fetch_cipher_number_by_order(&bought.id).await.unwrap(),
            None
        );
        assert_eq!(order(&db, &bought.id).await.state, OrderState::Refunded);

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

    #[tokio::test]
    async fn a_repurchase_after_a_stopped_release_keeps_the_new_membership() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let first = buy(&db, &stripe, &s, "u1", CipherTier::T99, "pi_1", NOW).await;
        release_decided(&db, "u1", &first.id, NOW + DAY, true).await;

        // The buyer buys again before anything finishes the release: #1 is
        // still claimed, so the new purchase gets #2 and replaces the
        // revoked row
        let again = buy(
            &db,
            &stripe,
            &s,
            "u1",
            CipherTier::T149,
            "pi_2",
            NOW + DAY + 1,
        )
        .await;
        let m = membership(&db, "u1").await;
        assert_eq!((m.number, m.orders.clone()), (2, vec![again.id.clone()]));

        // The reconcile sweep finishes the old release without touching
        // the new membership
        reconcile(&db, &stripe, &s, NOW + DAY + 2 * MINUTE)
            .await
            .unwrap();
        assert_eq!(
            db.fetch_cipher_number_by_order(&first.id).await.unwrap(),
            None
        );
        assert_eq!(order(&db, &first.id).await.state, OrderState::Refunded);
        let m = membership(&db, "u1").await;
        assert!(m.is_active());
        assert_eq!((m.number, m.tier), (2, CipherTier::T149));
        assert_eq!(badge(&db, "u1").await, badge_of(2, CipherTier::T149));
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());

        // A second sweep finds nothing to do
        reconcile(&db, &stripe, &s, NOW + DAY + 4 * MINUTE)
            .await
            .unwrap();
        assert_eq!(membership(&db, "u1").await.number, 2);
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

        // The upgrade's own refund then only records it
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
}
