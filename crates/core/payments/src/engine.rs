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
//!   (session id, order id, amount, currency, livemode)
//! - a resumed fulfil never refunds or re-numbers an order it already
//!   applied: the "already applied?" check runs before any precondition
//! - our own refunds use the idempotency key `void-{order_id}`, and a
//!   payment already refunded or lost in a dispute is never refunded again
//! - a reversal only touches a membership when the order is Fulfilled and
//!   listed in that membership, so the refund of a voided order is a no-op

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
use crate::settings::PaymentsSettings;
use crate::stripe::{CheckoutSession, CheckoutSessionParams, StripeApi, StripeError};

/// How long a worker holds an order; longer than the worst-case chain of
/// Stripe calls (each has a 10 s timeout)
pub const LEASE_MS: i64 = 120_000;

/// Lifetime of a Stripe Checkout Session, from the order's creation
pub const SESSION_TTL_SECS: i64 = 35 * 60;

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
    /// The session is ours but not paid
    NotPaid,
    /// The session does not match the order; nothing was changed
    Ignored,
}

/// A reversal reported by the provider
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
    /// The order is not fulfilled yet; fulfilment applies the reversal last
    RecordedPending,
    /// Nothing to do (voided, expired or already reversed, or not applied
    /// to any membership)
    NoOp,
    /// Another worker holds the order, or the order is paid but not
    /// fulfilled yet; the caller retries later
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
/// already refunded counts as done (the money is back either way).
async fn refund_for_void(
    stripe: &dyn StripeApi,
    payment_intent: &str,
    order_id: &str,
) -> Result<()> {
    match stripe
        .create_refund(payment_intent, &void_key(order_id))
        .await
    {
        Ok(_) => Ok(()),
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

fn pending_kind(pending: &ReversalPending) -> ReverseKind {
    match pending {
        ReversalPending::Refund => ReverseKind::Refund,
        ReversalPending::DisputeLost => ReverseKind::DisputeLost,
    }
}

/// Why a completed session cannot be applied to this order, if it cannot.
/// The session is what Stripe reports (a signed event or an API read).
fn session_mismatch(
    order: &PaymentOrder,
    session: &CheckoutSession,
    s: &PaymentsSettings,
) -> Option<String> {
    match &order.checkout_session_id {
        Some(id) if *id != session.id => {
            return Some(format!(
                "session {} is not the order's session {id}",
                session.id
            ))
        }
        Some(_) => {}
        // The session id was never stored (a crash between Stripe's answer
        // and the Pending write): bind on the order id we put in metadata
        None if session.metadata_order_id.as_deref() != Some(order.id.as_str()) => {
            return Some(format!(
                "order has no stored session and session {} names another order",
                session.id
            ))
        }
        None => {}
    }

    if let Some(named) = &session.metadata_order_id {
        if *named != order.id {
            return Some(format!("session metadata names order {named}"));
        }
    }

    if session.livemode != s.expect_livemode {
        return Some(format!(
            "session livemode {} but expect_livemode {}",
            session.livemode, s.expect_livemode
        ));
    }

    if session.amount_total != Some(order.amount_cents) {
        return Some(format!(
            "session amount {:?} but order amount {}",
            session.amount_total, order.amount_cents
        ));
    }

    if order.currency != "usd" || session.currency.as_deref() != Some(order.currency.as_str()) {
        return Some(format!(
            "session currency {:?} but order currency {}",
            session.currency, order.currency
        ));
    }

    if let (Some(stored), Some(reported)) = (&order.payment_intent_id, &session.payment_intent) {
        if stored != reported {
            return Some(format!(
                "session payment intent {reported} but the order is paid by {stored}"
            ));
        }
    }

    if let (Some(user_id), Some(reference)) = (&order.user_id, &session.client_reference_id) {
        if user_id != reference {
            return Some("session client_reference_id names another user".to_string());
        }
    }

    None
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
/// then fulfil_order. Also finishes a Fulfilled order's recorded reversal.
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
    fulfil_order(db, stripe, s, order_id, &session, now_ms).await
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

    if let Some(why) = session_mismatch(&leased.order, session, s) {
        log::warn!(
            "payments: ignoring session {} for order {}: {why}",
            session.id,
            leased.order.id
        );
        return Ok(FulfilOutcome::Ignored);
    }

    if session.payment_status.as_deref() != Some("paid") {
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
        write(db, leased, move |o| {
            o.state = OrderState::Paid;
            o.payment_intent_id = Some(payment_intent);
            o.paid_at = Some(now_ms);
            if o.checkout_session_id.is_none() {
                o.checkout_session_id = Some(session_id);
            }
        })
        .await?;
    }

    // The buyer deleted their account before fulfilment
    let Some(user_id) = leased.order.user_id.clone() else {
        return void_paid(db, stripe, leased, VoidReason::AccountDeleted, now_ms).await;
    };

    // 2. Already applied? (a resume after a crash must neither refund nor
    //    re-number, so this runs before the preconditions)
    let membership = db.fetch_cipher_membership(&user_id).await?;
    let applied = membership
        .as_ref()
        .is_some_and(|m| m.orders.contains(&leased.order.id));

    if !applied {
        // 3. Preconditions
        if let Some(reason) = precondition_failure(s, &leased.order, membership.as_ref()) {
            return void_paid(db, stripe, leased, reason, now_ms).await;
        }

        // 4. + 5. Number and membership
        if let Applied::Void(reason) =
            apply_membership(db, s, &leased.order, &user_id, now_ms).await?
        {
            return void_paid(db, stripe, leased, reason, now_ms).await;
        }
    }

    // 6. Public badge
    sync_user_badge(db, &user_id).await?;

    // 7. Fulfilled, then any reversal that arrived first
    write(db, leased, move |o| {
        o.state = OrderState::Fulfilled;
        o.fulfilled_at = Some(now_ms);
    })
    .await?;

    if let Some(pending) = leased.order.reversal_pending.clone() {
        reverse_locked(db, leased, pending_kind(&pending), now_ms).await?;
    }

    Ok(FulfilOutcome::Fulfilled)
}

/// A Fulfilled order seen again: re-assert the badge and apply a reversal
/// recorded before a crash
async fn finish_fulfilled(db: &Database, leased: &mut Leased, now_ms: i64) -> Result<()> {
    if let Some(user_id) = leased.order.user_id.clone() {
        sync_user_badge(db, &user_id).await?;
    }

    if let Some(pending) = leased.order.reversal_pending.clone() {
        reverse_locked(db, leased, pending_kind(&pending), now_ms).await?;
    }

    Ok(())
}

/// A completed session for a Voided order. An order voided before it was
/// paid (account deletion while the session was open) is refunded now;
/// one voided after payment was refunded then.
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

    if let Some(why) = session_mismatch(&leased.order, session, s) {
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
                None => match db.claim_cipher_number(&order.id, s.cap).await? {
                    Some(number) => number,
                    None => {
                        // Sold out only if the table was seeded to the cap;
                        // an empty or short table is a deployment error
                        let seeded = db.count_cipher_numbers().await?;
                        if seeded < s.cap {
                            log::error!(
                                "payments: cipher_numbers holds {seeded} rows, fewer than cipher_cap {}; \
                                 not selling order {} as sold out",
                                s.cap,
                                order.id
                            );
                            return Err(create_error!(InternalError));
                        }
                        return Ok(Applied::Void(VoidReason::SoldOut));
                    }
                },
            };

            let fresh = CipherMembership {
                user_id: user_id.to_string(),
                number,
                tier: *tier,
                prot_grant: catalog::tier_prot(*tier),
                orders: vec![order.id.clone()],
                disputed_orders: vec![],
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

                let mut next = m.clone();
                next.tier = *to;
                next.prot_grant = catalog::tier_prot(*to);
                next.orders.push(order.id.clone());
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

/// Void a Paid order: refund it (unless the payment is already refunded or
/// lost in a dispute), then record Voided with `reason`
async fn void_paid(
    db: &Database,
    stripe: &dyn StripeApi,
    leased: &mut Leased,
    reason: VoidReason,
    now_ms: i64,
) -> Result<FulfilOutcome> {
    if leased.order.reversal_pending.is_none() {
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

// ---------------------------------------------------------------------------
// Reverse
// ---------------------------------------------------------------------------

/// Apply a refund or dispute event to an order. Acts on a membership only
/// when the order is Fulfilled and listed in that membership.
pub async fn reverse_order(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    order_id: &str,
    kind: ReverseKind,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    // Reversals never call Stripe or read the sale settings
    let _ = (stripe, s);

    let Some(mut leased) = acquire(db, order_id, now_ms).await? else {
        return Ok(ReverseOutcome::Busy);
    };
    let outcome = reverse_locked(db, &mut leased, kind, now_ms).await;
    release(db, &leased).await;
    outcome
}

/// [`reverse_order`] on an order whose lease the caller already holds
/// (fulfil applies a recorded reversal this way; leases are not re-entrant)
async fn reverse_locked(
    db: &Database,
    leased: &mut Leased,
    kind: ReverseKind,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    match leased.order.state {
        // Includes the charge.refunded of our own void refund
        OrderState::Voided | OrderState::Expired | OrderState::Refunded => Ok(ReverseOutcome::NoOp),
        OrderState::Creating
        | OrderState::Pending
        | OrderState::SessionFailed
        | OrderState::Paid => match kind {
            ReverseKind::Refund | ReverseKind::DisputeLost => {
                if leased.order.reversal_pending.is_none() {
                    let pending = match kind {
                        ReverseKind::Refund => ReversalPending::Refund,
                        _ => ReversalPending::DisputeLost,
                    };
                    write(db, leased, move |o| o.reversal_pending = Some(pending)).await?;
                }
                Ok(ReverseOutcome::RecordedPending)
            }
            // A dispute on a paid order that is not fulfilled yet cannot be
            // recorded; retry once fulfilment has run, so the badge is never
            // shown while the dispute is open
            ReverseKind::DisputeOpened | ReverseKind::DisputeWon => {
                if leased.order.state == OrderState::Paid {
                    Ok(ReverseOutcome::Busy)
                } else {
                    Ok(ReverseOutcome::NoOp)
                }
            }
        },
        OrderState::Fulfilled => reverse_fulfilled(db, leased, kind, now_ms).await,
    }
}

async fn reverse_fulfilled(
    db: &Database,
    leased: &mut Leased,
    kind: ReverseKind,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    // Unlinked by an account deletion: the membership is gone with it
    let Some(user_id) = leased.order.user_id.clone() else {
        return no_membership_to_reverse(db, leased).await;
    };
    let order_id = leased.order.id.clone();

    let mut settled = false;
    for _ in 0..MEMBERSHIP_RETRIES {
        let Some(m) = db.fetch_cipher_membership(&user_id).await? else {
            return no_membership_to_reverse(db, leased).await;
        };
        if !m.orders.contains(&order_id) {
            log::warn!(
                "payments: {kind:?} on order {order_id}, which is not part of the membership; ignored"
            );
            return no_membership_to_reverse(db, leased).await;
        }

        let mut next = m.clone();
        match kind {
            ReverseKind::Refund | ReverseKind::DisputeLost => {
                if next.is_active() {
                    next.revoked_at = Some(now_ms);
                    next.revoke_reason = Some(match kind {
                        ReverseKind::Refund => CipherRevokeReason::Refund,
                        _ => CipherRevokeReason::DisputeLost,
                    });
                }
                if kind == ReverseKind::DisputeLost {
                    next.disputed_orders.retain(|id| *id != order_id);
                }
            }
            ReverseKind::DisputeOpened => {
                if !next.disputed_orders.contains(&order_id) {
                    next.disputed_orders.push(order_id.clone());
                }
            }
            ReverseKind::DisputeWon => next.disputed_orders.retain(|id| *id != order_id),
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
/// Per-order failures are logged, not returned: every one heals itself once
/// the orders are unlinked (a Paid order left behind is voided and refunded
/// by the reconcile resume, because fulfil voids an order with no buyer; a
/// session paid after deletion is refunded by fulfil; a Creating order
/// expires). An order whose lease is held is left to its holder, whose next
/// write is fenced off by the unlink. Fulfilled orders are not refunded.
pub async fn on_account_deleted(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    user_id: &str,
    now_ms: i64,
) -> Result<()> {
    let _ = s;

    let open = db
        .fetch_payment_orders_by_user(
            user_id,
            &[
                OrderState::Creating,
                OrderState::Pending,
                OrderState::SessionFailed,
                OrderState::Paid,
            ],
        )
        .await?;

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
            void_paid(db, stripe, leased, VoidReason::AccountDeleted, now_ms).await?;
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
    use crate::stripe::MockStripe;

    const NOW: i64 = 1_760_000_000_000;
    /// After a dead worker's lease has run out
    const LATER: i64 = NOW + LEASE_MS + 1;
    const MINUTE: i64 = 60_000;

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
        // held (or, if it ran second, the order fulfilled)
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
            reverse_order(&db, &stripe, &s, &pending.id, ReverseKind::Refund, NOW + 1)
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
            reverse_order(&db, &stripe, &s, &stale.id, ReverseKind::Refund, later + 1)
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

    #[tokio::test]
    async fn a_refund_before_completion_is_recorded_and_fulfil_ends_revoked() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        let pending = checkout(&db, &stripe, &s, "u1", CipherTier::T149, NOW).await;
        let session = pay(&stripe, &pending, "pi_1");

        assert_eq!(
            reverse_order(&db, &stripe, &s, &pending.id, ReverseKind::Refund, NOW)
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
            FulfilOutcome::Fulfilled
        );
        let reversed = order(&db, &pending.id).await;
        assert_eq!(reversed.state, OrderState::Refunded);
        assert_eq!(reversed.reversal_pending, None);
        assert!(reversed.lease_until.is_none());

        let m = membership(&db, "u1").await;
        assert!(!m.is_active());
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::Refund));
        assert_eq!(badge(&db, "u1").await, None);
        assert_eq!(
            cipher_me(&db, "u1", NOW + 2).await.unwrap().membership,
            None
        );
        // The owner refunded; we never refund on top
        assert_eq!(stripe.call_count("create_refund"), 0);
        // The number is retired, not freed
        assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_void_after_a_recorded_refund_does_not_refund_again() {
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

        // b's payment was refunded at Stripe before its completion was handled
        assert_eq!(
            reverse_order(&db, &stripe, &s, &b.id, ReverseKind::Refund, NOW)
                .await
                .unwrap(),
            ReverseOutcome::RecordedPending
        );
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &b.id, &session_b, NOW + 1)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::SoldOut)
        );
        assert_eq!(stripe.call_count("create_refund"), 0);
        assert_eq!(order(&db, &b.id).await.reversal_pending, None);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn disputes_hide_the_badge_and_a_lost_one_revokes() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let bought = buy(&db, &stripe, &s, "u1", CipherTier::T299, "pi_1", NOW).await;
        let reverse = |kind, at| reverse_order(&db, &stripe, &s, &bought.id, kind, at);

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
            reverse_order(
                &db,
                &stripe,
                &s,
                &first.id,
                ReverseKind::DisputeOpened,
                NOW + 1
            )
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
    async fn a_dispute_on_a_paid_unfulfilled_order_waits_for_fulfilment() {
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

        assert_eq!(
            reverse_order(
                &db,
                &stripe,
                &s,
                &pending.id,
                ReverseKind::DisputeOpened,
                LATER
            )
            .await
            .unwrap(),
            ReverseOutcome::Busy
        );
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, LATER + 1)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        assert_eq!(
            reverse_order(
                &db,
                &stripe,
                &s,
                &pending.id,
                ReverseKind::DisputeOpened,
                LATER + 2
            )
            .await
            .unwrap(),
            ReverseOutcome::Applied
        );
        assert_eq!(badge(&db, "u1").await, None);
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
        assert_eq!(
            reverse_order(&db, &stripe, &s, &first.id, ReverseKind::Refund, NOW + 1)
                .await
                .unwrap(),
            ReverseOutcome::Applied
        );
        assert_eq!(badge(&db, "u1").await, None);

        // The revoked row does not block a new purchase, and is not an upgrade
        let again = buy(&db, &stripe, &s, "u1", CipherTier::T149, "pi_3", NOW + 2).await;
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
        assert_eq!(m.granted_at, NOW + 2);
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

        let cases = [
            CheckoutSession {
                amount_total: Some(100),
                ..paid.clone()
            },
            CheckoutSession {
                currency: Some("eur".to_string()),
                ..paid.clone()
            },
            CheckoutSession {
                livemode: true,
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
        reverse_order(&db, &stripe, &s, &first.id, ReverseKind::Refund, NOW + 1)
            .await
            .unwrap();
        buy(&db, &stripe, &s, "u2", CipherTier::T99, "pi_2", NOW + 2).await;

        assert_eq!(
            cipher_stats(&db, &s, NOW + 3).await.unwrap(),
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
}
