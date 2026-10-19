//! Webhook event handling and the crond reconcile sweep
//!
//! [`handle_event`] runs once per delivery, after the route has verified the
//! signature. It records the event in `payment_events` (the dedupe key is the
//! Stripe event id), works out which order it is about, and hands the order
//! to the engine. Dispatch never writes an order itself: every order change
//! goes through an engine function, which owns the order lease.
//!
//! Redelivery is the retry mechanism. An event that fails is marked Failed and
//! the route answers 500, so Stripe delivers it again; [`reconcile`] also
//! re-drives Failed events (and Received ones a crash stranded) by fetching
//! them from Stripe by id, so no event payload is ever stored.
//!
//! Decision: `checkout.session.completed` RE-FETCHES the session from Stripe
//! (`get_checkout_session`) and fulfils from that, not from the event payload.
//! A redelivered or re-driven event can be days old, and fulfilment checks the
//! amount, currency, livemode and payment status; those are read from Stripe's
//! current view, never from a copy that may be stale. The cost is one extra
//! API call per completed checkout, and only for sessions that are ours.
//!
//! Decision: every `charge.dispute.*` event RE-FETCHES the dispute
//! (`get_dispute`) and applies its CURRENT status, ignoring the type and the
//! status in the payload. Stripe does not order deliveries: a `closed (lost)`
//! can arrive before its `created`, and acting on the payload would leave the
//! later `created` re-opening a dispute that is already over. The engine
//! ([`engine::reverse_dispute`]) reads the dispute inside the order's lease,
//! so two deliveries handled back to back cannot apply an older status after
//! a newer one; applying where the dispute is now, through idempotent
//! reversals, makes every delivery order converge. A failed lookup is a
//! retry, never a guess.
//!
//! Decision: `charge.refunded` is judged from the event itself
//! ([`refund_facts`]): its `created` is when the refund was made (the
//! 14-day refund window is measured to it, not to when a late or re-driven
//! delivery is processed), and its Charge says whether the refund is full.
//! The event is either signature-verified (webhook) or fetched from Stripe
//! by id (re-drive), and each refund has its own event, so the snapshot is
//! the right one to read.
use log::{info, warn};
use revolt_database::{Database, OrderState, PaymentEvent, PaymentEventState, ReversalPending};
use revolt_result::{Error, Result};
use serde_json::Value;

use crate::engine::{self, FulfilOutcome, RefundFacts, ReverseKind, ReverseOutcome};
use crate::settings::PaymentsSettings;
use crate::stripe::event::{
    obj_expandable_id, obj_str, StripeEvent, CHARGE_DISPUTE_PREFIX, CHARGE_REFUNDED,
    CHECKOUT_SESSION_COMPLETED, CHECKOUT_SESSION_EXPIRED,
};
use crate::stripe::{StripeApi, StripeError};

/// Creating / SessionFailed orders older than this are expired (no buyer can
/// still be paying for them: the checkout URL was never handed out, or the
/// session could not be created)
const EXPIRE_UNPAID_AFTER_MS: i64 = 10 * 60 * 1000;

/// Pending orders older than this are checked against Stripe. Sessions live
/// for `engine::SESSION_TTL_SECS` (35 min), so by now each one is complete or
/// expired.
const CHECK_PENDING_AFTER_MS: i64 = 40 * 60 * 1000;

/// Received events older than this were stranded by a crash between the
/// insert and the final state write
const STRANDED_EVENT_AFTER_MS: i64 = 10 * 60 * 1000;

/// A Failed event is re-driven until it has been attempted this many times
const MAX_EVENT_ATTEMPTS: u32 = 10;

/// Upper bound on the rows each part of one sweep looks at. Every query
/// filters on the states its part acts on, so only rows that keep failing
/// can fill a batch, and it takes this many of them to starve the rest.
const SWEEP_BATCH: i64 = 200;

/// Longest `last_error` stored on an event
const ERROR_TEXT_MAX: usize = 160;

/// What the webhook route should answer for an event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventOutcome {
    /// Handled now
    Processed,
    /// Not ours or not relevant (livemode mismatch, unknown type, an order
    /// we do not have)
    Ignored,
    /// Already handled by an earlier delivery
    Duplicate,
    /// Handling failed or the order is busy; the route answers 500 so Stripe
    /// delivers it again
    Retry,
}

/// What an event asks for, decided from its type alone (before any lookup)
enum Action {
    Fulfil,
    Expire,
    Reverse(ReverseKind),
    /// Any `charge.dispute.*`: the reversal comes from the dispute's current
    /// status, looked up at Stripe
    Dispute,
    Ignore,
}

fn action_for(event: &StripeEvent) -> Action {
    match event.event_type.as_str() {
        CHECKOUT_SESSION_COMPLETED => Action::Fulfil,
        CHECKOUT_SESSION_EXPIRED => Action::Expire,
        CHARGE_REFUNDED => Action::Reverse(ReverseKind::Refund),
        ty if ty.starts_with(CHARGE_DISPUTE_PREFIX) => Action::Dispute,
        _ => Action::Ignore,
    }
}

/// The reversal a dispute's CURRENT status calls for. `lost` revokes;
/// `won`, `warning_closed` (an inquiry that never became a chargeback) and
/// `prevented` clear the dispute; every other status, a missing one
/// included, counts as open, which hides the badge (fail closed).
/// Used by [`engine::reverse_dispute`] on the dispute it reads.
pub(crate) fn dispute_kind(status: Option<&str>) -> ReverseKind {
    match status {
        Some("lost") => ReverseKind::DisputeLost,
        Some("won" | "warning_closed" | "prevented") => ReverseKind::DisputeWon,
        _ => ReverseKind::DisputeOpened,
    }
}

/// How one processing attempt ended
enum Step {
    Processed,
    Ignored,
    /// Short reason, safe to store: no secrets, no buyer details
    Retry(String),
}

/// Handle one Stripe event. The route has already verified its signature.
///
/// - livemode differs from `expect_livemode` → recorded as Ignored, nothing
///   else happens
/// - seen before and settled (Processed / Ignored) → Duplicate; seen before
///   but Received / Failed → processed again
/// - processed → Processed or Ignored (an order we do not have, an event type
///   we do not act on)
/// - a held lease, a busy order or any error → the event is marked Failed and
///   the outcome is Retry
///
/// `Err` only when recording the event itself fails; the route answers 500
/// then too.
pub async fn handle_event(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    event: &StripeEvent,
    now_ms: i64,
) -> Result<EventOutcome> {
    if event.livemode != s.expect_livemode {
        info!(
            "payments: ignoring event {} ({}): livemode {} but expecting {}",
            event.id, event.event_type, event.livemode, s.expect_livemode
        );
        record_livemode_mismatch(db, event, now_ms).await?;
        return Ok(EventOutcome::Ignored);
    }

    let row = PaymentEvent {
        id: event.id.clone(),
        event_type: event.event_type.clone(),
        livemode: event.livemode,
        received_at: now_ms,
        state: PaymentEventState::Received,
        attempts: 0,
        last_error: None,
    };
    if !db.insert_payment_event_if_absent(&row).await? && is_settled(db, &event.id).await? {
        return Ok(EventOutcome::Duplicate);
    }

    match process(db, stripe, s, event, now_ms).await {
        Step::Processed => {
            db.set_payment_event_state(&event.id, PaymentEventState::Processed, None)
                .await?;
            Ok(EventOutcome::Processed)
        }
        Step::Ignored => {
            db.set_payment_event_state(&event.id, PaymentEventState::Ignored, None)
                .await?;
            Ok(EventOutcome::Ignored)
        }
        Step::Retry(reason) => {
            // Another delivery of the same event may have settled it while
            // this one waited on the lease; never put a settled row back
            // into the re-drive queue
            if is_settled(db, &event.id).await? {
                return Ok(EventOutcome::Duplicate);
            }

            warn!(
                "payments: event {} ({}) will be retried: {reason}",
                event.id, event.event_type
            );
            db.set_payment_event_state(&event.id, PaymentEventState::Failed, Some(reason))
                .await?;
            Ok(EventOutcome::Retry)
        }
    }
}

/// Whether the stored event is Processed or Ignored
async fn is_settled(db: &Database, id: &str) -> Result<bool> {
    Ok(db.fetch_payment_event(id).await?.is_some_and(|row| {
        matches!(
            row.state,
            PaymentEventState::Processed | PaymentEventState::Ignored
        )
    }))
}

/// Record a livemode-mismatched event as Ignored. A row left Received or
/// Failed from before `expect_livemode` changed is settled too, or the
/// re-drive would fetch it every sweep without ever counting an attempt.
async fn record_livemode_mismatch(db: &Database, event: &StripeEvent, now_ms: i64) -> Result<()> {
    let row = PaymentEvent {
        id: event.id.clone(),
        event_type: event.event_type.clone(),
        livemode: event.livemode,
        received_at: now_ms,
        state: PaymentEventState::Ignored,
        // Handled once: ignoring it is the whole of the handling
        attempts: 1,
        last_error: None,
    };
    if !db.insert_payment_event_if_absent(&row).await? && !is_settled(db, &event.id).await? {
        db.set_payment_event_state(&event.id, PaymentEventState::Ignored, None)
            .await?;
    }
    Ok(())
}

/// One processing attempt. Never returns early with an error: every failure
/// becomes a [`Step::Retry`] carrying a short, storable reason.
async fn process(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    event: &StripeEvent,
    now_ms: i64,
) -> Step {
    match action_for(event) {
        Action::Ignore => Step::Ignored,
        Action::Fulfil => {
            let Some(session_id) = obj_str(&event.object, "id") else {
                return Step::Ignored;
            };
            let order_id = match db.fetch_payment_order_by_session(session_id).await {
                Ok(Some(order)) => order.id,
                Ok(None) => return Step::Ignored,
                Err(error) => return Step::Retry(engine_text("find order", &error)),
            };

            // The session as Stripe reports it now (see the module docs)
            let session = match stripe.get_checkout_session(session_id).await {
                Ok(session) => session,
                Err(error) => return Step::Retry(stripe_text("get_checkout_session", &error)),
            };
            if session.id != session_id {
                return Step::Retry("stripe returned a different checkout session".to_string());
            }

            match engine::fulfil_order(db, stripe, s, &order_id, &session, now_ms).await {
                Ok(outcome) => fulfil_step(outcome),
                Err(error) => Step::Retry(engine_text("fulfil", &error)),
            }
        }
        Action::Expire => {
            let Some(session_id) = obj_str(&event.object, "id") else {
                return Step::Ignored;
            };
            let order_id = match db.fetch_payment_order_by_session(session_id).await {
                Ok(Some(order)) => order.id,
                Ok(None) => return Step::Ignored,
                Err(error) => return Step::Retry(engine_text("find order", &error)),
            };

            match engine::expire_order(db, &order_id, now_ms).await {
                Ok(()) => Step::Processed,
                Err(error) => Step::Retry(engine_text("expire", &error)),
            }
        }
        Action::Reverse(kind) => {
            // A charge names its payment intent
            let Some(payment_intent) = obj_expandable_id(&event.object, "payment_intent") else {
                return Step::Ignored;
            };
            let order_id = match order_for_intent(db, stripe, s, payment_intent).await {
                Ok(Some(order_id)) => order_id,
                Ok(None) => return Step::Ignored,
                Err(reason) => return Step::Retry(reason),
            };

            let refund = (kind == ReverseKind::Refund).then(|| refund_facts(event, now_ms));
            match Box::pin(engine::reverse_order(
                db, stripe, s, &order_id, kind, refund, now_ms,
            ))
            .await
            {
                Ok(outcome) => reverse_step(outcome),
                Err(error) => Step::Retry(engine_text("reverse", &error)),
            }
        }
        Action::Dispute => {
            let Some(payment_intent) = obj_expandable_id(&event.object, "payment_intent") else {
                return Step::Ignored;
            };
            let order_id = match order_for_intent(db, stripe, s, payment_intent).await {
                Ok(Some(order_id)) => order_id,
                Ok(None) => return Step::Ignored,
                Err(reason) => return Step::Retry(reason),
            };

            // Where the dispute is now, not what this delivery says: the
            // engine reads it under the order's lease and checks it is on
            // the order's payment
            let Some(dispute_id) = obj_str(&event.object, "id") else {
                return Step::Retry("dispute event has no dispute id".to_string());
            };

            match engine::reverse_dispute(db, stripe, s, &order_id, dispute_id, now_ms).await {
                Ok(outcome) => reverse_step(outcome),
                Err(error) => Step::Retry(engine_text("dispute", &error)),
            }
        }
    }
}

/// What a `charge.refunded` event says about its refund: when it was made
/// (the signed event's `created`, never later than `now_ms`, so a late or
/// re-driven delivery is judged by when the owner refunded) and whether the
/// charge is now refunded in full
pub(crate) fn refund_facts(event: &StripeEvent, now_ms: i64) -> RefundFacts {
    RefundFacts {
        refunded_at_ms: event.created.saturating_mul(1000).min(now_ms),
        full: charge_fully_refunded(&event.object),
    }
}

/// Whether a Charge object is refunded in full: Stripe's `refunded` flag,
/// or `amount_refunded` reaching a positive `amount`. Anything missing or
/// malformed is "not full" (fails toward revoke + retire).
pub(crate) fn charge_fully_refunded(charge: &Value) -> bool {
    if charge.get("refunded").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    match (
        charge.get("amount").and_then(Value::as_i64),
        charge.get("amount_refunded").and_then(Value::as_i64),
    ) {
        (Some(amount), Some(refunded)) => amount > 0 && refunded >= amount,
        _ => false,
    }
}

fn fulfil_step(outcome: FulfilOutcome) -> Step {
    match outcome {
        FulfilOutcome::Fulfilled | FulfilOutcome::AlreadyFulfilled | FulfilOutcome::Voided(_) => {
            Step::Processed
        }
        // The order is not in a state fulfilment applies to: nothing changed
        FulfilOutcome::Ignored => Step::Ignored,
        // A completed card checkout is paid, so Stripe's view has not caught
        // up yet: retry rather than settle (the Pending sweep is the backstop)
        FulfilOutcome::NotPaid => Step::Retry("session not reported paid yet".to_string()),
        FulfilOutcome::LeaseHeld => Step::Retry("order lease held".to_string()),
        // Handled: the deferral is durable (the order stays Paid), and the
        // reconcile resume owns it from here, re-reading the disputes it
        // waits on every sweep. Retrying the event would only spend its
        // attempts while the dispute runs for weeks.
        FulfilOutcome::VoidDeferred(_) => Step::Processed,
    }
}

fn reverse_step(outcome: ReverseOutcome) -> Step {
    match outcome {
        ReverseOutcome::Applied | ReverseOutcome::RecordedPending | ReverseOutcome::NoOp => {
            Step::Processed
        }
        ReverseOutcome::Busy => Step::Retry("order busy".to_string()),
    }
}

/// The order a payment intent belongs to.
///
/// By the stored `payment_intent_id` first. An order only stores its intent
/// once fulfilment marks it Paid, so a refund or dispute that arrives earlier
/// falls back to the intent's `metadata.order_id` (set by us at checkout via
/// `payment_intent_data[metadata][order_id]`). That order is accepted only if
/// it has no intent yet or this one: metadata pointing at an order paid by a
/// different intent is not trusted.
///
/// Ok(None): not ours. Err: a short reason to retry with.
async fn order_for_intent(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    payment_intent: &str,
) -> std::result::Result<Option<String>, String> {
    match db.fetch_payment_order_by_intent(payment_intent).await {
        Ok(Some(order)) => return Ok(Some(order.id)),
        Ok(None) => {}
        Err(error) => return Err(engine_text("find order", &error)),
    }

    let intent = match stripe.get_payment_intent(payment_intent).await {
        Ok(intent) => intent,
        // Stripe has no such intent for this key: not ours
        Err(StripeError::Api { status: 404, .. }) => return Ok(None),
        Err(error) => return Err(stripe_text("get_payment_intent", &error)),
    };
    if intent.id != payment_intent {
        return Err("stripe returned a different payment intent".to_string());
    }
    if intent.livemode != s.expect_livemode {
        return Ok(None);
    }
    let Some(order_id) = intent.metadata_order_id else {
        return Ok(None);
    };

    let order = match db.fetch_payment_order(&order_id).await {
        Ok(Some(order)) => order,
        Ok(None) => return Ok(None),
        Err(error) => return Err(engine_text("find order", &error)),
    };
    match order.payment_intent_id.as_deref() {
        None => Ok(Some(order.id)),
        Some(stored) if stored == payment_intent => Ok(Some(order.id)),
        Some(_) => {
            warn!(
                "payments: payment intent {payment_intent} names order {} in its metadata, \
                 but that order was paid by another intent; ignoring",
                order.id
            );
            Ok(None)
        }
    }
}

/// Error text for a failed Stripe call. Only the call, the HTTP status and
/// Stripe's error code: Stripe's message and transport details are left out,
/// so nothing it echoes back can reach storage.
fn stripe_text(call: &str, error: &StripeError) -> String {
    match error {
        StripeError::Transport(_) => format!("stripe {call}: transport error"),
        StripeError::Api {
            status,
            code: Some(code),
            ..
        } => {
            let code: String = code
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(40)
                .collect();
            format!("stripe {call}: HTTP {status} ({code})")
        }
        StripeError::Api { status, .. } => format!("stripe {call}: HTTP {status}"),
        StripeError::Decode(_) => format!("stripe {call}: unexpected response"),
    }
}

/// Error text for a failed engine or database step: the error type only
/// (never the source location)
fn engine_text(step: &str, error: &Error) -> String {
    truncate(format!("{step}: {:?}", error.error_type))
}

fn truncate(mut text: String) -> String {
    if text.len() > ERROR_TEXT_MAX {
        let mut end = ERROR_TEXT_MAX;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// Counts reported by one sweep
#[derive(Default)]
struct Tally {
    expired: u32,
    resumed: u32,
    reversed: u32,
    redriven: u32,
    errors: u32,
    /// Paid upgrades deleted with a membership whose number a release put
    /// back in the pool; each one is logged at error level, to refund
    unrefunded_upgrades: u32,
}

impl Tally {
    fn summary(&self) -> String {
        let mut summary = format!(
            "expired={}, resumed={}, reversed={}, redriven={}, errors={}",
            self.expired, self.resumed, self.reversed, self.redriven, self.errors
        );
        // Only when there are any, so the usual line stays as it was
        if self.unrefunded_upgrades > 0 {
            summary.push_str(&format!(
                ", unrefunded_upgrades={}",
                self.unrefunded_upgrades
            ));
        }
        summary
    }

    fn error(&mut self, what: &str, id: &str, reason: &str) {
        warn!("payments reconcile: {what} {id}: {reason}");
        self.errors += 1;
    }

    /// Log how many failures one part of the sweep had since `errors_before`
    /// (its rows stay where they are and the next sweep tries them again)
    fn report(&self, part: &str, errors_before: u32) {
        let failed = self.errors.saturating_sub(errors_before);
        if failed > 0 {
            warn!("payments reconcile: {failed} failure(s) in {part} this sweep");
        }
    }
}

/// The crond sweep (plan "crond payments_reconcile"), run every 10 minutes:
///
/// 1. Creating / SessionFailed orders older than 10 min → Expired
/// 2. Pending orders older than 40 min, checked against Stripe: complete and
///    paid → fulfil; expired → Expired; open → left alone
/// 3. Paid orders whose lease is free (a fulfilment that crashed or gave up)
///    → resumed
/// 4. Fulfilled orders with a reversal still pending → reversed; then
///    Cipher numbers whose release a refund decided but did not finish →
///    finished (membership deleted, order Refunded, number released; paid
///    upgrades deleted with a membership are counted under
///    `unrefunded_upgrades`)
/// 5. Fulfilled orders that list open disputes: each dispute is re-read at
///    Stripe and its current status applied (counted under `reversed` when
///    it changed the order), so a lost close event cannot keep a badge
///    hidden for good
/// 6. Failed events (fewer than 10 attempts) and Received events older than
///    10 min → fetched from Stripe by id and handled again
///
/// Each part looks at a bounded batch. A failing item, or a failing query,
/// is counted under `errors` and never stops the rest of the sweep. Returns
/// a one-line summary for the crond log.
pub async fn reconcile(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    now_ms: i64,
) -> Result<String> {
    let mut tally = Tally::default();

    let before = tally.errors;
    expire_unpaid(db, now_ms, &mut tally).await;
    tally.report("unpaid orders", before);

    let before = tally.errors;
    check_pending(db, stripe, s, now_ms, &mut tally).await;
    tally.report("pending orders", before);

    let before = tally.errors;
    resume_paid(db, stripe, s, now_ms, &mut tally).await;
    tally.report("paid orders", before);

    let before = tally.errors;
    apply_pending_reversals(db, stripe, s, now_ms, &mut tally).await;
    tally.report("pending reversals", before);

    let before = tally.errors;
    finish_number_releases(db, now_ms, &mut tally).await;
    tally.report("number releases", before);

    let before = tally.errors;
    recheck_open_disputes(db, stripe, s, now_ms, &mut tally).await;
    tally.report("open disputes", before);

    let before = tally.errors;
    redrive_events(db, stripe, s, now_ms, &mut tally).await;
    tally.report("events", before);

    Ok(tally.summary())
}

async fn expire_unpaid(db: &Database, now_ms: i64, tally: &mut Tally) {
    let orders = match db
        .fetch_payment_orders_by_state(
            &[OrderState::Creating, OrderState::SessionFailed],
            now_ms - EXPIRE_UNPAID_AFTER_MS,
            SWEEP_BATCH,
        )
        .await
    {
        Ok(orders) => orders,
        Err(error) => return tally.error("query", "unpaid orders", &engine_text("fetch", &error)),
    };

    for order in orders {
        match engine::expire_order(db, &order.id, now_ms).await {
            Ok(()) => tally.expired += 1,
            Err(error) => tally.error("order", &order.id, &engine_text("expire", &error)),
        }
    }
}

async fn check_pending(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    now_ms: i64,
    tally: &mut Tally,
) {
    let orders = match db
        .fetch_payment_orders_by_state(
            &[OrderState::Pending],
            now_ms - CHECK_PENDING_AFTER_MS,
            SWEEP_BATCH,
        )
        .await
    {
        Ok(orders) => orders,
        Err(error) => return tally.error("query", "pending orders", &engine_text("fetch", &error)),
    };

    for order in orders {
        let Some(session_id) = order.checkout_session_id.as_deref() else {
            // A Pending order always has a session; without one nobody can
            // pay it
            match engine::expire_order(db, &order.id, now_ms).await {
                Ok(()) => tally.expired += 1,
                Err(error) => tally.error("order", &order.id, &engine_text("expire", &error)),
            }
            continue;
        };

        let session = match stripe.get_checkout_session(session_id).await {
            Ok(session) if session.id == session_id => session,
            Ok(_) => {
                tally.error(
                    "order",
                    &order.id,
                    "stripe returned a different checkout session",
                );
                continue;
            }
            Err(error) => {
                tally.error(
                    "order",
                    &order.id,
                    &stripe_text("get_checkout_session", &error),
                );
                continue;
            }
        };

        match (session.status.as_deref(), session.payment_status.as_deref()) {
            (Some("complete"), Some("paid")) => {
                match engine::fulfil_order(db, stripe, s, &order.id, &session, now_ms).await {
                    Ok(outcome) => count_fulfil(tally, outcome),
                    Err(error) => tally.error("order", &order.id, &engine_text("fulfil", &error)),
                }
            }
            (Some("expired"), _) => match engine::expire_order(db, &order.id, now_ms).await {
                Ok(()) => tally.expired += 1,
                Err(error) => tally.error("order", &order.id, &engine_text("expire", &error)),
            },
            // Still open (or complete without payment, which card-only
            // checkout never produces): leave it for a later sweep
            _ => {}
        }
    }
}

async fn resume_paid(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    now_ms: i64,
    tally: &mut Tally,
) {
    let orders = match db
        .fetch_payment_orders_by_state(&[OrderState::Paid], now_ms, SWEEP_BATCH)
        .await
    {
        Ok(orders) => orders,
        Err(error) => return tally.error("query", "paid orders", &engine_text("fetch", &error)),
    };

    for order in orders {
        // A held lease means a fulfilment is running right now
        if order.lease_until.is_some_and(|until| until >= now_ms) {
            continue;
        }

        match engine::resume_order(db, stripe, s, &order.id, now_ms).await {
            Ok(outcome) => count_fulfil(tally, outcome),
            Err(error) => tally.error("order", &order.id, &engine_text("resume", &error)),
        }
    }
}

fn count_fulfil(tally: &mut Tally, outcome: FulfilOutcome) {
    match outcome {
        FulfilOutcome::Fulfilled | FulfilOutcome::AlreadyFulfilled | FulfilOutcome::Voided(_) => {
            tally.resumed += 1
        }
        // Someone else holds the order, or there was nothing to do (yet: a
        // void that waits for a dispute is resumed again by the next sweep,
        // and the engine logs it)
        FulfilOutcome::LeaseHeld
        | FulfilOutcome::NotPaid
        | FulfilOutcome::Ignored
        | FulfilOutcome::VoidDeferred(_) => {}
    }
}

async fn apply_pending_reversals(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    now_ms: i64,
    tally: &mut Tally,
) {
    // Fulfilled only, filtered in the query: Paid orders are resumed above
    // and fulfilment applies the reversal as its last step; unpaid ones wait
    // for payment; terminal ones have nothing left to reverse
    let orders = match db
        .fetch_payment_orders_reversal_pending(&[OrderState::Fulfilled], now_ms, SWEEP_BATCH)
        .await
    {
        Ok(orders) => orders,
        Err(error) => {
            return tally.error("query", "pending reversals", &engine_text("fetch", &error))
        }
    };

    for order in orders {
        let Some(pending) = order.reversal_pending.as_ref() else {
            continue;
        };
        let kind = match pending {
            ReversalPending::Refund => ReverseKind::Refund,
            ReversalPending::DisputeLost => ReverseKind::DisputeLost,
        };

        // A recorded refund carries no refund event: nothing says it was
        // full, so it revokes and retires (fails closed)
        match engine::reverse_order(db, stripe, s, &order.id, kind, None, now_ms).await {
            Ok(ReverseOutcome::Applied) => tally.reversed += 1,
            Ok(ReverseOutcome::RecordedPending | ReverseOutcome::NoOp | ReverseOutcome::Busy) => {}
            Err(error) => tally.error("order", &order.id, &engine_text("reverse", &error)),
        }
    }
}

/// Numbers whose release a refund decided but did not finish (a crash, a
/// failed write, an event that will not come back): finished here
async fn finish_number_releases(db: &Database, now_ms: i64, tally: &mut Tally) {
    let rows = match db.fetch_cipher_numbers_release_pending(SWEEP_BATCH).await {
        Ok(rows) => rows,
        Err(error) => {
            return tally.error("query", "number releases", &engine_text("fetch", &error))
        }
    };

    for row in rows {
        let Some(order_id) = row.order_id else {
            continue;
        };
        let mut unrefunded = 0;
        let outcome = engine::finish_number_release(db, &order_id, now_ms, &mut unrefunded).await;
        tally.unrefunded_upgrades += unrefunded;
        match outcome {
            Ok(ReverseOutcome::Applied) => tally.reversed += 1,
            Ok(ReverseOutcome::RecordedPending | ReverseOutcome::NoOp | ReverseOutcome::Busy) => {}
            Err(error) => tally.error("order", &order_id, &engine_text("release", &error)),
        }
    }
}

async fn recheck_open_disputes(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    now_ms: i64,
    tally: &mut Tally,
) {
    // Paid ones are re-read by the resume above
    let orders = match db
        .fetch_payment_orders_disputed(&[OrderState::Fulfilled], now_ms, SWEEP_BATCH)
        .await
    {
        Ok(orders) => orders,
        Err(error) => return tally.error("query", "open disputes", &engine_text("fetch", &error)),
    };

    for order in orders {
        match engine::recheck_disputes(db, stripe, s, &order.id, now_ms).await {
            Ok(ReverseOutcome::Applied) => tally.reversed += 1,
            Ok(ReverseOutcome::RecordedPending | ReverseOutcome::NoOp | ReverseOutcome::Busy) => {}
            Err(error) => tally.error("order", &order.id, &engine_text("dispute", &error)),
        }
    }
}

async fn redrive_events(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    now_ms: i64,
    tally: &mut Tally,
) {
    let mut rows = Vec::new();
    match db
        .fetch_failed_payment_events(MAX_EVENT_ATTEMPTS, SWEEP_BATCH)
        .await
    {
        Ok(failed) => rows.extend(failed),
        Err(error) => tally.error("query", "failed events", &engine_text("fetch", &error)),
    }
    match db
        .fetch_payment_events_by_state(
            PaymentEventState::Received,
            now_ms - STRANDED_EVENT_AFTER_MS,
            SWEEP_BATCH,
        )
        .await
    {
        Ok(stranded) => rows.extend(stranded),
        Err(error) => tally.error("query", "stranded events", &engine_text("fetch", &error)),
    }

    for row in rows {
        let reason = match stripe.get_event(&row.id).await {
            Ok(event) if event.id == row.id => {
                match handle_event(db, stripe, s, &event, now_ms).await {
                    Ok(
                        EventOutcome::Processed | EventOutcome::Ignored | EventOutcome::Duplicate,
                    ) => tally.redriven += 1,
                    // handle_event has marked it Failed already
                    Ok(EventOutcome::Retry) => tally.error("event", &row.id, "retry"),
                    Err(error) => tally.error("event", &row.id, &engine_text("handle", &error)),
                }
                continue;
            }
            Ok(_) => "stripe returned a different event".to_string(),
            Err(error) => stripe_text("get_event", &error),
        };

        // Count the attempt: a Received row moves into the Failed queue, and a
        // Failed one gets closer to the attempt cap (Stripe keeps events for
        // 30 days, so an old one 404s for good)
        tally.error("event", &row.id, &reason);
        if let Err(error) = db
            .set_payment_event_state(&row.id, PaymentEventState::Failed, Some(reason))
            .await
        {
            tally.error("event", &row.id, &engine_text("mark failed", &error));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    use revolt_database::test_teardown::TestDatabaseGuard;
    use revolt_database::{
        CipherMembership, CipherRevokeReason, Database, DatabaseInfo, OrderState, PaymentEvent,
        PaymentEventState, PaymentOrder, PaymentProvider, ReversalPending, User,
    };
    use revolt_models::v0;
    use serde_json::{json, Value};

    use super::{
        action_for, charge_fully_refunded, dispute_kind, handle_event, reconcile, refund_facts,
        Action, EventOutcome,
    };
    use crate::engine::{sync_user_badge, ReverseKind, LEASE_MS};
    use crate::settings::PaymentsSettings;
    use crate::stripe::{
        CheckoutSession, Dispute, MockStripe, PaymentIntent, StripeError, StripeEvent,
    };

    const NOW: i64 = 1_760_000_000_000;
    const MINUTE: i64 = 60 * 1000;
    /// Planted in the settings: it must never show up in stored error text
    const SECRET_MARKER: &str = "sk_test_dispatch_secret_marker";

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

    /// A throwaway database for the driver `TEST_DB` selects, named like the
    /// ones `DatabaseInfo::Auto` mints so `scripts/drop-test-databases.sh`
    /// sweeps it if even the guard fails
    async fn test_db() -> TestDb {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .subsec_nanos();
        let name = format!(
            "revolt_test_{}{:03}",
            nanos % 10_000_000,
            NEXT.fetch_add(1, Ordering::Relaxed) % 1000
        );
        let db = DatabaseInfo::Test(name)
            .connect()
            .await
            .expect("database connection failed");
        let guard = TestDatabaseGuard::arm(&db).await;
        TestDb {
            db,
            guard: Mutex::new(Some(guard)),
        }
    }

    async fn drop_db(db: &TestDb) {
        if let Database::MongoDb(mongo) = &db.db {
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
            cap: 1000,
            close_at_ms: None,
            expect_livemode: false,
            tolerance_secs: 300,
            secret_key: SECRET_MARKER.to_string(),
            webhook_secret: "whsec_test_dispatch".to_string(),
            success_url_web: "https://app.sloga.gg/settings?cipher=success".to_string(),
            cancel_url_web: "https://app.sloga.gg/settings?cipher=cancel".to_string(),
            success_url_shell: "https://sloga.gg/cipher/thanks/".to_string(),
            cancel_url_shell: "https://sloga.gg/cipher/".to_string(),
        }
    }

    fn event(id: &str, event_type: &str, livemode: bool, object: Value) -> StripeEvent {
        StripeEvent {
            id: id.to_string(),
            event_type: event_type.to_string(),
            livemode,
            created: NOW / 1000,
            object,
        }
    }

    fn charge(payment_intent: &str) -> Value {
        json!({ "id": "ch_test_1", "object": "charge", "payment_intent": payment_intent })
    }

    fn dispute(payment_intent: &str, status: &str) -> Value {
        json!({
            "id": "dp_test_1",
            "object": "dispute",
            "payment_intent": payment_intent,
            "status": status
        })
    }

    /// The dispute as Stripe reports it now (what `get_dispute` returns)
    fn dispute_now(payment_intent: &str, status: &str) -> Dispute {
        Dispute {
            id: "dp_test_1".to_string(),
            status: Some(status.to_string()),
            payment_intent: Some(payment_intent.to_string()),
        }
    }

    /// A Fulfilled order of u1, its active membership (#7) and the badge
    async fn fulfilled_member(db: &Database, order_id: &str, payment_intent: &str) {
        insert_buyer(db).await;
        db.insert_payment_order(&PaymentOrder {
            payment_intent_id: Some(payment_intent.to_string()),
            fulfilled_at: Some(NOW - 50 * MINUTE),
            ..with_session(
                order(order_id, OrderState::Fulfilled, NOW - 60 * MINUTE),
                &format!("cs_{order_id}"),
            )
        })
        .await
        .unwrap();
        assert!(db
            .insert_cipher_membership(&CipherMembership {
                user_id: "u1".to_string(),
                number: 7,
                tier: v0::CipherTier::T99,
                prot_grant: 16_500,
                orders: vec![order_id.to_string()],
                disputed_orders: vec![],
                granted_at: NOW - 50 * MINUTE,
                revoked_at: None,
                revoke_reason: None,
                prot_posted_at: None,
                version: 0,
            })
            .await
            .unwrap());
        sync_user_badge(db, "u1").await.unwrap();
        assert_eq!(badge(db).await, Some(t99_badge()));
    }

    fn t99_badge() -> v0::UserCipher {
        v0::UserCipher {
            number: 7,
            tier: v0::CipherTier::T99,
        }
    }

    async fn badge(db: &Database) -> Option<v0::UserCipher> {
        db.fetch_user("u1").await.unwrap().cipher
    }

    /// u1's membership revoked for a lost dispute, the order Refunded and
    /// the badge gone
    async fn assert_lost(db: &Database, order_id: &str) {
        let m = db.fetch_cipher_membership("u1").await.unwrap().unwrap();
        assert!(m.revoked_at.is_some());
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::DisputeLost));
        assert!(m.disputed_orders.is_empty());
        let o = db.fetch_payment_order(order_id).await.unwrap().unwrap();
        assert_eq!(o.state, OrderState::Refunded);
        assert_eq!(badge(db).await, None);
    }

    fn order(id: &str, state: OrderState, created_at: i64) -> PaymentOrder {
        PaymentOrder {
            id: id.to_string(),
            user_id: Some("u1".to_string()),
            provider: PaymentProvider::Stripe,
            sku: v0::Sku::CipherNew {
                tier: v0::CipherTier::T99,
            },
            amount_cents: 9900,
            currency: "usd".to_string(),
            checkout_session_id: None,
            checkout_url: None,
            session_expires_at: None,
            payment_intent_id: None,
            state,
            void_reason: None,
            reversal_pending: None,
            open_disputes: vec![],
            lease_until: None,
            created_at,
            paid_at: None,
            fulfilled_at: None,
            reversed_at: None,
            version: 0,
        }
    }

    fn with_session(o: PaymentOrder, session_id: &str) -> PaymentOrder {
        PaymentOrder {
            checkout_session_id: Some(session_id.to_string()),
            checkout_url: Some(format!("https://checkout.stripe.test/{session_id}")),
            session_expires_at: Some(o.created_at + 35 * MINUTE),
            ..o
        }
    }

    fn session(id: &str, order_id: &str, status: &str, payment_status: &str) -> CheckoutSession {
        CheckoutSession {
            id: id.to_string(),
            url: None,
            status: Some(status.to_string()),
            payment_status: Some(payment_status.to_string()),
            payment_intent: (payment_status == "paid").then(|| format!("pi_for_{id}")),
            amount_total: Some(9900),
            currency: Some("usd".to_string()),
            livemode: false,
            client_reference_id: Some("u1".to_string()),
            metadata_order_id: Some(order_id.to_string()),
            expires_at: None,
        }
    }

    fn intent(id: &str, order_id: Option<&str>) -> PaymentIntent {
        PaymentIntent {
            id: id.to_string(),
            livemode: false,
            metadata_order_id: order_id.map(str::to_string),
            ..Default::default()
        }
    }

    fn event_row(
        id: &str,
        state: PaymentEventState,
        received_at: i64,
        attempts: u32,
    ) -> PaymentEvent {
        PaymentEvent {
            id: id.to_string(),
            event_type: "charge.refunded".to_string(),
            livemode: false,
            received_at,
            state,
            attempts,
            last_error: None,
        }
    }

    #[allow(clippy::disallowed_methods)]
    async fn insert_buyer(db: &Database) {
        db.insert_user(&User {
            id: "u1".to_string(),
            username: "cipherbuyer".to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    }

    async fn stored(db: &Database, id: &str) -> PaymentEvent {
        db.fetch_payment_event(id)
            .await
            .unwrap()
            .expect("event row")
    }

    #[test]
    fn dispute_statuses_map_to_their_reversal() {
        assert_eq!(dispute_kind(Some("lost")), ReverseKind::DisputeLost);
        for won in ["won", "warning_closed", "prevented"] {
            assert_eq!(dispute_kind(Some(won)), ReverseKind::DisputeWon, "{won}");
        }
        // Every open status, and anything unknown, counts as open
        for open in [
            Some("needs_response"),
            Some("under_review"),
            Some("warning_needs_response"),
            Some("warning_under_review"),
            Some("LOST"),
            Some("WON"),
            Some(""),
            None,
        ] {
            assert_eq!(dispute_kind(open), ReverseKind::DisputeOpened, "{open:?}");
        }
    }

    #[test]
    fn event_types_map_to_their_actions() {
        let of = |ty: &str, object: Value| action_for(&event("evt_map", ty, false, object));
        assert!(matches!(
            of("checkout.session.completed", json!({})),
            Action::Fulfil
        ));
        assert!(matches!(
            of("checkout.session.expired", json!({})),
            Action::Expire
        ));
        assert!(matches!(
            of("charge.refunded", json!({})),
            Action::Reverse(ReverseKind::Refund)
        ));
        // Every dispute event goes through the dispute's current status,
        // whatever its type or payload status says
        for (ty, status) in [
            ("charge.dispute.created", "needs_response"),
            ("charge.dispute.closed", "lost"),
            ("charge.dispute.closed", "under_review"),
            ("charge.dispute.updated", "won"),
            ("charge.dispute.funds_withdrawn", "needs_response"),
            ("charge.dispute.funds_reinstated", "won"),
        ] {
            assert!(
                matches!(of(ty, json!({ "status": status })), Action::Dispute),
                "{ty}"
            );
        }
        // Lookalikes are not ours
        for ty in [
            "checkout.session.async_payment_succeeded",
            "charge.refund.updated",
            "charge.dispute",
            "charge.disputed",
            "payment_intent.succeeded",
            "",
        ] {
            assert!(matches!(of(ty, json!({})), Action::Ignore), "{ty}");
        }
    }

    #[tokio::test]
    async fn an_event_seen_before_is_a_duplicate() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();

        let first = event(
            "evt_dup",
            "customer.created",
            false,
            json!({ "id": "cus_1" }),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &first, NOW).await.unwrap(),
            EventOutcome::Ignored
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &first, NOW + 1)
                .await
                .unwrap(),
            EventOutcome::Duplicate
        );
        let row = stored(&db, "evt_dup").await;
        assert_eq!(row.state, PaymentEventState::Ignored);
        assert_eq!(row.attempts, 1);
        assert_eq!(row.received_at, NOW);

        // A Processed row is never handled again: no lookup at all
        db.insert_payment_event_if_absent(&event_row(
            "evt_done",
            PaymentEventState::Processed,
            NOW - MINUTE,
            1,
        ))
        .await
        .unwrap();
        let again = event("evt_done", "charge.refunded", false, charge("pi_done"));
        assert_eq!(
            handle_event(&db, &stripe, &s, &again, NOW).await.unwrap(),
            EventOutcome::Duplicate
        );
        assert!(stripe.calls().is_empty());
        assert_eq!(stored(&db, "evt_done").await.attempts, 1);

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_livemode_mismatch_is_recorded_and_ignored() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();

        let paid = PaymentOrder {
            payment_intent_id: Some("pi_live".to_string()),
            ..order("o_live", OrderState::Fulfilled, NOW - 60 * MINUTE)
        };
        db.insert_payment_order(&paid).await.unwrap();

        // A live-mode refund delivered to a test-mode deployment
        let live = event("evt_live", "charge.refunded", true, charge("pi_live"));
        assert_eq!(
            handle_event(&db, &stripe, &s, &live, NOW).await.unwrap(),
            EventOutcome::Ignored
        );
        let row = stored(&db, "evt_live").await;
        assert_eq!(row.state, PaymentEventState::Ignored);
        assert!(row.livemode);
        assert!(stripe.calls().is_empty());
        assert_eq!(db.fetch_payment_order("o_live").await.unwrap(), Some(paid));

        // A row left Failed from before `expect_livemode` changed is settled
        // too, so the re-drive stops fetching it
        db.insert_payment_event_if_absent(&event_row(
            "evt_flip",
            PaymentEventState::Failed,
            NOW - 20 * MINUTE,
            2,
        ))
        .await
        .unwrap();
        let flipped = event("evt_flip", "charge.refunded", true, charge("pi_live"));
        assert_eq!(
            handle_event(&db, &stripe, &s, &flipped, NOW).await.unwrap(),
            EventOutcome::Ignored
        );
        assert_eq!(
            stored(&db, "evt_flip").await.state,
            PaymentEventState::Ignored
        );
        assert!(stripe.calls().is_empty());

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_foreign_payment_intent_is_ignored() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();

        let ours = PaymentOrder {
            payment_intent_id: Some("pi_ours".to_string()),
            ..order("o_ours", OrderState::Fulfilled, NOW - 60 * MINUTE)
        };
        db.insert_payment_order(&ours).await.unwrap();

        // No metadata: some other payment on the account
        stripe.set_payment_intent(intent("pi_other", None));
        // Metadata naming our order, which another intent paid
        stripe.set_payment_intent(intent("pi_claims_ours", Some("o_ours")));
        // Metadata naming an order we do not have
        stripe.set_payment_intent(intent("pi_unknown_order", Some("o_missing")));

        for (id, pi) in [
            ("evt_f1", "pi_other"),
            ("evt_f2", "pi_claims_ours"),
            ("evt_f3", "pi_unknown_order"),
            // Unknown to Stripe (404)
            ("evt_f4", "pi_nowhere"),
        ] {
            let refund = event(id, "charge.refunded", false, charge(pi));
            assert_eq!(
                handle_event(&db, &stripe, &s, &refund, NOW).await.unwrap(),
                EventOutcome::Ignored,
                "{pi}"
            );
            assert_eq!(stored(&db, id).await.state, PaymentEventState::Ignored);
        }

        // A dispute on a charge with no payment intent
        let bare = event(
            "evt_f5",
            "charge.dispute.created",
            false,
            json!({ "id": "dp_test_2", "object": "dispute", "payment_intent": null }),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &bare, NOW).await.unwrap(),
            EventOutcome::Ignored
        );

        // A checkout session we never created: no Stripe call for it
        let calls_before = stripe.call_count("get_checkout_session");
        let foreign = event(
            "evt_f6",
            "checkout.session.completed",
            false,
            json!({ "id": "cs_foreign", "object": "checkout.session", "metadata": { "order_id": "o_ours" } }),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &foreign, NOW).await.unwrap(),
            EventOutcome::Ignored
        );
        assert_eq!(stripe.call_count("get_checkout_session"), calls_before);

        // Our order was never touched, and nothing was refunded
        assert_eq!(db.fetch_payment_order("o_ours").await.unwrap(), Some(ours));
        assert_eq!(stripe.refund_count(), 0);

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_lost_close_delivered_before_its_creation_ends_revoked() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        fulfilled_member(&db, "o_lost", "pi_lost").await;
        stripe.set_dispute(dispute_now("pi_lost", "lost"));

        // The close arrives first
        let closed = event(
            "evt_lost_closed",
            "charge.dispute.closed",
            false,
            dispute("pi_lost", "lost"),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &closed, NOW).await.unwrap(),
            EventOutcome::Processed
        );
        assert_lost(&db, "o_lost").await;

        // Then the creation, whose payload still says needs_response: the
        // dispute is lost now, so nothing re-opens and nothing is restored
        let created = event(
            "evt_lost_created",
            "charge.dispute.created",
            false,
            dispute("pi_lost", "needs_response"),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &created, NOW + MINUTE)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        assert_lost(&db, "o_lost").await;
        assert_eq!(stripe.call_count("get_dispute"), 2);
        // A lost dispute is never refunded by us on top
        assert_eq!(stripe.refund_count(), 0);

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_creation_delivered_after_a_won_close_does_not_reopen() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        fulfilled_member(&db, "o_won", "pi_won").await;
        stripe.set_dispute(dispute_now("pi_won", "won"));

        let closed = event(
            "evt_won_closed",
            "charge.dispute.closed",
            false,
            dispute("pi_won", "won"),
        );
        let created = event(
            "evt_won_created",
            "charge.dispute.created",
            false,
            dispute("pi_won", "needs_response"),
        );
        for (delivery, at) in [(&closed, NOW), (&created, NOW + MINUTE)] {
            assert_eq!(
                handle_event(&db, &stripe, &s, delivery, at).await.unwrap(),
                EventOutcome::Processed,
                "{}",
                delivery.id
            );
            let m = db.fetch_cipher_membership("u1").await.unwrap().unwrap();
            assert!(m.revoked_at.is_none(), "{}", delivery.id);
            assert!(m.disputed_orders.is_empty(), "{}", delivery.id);
            assert_eq!(badge(&db).await, Some(t99_badge()), "{}", delivery.id);
            assert_eq!(
                db.fetch_payment_order("o_won")
                    .await
                    .unwrap()
                    .unwrap()
                    .state,
                OrderState::Fulfilled
            );
        }
        assert_eq!(stripe.call_count("get_dispute"), 2);

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn dispute_events_in_order_hide_then_restore_the_badge() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        fulfilled_member(&db, "o_seq", "pi_seq").await;

        stripe.set_dispute(dispute_now("pi_seq", "needs_response"));
        let created = event(
            "evt_seq_created",
            "charge.dispute.created",
            false,
            dispute("pi_seq", "needs_response"),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &created, NOW).await.unwrap(),
            EventOutcome::Processed
        );
        let m = db.fetch_cipher_membership("u1").await.unwrap().unwrap();
        assert_eq!(m.disputed_orders, vec!["o_seq".to_string()]);
        assert_eq!(badge(&db).await, None);

        // An update whose payload claims won while Stripe says it is still
        // under review keeps the badge hidden
        stripe.set_dispute(dispute_now("pi_seq", "under_review"));
        let updated = event(
            "evt_seq_updated",
            "charge.dispute.updated",
            false,
            dispute("pi_seq", "won"),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &updated, NOW + MINUTE)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        assert_eq!(badge(&db).await, None);

        stripe.set_dispute(dispute_now("pi_seq", "won"));
        let closed = event(
            "evt_seq_closed",
            "charge.dispute.closed",
            false,
            dispute("pi_seq", "won"),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &closed, NOW + 2 * MINUTE)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        let m = db.fetch_cipher_membership("u1").await.unwrap().unwrap();
        assert!(m.disputed_orders.is_empty());
        assert!(m.revoked_at.is_none());
        assert_eq!(badge(&db).await, Some(t99_badge()));

        drop_db(&db).await;
    }

    /// Set dispute `id` on `payment_intent` to `status` at Stripe
    fn set_dispute_status(stripe: &MockStripe, id: &str, payment_intent: &str, status: &str) {
        stripe.set_dispute(Dispute {
            id: id.to_string(),
            status: Some(status.to_string()),
            payment_intent: Some(payment_intent.to_string()),
        });
    }

    /// Deliver event `event_id` about dispute `dispute_id` on
    /// `payment_intent`. The payload's status is deliberately stale: the
    /// engine applies the status Stripe reports now.
    async fn deliver_dispute(
        db: &Database,
        stripe: &MockStripe,
        event_id: &str,
        dispute_id: &str,
        payment_intent: &str,
        at: i64,
    ) {
        let object = json!({
            "id": dispute_id,
            "object": "dispute",
            "payment_intent": payment_intent,
            "status": "needs_response"
        });
        let delivery = event(event_id, "charge.dispute.updated", false, object);
        assert_eq!(
            handle_event(db, stripe, &settings(), &delivery, at)
                .await
                .unwrap(),
            EventOutcome::Processed,
            "{event_id}"
        );
    }

    /// The order's open disputes, u1's listed orders and u1's badge
    async fn dispute_state(
        db: &Database,
        order_id: &str,
    ) -> (Vec<String>, Vec<String>, Option<v0::UserCipher>) {
        let o = db.fetch_payment_order(order_id).await.unwrap().unwrap();
        let m = db.fetch_cipher_membership("u1").await.unwrap().unwrap();
        assert!(m.revoked_at.is_none());
        (o.open_disputes, m.disputed_orders, badge(db).await)
    }

    #[tokio::test]
    async fn a_closed_inquiry_never_clears_an_open_chargeback_on_the_same_payment() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        fulfilled_member(&db, "o_two", "pi_two").await;
        let listed = vec!["o_two".to_string()];

        // An inquiry opens, then a chargeback on the same payment
        set_dispute_status(&stripe, "dp_inquiry", "pi_two", "warning_needs_response");
        deliver_dispute(&db, &stripe, "evt_inq_created", "dp_inquiry", "pi_two", NOW).await;
        set_dispute_status(&stripe, "dp_chargeback", "pi_two", "needs_response");
        deliver_dispute(
            &db,
            &stripe,
            "evt_cb_created",
            "dp_chargeback",
            "pi_two",
            NOW + 1,
        )
        .await;
        assert_eq!(
            dispute_state(&db, "o_two").await,
            (
                vec!["dp_inquiry".to_string(), "dp_chargeback".to_string()],
                listed.clone(),
                None
            )
        );

        // The inquiry closes in our favor: the chargeback still hides the
        // badge
        set_dispute_status(&stripe, "dp_inquiry", "pi_two", "warning_closed");
        deliver_dispute(
            &db,
            &stripe,
            "evt_inq_closed",
            "dp_inquiry",
            "pi_two",
            NOW + 2,
        )
        .await;
        assert_eq!(
            dispute_state(&db, "o_two").await,
            (vec!["dp_chargeback".to_string()], listed.clone(), None)
        );

        // The chargeback is won: the badge is back
        set_dispute_status(&stripe, "dp_chargeback", "pi_two", "won");
        deliver_dispute(
            &db,
            &stripe,
            "evt_cb_closed",
            "dp_chargeback",
            "pi_two",
            NOW + 3,
        )
        .await;
        assert_eq!(
            dispute_state(&db, "o_two").await,
            (vec![], vec![], Some(t99_badge()))
        );

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn two_disputes_delivered_out_of_order_keep_the_badge_hidden_until_both_close() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        fulfilled_member(&db, "o_ooo", "pi_ooo").await;
        let listed = vec!["o_ooo".to_string()];
        let only_cb = || {
            (
                vec!["dp_cb".to_string()],
                listed.clone(),
                None::<v0::UserCipher>,
            )
        };

        // By the time anything is delivered, the inquiry is already closed
        // and the chargeback open
        set_dispute_status(&stripe, "dp_inq", "pi_ooo", "warning_closed");
        set_dispute_status(&stripe, "dp_cb", "pi_ooo", "needs_response");

        deliver_dispute(&db, &stripe, "evt_cb_created", "dp_cb", "pi_ooo", NOW).await;
        assert_eq!(dispute_state(&db, "o_ooo").await, only_cb());
        // The inquiry's close, then its creation: neither touches the
        // chargeback
        deliver_dispute(&db, &stripe, "evt_inq_closed", "dp_inq", "pi_ooo", NOW + 1).await;
        assert_eq!(dispute_state(&db, "o_ooo").await, only_cb());
        deliver_dispute(&db, &stripe, "evt_inq_created", "dp_inq", "pi_ooo", NOW + 2).await;
        assert_eq!(dispute_state(&db, "o_ooo").await, only_cb());

        // The chargeback is won, and a late update of it does not reopen it
        set_dispute_status(&stripe, "dp_cb", "pi_ooo", "won");
        deliver_dispute(&db, &stripe, "evt_cb_closed", "dp_cb", "pi_ooo", NOW + 3).await;
        assert_eq!(
            dispute_state(&db, "o_ooo").await,
            (vec![], vec![], Some(t99_badge()))
        );
        deliver_dispute(&db, &stripe, "evt_cb_late", "dp_cb", "pi_ooo", NOW + 4).await;
        assert_eq!(
            dispute_state(&db, "o_ooo").await,
            (vec![], vec![], Some(t99_badge()))
        );

        // The other way round: a second chargeback's close (won) arrives
        // while a new inquiry is open, before its own creation
        set_dispute_status(&stripe, "dp_inq2", "pi_ooo", "warning_under_review");
        set_dispute_status(&stripe, "dp_cb2", "pi_ooo", "won");
        deliver_dispute(
            &db,
            &stripe,
            "evt_inq2_created",
            "dp_inq2",
            "pi_ooo",
            NOW + 5,
        )
        .await;
        let only_inq2 = || {
            (
                vec!["dp_inq2".to_string()],
                listed.clone(),
                None::<v0::UserCipher>,
            )
        };
        assert_eq!(dispute_state(&db, "o_ooo").await, only_inq2());
        deliver_dispute(&db, &stripe, "evt_cb2_closed", "dp_cb2", "pi_ooo", NOW + 6).await;
        assert_eq!(dispute_state(&db, "o_ooo").await, only_inq2());
        deliver_dispute(&db, &stripe, "evt_cb2_created", "dp_cb2", "pi_ooo", NOW + 7).await;
        assert_eq!(dispute_state(&db, "o_ooo").await, only_inq2());

        set_dispute_status(&stripe, "dp_inq2", "pi_ooo", "warning_closed");
        deliver_dispute(
            &db,
            &stripe,
            "evt_inq2_closed",
            "dp_inq2",
            "pi_ooo",
            NOW + 8,
        )
        .await;
        assert_eq!(
            dispute_state(&db, "o_ooo").await,
            (vec![], vec![], Some(t99_badge()))
        );
        assert_eq!(stripe.refund_count(), 0);

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_void_waiting_on_a_dispute_is_settled_and_finished_by_the_sweep() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = PaymentsSettings {
            close_at_ms: Some(NOW - 10 * MINUTE),
            ..settings()
        };
        // Created after the sale closed, so it can only be voided; disputed
        // before its completion is handled
        paid_at_stripe(&db, &stripe, "o_wait", "pi_wait").await;
        set_dispute_status(&stripe, "dp_wait", "pi_wait", "needs_response");
        let opened = event(
            "evt_wait_dp",
            "charge.dispute.created",
            false,
            json!({ "id": "dp_wait", "object": "dispute", "payment_intent": "pi_wait" }),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &opened, NOW).await.unwrap(),
            EventOutcome::Processed
        );

        // The completion cannot void while the dispute is open. The
        // deferral is durable (the order stays Paid, nothing refunded), so
        // the event is settled: retrying it would only burn its attempts
        let done = completed("evt_wait_done", "o_wait");
        assert_eq!(
            handle_event(&db, &stripe, &s, &done, NOW + 1)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        assert_eq!(
            stored(&db, "evt_wait_done").await.state,
            PaymentEventState::Processed
        );
        let o = db.fetch_payment_order("o_wait").await.unwrap().unwrap();
        assert_eq!(o.state, OrderState::Paid);
        assert_eq!(o.open_disputes, ["dp_wait"]);
        assert_eq!(stripe.call_count("create_refund"), 0);

        // The sweep resumes the order and re-reads the dispute: still open,
        // so it keeps waiting (not counted, not an error)
        let lookups = stripe.call_count("get_dispute");
        assert_eq!(
            reconcile(&db, &stripe, &s, NOW + 2).await.unwrap(),
            "expired=0, resumed=0, reversed=0, redriven=0, errors=0"
        );
        assert_eq!(stripe.call_count("get_dispute"), lookups + 1);
        assert_eq!(stripe.call_count("create_refund"), 0);
        assert_eq!(
            db.fetch_payment_order("o_wait")
                .await
                .unwrap()
                .unwrap()
                .state,
            OrderState::Paid
        );

        // Won at Stripe, and the close event never arrives: the next sweep
        // reads the win and the void refunds, once
        set_dispute_status(&stripe, "dp_wait", "pi_wait", "won");
        assert_eq!(
            reconcile(&db, &stripe, &s, NOW + 3).await.unwrap(),
            "expired=0, resumed=1, reversed=0, redriven=0, errors=0"
        );
        let o = db.fetch_payment_order("o_wait").await.unwrap().unwrap();
        assert_eq!(o.state, OrderState::Voided);
        assert!(o.open_disputes.is_empty());
        assert_eq!(stripe.refund_count_for("pi_wait"), 1);

        // The close event arriving late, and the completion again, change
        // nothing
        let closed = event(
            "evt_wait_dp_closed",
            "charge.dispute.closed",
            false,
            json!({ "id": "dp_wait", "object": "dispute", "payment_intent": "pi_wait" }),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &closed, NOW + 4)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &done, NOW + 5)
                .await
                .unwrap(),
            EventOutcome::Duplicate
        );
        assert_eq!(stripe.refund_count_for("pi_wait"), 1);
        assert_eq!(
            reconcile(&db, &stripe, &s, NOW + 6).await.unwrap(),
            "expired=0, resumed=0, reversed=0, redriven=0, errors=0"
        );

        drop_db(&db).await;
    }

    /// m2: a Fulfilled order whose dispute closes at Stripe without the
    /// close event ever arriving. The sweep re-reads its open disputes, so
    /// the won dispute restores the badge; a failed read changes nothing
    /// (the badge stays hidden) and is counted as an error.
    #[tokio::test]
    async fn a_dispute_whose_close_event_never_arrives_is_settled_by_the_sweep() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        fulfilled_member(&db, "o_quiet", "pi_quiet").await;

        set_dispute_status(&stripe, "dp_quiet", "pi_quiet", "needs_response");
        let opened = event(
            "evt_quiet_dp",
            "charge.dispute.created",
            false,
            json!({ "id": "dp_quiet", "object": "dispute", "payment_intent": "pi_quiet" }),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &opened, NOW).await.unwrap(),
            EventOutcome::Processed
        );
        assert_eq!(badge(&db).await, None);
        let o = db.fetch_payment_order("o_quiet").await.unwrap().unwrap();
        assert_eq!(o.open_disputes, ["dp_quiet"]);

        // Still open: read, nothing changes
        assert_eq!(
            reconcile(&db, &stripe, &s, NOW + 1).await.unwrap(),
            "expired=0, resumed=0, reversed=0, redriven=0, errors=0"
        );
        assert_eq!(badge(&db).await, None);

        // Won at Stripe, but Stripe cannot be reached this sweep: an
        // error, and the badge stays hidden (fail closed)
        set_dispute_status(&stripe, "dp_quiet", "pi_quiet", "won");
        stripe.fail_next(
            "get_dispute",
            StripeError::Transport("connection reset".to_string()),
        );
        assert_eq!(
            reconcile(&db, &stripe, &s, NOW + 2).await.unwrap(),
            "expired=0, resumed=0, reversed=0, redriven=0, errors=1"
        );
        assert_eq!(badge(&db).await, None);

        // The next sweep reads the win: the badge is back
        assert_eq!(
            reconcile(&db, &stripe, &s, NOW + 3).await.unwrap(),
            "expired=0, resumed=0, reversed=1, redriven=0, errors=0"
        );
        assert_eq!(badge(&db).await, Some(t99_badge()));
        let m = db.fetch_cipher_membership("u1").await.unwrap().unwrap();
        assert!(m.disputed_orders.is_empty());
        assert!(m.revoked_at.is_none());
        let o = db.fetch_payment_order("o_quiet").await.unwrap().unwrap();
        assert_eq!(o.state, OrderState::Fulfilled);
        assert!(o.open_disputes.is_empty());

        // Nothing is left to read
        let lookups = stripe.call_count("get_dispute");
        assert_eq!(
            reconcile(&db, &stripe, &s, NOW + 4).await.unwrap(),
            "expired=0, resumed=0, reversed=0, redriven=0, errors=0"
        );
        assert_eq!(stripe.call_count("get_dispute"), lookups);

        drop_db(&db).await;
    }

    /// The lost variant: the sweep reads the loss and revokes
    #[tokio::test]
    async fn a_lost_dispute_whose_close_event_never_arrives_revokes_at_the_sweep() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        fulfilled_member(&db, "o_gone", "pi_gone").await;

        set_dispute_status(&stripe, "dp_gone", "pi_gone", "needs_response");
        let opened = event(
            "evt_gone_dp",
            "charge.dispute.created",
            false,
            json!({ "id": "dp_gone", "object": "dispute", "payment_intent": "pi_gone" }),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &opened, NOW).await.unwrap(),
            EventOutcome::Processed
        );

        set_dispute_status(&stripe, "dp_gone", "pi_gone", "lost");
        assert_eq!(
            reconcile(&db, &stripe, &s, NOW + 1).await.unwrap(),
            "expired=0, resumed=0, reversed=1, redriven=0, errors=0"
        );
        assert_lost(&db, "o_gone").await;
        assert_eq!(stripe.call_count("create_refund"), 0);

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_failed_dispute_lookup_retries_and_never_guesses() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        fulfilled_member(&db, "o_look", "pi_look").await;

        // The payload says lost; Stripe cannot be asked
        let closed = event(
            "evt_look",
            "charge.dispute.closed",
            false,
            dispute("pi_look", "lost"),
        );
        stripe.fail_next(
            "get_dispute",
            StripeError::Transport(format!("timed out using {SECRET_MARKER}")),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &closed, NOW).await.unwrap(),
            EventOutcome::Retry
        );
        // Not known at Stripe (yet): also a retry, not "not ours"
        assert_eq!(
            handle_event(&db, &stripe, &s, &closed, NOW + 1)
                .await
                .unwrap(),
            EventOutcome::Retry
        );
        // Stripe names another payment for this dispute: a retry too
        stripe.set_dispute(dispute_now("pi_somebody_else", "lost"));
        assert_eq!(
            handle_event(&db, &stripe, &s, &closed, NOW + 2)
                .await
                .unwrap(),
            EventOutcome::Retry
        );

        let row = stored(&db, "evt_look").await;
        assert_eq!(row.state, PaymentEventState::Failed);
        assert_eq!(row.attempts, 3);
        let reason = row.last_error.expect("a failure reason is stored");
        assert!(!reason.contains(SECRET_MARKER), "{reason}");
        assert!(!reason.contains("sk_"), "{reason}");

        // Nothing was applied on the payload's word
        let m = db.fetch_cipher_membership("u1").await.unwrap().unwrap();
        assert!(m.revoked_at.is_none());
        assert!(m.disputed_orders.is_empty());
        assert_eq!(
            db.fetch_payment_order("o_look")
                .await
                .unwrap()
                .unwrap()
                .state,
            OrderState::Fulfilled
        );
        assert_eq!(badge(&db).await, Some(t99_badge()));

        // Once Stripe answers, the redelivery applies the real status
        stripe.set_dispute(dispute_now("pi_look", "lost"));
        assert_eq!(
            handle_event(&db, &stripe, &s, &closed, NOW + 3)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        assert_eq!(badge(&db).await, None);
        assert_eq!(
            db.fetch_payment_order("o_look")
                .await
                .unwrap()
                .unwrap()
                .state,
            OrderState::Refunded
        );

        drop_db(&db).await;
    }

    /// A Pending order of u1 with a live session `cs_<order_id>` that is now
    /// complete and paid by `payment_intent` at Stripe, whose metadata
    /// names the order
    async fn paid_at_stripe(
        db: &Database,
        stripe: &MockStripe,
        order_id: &str,
        payment_intent: &str,
    ) {
        insert_buyer(db).await;
        db.seed_cipher_numbers(1000).await.unwrap();
        let session_id = format!("cs_{order_id}");
        db.insert_payment_order(&with_session(
            order(order_id, OrderState::Pending, NOW - 5 * MINUTE),
            &session_id,
        ))
        .await
        .unwrap();
        stripe.set_session(CheckoutSession {
            payment_intent: Some(payment_intent.to_string()),
            ..session(&session_id, order_id, "complete", "paid")
        });
        stripe.set_payment_intent(intent(payment_intent, Some(order_id)));
    }

    fn completed(id: &str, order_id: &str) -> StripeEvent {
        event(
            id,
            "checkout.session.completed",
            false,
            json!({ "id": format!("cs_{order_id}"), "object": "checkout.session" }),
        )
    }

    #[tokio::test]
    async fn a_dispute_before_the_completion_never_shows_the_badge() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        paid_at_stripe(&db, &stripe, "o_early_dp", "pi_early_dp").await;
        stripe.set_dispute(dispute_now("pi_early_dp", "needs_response"));

        // The order has no payment intent yet: found by the intent's
        // metadata, and the dispute is recorded on the Pending order
        let opened = event(
            "evt_dp_created",
            "charge.dispute.created",
            false,
            dispute("pi_early_dp", "needs_response"),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &opened, NOW).await.unwrap(),
            EventOutcome::Processed
        );
        let o = db.fetch_payment_order("o_early_dp").await.unwrap().unwrap();
        assert_eq!(o.state, OrderState::Pending);
        assert_eq!(o.open_disputes, ["dp_test_1"]);
        assert_eq!(badge(&db).await, None);

        // The completion: a member, listed as disputed, and no badge
        assert_eq!(
            handle_event(
                &db,
                &stripe,
                &s,
                &completed("evt_dp_done", "o_early_dp"),
                NOW + 1
            )
            .await
            .unwrap(),
            EventOutcome::Processed
        );
        let m = db.fetch_cipher_membership("u1").await.unwrap().unwrap();
        assert!(m.revoked_at.is_none());
        assert_eq!(m.orders, vec!["o_early_dp".to_string()]);
        assert_eq!(m.disputed_orders, vec!["o_early_dp".to_string()]);
        assert_eq!(badge(&db).await, None);
        assert_eq!(
            db.fetch_payment_order("o_early_dp")
                .await
                .unwrap()
                .unwrap()
                .state,
            OrderState::Fulfilled
        );

        // Won: the badge appears
        stripe.set_dispute(dispute_now("pi_early_dp", "won"));
        let closed = event(
            "evt_dp_closed",
            "charge.dispute.closed",
            false,
            dispute("pi_early_dp", "won"),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &closed, NOW + 2)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        assert!(db
            .fetch_cipher_membership("u1")
            .await
            .unwrap()
            .unwrap()
            .disputed_orders
            .is_empty());
        assert_eq!(
            badge(&db).await,
            Some(v0::UserCipher {
                number: 1,
                tier: v0::CipherTier::T99,
            })
        );
        assert_eq!(stripe.refund_count(), 0);

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_dispute_on_a_paid_order_before_its_fulfilment_never_shows_the_badge() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        paid_at_stripe(&db, &stripe, "o_paid_dp", "pi_paid_dp").await;

        // A fulfilment marked it Paid and died; its lease has run out
        let leased = db
            .acquire_payment_order_lease("o_paid_dp", NOW - 4 * MINUTE, NOW - 2 * MINUTE)
            .await
            .unwrap()
            .unwrap();
        assert!(db
            .update_payment_order_if_state(
                &PaymentOrder {
                    state: OrderState::Paid,
                    payment_intent_id: Some("pi_paid_dp".to_string()),
                    paid_at: Some(NOW - 4 * MINUTE),
                    ..leased
                },
                OrderState::Pending,
            )
            .await
            .unwrap());

        stripe.set_dispute(dispute_now("pi_paid_dp", "under_review"));
        let opened = event(
            "evt_pdp_created",
            "charge.dispute.created",
            false,
            dispute("pi_paid_dp", "needs_response"),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &opened, NOW).await.unwrap(),
            EventOutcome::Processed
        );
        let o = db.fetch_payment_order("o_paid_dp").await.unwrap().unwrap();
        assert_eq!(o.state, OrderState::Paid);
        assert_eq!(o.open_disputes, ["dp_test_1"]);
        assert_eq!(badge(&db).await, None);

        // The sweep resumes the Paid order
        let summary = reconcile(&db, &stripe, &s, NOW + MINUTE).await.unwrap();
        assert_eq!(
            summary,
            "expired=0, resumed=1, reversed=0, redriven=0, errors=0"
        );
        let m = db.fetch_cipher_membership("u1").await.unwrap().unwrap();
        assert_eq!(m.disputed_orders, vec!["o_paid_dp".to_string()]);
        assert_eq!(badge(&db).await, None);

        // Lost: revoked, and the badge was never shown
        stripe.set_dispute(dispute_now("pi_paid_dp", "lost"));
        let closed = event(
            "evt_pdp_closed",
            "charge.dispute.closed",
            false,
            dispute("pi_paid_dp", "lost"),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &closed, NOW + 2 * MINUTE)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        assert_lost(&db, "o_paid_dp").await;
        assert_eq!(stripe.refund_count(), 0);

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn unknown_event_types_are_ignored() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();

        for (id, ty) in [
            ("evt_u1", "customer.created"),
            ("evt_u2", "payment_intent.succeeded"),
            ("evt_u3", "invoice.paid"),
            ("evt_u4", "checkout.session.async_payment_failed"),
        ] {
            let other = event(
                id,
                ty,
                false,
                json!({ "id": "obj_1", "payment_intent": "pi_x" }),
            );
            assert_eq!(
                handle_event(&db, &stripe, &s, &other, NOW).await.unwrap(),
                EventOutcome::Ignored,
                "{ty}"
            );
            assert_eq!(stored(&db, id).await.state, PaymentEventState::Ignored);
        }
        assert!(stripe.calls().is_empty());

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn completion_is_judged_by_the_session_stripe_reports_now() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();

        let pending = with_session(
            order("o_stale", OrderState::Pending, NOW - 5 * MINUTE),
            "cs_stale",
        );
        db.insert_payment_order(&pending).await.unwrap();
        // The event payload claims a paid session; Stripe says it is unpaid
        stripe.set_session(session("cs_stale", "o_stale", "open", "unpaid"));

        let completed = event(
            "evt_stale",
            "checkout.session.completed",
            false,
            json!({
                "id": "cs_stale",
                "object": "checkout.session",
                "status": "complete",
                "payment_status": "paid",
                "payment_intent": "pi_forged",
                "amount_total": 9900,
                "currency": "usd",
                "metadata": { "order_id": "o_stale" }
            }),
        );
        // Not settled: retried until Stripe reports it paid
        assert_eq!(
            handle_event(&db, &stripe, &s, &completed, NOW)
                .await
                .unwrap(),
            EventOutcome::Retry
        );
        assert_eq!(stripe.call_count("get_checkout_session"), 1);
        assert_eq!(
            stored(&db, "evt_stale").await.state,
            PaymentEventState::Failed
        );

        let after = db.fetch_payment_order("o_stale").await.unwrap().unwrap();
        assert_eq!(after.state, OrderState::Pending);
        assert!(after.payment_intent_id.is_none());
        assert_eq!(stripe.refund_count(), 0);

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_failed_attempt_is_marked_failed_and_a_redelivery_processes_it() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();

        // A refund that arrives before fulfilment stored the intent: only the
        // intent's metadata can find the order
        let pending = with_session(
            order("o_early", OrderState::Pending, NOW - 5 * MINUTE),
            "cs_early",
        );
        db.insert_payment_order(&pending).await.unwrap();
        stripe.set_payment_intent(intent("pi_early", Some("o_early")));
        stripe.fail_next(
            "get_payment_intent",
            StripeError::Transport(format!("timed out using {SECRET_MARKER}")),
        );

        let refund = event("evt_retry", "charge.refunded", false, charge("pi_early"));
        assert_eq!(
            handle_event(&db, &stripe, &s, &refund, NOW).await.unwrap(),
            EventOutcome::Retry
        );
        let row = stored(&db, "evt_retry").await;
        assert_eq!(row.state, PaymentEventState::Failed);
        assert_eq!(row.attempts, 1);
        let reason = row.last_error.expect("a failure reason is stored");
        assert!(reason.contains("get_payment_intent"), "{reason}");
        assert!(!reason.contains(SECRET_MARKER), "{reason}");
        assert!(!reason.contains("sk_"), "{reason}");
        assert_eq!(
            db.fetch_payment_order("o_early").await.unwrap(),
            Some(pending.clone())
        );

        // Stripe delivers it again
        assert_eq!(
            handle_event(&db, &stripe, &s, &refund, NOW + MINUTE)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        let row = stored(&db, "evt_retry").await;
        assert_eq!(row.state, PaymentEventState::Processed);
        assert_eq!(row.attempts, 2);
        assert!(row.last_error.is_none());

        // The engine recorded the refund for fulfilment to apply
        let after = db.fetch_payment_order("o_early").await.unwrap().unwrap();
        assert_eq!(after.state, OrderState::Pending);
        assert_eq!(after.reversal_pending, Some(ReversalPending::Refund));

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_busy_order_answers_retry_until_its_lease_is_free() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_buyer(&db).await;

        let fulfilled = PaymentOrder {
            payment_intent_id: Some("pi_busy".to_string()),
            fulfilled_at: Some(NOW - 50 * MINUTE),
            ..with_session(
                order("o_busy", OrderState::Fulfilled, NOW - 60 * MINUTE),
                "cs_busy",
            )
        };
        db.insert_payment_order(&fulfilled).await.unwrap();
        assert!(db
            .insert_cipher_membership(&CipherMembership {
                user_id: "u1".to_string(),
                number: 7,
                tier: v0::CipherTier::T99,
                prot_grant: 16_500,
                orders: vec!["o_busy".to_string()],
                disputed_orders: vec![],
                granted_at: NOW - 50 * MINUTE,
                revoked_at: None,
                revoke_reason: None,
                prot_posted_at: None,
                version: 0,
            })
            .await
            .unwrap());

        // Another worker holds the order
        let until = NOW + LEASE_MS;
        db.acquire_payment_order_lease("o_busy", NOW, until)
            .await
            .unwrap()
            .expect("lease");

        stripe.set_dispute(dispute_now("pi_busy", "needs_response"));
        let opened = event(
            "evt_busy",
            "charge.dispute.created",
            false,
            dispute("pi_busy", "needs_response"),
        );
        assert_eq!(
            handle_event(&db, &stripe, &s, &opened, NOW + 1)
                .await
                .unwrap(),
            EventOutcome::Retry
        );
        let row = stored(&db, "evt_busy").await;
        assert_eq!(row.state, PaymentEventState::Failed);
        assert!(row.last_error.is_some());

        // The holder finishes; the redelivery goes through
        db.release_payment_order_lease("o_busy", until)
            .await
            .unwrap();
        assert_eq!(
            handle_event(&db, &stripe, &s, &opened, NOW + 2)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        assert_eq!(
            stored(&db, "evt_busy").await.state,
            PaymentEventState::Processed
        );

        // It reached the engine as a dispute opening
        let membership = db.fetch_cipher_membership("u1").await.unwrap().unwrap();
        assert_eq!(membership.disputed_orders, vec!["o_busy".to_string()]);
        assert!(membership.revoked_at.is_none());

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn reconcile_expires_stale_unpaid_orders_and_fulfils_a_paid_pending_one() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_buyer(&db).await;
        db.seed_cipher_numbers(1000).await.unwrap();

        db.insert_payment_order(&order(
            "o_creating",
            OrderState::Creating,
            NOW - 11 * MINUTE,
        ))
        .await
        .unwrap();
        // Too young to expire
        db.insert_payment_order(&order("o_young", OrderState::Creating, NOW - 5 * MINUTE))
            .await
            .unwrap();
        // Paid on Stripe, but the completion webhook never arrived
        db.insert_payment_order(&with_session(
            order("o_paid", OrderState::Pending, NOW - 41 * MINUTE),
            "cs_paid",
        ))
        .await
        .unwrap();
        stripe.set_session(session("cs_paid", "o_paid", "complete", "paid"));
        // Still open on Stripe
        db.insert_payment_order(&PaymentOrder {
            user_id: Some("u2".to_string()),
            ..with_session(
                order("o_open", OrderState::Pending, NOW - 42 * MINUTE),
                "cs_open",
            )
        })
        .await
        .unwrap();
        stripe.set_session(session("cs_open", "o_open", "open", "unpaid"));

        let summary = reconcile(&db, &stripe, &s, NOW).await.unwrap();
        assert_eq!(
            summary,
            "expired=1, resumed=1, reversed=0, redriven=0, errors=0"
        );

        let state = |id: &'static str| {
            let db = db.clone();
            async move { db.fetch_payment_order(id).await.unwrap().unwrap().state }
        };
        assert_eq!(state("o_creating").await, OrderState::Expired);
        assert_eq!(state("o_young").await, OrderState::Creating);
        assert_eq!(state("o_paid").await, OrderState::Fulfilled);
        assert_eq!(state("o_open").await, OrderState::Pending);
        assert_eq!(stripe.refund_count(), 0);

        drop_db(&db).await;
    }

    #[tokio::test]
    async fn one_failing_item_does_not_stop_the_sweep() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_buyer(&db).await;
        db.seed_cipher_numbers(1000).await.unwrap();

        // Oldest first: this one fails and must not block the others
        db.insert_payment_order(&with_session(
            order("o_fail", OrderState::Pending, NOW - 50 * MINUTE),
            "cs_fail",
        ))
        .await
        .unwrap();
        stripe.set_session(session("cs_fail", "o_fail", "complete", "paid"));
        stripe.fail_next(
            "get_checkout_session",
            StripeError::Transport("connection reset".to_string()),
        );
        db.insert_payment_order(&PaymentOrder {
            user_id: Some("u2".to_string()),
            ..with_session(
                order("o_lapsed", OrderState::Pending, NOW - 45 * MINUTE),
                "cs_lapsed",
            )
        })
        .await
        .unwrap();
        stripe.set_session(session("cs_lapsed", "o_lapsed", "expired", "unpaid"));
        db.insert_payment_order(&PaymentOrder {
            user_id: Some("u3".to_string()),
            ..order(
                "o_failed_session",
                OrderState::SessionFailed,
                NOW - 20 * MINUTE,
            )
        })
        .await
        .unwrap();

        // Events: one Stripe no longer has, one stranded by a crash, one
        // still in flight
        db.insert_payment_event_if_absent(&event_row(
            "evt_gone",
            PaymentEventState::Failed,
            NOW - 30 * MINUTE,
            1,
        ))
        .await
        .unwrap();
        db.insert_payment_event_if_absent(&event_row(
            "evt_stranded",
            PaymentEventState::Received,
            NOW - 11 * MINUTE,
            0,
        ))
        .await
        .unwrap();
        stripe.set_event(event(
            "evt_stranded",
            "customer.created",
            false,
            json!({ "id": "cus_1" }),
        ));
        db.insert_payment_event_if_absent(&event_row(
            "evt_in_flight",
            PaymentEventState::Received,
            NOW - MINUTE,
            0,
        ))
        .await
        .unwrap();

        let summary = reconcile(&db, &stripe, &s, NOW).await.unwrap();
        assert_eq!(
            summary,
            "expired=2, resumed=0, reversed=0, redriven=1, errors=2"
        );

        let state = |id: &'static str| {
            let db = db.clone();
            async move { db.fetch_payment_order(id).await.unwrap().unwrap().state }
        };
        assert_eq!(state("o_fail").await, OrderState::Pending);
        assert_eq!(state("o_lapsed").await, OrderState::Expired);
        assert_eq!(state("o_failed_session").await, OrderState::Expired);

        let gone = stored(&db, "evt_gone").await;
        assert_eq!(gone.state, PaymentEventState::Failed);
        assert_eq!(gone.attempts, 2);
        assert!(gone.last_error.unwrap().contains("get_event"));
        assert_eq!(
            stored(&db, "evt_stranded").await.state,
            PaymentEventState::Ignored
        );
        let in_flight = stored(&db, "evt_in_flight").await;
        assert_eq!(in_flight.state, PaymentEventState::Received);
        assert_eq!(in_flight.attempts, 0);
        assert_eq!(stripe.call_count("get_event"), 2);

        // The failed order is picked up by the next sweep; the event Stripe
        // no longer has keeps counting attempts toward the cap, and the one
        // that was in flight is now stranded too (Stripe has no copy of it
        // either, so it moves into the Failed queue with its first attempt)
        let summary = reconcile(&db, &stripe, &s, NOW + 10 * MINUTE)
            .await
            .unwrap();
        assert_eq!(
            summary,
            "expired=0, resumed=1, reversed=0, redriven=0, errors=2"
        );
        assert_eq!(state("o_fail").await, OrderState::Fulfilled);
        assert_eq!(stored(&db, "evt_gone").await.attempts, 3);
        let in_flight = stored(&db, "evt_in_flight").await;
        assert_eq!(in_flight.state, PaymentEventState::Failed);
        assert_eq!(in_flight.attempts, 1);

        drop_db(&db).await;
    }

    // --- refunds: when made, and whether full ---------------------------

    const DAY: i64 = 24 * 60 * MINUTE;

    #[test]
    fn a_charge_is_fully_refunded_by_its_flag_or_its_amounts() {
        assert!(charge_fully_refunded(&json!({ "refunded": true })));
        assert!(charge_fully_refunded(
            &json!({ "amount": 9900, "amount_refunded": 9900 })
        ));
        assert!(!charge_fully_refunded(
            &json!({ "refunded": false, "amount": 9900, "amount_refunded": 5000 })
        ));
        // Missing or malformed: not full (revoke + retire)
        assert!(!charge_fully_refunded(&json!({})));
        assert!(!charge_fully_refunded(
            &json!({ "amount": 0, "amount_refunded": 0 })
        ));
        assert!(!charge_fully_refunded(&json!({ "refunded": "true" })));
    }

    #[test]
    fn a_refund_is_dated_by_its_event_and_never_in_the_future() {
        let mut refunded = event(
            "evt_d",
            "charge.refunded",
            false,
            json!({ "refunded": true }),
        );
        refunded.created = (NOW + 16 * DAY) / 1000;
        let facts = refund_facts(&refunded, NOW + 19 * DAY);
        assert_eq!(facts.refunded_at_ms, NOW + 16 * DAY);
        assert!(facts.full);

        // A `created` ahead of our clock is capped at now
        refunded.created = (NOW + 30 * DAY) / 1000;
        assert_eq!(refund_facts(&refunded, NOW).refunded_at_ms, NOW);
    }

    /// A Fulfilled new purchase of u1 paid at `paid_at`, holding a claimed
    /// number, its membership and badge; the number
    async fn paid_member(db: &Database, order_id: &str, payment_intent: &str, paid_at: i64) -> u32 {
        insert_buyer(db).await;
        db.seed_cipher_numbers(10).await.unwrap();
        db.insert_payment_order(&PaymentOrder {
            payment_intent_id: Some(payment_intent.to_string()),
            paid_at: Some(paid_at),
            fulfilled_at: Some(paid_at),
            ..with_session(
                order(order_id, OrderState::Fulfilled, paid_at - MINUTE),
                &format!("cs_{order_id}"),
            )
        })
        .await
        .unwrap();
        let number = db
            .claim_cipher_number(order_id, 10)
            .await
            .unwrap()
            .expect("a number");
        assert!(db
            .insert_cipher_membership(&CipherMembership {
                user_id: "u1".to_string(),
                number,
                tier: v0::CipherTier::T99,
                prot_grant: 16_500,
                orders: vec![order_id.to_string()],
                disputed_orders: vec![],
                granted_at: paid_at,
                revoked_at: None,
                revoke_reason: None,
                prot_posted_at: None,
                version: 0,
            })
            .await
            .unwrap());
        sync_user_badge(db, "u1").await.unwrap();
        number
    }

    fn refunded_charge(payment_intent: &str, amount_refunded: i64) -> Value {
        json!({
            "id": "ch_test_1",
            "object": "charge",
            "payment_intent": payment_intent,
            "amount": 9900,
            "amount_refunded": amount_refunded,
            "refunded": amount_refunded >= 9900
        })
    }

    #[tokio::test]
    async fn a_redriven_refund_made_in_time_releases_the_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        paid_member(&db, "o_rel", "pi_rel", NOW).await;

        // Refunded in full on day 16 (inside the 14 days plus the grace);
        // the delivery failed and the sweep re-drives it on day 19
        let mut refunded = event(
            "evt_rel",
            "charge.refunded",
            false,
            refunded_charge("pi_rel", 9900),
        );
        refunded.created = (NOW + 16 * DAY) / 1000;
        stripe.set_event(refunded);
        db.insert_payment_event_if_absent(&event_row(
            "evt_rel",
            PaymentEventState::Failed,
            NOW + 16 * DAY,
            1,
        ))
        .await
        .unwrap();

        reconcile(&db, &stripe, &s, NOW + 19 * DAY).await.unwrap();
        assert_eq!(
            stored(&db, "evt_rel").await.state,
            PaymentEventState::Processed
        );
        assert_eq!(db.fetch_cipher_membership("u1").await.unwrap(), None);
        assert_eq!(
            db.fetch_cipher_number_by_order("o_rel").await.unwrap(),
            None
        );
        assert_eq!(badge(&db).await, None);
        assert_eq!(
            db.fetch_payment_order("o_rel")
                .await
                .unwrap()
                .unwrap()
                .state,
            OrderState::Refunded
        );
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_refund_made_after_the_grace_retires_the_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let number = paid_member(&db, "o_late", "pi_late", NOW).await;

        let mut refunded = event(
            "evt_late",
            "charge.refunded",
            false,
            refunded_charge("pi_late", 9900),
        );
        refunded.created = (NOW + 18 * DAY) / 1000;
        assert_eq!(
            handle_event(&db, &stripe, &s, &refunded, NOW + 18 * DAY)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        let m = db.fetch_cipher_membership("u1").await.unwrap().unwrap();
        assert_eq!(m.revoke_reason, Some(CipherRevokeReason::Refund));
        assert_eq!(
            db.fetch_cipher_number_by_order("o_late").await.unwrap(),
            Some(number)
        );
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_partial_refund_inside_the_window_retires_the_number() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let number = paid_member(&db, "o_part", "pi_part", NOW).await;

        let mut refunded = event(
            "evt_part",
            "charge.refunded",
            false,
            refunded_charge("pi_part", 5000),
        );
        refunded.created = (NOW + DAY) / 1000;
        assert_eq!(
            handle_event(&db, &stripe, &s, &refunded, NOW + DAY)
                .await
                .unwrap(),
            EventOutcome::Processed
        );
        let m = db.fetch_cipher_membership("u1").await.unwrap().unwrap();
        assert!(!m.is_active());
        assert_eq!(
            db.fetch_cipher_number_by_order("o_part").await.unwrap(),
            Some(number)
        );
        assert_eq!(badge(&db).await, None);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn the_sweep_finishes_a_release_whose_event_never_returns() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        paid_member(&db, "o_strand", "pi_strand", NOW).await;

        // A worker recorded the release and died; the event was settled
        // by then, so nothing will deliver it again
        assert!(db
            .mark_cipher_number_release("o_strand", NOW + DAY)
            .await
            .unwrap());

        reconcile(&db, &stripe, &s, NOW + DAY + MINUTE)
            .await
            .unwrap();
        assert_eq!(db.fetch_cipher_membership("u1").await.unwrap(), None);
        assert_eq!(
            db.fetch_cipher_number_by_order("o_strand").await.unwrap(),
            None
        );
        assert_eq!(
            db.fetch_payment_order("o_strand")
                .await
                .unwrap()
                .unwrap()
                .state,
            OrderState::Refunded
        );
        assert!(db
            .fetch_cipher_numbers_release_pending(10)
            .await
            .unwrap()
            .is_empty());
        drop_db(&db).await;
    }
}
