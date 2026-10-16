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
//! later `created` re-opening a dispute that is already over. Applying where
//! the dispute is now, through idempotent engine reversals, makes every
//! delivery order converge. A failed lookup is a retry, never a guess.
use log::{info, warn};
use revolt_database::{Database, OrderState, PaymentEvent, PaymentEventState, ReversalPending};
use revolt_result::{Error, Result};

use crate::engine::{self, FulfilOutcome, ReverseKind, ReverseOutcome};
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

/// Upper bound on the rows each part of one sweep looks at
const SWEEP_BATCH: i64 = 50;

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
fn dispute_kind(status: Option<&str>) -> ReverseKind {
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

            match engine::reverse_order(db, stripe, s, &order_id, kind, now_ms).await {
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

            // Where the dispute is now, not what this delivery says
            let Some(dispute_id) = obj_str(&event.object, "id") else {
                return Step::Retry("dispute event has no dispute id".to_string());
            };
            let dispute = match stripe.get_dispute(dispute_id).await {
                Ok(dispute) => dispute,
                Err(error) => return Step::Retry(stripe_text("get_dispute", &error)),
            };
            if dispute.id != dispute_id {
                return Step::Retry("stripe returned a different dispute".to_string());
            }
            if dispute
                .payment_intent
                .as_deref()
                .is_some_and(|reported| reported != payment_intent)
            {
                return Step::Retry("stripe reports the dispute on another payment".to_string());
            }
            let kind = dispute_kind(dispute.status.as_deref());

            match engine::reverse_order(db, stripe, s, &order_id, kind, now_ms).await {
                Ok(outcome) => reverse_step(outcome),
                Err(error) => Step::Retry(engine_text("reverse", &error)),
            }
        }
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
}

impl Tally {
    fn summary(&self) -> String {
        format!(
            "expired={}, resumed={}, reversed={}, redriven={}, errors={}",
            self.expired, self.resumed, self.reversed, self.redriven, self.errors
        )
    }

    fn error(&mut self, what: &str, id: &str, reason: &str) {
        warn!("payments reconcile: {what} {id}: {reason}");
        self.errors += 1;
    }
}

/// The crond sweep (plan "crond payments_reconcile"), run every 10 minutes:
///
/// 1. Creating / SessionFailed orders older than 10 min → Expired
/// 2. Pending orders older than 40 min, checked against Stripe: complete and
///    paid → fulfil; expired → Expired; open → left alone
/// 3. Paid orders whose lease is free (a fulfilment that crashed or gave up)
///    → resumed
/// 4. Fulfilled orders with a reversal still pending → reversed
/// 5. Failed events (fewer than 10 attempts) and Received events older than
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

    expire_unpaid(db, now_ms, &mut tally).await;
    check_pending(db, stripe, s, now_ms, &mut tally).await;
    resume_paid(db, stripe, s, now_ms, &mut tally).await;
    apply_pending_reversals(db, stripe, s, now_ms, &mut tally).await;
    redrive_events(db, stripe, s, now_ms, &mut tally).await;

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
        // Someone else holds the order, or there was nothing to do
        FulfilOutcome::LeaseHeld | FulfilOutcome::NotPaid | FulfilOutcome::Ignored => {}
    }
}

async fn apply_pending_reversals(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    now_ms: i64,
    tally: &mut Tally,
) {
    let orders = match db
        .fetch_payment_orders_reversal_pending(now_ms, SWEEP_BATCH)
        .await
    {
        Ok(orders) => orders,
        Err(error) => {
            return tally.error("query", "pending reversals", &engine_text("fetch", &error))
        }
    };

    for order in orders {
        // Paid orders are resumed above and fulfilment applies the reversal
        // as its last step; Pending ones wait for payment; terminal ones
        // have nothing left to reverse
        if order.state != OrderState::Fulfilled {
            continue;
        }
        let Some(pending) = order.reversal_pending.as_ref() else {
            continue;
        };
        let kind = match pending {
            ReversalPending::Refund => ReverseKind::Refund,
            ReversalPending::DisputeLost => ReverseKind::DisputeLost,
        };

        match engine::reverse_order(db, stripe, s, &order.id, kind, now_ms).await {
            Ok(ReverseOutcome::Applied) => tally.reversed += 1,
            Ok(ReverseOutcome::RecordedPending | ReverseOutcome::NoOp | ReverseOutcome::Busy) => {}
            Err(error) => tally.error("order", &order.id, &engine_text("reverse", &error)),
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

    use super::{action_for, dispute_kind, handle_event, reconcile, Action, EventOutcome};
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
}
