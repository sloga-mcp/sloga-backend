use revolt_result::Result;

use crate::ReferenceDb;
use crate::{PaymentEvent, PaymentEventState};

use super::AbstractPaymentEvents;

#[async_trait]
impl AbstractPaymentEvents for ReferenceDb {
    async fn insert_payment_event_if_absent(&self, e: &PaymentEvent) -> Result<bool> {
        let mut events = self.payment_events.lock().await;
        if events.contains_key(&e.id) {
            Ok(false)
        } else {
            events.insert(e.id.clone(), e.clone());
            Ok(true)
        }
    }

    async fn fetch_payment_event(&self, id: &str) -> Result<Option<PaymentEvent>> {
        let events = self.payment_events.lock().await;
        Ok(events.get(id).cloned())
    }

    async fn set_payment_event_state(
        &self,
        id: &str,
        state: PaymentEventState,
        last_error: Option<String>,
    ) -> Result<()> {
        let mut events = self.payment_events.lock().await;
        match events.get_mut(id) {
            Some(row) => {
                row.state = state;
                row.attempts = row.attempts.saturating_add(1);
                row.last_error = last_error;
                Ok(())
            }
            None => Err(create_error!(NotFound)),
        }
    }

    async fn fetch_failed_payment_events(
        &self,
        max_attempts: u32,
        limit: i64,
    ) -> Result<Vec<PaymentEvent>> {
        let events = self.payment_events.lock().await;
        let rows: Vec<PaymentEvent> = events
            .values()
            .filter(|row| {
                matches!(row.state, PaymentEventState::Failed) && row.attempts < max_attempts
            })
            .cloned()
            .collect();
        Ok(oldest_first(rows, limit))
    }

    async fn fetch_payment_events_by_state(
        &self,
        state: PaymentEventState,
        before: i64,
        limit: i64,
    ) -> Result<Vec<PaymentEvent>> {
        let events = self.payment_events.lock().await;
        let rows: Vec<PaymentEvent> = events
            .values()
            .filter(|row| row.state == state && row.received_at < before)
            .cloned()
            .collect();
        Ok(oldest_first(rows, limit))
    }
}

/// Oldest `received_at` first, ties by id, as the Mongo sort; then the
/// same limit as Mongo: 0 is no limit, a negative value its magnitude
fn oldest_first(mut rows: Vec<PaymentEvent>, limit: i64) -> Vec<PaymentEvent> {
    rows.sort_by(|a, b| {
        a.received_at
            .cmp(&b.received_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    if limit != 0 {
        rows.truncate(limit.unsigned_abs().try_into().unwrap_or(usize::MAX));
    }
    rows
}
