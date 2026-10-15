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
        let mut rows: Vec<PaymentEvent> = events
            .values()
            .filter(|row| {
                matches!(row.state, PaymentEventState::Failed) && row.attempts < max_attempts
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.received_at
                .cmp(&b.received_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        // Same as a Mongo limit: 0 is no limit, a negative value its magnitude
        if limit != 0 {
            rows.truncate(limit.unsigned_abs().try_into().unwrap_or(usize::MAX));
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Database, PaymentEvent, PaymentEventState, ReferenceDb};

    fn event(id: &str, received_at: i64, state: PaymentEventState, attempts: u32) -> PaymentEvent {
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

    #[tokio::test]
    async fn a_redelivered_event_is_not_inserted_twice() {
        // Always the in-memory driver: this test never touches MongoDB
        let db = Database::Reference(ReferenceDb::default());
        let first = event("evt_dup", 10, PaymentEventState::Received, 0);
        assert!(db.insert_payment_event_if_absent(&first).await.unwrap());

        // A redelivery must not reset the stored row
        db.set_payment_event_state("evt_dup", PaymentEventState::Processed, None)
            .await
            .unwrap();
        let again = event("evt_dup", 20, PaymentEventState::Received, 0);
        assert!(!db.insert_payment_event_if_absent(&again).await.unwrap());

        let stored = db.fetch_payment_event("evt_dup").await.unwrap().unwrap();
        assert_eq!(stored.state, PaymentEventState::Processed);
        assert_eq!(stored.received_at, 10);
        assert_eq!(stored.attempts, 1);
        assert!(db
            .fetch_payment_event("evt_missing")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn state_changes_count_attempts_and_set_or_clear_the_error() {
        let db = Database::Reference(ReferenceDb::default());
        let row = event("evt_state", 10, PaymentEventState::Received, 0);
        assert!(db.insert_payment_event_if_absent(&row).await.unwrap());

        db.set_payment_event_state(
            "evt_state",
            PaymentEventState::Failed,
            Some("stripe timeout".to_string()),
        )
        .await
        .unwrap();
        let stored = db.fetch_payment_event("evt_state").await.unwrap().unwrap();
        assert_eq!(stored.state, PaymentEventState::Failed);
        assert_eq!(stored.attempts, 1);
        assert_eq!(stored.last_error.as_deref(), Some("stripe timeout"));

        db.set_payment_event_state("evt_state", PaymentEventState::Processed, None)
            .await
            .unwrap();
        let stored = db.fetch_payment_event("evt_state").await.unwrap().unwrap();
        assert_eq!(stored.state, PaymentEventState::Processed);
        assert_eq!(stored.attempts, 2);
        assert!(stored.last_error.is_none());

        // An unknown id is an error, never a silent no-op
        assert!(db
            .set_payment_event_state("evt_missing", PaymentEventState::Processed, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn failed_events_come_back_oldest_first_below_the_attempt_cap() {
        let db = Database::Reference(ReferenceDb::default());
        for row in [
            event("evt_newer", 30, PaymentEventState::Failed, 1),
            event("evt_older", 10, PaymentEventState::Failed, 9),
            event("evt_middle", 20, PaymentEventState::Failed, 0),
            // At the cap: retired from re-drive
            event("evt_capped", 5, PaymentEventState::Failed, 10),
            // Not Failed
            event("evt_done", 1, PaymentEventState::Processed, 1),
            event("evt_ignored", 2, PaymentEventState::Ignored, 1),
            event("evt_received", 3, PaymentEventState::Received, 0),
        ] {
            assert!(db.insert_payment_event_if_absent(&row).await.unwrap());
        }

        let ids = |rows: Vec<PaymentEvent>| rows.into_iter().map(|row| row.id).collect::<Vec<_>>();

        assert_eq!(
            ids(db.fetch_failed_payment_events(10, 100).await.unwrap()),
            ["evt_older", "evt_middle", "evt_newer"]
        );
        assert_eq!(
            ids(db.fetch_failed_payment_events(10, 2).await.unwrap()),
            ["evt_older", "evt_middle"]
        );
        assert_eq!(
            ids(db.fetch_failed_payment_events(2, 100).await.unwrap()),
            ["evt_middle", "evt_newer"]
        );
        assert!(db
            .fetch_failed_payment_events(0, 100)
            .await
            .unwrap()
            .is_empty());
    }
}
