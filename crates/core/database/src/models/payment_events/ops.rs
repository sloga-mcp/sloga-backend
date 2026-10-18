pub mod mongodb;
pub mod reference;

use revolt_result::Result;

use crate::{PaymentEvent, PaymentEventState};

#[async_trait]
pub trait AbstractPaymentEvents: Sync + Send {
    /// Insert an event unless a row with the same id already exists;
    /// Ok(true) if it was inserted, Ok(false) if a row with this id exists
    async fn insert_payment_event_if_absent(&self, e: &PaymentEvent) -> Result<bool>;

    /// Fetch an event by its Stripe event id
    async fn fetch_payment_event(&self, id: &str) -> Result<Option<PaymentEvent>>;

    /// Set the state, bump `attempts` by 1, and set `last_error` (or clear
    /// it when `None`); NotFound if no row has this id
    async fn set_payment_event_state(
        &self,
        id: &str,
        state: PaymentEventState,
        last_error: Option<String>,
    ) -> Result<()>;

    /// Failed rows with `attempts < max_attempts`, oldest `received_at`
    /// first, up to `limit` (0 = no limit)
    async fn fetch_failed_payment_events(
        &self,
        max_attempts: u32,
        limit: i64,
    ) -> Result<Vec<PaymentEvent>>;

    /// Rows in `state` with `received_at < before`, oldest `received_at`
    /// first, up to `limit` (0 = no limit). Finds Received rows stranded
    /// by a crash between the insert and the state update.
    async fn fetch_payment_events_by_state(
        &self,
        state: PaymentEventState,
        before: i64,
        limit: i64,
    ) -> Result<Vec<PaymentEvent>>;
}

#[cfg(test)]
mod tests {
    use crate::{PaymentEvent, PaymentEventState};

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

    fn ids(rows: Vec<PaymentEvent>) -> Vec<String> {
        rows.into_iter().map(|row| row.id).collect()
    }

    #[tokio::test]
    async fn a_redelivered_event_is_not_inserted_twice() {
        database_test!(|db| async move {
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
        });
    }

    #[tokio::test]
    async fn state_changes_count_attempts_and_set_or_clear_the_error() {
        database_test!(|db| async move {
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
        });
    }

    #[tokio::test]
    async fn failed_events_come_back_oldest_first_below_the_attempt_cap() {
        database_test!(|db| async move {
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
        });
    }

    #[tokio::test]
    async fn stranded_events_come_back_by_state_oldest_first_before_the_cutoff() {
        database_test!(|db| async move {
            for row in [
                event("evt_newer", 30, PaymentEventState::Received, 0),
                event("evt_older", 10, PaymentEventState::Received, 0),
                event("evt_middle", 20, PaymentEventState::Received, 0),
                // Same instant: ties break by id
                event("evt_middle_b", 20, PaymentEventState::Received, 0),
                // Too young: its handler may still be running
                event("evt_young", 100, PaymentEventState::Received, 0),
                // Other states
                event("evt_failed", 1, PaymentEventState::Failed, 1),
                event("evt_done", 2, PaymentEventState::Processed, 1),
                event("evt_ignored", 3, PaymentEventState::Ignored, 1),
            ] {
                assert!(db.insert_payment_event_if_absent(&row).await.unwrap());
            }

            assert_eq!(
                ids(db
                    .fetch_payment_events_by_state(PaymentEventState::Received, 99, 0)
                    .await
                    .unwrap()),
                ["evt_older", "evt_middle", "evt_middle_b", "evt_newer"]
            );
            assert_eq!(
                ids(db
                    .fetch_payment_events_by_state(PaymentEventState::Received, 99, 2)
                    .await
                    .unwrap()),
                ["evt_older", "evt_middle"]
            );
            // The cutoff is strict
            assert_eq!(
                ids(db
                    .fetch_payment_events_by_state(PaymentEventState::Received, 20, 0)
                    .await
                    .unwrap()),
                ["evt_older"]
            );
            assert_eq!(
                ids(db
                    .fetch_payment_events_by_state(PaymentEventState::Failed, 99, 0)
                    .await
                    .unwrap()),
                ["evt_failed"]
            );
            assert!(db
                .fetch_payment_events_by_state(PaymentEventState::Received, 10, 0)
                .await
                .unwrap()
                .is_empty());
        });
    }
}
