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
}
