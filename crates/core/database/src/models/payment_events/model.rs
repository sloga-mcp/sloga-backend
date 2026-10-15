auto_derived!(
    /// Where a received provider event stands
    pub enum PaymentEventState {
        /// Stored, not yet handled (or handling is in flight)
        Received,
        /// Handled; a redelivery is answered without acting again
        Processed,
        /// Not ours or not relevant (unknown type, livemode mismatch,
        /// a payment intent that belongs to no order)
        Ignored,
        /// Handling failed; the reconcile sweep re-drives it by id
        Failed,
    }

    /// A Stripe webhook event, recorded for idempotency and re-drive.
    /// Only the id and envelope are kept: the payload is fetched again
    /// from Stripe on re-drive, so no buyer details are stored here.
    /// Timestamps are epoch milliseconds.
    pub struct PaymentEvent {
        /// Stripe event id
        #[serde(rename = "_id")]
        pub id: String,
        /// Stripe event type, e.g. `checkout.session.completed`
        pub event_type: String,
        /// Whether Stripe sent this event in live mode
        pub livemode: bool,
        /// Epoch ms the event was first received
        pub received_at: i64,
        /// Handling state
        pub state: PaymentEventState,
        /// How many times handling has finished (successfully or not)
        pub attempts: u32,
        /// Error from the last failed attempt
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub last_error: Option<String>,
    }
);
