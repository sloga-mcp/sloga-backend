use revolt_models::v0;

auto_derived!(
    /// Who takes the payment for an order
    pub enum PaymentProvider {
        /// Stripe Checkout
        Stripe,
    }

    /// Where a payment order stands
    pub enum OrderState {
        /// Stored; the checkout session is being created
        Creating,
        /// Checkout session created, waiting for the buyer to pay
        Pending,
        /// Creating the checkout session failed; never payable
        SessionFailed,
        /// Paid; fulfilment has not finished yet
        Paid,
        /// Paid and fulfilled
        Fulfilled,
        /// The checkout session expired unpaid
        Expired,
        /// Fulfilled, then reversed by a refund or a lost dispute
        Refunded,
        /// Paid but not fulfilled; the payment was refunded (see `void_reason`)
        Voided,
    }

    /// Why a paid order was voided instead of fulfilled
    pub enum VoidReason {
        /// No Cipher number was left to claim
        SoldOut,
        /// The order no longer applies (e.g. an upgrade from a tier the
        /// buyer no longer holds, or a new purchase by an existing member)
        Stale,
        /// Created after the sale closed
        SalesClosed,
        /// An upgrade while a payment of the membership is under dispute
        DisputeOpen,
        /// The buyer deleted their account before fulfilment
        AccountDeleted,
        /// Our own session was paid, but not in the order's amount or
        /// currency
        AmountMismatch,
        /// A refund or a lost dispute arrived before fulfilment applied the
        /// order, so it was never applied
        Reversed,
        /// A new purchase paid while the release of the buyer's previous
        /// Cipher number (a refund within the 14 days) was still running
        ReleasePending,
        /// The buyer's billing country, or their card's issuing country, is
        /// one Cipher is not sold to (`[features.payments]
        /// cipher_blocked_countries`); the country is kept in
        /// `region_blocked_country`
        RegionUnavailable,
    }

    /// A reversal that arrived before fulfilment finished; fulfilment
    /// applies it as its last step
    pub enum ReversalPending {
        /// The payment was refunded
        Refund,
        /// A dispute on the payment was lost
        DisputeLost,
    }

    /// A purchase, from checkout to fulfilment or reversal.
    /// Timestamps are epoch milliseconds.
    ///
    /// Every optional field is left out of the stored document when unset
    /// (never written as null): the partial unique indexes on
    /// `checkout_session_id` and `payment_intent_id` only skip a row when
    /// the field is absent or not a string, and the lease and reversal
    /// queries rely on `$exists`.
    pub struct PaymentOrder {
        /// Order id (ULID)
        #[serde(rename = "_id")]
        pub id: String,
        /// Buyer; unset when the buyer deletes their account
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub user_id: Option<String>,
        /// Payment provider
        pub provider: PaymentProvider,
        /// What the order buys
        pub sku: v0::Sku,
        /// Price in the smallest unit of `currency`
        pub amount_cents: i64,
        /// Lowercase ISO currency code ("usd")
        pub currency: String,
        /// Provider checkout session id, once created
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub checkout_session_id: Option<String>,
        /// Hosted checkout URL, once created
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub checkout_url: Option<String>,
        /// Epoch ms at which the checkout session expires
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub session_expires_at: Option<i64>,
        /// Provider payment intent id, set when the order becomes Paid
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub payment_intent_id: Option<String>,
        /// Order state
        pub state: OrderState,
        /// Why the order was voided (only on Voided)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub void_reason: Option<VoidReason>,
        /// The country (ISO 3166-1 alpha-2, as Stripe reported it) a
        /// `RegionUnavailable` void was for: the billing country, or the
        /// card's issuing country. Checkout refuses the buyer again only
        /// while that country is still blocked. Unset on every other order,
        /// and on a void recorded before the field existed.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub region_blocked_country: Option<String>,
        /// A reversal still to be applied once fulfilment finishes
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub reversal_pending: Option<ReversalPending>,
        /// Epoch ms a refund of the payment was first seen still settling
        /// (`pending` or `requires_action` at the provider). Set until the
        /// refund is acted on, or until every refund failed; the reconcile
        /// sweep re-reads the refunds of every order that carries it, so a
        /// refund whose update event never arrives is still applied.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub refund_settling_since: Option<i64>,
        /// Provider ids of the disputes open on the payment. One payment can
        /// carry more than one (an inquiry closed `warning_closed`, then a
        /// chargeback), so each dispute is added and removed by its own id.
        /// Changed under the lease in every state before fulfilment as well
        /// as after it. While it is non-empty the order is listed in the
        /// membership's `disputed_orders` (fulfilment lists it in the same
        /// write that adds it), so no badge is published. Left out of the
        /// stored document when empty (absent reads empty).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub open_disputes: Vec<String>,
        /// Epoch ms until which a worker holds this order; unset when free
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub lease_until: Option<i64>,
        /// Optimistic-concurrency counter, bumped by every
        /// `update_payment_order_if_state`, `acquire_payment_order_lease` and
        /// `unlink_payment_orders_by_user`; an order stored before the field
        /// existed reads as 0. Stored as Int64 (bson refuses a u64 above
        /// `i64::MAX`, so such a write fails instead of wrapping).
        #[serde(default)]
        pub version: u64,
        /// Epoch ms the order was created
        pub created_at: i64,
        /// Epoch ms the payment was confirmed
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub paid_at: Option<i64>,
        /// Epoch ms the order was fulfilled
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub fulfilled_at: Option<i64>,
        /// Epoch ms the order was refunded or voided
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub reversed_at: Option<i64>,
    }
);
