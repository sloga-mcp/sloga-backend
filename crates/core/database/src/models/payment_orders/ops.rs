pub mod mongodb;
pub mod reference;

use revolt_result::Result;

use crate::{OrderState, PaymentOrder};

#[async_trait]
pub trait AbstractPaymentOrders: Sync + Send {
    /// Insert a new order (a duplicate id is an error)
    async fn insert_payment_order(&self, o: &PaymentOrder) -> Result<()>;

    /// Fetch an order by id
    async fn fetch_payment_order(&self, id: &str) -> Result<Option<PaymentOrder>>;

    /// Fetch the order a checkout session belongs to
    async fn fetch_payment_order_by_session(
        &self,
        session_id: &str,
    ) -> Result<Option<PaymentOrder>>;

    /// Fetch the order a payment intent belongs to
    async fn fetch_payment_order_by_intent(
        &self,
        payment_intent_id: &str,
    ) -> Result<Option<PaymentOrder>>;

    /// Orders of a user in any of `states`, oldest `created_at` first
    async fn fetch_payment_orders_by_user(
        &self,
        user_id: &str,
        states: &[OrderState],
    ) -> Result<Vec<PaymentOrder>>;

    /// Orders in any of `states` with `created_at < before`, oldest
    /// `created_at` first, up to `limit` (0 = no limit)
    async fn fetch_payment_orders_by_state(
        &self,
        states: &[OrderState],
        before: i64,
        limit: i64,
    ) -> Result<Vec<PaymentOrder>>;

    /// Orders with `reversal_pending` set whose lease is free (`lease_until`
    /// unset or `< now`), oldest `created_at` first, up to `limit`
    /// (0 = no limit)
    async fn fetch_payment_orders_reversal_pending(
        &self,
        now: i64,
        limit: i64,
    ) -> Result<Vec<PaymentOrder>>;

    /// Atomically set `lease_until = until` WHERE `_id = id` AND
    /// (`lease_until` unset OR `lease_until < now`).
    /// Ok(Some(order_after)) if acquired, Ok(None) if held by someone else
    /// or no such order.
    async fn acquire_payment_order_lease(
        &self,
        id: &str,
        now: i64,
        until: i64,
    ) -> Result<Option<PaymentOrder>>;

    /// Unset `lease_until`; a missing order is not an error
    async fn release_payment_order_lease(&self, id: &str) -> Result<()>;

    /// Conditional replace: write `o` in full WHERE `_id = o.id` AND
    /// `state = expected`.
    /// Ok(true) if matched and written, Ok(false) if the state differed or
    /// the order does not exist. `lease_until` is written as `o` carries it,
    /// so a lease holder writing the order it acquired keeps its lease.
    async fn update_payment_order_if_state(
        &self,
        o: &PaymentOrder,
        expected: OrderState,
    ) -> Result<bool>;

    /// Account deletion: unset `user_id` on every order of the user
    async fn unlink_payment_orders_by_user(&self, user_id: &str) -> Result<()>;
}
