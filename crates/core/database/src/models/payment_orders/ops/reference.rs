use std::collections::HashMap;

use revolt_result::Result;

use crate::ReferenceDb;
use crate::{OrderState, PaymentOrder};

use super::AbstractPaymentOrders;

/// Whether the lease on `row` is free at `now` (never taken, or run out)
fn lease_free(row: &PaymentOrder, now: i64) -> bool {
    match row.lease_until {
        None => true,
        Some(until) => until < now,
    }
}

/// Same as a Mongo limit: 0 is no limit, a negative value its magnitude
fn apply_limit(rows: &mut Vec<PaymentOrder>, limit: i64) {
    if limit != 0 {
        rows.truncate(limit.unsigned_abs().try_into().unwrap_or(usize::MAX));
    }
}

/// Oldest `created_at` first, ties by id, as the Mongo sort
fn sort_oldest_first(rows: &mut [PaymentOrder]) {
    rows.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
}

/// Stand-in for the partial unique indexes on `checkout_session_id` and
/// `payment_intent_id`: true if an order other than `o` already holds
/// either id
fn provider_id_taken(orders: &HashMap<String, PaymentOrder>, o: &PaymentOrder) -> bool {
    orders.values().any(|row| {
        row.id != o.id
            && ((o.checkout_session_id.is_some()
                && row.checkout_session_id == o.checkout_session_id)
                || (o.payment_intent_id.is_some() && row.payment_intent_id == o.payment_intent_id))
    })
}

#[async_trait]
impl AbstractPaymentOrders for ReferenceDb {
    async fn insert_payment_order(&self, o: &PaymentOrder) -> Result<()> {
        let mut orders = self.payment_orders.lock().await;
        if orders.contains_key(&o.id) || provider_id_taken(&orders, o) {
            Err(create_database_error!("insert", "payment_order"))
        } else {
            orders.insert(o.id.clone(), o.clone());
            Ok(())
        }
    }

    async fn fetch_payment_order(&self, id: &str) -> Result<Option<PaymentOrder>> {
        let orders = self.payment_orders.lock().await;
        Ok(orders.get(id).cloned())
    }

    async fn fetch_payment_order_by_session(
        &self,
        session_id: &str,
    ) -> Result<Option<PaymentOrder>> {
        let orders = self.payment_orders.lock().await;
        Ok(orders
            .values()
            .find(|row| row.checkout_session_id.as_deref() == Some(session_id))
            .cloned())
    }

    async fn fetch_payment_order_by_intent(
        &self,
        payment_intent_id: &str,
    ) -> Result<Option<PaymentOrder>> {
        let orders = self.payment_orders.lock().await;
        Ok(orders
            .values()
            .find(|row| row.payment_intent_id.as_deref() == Some(payment_intent_id))
            .cloned())
    }

    async fn fetch_payment_orders_by_user(
        &self,
        user_id: &str,
        states: &[OrderState],
    ) -> Result<Vec<PaymentOrder>> {
        let orders = self.payment_orders.lock().await;
        let mut rows: Vec<PaymentOrder> = orders
            .values()
            .filter(|row| row.user_id.as_deref() == Some(user_id) && states.contains(&row.state))
            .cloned()
            .collect();
        sort_oldest_first(&mut rows);
        Ok(rows)
    }

    async fn fetch_payment_orders_by_state(
        &self,
        states: &[OrderState],
        before: i64,
        limit: i64,
    ) -> Result<Vec<PaymentOrder>> {
        let orders = self.payment_orders.lock().await;
        let mut rows: Vec<PaymentOrder> = orders
            .values()
            .filter(|row| states.contains(&row.state) && row.created_at < before)
            .cloned()
            .collect();
        sort_oldest_first(&mut rows);
        apply_limit(&mut rows, limit);
        Ok(rows)
    }

    async fn fetch_payment_orders_reversal_pending(
        &self,
        states: &[OrderState],
        now: i64,
        limit: i64,
    ) -> Result<Vec<PaymentOrder>> {
        let orders = self.payment_orders.lock().await;
        let mut rows: Vec<PaymentOrder> = orders
            .values()
            .filter(|row| {
                states.contains(&row.state)
                    && row.reversal_pending.is_some()
                    && lease_free(row, now)
            })
            .cloned()
            .collect();
        sort_oldest_first(&mut rows);
        apply_limit(&mut rows, limit);
        Ok(rows)
    }

    async fn acquire_payment_order_lease(
        &self,
        id: &str,
        now: i64,
        until: i64,
    ) -> Result<Option<PaymentOrder>> {
        // The check and the write run while the map mutex is held, which is
        // this driver's equivalent of Mongo's single-document
        // find_one_and_update
        let mut orders = self.payment_orders.lock().await;
        match orders.get_mut(id) {
            Some(row) if lease_free(row, now) => {
                // Same as the Mongo `$inc`: taking a lease moves the version
                row.version = row
                    .version
                    .checked_add(1)
                    .ok_or_else(|| create_database_error!("update", "payment_order"))?;
                row.lease_until = Some(until);
                Ok(Some(row.clone()))
            }
            _ => Ok(None),
        }
    }

    async fn release_payment_order_lease(&self, id: &str, until: i64) -> Result<()> {
        let mut orders = self.payment_orders.lock().await;
        // Fenced on the holder's own token: a stale release is a no-op
        if let Some(row) = orders.get_mut(id) {
            if row.lease_until == Some(until) {
                row.lease_until = None;
            }
        }
        Ok(())
    }

    async fn update_payment_order_if_state(
        &self,
        o: &PaymentOrder,
        expected: OrderState,
    ) -> Result<bool> {
        let next = o
            .version
            .checked_add(1)
            .ok_or_else(|| create_database_error!("replace", "payment_order"))?;

        let mut orders = self.payment_orders.lock().await;
        // Same filter as the Mongo driver: the state, the version (this
        // driver has no absent field; an order always reads as at least 0),
        // the lease as a fencing token (a taken-over holder carries the old
        // `lease_until`), and the buyer (an account-deletion unlink is never
        // undone)
        if !orders.get(&o.id).is_some_and(|row| {
            row.state == expected
                && row.version == o.version
                && row.lease_until == o.lease_until
                && row.user_id == o.user_id
        }) {
            return Ok(false);
        }
        // Mongo rejects a replacement that collides on a unique index
        if provider_id_taken(&orders, o) {
            return Err(create_database_error!("replace", "payment_order"));
        }
        orders.insert(
            o.id.clone(),
            PaymentOrder {
                version: next,
                ..o.clone()
            },
        );
        Ok(true)
    }

    async fn unlink_payment_orders_by_user(&self, user_id: &str) -> Result<()> {
        let mut orders = self.payment_orders.lock().await;
        for row in orders.values_mut() {
            if row.user_id.as_deref() == Some(user_id) {
                // Same as the Mongo `$inc`: a copy read before the unlink
                // can no longer write
                row.version = row
                    .version
                    .checked_add(1)
                    .ok_or_else(|| create_database_error!("update", "payment_order"))?;
                row.user_id = None;
            }
        }
        Ok(())
    }
}
