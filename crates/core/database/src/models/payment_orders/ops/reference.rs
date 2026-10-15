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
        now: i64,
        limit: i64,
    ) -> Result<Vec<PaymentOrder>> {
        let orders = self.payment_orders.lock().await;
        let mut rows: Vec<PaymentOrder> = orders
            .values()
            .filter(|row| row.reversal_pending.is_some() && lease_free(row, now))
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
                row.lease_until = Some(until);
                Ok(Some(row.clone()))
            }
            _ => Ok(None),
        }
    }

    async fn release_payment_order_lease(&self, id: &str) -> Result<()> {
        let mut orders = self.payment_orders.lock().await;
        if let Some(row) = orders.get_mut(id) {
            row.lease_until = None;
        }
        Ok(())
    }

    async fn update_payment_order_if_state(
        &self,
        o: &PaymentOrder,
        expected: OrderState,
    ) -> Result<bool> {
        let mut orders = self.payment_orders.lock().await;
        if !orders.get(&o.id).is_some_and(|row| row.state == expected) {
            return Ok(false);
        }
        // Mongo rejects a replacement that collides on a unique index
        if provider_id_taken(&orders, o) {
            return Err(create_database_error!("replace", "payment_order"));
        }
        orders.insert(o.id.clone(), o.clone());
        Ok(true)
    }

    async fn unlink_payment_orders_by_user(&self, user_id: &str) -> Result<()> {
        let mut orders = self.payment_orders.lock().await;
        for row in orders.values_mut() {
            if row.user_id.as_deref() == Some(user_id) {
                row.user_id = None;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use revolt_models::v0;

    use crate::{
        Database, OrderState, PaymentOrder, PaymentProvider, ReferenceDb, ReversalPending,
    };

    fn order(id: &str, user_id: &str, state: OrderState, created_at: i64) -> PaymentOrder {
        PaymentOrder {
            id: id.to_string(),
            user_id: Some(user_id.to_string()),
            provider: PaymentProvider::Stripe,
            sku: v0::Sku::CipherNew {
                tier: v0::CipherTier::T149,
            },
            amount_cents: 14900,
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
        }
    }

    fn ids(rows: Vec<PaymentOrder>) -> Vec<String> {
        rows.into_iter().map(|row| row.id).collect()
    }

    #[tokio::test]
    async fn only_one_worker_holds_the_lease_until_it_runs_out() {
        // Always the in-memory driver: this test never touches MongoDB
        let db = Database::Reference(ReferenceDb::default());
        db.insert_payment_order(&order("o1", "u1", OrderState::Pending, 10))
            .await
            .unwrap();

        let leased = db
            .acquire_payment_order_lease("o1", 1_000, 121_000)
            .await
            .unwrap()
            .expect("a free lease is acquired");
        // The holder gets the document after the write
        assert_eq!(leased.lease_until, Some(121_000));

        // Held: a second worker gets nothing, and the lease is unchanged
        assert!(db
            .acquire_payment_order_lease("o1", 2_000, 122_000)
            .await
            .unwrap()
            .is_none());
        // Exactly at `until` the lease still holds (`lease_until < now`)
        assert!(db
            .acquire_payment_order_lease("o1", 121_000, 241_000)
            .await
            .unwrap()
            .is_none());
        // Run out: taken over
        assert_eq!(
            db.acquire_payment_order_lease("o1", 121_001, 241_001)
                .await
                .unwrap()
                .unwrap()
                .lease_until,
            Some(241_001)
        );

        // Released: free again at any time
        db.release_payment_order_lease("o1").await.unwrap();
        assert!(db
            .fetch_payment_order("o1")
            .await
            .unwrap()
            .unwrap()
            .lease_until
            .is_none());
        assert!(db
            .acquire_payment_order_lease("o1", 0, 120_000)
            .await
            .unwrap()
            .is_some());

        // Unknown orders are never created by a lease
        assert!(db
            .acquire_payment_order_lease("missing", 0, 120_000)
            .await
            .unwrap()
            .is_none());
        db.release_payment_order_lease("missing").await.unwrap();
        assert!(db.fetch_payment_order("missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_conditional_update_never_overwrites_a_newer_state() {
        let db = Database::Reference(ReferenceDb::default());
        let pending = order("o1", "u1", OrderState::Pending, 10);
        db.insert_payment_order(&pending).await.unwrap();

        let paid = PaymentOrder {
            state: OrderState::Paid,
            payment_intent_id: Some("pi_1".to_string()),
            paid_at: Some(20),
            ..pending.clone()
        };
        assert!(db
            .update_payment_order_if_state(&paid, OrderState::Pending)
            .await
            .unwrap());

        // A stale writer that still believes the order is Pending loses
        let expired = PaymentOrder {
            state: OrderState::Expired,
            ..pending.clone()
        };
        assert!(!db
            .update_payment_order_if_state(&expired, OrderState::Pending)
            .await
            .unwrap());
        assert_eq!(db.fetch_payment_order("o1").await.unwrap(), Some(paid));

        // No upsert
        let ghost = order("ghost", "u1", OrderState::Paid, 10);
        assert!(!db
            .update_payment_order_if_state(&ghost, OrderState::Pending)
            .await
            .unwrap());
        assert!(db.fetch_payment_order("ghost").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn provider_ids_are_unique_across_orders() {
        let db = Database::Reference(ReferenceDb::default());
        let first = PaymentOrder {
            checkout_session_id: Some("cs_1".to_string()),
            payment_intent_id: Some("pi_1".to_string()),
            ..order("o1", "u1", OrderState::Paid, 10)
        };
        db.insert_payment_order(&first).await.unwrap();
        // Unset ids never collide
        db.insert_payment_order(&order("o2", "u1", OrderState::Creating, 20))
            .await
            .unwrap();
        db.insert_payment_order(&order("o3", "u2", OrderState::Creating, 30))
            .await
            .unwrap();

        // Duplicate id, or a session already owned by another order
        assert!(db.insert_payment_order(&first).await.is_err());
        assert!(db
            .insert_payment_order(&PaymentOrder {
                checkout_session_id: Some("cs_1".to_string()),
                ..order("o4", "u2", OrderState::Pending, 40)
            })
            .await
            .is_err());

        // Moving another order onto the same intent is refused
        let stolen = PaymentOrder {
            state: OrderState::Paid,
            payment_intent_id: Some("pi_1".to_string()),
            ..order("o2", "u1", OrderState::Creating, 20)
        };
        assert!(db
            .update_payment_order_if_state(&stolen, OrderState::Creating)
            .await
            .is_err());

        assert_eq!(
            db.fetch_payment_order_by_session("cs_1")
                .await
                .unwrap()
                .map(|row| row.id),
            Some("o1".to_string())
        );
        assert_eq!(
            db.fetch_payment_order_by_intent("pi_1")
                .await
                .unwrap()
                .map(|row| row.id),
            Some("o1".to_string())
        );
        assert!(db
            .fetch_payment_order_by_intent("pi_missing")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn sweeps_select_by_state_age_and_reversal() {
        let db = Database::Reference(ReferenceDb::default());
        for row in [
            order("newer", "u1", OrderState::Pending, 30),
            order("older", "u2", OrderState::Creating, 10),
            order("middle", "u1", OrderState::SessionFailed, 20),
            // Too young for the cutoff
            order("young", "u1", OrderState::Pending, 100),
            // Not one of the swept states
            order("done", "u1", OrderState::Fulfilled, 5),
            PaymentOrder {
                reversal_pending: Some(ReversalPending::Refund),
                ..order("rev_free", "u3", OrderState::Paid, 50)
            },
            PaymentOrder {
                reversal_pending: Some(ReversalPending::DisputeLost),
                lease_until: Some(1_000),
                ..order("rev_held", "u3", OrderState::Fulfilled, 40)
            },
            PaymentOrder {
                reversal_pending: Some(ReversalPending::Refund),
                lease_until: Some(400),
                ..order("rev_lapsed", "u3", OrderState::Paid, 60)
            },
        ] {
            db.insert_payment_order(&row).await.unwrap();
        }

        let swept = [
            OrderState::Creating,
            OrderState::SessionFailed,
            OrderState::Pending,
        ];
        assert_eq!(
            ids(db
                .fetch_payment_orders_by_state(&swept, 99, 0)
                .await
                .unwrap()),
            ["older", "middle", "newer"]
        );
        assert_eq!(
            ids(db
                .fetch_payment_orders_by_state(&swept, 99, 2)
                .await
                .unwrap()),
            ["older", "middle"]
        );
        assert!(db
            .fetch_payment_orders_by_state(&[], 1_000, 0)
            .await
            .unwrap()
            .is_empty());

        // Free leases only: unset, or run out before `now`
        assert_eq!(
            ids(db
                .fetch_payment_orders_reversal_pending(500, 0)
                .await
                .unwrap()),
            ["rev_free", "rev_lapsed"]
        );
        assert_eq!(
            ids(db
                .fetch_payment_orders_reversal_pending(1_001, 0)
                .await
                .unwrap()),
            ["rev_held", "rev_free", "rev_lapsed"]
        );
        assert_eq!(
            ids(db
                .fetch_payment_orders_reversal_pending(1_001, 1)
                .await
                .unwrap()),
            ["rev_held"]
        );

        assert_eq!(
            ids(db
                .fetch_payment_orders_by_user("u1", &[OrderState::Pending, OrderState::Fulfilled])
                .await
                .unwrap()),
            ["done", "newer", "young"]
        );
    }

    #[tokio::test]
    async fn account_deletion_unlinks_only_that_users_orders() {
        let db = Database::Reference(ReferenceDb::default());
        db.insert_payment_order(&order("mine", "u1", OrderState::Fulfilled, 10))
            .await
            .unwrap();
        db.insert_payment_order(&order("theirs", "u2", OrderState::Fulfilled, 20))
            .await
            .unwrap();

        db.unlink_payment_orders_by_user("u1").await.unwrap();

        let mine = db.fetch_payment_order("mine").await.unwrap().unwrap();
        assert!(mine.user_id.is_none());
        // The order itself stays (it is the payment record)
        assert_eq!(mine.state, OrderState::Fulfilled);
        assert_eq!(
            db.fetch_payment_order("theirs")
                .await
                .unwrap()
                .unwrap()
                .user_id
                .as_deref(),
            Some("u2")
        );
        assert!(db
            .fetch_payment_orders_by_user("u1", &[OrderState::Fulfilled])
            .await
            .unwrap()
            .is_empty());
    }
}
