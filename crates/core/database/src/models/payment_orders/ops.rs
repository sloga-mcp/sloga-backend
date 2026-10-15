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
    /// `state = expected` AND
    /// - `lease_until` equals `o.lease_until` (`None`: the stored field
    ///   must be unset). This is the fencing token: a holder whose lease ran
    ///   out and was taken over carries the old value and cannot write.
    ///   Always write the order the lease call returned.
    /// - `user_id` equals `o.user_id` (`None`: the stored field must be
    ///   unset), so a writer that read the order before an account-deletion
    ///   unlink cannot put the buyer back.
    ///
    /// Ok(true) if matched and written, Ok(false) if the state, lease or
    /// buyer differed or the order does not exist. `lease_until` is written
    /// as `o` carries it, so a lease holder writing the order it acquired
    /// keeps its lease.
    async fn update_payment_order_if_state(
        &self,
        o: &PaymentOrder,
        expected: OrderState,
    ) -> Result<bool>;

    /// Account deletion: unset `user_id` on every order of the user
    async fn unlink_payment_orders_by_user(&self, user_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use revolt_models::v0;

    use crate::{OrderState, PaymentOrder, PaymentProvider, ReversalPending};

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

    /// Install the partial unique `checkout_session_id` and
    /// `payment_intent_id` indexes on MongoDB.
    ///
    /// `database_test!` connects to a fresh database with no migrations run.
    /// These specs MUST stay identical to the ones in
    /// `admin_migrations/ops/mongodb/scripts.rs` (`create_payment_indexes`).
    /// The reference driver enforces both in code, so it needs no setup.
    async fn create_payment_order_indexes(db: &crate::Database) {
        match db {
            crate::Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                mongo
                    .db()
                    .run_command(bson::doc! {
                        "createIndexes": "payment_orders",
                        "indexes": [
                            {
                                "key": { "checkout_session_id": 1_i32 },
                                "name": "payment_orders_session_unique",
                                "unique": true,
                                "partialFilterExpression": {
                                    "checkout_session_id": { "$type": "string" }
                                }
                            },
                            {
                                "key": { "payment_intent_id": 1_i32 },
                                "name": "payment_orders_intent_unique",
                                "unique": true,
                                "partialFilterExpression": {
                                    "payment_intent_id": { "$type": "string" }
                                }
                            }
                        ]
                    })
                    .await
                    .expect("failed to create payment_orders indexes");
            }
        }
    }

    #[tokio::test]
    async fn only_one_worker_holds_the_lease_until_it_runs_out() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
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
        });
    }

    #[tokio::test]
    async fn a_conditional_update_never_overwrites_a_newer_state() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
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
        });
    }

    #[tokio::test]
    async fn a_holder_whose_lease_was_taken_over_cannot_write() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
            db.insert_payment_order(&order("o1", "u1", OrderState::Pending, 10))
                .await
                .unwrap();

            // Worker A leases the order, then stalls past its lease
            let a = db
                .acquire_payment_order_lease("o1", 1_000, 2_000)
                .await
                .unwrap()
                .expect("A acquires");
            // Worker B takes the run-out lease over
            let b = db
                .acquire_payment_order_lease("o1", 2_001, 3_001)
                .await
                .unwrap()
                .expect("B takes over");

            // A wakes up and writes from its copy: the state still matches,
            // but its lease token is stale
            let a_paid = PaymentOrder {
                state: OrderState::Paid,
                paid_at: Some(2_500),
                ..a
            };
            assert!(!db
                .update_payment_order_if_state(&a_paid, OrderState::Pending)
                .await
                .unwrap());
            let stored = db.fetch_payment_order("o1").await.unwrap().unwrap();
            assert_eq!(stored.state, OrderState::Pending);
            assert_eq!(stored.lease_until, Some(3_001));

            // A writer with no lease cannot write over a held one either
            let unleased = PaymentOrder {
                state: OrderState::Expired,
                lease_until: None,
                ..stored.clone()
            };
            assert!(!db
                .update_payment_order_if_state(&unleased, OrderState::Pending)
                .await
                .unwrap());

            // The current holder writes, and keeps its lease
            let b_paid = PaymentOrder {
                state: OrderState::Paid,
                paid_at: Some(2_600),
                ..b
            };
            assert!(db
                .update_payment_order_if_state(&b_paid, OrderState::Pending)
                .await
                .unwrap());
            assert_eq!(db.fetch_payment_order("o1").await.unwrap(), Some(b_paid));

            // Released: a write from an unleased read matches again
            db.release_payment_order_lease("o1").await.unwrap();
            let released = db.fetch_payment_order("o1").await.unwrap().unwrap();
            assert!(released.lease_until.is_none());
            let fulfilled = PaymentOrder {
                state: OrderState::Fulfilled,
                fulfilled_at: Some(2_700),
                ..released
            };
            assert!(db
                .update_payment_order_if_state(&fulfilled, OrderState::Paid)
                .await
                .unwrap());
        });
    }

    #[tokio::test]
    async fn a_write_never_undoes_an_account_deletion_unlink() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
            let read = order("o1", "u1", OrderState::Paid, 10);
            db.insert_payment_order(&read).await.unwrap();

            // The buyer deletes their account after the worker read the order
            db.unlink_payment_orders_by_user("u1").await.unwrap();

            let fulfilled = PaymentOrder {
                state: OrderState::Fulfilled,
                fulfilled_at: Some(20),
                ..read.clone()
            };
            assert!(!db
                .update_payment_order_if_state(&fulfilled, OrderState::Paid)
                .await
                .unwrap());
            let stored = db.fetch_payment_order("o1").await.unwrap().unwrap();
            assert!(stored.user_id.is_none());
            assert_eq!(stored.state, OrderState::Paid);

            // A writer that read after the unlink carries no buyer and wins;
            // the field stays unset
            let voided = PaymentOrder {
                state: OrderState::Voided,
                reversed_at: Some(30),
                ..stored
            };
            assert!(db
                .update_payment_order_if_state(&voided, OrderState::Paid)
                .await
                .unwrap());
            assert_eq!(db.fetch_payment_order("o1").await.unwrap(), Some(voided));
            assert!(db
                .fetch_payment_orders_by_user("u1", &[OrderState::Voided])
                .await
                .unwrap()
                .is_empty());

            // Nor can a writer attach a buyer to an unlinked order
            let relinked = PaymentOrder {
                user_id: Some("u1".to_string()),
                state: OrderState::Refunded,
                ..read
            };
            assert!(!db
                .update_payment_order_if_state(&relinked, OrderState::Voided)
                .await
                .unwrap());
        });
    }

    #[tokio::test]
    async fn provider_ids_are_unique_across_orders() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
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
        });
    }

    #[tokio::test]
    async fn sweeps_select_by_state_age_and_reversal() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
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
                    .fetch_payment_orders_by_user(
                        "u1",
                        &[OrderState::Pending, OrderState::Fulfilled]
                    )
                    .await
                    .unwrap()),
                ["done", "newer", "young"]
            );
        });
    }

    #[tokio::test]
    async fn account_deletion_unlinks_only_that_users_orders() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
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
        });
    }
}
