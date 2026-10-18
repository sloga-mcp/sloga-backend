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

    /// Orders in any of `states` with `reversal_pending` set whose lease is
    /// free (`lease_until` unset or `< now`), oldest `created_at` first, up
    /// to `limit` (0 = no limit). The state filter runs in the query, so
    /// rows the caller cannot act on never fill the batch.
    async fn fetch_payment_orders_reversal_pending(
        &self,
        states: &[OrderState],
        now: i64,
        limit: i64,
    ) -> Result<Vec<PaymentOrder>>;

    /// Atomically set `lease_until = until` WHERE `_id = id` AND
    /// (`lease_until` unset OR `lease_until < now`), and bump `version`
    /// (+1).
    /// Ok(Some(order_after)) if acquired (it carries the new `version` and
    /// `lease_until = until`), Ok(None) if held by someone else or no such
    /// order.
    async fn acquire_payment_order_lease(
        &self,
        id: &str,
        now: i64,
        until: i64,
    ) -> Result<Option<PaymentOrder>>;

    /// Fenced release: `$unset lease_until` WHERE `_id = id` AND
    /// `lease_until == until`, so a stale holder cannot clear a newer
    /// lease. No version bump. A stale release (the lease was taken over)
    /// and a missing order are both a no-op Ok(()).
    async fn release_payment_order_lease(&self, id: &str, until: i64) -> Result<()>;

    /// Conditional replace: write `o` in full WHERE `_id = o.id` AND
    /// `state = expected` AND
    /// - `version` equals `o.version` (`o.version == 0` also matches a
    ///   stored order with no version field). The stored version becomes
    ///   `o.version + 1`: a caller doing a second write in the same lease
    ///   bumps its copy first.
    /// - `lease_until` equals `o.lease_until` (`None`: the stored field
    ///   must be unset). This is the fencing token: a holder whose lease ran
    ///   out and was taken over carries the old value and cannot write.
    ///   Always write the order the lease call returned.
    /// - `user_id` equals `o.user_id` (`None`: the stored field must be
    ///   unset), so a writer that read the order before an account-deletion
    ///   unlink cannot put the buyer back.
    ///
    /// `acquire_payment_order_lease` and `unlink_payment_orders_by_user`
    /// also bump `version` (+1).
    ///
    /// Ok(true) if matched and written, Ok(false) if the state, version,
    /// lease or buyer differed or the order does not exist. Ok(false) does
    /// not say which check failed: re-fetch before deciding to retry or give
    /// up. `lease_until` is written as `o` carries it, so a lease holder
    /// writing the order it acquired keeps its lease.
    async fn update_payment_order_if_state(
        &self,
        o: &PaymentOrder,
        expected: OrderState,
    ) -> Result<bool>;

    /// Account deletion: unset `user_id` and bump `version` (+1) on every
    /// order of the user
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
            open_disputes: vec![],
            lease_until: None,
            version: 0,
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

            // Released by its holder: free again at any time
            db.release_payment_order_lease("o1", 241_001).await.unwrap();
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
            db.release_payment_order_lease("missing", 120_000)
                .await
                .unwrap();
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

            // The write moved the version on
            let paid = PaymentOrder { version: 1, ..paid };
            assert_eq!(
                db.fetch_payment_order("o1").await.unwrap(),
                Some(paid.clone())
            );

            // A stale writer that still believes the order is Pending loses.
            // It carries the current version, so only the state check can
            // refuse it.
            let expired = PaymentOrder {
                state: OrderState::Expired,
                version: 1,
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
            // but its lease token is stale. Even given the current version,
            // the stale token alone refuses it.
            assert_eq!((a.version, b.version), (1, 2));
            let a_paid = PaymentOrder {
                state: OrderState::Paid,
                paid_at: Some(2_500),
                version: b.version,
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
            assert_eq!(
                db.fetch_payment_order("o1").await.unwrap(),
                Some(PaymentOrder {
                    version: 3,
                    ..b_paid
                })
            );

            // Released: a write from an unleased read matches again
            db.release_payment_order_lease("o1", 3_001).await.unwrap();
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

            // Given the current version, the stale buyer alone refuses it
            let fulfilled = PaymentOrder {
                state: OrderState::Fulfilled,
                fulfilled_at: Some(20),
                version: 1,
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
            assert_eq!(
                db.fetch_payment_order("o1").await.unwrap(),
                Some(PaymentOrder {
                    version: 2,
                    ..voided
                })
            );
            assert!(db
                .fetch_payment_orders_by_user("u1", &[OrderState::Voided])
                .await
                .unwrap()
                .is_empty());

            // Nor can a writer attach a buyer to an unlinked order (again
            // with the current version, so the buyer check alone refuses it)
            let relinked = PaymentOrder {
                user_id: Some("u1".to_string()),
                state: OrderState::Refunded,
                version: 2,
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
                // Too young for the by-state cutoff; only the reversal
                // queries that name Pending see it
                PaymentOrder {
                    reversal_pending: Some(ReversalPending::Refund),
                    ..order("rev_pending", "u4", OrderState::Pending, 150)
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
            let paid_or_fulfilled = [OrderState::Paid, OrderState::Fulfilled];
            assert_eq!(
                ids(db
                    .fetch_payment_orders_reversal_pending(&paid_or_fulfilled, 500, 0)
                    .await
                    .unwrap()),
                ["rev_free", "rev_lapsed"]
            );
            assert_eq!(
                ids(db
                    .fetch_payment_orders_reversal_pending(&paid_or_fulfilled, 1_001, 0)
                    .await
                    .unwrap()),
                ["rev_held", "rev_free", "rev_lapsed"]
            );
            assert_eq!(
                ids(db
                    .fetch_payment_orders_reversal_pending(&paid_or_fulfilled, 1_001, 1)
                    .await
                    .unwrap()),
                ["rev_held"]
            );

            // Only the named states, filtered before the limit
            assert_eq!(
                ids(db
                    .fetch_payment_orders_reversal_pending(&[OrderState::Fulfilled], 1_001, 1)
                    .await
                    .unwrap()),
                ["rev_held"]
            );
            assert!(db
                .fetch_payment_orders_reversal_pending(&[OrderState::Fulfilled], 500, 0)
                .await
                .unwrap()
                .is_empty());
            assert_eq!(
                ids(db
                    .fetch_payment_orders_reversal_pending(&[OrderState::Pending], 500, 0)
                    .await
                    .unwrap()),
                ["rev_pending"]
            );
            assert!(db
                .fetch_payment_orders_reversal_pending(&[], 1_001, 0)
                .await
                .unwrap()
                .is_empty());

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
            assert_eq!(mine.version, 1);
            let theirs = db.fetch_payment_order("theirs").await.unwrap().unwrap();
            assert_eq!(theirs.user_id.as_deref(), Some("u2"));
            // Untouched orders keep their version
            assert_eq!(theirs.version, 0);
            assert!(db
                .fetch_payment_orders_by_user("u1", &[OrderState::Fulfilled])
                .await
                .unwrap()
                .is_empty());
        });
    }

    #[tokio::test]
    async fn a_write_from_a_read_during_a_lease_loses_to_the_holders_write() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
            db.insert_payment_order(&order("o1", "u1", OrderState::Paid, 10))
                .await
                .unwrap();

            // A worker leases the order to fulfil it
            let held = db
                .acquire_payment_order_lease("o1", 1_000, 121_000)
                .await
                .unwrap()
                .expect("a free lease is acquired");
            // Meanwhile a refund handler reads the order (not via a lease):
            // it carries the holder's lease token, state and buyer
            let outside = db.fetch_payment_order("o1").await.unwrap().unwrap();
            assert_eq!(outside.lease_until, Some(121_000));

            // The holder writes without changing the state
            let held_write = PaymentOrder {
                payment_intent_id: Some("pi_1".to_string()),
                ..held
            };
            assert!(db
                .update_payment_order_if_state(&held_write, OrderState::Paid)
                .await
                .unwrap());

            // The outside write keeps the state, lease and buyer; only the
            // version moved, and that alone refuses it
            let outside_write = PaymentOrder {
                reversal_pending: Some(ReversalPending::Refund),
                ..outside
            };
            assert!(!db
                .update_payment_order_if_state(&outside_write, OrderState::Paid)
                .await
                .unwrap());
            assert_eq!(
                db.fetch_payment_order("o1").await.unwrap(),
                Some(PaymentOrder {
                    version: 2,
                    ..held_write
                })
            );
        });
    }

    #[tokio::test]
    async fn the_holders_write_loses_to_an_earlier_outside_write() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
            db.insert_payment_order(&order("o1", "u1", OrderState::Paid, 10))
                .await
                .unwrap();

            let held = db
                .acquire_payment_order_lease("o1", 1_000, 121_000)
                .await
                .unwrap()
                .expect("a free lease is acquired");
            let outside = db.fetch_payment_order("o1").await.unwrap().unwrap();

            // The outside write lands first
            let outside_write = PaymentOrder {
                reversal_pending: Some(ReversalPending::Refund),
                ..outside
            };
            assert!(db
                .update_payment_order_if_state(&outside_write, OrderState::Paid)
                .await
                .unwrap());

            // The holder's write from its leased copy would drop the
            // pending reversal; the version refuses it
            let held_write = PaymentOrder {
                payment_intent_id: Some("pi_1".to_string()),
                ..held
            };
            assert!(!db
                .update_payment_order_if_state(&held_write, OrderState::Paid)
                .await
                .unwrap());
            let stored = db.fetch_payment_order("o1").await.unwrap().unwrap();
            assert_eq!(stored.reversal_pending, Some(ReversalPending::Refund));
            assert!(stored.payment_intent_id.is_none());
            assert_eq!(stored.version, 2);

            // Re-fetched, the holder keeps both changes
            let retried = PaymentOrder {
                payment_intent_id: Some("pi_1".to_string()),
                ..stored
            };
            assert!(db
                .update_payment_order_if_state(&retried, OrderState::Paid)
                .await
                .unwrap());
            let stored = db.fetch_payment_order("o1").await.unwrap().unwrap();
            assert_eq!(stored.reversal_pending, Some(ReversalPending::Refund));
            assert_eq!(stored.payment_intent_id.as_deref(), Some("pi_1"));
            assert_eq!(stored.version, 3);
        });
    }

    #[tokio::test]
    async fn consecutive_writes_in_one_lease_bump_the_local_version() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
            db.insert_payment_order(&order("o1", "u1", OrderState::Pending, 10))
                .await
                .unwrap();

            let mut held = db
                .acquire_payment_order_lease("o1", 1_000, 121_000)
                .await
                .unwrap()
                .expect("a free lease is acquired");
            assert_eq!(held.version, 1);

            held.state = OrderState::Paid;
            held.paid_at = Some(1_100);
            assert!(db
                .update_payment_order_if_state(&held, OrderState::Pending)
                .await
                .unwrap());

            // The same copy again, without the bump, is refused
            held.state = OrderState::Fulfilled;
            held.fulfilled_at = Some(1_200);
            assert!(!db
                .update_payment_order_if_state(&held, OrderState::Paid)
                .await
                .unwrap());

            // Bumped to what the first write stored: the second write lands
            held.version += 1;
            assert!(db
                .update_payment_order_if_state(&held, OrderState::Paid)
                .await
                .unwrap());
            assert_eq!(
                db.fetch_payment_order("o1").await.unwrap(),
                Some(PaymentOrder { version: 3, ..held })
            );
        });
    }

    #[tokio::test]
    async fn a_stale_release_leaves_the_new_lease() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
            db.insert_payment_order(&order("o1", "u1", OrderState::Paid, 10))
                .await
                .unwrap();

            // A's lease runs out and B takes it over
            db.acquire_payment_order_lease("o1", 1_000, 2_000)
                .await
                .unwrap()
                .expect("A acquires");
            db.acquire_payment_order_lease("o1", 2_001, 3_001)
                .await
                .unwrap()
                .expect("B takes over");

            // A releases late, with its own token: a no-op
            db.release_payment_order_lease("o1", 2_000).await.unwrap();
            let stored = db.fetch_payment_order("o1").await.unwrap().unwrap();
            assert_eq!(stored.lease_until, Some(3_001));
            // A release never moves the version
            assert_eq!(stored.version, 2);
            // B still holds it
            assert!(db
                .acquire_payment_order_lease("o1", 2_500, 4_000)
                .await
                .unwrap()
                .is_none());

            // B's own release frees it, still without a version bump
            db.release_payment_order_lease("o1", 3_001).await.unwrap();
            let stored = db.fetch_payment_order("o1").await.unwrap().unwrap();
            assert!(stored.lease_until.is_none());
            assert_eq!(stored.version, 2);

            // Releasing a free lease is a no-op too
            db.release_payment_order_lease("o1", 3_001).await.unwrap();
            assert_eq!(db.fetch_payment_order("o1").await.unwrap(), Some(stored));
        });
    }

    #[tokio::test]
    async fn acquiring_a_lease_bumps_the_version() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
            db.insert_payment_order(&order("o1", "u1", OrderState::Pending, 10))
                .await
                .unwrap();
            // A copy read before anyone leased the order
            let before = db.fetch_payment_order("o1").await.unwrap().unwrap();
            assert_eq!(before.version, 0);

            let held = db
                .acquire_payment_order_lease("o1", 1_000, 121_000)
                .await
                .unwrap()
                .unwrap();
            // The returned post-image carries the new version and lease
            assert_eq!(held.version, 1);
            assert_eq!(held.lease_until, Some(121_000));
            assert_eq!(db.fetch_payment_order("o1").await.unwrap(), Some(held));

            // A refused acquire does not bump it
            assert!(db
                .acquire_payment_order_lease("o1", 2_000, 122_000)
                .await
                .unwrap()
                .is_none());
            db.release_payment_order_lease("o1", 121_000).await.unwrap();
            assert_eq!(
                db.fetch_payment_order("o1").await.unwrap().unwrap().version,
                1
            );

            // The lease is free again, so the pre-lease copy matches on
            // state, lease (unset) and buyer; the moved version alone
            // refuses it
            let stale = PaymentOrder {
                state: OrderState::Expired,
                ..before
            };
            assert!(!db
                .update_payment_order_if_state(&stale, OrderState::Pending)
                .await
                .unwrap());

            assert_eq!(
                db.acquire_payment_order_lease("o1", 3_000, 123_000)
                    .await
                    .unwrap()
                    .unwrap()
                    .version,
                2
            );
        });
    }

    #[tokio::test]
    async fn an_unlink_bumps_the_version_and_refuses_a_pre_unlink_copy() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
            db.insert_payment_order(&order("o1", "u1", OrderState::Paid, 10))
                .await
                .unwrap();
            let before = db.fetch_payment_order("o1").await.unwrap().unwrap();

            db.unlink_payment_orders_by_user("u1").await.unwrap();
            let stored = db.fetch_payment_order("o1").await.unwrap().unwrap();
            assert!(stored.user_id.is_none());
            assert_eq!(stored.version, 1);

            // A pre-unlink copy that itself drops the buyer passes the
            // buyer check; the moved version alone refuses it
            let voided = PaymentOrder {
                user_id: None,
                state: OrderState::Voided,
                void_reason: Some(crate::VoidReason::AccountDeleted),
                reversed_at: Some(20),
                ..before
            };
            assert!(!db
                .update_payment_order_if_state(&voided, OrderState::Paid)
                .await
                .unwrap());
            assert_eq!(db.fetch_payment_order("o1").await.unwrap(), Some(stored));
        });
    }

    #[tokio::test]
    async fn expected_version_zero_matches_an_order_stored_without_a_version() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
            let row = order("o1", "u1", OrderState::Pending, 10);
            let leased_row = order("o2", "u1", OrderState::Pending, 20);

            match &db {
                // This driver has no absent field: the order reads as 0
                crate::Database::Reference(_) => {
                    db.insert_payment_order(&row).await.unwrap();
                    db.insert_payment_order(&leased_row).await.unwrap();
                }
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(mongo) => {
                    // Orders written before `version` existed
                    for typed in [&row, &leased_row] {
                        let mut raw = bson::to_document(typed).unwrap();
                        raw.remove("version");
                        assert!(!raw.contains_key("version"));
                        mongo
                            .col::<bson::Document>("payment_orders")
                            .insert_one(raw)
                            .await
                            .unwrap();
                    }
                }
            }

            assert_eq!(
                db.fetch_payment_order("o1").await.unwrap(),
                Some(row.clone())
            );

            let paid = PaymentOrder {
                state: OrderState::Paid,
                paid_at: Some(30),
                ..row.clone()
            };
            assert!(db
                .update_payment_order_if_state(&paid, OrderState::Pending)
                .await
                .unwrap());
            assert_eq!(
                db.fetch_payment_order("o1").await.unwrap(),
                Some(PaymentOrder {
                    version: 1,
                    ..paid.clone()
                })
            );

            // Now at 1: the absent-or-zero match no longer applies
            let stale = PaymentOrder {
                paid_at: Some(40),
                ..paid
            };
            assert!(!db
                .update_payment_order_if_state(&stale, OrderState::Paid)
                .await
                .unwrap());

            // A lease on a version-less order starts the count at 1
            let held = db
                .acquire_payment_order_lease("o2", 1_000, 121_000)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(held.version, 1);
        });
    }

    #[tokio::test]
    async fn open_disputes_are_written_and_cleared_by_id() {
        database_test!(|db| async move {
            create_payment_order_indexes(&db).await;
            let row = order("o1", "u1", OrderState::Paid, 10);
            db.insert_payment_order(&row).await.unwrap();
            assert!(db
                .fetch_payment_order("o1")
                .await
                .unwrap()
                .unwrap()
                .open_disputes
                .is_empty());

            // Two disputes on one payment, kept apart by id
            let two = PaymentOrder {
                open_disputes: vec!["dp_a".to_string(), "dp_b".to_string()],
                ..row
            };
            assert!(db
                .update_payment_order_if_state(&two, OrderState::Paid)
                .await
                .unwrap());
            let stored = db.fetch_payment_order("o1").await.unwrap().unwrap();
            assert_eq!(stored.open_disputes, ["dp_a", "dp_b"]);

            // One closes: only its id goes
            let one = PaymentOrder {
                open_disputes: vec!["dp_b".to_string()],
                ..stored
            };
            assert!(db
                .update_payment_order_if_state(&one, OrderState::Paid)
                .await
                .unwrap());
            let stored = db.fetch_payment_order("o1").await.unwrap().unwrap();
            assert_eq!(stored.open_disputes, ["dp_b"]);

            // The last closes: read back empty, and (Mongo) the field is
            // gone from the stored document, not left as an empty array
            let none = PaymentOrder {
                open_disputes: vec![],
                ..stored
            };
            assert!(db
                .update_payment_order_if_state(&none, OrderState::Paid)
                .await
                .unwrap());
            assert!(db
                .fetch_payment_order("o1")
                .await
                .unwrap()
                .unwrap()
                .open_disputes
                .is_empty());

            match &db {
                crate::Database::Reference(_) => {}
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(mongo) => {
                    let raw = mongo
                        .col::<bson::Document>("payment_orders")
                        .find_one(bson::doc! { "_id": "o1" })
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(!raw.contains_key("open_disputes"), "{raw:?}");
                }
            }
        });
    }
}
