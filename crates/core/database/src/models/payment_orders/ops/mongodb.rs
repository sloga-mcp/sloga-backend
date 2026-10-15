use bson::{to_bson, Bson, Document};
use futures::TryStreamExt;
use mongodb::options::{FindOneAndUpdateOptions, ReturnDocument};
use revolt_result::Result;

use crate::MongoDb;
use crate::{OrderState, PaymentOrder};

use super::AbstractPaymentOrders;

static COL: &str = "payment_orders";

/// A state exactly as the typed insert stores it (unit variants are plain
/// strings, e.g. "Pending")
fn state_bson(state: &OrderState) -> Result<Bson> {
    to_bson(state).map_err(|_| create_database_error!("to_bson", COL))
}

/// An `$in` list of states, in the stored encoding
fn states_bson(states: &[OrderState]) -> Result<Bson> {
    to_bson(states).map_err(|_| create_database_error!("to_bson", COL))
}

/// A row of a list query that failed to read (or decode) fails the whole
/// query: a money sweep that skipped it would never act on that order
fn row_error(error: mongodb::error::Error) -> revolt_result::Error {
    log::error!("{COL}: failed to read a row of a list query: {error}");
    create_database_error!("find", COL)
}

/// The lease is free: never taken, or taken and run out before `now`.
/// Optional fields are never stored as null, so `$exists: false` is the
/// only shape of an unset lease.
fn lease_free(now: i64) -> Bson {
    Bson::Array(vec![
        Bson::Document(doc! { "lease_until": { "$exists": false } }),
        Bson::Document(doc! { "lease_until": { "$lt": now } }),
    ])
}

#[async_trait]
impl AbstractPaymentOrders for MongoDb {
    async fn insert_payment_order(&self, o: &PaymentOrder) -> Result<()> {
        // Not query!: a duplicate must come back as an error, never a
        // debug-build panic
        self.col::<PaymentOrder>(COL)
            .insert_one(o)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("insert_one", COL))
    }

    async fn fetch_payment_order(&self, id: &str) -> Result<Option<PaymentOrder>> {
        query!(self, find_one_by_id, COL, id)
    }

    async fn fetch_payment_order_by_session(
        &self,
        session_id: &str,
    ) -> Result<Option<PaymentOrder>> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "checkout_session_id": session_id
            }
        )
    }

    async fn fetch_payment_order_by_intent(
        &self,
        payment_intent_id: &str,
    ) -> Result<Option<PaymentOrder>> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "payment_intent_id": payment_intent_id
            }
        )
    }

    async fn fetch_payment_orders_by_user(
        &self,
        user_id: &str,
        states: &[OrderState],
    ) -> Result<Vec<PaymentOrder>> {
        self.col::<PaymentOrder>(COL)
            .find(doc! {
                "user_id": user_id,
                "state": { "$in": states_bson(states)? }
            })
            .sort(doc! { "created_at": 1_i32, "_id": 1_i32 })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .try_collect()
            .await
            .map_err(row_error)
    }

    async fn fetch_payment_orders_by_state(
        &self,
        states: &[OrderState],
        before: i64,
        limit: i64,
    ) -> Result<Vec<PaymentOrder>> {
        self.col::<PaymentOrder>(COL)
            .find(doc! {
                "state": { "$in": states_bson(states)? },
                "created_at": { "$lt": before }
            })
            .sort(doc! { "created_at": 1_i32, "_id": 1_i32 })
            .limit(limit)
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .try_collect()
            .await
            .map_err(row_error)
    }

    async fn fetch_payment_orders_reversal_pending(
        &self,
        now: i64,
        limit: i64,
    ) -> Result<Vec<PaymentOrder>> {
        self.col::<PaymentOrder>(COL)
            .find(doc! {
                "reversal_pending": { "$exists": true },
                "$or": lease_free(now)
            })
            .sort(doc! { "created_at": 1_i32, "_id": 1_i32 })
            .limit(limit)
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .try_collect()
            .await
            .map_err(row_error)
    }

    async fn acquire_payment_order_lease(
        &self,
        id: &str,
        now: i64,
        until: i64,
    ) -> Result<Option<PaymentOrder>> {
        // The lease check and the write happen under one document lock, so
        // of two workers racing for a free lease exactly one gets the order
        // back. Never upserts: an unknown id is None.
        self.col::<PaymentOrder>(COL)
            .find_one_and_update(
                // Only one `_id` key: a second one would replace the first
                doc! {
                    "_id": id,
                    "$or": lease_free(now)
                },
                doc! {
                    "$set": {
                        "lease_until": until
                    }
                },
            )
            .with_options(
                FindOneAndUpdateOptions::builder()
                    // The holder works from the leased document
                    .return_document(ReturnDocument::After)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_one_and_update", COL))
    }

    async fn release_payment_order_lease(&self, id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id
                },
                doc! {
                    "$unset": {
                        "lease_until": 1_i32
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    async fn update_payment_order_if_state(
        &self,
        o: &PaymentOrder,
        expected: OrderState,
    ) -> Result<bool> {
        // Filter + replace under one document lock: a writer that read the
        // order before another moved it on cannot overwrite the newer
        // state. The typed replacement leaves unset optionals out (never
        // null), which the partial unique indexes depend on. No upsert, so
        // a missing order is `false`.
        let mut filter = doc! {
            "_id": &o.id,
            "state": state_bson(&expected)?
        };

        // Fencing token: a worker whose lease ran out and was taken over
        // still carries the old `lease_until`, so it no longer matches
        match o.lease_until {
            Some(until) => {
                filter.insert("lease_until", until);
            }
            None => {
                filter.insert("lease_until", doc! { "$exists": false });
            }
        }

        // An account-deletion unlink is never undone by a writer that read
        // the order before it ran
        match &o.user_id {
            Some(user_id) => {
                filter.insert("user_id", user_id.as_str());
            }
            None => {
                filter.insert("user_id", doc! { "$exists": false });
            }
        }

        self.col::<PaymentOrder>(COL)
            .replace_one(filter, o)
            .await
            .map(|result| result.matched_count == 1)
            .map_err(|_| create_database_error!("replace_one", COL))
    }

    async fn unlink_payment_orders_by_user(&self, user_id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_many(
                doc! {
                    "user_id": user_id
                },
                doc! {
                    "$unset": {
                        "user_id": 1_i32
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_many", COL))
    }
}

#[cfg(test)]
mod tests {
    use bson::{from_document, to_document};
    use revolt_models::v0;

    use crate::{OrderState, PaymentOrder, PaymentProvider, ReversalPending, VoidReason};

    use super::{state_bson, states_bson};

    fn order() -> PaymentOrder {
        PaymentOrder {
            id: "01J0000000000000000000000A".to_string(),
            user_id: None,
            provider: PaymentProvider::Stripe,
            sku: v0::Sku::CipherNew {
                tier: v0::CipherTier::T99,
            },
            amount_cents: 9900,
            currency: "usd".to_string(),
            checkout_session_id: None,
            checkout_url: None,
            session_expires_at: None,
            payment_intent_id: None,
            state: OrderState::Creating,
            void_reason: None,
            reversal_pending: None,
            lease_until: None,
            created_at: 1_788_264_000_000,
            paid_at: None,
            fulfilled_at: None,
            reversed_at: None,
        }
    }

    #[test]
    fn unset_fields_are_absent_from_the_stored_document() {
        // The partial unique indexes treat an explicit null as a value, so
        // two orders without a session would collide if None were stored
        let doc = to_document(&order()).unwrap();
        let mut keys: Vec<&str> = doc.keys().map(|key| key.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "_id",
                "amount_cents",
                "created_at",
                "currency",
                "provider",
                "sku",
                "state"
            ]
        );
        assert_eq!(doc.get_str("state").unwrap(), "Creating");
        assert_eq!(doc.get_str("provider").unwrap(), "Stripe");
        let sku = doc.get_document("sku").unwrap();
        assert_eq!(sku.get_str("type").unwrap(), "CipherNew");
        assert_eq!(sku.get_str("tier").unwrap(), "T99");
        assert_eq!(from_document::<PaymentOrder>(doc).unwrap(), order());
    }

    #[test]
    fn a_full_order_round_trips() {
        let full = PaymentOrder {
            user_id: Some("01J000000000000000000000U1".to_string()),
            sku: v0::Sku::CipherUpgrade {
                from: v0::CipherTier::T99,
                to: v0::CipherTier::T299,
            },
            checkout_session_id: Some("cs_test_1".to_string()),
            checkout_url: Some("https://checkout.stripe.com/c/pay/cs_test_1".to_string()),
            session_expires_at: Some(1_788_266_100_000),
            payment_intent_id: Some("pi_1".to_string()),
            state: OrderState::Voided,
            void_reason: Some(VoidReason::DisputeOpen),
            reversal_pending: Some(ReversalPending::DisputeLost),
            lease_until: Some(1_788_264_120_000),
            paid_at: Some(1_788_264_060_000),
            fulfilled_at: Some(1_788_264_070_000),
            reversed_at: Some(1_788_264_080_000),
            ..order()
        };
        let doc = to_document(&full).unwrap();
        assert_eq!(doc.get_str("void_reason").unwrap(), "DisputeOpen");
        assert_eq!(doc.get_str("reversal_pending").unwrap(), "DisputeLost");
        assert_eq!(doc.get_i64("lease_until").unwrap(), 1_788_264_120_000);
        assert_eq!(from_document::<PaymentOrder>(doc).unwrap(), full);
    }

    #[test]
    fn state_filters_use_the_stored_encoding() {
        // A filter value that differs from what the typed write stored
        // silently matches nothing
        let doc = to_document(&PaymentOrder {
            state: OrderState::SessionFailed,
            ..order()
        })
        .unwrap();
        assert_eq!(
            doc.get("state").unwrap(),
            &state_bson(&OrderState::SessionFailed).unwrap()
        );
        assert_eq!(
            states_bson(&[OrderState::Paid, OrderState::Fulfilled]).unwrap(),
            bson::Bson::Array(vec!["Paid".into(), "Fulfilled".into()])
        );
    }
}
