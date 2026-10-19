pub mod mongodb;
pub mod reference;

use revolt_result::Result;

use crate::CipherNumber;

#[async_trait]
pub trait AbstractCipherNumbers: Sync + Send {
    /// Claim the lowest number `<= cap` whose `order_id` is absent by
    /// setting it to `order_id`; Ok(None) if no such number is free.
    ///
    /// An order that already holds a number gets that number back instead
    /// of claiming a second one, so a retried or racing claim never burns a
    /// number. The resume runs before the cap applies, so a number claimed
    /// under a higher cap is still returned. `cap` lets a lowered
    /// `cipher_cap` bind a table seeded larger. Ok(None) on an empty table
    /// means "not seeded", not "sold out"; callers tell the two apart with
    /// `count_cipher_numbers`. `cap == 0` is a configuration error and
    /// returns Err (checked before the resume), never Ok(None).
    async fn claim_cipher_number(&self, order_id: &str, cap: u32) -> Result<Option<u32>>;

    /// Fetch the number claimed by an order, if any
    async fn fetch_cipher_number_by_order(&self, order_id: &str) -> Result<Option<u32>>;

    /// The row held by `order_id`, if any
    async fn fetch_cipher_number_row_by_order(
        &self,
        order_id: &str,
    ) -> Result<Option<CipherNumber>>;

    /// Record that the number held by `order_id` is to be released: set
    /// `release_pending_at = at` on that one row unless it is set already
    /// (the first decision's time is kept). Ok(true) if the row is marked
    /// (now or before), Ok(false) if the order holds no number. The row
    /// stays claimed until [`Self::release_cipher_number`].
    async fn mark_cipher_number_release(&self, order_id: &str, at: i64) -> Result<bool>;

    /// Put the number held by `order_id` back in the pool: unset `order_id`
    /// and `release_pending_at` on that one row, atomically. Ok(true) if a
    /// number was released, Ok(false) if the order holds none (never
    /// claimed, or released already, so a retry is a no-op). No other row
    /// is touched, so a number another order claimed since an earlier
    /// release stays claimed.
    ///
    /// Only for a purchase refunded in full within the release window: a
    /// retired number (refunded later, or a lost dispute) is never released.
    async fn release_cipher_number(&self, order_id: &str) -> Result<bool>;

    /// Rows whose release was decided but not finished (`release_pending_at`
    /// set, still claimed), oldest decision first, up to `limit`: the
    /// reconcile sweep finishes them
    async fn fetch_cipher_numbers_release_pending(&self, limit: i64) -> Result<Vec<CipherNumber>>;

    /// Count rows with `order_id` present (retired numbers included)
    async fn count_claimed_cipher_numbers(&self) -> Result<u32>;

    /// Count all rows (the seeded table size)
    async fn count_cipher_numbers(&self) -> Result<u32>;

    /// Idempotent seed of `1..=cap`; never touches `order_id` on rows that
    /// already exist
    async fn seed_cipher_numbers(&self, cap: u32) -> Result<()>;
}

#[cfg(test)]
mod tests {
    /// Install the unique partial `order_id` index on MongoDB.
    ///
    /// `database_test!` connects to a fresh database with no migrations run.
    /// This spec MUST stay identical to the one in
    /// `admin_migrations/ops/mongodb/scripts.rs` and `init.rs`. The reference
    /// driver enforces one number per order in code, so it needs no setup.
    async fn create_cipher_number_indexes(db: &crate::Database) {
        match db {
            crate::Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                mongo
                    .db()
                    .run_command(bson::doc! {
                        "createIndexes": "cipher_numbers",
                        "indexes": [
                            {
                                "key": { "order_id": 1_i32 },
                                "name": "cipher_numbers_order_unique",
                                "unique": true,
                                "partialFilterExpression": {
                                    "order_id": { "$type": "string" }
                                }
                            }
                        ]
                    })
                    .await
                    .expect("failed to create cipher_numbers indexes");
            }
        }
    }

    #[tokio::test]
    async fn empty_table_claims_nothing() {
        database_test!(|db| async move {
            assert_eq!(db.count_cipher_numbers().await.unwrap(), 0);
            assert_eq!(db.claim_cipher_number("order-a", 1000).await.unwrap(), None);
            assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);
        });
    }

    #[tokio::test]
    async fn claims_lowest_free_number_until_sold_out() {
        database_test!(|db| async move {
            create_cipher_number_indexes(&db).await;
            db.seed_cipher_numbers(3).await.unwrap();
            assert_eq!(db.count_cipher_numbers().await.unwrap(), 3);

            assert_eq!(db.claim_cipher_number("order-a", 3).await.unwrap(), Some(1));
            assert_eq!(db.claim_cipher_number("order-b", 3).await.unwrap(), Some(2));

            // A second claim for the same order resumes, never burns a number
            assert_eq!(db.claim_cipher_number("order-a", 3).await.unwrap(), Some(1));
            assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 2);

            assert_eq!(
                db.fetch_cipher_number_by_order("order-b").await.unwrap(),
                Some(2)
            );
            assert_eq!(
                db.fetch_cipher_number_by_order("order-unknown")
                    .await
                    .unwrap(),
                None
            );

            assert_eq!(db.claim_cipher_number("order-c", 3).await.unwrap(), Some(3));
            assert_eq!(db.claim_cipher_number("order-d", 3).await.unwrap(), None);
            assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 3);
            assert_eq!(db.count_cipher_numbers().await.unwrap(), 3);
        });
    }

    #[tokio::test]
    async fn claims_stop_at_the_cap_below_the_table_size() {
        database_test!(|db| async move {
            create_cipher_number_indexes(&db).await;
            db.seed_cipher_numbers(5).await.unwrap();

            assert_eq!(db.claim_cipher_number("order-a", 3).await.unwrap(), Some(1));
            assert_eq!(db.claim_cipher_number("order-b", 3).await.unwrap(), Some(2));
            assert_eq!(db.claim_cipher_number("order-c", 3).await.unwrap(), Some(3));

            // Numbers 4 and 5 are free, but above the cap
            assert_eq!(db.claim_cipher_number("order-d", 3).await.unwrap(), None);
            assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 3);
            assert_eq!(
                db.fetch_cipher_number_by_order("order-d").await.unwrap(),
                None
            );

            // A raised cap reaches them; a resume under a lower cap still
            // returns the number the order already holds
            assert_eq!(db.claim_cipher_number("order-d", 5).await.unwrap(), Some(4));
            assert_eq!(db.claim_cipher_number("order-d", 3).await.unwrap(), Some(4));
            assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 4);
        });
    }

    #[tokio::test]
    async fn a_zero_cap_is_an_error_not_sold_out() {
        database_test!(|db| async move {
            create_cipher_number_indexes(&db).await;

            // Unseeded and seeded alike
            assert!(db.claim_cipher_number("order-a", 0).await.is_err());
            db.seed_cipher_numbers(3).await.unwrap();
            assert!(db.claim_cipher_number("order-a", 0).await.is_err());
            assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 0);

            // Even for an order that already holds a number
            assert_eq!(db.claim_cipher_number("order-a", 3).await.unwrap(), Some(1));
            assert!(db.claim_cipher_number("order-a", 0).await.is_err());
            assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);
        });
    }

    #[tokio::test]
    async fn reseeding_keeps_claims_and_grows_the_table() {
        database_test!(|db| async move {
            db.seed_cipher_numbers(2).await.unwrap();
            assert_eq!(db.claim_cipher_number("order-a", 2).await.unwrap(), Some(1));

            // Same cap again: nothing changes
            db.seed_cipher_numbers(2).await.unwrap();
            assert_eq!(db.count_cipher_numbers().await.unwrap(), 2);
            assert_eq!(
                db.fetch_cipher_number_by_order("order-a").await.unwrap(),
                Some(1)
            );

            // A larger cap adds rows without releasing the claimed one
            db.seed_cipher_numbers(4).await.unwrap();
            assert_eq!(db.count_cipher_numbers().await.unwrap(), 4);
            assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);
            assert_eq!(
                db.fetch_cipher_number_by_order("order-a").await.unwrap(),
                Some(1)
            );
            assert_eq!(db.claim_cipher_number("order-b", 4).await.unwrap(), Some(2));

            // Seeding nothing is a no-op, not an error
            db.seed_cipher_numbers(0).await.unwrap();
            assert_eq!(db.count_cipher_numbers().await.unwrap(), 4);
        });
    }

    #[tokio::test]
    async fn release_frees_only_the_orders_number_and_is_idempotent() {
        database_test!(|db| async move {
            create_cipher_number_indexes(&db).await;
            db.seed_cipher_numbers(3).await.unwrap();
            assert_eq!(db.claim_cipher_number("order-a", 3).await.unwrap(), Some(1));
            assert_eq!(db.claim_cipher_number("order-b", 3).await.unwrap(), Some(2));

            // An order that holds nothing releases nothing
            assert!(!db.release_cipher_number("order-unknown").await.unwrap());
            assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 2);

            assert!(db.release_cipher_number("order-a").await.unwrap());
            assert_eq!(
                db.fetch_cipher_number_by_order("order-a").await.unwrap(),
                None
            );
            assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 1);
            // The other order's number is untouched
            assert_eq!(
                db.fetch_cipher_number_by_order("order-b").await.unwrap(),
                Some(2)
            );

            // A retry is a no-op
            assert!(!db.release_cipher_number("order-a").await.unwrap());

            // The released number is the lowest free one again, and a new
            // order claims it under the unique order_id index
            assert_eq!(db.claim_cipher_number("order-c", 3).await.unwrap(), Some(1));

            // A late retry of the old release never frees the new claim
            assert!(!db.release_cipher_number("order-a").await.unwrap());
            assert_eq!(
                db.fetch_cipher_number_by_order("order-c").await.unwrap(),
                Some(1)
            );
            assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 2);

            match &db {
                crate::Database::Reference(_) => {}
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(mongo) => {
                    // Released means the field is gone, not null: the claim
                    // filter is `$exists: false` and the index is partial
                    // on `$type: "string"`
                    assert!(db.release_cipher_number("order-b").await.unwrap());
                    let row = mongo
                        .col::<bson::Document>("cipher_numbers")
                        .find_one(bson::doc! { "_id": 2_i64 })
                        .await
                        .unwrap()
                        .expect("seeded row");
                    assert!(row.get("order_id").is_none());
                }
            }
        });
    }

    #[tokio::test]
    async fn a_release_mark_is_durable_until_the_release() {
        database_test!(|db| async move {
            create_cipher_number_indexes(&db).await;
            db.seed_cipher_numbers(4).await.unwrap();
            for order in ["order-a", "order-b", "order-c"] {
                db.claim_cipher_number(order, 4).await.unwrap();
            }

            // Nothing held, nothing marked
            assert!(!db
                .mark_cipher_number_release("order-unknown", 10)
                .await
                .unwrap());
            assert!(db
                .fetch_cipher_numbers_release_pending(10)
                .await
                .unwrap()
                .is_empty());

            assert!(db.mark_cipher_number_release("order-b", 20).await.unwrap());
            assert!(db.mark_cipher_number_release("order-a", 30).await.unwrap());
            // Marking again keeps the first decision's time
            assert!(db.mark_cipher_number_release("order-b", 99).await.unwrap());

            let row = db
                .fetch_cipher_number_row_by_order("order-b")
                .await
                .unwrap()
                .expect("held row");
            assert_eq!((row.number, row.release_pending_at), (2, Some(20)));
            assert_eq!(
                db.fetch_cipher_number_row_by_order("order-c")
                    .await
                    .unwrap()
                    .map(|row| row.release_pending_at),
                Some(None)
            );

            // A marked number is still claimed: not handed out, counted
            assert_eq!(db.count_claimed_cipher_numbers().await.unwrap(), 3);
            assert_eq!(db.claim_cipher_number("order-d", 4).await.unwrap(), Some(4));

            // Oldest decision first, bounded
            let pending = db.fetch_cipher_numbers_release_pending(10).await.unwrap();
            assert_eq!(
                pending
                    .iter()
                    .map(|row| (row.number, row.order_id.clone()))
                    .collect::<Vec<_>>(),
                vec![
                    (2, Some("order-b".to_string())),
                    (1, Some("order-a".to_string()))
                ]
            );
            assert_eq!(
                db.fetch_cipher_numbers_release_pending(1)
                    .await
                    .unwrap()
                    .len(),
                1
            );

            // The release clears both fields together
            assert!(db.release_cipher_number("order-b").await.unwrap());
            assert_eq!(
                db.fetch_cipher_number_row_by_order("order-b")
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(
                db.fetch_cipher_numbers_release_pending(10)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(db.claim_cipher_number("order-e", 4).await.unwrap(), Some(2));
            assert_eq!(
                db.fetch_cipher_number_row_by_order("order-e")
                    .await
                    .unwrap()
                    .and_then(|row| row.release_pending_at),
                None,
                "a re-claimed number carries no stale mark"
            );

            match &db {
                crate::Database::Reference(_) => {}
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(mongo) => {
                    let row = mongo
                        .col::<bson::Document>("cipher_numbers")
                        .find_one(bson::doc! { "_id": 2_i64 })
                        .await
                        .unwrap()
                        .expect("seeded row");
                    assert!(row.get("release_pending_at").is_none());
                }
            }
        });
    }

    #[tokio::test]
    async fn stored_id_is_int64() {
        database_test!(|db| async move {
            db.seed_cipher_numbers(1).await.unwrap();

            match &db {
                crate::Database::Reference(_) => {}
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(mongo) => {
                    // Pins the encoding hand-built filters and the migration
                    // seed rely on
                    let row = mongo
                        .col::<bson::Document>("cipher_numbers")
                        .find_one(bson::doc! {})
                        .await
                        .unwrap()
                        .expect("seeded row");
                    assert_eq!(row.get("_id"), Some(&bson::Bson::Int64(1)));
                    assert!(row.get("order_id").is_none());
                }
            }
        });
    }
}
