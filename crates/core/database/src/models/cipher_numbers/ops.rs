pub mod mongodb;
pub mod reference;

use revolt_result::Result;

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
