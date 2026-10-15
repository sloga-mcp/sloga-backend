use bson::Document;
use mongodb::options::{FindOneAndUpdateOptions, InsertManyOptions, ReturnDocument};
use revolt_result::Result;

use crate::CipherNumber;
use crate::MongoDb;

use super::AbstractCipherNumbers;

static COL: &str = "cipher_numbers";

/// Rows per `insert_many` call when seeding
const SEED_BATCH: u32 = 1000;

/// Whether a Mongo error is a duplicate key violation. `findAndModify`
/// reports one as a command error, `insert_one` as a write error.
fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    match *error.kind {
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
            ref write_error,
        )) => write_error.code == 11000,
        mongodb::error::ErrorKind::Command(ref command_error) => command_error.code == 11000,
        _ => false,
    }
}

/// Whether an unordered `insert_many` failed only on rows that already
/// exist
fn is_only_duplicate_keys(error: &mongodb::error::Error) -> bool {
    match *error.kind {
        mongodb::error::ErrorKind::InsertMany(ref failure) => {
            failure.write_concern_error.is_none()
                && failure.write_errors.as_ref().is_some_and(|errors| {
                    errors.iter().all(|write_error| write_error.code == 11000)
                })
        }
        _ => false,
    }
}

/// Convert a document count to the trait's `u32`
fn count_to_u32(count: u64) -> Result<u32> {
    u32::try_from(count).map_err(|_| create_database_error!("count_documents", COL))
}

#[async_trait]
impl AbstractCipherNumbers for MongoDb {
    async fn claim_cipher_number(&self, order_id: &str, cap: u32) -> Result<Option<u32>> {
        // Resume: an order that already holds a number keeps it
        if let Some(number) = self.fetch_cipher_number_by_order(order_id).await? {
            return Ok(Some(number));
        }

        // One find_one_and_update: the match on a free row and the write of
        // order_id happen under one document lock, so two concurrent claims
        // for different orders always get different numbers.
        let claimed = self
            .col::<CipherNumber>(COL)
            .find_one_and_update(
                doc! {
                    "_id": { "$lte": i64::from(cap) },
                    "order_id": { "$exists": false }
                },
                doc! {
                    "$set": {
                        "order_id": order_id
                    }
                },
            )
            .with_options(
                FindOneAndUpdateOptions::builder()
                    .sort(doc! { "_id": 1_i32 })
                    .return_document(ReturnDocument::After)
                    .build(),
            )
            .await;

        match claimed {
            Ok(row) => Ok(row.map(|row| row.number)),
            // Two claims for the same order raced past the pre-check and the
            // unique partial order_id index refused the loser: the winner's
            // number is this order's number.
            Err(error) if is_duplicate_key(&error) => self
                .fetch_cipher_number_by_order(order_id)
                .await?
                .map(Some)
                .ok_or_else(|| create_database_error!("find_one_and_update", COL)),
            Err(_) => Err(create_database_error!("find_one_and_update", COL)),
        }
    }

    async fn fetch_cipher_number_by_order(&self, order_id: &str) -> Result<Option<u32>> {
        self.col::<CipherNumber>(COL)
            .find_one(doc! {
                "order_id": order_id
            })
            .await
            .map(|row| row.map(|row| row.number))
            .map_err(|_| create_database_error!("find_one", COL))
    }

    async fn count_claimed_cipher_numbers(&self) -> Result<u32> {
        let count = self
            .col::<Document>(COL)
            .count_documents(doc! {
                "order_id": { "$exists": true }
            })
            .await
            .map_err(|_| create_database_error!("count_documents", COL))?;

        count_to_u32(count)
    }

    async fn count_cipher_numbers(&self) -> Result<u32> {
        let count = self
            .col::<Document>(COL)
            .count_documents(doc! {})
            .await
            .map_err(|_| create_database_error!("count_documents", COL))?;

        count_to_u32(count)
    }

    async fn seed_cipher_numbers(&self, cap: u32) -> Result<()> {
        // Unordered inserts of bare `{_id}` rows: an existing row (claimed or
        // not) is a duplicate key and is left exactly as it is, so a reseed
        // can never touch an order_id.
        let mut start = 1_u32;
        while start <= cap {
            let end = start.saturating_add(SEED_BATCH - 1).min(cap);
            let rows: Vec<CipherNumber> = (start..=end)
                .map(|number| CipherNumber {
                    number,
                    order_id: None,
                })
                .collect();

            match self
                .col::<CipherNumber>(COL)
                .insert_many(rows)
                .with_options(InsertManyOptions::builder().ordered(false).build())
                .await
            {
                Ok(_) => {}
                Err(error) if is_only_duplicate_keys(&error) => {}
                Err(_) => return Err(create_database_error!("insert_many", COL)),
            }

            if end == cap {
                break;
            }
            start = end + 1;
        }

        Ok(())
    }
}
