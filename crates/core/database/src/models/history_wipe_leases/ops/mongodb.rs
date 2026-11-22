use bson::Document;
use mongodb::options::{FindOneAndUpdateOptions, ReturnDocument};
use revolt_result::Result;

use crate::{HistoryWipeLease, MongoDb};

use super::AbstractHistoryWipeLeases;

/// Created by the first claim's upsert; keyed by `_id` only (no migration)
static COL: &str = "history_wipe_leases";

/// 11000, as a write error or a command error (`findAndModify` reports a
/// duplicate key as a command error)
fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    match &*error.kind {
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(write_error)) => {
            write_error.code == 11000
        }
        mongodb::error::ErrorKind::Command(command_error) => command_error.code == 11000,
        _ => false,
    }
}

#[async_trait]
impl AbstractHistoryWipeLeases for MongoDb {
    /// One filtered upsert. While another holder's lease is live the filter
    /// misses and the upsert's insert hits the stored `_id`: that duplicate
    /// key (also the loser of two racing claims on an absent row) is `None`.
    async fn claim_history_wipe_lease(
        &self,
        channel_id: &str,
        holder: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<Option<u64>> {
        let result = self
            .col::<HistoryWipeLease>(COL)
            .find_one_and_update(
                doc! {
                    "_id": channel_id,
                    "$or": [
                        { "expires_at": { "$lte": now_ms } },
                        { "holder": holder }
                    ]
                },
                doc! {
                    "$set": {
                        "holder": holder,
                        "expires_at": now_ms.saturating_add(ttl_ms)
                    },
                    "$setOnInsert": { "count": 0_i64 }
                },
            )
            .with_options(
                FindOneAndUpdateOptions::builder()
                    .upsert(true)
                    .return_document(ReturnDocument::After)
                    .build(),
            )
            .await;

        match result {
            Ok(Some(lease)) => u64::try_from(lease.count)
                .map(Some)
                .map_err(|_| create_database_error!("find_one_and_update", COL)),
            // An upsert returning the document after always has one
            Ok(None) => Err(create_database_error!("find_one_and_update", COL)),
            Err(error) if is_duplicate_key(&error) => Ok(None),
            Err(_) => Err(create_database_error!("find_one_and_update", COL)),
        }
    }

    /// Filtered on the holder
    async fn advance_history_wipe_lease(
        &self,
        channel_id: &str,
        holder: &str,
        add: u64,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<bool> {
        let add = i64::try_from(add).map_err(|_| create_error!(InternalError))?;
        self.col::<Document>(COL)
            .update_one(
                doc! { "_id": channel_id, "holder": holder },
                doc! {
                    "$inc": { "count": add },
                    "$set": { "expires_at": now_ms.saturating_add(ttl_ms) }
                },
            )
            .await
            .map(|result| result.matched_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Filtered on the holder; the count is left alone
    async fn release_history_wipe_lease(&self, channel_id: &str, holder: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! { "_id": channel_id, "holder": holder },
                doc! { "$set": { "expires_at": 0_i64 } },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Delete the row; no row is not an error
    async fn delete_history_wipe_lease(&self, channel_id: &str) -> Result<()> {
        query!(self, delete_one_by_id, COL, channel_id).map(|_| ())
    }
}
