use bson::Document;
use revolt_result::Result;

use crate::{MongoDb, UploadHashBlock};

use super::AbstractUploadHashBlocks;

static COL: &str = "upload_hash_blocks";

fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    matches!(
        *error.kind,
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
            ref write_error,
        )) if write_error.code == 11000
    )
}

#[async_trait]
impl AbstractUploadHashBlocks for MongoDb {
    async fn insert_upload_hash_block(&self, b: &UploadHashBlock) -> Result<()> {
        match self.col::<UploadHashBlock>(COL).insert_one(b).await {
            Ok(_) => Ok(()),
            // The key is the `_id`: already blocked is success, with this
            // request added to the row's holders
            Err(error) if is_duplicate_key(&error) => self
                .col::<Document>(COL)
                .update_one(
                    doc! { "_id": &b.id, "request_id": { "$ne": &b.request_id } },
                    doc! { "$addToSet": { "also_request_ids": &b.request_id } },
                )
                .await
                .map(|_| ())
                .map_err(|_| create_database_error!("update_one", COL)),
            Err(_) => Err(create_database_error!("insert_one", COL)),
        }
    }

    async fn is_hash_blocked(&self, key: &str) -> Result<bool> {
        self.col::<Document>(COL)
            .find_one(doc! { "_id": key })
            .await
            .map(|row| row.is_some())
            .map_err(|_| create_database_error!("find_one", COL))
    }

    async fn delete_upload_hash_blocks_for_request(&self, request_id: &str) -> Result<()> {
        // Rows only this request holds go
        self.col::<Document>(COL)
            .delete_many(doc! {
                "request_id": request_id,
                "$or": [
                    { "also_request_ids": { "$exists": false } },
                    { "also_request_ids": { "$size": 0_i32 } },
                ],
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL))?;

        // Where it was a later holder, it stops being one
        self.col::<Document>(COL)
            .update_many(
                doc! { "also_request_ids": request_id },
                doc! { "$pull": { "also_request_ids": request_id } },
            )
            .await
            .map_err(|_| create_database_error!("update_many", COL))?;

        // Rows it blocked first that others still hold pass to the next one
        let rows: Vec<UploadHashBlock> = self
            .find(COL, doc! { "request_id": request_id })
            .await
            .map_err(|_| create_database_error!("find", COL))?;
        for row in rows {
            let Some(next) = row.also_request_ids.first() else {
                continue;
            };
            self.col::<Document>(COL)
                .update_one(
                    doc! { "_id": &row.id, "request_id": request_id },
                    doc! {
                        "$set": { "request_id": next },
                        "$pull": { "also_request_ids": next },
                    },
                )
                .await
                .map_err(|_| create_database_error!("update_one", COL))?;
        }
        Ok(())
    }
}
