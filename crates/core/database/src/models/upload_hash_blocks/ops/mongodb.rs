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
            // The key is the `_id`: already blocked is success
            Err(error) if is_duplicate_key(&error) => Ok(()),
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
        self.col::<Document>(COL)
            .delete_many(doc! { "request_id": request_id })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }
}
