use revolt_result::Result;

use crate::UploadHashBlock;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractUploadHashBlocks: Sync + Send {
    /// Add a block. Idempotent: if the key is already blocked this is `Ok`
    /// and the existing row (and its `request_id`) is kept.
    async fn insert_upload_hash_block(&self, b: &UploadHashBlock) -> Result<()>;

    /// Whether a key from `upload_hash_block_key` is blocked
    async fn is_hash_blocked(&self, key: &str) -> Result<bool>;

    /// Remove every block a request added
    async fn delete_upload_hash_blocks_for_request(&self, request_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::Timestamp;

    use super::AbstractUploadHashBlocks;
    use crate::{upload_hash_block_key, UploadHashBlock};

    const REQUEST_A: &str = "01TD0000000000000000000001";
    const REQUEST_B: &str = "01TD0000000000000000000002";

    fn block(kind: &str, hash: &str, request: &str) -> UploadHashBlock {
        UploadHashBlock {
            id: upload_hash_block_key(kind, hash),
            request_id: request.to_string(),
            created_at: Timestamp::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn insert_is_idempotent_and_blocks() {
        database_test!(|db| async move {
            let orig = upload_hash_block_key("orig", "aa");
            let proc = upload_hash_block_key("proc", "aa");

            assert!(!db.is_hash_blocked(&orig).await.unwrap());

            db.insert_upload_hash_block(&block("orig", "aa", REQUEST_A))
                .await
                .unwrap();
            db.insert_upload_hash_block(&block("orig", "aa", REQUEST_A))
                .await
                .unwrap();

            assert!(db.is_hash_blocked(&orig).await.unwrap());
            // Same hash, different kind: a different key.
            assert!(!db.is_hash_blocked(&proc).await.unwrap());
        });
    }

    #[tokio::test]
    async fn delete_for_request_removes_only_its_own_blocks() {
        database_test!(|db| async move {
            db.insert_upload_hash_block(&block("orig", "aa", REQUEST_A))
                .await
                .unwrap();
            db.insert_upload_hash_block(&block("proc", "bb", REQUEST_A))
                .await
                .unwrap();
            db.insert_upload_hash_block(&block("chunk", "cc", REQUEST_B))
                .await
                .unwrap();
            // Already blocked by A: B's insert is Ok and A keeps the row.
            db.insert_upload_hash_block(&block("orig", "aa", REQUEST_B))
                .await
                .unwrap();

            db.delete_upload_hash_blocks_for_request(REQUEST_B)
                .await
                .unwrap();
            assert!(db
                .is_hash_blocked(&upload_hash_block_key("orig", "aa"))
                .await
                .unwrap());
            assert!(db
                .is_hash_blocked(&upload_hash_block_key("proc", "bb"))
                .await
                .unwrap());
            assert!(!db
                .is_hash_blocked(&upload_hash_block_key("chunk", "cc"))
                .await
                .unwrap());

            db.delete_upload_hash_blocks_for_request(REQUEST_A)
                .await
                .unwrap();
            assert!(!db
                .is_hash_blocked(&upload_hash_block_key("orig", "aa"))
                .await
                .unwrap());
            assert!(!db
                .is_hash_blocked(&upload_hash_block_key("proc", "bb"))
                .await
                .unwrap());

            // Deleting for a request with no blocks is fine.
            db.delete_upload_hash_blocks_for_request(REQUEST_A)
                .await
                .unwrap();
        });
    }
}
