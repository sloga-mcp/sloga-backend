use revolt_result::Result;

use crate::{ReferenceDb, UploadHashBlock};

use super::AbstractUploadHashBlocks;

#[async_trait]
impl AbstractUploadHashBlocks for ReferenceDb {
    async fn insert_upload_hash_block(&self, b: &UploadHashBlock) -> Result<()> {
        let mut rows = self.upload_hash_blocks.lock().await;
        // Already blocked is success; the first row is kept
        if !rows.contains_key(&b.id) {
            rows.insert(b.id.clone(), b.clone());
        }
        Ok(())
    }

    async fn is_hash_blocked(&self, key: &str) -> Result<bool> {
        Ok(self.upload_hash_blocks.lock().await.contains_key(key))
    }

    async fn delete_upload_hash_blocks_for_request(&self, request_id: &str) -> Result<()> {
        self.upload_hash_blocks
            .lock()
            .await
            .retain(|_, row| row.request_id != request_id);
        Ok(())
    }
}
