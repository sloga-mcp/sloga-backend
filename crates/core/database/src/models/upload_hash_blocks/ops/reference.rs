use revolt_result::Result;

use crate::{ReferenceDb, UploadHashBlock};

use super::AbstractUploadHashBlocks;

#[async_trait]
impl AbstractUploadHashBlocks for ReferenceDb {
    async fn insert_upload_hash_block(&self, b: &UploadHashBlock) -> Result<()> {
        let mut rows = self.upload_hash_blocks.lock().await;
        // Already blocked is success; the first row is kept, with this
        // request added to its holders
        match rows.get_mut(&b.id) {
            None => {
                rows.insert(b.id.clone(), b.clone());
            }
            Some(row) => {
                if row.request_id != b.request_id && !row.also_request_ids.contains(&b.request_id) {
                    row.also_request_ids.push(b.request_id.clone());
                }
            }
        }
        Ok(())
    }

    async fn is_hash_blocked(&self, key: &str) -> Result<bool> {
        Ok(self.upload_hash_blocks.lock().await.contains_key(key))
    }

    async fn delete_upload_hash_blocks_for_request(&self, request_id: &str) -> Result<()> {
        let mut rows = self.upload_hash_blocks.lock().await;
        for row in rows.values_mut() {
            row.also_request_ids.retain(|held| held != request_id);
            // Its own rows pass to the next holder, if any
            if row.request_id == request_id && !row.also_request_ids.is_empty() {
                row.request_id = row.also_request_ids.remove(0);
            }
        }
        // Rows no request holds any more go
        rows.retain(|_, row| row.request_id != request_id);
        Ok(())
    }
}
