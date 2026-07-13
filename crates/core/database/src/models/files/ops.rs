use revolt_result::Result;

use crate::File;

use super::FileUsedFor;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractAttachments: Sync + Send {
    /// Insert attachment into database.
    async fn insert_attachment(&self, attachment: &File) -> Result<()>;

    /// Fetch an attachment by its id.
    async fn fetch_attachment(&self, tag: &str, file_id: &str) -> Result<File>;

    /// Fetch all deleted attachments.
    async fn fetch_deleted_attachments(&self) -> Result<Vec<File>>;

    /// Fetch all dangling attachments.
    async fn fetch_dangling_files(&self) -> Result<Vec<File>>;

    /// Fetch message attachments larger than `min_size` bytes that are not yet deleted.
    async fn fetch_large_message_attachments(&self, min_size: usize) -> Result<Vec<File>>;

    /// Count references to a given hash.
    async fn count_file_hash_references(&self, hash: &str) -> Result<usize>;

    /// Find an attachment by its details and mark it as used by a given parent.
    async fn find_and_use_attachment(
        &self,
        id: &str,
        tag: &str,
        used_for: FileUsedFor,
        uploader_id: String,
    ) -> Result<File>;

    /// Repoint an already-claimed attachment's `used_for.id` at a new
    /// parent. Used by scheduled-message delivery: attachments are claimed
    /// against the scheduled row at schedule time (so the dangling-file
    /// sweep can't collect them) and retargeted to the real message id at
    /// fire time.
    async fn retarget_attachment(&self, id: &str, new_parent_id: &str) -> Result<()>;

    /// Mark an attachment as having been reported.
    async fn mark_attachment_as_reported(&self, id: &str) -> Result<()>;

    /// Mark an attachment as having been deleted.
    async fn mark_attachment_as_deleted(&self, id: &str) -> Result<()>;

    /// Mark multiple attachments as having been deleted.
    async fn mark_attachments_as_deleted(&self, ids: &[String]) -> Result<()>;

    /// Delete the attachment entry.
    async fn delete_attachment(&self, id: &str) -> Result<()>;
}
