use revolt_result::Result;

use crate::File;
use crate::FileUsedFor;
use crate::FileUsedForType;
use crate::ReferenceDb;

use super::AbstractAttachments;

#[async_trait]
impl AbstractAttachments for ReferenceDb {
    /// Insert attachment into database.
    async fn insert_attachment(&self, attachment: &File) -> Result<()> {
        let mut attachments = self.files.lock().await;
        if attachments.contains_key(&attachment.id) {
            Err(create_database_error!("insert", "attachment"))
        } else {
            attachments.insert(attachment.id.to_string(), attachment.clone());
            Ok(())
        }
    }

    /// Fetch an attachment by its id.
    async fn fetch_attachment(&self, tag: &str, file_id: &str) -> Result<File> {
        let files = self.files.lock().await;
        if let Some(file) = files.get(file_id) {
            if file.tag == tag {
                Ok(file.clone())
            } else {
                Err(create_error!(NotFound))
            }
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Fetch all deleted attachments.
    async fn fetch_deleted_attachments(&self) -> Result<Vec<File>> {
        let files = self.files.lock().await;
        Ok(files
            .values()
            .filter(|file| {
                // file has been marked as deleted
                file.deleted.is_some_and(|v| v)
                    // and it has not been reported
                    && !file.reported.is_some_and(|v| v)
            })
            .cloned()
            .collect())
    }

    /// Fetch all dangling attachments.
    async fn fetch_dangling_files(&self) -> Result<Vec<File>> {
        let files = self.files.lock().await;
        Ok(files
            .values()
            .filter(|file| file.used_for.is_none() && !file.deleted.is_some_and(|v| v))
            .cloned()
            .collect())
    }

    /// Fetch message attachments larger than `min_size` bytes that are not yet deleted.
    async fn fetch_large_message_attachments(&self, min_size: usize) -> Result<Vec<File>> {
        let files = self.files.lock().await;
        Ok(files
            .values()
            .filter(|file| {
                file.used_for
                    .as_ref()
                    .is_some_and(|used_for| used_for.object_type == FileUsedForType::Message)
                    && file.size > min_size as isize
                    && !file.deleted.is_some_and(|v| v)
            })
            .cloned()
            .collect())
    }

    /// Count references to a given hash.
    async fn count_file_hash_references(&self, hash: &str) -> Result<usize> {
        let files = self.files.lock().await;
        Ok(files
            .values()
            .filter(|file| file.hash.as_ref().is_some_and(|h| h == hash))
            .cloned()
            .count())
    }

    /// Find an attachment by its details and mark it as used by a given parent.
    async fn find_and_use_attachment(
        &self,
        id: &str,
        tag: &str,
        used_for: FileUsedFor,
        uploader_id: String,
    ) -> Result<File> {
        let mut files = self.files.lock().await;
        if let Some(file) = files.get_mut(id) {
            // Claim-once: match the tag AND require the file to be unclaimed, mirroring the
            // Mongo driver's `used_for: {$exists: false}` filter. Without the `used_for`
            // check a file already claimed by one parent could be re-pointed/stolen into
            // another — this keeps the Reference mock a faithful oracle for that guarantee.
            if file.tag == tag && file.used_for.is_none() {
                file.uploader_id = Some(uploader_id);
                file.used_for = Some(used_for);

                Ok(file.clone())
            } else {
                Err(create_error!(NotFound))
            }
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Repoint an already-claimed attachment's `used_for.id` at a new parent.
    async fn retarget_attachment(&self, id: &str, new_parent_id: &str) -> Result<()> {
        let mut files = self.files.lock().await;
        if let Some(file) = files.get_mut(id) {
            if let Some(used_for) = &mut file.used_for {
                used_for.id = new_parent_id.to_string();
            }
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Mark an attachment as having been reported.
    async fn mark_attachment_as_reported(&self, id: &str) -> Result<()> {
        let mut files = self.files.lock().await;
        if let Some(file) = files.get_mut(id) {
            file.reported = Some(true);
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Mark an attachment as having been deleted.
    async fn mark_attachment_as_deleted(&self, id: &str) -> Result<()> {
        let mut files = self.files.lock().await;
        if let Some(file) = files.get_mut(id) {
            file.deleted = Some(true);
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Mark multiple attachments as having been deleted.
    async fn mark_attachments_as_deleted(&self, ids: &[String]) -> Result<()> {
        let mut files = self.files.lock().await;

        for id in ids {
            if !files.contains_key(id) {
                return Err(create_error!(NotFound));
            }
        }

        for id in ids {
            if let Some(file) = files.get_mut(id) {
                file.deleted = Some(true);
            }
        }

        Ok(())
    }

    /// Delete the attachment entry.
    async fn delete_attachment(&self, id: &str) -> Result<()> {
        let mut files = self.files.lock().await;
        if files.remove(id).is_some() {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }
}
