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

    /// Mark every attachment whose `used_for.id` is in `used_for_ids` as
    /// deleted, the same soft delete server deletion applies to files used by
    /// the server; the file deletion task then removes the stored objects.
    /// Files with no `used_for` never match. Ids that match nothing are not an
    /// error, and an empty slice is a no-op.
    ///
    /// Server deletion only detaches emojis, and emoji files are used by the
    /// emoji id rather than the server id, so a rollback that discards emojis
    /// passes their ids here.
    async fn delete_attachments_used_by(&self, used_for_ids: &[String]) -> Result<()>;

    /// Delete the attachment entry.
    async fn delete_attachment(&self, id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use crate::{File, FileUsedFor, FileUsedForType, Metadata};

    const EMOJI_A: &str = "01EMOJIA000000000000000001";
    const EMOJI_B: &str = "01EMOJIB000000000000000001";
    const EMOJI_C: &str = "01EMOJIC000000000000000001";
    const SERVER_S: &str = "01SERVERS00000000000000001";

    fn file(id: &str, used_for: Option<(FileUsedForType, &str)>) -> File {
        File {
            id: id.to_string(),
            tag: "emojis".to_string(),
            filename: "emoji.png".to_string(),
            hash: None,
            uploaded_at: None,
            uploader_id: None,
            used_for: used_for.map(|(object_type, id)| FileUsedFor {
                object_type,
                id: id.to_string(),
            }),
            deleted: None,
            reported: None,
            metadata: Metadata::File,
            content_type: "image/png".to_string(),
            size: 1,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        }
    }

    /// Ids of the files the file deletion task would pick up, sorted.
    async fn deleted_ids(db: &crate::Database) -> Vec<String> {
        let mut ids: Vec<String> = db
            .fetch_deleted_attachments()
            .await
            .unwrap()
            .into_iter()
            .map(|file| file.id)
            .collect();
        ids.sort();
        ids
    }

    #[tokio::test]
    async fn delete_attachments_used_by_marks_only_the_listed_parents() {
        database_test!(|db| async move {
            let files = [
                file(
                    "01FILEA0000000000000000001",
                    Some((FileUsedForType::Emoji, EMOJI_A)),
                ),
                file(
                    "01FILEB0000000000000000001",
                    Some((FileUsedForType::Emoji, EMOJI_B)),
                ),
                file(
                    "01FILEC0000000000000000001",
                    Some((FileUsedForType::Emoji, EMOJI_C)),
                ),
                file(
                    "01FILES0000000000000000001",
                    Some((FileUsedForType::ServerIcon, SERVER_S)),
                ),
                // Unclaimed: no `used_for` at all.
                file("01FILEU0000000000000000001", None),
                // A file whose own id equals a listed emoji id but is used by
                // something else: the filter is on `used_for.id`, not `_id`.
                file(EMOJI_A, Some((FileUsedForType::ServerBanner, SERVER_S))),
            ];
            for file in &files {
                db.insert_attachment(file).await.unwrap();
            }

            // Empty slice: Ok, nothing marked.
            db.delete_attachments_used_by(&[]).await.unwrap();
            assert!(deleted_ids(&db).await.is_empty());

            // An id that matches nothing is not an error.
            db.delete_attachments_used_by(&[
                EMOJI_A.to_string(),
                EMOJI_B.to_string(),
                "01NOSUCHPARENT000000000001".to_string(),
            ])
            .await
            .unwrap();

            assert_eq!(
                deleted_ids(&db).await,
                vec![
                    "01FILEA0000000000000000001".to_string(),
                    "01FILEB0000000000000000001".to_string(),
                ]
            );

            for (id, tag) in [
                ("01FILEC0000000000000000001", "emojis"),
                ("01FILES0000000000000000001", "emojis"),
                ("01FILEU0000000000000000001", "emojis"),
                (EMOJI_A, "emojis"),
            ] {
                let untouched = db.fetch_attachment(tag, id).await.unwrap();
                assert_eq!(untouched.deleted, None, "{id} was touched");
            }

            // The rows stay until the file deletion task removes them, and
            // nothing else on them changes.
            let marked = db
                .fetch_attachment("emojis", "01FILEA0000000000000000001")
                .await
                .unwrap();
            assert_eq!(marked.deleted, Some(true));
            assert_eq!(marked.used_for, files[0].used_for);

            // Repeating the call is harmless.
            db.delete_attachments_used_by(&[EMOJI_A.to_string()])
                .await
                .unwrap();
            assert_eq!(deleted_ids(&db).await.len(), 2);
        });
    }
}
