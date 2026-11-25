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

    /// Fetch an attachment by its id, whatever its tag, `deleted` or
    /// `reported` state.
    async fn fetch_attachment_by_id(&self, id: &str) -> Result<File>;

    /// Fetch every attachment whose original `hash` is in `hashes`, in any
    /// state (deleted and hidden rows included). Order is not guaranteed; an
    /// empty slice gives an empty list.
    async fn fetch_attachments_by_hashes(&self, hashes: &[String]) -> Result<Vec<File>>;

    /// Hide attachments but keep the stored objects: sets `deleted` AND
    /// `reported`, so the upload server stops serving them and the file
    /// deletion task skips them. Unknown ids are ignored; an empty slice is a
    /// no-op.
    async fn hide_attachments(&self, ids: &[String]) -> Result<()>;

    /// Undo [`Self::hide_attachments`]: sets `deleted` to false and leaves
    /// `reported` as it is. Unknown ids are ignored; an empty slice is a
    /// no-op.
    async fn unhide_attachments(&self, ids: &[String]) -> Result<()>;

    /// End a hold: sets `reported` to false and leaves `deleted` as it is,
    /// so a hidden file becomes eligible for the file deletion task. Unknown
    /// ids are ignored; an empty slice is a no-op.
    async fn release_attachment_hold(&self, ids: &[String]) -> Result<()>;
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

/// Hidden-but-kept state used by Take It Down removals and holds.
#[cfg(test)]
mod hold_tests {
    use revolt_result::ErrorType;

    use crate::{File, Metadata};

    const HASH_A: &str = "hash-a";
    const HASH_B: &str = "hash-b";

    fn file(id: &str, tag: &str, hash: Option<&str>) -> File {
        File {
            id: id.to_string(),
            tag: tag.to_string(),
            filename: "image.png".to_string(),
            hash: hash.map(str::to_string),
            uploaded_at: None,
            uploader_id: None,
            used_for: None,
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

    fn ids(files: Vec<File>) -> Vec<String> {
        let mut ids: Vec<String> = files.into_iter().map(|file| file.id).collect();
        ids.sort();
        ids
    }

    async fn sweep_ids(db: &crate::Database) -> Vec<String> {
        ids(db.fetch_deleted_attachments().await.unwrap())
    }

    async fn flags(db: &crate::Database, id: &str) -> (Option<bool>, Option<bool>) {
        let file = db.fetch_attachment_by_id(id).await.unwrap();
        (file.deleted, file.reported)
    }

    #[tokio::test]
    async fn hidden_files_are_kept_until_the_hold_is_released() {
        database_test!(|db| async move {
            let hidden = "01HIDDEN000000000000000001";
            let bystander = "01BYSTANDER000000000000001";
            let deleted = "01DELETED00000000000000001";
            db.insert_attachment(&file(hidden, "attachments", Some(HASH_A)))
                .await
                .unwrap();
            db.insert_attachment(&file(bystander, "attachments", Some(HASH_A)))
                .await
                .unwrap();
            db.insert_attachment(&file(deleted, "attachments", None))
                .await
                .unwrap();
            db.mark_attachment_as_deleted(deleted).await.unwrap();

            // Control: an ordinary delete is picked up by the sweep
            assert_eq!(sweep_ids(&db).await, vec![deleted.to_string()]);

            db.hide_attachments(&[hidden.to_string(), "01NOSUCHFILE00000000000001".to_string()])
                .await
                .expect("unknown ids are not an error");
            assert_eq!(flags(&db, hidden).await, (Some(true), Some(true)));
            assert_eq!(flags(&db, bystander).await, (None, None));

            // Hidden but kept: the sweep never sees it
            assert_eq!(sweep_ids(&db).await, vec![deleted.to_string()]);

            db.release_attachment_hold(&[hidden.to_string()])
                .await
                .unwrap();
            assert_eq!(flags(&db, hidden).await, (Some(true), Some(false)));
            assert_eq!(
                sweep_ids(&db).await,
                vec![deleted.to_string(), hidden.to_string()]
            );
            assert_eq!(flags(&db, bystander).await, (None, None));
        });
    }

    #[tokio::test]
    async fn unhide_restores_the_file_and_keeps_the_hold() {
        database_test!(|db| async move {
            let hidden = "01HIDDEN000000000000000002";
            let other = "01OTHERHIDDEN0000000000002";
            db.insert_attachment(&file(hidden, "attachments", Some(HASH_A)))
                .await
                .unwrap();
            db.insert_attachment(&file(other, "attachments", Some(HASH_A)))
                .await
                .unwrap();
            db.hide_attachments(&[hidden.to_string(), other.to_string()])
                .await
                .unwrap();

            db.unhide_attachments(&[hidden.to_string()]).await.unwrap();
            assert_eq!(flags(&db, hidden).await, (Some(false), Some(true)));
            assert_eq!(flags(&db, other).await, (Some(true), Some(true)));

            // Neither is swept: one is live again, the other still held
            assert!(sweep_ids(&db).await.is_empty());

            // Releasing the hold of a live file does not delete it
            db.release_attachment_hold(&[hidden.to_string()])
                .await
                .unwrap();
            assert_eq!(flags(&db, hidden).await, (Some(false), Some(false)));
            assert!(sweep_ids(&db).await.is_empty());
        });
    }

    #[tokio::test]
    async fn empty_and_unknown_id_lists_are_no_ops() {
        database_test!(|db| async move {
            let id = "01UNTOUCHED000000000000003";
            db.insert_attachment(&file(id, "attachments", Some(HASH_A)))
                .await
                .unwrap();

            db.hide_attachments(&[]).await.unwrap();
            db.unhide_attachments(&[]).await.unwrap();
            db.release_attachment_hold(&[]).await.unwrap();

            let unknown = ["01NOSUCHFILE00000000000003".to_string()];
            db.hide_attachments(&unknown).await.unwrap();
            db.unhide_attachments(&unknown).await.unwrap();
            db.release_attachment_hold(&unknown).await.unwrap();

            assert_eq!(flags(&db, id).await, (None, None));
            assert!(db
                .fetch_attachment_by_id("01NOSUCHFILE00000000000003")
                .await
                .is_err());
        });
    }

    #[tokio::test]
    async fn fetch_attachment_by_id_ignores_tag_and_state() {
        database_test!(|db| async move {
            let avatar = "01AVATAR000000000000000004";
            let hidden = "01HIDDEN000000000000000004";
            db.insert_attachment(&file(avatar, "avatars", None))
                .await
                .unwrap();
            db.insert_attachment(&file(hidden, "attachments", Some(HASH_A)))
                .await
                .unwrap();
            db.hide_attachments(&[hidden.to_string()]).await.unwrap();

            assert_eq!(
                db.fetch_attachment_by_id(avatar).await.unwrap(),
                file(avatar, "avatars", None)
            );
            let fetched = db.fetch_attachment_by_id(hidden).await.unwrap();
            assert_eq!(fetched.tag, "attachments");
            assert_eq!(fetched.deleted, Some(true));

            let err = db
                .fetch_attachment_by_id("01NOSUCHFILE00000000000004")
                .await
                .expect_err("missing file");
            assert!(matches!(err.error_type, ErrorType::NotFound), "{err:?}");
        });
    }

    #[tokio::test]
    async fn fetch_attachments_by_hashes_returns_every_state() {
        database_test!(|db| async move {
            let live = "01LIVE00000000000000000005";
            let deleted = "01DELETED00000000000000005";
            let hidden = "01HIDDEN000000000000000005";
            let other_hash = "01OTHERHASH000000000000005";
            let no_hash = "01NOHASH000000000000000005";
            db.insert_attachment(&file(live, "attachments", Some(HASH_A)))
                .await
                .unwrap();
            db.insert_attachment(&file(deleted, "avatars", Some(HASH_A)))
                .await
                .unwrap();
            db.insert_attachment(&file(hidden, "attachments", Some(HASH_A)))
                .await
                .unwrap();
            db.insert_attachment(&file(other_hash, "attachments", Some(HASH_B)))
                .await
                .unwrap();
            db.insert_attachment(&file(no_hash, "attachments", None))
                .await
                .unwrap();
            db.mark_attachment_as_deleted(deleted).await.unwrap();
            db.hide_attachments(&[hidden.to_string()]).await.unwrap();

            let mut expected_a = vec![live.to_string(), deleted.to_string(), hidden.to_string()];
            expected_a.sort();
            assert_eq!(
                ids(db
                    .fetch_attachments_by_hashes(&[HASH_A.to_string()])
                    .await
                    .unwrap()),
                expected_a
            );

            let mut expected_ab = expected_a;
            expected_ab.push(other_hash.to_string());
            expected_ab.sort();
            assert_eq!(
                ids(db
                    .fetch_attachments_by_hashes(&[
                        HASH_A.to_string(),
                        HASH_B.to_string(),
                        "hash-unknown".to_string(),
                    ])
                    .await
                    .unwrap()),
                expected_ab
            );

            assert!(db
                .fetch_attachments_by_hashes(&[])
                .await
                .unwrap()
                .is_empty());
            assert!(db
                .fetch_attachments_by_hashes(&["hash-unknown".to_string()])
                .await
                .unwrap()
                .is_empty());
        });
    }
}
