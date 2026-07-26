use std::time::Duration;

use revolt_database::{iso8601_timestamp::Timestamp, Database, UploadSession, UploadSessionState};
use revolt_files::{abort_multipart_in_s3, delete_from_s3, object_exists_in_s3};
use revolt_result::Result;
use tokio::time::sleep;

/// Reap expired chunked-upload sessions (the primary cleanup; MinIO's
/// `stale_uploads_expiry` = 72 h is only the backstop behind this).
///
/// S3 work first, row second — a failed S3 call keeps the row for the next
/// sweep instead of orphaning parts or objects. Branches on state because an
/// expired session can be stranded anywhere in its lifecycle:
///
/// - `Completed`: the object belongs to a live `FileHash`; only the row
///   (kept until now for complete-retry idempotency) is deleted.
/// - `Completing`: a `complete` crashed. If the composite hash row exists,
///   the object is owned and live — drop the row. If instead an assembled
///   object exists with NO hash row, it is invisible to every pruner and
///   must be deleted here, along with the multipart state. Otherwise plain
///   abort.
/// - `Pending`/`Aborted`: abort the multipart upload (a missing upload —
///   already reaped — is success).
async fn resolve(db: &Database, session: &UploadSession) -> Result<()> {
    match session.state {
        UploadSessionState::Completed => {}
        UploadSessionState::Completing => {
            let hash_owned = match &session.composite_hash {
                Some(composite) => db
                    .fetch_attachment_hash(composite)
                    .await
                    .map(|hash| !hash.iv.is_empty())
                    .unwrap_or(false),
                None => false,
            };

            if !hash_owned {
                if object_exists_in_s3(&session.bucket_id, &session.path).await? {
                    // Assembled but never registered — nothing else can ever
                    // find or delete this object
                    delete_from_s3(&session.bucket_id, &session.path).await?;
                }
                abort_multipart_in_s3(&session.bucket_id, &session.path, &session.s3_upload_id)
                    .await?;
            }
        }
        UploadSessionState::Pending | UploadSessionState::Aborted => {
            abort_multipart_in_s3(&session.bucket_id, &session.path, &session.s3_upload_id)
                .await?;
        }
    }

    db.delete_upload_session(&session.id).await
}

pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    loop {
        let mut swept = 0;
        for session in db
            .fetch_expired_upload_sessions(Timestamp::now_utc())
            .await?
        {
            match resolve(&db, &session).await {
                Ok(()) => swept += 1,
                Err(error) => {
                    log::error!(
                        "failed to reap upload session {} (state {:?}, will retry next sweep): {error:?}",
                        session.id,
                        session.state
                    );
                }
            }
        }
        log::info!("Reaped {swept} expired upload sessions");

        sleep(Duration::from_secs(60 * 60)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revolt_database::UploadSessionState;

    fn test_env() {
        std::env::set_var("REVOLT_FILES__S3__DEFAULT_BUCKET", "autumn-upload-tests");
    }

    async fn ensure_bucket() {
        use revolt_files::{EncryptionKey, FileStorageRepository, S3Storage};
        let storage = S3Storage::from_config(EncryptionKey::from_config().await).await;
        let _ = storage.create_bucket("autumn-upload-tests").await;
    }

    fn expired_session(state: UploadSessionState, s3_upload_id: String) -> UploadSession {
        let mut session = UploadSession::new(
            ulid::Ulid::new().to_string(),
            "attachments".into(),
            "swept.bin".into(),
            "application/octet-stream".into(),
            64 * 1024 * 1024,
            32 * 1024 * 1024,
            "autumn-upload-tests".into(),
            s3_upload_id,
            "bm9uY2U3Nzc=".into(),
        );
        session.state = state;
        session.expires_at = Timestamp::UNIX_EPOCH;
        session
    }

    #[tokio::test]
    async fn sweep_aborts_pending_and_deletes_orphaned_completing_objects() {
        test_env();
        ensure_bucket().await;
        let db = Database::Reference(Default::default());

        // A pending session with real multipart state: resolve aborts the
        // upload (idempotently) and removes the row
        let upload_id =
            revolt_files::create_multipart_in_s3("autumn-upload-tests", "chunked/sweep-pending")
                .await
                .unwrap();
        let mut pending = expired_session(UploadSessionState::Pending, upload_id);
        pending.path = "chunked/sweep-pending".into();
        db.insert_upload_session(&pending).await.unwrap();

        resolve(&db, &pending).await.unwrap();
        assert!(db.fetch_upload_session(&pending.id).await.is_err());

        // A completing session whose assembled object was never registered:
        // the object is invisible to every pruner — the sweep must delete it
        let upload_id =
            revolt_files::create_multipart_in_s3("autumn-upload-tests", "chunked/sweep-orphan")
                .await
                .unwrap();
        let etag = revolt_files::upload_part_to_s3(
            "autumn-upload-tests",
            "chunked/sweep-orphan",
            &upload_id,
            1,
            vec![7u8; 5 * 1024 * 1024],
        )
        .await
        .unwrap();
        revolt_files::complete_multipart_in_s3(
            "autumn-upload-tests",
            "chunked/sweep-orphan",
            &upload_id,
            &[(1, etag)],
        )
        .await
        .unwrap();
        assert!(
            object_exists_in_s3("autumn-upload-tests", "chunked/sweep-orphan")
                .await
                .unwrap()
        );

        let mut orphan = expired_session(UploadSessionState::Completing, upload_id);
        orphan.path = "chunked/sweep-orphan".into();
        orphan.composite_hash = Some("no-such-hash-row".into());
        db.insert_upload_session(&orphan).await.unwrap();

        resolve(&db, &orphan).await.unwrap();
        assert!(db.fetch_upload_session(&orphan.id).await.is_err());
        assert!(
            !object_exists_in_s3("autumn-upload-tests", "chunked/sweep-orphan")
                .await
                .unwrap(),
            "orphaned assembled object must be deleted by the sweep"
        );

        // Completed rows are metadata-only deletions
        let done = expired_session(UploadSessionState::Completed, "gone".into());
        db.insert_upload_session(&done).await.unwrap();
        resolve(&db, &done).await.unwrap();
        assert!(db.fetch_upload_session(&done.id).await.is_err());
    }
}
