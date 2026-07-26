use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{UploadPartRecord, UploadSession};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractUploadSessions: Sync + Send {
    /// Insert a freshly created session.
    ///
    /// The per-user open-session cap is enforced by the caller via
    /// [`Self::count_active_upload_sessions_for_user`] — a lost race there
    /// admits at most one extra session, which the cap tolerates (it is a
    /// resource guard, not an invariant).
    async fn insert_upload_session(&self, session: &UploadSession) -> Result<()>;

    /// Fetch a session by id, NotFound if it is gone.
    async fn fetch_upload_session(&self, id: &str) -> Result<UploadSession>;

    /// How many non-terminal (`Pending`/`Completing`) sessions a user holds.
    async fn count_active_upload_sessions_for_user(&self, uploader_id: &str) -> Result<u64>;

    /// ATOMICALLY claim a part index for one in-flight PUT.
    ///
    /// Succeeds only while the session is `Pending` AND the index has no
    /// claim fresher than `stale_cutoff` (a crashed PUT's claim ages out and
    /// becomes stealable). Returns the post-claim session, or `None` when
    /// the claim was refused — the caller re-fetches to distinguish "another
    /// PUT is in flight" from "state changed" for its error message.
    async fn try_claim_upload_part(
        &self,
        id: &str,
        part_key: &str,
        claimed_at: Timestamp,
        stale_cutoff: Timestamp,
    ) -> Result<Option<UploadSession>>;

    /// Record a part (etag + plaintext sha256 + size) and release its claim
    /// in one write. For part 1, `head_b64` carries the sniff bytes.
    ///
    /// Filtered on `state == Pending`, so a PUT that raced past a
    /// `complete`/abort cannot record anything afterwards — returns whether
    /// the write happened.
    async fn record_upload_part(
        &self,
        id: &str,
        part_key: &str,
        record: &UploadPartRecord,
        head_b64: Option<&str>,
    ) -> Result<bool>;

    /// Release a claim without recording (the PUT failed).
    async fn release_upload_part_claim(&self, id: &str, part_key: &str) -> Result<()>;

    /// The `Pending -> Completing` compare-and-set. Requires `in_flight`
    /// empty (no PUT may straddle completion) and persists the composite
    /// hash so a crashed `complete` can be resolved from the row alone.
    /// Returns the post-CAS session, or `None` if the CAS did not apply.
    async fn begin_upload_session_complete(
        &self,
        id: &str,
        composite_hash: &str,
    ) -> Result<Option<UploadSession>>;

    /// The `Completing -> Pending` rollback, clearing the composite hash.
    ///
    /// ONLY sound while `complete_multipart_upload` has provably not
    /// succeeded (the multipart upload still exists and no object is at the
    /// path) — after S3-complete, rolling back would strand an assembled
    /// object no pruner can see. Returns whether the row was still
    /// `Completing`.
    async fn revert_upload_session_to_pending(&self, id: &str) -> Result<bool>;

    /// Stamp terminal success and the minted file id. A retried `complete`
    /// returns this id instead of failing.
    async fn set_upload_session_completed(&self, id: &str, file_id: &str) -> Result<()>;

    /// Flip a `Pending` session to `Aborted` (user cancel). The DELETE
    /// handler does ONLY this state flip — the sweep performs the S3 abort
    /// with its retry semantics. Returns whether the row was `Pending`
    /// (a `Completing` session cannot be user-aborted; let `complete`
    /// resolve).
    async fn set_upload_session_aborted(&self, id: &str) -> Result<bool>;

    /// Sessions whose `expires_at` has passed, any state — the sweep
    /// branches on state to resolve each.
    async fn fetch_expired_upload_sessions(&self, before: Timestamp) -> Result<Vec<UploadSession>>;

    /// Remove a session row.
    async fn delete_upload_session(&self, id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::AbstractUploadSessions;
    use crate::{UploadPartRecord, UploadSession, UploadSessionState};
    use iso8601_timestamp::{Duration, Timestamp};

    fn session(uploader_id: &str) -> UploadSession {
        UploadSession::new(
            uploader_id.to_string(),
            "attachments".to_string(),
            "big.bin".to_string(),
            "application/octet-stream".to_string(),
            100,
            40,
            "revolt-uploads".to_string(),
            "s3-upload-id".to_string(),
            "bm9uY2U3Nzc=".to_string(),
        )
    }

    fn record(size: i64, marker: &str) -> UploadPartRecord {
        UploadPartRecord {
            size,
            etag: format!("etag-{marker}"),
            sha256: format!("sha-{marker}"),
        }
    }

    #[tokio::test]
    async fn round_trip_with_string_keyed_maps() {
        database_test!(|db| async move {
            let mut row = session("01USER000000000000000000000");
            row.parts
                .insert(UploadSession::part_key(1), record(40, "one"));
            row.in_flight
                .insert(UploadSession::part_key(2), Timestamp::now_utc());
            row.head_b64 = "aGVhZA==".to_string();
            db.insert_upload_session(&row).await.unwrap();

            let fetched = db.fetch_upload_session(&row.id).await.unwrap();
            assert_eq!(fetched.id, row.id);
            assert_eq!(fetched.state, UploadSessionState::Pending);
            assert_eq!(fetched.total_size, 100);
            assert_eq!(fetched.chunk_size, 40);
            assert_eq!(fetched.total_parts(), 3);
            assert_eq!(fetched.expected_part_size(3), Some(20));
            assert_eq!(fetched.expected_part_size(4), None);
            assert_eq!(fetched.parts.len(), 1);
            assert_eq!(fetched.parts["1"].etag, "etag-one");
            assert!(fetched.in_flight.contains_key("2"));
            assert_eq!(fetched.head_b64, "aGVhZA==");
            assert_eq!(fetched.composite_hash, None);
            assert_eq!(fetched.file_id, None);
        });
    }

    #[tokio::test]
    async fn claim_is_exclusive_until_stale() {
        database_test!(|db| async move {
            let row = session("01USER000000000000000000000");
            db.insert_upload_session(&row).await.unwrap();

            let now = Timestamp::now_utc();
            let stale_cutoff = now - Duration::minutes(10);

            // First claim wins, second is refused while fresh
            assert!(db
                .try_claim_upload_part(&row.id, "1", now, stale_cutoff)
                .await
                .unwrap()
                .is_some());
            assert!(db
                .try_claim_upload_part(&row.id, "1", now, stale_cutoff)
                .await
                .unwrap()
                .is_none());

            // A different index is unaffected
            assert!(db
                .try_claim_upload_part(&row.id, "2", now, stale_cutoff)
                .await
                .unwrap()
                .is_some());

            // Release makes it claimable again
            db.release_upload_part_claim(&row.id, "1").await.unwrap();
            assert!(db
                .try_claim_upload_part(&row.id, "1", now, stale_cutoff)
                .await
                .unwrap()
                .is_some());

            // A claim older than the cutoff is stealable
            let future_cutoff = now + Duration::minutes(1);
            assert!(db
                .try_claim_upload_part(&row.id, "1", now, future_cutoff)
                .await
                .unwrap()
                .is_some());
        });
    }

    #[tokio::test]
    async fn record_only_while_pending() {
        database_test!(|db| async move {
            let row = session("01USER000000000000000000000");
            db.insert_upload_session(&row).await.unwrap();

            let now = Timestamp::now_utc();
            let cutoff = now - Duration::minutes(10);
            db.try_claim_upload_part(&row.id, "1", now, cutoff)
                .await
                .unwrap()
                .unwrap();
            assert!(db
                .record_upload_part(&row.id, "1", &record(40, "one"), Some("aGVhZA=="))
                .await
                .unwrap());

            let fetched = db.fetch_upload_session(&row.id).await.unwrap();
            assert_eq!(fetched.parts["1"].sha256, "sha-one");
            assert!(fetched.in_flight.is_empty(), "record must release the claim");
            assert_eq!(fetched.head_b64, "aGVhZA==");

            // Aborted sessions accept nothing
            assert!(db.set_upload_session_aborted(&row.id).await.unwrap());
            assert!(!db
                .record_upload_part(&row.id, "2", &record(40, "two"), None)
                .await
                .unwrap());
            assert!(db
                .try_claim_upload_part(&row.id, "2", now, cutoff)
                .await
                .unwrap()
                .is_none());
        });
    }

    #[tokio::test]
    async fn complete_cas_requires_quiesced_session() {
        database_test!(|db| async move {
            let row = session("01USER000000000000000000000");
            db.insert_upload_session(&row).await.unwrap();

            let now = Timestamp::now_utc();
            let cutoff = now - Duration::minutes(10);

            // In-flight claim blocks the CAS
            db.try_claim_upload_part(&row.id, "1", now, cutoff)
                .await
                .unwrap()
                .unwrap();
            assert!(db
                .begin_upload_session_complete(&row.id, "composite")
                .await
                .unwrap()
                .is_none());

            db.release_upload_part_claim(&row.id, "1").await.unwrap();
            let completing = db
                .begin_upload_session_complete(&row.id, "composite")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(completing.state, UploadSessionState::Completing);
            assert_eq!(completing.composite_hash.as_deref(), Some("composite"));

            // Second CAS is refused (already Completing) — the owner's retry
            // path goes through the re-entrancy protocol instead
            assert!(db
                .begin_upload_session_complete(&row.id, "composite")
                .await
                .unwrap()
                .is_none());

            // A Completing session cannot be user-aborted
            assert!(!db.set_upload_session_aborted(&row.id).await.unwrap());

            // Rollback (pre-S3-complete only) clears the hash and re-arms
            assert!(db.revert_upload_session_to_pending(&row.id).await.unwrap());
            let reverted = db.fetch_upload_session(&row.id).await.unwrap();
            assert_eq!(reverted.state, UploadSessionState::Pending);
            assert_eq!(reverted.composite_hash, None);
            assert!(!db.revert_upload_session_to_pending(&row.id).await.unwrap());

            // Complete for real
            db.begin_upload_session_complete(&row.id, "composite")
                .await
                .unwrap()
                .unwrap();
            db.set_upload_session_completed(&row.id, "FILE0001")
                .await
                .unwrap();
            let done = db.fetch_upload_session(&row.id).await.unwrap();
            assert_eq!(done.state, UploadSessionState::Completed);
            assert_eq!(done.file_id.as_deref(), Some("FILE0001"));
        });
    }

    #[tokio::test]
    async fn active_count_and_expiry_sweep() {
        database_test!(|db| async move {
            let user = "01USER000000000000000000000";
            let other = "01OTHER00000000000000000000";

            let one = session(user);
            let two = session(user);
            let theirs = session(other);
            db.insert_upload_session(&one).await.unwrap();
            db.insert_upload_session(&two).await.unwrap();
            db.insert_upload_session(&theirs).await.unwrap();

            assert_eq!(
                db.count_active_upload_sessions_for_user(user).await.unwrap(),
                2
            );

            // Terminal states stop counting
            assert!(db.set_upload_session_aborted(&two.id).await.unwrap());
            assert_eq!(
                db.count_active_upload_sessions_for_user(user).await.unwrap(),
                1
            );

            // Nothing expired yet
            assert!(db
                .fetch_expired_upload_sessions(Timestamp::now_utc())
                .await
                .unwrap()
                .is_empty());

            // Far-future cutoff sees everything, any state
            let expired = db
                .fetch_expired_upload_sessions(Timestamp::now_utc() + Duration::hours(72))
                .await
                .unwrap();
            assert_eq!(expired.len(), 3);

            db.delete_upload_session(&one.id).await.unwrap();
            assert!(matches!(
                db.fetch_upload_session(&one.id).await,
                Err(err) if matches!(err.error_type, revolt_result::ErrorType::NotFound)
            ));
        });
    }
}
