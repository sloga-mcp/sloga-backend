use bson::{Bson, Document};
use futures::StreamExt;
use iso8601_timestamp::Timestamp;
use mongodb::options::{FindOneAndUpdateOptions, ReturnDocument};
use revolt_result::Result;

use crate::MongoDb;
use crate::{UploadPartRecord, UploadSession, UploadSessionState};

use super::AbstractUploadSessions;

static COL: &str = "upload_sessions";

/// Typed collection writes serialize `Timestamp` through bson's
/// NON-human-readable serde path: Int64 unix-milliseconds. Every hand-built
/// document ($set claims, $lt cutoffs) MUST use the same encoding —
/// `bson::to_bson` would emit an ISO STRING and a `$lt` across BSON types
/// silently matches nothing. Same helper (and trap) as the import-job ops.
fn timestamp_bson(at: &Timestamp) -> Bson {
    Bson::Int64(
        at.duration_since(Timestamp::UNIX_EPOCH)
            .whole_milliseconds() as i64,
    )
}

fn active_states() -> Bson {
    Bson::Array(vec![
        Bson::String(UploadSessionState::Pending.as_variant_str().to_string()),
        Bson::String(UploadSessionState::Completing.as_variant_str().to_string()),
    ])
}

fn part_record_document(record: &UploadPartRecord) -> Document {
    doc! {
        "size": record.size,
        "etag": &record.etag,
        "sha256": &record.sha256,
    }
}

#[async_trait]
impl AbstractUploadSessions for MongoDb {
    async fn insert_upload_session(&self, session: &UploadSession) -> Result<()> {
        query!(self, insert_one, COL, &session).map(|_| ())
    }

    async fn fetch_upload_session(&self, id: &str) -> Result<UploadSession> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    async fn count_active_upload_sessions_for_user(&self, uploader_id: &str) -> Result<u64> {
        self.col::<UploadSession>(COL)
            .count_documents(doc! {
                "uploader_id": uploader_id,
                "state": { "$in": active_states() }
            })
            .await
            .map_err(|_| create_database_error!("count_documents", COL))
    }

    /// The match on state + claim freshness and the claim write happen under
    /// one document lock — two PUTs racing the same index get one winner.
    async fn try_claim_upload_part(
        &self,
        id: &str,
        part_key: &str,
        claimed_at: Timestamp,
        stale_cutoff: Timestamp,
    ) -> Result<Option<UploadSession>> {
        let claim_field = format!("in_flight.{part_key}");
        self.col::<UploadSession>(COL)
            .find_one_and_update(
                doc! {
                    "_id": id,
                    "state": UploadSessionState::Pending.as_variant_str(),
                    "$or": [
                        { &claim_field: { "$exists": false } },
                        { &claim_field: { "$lt": timestamp_bson(&stale_cutoff) } },
                    ]
                },
                doc! {
                    "$set": { &claim_field: timestamp_bson(&claimed_at) }
                },
            )
            .with_options(
                FindOneAndUpdateOptions::builder()
                    .return_document(ReturnDocument::After)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_one_and_update", COL))
    }

    async fn record_upload_part(
        &self,
        id: &str,
        part_key: &str,
        record: &UploadPartRecord,
        head_b64: Option<&str>,
    ) -> Result<bool> {
        let mut set = doc! {
            format!("parts.{part_key}"): part_record_document(record),
        };
        if let Some(head) = head_b64 {
            set.insert("head_b64", head);
        }

        self.col::<UploadSession>(COL)
            .update_one(
                // `state: Pending` in the filter is what stops a PUT that
                // raced past a complete/abort from recording anything
                doc! {
                    "_id": id,
                    "state": UploadSessionState::Pending.as_variant_str(),
                },
                doc! {
                    "$set": set,
                    "$unset": { format!("in_flight.{part_key}"): "" },
                },
            )
            .await
            .map(|result| result.matched_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    async fn release_upload_part_claim(&self, id: &str, part_key: &str) -> Result<()> {
        self.col::<UploadSession>(COL)
            .update_one(
                doc! { "_id": id },
                doc! { "$unset": { format!("in_flight.{part_key}"): "" } },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// CAS `Pending -> Completing`: state check, quiescence check
    /// (`in_flight` empty) and the flip happen under one document lock.
    async fn begin_upload_session_complete(
        &self,
        id: &str,
        composite_hash: &str,
    ) -> Result<Option<UploadSession>> {
        self.col::<UploadSession>(COL)
            .find_one_and_update(
                doc! {
                    "_id": id,
                    "state": UploadSessionState::Pending.as_variant_str(),
                    // Equality match on the empty document: no straddling PUT
                    "in_flight": Document::new(),
                },
                doc! {
                    "$set": {
                        "state": UploadSessionState::Completing.as_variant_str(),
                        "composite_hash": composite_hash,
                    }
                },
            )
            .with_options(
                FindOneAndUpdateOptions::builder()
                    .return_document(ReturnDocument::After)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_one_and_update", COL))
    }

    async fn revert_upload_session_to_pending(&self, id: &str) -> Result<bool> {
        self.col::<UploadSession>(COL)
            .update_one(
                doc! {
                    "_id": id,
                    "state": UploadSessionState::Completing.as_variant_str(),
                },
                doc! {
                    "$set": { "state": UploadSessionState::Pending.as_variant_str() },
                    "$unset": { "composite_hash": "" },
                },
            )
            .await
            .map(|result| result.matched_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    async fn set_upload_session_completed(&self, id: &str, file_id: &str) -> Result<()> {
        self.col::<UploadSession>(COL)
            .update_one(
                doc! { "_id": id },
                doc! {
                    "$set": {
                        "state": UploadSessionState::Completed.as_variant_str(),
                        "file_id": file_id,
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    async fn set_upload_session_aborted(&self, id: &str) -> Result<bool> {
        self.col::<UploadSession>(COL)
            .update_one(
                doc! {
                    "_id": id,
                    "state": UploadSessionState::Pending.as_variant_str(),
                },
                doc! {
                    "$set": { "state": UploadSessionState::Aborted.as_variant_str() }
                },
            )
            .await
            .map(|result| result.matched_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    async fn fetch_expired_upload_sessions(&self, before: Timestamp) -> Result<Vec<UploadSession>> {
        Ok(self
            .col::<UploadSession>(COL)
            .find(doc! {
                "expires_at": { "$lt": timestamp_bson(&before) }
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    async fn delete_upload_session(&self, id: &str) -> Result<()> {
        self.col::<UploadSession>(COL)
            .delete_one(doc! { "_id": id })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_one", COL))
    }
}
