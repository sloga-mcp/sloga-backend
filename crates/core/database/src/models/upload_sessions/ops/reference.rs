use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::ReferenceDb;
use crate::{UploadPartRecord, UploadSession, UploadSessionState};

use super::AbstractUploadSessions;

#[async_trait]
impl AbstractUploadSessions for ReferenceDb {
    async fn insert_upload_session(&self, session: &UploadSession) -> Result<()> {
        let mut rows = self.upload_sessions.lock().await;
        rows.insert(session.id.to_string(), session.clone());
        Ok(())
    }

    async fn fetch_upload_session(&self, id: &str) -> Result<UploadSession> {
        let rows = self.upload_sessions.lock().await;
        rows.get(id).cloned().ok_or_else(|| create_error!(NotFound))
    }

    async fn count_active_upload_sessions_for_user(&self, uploader_id: &str) -> Result<u64> {
        let rows = self.upload_sessions.lock().await;
        Ok(rows
            .values()
            .filter(|row| row.uploader_id == uploader_id && row.is_active())
            .count() as u64)
    }

    /// The whole check-then-claim runs while the map mutex is held — this
    /// driver's equivalent of Mongo's single-document find_one_and_update.
    async fn try_claim_upload_part(
        &self,
        id: &str,
        part_key: &str,
        claimed_at: Timestamp,
        stale_cutoff: Timestamp,
    ) -> Result<Option<UploadSession>> {
        let mut rows = self.upload_sessions.lock().await;
        let Some(row) = rows.get_mut(id) else {
            return Ok(None);
        };
        if !matches!(row.state, UploadSessionState::Pending) {
            return Ok(None);
        }
        if let Some(existing) = row.in_flight.get(part_key) {
            if *existing >= stale_cutoff {
                return Ok(None);
            }
        }
        row.in_flight.insert(part_key.to_string(), claimed_at);
        Ok(Some(row.clone()))
    }

    async fn record_upload_part(
        &self,
        id: &str,
        part_key: &str,
        record: &UploadPartRecord,
        head_b64: Option<&str>,
    ) -> Result<bool> {
        let mut rows = self.upload_sessions.lock().await;
        match rows.get_mut(id) {
            Some(row) if matches!(row.state, UploadSessionState::Pending) => {
                row.parts.insert(part_key.to_string(), record.clone());
                row.in_flight.remove(part_key);
                if let Some(head) = head_b64 {
                    row.head_b64 = head.to_string();
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn release_upload_part_claim(&self, id: &str, part_key: &str) -> Result<()> {
        let mut rows = self.upload_sessions.lock().await;
        if let Some(row) = rows.get_mut(id) {
            row.in_flight.remove(part_key);
        }
        Ok(())
    }

    async fn begin_upload_session_complete(
        &self,
        id: &str,
        composite_hash: &str,
    ) -> Result<Option<UploadSession>> {
        let mut rows = self.upload_sessions.lock().await;
        match rows.get_mut(id) {
            Some(row)
                if matches!(row.state, UploadSessionState::Pending)
                    && row.in_flight.is_empty() =>
            {
                row.state = UploadSessionState::Completing;
                row.composite_hash = Some(composite_hash.to_string());
                Ok(Some(row.clone()))
            }
            _ => Ok(None),
        }
    }

    async fn revert_upload_session_to_pending(&self, id: &str) -> Result<bool> {
        let mut rows = self.upload_sessions.lock().await;
        match rows.get_mut(id) {
            Some(row) if matches!(row.state, UploadSessionState::Completing) => {
                row.state = UploadSessionState::Pending;
                row.composite_hash = None;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn set_upload_session_completed(&self, id: &str, file_id: &str) -> Result<()> {
        let mut rows = self.upload_sessions.lock().await;
        if let Some(row) = rows.get_mut(id) {
            row.state = UploadSessionState::Completed;
            row.file_id = Some(file_id.to_string());
        }
        Ok(())
    }

    async fn set_upload_session_aborted(&self, id: &str) -> Result<bool> {
        let mut rows = self.upload_sessions.lock().await;
        match rows.get_mut(id) {
            Some(row) if matches!(row.state, UploadSessionState::Pending) => {
                row.state = UploadSessionState::Aborted;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn fetch_expired_upload_sessions(&self, before: Timestamp) -> Result<Vec<UploadSession>> {
        let rows = self.upload_sessions.lock().await;
        Ok(rows
            .values()
            .filter(|row| row.expires_at < before)
            .cloned()
            .collect())
    }

    async fn delete_upload_session(&self, id: &str) -> Result<()> {
        let mut rows = self.upload_sessions.lock().await;
        rows.remove(id);
        Ok(())
    }
}
