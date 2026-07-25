use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::ReferenceDb;
use crate::{DiscordImportJob, ImportStatus};

use super::AbstractDiscordImportJobs;

#[async_trait]
impl AbstractDiscordImportJobs for ReferenceDb {
    /// Insert a newly queued import job, enforcing one active import per
    /// user.
    async fn insert_discord_import_job(&self, job: &DiscordImportJob) -> Result<()> {
        // Single Mutex = check and insert are atomic — this driver's
        // equivalent of the Mongo `active_user_id` partial unique index
        // (same precedent as `create_mls_group`). Scoped to non-terminal
        // rows exactly like the partial filter, so a user with a history of
        // finished imports can still start a new one.
        let mut rows = self.discord_import_jobs.lock().await;

        if job.is_active()
            && rows
                .values()
                .any(|row| row.user_id == job.user_id && row.is_active())
        {
            return Err(create_error!(ImportAlreadyInProgress));
        }

        rows.insert(job.id.to_string(), job.clone());
        Ok(())
    }

    /// Fetch a job by id.
    async fn fetch_discord_import_job(&self, id: &str) -> Result<DiscordImportJob> {
        let rows = self.discord_import_jobs.lock().await;
        rows.get(id).cloned().ok_or_else(|| create_error!(NotFound))
    }

    /// Save an existing job WITHOUT upserting, unconditionally.
    async fn save_discord_import_job(&self, job: &DiscordImportJob) -> Result<()> {
        let mut rows = self.discord_import_jobs.lock().await;
        if let Some(existing) = rows.get_mut(&job.id) {
            *existing = job.clone();
        }
        Ok(())
    }

    /// Save an existing job only while the stored row is non-terminal.
    async fn save_discord_import_job_if_active(&self, job: &DiscordImportJob) -> Result<bool> {
        // The status check and the write happen under one mutex acquisition,
        // matching the atomicity of Mongo's filtered replace_one.
        let mut rows = self.discord_import_jobs.lock().await;
        match rows.get_mut(&job.id) {
            Some(existing) if existing.is_active() => {
                *existing = job.clone();
                Ok(true)
            }
            // Terminal (someone else finalized it) or absent (deleted) —
            // either way this write is dropped, never upserted.
            _ => Ok(false),
        }
    }

    /// Fetch a user's in-flight job (`Queued` or `Running`).
    async fn fetch_active_discord_import_job_for_user(
        &self,
        user_id: &str,
    ) -> Result<Option<DiscordImportJob>> {
        let rows = self.discord_import_jobs.lock().await;
        Ok(rows
            .values()
            .filter(|row| row.user_id == user_id && row.is_active())
            // Deterministic pick when a user somehow holds several.
            .min_by(|a, b| a.id.cmp(&b.id))
            .cloned())
    }

    /// ATOMICALLY claim the oldest queued job.
    async fn claim_next_queued_discord_import_job(&self) -> Result<Option<DiscordImportJob>> {
        // The whole find-then-flip runs while the map mutex is held, which
        // is this driver's equivalent of Mongo's single-document
        // find_one_and_update: no other task can observe or claim the same
        // row half-way through.
        let mut rows = self.discord_import_jobs.lock().await;

        // ULID ids sort by creation time — oldest queued first.
        let next = rows
            .values()
            .filter(|row| matches!(row.status, ImportStatus::Queued))
            .min_by(|a, b| a.id.cmp(&b.id))
            .map(|row| row.id.clone());

        let Some(id) = next else {
            return Ok(None);
        };

        let job = rows
            .get_mut(&id)
            .expect("claimed id was just read from this map");
        job.status = ImportStatus::Running;
        job.updated_at = Timestamp::now_utc();

        Ok(Some(job.clone()))
    }

    /// Fetch non-terminal jobs whose heartbeat went stale.
    async fn fetch_stale_discord_import_jobs(
        &self,
        cutoff: Timestamp,
    ) -> Result<Vec<DiscordImportJob>> {
        let rows = self.discord_import_jobs.lock().await;
        Ok(rows
            .values()
            // `is_active()` is Queued OR Running: an unclaimed job never
            // heartbeats, so excluding Queued would leave it holding its
            // owner's active-job slot forever.
            .filter(|row| row.is_active() && row.updated_at < cutoff)
            .cloned()
            .collect())
    }
}
