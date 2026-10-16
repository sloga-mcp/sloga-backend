use bson::{Bson, Document};
use futures::StreamExt;
use iso8601_timestamp::Timestamp;
use mongodb::options::{FindOneAndUpdateOptions, ReturnDocument};
use revolt_result::Result;

use crate::MongoDb;
use crate::{DiscordImportJob, ImportJobKind, ImportStatus};

use super::{unleft_cutoff, AbstractDiscordImportJobs};

static COL: &str = "discord_import_jobs";

/// Typed collection writes (insert_one/replace_one) serialize `Timestamp`
/// through bson's NON-human-readable serde path: Int64 unix-milliseconds.
/// Every hand-built document ($set updates, range-query thresholds) MUST use
/// the same encoding — `bson::to_bson` would emit an ISO STRING, and a `$lt`
/// across BSON types silently matches nothing, which here would mean the
/// heartbeat sweeper never reaping anything. Same helper as the MLS ops.
fn timestamp_bson(at: &Timestamp) -> Bson {
    Bson::Int64(
        at.duration_since(Timestamp::UNIX_EPOCH)
            .whole_milliseconds() as i64,
    )
}

/// The `$in` filter used by the active-job partial unique index and by every
/// non-terminal status query.
fn active_statuses() -> Bson {
    Bson::Array(vec![
        Bson::String(ImportStatus::Queued.as_variant_str().to_string()),
        Bson::String(ImportStatus::Running.as_variant_str().to_string()),
    ])
}

/// The complement of `active_statuses()` — the states nothing moves out of.
fn terminal_statuses() -> Bson {
    Bson::Array(vec![
        Bson::String(ImportStatus::Completed.as_variant_str().to_string()),
        Bson::String(ImportStatus::Failed.as_variant_str().to_string()),
    ])
}

#[async_trait]
impl AbstractDiscordImportJobs for MongoDb {
    /// Insert a newly queued import job, enforcing one active import per
    /// user.
    async fn insert_discord_import_job(&self, job: &DiscordImportJob) -> Result<()> {
        // The `active_user_id` partial unique index (user_id, scoped to
        // status $in [Queued, Running]) is what actually serializes
        // concurrent requests — delta's read-then-insert check is a TOCTOU
        // and N simultaneous clicks all pass it. A duplicate-key rejection
        // here is the expected outcome of that race, not a database fault,
        // so it becomes the same 409 the early check returns.
        //
        // The only unique indexes on this collection are `_id` (a fresh
        // ULID per job, so it never collides in practice) and
        // `active_user_id`, which makes 11000 unambiguous.
        self.col::<DiscordImportJob>(COL)
            .insert_one(job)
            .await
            .map(|_| ())
            .map_err(|error| match *error.kind {
                mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
                    ref write_error,
                )) if write_error.code == 11000 => create_error!(ImportAlreadyInProgress),
                _ => create_database_error!("insert_one", COL),
            })
    }

    /// Fetch a job by id.
    async fn fetch_discord_import_job(&self, id: &str) -> Result<DiscordImportJob> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    /// Save an existing job WITHOUT upserting, unconditionally.
    async fn save_discord_import_job(&self, job: &DiscordImportJob) -> Result<()> {
        self.col::<DiscordImportJob>(COL)
            .replace_one(doc! { "_id": &job.id }, job)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("replace_one", COL))
    }

    /// Save an existing job only while the stored row is non-terminal.
    async fn save_discord_import_job_if_active(&self, job: &DiscordImportJob) -> Result<bool> {
        // Filter + replace under one document lock: the status check and
        // the write cannot be interleaved, so a terminal state can never be
        // clobbered by a writer that read the row before it finalized.
        // No upsert, so a deleted row reports `false` rather than coming
        // back to life.
        self.col::<DiscordImportJob>(COL)
            .replace_one(
                doc! {
                    "_id": &job.id,
                    "status": { "$in": active_statuses() }
                },
                job,
            )
            .await
            .map(|result| result.matched_count == 1)
            .map_err(|_| create_database_error!("replace_one", COL))
    }

    /// Fetch a user's in-flight job (`Queued` or `Running`).
    async fn fetch_active_discord_import_job_for_user(
        &self,
        user_id: &str,
    ) -> Result<Option<DiscordImportJob>> {
        // Enum unit variants land in BSON as their bare variant NAME, so
        // the filter must match those exact strings.
        self.col::<DiscordImportJob>(COL)
            .find_one(doc! {
                "user_id": user_id,
                "status": { "$in": active_statuses() }
            })
            // ULID ids sort by creation time; the reference driver picks
            // the same row, so the two drivers agree when a user somehow
            // holds more than one in-flight job.
            .sort(doc! { "_id": 1_i32 })
            .await
            .map_err(|_| create_database_error!("find_one", COL))
    }

    /// ATOMICALLY claim the oldest queued job.
    async fn claim_next_queued_discord_import_job(&self) -> Result<Option<DiscordImportJob>> {
        // A single find_one_and_update: the match on `status: Queued` and
        // the flip to `Running` happen under one document lock, so two
        // crond instances racing here always claim two different jobs (or
        // one claims and the other gets None).
        self.col::<DiscordImportJob>(COL)
            .find_one_and_update(
                doc! { "status": ImportStatus::Queued.as_variant_str() },
                doc! {
                    "$set": {
                        "status": ImportStatus::Running.as_variant_str(),
                        "updated_at": timestamp_bson(&Timestamp::now_utc())
                    }
                },
            )
            .with_options(
                FindOneAndUpdateOptions::builder()
                    // ULID ids sort by creation time — oldest queued first.
                    .sort(doc! { "_id": 1_i32 })
                    // The caller needs the post-claim document (Running +
                    // fresh heartbeat), not the pre-claim one.
                    .return_document(ReturnDocument::After)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_one_and_update", COL))
    }

    /// Fetch non-terminal jobs whose heartbeat went stale.
    async fn fetch_stale_discord_import_jobs(
        &self,
        cutoff: Timestamp,
    ) -> Result<Vec<DiscordImportJob>> {
        Ok(self
            .col::<DiscordImportJob>(COL)
            .find(doc! {
                // Queued too: an unclaimed job never heartbeats, so without
                // this it would hold its owner's active-job slot forever.
                "status": { "$in": active_statuses() },
                "updated_at": { "$lt": timestamp_bson(&cutoff) }
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Whether another in-flight job of this kind targets the same source.
    async fn has_other_active_job_for_source(
        &self,
        kind: &ImportJobKind,
        source_server_id: &str,
        except_job_id: &str,
    ) -> Result<bool> {
        // Untyped + id-only projection: this answers yes/no, and must not
        // turn a row this binary cannot decode into an error.
        self.col::<Document>(COL)
            .find_one(doc! {
                "_id": { "$ne": except_job_id },
                "kind": kind.as_variant_str(),
                "source_server_id": source_server_id,
                // Same set as the `active_user_id` partial index.
                "status": { "$in": active_statuses() }
            })
            .projection(doc! { "_id": 1_i32 })
            .await
            .map(|found| found.is_some())
            .map_err(|_| create_database_error!("find_one", COL))
    }

    /// Whether a job of this kind on this source is active or recent.
    async fn has_recent_job_for_source(
        &self,
        kind: &ImportJobKind,
        source_server_id: &str,
        since: Timestamp,
    ) -> Result<bool> {
        // Untyped + id-only projection, as above. `updated_at` is stored
        // as Int64 milliseconds, so the bound goes through `timestamp_bson`
        // too — an ISO-string bound would compare across BSON types and
        // never match.
        self.col::<Document>(COL)
            .find_one(doc! {
                "kind": kind.as_variant_str(),
                "source_server_id": source_server_id,
                "$or": [
                    { "status": { "$in": active_statuses() } },
                    { "updated_at": { "$gte": timestamp_bson(&since) } }
                ]
            })
            .projection(doc! { "_id": 1_i32 })
            .await
            .map(|found| found.is_some())
            .map_err(|_| create_database_error!("find_one", COL))
    }

    /// Terminal source-kind jobs whose bot has not left the source yet.
    async fn fetch_unleft_terminal_source_jobs(
        &self,
        max_age_days: i64,
        limit: i64,
    ) -> Result<Vec<DiscordImportJob>> {
        // Mongo reads `limit(0)` as "no limit" and a negative limit as a
        // single batch; neither is what a caller passing <= 0 means.
        if limit <= 0 {
            return Ok(vec![]);
        }

        let source_kinds: Vec<Bson> = ImportJobKind::SOURCE_KINDS
            .iter()
            .map(|kind| Bson::String(kind.as_variant_str().to_string()))
            .collect();

        Ok(self
            .col::<DiscordImportJob>(COL)
            .find(doc! {
                "kind": { "$in": source_kinds },
                "status": { "$in": terminal_statuses() },
                // `$ne: true`, NOT `false`: the field is omitted while
                // false (`skip_serializing_if`), and absent on every row
                // written before it existed.
                "source_left": { "$ne": true },
                "updated_at": { "$gte": timestamp_bson(&unleft_cutoff(max_age_days)) }
            })
            .sort(doc! { "_id": 1_i32 })
            .limit(limit)
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Record that the bot has left this job's source.
    async fn mark_source_left(&self, id: &str) -> Result<()> {
        // `$set` on the one field, no upsert: the rest of the terminal row
        // (including its `updated_at`) stays exactly as the worker left it.
        self.col::<Document>(COL)
            .update_one(doc! { "_id": id }, doc! { "$set": { "source_left": true } })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }
}
