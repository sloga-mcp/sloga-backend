use iso8601_timestamp::{Duration, Timestamp};
use revolt_result::Result;

use crate::{DiscordImportJob, ImportJobKind};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractDiscordImportJobs: Sync + Send {
    /// Insert a newly queued import job.
    ///
    /// ENFORCES the one-active-import-per-user rule: if the user already
    /// holds a `Queued` or `Running` job this fails with
    /// `ImportAlreadyInProgress`. delta's read-then-insert check is a
    /// friendly early exit, NOT the guard — two concurrent requests both
    /// pass it, and only this insert stops the second one from minting a
    /// second server.
    async fn insert_discord_import_job(&self, job: &DiscordImportJob) -> Result<()>;

    /// Fetch a job by id, NotFound if it is gone.
    async fn fetch_discord_import_job(&self, id: &str) -> Result<DiscordImportJob>;

    /// Save an existing job WITHOUT upserting (losing the race against a
    /// delete must not resurrect the row).
    ///
    /// UNCONDITIONAL on status: this will happily write over a terminal
    /// row. Only use it where the caller is provably the sole writer —
    /// i.e. immediately after `claim_next_queued_discord_import_job`, before
    /// any await that could let a sweeper in. Every later worker write must
    /// use `save_discord_import_job_if_active` instead.
    async fn save_discord_import_job(&self, job: &DiscordImportJob) -> Result<()>;

    /// Save an existing job ONLY while the STORED row is still non-terminal
    /// (`Queued` or `Running`), returning whether the write happened.
    ///
    /// This is the compare-and-set that makes `Completed`/`Failed` actually
    /// terminal. Two crond instances is an advertised-safe configuration, so
    /// a sweeper can be holding a snapshot of a job that the owning worker
    /// has since completed; an unconditional replace would stamp `Failed`
    /// over that `Completed` and show the user a failure for a server that
    /// built perfectly. `Ok(false)` means "someone else finalized this" —
    /// the caller must abandon the job silently rather than emit an event.
    ///
    /// Also inherits the no-upsert contract: a deleted row returns
    /// `Ok(false)`, never resurrection.
    async fn save_discord_import_job_if_active(&self, job: &DiscordImportJob) -> Result<bool>;

    /// Fetch a user's in-flight job (`Queued` or `Running`), if any — the
    /// one-active-import-per-user guard.
    async fn fetch_active_discord_import_job_for_user(
        &self,
        user_id: &str,
    ) -> Result<Option<DiscordImportJob>>;

    /// ATOMICALLY claim the oldest `Queued` job: flip it to `Running` and
    /// stamp the heartbeat in ONE operation, returning the claimed job.
    ///
    /// This single-operation flip is what makes running multiple crond
    /// instances safe — a find-then-update pair would let two workers claim
    /// the same import and build two servers from one request.
    async fn claim_next_queued_discord_import_job(&self) -> Result<Option<DiscordImportJob>>;

    /// Fetch NON-TERMINAL jobs (`Queued` or `Running`) whose HEARTBEAT went
    /// stale (`updated_at < cutoff`) — the sweeper's input.
    ///
    /// Deliberately keyed on the heartbeat and never on creation age: a
    /// long-but-healthy import must never be false-failed mid-run.
    ///
    /// `Queued` is included on purpose. A job nothing ever claimed — crond
    /// down, or not yet restarted to pick up the feature flag — would
    /// otherwise never age out, and because the active-job guard counts it,
    /// it would lock its owner out of the feature permanently: there is no
    /// cancel route and no delete op.
    async fn fetch_stale_discord_import_jobs(
        &self,
        cutoff: Timestamp,
    ) -> Result<Vec<DiscordImportJob>>;

    /// Whether any job OTHER than `except_job_id` of this `kind` is still
    /// in flight (`Queued` or `Running` — the same set as the
    /// `active_user_id` partial index and `is_active`) against the same
    /// `source_server_id`.
    ///
    /// Drives "the bot leaves a source only once no job still needs it". A
    /// read, not a lock: a job queued for the source an instant after this
    /// returns `false` finds the bot gone and fails with `ImportBotNotInServer`;
    /// the user re-adds the bot and retries. Meant
    /// for source kinds; template and sticker rows never carry
    /// `source_server_id`, so they never match.
    ///
    /// An empty `except_job_id` excludes nothing (job ids are ULIDs): crond's
    /// bot reconcile asks that way, having no job of its own.
    async fn has_other_active_job_for_source(
        &self,
        kind: &ImportJobKind,
        source_server_id: &str,
        except_job_id: &str,
    ) -> Result<bool>;

    /// Terminal (`Completed` / `Failed`) source-kind jobs whose bot has not
    /// yet left the source (`source_left` false OR ABSENT), whose heartbeat
    /// (`updated_at`, which stops moving once a job is terminal) is within
    /// the last `max_age_days` days — the leave-retry sweep's input.
    ///
    /// Oldest first (ULID id order), at most `limit` rows; `limit <= 0`
    /// returns nothing rather than meaning "unbounded". Rows past the age
    /// cap drop out on purpose: the caller logs them loudly instead of
    /// retrying forever.
    async fn fetch_unleft_terminal_source_jobs(
        &self,
        max_age_days: i64,
        limit: i64,
    ) -> Result<Vec<DiscordImportJob>>;

    /// Record that the bot has left this job's source (`source_left =
    /// true`), touching nothing else — in particular NOT `updated_at`, so
    /// the row's terminal time is preserved.
    ///
    /// A targeted field write, not a replace: the job is terminal, and
    /// `save_discord_import_job_if_active` refuses terminal rows by design.
    /// No upsert; a missing row is a silent no-op.
    async fn mark_source_left(&self, id: &str) -> Result<()>;
}

/// Lower bound on `updated_at` for `fetch_unleft_terminal_source_jobs`,
/// shared by both drivers so they agree on the boundary.
///
/// The age is clamped to `0..=UNLEFT_MAX_AGE_DAYS` first: `Duration::days`
/// PANICS on overflow, and a crond config typo must not take the sweeper
/// down. Negative reads as 0 (bound = now, so nothing qualifies).
fn unleft_cutoff(max_age_days: i64) -> Timestamp {
    let days = max_age_days.clamp(0, UNLEFT_MAX_AGE_DAYS);
    Timestamp::now_utc()
        .checked_sub(Duration::days(days))
        .unwrap_or(Timestamp::UNIX_EPOCH)
}

/// Upper clamp for `unleft_cutoff` — 100 years, far beyond any sane cap.
const UNLEFT_MAX_AGE_DAYS: i64 = 36_500;

#[cfg(test)]
mod tests {
    use super::AbstractDiscordImportJobs;
    use crate::{DiscordImportJob, DiscordImportSummary, ImportJobKind, ImportStage, ImportStatus};
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_result::ErrorType;

    fn job(user_id: &str, template_code: &str) -> DiscordImportJob {
        DiscordImportJob::new(user_id.to_string(), template_code.to_string())
    }

    #[tokio::test]
    async fn insert_and_fetch_round_trip() {
        database_test!(|db| async move {
            let user = "01USER000000000000000000000";
            let mut row = job(user, "tmpl-abc");
            row.total = 12;
            row.summary = Some(DiscordImportSummary {
                channels_created: 3,
                categories_created: 1,
                channels_skipped: 2,
                roles_created: 4,
                roles_skipped: 1,
                stickers_created: None,
                stickers_skipped: None,
                notes: vec!["skipped 2 stage channels".to_string()],
            });
            db.insert_discord_import_job(&row).await.unwrap();

            let fetched = db.fetch_discord_import_job(&row.id).await.unwrap();
            assert_eq!(fetched.id, row.id);
            assert_eq!(fetched.user_id, user);
            assert_eq!(fetched.template_code, "tmpl-abc");
            assert_eq!(fetched.status, ImportStatus::Queued);
            assert_eq!(fetched.stage, ImportStage::Fetching);
            assert_eq!(fetched.done, 0);
            assert_eq!(fetched.total, 12);
            assert_eq!(fetched.server_id, None);
            assert_eq!(fetched.invite_code, None);
            assert_eq!(fetched.error, None);
            assert_eq!(fetched.summary, row.summary);

            // Timestamps round-trip through BSON Int64 milliseconds, so the
            // sub-millisecond tail of `now_utc()` is dropped — compare with
            // a tolerance rather than asserting struct equality.
            assert!(
                fetched.updated_at.duration_since(row.updated_at).abs() < Duration::milliseconds(2),
                "heartbeat did not round-trip: {:?} vs {:?}",
                fetched.updated_at,
                row.updated_at
            );

            // Slice-2 fields on a template job: absent, and read back as the
            // defaults old rows rely on.
            assert_eq!(fetched.kind, crate::ImportJobKind::Template);
            assert_eq!(fetched.source_guild_id, None);
            assert_eq!(fetched.parent_job_id, None);
            assert_eq!(fetched.summary.as_ref().unwrap().stickers_created, None);

            assert!(db
                .fetch_discord_import_job("01JOB0000000000000000000000")
                .await
                .is_err());
        });
    }

    /// A sticker-kind job's slice-2 fields survive both drivers, and the
    /// birth invariants (`stage: Stickers`, EMPTY `template_code` — what
    /// makes the row illegible/inert to pre-slice-2 binaries) hold.
    #[tokio::test]
    async fn sticker_job_round_trip() {
        database_test!(|db| async move {
            let user = "01USER00000000000000000STK0";
            let mut parent = job(user, "tmpl-parent");
            parent.status = ImportStatus::Completed;
            parent.stage = ImportStage::Done;
            parent.server_id = Some("01SERVER0000000000000000000".to_string());
            parent.source_guild_id = Some("1530784817975660565".to_string());
            db.insert_discord_import_job(&parent).await.unwrap();

            let mut row = DiscordImportJob::new_stickers(&parent);
            row.summary = Some(DiscordImportSummary {
                channels_created: 0,
                categories_created: 0,
                channels_skipped: 0,
                roles_created: 0,
                roles_skipped: 0,
                stickers_created: Some(5),
                stickers_skipped: Some(2),
                notes: vec!["2 sticker(s) were too large".to_string()],
            });
            db.insert_discord_import_job(&row).await.unwrap();

            let fetched = db.fetch_discord_import_job(&row.id).await.unwrap();
            assert_eq!(fetched.kind, crate::ImportJobKind::Stickers);
            assert_eq!(fetched.stage, ImportStage::Stickers);
            assert_eq!(
                fetched.template_code, "",
                "must NEVER copy the parent's code"
            );
            assert_eq!(fetched.parent_job_id.as_deref(), Some(parent.id.as_str()));
            assert_eq!(
                fetched.source_guild_id.as_deref(),
                Some("1530784817975660565")
            );
            assert_eq!(
                fetched.server_id.as_deref(),
                Some("01SERVER0000000000000000000")
            );
            let summary = fetched.summary.unwrap();
            assert_eq!(summary.stickers_created, Some(5));
            assert_eq!(summary.stickers_skipped, Some(2));
        });
    }

    #[tokio::test]
    async fn save_does_not_resurrect_deleted_rows() {
        database_test!(|db| async move {
            let user = "01USER000000000000000000001";
            let mut row = job(user, "tmpl-gone");

            // Never inserted at all — a save must not create it.
            row.stage = ImportStage::Channels;
            db.save_discord_import_job(&row).await.unwrap();
            assert!(db.fetch_discord_import_job(&row.id).await.is_err());

            // Insert, then remove the row out from under the worker.
            db.insert_discord_import_job(&row).await.unwrap();
            delete_row(&db, &row.id).await;

            // ...a stale worker progress write must NOT bring it back.
            row.done = 7;
            db.save_discord_import_job(&row).await.unwrap();
            assert!(db.fetch_discord_import_job(&row.id).await.is_err());
        });
    }

    #[tokio::test]
    async fn active_job_guard() {
        database_test!(|db| async move {
            let user = "01USER000000000000000000002";
            assert!(db
                .fetch_active_discord_import_job_for_user(user)
                .await
                .unwrap()
                .is_none());

            // Queued counts as active.
            let queued = job(user, "tmpl-queued");
            db.insert_discord_import_job(&queued).await.unwrap();
            assert_eq!(
                db.fetch_active_discord_import_job_for_user(user)
                    .await
                    .unwrap()
                    .unwrap()
                    .id,
                queued.id
            );

            // Running counts as active.
            let mut running = queued.clone();
            running.status = ImportStatus::Running;
            db.save_discord_import_job(&running).await.unwrap();
            assert_eq!(
                db.fetch_active_discord_import_job_for_user(user)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                ImportStatus::Running
            );

            // Terminal states do not.
            let mut completed = running.clone();
            completed.status = ImportStatus::Completed;
            completed.stage = ImportStage::Done;
            db.save_discord_import_job(&completed).await.unwrap();
            assert!(db
                .fetch_active_discord_import_job_for_user(user)
                .await
                .unwrap()
                .is_none());

            let mut failed = completed.clone();
            failed.status = ImportStatus::Failed;
            failed.error = Some("template not found".to_string());
            db.save_discord_import_job(&failed).await.unwrap();
            assert!(db
                .fetch_active_discord_import_job_for_user(user)
                .await
                .unwrap()
                .is_none());

            // Another user's queued job must not leak into this guard.
            let other = job("01USER000000000000000000003", "tmpl-other");
            db.insert_discord_import_job(&other).await.unwrap();
            assert!(db
                .fetch_active_discord_import_job_for_user(user)
                .await
                .unwrap()
                .is_none());
        });
    }

    #[tokio::test]
    async fn claim_is_atomic_and_exclusive() {
        database_test!(|db| async move {
            let first = job("01USER00000000000000000000A", "tmpl-a");
            let second = job("01USER00000000000000000000B", "tmpl-b");
            db.insert_discord_import_job(&first).await.unwrap();
            db.insert_discord_import_job(&second).await.unwrap();

            let a = db
                .claim_next_queued_discord_import_job()
                .await
                .unwrap()
                .expect("first claim");
            let b = db
                .claim_next_queued_discord_import_job()
                .await
                .unwrap()
                .expect("second claim");

            // Two claims, two DIFFERENT jobs — the flip is what stops a
            // second crond instance re-claiming the same import.
            assert_ne!(a.id, b.id);
            assert_eq!(a.status, ImportStatus::Running);
            assert_eq!(b.status, ImportStatus::Running);

            // Both flips are durable, not just reflected in the return value.
            assert_eq!(
                db.fetch_discord_import_job(&a.id).await.unwrap().status,
                ImportStatus::Running
            );
            assert_eq!(
                db.fetch_discord_import_job(&b.id).await.unwrap().status,
                ImportStatus::Running
            );

            // Queue drained.
            assert!(db
                .claim_next_queued_discord_import_job()
                .await
                .unwrap()
                .is_none());

            // A single queued job can be claimed exactly once.
            let lone = job("01USER00000000000000000000C", "tmpl-c");
            db.insert_discord_import_job(&lone).await.unwrap();
            assert_eq!(
                db.claim_next_queued_discord_import_job()
                    .await
                    .unwrap()
                    .unwrap()
                    .id,
                lone.id
            );
            assert!(db
                .claim_next_queued_discord_import_job()
                .await
                .unwrap()
                .is_none());
        });
    }

    #[tokio::test]
    async fn stale_heartbeat_scan() {
        database_test!(|db| async move {
            let now = Timestamp::now_utc();
            let cutoff = now.checked_sub(Duration::minutes(5)).unwrap();

            // Running, heartbeat long past the cutoff — reap.
            let mut stale = job("01USER00000000000000000001A", "tmpl-stale");
            stale.status = ImportStatus::Running;
            stale.stage = ImportStage::Channels;
            stale.updated_at = now.checked_sub(Duration::minutes(30)).unwrap();
            db.insert_discord_import_job(&stale).await.unwrap();

            // Running but freshly heartbeated — a long, healthy import.
            // Must NEVER be returned, no matter how old the row is.
            let mut fresh = job("01USER00000000000000000001B", "tmpl-fresh");
            fresh.status = ImportStatus::Running;
            fresh.updated_at = now;
            db.insert_discord_import_job(&fresh).await.unwrap();

            // Queued with an ancient heartbeat — nothing ever claimed it
            // (crond down, or not restarted for the feature flag). MUST be
            // reaped: it never heartbeats, so it would otherwise hold its
            // owner's active-job slot forever and 409 every future import.
            let mut old_queued = job("01USER00000000000000000001C", "tmpl-queued");
            old_queued.updated_at = now.checked_sub(Duration::hours(2)).unwrap();
            db.insert_discord_import_job(&old_queued).await.unwrap();

            // Terminal with an ancient heartbeat — already finished.
            let mut old_done = job("01USER00000000000000000001D", "tmpl-done");
            old_done.status = ImportStatus::Completed;
            old_done.stage = ImportStage::Done;
            old_done.updated_at = now.checked_sub(Duration::hours(2)).unwrap();
            db.insert_discord_import_job(&old_done).await.unwrap();

            assert_eq!(
                reaped_ids(&db, cutoff).await,
                sorted(vec![stale.id.clone(), old_queued.id.clone()]),
                "both the dead Running job and the never-claimed Queued job must be reaped"
            );

            // A heartbeat bump pulls a job back out of the sweeper's view.
            let mut recovered = stale.clone();
            recovered.touch();
            db.save_discord_import_job(&recovered).await.unwrap();
            assert_eq!(
                reaped_ids(&db, cutoff).await,
                vec![old_queued.id.clone()],
                "a freshly heartbeated import must never be false-failed"
            );

            // ...and once the Queued one is claimed/heartbeated too, the
            // sweeper has nothing left to do.
            let mut claimed = old_queued.clone();
            claimed.status = ImportStatus::Running;
            claimed.touch();
            db.save_discord_import_job(&claimed).await.unwrap();
            assert!(reaped_ids(&db, cutoff).await.is_empty());
        });
    }

    #[tokio::test]
    async fn save_if_active_refuses_to_clobber_terminal_states() {
        database_test!(|db| async move {
            // A sweeper holding a stale snapshot must not be able to stamp
            // `Failed` over a `Completed` written by the worker that
            // actually finished the import.
            let mut row = job("01USER00000000000000000002A", "tmpl-cas");
            row.status = ImportStatus::Running;
            db.insert_discord_import_job(&row).await.unwrap();

            // Running (non-terminal) — the write lands.
            let mut progress = row.clone();
            progress.stage = ImportStage::Channels;
            progress.done = 4;
            progress.total = 9;
            assert!(db
                .save_discord_import_job_if_active(&progress)
                .await
                .unwrap());
            let stored = db.fetch_discord_import_job(&row.id).await.unwrap();
            assert_eq!(stored.stage, ImportStage::Channels);
            assert_eq!(stored.done, 4);

            // The owning worker finalizes it.
            let mut completed = progress.clone();
            completed.status = ImportStatus::Completed;
            completed.stage = ImportStage::Done;
            completed.invite_code = Some("aBcDeF".to_string());
            assert!(db
                .save_discord_import_job_if_active(&completed)
                .await
                .unwrap());

            // The sweeper's stale snapshot now tries to fail it. Refused,
            // and the stored document is untouched.
            let mut sweeper = row.clone();
            sweeper.status = ImportStatus::Failed;
            sweeper.error = Some("import worker vanished".to_string());
            assert!(
                !db.save_discord_import_job_if_active(&sweeper)
                    .await
                    .unwrap(),
                "writing over a Completed job must report that it did not write"
            );

            let stored = db.fetch_discord_import_job(&row.id).await.unwrap();
            assert_eq!(stored.status, ImportStatus::Completed);
            assert_eq!(stored.stage, ImportStage::Done);
            assert_eq!(stored.invite_code, Some("aBcDeF".to_string()));
            assert_eq!(stored.error, None);

            // Same in the other direction: nothing escapes `Failed` either.
            let mut failed = job("01USER00000000000000000002B", "tmpl-cas2");
            failed.status = ImportStatus::Failed;
            failed.error = Some("template not found".to_string());
            db.insert_discord_import_job(&failed).await.unwrap();

            let mut late_complete = failed.clone();
            late_complete.status = ImportStatus::Completed;
            late_complete.error = None;
            assert!(!db
                .save_discord_import_job_if_active(&late_complete)
                .await
                .unwrap());
            assert_eq!(
                db.fetch_discord_import_job(&failed.id)
                    .await
                    .unwrap()
                    .status,
                ImportStatus::Failed
            );

            // A row that was deleted out from under the worker reports
            // "did not write" rather than being upserted back into life.
            delete_row(&db, &row.id).await;
            assert!(!db
                .save_discord_import_job_if_active(&completed)
                .await
                .unwrap());
            assert!(db.fetch_discord_import_job(&row.id).await.is_err());
        });
    }

    #[tokio::test]
    async fn insert_enforces_one_active_job_per_user() {
        database_test!(|db| async move {
            // Mongo's guard is a partial unique index; `database_test!`
            // hands us an un-migrated database, so install it here.
            create_active_user_index(&db).await;

            let user = "01USER00000000000000000003A";
            let first = job(user, "tmpl-first");
            db.insert_discord_import_job(&first).await.unwrap();

            // The TOCTOU case: delta's read-then-insert check passed for
            // both requests, so the storage layer has to be the one that
            // says no — otherwise one click creates two servers and two
            // invites.
            let second = job(user, "tmpl-second");
            let error = db
                .insert_discord_import_job(&second)
                .await
                .expect_err("a second active job for one user must be rejected");
            assert!(
                matches!(error.error_type, ErrorType::ImportAlreadyInProgress),
                "expected ImportAlreadyInProgress, got {:?}",
                error.error_type
            );
            assert!(db.fetch_discord_import_job(&second.id).await.is_err());

            // Another user is unaffected.
            let other = job("01USER00000000000000000003B", "tmpl-other");
            db.insert_discord_import_job(&other).await.unwrap();

            // Once claimed the job is Running, still active — the guard has
            // to hold there too, not just for Queued.
            let mut running = first.clone();
            running.status = ImportStatus::Running;
            db.save_discord_import_job(&running).await.unwrap();
            let third = job(user, "tmpl-third");
            assert!(db.insert_discord_import_job(&third).await.is_err());

            // Once the job reaches a terminal state the user is free again —
            // the constraint is scoped to non-terminal rows, so a history of
            // finished imports never locks anyone out.
            let mut done = db.fetch_discord_import_job(&first.id).await.unwrap();
            done.status = ImportStatus::Completed;
            done.stage = ImportStage::Done;
            assert!(db.save_discord_import_job_if_active(&done).await.unwrap());

            let fourth = job(user, "tmpl-fourth");
            db.insert_discord_import_job(&fourth).await.unwrap();
            assert_eq!(
                db.fetch_active_discord_import_job_for_user(user)
                    .await
                    .unwrap()
                    .unwrap()
                    .id,
                fourth.id
            );
        });
    }

    fn source_job(user_id: &str, kind: ImportJobKind, source_server_id: &str) -> DiscordImportJob {
        DiscordImportJob::new_source(
            user_id.to_string(),
            kind,
            format!("pasted:{source_server_id}"),
            Some(source_server_id.to_string()),
            Some("sloga-import-ABCDEFGH".to_string()),
        )
    }

    /// Each source kind, its birth stage, the three new fields, and the
    /// `Assets` stage survive both drivers.
    #[tokio::test]
    async fn source_job_round_trip() {
        database_test!(|db| async move {
            for (index, kind) in ImportJobKind::SOURCE_KINDS.into_iter().enumerate() {
                let user = format!("01USER00000000000000000SRC{index}");
                let row = source_job(&user, kind.clone(), "01SRCSERVER0000000000000000");
                db.insert_discord_import_job(&row).await.unwrap();

                let fetched = db.fetch_discord_import_job(&row.id).await.unwrap();
                assert_eq!(fetched.kind, kind);
                assert_eq!(fetched.stage, ImportStage::Verifying);
                assert_eq!(fetched.status, ImportStatus::Queued);
                assert_eq!(fetched.template_code, "pasted:01SRCSERVER0000000000000000");
                assert_eq!(
                    fetched.source_server_id.as_deref(),
                    Some("01SRCSERVER0000000000000000")
                );
                assert_eq!(
                    fetched.challenge_code.as_deref(),
                    Some("sloga-import-ABCDEFGH")
                );
                assert!(!fetched.source_left);

                let mut assets = fetched.clone();
                assets.status = ImportStatus::Running;
                assets.stage = ImportStage::Assets;
                assert!(db.save_discord_import_job_if_active(&assets).await.unwrap());
                assert_eq!(
                    db.fetch_discord_import_job(&row.id).await.unwrap().stage,
                    ImportStage::Assets
                );
            }

            // A template job carries none of the source fields.
            let template = job("01USER00000000000000000SRCT", "tmpl-x");
            db.insert_discord_import_job(&template).await.unwrap();
            let fetched = db.fetch_discord_import_job(&template.id).await.unwrap();
            assert_eq!(fetched.source_server_id, None);
            assert_eq!(fetched.challenge_code, None);
            assert!(!fetched.source_left);
        });
    }

    #[tokio::test]
    async fn other_active_job_for_source() {
        database_test!(|db| async move {
            let source = "01SRCSERVER00000000000000AA";
            let stoat = ImportJobKind::StoatServer;

            // This job alone: there is no OTHER job, so the bot may leave.
            let mine = source_job("01USER0000000000000000OJS1", stoat.clone(), source);
            db.insert_discord_import_job(&mine).await.unwrap();
            assert!(!db
                .has_other_active_job_for_source(&stoat, source, &mine.id)
                .await
                .unwrap());

            // Terminal jobs on the same source do not hold the bot.
            for (user, status) in [
                ("01USER0000000000000000OJS2", ImportStatus::Completed),
                ("01USER0000000000000000OJS3", ImportStatus::Failed),
            ] {
                let mut done = source_job(user, stoat.clone(), source);
                done.status = status;
                done.stage = ImportStage::Done;
                db.insert_discord_import_job(&done).await.unwrap();
            }
            assert!(!db
                .has_other_active_job_for_source(&stoat, source, &mine.id)
                .await
                .unwrap());

            // Same source id, different kind: not the same source.
            let fluxer = source_job(
                "01USER0000000000000000OJS4",
                ImportJobKind::FluxerServer,
                source,
            );
            db.insert_discord_import_job(&fluxer).await.unwrap();
            assert!(!db
                .has_other_active_job_for_source(&stoat, source, &mine.id)
                .await
                .unwrap());

            // Same kind, different source: unrelated.
            let elsewhere = source_job(
                "01USER0000000000000000OJS5",
                stoat.clone(),
                "01SRCSERVER00000000000000BB",
            );
            db.insert_discord_import_job(&elsewhere).await.unwrap();
            assert!(!db
                .has_other_active_job_for_source(&stoat, source, &mine.id)
                .await
                .unwrap());

            // Another user's QUEUED job on the same source holds the bot...
            let queued = source_job("01USER0000000000000000OJS6", stoat.clone(), source);
            db.insert_discord_import_job(&queued).await.unwrap();
            assert!(db
                .has_other_active_job_for_source(&stoat, source, &mine.id)
                .await
                .unwrap());
            // ...and the exclusion is by job id only: from `queued`'s side,
            // `mine` is the other active job.
            assert!(db
                .has_other_active_job_for_source(&stoat, source, &queued.id)
                .await
                .unwrap());

            // RUNNING holds it too.
            let mut running = queued.clone();
            running.status = ImportStatus::Running;
            db.save_discord_import_job(&running).await.unwrap();
            assert!(db
                .has_other_active_job_for_source(&stoat, source, &mine.id)
                .await
                .unwrap());

            // Once it finishes, `mine` is the only active job again.
            let mut finished = running.clone();
            finished.status = ImportStatus::Completed;
            finished.stage = ImportStage::Done;
            assert!(db
                .save_discord_import_job_if_active(&finished)
                .await
                .unwrap());
            assert!(!db
                .has_other_active_job_for_source(&stoat, source, &mine.id)
                .await
                .unwrap());
        });
    }

    /// crond's bot reconcile asks with no job of its own: an empty exclusion
    /// must count every active job on the source, and nothing else.
    #[tokio::test]
    async fn an_empty_exclusion_counts_every_active_job_on_the_source() {
        database_test!(|db| async move {
            let source = "01SRCSERVER00000000000000DD";
            let stoat = ImportJobKind::StoatServer;
            assert!(!db
                .has_other_active_job_for_source(&stoat, source, "")
                .await
                .unwrap());

            // Terminal jobs, another kind on the same id, and the same kind
            // on another source: none of them hold the bot.
            for (user, status) in [
                ("01USER0000000000000000EEX1", ImportStatus::Completed),
                ("01USER0000000000000000EEX2", ImportStatus::Failed),
            ] {
                let mut done = source_job(user, stoat.clone(), source);
                done.status = status;
                done.stage = ImportStage::Done;
                db.insert_discord_import_job(&done).await.unwrap();
            }
            let fluxer = source_job(
                "01USER0000000000000000EEX3",
                ImportJobKind::FluxerServer,
                source,
            );
            db.insert_discord_import_job(&fluxer).await.unwrap();
            let elsewhere = source_job(
                "01USER0000000000000000EEX4",
                stoat.clone(),
                "01SRCSERVER00000000000000EE",
            );
            db.insert_discord_import_job(&elsewhere).await.unwrap();
            assert!(!db
                .has_other_active_job_for_source(&stoat, source, "")
                .await
                .unwrap());

            // A Queued job holds it, then Running, and not once it finishes.
            let queued = source_job("01USER0000000000000000EEX5", stoat.clone(), source);
            db.insert_discord_import_job(&queued).await.unwrap();
            assert!(db
                .has_other_active_job_for_source(&stoat, source, "")
                .await
                .unwrap());

            let mut running = queued.clone();
            running.status = ImportStatus::Running;
            db.save_discord_import_job(&running).await.unwrap();
            assert!(db
                .has_other_active_job_for_source(&stoat, source, "")
                .await
                .unwrap());

            let mut finished = running.clone();
            finished.status = ImportStatus::Completed;
            finished.stage = ImportStage::Done;
            assert!(db
                .save_discord_import_job_if_active(&finished)
                .await
                .unwrap());
            assert!(!db
                .has_other_active_job_for_source(&stoat, source, "")
                .await
                .unwrap());
        });
    }

    #[tokio::test]
    async fn unleft_terminal_source_jobs_scan_and_mark_left() {
        database_test!(|db| async move {
            let now = Timestamp::now_utc();
            let source = "01SRCSERVER00000000000000CC";

            let terminal =
                |user: &str, kind: ImportJobKind, status: ImportStatus, age_days: i64| {
                    let mut row = source_job(user, kind, source);
                    row.status = status;
                    row.stage = ImportStage::Done;
                    row.updated_at = now.checked_sub(Duration::days(age_days)).unwrap();
                    row
                };

            // Qualify: terminal, source kind, not left, within 7 days.
            let completed = terminal(
                "01USER0000000000000000ULT1",
                ImportJobKind::StoatServer,
                ImportStatus::Completed,
                1,
            );
            let failed = terminal(
                "01USER0000000000000000ULT2",
                ImportJobKind::MatrixSpace,
                ImportStatus::Failed,
                3,
            );
            let fluxer = terminal(
                "01USER0000000000000000ULT3",
                ImportJobKind::FluxerServer,
                ImportStatus::Completed,
                0,
            );

            // Excluded: already left.
            let mut left = terminal(
                "01USER0000000000000000ULT4",
                ImportJobKind::StoatServer,
                ImportStatus::Completed,
                1,
            );
            left.source_left = true;
            // Excluded: past the age cap.
            let ancient = terminal(
                "01USER0000000000000000ULT5",
                ImportJobKind::StoatServer,
                ImportStatus::Failed,
                30,
            );
            // Excluded: still active (Queued and Running).
            let queued = source_job(
                "01USER0000000000000000ULT6",
                ImportJobKind::StoatServer,
                source,
            );
            let mut running = source_job(
                "01USER0000000000000000ULT7",
                ImportJobKind::StoatServer,
                source,
            );
            running.status = ImportStatus::Running;
            // Excluded: terminal but not a source kind.
            let mut template = job("01USER0000000000000000ULT8", "tmpl-done");
            template.status = ImportStatus::Completed;
            template.stage = ImportStage::Done;
            let mut stickers = DiscordImportJob::new_stickers(&template);
            stickers.user_id = "01USER0000000000000000ULT9".to_string();
            stickers.status = ImportStatus::Failed;

            for row in [
                &completed, &failed, &fluxer, &left, &ancient, &queued, &running, &template,
                &stickers,
            ] {
                db.insert_discord_import_job(row).await.unwrap();
            }

            let ids =
                |rows: Vec<DiscordImportJob>| rows.into_iter().map(|r| r.id).collect::<Vec<_>>();

            // Oldest-first by id, all three qualifying rows.
            let mut expected = vec![completed.id.clone(), failed.id.clone(), fluxer.id.clone()];
            expected.sort();
            assert_eq!(
                ids(db.fetch_unleft_terminal_source_jobs(7, 100).await.unwrap()),
                expected
            );

            // `limit` caps the batch and keeps the oldest.
            assert_eq!(
                ids(db.fetch_unleft_terminal_source_jobs(7, 2).await.unwrap()),
                expected[..2].to_vec()
            );
            // <= 0 is "nothing", never "unbounded".
            assert!(db
                .fetch_unleft_terminal_source_jobs(7, 0)
                .await
                .unwrap()
                .is_empty());
            assert!(db
                .fetch_unleft_terminal_source_jobs(7, -1)
                .await
                .unwrap()
                .is_empty());

            // A wider window takes in the 30-day-old row; a narrower one
            // drops the 3-day-old row. An absurd window must not panic.
            assert_eq!(
                db.fetch_unleft_terminal_source_jobs(60, 100)
                    .await
                    .unwrap()
                    .len(),
                4
            );
            assert_eq!(
                db.fetch_unleft_terminal_source_jobs(2, 100)
                    .await
                    .unwrap()
                    .len(),
                2
            );
            assert_eq!(
                db.fetch_unleft_terminal_source_jobs(i64::MAX, 100)
                    .await
                    .unwrap()
                    .len(),
                4
            );

            // Mark one left: it drops out, and NOTHING else on the row moves —
            // in particular not the terminal heartbeat.
            let before = db.fetch_discord_import_job(&completed.id).await.unwrap();
            db.mark_source_left(&completed.id).await.unwrap();
            let after = db.fetch_discord_import_job(&completed.id).await.unwrap();
            assert!(after.source_left);
            assert_eq!(after.status, before.status);
            assert_eq!(after.stage, before.stage);
            assert_eq!(after.updated_at, before.updated_at);
            assert_eq!(after.source_server_id, before.source_server_id);
            assert_eq!(after.challenge_code, before.challenge_code);

            let mut expected_after: Vec<String> = expected
                .into_iter()
                .filter(|id| id != &completed.id)
                .collect();
            expected_after.sort();
            assert_eq!(
                ids(db.fetch_unleft_terminal_source_jobs(7, 100).await.unwrap()),
                expected_after
            );

            // Marking a row that does not exist is a no-op, not an upsert.
            db.mark_source_left("01JOB00000000000000000NONE")
                .await
                .unwrap();
            assert!(db
                .fetch_discord_import_job("01JOB00000000000000000NONE")
                .await
                .is_err());
        });
    }

    /// Ids of everything the sweeper would reap, sorted for a stable compare
    /// (neither driver promises an order).
    async fn reaped_ids(db: &crate::Database, cutoff: Timestamp) -> Vec<String> {
        sorted(
            db.fetch_stale_discord_import_jobs(cutoff)
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.id)
                .collect(),
        )
    }

    fn sorted(mut ids: Vec<String>) -> Vec<String> {
        ids.sort();
        ids
    }

    /// Install the partial unique index that enforces one active import per
    /// user on MongoDB.
    ///
    /// `database_test!` connects to a fresh database with no migrations run,
    /// so without this the Mongo driver would silently accept a second
    /// active job and the guard would go untested. This spec MUST stay
    /// identical to the one in `admin_migrations/ops/mongodb/scripts.rs`
    /// (revision 65) and `init.rs`. The reference driver enforces the same
    /// rule in code, so it needs no setup.
    async fn create_active_user_index(db: &crate::Database) {
        match db {
            crate::Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                mongo
                    .db()
                    .run_command(bson::doc! {
                        "createIndexes": "discord_import_jobs",
                        "indexes": [
                            {
                                "key": { "user_id": 1_i32 },
                                "name": "active_user_id",
                                "unique": true,
                                "partialFilterExpression": {
                                    "status": { "$in": ["Queued", "Running"] }
                                }
                            }
                        ]
                    })
                    .await
                    .expect("failed to create active_user_id index");
            }
        }
    }

    /// Remove a row directly — there is no public delete op (jobs are
    /// retained for their history), but the no-resurrect contract still
    /// has to hold against an out-of-band removal.
    async fn delete_row(db: &crate::Database, id: &str) {
        match db {
            crate::Database::Reference(reference) => {
                reference.discord_import_jobs.lock().await.remove(id);
            }
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                mongo
                    .col::<bson::Document>("discord_import_jobs")
                    .delete_one(bson::doc! { "_id": id })
                    .await
                    .unwrap();
            }
        }
    }
}
