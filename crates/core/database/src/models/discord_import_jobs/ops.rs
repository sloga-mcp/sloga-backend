use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::DiscordImportJob;

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
}

#[cfg(test)]
mod tests {
    use super::AbstractDiscordImportJobs;
    use crate::{DiscordImportJob, DiscordImportSummary, ImportStage, ImportStatus};
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

            assert!(db
                .fetch_discord_import_job("01JOB0000000000000000000000")
                .await
                .is_err());
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
