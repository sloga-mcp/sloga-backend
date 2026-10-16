//! Make the Stoat importer bot leave servers no import is using.
//!
//! The bot leaves a server through its job: `on_terminal`, then the leave
//! retry. A server where no job was ever created (someone added the bot, then
//! verification failed or they gave up) has nothing that would ever make it
//! leave, and the bot keeps view access to that server's private channels.
//!
//! Once an hour this lists the bot's own memberships from one events session
//! (Stoat has no REST route for them) and leaves every server it joined more
//! than `reconcile_after_hours` ago that has no `Queued` or `Running`
//! `StoatServer` job. The join time is the grace clock: a user who has just
//! added the bot may still be pasting the code, and re-adding the bot after a
//! finished import starts the clock again. A terminal job never holds the
//! bot here, since its own leave path already let it go.
//!
//! Fails safe: no readable join time keeps the bot where it is, and a failed
//! job lookup ends the run there. Needs only `api_url` and `bot_token`, not
//! `enabled`, like the leave: a source switched off still has bots to remove.
//!
//! 🔴 Opt-in, on exactly ONE deployment (`reconcile_after_hours`, 0 = off by
//! default). "No job is using it" is read from this crond's own database, so
//! any other deployment holding the same bot token (the home box, a live leg)
//! would evict the bot from servers this one is importing, and the other way
//! round.
//!
//! Known race, the same one `has_other_active_job_for_source` documents:
//! delta verifies a server whose bot joined over a day ago and queues a job
//! just after this read "no active job". The job then fails with "the bot is
//! not in that server" and the user adds it again.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iso8601_timestamp::{Duration as Span, Timestamp};
use revolt_config::{config, ApiImportBotSource};
use revolt_database::{Database, ImportJobKind, AMQP};
use revolt_result::Result;
use tokio::time::sleep;

use super::source::{BotMembership, EventsLimits, StoatApi};

/// How often the reconcile runs.
const RECONCILE_EVERY: Duration = Duration::from_secs(60 * 60);

/// Wait after crond starts, so a crash loop does not open an events session
/// on every restart.
const FIRST_RUN_DELAY: Duration = Duration::from_secs(10 * 60);

/// Leaves attempted per run. The rest wait for the next run.
pub(crate) const LEAVE_BATCH: usize = 20;

/// Pause between two leaves, far under Stoat's `servers` bucket.
const LEAVE_SPACING: Duration = Duration::from_secs(1);

/// Whether the no-token notice has been logged in this process.
static NO_TOKEN_WARNED: AtomicBool = AtomicBool::new(false);

pub async fn task(db: Database, _amqp: AMQP) -> Result<()> {
    sleep(FIRST_RUN_DELAY).await;
    loop {
        let config = config().await;
        run(
            &db,
            &config.api.import.stoat,
            EventsLimits::default(),
            LEAVE_SPACING,
        )
        .await;
        sleep(RECONCILE_EVERY).await;
    }
}

/// What one run did, for the summary line and the tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Outcome {
    /// The bot's memberships in `Ready`
    pub seen: usize,
    /// Joined within the grace
    pub recent: usize,
    /// No readable join time (kept)
    pub no_join_time: usize,
    /// An active import job uses the server
    pub in_use: usize,
    /// Not judged: the job lookup failed on the first of these (kept)
    pub unchecked: usize,
    pub left: usize,
    /// Stoat refused or did not answer the leave
    pub failed: usize,
    /// Past the per-run cap, left for the next run
    pub deferred: usize,
}

/// The memberships the grace no longer protects, oldest join first, with
/// the counts of those it kept: `(candidates, recent, no_join_time)`.
///
/// A membership is past the grace when the bot joined at least
/// `after_hours` hours before `now`.
pub(crate) fn past_grace(
    memberships: &[BotMembership],
    now: Timestamp,
    after_hours: u32,
) -> (Vec<&BotMembership>, usize, usize) {
    let cutoff = now
        .checked_sub(Span::hours(i64::from(after_hours)))
        .unwrap_or(Timestamp::UNIX_EPOCH);

    let mut candidates = Vec::new();
    let (mut recent, mut no_join_time) = (0, 0);
    for membership in memberships {
        match membership.joined_at {
            None => no_join_time += 1,
            Some(joined) if joined > cutoff => recent += 1,
            Some(_) => candidates.push(membership),
        }
    }
    candidates.sort_by_key(|membership| membership.joined_at);
    (candidates, recent, no_join_time)
}

/// One reconcile run against this crond's database. `None` when it did not
/// run: switched off, no token, or the memberships could not be read (each
/// logged).
pub(crate) async fn run(
    db: &Database,
    stoat: &ApiImportBotSource,
    limits: EventsLimits,
    spacing: Duration,
) -> Option<Outcome> {
    let db = db.clone();
    run_with(stoat, limits, spacing, move |server_id| {
        let db = db.clone();
        // ULID job ids are never empty, so an empty exclusion counts every
        // active job on the server.
        async move {
            db.has_other_active_job_for_source(&ImportJobKind::StoatServer, &server_id, "")
                .await
        }
    })
    .await
}

/// [`run`], with the "is an active job using this server?" lookup passed in
/// (tests make it fail).
async fn run_with<F, Fut>(
    stoat: &ApiImportBotSource,
    limits: EventsLimits,
    spacing: Duration,
    in_use: F,
) -> Option<Outcome>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    if stoat.reconcile_after_hours == 0 {
        return None;
    }
    let Some(api) = StoatApi::new(stoat) else {
        if !NO_TOKEN_WARNED.swap(true, Ordering::Relaxed) {
            log::info!(
                "stoat import: no Stoat bot token configured; the bot reconcile has nothing to do"
            );
        }
        return None;
    };

    let memberships = match api.fetch_memberships(&stoat.app_url, limits).await {
        Ok(memberships) => memberships,
        Err(error) => {
            log::warn!(
                "stoat import: could not list the bot's Stoat servers ({error:?}); the reconcile \
                 tries again next hour"
            );
            return None;
        }
    };

    let (candidates, recent, no_join_time) = past_grace(
        &memberships,
        Timestamp::now_utc(),
        stoat.reconcile_after_hours,
    );
    let mut outcome = Outcome {
        seen: memberships.len(),
        recent,
        no_join_time,
        ..Outcome::default()
    };
    if no_join_time > 0 {
        log::warn!(
            "stoat import: {no_join_time} of the bot's Stoat memberships have no readable join \
             time; the bot stays in those servers"
        );
    }

    let total = candidates.len();
    for (index, membership) in candidates.into_iter().enumerate() {
        let server_id = membership.server_id.as_str();
        if outcome.left + outcome.failed >= LEAVE_BATCH {
            outcome.deferred = total - index;
            break;
        }

        match in_use(server_id.to_string()).await {
            Ok(true) => {
                outcome.in_use += 1;
                continue;
            }
            Ok(false) => {}
            Err(error) => {
                // The database is likely down for all of them: one error
                // line and stop, rather than a timeout per server.
                log::error!(
                    "stoat import: could not check for import jobs on server {server_id}: \
                     {error:?}; the reconcile stops here and tries again next hour"
                );
                outcome.unchecked = total - index;
                break;
            }
        }

        if outcome.left + outcome.failed > 0 {
            sleep(spacing).await;
        }
        if api.leave_server(server_id).await {
            outcome.left += 1;
            log::info!(
                "stoat import: the bot left server {server_id} (joined {}), which no import job \
                 is using",
                membership
                    .joined_at
                    .map(|joined| joined.to_string())
                    .unwrap_or_default()
            );
        } else {
            outcome.failed += 1;
        }
    }

    log::info!("stoat import: bot reconcile {outcome:?}");
    Some(outcome)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use revolt_database::test_teardown::TestDatabaseGuard;
    use revolt_database::{DatabaseInfo, DiscordImportJob, ImportStage, ImportStatus};

    use super::*;
    use crate::tasks::stoat_import::source::fake_upstream::{FakeEvents, FakeStoat};

    const BOT: &str = "01BOT000000000000000000000";

    fn membership(server_id: &str, joined_at: Option<Timestamp>) -> BotMembership {
        BotMembership {
            server_id: server_id.to_string(),
            joined_at,
        }
    }

    fn hours_ago(now: Timestamp, hours: i64) -> Timestamp {
        now.checked_sub(Span::hours(hours)).unwrap()
    }

    #[test]
    fn the_grace_keeps_fresh_joins_and_unknown_join_times() {
        let now = Timestamp::now_utc();
        let memberships = [
            membership("01FRESH", Some(hours_ago(now, 1))),
            membership("01OLDER", Some(hours_ago(now, 72))),
            membership("01UNKNOWN", None),
            membership("01OLD", Some(hours_ago(now, 25))),
            // Exactly at the grace: past it.
            membership("01EDGE", Some(hours_ago(now, 24))),
            membership("01JUSTIN", hours_ago(now, 24).checked_add(Span::seconds(1))),
        ];

        let (candidates, recent, no_join_time) = past_grace(&memberships, now, 24);
        let ids: Vec<&str> = candidates.iter().map(|m| m.server_id.as_str()).collect();
        // Oldest join first.
        assert_eq!(ids, ["01OLDER", "01OLD", "01EDGE"]);
        assert_eq!(recent, 2);
        assert_eq!(no_join_time, 1);
    }

    /// A grace no clock could subtract still answers (everything is recent).
    #[test]
    fn a_huge_grace_keeps_everything() {
        let now = Timestamp::now_utc();
        let memberships = [membership("01OLD", Some(hours_ago(now, 72)))];
        let (candidates, recent, _) = past_grace(&memberships, now, u32::MAX);
        assert!(candidates.is_empty());
        assert_eq!(recent, 1);
    }

    /// A fresh test database on the driver `TEST_DB` names (which must be
    /// set: `DatabaseInfo::Test` panics without it rather than reach the
    /// configured database). The name has the harness shape
    /// `is_throwaway_test_database` allows, so the guard drops it when the
    /// test ends, panics included.
    async fn test_db() -> (Database, TestDatabaseGuard) {
        let suffix = 1_000_000 + (ulid::Ulid::new().random() % 9_000_000);
        let db = DatabaseInfo::Test(format!("revolt_test_{suffix}"))
            .connect()
            .await
            .expect("test database");
        let guard = TestDatabaseGuard::arm(&db).await;
        (db, guard)
    }

    fn member(server_id: &str, user_id: &str, joined_at: Option<Timestamp>) -> String {
        match joined_at {
            Some(joined) => format!(
                r#"{{"_id":{{"server":"{server_id}","user":"{user_id}"}},"joined_at":"{joined}"}}"#
            ),
            None => format!(r#"{{"_id":{{"server":"{server_id}","user":"{user_id}"}}}}"#),
        }
    }

    fn ready(members: &[String]) -> String {
        format!(r#"{{"type":"Ready","members":[{}]}}"#, members.join(","))
    }

    fn leave_path(server_id: &str) -> String {
        format!("/servers/{server_id}?leave_silently=true")
    }

    /// A fake Stoat whose events session answers `ready_frame`, and whose
    /// leave answers `leave_status` for each of `servers`.
    async fn stoat(
        ready_frame: String,
        servers: &[&str],
        leave_status: u16,
    ) -> (FakeStoat, FakeEvents, ApiImportBotSource) {
        let events = FakeEvents::start(vec![ready_frame]).await;
        let mut api = FakeStoat::new()
            .reply("GET", "/", 200, format!(r#"{{"ws":"{}"}}"#, events.url))
            .reply("GET", "/users/@me", 200, format!(r#"{{"_id":"{BOT}"}}"#));
        for server in servers {
            api = api.reply("DELETE", &leave_path(server), leave_status, "");
        }
        let api = api.start().await;
        let config = api.source_config(&FakeStoat::new());
        (api, events, config)
    }

    fn deleted(api: &FakeStoat) -> HashSet<String> {
        api.seen()
            .into_iter()
            .filter(|seen| seen.method == "DELETE")
            .map(|seen| seen.path)
            .collect()
    }

    fn stoat_job(user: &str, server: &str, status: ImportStatus) -> DiscordImportJob {
        let mut job = DiscordImportJob::new_source(
            user.to_string(),
            ImportJobKind::StoatServer,
            server.to_string(),
            Some(server.to_string()),
            Some("sloga-import-AAAAAAAA".to_string()),
        );
        if status != ImportStatus::Queued {
            job.stage = ImportStage::Done;
        }
        job.status = status;
        job
    }

    /// The whole run against a fake Stoat, on the driver `TEST_DB` names:
    /// only servers past the grace with no active job are left.
    #[tokio::test]
    async fn the_bot_leaves_only_stray_servers_past_the_grace() {
        let (db, _teardown) = test_db().await;
        let now = Timestamp::now_utc();
        let old = Some(hours_ago(now, 48));
        let stray = "01RECSTRAY0000000000000000";
        let queued = "01RECQUEUED000000000000000";
        let running = "01RECRUNNING00000000000000";
        let finished = "01RECFINISHED0000000000000";
        let fresh = "01RECFRESH0000000000000000";
        let unknown = "01RECUNKNOWN00000000000000";
        let fluxer = "01RECFLUXER000000000000000";
        let someone_elses = "01RECOTHERUSER000000000000";

        db.insert_discord_import_job(&stoat_job(
            "01RECUSER0000000000000001",
            queued,
            ImportStatus::Queued,
        ))
        .await
        .unwrap();
        db.insert_discord_import_job(&stoat_job(
            "01RECUSER0000000000000002",
            running,
            ImportStatus::Running,
        ))
        .await
        .unwrap();
        db.insert_discord_import_job(&stoat_job(
            "01RECUSER0000000000000003",
            finished,
            ImportStatus::Completed,
        ))
        .await
        .unwrap();
        // An active job of ANOTHER kind on the same id does not hold the bot.
        let mut other_kind = stoat_job("01RECUSER0000000000000004", fluxer, ImportStatus::Queued);
        other_kind.kind = ImportJobKind::FluxerServer;
        db.insert_discord_import_job(&other_kind).await.unwrap();

        let frame = ready(&[
            member(stray, BOT, old),
            member(queued, BOT, old),
            member(running, BOT, old),
            member(finished, BOT, old),
            member(fresh, BOT, Some(hours_ago(now, 2))),
            member(unknown, BOT, None),
            member(fluxer, BOT, old),
            // A voice participant's member, as an older bonfire sends.
            member(someone_elses, "01SOMEONEELSE0000000000000", old),
        ]);
        let all = [
            stray,
            queued,
            running,
            finished,
            fresh,
            unknown,
            fluxer,
            someone_elses,
        ];
        let (api, events, config) = stoat(frame, &all, 204).await;

        let outcome = run(&db, &config, EventsLimits::default(), Duration::ZERO)
            .await
            .expect("the reconcile ran");
        assert_eq!(
            outcome,
            Outcome {
                seen: 7,
                recent: 1,
                no_join_time: 1,
                in_use: 2,
                left: 3,
                ..Outcome::default()
            }
        );
        assert_eq!(
            deleted(&api),
            HashSet::from([leave_path(stray), leave_path(finished), leave_path(fluxer)])
        );
        assert_eq!(events.sessions(), 1);
    }

    #[tokio::test]
    async fn leaves_are_capped_per_run_and_failures_count() {
        let (db, _teardown) = test_db().await;
        let old = Some(hours_ago(Timestamp::now_utc(), 48));
        let servers: Vec<String> = (0..LEAVE_BATCH + 3)
            .map(|i| format!("01RECCAP{i:018}"))
            .collect();
        let ids: Vec<&str> = servers.iter().map(String::as_str).collect();
        let frame = ready(
            &ids.iter()
                .map(|id| member(id, BOT, old))
                .collect::<Vec<_>>(),
        );

        // Stoat refuses every leave: each counts against the cap too.
        let (api, _events, config) = stoat(frame, &ids, 403).await;
        let outcome = run(&db, &config, EventsLimits::default(), Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(outcome.failed, LEAVE_BATCH);
        assert_eq!(outcome.deferred, 3);
        assert_eq!(outcome.left, 0);
        assert_eq!(deleted(&api).len(), LEAVE_BATCH);
    }

    #[tokio::test]
    async fn switched_off_or_without_a_token_nothing_is_sent() {
        let (db, _teardown) = test_db().await;
        let old = Some(hours_ago(Timestamp::now_utc(), 48));
        let stray = "01RECOFF000000000000000000";
        let (api, events, mut config) =
            stoat(ready(&[member(stray, BOT, old)]), &[stray], 204).await;

        config.reconcile_after_hours = 0;
        assert!(run(&db, &config, EventsLimits::default(), Duration::ZERO)
            .await
            .is_none());

        config.reconcile_after_hours = 24;
        config.bot_token.clear();
        assert!(run(&db, &config, EventsLimits::default(), Duration::ZERO)
            .await
            .is_none());

        assert!(api.seen().is_empty());
        assert_eq!(events.sessions(), 0);
    }

    /// A failed job lookup keeps the bot, and ends the run there: the
    /// database is likely down for every server, so no per-server timeouts.
    #[tokio::test]
    async fn a_failed_job_lookup_keeps_the_bot_and_stops_the_run() {
        let now = Timestamp::now_utc();
        let first = "01RECLOOKUP000000000000001";
        let broken = "01RECLOOKUP000000000000002";
        let after = "01RECLOOKUP000000000000003";
        let frame = ready(&[
            member(first, BOT, Some(hours_ago(now, 72))),
            member(broken, BOT, Some(hours_ago(now, 48))),
            member(after, BOT, Some(hours_ago(now, 30))),
        ]);
        let (api, _events, config) = stoat(frame, &[first, broken, after], 204).await;

        let asked = std::sync::Mutex::new(Vec::new());
        let outcome = run_with(
            &config,
            EventsLimits::default(),
            Duration::ZERO,
            |server_id| {
                asked.lock().unwrap().push(server_id.clone());
                async move {
                    if server_id == broken {
                        Err(revolt_result::create_error!(InternalError))
                    } else {
                        Ok(false)
                    }
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(outcome.left, 1);
        assert_eq!(outcome.unchecked, 2);
        assert_eq!(*asked.lock().unwrap(), [first, broken]);
        assert_eq!(deleted(&api), HashSet::from([leave_path(first)]));
    }

    /// Nothing is left when the memberships cannot be read.
    #[tokio::test]
    async fn an_unreadable_session_leaves_nothing() {
        let (db, _teardown) = test_db().await;
        let stray = "01RECUNREAD000000000000000";
        let (api, _events, config) = stoat(
            r#"{"type":"Error","error":"InvalidSession"}"#.to_string(),
            &[stray],
            204,
        )
        .await;
        // Refused at once, not by waiting out the deadline (the fake keeps
        // the connection open for 5 s after its script).
        let started = std::time::Instant::now();
        assert!(run(&db, &config, EventsLimits::default(), Duration::ZERO)
            .await
            .is_none());
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(deleted(&api).is_empty());
    }
}
