//! Pass that takes the Fluxer importer bot out of guilds nobody is
//! importing.
//!
//! A user adds the bot (with Administrator) before verifying, and an import
//! that is never started, or fails verification, has no job to make the bot
//! leave. Left alone the bot would keep Administrator in that guild for
//! good. Every [`PASS_INTERVAL`] this pass lists the guilds the bot is in and
//! leaves each one it joined at least `reconcile_after_hours` ago that no
//! Fluxer job has touched in the last `reconcile_after_hours`. The explain
//! screen promises 24 hours to finish, so a deployment that turns this on
//! sets 24 or more.
//!
//! 🔴 Opt-in, on exactly ONE deployment (`[api.import.fluxer]`
//! `reconcile_after_hours`, 0 = off by default: the pass then sends nothing).
//! "No job is using it" is read from this crond's own database, so any other
//! deployment holding the same bot token (the home box, a live leg) would
//! evict the bot from guilds this one is importing, and the other way round.
//!
//! When the bot joined comes from Fluxer (`joined_at` of
//! `GET /v1/guilds/{id}/members/@me`), not from this process, so a crond
//! restart neither delays nor brings forward a leave. A join time that is
//! missing or unreadable keeps the bot there (and is logged).
//!
//! Costs: the guild listing (at most [`MAX_LIST_PAGES`] calls), then at most
//! [`MAX_CALLS_PER_PASS`] join-time lookups and leaves together, about one a
//! second. A guild with a recent job costs no call. A 429 is waited out once
//! per pass (its `Retry-After`, capped); a second one stops the pass.
//!
//! Guilds are visited in ascending id order, each pass starting after the
//! last guild the previous pass in this process finished, wrapping round, so
//! a bot in more guilds than one pass can afford is still swept over
//! successive passes. A restart starts again from the lowest id. With several
//! crond replicas each runs its own pass; leaving is idempotent (404 counts
//! as left).
//!
//! Every page is listed BEFORE anything is left: Fluxer pages by "guilds
//! after this id", and a cursor naming a guild the bot has just left
//! restarts the listing from the first page.

#[cfg(test)]
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::future::BoxFuture;
use iso8601_timestamp::Timestamp;
use revolt_config::{config, ApiImportBotSource};
use revolt_database::{Database, ImportJobKind, AMQP};
use revolt_result::Result;
use tokio::time::sleep;

use super::source::{
    FluxerApi, LeaveOutcome, ListError, MemberLookup, Snowflake, GUILD_LIST_LIMIT,
};

/// How long after crond starts the first pass runs.
const FIRST_PASS_DELAY: Duration = Duration::from_secs(10 * 60);

/// Time between passes.
const PASS_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Whether the switched-off notice has been logged in this process.
static OFF_NOTED: AtomicBool = AtomicBool::new(false);

/// Pages of `GET /v1/users/@me/guilds` read per pass (5000 guilds).
pub(crate) const MAX_LIST_PAGES: usize = 25;

/// Join-time lookups and leaves per pass, together (retries included).
pub(crate) const MAX_CALLS_PER_PASS: usize = 200;

/// How long to wait after a 429 that names no `Retry-After`.
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(5);

/// How fast, and how far, a pass goes.
pub(crate) struct Pacing {
    /// Between two lookups or leaves.
    pub between_calls: Duration,
    /// Longest `Retry-After` honoured as given; longer waits are cut to this.
    pub max_retry_after: Duration,
    /// Lookups and leaves per pass, together.
    pub max_calls: usize,
}

const PRODUCTION_PACING: Pacing = Pacing {
    between_calls: Duration::from_secs(1),
    max_retry_after: Duration::from_secs(60),
    max_calls: MAX_CALLS_PER_PASS,
};

impl Pacing {
    fn retry_wait(&self, asked: Option<Duration>) -> Duration {
        asked
            .unwrap_or(DEFAULT_RETRY_AFTER)
            .min(self.max_retry_after)
    }
}

pub async fn task(db: Database, _amqp: AMQP) -> Result<()> {
    // The last guild a pass finished, so the next one carries on after it.
    let mut cursor: Option<Snowflake> = None;
    sleep(FIRST_PASS_DELAY).await;

    loop {
        let config = config().await;
        run_configured_pass(
            &db,
            &config.api.import.fluxer,
            &mut cursor,
            &PRODUCTION_PACING,
        )
        .await;
        sleep(PASS_INTERVAL).await;
    }
}

/// One pass for `[api.import.fluxer]`. Nothing is sent, and `None` comes
/// back, when `reconcile_after_hours` is 0 (switched off, logged once), or
/// without an API URL and a bot token: no bot could have been added.
pub(crate) async fn run_configured_pass(
    jobs: &dyn RecentJobs,
    config: &ApiImportBotSource,
    cursor: &mut Option<Snowflake>,
    pacing: &Pacing,
) -> Option<PassReport> {
    let grace_hours = config.reconcile_after_hours;
    if grace_hours == 0 {
        if !OFF_NOTED.swap(true, Ordering::Relaxed) {
            log::info!(
                "fluxer reconcile: reconcile_after_hours is 0; the bot reconcile is switched off"
            );
        }
        return None;
    }
    let api = FluxerApi::new(config)?;
    run_pass(jobs, &api, cursor, pacing, grace_hours).await
}

/// The guilds the bot is in, as far as one pass could read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Listing {
    /// In the order listed, without repeats.
    pub guilds: Vec<Snowflake>,
    /// Whether every page was read. An incomplete listing still has each of
    /// its guilds checked on its own.
    pub complete: bool,
}

/// Read every page of the bot's guilds. `None` when the listing failed
/// outright (a second 429 included): the pass then does nothing.
pub(crate) async fn list_guilds(api: &FluxerApi, pacing: &Pacing) -> Option<Listing> {
    let mut guilds = Vec::new();
    let mut listed = HashSet::new();
    let mut after: Option<Snowflake> = None;

    for _ in 0..MAX_LIST_PAGES {
        let page = match api.list_guilds_page(after).await {
            Ok(page) => page,
            Err(ListError::RateLimited(asked)) => {
                sleep(pacing.retry_wait(asked)).await;
                api.list_guilds_page(after).await.ok()?
            }
            Err(ListError::Failed) => return None,
        };

        // Ids ascend past the cursor. One that does not means Fluxer ignored
        // the cursor and started over: what was read so far is all this pass
        // gets.
        if after.is_some_and(|cursor| page.iter().any(|id| *id <= cursor)) {
            log::warn!("fluxer reconcile: the guild listing restarted; stopping it there");
            return Some(Listing {
                guilds,
                complete: false,
            });
        }

        for id in &page {
            if listed.insert(*id) {
                guilds.push(*id);
            }
        }

        if page.len() < GUILD_LIST_LIMIT {
            return Some(Listing {
                guilds,
                complete: true,
            });
        }
        after = page.iter().max().copied();
    }

    log::warn!("fluxer reconcile: the bot is in more guilds than one pass lists");
    Some(Listing {
        guilds,
        complete: false,
    })
}

/// THE rule, with no I/O: the bot leaves a guild only when no Fluxer job is
/// recent on it and Fluxer says the bot joined it at least `grace_hours`
/// before `now`. A join time that is not known, or lies in the future, keeps
/// the bot, and so does a grace of 0 (the reconcile is switched off).
pub(crate) fn should_leave(
    joined_at: Option<Timestamp>,
    now: Timestamp,
    recent_job: bool,
    grace_hours: u32,
) -> bool {
    if recent_job || grace_hours == 0 {
        return false;
    }
    let Some(joined) = joined_at else {
        return false;
    };
    let grace = iso8601_timestamp::Duration::hours(i64::from(grace_hours));
    let Some(cutoff) = now.checked_sub(grace) else {
        return false;
    };
    joined <= cutoff
}

/// [`should_leave`] over a whole listing: the guilds of `listed` (in that
/// order) the bot would leave, given each one's join time (absent = not
/// known) and the guilds with a recent job.
#[cfg(test)]
pub(crate) fn guilds_to_leave(
    listed: &[Snowflake],
    joined_at: &HashMap<Snowflake, Option<Timestamp>>,
    now: Timestamp,
    recent: &HashSet<Snowflake>,
    grace_hours: u32,
) -> Vec<Snowflake> {
    listed
        .iter()
        .copied()
        .filter(|guild| {
            should_leave(
                joined_at.get(guild).copied().flatten(),
                now,
                recent.contains(guild),
                grace_hours,
            )
        })
        .collect()
}

/// The order one pass visits `listed` in: ascending id, starting with the
/// first guild after `cursor` and wrapping round, each guild once.
pub(crate) fn pass_order(listed: &[Snowflake], cursor: Option<Snowflake>) -> Vec<Snowflake> {
    let mut order = listed.to_vec();
    order.sort();
    order.dedup();
    let start = cursor.map_or(0, |cursor| order.partition_point(|id| *id <= cursor));
    order.rotate_left(start);
    order
}

/// Whether a Fluxer job is active on a guild or touched it within the last
/// `grace_hours`. `None` when that cannot be read, which keeps the bot.
///
/// The database in production; a seam so a test can make a job appear at a
/// chosen moment.
pub(crate) trait RecentJobs: Sync {
    fn recent_job(&self, guild: Snowflake, grace_hours: u32) -> BoxFuture<'_, Option<bool>>;
}

impl RecentJobs for Database {
    fn recent_job(&self, guild: Snowflake, grace_hours: u32) -> BoxFuture<'_, Option<bool>> {
        Box::pin(async move {
            // A grace no clock could subtract counts every job ever made.
            let since = Timestamp::now_utc()
                .checked_sub(iso8601_timestamp::Duration::hours(i64::from(grace_hours)))
                .unwrap_or(Timestamp::UNIX_EPOCH);
            match self
                .has_recent_job_for_source(&ImportJobKind::FluxerServer, &guild.to_string(), since)
                .await
            {
                Ok(recent) => Some(recent),
                Err(error) => {
                    log::error!(
                        "fluxer reconcile: could not check jobs for guild {guild}: {error:?}"
                    );
                    None
                }
            }
        })
    }
}

/// What one pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct PassReport {
    pub listed: usize,
    /// Whether every page of the listing was read.
    pub complete: bool,
    /// Join-time lookups and leaves sent (retries included).
    pub calls: usize,
    pub left: usize,
    /// The join-time lookup answered 404: the bot was no longer there.
    pub gone: usize,
    /// A Fluxer job is active on the guild or touched it within the grace.
    pub kept_for_job: usize,
    /// The bot joined less than `reconcile_after_hours` ago.
    pub kept_joined_recently: usize,
    /// Fluxer gave no readable join time.
    pub kept_join_unknown: usize,
    /// A lookup or leave failed, or whether a job uses the guild could not
    /// be read.
    pub failed: usize,
    /// The pass ran out of calls before visiting every guild.
    pub capped: bool,
    /// A second 429 ended the pass early.
    pub rate_limited: bool,
}

/// The lookups and leaves one pass may still send, and their pacing.
struct Calls<'a> {
    pacing: &'a Pacing,
    sent: usize,
    /// Whether this pass has already waited out a 429.
    waited: bool,
}

impl Calls<'_> {
    /// Pace and count the next call. `false` once the pass has none left.
    async fn take(&mut self) -> bool {
        if self.sent >= self.pacing.max_calls {
            return false;
        }
        if self.sent > 0 {
            sleep(self.pacing.between_calls).await;
        }
        self.sent += 1;
        true
    }

    /// After a 429: the first in this pass is waited out (`true`: send it
    /// again); a second one ends the pass (`false`).
    async fn rate_limited(&mut self, asked: Option<Duration>) -> bool {
        if self.waited {
            log::warn!("fluxer reconcile: rate-limited again; stopping this pass");
            return false;
        }
        self.waited = true;
        sleep(self.pacing.retry_wait(asked)).await;
        true
    }
}

/// Whether a guild was dealt with, or the pass has to stop before it.
enum Visit {
    Done,
    Stop,
}

/// Check one guild and leave it if [`should_leave`] says so. The job check is
/// made again right before the leave: a job queued after the lookup keeps
/// the bot.
async fn visit(
    jobs: &dyn RecentJobs,
    api: &FluxerApi,
    guild: Snowflake,
    now: Timestamp,
    grace_hours: u32,
    calls: &mut Calls<'_>,
    report: &mut PassReport,
) -> Visit {
    let recent = match jobs.recent_job(guild, grace_hours).await {
        Some(false) => false,
        Some(true) => {
            report.kept_for_job += 1;
            return Visit::Done;
        }
        None => {
            report.failed += 1;
            return Visit::Done;
        }
    };

    let joined_at = loop {
        if !calls.take().await {
            report.capped = true;
            return Visit::Stop;
        }
        match api.fetch_bot_joined_at(guild).await {
            MemberLookup::Member(joined_at) => break joined_at,
            MemberLookup::NotMember => {
                report.gone += 1;
                return Visit::Done;
            }
            MemberLookup::Failed => {
                report.failed += 1;
                return Visit::Done;
            }
            MemberLookup::RateLimited(asked) => {
                if !calls.rate_limited(asked).await {
                    report.rate_limited = true;
                    return Visit::Stop;
                }
            }
        }
    };

    if !should_leave(joined_at, now, recent, grace_hours) {
        if joined_at.is_none() {
            log::warn!("fluxer reconcile: no readable joined_at for guild {guild}; staying");
            report.kept_join_unknown += 1;
        } else {
            report.kept_joined_recently += 1;
        }
        return Visit::Done;
    }

    loop {
        match jobs.recent_job(guild, grace_hours).await {
            Some(false) => {}
            Some(true) => {
                report.kept_for_job += 1;
                return Visit::Done;
            }
            None => {
                report.failed += 1;
                return Visit::Done;
            }
        }

        if !calls.take().await {
            report.capped = true;
            return Visit::Stop;
        }
        match api.leave_guild(guild).await {
            LeaveOutcome::Left => {
                report.left += 1;
                return Visit::Done;
            }
            LeaveOutcome::NotLeft => {
                report.failed += 1;
                return Visit::Done;
            }
            LeaveOutcome::RateLimited(asked) => {
                if !calls.rate_limited(asked).await {
                    report.rate_limited = true;
                    return Visit::Stop;
                }
            }
        }
    }
}

/// One pass: list, then visit each guild in [`pass_order`] until done or
/// out of calls, moving `cursor` past every guild finished; log the counts.
/// `None` when the listing failed (nothing is visited, `cursor` is kept).
/// `grace_hours` is `reconcile_after_hours`, which [`run_configured_pass`]
/// has already checked is not 0.
pub(crate) async fn run_pass(
    jobs: &dyn RecentJobs,
    api: &FluxerApi,
    cursor: &mut Option<Snowflake>,
    pacing: &Pacing,
    grace_hours: u32,
) -> Option<PassReport> {
    let Some(listing) = list_guilds(api, pacing).await else {
        log::warn!("fluxer reconcile: could not list the bot's guilds; nothing left this pass");
        return None;
    };

    let mut report = PassReport {
        listed: listing.guilds.len(),
        complete: listing.complete,
        ..PassReport::default()
    };
    let mut calls = Calls {
        pacing,
        sent: 0,
        waited: false,
    };
    // One clock for the whole pass: a pass that runs long only ever makes a
    // join look more recent than it is.
    let now = Timestamp::now_utc();

    for guild in pass_order(&listing.guilds, *cursor) {
        match visit(jobs, api, guild, now, grace_hours, &mut calls, &mut report).await {
            Visit::Done => *cursor = Some(guild),
            Visit::Stop => break,
        }
    }
    report.calls = calls.sent;

    log::info!(
        "fluxer reconcile: {} guild(s) listed{}, {} call(s); {} left, {} already gone, {} kept for \
         an import, {} joined recently, {} with no join time, {} failed{}{}",
        report.listed,
        if report.complete {
            ""
        } else {
            " (incomplete)"
        },
        report.calls,
        report.left,
        report.gone,
        report.kept_for_job,
        report.kept_joined_recently,
        report.kept_join_unknown,
        report.failed,
        if report.capped {
            "; out of calls, the next pass carries on"
        } else {
            ""
        },
        if report.rate_limited {
            "; stopped on rate limits"
        } else {
            ""
        },
    );
    Some(report)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use super::super::source::fake_upstream::FakeUpstream;
    use super::super::source::{guild_list_path, member_me_path};
    use super::*;
    use revolt_database::{DatabaseInfo, DiscordImportJob, ImportStatus};

    const FAST: Pacing = Pacing {
        between_calls: Duration::ZERO,
        max_retry_after: Duration::from_secs(5),
        max_calls: MAX_CALLS_PER_PASS,
    };

    /// The `reconcile_after_hours` most tests run with (the fixture's).
    const GRACE: u32 = 24;
    const GRACE_HOURS: i64 = GRACE as i64;

    /// The database `TEST_DB` names (refuses to run without it).
    async fn database() -> Database {
        DatabaseInfo::Test(format!("fluxer_reconcile_{}", ulid::Ulid::new()))
            .connect()
            .await
            .expect("test database")
    }

    fn api(fake: &FakeUpstream) -> FluxerApi {
        FluxerApi::new(&fake.fluxer_config(fake)).expect("client")
    }

    fn page(ids: impl IntoIterator<Item = u64>) -> String {
        serde_json::Value::Array(
            ids.into_iter()
                .map(|id| serde_json::json!({ "id": id.to_string(), "name": "g" }))
                .collect(),
        )
        .to_string()
    }

    fn hours_ago(hours: i64) -> Timestamp {
        Timestamp::now_utc()
            .checked_sub(iso8601_timestamp::Duration::hours(hours))
            .unwrap()
    }

    /// A `members/@me` answer for a bot that joined `hours` ago.
    fn joined(hours: i64) -> String {
        serde_json::json!({
            "user": { "id": "1300000000000000999" },
            "roles": [],
            "joined_at": hours_ago(hours),
        })
        .to_string()
    }

    fn leave_path(id: u64) -> String {
        format!("/v1/users/@me/guilds/{id}")
    }

    fn lookup_path(id: u64) -> String {
        member_me_path(Snowflake(id))
    }

    fn requests(fake: &FakeUpstream, method: &str) -> Vec<String> {
        fake.seen()
            .into_iter()
            .filter(|seen| seen.method == method)
            .map(|seen| seen.path)
            .collect()
    }

    fn deletes(fake: &FakeUpstream) -> Vec<String> {
        requests(fake, "DELETE")
    }

    fn lookups(fake: &FakeUpstream) -> Vec<String> {
        requests(fake, "GET")
            .into_iter()
            .filter(|path| path.ends_with("/members/@me"))
            .collect()
    }

    fn ids(ids: &[u64]) -> Vec<Snowflake> {
        ids.iter().copied().map(Snowflake).collect()
    }

    /// A Fluxer job on `guild`, finished `hours` ago.
    async fn job_on(db: &Database, guild: u64, hours: i64) {
        let mut job = DiscordImportJob::new_source(
            ulid::Ulid::new().to_string(),
            ImportJobKind::FluxerServer,
            "x".to_string(),
            Some(guild.to_string()),
            None,
        );
        job.status = ImportStatus::Completed;
        job.updated_at = hours_ago(hours);
        db.insert_discord_import_job(&job).await.unwrap();
    }

    /// A fake listing `guilds` (one page) whose `members/@me` answers
    /// `joined(hours)` for each; leaves are unscripted (404, which is left).
    async fn fake_with(guilds: &[(u64, i64)]) -> FakeUpstream {
        let mut fake = FakeUpstream::new().reply(
            "GET",
            &guild_list_path(None),
            200,
            page(guilds.iter().map(|(id, _)| *id)),
        );
        for (id, hours) in guilds {
            fake = fake.reply("GET", &lookup_path(*id), 200, joined(*hours));
        }
        fake.start().await
    }

    // ---- the rule ----

    #[test]
    fn the_rule_leaves_only_old_joins_without_a_job() {
        let now = Timestamp::now_utc();
        let ago = |hours: i64, seconds: i64| {
            now.checked_sub(iso8601_timestamp::Duration::hours(hours))
                .and_then(|t| t.checked_add(iso8601_timestamp::Duration::seconds(seconds)))
        };

        // Joined exactly 24 h ago, or longer, with no recent job: leave.
        assert!(should_leave(ago(GRACE_HOURS, 0), now, false, GRACE));
        assert!(should_leave(ago(24 * 30, 0), now, false, GRACE));
        // A second short of 24 h: stay.
        assert!(!should_leave(ago(GRACE_HOURS, 1), now, false, GRACE));
        assert!(!should_leave(ago(1, 0), now, false, GRACE));
        // Joined "in the future" (clock skew): stay.
        assert!(!should_leave(ago(-1, 0), now, false, GRACE));
        // A recent job keeps the bot however old the join.
        assert!(!should_leave(ago(24 * 30, 0), now, true, GRACE));
        // No known join time: stay.
        assert!(!should_leave(None, now, false, GRACE));
        assert!(!should_leave(None, now, true, GRACE));
    }

    /// The boundary is the configured `reconcile_after_hours`, not a fixed
    /// 24; 0 (switched off) never leaves, and a grace no clock could
    /// subtract keeps everything.
    #[test]
    fn the_rule_uses_the_configured_grace() {
        let now = Timestamp::now_utc();
        let ago = |hours: i64, seconds: i64| {
            now.checked_sub(iso8601_timestamp::Duration::hours(hours))
                .and_then(|t| t.checked_add(iso8601_timestamp::Duration::seconds(seconds)))
        };

        // Exactly 48 h: past a 48 h grace and a 24 h one.
        assert!(should_leave(ago(48, 0), now, false, 48));
        assert!(should_leave(ago(48, 0), now, false, 24));
        // A second short of 48 h: inside a 48 h grace, past a 24 h one.
        assert!(!should_leave(ago(48, 1), now, false, 48));
        assert!(should_leave(ago(48, 1), now, false, 24));
        // 30 h: inside 48, past 24.
        assert!(!should_leave(ago(30, 0), now, false, 48));
        assert!(should_leave(ago(30, 0), now, false, 24));
        // A second short of 24 h: inside both.
        assert!(!should_leave(ago(24, 1), now, false, 24));

        // 0 is "off": however old the join, never a reason to leave.
        assert!(!should_leave(ago(24 * 365, 0), now, false, 0));
        assert!(!should_leave(ago(24 * 365, 0), now, false, u32::MAX));
    }

    #[test]
    fn the_rule_over_a_listing() {
        let now = Timestamp::now_utc();
        let at = |hours| {
            Some(
                now.checked_sub(iso8601_timestamp::Duration::hours(hours))
                    .unwrap(),
            )
        };
        let joined_at: HashMap<Snowflake, Option<Timestamp>> = [
            (Snowflake(1), at(48)), // old, no job: leave
            (Snowflake(2), at(23)), // joined recently
            (Snowflake(3), at(48)), // old, recent job
            (Snowflake(4), None),   // join time unreadable
            // 5: no lookup answer at all
            (Snowflake(6), at(24)), // exactly the grace: leave
        ]
        .into_iter()
        .collect();
        let recent: HashSet<Snowflake> = [Snowflake(3)].into_iter().collect();

        assert_eq!(
            guilds_to_leave(&ids(&[6, 5, 4, 3, 2, 1]), &joined_at, now, &recent, GRACE),
            ids(&[6, 1])
        );
        // With a 48 h grace only the exact-48 h join is past it; 6 (24 h) stays.
        assert_eq!(
            guilds_to_leave(&ids(&[6, 5, 4, 3, 2, 1]), &joined_at, now, &recent, 48),
            ids(&[1])
        );
    }

    #[test]
    fn pass_order_starts_after_the_cursor_and_wraps() {
        let listed = ids(&[30, 10, 20, 40, 10]);
        assert_eq!(pass_order(&listed, None), ids(&[10, 20, 30, 40]));
        assert_eq!(
            pass_order(&listed, Some(Snowflake(20))),
            ids(&[30, 40, 10, 20])
        );
        // A cursor guild no longer listed: carry on after where it was.
        assert_eq!(
            pass_order(&listed, Some(Snowflake(25))),
            ids(&[30, 40, 10, 20])
        );
        assert_eq!(
            pass_order(&listed, Some(Snowflake(40))),
            ids(&[10, 20, 30, 40])
        );
        assert_eq!(
            pass_order(&listed, Some(Snowflake(99))),
            ids(&[10, 20, 30, 40])
        );
        assert_eq!(
            pass_order(&listed, Some(Snowflake(1))),
            ids(&[10, 20, 30, 40])
        );
        assert!(pass_order(&[], Some(Snowflake(5))).is_empty());
    }

    // ---- passes ----

    /// Joined under 24 h ago: looked up, kept. Joined 24 h ago or more with
    /// no recent job: left. A recent job: kept without any call.
    #[tokio::test]
    async fn old_joins_are_left_and_recent_ones_and_jobs_are_kept() {
        let db = database().await;
        job_on(&db, 13, 1).await;
        // A job older than the grace does not keep the bot.
        job_on(&db, 14, GRACE_HOURS + 2).await;
        let fake = fake_with(&[(11, 23), (12, GRACE_HOURS + 1), (13, 48), (14, 48)]).await;

        let mut cursor = None;
        let report = run_pass(&db, &api(&fake), &mut cursor, &FAST, GRACE)
            .await
            .unwrap();
        assert_eq!(
            report,
            PassReport {
                listed: 4,
                complete: true,
                calls: 5,
                left: 2,
                kept_for_job: 1,
                kept_joined_recently: 1,
                ..PassReport::default()
            }
        );
        assert_eq!(deletes(&fake), vec![leave_path(12), leave_path(14)]);
        // The guild with a recent job cost no call.
        assert_eq!(
            lookups(&fake),
            vec![lookup_path(11), lookup_path(12), lookup_path(14)]
        );
        assert_eq!(cursor, Some(Snowflake(14)));
    }

    /// A join time that is missing or unreadable keeps the bot.
    #[tokio::test]
    async fn a_missing_or_garbage_join_time_keeps_the_bot() {
        let db = database().await;
        let fake = FakeUpstream::new()
            .reply("GET", &guild_list_path(None), 200, page([21, 22, 23, 24]))
            .reply("GET", &lookup_path(21), 200, r#"{"roles":[]}"#)
            .reply("GET", &lookup_path(22), 200, r#"{"joined_at":"garbage"}"#)
            .reply("GET", &lookup_path(23), 200, r#"{"joined_at":null}"#)
            .reply("GET", &lookup_path(24), 200, r#"{"joined_at":1}"#)
            .start()
            .await;

        let report = run_pass(&db, &api(&fake), &mut None, &FAST, GRACE)
            .await
            .unwrap();
        assert_eq!(report.kept_join_unknown, 4, "{report:?}");
        assert_eq!(report.left, 0);
        assert!(deletes(&fake).is_empty(), "{:?}", deletes(&fake));
    }

    /// A 404 on `members/@me` means the bot is already gone: no leave is
    /// sent. Any other failure keeps the bot until a later pass.
    #[tokio::test]
    async fn a_missing_membership_is_skipped_and_failures_keep_the_bot() {
        let db = database().await;
        let fake = FakeUpstream::new()
            .reply("GET", &guild_list_path(None), 200, page([31, 32, 33]))
            .reply("GET", &lookup_path(31), 404, r#"{"code":"UNKNOWN_MEMBER"}"#)
            .reply("GET", &lookup_path(32), 500, "{}")
            .reply("GET", &lookup_path(33), 200, joined(48))
            .reply("DELETE", &leave_path(33), 500, "{}")
            .start()
            .await;

        let report = run_pass(&db, &api(&fake), &mut None, &FAST, GRACE)
            .await
            .unwrap();
        assert_eq!(report.gone, 1, "{report:?}");
        assert_eq!(report.failed, 2, "{report:?}");
        assert_eq!(report.left, 0);
        assert_eq!(deletes(&fake), vec![leave_path(33)]);
    }

    /// Jobs as the database has them, except that a queued Fluxer job on
    /// `guild` is added at its second check: after the join-time lookup,
    /// right before the leave.
    struct JobAppearsBeforeLeave {
        db: Database,
        guild: Snowflake,
        checks: AtomicUsize,
    }

    impl RecentJobs for JobAppearsBeforeLeave {
        fn recent_job(&self, guild: Snowflake, grace_hours: u32) -> BoxFuture<'_, Option<bool>> {
            Box::pin(async move {
                if guild == self.guild && self.checks.fetch_add(1, Ordering::SeqCst) == 1 {
                    let mut job = DiscordImportJob::new_source(
                        ulid::Ulid::new().to_string(),
                        ImportJobKind::FluxerServer,
                        "x".to_string(),
                        Some(guild.to_string()),
                        None,
                    );
                    job.status = ImportStatus::Queued;
                    self.db.insert_discord_import_job(&job).await.unwrap();
                }
                self.db.recent_job(guild, grace_hours).await
            })
        }
    }

    /// The job check is made again at leave time: a job created after the
    /// join-time lookup keeps the bot.
    #[tokio::test]
    async fn a_job_created_between_lookup_and_leave_keeps_the_bot() {
        let db = database().await;
        let fake = fake_with(&[(41, 48), (42, 48)]).await;
        let jobs = JobAppearsBeforeLeave {
            db: db.clone(),
            guild: Snowflake(41),
            checks: AtomicUsize::new(0),
        };

        let report = run_pass(&jobs, &api(&fake), &mut None, &FAST, GRACE)
            .await
            .unwrap();
        assert_eq!(jobs.checks.load(Ordering::SeqCst), 2);
        assert_eq!(report.kept_for_job, 1, "{report:?}");
        assert_eq!(report.left, 1);
        // 41 was looked up (old enough), then kept by the re-check.
        assert_eq!(lookups(&fake), vec![lookup_path(41), lookup_path(42)]);
        assert_eq!(deletes(&fake), vec![leave_path(42)]);
    }

    /// Lookups and leaves together stop at the cap; listing pages do not
    /// count. Every page is read before anything is left.
    #[tokio::test]
    async fn the_call_cap_is_honoured_and_every_page_is_listed_first() {
        let db = database().await;
        let first: Vec<u64> = (1..=GUILD_LIST_LIMIT as u64).collect();
        let mut fake = FakeUpstream::new()
            .reply("GET", &guild_list_path(None), 200, page(first))
            .reply(
                "GET",
                &guild_list_path(Some(Snowflake(GUILD_LIST_LIMIT as u64))),
                200,
                page(201..=250),
            );
        for id in 1..=250 {
            fake = fake.reply("GET", &lookup_path(id), 200, joined(48));
        }
        let fake = fake.start().await;
        // The cap used here is the production one.
        assert_eq!(FAST.max_calls, PRODUCTION_PACING.max_calls);

        let mut cursor = None;
        let report = run_pass(&db, &api(&fake), &mut cursor, &FAST, GRACE)
            .await
            .unwrap();
        assert!(report.capped, "{report:?}");
        assert_eq!(report.listed, 250);
        assert_eq!(report.calls, MAX_CALLS_PER_PASS);
        assert_eq!(report.left, MAX_CALLS_PER_PASS / 2);
        assert_eq!(
            lookups(&fake).len() + deletes(&fake).len(),
            MAX_CALLS_PER_PASS
        );
        assert_eq!(cursor, Some(Snowflake(MAX_CALLS_PER_PASS as u64 / 2)));

        let seen = fake.seen();
        assert_eq!(seen[0].path, guild_list_path(None));
        assert_eq!(seen[1].path, guild_list_path(Some(Snowflake(200))));
        assert!(seen[2..].iter().all(|s| !s.path.contains("?limit=")));
    }

    /// Each pass carries on after the last guild the previous one finished,
    /// and wraps round to the lowest id.
    #[tokio::test]
    async fn the_cursor_advances_and_wraps() {
        let db = database().await;
        let fake = fake_with(&[(1, 48), (2, 48), (3, 48), (4, 48), (5, 48)]).await;
        let api = api(&fake);
        let small = Pacing {
            max_calls: 4,
            ..FAST
        };

        let mut cursor = None;
        for expected in [2, 4, 1] {
            run_pass(&db, &api, &mut cursor, &small, GRACE)
                .await
                .unwrap();
            assert_eq!(cursor, Some(Snowflake(expected)));
        }
        // Unscripted leaves answer 404 (left), and the fake keeps listing
        // every guild, so the third pass wraps from 5 to 1.
        assert_eq!(deletes(&fake), [1, 2, 3, 4, 5, 1].map(leave_path).to_vec());

        // A new process starts from the lowest id again.
        let mut fresh = None;
        run_pass(&db, &api, &mut fresh, &small, GRACE)
            .await
            .unwrap();
        assert_eq!(fresh, Some(Snowflake(2)));
    }

    /// A 429 is waited out for its `Retry-After`, then the call is sent
    /// again; a second 429 in the same pass stops it before the next guild,
    /// and the cursor stays before the guild it stopped on.
    #[tokio::test]
    async fn retry_after_is_honoured_and_a_second_429_stops_the_pass() {
        let db = database().await;
        let fake = FakeUpstream::new()
            .reply("GET", &guild_list_path(None), 200, page([51, 52, 53]))
            .reply_with_headers("GET", &lookup_path(51), 429, "{}", &[("Retry-After", "1")])
            .then_reply("GET", &lookup_path(51), 200, joined(48))
            .reply("DELETE", &leave_path(51), 204, "")
            .reply_with_headers("GET", &lookup_path(52), 429, "{}", &[("Retry-After", "0")])
            .reply("GET", &lookup_path(53), 200, joined(48))
            .start()
            .await;

        let mut cursor = None;
        let started = Instant::now();
        let report = run_pass(&db, &api(&fake), &mut cursor, &FAST, GRACE)
            .await
            .unwrap();
        assert!(
            started.elapsed() >= Duration::from_secs(1),
            "Retry-After was not waited"
        );
        assert!(report.rate_limited, "{report:?}");
        assert_eq!(report.left, 1);
        assert_eq!(
            lookups(&fake),
            vec![lookup_path(51), lookup_path(51), lookup_path(52)]
        );
        assert_eq!(deletes(&fake), vec![leave_path(51)]);
        assert_eq!(cursor, Some(Snowflake(51)));
    }

    /// A long `Retry-After` is cut to the cap.
    #[tokio::test]
    async fn a_long_retry_after_is_capped() {
        let db = database().await;
        let fake = FakeUpstream::new()
            .reply("GET", &guild_list_path(None), 200, page([61]))
            .reply_with_headers(
                "GET",
                &lookup_path(61),
                429,
                "{}",
                &[("Retry-After", "3600")],
            )
            .then_reply("GET", &lookup_path(61), 200, joined(48))
            .start()
            .await;
        let quick = Pacing {
            max_retry_after: Duration::from_millis(50),
            ..FAST
        };

        let started = Instant::now();
        let report = run_pass(&db, &api(&fake), &mut None, &quick, GRACE)
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(30));
        assert_eq!(report.left, 1, "{report:?}");
    }

    #[tokio::test]
    async fn a_restarted_listing_stops_and_is_incomplete() {
        let first: Vec<u64> = (1..=GUILD_LIST_LIMIT as u64).collect();
        let fake = FakeUpstream::new()
            .reply("GET", &guild_list_path(None), 200, page(first.clone()))
            // The cursor guild is gone: Fluxer starts again from the top.
            .reply(
                "GET",
                &guild_list_path(Some(Snowflake(GUILD_LIST_LIMIT as u64))),
                200,
                page(first.clone()),
            )
            .start()
            .await;
        let listing = list_guilds(&api(&fake), &FAST).await.unwrap();
        assert!(!listing.complete);
        assert_eq!(listing.guilds.len(), GUILD_LIST_LIMIT);
        assert_eq!(fake.seen().len(), 2);
    }

    #[tokio::test]
    async fn a_failed_or_twice_rate_limited_listing_leaves_nothing() {
        let db = database().await;
        for fake in [
            FakeUpstream::new()
                .reply("GET", &guild_list_path(None), 500, "{}")
                .reply("GET", &lookup_path(71), 200, joined(48))
                .start()
                .await,
            FakeUpstream::new()
                .reply_with_headers(
                    "GET",
                    &guild_list_path(None),
                    429,
                    "{}",
                    &[("Retry-After", "0")],
                )
                .reply("GET", &lookup_path(71), 200, joined(48))
                .start()
                .await,
        ] {
            let mut cursor = Some(Snowflake(70));
            assert_eq!(
                run_pass(&db, &api(&fake), &mut cursor, &FAST, GRACE).await,
                None
            );
            assert!(lookups(&fake).is_empty());
            assert!(deletes(&fake).is_empty());
            assert_eq!(cursor, Some(Snowflake(70)), "the cursor is kept");
        }
    }

    /// Without a bot token (or an API URL) nothing is sent at all.
    #[tokio::test]
    async fn no_token_no_calls() {
        let db = database().await;
        let fake = fake_with(&[(81, 48)]).await;

        let mut config = fake.fluxer_config(&fake);
        config.bot_token = String::new();
        let mut cursor = None;
        assert_eq!(
            run_configured_pass(&db, &config, &mut cursor, &FAST).await,
            None
        );

        let mut config = fake.fluxer_config(&fake);
        config.api_url = String::new();
        assert_eq!(
            run_configured_pass(&db, &config, &mut cursor, &FAST).await,
            None
        );
        assert!(fake.seen().is_empty(), "{:?}", fake.seen());
        assert_eq!(cursor, None);

        // The same fake with the token set is called: the check above is
        // not vacuous.
        let config = fake.fluxer_config(&fake);
        assert!(run_configured_pass(&db, &config, &mut cursor, &FAST)
            .await
            .is_some());
        assert_eq!(deletes(&fake), vec![leave_path(81)]);
    }

    /// `reconcile_after_hours = 0` (the default) switches the pass off:
    /// nothing is listed, looked up or left, and the cursor stays put.
    #[tokio::test]
    async fn switched_off_no_calls() {
        let db = database().await;
        let fake = fake_with(&[(85, 24 * 30)]).await;

        let mut config = fake.fluxer_config(&fake);
        config.reconcile_after_hours = 0;
        let mut cursor = None;
        for _ in 0..2 {
            assert_eq!(
                run_configured_pass(&db, &config, &mut cursor, &FAST).await,
                None
            );
        }
        assert!(fake.seen().is_empty(), "{:?}", fake.seen());
        assert_eq!(cursor, None);

        // Switched on, the same fake is called: the check above is not
        // vacuous.
        config.reconcile_after_hours = GRACE;
        assert!(run_configured_pass(&db, &config, &mut cursor, &FAST)
            .await
            .is_some());
        assert_eq!(deletes(&fake), vec![leave_path(85)]);
    }

    /// A whole pass judges both the join time and the last job by the
    /// configured `reconcile_after_hours`, read from the config.
    #[tokio::test]
    async fn a_pass_uses_the_configured_grace() {
        // Joined 30 h ago; joined 50 h ago; joined 72 h ago with a job
        // finished 30 h ago.
        let guilds = [(91, 30), (92, 50), (93, 72)];

        let db = database().await;
        job_on(&db, 93, 30).await;

        // 48 h: 91 joined too recently, 93's job is recent, 92 is left.
        let fake = fake_with(&guilds).await;
        let mut config = fake.fluxer_config(&fake);
        config.reconcile_after_hours = 48;
        let report = run_configured_pass(&db, &config, &mut None, &FAST)
            .await
            .unwrap();
        assert_eq!(
            report,
            PassReport {
                listed: 3,
                complete: true,
                calls: 3,
                left: 1,
                kept_for_job: 1,
                kept_joined_recently: 1,
                ..PassReport::default()
            }
        );
        assert_eq!(deletes(&fake), vec![leave_path(92)]);
        assert_eq!(lookups(&fake), vec![lookup_path(91), lookup_path(92)]);

        // 24 h: every one of them is past it, the job included.
        let fake = fake_with(&guilds).await;
        let mut config = fake.fluxer_config(&fake);
        config.reconcile_after_hours = 24;
        let report = run_configured_pass(&db, &config, &mut None, &FAST)
            .await
            .unwrap();
        assert_eq!(report.left, 3, "{report:?}");
        assert_eq!(
            deletes(&fake),
            vec![leave_path(91), leave_path(92), leave_path(93)]
        );
    }
}
