//! Claim-based import worker + heartbeat sweeper.
//!
//! Delta only writes a `Queued` job; all the work happens here. That follows
//! the repo's universal background-job shape (every other long task lives in
//! crond) and buys restart-safety and a natural cross-process concurrency
//! bound for free — a `tokio::spawn` inside a Rocket handler would die on
//! every deploy with no supervision.
//!
//! ## Ownership invariant
//!
//! A claim is not permanent. Every progress write goes through
//! `save_discord_import_job_if_active`, which refuses to write once the job
//! has reached a terminal state. If a write is refused, some other actor (a
//! sweeper on another crond, most likely) has finalized the job and this
//! worker must abandon it immediately — including rolling back the half-built
//! server. That is what makes sweeper-side cleanup safe.

use std::collections::HashMap;
use std::time::Duration;

use futures::future::BoxFuture;
use iso8601_timestamp::Timestamp;
use revolt_config::{config, Settings};
use revolt_database::{
    events::client::EventV1, Category, Channel, Database, DiscordImportJob, DiscordImportSummary,
    Emoji, EmojiParent, File, ImportJobKind, ImportStage, ImportStatus, Invite, Member,
    PartialChannel, PartialServer, Role, Server, SystemMessageChannels, User, AMQP,
};
use revolt_models::v0;
use revolt_permissions::OverrideField;
use revolt_result::{ErrorType, Result};
use tokio::time::sleep;

use super::assets::{store_file, AssetFetcher, NoAssets};
use super::mapper::{
    everyone_can_view, plan_import, AssetKind, ImportPlan, PlannedAsset, PlannedChannel,
    PlannedChannelKind, PlannedOverride,
};
use super::template::{self, PlaceholderId, TemplateFetchError};

/// Template placeholder role id → the real Sloga role id it became.
type RoleMap = HashMap<String, String>;

/// How often we look for queued work. Deliberately much tighter than the
/// 60s house tick: a human is staring at a progress bar waiting for this.
const TICK: Duration = Duration::from_secs(3);

/// Idle tick when the feature is switched off entirely — no reason to poll the
/// database every 3s for work that can't exist.
const DISABLED_TICK: Duration = Duration::from_secs(60);

/// Sweep every Nth tick rather than every tick (≈30s), so an idle instance
/// isn't issuing 28k redundant scans a day.
const SWEEP_EVERY_N_TICKS: u32 = 10;

/// A job whose heartbeat is older than this is presumed dead (delta/crond
/// restarted mid-import) and gets reaped.
///
/// Checked against `updated_at`, which is bumped on **every** stage — never
/// against creation time. A large guild legitimately takes minutes, and
/// reaping on age would kill a healthy import mid-run and then race its own
/// completion write.
const HEARTBEAT_TIMEOUT_SECS: i64 = 300;

/// How long the sweeper keeps retrying the bot's leave for a finished
/// source job before giving up loudly. See `retry_source_leaves_with`.
const LEAVE_RETRY_DAYS: i64 = 7;

/// The leave-retry scan reads a day further back than it retries, so a job
/// crossing the cap is seen (and logged, and marked) rather than silently
/// aging out of the query.
const LEAVE_RETRY_WINDOW_DAYS: i64 = LEAVE_RETRY_DAYS + 1;

/// Finished source jobs processed per sweep.
const LEAVE_RETRY_BATCH: i64 = 20;

/// Why an import stopped early. Shared with the sticker worker and the
/// source importers.
pub(crate) enum ImportAbort {
    /// Genuine failure; the string is user-safe and gets stored + pushed.
    Failed(String),
    /// Another actor finalized this job while we held it. Do not write
    /// anything further — whatever finalized it already told the user.
    Superseded,
}

pub async fn task(db: Database, _amqp: AMQP) -> Result<()> {
    let mut tick: u32 = 0;

    loop {
        let config = config().await;

        // The claim loop runs while ANY source is switched on. That alone
        // would weaken the Discord kill switch, so `run_job` re-checks each
        // job's own source (`kind_source_ready`) and fails the job when it
        // is off.
        if !housekeeping(&db, &config, tick, &leave_source).await {
            sleep(DISABLED_TICK).await;
            continue;
        }
        tick = tick.wrapping_add(1);

        // Drain the queue rather than taking one per tick, so a burst doesn't
        // serialize at 3s apiece. Bounded per tick so a steady stream of work
        // can't starve the sweeper indefinitely.
        for _ in 0..SWEEP_EVERY_N_TICKS {
            match db.claim_next_queued_discord_import_job().await {
                Ok(Some(job)) => run_job(&db, job, &config).await,
                Ok(None) => break,
                Err(error) => {
                    log::error!("failed to claim discord import job: {error:?}");
                    break;
                }
            }
        }

        sleep(TICK).await;
    }
}

/// The sweeps a tick owes before any claiming. Returns whether any source
/// is switched on, i.e. whether the claim loop should run.
///
/// Both sweeps run whatever is switched on. Rows whose bot has not left yet
/// must keep being retried (and, past the cap, given up on loudly) after
/// every import source is turned off. So must the stale-job sweep: a source
/// job orphaned while Running is only made terminal by it, and until it is
/// the bot never leaves and its owner's one active job is never freed.
/// Switched off, both run once per idle tick (`DISABLED_TICK`, slower than
/// the sweep cadence while on); the tick counter does not advance there, so
/// the cadence check cannot be used.
async fn housekeeping(db: &Database, config: &Settings, tick: u32, leave: &LeaveHook) -> bool {
    if !config.api.import.any_enabled() {
        if let Err(error) = sweep_stale(db).await {
            log::error!("discord import sweeper failed: {error:?}");
        }
        retry_source_leaves_with(db, config, leave).await;
        return false;
    }

    if tick % SWEEP_EVERY_N_TICKS == 0 {
        if let Err(error) = sweep_stale(db).await {
            log::error!("discord import sweeper failed: {error:?}");
        }
        retry_source_leaves_with(db, config, leave).await;
    }
    true
}

/// Fail jobs whose worker vanished, so the UI never spins forever.
///
/// Covers `Queued` as well as `Running`: a job nothing ever claimed (crond
/// down, or not yet restarted to pick up the feature flag) would otherwise sit
/// there forever, and — because the active-job guard counts it — lock its owner
/// out of the feature permanently.
async fn sweep_stale(db: &Database) -> Result<()> {
    // NB: `iso8601_timestamp::Duration` is `time::Duration`, not
    // `std::time::Duration` — same name, different types.
    let Some(cutoff) = Timestamp::now_utc()
        .checked_sub(iso8601_timestamp::Duration::seconds(HEARTBEAT_TIMEOUT_SECS))
    else {
        // Fail closed: a cutoff of "now" would reap every healthy import.
        log::error!("could not compute import sweeper cutoff; skipping sweep");
        return Ok(());
    };

    for mut job in db.fetch_stale_discord_import_jobs(cutoff).await? {
        log::warn!(
            "reaping discord import job {} (no heartbeat since {:?})",
            job.id,
            job.updated_at
        );

        // Clean up a server the dead worker created but never gave anyone
        // membership of. Without this it is invisible (bonfire builds the
        // server list from memberships), undeletable (server_delete requires a
        // membership row), and free (the quota counts memberships) — an orphan
        // that accumulates one per deploy-during-import.
        //
        // Ask the database whether the membership row exists rather than
        // inferring it from the stage. The stage is written BEFORE the work it
        // names, so a job stalled at `Membership` has not necessarily got one —
        // and a stage-name list silently stops covering new stages the moment
        // somebody adds one without editing it here.
        //
        // ONLY `NotFound` means "no membership row". Treating every error as
        // one would let a single Mongo blip delete a server that is fully built
        // and live: `Server::delete` cascades channels, messages, events and
        // boosts and broadcasts `ServerDelete`, with no undo. It would also
        // never surface in development, because `query!` unwraps in debug
        // builds — the mappable-error path exists only in release.
        //
        // Leaving an orphan behind is cheap and recoverable; deleting a real
        // server is neither. So anything ambiguous skips the rollback.
        //
        // KIND GATE, load-bearing: only a job kind that BUILDS a server (a
        // template or a source import) can ever have built the server it
        // points at. A sticker job's `server_id` is a fully-built, LIVE
        // server inherited from its parent — and if its owner happens to
        // have left that server, the membership probe below answers NotFound
        // and the ungated rollback would delete the whole thing, cascades and
        // all, to reap a job whose worst real failure is "some stickers
        // missing". Guarded by
        // `reaped_sticker_job_never_rolls_back_the_server`.
        let rollback_eligible = job.kind.builds_server();
        let orphan = match &job.server_id {
            Some(_) if !rollback_eligible => None,
            Some(server_id) => match db.fetch_member(server_id, &job.user_id).await {
                Ok(_) => None,
                Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
                    Some(server_id.clone())
                }
                Err(error) => {
                    log::error!(
                        "could not determine membership for reaped import {} \
                         (server {server_id}); leaving the server in place: {error:?}",
                        job.id
                    );
                    None
                }
            },
            None => None,
        };

        let reaped = fail_job(
            db,
            &mut job,
            "The import stopped unexpectedly. Please try again.".to_string(),
        )
        .await;

        // Only clean up if WE were the one that finalized it — otherwise the
        // job completed in the gap and that server is real.
        if reaped {
            if let Some(server_id) = orphan {
                rollback_server(db, &server_id).await;
            }

            // The terminal status is persisted (by `fail_job` above), so the
            // bot can now leave the source unless another job still uses it.
            if job.kind.is_source() {
                on_terminal(db, &mut job, &config().await).await;
            }
        }
    }

    Ok(())
}

/// Retry the bot's leave for finished source jobs it has not left yet.
///
/// A leave fails when the source API is down or rate-limiting, and it is
/// skipped while another job still uses the source; either way the job stays
/// `source_left == false` and comes back here on the next sweep. Each source
/// treats "that server no longer exists / the bot is not in it" as LEFT, so
/// a deleted source cannot keep a row in this queue.
///
/// The scan is oldest-first and bounded, so rows that can never leave would
/// otherwise starve newer ones. Hence the age cap: a job finished more than
/// `LEAVE_RETRY_DAYS` ago is logged loudly ONCE (job id, kind, source id,
/// never a token) and marked left so it stops occupying the batch; the bot
/// may still be in that source and has to be removed by hand. The query
/// reads one day further back than the cap so a job crossing it is seen and
/// logged instead of silently aging out of the window.
///
/// `leave` is `leave_source` outside tests.
async fn retry_source_leaves_with(db: &Database, config: &Settings, leave: &LeaveHook) {
    let jobs = match db
        .fetch_unleft_terminal_source_jobs(LEAVE_RETRY_WINDOW_DAYS, LEAVE_RETRY_BATCH)
        .await
    {
        Ok(jobs) => jobs,
        Err(error) => {
            log::error!("could not list import sources awaiting a bot leave: {error:?}");
            return;
        }
    };

    // Fails closed: without a cutoff nothing is given up on.
    let give_up_before =
        Timestamp::now_utc().checked_sub(iso8601_timestamp::Duration::days(LEAVE_RETRY_DAYS));

    for mut job in jobs {
        if give_up_before.is_some_and(|cutoff| job.updated_at < cutoff) {
            log::error!(
                "import job {} ({}) could not confirm the importer bot left source {} within \
                 {LEAVE_RETRY_DAYS} days; giving up — remove the bot from that source by hand",
                job.id,
                job.kind.as_variant_str(),
                job.source_server_id.as_deref().unwrap_or("<unknown>"),
            );
            if let Err(error) = db.mark_source_left(&job.id).await {
                log::error!("could not mark import job {} as left: {error:?}", job.id);
            }
            continue;
        }

        on_terminal_with(db, &mut job, config, leave).await;
    }
}

/// What a source does once one of its jobs is terminal: make the operator
/// bot leave the source. Returns whether it has left. `false` keeps the job
/// in the leave retry; "the source is gone or the bot is not in it" counts
/// as left.
type LeaveHook = dyn for<'a> Fn(&'a Database, &'a mut DiscordImportJob, &'a Settings) -> BoxFuture<'a, bool>
    + Send
    + Sync;

/// Per-source leave dispatch. A source without an importer cannot report
/// having left; each source's importer replaces its own arm.
fn leave_source<'a>(
    _db: &'a Database,
    job: &'a mut DiscordImportJob,
    config: &'a Settings,
) -> BoxFuture<'a, bool> {
    Box::pin(async move {
        match job.kind {
            ImportJobKind::StoatServer => crate::tasks::stoat_import::leave(job, config).await,
            ImportJobKind::FluxerServer => false,
            ImportJobKind::MatrixSpace => false,
            // Never reached: `on_terminal` returns early for these.
            ImportJobKind::Template | ImportJobKind::Stickers => false,
        }
    })
}

/// Clean up after a job reached a terminal state: for a source kind, the
/// operator bot leaves the source, unless another active job still uses it.
///
/// Call only once the terminal status is PERSISTED. The "another job still
/// uses this source" check reads the database, so of two jobs on one source
/// finishing together at least the later one sees the other's terminal row
/// and leaves (a second leave is harmless: "not in it" counts as left). If
/// this job's status were still in flight, both could see the other as
/// active, both skip, and the bot would stay until the leave retry.
///
/// Template and sticker jobs have no source to leave: nothing happens. A
/// skip leaves `source_left` false, so the sweeper's leave retry re-checks
/// it later. Errors are logged, never raised.
pub(crate) async fn on_terminal(db: &Database, job: &mut DiscordImportJob, config: &Settings) {
    on_terminal_with(db, job, config, &leave_source).await
}

async fn on_terminal_with(
    db: &Database,
    job: &mut DiscordImportJob,
    config: &Settings,
    leave: &LeaveHook,
) {
    if !job.kind.is_source() || job.source_left {
        return;
    }

    if let Some(source_server_id) = job.source_server_id.as_deref() {
        match db
            .has_other_active_job_for_source(&job.kind, source_server_id, &job.id)
            .await
        {
            Ok(false) => {}
            Ok(true) => {
                log::info!(
                    "import job {}: another job still uses its source; the bot stays for now",
                    job.id
                );
                return;
            }
            Err(error) => {
                // Leaving under a job that still needs the bot would fail
                // that job; the retry will ask again.
                log::error!(
                    "import job {}: could not check for other jobs on its source: {error:?}",
                    job.id
                );
                return;
            }
        }
    }

    if !leave(db, job, config).await {
        return;
    }

    match db.mark_source_left(&job.id).await {
        Ok(()) => job.source_left = true,
        Err(error) => log::error!(
            "import job {}: the bot left its source but that could not be recorded: {error:?}",
            job.id
        ),
    }
}

/// Delete a half-built server. Best-effort: a failure here leaves an orphan,
/// which is bad but strictly better than aborting the cleanup pass.
///
/// Emojis first. Deleting a server only detaches its emojis (and on the
/// Reference driver does not touch them at all), and an emoji's file is used by the
/// emoji id, not the server id, so server deletion never removes it. The
/// emojis have to be found while they still point at the server.
async fn rollback_server(db: &Database, server_id: &str) {
    match db.fetch_emoji_by_parent_id(server_id).await {
        Ok(emojis) if !emojis.is_empty() => {
            let ids: Vec<String> = emojis.iter().map(|emoji| emoji.id.clone()).collect();
            for emoji in &emojis {
                if let Err(error) = db.detach_emoji(emoji).await {
                    log::error!(
                        "failed to detach emoji {} during rollback: {error:?}",
                        emoji.id
                    );
                }
            }
            if let Err(error) = db.delete_attachments_used_by(&ids).await {
                log::error!(
                    "failed to delete emoji files of server {server_id} during rollback: {error:?}"
                );
            }
        }
        Ok(_) => {}
        Err(error) => log::error!(
            "could not list emojis of server {server_id} for rollback; their files stay: {error:?}"
        ),
    }

    match db.fetch_server(server_id).await {
        Ok(server) => {
            log::warn!("rolling back partially imported server {server_id}");
            if let Err(error) = server.delete(db).await {
                log::error!("failed to roll back server {server_id}: {error:?}");
            }
        }
        Err(error) => log::warn!("could not fetch server {server_id} for rollback: {error:?}"),
    }
}

/// Persist progress + heartbeat, and tell the user's client about it.
///
/// Returns `false` if the job is no longer ours — see the ownership invariant
/// in the module docs. Transient database errors return `true`: losing one
/// heartbeat write is not grounds to abandon a running import.
pub(crate) async fn progress(
    db: &Database,
    job: &mut DiscordImportJob,
    stage: ImportStage,
    done: u32,
    total: u32,
) -> bool {
    job.stage = stage;
    job.done = done;
    job.total = total;
    job.touch();

    match db.save_discord_import_job_if_active(job).await {
        Ok(false) => {
            log::warn!("import job {} was finalized elsewhere; abandoning", job.id);
            return false;
        }
        Err(error) => {
            log::error!(
                "failed to persist import progress for {}: {error:?}",
                job.id
            )
        }
        Ok(true) => {}
    }

    EventV1::DiscordImportProgress {
        job_id: job.id.clone(),
        stage: job.stage.as_variant_str().to_string(),
        done,
        total,
    }
    .private(job.user_id.clone())
    .await;

    true
}

/// Mark a job failed. Returns whether this call is the one that finalized it —
/// `false` means someone else got there first and no event was sent.
async fn fail_job(db: &Database, job: &mut DiscordImportJob, message: String) -> bool {
    job.status = ImportStatus::Failed;
    job.error = Some(message.clone());
    job.touch();

    match db.save_discord_import_job_if_active(job).await {
        Ok(true) => {}
        Ok(false) => {
            log::warn!("import job {} already finalized; not overwriting", job.id);
            return false;
        }
        Err(error) => {
            log::error!("failed to persist import failure for {}: {error:?}", job.id);
            return false;
        }
    }

    EventV1::DiscordImportFailed {
        job_id: job.id.clone(),
        error: message,
    }
    .private(job.user_id.clone())
    .await;

    true
}

/// Generic failure text. Anything the user could act on gets a specific
/// message at the call site; this is the catch-all and must never leak
/// internals.
pub(crate) fn generic_failure() -> String {
    "Something went wrong while importing your server. Please try again.".to_string()
}

/// Whether jobs of `kind` may run under `config`: the per-kind half of the
/// kill switch (the claim loop runs while any source is on).
///
/// Template and sticker jobs use exactly the gates their delta routes use:
/// `discord.enabled` for a template, `stickers_enabled()` for stickers.
pub(crate) fn kind_source_ready(kind: &ImportJobKind, config: &Settings) -> bool {
    let import = &config.api.import;
    match kind {
        ImportJobKind::Template => import.discord.enabled,
        ImportJobKind::Stickers => import.discord.stickers_enabled(),
        ImportJobKind::StoatServer => import.stoat_ready(),
        ImportJobKind::FluxerServer => import.fluxer_ready(),
        ImportJobKind::MatrixSpace => import.matrix_ready(),
    }
}

/// What a job is failed with when its source is switched off or has no
/// importer on this instance.
fn source_unavailable_message(kind: &ImportJobKind) -> String {
    match kind {
        ImportJobKind::Template => "Importing from Discord is not available on this instance.",
        // The sticker worker's own message for its (identical) re-check.
        ImportJobKind::Stickers => super::stickers::STICKERS_DISABLED,
        ImportJobKind::StoatServer => "Importing from Stoat is not available on this instance.",
        ImportJobKind::FluxerServer => "Importing from Fluxer is not available on this instance.",
        ImportJobKind::MatrixSpace => "Importing from Matrix is not available on this instance.",
    }
    .to_string()
}

async fn run_job(db: &Database, mut job: DiscordImportJob, config: &Settings) {
    let result = if !kind_source_ready(&job.kind, config) {
        // This job's source is off. Fail it rather than leave it queued:
        // the claim cannot skip a kind, and handing the row back would have
        // it re-claimed at once, ahead of every newer job.
        Err(ImportAbort::Failed(source_unavailable_message(&job.kind)))
    } else {
        // Kind dispatch. The paths share the job/progress/failure machinery
        // but almost nothing else — in particular the sticker path NEVER
        // rolls a server back (its `server_id` is a live server it did not
        // build).
        match job.kind {
            ImportJobKind::Template => import(db, &mut job).await,
            ImportJobKind::Stickers => super::stickers::import_stickers(db, &mut job).await,
            ImportJobKind::StoatServer => {
                crate::tasks::stoat_import::run(db, &mut job, config).await
            }
            // No importer for these sources on this build: fail closed so a
            // row can never sit unclaimed.
            ImportJobKind::FluxerServer => {
                Err(ImportAbort::Failed(source_unavailable_message(&job.kind)))
            }
            ImportJobKind::MatrixSpace => {
                Err(ImportAbort::Failed(source_unavailable_message(&job.kind)))
            }
        }
    };

    match result {
        Ok(()) => {}
        Err(ImportAbort::Superseded) => {
            // Deliberately silent: whoever finalized the job already informed
            // the user, and (for a server-building job) any server we built
            // was rolled back below.
        }
        Err(ImportAbort::Failed(message)) => {
            fail_job(db, &mut job, message).await;
        }
    }

    // After the terminal write, never before: see `on_terminal`.
    on_terminal(db, &mut job, config).await;
}

async fn import(db: &Database, job: &mut DiscordImportJob) -> std::result::Result<(), ImportAbort> {
    // Checked before anything leaves the process. `execute_plan` fetches the
    // owner again; this one keeps a deleted owner from costing a template
    // fetch.
    db.fetch_user(&job.user_id)
        .await
        .map_err(|_| ImportAbort::Failed(generic_failure()))?;

    // 1. Fetch the template.
    if !progress(db, job, ImportStage::Fetching, 0, 0).await {
        return Err(ImportAbort::Superseded);
    }

    let fetched = template::fetch_template(&job.template_code)
        .await
        .map_err(|error: TemplateFetchError| ImportAbort::Failed(error.user_message()))?;

    // Remember which guild this template came from — the optional sticker
    // step needs it later, and only the template payload knows. Validated as
    // a numeric snowflake HERE, because downstream it is interpolated into a
    // bot-authenticated API URL (same hygiene as template codes; a value
    // that fails the parse is dropped, not stored).
    job.source_guild_id = fetched
        .source_guild_id
        .as_deref()
        .filter(|id| id.parse::<u64>().is_ok())
        .map(String::from);

    // The mapper refuses templates whose permission shape it cannot read with
    // certainty, rather than guessing — see `mapper::PlanError`.
    let plan = plan_import(&fetched).map_err(|error| {
        log::warn!("refusing discord template for job {}: {error:?}", job.id);
        ImportAbort::Failed(error.user_message())
    })?;

    // Templates carry no images.
    execute_plan(db, job, plan, &NoAssets).await
}

/// Build the server a plan describes and hand it to the job's owner: the
/// shared back half of every server-building import.
///
/// Owns the time-of-use restriction and quota re-checks, `Server::create`,
/// roles, channels, the Assets stage (icon, banner, emojis — skipped
/// entirely when the plan has none), categories and system channels,
/// membership, the welcome invite and the completion write; and on any
/// failure after `Server::create`, rolling the server back. A source's
/// importer is only fetch → verify → map → this.
///
/// Asset downloads that fail are notes on the summary, never a failed
/// import.
pub(crate) async fn execute_plan(
    db: &Database,
    job: &mut DiscordImportJob,
    plan: ImportPlan,
    fetch_asset: &dyn AssetFetcher,
) -> std::result::Result<(), ImportAbort> {
    execute_plan_with(db, job, plan, fetch_asset, &StoredChannels).await
}

/// `execute_plan` with the channel writes as a seam (tests fail them).
async fn execute_plan_with(
    db: &Database,
    job: &mut DiscordImportJob,
    plan: ImportPlan,
    fetch_asset: &dyn AssetFetcher,
    writes: &dyn ChannelWrites,
) -> std::result::Result<(), ImportAbort> {
    let owner = db
        .fetch_user(&job.user_id)
        .await
        .map_err(|_| ImportAbort::Failed(generic_failure()))?;

    let total = plan.total_steps().max(1);

    // 2. Create the server shell.
    if !progress(db, job, ImportStage::Server, 0, total).await {
        return Err(ImportAbort::Superseded);
    }

    let config = config().await;

    // Time-of-use re-check of the operator gate (the route checks it too, but
    // config can change between queueing and running).
    if !config
        .features
        .limits
        .global
        .restrict_server_creation
        .is_empty()
        && !config
            .features
            .limits
            .global
            .restrict_server_creation
            .contains(&owner.id)
    {
        return Err(ImportAbort::Failed(
            "Server creation is restricted on this instance.".to_string(),
        ));
    }

    owner.can_acquire_server(db).await.map_err(|_| {
        ImportAbort::Failed("You've reached the maximum number of servers.".to_string())
    })?;

    // `create_default_channels = false`: the importer supplies every channel,
    // and a stray auto-created "General" would be wrong.
    let (server, _) = Server::create(
        db,
        v0::DataCreateServer {
            name: plan.server_name.clone(),
            description: plan.server_description.clone(),
            // `Server::create` stores `None` as false, so a Discord plan
            // (always false) creates exactly the server it did before.
            nsfw: Some(plan.nsfw),
        },
        &owner,
        false,
    )
    .await
    .map_err(|_| ImportAbort::Failed(generic_failure()))?;

    let server_id = server.id.clone();
    job.server_id = Some(server_id.clone());

    // Everything past this point can leave a half-built server behind, so it
    // runs in an inner call whose failures trigger a rollback.
    match build_server(db, job, &owner, server, &plan, total, fetch_asset, writes).await {
        Ok(()) => Ok(()),
        Err(abort) => {
            rollback_server(db, &server_id).await;
            job.server_id = None;
            Err(abort)
        }
    }
}

/// Populate the server and hand it to its owner. Any error here means the
/// caller rolls the whole server back.
#[allow(clippy::too_many_arguments)]
async fn build_server(
    db: &Database,
    job: &mut DiscordImportJob,
    owner: &User,
    mut server: Server,
    plan: &ImportPlan,
    total: u32,
    fetch_asset: &dyn AssetFetcher,
    writes: &dyn ChannelWrites,
) -> std::result::Result<(), ImportAbort> {
    // 3. Roles, before channels — per-channel overwrites are keyed by role id.
    let (roles, roles_created, roles_skipped, role_notes) =
        create_roles(db, job, &mut server, plan).await?;

    // 4. Channels, with their permission overwrites resolved against `roles`.
    let (channels, mut summary) =
        create_channels(db, &mut server, plan, job, total, &roles, writes).await?;
    summary.roles_created = roles_created;
    summary.roles_skipped = roles_skipped;
    summary.notes.extend(role_notes);

    // 4b. Icon, banner and emojis. Only when the plan has any: a Discord
    // template has none, and its job must never record the `Assets` stage
    // (a delta from before that stage existed could not read the row).
    let assets = if plan.has_assets() {
        import_assets(db, job, owner, &server, plan, fetch_asset).await?
    } else {
        ImportedAssets::default()
    };
    summary.notes.extend(assets.notes);

    // 5. Categories + system messages + the imported `@everyone` baseline
    // (+ icon and banner), persisted AND applied in memory.
    //
    // This matters beyond persistence: `ServerCreate` (emitted by
    // `Member::create` below) snapshots the IN-MEMORY server, so anything
    // missing here renders as missing on the client.
    let categories = build_categories(plan, &channels);
    summary.categories_created = categories.len() as u32;

    let system_messages = resolve_system_messages(plan, &channels);

    // Discord's AFK channel is a guild-level pointer, so it lands here with the
    // rest of the server document, never on the channel-create DTO (see the
    // `afk: None` literal in `create_channels`). A brand-new server has nobody
    // in voice, so there are no occupants whose grants the designation would
    // need re-syncing (`sync_afk_designation_change` is for live servers).
    let (afk_channel_id, afk_timeout) = afk_designation(plan, &channels);

    let created_channels: Vec<Channel> = channels.iter().map(|(_, c)| c.clone()).collect();

    server
        .update(
            db,
            PartialServer {
                channels: Some(
                    created_channels
                        .iter()
                        .map(|c| c.id().to_string())
                        .collect(),
                ),
                categories: if categories.is_empty() {
                    None
                } else {
                    Some(categories)
                },
                system_messages,
                // The Discord `@everyone` role is not a Sloga role — its
                // permissions are the server baseline. `Server::create` seeded
                // this with Sloga's own default, which we now replace.
                default_permissions: Some(plan.default_permissions as i64),
                afk_channel_id,
                afk_timeout,
                // Already claimed for this server (`use_server_icon` /
                // `use_server_banner`); `None` leaves the field unset.
                icon: assets.icon,
                banner: assets.banner,
                ..Default::default()
            },
            vec![],
        )
        .await
        .map_err(|_| ImportAbort::Failed(generic_failure()))?;

    // 6. Membership — LOAD-BEARING, and the single easiest thing to get wrong.
    //
    // `Server::create` writes the server document and emits NOTHING.
    // `Member::create` is the sole writer of the `server_members` row and the
    // sole emitter of `ServerCreate`. bonfire builds a user's server list from
    // their memberships, so skipping this produces an import that "succeeds"
    // and then vanishes from the client on the next reconnect.
    //
    // It must also run AFTER the server struct is fully populated (steps 3-5,
    // roles included) and BEFORE the completion event (step 8), so the client
    // has the server cached by the time it navigates to it.
    if !progress(db, job, ImportStage::Membership, total, total).await {
        return Err(ImportAbort::Superseded);
    }

    Member::create(db, &server, owner, Some(created_channels.clone()))
        .await
        .map_err(|_| ImportAbort::Failed(generic_failure()))?;

    // 7. Welcome invite — the actual payload of this feature ("paste this in
    // your Discord"). Best-effort: a server without an invite is still a
    // successful import, and the user can mint one by hand.
    if !progress(db, job, ImportStage::Invite, total, total).await {
        return Err(ImportAbort::Superseded);
    }

    let invite_code = match invite_target(server.default_permissions as u64, plan, &channels) {
        Some(target) => mint_invite(db, owner, target).await,
        None => {
            summary.notes.push(NO_INVITE_CHANNEL.to_string());
            None
        }
    };
    job.invite_code = invite_code.clone();

    // 8. Done.
    job.status = ImportStatus::Completed;
    job.stage = ImportStage::Done;
    job.done = total;
    job.total = total;
    job.summary = Some(summary);
    job.touch();

    match db.save_discord_import_job_if_active(job).await {
        Ok(true) => {}
        // Reaped in the gap: the sweeper already told the user it failed, and
        // it will have cleaned up. Don't claim success over that.
        Ok(false) => return Err(ImportAbort::Superseded),
        Err(_) => return Err(ImportAbort::Failed(generic_failure())),
    }

    EventV1::DiscordImportComplete {
        job_id: job.id.clone(),
        server_id: server.id.clone(),
        // Empty means "no invite was minted"; the job document is the
        // authoritative source (its `invite_code` is properly optional).
        invite_code: invite_code.unwrap_or_default(),
    }
    .private(job.user_id.clone())
    .await;

    Ok(())
}

/// Recreate the template's roles.
///
/// Returns the placeholder-id → real-id map that channel overwrites resolve
/// against, the created count, and any notes for the summary.
async fn create_roles(
    db: &Database,
    job: &mut DiscordImportJob,
    server: &mut Server,
    plan: &ImportPlan,
) -> std::result::Result<(RoleMap, u32, u32, Vec<String>), ImportAbort> {
    let role_limit = config().await.features.limits.global.server_roles;
    let mut roles: RoleMap = HashMap::new();
    let mut notes: Vec<String> = Vec::new();
    let mut created = 0u32;
    let mut failed = 0u32;

    // `plan.roles` is ordered most-authoritative-first, so truncating the tail
    // drops the *least* powerful roles. Capping beats failing: a guild over the
    // limit still gets an import, with the shortfall stated in the summary
    // (plan §7).
    let importable = plan.roles.len().min(role_limit);
    let over_limit = plan.roles.len() - importable;

    // The roles stage reports against its OWN item count, not the channel
    // total: reusing the channel denominator made a 60-role, 6-channel guild
    // render "0 / 6" for the whole phase and then jump — the stall-then-jump
    // the slice-0 audit already fixed once (#9).
    let role_total = importable as u32;

    if !progress(db, job, ImportStage::Roles, 0, role_total).await {
        return Err(ImportAbort::Superseded);
    }

    for planned in plan.roles[..importable].iter() {
        let role = Role {
            id: ulid::Ulid::new().to_string(),
            name: planned.name.clone(),
            // Discord role permissions are pure grants — deny exists only in
            // channel overwrites — so the Discord mapper always plans `deny:
            // 0`; other sources can carry role denies. The wire type is u64
            // and the stored type i64; this is the cast.
            permissions: OverrideField {
                a: planned.permissions as i64,
                d: planned.deny as i64,
            },
            colour: planned.colour.clone(),
            hoist: planned.hoist,
            // The mapper already performed the Discord-position-DESC →
            // Sloga-rank-ASC inversion; this is only the numbering. Ranks count
            // successes, not loop iterations, so a failed insert leaves no gap.
            rank: created as i64,
            icon: None,
        };

        if let Err(error) = db.insert_role(&server.id, &role).await {
            // One bad role must not cost the user the whole server.
            log::warn!("skipping role during import: {error:?}");
            failed += 1;
            continue;
        }

        roles.insert(planned.template_id.0.clone(), role.id.clone());

        // LOAD-BEARING. `insert_role` writes the database and nothing else,
        // while `ServerCreate` — emitted later by `Member::create` — snapshots
        // the IN-MEMORY server (`server_members/model.rs`, `server.clone()`).
        // Skip this line and the import "succeeds" with a client that shows a
        // server with no roles at all until the user reloads. Same class of
        // bug as the missing `Member::create` the first audit caught.
        server.roles.insert(role.id.clone(), role);
        created += 1;

        // Report successes, matching how `rank` is assigned — counting loop
        // iterations would run the bar ahead of reality after a failed insert.
        if !progress(db, job, ImportStage::Roles, created, role_total).await {
            return Err(ImportAbort::Superseded);
        }
    }

    if failed > 0 {
        notes.push(format!(
            "{failed} role(s) couldn't be created and were skipped."
        ));
    }

    if over_limit > 0 {
        notes.push(format!(
            "{over_limit} role(s) weren't imported — this server hit the {role_limit}-role limit. \
             The roles with the least authority were dropped first."
        ));
    }

    Ok((roles, created, failed + over_limit as u32, notes))
}

/// Turn a mapped override into the stored representation.
///
/// The wire/permission side of Sloga speaks u64 (`Override { allow, deny }`);
/// what lands in the database is i64 (`OverrideField { a, d }`). This is that
/// cast, in one place.
fn stored_override(planned: &PlannedOverride) -> OverrideField {
    OverrideField {
        a: planned.allow as i64,
        d: planned.deny as i64,
    }
}

/// The writes `create_channels` makes to a channel it has created: a seam so
/// tests can make them fail. Outside tests this is [`StoredChannels`].
trait ChannelWrites: Sync {
    /// `Channel::update`: applies `partial` in memory, then persists it.
    fn update<'a>(
        &'a self,
        db: &'a Database,
        channel: &'a mut Channel,
        partial: PartialChannel,
    ) -> BoxFuture<'a, Result<()>>;

    /// `Channel::delete`.
    fn delete<'a>(&'a self, db: &'a Database, channel: &'a Channel) -> BoxFuture<'a, Result<()>>;
}

/// The real channel writes.
struct StoredChannels;

impl ChannelWrites for StoredChannels {
    fn update<'a>(
        &'a self,
        db: &'a Database,
        channel: &'a mut Channel,
        partial: PartialChannel,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(channel.update(db, partial, vec![]))
    }

    fn delete<'a>(&'a self, db: &'a Database, channel: &'a Channel) -> BoxFuture<'a, Result<()>> {
        Box::pin(channel.delete(db))
    }
}

/// Whether a created channel whose permission write failed has to be
/// removed instead of kept.
///
/// Without its overrides a channel inherits the server default. Losing only
/// allows leaves it more closed than on the source, which fails safe. Losing
/// any deny leaves it more open, above all a private channel whose
/// `@everyone` ViewChannel deny is gone: that channel would be imported
/// public. Decided on the planned overrides, including any for a role that
/// was not created, which errs towards removing.
fn must_remove_without_overrides(planned: &PlannedChannel) -> bool {
    planned
        .default_permissions
        .is_some_and(|everyone| everyone.deny != 0)
        || planned
            .role_overrides
            .iter()
            .any(|(_, role)| role.deny != 0)
}

/// Create every planned channel, returning them paired with their template id
/// so categories and the system channel can be resolved afterwards.
///
/// A channel whose permission write fails and whose planned overrides deny
/// anything is removed again (with a note), and if that removal fails too
/// the import aborts: see `must_remove_without_overrides`.
async fn create_channels(
    db: &Database,
    server: &mut Server,
    plan: &ImportPlan,
    job: &mut DiscordImportJob,
    total: u32,
    roles: &RoleMap,
    writes: &dyn ChannelWrites,
) -> std::result::Result<(Vec<(String, Channel)>, DiscordImportSummary), ImportAbort> {
    let mut created: Vec<(String, Channel)> = Vec::new();
    let mut skipped = 0u32;
    let mut notes = plan.skipped.clone();

    // The model's own cap check reads `server.channels`, which stays empty for
    // this whole loop because we pass `update_server = false` — so it never
    // fires and a 500-channel guild would sail past a 200-channel limit.
    // Enforce it here instead, capping rather than hard-failing (plan §7).
    let channel_limit = config().await.features.limits.global.server_channels;
    let mut over_limit = 0u32;
    // Overwrites whose target role never made it into the server.
    let mut dropped_overrides = 0u32;
    // Channels created, but whose slowmode/permissions write failed.
    let mut settings_failed = 0u32;
    // Channels created, then removed because that write failed and lost a
    // deny (see `must_remove_without_overrides`).
    let mut removed = 0u32;

    for (index, planned) in plan.channels.iter().enumerate() {
        if created.len() >= channel_limit {
            over_limit += 1;
            continue;
        }

        let (channel_type, voice, announcement, slowmode) = match &planned.kind {
            PlannedChannelKind::Text {
                slowmode,
                announcement,
            } => (
                v0::LegacyServerChannelType::Text,
                None,
                Some(*announcement),
                *slowmode,
            ),
            PlannedChannelKind::Voice { max_users } => (
                v0::LegacyServerChannelType::Voice,
                Some(v0::VoiceInformation {
                    max_users: max_users.map(|value| value as usize),
                    disabled: false,
                }),
                None,
                None,
            ),
            PlannedChannelKind::Forum => (v0::LegacyServerChannelType::Forum, None, None, None),
        };

        let result = Channel::create_server_channel(
            db,
            server,
            v0::DataCreateServerChannel {
                channel_type,
                name: planned.name.clone(),
                description: planned.description.clone(),
                nsfw: Some(planned.nsfw),
                // Discord has no equivalent flag to import from.
                spoiler: None,
                voice,
                announcement,
                // Discord's `afk_channel_id` is a guild-level pointer, not a
                // per-channel flag, so there is nothing per-channel to map here.
                // The designation is written onto the server in step 5
                // (`afk_designation`). Do not "fix" this to `Some(true)`:
                // `create_server_channel` never reads `afk` (only delta's
                // channel_create route does), so that would silently do
                // nothing.
                //
                // Spelled out rather than covered by `..Default::default()`.
                // This literal is exhaustive on purpose: it is the tripwire
                // that forces whoever adds a field to
                // `DataCreateServerChannel` to decide what the Discord import
                // should do with it, instead of silently inheriting a default.
                // A spread here would have made that decision invisibly, and
                // the decision is the point.
                afk: None,
                afk_timeout: None,
                // The import never designates through this path (it does so in
                // step 5), so there is no timeout here to clear either.
                afk_timeout_never: None,
            },
            // Don't let the model push ids / emit ChannelCreate: the server
            // document is written once in step 4, and nobody is subscribed to
            // this server yet anyway.
            false,
        )
        .await;

        match result {
            Ok(mut channel) => {
                // Neither slowmode nor the permission overwrites are part of
                // the creation DTO, so they land in a single follow-up update.
                // `Channel::update` applies the partial in memory as well as
                // persisting it, which is what keeps the structs handed to
                // `Member::create` — and therefore `ServerCreate` — accurate.
                let role_permissions: HashMap<String, OverrideField> = planned
                    .role_overrides
                    .iter()
                    // A role dropped by the cap (or absent from the template)
                    // has no id to key on; its overwrite is skipped rather
                    // than written against a dangling id.
                    .filter_map(|(template_id, override_)| {
                        roles
                            .get(&template_id.0)
                            .map(|role_id| (role_id.clone(), stored_override(override_)))
                    })
                    .collect();

                // Count what failed to RESOLVE, not `len - map.len()`: the
                // mapper already rejects duplicate entries for one role, but
                // deriving the count from the map's size would silently absorb
                // any future duplicate into this figure and misreport it as a
                // dropped role reference.
                let unresolved = planned
                    .role_overrides
                    .iter()
                    .filter(|(template_id, _)| !roles.contains_key(&template_id.0))
                    .count() as u32;

                // Leaving `default_permissions` unset means "inherit the
                // server default", which is exactly right for a channel
                // Discord had no `@everyone` overwrite on. Writing an empty
                // override instead would pin it.
                let default_permissions = planned.default_permissions.as_ref().map(stored_override);

                let partial = PartialChannel {
                    slowmode,
                    default_permissions,
                    role_permissions: (!role_permissions.is_empty()).then_some(role_permissions),
                    ..Default::default()
                };

                let needs_update = partial.slowmode.is_some()
                    || partial.default_permissions.is_some()
                    || partial.role_permissions.is_some();

                let mut keep = true;
                if needs_update {
                    // `Channel::update` applies the partial in memory BEFORE
                    // it writes, so a failed write leaves the struct claiming
                    // settings the database does not have. This struct is
                    // what `ServerCreate` ships and what the invite check
                    // reads, so it goes back to what is stored.
                    let stored = channel.clone();
                    if let Err(error) = writes.update(db, &mut channel, partial).await {
                        log::warn!("could not apply channel settings during import: {error:?}");
                        channel = stored;

                        if must_remove_without_overrides(planned) {
                            // Fail closed: without its denies the channel is
                            // more open than on the source (a private channel
                            // imported public). Remove it; if even that
                            // fails, the whole import is rolled back rather
                            // than handed over with it in place.
                            if let Err(error) = writes.delete(db, &channel).await {
                                log::error!(
                                    "could not remove an imported channel whose permissions \
                                     failed to apply; abandoning the import: {error:?}"
                                );
                                return Err(ImportAbort::Failed(generic_failure()));
                            }
                            removed += 1;
                            keep = false;
                        } else {
                            // Only allows or slowmode were lost: the channel
                            // is, if anything, more closed than on the
                            // source. Worth a note, not the channel.
                            settings_failed += 1;
                        }
                    }
                }

                // A removed channel is not in `created`, so categories, the
                // system-message slots, the AFK pointer and the invite never
                // resolve to it.
                if keep {
                    dropped_overrides += unresolved;
                    created.push((planned.template_id.0.clone(), channel));
                }
            }
            Err(error) => {
                // One bad channel must not cost the user the whole server.
                log::warn!("skipping channel during import: {error:?}");
                skipped += 1;
            }
        }

        if !progress(db, job, ImportStage::Channels, (index + 1) as u32, total).await {
            return Err(ImportAbort::Superseded);
        }
    }

    if skipped > 0 {
        notes.push(format!(
            "{skipped} channel(s) couldn't be created and were skipped."
        ));
    }

    if over_limit > 0 {
        notes.push(format!(
            "{over_limit} channel(s) weren't imported — this server hit the {channel_limit}-channel limit."
        ));
    }

    if removed > 0 {
        notes.push(format!(
            "{removed} channel(s) weren't imported because their permissions couldn't be applied \
             — without them, more people could have seen or used them than on the original server."
        ));
    }

    if settings_failed > 0 {
        notes.push(format!(
            "{settings_failed} channel(s) were created but their permissions or slowmode couldn't \
             be applied — check them in channel settings."
        ));
    }

    if dropped_overrides > 0 {
        notes.push(format!(
            "{dropped_overrides} channel permission(s) referenced a role that wasn't imported and \
             were skipped."
        ));
    }

    let summary = DiscordImportSummary {
        channels_created: created.len() as u32,
        categories_created: 0, // set by the caller once categories are built
        // Everything the user didn't get, so this can't contradict the notes
        // rendered beside it.
        channels_skipped: skipped + over_limit + removed + plan.skipped_channel_count,
        // Both set by the caller; roles are created before this runs.
        roles_created: 0,
        roles_skipped: 0,
        // Template jobs have no sticker counts — None keeps them off the wire.
        stickers_created: None,
        stickers_skipped: None,
        notes,
    };

    Ok((created, summary))
}

fn resolve_channel_id(channels: &[(String, Channel)], template_id: &str) -> Option<String> {
    channels
        .iter()
        .find(|(id, _)| id == template_id)
        .map(|(_, channel)| channel.id().to_string())
}

/// The real channel ids the plan's system-message slots became, or `None`
/// when not one of them resolved (no system channels, or none created).
///
/// Each slot resolves on its own. A Discord plan points all four at one
/// channel, so they resolve or fail together, exactly like the single system
/// channel did before.
fn resolve_system_messages(
    plan: &ImportPlan,
    channels: &[(String, Channel)],
) -> Option<SystemMessageChannels> {
    let resolve = |slot: &Option<PlaceholderId>| {
        slot.as_ref()
            .and_then(|wanted| resolve_channel_id(channels, &wanted.0))
    };
    let planned = &plan.system_messages;
    let resolved = SystemMessageChannels {
        user_joined: resolve(&planned.user_joined),
        user_left: resolve(&planned.user_left),
        user_kicked: resolve(&planned.user_kicked),
        user_banned: resolve(&planned.user_banned),
    };

    (resolved.user_joined.is_some()
        || resolved.user_left.is_some()
        || resolved.user_kicked.is_some()
        || resolved.user_banned.is_some())
    .then_some(resolved)
}

/// What the Assets stage produced: the claimed icon and banner files for the
/// server update, and notes for whatever did not make it.
#[derive(Default)]
struct ImportedAssets {
    icon: Option<File>,
    banner: Option<File>,
    notes: Vec<String>,
}

/// Fetch, store and attach a server icon or banner (`slot` says which; the
/// plan field it came from decides, not the asset). `None` on any failure;
/// the caller turns that into a note.
async fn import_server_image(
    db: &Database,
    owner: &User,
    server: &Server,
    slot: AssetKind,
    asset: &PlannedAsset,
    fetch_asset: &dyn AssetFetcher,
) -> Option<File> {
    // Autumn's tags for these, which `use_server_icon` / `use_server_banner`
    // require the file to carry.
    let (tag, filename) = match slot {
        AssetKind::Icon => ("icons", "icon"),
        AssetKind::Banner => ("banners", "banner"),
        AssetKind::Emoji => return None,
    };

    let buf = fetch_asset.fetch(asset).await?;

    let file = match store_file(db, &owner.id, tag, filename, buf, asset.animated).await {
        Ok(file) => file,
        Err(error) => {
            log::warn!("could not store imported server {filename}: {error:?}");
            return None;
        }
    };

    let claimed = match slot {
        AssetKind::Icon => File::use_server_icon(db, &file.id, &server.id, &owner.id).await,
        _ => File::use_server_banner(db, &file.id, &server.id, &owner.id).await,
    };
    claimed
        .inspect_err(|error| log::warn!("could not attach imported server {filename}: {error:?}"))
        .ok()
}

/// Recreate one planned emoji on the server, the way delta's emoji route
/// does: the emoji id is its file's id (a ULID), the file is claimed for
/// that id, and `animated` follows the stored content type.
///
/// Returns whether the emoji now exists.
async fn import_emoji(
    db: &Database,
    owner: &User,
    server: &Server,
    name: &str,
    asset: &PlannedAsset,
    fetch_asset: &dyn AssetFetcher,
) -> bool {
    let Some(buf) = fetch_asset.fetch(asset).await else {
        return false;
    };

    let file = match store_file(db, &owner.id, "emojis", name, buf, asset.animated).await {
        Ok(file) => file,
        Err(error) => {
            log::warn!("could not store imported emoji: {error:?}");
            return false;
        }
    };

    if let Err(error) = File::use_emoji(db, &file.id, &file.id, &owner.id).await {
        log::warn!("could not claim imported emoji file: {error:?}");
        return false;
    }

    let emoji = Emoji {
        id: file.id.clone(),
        parent: EmojiParent::Server {
            id: server.id.clone(),
        },
        creator_id: owner.id.clone(),
        name: name.to_string(),
        animated: "image/gif" == file.content_type,
        nsfw: false,
    };

    match emoji.create(db).await {
        Ok(()) => true,
        Err(error) => {
            log::warn!("could not create imported emoji: {error:?}");
            // The file is claimed for an emoji that does not exist, so no
            // rollback would ever find it.
            if let Err(error) = db.delete_attachments_used_by(&[file.id]).await {
                log::warn!("could not delete the file of a failed emoji: {error:?}");
            }
            false
        }
    }
}

/// The Assets stage: icon, banner and emojis, before membership so the
/// `ServerCreate` snapshot carries them.
///
/// Emojis over the server's emoji cap (the same boost-aware cap delta's
/// emoji route applies) and emojis whose names Sloga would refuse are
/// skipped with a note. Nothing here fails the import except losing the job
/// to another actor.
async fn import_assets(
    db: &Database,
    job: &mut DiscordImportJob,
    owner: &User,
    server: &Server,
    plan: &ImportPlan,
    fetch_asset: &dyn AssetFetcher,
) -> std::result::Result<ImportedAssets, ImportAbort> {
    let config = config().await;
    let mut assets = ImportedAssets::default();

    let emoji_cap = config.features.boosts.effective_server_emoji(
        config.features.limits.global.server_emoji,
        server.boost_tier.unwrap_or_default() as u32,
    );
    let importable_emojis = plan.emojis.len().min(emoji_cap);
    let over_cap = plan.emojis.len() - importable_emojis;

    let total =
        (plan.icon.is_some() as u32) + (plan.banner.is_some() as u32) + importable_emojis as u32;
    let mut done = 0u32;

    if !progress(db, job, ImportStage::Assets, done, total.max(1)).await {
        return Err(ImportAbort::Superseded);
    }

    for (slot, planned) in [
        (AssetKind::Icon, &plan.icon),
        (AssetKind::Banner, &plan.banner),
    ] {
        let Some(asset) = planned else {
            continue;
        };

        let file = import_server_image(db, owner, server, slot, asset, fetch_asset).await;
        if file.is_none() {
            assets.notes.push(match slot {
                AssetKind::Icon => "The server icon couldn't be imported.".to_string(),
                _ => "The server banner couldn't be imported.".to_string(),
            });
        }
        match slot {
            AssetKind::Icon => assets.icon = file,
            _ => assets.banner = file,
        }

        done += 1;
        if !progress(db, job, ImportStage::Assets, done, total.max(1)).await {
            return Err(ImportAbort::Superseded);
        }
    }

    let mut invalid_names = 0u32;
    let mut failed = 0u32;
    for planned in &plan.emojis[..importable_emojis] {
        // Delta's `DataCreateEmoji` rules; the worker bypasses the route.
        let length = planned.name.chars().count();
        if !(1..=32).contains(&length) || !v0::RE_EMOJI.is_match(&planned.name) {
            invalid_names += 1;
        } else if !import_emoji(
            db,
            owner,
            server,
            &planned.name,
            &planned.asset,
            fetch_asset,
        )
        .await
        {
            failed += 1;
        }

        done += 1;
        if !progress(db, job, ImportStage::Assets, done, total.max(1)).await {
            return Err(ImportAbort::Superseded);
        }
    }

    if failed > 0 {
        assets.notes.push(format!(
            "{failed} emoji couldn't be imported and were skipped."
        ));
    }
    if invalid_names > 0 {
        assets.notes.push(format!(
            "{invalid_names} emoji had names Sloga doesn't allow (letters, numbers and \
             underscores, up to 32 characters) and were skipped."
        ));
    }
    if over_cap > 0 {
        assets.notes.push(format!(
            "{over_cap} emoji weren't imported — this server hit the {emoji_cap}-emoji limit."
        ));
    }

    Ok(assets)
}

/// The AFK designation step 5 writes: the real id the planned AFK channel got,
/// and its timeout.
///
/// The mapper already kept only a voice channel and a preset timeout. What it
/// cannot know is whether that channel was actually created (the channel cap,
/// or a failed insert), and a pointer to a channel that does not exist is
/// worse than none. The timeout drops with the channel: every Sloga writer
/// refuses a timeout with no channel to move people to.
fn afk_designation(
    plan: &ImportPlan,
    channels: &[(String, Channel)],
) -> (Option<String>, Option<u32>) {
    let afk_channel_id = plan
        .afk_channel
        .as_ref()
        .and_then(|wanted| resolve_channel_id(channels, &wanted.0));
    let afk_timeout = afk_channel_id.as_ref().and(plan.afk_timeout);
    (afk_channel_id, afk_timeout)
}

/// Build the category list from the plan, translating template placeholder ids
/// into real channel ids.
///
/// Only channels that actually got created are referenced: `server_edit`'s
/// validation drops category entries pointing at unknown ids, and a dangling
/// reference would silently lose the channel from the sidebar.
fn build_categories(plan: &ImportPlan, channels: &[(String, Channel)]) -> Vec<Category> {
    plan.categories
        .iter()
        .filter_map(|category| {
            let members: Vec<String> = plan
                .channels
                .iter()
                .filter(|channel| channel.parent.as_ref() == Some(&category.template_id))
                .filter_map(|channel| resolve_channel_id(channels, &channel.template_id.0))
                .collect();

            if members.is_empty() {
                return None;
            }

            Some(Category {
                id: ulid::Ulid::new().to_string(),
                title: category.title.clone(),
                channels: members,
            })
        })
        .collect()
}

/// Summary note when no created channel could take the welcome invite.
const NO_INVITE_CHANNEL: &str = "No invite link was created because none of the imported text \
     channels is visible to everyone. Create one from a channel new members should see.";

/// The channel the welcome invite goes in: the source's own pick (Discord:
/// the guild's system channel), else the first text channel, and either way
/// only a text channel `@everyone` can view (`everyone_can_view`). `None`
/// when no created channel qualifies, and then no invite is minted.
///
/// Anyone holding an invite can read its channel's name and description,
/// and joiners land in it, so a private channel must never be the target.
/// Read off the created channels, which carry what is stored (a channel
/// whose permission write failed is either removed or back to its stored
/// state), against the server default the import wrote.
fn invite_target<'a>(
    server_default: u64,
    plan: &ImportPlan,
    channels: &'a [(String, Channel)],
) -> Option<&'a Channel> {
    let invitable = |channel: &&Channel| match channel {
        // Voice channels are `TextChannel` with `voice: Some(..)`, so a naive
        // TextChannel match would happily drop new members into a voice room.
        Channel::TextChannel {
            voice: None,
            default_permissions,
            ..
        } => everyone_can_view(
            server_default,
            default_permissions.map(|everyone| PlannedOverride {
                allow: everyone.a as u64,
                deny: everyone.d as u64,
            }),
        ),
        _ => false,
    };

    plan.invite_channel
        .as_ref()
        .and_then(|wanted| {
            channels
                .iter()
                .find(|(id, _)| id == &wanted.0)
                .map(|(_, channel)| channel)
                .filter(invitable)
        })
        .or_else(|| channels.iter().map(|(_, channel)| channel).find(invitable))
}

/// Mint the welcome invite in `target` (see `invite_target`).
async fn mint_invite(db: &Database, owner: &User, target: &Channel) -> Option<String> {
    match Invite::create_channel_invite(db, owner, target).await {
        Ok(invite) => Some(invite.code().to_string()),
        Err(error) => {
            log::warn!("could not mint import invite: {error:?}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::template::GuildTemplate;
    use super::*;
    use revolt_database::DatabaseInfo;
    use revolt_permissions::ChannelPermission;

    /// Two ranked roles, one private channel, one public one.
    const FIXTURE: &str = r#"{
        "code": "test",
        "name": "Test Template",
        "serialized_source_guild": {
            "name": "Test Guild",
            "roles": [
                {"id": 0, "name": "@everyone", "permissions": "3072"},
                {"id": 1, "name": "Member", "permissions": "0", "color": 0},
                {"id": 2, "name": "Moderator", "permissions": "8192",
                 "color": 1752220, "hoist": true},
                {"id": 3, "name": "Admin", "permissions": "8"}
            ],
            "channels": [
                {"id": 10, "type": 4, "name": "STAFF", "position": 0},
                {"id": 11, "type": 0, "name": "mod-chat", "position": 0, "parent_id": 10,
                 "permission_overwrites": [
                    {"id": "0", "type": 0, "allow": "0", "deny": "1024"},
                    {"id": "2", "type": 0, "allow": "1024", "deny": "0"}
                 ]},
                {"id": 12, "type": 0, "name": "general", "position": 1,
                 "permission_overwrites": []}
            ]
        }
    }"#;

    // `insert_user` is disallowed in favour of `Object::create()`, but the real
    // account-creation flow is an authifier concern this test has no business
    // dragging in — it needs a user row and nothing else.
    #[allow(clippy::disallowed_methods)]
    async fn make_owner(db: &Database) -> User {
        let user = User {
            id: ulid::Ulid::new().to_string(),
            username: "importer".to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        };
        db.insert_user(&user).await.unwrap();
        user
    }

    /// **The invariant this whole slice turns on.**
    ///
    /// `db.insert_role` writes the database and nothing else, while
    /// `ServerCreate` — the only event that ever tells a client the server
    /// exists — is built by `Member::create` from the IN-MEMORY `Server`
    /// struct. So every role has to be inserted into `server.roles` as well,
    /// and the same goes for the channel structs' permission fields.
    ///
    /// Drop any of that and the import "succeeds" while the client renders a
    /// server with no roles until the user reloads. It is precisely the bug the
    /// slice-0 audit caught in its `Member::create` form, and no amount of
    /// testing the pure mapper can see it — it lives entirely in the worker.
    #[tokio::test]
    async fn in_memory_server_carries_roles_and_permissions_for_server_create() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;

        let template: GuildTemplate = serde_json::from_str(FIXTURE).unwrap();
        let plan = plan_import(&template).unwrap();

        let (mut server, _) = Server::create(
            &db,
            v0::DataCreateServer {
                name: plan.server_name.clone(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .unwrap();

        let mut job = DiscordImportJob::new(owner.id.clone(), "test".to_string());
        db.insert_discord_import_job(&job).await.unwrap();

        let (roles, created, skipped, _notes) =
            match create_roles(&db, &mut job, &mut server, &plan).await {
                Ok(result) => result,
                Err(_) => panic!("create_roles aborted"),
            };

        assert_eq!(created, 3, "every non-@everyone role should be created");
        assert_eq!(skipped, 0);

        // THE ASSERTION. Deliberately NOT `db.fetch_server(...)`: the database
        // was always right. It is the in-memory struct — the one `ServerCreate`
        // snapshots — that would be empty.
        assert_eq!(
            server.roles.len(),
            3,
            "roles reached the database but not the in-memory server; \
             ServerCreate would ship a server with no roles"
        );

        // Rank inversion survives into real rows: Admin is last in Discord's
        // ascending array, so it is the most authoritative, so it must hold
        // Sloga rank 0 — and the ranks must run 0,1,2 with no gaps.
        let ordered = server.ordered_roles();
        assert_eq!(
            ordered
                .iter()
                .map(|(_, role)| (role.name.as_str(), role.rank))
                .collect::<Vec<_>>(),
            vec![("Admin", 0), ("Moderator", 1), ("Member", 2)]
        );

        let moderator = &ordered[1].1;
        assert!(moderator.hoist);
        assert_eq!(moderator.colour.as_deref(), Some("#1ABC9C"));
        // Moderator held MANAGE_MESSAGES (Discord bit 13 = 8192).
        assert!(moderator.permissions.a & (ChannelPermission::ManageMessages as i64) != 0);

        let total = plan.total_steps().max(1);
        let (channels, summary) = match create_channels(
            &db,
            &mut server,
            &plan,
            &mut job,
            total,
            &roles,
            &StoredChannels,
        )
        .await
        {
            Ok(result) => result,
            Err(_) => panic!("create_channels aborted"),
        };

        assert_eq!(channels.len(), 2);
        assert_eq!(summary.channels_created, 2);

        let named = |wanted: &str| {
            channels
                .iter()
                .map(|(_, channel)| channel)
                .find(|channel| match channel {
                    Channel::TextChannel { name, .. } => name == wanted,
                    _ => false,
                })
                .unwrap_or_else(|| panic!("{wanted} should have been created"))
        };

        // These are the exact structs handed to `Member::create`, so the
        // overwrites have to be ON them, not merely persisted.
        match named("mod-chat") {
            Channel::TextChannel {
                default_permissions,
                role_permissions,
                ..
            } => {
                let default = default_permissions.expect("@everyone overwrite must be applied");
                assert_eq!(
                    default.d & (ChannelPermission::ViewChannel as i64),
                    ChannelPermission::ViewChannel as i64,
                    "the private channel must stay private"
                );
                let moderator_id = roles.get("2").expect("moderator id mapping");
                assert!(
                    role_permissions.contains_key(moderator_id),
                    "the Moderator overwrite must be keyed by its REAL role id"
                );

                // Discord's ADMINISTRATOR bypass, materialised: the Admin role
                // carries no overwrite in the template (it needs none on
                // Discord) but must be granted access here, or the imported
                // admins cannot see the private channel at all. Only the OWNER
                // bypasses on Sloga — which is why a one-account smoke test
                // would never notice.
                let admin_id = roles.get("3").expect("admin id mapping");
                let admin_grant = role_permissions
                    .get(admin_id)
                    .expect("admin must be granted access to the restricted channel");
                assert_eq!(admin_grant.a, ChannelPermission::GrantAllSafe as i64);
                assert_eq!(admin_grant.d, 0);

                assert_eq!(role_permissions.len(), 2);
            }
            _ => panic!("expected a text channel"),
        }

        // A channel Discord had no overwrites on must be left inheriting, not
        // pinned to an empty override.
        match named("general") {
            Channel::TextChannel {
                default_permissions,
                role_permissions,
                ..
            } => {
                assert!(default_permissions.is_none());
                assert!(role_permissions.is_empty());
            }
            _ => panic!("expected a text channel"),
        }

        // And the imported @everyone baseline must land on the struct too — it
        // rides `Server::update`, which applies the partial before it writes.
        server
            .update(
                &db,
                PartialServer {
                    default_permissions: Some(plan.default_permissions as i64),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();

        assert_eq!(server.default_permissions, plan.default_permissions as i64);
        assert!(
            server.default_permissions & (ChannelPermission::ChangeAvatar as i64) != 0,
            "Sloga baseline grants must survive onto the struct ServerCreate ships"
        );
    }

    /// **The one place slice 2 could destroy data — negative-controlled.**
    ///
    /// A sticker job's `server_id` is a LIVE server inherited from its
    /// Completed parent. If its owner has since LEFT that server, the
    /// sweeper's membership probe answers NotFound — the exact signal that,
    /// for a template job, means "half-built orphan, roll it back". Without
    /// the kind gate, reaping a stale sticker job would `Server::delete` a
    /// fully-built server (cascading channels, messages, events, no undo) to
    /// clean up a job whose worst real failure is "some stickers missing".
    ///
    /// The template control at the end is what makes this a real test:
    /// remove the `builds_server` kind gate in `sweep_stale` and the
    /// sticker half fails; break the orphan cleanup entirely and the
    /// template half fails.
    #[tokio::test]
    async fn reaped_sticker_job_never_rolls_back_the_server() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;

        // A server the owner holds NO membership row for — for a template
        // job this is the orphan condition; for a sticker job it just means
        // the owner left after importing.
        let (server, _) = Server::create(
            &db,
            v0::DataCreateServer {
                name: "Imported".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .unwrap();

        // A Completed parent to spawn the sticker job from, exactly as the
        // delta route does.
        let mut parent = DiscordImportJob::new(owner.id.clone(), "tmpl".to_string());
        parent.status = ImportStatus::Completed;
        parent.stage = ImportStage::Done;
        parent.server_id = Some(server.id.clone());
        parent.source_guild_id = Some("1530784817975660565".to_string());
        db.insert_discord_import_job(&parent).await.unwrap();

        // The sticker job goes stale (its worker died mid-batch).
        let mut sticker_job = DiscordImportJob::new_stickers(&parent);
        sticker_job.status = ImportStatus::Running;
        sticker_job.updated_at = Timestamp::now_utc()
            .checked_sub(iso8601_timestamp::Duration::hours(1))
            .unwrap();
        db.insert_discord_import_job(&sticker_job).await.unwrap();

        sweep_stale(&db).await.unwrap();

        // Reaped, yes — but the server MUST survive.
        assert_eq!(
            db.fetch_discord_import_job(&sticker_job.id)
                .await
                .unwrap()
                .status,
            ImportStatus::Failed,
            "the stale sticker job itself must be reaped"
        );
        db.fetch_server(&server.id)
            .await
            .expect("a reaped sticker job must NEVER take the live server with it");

        // CONTROL: the identical situation on a TEMPLATE job must still roll
        // the orphan back — proving the gate above is the kind check, not a
        // broken cleanup.
        let mut template_job = DiscordImportJob::new(
            "01USER0000000000000000STKT".to_string(),
            "tmpl2".to_string(),
        );
        template_job.status = ImportStatus::Running;
        template_job.server_id = Some(server.id.clone());
        template_job.updated_at = Timestamp::now_utc()
            .checked_sub(iso8601_timestamp::Duration::hours(1))
            .unwrap();
        db.insert_discord_import_job(&template_job).await.unwrap();

        sweep_stale(&db).await.unwrap();

        assert!(
            db.fetch_server(&server.id).await.is_err(),
            "control: the ungated template path must still clean up orphans"
        );
    }

    /// Audit #5's pin: no failure path of the sticker kind may touch the
    /// server it points at, nor the stickers already created.
    ///
    /// Two legs, both network-free:
    /// 1. FAILED — the job carries a non-numeric `source_guild_id`, so the
    ///    worker fails at its snowflake re-validation. Deliberately NOT the
    ///    feature-flag check: this box's real config has the bot keys
    ///    installed, and a test that leans on ambient config goes live (and
    ///    completes!) the day the flag turns on. Server + pre-created
    ///    sticker survive.
    /// 2. STALE SNAPSHOT — another actor already finalized the job, and a
    ///    worker holding the old Running snapshot runs it. The terminal
    ///    state must not be clobbered and nothing may be rolled back —
    ///    this is the same save-if-active discipline whose TEMPLATE-side
    ///    counterpart deliberately DOES roll a server back (worker::import's
    ///    Superseded arm), which is exactly the refactor hazard this pins.
    ///
    /// Honest limitation: a batch-interior Superseded (mid-download) needs a
    /// live Discord response and can't run here; the reachable-in-test legs
    /// plus `reaped_sticker_job_never_rolls_back_the_server` cover every
    /// rollback entry point that exists today.
    #[tokio::test]
    async fn failed_sticker_job_leaves_the_server_alone() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;

        let (server, _) = Server::create(
            &db,
            v0::DataCreateServer {
                name: "Imported".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .unwrap();

        // A sticker a previous (partially successful) run already created —
        // a retry gone wrong must not cost the user what they already have.
        let existing_sticker = revolt_database::Sticker {
            id: "stickerstickerstickersticker00000000000000".to_string(),
            server_id: server.id.clone(),
            creator_id: owner.id.clone(),
            name: "already-imported".to_string(),
            description: None,
            file_id: "stickerstickerstickersticker00000000000000".to_string(),
            format: revolt_database::StickerFormat::PNG,
            nsfw: false,
        };
        existing_sticker.create(&db).await.unwrap();

        let mut parent = DiscordImportJob::new(owner.id.clone(), "tmpl".to_string());
        parent.status = ImportStatus::Completed;
        parent.stage = ImportStage::Done;
        parent.server_id = Some(server.id.clone());
        parent.source_guild_id = Some("1530784817975660565".to_string());
        db.insert_discord_import_job(&parent).await.unwrap();

        // Leg 1: genuine failure — the invalid guild id fails the worker's
        // snowflake re-validation before anything can leave the process.
        let mut sticker_job = DiscordImportJob::new_stickers(&parent);
        sticker_job.status = ImportStatus::Running;
        sticker_job.source_guild_id = Some("not-a-snowflake".to_string());
        db.insert_discord_import_job(&sticker_job).await.unwrap();

        // Sticker import switched on for the per-kind gate, so what fails
        // the job is the worker's own validation, as before that gate.
        let config = config_with(true, true, false).await;
        run_job(&db, sticker_job.clone(), &config).await;

        let stored = db.fetch_discord_import_job(&sticker_job.id).await.unwrap();
        assert_eq!(
            stored.status,
            ImportStatus::Failed,
            "an unusable guild id must fail the job cleanly"
        );
        assert!(stored.error.is_some());

        db.fetch_server(&server.id)
            .await
            .expect("a failed sticker job must never roll the live server back");
        db.fetch_sticker(&existing_sticker.id)
            .await
            .expect("previously imported stickers must survive a failed retry");
        assert_eq!(
            stored.server_id.as_deref(),
            Some(server.id.as_str()),
            "the job must keep pointing at the server it was for"
        );

        // Leg 2: stale snapshot of an already-finalized job. Another actor
        // (a second crond's sweeper, in real life) completed it; running the
        // old Running snapshot must neither clobber the terminal state nor
        // touch anything.
        let mut second = DiscordImportJob::new_stickers(&parent);
        second.status = ImportStatus::Running;
        // Also non-numeric: whichever path the worker takes with the stale
        // snapshot (fail or Superseded), it must stay off the network and
        // the assertions below hold either way.
        second.source_guild_id = Some("not-a-snowflake".to_string());
        db.insert_discord_import_job(&second).await.unwrap();

        let stale_snapshot = second.clone();
        second.status = ImportStatus::Completed;
        second.stage = ImportStage::Done;
        assert!(db.save_discord_import_job_if_active(&second).await.unwrap());

        run_job(&db, stale_snapshot, &config).await;

        let stored = db.fetch_discord_import_job(&second.id).await.unwrap();
        assert_eq!(
            stored.status,
            ImportStatus::Completed,
            "a stale worker must not write Failed over a finalized sticker job"
        );
        db.fetch_server(&server.id)
            .await
            .expect("the stale-snapshot path must not roll the server back either");
        db.fetch_sticker(&existing_sticker.id)
            .await
            .expect("nor may it touch existing stickers");
    }

    /// A text channel and a voice channel, with the voice channel designated
    /// as the guild's AFK channel on a 15-minute timeout.
    const AFK_FIXTURE: &str = r#"{
        "code": "afk",
        "name": "AFK Template",
        "serialized_source_guild": {
            "name": "AFK Guild",
            "afk_channel_id": 2,
            "afk_timeout": 900,
            "roles": [{"id": 0, "name": "@everyone", "permissions": "3148800"}],
            "channels": [
                {"id": 1, "type": 0, "name": "general", "position": 0},
                {"id": 2, "type": 2, "name": "AFK", "position": 1}
            ]
        }
    }"#;

    /// The designation has to reach the stored server document, and the only
    /// path there is step 5's `PartialServer`. Runs the real `build_server`
    /// (every step, including `Member::create` and the invite) on the
    /// Reference driver and reads the server back.
    #[tokio::test]
    async fn import_designates_the_afk_channel_on_the_stored_server() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;

        let template: GuildTemplate = serde_json::from_str(AFK_FIXTURE).unwrap();
        let plan = plan_import(&template).unwrap();
        assert!(
            plan.afk_channel.is_some(),
            "fixture must plan a designation"
        );

        let (server, _) = Server::create(
            &db,
            v0::DataCreateServer {
                name: plan.server_name.clone(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .unwrap();
        let server_id = server.id.clone();

        let mut job = DiscordImportJob::new(owner.id.clone(), "afk".to_string());
        db.insert_discord_import_job(&job).await.unwrap();

        let total = plan.total_steps().max(1);
        if build_server(
            &db,
            &mut job,
            &owner,
            server,
            &plan,
            total,
            &NoAssets,
            &StoredChannels,
        )
        .await
        .is_err()
        {
            panic!("build_server aborted");
        }

        let stored = db.fetch_server(&server_id).await.unwrap();

        // Find the channel the AFK placeholder became, by what it IS rather
        // than by trusting the pointer under test.
        let mut voice_id = None;
        for id in &stored.channels {
            let channel = db.fetch_channel(id).await.unwrap();
            if let Channel::TextChannel { name, .. } = &channel {
                if name == "AFK" && channel.voice().is_some() {
                    voice_id = Some(id.clone());
                }
            }
        }
        let voice_id = voice_id.expect("the AFK voice channel should have been created");

        assert_eq!(
            stored.afk_channel_id.as_deref(),
            Some(voice_id.as_str()),
            "step 5 must write the imported AFK channel onto the server"
        );
        assert_eq!(stored.afk_timeout, Some(900));
    }

    /// The mapper cannot know whether its AFK channel was actually created. If
    /// it was not (the channel cap, a failed insert), neither the pointer nor
    /// a now-orphaned timeout may be written.
    #[test]
    fn afk_designation_needs_the_channel_to_have_been_created() {
        let template: GuildTemplate = serde_json::from_str(AFK_FIXTURE).unwrap();
        let plan = plan_import(&template).unwrap();
        assert_eq!(plan.afk_timeout, Some(900));

        assert_eq!(afk_designation(&plan, &[]), (None, None));
    }

    /// `create_server_channel` never reads `afk`; only delta's channel_create
    /// route does. So flipping this literal to `Some(true)` would compile, pass
    /// every behavioral test, and designate nothing, while the exhaustive
    /// literal (no `..Default::default()`) is the tripwire for new fields.
    #[test]
    fn channel_create_dto_keeps_its_explicit_afk_none() {
        let source = include_str!("worker.rs");
        let production = &source[..source.find("#[cfg(test)]").expect("test module")];
        let start = production
            .find("Channel::create_server_channel(")
            .expect("create_channels must call create_server_channel");
        let dto = &production[start..];
        let dto = &dto[..dto.find(".await").expect("the call is awaited")];
        // Code only: the comment beside the literal names
        // `..Default::default()` in prose.
        let dto = dto
            .lines()
            .map(|line| line.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            dto.contains("afk: None,"),
            "the `afk: None` literal is gone"
        );
        assert!(
            dto.contains("afk_timeout: None,"),
            "the `afk_timeout: None` literal is gone"
        );
        assert!(
            !dto.contains("..Default::default()"),
            "the channel-create DTO must stay an exhaustive literal"
        );
    }

    // ----------------------------------------------------------------------
    // Shared framework for imports from other platforms
    // ----------------------------------------------------------------------

    use super::super::assets::tests::PNG_1X1;
    use super::super::mapper::PlannedEmoji;
    use revolt_database::{FileHash, FileUsedFor, FileUsedForType, Metadata};
    use std::sync::Mutex;

    /// The real config with every import gate set explicitly, so no test
    /// depends on what this box's config happens to switch on.
    async fn config_with(discord: bool, stickers: bool, sources: bool) -> Settings {
        let mut config = config().await;
        let import = &mut config.api.import;
        import.discord.enabled = discord;
        import.discord.client_id = if stickers {
            "1".to_string()
        } else {
            String::new()
        };
        import.discord.bot_token = if stickers {
            "token".to_string()
        } else {
            String::new()
        };
        import.challenge_secret = if sources {
            "secret".to_string()
        } else {
            String::new()
        };
        for source in [&mut import.stoat, &mut import.fluxer] {
            source.enabled = sources;
            source.api_url = "https://api.example".to_string();
            source.cdn_url = "https://cdn.example".to_string();
            source.bot_id = "bot".to_string();
            source.bot_token = "token".to_string();
        }
        import.matrix.enabled = sources;
        import.matrix.homeserver_url = "https://matrix.example".to_string();
        import.matrix.bot_user_id = "@bot:matrix.example".to_string();
        import.matrix.access_token = "token".to_string();
        config
    }

    fn source_job(user_id: &str, kind: ImportJobKind, source: &str) -> DiscordImportJob {
        DiscordImportJob::new_source(
            user_id.to_string(),
            kind,
            source.to_string(),
            Some(source.to_string()),
            Some("sloga-import-AAAAAAAA".to_string()),
        )
    }

    /// Ids of the jobs the test leave hooks were called for. Tests check
    /// only their own (fresh ULID) ids, so running in parallel is fine.
    static LEAVE_CALLS: Mutex<Vec<String>> = Mutex::new(Vec::new());

    fn leave_called(job_id: &str) -> bool {
        LEAVE_CALLS.lock().unwrap().iter().any(|id| id == job_id)
    }

    fn leaves<'a>(
        _db: &'a Database,
        job: &'a mut DiscordImportJob,
        _config: &'a Settings,
    ) -> BoxFuture<'a, bool> {
        LEAVE_CALLS.lock().unwrap().push(job.id.clone());
        Box::pin(async { true })
    }

    fn stays<'a>(
        _db: &'a Database,
        job: &'a mut DiscordImportJob,
        _config: &'a Settings,
    ) -> BoxFuture<'a, bool> {
        LEAVE_CALLS.lock().unwrap().push(job.id.clone());
        Box::pin(async { false })
    }

    #[tokio::test]
    async fn each_kind_runs_only_when_its_own_source_is_ready() {
        let discord_only = config_with(true, false, false).await;
        assert!(kind_source_ready(&ImportJobKind::Template, &discord_only));
        assert!(!kind_source_ready(&ImportJobKind::Stickers, &discord_only));
        for kind in ImportJobKind::SOURCE_KINDS {
            assert!(!kind_source_ready(&kind, &discord_only), "{kind:?}");
        }

        let sources_only = config_with(false, false, true).await;
        assert!(sources_only.api.import.any_enabled());
        assert!(!kind_source_ready(&ImportJobKind::Template, &sources_only));
        assert!(!kind_source_ready(&ImportJobKind::Stickers, &sources_only));
        for kind in ImportJobKind::SOURCE_KINDS {
            assert!(kind_source_ready(&kind, &sources_only), "{kind:?}");
        }

        let everything = config_with(true, true, true).await;
        assert!(kind_source_ready(&ImportJobKind::Template, &everything));
        assert!(kind_source_ready(&ImportJobKind::Stickers, &everything));

        // Sticker keys without Discord itself switched on: off, as the delta
        // route's `stickers_enabled()` says.
        let keys_only = config_with(false, true, false).await;
        assert!(!kind_source_ready(&ImportJobKind::Stickers, &keys_only));
    }

    /// **The Discord kill switch, with another source switched on.**
    ///
    /// Before other sources, switching Discord off stopped the claim loop
    /// entirely. It now runs while any source is on, so the per-kind gate is
    /// what keeps a Discord job from running: the job is failed before
    /// anything is fetched or built (its stage never moves past the one it
    /// was born at), rather than left queued. Remove the gate in `run_job`
    /// and the template job runs (fetching from Discord) and this fails.
    #[tokio::test]
    async fn discord_kill_switch_still_stops_discord_jobs_when_another_source_is_on() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;
        let config = config_with(false, false, true).await;
        assert!(config.api.import.any_enabled(), "the claim loop is running");

        let job = DiscordImportJob::new(owner.id.clone(), "killswitch".to_string());
        db.insert_discord_import_job(&job).await.unwrap();
        let claimed = db
            .claim_next_queued_discord_import_job()
            .await
            .unwrap()
            .expect("the queued template job is claimable");
        assert_eq!(claimed.id, job.id);
        run_job(&db, claimed, &config).await;

        let stored = db.fetch_discord_import_job(&job.id).await.unwrap();
        assert_eq!(stored.status, ImportStatus::Failed);
        assert_eq!(
            stored.error.as_deref(),
            Some("Importing from Discord is not available on this instance.")
        );
        assert_eq!(stored.stage, ImportStage::Fetching, "nothing ran");
        assert_eq!(stored.server_id, None);
        assert_eq!(stored.source_guild_id, None);

        // A sticker job under the same switch fails with the sticker
        // worker's own wording, at its birth stage.
        let mut parent = DiscordImportJob::new(owner.id.clone(), "tmpl".to_string());
        parent.status = ImportStatus::Completed;
        parent.stage = ImportStage::Done;
        parent.server_id = Some("01SERVER000000000000000001".to_string());
        parent.source_guild_id = Some("1530784817975660565".to_string());
        db.insert_discord_import_job(&parent).await.unwrap();
        let stickers = DiscordImportJob::new_stickers(&parent);
        db.insert_discord_import_job(&stickers).await.unwrap();
        let claimed = db
            .claim_next_queued_discord_import_job()
            .await
            .unwrap()
            .expect("the queued sticker job is claimable");
        run_job(&db, claimed, &config).await;

        let stored = db.fetch_discord_import_job(&stickers.id).await.unwrap();
        assert_eq!(stored.status, ImportStatus::Failed);
        assert_eq!(
            stored.error.as_deref(),
            Some("Sticker import is not enabled on this instance.")
        );
        assert_eq!(stored.stage, ImportStage::Stickers);
    }

    /// A source kind with no importer on this build must not sit in the
    /// queue (holding its owner's one active job) forever: it is claimed and
    /// failed, whether or not its source is configured.
    ///
    /// Stoat has an importer (and is covered by the `stoat_` tests below);
    /// run here with its source configured it would contact the configured
    /// API, so it is left out.
    #[tokio::test]
    async fn source_kinds_without_an_importer_fail_closed_instead_of_sitting_queued() {
        for sources_ready in [true, false] {
            let config = config_with(true, true, sources_ready).await;
            for kind in ImportJobKind::SOURCE_KINDS
                .into_iter()
                .filter(|kind| !matches!(kind, ImportJobKind::StoatServer))
            {
                let db = DatabaseInfo::Reference.connect().await.unwrap();
                let owner = make_owner(&db).await;
                let job = source_job(&owner.id, kind.clone(), "01SOURCE000000000000000001");
                db.insert_discord_import_job(&job).await.unwrap();

                let claimed = db
                    .claim_next_queued_discord_import_job()
                    .await
                    .unwrap()
                    .expect("a source job is claimable");
                run_job(&db, claimed, &config).await;

                let stored = db.fetch_discord_import_job(&job.id).await.unwrap();
                assert_eq!(stored.status, ImportStatus::Failed, "{kind:?}");
                assert_eq!(
                    stored.error,
                    Some(source_unavailable_message(&kind)),
                    "{kind:?}"
                );
                assert_eq!(stored.stage, ImportStage::Verifying, "{kind:?}");
                assert_eq!(stored.server_id, None, "{kind:?}");
                // No source can leave yet, so the leave retry keeps it.
                assert!(!stored.source_left, "{kind:?}");
            }
        }

        assert_eq!(
            source_unavailable_message(&ImportJobKind::StoatServer),
            "Importing from Stoat is not available on this instance."
        );
    }

    /// The bot must not leave a source while another job still needs it,
    /// and must leave once none does. Both jobs' terminal states are read
    /// from the database, which is why `on_terminal` runs only after the
    /// terminal write.
    #[tokio::test]
    async fn the_bot_stays_while_another_job_uses_the_source() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let config = config_with(false, false, true).await;
        let source = "01SHARED000000000000000001";

        let mut finished = source_job(
            "01USERA0000000000000000001",
            ImportJobKind::StoatServer,
            source,
        );
        finished.status = ImportStatus::Completed;
        db.insert_discord_import_job(&finished).await.unwrap();

        let mut running = source_job(
            "01USERB0000000000000000001",
            ImportJobKind::StoatServer,
            source,
        );
        running.status = ImportStatus::Running;
        db.insert_discord_import_job(&running).await.unwrap();

        on_terminal_with(&db, &mut finished, &config, &leaves).await;
        assert!(!leave_called(&finished.id), "the bot must not leave yet");
        assert!(!finished.source_left);
        assert!(
            !db.fetch_discord_import_job(&finished.id)
                .await
                .unwrap()
                .source_left
        );

        // The other job finishes; now nothing holds the source.
        running.status = ImportStatus::Failed;
        assert!(db
            .save_discord_import_job_if_active(&running)
            .await
            .unwrap());

        on_terminal_with(&db, &mut finished, &config, &leaves).await;
        assert!(leave_called(&finished.id));
        assert!(finished.source_left);
        assert!(
            db.fetch_discord_import_job(&finished.id)
                .await
                .unwrap()
                .source_left
        );

        // Template jobs have no source: the hook is never consulted.
        let mut template =
            DiscordImportJob::new("01USERC0000000000000000001".to_string(), "t".to_string());
        template.status = ImportStatus::Completed;
        db.insert_discord_import_job(&template).await.unwrap();
        on_terminal_with(&db, &mut template, &config, &leaves).await;
        assert!(!leave_called(&template.id));
    }

    /// The sweeper's leave retry: a failed leave stays queued for the next
    /// sweep, a successful one is recorded, and a job past the age cap is
    /// marked left without another attempt (and logged loudly) so it stops
    /// occupying the oldest-first batch.
    #[tokio::test]
    async fn leave_retry_marks_left_on_success_and_gives_up_after_the_cap() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let config = config_with(false, false, true).await;

        let mut recent = source_job(
            "01USERA0000000000000000002",
            ImportJobKind::StoatServer,
            "01SRCA",
        );
        recent.status = ImportStatus::Failed;
        db.insert_discord_import_job(&recent).await.unwrap();

        let mut stale = source_job(
            "01USERB0000000000000000002",
            ImportJobKind::FluxerServer,
            "01SRCB",
        );
        stale.status = ImportStatus::Completed;
        stale.updated_at = Timestamp::now_utc()
            .checked_sub(iso8601_timestamp::Duration::hours(
                LEAVE_RETRY_DAYS * 24 + 1,
            ))
            .unwrap();
        db.insert_discord_import_job(&stale).await.unwrap();

        // A leave that fails: the recent job stays queued; the stale one is
        // given up on without another attempt.
        retry_source_leaves_with(&db, &config, &stays).await;
        assert!(leave_called(&recent.id));
        assert!(
            !db.fetch_discord_import_job(&recent.id)
                .await
                .unwrap()
                .source_left
        );
        assert!(!leave_called(&stale.id), "past the cap: no further attempt");
        assert!(
            db.fetch_discord_import_job(&stale.id)
                .await
                .unwrap()
                .source_left
        );

        // The next sweep's leave succeeds.
        retry_source_leaves_with(&db, &config, &leaves).await;
        assert!(
            db.fetch_discord_import_job(&recent.id)
                .await
                .unwrap()
                .source_left
        );
    }

    fn emoji_file(id: &str, emoji_id: &str) -> File {
        File {
            id: id.to_string(),
            tag: "emojis".to_string(),
            filename: "emoji.png".to_string(),
            hash: None,
            uploaded_at: None,
            uploader_id: None,
            used_for: Some(FileUsedFor {
                object_type: FileUsedForType::Emoji,
                id: emoji_id.to_string(),
            }),
            deleted: None,
            reported: None,
            metadata: Metadata::File,
            content_type: "image/png".to_string(),
            size: 1,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        }
    }

    async fn deleted_file_ids(db: &Database) -> Vec<String> {
        db.fetch_deleted_attachments()
            .await
            .unwrap()
            .into_iter()
            .map(|file| file.id)
            .collect()
    }

    /// Rollback removes the emoji the import created, files included. On
    /// the Reference driver server deletion touches no emoji at all, so
    /// without the emoji step both files would survive.
    #[allow(clippy::disallowed_methods)]
    #[tokio::test]
    async fn rollback_deletes_the_imported_emoji_files() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;
        let (server, _) = Server::create(
            &db,
            v0::DataCreateServer {
                name: "Imported".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .unwrap();

        let mut emoji_ids = vec![];
        for (emoji_id, file_id) in [
            ("01EMOJIA000000000000000003", "01FILEA0000000000000000003"),
            ("01EMOJIB000000000000000003", "01FILEB0000000000000000003"),
        ] {
            db.insert_attachment(&emoji_file(file_id, emoji_id))
                .await
                .unwrap();
            Emoji {
                id: emoji_id.to_string(),
                parent: EmojiParent::Server {
                    id: server.id.clone(),
                },
                creator_id: owner.id.clone(),
                name: "e".to_string(),
                animated: false,
                nsfw: false,
            }
            .create(&db)
            .await
            .unwrap();
            emoji_ids.push(emoji_id);
        }

        // Another server's emoji must be untouched.
        db.insert_attachment(&emoji_file(
            "01FILEC0000000000000000003",
            "01EMOJIC000000000000000003",
        ))
        .await
        .unwrap();
        Emoji {
            id: "01EMOJIC000000000000000003".to_string(),
            parent: EmojiParent::Server {
                id: "01OTHERSERVER0000000000003".to_string(),
            },
            creator_id: owner.id.clone(),
            name: "e".to_string(),
            animated: false,
            nsfw: false,
        }
        .create(&db)
        .await
        .unwrap();

        rollback_server(&db, &server.id).await;

        assert!(db.fetch_server(&server.id).await.is_err());
        let deleted = deleted_file_ids(&db).await;
        assert!(deleted.contains(&"01FILEA0000000000000000003".to_string()));
        assert!(deleted.contains(&"01FILEB0000000000000000003".to_string()));
        assert!(!deleted.contains(&"01FILEC0000000000000000003".to_string()));
        for emoji_id in emoji_ids {
            assert_eq!(
                db.fetch_emoji(emoji_id).await.unwrap().parent,
                EmojiParent::Detached
            );
        }
        assert!(matches!(
            db.fetch_emoji("01EMOJIC000000000000000003")
                .await
                .unwrap()
                .parent,
            EmojiParent::Server { .. }
        ));
    }

    /// Hands back a 1x1 PNG for every asset except id `missing`, recording
    /// whether the job's owner was already a member when each fetch ran.
    /// With `supersede_on_emoji`, another actor finalizes the job while the
    /// emoji is being fetched (a sweeper on another crond, in real life).
    struct TestFetcher {
        db: Database,
        job_id: String,
        supersede_on_emoji: bool,
        member_at_fetch: Mutex<Vec<bool>>,
    }

    impl AssetFetcher for TestFetcher {
        fn fetch<'a>(&'a self, asset: &'a PlannedAsset) -> BoxFuture<'a, Option<Vec<u8>>> {
            Box::pin(async move {
                let job = self
                    .db
                    .fetch_discord_import_job(&self.job_id)
                    .await
                    .unwrap();
                let server_id = job.server_id.clone().expect("the server exists by now");
                let member = self.db.fetch_member(&server_id, &job.user_id).await.is_ok();
                self.member_at_fetch.lock().unwrap().push(member);

                if self.supersede_on_emoji && asset.kind == AssetKind::Emoji {
                    let mut reaped = job;
                    reaped.status = ImportStatus::Failed;
                    assert!(self
                        .db
                        .save_discord_import_job_if_active(&reaped)
                        .await
                        .unwrap());
                }

                (asset.id != "missing").then(|| PNG_1X1.to_vec())
            })
        }
    }

    /// The stored object for `PNG_1X1` already exists, so `store_file`
    /// reuses it (content addressing) and no object store is needed.
    async fn seed_png_hash(db: &Database) {
        use sha2::Digest;
        let hash = format!("{:02x}", sha2::Sha256::digest(PNG_1X1));
        db.insert_attachment_hash(&FileHash {
            id: hash.clone(),
            processed_hash: hash.clone(),
            created_at: Timestamp::now_utc(),
            bucket_id: "revolt-uploads".to_string(),
            path: format!("rk/k1/{hash}"),
            iv: "iv".to_string(),
            format_version: None,
            key_id: Some("k1".to_string()),
            metadata: Metadata::Image {
                width: 1,
                height: 1,
                thumbhash: None,
                animated: None,
            },
            content_type: "image/png".to_string(),
            size: PNG_1X1.len() as isize,
        })
        .await
        .unwrap();
    }

    fn plan_with_assets() -> ImportPlan {
        let template: GuildTemplate = serde_json::from_str(FIXTURE).unwrap();
        let mut plan = plan_import(&template).unwrap();
        plan.icon = Some(PlannedAsset {
            kind: AssetKind::Icon,
            id: "icon1".to_string(),
            animated: false,
        });
        plan.banner = Some(PlannedAsset {
            kind: AssetKind::Banner,
            id: "missing".to_string(),
            animated: false,
        });
        plan.emojis = vec![
            PlannedEmoji {
                name: "party".to_string(),
                asset: PlannedAsset {
                    kind: AssetKind::Emoji,
                    id: "e1".to_string(),
                    animated: false,
                },
            },
            PlannedEmoji {
                name: "not allowed!".to_string(),
                asset: PlannedAsset {
                    kind: AssetKind::Emoji,
                    id: "e2".to_string(),
                    animated: false,
                },
            },
        ];
        plan
    }

    /// Icon and emojis are stored and attached BEFORE the owner's membership
    /// exists (so the `ServerCreate` snapshot carries them), the icon lands
    /// on the server document, failed and refused assets become notes, and
    /// the import still completes.
    #[tokio::test]
    async fn execute_plan_attaches_assets_before_membership() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;
        seed_png_hash(&db).await;

        let mut job = source_job(&owner.id, ImportJobKind::StoatServer, "01SRCASSETS");
        job.status = ImportStatus::Running;
        db.insert_discord_import_job(&job).await.unwrap();

        let fetcher = TestFetcher {
            db: db.clone(),
            job_id: job.id.clone(),
            supersede_on_emoji: false,
            member_at_fetch: Mutex::new(vec![]),
        };

        if execute_plan(&db, &mut job, plan_with_assets(), &fetcher)
            .await
            .is_err()
        {
            panic!("execute_plan aborted");
        }

        // Icon, banner, and the one emoji with a valid name: three fetches,
        // all before membership.
        assert_eq!(*fetcher.member_at_fetch.lock().unwrap(), vec![false; 3]);

        let server_id = job.server_id.clone().expect("server built");
        db.fetch_member(&server_id, &owner.id)
            .await
            .expect("the owner joined afterwards");

        let server = db.fetch_server(&server_id).await.unwrap();
        let icon = server.icon.expect("the icon is on the server document");
        assert_eq!(icon.tag, "icons");
        assert_eq!(
            icon.used_for
                .as_ref()
                .map(|used| (&used.object_type, used.id.as_str())),
            Some((&FileUsedForType::ServerIcon, server_id.as_str()))
        );
        assert!(server.banner.is_none(), "the banner fetch failed");

        let emojis = db.fetch_emoji_by_parent_id(&server_id).await.unwrap();
        assert_eq!(emojis.len(), 1);
        assert_eq!(emojis[0].name, "party");
        assert_eq!(emojis[0].creator_id, owner.id);
        assert!(!emojis[0].animated);
        assert!(ulid::Ulid::from_string(&emojis[0].id).is_ok());

        let stored = db.fetch_discord_import_job(&job.id).await.unwrap();
        assert_eq!(stored.status, ImportStatus::Completed);
        let notes = stored.summary.expect("summary").notes;
        assert!(notes.contains(&"The server banner couldn't be imported.".to_string()));
        assert!(notes
            .iter()
            .any(|note| note.starts_with("1 emoji had names")));
    }

    /// A failure AFTER the Assets stage (here: the job reaped while the
    /// emoji was being fetched) rolls the server back, and the rollback
    /// takes the emoji it created, files included.
    #[tokio::test]
    async fn a_failure_after_assets_removes_the_imported_emoji() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;
        seed_png_hash(&db).await;

        let mut job = source_job(&owner.id, ImportJobKind::StoatServer, "01SRCROLLBACK");
        job.status = ImportStatus::Running;
        db.insert_discord_import_job(&job).await.unwrap();

        let fetcher = TestFetcher {
            db: db.clone(),
            job_id: job.id.clone(),
            supersede_on_emoji: true,
            member_at_fetch: Mutex::new(vec![]),
        };

        let mut plan = plan_with_assets();
        plan.emojis.truncate(1);
        let result = execute_plan(&db, &mut job, plan, &fetcher).await;
        assert!(matches!(result, Err(ImportAbort::Superseded)));

        // The emoji was created before the refused progress write noticed.
        let created: Vec<File> = db
            .fetch_deleted_attachments()
            .await
            .unwrap()
            .into_iter()
            .filter(|file| file.tag == "emojis")
            .collect();
        assert_eq!(created.len(), 1, "the emoji's file is marked deleted");
        let emoji_id = &created[0].used_for.as_ref().unwrap().id;
        assert_eq!(
            db.fetch_emoji(emoji_id).await.unwrap().parent,
            EmojiParent::Detached
        );

        let stored = db.fetch_discord_import_job(&job.id).await.unwrap();
        let server_id = stored.server_id.expect("the job recorded its server");
        assert!(db.fetch_server(&server_id).await.is_err(), "rolled back");
    }

    /// Fails the test if a Discord plan ever asks for an asset.
    struct NoFetchExpected;

    impl AssetFetcher for NoFetchExpected {
        fn fetch<'a>(&'a self, asset: &'a PlannedAsset) -> BoxFuture<'a, Option<Vec<u8>>> {
            panic!("a Discord template plan fetched an asset: {asset:?}")
        }
    }

    /// Two text channels; the guild's system channel is the SECOND, so the
    /// first-text-channel fallback cannot pass for it.
    const WELCOME_FIXTURE: &str = r#"{
        "code": "welcome",
        "name": "Welcome Template",
        "serialized_source_guild": {
            "name": "Welcome Guild",
            "system_channel_id": 2,
            "roles": [{"id": 0, "name": "@everyone", "permissions": "3148800"}],
            "channels": [
                {"id": 1, "type": 0, "name": "general", "position": 0},
                {"id": 2, "type": 0, "name": "welcome", "position": 1}
            ]
        }
    }"#;

    /// Discord behaviour preserved across the `system_channel` split: the
    /// welcome invite is minted in the guild's system channel, and all four
    /// system-message kinds go there.
    #[tokio::test]
    async fn welcome_invite_still_lands_in_the_discord_system_channel() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;

        let template: GuildTemplate = serde_json::from_str(WELCOME_FIXTURE).unwrap();
        let plan = plan_import(&template).unwrap();

        let mut job = DiscordImportJob::new(owner.id.clone(), "welcome".to_string());
        job.status = ImportStatus::Running;
        db.insert_discord_import_job(&job).await.unwrap();

        if execute_plan(&db, &mut job, plan, &NoFetchExpected)
            .await
            .is_err()
        {
            panic!("execute_plan aborted");
        }

        let server = db
            .fetch_server(job.server_id.as_deref().unwrap())
            .await
            .unwrap();
        let mut welcome_id = None;
        for id in &server.channels {
            if let Channel::TextChannel { name, .. } = db.fetch_channel(id).await.unwrap() {
                if name == "welcome" {
                    welcome_id = Some(id.clone());
                }
            }
        }
        let welcome_id = welcome_id.expect("the welcome channel was created");

        let invite = db
            .fetch_invite(job.invite_code.as_deref().expect("an invite was minted"))
            .await
            .unwrap();
        match invite {
            Invite::Server { channel, .. } => assert_eq!(
                channel, welcome_id,
                "the invite belongs in the guild's system channel"
            ),
            _ => panic!("expected a server invite"),
        }

        let system = server.system_messages.expect("system messages set");
        assert_eq!(system.user_joined.as_deref(), Some(welcome_id.as_str()));
        assert_eq!(system.user_left.as_deref(), Some(welcome_id.as_str()));
        assert_eq!(system.user_kicked.as_deref(), Some(welcome_id.as_str()));
        assert_eq!(system.user_banned.as_deref(), Some(welcome_id.as_str()));
        assert!(server.icon.is_none());

        assert_eq!(
            db.fetch_discord_import_job(&job.id).await.unwrap().status,
            ImportStatus::Completed
        );
    }

    /// A role's deny bits reach the stored role (Discord plans carry none;
    /// Stoat roles can).
    #[tokio::test]
    async fn role_deny_bits_are_written() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;

        let template: GuildTemplate = serde_json::from_str(FIXTURE).unwrap();
        let mut plan = plan_import(&template).unwrap();
        let denied = ChannelPermission::SendMessage as u64 | ChannelPermission::React as u64;
        plan.roles[0].deny = denied;

        let (mut server, _) = Server::create(
            &db,
            v0::DataCreateServer {
                name: plan.server_name.clone(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .unwrap();
        let mut job = DiscordImportJob::new(owner.id.clone(), "deny".to_string());
        db.insert_discord_import_job(&job).await.unwrap();

        let (roles, ..) = match create_roles(&db, &mut job, &mut server, &plan).await {
            Ok(result) => result,
            Err(_) => panic!("create_roles aborted"),
        };

        let role_id = roles.get(&plan.roles[0].template_id.0).unwrap();
        assert_eq!(server.roles[role_id].permissions.d, denied as i64);
        let stored = db.fetch_server(&server.id).await.unwrap();
        assert_eq!(stored.roles[role_id].permissions.d, denied as i64);

        // Everyone else keeps the Discord shape: no deny.
        let other_id = roles.get(&plan.roles[1].template_id.0).unwrap();
        assert_eq!(stored.roles[other_id].permissions.d, 0);
    }

    /// The leave retry runs with every import source switched off: the rows
    /// whose bot has not left are still retried and, past the cap, given up
    /// on loudly. Tick 1 is off the sweep cadence, so only the switched-off
    /// branch can have run it.
    #[tokio::test]
    async fn leave_retry_runs_while_every_source_is_switched_off() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let config = config_with(false, false, false).await;
        assert!(!config.api.import.any_enabled());

        let mut job = source_job(
            "01USERA0000000000000000009",
            ImportJobKind::StoatServer,
            "01SRCOFF",
        );
        job.status = ImportStatus::Failed;
        db.insert_discord_import_job(&job).await.unwrap();

        assert!(
            !housekeeping(&db, &config, 1, &leaves).await,
            "nothing is switched on: no claiming"
        );
        assert!(leave_called(&job.id), "the leave retry must still run");
        assert!(
            db.fetch_discord_import_job(&job.id)
                .await
                .unwrap()
                .source_left
        );
    }

    /// The stale-job sweep runs with every import source switched off too. A
    /// Stoat job orphaned while Running is only made terminal by it; without
    /// it the job would hold its owner's one active slot and keep the bot in
    /// the source forever. Tick 1 is off the sweep cadence, so only the
    /// switched-off branch can have run it.
    #[tokio::test]
    async fn stale_jobs_are_reaped_while_every_source_is_switched_off() {
        assert!(
            config().await.api.import.stoat.bot_token.is_empty(),
            "the sweep's own leave reads the ambient config; it must not reach a real Stoat"
        );

        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let config = config_with(false, false, false).await;
        assert!(!config.api.import.any_enabled());
        let owner = make_owner(&db).await;
        let (server, _) = Server::create(
            &db,
            v0::DataCreateServer {
                name: "Half built".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .unwrap();

        let mut job = source_job(&owner.id, ImportJobKind::StoatServer, "01SRCOFFSTALE");
        job.status = ImportStatus::Running;
        job.stage = ImportStage::Channels;
        job.server_id = Some(server.id.clone());
        job.updated_at = Timestamp::now_utc()
            .checked_sub(iso8601_timestamp::Duration::hours(1))
            .unwrap();
        db.insert_discord_import_job(&job).await.unwrap();

        assert!(!housekeeping(&db, &config, 1, &leaves).await);

        let stored = db.fetch_discord_import_job(&job.id).await.unwrap();
        assert_eq!(stored.status, ImportStatus::Failed, "the orphan is reaped");
        assert!(
            db.fetch_server(&server.id).await.is_err(),
            "its half-built server is rolled back"
        );
        // Terminal now, so the same tick's leave retry gets the bot out.
        assert!(leave_called(&job.id));
        assert!(stored.source_left);
    }

    /// Channel writes that fail on demand. `update` behaves like
    /// `Channel::update` on a failed write: the partial is applied in memory,
    /// then the write errors.
    struct FailingWrites {
        /// Channel name whose settings write fails.
        fail_update_for: &'static str,
        /// Whether removing that channel fails as well.
        fail_delete: bool,
        /// Ids of the channels `delete` was asked to remove.
        deleted: Mutex<Vec<String>>,
    }

    impl FailingWrites {
        fn new(fail_update_for: &'static str, fail_delete: bool) -> FailingWrites {
            FailingWrites {
                fail_update_for,
                fail_delete,
                deleted: Mutex::new(vec![]),
            }
        }
    }

    impl ChannelWrites for FailingWrites {
        fn update<'a>(
            &'a self,
            db: &'a Database,
            channel: &'a mut Channel,
            partial: PartialChannel,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                let failing = matches!(&*channel, Channel::TextChannel { name, .. } if name == self.fail_update_for);
                if failing {
                    channel.apply_options(partial);
                    Err(revolt_result::create_error!(InternalError))
                } else {
                    channel.update(db, partial, vec![]).await
                }
            })
        }

        fn delete<'a>(
            &'a self,
            db: &'a Database,
            channel: &'a Channel,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.deleted.lock().unwrap().push(channel.id().to_string());
                if self.fail_delete {
                    Err(revolt_result::create_error!(InternalError))
                } else {
                    channel.delete(db).await
                }
            })
        }
    }

    /// Created text channels of the stored server, by name.
    async fn stored_channels_by_name(db: &Database, server: &Server) -> HashMap<String, Channel> {
        let mut by_name = HashMap::new();
        for id in &server.channels {
            let channel = db.fetch_channel(id).await.unwrap();
            if let Channel::TextChannel { name, .. } = &channel {
                by_name.insert(name.clone(), channel.clone());
            }
        }
        by_name
    }

    /// Run a plan as a Discord template job would, with `writes`.
    async fn run_plan_with(
        db: &Database,
        plan: ImportPlan,
        writes: &dyn ChannelWrites,
    ) -> (DiscordImportJob, std::result::Result<(), ImportAbort>) {
        let owner = make_owner(db).await;
        let mut job = DiscordImportJob::new(owner.id.clone(), "writes".to_string());
        job.status = ImportStatus::Running;
        db.insert_discord_import_job(&job).await.unwrap();
        let result = execute_plan_with(db, &mut job, plan, &NoFetchExpected, writes).await;
        (job, result)
    }

    #[test]
    fn a_failed_permission_write_removes_the_channel_only_if_a_deny_is_lost() {
        let template: GuildTemplate = serde_json::from_str(FIXTURE).unwrap();
        let plan = plan_import(&template).unwrap();
        let named = |wanted: &str| {
            plan.channels
                .iter()
                .find(|channel| channel.name == wanted)
                .unwrap()
                .clone()
        };

        // `@everyone` denied ViewChannel: private.
        assert!(must_remove_without_overrides(&named("mod-chat")));
        // No overrides at all.
        assert!(!must_remove_without_overrides(&named("general")));

        let mut allow_only = named("general");
        allow_only.role_overrides = vec![(
            PlaceholderId("2".to_string()),
            PlannedOverride {
                allow: ChannelPermission::ViewChannel as u64,
                deny: 0,
            },
        )];
        allow_only.default_permissions = Some(PlannedOverride {
            allow: ChannelPermission::SendMessage as u64,
            deny: 0,
        });
        assert!(!must_remove_without_overrides(&allow_only));

        // A deny on a role (a muted role), not on `@everyone`, also counts.
        let mut role_deny = allow_only.clone();
        role_deny.role_overrides[0].1.deny = ChannelPermission::SendMessage as u64;
        assert!(must_remove_without_overrides(&role_deny));
    }

    /// **A private channel is never imported public.** Its permission write
    /// fails, so without its `@everyone` deny it would be open to everyone:
    /// it is removed again, and with it every pointer to it (its category,
    /// the system-message slots, the invite), with a note.
    #[tokio::test]
    async fn a_private_channel_whose_permissions_fail_is_removed_not_imported_public() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let template: GuildTemplate = serde_json::from_str(FIXTURE).unwrap();
        let mut plan = plan_import(&template).unwrap();
        // Point the system messages and the invite at the private channel.
        let private = PlaceholderId("11".to_string());
        plan.system_messages.user_joined = Some(private.clone());
        plan.system_messages.user_left = Some(private.clone());
        plan.invite_channel = Some(private);

        let writes = FailingWrites::new("mod-chat", false);
        let (job, result) = run_plan_with(&db, plan, &writes).await;
        assert!(result.is_ok(), "the import still completes");

        let server = db
            .fetch_server(job.server_id.as_deref().unwrap())
            .await
            .unwrap();
        let by_name = stored_channels_by_name(&db, &server).await;
        assert_eq!(
            by_name.keys().collect::<Vec<_>>(),
            vec!["general"],
            "the private channel is not on the server"
        );
        let deleted = writes.deleted.lock().unwrap().clone();
        assert_eq!(deleted.len(), 1);
        assert!(db.fetch_channel(&deleted[0]).await.is_err(), "and is gone");

        // Its category had nothing else in it; the slots and the invite
        // that named it resolve to nothing / fall back.
        assert!(server.categories.unwrap_or_default().is_empty());
        assert!(server.system_messages.is_none());
        match db
            .fetch_invite(job.invite_code.as_deref().expect("an invite was minted"))
            .await
            .unwrap()
        {
            Invite::Server { channel, .. } => assert_eq!(channel, by_name["general"].id()),
            _ => panic!("expected a server invite"),
        }

        let summary = job.summary.expect("summary");
        assert_eq!(summary.channels_created, 1);
        assert_eq!(summary.channels_skipped, 1);
        assert!(
            summary.notes.contains(
                &"1 channel(s) weren't imported because their permissions couldn't be applied — \
                  without them, more people could have seen or used them than on the original \
                  server."
                    .to_string()
            ),
            "{:?}",
            summary.notes
        );
    }

    /// The removal failing as well: the import is abandoned and the server
    /// rolled back, never handed over with the channel open.
    #[tokio::test]
    async fn a_private_channel_that_cannot_be_removed_either_aborts_the_import() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let template: GuildTemplate = serde_json::from_str(FIXTURE).unwrap();
        let plan = plan_import(&template).unwrap();

        let writes = FailingWrites::new("mod-chat", true);
        let (job, result) = run_plan_with(&db, plan, &writes).await;
        match result {
            Err(ImportAbort::Failed(message)) => assert_eq!(message, generic_failure()),
            Err(ImportAbort::Superseded) => panic!("expected a failure, got superseded"),
            Ok(()) => panic!("the import must not complete"),
        }
        assert_eq!(writes.deleted.lock().unwrap().len(), 1);
        assert_eq!(job.server_id, None);
        assert!(job.invite_code.is_none());
        let stored = db.fetch_discord_import_job(&job.id).await.unwrap();
        let server_id = stored.server_id.expect("the job recorded its server");
        assert!(db.fetch_server(&server_id).await.is_err(), "rolled back");
    }

    /// Only allows lost: the channel stays (it is, if anything, more closed
    /// than on the source), with a source-neutral note, and the struct
    /// `ServerCreate` ships says what is stored, not what failed to write.
    #[tokio::test]
    async fn a_channel_that_only_loses_allows_is_kept_as_stored() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let template: GuildTemplate = serde_json::from_str(FIXTURE).unwrap();
        let mut plan = plan_import(&template).unwrap();
        let general = plan
            .channels
            .iter_mut()
            .find(|channel| channel.name == "general")
            .unwrap();
        general.role_overrides = vec![(
            PlaceholderId("2".to_string()),
            PlannedOverride {
                allow: ChannelPermission::ManageMessages as u64,
                deny: 0,
            },
        )];

        let writes = FailingWrites::new("general", false);
        let (job, result) = run_plan_with(&db, plan, &writes).await;
        assert!(result.is_ok());
        assert!(writes.deleted.lock().unwrap().is_empty());

        let server = db
            .fetch_server(job.server_id.as_deref().unwrap())
            .await
            .unwrap();
        let by_name = stored_channels_by_name(&db, &server).await;
        assert_eq!(by_name.len(), 2);
        match &by_name["general"] {
            Channel::TextChannel {
                role_permissions, ..
            } => assert!(role_permissions.is_empty()),
            _ => panic!("expected a text channel"),
        }

        let summary = job.summary.expect("summary");
        assert_eq!(summary.channels_created, 2);
        assert!(
            summary.notes.contains(
                &"1 channel(s) were created but their permissions or slowmode couldn't be \
                  applied — check them in channel settings."
                    .to_string()
            ),
            "{:?}",
            summary.notes
        );
        assert!(!summary
            .notes
            .iter()
            .any(|note| note.contains("Discord permissions")));
    }

    /// The restore itself, on the exact struct `create_channels` returns
    /// (the one `Member::create` snapshots into `ServerCreate`).
    #[tokio::test]
    async fn a_failed_settings_write_leaves_the_struct_as_stored() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;
        let template: GuildTemplate = serde_json::from_str(FIXTURE).unwrap();
        let mut plan = plan_import(&template).unwrap();
        for channel in &mut plan.channels {
            if channel.name == "general" {
                channel.kind = PlannedChannelKind::Text {
                    slowmode: Some(10),
                    announcement: false,
                };
            }
        }
        let (mut server, _) = Server::create(
            &db,
            v0::DataCreateServer {
                name: plan.server_name.clone(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .unwrap();
        let mut job = DiscordImportJob::new(owner.id.clone(), "restore".to_string());
        db.insert_discord_import_job(&job).await.unwrap();

        let writes = FailingWrites::new("general", false);
        let total = plan.total_steps().max(1);
        let (channels, _) = match create_channels(
            &db,
            &mut server,
            &plan,
            &mut job,
            total,
            &RoleMap::new(),
            &writes,
        )
        .await
        {
            Ok(result) => result,
            Err(_) => panic!("create_channels aborted"),
        };
        let general = channels
            .iter()
            .map(|(_, channel)| channel)
            .find(
                |channel| matches!(channel, Channel::TextChannel { name, .. } if name == "general"),
            )
            .expect("kept");
        assert_eq!(
            general,
            &db.fetch_channel(general.id()).await.unwrap(),
            "the returned struct must match the stored channel"
        );
        match general {
            Channel::TextChannel { slowmode, .. } => assert_eq!(*slowmode, None),
            _ => panic!("expected a text channel"),
        }
    }

    /// A Discord guild whose system channel and first text channel are both
    /// private: the invite goes to the first channel `@everyone` can view.
    /// System messages still go to the system channel (members who can see
    /// it see them). With nothing public at all there is no invite, a note
    /// says so, and the import still completes.
    #[tokio::test]
    async fn the_discord_invite_skips_channels_everyone_cannot_view() {
        let guild = |with_public: bool| {
            let public = if with_public {
                r#",{"id": 3, "type": 0, "name": "general", "position": 2}"#
            } else {
                ""
            };
            format!(
                r#"{{
                "code": "private",
                "name": "Private Template",
                "serialized_source_guild": {{
                    "name": "Private Guild",
                    "system_channel_id": 2,
                    "roles": [{{"id": 0, "name": "@everyone", "permissions": "3148800"}}],
                    "channels": [
                        {{"id": 1, "type": 0, "name": "staff", "position": 0,
                         "permission_overwrites": [{{"id": "0", "type": 0, "allow": "0", "deny": "1024"}}]}},
                        {{"id": 2, "type": 0, "name": "welcome", "position": 1,
                         "permission_overwrites": [{{"id": "0", "type": 0, "allow": "0", "deny": "1024"}}]}}
                        {public}
                    ]
                }}
            }}"#
            )
        };

        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let template: GuildTemplate = serde_json::from_str(&guild(true)).unwrap();
        let (job, result) =
            run_plan_with(&db, plan_import(&template).unwrap(), &StoredChannels).await;
        assert!(result.is_ok());
        let server = db
            .fetch_server(job.server_id.as_deref().unwrap())
            .await
            .unwrap();
        let by_name = stored_channels_by_name(&db, &server).await;
        match db
            .fetch_invite(job.invite_code.as_deref().expect("an invite was minted"))
            .await
            .unwrap()
        {
            Invite::Server { channel, .. } => assert_eq!(
                channel,
                by_name["general"].id(),
                "the invite goes to the public channel"
            ),
            _ => panic!("expected a server invite"),
        }
        assert_eq!(
            server.system_messages.unwrap().user_joined.as_deref(),
            Some(by_name["welcome"].id())
        );
        assert!(!job
            .summary
            .expect("summary")
            .notes
            .contains(&NO_INVITE_CHANNEL.to_string()));

        let template: GuildTemplate = serde_json::from_str(&guild(false)).unwrap();
        let (job, result) =
            run_plan_with(&db, plan_import(&template).unwrap(), &StoredChannels).await;
        assert!(result.is_ok());
        assert_eq!(job.invite_code, None, "no channel to invite into");
        let stored = db.fetch_discord_import_job(&job.id).await.unwrap();
        assert_eq!(stored.status, ImportStatus::Completed);
        assert_eq!(stored.invite_code, None);
        assert!(stored
            .summary
            .expect("summary")
            .notes
            .contains(&NO_INVITE_CHANNEL.to_string()));
    }

    // ----------------------------------------------------------------------
    // Stoat importer, through the claim loop's dispatch, against a fake
    // Stoat API and CDN on loopback
    // ----------------------------------------------------------------------

    use crate::tasks::stoat_import::source::fake_upstream::{FakeStoat, BOT_TOKEN};
    use crate::tasks::stoat_import::source::tests::SERVER as STOAT_SERVER;
    use crate::tasks::stoat_import::VERIFICATION_MISSING;

    const STOAT_CODE: &str = "sloga-import-ABCDEFGH";

    /// A Stoat server as `GET /servers/{id}?include_channels=true` returns
    /// it: the server's id list under `channels`, then the visible channel
    /// objects under `channels` again. `01CHANHID` is not visible to the bot.
    fn stoat_server_body(description: &str) -> String {
        let bit = |permission: ChannelPermission| permission as u64 as i64;
        let view = bit(ChannelPermission::ViewChannel);
        let admin_allow = bit(ChannelPermission::ManageServer) | view;
        let muted_deny = bit(ChannelPermission::SendMessage);
        // Bits 14 and 41 must not survive the trip.
        let default_permissions = view
            | bit(ChannelPermission::ReadMessageHistory)
            | bit(ChannelPermission::SendMessage)
            | bit(ChannelPermission::ViewAuditLog)
            | bit(ChannelPermission::UseRemoteControl);
        let server = serde_json::json!({
            "_id": STOAT_SERVER,
            "owner": "01OWNER0000000000000000000",
            "name": "Stoat Place",
            "description": description,
            "nsfw": true,
            "categories": [
                { "id": "c1", "title": "Text",
                  "channels": ["01CHANWEL", "01CHANGEN", "01CHANPRV", "01CHANGONE"] },
                { "id": "c2", "title": "Voice", "channels": ["01CHANVOI"] }
            ],
            "system_messages": { "user_joined": "01CHANWEL", "user_left": "01CHANGEN" },
            "roles": {
                "01ROLEADM": {
                    "name": "Admin",
                    "permissions": { "a": admin_allow, "d": 0 },
                    "colour": "linear-gradient(90deg, #ff0000 0%, #0000ff 100%)",
                    "hoist": true,
                    "rank": 0
                },
                "01ROLEMUT": {
                    "name": "Muted",
                    "permissions": { "a": 0, "d": muted_deny },
                    "rank": 1
                }
            },
            "default_permissions": default_permissions,
            "icon": { "_id": "01ICON", "tag": "icons", "filename": "icon.png",
                      "content_type": "image/png", "size": 67,
                      "metadata": { "type": "Image", "width": 1, "height": 1 } }
        });
        let ids = serde_json::json!([
            "01CHANGEN",
            "01CHANWEL",
            "01CHANVOI",
            "01CHANPRV",
            "01CHANHID"
        ]);
        let visible = serde_json::json!([
            { "channel_type": "TextChannel", "_id": "01CHANGEN", "server": STOAT_SERVER,
              "name": "general" },
            { "channel_type": "TextChannel", "_id": "01CHANWEL", "server": STOAT_SERVER,
              "name": "welcome" },
            { "channel_type": "TextChannel", "_id": "01CHANVOI", "server": STOAT_SERVER,
              "name": "Lounge", "voice": { "max_users": 0 } },
            { "channel_type": "TextChannel", "_id": "01CHANPRV", "server": STOAT_SERVER,
              "name": "staff",
              "default_permissions": { "a": 0, "d": view },
              "role_permissions": { "01ROLEADM": { "a": view, "d": 0 } } }
        ]);
        let head = server.to_string();
        format!(
            "{},\"channels\":{ids},\"channels\":{visible}}}",
            &head[..head.len() - 1]
        )
    }

    fn stoat_job(owner_id: &str) -> DiscordImportJob {
        DiscordImportJob::new_source(
            owner_id.to_string(),
            ImportJobKind::StoatServer,
            "https://stoat.chat/invite/AbC123".to_string(),
            Some(STOAT_SERVER.to_string()),
            Some(STOAT_CODE.to_string()),
        )
    }

    fn server_path() -> String {
        format!("/servers/{STOAT_SERVER}?include_channels=true")
    }

    fn leave_path() -> String {
        format!("/servers/{STOAT_SERVER}?leave_silently=true")
    }

    /// Claim the queued job and run it the way the claim loop does.
    async fn claim_and_run(db: &Database, job: &DiscordImportJob, config: &Settings) {
        db.insert_discord_import_job(job).await.unwrap();
        let claimed = db
            .claim_next_queued_discord_import_job()
            .await
            .unwrap()
            .expect("the queued Stoat job is claimable");
        assert_eq!(claimed.id, job.id);
        run_job(db, claimed, config).await;
    }

    #[tokio::test]
    async fn stoat_import_runs_end_to_end_and_the_bot_leaves() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;
        seed_png_hash(&db).await;

        let api = FakeStoat::new()
            .reply(
                "GET",
                &server_path(),
                200,
                stoat_server_body(&format!("Welcome! Verify: {STOAT_CODE}")),
            )
            .reply(
                "GET",
                &format!("/servers/{STOAT_SERVER}/emojis"),
                200,
                serde_json::json!([{
                    "_id": "01EMOJI", "parent": { "type": "Server", "id": STOAT_SERVER },
                    "creator_id": "01OWNER0000000000000000000", "name": "party"
                }])
                .to_string(),
            )
            .reply("DELETE", &leave_path(), 204, "")
            .start()
            .await;
        let cdn = FakeStoat::new()
            // Autumn's `original` is a relative redirect to the filename.
            .redirect("/icons/01ICON/original", "icon.png")
            .reply("GET", "/icons/01ICON/icon.png", 200, PNG_1X1)
            .reply("GET", "/emojis/01EMOJI/original", 200, PNG_1X1)
            .start()
            .await;
        let mut config = config_with(false, false, true).await;
        config.api.import.stoat = api.source_config(&cdn);

        let job = stoat_job(&owner.id);
        claim_and_run(&db, &job, &config).await;

        let stored = db.fetch_discord_import_job(&job.id).await.unwrap();
        assert_eq!(stored.status, ImportStatus::Completed, "{:?}", stored.error);
        assert!(stored.source_left, "the bot leaves once the job is done");

        // Exactly the three API calls the rate limit budget allows, all as
        // the bot; no CDN call carries the token.
        let calls: Vec<(String, String)> = api
            .seen()
            .into_iter()
            .map(|seen| {
                assert_eq!(seen.bot_token.as_deref(), Some(BOT_TOKEN));
                (seen.method, seen.path)
            })
            .collect();
        assert_eq!(
            calls,
            vec![
                ("GET".to_string(), server_path()),
                ("GET".to_string(), format!("/servers/{STOAT_SERVER}/emojis")),
                ("DELETE".to_string(), leave_path()),
            ]
        );
        assert!(cdn.seen().iter().all(|seen| seen.bot_token.is_none()));

        let server_id = stored.server_id.clone().expect("server built");
        db.fetch_member(&server_id, &owner.id)
            .await
            .expect("the owner is a member");
        let server = db.fetch_server(&server_id).await.unwrap();
        assert_eq!(server.name, "Stoat Place");
        assert_eq!(
            server.description.as_deref(),
            Some("Welcome! Verify:"),
            "the verification code must not be imported"
        );
        assert!(server.nsfw);
        assert_eq!(
            server.default_permissions as u64,
            ChannelPermission::ViewChannel as u64
                | ChannelPermission::ReadMessageHistory as u64
                | ChannelPermission::SendMessage as u64
                | ChannelPermission::UseSoundboard as u64
                | ChannelPermission::UseWatchTogether as u64
        );
        assert_eq!(server.icon.as_ref().expect("icon imported").tag, "icons");

        // Roles: rank order, gradient, derived audit log, deny bits.
        let ordered = server.ordered_roles();
        assert_eq!(
            ordered
                .iter()
                .map(|(_, role)| (role.name.as_str(), role.rank))
                .collect::<Vec<_>>(),
            vec![("Admin", 0), ("Muted", 1)]
        );
        let (admin_id, admin) = &ordered[0];
        assert_eq!(
            admin.colour.as_deref(),
            Some("linear-gradient(90deg, #ff0000 0%, #0000ff 100%)")
        );
        assert!(admin.hoist);
        assert_ne!(
            admin.permissions.a & ChannelPermission::ViewAuditLog as i64,
            0
        );
        assert_eq!(
            ordered[1].1.permissions.d,
            ChannelPermission::SendMessage as i64
        );

        // Channels by name.
        let mut by_name = HashMap::new();
        for id in &server.channels {
            let channel = db.fetch_channel(id).await.unwrap();
            if let Channel::TextChannel { name, .. } = &channel {
                by_name.insert(name.clone(), channel.clone());
            }
        }
        assert_eq!(by_name.len(), 4, "{:?}", by_name.keys());
        let id_of = |name: &str| by_name[name].id().to_string();

        let voice = by_name["Lounge"].voice().expect("a voice channel");
        assert_eq!(voice.max_users, None, "max_users 0 is unlimited");
        match &by_name["staff"] {
            Channel::TextChannel {
                default_permissions,
                role_permissions,
                ..
            } => {
                assert_eq!(
                    default_permissions.expect("private").d,
                    ChannelPermission::ViewChannel as i64
                );
                assert_eq!(
                    role_permissions[admin_id.as_str()].a,
                    ChannelPermission::ViewChannel as i64
                );
            }
            _ => panic!("expected a text channel"),
        }

        let categories = server.categories.expect("categories");
        assert_eq!(
            categories
                .iter()
                .map(|category| (category.title.as_str(), category.channels.clone()))
                .collect::<Vec<_>>(),
            vec![
                (
                    "Text",
                    vec![id_of("welcome"), id_of("general"), id_of("staff")]
                ),
                ("Voice", vec![id_of("Lounge")]),
            ]
        );

        let system = server.system_messages.expect("system messages");
        assert_eq!(system.user_joined, Some(id_of("welcome")));
        assert_eq!(system.user_left, Some(id_of("general")));
        assert_eq!(system.user_kicked, None);
        assert_eq!(system.user_banned, None);

        match db
            .fetch_invite(stored.invite_code.as_deref().expect("invite minted"))
            .await
            .unwrap()
        {
            Invite::Server { channel, .. } => assert_eq!(channel, id_of("welcome")),
            _ => panic!("expected a server invite"),
        }

        let emojis = db.fetch_emoji_by_parent_id(&server_id).await.unwrap();
        assert_eq!(emojis.len(), 1);
        assert_eq!(emojis[0].name, "party");

        let summary = stored.summary.expect("summary");
        assert_eq!(summary.channels_created, 4);
        assert_eq!(summary.channels_skipped, 1);
        assert!(
            summary
                .notes
                .iter()
                .any(|note| note.starts_with("1 channel(s) were not visible to the importer bot")),
            "{:?}",
            summary.notes
        );
    }

    /// The code delta matched has since been removed from the description:
    /// nothing is built, the job fails with the verification copy, the emoji
    /// are never fetched, and the bot still leaves. A rate-limited fetch
    /// fails as "unavailable" with no retry, and the bot leaves then too.
    #[tokio::test]
    async fn stoat_job_fails_without_its_code_or_on_429_and_the_bot_still_leaves() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;

        let api = FakeStoat::new()
            .reply(
                "GET",
                &server_path(),
                200,
                // Another code is not this job's code.
                stoat_server_body("Welcome! sloga-import-ZZZZZZZZ"),
            )
            .reply("DELETE", &leave_path(), 204, "")
            .start()
            .await;
        let mut config = config_with(false, false, true).await;
        config.api.import.stoat = api.source_config(&api);

        let job = stoat_job(&owner.id);
        claim_and_run(&db, &job, &config).await;

        let stored = db.fetch_discord_import_job(&job.id).await.unwrap();
        assert_eq!(stored.status, ImportStatus::Failed);
        assert_eq!(stored.error.as_deref(), Some(VERIFICATION_MISSING));
        assert_eq!(stored.server_id, None, "nothing was built");
        assert!(stored.source_left, "the bot leaves after a failure too");
        assert_eq!(
            api.seen()
                .into_iter()
                .map(|seen| (seen.method, seen.path))
                .collect::<Vec<_>>(),
            vec![
                ("GET".to_string(), server_path()),
                ("DELETE".to_string(), leave_path()),
            ]
        );

        let limited = FakeStoat::new()
            .reply("GET", &server_path(), 429, r#"{"type":"RateLimited"}"#)
            .reply("DELETE", &leave_path(), 204, "")
            .start()
            .await;
        config.api.import.stoat = limited.source_config(&limited);

        let job = stoat_job(&owner.id);
        claim_and_run(&db, &job, &config).await;

        let stored = db.fetch_discord_import_job(&job.id).await.unwrap();
        assert_eq!(stored.status, ImportStatus::Failed);
        assert_eq!(
            stored.error,
            Some(crate::tasks::stoat_import::source::StoatError::Unavailable.user_message())
        );
        assert!(stored.source_left);
        assert_eq!(
            limited
                .seen()
                .into_iter()
                .map(|seen| seen.method)
                .collect::<Vec<_>>(),
            vec!["GET", "DELETE"],
            "one fetch, no retry"
        );
    }

    /// A Stoat job whose worker died mid-build: the sweeper rolls its
    /// orphan server back, and the bot leaves on the leave retry.
    ///
    /// `sweep_stale` reads the ambient config, which on a dev box has no
    /// Stoat bot token, so the sweep's own leave sends nothing (asserted);
    /// the next housekeeping tick, with the fake upstream's config, leaves.
    #[tokio::test]
    async fn reaped_stoat_job_rolls_back_and_the_bot_leaves() {
        assert!(
            config().await.api.import.stoat.bot_token.is_empty(),
            "this test assumes no Stoat bot token in the ambient config"
        );

        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;
        let (server, _) = Server::create(
            &db,
            v0::DataCreateServer {
                name: "Half built".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .unwrap();

        let mut job = stoat_job(&owner.id);
        job.status = ImportStatus::Running;
        job.stage = ImportStage::Channels;
        job.server_id = Some(server.id.clone());
        job.updated_at = Timestamp::now_utc()
            .checked_sub(iso8601_timestamp::Duration::hours(1))
            .unwrap();
        db.insert_discord_import_job(&job).await.unwrap();

        sweep_stale(&db).await.unwrap();

        assert!(
            db.fetch_server(&server.id).await.is_err(),
            "the orphan server is rolled back"
        );
        let stored = db.fetch_discord_import_job(&job.id).await.unwrap();
        assert_eq!(stored.status, ImportStatus::Failed);
        assert!(!stored.source_left, "no token: nothing could be sent yet");

        let api = FakeStoat::new()
            .reply("DELETE", &leave_path(), 204, "")
            .start()
            .await;
        let mut config = config_with(false, false, true).await;
        config.api.import.stoat = api.source_config(&api);

        // Tick 0 is a sweep tick: the leave retry runs with the real hook.
        assert!(housekeeping(&db, &config, 0, &leave_source).await);

        assert!(
            db.fetch_discord_import_job(&job.id)
                .await
                .unwrap()
                .source_left
        );
        assert_eq!(
            api.seen()
                .into_iter()
                .map(|seen| (seen.method, seen.path))
                .collect::<Vec<_>>(),
            vec![("DELETE".to_string(), leave_path())]
        );
    }

    /// The leave needs the bot token, not `enabled`. Without one nothing is
    /// sent and the row stays un-left for the retry (and its give-up); with
    /// one, the same retry leaves even though Stoat is switched off.
    #[tokio::test]
    async fn stoat_leave_needs_the_bot_token_not_the_switch() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let api = FakeStoat::new()
            .reply("DELETE", &leave_path(), 204, "")
            .start()
            .await;

        let mut config = config_with(false, false, false).await;
        config.api.import.stoat = api.source_config(&api);
        config.api.import.stoat.enabled = false;
        config.api.import.stoat.bot_token = String::new();

        let mut job = stoat_job("01USERA000000000000000000A");
        job.status = ImportStatus::Completed;
        db.insert_discord_import_job(&job).await.unwrap();

        retry_source_leaves_with(&db, &config, &leave_source).await;
        assert!(
            !db.fetch_discord_import_job(&job.id)
                .await
                .unwrap()
                .source_left
        );
        assert!(api.seen().is_empty(), "{:?}", api.seen());

        config.api.import.stoat.bot_token = BOT_TOKEN.to_string();
        retry_source_leaves_with(&db, &config, &leave_source).await;
        assert!(
            db.fetch_discord_import_job(&job.id)
                .await
                .unwrap()
                .source_left
        );
        assert_eq!(api.seen().len(), 1);
    }
}
