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

use iso8601_timestamp::Timestamp;
use revolt_config::config;
use revolt_database::{
    events::client::EventV1, Category, Channel, Database, DiscordImportJob, DiscordImportSummary,
    ImportJobKind, ImportStage, ImportStatus, Invite, Member, PartialChannel, PartialServer, Role,
    Server, SystemMessageChannels, User, AMQP,
};
use revolt_models::v0;
use revolt_permissions::OverrideField;
use revolt_result::{ErrorType, Result};
use tokio::time::sleep;

use super::mapper::{plan_import, ImportPlan, PlannedChannelKind, PlannedOverride};
use super::template::{self, TemplateFetchError};

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

/// Why an import stopped early. Shared with the sticker worker.
pub(super) enum ImportAbort {
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

        if !config.api.import.discord.enabled {
            sleep(DISABLED_TICK).await;
            continue;
        }

        if tick % SWEEP_EVERY_N_TICKS == 0 {
            if let Err(error) = sweep_stale(&db).await {
                log::error!("discord import sweeper failed: {error:?}");
            }
        }
        tick = tick.wrapping_add(1);

        // Drain the queue rather than taking one per tick, so a burst doesn't
        // serialize at 3s apiece. Bounded per tick so a steady stream of work
        // can't starve the sweeper indefinitely.
        for _ in 0..SWEEP_EVERY_N_TICKS {
            match db.claim_next_queued_discord_import_job().await {
                Ok(Some(job)) => run_job(&db, job).await,
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
        // KIND GATE, load-bearing: only a TEMPLATE job can ever have built the
        // server it points at. A sticker job's `server_id` is a fully-built,
        // LIVE server inherited from its parent — and if its owner happens to
        // have left that server, the membership probe below answers NotFound
        // and the ungated rollback would delete the whole thing, cascades and
        // all, to reap a job whose worst real failure is "some stickers
        // missing". Guarded by
        // `reaped_sticker_job_never_rolls_back_the_server`.
        let rollback_eligible = matches!(job.kind, ImportJobKind::Template);
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
        }
    }

    Ok(())
}

/// Delete a half-built server. Best-effort: a failure here leaves an orphan,
/// which is bad but strictly better than aborting the cleanup pass.
async fn rollback_server(db: &Database, server_id: &str) {
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
pub(super) async fn progress(
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
pub(super) fn generic_failure() -> String {
    "Something went wrong while importing your server. Please try again.".to_string()
}

async fn run_job(db: &Database, mut job: DiscordImportJob) {
    // Kind dispatch. The two paths share the job/progress/failure machinery
    // but almost nothing else — in particular the sticker path NEVER rolls
    // a server back (its `server_id` is a live server it did not build).
    let result = match job.kind {
        ImportJobKind::Template => import(db, &mut job).await,
        ImportJobKind::Stickers => super::stickers::import_stickers(db, &mut job).await,
    };

    match result {
        Ok(()) => {}
        Err(ImportAbort::Superseded) => {
            // Deliberately silent: whoever finalized the job already informed
            // the user, and (for a template job) any server we built was
            // rolled back below.
        }
        Err(ImportAbort::Failed(message)) => {
            fail_job(db, &mut job, message).await;
        }
    }
}

async fn import(db: &Database, job: &mut DiscordImportJob) -> std::result::Result<(), ImportAbort> {
    let owner = db
        .fetch_user(&job.user_id)
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
            nsfw: None,
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
    match build_server(db, job, &owner, server, &plan, total).await {
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
async fn build_server(
    db: &Database,
    job: &mut DiscordImportJob,
    owner: &User,
    mut server: Server,
    plan: &ImportPlan,
    total: u32,
) -> std::result::Result<(), ImportAbort> {
    // 3. Roles, before channels — per-channel overwrites are keyed by role id.
    let (roles, roles_created, roles_skipped, role_notes) =
        create_roles(db, job, &mut server, plan).await?;

    // 4. Channels, with their permission overwrites resolved against `roles`.
    let (channels, mut summary) =
        create_channels(db, &mut server, plan, job, total, &roles).await?;
    summary.roles_created = roles_created;
    summary.roles_skipped = roles_skipped;
    summary.notes.extend(role_notes);

    // 5. Categories + system messages + the imported `@everyone` baseline,
    // persisted AND applied in memory.
    //
    // This matters beyond persistence: `ServerCreate` (emitted by
    // `Member::create` below) snapshots the IN-MEMORY server, so anything
    // missing here renders as missing on the client.
    let categories = build_categories(plan, &channels);
    summary.categories_created = categories.len() as u32;

    let system_messages = plan
        .system_channel
        .as_ref()
        .and_then(|wanted| resolve_channel_id(&channels, &wanted.0))
        .map(|channel_id| SystemMessageChannels {
            user_joined: Some(channel_id.clone()),
            user_left: Some(channel_id.clone()),
            user_kicked: Some(channel_id.clone()),
            user_banned: Some(channel_id),
        });

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

    let invite_code = mint_invite(db, owner, plan, &channels).await;
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
            // channel overwrites — so `d` is always 0 here. The wire type is
            // u64 and the stored type i64; this is the cast.
            permissions: OverrideField {
                a: planned.permissions as i64,
                d: 0,
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

/// Create every planned channel, returning them paired with their template id
/// so categories and the system channel can be resolved afterwards.
async fn create_channels(
    db: &Database,
    server: &mut Server,
    plan: &ImportPlan,
    job: &mut DiscordImportJob,
    total: u32,
    roles: &RoleMap,
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
                voice,
                announcement,
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
                dropped_overrides += planned
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

                if needs_update {
                    if let Err(error) = channel.update(db, partial, vec![]).await {
                        // The channel exists and is usable; losing its
                        // permissions is worth a note, not the whole import.
                        log::warn!("could not apply channel settings during import: {error:?}");
                        settings_failed += 1;
                    }
                }

                created.push((planned.template_id.0.clone(), channel));
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

    if settings_failed > 0 {
        notes.push(format!(
            "{settings_failed} channel(s) were created but their Discord permissions couldn't be \
             applied — check them in channel settings."
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
        channels_skipped: skipped + over_limit + plan.skipped_channel_count,
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

/// Mint the welcome invite in the most sensible channel we have.
async fn mint_invite(
    db: &Database,
    owner: &User,
    plan: &ImportPlan,
    channels: &[(String, Channel)],
) -> Option<String> {
    // Voice channels are `TextChannel` with `voice: Some(..)`, so a naive
    // TextChannel match would happily drop new members into a voice room.
    let is_text = |channel: &&Channel| matches!(channel, Channel::TextChannel { voice: None, .. });

    // Prefer the guild's own system channel, else the first real text channel.
    let target = plan
        .system_channel
        .as_ref()
        .and_then(|wanted| {
            channels
                .iter()
                .find(|(id, _)| id == &wanted.0)
                .map(|(_, channel)| channel)
                .filter(is_text)
        })
        .or_else(|| channels.iter().map(|(_, channel)| channel).find(is_text))?;

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
        let (channels, summary) =
            match create_channels(&db, &mut server, &plan, &mut job, total, &roles).await {
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
    /// remove the `ImportJobKind::Template` gate in `sweep_stale` and the
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

    /// Audit #5's pin: a sticker job that FAILS must not touch the server it
    /// points at. The failure here is the cheapest one to arrange (the
    /// feature flag is off in the test config, so the worker fails at its
    /// time-of-use check), but the invariant it pins is structural: no
    /// failure path of the sticker kind may route into `rollback_server`.
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

        let mut parent = DiscordImportJob::new(owner.id.clone(), "tmpl".to_string());
        parent.status = ImportStatus::Completed;
        parent.stage = ImportStage::Done;
        parent.server_id = Some(server.id.clone());
        parent.source_guild_id = Some("1530784817975660565".to_string());
        db.insert_discord_import_job(&parent).await.unwrap();

        let mut sticker_job = DiscordImportJob::new_stickers(&parent);
        sticker_job.status = ImportStatus::Running;
        db.insert_discord_import_job(&sticker_job).await.unwrap();

        run_job(&db, sticker_job.clone()).await;

        let stored = db.fetch_discord_import_job(&sticker_job.id).await.unwrap();
        assert_eq!(
            stored.status,
            ImportStatus::Failed,
            "with the bot upgrade unconfigured the job must fail cleanly"
        );
        assert!(stored.error.is_some());

        db.fetch_server(&server.id)
            .await
            .expect("a failed sticker job must never roll the live server back");
        assert_eq!(
            stored.server_id.as_deref(),
            Some(server.id.as_str()),
            "the job must keep pointing at the server it was for"
        );
    }
}
