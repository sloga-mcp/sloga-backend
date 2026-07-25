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

use std::time::Duration;

use iso8601_timestamp::Timestamp;
use revolt_config::config;
use revolt_database::{
    events::client::EventV1, Category, Channel, Database, DiscordImportJob, DiscordImportSummary,
    ImportStage, ImportStatus, Invite, Member, PartialChannel, PartialServer, Server,
    SystemMessageChannels, User, AMQP,
};
use revolt_models::v0;
use revolt_result::Result;
use tokio::time::sleep;

use super::mapper::{plan_import, ImportPlan, PlannedChannelKind};
use super::template::{self, TemplateFetchError};

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

/// Why an import stopped early.
enum ImportAbort {
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
    let Some(cutoff) =
        Timestamp::now_utc().checked_sub(iso8601_timestamp::Duration::seconds(HEARTBEAT_TIMEOUT_SECS))
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
        // membership row), and free (the quota counts memberships) — an
        // orphan that accumulates one per deploy-during-import.
        let orphan = job.server_id.clone().filter(|_| {
            matches!(
                job.stage,
                ImportStage::Fetching | ImportStage::Server | ImportStage::Channels
            )
        });

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
async fn progress(
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
            log::error!("failed to persist import progress for {}: {error:?}", job.id)
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
fn generic_failure() -> String {
    "Something went wrong while importing your server. Please try again.".to_string()
}

async fn run_job(db: &Database, mut job: DiscordImportJob) {
    match import(db, &mut job).await {
        Ok(()) => {}
        Err(ImportAbort::Superseded) => {
            // Deliberately silent: whoever finalized the job already informed
            // the user, and any server we built was rolled back below.
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

    let plan = plan_import(&fetched);
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
    // 3. Channels.
    let (channels, mut summary) = create_channels(db, &mut server, plan, job, total).await?;

    // 4. Categories + system messages, persisted AND applied in memory.
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
                channels: Some(created_channels.iter().map(|c| c.id().to_string()).collect()),
                categories: if categories.is_empty() {
                    None
                } else {
                    Some(categories)
                },
                system_messages,
                ..Default::default()
            },
            vec![],
        )
        .await
        .map_err(|_| ImportAbort::Failed(generic_failure()))?;

    // 5. Membership — LOAD-BEARING, and the single easiest thing to get wrong.
    //
    // `Server::create` writes the server document and emits NOTHING.
    // `Member::create` is the sole writer of the `server_members` row and the
    // sole emitter of `ServerCreate`. bonfire builds a user's server list from
    // their memberships, so skipping this produces an import that "succeeds"
    // and then vanishes from the client on the next reconnect.
    //
    // It must also run AFTER the server struct is fully populated (step 4) and
    // BEFORE the completion event (step 7), so the client has the server
    // cached by the time it navigates to it.
    if !progress(db, job, ImportStage::Membership, total, total).await {
        return Err(ImportAbort::Superseded);
    }

    Member::create(db, &server, owner, Some(created_channels.clone()))
        .await
        .map_err(|_| ImportAbort::Failed(generic_failure()))?;

    // 6. Welcome invite — the actual payload of this feature ("paste this in
    // your Discord"). Best-effort: a server without an invite is still a
    // successful import, and the user can mint one by hand.
    if !progress(db, job, ImportStage::Invite, total, total).await {
        return Err(ImportAbort::Superseded);
    }

    let invite_code = mint_invite(db, owner, plan, &channels).await;
    job.invite_code = invite_code.clone();

    // 7. Done.
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

/// Create every planned channel, returning them paired with their template id
/// so categories and the system channel can be resolved afterwards.
async fn create_channels(
    db: &Database,
    server: &mut Server,
    plan: &ImportPlan,
    job: &mut DiscordImportJob,
    total: u32,
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
                // Slowmode isn't part of the creation DTO, so apply it after.
                if let Some(seconds) = slowmode {
                    if let Err(error) = channel
                        .update(
                            db,
                            PartialChannel {
                                slowmode: Some(seconds),
                                ..Default::default()
                            },
                            vec![],
                        )
                        .await
                    {
                        log::warn!("could not apply slowmode during import: {error:?}");
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

    let summary = DiscordImportSummary {
        channels_created: created.len() as u32,
        categories_created: 0, // set by the caller once categories are built
        // Everything the user didn't get, so this can't contradict the notes
        // rendered beside it.
        channels_skipped: skipped + over_limit + plan.skipped_channel_count,
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
    let is_text = |channel: &&Channel| {
        matches!(
            channel,
            Channel::TextChannel { voice: None, .. }
        )
    };

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
