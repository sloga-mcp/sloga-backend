//! Sticker-import worker — the "bot upgrade" half of the Discord importer.
//!
//! A sticker job is spawned by delta from a Completed template job after the
//! user adds the operator's importer bot to the source guild. This module
//! reads the guild's sticker list through the authenticated Discord API,
//! downloads each sticker from the public CDN, and recreates it as a Sloga
//! server sticker via the same storage path as the sticker CRUD.
//!
//! Differences from the template worker that are DELIBERATE:
//!
//! - **No rollback, ever.** `job.server_id` points at a live server this job
//!   did not build; created stickers are real, usable and individually
//!   deletable. A failed batch is retried by clicking the button again —
//!   creation is idempotent by name.
//! - **The stage never moves.** The job is born at `ImportStage::Stickers`
//!   (which is also what makes the row illegible to pre-slice-2 binaries);
//!   `done`/`total` carry all progress.
//! - **Heartbeat ≠ progress counter.** The heartbeat is bumped every
//!   iteration, success or failure — a failure-heavy batch of slow CDN
//!   timeouts must not out-wait the sweeper and get reaped alive. `done`
//!   still counts successes only.

use std::collections::HashSet;

use revolt_config::config;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::{
    events::client::EventV1, iso8601_timestamp::Timestamp, Database, DiscordImportJob,
    DiscordImportSummary, File, FileHash, ImportStage, ImportStatus, Metadata, Sticker,
    StickerFormat,
};
use revolt_files::{image_size_vec, upload_to_s3, AUTHENTICATION_TAG_SIZE_BYTES};
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use serde::Deserialize;
use sha2::Digest;

use super::template::{DISCORD_API, FETCH_TIMEOUT};
use super::worker::{generic_failure, progress, ImportAbort};

/// Fallback byte cap if the config map is missing a `stickers` entry.
/// Matches the baked `Revolt.toml`; only reachable on a broken config.
const FALLBACK_STICKER_BYTES: usize = 500_000;

/// Sloga's sticker-name validator bound (`DataCreateSticker`), char-based.
const NAME_MAX_CHARS: usize = 32;
/// Sloga's sticker-description validator bound, char-based.
const DESCRIPTION_MAX_CHARS: usize = 200;

// ---------------------------------------------------------------------------
// Discord API shapes
// ---------------------------------------------------------------------------

/// A guild sticker as returned by `GET /guilds/{id}/stickers`.
///
/// Scalars are kept permissive for the same reason the template parser's are:
/// Discord's docs and Discord's wire format have disagreed before.
#[derive(Debug, Deserialize)]
pub(super) struct GuildSticker {
    /// Snowflake. STRING on the wire; validated as numeric before it may
    /// reach a CDN URL.
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// 1 = PNG, 2 = APNG, 3 = Lottie, 4 = GIF.
    #[serde(default)]
    pub format_type: u8,
    /// False for stickers whose asset may be gone (e.g. expired boost tier).
    /// Absent is treated as available.
    #[serde(default)]
    pub available: Option<bool>,
}

/// Why the guild sticker list couldn't be read.
#[derive(Debug)]
pub(super) enum StickerFetchError {
    /// 403/404: the bot isn't in the guild (or the guild is gone) — the one
    /// the user can act on.
    NoAccess,
    /// 401: the operator's token is wrong. Not the user's problem.
    BadToken,
    RateLimited,
    Upstream(u16),
    Network(String),
    Malformed(String),
}

impl StickerFetchError {
    /// User-safe message stored on the job. Must never leak internals.
    pub fn user_message(&self) -> String {
        match self {
            StickerFetchError::NoAccess => {
                "We couldn't access that Discord server's stickers. Make sure the importer \
                 bot has been added to it, then try again."
                    .to_string()
            }
            StickerFetchError::BadToken => generic_failure(),
            StickerFetchError::RateLimited => {
                "Discord is rate-limiting us right now. Please try again in a few minutes."
                    .to_string()
            }
            StickerFetchError::Upstream(_) | StickerFetchError::Network(_) => {
                "We couldn't reach Discord to read the stickers. Please try again shortly."
                    .to_string()
            }
            StickerFetchError::Malformed(_) => {
                "Discord returned sticker data we couldn't understand. Please report this if \
                 it keeps happening."
                    .to_string()
            }
        }
    }
}

/// Fetch a guild's stickers with the operator's bot token.
///
/// The token appears HERE and nowhere else, and never in any log or error:
/// every failure is mapped to a static classification before it can carry
/// request detail.
async fn fetch_guild_stickers(
    guild_id: u64,
    bot_token: &str,
) -> Result<Vec<GuildSticker>, StickerFetchError> {
    // Tight redirect policy + https-only (plan §6): this client carries the
    // bot token, so it must never be walked off to another scheme or into a
    // redirect chain. (reqwest strips Authorization cross-host anyway; this
    // makes the posture explicit.)
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(2))
        .https_only(true)
        .build()
        .map_err(|e| StickerFetchError::Network(e.to_string()))?;

    let response = client
        .get(format!("{DISCORD_API}/guilds/{guild_id}/stickers"))
        .header("Authorization", format!("Bot {bot_token}"))
        .send()
        .await
        .map_err(|_| StickerFetchError::Network("request failed".to_string()))?;

    let status = response.status();
    match status {
        reqwest::StatusCode::OK => response
            .json::<Vec<GuildSticker>>()
            .await
            .map_err(|e| StickerFetchError::Malformed(e.to_string())),
        reqwest::StatusCode::UNAUTHORIZED => Err(StickerFetchError::BadToken),
        reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::NOT_FOUND => {
            Err(StickerFetchError::NoAccess)
        }
        reqwest::StatusCode::TOO_MANY_REQUESTS => Err(StickerFetchError::RateLimited),
        other => Err(StickerFetchError::Upstream(other.as_u16())),
    }
}

// ---------------------------------------------------------------------------
// Batch planning (pure)
// ---------------------------------------------------------------------------

/// One sticker we intend to create, with its format triple resolved.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PlannedSticker {
    /// Validated numeric snowflake — the only thing allowed into a CDN URL.
    pub discord_id: u64,
    pub name: String,
    pub description: Option<String>,
    pub format: StickerFormat,
    pub content_type: &'static str,
    pub extension: &'static str,
    pub animated: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct StickerPlan {
    pub planned: Vec<PlannedSticker>,
    /// Everything the user will NOT get, bucketed so each count can carry an
    /// honest note. `planned + all skips == guild list length` always.
    pub skipped_unsupported: u32,
    pub skipped_unavailable: u32,
    pub skipped_name_collision: u32,
    pub skipped_over_cap: u32,
}

impl StickerPlan {
    pub fn skipped_total(&self) -> u32 {
        self.skipped_unsupported
            + self.skipped_unavailable
            + self.skipped_name_collision
            + self.skipped_over_cap
    }
}

/// The format triple, derived from `format_type` in ONE place.
///
/// Deliberately NOT routed through delta's `detect_sticker_format`: that maps
/// `image/png` → `PNG`, and Discord serves APNG under `.png` — deriving from
/// the content type would ship an animated sticker labeled static. Pinned by
/// `format_triple_is_internally_consistent`.
fn format_triple(format_type: u8) -> Option<(StickerFormat, &'static str, &'static str, bool)> {
    match format_type {
        1 => Some((StickerFormat::PNG, "image/png", "png", false)),
        2 => Some((StickerFormat::APNG, "image/apng", "png", true)),
        4 => Some((StickerFormat::GIF, "image/gif", "gif", true)),
        // 3 = Lottie: first-party packs only (and Discord-copyrighted);
        // guild stickers can't be Lottie. Skip, never guess.
        _ => None,
    }
}

/// Decide what to create. Pure, so every rule is unit-testable.
///
/// `existing_names` also provides idempotency: a retry after a partial
/// failure re-plans only what is missing. Collisions ARE counted as skipped
/// (Discord doesn't force unique names in a guild, and neither do we — the
/// user must be able to reconcile `created + skipped` with what Discord
/// shows), which means a retry that finds everything present reports
/// "0 created, N skipped" rather than pretending the guild was empty.
pub(super) fn plan_stickers(
    guild: Vec<GuildSticker>,
    existing_names: &HashSet<String>,
    existing_count: usize,
    cap: usize,
) -> StickerPlan {
    let mut plan = StickerPlan::default();
    let mut taken: HashSet<String> = existing_names.clone();
    let mut room = cap.saturating_sub(existing_count);

    for sticker in guild {
        if sticker.available == Some(false) {
            plan.skipped_unavailable += 1;
            continue;
        }

        // The id is interpolated into a CDN URL; only a numeric snowflake
        // may pass (same hygiene as template codes).
        let Ok(discord_id) = sticker.id.parse::<u64>() else {
            plan.skipped_unsupported += 1;
            continue;
        };

        let Some((format, content_type, extension, animated)) = format_triple(sticker.format_type)
        else {
            plan.skipped_unsupported += 1;
            continue;
        };

        // Char-based clamps, matching the validator delta's CRUD applies.
        let name: String = sticker.name.trim().chars().take(NAME_MAX_CHARS).collect();
        if name.is_empty() {
            plan.skipped_unsupported += 1;
            continue;
        }

        if taken.contains(&name) {
            plan.skipped_name_collision += 1;
            continue;
        }

        if room == 0 {
            plan.skipped_over_cap += 1;
            continue;
        }

        let description = sticker
            .description
            .filter(|d| !d.trim().is_empty())
            .map(|d| d.chars().take(DESCRIPTION_MAX_CHARS).collect());

        taken.insert(name.clone());
        room -= 1;
        plan.planned.push(PlannedSticker {
            discord_id,
            name,
            description,
            format,
            content_type,
            extension,
            animated,
        });
    }

    plan
}

/// Turn the plan's skip buckets into the summary notes shown on the done
/// screen. Counts and prose come from the same numbers so they can't
/// disagree.
fn plan_notes(plan: &StickerPlan, cap: usize) -> Vec<String> {
    let mut notes = Vec::new();
    if plan.skipped_unsupported > 0 {
        notes.push(format!(
            "{} sticker(s) were in a format we can't import and were skipped.",
            plan.skipped_unsupported
        ));
    }
    if plan.skipped_unavailable > 0 {
        notes.push(format!(
            "{} sticker(s) are marked unavailable on Discord and were skipped.",
            plan.skipped_unavailable
        ));
    }
    if plan.skipped_name_collision > 0 {
        notes.push(format!(
            "{} sticker(s) shared a name with one already on the server and were skipped.",
            plan.skipped_name_collision
        ));
    }
    if plan.skipped_over_cap > 0 {
        notes.push(format!(
            "{} sticker(s) weren't imported — this server hit the {cap}-sticker limit.",
            plan.skipped_over_cap
        ));
    }
    notes
}

// ---------------------------------------------------------------------------
// Download + store
// ---------------------------------------------------------------------------

/// Download one sticker from the public CDN, refusing to buffer past
/// `byte_limit`.
///
/// The limit is enforced twice: on `Content-Length` when present, and again
/// on the actual bytes read — never trust a header alone, never read
/// unbounded.
async fn download_sticker(
    client: &reqwest::Client,
    planned: &PlannedSticker,
    byte_limit: usize,
) -> Option<Vec<u8>> {
    let url = format!(
        "https://cdn.discordapp.com/stickers/{}.{}",
        planned.discord_id, planned.extension
    );

    let mut response = client.get(&url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }

    if let Some(length) = response.content_length() {
        if length as usize > byte_limit {
            return None;
        }
    }

    let mut buf: Vec<u8> = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        if buf.len() + chunk.len() > byte_limit {
            return None;
        }
        buf.extend_from_slice(&chunk);
    }

    if buf.is_empty() {
        return None;
    }

    Some(buf)
}

/// Store sticker bytes the way autumn + the sticker CRUD would: FileHash +
/// S3 blob + attachment row with `used_for` set immediately (so the
/// dangling-file pruner never touches it), sticker id == attachment id.
///
/// Mirrors `seed_stickers.rs` (the sanctioned seeding pattern). Kept here
/// rather than in a shared crate on purpose: the natural shared home would
/// drag the S3 SDK into the database crate for two call sites.
///
/// `insert_attachment` is on the disallowed list because attachments are
/// normally minted by autumn's upload route; this helper IS that upload
/// route replicated at library level (no session token exists server-side),
/// so the raw insert is the point — same justification as the seeder.
#[allow(clippy::disallowed_methods)]
async fn store_sticker_file(
    db: &Database,
    planned: &PlannedSticker,
    buf: &[u8],
    creator_id: &str,
) -> Result<File, ()> {
    let config = config().await;
    let hash_hex = format!("{:02x}", sha2::Sha256::digest(buf));

    // ACCEPTED RESIDUAL: content-addressed reuse means byte-identical media
    // uploaded earlier through autumn keeps ITS hash metadata (e.g. an APNG
    // autumn sniffed as image/png) — the Sticker row's `format` is still
    // correct (it comes from format_type), only serving metadata can be
    // stale, and only for byte-identical prior uploads.
    let file_hash = match db.fetch_attachment_hash(&hash_hex).await {
        Ok(hash) if !hash.iv.is_empty() => hash,
        _ => {
            let (width, height) = image_size_vec(buf, planned.content_type).unwrap_or((320, 320));
            let fresh = FileHash {
                id: hash_hex.clone(),
                processed_hash: hash_hex.clone(),
                created_at: Timestamp::now_utc(),
                bucket_id: config.files.s3.default_bucket.clone(),
                path: hash_hex.clone(),
                iv: String::new(),
                format_version: None, // legacy whole-file GCM format
                metadata: Metadata::Image {
                    width: width as isize,
                    height: height as isize,
                    thumbhash: None,
                    animated: planned.animated.then_some(true),
                },
                content_type: planned.content_type.to_owned(),
                size: (buf.len() + AUTHENTICATION_TAG_SIZE_BYTES) as isize,
            };
            // Duplicate-insert errors are IGNORED on purpose, exactly like the
            // seeder: a crashed earlier attempt can leave a `{iv: ""}` hash
            // row behind, and failing here would wedge that sticker forever —
            // every retry would re-insert, hit the duplicate id, and error.
            // The heal is to fall through and (re)upload + set the nonce.
            let _ = db.insert_attachment_hash(&fresh).await;
            let nonce = upload_to_s3(&fresh.bucket_id, &fresh.id, buf)
                .await
                .map_err(|_| ())?;
            db.set_attachment_hash_nonce(&fresh.id, &nonce)
                .await
                .map_err(|_| ())?;
            db.fetch_attachment_hash(&hash_hex).await.map_err(|_| ())?
        }
    };

    let id = nanoid::nanoid!(42);
    db.insert_attachment(&file_hash.into_file(
        id.clone(),
        "stickers".to_owned(),
        format!("{}.{}", planned.discord_id, planned.extension),
        creator_id.to_owned(),
    ))
    .await
    .map_err(|_| ())?;

    File::use_sticker(db, &id, &id, creator_id)
        .await
        .map_err(|_| ())
}

// ---------------------------------------------------------------------------
// The worker
// ---------------------------------------------------------------------------

/// Run a sticker-import job to completion. See the module docs for how this
/// deliberately differs from the template worker.
pub(super) async fn import_stickers(
    db: &Database,
    job: &mut DiscordImportJob,
) -> Result<(), ImportAbort> {
    let config = config().await;

    // Time-of-use re-checks: config can change between queue and claim, and
    // the user's standing on the server can too.
    if !config.api.import.discord.stickers_enabled() {
        return Err(ImportAbort::Failed(
            "Sticker import is not enabled on this instance.".to_string(),
        ));
    }

    let owner = db
        .fetch_user(&job.user_id)
        .await
        .map_err(|_| ImportAbort::Failed(generic_failure()))?;

    let Some(server_id) = job.server_id.clone() else {
        return Err(ImportAbort::Failed(generic_failure()));
    };

    // Snowflake-validated at persist time; re-validated here because it is
    // about to be interpolated into a bot-authenticated URL.
    let guild_id: u64 = match job.source_guild_id.as_deref().map(str::parse) {
        Some(Ok(id)) => id,
        _ => return Err(ImportAbort::Failed(generic_failure())),
    };

    // The server must still exist and the owner must still hold the exact
    // permission the sticker CRUD demands. NO rollback on failure here or
    // anywhere below — this job did not build the server it points at.
    let server = db
        .fetch_server(&server_id)
        .await
        .map_err(|_| ImportAbort::Failed("That server no longer exists.".to_string()))?;

    let mut query = DatabasePermissionQuery::new(db, &owner).server(&server);
    if calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageCustomisation)
        .is_err()
    {
        return Err(ImportAbort::Failed(
            "You need the Manage Customisation permission on the imported server to add \
             stickers to it."
                .to_string(),
        ));
    }

    if !progress(db, job, ImportStage::Stickers, 0, 0).await {
        return Err(ImportAbort::Superseded);
    }

    let guild_stickers = fetch_guild_stickers(guild_id, &config.api.import.discord.bot_token)
        .await
        .map_err(|error| {
            // Classification only — never the raw error, which could carry
            // request detail.
            // The detail strings below can never carry the token: Network is
            // a static classification and Malformed is a serde message about
            // response BODY shape.
            log::warn!(
                "sticker fetch for import job {} failed: {}",
                job.id,
                match &error {
                    StickerFetchError::NoAccess => "no access (bot not in guild?)".to_string(),
                    StickerFetchError::BadToken => "bad token (check operator config)".to_string(),
                    StickerFetchError::RateLimited => "rate limited".to_string(),
                    StickerFetchError::Upstream(status) => format!("upstream error ({status})"),
                    StickerFetchError::Network(detail) => format!("network error ({detail})"),
                    StickerFetchError::Malformed(detail) =>
                        format!("malformed response ({detail})"),
                }
            );
            ImportAbort::Failed(error.user_message())
        })?;

    let existing = db
        .fetch_stickers_by_server_id(&server_id)
        .await
        .map_err(|_| ImportAbort::Failed(generic_failure()))?;
    let existing_names: HashSet<String> = existing
        .iter()
        .map(|sticker| sticker.name.clone())
        .collect();

    let cap = config.features.limits.global.server_stickers;
    let plan = plan_stickers(guild_stickers, &existing_names, existing.len(), cap);
    let mut notes = plan_notes(&plan, cap);

    let byte_limit = config
        .features
        .limits
        .default
        .file_upload_size_limit
        .get("stickers")
        .copied()
        .unwrap_or(FALLBACK_STICKER_BYTES);

    let total = plan.planned.len() as u32;
    if !progress(db, job, ImportStage::Stickers, 0, total.max(1)).await {
        return Err(ImportAbort::Superseded);
    }

    // Same tight policy as the list fetch (plan §6): the CDN 302s at most
    // once to a media host, and nothing here may ever leave https.
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(2))
        .https_only(true)
        .build()
        .map_err(|_| ImportAbort::Failed(generic_failure()))?;

    let mut created = 0u32;
    let mut failed = 0u32;

    for planned in &plan.planned {
        match download_sticker(&client, planned, byte_limit).await {
            Some(buf) => match store_sticker_file(db, planned, &buf, &owner.id).await {
                Ok(attachment) => {
                    let sticker = Sticker {
                        id: attachment.id.clone(),
                        server_id: server_id.clone(),
                        creator_id: owner.id.clone(),
                        name: planned.name.clone(),
                        description: planned.description.clone(),
                        file_id: attachment.id.clone(),
                        format: planned.format.clone(),
                        nsfw: false,
                    };
                    // The model method, NOT a raw insert: it emits
                    // `StickerCreate` to the server topic, so members'
                    // pickers fill in live.
                    match sticker.create(db).await {
                        Ok(()) => created += 1,
                        Err(error) => {
                            log::warn!("skipping sticker during import: {error:?}");
                            failed += 1;
                        }
                    }
                }
                Err(()) => {
                    log::warn!(
                        "could not store sticker {} during import",
                        planned.discord_id
                    );
                    failed += 1;
                }
            },
            None => {
                // Oversize, gone from the CDN, or a transport failure —
                // all the same to the user: this one didn't make it.
                failed += 1;
            }
        }

        // Heartbeat EVERY iteration, success or failure — a failure-heavy
        // batch of slow downloads must not out-wait the sweeper. `done`
        // counts successes only.
        if !progress(db, job, ImportStage::Stickers, created, total.max(1)).await {
            return Err(ImportAbort::Superseded);
        }
    }

    if failed > 0 {
        notes.push(format!(
            "{failed} sticker(s) couldn't be downloaded or stored and were skipped."
        ));
    }

    // Complete. Same terminal-write discipline as the template worker: a
    // refused save means someone else finalized the job, and we must not
    // claim success over that (but nothing gets rolled back either way).
    job.status = ImportStatus::Completed;
    job.stage = ImportStage::Done;
    job.done = created;
    job.total = total.max(1);
    job.summary = Some(DiscordImportSummary {
        channels_created: 0,
        categories_created: 0,
        channels_skipped: 0,
        roles_created: 0,
        roles_skipped: 0,
        stickers_created: Some(created),
        stickers_skipped: Some(plan.skipped_total() + failed),
        notes,
    });
    job.touch();

    match db.save_discord_import_job_if_active(job).await {
        Ok(true) => {}
        Ok(false) => return Err(ImportAbort::Superseded),
        Err(_) => return Err(ImportAbort::Failed(generic_failure())),
    }

    EventV1::DiscordImportComplete {
        job_id: job.id.clone(),
        server_id: server_id.clone(),
        // No invite is minted for a sticker run; empty means "none", as the
        // template worker already established.
        invite_code: String::new(),
    }
    .private(job.user_id.clone())
    .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guild_sticker(id: &str, name: &str, format_type: u8) -> GuildSticker {
        GuildSticker {
            id: id.to_string(),
            name: name.to_string(),
            description: Some("a sticker".to_string()),
            format_type,
            available: None,
        }
    }

    /// The format triple is the whole of audit finding #4: `format` must
    /// come from `format_type`, and APNG must never degrade to PNG.
    #[test]
    fn format_triple_is_internally_consistent() {
        assert_eq!(
            format_triple(1),
            Some((StickerFormat::PNG, "image/png", "png", false))
        );
        assert_eq!(
            format_triple(2),
            Some((StickerFormat::APNG, "image/apng", "png", true))
        );
        assert_eq!(
            format_triple(4),
            Some((StickerFormat::GIF, "image/gif", "gif", true))
        );
        // Lottie and anything unknown: skip, never guess.
        assert_eq!(format_triple(3), None);
        assert_eq!(format_triple(0), None);
        assert_eq!(format_triple(99), None);
        // An animated format may never carry the static PNG content type.
        for format_type in [2u8, 4] {
            let (_, content_type, _, animated) = format_triple(format_type).unwrap();
            assert!(animated);
            assert_ne!(content_type, "image/png");
        }
    }

    #[test]
    fn planner_drops_what_it_cannot_import_and_counts_every_drop() {
        let guild = vec![
            guild_sticker("111", "keep-png", 1),
            guild_sticker("222", "keep-apng", 2),
            guild_sticker("333", "lottie", 3),
            guild_sticker("444", "keep-gif", 4),
            guild_sticker("not-a-snowflake", "bad-id", 1),
            GuildSticker {
                available: Some(false),
                ..guild_sticker("555", "expired", 1)
            },
            GuildSticker {
                name: "   ".to_string(),
                ..guild_sticker("666", "", 1)
            },
        ];

        let plan = plan_stickers(guild, &HashSet::new(), 0, 60);

        assert_eq!(
            plan.planned
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            vec!["keep-png", "keep-apng", "keep-gif"]
        );
        // lottie + bad id + blank name
        assert_eq!(plan.skipped_unsupported, 3);
        assert_eq!(plan.skipped_unavailable, 1);
        // Every input is accounted for: planned + skipped == guild total.
        assert_eq!(plan.planned.len() as u32 + plan.skipped_total(), 7);
    }

    /// Ids reach a CDN URL, so the planner is the SSRF gate: whatever
    /// survives must format into a pure-numeric path segment.
    #[test]
    fn only_numeric_snowflakes_survive_into_urls() {
        let hostile = vec![
            guild_sticker("123/../../secrets", "a", 1),
            guild_sticker("123?query", "b", 1),
            guild_sticker("123#frag", "c", 1),
            guild_sticker("../123", "d", 1),
            guild_sticker("0x123", "e", 1),
            guild_sticker(" 123", "f", 1),
            guild_sticker("99999999999999999999999999", "overflow", 1),
            guild_sticker("841341949872046131", "legit", 1),
        ];

        let plan = plan_stickers(hostile, &HashSet::new(), 0, 60);
        assert_eq!(plan.planned.len(), 1);
        assert_eq!(plan.planned[0].discord_id, 841341949872046131);
    }

    #[test]
    fn names_and_descriptions_are_clamped_char_based() {
        let long_name = "é".repeat(64);
        let long_description = "d".repeat(500);
        let guild = vec![GuildSticker {
            description: Some(long_description),
            ..guild_sticker("111", &long_name, 1)
        }];

        let plan = plan_stickers(guild, &HashSet::new(), 0, 60);
        assert_eq!(plan.planned[0].name.chars().count(), NAME_MAX_CHARS);
        assert_eq!(
            plan.planned[0]
                .description
                .as_ref()
                .unwrap()
                .chars()
                .count(),
            DESCRIPTION_MAX_CHARS
        );
    }

    /// Idempotency + honest accounting: names already on the server (and
    /// duplicate names within the guild itself) are SKIPPED and COUNTED —
    /// a retry that finds everything present must report "0 created,
    /// N skipped", not pretend the guild was empty.
    #[test]
    fn name_collisions_are_skipped_and_counted() {
        let existing: HashSet<String> = ["pog".to_string()].into_iter().collect();
        let guild = vec![
            guild_sticker("111", "pog", 1),   // collides with the server
            guild_sticker("222", "fresh", 1), // fine
            guild_sticker("333", "fresh", 1), // collides within the batch
        ];

        let plan = plan_stickers(guild, &existing, 1, 60);
        assert_eq!(plan.planned.len(), 1);
        assert_eq!(plan.planned[0].name, "fresh");
        assert_eq!(plan.skipped_name_collision, 2);
    }

    #[test]
    fn cap_is_enforced_against_existing_count() {
        let guild = vec![
            guild_sticker("111", "a", 1),
            guild_sticker("222", "b", 1),
            guild_sticker("333", "c", 1),
        ];

        // 58 already on the server, cap 60 → room for exactly 2.
        let plan = plan_stickers(guild, &HashSet::new(), 58, 60);
        assert_eq!(plan.planned.len(), 2);
        assert_eq!(plan.skipped_over_cap, 1);

        // Already at the cap → nothing planned, everything counted.
        let guild = vec![guild_sticker("111", "a", 1)];
        let plan = plan_stickers(guild, &HashSet::new(), 60, 60);
        assert!(plan.planned.is_empty());
        assert_eq!(plan.skipped_over_cap, 1);
    }

    /// Notes and counts come from the same numbers — the slice-0 #10 rule.
    #[test]
    fn notes_mirror_the_skip_buckets() {
        let plan = StickerPlan {
            planned: vec![],
            skipped_unsupported: 1,
            skipped_unavailable: 2,
            skipped_name_collision: 3,
            skipped_over_cap: 4,
        };
        let notes = plan_notes(&plan, 60);
        assert_eq!(notes.len(), 4);
        assert!(notes[0].contains('1'));
        assert!(notes[1].contains('2'));
        assert!(notes[2].contains('3'));
        assert!(notes[3].contains("60-sticker limit"));
        assert_eq!(plan.skipped_total(), 10);
    }

    /// REAL payload captured live 2026-08-06 from
    /// `GET /guilds/1530784817975660565/stickers` (the Import Test guild),
    /// the way the template parser pins `2TffvPucqHkN` — Discord's docs
    /// have been wrong about scalar types before. Facts worth keeping:
    /// `description` arrives as an EMPTY STRING (not null), `tags` is an
    /// emoji snowflake (not a keyword), and a `user` object rides along.
    #[test]
    fn real_captured_payload_parses_and_plans() {
        let payload = r#"[{"id":"1534903197930360952","name":"Sloga Logo","tags":"1534903157140754522","type":2,"format_type":1,"description":"","asset":"","available":true,"guild_id":"1530784817975660565","user":{"id":"237728279405133824","username":"jcs_netherspite","avatar":"e37d7eae57febd30b2e7b6f4991fff8a","discriminator":"0","public_flags":0,"flags":0,"banner":null,"accent_color":null,"global_name":"Ding","avatar_decoration_data":null,"collectibles":null,"display_name_styles":null,"banner_color":null,"clan":null,"primary_guild":null}}]"#;
        let stickers: Vec<GuildSticker> = serde_json::from_str(payload).unwrap();
        assert_eq!(stickers.len(), 1);
        assert_eq!(stickers[0].name, "Sloga Logo");
        assert_eq!(stickers[0].format_type, 1);
        assert_eq!(stickers[0].available, Some(true));

        let plan = plan_stickers(stickers, &HashSet::new(), 0, 60);
        assert_eq!(plan.planned.len(), 1);
        assert_eq!(plan.planned[0].discord_id, 1534903197930360952);
        // The empty-string description must collapse to None, not create a
        // sticker with a blank description.
        assert_eq!(plan.planned[0].description, None);
        // This exact plan produced "Imported 1 stickers." in the live smoke.
        assert_eq!(plan.skipped_total(), 0);
    }
}
