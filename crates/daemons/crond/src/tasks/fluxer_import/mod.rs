//! Fluxer guild importer.
//!
//! The user added the operator bot to their Fluxer guild (with
//! Administrator, so it can see every channel and read the audit log) and
//! created a role named exactly their verification code, with Manage Server;
//! delta checked that and queued a `FluxerServer` job with the matched code.
//! This worker, run from the shared import claim loop:
//!
//! 1. reads the roles, the bot's own roles and the role audit log since the
//!    code's day,
//! 2. checks the stored code still proves ownership, with the same rule
//!    delta used (`import_challenge::fluxer_role_proof`),
//! 3. reads the guild (with its emoji) and every channel the bot can see,
//! 4. rewrites them into the Discord mapper's template shape (`adapter`),
//!    maps that into an `ImportPlan` and hands it to the shared
//!    `execute_plan`, with a fetcher for the icon, banner and emoji files.
//!
//! The bot leaves the guild once the job is terminal (completed, failed or
//! reaped), through the worker's `on_terminal` and its leave retry; a daily
//! pass (`reconcile`) also removes it from guilds nobody is importing.
//! Upstream calls per import: roles, members/@me, two audit-log pages,
//! guild, channels and the leave, plus the CDN downloads on another host.

pub(crate) mod adapter;
pub mod reconcile;
pub(crate) mod source;

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use revolt_config::Settings;
use revolt_database::util::import_challenge::{
    code_day, fluxer_audit_after_cursor, fluxer_role_proof, ProofRole, FLUXER_AUDIT_ROLE_CREATE,
    FLUXER_AUDIT_ROLE_UPDATE,
};
use revolt_database::{Database, DiscordImportJob, ImportStage};

use super::discord_import::mapper::{plan_import_from, SourceLabel};
use super::discord_import::worker::{execute_plan, generic_failure, progress, ImportAbort};
use super::import_http::AssetLimits;
use source::{FluxerApi, FluxerAssets, FluxerError, Snowflake};

/// The challenge-code source tag (delta's `fluxer_source::SOURCE_TAG`).
pub(crate) const SOURCE_TAG: &str = "fluxer";

/// The job's code no longer proves ownership: the role is gone, renamed,
/// lost its privilege, or the job carries no usable code.
pub(crate) const VERIFICATION_FAILED: &str = "The verification role was not found, was renamed, \
     or lost Manage Server — keep it until the import finishes.";

/// The audit log holds more role changes since the code's day than one page
/// shows, so the role's history cannot be read in full.
pub(crate) const AUDIT_INCOMPLETE: &str = "Your Fluxer server's audit log has too many role \
     changes since your verification code was made for us to check your verification role. \
     Please try again tomorrow with a new code.";

/// When the job was created: the time in its ULID. The job carries no
/// creation timestamp of its own (`updated_at` moves at every stage).
fn job_created_at(job_id: &str) -> Option<SystemTime> {
    let id = ulid::Ulid::from_string(job_id).ok()?;
    UNIX_EPOCH.checked_add(Duration::from_millis(id.timestamp_ms()))
}

/// Log a failed Fluxer read and turn it into the job's failure.
fn fetch_failed(job: &DiscordImportJob, what: &str, error: FluxerError) -> ImportAbort {
    log::warn!(
        "fluxer import job {}: {what} fetch failed: {error:?}",
        job.id
    );
    ImportAbort::Failed(error.user_message())
}

/// Import the Fluxer guild a `FluxerServer` job names. The claim loop has
/// already checked the Fluxer source is ready.
pub(crate) async fn run(
    db: &Database,
    job: &mut DiscordImportJob,
    config: &Settings,
) -> Result<(), ImportAbort> {
    let fluxer = &config.api.import.fluxer;
    let secret = config.api.import.challenge_secret.as_bytes();
    let Some(api) = FluxerApi::new(fluxer).filter(|_| !secret.is_empty()) else {
        log::error!("fluxer import job {}: no usable Fluxer API config", job.id);
        return Err(ImportAbort::Failed(generic_failure()));
    };

    // Checked before anything leaves the process.
    db.fetch_user(&job.user_id)
        .await
        .map_err(|_| ImportAbort::Failed(generic_failure()))?;

    let Some(guild_id) = job.source_server_id.as_deref().and_then(Snowflake::parse) else {
        log::error!(
            "fluxer import job {}: missing or invalid source guild id",
            job.id
        );
        return Err(ImportAbort::Failed(generic_failure()));
    };
    let Some(code) = job.challenge_code.clone().filter(|code| !code.is_empty()) else {
        return Err(ImportAbort::Failed(VERIFICATION_FAILED.to_string()));
    };
    let Some(created) = job_created_at(&job.id) else {
        log::error!("fluxer import job {}: id is not a ULID", job.id);
        return Err(ImportAbort::Failed(generic_failure()));
    };
    // The day the stored code was minted for: the job's creation day or one
    // of the two before it. Anything else is not this user's Fluxer code.
    let Some(day) = code_day(secret, SOURCE_TAG, &job.user_id, &code, created.into()) else {
        return Err(ImportAbort::Failed(VERIFICATION_FAILED.to_string()));
    };
    let candidates = [(code, day)];

    // 1. What the proof needs.
    if !progress(db, job, ImportStage::Fetching, 0, 0).await {
        return Err(ImportAbort::Superseded);
    }
    let roles = api
        .fetch_roles(guild_id)
        .await
        .map_err(|error| fetch_failed(job, "roles", error))?;
    let bot_roles = api
        .fetch_bot_roles(guild_id)
        .await
        .map_err(|error| fetch_failed(job, "bot member", error))?;

    // Fluxer reads the audit log newest first and cannot page forward from
    // the code's day, so ONE page per action type is all there is. A full
    // page may have dropped the oldest entries (the ones that matter), so it
    // is refused, never taken as the whole history.
    let after = fluxer_audit_after_cursor(&candidates);
    let mut audit = Vec::new();
    for action_type in [FLUXER_AUDIT_ROLE_CREATE, FLUXER_AUDIT_ROLE_UPDATE] {
        let page = api
            .fetch_audit_page(guild_id, action_type, after)
            .await
            .map_err(|error| fetch_failed(job, "audit log", error))?;
        if page.is_full() {
            log::warn!(
                "fluxer import job {}: audit log page for action {action_type} is full; refusing",
                job.id
            );
            return Err(ImportAbort::Failed(AUDIT_INCOMPLETE.to_string()));
        }
        audit.extend(page.entries);
    }

    // 2. The role must still prove ownership, by the rule delta applied.
    if !progress(db, job, ImportStage::Verifying, 0, 0).await {
        return Err(ImportAbort::Superseded);
    }
    let proof_roles: Vec<ProofRole<'_>> = roles
        .iter()
        .map(|role| ProofRole {
            id: role.id.0,
            name: role.name.as_deref().unwrap_or(""),
            permissions: role.permissions.0,
        })
        .collect();
    let bot_role_ids: Vec<u64> = bot_roles.iter().map(|role| role.0).collect();
    let Some((_, challenge_role)) =
        fluxer_role_proof(&proof_roles, guild_id.0, &bot_role_ids, &audit, &candidates)
    else {
        return Err(ImportAbort::Failed(VERIFICATION_FAILED.to_string()));
    };

    // 3. The guild and its channels, only once verified.
    let guild = api
        .fetch_guild(guild_id)
        .await
        .map_err(|error| fetch_failed(job, "guild", error))?;
    let channels = api
        .fetch_channels(guild_id)
        .await
        .map_err(|error| fetch_failed(job, "channels", error))?;

    // 4. Rewrite, map and build.
    let adapted = adapter::adapt(
        &guild,
        &roles,
        &channels,
        &bot_roles,
        Snowflake(challenge_role),
    )
    .map_err(|error| ImportAbort::Failed(error.user_message_for(&job.kind)))?;
    let mut plan = plan_import_from(&adapted.template, SourceLabel::Fluxer).map_err(|error| {
        log::warn!("refusing fluxer guild for job {}: {error:?}", job.id);
        ImportAbort::Failed(error.user_message_for(&job.kind))
    })?;
    plan.nsfw = adapted.nsfw;
    plan.icon = adapted.icon;
    plan.banner = adapted.banner;
    plan.emojis = adapted.emojis;
    plan.skipped.extend(adapted.notes);

    let assets = FluxerAssets::new(
        &fluxer.cdn_url,
        guild_id,
        AssetLimits::from_upload_limits(&config.features.limits.default.file_upload_size_limit),
    );
    execute_plan(db, job, plan, &assets).await
}

/// Make the bot leave the job's Fluxer guild. Returns whether it is out
/// (see `FluxerApi::leave_guild`; a 429 is "not yet", for the leave retry).
///
/// Needs only the bot token and API URL, not `enabled`: a source switched
/// off still has bots to remove. Without a token nothing can be sent; the
/// row stays un-left, and the leave retry gives up loudly after its cap.
pub(crate) async fn leave(job: &DiscordImportJob, config: &Settings) -> bool {
    let Some(guild_id) = job.source_server_id.as_deref().and_then(Snowflake::parse) else {
        log::error!(
            "fluxer import job {}: no usable source guild id; the bot cannot leave it",
            job.id
        );
        return false;
    };

    let Some(api) = FluxerApi::new(&config.api.import.fluxer) else {
        // The leave retry calls this every sweep for days; say it once.
        if first_no_token_warning(&job.id) {
            log::warn!(
                "fluxer import job {}: no Fluxer bot token configured; the bot stays in \
                 {guild_id} until one is (the leave retry keeps trying, and logs again if it \
                 gives up)",
                job.id
            );
        }
        return false;
    };

    api.leave_guild(guild_id).await == source::LeaveOutcome::Left
}

/// Jobs the no-token leave warning has been logged for in this process.
static NO_TOKEN_WARNED: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Past this many ids the set starts over, so it stays bounded; each job
/// then warns once more at most.
const NO_TOKEN_WARNED_CAP: usize = 10_000;

/// Whether this is the first no-token leave for `job_id` (in this process).
fn first_no_token_warning(job_id: &str) -> bool {
    let mut warned = NO_TOKEN_WARNED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if warned.contains(job_id) {
        return false;
    }
    if warned.len() >= NO_TOKEN_WARNED_CAP {
        warned.clear();
    }
    warned.insert(job_id.to_string());
    true
}

/// A Fluxer guild as the fake upstream serves it, for this module's tests
/// and the worker's.
#[cfg(test)]
pub(crate) mod fixtures {
    use std::time::SystemTime;

    use revolt_database::util::import_challenge::{
        accepted_codes, code_day, fluxer_audit_after_cursor, FLUXER_EPOCH_MS,
    };
    use serde_json::{json, Value};

    use super::source::{audit_path, Snowflake};
    use super::SOURCE_TAG;
    use crate::tasks::import_http::fake_upstream::FakeUpstream;

    /// The challenge secret the fixtures' codes are minted under.
    pub(crate) const SECRET: &str = "secret";

    /// A guild created in 2024; its id is also `@everyone`'s.
    pub(crate) const GUILD: Snowflake = Snowflake(1_300_000_000_000_000_011);
    /// The role the bot's current install holds (Administrator).
    pub(crate) const BOT_ROLE: Snowflake = Snowflake(1_300_000_000_000_000_201);
    pub(crate) const MOD_ROLE: Snowflake = Snowflake(1_300_000_000_000_000_203);
    pub(crate) const OWNER: u64 = 1_300_000_000_000_000_001;
    pub(crate) const ADMIN: u64 = 1_300_000_000_000_000_002;
    pub(crate) const MODERATOR: u64 = 1_300_000_000_000_000_003;

    pub(crate) const ADMINISTRATOR: u64 = 1 << 3;
    pub(crate) const MANAGE_GUILD: u64 = 1 << 5;
    pub(crate) const VIEW: u64 = 1 << 10;
    pub(crate) const SEND: u64 = 1 << 11;
    /// What Fluxer gives a new role: nothing privileged.
    pub(crate) const NEW_ROLE_DEFAULTS: u64 = VIEW | SEND;

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// A snowflake minted now, with `low` in the worker/sequence bits.
    /// Everything minted by one fixture shares one millisecond and is
    /// ordered by `low`.
    fn minted(ms: u64, low: u64) -> u64 {
        ((ms - FLUXER_EPOCH_MS) << 22) | low
    }

    pub(crate) fn create_entry(id: u64, role: u64, user: u64, name: &str, bits: u64) -> Value {
        json!({
            "id": id.to_string(), "action_type": 30, "user_id": user.to_string(),
            "target_id": role.to_string(),
            "changes": [
                { "key": "role_id", "new_value": role.to_string() },
                { "key": "name", "new_value": name },
                { "key": "permissions", "new_value": bits.to_string() },
                { "key": "position", "new_value": 1 },
                { "key": "color", "new_value": 0 },
                { "key": "hoist", "new_value": false },
                { "key": "mentionable", "new_value": false }
            ]
        })
    }

    pub(crate) fn rename_entry(id: u64, role: u64, user: u64, from: &str, to: &str) -> Value {
        json!({
            "id": id.to_string(), "action_type": 31, "user_id": user.to_string(),
            "target_id": role.to_string(),
            "changes": [ { "key": "name", "old_value": from, "new_value": to } ]
        })
    }

    pub(crate) fn grant_entry(id: u64, role: u64, user: u64, old: u64, new: u64) -> Value {
        json!({
            "id": id.to_string(), "action_type": 31, "user_id": user.to_string(),
            "target_id": role.to_string(),
            "changes": [ {
                "key": "permissions", "old_value": old.to_string(), "new_value": new.to_string()
            } ]
        })
    }

    pub(crate) fn audit_page(entries: Vec<Value>) -> String {
        json!({ "audit_log_entries": entries, "users": [], "webhooks": [] }).to_string()
    }

    /// Everything the importer reads from one guild.
    pub(crate) struct Fixture {
        pub code: String,
        /// The role that carries the code.
        pub code_role: u64,
        /// The audit-log `after` cursor the importer will send.
        pub after: u64,
        pub guild: Value,
        pub roles: Value,
        pub channels: Value,
        pub bot_roles: Vec<Snowflake>,
        pub creates: Vec<Value>,
        pub updates: Vec<Value>,
    }

    impl Fixture {
        /// What Fluxer's web UI produces, made today by the owner: the bot
        /// installed (its role, Administrator), a role created as "new
        /// role", renamed to the code, then given Manage Server.
        pub(crate) fn ui_flow(user_id: &str) -> Fixture {
            let ms = now_ms();
            // `SystemTime` converts into the helpers' time type; crond has
            // no chrono dependency to name it with.
            let now = SystemTime::now();
            let code =
                accepted_codes(SECRET.as_bytes(), SOURCE_TAG, user_id, now.into())[0].clone();
            let day = code_day(SECRET.as_bytes(), SOURCE_TAG, user_id, &code, now.into())
                .expect("today's code");
            let after = fluxer_audit_after_cursor(&[(code.clone(), day)]);

            let code_role = minted(ms, 1);
            let roles = json!([
                { "id": MOD_ROLE.to_string(), "name": "Mod", "permissions": "8192",
                  "position": 3, "color": 1752220, "hoist": true },
                { "id": code_role.to_string(), "name": code,
                  "permissions": (NEW_ROLE_DEFAULTS | MANAGE_GUILD).to_string(), "position": 2 },
                { "id": BOT_ROLE.to_string(), "name": "Sloga Importer",
                  "permissions": ADMINISTRATOR.to_string(), "position": 1 },
                { "id": GUILD.to_string(), "name": "@everyone",
                  "permissions": (VIEW | SEND | (1u64 << 54)).to_string(), "position": 0 }
            ]);

            Fixture {
                creates: vec![create_entry(
                    minted(ms, 10),
                    code_role,
                    OWNER,
                    "new role",
                    NEW_ROLE_DEFAULTS,
                )],
                updates: vec![
                    // Newest first, as Fluxer returns them.
                    grant_entry(
                        minted(ms, 12),
                        code_role,
                        OWNER,
                        NEW_ROLE_DEFAULTS,
                        NEW_ROLE_DEFAULTS | MANAGE_GUILD,
                    ),
                    rename_entry(minted(ms, 11), code_role, OWNER, "new role", &code),
                ],
                code,
                code_role,
                after,
                guild: json!({
                    "id": GUILD.to_string(), "name": "Flux Place", "nsfw": false,
                    "icon": null, "banner": null, "emojis": [],
                    "afk_timeout": 300, "system_channel_id": null
                }),
                roles,
                channels: json!([
                    { "id": "1300000000000000301", "type": 0, "name": "general", "position": 0,
                      "permission_overwrites": [] }
                ]),
                bot_roles: vec![BOT_ROLE],
            }
        }

        /// Script every read the importer makes, plus a 204 leave.
        pub(crate) fn script(&self, fake: FakeUpstream) -> FakeUpstream {
            fake.reply(
                "GET",
                &format!("/v1/guilds/{GUILD}"),
                200,
                self.guild.to_string(),
            )
            .reply(
                "GET",
                &format!("/v1/guilds/{GUILD}/roles"),
                200,
                self.roles.to_string(),
            )
            .reply(
                "GET",
                &format!("/v1/guilds/{GUILD}/channels"),
                200,
                self.channels.to_string(),
            )
            .reply(
                "GET",
                &format!("/v1/guilds/{GUILD}/members/@me"),
                200,
                json!({
                    "user": { "id": "1300000000000000999" },
                    "roles": self.bot_roles.iter().map(|r| r.to_string()).collect::<Vec<_>>()
                })
                .to_string(),
            )
            .reply(
                "GET",
                &audit_path(GUILD, 30, self.after),
                200,
                audit_page(self.creates.clone()),
            )
            .reply(
                "GET",
                &audit_path(GUILD, 31, self.after),
                200,
                audit_page(self.updates.clone()),
            )
            .reply("DELETE", &leave_path(), 204, "")
        }

        /// A snowflake minted in the same millisecond as this fixture's
        /// roles, after them.
        pub(crate) fn later(&self, low: u64) -> u64 {
            let ms = (self.code_role >> 22) + FLUXER_EPOCH_MS;
            minted(ms, low)
        }
    }

    pub(crate) fn leave_path() -> String {
        format!("/v1/users/@me/guilds/{GUILD}")
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::source::fake_upstream::FakeUpstream;
    use super::*;
    use revolt_config::config;
    use revolt_database::{DatabaseInfo, ImportJobKind, ImportStatus, User};
    use serde_json::json;

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

    async fn settings(api: &FakeUpstream) -> Settings {
        let mut config = config().await;
        config.api.import.challenge_secret = SECRET.to_string();
        config.api.import.fluxer = api.fluxer_config(api);
        config
    }

    /// A running job, as the claim loop hands it over.
    async fn running_job(db: &Database, owner: &User, code: &str) -> DiscordImportJob {
        let mut job = DiscordImportJob::new_source(
            owner.id.clone(),
            ImportJobKind::FluxerServer,
            "https://fluxer.gg/AbC123".to_string(),
            Some(GUILD.to_string()),
            Some(code.to_string()),
        );
        job.status = ImportStatus::Running;
        db.insert_discord_import_job(&job).await.unwrap();
        job
    }

    /// Run the job; its failure message, or `None` if it did not fail.
    async fn failure(
        db: &Database,
        job: &mut DiscordImportJob,
        config: &Settings,
    ) -> Option<String> {
        match run(db, job, config).await {
            Err(ImportAbort::Failed(message)) => Some(message),
            Err(ImportAbort::Superseded) => panic!("superseded"),
            Ok(()) => None,
        }
    }

    fn paths(fake: &FakeUpstream) -> Vec<String> {
        fake.seen().into_iter().map(|seen| seen.path).collect()
    }

    #[test]
    fn job_creation_time_comes_from_its_ulid() {
        let id = ulid::Ulid::new();
        let created = job_created_at(&id.to_string()).unwrap();
        assert_eq!(
            created.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            id.timestamp_ms()
        );
        assert_eq!(job_created_at("not-a-ulid"), None);
    }

    /// The flow Fluxer's web UI produces passes re-verification, and the
    /// guild and channels are read only after it.
    #[tokio::test]
    async fn the_real_ui_flow_passes_reverification() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;
        let fixture = Fixture::ui_flow(&owner.id);
        // The guild read fails on purpose: reaching it means the proof
        // passed, and nothing is built.
        let api = FakeUpstream::new();
        let api = fixture
            .script(api)
            .reply("GET", &format!("/v1/guilds/{GUILD}"), 503, "{}")
            .start()
            .await;
        let config = settings(&api).await;
        let mut job = running_job(&db, &owner, &fixture.code).await;

        assert_eq!(
            failure(&db, &mut job, &config).await,
            Some(FluxerError::Unavailable.user_message())
        );
        assert_eq!(
            paths(&api),
            vec![
                format!("/v1/guilds/{GUILD}/roles"),
                format!("/v1/guilds/{GUILD}/members/@me"),
                source::audit_path(GUILD, 30, fixture.after),
                source::audit_path(GUILD, 31, fixture.after),
                format!("/v1/guilds/{GUILD}"),
            ]
        );
        assert_eq!(job.server_id, None);
    }

    /// An orphaned install role from an earlier add of the bot (Administrator
    /// from its creation, no longer held by the bot) renamed to the code by
    /// a moderator: refused, and the guild is never read.
    #[tokio::test]
    async fn a_renamed_bot_install_role_fails() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;
        let mut fixture = Fixture::ui_flow(&owner.id);
        let orphan = fixture.later(2);
        // Only the orphan carries the code now.
        fixture.roles = json!([
            { "id": orphan.to_string(), "name": fixture.code,
              "permissions": ADMINISTRATOR.to_string(), "position": 2 },
            { "id": BOT_ROLE.to_string(), "name": "Sloga Importer",
              "permissions": ADMINISTRATOR.to_string(), "position": 1 },
            { "id": GUILD.to_string(), "name": "@everyone", "permissions": "0", "position": 0 }
        ]);
        fixture.creates = vec![create_entry(
            fixture.later(20),
            orphan,
            ADMIN,
            "Sloga Importer",
            ADMINISTRATOR,
        )];
        fixture.updates = vec![rename_entry(
            fixture.later(21),
            orphan,
            MODERATOR,
            "Sloga Importer",
            &fixture.code,
        )];
        let api = fixture.script(FakeUpstream::new()).start().await;
        let config = settings(&api).await;
        let mut job = running_job(&db, &owner, &fixture.code).await;

        assert_eq!(
            failure(&db, &mut job, &config).await.as_deref(),
            Some(VERIFICATION_FAILED)
        );
        assert!(!paths(&api).contains(&format!("/v1/guilds/{GUILD}")));
        assert!(!paths(&api).contains(&format!("/v1/guilds/{GUILD}/channels")));
    }

    /// The code role is the bot's own: refused.
    #[tokio::test]
    async fn a_bot_held_code_role_fails() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;
        let mut fixture = Fixture::ui_flow(&owner.id);
        fixture.bot_roles.push(Snowflake(fixture.code_role));
        let api = fixture.script(FakeUpstream::new()).start().await;
        let config = settings(&api).await;
        let mut job = running_job(&db, &owner, &fixture.code).await;

        assert_eq!(
            failure(&db, &mut job, &config).await.as_deref(),
            Some(VERIFICATION_FAILED)
        );
    }

    /// A full page may have dropped the oldest entries: fail closed,
    /// whichever action type it is.
    #[tokio::test]
    async fn a_full_audit_page_fails_closed() {
        for full_type in [30u8, 31] {
            let db = DatabaseInfo::Reference.connect().await.unwrap();
            let owner = make_owner(&db).await;
            let mut fixture = Fixture::ui_flow(&owner.id);
            let filler: Vec<_> = (0..100u64)
                .map(|i| {
                    let role = fixture.later(1000 + i);
                    if full_type == 30 {
                        create_entry(fixture.later(2000 + i), role, OWNER, "x", 0)
                    } else {
                        rename_entry(fixture.later(2000 + i), role, OWNER, "x", "y")
                    }
                })
                .collect();
            if full_type == 30 {
                fixture.creates.extend(filler);
            } else {
                fixture.updates.extend(filler);
            }
            let api = fixture.script(FakeUpstream::new()).start().await;
            let config = settings(&api).await;
            let mut job = running_job(&db, &owner, &fixture.code).await;

            assert_eq!(
                failure(&db, &mut job, &config).await.as_deref(),
                Some(AUDIT_INCOMPLETE),
                "{full_type}"
            );
            assert!(!paths(&api).contains(&format!("/v1/guilds/{GUILD}")));
        }
    }

    #[tokio::test]
    async fn an_unreadable_or_forbidden_audit_log_fails() {
        for (status, body, expected) in [
            (
                403,
                "{}".to_string(),
                FluxerError::AuditLogForbidden.user_message(),
            ),
            (200, "[]".to_string(), FluxerError::Malformed.user_message()),
            (
                200,
                // A ROLE_UPDATE whose permissions cannot be read.
                audit_page(vec![json!({
                    "id": "5", "action_type": 31, "target_id": "6",
                    "changes": [ { "key": "permissions", "old_value": "x", "new_value": "8" } ]
                })]),
                FluxerError::Malformed.user_message(),
            ),
        ] {
            let db = DatabaseInfo::Reference.connect().await.unwrap();
            let owner = make_owner(&db).await;
            let fixture = Fixture::ui_flow(&owner.id);
            let api = fixture
                .script(FakeUpstream::new())
                .reply(
                    "GET",
                    &source::audit_path(GUILD, 31, fixture.after),
                    status,
                    body,
                )
                .start()
                .await;
            let config = settings(&api).await;
            let mut job = running_job(&db, &owner, &fixture.code).await;

            assert_eq!(
                failure(&db, &mut job, &config).await,
                Some(expected),
                "{status}"
            );
            assert!(!paths(&api).contains(&format!("/v1/guilds/{GUILD}")));
        }
    }

    #[tokio::test]
    async fn bot_not_in_guild_and_rate_limits_fail_like_stoat() {
        for (status, expected) in [
            (404, FluxerError::BotNotInServer),
            (403, FluxerError::BotNotInServer),
            (401, FluxerError::BotNotInServer),
            (429, FluxerError::Unavailable),
            (502, FluxerError::Unavailable),
        ] {
            let db = DatabaseInfo::Reference.connect().await.unwrap();
            let owner = make_owner(&db).await;
            let fixture = Fixture::ui_flow(&owner.id);
            let api = fixture
                .script(FakeUpstream::new())
                .reply("GET", &format!("/v1/guilds/{GUILD}/roles"), status, "{}")
                .start()
                .await;
            let config = settings(&api).await;
            let mut job = running_job(&db, &owner, &fixture.code).await;

            assert_eq!(
                failure(&db, &mut job, &config).await,
                Some(expected.user_message()),
                "{status}"
            );
            // One request, no retry.
            assert_eq!(api.seen().len(), 1, "{status}");
        }
    }

    /// A code that is not this user's Fluxer code for the job's day (another
    /// user's, another source's, none) fails before anything is sent.
    #[tokio::test]
    async fn a_code_that_is_not_this_jobs_fails_without_a_request() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;
        let other = Fixture::ui_flow("01OTHERUSER000000000000000");
        let stoat = revolt_database::util::import_challenge::accepted_codes(
            SECRET.as_bytes(),
            "stoat",
            &owner.id,
            SystemTime::now().into(),
        )[0]
        .clone();
        let api = FakeUpstream::new().start().await;
        let config = settings(&api).await;

        for code in [other.code.as_str(), stoat.as_str(), ""] {
            let mut job = running_job(&db, &owner, code).await;
            assert_eq!(
                failure(&db, &mut job, &config).await.as_deref(),
                Some(VERIFICATION_FAILED),
                "{code:?}"
            );
            let mut done = job.clone();
            done.status = ImportStatus::Failed;
            db.save_discord_import_job(&done).await.unwrap();
        }
        assert!(api.seen().is_empty(), "{:?}", api.seen());
    }

    /// `@everyone` missing from the role list: refused before anything is
    /// built.
    #[tokio::test]
    async fn a_guild_without_everyone_fails_closed() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let owner = make_owner(&db).await;
        let mut fixture = Fixture::ui_flow(&owner.id);
        fixture.roles.as_array_mut().unwrap().pop();
        let api = fixture.script(FakeUpstream::new()).start().await;
        let config = settings(&api).await;
        let mut job = running_job(&db, &owner, &fixture.code).await;

        assert_eq!(
            failure(&db, &mut job, &config).await,
            Some(
                crate::tasks::discord_import::mapper::PlanError::UnexpectedRoleOrder
                    .user_message_for(&ImportJobKind::FluxerServer)
            )
        );
        assert_eq!(job.server_id, None);
    }

    /// The leave needs the token, not `enabled`, and a 404 counts as left.
    #[tokio::test]
    async fn leave_needs_the_token_and_treats_404_as_left() {
        let api = FakeUpstream::new()
            .reply("DELETE", &leave_path(), 404, r#"{"code":"UNKNOWN_MEMBER"}"#)
            .start()
            .await;
        let mut config = settings(&api).await;
        config.api.import.fluxer.enabled = false;
        let mut job = DiscordImportJob::new_source(
            "01USERA000000000000000000F".to_string(),
            ImportJobKind::FluxerServer,
            "x".to_string(),
            Some(GUILD.to_string()),
            None,
        );

        assert!(leave(&job, &config).await);
        let seen = api.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "DELETE");
        assert_eq!(seen[0].body, b"{}");

        config.api.import.fluxer.bot_token = String::new();
        assert!(!leave(&job, &config).await);
        job.source_server_id = Some("../x".to_string());
        config.api.import.fluxer = api.fluxer_config(&api);
        assert!(!leave(&job, &config).await);
        assert_eq!(api.seen().len(), 1, "nothing more was sent");
    }

    #[test]
    fn the_no_token_warning_is_once_per_job() {
        let job = "01WARNONCEFLUXER0000000001";
        assert!(first_no_token_warning(job));
        assert!(!first_no_token_warning(job));
        assert!(first_no_token_warning("01WARNONCEFLUXER0000000002"));
    }
}
