//! Fluxer as an import source: turn what the user pasted into something safe
//! to put in an outbound URL, and verify ownership against the live Fluxer
//! API before a job is queued.
//!
//! The proof is a role, not a description: the user creates a new role named
//! exactly their challenge code and gives it Manage Server (or
//! Administrator). A role name alone proves nothing on Fluxer, so the guild
//! audit log is read as well and the shared helper
//! (`import_challenge::fluxer_role_proof`) decides; crond re-checks the same
//! way before the import runs.
//!
//! Verification is at most five upstream calls: resolve the invite (public,
//! no token), then as the operator bot (`Authorization: Bot <token>`) the
//! guild's roles, the bot's own member (its roles are excluded from the
//! proof), and one audit-log page each for ROLE_CREATE and ROLE_UPDATE. Each
//! call first spends from Fluxer's outbound budgets (`upstream_throttle`).
//!
//! Fluxer reads audit pages newest first and cannot page forward from the
//! code's day, so a full page means part of the window was not seen and the
//! verification fails closed.
//!
//! Failures are logged at `warn` by call, status code and error kind only:
//! never the URL (it carries what the user pasted), the token or a body.

use chrono::{DateTime, Utc};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use reqwest::StatusCode;
use revolt_config::ApiImportBotSource;
use revolt_database::util::import_challenge::{
    accepted_codes_with_days, fluxer_audit_after_cursor, fluxer_role_proof,
    parse_fluxer_role_audit_page, ProofRole, RoleAuditEvent, FLUXER_AUDIT_PAGE_LIMIT,
    FLUXER_AUDIT_ROLE_CREATE, FLUXER_AUDIT_ROLE_UPDATE,
};
use revolt_result::{create_error, Result};
use serde::Deserialize;
use serde_json::Value;

use super::upstream_http::{build_client, error_kind, read_json, Transport};
use super::upstream_throttle::{UpstreamTarget, UpstreamThrottle};

/// Challenge source tag for Fluxer. A code minted for another source never
/// verifies here.
pub const SOURCE_TAG: &str = "fluxer";

/// Invite code length bounds. Everything that reaches an outbound URL is
/// `[A-Za-z0-9-]{CODE_MIN,CODE_MAX}` or a decimal guild id.
const CODE_MIN: usize = 2;
const CODE_MAX: usize = 32;

/// A guild id pasted bare: a snowflake of 17 to 20 digits
const GUILD_ID_MIN: usize = 17;
const GUILD_ID_MAX: usize = 20;

/// A snowflake as Fluxer returns it: 1 to 20 decimal digits
const SNOWFLAKE_MAX: usize = 20;

/// What the user pasted, reduced to one whitelisted token
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FluxerSource {
    /// An invite code, resolved to its guild with one public call
    Invite(String),
    /// A guild id, used directly
    GuildId(u64),
}

/// Parse a Fluxer invite link, bare invite code, or guild id.
///
/// An `http://` or `https://` link on any host names an invite: its last
/// non-empty path segment is the code (Fluxer's web hosts are moving, so the
/// host is not checked; it is never contacted). The whole link may only use
/// host and path characters: a query, fragment, `%` escape, whitespace, or a
/// `.` / `..` path segment refuses it outright rather than reducing it to a
/// segment.
///
/// A bare value of 17 to 20 digits is a guild id; any other bare
/// `[A-Za-z0-9-]{2,32}` that is not all digits is an invite code. Surrounding
/// whitespace is ignored. Anything else is refused: the result goes straight
/// into an outbound URL.
pub fn parse_fluxer_source(input: &str) -> Option<FluxerSource> {
    let trimmed = input.trim();

    if let Some(rest) = strip_prefix_ignore_case(trimmed, "https://")
        .or_else(|| strip_prefix_ignore_case(trimmed, "http://"))
    {
        return invite_from_link(rest).map(FluxerSource::Invite);
    }

    if is_invite_code(trimmed) && !is_all_digits(trimmed) {
        return Some(FluxerSource::Invite(trimmed.to_string()));
    }

    if (GUILD_ID_MIN..=GUILD_ID_MAX).contains(&trimmed.len()) && is_all_digits(trimmed) {
        // 20 digits can overflow a snowflake; that is not a guild id
        return trimmed.parse().ok().map(FluxerSource::GuildId);
    }

    None
}

fn strip_prefix_ignore_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

/// The invite code in a link with its scheme dropped: `host/…/<code>[/]`
fn invite_from_link(rest: &str) -> Option<String> {
    let allowed = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b':' | b'/');
    if !rest.bytes().all(allowed) {
        return None;
    }

    let (host, path) = rest.split_once('/')?;
    if host.is_empty() {
        return None;
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return None;
    }

    let code = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .last()?;
    is_invite_code(code).then(|| code.to_string())
}

/// The whole outbound-URL safety property for an invite code: one path
/// segment of ASCII alphanumerics and `-`, nothing that can add a segment,
/// host, query or escape
fn is_invite_code(token: &str) -> bool {
    (CODE_MIN..=CODE_MAX).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn is_all_digits(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| b.is_ascii_digit())
}

/// A snowflake as Fluxer writes it, a string of 1 to 20 decimal digits
fn snowflake(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    if text.len() > SNOWFLAKE_MAX || !is_all_digits(text) {
        return None;
    }
    text.parse().ok()
}

/// Permission bits: a decimal string (what Fluxer sends) or a plain integer
fn permission_bits(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| snowflake(value))
}

/// `GET /v1/invites/<code>`, read permissively: only the type and guild id
#[derive(Deserialize)]
struct InviteProbe {
    #[serde(rename = "type", default)]
    kind: Option<Value>,
    #[serde(default)]
    guild: Option<InviteGuild>,
}

#[derive(Deserialize)]
struct InviteGuild {
    #[serde(default)]
    id: Option<Value>,
}

/// A guild role, as the proof needs it
#[derive(Debug, Clone, PartialEq, Eq)]
struct FluxerRole {
    id: u64,
    name: String,
    permissions: u64,
}

/// The source after verification: what the job is created with
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFluxerSource {
    /// The guild id, in canonical decimal form
    pub guild_id: String,
    /// The accepted code the proving role carries (today's or yesterday's)
    pub challenge_code: String,
}

/// Minimal Fluxer API client for verification.
///
/// The base URL comes only from operator config; every path is `/v1/…`.
/// Redirects are never followed (the client carries the bot token), and
/// every failure maps to a fixed error before it can carry request detail.
/// No `Debug`: the token must not reach a log line.
pub struct FluxerApi {
    client: reqwest::Client,
    api_url: String,
    bot_token: String,
}

impl FluxerApi {
    /// Client for `config` (`[api.import.fluxer]`) over `transport`. Under
    /// `Production` an `http://` `api_url` is refused at request time too.
    pub fn connect(config: &ApiImportBotSource, transport: Transport) -> Result<FluxerApi> {
        let client = build_client(transport, SOURCE_TAG)?;

        Ok(FluxerApi {
            client,
            api_url: config.api_url.trim_end_matches('/').to_string(),
            bot_token: config.bot_token.clone(),
        })
    }

    fn transport_error(call: &str, error: &reqwest::Error) -> revolt_result::Error {
        log::warn!("fluxer import: {call} failed ({})", error_kind(error));
        create_error!(ImportUpstreamUnavailable)
    }

    /// Resolve an invite to its guild id. Public route, sent without the
    /// bot token.
    async fn resolve_invite(&self, code: &str) -> Result<u64> {
        const CALL: &str = "invite lookup";
        let response = self
            .client
            .get(format!("{}/v1/invites/{code}", self.api_url))
            .send()
            .await
            .map_err(|error| Self::transport_error(CALL, &error))?;

        match response.status() {
            status if status.is_success() => {}
            StatusCode::NOT_FOUND => return Err(create_error!(ImportSourceNotFound)),
            status => {
                log::warn!("fluxer import: {CALL} answered {}", status.as_u16());
                return Err(create_error!(ImportUpstreamUnavailable));
            }
        }

        let invite: InviteProbe = read_json(response, SOURCE_TAG, CALL).await?;

        // Only a guild invite (type 0) names a guild; a group DM invite does not
        if invite.kind.as_ref().and_then(Value::as_u64) != Some(0) {
            return Err(create_error!(ImportSourceNotFound));
        }

        // The id goes into the next URLs, so it gets the same whitelist as
        // user input even though it came from the configured upstream
        match invite.guild.and_then(|guild| guild.id) {
            None | Some(Value::Null) => Err(create_error!(ImportSourceNotFound)),
            Some(id) => snowflake(&id).ok_or_else(|| {
                log::warn!("fluxer import: {CALL} returned an unusable guild id");
                create_error!(ImportUpstreamUnavailable)
            }),
        }
    }

    /// `GET` `path` (under the API base) as the operator bot
    async fn bot_get(&self, call: &str, path: &str) -> Result<reqwest::Response> {
        let mut token =
            HeaderValue::from_str(&format!("Bot {}", self.bot_token)).map_err(|_| {
                log::warn!("fluxer import: the configured bot token is not a valid header value");
                create_error!(ImportUpstreamUnavailable)
            })?;
        token.set_sensitive(true);

        self.client
            .get(format!("{}{path}", self.api_url))
            .header(AUTHORIZATION, token)
            .send()
            .await
            .map_err(|error| Self::transport_error(call, &error))
    }

    /// Refuse anything but a success on a bot call that only a member can
    /// make: 401, 403 and 404 mean the bot cannot see the guild (Fluxer does
    /// not let a non-member tell them apart, and neither do we). A 401 can
    /// also mean the operator's token was revoked, which would otherwise
    /// fail every import quietly, so it is logged.
    fn member_call_status(call: &str, status: StatusCode) -> Result<()> {
        match status {
            status if status.is_success() => Ok(()),
            StatusCode::UNAUTHORIZED => {
                log::warn!("fluxer import: {call} answered 401; check the bot token");
                Err(create_error!(ImportBotNotInServer))
            }
            StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => {
                Err(create_error!(ImportBotNotInServer))
            }
            status => {
                log::warn!("fluxer import: {call} answered {}", status.as_u16());
                Err(create_error!(ImportUpstreamUnavailable))
            }
        }
    }

    /// The guild's roles. Any role that does not parse fails the call.
    async fn fetch_roles(&self, guild_id: u64) -> Result<Vec<FluxerRole>> {
        const CALL: &str = "role list";
        let response = self
            .bot_get(CALL, &format!("/v1/guilds/{guild_id}/roles"))
            .await?;
        Self::member_call_status(CALL, response.status())?;

        let body: Value = read_json(response, SOURCE_TAG, CALL).await?;
        let roles = body.as_array().map(|roles| {
            roles
                .iter()
                .map(|role| {
                    Some(FluxerRole {
                        id: role.get("id").and_then(snowflake)?,
                        name: role.get("name")?.as_str()?.to_string(),
                        permissions: role.get("permissions").and_then(permission_bits)?,
                    })
                })
                .collect::<Option<Vec<_>>>()
        });

        roles.flatten().ok_or_else(|| {
            log::warn!("fluxer import: {CALL} returned a role it could not read");
            create_error!(ImportUpstreamUnavailable)
        })
    }

    /// The ids of the roles the bot itself holds in the guild
    async fn fetch_bot_role_ids(&self, guild_id: u64) -> Result<Vec<u64>> {
        const CALL: &str = "own member";
        let response = self
            .bot_get(CALL, &format!("/v1/guilds/{guild_id}/members/@me"))
            .await?;
        Self::member_call_status(CALL, response.status())?;

        let body: Value = read_json(response, SOURCE_TAG, CALL).await?;
        body.get("roles")
            .and_then(Value::as_array)
            .and_then(|roles| roles.iter().map(snowflake).collect::<Option<Vec<_>>>())
            .ok_or_else(|| {
                log::warn!("fluxer import: {CALL} returned roles it could not read");
                create_error!(ImportUpstreamUnavailable)
            })
    }

    /// One page of role audit entries of `action_type`, newer than `after`.
    ///
    /// A 403 means the bot cannot view the audit log, i.e. it was not
    /// installed with Administrator: without the log nothing can be proven,
    /// so it is `ImportVerificationMissing`. A page that is full or does not
    /// parse is refused the same way.
    async fn fetch_role_audit(
        &self,
        guild_id: u64,
        action_type: u8,
        after: u64,
    ) -> Result<Vec<RoleAuditEvent>> {
        const CALL: &str = "audit log";
        let response = self
            .bot_get(
                CALL,
                &format!(
                    "/v1/guilds/{guild_id}/audit-logs?action_type={action_type}&after={after}&limit={FLUXER_AUDIT_PAGE_LIMIT}"
                ),
            )
            .await?;

        match response.status() {
            StatusCode::FORBIDDEN => {
                log::info!("fluxer import: {CALL} answered 403; the bot cannot view it");
                return Err(create_error!(ImportVerificationMissing));
            }
            status => Self::member_call_status(CALL, status)?,
        }

        let body: Value = read_json(response, SOURCE_TAG, CALL).await?;
        let page = parse_fluxer_role_audit_page(&body, action_type).map_err(|_| {
            log::warn!("fluxer import: {CALL} page could not be read; refused");
            create_error!(ImportVerificationMissing)
        })?;

        // Newest first: a full page has dropped the oldest entries of the
        // window, and they cannot be fetched by paging forward
        if page.is_full() {
            log::info!("fluxer import: {CALL} page is full; refused");
            return Err(create_error!(ImportVerificationMissing));
        }

        Ok(page.entries)
    }
}

/// Resolve `source` and check the guild has a role proving `user_id` manages
/// it: named exactly one of their accepted Fluxer codes (today's or
/// yesterday's, UTC), holding Manage Server or Administrator, and created and
/// privileged in a way the audit log shows (`fluxer_role_proof`).
///
/// Errors: `ImportSourceNotFound` (unknown or group DM invite, an invite
/// with no guild), `ImportBotNotInServer` (the bot cannot see the guild),
/// `ImportVerificationMissing` (no proving role, or the audit log cannot be
/// read in full), `ImportUpstreamUnavailable` (`throttle` refused a call,
/// 429, 5xx, timeout, transport, redirect, an oversize or malformed
/// response).
///
/// Every upstream call is preceded by a `throttle` check; a refused check
/// makes no call. The caller must have finished every local refusal first.
pub async fn verify_fluxer_source(
    api: &FluxerApi,
    throttle: &UpstreamThrottle,
    source: &FluxerSource,
    challenge_secret: &[u8],
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<VerifiedFluxerSource> {
    let guild_id = match source {
        FluxerSource::Invite(code) => {
            throttle
                .begin_verification(user_id, UpstreamTarget::Invite(code), now)
                .await?;
            let guild_id = api.resolve_invite(code).await?;
            throttle
                .next_call(UpstreamTarget::Server(&guild_id.to_string()), now)
                .await?;
            guild_id
        }
        FluxerSource::GuildId(id) => {
            throttle
                .begin_verification(user_id, UpstreamTarget::Server(&id.to_string()), now)
                .await?;
            *id
        }
    };
    let target = guild_id.to_string();

    let roles = api.fetch_roles(guild_id).await?;

    throttle
        .next_call(UpstreamTarget::Server(&target), now)
        .await?;
    let bot_role_ids = api.fetch_bot_role_ids(guild_id).await?;

    let candidates = accepted_codes_with_days(challenge_secret, SOURCE_TAG, user_id, now);

    // No role carries an accepted code: nothing in the audit log could
    // change that, so it is not read
    if !roles
        .iter()
        .any(|role| candidates.iter().any(|(code, _)| role.name == *code))
    {
        return Err(create_error!(ImportVerificationMissing));
    }

    let after = fluxer_audit_after_cursor(&candidates);
    let mut audit = Vec::new();
    for action_type in [FLUXER_AUDIT_ROLE_CREATE, FLUXER_AUDIT_ROLE_UPDATE] {
        throttle
            .next_call(UpstreamTarget::Server(&target), now)
            .await?;
        audit.extend(api.fetch_role_audit(guild_id, action_type, after).await?);
    }

    let proof_roles: Vec<ProofRole<'_>> = roles
        .iter()
        .map(|role| ProofRole {
            id: role.id,
            name: &role.name,
            permissions: role.permissions,
        })
        .collect();

    let (challenge_code, _) =
        fluxer_role_proof(&proof_roles, guild_id, &bot_role_ids, &audit, &candidates)
            .ok_or_else(|| create_error!(ImportVerificationMissing))?;

    Ok(VerifiedFluxerSource {
        guild_id: target,
        challenge_code,
    })
}

/// Fixtures shared by the Fluxer tests here and the route tests
#[cfg(test)]
pub(super) mod fixtures {
    use chrono::{DateTime, Utc};
    use revolt_config::ApiImportBotSource;
    use revolt_database::util::import_challenge::{
        accepted_codes_with_days, fluxer_audit_after_cursor, ADMINISTRATOR, FLUXER_EPOCH_MS,
        MANAGE_GUILD,
    };
    use serde_json::Value;

    use super::super::fake_upstream::FakeUpstream;
    use super::SOURCE_TAG;

    pub use super::super::fake_upstream::BOT_TOKEN;

    pub const INVITE: &str = "fluxer-Ab12";
    /// The guild (created long before any code)
    pub const GUILD: u64 = 1_200_000_000_000_000_001;
    /// The bot's current install role, and its user
    pub const BOT_ROLE: u64 = 1_300_000_000_000_000_002;
    pub const BOT_USER: u64 = 1_560_481_642_991_071_233;
    /// Fluxer users: the importer, a bot installer, a Manage-Roles moderator
    pub const IMPORTER: u64 = 1_400_000_000_000_000_011;
    pub const INSTALLER: u64 = 1_400_000_000_000_000_012;
    pub const MODERATOR: u64 = 1_400_000_000_000_000_013;

    /// `[api.import.fluxer]` ready and pointing at `fake`
    pub fn fluxer_config(fake: &FakeUpstream) -> ApiImportBotSource {
        ApiImportBotSource {
            enabled: true,
            api_url: fake.api_url.clone(),
            app_url: "https://fluxer.example".to_string(),
            cdn_url: "https://cdn.fluxer.example".to_string(),
            bot_id: BOT_USER.to_string(),
            bot_token: BOT_TOKEN.to_string(),
            reconcile_after_hours: 24,
        }
    }

    /// A snowflake minted at `time`, `low` in the low bits
    pub fn snowflake_at(time: DateTime<Utc>, low: u64) -> u64 {
        let ms = time.timestamp_millis() as u64 - FLUXER_EPOCH_MS;
        (ms << 22) | low
    }

    pub fn role(id: u64, name: &str, permissions: u64) -> Value {
        json!({
            "id": id.to_string(),
            "name": name,
            "color": 0,
            "position": 1,
            "permissions": permissions.to_string(),
            "hoist": false,
            "mentionable": false,
        })
    }

    pub fn everyone() -> Value {
        role(GUILD, "@everyone", 0x6_4000_0c41)
    }

    pub fn install_role() -> Value {
        role(BOT_ROLE, "Sloga Importer", ADMINISTRATOR)
    }

    /// A ROLE_CREATE entry as Fluxer writes it
    pub fn create_entry(id: u64, role_id: u64, user: u64, name: &str, bits: u64) -> Value {
        json!({
            "id": id.to_string(),
            "action_type": 30,
            "user_id": user.to_string(),
            "target_id": role_id.to_string(),
            "changes": [
                { "key": "role_id", "new_value": role_id.to_string() },
                { "key": "name", "new_value": name },
                { "key": "permissions", "new_value": bits.to_string() },
                { "key": "position", "new_value": 1 },
                { "key": "color", "new_value": 0 },
                { "key": "hoist", "new_value": false },
                { "key": "mentionable", "new_value": false },
            ],
        })
    }

    /// A ROLE_UPDATE entry renaming the role
    pub fn rename_entry(id: u64, role_id: u64, user: u64, old: &str, new: &str) -> Value {
        json!({
            "id": id.to_string(),
            "action_type": 31,
            "user_id": user.to_string(),
            "target_id": role_id.to_string(),
            "changes": [{ "key": "name", "old_value": old, "new_value": new }],
        })
    }

    /// A ROLE_UPDATE entry changing the role's permissions
    pub fn grant_entry(id: u64, role_id: u64, user: u64, old: u64, new: u64) -> Value {
        json!({
            "id": id.to_string(),
            "action_type": 31,
            "user_id": user.to_string(),
            "target_id": role_id.to_string(),
            "changes": [{
                "key": "permissions",
                "old_value": old.to_string(),
                "new_value": new.to_string(),
            }],
        })
    }

    pub fn audit_page(entries: Vec<Value>) -> Value {
        json!({ "audit_log_entries": entries, "users": [], "webhooks": [] })
    }

    /// The `after` cursor a verification at `now` sends
    pub fn audit_after(now: DateTime<Utc>) -> u64 {
        // The cursor depends only on the candidate days, not the key or user
        fluxer_audit_after_cursor(&accepted_codes_with_days(b"any", SOURCE_TAG, "any", now))
    }

    pub fn audit_path(action_type: u8, now: DateTime<Utc>) -> String {
        format!(
            "/v1/guilds/{GUILD}/audit-logs?action_type={action_type}&after={}&limit=100",
            audit_after(now)
        )
    }

    pub fn invite_path() -> String {
        format!("/v1/invites/{INVITE}")
    }

    pub fn roles_path() -> String {
        format!("/v1/guilds/{GUILD}/roles")
    }

    pub fn member_path() -> String {
        format!("/v1/guilds/{GUILD}/members/@me")
    }

    pub fn guild_invite() -> Value {
        json!({
            "code": INVITE,
            "type": 0,
            "guild": { "id": GUILD.to_string(), "name": "G", "features": [] },
            "channel": { "id": "1300000000000000099", "name": "general", "type": 0 },
            "member_count": 3,
            "presence_count": 1,
            "temporary": false,
        })
    }

    /// What the scripted guild holds
    pub struct Guild {
        pub roles: Vec<Value>,
        pub bot_roles: Vec<u64>,
        pub creates: Vec<Value>,
        pub updates: Vec<Value>,
    }

    impl Guild {
        /// `@everyone` and the bot's install role (held by the bot), plus
        /// `role_id` named `code` with Manage Server, made through the web
        /// UI by the importer from `at`: created as "new role", renamed to
        /// the code, then granted Manage Server
        pub fn ui_flow(code: &str, role_id: u64, at: DateTime<Utc>) -> Guild {
            let entry =
                |seconds: i64, low: u64| snowflake_at(at + chrono::Duration::seconds(seconds), low);
            Guild {
                roles: vec![
                    everyone(),
                    install_role(),
                    role(role_id, code, MANAGE_GUILD),
                ],
                bot_roles: vec![BOT_ROLE],
                creates: vec![create_entry(entry(1, 1), role_id, IMPORTER, "new role", 0)],
                updates: vec![
                    rename_entry(entry(20, 2), role_id, IMPORTER, "new role", code),
                    grant_entry(entry(30, 3), role_id, IMPORTER, 0, MANAGE_GUILD),
                ],
            }
        }

        /// A fake answering the invite, roles, own member and both audit
        /// pages for a verification at `now` (not started: add or override
        /// replies, then `start`)
        pub fn fake(self, now: DateTime<Utc>) -> FakeUpstream {
            let bot_roles: Vec<String> = self.bot_roles.iter().map(u64::to_string).collect();
            FakeUpstream::new()
                .reply(&invite_path(), 200, guild_invite())
                .reply(&roles_path(), 200, Value::Array(self.roles))
                .reply(
                    &member_path(),
                    200,
                    json!({
                        "user": { "id": BOT_USER.to_string(), "username": "Sloga_Importer", "bot": true },
                        "roles": bot_roles,
                        "joined_at": "2026-10-15T09:00:00.000Z",
                        "mute": false,
                        "deaf": false,
                    }),
                )
                .reply(&audit_path(30, now), 200, audit_page(self.creates))
                .reply(&audit_path(31, now), 200, audit_page(self.updates))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_upstream::FakeUpstream;
    use super::fixtures::*;
    use super::*;
    use chrono::TimeZone;
    use revolt_database::util::import_challenge::{code, ADMINISTRATOR, MANAGE_GUILD};

    const SECRET: &[u8] = b"r2-fluxer-test-secret";
    const USER: &str = "01J9ZQ4V6X7B8C9D0E1F2G3H4J";
    const OTHER_USER: &str = "01J9ZQ4V6X7B8C9D0E1F2G3H4K";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 15, 12, 0, 0).unwrap()
    }

    fn my_code() -> String {
        code(SECRET, SOURCE_TAG, USER, now().date_naive())
    }

    /// The code role: created an hour before `now`, today
    fn code_role_id() -> u64 {
        snowflake_at(now() - chrono::Duration::hours(1), 7)
    }

    /// The usual web flow for `my_code()`
    fn ui_flow() -> Guild {
        Guild::ui_flow(
            &my_code(),
            code_role_id(),
            now() - chrono::Duration::hours(1),
        )
    }

    /// One verification, with Fluxer budgets of its own
    async fn verify(fake: &FakeUpstream, source: FluxerSource) -> Result<VerifiedFluxerSource> {
        let api =
            FluxerApi::connect(&fluxer_config(fake), Transport::LoopbackTest).expect("client");
        let throttle = UpstreamThrottle::isolated_for_source_tests(SOURCE_TAG);
        verify_fluxer_source(&api, &throttle, &source, SECRET, USER, now()).await
    }

    fn invite() -> FluxerSource {
        FluxerSource::Invite(INVITE.to_string())
    }

    fn guild() -> FluxerSource {
        FluxerSource::GuildId(GUILD)
    }

    /// `ErrorType` has no `PartialEq`; a unit variant's `Debug` is its name
    fn assert_error(result: Result<VerifiedFluxerSource>, expected: &str) {
        match result {
            Ok(verified) => panic!("expected {}, got Ok({:?})", expected, verified),
            Err(error) => assert_eq!(format!("{:?}", error.error_type), expected),
        }
    }

    // ---- parse_fluxer_source ----

    #[test]
    fn parses_every_supported_form() {
        let invite = |code: &str| Some(FluxerSource::Invite(code.to_string()));
        let guild = |id: u64| Some(FluxerSource::GuildId(id));

        for (input, expected) in [
            ("https://fluxer.gg/AbC123", invite("AbC123")),
            ("http://fluxer.gg/AbC123", invite("AbC123")),
            ("HTTPS://Fluxer.GG/AbC123", invite("AbC123")),
            ("https://web.fluxer.app/invite/AbC123", invite("AbC123")),
            ("https://fluxer.com/invite/AbC123/", invite("AbC123")),
            ("https://fluxer.com//invite//AbC123//", invite("AbC123")),
            (
                "https://fluxer.example:8443/i/my-server",
                invite("my-server"),
            ),
            // Host-agnostic: the host is never contacted
            ("https://anything.example/x/Ab", invite("Ab")),
            // In a link the last segment is always an invite code
            (
                "https://fluxer.gg/1200000000000000001",
                invite("1200000000000000001"),
            ),
            ("AbC123", invite("AbC123")),
            ("my-server", invite("my-server")),
            ("Ab", invite("Ab")),
            ("12a", invite("12a")),
            ("  AbC123\t", invite("AbC123")),
            ("\n https://fluxer.gg/AbC123 \n", invite("AbC123")),
            ("1200000000000000001", guild(1_200_000_000_000_000_001)),
            ("12345678901234567", guild(12_345_678_901_234_567)),
            ("18446744073709551615", guild(u64::MAX)),
            (" 1200000000000000001 ", guild(1_200_000_000_000_000_001)),
            // Leading zeros are the same guild in canonical form
            ("01200000000000000001", guild(1_200_000_000_000_000_001)),
        ] {
            assert_eq!(parse_fluxer_source(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn refuses_everything_else() {
        let overlong = "a".repeat(CODE_MAX + 1);
        let overlong_link = format!("https://fluxer.gg/{overlong}");
        for input in [
            "",
            "   ",
            "a",
            "-",
            // Bare digits that are not a guild id
            "12",
            "1234567890123456",
            "123456789012345678901",
            // Over a snowflake
            "18446744073709551616",
            "99999999999999999999",
            overlong.as_str(),
            overlong_link.as_str(),
            // A slash in a bare value
            "fluxer.gg/AbC123",
            "invite/AbC123",
            "AbC/123",
            "/AbC123",
            // Links that name nothing
            "https://",
            "https:///AbC123",
            "https://fluxer.gg",
            "https://fluxer.gg/",
            "https://fluxer.gg//",
            "https://fluxer.gg/a",
            "ftp://fluxer.gg/AbC123",
            // Query, fragment, userinfo
            "https://fluxer.gg/AbC123?ref=x",
            "https://fluxer.gg/AbC123#frag",
            "https://user@fluxer.gg/AbC123",
            "https://fluxer.gg/invite/Ab_C",
            "https://fluxer.gg/invite.html",
        ] {
            assert_eq!(parse_fluxer_source(input), None, "input {input:?}");
        }
    }

    /// Whatever comes back is interpolated into `{api_url}/v1/invites/{}` or
    /// `{api_url}/v1/guilds/{}/…`, so the output alphabet and length are the
    /// security property. Traversal, escapes and whitespace inside are
    /// refused outright, never reduced to a segment.
    #[test]
    fn hostile_input_never_yields_an_unsafe_token() {
        for input in [
            "../",
            "..",
            "../../admin",
            "AbC123/../x",
            "https://fluxer.gg/invite/../../guilds/x",
            "https://fluxer.gg/AbC123/..",
            "https://fluxer.gg/AbC123/.",
            "https://fluxer.gg/./AbC123",
            "https://fluxer.gg/invite/..%2F..%2Fadmin",
            "https://fluxer.gg/%2e%2e",
            "https://fluxer.gg/Ab%43",
            "%2e%2e%2f",
            "%2E%2E",
            "Ab%20C",
            "Ab C123",
            "Ab\tC123",
            "Ab\nC123",
            "https://fluxer.gg/Ab C123",
            "https://fluxer.gg /AbC123",
            "AbC_123",
            "Ab.C123",
            "Ab\\C123",
            "https://fluxer.gg\\AbC123",
            "Ab;C",
            "Ab@C",
            "Ab:C",
            "Ab+C",
            "Abé123",
            "https://fluxer.gg/Abé123",
            "Ab／C",
            "Ab\u{0}C",
        ] {
            assert_eq!(parse_fluxer_source(input), None, "input {input:?}");
        }

        // Exhaustive over single bytes inside a valid token: anything outside
        // `[A-Za-z0-9-]` makes the whole input refused
        for byte in 0u8..=127 {
            let ch = byte as char;
            for input in [
                format!("AbC{ch}123"),
                format!("https://fluxer.gg/AbC{ch}123"),
                format!("https://fluxer.gg/invite/AbC{ch}123/"),
            ] {
                let token = match parse_fluxer_source(&input) {
                    Some(FluxerSource::Invite(token)) => Some(token),
                    Some(FluxerSource::GuildId(id)) => panic!("{:?} gave guild {}", input, id),
                    None => None,
                };
                let safe = ch.is_ascii_alphanumeric() || ch == '-';
                if safe {
                    assert_eq!(token, Some(format!("AbC{ch}123")), "input {input:?}");
                }
                if let Some(token) = token {
                    assert!(
                        is_invite_code(&token),
                        "unsafe {:?} from {:?}",
                        token,
                        input
                    );
                    // A `/` splits a link into segments; the code is still safe
                    assert!(safe || ch == '/', "{:?} parsed but carries {:?}", input, ch);
                }
            }
        }
    }

    #[test]
    fn invite_length_bounds_are_inclusive() {
        let max = "a".repeat(CODE_MAX);
        assert_eq!(
            parse_fluxer_source(&max),
            Some(FluxerSource::Invite(max.clone()))
        );
        assert_eq!(parse_fluxer_source(&format!("{max}a")), None);
        assert_eq!(
            parse_fluxer_source(&format!("https://fluxer.gg/{max}")),
            Some(FluxerSource::Invite(max.clone()))
        );
        assert_eq!(
            parse_fluxer_source("ab"),
            Some(FluxerSource::Invite("ab".to_string()))
        );
        assert_eq!(parse_fluxer_source("b"), None);
    }

    // ---- verify_fluxer_source against a fake upstream ----

    #[test]
    fn real_ui_flow_via_invite_passes_and_every_bot_call_is_authorized() {
        crate::util::test::rt().block_on(async {
            let fake = ui_flow().fake(now()).start().await;

            let verified = verify(&fake, invite()).await.expect("verified");
            assert_eq!(
                verified,
                VerifiedFluxerSource {
                    guild_id: GUILD.to_string(),
                    challenge_code: my_code(),
                }
            );

            let seen = fake.seen();
            let paths: Vec<&str> = seen.iter().map(|seen| seen.path.as_str()).collect();
            assert_eq!(
                paths,
                [
                    invite_path(),
                    roles_path(),
                    member_path(),
                    audit_path(30, now()),
                    audit_path(31, now()),
                ],
                "{seen:?}"
            );
            // The invite lookup is public; every other call is the bot's
            assert_eq!(seen[0].header("authorization"), None);
            let expected = format!("Bot {BOT_TOKEN}");
            for call in &seen[1..] {
                assert_eq!(
                    call.header("authorization"),
                    Some(expected.as_str()),
                    "{}",
                    call.path
                );
            }
            // Stoat's header is never sent to Fluxer
            assert!(seen.iter().all(|call| call.bot_token.is_none()));
        })
    }

    #[test]
    fn real_ui_flow_via_guild_id_passes() {
        crate::util::test::rt().block_on(async {
            let fake = ui_flow().fake(now()).start().await;

            let verified = verify(&fake, guild()).await.expect("verified");
            assert_eq!(verified.guild_id, GUILD.to_string());
            assert_eq!(verified.challenge_code, my_code());
            assert_eq!(fake.seen().len(), 4, "{:?}", fake.seen());
        })
    }

    /// The audit `after` cursor starts just before yesterday's midnight,
    /// the earliest day an accepted code can be from
    #[test]
    fn yesterdays_code_on_a_role_made_yesterday_passes() {
        crate::util::test::rt().block_on(async {
            let yesterday = now().date_naive().pred_opt().unwrap();
            let theirs = code(SECRET, SOURCE_TAG, USER, yesterday);
            let made = yesterday.and_hms_opt(0, 0, 5).unwrap().and_utc();
            let fake = Guild::ui_flow(&theirs, snowflake_at(made, 9), made)
                .fake(now())
                .start()
                .await;

            let verified = verify(&fake, guild()).await.expect("verified");
            assert_eq!(verified.challenge_code, theirs);
            assert_eq!(
                audit_after(now()) + 1,
                snowflake_at(yesterday.and_hms_opt(0, 0, 0).unwrap().and_utc(), 0)
            );
        })
    }

    #[test]
    fn bot_not_in_server() {
        crate::util::test::rt().block_on(async {
            for status in [401, 403, 404] {
                // On the role list: nothing after it is called
                let fake = ui_flow()
                    .fake(now())
                    .reply(&roles_path(), status, json!({ "code": "UNKNOWN_GUILD" }))
                    .start()
                    .await;
                assert_error(verify(&fake, invite()).await, "ImportBotNotInServer");
                assert_eq!(fake.seen().len(), 2, "{:?}", fake.seen());

                // On the bot's own member
                let fake = ui_flow()
                    .fake(now())
                    .reply(&member_path(), status, json!({ "code": "UNKNOWN_MEMBER" }))
                    .start()
                    .await;
                assert_error(verify(&fake, guild()).await, "ImportBotNotInServer");
                assert_eq!(fake.seen().len(), 2, "{:?}", fake.seen());
            }
        })
    }

    #[test]
    fn no_code_role_is_verification_missing_without_reading_the_audit_log() {
        crate::util::test::rt().block_on(async {
            let mut guild_state = ui_flow();
            guild_state.roles = vec![
                everyone(),
                install_role(),
                role(code_role_id(), "Moderators", MANAGE_GUILD),
                // The code with something around it is a different name
                role(
                    snowflake_at(now(), 3),
                    &format!("{} ", my_code()),
                    ADMINISTRATOR,
                ),
            ];
            let fake = guild_state.fake(now()).start().await;

            assert_error(verify(&fake, guild()).await, "ImportVerificationMissing");
            assert_eq!(fake.seen().len(), 2, "{:?}", fake.seen());
        })
    }

    #[test]
    fn code_role_without_manage_server_is_verification_missing() {
        crate::util::test::rt().block_on(async {
            // Every step of the web flow but the grant
            let mut guild_state = ui_flow();
            guild_state.roles[2] = role(code_role_id(), &my_code(), 0x400 | 0x800);
            guild_state.updates.truncate(1);
            let fake = guild_state.fake(now()).start().await;

            assert_error(verify(&fake, guild()).await, "ImportVerificationMissing");
        })
    }

    /// The rename bypass: an orphaned bot-install role (created by whoever
    /// added a bot, holding Administrator, no longer held by any bot)
    /// renamed to the code by a Manage-Roles moderator. Its name and bits
    /// match today; only the audit log tells it apart.
    #[test]
    fn renamed_install_role_is_verification_missing() {
        crate::util::test::rt().block_on(async {
            let at = now() - chrono::Duration::hours(2);
            let orphan = snowflake_at(at, 5);
            let entry =
                |minutes: i64, low: u64| snowflake_at(at + chrono::Duration::minutes(minutes), low);
            let guild_state = Guild {
                roles: vec![
                    everyone(),
                    install_role(),
                    role(orphan, &my_code(), ADMINISTRATOR),
                ],
                bot_roles: vec![BOT_ROLE],
                creates: vec![create_entry(
                    entry(0, 1),
                    orphan,
                    INSTALLER,
                    "Sloga Importer",
                    ADMINISTRATOR,
                )],
                updates: vec![rename_entry(
                    entry(30, 2),
                    orphan,
                    MODERATOR,
                    "Sloga Importer",
                    &my_code(),
                )],
            };
            let fake = guild_state.fake(now()).start().await;

            assert_error(verify(&fake, invite()).await, "ImportVerificationMissing");
            // Refused on the evidence, after both pages were read
            assert_eq!(fake.seen().len(), 5, "{:?}", fake.seen());
        })
    }

    /// A role the bot holds never proves anything, even one whose audit
    /// history would: it carries the bot's permissions, not the user's
    #[test]
    fn code_role_held_by_the_bot_is_verification_missing() {
        crate::util::test::rt().block_on(async {
            let mut guild_state = ui_flow();
            guild_state.bot_roles.push(code_role_id());
            let fake = guild_state.fake(now()).start().await;

            assert_error(verify(&fake, guild()).await, "ImportVerificationMissing");
        })
    }

    /// A full page has dropped the oldest entries of the window (Fluxer
    /// reads newest first), so it is refused even when what it does show
    /// would prove ownership
    #[test]
    fn a_full_audit_page_is_verification_missing() {
        crate::util::test::rt().block_on(async {
            let at = now() - chrono::Duration::minutes(30);
            let filler = |count: usize, action: u8| -> Vec<Value> {
                (0..count as u64)
                    .map(|i| {
                        let id = snowflake_at(at, 100 + i);
                        let target = snowflake_at(at, 1000 + i);
                        if action == 30 {
                            create_entry(id, target, MODERATOR, "spam", 0)
                        } else {
                            rename_entry(id, target, MODERATOR, "spam", "more spam")
                        }
                    })
                    .collect()
            };

            for action in [30u8, 31] {
                let mut guild_state = ui_flow();
                let page = if action == 30 {
                    &mut guild_state.creates
                } else {
                    &mut guild_state.updates
                };
                let short = 100 - page.len();
                page.extend(filler(short, action));
                assert_eq!(page.len(), 100);
                let fake = guild_state.fake(now()).start().await;

                assert_error(verify(&fake, guild()).await, "ImportVerificationMissing");
            }

            // One entry short of full is read and verifies
            let mut guild_state = ui_flow();
            let short = 99 - guild_state.updates.len();
            guild_state.updates.extend(filler(short, 31));
            let fake = guild_state.fake(now()).start().await;
            verify(&fake, guild())
                .await
                .expect("a page of 99 is complete");
        })
    }

    #[test]
    fn an_unreadable_audit_page_is_verification_missing() {
        crate::util::test::rt().block_on(async {
            for page in [
                json!({ "entries": [] }),
                json!({ "audit_log_entries": [{ "id": "x", "action_type": 31 }] }),
                // A permission change it cannot read
                audit_page(vec![json!({
                    "id": snowflake_at(now(), 1).to_string(),
                    "action_type": 31,
                    "user_id": IMPORTER.to_string(),
                    "target_id": code_role_id().to_string(),
                    "changes": [{ "key": "permissions", "old_value": "0", "new_value": "lots" }],
                })]),
            ] {
                let fake = ui_flow()
                    .fake(now())
                    .reply(&audit_path(31, now()), 200, page)
                    .start()
                    .await;
                assert_error(verify(&fake, guild()).await, "ImportVerificationMissing");
            }
        })
    }

    /// The bot cannot view the audit log: it was not installed with
    /// Administrator, and nothing can be proven without the log
    #[test]
    fn audit_log_403_is_verification_missing() {
        crate::util::test::rt().block_on(async {
            for action in [30u8, 31] {
                let fake = ui_flow()
                    .fake(now())
                    .reply(
                        &audit_path(action, now()),
                        403,
                        json!({ "code": "MISSING_PERMISSIONS" }),
                    )
                    .start()
                    .await;
                assert_error(verify(&fake, guild()).await, "ImportVerificationMissing");
            }
        })
    }

    #[test]
    fn another_users_code_is_verification_missing() {
        crate::util::test::rt().block_on(async {
            let theirs = code(SECRET, SOURCE_TAG, OTHER_USER, now().date_naive());
            let fake = Guild::ui_flow(&theirs, code_role_id(), now() - chrono::Duration::hours(1))
                .fake(now())
                .start()
                .await;
            assert_error(verify(&fake, guild()).await, "ImportVerificationMissing");
        })
    }

    #[test]
    fn another_source_tags_code_is_verification_missing() {
        crate::util::test::rt().block_on(async {
            for tag in ["stoat", "matrix"] {
                let other = code(SECRET, tag, USER, now().date_naive());
                let fake =
                    Guild::ui_flow(&other, code_role_id(), now() - chrono::Duration::hours(1))
                        .fake(now())
                        .start()
                        .await;
                assert_error(verify(&fake, guild()).await, "ImportVerificationMissing");
            }
        })
    }

    #[test]
    fn unknown_and_group_dm_invites_are_not_found() {
        crate::util::test::rt().block_on(async {
            for (status, body) in [
                // Unknown invite
                (404, json!({ "code": "UNKNOWN_INVITE" })),
                // Group DM invite: no guild
                (
                    200,
                    json!({
                        "code": INVITE,
                        "type": 1,
                        "channel": { "id": "1300000000000000099", "type": 3 },
                        "member_count": 2,
                        "temporary": false,
                    }),
                ),
                // A group DM invite that names a guild anyway
                (
                    200,
                    json!({ "code": INVITE, "type": 1, "guild": { "id": GUILD.to_string() } }),
                ),
                // No type, or no guild id
                (
                    200,
                    json!({ "code": INVITE, "guild": { "id": GUILD.to_string() } }),
                ),
                (200, json!({ "code": INVITE, "type": 0, "guild": {} })),
                (200, json!({ "code": INVITE, "type": 0, "guild": null })),
                (200, json!({ "code": INVITE, "type": 0 })),
            ] {
                let fake = ui_flow()
                    .fake(now())
                    .reply(&invite_path(), status, body)
                    .start()
                    .await;
                assert_error(verify(&fake, invite()).await, "ImportSourceNotFound");
                assert_eq!(fake.seen().len(), 1, "no bot call after a bad invite");
            }
        })
    }

    #[test]
    fn an_unusable_guild_id_from_the_invite_is_upstream_unavailable() {
        crate::util::test::rt().block_on(async {
            for id in [
                json!("../users/@me"),
                json!("12a"),
                json!(""),
                json!("123456789012345678901"),
                json!("99999999999999999999"),
                json!(1200000000000000001u64),
            ] {
                let fake = ui_flow()
                    .fake(now())
                    .reply(
                        &invite_path(),
                        200,
                        json!({ "code": INVITE, "type": 0, "guild": { "id": id } }),
                    )
                    .start()
                    .await;
                assert_error(verify(&fake, invite()).await, "ImportUpstreamUnavailable");
                assert_eq!(fake.seen().len(), 1, "unsafe id must not be fetched");
            }
        })
    }

    #[test]
    fn rate_limits_and_server_errors_are_upstream_unavailable() {
        crate::util::test::rt().block_on(async {
            for status in [429, 500, 502, 503] {
                let calls = [
                    invite_path(),
                    roles_path(),
                    member_path(),
                    audit_path(30, now()),
                    audit_path(31, now()),
                ];
                for (index, path) in calls.iter().enumerate() {
                    let fake = ui_flow()
                        .fake(now())
                        .reply(
                            path,
                            status,
                            json!({ "code": "RATE_LIMITED", "retry_after": 5 }),
                        )
                        .start()
                        .await;
                    assert_error(verify(&fake, invite()).await, "ImportUpstreamUnavailable");
                    assert_eq!(fake.seen().len(), index + 1, "{path}");
                }
            }
        })
    }

    #[test]
    fn unreadable_roles_or_member_are_upstream_unavailable() {
        crate::util::test::rt().block_on(async {
            let mut bad_roles = vec![
                json!({ "roles": [] }),
                json!([{ "id": GUILD.to_string(), "name": "@everyone" }]),
                json!([{ "id": GUILD.to_string(), "name": "@everyone", "permissions": "lots" }]),
                json!([{ "id": GUILD.to_string(), "name": "@everyone", "permissions": -1 }]),
                json!([{ "id": 5, "name": "x", "permissions": "8" }]),
                json!([{ "id": "5", "name": 5, "permissions": "8" }]),
                json!("not roles"),
            ];
            // One bad role among good ones fails the whole list
            let mut mixed = vec![everyone(), install_role()];
            mixed.push(json!({ "id": "x", "name": my_code(), "permissions": "32" }));
            bad_roles.push(Value::Array(mixed));

            for body in bad_roles {
                let fake = ui_flow()
                    .fake(now())
                    .reply(&roles_path(), 200, body)
                    .start()
                    .await;
                assert_error(verify(&fake, guild()).await, "ImportUpstreamUnavailable");
            }

            for body in [
                json!({}),
                json!({ "roles": null }),
                json!({ "roles": "1300000000000000002" }),
                json!({ "roles": [1300000000000000002u64] }),
                json!({ "roles": ["role"] }),
            ] {
                let fake = ui_flow()
                    .fake(now())
                    .reply(&member_path(), 200, body)
                    .start()
                    .await;
                assert_error(verify(&fake, guild()).await, "ImportUpstreamUnavailable");
            }
        })
    }

    /// Permissions as a plain integer are read the same as a string
    #[test]
    fn numeric_permissions_are_read() {
        crate::util::test::rt().block_on(async {
            let mut guild_state = ui_flow();
            guild_state.roles[2]["permissions"] = json!(MANAGE_GUILD);
            let fake = guild_state.fake(now()).start().await;
            verify(&fake, guild()).await.expect("verified");
        })
    }

    #[test]
    fn redirects_are_not_followed() {
        crate::util::test::rt().block_on(async {
            // The redirect target would verify; following it is the bug
            let fake = ui_flow()
                .fake(now())
                .redirect(&roles_path(), "/v1/guilds/1/roles")
                .reply(
                    "/v1/guilds/1/roles",
                    200,
                    json!([
                        everyone(),
                        install_role(),
                        role(code_role_id(), &my_code(), 8)
                    ]),
                )
                .start()
                .await;
            assert_error(verify(&fake, guild()).await, "ImportUpstreamUnavailable");
            assert_eq!(fake.seen().len(), 1, "{:?}", fake.seen());
        })
    }

    #[test]
    fn production_client_refuses_plain_http() {
        crate::util::test::rt().block_on(async {
            let fake = ui_flow().fake(now()).start().await;
            let api =
                FluxerApi::connect(&fluxer_config(&fake), Transport::Production).expect("client");
            assert_error(
                verify_fluxer_source(
                    &api,
                    &UpstreamThrottle::isolated_for_source_tests(SOURCE_TAG),
                    &guild(),
                    SECRET,
                    USER,
                    now(),
                )
                .await,
                "ImportUpstreamUnavailable",
            );
            assert!(fake.seen().is_empty(), "{:?}", fake.seen());
        })
    }

    // ---- outbound budgets ----

    #[test]
    fn a_throttled_verification_makes_no_upstream_call() {
        crate::util::test::rt().block_on(async {
            let fake = ui_flow().fake(now()).start().await;
            let api =
                FluxerApi::connect(&fluxer_config(&fake), Transport::LoopbackTest).expect("client");
            let throttle = UpstreamThrottle::isolated_for_source_tests(SOURCE_TAG);

            // Two verifications per user per 30 s, on different targets
            for source in [invite(), FluxerSource::GuildId(GUILD + 1)] {
                let _ = verify_fluxer_source(&api, &throttle, &source, SECRET, USER, now()).await;
            }
            let calls = fake.seen().len();
            assert_error(
                verify_fluxer_source(&api, &throttle, &guild(), SECRET, USER, now()).await,
                "ImportUpstreamUnavailable",
            );
            assert_eq!(fake.seen().len(), calls, "{:?}", fake.seen());

            // A full verification spends four calls on the guild; a second
            // one by another user runs out partway, within the five
            let throttle = UpstreamThrottle::isolated_for_source_tests(SOURCE_TAG);
            verify_fluxer_source(&api, &throttle, &guild(), SECRET, USER, now())
                .await
                .expect("verified");
            let calls = fake.seen().len();
            assert_error(
                verify_fluxer_source(&api, &throttle, &guild(), SECRET, OTHER_USER, now()).await,
                "ImportUpstreamUnavailable",
            );
            assert_eq!(fake.seen().len(), calls + 1, "{:?}", fake.seen());
        })
    }
}
