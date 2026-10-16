//! Fluxer API and CDN client for the importer.
//!
//! Everything here talks to hosts named in `[api.import.fluxer]` only. The
//! API client carries the bot token (`Authorization: Bot <token>`, marked
//! sensitive, never logged) and follows no redirects. The CDN client carries
//! no credential and follows no redirects either: Fluxer's media proxy
//! serves `/icons`, `/banners` and `/emojis` directly.
//!
//! `api_url` is the API origin without a version (`https://api.fluxer.app`);
//! every path below is written with its `/v1` prefix.
//!
//! Nothing here retries an import call: a 429 or 5xx is "Fluxer is
//! unavailable", and the user tries again. Only the reconcile pass waits out
//! a `Retry-After` (see `reconcile`).
//!
//! Every response body is read through a size cap. Wire types are read
//! permissively (unknown fields ignored, cosmetic fields optional) except
//! ids and permission values: a role or overwrite whose bits cannot be read,
//! or a channel without its overwrite list, fails the import rather than
//! defaulting to "no deny", which is how a private channel would become
//! public.

use std::fmt;
use std::time::Duration;

use futures::future::BoxFuture;
use iso8601_timestamp::Timestamp;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use reqwest::{StatusCode, Url};
use revolt_config::ApiImportBotSource;
use revolt_database::util::import_challenge::{
    parse_fluxer_role_audit_page, FluxerAuditPage, FLUXER_AUDIT_PAGE_LIMIT,
};
use serde::de::{DeserializeOwned, Deserializer, Error as _};
use serde::Deserialize;
use serde_json::Value;

use crate::tasks::discord_import::assets::AssetFetcher;
use crate::tasks::discord_import::mapper::{AssetKind, PlannedAsset};
use crate::tasks::discord_import::template::OverwriteKind;
use crate::tasks::import_http::{
    client_builder, read_capped, same_origin, transport_for, AssetLimits, ReadError, Transport,
};

/// Largest JSON body read from the API. A guild at Fluxer's 500-channel
/// limit, each channel with a full set of role overwrites, is well under it.
pub(crate) const JSON_BODY_CAP: usize = 4 * 1024 * 1024;

/// Longest snowflake accepted: `[0-9]{1,20}`.
const SNOWFLAKE_MAX: usize = 20;

/// Longest asset hash accepted after its optional `a_` prefix.
const ASSET_HASH_MAX: usize = 64;

/// Guilds per `GET /v1/users/@me/guilds` page (Fluxer's maximum).
pub(crate) const GUILD_LIST_LIMIT: usize = 200;

/// Size asked of the CDN for each kind of asset. Without one the media
/// proxy answers with a 128 px rendition.
const ICON_SIZE: &str = "1024";
const BANNER_SIZE: &str = "2400";
const EMOJI_SIZE: &str = "512";

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

/// A Fluxer id: a decimal string of 1 to 20 digits that fits a `u64`, in
/// canonical form (no leading zeros), so the same guild always has the same
/// string and a job's `source_server_id` compares equal to what Fluxer
/// lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Snowflake(pub u64);

impl Snowflake {
    pub(crate) fn parse(text: &str) -> Option<Snowflake> {
        if text.is_empty()
            || text.len() > SNOWFLAKE_MAX
            || !text.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let value: u64 = text.parse().ok()?;
        (value.to_string() == text).then_some(Snowflake(value))
    }
}

impl fmt::Display for Snowflake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> Deserialize<'de> for Snowflake {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::String(text) => {
                Snowflake::parse(&text).ok_or_else(|| D::Error::custom("not a snowflake"))
            }
            Value::Number(number) => number
                .as_u64()
                .map(Snowflake)
                .ok_or_else(|| D::Error::custom("not a snowflake")),
            _ => Err(D::Error::custom("not a snowflake")),
        }
    }
}

/// A permission bitfield: a decimal string (what Fluxer sends) or a JSON
/// integer. Anything else is an error, never "no bits".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Bits(pub u64);

impl<'de> Deserialize<'de> for Bits {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = match Value::deserialize(deserializer)? {
            Value::String(text)
                if !text.is_empty()
                    && text.len() <= SNOWFLAKE_MAX
                    && text.bytes().all(|b| b.is_ascii_digit()) =>
            {
                text.parse().ok()
            }
            Value::Number(number) => number.as_u64(),
            _ => None,
        };
        bits.map(Bits)
            .ok_or_else(|| D::Error::custom("not a permission value"))
    }
}

/// A channel `type`: any JSON integer. `None` for one outside `i64`, which
/// no known type is (the importer skips it like any unknown type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChannelType(pub Option<i64>);

impl<'de> Deserialize<'de> for ChannelType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::Number(number) if number.is_i64() || number.is_u64() => {
                Ok(ChannelType(number.as_i64()))
            }
            _ => Err(D::Error::custom("not a channel type")),
        }
    }
}

/// A non-negative whole number, as an integer or a numeric string. Anything
/// else is `None`: these are cosmetic settings (slowmode, voice limits, the
/// AFK timeout), and the importer leaves them unset rather than failing.
fn lenient_u64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(text)) => text.trim().parse().ok(),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// Wire types (Fluxer API v1)
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct FluxerEmoji {
    pub id: Snowflake,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub animated: Option<bool>,
}

/// `GET /v1/guilds/{id}`. Fluxer guilds have no description.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct FluxerGuild {
    pub id: Snowflake,
    #[serde(default)]
    pub name: Option<String>,
    /// Icon hash; `a_` marks an animated one.
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub banner: Option<String>,
    #[serde(default)]
    pub system_channel_id: Option<Snowflake>,
    #[serde(default)]
    pub afk_channel_id: Option<Snowflake>,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub afk_timeout: Option<u64>,
    /// Whether the guild is marked adult content: the last step of every
    /// channel's age-restriction inheritance.
    #[serde(default)]
    pub nsfw: Option<bool>,
    /// Only `GET /v1/guilds/{id}` carries this.
    #[serde(default)]
    pub emojis: Option<Vec<FluxerEmoji>>,
}

/// `GET /v1/guilds/{id}/roles`. `@everyone` is the role whose id is the
/// guild id.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct FluxerRole {
    pub id: Snowflake,
    #[serde(default)]
    pub name: Option<String>,
    /// Required: a role's grant is never guessed.
    pub permissions: Bits,
    #[serde(default)]
    pub position: Option<i64>,
    #[serde(default)]
    pub color: Option<i64>,
    #[serde(default)]
    pub hoist: Option<bool>,
}

/// One entry of a channel's `permission_overwrites`. Both halves are
/// required; `type` is 0 (role) or 1 (member), and anything else reaches
/// the mapper as `Unknown`, which refuses the import.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct FluxerOverwrite {
    pub id: Snowflake,
    #[serde(rename = "type", default = "unknown_overwrite_kind")]
    pub kind: OverwriteKind,
    pub allow: Bits,
    pub deny: Bits,
}

fn unknown_overwrite_kind() -> OverwriteKind {
    OverwriteKind::Unknown
}

/// `GET /v1/guilds/{id}/channels`: every channel the bot can view.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct FluxerChannel {
    pub id: Snowflake,
    #[serde(rename = "type")]
    pub channel_type: ChannelType,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub position: Option<i64>,
    #[serde(default)]
    pub parent_id: Option<Snowflake>,
    /// The channel's own age restriction (false when it sets none).
    #[serde(default)]
    pub nsfw: Option<bool>,
    /// The channel's own setting, or null when it inherits from its
    /// category and then the guild.
    #[serde(default)]
    pub nsfw_override: Option<bool>,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub rate_limit_per_user: Option<u64>,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub user_limit: Option<u64>,
    #[serde(default, deserialize_with = "lenient_u64")]
    pub bitrate: Option<u64>,
    /// Required: Fluxer always sends the complete list, and a channel read
    /// without it would lose its denies.
    pub permission_overwrites: Vec<FluxerOverwrite>,
}

/// `GET /v1/guilds/{id}/members/@me`, the part the importer reads.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
struct FluxerMember {
    roles: Vec<Snowflake>,
}

/// One entry of `GET /v1/users/@me/guilds`.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
struct ListedGuild {
    id: Snowflake,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a Fluxer API call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FluxerError {
    /// 401, 403 or 404 on a guild read: the bot is not in that guild, or the
    /// guild is gone.
    BotNotInServer,
    /// 403 on the audit log: the bot is in the guild but may not read it
    /// (it lost Administrator / View Audit Log).
    AuditLogForbidden,
    /// 429, 5xx, any other unexpected status, a redirect, a timeout or a
    /// transport failure. Retry later.
    Unavailable,
    /// The answer could not be read: not the expected JSON, another guild,
    /// ids or permission values in an unknown shape, or over the size cap.
    Malformed,
}

impl FluxerError {
    /// User-safe message stored on the job.
    pub(crate) fn user_message(&self) -> String {
        match self {
            FluxerError::BotNotInServer => {
                "The Sloga importer bot can't see your Fluxer server anymore. Make sure the bot \
                 is still a member of the server, then start the import again."
            }
            FluxerError::AuditLogForbidden => {
                "The Sloga importer bot can't read your Fluxer server's audit log anymore, so \
                 your verification role can't be checked. Make sure the bot still has \
                 Administrator, then start the import again."
            }
            FluxerError::Unavailable => {
                "We couldn't reach Fluxer right now, or Fluxer is rate-limiting us. Please try \
                 again in a few minutes."
            }
            FluxerError::Malformed => {
                "Fluxer returned a server we couldn't read. Please report this if it keeps \
                 happening."
            }
        }
        .to_string()
    }
}

/// What a leave request came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeaveOutcome {
    /// 2xx, or 404: the bot holds no membership there now.
    Left,
    /// 429, with how long Fluxer asked to wait (if it said).
    RateLimited(Option<Duration>),
    /// Anything else: the bot may well still be in the guild.
    NotLeft,
}

/// Why a guild-list page could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListError {
    /// 429, with how long Fluxer asked to wait (if it said).
    RateLimited(Option<Duration>),
    /// Any other failure.
    Failed,
}

/// What `GET /v1/guilds/{id}/members/@me` said about the bot's membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemberLookup {
    /// The bot is a member. When it joined (Fluxer's `joined_at`), or `None`
    /// when the answer had no readable ISO-8601 time there.
    Member(Option<Timestamp>),
    /// 404: the bot holds no membership there now.
    NotMember,
    /// 429, with how long Fluxer asked to wait (if it said).
    RateLimited(Option<Duration>),
    /// Anything else, an unreadable answer included.
    Failed,
}

/// `Retry-After` in whole seconds (Fluxer's form), if present and readable.
fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    let value = response.headers().get(RETRY_AFTER)?.to_str().ok()?.trim();
    let seconds: f64 = value.parse().ok()?;
    (seconds.is_finite() && seconds >= 0.0).then(|| Duration::from_secs_f64(seconds.min(86_400.0)))
}

// ---------------------------------------------------------------------------
// API client
// ---------------------------------------------------------------------------

/// Fluxer API client acting as the operator bot.
///
/// No `Debug`: the token must not reach a log line.
pub(crate) struct FluxerApi {
    client: reqwest::Client,
    api_url: String,
    bot_token: String,
}

impl FluxerApi {
    /// Client for `[api.import.fluxer]`, or `None` when it has no API URL or
    /// no bot token (nothing could be sent).
    pub(crate) fn new(config: &ApiImportBotSource) -> Option<FluxerApi> {
        FluxerApi::build(config, transport_for(&config.api_url))
    }

    fn build(config: &ApiImportBotSource, transport: Transport) -> Option<FluxerApi> {
        if config.api_url.is_empty() || config.bot_token.is_empty() {
            return None;
        }

        let client = client_builder(transport)
            // The token rides every request: never follow a redirect.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;

        Some(FluxerApi {
            client,
            api_url: config.api_url.trim_end_matches('/').to_string(),
            bot_token: config.bot_token.clone(),
        })
    }

    fn authorization(&self) -> Option<HeaderValue> {
        let mut value = HeaderValue::from_str(&format!("Bot {}", self.bot_token)).ok()?;
        value.set_sensitive(true);
        Some(value)
    }

    /// `GET {path}` as the bot, parsed from the capped body of a 2xx answer.
    /// A 403 is `forbidden`; 401 and 404 are `BotNotInServer`.
    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        forbidden: FluxerError,
    ) -> Result<T, FluxerError> {
        let authorization = self.authorization().ok_or(FluxerError::Unavailable)?;
        let response = self
            .client
            .get(format!("{}{path}", self.api_url))
            .header(AUTHORIZATION, authorization)
            .send()
            .await
            .map_err(|_| FluxerError::Unavailable)?;

        match response.status() {
            status if status.is_success() => {}
            StatusCode::FORBIDDEN => return Err(forbidden),
            StatusCode::NOT_FOUND | StatusCode::UNAUTHORIZED => {
                return Err(FluxerError::BotNotInServer)
            }
            _ => return Err(FluxerError::Unavailable),
        }

        let body = read_capped(response, JSON_BODY_CAP)
            .await
            .map_err(|error| match error {
                ReadError::TooLarge => FluxerError::Malformed,
                ReadError::Transport => FluxerError::Unavailable,
            })?;
        serde_json::from_slice(&body).map_err(|_| FluxerError::Malformed)
    }

    /// The guild, with its emoji.
    pub(crate) async fn fetch_guild(&self, guild: Snowflake) -> Result<FluxerGuild, FluxerError> {
        let fetched: FluxerGuild = self
            .get_json(&format!("/v1/guilds/{guild}"), FluxerError::BotNotInServer)
            .await?;
        if fetched.id != guild {
            return Err(FluxerError::Malformed);
        }
        Ok(fetched)
    }

    /// Every role in the guild, `@everyone` included.
    pub(crate) async fn fetch_roles(
        &self,
        guild: Snowflake,
    ) -> Result<Vec<FluxerRole>, FluxerError> {
        self.get_json(
            &format!("/v1/guilds/{guild}/roles"),
            FluxerError::BotNotInServer,
        )
        .await
    }

    /// Every channel the bot can view.
    pub(crate) async fn fetch_channels(
        &self,
        guild: Snowflake,
    ) -> Result<Vec<FluxerChannel>, FluxerError> {
        self.get_json(
            &format!("/v1/guilds/{guild}/channels"),
            FluxerError::BotNotInServer,
        )
        .await
    }

    /// The roles the bot holds in the guild.
    pub(crate) async fn fetch_bot_roles(
        &self,
        guild: Snowflake,
    ) -> Result<Vec<Snowflake>, FluxerError> {
        let member: FluxerMember = self
            .get_json(
                &format!("/v1/guilds/{guild}/members/@me"),
                FluxerError::BotNotInServer,
            )
            .await?;
        Ok(member.roles)
    }

    /// One audit-log page of `action_type` entries newer than `after`,
    /// parsed by the shared parser (fails closed on anything it cannot
    /// read). Fluxer reads newest first and cannot page forward, so this is
    /// the only page the caller reads; a full one is the caller's to refuse.
    pub(crate) async fn fetch_audit_page(
        &self,
        guild: Snowflake,
        action_type: u8,
        after: u64,
    ) -> Result<FluxerAuditPage, FluxerError> {
        let body: Value = self
            .get_json(
                &audit_path(guild, action_type, after),
                FluxerError::AuditLogForbidden,
            )
            .await?;
        parse_fluxer_role_audit_page(&body, action_type).map_err(|_| FluxerError::Malformed)
    }

    /// One page of the guilds the bot is in, ascending by id, after `after`.
    pub(crate) async fn list_guilds_page(
        &self,
        after: Option<Snowflake>,
    ) -> Result<Vec<Snowflake>, ListError> {
        let authorization = self.authorization().ok_or(ListError::Failed)?;
        let response = self
            .client
            .get(format!("{}{}", self.api_url, guild_list_path(after)))
            .header(AUTHORIZATION, authorization)
            .send()
            .await
            .map_err(|_| ListError::Failed)?;

        match response.status() {
            status if status.is_success() => {}
            StatusCode::TOO_MANY_REQUESTS => {
                return Err(ListError::RateLimited(retry_after(&response)))
            }
            status => {
                log::warn!("fluxer import: listing the bot's guilds answered {status}");
                return Err(ListError::Failed);
            }
        }

        let body = read_capped(response, JSON_BODY_CAP)
            .await
            .map_err(|_| ListError::Failed)?;
        let guilds: Vec<ListedGuild> =
            serde_json::from_slice(&body).map_err(|_| ListError::Failed)?;
        Ok(guilds.into_iter().map(|guild| guild.id).collect())
    }

    /// When the bot joined the guild, from the same `members/@me` read the
    /// import makes (`fetch_bot_roles`), with a 404 and a 429 told apart.
    pub(crate) async fn fetch_bot_joined_at(&self, guild: Snowflake) -> MemberLookup {
        let Some(authorization) = self.authorization() else {
            return MemberLookup::Failed;
        };
        let Ok(response) = self
            .client
            .get(format!("{}{}", self.api_url, member_me_path(guild)))
            .header(AUTHORIZATION, authorization)
            .send()
            .await
        else {
            return MemberLookup::Failed;
        };

        match response.status() {
            status if status.is_success() => {}
            StatusCode::NOT_FOUND => return MemberLookup::NotMember,
            StatusCode::TOO_MANY_REQUESTS => {
                return MemberLookup::RateLimited(retry_after(&response))
            }
            status => {
                log::warn!(
                    "fluxer import: reading the bot's membership of {guild} answered {status}"
                );
                return MemberLookup::Failed;
            }
        }

        let Ok(body) = read_capped(response, JSON_BODY_CAP).await else {
            return MemberLookup::Failed;
        };
        // A member object, with `joined_at` read as any JSON value so a
        // missing or odd one is "not known" rather than an unreadable answer.
        let Ok(Value::Object(member)) = serde_json::from_slice::<Value>(&body) else {
            return MemberLookup::Failed;
        };
        MemberLookup::Member(match member.get("joined_at") {
            Some(Value::String(text)) => Timestamp::parse(text),
            _ => None,
        })
    }

    /// Make the bot leave the guild: `DELETE /v1/users/@me/guilds/{id}`
    /// with an empty JSON object as its body (the route validates a JSON
    /// body on every request).
    ///
    /// A 2xx is left, and so is a 404 (Fluxer's answer, `UNKNOWN_MEMBER`,
    /// whenever the bot holds no membership, whether or not the guild
    /// exists). Anything else is "not left" and the caller asks again later.
    pub(crate) async fn leave_guild(&self, guild: Snowflake) -> LeaveOutcome {
        let Some(authorization) = self.authorization() else {
            return LeaveOutcome::NotLeft;
        };

        let response = match self
            .client
            .delete(format!("{}/v1/users/@me/guilds/{guild}", self.api_url))
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, "application/json")
            .body("{}")
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => {
                log::warn!("fluxer import: could not reach Fluxer to leave guild {guild}");
                return LeaveOutcome::NotLeft;
            }
        };

        let status = response.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            LeaveOutcome::Left
        } else if status == StatusCode::TOO_MANY_REQUESTS {
            LeaveOutcome::RateLimited(retry_after(&response))
        } else {
            log::warn!("fluxer import: leaving guild {guild} answered {status}");
            LeaveOutcome::NotLeft
        }
    }
}

/// `GET /v1/guilds/{id}/audit-logs` for one action type, from `after` on.
pub(crate) fn audit_path(guild: Snowflake, action_type: u8, after: u64) -> String {
    format!(
        "/v1/guilds/{guild}/audit-logs?action_type={action_type}&after={after}&limit={FLUXER_AUDIT_PAGE_LIMIT}"
    )
}

/// `GET /v1/guilds/{id}/members/@me`: the bot's own membership.
pub(crate) fn member_me_path(guild: Snowflake) -> String {
    format!("/v1/guilds/{guild}/members/@me")
}

/// `GET /v1/users/@me/guilds`, from the start or after `after`.
pub(crate) fn guild_list_path(after: Option<Snowflake>) -> String {
    match after {
        Some(after) => format!("/v1/users/@me/guilds?limit={GUILD_LIST_LIMIT}&after={after}"),
        None => format!("/v1/users/@me/guilds?limit={GUILD_LIST_LIMIT}"),
    }
}

// ---------------------------------------------------------------------------
// CDN
// ---------------------------------------------------------------------------

/// Whether `hash` may be put into a CDN path: `(a_)?[0-9a-f]{1,64}`.
fn is_asset_hash(hash: &str) -> bool {
    let digest = hash.strip_prefix("a_").unwrap_or(hash);
    (1..=ASSET_HASH_MAX).contains(&digest.len())
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The CDN URL of `asset` at the size the importer wants, on the configured
/// CDN only:
///
/// - icon: `{cdn}/icons/{guild}/{hash}.png?size=1024` (`.gif` for an `a_`
///   hash)
/// - banner: `{cdn}/banners/{guild}/{hash}.png?size=2400` (`.gif` likewise)
/// - emoji: `{cdn}/emojis/{id}.png?size=512`, or
///   `{cdn}/emojis/{id}.gif?size=512&animated=true` when animated
///
/// `None` (the asset is skipped) when the guild id or emoji id is not a
/// snowflake, the hash fails `(a_)?[0-9a-f]{1,64}`, or `cdn_url` is
/// unusable. Segments are pushed percent-encoded, and the result must still
/// be on the CDN's origin.
pub(crate) fn asset_url(asset: &PlannedAsset, cdn_url: &str, guild_id: &str) -> Option<Url> {
    let cdn = Url::parse(cdn_url).ok()?;
    cdn.host_str()?;

    let mut url = cdn.clone();
    url.set_query(None);
    url.set_fragment(None);

    let size = match asset.kind {
        AssetKind::Icon | AssetKind::Banner => {
            let guild = Snowflake::parse(guild_id)?;
            if !is_asset_hash(&asset.id) {
                return None;
            }
            let extension = if asset.id.starts_with("a_") {
                "gif"
            } else {
                "png"
            };
            let (prefix, size) = match asset.kind {
                AssetKind::Icon => ("icons", ICON_SIZE),
                _ => ("banners", BANNER_SIZE),
            };
            url.path_segments_mut()
                .ok()?
                .pop_if_empty()
                .push(prefix)
                .push(&guild.to_string())
                .push(&format!("{}.{extension}", asset.id));
            size
        }
        AssetKind::Emoji => {
            let id = Snowflake::parse(&asset.id)?;
            let extension = if asset.animated { "gif" } else { "png" };
            url.path_segments_mut()
                .ok()?
                .pop_if_empty()
                .push("emojis")
                .push(&format!("{id}.{extension}"));
            EMOJI_SIZE
        }
    };

    {
        let mut query = url.query_pairs_mut();
        query.append_pair("size", size);
        if asset.kind == AssetKind::Emoji && asset.animated {
            query.append_pair("animated", "true");
        }
    }

    (same_origin(&url, &cdn) && url.host_str() == cdn.host_str()).then_some(url)
}

/// Downloads planned assets from Fluxer's CDN for one guild.
///
/// Carries no credential and follows no redirects. Anything else (an invalid
/// id or hash, another origin, a non-2xx answer, a body over the cap) is
/// `None`, which the worker turns into a note.
pub(crate) struct FluxerAssets {
    client: Option<reqwest::Client>,
    cdn_url: String,
    /// Validated by the caller; checked again by [`asset_url`].
    guild_id: String,
    limits: AssetLimits,
}

impl FluxerAssets {
    pub(crate) fn new(cdn_url: &str, guild: Snowflake, limits: AssetLimits) -> FluxerAssets {
        let client = Url::parse(cdn_url).ok().and_then(|_| {
            client_builder(transport_for(cdn_url))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .ok()
        });

        FluxerAssets {
            client,
            cdn_url: cdn_url.to_string(),
            guild_id: guild.to_string(),
            limits,
        }
    }

    async fn download(&self, asset: &PlannedAsset) -> Option<Vec<u8>> {
        let client = self.client.as_ref()?;
        let Some(url) = asset_url(asset, &self.cdn_url, &self.guild_id) else {
            log::warn!("fluxer import: skipping an asset whose id is not a valid CDN id");
            return None;
        };
        let origin = Url::parse(&self.cdn_url).ok()?;

        let response = client
            .get(url)
            .send()
            .await
            .inspect_err(|_| log::warn!("fluxer import: could not download {}", asset.id))
            .ok()?;

        if !response.status().is_success() || !same_origin(response.url(), &origin) {
            log::warn!(
                "fluxer import: CDN answered {} for {}",
                response.status(),
                asset.id
            );
            return None;
        }

        read_capped(response, self.limits.for_kind(asset.kind))
            .await
            .inspect_err(|error| {
                log::warn!("fluxer import: could not read {}: {error:?}", asset.id)
            })
            .ok()
    }
}

impl AssetFetcher for FluxerAssets {
    fn fetch<'a>(&'a self, asset: &'a PlannedAsset) -> BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move { self.download(asset).await })
    }
}

/// The Fluxer side of the shared loopback fake (`import_http::fake_upstream`).
#[cfg(test)]
pub(crate) mod fake_upstream {
    use revolt_config::ApiImportBotSource;

    pub(crate) use crate::tasks::import_http::fake_upstream::{FakeUpstream, BOT_TOKEN};

    impl FakeUpstream {
        /// A ready `[api.import.fluxer]` whose API is this fake and whose CDN
        /// is `cdn`.
        pub(crate) fn fluxer_config(&self, cdn: &FakeUpstream) -> ApiImportBotSource {
            ApiImportBotSource {
                enabled: true,
                api_url: self.url.clone(),
                app_url: "https://fluxer.example".to_string(),
                cdn_url: cdn.url.clone(),
                bot_id: "1300000000000000999".to_string(),
                bot_token: BOT_TOKEN.to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake_upstream::{FakeUpstream, BOT_TOKEN};
    use super::*;

    const GUILD: Snowflake = Snowflake(1_300_000_000_000_000_011);

    fn api(fake: &FakeUpstream) -> FluxerApi {
        FluxerApi::new(&fake.fluxer_config(fake)).expect("client")
    }

    fn asset(kind: AssetKind, id: &str, animated: bool) -> PlannedAsset {
        PlannedAsset {
            kind,
            id: id.to_string(),
            animated,
        }
    }

    fn limits() -> AssetLimits {
        AssetLimits {
            icon: 1024,
            banner: 1024,
            emoji: 1024,
        }
    }

    #[test]
    fn snowflakes_are_canonical_decimal_u64s() {
        assert_eq!(
            Snowflake::parse("1300000000000000011"),
            Some(Snowflake(1_300_000_000_000_000_011))
        );
        assert_eq!(Snowflake::parse("0"), Some(Snowflake(0)));
        assert_eq!(
            Snowflake::parse("18446744073709551615"),
            Some(Snowflake(u64::MAX))
        );
        for bad in [
            "",
            "01",
            "18446744073709551616",
            "123456789012345678901",
            "12a",
            "-1",
            " 1",
            "1 ",
            "../x",
            "%2e%2e",
        ] {
            assert_eq!(Snowflake::parse(bad), None, "{bad:?}");
        }

        // Fluxer writes ids as strings; a plain integer is accepted too.
        let ids: Vec<Snowflake> = serde_json::from_str(r#"["5", 6]"#).unwrap();
        assert_eq!(ids, vec![Snowflake(5), Snowflake(6)]);
        assert!(serde_json::from_str::<Snowflake>(r#""x""#).is_err());
        assert!(serde_json::from_str::<Snowflake>("null").is_err());
    }

    #[test]
    fn permission_values_never_degrade_to_no_bits() {
        let bits: Vec<Bits> = serde_json::from_str(r#"["1024", 2048, "0"]"#).unwrap();
        assert_eq!(bits, vec![Bits(1024), Bits(2048), Bits(0)]);
        for bad in [
            r#""""#, r#""1e3""#, r#""-1""#, "-1", "1.5", "null", r#""abc""#,
        ] {
            assert!(serde_json::from_str::<Bits>(bad).is_err(), "{bad}");
        }

        // An overwrite missing its deny half, or a channel missing its
        // overwrite list, does not parse.
        assert!(
            serde_json::from_str::<FluxerOverwrite>(r#"{"id":"1","type":0,"allow":"1024"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<FluxerChannel>(r#"{"id":"1","type":0}"#).is_err());
    }

    #[test]
    fn channel_types_of_any_size_parse() {
        for (raw, expected) in [
            ("0", Some(0)),
            ("998", Some(998)),
            ("-3", Some(-3)),
            ("18446744073709551615", None),
        ] {
            let channel: FluxerChannel = serde_json::from_str(&format!(
                r#"{{"id":"1","type":{raw},"permission_overwrites":[]}}"#
            ))
            .unwrap();
            assert_eq!(channel.channel_type, ChannelType(expected), "{raw}");
        }
        for raw in [r#""0""#, "1.5", "null"] {
            assert!(
                serde_json::from_str::<FluxerChannel>(&format!(
                    r#"{{"id":"1","type":{raw},"permission_overwrites":[]}}"#
                ))
                .is_err(),
                "{raw}"
            );
        }
    }

    /// Every API call carries `Authorization: Bot <token>`, under `/v1`.
    #[tokio::test]
    async fn api_calls_carry_the_bot_authorization_under_v1() {
        let fake = FakeUpstream::new()
            .reply(
                "GET",
                &format!("/v1/guilds/{GUILD}"),
                200,
                format!(r#"{{"id":"{GUILD}","name":"G","nsfw":false,"emojis":[]}}"#),
            )
            .reply(
                "GET",
                &format!("/v1/guilds/{GUILD}/members/@me"),
                200,
                r#"{"user":{"id":"9"},"roles":["7","8"]}"#,
            )
            .start()
            .await;
        let api = api(&fake);

        assert_eq!(api.fetch_guild(GUILD).await.unwrap().id, GUILD);
        assert_eq!(
            api.fetch_bot_roles(GUILD).await.unwrap(),
            vec![Snowflake(7), Snowflake(8)]
        );

        let expected = format!("Bot {BOT_TOKEN}");
        let seen = fake.seen();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(seen
            .iter()
            .all(|s| s.header("authorization") == Some(expected.as_str())));
        assert!(seen.iter().all(|s| s.bot_token.is_none()));
    }

    #[tokio::test]
    async fn status_mapping() {
        for (status, guild_error, audit_error) in [
            (
                404,
                FluxerError::BotNotInServer,
                FluxerError::BotNotInServer,
            ),
            (
                401,
                FluxerError::BotNotInServer,
                FluxerError::BotNotInServer,
            ),
            (
                403,
                FluxerError::BotNotInServer,
                FluxerError::AuditLogForbidden,
            ),
            (429, FluxerError::Unavailable, FluxerError::Unavailable),
            (500, FluxerError::Unavailable, FluxerError::Unavailable),
            (503, FluxerError::Unavailable, FluxerError::Unavailable),
            (307, FluxerError::Unavailable, FluxerError::Unavailable),
        ] {
            let fake = FakeUpstream::new()
                .reply("GET", &format!("/v1/guilds/{GUILD}"), status, "{}")
                .reply("GET", &format!("/v1/guilds/{GUILD}/roles"), status, "{}")
                .reply("GET", &format!("/v1/guilds/{GUILD}/channels"), status, "{}")
                .reply(
                    "GET",
                    &format!("/v1/guilds/{GUILD}/members/@me"),
                    status,
                    "{}",
                )
                .reply("GET", &audit_path(GUILD, 30, 5), status, "{}")
                .start()
                .await;
            let api = api(&fake);
            assert_eq!(api.fetch_guild(GUILD).await, Err(guild_error), "{status}");
            assert_eq!(api.fetch_roles(GUILD).await, Err(guild_error), "{status}");
            assert_eq!(
                api.fetch_channels(GUILD).await,
                Err(guild_error),
                "{status}"
            );
            assert_eq!(
                api.fetch_bot_roles(GUILD).await,
                Err(guild_error),
                "{status}"
            );
            assert_eq!(
                api.fetch_audit_page(GUILD, 30, 5).await,
                Err(audit_error),
                "{status}"
            );
            // No retries: one request per call.
            assert_eq!(fake.seen().len(), 5, "{status}");
        }
    }

    #[tokio::test]
    async fn unreadable_answers_are_malformed() {
        let fake = FakeUpstream::new()
            // Another guild in the answer.
            .reply(
                "GET",
                &format!("/v1/guilds/{GUILD}"),
                200,
                r#"{"id":"42","name":"x"}"#,
            )
            // A role without permissions.
            .reply(
                "GET",
                &format!("/v1/guilds/{GUILD}/roles"),
                200,
                r#"[{"id":"1","name":"r"}]"#,
            )
            .reply("GET", &format!("/v1/guilds/{GUILD}/channels"), 200, "{}")
            // Not an audit-log page.
            .reply("GET", &audit_path(GUILD, 31, 5), 200, "[]")
            .start()
            .await;
        let api = api(&fake);
        assert_eq!(api.fetch_guild(GUILD).await, Err(FluxerError::Malformed));
        assert_eq!(api.fetch_roles(GUILD).await, Err(FluxerError::Malformed));
        assert_eq!(api.fetch_channels(GUILD).await, Err(FluxerError::Malformed));
        assert_eq!(
            api.fetch_audit_page(GUILD, 31, 5).await,
            Err(FluxerError::Malformed)
        );
    }

    #[tokio::test]
    async fn api_redirects_are_not_followed() {
        let fake = FakeUpstream::new()
            .redirect(&format!("/v1/guilds/{GUILD}/roles"), "/elsewhere")
            .reply("GET", "/elsewhere", 200, "[]")
            .start()
            .await;
        assert_eq!(
            api(&fake).fetch_roles(GUILD).await,
            Err(FluxerError::Unavailable)
        );
        assert_eq!(fake.seen().len(), 1, "{:?}", fake.seen());
    }

    #[tokio::test]
    async fn production_transport_refuses_plain_http() {
        let fake = FakeUpstream::new()
            .reply("GET", &format!("/v1/guilds/{GUILD}/roles"), 200, "[]")
            .start()
            .await;
        let api =
            FluxerApi::build(&fake.fluxer_config(&fake), Transport::Production).expect("client");
        assert_eq!(api.fetch_roles(GUILD).await, Err(FluxerError::Unavailable));
        assert!(fake.seen().is_empty(), "{:?}", fake.seen());
    }

    #[test]
    fn no_client_without_a_token_or_an_api_url() {
        let fake = FakeUpstream::new();
        let mut config = fake.fluxer_config(&fake);
        config.api_url = "http://127.0.0.1:1".to_string();
        config.bot_token = String::new();
        assert!(FluxerApi::new(&config).is_none());
        config.bot_token = BOT_TOKEN.to_string();
        config.api_url = String::new();
        assert!(FluxerApi::new(&config).is_none());
    }

    /// The leave is a `DELETE` with an empty JSON object as its body; 2xx
    /// and 404 are left, 429 carries its `Retry-After`, anything else is not
    /// left.
    #[tokio::test]
    async fn leave_request_shape_and_outcomes() {
        let path = format!("/v1/users/@me/guilds/{GUILD}");
        for (status, expected) in [
            (204, LeaveOutcome::Left),
            (200, LeaveOutcome::Left),
            (404, LeaveOutcome::Left),
            (403, LeaveOutcome::NotLeft),
            (400, LeaveOutcome::NotLeft),
            (500, LeaveOutcome::NotLeft),
            (307, LeaveOutcome::NotLeft),
            (429, LeaveOutcome::RateLimited(Some(Duration::from_secs(3)))),
        ] {
            let fake = FakeUpstream::new()
                .reply_with_headers("DELETE", &path, status, "", &[("Retry-After", "3")])
                .start()
                .await;
            assert_eq!(api(&fake).leave_guild(GUILD).await, expected, "{status}");

            let seen = fake.seen();
            assert_eq!(seen.len(), 1, "{status}: {seen:?}");
            assert_eq!(seen[0].method, "DELETE");
            assert_eq!(seen[0].path, path);
            assert_eq!(seen[0].body, b"{}");
            assert_eq!(seen[0].header("content-type"), Some("application/json"));
            assert_eq!(
                seen[0].header("authorization"),
                Some(format!("Bot {BOT_TOKEN}").as_str())
            );
        }
    }

    /// `joined_at` is read from the same `members/@me` route the import
    /// uses; a missing or unreadable one is "not known", a 404 is "not a
    /// member", a 429 carries its `Retry-After`.
    #[tokio::test]
    async fn bot_join_time_lookup() {
        let path = member_me_path(GUILD);
        assert_eq!(path, format!("/v1/guilds/{GUILD}/members/@me"));
        for (status, body, expected) in [
            (
                200,
                r#"{"roles":[],"joined_at":"2026-10-15T08:30:00.123Z"}"#,
                MemberLookup::Member(Timestamp::parse("2026-10-15T08:30:00.123Z")),
            ),
            (200, r#"{"roles":[]}"#, MemberLookup::Member(None)),
            (200, r#"{"joined_at":null}"#, MemberLookup::Member(None)),
            (
                200,
                r#"{"joined_at":"yesterday"}"#,
                MemberLookup::Member(None),
            ),
            (
                200,
                r#"{"joined_at":1760000000}"#,
                MemberLookup::Member(None),
            ),
            (200, "not json", MemberLookup::Failed),
            (200, "[]", MemberLookup::Failed),
            (404, r#"{"code":"UNKNOWN_MEMBER"}"#, MemberLookup::NotMember),
            (
                429,
                "{}",
                MemberLookup::RateLimited(Some(Duration::from_secs(3))),
            ),
            (401, "{}", MemberLookup::Failed),
            (403, "{}", MemberLookup::Failed),
            (500, "{}", MemberLookup::Failed),
        ] {
            let fake = FakeUpstream::new()
                .reply_with_headers("GET", &path, status, body, &[("Retry-After", "3")])
                .start()
                .await;
            assert_eq!(
                api(&fake).fetch_bot_joined_at(GUILD).await,
                expected,
                "{status} {body}"
            );
            let seen = fake.seen();
            assert_eq!(seen.len(), 1, "{status}: {seen:?}");
            assert_eq!(seen[0].method, "GET");
            assert_eq!(
                seen[0].header("authorization"),
                Some(format!("Bot {BOT_TOKEN}").as_str())
            );
        }
        assert!(Timestamp::parse("2026-10-15T08:30:00.123Z").is_some());
    }

    #[tokio::test]
    async fn guild_list_pages_and_rate_limits() {
        let fake = FakeUpstream::new()
            .reply(
                "GET",
                &guild_list_path(None),
                200,
                r#"[{"id":"5","name":"a"},{"id":"9"}]"#,
            )
            .reply_with_headers(
                "GET",
                &guild_list_path(Some(Snowflake(9))),
                429,
                "{}",
                &[("Retry-After", "2")],
            )
            .reply("GET", &guild_list_path(Some(Snowflake(10))), 200, "[{}]")
            .start()
            .await;
        let api = api(&fake);
        assert_eq!(
            api.list_guilds_page(None).await,
            Ok(vec![Snowflake(5), Snowflake(9)])
        );
        assert_eq!(
            api.list_guilds_page(Some(Snowflake(9))).await,
            Err(ListError::RateLimited(Some(Duration::from_secs(2))))
        );
        assert_eq!(
            api.list_guilds_page(Some(Snowflake(10))).await,
            Err(ListError::Failed)
        );
        assert_eq!(
            fake.seen()[0].path,
            "/v1/users/@me/guilds?limit=200",
            "{:?}",
            fake.seen()
        );
    }

    // ---- CDN ----

    #[test]
    fn asset_urls_carry_size_and_animated() {
        let cdn = "https://fluxerusercontent.com";
        let guild = "1300000000000000011";
        let url = |asset: &PlannedAsset| asset_url(asset, cdn, guild).map(|u| u.to_string());

        assert_eq!(
            url(&asset(AssetKind::Icon, "0a1b2c", false)).as_deref(),
            Some("https://fluxerusercontent.com/icons/1300000000000000011/0a1b2c.png?size=1024")
        );
        assert_eq!(
            url(&asset(AssetKind::Icon, "a_0a1b2c", true)).as_deref(),
            Some("https://fluxerusercontent.com/icons/1300000000000000011/a_0a1b2c.gif?size=1024")
        );
        assert_eq!(
            url(&asset(AssetKind::Banner, "ff", false)).as_deref(),
            Some("https://fluxerusercontent.com/banners/1300000000000000011/ff.png?size=2400")
        );
        assert_eq!(
            url(&asset(AssetKind::Banner, "a_ff", true)).as_deref(),
            Some("https://fluxerusercontent.com/banners/1300000000000000011/a_ff.gif?size=2400")
        );
        assert_eq!(
            url(&asset(AssetKind::Emoji, "1300000000000000077", false)).as_deref(),
            Some("https://fluxerusercontent.com/emojis/1300000000000000077.png?size=512")
        );
        assert_eq!(
            url(&asset(AssetKind::Emoji, "1300000000000000077", true)).as_deref(),
            Some(
                "https://fluxerusercontent.com/emojis/1300000000000000077.gif?size=512&animated=true"
            )
        );
        // A CDN base with a path keeps it.
        assert_eq!(
            asset_url(
                &asset(AssetKind::Emoji, "7", false),
                "https://cdn.example/media/",
                guild
            )
            .unwrap()
            .as_str(),
            "https://cdn.example/media/emojis/7.png?size=512"
        );
    }

    #[test]
    fn hostile_asset_ids_are_rejected() {
        let cdn = "https://fluxerusercontent.com";
        let guild = "1300000000000000011";
        let overlong = "a".repeat(ASSET_HASH_MAX + 1);
        for hostile in [
            "../x",
            "%2e%2e",
            "a_zz",
            "a_",
            "",
            "..",
            "a/b",
            "ab?c",
            "ab#c",
            "AB",
            "a_AB",
            "b_ab",
            "ab.png",
            overlong.as_str(),
        ] {
            for kind in [AssetKind::Icon, AssetKind::Banner] {
                assert_eq!(
                    asset_url(&asset(kind, hostile, false), cdn, guild),
                    None,
                    "{hostile:?}"
                );
            }
            assert_eq!(
                asset_url(&asset(AssetKind::Emoji, hostile, false), cdn, guild),
                None,
                "{hostile:?}"
            );
        }
        assert!(asset_url(&asset(AssetKind::Icon, &"f".repeat(64), false), cdn, guild).is_some());

        // A guild id that is not a snowflake is never put into a path.
        for guild in ["", "../x", "%2e%2e", "12a", "0012", "1/2"] {
            assert_eq!(
                asset_url(&asset(AssetKind::Icon, "ab", false), cdn, guild),
                None,
                "{guild:?}"
            );
        }
        assert_eq!(
            asset_url(&asset(AssetKind::Icon, "ab", false), "not a url", "1"),
            None
        );
    }

    #[tokio::test]
    async fn hostile_assets_are_never_requested_and_downloads_carry_no_token() {
        let cdn = FakeUpstream::new()
            .reply(
                "GET",
                &format!("/icons/{GUILD}/abc.png?size=1024"),
                200,
                vec![1u8; 10],
            )
            .reply(
                "GET",
                "/emojis/77.gif?size=512&animated=true",
                200,
                vec![2u8; 10],
            )
            .redirect(
                "/emojis/78.png?size=512",
                "/emojis/77.gif?size=512&animated=true",
            )
            .reply("GET", "/emojis/79.png?size=512", 200, vec![0u8; 1025])
            .start()
            .await;
        let assets = FluxerAssets::new(&cdn.url, GUILD, limits());

        for hostile in ["../x", "%2e%2e", "a_zz"] {
            assert_eq!(
                assets.fetch(&asset(AssetKind::Icon, hostile, false)).await,
                None
            );
            assert_eq!(
                assets.fetch(&asset(AssetKind::Emoji, hostile, false)).await,
                None
            );
        }
        assert!(cdn.seen().is_empty(), "{:?}", cdn.seen());

        assert_eq!(
            assets.fetch(&asset(AssetKind::Icon, "abc", false)).await,
            Some(vec![1u8; 10])
        );
        assert_eq!(
            assets.fetch(&asset(AssetKind::Emoji, "77", true)).await,
            Some(vec![2u8; 10])
        );
        // No redirect is followed, even on the same origin.
        assert_eq!(
            assets.fetch(&asset(AssetKind::Emoji, "78", false)).await,
            None
        );
        // Over the cap.
        assert_eq!(
            assets.fetch(&asset(AssetKind::Emoji, "79", false)).await,
            None
        );

        let seen = cdn.seen();
        assert_eq!(seen.len(), 4, "{seen:?}");
        assert!(
            seen.iter().all(|s| s.header("authorization").is_none()),
            "{seen:?}"
        );
    }
}
