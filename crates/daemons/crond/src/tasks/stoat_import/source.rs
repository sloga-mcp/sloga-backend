//! Stoat API and CDN client for the importer.
//!
//! Everything here talks to hosts named in `[api.import.stoat]` only. The
//! API client carries the bot token (`x-bot-token`, marked sensitive, never
//! logged) and follows no redirects at all. The CDN client carries no
//! credential and follows at most one redirect, and only within the
//! configured CDN origin (see [`StoatAssets`]).
//!
//! Upstream budget per import: one server fetch (channels included), one
//! emoji fetch, the CDN downloads, and one leave. Stoat's `servers` bucket is
//! 5 requests / 10 s per bot and server, and delta's verification already
//! spent some of it, so nothing here retries: a 429 is "Stoat is
//! unavailable", and the user tries again.
//!
//! Every response body is read through a size cap, aborting as soon as it is
//! exceeded. The transport, timeouts, user agent, capped read and asset caps
//! are shared with the other source importers (`tasks::import_http`).
//!
//! Wire types are read permissively (unknown fields ignored, cosmetic fields
//! optional) except permission values: a role or channel override whose
//! `a`/`d` cannot be read fails the import rather than defaulting to "no
//! deny", which is how a private channel would become public.

use std::collections::HashMap;
use std::fmt;

use futures::future::BoxFuture;
use reqwest::header::HeaderValue;
use reqwest::{StatusCode, Url};
use revolt_config::ApiImportBotSource;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;

use crate::tasks::discord_import::assets::AssetFetcher;
use crate::tasks::discord_import::mapper::{AssetKind, PlannedAsset};
pub(crate) use crate::tasks::import_http::AssetLimits;
use crate::tasks::import_http::{
    client_builder, read_capped, same_origin, same_origin_redirects, transport_for, ReadError,
    Transport,
};

/// Largest JSON body read from the API. A server with 200 channels, each
/// with a full set of role overrides, is well under 1 MiB.
pub(crate) const JSON_BODY_CAP: usize = 4 * 1024 * 1024;

/// Longest server id accepted into an API path: `[A-Za-z0-9]{1,32}`, the
/// same whitelist delta applies to what the user pasted.
const SERVER_ID_MAX: usize = 32;

/// Longest asset id accepted into a CDN path: `[A-Za-z0-9_-]{1,64}`.
const ASSET_ID_MAX: usize = 64;

/// Redirects the CDN client follows, all within the CDN origin. Autumn
/// answers `/{tag}/{id}/original` with one relative redirect to the stored
/// filename.
const MAX_CDN_REDIRECTS: usize = 1;

/// Why a Stoat API call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoatError {
    /// 401, 403 or 404: the bot is not in that server (Stoat does not let a
    /// non-member tell "no such server" apart from "not a member").
    BotNotInServer,
    /// 429, 5xx, any other unexpected status, a redirect, a timeout or a
    /// transport failure. Retry later.
    Unavailable,
    /// The answer could not be read: not the expected JSON, a different
    /// server, permission values in an unknown shape, or over the size cap.
    Malformed,
    /// The server id failed the path whitelist; nothing was sent.
    InvalidId,
}

impl StoatError {
    /// User-safe message stored on the job.
    pub(crate) fn user_message(&self) -> String {
        match self {
            StoatError::BotNotInServer => {
                "The Sloga importer bot can't see your Stoat server anymore. Make sure the bot is \
                 still a member of the server, then start the import again."
            }
            StoatError::Unavailable => {
                "We couldn't reach Stoat right now, or Stoat is rate-limiting us. Please try \
                 again in a few minutes."
            }
            StoatError::Malformed => {
                "Stoat returned a server we couldn't read. Please report this if it keeps \
                 happening."
            }
            StoatError::InvalidId => {
                "Something went wrong while importing your server. Please try again."
            }
        }
        .to_string()
    }
}

/// Whether `id` may be put into an API path: `[A-Za-z0-9]{1,32}`.
pub(crate) fn is_server_id(id: &str) -> bool {
    (1..=SERVER_ID_MAX).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Whether `id` may be put into a CDN path: `[A-Za-z0-9_-]{1,64}`.
pub(crate) fn is_asset_id(id: &str) -> bool {
    (1..=ASSET_ID_MAX).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// ---------------------------------------------------------------------------
// Wire types (Stoat API v0, which is this codebase's upstream)
// ---------------------------------------------------------------------------

/// A permission override as Stoat stores it. Both halves are required.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StoatOverride {
    pub a: i64,
    pub d: i64,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoatRole {
    #[serde(default)]
    pub name: Option<String>,
    pub permissions: StoatOverride,
    #[serde(default)]
    pub colour: Option<String>,
    #[serde(default)]
    pub hoist: Option<bool>,
    #[serde(default)]
    pub rank: Option<i64>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct StoatCategory {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub channels: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct StoatSystemMessages {
    #[serde(default)]
    pub user_joined: Option<String>,
    #[serde(default)]
    pub user_left: Option<String>,
    #[serde(default)]
    pub user_kicked: Option<String>,
    #[serde(default)]
    pub user_banned: Option<String>,
}

/// An autumn file as embedded in a server (icon, banner).
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoatFile {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(default)]
    pub content_type: Option<String>,
}

/// `GET /servers/{id}`, minus the channel list (see [`FetchedServer`]).
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoatServer {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Every channel id in the server, in order, whether or not the bot can
    /// see it. Filled from the response's first `channels` array.
    #[serde(skip)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub categories: Option<Vec<StoatCategory>>,
    #[serde(default)]
    pub system_messages: Option<StoatSystemMessages>,
    #[serde(default)]
    pub roles: Option<HashMap<String, StoatRole>>,
    /// Required: the server baseline is never guessed.
    pub default_permissions: i64,
    #[serde(default)]
    pub icon: Option<StoatFile>,
    #[serde(default)]
    pub banner: Option<StoatFile>,
    #[serde(default)]
    pub nsfw: Option<bool>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct StoatVoice {
    #[serde(default)]
    pub max_users: Option<u64>,
}

/// A `TextChannel` (a voice channel is one with `voice` set).
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoatTextChannel {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default_permissions: Option<StoatOverride>,
    #[serde(default)]
    pub role_permissions: Option<HashMap<String, StoatOverride>>,
    #[serde(default)]
    pub nsfw: Option<bool>,
    #[serde(default)]
    pub voice: Option<StoatVoice>,
    #[serde(default)]
    pub slowmode: Option<u64>,
}

/// One entry of the response's channel list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoatChannel {
    Text(StoatTextChannel),
    /// A channel type this importer does not know, or a `TextChannel` that
    /// could not be read. Skipped with a note.
    Unsupported {
        id: Option<String>,
        channel_type: String,
    },
}

impl StoatChannel {
    pub(crate) fn id(&self) -> Option<&str> {
        match self {
            StoatChannel::Text(channel) => Some(&channel.id),
            StoatChannel::Unsupported { id, .. } => id.as_deref(),
        }
    }

    pub(crate) fn from_value(value: Value) -> StoatChannel {
        let channel_type = value
            .get("channel_type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let id = value.get("_id").and_then(Value::as_str).map(String::from);

        if channel_type == "TextChannel" {
            if let Ok(channel) = serde_json::from_value::<StoatTextChannel>(value) {
                return StoatChannel::Text(channel);
            }
        }

        StoatChannel::Unsupported { id, channel_type }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoatEmoji {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub animated: Option<bool>,
}

/// `GET /servers/{id}?include_channels=true`, split into its two halves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FetchedServer {
    pub server: StoatServer,
    /// The channels the bot can see (the route filters by its ViewChannel).
    pub channels: Vec<StoatChannel>,
}

/// A JSON object's entries in order, duplicates kept.
struct Entries(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for Entries {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EntriesVisitor;

        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = Entries;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Entries, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry::<String, Value>()? {
                    entries.push(entry);
                }
                Ok(Entries(entries))
            }
        }

        deserializer.deserialize_map(EntriesVisitor)
    }
}

/// Read a `GET /servers/{id}?include_channels=true` body.
///
/// The response flattens the server object next to the channel list
/// (`FetchServerResponse::ServerWithChannels`, `#[serde(flatten)]`), and the
/// server object has a `channels` field of its own. So the body carries the
/// key `channels` TWICE: first the server's full id list, then the channel
/// objects the bot can see. A plain struct parse rejects that (duplicate
/// field) and a JSON map keeps only the last, which would lose the id list
/// the hidden-channel count needs. Hence the entry-by-entry read.
///
/// A single `channels` key is accepted only as an array of channel objects
/// (if Stoat ever stops duplicating the key); a lone id list means the
/// channels were not included, which is refused.
pub(crate) fn parse_server_response(body: &[u8]) -> Result<FetchedServer, StoatError> {
    let Entries(entries) = serde_json::from_slice(body).map_err(|_| StoatError::Malformed)?;

    let mut fields = serde_json::Map::new();
    let mut channel_lists: Vec<Value> = Vec::new();
    for (key, value) in entries {
        if key == "channels" {
            channel_lists.push(value);
        } else {
            fields.insert(key, value);
        }
    }

    let into_array = |value: Value| match value {
        Value::Array(items) => Ok(items),
        _ => Err(StoatError::Malformed),
    };

    let (ids, objects) = match channel_lists.len() {
        2 => {
            let objects = into_array(channel_lists.pop().expect("two lists"))?;
            let ids = into_array(channel_lists.pop().expect("two lists"))?;
            let ids = ids
                .into_iter()
                .map(|id| match id {
                    Value::String(id) => Ok(id),
                    _ => Err(StoatError::Malformed),
                })
                .collect::<Result<Vec<String>, StoatError>>()?;
            (Some(ids), objects)
        }
        1 => (None, into_array(channel_lists.pop().expect("one list"))?),
        _ => return Err(StoatError::Malformed),
    };

    // Also what refuses a lone id list: the channels were not included.
    if !objects.iter().all(Value::is_object) {
        return Err(StoatError::Malformed);
    }
    let channels: Vec<StoatChannel> = objects.into_iter().map(StoatChannel::from_value).collect();

    let mut server: StoatServer =
        serde_json::from_value(Value::Object(fields)).map_err(|_| StoatError::Malformed)?;
    // Without the id list nothing is known to be hidden.
    server.channels = ids.unwrap_or_else(|| {
        channels
            .iter()
            .filter_map(|channel| channel.id().map(String::from))
            .collect()
    });

    Ok(FetchedServer { server, channels })
}

// ---------------------------------------------------------------------------
// API client
// ---------------------------------------------------------------------------

/// Stoat API client acting as the operator bot.
///
/// No `Debug`: the token must not reach a log line.
pub(crate) struct StoatApi {
    client: reqwest::Client,
    api_url: String,
    bot_token: String,
}

impl StoatApi {
    /// Client for `[api.import.stoat]`, or `None` when it has no API URL or
    /// no bot token (nothing could be sent).
    pub(crate) fn new(config: &ApiImportBotSource) -> Option<StoatApi> {
        StoatApi::build(config, transport_for(&config.api_url))
    }

    fn build(config: &ApiImportBotSource, transport: Transport) -> Option<StoatApi> {
        if config.api_url.is_empty() || config.bot_token.is_empty() {
            return None;
        }

        let client = client_builder(transport)
            // The token rides every request: never follow a redirect.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;

        Some(StoatApi {
            client,
            api_url: config.api_url.trim_end_matches('/').to_string(),
            bot_token: config.bot_token.clone(),
        })
    }

    fn token(&self) -> Result<HeaderValue, StoatError> {
        let mut token =
            HeaderValue::from_str(&self.bot_token).map_err(|_| StoatError::Unavailable)?;
        token.set_sensitive(true);
        Ok(token)
    }

    /// `GET {path}` as the bot, returning the capped body of a 2xx answer.
    async fn get_json(&self, path: &str) -> Result<Vec<u8>, StoatError> {
        let response = self
            .client
            .get(format!("{}{path}", self.api_url))
            .header("x-bot-token", self.token()?)
            .send()
            .await
            .map_err(|_| StoatError::Unavailable)?;

        match response.status() {
            status if status.is_success() => {}
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => {
                return Err(StoatError::BotNotInServer)
            }
            _ => return Err(StoatError::Unavailable),
        }

        read_capped(response, JSON_BODY_CAP)
            .await
            .map_err(|error| match error {
                ReadError::TooLarge => StoatError::Malformed,
                ReadError::Transport => StoatError::Unavailable,
            })
    }

    /// The server and every channel the bot can see, in ONE request.
    pub(crate) async fn fetch_server(&self, server_id: &str) -> Result<FetchedServer, StoatError> {
        if !is_server_id(server_id) {
            return Err(StoatError::InvalidId);
        }

        let body = self
            .get_json(&format!("/servers/{server_id}?include_channels=true"))
            .await?;
        let fetched = parse_server_response(&body)?;

        if fetched.server.id != server_id {
            return Err(StoatError::Malformed);
        }
        Ok(fetched)
    }

    /// The server's custom emoji (membership is all the route requires).
    pub(crate) async fn fetch_emojis(
        &self,
        server_id: &str,
    ) -> Result<Vec<StoatEmoji>, StoatError> {
        if !is_server_id(server_id) {
            return Err(StoatError::InvalidId);
        }

        let body = self
            .get_json(&format!("/servers/{server_id}/emojis"))
            .await?;
        serde_json::from_slice(&body).map_err(|_| StoatError::Malformed)
    }

    /// Make the bot leave the server. `DELETE /servers/{id}` as a non-owner
    /// is a leave (the bot cannot own a Stoat server: bots cannot create
    /// one), sent with `leave_silently` so no "left" message is posted.
    ///
    /// Returns whether the bot is now out: a 2xx, and also a 404 (Stoat's
    /// answer when the server is gone or the bot is not a member). Anything
    /// else is "not left", and the sweeper's leave retry asks again until
    /// its give-up. That includes 403: Stoat does not send it for a
    /// non-member, so it means something stood in the way (an edge block,
    /// a disabled bot) and the bot may well still be in the server.
    pub(crate) async fn leave_server(&self, server_id: &str) -> bool {
        if !is_server_id(server_id) {
            return false;
        }

        let Ok(token) = self.token() else {
            return false;
        };

        let response = match self
            .client
            .delete(format!(
                "{}/servers/{server_id}?leave_silently=true",
                self.api_url
            ))
            .header("x-bot-token", token)
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => {
                log::warn!("stoat import: could not reach Stoat to leave server {server_id}");
                return false;
            }
        };

        let status = response.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            true
        } else {
            log::warn!("stoat import: leaving server {server_id} answered {status}");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// CDN
// ---------------------------------------------------------------------------

/// Autumn tag a planned asset is stored under on Stoat's CDN (the same tags
/// as this codebase's autumn: `icons`, `banners`, `emojis`).
fn cdn_tag(kind: AssetKind) -> &'static str {
    match kind {
        AssetKind::Icon => "icons",
        AssetKind::Banner => "banners",
        AssetKind::Emoji => "emojis",
    }
}

/// The CDN URL of the ORIGINAL file behind `asset`, on the configured CDN
/// only: `{cdn_url}/{tag}/{id}/original`.
///
/// `None` (the asset is skipped) when the id fails `[A-Za-z0-9_-]{1,64}` or
/// `cdn_url` is unusable. The id is pushed as a percent-encoded path
/// segment, and the result must still have the CDN's origin.
///
/// `original` rather than the bare `{tag}/{id}`: the bare path is a
/// downscaled preview (icons at 128 px) and redirects for animated images.
pub(crate) fn asset_url(asset: &PlannedAsset, cdn_url: &str) -> Option<Url> {
    if !is_asset_id(&asset.id) {
        return None;
    }

    let cdn = Url::parse(cdn_url).ok()?;
    cdn.host_str()?;

    let mut url = cdn.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.path_segments_mut()
        .ok()?
        .pop_if_empty()
        .push(cdn_tag(asset.kind))
        .push(&asset.id)
        .push("original");

    same_origin(&url, &cdn).then_some(url)
}

/// Downloads planned assets from Stoat's CDN.
///
/// Carries no credential. Follows at most one redirect, and only when it
/// stays on the configured CDN origin: autumn's `/original` is a relative
/// redirect to the stored filename, and an emoji object carries no filename
/// to request directly. Anything else (an invalid id, another origin, a
/// second hop, a non-2xx answer, a body over the cap) is `None`, which the
/// worker turns into a note.
pub(crate) struct StoatAssets {
    client: Option<reqwest::Client>,
    cdn_url: String,
    limits: AssetLimits,
}

impl StoatAssets {
    pub(crate) fn new(cdn_url: &str, limits: AssetLimits) -> StoatAssets {
        let client = Url::parse(cdn_url).ok().and_then(|origin| {
            client_builder(transport_for(cdn_url))
                .redirect(same_origin_redirects(origin, MAX_CDN_REDIRECTS))
                .build()
                .ok()
        });

        StoatAssets {
            client,
            cdn_url: cdn_url.to_string(),
            limits,
        }
    }

    async fn download(&self, asset: &PlannedAsset) -> Option<Vec<u8>> {
        let client = self.client.as_ref()?;
        let Some(url) = asset_url(asset, &self.cdn_url) else {
            log::warn!("stoat import: skipping an asset whose id is not a valid CDN id");
            return None;
        };
        let origin = Url::parse(&self.cdn_url).ok()?;

        let response = client
            .get(url)
            .send()
            .await
            .inspect_err(|_| log::warn!("stoat import: could not download {}", asset.id))
            .ok()?;

        if !response.status().is_success() || !same_origin(response.url(), &origin) {
            log::warn!(
                "stoat import: CDN answered {} for {}",
                response.status(),
                asset.id
            );
            return None;
        }

        read_capped(response, self.limits.for_kind(asset.kind))
            .await
            .inspect_err(|error| log::warn!("stoat import: could not read {}: {error:?}", asset.id))
            .ok()
    }
}

impl AssetFetcher for StoatAssets {
    fn fetch<'a>(&'a self, asset: &'a PlannedAsset) -> BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move { self.download(asset).await })
    }
}

/// The Stoat side of the shared loopback fake (`import_http::fake_upstream`),
/// at the path the Stoat and worker tests import it from.
#[cfg(test)]
pub(crate) mod fake_upstream {
    use revolt_config::ApiImportBotSource;

    pub(crate) use crate::tasks::import_http::fake_upstream::{
        FakeUpstream as FakeStoat, BOT_TOKEN,
    };

    impl FakeStoat {
        /// A ready `[api.import.stoat]` whose API is this fake and whose CDN
        /// is `cdn`.
        pub(crate) fn source_config(&self, cdn: &FakeStoat) -> ApiImportBotSource {
            ApiImportBotSource {
                enabled: true,
                api_url: self.url.clone(),
                app_url: "https://stoat.example".to_string(),
                cdn_url: cdn.url.clone(),
                bot_id: "01BOT000000000000000000000".to_string(),
                bot_token: BOT_TOKEN.to_string(),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::fake_upstream::{FakeStoat, BOT_TOKEN};
    use super::*;

    pub(crate) const SERVER: &str = "01HSERVER00000000000000000";

    /// A 1x1 RGBA PNG.
    pub(crate) const PNG_1X1: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    pub(crate) fn server_path() -> String {
        format!("/servers/{SERVER}?include_channels=true")
    }

    /// A `?include_channels=true` body shaped as this codebase serializes it:
    /// the server's id list under `channels`, then the visible channel
    /// objects under `channels` again.
    pub(crate) fn server_body(description: &str) -> String {
        format!(
            r#"{{"_id":"{SERVER}","owner":"01OWNER","name":"Stoat Place","description":{},"channels":["01CHANA","01CHANB"],"default_permissions":0,"channels":[{{"channel_type":"TextChannel","_id":"01CHANA","server":"{SERVER}","name":"general"}}]}}"#,
            serde_json::to_string(description).unwrap()
        )
    }

    fn api(fake: &FakeStoat) -> StoatApi {
        StoatApi::new(&fake.source_config(fake)).expect("client")
    }

    fn icon(id: &str) -> PlannedAsset {
        PlannedAsset {
            kind: AssetKind::Icon,
            id: id.to_string(),
            animated: false,
        }
    }

    fn limits() -> AssetLimits {
        AssetLimits {
            icon: 1024,
            banner: 1024,
            emoji: 1024,
        }
    }

    /// The fixture this module's tests use must be what this codebase's own
    /// `FetchServerResponse::ServerWithChannels` actually puts on the wire:
    /// serialize the real model and read it back.
    #[test]
    fn reads_the_include_channels_shape_this_codebase_serializes() {
        use revolt_models::v0;

        let server: v0::Server = serde_json::from_value(serde_json::json!({
            "_id": SERVER, "owner": "01OWNER", "name": "Stoat Place",
            "description": "hello", "channels": ["01CHANA", "01CHANB", "01CHANC"],
            "default_permissions": 1234
        }))
        .unwrap();
        let visible: v0::Channel = serde_json::from_value(serde_json::json!({
            "channel_type": "TextChannel", "_id": "01CHANA", "server": SERVER,
            "name": "general", "role_permissions": {"01ROLE": {"a": 1, "d": 2}},
            "voice": {"max_users": 4}
        }))
        .unwrap();
        let body = serde_json::to_vec(&v0::FetchServerResponse::ServerWithChannels {
            server,
            channels: vec![visible],
        })
        .unwrap();

        // The duplicated key is real: both lists are on the wire.
        assert_eq!(
            String::from_utf8_lossy(&body)
                .matches("\"channels\":")
                .count(),
            2
        );

        let fetched = parse_server_response(&body).expect("parsed");
        assert_eq!(fetched.server.id, SERVER);
        assert_eq!(fetched.server.description.as_deref(), Some("hello"));
        assert_eq!(fetched.server.default_permissions, 1234);
        assert_eq!(
            fetched.server.channels,
            vec!["01CHANA", "01CHANB", "01CHANC"]
        );
        assert_eq!(fetched.channels.len(), 1);
        match &fetched.channels[0] {
            StoatChannel::Text(channel) => {
                assert_eq!(channel.id, "01CHANA");
                assert_eq!(channel.voice.as_ref().unwrap().max_users, Some(4));
                assert_eq!(
                    channel.role_permissions.as_ref().unwrap()["01ROLE"],
                    StoatOverride { a: 1, d: 2 }
                );
            }
            other => panic!("expected a text channel, got {other:?}"),
        }
    }

    #[test]
    fn unknown_channel_types_and_unreadable_channels_are_kept_as_unsupported() {
        let body = format!(
            r#"{{"_id":"{SERVER}","channels":["A","B","C"],"default_permissions":0,"channels":[
                {{"channel_type":"Forum","_id":"A"}},
                {{"channel_type":"TextChannel","_id":"B","default_permissions":{{"a":1}}}},
                {{"channel_type":"TextChannel","_id":"C","name":"ok","surprise":true}}
            ]}}"#
        );
        let fetched = parse_server_response(body.as_bytes()).unwrap();
        assert_eq!(
            fetched.channels[0],
            StoatChannel::Unsupported {
                id: Some("A".to_string()),
                channel_type: "Forum".to_string()
            }
        );
        // An override missing its deny half is never read as "no deny".
        assert!(matches!(
            &fetched.channels[1],
            StoatChannel::Unsupported { id: Some(id), .. } if id == "B"
        ));
        assert!(matches!(&fetched.channels[2], StoatChannel::Text(_)));
    }

    #[test]
    fn unreadable_server_answers_are_malformed() {
        for body in [
            // Channels were not included.
            format!(r#"{{"_id":"{SERVER}","channels":["A"],"default_permissions":0}}"#),
            // No baseline permissions.
            format!(r#"{{"_id":"{SERVER}","channels":[],"channels":[]}}"#),
            // A role whose permissions lack a half.
            format!(
                r#"{{"_id":"{SERVER}","channels":[],"default_permissions":0,"channels":[],
                    "roles":{{"R":{{"name":"Mod","permissions":{{"a":3}}}}}}}}"#
            ),
            "[]".to_string(),
            "not json".to_string(),
        ] {
            assert_eq!(
                parse_server_response(body.as_bytes()),
                Err(StoatError::Malformed),
                "{body}"
            );
        }

        // Without a duplicate key, an object list is still accepted.
        let single = format!(
            r#"{{"_id":"{SERVER}","default_permissions":0,"channels":[{{"channel_type":"TextChannel","_id":"A"}}]}}"#
        );
        let fetched = parse_server_response(single.as_bytes()).unwrap();
        assert_eq!(fetched.server.channels, vec!["A"]);
    }

    #[tokio::test]
    async fn one_server_fetch_includes_channels_and_carries_the_token() {
        let fake = FakeStoat::new()
            .reply("GET", &server_path(), 200, server_body("desc"))
            .start()
            .await;

        let fetched = api(&fake).fetch_server(SERVER).await.expect("fetched");
        assert_eq!(fetched.server.channels.len(), 2);
        assert_eq!(fetched.channels.len(), 1);

        let seen = fake.seen();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0].method, "GET");
        assert_eq!(seen[0].path, server_path());
        assert_eq!(seen[0].bot_token.as_deref(), Some(BOT_TOKEN));
    }

    #[tokio::test]
    async fn fetch_status_mapping() {
        for (status, expected) in [
            (404, StoatError::BotNotInServer),
            (403, StoatError::BotNotInServer),
            (401, StoatError::BotNotInServer),
            (429, StoatError::Unavailable),
            (500, StoatError::Unavailable),
            (502, StoatError::Unavailable),
            (503, StoatError::Unavailable),
        ] {
            let fake = FakeStoat::new()
                .reply("GET", &server_path(), status, "{}")
                .reply("GET", &format!("/servers/{SERVER}/emojis"), status, "{}")
                .start()
                .await;
            assert_eq!(
                api(&fake).fetch_server(SERVER).await,
                Err(expected),
                "{status}"
            );
            assert_eq!(
                api(&fake).fetch_emojis(SERVER).await,
                Err(expected),
                "{status}"
            );
            // No retries: exactly one request per call.
            assert_eq!(fake.seen().len(), 2, "{status}: {:?}", fake.seen());
        }
    }

    #[tokio::test]
    async fn a_different_server_in_the_answer_is_malformed() {
        let fake = FakeStoat::new()
            .reply(
                "GET",
                &server_path(),
                200,
                server_body("x").replace(SERVER, "01HOTHER00000000000000000"),
            )
            .start()
            .await;
        assert_eq!(
            api(&fake).fetch_server(SERVER).await,
            Err(StoatError::Malformed)
        );
    }

    #[tokio::test]
    async fn oversize_bodies_are_refused_with_or_without_a_length() {
        // Valid JSON, one byte over the cap.
        let padding = "x".repeat(JSON_BODY_CAP);
        let body = server_body(&padding);
        assert!(body.len() > JSON_BODY_CAP);

        let fake = FakeStoat::new()
            .reply("GET", &server_path(), 200, body.clone())
            .reply_unsized("GET", &format!("/servers/{SERVER}/emojis"), 200, {
                let mut list = String::from("[");
                while list.len() <= JSON_BODY_CAP {
                    list.push_str(r#"{"_id":"01EMOJI","name":"e"},"#);
                }
                list.push_str(r#"{"_id":"01EMOJI","name":"e"}]"#);
                list
            })
            .start()
            .await;

        assert_eq!(
            api(&fake).fetch_server(SERVER).await,
            Err(StoatError::Malformed)
        );
        assert_eq!(
            api(&fake).fetch_emojis(SERVER).await,
            Err(StoatError::Malformed)
        );
    }

    #[tokio::test]
    async fn api_redirects_are_not_followed() {
        // The redirect target would parse; following it is the bug.
        let fake = FakeStoat::new()
            .redirect(&server_path(), "/elsewhere")
            .reply("GET", "/elsewhere", 200, server_body("x"))
            .start()
            .await;
        assert_eq!(
            api(&fake).fetch_server(SERVER).await,
            Err(StoatError::Unavailable)
        );
        assert_eq!(fake.seen().len(), 1, "{:?}", fake.seen());
    }

    #[tokio::test]
    async fn transport_failure_is_unavailable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let fake = FakeStoat::new();
        let mut config = fake.source_config(&fake);
        config.api_url = format!("http://{address}");
        let api = StoatApi::new(&config).expect("client");
        assert_eq!(api.fetch_server(SERVER).await, Err(StoatError::Unavailable));
        assert!(!api.leave_server(SERVER).await);
    }

    #[tokio::test]
    async fn production_transport_refuses_plain_http() {
        let fake = FakeStoat::new()
            .reply("GET", &server_path(), 200, server_body("x"))
            .start()
            .await;
        let api =
            StoatApi::build(&fake.source_config(&fake), Transport::Production).expect("client");
        assert_eq!(api.fetch_server(SERVER).await, Err(StoatError::Unavailable));
        assert!(fake.seen().is_empty(), "{:?}", fake.seen());
    }

    #[test]
    fn no_client_without_a_token_or_an_api_url() {
        let fake = FakeStoat::new();
        let mut config = fake.source_config(&fake);
        config.api_url = "http://127.0.0.1:1".to_string();
        config.bot_token = String::new();
        assert!(StoatApi::new(&config).is_none());
        config.bot_token = BOT_TOKEN.to_string();
        config.api_url = String::new();
        assert!(StoatApi::new(&config).is_none());
    }

    #[tokio::test]
    async fn invalid_server_ids_never_reach_the_network() {
        let fake = FakeStoat::new().start().await;
        let api = api(&fake);
        for id in ["", "../x", "%2e%2e", "a/b", "a?b", "a b", &"A".repeat(33)] {
            assert_eq!(api.fetch_server(id).await, Err(StoatError::InvalidId));
            assert_eq!(api.fetch_emojis(id).await, Err(StoatError::InvalidId));
            assert!(!api.leave_server(id).await);
        }
        assert!(fake.seen().is_empty(), "{:?}", fake.seen());
    }

    #[tokio::test]
    async fn leave_treats_gone_and_not_a_member_as_left() {
        for (status, left) in [
            (204, true),
            (200, true),
            (404, true),
            // Not Stoat's non-member answer: something blocked the leave.
            (403, false),
            (401, false),
            (429, false),
            (500, false),
            (307, false),
        ] {
            let path = format!("/servers/{SERVER}?leave_silently=true");
            let fake = FakeStoat::new()
                .reply("DELETE", &path, status, "")
                .start()
                .await;
            assert_eq!(api(&fake).leave_server(SERVER).await, left, "{status}");

            let seen = fake.seen();
            assert_eq!(seen.len(), 1, "{status}: {seen:?}");
            assert_eq!(seen[0].method, "DELETE");
            assert_eq!(seen[0].path, path);
            assert_eq!(seen[0].bot_token.as_deref(), Some(BOT_TOKEN));
        }
    }

    // ---- CDN ----

    #[test]
    fn asset_urls_are_built_on_the_cdn_only() {
        let cdn = "https://cdn.stoatusercontent.com";
        assert_eq!(
            asset_url(&icon("01ICON_a-b"), cdn).unwrap().as_str(),
            "https://cdn.stoatusercontent.com/icons/01ICON_a-b/original"
        );
        let mut banner = icon("01BANNER");
        banner.kind = AssetKind::Banner;
        assert_eq!(
            asset_url(&banner, "https://cdn.example/media/")
                .unwrap()
                .as_str(),
            "https://cdn.example/media/banners/01BANNER/original"
        );
        let mut emoji = icon("01EMOJI");
        emoji.kind = AssetKind::Emoji;
        assert_eq!(
            asset_url(&emoji, cdn).unwrap().as_str(),
            "https://cdn.stoatusercontent.com/emojis/01EMOJI/original"
        );

        let overlong = "a".repeat(ASSET_ID_MAX + 1);
        for hostile in [
            "../x",
            "..",
            ".",
            "%2e%2e",
            "a/b",
            "a\\b",
            "a?b",
            "a#b",
            "a b",
            "a.b",
            "@evil.example",
            "",
            overlong.as_str(),
        ] {
            assert_eq!(asset_url(&icon(hostile), cdn), None, "{hostile:?}");
        }
        assert!(asset_url(&icon(&"a".repeat(ASSET_ID_MAX)), cdn).is_some());
        assert_eq!(asset_url(&icon("ok"), "not a url"), None);
    }

    #[tokio::test]
    async fn hostile_asset_ids_are_never_requested() {
        let cdn = FakeStoat::new().start().await;
        let assets = StoatAssets::new(&cdn.url, limits());
        for hostile in ["../x", "%2e%2e", "a/b", "..", "a?b"] {
            assert_eq!(assets.fetch(&icon(hostile)).await, None, "{hostile:?}");
        }
        assert!(cdn.seen().is_empty(), "{:?}", cdn.seen());
    }

    #[tokio::test]
    async fn cdn_downloads_carry_no_token_and_follow_one_same_origin_hop() {
        let cdn = FakeStoat::new()
            .redirect("/icons/01ICON/original", "icon.png")
            .reply("GET", "/icons/01ICON/icon.png", 200, PNG_1X1)
            .reply("GET", "/icons/01DIRECT/original", 200, PNG_1X1)
            .start()
            .await;
        let assets = StoatAssets::new(&cdn.url, limits());

        assert_eq!(
            assets.fetch(&icon("01ICON")).await.as_deref(),
            Some(PNG_1X1)
        );
        assert_eq!(
            assets.fetch(&icon("01DIRECT")).await.as_deref(),
            Some(PNG_1X1)
        );

        let seen = cdn.seen();
        assert_eq!(
            seen.iter().map(|s| s.path.as_str()).collect::<Vec<_>>(),
            vec![
                "/icons/01ICON/original",
                "/icons/01ICON/icon.png",
                "/icons/01DIRECT/original"
            ]
        );
        assert!(seen.iter().all(|s| s.bot_token.is_none()), "{seen:?}");
    }

    #[tokio::test]
    async fn cdn_redirects_off_origin_or_past_one_hop_are_not_followed() {
        let elsewhere = FakeStoat::new()
            .reply("GET", "/x.png", 200, PNG_1X1)
            .start()
            .await;
        let cdn = FakeStoat::new()
            .redirect(
                "/icons/01AWAY/original",
                &format!("{}/x.png", elsewhere.url),
            )
            .redirect("/icons/01TWO/original", "hop1")
            .redirect("/icons/01TWO/hop1", "hop2")
            .reply("GET", "/icons/01TWO/hop2", 200, PNG_1X1)
            .start()
            .await;
        let assets = StoatAssets::new(&cdn.url, limits());

        assert_eq!(assets.fetch(&icon("01AWAY")).await, None);
        assert!(elsewhere.seen().is_empty(), "{:?}", elsewhere.seen());

        assert_eq!(assets.fetch(&icon("01TWO")).await, None);
        assert!(
            !cdn.seen().iter().any(|s| s.path == "/icons/01TWO/hop2"),
            "{:?}",
            cdn.seen()
        );
    }

    #[tokio::test]
    async fn cdn_failures_and_oversize_assets_are_none() {
        let big = vec![0u8; 1025];
        let cdn = FakeStoat::new()
            .reply("GET", "/icons/01BIG/original", 200, big.clone())
            .reply_unsized("GET", "/icons/01BIGSTREAM/original", 200, big)
            .reply("GET", "/icons/01ERR/original", 500, "")
            .reply("GET", "/icons/01FIT/original", 200, vec![0u8; 1024])
            .start()
            .await;
        let assets = StoatAssets::new(&cdn.url, limits());

        assert_eq!(assets.fetch(&icon("01BIG")).await, None);
        assert_eq!(assets.fetch(&icon("01BIGSTREAM")).await, None);
        assert_eq!(assets.fetch(&icon("01ERR")).await, None);
        assert_eq!(assets.fetch(&icon("01MISSING")).await, None);
        assert_eq!(
            assets.fetch(&icon("01FIT")).await.map(|b| b.len()),
            Some(1024)
        );
    }

    #[test]
    fn asset_limits_come_from_the_upload_limits() {
        let mut configured = HashMap::new();
        configured.insert("icons".to_string(), 10);
        configured.insert("emojis".to_string(), 30);
        assert_eq!(
            AssetLimits::from_upload_limits(&configured),
            AssetLimits {
                icon: 10,
                banner: 6_000_000,
                emoji: 30
            }
        );
    }
}
