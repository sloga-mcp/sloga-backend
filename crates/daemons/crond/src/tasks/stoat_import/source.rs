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
//! The bot reconcile also opens one events (WebSocket) session an hour to
//! read the bot's own memberships from `Ready`; Stoat has no REST route that
//! lists them. Its URL comes from the API root and must be on the API host,
//! the app host or a subdomain of the app host (see [`events_url_allowed`]).
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
use std::time::Duration;

use futures::future::BoxFuture;
use futures::{SinkExt, Stream, StreamExt};
use iso8601_timestamp::Timestamp;
use reqwest::header::{
    HeaderValue, CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION,
    UPGRADE,
};
use reqwest::{StatusCode, Url};
use revolt_config::ApiImportBotSource;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

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

    /// The bot's own user id (`GET /users/@me`, the `users` bucket).
    pub(crate) async fn fetch_self_id(&self) -> Result<String, StoatError> {
        #[derive(Deserialize)]
        struct Me {
            #[serde(rename = "_id")]
            id: String,
        }

        let body = self.get_json("/users/@me").await?;
        let me: Me = serde_json::from_slice(&body).map_err(|_| StoatError::Malformed)?;
        // User and server ids share one shape.
        if !is_server_id(&me.id) {
            return Err(StoatError::Malformed);
        }
        Ok(me.id)
    }

    /// The events URL the API root advertises (`GET /` → `ws`), if it is
    /// one the token may be sent to (see [`events_url_allowed`]).
    async fn events_url(&self, app_url: &str) -> Result<Url, StoatError> {
        #[derive(Deserialize)]
        struct Root {
            ws: String,
        }

        let body = self.get_json("/").await?;
        let root: Root = serde_json::from_slice(&body).map_err(|_| StoatError::Malformed)?;
        let url = Url::parse(&root.ws).map_err(|_| StoatError::Malformed)?;
        if !events_url_allowed(&url, &self.api_url, app_url) {
            log::warn!(
                "stoat import: the API advertises events at {url}, which is not on the API or \
                 app host; the bot will not send its token there"
            );
            return Err(StoatError::Malformed);
        }
        Ok(url)
    }

    /// Every server the bot is a member of, with its join time, read from
    /// ONE events session (see [`EventsLimits`]).
    pub(crate) async fn fetch_memberships(
        &self,
        app_url: &str,
        limits: EventsLimits,
    ) -> Result<Vec<BotMembership>, StoatError> {
        let self_id = self.fetch_self_id().await?;
        let url = self.events_url(app_url).await?;
        let members = tokio::time::timeout(limits.deadline, self.ready_members(url, limits))
            .await
            .map_err(|_| StoatError::Unavailable)??;
        Ok(own_memberships(&members, &self_id))
    }

    /// Connect, authenticate and return `Ready.members`, closing after.
    ///
    /// The connection is a reqwest HTTP/1.1 upgrade, so it has the same
    /// transport rules as every other call here (HTTPS only, no redirects,
    /// system proxy). The token rides only the `Authenticate` frame, never
    /// the URL, where it would reach access logs.
    async fn ready_members(
        &self,
        url: Url,
        limits: EventsLimits,
    ) -> Result<Vec<Value>, StoatError> {
        let mut http = url;
        let scheme = if http.scheme() == "wss" {
            "https"
        } else {
            "http"
        };
        http.set_scheme(scheme).map_err(|_| StoatError::Malformed)?;
        // `ready=` trims Ready to the fields named (upstream b3ca4399). An
        // older bonfire ignores it and sends everything, which still parses.
        http.query_pairs_mut()
            .append_pair("version", "1")
            .append_pair("format", "json")
            .append_pair("ready", "members");

        let client = client_builder(transport_for(http.as_str()))
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| StoatError::Unavailable)?;

        let key = generate_key();
        let response = client
            .get(http)
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "websocket")
            .header(SEC_WEBSOCKET_VERSION, "13")
            .header(SEC_WEBSOCKET_KEY, &key)
            .send()
            .await
            .map_err(|_| StoatError::Unavailable)?;

        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            log::warn!(
                "stoat import: the events endpoint answered {} instead of upgrading",
                response.status()
            );
            return Err(StoatError::Unavailable);
        }
        let accepted = response
            .headers()
            .get(SEC_WEBSOCKET_ACCEPT)
            .and_then(|value| value.to_str().ok())
            == Some(derive_accept_key(key.as_bytes()).as_str());
        if !accepted {
            return Err(StoatError::Malformed);
        }

        let upgraded = response
            .upgrade()
            .await
            .map_err(|_| StoatError::Unavailable)?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(limits.frame_cap))
            .max_frame_size(Some(limits.frame_cap));
        let mut socket =
            WebSocketStream::from_raw_socket(upgraded, Role::Client, Some(config)).await;

        let authenticate =
            serde_json::json!({ "type": "Authenticate", "token": self.bot_token }).to_string();
        socket
            .send(Message::text(authenticate))
            .await
            .map_err(|_| StoatError::Unavailable)?;

        let result = read_ready(&mut socket).await;
        // Best effort, and short, so a stalled close cannot use up the
        // session deadline once Ready is in.
        let _ = tokio::time::timeout(Duration::from_secs(2), socket.close(None)).await;
        result
    }
}

// ---------------------------------------------------------------------------
// Events session
// ---------------------------------------------------------------------------

/// Bounds on the one events session the reconcile opens.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EventsLimits {
    /// The whole session: both REST calls before it are bounded by
    /// `UPSTREAM_TIMEOUT` already, this covers connect, authenticate and
    /// `Ready`.
    pub deadline: Duration,
    /// Largest frame or message read. `Ready` trimmed to `members` is a
    /// few hundred bytes per server; the full payload an older bonfire sends
    /// is still far under the default for a bot in thousands of servers.
    pub frame_cap: usize,
}

impl Default for EventsLimits {
    fn default() -> Self {
        EventsLimits {
            deadline: Duration::from_secs(30),
            frame_cap: 16 * 1024 * 1024,
        }
    }
}

/// Frames read while waiting for `Ready` before giving up.
const EVENTS_MAX_FRAMES: usize = 64;

/// One of the bot's own server memberships.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BotMembership {
    pub server_id: String,
    /// When the bot joined; `None` when Stoat sent nothing readable.
    pub joined_at: Option<Timestamp>,
}

/// Whether the token may be sent to this events URL: `wss` on the API host,
/// the app host, or a subdomain of the app host (stoat.chat advertises
/// `wss://events.stoat.chat`). The URL comes from the API root, so this keeps
/// a bad or hijacked answer there from sending the token anywhere else.
///
/// A test build also accepts plain `ws://` to the loopback fake, the same
/// split as `transport_for`.
pub(crate) fn events_url_allowed(url: &Url, api_url: &str, app_url: &str) -> bool {
    let loopback_test = cfg!(test) && url.scheme() == "ws" && url.host_str() == Some("127.0.0.1");
    // `wss` on its default port only (the `url` crate drops an explicit 443).
    let scheme_ok = (url.scheme() == "wss" && url.port().is_none()) || loopback_test;
    if !scheme_ok || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };

    let host_of = |base: &str| Url::parse(base).ok()?.host_str().map(str::to_string);
    let api_host = host_of(api_url);
    let app_host = host_of(app_url);
    api_host.as_deref() == Some(host)
        || app_host
            .as_deref()
            .is_some_and(|app| host == app || host.ends_with(&format!(".{app}")))
}

/// Read frames until `Ready` and return its `members`. Frames before it
/// (`Authenticated`, pings, anything binary) are skipped; an `Error` frame,
/// a close, a frame over the cap or too many frames fail the session.
async fn read_ready<S>(socket: &mut S) -> Result<Vec<Value>, StoatError>
where
    S: Stream<Item = Result<Message, WsError>> + Unpin,
{
    #[derive(Deserialize)]
    struct Frame {
        #[serde(rename = "type")]
        kind: String,
        #[serde(default)]
        members: Option<Vec<Value>>,
        #[serde(default)]
        error: Option<Value>,
    }

    for _ in 0..EVENTS_MAX_FRAMES {
        let text = match socket.next().await {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(Message::Close(_))) | None => return Err(StoatError::Unavailable),
            Some(Ok(_)) => continue,
            Some(Err(WsError::Capacity(_))) => {
                log::warn!("stoat import: an events frame went over the size cap");
                return Err(StoatError::Malformed);
            }
            Some(Err(_)) => return Err(StoatError::Unavailable),
        };

        let frame: Frame =
            serde_json::from_str(text.as_str()).map_err(|_| StoatError::Malformed)?;
        match frame.kind.as_str() {
            "Ready" => return frame.members.ok_or(StoatError::Malformed),
            "Error" => {
                log::warn!(
                    "stoat import: the events session was refused: {}",
                    frame.error.unwrap_or(Value::Null)
                );
                return Err(StoatError::Unavailable);
            }
            _ => continue,
        }
    }
    Err(StoatError::Malformed)
}

/// The members in `Ready` that are the bot's own (an older bonfire also
/// sends voice participants' members), one per server, in server id order.
/// Rows whose server id is unusable are dropped; an unreadable `joined_at`
/// is kept as `None` so the caller can decide what that means.
pub(crate) fn own_memberships(members: &[Value], self_id: &str) -> Vec<BotMembership> {
    let mut own = std::collections::BTreeMap::new();
    for member in members {
        if member["_id"]["user"].as_str() != Some(self_id) {
            continue;
        }
        let Some(server_id) = member["_id"]["server"]
            .as_str()
            .filter(|id| is_server_id(id))
        else {
            continue;
        };
        let joined_at = member["joined_at"].as_str().and_then(Timestamp::parse);
        own.insert(server_id.to_string(), joined_at);
    }
    own.into_iter()
        .map(|(server_id, joined_at)| BotMembership {
            server_id,
            joined_at,
        })
        .collect()
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
    use std::sync::{Arc, Mutex};

    use revolt_config::ApiImportBotSource;
    use tokio::net::TcpListener;

    pub(crate) use crate::tasks::import_http::fake_upstream::{
        FakeUpstream as FakeStoat, BOT_TOKEN,
    };

    /// What a [`FakeEvents`] session sends after the client's first frame.
    #[derive(Clone)]
    pub(crate) enum Send {
        Text(String),
        Binary,
        Ping,
        Close,
        /// Send nothing more, keeping the connection open.
        Hang,
    }

    /// One session a [`FakeEvents`] accepted.
    #[derive(Clone, Debug)]
    pub(crate) struct EventsSeen {
        /// Request target of the upgrade, query included
        pub uri: String,
        /// Every request header line, lowercased names
        pub headers: Vec<(String, String)>,
        /// The client's first frame (its `Authenticate`)
        pub first_frame: Option<String>,
    }

    /// A scripted Stoat events WebSocket on a loopback port. Every session
    /// reads the client's first frame, then plays the script.
    pub(crate) struct FakeEvents {
        pub url: String,
        seen: Arc<Mutex<Vec<EventsSeen>>>,
    }

    impl FakeEvents {
        /// Answer each session's first frame with these text frames.
        pub(crate) async fn start(frames: Vec<String>) -> FakeEvents {
            FakeEvents::script(frames.into_iter().map(Send::Text).collect()).await
        }

        pub(crate) async fn script(script: Vec<Send>) -> FakeEvents {
            use futures::{SinkExt, StreamExt};
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            use tokio_tungstenite::tungstenite::Message;

            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let url = format!("ws://{}/events", listener.local_addr().expect("addr"));
            let seen: Arc<Mutex<Vec<EventsSeen>>> = Arc::new(Mutex::new(vec![]));

            let sessions = seen.clone();
            tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    let script = script.clone();
                    let sessions = sessions.clone();
                    tokio::spawn(async move {
                        let request = Arc::new(Mutex::new((String::new(), vec![])));
                        let record = request.clone();
                        let callback = move |req: &Request, response: Response| {
                            let headers = req
                                .headers()
                                .iter()
                                .map(|(name, value)| {
                                    (
                                        name.as_str().to_lowercase(),
                                        value.to_str().unwrap_or("").to_string(),
                                    )
                                })
                                .collect();
                            *record.lock().unwrap() = (req.uri().to_string(), headers);
                            Ok(response)
                        };
                        let Ok(mut ws) =
                            tokio_tungstenite::accept_hdr_async(socket, callback).await
                        else {
                            return;
                        };

                        let first_frame = match ws.next().await {
                            Some(Ok(Message::Text(text))) => Some(text.to_string()),
                            _ => None,
                        };
                        let (uri, headers) = request.lock().unwrap().clone();
                        sessions.lock().unwrap().push(EventsSeen {
                            uri,
                            headers,
                            first_frame,
                        });

                        for step in script {
                            let message = match step {
                                Send::Text(text) => Message::text(text),
                                Send::Binary => Message::binary(vec![0u8, 1, 2]),
                                Send::Ping => Message::Ping(vec![1u8].into()),
                                Send::Close => Message::Close(None),
                                Send::Hang => {
                                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                                    return;
                                }
                            };
                            if ws.send(message).await.is_err() {
                                return;
                            }
                        }
                        // Let the client read and close.
                        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                            while let Some(Ok(_)) = ws.next().await {}
                        })
                        .await;
                    });
                }
            });

            FakeEvents { url, seen }
        }

        /// Sessions that got as far as the client's first frame.
        pub(crate) fn sessions(&self) -> usize {
            self.seen.lock().unwrap().len()
        }

        pub(crate) fn seen(&self) -> Vec<EventsSeen> {
            self.seen.lock().unwrap().clone()
        }
    }

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
                reconcile_after_hours: 24,
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

    // ------------------------------------------------------------ events --

    use super::fake_upstream::{FakeEvents, Send};

    const SELF_ID: &str = "01BOT000000000000000000000";
    const APP: &str = "https://stoat.example";

    fn me_body() -> String {
        format!(r#"{{"_id":"{SELF_ID}"}}"#)
    }

    /// An API whose root advertises `ws` and whose `/users/@me` is the bot.
    async fn events_api(ws: &str) -> (FakeStoat, StoatApi) {
        let fake = FakeStoat::new()
            .reply("GET", "/", 200, format!(r#"{{"ws":"{ws}"}}"#))
            .reply("GET", "/users/@me", 200, me_body())
            .start()
            .await;
        let api = StoatApi::new(&fake.source_config(&FakeStoat::new())).expect("api");
        (fake, api)
    }

    fn quick() -> EventsLimits {
        EventsLimits {
            deadline: Duration::from_millis(500),
            frame_cap: 64 * 1024,
        }
    }

    #[tokio::test]
    async fn memberships_come_from_one_authenticated_ready_session() {
        let joined = "2026-10-01T10:00:00.000Z";
        let ready = format!(
            r#"{{"type":"Ready","servers":[],"members":[
                {{"_id":{{"server":"01SRVB","user":"{SELF_ID}"}},"joined_at":"{joined}"}},
                {{"_id":{{"server":"01SRVA","user":"{SELF_ID}"}},"joined_at":"not a time"}},
                {{"_id":{{"server":"01SRVC","user":"01SOMEONEELSE"}},"joined_at":"{joined}"}},
                {{"_id":{{"server":"bad/id","user":"{SELF_ID}"}},"joined_at":"{joined}"}},
                {{"_id":{{"user":"{SELF_ID}"}},"joined_at":"{joined}"}}
            ]}}"#
        );
        let events = FakeEvents::script(vec![
            Send::Text(r#"{"type":"Authenticated"}"#.to_string()),
            Send::Ping,
            Send::Binary,
            Send::Text(r#"{"type":"Pong","data":0}"#.to_string()),
            Send::Text(ready),
        ])
        .await;
        let (fake, api) = events_api(&events.url).await;

        let memberships = api.fetch_memberships(APP, quick()).await.unwrap();
        assert_eq!(
            memberships,
            vec![
                BotMembership {
                    server_id: "01SRVA".to_string(),
                    joined_at: None,
                },
                BotMembership {
                    server_id: "01SRVB".to_string(),
                    joined_at: Timestamp::parse(joined),
                },
            ]
        );
        assert!(memberships[1].joined_at.is_some());

        let sessions = events.seen();
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        for part in ["version=1", "format=json", "ready=members"] {
            assert!(session.uri.contains(part), "{}", session.uri);
        }
        // The token rides the Authenticate frame only.
        assert!(!session.uri.contains(BOT_TOKEN));
        assert!(session
            .headers
            .iter()
            .all(|(_, value)| !value.contains(BOT_TOKEN)));
        let auth: Value = serde_json::from_str(session.first_frame.as_deref().unwrap()).unwrap();
        assert_eq!(
            auth,
            serde_json::json!({ "type": "Authenticate", "token": BOT_TOKEN })
        );

        let paths: Vec<String> = fake.seen().into_iter().map(|seen| seen.path).collect();
        assert_eq!(paths, ["/users/@me", "/"]);
    }

    /// Each way a session can go wrong fails with its own error, and at once:
    /// the fake keeps the connection open for 5 s after its script, so a
    /// case that only failed by waiting out a deadline would show here.
    #[tokio::test]
    async fn a_session_that_never_delivers_a_usable_ready_fails() {
        use std::time::Instant;
        use StoatError::{Malformed, Unavailable};

        let authenticated = || Send::Text(r#"{"type":"Authenticated"}"#.to_string());
        let error = r#"{"type":"Error","error":"InvalidSession"}"#.to_string();
        let oversized = format!(
            r#"{{"type":"Ready","members":[],"pad":"{}"}}"#,
            "x".repeat(128 * 1024)
        );
        let too_many: Vec<Send> = (0..=EVENTS_MAX_FRAMES).map(|_| authenticated()).collect();
        let scripts = [
            (
                "error",
                vec![authenticated(), Send::Text(error)],
                Unavailable,
            ),
            ("close", vec![authenticated(), Send::Close], Unavailable),
            (
                "no members",
                vec![Send::Text(r#"{"type":"Ready"}"#.to_string())],
                Malformed,
            ),
            (
                "not json",
                vec![Send::Text("not json".to_string())],
                Malformed,
            ),
            ("over the cap", vec![Send::Text(oversized)], Malformed),
            ("too many frames", too_many, Malformed),
        ];
        let limits = EventsLimits {
            deadline: Duration::from_secs(10),
            frame_cap: 64 * 1024,
        };
        for (name, script, expected) in scripts {
            let events = FakeEvents::script(script).await;
            let (_fake, api) = events_api(&events.url).await;
            let started = Instant::now();
            assert_eq!(
                api.fetch_memberships(APP, limits).await,
                Err(expected),
                "{name}"
            );
            assert!(started.elapsed() < Duration::from_secs(3), "{name}");
            assert_eq!(events.sessions(), 1, "{name}");
        }

        // Silence is bounded by the deadline.
        let events = FakeEvents::script(vec![authenticated(), Send::Hang]).await;
        let (_fake, api) = events_api(&events.url).await;
        let started = Instant::now();
        assert_eq!(api.fetch_memberships(APP, quick()).await, Err(Unavailable));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    /// A 101 without the right `Sec-WebSocket-Accept` is not our upgrade.
    #[tokio::test]
    async fn a_wrong_handshake_answer_fails() {
        let path = "/events?version=1&format=json&ready=members";
        let wrong = FakeStoat::new().reply("GET", path, 101, "").start().await;
        let ws = format!("{}/events", wrong.url.replacen("http://", "ws://", 1));
        let (_fake, api) = events_api(&ws).await;
        assert_eq!(
            api.fetch_memberships(APP, quick()).await,
            Err(StoatError::Malformed)
        );
    }

    /// An endpoint that answers the upgrade with a plain response fails, and
    /// the upgrade request itself carries no token.
    #[tokio::test]
    async fn an_endpoint_that_does_not_upgrade_fails() {
        let plain = FakeStoat::new().start().await;
        let ws = format!("{}/events", plain.url.replacen("http://", "ws://", 1));
        let (_fake, api) = events_api(&ws).await;

        assert!(matches!(
            api.fetch_memberships(APP, quick()).await,
            Err(StoatError::Unavailable)
        ));
        let seen = plain.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, "/events?version=1&format=json&ready=members");
        assert!(seen[0].bot_token.is_none());
    }

    /// The root's `ws` decides where the token goes, so an answer off the
    /// configured hosts is refused before anything connects.
    #[tokio::test]
    async fn an_events_url_off_the_configured_hosts_is_never_contacted() {
        let events = FakeEvents::start(vec![]).await;
        let elsewhere = events.url.replacen("127.0.0.1", "localhost", 1);
        for ws in [
            elsewhere.as_str(),
            "wss://evil.example/events",
            "https://127.0.0.1/events",
            "not a url",
        ] {
            let (_fake, api) = events_api(ws).await;
            assert!(
                matches!(
                    api.fetch_memberships(APP, quick()).await,
                    Err(StoatError::Malformed)
                ),
                "{ws}"
            );
        }
        assert_eq!(events.sessions(), 0);
    }

    #[tokio::test]
    async fn no_session_without_the_bot_s_own_id() {
        let events = FakeEvents::start(vec![]).await;
        for (status, body) in [
            (401, "{}".to_string()),
            (200, r#"{"_id":"bad/id"}"#.to_string()),
        ] {
            let fake = FakeStoat::new()
                .reply("GET", "/", 200, format!(r#"{{"ws":"{}"}}"#, events.url))
                .reply("GET", "/users/@me", status, body)
                .start()
                .await;
            let api = StoatApi::new(&fake.source_config(&FakeStoat::new())).unwrap();
            assert!(api.fetch_memberships(APP, quick()).await.is_err());
        }
        assert_eq!(events.sessions(), 0);
    }

    #[test]
    fn events_urls_must_be_wss_on_the_api_or_app_host() {
        let api = "https://api.stoat.chat";
        let app = "https://stoat.chat";
        let allowed = |url: &str| events_url_allowed(&Url::parse(url).unwrap(), api, app);

        // What stoat.chat advertises today, and the other plausible layouts.
        assert!(allowed("wss://events.stoat.chat"));
        assert!(allowed("wss://events.stoat.chat:443"));
        assert!(allowed("wss://stoat.chat/events"));
        assert!(allowed("wss://api.stoat.chat/ws"));

        for url in [
            "ws://events.stoat.chat",
            "https://events.stoat.chat",
            "wss://stoat.chat.evil.example",
            "wss://evilstoat.chat",
            "wss://api.stoat.chat.evil.example",
            "wss://evil.example",
            "wss://user:secret@events.stoat.chat",
            "wss://events.stoat.chat:8443",
            "ws://127.0.0.2:1/events",
        ] {
            assert!(!allowed(url), "{url}");
        }

        // Without an app URL, only the API host.
        let url = |url: &str| Url::parse(url).unwrap();
        assert!(events_url_allowed(&url("wss://api.stoat.chat"), api, ""));
        assert!(!events_url_allowed(
            &url("wss://events.stoat.chat"),
            api,
            ""
        ));
    }
}
