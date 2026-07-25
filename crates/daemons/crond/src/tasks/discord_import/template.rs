//! Discord guild-template client.
//!
//! `GET /guilds/templates/{code}` is a **public, unauthenticated** endpoint.
//! Verified live 2026-07-25: a bogus code returns `404 {"message": "Unknown
//! server template", "code": 10057}` — *not* `401` — and an invalid
//! `Authorization: Bot` header behaves identically, i.e. auth is not
//! evaluated on this route at all. Slice 0 of the Discord importer therefore
//! needs no Discord application, no bot token and no secrets of any kind.
//!
//! Templates carry channels/roles/permission overwrites (including private
//! channels, because the admin who created the template had full visibility)
//! but **not** the server icon and **not** emojis — those require the
//! optional bot upgrade (slice 2).

use std::time::Duration;

use serde::{Deserialize, Deserializer};

const DISCORD_API: &str = "https://discord.com/api/v10";
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Discord error code for a template that does not resolve.
const ERR_UNKNOWN_TEMPLATE: i64 = 10057;

// ---------------------------------------------------------------------------
// Permissive scalars (landmine A-6)
// ---------------------------------------------------------------------------

/// A Discord permission bitfield.
///
/// **Discord is inconsistent here and it will bite you.** The guild-template
/// documentation serializes role `permissions` as a JSON **integer**
/// (`104324689`), while the modern REST API returns permission bitfields as
/// **strings** (`"104324689"`). `permission_overwrites` entries are shown only
/// as an empty array in the docs, so their in-template form is unconfirmed and
/// may be either.
///
/// A struct that insists on one form will fail to deserialize the other at
/// runtime — so accept both and normalise to `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiscordBits(pub u64);

impl<'de> Deserialize<'de> for DiscordBits {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u64),
            Str(String),
        }

        match Raw::deserialize(deserializer)? {
            Raw::Num(n) => Ok(DiscordBits(n)),
            // Unparseable bitfields are treated as "no bits" rather than
            // failing the whole import: a single weird overwrite must not
            // cost the user their entire server.
            Raw::Str(s) => Ok(DiscordBits(s.trim().parse::<u64>().unwrap_or(0))),
        }
    }
}

/// A template-local placeholder id.
///
/// Inside `serialized_source_guild`, ids are **not** snowflakes — Discord
/// documents them as "placeholder IDs ... given as integers" (0, 1, 2 …), and
/// `parent_id` / overwrite `id` reference those integers. They may also arrive
/// as strings. Normalised to `String` so they can key a lookup map.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PlaceholderId(pub String);

impl std::fmt::Display for PlaceholderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PlaceholderId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(i64),
            Str(String),
        }

        Ok(match Raw::deserialize(deserializer)? {
            Raw::Num(n) => PlaceholderId(n.to_string()),
            Raw::Str(s) => PlaceholderId(s),
        })
    }
}

/// Target of a channel permission overwrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwriteKind {
    Role,
    Member,
    Unknown,
}

impl<'de> Deserialize<'de> for OverwriteKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(i64),
            Str(String),
        }

        Ok(match Raw::deserialize(deserializer)? {
            Raw::Num(0) => OverwriteKind::Role,
            Raw::Num(1) => OverwriteKind::Member,
            Raw::Num(_) => OverwriteKind::Unknown,
            Raw::Str(s) => match s.trim().to_ascii_lowercase().as_str() {
                "0" | "role" => OverwriteKind::Role,
                "1" | "member" => OverwriteKind::Member,
                _ => OverwriteKind::Unknown,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Discord channel type numbers we care about.
pub mod channel_type {
    pub const GUILD_TEXT: u8 = 0;
    pub const GUILD_VOICE: u8 = 2;
    pub const GUILD_CATEGORY: u8 = 4;
    pub const GUILD_ANNOUNCEMENT: u8 = 5;
    pub const GUILD_STAGE_VOICE: u8 = 13;
    pub const GUILD_FORUM: u8 = 15;
    pub const GUILD_MEDIA: u8 = 16;
}

#[derive(Deserialize, Debug, Clone)]
pub struct GuildTemplate {
    pub code: String,
    /// The *template's* name (user-chosen, e.g. "My Template") — NOT the
    /// guild name. Use [`SerializedGuild::name`] for the server name.
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub source_guild_id: Option<String>,
    #[serde(default)]
    pub serialized_source_guild: SerializedGuild,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct SerializedGuild {
    /// The source guild's name — this is what the imported server is called.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub roles: Vec<TemplateRole>,
    #[serde(default)]
    pub channels: Vec<TemplateChannel>,
    #[serde(default)]
    pub system_channel_id: Option<PlaceholderId>,
    #[serde(default)]
    pub afk_channel_id: Option<PlaceholderId>,
}

/// Roles are parsed in slice 0 (so the payload round-trips) but not yet
/// mapped — slice 1 owns roles + the permission table.
#[derive(Deserialize, Debug, Clone)]
pub struct TemplateRole {
    pub id: PlaceholderId,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub permissions: DiscordBits,
    #[serde(default)]
    pub color: i64,
    #[serde(default)]
    pub hoist: bool,
    #[serde(default)]
    pub mentionable: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TemplateChannel {
    pub id: PlaceholderId,
    #[serde(rename = "type")]
    pub channel_type: u8,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub position: i64,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub nsfw: bool,
    #[serde(default)]
    pub rate_limit_per_user: Option<u64>,
    #[serde(default)]
    pub user_limit: Option<u64>,
    #[serde(default)]
    pub bitrate: Option<u64>,
    #[serde(default)]
    pub parent_id: Option<PlaceholderId>,
    #[serde(default)]
    pub permission_overwrites: Vec<TemplateOverwrite>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TemplateOverwrite {
    pub id: PlaceholderId,
    #[serde(rename = "type", default = "unknown_overwrite_kind")]
    pub kind: OverwriteKind,
    #[serde(default)]
    pub allow: DiscordBits,
    #[serde(default)]
    pub deny: DiscordBits,
}

fn unknown_overwrite_kind() -> OverwriteKind {
    OverwriteKind::Unknown
}

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateFetchError {
    /// Template code did not resolve (deleted, typo'd, or never existed).
    NotFound,
    /// Discord rate-limited us.
    RateLimited,
    /// Any other non-success HTTP status.
    Upstream(u16),
    /// Transport failure (DNS, TLS, timeout).
    Network(String),
    /// 2xx whose body did not match the documented shape.
    Malformed(String),
}

impl TemplateFetchError {
    /// User-safe message stored on the job and shown in the client. Must never
    /// leak internals.
    pub fn user_message(&self) -> String {
        match self {
            TemplateFetchError::NotFound => {
                "We couldn't find that Discord template. Check the link and make sure the \
                 template still exists in your Discord server settings."
                    .to_string()
            }
            TemplateFetchError::RateLimited => {
                "Discord is rate-limiting us right now. Please try again in a few minutes."
                    .to_string()
            }
            TemplateFetchError::Upstream(_) | TemplateFetchError::Network(_) => {
                "We couldn't reach Discord to read your template. Please try again shortly."
                    .to_string()
            }
            TemplateFetchError::Malformed(_) => {
                "Discord returned a template we couldn't understand. Please report this if it \
                 keeps happening."
                    .to_string()
            }
        }
    }
}

#[derive(Deserialize)]
struct DiscordError {
    #[serde(default)]
    code: i64,
}

/// Fetch a guild template by code. No authentication is sent (see module docs).
pub async fn fetch_template(code: &str) -> Result<GuildTemplate, TemplateFetchError> {
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|e| TemplateFetchError::Network(e.to_string()))?;

    let response = client
        .get(format!("{DISCORD_API}/guilds/templates/{code}"))
        .send()
        .await
        .map_err(|e| TemplateFetchError::Network(e.to_string()))?;

    let status = response.status();

    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(TemplateFetchError::RateLimited);
    }

    if !status.is_success() {
        // 404 covers both "no such template" and Discord's 10057; either way
        // it is the same user-facing problem.
        let body = response.text().await.unwrap_or_default();
        let discord_code = serde_json::from_str::<DiscordError>(&body)
            .map(|e| e.code)
            .unwrap_or_default();

        return Err(
            if status == reqwest::StatusCode::NOT_FOUND || discord_code == ERR_UNKNOWN_TEMPLATE {
                TemplateFetchError::NotFound
            } else {
                TemplateFetchError::Upstream(status.as_u16())
            },
        );
    }

    response
        .json::<GuildTemplate>()
        .await
        .map_err(|e| TemplateFetchError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- landmine A-6: both scalar forms must parse ---

    #[test]
    fn permissions_parse_as_integer_and_as_string() {
        // Form 1: the guild-template docs' own example uses an integer.
        let int_form: TemplateRole =
            serde_json::from_str(r#"{"id":0,"name":"everyone","permissions":104324689}"#).unwrap();
        assert_eq!(int_form.permissions, DiscordBits(104324689));

        // Form 2: the modern REST API uses a string.
        let str_form: TemplateRole =
            serde_json::from_str(r#"{"id":"0","name":"everyone","permissions":"104324689"}"#)
                .unwrap();
        assert_eq!(str_form.permissions, DiscordBits(104324689));

        // Both id forms normalise to the same lookup key.
        assert_eq!(int_form.id, str_form.id);
    }

    #[test]
    fn overwrite_allow_deny_accept_both_forms() {
        let int_form: TemplateOverwrite =
            serde_json::from_str(r#"{"id":1,"type":0,"allow":1024,"deny":2048}"#).unwrap();
        assert_eq!(int_form.allow, DiscordBits(1024));
        assert_eq!(int_form.deny, DiscordBits(2048));
        assert_eq!(int_form.kind, OverwriteKind::Role);

        let str_form: TemplateOverwrite =
            serde_json::from_str(r#"{"id":"1","type":"1","allow":"1024","deny":"2048"}"#).unwrap();
        assert_eq!(str_form.allow, DiscordBits(1024));
        assert_eq!(str_form.kind, OverwriteKind::Member);
    }

    #[test]
    fn unparseable_bitfield_degrades_to_zero_rather_than_failing() {
        let row: TemplateOverwrite =
            serde_json::from_str(r#"{"id":1,"type":0,"allow":"not-a-number","deny":0}"#).unwrap();
        assert_eq!(row.allow, DiscordBits(0));
    }

    #[test]
    fn missing_optional_fields_default_cleanly() {
        let channel: TemplateChannel =
            serde_json::from_str(r#"{"id":3,"type":0,"name":"general"}"#).unwrap();
        assert_eq!(channel.parent_id, None);
        assert!(channel.permission_overwrites.is_empty());
        assert!(!channel.nsfw);
    }

    /// Hits the REAL Discord API. `#[ignore]`d so CI stays hermetic; run with
    /// `cargo test -p revolt-crond --bins -- --ignored --nocapture`.
    ///
    /// Proves two things the unit tests can't: that the endpoint genuinely
    /// needs no authentication (we send none), and that an unresolvable code
    /// maps to `NotFound` rather than being mistaken for a transport error.
    #[tokio::test]
    #[ignore]
    async fn live_unknown_code_maps_to_not_found() {
        let result = fetch_template("zzzzzzzzzzzz").await;
        assert_eq!(result.unwrap_err(), TemplateFetchError::NotFound);
    }

    #[test]
    fn full_template_payload_round_trips() {
        // Shaped after the documented example, with both scalar conventions
        // deliberately mixed to prove neither breaks the other.
        let payload = r#"{
            "code": "abc123",
            "name": "My Template",
            "description": "a template",
            "source_guild_id": "678070694164299796",
            "serialized_source_guild": {
                "name": "Real Guild Name",
                "roles": [
                    {"id": 0, "name": "@everyone", "permissions": 104324689, "color": 0, "hoist": false}
                ],
                "channels": [
                    {"id": 1, "type": 4, "name": "TEXT CHANNELS", "position": 0, "parent_id": null},
                    {"id": 2, "type": 0, "name": "general", "position": 0, "parent_id": 1,
                     "topic": "hi", "nsfw": false, "rate_limit_per_user": 5,
                     "permission_overwrites": [{"id": "0", "type": "0", "allow": "0", "deny": "1024"}]},
                    {"id": 3, "type": 2, "name": "Voice", "position": 1, "parent_id": 1, "user_limit": 0}
                ],
                "system_channel_id": 2
            }
        }"#;

        let template: GuildTemplate = serde_json::from_str(payload).unwrap();
        assert_eq!(template.code, "abc123");
        // Server name must come from the GUILD, not the template's own name.
        assert_eq!(
            template.serialized_source_guild.name.as_deref(),
            Some("Real Guild Name")
        );
        assert_eq!(template.serialized_source_guild.channels.len(), 3);
        assert_eq!(
            template.serialized_source_guild.system_channel_id,
            Some(PlaceholderId("2".to_string()))
        );
    }
}
