//! Game data for game cards and game lookups
//!
//! Fetches from three upstreams (the Steam store and news API, the Blizzard
//! World of Warcraft API, Riot Data Dragon) through one SSRF-hardened HTTP
//! client, with a per-source host allowlist, Redis-shared budgets and a
//! Redis cache (both with in-process fallbacks). January (embeds), delta
//! (lookups) and crond share this crate, so they share the budgets too.

use std::sync::Mutex;

use revolt_config::{ApiGamedata, Settings};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

pub mod blizzard;
pub mod ip_policy;
pub mod riot;
pub mod steam;

mod budget;
mod cache;
mod http;
mod text;

#[cfg(test)]
mod tests;

pub use steam::SteamNewsItem;

/// Result type of every game data operation
pub type Result<T, E = GameDataError> = std::result::Result<T, E>;

/// Which share of an upstream budget a call draws on
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pool {
    /// Embeds generated for posted links
    Embed,
    /// A user waiting on a lookup
    Interactive,
}

/// Why game data could not be produced. `Budget` means "fall back to the
/// normal preview".
#[derive(thiserror::Error, Debug)]
pub enum GameDataError {
    #[error("game data budget is spent")]
    Budget,
    #[error("game data source is disabled")]
    Disabled,
    #[error("game data not found")]
    NotFound,
    #[error("host is not allowed for game data")]
    HostNotAllowed,
    #[error("game data upstream error: {0}")]
    Upstream(String),
}

/// A normalised game card, ready to be turned into an embed
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GameCard {
    pub title: String,
    pub subtitle: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub image_large: bool,
    pub site_name: String,
    pub colour: Option<String>,
    pub url: String,
}

/// One lookup result
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SearchHit {
    pub title: String,
    pub subtitle: Option<String>,
    pub url: String,
}

/// What a link points at
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardTarget {
    SteamApp(u32),
    WowItem(u64),
    /// Normalised champion slug (see `riot::normalise_slug`)
    Champion(String),
}

/// Which source a lookup searches
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupSource {
    Steam,
    Wow,
    Lol,
}

/// Cached Blizzard client-credentials token
pub(crate) struct BlizzardToken {
    pub(crate) access_token: String,
    pub(crate) expires_at: std::time::Instant,
}

/// Shared game data client: HTTP client, caches, budgets and a snapshot of
/// `[api.gamedata]`
pub struct GameData {
    pub(crate) client: reqwest::Client,
    pub(crate) config: ApiGamedata,
    /// Whether budgets and caches go to Redis first (false in tests)
    pub(crate) redis: bool,
    pub(crate) cache: cache::Caches,
    pub(crate) budgets: Mutex<budget::LocalBudgets>,
    pub(crate) blizzard_token: tokio::sync::Mutex<Option<BlizzardToken>>,
}

static GLOBAL: tokio::sync::OnceCell<GameData> = tokio::sync::OnceCell::const_new();

impl GameData {
    fn new(config: ApiGamedata, redis: bool) -> GameData {
        GameData {
            client: http::build_client(),
            config,
            redis,
            cache: cache::Caches::new(),
            budgets: Mutex::new(budget::LocalBudgets::default()),
            blizzard_token: tokio::sync::Mutex::new(None),
        }
    }

    /// Client for a service. Budgets and caches go to Redis (`REDIS_URI`,
    /// set by revolt-config) and fall back to in-process state whenever
    /// Redis is unreachable.
    pub fn from_config(cfg: &Settings) -> GameData {
        GameData::new(cfg.api.gamedata.clone(), true)
    }

    /// Client for tests: no Redis, in-process caches and budgets, default
    /// budgets, no Blizzard credentials
    pub fn for_tests() -> GameData {
        GameData::new(ApiGamedata::default(), false)
    }

    /// Client for tests with a chosen configuration (still no Redis)
    #[cfg(test)]
    pub(crate) fn for_tests_with(config: ApiGamedata) -> GameData {
        GameData::new(config, false)
    }

    /// Whether `presented` (the `X-Internal-Key` header) unlocks game card
    /// enrichment. Fails closed: false when no key is configured (empty or
    /// whitespace) or no header was sent; otherwise a constant-time compare
    /// against the configured key.
    pub fn internal_key_ok(&self, presented: Option<&str>) -> bool {
        let configured = self.config.internal_key.as_str();
        if configured.trim().is_empty() {
            return false;
        }
        let Some(presented) = presented else {
            return false;
        };
        bool::from(presented.as_bytes().ct_eq(configured.as_bytes()))
    }

    /// Process-wide client, built from the loaded configuration on first use
    pub async fn global() -> &'static GameData {
        GLOBAL
            .get_or_init(|| async { GameData::from_config(&revolt_config::config().await) })
            .await
    }
}

fn is_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// Which game card a link should get, judged on the link alone (the page
/// is never fetched). `http` and `https` both match; query and fragment
/// are ignored; the host must match exactly, with an optional `www.`.
pub fn match_url(url: &str) -> Option<CardTarget> {
    let url = url::Url::parse(url.trim()).ok()?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return None;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }

    let host = url.host_str()?.to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);

    // Path segments with one trailing slash tolerated
    let mut segments: Vec<&str> = url.path_segments()?.collect();
    if segments.last() == Some(&"") {
        segments.pop();
    }

    match host {
        "store.steampowered.com" => match segments.as_slice() {
            ["app", id, ..] if is_digits(id) => id.parse().ok().map(CardTarget::SteamApp),
            _ => None,
        },
        "wowhead.com" => match segments.as_slice() {
            [first] | [first, _] => {
                let id = first.strip_prefix("item=")?;
                if is_digits(id) {
                    id.parse().ok().map(CardTarget::WowItem)
                } else {
                    None
                }
            }
            _ => None,
        },
        "leagueoflegends.com" => match segments.as_slice() {
            [locale, "champions", slug] if is_locale(locale) => champion_target(slug),
            _ => None,
        },
        // op.gg is never fetched, so its trailing sub-pages (`/build`,
        // `/counters`, ...) are accepted
        "op.gg" => match segments.as_slice() {
            ["champions", slug, ..] | ["lol", "champions", slug, ..] => champion_target(slug),
            _ => None,
        },
        _ => None,
    }
}

/// `en-us`, `pt-br`, ... (case-insensitive)
fn is_locale(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 5
        && bytes[2] == b'-'
        && bytes[..2].iter().all(u8::is_ascii_alphabetic)
        && bytes[3..].iter().all(u8::is_ascii_alphabetic)
}

fn champion_target(slug: &str) -> Option<CardTarget> {
    let slug = riot::normalise_slug(slug);
    if slug.is_empty() || slug.len() > 40 {
        None
    } else {
        Some(CardTarget::Champion(slug))
    }
}

/// Build the card for `target`; `url` is the link the card is for
pub async fn card_for(
    gd: &GameData,
    target: &CardTarget,
    url: &str,
    pool: Pool,
) -> Result<GameCard> {
    match target {
        CardTarget::SteamApp(id) => {
            let app = steam::app_details(gd, *id, pool).await?;
            Ok(steam::card(&app, url))
        }
        CardTarget::WowItem(id) => {
            let item = blizzard::item(gd, *id, pool).await?;
            // The icon is decoration: a card without one beats no card
            let icon = match blizzard::item_media(gd, *id, pool).await {
                Ok(icon) => icon,
                Err(error) => {
                    log::debug!("gamedata: no icon for WoW item {id}: {error}");
                    None
                }
            };
            Ok(blizzard::card(&item, icon.as_deref(), url))
        }
        CardTarget::Champion(slug) => {
            let version = riot::latest_version(gd).await?;
            let champions = riot::champions(gd, &version).await?;
            let champion =
                riot::find_champion(&champions, slug).ok_or(GameDataError::NotFound)?;
            Ok(riot::card(champion, &version, url))
        }
    }
}

/// Maximum hits a lookup returns
pub(crate) const MAX_HITS: usize = 5;
/// Lookup queries are cut to this many characters
pub(crate) const MAX_QUERY_CHARS: usize = 100;

/// Normalise a user query: trimmed, at most `MAX_QUERY_CHARS` characters
pub(crate) fn normalise_query(query: &str) -> String {
    text::cap(query.trim(), MAX_QUERY_CHARS).trim().to_string()
}

/// Search `source` for `query` (interactive pool, at most 5 hits). Every
/// hit URL matches back to its target through `match_url`.
pub async fn lookup(gd: &GameData, source: LookupSource, query: &str) -> Result<Vec<SearchHit>> {
    let query = normalise_query(query);
    let mut hits = match source {
        LookupSource::Steam => steam::search(gd, &query, Pool::Interactive).await?,
        LookupSource::Wow => blizzard::item_search(gd, &query, Pool::Interactive).await?,
        LookupSource::Lol => {
            if query.is_empty() {
                return Ok(Vec::new());
            }
            let version = riot::latest_version(gd).await?;
            let champions = riot::champions(gd, &version).await?;
            riot::search_hits(&champions, &query)
        }
    };
    hits.truncate(MAX_HITS);
    Ok(hits)
}

/// Field limits of a `GameCard`, in characters
pub(crate) const CAP_TITLE: usize = 100;
pub(crate) const CAP_SUBTITLE: usize = 200;
pub(crate) const CAP_DESCRIPTION: usize = 1000;
pub(crate) const CAP_SITE_NAME: usize = 50;
pub(crate) const CAP_URL: usize = 256;

/// A URL is usable in a card when it is non-empty, within `CAP_URL` and
/// free of control / bidi characters
fn usable_url(url: &str) -> bool {
    !url.trim().is_empty() && url.chars().count() <= CAP_URL && !url.chars().any(text::is_hidden)
}

/// Apply every field limit and drop control / bidi characters from every
/// text field. An unusable image URL is dropped; an unusable card URL is
/// replaced by the target's canonical URL (a cut URL would be a broken
/// link).
pub(crate) fn finish_card(card: GameCard, canonical_url: &str) -> GameCard {
    let clean_cap = |value: &str, max: usize| text::cap(text::clean(value).trim(), max);
    let clean_cap_opt = |value: Option<String>, max: usize| {
        value
            .map(|v| clean_cap(&v, max))
            .filter(|v| !v.is_empty())
    };

    let url = if usable_url(&card.url) {
        card.url
    } else {
        text::cap(&text::clean(canonical_url), CAP_URL)
    };

    GameCard {
        title: clean_cap(&card.title, CAP_TITLE),
        subtitle: clean_cap_opt(card.subtitle, CAP_SUBTITLE),
        description: clean_cap_opt(card.description, CAP_DESCRIPTION),
        image_url: card.image_url.filter(|u| usable_url(u)),
        image_large: card.image_large,
        site_name: clean_cap(&card.site_name, CAP_SITE_NAME),
        colour: card.colour.filter(|c| !c.chars().any(text::is_hidden)),
        url,
    }
}

/// A lookup hit with control / bidi characters dropped and fields capped
pub(crate) fn clean_hit(title: &str, subtitle: Option<&str>, url: String) -> SearchHit {
    SearchHit {
        title: text::cap(text::clean(title).trim(), CAP_TITLE),
        subtitle: subtitle
            .map(|s| text::cap(text::clean(s).trim(), CAP_SUBTITLE))
            .filter(|s| !s.is_empty()),
        url,
    }
}
