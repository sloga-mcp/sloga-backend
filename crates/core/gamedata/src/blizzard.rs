//! Blizzard World of Warcraft Game Data API (US retail only), with a cached
//! client-credentials token. Every pool shares one per-second budget.
//! Empty credentials turn the source off (`Disabled`, no request).

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{
    budget::Budget,
    cache::Ttl,
    clean_hit, finish_card,
    http::parse_json,
    normalise_query, BlizzardToken, GameCard, GameData, GameDataError, Pool, Result,
    SearchHit, MAX_HITS,
};

const TOKEN_URL: &str = "https://oauth.battle.net/token";
const API: &str = "https://us.api.blizzard.com";

/// The parts of a WoW item a card uses
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WowItem {
    pub id: u64,
    pub name: String,
    /// `POOR`, `COMMON`, ... `EPIC`, `LEGENDARY`, ...
    pub quality_type: Option<String>,
    pub quality_name: Option<String>,
    pub level: u32,
    pub required_level: u32,
    pub item_subclass: Option<String>,
    pub inventory_type: Option<String>,
}

/// Wowhead's page for an item (what lookups link to)
pub fn wowhead_url(id: u64) -> String {
    format!("https://www.wowhead.com/item={id}")
}

/// A localised string: plain with `locale=en_US`, a per-locale object
/// otherwise (search results)
fn localised(value: Option<&serde_json::Value>) -> Option<String> {
    match value? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(map) => map.get("en_US")?.as_str().map(String::from),
        _ => None,
    }
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty())
}

fn named(value: Option<&serde_json::Value>) -> Option<String> {
    localised(value?.get("name"))
}

fn number(value: Option<&serde_json::Value>) -> u32 {
    value
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0)
}

/// Parse an item response
pub fn parse_item(body: &[u8]) -> Result<WowItem> {
    let raw: serde_json::Value = parse_json(body)?;
    let id = raw
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| GameDataError::Upstream("item without id".into()))?;
    let name = localised(raw.get("name"))
        .ok_or_else(|| GameDataError::Upstream("item without name".into()))?;
    let quality = raw.get("quality");
    Ok(WowItem {
        id,
        name,
        quality_type: quality
            .and_then(|q| q.get("type"))
            .and_then(serde_json::Value::as_str)
            .map(String::from),
        quality_name: named(quality),
        level: number(raw.get("level")),
        required_level: number(raw.get("required_level")),
        item_subclass: named(raw.get("item_subclass")),
        inventory_type: named(raw.get("inventory_type")),
    })
}

/// Parse an item media response: the `icon` asset's URL, if any
pub fn parse_media(body: &[u8]) -> Result<Option<String>> {
    let raw: serde_json::Value = parse_json(body)?;
    Ok(raw
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .and_then(|assets| {
            assets
                .iter()
                .find(|asset| asset.get("key").and_then(serde_json::Value::as_str) == Some("icon"))
        })
        .and_then(|asset| asset.get("value"))
        .and_then(serde_json::Value::as_str)
        .filter(|url| url.starts_with("https://"))
        .map(String::from))
}

/// Parse an item search response, at most 5 hits linking to Wowhead
pub fn parse_search(body: &[u8]) -> Result<Vec<SearchHit>> {
    let raw: serde_json::Value = parse_json(body)?;
    let Some(results) = raw.get("results").and_then(serde_json::Value::as_array) else {
        return Ok(Vec::new());
    };
    Ok(results
        .iter()
        .filter_map(|result| {
            let data = result.get("data")?;
            let id = data.get("id")?.as_u64()?;
            let name = localised(data.get("name"))?;
            let mut parts = Vec::new();
            let level = number(data.get("level"));
            if level > 0 {
                parts.push(format!("Item Level {level}"));
            }
            if let Some(quality) = named(data.get("quality")) {
                parts.push(quality);
            }
            let subtitle = (!parts.is_empty()).then(|| parts.join(" \u{00B7} "));
            Some(clean_hit(&name, subtitle.as_deref(), wowhead_url(id)))
        })
        .take(MAX_HITS)
        .collect())
}

/// Parse a token response: (access token, lifetime in seconds)
pub fn parse_token(body: &[u8]) -> Result<(String, u64)> {
    #[derive(Deserialize)]
    struct RawToken {
        access_token: String,
        #[serde(default)]
        expires_in: u64,
    }
    let raw: RawToken = parse_json(body)?;
    if raw.access_token.is_empty() {
        return Err(GameDataError::Upstream("empty access token".into()));
    }
    Ok((raw.access_token, raw.expires_in))
}

fn credentials(gd: &GameData) -> Result<(&str, &str)> {
    let id = gd.config.blizzard_client_id.trim();
    let secret = gd.config.blizzard_client_secret.trim();
    if id.is_empty() || secret.is_empty() {
        Err(GameDataError::Disabled)
    } else {
        Ok((id, secret))
    }
}

/// A valid access token, fetched when the cached one is missing or within
/// 60 s of expiring
async fn token(gd: &GameData) -> Result<String> {
    let (id, secret) = credentials(gd)?;
    let mut cached = gd.blizzard_token.lock().await;
    if let Some(token) = cached.as_ref() {
        if Instant::now() < token.expires_at {
            return Ok(token.access_token.clone());
        }
    }
    let body = gd
        .post_form_basic(TOKEN_URL, "grant_type=client_credentials", id, secret)
        .await?;
    let (access_token, expires_in) = parse_token(&body)?;
    *cached = Some(BlizzardToken {
        access_token: access_token.clone(),
        expires_at: Instant::now() + Duration::from_secs(expires_in.saturating_sub(60)),
    });
    Ok(access_token)
}

/// GET an API URL with the access token. Any upstream failure drops the
/// cached token, so a revoked one is replaced on the next call.
async fn api_get(gd: &GameData, url: &str) -> Result<Vec<u8>> {
    let token = token(gd).await?;
    let result = gd
        .get_bytes(url, Some(&token))
        .await;
    if matches!(result, Err(GameDataError::Upstream(_))) {
        *gd.blizzard_token.lock().await = None;
    }
    result
}

/// An item (cached 24 h; a miss draws on the Blizzard budget)
pub async fn item(gd: &GameData, id: u64, _pool: Pool) -> Result<WowItem> {
    credentials(gd)?;
    let key = format!("gamedata:v1:wow_item:{id}");
    if let Some(item) = gd.cache_get(&key, Ttl::OneDay).await {
        return Ok(item);
    }
    gd.take_budget(Budget::Blizzard).await?;
    let body = api_get(
        gd,
        &format!("{API}/data/wow/item/{id}?namespace=static-us&locale=en_US"),
    )
    .await?;
    let item = parse_item(&body)?;
    gd.cache_put(&key, Ttl::OneDay, &item).await;
    Ok(item)
}

/// An item's icon URL (cached 24 h; a miss draws on the Blizzard budget)
pub async fn item_media(gd: &GameData, id: u64, _pool: Pool) -> Result<Option<String>> {
    credentials(gd)?;
    let key = format!("gamedata:v1:wow_media:{id}");
    if let Some(icon) = gd.cache_get(&key, Ttl::OneDay).await {
        return Ok(icon);
    }
    gd.take_budget(Budget::Blizzard).await?;
    let body = api_get(
        gd,
        &format!("{API}/data/wow/media/item/{id}?namespace=static-us&locale=en_US"),
    )
    .await?;
    let icon = parse_media(&body)?;
    gd.cache_put(&key, Ttl::OneDay, &icon).await;
    Ok(icon)
}

/// Item search by English name (cached 1 h; a miss draws on the Blizzard
/// budget)
pub async fn item_search(gd: &GameData, name: &str, _pool: Pool) -> Result<Vec<SearchHit>> {
    credentials(gd)?;
    let name = normalise_query(name);
    if name.is_empty() {
        return Ok(Vec::new());
    }
    let key = format!("gamedata:v1:wow_search:{}", name.to_lowercase());
    if let Some(hits) = gd.cache_get(&key, Ttl::OneHour).await {
        return Ok(hits);
    }
    gd.take_budget(Budget::Blizzard).await?;
    let url = url::Url::parse_with_params(
        &format!("{API}/data/wow/search/item"),
        &[
            ("namespace", "static-us"),
            ("locale", "en_US"),
            ("name.en_US", name.as_str()),
            ("orderby", "id"),
            ("_page", "1"),
            ("_pageSize", "5"),
        ],
    )
    .map_err(|error| GameDataError::Upstream(error.to_string()))?;
    let body = api_get(gd, url.as_str()).await?;
    let hits = parse_search(&body)?;
    gd.cache_put(&key, Ttl::OneHour, &hits).await;
    Ok(hits)
}

/// Card colour for an item quality
pub fn quality_colour(quality_type: &str) -> Option<&'static str> {
    Some(match quality_type {
        "POOR" => "#9d9d9d",
        "COMMON" => "#ffffff",
        "UNCOMMON" => "#1eff00",
        "RARE" => "#0070dd",
        "EPIC" => "#a335ee",
        "LEGENDARY" => "#ff8000",
        "ARTIFACT" => "#e6cc80",
        "HEIRLOOM" => "#00ccff",
        _ => return None,
    })
}

/// Card for an item
pub fn card(item: &WowItem, icon: Option<&str>, url: &str) -> GameCard {
    let mut subtitle = Vec::new();
    if item.level > 0 {
        subtitle.push(format!("Item Level {}", item.level));
    }
    subtitle.extend(item.item_subclass.clone());
    subtitle.extend(item.inventory_type.clone());

    let mut description = item.quality_name.clone().unwrap_or_default();
    if item.required_level > 0 {
        if !description.is_empty() {
            description.push_str(" \u{00B7} ");
        }
        description.push_str(&format!("Requires level {}", item.required_level));
    }

    finish_card(
        GameCard {
            title: item.name.clone(),
            subtitle: (!subtitle.is_empty()).then(|| subtitle.join(" \u{00B7} ")),
            description: (!description.is_empty()).then_some(description),
            image_url: icon.map(String::from),
            image_large: false,
            site_name: "World of Warcraft".to_string(),
            colour: item
                .quality_type
                .as_deref()
                .and_then(quality_colour)
                .map(String::from),
            url: url.to_string(),
        },
        &wowhead_url(item.id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITEM: &str = include_str!("../tests/fixtures/blizzard_item_19019.json");
    const MEDIA: &str = include_str!("../tests/fixtures/blizzard_media_19019.json");
    const SEARCH: &str = include_str!("../tests/fixtures/blizzard_search.json");
    const TOKEN: &str = include_str!("../tests/fixtures/blizzard_token.json");

    #[test]
    fn parses_item() {
        let item = parse_item(ITEM.as_bytes()).unwrap();
        assert_eq!(item.id, 19019);
        assert_eq!(item.name, "Thunderfury, Blessed Blade of the Windseeker");
        assert_eq!(item.quality_type.as_deref(), Some("LEGENDARY"));
        assert_eq!(item.quality_name.as_deref(), Some("Legendary"));
        assert_eq!(item.level, 80);
        assert_eq!(item.required_level, 60);
        assert_eq!(item.item_subclass.as_deref(), Some("Sword"));
        assert_eq!(item.inventory_type.as_deref(), Some("One-Hand"));
    }

    #[test]
    fn parses_media_icon() {
        assert_eq!(
            parse_media(MEDIA.as_bytes()).unwrap().as_deref(),
            Some("https://render.worldofwarcraft.com/us/icons/56/inv_sword_39.jpg")
        );
        assert_eq!(parse_media(br#"{"assets":[]}"#).unwrap(), None);
        assert_eq!(
            parse_media(br#"{"assets":[{"key":"icon","value":"http://x/y.jpg"}]}"#).unwrap(),
            None
        );
    }

    #[test]
    fn parses_search() {
        let hits = parse_search(SEARCH.as_bytes()).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].title, "Thunderfury, Blessed Blade of the Windseeker");
        assert_eq!(hits[0].subtitle.as_deref(), Some("Item Level 80 \u{00B7} Legendary"));
        assert_eq!(hits[0].url, "https://www.wowhead.com/item=19019");
        assert_eq!(parse_search(br#"{"results":[]}"#).unwrap(), vec![]);
    }

    #[test]
    fn parses_token() {
        let (token, expires_in) = parse_token(TOKEN.as_bytes()).unwrap();
        assert_eq!(token, "USVb1nGO9kwQlhNRRnI4iWVy2UV5j7M6h7");
        assert_eq!(expires_in, 86399);
        assert!(parse_token(br#"{"access_token":""}"#).is_err());
    }

    #[test]
    fn card_quality_colours() {
        let mut item = parse_item(ITEM.as_bytes()).unwrap();
        let card = card(
            &item,
            Some("https://render.worldofwarcraft.com/us/icons/56/inv_sword_39.jpg"),
            "https://www.wowhead.com/item=19019/thunderfury",
        );
        assert_eq!(card.colour.as_deref(), Some("#ff8000"));
        assert_eq!(card.title, "Thunderfury, Blessed Blade of the Windseeker");
        assert_eq!(
            card.subtitle.as_deref(),
            Some("Item Level 80 \u{00B7} Sword \u{00B7} One-Hand")
        );
        assert_eq!(
            card.description.as_deref(),
            Some("Legendary \u{00B7} Requires level 60")
        );
        assert!(!card.image_large);
        assert_eq!(card.site_name, "World of Warcraft");

        for (quality, colour) in [
            ("POOR", Some("#9d9d9d")),
            ("COMMON", Some("#ffffff")),
            ("UNCOMMON", Some("#1eff00")),
            ("RARE", Some("#0070dd")),
            ("EPIC", Some("#a335ee")),
            ("ARTIFACT", Some("#e6cc80")),
            ("HEIRLOOM", Some("#00ccff")),
            ("WOW_TOKEN", None),
        ] {
            item.quality_type = Some(quality.to_string());
            item.required_level = 0;
            let card = super::card(&item, None, "https://www.wowhead.com/item=19019");
            assert_eq!(card.colour.as_deref(), colour, "{quality}");
            assert_eq!(card.description.as_deref(), Some("Legendary"));
            assert_eq!(card.image_url, None);
        }
    }
}
