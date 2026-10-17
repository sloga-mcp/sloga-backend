//! Steam: store `appdetails` and `storesearch` (undocumented, shared store
//! budget split by pool) and `ISteamNews/GetNewsForApp` (official, its own
//! budget, never cached). Cards never show a price (plan D5).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    budget::Budget,
    cache::Ttl,
    clean_hit, finish_card,
    http::parse_json,
    normalise_query, text, GameCard, GameData, GameDataError, Pool, Result, SearchHit, MAX_HITS,
};

/// The parts of a Steam app a card uses. There is deliberately no price
/// field: the card must never show one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SteamApp {
    pub app_id: u32,
    pub name: String,
    pub short_description: Option<String>,
    pub header_image: Option<String>,
    pub developers: Vec<String>,
    pub genres: Vec<String>,
    pub release_date: Option<String>,
    pub coming_soon: bool,
    pub metacritic: Option<u32>,
}

/// One Steam news post
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SteamNewsItem {
    pub gid: String,
    pub title: String,
    pub url: String,
    pub excerpt: String,
    pub date: i64,
}

/// Steam's store page for an app
pub fn store_url(app_id: u32) -> String {
    format!("https://store.steampowered.com/app/{app_id}/")
}

#[derive(Deserialize)]
struct RawEntry {
    #[serde(default)]
    success: bool,
    data: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct RawApp {
    name: String,
    short_description: Option<String>,
    header_image: Option<String>,
    #[serde(default)]
    developers: Vec<String>,
    #[serde(default)]
    genres: Vec<RawGenre>,
    release_date: Option<RawRelease>,
    metacritic: Option<RawMetacritic>,
}

#[derive(Deserialize)]
struct RawGenre {
    description: String,
}

#[derive(Deserialize)]
struct RawRelease {
    #[serde(default)]
    coming_soon: bool,
    date: Option<String>,
}

#[derive(Deserialize)]
struct RawMetacritic {
    score: Option<u32>,
}

/// Parse an `appdetails` response for `app_id`
pub fn parse_app_details(body: &[u8], app_id: u32) -> Result<SteamApp> {
    // Unknown ids come back as `{"<id>":{"success":false}}` (or `null`)
    let entries: Option<HashMap<String, RawEntry>> = parse_json(body)?;
    let entry = entries
        .and_then(|mut entries| entries.remove(&app_id.to_string()))
        .ok_or(GameDataError::NotFound)?;
    if !entry.success {
        return Err(GameDataError::NotFound);
    }
    let data = entry
        .data
        .filter(serde_json::Value::is_object)
        .ok_or(GameDataError::NotFound)?;
    let raw: RawApp = serde_json::from_value(data)
        .map_err(|error| GameDataError::Upstream(format!("bad appdetails: {error}")))?;

    let release = raw.release_date;
    Ok(SteamApp {
        app_id,
        name: raw.name,
        short_description: raw.short_description,
        header_image: raw.header_image,
        developers: raw.developers,
        genres: raw.genres.into_iter().map(|g| g.description).collect(),
        coming_soon: release.as_ref().is_some_and(|r| r.coming_soon),
        release_date: release.and_then(|r| r.date),
        metacritic: raw.metacritic.and_then(|m| m.score),
    })
}

#[derive(Deserialize)]
struct RawSearch {
    #[serde(default)]
    items: Vec<RawSearchItem>,
}

#[derive(Deserialize)]
struct RawSearchItem {
    #[serde(rename = "type", default)]
    kind: String,
    name: String,
    id: u32,
}

/// Parse a `storesearch` response: apps only, at most 5
pub fn parse_search(body: &[u8]) -> Result<Vec<SearchHit>> {
    let raw: RawSearch = parse_json(body)?;
    Ok(raw
        .items
        .into_iter()
        .filter(|item| item.kind == "app")
        .take(MAX_HITS)
        .map(|item| clean_hit(&item.name, None, store_url(item.id)))
        .collect())
}

#[derive(Deserialize)]
struct RawNews {
    appnews: RawAppNews,
}

#[derive(Deserialize)]
struct RawAppNews {
    #[serde(default)]
    newsitems: Vec<RawNewsItem>,
}

#[derive(Deserialize)]
struct RawNewsItem {
    gid: String,
    title: String,
    url: String,
    #[serde(default)]
    contents: String,
    #[serde(default)]
    date: i64,
}

/// News excerpts are cut to this many characters
pub const NEWS_EXCERPT_CHARS: usize = 300;

/// Plain-text excerpt of a news body: BBCode and HTML tags stripped,
/// entities decoded, control / bidi characters dropped, whitespace
/// collapsed, at most 300 characters
pub fn news_excerpt(contents: &str) -> String {
    let plain = text::plain_text(&text::strip_bbcode(contents));
    text::cap(&plain, NEWS_EXCERPT_CHARS).trim_end().to_string()
}

/// Parse a `GetNewsForApp` response
pub fn parse_news(body: &[u8]) -> Result<Vec<SteamNewsItem>> {
    let raw: RawNews = parse_json(body)?;
    Ok(raw
        .appnews
        .newsitems
        .into_iter()
        .map(|item| SteamNewsItem {
            gid: text::clean(&item.gid),
            title: text::collapse_whitespace(&text::clean(&item.title)),
            url: text::clean(&item.url),
            excerpt: news_excerpt(&item.contents),
            date: item.date,
        })
        .collect())
}

/// App details (cached 6 h; a miss draws on the store budget of `pool`)
pub async fn app_details(gd: &GameData, app_id: u32, pool: Pool) -> Result<SteamApp> {
    let key = format!("gamedata:v1:steam_app:{app_id}");
    if let Some(app) = gd.cache_get(&key, Ttl::SixHours).await {
        return Ok(app);
    }
    gd.take_budget(Budget::SteamStore(pool)).await?;
    let body = gd
        .get_bytes(
            &format!("https://store.steampowered.com/api/appdetails?appids={app_id}&l=english"),
            None,
        )
        .await?;
    let app = parse_app_details(&body, app_id)?;
    gd.cache_put(&key, Ttl::SixHours, &app).await;
    Ok(app)
}

/// Store search (cached 1 h; a miss draws on the store budget of `pool`)
pub async fn search(gd: &GameData, term: &str, pool: Pool) -> Result<Vec<SearchHit>> {
    let term = normalise_query(term);
    if term.is_empty() {
        return Ok(Vec::new());
    }
    let key = format!("gamedata:v1:steam_search:{}", term.to_lowercase());
    if let Some(hits) = gd.cache_get(&key, Ttl::OneHour).await {
        return Ok(hits);
    }
    gd.take_budget(Budget::SteamStore(pool)).await?;
    let url = url::Url::parse_with_params(
        "https://store.steampowered.com/api/storesearch/",
        &[("term", term.as_str()), ("l", "english"), ("cc", "US")],
    )
    .map_err(|error| GameDataError::Upstream(error.to_string()))?;
    let body = gd.get_bytes(url.as_str(), None).await?;
    let hits = parse_search(&body)?;
    gd.cache_put(&key, Ttl::OneHour, &hits).await;
    Ok(hits)
}

/// Latest community announcements of an app (never cached; draws on the
/// news budget). `count` is clamped to 1..=20.
pub async fn news(gd: &GameData, app_id: u32, count: u8) -> Result<Vec<SteamNewsItem>> {
    let count = count.clamp(1, 20);
    gd.take_budget(Budget::SteamNews).await?;
    let body = gd
        .get_bytes(
            &format!(
                "https://api.steampowered.com/ISteamNews/GetNewsForApp/v2/?appid={app_id}&count={count}&maxlength=300&feeds=steam_community_announcements&format=json"
            ),
            None,
        )
        .await?;
    parse_news(&body)
}

/// Card for an app. No price, ever.
pub fn card(app: &SteamApp, url: &str) -> GameCard {
    let mut parts = Vec::new();
    let genres: Vec<&str> = app
        .genres
        .iter()
        .map(|g| g.trim())
        .filter(|g| !g.is_empty())
        .take(3)
        .collect();
    if !genres.is_empty() {
        parts.push(genres.join(", "));
    }
    if let Some(developer) = app.developers.first().map(|d| d.trim()).filter(|d| !d.is_empty()) {
        parts.push(developer.to_string());
    }
    if let Some(date) = app.release_date.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
        parts.push(if app.coming_soon {
            format!("Releases {date}")
        } else {
            format!("Released {date}")
        });
    }
    if let Some(score) = app.metacritic {
        parts.push(format!("Metacritic {score}"));
    }

    finish_card(
        GameCard {
            title: app.name.clone(),
            subtitle: (!parts.is_empty()).then(|| parts.join(" \u{00B7} ")),
            description: app.short_description.as_deref().map(text::plain_text),
            image_url: app.header_image.clone(),
            image_large: true,
            site_name: "Steam".to_string(),
            colour: Some("#1b2838".to_string()),
            url: url.to_string(),
        },
        &store_url(app.app_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = include_str!("../tests/fixtures/steam_appdetails_620.json");
    const MISSING: &str = include_str!("../tests/fixtures/steam_appdetails_missing.json");
    const SEARCH: &str = include_str!("../tests/fixtures/steam_storesearch.json");
    const NEWS: &str = include_str!("../tests/fixtures/steam_news_730.json");

    #[test]
    fn parses_app_details() {
        let app = parse_app_details(APP.as_bytes(), 620).unwrap();
        assert_eq!(app.name, "Portal 2");
        assert_eq!(app.developers, vec!["Valve"]);
        assert_eq!(app.genres, vec!["Action", "Adventure"]);
        assert_eq!(app.release_date.as_deref(), Some("Apr 18, 2011"));
        assert!(!app.coming_soon);
        assert_eq!(app.metacritic, Some(95));
        assert!(app.header_image.unwrap().starts_with("https://"));
    }

    #[test]
    fn unknown_app_is_not_found() {
        assert!(matches!(
            parse_app_details(MISSING.as_bytes(), 999_999_999),
            Err(GameDataError::NotFound)
        ));
        // The fixture answers for 620, not for 621
        assert!(matches!(
            parse_app_details(APP.as_bytes(), 621),
            Err(GameDataError::NotFound)
        ));
        assert!(matches!(parse_app_details(b"null", 1), Err(GameDataError::NotFound)));
        assert!(matches!(
            parse_app_details(br#"{"1":{"success":true,"data":[]}}"#, 1),
            Err(GameDataError::NotFound)
        ));
        assert!(matches!(
            parse_app_details(b"<html>", 1),
            Err(GameDataError::Upstream(_))
        ));
    }

    #[test]
    fn card_never_shows_a_price() {
        // The fixture carries a real `price_overview` ($9.99)
        assert!(APP.contains("price_overview") && APP.contains("9.99"));
        let app = parse_app_details(APP.as_bytes(), 620).unwrap();
        let card = card(&app, "https://store.steampowered.com/app/620/Portal_2/");
        let rendered = serde_json::to_string(&card).unwrap();
        for needle in ["9.99", "$", "USD", "price", "Price"] {
            assert!(!rendered.contains(needle), "card leaks {needle:?}: {rendered}");
        }
        // Nor can the cached app value carry one
        let cached = serde_json::to_string(&app).unwrap();
        assert!(!cached.contains("9.99") && !cached.contains("price"), "{cached}");
    }

    #[test]
    fn card_fields() {
        let app = parse_app_details(APP.as_bytes(), 620).unwrap();
        let card = card(&app, "https://store.steampowered.com/app/620/Portal_2/");
        assert_eq!(card.title, "Portal 2");
        assert_eq!(
            card.subtitle.as_deref(),
            Some("Action, Adventure \u{00B7} Valve \u{00B7} Released Apr 18, 2011 \u{00B7} Metacritic 95")
        );
        // `&quot;` decoded
        assert_eq!(
            card.description.as_deref(),
            Some("The \"Perpetual Testing Initiative\" has been expanded to allow you to design co-op puzzles for you and your friends!")
        );
        assert!(card.image_large);
        assert_eq!(card.site_name, "Steam");
        assert_eq!(card.colour.as_deref(), Some("#1b2838"));
        assert_eq!(card.url, "https://store.steampowered.com/app/620/Portal_2/");
    }

    #[test]
    fn card_omits_missing_parts_and_caps_fields() {
        let app = SteamApp {
            app_id: 1,
            name: "x".repeat(300),
            short_description: Some("d".repeat(5000)),
            header_image: Some(format!("https://cdn.example/{}", "a".repeat(300))),
            developers: vec![],
            genres: vec!["A".into(), "B".into(), "C".into(), "D".into()],
            release_date: Some("Q4 2027".into()),
            coming_soon: true,
            metacritic: None,
        };
        let long_url = format!("https://store.steampowered.com/app/1/{}", "z".repeat(400));
        let card = card(&app, &long_url);
        assert_eq!(card.title.chars().count(), 100);
        assert_eq!(card.description.unwrap().chars().count(), 1000);
        assert_eq!(card.subtitle.as_deref(), Some("A, B, C \u{00B7} Releases Q4 2027"));
        assert_eq!(card.image_url, None, "an over-long image URL is dropped");
        assert_eq!(card.url, "https://store.steampowered.com/app/1/");
    }

    #[test]
    fn parses_search_apps_only() {
        let hits = parse_search(SEARCH.as_bytes()).unwrap();
        assert_eq!(hits.len(), 4);
        assert_eq!(hits[0].title, "Portal 2");
        assert_eq!(hits[0].url, "https://store.steampowered.com/app/620/");
        assert!(hits.iter().all(|h| h.subtitle.is_none()));

        let mixed = br#"{"total":7,"items":[
            {"type":"sub","name":"Bundle","id":1},
            {"type":"app","name":"A","id":2},{"type":"app","name":"B","id":3},
            {"type":"app","name":"C","id":4},{"type":"app","name":"D","id":5},
            {"type":"app","name":"E","id":6},{"type":"app","name":"F","id":7}]}"#;
        let hits = parse_search(mixed).unwrap();
        assert_eq!(hits.len(), 5);
        assert_eq!(hits[0].title, "A");
        assert_eq!(hits[4].title, "E");
    }

    #[test]
    fn parses_news() {
        let items = parse_news(NEWS.as_bytes()).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Counter-Strike 2 Update");
        assert_eq!(items[0].gid, "1846651706675829");
        assert!(items[0].date > 1_700_000_000);
        assert!(items[0].excerpt.chars().count() <= 300);
        assert!(!items[0].excerpt.is_empty());
    }

    #[test]
    fn news_and_cards_drop_bidi_and_control_characters() {
        // JSON escapes, so the source stays ASCII
        let body = br#"{"appnews":{"appid":1,"newsitems":[{"gid":"1\u202e2","title":"Patch\u202e 1.2\u0007\nnotes","url":"https://example.com/n\u2066ews","contents":"Fixed \u200fbugs &#x202E;now\u001b ok","date":5}]}}"#;
        let items = parse_news(body).unwrap();
        assert_eq!(items[0].gid, "12");
        assert_eq!(items[0].title, "Patch 1.2 notes");
        assert_eq!(items[0].url, "https://example.com/news");
        assert_eq!(items[0].excerpt, "Fixed bugs now ok");

        let app = SteamApp {
            app_id: 7,
            name: "Game\u{202E}exe.txt".into(),
            short_description: Some("Short &#x2067;desc\u{061C}\u{200E}".into()),
            header_image: Some("https://cdn.example/h\u{202D}.jpg".into()),
            developers: vec!["Dev\u{2069}".into()],
            genres: vec!["Action\u{202A}".into()],
            release_date: None,
            coming_soon: false,
            metacritic: None,
        };
        let card = card(&app, "https://store.steampowered.com/app/7/\u{202E}x");
        assert_eq!(card.title, "Gameexe.txt");
        assert_eq!(card.subtitle.as_deref(), Some("Action \u{00B7} Dev"));
        assert_eq!(card.description.as_deref(), Some("Short desc"));
        assert_eq!(card.image_url, None, "an image URL carrying a bidi control is dropped");
        assert_eq!(card.url, "https://store.steampowered.com/app/7/");
        let rendered = serde_json::to_string(&card).unwrap();
        assert!(!rendered.chars().any(crate::text::is_hidden));

        let hits = parse_search(br#"{"items":[{"type":"app","name":"Por\u202etal","id":1}]}"#).unwrap();
        assert_eq!(hits[0].title, "Portal");
    }

    #[test]
    fn news_excerpt_strips_markup() {
        let raw = "[h1]Patch[/h1]\n[list][*]Fixed <b>things</b> &amp; stuff[/list]\n\n  More";
        assert_eq!(news_excerpt(raw), "Patch Fixed things & stuff More");
        let long = "\u{00E9}".repeat(400);
        assert_eq!(news_excerpt(&long).chars().count(), 300);
    }
}
