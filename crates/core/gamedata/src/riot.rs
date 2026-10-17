//! Riot Data Dragon (keyless, no budget): latest version and champion list

use serde::{Deserialize, Serialize};

use crate::{
    cache::Ttl, clean_hit, finish_card, http::parse_json, text, GameCard, GameData,
    GameDataError, Result, SearchHit, MAX_HITS,
};

const DDRAGON: &str = "https://ddragon.leagueoflegends.com";

/// The parts of a champion a card uses
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Champion {
    /// Data Dragon id (`MonkeyKing`, `KSante`, ...)
    pub id: String,
    pub name: String,
    pub title: String,
    pub blurb: String,
    pub tags: Vec<String>,
    /// Square image file name (`MonkeyKing.png`)
    pub image_full: String,
}

/// Lowercase, only `[a-z0-9]` kept (`K'Sante` -> `ksante`)
pub fn normalise_slug(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// League of Legends' page for a champion (what lookups link to)
// Riot's own champion URLs use the normalised id (verified live: /champions/monkeyking/ returns 200, /wukong/ returns 404).
pub fn champion_url(champion: &Champion) -> String {
    format!(
        "https://www.leagueoflegends.com/en-us/champions/{}/",
        normalise_slug(&champion.id)
    )
}

/// Versions are interpolated into URL paths: digits and dots only
fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 32
        && version.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

/// Image file names are interpolated into URL paths
fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Parse `versions.json`: the newest (first) version
pub fn parse_versions(body: &[u8]) -> Result<String> {
    let versions: Vec<String> = parse_json(body)?;
    versions
        .into_iter()
        .next()
        .filter(|v| valid_version(v))
        .ok_or_else(|| GameDataError::Upstream("no valid version".into()))
}

#[derive(Deserialize)]
struct RawChampions {
    data: std::collections::BTreeMap<String, RawChampion>,
}

#[derive(Deserialize)]
struct RawChampion {
    id: String,
    name: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    blurb: String,
    #[serde(default)]
    tags: Vec<String>,
    image: Option<RawImage>,
}

#[derive(Deserialize)]
struct RawImage {
    full: String,
}

/// Parse `champion.json`, sorted by name
pub fn parse_champions(body: &[u8]) -> Result<Vec<Champion>> {
    let raw: RawChampions = parse_json(body)?;
    let mut champions: Vec<Champion> = raw
        .data
        .into_values()
        .map(|c| Champion {
            id: c.id,
            name: c.name,
            title: c.title,
            blurb: c.blurb,
            tags: c.tags,
            image_full: c.image.map(|i| i.full).unwrap_or_default(),
        })
        .collect();
    champions.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(champions)
}

/// The champion whose normalised id or name equals the normalised `slug`
pub fn find_champion<'a>(champions: &'a [Champion], slug: &str) -> Option<&'a Champion> {
    let slug = normalise_slug(slug);
    if slug.is_empty() {
        return None;
    }
    champions
        .iter()
        .find(|c| normalise_slug(&c.id) == slug || normalise_slug(&c.name) == slug)
}

/// Champions whose name contains `query` (case-insensitive), at most 5
pub fn search_hits(champions: &[Champion], query: &str) -> Vec<SearchHit> {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return Vec::new();
    }
    champions
        .iter()
        .filter(|c| c.name.to_lowercase().contains(&query))
        .take(MAX_HITS)
        .map(|c| clean_hit(&c.name, Some(&c.title), champion_url(c)))
        .collect()
}

/// Newest Data Dragon version (cached 1 h)
pub async fn latest_version(gd: &GameData) -> Result<String> {
    let key = "gamedata:v1:riot_version:latest";
    if let Some(version) = gd.cache_get::<String>(key, Ttl::OneHour).await {
        if valid_version(&version) {
            return Ok(version);
        }
    }
    let body = gd
        .get_bytes(&format!("{DDRAGON}/api/versions.json"), None)
        .await?;
    let version = parse_versions(&body)?;
    gd.cache_put(key, Ttl::OneHour, &version).await;
    Ok(version)
}

/// Every champion of `version` (cached 24 h per version)
pub async fn champions(gd: &GameData, version: &str) -> Result<Vec<Champion>> {
    if !valid_version(version) {
        return Err(GameDataError::Upstream("invalid version".into()));
    }
    let key = format!("gamedata:v1:riot_champions:{version}");
    if let Some(champions) = gd.cache_get(&key, Ttl::OneDay).await {
        return Ok(champions);
    }
    let body = gd
        .get_bytes(
            &format!("{DDRAGON}/cdn/{version}/data/en_US/champion.json"),
            None,
        )
        .await?;
    let champions = parse_champions(&body)?;
    gd.cache_put(&key, Ttl::OneDay, &champions).await;
    Ok(champions)
}

/// Card for a champion
pub fn card(champion: &Champion, version: &str, url: &str) -> GameCard {
    let image_url = (valid_version(version) && valid_file_name(&champion.image_full)).then(|| {
        format!(
            "{DDRAGON}/cdn/{version}/img/champion/{}",
            champion.image_full
        )
    });
    let title = if champion.title.is_empty() {
        champion.name.clone()
    } else {
        format!("{}, {}", champion.name, champion.title)
    };

    finish_card(
        GameCard {
            title,
            subtitle: (!champion.tags.is_empty()).then(|| champion.tags.join(" \u{00B7} ")),
            description: Some(text::plain_text(&champion.blurb)),
            image_url,
            image_large: false,
            site_name: "League of Legends".to_string(),
            colour: Some("#c8aa6e".to_string()),
            url: url.to_string(),
        },
        &champion_url(champion),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSIONS: &str = include_str!("../tests/fixtures/riot_versions.json");
    const CHAMPIONS: &str = include_str!("../tests/fixtures/riot_champion.json");

    #[test]
    fn parses_versions() {
        assert_eq!(parse_versions(VERSIONS.as_bytes()).unwrap(), "16.20.1");
        assert!(parse_versions(b"[]").is_err());
        assert!(parse_versions(br#"["../../etc"]"#).is_err());
    }

    #[test]
    fn parses_and_finds_champions() {
        let champions = parse_champions(CHAMPIONS.as_bytes()).unwrap();
        assert_eq!(champions.len(), 6);
        // by id, by name, by apostrophe'd name, case-insensitive
        assert_eq!(find_champion(&champions, "monkeyking").unwrap().name, "Wukong");
        assert_eq!(find_champion(&champions, "Wukong").unwrap().id, "MonkeyKing");
        assert_eq!(find_champion(&champions, "k-sante").unwrap().id, "KSante");
        assert_eq!(find_champion(&champions, "KAI'SA").unwrap().id, "Kaisa");
        assert_eq!(find_champion(&champions, "nunu").unwrap().id, "Nunu");
        assert!(find_champion(&champions, "teemo").is_none());
        assert!(find_champion(&champions, "'''").is_none());
    }

    #[test]
    fn champion_card_image_url() {
        let champions = parse_champions(CHAMPIONS.as_bytes()).unwrap();
        let wukong = find_champion(&champions, "wukong").unwrap();
        let card = card(
            wukong,
            "16.20.1",
            "https://www.leagueoflegends.com/en-us/champions/wukong/",
        );
        assert_eq!(
            card.image_url.as_deref(),
            Some("https://ddragon.leagueoflegends.com/cdn/16.20.1/img/champion/MonkeyKing.png")
        );
        assert_eq!(card.title, "Wukong, the Monkey King");
        assert_eq!(card.subtitle.as_deref(), Some("Fighter \u{00B7} Tank"));
        assert!(card.description.unwrap().starts_with("Wukong is a vastayan trickster"));
        assert!(!card.image_large);
        assert_eq!(card.site_name, "League of Legends");
        assert_eq!(card.colour.as_deref(), Some("#c8aa6e"));

        // A version or file name that could escape the path gets no image
        assert_eq!(super::card(wukong, "../x", "https://x/").image_url, None);
        let mut evil = wukong.clone();
        evil.image_full = "../../x.png".into();
        assert_eq!(super::card(&evil, "16.20.1", "https://x/").image_url, None);
    }

    #[test]
    fn search_hits_by_name_substring() {
        let champions = parse_champions(CHAMPIONS.as_bytes()).unwrap();
        let hits = search_hits(&champions, "A");
        // Aatrox, Ahri, Kai'Sa, K'Sante (Wukong has no `a`, Nunu & Willump neither)
        assert_eq!(hits.len(), 4);
        let hits = search_hits(&champions, "kong");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "Wukong");
        assert_eq!(hits[0].subtitle.as_deref(), Some("the Monkey King"));
        assert_eq!(
            hits[0].url,
            "https://www.leagueoflegends.com/en-us/champions/monkeyking/"
        );
        assert!(search_hits(&champions, "  ").is_empty());
    }
}
