//! Game cards for Steam, World of Warcraft and League of Legends links
//!
//! A card is chosen from the request URL alone (never a rewritten URL, never
//! the page's `og:url`) and built through `revolt_gamedata` before any page
//! is fetched. It fills the ordinary `WebsiteMetadata` fields, so no new
//! embed or `Special` variant reaches the wire. Cards are only built for
//! callers that presented the internal key (`enrich`); every other caller,
//! and every failure, gets the normal OpenGraph preview.

use revolt_gamedata::{card_for, CardTarget, GameCard, GameData, GameDataError, Pool};
use revolt_models::v0::{Embed, Image, ImageSize, WebsiteMetadata};

/// `EMBED_CACHE` key: the URL, and whether the entry is the result for a
/// game link requested with enrichment. Only game links are split, so an
/// anonymous plain preview is never served to the embed worker (losing the
/// card) nor a card to an anonymous caller, while every other URL shares
/// one entry exactly as before.
pub type EmbedCacheKey = (String, bool);

/// Which card `url` gets: `None` unless the caller may spend the game data
/// budget (`enrich`) and the URL itself is a game link
pub fn game_target_for(url: &str, enrich: bool) -> Option<CardTarget> {
    if !enrich {
        return None;
    }

    revolt_gamedata::match_url(url)
}

/// Cache key for the embed of `url` requested with or without enrichment
pub fn embed_cache_key(url: &str, enrich: bool) -> EmbedCacheKey {
    (url.to_owned(), game_target_for(url, enrich).is_some())
}

/// Known dimensions of each source's card image: Steam header capsule,
/// Blizzard 56 px item icon, Data Dragon champion square
fn image_dimensions(target: &CardTarget) -> (usize, usize) {
    match target {
        CardTarget::SteamApp(_) => (460, 215),
        CardTarget::WowItem(_) => (56, 56),
        CardTarget::Champion(_) => (120, 120),
    }
}

/// Byte limits `WebsiteMetadata::truncate` applies. The card is cut to them
/// on a character boundary first, because `String::truncate` panics inside
/// a multi-byte character.
const CAP_URL: usize = 256;
const CAP_TITLE: usize = 100;
const CAP_DESCRIPTION: usize = 1000;
const CAP_SITE_NAME: usize = 32;
const CAP_COLOUR: usize = 32;

/// Keep at most `max` bytes of `value`, cutting on a character boundary
fn cap_bytes(mut value: String, max: usize) -> String {
    if value.len() > max {
        let mut end = max;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    value
}

/// Website metadata for a card on `request_url`; `None` if the card would
/// be an empty embed
pub fn card_metadata(
    target: &CardTarget,
    request_url: &str,
    card: GameCard,
) -> Option<WebsiteMetadata> {
    let GameCard {
        title,
        subtitle,
        description,
        image_url,
        image_large,
        site_name,
        colour,
        url,
    } = card;

    let description = match (subtitle, description) {
        (Some(subtitle), Some(description)) => Some(format!("{subtitle}\n\n{description}")),
        (subtitle, description) => subtitle.or(description),
    };

    let (width, height) = image_dimensions(target);
    let image = image_url.map(|url| Image {
        url,
        width,
        height,
        size: if image_large {
            ImageSize::Large
        } else {
            ImageSize::Preview
        },
    });

    let mut metadata = WebsiteMetadata {
        // The request URL, unless gamedata replaced an unusable one with the
        // canonical page (a cut URL would be a broken link)
        url: Some(cap_bytes(url, CAP_URL)),
        original_url: Some(cap_bytes(request_url.to_owned(), CAP_URL)),
        special: None,
        title: Some(cap_bytes(title, CAP_TITLE)).filter(|title| !title.is_empty()),
        description: description.map(|description| cap_bytes(description, CAP_DESCRIPTION)),
        image,
        video: None,
        site_name: Some(cap_bytes(site_name, CAP_SITE_NAME)).filter(|name| !name.is_empty()),
        icon_url: None,
        colour: colour.map(|colour| cap_bytes(colour, CAP_COLOUR)),
    };

    // Already within every limit; kept so the shared caps stay authoritative
    metadata.truncate();

    if metadata.is_empty() {
        None
    } else {
        Some(metadata)
    }
}

/// Short name of a game data failure, for logs (never the URL)
fn error_kind(error: &GameDataError) -> &'static str {
    match error {
        GameDataError::Budget => "budget",
        GameDataError::Disabled => "disabled",
        GameDataError::NotFound => "not found",
        GameDataError::HostNotAllowed => "host not allowed",
        GameDataError::Upstream(_) => "upstream",
    }
}

/// The card embed for `request_url`, or `None` on any failure (the caller
/// then builds the normal preview)
pub async fn card_embed(target: &CardTarget, request_url: &str) -> Option<Embed> {
    let gd = GameData::global().await;
    match card_for(gd, target, request_url, Pool::Embed).await {
        Ok(card) => card_metadata(target, request_url, card).map(Embed::Website),
        Err(error) => {
            tracing::debug!(
                "game card unavailable ({}), using the normal preview",
                error_kind(&error)
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STEAM: &str = "https://store.steampowered.com/app/620/Portal_2/";
    const WOWHEAD: &str = "https://www.wowhead.com/item=19019/thunderfury";
    const LEAGUE: &str = "https://www.leagueoflegends.com/en-us/champions/ahri/";

    fn card(site_name: &str, image_large: bool) -> GameCard {
        GameCard {
            title: "Title".to_string(),
            subtitle: Some("Sub \u{00B7} title".to_string()),
            description: Some("Body text".to_string()),
            image_url: Some("https://cdn.example/image.jpg".to_string()),
            image_large,
            site_name: site_name.to_string(),
            colour: Some("#123456".to_string()),
            url: "https://canonical.example/page".to_string(),
        }
    }

    #[test]
    fn steam_card_maps_to_a_large_460_by_215_image() {
        let target = game_target_for(STEAM, true).expect("steam link");
        let metadata = card_metadata(&target, STEAM, card("Steam", true)).expect("card");

        assert_eq!(metadata.special, None);
        assert_eq!(metadata.title.as_deref(), Some("Title"));
        assert_eq!(
            metadata.description.as_deref(),
            Some("Sub \u{00B7} title\n\nBody text")
        );
        assert_eq!(metadata.site_name.as_deref(), Some("Steam"));
        assert_eq!(metadata.colour.as_deref(), Some("#123456"));
        assert_eq!(metadata.original_url.as_deref(), Some(STEAM));
        assert_eq!(
            metadata.url.as_deref(),
            Some("https://canonical.example/page")
        );
        assert_eq!(metadata.video, None);
        assert_eq!(metadata.icon_url, None);
        assert_eq!(
            metadata.image,
            Some(Image {
                url: "https://cdn.example/image.jpg".to_string(),
                width: 460,
                height: 215,
                size: ImageSize::Large,
            })
        );
    }

    #[test]
    fn wow_card_maps_to_a_56_px_preview_icon() {
        let target = game_target_for(WOWHEAD, true).expect("wowhead link");
        assert_eq!(target, CardTarget::WowItem(19019));
        let metadata =
            card_metadata(&target, WOWHEAD, card("World of Warcraft", false)).expect("card");

        assert_eq!(metadata.special, None);
        assert_eq!(metadata.site_name.as_deref(), Some("World of Warcraft"));
        let image = metadata.image.expect("image");
        assert_eq!((image.width, image.height), (56, 56));
        assert_eq!(image.size, ImageSize::Preview);
    }

    #[test]
    fn league_card_maps_to_a_120_px_preview_square() {
        let target = game_target_for(LEAGUE, true).expect("league link");
        let metadata =
            card_metadata(&target, LEAGUE, card("League of Legends", false)).expect("card");

        assert_eq!(metadata.special, None);
        assert_eq!(metadata.site_name.as_deref(), Some("League of Legends"));
        let image = metadata.image.expect("image");
        assert_eq!((image.width, image.height), (120, 120));
        assert_eq!(image.size, ImageSize::Preview);
    }

    #[test]
    fn description_joins_whichever_parts_exist() {
        let target = CardTarget::SteamApp(620);
        for (subtitle, description, joined) in [
            (Some("S"), Some("D"), Some("S\n\nD")),
            (Some("S"), None, Some("S")),
            (None, Some("D"), Some("D")),
            (None, None, None),
        ] {
            let mut input = card("Steam", true);
            input.subtitle = subtitle.map(String::from);
            input.description = description.map(String::from);
            let metadata = card_metadata(&target, STEAM, input).expect("card");
            assert_eq!(metadata.description.as_deref(), joined, "{subtitle:?} {description:?}");
        }
    }

    #[test]
    fn a_card_without_an_image_has_none() {
        let mut input = card("Steam", true);
        input.image_url = None;
        let metadata = card_metadata(&CardTarget::SteamApp(620), STEAM, input).expect("card");
        assert_eq!(metadata.image, None);
    }

    #[test]
    fn an_empty_card_is_no_card() {
        let input = GameCard {
            title: String::new(),
            subtitle: None,
            description: None,
            image_url: None,
            image_large: false,
            site_name: "Steam".to_string(),
            colour: None,
            url: STEAM.to_string(),
        };
        assert!(card_metadata(&CardTarget::SteamApp(620), STEAM, input).is_none());
    }

    #[test]
    fn multi_byte_fields_are_capped_on_a_character_boundary() {
        // 3-byte characters: no byte limit falls on a boundary
        let mut input = card("\u{30B9}".repeat(20).as_str(), true);
        input.title = "\u{30B9}".repeat(100);
        input.subtitle = Some("\u{00B7}".repeat(200));
        input.description = Some("\u{30B9}".repeat(1000));
        input.url = format!("https://store.steampowered.com/app/620/{}", "\u{00E9}".repeat(200));

        let metadata =
            card_metadata(&CardTarget::SteamApp(620), STEAM, input).expect("card (no panic)");
        assert!(metadata.title.as_ref().unwrap().len() <= CAP_TITLE);
        assert!(metadata.description.as_ref().unwrap().len() <= CAP_DESCRIPTION);
        assert!(metadata.site_name.as_ref().unwrap().len() <= CAP_SITE_NAME);
        assert!(metadata.url.as_ref().unwrap().len() <= CAP_URL);
    }

    #[test]
    fn gate_only_matches_when_enrichment_was_unlocked() {
        for url in [STEAM, WOWHEAD, LEAGUE] {
            assert!(game_target_for(url, true).is_some(), "{url}");
            assert_eq!(game_target_for(url, false), None, "{url}");
        }
        assert_eq!(game_target_for(STEAM, true), Some(CardTarget::SteamApp(620)));
    }

    #[test]
    fn gate_judges_the_request_url_never_the_page_og_url() {
        // A page whose og:url is a Steam link: only the request URL counts
        let page = "https://blog.example/my-favourite-game";
        let og_url = "https://store.steampowered.com/app/620/";
        assert!(game_target_for(og_url, true).is_some(), "control: og:url is a game link");
        assert_eq!(game_target_for(page, true), None);
        assert_eq!(game_target_for(page, false), None);

        // Classic Wowhead and unknown hosts keep the normal preview
        assert_eq!(
            game_target_for("https://www.wowhead.com/classic/item=19019", true),
            None
        );
        assert_eq!(game_target_for("https://example.com/app/620", true), None);
    }

    #[test]
    fn cache_key_separates_enriched_game_links() {
        assert_ne!(embed_cache_key(STEAM, true), embed_cache_key(STEAM, false));
        assert_ne!(
            embed_cache_key(LEAGUE, true),
            embed_cache_key(LEAGUE, false)
        );
        assert_eq!(embed_cache_key(STEAM, false), (STEAM.to_string(), false));

        // Every other URL keeps one shared entry, as before
        let page = "https://blog.example/post";
        assert_eq!(embed_cache_key(page, true), embed_cache_key(page, false));
    }

    #[test]
    fn errors_are_logged_by_kind_only() {
        assert_eq!(
            error_kind(&GameDataError::Upstream("https://secret.example".into())),
            "upstream"
        );
        assert_eq!(error_kind(&GameDataError::Budget), "budget");
    }
}
