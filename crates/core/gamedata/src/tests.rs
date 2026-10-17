//! Cross-module tests. None of these reach the network: every request
//! they provoke is refused before it is sent, or targets a name the
//! vetting resolver refuses.

use std::time::Duration;

use revolt_config::ApiGamedata;

use crate::{
    blizzard, budget::Budget, card_for, http, lookup, match_url, riot, steam, CardTarget,
    GameData, GameDataError, LookupSource, Pool,
};

const STEAM_SEARCH: &str = include_str!("../tests/fixtures/steam_storesearch.json");
const STEAM_APP: &str = include_str!("../tests/fixtures/steam_appdetails_620.json");
const WOW_SEARCH: &str = include_str!("../tests/fixtures/blizzard_search.json");
const CHAMPIONS: &str = include_str!("../tests/fixtures/riot_champion.json");

/// A fixed instant, mid-window for every budget (300 s and 1 s windows)
const NOW: u64 = 1_800_000_150;

fn champion(slug: &str) -> Option<CardTarget> {
    Some(CardTarget::Champion(slug.to_string()))
}

#[test]
fn match_url_positive() {
    for (url, target) in [
        ("https://store.steampowered.com/app/620/Portal_2/", Some(CardTarget::SteamApp(620))),
        ("https://store.steampowered.com/app/620", Some(CardTarget::SteamApp(620))),
        ("http://store.steampowered.com/app/620/", Some(CardTarget::SteamApp(620))),
        ("https://STORE.SteamPowered.com/app/620/?l=german#x", Some(CardTarget::SteamApp(620))),
        ("https://www.wowhead.com/item=19019", Some(CardTarget::WowItem(19019))),
        ("https://wowhead.com/item=19019/thunderfury-blessed-blade", Some(CardTarget::WowItem(19019))),
        ("http://www.wowhead.com/item=19019/?bonus=1", Some(CardTarget::WowItem(19019))),
        ("https://www.leagueoflegends.com/en-us/champions/ahri/", champion("ahri")),
        ("https://leagueoflegends.com/pt-BR/champions/k-sante", champion("ksante")),
        ("https://www.leagueoflegends.com/en-gb/champions/Kai'Sa/", champion("kaisa")),
        ("https://op.gg/champions/ahri", champion("ahri")),
        ("https://www.op.gg/champions/ahri/build?region=na", champion("ahri")),
        ("https://op.gg/lol/champions/monkeyking/counters", champion("monkeyking")),
    ] {
        assert_eq!(match_url(url), target, "{url}");
    }
}

#[test]
fn match_url_negative() {
    for url in [
        "evil.com/store.steampowered.com/app/1",
        "https://evil.com/store.steampowered.com/app/1",
        "https://store.steampowered.com.evil.com/app/1",
        "https://evilstore.steampowered.com/app/1",
        "https://store.steampowered.com@evil.com/app/1",
        "https://user:pw@store.steampowered.com/app/1",
        "ftp://store.steampowered.com/app/1",
        "https://store.steampowered.com/app/",
        "https://store.steampowered.com/app/+1",
        "https://store.steampowered.com/app/1x",
        "https://store.steampowered.com/app/99999999999",
        "https://store.steampowered.com/sub/1",
        "https://store.steampowered.com/",
        "https://www.wowhead.com/classic/item=19019",
        "https://www.wowhead.com/ptr/item=19019",
        "https://www.wowhead.com/item=abc",
        "https://www.wowhead.com/item=",
        "https://www.wowhead.com/npc=1",
        "https://www.wowhead.com/item=1/slug/extra",
        "https://wowhead.com.evil.com/item=1",
        "https://www.leagueoflegends.com/champions/ahri/",
        "https://www.leagueoflegends.com/en-us/champions/",
        "https://www.leagueoflegends.com/en-us/champions/ahri/skins",
        "https://www.leagueoflegends.com/english/champions/ahri/",
        "https://www.leagueoflegends.com/en-us/champions/'''/",
        "https://na.op.gg/champions/ahri",
        "https://op.gg/summoners/na/foo",
        "https://op.gg.evil.com/champions/ahri",
        "not a url",
        "",
    ] {
        assert_eq!(match_url(url), None, "{url}");
    }
}

#[test]
fn every_lookup_hit_round_trips_through_match_url() {
    let steam_hits = steam::parse_search(STEAM_SEARCH.as_bytes()).unwrap();
    assert!(!steam_hits.is_empty());
    let raw: serde_json::Value = serde_json::from_str(STEAM_SEARCH).unwrap();
    for (hit, item) in steam_hits.iter().zip(raw["items"].as_array().unwrap()) {
        let id = item["id"].as_u64().unwrap() as u32;
        assert_eq!(match_url(&hit.url), Some(CardTarget::SteamApp(id)), "{}", hit.url);
    }

    let wow_hits = blizzard::parse_search(WOW_SEARCH.as_bytes()).unwrap();
    assert_eq!(wow_hits.len(), 2);
    assert_eq!(match_url(&wow_hits[0].url), Some(CardTarget::WowItem(19019)));
    assert_eq!(match_url(&wow_hits[1].url), Some(CardTarget::WowItem(17182)));

    let champions = riot::parse_champions(CHAMPIONS.as_bytes()).unwrap();
    let lol_hits = riot::search_hits(&champions, "");
    assert!(lol_hits.is_empty());
    // Every champion, as a hit, resolves back to itself
    for champion in &champions {
        let hits = riot::search_hits(&champions, &champion.name);
        let hit = hits
            .iter()
            .find(|h| h.title == champion.name)
            .expect("champion finds itself");
        let Some(CardTarget::Champion(slug)) = match_url(&hit.url) else {
            panic!("{} does not match", hit.url);
        };
        assert_eq!(slug, riot::normalise_slug(&champion.id));
        assert_eq!(riot::find_champion(&champions, &slug), Some(champion));
    }
}

#[test]
fn allowlist_accepts_only_its_hosts_over_https() {
    for url in [
        "https://store.steampowered.com/api/appdetails?appids=1",
        "https://api.steampowered.com/ISteamNews/GetNewsForApp/v2/",
        "https://oauth.battle.net/token",
        "https://us.api.blizzard.com/data/wow/item/1",
        "https://ddragon.leagueoflegends.com/api/versions.json",
        "https://STORE.steampowered.com:443/x",
    ] {
        assert!(http::check_url(url).is_ok(), "{url}");
    }
    for url in [
        "http://store.steampowered.com/api/appdetails",
        "https://store.steampowered.com.evil.com/",
        "https://evil.com/store.steampowered.com/",
        "https://steampowered.com/",
        "https://eu.api.blizzard.com/data/wow/item/1",
        "https://store.steampowered.com:8443/",
        "https://user@store.steampowered.com/",
        "https://127.0.0.1/",
        "https://localhost/",
        "https://www.wowhead.com/item=1",
        "not a url",
    ] {
        assert!(
            matches!(http::check_url(url), Err(GameDataError::HostNotAllowed)),
            "{url}"
        );
    }
}

#[tokio::test]
async fn non_allowlisted_host_is_refused_before_any_request() {
    let gd = GameData::for_tests();
    // `localhost` would otherwise reach the vetting resolver and fail as
    // `Upstream` (127.0.0.1 is forbidden), so `HostNotAllowed` proves the
    // allowlist answered before a request was built
    for url in ["https://localhost/", "https://127.0.0.1:1/x"] {
        let result = tokio::time::timeout(Duration::from_secs(20), gd.get_bytes(url, None))
            .await
            .expect("no hang");
        assert!(
            matches!(result, Err(GameDataError::HostNotAllowed)),
            "{url}: {result:?}"
        );
    }
}

#[tokio::test]
async fn budget_n_plus_one_is_refused_and_steam_pools_are_independent() {
    let gd = GameData::for_tests();
    let cfg = ApiGamedata::default();

    for _ in 0..cfg.steam_store_embed_budget {
        gd.take_budget_at(Budget::SteamStore(Pool::Embed), NOW).await.unwrap();
    }
    assert!(matches!(
        gd.take_budget_at(Budget::SteamStore(Pool::Embed), NOW).await,
        Err(GameDataError::Budget)
    ));

    // The interactive share is untouched by the spent embed share
    for _ in 0..cfg.steam_store_interactive_budget {
        gd.take_budget_at(Budget::SteamStore(Pool::Interactive), NOW)
            .await
            .unwrap();
    }
    assert!(matches!(
        gd.take_budget_at(Budget::SteamStore(Pool::Interactive), NOW).await,
        Err(GameDataError::Budget)
    ));

    // News has its own budget
    for _ in 0..cfg.steam_news_per_window {
        gd.take_budget_at(Budget::SteamNews, NOW).await.unwrap();
    }
    assert!(matches!(
        gd.take_budget_at(Budget::SteamNews, NOW).await,
        Err(GameDataError::Budget)
    ));

    // The next window starts afresh
    gd.take_budget_at(Budget::SteamStore(Pool::Embed), NOW + 300)
        .await
        .unwrap();
}

#[tokio::test]
async fn blizzard_budget_is_shared_by_both_pools() {
    let gd = GameData::for_tests();
    let limit = ApiGamedata::default().blizzard_per_second;
    assert_eq!(limit, 20);
    // Embed and interactive callers both draw on `Budget::Blizzard`
    for _ in 0..limit {
        gd.take_budget_at(Budget::Blizzard, NOW).await.unwrap();
    }
    assert!(matches!(
        gd.take_budget_at(Budget::Blizzard, NOW).await,
        Err(GameDataError::Budget)
    ));
    // One second later the window is new
    gd.take_budget_at(Budget::Blizzard, NOW + 1).await.unwrap();
}

#[tokio::test]
async fn an_empty_budget_refuses_before_fetching_and_a_cache_hit_is_free() {
    let gd = GameData::for_tests_with(ApiGamedata {
        steam_store_embed_budget: 0,
        steam_store_interactive_budget: 0,
        steam_news_per_window: 0,
        ..ApiGamedata::default()
    });

    assert!(matches!(
        steam::app_details(&gd, 620, Pool::Embed).await,
        Err(GameDataError::Budget)
    ));
    assert!(matches!(
        steam::search(&gd, "portal", Pool::Interactive).await,
        Err(GameDataError::Budget)
    ));
    assert!(matches!(steam::news(&gd, 730, 3).await, Err(GameDataError::Budget)));
    assert!(matches!(
        lookup(&gd, LookupSource::Steam, "portal").await,
        Err(GameDataError::Budget)
    ));
    assert!(matches!(
        card_for(
            &gd,
            &CardTarget::SteamApp(620),
            "https://store.steampowered.com/app/620/",
            Pool::Embed
        )
        .await,
        Err(GameDataError::Budget)
    ));

    // With the app cached, the spent budget does not matter
    let app = steam::parse_app_details(STEAM_APP.as_bytes(), 620).unwrap();
    gd.cache_put("gamedata:v1:steam_app:620", crate::cache::Ttl::SixHours, &app)
        .await;
    let card = card_for(
        &gd,
        &CardTarget::SteamApp(620),
        "https://store.steampowered.com/app/620/",
        Pool::Embed,
    )
    .await
    .unwrap();
    assert_eq!(card.title, "Portal 2");
}

#[tokio::test]
async fn blizzard_without_credentials_is_disabled() {
    let gd = GameData::for_tests();
    assert!(matches!(
        blizzard::item(&gd, 19019, Pool::Embed).await,
        Err(GameDataError::Disabled)
    ));
    assert!(matches!(
        blizzard::item_media(&gd, 19019, Pool::Embed).await,
        Err(GameDataError::Disabled)
    ));
    assert!(matches!(
        blizzard::item_search(&gd, "thunderfury", Pool::Interactive).await,
        Err(GameDataError::Disabled)
    ));
    assert!(matches!(
        lookup(&gd, LookupSource::Wow, "thunderfury").await,
        Err(GameDataError::Disabled)
    ));
    assert!(matches!(
        card_for(
            &gd,
            &CardTarget::WowItem(19019),
            "https://www.wowhead.com/item=19019",
            Pool::Embed
        )
        .await,
        Err(GameDataError::Disabled)
    ));

    // One half of the pair is not enough
    let gd = GameData::for_tests_with(ApiGamedata {
        blizzard_client_id: "id".into(),
        blizzard_client_secret: "   ".into(),
        ..ApiGamedata::default()
    });
    assert!(matches!(
        blizzard::item(&gd, 19019, Pool::Embed).await,
        Err(GameDataError::Disabled)
    ));
}

#[tokio::test]
async fn empty_queries_make_no_request() {
    let gd = GameData::for_tests();
    for source in [LookupSource::Steam, LookupSource::Lol] {
        assert_eq!(lookup(&gd, source, "   ").await.unwrap(), vec![]);
    }
}

#[test]
fn query_is_trimmed_to_100_chars() {
    let long = format!("  {}  ", "\u{00E9}".repeat(150));
    let query = crate::normalise_query(&long);
    assert_eq!(query.chars().count(), 100);
}

#[test]
fn body_cap_is_one_mebibyte() {
    let mut body = Vec::new();
    http::push_capped(&mut body, &vec![0u8; http::MAX_BODY_BYTES - 1]).unwrap();
    http::push_capped(&mut body, &[0u8]).unwrap();
    assert!(matches!(
        http::push_capped(&mut body, &[0u8]),
        Err(GameDataError::Upstream(_))
    ));
    assert_eq!(body.len(), http::MAX_BODY_BYTES);
}

#[test]
fn budget_keys_follow_the_documented_shape() {
    let gd = GameData::for_tests();
    assert_eq!(gd.budget_spec(Budget::SteamStore(Pool::Embed)).stem, "steam_store:embed");
    assert_eq!(
        gd.budget_spec(Budget::SteamStore(Pool::Interactive)).stem,
        "steam_store:interactive"
    );
    assert_eq!(gd.budget_spec(Budget::SteamNews).stem, "steam_news:shared");
    let blizzard = gd.budget_spec(Budget::Blizzard);
    assert_eq!((blizzard.stem, blizzard.window_secs), ("blizzard:shared", 1));
    assert_eq!(gd.budget_spec(Budget::SteamStore(Pool::Embed)).window_secs, 300);
}

fn with_internal_key(key: &str) -> GameData {
    GameData::for_tests_with(ApiGamedata {
        internal_key: key.to_string(),
        ..ApiGamedata::default()
    })
}

#[test]
fn empty_internal_key_never_unlocks() {
    for configured in ["", "   ", "\t\n"] {
        let gd = with_internal_key(configured);
        assert!(!gd.internal_key_ok(Some("")), "empty header vs {configured:?}");
        assert!(!gd.internal_key_ok(Some(configured)), "same blank vs {configured:?}");
        assert!(!gd.internal_key_ok(None), "missing header vs {configured:?}");
        assert!(!gd.internal_key_ok(Some("anything")), "any header vs {configured:?}");
    }
}

#[test]
fn internal_key_must_be_presented_and_exact() {
    let gd = with_internal_key("la1-internal-key");
    assert!(!gd.internal_key_ok(None), "missing header");
    assert!(!gd.internal_key_ok(Some("")), "empty header");
    assert!(!gd.internal_key_ok(Some("la1-internal-kex")), "wrong key");
    assert!(!gd.internal_key_ok(Some("la1-internal-ke")), "prefix");
    assert!(!gd.internal_key_ok(Some("la1-internal-key ")), "suffix");
    assert!(!gd.internal_key_ok(Some("LA1-INTERNAL-KEY")), "case");
    assert!(gd.internal_key_ok(Some("la1-internal-key")), "right key");
}
