//! GET /lookup/games?source=steam|wow|lol&q=<text>
//!
//! Searches one game data source and returns up to five
//! `{ title, subtitle, url }` candidates. Upstream calls go through
//! `revolt-gamedata`, so they draw on the shared `interactive` budget share
//! and its caches.
//!
//! Two rate limits apply. The `lookup` ratelimit bucket (5 per window) is
//! keyed per session, and the fairing's window is fixed at 10 s for every
//! bucket. The contract is 5 per 30 s per USER, so the route also keeps its
//! own per-user 30 s window (`LookupWindows`), which a user with several
//! sessions cannot multiply.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use revolt_database::User;
use revolt_gamedata::{GameData, GameDataError, LookupSource, SearchHit};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Most results a lookup returns
const MAX_HITS: usize = 5;

/// Raw queries longer than this are refused before any trimming. The
/// gamedata crate trims and cuts the query to 100 characters on its own.
const MAX_RAW_QUERY_CHARS: usize = 200;

/// Per-user lookup window
const WINDOW_SECS: u64 = 30;
/// Lookups that reach the upstream per user per window
const WINDOW_LIMIT: u32 = 5;
/// Once this many users are tracked, entries from past windows are dropped
const WINDOW_PRUNE_AT: usize = 4096;

/// `retry_after` sent when the shared upstream budget is spent. The budget
/// windows live in the gamedata crate (5 minutes for the Steam store, 1 s
/// for Blizzard); this is a hint for the client, not a promise.
const BUDGET_RETRY_AFTER_SECS: u64 = 30;

/// # Game Lookup Result
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, PartialEq)]
pub struct GameLookupHit {
    /// Name of the game, item or champion
    pub title: String,
    /// Short secondary line, if the source has one
    pub subtitle: Option<String>,
    /// Link to send; it renders as a game card
    pub url: String,
}

impl From<SearchHit> for GameLookupHit {
    fn from(hit: SearchHit) -> Self {
        GameLookupHit {
            title: hit.title,
            subtitle: hit.subtitle,
            url: hit.url,
        }
    }
}

/// Parse the `source` query parameter. Exact, lowercase names only.
fn parse_source(source: &str) -> Result<LookupSource> {
    match source {
        "steam" => Ok(LookupSource::Steam),
        "wow" => Ok(LookupSource::Wow),
        "lol" => Ok(LookupSource::Lol),
        _ => Err(create_error!(InvalidOperation)),
    }
}

fn source_name(source: LookupSource) -> &'static str {
    match source {
        LookupSource::Steam => "steam",
        LookupSource::Wow => "wow",
        LookupSource::Lol => "lol",
    }
}

/// Validate a request. `Ok(None)` means the trimmed query is empty: the
/// answer is `[]` and nothing upstream is touched.
fn prepare<'q>(
    user: &User,
    source: Option<&str>,
    q: Option<&'q str>,
) -> Result<Option<(LookupSource, &'q str)>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let q = q.unwrap_or("");
    if q.chars().count() > MAX_RAW_QUERY_CHARS {
        return Err(create_error!(FailedValidation {
            error: format!("q: at most {MAX_RAW_QUERY_CHARS} characters"),
        }));
    }

    let source = parse_source(source.unwrap_or(""))?;

    let query = q.trim();
    if query.is_empty() {
        return Ok(None);
    }

    Ok(Some((source, query)))
}

/// Map a gamedata failure onto the response. Only existing error variants
/// are used, so clients need no new cast. The match is exhaustive on
/// purpose: a new `GameDataError` variant must be mapped here explicitly.
fn map_lookup_error(source: LookupSource, error: GameDataError) -> Result<Vec<SearchHit>> {
    match error {
        // Nothing matched: an empty result, not an error
        GameDataError::NotFound => Ok(Vec::new()),
        // The shared upstream budget is spent: the user should retry later
        GameDataError::Budget => {
            log::info!(
                "lookup: {} budget spent, refusing with InSlowmode",
                source_name(source)
            );
            Err(create_error!(InSlowmode {
                retry_after: BUDGET_RETRY_AFTER_SECS
            }))
        }
        // The source is switched off (for WoW: no Blizzard credentials)
        GameDataError::Disabled => Err(create_error!(FeatureDisabled {
            feature: format!("game_lookup_{}", source_name(source)),
        })),
        // Upstream trouble degrades quietly to an empty result
        GameDataError::Upstream(reason) => {
            log::warn!("lookup: {} upstream error: {reason}", source_name(source));
            Ok(Vec::new())
        }
        GameDataError::HostNotAllowed => {
            log::warn!(
                "lookup: {} upstream host refused by the allowlist",
                source_name(source)
            );
            Ok(Vec::new())
        }
    }
}

/// Fixed 30 s windows per user id: user id -> (window index, lookups)
#[derive(Default)]
struct LookupWindows {
    counters: HashMap<String, (u64, u32)>,
}

impl LookupWindows {
    /// Count one lookup by `user_id` at `now_secs`. `Err(retry_after)` once
    /// the user has spent this window.
    fn take(&mut self, user_id: &str, now_secs: u64) -> std::result::Result<(), u64> {
        let window = now_secs / WINDOW_SECS;

        // Bounded: past windows are dropped once the map is large, so it
        // holds at most the users who looked something up in this window
        if self.counters.len() >= WINDOW_PRUNE_AT && !self.counters.contains_key(user_id) {
            self.counters.retain(|_, (w, _)| *w == window);
        }

        let entry = self
            .counters
            .entry(user_id.to_string())
            .or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= WINDOW_LIMIT {
            return Err(WINDOW_SECS - now_secs % WINDOW_SECS);
        }
        entry.1 += 1;
        Ok(())
    }
}

fn windows() -> &'static Mutex<LookupWindows> {
    static WINDOWS: OnceLock<Mutex<LookupWindows>> = OnceLock::new();
    WINDOWS.get_or_init(|| Mutex::new(LookupWindows::default()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Spend one slot of the user's window, or refuse with `InSlowmode`
fn take_slot(windows: &Mutex<LookupWindows>, user_id: &str, now_secs: u64) -> Result<()> {
    // The guarded section only touches a HashMap; recover a poisoned lock
    // rather than failing every later lookup
    let mut windows = windows
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    windows
        .take(user_id, now_secs)
        .map_err(|retry_after| create_error!(InSlowmode { retry_after }))
}

/// The route body, with the upstream search passed in so tests can count
/// calls without network access
async fn run<F, Fut>(
    user: &User,
    source: Option<&str>,
    q: Option<&str>,
    windows: &Mutex<LookupWindows>,
    now_secs: u64,
    search: F,
) -> Result<Vec<GameLookupHit>>
where
    F: FnOnce(LookupSource, String) -> Fut,
    Fut: Future<Output = revolt_gamedata::Result<Vec<SearchHit>>>,
{
    let Some((source, query)) = prepare(user, source, q)? else {
        return Ok(Vec::new());
    };

    take_slot(windows, &user.id, now_secs)?;

    let hits = match search(source, query.to_string()).await {
        Ok(hits) => hits,
        Err(error) => map_lookup_error(source, error)?,
    };

    Ok(hits
        .into_iter()
        .take(MAX_HITS)
        .map(GameLookupHit::from)
        .collect())
}

/// # Look Up Games
///
/// Search Steam games (`steam`), World of Warcraft items (`wow`) or League
/// of Legends champions (`lol`). Returns up to five results; an empty or
/// blank query returns an empty list. Bots cannot use this route.
#[openapi(tag = "Game Lookup")]
#[get("/games?<source>&<q>")]
pub async fn lookup_games(
    user: User,
    source: Option<String>,
    q: Option<String>,
) -> Result<Json<Vec<GameLookupHit>>> {
    run(
        &user,
        source.as_deref(),
        q.as_deref(),
        windows(),
        now_secs(),
        |source, query| async move {
            revolt_gamedata::lookup(GameData::global().await, source, &query).await
        },
    )
    .await
    .map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use revolt_database::BotInformation;
    use revolt_result::ErrorType;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fixed clock at a window boundary, so window tests never straddle one
    const NOW: u64 = 1_000 * WINDOW_SECS;

    fn human() -> User {
        User {
            id: "01HUMAN".to_string(),
            ..Default::default()
        }
    }

    fn bot() -> User {
        User {
            id: "01BOT".to_string(),
            bot: Some(BotInformation {
                owner: "01OWNER".to_string(),
            }),
            ..Default::default()
        }
    }

    fn hit(n: usize) -> SearchHit {
        SearchHit {
            title: format!("Game {n}"),
            subtitle: Some("Steam".to_string()),
            url: format!("https://store.steampowered.com/app/{n}/"),
        }
    }

    /// Run the route body with a search that counts its calls and returns
    /// `result`
    fn run_counting(
        user: &User,
        source: Option<&str>,
        q: Option<&str>,
        windows: &Mutex<LookupWindows>,
        result: revolt_gamedata::Result<Vec<SearchHit>>,
    ) -> (Result<Vec<GameLookupHit>>, usize) {
        let calls = AtomicUsize::new(0);
        let out = futures::executor::block_on(run(user, source, q, windows, NOW, |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { result }
        }));
        (out, calls.load(Ordering::SeqCst))
    }

    #[test]
    fn lookup_parses_each_source() {
        assert_eq!(parse_source("steam").unwrap(), LookupSource::Steam);
        assert_eq!(parse_source("wow").unwrap(), LookupSource::Wow);
        assert_eq!(parse_source("lol").unwrap(), LookupSource::Lol);
        for bad in ["", "STEAM", " steam", "poe", "steam ", "riot"] {
            let error = parse_source(bad).expect_err(bad);
            assert!(
                matches!(error.error_type, ErrorType::InvalidOperation),
                "{:?}: {:?}",
                bad,
                error
            );
        }
    }

    #[test]
    fn lookup_empty_query_answers_empty_without_upstream() {
        let windows = Mutex::new(LookupWindows::default());
        for q in [None, Some(""), Some("   "), Some("\t\n ")] {
            let (out, calls) = run_counting(&human(), Some("steam"), q, &windows, Ok(vec![hit(1)]));
            assert_eq!(out.unwrap(), Vec::new(), "{q:?}");
            assert_eq!(calls, 0, "{q:?} must not reach the upstream");
        }
        // Empty queries spend no slot of the per-user window
        assert!(windows.lock().unwrap().counters.is_empty());

        // The counter is live: a real query calls the search exactly once
        let (out, calls) = run_counting(
            &human(),
            Some("steam"),
            Some(" portal "),
            &windows,
            Ok(vec![hit(1)]),
        );
        assert_eq!(out.unwrap().len(), 1);
        assert_eq!(calls, 1);
    }

    #[test]
    fn lookup_passes_the_trimmed_query_and_source() {
        let windows = Mutex::new(LookupWindows::default());
        let seen = std::cell::RefCell::new(None);
        let out = futures::executor::block_on(run(
            &human(),
            Some("lol"),
            Some("  ahri  "),
            &windows,
            NOW,
            |source, query| {
                *seen.borrow_mut() = Some((source, query));
                async { Ok(vec![]) }
            },
        ));
        assert_eq!(out.unwrap(), Vec::new());
        assert_eq!(
            seen.into_inner(),
            Some((LookupSource::Lol, "ahri".to_string()))
        );
    }

    #[test]
    fn lookup_refuses_bots() {
        let windows = Mutex::new(LookupWindows::default());
        for q in [Some("portal"), Some(""), None] {
            let (out, calls) = run_counting(&bot(), Some("steam"), q, &windows, Ok(vec![hit(1)]));
            let error = out.expect_err("a bot must be refused");
            assert!(matches!(error.error_type, ErrorType::IsBot), "{:?}", error);
            assert_eq!(calls, 0);
        }
    }

    #[test]
    fn lookup_refuses_bad_source_and_long_query() {
        let windows = Mutex::new(LookupWindows::default());

        for source in [None, Some(""), Some("poe")] {
            let (out, calls) = run_counting(&human(), source, Some("x"), &windows, Ok(vec![]));
            let error = out.expect_err("bad source");
            assert!(
                matches!(error.error_type, ErrorType::InvalidOperation),
                "{:?}: {:?}",
                source,
                error
            );
            assert_eq!(calls, 0);
        }

        // 200 characters are accepted, 201 are not (characters, not bytes)
        let ok = "é".repeat(MAX_RAW_QUERY_CHARS);
        let (out, _) = run_counting(&human(), Some("steam"), Some(&ok), &windows, Ok(vec![]));
        assert!(out.is_ok());
        let long = "é".repeat(MAX_RAW_QUERY_CHARS + 1);
        let (out, calls) = run_counting(&human(), Some("steam"), Some(&long), &windows, Ok(vec![]));
        let error = out.expect_err("too long");
        assert!(
            matches!(error.error_type, ErrorType::FailedValidation { .. }),
            "{:?}",
            error
        );
        assert_eq!(calls, 0);
        // Whitespace counts toward the raw cap: it is checked before trimming
        let padded = format!("{}x", " ".repeat(MAX_RAW_QUERY_CHARS));
        let (out, _) = run_counting(&human(), Some("steam"), Some(&padded), &windows, Ok(vec![]));
        assert!(out.is_err());
    }

    #[test]
    fn lookup_returns_at_most_five_hits() {
        let windows = Mutex::new(LookupWindows::default());
        let many = (0..8).map(hit).collect();
        let (out, _) = run_counting(&human(), Some("steam"), Some("game"), &windows, Ok(many));
        let out = out.unwrap();
        assert_eq!(out.len(), MAX_HITS);
        assert_eq!(out[0], GameLookupHit::from(hit(0)));
    }

    #[test]
    fn lookup_response_has_title_subtitle_url() {
        let body = serde_json::to_value(vec![GameLookupHit::from(hit(7))]).unwrap();
        assert_eq!(
            body,
            serde_json::json!([{
                "title": "Game 7",
                "subtitle": "Steam",
                "url": "https://store.steampowered.com/app/7/"
            }])
        );
    }

    #[test]
    fn lookup_maps_every_gamedata_error() {
        for source in [LookupSource::Steam, LookupSource::Wow, LookupSource::Lol] {
            assert_eq!(
                map_lookup_error(source, GameDataError::NotFound).unwrap(),
                Vec::new()
            );
            assert_eq!(
                map_lookup_error(source, GameDataError::Upstream("502".into())).unwrap(),
                Vec::new()
            );
            assert_eq!(
                map_lookup_error(source, GameDataError::HostNotAllowed).unwrap(),
                Vec::new()
            );

            let budget = map_lookup_error(source, GameDataError::Budget).unwrap_err();
            assert!(
                matches!(
                    budget.error_type,
                    ErrorType::InSlowmode {
                        retry_after: BUDGET_RETRY_AFTER_SECS
                    }
                ),
                "{:?}",
                budget
            );

            let disabled = map_lookup_error(source, GameDataError::Disabled).unwrap_err();
            match disabled.error_type {
                ErrorType::FeatureDisabled { feature } => {
                    assert_eq!(feature, format!("game_lookup_{}", source_name(source)))
                }
                other => panic!("{:?}", other),
            }
        }
    }

    #[test]
    fn lookup_upstream_errors_flow_through_the_mapping() {
        let windows = Mutex::new(LookupWindows::default());
        let (out, calls) = run_counting(
            &human(),
            Some("steam"),
            Some("portal"),
            &windows,
            Err(GameDataError::Upstream("timeout".into())),
        );
        assert_eq!(out.unwrap(), Vec::new());
        assert_eq!(calls, 1);

        let (out, _) = run_counting(
            &human(),
            Some("wow"),
            Some("thunderfury"),
            &windows,
            Err(GameDataError::Disabled),
        );
        assert!(matches!(
            out.unwrap_err().error_type,
            ErrorType::FeatureDisabled { .. }
        ));
    }

    #[test]
    fn lookup_window_allows_five_per_thirty_seconds_per_user() {
        let mut windows = LookupWindows::default();
        let start = 1_000 * WINDOW_SECS; // window boundary
        for n in 0..WINDOW_LIMIT {
            assert_eq!(windows.take("a", start + n as u64), Ok(()));
        }
        assert_eq!(windows.take("a", start + 10), Err(WINDOW_SECS - 10));
        // Another user is counted separately
        assert_eq!(windows.take("b", start + 10), Ok(()));
        // The next window starts fresh
        assert_eq!(windows.take("a", start + WINDOW_SECS), Ok(()));
    }

    #[test]
    fn lookup_window_refusal_is_in_slowmode_and_skips_upstream() {
        let windows = Mutex::new(LookupWindows::default());
        let mut total = 0;
        for _ in 0..WINDOW_LIMIT {
            let (out, calls) =
                run_counting(&human(), Some("lol"), Some("ahri"), &windows, Ok(vec![]));
            assert!(out.is_ok());
            total += calls;
        }
        assert_eq!(total, WINDOW_LIMIT as usize);

        let (out, calls) = run_counting(&human(), Some("lol"), Some("ahri"), &windows, Ok(vec![]));
        let error = out.expect_err("the sixth lookup in the window is refused");
        assert!(
            matches!(
                error.error_type,
                ErrorType::InSlowmode {
                    retry_after: WINDOW_SECS
                }
            ),
            "{:?}",
            error
        );
        assert_eq!(calls, 0, "a refused lookup must not reach the upstream");

        // Empty queries are still answered: they never spend a slot
        let (out, calls) = run_counting(&human(), Some("lol"), Some(" "), &windows, Ok(vec![]));
        assert_eq!(out.unwrap(), Vec::new());
        assert_eq!(calls, 0);
    }

    #[test]
    fn lookup_window_map_stays_bounded() {
        let mut windows = LookupWindows::default();
        let old = 10 * WINDOW_SECS;
        for n in 0..WINDOW_PRUNE_AT {
            windows.take(&format!("u{n}"), old).unwrap();
        }
        assert_eq!(windows.counters.len(), WINDOW_PRUNE_AT);
        // A new user in a later window drops every stale entry
        windows.take("fresh", old + WINDOW_SECS).unwrap();
        assert_eq!(windows.counters.len(), 1);
    }

    /// Route tests: real Rocket, real database (`TEST_DB`), no upstream.
    /// Every request here is answered before `GameData` is touched.
    mod route {
        use crate::util::test::TestHarness;
        use revolt_database::Bot;
        use rocket::http::{Header, Status};

        #[test]
        fn lookup_route_empty_query_is_ok_and_empty() {
            crate::util::test::rt().block_on(empty_query_case())
        }

        async fn empty_query_case() {
            let harness = TestHarness::new().await;
            let (_, session, _) = harness.new_user().await;

            for path in [
                "/lookup/games?source=steam&q=",
                "/lookup/games?source=wow&q=%20%20%20",
                "/lookup/games?source=lol",
            ] {
                let response = harness
                    .client
                    .get(path)
                    .header(Header::new("x-session-token", session.token.to_string()))
                    .dispatch()
                    .await;
                assert_eq!(response.status(), Status::Ok, "{path}");
                let body: serde_json::Value = response.into_json().await.expect("json");
                assert_eq!(body, serde_json::json!([]), "{path}");
            }
        }

        #[test]
        fn lookup_route_refuses_bots() {
            crate::util::test::rt().block_on(bot_case())
        }

        async fn bot_case() {
            let harness = TestHarness::new().await;
            let (_, _, owner) = harness.new_user().await;
            let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
                .await
                .expect("`Bot`");

            let response = harness
                .client
                .get("/lookup/games?source=steam&q=")
                .header(Header::new("x-bot-token", bot.token.to_string()))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::BadRequest);
            let body = response.into_string().await.unwrap_or_default();
            assert!(body.contains("IsBot"), "{}", body);
        }

        #[test]
        fn lookup_route_refuses_bad_input_and_anonymous_callers() {
            crate::util::test::rt().block_on(bad_input_case())
        }

        async fn bad_input_case() {
            let harness = TestHarness::new().await;
            let (_, session, _) = harness.new_user().await;

            let response = harness
                .client
                .get("/lookup/games?source=poe&q=")
                .header(Header::new("x-session-token", session.token.to_string()))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::BadRequest);
            let body = response.into_string().await.unwrap_or_default();
            assert!(body.contains("InvalidOperation"), "{}", body);

            let long = format!("/lookup/games?source=steam&q={}", "x".repeat(201));
            let response = harness
                .client
                .get(long.as_str())
                .header(Header::new("x-session-token", session.token.to_string()))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::BadRequest);
            let body = response.into_string().await.unwrap_or_default();
            assert!(body.contains("FailedValidation"), "{}", body);

            let response = harness
                .client
                .get("/lookup/games?source=steam&q=")
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Unauthorized);
        }
    }
}
