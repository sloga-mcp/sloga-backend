//! GIF picker proxy.
//!
//! The client's GIF picker historically talked to GIFBox (a community proxy
//! over the Tenor API). Tenor's public API was discontinued on 2026-06-30 and
//! GIFBox only accepts Revolt sessions, so the picker is served from our own
//! API instead: these routes proxy GIPHY with a server-side key and translate
//! responses into the GIFBox/Tenor shape the client already understands
//! (`results[].media_formats.{webm,tinywebm}.url` + `url`).
//!
//! Requests require a valid session, and only ever carry the search string to
//! the provider — user tokens and client IPs stay on our side. Responses are
//! cached in-memory to stay well inside provider quotas.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use revolt_config::config;
use revolt_database::User;
use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::serde::json::Json;
use rocket::Route;
use serde_json::{json, Value};

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![categories, trending, search]
}

/// Cached provider responses, keyed by full request URL
static CACHE: OnceLock<Mutex<HashMap<String, (Instant, Value)>>> = OnceLock::new();

const TTL_BROWSE: Duration = Duration::from_secs(30 * 60);
const TTL_SEARCH: Duration = Duration::from_secs(10 * 60);

/// Fetch a provider URL with an in-memory TTL cache. Provider failures
/// resolve to `None` so the picker degrades to an empty pane instead of an
/// error toast (the beta GIPHY tier is tightly rate limited).
async fn cached_fetch(url: String, ttl: Duration) -> Option<Value> {
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    if let Some((at, value)) = cache
        .lock()
        .expect("gif cache poisoned")
        .get(&url)
        .cloned()
    {
        if at.elapsed() < ttl {
            return Some(value);
        }
    }

    let value: Value = reqwest::get(&url).await.ok()?.json().await.ok()?;
    cache
        .lock()
        .expect("gif cache poisoned")
        .insert(url, (Instant::now(), value.clone()));
    Some(value)
}

fn provider_url(endpoint: &str, params: &[(&str, &str)]) -> Option<String> {
    reqwest::Url::parse_with_params(
        &format!("https://api.giphy.com/v1/gifs/{endpoint}"),
        params,
    )
    .ok()
    .map(|u| u.to_string())
}

/// Translate one GIPHY gif object into the shape the client expects. The
/// `media_formats` URLs feed the picker's preview `<video>` elements (mp4
/// plays fine there); `url` is what gets sent to chat when clicked (direct
/// .gif so it embeds as an animated image).
fn map_gif(gif: &Value) -> Option<Value> {
    let images = gif.get("images")?;
    let original = images.get("original")?;
    let gif_url = original.get("url")?.as_str()?;
    let full_mp4 = original
        .get("mp4")
        .and_then(Value::as_str)
        .or_else(|| {
            images
                .get("original_mp4")
                .and_then(|o| o.get("mp4"))
                .and_then(Value::as_str)
        })?;
    let tiny_mp4 = images
        .get("fixed_width")
        .and_then(|o| o.get("mp4"))
        .and_then(Value::as_str)
        .unwrap_or(full_mp4);

    Some(json!({
        "url": gif_url,
        "media_formats": {
            "webm": { "url": full_mp4 },
            "tinywebm": { "url": tiny_mp4 }
        }
    }))
}

fn map_results(response: Option<Value>) -> Value {
    let results: Vec<Value> = response
        .as_ref()
        .and_then(|r| r.get("data"))
        .and_then(Value::as_array)
        .map(|gifs| gifs.iter().filter_map(map_gif).collect())
        .unwrap_or_default();

    json!({ "results": results })
}

/// # GIF Categories
///
/// Browsable category tiles for the GIF picker.
#[openapi(tag = "GIFs")]
#[get("/categories?<locale>")]
pub async fn categories(_user: User, locale: Option<String>) -> Json<Value> {
    let _ = locale;
    let key = &config().await.api.gifs.giphy_key;
    if key.is_empty() {
        return Json(json!([]));
    }

    let response = match provider_url("categories", &[("api_key", key)]) {
        Some(url) => cached_fetch(url, TTL_BROWSE).await,
        None => None,
    };

    let categories: Vec<Value> = response
        .as_ref()
        .and_then(|r| r.get("data"))
        .and_then(Value::as_array)
        .map(|cats| {
            cats.iter()
                .filter_map(|cat| {
                    let title = cat.get("name")?.as_str()?;
                    let image = cat
                        .get("gif")?
                        .get("images")?
                        .get("fixed_width")?
                        .get("url")?
                        .as_str()?;
                    Some(json!({ "title": title, "image": image }))
                })
                .collect()
        })
        .unwrap_or_default();

    Json(json!(categories))
}

/// # Trending GIFs
///
/// Currently-trending GIFs.
#[openapi(tag = "GIFs")]
#[get("/trending?<locale>&<limit>")]
pub async fn trending(_user: User, locale: Option<String>, limit: Option<u32>) -> Json<Value> {
    let _ = locale;
    let key = &config().await.api.gifs.giphy_key;
    if key.is_empty() {
        return Json(json!({ "results": [] }));
    }

    let limit = limit.unwrap_or(30).min(50).to_string();
    let response = match provider_url(
        "trending",
        &[("api_key", key), ("limit", &limit), ("rating", "pg-13")],
    ) {
        Some(url) => cached_fetch(url, TTL_BROWSE).await,
        None => None,
    };

    Json(map_results(response))
}

/// # Search GIFs
///
/// Search for GIFs by query.
#[openapi(tag = "GIFs")]
#[get("/search?<locale>&<query>")]
pub async fn search(_user: User, locale: Option<String>, query: String) -> Json<Value> {
    let _ = locale;
    let key = &config().await.api.gifs.giphy_key;
    if key.is_empty() || query.trim().is_empty() {
        return Json(json!({ "results": [] }));
    }

    let response = match provider_url(
        "search",
        &[
            ("api_key", key),
            ("q", query.trim()),
            ("limit", "30"),
            ("rating", "pg-13"),
        ],
    ) {
        Some(url) => cached_fetch(url, TTL_SEARCH).await,
        None => None,
    };

    Json(map_results(response))
}
