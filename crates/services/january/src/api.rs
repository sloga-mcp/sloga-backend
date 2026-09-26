use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::Query,
    http::HeaderMap,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use reqwest::header;
use revolt_models::v0::Embed;
use revolt_result::{create_error, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore};
use utoipa::ToSchema;

use crate::requests::Request;

pub static CACHE_CONTROL: &str = "public, max-age=600, immutable";

/// Concurrent `/audio` relay limit, sized from `january.max_audio_streams`
/// on first use.
static AUDIO_STREAMS: OnceCell<Arc<Semaphore>> = OnceCell::const_new();

pub async fn router() -> Router {
    Router::new()
        .route("/", get(root))
        .route("/proxy", get(proxy))
        .route("/embed", get(embed))
        .route("/audio", get(audio))
}

/// Successful root response
#[derive(Serialize, Debug, ToSchema)]
pub struct RootResponse {
    january: &'static str,
    version: &'static str,
}

/// Capture crate version from Cargo
static CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Root response from service
#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = 200, description = "Echo response", body = RootResponse)
    )
)]
async fn root() -> Json<RootResponse> {
    Json(RootResponse {
        january: "Hello, I am a media proxy server!",
        version: CRATE_VERSION,
    })
}

#[derive(Deserialize)]
pub struct UrlQuery {
    url: String,
}

/// Proxy a given URL and load media
#[utoipa::path(
    get,
    path = "/proxy",
    responses(
        (status = 200, description = "Requested media file", body = Vec<u8>)
    ),
    params(
        ("url" = String, Query, description = "URL to fetch")
    ),
)]
async fn proxy(Query(UrlQuery { url }): Query<UrlQuery>) -> Result<impl IntoResponse> {
    Request::proxy_file(&url).await.map(|(content_type, data)| {
        (
            [
                (header::CONTENT_TYPE, content_type),
                (header::CONTENT_DISPOSITION, "inline".to_owned()),
                (header::CACHE_CONTROL, CACHE_CONTROL.to_owned()),
            ],
            data,
        )
    })
}

/// Generate embed for a given URL
#[utoipa::path(
    get,
    path = "/embed",
    responses(
        (status = 200, description = "Generated embed information", body = Embed)
    ),
    params(
        ("url" = String, Query, description = "URL to fetch")
    ),
    security(
        ("api_key" = [])
    )
)]
async fn embed(
    Query(UrlQuery { url }): Query<UrlQuery>,
    // TypedHeader(Authorization(_bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse> {
    match Request::generate_embed(url).await {
        Ok(Embed::None) => Err(create_error!(NoEmbedData)),
        result => result,
    }
    .map(Json)
}

/// Stream an audio file for an audio link embed
///
/// Returns 404 when `january.audio_embeds` is off and 503 when
/// `january.max_audio_streams` relays are already running. Otherwise opens
/// the upstream via `Request::open_audio_stream` (forwarding only the
/// client's `Range`) and relays upstream 200/206 with the canonical
/// `Content-Type`, `nosniff`, `Content-Security-Policy: sandbox`, inline
/// disposition and the upstream `Content-Length`/`Content-Range`/
/// `Accept-Ranges`; the body goes through [`relay`]. Never logs the URL,
/// query, `Range` or upstream response.
#[utoipa::path(
    get,
    path = "/audio",
    params(
        ("url" = String, Query, description = "URL to fetch")
    ),
    responses(
        (status = 200, description = "Audio stream"),
        (status = 206, description = "Partial audio stream")
    )
)]
pub async fn audio(
    Query(UrlQuery { url }): Query<UrlQuery>,
    headers: HeaderMap,
) -> axum::response::Response {
    let _ = (url, headers, &AUDIO_STREAMS);
    todo!("wave 3")
}

/// Relay an upstream body to the client
///
/// Owns `permit` for the stream's lifetime (released when the stream is
/// dropped, including on client disconnect), yields upstream chunks as-is,
/// errors and ends once more than `cap` bytes would have been relayed, and
/// ends at `deadline`.
pub fn relay<S>(
    upstream: S,
    cap: u64,
    permit: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
) -> impl futures::Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send + 'static
where
    S: futures::Stream<Item = reqwest::Result<Bytes>> + Send + Unpin + 'static,
{
    // Stub: the closure moves every argument in (so the permit is owned by
    // the returned stream, as the contract requires) and its explicit return
    // type pins the Item type; it only panics if polled.
    futures::stream::poll_fn(
        move |_cx| -> std::task::Poll<Option<std::result::Result<Bytes, std::io::Error>>> {
            let _ = (&upstream, cap, &permit, deadline);
            todo!("wave 3")
        },
    )
}
