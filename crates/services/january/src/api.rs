use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    extract::{rejection::QueryRejection, Query},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use futures::{future::Either, Stream, StreamExt};
use reqwest::header;
use revolt_models::v0::Embed;
use revolt_result::{create_error, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{mpsc, OnceCell, OwnedSemaphorePermit, Semaphore},
    time::{timeout_at, Instant},
};
use utoipa::ToSchema;

use crate::requests::Request;

pub static CACHE_CONTROL: &str = "public, max-age=600, immutable";

/// `/audio` responses are not `immutable`: a later range or re-fetch may see
/// a changed upstream file
static AUDIO_CACHE_CONTROL: &str = "public, max-age=600";

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
/// client's `Range`, re-serialized) and relays upstream 200/206 with the
/// canonical `Content-Type`, `nosniff`, `Content-Security-Policy: sandbox`,
/// inline disposition and the upstream `Content-Length`/`Content-Range`/
/// `Accept-Ranges`; the body goes through [`relay`]. An upstream 416 is
/// passed on with an empty body. Everything else is a 502 before any body
/// byte is sent. Never logs the URL, query, `Range` or upstream response.
#[utoipa::path(
    get,
    path = "/audio",
    params(
        ("url" = String, Query, description = "URL to fetch")
    ),
    responses(
        (status = 200, description = "Audio stream"),
        (status = 206, description = "Partial audio stream"),
        (status = 400, description = "Missing or malformed url"),
        (status = 404, description = "Audio embeds are disabled"),
        (status = 416, description = "Requested range not satisfiable upstream"),
        (status = 502, description = "Upstream unreachable, not an allowed audio file, or too large"),
        (status = 503, description = "Too many concurrent audio streams")
    )
)]
pub async fn audio(
    query: std::result::Result<Query<UrlQuery>, QueryRejection>,
    headers: HeaderMap,
) -> axum::response::Response {
    let config = revolt_config::config().await.january;
    let url = match audio_url(config.audio_embeds, query) {
        Ok(url) => url,
        Err(status) => return status.into_response(),
    };

    let max_streams = config.max_audio_streams.min(Semaphore::MAX_PERMITS);
    let streams = AUDIO_STREAMS
        .get_or_init(|| async move { Arc::new(Semaphore::new(max_streams)) })
        .await
        .clone();
    let Ok(permit) = streams.try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };

    // The wall-clock limit starts now, so opening and sniffing the upstream
    // count against it too and a stalling upstream can't hold the permit
    // past it
    let deadline = deadline_after(config.max_audio_stream_secs);
    let max_bytes = config.max_audio_bytes as u64;

    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(crate::audio::parse_range)
        .and_then(|(start, end)| range_header(start, end));

    let Ok(Ok(request)) = timeout_at(deadline, Request::open_audio_stream(&url, range)).await
    else {
        return StatusCode::BAD_GATEWAY.into_response();
    };

    let (response, mime) = request.into_parts();
    let status = response.status();

    let (content_type, sniff) = match classify(status, &mime, response.headers(), max_bytes) {
        Upstream::NotSatisfiable => return not_satisfiable(response.headers()),
        Upstream::Reject => return StatusCode::BAD_GATEWAY.into_response(),
        Upstream::Relay {
            content_type,
            sniff,
        } => (content_type, sniff),
    };

    let response_headers = relay_headers(content_type, response.headers());
    let upstream = Box::pin(response.bytes_stream());

    let Some(body) = peek_magic(upstream, content_type, sniff, deadline).await else {
        return StatusCode::BAD_GATEWAY.into_response();
    };

    let mut response =
        axum::response::Response::new(Body::from_stream(relay(body, max_bytes, permit, deadline)));
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    response
}

/// The URL `/audio` should fetch, or the empty-bodied status to answer with
///
/// The query is taken as a `Result` so the flag is checked first: with audio
/// embeds off the route is a 404 whatever the query, and only with them on
/// does a missing or malformed `url` become a 400. The rejection itself is
/// dropped unrendered, so nothing about the query is logged or echoed.
fn audio_url(
    enabled: bool,
    query: std::result::Result<Query<UrlQuery>, QueryRejection>,
) -> std::result::Result<String, StatusCode> {
    if !enabled {
        return Err(StatusCode::NOT_FOUND);
    }
    match query {
        Ok(Query(UrlQuery { url })) => Ok(url),
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

/// What `/audio` does with an opened upstream, decided from its status,
/// Content-Type and headers alone (before any body byte is read)
#[derive(Debug, PartialEq, Eq)]
enum Upstream {
    /// 416: pass on `Content-Range` with an empty body
    NotSatisfiable,
    /// 200/206: relay as `content_type`; `sniff` when the body may start at
    /// byte 0 and so must carry the format's magic
    Relay {
        content_type: &'static str,
        sniff: bool,
    },
    /// Anything else: 502
    Reject,
}

fn classify(
    status: StatusCode,
    mime: &mime::Mime,
    headers: &HeaderMap,
    max_bytes: u64,
) -> Upstream {
    match status {
        StatusCode::RANGE_NOT_SATISFIABLE => return Upstream::NotSatisfiable,
        StatusCode::OK | StatusCode::PARTIAL_CONTENT => {}
        _ => return Upstream::Reject,
    }

    if mime
        .essence_str()
        .eq_ignore_ascii_case("multipart/byteranges")
    {
        return Upstream::Reject;
    }

    let Some(content_type) = crate::audio::canonical_type(mime) else {
        return Upstream::Reject;
    };

    if crate::audio::total_size(status, headers).is_some_and(|size| size > max_bytes) {
        return Upstream::Reject;
    }

    // A 206 whose start can't be read is sniffed too (fail closed)
    let sniff =
        status == StatusCode::OK || content_range_start(headers).is_none_or(|start| start == 0);

    Upstream::Relay {
        content_type,
        sniff,
    }
}

/// An upstream with the chunks [`peek_magic`] pulled put back in front
type Peeked<S> =
    futures::stream::Chain<futures::stream::Iter<std::vec::IntoIter<reqwest::Result<Bytes>>>, S>;

/// Check the format magic of a body that starts at byte 0 and hand the
/// upstream back with every chunk read for it re-prepended
///
/// Pulls chunks until `SNIFF_MIN_BYTES` are buffered or the upstream ends.
/// `None` (a 502) when the magic doesn't match `content_type`, the upstream
/// fails, or `deadline` passes while peeking. A body shorter than
/// `SNIFF_MIN_BYTES` is let through and relies on the forced headers. A body
/// that doesn't start at byte 0 is not read at all.
async fn peek_magic<S>(
    mut upstream: S,
    content_type: &str,
    starts_at_zero: bool,
    deadline: Instant,
) -> Option<Peeked<S>>
where
    S: Stream<Item = reqwest::Result<Bytes>> + Unpin,
{
    let mut head: Vec<Bytes> = Vec::new();
    if starts_at_zero {
        let peek = async {
            let mut buffered = 0;
            while buffered < crate::audio::SNIFF_MIN_BYTES {
                match upstream.next().await {
                    Some(Ok(chunk)) => {
                        buffered += chunk.len();
                        head.push(chunk);
                    }
                    Some(Err(_)) => return false,
                    None => break,
                }
            }

            // Fewer bytes than the magic needs: rely on the forced headers
            buffered < crate::audio::SNIFF_MIN_BYTES
                || crate::audio::sniff_ok(content_type, &head.concat())
        };

        if !matches!(timeout_at(deadline, peek).await, Ok(true)) {
            return None;
        }
    }

    let head: Vec<reqwest::Result<Bytes>> = head.into_iter().map(Ok).collect();
    Some(futures::stream::iter(head).chain(upstream))
}

/// First byte position of `Content-Range: bytes a-b/total`
fn content_range_start(headers: &HeaderMap) -> Option<u64> {
    let value = headers.get(header::CONTENT_RANGE)?.to_str().ok()?;
    let (start, _) = value.trim().strip_prefix("bytes")?.split_once('-')?;
    start.trim().parse().ok()
}

/// Re-serialized single `Range` to forward upstream
fn range_header(start: u64, end: Option<u64>) -> Option<HeaderValue> {
    let value = match end {
        Some(end) => format!("bytes={start}-{end}"),
        None => format!("bytes={start}-"),
    };
    HeaderValue::try_from(value).ok()
}

fn deadline_after(secs: u64) -> Instant {
    let now = Instant::now();
    // Saturate instead of panicking on an absurd config value
    now.checked_add(Duration::from_secs(secs))
        .unwrap_or_else(|| now + Duration::from_secs(u32::MAX as u64))
}

/// Headers every `/audio` response carries; `Content-Type` only when a
/// canonical type is known
fn forced_headers(content_type: Option<&'static str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(content_type) = content_type {
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(AUDIO_CACHE_CONTROL),
    );
    headers
}

/// Headers for a relayed 200/206: the forced set plus the upstream
/// `Content-Length`, `Content-Range` and `Accept-Ranges` when present
fn relay_headers(content_type: &'static str, upstream: &HeaderMap) -> HeaderMap {
    let mut headers = forced_headers(Some(content_type));
    for name in [
        header::CONTENT_LENGTH,
        header::CONTENT_RANGE,
        header::ACCEPT_RANGES,
    ] {
        if let Some(value) = upstream.get(&name) {
            headers.insert(name, value.clone());
        }
    }
    headers
}

/// 416 with the upstream `Content-Range` and an empty body
fn not_satisfiable(upstream: &HeaderMap) -> axum::response::Response {
    let mut headers = forced_headers(None);
    if let Some(value) = upstream.get(header::CONTENT_RANGE) {
        headers.insert(header::CONTENT_RANGE, value.clone());
    }
    (StatusCode::RANGE_NOT_SATISFIABLE, headers).into_response()
}

/// Upstream chunks the relay may read ahead of a slow client
const RELAY_BUFFER: usize = 4;

/// Longest a relay waits on a single upstream read or client send before
/// giving up its stream slot. A client that pauses playback longer than this
/// re-requests with a `Range` when it resumes.
const STALL: Duration = Duration::from_secs(30);

type Item = std::result::Result<Bytes, io::Error>;

/// Relay an upstream body to the client
///
/// A spawned task owns the upstream and `permit` and reads ahead into a
/// channel of [`RELAY_BUFFER`] chunks, so the relay ends at `deadline` even
/// when the client stops reading and the returned stream is never polled
/// again. The task yields upstream chunks as-is, errors and ends once more
/// than `cap` bytes would have been relayed, errors and ends at `deadline`
/// or once the upstream or the client makes no progress for [`STALL`], and
/// exits as soon as the returned stream is dropped (client disconnect).
/// The permit and the upstream are released when the task exits. A relay
/// that stops for any reason other than the upstream's clean end always
/// ends with an error, so a truncated body never looks complete.
pub fn relay<S>(
    upstream: S,
    cap: u64,
    permit: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
) -> impl futures::Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send + 'static
where
    S: futures::Stream<Item = reqwest::Result<Bytes>> + Send + Unpin + 'static,
{
    relay_with_stall(upstream, cap, permit, deadline, STALL)
}

/// [`relay`] with the stall bound as a parameter
fn relay_with_stall<S>(
    upstream: S,
    cap: u64,
    permit: OwnedSemaphorePermit,
    deadline: Instant,
    stall: Duration,
) -> impl Stream<Item = Item> + Send + 'static
where
    S: Stream<Item = reqwest::Result<Bytes>> + Send + Unpin + 'static,
{
    let (tx, rx) = mpsc::channel(RELAY_BUFFER);
    let finished = Arc::new(AtomicBool::new(false));
    let limits = Limits { deadline, stall };
    tokio::spawn(pump(upstream, cap, permit, limits, tx, finished.clone()));

    let receiver = Receiver {
        rx,
        finished,
        ended: false,
    };
    // Fused: an ended relay keeps returning `None` instead of panicking
    futures::stream::unfold(receiver, |mut receiver| async move {
        if receiver.ended {
            return None;
        }

        match receiver.rx.recv().await {
            Some(Ok(chunk)) => Some((Ok(chunk), receiver)),
            Some(Err(error)) => {
                receiver.ended = true;
                Some((Err(error), receiver))
            }
            // The pump is gone: a clean end only if it said so, otherwise its
            // own error couldn't be delivered (or it panicked)
            None if receiver.finished.load(Ordering::Acquire) => None,
            None => {
                receiver.ended = true;
                Some((Err(io::Error::other("stream ended early")), receiver))
            }
        }
    })
    .fuse()
}

/// Client side of a [`relay`]
struct Receiver {
    rx: mpsc::Receiver<Item>,
    /// Set by the pump only when the upstream ended cleanly
    finished: Arc<AtomicBool>,
    /// An error was yielded; nothing may follow it
    ended: bool,
}

/// How [`forward`] stopped
enum End {
    /// The upstream ended cleanly
    Finished,
    /// The receiver was dropped
    ClientGone,
    TimedOut,
    /// A single wait on the upstream or the client outlasted the stall bound
    Stalled,
    Failed(io::Error),
}

fn time_limit_reached() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "stream time limit reached")
}

fn stalled() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "stream stalled")
}

/// Time bounds of a relay
#[derive(Clone, Copy)]
struct Limits {
    /// Wall-clock end of the whole relay
    deadline: Instant,
    /// Longest any single wait may take
    stall: Duration,
}

impl Limits {
    /// Run `future` until the deadline or, sooner, until the stall bound
    /// runs out
    async fn wait<F: std::future::Future>(self, future: F) -> std::result::Result<F::Output, End> {
        let bound = Instant::now()
            .checked_add(self.stall)
            .map_or(self.deadline, |stall_at| stall_at.min(self.deadline));
        timeout_at(bound, future).await.map_err(|_| {
            if bound < self.deadline {
                End::Stalled
            } else {
                End::TimedOut
            }
        })
    }
}

async fn pump<S>(
    mut upstream: S,
    cap: u64,
    permit: OwnedSemaphorePermit,
    limits: Limits,
    tx: mpsc::Sender<Item>,
    finished: Arc<AtomicBool>,
) where
    S: Stream<Item = reqwest::Result<Bytes>> + Unpin,
{
    let end = forward(&mut upstream, cap, limits, &tx).await;

    // Free the stream slot and the upstream connection before telling the
    // client how the relay ended
    drop(permit);
    drop(upstream);

    match end {
        End::Finished => finished.store(true, Ordering::Release),
        End::ClientGone => {}
        // Best effort: a full channel means the client isn't reading, and the
        // receiver reports the early end itself once the buffer is drained
        End::TimedOut => {
            let _ = tx.try_send(Err(time_limit_reached()));
        }
        End::Stalled => {
            let _ = tx.try_send(Err(stalled()));
        }
        End::Failed(error) => {
            let _ = limits.wait(tx.send(Err(error))).await;
        }
    }
}

/// Move upstream chunks into `tx` until the upstream ends or fails, `cap`
/// would be exceeded, the deadline passes, a single wait outlasts the stall
/// bound, or the receiver is dropped. Every wait is bounded by `limits`.
async fn forward<S>(upstream: &mut S, cap: u64, limits: Limits, tx: &mpsc::Sender<Item>) -> End
where
    S: Stream<Item = reqwest::Result<Bytes>> + Unpin,
{
    let mut remaining = cap;
    loop {
        // `timeout_at` polls its future before its timer, so an always-ready
        // upstream would otherwise keep flowing past the deadline
        if Instant::now() >= limits.deadline {
            return End::TimedOut;
        }

        let next = {
            let closed = std::pin::pin!(tx.closed());
            match limits
                .wait(futures::future::select(upstream.next(), closed))
                .await
            {
                Err(end) => return end,
                Ok(Either::Right(_)) => return End::ClientGone,
                Ok(Either::Left((next, _))) => next,
            }
        };

        let chunk = match next {
            None => return End::Finished,
            // Never the reqwest error itself: its text can carry the URL
            Some(Err(_)) => return End::Failed(io::Error::other("upstream read failed")),
            Some(Ok(chunk)) => chunk,
        };

        let len = chunk.len() as u64;
        if len > remaining {
            return End::Failed(io::Error::other("stream size limit reached"));
        }
        remaining -= len;

        match limits.wait(tx.send(Ok(chunk))).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return End::ClientGone,
            Err(end) => return end,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Item = std::result::Result<Bytes, std::io::Error>;

    /// In-memory upstream: one chunk per entry, chunk `i` filled with byte `i`
    fn upstream(
        sizes: &[usize],
    ) -> futures::stream::Iter<std::vec::IntoIter<reqwest::Result<Bytes>>> {
        futures::stream::iter(
            sizes
                .iter()
                .enumerate()
                .map(|(i, &n)| Ok(Bytes::from(vec![i as u8; n])))
                .collect::<Vec<_>>(),
        )
    }

    fn expected(sizes: &[usize]) -> Vec<u8> {
        sizes
            .iter()
            .enumerate()
            .flat_map(|(i, &n)| std::iter::repeat_n(i as u8, n))
            .collect()
    }

    fn semaphore() -> (Arc<Semaphore>, OwnedSemaphorePermit) {
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = semaphore.clone().try_acquire_owned().unwrap();
        (semaphore, permit)
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    /// Split relayed items into the concatenated bytes before the first error
    /// and the number of items (bytes included) seen after it
    fn split(items: Vec<Item>) -> (Vec<u8>, Option<std::io::Error>, usize) {
        let mut bytes = Vec::new();
        let mut items = items.into_iter();
        for item in items.by_ref() {
            match item {
                Ok(chunk) => bytes.extend_from_slice(&chunk),
                Err(error) => return (bytes, Some(error), items.count()),
            }
        }
        (bytes, None, 0)
    }

    #[tokio::test]
    async fn relay_under_cap_yields_every_byte_and_releases_on_finish() {
        let sizes = [3, 5, 7];
        let (semaphore, permit) = semaphore();
        let mut stream = Box::pin(relay(upstream(&sizes), 100, permit, later()));

        let mut items = Vec::new();
        while let Some(item) = stream.next().await {
            items.push(item);
        }

        let (bytes, error, _) = split(items);
        assert!(error.is_none());
        assert_eq!(bytes, expected(&sizes));
        // Released once the upstream ends, before the stream itself is dropped
        assert_eq!(semaphore.available_permits(), 1);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn relay_exactly_at_cap_is_not_an_error() {
        let sizes = [4, 4];
        let (_semaphore, permit) = semaphore();
        let items: Vec<Item> = relay(upstream(&sizes), 8, permit, later()).collect().await;

        let (bytes, error, _) = split(items);
        assert!(error.is_none());
        assert_eq!(bytes, expected(&sizes));
    }

    #[tokio::test]
    async fn relay_over_cap_stops_at_cap_then_errors_then_ends() {
        let (semaphore, permit) = semaphore();
        let mut stream = Box::pin(relay(upstream(&[4, 4, 4, 4]), 10, permit, later()));

        let mut items = Vec::new();
        while let Some(item) = stream.next().await {
            items.push(item);
        }

        let (bytes, error, after) = split(items);
        assert!(bytes.len() as u64 <= 10);
        assert_eq!(bytes, expected(&[4, 4]));
        assert!(error.is_some());
        assert_eq!(after, 0, "nothing may follow the cap error");
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn relay_single_chunk_over_cap_yields_nothing() {
        let (_semaphore, permit) = semaphore();
        let items: Vec<Item> = relay(upstream(&[11]), 10, permit, later()).collect().await;

        let (bytes, error, after) = split(items);
        assert!(bytes.is_empty());
        assert!(error.is_some());
        assert_eq!(after, 0);
    }

    #[tokio::test]
    async fn relay_releases_permit_when_dropped_mid_stream() {
        let (semaphore, permit) = semaphore();
        // Stalls after one chunk with a far deadline: only the drop can end it
        let stalled = upstream(&[1]).chain(futures::stream::pending());
        let mut stream = Box::pin(relay(stalled, 100, permit, later()));

        assert!(matches!(stream.next().await, Some(Ok(_))));
        assert_eq!(semaphore.available_permits(), 0);

        drop(stream);
        assert!(
            released_within(&semaphore, Duration::from_secs(1)).await,
            "dropping the stream must end the relay"
        );
    }

    /// A real `reqwest::Error`, built without touching the network
    fn reqwest_error() -> reqwest::Error {
        reqwest::Client::new()
            .get("not a url")
            .build()
            .expect_err("an unparsable URL is a builder error")
    }

    #[tokio::test]
    async fn relay_upstream_error_is_generic_and_ends_the_stream() {
        let (semaphore, permit) = semaphore();
        let failing =
            futures::stream::iter(vec![Ok(Bytes::from_static(b"abc")), Err(reqwest_error())]);
        let items: Vec<Item> = relay(failing, 100, permit, later()).collect().await;

        let (bytes, error, after) = split(items);
        assert_eq!(bytes, b"abc");
        assert_eq!(
            error.map(|e| e.to_string()).as_deref(),
            Some("upstream read failed")
        );
        assert_eq!(after, 0);
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn relay_past_deadline_errors_without_yielding_upstream_bytes() {
        let (semaphore, permit) = semaphore();
        let items: Vec<Item> = relay(upstream(&[5, 5]), 100, permit, Instant::now())
            .collect()
            .await;

        let (bytes, error, after) = split(items);
        assert!(bytes.is_empty());
        assert_eq!(error.map(|e| e.kind()), Some(std::io::ErrorKind::TimedOut));
        assert_eq!(after, 0);
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn relay_deadline_fires_while_upstream_is_stalled() {
        let (semaphore, permit) = semaphore();
        let stalled = upstream(&[3]).chain(futures::stream::pending());
        let deadline = Instant::now() + Duration::from_millis(100);

        let items: Vec<Item> = tokio::time::timeout(
            Duration::from_secs(10),
            relay(stalled, 100, permit, deadline).collect(),
        )
        .await
        .expect("relay must end at its deadline");

        let (bytes, error, after) = split(items);
        assert_eq!(bytes, expected(&[3]));
        assert_eq!(error.map(|e| e.kind()), Some(std::io::ErrorKind::TimedOut));
        assert_eq!(after, 0);
        assert_eq!(semaphore.available_permits(), 1);
    }

    /// Wait (without touching any relay) until the permit is back, up to `limit`
    async fn released_within(semaphore: &Semaphore, limit: Duration) -> bool {
        let give_up = Instant::now() + limit;
        while semaphore.available_permits() == 0 {
            if Instant::now() >= give_up {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        true
    }

    #[tokio::test]
    async fn relay_releases_permit_at_deadline_when_the_consumer_stops_reading() {
        static CHUNK: [u8; 1024] = [7; 1024];
        let (semaphore, permit) = semaphore();
        // Plenty of data, always ready: only the deadline can end this relay
        let endless = futures::stream::repeat_with(|| Ok(Bytes::from_static(&CHUNK)));
        let deadline = Instant::now() + Duration::from_millis(100);
        let mut stream = Box::pin(relay(endless, u64::MAX, permit, deadline));

        assert!(matches!(stream.next().await, Some(Ok(_))));

        // The consumer never polls again (a client that stopped reading)
        assert!(
            released_within(&semaphore, Duration::from_secs(1)).await,
            "a stalled consumer must not hold the permit past the deadline"
        );

        // Reading again later: whatever was buffered, then an error, then the end
        let items: Vec<Item> = tokio::time::timeout(Duration::from_secs(10), stream.collect())
            .await
            .expect("relay must end after its deadline");
        let (_, error, after) = split(items);
        assert!(error.is_some());
        assert_eq!(after, 0);
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(600)
    }

    #[tokio::test]
    async fn relay_releases_permit_after_a_stall_when_the_consumer_stops_reading() {
        static CHUNK: [u8; 1024] = [7; 1024];
        let (semaphore, permit) = semaphore();
        // Plenty of data, always ready, deadline far away: only the stall
        // bound can end this relay while the consumer isn't reading
        let endless = futures::stream::repeat_with(|| Ok(Bytes::from_static(&CHUNK)));
        let stall = Duration::from_millis(100);
        let mut stream = Box::pin(relay_with_stall(endless, u64::MAX, permit, far(), stall));

        assert!(matches!(stream.next().await, Some(Ok(_))));

        // The consumer stays connected but never polls again
        assert!(
            released_within(&semaphore, Duration::from_secs(1)).await,
            "a consumer that stops reading must not hold the permit until the deadline"
        );

        // Reading again later: whatever was buffered, then an error, then the end
        let items: Vec<Item> = tokio::time::timeout(Duration::from_secs(10), stream.collect())
            .await
            .expect("relay must end after a stall");
        let (_, error, after) = split(items);
        assert!(error.is_some());
        assert_eq!(after, 0);
    }

    #[tokio::test]
    async fn relay_ends_after_a_stall_when_the_upstream_stops_sending() {
        let (semaphore, permit) = semaphore();
        let stalled = upstream(&[3]).chain(futures::stream::pending());
        let stall = Duration::from_millis(100);

        let items: Vec<Item> = tokio::time::timeout(
            Duration::from_secs(10),
            relay_with_stall(stalled, 100, permit, far(), stall).collect(),
        )
        .await
        .expect("relay must end after a stall");

        let (bytes, error, after) = split(items);
        assert_eq!(bytes, expected(&[3]));
        assert_eq!(error.map(|e| e.kind()), Some(std::io::ErrorKind::TimedOut));
        assert_eq!(after, 0);
        assert_eq!(semaphore.available_permits(), 1);
    }

    /// In-memory upstream yielding `chunks` as given
    fn chunked(
        chunks: &[&'static [u8]],
    ) -> futures::stream::Iter<std::vec::IntoIter<reqwest::Result<Bytes>>> {
        futures::stream::iter(
            chunks
                .iter()
                .map(|chunk| Ok(Bytes::from_static(chunk)))
                .collect::<Vec<_>>(),
        )
    }

    /// Every byte of a peeked stream, which must not error
    async fn drain<S>(stream: S) -> Vec<u8>
    where
        S: Stream<Item = reqwest::Result<Bytes>>,
    {
        let chunks: Vec<reqwest::Result<Bytes>> = stream.collect().await;
        chunks
            .into_iter()
            .flat_map(|chunk| chunk.expect("no upstream error").to_vec())
            .collect()
    }

    /// 20 bytes of a valid Ogg head
    const OGG_HEAD: &[u8] = b"OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06";

    #[tokio::test]
    async fn peek_magic_rejects_bad_magic_at_zero() {
        let junk = chunked(&[b"<html><body>not audio</body></html>"]);
        assert!(peek_magic(junk, "audio/ogg", true, later()).await.is_none());

        // The magic is checked across chunk boundaries too
        let split_junk = chunked(&[b"<ht", b"ml", b"><bo", b"dy>not ", b"audio"]);
        assert!(peek_magic(split_junk, "audio/ogg", true, later())
            .await
            .is_none());
    }

    #[tokio::test]
    async fn peek_magic_lets_short_bodies_through_byte_exact() {
        // Under SNIFF_MIN_BYTES in total, even without the magic
        let body: &[&'static [u8]] = &[b"not", b" audio"];
        let peeked = peek_magic(chunked(body), "audio/ogg", true, later())
            .await
            .expect("short bodies rely on the forced headers");
        assert_eq!(drain(peeked).await, b"not audio");
    }

    #[tokio::test]
    async fn peek_magic_skips_bodies_not_starting_at_zero() {
        let junk = chunked(&[b"<html><body>not audio</body></html>"]);
        let peeked = peek_magic(junk, "audio/ogg", false, later())
            .await
            .expect("mid-file ranges carry no magic");
        assert_eq!(drain(peeked).await, b"<html><body>not audio</body></html>");

        // Not read at all: a stalled upstream past its deadline still passes
        let stalled = futures::stream::pending::<reqwest::Result<Bytes>>();
        assert!(peek_magic(stalled, "audio/ogg", false, Instant::now())
            .await
            .is_some());
    }

    #[tokio::test]
    async fn peek_magic_reprepends_split_chunks_byte_exact() {
        let (a, rest) = OGG_HEAD.split_at(1);
        let (b, rest) = rest.split_at(3);
        let (c, d) = rest.split_at(9);
        let body: &[&'static [u8]] = &[a, b, c, d, b"trailing audio"];

        let peeked = peek_magic(chunked(body), "audio/ogg", true, later())
            .await
            .expect("valid magic split across chunks");
        assert_eq!(drain(peeked).await, [OGG_HEAD, b"trailing audio"].concat());
    }

    #[tokio::test]
    async fn peek_magic_rejects_a_read_error_while_peeking() {
        let failing =
            futures::stream::iter(vec![Ok(Bytes::from_static(b"OggS")), Err(reqwest_error())]);
        assert!(peek_magic(failing, "audio/ogg", true, later())
            .await
            .is_none());
    }

    #[tokio::test]
    async fn peek_magic_rejects_a_stall_past_the_deadline() {
        let stalled = chunked(&[b"OggS"]).chain(futures::stream::pending());
        let deadline = Instant::now() + Duration::from_millis(100);
        let peeked = tokio::time::timeout(
            Duration::from_secs(10),
            peek_magic(stalled, "audio/ogg", true, deadline),
        )
        .await
        .expect("peeking must end at the deadline");
        assert!(peeked.is_none());
    }

    fn headers(pairs: &[(header::HeaderName, &'static str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| (name.clone(), HeaderValue::from_static(value)))
            .collect()
    }

    fn parse_mime(value: &str) -> mime::Mime {
        value.parse().unwrap()
    }

    const MAX: u64 = 1000;

    #[test]
    fn classify_416_is_not_satisfiable() {
        let upstream = headers(&[(header::CONTENT_RANGE, "bytes */5000")]);
        assert_eq!(
            classify(
                StatusCode::RANGE_NOT_SATISFIABLE,
                &mime::APPLICATION_OCTET_STREAM,
                &upstream,
                MAX
            ),
            Upstream::NotSatisfiable
        );
    }

    #[test]
    fn classify_multipart_byteranges_is_rejected() {
        let upstream = headers(&[(header::CONTENT_LENGTH, "10")]);
        for value in [
            "multipart/byteranges; boundary=x",
            "Multipart/ByteRanges; boundary=x",
        ] {
            assert_eq!(
                classify(
                    StatusCode::PARTIAL_CONTENT,
                    &parse_mime(value),
                    &upstream,
                    MAX
                ),
                Upstream::Reject
            );
        }
    }

    #[test]
    fn classify_other_statuses_are_rejected() {
        for status in [
            StatusCode::NO_CONTENT,
            StatusCode::NOT_MODIFIED,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert_eq!(
                classify(status, &parse_mime("audio/mpeg"), &HeaderMap::new(), MAX),
                Upstream::Reject
            );
        }
    }

    #[test]
    fn classify_non_audio_is_rejected() {
        for value in ["text/html", "application/octet-stream", "video/mp4"] {
            assert_eq!(
                classify(StatusCode::OK, &parse_mime(value), &HeaderMap::new(), MAX),
                Upstream::Reject
            );
        }
    }

    #[test]
    fn classify_oversize_total_is_rejected() {
        let over_200 = headers(&[(header::CONTENT_LENGTH, "1001")]);
        assert_eq!(
            classify(StatusCode::OK, &parse_mime("audio/mpeg"), &over_200, MAX),
            Upstream::Reject
        );

        let over_206 = headers(&[
            (header::CONTENT_RANGE, "bytes 0-99/1001"),
            (header::CONTENT_LENGTH, "100"),
        ]);
        assert_eq!(
            classify(
                StatusCode::PARTIAL_CONTENT,
                &parse_mime("audio/mpeg"),
                &over_206,
                MAX
            ),
            Upstream::Reject
        );

        let at_max = headers(&[(header::CONTENT_LENGTH, "1000")]);
        assert_eq!(
            classify(StatusCode::OK, &parse_mime("audio/x-wav"), &at_max, MAX),
            Upstream::Relay {
                content_type: "audio/wav",
                sniff: true
            }
        );
    }

    #[test]
    fn classify_sniffs_only_responses_that_may_start_at_zero() {
        let decide = |status, upstream: &HeaderMap| {
            classify(status, &parse_mime("audio/ogg"), upstream, MAX)
        };

        // No size known: the relay cap is what bounds it
        assert_eq!(
            decide(StatusCode::OK, &HeaderMap::new()),
            Upstream::Relay {
                content_type: "audio/ogg",
                sniff: true
            }
        );
        assert_eq!(
            decide(
                StatusCode::PARTIAL_CONTENT,
                &headers(&[(header::CONTENT_RANGE, "bytes 0-99/500")])
            ),
            Upstream::Relay {
                content_type: "audio/ogg",
                sniff: true
            }
        );
        assert_eq!(
            decide(
                StatusCode::PARTIAL_CONTENT,
                &headers(&[(header::CONTENT_RANGE, "bytes 100-199/500")])
            ),
            Upstream::Relay {
                content_type: "audio/ogg",
                sniff: false
            }
        );
        assert_eq!(
            decide(StatusCode::PARTIAL_CONTENT, &HeaderMap::new()),
            Upstream::Relay {
                content_type: "audio/ogg",
                sniff: true
            }
        );
    }

    #[test]
    fn content_range_start_parses_the_first_position() {
        let start =
            |value: &'static str| content_range_start(&headers(&[(header::CONTENT_RANGE, value)]));
        assert_eq!(start("bytes 0-99/500"), Some(0));
        assert_eq!(start("bytes 123-456/*"), Some(123));
        assert_eq!(start("bytes */500"), None);
        assert_eq!(start("items 0-1/2"), None);
        assert_eq!(content_range_start(&HeaderMap::new()), None);
    }

    #[test]
    fn range_header_reserializes() {
        assert_eq!(range_header(0, None).unwrap(), "bytes=0-");
        assert_eq!(range_header(5, Some(10)).unwrap(), "bytes=5-10");
    }

    #[test]
    fn relay_headers_are_exactly_the_listed_set() {
        let upstream = headers(&[
            (header::CONTENT_TYPE, "text/html"),
            (header::CONTENT_LENGTH, "100"),
            (header::CONTENT_RANGE, "bytes 0-99/500"),
            (header::ACCEPT_RANGES, "bytes"),
            (header::SET_COOKIE, "a=b"),
            (header::CONTENT_ENCODING, "gzip"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::LOCATION, "https://example.com"),
        ]);

        let expected = headers(&[
            (header::CONTENT_TYPE, "audio/mpeg"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CONTENT_SECURITY_POLICY, "sandbox"),
            (header::CONTENT_DISPOSITION, "inline"),
            (header::CACHE_CONTROL, "public, max-age=600"),
            (header::CONTENT_LENGTH, "100"),
            (header::CONTENT_RANGE, "bytes 0-99/500"),
            (header::ACCEPT_RANGES, "bytes"),
        ]);

        assert_eq!(relay_headers("audio/mpeg", &upstream), expected);
    }

    #[test]
    fn relay_headers_never_invent_upstream_headers() {
        let expected = headers(&[
            (header::CONTENT_TYPE, "audio/flac"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CONTENT_SECURITY_POLICY, "sandbox"),
            (header::CONTENT_DISPOSITION, "inline"),
            (header::CACHE_CONTROL, "public, max-age=600"),
        ]);

        assert_eq!(relay_headers("audio/flac", &HeaderMap::new()), expected);
    }

    #[tokio::test]
    async fn not_satisfiable_is_an_empty_416_with_content_range() {
        let upstream = headers(&[
            (header::CONTENT_RANGE, "bytes */5000"),
            (header::CONTENT_LENGTH, "42"),
            (header::CONTENT_TYPE, "text/html"),
            (header::ACCEPT_RANGES, "bytes"),
        ]);

        let response = not_satisfiable(&upstream);
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);

        let expected = headers(&[
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CONTENT_SECURITY_POLICY, "sandbox"),
            (header::CONTENT_DISPOSITION, "inline"),
            (header::CACHE_CONTROL, "public, max-age=600"),
            (header::CONTENT_RANGE, "bytes */5000"),
        ]);
        assert_eq!(response.headers(), &expected);

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    /// Run the `/audio` query extractor on `uri` and decide with `enabled`
    async fn decide_url(enabled: bool, uri: &str) -> std::result::Result<String, StatusCode> {
        use axum::extract::FromRequestParts;

        let (mut parts, _) = axum::http::Request::builder()
            .uri(uri)
            .body(())
            .unwrap()
            .into_parts();
        let query =
            <std::result::Result<Query<UrlQuery>, QueryRejection>>::from_request_parts(
                &mut parts,
                &(),
            )
            .await
            .unwrap();
        audio_url(enabled, query)
    }

    const BAD_QUERIES: [&str; 4] = [
        "/audio",
        "/audio?",
        "/audio?link=https%3A%2F%2Fexample.com%2Fa.mp3",
        "/audio?url=a&url=b",
    ];

    #[tokio::test]
    async fn audio_url_is_404_when_disabled_whatever_the_query() {
        for uri in BAD_QUERIES
            .iter()
            .chain(&["/audio?url=https%3A%2F%2Fexample.com%2Fa.mp3"])
        {
            assert_eq!(
                decide_url(false, uri).await,
                Err(StatusCode::NOT_FOUND),
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn audio_url_is_400_for_a_missing_or_malformed_url_when_enabled() {
        for uri in BAD_QUERIES {
            assert_eq!(
                decide_url(true, uri).await,
                Err(StatusCode::BAD_REQUEST),
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn audio_url_decodes_the_url_when_enabled() {
        assert_eq!(
            decide_url(true, "/audio?url=https%3A%2F%2Fexample.com%2Fa%20b.mp3").await,
            Ok("https://example.com/a b.mp3".to_owned())
        );
    }

    #[test]
    fn deadline_after_saturates() {
        assert!(deadline_after(u64::MAX) > Instant::now());
    }
}
