use encoding_rs::{Encoding, UTF_8_INIT};
use lazy_static::lazy_static;
use mime::Mime;
use regex::Regex;
use reqwest::{
    dns::{Addrs, Name, Resolve},
    header::{self, HeaderMap, HeaderValue, CONTENT_TYPE},
    redirect, Client, Response, StatusCode,
};
use revolt_config::{config, report_internal_error};
use revolt_files::{create_thumbnail, decode_image, image_size_vec, is_valid_image, video_size};
use revolt_models::v0::{Audio, Embed, Image, ImageSize, Video};
use revolt_result::{create_error, Error, Result, ToRevoltError};
use std::net::{IpAddr, SocketAddr};
use std::{
    io::{Cursor, Write},
    time::Duration,
};
use url::{Host, Url};

use crate::ip_policy;

// TODO config
/// At most this much of an HTML page is read for a website embed
const HTML_READ_BYTES: usize = 2 * 1024 * 1024;
/// At most this much of an image is read to find its dimensions
const IMAGE_PROBE_BYTES: usize = 1024 * 1024;
/// At most this much of a video is read for ffprobe
const VIDEO_PROBE_BYTES: usize = 32 * 1024 * 1024;
/// Largest image `/proxy` serves
const PROXY_IMAGE_BYTES: usize = 20 * 1024 * 1024;
/// Largest video `/proxy` serves
const PROXY_VIDEO_BYTES: usize = 50 * 1024 * 1024;

lazy_static! {
    /// Request client
    ///
    /// No proxy: a proxy would resolve the upstream host itself, outside
    /// the vetting resolver.
    static ref CLIENT: Client = reqwest::Client::builder()
        .dns_resolver(VettingDnsResolver)
        .timeout(Duration::from_secs(10)) // TODO config
        .connect_timeout(Duration::from_secs(5)) // TODO config
        .redirect(redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("reqwest Client");

    /// Request client for streamed audio relays (`/audio`)
    ///
    /// Same SSRF posture as `CLIENT` (vetting resolver, no automatic redirects;
    /// `Request::open` follows them manually and re-checks every hop), but
    /// no total timeout: a stream may legitimately run for minutes, so only
    /// connect and per-read stalls are bounded here and the wall-clock limit
    /// is enforced by the relay. Every response decoder is off and
    /// `Accept-Encoding: identity` is sent, because byte ranges and sizes
    /// must refer to the raw file. No proxy: a proxy would resolve the
    /// upstream host itself, outside the resolver the blocklist checked.
    static ref STREAM_CLIENT: Client = reqwest::Client::builder()
        .dns_resolver(VettingDnsResolver)
        .connect_timeout(Duration::from_secs(5))
        // Some hosts take tens of seconds to send the first byte of a cold
        // file (catbox measured up to 45.6 s). This timeout therefore only
        // bounds the wait for headers on each redirect hop and the sniff
        // peek; on every later read the relay's 30 s STALL fires first (the
        // browser then resumes with a Range request). Every slot stays
        // bounded by the wall-clock deadline.
        .read_timeout(Duration::from_secs(60))
        .redirect(redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .no_proxy()
        .default_headers(HeaderMap::from_iter([(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        )]))
        .build()
        .expect("reqwest Client");

    /// Spoof User Agent as Discord
    static ref RE_USER_AGENT_SPOOFING_AS_DISCORD: Regex = Regex::new("^(?:(?:vx|fx)?twitter|(?:fixv|fixup)?x|(?:old\\.|new\\.|www\\.)reddit).com").expect("valid regex");

    /// Regex for matching new Reddit URLs
    static ref RE_URL_NEW_REDDIT: Regex = Regex::new("^(?:(?:new\\.|www\\.)?reddit).com").expect("valid regex");

    /// Regex for matching YouTube Shorts URLs
    static ref RE_URL_YOUTUBE_SHORTS: Regex = Regex::new("^(?:(?:https?:)?//)?(?:(?:www\\.)?youtube\\.com)/shorts/([a-zA-Z0-9_-]+)").expect("valid regex");

    /// Cache for proxy results
    static ref PROXY_CACHE: moka::future::Cache<String, Result<(String, Vec<u8>)>> = moka::future::Cache::builder()
        .weigher(|_key, value: &Result<(String, Vec<u8>)>| -> u32 {
            std::mem::size_of::<Result<(String, Vec<u8>)>>() as u32 + if let Ok((url, vec)) = value {
                url.len().try_into().unwrap_or(u32::MAX) +
                vec.len().try_into().unwrap_or(u32::MAX)
            } else {
                std::mem::size_of::<Error>() as u32
            }
        })
        // TODO config
        .max_capacity(512 * 1024 * 1024) // Cache up to 512MiB in memory
        .time_to_live(Duration::from_secs(60)) // For up to 1 minute
        .build();

    /// Cache for embed results
    static ref EMBED_CACHE: moka::future::Cache<String, Embed> = moka::future::Cache::builder()
        // TODO config
        .max_capacity(10_000) // Cache up to 10k embeds
        .time_to_live(Duration::from_secs(60)) // For up to 1 minute
        .build();

    /// Resolved addresses per host name; only `resolve_vetted` inserts, and
    /// it re-vets every hit
    static ref DNS_CACHE: moka::future::Cache<String, Vec<SocketAddr>> = moka::future::Cache::builder()
        .max_capacity(10_000)
        .time_to_idle(Duration::from_secs(30))
        .build();
}

#[derive(Clone)]
pub struct IPRequest {
    url: Url,
    ip: IpAddr,
    pub blocked: bool,
}

impl From<IPRequest> for Url {
    fn from(value: IPRequest) -> Self {
        let mut url = value.url.clone();
        url.set_host(Some(&value.ip.to_string()))
            .map(|_| url)
            .unwrap_or(value.url)
    }
}

/// Resolver for `CLIENT` and `STREAM_CLIENT`: the connector is only ever
/// handed an address list that passed `resolve_vetted`
struct VettingDnsResolver;

impl Resolve for VettingDnsResolver {
    fn resolve(&self, name: Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let addrs: Addrs = Box::new(resolve_vetted(name.as_str()).await?.into_iter());
            Ok(addrs)
        })
    }
}

/// Resolve `host`, failing the whole name unless the answer is non-empty
/// and no address in it is `ip_policy::is_forbidden`
///
/// Cache hits are vetted again and only vetted answers are cached, so a
/// mixed answer (public + private) or a name that rebinds to a private
/// address never reaches the connector. A refusal is a `PermissionDenied`
/// io error; a failed lookup keeps its own error.
async fn resolve_vetted(host: &str) -> std::io::Result<Vec<SocketAddr>> {
    if let Some(addrs) = DNS_CACHE.get(host).await {
        return vet_addresses(addrs);
    }

    let mut lookup = host.to_string();
    if !lookup.contains(':') {
        lookup += ":0";
    }

    let addrs = vet_addresses(tokio::net::lookup_host(&lookup).await?.collect())?;
    DNS_CACHE.insert(host.to_string(), addrs.clone()).await;
    Ok(addrs)
}

fn vet_addresses(addrs: Vec<SocketAddr>) -> std::io::Result<Vec<SocketAddr>> {
    if addrs.is_empty() || addrs.iter().any(|addr| ip_policy::is_forbidden(addr.ip())) {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "host resolves to a forbidden address",
        ))
    } else {
        Ok(addrs)
    }
}

/// Information about a successful request
pub struct Request {
    response: Response,
    mime: Mime,
}

impl Request {
    /// Split an opened request into its upstream response and parsed
    /// Content-Type (for callers outside this module, e.g. `/audio`)
    pub fn into_parts(self) -> (Response, Mime) {
        (self.response, self.mime)
    }

    /// Proxy a given URL
    pub async fn proxy_file(url: &str) -> Result<(String, Vec<u8>)> {
        if let Some(hit) = PROXY_CACHE.get(url).await {
            hit
        } else {
            let request = Request::new_from_str(url).await?;
            Request::proxy_request(url, request).await
        }
    }

    /// Proxy the already-opened upstream `request` for `url`, caching the
    /// outcome in `PROXY_CACHE`
    async fn proxy_request(url: &str, request: Request) -> Result<(String, Vec<u8>)> {
        let Request { response, mime } = request;

        // SVG is never parsed or rendered server-side: refuse it unread, as a
        // cached client error (not an internal error per request)
        if is_svg(&mime) {
            let result = Err(create_error!(FileTypeNotAllowed));
            PROXY_CACHE.insert(url.to_owned(), result.clone()).await;
            return result;
        }

        if matches!(mime.type_(), mime::IMAGE | mime::VIDEO) {
            let cap = if matches!(mime.type_(), mime::IMAGE) {
                PROXY_IMAGE_BYTES
            } else {
                PROXY_VIDEO_BYTES
            };
            let bytes = read_capped(response, cap, Overflow::Error).await;

            let result = match bytes {
                Ok(bytes) => {
                    if matches!(mime.type_(), mime::IMAGE) {
                        let reader = &mut Cursor::new(&bytes);

                        if matches!(mime.subtype(), mime::GIF) {
                            if is_valid_image(reader, "image/gif") {
                                Ok(("image/gif".to_owned(), bytes.to_vec()))
                            } else {
                                Err(create_error!(FileTypeNotAllowed))
                            }
                        } else {
                            Ok((
                                "image/webp".to_owned(),
                                create_thumbnail(
                                    decode_image(reader, mime.as_ref())?,
                                    "attachments",
                                )
                                .await,
                            ))
                        }
                    } else {
                        let mut file = report_internal_error!(tempfile::NamedTempFile::new())?;
                        report_internal_error!(file.write_all(&bytes))?;

                        if video_size(&file).is_some() {
                            Ok((mime.to_string(), bytes.to_vec()))
                        } else {
                            Err(create_error!(FileTypeNotAllowed))
                        }
                    }
                }
                Err(err) => Err(err),
            };

            PROXY_CACHE.insert(url.to_owned(), result.clone()).await;
            result
        } else {
            Err(create_error!(FileTypeNotAllowed))
        }
    }

    /// Fetch metadata for an image
    pub async fn fetch_image_metadata(
        url: &str,
        request: Option<Request>,
    ) -> Result<Option<Image>> {
        if let Some(hit) = EMBED_CACHE.get(url).await {
            match hit {
                Embed::Image(img) => Ok(Some(img)),
                _ => Ok(None),
            }
        } else {
            let request = if let Some(request) = request {
                request
            } else {
                let request = Request::new_from_str(url).await?;
                if matches!(request.mime.type_(), mime::IMAGE) {
                    request
                } else {
                    return Err(create_error!(FileTypeNotAllowed));
                }
            };

            let Request { response, mime } = request;

            // SVG is never parsed server-side, so its size is never known:
            // skip the read
            if is_svg(&mime) {
                return Ok(None);
            }

            if let Some((width, height)) = image_size_vec(
                &read_capped(response, IMAGE_PROBE_BYTES, Overflow::Truncate).await?,
                mime.as_ref(),
            ) {
                Ok(Some(Image {
                    url: url.to_owned(),
                    width,
                    height,
                    size: ImageSize::Large,
                }))
            } else {
                Ok(None)
            }
        }
    }

    /// Fetch metadata for an video
    pub async fn fetch_video_metadata(
        url: &str,
        request: Option<Request>,
    ) -> Result<Option<Video>> {
        if let Some(hit) = EMBED_CACHE.get(url).await {
            match hit {
                Embed::Video(vid) => Ok(Some(vid)),
                _ => Ok(None),
            }
        } else {
            let response = if let Some(Request { response, .. }) = request {
                response
            } else {
                let Request { response, mime } = Request::new_from_str(url).await?;
                if matches!(mime.type_(), mime::VIDEO) {
                    response
                } else {
                    return Err(create_error!(FileTypeNotAllowed));
                }
            };

            let head = read_capped(response, VIDEO_PROBE_BYTES, Overflow::Truncate).await?;
            let mut file = report_internal_error!(tempfile::NamedTempFile::new())?;
            report_internal_error!(file.write_all(&head))?;

            if let Some((width, height)) = video_size(&file) {
                Ok(Some(Video {
                    url: url.to_owned(),
                    width: width as usize,
                    height: height as usize,
                }))
            } else {
                Ok(None)
            }
        }
    }

    /// Generate embed for a given URL
    pub async fn generate_embed(mut url: String) -> Result<Embed> {
        // Re-map certain links for better metadata generation
        if RE_URL_NEW_REDDIT.is_match(&url) {
            url = RE_URL_NEW_REDDIT
                // Reddit has a bunch of clickbait-y marketing on the new URLs, so we use the old site instead
                .replace(&url, "https://old.reddit.com")
                .to_string();
        }

        // Re-map Youtube Shorts to regular Youtube links
        if let Some(captures) = RE_URL_YOUTUBE_SHORTS.captures(&url) {
            if let Some(video_id) = captures.get(1) {
                url = format!("https://youtube.com/watch?v={}", video_id.as_str());
            }
        }

        // Generate the actual embed
        if let Some(hit) = EMBED_CACHE.get(&url).await {
            Ok(hit)
        } else {
            let request = Request::new_from_str(&url).await?;
            let audio_embeds = config().await.january.audio_embeds;
            let embed = match classify_embed(&request.mime, audio_embeds) {
                EmbedKind::Website => {
                    let content_type = request
                        .response
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse::<Mime>().ok());

                    let encoding_name = content_type
                        .as_ref()
                        .and_then(|mime| mime.get_param("charset").map(|charset| charset.as_str()))
                        .unwrap_or("utf-8");

                    let encoding =
                        Encoding::for_label(encoding_name.as_bytes()).unwrap_or(&UTF_8_INIT);

                    let bytes =
                        read_capped(request.response, HTML_READ_BYTES, Overflow::Truncate).await?;
                    let (text, _, _) = encoding.decode(&bytes);

                    crate::website_embed::create_website_embed(&url, &text)
                        .await
                        .map(Embed::Website)
                        .unwrap_or_default()
                }
                EmbedKind::Image => Request::fetch_image_metadata(&url, Some(request))
                    .await
                    .map(|res| res.map(Embed::Image).unwrap_or_default())
                    .unwrap_or_default(),
                EmbedKind::Video => Request::fetch_video_metadata(&url, Some(request))
                    .await
                    .map(|res| res.map(Embed::Video).unwrap_or_default())
                    .unwrap_or_default(),
                EmbedKind::Audio => Request::fetch_audio_metadata(&url, request)
                    .await
                    .map(|res| res.map(Embed::Audio).unwrap_or_default())
                    .unwrap_or_default(),
                EmbedKind::None => Embed::None,
            };

            EMBED_CACHE.insert(url.to_owned(), embed.clone()).await;
            Ok(embed)
        }
    }

    /// Fetch metadata for an audio file
    ///
    /// `request` is an already-opened upstream response for `url`. Reads at
    /// most `crate::audio::METADATA_READ_BYTES` of the body via
    /// `Response::chunk()` (never `bytes()`), requires
    /// `crate::audio::canonical_type` and `crate::audio::sniff_ok` to accept
    /// it, and returns `Ok(None)` when either rejects or the total size
    /// exceeds `january.max_audio_bytes`.
    pub async fn fetch_audio_metadata(url: &str, request: Request) -> Result<Option<Audio>> {
        let Request { mut response, mime } = request;

        let Some(content_type) = crate::audio::canonical_type(&mime) else {
            return Ok(None);
        };

        let size = crate::audio::total_size(response.status(), response.headers());
        let max_audio_bytes = config().await.january.max_audio_bytes as u64;
        if size.is_some_and(|size| size > max_audio_bytes) {
            return Ok(None);
        }

        // Only the head is needed for the magic check; the rest of the body
        // is dropped unread
        let mut head = Vec::new();
        while head.len() < crate::audio::METADATA_READ_BYTES {
            // Not logged: reqwest errors can carry the upstream URL
            let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| create_error!(ProxyError))?
            else {
                break;
            };

            let take = chunk
                .len()
                .min(crate::audio::METADATA_READ_BYTES - head.len());
            head.extend_from_slice(&chunk[..take]);
        }

        if !crate::audio::sniff_ok(content_type, &head) {
            return Ok(None);
        }

        Ok(Some(Audio {
            url: url.to_owned(),
            content_type: content_type.to_owned(),
            size: size.and_then(|size| usize::try_from(size).ok()),
            filename: Url::parse(url)
                .ok()
                .and_then(|url| crate::audio::filename_from_url(&url)),
        }))
    }

    /// Open an upstream audio stream for the `/audio` relay
    ///
    /// Parses `url` and opens it with `STREAM_CLIENT` through the same
    /// redirect loop as `Request::new_with` (so every hop is SSRF-checked and
    /// re-sends `range`), accepting only 200, 206 and 416. Returns the opened
    /// upstream (response + mime) WITHOUT reading the body; for a 416 the
    /// mime is `application/octet-stream` whatever upstream sent. Logs
    /// nothing.
    pub async fn open_audio_stream(url: &str, range: Option<HeaderValue>) -> Result<Request> {
        let url = Url::parse(url).map_err(|_| create_error!(ProxyError))?;
        Request::open(&STREAM_CLIENT, url, range, accept_audio_stream).await
    }

    /// Send a new request to a service
    pub async fn new(url: Url) -> Result<Request> {
        Request::new_with(&CLIENT, url, None).await
    }

    /// Send a new request to a service using `client`
    ///
    /// Accepts any 2xx; redirects and `range` are handled by `Request::open`.
    pub async fn new_with(
        client: &Client,
        url: Url,
        range: Option<HeaderValue>,
    ) -> Result<Request> {
        Request::open(client, url, range, accept_success).await
    }

    /// Send a request with `client`, keeping the final response when
    /// `accept` allows its status
    ///
    /// Follows up to 5 redirects manually, checking the initial URL and every
    /// hop against `url_is_blacklisted`. When `range` is set it is sent as the
    /// `Range` header on every hop; nothing else from the caller's client
    /// request is forwarded. The mime is chosen by `mime_for_status`.
    async fn open(
        client: &Client,
        url: Url,
        range: Option<HeaderValue>,
        accept: fn(StatusCode) -> bool,
    ) -> Result<Request> {
        let mut url = url;
        let url_host_str = url.host_str().ok_or(create_error!(ProxyError))?.to_string();

        let mut blocker = Request::url_is_blacklisted(&url).await?;

        if blocker.blocked {
            return Err(create_error!(InvalidOperation));
        }

        let mut redirect_count = 0;

        loop {
            let mut builder = client
            .get(url.clone())
            .header(
                "User-Agent",
                if RE_USER_AGENT_SPOOFING_AS_DISCORD.is_match(&url_host_str) {
                    "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
                } else {
                    "Mozilla/5.0 (compatible; January/2.0; +https://github.com/stoatchat/stoatchat)"
                },
            )
            .header("Accept-Language", "en-US,en;q=0.5");

            // Set inside the loop so every redirect hop re-sends it
            if let Some(range) = &range {
                builder = builder.header(header::RANGE, range.clone());
            }

            let response = builder
                .send()
                .await
                .map_err(|_| create_error!(ProxyError))?;

            if response.status().is_redirection() {
                redirect_count += 1;

                if redirect_count > 5 {
                    return Err(create_error!(ProxyError));
                }
                if let Some(location) = response.headers().get("location") {
                    let location = location.to_str().map_err(|_| create_error!(ProxyError))?;
                    // Location may be relative (RFC 9110 §10.2.2) — resolve
                    // against the current URL. Autumn deliberately issues
                    // relative redirects (e.g. stickers → `<id>/<name>`) so
                    // they survive the `/media` reverse-proxy prefix.
                    url = url.join(location).to_internal_error()?;

                    blocker = Request::url_is_blacklisted(&url).await?;

                    if blocker.blocked {
                        return Err(create_error!(InvalidOperation));
                    }

                    continue;
                } else {
                    return Err(create_error!(ProxyError));
                }
            }

            if !accept(response.status()) {
                // The Debug output carries the upstream URL; only the legacy
                // embed/proxy client logs it, stream relays must not.
                if std::ptr::eq(client, &*CLIENT) {
                    tracing::error!("{:?}", response);
                }
                return Err(create_error!(ProxyError));
            }

            let mime = mime_for_status(response.status(), response.headers())?;

            return Ok(Request { response, mime });
        }
    }

    pub async fn new_from_str(url: &str) -> Result<Request> {
        let proper_url = Url::parse(url).map_err(|_| create_error!(ProxyError))?;
        Request::new(proper_url).await
    }

    /// Check if something exists
    pub async fn exists(url: Url) -> bool {
        if Request::url_is_blacklisted(&url).await.is_err() {
            return false;
        }

        if let Ok(response) = CLIENT.head(url).send().await {
            response.status().is_success()
        } else {
            false
        }
    }

    pub async fn exists_from_str(url: &str) -> Result<bool> {
        let proper_url = Url::parse(url).map_err(|_| create_error!(ProxyError))?;
        Ok(Request::exists(proper_url).await)
    }

    /// Refuse `url` unless every address it can reach is allowed
    ///
    /// A literal IP host is judged by `ip_policy::is_forbidden` directly. A
    /// name must contain a dot and not be in `january.blocked_domains`, and
    /// then goes through `resolve_vetted` (the same vetting the clients'
    /// resolver applies), so EVERY address it resolves to must be allowed.
    pub async fn url_is_blacklisted(url: &Url) -> Result<IPRequest> {
        let resolved_address: IpAddr;

        if let Some(host) = url.host() {
            match host {
                Host::Ipv4(ipv4) => {
                    resolved_address = ipv4.into();
                    if ip_policy::is_forbidden(resolved_address) {
                        return Err(create_error!(InvalidOperation));
                    }
                }
                Host::Ipv6(ipv6) => {
                    resolved_address = ipv6.into();
                    if ip_policy::is_forbidden(resolved_address) {
                        return Err(create_error!(InvalidOperation));
                    }
                }
                Host::Domain(domain) => {
                    let domain = domain.to_string();

                    let config = config().await;

                    // First step: TLDs and blocked domains
                    if !domain.contains(".") // lazily block TLDs
                        || config.january.blocked_domains.iter().any(|x| x == &domain)
                    {
                        return Err(create_error!(InvalidOperation));
                    }

                    // Second step: resolve and vet every address
                    match resolve_vetted(&domain).await {
                        Ok(addrs) => resolved_address = addrs[0].ip(),
                        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                            return Err(create_error!(InvalidOperation));
                        }
                        Err(_) => return Err(create_error!(ProxyError)),
                    }
                }
            }
        } else {
            return Err(create_error!(ProxyError));
        };

        Ok(IPRequest {
            url: url.clone(),
            ip: resolved_address,
            blocked: false,
        })
    }
}

/// Final statuses `Request::new_with` accepts: any 2xx
fn accept_success(status: StatusCode) -> bool {
    status.is_success()
}

/// Final statuses `Request::open_audio_stream` accepts: 200 and 206 are
/// relayed, 416 is passed through to the client
fn accept_audio_stream(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::OK | StatusCode::PARTIAL_CONTENT | StatusCode::RANGE_NOT_SATISFIABLE
    )
}

/// Mime of an accepted response
///
/// A 2xx must carry a parsable `Content-Type`. Any other accepted status
/// (416 on the audio path) has no body to type, so the upstream
/// `Content-Type` is ignored and `application/octet-stream` is used.
fn mime_for_status(status: StatusCode, headers: &HeaderMap) -> Result<Mime> {
    if !status.is_success() {
        return Ok(mime::APPLICATION_OCTET_STREAM);
    }

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(create_error!(ProxyError))?
        .to_str()
        .map_err(|_| create_error!(ProxyError))?;

    content_type.parse().map_err(|_| create_error!(ProxyError))
}

/// Whether `mime` is SVG (`image/svg+xml` in any case, whatever its
/// parameters); january never reads SVG bodies
fn is_svg(mime: &Mime) -> bool {
    mime.essence_str()
        .trim()
        .eq_ignore_ascii_case("image/svg+xml")
}

/// What `read_capped` does with a body longer than its cap
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Overflow {
    /// Keep the first `cap` bytes and leave the rest unread
    Truncate,
    /// Drop the response and fail with `FileTooLarge`
    Error,
}

/// Read a response body, holding at most `cap` bytes of it
///
/// Counts the bytes `Response::chunk()` hands over, so the cap bounds
/// memory whatever upstream declares. In `Overflow::Error` mode a
/// `Content-Length` above `cap` is refused before any of the body is read
/// (not in `Truncate` mode: a large image or page still has a usable head).
async fn read_capped(mut response: Response, cap: usize, mode: Overflow) -> Result<Vec<u8>> {
    if mode == Overflow::Error {
        let declared = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());

        if declared.is_some_and(|declared| declared > cap as u64) {
            return Err(create_error!(FileTooLarge { max: cap }));
        }
    }

    let mut body = Vec::new();
    while let Some(chunk) = report_internal_error!(response.chunk().await)? {
        let room = cap - body.len();
        if chunk.len() > room {
            match mode {
                Overflow::Truncate => {
                    body.extend_from_slice(&chunk[..room]);
                    break;
                }
                Overflow::Error => return Err(create_error!(FileTooLarge { max: cap })),
            }
        }

        body.extend_from_slice(&chunk);
        if mode == Overflow::Truncate && body.len() == cap {
            break;
        }
    }

    Ok(body)
}

/// Metadata path `Request::generate_embed` takes for a response
#[derive(Debug, PartialEq, Eq)]
enum EmbedKind {
    Website,
    Image,
    Video,
    Audio,
    None,
}

/// Pick the metadata path for `mime`; audio types (and `application/ogg`)
/// only get one while `january.audio_embeds` is on
fn classify_embed(mime: &Mime, audio_embeds: bool) -> EmbedKind {
    match (mime.type_(), mime.subtype()) {
        (_, mime::HTML) => EmbedKind::Website,
        (mime::IMAGE, _) => EmbedKind::Image,
        (mime::VIDEO, _) => EmbedKind::Video,
        (mime::AUDIO, _) | (mime::APPLICATION, mime::OGG) if audio_embeds => EmbedKind::Audio,
        _ => EmbedKind::None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use reqwest::header::{HeaderName, CONTENT_LENGTH, CONTENT_RANGE};
    use revolt_result::ErrorType;

    use super::*;
    use crate::audio::METADATA_READ_BYTES;

    fn status(code: u16) -> StatusCode {
        StatusCode::from_u16(code).expect("valid status")
    }

    fn mime(value: &str) -> Mime {
        value.parse().expect("valid mime")
    }

    fn headers(pairs: &[(HeaderName, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| (name.clone(), HeaderValue::from_str(value).unwrap()))
            .collect()
    }

    /// An opened request built in memory (no network): `chunks` are served in
    /// order and every byte pulled from the body is added to the returned
    /// counter
    fn synthetic(
        code: u16,
        pairs: &[(HeaderName, &str)],
        chunks: Vec<Vec<u8>>,
    ) -> (Request, Arc<AtomicUsize>) {
        let pulled = Arc::new(AtomicUsize::new(0));
        let counter = pulled.clone();
        let body = reqwest::Body::wrap_stream(futures::stream::iter(chunks.into_iter().map(
            move |chunk| {
                counter.fetch_add(chunk.len(), Ordering::SeqCst);
                Ok::<_, std::io::Error>(chunk)
            },
        )));

        let mut builder = axum::http::Response::builder().status(code);
        for (name, value) in pairs {
            builder = builder.header(name, *value);
        }

        let response: Response = builder.body(body).expect("valid response").into();
        let mime = mime_for_status(response.status(), response.headers()).expect("mime");
        (Request { response, mime }, pulled)
    }

    /// A 4 KiB chunk that starts with an ID3v2 tag header
    fn id3_chunk() -> Vec<u8> {
        let mut chunk = b"ID3\x04\x00\x00\x00\x00\x00\x00".to_vec();
        chunk.resize(4096, 0);
        chunk
    }

    const SONG: &str = "https://example.com/music/song.mp3";

    #[test]
    fn legacy_path_accepts_exactly_2xx() {
        for code in 100..=599u16 {
            assert_eq!(
                accept_success(status(code)),
                (200..300).contains(&code),
                "status {code}"
            );
        }
    }

    #[test]
    fn audio_stream_accepts_exactly_200_206_416() {
        for code in 100..=599u16 {
            assert_eq!(
                accept_audio_stream(status(code)),
                matches!(code, 200 | 206 | 416),
                "status {code}"
            );
        }

        for code in [204, 301, 500] {
            assert!(!accept_audio_stream(status(code)), "status {code}");
        }
    }

    #[test]
    fn range_not_satisfiable_is_octet_stream_whatever_upstream_says() {
        for pairs in [
            vec![(CONTENT_TYPE, "audio/mpeg")],
            vec![(CONTENT_TYPE, "text/html; charset=utf-8")],
            vec![(CONTENT_TYPE, "not a mime")],
            vec![],
        ] {
            assert_eq!(
                mime_for_status(StatusCode::RANGE_NOT_SATISFIABLE, &headers(&pairs)).unwrap(),
                mime::APPLICATION_OCTET_STREAM
            );
        }
    }

    #[test]
    fn success_without_a_parsable_content_type_is_an_error() {
        assert!(mime_for_status(StatusCode::OK, &HeaderMap::new()).is_err());
        assert!(mime_for_status(StatusCode::PARTIAL_CONTENT, &HeaderMap::new()).is_err());
        assert!(
            mime_for_status(StatusCode::OK, &headers(&[(CONTENT_TYPE, "not a mime")])).is_err()
        );

        let mut opaque = HeaderMap::new();
        opaque.insert(
            CONTENT_TYPE,
            HeaderValue::from_bytes(b"audio/\xff").unwrap(),
        );
        assert!(mime_for_status(StatusCode::PARTIAL_CONTENT, &opaque).is_err());
    }

    #[test]
    fn success_keeps_the_upstream_content_type() {
        let parsed = mime_for_status(
            StatusCode::PARTIAL_CONTENT,
            &headers(&[(CONTENT_TYPE, "audio/mpeg; foo=bar")]),
        )
        .unwrap();
        assert_eq!(parsed.essence_str(), "audio/mpeg");
    }

    #[test]
    fn audio_types_route_to_audio_only_behind_the_flag() {
        for value in ["audio/mpeg", "audio/ogg", "audio/x-wav", "application/ogg"] {
            assert_eq!(
                classify_embed(&mime(value), true),
                EmbedKind::Audio,
                "{value}"
            );
            assert_eq!(
                classify_embed(&mime(value), false),
                EmbedKind::None,
                "{value}"
            );
        }
    }

    #[test]
    fn other_types_route_as_before_whatever_the_flag() {
        for flag in [false, true] {
            for (value, kind) in [
                ("text/html", EmbedKind::Website),
                ("text/html; charset=utf-8", EmbedKind::Website),
                ("image/png", EmbedKind::Image),
                ("image/gif", EmbedKind::Image),
                ("video/webm", EmbedKind::Video),
                ("video/mp4", EmbedKind::Video),
                ("application/octet-stream", EmbedKind::None),
                ("application/json", EmbedKind::None),
                ("text/plain", EmbedKind::None),
            ] {
                assert_eq!(
                    classify_embed(&mime(value), flag),
                    kind,
                    "{value} flag={flag}"
                );
            }
        }
    }

    #[tokio::test]
    async fn audio_stream_refuses_blocklisted_hosts_before_connecting() {
        for url in [
            "http://127.0.0.1/a.mp3",
            "http://10.1.2.3/a.mp3",
            "http://192.168.1.1/a.mp3",
            "http://169.254.169.254/latest",
            "http://[::1]/a.mp3",
        ] {
            let error = Request::open_audio_stream(url, None)
                .await
                .err()
                .expect("blocked");
            assert!(
                matches!(error.error_type, ErrorType::InvalidOperation),
                "{url}"
            );
        }
    }

    #[tokio::test]
    async fn audio_stream_refuses_unparsable_urls() {
        for url in ["not a url", "", "data:audio/mpeg;base64,SUQz"] {
            let error = Request::open_audio_stream(url, None)
                .await
                .err()
                .expect("rejected");
            assert!(matches!(error.error_type, ErrorType::ProxyError), "{url:?}");
        }
    }

    #[tokio::test]
    async fn audio_metadata_reads_at_most_the_metadata_window() {
        // 1 MiB body: a `bytes()` read would pull all of it
        let mut chunks = vec![id3_chunk()];
        chunks.extend(std::iter::repeat_n(vec![0u8; 4096], 255));
        let (request, pulled) = synthetic(200, &[(CONTENT_TYPE, "audio/mp3")], chunks);

        let audio = Request::fetch_audio_metadata(SONG, request)
            .await
            .unwrap()
            .expect("audio embed");

        assert!(pulled.load(Ordering::SeqCst) <= METADATA_READ_BYTES);
        assert_eq!(audio.url, SONG);
        assert_eq!(audio.content_type, "audio/mpeg");
        assert_eq!(audio.size, None);
        assert_eq!(audio.filename.as_deref(), Some("song.mp3"));
    }

    #[tokio::test]
    async fn audio_metadata_reports_the_full_size() {
        let (request, _) = synthetic(
            200,
            &[(CONTENT_TYPE, "audio/mpeg"), (CONTENT_LENGTH, "4096")],
            vec![id3_chunk()],
        );
        let audio = Request::fetch_audio_metadata(SONG, request).await.unwrap();
        assert_eq!(audio.expect("audio embed").size, Some(4096));

        let (request, _) = synthetic(
            206,
            &[
                (CONTENT_TYPE, "audio/mpeg"),
                (CONTENT_RANGE, "bytes 0-4095/1234567"),
            ],
            vec![id3_chunk()],
        );
        let audio = Request::fetch_audio_metadata(SONG, request).await.unwrap();
        assert_eq!(audio.expect("audio embed").size, Some(1234567));
    }

    #[tokio::test]
    async fn audio_metadata_rejects_oversize_files_without_reading() {
        let limit = config().await.january.max_audio_bytes as u64;
        let (request, pulled) = synthetic(
            200,
            &[
                (CONTENT_TYPE, "audio/mpeg"),
                (CONTENT_LENGTH, &(limit + 1).to_string()),
            ],
            vec![id3_chunk()],
        );

        assert!(Request::fetch_audio_metadata(SONG, request)
            .await
            .unwrap()
            .is_none());
        assert_eq!(pulled.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn audio_metadata_rejects_unlisted_types_without_reading() {
        for value in ["application/octet-stream", "video/mp4", "audio/x-unknown"] {
            let (request, pulled) = synthetic(200, &[(CONTENT_TYPE, value)], vec![id3_chunk()]);
            assert!(Request::fetch_audio_metadata(SONG, request)
                .await
                .unwrap()
                .is_none());
            assert_eq!(pulled.load(Ordering::SeqCst), 0, "{value}");
        }
    }

    #[tokio::test]
    async fn audio_metadata_rejects_bad_or_short_magic() {
        for body in [vec![0u8; 4096], b"ID3".to_vec(), vec![]] {
            let (request, _) = synthetic(200, &[(CONTENT_TYPE, "audio/mpeg")], vec![body]);
            assert!(Request::fetch_audio_metadata(SONG, request)
                .await
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    async fn audio_metadata_maps_application_ogg_to_audio_ogg() {
        let mut chunk = b"OggS".to_vec();
        chunk.resize(4096, 0);
        let (request, _) = synthetic(200, &[(CONTENT_TYPE, "application/ogg")], vec![chunk]);

        let audio = Request::fetch_audio_metadata("https://example.com/a/b/track.ogg", request)
            .await
            .unwrap()
            .expect("audio embed");
        assert_eq!(audio.content_type, "audio/ogg");
        assert_eq!(audio.filename.as_deref(), Some("track.ogg"));
    }

    /// Make `host` resolve to `addrs` (as if a lookup had just returned them)
    async fn seed_dns(host: &str, addrs: &[(&str, u16)]) {
        DNS_CACHE
            .insert(
                host.to_owned(),
                addrs
                    .iter()
                    .map(|(ip, port)| SocketAddr::new(ip.parse().expect("valid ip"), *port))
                    .collect(),
            )
            .await;
    }

    fn url(value: &str) -> Url {
        Url::parse(value).expect("valid url")
    }

    /// A listener on 127.0.0.1 that nothing should ever connect to
    async fn bait() -> (tokio::net::TcpListener, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        (listener, port)
    }

    async fn assert_never_accepted(listener: &tokio::net::TcpListener) {
        assert!(
            tokio::time::timeout(Duration::from_millis(500), listener.accept())
                .await
                .is_err(),
            "a forbidden address was dialed"
        );
    }

    #[tokio::test]
    async fn sec002_any_forbidden_address_in_an_answer_refuses_the_name() {
        seed_dns("mixed.test", &[("8.8.8.8", 0), ("127.0.0.1", 0)]).await;
        assert!(Request::url_is_blacklisted(&url("http://mixed.test/"))
            .await
            .is_err());

        seed_dns("mixed-v6.test", &[("2606:4700::1111", 0), ("fe80::1", 0)]).await;
        assert!(Request::url_is_blacklisted(&url("http://mixed-v6.test/"))
            .await
            .is_err());

        seed_dns("empty.test", &[]).await;
        assert!(Request::url_is_blacklisted(&url("http://empty.test/"))
            .await
            .is_err());

        // an all-public answer still passes
        seed_dns("public.test", &[("8.8.8.8", 0), ("2606:4700::1111", 0)]).await;
        assert!(Request::url_is_blacklisted(&url("http://public.test/"))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn sec002_forbidden_literal_hosts_are_refused() {
        for value in [
            "http://[::]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::127.0.0.1]/",
            "http://[fe80::1]/",
            "http://[fec0::1]/",
            "http://[ff02::1]/",
            "http://[64:ff9b::7f00:1]/",
            "http://[2002:7f00:1::]/",
            "http://100.64.0.1/",
            "http://198.18.0.1/",
            "http://224.0.0.1/",
            "http://255.255.255.255/",
            "http://0.0.0.0/",
            "http://2130706433/",
        ] {
            assert!(
                Request::url_is_blacklisted(&url(value)).await.is_err(),
                "{value}"
            );
        }

        for value in [
            "http://8.8.8.8/",
            "http://1.1.1.1/",
            "http://[2606:4700::1111]/",
            "http://[2a00:1450::1]/",
        ] {
            assert!(
                Request::url_is_blacklisted(&url(value)).await.is_ok(),
                "{value}"
            );
        }
    }

    #[tokio::test]
    async fn sec002_audio_stream_refuses_a_mixed_answer_before_connecting() {
        let (listener, port) = bait().await;
        seed_dns(
            "mixed-audio.test",
            &[("8.8.8.8", port), ("127.0.0.1", port)],
        )
        .await;

        let error = tokio::time::timeout(
            Duration::from_secs(15),
            Request::open_audio_stream(&format!("http://mixed-audio.test:{port}/a.mp3"), None),
        )
        .await
        .expect("refused without waiting on a connection")
        .err()
        .expect("refused");

        assert!(matches!(error.error_type, ErrorType::InvalidOperation));
        assert_never_accepted(&listener).await;
    }

    #[tokio::test]
    async fn sec002_clients_never_dial_a_forbidden_address() {
        // Straight to the clients, past `url_is_blacklisted`: the resolver
        // itself must refuse (a name that rebinds after the check)
        for (client, host) in [
            (&*CLIENT, "rebind.test"),
            (&*STREAM_CLIENT, "rebind-stream.test"),
        ] {
            let (listener, port) = bait().await;
            seed_dns(host, &[("127.0.0.1", port)]).await;

            let sent = tokio::time::timeout(
                Duration::from_secs(5),
                client.get(format!("http://{host}:{port}/")).send(),
            )
            .await
            .expect("refused without waiting on a connection");

            assert!(sent.is_err(), "{host}");
            assert_never_accepted(&listener).await;
        }

        // A fresh lookup (not a cache hit) is vetted too, and not cached
        let (listener, port) = bait().await;
        let sent = tokio::time::timeout(
            Duration::from_secs(5),
            CLIENT.get(format!("http://localhost:{port}/")).send(),
        )
        .await
        .expect("refused without waiting on a connection");

        assert!(sent.is_err());
        assert_never_accepted(&listener).await;
        assert!(DNS_CACHE.get("localhost").await.is_none());
    }

    #[tokio::test]
    async fn sec002_exists_refuses_forbidden_hosts_before_connecting() {
        let (listener, port) = bait().await;
        seed_dns("exists.test", &[("127.0.0.1", port)]).await;

        for value in [
            format!("http://exists.test:{port}/"),
            format!("http://127.0.0.1:{port}/"),
        ] {
            let found = tokio::time::timeout(Duration::from_secs(5), Request::exists(url(&value)))
                .await
                .expect("refused without waiting on a connection");
            assert!(!found, "{value}");
        }

        assert_never_accepted(&listener).await;
    }

    const CAP: usize = 4096;

    async fn read_body(chunks: Vec<Vec<u8>>, mode: Overflow) -> (Result<Vec<u8>>, usize) {
        let (request, pulled) = synthetic(200, &[(CONTENT_TYPE, "image/png")], chunks);
        let body = read_capped(request.response, CAP, mode).await;
        (body, pulled.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn sec004_one_byte_over_the_cap_is_truncated_or_refused() {
        for chunks in [
            vec![vec![1u8; CAP + 1]],
            vec![vec![1u8; CAP], vec![2u8]],
            vec![vec![1u8; 1000]; 5],
        ] {
            let total: usize = chunks.iter().map(Vec::len).sum();
            assert!(total > CAP);

            let (body, _) = read_body(chunks.clone(), Overflow::Truncate).await;
            let body = body.expect("truncated");
            assert_eq!(body, chunks.concat()[..CAP]);

            let (body, _) = read_body(chunks, Overflow::Error).await;
            assert!(matches!(
                body.expect_err("refused").error_type,
                ErrorType::FileTooLarge { max: CAP }
            ));
        }
    }

    #[tokio::test]
    async fn sec004_exactly_the_cap_is_read_whole() {
        for chunks in [vec![vec![3u8; CAP]], vec![vec![3u8; CAP / 2]; 2], vec![]] {
            for mode in [Overflow::Truncate, Overflow::Error] {
                let (body, _) = read_body(chunks.clone(), mode).await;
                assert_eq!(body.expect("read"), chunks.concat(), "{mode:?}");
            }
        }
    }

    #[tokio::test]
    async fn sec004_reading_stops_at_the_cap() {
        // 1 MiB body: an uncapped read would pull all of it
        for mode in [Overflow::Truncate, Overflow::Error] {
            let (_, pulled) = read_body(vec![vec![0u8; 1024]; 1024], mode).await;
            assert!(pulled <= CAP + 1024, "{mode:?} pulled {pulled}");
        }
    }

    #[tokio::test]
    async fn sec004_declared_oversize_is_refused_unread_only_in_error_mode() {
        let declared = (CAP + 1).to_string();
        let pairs = [
            (CONTENT_TYPE, "image/png"),
            (CONTENT_LENGTH, declared.as_str()),
        ];

        let (request, pulled) = synthetic(200, &pairs, vec![vec![4u8; CAP + 1]]);
        let body = read_capped(request.response, CAP, Overflow::Error).await;
        assert!(matches!(
            body.expect_err("refused").error_type,
            ErrorType::FileTooLarge { max: CAP }
        ));
        assert_eq!(pulled.load(Ordering::SeqCst), 0);

        let (request, _) = synthetic(200, &pairs, vec![vec![4u8; CAP + 1]]);
        let body = read_capped(request.response, CAP, Overflow::Truncate).await;
        assert_eq!(body.expect("truncated").len(), CAP);
    }

    #[tokio::test]
    async fn sec004_image_probe_reads_at_most_its_cap() {
        let (request, pulled) = synthetic(
            200,
            &[(CONTENT_TYPE, "image/png")],
            vec![vec![0u8; 64 * 1024]; 64],
        );

        let image =
            Request::fetch_image_metadata("https://example.com/sec004-probe.png", Some(request))
                .await
                .expect("probe");
        assert!(image.is_none());
        assert!(pulled.load(Ordering::SeqCst) <= IMAGE_PROBE_BYTES + 64 * 1024);
    }

    const SVG: &[u8] = br#"<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>"#;

    #[test]
    fn sec003_svg_is_recognized_whatever_its_case_or_parameters() {
        for (value, svg) in [
            ("image/svg+xml", true),
            ("image/svg+xml; charset=utf-8", true),
            ("IMAGE/SVG+XML", true),
            ("Image/Svg+Xml;charset=UTF-8", true),
            ("image/png", false),
            ("image/svg", false),
            ("text/xml", false),
            ("application/xml", false),
        ] {
            assert_eq!(is_svg(&mime(value)), svg, "{value}");
        }
    }

    #[tokio::test]
    async fn sec003_proxy_refuses_svg_unread_and_caches_the_refusal() {
        for (n, value) in [
            "image/svg+xml",
            "image/svg+xml; charset=utf-8",
            "IMAGE/SVG+XML",
        ]
        .into_iter()
        .enumerate()
        {
            let url = format!("https://sec003-proxy-{n}.invalid/a.svg");
            let (request, pulled) = synthetic(200, &[(CONTENT_TYPE, value)], vec![SVG.to_vec()]);

            let error = Request::proxy_request(&url, request)
                .await
                .expect_err("refused");
            assert!(
                matches!(error.error_type, ErrorType::FileTypeNotAllowed),
                "{value}"
            );
            assert_eq!(pulled.load(Ordering::SeqCst), 0, "{value}");

            // The refusal is cached, so a repeat never fetches again
            let cached = PROXY_CACHE.get(&url).await.expect("cached");
            assert!(
                matches!(
                    cached.map_err(|error| error.error_type),
                    Err(ErrorType::FileTypeNotAllowed)
                ),
                "{value}"
            );

            let error = tokio::time::timeout(Duration::from_secs(10), Request::proxy_file(&url))
                .await
                .expect("answered from the cache")
                .expect_err("refused");
            assert!(
                matches!(error.error_type, ErrorType::FileTypeNotAllowed),
                "{value}"
            );
        }
    }

    #[tokio::test]
    async fn sec003_image_metadata_skips_svg_unread() {
        for value in ["image/svg+xml", "image/svg+xml; charset=utf-8"] {
            let (request, pulled) = synthetic(200, &[(CONTENT_TYPE, value)], vec![SVG.to_vec()]);

            let image =
                Request::fetch_image_metadata("https://example.com/sec003.svg", Some(request))
                    .await
                    .expect("probe");
            assert!(image.is_none(), "{value}");
            assert_eq!(pulled.load(Ordering::SeqCst), 0, "{value}");
        }
    }
}
