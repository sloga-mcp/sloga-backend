use encoding_rs::{Encoding, UTF_8_INIT};
use lazy_static::lazy_static;
use mime::Mime;
use pdk_ip_filter_lib::IpFilter;
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
    str::FromStr,
    time::Duration,
};
use url::{Host, Url};

lazy_static! {
    /// Request client
    static ref CLIENT: Client = reqwest::Client::builder()
        .dns_resolver(CachedDnsResolver {})
        .timeout(Duration::from_secs(10)) // TODO config
        .connect_timeout(Duration::from_secs(5)) // TODO config
        .redirect(redirect::Policy::none())
        .build()
        .expect("reqwest Client");

    /// Request client for streamed audio relays (`/audio`)
    ///
    /// Same SSRF posture as `CLIENT` (cached resolver, no automatic redirects;
    /// `Request::open` follows them manually and re-checks every hop), but
    /// no total timeout: a stream may legitimately run for minutes, so only
    /// connect and per-read stalls are bounded here and the wall-clock limit
    /// is enforced by the relay. Every response decoder is off and
    /// `Accept-Encoding: identity` is sent, because byte ranges and sizes
    /// must refer to the raw file. No proxy: a proxy would resolve the
    /// upstream host itself, outside the resolver the blocklist checked.
    static ref STREAM_CLIENT: Client = reqwest::Client::builder()
        .dns_resolver(CachedDnsResolver {})
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

    static ref DNS_CACHE: moka::future::Cache<String, Vec<SocketAddr>> = moka::future::Cache::builder()
        .max_capacity(10_000)
        .time_to_idle(Duration::from_secs(30))
        .build();

    static ref IP_BLOCKLIST: IpFilter = IpFilter::block(&[
        "0.0.0.0/8",
        "10.0.0.0/8",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "172.16.0.0/12",
        "169.254.0.0/16",
        "::1",
        "fc00::/7",
        ]
    ).unwrap();
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

struct CachedDnsResolver {}

impl reqwest::dns::Resolve for CachedDnsResolver {
    fn resolve(&self, name: Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            {
                if let Some(addrs) = DNS_CACHE.get(&name.as_str().to_string()).await {
                    let resp: Addrs = Box::new(addrs.clone().into_iter());
                    return Ok(resp);
                }
            }

            let mut lookup = name.as_str().to_string();
            if !lookup.contains(":") {
                lookup += ":0";
            }

            let fallback: Vec<SocketAddr> = tokio::net::lookup_host(&lookup)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();

            {
                DNS_CACHE
                    .insert(name.as_str().to_string().clone(), fallback.clone())
                    .await;
                let addrs: Addrs = Box::new(fallback.clone().into_iter());
                Ok(addrs)
            }
        })
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
            let Request { response, mime } = Request::new_from_str(url).await?;

            if matches!(mime.type_(), mime::IMAGE | mime::VIDEO) {
                let bytes = report_internal_error!(response.bytes().await);

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

            if let Some((width, height)) = image_size_vec(
                &report_internal_error!(request.response.bytes().await)?,
                request.mime.as_ref(),
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

            let mut file = report_internal_error!(tempfile::NamedTempFile::new())?;
            report_internal_error!(
                file.write_all(&report_internal_error!(response.bytes().await)?)
            )?;

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

                    let bytes = report_internal_error!(request.response.bytes().await)?;
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

    pub async fn url_is_blacklisted(url: &Url) -> Result<IPRequest> {
        let resolved_address: IpAddr;

        if let Some(host) = url.host() {
            match host {
                Host::Ipv4(ipv4) => {
                    resolved_address = ipv4.into();
                    if !IP_BLOCKLIST.is_allowed(&ipv4.to_string()) {
                        return Err(create_error!(InvalidOperation));
                    }
                }
                Host::Ipv6(ipv6) => {
                    resolved_address = ipv6.into();
                    if !IP_BLOCKLIST.is_allowed(&ipv6.to_string()) {
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

                    // Second step: resolve the IP and check the blocklist
                    let resolver = CachedDnsResolver {};
                    if let Ok(mut resolved_ip) = resolver
                        .resolve(
                            Name::from_str(&domain)
                                .map_err(|_| create_error!(ProxyError))
                                .unwrap(),
                        )
                        .await
                    {
                        if let Some(resolved_ip) = resolved_ip.next() {
                            resolved_address = resolved_ip.ip();
                            let resolved_string = resolved_address.to_string();
                            if !IP_BLOCKLIST.is_allowed(&resolved_string)
                                || resolved_string.contains("::ffff:")
                            {
                                return Err(create_error!(InvalidOperation));
                            }
                        } else {
                            return Err(create_error!(InvalidOperation));
                        }
                    } else {
                        return Err(create_error!(ProxyError));
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
}
