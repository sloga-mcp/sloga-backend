use crate::{models::Message, AppendMessage, Database};

use futures::future::join_all;
use linkify::{LinkFinder, LinkKind};
use regex::Regex;
use revolt_config::config;
use revolt_result::{ErrorType, Result};

use async_lock::Semaphore;
use deadqueue::limited::Queue;
use once_cell::sync::Lazy;
use revolt_models::v0::Embed;
use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::task::spawn;

use isahc::prelude::*;

/// Task information
#[derive(Debug)]
struct EmbedTask {
    /// Channel we're processing the event in
    channel: String,
    /// ID of the message we're processing
    id: String,
    /// Content of the message
    content: String,
}

static Q: Lazy<Queue<EmbedTask>> = Lazy::new(|| Queue::new(10_000));

/// Queue a new task for a worker
pub async fn queue(channel: String, id: String, content: String) {
    Q.try_push(EmbedTask {
        channel,
        id,
        content,
    })
    .ok();

    info!("Queue is using {} slots from {}.", Q.len(), Q.capacity());
}

/// Start a new worker
pub async fn worker(db: Database) {
    let semaphore = Arc::new(Semaphore::new(
        config().await.api.workers.max_concurrent_connections,
    ));

    loop {
        let task = Q.pop().await;
        let db = db.clone();
        let semaphore = semaphore.clone();

        spawn(async move {
            let config = config().await;
            let embeds = generate(
                task.content,
                &config.hosts.january,
                &config.api.gamedata.internal_key,
                &config.api.gamedata.internal_january,
                config.features.limits.global.message_embeds,
                semaphore,
            )
            .await;

            if let Ok(embeds) = embeds {
                match Message::append(
                    &db,
                    task.id.clone(),
                    task.channel,
                    AppendMessage {
                        embeds: Some(embeds),
                    },
                )
                .await
                {
                    Ok(()) => {}
                    Err(err) if matches!(err.error_type, ErrorType::NotFound) => debug!(
                        "Message {} was deleted before its embeds resolved; dropping them",
                        task.id
                    ),
                    Err(err) => {
                        error!("Encountered an error appending to message: {:?}", err);
                    }
                }
            }
        });
    }
}

static RE_CODE: Lazy<Regex> = Lazy::new(|| Regex::new("```(?:.|\n)+?```|`(?:.|\n)+?`").unwrap());
static RE_IGNORED: Lazy<Regex> = Lazy::new(|| Regex::new("(<http.+>)").unwrap());

/// Header that lets January build game cards (and spend the shared game
/// data budget) for the worker's requests
const INTERNAL_KEY_HEADER: &str = "X-Internal-Key";

/// Where the worker sends its `/embed` requests, and with which key
#[derive(Debug, PartialEq, Eq)]
struct EmbedRoute<'a> {
    /// January base URL
    host: &'a str,
    /// `X-Internal-Key` value, if one is sent
    key: Option<&'a str>,
    /// Both settings were present but `internal_january` was not a
    /// loopback / private URL, so the key was withheld
    refused: bool,
}

/// Whether `url` is an http(s) URL whose host is `localhost`, a loopback
/// address (127.0.0.0/8, ::1) or an RFC 1918 private IPv4 address. The
/// internal key may only travel to such a host, never through a public
/// proxy or CDN.
fn is_internal_url(url: &str) -> bool {
    let Ok(uri) = url.parse::<isahc::http::Uri>() else {
        return false;
    };
    let Some(scheme) = uri.scheme_str() else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let Some(authority) = uri.authority() else {
        return false;
    };
    // No credentials in the URL
    if authority.as_str().contains('@') {
        return false;
    }

    let host = authority.host();
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private(),
        Ok(IpAddr::V6(ip)) => ip.is_loopback(),
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    }
}

/// Route for the worker's `/embed` requests. The key is sent only when
/// both `internal_key` and `internal_january` are set and the latter is an
/// internal URL; the request then goes there instead of the public
/// `hosts.january`. In every other case the request is exactly as before:
/// the public host, no key (so no game cards).
fn embed_route<'a>(
    public_host: &'a str,
    internal_key: &'a str,
    internal_january: &'a str,
) -> EmbedRoute<'a> {
    let internal_january = internal_january.trim();
    if internal_key.trim().is_empty() || internal_january.is_empty() {
        return EmbedRoute {
            host: public_host,
            key: None,
            refused: false,
        };
    }

    if !is_internal_url(internal_january) {
        return EmbedRoute {
            host: public_host,
            key: None,
            refused: true,
        };
    }

    EmbedRoute {
        host: internal_january.trim_end_matches('/'),
        key: Some(internal_key),
        refused: false,
    }
}

/// Set once the refused-route warning has been logged
static WARNED_REFUSED_ROUTE: AtomicBool = AtomicBool::new(false);

/// January `/embed` request for `link` along `route`. The key header is
/// marked sensitive so it is never printed.
fn embed_request(route: &EmbedRoute, link: &str) -> Option<isahc::Request<()>> {
    let host = route.host;
    let mut builder = isahc::Request::get(format!(
        "{host}/embed?url={}",
        url_escape::encode_component(link)
    ));

    if let Some(key) = route.key {
        if let Ok(mut value) = isahc::http::HeaderValue::from_str(key) {
            value.set_sensitive(true);
            builder = builder.header(INTERNAL_KEY_HEADER, value);
        }
    }

    builder.body(()).ok()
}

pub async fn generate(
    content: String,
    host: &str,
    internal_key: &str,
    internal_january: &str,
    max_embeds: usize,
    semaphore: Arc<Semaphore>,
) -> Result<Vec<Embed>> {
    // Ignore code blocks.
    let content = RE_CODE.replace_all(&content, "");

    // Ignore all content between angle brackets starting with http.
    let content = RE_IGNORED.replace_all(&content, "");

    let content = content
        // Ignore quoted lines.
        .split('\n')
        .map(|v| {
            if let Some(c) = v.chars().next() {
                if c == '>' {
                    return "";
                }
            }

            v
        })
        .collect::<Vec<&str>>()
        .join("\n");

    let mut finder = LinkFinder::new();
    finder.kinds(&[LinkKind::Url]);

    // Process all links, stripping anchors and
    // only taking up to `max_embeds` of links.
    let links: Vec<String> = finder
        .links(&content)
        .map(|x| {
            x.as_str()
                .chars()
                .take_while(|&ch| ch != '#')
                .collect::<String>()
        })
        .collect::<HashSet<String>>()
        .into_iter()
        .take(max_embeds)
        .collect();

    // If no links, fail out.
    if links.is_empty() {
        return Err(create_error!(LabelMe));
    }

    // TODO: batch request to january
    let mut tasks = Vec::new();

    let route = embed_route(host, internal_key, internal_january);
    if route.refused && !WARNED_REFUSED_ROUTE.swap(true, Ordering::Relaxed) {
        warn!(
            "api.gamedata.internal_january is not an http(s) URL on localhost, a loopback or a \
             private address; the internal key is not sent and game cards stay off"
        );
    }

    for link in links {
        let semaphore = semaphore.clone();
        let request = embed_request(&route, &link);
        tasks.push(spawn(async move {
            let request = request?;
            let guard = semaphore.acquire().await;

            if let Ok(mut response) = request.send_async().await {
                drop(guard);
                let status_ok = response.status().is_success();
                keep_embed(status_ok, response.json::<Embed>().await.ok())
            } else {
                None
            }
        }));
    }

    let embeds = join_all(tasks)
        .await
        .into_iter()
        .flatten()
        .flatten()
        .collect::<Vec<Embed>>();

    // Prevent database update when no embeds are found.
    if !embeds.is_empty() {
        Ok(embeds)
    } else {
        Err(create_error!(LabelMe))
    }
}

/// Keep a january response only if it succeeded and carries a real embed.
/// Unknown embed types decode as `Embed::None`, and so does january's
/// `{"type":"NoEmbedData"}` error body, so `None` must be filtered out.
fn keep_embed(status_ok: bool, embed: Option<Embed>) -> Option<Embed> {
    if !status_ok {
        return None;
    }

    embed.filter(|e| !matches!(e, Embed::None))
}

#[cfg(test)]
mod tests {
    use super::{embed_request, embed_route, is_internal_url, keep_embed, INTERNAL_KEY_HEADER};
    use revolt_models::v0::{Embed, Image, ImageSize};

    const LINK: &str = "https://store.steampowered.com/app/620/?a=1&b=2";
    const QUERY: &str =
        "/embed?url=https%3A%2F%2Fstore.steampowered.com%2Fapp%2F620%2F%3Fa%3D1%26b%3D2";
    const PUBLIC: &str = "https://app.sloga.gg/proxy";
    const INTERNAL: &str = "http://127.0.0.1:14705";
    const KEY: &str = "s3cret-internal-key";

    /// (uri, key header) the worker would send for `LINK`
    fn sent(key: &str, internal_january: &str) -> (String, Option<String>) {
        let route = embed_route(PUBLIC, key, internal_january);
        let request = embed_request(&route, LINK).expect("request");
        assert!(!format!("{request:?}").contains(KEY), "key printed");
        let header = request.headers().get(INTERNAL_KEY_HEADER).map(|value| {
            assert!(value.is_sensitive());
            value.to_str().unwrap().to_string()
        });
        (request.uri().to_string(), header)
    }

    #[test]
    fn key_without_an_internal_url_goes_to_the_public_host_without_a_header() {
        for internal in ["", "   "] {
            let (uri, header) = sent(KEY, internal);
            assert_eq!(uri, format!("{PUBLIC}{QUERY}"), "{internal:?}");
            assert_eq!(header, None, "{internal:?}");
            assert!(!embed_route(PUBLIC, KEY, internal).refused);
        }
    }

    #[test]
    fn no_key_is_exactly_the_old_request() {
        for (key, internal) in [("", ""), ("   ", ""), ("", INTERNAL), ("  ", INTERNAL)] {
            let route = embed_route(PUBLIC, key, internal);
            let request = embed_request(&route, LINK).expect("request");
            assert_eq!(request.uri().to_string(), format!("{PUBLIC}{QUERY}"));
            assert!(request.headers().is_empty(), "{key:?} {internal:?}");
            assert!(!route.refused);
        }
    }

    #[test]
    fn key_and_internal_url_send_the_header_to_the_internal_host() {
        for internal in [INTERNAL, "http://127.0.0.1:14705/", " http://localhost:14705 "] {
            let (uri, header) = sent(KEY, internal);
            let base = internal.trim().trim_end_matches('/');
            assert_eq!(uri, format!("{base}{QUERY}"), "{internal:?}");
            assert_eq!(header.as_deref(), Some(KEY), "{internal:?}");
        }
    }

    #[test]
    fn a_public_internal_url_never_gets_the_key() {
        for internal in [
            PUBLIC,
            "http://january:14705",
            "http://8.8.8.8:14705",
            "http://localhost.evil.example",
            "ftp://127.0.0.1",
            "127.0.0.1:14705",
        ] {
            let (uri, header) = sent(KEY, internal);
            assert_eq!(uri, format!("{PUBLIC}{QUERY}"), "{internal:?}");
            assert_eq!(header, None, "{internal:?}");
            assert!(embed_route(PUBLIC, KEY, internal).refused, "{internal:?}");
        }
    }

    #[test]
    fn internal_urls_are_loopback_or_private_only() {
        for (url, internal) in [
            ("http://127.0.0.1:14705", true),
            ("http://127.8.9.10", true),
            ("https://localhost", true),
            ("HTTP://LOCALHOST:14705", true),
            ("http://[::1]:14705", true),
            ("http://10.0.0.5:14705", true),
            ("http://172.16.0.1", true),
            ("http://172.31.255.255", true),
            ("http://192.168.1.20:14705", true),
            ("http://172.32.0.1", false),
            ("http://169.254.169.254", false),
            ("http://100.64.0.1", false),
            ("http://[::ffff:127.0.0.1]", false),
            ("http://[fd00::1]", false),
            ("http://127.1", false),
            ("http://user:pass@127.0.0.1", false),
            ("https://app.sloga.gg/proxy", false),
            ("ws://127.0.0.1", false),
            ("not a url", false),
            ("", false),
        ] {
            assert_eq!(is_internal_url(url), internal, "{url}");
        }
    }

    fn image() -> Embed {
        Embed::Image(Image {
            url: "https://example.com/a.png".to_string(),
            width: 1,
            height: 1,
            size: ImageSize::Large,
        })
    }

    #[test]
    fn non_success_status_is_dropped() {
        assert!(keep_embed(false, Some(image())).is_none());
    }

    #[test]
    fn none_embed_is_dropped() {
        assert!(keep_embed(true, Some(Embed::None)).is_none());
    }

    #[test]
    fn real_embed_is_kept() {
        assert!(matches!(
            keep_embed(true, Some(image())),
            Some(Embed::Image(_))
        ));
    }

    #[test]
    fn january_error_body_is_dropped() {
        let body = serde_json::from_str::<Embed>(r#"{"type":"NoEmbedData","location":"x"}"#).ok();
        assert!(matches!(body, Some(Embed::None)));
        assert!(keep_embed(true, body).is_none());
    }
}
