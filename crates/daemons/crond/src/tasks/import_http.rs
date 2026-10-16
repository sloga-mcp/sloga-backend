//! Outbound HTTP plumbing shared by the source importers (Stoat, Fluxer).
//!
//! Nothing here knows which source it talks to: no header names, no URL
//! shapes, no log lines. Each source builds its API and CDN clients from
//! [`client_builder`], picks its own redirect policy (an API client carrying
//! a credential follows none; a CDN client may use
//! [`same_origin_redirects`]), and reads every body through [`read_capped`].

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Url;

use crate::tasks::discord_import::mapper::AssetKind;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);
const USER_AGENT: &str = concat!(
    "SlogaImport/",
    env!("CARGO_PKG_VERSION"),
    " (+https://sloga.gg)"
);

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

pub(crate) enum Transport {
    /// HTTPS only, system proxy settings honored.
    Production,
    /// Plain HTTP to a loopback fake, never through a proxy.
    #[cfg(test)]
    LoopbackTest,
}

/// The production transport, except that a TEST build talks plain HTTP to a
/// loopback fake upstream. That is what lets the worker tests drive the real
/// dispatch (claim → run → leave) against a fake source; a non-test build has
/// no such branch, and `production_transport_refuses_plain_http` (in
/// `stoat_import::source`) pins the production half.
pub(crate) fn transport_for(url: &str) -> Transport {
    #[cfg(test)]
    if url.starts_with("http://127.0.0.1:") {
        return Transport::LoopbackTest;
    }
    let _ = url;
    Transport::Production
}

/// A client builder with the importer's timeouts and user agent. The caller
/// sets the redirect policy.
pub(crate) fn client_builder(transport: Transport) -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder()
        .timeout(UPSTREAM_TIMEOUT)
        .connect_timeout(UPSTREAM_TIMEOUT)
        .user_agent(USER_AGENT);

    match transport {
        Transport::Production => builder.https_only(true),
        #[cfg(test)]
        Transport::LoopbackTest => builder.no_proxy(),
    }
}

/// Follow at most `max_redirects` redirects, and only while every hop stays
/// on `origin`.
pub(crate) fn same_origin_redirects(
    origin: Url,
    max_redirects: usize,
) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > max_redirects || !same_origin(attempt.url(), &origin) {
            attempt.stop()
        } else {
            attempt.follow()
        }
    })
}

pub(crate) fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Why a capped body read failed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadError {
    TooLarge,
    Transport,
}

/// Read a response body, refusing it as soon as it is known to exceed `cap`
/// bytes: up front from `Content-Length`, else while streaming.
pub(crate) async fn read_capped(
    mut response: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, ReadError> {
    if response
        .content_length()
        .is_some_and(|length| length > cap as u64)
    {
        return Err(ReadError::TooLarge);
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ReadError::Transport)? {
        if body.len() + chunk.len() > cap {
            return Err(ReadError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// Asset caps
// ---------------------------------------------------------------------------

/// Per-kind download caps, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AssetLimits {
    pub icon: usize,
    pub banner: usize,
    pub emoji: usize,
}

impl AssetLimits {
    /// Sloga's own upload limits for the three tags (`store_file` refuses
    /// anything larger, so there is no point reading more), with the stock
    /// values as a fallback when a tag is missing from the config.
    pub(crate) fn from_upload_limits(limits: &HashMap<String, usize>) -> AssetLimits {
        let limit = |tag: &str, fallback: usize| limits.get(tag).copied().unwrap_or(fallback);
        AssetLimits {
            icon: limit("icons", 2_500_000),
            banner: limit("banners", 6_000_000),
            emoji: limit("emojis", 500_000),
        }
    }

    pub(crate) fn for_kind(&self, kind: AssetKind) -> usize {
        match kind {
            AssetKind::Icon => self.icon,
            AssetKind::Banner => self.banner,
            AssetKind::Emoji => self.emoji,
        }
    }
}

/// A scripted upstream API / CDN on a loopback port, for tests that must not
/// reach a real one. Source-specific helpers (a ready config for that
/// source) live with the source, as inherent methods on [`FakeUpstream`].
#[cfg(test)]
pub(crate) mod fake_upstream {
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    pub(crate) const BOT_TOKEN: &str = "fake-bot-token";

    /// Largest request body the fake reads.
    const MAX_REQUEST_BODY: usize = 1024 * 1024;

    /// One request the fake received.
    #[derive(Clone, Debug)]
    pub(crate) struct Seen {
        pub method: String,
        pub path: String,
        /// Every request header in order, names lowercased, values trimmed.
        pub headers: Vec<(String, String)>,
        /// The `x-bot-token` header (Stoat's bot credential), if sent.
        pub bot_token: Option<String>,
        /// The request body, as long as its `Content-Length` said (empty
        /// without one).
        pub body: Vec<u8>,
    }

    impl Seen {
        /// The first header called `name` (any case), if sent.
        pub(crate) fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    #[derive(Clone)]
    struct Reply {
        status: u16,
        body: Vec<u8>,
        location: Option<String>,
        /// Leave out `Content-Length` (the body ends at connection close),
        /// so a size cap must be enforced while streaming.
        no_length: bool,
        /// Further response headers, written as given.
        headers: Vec<(String, String)>,
    }

    /// The replies scripted for one `(method, path)`, served in order; the
    /// last one is repeated once the others are used up.
    type Script = Arc<Mutex<HashMap<(String, String), VecDeque<Reply>>>>;

    pub(crate) struct FakeUpstream {
        pub url: String,
        replies: HashMap<(String, String), VecDeque<Reply>>,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl FakeUpstream {
        pub(crate) fn new() -> FakeUpstream {
            FakeUpstream {
                url: String::new(),
                replies: HashMap::new(),
                seen: Arc::new(Mutex::new(vec![])),
            }
        }

        /// Make `reply` the only answer to `method path`.
        fn with(mut self, method: &str, path: &str, reply: Reply) -> FakeUpstream {
            self.replies.insert(
                (method.to_string(), path.to_string()),
                VecDeque::from([reply]),
            );
            self
        }

        /// Queue `reply` after the answers already scripted for `method path`.
        fn then(mut self, method: &str, path: &str, reply: Reply) -> FakeUpstream {
            self.replies
                .entry((method.to_string(), path.to_string()))
                .or_default()
                .push_back(reply);
            self
        }

        fn plain(status: u16, body: Vec<u8>, headers: &[(&str, &str)]) -> Reply {
            Reply {
                status,
                body,
                location: None,
                no_length: false,
                headers: headers
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_string()))
                    .collect(),
            }
        }

        /// Answer `method path` with `status` and `body` as is.
        pub(crate) fn reply(
            self,
            method: &str,
            path: &str,
            status: u16,
            body: impl Into<Vec<u8>>,
        ) -> FakeUpstream {
            self.with(method, path, FakeUpstream::plain(status, body.into(), &[]))
        }

        /// Like `reply`, with extra response headers (`Retry-After`, ...).
        pub(crate) fn reply_with_headers(
            self,
            method: &str,
            path: &str,
            status: u16,
            body: impl Into<Vec<u8>>,
            headers: &[(&str, &str)],
        ) -> FakeUpstream {
            self.with(
                method,
                path,
                FakeUpstream::plain(status, body.into(), headers),
            )
        }

        /// Answer the NEXT `method path` request this way, after the
        /// replies already scripted for it. Each scripted reply is used once,
        /// in order, and the last one is repeated from then on.
        pub(crate) fn then_reply(
            self,
            method: &str,
            path: &str,
            status: u16,
            body: impl Into<Vec<u8>>,
        ) -> FakeUpstream {
            self.then(method, path, FakeUpstream::plain(status, body.into(), &[]))
        }

        /// Like `reply`, without a `Content-Length` header.
        pub(crate) fn reply_unsized(
            self,
            method: &str,
            path: &str,
            status: u16,
            body: impl Into<Vec<u8>>,
        ) -> FakeUpstream {
            self.with(
                method,
                path,
                Reply {
                    status,
                    body: body.into(),
                    location: None,
                    no_length: true,
                    headers: Vec::new(),
                },
            )
        }

        /// Answer `GET path` with a 307 to `location`.
        pub(crate) fn redirect(self, path: &str, location: &str) -> FakeUpstream {
            self.with(
                "GET",
                path,
                Reply {
                    status: 307,
                    body: Vec::new(),
                    location: Some(location.to_string()),
                    no_length: false,
                    headers: Vec::new(),
                },
            )
        }

        /// The reply for `key`: the next scripted one, or the last again.
        fn next_reply(script: &Script, key: &(String, String)) -> Option<Reply> {
            let mut script = script.lock().unwrap();
            let queue = script.get_mut(key)?;
            if queue.len() > 1 {
                queue.pop_front()
            } else {
                queue.front().cloned()
            }
        }

        /// Start serving; unscripted requests get 404.
        pub(crate) async fn start(mut self) -> FakeUpstream {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            self.url = format!("http://{}", listener.local_addr().expect("addr"));

            let replies: Script = Arc::new(Mutex::new(self.replies.clone()));
            let seen = self.seen.clone();
            tokio::spawn(async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    let replies = replies.clone();
                    let seen = seen.clone();
                    tokio::spawn(async move {
                        let mut raw = Vec::new();
                        let mut chunk = [0u8; 1024];
                        while !raw.windows(4).any(|w| w == b"\r\n\r\n") && raw.len() < 65536 {
                            match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => raw.extend_from_slice(&chunk[..n]),
                            }
                        }

                        // Whatever followed the blank line is the start of
                        // the body; read the rest of what `Content-Length`
                        // announced.
                        let head_end = raw
                            .windows(4)
                            .position(|w| w == b"\r\n\r\n")
                            .map_or(raw.len(), |at| at + 4);
                        let mut body = raw.split_off(head_end);
                        let head = String::from_utf8_lossy(&raw).to_string();
                        let mut words = head.split_whitespace();
                        let method = words.next().unwrap_or("").to_string();
                        let path = words.next().unwrap_or("").to_string();
                        // Header lines only: after the request line, up to
                        // the blank line (whatever follows is body).
                        let headers: Vec<(String, String)> = head
                            .split("\r\n\r\n")
                            .next()
                            .unwrap_or("")
                            .lines()
                            .skip(1)
                            .filter_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
                            })
                            .collect();
                        let bot_token = headers
                            .iter()
                            .find(|(name, _)| name == "x-bot-token")
                            .map(|(_, value)| value.clone());
                        let length = headers
                            .iter()
                            .find(|(name, _)| name == "content-length")
                            .and_then(|(_, value)| value.parse::<usize>().ok())
                            .unwrap_or(0)
                            .min(MAX_REQUEST_BODY);
                        while body.len() < length {
                            match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => body.extend_from_slice(&chunk[..n]),
                            }
                        }
                        body.truncate(length);
                        seen.lock().unwrap().push(Seen {
                            method: method.clone(),
                            path: path.clone(),
                            headers,
                            bot_token,
                            body,
                        });

                        let reply =
                            FakeUpstream::next_reply(&replies, &(method, path)).unwrap_or(Reply {
                                status: 404,
                                body: br#"{"type":"NotFound"}"#.to_vec(),
                                location: None,
                                no_length: false,
                                headers: Vec::new(),
                            });
                        let location = reply
                            .location
                            .map(|to| format!("location: {to}\r\n"))
                            .unwrap_or_default();
                        let length = if reply.no_length {
                            String::new()
                        } else {
                            format!("content-length: {}\r\n", reply.body.len())
                        };
                        let extra: String = reply
                            .headers
                            .iter()
                            .map(|(name, value)| format!("{name}: {value}\r\n"))
                            .collect();
                        let mut response = format!(
                            "HTTP/1.1 {} Scripted\r\n{location}{length}{extra}connection: close\r\n\r\n",
                            reply.status
                        )
                        .into_bytes();
                        response.extend_from_slice(&reply.body);
                        let _ = socket.write_all(&response).await;
                        let _ = socket.shutdown().await;
                    });
                }
            });

            self
        }

        /// Requests received so far, in order.
        pub(crate) fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake_upstream::{FakeUpstream, BOT_TOKEN};
    use super::*;

    #[tokio::test]
    async fn the_fake_records_every_request_header() {
        let fake = FakeUpstream::new()
            .reply("GET", "/v1/thing", 200, "{}")
            .start()
            .await;
        let client = client_builder(transport_for(&fake.url))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client");

        client
            .get(format!("{}/v1/thing", fake.url))
            .header("Authorization", format!("Bot {BOT_TOKEN}"))
            .header("X-Custom", "  padded  ")
            .send()
            .await
            .expect("sent");
        client
            .get(format!("{}/v1/thing", fake.url))
            .header("x-bot-token", BOT_TOKEN)
            .send()
            .await
            .expect("sent");

        let seen = fake.seen();
        assert_eq!(seen.len(), 2, "{seen:?}");

        let expected = format!("Bot {BOT_TOKEN}");
        assert_eq!(seen[0].header("authorization"), Some(expected.as_str()));
        assert_eq!(seen[0].header("AUTHORIZATION"), Some(expected.as_str()));
        assert_eq!(seen[0].header("x-custom"), Some("padded"));
        assert!(seen[0]
            .header("user-agent")
            .is_some_and(|ua| ua.starts_with("SlogaImport/")));
        assert!(seen[0]
            .headers
            .iter()
            .all(|(name, _)| *name == name.to_ascii_lowercase()));
        assert_eq!(seen[0].bot_token, None);
        assert_eq!(seen[0].header("x-bot-token"), None);

        assert_eq!(seen[1].bot_token.as_deref(), Some(BOT_TOKEN));
        assert_eq!(seen[1].header("x-bot-token"), Some(BOT_TOKEN));
        assert_eq!(seen[1].header("authorization"), None);
    }

    /// Scripted replies are served in order and the last one repeats; extra
    /// reply headers arrive; request bodies are recorded.
    #[tokio::test]
    async fn the_fake_scripts_replies_in_order_and_records_bodies() {
        let fake = FakeUpstream::new()
            .reply_with_headers("DELETE", "/v1/x", 429, "{}", &[("Retry-After", "7")])
            .then_reply("DELETE", "/v1/x", 204, "")
            .reply("GET", "/v1/once", 200, "a")
            .reply("GET", "/v1/once", 200, "b")
            .start()
            .await;
        let client = client_builder(transport_for(&fake.url))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client");

        let mut statuses = Vec::new();
        for _ in 0..3 {
            let response = client
                .delete(format!("{}/v1/x", fake.url))
                .header("Content-Type", "application/json")
                .body("{\"k\":1}")
                .send()
                .await
                .expect("sent");
            statuses.push((
                response.status().as_u16(),
                response
                    .headers()
                    .get("retry-after")
                    .map(|value| value.to_str().unwrap().to_string()),
            ));
        }
        assert_eq!(
            statuses,
            vec![
                (429, Some("7".to_string())),
                (204, None),
                // The last scripted reply repeats.
                (204, None),
            ]
        );

        // `reply` still replaces what was scripted before it.
        let body = client
            .get(format!("{}/v1/once", fake.url))
            .send()
            .await
            .expect("sent")
            .text()
            .await
            .unwrap();
        assert_eq!(body, "b");

        let seen = fake.seen();
        assert_eq!(seen.len(), 4, "{seen:?}");
        assert!(seen[..3].iter().all(|s| s.body == b"{\"k\":1}"), "{seen:?}");
        assert!(seen[3].body.is_empty());
    }

    #[test]
    fn same_origin_compares_scheme_host_and_port() {
        let url = |s: &str| Url::parse(s).unwrap();
        assert!(same_origin(
            &url("https://cdn.example/a"),
            &url("https://cdn.example:443/b")
        ));
        assert!(!same_origin(
            &url("https://cdn.example/a"),
            &url("http://cdn.example/a")
        ));
        assert!(!same_origin(
            &url("https://cdn.example/a"),
            &url("https://cdn.example:8443/a")
        ));
        assert!(!same_origin(
            &url("https://cdn.example/a"),
            &url("https://evil.example/a")
        ));
    }
}
