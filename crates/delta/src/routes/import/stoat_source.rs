//! Stoat as an import source: turn what the user pasted into something safe
//! to put in an outbound URL, and verify ownership against the live Stoat
//! API before a job is queued.
//!
//! Verification is at most two upstream calls (Stoat's `servers` bucket is
//! 5 requests / 10 s per bot and server): resolve the invite (public, no
//! token), then fetch the server as the operator bot and look for the
//! requester's challenge code in its description. Each call first spends
//! from the shared outbound budgets (`upstream_throttle`). crond owns the
//! full read client; this one only verifies.
//!
//! Failures are logged at `warn` by call, status code and error kind only:
//! never the URL (it carries what the user pasted), the token or a body.

use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::header::HeaderValue;
use reqwest::StatusCode;
use revolt_config::ApiImportBotSource;
use revolt_database::util::import_challenge::find_accepted_code;
use revolt_result::{create_error, Result};
use serde::de::DeserializeOwned;
use serde::Deserialize;

use super::upstream_throttle::{UpstreamTarget, UpstreamThrottle};

/// Challenge source tag for Stoat. A code minted for another source never
/// verifies here.
pub const SOURCE_TAG: &str = "stoat";

/// Longest invite code or id accepted. Everything that reaches an outbound
/// URL is `[A-Za-z0-9]{1,TOKEN_MAX}`.
const TOKEN_MAX: usize = 32;

/// A Stoat id is a ULID: 26 characters of Crockford base32
const ULID_LEN: usize = 26;
const ULID_ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Link forms that carry an invite code, matched case-insensitively after the
/// scheme is dropped. Self-hosted instances are out of scope.
const INVITE_PREFIXES: [&str; 2] = ["stoat.chat/invite/", "rvlt.gg/"];

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest upstream body read. An invite or server object is a few KiB;
/// a description is capped far below this upstream.
const MAX_BODY_BYTES: usize = 1024 * 1024;
const USER_AGENT: &str = concat!(
    "SlogaImport/",
    env!("CARGO_PKG_VERSION"),
    " (+https://sloga.gg)"
);

/// What the user pasted, reduced to one whitelisted token
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoatSource {
    /// An invite code, resolved to its server with one public call
    Invite(String),
    /// A server id (ULID), fetched directly
    ServerId(String),
}

/// Parse a Stoat invite link, bare invite code, or server id.
///
/// Accepts `https://stoat.chat/invite/<code>`, `stoat.chat/invite/<code>`,
/// `https://rvlt.gg/<code>`, `rvlt.gg/<code>`, a bare invite code, and a raw
/// 26-character ULID. Surrounding whitespace and one trailing `/` are
/// ignored. Anything else (another host, a query or fragment, extra path
/// segments, any character outside `[A-Za-z0-9]`) is refused outright rather
/// than reduced to a segment: the result goes straight into an outbound URL.
///
/// A bare token that is a 26-character ULID is a server id (uppercased, the
/// canonical form Stoat stores); any other bare token is an invite code. A
/// token taken from an invite link is always an invite code.
pub fn parse_stoat_source(input: &str) -> Option<StoatSource> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (rest, had_scheme) = match strip_prefix_ignore_case(trimmed, "https://")
        .or_else(|| strip_prefix_ignore_case(trimmed, "http://"))
    {
        Some(rest) => (rest, true),
        None => (trimmed, false),
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);

    let (token, from_link) = match INVITE_PREFIXES
        .iter()
        .find_map(|prefix| strip_prefix_ignore_case(rest, prefix))
    {
        Some(token) => (token, true),
        // A URL on any other host is not a Stoat source
        None if had_scheme => return None,
        None => (rest, false),
    };

    if !is_safe_token(token) {
        return None;
    }

    if !from_link && is_ulid(token) {
        Some(StoatSource::ServerId(token.to_ascii_uppercase()))
    } else {
        Some(StoatSource::Invite(token.to_string()))
    }
}

fn strip_prefix_ignore_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

/// The whole outbound-URL safety property: one path segment of ASCII
/// alphanumerics, nothing that can add a segment, host, query or escape
fn is_safe_token(token: &str) -> bool {
    (1..=TOKEN_MAX).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn is_ulid(token: &str) -> bool {
    token.len() == ULID_LEN
        && token
            .bytes()
            .all(|b| ULID_ALPHABET.as_bytes().contains(&b.to_ascii_uppercase()))
}

/// `GET /invites/<code>`, read permissively: only the type and server id
#[derive(Deserialize)]
struct InviteProbe {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    server_id: Option<String>,
}

/// `GET /servers/<id>`, read permissively: only the id and description
#[derive(Deserialize)]
struct ServerProbe {
    #[serde(rename = "_id")]
    id: String,
    #[serde(default)]
    description: Option<String>,
}

/// The source after verification: what the job is created with
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStoatSource {
    pub server_id: String,
    /// The accepted code found in the description (today's or yesterday's)
    pub challenge_code: String,
}

/// Whether `api_url` is an absolute `https://` URL with a host. A source
/// whose API URL is anything else is not ready: the production client
/// refuses plain HTTP, so it could never verify.
pub fn api_url_is_https(api_url: &str) -> bool {
    url::Url::parse(api_url)
        .map(|url| url.scheme() == "https" && url.host_str().is_some_and(|host| !host.is_empty()))
        .unwrap_or(false)
}

/// Minimal Stoat API client for verification.
///
/// The base URL comes only from operator config. Redirects are never
/// followed (the client carries the bot token), and every failure maps to a
/// fixed error before it can carry request detail. No `Debug`: the token
/// must not reach a log line.
pub struct StoatApi {
    client: reqwest::Client,
    api_url: String,
    bot_token: String,
}

/// How the client reaches its upstream
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// HTTPS only, system proxy settings honored
    Production,
    /// Plain HTTP to a loopback fake, never through a proxy
    #[cfg(test)]
    LoopbackTest,
}

impl Transport {
    /// Whether this transport can reach `api_url` at all. Production is
    /// exactly [`api_url_is_https`], the same test `GET /` and the challenge
    /// route apply through `ImportSource::ready`.
    pub fn accepts_api_url(self, api_url: &str) -> bool {
        match self {
            Transport::Production => api_url_is_https(api_url),
            #[cfg(test)]
            Transport::LoopbackTest => api_url.starts_with("http://127.0.0.1:"),
        }
    }
}

/// A transport error by kind. `reqwest::Error`'s `Display` includes the
/// URL, which carries what the user pasted, so it is never logged.
fn error_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_redirect() {
        "redirect"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else if error.is_request() {
        "request"
    } else if error.is_builder() {
        "builder"
    } else {
        "other"
    }
}

/// Read a JSON body of at most [`MAX_BODY_BYTES`]: refused up front when the
/// declared length is over, and while reading when the bytes are (chunked
/// or undeclared bodies). Every failure is `ImportUpstreamUnavailable`.
async fn read_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    call: &'static str,
) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        log::warn!("stoat import: {call}: declared body over {MAX_BODY_BYTES} bytes; refused");
        return Err(create_error!(ImportUpstreamUnavailable));
    }

    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > MAX_BODY_BYTES {
                    log::warn!("stoat import: {call}: body over {MAX_BODY_BYTES} bytes; refused");
                    return Err(create_error!(ImportUpstreamUnavailable));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(error) => {
                log::warn!(
                    "stoat import: {call}: reading the body failed ({})",
                    error_kind(&error)
                );
                return Err(create_error!(ImportUpstreamUnavailable));
            }
        }
    }

    serde_json::from_slice(&body).map_err(|_| {
        log::warn!("stoat import: {call}: body is not the expected JSON");
        create_error!(ImportUpstreamUnavailable)
    })
}

impl StoatApi {
    /// Client for `config` (`[api.import.stoat]`) over `transport`. Under
    /// `Production` an `http://` `api_url` is refused at request time too.
    pub fn connect(config: &ApiImportBotSource, transport: Transport) -> Result<StoatApi> {
        let builder = reqwest::Client::builder()
            .timeout(UPSTREAM_TIMEOUT)
            .connect_timeout(UPSTREAM_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(USER_AGENT);

        let builder = match transport {
            Transport::Production => builder.https_only(true),
            #[cfg(test)]
            Transport::LoopbackTest => builder.no_proxy(),
        };

        let client = builder.build().map_err(|error| {
            log::warn!(
                "stoat import: building the client failed ({})",
                error_kind(&error)
            );
            create_error!(ImportUpstreamUnavailable)
        })?;

        Ok(StoatApi {
            client,
            api_url: config.api_url.trim_end_matches('/').to_string(),
            bot_token: config.bot_token.clone(),
        })
    }

    /// Resolve an invite to its server id. Public route, sent without the
    /// bot token.
    async fn resolve_invite(&self, code: &str) -> Result<String> {
        const CALL: &str = "invite lookup";
        let response = self
            .client
            .get(format!("{}/invites/{code}", self.api_url))
            .send()
            .await
            .map_err(|error| {
                log::warn!("stoat import: {CALL} failed ({})", error_kind(&error));
                create_error!(ImportUpstreamUnavailable)
            })?;

        match response.status() {
            status if status.is_success() => {}
            StatusCode::NOT_FOUND => return Err(create_error!(ImportSourceNotFound)),
            status => {
                log::warn!("stoat import: {CALL} answered {}", status.as_u16());
                return Err(create_error!(ImportUpstreamUnavailable));
            }
        }

        let invite: InviteProbe = read_json(response, CALL).await?;

        // A group invite names no server
        if invite.kind.as_deref() != Some("Server") {
            return Err(create_error!(ImportSourceNotFound));
        }

        // The id goes into the next URL, so it gets the same whitelist as
        // user input even though it came from the configured upstream
        match invite.server_id {
            Some(id) if is_safe_token(&id) => Ok(id),
            _ => {
                log::warn!("stoat import: {CALL} returned an unusable server id");
                Err(create_error!(ImportUpstreamUnavailable))
            }
        }
    }

    /// Fetch a server as the operator bot
    async fn fetch_server(&self, server_id: &str) -> Result<ServerProbe> {
        const CALL: &str = "server fetch";
        let mut token = HeaderValue::from_str(&self.bot_token).map_err(|_| {
            log::warn!("stoat import: the configured bot token is not a valid header value");
            create_error!(ImportUpstreamUnavailable)
        })?;
        token.set_sensitive(true);

        let response = self
            .client
            .get(format!("{}/servers/{server_id}", self.api_url))
            .header("x-bot-token", token)
            .send()
            .await
            .map_err(|error| {
                log::warn!("stoat import: {CALL} failed ({})", error_kind(&error));
                create_error!(ImportUpstreamUnavailable)
            })?;

        match response.status() {
            status if status.is_success() => {}
            // Not a member, removed, or no such server: Stoat does not let
            // a non-member tell these apart, and neither do we. A 401 can
            // also mean the operator's token was revoked, which would
            // otherwise fail every import quietly, so it is logged.
            StatusCode::UNAUTHORIZED => {
                log::warn!("stoat import: {CALL} answered 401; check the bot token");
                return Err(create_error!(ImportBotNotInServer));
            }
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN => {
                return Err(create_error!(ImportBotNotInServer))
            }
            status => {
                log::warn!("stoat import: {CALL} answered {}", status.as_u16());
                return Err(create_error!(ImportUpstreamUnavailable));
            }
        }

        let server: ServerProbe = read_json(response, CALL).await?;

        if server.id != server_id {
            log::warn!("stoat import: {CALL} returned a different server");
            return Err(create_error!(ImportUpstreamUnavailable));
        }

        Ok(server)
    }
}

/// Resolve `source` and check the server description holds one of
/// `user_id`'s accepted Stoat codes (today's or yesterday's, UTC).
///
/// Errors: `ImportSourceNotFound` (unknown or group invite),
/// `ImportBotNotInServer` (the bot cannot see the server),
/// `ImportVerificationMissing` (no accepted code for this user and source),
/// `ImportUpstreamUnavailable` (`throttle` refused a call, 429, 5xx,
/// timeout, transport, redirect, an oversize or malformed response).
///
/// Every upstream call is preceded by a `throttle` check; a refused check
/// makes no call. The caller must have finished every local refusal first.
pub async fn verify_stoat_source(
    api: &StoatApi,
    throttle: &UpstreamThrottle,
    source: &StoatSource,
    challenge_secret: &[u8],
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<VerifiedStoatSource> {
    let server_id = match source {
        StoatSource::Invite(code) => {
            throttle
                .begin_verification(user_id, UpstreamTarget::Invite(code), now)
                .await?;
            let server_id = api.resolve_invite(code).await?;
            throttle
                .next_call(UpstreamTarget::Server(&server_id), now)
                .await?;
            server_id
        }
        StoatSource::ServerId(id) => {
            throttle
                .begin_verification(user_id, UpstreamTarget::Server(id), now)
                .await?;
            id.clone()
        }
    };

    let server = api.fetch_server(&server_id).await?;

    let challenge_code = find_accepted_code(
        server.description.as_deref().unwrap_or(""),
        challenge_secret,
        SOURCE_TAG,
        user_id,
        now,
    )
    .ok_or_else(|| create_error!(ImportVerificationMissing))?;

    Ok(VerifiedStoatSource {
        server_id,
        challenge_code,
    })
}

/// A scripted Stoat API on a loopback port, for tests that must not reach
/// the real one
#[cfg(test)]
pub(super) mod fake_upstream {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use revolt_config::ApiImportBotSource;
    use rocket::tokio::io::{AsyncReadExt, AsyncWriteExt};
    use rocket::tokio::net::TcpListener;

    pub const BOT_TOKEN: &str = "fake-bot-token";

    /// One request the fake received
    #[derive(Clone, Debug)]
    pub struct Seen {
        pub path: String,
        pub bot_token: Option<String>,
    }

    /// How a reply's body is framed on the wire
    #[derive(Clone, Copy)]
    pub enum Framing {
        /// `content-length` = the body, then close
        Length,
        /// `transfer-encoding: chunked`, no declared length, then close
        Chunked,
        /// `content-length: <n>` with only the body sent, then the
        /// connection held open: a reader that trusts the declared length
        /// waits for bytes that never come
        DeclaredButHeld(usize),
    }

    #[derive(Clone)]
    struct Reply {
        status: u16,
        body: String,
        location: Option<String>,
        framing: Framing,
    }

    pub struct FakeStoat {
        pub api_url: String,
        replies: HashMap<String, Reply>,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl FakeStoat {
        pub fn new() -> FakeStoat {
            FakeStoat {
                api_url: String::new(),
                replies: HashMap::new(),
                seen: Arc::new(Mutex::new(vec![])),
            }
        }

        /// Answer `path` with `status` and a JSON `body`
        pub fn reply(self, path: &str, status: u16, body: serde_json::Value) -> FakeStoat {
            self.reply_framed(path, status, body, Framing::Length)
        }

        /// Answer `path` with `status` and a JSON `body` framed as `framing`
        pub fn reply_framed(
            mut self,
            path: &str,
            status: u16,
            body: serde_json::Value,
            framing: Framing,
        ) -> FakeStoat {
            self.replies.insert(
                path.to_string(),
                Reply {
                    status,
                    body: body.to_string(),
                    location: None,
                    framing,
                },
            );
            self
        }

        /// Answer `path` with a 302 to `location`
        pub fn redirect(mut self, path: &str, location: &str) -> FakeStoat {
            self.replies.insert(
                path.to_string(),
                Reply {
                    status: 302,
                    body: String::new(),
                    location: Some(location.to_string()),
                    framing: Framing::Length,
                },
            );
            self
        }

        /// Start serving; unscripted paths get 404
        pub async fn start(mut self) -> FakeStoat {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            self.api_url = format!("http://{}", listener.local_addr().expect("addr"));

            let replies = self.replies.clone();
            let seen = self.seen.clone();
            rocket::tokio::spawn(async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    let replies = replies.clone();
                    let seen = seen.clone();
                    rocket::tokio::spawn(async move {
                        let mut head = Vec::new();
                        let mut chunk = [0u8; 1024];
                        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 65536 {
                            match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => head.extend_from_slice(&chunk[..n]),
                            }
                        }

                        let head = String::from_utf8_lossy(&head).to_string();
                        let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                        let bot_token = head.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.trim()
                                .eq_ignore_ascii_case("x-bot-token")
                                .then(|| value.trim().to_string())
                        });
                        seen.lock().unwrap().push(Seen {
                            path: path.clone(),
                            bot_token,
                        });

                        let reply = replies.get(&path).cloned().unwrap_or(Reply {
                            status: 404,
                            body: r#"{"type":"NotFound"}"#.to_string(),
                            location: None,
                            framing: Framing::Length,
                        });
                        let location = reply
                            .location
                            .map(|to| format!("location: {to}\r\n"))
                            .unwrap_or_default();
                        let head = format!(
                            "HTTP/1.1 {} Scripted\r\ncontent-type: application/json\r\n{location}connection: close\r\n",
                            reply.status
                        );
                        let response = match reply.framing {
                            Framing::Length => format!(
                                "{head}content-length: {}\r\n\r\n{}",
                                reply.body.len(),
                                reply.body
                            ),
                            Framing::DeclaredButHeld(declared) => {
                                format!("{head}content-length: {declared}\r\n\r\n{}", reply.body)
                            }
                            Framing::Chunked => {
                                let mut out = format!("{head}transfer-encoding: chunked\r\n\r\n");
                                for chunk in reply.body.as_bytes().chunks(64 * 1024) {
                                    out.push_str(&format!("{:x}\r\n", chunk.len()));
                                    out.push_str(std::str::from_utf8(chunk).expect("ascii body"));
                                    out.push_str("\r\n");
                                }
                                out.push_str("0\r\n\r\n");
                                out
                            }
                        };
                        let _ = socket.write_all(response.as_bytes()).await;
                        if let Framing::DeclaredButHeld(_) = reply.framing {
                            rocket::tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                        }
                        let _ = socket.shutdown().await;
                    });
                }
            });

            self
        }

        /// Requests received so far, in order
        pub fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }

        /// A ready-looking `[api.import.stoat]` pointing at this fake
        pub fn source_config(&self) -> ApiImportBotSource {
            ApiImportBotSource {
                enabled: true,
                api_url: self.api_url.clone(),
                app_url: "https://stoat.example".to_string(),
                cdn_url: "https://cdn.stoat.example".to_string(),
                bot_id: "01BOT000000000000000000000".to_string(),
                bot_token: BOT_TOKEN.to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake_upstream::{FakeStoat, Framing, BOT_TOKEN};
    use super::*;
    use chrono::TimeZone;
    use revolt_database::util::import_challenge::code;

    const SECRET: &[u8] = b"r1-test-challenge-secret";
    const USER: &str = "01J9ZQ4V6X7B8C9D0E1F2G3H4J";
    const OTHER_USER: &str = "01J9ZQ4V6X7B8C9D0E1F2G3H4K";
    const SERVER: &str = "01HSERVER00000000000000000";
    const INVITE: &str = "AbC123xy";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 15, 12, 0, 0).unwrap()
    }

    fn my_code() -> String {
        code(SECRET, SOURCE_TAG, USER, now().date_naive())
    }

    fn server_invite() -> serde_json::Value {
        json!({ "type": "Server", "code": INVITE, "server_id": SERVER, "server_name": "S" })
    }

    fn server_with(description: &str) -> serde_json::Value {
        json!({ "_id": SERVER, "name": "S", "description": description })
    }

    /// One verification, with outbound budgets of its own
    async fn verify(fake: &FakeStoat, source: StoatSource) -> Result<VerifiedStoatSource> {
        let api =
            StoatApi::connect(&fake.source_config(), Transport::LoopbackTest).expect("client");
        let throttle = UpstreamThrottle::isolated_for_tests();
        verify_stoat_source(&api, &throttle, &source, SECRET, USER, now()).await
    }

    fn invite() -> StoatSource {
        StoatSource::Invite(INVITE.to_string())
    }

    /// `ErrorType` has no `PartialEq`; a unit variant's `Debug` is its name
    fn assert_error(result: Result<VerifiedStoatSource>, expected: &str) {
        match result {
            Ok(verified) => panic!("expected {}, got Ok({:?})", expected, verified),
            Err(error) => assert_eq!(format!("{:?}", error.error_type), expected),
        }
    }

    // ---- parse_stoat_source ----

    #[test]
    fn parses_every_supported_form() {
        let invite = |code: &str| Some(StoatSource::Invite(code.to_string()));
        let ulid = "01HZY3K8Q4W5N6P7R8S9T0V1X2";
        let server_id = Some(StoatSource::ServerId(ulid.to_string()));
        let spaced_ulid = format!(" {ulid} ");
        let ulid_in_link = format!("https://stoat.chat/invite/{ulid}");

        for (input, expected) in [
            ("https://stoat.chat/invite/AbC123", invite("AbC123")),
            ("http://stoat.chat/invite/AbC123", invite("AbC123")),
            ("stoat.chat/invite/AbC123", invite("AbC123")),
            ("HTTPS://Stoat.Chat/Invite/AbC123", invite("AbC123")),
            ("https://rvlt.gg/AbC123", invite("AbC123")),
            ("rvlt.gg/AbC123", invite("AbC123")),
            ("AbC123", invite("AbC123")),
            ("  https://stoat.chat/invite/AbC123/  ", invite("AbC123")),
            ("\thttps://rvlt.gg/AbC123/\n", invite("AbC123")),
            (ulid, server_id.clone()),
            ("01hzy3k8q4w5n6p7r8s9t0v1x2", server_id.clone()),
            (spaced_ulid.as_str(), server_id.clone()),
            // In an invite link the path decides: always an invite code
            (ulid_in_link.as_str(), invite(ulid)),
        ] {
            assert_eq!(parse_stoat_source(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn ulid_lookalikes_are_invite_codes() {
        // 26 characters but `I`, `L`, `O`, `U` are outside Crockford base32
        let not_ulid = "01HZY3K8Q4W5N6P7R8S9T0V1XU";
        assert_eq!(
            parse_stoat_source(not_ulid),
            Some(StoatSource::Invite(not_ulid.to_string()))
        );
        // 25 and 27 characters
        assert!(matches!(
            parse_stoat_source("01HZY3K8Q4W5N6P7R8S9T0V1X"),
            Some(StoatSource::Invite(_))
        ));
        assert!(matches!(
            parse_stoat_source("01HZY3K8Q4W5N6P7R8S9T0V1X23"),
            Some(StoatSource::Invite(_))
        ));
    }

    #[test]
    fn refuses_everything_else() {
        let overlong = "a".repeat(TOKEN_MAX + 1);
        for input in [
            "",
            "   ",
            "https://stoat.chat/invite/",
            "https://stoat.chat/invite",
            "stoat.chat",
            "rvlt.gg",
            "https://rvlt.gg/",
            "https://evil.example/AbC123",
            "https://evil.example/stoat.chat/invite/AbC123",
            "https://stoat.chat.evil.example/invite/AbC123",
            "https://app.revolt.chat/invite/AbC123",
            "https://stoat.chat/server/01HZY3K8Q4W5N6P7R8S9T0V1X2",
            "ftp://stoat.chat/invite/AbC123",
            "https://stoat.chat/invite/AbC123?ref=x",
            "https://stoat.chat/invite/AbC123#frag",
            "https://stoat.chat/invite/AbC123//",
            "https://stoat.chat/invite/Ab/C123",
            "AbC123?x=1",
            overlong.as_str(),
        ] {
            assert_eq!(parse_stoat_source(input), None, "input {input:?}");
        }
    }

    /// Whatever comes back is interpolated into `{api_url}/invites/{}` or
    /// `{api_url}/servers/{}`, so the output alphabet and length are the
    /// security property. Every hostile input either parses to a token in
    /// that alphabet or is refused; the traversal and encoding forms are
    /// refused outright (not reduced to a segment).
    #[test]
    fn hostile_input_never_yields_an_unsafe_token() {
        let overlong = "A".repeat(TOKEN_MAX + 1);
        let hostile = [
            "../",
            "..",
            "../../admin",
            "AbC123/../x",
            "https://stoat.chat/invite/../../servers/x",
            "https://stoat.chat/invite/..%2F..%2Fadmin",
            "https://rvlt.gg/%2e%2e",
            "%2e%2e%2f",
            "%2E%2E",
            "Ab%20C",
            "Ab C123",
            "Ab\tC123",
            "Ab\nC123",
            "https://rvlt.gg/Ab C123",
            "AbC-123",
            "AbC_123",
            "Ab.C123",
            "Ab\\C123",
            "Ab;C",
            "Ab@C",
            "Ab:C",
            "Ab+C",
            "Abé123",
            "Ab／C",
            "Ab\u{0}C",
            overlong.as_str(),
        ];
        for input in hostile {
            assert_eq!(parse_stoat_source(input), None, "input {input:?}");
        }

        // Exhaustive over single-byte suffixes: any byte that is not ASCII
        // alphanumeric after a valid prefix makes the whole input refused
        for byte in 0u8..=127 {
            let ch = byte as char;
            for input in [
                format!("AbC{ch}123"),
                format!("https://stoat.chat/invite/AbC{ch}123"),
                format!("rvlt.gg/AbC{ch}123"),
            ] {
                let parsed = parse_stoat_source(&input);
                let token = match &parsed {
                    Some(StoatSource::Invite(t)) | Some(StoatSource::ServerId(t)) => Some(t),
                    None => None,
                };
                if ch.is_ascii_alphanumeric() {
                    assert!(token.is_some(), "input {:?} should parse", input);
                }
                if let Some(token) = token {
                    assert!(
                        is_safe_token(token),
                        "unsafe token {:?} from {:?}",
                        token,
                        input
                    );
                    assert!(
                        ch.is_ascii_alphanumeric(),
                        "{:?} parsed but carries {:?}",
                        input,
                        ch
                    );
                }
            }
        }
    }

    #[test]
    fn length_bound_is_inclusive() {
        let max = "a".repeat(TOKEN_MAX);
        assert_eq!(
            parse_stoat_source(&max),
            Some(StoatSource::Invite(max.clone()))
        );
        assert_eq!(parse_stoat_source(&format!("{max}a")), None);
    }

    // ---- verify_stoat_source against a fake upstream ----

    #[test]
    fn happy_path_via_invite() {
        crate::util::test::rt().block_on(async {
            let description = format!("Our server.\nVerify: {}\nRules below", my_code());
            let fake = FakeStoat::new()
                .reply(&format!("/invites/{INVITE}"), 200, server_invite())
                .reply(
                    &format!("/servers/{SERVER}"),
                    200,
                    server_with(&description),
                )
                .start()
                .await;

            let verified = verify(&fake, invite()).await.expect("verified");
            assert_eq!(
                verified,
                VerifiedStoatSource {
                    server_id: SERVER.to_string(),
                    challenge_code: my_code(),
                }
            );

            // Two calls; the token goes only to the server fetch
            let seen = fake.seen();
            assert_eq!(seen.len(), 2, "{seen:?}");
            assert_eq!(seen[0].path, format!("/invites/{INVITE}"));
            assert_eq!(seen[0].bot_token, None);
            assert_eq!(seen[1].path, format!("/servers/{SERVER}"));
            assert_eq!(seen[1].bot_token.as_deref(), Some(BOT_TOKEN));
        })
    }

    #[test]
    fn happy_path_via_server_id_is_one_call() {
        crate::util::test::rt().block_on(async {
            let fake = FakeStoat::new()
                .reply(&format!("/servers/{SERVER}"), 200, server_with(&my_code()))
                .start()
                .await;

            let verified = verify(&fake, StoatSource::ServerId(SERVER.to_string()))
                .await
                .expect("verified");
            assert_eq!(verified.server_id, SERVER);
            assert_eq!(verified.challenge_code, my_code());
            assert_eq!(fake.seen().len(), 1);
        })
    }

    #[test]
    fn yesterdays_code_is_accepted_and_stored_as_matched() {
        crate::util::test::rt().block_on(async {
            let yesterday = code(
                SECRET,
                SOURCE_TAG,
                USER,
                now().date_naive().pred_opt().unwrap(),
            );
            let fake = FakeStoat::new()
                .reply(&format!("/servers/{SERVER}"), 200, server_with(&yesterday))
                .start()
                .await;

            let verified = verify(&fake, StoatSource::ServerId(SERVER.to_string()))
                .await
                .expect("verified");
            assert_eq!(verified.challenge_code, yesterday);
        })
    }

    #[test]
    fn bot_not_in_server() {
        crate::util::test::rt().block_on(async {
            for status in [404, 403, 401] {
                let fake = FakeStoat::new()
                    .reply(&format!("/invites/{INVITE}"), 200, server_invite())
                    .reply(
                        &format!("/servers/{SERVER}"),
                        status,
                        json!({ "type": "NotFound" }),
                    )
                    .start()
                    .await;
                assert_error(verify(&fake, invite()).await, "ImportBotNotInServer");
            }
        })
    }

    #[test]
    fn unknown_and_group_invites_are_not_found() {
        crate::util::test::rt().block_on(async {
            // Unscripted path: the fake answers 404
            let fake = FakeStoat::new().start().await;
            assert_error(verify(&fake, invite()).await, "ImportSourceNotFound");
            assert_eq!(fake.seen().len(), 1, "no server fetch after a 404 invite");

            let fake = FakeStoat::new()
                .reply(
                    &format!("/invites/{INVITE}"),
                    200,
                    json!({ "type": "Group", "code": INVITE, "channel_id": "01CHANNEL" }),
                )
                .start()
                .await;
            assert_error(verify(&fake, invite()).await, "ImportSourceNotFound");
            assert_eq!(fake.seen().len(), 1, "no server fetch after a group invite");
        })
    }

    #[test]
    fn description_without_a_code_is_verification_missing() {
        crate::util::test::rt().block_on(async {
            for server in [
                json!({ "_id": SERVER, "name": "S" }),
                server_with(""),
                server_with("A friendly server, no code here"),
            ] {
                let fake = FakeStoat::new()
                    .reply(&format!("/servers/{SERVER}"), 200, server)
                    .start()
                    .await;
                assert_error(
                    verify(&fake, StoatSource::ServerId(SERVER.to_string())).await,
                    "ImportVerificationMissing",
                );
            }
        })
    }

    #[test]
    fn another_users_code_is_verification_missing() {
        crate::util::test::rt().block_on(async {
            let theirs = code(SECRET, SOURCE_TAG, OTHER_USER, now().date_naive());
            let fake = FakeStoat::new()
                .reply(
                    &format!("/servers/{SERVER}"),
                    200,
                    server_with(&format!("verify {theirs}")),
                )
                .start()
                .await;
            assert_error(
                verify(&fake, StoatSource::ServerId(SERVER.to_string())).await,
                "ImportVerificationMissing",
            );
        })
    }

    #[test]
    fn another_source_tags_code_is_verification_missing() {
        crate::util::test::rt().block_on(async {
            for tag in ["fluxer", "matrix"] {
                let other = code(SECRET, tag, USER, now().date_naive());
                let fake = FakeStoat::new()
                    .reply(
                        &format!("/servers/{SERVER}"),
                        200,
                        server_with(&format!("verify {other}")),
                    )
                    .start()
                    .await;
                assert_error(
                    verify(&fake, StoatSource::ServerId(SERVER.to_string())).await,
                    "ImportVerificationMissing",
                );
            }
        })
    }

    #[test]
    fn rate_limits_and_server_errors_are_upstream_unavailable() {
        crate::util::test::rt().block_on(async {
            for status in [429, 500, 502, 503] {
                // On the server fetch
                let fake = FakeStoat::new()
                    .reply(&format!("/invites/{INVITE}"), 200, server_invite())
                    .reply(
                        &format!("/servers/{SERVER}"),
                        status,
                        json!({ "type": "RateLimited" }),
                    )
                    .start()
                    .await;
                assert_error(verify(&fake, invite()).await, "ImportUpstreamUnavailable");

                // On the invite
                let fake = FakeStoat::new()
                    .reply(&format!("/invites/{INVITE}"), status, json!({}))
                    .start()
                    .await;
                assert_error(verify(&fake, invite()).await, "ImportUpstreamUnavailable");
            }
        })
    }

    #[test]
    fn redirects_are_not_followed() {
        crate::util::test::rt().block_on(async {
            // The redirect target would verify; following it is the bug
            let fake = FakeStoat::new()
                .redirect(&format!("/servers/{SERVER}"), "/servers/elsewhere")
                .reply("/servers/elsewhere", 200, server_with(&my_code()))
                .start()
                .await;
            assert_error(
                verify(&fake, StoatSource::ServerId(SERVER.to_string())).await,
                "ImportUpstreamUnavailable",
            );
            assert_eq!(fake.seen().len(), 1, "{:?}", fake.seen());
        })
    }

    #[test]
    fn malformed_upstream_answers_are_upstream_unavailable() {
        crate::util::test::rt().block_on(async {
            // An invite whose server id would escape the URL path
            let fake = FakeStoat::new()
                .reply(
                    &format!("/invites/{INVITE}"),
                    200,
                    json!({ "type": "Server", "server_id": "../users/@me" }),
                )
                .start()
                .await;
            assert_error(verify(&fake, invite()).await, "ImportUpstreamUnavailable");
            assert_eq!(fake.seen().len(), 1, "unsafe id must not be fetched");

            // A server body for a different id
            let fake = FakeStoat::new()
                .reply(
                    &format!("/servers/{SERVER}"),
                    200,
                    json!({ "_id": "01HOTHER0000000000000000000", "description": my_code() }),
                )
                .start()
                .await;
            assert_error(
                verify(&fake, StoatSource::ServerId(SERVER.to_string())).await,
                "ImportUpstreamUnavailable",
            );

            // Not JSON
            let fake = FakeStoat::new()
                .reply(&format!("/servers/{SERVER}"), 200, json!("not a server"))
                .start()
                .await;
            assert_error(
                verify(&fake, StoatSource::ServerId(SERVER.to_string())).await,
                "ImportUpstreamUnavailable",
            );
        })
    }

    #[test]
    fn transport_failure_is_upstream_unavailable() {
        crate::util::test::rt().block_on(async {
            // A port nothing listens on
            let listener = rocket::tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            drop(listener);

            let mut config = FakeStoat::new().source_config();
            config.api_url = format!("http://{address}");
            let api = StoatApi::connect(&config, Transport::LoopbackTest).expect("client");
            assert_error(
                verify_stoat_source(
                    &api,
                    &UpstreamThrottle::isolated_for_tests(),
                    &invite(),
                    SECRET,
                    USER,
                    now(),
                )
                .await,
                "ImportUpstreamUnavailable",
            );
        })
    }

    #[test]
    fn production_client_refuses_plain_http() {
        crate::util::test::rt().block_on(async {
            let fake = FakeStoat::new()
                .reply(&format!("/servers/{SERVER}"), 200, server_with(&my_code()))
                .start()
                .await;
            let api =
                StoatApi::connect(&fake.source_config(), Transport::Production).expect("client");
            assert_error(
                verify_stoat_source(
                    &api,
                    &UpstreamThrottle::isolated_for_tests(),
                    &StoatSource::ServerId(SERVER.to_string()),
                    SECRET,
                    USER,
                    now(),
                )
                .await,
                "ImportUpstreamUnavailable",
            );
            assert!(fake.seen().is_empty(), "{:?}", fake.seen());
        })
    }

    #[test]
    fn api_url_must_be_https_with_a_host() {
        for url in [
            "https://api.stoat.chat",
            "https://api.stoat.chat/",
            "HTTPS://api.stoat.chat",
            "https://127.0.0.1:8443/api",
        ] {
            assert!(api_url_is_https(url), "{}", url);
            assert!(Transport::Production.accepts_api_url(url), "{}", url);
        }
        for url in [
            "http://api.stoat.chat",
            "http://127.0.0.1:1234",
            "ftp://api.stoat.chat",
            "api.stoat.chat",
            "//api.stoat.chat",
            "https://",
            "",
        ] {
            assert!(!api_url_is_https(url), "{}", url);
            assert!(!Transport::Production.accepts_api_url(url), "{}", url);
        }
    }

    // ---- outbound budgets ----

    /// With one `throttle` for every call, as one delta process has
    async fn verify_as(
        fake: &FakeStoat,
        throttle: &UpstreamThrottle,
        user_id: &str,
        source: StoatSource,
    ) -> Result<VerifiedStoatSource> {
        let api =
            StoatApi::connect(&fake.source_config(), Transport::LoopbackTest).expect("client");
        verify_stoat_source(&api, throttle, &source, SECRET, user_id, now()).await
    }

    #[test]
    fn a_throttled_verification_makes_no_upstream_call() {
        crate::util::test::rt().block_on(async {
            let fake = FakeStoat::new()
                .reply(&format!("/invites/{INVITE}"), 200, server_invite())
                .reply(&format!("/servers/{SERVER}"), 200, server_with("no code"))
                .start()
                .await;
            let throttle = UpstreamThrottle::isolated_for_tests();

            // Per user: the second attempt within 30 s, whatever its target
            assert_error(
                verify_as(&fake, &throttle, USER, invite()).await,
                "ImportVerificationMissing",
            );
            assert_eq!(fake.seen().len(), 2);
            assert_error(
                verify_as(
                    &fake,
                    &throttle,
                    USER,
                    StoatSource::ServerId("01HOTHER000000000000000000".to_string()),
                )
                .await,
                "ImportUpstreamUnavailable",
            );
            assert_eq!(fake.seen().len(), 2, "{:?}", fake.seen());

            // Per target: the invite code is spent once more by another
            // user, then a third user is refused before the invite lookup
            assert_error(
                verify_as(&fake, &throttle, OTHER_USER, invite()).await,
                "ImportVerificationMissing",
            );
            assert_eq!(fake.seen().len(), 4);
            assert_error(
                verify_as(&fake, &throttle, "01J9ZQ4V6X7B8C9D0E1F2G3H4M", invite()).await,
                "ImportUpstreamUnavailable",
            );
            // ...and the resolved server id is spent too: a fourth user
            // naming it directly is refused
            assert_error(
                verify_as(
                    &fake,
                    &throttle,
                    "01J9ZQ4V6X7B8C9D0E1F2G3H4N",
                    StoatSource::ServerId(SERVER.to_string()),
                )
                .await,
                "ImportUpstreamUnavailable",
            );
            assert_eq!(fake.seen().len(), 4, "{:?}", fake.seen());
        })
    }

    // ---- response size ----

    /// A server body padded to `size` bytes whose description carries the
    /// requester's code: it verifies unless refused for its size
    fn padded_server(size: usize) -> serde_json::Value {
        let base = server_with(&my_code()).to_string().len();
        json!({
            "_id": SERVER,
            "name": "S",
            "description": my_code(),
            "pad": "x".repeat(size - base - r#","pad":"""#.len()),
        })
    }

    #[test]
    fn padding_helper_hits_the_size() {
        for size in [MAX_BODY_BYTES, MAX_BODY_BYTES + 1] {
            assert_eq!(padded_server(size).to_string().len(), size);
        }
    }

    #[test]
    fn bodies_up_to_the_cap_are_read() {
        crate::util::test::rt().block_on(async {
            for framing in [Framing::Length, Framing::Chunked] {
                let fake = FakeStoat::new()
                    .reply_framed(
                        &format!("/servers/{SERVER}"),
                        200,
                        padded_server(MAX_BODY_BYTES),
                        framing,
                    )
                    .start()
                    .await;
                let verified = verify(&fake, StoatSource::ServerId(SERVER.to_string()))
                    .await
                    .expect("a body of exactly the cap verifies");
                assert_eq!(verified.challenge_code, my_code());
            }
        })
    }

    #[test]
    fn oversize_bodies_are_upstream_unavailable() {
        crate::util::test::rt().block_on(async {
            // Over by one byte, declared and undeclared (chunked: only the
            // running count can catch it)
            for framing in [Framing::Length, Framing::Chunked] {
                let fake = FakeStoat::new()
                    .reply_framed(
                        &format!("/servers/{SERVER}"),
                        200,
                        padded_server(MAX_BODY_BYTES + 1),
                        framing,
                    )
                    .start()
                    .await;
                assert_error(
                    verify(&fake, StoatSource::ServerId(SERVER.to_string())).await,
                    "ImportUpstreamUnavailable",
                );
            }

            // The invite lookup is capped as well
            let fake = FakeStoat::new()
                .reply_framed(
                    &format!("/invites/{INVITE}"),
                    200,
                    json!({
                        "type": "Server",
                        "server_id": SERVER,
                        "pad": "x".repeat(MAX_BODY_BYTES),
                    }),
                    Framing::Chunked,
                )
                .start()
                .await;
            assert_error(verify(&fake, invite()).await, "ImportUpstreamUnavailable");
            assert_eq!(
                fake.seen().len(),
                1,
                "no server fetch after an oversize invite"
            );
        })
    }

    /// An oversize declared length is refused from the header, before any
    /// of the body is awaited: the fake sends a small valid body and holds
    /// the connection, so a reader that waited would sit out the 15 s
    /// client timeout
    #[test]
    fn an_oversize_declared_length_is_refused_without_reading() {
        crate::util::test::rt().block_on(async {
            let fake = FakeStoat::new()
                .reply_framed(
                    &format!("/servers/{SERVER}"),
                    200,
                    server_with(&my_code()),
                    Framing::DeclaredButHeld(MAX_BODY_BYTES + 1),
                )
                .start()
                .await;
            let started = std::time::Instant::now();
            assert_error(
                verify(&fake, StoatSource::ServerId(SERVER.to_string())).await,
                "ImportUpstreamUnavailable",
            );
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "took {:?}",
                started.elapsed()
            );
        })
    }
}
