//! What every import source's verification client shares: the HTTP client
//! (fixed timeouts, no redirects, HTTPS only in production), the transport
//! tests use to reach a loopback fake instead, and a capped JSON reader.
//! Each source module adds its own URLs, headers and parsing.
//!
//! Failures are logged under the caller's source tag (`<source> import:`)
//! by call, status code and error kind only: never the URL (it carries what
//! the user pasted), a token or a body.

use std::time::Duration;

use revolt_result::{create_error, Result};
use serde::de::DeserializeOwned;

pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest upstream body read. An invite or server object is a few KiB;
/// a description is capped far below this upstream.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
pub const USER_AGENT: &str = concat!(
    "SlogaImport/",
    env!("CARGO_PKG_VERSION"),
    " (+https://sloga.gg)"
);

/// Whether `api_url` is an absolute `https://` URL with a host. A source
/// whose API URL is anything else is not ready: the production client
/// refuses plain HTTP, so it could never verify.
pub fn api_url_is_https(api_url: &str) -> bool {
    url::Url::parse(api_url)
        .map(|url| url.scheme() == "https" && url.host_str().is_some_and(|host| !host.is_empty()))
        .unwrap_or(false)
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

/// The client for one source over `transport`. Redirects are never followed
/// (the client may carry a bot token); under `Production` an `http://` URL is
/// refused at request time. `source` is the log prefix.
pub fn build_client(transport: Transport, source: &str) -> Result<reqwest::Client> {
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

    builder.build().map_err(|error| {
        log::warn!(
            "{source} import: building the client failed ({})",
            error_kind(&error)
        );
        create_error!(ImportUpstreamUnavailable)
    })
}

/// A transport error by kind. `reqwest::Error`'s `Display` includes the
/// URL, which carries what the user pasted, so it is never logged.
pub fn error_kind(error: &reqwest::Error) -> &'static str {
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
/// or undeclared bodies). Every failure is `ImportUpstreamUnavailable`,
/// logged as `<source> import: <call>: …`.
pub async fn read_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    source: &str,
    call: &str,
) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        log::warn!("{source} import: {call}: declared body over {MAX_BODY_BYTES} bytes; refused");
        return Err(create_error!(ImportUpstreamUnavailable));
    }

    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > MAX_BODY_BYTES {
                    log::warn!(
                        "{source} import: {call}: body over {MAX_BODY_BYTES} bytes; refused"
                    );
                    return Err(create_error!(ImportUpstreamUnavailable));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(error) => {
                log::warn!(
                    "{source} import: {call}: reading the body failed ({})",
                    error_kind(&error)
                );
                return Err(create_error!(ImportUpstreamUnavailable));
            }
        }
    }

    serde_json::from_slice(&body).map_err(|_| {
        log::warn!("{source} import: {call}: body is not the expected JSON");
        create_error!(ImportUpstreamUnavailable)
    })
}
