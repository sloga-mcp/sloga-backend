//! The one HTTP client game data uses
//!
//! Same SSRF posture as January's `CLIENT`: a resolver that refuses any
//! name resolving to an `ip_policy::is_forbidden` address, no redirects, no
//! proxy, 10 s total / 5 s connect timeouts. On top of that every request
//! must be `https` to an allowlisted host, and bodies are capped at 1 MiB.

use std::{net::SocketAddr, time::Duration};

use reqwest::{
    dns::{Addrs, Name, Resolve},
    header::{HeaderValue, CONTENT_TYPE},
    redirect, Client, Response, StatusCode,
};
use url::Url;

use crate::{ip_policy, GameData, GameDataError, Result};

/// The only hosts game data talks to
pub(crate) const ALLOWED_HOSTS: [&str; 5] = [
    "store.steampowered.com",
    "api.steampowered.com",
    "oauth.battle.net",
    "us.api.blizzard.com",
    "ddragon.leagueoflegends.com",
];

/// Largest upstream body read
pub(crate) const MAX_BODY_BYTES: usize = 1024 * 1024;

pub(crate) fn build_client() -> Client {
    Client::builder()
        .dns_resolver(VettingDnsResolver)
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .redirect(redirect::Policy::none())
        .no_proxy()
        .user_agent(concat!("Sloga-GameData/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("reqwest Client")
}

/// Resolver handing the connector only address lists where no address is
/// forbidden
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
/// and no address in it is forbidden (a mixed public + private answer is
/// refused, not filtered)
async fn resolve_vetted(host: &str) -> std::io::Result<Vec<SocketAddr>> {
    let mut lookup = host.to_string();
    if !lookup.contains(':') {
        lookup += ":0";
    }
    let addrs = tokio::net::lookup_host(&lookup).await?.collect();
    vet_addresses(addrs)
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

/// Parse `url` and refuse it unless it is `https` on the default port to
/// an allowlisted host, with no credentials in it
pub(crate) fn check_url(url: &str) -> Result<Url> {
    let parsed = Url::parse(url).map_err(|_| GameDataError::HostNotAllowed)?;
    let host_ok = parsed
        .host_str()
        .is_some_and(|host| ALLOWED_HOSTS.contains(&host));
    if parsed.scheme() != "https"
        || !host_ok
        || parsed.port().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(GameDataError::HostNotAllowed);
    }
    Ok(parsed)
}

fn upstream(error: reqwest::Error) -> GameDataError {
    // Without the URL: it can carry a user's search text
    GameDataError::Upstream(error.without_url().to_string())
}

/// Append `chunk` to `body`, refusing to grow past `MAX_BODY_BYTES`
pub(crate) fn push_capped(body: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
        return Err(GameDataError::Upstream("response body too large".into()));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

async fn read_capped(mut response: Response) -> Result<Vec<u8>> {
    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return Err(GameDataError::NotFound);
    }
    if !status.is_success() {
        return Err(GameDataError::Upstream(format!("status {}", status.as_u16())));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        return Err(GameDataError::Upstream("response body too large".into()));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(upstream)? {
        push_capped(&mut body, &chunk)?;
    }
    Ok(body)
}

impl GameData {
    /// GET an allowlisted URL, optionally with a bearer token
    pub(crate) async fn get_bytes(&self, url: &str, bearer: Option<&str>) -> Result<Vec<u8>> {
        let url = check_url(url)?;
        let mut request = self.client.get(url);
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        read_capped(request.send().await.map_err(upstream)?).await
    }

    /// POST a form body to an allowlisted URL with HTTP basic auth
    pub(crate) async fn post_form_basic(
        &self,
        url: &str,
        form: &'static str,
        user: &str,
        password: &str,
    ) -> Result<Vec<u8>> {
        let url = check_url(url)?;
        let request = self
            .client
            .post(url)
            .basic_auth(user, Some(password))
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .body(form);
        read_capped(request.send().await.map_err(upstream)?).await
    }
}

/// Parse a JSON body, mapping a parse failure to `Upstream`
pub(crate) fn parse_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|error| GameDataError::Upstream(format!("bad json: {error}")))
}
