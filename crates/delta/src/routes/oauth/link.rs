//! Shared plumbing for the streaming-channel LINK flow (Twitch / YouTube /
//! Kick).
//!
//! This is a *connect* flow, not a login flow: the initiating user is
//! already authenticated. Because session auth is a header (not a cookie)
//! the provider redirect cannot carry it, so the flow is split:
//!
//! 1. authed `POST /users/@me/connections/{platform}/authorize` stores a
//!    state (bound to the session user) and returns the provider URL;
//! 2. the unauthenticated provider callback exchanges the code, fetches
//!    the channel identity and parks it as a one-time HANDOFF — it never
//!    persists anything itself;
//! 3. authed `POST /users/@me/connections/complete` consumes the handoff
//!    and verifies `session user == state-bound user` before persisting.
//!
//! Step 3 is load-bearing for security: without it an attacker could
//! start the flow on their own account and social-engineer a victim into
//! completing the consent screen, linking the victim's channel (and
//! YouTube tokens) to the attacker's account.

use redis_kiss::{get_connection, redis, AsyncCommands};
use revolt_config::config;
use rocket::response::Redirect;

/// State parked between authorize and callback, bound to the initiator
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LinkState {
    pub user_id: String,
    /// PKCE verifier (YouTube and Kick; Twitch does not use PKCE)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
}

/// Fetched channel identity + tokens parked between callback and complete
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LinkHandoff {
    pub user_id: String,
    /// Platform key ("twitch" / "youtube" / "kick")
    pub platform: String,
    pub channel_id: String,
    pub handle: String,
    pub display_name: String,
    /// YouTube only — Twitch link stores no user tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    /// Access-token lifetime in seconds, from the provider
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
}

/// Provider slot in the state/handoff keyspace; suffixed so a future
/// *login* flow on the same provider can never collide with link state.
pub fn link_provider(platform: &str) -> String {
    format!("{}-link", platform)
}

/// Store link state under `oauth:{platform}-link:state:{state}` (NX EX 600)
pub async fn store_link_state(platform: &str, state: &str, value: &LinkState) -> Option<()> {
    let payload = serde_json::to_string(value).ok()?;
    let mut conn = get_connection().await.ok()?.into_inner();

    let set: Option<String> = conn
        .set_options(
            super::state_key(&link_provider(platform), state),
            payload,
            redis::SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX)
                .with_expiration(redis::SetExpiry::EX(600)),
        )
        .await
        .ok()?;

    set.map(|_| ())
}

/// Consume (GETDEL) link state; `None` means forged or expired
pub async fn consume_link_state(platform: &str, state: &str) -> Option<LinkState> {
    let mut conn = get_connection().await.ok()?.into_inner();

    let payload: Option<String> = redis::cmd("GETDEL")
        .arg(super::state_key(&link_provider(platform), state))
        .query_async(&mut conn)
        .await
        .ok()?;

    serde_json::from_str(&payload?).ok()
}

/// Park a fetched identity as a one-time handoff (NX EX 300); returns the code
pub async fn store_link_handoff(platform: &str, value: &LinkHandoff) -> Option<String> {
    let code = nanoid::nanoid!(43);
    let payload = serde_json::to_string(value).ok()?;
    let mut conn = get_connection().await.ok()?.into_inner();

    let set: Option<String> = conn
        .set_options(
            super::handoff_key(&link_provider(platform), &code),
            payload,
            redis::SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX)
                .with_expiration(redis::SetExpiry::EX(300)),
        )
        .await
        .ok()?;

    set.map(|_| code)
}

/// Consume (GETDEL) a link handoff
pub async fn consume_link_handoff(platform: &str, code: &str) -> Option<LinkHandoff> {
    let mut conn = get_connection().await.ok()?.into_inner();

    let payload: Option<String> = redis::cmd("GETDEL")
        .arg(super::handoff_key(&link_provider(platform), code))
        .query_async(&mut conn)
        .await
        .ok()?;

    serde_json::from_str(&payload?).ok()
}

/// Redirect back to the app with an error code. `/settings` is the
/// client's settings deep-link route (opens the settings modal); the
/// `stream_*` params are handled there.
pub async fn settings_error_redirect(code: &str) -> Redirect {
    let config = config().await;
    Redirect::to(format!(
        "{}/settings?stream_error={}",
        config.hosts.app, code
    ))
}

/// Redirect back to the app with the handoff code
pub async fn settings_complete_redirect(platform: &str, code: &str) -> Redirect {
    let config = config().await;
    Redirect::to(format!(
        "{}/settings?stream_complete={}&stream_platform={}",
        config.hosts.app, code, platform
    ))
}

/// Resolve the Twitch redirect URI, defaulting to the public API host
pub fn twitch_redirect_uri(
    twitch: &revolt_config::ApiOauthTwitch,
    api_host: &str,
) -> String {
    if twitch.redirect_uri.is_empty() {
        format!("{}/auth/oauth/twitch/callback", api_host)
    } else {
        twitch.redirect_uri.clone()
    }
}

/// Resolve the YouTube redirect URI, defaulting to the public API host
pub fn youtube_redirect_uri(
    youtube: &revolt_config::ApiOauthYoutube,
    api_host: &str,
) -> String {
    if youtube.redirect_uri.is_empty() {
        format!("{}/auth/oauth/youtube/callback", api_host)
    } else {
        youtube.redirect_uri.clone()
    }
}

/// Resolve the Kick redirect URI, defaulting to the public API host
pub fn kick_redirect_uri(kick: &revolt_config::ApiOauthKick, api_host: &str) -> String {
    if kick.redirect_uri.is_empty() {
        format!("{}/auth/oauth/kick/callback", api_host)
    } else {
        kick.redirect_uri.clone()
    }
}
