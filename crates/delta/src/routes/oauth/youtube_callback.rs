//! YouTube channel-link callback
//! GET /auth/oauth/youtube/callback
//!
//! Exchanges the code (PKCE), fetches the user's channel and parks
//! identity + tokens as a one-time handoff completed by the authed
//! `POST /users/@me/connections/complete` (see `super::link` for why the
//! callback itself must not persist). The refresh token is kept: live
//! checks use `liveBroadcasts.list` under the user's own credentials
//! (1 quota unit) instead of the 100-unit `search.list`.

use revolt_config::config;
use rocket::response::Redirect;

use super::link;

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(serde::Deserialize)]
struct ChannelsResponse {
    #[serde(default)]
    items: Vec<Channel>,
}

#[derive(serde::Deserialize)]
struct Channel {
    id: String,
    snippet: ChannelSnippet,
}

#[derive(serde::Deserialize)]
struct ChannelSnippet {
    title: String,
    #[serde(rename = "customUrl")]
    #[serde(default)]
    custom_url: Option<String>,
}

/// # YouTube Link Callback
#[openapi(skip)]
#[get("/youtube/callback?<code>&<state>&<error>")]
pub async fn youtube_callback(
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
) -> Redirect {
    match callback_inner(code, state, error).await {
        Ok(redirect) => redirect,
        Err(code) => link::settings_error_redirect(code).await,
    }
}

async fn callback_inner(
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
) -> std::result::Result<Redirect, &'static str> {
    let config = config().await;
    let youtube = &config.api.oauth.youtube;

    if !youtube.enabled {
        return Err("disabled");
    }

    if error.is_some() {
        return Err("cancelled");
    }

    let (code, state) = match (code, state) {
        (Some(code), Some(state)) => (code, state),
        _ => return Err("invalid_request"),
    };

    let link_state = link::consume_link_state("youtube", &state)
        .await
        .ok_or("invalid_state")?;
    let verifier = link_state.verifier.as_deref().ok_or("invalid_state")?;

    // Exchange the authorisation code for tokens
    let response = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code.as_str()),
            ("client_id", youtube.client_id.as_str()),
            ("client_secret", youtube.client_secret.as_str()),
            (
                "redirect_uri",
                &link::youtube_redirect_uri(youtube, &config.hosts.api),
            ),
            ("grant_type", "authorization_code"),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .map_err(|_| "exchange_failed")?;

    if !response.status().is_success() {
        return Err("exchange_failed");
    }

    let tokens: TokenResponse = response.json().await.map_err(|_| "exchange_failed")?;

    // The user's own channel; a Google account without a YouTube channel
    // returns zero items — surface that distinctly
    let response = reqwest::Client::new()
        .get("https://www.googleapis.com/youtube/v3/channels")
        .query(&[("part", "id,snippet"), ("mine", "true")])
        .bearer_auth(&tokens.access_token)
        .send()
        .await
        .map_err(|_| "identity_failed")?;

    if !response.status().is_success() {
        return Err("identity_failed");
    }

    let channels: ChannelsResponse = response.json().await.map_err(|_| "identity_failed")?;
    let channel = match channels.items.into_iter().next() {
        Some(channel) => channel,
        None => {
            // Nothing to link — revoke what we were granted (best-effort)
            if let Some(token) = tokens.refresh_token.as_ref() {
                let _ = reqwest::Client::new()
                    .post("https://oauth2.googleapis.com/revoke")
                    .form(&[("token", token.as_str())])
                    .send()
                    .await;
            }
            return Err("no_channel");
        }
    };

    // Handle drives the public URL: "@custom" when the channel has one,
    // otherwise the raw channel id (client renders /channel/{id})
    let handle = channel
        .snippet
        .custom_url
        .clone()
        .unwrap_or_else(|| channel.id.clone());

    let handoff = link::store_link_handoff(
        "youtube",
        &link::LinkHandoff {
            user_id: link_state.user_id,
            platform: "youtube".to_string(),
            channel_id: channel.id,
            handle,
            display_name: channel.snippet.title,
            refresh_token: tokens.refresh_token,
            access_token: Some(tokens.access_token),
            expires_in: tokens.expires_in,
        },
    )
    .await
    .ok_or("internal")?;

    Ok(link::settings_complete_redirect("youtube", &handoff).await)
}
