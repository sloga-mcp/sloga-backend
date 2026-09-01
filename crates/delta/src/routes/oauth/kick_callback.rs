//! Kick channel-link callback
//! GET /auth/oauth/kick/callback
//!
//! Exchanges the code (PKCE — Kick's OAuth 2.1 requires it even for
//! confidential clients), fetches the channel identity, then immediately
//! revokes the one-shot user token — live checks use an app token, so no
//! Kick user token is ever stored. Persists NOTHING: identity is parked
//! as a one-time handoff completed by the authed
//! `POST /users/@me/connections/complete` (see `super::link` for why).

use revolt_config::config;
use rocket::response::Redirect;

use super::link;

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(serde::Deserialize)]
struct ChannelsResponse {
    data: Vec<Channel>,
}

#[derive(serde::Deserialize)]
struct Channel {
    broadcaster_user_id: u64,
    slug: String,
}

#[derive(serde::Deserialize)]
struct UsersResponse {
    data: Vec<KickUser>,
}

#[derive(serde::Deserialize)]
struct KickUser {
    name: String,
}

/// # Kick Link Callback
#[openapi(skip)]
#[get("/kick/callback?<code>&<state>&<error>")]
pub async fn kick_callback(
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
    let kick = &config.api.oauth.kick;

    if !kick.enabled {
        return Err("disabled");
    }

    if error.is_some() {
        return Err("cancelled");
    }

    let (code, state) = match (code, state) {
        (Some(code), Some(state)) => (code, state),
        _ => return Err("invalid_request"),
    };

    let link_state = link::consume_link_state("kick", &state)
        .await
        .ok_or("invalid_state")?;
    let verifier = link_state.verifier.as_deref().ok_or("invalid_state")?;

    // Exchange the authorisation code for a one-shot user token
    let response = reqwest::Client::new()
        .post("https://id.kick.com/oauth/token")
        .form(&[
            ("client_id", kick.client_id.as_str()),
            ("client_secret", kick.client_secret.as_str()),
            ("code", code.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", verifier),
            (
                "redirect_uri",
                &link::kick_redirect_uri(kick, &config.hosts.api),
            ),
        ])
        .send()
        .await
        .map_err(|_| "exchange_failed")?;

    if !response.status().is_success() {
        return Err("exchange_failed");
    }

    let tokens: TokenResponse = response.json().await.map_err(|_| "exchange_failed")?;

    // Fetch the channel behind the token (no params = the authed user's
    // own channel) — this is where the poller's broadcaster id comes from
    let response = reqwest::Client::new()
        .get("https://api.kick.com/public/v1/channels")
        .bearer_auth(&tokens.access_token)
        .send()
        .await
        .map_err(|_| "identity_failed")?;

    if !response.status().is_success() {
        return Err("identity_failed");
    }

    let channels: ChannelsResponse = response.json().await.map_err(|_| "identity_failed")?;
    let channel = channels.data.into_iter().next().ok_or("identity_failed")?;

    // The channels payload only carries the slug; the display name lives
    // on the users endpoint. Best-effort — fall back to the slug.
    let display_name = match reqwest::Client::new()
        .get("https://api.kick.com/public/v1/users")
        .bearer_auth(&tokens.access_token)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => response
            .json::<UsersResponse>()
            .await
            .ok()
            .and_then(|users| users.data.into_iter().next())
            .map(|user| user.name)
            .unwrap_or_else(|| channel.slug.clone()),
        _ => channel.slug.clone(),
    };

    // One-shot token served its purpose — revoke it (best-effort) so
    // nothing usable ever leaves this request's scope
    let _ = reqwest::Client::new()
        .post("https://id.kick.com/oauth/revoke")
        .query(&[
            ("token", tokens.access_token.as_str()),
            ("token_hint_type", "access_token"),
        ])
        .send()
        .await;

    let handoff = link::store_link_handoff(
        "kick",
        &link::LinkHandoff {
            user_id: link_state.user_id,
            platform: "kick".to_string(),
            channel_id: channel.broadcaster_user_id.to_string(),
            handle: channel.slug,
            display_name,
            refresh_token: None,
            access_token: None,
            expires_in: None,
        },
    )
    .await
    .ok_or("internal")?;

    Ok(link::settings_complete_redirect("kick", &handoff).await)
}

#[cfg(test)]
mod tests {
    use crate::rocket;
    use crate::util::test::TestHarness;
    use rocket::http::Status;

    #[test]
    fn callback_redirects_with_error_when_disabled() {
        crate::util::test::rt().block_on(callback_redirects_with_error_when_disabled_case())
    }

    async fn callback_redirects_with_error_when_disabled_case() {
        let harness = TestHarness::new().await;

        let res = harness
            .client
            .get("/auth/oauth/kick/callback?code=x&state=y")
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::SeeOther);
        let location = res.headers().get_one("Location").unwrap();
        assert!(location.contains("error=disabled"));
    }
}
