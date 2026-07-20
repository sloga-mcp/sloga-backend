//! Twitch channel-link callback
//! GET /auth/oauth/twitch/callback
//!
//! Exchanges the code, fetches the channel identity, then immediately
//! revokes the one-shot user token — live checks use an app token, so no
//! Twitch user token is ever stored. Persists NOTHING: identity is parked
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
struct HelixUsersResponse {
    data: Vec<HelixUser>,
}

#[derive(serde::Deserialize)]
struct HelixUser {
    id: String,
    login: String,
    display_name: String,
}

/// # Twitch Link Callback
#[openapi(skip)]
#[get("/twitch/callback?<code>&<state>&<error>")]
pub async fn twitch_callback(
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
    let twitch = &config.api.oauth.twitch;

    if !twitch.enabled {
        return Err("disabled");
    }

    if error.is_some() {
        return Err("cancelled");
    }

    let (code, state) = match (code, state) {
        (Some(code), Some(state)) => (code, state),
        _ => return Err("invalid_request"),
    };

    let link_state = link::consume_link_state("twitch", &state)
        .await
        .ok_or("invalid_state")?;

    // Exchange the authorisation code for a one-shot user token
    let response = reqwest::Client::new()
        .post("https://id.twitch.tv/oauth2/token")
        .form(&[
            ("client_id", twitch.client_id.as_str()),
            ("client_secret", twitch.client_secret.as_str()),
            ("code", code.as_str()),
            ("grant_type", "authorization_code"),
            (
                "redirect_uri",
                &link::twitch_redirect_uri(twitch, &config.hosts.api),
            ),
        ])
        .send()
        .await
        .map_err(|_| "exchange_failed")?;

    if !response.status().is_success() {
        return Err("exchange_failed");
    }

    let tokens: TokenResponse = response.json().await.map_err(|_| "exchange_failed")?;

    // Fetch the channel identity behind the token
    let response = reqwest::Client::new()
        .get("https://api.twitch.tv/helix/users")
        .bearer_auth(&tokens.access_token)
        .header("Client-Id", twitch.client_id.as_str())
        .send()
        .await
        .map_err(|_| "identity_failed")?;

    if !response.status().is_success() {
        return Err("identity_failed");
    }

    let users: HelixUsersResponse = response.json().await.map_err(|_| "identity_failed")?;
    let channel = users.data.into_iter().next().ok_or("identity_failed")?;

    // One-shot token served its purpose — revoke it (best-effort) so
    // nothing usable ever leaves this request's scope
    let _ = reqwest::Client::new()
        .post("https://id.twitch.tv/oauth2/revoke")
        .form(&[
            ("client_id", twitch.client_id.as_str()),
            ("token", tokens.access_token.as_str()),
        ])
        .send()
        .await;

    let handoff = link::store_link_handoff(
        "twitch",
        &link::LinkHandoff {
            user_id: link_state.user_id,
            platform: "twitch".to_string(),
            channel_id: channel.id,
            handle: channel.login,
            display_name: channel.display_name,
            refresh_token: None,
            access_token: None,
            expires_in: None,
        },
    )
    .await
    .ok_or("internal")?;

    Ok(link::settings_complete_redirect("twitch", &handoff).await)
}

#[cfg(test)]
mod tests {
    use crate::rocket;
    use crate::util::test::TestHarness;
    use rocket::http::Status;

    #[rocket::async_test]
    async fn callback_redirects_with_error_when_disabled() {
        let harness = TestHarness::new().await;

        let res = harness
            .client
            .get("/auth/oauth/twitch/callback?code=x&state=y")
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::SeeOther);
        let location = res.headers().get_one("Location").unwrap();
        assert!(location.contains("error=disabled"));
    }
}
