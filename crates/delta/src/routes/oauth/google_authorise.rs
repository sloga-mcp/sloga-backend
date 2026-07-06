//! Begin Google OAuth login
//! GET /auth/oauth/google
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use nanoid::nanoid;
use redis_kiss::{get_connection, redis, AsyncCommands};
use revolt_config::config;
use revolt_result::{create_error, Result};
use rocket::response::Redirect;
use sha2::{Digest, Sha256};

/// # Google OAuth
///
/// Redirects the browser to Google's consent screen using the
/// authorization-code flow with PKCE.
#[openapi(skip)]
#[get("/google")]
pub async fn google_authorise() -> Result<Redirect> {
    let config = config().await;
    let google = &config.api.oauth.google;

    if !google.enabled || google.client_id.is_empty() {
        return Err(create_error!(OperationFailed));
    }

    let state = nanoid!(32);
    let verifier = nanoid!(64);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    // Stash the PKCE verifier under the state parameter so the
    // callback can both validate state and complete the exchange.
    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let set: Option<String> = conn
        .set_options(
            super::state_key(&state),
            &verifier,
            redis::SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX)
                .with_expiration(redis::SetExpiry::EX(600)),
        )
        .await
        .map_err(|_| create_error!(InternalError))?;

    if set.is_none() {
        return Err(create_error!(InternalError));
    }

    let mut url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
        .expect("valid authorisation endpoint");
    url.query_pairs_mut()
        .append_pair("client_id", &google.client_id)
        .append_pair("redirect_uri", &redirect_uri(google, &config.hosts.api))
        .append_pair("response_type", "code")
        .append_pair("scope", "openid email")
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("prompt", "select_account");

    Ok(Redirect::to(url.to_string()))
}

/// Resolve the redirect URI, defaulting to the public API host
pub fn redirect_uri(google: &revolt_config::ApiOauthGoogle, api_host: &str) -> String {
    if google.redirect_uri.is_empty() {
        format!("{}/auth/oauth/google/callback", api_host)
    } else {
        google.redirect_uri.clone()
    }
}
