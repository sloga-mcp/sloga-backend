//! Begin Sign in with Apple login
//! GET /auth/oauth/apple
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use nanoid::nanoid;
use redis_kiss::{get_connection, redis, AsyncCommands};
use revolt_config::config;
use revolt_result::{create_error, Result};
use rocket::response::Redirect;
use sha2::{Digest, Sha256};

/// # Apple OAuth
///
/// Redirects the browser to Apple's consent screen using the
/// authorization-code flow with PKCE.
#[openapi(skip)]
#[get("/apple")]
pub async fn apple_authorise() -> Result<Redirect> {
    let config = config().await;
    let apple = &config.api.oauth.apple;

    if !apple.enabled || apple.client_id.is_empty() {
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
            super::state_key("apple", &state),
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

    let mut url = url::Url::parse("https://appleid.apple.com/auth/authorize")
        .expect("valid authorisation endpoint");
    url.query_pairs_mut()
        .append_pair("client_id", &apple.client_id)
        .append_pair("redirect_uri", &redirect_uri(apple, &config.hosts.api))
        .append_pair("response_type", "code")
        .append_pair("scope", "email")
        // Apple requires form_post whenever scopes are requested, so the
        // callback below is a POST rather than a GET
        .append_pair("response_mode", "form_post")
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");

    Ok(Redirect::to(url.to_string()))
}

/// Resolve the redirect URI, defaulting to the public API host
pub fn redirect_uri(apple: &revolt_config::ApiOauthApple, api_host: &str) -> String {
    if apple.redirect_uri.is_empty() {
        format!("{}/auth/oauth/apple/callback", api_host)
    } else {
        apple.redirect_uri.clone()
    }
}
