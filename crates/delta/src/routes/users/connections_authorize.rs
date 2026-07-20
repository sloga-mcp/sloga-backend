//! Begin linking a streaming channel (Twitch / YouTube)
//! POST /users/@me/connections/<platform>/authorize

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use nanoid::nanoid;
use revolt_config::config;
use revolt_database::User;
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use sha2::{Digest, Sha256};

use crate::routes::oauth::link;

/// # Begin Streaming-Channel Link
///
/// Returns the provider authorize URL for the client to navigate to.
/// State is bound to the session user; the flow is finalized by the
/// authed `complete` call, never by the provider callback itself.
#[openapi(tag = "User Information")]
#[post("/@me/connections/<platform>/authorize")]
pub async fn connections_authorize(
    user: User,
    platform: &str,
) -> Result<Json<v0::ResponseConnectionAuthorize>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let config = config().await;
    let state = nanoid!(32);

    let url = match platform {
        "twitch" => {
            let twitch = &config.api.oauth.twitch;
            if !twitch.enabled || twitch.client_id.is_empty() {
                return Err(create_error!(OperationFailed));
            }

            link::store_link_state(
                "twitch",
                &state,
                &link::LinkState {
                    user_id: user.id.clone(),
                    verifier: None,
                },
            )
            .await
            .ok_or_else(|| create_error!(InternalError))?;

            let mut url = url::Url::parse("https://id.twitch.tv/oauth2/authorize")
                .expect("valid authorisation endpoint");
            url.query_pairs_mut()
                .append_pair("client_id", &twitch.client_id)
                .append_pair(
                    "redirect_uri",
                    &link::twitch_redirect_uri(twitch, &config.hosts.api),
                )
                .append_pair("response_type", "code")
                // Identity only — no scopes; the one-shot token is revoked
                // right after the helix/users fetch
                .append_pair("scope", "")
                .append_pair("state", &state);
            url.to_string()
        }
        "youtube" => {
            let youtube = &config.api.oauth.youtube;
            if !youtube.enabled || youtube.client_id.is_empty() {
                return Err(create_error!(OperationFailed));
            }

            let verifier = nanoid!(64);
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

            link::store_link_state(
                "youtube",
                &state,
                &link::LinkState {
                    user_id: user.id.clone(),
                    verifier: Some(verifier),
                },
            )
            .await
            .ok_or_else(|| create_error!(InternalError))?;

            let mut url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
                .expect("valid authorisation endpoint");
            url.query_pairs_mut()
                .append_pair("client_id", &youtube.client_id)
                .append_pair(
                    "redirect_uri",
                    &link::youtube_redirect_uri(youtube, &config.hosts.api),
                )
                .append_pair("response_type", "code")
                .append_pair("scope", "https://www.googleapis.com/auth/youtube.readonly")
                .append_pair("state", &state)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256")
                // offline + consent force a refresh token so the live
                // poller can use the cheap liveBroadcasts.list call
                .append_pair("access_type", "offline")
                .append_pair("prompt", "consent");
            url.to_string()
        }
        _ => return Err(create_error!(InvalidOperation)),
    };

    Ok(Json(v0::ResponseConnectionAuthorize { url }))
}

#[cfg(test)]
mod tests {
    use crate::rocket;
    use crate::util::test::TestHarness;
    use revolt_result::{Error, ErrorType};
    use rocket::http::Status;

    #[rocket::async_test]
    async fn fail_authorize_when_disabled() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        // Config defaults (and Revolt.test-overrides.toml) ship with both
        // providers disabled
        for platform in ["twitch", "youtube"] {
            let res = TestHarness::with_session(
                session.clone(),
                harness
                    .client
                    .post(format!("/users/@me/connections/{}/authorize", platform)),
            )
            .await;
            assert_eq!(res.status(), Status::InternalServerError);
        }
    }

    #[rocket::async_test]
    async fn fail_authorize_unknown_platform() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let res = TestHarness::with_session(
            session,
            harness
                .client
                .post("/users/@me/connections/kick/authorize"),
        )
        .await;

        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidOperation,
        ));
    }
}
