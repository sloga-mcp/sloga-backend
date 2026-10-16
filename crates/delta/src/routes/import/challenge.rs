//! Ownership-challenge code for importing from another platform.
//! GET /import/<source>/challenge
//!
//! The code is derived, not stored: an HMAC over the source, the caller and
//! the UTC day (`revolt_database::util::import_challenge`). Showing it to its
//! owner discloses nothing; it only proves anything once it appears on a
//! source server the caller manages.

use chrono::{DateTime, Utc};
use revolt_config::{config, ApiImport};
use revolt_database::util::import_challenge::code;
use revolt_database::User;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use serde::Serialize;

use super::source_server::ImportSource;

/// # Import Challenge
#[derive(Serialize, JsonSchema, Debug)]
pub struct ResponseImportChallenge {
    /// Today's code (UTC), e.g. `sloga-import-7K3QX2MB`. Place it on the
    /// source server as the source's instructions say; yesterday's code is
    /// still accepted shortly after midnight.
    pub code: String,
}

/// # Fetch Import Challenge
///
/// Returns your ownership-challenge code for importing from `source`.
/// Not found when the source is unknown, not available in this release, or
/// not configured on this instance.
#[openapi(tag = "Import")]
#[get("/<source>/challenge")]
pub async fn import_source_challenge(
    user: User,
    source: ImportSource,
) -> Result<Json<ResponseImportChallenge>> {
    let config = config().await;
    challenge_for(&user, source, &config.api.import, Utc::now())
        .map(|code| Json(ResponseImportChallenge { code }))
}

/// Any other `<source>` on the challenge route: a failed typed path
/// parameter forwards with 422, so this rank-2 catch-all answers 404 (see
/// `source_server::import_unknown_source_server`).
#[openapi(skip)]
#[get("/<_>/challenge", rank = 2)]
pub async fn import_unknown_source_challenge() -> Result<()> {
    Err(create_error!(NotFound))
}

/// Today's code for `user` and `source`, or `NotFound` unless the source is
/// implemented and ready
fn challenge_for(
    user: &User,
    source: ImportSource,
    import: &ApiImport,
    now: DateTime<Utc>,
) -> Result<String> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    if !source.ready(import) {
        return Err(create_error!(NotFound));
    }

    Ok(code(
        import.challenge_secret.as_bytes(),
        source.tag(),
        &user.id,
        now.date_naive(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test::TestHarness;
    use chrono::TimeZone;
    use revolt_config::{ApiImportBotSource, ApiImportMatrix};
    use revolt_database::util::import_challenge::find_accepted_code;
    use revolt_database::BotInformation;
    use rocket::http::{Header, Status};

    const SECRET: &str = "test-challenge-secret";

    fn bot_source() -> ApiImportBotSource {
        ApiImportBotSource {
            enabled: true,
            api_url: "https://api.example".to_string(),
            app_url: "https://app.example".to_string(),
            cdn_url: "https://cdn.example".to_string(),
            bot_id: "01BOT000000000000000000000".to_string(),
            bot_token: "token".to_string(),
            reconcile_after_hours: 24,
        }
    }

    /// Every source configured and ready
    fn all_ready() -> ApiImport {
        let import = ApiImport {
            challenge_secret: SECRET.to_string(),
            stoat: bot_source(),
            fluxer: bot_source(),
            matrix: ApiImportMatrix {
                enabled: true,
                homeserver_url: "https://matrix.example".to_string(),
                bot_user_id: "@sloga-import:matrix.example".to_string(),
                access_token: "token".to_string(),
                max_joins: 8,
            },
            ..ApiImport::default()
        };
        assert!(import.stoat_ready() && import.fluxer_ready() && import.matrix_ready());
        import
    }

    fn error_name(result: Result<String>) -> String {
        match result {
            Ok(code) => panic!("expected an error, got {}", code),
            Err(error) => format!("{:?}", error.error_type),
        }
    }

    #[test]
    fn returns_todays_stoat_code() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, mut user) = harness.new_user().await;
            let import = all_ready();
            let now = Utc.with_ymd_and_hms(2026, 10, 15, 23, 59, 0).unwrap();

            let issued = challenge_for(&user, ImportSource::Stoat, &import, now).unwrap();
            assert_eq!(
                issued,
                code(SECRET.as_bytes(), "stoat", &user.id, now.date_naive())
            );
            // ...and it is what POST verification accepts for this user
            assert_eq!(
                find_accepted_code(&issued, SECRET.as_bytes(), "stoat", &user.id, now),
                Some(issued.clone())
            );

            // Pinned to the helper's known-answer vector, so the route
            // cannot drift to another tag, key or day format
            user.id = "01J9ZQ4V6X7B8C9D0E1F2G3H4J".to_string();
            assert_eq!(
                challenge_for(&user, ImportSource::Stoat, &import, now).unwrap(),
                "sloga-import-AKY7V2QD"
            );
        })
    }

    #[test]
    fn not_found_unless_implemented_and_ready() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let now = Utc::now();

            // Configured, but not built in this release
            for source in [ImportSource::Fluxer, ImportSource::Matrix] {
                assert_eq!(
                    error_name(challenge_for(&user, source, &all_ready(), now)),
                    "NotFound"
                );
            }

            // Built, but not ready
            let mut disabled = all_ready();
            disabled.stoat.enabled = false;
            let mut no_secret = all_ready();
            no_secret.challenge_secret = String::new();
            let mut no_token = all_ready();
            no_token.stoat.bot_token = String::new();
            // The client refuses plain HTTP, so the source could never verify
            let mut plain_http = all_ready();
            plain_http.stoat.api_url = "http://api.example".to_string();
            for import in [
                disabled,
                no_secret,
                no_token,
                plain_http,
                ApiImport::default(),
            ] {
                assert_eq!(
                    error_name(challenge_for(&user, ImportSource::Stoat, &import, now)),
                    "NotFound"
                );
            }

            // Bots are refused before anything else
            let mut bot = user.clone();
            bot.bot = Some(BotInformation {
                owner: user.id.clone(),
            });
            assert_eq!(
                error_name(challenge_for(&bot, ImportSource::Stoat, &all_ready(), now)),
                "IsBot"
            );
        })
    }

    /// Through Rocket with the shipped config (every source dark): known
    /// sources 404 from the handler, unknown ones from the rank-2 catch-all,
    /// and the Discord routes beside them are untouched
    #[test]
    fn route_answers_404_for_dark_and_unknown_sources() {
        crate::util::test::rt().block_on(async {
            assert!(
                !config().await.api.import.stoat_ready(),
                "test config unexpectedly enables Stoat imports"
            );

            let harness = TestHarness::new().await;
            let (_, session, _) = harness.new_user().await;

            for path in [
                "/import/stoat/challenge",
                "/import/fluxer/challenge",
                "/import/matrix/challenge",
                "/import/discord/challenge",
                "/import/bogus/challenge",
                "/import/Stoat/challenge",
            ] {
                let response = harness
                    .client
                    .get(path)
                    .header(Header::new("X-Session-Token", session.token.clone()))
                    .dispatch()
                    .await;
                let status = response.status();
                let body = response.into_string().await.unwrap_or_default();
                assert_eq!(status, Status::NotFound, "{path}: {body}");
                assert!(body.contains(r#""type":"NotFound""#), "{}: {}", path, body);
            }

            // A static Discord GET beside it still routes to its handler
            let response = harness
                .client
                .get("/import/discord/active")
                .header(Header::new("X-Session-Token", session.token.clone()))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
        })
    }
}
