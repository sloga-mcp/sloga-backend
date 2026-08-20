//! Exchange a one-time OAuth handoff code for the login response
//! POST /auth/oauth/google/complete
use redis_kiss::{get_connection, redis};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct DataOauthComplete {
    /// One-time handoff code issued by the OAuth callback
    pub code: String,
}

/// # Complete Google OAuth
///
/// Swaps the one-time handoff code from the OAuth redirect for the
/// actual login response (session token, MFA challenge or disabled
/// notice). Codes are single-use and expire after 60 seconds.
#[openapi(tag = "Session")]
#[post("/google/complete", data = "<data>")]
pub async fn google_complete(data: Json<DataOauthComplete>) -> Result<Json<v0::ResponseLogin>> {
    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let payload: Option<String> = redis::cmd("GETDEL")
        .arg(super::handoff_key("google", &data.code))
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    let payload = payload.ok_or_else(|| create_error!(InvalidToken))?;

    serde_json::from_str(&payload)
        .map(Json)
        .map_err(|_| create_error!(InternalError))
}

#[cfg(test)]
mod tests {
    use crate::rocket;
    use crate::util::test::TestHarness;
    use revolt_result::{Error, ErrorType};
    use rocket::http::{ContentType, Status};

    #[test]
    fn fail_unknown_handoff_code() {
        crate::util::test::rt().block_on(fail_unknown_handoff_code_case())
    }

    async fn fail_unknown_handoff_code_case() {
        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/oauth/google/complete")
            .header(ContentType::JSON)
            .body(json!({ "code": "not-a-real-handoff-code" }).to_string())
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidToken,
        ));
    }

    #[test]
    fn fail_authorise_when_disabled() {
        crate::util::test::rt().block_on(fail_authorise_when_disabled_case())
    }

    async fn fail_authorise_when_disabled_case() {
        let harness = TestHarness::new().await;

        // Config defaults ship with oauth disabled
        let res = harness.client.get("/auth/oauth/google").dispatch().await;
        assert_eq!(res.status(), Status::InternalServerError);
    }
}
