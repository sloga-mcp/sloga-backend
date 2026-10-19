use revolt_database::{is_invalid_session, Session, User};
use revolt_result::{Error, Result};

use rocket::serde::json::Json;
use serde::Serialize;

/// # Onboarding Status
#[derive(Serialize, JsonSchema)]
pub struct DataHello {
    /// Whether onboarding is required
    onboarding: bool,
}

/// # Check Onboarding Status
///
/// This will tell you whether the current account requires onboarding or whether you can continue to send requests as usual. You may skip calling this if you're restoring an existing session.
#[openapi(tag = "Onboarding")]
#[get("/hello")]
pub async fn hello(
    _session: Session,
    user: std::result::Result<User, Error>,
) -> Result<Json<DataHello>> {
    let onboarding = match user {
        Ok(_) => false,
        Err(e) if is_invalid_session(&e) => true,
        // A lookup failure must not read as "needs onboarding", or the client
        // would send an existing user to the username picker
        Err(e) => return Err(e),
    };

    Ok(Json(DataHello { onboarding }))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use rocket::http::{Header, Status};
    use serde_json::{json, Value};

    async fn hello_status(harness: &TestHarness, token: &str) -> (Status, Value) {
        let response = harness
            .client
            .get("/onboard/hello")
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await;
        let status = response.status();
        let body: Value = response.into_json().await.expect("json body");
        (status, body)
    }

    #[test]
    fn hello_session_without_user_needs_onboarding() {
        crate::util::test::rt().block_on(hello_session_without_user_needs_onboarding_case())
    }

    async fn hello_session_without_user_needs_onboarding_case() {
        let harness = TestHarness::new().await;
        let id = ulid::Ulid::new().to_string();
        let (_, session) = harness.account_from_user(id.clone()).await;
        assert!(harness.db.fetch_user(&id).await.is_err());

        let (status, body) = hello_status(&harness, &session.token).await;
        assert_eq!(status, Status::Ok);
        assert_eq!(body, json!({ "onboarding": true }));
    }

    #[test]
    fn hello_onboarded_user_needs_no_onboarding() {
        crate::util::test::rt().block_on(hello_onboarded_user_needs_no_onboarding_case())
    }

    async fn hello_onboarded_user_needs_no_onboarding_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let (status, body) = hello_status(&harness, &session.token).await;
        assert_eq!(status, Status::Ok);
        assert_eq!(body, json!({ "onboarding": false }));
    }
}
