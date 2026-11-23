//! Start a passkey assertion for the current session.
//! POST /passkey/assert/start
use revolt_database::{Account, Database, Session};
use revolt_models::v0;
use revolt_result::Result;
use rocket::serde::json::Json;
use rocket::State;

use crate::util::passkey;

/// # Start Passkey Assertion
///
/// Get the options for confirming a sensitive action with one of the
/// account's passkeys. The signed result goes to `PUT /auth/mfa/ticket` as
/// `passkey_response`, from this same session.
#[openapi(tag = "Passkey")]
#[post("/assert/start")]
pub async fn assert_start(
    db: &State<Database>,
    account: Account,
    session: Session,
) -> Result<Json<v0::ResponsePasskeyOptions>> {
    passkey::assert_available().await?;

    // The challenge is bound to this account and this session. An account
    // without a passkey gets the verifier's own refusal
    passkey::start_assertion(db, &account, &session.id)
        .await
        .map(Json)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::passkey, util::test::TestHarness};
    use revolt_result::{Error, ErrorType};
    use rocket::http::{Header, Status};

    /// The wire form of an error type, so two errors can be compared
    fn kind(error_type: &ErrorType) -> serde_json::Value {
        serde_json::to_value(error_type).expect("an error type")
    }

    #[test]
    fn refused_with_the_feature_off() {
        crate::util::test::rt().block_on(refused_with_the_feature_off_case())
    }

    /// Passkeys ship off: the route answers with the switch's own refusal
    async fn refused_with_the_feature_off_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let off = passkey::assert_available()
            .await
            .expect_err("the control: passkeys are off in the test config");

        let res = harness.client
            .post("/auth/passkey/assert/start")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .dispatch()
            .await;

        // A route that is not mounted would also refuse: not that
        assert_ne!(res.status(), Status::NotFound, "the route is mounted");
        assert_ne!(res.status(), Status::Ok);
        assert_eq!(
            kind(&res.into_json::<Error>().await.unwrap().error_type),
            kind(&off.error_type)
        );
    }

    #[test]
    fn refused_without_a_session() {
        crate::util::test::rt().block_on(refused_without_a_session_case())
    }

    async fn refused_without_a_session_case() {
        revolt_config::overwrite_config(|settings| {
            settings.features.passkeys.available = true;
        })
        .await;
        let harness = TestHarness::new().await;
        passkey::assert_available()
            .await
            .expect("the control: passkeys are on");

        let res = harness.client
            .post("/auth/passkey/assert/start")
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Unauthorized);

        let res = harness.client
            .post("/auth/passkey/assert/start")
            .header(Header::new("X-Session-Token", "not a session"))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Unauthorized);
    }

    #[test]
    fn refused_without_a_passkey() {
        crate::util::test::rt().block_on(refused_without_a_passkey_case())
    }

    /// Nothing is special-cased here: the verifier refuses, and no options
    /// leave the server
    async fn refused_without_a_passkey_case() {
        revolt_config::overwrite_config(|settings| {
            settings.features.passkeys.available = true;
        })
        .await;
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        passkey::assert_available()
            .await
            .expect("the control: passkeys are on");

        let res = harness.client
            .post("/auth/passkey/assert/start")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .dispatch()
            .await;

        // The verifier's refusal for an account with no passkey
        let status = res.status();
        let body = res.into_string().await.unwrap_or_default();
        assert_eq!(status, Status::BadRequest, "{body}");
        let error: serde_json::Value = serde_json::from_str(&body).expect("an error body");
        assert_eq!(error["type"], "InvalidOperation", "{body}");
        assert!(!body.contains("challenge_id"), "{body}");
    }
}
