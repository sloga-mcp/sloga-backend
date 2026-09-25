//! Send a password reset email
//! POST /account/reset_password
use std::time::Duration;

use tokio::time::sleep;
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;
use revolt_result::Result;
use revolt_database::{Database, util::{email::{normalise_email, validate_email}, captcha::check_captcha}};
use revolt_models::v0;

/// # Send Password Reset
///
/// Send an email to reset account password.
#[openapi(tag = "Account")]
#[post("/reset_password", data = "<data>")]
pub async fn send_password_reset(
    db: &State<Database>,
    data: Json<v0::DataSendPasswordReset>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();

    // Random jitter from 0-1000ms
    sleep(Duration::from_millis((rand::random::<f32>() * 1000.) as u64)).await;

    // Check Captcha token
    check_captcha(data.captcha.as_deref()).await?;

    // Make sure email is valid and not blocked
    validate_email(&data.email)?;

    // From this point on, do not report failure to the
    // remote client, as this will open us up to user enumeration.

    // Normalise the email
    let email_normalised = normalise_email(data.email);

    // Try to find the relevant account
    //
    // Unverified accounts get the reset too. They used to get nothing while
    // the client said "check your email", and since login refuses them they
    // had no way back in. Completing the reset proves they own the mailbox,
    // so it verifies the account as well (see `password_reset`).
    if let Ok(Some(mut account)) = db
        .fetch_account_by_normalised_email(&email_normalised)
        .await
    {
        if let Err(e) = account.start_password_reset(db, false).await {
            revolt_config::capture_error(&e);
        }
    }

    // Never fail this route, (except for db error)
    // You may open the application to email enumeration otherwise.
    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{Account, EmailVerification};
    use revolt_models::v0;
    use rocket::http::{ContentType, Status};

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let harness = TestHarness::new().await;

        Account::new(
            &harness.db,
            "password_reset@smtp.test".into(),
            "password".into(),
            false,
        )
        .await
        .unwrap();

        let res = harness.client
            .post("/auth/account/reset_password")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "password_reset@smtp.test",
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let (_, code) = harness.assert_email("password_reset@smtp.test").await;
        let res = harness.client
            .patch("/auth/account/reset_password")
            .header(ContentType::JSON)
            .body(
                json!({
                    "token": code,
                    "password": "valid password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "password_reset@smtp.test",
                    "password": "valid password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(serde_json::from_str::<v0::Session>(&res.into_string().await.unwrap()).is_ok());
    }

    #[test]
    fn unverified_account() {
        crate::util::test::rt().block_on(unverified_account_case())
    }

    /// An account still waiting on its verification link used to get no
    /// reset email at all, and login refuses it, so it was locked out for
    /// good. Now it gets the email, and completing the reset verifies it.
    async fn unverified_account_case() {
        let harness = TestHarness::new().await;

        let mut account = Account::new(
            &harness.db,
            "password_reset_unverified@smtp.test".into(),
            "password".into(),
            false,
        )
        .await
        .unwrap();

        account.verification = EmailVerification::Pending {
            token: "unverified-token".into(),
            expiry: Timestamp::now_utc() + Duration::seconds(100),
        };
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "password_reset_unverified@smtp.test",
                    "password": "password"
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Forbidden, "login refuses an unverified account");

        let res = harness.client
            .post("/auth/account/reset_password")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "password_reset_unverified@smtp.test",
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::NoContent);

        let (_, code) = harness.assert_email("password_reset_unverified@smtp.test").await;
        let res = harness.client
            .patch("/auth/account/reset_password")
            .header(ContentType::JSON)
            .body(
                json!({
                    "token": code,
                    "password": "valid password"
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::NoContent);

        let account = harness
            .db
            .fetch_account(&account.id)
            .await
            .unwrap();
        assert!(
            matches!(account.verification, EmailVerification::Verified),
            "completing the reset must verify the account"
        );

        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "password_reset_unverified@smtp.test",
                    "password": "valid password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(serde_json::from_str::<v0::Session>(&res.into_string().await.unwrap()).is_ok());
    }
}
