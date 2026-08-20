//! Create a new account
//! POST /account/create
use std::time::Duration;

use tokio::time::sleep;
use revolt_config::config;
use revolt_database::{
    util::{
        captcha::check_captcha,
        email::validate_email,
        password::assert_safe,
        shield::{validate_shield, ShieldValidationInput},
    },
    Account, Database,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Create Account
///
/// Create a new account.
#[openapi(tag = "Account")]
#[post("/create", data = "<data>")]
pub async fn create_account(
    db: &State<Database>,
    data: Json<v0::DataCreateAccount>,
    mut shield: ShieldValidationInput,
) -> Result<EmptyResponse> {
    let data = data.into_inner();

    // Random jitter from 0-1000ms
    sleep(Duration::from_millis((rand::random::<f32>() * 1000.) as u64)).await;

    // Check Captcha token
    check_captcha(data.captcha.as_deref()).await?;

    // Validate the request
    shield.email = Some(data.email.to_string());
    validate_shield(shield).await?;

    // Make sure email is valid and not blocked
    validate_email(&data.email)?;

    // Ensure password is safe to use
    assert_safe(&data.password).await?;

    // If required, fetch valid invite
    let invite = if config().await.api.registration.invite_only {
        if let Some(invite) = data.invite {
            Some(db.fetch_account_invite(&invite).await?)
        } else {
            return Err(create_error!(MissingInvite));
        }
    } else {
        None
    };

    // Create account
    let account = Account::new(db, data.email, data.password, true).await?;

    // Use up the invite
    if let Some(mut invite) = invite {
        invite.claimed_by = Some(account.id);
        invite.used = true;

        db.save_account_invite(&invite).await?;
    }

    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_config::overwrite_config;
    use revolt_database::{events::client::EventV1, AccountInvite};
    use revolt_result::{Error, ErrorType};
    use rocket::http::{ContentType, Status};

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let mut harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "success@validemail.com",
                    "password": "valid password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
        drop(res);

        harness
            // Match on the address, not just the variant: `global` on the
            // shared redis also carries CreateAccount from every other test
            // process, so a bare variant check can pass on someone else's
            // event. See the note in routes::session::login::tests::success.
            .wait_for_event("global", |e| {
                matches!(e, EventV1::CreateAccount { account } if account.email == "success@validemail.com")
            })
            .await;
    }

    #[test]
    fn fail_invalid_email() {
        crate::util::test::rt().block_on(fail_invalid_email_case())
    }

    async fn fail_invalid_email_case() {
        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "invalid",
                    "password": "valid password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::IncorrectData { .. },
        ));
    }

    #[test]
    fn fail_invalid_password() {
        crate::util::test::rt().block_on(fail_invalid_password_case())
    }

    async fn fail_invalid_password_case() {
        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "fail_invalid_password@validemail.com",
                    "password": "password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::CompromisedPassword,
        ));
    }

    #[test]
    fn fail_invalid_invite() {
        crate::util::test::rt().block_on(fail_invalid_invite_case())
    }

    async fn fail_invalid_invite_case() {
        overwrite_config(|config| config.api.registration.invite_only = true).await;

        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "fail_invalid_invite@validemail.com",
                    "password": "valid password",
                    "invite": "invalid"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidInvite,
        ));
    }

    #[test]
    fn success_valid_invite() {
        crate::util::test::rt().block_on(success_valid_invite_case())
    }

    async fn success_valid_invite_case() {
        overwrite_config(|config| config.api.registration.invite_only = true).await;

        let harness = TestHarness::new().await;

        let invite = AccountInvite {
            id: "invite".to_string(),
            used: false,
            claimed_by: None,
        };

        invite.save(&harness.db).await.unwrap();

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "success_valid_invite@validemail.com",
                    "password": "valid password",
                    "invite": "invite"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let invite = harness
            .db
            .fetch_account_invite("invite")
            .await
            .expect("`Invite`");

        assert!(invite.used);
    }

    #[test]
    fn fail_missing_captcha() {
        crate::util::test::rt().block_on(fail_missing_captcha_case())
    }

    async fn fail_missing_captcha_case() {
        overwrite_config(|config| {
            config.api.security.captcha.hcaptcha_key =
                "0x0000000000000000000000000000000000000000".to_string()
        })
        .await;

        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "fail_missing_captcha@validemail.com",
                    "password": "valid password",
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::CaptchaFailed,
        ));
    }

    #[test]
    fn fail_captcha_invalid() {
        crate::util::test::rt().block_on(fail_captcha_invalid_case())
    }

    async fn fail_captcha_invalid_case() {
        overwrite_config(|config| {
            config.api.security.captcha.hcaptcha_key =
                "0x0000000000000000000000000000000000000000".to_string()
        })
        .await;

        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "fail_captcha_invalid@validemail.com",
                    "password": "valid password",
                    "captcha": "00000000-aaaa-bbbb-cccc-000000000000"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::CaptchaFailed,
        ));
    }

    #[test]
    fn success_captcha_valid() {
        crate::util::test::rt().block_on(success_captcha_valid_case())
    }

    async fn success_captcha_valid_case() {
        overwrite_config(|config| {
            config.api.security.captcha.hcaptcha_key =
                "0x0000000000000000000000000000000000000000".to_string()
        })
        .await;

        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "success_captcha_valid@validemail.com",
                    "password": "valid password",
                    "captcha": "20000000-aaaa-bbbb-cccc-000000000002"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
    }

    #[test]
    fn success_smtp_sent() {
        crate::util::test::rt().block_on(success_smtp_sent_case())
    }

    async fn success_smtp_sent_case() {
        let harness = TestHarness::new().await;

        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "success_smtp_sent@smtp.test",
                    "password": "valid password",
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let (_, code) = harness.assert_email("success_smtp_sent@smtp.test").await;
        let res = harness
            .client
            .post(format!("/auth/account/verify/{code}"))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
    }
}
