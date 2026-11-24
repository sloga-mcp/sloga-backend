//! Send a password reset email
//! POST /account/reset_password
use std::time::Duration;

use tokio::time::sleep;
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;
use revolt_result::Result;
use revolt_database::{Account, Database, util::{email::validate_lookup_email, captcha::check_captcha}};
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

    // Make sure email is valid and not blocked. The address is only used
    // to find an account, so of `.invalid` just the stand-in domain is
    // refused: an account that stores another `.invalid` address is found.
    validate_lookup_email(&data.email)?;

    // From this point on, do not report failure to the
    // remote client, as this will open us up to user enumeration.

    // Try to find the relevant account. The wrapper normalises the email
    // and never matches an account that has no email.
    //
    // Unverified accounts get the reset too. They used to get nothing while
    // the client said "check your email", and since login refuses them they
    // had no way back in. Completing the reset proves they own the mailbox,
    // so it verifies the account as well (see `password_reset`).
    if let Ok(Some(mut account)) = Account::fetch_by_email(db, &data.email).await {
        // An account with no email is never mailed a reset. The lookup
        // above cannot return one; this holds if that ever changes.
        if account.real_email().is_some() {
            if let Err(e) = account.start_password_reset(db, false).await {
                revolt_config::capture_error(&e);
            }
        }
    }

    // Never fail this route, (except for db error)
    // You may open the application to email enumeration otherwise.
    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{
        rocket,
        util::test::{without_comments, without_whitespace, Mail, TestHarness},
    };
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

    /// Status and raw body of a reset request for `email`
    async fn request_reset(harness: &TestHarness, email: &str) -> (Status, String) {
        let res = harness
            .client
            .post("/auth/account/reset_password")
            .header(ContentType::JSON)
            .body(json!({ "email": email }).to_string())
            .dispatch()
            .await;

        let status = res.status();
        (status, res.into_string().await.unwrap_or_default())
    }

    /// Every mail maildev holds for `mailbox`, left in place
    async fn mail_to(mailbox: &str) -> Vec<Mail> {
        reqwest::Client::new()
            .get("http://localhost:14080/api/email")
            .send()
            .await
            .expect("maildev unreachable on :14080; is `stoatchat-maildev-1` running?")
            .json::<Vec<Mail>>()
            .await
            .expect("maildev did not return `Vec<Mail>`")
            .into_iter()
            .filter(|mail| {
                mail.envelope
                    .to
                    .iter()
                    .any(|to| to.address.eq_ignore_ascii_case(mailbox))
            })
            .collect()
    }

    /// Fails if: typing the stand-in address of an account with no email
    /// (as stored, or in another case) answers differently from a stand-in
    /// address nobody holds, stores a reset token on that account, or mails
    /// it. `validate_lookup_email` refuses every `noemail.invalid` address
    /// before the lookup, so the answer compared here is that refusal; the
    /// lookup is pinned by `the_lookup_goes_through_the_wrapper`.
    #[test]
    fn typed_placeholder_gets_the_unknown_address_answer() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            let account = Account::new_passkey_signup(None).expect("a no-email account");
            account.save(&harness.db).await.unwrap();
            let before = harness.db.fetch_account(&account.id).await.unwrap();
            assert!(before.email_absent, "the seed must be stored");
            assert!(before.password_reset.is_none());

            let nobody = format!("{}@noemail.invalid", TestHarness::rand_string());
            let unknown = request_reset(&harness, &nobody).await;

            for typed in [account.email.clone(), account.email.to_uppercase()] {
                assert_eq!(request_reset(&harness, &typed).await, unknown, "{typed}");
            }

            // The marker: a reset for an ordinary account, requested after
            // the ones above, has arrived
            let mailbox = format!("{}@smtp.test", TestHarness::rand_string());
            Account::new(&harness.db, mailbox.clone(), "password".into(), false)
                .await
                .unwrap();
            assert_eq!(request_reset(&harness, &mailbox).await.0, Status::NoContent);
            harness.assert_email(&mailbox).await;

            assert!(
                mail_to(&account.email).await.is_empty(),
                "nothing may be mailed to a stand-in address"
            );

            let after = harness.db.fetch_account(&account.id).await.unwrap();
            assert!(after.password_reset.is_none(), "no reset token may be stored");
            assert_eq!(after.email, before.email);
            assert_eq!(after.password, before.password);
            assert!(after.email_absent);
            assert!(after.password_absent);
        })
    }

    /// Fails if: the route looks the typed address up in the stored email
    /// fields again instead of through `Account::fetch_by_email`, the one
    /// lookup that never matches an account with no email.
    #[test]
    fn the_lookup_goes_through_the_wrapper() {
        let source = include_str!("send_password_reset.rs");
        let shipping = source.find("#[cfg(test)]").map_or(source, |end| &source[..end]);
        let code = without_whitespace(&without_comments(shipping));

        assert!(code.contains("Account::fetch_by_email(db,&data.email)"));
        assert!(!code.contains("fetch_account_by_normalised_email"));
        assert!(!code.contains("normalise_email"));
    }

    /// Fails if: an account that stores a `.invalid` address outside the
    /// stand-in domain (one exists in production) is refused at the reset
    /// form, gets no reset token or no mail, cannot set a new password with
    /// the token, cannot sign in with it, or cannot change it afterwards.
    #[test]
    fn an_ordinary_invalid_address_resets_and_changes_its_password() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            // Seeded as an ordinary account, then given the old address
            let local = TestHarness::rand_string();
            let email = format!("{local}@sloga.invalid");
            let mut account = Account::new(
                &harness.db,
                format!("{local}@smtp.test"),
                "first password".into(),
                false,
            )
            .await
            .unwrap();
            account.email = email.clone();
            account.email_normalised = email.clone();
            account.save(&harness.db).await.unwrap();

            assert_eq!(
                request_reset(&harness, &email).await,
                (Status::NoContent, String::new())
            );

            let stored = harness.db.fetch_account(&account.id).await.unwrap();
            assert!(stored.password_reset.is_some(), "a reset token is stored");

            let (_, code) = harness.assert_email(&email).await;
            let res = harness
                .client
                .patch("/auth/account/reset_password")
                .header(ContentType::JSON)
                .body(json!({ "token": code, "password": "valid password" }).to_string())
                .dispatch()
                .await;
            assert_eq!(res.status(), Status::NoContent);

            let res = harness
                .client
                .post("/auth/session/login")
                .header(ContentType::JSON)
                .body(json!({ "email": email, "password": "valid password" }).to_string())
                .dispatch()
                .await;
            assert_eq!(res.status(), Status::Ok);
            let session: v0::Session =
                serde_json::from_str(&res.into_string().await.unwrap()).expect("a session");

            let res = harness
                .client
                .patch("/auth/account/change/password")
                .header(ContentType::JSON)
                .header(rocket::http::Header::new("X-Session-Token", session.token))
                .body(
                    json!({
                        "password": "new password",
                        "current_password": "valid password"
                    })
                    .to_string(),
                )
                .dispatch()
                .await;
            assert_eq!(res.status(), Status::NoContent);

            let stored = harness.db.fetch_account(&account.id).await.unwrap();
            stored
                .verify_password("new password")
                .expect("the changed password is stored");
            assert_eq!(stored.email, email);
        })
    }
}
