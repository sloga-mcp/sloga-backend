//! Resend account verification email
//! POST /account/reverify
use std::time::Duration;

use tokio::time::sleep;
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;
use revolt_result::Result;
use revolt_database::{Account, Database, util::{email::validate_lookup_email, captcha::check_captcha}, EmailVerification};
use revolt_models::v0;

/// # Resend Verification
///
/// Resend account creation verification email.
#[openapi(tag = "Account")]
#[post("/reverify", data = "<data>")]
pub async fn resend_verification(
    db: &State<Database>,
    data: Json<v0::DataResendVerification>,
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
    // and never matches an account that has no email. Such an account is
    // stored `Verified`, which below would mean "send a password reset":
    // the filter keeps it out if the lookup ever changes.
    if let Ok(Some(mut account)) = Account::fetch_by_email(db, &data.email)
        .await
        .map(|found| found.filter(|account| account.real_email().is_some()))
    {
        match account.verification {
            EmailVerification::Verified => {
                // Send password reset if already verified
                account.start_password_reset(db, true).await?;
            }
            EmailVerification::Pending { .. } => {
                // Resend if not verified yet
                account.start_email_verification(db).await?;
            }
            // Ignore if pending for another email,
            // this should be re-initiated from settings.
            EmailVerification::Moving { .. } => {}
        }
    }

    // Never fail this route,
    // You may open the application to email enumeration otherwise.
    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::Timestamp;
    use revolt_database::{Account, EmailVerification};
    use crate::{
        rocket,
        util::test::{without_comments, without_whitespace, Mail, TestHarness},
    };
    use rocket::http::{ContentType, Status};
    use revolt_result::{Error, ErrorType};

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let harness = TestHarness::new().await;

        let mut account = Account::new(
            &harness.db,
            "resend_verification@smtp.test".into(),
            "password".into(),
            false,
        )
        .await
        .unwrap();

        account.verification = EmailVerification::Pending {
            token: "".into(),
            expiry: Timestamp::now_utc(),
        };

        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .post("/auth/account/reverify")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "resend_verification@smtp.test",
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let (_, code) = harness.assert_email("resend_verification@smtp.test").await;
        let res = harness.client
            .post(format!("/auth/account/verify/{code}"))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
    }

    #[test]
    fn success_unknown() {
        crate::util::test::rt().block_on(success_unknown_case())
    }

    async fn success_unknown_case() {
        let harness = TestHarness::new().await;

        let res = harness.client
            .post("/auth/account/reverify")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "smtptest1@insrt.uk",
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
    }

    #[test]
    fn fail_bad_email() {
        crate::util::test::rt().block_on(fail_bad_email_case())
    }

    async fn fail_bad_email_case() {
        let harness = TestHarness::new().await;

        let res = harness.client
            .post("/auth/account/reverify")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "invalid",
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

    /// Status and raw body of a resend request for `email`
    async fn request_resend(harness: &TestHarness, email: &str) -> (Status, String) {
        let res = harness
            .client
            .post("/auth/account/reverify")
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
    /// address nobody holds, or sends that account the password reset a
    /// `Verified` account gets here (a stored token or a mail), or touches
    /// its verification. `validate_lookup_email` refuses every
    /// `noemail.invalid` address before the lookup, so the answer compared
    /// here is that refusal; the lookup is pinned by
    /// `the_lookup_goes_through_the_wrapper`.
    #[test]
    fn typed_placeholder_gets_the_unknown_address_answer() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            let account = Account::new_passkey_signup(None).expect("a no-email account");
            account.save(&harness.db).await.unwrap();
            let before = harness.db.fetch_account(&account.id).await.unwrap();
            assert!(before.email_absent, "the seed must be stored");
            assert!(matches!(before.verification, EmailVerification::Verified));

            let nobody = format!("{}@noemail.invalid", TestHarness::rand_string());
            let unknown = request_resend(&harness, &nobody).await;

            for typed in [account.email.clone(), account.email.to_uppercase()] {
                assert_eq!(request_resend(&harness, &typed).await, unknown, "{typed}");
            }

            // The marker: a resend for an ordinary pending account,
            // requested after the ones above, has arrived
            let mailbox = format!("{}@smtp.test", TestHarness::rand_string());
            let mut pending = Account::new(&harness.db, mailbox.clone(), "password".into(), false)
                .await
                .unwrap();
            pending.verification = EmailVerification::Pending {
                token: "".into(),
                expiry: Timestamp::now_utc(),
            };
            pending.save(&harness.db).await.unwrap();
            assert_eq!(request_resend(&harness, &mailbox).await.0, Status::NoContent);
            harness.assert_email(&mailbox).await;

            assert!(
                mail_to(&account.email).await.is_empty(),
                "nothing may be mailed to a stand-in address"
            );

            let after = harness.db.fetch_account(&account.id).await.unwrap();
            assert!(after.password_reset.is_none(), "no reset token may be stored");
            assert!(matches!(after.verification, EmailVerification::Verified));
            assert_eq!(after.email, before.email);
            assert!(after.email_absent);
        })
    }

    /// Fails if: the route looks the typed address up in the stored email
    /// fields again instead of through `Account::fetch_by_email`, the one
    /// lookup that never matches an account with no email.
    #[test]
    fn the_lookup_goes_through_the_wrapper() {
        let source = include_str!("resend_verification.rs");
        let shipping = source.find("#[cfg(test)]").map_or(source, |end| &source[..end]);
        let code = without_whitespace(&without_comments(shipping));

        assert!(code.contains("Account::fetch_by_email(db,&data.email)"));
        assert!(!code.contains("fetch_account_by_normalised_email"));
        assert!(!code.contains("normalise_email"));
    }

    /// Fails if: an account that stores a `.invalid` address outside the
    /// stand-in domain is refused at this form or gets no mail: the address
    /// typed here only finds an account, it is not a new address.
    #[test]
    fn an_ordinary_invalid_address_gets_its_verification_resent() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            // Seeded as an ordinary account, then given the old address
            let local = TestHarness::rand_string();
            let email = format!("{local}@sloga.invalid");
            let mut account = Account::new(
                &harness.db,
                format!("{local}@smtp.test"),
                "password".into(),
                false,
            )
            .await
            .unwrap();
            account.email = email.clone();
            account.email_normalised = email.clone();
            account.verification = EmailVerification::Pending {
                token: "".into(),
                expiry: Timestamp::now_utc(),
            };
            account.save(&harness.db).await.unwrap();

            assert_eq!(
                request_resend(&harness, &email).await,
                (Status::NoContent, String::new())
            );

            let (_, code) = harness.assert_email(&email).await;
            let stored = harness.db.fetch_account(&account.id).await.unwrap();
            assert!(
                matches!(
                    &stored.verification,
                    EmailVerification::Pending { token, .. } if *token == code
                ),
                "the mailed token is the stored one"
            );
        })
    }
}
