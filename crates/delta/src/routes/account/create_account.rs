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
use revolt_result::{create_error, Error, ErrorType, Result};
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

    // If required, fetch valid invite. A look only: a used one is refused
    // here, and the invite is taken below by one conditional write.
    let invite = if config().await.api.registration.invite_only {
        if let Some(invite) = data.invite {
            let invite = db.fetch_account_invite(&invite).await?;
            if invite.used {
                return Err(create_error!(InvalidInvite));
            }

            Some(invite)
        } else {
            return Err(create_error!(MissingInvite));
        }
    } else {
        None
    };

    let Some(invite) = invite else {
        // Create account
        Account::new(db, data.email, data.password, true).await?;
        return Ok(EmptyResponse);
    };

    // Use up the invite BEFORE the account exists, under the id the account
    // will get: one conditional write, so of two sign-ups that both passed
    // the look above with one invite, one gets it. The other is refused
    // here with nothing created and nothing mailed. Every sign-up takes this
    // path, whatever the address: there is no branch that reaches
    // `new_with_id` without holding the invite.
    let id = ulid::Ulid::new().to_string();
    if !db.claim_account_invite_if_unused(&invite.id, &id).await? {
        return Err(create_error!(InvalidInvite));
    }

    match Account::new_with_id(db, id.clone(), data.email, data.password, true).await {
        // Either the account was made under `id`, or the address already
        // had an account (that one is returned and mailed, and none is
        // made). The invite stays used both ways: giving it back in the
        // second case would let whoever holds the invite read from its
        // state whether an address is registered.
        Ok(_) => Ok(EmptyResponse),
        Err(error) => {
            // Give the invite back only when it is certain no account was
            // stored under `id`. A failed save can still have written the
            // account (the write landed and its answer was lost), so if
            // the account is there, or the read to find out fails, the
            // claim is kept: an invite spent on nobody can be freed by
            // hand (docs/passkeys-operator-notes.md), a second account
            // from one invite cannot be undone.
            if matches!(
                db.fetch_account(&id).await,
                Err(Error {
                    error_type: ErrorType::UnknownUser,
                    ..
                })
            ) {
                release_invite(db, &invite.id, &id).await;
            }

            Err(error)
        }
    }
}

/// Give back the invite a sign-up claimed under `account_id` and then did
/// not use. One conditional write: an invite another account holds is left
/// alone. A failure is reported and does not change the answer.
async fn release_invite(db: &Database, invite_id: &str, account_id: &str) {
    if let Err(error) = db
        .release_account_invite_if_claimed_by(invite_id, account_id)
        .await
    {
        revolt_config::capture_error(&error);
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        rocket,
        util::test::{without_comments, without_whitespace, Mail, TestHarness},
    };
    use revolt_config::overwrite_config;
    use revolt_database::{events::client::EventV1, Account, AccountInvite};
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

    /// Fails if: sign-up accepts a new address under `.invalid` (at the
    /// stand-in domain or anywhere else), or stores an account for one. The
    /// last two are spellings the format check lets through and reads as
    /// `sloga.invalid` and `noemail.invalid`: fullwidth letters, and an
    /// ideographic full stop for the dot.
    #[test]
    fn fail_invalid_tld_email() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let local = TestHarness::rand_string();

            for domain in [
                "sloga.invalid",
                "noemail.invalid",
                "Other.INVALID",
                "sloga.\u{FF49}\u{FF4E}\u{FF56}\u{FF41}\u{FF4C}\u{FF49}\u{FF44}",
                "noemail\u{3002}invalid",
            ] {
                let email = format!("{local}@{domain}");
                let res = harness
                    .client
                    .post("/auth/account/create")
                    .header(ContentType::JSON)
                    .body(json!({ "email": email, "password": "valid password" }).to_string())
                    .dispatch()
                    .await;

                assert_eq!(res.status(), Status::BadRequest, "{email}");
                assert!(
                    matches!(
                        res.into_json::<Error>().await.unwrap().error_type,
                        ErrorType::IncorrectData { .. },
                    ),
                    "{email}"
                );
                assert!(
                    harness
                        .db
                        .fetch_account_by_normalised_email(&email.to_lowercase())
                        .await
                        .unwrap()
                        .is_none(),
                    "{email}: no account may be stored"
                );
            }
        })
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

    /// An unused invite, stored
    async fn unused_invite(harness: &TestHarness) -> AccountInvite {
        let invite = AccountInvite {
            id: TestHarness::rand_string(),
            used: false,
            claimed_by: None,
        };
        invite.save(&harness.db).await.expect("an invite");
        invite
    }

    /// A sign-up with `invite`; the status and, on failure, the error type
    async fn sign_up(
        harness: &TestHarness,
        email: &str,
        invite: &str,
    ) -> (Status, Option<ErrorType>) {
        let res = harness
            .client
            .post("/auth/account/create")
            .header(ContentType::JSON)
            .body(
                json!({ "email": email, "password": "valid password", "invite": invite })
                    .to_string(),
            )
            .dispatch()
            .await;

        let status = res.status();
        let error = if status == Status::NoContent {
            None
        } else {
            res.into_json::<Error>().await.map(|error| error.error_type)
        };

        (status, error)
    }

    /// The account stored under this (already normalised) address, if any
    async fn account_at(harness: &TestHarness, email: &str) -> Option<Account> {
        harness
            .db
            .fetch_account_by_normalised_email(email)
            .await
            .unwrap()
    }

    fn fresh_address(domain: &str) -> String {
        format!("{}@{domain}", TestHarness::rand_string())
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

    /// Fails if: an invite that is already used up still lets a sign-up
    /// through (an account stored, or a mail sent), or the refused sign-up
    /// changes who holds the invite.
    #[test]
    fn a_used_invite_is_refused_and_nothing_is_created() {
        crate::util::test::rt().block_on(async {
            overwrite_config(|config| config.api.registration.invite_only = true).await;
            let harness = TestHarness::new().await;

            let invite = unused_invite(&harness).await;
            assert!(harness
                .db
                .claim_account_invite_if_unused(&invite.id, "01ACCOUNTINVITEHOLDER00000")
                .await
                .unwrap());

            let refused = fresh_address("smtp.test");
            let (status, error) = sign_up(&harness, &refused, &invite.id).await;
            assert_eq!(status, Status::BadRequest);
            assert!(matches!(error, Some(ErrorType::InvalidInvite)), "{error:?}");
            assert!(account_at(&harness, &refused).await.is_none());

            // The marker: a sign-up made after the refused one has been
            // mailed, so a mail for the refused one would be here by now
            let marker_invite = unused_invite(&harness).await;
            let marker = fresh_address("smtp.test");
            let (status, error) = sign_up(&harness, &marker, &marker_invite.id).await;
            assert_eq!(status, Status::NoContent, "{error:?}");
            harness.assert_email(&marker).await;
            assert!(mail_to(&refused).await.is_empty(), "nothing may be mailed");

            let stored = harness.db.fetch_account_invite(&invite.id).await.unwrap();
            assert!(stored.used);
            assert_eq!(
                stored.claimed_by.as_deref(),
                Some("01ACCOUNTINVITEHOLDER00000")
            );
        })
    }

    /// Fails if: one invite makes two accounts, whether the sign-ups come
    /// one after the other or at once; the invite does not name the account
    /// it made; or a sign-up that lost is answered with anything other than
    /// `InvalidInvite`.
    #[test]
    fn one_invite_makes_one_account() {
        crate::util::test::rt().block_on(async {
            overwrite_config(|config| config.api.registration.invite_only = true).await;
            let harness = TestHarness::new().await;

            // One after the other
            let invite = unused_invite(&harness).await;
            let first = fresh_address("validemail.com");
            let second = fresh_address("validemail.com");

            let (status, error) = sign_up(&harness, &first, &invite.id).await;
            assert_eq!(status, Status::NoContent, "{error:?}");
            let made = account_at(&harness, &first).await.expect("the first account");

            let (status, error) = sign_up(&harness, &second, &invite.id).await;
            assert_eq!(status, Status::BadRequest);
            assert!(matches!(error, Some(ErrorType::InvalidInvite)), "{error:?}");
            assert!(account_at(&harness, &second).await.is_none());

            let stored = harness.db.fetch_account_invite(&invite.id).await.unwrap();
            assert!(stored.used);
            assert_eq!(stored.claimed_by.as_deref(), Some(made.id.as_str()));

            // At once
            let invite = unused_invite(&harness).await;
            let addresses = [
                fresh_address("validemail.com"),
                fresh_address("validemail.com"),
                fresh_address("validemail.com"),
                fresh_address("validemail.com"),
            ];
            let answers = tokio::join!(
                sign_up(&harness, &addresses[0], &invite.id),
                sign_up(&harness, &addresses[1], &invite.id),
                sign_up(&harness, &addresses[2], &invite.id),
                sign_up(&harness, &addresses[3], &invite.id),
            );
            let answers = [answers.0, answers.1, answers.2, answers.3];

            let mut made = vec![];
            for (address, (status, error)) in addresses.iter().zip(&answers) {
                match account_at(&harness, address).await {
                    Some(account) => {
                        assert_eq!(*status, Status::NoContent, "{address}: {error:?}");
                        made.push(account.id);
                    }
                    None => {
                        assert_eq!(*status, Status::BadRequest, "{address}");
                        assert!(
                            matches!(error, Some(ErrorType::InvalidInvite)),
                            "{address}: {error:?}"
                        );
                    }
                }
            }
            assert_eq!(made.len(), 1, "one invite, one account: {made:?}");

            let stored = harness.db.fetch_account_invite(&invite.id).await.unwrap();
            assert!(stored.used);
            assert_eq!(stored.claimed_by.as_deref(), Some(made[0].as_str()));
        })
    }

    /// Fails if: a sign-up for an address that already has an account gives
    /// the invite back (its state would then tell the invite's holder that
    /// the address is registered), lets the invite make an account
    /// afterwards, makes a second account for the address, answers
    /// differently from a fresh address, or stops mailing the account that
    /// exists.
    #[test]
    fn an_existing_address_still_uses_the_invite_up() {
        crate::util::test::rt().block_on(async {
            overwrite_config(|config| config.api.registration.invite_only = true).await;
            let harness = TestHarness::new().await;

            let address = fresh_address("smtp.test");
            let existing = Account::new(&harness.db, address.clone(), "password".into(), false)
                .await
                .unwrap();

            let invite = unused_invite(&harness).await;
            let (status, error) = sign_up(&harness, &address.to_uppercase(), &invite.id).await;
            assert_eq!(status, Status::NoContent, "{error:?}");

            // The existing, verified account gets a password reset
            harness.assert_email(&address).await;
            let stored = account_at(&harness, &address).await.expect("the account");
            assert_eq!(stored.id, existing.id);
            assert_eq!(stored.password, existing.password);

            // The invite is used, as it is after a sign-up for a fresh
            // address. It names the id the sign-up chose, under which no
            // account was made: not the account that already existed.
            let after = harness.db.fetch_account_invite(&invite.id).await.unwrap();
            assert!(after.used, "the invite must stay used");
            let claimed_by = after.claimed_by.clone().expect("the claim");
            assert_ne!(claimed_by, existing.id);
            assert!(
                harness.db.fetch_account(&claimed_by).await.is_err(),
                "no second account may be made"
            );

            // The same invite makes no account afterwards
            let fresh = fresh_address("smtp.test");
            let (status, error) = sign_up(&harness, &fresh, &invite.id).await;
            assert_eq!(status, Status::BadRequest);
            assert!(matches!(error, Some(ErrorType::InvalidInvite)), "{error:?}");
            assert!(account_at(&harness, &fresh).await.is_none());
            let later = harness.db.fetch_account_invite(&invite.id).await.unwrap();
            assert!(later.used);
            assert_eq!(later.claimed_by, after.claimed_by);

            // The control: a fresh address with an unused invite is
            // answered the same way and leaves its invite in the same state
            let control_invite = unused_invite(&harness).await;
            let (status, error) = sign_up(&harness, &fresh, &control_invite.id).await;
            assert_eq!(status, Status::NoContent, "{error:?}");
            let made = account_at(&harness, &fresh).await.expect("the new account");
            let control = harness
                .db
                .fetch_account_invite(&control_invite.id)
                .await
                .unwrap();
            assert!(control.used);
            assert_eq!(control.claimed_by.as_deref(), Some(made.id.as_str()));
        })
    }

    /// Fails if: a sign-up whose account could not be created keeps the
    /// invite it claimed, so the invite is spent on nobody. The mail server
    /// is unreachable here, which fails the creation before anything is
    /// stored.
    #[test]
    fn a_failed_creation_gives_the_invite_back() {
        crate::util::test::rt().block_on(async {
            overwrite_config(|config| {
                config.api.registration.invite_only = true;
                config.api.smtp.port = Some(1);
            })
            .await;
            let harness = TestHarness::new().await;

            let invite = unused_invite(&harness).await;
            let address = fresh_address("validemail.com");
            let (status, error) = sign_up(&harness, &address, &invite.id).await;
            assert_ne!(status, Status::NoContent, "the control: the creation fails");
            assert!(
                !matches!(error, Some(ErrorType::InvalidInvite)),
                "the control: the invite was not what failed"
            );
            assert!(account_at(&harness, &address).await.is_none());

            let after = harness.db.fetch_account_invite(&invite.id).await.unwrap();
            assert!(!after.used, "the invite must be given back");
            assert_eq!(after.claimed_by, None);
        })
    }

    /// Fails if: the route writes an invite back whole again (the read,
    /// then blind save that let one invite make several accounts), claims
    /// the invite after the account is created, ignores what the claim
    /// answers, creates an account on a path that holds no claim, gives the
    /// invite back when the address already had an account, or gives it
    /// back after a failure without first reading that no account exists.
    #[test]
    fn the_invite_is_claimed_before_the_account_is_created() {
        let source = include_str!("create_account.rs");
        let shipping = source.find("#[cfg(test)]").map_or(source, |end| &source[..end]);
        let code = without_whitespace(&without_comments(shipping));

        assert!(!code.contains("save_account_invite"));
        assert!(!code.contains(".save(db)"));

        let claim = code
            .find(
                "if!db.claim_account_invite_if_unused(&invite.id,&id).await?\
                 {returnErr(create_error!(InvalidInvite));}",
            )
            .expect("the claim, with its refusal");
        let create = code
            .find("Account::new_with_id(db,id.clone(),")
            .expect("the creation under the claimed id");
        assert!(claim < create, "the claim comes first");

        // Nothing creates an account ahead of the claim: no `Account::new`
        // at all in the invite path, and one `new_with_id`
        let invite_path = &code[claim..];
        assert!(!invite_path.contains("Account::new("));
        assert_eq!(code.matches("Account::new_with_id(").count(), 1);
        assert!(!code.contains("fetch_by_email"));

        // Given back in one place only: after a failed creation, and only
        // once the account is known not to exist. Never when the address
        // already had an account.
        assert_eq!(
            code.matches("release_invite(db,&invite.id,&id).await;").count(),
            1,
            "given back only when the creation fails"
        );
        assert!(code.contains(
            "Ok(_)=>Ok(EmptyResponse),Err(error)=>{ifmatches!(db.fetch_account(&id).await,\
             Err(Error{error_type:ErrorType::UnknownUser,..})){release_invite(db,&invite.id,&id).await;}\
             Err(error)}"
        ));
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
