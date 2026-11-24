//! Change account email.
//! PATCH /account/change/email
use iso8601_timestamp::Timestamp;
use revolt_database::util::email::validate_email;
use revolt_database::{Account, Database, ValidatedTicket};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;
use revolt_result::{Result, create_error};
use serde::{Deserialize, Serialize};

/// # Change Email Data
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct DataChangeEmail {
    /// Valid email address
    pub email: String,
    /// Current password
    ///
    /// Required. Optional in the body only so that leaving it out is
    /// answered as a wrong password is.
    pub current_password: Option<String>,
}

/// # Change Email
///
/// Change the associated account email.
///
/// The current password must be sent, and with MFA enabled a validated MFA
/// ticket as well. An account that has no email or no password is refused
/// (`InvalidOperation`): it sets a password first.
#[openapi(tag = "Account")]
#[patch("/change/email", data = "<data>")]
pub async fn change_email(
    db: &State<Database>,
    validated_ticket: Option<ValidatedTicket>,
    mut account: Account,
    data: Json<DataChangeEmail>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();

    // This route moves an existing address by a confirmation link. An
    // account with no email has nothing to move: it gets its first address
    // through a code typed into the app. Refused before anything in the
    // request is looked at, so the answer is the same whatever was sent, no
    // password is checked and no attempt is counted. `start_email_move`
    // refuses the same way; this keeps the refusal ahead of the checks.
    if account.real_email().is_none() {
        return Err(create_error!(InvalidOperation));
    }

    // Nor does an account that has no password (created with a passkey, or
    // through Google or Apple) move its address here: this route confirms
    // by a clicked link, and such an account takes an address only through
    // a code typed into the app. Same answer as above, and as early, so
    // nothing sent is checked or counted. Until a typed-code move exists,
    // such an account sets a password first.
    if account.password_absent {
        return Err(create_error!(InvalidOperation));
    }

    validate_email(&data.email)?;

    // A locked account cannot probe the ticket or the password
    if let Some(lockout) = &account.lockout {
        if let Some(expiry) = lockout.expiry {
            if expiry > Timestamp::now_utc() {
                return Err(create_error!(LockedOut));
            }
        }
    }

    if account.mfa.is_active() && validated_ticket.is_none() {
        return Err(create_error!(InvalidCredentials));
    }

    if let Some(current_password) = &data.current_password {
        // Ensure given password is correct, counting a wrong one
        if let Err(error) = account.verify_password(current_password) {
            db.bump_lockout_count(&account.id).await?;
            return Err(error);
        }
    } else {
        // An account that has a password must send it: a ticket alone does
        // not stand in for it. Nothing was guessed, so nothing is counted
        return Err(create_error!(InvalidCredentials));
    }

    // Send email verification for new email
    account
        .start_email_move(db, data.email)
        .await
        .map(|_| EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_config::overwrite_config;
    use revolt_database::{Account, EmailVerification, MFATicket, Session, Totp};
    use revolt_models::v0;
    use revolt_result::{Error, ErrorType};
    use rocket::http::{ContentType, Header, Status};

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        overwrite_config(|config| config.api.smtp.host = "".to_string()).await;

        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;

        let res = harness.client
            .patch("/auth/account/change/email")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "email": "validexample@valid.com",
                    "current_password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let account = harness.db.fetch_account(&account.id).await.unwrap();

        assert_eq!(account.email, "validexample@valid.com");
    }

    #[test]
    fn success_smtp() {
        crate::util::test::rt().block_on(success_smtp_case())
    }

    async fn success_smtp_case() {
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;

        let res = harness.client
            .patch("/auth/account/change/email")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "email": "change_email@smtp.test",
                    "current_password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let account = harness.db.fetch_account(&account.id).await.unwrap();

        let (_, code) = harness.assert_email("change_email@smtp.test").await;
        let res = harness.client
            .post(format!("/auth/account/verify/{}", code))
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);

        let account = harness.db.fetch_account(&account.id).await.unwrap();

        assert_eq!(account.email, "change_email@smtp.test");

        // Ensure that we did not receive a ticket
        assert_eq!(
            v0::ResponseVerify::NoTicket,
            res.into_json().await.expect("`ResponseVerify")
        )
    }

    #[test]
    fn success_mfa() {
        crate::util::test::rt().block_on(success_mfa_case())
    }

    async fn success_mfa_case() {
        overwrite_config(|config| config.api.smtp.host = "".to_string()).await;

        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let ticket = MFATicket::new(account.id.to_string(), true);
        ticket.save(&harness.db).await.unwrap();

        let res = harness.client
            .patch("/auth/account/change/email")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .header(Header::new("X-MFA-Ticket", ticket.token))
            .body(
                json!({
                    "email": "validexample@valid.com",
                    "current_password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let account = harness.db.fetch_account(&account.id).await.unwrap();

        assert_eq!(account.email, "validexample@valid.com");
    }

    #[test]
    fn fail_mfa() {
        crate::util::test::rt().block_on(fail_mfa_case())
    }

    async fn fail_mfa_case() {
        overwrite_config(|config| config.api.smtp.host = "".to_string()).await;

        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .patch("/auth/account/change/email")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "email": "validexample@valid.com",
                    "current_password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
    }

    /// A harness that changes the email at once (no SMTP, so no
    /// confirmation mail stands between the request and the stored address)
    async fn harness_without_smtp() -> TestHarness {
        overwrite_config(|config| config.api.smtp.host = "".to_string()).await;
        TestHarness::new().await
    }

    /// PATCH /auth/account/change/email with `session`, and `ticket` as the
    /// `X-MFA-Ticket` header if given. The error type comes back on failure.
    async fn send(
        harness: &TestHarness,
        session: &Session,
        ticket: Option<&MFATicket>,
        body: serde_json::Value,
    ) -> (Status, Option<ErrorType>) {
        let mut request = harness
            .client
            .patch("/auth/account/change/email")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(body.to_string());

        if let Some(ticket) = ticket {
            request = request.header(Header::new("X-MFA-Ticket", ticket.token.clone()));
        }

        let res = request.dispatch().await;
        let status = res.status();
        let error = if status == Status::NoContent {
            None
        } else {
            res.into_json::<Error>().await.map(|error| error.error_type)
        };

        (status, error)
    }

    async fn saved_ticket(harness: &TestHarness, account_id: &str, validated: bool) -> MFATicket {
        let ticket = MFATicket::new(account_id.to_string(), validated);
        ticket.save(&harness.db).await.unwrap();
        ticket
    }

    async fn ticket_exists(harness: &TestHarness, ticket: &MFATicket) -> bool {
        harness
            .db
            .fetch_ticket_by_token(&ticket.token)
            .await
            .is_ok()
    }

    async fn stored(harness: &TestHarness, account: &Account) -> Account {
        harness.db.fetch_account(&account.id).await.unwrap()
    }

    fn attempts(account: &Account) -> Option<i32> {
        account.lockout.as_ref().map(|lockout| lockout.attempts)
    }

    /// An account that has no password: the flag is set, and the hash the
    /// harness stored stays behind, as the random one does on an account
    /// created through Google. `password_insecure` still matches that hash,
    /// so a test that sends it proves the route never looked.
    async fn without_password(harness: &TestHarness) -> (Account, Session) {
        let (mut account, session, _) = harness.new_user().await;
        account.password_absent = true;
        account.save(&harness.db).await.unwrap();
        assert!(stored(harness, &account).await.password_absent);
        (account, session)
    }

    /// A wrong password is refused and counts one lockout attempt, as before
    #[test]
    fn wrong_password_counts_an_attempt() {
        crate::util::test::rt().block_on(async {
            let harness = harness_without_smtp().await;
            let (account, session, _) = harness.new_user().await;

            let (status, error) = send(
                &harness,
                &session,
                None,
                json!({ "email": "validexample@valid.com", "current_password": "wrong password" }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));

            let after = stored(&harness, &account).await;
            assert_eq!(attempts(&after), Some(1));
            assert_eq!(after.email, account.email);
        })
    }

    /// The answer every request of an account with no password gets
    fn assert_no_password_refusal(row: &str, answer: &(Status, Option<ErrorType>)) {
        assert_eq!(answer.0, Status::BadRequest, "{}", row);
        assert!(
            matches!(answer.1, Some(ErrorType::InvalidOperation)),
            "{}: expected `InvalidOperation`, got {:?}",
            row,
            answer.1
        );
    }

    /// Fails if: an account with no password gets anything other than
    /// `InvalidOperation` for a password (the stored hash's own included, so
    /// the route never looked), for a wrong one or for none; counts an
    /// attempt; or changes the address.
    #[test]
    fn no_password_account_refuses_every_password() {
        crate::util::test::rt().block_on(async {
            let harness = harness_without_smtp().await;
            let (account, session) = without_password(&harness).await;

            for body in [
                json!({ "email": "validexample@valid.com", "current_password": "password_insecure" }),
                json!({ "email": "validexample@valid.com", "current_password": "wrong password" }),
                json!({ "email": "validexample@valid.com" }),
                json!({ "email": "not an email" }),
            ] {
                let row = body.to_string();
                let answer = send(&harness, &session, None, body).await;
                assert_no_password_refusal(&row, &answer);
            }

            let after = stored(&harness, &account).await;
            assert_eq!(attempts(&after), None, "no attempt may be counted");
            assert_eq!(after.email, account.email);
        })
    }

    /// Until this step an account with no password changed its email here
    /// with a validated ticket alone.
    ///
    /// Fails if: it still can (with SMTP off as here the address would move
    /// at once, with SMTP on a link would be mailed and a move left
    /// pending), with or without a password next to the ticket; the refusal
    /// is not `InvalidOperation`; or an attempt is counted.
    #[test]
    fn no_password_account_is_refused_with_a_ticket() {
        crate::util::test::rt().block_on(async {
            let harness = harness_without_smtp().await;
            let (account, session) = without_password(&harness).await;

            for body in [
                json!({ "email": "validexample@valid.com" }),
                json!({ "email": "validexample@valid.com", "current_password": "password_insecure" }),
            ] {
                let row = body.to_string();
                let ticket = saved_ticket(&harness, &account.id, true).await;
                let answer = send(&harness, &session, Some(&ticket), body).await;
                assert_no_password_refusal(&row, &answer);
            }

            let after = stored(&harness, &account).await;
            assert_eq!(after.email, account.email);
            assert_eq!(after.email_normalised, account.email_normalised);
            assert!(
                matches!(after.verification, EmailVerification::Verified),
                "no move is pending"
            );
            assert_eq!(attempts(&after), None);

            // The control: the same account, once it has a password, moves
            // its address with that password
            let mut with_password = after;
            with_password.password_absent = false;
            with_password.save(&harness.db).await.unwrap();

            let (status, _) = send(
                &harness,
                &session,
                None,
                json!({ "email": "validexample@valid.com", "current_password": "password_insecure" }),
            )
            .await;
            assert_eq!(status, Status::NoContent, "the control");
            assert_eq!(
                stored(&harness, &account).await.email,
                "validexample@valid.com"
            );
        })
    }

    /// Fails if: a validated ticket minted on another account changes the
    /// answer or the address of an account with no password, or is burned.
    #[test]
    fn no_password_account_refuses_a_foreign_ticket() {
        crate::util::test::rt().block_on(async {
            let harness = harness_without_smtp().await;
            let (account, session) = without_password(&harness).await;
            let (other, _, _) = harness.new_user().await;
            let ticket = saved_ticket(&harness, &other.id, true).await;

            let answer = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "email": "validexample@valid.com" }),
            )
            .await;
            assert_no_password_refusal("a foreign ticket", &answer);

            let after = stored(&harness, &account).await;
            assert_eq!(after.email, account.email);
            assert_eq!(attempts(&after), None);
            assert!(ticket_exists(&harness, &ticket).await);
        })
    }

    /// Fails if: a ticket that was never validated changes the answer or
    /// the address of an account with no password.
    #[test]
    fn no_password_account_refuses_an_unvalidated_ticket() {
        crate::util::test::rt().block_on(async {
            let harness = harness_without_smtp().await;
            let (account, session) = without_password(&harness).await;
            let ticket = saved_ticket(&harness, &account.id, false).await;

            let answer = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "email": "validexample@valid.com" }),
            )
            .await;
            assert_no_password_refusal("an unvalidated ticket", &answer);
            assert_eq!(stored(&harness, &account).await.email, account.email);
        })
    }

    /// A password account that sends neither proof is refused, and since
    /// nothing was guessed nothing is counted
    #[test]
    fn neither_ticket_nor_password_is_refused() {
        crate::util::test::rt().block_on(async {
            let harness = harness_without_smtp().await;
            let (account, session, _) = harness.new_user().await;

            let (status, error) = send(
                &harness,
                &session,
                None,
                json!({ "email": "validexample@valid.com" }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));

            let after = stored(&harness, &account).await;
            assert_eq!(after.email, account.email);
            assert_eq!(attempts(&after), None);
        })
    }

    /// A validated ticket does not stand in for the password of an account
    /// that has one. No password was sent, so no attempt is counted
    #[test]
    fn ticket_alone_is_refused_for_a_password_account() {
        crate::util::test::rt().block_on(async {
            let harness = harness_without_smtp().await;
            let (account, session, _) = harness.new_user().await;
            let ticket = saved_ticket(&harness, &account.id, true).await;

            let (status, error) = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "email": "validexample@valid.com" }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));

            let after = stored(&harness, &account).await;
            assert_eq!(after.email, account.email);
            assert_eq!(attempts(&after), None, "nothing was guessed");
        })
    }

    /// A wrong password is refused and counted when a ticket comes with it,
    /// as before
    #[test]
    fn sent_password_is_checked_even_with_a_ticket() {
        crate::util::test::rt().block_on(async {
            let harness = harness_without_smtp().await;
            let (account, session, _) = harness.new_user().await;
            let ticket = saved_ticket(&harness, &account.id, true).await;

            let (status, error) = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "email": "validexample@valid.com", "current_password": "wrong password" }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));

            let after = stored(&harness, &account).await;
            assert_eq!(after.email, account.email);
            assert_eq!(attempts(&after), Some(1));
        })
    }

    /// Fails if: an account with no email can start (or, with SMTP off as
    /// here, complete at once) a link-based email move, with a validated
    /// ticket or with any password; or the refusal is anything other than
    /// `InvalidOperation`, depends on what was sent, or counts an attempt.
    #[test]
    fn no_email_account_is_refused() {
        crate::util::test::rt().block_on(async {
            let harness = harness_without_smtp().await;

            let account = Account::new_passkey_signup(None).expect("a no-email account");
            account.save(&harness.db).await.unwrap();
            let session = account
                .create_session(&harness.db, String::new())
                .await
                .unwrap();
            let before = stored(&harness, &account).await;
            assert!(before.email_absent, "the seed must be stored");

            // The control: an account WITH an email and a password changes
            // the address in this harness
            {
                let (ordinary, ordinary_session, _) = harness.new_user().await;
                let (status, _) = send(
                    &harness,
                    &ordinary_session,
                    None,
                    json!({ "email": "control@valid.com", "current_password": "password_insecure" }),
                )
                .await;
                assert_eq!(status, Status::NoContent, "the control");
                assert_eq!(stored(&harness, &ordinary).await.email, "control@valid.com");
            }

            let ticket = saved_ticket(&harness, &account.id, true).await;
            for (ticket, body) in [
                (Some(&ticket), json!({ "email": "validexample@valid.com" })),
                (
                    None,
                    json!({ "email": "validexample@valid.com", "current_password": "password_insecure" }),
                ),
                (None, json!({ "email": "validexample@valid.com" })),
                (None, json!({ "email": "not an email" })),
            ] {
                let (status, error) = send(&harness, &session, ticket, body).await;
                assert_eq!(status, Status::BadRequest);
                assert!(
                    matches!(error, Some(ErrorType::InvalidOperation)),
                    "expected `InvalidOperation`, got {:?}",
                    error
                );
            }

            let after = stored(&harness, &account).await;
            assert_eq!(after.email, before.email);
            assert_eq!(after.email_normalised, before.email_normalised);
            assert!(after.email_absent);
            assert!(
                matches!(after.verification, EmailVerification::Verified),
                "no move is pending"
            );
            assert_eq!(attempts(&after), None, "no attempt may be counted");
        })
    }

    /// Fails if: an account can move to a new address under `.invalid` (at
    /// the stand-in domain or anywhere else): with SMTP off, as here, the
    /// move would be applied at once.
    #[test]
    fn a_move_to_an_invalid_address_is_refused() {
        crate::util::test::rt().block_on(async {
            let harness = harness_without_smtp().await;
            let (account, session, _) = harness.new_user().await;

            for email in ["new@sloga.invalid", "new@noemail.invalid", "new@Other.INVALID"] {
                let (status, error) = send(
                    &harness,
                    &session,
                    None,
                    json!({ "email": email, "current_password": "password_insecure" }),
                )
                .await;
                assert_eq!(status, Status::BadRequest, "{email}");
                assert!(
                    matches!(error, Some(ErrorType::IncorrectData { .. })),
                    "{email}: {error:?}"
                );
            }

            let after = stored(&harness, &account).await;
            assert_eq!(after.email, account.email);
            assert!(
                matches!(after.verification, EmailVerification::Verified),
                "no move is pending"
            );

            // The control: the same request with an ordinary address moves
            let moved = format!("{}@valid.com", TestHarness::rand_string());
            let (status, _) = send(
                &harness,
                &session,
                None,
                json!({ "email": moved, "current_password": "password_insecure" }),
            )
            .await;
            assert_eq!(status, Status::NoContent, "the control");
            assert_eq!(stored(&harness, &account).await.email, moved);
        })
    }
}
