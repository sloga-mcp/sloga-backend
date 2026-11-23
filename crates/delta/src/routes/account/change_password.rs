//! Change account password.
//! PATCH /account/change/password
use iso8601_timestamp::Timestamp;
use revolt_database::{
    util::password::{assert_safe, hash_password},
    Account, Database, ValidatedTicket,
};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;
use serde::{Deserialize, Serialize};

/// # Change Data
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct DataChangePassword {
    /// New password
    pub password: String,
    /// Current password
    ///
    /// Left out only by an account that has no password, which sets its
    /// first one with a validated MFA ticket (`X-MFA-Ticket`) instead.
    pub current_password: Option<String>,
}

/// # Change Password
///
/// Change the current account password.
///
/// An account that has a password must send it. An account that has none
/// sets its first one with a validated MFA ticket.
#[openapi(tag = "Account")]
#[patch("/change/password", data = "<data>")]
pub async fn change_password(
    db: &State<Database>,
    validated_ticket: Option<ValidatedTicket>,
    mut account: Account,
    data: Json<DataChangePassword>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();

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

    // Verify password can be used
    assert_safe(&data.password).await?;

    if account.password_absent {
        // No password exists, so none is checked and no attempt is counted:
        // a guess could never be right, and counting it would let whoever
        // holds a session lock the owner out. Only a ticket will do, and
        // the refusal reads as a wrong password does
        if validated_ticket.is_none() {
            return Err(create_error!(InvalidCredentials));
        }
    } else if let Some(current_password) = &data.current_password {
        // Ensure given password is correct, counting a wrong one
        if let Err(error) = account.verify_password(current_password) {
            db.bump_lockout_count(&account.id).await?;
            return Err(error);
        }
    } else {
        // An existing password is never replaced on a ticket alone. Nothing
        // was guessed, so nothing is counted
        return Err(create_error!(InvalidCredentials));
    }

    // Hash and replace password
    account.password = hash_password(data.password)?;

    // The account has a password its owner knows from here on. Cleared in
    // the same save as the hash, so the flag and the hash it describes
    // never disagree in storage
    account.password_absent = false;

    // Commit to database
    account.save(db).await.map(|_| EmptyResponse)
}

#[cfg(test)]
mod tests {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{Account, MFATicket, Session, Totp};
    use revolt_models::v0;
    use revolt_result::{Error, ErrorType};
    use rocket::http::{ContentType, Header, Status};

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let res = harness
            .client
            .patch("/auth/account/change/password")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "password": "new password",
                    "current_password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);

        let res = harness
            .client
            .patch("/auth/account/change/password")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token))
            .body(
                json!({
                    "password": "sussy password",
                    "current_password": "new password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
    }

    /// An account with no password sets its first one with a validated
    /// ticket and no current password. The flag is cleared in the same
    /// save, and the new password then logs in and mints a ticket.
    #[test]
    fn change_clears_the_password_absent_flag() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session) = without_password(&harness).await;

            // The controls: while the flag is stored, the password factor
            // and the password login are both refused
            let res = harness
                .client
                .put("/auth/mfa/ticket")
                .header(Header::new("X-Session-Token", session.token.clone()))
                .body(json!({ "password": "password_insecure" }).to_string())
                .dispatch()
                .await;
            assert_eq!(res.status(), Status::BadRequest);
            assert!(matches!(
                res.into_json::<Error>().await.unwrap().error_type,
                ErrorType::DisallowedMFAMethod
            ));
            assert_eq!(
                login(&harness, &account, "password_insecure").await,
                Status::Unauthorized
            );

            let ticket = saved_ticket(&harness, &account.id, true).await;
            let (status, _) = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "password": "new password" }),
            )
            .await;
            assert_eq!(status, Status::NoContent);

            let after = stored(&harness, &account).await;
            assert!(
                !after.password_absent,
                "a password change must clear the stored flag"
            );
            assert!(after.verify_password("new password").is_ok());
            assert!(!ticket_exists(&harness, &ticket).await, "the ticket is single use");

            assert_eq!(login(&harness, &account, "new password").await, Status::Ok);

            let res = harness
                .client
                .put("/auth/mfa/ticket")
                .header(Header::new("X-Session-Token", session.token.clone()))
                .body(json!({ "password": "new password" }).to_string())
                .dispatch()
                .await;
            assert_eq!(res.status(), Status::Ok);
            assert!(res.into_json::<v0::MFATicket>().await.unwrap().validated);
        })
    }

    #[test]
    fn success_mfa() {
        crate::util::test::rt().block_on(success_mfa_case())
    }

    async fn success_mfa_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let ticket = MFATicket::new(account.id.to_string(), true);
        ticket.save(&harness.db).await.unwrap();

        let res = harness
            .client
            .patch("/auth/account/change/password")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .header(Header::new("X-MFA-Ticket", ticket.token))
            .body(
                json!({
                    "password": "new password",
                    "current_password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::NoContent);
    }

    #[test]
    fn fail_mfa_no_ticket() {
        crate::util::test::rt().block_on(fail_mfa_no_ticket_case())
    }

    async fn fail_mfa_no_ticket_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let res = harness
            .client
            .patch("/auth/account/change/password")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "password": "new password",
                    "current_password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
    }

    #[test]
    fn fail_mfa_invalid_password() {
        crate::util::test::rt().block_on(fail_mfa_invalid_password_case())
    }

    async fn fail_mfa_invalid_password_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let mut ticket = MFATicket::new(account.id.to_string(), true);
        ticket.last_totp_code = Some("token from earlier".into());
        ticket.save(&harness.db).await.unwrap();

        let res = harness
            .client
            .patch("/auth/account/change/password")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .header(Header::new("X-MFA-Ticket", ticket.token))
            .body(
                json!({
                    "password": "new password",
                    "current_password": "incorrect password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
    }

    /// PATCH /auth/account/change/password with `session`, and `ticket` as
    /// the `X-MFA-Ticket` header if given. The error type comes back on
    /// failure.
    async fn send(
        harness: &TestHarness,
        session: &Session,
        ticket: Option<&MFATicket>,
        body: serde_json::Value,
    ) -> (Status, Option<ErrorType>) {
        let mut request = harness
            .client
            .patch("/auth/account/change/password")
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

    /// POST /auth/session/login with the account's email
    async fn login(harness: &TestHarness, account: &Account, password: &str) -> Status {
        harness
            .client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(json!({ "email": account.email.clone(), "password": password }).to_string())
            .dispatch()
            .await
            .status()
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

    /// A wrong current password is refused and counts one lockout attempt,
    /// as before
    #[test]
    fn wrong_password_counts_an_attempt() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session, _) = harness.new_user().await;

            let (status, error) = send(
                &harness,
                &session,
                None,
                json!({ "password": "new password", "current_password": "wrong password" }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));

            let after = stored(&harness, &account).await;
            assert_eq!(attempts(&after), Some(1));
            assert!(after.verify_password("password_insecure").is_ok());
        })
    }

    /// R9: an account with no password gets the wrong-password answer for
    /// any current password, the stored hash's own included, and nothing is
    /// counted or changed
    #[test]
    fn no_password_account_refuses_every_password() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session) = without_password(&harness).await;

            for body in [
                json!({ "password": "new password", "current_password": "password_insecure" }),
                json!({ "password": "new password", "current_password": "wrong password" }),
                json!({ "password": "new password" }),
            ] {
                let (status, error) = send(&harness, &session, None, body).await;
                assert_eq!(status, Status::Unauthorized);
                assert!(matches!(error, Some(ErrorType::InvalidCredentials)));
            }

            let after = stored(&harness, &account).await;
            assert_eq!(attempts(&after), None, "no attempt may be counted");
            assert!(after.password_absent);
            assert_eq!(after.password, account.password);
        })
    }

    /// The ticket replaces the current password only: the new password
    /// still has to pass the strength check, and the flag stays
    #[test]
    fn ticket_does_not_skip_the_strength_check() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session) = without_password(&harness).await;
            let ticket = saved_ticket(&harness, &account.id, true).await;

            let (status, error) = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "password": "short" }),
            )
            .await;

            assert_ne!(status, Status::NoContent);
            assert!(matches!(error, Some(ErrorType::ShortPassword)));

            let after = stored(&harness, &account).await;
            assert!(after.password_absent);
            assert_eq!(after.password, account.password);
        })
    }

    /// A validated ticket minted on another account proves nothing here,
    /// and it is not burned
    #[test]
    fn no_password_account_refuses_a_foreign_ticket() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session) = without_password(&harness).await;
            let (other, _, _) = harness.new_user().await;
            let ticket = saved_ticket(&harness, &other.id, true).await;

            let (status, error) = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "password": "new password" }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));

            let after = stored(&harness, &account).await;
            assert!(after.password_absent);
            assert_eq!(after.password, account.password);
            assert_eq!(attempts(&after), None);
            assert!(ticket_exists(&harness, &ticket).await);
        })
    }

    /// A ticket that was never validated is no proof
    #[test]
    fn no_password_account_refuses_an_unvalidated_ticket() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session) = without_password(&harness).await;
            let ticket = saved_ticket(&harness, &account.id, false).await;

            let (status, error) = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "password": "new password" }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));

            let after = stored(&harness, &account).await;
            assert!(after.password_absent);
            assert_eq!(after.password, account.password);
        })
    }

    /// An account that has a password never replaces it without the old
    /// one: not with nothing, and not with a validated ticket alone
    #[test]
    fn existing_password_is_not_replaced_without_the_old_one() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session, _) = harness.new_user().await;

            let (status, error) =
                send(&harness, &session, None, json!({ "password": "new password" })).await;
            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));

            let ticket = saved_ticket(&harness, &account.id, true).await;
            let (status, error) = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "password": "new password" }),
            )
            .await;
            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));

            let after = stored(&harness, &account).await;
            assert!(after.verify_password("password_insecure").is_ok());
            assert_eq!(attempts(&after), None, "nothing was guessed");
        })
    }
}
