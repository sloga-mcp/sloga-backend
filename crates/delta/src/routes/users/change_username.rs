use iso8601_timestamp::Timestamp;
use once_cell::sync::Lazy;
use regex::Regex;
use revolt_database::{Account, Database, User, ValidatedTicket};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use serde::{Deserialize, Serialize};
use validator::Validate;

/// Regex for valid usernames
///
/// Block zero width space
/// Block lookalike characters
pub static RE_USERNAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(\p{L}|[\d_.-])+$").unwrap());

/// # Username Information
#[derive(Validate, Serialize, Deserialize, JsonSchema)]
pub struct DataChangeUsername {
    /// New username
    #[validate(length(min = 2, max = 32), regex = "RE_USERNAME")]
    username: String,
    /// Current account password
    ///
    /// Left out only by an account that has no password, which sends a
    /// validated MFA ticket (`X-MFA-Ticket`) instead.
    #[validate(length(min = 8, max = 1024))]
    password: Option<String>,
}

/// # Change Username
///
/// Change your username.
///
/// An account that has a password must send it. An account that has none
/// sends a validated MFA ticket instead.
#[openapi(tag = "User Information")]
#[patch("/@me/username", data = "<data>")]
pub async fn change_username(
    db: &State<Database>,
    validated_ticket: Option<ValidatedTicket>,
    account: Account,
    mut user: User,
    data: Json<DataChangeUsername>,
) -> Result<Json<v0::User>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // A locked account cannot probe the ticket or the password
    if let Some(lockout) = &account.lockout {
        if let Some(expiry) = lockout.expiry {
            if expiry > Timestamp::now_utc() {
                return Err(create_error!(LockedOut));
            }
        }
    }

    if account.password_absent {
        // No password exists, so none is checked and no attempt is counted:
        // a guess could never be right, and counting it would let whoever
        // holds a session lock the owner out. Only a ticket will do, and
        // the refusal reads as a wrong password does
        if validated_ticket.is_none() {
            return Err(create_error!(InvalidCredentials));
        }
    } else if let Some(password) = &data.password {
        // Count a wrong password towards the lockout
        if account.verify_password(password).is_err() {
            db.bump_lockout_count(&account.id).await?;
            return Err(create_error!(InvalidCredentials));
        }
    } else {
        // An account that has a password must send it: a ticket alone does
        // not stand in for it. Nothing was guessed, so nothing is counted
        return Err(create_error!(InvalidCredentials));
    }

    user.update_username(db, data.username).await?;
    Ok(Json(user.into(db, None).await))
}

#[cfg(test)]
mod tests {
    use crate::util::test::TestHarness;
    use revolt_database::{Account, MFATicket, Session, User};
    use revolt_result::{Error, ErrorType};
    use rocket::http::{ContentType, Header, Status};

    /// PATCH /users/@me/username with `session`, and `ticket` as the
    /// `X-MFA-Ticket` header if given. The error type comes back on failure.
    async fn send(
        harness: &TestHarness,
        session: &Session,
        ticket: Option<&MFATicket>,
        body: serde_json::Value,
    ) -> (Status, Option<ErrorType>) {
        let mut request = harness
            .client
            .patch("/users/@me/username")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(body.to_string());

        if let Some(ticket) = ticket {
            request = request.header(Header::new("X-MFA-Ticket", ticket.token.clone()));
        }

        let res = request.dispatch().await;
        let status = res.status();
        let error = if status == Status::Ok {
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

    async fn stored_attempts(harness: &TestHarness, account: &Account) -> Option<i32> {
        harness
            .db
            .fetch_account(&account.id)
            .await
            .unwrap()
            .lockout
            .map(|lockout| lockout.attempts)
    }

    async fn stored_username(harness: &TestHarness, user: &User) -> String {
        harness.db.fetch_user(&user.id).await.unwrap().username
    }

    /// An account that has no password: the flag is set, and the hash the
    /// harness stored stays behind, as the random one does on an account
    /// created through Google. `password_insecure` still matches that hash,
    /// so a test that sends it proves the route never looked.
    async fn without_password(harness: &TestHarness) -> (Account, Session, User) {
        let (mut account, session, user) = harness.new_user().await;
        account.password_absent = true;
        account.save(&harness.db).await.unwrap();
        assert!(
            harness
                .db
                .fetch_account(&account.id)
                .await
                .unwrap()
                .password_absent
        );
        (account, session, user)
    }

    /// The right password changes the username, as before
    #[test]
    fn right_password_changes_the_username() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session, user) = harness.new_user().await;
            let username = TestHarness::rand_string();

            let (status, _) = send(
                &harness,
                &session,
                None,
                json!({ "username": username.clone(), "password": "password_insecure" }),
            )
            .await;

            assert_eq!(status, Status::Ok);
            assert_eq!(stored_username(&harness, &user).await, username);
            assert_eq!(stored_attempts(&harness, &account).await, None);
        })
    }

    /// A wrong password is refused and counts one lockout attempt, as before
    #[test]
    fn wrong_password_counts_an_attempt() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session, user) = harness.new_user().await;

            let (status, error) = send(
                &harness,
                &session,
                None,
                json!({ "username": TestHarness::rand_string(), "password": "wrong password" }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));
            assert_eq!(stored_attempts(&harness, &account).await, Some(1));
            assert_eq!(stored_username(&harness, &user).await, user.username);
        })
    }

    /// R9: an account with no password gets the wrong-password answer for
    /// any password, the stored hash's own included, and nothing is counted
    #[test]
    fn no_password_account_refuses_every_password() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            // One account per body: the route's rate limit allows two
            // requests per user, and a third would answer 429 instead
            for body in [
                json!({ "username": TestHarness::rand_string(), "password": "password_insecure" }),
                json!({ "username": TestHarness::rand_string(), "password": "wrong password" }),
                json!({ "username": TestHarness::rand_string() }),
            ] {
                let (account, session, user) = without_password(&harness).await;

                let (status, error) = send(&harness, &session, None, body).await;
                assert_eq!(status, Status::Unauthorized);
                assert!(matches!(error, Some(ErrorType::InvalidCredentials)));

                assert_eq!(
                    stored_attempts(&harness, &account).await,
                    None,
                    "no attempt may be counted"
                );
                assert_eq!(stored_username(&harness, &user).await, user.username);
            }
        })
    }

    /// An account with no password changes its username with a validated
    /// ticket and no password field, and the ticket is used up
    #[test]
    fn no_password_account_changes_username_with_a_ticket() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session, user) = without_password(&harness).await;
            let ticket = saved_ticket(&harness, &account.id, true).await;
            let username = TestHarness::rand_string();

            let (status, _) = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "username": username.clone() }),
            )
            .await;

            assert_eq!(status, Status::Ok);
            assert_eq!(stored_username(&harness, &user).await, username);
            assert_eq!(stored_attempts(&harness, &account).await, None);
            assert!(!ticket_exists(&harness, &ticket).await, "the ticket is single use");
        })
    }

    /// A validated ticket minted on another account proves nothing here,
    /// and it is not burned
    #[test]
    fn no_password_account_refuses_a_foreign_ticket() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session, user) = without_password(&harness).await;
            let (other, _, _) = harness.new_user().await;
            let ticket = saved_ticket(&harness, &other.id, true).await;

            let (status, error) = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "username": TestHarness::rand_string() }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));
            assert_eq!(stored_username(&harness, &user).await, user.username);
            assert_eq!(stored_attempts(&harness, &account).await, None);
            assert!(ticket_exists(&harness, &ticket).await);
        })
    }

    /// A ticket that was never validated is no proof
    #[test]
    fn no_password_account_refuses_an_unvalidated_ticket() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session, user) = without_password(&harness).await;
            let ticket = saved_ticket(&harness, &account.id, false).await;

            let (status, error) = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "username": TestHarness::rand_string() }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));
            assert_eq!(stored_username(&harness, &user).await, user.username);
        })
    }

    /// A password account that sends neither proof is refused, and since
    /// nothing was guessed nothing is counted
    #[test]
    fn neither_ticket_nor_password_is_refused() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session, user) = harness.new_user().await;

            let (status, error) = send(
                &harness,
                &session,
                None,
                json!({ "username": TestHarness::rand_string() }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));
            assert_eq!(stored_username(&harness, &user).await, user.username);
            assert_eq!(stored_attempts(&harness, &account).await, None);
        })
    }

    /// A validated ticket does not stand in for the password of an account
    /// that has one. No password was sent, so no attempt is counted
    #[test]
    fn ticket_alone_is_refused_for_a_password_account() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session, user) = harness.new_user().await;
            let ticket = saved_ticket(&harness, &account.id, true).await;

            let (status, error) = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "username": TestHarness::rand_string() }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));
            assert_eq!(stored_username(&harness, &user).await, user.username);
            assert_eq!(
                stored_attempts(&harness, &account).await,
                None,
                "nothing was guessed"
            );
        })
    }

    /// A wrong password is refused and counted when a ticket comes with it
    #[test]
    fn sent_password_is_checked_even_with_a_ticket() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (account, session, user) = harness.new_user().await;
            let ticket = saved_ticket(&harness, &account.id, true).await;

            let (status, error) = send(
                &harness,
                &session,
                Some(&ticket),
                json!({ "username": TestHarness::rand_string(), "password": "wrong password" }),
            )
            .await;

            assert_eq!(status, Status::Unauthorized);
            assert!(matches!(error, Some(ErrorType::InvalidCredentials)));
            assert_eq!(stored_username(&harness, &user).await, user.username);
            assert_eq!(stored_attempts(&harness, &account).await, Some(1));
        })
    }
}
