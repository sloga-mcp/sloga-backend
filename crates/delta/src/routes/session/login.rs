//! Login to an account
//! POST /session/login
use std::time::Duration;

use tokio::time::sleep;
use iso8601_timestamp::Timestamp;
use revolt_database::{
    util::{email::normalise_email, password::assert_safe},
    Account, Database, DeletionInfo, EmailVerification, MFATicket,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;

/// # Login
///
/// Login to an account.
#[openapi(tag = "Session")]
#[post("/login", data = "<data>")]
pub async fn login(
    db: &State<Database>,
    data: Json<v0::DataLogin>,
) -> Result<Json<v0::ResponseLogin>> {
    // Random jitter from 0-1000ms
    sleep(Duration::from_millis((rand::random::<f32>() * 1000.) as u64)).await;

    let (account, name) = match data.into_inner() {
        v0::DataLogin::Email {
            email,
            password,
            friendly_name,
        } => {
            // Try to find the account we want
            let email_normalised = normalise_email(email);

            // Lookup the email in database
            if let Some(mut account) = db
                .fetch_account_by_normalised_email(&email_normalised)
                .await?
            {
                // Verification and password strength are only checked once
                // the password is proven (below): before that, an existing
                // email must get the same answer as a missing one

                // Check for account lockout (read-only; a request that
                // arrives while locked does not extend the lockout)
                if let Some(lockout) = &account.lockout {
                    if let Some(expiry) = lockout.expiry {
                        if expiry > Timestamp::now_utc() {
                            return Err(create_error!(LockedOut));
                        }
                    }
                }

                // Attempts are counted atomically in the database (3 free,
                // then locked for 1 minute, 5 minutes on the 4th and 1 hour
                // on each subsequent one); `account.save` never writes the
                // lockout
                if !account.mfa.is_active() {
                    // The password is the only factor: count the attempt
                    // BEFORE verifying it, so concurrent guesses cannot
                    // share a stale counter
                    db.reserve_lockout_attempt(&account.id).await?;

                    // A wrong password stays counted
                    account.verify_password(&password)?;

                    // The reservation always leaves a lockout behind, and
                    // the copy fetched above predates it, so clear it
                    // unconditionally
                    db.set_lockout(&account.id, None).await?;
                    account.lockout = None;

                    assert_login_allowed(&account, &password).await?;
                } else {
                    // Count only a wrong password: counting a correct one
                    // would lock users out over MFA typos. The lockout is
                    // cleared only once MFA passes, so a correct password
                    // cannot reset the MFA attempt count.
                    if let Err(err) = account.verify_password(&password) {
                        db.bump_lockout_count(&account.id).await?;
                        return Err(err);
                    }

                    assert_login_allowed(&account, &password).await?;

                    // Create a new ticket
                    let mut ticket = MFATicket::new(account.id, false);
                    ticket.populate(&account.mfa).await;
                    ticket.save(db).await?;

                    // Return applicable methods
                    return Ok(Json(v0::ResponseLogin::MFA {
                        ticket: ticket.token,
                        allowed_methods: account
                            .mfa
                            .get_methods()
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                    }));
                }

                (account, friendly_name)
            } else {
                return Err(create_error!(InvalidCredentials));
            }
        }
        v0::DataLogin::MFA {
            mfa_ticket,
            mfa_response,
            friendly_name,
        } => {
            // Resolve the MFA ticket
            let ticket = db
                .fetch_ticket_by_token(&mfa_ticket)
                .await?;

            // Find the corresponding account
            let mut account = db.fetch_account(&ticket.account_id).await?;

            // Check for account lockout (read-only), before either path
            if let Some(lockout) = &account.lockout {
                if let Some(expiry) = lockout.expiry {
                    if expiry > Timestamp::now_utc() {
                        return Err(create_error!(LockedOut));
                    }
                }
            }

            // Verify the MFA response
            if let Some(mfa_response) = mfa_response {
                // Counts one ticket attempt and one lockout attempt
                // atomically; on success the ticket is already claimed
                // (single use) and the lockout cleared
                account
                    .consume_mfa_response(db, mfa_response, Some(&ticket))
                    .await?;
            } else if ticket.authorised {
                // Single use: of two concurrent requests only one claims
                // the ticket, and the other gets no session
                ticket.claim(db).await?;
            } else {
                return Err(create_error!(InvalidToken));
            }

            (account, friendly_name)
        }
    };

    // Generate a session name
    let name = name.unwrap_or_else(|| "Unknown".to_string());

    // A confirmed (or finished) deletion refuses the login exactly as a
    // disabled account does. This runs BEFORE the `disabled` check: a stale
    // whole-document save can write `disabled` back to false while the
    // deletion stays Scheduled, and the suspension branch below could lift
    // `disabled` itself. Only a pending (WaitingForVerification) request is
    // cancelled by signing in, in `create_session`
    if matches!(
        account.deletion,
        Some(DeletionInfo::Scheduled { .. } | DeletionInfo::Deleted)
    ) {
        return Ok(Json(v0::ResponseLogin::Disabled {
            user_id: account.id,
            suspended_until: None,
        }));
    }

    // Prevent disabled accounts from logging in;
    // timed suspensions that have expired are lifted here
    if account.disabled {
        let suspended_until = match db.fetch_user(&account.id).await {
            Ok(mut user) => match user.suspended_until {
                Some(until) if until <= Timestamp::now_utc() => {
                    user.unsuspend(db).await?;
                    None
                }
                until => until,
            },
            Err(_) => None,
        };

        // Unless the suspension just expired, refuse the login
        if suspended_until.is_some() || db.fetch_account(&account.id).await?.disabled {
            return Ok(Json(v0::ResponseLogin::Disabled {
                user_id: account.id,
                suspended_until,
            }));
        }
    }

    // Create and return a new session
    Ok(Json(v0::ResponseLogin::Success(
        account.create_session(db, name).await?.into(),
    )))
}

/// Checks that only an existing account can fail, so they run once its
/// password is proven
async fn assert_login_allowed(account: &Account, password: &str) -> Result<()> {
    // Make sure the account has been verified
    if let EmailVerification::Pending { .. } = account.verification {
        return Err(create_error!(UnverifiedAccount));
    }

    // Make sure password has not been compromised
    assert_safe(password).await
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        Account, DeletionInfo, EmailVerification, Lockout, MFATicket, Totp,
        events::client::EventV1,
    };
    use crate::{rocket, util::test::{Mail, TestHarness}};
    use rocket::http::{ContentType, Status};
    use revolt_models::v0;
    use revolt_result::{Error, ErrorType};

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let mut harness = TestHarness::new().await;

        let account = Account::new(
            &harness.db,
            "example@validemail.com".into(),
            "password_insecure".into(),
            false,
        )
        .await
        .unwrap();

        // Both waits below MUST match on this account. The harness
        // psubscribes `*` against a SHARED redis, so `global` also carries
        // events published by every other test process nextest is running in
        // parallel — with a `|_| true` predicate this wait swallowed a
        // neighbouring test's account/session event, leaving our own
        // CreateAccount queued, and the CreateSession assertion at the bottom
        // then popped that stale CreateAccount and failed.
        harness
            .wait_for_event("global", |event| {
                matches!(event, EventV1::CreateAccount { account: created } if created.id == account.id)
            })
            .await;

        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "EXAMPLE@validemail.com",
                    "password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(res.into_json::<v0::Session>().await.is_some());

        let event = harness
            .wait_for_event("global", |event| {
                matches!(event, EventV1::CreateSession { session } if session.user_id == account.id)
            })
            .await;

        if !matches!(event, EventV1::CreateSession { .. }) {
            panic!("Received incorrect event type. {:?}", event);
        }
    }

    #[test]
    fn success_totp_mfa() {
        crate::util::test::rt().block_on(success_totp_mfa_case())
    }

    async fn success_totp_mfa_case() {
        let harness = TestHarness::new().await;
        let (mut account, _, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": &account.email,
                    "password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        let response = serde_json::from_str::<v0::ResponseLogin>(
            &res.into_string().await.unwrap(),
        )
        .expect("`ResponseLogin`");

        if let v0::ResponseLogin::MFA {
            ticket,
            allowed_methods,
        } = response
        {
            assert!(allowed_methods.contains(&v0::MFAMethod::Totp));

            let res = harness.client
                .post("/auth/session/login")
                .header(ContentType::JSON)
                .body(
                    json!({
                        "mfa_ticket": ticket,
                        "mfa_response": {
                            "totp_code": totp.generate_code().expect("totp code")
                        }
                    })
                    .to_string(),
                )
                .dispatch()
                .await;

            assert_eq!(res.status(), Status::Ok);
            assert!(serde_json::from_str::<v0::Session>(&res.into_string().await.unwrap()).is_ok());
        } else {
            panic!("expected `ResponseLogin::MFA`")
        }
    }

    #[test]
    fn success_totp_stored_mfa() {
        crate::util::test::rt().block_on(success_totp_stored_mfa_case())
    }

    async fn success_totp_stored_mfa_case() {
        let harness = TestHarness::new().await;
        let (mut account, _, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let mut ticket = MFATicket::new(account.id.to_string(), true);
        ticket.last_totp_code = Some("token from earlier".into());
        ticket.save(&harness.db).await.unwrap();

        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "mfa_ticket": ticket.token,
                    "mfa_response": {
                        "totp_code": "token from earlier"
                    }
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(serde_json::from_str::<v0::Session>(&res.into_string().await.unwrap()).is_ok());
    }

    #[test]
    fn fail_totp_invalid_mfa() {
        crate::util::test::rt().block_on(fail_totp_invalid_mfa_case())
    }

    async fn fail_totp_invalid_mfa_case() {
        let harness = TestHarness::new().await;
        let (mut account, _, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .post("/auth/session/login")
            .json(
                &json!({
                    "email": account.email.clone(),
                    "password": "password_insecure"
                })
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        let response = serde_json::from_str::<v0::ResponseLogin>(
            &res.into_string().await.unwrap(),
        )
        .expect("`ResponseLogin`");

        if let v0::ResponseLogin::MFA {
            ticket,
            allowed_methods,
        } = response
        {
            assert!(allowed_methods.contains(&v0::MFAMethod::Totp));

            let res = harness.client
                .post("/auth/session/login")
                .json(
                    &json!({
                        "mfa_ticket": ticket,
                        "mfa_response": {
                            "totp_code": "some random data"
                        }
                    })
                )
                .dispatch()
                .await;

            assert_eq!(res.status(), Status::Unauthorized);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidToken,
        ));
        } else {
            panic!("expected `ResponseLogin::MFA`")
        }
    }

    #[test]
    fn fail_invalid_user() {
        crate::util::test::rt().block_on(fail_invalid_user_case())
    }

    async fn fail_invalid_user_case() {
        let harness = TestHarness::new().await;

        let res = harness.client
            .post("/auth/session/login")
            .json(
                &json!({
                    "email": "example@validemail.com",
                    "password": "password_insecure"
                })
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidCredentials,
        ));
    }

    #[test]
    fn fail_disabled_account() {
        crate::util::test::rt().block_on(fail_disabled_account_case())
    }

    async fn fail_disabled_account_case() {
        let harness = TestHarness::new().await;

        let mut account = Account::new(
            &harness.db,
            "example@validemail.com".into(),
            "password_insecure".into(),
            false,
        )
        .await
        .unwrap();

        account.disabled = true;
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "example@validemail.com",
                    "password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        let response = serde_json::from_str::<v0::ResponseLogin>(
            &res.into_string().await.unwrap(),
        )
        .expect("`ResponseLogin`");

        assert!(matches!(
            response,
            v0::ResponseLogin::Disabled { .. }
        ));
    }

    #[test]
    fn fail_unverified_account() {
        crate::util::test::rt().block_on(fail_unverified_account_case())
    }

    async fn fail_unverified_account_case() {
        let harness = TestHarness::new().await;

        let mut account = Account::new(
            &harness.db,
            "example@validemail.com".into(),
            "password_insecure".into(),
            false,
        )
        .await
        .unwrap();

        account.verification = EmailVerification::Pending {
            token: "".to_string(),
            expiry: Timestamp::now_utc(),
        };

        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "example@validemail.com",
                    "password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Forbidden);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::UnverifiedAccount,
        ));
    }

    #[test]
    fn fail_locked_account() {
        crate::util::test::rt().block_on(fail_locked_account_case())
    }

    async fn fail_locked_account_case() {
        let harness = TestHarness::new().await;

        let account = Account::new(
            &harness.db,
            "example@validemail.com".into(),
            "password_insecure".into(),
            false,
        )
        .await
        .unwrap();

        account.save(&harness.db).await.unwrap();


        // Attempt 1
        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "example@validemail.com",
                    "password": "wrong_password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidCredentials,
        ));

        // Attempt 2
        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "example@validemail.com",
                    "password": "wrong_password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidCredentials,
        ));

        // Attempt 3
        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "example@validemail.com",
                    "password": "wrong_password"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidCredentials,
        ));

        // Attempt 4: Locked Out
        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "example@validemail.com",
                    "password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Forbidden);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::LockedOut,
        ));
        // Pretend it expired (`save` never writes the lockout)
        harness
            .db
            .set_lockout(
                &account.id,
                Some(Lockout {
                    attempts: 9001,
                    expiry: Some(Timestamp::now_utc()),
                }),
            )
            .await
            .unwrap();

        // Once it expires, we can log in.
        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "email": "example@validemail.com",
                    "password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(serde_json::from_str::<v0::Session>(&res.into_string().await.unwrap()).is_ok());
    }

    /// Status and raw body of an email login
    async fn sec009_login(harness: &TestHarness, email: &str, password: &str) -> (Status, String) {
        let res = harness
            .client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(json!({ "email": email, "password": password }).to_string())
            .dispatch()
            .await;

        let status = res.status();
        (status, res.into_string().await.expect("a response body"))
    }

    fn sec009_email() -> String {
        format!("{}@validemail.com", TestHarness::rand_string())
    }

    /// A fresh account, so no earlier attempt counts toward its lockout
    async fn sec009_account(
        harness: &TestHarness,
        password: &str,
        pending: bool,
        totp: bool,
    ) -> Account {
        let mut account = Account::new(&harness.db, sec009_email(), password.into(), false)
            .await
            .unwrap();

        if pending {
            account.verification = EmailVerification::Pending {
                token: "".to_string(),
                expiry: Timestamp::now_utc(),
            };
        }

        if totp {
            account.mfa.totp_token = Totp::Enabled {
                secret: "secret".to_string(),
            };
        }

        account.save(&harness.db).await.unwrap();
        account
    }

    /// The answer for an existing email must equal the answer for a missing
    /// one, byte for byte
    async fn sec009_assert_matches_unknown_email(
        harness: &TestHarness,
        account: &Account,
        password: &str,
    ) {
        let known = sec009_login(harness, &account.email, password).await;
        let unknown = sec009_login(harness, &sec009_email(), password).await;

        assert_eq!(known, unknown);
        assert_eq!(known.0, Status::Unauthorized);
        assert!(matches!(
            serde_json::from_str::<Error>(&known.1).unwrap().error_type,
            ErrorType::InvalidCredentials,
        ));
    }

    #[test]
    fn sec009_wrong_password_matches_unknown_email() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let account = sec009_account(&harness, "password_insecure", false, false).await;
            sec009_assert_matches_unknown_email(&harness, &account, "wrong_password").await;
        })
    }

    #[test]
    fn sec009_short_password_matches_unknown_email() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let account = sec009_account(&harness, "password_insecure", false, false).await;
            sec009_assert_matches_unknown_email(&harness, &account, "a").await;
        })
    }

    #[test]
    fn sec009_short_password_with_mfa_matches_unknown_email() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let account = sec009_account(&harness, "password_insecure", false, true).await;
            sec009_assert_matches_unknown_email(&harness, &account, "a").await;
        })
    }

    #[test]
    fn sec009_unverified_wrong_password_matches_unknown_email() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let account = sec009_account(&harness, "password_insecure", true, false).await;
            sec009_assert_matches_unknown_email(&harness, &account, "wrong_password").await;
        })
    }

    #[test]
    fn sec009_unverified_right_password_is_still_refused() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let account = sec009_account(&harness, "password_insecure", true, false).await;

            let (status, body) = sec009_login(&harness, &account.email, "password_insecure").await;
            assert_eq!(status, Status::Forbidden);
            assert!(matches!(
                serde_json::from_str::<Error>(&body).unwrap().error_type,
                ErrorType::UnverifiedAccount,
            ));
        })
    }

    #[test]
    fn sec009_unverified_right_password_with_mfa_gets_no_ticket() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let account = sec009_account(&harness, "password_insecure", true, true).await;

            let (status, body) = sec009_login(&harness, &account.email, "password_insecure").await;
            assert_eq!(status, Status::Forbidden);
            assert!(matches!(
                serde_json::from_str::<Error>(&body).unwrap().error_type,
                ErrorType::UnverifiedAccount,
            ));
        })
    }

    #[test]
    fn sec009_right_short_password_is_still_refused() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            // Account::new does not check the password, so an old weak one
            // can be set up directly
            let account = sec009_account(&harness, "short", false, false).await;

            let (status, body) = sec009_login(&harness, &account.email, "short").await;
            assert_eq!(status, Status::BadRequest);
            assert!(matches!(
                serde_json::from_str::<Error>(&body).unwrap().error_type,
                ErrorType::ShortPassword,
            ));
        })
    }

    /// The variant only: MongoDB keeps timestamps to the millisecond, so a
    /// seeded value does not compare equal to what is read back
    fn deletion_kind(deletion: &Option<DeletionInfo>) -> &'static str {
        match deletion {
            None => "none",
            Some(DeletionInfo::WaitingForVerification { .. }) => "pending",
            Some(DeletionInfo::Scheduled { .. }) => "scheduled",
            Some(DeletionInfo::Deleted) => "deleted",
        }
    }

    /// A fresh account under its own mailbox, not disabled, with `deletion`
    /// seeded through `set_account_deletion` (`save_account` never writes it)
    ///
    /// Returns the account as stored.
    async fn deletion_account(harness: &TestHarness, deletion: Option<DeletionInfo>) -> Account {
        let account = sec009_account(harness, "password_insecure", false, false).await;
        harness
            .db
            .set_account_deletion(&account.id, deletion.clone())
            .await
            .unwrap();

        let stored = harness.db.fetch_account(&account.id).await.unwrap();
        assert_eq!(
            deletion_kind(&stored.deletion),
            deletion_kind(&deletion),
            "the seed must be stored"
        );
        assert!(!stored.disabled);
        stored
    }

    fn pending(expiry: Timestamp) -> Option<DeletionInfo> {
        Some(DeletionInfo::WaitingForVerification {
            token: TestHarness::rand_string(),
            expiry,
        })
    }

    fn soon() -> Timestamp {
        Timestamp::now_utc() + Duration::seconds(3600)
    }

    fn long_ago() -> Timestamp {
        Timestamp::now_utc() - Duration::seconds(3600)
    }

    /// Log in with the password and return the session it created
    async fn deletion_login_succeeds(harness: &TestHarness, account: &Account) -> v0::Session {
        let (status, body) = sec009_login(harness, &account.email, "password_insecure").await;
        assert_eq!(status, Status::Ok, "login refused: {}", body);

        match serde_json::from_str::<v0::ResponseLogin>(&body).expect("`ResponseLogin`") {
            v0::ResponseLogin::Success(session) => {
                assert_eq!(session.user_id, account.id);
                session
            }
            other => panic!("expected `ResponseLogin::Success`, got {:?}", other),
        }
    }

    /// Every mail maildev holds for `mailbox`, left in place (unlike
    /// `TestHarness::assert_email`, which deletes them), so it can be counted
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
            .filter(|mail| mail.envelope.to.iter().any(|to| to.address == mailbox))
            .collect()
    }

    async fn stored_deletion(harness: &TestHarness, account_id: &str) -> Option<DeletionInfo> {
        harness.db.fetch_account(account_id).await.unwrap().deletion
    }

    async fn session_ids(harness: &TestHarness, account_id: &str) -> Vec<String> {
        let sessions = harness.db.fetch_sessions(account_id).await.unwrap();
        sessions.into_iter().map(|session| session.id).collect()
    }

    /// Signing in cancels a live deletion request and emails the user
    #[test]
    fn deletion_pending_is_cancelled_by_login() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let account = deletion_account(&harness, pending(soon())).await;

            let session = deletion_login_succeeds(&harness, &account).await;

            assert_eq!(
                stored_deletion(&harness, &account.id).await,
                None,
                "signing in must cancel the pending deletion"
            );
            assert_eq!(session_ids(&harness, &account.id).await, vec![session.id]);

            let (mail, url) = harness.assert_email(&account.email).await;
            assert_eq!(mail.subject, "deletion_cancelled");
            assert_eq!(url, "", "the TEST_DB cancel template has an empty url");
        })
    }

    /// An expired request is cleared too, but it was dead already, so no
    /// cancel email is sent for it
    ///
    /// Absence is proven against a marker: a second login, after a live
    /// request is seeded, sends exactly one cancel email. Once that has
    /// arrived (plus a grace period for the earlier send, which would have
    /// been started first), the mailbox must hold that one mail only.
    #[test]
    fn deletion_expired_is_cleared_without_email() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let account = deletion_account(&harness, pending(long_ago())).await;

            deletion_login_succeeds(&harness, &account).await;
            assert_eq!(
                stored_deletion(&harness, &account.id).await,
                None,
                "signing in must clear an expired pending deletion"
            );

            // The marker: a live request, cancelled by a second login
            harness
                .db
                .set_account_deletion(&account.id, pending(soon()))
                .await
                .unwrap();
            deletion_login_succeeds(&harness, &account).await;

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            while mail_to(&account.email).await.is_empty() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the marker cancel email never reached {}",
                    account.email
                );
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let mails = mail_to(&account.email).await;
            let subjects: Vec<&str> = mails.iter().map(|mail| mail.subject.as_str()).collect();
            assert_eq!(
                subjects,
                vec!["deletion_cancelled"],
                "only the live request may send a cancel email"
            );

            // Clean the mailbox up
            harness.assert_email(&account.email).await;
        })
    }

    /// A confirmed or finished deletion refuses the login as a disabled
    /// account does, even with `disabled` false (a stale whole-document save
    /// can write it back), and stores no session
    #[test]
    fn deletion_scheduled_or_deleted_is_refused() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            for deletion in [
                DeletionInfo::Scheduled { after: soon() },
                DeletionInfo::Deleted,
            ] {
                let account = deletion_account(&harness, Some(deletion.clone())).await;

                let (status, body) =
                    sec009_login(&harness, &account.email, "password_insecure").await;
                assert_eq!(status, Status::Ok, "{:?}: {}", deletion, body);
                match serde_json::from_str::<v0::ResponseLogin>(&body).expect("`ResponseLogin`") {
                    v0::ResponseLogin::Disabled {
                        user_id,
                        suspended_until,
                    } => {
                        assert_eq!(user_id, account.id);
                        assert_eq!(suspended_until, None);
                    }
                    other => panic!("{:?}: expected `Disabled`, got {:?}", deletion, other),
                }

                assert!(
                    session_ids(&harness, &account.id).await.is_empty(),
                    "{:?}: a refused login must store no session",
                    deletion
                );
                // `account` is the stored copy, so this compares like with like
                let stored = harness.db.fetch_account(&account.id).await.unwrap();
                assert_eq!(
                    stored.deletion, account.deletion,
                    "{:?}: a refused login changes nothing",
                    deletion
                );
                assert!(!stored.disabled);
            }
        })
    }

    /// The refusal sits after both login paths, so an authorised MFA ticket
    /// for a Scheduled account gets no session either
    #[test]
    fn deletion_scheduled_is_refused_after_mfa() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let account =
                deletion_account(&harness, Some(DeletionInfo::Scheduled { after: soon() })).await;

            let mut ticket = MFATicket::new(account.id.clone(), false);
            ticket.authorised = true;
            ticket.save(&harness.db).await.unwrap();

            let res = harness
                .client
                .post("/auth/session/login")
                .header(ContentType::JSON)
                .body(json!({ "mfa_ticket": ticket.token }).to_string())
                .dispatch()
                .await;

            assert_eq!(res.status(), Status::Ok);
            let response =
                serde_json::from_str::<v0::ResponseLogin>(&res.into_string().await.unwrap())
                    .expect("`ResponseLogin`");
            match response {
                v0::ResponseLogin::Disabled { user_id, .. } => assert_eq!(user_id, account.id),
                other => panic!("expected `Disabled`, got {:?}", other),
            }
            assert!(session_ids(&harness, &account.id).await.is_empty());
        })
    }

    /// Login never waits on, or fails with, the cancel email: SMTP points at
    /// a closed port here
    ///
    /// `overwrite_config` is process-wide and works once per process, so
    /// this relies on nextest's one-process-per-test (as `change_email`'s
    /// tests do). It runs before anything reads the config, because
    /// `config()` caches for 30 s.
    #[test]
    fn deletion_cancel_login_succeeds_with_smtp_down() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|config| config.api.smtp.port = Some(1)).await;

            let harness = TestHarness::new().await;
            let account = deletion_account(&harness, pending(soon())).await;

            let session = deletion_login_succeeds(&harness, &account).await;
            assert_eq!(
                stored_deletion(&harness, &account.id).await,
                None,
                "the cancel must not depend on the email"
            );
            assert_eq!(session_ids(&harness, &account.id).await, vec![session.id]);
        })
    }
}
