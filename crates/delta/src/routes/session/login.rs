//! Login to an account
//! POST /session/login
use std::time::Duration;

use tokio::time::sleep;
use iso8601_timestamp::Timestamp;
use revolt_database::{
    util::password::assert_safe,
    Account, Database, DeletionInfo, EmailVerification, MFATicket, MfaPurpose,
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
            // Look the email up. The wrapper normalises it and never matches
            // an account that has no email, so the stand-in address of such
            // an account answers as a missing email does
            if let Some(mut account) = Account::fetch_by_email(db, &email).await? {
                // An account with no password (created through Google or
                // Apple) answers as a missing email does: there is nothing
                // to verify, and counting the attempt would let anyone who
                // knows the email lock its owner out. This sits before the
                // lockout check, so the answer is the same while locked.
                //
                // The same for an account with no email, whatever password
                // it has: nobody signs in to it by email. The lookup above
                // cannot return one; this holds if that ever changes.
                if account.password_absent || account.real_email().is_none() {
                    return Err(create_error!(InvalidCredentials));
                }

                // Verification and password strength are only checked once
                // the password is proven (below): before that, an existing
                // email must get the same answer as a missing one

                // Check for account lockout (read-only; a request that
                // arrives while locked does not extend the lockout)
                assert_not_locked_out(&account)?;

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
            assert_not_locked_out(&account)?;

            // Verify the MFA response
            if let Some(mfa_response) = mfa_response {
                // Counts one ticket attempt and one lockout attempt
                // atomically; on success the ticket is already claimed
                // (single use) and the lockout cleared
                account
                    .consume_mfa_response(db, mfa_response, MfaPurpose::LoginStep(&ticket))
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

    // The proof is checked: the rest is the shared gate
    complete_login(db, account, name).await.map(Json)
}

/// Refuses an account that is locked out. Read-only: a request that arrives
/// while locked does not extend the lockout.
///
/// With `complete_login`, this is the one shared login gate. Every sign-in
/// path whose proof can be guessed (password, MFA ticket) must call
/// `assert_not_locked_out` BEFORE it checks any proof and `complete_login`
/// AFTER the proof passes, and must never build a session any other way.
///
/// A passkey sign-in (`routes/passkey/login.rs`) calls `complete_login`
/// only: a signature cannot be guessed, and honouring the lockout there
/// would let anyone who knows the email keep a passkey user out.
///
/// Counting attempts (`reserve_lockout_attempt`, `bump_lockout_count`,
/// `set_lockout`) differs per kind of proof and stays with the caller.
pub(crate) fn assert_not_locked_out(account: &Account) -> Result<()> {
    if let Some(lockout) = &account.lockout {
        if let Some(expiry) = lockout.expiry {
            if expiry > Timestamp::now_utc() {
                return Err(create_error!(LockedOut));
            }
        }
    }

    Ok(())
}

/// Finishes a sign-in whose proof has already been checked: refuses an
/// account that is being deleted or is disabled (lifting a timed suspension
/// that has expired), and only then creates the session.
///
/// With `assert_not_locked_out`, this is the one shared login gate. Every
/// sign-in path (password, MFA ticket, passkey) must call `complete_login`
/// AFTER the proof passes, and must never build a session any other way;
/// the password and MFA ticket paths also call `assert_not_locked_out`
/// BEFORE they check any proof (a passkey sign-in does not, see there).
///
/// `assert_login_allowed` (verification, password strength) is not part of
/// this gate: it needs the password, so the password path runs it itself.
/// The passkey path checks verification itself, for the same answer.
pub(crate) async fn complete_login(
    db: &Database,
    account: Account,
    name: Option<String>,
) -> Result<v0::ResponseLogin> {
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
        return Ok(login_refused(account.id, None));
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
            return Ok(login_refused(account.id, suspended_until));
        }
    }

    // Create and return a new session
    Ok(v0::ResponseLogin::Success(
        account.create_session(db, name).await?.into(),
    ))
}

/// The answer a deleted, disabled or suspended account gets instead of a
/// session
fn login_refused(user_id: String, suspended_until: Option<Timestamp>) -> v0::ResponseLogin {
    v0::ResponseLogin::Disabled {
        user_id,
        suspended_until,
    }
}

/// Checks that only an existing account can fail, so they run once its
/// password is proven
async fn assert_login_allowed(account: &Account, password: &str) -> Result<()> {
    // Make sure the account has been verified. Only an account found by its
    // email gets here, so it has one; an account with no email is stored
    // `Verified` and is refused before this, at the lookup
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
        Account, DeletionInfo, EmailVerification, Lockout, MFAMethod, MFATicket, PartialUser,
        Passkey, Totp,
        events::client::EventV1,
    };
    use crate::{
        rocket,
        util::test::{without_comments, without_whitespace, Mail, TestHarness},
    };
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

    /// R8: the password step of a login never offers a passkey. An account
    /// with TOTP, recovery codes and a stored passkey is told exactly
    /// `[Totp, Recovery]`; old apps would render a blank row for anything
    /// else.
    #[test]
    fn mfa_login_never_offers_a_stored_passkey() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (mut account, _, _) = harness.new_user().await;

            account.mfa.totp_token = Totp::Enabled {
                secret: "secret".to_string(),
            };
            account.mfa.recovery_codes = vec!["abcde-fghjk".to_string()];
            account.save(&harness.db).await.unwrap();

            harness
                .db
                .insert_passkey(&Passkey::new(
                    account.id.clone(),
                    format!("credential-{}", TestHarness::rand_string()),
                    format!("handle-{}", account.id),
                    "{}".to_string(),
                    "Phone".to_string(),
                ))
                .await
                .unwrap();

            // The control: the stored account has TOTP, recovery codes and a
            // passkey. (Passkeys are off in this test's config, so the list
            // that mints a ticket would not show the passkey either.)
            let stored = harness.db.fetch_account(&account.id).await.unwrap();
            assert_eq!(
                stored.mfa.get_methods(),
                vec![MFAMethod::Totp, MFAMethod::Recovery],
                "the control: the stored account has TOTP and recovery codes"
            );
            assert_eq!(
                harness.db.count_passkeys(&account.id).await.unwrap(),
                1,
                "the control: the passkey is stored"
            );

            let (status, body) = sec009_login(&harness, &account.email, "password_insecure").await;
            assert_eq!(status, Status::Ok, "login refused: {}", body);

            match serde_json::from_str::<v0::ResponseLogin>(&body).expect("`ResponseLogin`") {
                v0::ResponseLogin::MFA {
                    allowed_methods, ..
                } => assert_eq!(
                    allowed_methods,
                    vec![v0::MFAMethod::Totp, v0::MFAMethod::Recovery],
                    "the login MFA step offers exactly TOTP and recovery"
                ),
                other => panic!("expected `ResponseLogin::MFA`, got {:?}", other),
            }
        })
    }

    /// The code that ships in `source`: everything above its test module,
    /// if it has one, without comments or whitespace. So neither a comment
    /// nor this test module's own text can satisfy or trip a pin below.
    fn r8_shipping(source: &str) -> String {
        let shipping = source.find("#[cfg(test)]").map_or(source, |end| &source[..end]);
        without_whitespace(&without_comments(shipping))
    }

    /// R8, for every route that answers a login with `ResponseLogin::MFA`:
    /// `allowed_methods` is built from `account.mfa.get_methods()` and
    /// nothing else, and `ticket_methods` (which offers a passkey) is not
    /// used in the file at all.
    #[test]
    fn mfa_login_responses_are_built_from_get_methods() {
        const BUILT: &str =
            "allowed_methods:account.mfa.get_methods().into_iter().map(Into::into).collect()";

        for (file, source) in [
            ("session/login.rs", include_str!("login.rs")),
            (
                "oauth/google_callback.rs",
                include_str!("../oauth/google_callback.rs"),
            ),
            (
                "oauth/apple_callback.rs",
                include_str!("../oauth/apple_callback.rs"),
            ),
        ] {
            let code = r8_shipping(source);

            assert!(
                !code.contains("ticket_methods("),
                "{file}: a login route must not call `ticket_methods`"
            );

            let fields = code.matches("allowed_methods:").count();
            assert!(fields > 0, "{file}: no `allowed_methods` field found");
            assert_eq!(
                code.matches(BUILT).count(),
                fields,
                "{file}: every `allowed_methods` must come from `account.mfa.get_methods()`"
            );
        }
    }

    /// The control for the pin above: the same checks refuse a route that
    /// builds the list from `ticket_methods`, and a comment does not count
    #[test]
    fn r8_shipping_reads_code_only() {
        let bad = r8_shipping(
            "allowed_methods: account\n    .ticket_methods(db)\n    .await?\n    .into_iter()\n    .map(Into::into)\n    .collect(),\n#[cfg(test)]\nmod tests { account.mfa.get_methods() }",
        );
        assert!(bad.contains("ticket_methods("));
        assert_eq!(bad.matches("allowed_methods:").count(), 1);
        assert!(!bad.contains("get_methods()"), "the test module is cut off");

        let commented = r8_shipping("// account.ticket_methods(db)\nlet a = 1;");
        assert_eq!(commented, "leta=1;");
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

    /// A confirmed or finished deletion refuses the login, even with
    /// `disabled` false (a stale whole-document save can write it back), and
    /// stores no session
    ///
    /// A confirmed deletion answers as a disabled account does. A finished
    /// one has no email any more (`Account::real_email`), so the email
    /// lookup does not find it and it answers as a missing email does; the
    /// gate's own refusal of it is row (e) of `login_gate_table`.
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

                if matches!(deletion, DeletionInfo::Deleted) {
                    let unknown =
                        sec009_login(&harness, &sec009_email(), "password_insecure").await;
                    assert_eq!((status, body), unknown, "{:?}", deletion);
                    assert_eq!(status, Status::Unauthorized, "{:?}", deletion);
                } else {
                    assert_eq!(status, Status::Ok, "{:?}: {}", deletion, body);
                    match serde_json::from_str::<v0::ResponseLogin>(&body)
                        .expect("`ResponseLogin`")
                    {
                        v0::ResponseLogin::Disabled {
                            user_id,
                            suspended_until,
                        } => {
                            assert_eq!(user_id, account.id);
                            assert_eq!(suspended_until, None);
                        }
                        other => panic!("{:?}: expected `Disabled`, got {:?}", deletion, other),
                    }
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

    /// Run the shared gate on the account as stored, expecting a session
    async fn gate_succeeds(harness: &TestHarness, account_id: &str, row: &str) -> v0::Session {
        let stored = harness.db.fetch_account(account_id).await.unwrap();
        super::assert_not_locked_out(&stored)
            .unwrap_or_else(|error| panic!("{}: locked out: {:?}", row, error));

        match super::complete_login(&harness.db, stored, None).await {
            Ok(v0::ResponseLogin::Success(session)) => {
                assert_eq!(session.user_id, account_id, "{}", row);
                session
            }
            other => panic!("{}: expected `Success`, got {:?}", row, other),
        }
    }

    /// Run the shared gate on the account as stored, expecting a refusal;
    /// returns its `suspended_until`
    async fn gate_refuses(harness: &TestHarness, account_id: &str, row: &str) -> Option<Timestamp> {
        let stored = harness.db.fetch_account(account_id).await.unwrap();
        super::assert_not_locked_out(&stored)
            .unwrap_or_else(|error| panic!("{}: locked out: {:?}", row, error));

        match super::complete_login(&harness.db, stored, None).await {
            Ok(v0::ResponseLogin::Disabled {
                user_id,
                suspended_until,
            }) => {
                assert_eq!(user_id, account_id, "{}", row);
                suspended_until
            }
            other => panic!("{}: expected `Disabled`, got {:?}", row, other),
        }
    }

    /// Session ids in a stable order, so two reads compare
    async fn gate_sessions(harness: &TestHarness, account_id: &str) -> Vec<String> {
        let mut ids = session_ids(harness, account_id).await;
        ids.sort();
        ids
    }

    /// An account with a user row (and so one session already), disabled,
    /// whose user carries `suspended_until`
    ///
    /// Returns the account id and the sessions it starts with.
    async fn gate_suspended_account(
        harness: &TestHarness,
        suspended_until: Timestamp,
    ) -> (String, Vec<String>) {
        let (mut account, session, mut user) = harness.new_user().await;

        account.disabled = true;
        account.save(&harness.db).await.unwrap();

        user.update(
            &harness.db,
            PartialUser {
                suspended_until: Some(suspended_until),
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();

        let before = gate_sessions(harness, &account.id).await;
        assert_eq!(before, vec![session.id], "the seed has one session");
        (account.id, before)
    }

    /// The shared login gate (`assert_not_locked_out` + `complete_login`),
    /// driven directly, as every sign-in path drives it. Each row that
    /// reaches `complete_login` checks the stored sessions, so a gate that
    /// is skipped shows up as a session that should not exist. Row (b) only
    /// calls `assert_not_locked_out`, which cannot store one.
    #[test]
    fn login_gate_table() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            // (a) A plain account signs in, under the default session name
            {
                let account = sec009_account(&harness, "password_insecure", false, false).await;
                let session = gate_succeeds(&harness, &account.id, "a").await;

                let sessions = harness.db.fetch_sessions(&account.id).await.unwrap();
                assert_eq!(sessions.len(), 1, "a: exactly one session is stored");
                assert_eq!(sessions[0].id, session.id, "a");
                assert_eq!(sessions[0].name, "Unknown", "a");
            }

            // (b) A lockout that has not expired refuses, before any proof
            {
                let account = sec009_account(&harness, "password_insecure", false, false).await;
                harness
                    .db
                    .set_lockout(
                        &account.id,
                        Some(Lockout {
                            attempts: 3,
                            expiry: Some(soon()),
                        }),
                    )
                    .await
                    .unwrap();

                let stored = harness.db.fetch_account(&account.id).await.unwrap();
                assert!(stored.lockout.is_some(), "b: the seed must be stored");
                match super::assert_not_locked_out(&stored) {
                    Err(error) => assert!(
                        matches!(error.error_type, ErrorType::LockedOut),
                        "b: expected `LockedOut`, got {:?}",
                        error
                    ),
                    Ok(()) => panic!("b: a live lockout must refuse"),
                }
            }

            // (c) An expired lockout does not refuse
            {
                let account = sec009_account(&harness, "password_insecure", false, false).await;
                harness
                    .db
                    .set_lockout(
                        &account.id,
                        Some(Lockout {
                            attempts: 3,
                            expiry: Some(long_ago()),
                        }),
                    )
                    .await
                    .unwrap();

                let stored = harness.db.fetch_account(&account.id).await.unwrap();
                assert!(stored.lockout.is_some(), "c: the seed must be stored");
                let session = gate_succeeds(&harness, &account.id, "c").await;
                assert_eq!(
                    session_ids(&harness, &account.id).await,
                    vec![session.id],
                    "c"
                );
            }

            // (d) + (e) A confirmed or finished deletion refuses with
            // `disabled` still false, and stores no session
            for (row, deletion) in [
                ("d", DeletionInfo::Scheduled { after: soon() }),
                ("e", DeletionInfo::Deleted),
            ] {
                let account = deletion_account(&harness, Some(deletion)).await;
                assert!(!account.disabled, "{}", row);

                assert_eq!(gate_refuses(&harness, &account.id, row).await, None, "{}", row);
                assert!(
                    session_ids(&harness, &account.id).await.is_empty(),
                    "{}: a refused login must store no session",
                    row
                );

                // `account` is the stored copy, so this compares like with like
                let stored = harness.db.fetch_account(&account.id).await.unwrap();
                assert_eq!(stored.deletion, account.deletion, "{}", row);
                assert!(!stored.disabled, "{}", row);
            }

            // (f) A pending deletion is cancelled by signing in
            {
                let account = deletion_account(&harness, pending(soon())).await;
                let session = gate_succeeds(&harness, &account.id, "f").await;

                assert_eq!(
                    stored_deletion(&harness, &account.id).await,
                    None,
                    "f: signing in must cancel the pending deletion"
                );
                assert_eq!(
                    session_ids(&harness, &account.id).await,
                    vec![session.id],
                    "f"
                );

                // The cancel email; taking it also cleans the mailbox up
                let (mail, _) = harness.assert_email(&account.email).await;
                assert_eq!(mail.subject, "deletion_cancelled", "f");
            }

            // (g) Disabled, with no suspension to lift (no user row at all)
            {
                let mut account =
                    sec009_account(&harness, "password_insecure", false, false).await;
                account.disabled = true;
                account.save(&harness.db).await.unwrap();

                assert_eq!(gate_refuses(&harness, &account.id, "g").await, None, "g");
                assert!(
                    session_ids(&harness, &account.id).await.is_empty(),
                    "g: a refused login must store no session"
                );
                assert!(
                    harness.db.fetch_account(&account.id).await.unwrap().disabled,
                    "g: a refused login changes nothing"
                );
            }

            // (h) Disabled under a suspension that has expired: `unsuspend`
            // re-enables the account and clears the user's suspension, and
            // the login goes through
            {
                let (account_id, before) = gate_suspended_account(&harness, long_ago()).await;
                let session = gate_succeeds(&harness, &account_id, "h").await;

                assert!(
                    !harness.db.fetch_account(&account_id).await.unwrap().disabled,
                    "h: the expired suspension must be lifted"
                );
                assert_eq!(
                    harness.db.fetch_user(&account_id).await.unwrap().suspended_until,
                    None,
                    "h"
                );

                let mut expected = before;
                expected.push(session.id);
                expected.sort();
                assert_eq!(
                    gate_sessions(&harness, &account_id).await,
                    expected,
                    "h: exactly one session is added"
                );
            }

            // (i) Disabled under a suspension still running: refused with
            // that timestamp, as stored (MongoDB keeps milliseconds only)
            {
                let (account_id, before) = gate_suspended_account(&harness, soon()).await;

                let stored_until = harness
                    .db
                    .fetch_user(&account_id)
                    .await
                    .unwrap()
                    .suspended_until
                    .expect("i: the seed must be stored");
                assert!(stored_until > Timestamp::now_utc(), "i");

                assert_eq!(
                    gate_refuses(&harness, &account_id, "i").await,
                    Some(stored_until),
                    "i"
                );
                assert_eq!(
                    gate_sessions(&harness, &account_id).await,
                    before,
                    "i: a refused login must store no session"
                );
                assert!(
                    harness.db.fetch_account(&account_id).await.unwrap().disabled,
                    "i: a running suspension is not lifted"
                );
                assert_eq!(
                    harness.db.fetch_user(&account_id).await.unwrap().suspended_until,
                    Some(stored_until),
                    "i"
                );
            }
        })
    }

    /// The stored lockout as plain values, so two reads compare
    async fn r9_lockout(
        harness: &TestHarness,
        account_id: &str,
    ) -> Option<(i32, Option<Timestamp>)> {
        let stored = harness.db.fetch_account(account_id).await.unwrap();
        stored.lockout.map(|lockout| (lockout.attempts, lockout.expiry))
    }

    /// An account whose stored hash IS of `password_insecure`, flagged as
    /// having no password. So a row that sends that password proves the
    /// hash is never consulted, not merely that it did not match.
    async fn r9_account(harness: &TestHarness, totp: bool) -> Account {
        let mut account = sec009_account(harness, "password_insecure", false, totp).await;
        account.password_absent = true;
        account.save(&harness.db).await.unwrap();

        let stored = harness.db.fetch_account(&account.id).await.unwrap();
        assert!(stored.password_absent, "the seed must be stored");
        assert!(
            stored.verify_password("password_insecure").is_ok(),
            "the control: the stored hash matches the password the rows send"
        );
        stored
    }

    /// R9: a password login against an account with no password answers as
    /// a missing email does, whatever the password, and writes nothing: no
    /// lockout attempt, no ticket, no session.
    #[test]
    fn r9_password_absent_login_table() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            // (control) A wrong password on an ordinary account IS counted,
            // so the unchanged lockouts below mean something
            {
                let account = sec009_account(&harness, "password_insecure", false, false).await;
                assert_eq!(r9_lockout(&harness, &account.id).await, None, "control");
                sec009_assert_matches_unknown_email(&harness, &account, "wrong_password").await;
                assert!(
                    r9_lockout(&harness, &account.id).await.is_some(),
                    "control: a wrong password on a password account is counted"
                );
            }

            // (a) + (b) The password the hash matches, and a wrong one
            for (row, password) in [("a", "password_insecure"), ("b", "wrong_password")] {
                let account = r9_account(&harness, false).await;

                sec009_assert_matches_unknown_email(&harness, &account, password).await;
                assert_eq!(
                    r9_lockout(&harness, &account.id).await,
                    None,
                    "{}: no lockout attempt is written",
                    row
                );
                assert!(
                    session_ids(&harness, &account.id).await.is_empty(),
                    "{}: no session is stored",
                    row
                );
            }

            // (c) With TOTP on: the same answer, so no ticket is handed out
            // and nothing is counted
            {
                let account = r9_account(&harness, true).await;

                sec009_assert_matches_unknown_email(&harness, &account, "password_insecure").await;
                sec009_assert_matches_unknown_email(&harness, &account, "wrong_password").await;
                assert_eq!(
                    r9_lockout(&harness, &account.id).await,
                    None,
                    "c: no lockout attempt is written"
                );
                assert!(session_ids(&harness, &account.id).await.is_empty(), "c");
            }

            // (d) While locked out: still the missing-email answer, not
            // `LockedOut`, and the lockout is left exactly as it was
            {
                let account = r9_account(&harness, false).await;
                harness
                    .db
                    .set_lockout(
                        &account.id,
                        Some(Lockout {
                            attempts: 3,
                            expiry: Some(soon()),
                        }),
                    )
                    .await
                    .unwrap();
                let before = r9_lockout(&harness, &account.id).await;
                assert!(before.is_some(), "d: the seed must be stored");

                sec009_assert_matches_unknown_email(&harness, &account, "password_insecure").await;
                assert_eq!(
                    r9_lockout(&harness, &account.id).await,
                    before,
                    "d: the lockout is neither extended nor cleared"
                );
                assert!(session_ids(&harness, &account.id).await.is_empty(), "d");
            }
        })
    }

    /// An account with no email, stored, that DOES have a password its owner
    /// knows (`password_insecure`): the worst case for a login by email
    async fn no_email_account_with_password(harness: &TestHarness) -> Account {
        let mut account = Account::new_passkey_signup(None).expect("a no-email account");
        account.password =
            revolt_database::util::password::hash_password("password_insecure".to_string())
                .unwrap();
        account.password_absent = false;
        account.save(&harness.db).await.unwrap();

        let stored = harness.db.fetch_account(&account.id).await.unwrap();
        assert!(stored.email_absent, "the seed must be stored");
        assert!(!stored.password_absent, "the seed must be stored");
        assert!(stored.email.ends_with("@noemail.invalid"), "{}", stored.email);
        assert!(
            stored.verify_password("password_insecure").is_ok(),
            "the control: the stored hash matches the password the rows send"
        );
        stored
    }

    /// Fails if: the login looks an account up by the stored `email` or
    /// `email_normalised` fields again instead of `Account::fetch_by_email`,
    /// so that typing an account's stand-in address (as stored, or in
    /// another case) with the right password signs in, counts a lockout
    /// attempt, or answers differently from an address nobody has.
    #[test]
    fn typed_placeholder_matches_unknown_email() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let account = no_email_account_with_password(&harness).await;

            let unknown = sec009_login(&harness, &sec009_email(), "password_insecure").await;
            assert_eq!(unknown.0, Status::Unauthorized);
            assert!(matches!(
                serde_json::from_str::<Error>(&unknown.1).unwrap().error_type,
                ErrorType::InvalidCredentials,
            ));

            for typed in [account.email.clone(), account.email.to_uppercase()] {
                for password in ["password_insecure", "wrong_password"] {
                    assert_eq!(
                        sec009_login(&harness, &typed, password).await,
                        unknown,
                        "{typed} / {password}"
                    );
                }
            }

            assert_eq!(
                r9_lockout(&harness, &account.id).await,
                None,
                "no lockout attempt is written"
            );
            assert!(
                session_ids(&harness, &account.id).await.is_empty(),
                "no session is stored"
            );
        })
    }

    /// Fails if: `Account::real_email` or `Account::fetch_by_email` treat
    /// every `.invalid` address as "no email" again, so an account that
    /// stores one outside the stand-in domain (one exists in production)
    /// can no longer sign in with its password.
    #[test]
    fn an_ordinary_invalid_address_signs_in_with_its_password() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            // Seeded as an ordinary account, then given the old address
            let local = TestHarness::rand_string();
            let email = format!("{local}@sloga.invalid");
            let mut account = Account::new(
                &harness.db,
                format!("{local}@validemail.com"),
                "password_insecure".into(),
                false,
            )
            .await
            .unwrap();
            account.email = email.clone();
            account.email_normalised = email.clone();
            account.save(&harness.db).await.unwrap();

            // The control: a wrong password is refused and stores nothing
            let (status, _) = sec009_login(&harness, &email, "wrong_password").await;
            assert_eq!(status, Status::Unauthorized);
            assert!(session_ids(&harness, &account.id).await.is_empty());

            for (row, typed) in [email.clone(), email.to_uppercase()].iter().enumerate() {
                let (status, body) = sec009_login(&harness, typed, "password_insecure").await;
                assert_eq!(status, Status::Ok, "{typed}: {body}");

                let session: v0::Session = serde_json::from_str(&body).expect("a session");
                assert_eq!(session.user_id, account.id, "{typed}");
                assert_eq!(session_ids(&harness, &account.id).await.len(), row + 1);
            }
        })
    }
}
