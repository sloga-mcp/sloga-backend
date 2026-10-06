//! Regression tests for the MFA attempt limits (SEC-006) and the stale
//! account saves on the SMTP paths.
//!
//! Every test here fails on `05b50d57`, the commit before the fix:
//!
//!  * a login ticket took unlimited TOTP guesses and was never consumed;
//!  * an `authorised` ticket could mint any number of sessions;
//!  * a failed MFA attempt never touched the account lockout, and a correct
//!    password cleared it before MFA;
//!  * `PUT /auth/mfa/ticket` and `change_password` had no lockout at all;
//!  * `start_email_verification` and `start_password_reset` saved the whole
//!    account document, so a stale copy reverted newer fields.
//!
//! The file uses only APIs that exist at `05b50d57`, so it can be copied
//! into a tree at that commit to show the failures.
//!
//! Requests per test stay under the `auth` bucket (15 per 10 s; sessionless
//! requests share one key per harness, session requests are keyed per
//! session). The count is in each test's comment.

use futures::future::join_all;
use iso8601_timestamp::{Duration, Timestamp};
use revolt_database::{
    util::password::hash_password, Account, EmailVerification, MFATicket, PasswordReset, Totp,
};
use revolt_models::v0;
use revolt_result::{Error, ErrorType};
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::LocalResponse;

use crate::util::test::TestHarness;

/// The password `TestHarness::new_user` gives every account
const PASSWORD: &str = "password_insecure";

/// Six-digit codes sent as wrong guesses. `wrong_code` picks one that is not
/// currently valid.
const WRONG_CODES: [&str; 3] = ["000000", "123456", "999999"];

fn totp() -> Totp {
    Totp::Enabled {
        secret: "secret".to_string(),
    }
}

/// A wrong six-digit TOTP code: the first of `WRONG_CODES` that is neither
/// `stamped` (the code stamped on the ticket at login) nor the current code.
/// The current code can still roll over during the login jitter; the chance
/// that it rolls onto the code picked here is one in a million.
fn wrong_code(stamped: Option<&str>) -> String {
    let current = totp().generate_code().expect("the current TOTP code");
    WRONG_CODES
        .iter()
        .find(|code| Some(**code) != stamped && **code != current.as_str())
        .expect("three candidates, at most two excluded")
        .to_string()
}

/// Turn TOTP on for `account`
async fn enable_totp(harness: &TestHarness, account: &mut Account) {
    account.mfa.totp_token = totp();
    account.save(&harness.db).await.unwrap();
}

async fn password_login<'c>(
    harness: &'c TestHarness,
    email: &str,
    password: &str,
) -> LocalResponse<'c> {
    harness
        .client
        .post("/auth/session/login")
        .header(ContentType::JSON)
        .body(
            json!({
                "email": email,
                "password": password
            })
            .to_string(),
        )
        .dispatch()
        .await
}

async fn mfa_login<'c>(harness: &'c TestHarness, ticket: &str, code: &str) -> LocalResponse<'c> {
    harness
        .client
        .post("/auth/session/login")
        .header(ContentType::JSON)
        .body(
            json!({
                "mfa_ticket": ticket,
                "mfa_response": {
                    "totp_code": code
                }
            })
            .to_string(),
        )
        .dispatch()
        .await
}

/// Log in with the correct password and return the MFA ticket (1 request)
async fn login_ticket(harness: &TestHarness, email: &str) -> String {
    let res = password_login(harness, email, PASSWORD).await;
    assert_eq!(res.status(), Status::Ok);

    let response =
        serde_json::from_str::<v0::ResponseLogin>(&res.into_string().await.unwrap())
            .expect("`ResponseLogin`");

    if let v0::ResponseLogin::MFA { ticket, .. } = response {
        ticket
    } else {
        panic!("expected `ResponseLogin::MFA`")
    }
}

/// The code stamped on the ticket at login. The server accepts it for the
/// ticket's whole lifetime, so a 30 s window rolling over during the login
/// jitter cannot turn it wrong.
async fn stamped_code(harness: &TestHarness, ticket: &str) -> String {
    harness
        .db
        .fetch_ticket_by_token(ticket)
        .await
        .expect("the login ticket")
        .last_totp_code
        .expect("a TOTP code stamped on the login ticket")
}

async fn assert_error(res: LocalResponse<'_>, status: Status, error: ErrorType) {
    assert_eq!(res.status(), status);
    let actual = res.into_json::<Error>().await.unwrap().error_type;
    assert_eq!(
        std::mem::discriminant(&actual),
        std::mem::discriminant(&error),
        "expected {:?}, got {:?}",
        error,
        actual
    );
}

async fn lockout_attempts(harness: &TestHarness, account_id: &str) -> Option<i32> {
    harness
        .db
        .fetch_account(account_id)
        .await
        .unwrap()
        .lockout
        .map(|lockout| lockout.attempts)
}

/// (a) A login ticket takes three wrong codes, then it is burned: the
/// correct code no longer works on it. 5 sessionless requests.
///
/// Base: the ticket survives every failure and the correct code logs in.
#[test]
fn ticket_capped_after_three() {
    crate::util::test::rt().block_on(ticket_capped_after_three_case())
}

async fn ticket_capped_after_three_case() {
    let harness = TestHarness::new().await;
    let (mut account, _, _) = harness.new_user().await;
    enable_totp(&harness, &mut account).await;

    let ticket = login_ticket(&harness, &account.email).await;
    let correct = stamped_code(&harness, &ticket).await;

    for _ in 0..3 {
        let res = mfa_login(&harness, &ticket, &wrong_code(Some(correct.as_str()))).await;
        assert_error(res, Status::Unauthorized, ErrorType::InvalidToken).await;
    }

    assert!(
        harness.db.fetch_ticket_by_token(&ticket).await.is_err(),
        "the ticket must be deleted by its third failed attempt"
    );

    let res = mfa_login(&harness, &ticket, &correct).await;
    assert_ne!(
        res.status(),
        Status::Ok,
        "the correct code must not log in on a ticket that used its three attempts"
    );
    assert!(harness.db.fetch_ticket_by_token(&ticket).await.is_err());
}

/// (b) A login ticket logs in once. 3 sessionless requests.
///
/// Base: the ticket is never consumed, so the replay logs in again.
#[test]
fn ticket_single_use() {
    crate::util::test::rt().block_on(ticket_single_use_case())
}

async fn ticket_single_use_case() {
    let harness = TestHarness::new().await;
    let (mut account, _, _) = harness.new_user().await;
    enable_totp(&harness, &mut account).await;

    let ticket = login_ticket(&harness, &account.email).await;
    let correct = stamped_code(&harness, &ticket).await;

    let res = mfa_login(&harness, &ticket, &correct).await;
    assert_eq!(res.status(), Status::Ok);
    assert!(serde_json::from_str::<v0::Session>(&res.into_string().await.unwrap()).is_ok());

    assert!(
        harness.db.fetch_ticket_by_token(&ticket).await.is_err(),
        "a successful login must consume its ticket"
    );

    let res = mfa_login(&harness, &ticket, &correct).await;
    assert_ne!(
        res.status(),
        Status::Ok,
        "a consumed ticket must not log in again"
    );
}

/// (c) An `authorised` ticket (as minted by email verification) logs in
/// once. 2 sessionless requests.
///
/// Base: the authorised branch never claims the ticket, so it mints a
/// session on every use for five minutes.
#[test]
fn authorised_ticket_single_use() {
    crate::util::test::rt().block_on(authorised_ticket_single_use_case())
}

async fn authorised_ticket_single_use_case() {
    let harness = TestHarness::new().await;
    let (account, _, _) = harness.new_user().await;

    let mut ticket = MFATicket::new(account.id.clone(), false);
    ticket.authorised = true;
    ticket.save(&harness.db).await.unwrap();

    let login = || {
        harness
            .client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "mfa_ticket": &ticket.token
                })
                .to_string(),
            )
            .dispatch()
    };

    let res = login().await;
    assert_eq!(res.status(), Status::Ok);
    assert!(serde_json::from_str::<v0::Session>(&res.into_string().await.unwrap()).is_ok());

    assert!(
        harness.db.fetch_ticket_by_token(&ticket.token).await.is_err(),
        "an authorised ticket must be consumed by the login it allows"
    );

    let res = login().await;
    assert_ne!(
        res.status(),
        Status::Ok,
        "an authorised ticket must not mint a second session"
    );
}

/// (d) A failed MFA attempt counts against the account lockout, a correct
/// password does not reset that count, and three failures lock the account.
/// 6 sessionless requests.
///
/// Base: MFA failures never touch the lockout, so it stays `None` and the
/// final login succeeds.
#[test]
fn mfa_failures_count_and_persist() {
    crate::util::test::rt().block_on(mfa_failures_count_and_persist_case())
}

async fn mfa_failures_count_and_persist_case() {
    let harness = TestHarness::new().await;
    let (mut account, _, _) = harness.new_user().await;
    enable_totp(&harness, &mut account).await;

    // One wrong code on the first ticket
    let ticket = login_ticket(&harness, &account.email).await;
    let stamped = stamped_code(&harness, &ticket).await;
    let res = mfa_login(&harness, &ticket, &wrong_code(Some(stamped.as_str()))).await;
    assert_error(res, Status::Unauthorized, ErrorType::InvalidToken).await;

    assert_eq!(
        lockout_attempts(&harness, &account.id).await,
        Some(1),
        "a failed MFA attempt must count against the account lockout"
    );

    // A correct password gets a new ticket but must not reset the count
    let ticket = login_ticket(&harness, &account.email).await;
    assert_eq!(
        lockout_attempts(&harness, &account.id).await,
        Some(1),
        "a correct password must not clear the lockout before MFA passes"
    );

    // Two more wrong codes on the new ticket
    let stamped = stamped_code(&harness, &ticket).await;
    for _ in 0..2 {
        let res = mfa_login(&harness, &ticket, &wrong_code(Some(stamped.as_str()))).await;
        assert_error(res, Status::Unauthorized, ErrorType::InvalidToken).await;
    }

    assert_eq!(lockout_attempts(&harness, &account.id).await, Some(3));

    // Three failures in total: even the correct password is refused now
    let res = password_login(&harness, &account.email, PASSWORD).await;
    assert_error(res, Status::Forbidden, ErrorType::LockedOut).await;
}

/// (e) Smoke test: ten parallel wrong codes on one ticket count at most
/// three attempts. The login jitter mostly serializes them, so this is no
/// proof of atomicity (the database tests are). 11 sessionless requests.
///
/// Base: no attempt is counted at all, so the lockout stays `None`.
#[test]
fn parallel_guesses_smoke() {
    crate::util::test::rt().block_on(parallel_guesses_smoke_case())
}

async fn parallel_guesses_smoke_case() {
    let harness = TestHarness::new().await;
    let (mut account, _, _) = harness.new_user().await;
    enable_totp(&harness, &mut account).await;

    let ticket = login_ticket(&harness, &account.email).await;
    let stamped = stamped_code(&harness, &ticket).await;
    let wrong = wrong_code(Some(stamped.as_str()));

    let harness_ref = &harness;
    let ticket_ref = ticket.as_str();
    let wrong_ref = wrong.as_str();
    let responses =
        join_all((0..10).map(move |_| mfa_login(harness_ref, ticket_ref, wrong_ref))).await;

    for res in &responses {
        assert_ne!(res.status(), Status::Ok, "a wrong code must not log in");
    }

    let attempts = lockout_attempts(&harness, &account.id)
        .await
        .expect("parallel failed MFA attempts must count against the account lockout");
    assert!(
        (1..=3).contains(&attempts),
        "one ticket must count between 1 and 3 attempts, counted {}",
        attempts
    );

    // At least three requests reached the ticket before the lockout could
    // engage, and the third of them burned it
    assert!(harness.db.fetch_ticket_by_token(&ticket).await.is_err());
}

/// (f) `PUT /auth/mfa/ticket` with a session: three wrong codes lock the
/// account, and the fourth request is refused even with the correct code.
/// 4 requests on one session.
///
/// Base: the route has no lockout, so the fourth request gets a ticket.
#[test]
fn create_ticket_lockout() {
    crate::util::test::rt().block_on(create_ticket_lockout_case())
}

async fn create_ticket_lockout_case() {
    let harness = TestHarness::new().await;
    let (mut account, session, _) = harness.new_user().await;
    enable_totp(&harness, &mut account).await;

    let create_ticket = |code: String| {
        harness
            .client
            .put("/auth/mfa/ticket")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "totp_code": code
                })
                .to_string(),
            )
            .dispatch()
    };

    for _ in 0..3 {
        let res = create_ticket(wrong_code(None)).await;
        assert_error(res, Status::Unauthorized, ErrorType::InvalidToken).await;
    }

    let res = create_ticket(totp().generate_code().unwrap()).await;
    assert_error(res, Status::Forbidden, ErrorType::LockedOut).await;

    assert_eq!(lockout_attempts(&harness, &account.id).await, Some(3));
}

/// (g) `PATCH /auth/account/change/password` with a session: three wrong
/// current passwords lock the account, and the fourth request is refused
/// even with the correct one. A non-MFA account, so no ticket is needed.
/// 4 requests on one session.
///
/// Base: the route has no lockout, so the fourth request changes the
/// password.
#[test]
fn change_password_lockout() {
    crate::util::test::rt().block_on(change_password_lockout_case())
}

async fn change_password_lockout_case() {
    let harness = TestHarness::new().await;
    let (account, session, _) = harness.new_user().await;

    let change_password = |current_password: &'static str| {
        harness
            .client
            .patch("/auth/account/change/password")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "password": "new password",
                    "current_password": current_password
                })
                .to_string(),
            )
            .dispatch()
    };

    for _ in 0..3 {
        let res = change_password("wrong password").await;
        assert_error(res, Status::Unauthorized, ErrorType::InvalidCredentials).await;
    }

    let res = change_password(PASSWORD).await;
    assert_error(res, Status::Forbidden, ErrorType::LockedOut).await;

    let stored = harness.db.fetch_account(&account.id).await.unwrap();
    assert_eq!(stored.lockout.as_ref().map(|lockout| lockout.attempts), Some(3));
    assert!(
        stored.verify_password(PASSWORD).is_ok(),
        "a locked request must not change the password"
    );
}

/// (h) The SMTP methods on a stale copy of the account must not revert a
/// newer password or newer recovery codes (D12). No HTTP requests.
///
/// Base: both methods end in a whole-document `save`, which writes the
/// stale password and recovery codes back.
///
/// The test config points SMTP at the compose maildev (localhost:14025).
/// With SMTP on, both methods send mail and then write. With SMTP off,
/// `start_email_verification` still writes and `start_password_reset`
/// returns `OperationFailed` before writing. If neither returns `Ok`, the
/// test cannot tell a fix from a revert and fails.
#[test]
fn smtp_start_does_not_revert() {
    crate::util::test::rt().block_on(smtp_start_does_not_revert_case())
}

async fn smtp_start_does_not_revert_case() {
    let harness = TestHarness::new().await;
    let (account, _, _) = harness.new_user().await;

    // The stale copy is read before the change below
    let mut stale = harness.db.fetch_account(&account.id).await.unwrap();

    let mut fresh = harness.db.fetch_account(&account.id).await.unwrap();
    fresh.password = hash_password("a password set after the stale read".to_string()).unwrap();
    fresh.mfa.generate_recovery_codes();
    fresh.save(&harness.db).await.unwrap();
    assert_ne!(fresh.password, stale.password);
    assert_ne!(fresh.mfa.recovery_codes, stale.mfa.recovery_codes);

    let verification = stale.start_email_verification(&harness.db).await;
    let reset = stale.start_password_reset(&harness.db, true).await;
    assert!(
        verification.is_ok() || reset.is_ok(),
        "neither method reached its write, so this proves nothing; is maildev up \
         on localhost:14025? (verification: {:?}, reset: {:?})",
        verification,
        reset
    );

    let stored = harness.db.fetch_account(&account.id).await.unwrap();
    assert_eq!(
        stored.password, fresh.password,
        "a stale SMTP write reverted the password"
    );
    assert_eq!(
        stored.mfa.recovery_codes, fresh.mfa.recovery_codes,
        "a stale SMTP write reverted the recovery codes"
    );

    // Each method that returned `Ok` wrote its own field. Compare tokens,
    // not expiries: MongoDB keeps timestamps to the millisecond.
    if verification.is_ok() {
        match (&stored.verification, &stale.verification) {
            (
                EmailVerification::Pending { token: a, .. },
                EmailVerification::Pending { token: b, .. },
            ) => assert_eq!(a, b),
            (a, b) => assert_eq!(a, b),
        }
    }
    if reset.is_ok() {
        assert!(stale.password_reset.is_some());
        assert_eq!(
            stored.password_reset.as_ref().map(|reset| &reset.token),
            stale.password_reset.as_ref().map(|reset| &reset.token)
        );
    }
}

/// (i) A password reset clears the lockout: the way back in for a victim
/// that a session thief has locked out (D10). Five sessionless requests.
///
/// Passes on base too; it guards the escape hatch against regressions.
#[test]
fn password_reset_clears_lockout() {
    crate::util::test::rt().block_on(password_reset_clears_lockout_case())
}

async fn password_reset_clears_lockout_case() {
    let harness = TestHarness::new().await;
    let (account, _, _) = harness.new_user().await;

    // Three wrong passwords lock the account
    for _ in 0..3 {
        let res = password_login(&harness, &account.email, "wrong password").await;
        assert_error(res, Status::Unauthorized, ErrorType::InvalidCredentials).await;
    }
    let res = password_login(&harness, &account.email, PASSWORD).await;
    assert_error(res, Status::Forbidden, ErrorType::LockedOut).await;

    // Plant a reset token directly instead of mailing one
    let mut planted = harness.db.fetch_account(&account.id).await.unwrap();
    planted.password_reset = Some(PasswordReset {
        token: "mfa-limit-tests-reset-token".to_string(),
        expiry: Timestamp::now_utc()
            .checked_add(Duration::minutes(10))
            .unwrap(),
    });
    planted.save(&harness.db).await.unwrap();

    let new_password = "a fresh password after the reset 4821";
    let res = harness
        .client
        .patch("/auth/account/reset_password")
        .header(ContentType::JSON)
        .body(
            json!({
                "token": "mfa-limit-tests-reset-token",
                "password": new_password,
                "remove_sessions": true
            })
            .to_string(),
        )
        .dispatch()
        .await;
    assert_eq!(res.status(), Status::NoContent);

    let stored = harness.db.fetch_account(&account.id).await.unwrap();
    assert!(stored.lockout.is_none(), "the reset must clear the lockout");

    let res = password_login(&harness, &account.email, new_password).await;
    assert_eq!(res.status(), Status::Ok);
}

/// (j) A recovery code logs in once and is then spent (D9). Four
/// sessionless requests.
///
/// Passes on base too; it guards the atomic `consume_recovery_code` call in
/// the MFA path against regressions.
#[test]
fn recovery_code_single_use() {
    crate::util::test::rt().block_on(recovery_code_single_use_case())
}

async fn recovery_code_single_use_case() {
    let harness = TestHarness::new().await;
    let (mut account, _, _) = harness.new_user().await;
    account.mfa.generate_recovery_codes();
    enable_totp(&harness, &mut account).await;
    let code = account.mfa.recovery_codes[0].clone();

    let recovery_login = |ticket: String| {
        let code = code.clone();
        let harness = &harness;
        async move {
            harness
                .client
                .post("/auth/session/login")
                .header(ContentType::JSON)
                .body(
                    json!({
                        "mfa_ticket": ticket,
                        "mfa_response": {
                            "recovery_code": code
                        }
                    })
                    .to_string(),
                )
                .dispatch()
                .await
        }
    };

    let ticket = login_ticket(&harness, &account.email).await;
    let res = recovery_login(ticket).await;
    assert_eq!(res.status(), Status::Ok);

    let stored = harness.db.fetch_account(&account.id).await.unwrap();
    assert!(
        !stored.mfa.recovery_codes.contains(&code),
        "a used recovery code must be removed"
    );

    let ticket = login_ticket(&harness, &account.email).await;
    let res = recovery_login(ticket).await;
    assert_error(res, Status::Unauthorized, ErrorType::InvalidToken).await;
}
