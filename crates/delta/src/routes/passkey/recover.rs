//! Get back into an account whose passkey was lost.
//! POST /passkey/recover/send
//! POST /passkey/recover/start
//! POST /passkey/recover/finish
use std::collections::HashMap;

use revolt_database::util::email::{email_templates, send_email_safe};
use revolt_database::{Account, Database, DeletionInfo, EmailVerification, MfaPurpose, Passkey};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;

use crate::routes::session::login::{assert_not_locked_out, complete_login};
use crate::util::{passkey, passkey_signup};

/// Longest address `recover/send` looks up
const MAX_EMAIL_LEN: usize = 320;

/// How one `recover/send` ended. Never part of the answer: the route has
/// answered before this is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    /// A link was mailed
    Sent,
    /// No account holds the address
    NoAccount,
    /// The account cannot recover a passkey this way
    NotEligible,
    /// The account got a link in the last ten minutes
    Cooldown,
    /// The database, Redis or the mail server failed
    Failed,
}

/// Every delivery this process finished, in order, so a test can wait for
/// the detached task and read how it ended
#[cfg(test)]
static DELIVERIES: std::sync::Mutex<Vec<Delivery>> = std::sync::Mutex::new(Vec::new());

/// Whether a lost passkey of `account` may be replaced through a mailed
/// link: the account is live, has a confirmed email, and has a passkey.
///
/// An account that never had a passkey has nothing to recover and uses the
/// password reset. Read at all three steps.
async fn recoverable(db: &Database, account: &Account) -> Result<bool> {
    if account.disabled
        || matches!(
            account.deletion,
            Some(DeletionInfo::Scheduled { .. } | DeletionInfo::Deleted)
        )
        || account.real_email().is_none()
        || matches!(account.verification, EmailVerification::Pending { .. })
    {
        return Ok(false);
    }

    Ok(db.count_passkeys(&account.id).await? > 0)
}

/// The work behind `recover/send`: look the address up, and mail a link if
/// the account may have one. Runs detached from the request.
///
/// The link goes to the address stored on the account, never to the one
/// that was typed.
async fn deliver(db: &Database, email: &str) -> Delivery {
    if email.len() > MAX_EMAIL_LEN {
        return Delivery::NoAccount;
    }

    let account = match Account::fetch_by_email(db, email).await {
        Ok(Some(account)) => account,
        Ok(None) => return Delivery::NoAccount,
        Err(_) => return Delivery::Failed,
    };

    match recoverable(db, &account).await {
        Ok(true) => {}
        Ok(false) => return Delivery::NotEligible,
        Err(_) => return Delivery::Failed,
    }

    let Some(address) = account.real_email().map(str::to_string) else {
        return Delivery::NotEligible;
    };

    let token = match passkey_signup::issue_recover_token(&account.id).await {
        Ok(Some(token)) => token,
        Ok(None) => return Delivery::Cooldown,
        Err(_) => return Delivery::Failed,
    };

    let templates = email_templates().await;
    let template = &templates.passkey_recovery;
    let variables = HashMap::from([
        ("email", address.clone()),
        ("url", format!("{}{}", template.url, token)),
    ]);

    match send_email_safe(&address, template, variables).await {
        Ok(()) => Delivery::Sent,
        Err(_) => Delivery::Failed,
    }
}

/// The account a live recovery token belongs to, and the hash the ceremony
/// is bound to. Does not consume the token.
///
/// `InvalidToken` for a token that is malformed, unknown, expired or used,
/// and for an account that is gone or may no longer recover.
async fn account_of_token(db: &Database, token: &str) -> Result<(Account, String)> {
    let token_hash = passkey_signup::recover_token_hash(token)?;
    let account_id = passkey_signup::peek_recover_token(token).await?;

    let account = match db.fetch_account(&account_id).await {
        Ok(account) => account,
        Err(error)
            if matches!(
                error.error_type,
                ErrorType::UnknownUser | ErrorType::NotFound
            ) =>
        {
            return Err(create_error!(InvalidToken))
        }
        Err(error) => return Err(error),
    };

    if !recoverable(db, &account).await? {
        return Err(create_error!(InvalidToken));
    }

    Ok((account, token_hash))
}

/// The second factor a recovery was sent with, for an account whose MFA is
/// active: the lockout, then which of the two codes was given. Nothing is
/// compared, counted or spent here; `consume_second_factor` does that once
/// the passkey ceremony has passed.
///
/// A locked account is refused before anything else. Only these two kinds
/// are ever built here, so a passkey can never be the second factor. A
/// request with no code, or with both, is refused without a count: nothing
/// was guessed.
fn second_factor_response(
    account: &Account,
    totp_code: Option<String>,
    recovery_code: Option<String>,
) -> Result<v0::MFAResponse> {
    assert_not_locked_out(account)?;

    let given = |code: Option<String>| code.filter(|code| !code.trim().is_empty());

    match (given(totp_code), given(recovery_code)) {
        (Some(totp_code), None) => Ok(v0::MFAResponse::Totp { totp_code }),
        (None, Some(recovery_code)) => Ok(v0::MFAResponse::Recovery { recovery_code }),
        _ => Err(create_error!(InvalidCredentials)),
    }
}

/// Check the code `second_factor_response` picked, and spend it.
///
/// Through `consume_mfa_response`, as the login MFA step does: one lockout
/// attempt is counted before the code is compared, a recovery code is
/// spent, and a right code clears the lockout.
///
/// A wrong code is `InvalidCredentials`: `InvalidToken` is kept for the link.
async fn consume_second_factor(
    db: &Database,
    account: &mut Account,
    response: v0::MFAResponse,
) -> Result<()> {
    // No ticket exists in this flow, so there is none to count or claim
    account
        .consume_mfa_response(db, response, MfaPurpose::MintTicket)
        .await
        .map_err(|error| match error.error_type {
            ErrorType::InvalidToken | ErrorType::DisallowedMFAMethod => {
                create_error!(InvalidCredentials)
            }
            _ => error,
        })
}

/// Delete every passkey of the account but `keep`. A row that is already
/// gone is as good as deleted.
async fn remove_other_passkeys(db: &Database, account_id: &str, keep: &str) -> Result<()> {
    for row in db.fetch_passkeys(account_id).await? {
        if row.id == keep {
            continue;
        }

        match db.delete_passkey(account_id, &row.id).await {
            Ok(()) => {}
            Err(error) if matches!(error.error_type, ErrorType::NotFound) => {}
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

/// The writes of a recovery, once its token is claimed: store the new
/// passkey, then remove every session and every other passkey.
///
/// The new passkey goes in first, so the account is never left with no way
/// in. The sessions go before the old passkeys are listed: a passkey that a
/// still-open session adds meanwhile is either listed and deleted here, or
/// taken back by its own route once it finds its session gone.
///
/// The token is spent by now, so every failure says in the log what state
/// the account is in.
async fn replace_passkeys(
    db: &Database,
    account: &Account,
    verified: passkey::VerifiedPasskey,
) -> Result<Passkey> {
    let stored = match verified.store(db, &account.id, None).await {
        Ok(stored) => stored,
        Err(error) => {
            log::error!(
                "passkeys: the recovery of account {} spent its link and stored no passkey \
                 ({:?}); the account is as it was",
                account.id,
                error.error_type
            );
            return Err(error);
        }
    };

    // Both are tried even when one fails; the first error is the answer
    let sessions_removed = account.delete_all_sessions(db, None).await;
    let passkeys_removed = remove_other_passkeys(db, &account.id, &stored.id).await;

    if let Err(error) = sessions_removed.and(passkeys_removed) {
        log::error!(
            "passkeys: the recovery of account {} stored its new passkey {} but could not \
             remove every session or every older passkey ({:?}); the new passkey signs in, \
             remove what is left by hand",
            account.id,
            stored.id,
            error.error_type
        );
        return Err(error);
    }

    Ok(stored)
}

/// Mail the "a passkey was added" notice, detached: the sign-in does not
/// wait for the mail server
fn send_added_notice(address: String) {
    tokio::spawn(async move {
        let templates = email_templates().await;
        let template = &templates.passkey_added;
        let variables = HashMap::from([
            ("email", address.clone()),
            ("url", template.url.clone()),
        ]);

        if send_email_safe(&address, template, variables).await.is_err() {
            log::warn!("passkeys: the notice of a recovered passkey could not be mailed");
        }
    });
}

/// Sign in after a recovery, through the gate every sign-in uses.
///
/// The session stands only while the new passkey is still stored: a
/// password reset that overtook this request removed it, and the session is
/// then taken back and the request answered as a failed ceremony.
async fn sign_in(db: &Database, account_id: &str, passkey_id: &str) -> Result<v0::ResponseLogin> {
    let account = db
        .fetch_account(account_id)
        .await
        .map_err(|_| create_error!(InvalidCredentials))?;

    let answer = complete_login(db, account, None).await?;

    let v0::ResponseLogin::Success(session) = &answer else {
        return Ok(answer);
    };

    if db.fetch_passkey(account_id, passkey_id).await.is_ok() {
        return Ok(answer);
    }

    let removed = match db.fetch_session(&session.id).await {
        Ok(session) => session.delete(db).await,
        Err(error) => Err(error),
    };
    if removed.is_err() {
        log::error!(
            "passkeys: could not remove session {} of a recovery whose passkey was removed; \
             revoke it by hand",
            session.id
        );
    }

    Err(create_error!(InvalidCredentials))
}

/// # Send a Passkey Recovery Link
///
/// Ask for a link to replace a lost passkey. Always answers 204, at once:
/// whether the address has an account, and whether a link was sent, is
/// worked out after the answer and never told.
///
/// A link is sent only to an account that has a confirmed email and at
/// least one passkey, at most once in ten minutes.
#[openapi(tag = "Passkey")]
#[post("/recover/send", data = "<data>")]
pub async fn recover_send(
    db: &State<Database>,
    data: Json<v0::DataPasskeyRecoverSend>,
) -> Result<EmptyResponse> {
    passkey::assert_available().await?;
    passkey_signup::assert_signup_on().await?;

    // Nothing below this line is awaited by the request
    let db = db.inner().clone();
    let email = data.into_inner().email;
    tokio::spawn(async move {
        let delivery = deliver(&db, &email).await;

        if delivery == Delivery::Failed {
            log::error!("passkeys: a recovery link could not be issued or mailed");
        }

        #[cfg(test)]
        DELIVERIES.lock().unwrap().push(delivery);
    });

    Ok(EmptyResponse)
}

/// # Open a Passkey Recovery Link
///
/// Get the options for creating the new passkey, and whether the finish
/// step also needs an authenticator code or an MFA recovery code. The
/// account's existing passkeys are not listed. The link stays usable.
#[openapi(tag = "Passkey")]
#[post("/recover/start", data = "<data>")]
pub async fn recover_start(
    db: &State<Database>,
    data: Json<v0::DataPasskeyRecoverStart>,
) -> Result<Json<v0::ResponsePasskeyRecoverStart>> {
    passkey::assert_available().await?;
    passkey_signup::assert_signup_on().await?;

    let v0::DataPasskeyRecoverStart { token } = data.into_inner();
    let (account, token_hash) = account_of_token(db, &token).await?;

    let started = passkey::start_recover_registration(db, &token_hash, &account).await?;

    Ok(Json(v0::ResponsePasskeyRecoverStart {
        challenge_id: started.challenge_id,
        options: started.options,
        second_factor_required: account.mfa.is_active(),
    }))
}

/// # Finish Passkey Recovery
///
/// Store the new passkey, remove every other passkey and every session of
/// the account, and sign in.
///
/// An account with an authenticator code must send that code or an MFA
/// recovery code in this request; a passkey is not accepted in its place.
/// The link works once.
#[openapi(tag = "Passkey")]
#[post("/recover/finish", data = "<data>")]
pub async fn recover_finish(
    db: &State<Database>,
    data: Json<v0::DataPasskeyRecoverFinish>,
) -> Result<Json<v0::ResponseLogin>> {
    passkey::assert_available().await?;
    passkey_signup::assert_signup_on().await?;

    let v0::DataPasskeyRecoverFinish {
        token,
        challenge_id,
        credential,
        totp_code,
        recovery_code,
    } = data.into_inner();

    let (mut account, token_hash) = account_of_token(db, &token).await?;

    // The lockout, and that one code was sent. A locked account, and a
    // request with no code, spend neither the challenge nor the link
    let second_factor = if account.mfa.is_active() {
        Some(second_factor_response(&account, totp_code, recovery_code)?)
    } else {
        None
    };

    // Before the claim: a ceremony that fails must not burn the mailed
    // link. Before the code is checked too: one that fails must not spend
    // an MFA recovery code
    let verified =
        passkey::finish_recover_registration(db, &challenge_id, credential, &token_hash, &account)
            .await?;

    // A wrong code is counted against the lockout and costs this challenge;
    // the link stays good for another `recover/start`
    if let Some(response) = second_factor {
        consume_second_factor(db, &mut account, response).await?;
    }

    // Single use: of any number of requests with one token, one gets here
    let claimed_for = passkey_signup::claim_recover_token(&token).await?;
    if claimed_for != account.id {
        return Err(create_error!(InvalidToken));
    }

    let stored = replace_passkeys(db, &account, verified).await?;

    if let Some(address) = account.real_email() {
        send_added_notice(address.to_string());
    }

    sign_in(db, &account.id, &stored.id).await.map(Json)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{Account, DeletionInfo, Lockout, Totp};
    use revolt_models::v0;
    use rocket::http::{ContentType, Status};
    use serde_json::Value;

    use super::super::fixtures::{keys, seed_passkey, switched_off_kind, STORED_CREDENTIAL_MARKER};
    use super::{Delivery, DELIVERIES};
    use crate::util::passkey;
    use crate::util::passkey_signup::{self, issue_recover_token, peek_recover_token};
    use crate::util::passkey_soft::{b64u, SoftPasskey};
    use crate::util::test::{rt, without_comments, Mail, TestHarness};

    const SEND: &str = "/auth/passkey/recover/send";
    const START: &str = "/auth/passkey/recover/start";
    const FINISH: &str = "/auth/passkey/recover/finish";
    const LOGIN_START: &str = "/auth/passkey/login/start";
    const LOGIN_FINISH: &str = "/auth/passkey/login/finish";

    /// The origin the test config accepts (`features.passkeys.origins`)
    const ORIGIN: &str = "https://app.sloga.gg";

    /// A harness with both switches the recovery routes ask for: passkeys
    /// and passkey sign-up. The config is process-wide and set once, before
    /// the harness (nextest runs one process per test).
    async fn harness_with_recovery_on() -> TestHarness {
        revolt_config::overwrite_config(|settings| {
            settings.features.passkeys.available = true;
            settings.features.passkeys.signup = true;
        })
        .await;

        let harness = TestHarness::new().await;
        passkey::assert_available()
            .await
            .expect("the control: passkeys are on");
        passkey_signup::assert_signup_on()
            .await
            .expect("the control: passkey sign-up is on");
        harness
    }

    /// Status and raw body
    async fn post(harness: &TestHarness, path: &str, body: Value) -> (Status, String) {
        let res = harness
            .client
            .post(path)
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        let status = res.status();
        (status, res.into_string().await.unwrap_or_default())
    }

    /// The `type` of an error body ("" if there is none)
    fn kind_of(body: &str) -> String {
        serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|value| value["type"].as_str().map(str::to_string))
            .unwrap_or_default()
    }

    fn assert_refused(answer: &(Status, String), status: Status, kind: &str, row: &str) {
        assert_eq!(answer.0, status, "{}: {}", row, answer.1);
        assert_eq!(kind_of(&answer.1), kind, "{}: {}", row, answer.1);
    }

    /// What `recover/start` answers for a token that is good
    async fn start(harness: &TestHarness, token: &str) -> Value {
        let (status, body) = post(harness, START, json!({ "token": token })).await;
        assert_eq!(status, Status::Ok, "recover/start refused: {}", body);
        serde_json::from_str(&body).expect("json")
    }

    fn finish_body(token: &str, started: &Value, credential: &Value) -> Value {
        json!({
            "token": token,
            "challenge_id": started["challenge_id"],
            "credential": credential
        })
    }

    /// The session of a finish that signed in
    fn session_of(answer: &(Status, String), row: &str) -> v0::Session {
        assert_eq!(answer.0, Status::Ok, "{}: {}", row, answer.1);
        match serde_json::from_str::<v0::ResponseLogin>(&answer.1).expect("`ResponseLogin`") {
            v0::ResponseLogin::Success(session) => session,
            other => panic!("{}: expected `Success`, got {:?}", row, other),
        }
    }

    /// A fresh recovery token of `account`, as the mail would carry it
    async fn token_for(account: &Account) -> String {
        issue_recover_token(&account.id)
            .await
            .expect("redis")
            .expect("the first token of an account is never held back")
    }

    /// Registers a real passkey on `account`, through the verifier
    async fn registered_passkey(harness: &TestHarness, account: &Account) -> SoftPasskey {
        let session_id = "01TESTSESSION";
        let options = passkey::start_registration(&harness.db, account, session_id)
            .await
            .expect("registration options");

        let mut soft = SoftPasskey::new();
        let credential = soft.create(&options.options, ORIGIN);
        passkey::finish_registration(
            &harness.db,
            account,
            session_id,
            &options.challenge_id,
            credential,
            Some("Phone".to_string()),
        )
        .await
        .expect("the passkey registers");
        soft
    }

    /// Try to sign in with `soft` through the passkey login routes
    async fn passkey_login(harness: &TestHarness, soft: &SoftPasskey) -> (Status, String) {
        let (status, body) = post(harness, LOGIN_START, json!({})).await;
        assert_eq!(status, Status::Ok, "login/start refused: {}", body);
        let options: v0::ResponsePasskeyOptions = serde_json::from_str(&body).expect("options");

        post(
            harness,
            LOGIN_FINISH,
            json!({
                "challenge_id": options.challenge_id,
                "credential": soft.get(&options.options, ORIGIN)
            }),
        )
        .await
    }

    /// Switch the account's authenticator code on, with a real secret
    async fn enable_totp(harness: &TestHarness, account: &mut Account) {
        let secret = account.mfa.generate_new_totp_secret().expect("a secret");
        account.mfa.totp_token = Totp::Enabled { secret };
        account.save(&harness.db).await.unwrap();
    }

    /// A six-digit code that is not the current one
    fn wrong_code(account: &Account) -> String {
        let right = account.mfa.totp_token.generate_code().unwrap();
        let wrong = if right == "000000" { "000001" } else { "000000" };
        wrong.to_string()
    }

    async fn attempts(harness: &TestHarness, account_id: &str) -> Option<i32> {
        let stored = harness.db.fetch_account(account_id).await.unwrap();
        stored.lockout.map(|lockout| lockout.attempts)
    }

    async fn passkey_ids(harness: &TestHarness, account_id: &str) -> Vec<String> {
        let rows = harness.db.fetch_passkeys(account_id).await.unwrap();
        rows.into_iter().map(|row| row.id).collect()
    }

    async fn session_ids(harness: &TestHarness, account_id: &str) -> Vec<String> {
        let sessions = harness.db.fetch_sessions(account_id).await.unwrap();
        sessions.into_iter().map(|session| session.id).collect()
    }

    /// How the `n`th `recover/send` of this process ended (from 0), waiting
    /// for its detached task
    async fn delivery(n: usize) -> Delivery {
        let deadline = Instant::now() + std::time::Duration::from_secs(15);

        loop {
            let found = DELIVERIES.lock().unwrap().get(n).copied();
            if let Some(found) = found {
                return found;
            }

            assert!(Instant::now() < deadline, "send {} never finished", n);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Mails maildev holds for `mailbox`
    async fn mail_count(mailbox: &str) -> usize {
        reqwest::Client::new()
            .get("http://localhost:14080/api/email")
            .send()
            .await
            .expect("maildev unreachable on :14080")
            .json::<Vec<Mail>>()
            .await
            .expect("`Vec<Mail>`")
            .into_iter()
            .filter(|mail| mail.envelope.to.iter().any(|to| to.address == mailbox))
            .count()
    }

    /// Both switches off, as shipped. Which of the two refused cannot be
    /// told here (both answer `FeatureDisabled`): the one-switch-off tests
    /// in `routes/mod.rs` pin each gate by itself.
    ///
    /// Fails if: a recover route asks neither switch, or `recover/send`
    /// answers 204 while passkeys are off.
    #[test]
    fn feature_off_refuses_all_three() {
        rt().block_on(async {
            let off = switched_off_kind().await;
            let harness = TestHarness::new().await;
            let (account, _, _) = harness.new_user().await;
            seed_passkey(&harness, &account, "Phone").await;

            for (path, body) in [
                (SEND, json!({ "email": account.email })),
                (START, json!({ "token": "t" })),
                (
                    FINISH,
                    json!({ "token": "t", "challenge_id": "c", "credential": {} }),
                ),
            ] {
                let answer = post(&harness, path, body).await;
                assert_ne!(answer.0, Status::NoContent, "{}", path);
                assert_ne!(answer.0, Status::Ok, "{}", path);
                assert_eq!(kind_of(&answer.1), off, "{}: {}", path, answer.1);
            }

            // Nothing was issued for the account
            assert!(issue_recover_token(&account.id).await.unwrap().is_some());
        })
    }

    /// The whole flow with no second factor: the mailed link, the new
    /// passkey, and what is left of the account afterwards.
    ///
    /// Fails if: the link is not mailed to the account's address, an older
    /// passkey or an older session survives the recovery, the new passkey
    /// is not stored or cannot sign in, the answer is not a session, or the
    /// "passkey added" notice is not sent.
    #[test]
    fn recovery_replaces_every_passkey_and_session() {
        rt().block_on(async {
            let harness = harness_with_recovery_on().await;
            let (account, old_session, _) = harness.new_user().await;
            let old = registered_passkey(&harness, &account).await;
            seed_passkey(&harness, &account, "Tablet").await;
            account
                .create_session(&harness.db, "Second device".to_string())
                .await
                .unwrap();
            assert_eq!(passkey_ids(&harness, &account.id).await.len(), 2);
            assert_eq!(session_ids(&harness, &account.id).await.len(), 2);

            // The control: the old passkey signs in before the recovery
            let before = passkey_login(&harness, &old).await;
            let control = session_of(&before, "the old passkey, before");
            assert_eq!(session_ids(&harness, &account.id).await.len(), 3);

            let sent = post(&harness, SEND, json!({ "email": account.email })).await;
            assert_eq!(sent, (Status::NoContent, String::new()));

            let (mail, token) = harness.assert_email(&account.email).await;
            assert_eq!(mail.subject, "passkey_recovery");
            assert_eq!(delivery(0).await, Delivery::Sent);

            let started = start(&harness, &token).await;
            assert_eq!(started["second_factor_required"], json!(false));

            let mut new = SoftPasskey::new();
            let credential = new.create(&started["options"], ORIGIN);
            let answer = post(&harness, FINISH, finish_body(&token, &started, &credential)).await;
            let session = session_of(&answer, "recover/finish");

            // Only the new passkey is left
            let rows = harness.db.fetch_passkeys(&account.id).await.unwrap();
            assert_eq!(rows.len(), 1, "every older passkey is gone");
            assert_eq!(rows[0].credential_id, b64u(&new.cred_id));

            // Only the new session is left
            let sessions = session_ids(&harness, &account.id).await;
            assert_eq!(sessions, vec![session.id.clone()]);
            assert!(!sessions.contains(&old_session.id));
            assert!(!sessions.contains(&control.id));

            let (notice, _) = harness.assert_email(&account.email).await;
            assert_eq!(notice.subject, "passkey_added");

            // The new passkey signs in, the old one no longer does
            let with_new = passkey_login(&harness, &new).await;
            session_of(&with_new, "the new passkey");
            let with_old = passkey_login(&harness, &old).await;
            assert_refused(
                &with_old,
                Status::Unauthorized,
                "InvalidCredentials",
                "the old passkey, after",
            );
        })
    }

    /// The passkey ceremony is checked before the code, so a wrong code
    /// costs its challenge and the right one needs a new `recover/start`.
    /// This test used to send the right code with the challenge the wrong
    /// one had used; that order was what let a failed ceremony spend an MFA
    /// recovery code.
    ///
    /// Fails if: an account with an authenticator code recovers without
    /// one, a request with no code spends the challenge, a wrong code is
    /// not counted against the lockout, a refused code spends the link or
    /// anything on the account, or the right code is refused or leaves the
    /// count behind.
    #[test]
    fn an_active_totp_must_be_answered_in_the_same_request() {
        rt().block_on(async {
            let harness = harness_with_recovery_on().await;
            let (mut account, _, _) = harness.new_user().await;
            enable_totp(&harness, &mut account).await;
            let old = seed_passkey(&harness, &account, "Phone").await;
            let sessions_before = session_ids(&harness, &account.id).await;

            let token = token_for(&account).await;
            let started = start(&harness, &token).await;
            assert_eq!(started["second_factor_required"], json!(true));

            let mut new = SoftPasskey::new();
            let credential = new.create(&started["options"], ORIGIN);
            let body = finish_body(&token, &started, &credential);

            // No code: refused, and nothing is counted
            let missing = post(&harness, FINISH, body.clone()).await;
            assert_refused(&missing, Status::Unauthorized, "InvalidCredentials", "no code");
            assert_eq!(attempts(&harness, &account.id).await, None);

            // A wrong code, with the challenge the request above left
            // unspent: refused and counted
            let mut wrong = body;
            wrong["totp_code"] = json!(wrong_code(&account));
            let answer = post(&harness, FINISH, wrong).await;
            assert_refused(&answer, Status::Unauthorized, "InvalidCredentials", "wrong code");
            assert_eq!(attempts(&harness, &account.id).await, Some(1));

            // Nothing on the account changed, and the link is still good
            assert_eq!(passkey_ids(&harness, &account.id).await, vec![old.id.clone()]);
            assert_eq!(session_ids(&harness, &account.id).await, sessions_before);
            assert_eq!(peek_recover_token(&token).await.unwrap(), account.id);

            // The right code, with a new challenge from the same link
            let started = start(&harness, &token).await;
            let credential = new.create(&started["options"], ORIGIN);
            let mut right = finish_body(&token, &started, &credential);
            right["totp_code"] = json!(account.mfa.totp_token.generate_code().unwrap());
            let answer = post(&harness, FINISH, right).await;
            let session = session_of(&answer, "the right code");

            assert_eq!(attempts(&harness, &account.id).await, None);
            let rows = harness.db.fetch_passkeys(&account.id).await.unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].credential_id, b64u(&new.cred_id));
            assert_eq!(session_ids(&harness, &account.id).await, vec![session.id]);
        })
    }

    /// Fails if: the second factor stops honouring the account lockout (a
    /// locked account may try a code), or a locked attempt spends the link.
    #[test]
    fn a_locked_out_account_cannot_try_a_code() {
        rt().block_on(async {
            let harness = harness_with_recovery_on().await;
            let (mut account, _, _) = harness.new_user().await;
            enable_totp(&harness, &mut account).await;
            let old = seed_passkey(&harness, &account, "Phone").await;

            let token = token_for(&account).await;
            let started = start(&harness, &token).await;
            let mut new = SoftPasskey::new();
            let credential = new.create(&started["options"], ORIGIN);

            harness
                .db
                .set_lockout(
                    &account.id,
                    Some(Lockout {
                        attempts: 5,
                        expiry: Some(Timestamp::now_utc() + Duration::seconds(3600)),
                    }),
                )
                .await
                .unwrap();

            // Even the right code
            let mut body = finish_body(&token, &started, &credential);
            body["totp_code"] = json!(account.mfa.totp_token.generate_code().unwrap());
            let answer = post(&harness, FINISH, body).await;
            assert_refused(&answer, Status::Forbidden, "LockedOut", "locked");

            assert_eq!(attempts(&harness, &account.id).await, Some(5));
            assert_eq!(passkey_ids(&harness, &account.id).await, vec![old.id]);
            assert_eq!(peek_recover_token(&token).await.unwrap(), account.id);
        })
    }

    /// Fails if: an MFA recovery code is not accepted as the second factor,
    /// is not spent by the recovery, or a code that is not on the account
    /// is accepted or goes uncounted.
    #[test]
    fn an_mfa_recovery_code_is_accepted_and_spent() {
        rt().block_on(async {
            let harness = harness_with_recovery_on().await;
            let (mut account, _, _) = harness.new_user().await;
            account.mfa.generate_recovery_codes();
            enable_totp(&harness, &mut account).await;
            let code = account.mfa.recovery_codes[0].clone();
            seed_passkey(&harness, &account, "Phone").await;

            let token = token_for(&account).await;
            let started = start(&harness, &token).await;
            let mut new = SoftPasskey::new();
            let credential = new.create(&started["options"], ORIGIN);
            let body = finish_body(&token, &started, &credential);

            let mut unknown = body.clone();
            unknown["recovery_code"] = json!("zzzzz-zzzzz");
            let answer = post(&harness, FINISH, unknown).await;
            assert_refused(&answer, Status::Unauthorized, "InvalidCredentials", "unknown code");
            assert_eq!(attempts(&harness, &account.id).await, Some(1));

            // Both kinds at once is not an answer
            let mut both = body;
            both["recovery_code"] = json!(code);
            both["totp_code"] = json!(account.mfa.totp_token.generate_code().unwrap());
            let answer = post(&harness, FINISH, both).await;
            assert_refused(&answer, Status::Unauthorized, "InvalidCredentials", "both codes");

            // The unknown code went through the ceremony and cost its
            // challenge, so the good one comes with a new one
            let started = start(&harness, &token).await;
            let credential = new.create(&started["options"], ORIGIN);
            let mut good = finish_body(&token, &started, &credential);
            good["recovery_code"] = json!(code);
            let answer = post(&harness, FINISH, good).await;
            session_of(&answer, "the recovery code");

            let stored = harness.db.fetch_account(&account.id).await.unwrap();
            assert!(!stored.mfa.recovery_codes.contains(&code), "the code is spent");
            assert_eq!(stored.mfa.recovery_codes.len(), 9);
        })
    }

    /// A good MFA recovery code sent with a passkey that does not verify.
    ///
    /// Fails if: the second factor is consumed before the passkey ceremony
    /// is verified (the failed request would spend the recovery code, or
    /// count a lockout attempt), the failed request spends the link, or the
    /// same code is then refused with a passkey that does verify.
    #[test]
    fn a_failed_ceremony_leaves_the_recovery_code_unused() {
        rt().block_on(async {
            let harness = harness_with_recovery_on().await;
            let (mut account, _, _) = harness.new_user().await;
            account.mfa.generate_recovery_codes();
            enable_totp(&harness, &mut account).await;
            let code = account.mfa.recovery_codes[0].clone();
            let codes_before = account.mfa.recovery_codes.len();
            let old = seed_passkey(&harness, &account, "Phone").await;

            let token = token_for(&account).await;

            // The right code, and a credential that cannot verify
            let started = start(&harness, &token).await;
            let mut junk = finish_body(&token, &started, &json!({ "id": "AAAA" }));
            junk["recovery_code"] = json!(code);
            let answer = post(&harness, FINISH, junk).await;
            assert_refused(&answer, Status::Unauthorized, "InvalidCredentials", "junk");

            let stored = harness.db.fetch_account(&account.id).await.unwrap();
            assert!(
                stored.mfa.recovery_codes.contains(&code),
                "a failed ceremony spent the recovery code"
            );
            assert_eq!(stored.mfa.recovery_codes.len(), codes_before);
            assert_eq!(attempts(&harness, &account.id).await, None, "nothing was guessed");
            assert_eq!(passkey_ids(&harness, &account.id).await, vec![old.id]);
            assert_eq!(peek_recover_token(&token).await.unwrap(), account.id);

            // The control: the code was a good one. With a passkey that
            // verifies it is accepted, and only now spent
            let started = start(&harness, &token).await;
            let mut new = SoftPasskey::new();
            let credential = new.create(&started["options"], ORIGIN);
            let mut good = finish_body(&token, &started, &credential);
            good["recovery_code"] = json!(code);
            let answer = post(&harness, FINISH, good).await;
            session_of(&answer, "the recovery code");

            let stored = harness.db.fetch_account(&account.id).await.unwrap();
            assert!(!stored.mfa.recovery_codes.contains(&code), "the code is spent");
            assert_eq!(stored.mfa.recovery_codes.len(), codes_before - 1);
        })
    }

    /// Fails if: an assertion from one of the account's passkeys, however
    /// it is sent, lets a recovery through in place of the authenticator
    /// code, or the route starts building a passkey MFA response.
    #[test]
    fn a_passkey_is_never_the_second_factor() {
        rt().block_on(async {
            let harness = harness_with_recovery_on().await;
            let (mut account, _, _) = harness.new_user().await;
            enable_totp(&harness, &mut account).await;
            let old = registered_passkey(&harness, &account).await;
            let rows_before = passkey_ids(&harness, &account.id).await;

            let token = token_for(&account).await;
            let started = start(&harness, &token).await;
            let mut new = SoftPasskey::new();
            let credential = new.create(&started["options"], ORIGIN);

            // A real assertion from the passkey the account still has
            let (status, text) = post(&harness, LOGIN_START, json!({})).await;
            assert_eq!(status, Status::Ok, "{}", text);
            let options: v0::ResponsePasskeyOptions = serde_json::from_str(&text).unwrap();
            let passkey_response = json!({
                "challenge_id": options.challenge_id,
                "credential": old.get(&options.options, ORIGIN)
            });

            // Under every name an MFA response could take
            let mut body = finish_body(&token, &started, &credential);
            body["passkey_response"] = passkey_response.clone();
            body["mfa_response"] = json!({ "passkey_response": passkey_response });
            let answer = post(&harness, FINISH, body).await;
            assert_refused(&answer, Status::Unauthorized, "InvalidCredentials", "as a field");
            assert_eq!(attempts(&harness, &account.id).await, None);

            // And typed into the code field
            let mut body = finish_body(&token, &started, &credential);
            body["totp_code"] = json!(passkey_response.to_string());
            let answer = post(&harness, FINISH, body).await;
            assert_refused(&answer, Status::Unauthorized, "InvalidCredentials", "as a code");

            assert_eq!(passkey_ids(&harness, &account.id).await, rows_before);
            assert_eq!(peek_recover_token(&token).await.unwrap(), account.id);

            // The route only ever builds a code response
            let source = include_str!("recover.rs");
            let routes = source
                .split("\n#[cfg(test)]\nmod tests {")
                .next()
                .expect("the route code");
            let code = without_comments(routes);
            assert!(code.contains("MFAResponse::Totp"), "the control");
            assert!(!code.contains("MFAResponse::Passkey"));
            assert!(!code.contains("finish_assertion"));
        })
    }

    /// Fails if: a failed ceremony burns the mailed link, or the link works
    /// a second time after a recovery, at either step.
    #[test]
    fn the_link_works_once() {
        rt().block_on(async {
            let harness = harness_with_recovery_on().await;
            let (account, _, _) = harness.new_user().await;
            seed_passkey(&harness, &account, "Phone").await;
            let token = token_for(&account).await;

            // A credential that cannot verify spends its challenge only
            let started = start(&harness, &token).await;
            let junk = post(
                &harness,
                FINISH,
                finish_body(&token, &started, &json!({ "id": "AAAA" })),
            )
            .await;
            assert_refused(&junk, Status::Unauthorized, "InvalidCredentials", "junk");
            assert_eq!(peek_recover_token(&token).await.unwrap(), account.id);

            let started = start(&harness, &token).await;
            let mut new = SoftPasskey::new();
            let credential = new.create(&started["options"], ORIGIN);
            let answer = post(&harness, FINISH, finish_body(&token, &started, &credential)).await;
            session_of(&answer, "the first use");
            let rows = passkey_ids(&harness, &account.id).await;
            assert_eq!(rows.len(), 1);

            // The same request again, and the link from the top
            let again = post(&harness, FINISH, finish_body(&token, &started, &credential)).await;
            assert_refused(&again, Status::Unauthorized, "InvalidToken", "finish again");
            let reopened = post(&harness, START, json!({ "token": token })).await;
            assert_refused(&reopened, Status::Unauthorized, "InvalidToken", "start again");

            assert_eq!(passkey_ids(&harness, &account.id).await, rows);
            assert_eq!(session_ids(&harness, &account.id).await.len(), 1);
        })
    }

    /// Fails if: a link issued earlier still works once the account is
    /// disabled or has lost every passkey, or a token that is not one gets
    /// any other answer than a dead link.
    #[test]
    fn a_link_dies_with_the_accounts_standing() {
        rt().block_on(async {
            let harness = harness_with_recovery_on().await;

            // Disabled after the link went out
            let (mut disabled, _, _) = harness.new_user().await;
            seed_passkey(&harness, &disabled, "Phone").await;
            let disabled_token = token_for(&disabled).await;
            let started = start(&harness, &disabled_token).await;
            disabled.disabled = true;
            disabled.save(&harness.db).await.unwrap();

            // Every passkey removed after the link went out
            let (bare, _, _) = harness.new_user().await;
            seed_passkey(&harness, &bare, "Phone").await;
            let bare_token = token_for(&bare).await;
            harness.db.delete_passkeys_for_user(&bare.id).await.unwrap();

            for (row, token) in [
                ("disabled", disabled_token.as_str()),
                ("no passkey", bare_token.as_str()),
                ("not a token", "not-a-token"),
            ] {
                let opened = post(&harness, START, json!({ "token": token })).await;
                assert_refused(&opened, Status::Unauthorized, "InvalidToken", row);

                let mut new = SoftPasskey::new();
                let credential = new.create(&started["options"], ORIGIN);
                let finished =
                    post(&harness, FINISH, finish_body(token, &started, &credential)).await;
                assert_refused(&finished, Status::Unauthorized, "InvalidToken", row);
            }

            assert_eq!(passkey_ids(&harness, &disabled.id).await.len(), 1);
            assert!(passkey_ids(&harness, &bare.id).await.is_empty());
        })
    }

    /// Fails if: `recover/send` answers differently for any kind of address,
    /// or issues or mails a link for an unknown address, an account with no
    /// email, a disabled account, one scheduled for deletion or one that
    /// has no passkey, or mails a second link inside the cooldown.
    #[test]
    fn send_answers_alike_and_mails_only_a_recoverable_account() {
        rt().block_on(async {
            let harness = harness_with_recovery_on().await;

            let unknown = format!("{}@stoat.chat", TestHarness::rand_string());

            let (no_email, _, _) = harness.new_no_email_user().await;
            seed_passkey(&harness, &no_email, "Phone").await;

            let (mut disabled, _, _) = harness.new_user().await;
            seed_passkey(&harness, &disabled, "Phone").await;
            disabled.disabled = true;
            disabled.save(&harness.db).await.unwrap();

            let (scheduled, _, _) = harness.new_user().await;
            seed_passkey(&harness, &scheduled, "Phone").await;
            harness
                .db
                .set_account_deletion(
                    &scheduled.id,
                    Some(DeletionInfo::Scheduled {
                        after: Timestamp::now_utc() + Duration::seconds(3600),
                    }),
                )
                .await
                .unwrap();

            // Has a password and never had a passkey
            let (passkey_less, _, _) = harness.new_user().await;

            let (good, _, _) = harness.new_user().await;
            seed_passkey(&harness, &good, "Phone").await;

            let rows: [(&str, &str, Option<&Account>, Delivery); 7] = [
                ("unknown", unknown.as_str(), None, Delivery::NoAccount),
                // The stand-in address of an account with no email
                ("no email", no_email.email.as_str(), Some(&no_email), Delivery::NoAccount),
                ("disabled", disabled.email.as_str(), Some(&disabled), Delivery::NotEligible),
                ("scheduled", scheduled.email.as_str(), Some(&scheduled), Delivery::NotEligible),
                (
                    "no passkey",
                    passkey_less.email.as_str(),
                    Some(&passkey_less),
                    Delivery::NotEligible,
                ),
                ("recoverable", good.email.as_str(), None, Delivery::Sent),
                ("recoverable, again", good.email.as_str(), None, Delivery::Cooldown),
            ];

            for (n, (row, address, account, expected)) in rows.iter().copied().enumerate() {
                let answer = post(&harness, SEND, json!({ "email": address })).await;
                assert_eq!(answer, (Status::NoContent, String::new()), "{}", row);
                assert_eq!(delivery(n).await, expected, "{}", row);

                match expected {
                    Delivery::Sent => {
                        let (mail, token) = harness.assert_email(address).await;
                        assert_eq!(mail.subject, "passkey_recovery", "{}", row);
                        assert_eq!(peek_recover_token(&token).await.unwrap(), good.id);
                    }
                    _ => assert_eq!(mail_count(address).await, 0, "{}: mailed", row),
                }

                // No token and no cooldown were written for the account
                if let Some(account) = account {
                    assert!(
                        issue_recover_token(&account.id).await.unwrap().is_some(),
                        "{}: a link was issued",
                        row
                    );
                }
            }
        })
    }

    /// Fails if: `recover/start` lists the account's passkeys (an
    /// `excludeCredentials` member, a credential id or a row id anywhere in
    /// the answer), carries more than its three fields, or spends the link.
    #[test]
    fn start_lists_no_credential() {
        rt().block_on(async {
            let harness = harness_with_recovery_on().await;
            let (account, _, _) = harness.new_user().await;
            let first = seed_passkey(&harness, &account, "Phone").await;
            let second = seed_passkey(&harness, &account, "Laptop").await;
            let token = token_for(&account).await;

            for round in 0..2 {
                let (status, body) = post(&harness, START, json!({ "token": token })).await;
                assert_eq!(status, Status::Ok, "round {}: {}", round, body);

                let value: Value = serde_json::from_str(&body).expect("json");
                assert_eq!(
                    keys(&value),
                    vec!["challenge_id", "options", "second_factor_required"]
                );

                let options = value["options"].as_object().expect("an options object");
                assert!(options.contains_key("challenge"), "the control: bare options");
                assert!(!options.contains_key("excludeCredentials"));
                assert!(!body.contains("excludeCredentials"));
                assert!(!body.contains("allowCredentials"));

                for needle in [
                    first.credential_id.as_str(),
                    second.credential_id.as_str(),
                    first.id.as_str(),
                    second.id.as_str(),
                    STORED_CREDENTIAL_MARKER,
                    token.as_str(),
                ] {
                    assert!(!body.contains(needle), "round {}: the answer carries {}", round, needle);
                }
            }

            assert_eq!(peek_recover_token(&token).await.unwrap(), account.id);
        })
    }
}
