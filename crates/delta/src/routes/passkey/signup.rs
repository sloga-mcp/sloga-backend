//! Sign up with a passkey
//! POST /passkey/signup/start
//! POST /passkey/signup/code
//! POST /passkey/signup/resend
//! POST /passkey/signup/options
//! POST /passkey/signup/finish
//!
//! No account exists until `finish` has verified the passkey and passed
//! every gate a second time. Until then the sign-up is a short-lived blob in
//! Redis (`util/passkey_signup.rs`) that only the server writes.
use std::collections::HashMap;

use rand::RngCore;
use revolt_config::config;
use revolt_database::{
    events::client::EventV1,
    util::{
        captcha::check_captcha,
        email::{email_templates, send_email_safe, validate_email},
        shield::{validate_shield, ShieldValidationInput},
    },
    Account, AccountInvite, Database,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;

use crate::routes::onboard::complete::{
    create_onboarded_user, validate_onboarding, DataOnboard, OnboardedUser, ValidOnboarding,
};
use crate::routes::session::login::complete_login;
use crate::util::email_code;
use crate::util::passkey::{self, VerifiedPasskey};
use crate::util::passkey_signup::{self, assert_signup_on, PendingSignup, SignupFields};

/// Err (`email_required`) unless a sign-up may go ahead with no email: its
/// own switch is on and both caps are above 0. The counter itself is only
/// taken from at finish.
async fn assert_no_email_signup_on() -> Result<()> {
    let features = config().await.features.passkeys;

    if features.signup_without_email
        && features.signup_without_email_per_hour > 0
        && features.signup_without_email_per_day > 0
    {
        Ok(())
    } else {
        Err(passkey_signup::email_required())
    }
}

/// Err (`email_required`, the answer finish gives) when this hour's or this
/// day's allowance of sign-ups with no email is used up, or cannot be read.
///
/// A look only, at start and at options, so a full cap refuses before the
/// device makes a passkey. Nothing is taken: finish still decides.
async fn assert_no_email_room() -> Result<()> {
    if passkey_signup::no_email_room().await? {
        Ok(())
    } else {
        Err(passkey_signup::email_required())
    }
}

/// What every refusal about a pending sign-up looks like
fn refused() -> revolt_result::Error {
    create_error!(InvalidCredentials)
}

/// The key of a pending sign-up, as `passkey_signup` names it. The resend
/// wait of its code hangs off this key (`email_code::cooling_down`).
fn pending_key(signup_id: &str) -> String {
    format!("passkey:signup:{signup_id}")
}

/// An id shaped like a sign-up id (32 random bytes, lower-case hex) that
/// names no pending sign-up. Answered by a start that stored nothing.
fn unstored_signup_id() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The account invite a sign-up has to hold: none unless sign-up is
/// invite-only, and then one that exists and is not used up. A look only:
/// the invite is taken at finish, by one conditional write.
async fn required_invite(db: &Database, code: Option<&str>) -> Result<Option<AccountInvite>> {
    if !config().await.api.registration.invite_only {
        return Ok(None);
    }

    match code {
        Some(code) => {
            let invite = db.fetch_account_invite(code).await?;
            if invite.used {
                return Err(create_error!(InvalidInvite));
            }

            Ok(Some(invite))
        }
        None => Err(create_error!(MissingInvite)),
    }
}

/// The onboarding checks for a sign-up's fields, at start and again at finish
async fn checked_onboarding(
    db: &Database,
    username: &str,
    referral_code: Option<&str>,
    invite_code: Option<&str>,
) -> Result<ValidOnboarding> {
    validate_onboarding(
        db,
        DataOnboard {
            username: username.to_string(),
            referral_code: referral_code.map(str::to_string),
            invite_code: invite_code.map(str::to_string),
        },
    )
    .await
}

/// Mail the code to `email`. When the address already has an account, the
/// notice that says so goes out instead and the code goes nowhere, so that
/// sign-up can never be confirmed. The caller answers the same either way.
async fn mail_code(db: &Database, username: &str, email: &str, code: String) -> Result<()> {
    let templates = email_templates().await;

    let mut variables = HashMap::new();
    variables.insert("email", email.to_string());

    if Account::fetch_by_email(db, email).await?.is_some() {
        variables.insert("url", templates.signup_existing.url.clone());
        send_email_safe(email, &templates.signup_existing, variables).await
    } else {
        variables.insert("username", username.to_string());
        variables.insert("code", code);
        send_email_safe(email, &templates.email_code, variables).await
    }
}

/// # Start Passkey Sign-Up
///
/// Check everything the new account will need and hold it as a pending
/// sign-up. With an email, a code is mailed and has to be confirmed
/// (`signup/code`) before the passkey can be created. The answer is the
/// same whether or not the address already has an account.
#[openapi(tag = "Passkey")]
#[post("/signup/start", data = "<data>")]
pub async fn signup_start(
    db: &State<Database>,
    data: Json<v0::DataPasskeySignupStart>,
    mut shield: ShieldValidationInput,
) -> Result<Json<v0::ResponsePasskeySignupStart>> {
    passkey::assert_available().await?;
    assert_signup_on().await?;

    let v0::DataPasskeySignupStart {
        username,
        email,
        no_email_ack,
        invite,
        referral_code,
        invite_code,
        captcha,
    } = data.into_inner();

    // As for a password sign-up: captcha, then shield
    check_captcha(captcha.as_deref()).await?;

    shield.email = email.clone();
    validate_shield(shield).await?;

    match &email {
        Some(email) => validate_email(email)?,
        None => {
            assert_no_email_signup_on().await?;

            // The person was told the account cannot be recovered
            if !no_email_ack {
                return Err(passkey_signup::email_required());
            }

            assert_no_email_room().await?;
        }
    }

    checked_onboarding(
        db,
        &username,
        referral_code.as_deref(),
        invite_code.as_deref(),
    )
    .await?;

    // Kept only where sign-up is invite-only; finish reads it again
    let invite = required_invite(db, invite.as_deref())
        .await?
        .map(|invite| invite.id);

    // Asked last of the checks, so a start refused for anything else takes
    // no mail from the address, and before anything is stored: an address
    // that has had its mails for now gets none, of either kind, and no code
    // is made for it. The answer does not say so: it carries an id of the
    // usual shape that names nothing, which `signup/code`, `signup/resend`
    // and `signup/options` answer as they would a sign-up nobody confirmed.
    if let Some(email) = &email {
        if !email_code::reserve_address(email).await? {
            return Ok(Json(v0::ResponsePasskeySignupStart {
                signup_id: unstored_signup_id(),
                email_code_required: true,
            }));
        }
    }

    let (signup_id, code) = passkey_signup::create(SignupFields {
        username: username.clone(),
        email: email.clone(),
        invite,
        referral_code,
        invite_code,
    })
    .await?;

    if let (Some(email), Some(code)) = (&email, code) {
        mail_code(db, &username, email, code).await?;
    }

    Ok(Json(v0::ResponsePasskeySignupStart {
        signup_id,
        email_code_required: email.is_some(),
    }))
}

/// # Confirm Passkey Sign-Up Email
///
/// Confirm the email of a pending sign-up with the code that was mailed to
/// it. A wrong code, a used one and an unknown sign-up all answer
/// `InvalidCredentials`; the fifth wrong code ends the sign-up.
#[openapi(tag = "Passkey")]
#[post("/signup/code", data = "<data>")]
pub async fn signup_code(data: Json<v0::DataPasskeySignupCode>) -> Result<EmptyResponse> {
    passkey::assert_available().await?;
    assert_signup_on().await?;

    let v0::DataPasskeySignupCode { signup_id, code } = data.into_inner();

    passkey_signup::mark_email_confirmed(&signup_id, &code).await?;

    Ok(EmptyResponse)
}

/// # Resend Passkey Sign-Up Code
///
/// Mail a new code for a pending sign-up; the one sent before stops
/// working. At most one a minute: a request inside that minute answers the
/// same and sends nothing. So does a request for a sign-up that is unknown
/// or has run out: `signup/code` is where that shows.
#[openapi(tag = "Passkey")]
#[post("/signup/resend", data = "<data>")]
pub async fn signup_resend(
    db: &State<Database>,
    data: Json<v0::DataPasskeySignupOptions>,
) -> Result<EmptyResponse> {
    passkey::assert_available().await?;
    assert_signup_on().await?;

    let v0::DataPasskeySignupOptions { signup_id } = data.into_inner();

    // An id that names no sign-up gets the answer of a resend that sent
    // nothing. A start that stored nothing hands out such an id, and it
    // must not be told apart here from one whose mail did go out.
    let pending = match passkey_signup::load(&signup_id).await {
        Ok(pending) => pending,
        Err(error) if matches!(error.error_type, ErrorType::InvalidCredentials) => {
            return Ok(EmptyResponse);
        }
        Err(error) => return Err(error),
    };

    // A sign-up with nothing to resend goes on to `reissue_code`'s refusal
    if let (Some(email), false) = (&pending.email, pending.email_confirmed) {
        // Inside the minute nothing is sent, so nothing is taken from the
        // address either: asked before `reserve_address`, never after
        if email_code::cooling_down(&pending_key(&signup_id)).await? {
            return Ok(EmptyResponse);
        }

        // Asked before a new code is made: an address that has had its
        // mails for now gets none, and the code it was sent before keeps
        // working
        if !email_code::reserve_address(email).await? {
            return Ok(EmptyResponse);
        }
    }

    if let Some((email, code)) = passkey_signup::reissue_code(&signup_id).await? {
        mail_code(db, &pending.username, &email, code).await?;
    }

    Ok(EmptyResponse)
}

/// # Passkey Sign-Up Options
///
/// The WebAuthn options to create the passkey of a pending sign-up. Refused
/// until its email, if it gave one, has been confirmed.
#[openapi(tag = "Passkey")]
#[post("/signup/options", data = "<data>")]
pub async fn signup_options(
    data: Json<v0::DataPasskeySignupOptions>,
) -> Result<Json<v0::ResponsePasskeyOptions>> {
    passkey::assert_available().await?;
    assert_signup_on().await?;

    let v0::DataPasskeySignupOptions { signup_id } = data.into_inner();

    let pending = passkey_signup::load(&signup_id).await?;
    if !pending.ready_for_passkey() {
        return Err(refused());
    }

    if pending.email.is_none() {
        assert_no_email_signup_on().await?;
        assert_no_email_room().await?;
    }

    passkey::start_signup_registration(&signup_id, &pending.user_handle, &pending.username)
        .await
        .map(Json)
}

/// # Finish Passkey Sign-Up
///
/// Create the account with the passkey made for `signup/options`, and sign
/// in. Reads the challenge id, the credential and a session name; everything
/// else was fixed when the sign-up started, and is checked again here.
#[openapi(tag = "Passkey")]
#[post("/signup/finish", data = "<data>")]
pub async fn signup_finish(
    db: &State<Database>,
    data: Json<v0::DataPasskeySignupFinish>,
) -> Result<Json<v0::ResponseLogin>> {
    passkey::assert_available().await?;
    assert_signup_on().await?;

    let v0::DataPasskeySignupFinish {
        challenge_id,
        credential,
        friendly_name,
    } = data.into_inner();

    // Which sign-up this is comes from the challenge, never from the body.
    // A ceremony that fails leaves the pending sign-up for another try.
    let (signup_id, verified) =
        passkey::finish_signup_registration(&challenge_id, credential).await?;

    // Single use: whatever happens below, this sign-up is spent
    let pending = passkey_signup::take(&signup_id).await?;

    let cleared = clear_gates(db, &pending, &verified.credential_id).await?;
    let account = Account::new_passkey_signup(cleared.email.clone())?;

    write_signup(db, account, cleared, verified, friendly_name)
        .await
        .map(Json)
}

/// A sign-up that passed every gate again at finish
struct Cleared {
    onboarding: ValidOnboarding,
    /// The invite to use up, where sign-up is invite-only
    invite: Option<AccountInvite>,
    /// The confirmed address, or None for an account with no email
    email: Option<String>,
}

/// Every gate from start, run again, and the no-email allowance last, so a
/// sign-up refused for anything else takes nothing from it. Writes nothing
/// to the database.
async fn clear_gates(
    db: &Database,
    pending: &PendingSignup,
    credential_id: &str,
) -> Result<Cleared> {
    // An email that was given and never confirmed
    if !pending.ready_for_passkey() {
        return Err(refused());
    }
    let email = pending.confirmed_email().map(str::to_string);

    // One credential, one account
    if db
        .fetch_passkey_by_credential_id(credential_id)
        .await?
        .is_some()
    {
        return Err(create_error!(NoEffect));
    }

    let onboarding = checked_onboarding(
        db,
        &pending.username,
        pending.referral_code.as_deref(),
        pending.invite_code.as_deref(),
    )
    .await?;

    let invite = required_invite(db, pending.invite.as_deref()).await?;

    match &email {
        // Claimed by another account since the code was confirmed
        Some(email) => {
            if Account::fetch_by_email(db, email).await?.is_some() {
                return Err(refused());
            }
        }
        None => {
            assert_no_email_signup_on().await?;
            passkey_signup::reserve_no_email_signup().await?;
        }
    }

    Ok(Cleared {
        onboarding,
        invite,
        email,
    })
}

/// What `write_rows` changed outside the new account's own rows
#[derive(Default)]
struct Written {
    /// The id of the invite this sign-up tried to claim, set before the
    /// claim is sent. The undo gives it back only if the claim names this
    /// account, so it is safe to name an invite the claim did not get.
    invite: Option<String>,
}

/// Insert the account, then everything that hangs off it. If anything
/// after the account insert fails, what was written is removed again and
/// the first error is the answer.
///
/// The referral row, the welcome-server join and `CreateAccount` wait until
/// nothing can fail any more, so an undone sign-up is never announced.
async fn write_signup(
    db: &Database,
    account: Account,
    cleared: Cleared,
    passkey: VerifiedPasskey,
    friendly_name: Option<String>,
) -> Result<v0::ResponseLogin> {
    let Cleared {
        onboarding,
        invite,
        email: _,
    } = cleared;

    db.save_account(&account).await?;

    let mut written = Written::default();
    match write_rows(
        db,
        &account,
        onboarding,
        invite,
        passkey,
        friendly_name,
        &mut written,
    )
    .await
    {
        Ok((answer, onboarded)) => {
            onboarded.settle(db).await;

            EventV1::CreateAccount { account }.global().await;

            Ok(answer)
        }
        Err(error) => {
            // What could not be removed is in the log
            let _ = undo_signup(db, &account.id, written.invite.as_deref()).await;
            Err(error)
        }
    }
}

/// The writes after the account insert, in order: passkey, user (same id as
/// the account), invite, session.
async fn write_rows(
    db: &Database,
    account: &Account,
    onboarding: ValidOnboarding,
    invite: Option<AccountInvite>,
    passkey: VerifiedPasskey,
    friendly_name: Option<String>,
    written: &mut Written,
) -> Result<(v0::ResponseLogin, OnboardedUser)> {
    passkey.store(db, &account.id, None).await?;

    let onboarded = create_onboarded_user(db, account.id.clone(), onboarding).await?;

    // Use up the invite: one conditional write, so of two sign-ups that
    // both passed the gates with one invite, one gets it. The other is
    // refused here and undone.
    if let Some(invite) = invite {
        written.invite = Some(invite.id.clone());

        if !db
            .claim_account_invite_if_unused(&invite.id, &account.id)
            .await?
        {
            return Err(create_error!(InvalidInvite));
        }
    }

    // The shared login gate, so the session is made the one way every
    // sign-in makes it
    match complete_login(db, account.clone(), friendly_name).await? {
        answer @ v0::ResponseLogin::Success(_) => Ok((answer, onboarded)),
        // A brand-new account is neither disabled nor being deleted
        _ => Err(create_error!(InternalError)),
    }
}

/// Give back an invite a failed sign-up claimed, but only while the claim
/// names `account_id`. An invite that is gone, that this sign-up did not
/// get, or that another account holds is left alone. One conditional write
/// in the database; nothing read earlier is written back.
async fn release_invite(db: &Database, account_id: &str, invite_id: &str) -> Result<()> {
    db.release_account_invite_if_claimed_by(invite_id, account_id)
        .await
        .map(|_| ())
}

/// Remove what a failed sign-up wrote for `account_id`: sessions, passkeys,
/// the user, the invite claim, then the account row. Every step is tried
/// whatever the one before it did; one line is logged if any of them fails.
/// Returns what could not be removed (empty when all of it went).
///
/// The account step also counts as failed when no row was removed: this is
/// only called after the insert, so a missing row means something else
/// took it, or it is no longer the row of a passkey sign-up.
///
/// Only ever called with the id of the account this request just inserted.
/// `invite_id` is the invite the sign-up tried to claim, if any.
async fn undo_signup(
    db: &Database,
    account_id: &str,
    invite_id: Option<&str>,
) -> Vec<&'static str> {
    let mut left: Vec<&'static str> = Vec::new();

    if db.delete_all_sessions(account_id, None).await.is_err() {
        left.push("sessions");
    }

    if db.delete_passkeys_for_user(account_id).await.is_err() {
        left.push("passkeys");
    }

    match db.delete_user(account_id).await {
        Ok(()) => {}
        // It was never created
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => {}
        Err(_) => left.push("user"),
    }

    if let Some(invite_id) = invite_id {
        if release_invite(db, account_id, invite_id).await.is_err() {
            left.push("invite claim");
        }
    }

    match db.rollback_signup_account(account_id).await {
        Ok(true) => {}
        Ok(false) => left.push("account (no row was removed)"),
        Err(_) => left.push("account"),
    }

    if !left.is_empty() {
        log::error!(
            "passkeys: a failed sign-up could not be fully undone for account {account_id}; \
             still stored: {}",
            left.join(", ")
        );
    }

    left
}

#[cfg(test)]
mod tests {
    //! The config is set with `overwrite_config`, which works once per
    //! process and before anything reads it: every test sets it first and
    //! relies on nextest's one process per test.
    //!
    //! The tests that give an email need the maildev container, as the
    //! other mail tests do. The no-email counter lives in the shared Redis
    //! under one key per clock hour and day, so the tests that pass it use
    //! caps no run can reach.

    use chrono::Utc;
    use redis_kiss::{get_connection, redis};
    use revolt_database::{
        events::client::EventV1, Account, AccountInvite, EmailVerification, User,
        DISCRIMINATOR_SEARCH_SPACE,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Status};
    use serde_json::Value;
    use ulid::Ulid;

    use super::super::fixtures::{keys, kind, seed_passkey};
    use super::{clear_gates, undo_signup, write_signup};
    use crate::util::email_code;
    use crate::util::passkey::{self, VerifiedPasskey};
    use crate::util::passkey_signup::{self, PendingSignup, SignupFields};
    use crate::util::passkey_soft::{b64u, SoftPasskey};
    use crate::util::test::{rt, Mail, TestHarness};

    const START: &str = "/auth/passkey/signup/start";
    const CODE: &str = "/auth/passkey/signup/code";
    const RESEND: &str = "/auth/passkey/signup/resend";
    const OPTIONS: &str = "/auth/passkey/signup/options";
    const FINISH: &str = "/auth/passkey/signup/finish";

    /// The origin the default config accepts
    const ORIGIN: &str = "https://app.sloga.gg";

    /// A cap on no-email sign-ups that no test run reaches
    const ROOMY: u32 = 1_000_000_000;

    /// Passkeys and passkey sign-up on. `no_email_caps` is the hourly and
    /// daily cap of sign-up with no email, or None to leave that off.
    async fn harness_with_signup(no_email_caps: Option<(u32, u32)>) -> TestHarness {
        revolt_config::overwrite_config(move |settings| {
            let passkeys = &mut settings.features.passkeys;
            passkeys.available = true;
            passkeys.signup = true;

            if let Some((per_hour, per_day)) = no_email_caps {
                passkeys.signup_without_email = true;
                passkeys.signup_without_email_per_hour = per_hour;
                passkeys.signup_without_email_per_day = per_day;
            }
        })
        .await;

        TestHarness::new().await
    }

    /// Sign-up by invite only, with passkeys, passkey sign-up and sign-up
    /// with no email on under caps no run reaches
    async fn harness_with_invite_only_signup() -> TestHarness {
        revolt_config::overwrite_config(|settings| {
            settings.api.registration.invite_only = true;

            let passkeys = &mut settings.features.passkeys;
            passkeys.available = true;
            passkeys.signup = true;
            passkeys.signup_without_email = true;
            passkeys.signup_without_email_per_hour = ROOMY;
            passkeys.signup_without_email_per_day = ROOMY;
        })
        .await;

        TestHarness::new().await
    }

    /// Status and parsed body (`Null` when empty or not JSON)
    async fn post(harness: &TestHarness, path: &str, body: Value) -> (Status, Value) {
        let res = harness
            .client
            .post(path)
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        let status = res.status();
        let body = res.into_string().await.unwrap_or_default();

        (status, serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    fn mailbox() -> String {
        format!("{}@smtp.test", TestHarness::rand_string())
    }

    /// `signup/start` for a sign-up that goes through: its id
    async fn started(harness: &TestHarness, body: Value) -> String {
        let with_email = body.get("email").is_some();
        let (status, answer) = post(harness, START, body).await;
        assert_eq!(status, Status::Ok, "{answer}");
        assert_eq!(keys(&answer), ["email_code_required", "signup_id"]);
        assert_eq!(answer["email_code_required"], with_email, "{answer}");

        answer["signup_id"].as_str().expect("an id").to_string()
    }

    /// `signup/options`, the software passkey, then the body for
    /// `signup/finish`
    async fn finish_body(harness: &TestHarness, signup_id: &str, soft: &mut SoftPasskey) -> Value {
        let (status, options) = post(harness, OPTIONS, json!({ "signup_id": signup_id })).await;
        assert_eq!(status, Status::Ok, "{options}");
        assert_eq!(keys(&options), ["challenge_id", "options"]);

        json!({
            "challenge_id": options["challenge_id"],
            "credential": soft.create(&options["options"], ORIGIN),
            "friendly_name": "Test phone"
        })
    }

    /// The session of a finish that signed in
    fn session_of(answer: &(Status, Value)) -> v0::Session {
        assert_eq!(answer.0, Status::Ok, "{}", answer.1);
        match serde_json::from_value::<v0::ResponseLogin>(answer.1.clone())
            .expect("`ResponseLogin`")
        {
            v0::ResponseLogin::Success(session) => session,
            other => panic!("expected `Success`, got {:?}", other),
        }
    }

    fn assert_refused(answer: &(Status, Value), status: Status, error: &str, row: &str) {
        assert_eq!(answer.0, status, "{row}: {}", answer.1);
        assert_eq!(kind(&answer.1), error, "{row}: {}", answer.1);
    }

    /// How many users hold `username`, whatever their discriminator
    async fn users_named(harness: &TestHarness, username: &str) -> usize {
        harness
            .db
            .fetch_discriminators_in_use(username)
            .await
            .expect("the users")
            .len()
    }

    async fn passkey_owner(harness: &TestHarness, soft: &SoftPasskey) -> Option<String> {
        harness
            .db
            .fetch_passkey_by_credential_id(&b64u(&soft.cred_id))
            .await
            .expect("the lookup")
            .map(|row| row.user_id)
    }

    /// A whole sign-up with no email: the session it ends in
    async fn sign_up_without_email(
        harness: &TestHarness,
        username: &str,
        soft: &mut SoftPasskey,
    ) -> v0::Session {
        let signup_id = started(
            harness,
            json!({ "username": username, "no_email_ack": true }),
        )
        .await;
        let body = finish_body(harness, &signup_id, soft).await;

        session_of(&post(harness, FINISH, body).await)
    }

    #[test]
    fn signup_with_an_email_makes_an_account_with_that_email() {
        rt().block_on(signup_with_an_email_makes_an_account_with_that_email_case())
    }

    /// Fails if: the code that was mailed does not confirm the sign-up, the
    /// account is stored without the address or flagged `email_absent`, the
    /// passkey, the user or the session is missing or under another id than
    /// the account's, or `CreateAccount` is not sent.
    async fn signup_with_an_email_makes_an_account_with_that_email_case() {
        let mut harness = harness_with_signup(None).await;
        let email = mailbox();
        let username = TestHarness::rand_string();

        let signup_id = started(&harness, json!({ "username": username, "email": email })).await;

        let (mail, code) = harness.assert_email(&email).await;
        assert_eq!(mail.subject, "email_code");
        assert_eq!(code.len(), 8, "the mailed code");
        assert!(mail.text.contains(&username), "the mail names the username");

        let (status, body) = post(
            &harness,
            CODE,
            json!({ "signup_id": signup_id, "code": code }),
        )
        .await;
        assert_eq!(status, Status::NoContent, "{body}");

        let mut soft = SoftPasskey::new();
        let body = finish_body(&harness, &signup_id, &mut soft).await;
        let session = session_of(&post(&harness, FINISH, body).await);

        let account = Account::fetch_by_email(&harness.db, &email)
            .await
            .expect("the lookup")
            .expect("an account with that email");
        assert_eq!(account.email, email);
        assert!(!account.email_absent);
        assert_eq!(account.real_email(), Some(email.as_str()));
        assert!(account.password_absent);
        assert!(matches!(account.verification, EmailVerification::Verified));

        // One id for the account, its passkey, its user and its session
        assert_eq!(session.user_id, account.id);
        assert_eq!(
            passkey_owner(&harness, &soft).await.as_deref(),
            Some(account.id.as_str())
        );
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);
        let user = harness.db.fetch_user(&account.id).await.expect("a user");
        assert_eq!(user.username, username);
        let sessions = harness.db.fetch_sessions(&account.id).await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, session.id);
        assert_eq!(sessions[0].name, "Test phone");

        let id = account.id.clone();
        harness
            .wait_for_event(
                "global",
                |event| matches!(event, EventV1::CreateAccount { account } if account.id == id),
            )
            .await;
    }

    #[test]
    fn signup_without_an_email_makes_an_email_absent_account() {
        rt().block_on(signup_without_an_email_makes_an_email_absent_account_case())
    }

    /// Fails if: a sign-up with no email (switch and caps on, acknowledged)
    /// is refused, asks for a code, or ends in an account that is not
    /// `email_absent` with a stand-in address nobody can be mailed at.
    async fn signup_without_an_email_makes_an_email_absent_account_case() {
        let harness = harness_with_signup(Some((ROOMY, ROOMY))).await;
        let username = TestHarness::rand_string();

        let mut soft = SoftPasskey::new();
        let session = sign_up_without_email(&harness, &username, &mut soft).await;

        let account = harness
            .db
            .fetch_account(&session.user_id)
            .await
            .expect("an account");
        assert!(account.email_absent);
        assert_eq!(account.real_email(), None);
        assert!(account.email.ends_with("@noemail.invalid"), "a stand-in");
        assert!(account.password_absent);
        assert!(matches!(account.verification, EmailVerification::Verified));

        assert_eq!(
            passkey_owner(&harness, &soft).await.as_deref(),
            Some(account.id.as_str())
        );
        let user = harness.db.fetch_user(&account.id).await.expect("a user");
        assert_eq!(user.username, username);
        assert_eq!(
            harness.db.fetch_sessions(&account.id).await.unwrap().len(),
            1
        );
    }

    #[test]
    fn no_email_is_refused_while_its_switch_is_off() {
        rt().block_on(no_email_is_refused_while_its_switch_is_off_case())
    }

    /// Fails if: with `signup` on and `signup_without_email` off, a start
    /// with no email goes through (acknowledged or not), or is refused with
    /// anything but `email_required()`.
    async fn no_email_is_refused_while_its_switch_is_off_case() {
        let harness = harness_with_signup(None).await;
        let required = format!("{:?}", passkey_signup::email_required().error_type);
        assert_eq!(required, "InvalidOperation", "the control");

        for (row, body) in [
            ("bare", json!({ "username": TestHarness::rand_string() })),
            (
                "acknowledged",
                json!({ "username": TestHarness::rand_string(), "no_email_ack": true }),
            ),
        ] {
            let answer = post(&harness, START, body).await;
            assert_refused(&answer, Status::BadRequest, &required, row);
            assert!(answer.1.get("signup_id").is_none(), "{}", row);
        }
    }

    #[test]
    fn no_email_needs_the_acknowledgement() {
        rt().block_on(no_email_needs_the_acknowledgement_case())
    }

    /// Fails if: with sign-up with no email on, a start that leaves
    /// `no_email_ack` out or false goes through, or is refused with
    /// anything but `email_required()`.
    async fn no_email_needs_the_acknowledgement_case() {
        let harness = harness_with_signup(Some((ROOMY, ROOMY))).await;

        for (row, body) in [
            (
                "left out",
                json!({ "username": TestHarness::rand_string() }),
            ),
            (
                "false",
                json!({ "username": TestHarness::rand_string(), "no_email_ack": false }),
            ),
        ] {
            let answer = post(&harness, START, body).await;
            assert_refused(&answer, Status::BadRequest, "InvalidOperation", row);
        }

        // The control: acknowledged, the same request starts a sign-up
        started(
            &harness,
            json!({ "username": TestHarness::rand_string(), "no_email_ack": true }),
        )
        .await;
    }

    #[test]
    fn options_wait_for_the_code() {
        rt().block_on(options_wait_for_the_code_case())
    }

    /// Fails if: `signup/options` hands out a challenge for a sign-up whose
    /// email is not confirmed yet, or still refuses once it is.
    async fn options_wait_for_the_code_case() {
        let harness = harness_with_signup(None).await;
        let email = mailbox();

        let signup_id = started(
            &harness,
            json!({ "username": TestHarness::rand_string(), "email": email }),
        )
        .await;

        let early = post(&harness, OPTIONS, json!({ "signup_id": signup_id })).await;
        assert_refused(&early, Status::Unauthorized, "InvalidCredentials", "early");
        assert!(early.1.get("challenge_id").is_none());

        let (_, code) = harness.assert_email(&email).await;
        let (status, body) = post(
            &harness,
            CODE,
            json!({ "signup_id": signup_id, "code": code }),
        )
        .await;
        assert_eq!(status, Status::NoContent, "{body}");

        let (status, options) = post(&harness, OPTIONS, json!({ "signup_id": signup_id })).await;
        assert_eq!(status, Status::Ok, "{options}");
    }

    #[test]
    fn an_address_whose_code_is_never_typed_gets_no_account() {
        rt().block_on(an_address_whose_code_is_never_typed_gets_no_account_case())
    }

    /// Someone signs up with an address that is not theirs. The code goes
    /// to the mailbox they cannot read.
    ///
    /// Fails if: anything short of the mailed code gets a challenge, or an
    /// account, a user or a passkey exists for a sign-up whose code was
    /// never typed.
    async fn an_address_whose_code_is_never_typed_gets_no_account_case() {
        let harness = harness_with_signup(None).await;
        let email = mailbox();
        let username = TestHarness::rand_string();

        let signup_id = started(&harness, json!({ "username": username, "email": email })).await;

        // The control: the code did go to that mailbox
        let (mail, code) = harness.assert_email(&email).await;
        assert_eq!(mail.subject, "email_code");

        let wrong = if code == "00000000" {
            "00000001"
        } else {
            "00000000"
        };
        let guess = post(
            &harness,
            CODE,
            json!({ "signup_id": signup_id, "code": wrong }),
        )
        .await;
        assert_refused(&guess, Status::Unauthorized, "InvalidCredentials", "guess");

        let options = post(&harness, OPTIONS, json!({ "signup_id": signup_id })).await;
        assert_refused(
            &options,
            Status::Unauthorized,
            "InvalidCredentials",
            "options",
        );

        // With no challenge there is nothing to finish with
        let finish = post(
            &harness,
            FINISH,
            json!({ "challenge_id": signup_id, "credential": {} }),
        )
        .await;
        assert_refused(
            &finish,
            Status::Unauthorized,
            "InvalidCredentials",
            "finish",
        );

        assert!(Account::fetch_by_email(&harness.db, &email)
            .await
            .expect("the lookup")
            .is_none());
        assert_eq!(users_named(&harness, &username).await, 0);
    }

    #[test]
    fn an_address_with_an_account_gets_the_same_answer_and_no_code() {
        rt().block_on(an_address_with_an_account_gets_the_same_answer_and_no_code_case())
    }

    /// Fails if: `signup/start` answers differently for an address that
    /// already has an account, mails it a code, lets that sign-up reach a
    /// challenge, or creates or changes any account.
    async fn an_address_with_an_account_gets_the_same_answer_and_no_code_case() {
        let harness = harness_with_signup(None).await;

        let taken = mailbox();
        let existing = Account::new(
            &harness.db,
            taken.clone(),
            "password_insecure".into(),
            false,
        )
        .await
        .expect("an account");
        let stored = |account: Account| serde_json::to_value(account).expect("an account");
        let before = stored(harness.db.fetch_account(&existing.id).await.unwrap());

        // The control: a new address
        let fresh = mailbox();
        let fresh_answer = post(
            &harness,
            START,
            json!({ "username": TestHarness::rand_string(), "email": fresh }),
        )
        .await;
        assert_eq!(fresh_answer.0, Status::Ok, "{}", fresh_answer.1);

        let username = TestHarness::rand_string();
        let answer = post(
            &harness,
            START,
            json!({ "username": username, "email": taken }),
        )
        .await;
        assert_eq!(answer.0, fresh_answer.0, "{}", answer.1);
        assert_eq!(keys(&answer.1), keys(&fresh_answer.1));
        assert_eq!(
            answer.1["email_code_required"],
            fresh_answer.1["email_code_required"]
        );
        let signup_id = answer.1["signup_id"].as_str().expect("an id").to_string();

        // The new address got a code, the taken one a notice with none
        let (mail, _) = harness.assert_email(&fresh).await;
        assert_eq!(mail.subject, "email_code");
        let (mail, token) = harness.assert_email(&taken).await;
        assert_eq!(mail.subject, "signup_existing");
        assert_eq!(token, "", "the notice carries no code");

        // So nothing confirms it, and it never reaches a challenge
        let guess = post(
            &harness,
            CODE,
            json!({ "signup_id": signup_id, "code": "00000000" }),
        )
        .await;
        assert_refused(&guess, Status::Unauthorized, "InvalidCredentials", "guess");
        let options = post(&harness, OPTIONS, json!({ "signup_id": signup_id })).await;
        assert_refused(
            &options,
            Status::Unauthorized,
            "InvalidCredentials",
            "options",
        );

        // Still the one account, exactly as it was
        let found = Account::fetch_by_email(&harness.db, &taken)
            .await
            .expect("the lookup")
            .expect("the account");
        assert_eq!(found.id, existing.id);
        assert_eq!(
            stored(harness.db.fetch_account(&existing.id).await.unwrap()),
            before
        );
        assert_eq!(users_named(&harness, &username).await, 0);
    }

    /// Give every discriminator of `username` to some user
    async fn take_every_discriminator(harness: &TestHarness, username: &str) {
        let space: Vec<String> = DISCRIMINATOR_SEARCH_SPACE.iter().cloned().collect();

        for chunk in space.chunks(200) {
            let inserts = chunk.iter().map(|discriminator| {
                let db = harness.db.clone();
                let user = User {
                    id: Ulid::new().to_string(),
                    username: username.to_string(),
                    discriminator: discriminator.clone(),
                    ..Default::default()
                };

                async move { db.insert_user(&user).await }
            });

            for inserted in futures::future::join_all(inserts).await {
                inserted.expect("a user");
            }
        }
    }

    #[test]
    fn a_username_taken_before_finish_leaves_nothing_behind() {
        rt().block_on(a_username_taken_before_finish_leaves_nothing_behind_case())
    }

    /// Fails if: a username that lost its last discriminator after start
    /// still gets an account at finish, the refusal is anything but
    /// `UsernameTaken`, or a passkey or user row stays behind. It does not
    /// tell the check before the writes from the undo after them: either
    /// keeps it green.
    async fn a_username_taken_before_finish_leaves_nothing_behind_case() {
        let harness = harness_with_signup(Some((ROOMY, ROOMY))).await;
        let username = TestHarness::rand_string();

        // Free at start
        let signup_id = started(
            &harness,
            json!({ "username": username, "no_email_ack": true }),
        )
        .await;
        let mut soft = SoftPasskey::new();
        let body = finish_body(&harness, &signup_id, &mut soft).await;

        // Taken by the time the passkey comes back
        take_every_discriminator(&harness, &username).await;
        let holders = users_named(&harness, &username).await;
        assert_eq!(holders, DISCRIMINATOR_SEARCH_SPACE.len(), "the control");

        let answer = post(&harness, FINISH, body).await;
        assert_refused(&answer, Status::Conflict, "UsernameTaken", "finish");

        assert_eq!(passkey_owner(&harness, &soft).await, None, "a passkey row");
        assert_eq!(
            users_named(&harness, &username).await,
            holders,
            "a user row"
        );

        // The sign-up is spent: there is nothing to try again with
        let again = post(&harness, OPTIONS, json!({ "signup_id": signup_id })).await;
        assert_refused(&again, Status::Unauthorized, "InvalidCredentials", "again");
    }

    #[test]
    fn finish_cannot_be_replayed() {
        rt().block_on(finish_cannot_be_replayed_case())
    }

    /// Fails if: the challenge or the pending sign-up can be used twice, or
    /// a replay stores a second account, user or session.
    async fn finish_cannot_be_replayed_case() {
        let harness = harness_with_signup(Some((ROOMY, ROOMY))).await;
        let username = TestHarness::rand_string();

        let signup_id = started(
            &harness,
            json!({ "username": username, "no_email_ack": true }),
        )
        .await;
        let mut soft = SoftPasskey::new();
        let body = finish_body(&harness, &signup_id, &mut soft).await;

        let session = session_of(&post(&harness, FINISH, body.clone()).await);

        // The very same request again
        let replay = post(&harness, FINISH, body).await;
        assert_refused(
            &replay,
            Status::Unauthorized,
            "InvalidCredentials",
            "replay",
        );

        // And the sign-up itself is gone: no second challenge for it
        let options = post(&harness, OPTIONS, json!({ "signup_id": signup_id })).await;
        assert_refused(
            &options,
            Status::Unauthorized,
            "InvalidCredentials",
            "options",
        );

        assert_eq!(users_named(&harness, &username).await, 1);
        assert_eq!(
            passkey_owner(&harness, &soft).await.as_deref(),
            Some(session.user_id.as_str())
        );
        assert_eq!(
            harness
                .db
                .fetch_sessions(&session.user_id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// Raise a no-email counter key by one, as a sign-up that got through
    /// would have, and give it an expiry if it has none
    async fn count_one(key: &str) {
        let mut conn = get_connection().await.expect("redis").into_inner();

        let _: i64 = redis::cmd("INCR")
            .arg(key)
            .query_async(&mut conn)
            .await
            .expect("INCR");

        let left: i64 = redis::cmd("TTL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .expect("TTL");
        if left < 0 {
            let _: i64 = redis::cmd("EXPIRE")
                .arg(key)
                .arg(7200)
                .query_async(&mut conn)
                .await
                .expect("EXPIRE");
        }
    }

    /// Count one sign-up with no email into this hour and this day, by
    /// hand: the keys are shared with every other test process, so "the
    /// first passes" cannot be pinned. With caps of 1 both are then full.
    async fn use_up_the_no_email_allowance() {
        // The key names of `passkey_signup::counter_keys`
        let now = Utc::now();
        count_one(&format!(
            "passkey:signup-noemail:hour:{}",
            now.format("%Y%m%d%H")
        ))
        .await;
        count_one(&format!(
            "passkey:signup-noemail:day:{}",
            now.format("%Y%m%d")
        ))
        .await;
    }

    #[test]
    fn a_reached_cap_refuses_and_leaves_nothing_behind() {
        rt().block_on(a_reached_cap_refuses_and_leaves_nothing_behind_case())
    }

    /// The caps are 1 an hour and 1 a day, and this hour and day already
    /// hold one sign-up. Driven on the gates of finish with a passkey that
    /// really verified: start and options now refuse a full cap themselves
    /// (`a_reached_cap_refuses_before_the_passkey_is_made`), so no request
    /// can carry a sign-up past them to finish any more.
    ///
    /// Fails if: finish stops taking from the allowance, answers anything
    /// but `email_required()` once it is used up, or leaves a passkey or a
    /// user row behind.
    async fn a_reached_cap_refuses_and_leaves_nothing_behind_case() {
        let harness = harness_with_signup(Some((1, 1))).await;
        let username = TestHarness::rand_string();

        use_up_the_no_email_allowance().await;

        let mut soft = SoftPasskey::new();
        let (pending, verified) = verified_signup(&mut soft, &username).await;

        let error = match clear_gates(&harness.db, &pending, &verified.credential_id).await {
            Err(error) => error,
            Ok(_) => panic!("a sign-up over the cap passed the gates of finish"),
        };
        assert_eq!(format!("{:?}", error.error_type), "InvalidOperation");

        assert_eq!(passkey_owner(&harness, &soft).await, None, "a passkey row");
        assert_eq!(users_named(&harness, &username).await, 0, "a user row");
    }

    #[test]
    fn a_reached_cap_refuses_before_the_passkey_is_made() {
        rt().block_on(a_reached_cap_refuses_before_the_passkey_is_made_case())
    }

    /// The caps are 1 an hour and 1 a day, and this hour and day already
    /// hold one sign-up. The control for "with room both steps answer" is
    /// every test here that signs up with no email under `ROOMY` caps.
    ///
    /// Fails if: `signup/start` or `signup/options` stops looking at the
    /// allowance of sign-ups with no email (the device would make a passkey
    /// that finish then refuses), answers a full cap with anything but
    /// `email_required()`, hands out a sign-up id or a challenge, or the
    /// look is made for a sign-up that gave an email.
    async fn a_reached_cap_refuses_before_the_passkey_is_made_case() {
        let harness = harness_with_signup(Some((1, 1))).await;

        use_up_the_no_email_allowance().await;

        let start = post(
            &harness,
            START,
            json!({ "username": TestHarness::rand_string(), "no_email_ack": true }),
        )
        .await;
        assert_refused(&start, Status::BadRequest, "InvalidOperation", "start");
        assert!(start.1.get("signup_id").is_none(), "{}", start.1);

        // A sign-up that started while there was room, as the route stores it
        let (signup_id, _) = passkey_signup::create(SignupFields {
            username: TestHarness::rand_string(),
            email: None,
            invite: None,
            referral_code: None,
            invite_code: None,
        })
        .await
        .expect("a pending sign-up");

        let options = post(&harness, OPTIONS, json!({ "signup_id": signup_id })).await;
        assert_refused(&options, Status::BadRequest, "InvalidOperation", "options");
        assert!(options.1.get("challenge_id").is_none(), "{}", options.1);

        // The refusal spent nothing: the sign-up is still there
        passkey_signup::load(&signup_id)
            .await
            .expect("the pending sign-up");

        // A sign-up with an email is not counted, so the full cap does not
        // touch it
        started(
            &harness,
            json!({ "username": TestHarness::rand_string(), "email": mailbox() }),
        )
        .await;
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

    /// `mail_count`, read after a pause long enough for a mail that was
    /// sent to show up. The routes wait for the mail server before they
    /// answer, so a mail that is coming is at maildev already.
    async fn settled_mail_count(mailbox: &str) -> usize {
        tokio::time::sleep(std::time::Duration::from_millis(750)).await;
        mail_count(mailbox).await
    }

    /// Take what is left of an address's 15 minutes, as mails to it would
    async fn use_up_the_address(email: &str, already_sent: u32) {
        for n in already_sent..email_code::ADDRESS_MAILS_PER_WINDOW {
            assert!(
                email_code::reserve_address(email).await.expect("redis"),
                "the control: mail {} still fits the window",
                n + 1
            );
        }
    }

    #[test]
    fn a_full_address_gets_the_same_answer_and_no_mail() {
        rt().block_on(a_full_address_gets_the_same_answer_and_no_mail_case())
    }

    /// One address is sent at most 3 mails in 15 minutes, whoever asks.
    ///
    /// Fails if: `signup/start` mails an address that has had its mails (a
    /// code, or the notice to an address that has an account), answers such
    /// a start differently from one that was mailed, stops asking
    /// `reserve_address` before it sends, stores a pending sign-up (and so
    /// a code) for an address it refused, or hands that start an id that
    /// `signup/resend`, `signup/code` or `signup/options` answer differently
    /// from the id of a sign-up that was mailed.
    async fn a_full_address_gets_the_same_answer_and_no_mail_case() {
        let harness = harness_with_signup(None).await;

        // The control: the first start for a new address is mailed a code
        let fresh = mailbox();
        let first = post(
            &harness,
            START,
            json!({ "username": TestHarness::rand_string(), "email": fresh }),
        )
        .await;
        assert_eq!(first.0, Status::Ok, "{}", first.1);
        let (mail, code) = harness.assert_email(&fresh).await;
        assert_eq!(mail.subject, "email_code");
        assert_eq!(mail_count(&fresh).await, 0, "the control: read and removed");

        // That start counted one; two more fill the window
        use_up_the_address(&fresh, 1).await;

        let full = post(
            &harness,
            START,
            json!({ "username": TestHarness::rand_string(), "email": fresh }),
        )
        .await;
        assert_eq!(full.0, first.0, "{}", full.1);
        assert_eq!(keys(&full.1), keys(&first.1));
        assert_eq!(
            full.1["email_code_required"],
            first.1["email_code_required"]
        );
        assert_eq!(settled_mail_count(&fresh).await, 0, "a mail was sent");

        // Nothing was stored for the refused start, so no code exists for
        // it. Its id has the shape of a real one and is not the real one.
        let mailed_id = first.1["signup_id"].as_str().expect("an id");
        let unstored_id = full.1["signup_id"].as_str().expect("an id");
        assert_ne!(unstored_id, mailed_id);
        assert_eq!(unstored_id.len(), mailed_id.len());
        assert_eq!(unstored_id.len(), 64);
        assert!(
            unstored_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{unstored_id}"
        );
        passkey_signup::load(mailed_id)
            .await
            .expect("the control: the mailed start stored its sign-up");
        assert!(
            passkey_signup::load(unstored_id).await.is_err(),
            "a start refused for its address stored a sign-up"
        );

        // The steps after start answer both ids alike. The mailed sign-up
        // is inside its minute, so its resend sends nothing either.
        let wrong = if code == "00000000" {
            "00000001"
        } else {
            "00000000"
        };
        for (path, body) in [
            (RESEND, json!({})),
            (CODE, json!({ "code": wrong })),
            (OPTIONS, json!({})),
        ] {
            let with_id = |id: &str| {
                let mut body = body.clone();
                body["signup_id"] = json!(id);
                body
            };

            let mailed = post(&harness, path, with_id(mailed_id)).await;
            let unstored = post(&harness, path, with_id(unstored_id)).await;
            assert_eq!(unstored, mailed, "{path}");
        }
        assert_eq!(settled_mail_count(&fresh).await, 0, "a mail was sent");

        // The same for an address that has an account: no notice either
        let taken = mailbox();
        Account::new(
            &harness.db,
            taken.clone(),
            "password_insecure".into(),
            false,
        )
        .await
        .expect("an account");
        let before = settled_mail_count(&taken).await;
        use_up_the_address(&taken, 0).await;

        let noticed = post(
            &harness,
            START,
            json!({ "username": TestHarness::rand_string(), "email": taken }),
        )
        .await;
        assert_eq!(noticed.0, first.0, "{}", noticed.1);
        assert_eq!(keys(&noticed.1), keys(&first.1));
        assert_eq!(settled_mail_count(&taken).await, before, "a notice was sent");
    }

    /// Let the next `signup/resend` of a sign-up through its one-a-minute
    /// wait (the key of `email_code::begin_issue` for a pending sign-up)
    async fn end_the_resend_wait(signup_id: &str) {
        let mut conn = get_connection().await.expect("redis").into_inner();

        let _: i64 = redis::cmd("DEL")
            .arg(format!("passkey:signup:{signup_id}:resend"))
            .query_async(&mut conn)
            .await
            .expect("DEL");
    }

    #[test]
    fn a_resend_to_a_full_address_sends_nothing_and_keeps_the_code() {
        rt().block_on(a_resend_to_a_full_address_sends_nothing_and_keeps_the_code_case())
    }

    /// Fails if: `signup/resend` mails an address that has had its mails,
    /// makes a new code for it (the code sent before would stop working),
    /// answers differently, or stops asking `reserve_address` before
    /// `reissue_code`. The first half is the control: with room, a resend
    /// does send a new code and the old one stops working.
    async fn a_resend_to_a_full_address_sends_nothing_and_keeps_the_code_case() {
        let harness = harness_with_signup(None).await;

        // The control: an address with room
        let roomy = mailbox();
        let roomy_id = started(
            &harness,
            json!({ "username": TestHarness::rand_string(), "email": roomy }),
        )
        .await;
        let (_, old_code) = harness.assert_email(&roomy).await;

        end_the_resend_wait(&roomy_id).await;
        let resent = post(&harness, RESEND, json!({ "signup_id": roomy_id })).await;
        assert_eq!(resent.0, Status::NoContent, "{}", resent.1);
        let (mail, new_code) = harness.assert_email(&roomy).await;
        assert_eq!(mail.subject, "email_code");

        // Two draws of eight digits are the same once in a hundred million
        if new_code != old_code {
            let stale = post(
                &harness,
                CODE,
                json!({ "signup_id": roomy_id, "code": old_code }),
            )
            .await;
            assert_refused(&stale, Status::Unauthorized, "InvalidCredentials", "stale");
        }

        // The address under test: one code sent, then its window filled
        let full = mailbox();
        let full_id = started(
            &harness,
            json!({ "username": TestHarness::rand_string(), "email": full }),
        )
        .await;
        let (_, code) = harness.assert_email(&full).await;
        use_up_the_address(&full, 1).await;

        end_the_resend_wait(&full_id).await;
        let refused = post(&harness, RESEND, json!({ "signup_id": full_id })).await;
        assert_eq!(refused, resent, "the same answer");
        assert_eq!(settled_mail_count(&full).await, 0, "a mail was sent");

        // No new code was made: the one that was mailed still confirms
        let (status, body) = post(
            &harness,
            CODE,
            json!({ "signup_id": full_id, "code": code }),
        )
        .await;
        assert_eq!(status, Status::NoContent, "{body}");
    }

    /// What Redis holds under `key`
    async fn stored_under(key: &str) -> Option<String> {
        let mut conn = get_connection().await.expect("redis").into_inner();

        redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .expect("GET")
    }

    #[test]
    fn a_resend_inside_the_minute_takes_nothing_from_the_address() {
        rt().block_on(a_resend_inside_the_minute_takes_nothing_from_the_address_case())
    }

    /// Two impatient taps on "send again" right after the first code.
    ///
    /// Fails if: `signup/resend` asks `reserve_address` before it looks at
    /// the one-a-minute wait (each tap would take one of the address's
    /// three mails and send nothing, locking the person out of their own
    /// code), the look reads another key than the wait of this sign-up, or
    /// a tap inside the minute sends a mail or answers differently. The
    /// second half is the control: once the minute is over, a resend does
    /// take one and does mail.
    async fn a_resend_inside_the_minute_takes_nothing_from_the_address_case() {
        let harness = harness_with_signup(None).await;
        let email = mailbox();
        let (window, _) = email_code::address_keys(&email);

        let signup_id = started(
            &harness,
            json!({ "username": TestHarness::rand_string(), "email": email }),
        )
        .await;
        harness.assert_email(&email).await;
        assert_eq!(
            stored_under(&window).await.as_deref(),
            Some("1"),
            "the control: the start took one mail"
        );

        for tap in 1..=2 {
            let answer = post(&harness, RESEND, json!({ "signup_id": signup_id })).await;
            assert_eq!(answer.0, Status::NoContent, "tap {tap}: {}", answer.1);
            assert_eq!(
                stored_under(&window).await.as_deref(),
                Some("1"),
                "tap {tap} inside the minute took a mail from the address"
            );
        }
        assert_eq!(settled_mail_count(&email).await, 0, "a mail was sent");

        // The control: with the minute over, the same request counts and
        // mails, and the answer is the same
        end_the_resend_wait(&signup_id).await;
        let resent = post(&harness, RESEND, json!({ "signup_id": signup_id })).await;
        assert_eq!(resent.0, Status::NoContent, "{}", resent.1);
        let (mail, second_code) = harness.assert_email(&email).await;
        assert_eq!(mail.subject, "email_code");
        assert_eq!(stored_under(&window).await.as_deref(), Some("2"));

        // A new minute started with that mail
        let answer = post(&harness, RESEND, json!({ "signup_id": signup_id })).await;
        assert_eq!(answer, resent, "the same answer");
        assert_eq!(stored_under(&window).await.as_deref(), Some("2"));
        assert_eq!(settled_mail_count(&email).await, 0, "a mail was sent");

        // The last code mailed is the one that confirms
        let (status, body) = post(
            &harness,
            CODE,
            json!({ "signup_id": signup_id, "code": second_code }),
        )
        .await;
        assert_eq!(status, Status::NoContent, "{body}");
    }

    #[test]
    fn one_credential_cannot_make_two_accounts() {
        rt().block_on(one_credential_cannot_make_two_accounts_case())
    }

    /// Fails if: a second sign-up finishes with a credential that is
    /// already registered, answers anything but `NoEffect`, leaves a second
    /// user, or moves the passkey away from the first account.
    async fn one_credential_cannot_make_two_accounts_case() {
        let harness = harness_with_signup(Some((ROOMY, ROOMY))).await;

        let mut soft = SoftPasskey::new();
        let first = sign_up_without_email(&harness, &TestHarness::rand_string(), &mut soft).await;

        // The same authenticator answers a second sign-up with the same key
        let username = TestHarness::rand_string();
        let signup_id = started(
            &harness,
            json!({ "username": username, "no_email_ack": true }),
        )
        .await;
        let body = finish_body(&harness, &signup_id, &mut soft).await;

        let answer = post(&harness, FINISH, body).await;
        assert_refused(&answer, Status::BadRequest, "NoEffect", "second");

        assert_eq!(users_named(&harness, &username).await, 0);
        assert_eq!(
            passkey_owner(&harness, &soft).await.as_deref(),
            Some(first.user_id.as_str())
        );
        assert_eq!(harness.db.count_passkeys(&first.user_id).await.unwrap(), 1);
    }

    /// A pending sign-up with no email and a passkey verified for it,
    /// straight from the building blocks the routes use
    async fn verified_signup(
        soft: &mut SoftPasskey,
        username: &str,
    ) -> (PendingSignup, VerifiedPasskey) {
        verified_signup_holding(soft, username, None).await
    }

    /// `verified_signup` for a sign-up that started with the account
    /// invite `invite`
    async fn verified_signup_holding(
        soft: &mut SoftPasskey,
        username: &str,
        invite: Option<&str>,
    ) -> (PendingSignup, VerifiedPasskey) {
        let (signup_id, _) = passkey_signup::create(SignupFields {
            username: username.to_string(),
            email: None,
            invite: invite.map(str::to_string),
            referral_code: None,
            invite_code: None,
        })
        .await
        .expect("a pending sign-up");
        let pending = passkey_signup::load(&signup_id).await.expect("load");

        let options =
            passkey::start_signup_registration(&signup_id, &pending.user_handle, username)
                .await
                .expect("options");
        let credential = soft.create(&options.options, ORIGIN);
        let (for_signup, verified) =
            passkey::finish_signup_registration(&options.challenge_id, credential)
                .await
                .expect("a verified passkey");
        assert_eq!(for_signup, signup_id);

        (
            passkey_signup::take(&signup_id).await.expect("take"),
            verified,
        )
    }

    #[test]
    fn a_failure_after_the_account_insert_removes_the_account() {
        rt().block_on(a_failure_after_the_account_insert_removes_the_account_case())
    }

    /// The credential gets registered on another account after the gates
    /// passed, so the passkey write fails with the account already stored.
    ///
    /// Fails if: `write_signup` stops undoing a failed sign-up (the account
    /// row stays), returns another error than the one that stopped it, or
    /// the undo removes the other account's passkey.
    async fn a_failure_after_the_account_insert_removes_the_account_case() {
        let harness = harness_with_signup(Some((ROOMY, ROOMY))).await;
        let (other, _, _) = harness.new_user().await;
        let username = TestHarness::rand_string();

        let mut soft = SoftPasskey::new();
        let (_, theirs) = verified_signup(&mut soft, &TestHarness::rand_string()).await;
        let (pending, ours) = verified_signup(&mut soft, &username).await;
        assert_eq!(theirs.credential_id, ours.credential_id, "the control");

        let cleared = clear_gates(&harness.db, &pending, &ours.credential_id)
            .await
            .expect("every gate passes: the credential is not registered yet");
        theirs
            .store(&harness.db, &other.id, Some("Theirs"))
            .await
            .expect("the other account's passkey");

        let account = Account::new_passkey_signup(None).expect("an account");
        let id = account.id.clone();
        let error = write_signup(&harness.db, account, cleared, ours, None)
            .await
            .expect_err("the credential is taken");
        assert_eq!(format!("{:?}", error.error_type), "NoEffect");

        assert!(harness.db.fetch_account(&id).await.is_err(), "the account");
        assert!(harness.db.fetch_user(&id).await.is_err(), "a user");
        assert_eq!(harness.db.count_passkeys(&id).await.unwrap(), 0);
        assert!(harness.db.fetch_sessions(&id).await.unwrap().is_empty());
        assert_eq!(users_named(&harness, &username).await, 0);

        // The other account keeps its passkey
        assert_eq!(
            passkey_owner(&harness, &soft).await.as_deref(),
            Some(other.id.as_str())
        );
    }

    #[test]
    fn the_undo_removes_every_row_of_the_new_account_only() {
        rt().block_on(the_undo_removes_every_row_of_the_new_account_only_case())
    }

    /// Fails if: `undo_signup` leaves the session, a passkey, the user or
    /// the account of the id it is given, reports a clean undo as failed,
    /// passes over an account row it did not remove (`Ok(false)` from
    /// `rollback_signup_account`) as if it had, or touches another
    /// account's rows.
    async fn the_undo_removes_every_row_of_the_new_account_only_case() {
        let harness = TestHarness::new().await;

        // A bystander with one of everything
        let (bystander, bystander_session, _) = harness.new_user().await;
        seed_passkey(&harness, &bystander, "Theirs").await;

        // What a sign-up that got as far as its session leaves
        let (account, session, user) = harness.new_no_email_user().await;
        seed_passkey(&harness, &account, "Phone").await;
        assert_eq!(user.id, account.id, "the control");
        assert!(harness.db.fetch_session(&session.id).await.is_ok());

        let left = undo_signup(&harness.db, &account.id, None).await;
        assert!(left.is_empty(), "not removed: {left:?}");

        assert!(harness.db.fetch_account(&account.id).await.is_err());
        assert!(harness.db.fetch_user(&account.id).await.is_err());
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 0);
        assert!(harness
            .db
            .fetch_sessions(&account.id)
            .await
            .unwrap()
            .is_empty());

        // A second run does no harm, and says that it removed no account
        // row: the one thing it has left to tell
        let left = undo_signup(&harness.db, &account.id, None).await;
        assert_eq!(left, ["account (no row was removed)"]);

        assert!(harness.db.fetch_account(&bystander.id).await.is_ok());
        assert!(harness.db.fetch_user(&bystander.id).await.is_ok());
        assert_eq!(harness.db.count_passkeys(&bystander.id).await.unwrap(), 1);
        assert!(harness
            .db
            .fetch_session(&bystander_session.id)
            .await
            .is_ok());
    }

    /// An unused invite, stored
    async fn unused_invite(harness: &TestHarness) -> AccountInvite {
        let invite = AccountInvite {
            id: TestHarness::rand_string(),
            used: false,
            claimed_by: None,
        };
        harness
            .db
            .save_account_invite(&invite)
            .await
            .expect("an invite");

        invite
    }

    /// An invite, stored, that `claimed_by` has used up the way a sign-up
    /// does. Returned as it was before the claim.
    async fn claimed_invite(harness: &TestHarness, claimed_by: &str) -> AccountInvite {
        let before = unused_invite(harness).await;

        assert!(
            harness
                .db
                .claim_account_invite_if_unused(&before.id, claimed_by)
                .await
                .expect("the claim"),
            "the control: an unused invite is claimed"
        );

        before
    }

    #[test]
    fn the_undo_leaves_an_invite_another_account_claimed() {
        rt().block_on(the_undo_leaves_an_invite_another_account_claimed_case())
    }

    /// The invite was claimed by another account by the time the undo runs.
    ///
    /// Fails if: `undo_signup` writes the invite back as it was before
    /// without looking at who holds it now (the other account's claim would
    /// be wiped and the invite usable again), or counts leaving it alone as
    /// a failed step.
    async fn the_undo_leaves_an_invite_another_account_claimed_case() {
        let harness = TestHarness::new().await;
        let (account, _, _) = harness.new_no_email_user().await;
        let (other, _, _) = harness.new_user().await;

        let before = claimed_invite(&harness, &other.id).await;

        let left = undo_signup(&harness.db, &account.id, Some(&before.id)).await;
        assert!(left.is_empty(), "not removed: {left:?}");

        let stored = harness
            .db
            .fetch_account_invite(&before.id)
            .await
            .expect("the invite");
        assert!(stored.used, "the other account's claim was wiped");
        assert_eq!(stored.claimed_by.as_deref(), Some(other.id.as_str()));

        // The control: the undo did run for the account it was given
        assert!(harness.db.fetch_account(&account.id).await.is_err());
    }

    #[test]
    fn the_undo_gives_back_an_invite_its_own_account_claimed() {
        rt().block_on(the_undo_gives_back_an_invite_its_own_account_claimed_case())
    }

    /// Fails if: an invite that the failed sign-up used up stays used or
    /// stays claimed by the account that no longer exists.
    async fn the_undo_gives_back_an_invite_its_own_account_claimed_case() {
        let harness = TestHarness::new().await;
        let (account, _, _) = harness.new_no_email_user().await;

        let before = claimed_invite(&harness, &account.id).await;

        // The control: the claim is stored
        let stored = harness
            .db
            .fetch_account_invite(&before.id)
            .await
            .expect("the invite");
        assert!(stored.used);
        assert_eq!(stored.claimed_by.as_deref(), Some(account.id.as_str()));

        let left = undo_signup(&harness.db, &account.id, Some(&before.id)).await;
        assert!(left.is_empty(), "not removed: {left:?}");

        let stored = harness
            .db
            .fetch_account_invite(&before.id)
            .await
            .expect("the invite");
        assert!(!stored.used, "the invite is still used up");
        assert_eq!(stored.claimed_by, None);
    }

    /// The invite `id` as it is stored now
    async fn stored_invite(harness: &TestHarness, id: &str) -> AccountInvite {
        harness
            .db
            .fetch_account_invite(id)
            .await
            .expect("the invite")
    }

    #[test]
    fn a_used_invite_is_refused() {
        rt().block_on(a_used_invite_is_refused_case())
    }

    /// Sign-up is invite-only.
    ///
    /// Fails if: `signup/start` takes an invite that is already used, is
    /// unknown or is left out; two sign-ups that both started with one
    /// unused invite both get an account; the one that comes second is
    /// refused with anything but `InvalidInvite`, leaves a user or a
    /// passkey behind, or changes who holds the invite; or a sign-up with
    /// an unused invite does not end up holding it.
    async fn a_used_invite_is_refused_case() {
        let harness = harness_with_invite_only_signup().await;
        let (other, _, _) = harness.new_user().await;

        let used = claimed_invite(&harness, &other.id).await;
        let start_with = |invite: Option<&str>| {
            let mut body = json!({ "username": TestHarness::rand_string(), "no_email_ack": true });
            if let Some(invite) = invite {
                body["invite"] = json!(invite);
            }
            body
        };

        for (row, invite, error) in [
            ("left out", None, "MissingInvite"),
            ("unknown", Some("no such invite"), "InvalidInvite"),
            ("used", Some(used.id.as_str()), "InvalidInvite"),
        ] {
            let answer = post(&harness, START, start_with(invite)).await;
            assert_refused(&answer, Status::BadRequest, error, row);
            assert!(answer.1.get("signup_id").is_none(), "{row}: {}", answer.1);
        }
        let stored = stored_invite(&harness, &used.id).await;
        assert!(stored.used);
        assert_eq!(stored.claimed_by.as_deref(), Some(other.id.as_str()));

        // Two sign-ups start with the same unused invite, and both get as
        // far as a passkey before either finishes
        let free = unused_invite(&harness).await;
        let late_name = TestHarness::rand_string();
        let first_id = started(&harness, start_with(Some(free.id.as_str()))).await;
        let late_id = started(
            &harness,
            json!({ "username": late_name, "no_email_ack": true, "invite": free.id }),
        )
        .await;

        let mut first_soft = SoftPasskey::new();
        let mut late_soft = SoftPasskey::new();
        let first_body = finish_body(&harness, &first_id, &mut first_soft).await;
        let late_body = finish_body(&harness, &late_id, &mut late_soft).await;

        // The control: the first one finishes and holds the invite
        let session = session_of(&post(&harness, FINISH, first_body).await);
        let stored = stored_invite(&harness, &free.id).await;
        assert!(stored.used, "the sign-up did not use its invite up");
        assert_eq!(stored.claimed_by.as_deref(), Some(session.user_id.as_str()));

        let late = post(&harness, FINISH, late_body).await;
        assert_refused(&late, Status::BadRequest, "InvalidInvite", "late");
        assert_eq!(users_named(&harness, &late_name).await, 0, "a user row");
        assert_eq!(
            passkey_owner(&harness, &late_soft).await,
            None,
            "a passkey row"
        );

        let stored = stored_invite(&harness, &free.id).await;
        assert!(stored.used, "the refused sign-up freed the invite");
        assert_eq!(stored.claimed_by.as_deref(), Some(session.user_id.as_str()));

        // And it is used up for every start from here on
        let again = post(&harness, START, start_with(Some(free.id.as_str()))).await;
        assert_refused(&again, Status::BadRequest, "InvalidInvite", "again");
    }

    #[test]
    fn a_claim_that_loses_the_invite_undoes_the_signup() {
        rt().block_on(a_claim_that_loses_the_invite_undoes_the_signup_case())
    }

    /// Sign-up is invite-only. Another account takes the invite after this
    /// sign-up passed the gates of finish and before its own claim, which
    /// no request can time: driven on `write_signup` with a passkey that
    /// really verified.
    ///
    /// Fails if: the claim in `write_rows` goes back to a blind save (this
    /// sign-up would get an account on an invite another account holds), a
    /// lost claim is answered with anything but `InvalidInvite`, the
    /// account, user, passkey or session of the loser stays, or the undo
    /// frees the invite the other account holds.
    async fn a_claim_that_loses_the_invite_undoes_the_signup_case() {
        let harness = harness_with_invite_only_signup().await;
        let (other, _, _) = harness.new_user().await;
        let invite = unused_invite(&harness).await;
        let username = TestHarness::rand_string();

        let mut soft = SoftPasskey::new();
        let (pending, verified) =
            verified_signup_holding(&mut soft, &username, Some(invite.id.as_str())).await;
        let cleared = clear_gates(&harness.db, &pending, &verified.credential_id)
            .await
            .expect("every gate passes: the invite is not used yet");

        assert!(
            harness
                .db
                .claim_account_invite_if_unused(&invite.id, &other.id)
                .await
                .expect("the other claim"),
            "the control: the other account gets the invite"
        );

        let account = Account::new_passkey_signup(None).expect("an account");
        let id = account.id.clone();
        let error = write_signup(&harness.db, account, cleared, verified, None)
            .await
            .expect_err("the invite is taken");
        assert_eq!(format!("{:?}", error.error_type), "InvalidInvite");

        assert!(harness.db.fetch_account(&id).await.is_err(), "the account");
        assert!(harness.db.fetch_user(&id).await.is_err(), "a user");
        assert_eq!(harness.db.count_passkeys(&id).await.unwrap(), 0);
        assert!(harness.db.fetch_sessions(&id).await.unwrap().is_empty());
        assert_eq!(users_named(&harness, &username).await, 0);
        assert_eq!(passkey_owner(&harness, &soft).await, None);

        // The other account still holds it
        let stored = stored_invite(&harness, &invite.id).await;
        assert!(stored.used, "the loser's undo freed the invite");
        assert_eq!(stored.claimed_by.as_deref(), Some(other.id.as_str()));
    }

    #[test]
    fn every_route_is_refused_while_signup_is_off() {
        rt().block_on(every_route_is_refused_while_signup_is_off_case())
    }

    /// Passkeys on, passkey sign-up off (as Step 1 shipped).
    ///
    /// Fails if: a sign-up route stops asking for the `signup` switch, or
    /// hands out a sign-up id or a challenge with it off.
    async fn every_route_is_refused_while_signup_is_off_case() {
        revolt_config::overwrite_config(|settings| {
            settings.features.passkeys.available = true;
        })
        .await;
        let harness = TestHarness::new().await;
        passkey::assert_available()
            .await
            .expect("the control: passkeys themselves are on");

        let id = "0".repeat(64);
        for (path, body) in [
            (
                START,
                json!({ "username": TestHarness::rand_string(), "email": mailbox() }),
            ),
            (CODE, json!({ "signup_id": id, "code": "00000000" })),
            (RESEND, json!({ "signup_id": id })),
            (OPTIONS, json!({ "signup_id": id })),
            (FINISH, json!({ "challenge_id": id, "credential": {} })),
        ] {
            let answer = post(&harness, path, body).await;
            assert_refused(&answer, Status::BadRequest, "FeatureDisabled", path);
            assert!(answer.1.get("signup_id").is_none(), "{}", path);
            assert!(answer.1.get("challenge_id").is_none(), "{}", path);
        }
    }
}
