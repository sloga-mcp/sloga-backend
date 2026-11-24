//! Give an account that has no email its first address.
//! POST /account/email/add/start
//! POST /account/email/add/finish
use std::collections::HashMap;

use revolt_database::util::email::{email_templates, send_email_safe, validate_email};
use revolt_database::{Account, Database, ValidatedTicket};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;

use crate::util::email_code;

/// Where the pending code of an account lives. One per account: a new start
/// replaces the code of the one before.
fn code_key(account_id: &str) -> String {
    format!("passkey:email-add:{account_id}")
}

/// # Add an Email
///
/// Start giving an account that has no email its first address: an 8-digit
/// code is mailed to the address, to be typed into the app.
///
/// Needs a validated MFA ticket. Only for an account that has no email.
/// An account that has one moves it with `PATCH /account/change/email`,
/// which refuses an account that has no password: such an account adds a
/// password first.
///
/// The answer is 204 whether or not a code was sent. An address that
/// already has an account gets a mail saying so instead of a code, a
/// second request within a minute sends nothing and does not count
/// against the address, and a request for an address that was mailed too
/// often lately sends nothing either.
#[openapi(tag = "Account")]
#[post("/email/add/start", data = "<data>")]
pub async fn email_add_start(
    db: &State<Database>,
    account: Account,
    _ticket: ValidatedTicket,
    data: Json<v0::DataEmailAddStart>,
) -> Result<EmptyResponse> {
    crate::util::passkey::assert_available().await?;
    crate::util::passkey_signup::assert_signup_on().await?;

    if account.real_email().is_some() {
        return Err(create_error!(InvalidOperation));
    }

    let v0::DataEmailAddStart { email } = data.into_inner();

    // Format, no address under `.invalid`, and the disposable list. Says
    // nothing about any account.
    validate_email(&email)?;

    // Read before the two cases part, so both do the same work
    let username = match db.fetch_user(&account.id).await {
        Ok(user) => user.username,
        Err(_) => "(no name yet)".to_string(),
    };

    let key = code_key(&account.id);

    // Inside the minute after this account's last code nothing would be
    // mailed anyway. Looked at first, and only read, so a request that
    // sends nothing takes nothing from the address's allowance below.
    if email_code::cooling_down(&key).await? {
        return Ok(EmptyResponse);
    }

    // The address's own allowance, whoever asks and whichever mail it would
    // be. Asked before a code exists, so a refusal sends nothing, stores no
    // new code and leaves the one mailed before working. The answer is the
    // same as for a mail that went out.
    if !email_code::reserve_address(&email).await? {
        return Ok(EmptyResponse);
    }

    // The cooldown is claimed whichever mail goes out, so neither kind can
    // be sent more than once a minute
    let Some(code) = email_code::issue(&key, &email).await? else {
        return Ok(EmptyResponse);
    };

    let taken = Account::fetch_by_email(db, &email).await?.is_some();
    let templates = email_templates().await;

    // Either way one mail to the same address, awaited, and a failure is
    // answered the same
    if taken {
        // The code is dropped unsent. What `issue` stored cannot be used:
        // nobody was told the code, and the finish step refuses an address
        // another account holds.
        drop(code);

        let template = &templates.signup_existing;
        let variables = HashMap::from([
            ("email", email.clone()),
            ("url", template.url.clone()),
        ]);
        send_email_safe(&email, template, variables).await?;
    } else {
        let variables = HashMap::from([
            ("username", username),
            ("code", code),
            ("email", email.clone()),
        ]);
        send_email_safe(&email, &templates.email_code, variables).await?;
    }

    Ok(EmptyResponse)
}

/// # Confirm the Added Email
///
/// Type in the code that `email/add/start` mailed. The address becomes the
/// account's email.
///
/// A wrong, expired or used code, a code that ran out of tries, and an
/// address that another account took meanwhile all get the same answer.
#[openapi(tag = "Account")]
#[post("/email/add/finish", data = "<data>")]
pub async fn email_add_finish(
    db: &State<Database>,
    mut account: Account,
    data: Json<v0::DataEmailAddFinish>,
) -> Result<EmptyResponse> {
    crate::util::passkey::assert_available().await?;
    crate::util::passkey_signup::assert_signup_on().await?;

    if account.real_email().is_some() {
        return Err(create_error!(InvalidOperation));
    }

    let v0::DataEmailAddFinish { code } = data.into_inner();

    // Counts the try, and deletes the code on the fifth wrong one or when
    // it is right
    let email = email_code::check(&code_key(&account.id), &code).await?;

    // One conditional write: only while this account still has no email
    // and no other account holds the address. The account is stored
    // `Verified` already and stays so.
    if !account.set_first_email(db, email).await? {
        return Err(create_error!(InvalidCredentials));
    }

    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use revolt_database::{Account, EmailVerification, MFATicket, Session};
    use rocket::http::{ContentType, Status};
    use rocket::local::asynchronous::LocalRequest;
    use serde_json::Value;

    use super::code_key;
    use crate::routes::passkey::fixtures::{kind, send, ticket_for};
    use crate::util::test::{rt, Mail, TestHarness};
    use crate::util::{email_code, passkey, passkey_signup};

    const START: &str = "/auth/account/email/add/start";
    const FINISH: &str = "/auth/account/email/add/finish";

    /// A harness with both switches these routes need: passkeys and passkey
    /// sign-up. As `fixtures::harness_with_passkeys_on`, with the second
    /// switch set in the same overwrite: the config can be set once per
    /// process (nextest runs one process per test).
    async fn harness_with_add_on() -> TestHarness {
        revolt_config::overwrite_config(|settings| {
            let passkeys = &mut settings.features.passkeys;
            passkeys.available = true;
            passkeys.signup = true;
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

    fn start<'c>(harness: &'c TestHarness, email: &str) -> LocalRequest<'c> {
        harness
            .client
            .post(START)
            .header(ContentType::JSON)
            .body(json!({ "email": email }).to_string())
    }

    fn finish<'c>(harness: &'c TestHarness, code: &str) -> LocalRequest<'c> {
        harness
            .client
            .post(FINISH)
            .header(ContentType::JSON)
            .body(json!({ "code": code }).to_string())
    }

    /// An address nobody holds, on a domain `validate_email` accepts
    fn fresh_address() -> String {
        format!("{}@validemail.com", TestHarness::rand_string())
    }

    /// Start with a fresh validated ticket; the status and body
    async fn start_with_ticket(
        harness: &TestHarness,
        account: &Account,
        session: &Session,
        email: &str,
    ) -> (Status, Value) {
        let ticket = ticket_for(harness, account).await;
        send(start(harness, email), session, Some(&ticket)).await
    }

    /// Start for `email` and read the code out of the mail
    async fn mailed_code(
        harness: &TestHarness,
        account: &Account,
        session: &Session,
        email: &str,
    ) -> String {
        let (status, body) = start_with_ticket(harness, account, session, email).await;
        assert_eq!(status, Status::NoContent, "{}", body);

        let (mail, code) = harness.assert_email(email).await;
        assert_eq!(mail.subject, "email_code");
        assert_eq!(code.len(), 8, "a code of 8 digits: {:?}", mail.text);
        code
    }

    /// Eight digits that are not `code`, different for each `n` below 10
    fn other_code(code: &str, n: u32) -> String {
        let number: u32 = code.parse().expect("digits");
        format!("{:08}", (number + 1 + n) % 100_000_000)
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

    async fn assert_still_without_email(harness: &TestHarness, account: &Account, row: &str) {
        let stored = harness.db.fetch_account(&account.id).await.unwrap();
        assert!(stored.email_absent, "{}", row);
        assert_eq!(stored.email, account.email, "{}: the stand-in moved", row);
        assert!(stored.real_email().is_none(), "{}", row);
    }

    /// Fails if: the code is not mailed to the new address, the right code
    /// does not land the address, the account is left `email_absent` or not
    /// `Verified`, the address cannot be looked up afterwards, or the code
    /// works a second time.
    #[test]
    fn a_typed_code_gives_the_account_its_email() {
        rt().block_on(async {
            let harness = harness_with_add_on().await;
            let (account, session, _) = harness.new_no_email_user().await;
            let address = fresh_address();

            let code = mailed_code(&harness, &account, &session, &address).await;

            // Nothing lands before the code is typed
            assert_still_without_email(&harness, &account, "before the code").await;

            let (status, body) = send(finish(&harness, &code), &session, None).await;
            assert_eq!(status, Status::NoContent, "{}", body);

            let stored = harness.db.fetch_account(&account.id).await.unwrap();
            assert_eq!(stored.email, address);
            assert!(!stored.email_absent);
            assert_eq!(stored.real_email(), Some(address.as_str()));
            assert!(matches!(stored.verification, EmailVerification::Verified));

            let found = Account::fetch_by_email(&harness.db, &address)
                .await
                .unwrap()
                .expect("the address finds the account");
            assert_eq!(found.id, account.id);

            // The account has an email now: both steps are closed to it
            let (status, body) = send(finish(&harness, &code), &session, None).await;
            assert_eq!(status, Status::BadRequest, "{}", body);
            assert_eq!(kind(&body), "InvalidOperation");
        })
    }

    /// Fails if: a wrong code is not counted, the code survives its fifth
    /// wrong try, or a wrong code changes the account.
    #[test]
    fn five_wrong_codes_use_the_code_up() {
        rt().block_on(async {
            let harness = harness_with_add_on().await;
            let (account, session, _) = harness.new_no_email_user().await;
            let address = fresh_address();

            let code = mailed_code(&harness, &account, &session, &address).await;

            for n in 0..5 {
                let wrong = other_code(&code, n);
                assert_ne!(wrong, code);

                let (status, body) = send(finish(&harness, &wrong), &session, None).await;
                assert_eq!(status, Status::Unauthorized, "try {}: {}", n, body);
                assert_eq!(kind(&body), "InvalidCredentials", "try {}", n);
            }

            // The right code, too late
            let (status, body) = send(finish(&harness, &code), &session, None).await;
            assert_eq!(status, Status::Unauthorized, "{}", body);
            assert_eq!(kind(&body), "InvalidCredentials");

            assert_still_without_email(&harness, &account, "after the tries").await;
            assert!(Account::fetch_by_email(&harness.db, &address)
                .await
                .unwrap()
                .is_none());
        })
    }

    /// Fails if: starting with an address another account holds answers
    /// differently from a free one, mails a code to it, skips the "you
    /// already have an account" mail, or lets the address land.
    #[test]
    fn an_address_held_at_start_gets_no_code() {
        rt().block_on(async {
            let harness = harness_with_add_on().await;
            let (account, session, _) = harness.new_no_email_user().await;
            let (holder, _, _) = harness.new_user().await;

            // The control: what a free address answers
            let (other, other_session, _) = harness.new_no_email_user().await;
            let free = start_with_ticket(&harness, &other, &other_session, &fresh_address()).await;

            let held = start_with_ticket(&harness, &account, &session, &holder.email).await;
            assert_eq!(held, free, "one answer for both");
            assert_eq!(held.0, Status::NoContent);
            assert_eq!(held.1, Value::Null, "an empty body");

            let (mail, code) = harness.assert_email(&holder.email).await;
            assert_eq!(mail.subject, "signup_existing");
            assert_eq!(code, "", "no code in the mail: {:?}", mail.text);
            assert_eq!(mail_count(&holder.email).await, 0, "one mail only");

            // No guess lands it
            let (status, body) = send(finish(&harness, "00000000"), &session, None).await;
            assert_eq!(status, Status::Unauthorized, "{}", body);
            assert_eq!(kind(&body), "InvalidCredentials");

            assert_still_without_email(&harness, &account, "held at start").await;
            let stored = harness.db.fetch_account(&holder.id).await.unwrap();
            assert_eq!(stored.email, holder.email);
        })
    }

    /// Fails if: an address that another account took between the two
    /// steps lands on this account, or the refusal differs from the one a
    /// wrong code gets.
    #[test]
    fn an_address_taken_before_finish_does_not_land() {
        rt().block_on(async {
            let harness = harness_with_add_on().await;
            let (account, session, _) = harness.new_no_email_user().await;
            let address = fresh_address();

            let code = mailed_code(&harness, &account, &session, &address).await;

            // What a wrong code answers, on another account so no try of
            // this one is spent
            let (other, other_session, _) = harness.new_no_email_user().await;
            let other_code_sent =
                mailed_code(&harness, &other, &other_session, &fresh_address()).await;
            let wrong = send(
                finish(&harness, &other_code(&other_code_sent, 0)),
                &other_session,
                None,
            )
            .await;
            assert_eq!(wrong.0, Status::Unauthorized);

            // Someone else signs up with the address meanwhile
            let holder = Account::new(
                &harness.db,
                address.clone(),
                "password_insecure".into(),
                false,
            )
            .await
            .unwrap();

            let late = send(finish(&harness, &code), &session, None).await;
            assert_eq!(late, wrong, "the same answer as a wrong code");
            assert_eq!(kind(&late.1), "InvalidCredentials");

            assert_still_without_email(&harness, &account, "taken before finish").await;
            let found = Account::fetch_by_email(&harness.db, &address)
                .await
                .unwrap()
                .expect("the holder");
            assert_eq!(found.id, holder.id);
        })
    }

    /// Fails if: an account that already has an email can start or finish
    /// here, or a code is issued for it.
    #[test]
    fn an_account_with_an_email_is_refused() {
        rt().block_on(async {
            let harness = harness_with_add_on().await;
            let (account, session, _) = harness.new_user().await;
            let address = fresh_address();

            let (status, body) = start_with_ticket(&harness, &account, &session, &address).await;
            assert_eq!(status, Status::BadRequest, "{}", body);
            assert_eq!(kind(&body), "InvalidOperation");

            let (status, body) = send(finish(&harness, "00000000"), &session, None).await;
            assert_eq!(status, Status::BadRequest, "{}", body);
            assert_eq!(kind(&body), "InvalidOperation");

            // Nothing was issued: the cooldown is still free
            assert!(email_code::issue(&code_key(&account.id), &address)
                .await
                .unwrap()
                .is_some());
            assert_eq!(mail_count(&address).await, 0);

            let stored = harness.db.fetch_account(&account.id).await.unwrap();
            assert_eq!(stored.email, account.email);
        })
    }

    /// Fails if: the start step runs with no ticket, with a ticket that was
    /// never validated, with another account's ticket or with a used one,
    /// or issues a code in any of those cases.
    #[test]
    fn start_needs_a_validated_ticket_of_this_account() {
        rt().block_on(async {
            let harness = harness_with_add_on().await;
            let (account, session, _) = harness.new_no_email_user().await;
            let (stranger, _, _) = harness.new_user().await;
            let address = fresh_address();

            let unvalidated = MFATicket::new(account.id.to_string(), false);
            unvalidated.save(&harness.db).await.unwrap();
            let foreign = ticket_for(&harness, &stranger).await;

            for (row, ticket) in [
                ("no ticket", None),
                ("unvalidated", Some(unvalidated.token.as_str())),
                ("another account's", Some(foreign.as_str())),
                ("unknown", Some("no-such-ticket")),
            ] {
                let (status, body) = send(start(&harness, &address), &session, ticket).await;
                assert_ne!(status, Status::NoContent, "{}: {}", row, body);
                assert_ne!(status, Status::Ok, "{}: {}", row, body);
                assert!(
                    status.code == 400 || status.code == 401 || status.code == 403,
                    "{}: {}",
                    row,
                    status
                );
            }

            // Nothing was issued or mailed
            assert_eq!(mail_count(&address).await, 0);
            assert_still_without_email(&harness, &account, "no ticket").await;

            // The control: a good ticket works, once
            let ticket = ticket_for(&harness, &account).await;
            let (status, body) = send(start(&harness, &address), &session, Some(&ticket)).await;
            assert_eq!(status, Status::NoContent, "{}", body);
            let (mail, _) = harness.assert_email(&address).await;
            assert_eq!(mail.subject, "email_code");

            let (status, body) = send(start(&harness, &address), &session, Some(&ticket)).await;
            assert_ne!(status, Status::NoContent, "a used ticket: {}", body);
        })
    }

    /// Fails if: a second start inside the minute mails again or answers
    /// differently, replaces the code that was mailed, or a stand-in
    /// (`.invalid`) address is accepted.
    #[test]
    fn a_second_start_within_the_minute_mails_nothing() {
        rt().block_on(async {
            let harness = harness_with_add_on().await;
            let (account, session, _) = harness.new_no_email_user().await;
            let address = fresh_address();

            let code = mailed_code(&harness, &account, &session, &address).await;

            let again = start_with_ticket(&harness, &account, &session, &address).await;
            assert_eq!(again, (Status::NoContent, Value::Null));
            assert_eq!(mail_count(&address).await, 0, "no second mail");

            // Addresses nobody may type: the stand-in domain, and any other
            // new address under `.invalid`
            for refused in ["someone@noemail.invalid", "new@sloga.invalid"] {
                let (status, body) =
                    start_with_ticket(&harness, &account, &session, refused).await;
                assert_eq!(status, Status::BadRequest, "{refused}: {}", body);
                assert_eq!(kind(&body), "IncorrectData", "{refused}");
            }

            // The first code still works
            let (status, body) = send(finish(&harness, &code), &session, None).await;
            assert_eq!(status, Status::NoContent, "{}", body);
            let stored = harness.db.fetch_account(&account.id).await.unwrap();
            assert_eq!(stored.email, address);
            assert_eq!(stored.real_email(), Some(address.as_str()));
        })
    }

    /// What the 15-minute counter of an address holds. The key is spelled
    /// out here as `util/email_code.rs` names it:
    /// `passkey:email-rate:<SHA-256 hex of the normalised address>:window`.
    async fn address_window_count(email: &str) -> Option<String> {
        use sha2::{Digest, Sha256};

        let normalised = revolt_database::util::email::normalise_email(email.to_string());
        let hash: String = Sha256::digest(normalised.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        let mut conn = redis_kiss::get_connection()
            .await
            .expect("redis")
            .into_inner();
        redis_kiss::redis::cmd("GET")
            .arg(format!("passkey:email-rate:{hash}:window"))
            .query_async(&mut conn)
            .await
            .expect("GET")
    }

    /// Fails if: a start inside the minute after the account's last code
    /// (which mails nothing) is still counted against the address it names,
    /// the same one or another, or answers differently from a start that
    /// was mailed.
    #[test]
    fn a_start_inside_the_cooldown_is_not_counted_against_the_address() {
        rt().block_on(async {
            let harness = harness_with_add_on().await;
            let (account, session, _) = harness.new_no_email_user().await;
            let address = fresh_address();
            let other = fresh_address();

            assert_eq!(
                address_window_count(&address).await,
                None,
                "the control: nothing counted yet"
            );

            let code = mailed_code(&harness, &account, &session, &address).await;
            assert_eq!(
                address_window_count(&address).await.as_deref(),
                Some("1"),
                "the control: the mail that went out is counted"
            );

            // Again inside the minute, for the same address and for another
            let again = start_with_ticket(&harness, &account, &session, &address).await;
            assert_eq!(again, (Status::NoContent, Value::Null));
            let elsewhere = start_with_ticket(&harness, &account, &session, &other).await;
            assert_eq!(elsewhere, (Status::NoContent, Value::Null));

            assert_eq!(
                address_window_count(&address).await.as_deref(),
                Some("1"),
                "a start that mailed nothing was counted"
            );
            assert_eq!(
                address_window_count(&other).await,
                None,
                "a start that mailed nothing was counted against another address"
            );
            assert_eq!(mail_count(&address).await, 0, "no second mail");
            assert_eq!(mail_count(&other).await, 0, "no mail");

            // The code that was mailed still works
            let (status, body) = send(finish(&harness, &code), &session, None).await;
            assert_eq!(status, Status::NoContent, "{}", body);
        })
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

    /// One address is sent at most 3 mails in 15 minutes, whoever asks.
    ///
    /// Fails if: a start for an address that has had its mails sends a code
    /// or the "you already have an account" mail, answers differently from
    /// a start that was mailed, makes a code for the asking account, counts
    /// another spelling of the mailbox apart, or stops the code that was
    /// mailed earlier from working.
    #[test]
    fn a_full_address_gets_the_same_answer_no_mail_and_no_code() {
        rt().block_on(async {
            let harness = harness_with_add_on().await;
            let address = fresh_address();

            // The control: the first start for the address is mailed a code
            let (first, first_session, _) = harness.new_no_email_user().await;
            let mailed = start_with_ticket(&harness, &first, &first_session, &address).await;
            assert_eq!(mailed, (Status::NoContent, Value::Null));
            let (mail, code) = harness.assert_email(&address).await;
            assert_eq!(mail.subject, "email_code");

            use_up_the_address(&address, 1).await;

            // Other accounts ask for the same mailbox, as typed and in
            // another spelling
            let shouted = address.to_uppercase();
            let mut late = vec![];
            for typed in [&address, &shouted] {
                let (account, session, _) = harness.new_no_email_user().await;
                let answer = start_with_ticket(&harness, &account, &session, typed).await;
                assert_eq!(answer, mailed, "{}: one answer, mailed or not", typed);
                late.push((account, session));
            }
            assert_eq!(mail_count(&address).await, 0, "no mail");
            assert_eq!(mail_count(&shouted).await, 0, "no mail");

            for (account, session) in &late {
                // The code mailed to the first account opens nothing here
                let (status, body) = send(finish(&harness, &code), session, None).await;
                assert_eq!(status, Status::Unauthorized, "{}", body);
                assert_eq!(kind(&body), "InvalidCredentials");
                assert_still_without_email(&harness, account, "a full address").await;

                // No code was made: the account's cooldown is still free
                assert!(email_code::issue(&code_key(&account.id), &address)
                    .await
                    .unwrap()
                    .is_some());
            }

            // An address that has an account: its notice is counted too
            let (holder, _, _) = harness.new_user().await;
            use_up_the_address(&holder.email, 0).await;
            let (asker, asker_session, _) = harness.new_no_email_user().await;
            let answer = start_with_ticket(&harness, &asker, &asker_session, &holder.email).await;
            assert_eq!(answer, mailed, "one answer, mailed or not");
            assert_eq!(mail_count(&holder.email).await, 0, "no notice");

            // The code that was mailed still works
            let (status, body) = send(finish(&harness, &code), &first_session, None).await;
            assert_eq!(status, Status::NoContent, "{}", body);
            let stored = harness.db.fetch_account(&first.id).await.unwrap();
            assert_eq!(stored.real_email(), Some(address.as_str()));
        })
    }
}
