//! Add a passkey to the signed-in account.
//! POST /passkey/register/start
//! POST /passkey/register/finish
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

use revolt_database::{Account, Database, Session, ValidatedTicket};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::serde::json::Json;
use rocket::State;

use crate::util::passkey;

/// How old a session may be and still add a first passkey with no ticket
const TICKETLESS_SESSION_MAX_AGE_MS: u64 = 10 * 60 * 1000;

/// What the ticketless rule reads. All of it is server state; nothing here
/// comes from the request.
struct TicketlessFacts {
    /// Passkeys the account has now
    passkeys: u64,
    /// `account.mfa.is_active()`
    mfa_active: bool,
    /// `account.password_absent`
    password_absent: bool,
    /// This session was made by a Google or Apple sign-in: the marker the
    /// callback wrote, read back from Redis
    oauth_session: bool,
    /// Time since the session was minted, from its id. `None` if the id
    /// carries no usable time.
    session_age_ms: Option<u64>,
}

/// Whether a passkey may be added with no MFA ticket.
///
/// Only a first passkey, on an account that has no usable password or from
/// a session that Google or Apple sign-in made, with no authenticator code,
/// a few minutes after sign-in. Such an account often cannot mint a ticket
/// at all (its password is random), so the fresh sign-in stands in for one.
/// An old session never does: a stolen one could plant a passkey. Being
/// linked to Google or Apple is not enough: a password sign-in on a linked
/// account still needs the ticket.
///
/// This is the only place that decides it. "The account has no ticket
/// methods" is not a reason to skip the ticket anywhere else.
fn may_register_without_ticket(facts: &TicketlessFacts) -> bool {
    facts.passkeys == 0
        && !facts.mfa_active
        && (facts.password_absent || facts.oauth_session)
        && matches!(
            facts.session_age_ms,
            Some(age) if age <= TICKETLESS_SESSION_MAX_AGE_MS
        )
}

/// Milliseconds since the session was minted, read from its id.
///
/// Session ids are ULIDs made by the server at sign-in, so the time in them
/// cannot be set or refreshed by a client, unlike the session's name or its
/// last-seen stamp. `None` for an id that is not a ULID or lies in the future.
fn session_age_ms(session_id: &str, now_ms: u64) -> Option<u64> {
    let minted_ms = ulid::Ulid::from_string(session_id).ok()?.timestamp_ms();
    now_ms.checked_sub(minted_ms)
}

fn now_ms() -> Option<u64> {
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(since_epoch.as_millis()).ok()
}

/// What let a request add a passkey
#[derive(PartialEq)]
enum AddProof {
    /// A validated ticket of this account, claimed by the guard
    Ticket,
    /// No ticket: the first-passkey rule held
    FreshSession,
}

/// The gate in front of storing a passkey: a ticket, or the first-passkey
/// rule.
///
/// `ticket` is `None` for every guard failure (no header, an unknown, used,
/// expired or unvalidated ticket, one minted on another account), so a bad
/// ticket gets exactly as far as no ticket.
async fn authorize_add(
    db: &Database,
    account: &Account,
    session: &Session,
    ticket: &Option<ValidatedTicket>,
) -> Result<AddProof> {
    if ticket.is_some() {
        return Ok(AddProof::Ticket);
    }

    let facts = TicketlessFacts {
        passkeys: db.count_passkeys(&account.id).await?,
        mfa_active: account.mfa.is_active(),
        password_absent: account.password_absent,
        // False when Redis cannot be read
        oauth_session: passkey::is_oauth_session(&session.id).await,
        session_age_ms: now_ms().and_then(|now| session_age_ms(&session.id, now)),
    };

    if may_register_without_ticket(&facts) {
        Ok(AddProof::FreshSession)
    } else {
        Err(create_error!(NotPrivileged))
    }
}

/// Delete a passkey that was stored a moment ago and may not stay. Tried
/// twice; a row that is already gone is as good as deleted.
async fn take_back(db: &Database, account_id: &str, passkey_id: &str) {
    for _ in 0..2 {
        match db.delete_passkey(account_id, passkey_id).await {
            Ok(()) => return,
            Err(error) if matches!(error.error_type, ErrorType::NotFound) => return,
            Err(_) => {}
        }
    }

    log::error!(
        "passkeys: could not take back a passkey added without a ticket \
         (account {account_id}, passkey {passkey_id}); remove it by hand"
    );
}

/// After a ticketless add: the new passkey stays only while it is the
/// account's only one.
///
/// Two ticketless requests can both see zero passkeys and both store one.
/// Only a first passkey may skip the ticket, so one that is not alone is
/// taken back and the request refused; both racers may lose. A count that
/// cannot be read is treated the same way.
async fn settle_ticketless_add(db: &Database, account_id: &str, passkey_id: &str) -> Result<()> {
    match db.count_passkeys(account_id).await {
        Ok(1) => Ok(()),
        Ok(_) => {
            take_back(db, account_id, passkey_id).await;
            Err(create_error!(NotPrivileged))
        }
        Err(error) => {
            take_back(db, account_id, passkey_id).await;
            Err(error)
        }
    }
}

/// # Start Adding a Passkey
///
/// Get the options for creating a passkey on this account.
///
/// Takes no MFA ticket, and a ticket sent here is left unused: this step
/// only hands out a challenge bound to this account and this session. The
/// finish step decides whether the passkey may be stored.
#[openapi(tag = "Passkey")]
#[post("/register/start")]
pub async fn register_start(
    db: &State<Database>,
    account: Account,
    session: Session,
) -> Result<Json<v0::ResponsePasskeyOptions>> {
    passkey::assert_available().await?;

    passkey::start_registration(db, &account, &session.id)
        .await
        .map(Json)
}

/// # Finish Adding a Passkey
///
/// Store the passkey the device created.
///
/// Needs an MFA ticket. The one exception is a first passkey on an account
/// that has no authenticator code and either no usable password or a session
/// made by Google or Apple sign-in, from a session that signed in within the
/// last ten minutes.
#[openapi(tag = "Passkey")]
#[post("/register/finish", data = "<data>")]
pub async fn register_finish(
    db: &State<Database>,
    account: Account,
    session: Session,
    ticket: Option<ValidatedTicket>,
    data: Json<v0::DataPasskeyFinish>,
) -> Result<Json<v0::PasskeyInfo>> {
    passkey::assert_available().await?;

    let proof = authorize_add(db, &account, &session, &ticket).await?;

    let data = data.into_inner();
    let stored = passkey::finish_registration(
        db,
        &account,
        &session.id,
        &data.challenge_id,
        data.credential,
        data.name,
    )
    .await?;

    // A ticketless add that raced another one does not stay
    if proof == AddProof::FreshSession {
        settle_ticketless_add(db, &account.id, &stored.id).await?;
    }

    // Nothing else changes: the account keeps `password_absent` and its MFA
    // settings as they were.

    // TODO(passkeys): email the owner that a passkey was added. Nothing is
    // sent yet: `email_templates()` has no plain security notice to send
    // (verify, reset, deletion, suspension and takedown only).

    Ok(Json(passkey::passkey_info(&stored)))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use iso8601_timestamp::Timestamp;
    use revolt_database::{Account, Session, Totp};
    use revolt_result::ErrorType;
    use rocket::http::{ContentType, Status};
    use rocket::local::asynchronous::LocalRequest;
    use serde_json::Value;
    use ulid::Ulid;

    use super::super::fixtures::{
        harness_with_passkeys_on, keys, kind, seed_passkey, send, switched_off_kind, ticket_for,
    };
    use super::{
        may_register_without_ticket, session_age_ms, settle_ticketless_add, take_back,
        TicketlessFacts, TICKETLESS_SESSION_MAX_AGE_MS,
    };
    use crate::util::passkey::mark_oauth_session;
    use crate::util::passkey_soft::SoftPasskey;
    use crate::util::test::{rt, without_comments, without_whitespace, TestHarness};

    const START: &str = "/auth/passkey/register/start";
    const FINISH: &str = "/auth/passkey/register/finish";

    /// The origin the test config accepts (`features.passkeys.origins`)
    const ORIGIN: &str = "https://app.sloga.gg";

    fn start(harness: &TestHarness) -> LocalRequest<'_> {
        harness.client.post(START)
    }

    fn finish<'c>(
        harness: &'c TestHarness,
        challenge_id: &str,
        credential: Value,
        name: Option<&str>,
    ) -> LocalRequest<'c> {
        harness.client.post(FINISH).header(ContentType::JSON).body(
            json!({
                "challenge_id": challenge_id,
                "credential": credential,
                "name": name
            })
            .to_string(),
        )
    }

    /// A finish body no verifier accepts, for the refusals that come first
    fn junk_finish(harness: &TestHarness) -> LocalRequest<'_> {
        finish(harness, "no-such-challenge", json!({}), None)
    }

    /// A session of `account` whose id says it was minted `age` ago. It was
    /// "seen" just now, and its name is whatever a client would like.
    async fn session_minted_ago(
        harness: &TestHarness,
        account: &Account,
        age: Duration,
    ) -> Session {
        let session = Session {
            id: Ulid::from_datetime(SystemTime::now() - age).to_string(),
            user_id: account.id.clone(),
            token: format!(
                "{}{}",
                TestHarness::rand_string(),
                TestHarness::rand_string()
            ),
            name: "signed in just now".to_string(),
            last_seen: Timestamp::now_utc(),
            origin: None,
            subscription: None,
        };
        harness.db.save_session(&session).await.unwrap();
        session
    }

    /// An account with no usable password and a session minted just now
    async fn passwordless_user(harness: &TestHarness) -> (Account, Session) {
        let (mut account, session, _) = harness.new_user().await;
        account.password_absent = true;
        account.save(&harness.db).await.unwrap();
        (account, session)
    }

    #[test]
    fn ticketless_rule_table() {
        const MAX: u64 = TICKETLESS_SESSION_MAX_AGE_MS;

        // Every row that may skip the ticket: (passkeys, mfa, no password,
        // oauth session, session age). Anything not listed must be refused.
        let allowed = [
            (0, false, true, false, Some(0)),
            (0, false, true, false, Some(MAX)),
            (0, false, false, true, Some(0)),
            (0, false, false, true, Some(MAX)),
            (0, false, true, true, Some(0)),
            (0, false, true, true, Some(MAX)),
        ];

        let mut passed = 0;
        let mut rows = 0;

        for passkeys in [0u64, 1, 2] {
            for mfa_active in [false, true] {
                for password_absent in [false, true] {
                    for oauth_session in [false, true] {
                        for session_age_ms in
                            [None, Some(0), Some(MAX), Some(MAX + 1), Some(u64::MAX)]
                        {
                            let row = (
                                passkeys,
                                mfa_active,
                                password_absent,
                                oauth_session,
                                session_age_ms,
                            );
                            let got = may_register_without_ticket(&TicketlessFacts {
                                passkeys,
                                mfa_active,
                                password_absent,
                                oauth_session,
                                session_age_ms,
                            });

                            assert_eq!(got, allowed.contains(&row), "{:?}", row);

                            rows += 1;
                            if got {
                                passed += 1;
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(rows, 120);
        assert_eq!(passed, allowed.len());
    }

    #[test]
    fn session_age_comes_from_the_ulid() {
        let minted = Ulid::from_parts(1_000_000, 7).to_string();

        assert_eq!(session_age_ms(&minted, 1_000_000), Some(0));
        assert_eq!(session_age_ms(&minted, 1_600_000), Some(600_000));

        // An id from the future, and ids that are not ULIDs, have no age
        assert_eq!(session_age_ms(&minted, 999_999), None);
        assert_eq!(session_age_ms("", 1_600_000), None);
        assert_eq!(session_age_ms("signed in just now", 1_600_000), None);
    }

    /// The finish step passes the gate before anything is verified or
    /// stored, the start step names no ticket at all (so one sent there is
    /// never claimed), and the route code reads nothing a client can set and
    /// never asks which ticket methods exist
    #[test]
    fn both_steps_pass_the_one_gate() {
        const GATE: &str = "authorize_add(db,&account,&session,&ticket).await?";
        const STORE: &str = "passkey::finish_registration(";

        let source = include_str!("register.rs");
        let routes = source
            .split("#[cfg(test)]")
            .next()
            .expect("the code above the tests");
        let code = without_whitespace(&without_comments(routes));

        let start_at = code
            .find("pubasyncfnregister_start(")
            .expect("the start route");
        let finish_at = code
            .find("pubasyncfnregister_finish(")
            .expect("the finish route");
        assert!(start_at < finish_at, "start is expected above finish");

        let start_route = &code[start_at..finish_at];
        let finish_route = &code[finish_at..];

        // Start: account and session only
        assert!(
            !start_route.to_lowercase().contains("ticket"),
            "the start route names a ticket"
        );
        assert!(
            !start_route.contains("authorize_add"),
            "the start route runs the gate"
        );
        assert!(start_route.contains("passkey::assert_available().await?;"));

        // Finish: the gate, then the verifier
        assert!(finish_route.contains("ticket:Option<ValidatedTicket>"));
        assert_eq!(code.matches(GATE).count(), 1, "the gate is called once");
        assert_eq!(code.matches(STORE).count(), 1);
        let gate_at = finish_route.find(GATE).expect("finish passes the gate");
        let store_at = finish_route.find(STORE).expect("finish stores the passkey");
        assert!(gate_at < store_at, "the gate must come before the verifier");

        assert_eq!(
            code.matches("may_register_without_ticket(").count(),
            2,
            "the rule is defined once and called once"
        );

        for banned in ["ticket_methods", "last_seen", "session.name", "get_methods"] {
            assert!(!code.contains(banned), "the route code reads `{}`", banned);
        }
    }

    /// The finish step refuses at the gate, before the verifier sees anything
    async fn assert_gate_refuses(harness: &TestHarness, session: &Session, ticket: Option<&str>) {
        let (status, body) = send(junk_finish(harness), session, ticket).await;
        assert_eq!(status, Status::Forbidden, "{}", body);
        assert_eq!(kind(&body), "NotPrivileged");
    }

    /// The finish step lets the request through the gate: the junk body
    /// reaches the verifier, which refuses the unknown challenge
    async fn assert_gate_passes(harness: &TestHarness, session: &Session, ticket: Option<&str>) {
        let (status, body) = send(junk_finish(harness), session, ticket).await;
        assert_eq!(status, Status::Unauthorized, "{}", body);
        assert_eq!(kind(&body), "InvalidCredentials", "{}", body);
    }

    /// The start step answers with a challenge
    async fn assert_start_answers(harness: &TestHarness, session: &Session, ticket: Option<&str>) {
        let (status, body) = send(start(harness), session, ticket).await;
        assert_eq!(status, Status::Ok, "{}", body);
        assert!(body["challenge_id"].is_string(), "{}", body);
    }

    #[test]
    fn refused_with_the_feature_off() {
        rt().block_on(refused_with_the_feature_off_case())
    }

    /// Passkeys ship off. An account that would need no ticket, and one
    /// that brings a ticket, both get the switch's own refusal.
    async fn refused_with_the_feature_off_case() {
        let harness = TestHarness::new().await;
        let off = switched_off_kind().await;

        let (account, session) = passwordless_user(&harness).await;

        let (status, body) = send(start(&harness), &session, None).await;
        assert_ne!(status, Status::NotFound, "the route is mounted");
        assert_ne!(status, Status::Ok);
        assert_eq!(kind(&body), off, "{}", body);
        assert!(body.get("challenge_id").is_none(), "{}", body);

        let ticket = ticket_for(&harness, &account).await;
        let (status, body) = send(start(&harness), &session, Some(&ticket)).await;
        assert_ne!(status, Status::Ok);
        assert_eq!(kind(&body), off, "{}", body);

        let (status, body) = send(junk_finish(&harness), &session, None).await;
        assert_ne!(status, Status::NotFound, "the route is mounted");
        assert_ne!(status, Status::Ok);
        assert_eq!(kind(&body), off, "{}", body);

        let ticket = ticket_for(&harness, &account).await;
        let (status, body) = send(junk_finish(&harness), &session, Some(&ticket)).await;
        assert_ne!(status, Status::Ok);
        assert_eq!(kind(&body), off, "{}", body);

        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 0);
    }

    #[test]
    fn a_ticket_is_needed_once_a_passkey_exists() {
        rt().block_on(a_ticket_is_needed_once_a_passkey_exists_case())
    }

    async fn a_ticket_is_needed_once_a_passkey_exists_case() {
        let harness = harness_with_passkeys_on().await;
        let (account, session) = passwordless_user(&harness).await;

        // The control: with no passkey yet, this account needs no ticket
        assert_gate_passes(&harness, &session, None).await;

        seed_passkey(&harness, &account, "Phone").await;

        // The start step still answers: it only hands out a challenge
        assert_start_answers(&harness, &session, None).await;

        assert_gate_refuses(&harness, &session, None).await;

        // With a ticket the finish step gets past the gate, to the verifier
        let ticket = ticket_for(&harness, &account).await;
        assert_gate_passes(&harness, &session, Some(&ticket)).await;

        // Which spent it
        assert_gate_refuses(&harness, &session, Some(&ticket)).await;

        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);
    }

    #[test]
    fn start_leaves_a_ticket_unused() {
        rt().block_on(start_leaves_a_ticket_unused_case())
    }

    /// One ticket per add: a ticket sent with the start step is still good
    /// for the finish step
    async fn start_leaves_a_ticket_unused_case() {
        let harness = harness_with_passkeys_on().await;
        let (account, session, _) = harness.new_user().await;

        let ticket = ticket_for(&harness, &account).await;
        assert_start_answers(&harness, &session, Some(&ticket)).await;
        assert!(
            harness.db.fetch_ticket_by_token(&ticket).await.is_ok(),
            "the start step claimed the ticket"
        );

        // The control: without it this password account is refused
        assert_gate_refuses(&harness, &session, None).await;
        assert_gate_passes(&harness, &session, Some(&ticket)).await;
    }

    #[test]
    fn an_old_session_is_refused_without_a_ticket() {
        rt().block_on(an_old_session_is_refused_without_a_ticket_case())
    }

    /// Eleven minutes after sign-in the session no longer stands in for a
    /// ticket, however recently it was seen
    async fn an_old_session_is_refused_without_a_ticket_case() {
        let harness = harness_with_passkeys_on().await;
        let (account, _) = passwordless_user(&harness).await;

        let old = session_minted_ago(&harness, &account, Duration::from_secs(11 * 60)).await;

        assert_gate_refuses(&harness, &old, None).await;

        // The control: the same account from a session minted nine minutes ago
        let young = session_minted_ago(&harness, &account, Duration::from_secs(9 * 60)).await;
        assert_gate_passes(&harness, &young, None).await;

        // And the old session still works with a ticket
        let ticket = ticket_for(&harness, &account).await;
        assert_gate_passes(&harness, &old, Some(&ticket)).await;
    }

    #[test]
    fn mfa_or_a_plain_password_account_is_refused_without_a_ticket() {
        rt().block_on(mfa_or_a_plain_password_account_is_refused_without_a_ticket_case())
    }

    async fn mfa_or_a_plain_password_account_is_refused_without_a_ticket_case() {
        let harness = harness_with_passkeys_on().await;

        // Linked to Google, with an authenticator code
        let (mut with_totp, with_totp_session, _) = harness.new_user().await;
        with_totp.google_id = Some(format!("google-{}", TestHarness::rand_string()));
        with_totp.password_absent = true;
        with_totp.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        with_totp.save(&harness.db).await.unwrap();

        // An ordinary password account
        let (plain, plain_session, _) = harness.new_user().await;

        // Even from a session Google sign-in made, the code still counts
        mark_oauth_session(&with_totp_session.id).await;

        for session in [&with_totp_session, &plain_session] {
            assert_gate_refuses(&harness, session, None).await;
        }

        // The control: the password account with a ticket
        let ticket = ticket_for(&harness, &plain).await;
        assert_gate_passes(&harness, &plain_session, Some(&ticket)).await;
    }

    #[test]
    fn a_linked_account_needs_the_oauth_session_marker() {
        rt().block_on(a_linked_account_needs_the_oauth_session_marker_case())
    }

    /// Linked to Google with its password kept: a session that signed in
    /// with the password gets no ticketless add; the session the Google
    /// callback marked does
    async fn a_linked_account_needs_the_oauth_session_marker_case() {
        let harness = harness_with_passkeys_on().await;

        let (mut linked, password_session, _) = harness.new_user().await;
        linked.google_id = Some(format!("google-{}", TestHarness::rand_string()));
        linked.save(&harness.db).await.unwrap();
        assert!(!linked.password_absent, "the control: the password is kept");

        // No marker: being linked is not enough
        assert_gate_refuses(&harness, &password_session, None).await;

        // Another session of the same account, marked as the callback does
        let google_session = session_minted_ago(&harness, &linked, Duration::from_secs(60)).await;
        mark_oauth_session(&google_session.id).await;
        assert_gate_passes(&harness, &google_session, None).await;

        // The marker belongs to that session only
        assert_gate_refuses(&harness, &password_session, None).await;

        // And it does not outlive the ten minutes: an old marked session
        let old = session_minted_ago(&harness, &linked, Duration::from_secs(11 * 60)).await;
        mark_oauth_session(&old.id).await;
        assert_gate_refuses(&harness, &old, None).await;
    }

    #[test]
    fn a_ticketless_add_that_is_not_alone_is_taken_back() {
        rt().block_on(a_ticketless_add_that_is_not_alone_is_taken_back_case())
    }

    /// The step after a ticketless store, on the state two racing ticketless
    /// finishes leave behind: two rows where only a first one was allowed
    async fn a_ticketless_add_that_is_not_alone_is_taken_back_case() {
        let harness = TestHarness::new().await;
        let (account, _, _) = harness.new_user().await;

        // Alone: it stays
        let first = seed_passkey(&harness, &account, "Phone").await;
        settle_ticketless_add(&harness.db, &account.id, &first.id)
            .await
            .expect("the only passkey stays");
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);

        // The other racer's row is there too: this one goes, and only it
        let second = seed_passkey(&harness, &account, "Laptop").await;
        let refused = settle_ticketless_add(&harness.db, &account.id, &second.id)
            .await
            .expect_err("a second ticketless passkey is refused");
        assert!(
            matches!(refused.error_type, ErrorType::NotPrivileged),
            "{:?}",
            refused
        );
        let left = harness.db.fetch_passkeys(&account.id).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, first.id);

        // A row that is already gone is not an error of its own
        take_back(&harness.db, &account.id, &second.id).await;
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);
    }

    #[test]
    fn a_bad_ticket_counts_as_no_ticket() {
        rt().block_on(a_bad_ticket_counts_as_no_ticket_case())
    }

    async fn a_bad_ticket_counts_as_no_ticket_case() {
        let harness = harness_with_passkeys_on().await;
        let (_, session, _) = harness.new_user().await;
        let (other, _, _) = harness.new_user().await;

        // A validated ticket, but of another account
        let foreign = ticket_for(&harness, &other).await;

        for ticket in ["not-a-ticket", foreign.as_str()] {
            assert_gate_refuses(&harness, &session, Some(ticket)).await;
        }

        // The other account's ticket was not burned by the attempts
        assert!(
            harness.db.fetch_ticket_by_token(&foreign).await.is_ok(),
            "a foreign ticket was claimed"
        );
    }

    #[test]
    fn first_passkey_without_a_ticket_then_tickets() {
        rt().block_on(first_passkey_without_a_ticket_then_tickets_case())
    }

    /// Real ceremonies with the software authenticator: the first passkey
    /// goes in with no ticket and changes nothing else on the account; the
    /// second needs one ticket, on the finish step.
    async fn first_passkey_without_a_ticket_then_tickets_case() {
        let harness = harness_with_passkeys_on().await;
        let (account, session) = passwordless_user(&harness).await;

        // First passkey, no ticket on either step
        let (status, started) = send(start(&harness), &session, None).await;
        assert_eq!(status, Status::Ok, "{}", started);
        assert_eq!(keys(&started), ["challenge_id", "options"]);

        let credential = SoftPasskey::new().create(&started["options"], ORIGIN);
        let challenge_id = started["challenge_id"].as_str().unwrap();
        let (status, info) = send(
            finish(&harness, challenge_id, credential, Some("Phone")),
            &session,
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "{}", info);
        assert_eq!(keys(&info), ["created_at", "id", "name"]);
        assert_eq!(info["name"], "Phone");

        let rows = harness.db.fetch_passkeys(&account.id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(info["id"], rows[0].id.as_str());

        // Nothing else moved
        let after = harness.db.fetch_account(&account.id).await.unwrap();
        assert!(after.password_absent, "adding a passkey cleared the flag");
        assert!(!after.mfa.is_active());

        // Second passkey. The start step asks for nothing more
        let (status, started) = send(start(&harness), &session, None).await;
        assert_eq!(status, Status::Ok, "{}", started);

        let mut second = SoftPasskey::new();
        let credential = second.create(&started["options"], ORIGIN);
        let challenge_id = started["challenge_id"].as_str().unwrap();

        // But the same young session no longer stores it without a ticket,
        // even with a ceremony the verifier would accept
        let (status, body) = send(
            finish(&harness, challenge_id, credential.clone(), Some("Laptop")),
            &session,
            None,
        )
        .await;
        assert_eq!(status, Status::Forbidden, "{}", body);
        assert_eq!(kind(&body), "NotPrivileged");
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);

        // The refusal came before the verifier, so the challenge is unspent:
        // with one ticket the same ceremony finishes
        let ticket = ticket_for(&harness, &account).await;
        let (status, info) = send(
            finish(&harness, challenge_id, credential, Some("Laptop")),
            &session,
            Some(&ticket),
        )
        .await;
        assert_eq!(status, Status::Ok, "{}", info);
        assert_eq!(info["name"], "Laptop");
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 2);
    }
}
