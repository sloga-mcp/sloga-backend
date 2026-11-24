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

    if fresh_session_suffices(db, account, session).await? {
        Ok(AddProof::FreshSession)
    } else {
        Err(create_error!(NotPrivileged))
    }
}

/// Whether the first-passkey rule holds for this account and session right
/// now. Gathers the facts from server state and asks the one rule.
///
/// Both steps call it: the finish step to decide, the start step only to
/// tell the app whether the finish step will want more. It takes the
/// account and the session and nothing from the request.
async fn fresh_session_suffices(
    db: &Database,
    account: &Account,
    session: &Session,
) -> Result<bool> {
    let facts = TicketlessFacts {
        passkeys: db.count_passkeys(&account.id).await?,
        mfa_active: account.mfa.is_active(),
        password_absent: account.password_absent,
        // False when Redis cannot be read
        oauth_session: passkey::is_oauth_session(&session.id).await,
        session_age_ms: now_ms().and_then(|now| session_age_ms(&session.id, now)),
    };

    Ok(may_register_without_ticket(&facts))
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
        "passkeys: could not take back a passkey that may not stay \
         (account {account_id}, passkey {passkey_id}); remove it by hand"
    );
}

/// After any add: the new passkey stays only while the session that added
/// it still exists.
///
/// A password reset removes the account's passkeys and, when asked, its
/// sessions. An add that was already past the session guard can store its
/// row after that purge; without this look the passkey of whoever held the
/// old session would outlive the reset. A session that is gone means the
/// row is taken back and the request answered as a failed ceremony. A
/// session that cannot be read is treated the same way, with the database
/// error as the answer.
async fn settle_add_after_session_check(
    db: &Database,
    session_id: &str,
    account_id: &str,
    passkey_id: &str,
) -> Result<()> {
    match db.fetch_session(session_id).await {
        Ok(session) if session.user_id == account_id => Ok(()),
        Ok(_) => {
            take_back(db, account_id, passkey_id).await;
            Err(create_error!(InvalidCredentials))
        }
        Err(error) => {
            take_back(db, account_id, passkey_id).await;
            Err(match error.error_type {
                ErrorType::UnknownUser | ErrorType::InvalidSession | ErrorType::NotFound => {
                    create_error!(InvalidCredentials)
                }
                _ => error,
            })
        }
    }
}

/// Err unless the session was made after the account's passkeys were last
/// purged, or no purge is on record.
///
/// A password reset stamps the time of its purge
/// (`passkey::mark_passkeys_purged`). A session whose id is older than the
/// stamp, or carries no time, belonged to whoever could sign in before the
/// reset: `InvalidCredentials`, the answer of a failed ceremony. A session
/// minted in the very millisecond of the stamp is counted as older. A stamp
/// that cannot be read is treated as a purge, with that error as the
/// answer.
///
/// Both steps ask it: the start step before it hands out a challenge, so
/// the device makes no passkey that could not stay, and the finish step
/// after the store, for a reset that came in between.
async fn refuse_session_older_than_purge(session_id: &str, account_id: &str) -> Result<()> {
    let Some(purged_ms) = passkey::purged_since(account_id).await? else {
        return Ok(());
    };

    // From the id, as `session_age_ms` reads it: a client cannot set it
    let minted_ms = ulid::Ulid::from_string(session_id)
        .ok()
        .map(|id| id.timestamp_ms());

    if matches!(minted_ms, Some(minted_ms) if minted_ms > purged_ms) {
        Ok(())
    } else {
        Err(create_error!(InvalidCredentials))
    }
}

/// After any add: the new passkey stays only if the session that added it
/// was made after the account's passkeys were last purged.
///
/// A password reset that keeps the sessions leaves the session re-check
/// nothing to find: the session is still there. This asks
/// `refuse_session_older_than_purge`, and on any refusal takes the new
/// passkey back before answering with it.
async fn settle_add_after_purge_check(
    db: &Database,
    session_id: &str,
    account_id: &str,
    passkey_id: &str,
) -> Result<()> {
    match refuse_session_older_than_purge(session_id, account_id).await {
        Ok(()) => Ok(()),
        Err(error) => {
            take_back(db, account_id, passkey_id).await;
            Err(error)
        }
    }
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
///
/// `ticket_required` says whether the finish step will ask for an MFA
/// ticket, by the rule it applies itself, read now. It is a hint for the
/// app and decides nothing: the finish step reads the rule again, and a
/// session that was young enough here may be too old there.
///
/// A session older than the account's last password reset gets no
/// challenge: the finish step would take its passkey back, so it is refused
/// here, before the device makes one, with the answer the finish step
/// gives.
#[openapi(tag = "Passkey")]
#[post("/register/start")]
pub async fn register_start(
    db: &State<Database>,
    account: Account,
    session: Session,
) -> Result<Json<v0::ResponsePasskeyRegisterStart>> {
    passkey::assert_available().await?;

    // The finish step asks again, after the store
    refuse_session_older_than_purge(&session.id, &account.id).await?;

    let started = passkey::start_registration(db, &account, &session.id).await?;
    let ticket_required = !fresh_session_suffices(db, &account, &session).await?;

    Ok(Json(v0::ResponsePasskeyRegisterStart {
        challenge_id: started.challenge_id,
        options: started.options,
        ticket_required,
    }))
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

    // An add that a password reset overtook does not stay
    settle_add_after_session_check(db, &session.id, &account.id, &stored.id).await?;

    // Nor does one from a session older than a reset that kept the sessions
    settle_add_after_purge_check(db, &session.id, &account.id, &stored.id).await?;

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
    use redis_kiss::{get_connection, redis};
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
        may_register_without_ticket, session_age_ms, settle_add_after_purge_check,
        settle_add_after_session_check, settle_ticketless_add, take_back, TicketlessFacts,
        TICKETLESS_SESSION_MAX_AGE_MS,
    };
    use crate::util::passkey::{mark_oauth_session, mark_passkeys_purged, purged_since};
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
        session_minted_at(harness, account, SystemTime::now() - age).await
    }

    /// A session of `account` whose id says it was minted at `at`
    async fn session_minted_at(harness: &TestHarness, account: &Account, at: SystemTime) -> Session {
        let session = Session {
            id: Ulid::from_datetime(at).to_string(),
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
    /// stored, the start step reads and claims no ticket (so one sent there
    /// is never spent), and the route code reads nothing a client can set
    /// and never asks which ticket methods exist.
    ///
    /// The start step may say `ticket_required`: that is an answer field,
    /// worked out from the account and the session by the helper the finish
    /// step uses. It is the only "ticket" the start step may name. With it
    /// set aside, the word must not appear there at all, so a ticket guard
    /// (`ticket: Option<ValidatedTicket>`), a ticket lookup or a call to the
    /// gate all still fail this test. The helper is held to the same: apart
    /// from the rule and its facts, it names no ticket.
    ///
    /// Fails if: the start step takes a ticket guard, looks one up, claims
    /// one or runs the gate; the start step hands out a challenge before
    /// it reads the purge stamp, or stops reading it; the helper behind
    /// `ticket_required` reads a ticket; the finish step verifies before
    /// the gate; or the session
    /// re-check or the purge check after the store is dropped or moved
    /// ahead of it.
    #[test]
    fn both_steps_pass_the_one_gate() {
        const GATE: &str = "authorize_add(db,&account,&session,&ticket).await?";
        const STORE: &str = "passkey::finish_registration(";
        const SESSION_CHECK: &str =
            "settle_add_after_session_check(db,&session.id,&account.id,&stored.id).await?;";
        const PURGE_CHECK: &str =
            "settle_add_after_purge_check(db,&session.id,&account.id,&stored.id).await?;";
        const START_PURGE_CHECK: &str =
            "refuse_session_older_than_purge(&session.id,&account.id).await?;";
        const HELPER: &str = "asyncfnfresh_session_suffices(";

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

        // Start: account and session only. `ticket_required` is the answer
        // field; no other "ticket" may stand in the route
        assert!(
            start_route.contains("ticket_required"),
            "the control: the start route answers `ticket_required`"
        );
        assert!(
            !start_route
                .to_lowercase()
                .replace("ticket_required", "")
                .contains("ticket"),
            "the start route names a ticket other than `ticket_required`"
        );
        assert!(
            !start_route.contains("authorize_add"),
            "the start route runs the gate"
        );
        assert!(start_route.contains("passkey::assert_available().await?;"));
        assert!(
            start_route.contains(
                "letticket_required=!fresh_session_suffices(db,&account,&session).await?;"
            ),
            "`ticket_required` must come from the helper the finish step uses"
        );

        // Start: the purge stamp is read before a challenge is handed out
        let start_purge_at = start_route
            .find(START_PURGE_CHECK)
            .expect("start reads the purge stamp");
        let challenge_at = start_route
            .find("passkey::start_registration(")
            .expect("start hands out a challenge");
        assert!(
            start_purge_at < challenge_at,
            "the purge check must come before the challenge"
        );

        // The helper: the rule and its facts, and no ticket
        let helper_at = code.find(HELPER).expect("the helper");
        let helper_end = helper_at
            + code[helper_at..]
                .find("asyncfntake_back(")
                .expect("the helper is expected above `take_back`");
        let helper = code[helper_at..helper_end]
            .to_lowercase()
            .replace("may_register_without_ticket", "")
            .replace("ticketlessfacts", "");
        assert!(!helper.contains("ticket"), "the helper names a ticket");
        assert!(!helper.contains("claim"), "the helper claims something");

        // Finish: the gate, then the verifier
        assert!(finish_route.contains("ticket:Option<ValidatedTicket>"));
        assert_eq!(code.matches(GATE).count(), 1, "the gate is called once");
        assert_eq!(code.matches(STORE).count(), 1);
        let gate_at = finish_route.find(GATE).expect("finish passes the gate");
        let store_at = finish_route.find(STORE).expect("finish stores the passkey");
        assert!(gate_at < store_at, "the gate must come before the verifier");

        // Then the session is read again, before the route answers
        assert_eq!(code.matches(SESSION_CHECK).count(), 1);
        let check_at = finish_route
            .find(SESSION_CHECK)
            .expect("finish re-reads the session");
        assert!(
            store_at < check_at,
            "the session re-check must come after the store"
        );

        // And the purge stamp is read, also after the store
        assert_eq!(code.matches(PURGE_CHECK).count(), 1);
        let purge_at = finish_route
            .find(PURGE_CHECK)
            .expect("finish reads the purge stamp");
        assert!(
            store_at < purge_at,
            "the purge check must come after the store"
        );

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

    /// What the start step answers for `ticket_required`
    async fn ticket_required(harness: &TestHarness, session: &Session, ticket: Option<&str>) -> bool {
        let (status, body) = send(start(harness), session, ticket).await;
        assert_eq!(status, Status::Ok, "{}", body);
        body["ticket_required"]
            .as_bool()
            .unwrap_or_else(|| panic!("`ticket_required` is not a boolean: {}", body))
    }

    #[test]
    fn start_says_whether_finish_wants_a_ticket() {
        rt().block_on(start_says_whether_finish_wants_a_ticket_case())
    }

    /// Each row asks the start step, then checks the finish gate agrees.
    ///
    /// Fails if: `ticket_required` is a constant, is worked out by another
    /// rule than the finish gate's, reads a ticket sent with the start step
    /// (a ticket there must not turn it false), or spends that ticket.
    async fn start_says_whether_finish_wants_a_ticket_case() {
        let harness = harness_with_passkeys_on().await;

        // No usable password, signed in just now: no ticket needed
        let (passwordless, young) = passwordless_user(&harness).await;
        assert!(!ticket_required(&harness, &young, None).await);
        assert_gate_passes(&harness, &young, None).await;

        // The same account from a session minted eleven minutes ago
        let old = session_minted_ago(&harness, &passwordless, Duration::from_secs(11 * 60)).await;
        assert!(ticket_required(&harness, &old, None).await);
        assert_gate_refuses(&harness, &old, None).await;

        // A password account: a ticket is needed, and sending one with the
        // start step neither changes the answer nor spends it
        let (plain, plain_session, _) = harness.new_user().await;
        assert!(ticket_required(&harness, &plain_session, None).await);
        let ticket = ticket_for(&harness, &plain).await;
        assert!(ticket_required(&harness, &plain_session, Some(&ticket)).await);
        assert!(
            harness.db.fetch_ticket_by_token(&ticket).await.is_ok(),
            "the start step claimed the ticket"
        );
        assert_gate_refuses(&harness, &plain_session, None).await;

        // Linked to Google with its password kept: only the session the
        // callback marked needs no ticket
        let (mut linked, password_session, _) = harness.new_user().await;
        linked.google_id = Some(format!("google-{}", TestHarness::rand_string()));
        linked.save(&harness.db).await.unwrap();
        assert!(ticket_required(&harness, &password_session, None).await);

        let google_session = session_minted_ago(&harness, &linked, Duration::from_secs(60)).await;
        mark_oauth_session(&google_session.id).await;
        assert!(!ticket_required(&harness, &google_session, None).await);
        assert_gate_passes(&harness, &google_session, None).await;

        // Once a passkey exists, every further one needs a ticket
        seed_passkey(&harness, &passwordless, "Phone").await;
        assert!(ticket_required(&harness, &young, None).await);
        assert_gate_refuses(&harness, &young, None).await;
    }

    #[test]
    fn an_add_whose_session_is_gone_is_taken_back() {
        rt().block_on(an_add_whose_session_is_gone_is_taken_back_case())
    }

    /// The step after the store, on the state a password reset that
    /// overtook the add leaves behind: the row is in, the session is not.
    /// Driven on the step itself, since nothing can remove a session in the
    /// middle of one request; `both_steps_pass_the_one_gate` pins that the
    /// finish route runs it after the store.
    ///
    /// Fails if: a passkey stays after the session that added it was
    /// removed, the refusal is not the failed-ceremony answer, a live
    /// session's passkey is taken back, or another passkey is removed.
    async fn an_add_whose_session_is_gone_is_taken_back_case() {
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;
        let (other, other_session, _) = harness.new_user().await;

        // The session is there: the row stays
        let kept = seed_passkey(&harness, &account, "Phone").await;
        settle_add_after_session_check(&harness.db, &session.id, &account.id, &kept.id)
            .await
            .expect("the session is live, so the passkey stays");
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);

        // What "sign out everywhere" on a reset does, then the late store
        account.delete_all_sessions(&harness.db, None).await.unwrap();
        assert!(
            harness.db.fetch_session(&session.id).await.is_err(),
            "the control: the session is gone"
        );
        let late = seed_passkey(&harness, &account, "Planted").await;

        let refused =
            settle_add_after_session_check(&harness.db, &session.id, &account.id, &late.id)
                .await
                .expect_err("an add whose session is gone is refused");
        assert!(
            matches!(refused.error_type, ErrorType::InvalidCredentials),
            "{:?}",
            refused
        );

        // Only the late row went
        let left = harness.db.fetch_passkeys(&account.id).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, kept.id);

        // A session of another account does not vouch for the add
        let planted = seed_passkey(&harness, &account, "Planted").await;
        let refused = settle_add_after_session_check(
            &harness.db,
            &other_session.id,
            &account.id,
            &planted.id,
        )
        .await
        .expect_err("another account's session vouches for nothing");
        assert!(
            matches!(refused.error_type, ErrorType::InvalidCredentials),
            "{:?}",
            refused
        );
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);
        assert_eq!(harness.db.count_passkeys(&other.id).await.unwrap(), 0);
    }

    /// When the id of `session` says it was minted, in Unix milliseconds
    fn minted_ms(session: &Session) -> u64 {
        Ulid::from_string(&session.id)
            .expect("a ULID")
            .timestamp_ms()
    }

    #[test]
    fn an_add_from_a_session_older_than_a_purge_is_taken_back() {
        rt().block_on(an_add_from_a_session_older_than_a_purge_is_taken_back_case())
    }

    /// The step after the store, on the state a password reset that kept
    /// the sessions leaves behind: the stamp is written, the passkeys are
    /// gone, and the session that was open before the reset is still
    /// there. Driven on the step itself, as the session re-check is;
    /// `both_steps_pass_the_one_gate` pins that the finish route runs it
    /// after the store.
    ///
    /// Fails if: a passkey added from a session older than the purge stamp
    /// stays, the refusal is not the failed-ceremony answer, an add with no
    /// stamp on record or from a session made after the stamp is taken
    /// back, a session id that carries no time vouches for an add, or
    /// another passkey of the account is removed.
    async fn an_add_from_a_session_older_than_a_purge_is_taken_back_case() {
        let harness = TestHarness::new().await;
        let (account, _, _) = harness.new_user().await;
        let old = session_minted_ago(&harness, &account, Duration::from_secs(60)).await;

        // No purge on record: the row stays
        assert_eq!(
            purged_since(&account.id).await.expect("redis"),
            None,
            "the control: no stamp yet"
        );
        let first = seed_passkey(&harness, &account, "Phone").await;
        settle_add_after_purge_check(&harness.db, &old.id, &account.id, &first.id)
            .await
            .expect("no purge is on record, so the passkey stays");
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);

        // What a reset that keeps the sessions does: the stamp, then the
        // purge
        mark_passkeys_purged(&account.id).await.expect("the stamp");
        harness
            .db
            .delete_passkeys_for_user(&account.id)
            .await
            .unwrap();
        let stamp = purged_since(&account.id)
            .await
            .expect("redis")
            .expect("the control: the stamp is on record");
        assert!(minted_ms(&old) < stamp, "the control: an older session");
        assert!(
            harness.db.fetch_session(&old.id).await.is_ok(),
            "the control: the session outlived the reset"
        );

        // A session made after the reset, by whoever knows the new password
        let new = session_minted_at(
            &harness,
            &account,
            SystemTime::now() + Duration::from_secs(5),
        )
        .await;
        assert!(minted_ms(&new) > stamp, "the control: a newer session");
        let kept = seed_passkey(&harness, &account, "After the reset").await;
        settle_add_after_purge_check(&harness.db, &new.id, &account.id, &kept.id)
            .await
            .expect("a session made after the purge keeps its passkey");

        // The late store of the session that was open before the reset
        let late = seed_passkey(&harness, &account, "Planted").await;
        let refused = settle_add_after_purge_check(&harness.db, &old.id, &account.id, &late.id)
            .await
            .expect_err("an add from a session older than the purge is refused");
        assert!(
            matches!(refused.error_type, ErrorType::InvalidCredentials),
            "{:?}",
            refused
        );

        // Only the late row went
        let left = harness.db.fetch_passkeys(&account.id).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, kept.id);

        // An id with no time in it vouches for nothing
        let planted = seed_passkey(&harness, &account, "Planted").await;
        let refused =
            settle_add_after_purge_check(&harness.db, "not a ulid", &account.id, &planted.id)
                .await
                .expect_err("a session id with no time is refused");
        assert!(
            matches!(refused.error_type, ErrorType::InvalidCredentials),
            "{:?}",
            refused
        );
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 1);
    }

    #[test]
    fn an_add_is_taken_back_when_the_purge_stamp_cannot_be_read() {
        rt().block_on(an_add_is_taken_back_when_the_purge_stamp_cannot_be_read_case())
    }

    /// A stamp that is there and is not a time, which `purged_since`
    /// answers with an error, as it does when Redis is down.
    ///
    /// Fails if: an unreadable purge stamp is taken for "no purge" and the
    /// passkey stays, the request is answered as a success, or another
    /// passkey of the account is removed.
    async fn an_add_is_taken_back_when_the_purge_stamp_cannot_be_read_case() {
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;
        let kept = seed_passkey(&harness, &account, "Phone").await;

        // The key of `passkey::mark_passkeys_purged`
        let mut conn = get_connection().await.expect("redis").into_inner();
        let set: Option<String> = redis::cmd("SET")
            .arg(format!("passkey:purged:{}", account.id))
            .arg("not a time")
            .arg("EX")
            .arg(60)
            .query_async(&mut conn)
            .await
            .expect("SET");
        assert!(set.is_some(), "the control: the stamp is stored");
        assert!(
            purged_since(&account.id).await.is_err(),
            "the control: the stamp cannot be read"
        );

        let late = seed_passkey(&harness, &account, "Planted").await;
        let refused =
            settle_add_after_purge_check(&harness.db, &session.id, &account.id, &late.id)
                .await
                .expect_err("an add whose purge stamp cannot be read is refused");
        assert!(
            matches!(refused.error_type, ErrorType::InternalError),
            "{:?}",
            refused
        );

        let left = harness.db.fetch_passkeys(&account.id).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, kept.id);
    }

    /// Store something that is not a time as the purge stamp of `account`
    /// (the key of `passkey::mark_passkeys_purged`)
    async fn unreadable_purge_stamp(account: &Account) {
        let mut conn = get_connection().await.expect("redis").into_inner();
        let set: Option<String> = redis::cmd("SET")
            .arg(format!("passkey:purged:{}", account.id))
            .arg("not a time")
            .arg("EX")
            .arg(60)
            .query_async(&mut conn)
            .await
            .expect("SET");
        assert!(set.is_some(), "the control: the stamp is stored");
        assert!(
            purged_since(&account.id).await.is_err(),
            "the control: the stamp cannot be read"
        );
    }

    #[test]
    fn start_refuses_a_session_older_than_a_purge() {
        rt().block_on(start_refuses_a_session_older_than_a_purge_case())
    }

    /// Over HTTP, on the state a password reset that kept the sessions
    /// leaves behind: the stamp is written and the session that was open
    /// before it is still there.
    ///
    /// Fails if: `register/start` hands a challenge to a session older than
    /// the purge stamp (the device would make a passkey the finish step
    /// takes back), refuses it with anything but the failed-ceremony
    /// answer, takes an unreadable stamp for "no purge", or refuses a
    /// session with no stamp on record, a session made after the stamp, or
    /// another account's session.
    async fn start_refuses_a_session_older_than_a_purge_case() {
        let harness = harness_with_passkeys_on().await;
        let (account, _) = passwordless_user(&harness).await;
        let old = session_minted_ago(&harness, &account, Duration::from_secs(60)).await;
        let (_, bystander) = passwordless_user(&harness).await;

        // The control: no purge on record, the same session gets a challenge
        assert_start_answers(&harness, &old, None).await;

        mark_passkeys_purged(&account.id).await.expect("the stamp");
        let stamp = purged_since(&account.id)
            .await
            .expect("redis")
            .expect("the control: the stamp is on record");
        assert!(minted_ms(&old) < stamp, "the control: an older session");

        let (status, body) = send(start(&harness), &old, None).await;
        assert_eq!(status, Status::Unauthorized, "{}", body);
        assert_eq!(kind(&body), "InvalidCredentials", "{}", body);
        assert!(body.get("challenge_id").is_none(), "{}", body);
        assert!(body.get("options").is_none(), "{}", body);

        // A ticket does not change that
        let ticket = ticket_for(&harness, &account).await;
        let (status, body) = send(start(&harness), &old, Some(&ticket)).await;
        assert_eq!(status, Status::Unauthorized, "{}", body);
        assert!(body.get("challenge_id").is_none(), "{}", body);

        // A session made after the reset, and another account, go ahead
        let new = session_minted_at(
            &harness,
            &account,
            SystemTime::now() + Duration::from_secs(5),
        )
        .await;
        assert!(minted_ms(&new) > stamp, "the control: a newer session");
        assert_start_answers(&harness, &new, None).await;
        assert_start_answers(&harness, &bystander, None).await;

        // A stamp that cannot be read refuses, whatever the session
        let (unread, unread_session) = passwordless_user(&harness).await;
        unreadable_purge_stamp(&unread).await;
        let (status, body) = send(start(&harness), &unread_session, None).await;
        assert_eq!(status, Status::InternalServerError, "{}", body);
        assert_eq!(kind(&body), "InternalError", "{}", body);
        assert!(body.get("challenge_id").is_none(), "{}", body);
    }

    #[test]
    fn finish_refuses_when_a_purge_lands_after_start() {
        rt().block_on(finish_refuses_when_a_purge_lands_after_start_case())
    }

    /// Over HTTP, with real ceremonies: the reset comes in after the start
    /// step answered and before the device's passkey comes back.
    ///
    /// Fails if: `register/finish` keeps a passkey whose session is older
    /// than a purge stamp written after `register/start` (the start check
    /// alone does not see that reset), answers anything but the
    /// failed-ceremony answer, or refuses the same ceremony from a session
    /// made after the stamp.
    async fn finish_refuses_when_a_purge_lands_after_start_case() {
        let harness = harness_with_passkeys_on().await;
        let (account, _) = passwordless_user(&harness).await;
        let old = session_minted_ago(&harness, &account, Duration::from_secs(60)).await;

        // Start goes through: nothing is on record yet
        let (status, started) = send(start(&harness), &old, None).await;
        assert_eq!(status, Status::Ok, "{}", started);
        assert_eq!(started["ticket_required"], false, "{}", started);
        let credential = SoftPasskey::new().create(&started["options"], ORIGIN);
        let challenge_id = started["challenge_id"].as_str().unwrap();

        // The reset: the stamp, then the purge
        mark_passkeys_purged(&account.id).await.expect("the stamp");
        harness
            .db
            .delete_passkeys_for_user(&account.id)
            .await
            .unwrap();
        let stamp = purged_since(&account.id)
            .await
            .expect("redis")
            .expect("the control: the stamp is on record");
        assert!(minted_ms(&old) < stamp, "the control: an older session");

        let (status, body) = send(
            finish(&harness, challenge_id, credential, Some("Planted")),
            &old,
            None,
        )
        .await;
        assert_eq!(status, Status::Unauthorized, "{}", body);
        assert_eq!(kind(&body), "InvalidCredentials", "{}", body);
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 0);

        // The control: a session made after the reset does the same
        // ceremony and keeps its passkey. Its id lies a few seconds ahead
        // so that it is surely newer than the stamp; an id from the future
        // has no age, so this add brings a ticket.
        let new = session_minted_at(
            &harness,
            &account,
            SystemTime::now() + Duration::from_secs(5),
        )
        .await;
        assert!(minted_ms(&new) > stamp, "the control: a newer session");
        let (status, started) = send(start(&harness), &new, None).await;
        assert_eq!(status, Status::Ok, "{}", started);
        let credential = SoftPasskey::new().create(&started["options"], ORIGIN);
        let challenge_id = started["challenge_id"].as_str().unwrap();
        let ticket = ticket_for(&harness, &account).await;
        let (status, info) = send(
            finish(&harness, challenge_id, credential, Some("Phone")),
            &new,
            Some(&ticket),
        )
        .await;
        assert_eq!(status, Status::Ok, "{}", info);
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
        assert_eq!(keys(&started), ["challenge_id", "options", "ticket_required"]);
        assert_eq!(started["ticket_required"], false, "{}", started);

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

        // Second passkey. The start step asks for nothing more, and says
        // the finish step will
        let (status, started) = send(start(&harness), &session, None).await;
        assert_eq!(status, Status::Ok, "{}", started);
        assert_eq!(started["ticket_required"], true, "{}", started);

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
