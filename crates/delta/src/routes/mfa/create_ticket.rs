//! Create a validated MFA ticket for the current session.
//! PUT /mfa/ticket
use revolt_result::{create_error, Result};
use revolt_database::{Account, Database, MFAMethod, MFATicket, MfaPurpose, Session};
use revolt_models::v0;
use rocket::serde::json::Json;
use rocket::State;

use crate::util::passkey;

/// # Create MFA ticket
///
/// Verify an MFA response for the account of the current session and
/// create a new validated ticket.
#[openapi(tag = "MFA")]
#[put("/ticket", data = "<data>")]
pub async fn create_ticket(
    db: &State<Database>,
    mut account: Account,
    session: Session,
    data: Json<v0::MFAResponse>,
) -> Result<Json<v0::MFATicket>> {
    match data.into_inner() {
        // Checked here and not in `consume_mfa_response`, which refuses a
        // passkey for every purpose: that refusal is what keeps one out of
        // the login second step
        v0::MFAResponse::Passkey { passkey_response } => {
            verify_passkey_response(db, &account, &session, passkey_response).await?;
        }
        // Validate the MFA response; this counts an account lockout attempt
        response => {
            account
                .consume_mfa_response(db, response, MfaPurpose::MintTicket)
                .await?;
        }
    }

    // Create a new ticket for this account
    let ticket = MFATicket::new(account.id, true);
    ticket.save(db).await?;
    Ok(Json(ticket.into()))
}

/// Check a passkey assertion offered to mint a ticket from `session`
///
/// The account lockout is neither read nor written. It slows down guessing
/// a password or a code; a signature cannot be guessed, and counting a
/// failed one would let whoever holds a session lock the owner's password
/// out. So a locked-out account can still confirm with a passkey, a failed
/// assertion costs no attempt, and a good one does not clear the count
/// that wrong passwords built up.
async fn verify_passkey_response(
    db: &Database,
    account: &Account,
    session: &Session,
    response: v0::PasskeyTicketResponse,
) -> Result<()> {
    passkey::assert_available().await?;

    // The allowed list first: an account that cannot use a passkey here is
    // refused before the verifier runs, so the challenge is not spent either
    if !account
        .ticket_methods(db)
        .await?
        .contains(&MFAMethod::Passkey)
    {
        return Err(create_error!(DisallowedMFAMethod));
    }

    // The challenge must have been issued to this account and this session
    passkey::finish_assertion(
        db,
        account,
        &session.id,
        &response.challenge_id,
        response.credential,
    )
    .await
}

#[cfg(test)]
mod tests {
    use crate::util::{passkey, passkey_soft::SoftPasskey};
    use crate::{rocket, util::test::TestHarness};
    use iso8601_timestamp::Timestamp;
    use revolt_database::{Account, Lockout, MFATicket, Passkey, Session, Totp};
    use rocket::http::{ContentType, Header, Status};
    use revolt_models::v0;
    use revolt_result::{Error, ErrorType};

    #[test]
    fn success() {
        crate::util::test::rt().block_on(success_case())
    }

    async fn success_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let res = harness.client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "password": "password_insecure"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(res.into_json::<v0::MFATicket>().await.unwrap().validated);
    }

    #[test]
    fn success_totp() {
        crate::util::test::rt().block_on(success_totp_case())
    }

    async fn success_totp_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "totp_code": Totp::Enabled {
                        secret: "secret".to_string(),
                    }.generate_code().unwrap()
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Ok);
        assert!(res.into_json::<v0::MFATicket>().await.is_some());
    }

    #[test]
    fn failure_totp() {
        crate::util::test::rt().block_on(failure_totp_case())
    }

    async fn failure_totp_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "totp_code": "000000"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::InvalidToken,
        ));
    }

    #[test]
    fn failure_no_totp() {
        crate::util::test::rt().block_on(failure_no_totp_case())
    }

    async fn failure_no_totp_case() {
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;

        account.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        account.save(&harness.db).await.unwrap();

        let res = harness.client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(
                json!({
                    "password": "this is the wrong mfa method"
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::BadRequest);
        assert!(matches!(
            res.into_json::<Error>().await.unwrap().error_type,
            ErrorType::DisallowedMFAMethod,
        ));
    }

    #[test]
    fn failure_unvalidated_ticket_without_session() {
        crate::util::test::rt().block_on(failure_unvalidated_ticket_without_session_case())
    }

    /// A login ticket alone no longer stands in for a session: the request
    /// is refused before the response is checked, and the ticket is intact.
    async fn failure_unvalidated_ticket_without_session_case() {
        let harness = TestHarness::new().await;
        let (mut account, _, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };

        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();

        let ticket = MFATicket::new(account.id.to_string(), false);
        ticket.save(&harness.db).await.unwrap();

        let res = harness.client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-MFA-Ticket", ticket.token.clone()))
            .body(
                json!({
                    "totp_code": totp.generate_code().unwrap()
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(res.status(), Status::Unauthorized);
        assert!(harness
            .db
            .fetch_ticket_by_token(&ticket.token)
            .await
            .is_ok());
    }

    // Passkey as a ticket factor. Every test that turns the feature on does
    // so with `overwrite_config`, which works once per process and before
    // the harness reads the config: these need nextest (one process per
    // test).

    /// The origin in the default `[features.passkeys]` config
    const ORIGIN: &str = "https://app.sloga.gg";

    async fn passkeys_on() {
        revolt_config::overwrite_config(|settings| {
            settings.features.passkeys.available = true;
        })
        .await;
    }

    /// Store a passkey row for `user_id`. Its credential is not a real one:
    /// enough to be listed, never enough to pass the verifier
    async fn add_unusable_passkey(harness: &TestHarness, user_id: &str) {
        harness
            .db
            .insert_passkey(&Passkey::new(
                user_id.to_string(),
                format!("credential-{}", TestHarness::rand_string()),
                format!("handle-{user_id}"),
                "{}".to_string(),
                "Phone".to_string(),
            ))
            .await
            .unwrap();
    }

    /// Register a real passkey for `account` straight through the verifier
    async fn register_passkey(
        harness: &TestHarness,
        account: &Account,
        session: &Session,
    ) -> SoftPasskey {
        let mut soft = SoftPasskey::new();
        let start = passkey::start_registration(&harness.db, account, &session.id)
            .await
            .expect("registration options");
        let credential = soft.create(&start.options, ORIGIN);
        passkey::finish_registration(
            &harness.db,
            account,
            &session.id,
            &start.challenge_id,
            credential,
            Some("Phone".to_string()),
        )
        .await
        .expect("a registered passkey");
        soft
    }

    fn passkey_body(challenge_id: &str, credential: serde_json::Value) -> serde_json::Value {
        json!({
            "passkey_response": {
                "challenge_id": challenge_id,
                "credential": credential
            }
        })
    }

    /// A well-formed passkey response for a challenge nobody issued
    fn unknown_challenge_body() -> serde_json::Value {
        passkey_body(
            "01UNKNOWNCHALLENGE",
            json!({ "id": "abc", "type": "public-key" }),
        )
    }

    /// Start an assertion over HTTP from `session` and sign it with `soft`
    async fn signed_body(
        harness: &TestHarness,
        session: &Session,
        soft: &SoftPasskey,
    ) -> serde_json::Value {
        let res = harness.client
            .post("/auth/passkey/assert/start")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Ok, "assert/start");

        let start = res
            .into_json::<v0::ResponsePasskeyOptions>()
            .await
            .expect("`ResponsePasskeyOptions`");
        passkey_body(&start.challenge_id, soft.get(&start.options, ORIGIN))
    }

    async fn put_ticket(
        harness: &TestHarness,
        session: &Session,
        body: &serde_json::Value,
    ) -> (Status, String) {
        let res = harness.client
            .put("/auth/mfa/ticket")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .body(body.to_string())
            .dispatch()
            .await;

        (res.status(), res.into_string().await.unwrap_or_default())
    }

    fn error_type(body: &str) -> ErrorType {
        serde_json::from_str::<Error>(body)
            .unwrap_or_else(|_| panic!("expected an error, got {body}"))
            .error_type
    }

    /// The wire form of an error type, so two errors can be compared
    fn kind(error_type: &ErrorType) -> serde_json::Value {
        serde_json::to_value(error_type).expect("an error type")
    }

    async fn stored_lockout(harness: &TestHarness, account_id: &str) -> Option<Lockout> {
        harness.db.fetch_account(account_id).await.unwrap().lockout
    }

    /// A lockout that is in force, with whole milliseconds so both drivers
    /// give it back unchanged
    fn locked() -> Lockout {
        Lockout {
            attempts: 5,
            expiry: Some(Timestamp::parse("2099-01-01T00:00:00.000Z").expect("valid timestamp")),
        }
    }

    #[test]
    fn passkey_refused_with_the_feature_off() {
        crate::util::test::rt().block_on(passkey_refused_with_the_feature_off_case())
    }

    /// Passkeys ship off. A stored passkey changes nothing: the answer is
    /// the switch's own refusal, and the verifier is never reached
    async fn passkey_refused_with_the_feature_off_case() {
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;
        add_unusable_passkey(&harness, &account.id).await;

        let off = passkey::assert_available()
            .await
            .expect_err("the control: passkeys are off in the test config");

        let (status, body) = put_ticket(&harness, &session, &unknown_challenge_body()).await;
        assert_ne!(status, Status::Ok);
        assert_eq!(kind(&error_type(&body)), kind(&off.error_type), "{body}");
        assert_eq!(stored_lockout(&harness, &account.id).await, None);

        // The control: the same session still mints a ticket with a password
        let (status, body) =
            put_ticket(&harness, &session, &json!({ "password": "password_insecure" })).await;
        assert_eq!(status, Status::Ok, "{body}");
    }

    #[test]
    fn passkey_refused_before_the_verifier_without_a_passkey() {
        crate::util::test::rt().block_on(passkey_refused_before_the_verifier_case())
    }

    /// An account whose ticket methods do not include a passkey is refused
    /// with `DisallowedMFAMethod`. The verifier would answer an unknown
    /// challenge differently, as the second half shows on the same body
    async fn passkey_refused_before_the_verifier_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;
        passkey::assert_available()
            .await
            .expect("the control: passkeys are on");

        let (status, body) = put_ticket(&harness, &session, &unknown_challenge_body()).await;
        assert_eq!(status, Status::BadRequest, "{body}");
        assert!(
            matches!(error_type(&body), ErrorType::DisallowedMFAMethod),
            "{body}"
        );
        assert_eq!(stored_lockout(&harness, &account.id).await, None);

        // The control: with a passkey listed, the same body reaches the
        // verifier, which refuses it in its own words
        add_unusable_passkey(&harness, &account.id).await;
        let (status, body) = put_ticket(&harness, &session, &unknown_challenge_body()).await;
        assert_ne!(status, Status::Ok, "{body}");
        assert!(
            !matches!(error_type(&body), ErrorType::DisallowedMFAMethod),
            "the verifier's refusal must differ from the allowed-list one: {body}"
        );
    }

    #[test]
    fn a_failed_passkey_writes_no_lockout() {
        crate::util::test::rt().block_on(a_failed_passkey_writes_no_lockout_case())
    }

    /// A failed assertion costs no attempt, however often it is tried
    async fn a_failed_passkey_writes_no_lockout_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;
        add_unusable_passkey(&harness, &account.id).await;

        // One wrong guess away from a lock
        let before = Lockout {
            attempts: 2,
            expiry: None,
        };
        harness
            .db
            .set_lockout(&account.id, Some(before.clone()))
            .await
            .unwrap();

        for _ in 0..4 {
            let (status, body) = put_ticket(&harness, &session, &unknown_challenge_body()).await;
            assert_ne!(status, Status::Ok, "{body}");
            assert!(
                !matches!(error_type(&body), ErrorType::LockedOut),
                "{body}"
            );
        }
        assert_eq!(
            stored_lockout(&harness, &account.id).await,
            Some(before),
            "a failed passkey assertion must not touch the lockout"
        );

        // The control: a wrong password on the same account is counted
        let (_, body) = put_ticket(&harness, &session, &json!({ "password": "guess" })).await;
        assert!(
            matches!(error_type(&body), ErrorType::InvalidCredentials),
            "{body}"
        );
        assert_eq!(
            stored_lockout(&harness, &account.id)
                .await
                .map(|lockout| lockout.attempts),
            Some(3)
        );
    }

    #[test]
    fn a_passkey_response_does_not_consult_the_lockout() {
        crate::util::test::rt().block_on(a_passkey_response_does_not_consult_the_lockout_case())
    }

    /// While the account is locked out a password is refused unread, and a
    /// passkey response still reaches the verifier
    async fn a_passkey_response_does_not_consult_the_lockout_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;
        add_unusable_passkey(&harness, &account.id).await;
        harness
            .db
            .set_lockout(&account.id, Some(locked()))
            .await
            .unwrap();

        // The control: the lockout is in force for the correct password
        let (status, body) =
            put_ticket(&harness, &session, &json!({ "password": "password_insecure" })).await;
        assert_eq!(status, Status::Forbidden, "{body}");
        assert!(matches!(error_type(&body), ErrorType::LockedOut), "{body}");

        let (status, body) = put_ticket(&harness, &session, &unknown_challenge_body()).await;
        assert_ne!(status, Status::Ok, "{body}");
        assert!(
            !matches!(error_type(&body), ErrorType::LockedOut),
            "a passkey response must get the verifier's answer: {body}"
        );
        assert_eq!(stored_lockout(&harness, &account.id).await, Some(locked()));
    }

    /// Send `mfa_response` to the login second step with a fresh login ticket
    async fn login_step(
        harness: &TestHarness,
        account_id: &str,
        mfa_response: &serde_json::Value,
    ) -> (Status, String, MFATicket) {
        let ticket = MFATicket::new(account_id.to_string(), false);
        ticket.save(&harness.db).await.unwrap();

        let res = harness.client
            .post("/auth/session/login")
            .header(ContentType::JSON)
            .body(
                json!({
                    "mfa_ticket": ticket.token.clone(),
                    "mfa_response": mfa_response
                })
                .to_string(),
            )
            .dispatch()
            .await;

        (
            res.status(),
            res.into_string().await.unwrap_or_default(),
            ticket,
        )
    }

    async fn session_count(harness: &TestHarness, account_id: &str) -> usize {
        harness.db.fetch_sessions(account_id).await.unwrap().len()
    }

    #[test]
    fn passkey_refused_on_the_login_step() {
        crate::util::test::rt().block_on(passkey_refused_on_the_login_step_case())
    }

    /// R8: the login second step never accepts a passkey, even with the
    /// feature on and a passkey stored
    async fn passkey_refused_on_the_login_step_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (mut account, _, _) = harness.new_user().await;

        let totp = Totp::Enabled {
            secret: "secret".to_string(),
        };
        account.mfa.totp_token = totp.clone();
        account.save(&harness.db).await.unwrap();
        add_unusable_passkey(&harness, &account.id).await;

        let sessions = session_count(&harness, &account.id).await;

        let (status, body, _) = login_step(&harness, &account.id, &unknown_challenge_body()).await;
        assert_eq!(status, Status::BadRequest, "{body}");
        assert!(
            matches!(error_type(&body), ErrorType::DisallowedMFAMethod),
            "{body}"
        );
        assert_eq!(
            session_count(&harness, &account.id).await,
            sessions,
            "a refused login must leave no session"
        );
        assert_eq!(stored_lockout(&harness, &account.id).await, None);

        // The control: the same request with the authenticator code signs in.
        // A code made in the last instant of its 30 second step is stale by
        // the time the route checks it, so a refused code gets one more try
        let mut control = (Status::Unauthorized, String::new());
        for _ in 0..2 {
            let (status, body, _) = login_step(
                &harness,
                &account.id,
                &json!({ "totp_code": totp.generate_code().expect("totp code") }),
            )
            .await;
            control = (status, body);
            if control.0 == Status::Ok {
                break;
            }
        }
        let (status, body) = control;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(session_count(&harness, &account.id).await, sessions + 1);
    }

    #[test]
    fn a_passkey_mints_a_ticket_another_route_accepts() {
        crate::util::test::rt().block_on(a_passkey_mints_a_ticket_case())
    }

    /// The whole ceremony: a signed assertion mints a validated ticket, a
    /// ticket-guarded route takes it, and the same assertion works once
    async fn a_passkey_mints_a_ticket_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;
        let soft = register_passkey(&harness, &account, &session).await;

        let signed = signed_body(&harness, &session, &soft).await;
        let (status, body) = put_ticket(&harness, &session, &signed).await;
        assert_eq!(status, Status::Ok, "{body}");

        let ticket = serde_json::from_str::<v0::MFATicket>(&body).expect("`MFATicket`");
        assert!(ticket.validated);
        assert!(!ticket.authorised, "a minted ticket never signs anyone in");
        assert_eq!(ticket.account_id, account.id);
        assert_eq!(stored_lockout(&harness, &account.id).await, None);

        let res = harness.client
            .post("/auth/mfa/recovery")
            .header(Header::new("X-Session-Token", session.token.clone()))
            .header(Header::new("X-MFA-Ticket", ticket.token.clone()))
            .header(ContentType::JSON)
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::Ok);

        // Single use: the challenge is gone
        let (status, body) = put_ticket(&harness, &session, &signed).await;
        assert_ne!(status, Status::Ok, "{body}");
    }

    #[test]
    fn a_challenge_from_another_session_is_refused() {
        crate::util::test::rt().block_on(a_challenge_from_another_session_case())
    }

    /// The challenge belongs to the session that started it, even for
    /// another session of the same account
    async fn a_challenge_from_another_session_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;
        let other_session = account
            .create_session(&harness.db, String::new())
            .await
            .expect("a second `Session`");
        let soft = register_passkey(&harness, &account, &session).await;

        let signed = signed_body(&harness, &session, &soft).await;
        let (status, body) = put_ticket(&harness, &other_session, &signed).await;
        assert_ne!(status, Status::Ok, "{body}");
        assert_eq!(stored_lockout(&harness, &account.id).await, None);

        // The control: started and finished from one session, it mints
        let signed = signed_body(&harness, &other_session, &soft).await;
        let (status, body) = put_ticket(&harness, &other_session, &signed).await;
        assert_eq!(status, Status::Ok, "{body}");
    }

    #[test]
    fn a_challenge_from_another_account_is_refused() {
        crate::util::test::rt().block_on(a_challenge_from_another_account_case())
    }

    /// An assertion made by one account's passkey, for a challenge that
    /// account started, mints nothing from another account's session
    async fn a_challenge_from_another_account_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (victim, victim_session, _) = harness.new_user().await;
        let (attacker, attacker_session, _) = harness.new_user().await;
        add_unusable_passkey(&harness, &victim.id).await;
        let soft = register_passkey(&harness, &attacker, &attacker_session).await;

        let signed = signed_body(&harness, &attacker_session, &soft).await;
        let (status, body) = put_ticket(&harness, &victim_session, &signed).await;
        assert_ne!(status, Status::Ok, "{body}");
        assert_eq!(stored_lockout(&harness, &victim.id).await, None);

        // The control: the attacker's own session mints with their own
        // passkey, so the assertion itself was good
        let signed = signed_body(&harness, &attacker_session, &soft).await;
        let (status, body) = put_ticket(&harness, &attacker_session, &signed).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(
            serde_json::from_str::<v0::MFATicket>(&body)
                .expect("`MFATicket`")
                .account_id,
            attacker.id
        );
    }

    #[test]
    fn a_passkey_mints_a_ticket_while_locked_out() {
        crate::util::test::rt().block_on(a_passkey_mints_a_ticket_while_locked_out_case())
    }

    /// The lockout decision, both halves: a good assertion mints a ticket
    /// while the password is locked out, and leaves the lockout as it was
    async fn a_passkey_mints_a_ticket_while_locked_out_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;
        let soft = register_passkey(&harness, &account, &session).await;
        harness
            .db
            .set_lockout(&account.id, Some(locked()))
            .await
            .unwrap();

        // The control: the lockout is in force for the correct password
        let (status, body) =
            put_ticket(&harness, &session, &json!({ "password": "password_insecure" })).await;
        assert_eq!(status, Status::Forbidden, "{body}");

        let signed = signed_body(&harness, &session, &soft).await;
        let (status, body) = put_ticket(&harness, &session, &signed).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(
            stored_lockout(&harness, &account.id).await,
            Some(locked()),
            "a passkey neither clears nor extends the password lockout"
        );
    }

    #[test]
    fn an_allowed_list_refusal_does_not_spend_the_challenge() {
        crate::util::test::rt().block_on(an_allowed_list_refusal_case())
    }

    /// The order, proven on a real challenge: while the account lists no
    /// passkey the request is refused without the verifier running, so the
    /// single-use challenge is still there once the passkey is back
    async fn an_allowed_list_refusal_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (account, session, _) = harness.new_user().await;
        let soft = register_passkey(&harness, &account, &session).await;
        let signed = signed_body(&harness, &session, &soft).await;

        let rows = harness.db.fetch_passkeys(&account.id).await.unwrap();
        assert_eq!(rows.len(), 1, "the control: one passkey is stored");
        harness
            .db
            .delete_passkeys_for_user(&account.id)
            .await
            .unwrap();

        let (status, body) = put_ticket(&harness, &session, &signed).await;
        assert_eq!(status, Status::BadRequest, "{body}");
        assert!(
            matches!(error_type(&body), ErrorType::DisallowedMFAMethod),
            "{body}"
        );

        // The same row again: had the verifier run above, the challenge
        // would be spent and this would fail
        harness.db.insert_passkey(&rows[0]).await.unwrap();
        let (status, body) = put_ticket(&harness, &session, &signed).await;
        assert_eq!(status, Status::Ok, "{body}");
    }

    #[test]
    fn a_good_assertion_is_refused_on_the_login_step() {
        crate::util::test::rt().block_on(a_good_assertion_on_the_login_step_case())
    }

    /// R8 with a real assertion: the login second step refuses it, and the
    /// very same response then mints a ticket, so it was valid and unspent
    async fn a_good_assertion_on_the_login_step_case() {
        passkeys_on().await;
        let harness = TestHarness::new().await;
        let (mut account, session, _) = harness.new_user().await;
        account.mfa.totp_token = Totp::Enabled {
            secret: "secret".to_string(),
        };
        account.save(&harness.db).await.unwrap();
        let soft = register_passkey(&harness, &account, &session).await;
        let sessions = session_count(&harness, &account.id).await;

        let signed = signed_body(&harness, &session, &soft).await;
        let (status, body, ticket) = login_step(&harness, &account.id, &signed).await;
        assert_eq!(status, Status::BadRequest, "{body}");
        assert!(
            matches!(error_type(&body), ErrorType::DisallowedMFAMethod),
            "{body}"
        );
        assert_eq!(session_count(&harness, &account.id).await, sessions);
        assert!(
            !harness
                .db
                .fetch_ticket_by_token(&ticket.token)
                .await
                .expect("the login ticket survives one refused attempt")
                .authorised,
            "a refused passkey must not authorise the login ticket"
        );

        let (status, body) = put_ticket(&harness, &session, &signed).await;
        assert_eq!(status, Status::Ok, "{body}");
    }
}
