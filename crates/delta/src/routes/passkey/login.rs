//! Sign in with a passkey
//! POST /passkey/login/start
//! POST /passkey/login/finish
use revolt_database::{Database, EmailVerification};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::serde::json::Json;
use rocket::State;
use serde::Deserialize;

use crate::routes::session::login::complete_login;
use crate::util::passkey;

/// # Passkey Login Data
// No `Debug`: nothing here is ever to be printed
#[derive(Deserialize, JsonSchema)]
pub struct DataPasskeyLogin {
    /// Id of the challenge the sign-in was started with
    pub challenge_id: String,

    /// WebAuthn assertion, as returned by the platform credential API
    pub credential: serde_json::Value,

    /// Friendly name used for the session
    #[serde(default)]
    pub friendly_name: Option<String>,
}

/// # Start Passkey Login
///
/// Start signing in with a passkey. Takes nothing and answers the same for
/// everyone: the device offers the passkeys it holds for this site, and the
/// account is only known once `login/finish` has verified the assertion.
#[openapi(tag = "Passkey")]
#[post("/login/start")]
pub async fn login_start() -> Result<Json<v0::ResponsePasskeyOptions>> {
    passkey::assert_available().await?;

    passkey::start_login().await.map(Json)
}

/// # Finish Passkey Login
///
/// Sign in with the assertion a passkey produced for `login/start`.
///
/// A passkey is a complete sign-in: there is no second step. An assertion
/// that does not verify, for any reason, is answered `InvalidCredentials`.
#[openapi(tag = "Passkey")]
#[post("/login/finish", data = "<data>")]
pub async fn login_finish(
    db: &State<Database>,
    data: Json<DataPasskeyLogin>,
) -> Result<Json<v0::ResponseLogin>> {
    passkey::assert_available().await?;

    let DataPasskeyLogin {
        challenge_id,
        credential,
        friendly_name,
    } = data.into_inner();

    // Whatever went wrong, the caller learns one thing only. No lockout
    // attempt is written for a failure: nothing here can be guessed, and
    // the account is not even known until the assertion verifies.
    let account_id = passkey::finish_login(db, &challenge_id, credential)
        .await
        .map_err(|error| {
            // Anything but a refused assertion is an outage (Redis, the
            // database). The caller is told the same; the log is not. Only
            // the error type is written, never what was sent.
            if !matches!(error.error_type, ErrorType::InvalidCredentials) {
                log::error!(
                    "passkeys: a sign-in could not be checked: {:?}",
                    error.error_type
                );
            }

            create_error!(InvalidCredentials)
        })?;

    sign_in(db, &account_id, friendly_name).await.map(Json)
}

/// Signs in the account a verified assertion belongs to.
///
/// The password lockout is deliberately not consulted, and not changed: it
/// counts guesses, a signature cannot be guessed, and honouring it here
/// would let anyone who knows the email keep a passkey user out.
async fn sign_in(
    db: &Database,
    account_id: &str,
    friendly_name: Option<String>,
) -> Result<v0::ResponseLogin> {
    // Read the account again: the verifier only hands back an id. A row
    // that is gone answers as an assertion that did not verify.
    let account = db
        .fetch_account(account_id)
        .await
        .map_err(|_| create_error!(InvalidCredentials))?;

    // As for a password login, once the proof has passed: an account whose
    // email was never verified gets no session
    if let EmailVerification::Pending { .. } = account.verification {
        return Err(create_error!(UnverifiedAccount));
    }

    // The shared gate: deletion, disabled, suspension lift, then the session
    complete_login(db, account, friendly_name).await
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::new_user_handle;
    use crate::util::passkey;
    use crate::util::passkey_soft::{b64u, b64u_decode, SoftPasskey};
    use crate::util::test::TestHarness;
    use webauthn_rs::prelude::Uuid;
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        Account, DeletionInfo, EmailVerification, Lockout, Passkey, Totp,
    };
    use revolt_models::v0;
    use revolt_result::{Error, ErrorType};
    use rocket::http::{ContentType, Status};
    use serde_json::Value;

    const START: &str = "/auth/passkey/login/start";
    const FINISH: &str = "/auth/passkey/login/finish";

    /// Turns passkeys on. `overwrite_config` works once per process and
    /// before anything reads the config, so this comes first in a test and
    /// relies on nextest's one process per test.
    async fn enabled_harness() -> TestHarness {
        revolt_config::overwrite_config(|config| config.features.passkeys.available = true).await;
        TestHarness::new().await
    }

    /// Status and raw body
    async fn post(harness: &TestHarness, path: &str, body: Option<Value>) -> (Status, String) {
        let mut request = harness.client.post(path);
        if let Some(body) = body {
            request = request.header(ContentType::JSON).body(body.to_string());
        }

        let res = request.dispatch().await;
        let status = res.status();
        (status, res.into_string().await.unwrap_or_default())
    }

    /// What `login/start` answers
    async fn start(harness: &TestHarness) -> v0::ResponsePasskeyOptions {
        let (status, body) = post(harness, START, None).await;
        assert_eq!(status, Status::Ok, "login/start refused: {}", body);

        serde_json::from_str(&body).expect("`ResponsePasskeyOptions`")
    }

    /// A fresh challenge id from `login/start`
    async fn challenge(harness: &TestHarness) -> String {
        start(harness).await.challenge_id
    }

    /// The first origin the default config accepts
    const ORIGIN: &str = "https://app.sloga.gg";

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

    /// A finish body carrying a real assertion from `soft` for a fresh
    /// challenge
    async fn signed_finish_body(harness: &TestHarness, soft: &SoftPasskey) -> Value {
        let options = start(harness).await;
        finish_body(&options.challenge_id, soft.get(&options.options, ORIGIN))
    }

    /// Flip the lowest bit of the last byte of an assertion's signature.
    /// The last byte lies inside the DER integer `s`, so the signature still
    /// parses and only fails to verify.
    fn flip_last_signature_byte(credential: &mut Value) {
        let text = credential["response"]["signature"]
            .as_str()
            .expect("a signature");
        let mut bytes = b64u_decode(text);
        *bytes.last_mut().expect("a signature") ^= 0x01;
        credential["response"]["signature"] = Value::from(b64u(&bytes));
    }

    /// The session of a finish that signed in
    fn session_of(answer: &(Status, String), row: &str) -> v0::Session {
        assert_eq!(answer.0, Status::Ok, "{}: {}", row, answer.1);
        match serde_json::from_str::<v0::ResponseLogin>(&answer.1).expect("`ResponseLogin`") {
            v0::ResponseLogin::Success(session) => session,
            other => panic!("{}: expected `Success`, got {:?}", row, other),
        }
    }

    /// The answer every failed finish gets
    fn assert_invalid_credentials(answer: &(Status, String), row: &str) {
        assert_eq!(answer.0, Status::Unauthorized, "{}: {}", row, answer.1);
        assert_eq!(answer.1, r#"{"type":"InvalidCredentials"}"#, "{}", row);
    }

    /// An assertion of the right shape that cannot verify
    fn assertion(credential_id: &str) -> Value {
        json!({
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": "e30",
                "authenticatorData": "AAAA",
                "signature": "AAAA",
                "userHandle": "AAAA"
            },
            "clientExtensionResults": {}
        })
    }

    fn finish_body(challenge_id: &str, credential: Value) -> Value {
        json!({
            "challenge_id": challenge_id,
            "credential": credential,
            "friendly_name": "Test phone"
        })
    }

    /// A fresh account, verified, with a password
    async fn new_account(harness: &TestHarness) -> Account {
        Account::new(
            &harness.db,
            format!("{}@validemail.com", TestHarness::rand_string()),
            "password_insecure".into(),
            false,
        )
        .await
        .unwrap()
    }

    /// A stored passkey for `account_id`; its credential is not a real one,
    /// so an assertion naming it can never verify. Returns its credential id.
    async fn stored_passkey(harness: &TestHarness, account_id: &str) -> String {
        // 24 base64url characters: 18 bytes exactly, so the text is canonical
        let credential_id = format!("Y3Jl{}", TestHarness::rand_string());
        assert_eq!(credential_id.len(), 24);
        harness
            .db
            .insert_passkey(&Passkey::new(
                account_id.to_string(),
                credential_id.clone(),
                new_user_handle(),
                "{}".to_string(),
                "Phone".to_string(),
            ))
            .await
            .unwrap();
        credential_id
    }

    /// The stored lockout as plain values, so two reads compare
    async fn lockout(harness: &TestHarness, account_id: &str) -> Option<(i32, Option<Timestamp>)> {
        let stored = harness.db.fetch_account(account_id).await.unwrap();
        stored.lockout.map(|lockout| (lockout.attempts, lockout.expiry))
    }

    async fn session_names(harness: &TestHarness, account_id: &str) -> Vec<String> {
        let sessions = harness.db.fetch_sessions(account_id).await.unwrap();
        sessions.into_iter().map(|session| session.name).collect()
    }

    fn soon() -> Timestamp {
        Timestamp::now_utc() + Duration::seconds(3600)
    }

    /// With the feature off (the default), both routes refuse the same way
    /// and hand out nothing
    #[test]
    fn feature_off_refuses_both_routes() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            assert!(
                !revolt_config::config().await.features.passkeys.available,
                "the control: passkeys ship off"
            );

            let start = post(&harness, START, None).await;
            assert_ne!(start.0, Status::Ok, "login/start answered: {}", start.1);
            assert!(!start.1.contains("challenge_id"), "{}", start.1);

            // A body that parses, so the refusal is the switch and not the
            // body guard
            let finish = post(
                &harness,
                FINISH,
                Some(finish_body("no-such-challenge", assertion("AAAA"))),
            )
            .await;
            assert_eq!(finish, start, "both routes refuse as one");
            assert!(!matches!(
                serde_json::from_str::<Error>(&finish.1).unwrap().error_type,
                ErrorType::InvalidCredentials,
            ));
        })
    }

    /// `login/start` is the same for everyone: it reads no email or name,
    /// lists no credentials, and names no account
    #[test]
    fn login_start_carries_no_account_data() {
        crate::util::test::rt().block_on(async {
            let harness = enabled_harness().await;

            // An account with a passkey exists, and the request names it
            let account = new_account(&harness).await;
            let credential_id = stored_passkey(&harness, &account.id).await;

            let plain = post(&harness, START, None).await;
            let named = post(
                &harness,
                START,
                Some(json!({ "email": account.email, "username": account.email })),
            )
            .await;

            for (row, (status, body)) in [("plain", &plain), ("named", &named)] {
                assert_eq!(*status, Status::Ok, "{}: {}", row, body);

                let value: Value = serde_json::from_str(body).expect("json");
                let mut keys: Vec<&str> =
                    value.as_object().unwrap().keys().map(String::as_str).collect();
                keys.sort();
                assert_eq!(keys, vec!["challenge_id", "options"], "{}", row);

                let options = value["options"].as_object().expect("an options object");
                assert!(options.contains_key("challenge"), "{}: bare options", row);
                assert!(!options.contains_key("publicKey"), "{}: not the wrapper", row);
                assert!(!options.contains_key("user"), "{}: no user entity", row);
                assert!(
                    options
                        .get("allowCredentials")
                        .map_or(true, |list| list.as_array().is_some_and(|list| list.is_empty())),
                    "{}: no credential is listed",
                    row
                );

                for needle in [
                    account.id.as_str(),
                    account.email.as_str(),
                    credential_id.as_str(),
                ] {
                    assert!(!body.contains(needle), "{}: the answer names the account", row);
                }
            }

            // Naming an account changes nothing but the two random values
            let shape = |body: &str| {
                let mut value: Value = serde_json::from_str(body).unwrap();
                value["challenge_id"] = Value::Null;
                value["options"]["challenge"] = Value::Null;
                value
            };
            assert_eq!(shape(&plain.1), shape(&named.1));
        })
    }

    /// Every way a finish can fail before a session answers with the same
    /// status and the same bytes, and leaves the named account untouched
    #[test]
    fn every_failed_finish_answers_alike() {
        crate::util::test::rt().block_on(async {
            let harness = enabled_harness().await;

            // An account with a real passkey and attempts already counted
            let account = new_account(&harness).await;
            let soft = registered_passkey(&harness, &account).await;
            let credential_id = b64u(&soft.cred_id);
            harness
                .db
                .set_lockout(
                    &account.id,
                    Some(Lockout {
                        attempts: 2,
                        expiry: None,
                    }),
                )
                .await
                .unwrap();
            let lockout_before = lockout(&harness, &account.id).await;
            assert!(lockout_before.is_some(), "the seed must be stored");

            let mut answers = vec![];

            // Not a credential at all, on a live challenge
            let used = challenge(&harness).await;
            answers.push((
                "garbage credential",
                post(&harness, FINISH, Some(finish_body(&used, json!("garbage")))).await,
            ));

            // The same challenge again: it was spent by the request above
            answers.push((
                "replayed challenge",
                post(
                    &harness,
                    FINISH,
                    Some(finish_body(&used, assertion(&credential_id))),
                )
                .await,
            ));

            // A challenge that never existed
            answers.push((
                "unknown challenge",
                post(
                    &harness,
                    FINISH,
                    Some(finish_body("no-such-challenge", assertion(&credential_id))),
                )
                .await,
            ));

            // A well-formed, correctly signed assertion from a passkey nobody
            // registered: it gets as far as the credential lookup
            let mut stranger = SoftPasskey::new();
            stranger.user_handle = Some(Uuid::new_v4().as_bytes().to_vec());
            answers.push((
                "unknown credential",
                post(
                    &harness,
                    FINISH,
                    Some(signed_finish_body(&harness, &stranger).await),
                )
                .await,
            ));

            // The registered passkey's own assertion with one bit of the
            // signature flipped: it gets as far as the signature check
            let mut body = signed_finish_body(&harness, &soft).await;
            flip_last_signature_byte(&mut body["credential"]);
            answers.push(("bad signature", post(&harness, FINISH, Some(body)).await));

            for (row, answer) in &answers {
                assert_invalid_credentials(answer, row);
            }

            assert_eq!(
                lockout(&harness, &account.id).await,
                lockout_before,
                "a failed assertion never writes a lockout attempt"
            );
            assert!(
                session_names(&harness, &account.id).await.is_empty(),
                "a failed assertion stores no session"
            );

            // The control for the last row: the same passkey, signature
            // left alone, signs in
            let body = signed_finish_body(&harness, &soft).await;
            let answer = post(&harness, FINISH, Some(body)).await;
            assert_eq!(session_of(&answer, "control").user_id, account.id);
        })
    }

    /// A real passkey signs in over HTTP in one step, TOTP or not, the
    /// session carries the friendly name, and the spent challenge cannot be
    /// used again
    #[test]
    fn passkey_login_signs_in_and_names_the_session() {
        crate::util::test::rt().block_on(async {
            let harness = enabled_harness().await;

            for (row, totp) in [("plain", false), ("totp", true)] {
                let mut account = new_account(&harness).await;
                if totp {
                    account.mfa.totp_token = Totp::Enabled {
                        secret: "secret".to_string(),
                    };
                    account.save(&harness.db).await.unwrap();
                }
                let soft = registered_passkey(&harness, &account).await;

                let body = signed_finish_body(&harness, &soft).await;
                let answer = post(&harness, FINISH, Some(body.clone())).await;
                let session = session_of(&answer, row);
                assert_eq!(session.user_id, account.id, "{}", row);
                assert_eq!(
                    session_names(&harness, &account.id).await,
                    vec!["Test phone".to_string()],
                    "{}: the session carries the friendly name",
                    row
                );

                // The very same request again: the challenge is spent
                let replay = post(&harness, FINISH, Some(body)).await;
                assert_invalid_credentials(&replay, row);
                assert_eq!(
                    session_names(&harness, &account.id).await.len(),
                    1,
                    "{}: a replay stores no session",
                    row
                );
            }
        })
    }

    /// The password lockout: a real passkey that fails its assertion writes
    /// no attempt, and one that passes signs in while the account is locked,
    /// leaving the lockout as it was
    #[test]
    fn passkey_login_neither_reads_nor_writes_the_lockout() {
        crate::util::test::rt().block_on(async {
            let harness = enabled_harness().await;

            let account = new_account(&harness).await;
            let mut soft = registered_passkey(&harness, &account).await;
            harness
                .db
                .set_lockout(
                    &account.id,
                    Some(Lockout {
                        attempts: 9,
                        expiry: Some(soon()),
                    }),
                )
                .await
                .unwrap();
            let before = lockout(&harness, &account.id).await;
            assert!(before.is_some(), "the seed must be stored");

            // The control: this lockout does refuse a password login
            let stored = harness.db.fetch_account(&account.id).await.unwrap();
            assert!(crate::routes::session::login::assert_not_locked_out(&stored).is_err());

            // The right key, without user verification: refused
            soft.uv = false;
            let body = signed_finish_body(&harness, &soft).await;
            let failed = post(&harness, FINISH, Some(body)).await;
            assert_invalid_credentials(&failed, "no user verification");
            assert_eq!(
                lockout(&harness, &account.id).await,
                before,
                "a failed assertion never writes a lockout attempt"
            );
            assert!(session_names(&harness, &account.id).await.is_empty());

            // The same key with user verification: signed in, still locked
            // for passwords
            soft.uv = true;
            let body = signed_finish_body(&harness, &soft).await;
            let answer = post(&harness, FINISH, Some(body)).await;
            assert_eq!(session_of(&answer, "locked").user_id, account.id);
            assert_eq!(
                lockout(&harness, &account.id).await,
                before,
                "a passkey sign-in leaves the password lockout alone"
            );
        })
    }

    /// A disabled account, or one whose deletion is confirmed, is refused
    /// over HTTP exactly as a password login is, and gets no session
    #[test]
    fn passkey_login_goes_through_the_shared_gate() {
        crate::util::test::rt().block_on(async {
            let harness = enabled_harness().await;

            for row in ["disabled", "scheduled"] {
                let account = new_account(&harness).await;
                let soft = registered_passkey(&harness, &account).await;

                if row == "disabled" {
                    let mut stored = harness.db.fetch_account(&account.id).await.unwrap();
                    stored.disabled = true;
                    stored.save(&harness.db).await.unwrap();
                } else {
                    harness
                        .db
                        .set_account_deletion(
                            &account.id,
                            Some(DeletionInfo::Scheduled { after: soon() }),
                        )
                        .await
                        .unwrap();
                }

                let body = signed_finish_body(&harness, &soft).await;
                let (status, body) = post(&harness, FINISH, Some(body)).await;
                assert_eq!(status, Status::Ok, "{}: {}", row, body);
                match serde_json::from_str::<v0::ResponseLogin>(&body).expect("`ResponseLogin`") {
                    v0::ResponseLogin::Disabled { user_id, .. } => {
                        assert_eq!(user_id, account.id, "{}", row)
                    }
                    other => panic!("{}: expected `Disabled`, got {:?}", row, other),
                }
                assert!(
                    session_names(&harness, &account.id).await.is_empty(),
                    "{}: a refused sign-in must store no session",
                    row
                );
            }
        })
    }

    /// Run `sign_in` (everything after the assertion has verified) and
    /// expect a session
    async fn signs_in(
        harness: &TestHarness,
        account_id: &str,
        name: Option<&str>,
        row: &str,
    ) -> v0::Session {
        match super::sign_in(&harness.db, account_id, name.map(str::to_string)).await {
            Ok(v0::ResponseLogin::Success(session)) => {
                assert_eq!(session.user_id, account_id, "{}", row);
                session
            }
            other => panic!("{}: expected `Success`, got {:?}", row, other),
        }
    }

    /// Run `sign_in` and expect the shared gate's refusal
    async fn refused(harness: &TestHarness, account_id: &str, row: &str) {
        match super::sign_in(&harness.db, account_id, Some("Test phone".to_string())).await {
            Ok(v0::ResponseLogin::Disabled {
                user_id,
                suspended_until,
            }) => {
                assert_eq!(user_id, account_id, "{}", row);
                assert_eq!(suspended_until, None, "{}", row);
            }
            other => panic!("{}: expected `Disabled`, got {:?}", row, other),
        }

        assert!(
            session_names(harness, account_id).await.is_empty(),
            "{}: a refused sign-in must store no session",
            row
        );
    }

    /// What a verified assertion leads to, for each kind of account. Driven
    /// on `sign_in`, which is all of `login_finish` after the verifier.
    #[test]
    fn sign_in_table() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;

            // (a) The session carries the friendly name
            {
                let account = new_account(&harness).await;
                signs_in(&harness, &account.id, Some("Test phone"), "a").await;
                assert_eq!(
                    session_names(&harness, &account.id).await,
                    vec!["Test phone".to_string()],
                    "a"
                );
            }

            // (b) No name given: the default every login uses
            {
                let account = new_account(&harness).await;
                signs_in(&harness, &account.id, None, "b").await;
                assert_eq!(
                    session_names(&harness, &account.id).await,
                    vec!["Unknown".to_string()],
                    "b"
                );
            }

            // (c) A live password lockout does not keep a passkey out, and
            // is left exactly as it was
            {
                let account = new_account(&harness).await;
                harness
                    .db
                    .set_lockout(
                        &account.id,
                        Some(Lockout {
                            attempts: 9,
                            expiry: Some(soon()),
                        }),
                    )
                    .await
                    .unwrap();
                let before = lockout(&harness, &account.id).await;
                assert!(before.is_some(), "c: the seed must be stored");

                // The control: this lockout does refuse a password login
                let stored = harness.db.fetch_account(&account.id).await.unwrap();
                assert!(
                    crate::routes::session::login::assert_not_locked_out(&stored).is_err(),
                    "c: the control"
                );

                signs_in(&harness, &account.id, Some("Test phone"), "c").await;
                assert_eq!(lockout(&harness, &account.id).await, before, "c");
            }

            // (d) TOTP on: a passkey is the whole sign-in, never a ticket
            {
                let mut account = new_account(&harness).await;
                account.mfa.totp_token = Totp::Enabled {
                    secret: "secret".to_string(),
                };
                account.save(&harness.db).await.unwrap();
                assert!(
                    harness.db.fetch_account(&account.id).await.unwrap().mfa.is_active(),
                    "d: the seed must be stored"
                );

                signs_in(&harness, &account.id, Some("Test phone"), "d").await;
            }

            // (e) An account with no password signs in
            {
                let mut account = new_account(&harness).await;
                account.password_absent = true;
                account.save(&harness.db).await.unwrap();

                signs_in(&harness, &account.id, Some("Test phone"), "e").await;
            }

            // (f) + (g) A confirmed or finished deletion is refused by the
            // shared gate
            for (row, deletion) in [
                ("f", DeletionInfo::Scheduled { after: soon() }),
                ("g", DeletionInfo::Deleted),
            ] {
                let account = new_account(&harness).await;
                harness
                    .db
                    .set_account_deletion(&account.id, Some(deletion))
                    .await
                    .unwrap();
                assert!(
                    harness.db.fetch_account(&account.id).await.unwrap().deletion.is_some(),
                    "{}: the seed must be stored",
                    row
                );

                refused(&harness, &account.id, row).await;
            }

            // (h) A disabled account is refused by the shared gate
            {
                let mut account = new_account(&harness).await;
                account.disabled = true;
                account.save(&harness.db).await.unwrap();

                refused(&harness, &account.id, "h").await;
            }

            // (i) An email that was never verified gets no session, with
            // the answer a password login gives
            {
                let mut account = new_account(&harness).await;
                account.verification = EmailVerification::Pending {
                    token: "".to_string(),
                    expiry: Timestamp::now_utc(),
                };
                account.save(&harness.db).await.unwrap();

                match super::sign_in(&harness.db, &account.id, None).await {
                    Err(error) => assert!(
                        matches!(error.error_type, ErrorType::UnverifiedAccount),
                        "i: expected `UnverifiedAccount`, got {:?}",
                        error
                    ),
                    Ok(other) => panic!("i: expected a refusal, got {:?}", other),
                }
                assert!(session_names(&harness, &account.id).await.is_empty(), "i");
            }

            // (j) The account row is gone: the answer of a failed assertion
            {
                match super::sign_in(&harness.db, "01NOSUCHACCOUNT", None).await {
                    Err(error) => assert!(
                        matches!(error.error_type, ErrorType::InvalidCredentials),
                        "j: expected `InvalidCredentials`, got {:?}",
                        error
                    ),
                    Ok(other) => panic!("j: expected a refusal, got {:?}", other),
                }
            }
        })
    }

    /// The body: the session name is optional, and a credential of any JSON
    /// shape reaches the verifier (so it, not the body guard, refuses it)
    #[test]
    fn finish_body_shape() {
        let named: super::DataPasskeyLogin = serde_json::from_value(json!({
            "challenge_id": "c1",
            "credential": { "id": "abc" },
            "friendly_name": "Test phone"
        }))
        .expect("a body with a name");
        assert_eq!(named.challenge_id, "c1");
        assert_eq!(named.credential, json!({ "id": "abc" }));
        assert_eq!(named.friendly_name.as_deref(), Some("Test phone"));

        let bare: super::DataPasskeyLogin =
            serde_json::from_value(json!({ "challenge_id": "c1", "credential": "garbage" }))
                .expect("a body without a name");
        assert_eq!(bare.friendly_name, None);

        // The register body's `name` is not the session name
        let other: super::DataPasskeyLogin = serde_json::from_value(json!({
            "challenge_id": "c1",
            "credential": {},
            "name": "Phone"
        }))
        .expect("an unknown field is ignored");
        assert_eq!(other.friendly_name, None);
    }
}
