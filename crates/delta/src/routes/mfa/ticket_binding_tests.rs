//! SEC-001: an MFA ticket authorizes a request only together with a session
//! of the account that passed MFA.
//!
//! A. One test per ticket route. The attacker holds the victim's session
//!    token and a validated ticket minted on the attacker's own account. The
//!    route must refuse, the victim's state must not move, and the attacker's
//!    ticket must survive: a mismatch does not burn it. The victim has TOTP
//!    and recovery codes, and every body carries the victim's correct
//!    password, so each refusal can only come from the binding. Two positive
//!    controls send the victim's own ticket and succeed.
//! B. The guards on a bare Rocket, with no route logic behind them.
//! C. Every route file that takes a ticket guard is listed in
//!    `TICKET_ROUTES`, and each listed route has its test here.
//!
//! Only APIs that exist at 05b50d57 are used, so this file also compiles on
//! the unfixed tree, where every A and B test fails.

use std::collections::BTreeSet;
use std::path::Path;

use revolt_database::{
    Account, MFATicket, Member, Session, Totp, UnvalidatedTicket, User, ValidatedTicket,
};
use revolt_models::v0;
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::{Client, LocalRequest};

use crate::routes::e2ee::tests::{publish_device, TestDevice};
use crate::util::test::{rt, without_comments, without_whitespace, TestHarness};

/// Every route file under `src/routes` that takes a ticket guard, with the
/// test below that sends it a foreign ticket. `mfa/create_ticket.rs` is not
/// here: it no longer takes a ticket (D3).
const TICKET_ROUTES: &[(&str, &str)] = &[
    ("account/change_email.rs", "foreign_ticket_change_email"),
    (
        "account/change_password.rs",
        "foreign_ticket_change_password",
    ),
    ("account/delete_account.rs", "foreign_ticket_delete_account"),
    (
        "account/disable_account.rs",
        "foreign_ticket_disable_account",
    ),
    ("e2ee/delete_backup.rs", "foreign_ticket_delete_backup"),
    ("e2ee/get_backup.rs", "foreign_ticket_get_backup"),
    ("e2ee/publish_keys.rs", "foreign_ticket_publish_keys"),
    ("e2ee/revoke_device.rs", "foreign_ticket_revoke_device"),
    ("mfa/fetch_recovery.rs", "foreign_ticket_fetch_recovery"),
    (
        "mfa/generate_recovery.rs",
        "foreign_ticket_generate_recovery",
    ),
    ("mfa/totp_disable.rs", "foreign_ticket_totp_disable"),
    (
        "mfa/totp_generate_secret.rs",
        "foreign_ticket_totp_generate_secret",
    ),
    ("servers/server_edit.rs", "foreign_ticket_server_edit"),
    ("session/revoke.rs", "foreign_ticket_session_revoke"),
    ("session/revoke_all.rs", "foreign_ticket_session_revoke_all"),
];

/// The victim's correct current password (`TestHarness::account_from_user`).
const VICTIM_PASSWORD: &str = "password_insecure";

/// Victim V, with TOTP enabled, recovery codes and two sessions, and
/// attacker A, who holds V's session token and a validated ticket for A's
/// own account.
struct Pair {
    harness: TestHarness,
    victim: Account,
    victim_user: User,
    victim_session: Session,
    victim_other_session: Session,
    attacker_user: User,
    attacker_ticket: MFATicket,
}

/// What a refused request must leave alone.
///
/// `lockout` is not compared: whether a refused request counts an attempt is
/// the business of `session/mfa_limit_tests.rs`, not of the binding.
struct VictimState {
    account: serde_json::Value,
    sessions: Vec<String>,
    devices: Vec<String>,
}

async fn saved_ticket(harness: &TestHarness, account_id: &str, validated: bool) -> MFATicket {
    let ticket = MFATicket::new(account_id.to_string(), validated);
    ticket.save(&harness.db).await.expect("`MFATicket`");
    ticket
}

async fn ticket_exists(harness: &TestHarness, ticket: &MFATicket) -> bool {
    harness
        .db
        .fetch_ticket_by_token(&ticket.token)
        .await
        .is_ok()
}

/// `request` with a session token and a ticket.
fn with_ticket<'c>(
    request: LocalRequest<'c>,
    session: &Session,
    ticket: &MFATicket,
) -> LocalRequest<'c> {
    request
        .header(Header::new("x-session-token", session.token.clone()))
        .header(Header::new("x-mfa-ticket", ticket.token.clone()))
}

async fn pair() -> Pair {
    let harness = TestHarness::new().await;

    let (mut victim, victim_session, victim_user) = harness.new_user().await;
    victim.mfa.totp_token = Totp::Enabled {
        secret: "secret".to_string(),
    };
    victim.mfa.generate_recovery_codes();
    victim.save(&harness.db).await.expect("victim MFA");
    let victim_other_session = victim
        .create_session(&harness.db, String::new())
        .await
        .expect("victim's second `Session`");

    let (attacker, _, attacker_user) = harness.new_user().await;
    let attacker_ticket = saved_ticket(&harness, &attacker.id, true).await;

    let pair = Pair {
        harness,
        victim,
        victim_user,
        victim_session,
        victim_other_session,
        attacker_user,
        attacker_ticket,
    };

    // Every MFA-gated branch is live, so a refusal is the binding's doing
    let account = pair.victim_account().await;
    assert!(account.mfa.is_active(), "setup: the victim's TOTP is on");
    assert!(
        !account.mfa.recovery_codes.is_empty(),
        "setup: the victim has recovery codes"
    );
    assert!(account.verify_password(VICTIM_PASSWORD).is_ok());
    assert_eq!(victim_state(&pair).await.sessions.len(), 2);
    assert!(ticket_exists(&pair.harness, &pair.attacker_ticket).await);

    pair
}

async fn victim_state(pair: &Pair) -> VictimState {
    let db = &pair.harness.db;
    let account = pair.victim_account().await;

    let mut sessions: Vec<String> = db
        .fetch_sessions(&pair.victim.id)
        .await
        .expect("victim's sessions")
        .into_iter()
        .map(|session| session.id)
        .collect();
    sessions.sort();

    let mut devices: Vec<String> = db
        .fetch_e2ee_identities(&pair.victim.id)
        .await
        .expect("victim's E2EE devices")
        .into_iter()
        .map(|identity| identity.device_id)
        .collect();
    devices.sort();

    VictimState {
        account: json!({
            "email": account.email,
            "email_normalised": account.email_normalised,
            "password": account.password,
            "verification": account.verification,
            "password_reset": account.password_reset,
            "mfa": account.mfa,
            "disabled": account.disabled,
            "deletion": account.deletion,
        }),
        sessions,
        devices,
    }
}

impl Pair {
    /// The attacker's request: the victim's session, the attacker's ticket.
    fn forged<'c>(&self, request: LocalRequest<'c>) -> LocalRequest<'c> {
        with_ticket(request, &self.victim_session, &self.attacker_ticket)
    }

    async fn victim_account(&self) -> Account {
        self.harness
            .db
            .fetch_account(&self.victim.id)
            .await
            .expect("victim `Account`")
    }

    async fn assert_unchanged(&self, route: &str, before: &VictimState) {
        let after = victim_state(self).await;
        assert_eq!(
            before.account, after.account,
            "{}: the victim's account changed",
            route
        );
        assert_eq!(
            before.sessions, after.sessions,
            "{}: the victim's sessions changed",
            route
        );
        assert_eq!(
            before.devices, after.devices,
            "{}: the victim's E2EE devices changed",
            route
        );
    }

    async fn assert_ticket_kept(&self, route: &str) {
        assert!(
            ticket_exists(&self.harness, &self.attacker_ticket).await,
            "{}: the attacker's ticket was consumed by a request it could not authorize",
            route
        );
    }
}

/// A backup for `device_id`, uploaded from the session the device is bound
/// to. The header is the one `e2ee::tests::backup_header` builds.
async fn put_backup(harness: &TestHarness, session: &Session, user_id: &str, device_id: &str) {
    let header = format!(
        "{{\"v\":1,\"kdf\":{{\"alg\":\"argon2id\",\"m_kib\":262144,\"t\":3,\"p\":4}},\
         \"salt\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\
         \"user_id\":\"{}\",\"device_id\":\"{}\",\
         \"generation\":1,\"created_at\":0}}",
        user_id, device_id
    );
    let body = v0::DataPutE2EEBackup {
        device_id: device_id.to_string(),
        header,
        ciphertext: "AAAAAAAAAAAAAAAA".to_string(),
        generation: 1,
    };

    let status = harness
        .client
        .put("/e2ee/backup")
        .header(ContentType::JSON)
        .header(Header::new("x-session-token", session.token.clone()))
        .body(serde_json::to_string(&body).unwrap())
        .dispatch()
        .await
        .status();
    assert_eq!(status, Status::Ok, "setup: backup upload");
    assert!(harness
        .db
        .fetch_e2ee_backup(user_id, device_id)
        .await
        .expect("backup lookup")
        .is_some());
}

// ========================================================================
// A. Route matrix
// ========================================================================

#[test]
fn foreign_ticket_totp_disable() {
    rt().block_on(foreign_ticket_totp_disable_case())
}

/// DELETE /auth/mfa/totp would strip the victim's TOTP.
async fn foreign_ticket_totp_disable_case() {
    let pair = pair().await;
    let before = victim_state(&pair).await;

    let status = pair
        .forged(pair.harness.client.delete("/auth/mfa/totp"))
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Forbidden, "totp_disable");
    assert!(
        pair.victim_account().await.mfa.is_active(),
        "totp_disable: the victim's TOTP was turned off"
    );
    pair.assert_unchanged("totp_disable", &before).await;
    pair.assert_ticket_kept("totp_disable").await;
}

#[test]
fn foreign_ticket_totp_generate_secret() {
    rt().block_on(foreign_ticket_totp_generate_secret_case())
}

/// POST /auth/mfa/totp would install a TOTP secret the attacker knows. The
/// route refuses to re-secret an enabled TOTP, so the victim's is off here:
/// otherwise the route itself would refuse, and the test would prove nothing.
async fn foreign_ticket_totp_generate_secret_case() {
    let mut pair = pair().await;
    pair.victim.mfa.totp_token = Totp::Disabled;
    pair.victim
        .save(&pair.harness.db)
        .await
        .expect("victim TOTP off");
    let before = victim_state(&pair).await;

    let status = pair
        .forged(pair.harness.client.post("/auth/mfa/totp"))
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Forbidden, "totp_generate_secret");
    assert!(
        matches!(pair.victim_account().await.mfa.totp_token, Totp::Disabled),
        "totp_generate_secret: a pending secret was installed"
    );
    pair.assert_unchanged("totp_generate_secret", &before).await;
    pair.assert_ticket_kept("totp_generate_secret").await;
}

#[test]
fn foreign_ticket_fetch_recovery() {
    rt().block_on(foreign_ticket_fetch_recovery_case())
}

/// POST /auth/mfa/recovery would hand over the victim's recovery codes. It
/// changes nothing, so the status and the kept ticket are what bite.
async fn foreign_ticket_fetch_recovery_case() {
    let pair = pair().await;
    let before = victim_state(&pair).await;

    let status = pair
        .forged(pair.harness.client.post("/auth/mfa/recovery"))
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Forbidden, "fetch_recovery");
    pair.assert_unchanged("fetch_recovery", &before).await;
    pair.assert_ticket_kept("fetch_recovery").await;
}

#[test]
fn foreign_ticket_generate_recovery() {
    rt().block_on(foreign_ticket_generate_recovery_case())
}

/// PATCH /auth/mfa/recovery would rotate the codes to ones the attacker reads.
async fn foreign_ticket_generate_recovery_case() {
    let pair = pair().await;
    let before = victim_state(&pair).await;

    let status = pair
        .forged(pair.harness.client.patch("/auth/mfa/recovery"))
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Forbidden, "generate_recovery");
    assert_eq!(
        pair.victim_account().await.mfa.recovery_codes,
        pair.victim.mfa.recovery_codes,
        "generate_recovery: the victim's recovery codes were rotated"
    );
    pair.assert_unchanged("generate_recovery", &before).await;
    pair.assert_ticket_kept("generate_recovery").await;
}

#[test]
fn foreign_ticket_change_password() {
    rt().block_on(foreign_ticket_change_password_case())
}

/// PATCH /auth/account/change/password takes `Option<ValidatedTicket>`. The
/// guard yields no ticket, and with MFA on the route refuses that with
/// InvalidCredentials (401), before it looks at the password.
async fn foreign_ticket_change_password_case() {
    let pair = pair().await;
    let before = victim_state(&pair).await;

    let status = pair
        .forged(pair.harness.client.patch("/auth/account/change/password"))
        .header(ContentType::JSON)
        .body(
            json!({
                "password": format!(
                    "{}-{}",
                    TestHarness::rand_string(),
                    TestHarness::rand_string()
                ),
                "current_password": VICTIM_PASSWORD,
            })
            .to_string(),
        )
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Unauthorized, "change_password");
    assert!(
        pair.victim_account()
            .await
            .verify_password(VICTIM_PASSWORD)
            .is_ok(),
        "change_password: the victim's password was changed"
    );
    pair.assert_unchanged("change_password", &before).await;
    pair.assert_ticket_kept("change_password").await;
}

#[test]
fn foreign_ticket_change_email() {
    rt().block_on(foreign_ticket_change_email_case())
}

/// PATCH /auth/account/change/email takes `Option<ValidatedTicket>`, as
/// change_password does: InvalidCredentials (401) with MFA on. The address is
/// on a domain `validate_email` accepts (`example.com` is blocked).
async fn foreign_ticket_change_email_case() {
    let pair = pair().await;
    let before = victim_state(&pair).await;

    let status = pair
        .forged(pair.harness.client.patch("/auth/account/change/email"))
        .header(ContentType::JSON)
        .body(
            json!({
                "email": format!("{}@valid.com", TestHarness::rand_string()),
                "current_password": VICTIM_PASSWORD,
            })
            .to_string(),
        )
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Unauthorized, "change_email");
    pair.assert_unchanged("change_email", &before).await;
    pair.assert_ticket_kept("change_email").await;
}

#[test]
fn foreign_ticket_delete_account() {
    rt().block_on(foreign_ticket_delete_account_case())
}

/// POST /auth/account/delete would start the victim's account deletion.
async fn foreign_ticket_delete_account_case() {
    let pair = pair().await;
    let before = victim_state(&pair).await;

    let status = pair
        .forged(pair.harness.client.post("/auth/account/delete"))
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Forbidden, "delete_account");
    let account = pair.victim_account().await;
    assert!(
        account.deletion.is_none(),
        "delete_account: deletion was started"
    );
    assert!(
        !account.disabled,
        "delete_account: the account was disabled"
    );
    pair.assert_unchanged("delete_account", &before).await;
    pair.assert_ticket_kept("delete_account").await;
}

#[test]
fn foreign_ticket_disable_account() {
    rt().block_on(foreign_ticket_disable_account_case())
}

/// POST /auth/account/disable would disable the victim and end every session.
async fn foreign_ticket_disable_account_case() {
    let pair = pair().await;
    let before = victim_state(&pair).await;

    let status = pair
        .forged(pair.harness.client.post("/auth/account/disable"))
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Forbidden, "disable_account");
    assert!(
        !pair.victim_account().await.disabled,
        "disable_account: the account was disabled"
    );
    pair.assert_unchanged("disable_account", &before).await;
    pair.assert_ticket_kept("disable_account").await;
}

#[test]
fn foreign_ticket_session_revoke() {
    rt().block_on(foreign_ticket_session_revoke_case())
}

/// DELETE /auth/session/:id would end the victim's other session.
async fn foreign_ticket_session_revoke_case() {
    let pair = pair().await;
    let before = victim_state(&pair).await;

    let status = pair
        .forged(
            pair.harness
                .client
                .delete(format!("/auth/session/{}", pair.victim_other_session.id)),
        )
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Forbidden, "session revoke");
    assert!(
        pair.harness
            .db
            .fetch_session(&pair.victim_other_session.id)
            .await
            .is_ok(),
        "session revoke: the victim's other session was ended"
    );
    pair.assert_unchanged("session revoke", &before).await;
    pair.assert_ticket_kept("session revoke").await;
}

#[test]
fn foreign_ticket_session_revoke_all() {
    rt().block_on(foreign_ticket_session_revoke_all_case())
}

/// DELETE /auth/session/all would log the victim out everywhere but the
/// attacker's copy of the session.
async fn foreign_ticket_session_revoke_all_case() {
    let pair = pair().await;
    let before = victim_state(&pair).await;

    let status = pair
        .forged(pair.harness.client.delete("/auth/session/all"))
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Forbidden, "session revoke_all");
    assert!(
        pair.harness
            .db
            .fetch_session(&pair.victim_other_session.id)
            .await
            .is_ok(),
        "session revoke_all: the victim's other session was ended"
    );
    pair.assert_unchanged("session revoke_all", &before).await;
    pair.assert_ticket_kept("session revoke_all").await;
}

#[test]
fn foreign_ticket_revoke_device() {
    rt().block_on(foreign_ticket_revoke_device_case())
}

/// DELETE /e2ee/keys/:device_id would revoke the victim's E2EE device.
async fn foreign_ticket_revoke_device_case() {
    let pair = pair().await;
    let device = publish_device(
        &pair.harness,
        &pair.victim.id,
        &pair.victim_session.token,
        1,
    )
    .await;
    let before = victim_state(&pair).await;
    assert_eq!(before.devices, vec![device.device_id.clone()]);

    let status = pair
        .forged(
            pair.harness
                .client
                .delete(format!("/e2ee/keys/{}", device.device_id)),
        )
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Forbidden, "revoke_device");
    assert!(
        pair.harness
            .db
            .fetch_e2ee_identity(&pair.victim_user.id, &device.device_id)
            .await
            .is_ok(),
        "revoke_device: the victim's device was revoked"
    );
    pair.assert_unchanged("revoke_device", &before).await;
    pair.assert_ticket_kept("revoke_device").await;
}

#[test]
fn foreign_ticket_publish_keys() {
    rt().block_on(foreign_ticket_publish_keys_case())
}

/// PUT /e2ee/keys with a new device would enroll an attacker-held E2EE
/// device on the victim's account. The route takes `Option<ValidatedTicket>`;
/// with no ticket a first publication is InvalidToken (401).
async fn foreign_ticket_publish_keys_case() {
    let pair = pair().await;
    let before = victim_state(&pair).await;
    assert!(before.devices.is_empty());
    let device = TestDevice::new();

    let status = pair
        .forged(pair.harness.client.put("/e2ee/keys"))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&device.bundle(1)).unwrap())
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Unauthorized, "publish_keys");
    assert!(
        pair.harness
            .db
            .fetch_e2ee_identity(&pair.victim_user.id, &device.device_id)
            .await
            .is_err(),
        "publish_keys: a device was enrolled on the victim's account"
    );
    pair.assert_unchanged("publish_keys", &before).await;
    pair.assert_ticket_kept("publish_keys").await;
}

#[test]
fn foreign_ticket_get_backup() {
    rt().block_on(foreign_ticket_get_backup_case())
}

/// GET /e2ee/backup checks the ticket's account itself (M8); the guard now
/// refuses first, with 403, and without consuming the ticket.
async fn foreign_ticket_get_backup_case() {
    let pair = pair().await;
    let device = publish_device(
        &pair.harness,
        &pair.victim.id,
        &pair.victim_session.token,
        1,
    )
    .await;
    put_backup(
        &pair.harness,
        &pair.victim_session,
        &pair.victim_user.id,
        &device.device_id,
    )
    .await;
    let before = victim_state(&pair).await;

    let status = pair
        .forged(pair.harness.client.get("/e2ee/backup"))
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Forbidden, "get_backup");
    assert!(pair
        .harness
        .db
        .fetch_e2ee_backup(&pair.victim_user.id, &device.device_id)
        .await
        .expect("backup lookup")
        .is_some());
    pair.assert_unchanged("get_backup", &before).await;
    pair.assert_ticket_kept("get_backup").await;
}

#[test]
fn foreign_ticket_delete_backup() {
    rt().block_on(foreign_ticket_delete_backup_case())
}

/// DELETE /e2ee/backup/:device_id would destroy the victim's recovery path.
/// Like get_backup it checks the ticket's account itself; the guard refuses
/// first.
async fn foreign_ticket_delete_backup_case() {
    let pair = pair().await;
    let device = publish_device(
        &pair.harness,
        &pair.victim.id,
        &pair.victim_session.token,
        1,
    )
    .await;
    put_backup(
        &pair.harness,
        &pair.victim_session,
        &pair.victim_user.id,
        &device.device_id,
    )
    .await;
    let before = victim_state(&pair).await;

    let status = pair
        .forged(
            pair.harness
                .client
                .delete(format!("/e2ee/backup/{}", device.device_id)),
        )
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Forbidden, "delete_backup");
    assert!(
        pair.harness
            .db
            .fetch_e2ee_backup(&pair.victim_user.id, &device.device_id)
            .await
            .expect("backup lookup")
            .is_some(),
        "delete_backup: the victim's backup was deleted"
    );
    pair.assert_unchanged("delete_backup", &before).await;
    pair.assert_ticket_kept("delete_backup").await;
}

#[test]
fn foreign_ticket_server_edit() {
    rt().block_on(foreign_ticket_server_edit_case())
}

/// PATCH /servers/:id with `owner` would hand the victim's server to the
/// attacker, a member of it. The route takes `Option<ValidatedTicket>`; an
/// ownership transfer with no ticket is InvalidCredentials (401).
async fn foreign_ticket_server_edit_case() {
    let pair = pair().await;
    let (server, _) = pair.harness.new_server(&pair.victim_user).await;
    Member::create(&pair.harness.db, &server, &pair.attacker_user, None)
        .await
        .expect("the attacker joins the victim's server");
    let before = victim_state(&pair).await;

    let status = pair
        .forged(pair.harness.client.patch(format!("/servers/{}", server.id)))
        .header(ContentType::JSON)
        .body(json!({ "owner": pair.attacker_user.id }).to_string())
        .dispatch()
        .await
        .status();

    assert_eq!(status, Status::Unauthorized, "server_edit");
    assert_eq!(
        pair.harness
            .db
            .fetch_server(&server.id)
            .await
            .expect("`Server`")
            .owner,
        pair.victim_user.id,
        "server_edit: the server changed hands"
    );
    pair.assert_unchanged("server_edit", &before).await;
    pair.assert_ticket_kept("server_edit").await;
}

// ------------------------------------------------------------------------
// Positive controls: the same setup, with the victim's own ticket
// ------------------------------------------------------------------------

#[test]
fn own_ticket_totp_disable_succeeds() {
    rt().block_on(own_ticket_totp_disable_succeeds_case())
}

async fn own_ticket_totp_disable_succeeds_case() {
    let pair = pair().await;
    let own = saved_ticket(&pair.harness, &pair.victim.id, true).await;

    let status = with_ticket(
        pair.harness.client.delete("/auth/mfa/totp"),
        &pair.victim_session,
        &own,
    )
    .dispatch()
    .await
    .status();

    assert_eq!(status, Status::NoContent);
    assert!(matches!(
        pair.victim_account().await.mfa.totp_token,
        Totp::Disabled
    ));
    assert!(
        !ticket_exists(&pair.harness, &own).await,
        "a validated ticket is consumed on use"
    );
}

#[test]
fn own_ticket_fetch_recovery_succeeds() {
    rt().block_on(own_ticket_fetch_recovery_succeeds_case())
}

async fn own_ticket_fetch_recovery_succeeds_case() {
    let pair = pair().await;
    let own = saved_ticket(&pair.harness, &pair.victim.id, true).await;

    let response = with_ticket(
        pair.harness.client.post("/auth/mfa/recovery"),
        &pair.victim_session,
        &own,
    )
    .dispatch()
    .await;

    assert_eq!(response.status(), Status::Ok);
    let codes: Vec<String> = response.into_json().await.expect("recovery codes");
    assert_eq!(codes, pair.victim.mfa.recovery_codes);
    assert!(
        !ticket_exists(&pair.harness, &own).await,
        "a validated ticket is consumed on use"
    );
}

// ========================================================================
// B. Guard probe: the guards alone, on a bare Rocket
// ========================================================================

#[rocket::get("/validated")]
fn probe_validated(_ticket: ValidatedTicket) -> &'static str {
    "ok"
}

#[rocket::get("/optional")]
fn probe_optional(ticket: Option<ValidatedTicket>) -> &'static str {
    if ticket.is_some() {
        "some"
    } else {
        "none"
    }
}

#[rocket::get("/unvalidated")]
fn probe_unvalidated(_ticket: UnvalidatedTicket) -> &'static str {
    "ok"
}

async fn probe_client(harness: &TestHarness) -> Client {
    let rocket = rocket::build().manage(harness.db.clone()).mount(
        "/",
        rocket::routes![probe_validated, probe_optional, probe_unvalidated],
    );
    Client::tracked(rocket).await.expect("probe rocket")
}

/// GET `path` with `ticket`, an optional session, and optionally a bot token.
async fn probe(
    client: &Client,
    path: &str,
    session: Option<&Session>,
    ticket: &MFATicket,
    bot_token: bool,
) -> (Status, String) {
    let mut request = client
        .get(path.to_string())
        .header(Header::new("x-mfa-ticket", ticket.token.clone()));
    if let Some(session) = session {
        request = request.header(Header::new("x-session-token", session.token.clone()));
    }
    if bot_token {
        request = request.header(Header::new("x-bot-token", "anything"));
    }

    let response = request.dispatch().await;
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

#[test]
fn guard_probe_refuses_a_foreign_session() {
    rt().block_on(guard_probe_refuses_a_foreign_session_case())
}

async fn guard_probe_refuses_a_foreign_session_case() {
    let harness = TestHarness::new().await;
    let (owner, owner_session, _) = harness.new_user().await;
    let (_, other_session, _) = harness.new_user().await;
    let ticket = saved_ticket(&harness, &owner.id, true).await;
    let client = probe_client(&harness).await;

    let (status, _) = probe(&client, "/validated", Some(&other_session), &ticket, false).await;
    assert_eq!(status, Status::Forbidden, "a ticket from another account");
    assert!(
        ticket_exists(&harness, &ticket).await,
        "a mismatch must not burn the ticket"
    );

    let (status, body) = probe(&client, "/validated", Some(&owner_session), &ticket, false).await;
    assert_eq!((status, body.as_str()), (Status::Ok, "ok"));
    assert!(
        !ticket_exists(&harness, &ticket).await,
        "a validated ticket is consumed on use"
    );
}

#[test]
fn guard_probe_needs_a_session() {
    rt().block_on(guard_probe_needs_a_session_case())
}

async fn guard_probe_needs_a_session_case() {
    let harness = TestHarness::new().await;
    let (owner, owner_session, _) = harness.new_user().await;
    let ticket = saved_ticket(&harness, &owner.id, true).await;
    let client = probe_client(&harness).await;

    // The session guard's own failure passes through
    let (status, _) = probe(&client, "/validated", None, &ticket, false).await;
    assert_eq!(status, Status::Unauthorized, "a ticket with no session");
    assert!(ticket_exists(&harness, &ticket).await);

    let (status, body) = probe(&client, "/validated", Some(&owner_session), &ticket, false).await;
    assert_eq!((status, body.as_str()), (Status::Ok, "ok"));
    assert!(!ticket_exists(&harness, &ticket).await);
}

#[test]
fn guard_probe_refuses_a_bot_token() {
    rt().block_on(guard_probe_refuses_a_bot_token_case())
}

/// The `User` guard prefers a bot token over the session, so a request that
/// carries one could act as the bot while the ticket matched the session.
async fn guard_probe_refuses_a_bot_token_case() {
    let harness = TestHarness::new().await;
    let (owner, owner_session, _) = harness.new_user().await;
    let ticket = saved_ticket(&harness, &owner.id, true).await;
    let client = probe_client(&harness).await;

    let (status, _) = probe(&client, "/validated", Some(&owner_session), &ticket, true).await;
    assert_eq!(status, Status::Forbidden, "a ticket next to a bot token");
    assert!(ticket_exists(&harness, &ticket).await);

    let (status, body) = probe(&client, "/validated", Some(&owner_session), &ticket, false).await;
    assert_eq!((status, body.as_str()), (Status::Ok, "ok"));
    assert!(!ticket_exists(&harness, &ticket).await);
}

#[test]
fn guard_probe_optional_is_none_for_a_foreign_ticket() {
    rt().block_on(guard_probe_optional_is_none_for_a_foreign_ticket_case())
}

async fn guard_probe_optional_is_none_for_a_foreign_ticket_case() {
    let harness = TestHarness::new().await;
    let (owner, owner_session, _) = harness.new_user().await;
    let (_, other_session, _) = harness.new_user().await;
    let ticket = saved_ticket(&harness, &owner.id, true).await;
    let client = probe_client(&harness).await;

    let (status, body) = probe(&client, "/optional", Some(&other_session), &ticket, false).await;
    assert_eq!((status, body.as_str()), (Status::Ok, "none"));
    assert!(ticket_exists(&harness, &ticket).await);

    let (status, body) = probe(&client, "/optional", Some(&owner_session), &ticket, false).await;
    assert_eq!((status, body.as_str()), (Status::Ok, "some"));
    assert!(!ticket_exists(&harness, &ticket).await);
}

#[test]
fn guard_probe_binds_an_unvalidated_ticket() {
    rt().block_on(guard_probe_binds_an_unvalidated_ticket_case())
}

async fn guard_probe_binds_an_unvalidated_ticket_case() {
    let harness = TestHarness::new().await;
    let (owner, owner_session, _) = harness.new_user().await;
    let (_, other_session, _) = harness.new_user().await;
    let ticket = saved_ticket(&harness, &owner.id, false).await;
    let client = probe_client(&harness).await;

    let (status, _) = probe(&client, "/unvalidated", None, &ticket, false).await;
    assert_eq!(
        status,
        Status::Unauthorized,
        "a login ticket with no session"
    );

    let (status, _) = probe(
        &client,
        "/unvalidated",
        Some(&other_session),
        &ticket,
        false,
    )
    .await;
    assert_eq!(
        status,
        Status::Forbidden,
        "a login ticket from another account"
    );

    let (status, body) = probe(
        &client,
        "/unvalidated",
        Some(&owner_session),
        &ticket,
        false,
    )
    .await;
    assert_eq!((status, body.as_str()), (Status::Ok, "ok"));
    // The unvalidated guard never consumes
    assert!(ticket_exists(&harness, &ticket).await);
}

// ========================================================================
// C. Textual contract: every ticket route has its test above
// ========================================================================

/// Test-only files: `tests.rs`, `test.rs`, `*_tests.rs`, and anything under
/// a `tests` directory. This file is one of them.
fn is_test_only(relative: &str) -> bool {
    let mut parts: Vec<&str> = relative.split('/').collect();
    let file = parts.pop().unwrap_or_default();
    file == "tests.rs"
        || file == "test.rs"
        || file.ends_with("_tests.rs")
        || parts.contains(&"tests")
}

/// The route files under `root`, relative and `/`-separated, whose code (not
/// their comments) names a ticket guard.
fn ticket_route_files(root: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];

    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("read {}: {}", dir.display(), error));
        for entry in entries {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }

            let relative = path
                .strip_prefix(root)
                .expect("under the routes directory")
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_only(&relative) {
                continue;
            }

            // Both names: `UnvalidatedTicket` does not contain `ValidatedTicket`
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {}", path.display(), error));
            if !source.contains("ValidatedTicket") && !source.contains("UnvalidatedTicket") {
                continue;
            }
            let code = without_comments(&source);
            if code.contains("ValidatedTicket") || code.contains("UnvalidatedTicket") {
                found.insert(relative);
            }
        }
    }

    found
}

#[test]
fn every_ticket_route_has_a_binding_test() {
    let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/routes"));
    let found = ticket_route_files(root);
    let listed: BTreeSet<String> = TICKET_ROUTES
        .iter()
        .map(|(file, _)| file.to_string())
        .collect();

    let unlisted: Vec<&String> = found.difference(&listed).collect();
    assert!(
        unlisted.is_empty(),
        "new ticket route: add a binding test, and its row in TICKET_ROUTES, for {:?}",
        unlisted
    );

    let stale: Vec<&String> = listed.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "{:?} no longer name a ticket guard: drop them from TICKET_ROUTES",
        stale
    );

    // Each row names a `#[test]` in this file
    let this_file = without_whitespace(&without_comments(include_str!("ticket_binding_tests.rs")));
    for (file, test) in TICKET_ROUTES {
        assert!(
            this_file.contains(&format!("#[test]fn{}()", test)),
            "{}: TICKET_ROUTES names `{}`, which is not a test in this file",
            file,
            test
        );
    }
}
