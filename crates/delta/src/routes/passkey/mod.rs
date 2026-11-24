use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod assert;
mod login;
mod manage;
mod recover;
mod register;
mod signup;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        register::register_start,
        register::register_finish,
        login::login_start,
        login::login_finish,
        assert::assert_start,
        manage::list,
        manage::rename,
        manage::remove,
        signup::signup_start,
        signup::signup_code,
        signup::signup_resend,
        signup::signup_options,
        signup::signup_finish,
        recover::recover_send,
        recover::recover_start,
        recover::recover_finish,
    ]
}

/// Shared by the passkey route tests, and open to the other route tests
/// (`crate::routes::passkey::fixtures`)
#[cfg(test)]
pub(crate) mod fixtures {
    use revolt_database::{Account, MFATicket, Passkey, Session};
    use rocket::http::{Header, Status};
    use rocket::local::asynchronous::LocalRequest;
    use serde_json::Value;
    use webauthn_rs::prelude::Uuid;

    use crate::util::passkey;
    use crate::util::test::TestHarness;

    /// What a stored credential holds in these tests. No response may carry it.
    pub const STORED_CREDENTIAL_MARKER: &str = "STORED-CREDENTIAL-MARKER";

    /// A harness with passkeys switched on. The switch is process-wide and
    /// can be set once, so a test that needs it off must not share a process
    /// with one that calls this (nextest runs one process per test).
    pub async fn harness_with_passkeys_on() -> TestHarness {
        revolt_config::overwrite_config(|settings| {
            settings.features.passkeys.available = true;
        })
        .await;

        let harness = TestHarness::new().await;
        passkey::assert_available()
            .await
            .expect("the control: passkeys are on");
        harness
    }

    /// The token of a validated ticket of `account`
    pub async fn ticket_for(harness: &TestHarness, account: &Account) -> String {
        let ticket = MFATicket::new(account.id.to_string(), true);
        ticket.save(&harness.db).await.unwrap();
        ticket.token
    }

    /// A user handle as the verifier stores it: a v4 UUID string. The
    /// verifier parses the handle of a stored row, so anything else is a 500.
    pub fn new_user_handle() -> String {
        Uuid::new_v4().to_string()
    }

    /// A stored passkey of `account`, written straight to the database. An
    /// account's passkeys share one handle, so a second row takes the first
    /// row's.
    pub async fn seed_passkey(harness: &TestHarness, account: &Account, name: &str) -> Passkey {
        let user_handle = harness
            .db
            .fetch_passkeys(&account.id)
            .await
            .unwrap()
            .first()
            .map(|row| row.user_handle.clone())
            .unwrap_or_else(new_user_handle);

        let passkey = Passkey::new(
            account.id.clone(),
            format!("credential-id-{}", TestHarness::rand_string()),
            user_handle,
            format!("{{\"key\":\"{}\"}}", STORED_CREDENTIAL_MARKER),
            name.to_string(),
        );
        harness.db.insert_passkey(&passkey).await.unwrap();
        passkey
    }

    /// Send `request` as `session`, with `ticket` as `X-MFA-Ticket` if given.
    /// The body comes back parsed, or `Null` when it is empty or not JSON.
    pub async fn send(
        request: LocalRequest<'_>,
        session: &Session,
        ticket: Option<&str>,
    ) -> (Status, Value) {
        let mut request = request.header(Header::new("X-Session-Token", session.token.clone()));

        if let Some(ticket) = ticket {
            request = request.header(Header::new("X-MFA-Ticket", ticket.to_string()));
        }

        let res = request.dispatch().await;
        let status = res.status();
        let body = res.into_string().await.unwrap_or_default();

        (status, serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    /// The `type` of an error body ("" if there is none)
    pub fn kind(body: &Value) -> &str {
        body["type"].as_str().unwrap_or("")
    }

    /// The `type` the passkey switch answers with while it is off
    pub async fn switched_off_kind() -> String {
        let off = passkey::assert_available()
            .await
            .expect_err("the control: passkeys are off in the test config");

        serde_json::to_value(&off.error_type).expect("an error type")["type"]
            .as_str()
            .expect("a tagged error type")
            .to_string()
    }

    /// The keys of a JSON object, sorted
    pub fn keys(value: &Value) -> Vec<&str> {
        let mut keys: Vec<&str> = value
            .as_object()
            .expect("a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
    }
}
