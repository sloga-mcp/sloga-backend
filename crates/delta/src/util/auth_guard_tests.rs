//! The rocket `Session` and `User` guards on a bare Rocket, with no route
//! logic behind them.
//!
//! These pin the 401/200 contract around the credential-lookup change: a
//! missing or unknown credential is 401, a valid one is 200, and a session
//! whose user doc does not exist yet passes `Session` but not `User`. Every
//! case here behaves the same before and after the guard rewrite, so this is
//! a regression pin, not proof of the fix. The DB-error (500) half is covered
//! by `revolt-database`'s `auth_error` unit tests, since the test drivers
//! cannot fail on demand.

use revolt_database::{Bot, Session, User};
use rocket::http::{Header, Status};
use rocket::local::asynchronous::Client;

use crate::util::test::TestHarness;

#[rocket::get("/session")]
fn probe_session(_s: Session) -> &'static str {
    "ok"
}

#[rocket::get("/user")]
fn probe_user(_u: User) -> &'static str {
    "ok"
}

async fn probe_client(harness: &TestHarness) -> Client {
    let rocket = rocket::build()
        .manage(harness.db.clone())
        .mount("/", rocket::routes![probe_session, probe_user]);
    Client::tracked(rocket).await.expect("probe rocket")
}

/// GET `path` with the given `(name, value)` headers.
async fn probe(client: &Client, path: &str, headers: &[(&str, &str)]) -> (Status, String) {
    let mut request = client.get(path.to_string());
    for (name, value) in headers {
        request = request.header(Header::new(name.to_string(), value.to_string()));
    }

    let response = request.dispatch().await;
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

/// A token in the same shape as a real one that matches nothing.
fn unknown_token() -> String {
    format!(
        "{}{}",
        TestHarness::rand_string(),
        TestHarness::rand_string()
    )
}

#[test]
fn auth_guard_unknown_session_token_is_401() {
    crate::util::test::rt().block_on(auth_guard_unknown_session_token_is_401_case())
}

async fn auth_guard_unknown_session_token_is_401_case() {
    let harness = TestHarness::new().await;
    let client = probe_client(&harness).await;
    let token = unknown_token();

    let (status, _) = probe(&client, "/session", &[("x-session-token", token.as_str())]).await;
    assert_eq!(
        status,
        Status::Unauthorized,
        "unknown session token, Session"
    );

    let (status, _) = probe(&client, "/user", &[("x-session-token", token.as_str())]).await;
    assert_eq!(status, Status::Unauthorized, "unknown session token, User");
}

#[test]
fn auth_guard_unknown_bot_token_is_401() {
    crate::util::test::rt().block_on(auth_guard_unknown_bot_token_is_401_case())
}

async fn auth_guard_unknown_bot_token_is_401_case() {
    let harness = TestHarness::new().await;
    let client = probe_client(&harness).await;
    let token = unknown_token();

    let (status, _) = probe(&client, "/user", &[("x-bot-token", token.as_str())]).await;
    assert_eq!(status, Status::Unauthorized, "unknown bot token, User");
}

#[test]
fn auth_guard_no_header_is_401() {
    crate::util::test::rt().block_on(auth_guard_no_header_is_401_case())
}

async fn auth_guard_no_header_is_401_case() {
    let harness = TestHarness::new().await;
    let client = probe_client(&harness).await;

    // `MissingHeaders`, carried with a 401 status
    let (status, _) = probe(&client, "/session", &[]).await;
    assert_eq!(status, Status::Unauthorized, "no header, Session");

    let (status, _) = probe(&client, "/user", &[]).await;
    assert_eq!(status, Status::Unauthorized, "no header, User");
}

#[test]
fn auth_guard_valid_session_is_200() {
    crate::util::test::rt().block_on(auth_guard_valid_session_is_200_case())
}

async fn auth_guard_valid_session_is_200_case() {
    let harness = TestHarness::new().await;
    let (_, session, _) = harness.new_user().await;
    let client = probe_client(&harness).await;
    let headers = [("x-session-token", session.token.as_str())];

    let (status, body) = probe(&client, "/session", &headers).await;
    assert_eq!((status, body.as_str()), (Status::Ok, "ok"), "Session");

    let (status, body) = probe(&client, "/user", &headers).await;
    assert_eq!((status, body.as_str()), (Status::Ok, "ok"), "User");
}

#[test]
fn auth_guard_session_without_user_passes_session_only() {
    crate::util::test::rt().block_on(auth_guard_session_without_user_passes_session_only_case())
}

/// An account and session with no user doc yet, as right after signup.
async fn auth_guard_session_without_user_passes_session_only_case() {
    let harness = TestHarness::new().await;
    let id = ulid::Ulid::new().to_string();
    let (_, session) = harness.account_from_user(id).await;
    let client = probe_client(&harness).await;
    let headers = [("x-session-token", session.token.as_str())];

    let (status, body) = probe(&client, "/session", &headers).await;
    assert_eq!(
        (status, body.as_str()),
        (Status::Ok, "ok"),
        "a session with no user is still a session"
    );

    let (status, _) = probe(&client, "/user", &headers).await;
    assert_eq!(
        status,
        Status::Unauthorized,
        "a session with no user doc, User"
    );
}

#[test]
fn auth_guard_valid_bot_token_is_200() {
    crate::util::test::rt().block_on(auth_guard_valid_bot_token_is_200_case())
}

async fn auth_guard_valid_bot_token_is_200_case() {
    let harness = TestHarness::new().await;
    let (_, _, owner) = harness.new_user().await;
    let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
        .await
        .expect("`Bot`");
    let client = probe_client(&harness).await;

    let (status, body) = probe(&client, "/user", &[("x-bot-token", bot.token.as_str())]).await;
    assert_eq!(
        (status, body.as_str()),
        (Status::Ok, "ok"),
        "bot token, User"
    );
}
