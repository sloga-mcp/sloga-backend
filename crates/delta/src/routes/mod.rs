use revolt_config::Settings;
use revolt_rocket_okapi::{revolt_okapi::openapi3::OpenApi, settings::OpenApiSettings};
pub use rocket::http::Status;
pub use rocket::response::Redirect;
use rocket::{Build, Rocket};

mod admin;
mod bots;
mod channels;
mod discover;
mod customisation;
mod e2ee;
mod events;
mod gifs;
mod interactions;
mod invites;
mod kofi;
mod lookup;
pub(crate) mod mls;
mod onboard;
mod payments;
mod policy;
mod prot;
mod push;
mod referrals;
mod root;
mod safety;
mod servers;
mod softres;
mod sync;
mod takedown;
mod users;
mod webhooks;
mod account;
mod session;
mod mfa;
mod passkey;
mod oauth;
mod import;
#[cfg(test)]
mod e2ee_only_scan_tests;

pub fn mount(config: Settings, mut rocket: Rocket<Build>) -> Rocket<Build> {
    let settings = OpenApiSettings::default();

    if config.features.webhooks_enabled {
        mount_endpoints_and_merged_docs! {
            rocket, "/".to_owned(), settings,
            "/" => (vec![], custom_openapi_spec()),
            "" => openapi_get_routes_spec![root::root],
            "/users" => users::routes(),
            "/bots" => bots::routes(),
            "/channels" => channels::routes(),
            "/servers" => servers::routes(),
            "/invites" => invites::routes(),
            "/discover" => discover::routes(),
            "/interactions" => interactions::routes(),
            "/custom" => customisation::routes(),
            "/safety" => safety::routes(),
            "/takedown" => takedown::routes(),
            "/e2ee" => e2ee::routes(),
            "/mls" => mls::routes(),
            "/events" => events::routes(),
            "/gifs" => gifs::routes(),
            "/lookup" => lookup::routes(),
            "/import" => import::routes(),
            "/softres" => softres::routes(),
            "/auth/account" => account::routes(),
            "/auth/session" => session::routes(),
            "/auth/oauth" => oauth::routes(),
            "/auth/mfa" => mfa::routes(),
            "/auth/passkey" => passkey::routes(),
            "/onboard" => onboard::routes(),
            "/policy" => policy::routes(),
            "/push" => push::routes(),
            "/referrals" => referrals::routes(),
            "/kofi" => kofi::routes(),
            "/payments" => payments::routes(),
            "/prot" => prot::routes(),
            "/admin" => admin::routes(),
            "/sync" => sync::routes(),
            "/webhooks" => webhooks::routes()
        };
    } else {
        mount_endpoints_and_merged_docs! {
            rocket, "/".to_owned(), settings,
            "/" => (vec![], custom_openapi_spec()),
            "" => openapi_get_routes_spec![root::root],
            "/users" => users::routes(),
            "/bots" => bots::routes(),
            "/channels" => channels::routes(),
            "/servers" => servers::routes(),
            "/invites" => invites::routes(),
            "/discover" => discover::routes(),
            "/interactions" => interactions::routes(),
            "/custom" => customisation::routes(),
            "/safety" => safety::routes(),
            "/takedown" => takedown::routes(),
            "/e2ee" => e2ee::routes(),
            "/mls" => mls::routes(),
            "/events" => events::routes(),
            "/gifs" => gifs::routes(),
            "/lookup" => lookup::routes(),
            "/import" => import::routes(),
            "/softres" => softres::routes(),
            "/auth/account" => account::routes(),
            "/auth/session" => session::routes(),
            "/auth/oauth" => oauth::routes(),
            "/auth/mfa" => mfa::routes(),
            "/auth/passkey" => passkey::routes(),
            "/onboard" => onboard::routes(),
            "/policy" => policy::routes(),
            "/push" => push::routes(),
            "/referrals" => referrals::routes(),
            "/kofi" => kofi::routes(),
            "/payments" => payments::routes(),
            "/prot" => prot::routes(),
            "/admin" => admin::routes(),
            "/sync" => sync::routes()
        };
    }

    rocket
}

fn custom_openapi_spec() -> OpenApi {
    use revolt_rocket_okapi::revolt_okapi::openapi3::*;

    let mut extensions = schemars::Map::new();
    extensions.insert(
        "x-logo".to_owned(),
        json!({
            "url": "https://stoat.chat/header.png",
            "altText": "Acutest Header"
        }),
    );

    extensions.insert(
        "x-tagGroups".to_owned(),
        json!([
          {
            "name": "Acutest",
            "tags": [
              "Core"
            ]
          },
          {
            "name": "Users",
            "tags": [
              "User Information",
              "Direct Messaging",
              "Relationships"
            ]
          },
          {
            "name": "Bots",
            "tags": [
              "Bots"
            ]
          },
          {
            "name": "Channels",
            "tags": [
              "Channel Information",
              "Channel Invites",
              "Channel Permissions",
              "Messaging",
              "Interactions",
              "Groups",
              "Voice",
              "Webhooks",
            ]
          },
          {
            "name": "Servers",
            "tags": [
              "Server Information",
              "Server Members",
              "Server Permissions",
              "Audit Log",
              "Calendar"
            ]
          },
          {
            "name": "Invites",
            "tags": [
              "Invites"
            ]
          },
          {
            "name": "Discovery",
            "tags": [
              "Discovery"
            ]
          },
          {
            "name": "Customisation",
            "tags": [
              "Emojis"
            ]
          },
          {
            "name": "Platform Administration",
            "tags": [
              "Admin",
              "User Safety"
            ]
          },
          {
            "name": "Authentication",
            "tags": [
              "Account",
              "Session",
              "Onboarding",
              "MFA",
              "Passkey"
            ]
          },
          {
            "name": "E2EE",
            "tags": [
              "E2EE",
              "MLS"
            ]
          },
          {
            "name": "Miscellaneous",
            "tags": [
              "Sync",
              "Web Push",
              "Soft Reserves",
              "Game Lookup",
              "Payments"
            ]
          }
        ]),
    );

    OpenApi {
        openapi: OpenApi::default_version(),
        info: Info {
            title: "Acutest API".to_owned(),
            description: Some("Open source user-first chat platform.".to_owned()),
            terms_of_service: Some("https://stoat.chat/terms".to_owned()),
            contact: Some(Contact {
                name: Some("Acutest".to_owned()),
                url: Some("https://stoat.chat".to_owned()),
                email: Some("contact@stoat.chat".to_owned()),
                ..Default::default()
            }),
            license: Some(License {
                name: "AGPLv3".to_owned(),
                url: Some(
                    "https://github.com/stoatchat/stoatchat/blob/main/crates/delta/LICENSE"
                        .to_owned(),
                ),
                ..Default::default()
            }),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ..Default::default()
        },
        servers: vec![
            Server {
                url: "https://api.stoat.chat".to_owned(),
                description: Some("Acutest Production".to_owned()),
                ..Default::default()
            },
            Server {
                url: "https://beta.stoat.chat/api".to_owned(),
                description: Some("Acutest Beta".to_owned()),
                ..Default::default()
            },
        ],
        external_docs: Some(ExternalDocs {
            url: "https://developers.stoat.chat".to_owned(),
            description: Some("Acutest Developer Documentation".to_owned()),
            ..Default::default()
        }),
        extensions,
        tags: vec![
            Tag {
                name: "Core".to_owned(),
                description: Some(
                    "Use in your applications to determine information about the Acutest node"
                        .to_owned(),
                ),
                ..Default::default()
            },
            Tag {
                name: "User Information".to_owned(),
                description: Some("Query and fetch users on Acutest".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Direct Messaging".to_owned(),
                description: Some("Direct message other users on Acutest".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Relationships".to_owned(),
                description: Some(
                    "Manage your friendships and block list on the platform".to_owned(),
                ),
                ..Default::default()
            },
            Tag {
                name: "Bots".to_owned(),
                description: Some("Create and edit bots".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Channel Information".to_owned(),
                description: Some("Query and fetch channels on Acutest".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Channel Invites".to_owned(),
                description: Some("Create and manage invites for channels".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Channel Permissions".to_owned(),
                description: Some("Manage permissions for channels".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Messaging".to_owned(),
                description: Some("Send and manipulate messages".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Groups".to_owned(),
                description: Some("Create, invite users and manipulate groups".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Voice".to_owned(),
                description: Some("Join and talk with other users".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Server Information".to_owned(),
                description: Some("Query and fetch servers on Acutest".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Server Members".to_owned(),
                description: Some("Find and edit server members".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Server Permissions".to_owned(),
                description: Some("Manage permissions for servers".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Audit Log".to_owned(),
                description: Some("Review moderation and configuration actions".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Invites".to_owned(),
                description: Some("View, join and delete invites".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Discovery".to_owned(),
                description: Some(
                    "Public server directory: browse and join discoverable servers".to_owned(),
                ),
                ..Default::default()
            },
            Tag {
                name: "Account".to_owned(),
                description: Some("Manage your account".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Session".to_owned(),
                description: Some("Create and manage sessions".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "MFA".to_owned(),
                description: Some("Multi-factor Authentication".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Passkey".to_owned(),
                description: Some("Sign in with a passkey and manage passkeys".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Onboarding".to_owned(),
                description: Some(
                    "After signing up to Acutest, users must pick a unique username".to_owned(),
                ),
                ..Default::default()
            },
            Tag {
                name: "Sync".to_owned(),
                description: Some("Upload and retrieve any JSON data between clients".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "Web Push".to_owned(),
                description: Some(
                    "Subscribe to and receive Acutest push notifications while offline".to_owned(),
                ),
                ..Default::default()
            },
            Tag {
                name: "Webhooks".to_owned(),
                description: Some("Send messages from 3rd party services".to_owned()),
                ..Default::default()
            },
            Tag {
                name: "E2EE".to_owned(),
                description: Some(
                    "Key directory and encrypted-envelope relay for end-to-end encrypted DMs"
                        .to_owned(),
                ),
                ..Default::default()
            },
            Tag {
                name: "MLS".to_owned(),
                description: Some(
                    "MLS delivery service + KeyPackage directory for media E2EE (calls)"
                        .to_owned(),
                ),
                ..Default::default()
            },
            Tag {
                name: "Calendar".to_owned(),
                description: Some(
                    "Server calendar events, recurrence, and RSVP invitations".to_owned(),
                ),
                ..Default::default()
            },
            Tag {
                name: "Soft Reserves".to_owned(),
                description: Some(
                    "Static raid loot catalog for soft-reserve sheets".to_owned(),
                ),
                ..Default::default()
            },
            Tag {
                name: "Game Lookup".to_owned(),
                description: Some(
                    "Search Steam games, World of Warcraft items and League of Legends champions"
                        .to_owned(),
                ),
                ..Default::default()
            },
            Tag {
                name: "Payments".to_owned(),
                description: Some("Cipher founding sale checkout and status".to_owned()),
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

#[cfg(test)]
mod passkey_mount_tests {
    //! `/auth/passkey` is mounted in both mount lists, and every route under
    //! it is reachable. The switch is process-wide and set once, so the "on"
    //! and "off" tests each need their own process (nextest).
    use revolt_database::{Account, MFATicket, Passkey, Session};
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::LocalRequest;
    use serde_json::Value;

    use crate::util::passkey;
    use crate::util::test::{rt, TestHarness};

    /// Every passkey route: method and path as Rocket holds them
    const PASSKEY_ROUTES: &[(&str, &str)] = &[
        ("POST", "/auth/passkey/register/start"),
        ("POST", "/auth/passkey/register/finish"),
        ("POST", "/auth/passkey/login/start"),
        ("POST", "/auth/passkey/login/finish"),
        ("POST", "/auth/passkey/assert/start"),
        ("GET", "/auth/passkey"),
        ("PATCH", "/auth/passkey/<id>"),
        ("DELETE", "/auth/passkey/<id>"),
        ("POST", "/auth/passkey/signup/start"),
        ("POST", "/auth/passkey/signup/code"),
        ("POST", "/auth/passkey/signup/resend"),
        ("POST", "/auth/passkey/signup/options"),
        ("POST", "/auth/passkey/signup/finish"),
        ("POST", "/auth/passkey/recover/send"),
        ("POST", "/auth/passkey/recover/start"),
        ("POST", "/auth/passkey/recover/finish"),
    ];

    /// The passkey routes that live under `/auth/account`
    const PASSKEY_ACCOUNT_ROUTES: &[(&str, &str)] = &[
        ("POST", "/auth/account/email/add/start"),
        ("POST", "/auth/account/email/add/finish"),
    ];

    /// A route path without doubled or trailing slashes
    fn tidy(path: &str) -> String {
        path.split('/')
            .filter(|part| !part.is_empty())
            .map(|part| format!("/{part}"))
            .collect()
    }

    /// The routes `mount` registers for one state of the webhooks switch,
    /// which is what picks between the two mount lists
    fn mounted(webhooks_enabled: bool) -> Vec<(String, String)> {
        let mut config = rt().block_on(revolt_config::config());
        config.features.webhooks_enabled = webhooks_enabled;

        super::mount(config, rocket::build())
            .routes()
            .map(|route| (route.method.as_str().to_string(), tidy(&route.uri.to_string())))
            .collect()
    }

    /// Fails if: `"/auth/passkey" => passkey::routes()` is dropped from
    /// either mount list, or a route leaves `passkey::routes()`.
    #[test]
    fn both_mount_lists_carry_every_passkey_route() {
        let with_webhooks = mounted(true);
        let without_webhooks = mounted(false);

        // The control: the two calls really took different lists, and the
        // comparison below matches paths the way Rocket writes them
        assert!(with_webhooks.iter().any(|(_, path)| path.starts_with("/webhooks")));
        assert!(!without_webhooks.iter().any(|(_, path)| path.starts_with("/webhooks")));

        for (label, routes) in [
            ("with webhooks", &with_webhooks),
            ("without webhooks", &without_webhooks),
        ] {
            let has = |method: &str, path: &str| {
                routes
                    .iter()
                    .any(|(m, p)| m.as_str() == method && p.as_str() == path)
            };

            assert!(has("PUT", "/auth/mfa/ticket"), "{label}: the control route");
            for (method, path) in PASSKEY_ROUTES.iter().chain(PASSKEY_ACCOUNT_ROUTES) {
                assert!(has(method, path), "{label}: {method} {path} is not mounted");
            }

            let under_passkey = routes
                .iter()
                .filter(|(_, path)| path == "/auth/passkey" || path.starts_with("/auth/passkey/"))
                .count();
            assert_eq!(
                under_passkey,
                PASSKEY_ROUTES.len(),
                "{label}: a passkey route this table does not list"
            );
        }
    }

    fn as_session<'c>(request: LocalRequest<'c>, session: &Session) -> LocalRequest<'c> {
        request.header(Header::new("X-Session-Token", session.token.clone()))
    }

    fn json_body<'c>(request: LocalRequest<'c>, body: Value) -> LocalRequest<'c> {
        request.header(ContentType::JSON).body(body.to_string())
    }

    async fn answer(request: LocalRequest<'_>) -> (Status, Value) {
        let response = request.dispatch().await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        (status, serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    /// Call each passkey route once, as `session`, with what its guards
    /// need: a stored passkey to name and, for the removal, a validated
    /// ticket. The removal goes last.
    async fn call_each(
        harness: &TestHarness,
        account: &Account,
        session: &Session,
    ) -> Vec<(&'static str, Status, Value)> {
        // The handle is a v4 UUID, as the verifier stores it: register/start
        // parses it, and anything else is a 500. The credential is not one
        // the verifier can read, which assert/start answers as "no passkey".
        let stored = Passkey::new(
            account.id.clone(),
            format!("credential-{}", TestHarness::rand_string()),
            webauthn_rs::prelude::Uuid::new_v4().to_string(),
            "{}".to_string(),
            "Phone".to_string(),
        );
        harness.db.insert_passkey(&stored).await.unwrap();

        let ticket = MFATicket::new(account.id.clone(), true);
        ticket.save(&harness.db).await.unwrap();

        let client = &harness.client;
        let one = format!("/auth/passkey/{}", stored.id);
        let junk = || json!({ "challenge_id": "no-such-challenge", "credential": {} });

        let mut answers = Vec::new();
        for (label, request) in [
            (
                "POST register/start",
                as_session(client.post("/auth/passkey/register/start"), session),
            ),
            (
                "POST register/finish",
                json_body(
                    as_session(client.post("/auth/passkey/register/finish"), session),
                    junk(),
                ),
            ),
            ("POST login/start", client.post("/auth/passkey/login/start")),
            (
                "POST login/finish",
                json_body(client.post("/auth/passkey/login/finish"), junk()),
            ),
            (
                "POST assert/start",
                as_session(client.post("/auth/passkey/assert/start"), session),
            ),
            ("GET list", as_session(client.get("/auth/passkey"), session)),
            (
                "PATCH rename",
                json_body(
                    as_session(client.patch(one.clone()), session),
                    json!({ "name": "Renamed" }),
                ),
            ),
            (
                "DELETE remove",
                as_session(client.delete(one.clone()), session)
                    .header(Header::new("X-MFA-Ticket", ticket.token.clone())),
            ),
        ] {
            let (status, body) = answer(request).await;
            answers.push((label, status, body));
        }

        answers
    }

    /// Call each sign-up, recovery and add-an-email route once, with a
    /// body its guard can parse and nothing any of them would accept. The
    /// first eight carry no session; the last two are sent as `session`,
    /// each with a validated ticket of its own.
    async fn call_each_step2(
        harness: &TestHarness,
        account: &Account,
        session: &Session,
    ) -> Vec<(&'static str, Status, Value)> {
        let client = &harness.client;
        let id = "0".repeat(64);
        // 32 bytes of unpadded base64url: the shape of a recovery token
        let token = "A".repeat(43);

        let mut requests = vec![
            (
                "POST signup/start",
                json_body(
                    client.post("/auth/passkey/signup/start"),
                    json!({
                        "username": TestHarness::rand_string(),
                        "email": "nobody@example.com"
                    }),
                ),
            ),
            (
                "POST signup/code",
                json_body(
                    client.post("/auth/passkey/signup/code"),
                    json!({ "signup_id": id, "code": "00000000" }),
                ),
            ),
            (
                "POST signup/resend",
                json_body(
                    client.post("/auth/passkey/signup/resend"),
                    json!({ "signup_id": id }),
                ),
            ),
            (
                "POST signup/options",
                json_body(
                    client.post("/auth/passkey/signup/options"),
                    json!({ "signup_id": id }),
                ),
            ),
            (
                "POST signup/finish",
                json_body(
                    client.post("/auth/passkey/signup/finish"),
                    json!({ "challenge_id": id, "credential": {} }),
                ),
            ),
            (
                "POST recover/send",
                json_body(
                    client.post("/auth/passkey/recover/send"),
                    json!({ "email": "nobody@example.com" }),
                ),
            ),
            (
                "POST recover/start",
                json_body(
                    client.post("/auth/passkey/recover/start"),
                    json!({ "token": token }),
                ),
            ),
            (
                "POST recover/finish",
                json_body(
                    client.post("/auth/passkey/recover/finish"),
                    json!({ "token": token, "challenge_id": id, "credential": {} }),
                ),
            ),
        ];

        for (label, path, body) in [
            (
                "POST email/add/start",
                "/auth/account/email/add/start",
                json!({ "email": "nobody@example.com" }),
            ),
            (
                "POST email/add/finish",
                "/auth/account/email/add/finish",
                json!({ "code": "00000000" }),
            ),
        ] {
            let ticket = MFATicket::new(account.id.clone(), true);
            ticket.save(&harness.db).await.unwrap();

            requests.push((
                label,
                json_body(as_session(client.post(path), session), body)
                    .header(Header::new("X-MFA-Ticket", ticket.token.clone())),
            ));
        }

        let mut answers = Vec::new();
        for (label, request) in requests {
            let (status, body) = answer(request).await;
            answers.push((label, status, body));
        }

        answers
    }

    /// Whether a route answered, as opposed to Rocket finding none. A route's
    /// own NotFound carries an error `type`; Rocket's 404 does not.
    fn reached_a_route(status: Status, body: &Value) -> bool {
        status != Status::NotFound || body["type"].is_string()
    }

    /// The `type` of an error body ("" if there is none)
    fn kind(body: &Value) -> &str {
        body["type"].as_str().unwrap_or("")
    }

    /// A harness with passkeys switched on and a valid relying party. The
    /// switch is process-wide and set once, before the harness.
    async fn harness_with_passkeys_on() -> TestHarness {
        revolt_config::overwrite_config(|settings| {
            let passkeys = &mut settings.features.passkeys;
            passkeys.available = true;
            passkeys.rp_id = "app.sloga.gg".to_string();
            passkeys.origins = vec!["https://app.sloga.gg".to_string()];
        })
        .await;

        let harness = TestHarness::new().await;
        passkey::assert_available()
            .await
            .expect("the control: passkeys are on");
        harness
    }

    /// What each call of `call_each` answers with passkeys on: the status
    /// and the error `type` ("" for a success). The account has a password
    /// and the one seeded passkey; the session is its own.
    const SWITCHED_ON: &[(&str, u16, &str)] = &[
        ("POST register/start", 200, ""),
        // No ticket, and not a first passkey: refused before the verifier
        ("POST register/finish", 403, "NotPrivileged"),
        ("POST login/start", 200, ""),
        // An unknown challenge is an assertion that did not verify
        ("POST login/finish", 401, "InvalidCredentials"),
        // The seeded credential is unreadable, so there is none to ask for
        ("POST assert/start", 400, "InvalidOperation"),
        ("GET list", 200, ""),
        ("PATCH rename", 200, ""),
        ("DELETE remove", 204, ""),
    ];

    #[test]
    fn every_passkey_route_answers_with_the_switch_on() {
        rt().block_on(every_passkey_route_answers_with_the_switch_on_case())
    }

    /// Fails if: the harness's mount list loses `/auth/passkey`, or a route
    /// answers anything but its pinned status and error type (a 500
    /// included).
    async fn every_passkey_route_answers_with_the_switch_on_case() {
        let harness = harness_with_passkeys_on().await;
        let (account, session, _) = harness.new_user().await;

        // The control: a path nothing is mounted on is told apart
        let (status, body) = answer(as_session(
            harness.client.post("/auth/passkey/no/such/route"),
            &session,
        ))
        .await;
        assert!(!reached_a_route(status, &body), "{status} {body}");

        let answers = call_each(&harness, &account, &session).await;
        assert_eq!(answers.len(), 8);
        for (label, status, body) in &answers {
            assert!(reached_a_route(*status, body), "{label}: {status} {body}");
            assert_ne!(
                body["type"], "FeatureDisabled",
                "{label}: refused as switched off"
            );
        }

        // Each one answers exactly what its route says for this request
        assert_eq!(SWITCHED_ON.len(), answers.len());
        for ((label, status, body), (expected_label, expected_status, expected_kind)) in
            answers.iter().zip(SWITCHED_ON)
        {
            assert_eq!(label, expected_label, "the table follows `call_each`");
            assert_eq!(status.code, *expected_status, "{label}: {body}");
            assert_eq!(kind(body), *expected_kind, "{label}: {status} {body}");
        }

        // And the two that change something did: renamed, then removed
        let renamed = answers
            .iter()
            .find(|(label, _, _)| *label == "PATCH rename")
            .expect("a listed call");
        assert_eq!(renamed.2["name"], "Renamed");
        assert_eq!(harness.db.count_passkeys(&account.id).await.unwrap(), 0);
    }

    /// `request` with `token` as its session token, if one is given
    fn with_token<'c>(request: LocalRequest<'c>, token: Option<&str>) -> LocalRequest<'c> {
        match token {
            Some(token) => request.header(Header::new("X-Session-Token", token.to_string())),
            None => request,
        }
    }

    #[test]
    fn passkey_routes_refuse_a_missing_or_unknown_session() {
        rt().block_on(passkey_routes_refuse_a_missing_or_unknown_session_case())
    }

    /// The six routes that need a session, with none and with a token that
    /// matches nothing: 401 from the session guard, before any route code.
    /// Rocket answers a guard failure itself, so the body carries no error
    /// `type`.
    ///
    /// Fails if: a passkey route loses its `Account` guard, or answers a
    /// request with no session from its own code (a 500 included).
    async fn passkey_routes_refuse_a_missing_or_unknown_session_case() {
        let harness = harness_with_passkeys_on().await;
        let (account, _, _) = harness.new_user().await;

        let stored = Passkey::new(
            account.id.clone(),
            format!("credential-{}", TestHarness::rand_string()),
            webauthn_rs::prelude::Uuid::new_v4().to_string(),
            "{}".to_string(),
            "Phone".to_string(),
        );
        harness.db.insert_passkey(&stored).await.unwrap();
        let ticket = MFATicket::new(account.id.clone(), true);
        ticket.save(&harness.db).await.unwrap();

        let client = &harness.client;
        let one = format!("/auth/passkey/{}", stored.id);

        for token in [None, Some("not a session")] {
            for (label, request) in [
                (
                    "POST register/start",
                    client.post("/auth/passkey/register/start"),
                ),
                (
                    "POST register/finish",
                    json_body(
                        client.post("/auth/passkey/register/finish"),
                        json!({ "challenge_id": "no-such-challenge", "credential": {} }),
                    ),
                ),
                (
                    "POST assert/start",
                    client.post("/auth/passkey/assert/start"),
                ),
                ("GET list", client.get("/auth/passkey")),
                (
                    "PATCH rename",
                    json_body(client.patch(one.clone()), json!({ "name": "Renamed" })),
                ),
                (
                    // A validated ticket of the account, so the session is
                    // all that is missing
                    "DELETE remove",
                    client
                        .delete(one.clone())
                        .header(Header::new("X-MFA-Ticket", ticket.token.clone())),
                ),
            ] {
                let (status, body) = answer(with_token(request, token)).await;
                assert_eq!(
                    status,
                    Status::Unauthorized,
                    "{label}, token {token:?}: {body}"
                );
                assert_eq!(kind(&body), "", "{label}, token {token:?}: {body}");
            }
        }

        // Nothing moved: the passkey is still there under its old name
        let rows = harness.db.fetch_passkeys(&account.id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "Phone");
    }

    #[test]
    fn every_passkey_route_is_refused_with_the_switch_off() {
        rt().block_on(every_passkey_route_is_refused_with_the_switch_off_case())
    }

    /// Both switches off, as shipped.
    ///
    /// Fails if: a Step 1 passkey route stops asking `assert_available`
    /// first, a sign-up, recovery or add-an-email route asks neither switch
    /// (each of their two gates is pinned by itself further down), or the
    /// harness's mount list loses `/auth/passkey` (Rocket's 404 carries no
    /// error type).
    async fn every_passkey_route_is_refused_with_the_switch_off_case() {
        let harness = TestHarness::new().await;
        let off = passkey::assert_available()
            .await
            .expect_err("the control: passkeys are off in the test config");
        let off = serde_json::to_value(&off.error_type).expect("an error type")["type"].clone();
        assert!(off.is_string());

        let (account, session, _) = harness.new_user().await;

        let mut answers = call_each(&harness, &account, &session).await;
        answers.extend(call_each_step2(&harness, &account, &session).await);
        assert_eq!(
            answers.len(),
            PASSKEY_ROUTES.len() + PASSKEY_ACCOUNT_ROUTES.len()
        );
        for (label, status, body) in &answers {
            assert!(reached_a_route(*status, body), "{label}: {status} {body}");
            assert_eq!(
                *status,
                Status::BadRequest,
                "{label}: answered {status} with passkeys off"
            );
            assert_eq!(body["type"], off, "{label}: {status} {body}");
        }

        // Nothing moved: the passkey is still there under its old name
        let stored = harness.db.fetch_passkeys(&account.id).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].name, "Phone");
    }

    /// The sign-up, recovery and add-an-email routes need two switches:
    /// passkeys (`available`) and passkey sign-up (`signup`). With both off,
    /// as in the test above, either gate alone refuses, so a route that lost
    /// one of them would still pass there. Each of the two tests below
    /// leaves exactly one switch off.
    ///
    /// Sets the two switches (process-wide, once, before the harness), calls
    /// every one of those routes, and checks each is refused the way the
    /// gate of the switch that is off refuses, which names `feature`.
    async fn assert_step2_routes_refuse(available: bool, signup: bool, feature: &str) {
        use crate::util::passkey_signup::assert_signup_on;

        revolt_config::overwrite_config(move |settings| {
            let passkeys = &mut settings.features.passkeys;
            passkeys.available = available;
            passkeys.signup = signup;
            passkeys.rp_id = "app.sloga.gg".to_string();
            passkeys.origins = vec!["https://app.sloga.gg".to_string()];
        })
        .await;

        let harness = TestHarness::new().await;

        // The control: the switches are as asked, so only one gate refuses
        assert_eq!(
            passkey::assert_available().await.is_ok(),
            available,
            "the control: `available`"
        );
        assert_eq!(
            assert_signup_on().await.is_ok(),
            signup,
            "the control: `signup`"
        );
        assert_ne!(available, signup, "the control: exactly one switch is off");

        // What the one gate that is shut answers
        let refusal = match available {
            true => assert_signup_on().await,
            false => passkey::assert_available().await,
        };
        let refusal = refusal.expect_err("the control: the gate under test refuses");
        let refusal = serde_json::to_value(&refusal.error_type).expect("an error type");
        assert_eq!(refusal["type"], "FeatureDisabled");
        assert_eq!(refusal["feature"], feature, "the control: which gate");

        let (account, session, _) = harness.new_user().await;

        let answers = call_each_step2(&harness, &account, &session).await;
        assert_eq!(answers.len(), 10);
        for (label, status, body) in &answers {
            assert!(reached_a_route(*status, body), "{label}: {status} {body}");
            assert_eq!(
                *status,
                Status::BadRequest,
                "{label}: answered {status} with `{feature}` off"
            );
            assert_eq!(body["type"], refusal["type"], "{label}: {status} {body}");
            assert_eq!(
                body["feature"], refusal["feature"],
                "{label}: {status} {body}"
            );
        }
    }

    #[test]
    fn signup_recovery_and_add_email_are_refused_with_only_signup_off() {
        rt().block_on(signup_recovery_and_add_email_are_refused_with_only_signup_off_case())
    }

    /// Passkeys on, passkey sign-up off (as Step 1 shipped).
    ///
    /// Fails if: a sign-up, recovery or add-an-email route stops asking
    /// `passkey_signup::assert_signup_on` (with passkeys themselves on, the
    /// route would go ahead), asks it after something else that answers
    /// first, or answers that refusal with another error.
    async fn signup_recovery_and_add_email_are_refused_with_only_signup_off_case() {
        assert_step2_routes_refuse(true, false, "passkey_signup").await
    }

    #[test]
    fn signup_recovery_and_add_email_are_refused_with_only_passkeys_off() {
        rt().block_on(signup_recovery_and_add_email_are_refused_with_only_passkeys_off_case())
    }

    /// Passkey sign-up on, passkeys themselves off.
    ///
    /// Fails if: a sign-up, recovery or add-an-email route stops asking
    /// `passkey::assert_available` (with passkey sign-up on, the route
    /// would go ahead), asks it after something else that answers first,
    /// or answers that refusal with another error.
    async fn signup_recovery_and_add_email_are_refused_with_only_passkeys_off_case() {
        assert_step2_routes_refuse(false, true, "passkeys").await
    }
}
