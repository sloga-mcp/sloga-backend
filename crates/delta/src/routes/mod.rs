use revolt_config::Settings;
use revolt_rocket_okapi::{revolt_okapi::openapi3::OpenApi, settings::OpenApiSettings};
pub use rocket::http::Status;
pub use rocket::response::Redirect;
use rocket::{Build, Rocket};

mod bots;
mod channels;
mod customisation;
mod e2ee;
mod events;
mod interactions;
mod invites;
mod mls;
mod onboard;
mod policy;
mod push;
mod root;
mod safety;
mod servers;
mod sync;
mod users;
mod webhooks;
mod account;
mod session;
mod mfa;
mod oauth;

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
            "/interactions" => interactions::routes(),
            "/custom" => customisation::routes(),
            "/safety" => safety::routes(),
            "/e2ee" => e2ee::routes(),
            "/mls" => mls::routes(),
            "/events" => events::routes(),
            "/auth/account" => account::routes(),
            "/auth/session" => session::routes(),
            "/auth/oauth" => oauth::routes(),
            "/auth/mfa" => mfa::routes(),
            "/onboard" => onboard::routes(),
            "/policy" => policy::routes(),
            "/push" => push::routes(),
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
            "/interactions" => interactions::routes(),
            "/custom" => customisation::routes(),
            "/safety" => safety::routes(),
            "/e2ee" => e2ee::routes(),
            "/mls" => mls::routes(),
            "/events" => events::routes(),
            "/auth/account" => account::routes(),
            "/auth/session" => session::routes(),
            "/auth/oauth" => oauth::routes(),
            "/auth/mfa" => mfa::routes(),
            "/onboard" => onboard::routes(),
            "/policy" => policy::routes(),
            "/push" => push::routes(),
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
              "MFA"
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
              "Web Push"
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
                name: "Invites".to_owned(),
                description: Some("View, join and delete invites".to_owned()),
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
        ],
        ..Default::default()
    }
}
