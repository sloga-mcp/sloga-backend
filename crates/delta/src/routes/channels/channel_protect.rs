use revolt_database::{util::reference::Reference, Database, Session, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};

/// # Protect Channel
///
/// Protect a server text channel with its genesis seat list. Only the
/// server owner may protect a channel.
#[openapi(tag = "E2EE")]
#[put("/<target>/protect", data = "<data>")]
pub async fn protect_channel(
    db: &State<Database>,
    user: User,
    session: Session,
    target: Reference<'_>,
    data: Json<v0::DataProtectChannel>,
) -> Result<Json<v0::Channel>> {
    // Not served yet: refuse until the protect rules are in place.
    let _ = (db, user, session, target, data);
    Err(create_error!(NotFound))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use rocket::http::{ContentType, Status};
    use serde_json::json;

    #[test]
    fn protect_channel_is_mounted_and_refuses() {
        crate::util::test::rt().block_on(protect_channel_is_mounted_and_refuses_case())
    }

    async fn protect_channel_is_mounted_and_refuses_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let response = TestHarness::with_session(
            session,
            harness
                .client
                .put(format!("/channels/{}/protect", ulid::Ulid::new()))
                .header(ContentType::JSON)
                .body(
                    json!({
                        "seat_list": {
                            "body": "body",
                            "signature": "signature",
                            "signer_device_id": "device"
                        }
                    })
                    .to_string(),
                ),
        )
        .await;

        // An unmounted route is also a 404, but from Rocket's catcher, which
        // carries no API error body. The location pins it to this handler.
        assert_eq!(response.status(), Status::NotFound);
        let error = response
            .into_json::<serde_json::Value>()
            .await
            .expect("API error body");
        assert_eq!(error["type"], "NotFound");
        assert!(
            error["location"]
                .as_str()
                .is_some_and(|location| location.contains("routes/channels/channel_protect.rs")),
            "unexpected error: {}",
            error
        );
    }
}
