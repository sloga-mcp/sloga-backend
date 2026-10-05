use revolt_database::{util::reference::Reference, Database, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};

/// # Grant Channel Entitlement
///
/// Grant (or update) the entitlement that lets a server channel be
/// protected. Requires a privileged account.
#[openapi(tag = "E2EE")]
#[put("/<target>/protected_entitlement", data = "<data>")]
pub async fn grant_entitlement(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataGrantChannelEntitlement>,
) -> Result<Json<v0::ChannelEntitlement>> {
    // Not served yet: refuse until the grant rules are in place.
    let _ = (db, user, target, data);
    Err(create_error!(NotFound))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use rocket::http::{ContentType, Status};
    use serde_json::json;

    #[test]
    fn grant_entitlement_is_mounted_and_refuses() {
        crate::util::test::rt().block_on(grant_entitlement_is_mounted_and_refuses_case())
    }

    async fn grant_entitlement_is_mounted_and_refuses_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let response = TestHarness::with_session(
            session,
            harness
                .client
                .put(format!(
                    "/channels/{}/protected_entitlement",
                    ulid::Ulid::new()
                ))
                .header(ContentType::JSON)
                .body(json!({ "slot_cap": 1 }).to_string()),
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
            error["location"].as_str().is_some_and(
                |location| location.contains("routes/channels/protected_entitlement_grant.rs")
            ),
            "unexpected error: {}",
            error
        );
    }
}
