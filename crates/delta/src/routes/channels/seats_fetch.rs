use revolt_database::{util::reference::Reference, Database, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};

/// # Fetch Seats
///
/// Fetch the seat state of a protected channel: the newest seat list, the
/// open text group's epoch and the seats in use.
#[openapi(tag = "E2EE")]
#[get("/<target>/seats")]
pub async fn fetch_seats(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::ResponseChannelSeats>> {
    // Not served yet: refuse until the seat read is in place.
    let _ = (db, user, target);
    Err(create_error!(NotFound))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use rocket::http::Status;

    #[test]
    fn fetch_seats_is_mounted_and_refuses() {
        crate::util::test::rt().block_on(fetch_seats_is_mounted_and_refuses_case())
    }

    async fn fetch_seats_is_mounted_and_refuses_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let response = TestHarness::with_session(
            session,
            harness
                .client
                .get(format!("/channels/{}/seats", ulid::Ulid::new())),
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
                .is_some_and(|location| location.contains("routes/channels/seats_fetch.rs")),
            "unexpected error: {}",
            error
        );
    }
}
