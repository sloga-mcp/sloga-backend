use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Fetch Text Group
///
/// The channel's open protected-channel Text group (protected-channels
/// design §7.2): id, generation, epoch, roster, pending removals and
/// `member_added`. ViewChannel; maintenance gate. 404 when the channel has
/// no open Text group.
///
/// Not served yet: every request gets the 404 of a channel with no Text
/// group, so the route discloses nothing until its body lands.
#[openapi(tag = "MLS")]
#[get("/channels/<channel_id>/text_group")]
pub async fn fetch_text_group(
    _db: &State<Database>,
    _user: User,
    channel_id: String,
) -> Result<Json<v0::ResponseTextGroup>> {
    let _ = channel_id;
    Err(create_error!(NotFound))
}

#[cfg(test)]
mod tests {
    use rocket::http::{Header, Status};

    use crate::util::test::TestHarness;

    #[test]
    fn the_stub_is_mounted_and_answers_not_found() {
        crate::util::test::rt().block_on(the_stub_is_mounted_and_answers_not_found_case())
    }

    async fn the_stub_is_mounted_and_answers_not_found_case() {
        let harness = TestHarness::new().await;
        let (_account, session, _user) = harness.new_user().await;

        let response = harness
            .client
            .get("/mls/channels/01J9Z3K4M5N6P7Q8R9S0T1V2W3/text_group")
            .header(Header::new("x-session-token", session.token.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // The 404 is this handler's, not an unmatched route's
        let body: serde_json::Value =
            serde_json::from_str(&response.into_string().await.expect("a body")).expect("JSON");
        assert_eq!(body["type"], "NotFound", "{}", body);
        assert!(
            body["location"]
                .as_str()
                .is_some_and(|location| location.contains("routes/mls/text_group.rs")),
            "{}",
            body
        );

        // The user guard runs first
        let response = harness
            .client
            .get("/mls/channels/01J9Z3K4M5N6P7Q8R9S0T1V2W3/text_group")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized);
    }
}
