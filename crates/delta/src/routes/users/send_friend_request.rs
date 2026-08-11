// use revolt_database::util::reference::Reference;
use revolt_database::{util::name_filter::contains_blocked_slur, Database, User, AMQP};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

/// # Send Friend Request
///
/// Send a friend request to another user.
#[openapi(tag = "Relationships")]
#[post("/friend", data = "<data>")]
pub async fn send_friend_request(
    db: &State<Database>,
    amqp: &State<AMQP>,
    mut user: User,
    data: Json<v0::DataSendFriendRequest>,
) -> Result<Json<v0::User>> {
    let mut data = data.into_inner();

    // Normalize the note BEFORE validation so an empty, whitespace-only or
    // absent note all behave identically (absent), and the length cap
    // applies to what would actually be stored. Control characters would
    // let a note break the request row layout.
    data.note = data
        .note
        .as_deref()
        .map(|note| {
            note.chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
                .trim()
                .to_string()
        })
        .filter(|note| !note.is_empty());

    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Notes are read by strangers before they ever accepted anything, so
    // they get the same slur filter as display names.
    let note = data.note.take();

    if let Some(note) = &note {
        if contains_blocked_slur(note) {
            return Err(create_error!(DisallowedName));
        }
    }

    if let Some((username, discriminator)) = data.username.split_once('#') {
        let mut target = db.fetch_user_by_username(username, discriminator).await?;

        if user.bot.is_some() || target.bot.is_some() {
            return Err(create_error!(IsBot));
        }

        user.add_friend(db, amqp, &mut target, note).await?;
        Ok(Json(target.into(db, &user).await))
    } else {
        Err(create_error!(InvalidProperty))
    }
}

#[cfg(test)]
mod tests {
    use crate::util::test::TestHarness;
    use revolt_models::v0;
    use rocket::http::{ContentType, Status};

    #[rocket::async_test]
    async fn note_rides_the_request_and_dies_on_accept() {
        let harness = TestHarness::new().await;
        let (_, session_a, user_a) = harness.new_user().await;
        let (_, session_b, user_b) = harness.new_user().await;

        // A sends B a request with a note wrapped in whitespace and a stray
        // control character; the server must store the cleaned-up version.
        let response = TestHarness::with_session(
            session_a,
            harness
                .client
                .post("/users/friend")
                .header(ContentType::JSON)
                .body(
                    json!({
                        "username": format!("{}#{}", user_b.username, user_b.discriminator),
                        "note": "  raid group from wednesday?\u{7}  "
                    })
                    .to_string(),
                ),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        // Persisted on B's side of the relationship — through whichever
        // driver TEST_DB selected; run under MONGODB to cover the hand-built
        // aggregation literal in set_relationship.
        let stored = harness.db.fetch_user(&user_b.id).await.expect("user b");
        let relation = stored
            .relations
            .as_ref()
            .and_then(|relations| relations.iter().find(|relation| relation.id == user_a.id))
            .expect("incoming relation");
        assert_eq!(relation.note.as_deref(), Some("raid group from wednesday?"));

        // B sees the note on A's user object.
        let response = TestHarness::with_session(
            session_b.clone(),
            harness.client.get(format!("/users/{}", user_a.id)),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let seen = response.into_json::<v0::User>().await.expect("`User`");
        assert_eq!(
            seen.relationship_note.as_deref(),
            Some("raid group from wednesday?")
        );

        // Accepting rewrites the entry; the note does not outlive the
        // pending state.
        let response = TestHarness::with_session(
            session_b,
            harness.client.put(format!("/users/{}/friend", user_a.id)),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        let stored = harness.db.fetch_user(&user_b.id).await.expect("user b");
        let relation = stored
            .relations
            .as_ref()
            .and_then(|relations| relations.iter().find(|relation| relation.id == user_a.id))
            .expect("friend relation");
        assert!(relation.note.is_none());
    }

    #[rocket::async_test]
    async fn whitespace_only_note_is_treated_as_absent() {
        let harness = TestHarness::new().await;
        let (_, session_a, user_a) = harness.new_user().await;
        let (_, _, user_b) = harness.new_user().await;

        // A blank note field must not fail the request — it is simply no note.
        let response = TestHarness::with_session(
            session_a,
            harness
                .client
                .post("/users/friend")
                .header(ContentType::JSON)
                .body(
                    json!({
                        "username": format!("{}#{}", user_b.username, user_b.discriminator),
                        "note": "   "
                    })
                    .to_string(),
                ),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        let stored = harness.db.fetch_user(&user_b.id).await.expect("user b");
        let relation = stored
            .relations
            .as_ref()
            .and_then(|relations| relations.iter().find(|relation| relation.id == user_a.id))
            .expect("incoming relation");
        assert!(relation.note.is_none());
    }

    #[rocket::async_test]
    async fn slur_in_note_is_rejected() {
        let harness = TestHarness::new().await;
        let (_, session_a, _) = harness.new_user().await;
        let (_, _, user_b) = harness.new_user().await;

        let response = TestHarness::with_session(
            session_a,
            harness
                .client
                .post("/users/friend")
                .header(ContentType::JSON)
                .body(
                    json!({
                        "username": format!("{}#{}", user_b.username, user_b.discriminator),
                        "note": "hey n1gg3r add me"
                    })
                    .to_string(),
                ),
        )
        .await;
        assert_eq!(response.status(), Status::BadRequest);
    }

    #[rocket::async_test]
    async fn overlong_note_is_rejected() {
        let harness = TestHarness::new().await;
        let (_, session_a, _) = harness.new_user().await;
        let (_, _, user_b) = harness.new_user().await;

        let response = TestHarness::with_session(
            session_a,
            harness
                .client
                .post("/users/friend")
                .header(ContentType::JSON)
                .body(
                    json!({
                        "username": format!("{}#{}", user_b.username, user_b.discriminator),
                        "note": "x".repeat(201)
                    })
                    .to_string(),
                ),
        )
        .await;
        assert_eq!(response.status(), Status::BadRequest);
    }
}
