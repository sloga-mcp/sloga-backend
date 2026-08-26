use revolt_database::{
    util::{name_filter::contains_blocked_slur, reference::Reference},
    Database, Respect, User,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::serde::json::Json;
use rocket::State;
use ulid::Ulid;
use validator::Validate;

/// Current time in milliseconds since the Unix epoch.
#[allow(clippy::disallowed_methods)]
fn now_ms() -> i64 {
    use iso8601_timestamp::Timestamp;
    Timestamp::now_utc()
        .duration_since(Timestamp::UNIX_EPOCH)
        .whole_milliseconds() as i64
}

/// # Give Respect
///
/// Write (or rewrite) your respect on a user's profile wall. One entry per
/// author per wall — giving respect again edits your existing entry in
/// place. Only the wall's owner and their friends may write.
#[openapi(tag = "Respect")]
#[put("/<target>/respect", data = "<data>")]
pub async fn respect_set(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataGiveRespect>,
) -> Result<Json<v0::Respect>> {
    let mut data = data.into_inner();

    // Normalize BEFORE validation so the length cap applies to what would
    // actually be stored. Control characters (newlines included — entries
    // render as a single paragraph) would let an entry break the wall
    // layout.
    data.content = data
        .content
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();

    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Wall entries are read by everyone who can see the profile, so they
    // get the same slur filter as display names.
    if contains_blocked_slur(&data.content) {
        return Err(create_error!(DisallowedName));
    }

    let target = target.as_user(db).await?;

    // Bots cannot have friends, so they cannot have walls.
    if target.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // Your own wall, or a friend's.
    if user.id != target.id && !user.is_friends_with(&target.id) {
        return Err(create_error!(NotFriends));
    }

    let now = now_ms();

    if let Some(existing) = db.fetch_respect(&target.id, &user.id).await? {
        db.update_respect(&existing.id, &data.content, now).await?;
        return Ok(Json(v0::Respect {
            id: existing.id,
            target_id: target.id,
            author_id: user.id,
            content: data.content,
            updated_at: now,
        }));
    }

    let respect = Respect {
        id: Ulid::new().to_string(),
        target_id: target.id.clone(),
        author_id: user.id.clone(),
        content: data.content.clone(),
        updated_at: now,
    };

    match db.insert_respect(&respect).await {
        Ok(()) => Ok(Json(respect.into_model())),
        Err(error) if matches!(error.error_type, ErrorType::NoEffect) => {
            // Lost the unique-index race to a concurrent first write from
            // this same author — the winner's row exists, so edit it. One
            // retry only: if the owner deleted the winner in the meantime,
            // fail rather than loop.
            if let Some(winner) = db.fetch_respect(&target.id, &user.id).await? {
                db.update_respect(&winner.id, &data.content, now).await?;
                Ok(Json(v0::Respect {
                    id: winner.id,
                    target_id: target.id,
                    author_id: user.id,
                    content: data.content,
                    updated_at: now,
                }))
            } else {
                Err(create_error!(InternalError))
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use crate::util::test::TestHarness;
    use revolt_models::v0;
    use rocket::http::{ContentType, Status};

    #[test]
    fn respect_needs_friendship_and_upserts() {
        crate::util::test::rt().block_on(respect_needs_friendship_and_upserts_case())
    }

    async fn respect_needs_friendship_and_upserts_case() {
        let harness = TestHarness::new().await;
        let (_, session_a, user_a) = harness.new_user().await;
        let (_, session_b, user_b) = harness.new_user().await;

        // A stranger may not write on the wall.
        let response = TestHarness::with_session(
            session_b.clone(),
            harness
                .client
                .put(format!("/users/{}/respect", user_a.id))
                .header(ContentType::JSON)
                .body(json!({ "content": "great teammate" }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::Forbidden);

        // You may write on your own wall.
        let response = TestHarness::with_session(
            session_a.clone(),
            harness
                .client
                .put(format!("/users/{}/respect", user_a.id))
                .header(ContentType::JSON)
                .body(json!({ "content": "welcome to my wall" }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        // Befriend: B requests, A accepts.
        let response = TestHarness::with_session(
            session_b.clone(),
            harness
                .client
                .post("/users/friend")
                .header(ContentType::JSON)
                .body(
                    json!({
                        "username": format!("{}#{}", user_a.username, user_a.discriminator)
                    })
                    .to_string(),
                ),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let response = TestHarness::with_session(
            session_a.clone(),
            harness.client.put(format!("/users/{}/friend", user_b.id)),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        // The friend writes...
        let response = TestHarness::with_session(
            session_b.clone(),
            harness
                .client
                .put(format!("/users/{}/respect", user_a.id))
                .header(ContentType::JSON)
                .body(json!({ "content": "carried the raid" }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let first = response.into_json::<v0::Respect>().await.expect("`Respect`");

        // ...and writing again EDITS the same entry instead of adding one.
        let response = TestHarness::with_session(
            session_b.clone(),
            harness
                .client
                .put(format!("/users/{}/respect", user_a.id))
                .header(ContentType::JSON)
                .body(json!({ "content": "carried two raids" }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let second = response.into_json::<v0::Respect>().await.expect("`Respect`");
        assert_eq!(first.id, second.id);
        assert_eq!(second.content, "carried two raids");

        let wall = harness
            .db
            .fetch_respect_by_target(&user_a.id)
            .await
            .expect("wall");
        assert_eq!(wall.len(), 2);

        // Over-long content is rejected.
        let response = TestHarness::with_session(
            session_b,
            harness
                .client
                .put(format!("/users/{}/respect", user_a.id))
                .header(ContentType::JSON)
                .body(json!({ "content": "x".repeat(241) }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::BadRequest);
    }
}
