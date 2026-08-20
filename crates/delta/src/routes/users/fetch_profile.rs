use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, ProfileVisibility, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_user_permissions, UserPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Fetch User Profile
///
/// Retrieve a user's profile data.
///
/// Will fail if you do not have permission to access the other user's profile.
#[openapi(tag = "User Information")]
#[get("/<target>/profile")]
pub async fn profile(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::UserProfile>> {
    if user.id == target.id {
        return Ok(Json(user.profile.map(Into::into).unwrap_or_default()));
    }

    let target = target.as_user(db).await?;

    let mut query = DatabasePermissionQuery::new(db, &user).user(&target);
    calculate_user_permissions(&mut query)
        .await
        .throw_if_lacking_user_permission(UserPermission::ViewProfile)?;

    // Friends-only visibility sits on top of ViewProfile, which mutual
    // server members hold. Bots are exempt: they cannot have friends and
    // their profile content doubles as the public bot description.
    if matches!(target.profile_visibility, Some(ProfileVisibility::Friends))
        && target.bot.is_none()
        && !user.privileged
        && !user.is_friends_with(&target.id)
    {
        return Err(create_error!(ProfileIsPrivate));
    }

    Ok(Json(target.profile.map(Into::into).unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use crate::util::test::TestHarness;
    use revolt_database::{BotInformation, Member, PartialUser, ProfileVisibility};
    use rocket::http::{ContentType, Status};

    #[test]
    fn bots_are_exempt_from_friends_only_visibility() {
        crate::util::test::rt().block_on(bots_are_exempt_from_friends_only_visibility_case())
    }

    async fn bots_are_exempt_from_friends_only_visibility_case() {
        // ViewProfile on the bot comes from the mutual-server path, which
        // only exists on the Mongo driver.
        if std::env::var("TEST_DB").map(|v| v == "MONGODB") != Ok(true) {
            return;
        }

        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, fetcher_session, fetcher) = harness.new_user().await;
        let (_, _, mut bot_user) = harness.new_user().await;

        // A bot with the field set (e.g. by a confused owner edit) must stay
        // fetchable by non-friends: bots cannot have friends and their
        // profile content doubles as the public bot description.
        bot_user
            .update(
                &harness.db,
                PartialUser {
                    bot: Some(BotInformation {
                        owner: owner.id.clone(),
                    }),
                    profile_visibility: Some(ProfileVisibility::Friends),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("bot user");

        let (server, _channels) = harness.new_server(&bot_user).await;
        Member::create(&harness.db, &server, &bot_user, None)
            .await
            .expect("bot member");
        Member::create(&harness.db, &server, &fetcher, None)
            .await
            .expect("fetcher member");

        let response = TestHarness::with_session(
            fetcher_session,
            harness.client.get(format!("/users/{}/profile", bot_user.id)),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    fn friends_only_profile_needs_friendship() {
        crate::util::test::rt().block_on(friends_only_profile_needs_friendship_case())
    }

    async fn friends_only_profile_needs_friendship_case() {
        // The mutual-server permission path only exists on the Mongo driver
        // (the reference driver has no mutual-server query), so the
        // baseline and the distinct-error assertions are Mongo-only; the
        // friendship leg is portable.
        let mongo = std::env::var("TEST_DB")
            .map(|v| v == "MONGODB")
            .unwrap_or_default();

        let harness = TestHarness::new().await;
        let (_, session_a, user_a) = harness.new_user().await;
        let (_, session_b, user_b) = harness.new_user().await;

        // A mutual server grants B ViewProfile on A. Server::create does
        // not write the owner's member document — the route does — so the
        // test adds both explicitly.
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_a, None)
            .await
            .expect("owner member");
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        if mongo {
            // Baseline: the mutual-server member can fetch the profile.
            let response = TestHarness::with_session(
                session_b.clone(),
                harness.client.get(format!("/users/{}/profile", user_a.id)),
            )
            .await;
            assert_eq!(response.status(), Status::Ok);
        }

        // A limits their profile to friends.
        let response = TestHarness::with_session(
            session_a.clone(),
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "profile_visibility": "Friends" }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        // The non-friend is refused either way; on Mongo, distinctly, so
        // clients can render the degraded card.
        let response = TestHarness::with_session(
            session_b.clone(),
            harness.client.get(format!("/users/{}/profile", user_a.id)),
        )
        .await;
        assert_eq!(response.status(), Status::Forbidden);
        if mongo {
            let error = response
                .into_json::<serde_json::Value>()
                .await
                .expect("error body");
            assert_eq!(error["type"], "ProfileIsPrivate");
        }

        // Friendship reopens it: B requests, A accepts.
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
            session_a,
            harness.client.put(format!("/users/{}/friend", user_b.id)),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        let response = TestHarness::with_session(
            session_b,
            harness.client.get(format!("/users/{}/profile", user_a.id)),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
    }
}
