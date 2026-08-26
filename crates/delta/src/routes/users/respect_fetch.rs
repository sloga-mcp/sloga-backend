use std::collections::HashSet;

use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, ProfileVisibility, Respect, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_user_permissions, UserPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Fetch Respect Wall
///
/// Retrieve a user's respect wall (newest-edited first), along with the
/// authors' user objects.
///
/// Gated exactly like the profile itself: `ViewProfile`, plus the target's
/// friends-only visibility setting.
#[openapi(tag = "Respect")]
#[get("/<target>/respect")]
pub async fn respect_fetch(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::RespectResponse>> {
    let target = target.as_user(db).await?;

    if user.id != target.id {
        let mut query = DatabasePermissionQuery::new(db, &user).user(&target);
        calculate_user_permissions(&mut query)
            .await
            .throw_if_lacking_user_permission(UserPermission::ViewProfile)?;

        // Same gate as fetch_profile: friends-only visibility sits on top of
        // ViewProfile. Bots are exempt there for description reasons; here
        // their wall is simply empty (they cannot receive respect).
        if matches!(target.profile_visibility, Some(ProfileVisibility::Friends))
            && target.bot.is_none()
            && !user.privileged
            && !user.is_friends_with(&target.id)
        {
            return Err(create_error!(ProfileIsPrivate));
        }
    }

    let respect = db.fetch_respect_by_target(&target.id).await?;

    // Authors, deduped, serialized PER-VIEWER: `into_known` nulls status and
    // connections for an author who has blocked the viewer — a wall must not
    // leak what `can_see_profile` would hide. Online pinned false: a wall is
    // not a presence surface either.
    let author_ids: Vec<String> = respect
        .iter()
        .map(|entry| entry.author_id.clone())
        .collect::<HashSet<String>>()
        .into_iter()
        .collect();

    let mut users = Vec::with_capacity(author_ids.len());
    for author in db.fetch_users(&author_ids).await? {
        users.push(author.into_known(&user, false).await);
    }

    Ok(Json(v0::RespectResponse {
        respect: respect.into_iter().map(Respect::into_model).collect(),
        users,
    }))
}

#[cfg(test)]
mod tests {
    use crate::util::test::TestHarness;
    use revolt_database::{Member, Respect};
    use revolt_models::v0;
    use rocket::http::{ContentType, Status};

    #[test]
    fn wall_hides_status_of_author_who_blocked_viewer() {
        crate::util::test::rt().block_on(wall_hides_status_of_author_who_blocked_viewer_case())
    }

    async fn wall_hides_status_of_author_who_blocked_viewer_case() {
        // The viewer's ViewProfile on the target comes from the
        // mutual-server path, which only exists on the Mongo driver.
        if std::env::var("TEST_DB").map(|v| v == "MONGODB") != Ok(true) {
            return;
        }

        let harness = TestHarness::new().await;
        let (_, _session_t, target) = harness.new_user().await;
        let (_, session_author, mut author) = harness.new_user().await;
        let (_, session_viewer, mut viewer) = harness.new_user().await;

        // A mutual server grants the viewer ViewProfile on the target
        // (Server::create does not write the owner's member document — the
        // route does — so the test adds both explicitly).
        let (server, _channels) = harness.new_server(&target).await;
        Member::create(&harness.db, &server, &target, None)
            .await
            .expect("target member");
        Member::create(&harness.db, &server, &viewer, None)
            .await
            .expect("viewer member");

        // The author has a custom status and an entry on the target's wall.
        TestHarness::with_session(
            session_author.clone(),
            harness
                .client
                .patch("/users/@me")
                .header(ContentType::JSON)
                .body(json!({ "status": { "text": "secret status" } }).to_string()),
        )
        .await;
        harness
            .db
            .insert_respect(&Respect {
                id: "01RSPCTBLK00000000000000001".to_string(),
                target_id: target.id.clone(),
                author_id: author.id.clone(),
                content: "solid".to_string(),
                updated_at: 1_000,
            })
            .await
            .expect("insert");

        // The author blocks the VIEWER (a third party — not the target, so
        // the block cascade does not touch this wall entry).
        author = harness.db.fetch_user(&author.id).await.expect("author");
        viewer = harness.db.fetch_user(&viewer.id).await.expect("viewer");
        author
            .block_user(&harness.db, &mut viewer)
            .await
            .expect("block");

        let response = TestHarness::with_session(
            session_viewer,
            harness.client.get(format!("/users/{}/respect", target.id)),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        let wall = response
            .into_json::<v0::RespectResponse>()
            .await
            .expect("`RespectResponse`");
        assert_eq!(wall.respect.len(), 1);

        let author_user = wall
            .users
            .iter()
            .find(|u| u.id == author.id)
            .expect("author in users");
        assert_eq!(author_user.status, None, "status must not leak to a blocked viewer");
        assert!(author_user.connections.is_empty());
        assert!(!author_user.online);
    }
}
