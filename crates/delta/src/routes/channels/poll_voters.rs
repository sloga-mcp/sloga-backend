use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;

/// # Fetch Poll Voters
///
/// Lists the users who voted for a given answer. Restricted to the poll
/// author and moderators (ManageMessages) — ballots are never exposed to
/// regular voters, and never broadcast over the WebSocket.
#[openapi(tag = "Polls")]
#[get("/<target>/polls/<poll_id>/voters?<answer_id>&<after>&<limit>")]
#[allow(clippy::too_many_arguments)]
pub async fn poll_voters(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    poll_id: String,
    answer_id: u8,
    after: Option<String>,
    limit: Option<i64>,
) -> Result<Json<v0::PollVotersResponse>> {
    let channel = target.as_channel(db).await?;

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    let poll = db.fetch_poll(&poll_id).await?;
    if poll.channel != channel.id() {
        return Err(create_error!(NotFound));
    }

    // Author-only voters list (or moderators with ManageMessages)
    if poll.author != user.id {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageMessages)?;
    }

    let limit = limit.unwrap_or(50).clamp(1, 100);
    let votes = db
        .fetch_poll_voters_page(&poll.id, answer_id, after.as_deref(), limit)
        .await?;

    let user_ids: Vec<String> = votes.into_iter().map(|vote| vote.user).collect();
    let mut users = Vec::with_capacity(user_ids.len());
    for voter in db.fetch_users(&user_ids).await? {
        users.push(voter.into(db, Some(&user)).await);
    }

    Ok(Json(v0::PollVotersResponse { users }))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::Member;
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    #[test]
    fn voters_list_is_author_gated() {
        crate::util::test::rt().block_on(voters_list_is_author_gated_case())
    }

    async fn voters_list_is_author_gated_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, other_session, other_user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        Member::create(&harness.db, &server, &other_user, None)
            .await
            .expect("member");
        let channel = harness.new_channel(&server).await;

        let response = harness
            .client
            .post(format!("/channels/{}/polls", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "question": "Best crab?",
                    "answers": [{ "text": "Ferris" }, { "text": "Sebastian" }]
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let message: v0::Message = response.into_json().await.expect("`Message`");
        let poll_id = message.poll.expect("poll").id;

        // Other user votes for answer 0
        let response = harness
            .client
            .put(format!("/channels/{}/polls/{}/vote", channel.id(), poll_id))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .header(ContentType::JSON)
            .body(json!({ "answer_ids": [0] }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // Author sees the voter
        let response = harness
            .client
            .get(format!(
                "/channels/{}/polls/{}/voters?answer_id=0",
                channel.id(),
                poll_id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let voters: v0::PollVotersResponse = response.into_json().await.expect("voters");
        assert_eq!(voters.users.len(), 1);
        assert_eq!(voters.users[0].id, other_user.id);

        // Answer with no votes is empty
        let response = harness
            .client
            .get(format!(
                "/channels/{}/polls/{}/voters?answer_id=1",
                channel.id(),
                poll_id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let voters: v0::PollVotersResponse = response.into_json().await.expect("voters");
        assert!(voters.users.is_empty());

        // The non-author voter is denied (no ManageMessages)
        let response = harness
            .client
            .get(format!(
                "/channels/{}/polls/{}/voters?answer_id=0",
                channel.id(),
                poll_id
            ))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "non-author must not list voters"
        );
    }
}
