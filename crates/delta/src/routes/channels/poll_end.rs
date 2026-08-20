use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;

/// # End Poll
///
/// Closes a poll immediately and publishes the final results. Only the
/// poll author or a moderator (ManageMessages) may end a poll early.
/// Idempotent: ending an already-closed poll returns its final state.
#[openapi(tag = "Polls")]
#[post("/<target>/polls/<poll_id>/end")]
pub async fn poll_end(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    poll_id: String,
) -> Result<Json<v0::Poll>> {
    let channel = target.as_channel(db).await?;

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    let poll = db.fetch_poll(&poll_id).await?;
    if poll.channel != channel.id() {
        return Err(create_error!(NotFound));
    }

    if poll.author != user.id {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageMessages)?;
    }

    // Exactly-once close arbitration is inside `close`; a lost race (or an
    // already-closed poll) still returns the final state below.
    poll.close(db).await?;

    let poll = db.fetch_poll(&poll_id).await?;
    let my_votes = db
        .fetch_poll_vote(&poll.id, &user.id)
        .await?
        .map(|vote| vote.answer_ids);

    // Closed ⇒ results are public.
    Ok(Json(poll.into_model(my_votes, true)))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::Member;
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    #[test]
    fn end_poll_finalises_results_and_rejects_votes() {
        crate::util::test::rt().block_on(end_poll_finalises_results_and_rejects_votes_case())
    }

    async fn end_poll_finalises_results_and_rejects_votes_case() {
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

        // A vote lands before close
        harness
            .client
            .put(format!("/channels/{}/polls/{}/vote", channel.id(), poll_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "answer_ids": [0] }).to_string())
            .dispatch()
            .await;

        // Non-author cannot end the poll
        let response = harness
            .client
            .post(format!("/channels/{}/polls/{}/end", channel.id(), poll_id))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok, "non-author must not end");

        // Author ends it
        let response = harness
            .client
            .post(format!("/channels/{}/polls/{}/end", channel.id(), poll_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let poll: v0::Poll = response.into_json().await.expect("`Poll`");
        assert!(poll.closed);
        let counts = poll.counts.expect("final counts are public");
        assert_eq!(counts.iter().find(|c| c.answer_id == 0).unwrap().count, 1);
        assert_eq!(poll.total_votes, Some(1));

        // Ending again is idempotent
        let response = harness
            .client
            .post(format!("/channels/{}/polls/{}/end", channel.id(), poll_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // Votes after close are rejected — and everyone sees final results
        let response = harness
            .client
            .put(format!("/channels/{}/polls/{}/vote", channel.id(), poll_id))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .header(ContentType::JSON)
            .body(json!({ "answer_ids": [1] }).to_string())
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok, "closed poll must reject votes");

        let response = harness
            .client
            .get(format!("/channels/{}/polls/{}", channel.id(), poll_id))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .dispatch()
            .await;
        let poll: v0::Poll = response.into_json().await.expect("`Poll`");
        assert!(poll.closed);
        assert!(
            poll.counts.is_some(),
            "closed poll results are public to non-voters"
        );
    }
}
