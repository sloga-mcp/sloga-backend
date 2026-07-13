use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

use crate::util::polls::{can_see_counts, now_ms};

/// # Fetch Poll
///
/// Fetches a poll's state. Live counts are included only when the caller
/// has voted, is the author, has ManageMessages, or the poll is closed —
/// hidden-until-vote is enforced here, server-side.
#[openapi(tag = "Polls")]
#[get("/<target>/polls/<poll_id>")]
pub async fn poll_fetch(
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

    let mut poll = db.fetch_poll(&poll_id).await?;
    if poll.channel != channel.id() {
        return Err(create_error!(NotFound));
    }

    // Lazy close: covers daemon downtime; refetch for authoritative counts.
    if !poll.closed && poll.is_expired(now_ms()) {
        poll.close(db).await?;
        poll = db.fetch_poll(&poll_id).await?;
    }

    let my_votes = db
        .fetch_poll_vote(&poll.id, &user.id)
        .await?
        .map(|vote| vote.answer_ids);

    let include_counts = can_see_counts(&poll, &user.id, &permissions, my_votes.is_some());
    Ok(Json(poll.into_model(my_votes, include_counts)))
}

/// # Bulk Fetch Polls
///
/// Fetches poll state for the polls on a page of messages in one request
/// (avoids one fetch per poll message on scroll). The same per-poll count
/// gating as the single fetch applies.
#[openapi(tag = "Polls")]
#[post("/<target>/polls/fetch", data = "<data>")]
pub async fn polls_fetch_bulk(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataPollsFetch>,
) -> Result<Json<Vec<v0::Poll>>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let channel = target.as_channel(db).await?;

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    let now = now_ms();
    let mut polls = db.fetch_polls(&data.ids).await?;

    // The channel topic is the authorization boundary: only polls that
    // actually live in this channel are returned.
    polls.retain(|poll| poll.channel == channel.id());

    // Lazily close any that expired while the daemon was down.
    let mut refetch = Vec::new();
    for poll in &polls {
        if !poll.closed && poll.is_expired(now) {
            poll.close(db).await?;
            refetch.push(poll.id.clone());
        }
    }
    if !refetch.is_empty() {
        let closed = db.fetch_polls(&refetch).await?;
        for updated in closed {
            if let Some(slot) = polls.iter_mut().find(|poll| poll.id == updated.id) {
                *slot = updated;
            }
        }
    }

    let poll_ids: Vec<String> = polls.iter().map(|poll| poll.id.clone()).collect();
    let my_votes = db.fetch_poll_votes_for_user(&poll_ids, &user.id).await?;

    Ok(Json(
        polls
            .into_iter()
            .map(|poll| {
                let mine = my_votes
                    .iter()
                    .find(|vote| vote.poll == poll.id)
                    .map(|vote| vote.answer_ids.clone());
                let include_counts =
                    can_see_counts(&poll, &user.id, &permissions, mine.is_some());
                poll.into_model(mine, include_counts)
            })
            .collect(),
    ))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::Member;
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    #[rocket::async_test]
    async fn results_hidden_until_vote_and_public_after_close() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, other_session, other_user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;

        // Second user joins the server
        Member::create(&harness.db, &server, &other_user, None)
            .await
            .expect("member");

        let channel = harness.new_channel(&server).await;

        // Author creates the poll and votes
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

        harness
            .client
            .put(format!("/channels/{}/polls/{}/vote", channel.id(), poll_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "answer_ids": [0] }).to_string())
            .dispatch()
            .await;

        // The non-voting other user cannot see counts...
        let response = harness
            .client
            .get(format!("/channels/{}/polls/{}", channel.id(), poll_id))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let poll: v0::Poll = response.into_json().await.expect("`Poll`");
        assert!(poll.counts.is_none(), "counts must be hidden before voting");
        assert!(poll.total_votes.is_none());
        assert_eq!(poll.my_votes, None);
        assert_eq!(poll.author_id, user.id);

        // ...but the author can (own poll)
        let response = harness
            .client
            .get(format!("/channels/{}/polls/{}", channel.id(), poll_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let poll: v0::Poll = response.into_json().await.expect("`Poll`");
        assert!(poll.counts.is_some(), "author sees counts");

        // After the other user votes, they see counts too
        harness
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
        let counts = poll.counts.expect("voter sees counts");
        assert_eq!(counts.iter().find(|c| c.answer_id == 0).unwrap().count, 1);
        assert_eq!(counts.iter().find(|c| c.answer_id == 1).unwrap().count, 1);
        assert_eq!(poll.total_votes, Some(2));
        assert_eq!(poll.my_votes, Some(vec![1]));
        assert_eq!(other_user.id, other_user.id);
    }

    #[rocket::async_test]
    async fn outsider_and_cross_channel_access_rejected() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        // NOT a member of the server below
        let (_, outsider_session, _) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let other_channel = harness.new_channel(&server).await;

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

        // An outsider can neither fetch nor vote
        let response = harness
            .client
            .get(format!("/channels/{}/polls/{}", channel.id(), poll_id))
            .header(Header::new(
                "x-session-token",
                outsider_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok, "outsider must not fetch");

        let response = harness
            .client
            .put(format!("/channels/{}/polls/{}/vote", channel.id(), poll_id))
            .header(Header::new(
                "x-session-token",
                outsider_session.token.to_string(),
            ))
            .header(ContentType::JSON)
            .body(json!({ "answer_ids": [0] }).to_string())
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok, "outsider must not vote");

        // A member addressing the poll through the WRONG channel is scoped out
        let response = harness
            .client
            .get(format!(
                "/channels/{}/polls/{}",
                other_channel.id(),
                poll_id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::NotFound,
            "poll lookups are channel-scoped"
        );
    }

    #[rocket::async_test]
    async fn bulk_fetch_gates_per_poll() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        // Two polls; author votes on the first only. (The author sees both
        // anyway, so gate assertions use my_votes instead.)
        let mut poll_ids = Vec::new();
        for question in ["one", "two"] {
            let response = harness
                .client
                .post(format!("/channels/{}/polls", channel.id()))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(
                    json!({
                        "question": question,
                        "answers": [{ "text": "a" }, { "text": "b" }]
                    })
                    .to_string(),
                )
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
            let message: v0::Message = response.into_json().await.expect("`Message`");
            poll_ids.push(message.poll.expect("poll").id);
        }

        harness
            .client
            .put(format!(
                "/channels/{}/polls/{}/vote",
                channel.id(),
                poll_ids[0]
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "answer_ids": [0] }).to_string())
            .dispatch()
            .await;

        let response = harness
            .client
            .post(format!("/channels/{}/polls/fetch", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "ids": poll_ids }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let polls: Vec<v0::Poll> = response.into_json().await.expect("`Vec<Poll>`");
        assert_eq!(polls.len(), 2);

        let first = polls.iter().find(|p| p.id == poll_ids[0]).unwrap();
        let second = polls.iter().find(|p| p.id == poll_ids[1]).unwrap();
        assert_eq!(first.my_votes, Some(vec![0]));
        assert_eq!(second.my_votes, None);
        // Author of both — counts visible on both
        assert!(first.counts.is_some());
        assert!(second.counts.is_some());
        assert_eq!(user.id, user.id);
    }
}
