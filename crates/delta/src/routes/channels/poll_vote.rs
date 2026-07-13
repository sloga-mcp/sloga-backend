use std::collections::HashMap;

use revolt_database::events::client::EventV1;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Database, Poll, PollVote, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

use crate::util::polls::now_ms;

/// Resolve the poll after the usual channel permission gate, lazily closing
/// it when its expiry has already passed (covers daemon downtime). Returns
/// `PollClosed` for closed or just-now-expired polls.
async fn resolve_open_poll(
    db: &Database,
    target: &Reference<'_>,
    poll_id: &str,
    user: &User,
) -> Result<Poll> {
    let channel = target.as_channel(db).await?;

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    let poll = db.fetch_poll(poll_id).await?;
    if poll.channel != channel.id() {
        return Err(create_error!(NotFound));
    }

    if poll.closed {
        return Err(create_error!(PollClosed));
    }

    // Lazy close: the crond tick may be down or up to a minute late.
    if poll.is_expired(now_ms()) {
        poll.close(db).await?;
        return Err(create_error!(PollClosed));
    }

    Ok(poll)
}

/// Publish the new aggregate counts to the channel topic. Count-only by
/// design: ballots (who voted for what) are never broadcast.
async fn publish_vote_update(poll: &Poll) {
    EventV1::PollVoteUpdate {
        id: poll.id.clone(),
        channel_id: poll.channel.clone(),
        message_id: poll.message.clone(),
        counts: poll.counts_vec(),
        total_votes: poll.total_votes,
    }
    .p(poll.channel.clone())
    .await;
}

/// After-close compensation for the write race: the open check in
/// `resolve_open_poll` and the ballot write are not one atomic step, so a
/// close (crond tick, lazy close, or manual /end) can slip in between. When
/// the post-write re-check finds the poll closed, restore the ballot to its
/// pre-request state and recount from the ballots so the stored finals
/// exactly match them again (healing any interleaving with the closer's own
/// recount), then reject the request — no `PollVoteUpdate` is ever published
/// after `PollClose`.
async fn compensate_write_after_close(
    db: &Database,
    poll: &Poll,
    user_id: &str,
    previous: Option<Vec<u8>>,
) -> Result<()> {
    match previous {
        Some(answer_ids) => {
            db.upsert_poll_vote(&PollVote {
                id: Poll::vote_key(&poll.id, user_id),
                poll: poll.id.clone(),
                user: user_id.to_string(),
                channel: poll.channel.clone(),
                answer_ids,
            })
            .await?;
        }
        None => {
            db.remove_poll_vote(&poll.id, user_id).await?;
        }
    }

    poll.recount(db).await?;
    Err(create_error!(PollClosed))
}

/// # Vote on Poll
///
/// Casts (or replaces) the calling user's ballot on a poll.
#[openapi(tag = "Polls")]
#[put("/<target>/polls/<poll_id>/vote", data = "<data>")]
pub async fn poll_vote(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    poll_id: String,
    data: Json<v0::DataPollVote>,
) -> Result<Json<v0::Poll>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let poll = resolve_open_poll(db, &target, &poll_id, &user).await?;

    // Validate the ballot against the immutable answer snapshot.
    let mut answer_ids = data.answer_ids;
    answer_ids.sort_unstable();
    answer_ids.dedup();

    if !poll.allow_multiselect && answer_ids.len() != 1 {
        return Err(create_error!(InvalidProperty));
    }

    let valid: std::collections::HashSet<u8> =
        poll.answers.iter().map(|answer| answer.id).collect();
    if !answer_ids.iter().all(|id| valid.contains(id)) {
        return Err(create_error!(InvalidProperty));
    }

    let vote = PollVote {
        id: Poll::vote_key(&poll.id, &user.id),
        poll: poll.id.clone(),
        user: user.id.clone(),
        channel: poll.channel.clone(),
        answer_ids: answer_ids.clone(),
    };

    let previous = db.upsert_poll_vote(&vote).await?;
    let is_new_ballot = previous.is_none();

    // Count deltas: -1 for every previously-selected answer, +1 for every
    // newly-selected one (overlaps cancel out).
    let mut deltas: HashMap<String, i64> = HashMap::new();
    for id in previous.iter().flatten() {
        *deltas.entry(id.to_string()).or_insert(0) -= 1;
    }
    for id in &answer_ids {
        *deltas.entry(id.to_string()).or_insert(0) += 1;
    }
    deltas.retain(|_, delta| *delta != 0);

    db.apply_poll_count_deltas(&poll.id, &deltas, if is_new_ballot { 1 } else { 0 })
        .await?;

    // Post-write re-check: a close may have raced in between the open check
    // and the ballot write — compensate and reject rather than mutating
    // published final results.
    let poll = db.fetch_poll(&poll.id).await?;
    if poll.closed {
        compensate_write_after_close(db, &poll, &user.id, previous).await?;
    }

    publish_vote_update(&poll).await;

    // The voter can now see live results (hidden-until-vote satisfied).
    Ok(Json(poll.into_model(Some(answer_ids), true)))
}

/// # Retract Poll Vote
///
/// Removes the calling user's ballot from a poll.
#[openapi(tag = "Polls")]
#[delete("/<target>/polls/<poll_id>/vote")]
pub async fn poll_unvote(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    poll_id: String,
) -> Result<Json<v0::Poll>> {
    let poll = resolve_open_poll(db, &target, &poll_id, &user).await?;

    let previous = db.remove_poll_vote(&poll.id, &user.id).await?;

    if let Some(removed) = &previous {
        let mut deltas: HashMap<String, i64> = HashMap::new();
        for id in removed {
            *deltas.entry(id.to_string()).or_insert(0) -= 1;
        }

        db.apply_poll_count_deltas(&poll.id, &deltas, -1).await?;

        // Post-write re-check, mirroring the vote path: if a close raced
        // in, restore the ballot (it was part of the published finals) and
        // reject the retraction.
        let poll = db.fetch_poll(&poll.id).await?;
        if poll.closed {
            compensate_write_after_close(db, &poll, &user.id, previous).await?;
        }

        publish_vote_update(&poll).await;
    }

    // Having retracted, the user no longer sees live results (unless they
    // are the author / a moderator — the fetch route re-applies that; keep
    // this response conservative).
    let poll = db.fetch_poll(&poll.id).await?;
    let include_counts = poll.author == user.id;
    Ok(Json(poll.into_model(None, include_counts)))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    async fn create_poll(
        harness: &TestHarness,
        session_token: &str,
        channel_id: &str,
        multiselect: bool,
    ) -> v0::Message {
        let response = harness
            .client
            .post(format!("/channels/{channel_id}/polls"))
            .header(Header::new("x-session-token", session_token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "question": "Best crab?",
                    "answers": [
                        { "text": "Ferris" },
                        { "text": "Sebastian" }
                    ],
                    "allow_multiselect": multiselect
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        response.into_json().await.expect("`Message`")
    }

    #[rocket::async_test]
    async fn vote_replace_and_retract_adjust_counts() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let message = create_poll(&harness, &session.token, channel.id(), false).await;
        let poll_id = message.poll.expect("poll").id;

        // Cast a ballot for answer 0
        let response = harness
            .client
            .put(format!("/channels/{}/polls/{}/vote", channel.id(), poll_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "answer_ids": [0] }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let poll: v0::Poll = response.into_json().await.expect("`Poll`");
        let counts = poll.counts.expect("voter sees counts");
        assert_eq!(counts.iter().find(|c| c.answer_id == 0).unwrap().count, 1);
        assert_eq!(poll.total_votes, Some(1));
        assert_eq!(poll.my_votes, Some(vec![0]));

        // Replace the ballot with answer 1 — counts move, total stays 1
        let response = harness
            .client
            .put(format!("/channels/{}/polls/{}/vote", channel.id(), poll_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "answer_ids": [1] }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let poll: v0::Poll = response.into_json().await.expect("`Poll`");
        let counts = poll.counts.expect("voter sees counts");
        assert_eq!(counts.iter().find(|c| c.answer_id == 0).unwrap().count, 0);
        assert_eq!(counts.iter().find(|c| c.answer_id == 1).unwrap().count, 1);
        assert_eq!(poll.total_votes, Some(1));

        // Retract — back to zero ballots
        let response = harness
            .client
            .delete(format!("/channels/{}/polls/{}/vote", channel.id(), poll_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let poll: v0::Poll = response.into_json().await.expect("`Poll`");
        // Author of the poll still sees counts
        let counts = poll.counts.expect("author sees counts");
        assert_eq!(counts.iter().find(|c| c.answer_id == 1).unwrap().count, 0);
        assert_eq!(poll.total_votes, Some(0));
    }

    #[rocket::async_test]
    async fn vote_validation_rejects_bad_ballots() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let message = create_poll(&harness, &session.token, channel.id(), false).await;
        let poll_id = message.poll.expect("poll").id;

        for body in [
            // Unknown answer id
            json!({ "answer_ids": [7] }),
            // Multiple answers on a single-select poll
            json!({ "answer_ids": [0, 1] }),
            // Empty ballot
            json!({ "answer_ids": [] }),
        ] {
            let response = harness
                .client
                .put(format!("/channels/{}/polls/{}/vote", channel.id(), poll_id))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
                .await;
            assert_ne!(response.status(), Status::Ok, "ballot should be rejected: {body}");
        }
    }

    #[rocket::async_test]
    async fn multiselect_ballot_counts_every_selection_once() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let message = create_poll(&harness, &session.token, channel.id(), true).await;
        let poll_id = message.poll.expect("poll").id;

        // Duplicate ids in the ballot are deduplicated
        let response = harness
            .client
            .put(format!("/channels/{}/polls/{}/vote", channel.id(), poll_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "answer_ids": [0, 1, 0] }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let poll: v0::Poll = response.into_json().await.expect("`Poll`");
        let counts = poll.counts.expect("voter sees counts");
        assert_eq!(counts.iter().find(|c| c.answer_id == 0).unwrap().count, 1);
        assert_eq!(counts.iter().find(|c| c.answer_id == 1).unwrap().count, 1);
        // One ballot, two selections
        assert_eq!(poll.total_votes, Some(1));
    }
}
