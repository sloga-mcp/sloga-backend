use std::collections::HashSet;

use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Channel, Database, Poll, ProtectedReadView, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, ErrorType, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

use crate::util::polls::{can_see_counts, now_ms};

/// Whether a read of `channel` (`permission_channel` is its permission
/// target) may serve `poll`: only while its parent message is servable
/// (`Message::is_servable`), so the poll of a wipe-pending row answers like
/// a poll of another channel (design 7.4 "S4"). An unprotected view serves
/// every row, so only a protected one reads the parent; a missing parent is
/// not served.
pub(super) async fn poll_is_servable(
    db: &Database,
    channel: &Channel,
    permission_channel: &Channel,
    poll: &Poll,
) -> Result<bool> {
    let view = ProtectedReadView::of_read_target(channel, permission_channel);
    if !view.protected {
        return Ok(true);
    }

    match db.fetch_message(&poll.message).await {
        Ok(message) => Ok(message.is_servable(&view)),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

/// [`poll_is_servable`] for a page of polls, in one read: drops every poll
/// the read may not serve
async fn retain_servable_polls(
    db: &Database,
    channel: &Channel,
    permission_channel: &Channel,
    polls: &mut Vec<Poll>,
) -> Result<()> {
    let view = ProtectedReadView::of_read_target(channel, permission_channel);
    if !view.protected || polls.is_empty() {
        return Ok(());
    }

    let ids: Vec<String> = polls.iter().map(|poll| poll.message.clone()).collect();
    let servable: HashSet<String> = db
        .fetch_messages_by_id(&ids)
        .await?
        .into_iter()
        .filter(|message| message.is_servable(&view))
        .map(|message| message.id)
        .collect();
    polls.retain(|poll| servable.contains(&poll.message));
    Ok(())
}

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
    if poll.channel != channel.id()
        || !poll_is_servable(db, &channel, &permission_channel, &poll).await?
    {
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
    // ...and whose parent message the channel still serves (design 7.4 "S4")
    retain_servable_polls(db, &channel, &permission_channel, &mut polls).await?;

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

    #[test]
    fn results_hidden_until_vote_and_public_after_close() {
        crate::util::test::rt().block_on(results_hidden_until_vote_and_public_after_close_case())
    }

    async fn results_hidden_until_vote_and_public_after_close_case() {
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

    #[test]
    fn outsider_and_cross_channel_access_rejected() {
        crate::util::test::rt().block_on(outsider_and_cross_channel_access_rejected_case())
    }

    async fn outsider_and_cross_channel_access_rejected_case() {
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

    #[test]
    fn bulk_fetch_gates_per_poll() {
        crate::util::test::rt().block_on(bulk_fetch_gates_per_poll_case())
    }

    async fn bulk_fetch_gates_per_poll_case() {
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

/// Protected channels (S4): the world the poll routes' protected tests share
#[cfg(test)]
pub(super) mod protected_fixture {
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        Channel, HistoryWipe, Message, PartialChannel, Poll, PollVote, Session, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Method, Status};
    use serde_json::Value;
    use ulid::Ulid;

    use crate::util::polls::now_ms;
    use crate::util::test::{ProtectedChannel, TestHarness};

    /// What [`world`] built
    pub struct World {
        pub harness: TestHarness,
        /// Protected with its history kept: the boundary B is `poll`'s row
        pub protected: ProtectedChannel,
        /// An unprotected channel of the same server
        pub ordinary: Channel,
        pub owner: User,
        pub owner_session: Session,
        /// Seated in the protected channel
        pub member: User,
        pub member_session: Session,
        /// An open poll by the owner in the protected channel, carried by
        /// the pre-protect row B; the member voted for answer 0
        pub poll: Poll,
        /// The same in the ordinary channel
        pub ordinary_poll: Poll,
    }

    /// An open poll by `author` carried by the plaintext row `message_id`
    /// of `channel`, both stored raw (as pre-protect history leaves them),
    /// with `voter`'s ballot for answer 0
    pub async fn new_poll(
        harness: &TestHarness,
        channel: &Channel,
        server_id: &str,
        author: &User,
        voter: &User,
        message_id: &str,
    ) -> Poll {
        harness
            .insert_raw_message(&Message {
                id: message_id.to_string(),
                channel: channel.id().to_string(),
                author: author.id.clone(),
                content: Some("Best crab?".to_string()),
                ..Default::default()
            })
            .await;

        let answer = |id: u8, text: &str| v0::PollAnswer {
            id,
            text: text.to_string(),
            emoji: None,
        };
        let poll = Poll {
            id: Ulid::new().to_string(),
            message: message_id.to_string(),
            channel: channel.id().to_string(),
            server: Some(server_id.to_string()),
            author: author.id.clone(),
            question: "Best crab?".to_string(),
            answers: vec![answer(0, "Ferris"), answer(1, "Sebastian")],
            allow_multiselect: false,
            expires_at: now_ms() + 60 * 60 * 1000,
            closed: false,
            counts: Default::default(),
            total_votes: 0,
        };
        harness.db.insert_poll(&poll).await.expect("`Poll`");
        harness
            .db
            .upsert_poll_vote(&PollVote {
                id: Poll::vote_key(&poll.id, &voter.id),
                poll: poll.id.clone(),
                user: voter.id.clone(),
                channel: poll.channel.clone(),
                answer_ids: vec![0],
            })
            .await
            .expect("`PollVote`");
        poll
    }

    /// A protected channel whose kept history holds an open poll (left open
    /// as a failed best-effort close would leave it), and an ordinary
    /// channel of the same server holding another
    pub async fn world() -> World {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let ordinary = harness.new_channel(&protected.server).await;
        let server_id = protected.server.id.clone();

        // Ten minutes ago: the poll's row is the newest pre-protect row, B
        let boundary = Ulid::from_parts(Ulid::new().timestamp_ms() - 600_000, 0).to_string();
        let poll = new_poll(
            &harness,
            &protected.channel,
            &server_id,
            &owner,
            &member,
            &boundary,
        )
        .await;
        let ordinary_poll = new_poll(
            &harness,
            &ordinary,
            &server_id,
            &owner,
            &member,
            &Ulid::new().to_string(),
        )
        .await;
        let channel = harness
            .protect_with_history_raw(protected.channel.id(), &boundary, HistoryWipe::None)
            .await;

        World {
            harness,
            protected: ProtectedChannel {
                channel,
                ..protected
            },
            ordinary,
            owner,
            owner_session,
            member,
            member_session,
            poll,
            ordinary_poll,
        }
    }

    /// Move the protected channel's wipe to `Requested`: from here on its
    /// pre-boundary rows are wipe-pending (S4-D21)
    pub async fn request_the_wipe(world: &World) {
        world
            .harness
            .protect_with_history_raw(
                world.protected.channel.id(),
                &world.poll.message,
                HistoryWipe::Requested {
                    at: Timestamp::now_utc(),
                    by: world.owner.id.clone(),
                },
            )
            .await;
    }

    /// The route's answer: status and JSON body (`Null` when there is none)
    pub async fn request(
        harness: &TestHarness,
        session: &Session,
        method: Method,
        path: String,
        body: Option<Value>,
    ) -> (Status, Value) {
        let mut request = harness
            .client
            .req(method, path)
            .header(Header::new("x-session-token", session.token.to_string()));
        if let Some(body) = body {
            request = request.header(ContentType::JSON).body(body.to_string());
        }
        let response = request.dispatch().await;
        let status = response.status();
        let body = response.into_json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }

    #[track_caller]
    pub fn assert_refused(answer: &(Status, Value), status: Status, error: &str, case: &str) {
        assert_eq!(answer.0, status, "{case}: {}", answer.1);
        assert_eq!(answer.1["type"], error, "{case}: {}", answer.1);
    }

    /// A thread under `parent`, for a raw insert (2.5 "Race closure": no
    /// route creates one under a protected parent)
    pub fn thread_under(parent: &Channel, server_id: &str, creator: &User) -> Channel {
        Channel::Thread {
            id: Ulid::new().to_string(),
            server: server_id.to_string(),
            parent_channel: parent.id().to_string(),
            name: "Thread".to_string(),
            creator: creator.id.clone(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: 0,
            locked: false,
            applied_tags: vec![],
        }
    }

    pub async fn deny_view(harness: &TestHarness, channel_id: &str) {
        harness
            .db
            .fetch_channel(channel_id)
            .await
            .expect("the channel")
            .update(
                &harness.db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ViewChannel as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny view");
    }
}

/// Protected channels (S4): a poll of a wipe-pending row is not served
#[cfg(test)]
mod protected_test {
    use rocket::http::{Method, Status};
    use serde_json::{json, Value};

    use super::protected_fixture::{
        assert_refused, deny_view, request, request_the_wipe, world, World,
    };

    async fn fetch(world: &World, channel_id: &str, poll_id: &str) -> (Status, Value) {
        request(
            &world.harness,
            &world.member_session,
            Method::Get,
            format!("/channels/{channel_id}/polls/{poll_id}"),
            None,
        )
        .await
    }

    async fn fetch_bulk(world: &World, channel_id: &str, poll_id: &str) -> (Status, Value) {
        request(
            &world.harness,
            &world.member_session,
            Method::Post,
            format!("/channels/{channel_id}/polls/fetch"),
            Some(json!({ "ids": [poll_id] })),
        )
        .await
    }

    /// Design 7.4 "S4": while the history is kept, the poll of the
    /// pre-boundary row B is served by the single and the bulk fetch; from
    /// `Requested` on, the single fetch answers exactly as for a poll of
    /// another channel and the bulk fetch drops it. The ordinary channel's
    /// poll is served throughout.
    #[test]
    fn a_wipe_pending_poll_answers_not_found() {
        crate::util::test::rt().block_on(Box::pin(a_wipe_pending_poll_answers_not_found_case()))
    }

    async fn a_wipe_pending_poll_answers_not_found_case() {
        let w = world().await;
        let channel_id = w.protected.channel.id();

        let kept = fetch(&w, channel_id, &w.poll.id).await;
        assert_eq!(kept.0, Status::Ok, "kept: {}", kept.1);
        assert_eq!(kept.1["_id"], w.poll.id.as_str(), "kept: {}", kept.1);
        let kept = fetch_bulk(&w, channel_id, &w.poll.id).await;
        assert_eq!(kept.0, Status::Ok, "kept bulk: {}", kept.1);
        assert_eq!(
            kept.1.as_array().map(Vec::len),
            Some(1),
            "kept bulk: {}",
            kept.1
        );

        request_the_wipe(&w).await;

        let foreign = fetch(&w, channel_id, &w.ordinary_poll.id).await;
        assert_refused(&foreign, Status::NotFound, "NotFound", "a foreign poll");
        assert_eq!(
            fetch(&w, channel_id, &w.poll.id).await,
            foreign,
            "wipe pending"
        );
        assert_eq!(
            fetch_bulk(&w, channel_id, &w.poll.id).await,
            (Status::Ok, json!([])),
            "wipe pending bulk"
        );

        // Only the answer changed: the job deletes the poll, not the read
        let stored = w.harness.db.fetch_poll(&w.poll.id).await.expect("poll");
        assert!(!stored.closed, "the read wrote the poll");

        let ordinary = fetch(&w, w.ordinary.id(), &w.ordinary_poll.id).await;
        assert_eq!(ordinary.0, Status::Ok, "ordinary: {}", ordinary.1);
        let ordinary = fetch_bulk(&w, w.ordinary.id(), &w.ordinary_poll.id).await;
        assert_eq!(
            ordinary.1.as_array().map(Vec::len),
            Some(1),
            "{}",
            ordinary.1
        );
    }

    /// Decision 18: every poll route answers a caller who cannot view the
    /// channel byte-identically for a protected (wipe-pending) and an
    /// ordinary channel, and a missing channel as before
    #[test]
    fn every_poll_route_answers_a_non_viewer_as_before() {
        crate::util::test::rt().block_on(Box::pin(
            every_poll_route_answers_a_non_viewer_as_before_case(),
        ))
    }

    async fn every_poll_route_answers_a_non_viewer_as_before_case() {
        let w = world().await;
        request_the_wipe(&w).await;
        deny_view(&w.harness, w.protected.channel.id()).await;
        deny_view(&w.harness, w.ordinary.id()).await;
        let missing = ulid::Ulid::new().to_string();

        let routes = [
            (Method::Put, "/vote"),
            (Method::Delete, "/vote"),
            (Method::Post, "/end"),
            (Method::Get, ""),
            (Method::Get, "/voters?answer_id=0"),
            (Method::Post, "/fetch"),
        ];
        for (method, suffix) in routes {
            let case = format!("{method} {suffix}");
            let mut answers = Vec::new();
            for (channel_id, poll) in [
                (w.ordinary.id(), &w.ordinary_poll),
                (w.protected.channel.id(), &w.poll),
                (missing.as_str(), &w.poll),
            ] {
                let (path, body) = match (method, suffix) {
                    (Method::Post, "/fetch") => (
                        format!("/channels/{channel_id}/polls/fetch"),
                        Some(json!({ "ids": [poll.id] })),
                    ),
                    (Method::Put, _) => (
                        format!("/channels/{channel_id}/polls/{}{suffix}", poll.id),
                        Some(json!({ "answer_ids": [1] })),
                    ),
                    _ => (
                        format!("/channels/{channel_id}/polls/{}{suffix}", poll.id),
                        None,
                    ),
                };
                answers.push(request(&w.harness, &w.member_session, method, path, body).await);
            }

            assert_refused(&answers[0], Status::Forbidden, "MissingPermission", &case);
            assert_eq!(answers[1], answers[0], "{case}: protected vs ordinary");
            assert_refused(&answers[2], Status::NotFound, "NotFound", &case);
        }
    }
}
