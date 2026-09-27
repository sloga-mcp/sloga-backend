use std::time::Duration;

use revolt_database::events::client::EventV1;
use revolt_database::util::idempotency::IdempotencyKey;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Channel, Database, Message, PartialChannel, User, AMQP};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionQuery};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

/// # Create Forum Post
///
/// Create a new post in a forum channel. A post is a thread whose starter
/// message is created in the same request; the starter message's id equals
/// the post's id.
#[openapi(tag = "Forums")]
#[post("/<target>/posts", data = "<data>")]
pub async fn create_forum_post(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataCreateForumPost>,
    idempotency: IdempotencyKey,
) -> Result<Json<v0::ForumPostResponse>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;
    data.message.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Posts can only be created in forum channels (this is also the E2EE
    // fail-closed gate — DMs/groups can never be forums).
    let forum = target.as_channel(db).await?;
    let Channel::Forum {
        tags,
        require_tag,
        server,
        ..
    } = &forum
    else {
        return Err(create_error!(InvalidOperation));
    };

    let mut query = DatabasePermissionQuery::new(db, &user).channel(&forum);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // Starter-message content permissions, mirroring message_send.
    if let Some(masq) = &data.message.masquerade {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::Masquerade)?;
        if masq.colour.is_some() {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageRole)?;
        }
    }
    if data.message.embeds.as_ref().is_some_and(|v| !v.is_empty()) {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::SendEmbeds)?;
    }
    if data
        .message
        .attachments
        .as_ref()
        .is_some_and(|v| !v.is_empty())
    {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::UploadFiles)?;
    }

    // Applied tags must reference the forum's tag definitions; moderated tags
    // need ManageChannel and require_tag forces at least one.
    crate::util::threads::validate_applied_tags(tags, &data.tags, *require_tag, &permissions)?;

    // Disallow mentions for new users (TRUST-0: <12 hours age) in public
    // servers, mirroring message_send.
    let allow_mentions = if let Some(server) = query.server_ref() {
        if server.discoverable {
            (ulid::Ulid::from_string(&user.id)
                .unwrap()
                .datetime()
                .elapsed()
                .expect("Time went backwards"))
                >= Duration::from_hours(12)
        } else {
            true
        }
    } else {
        true
    };

    // Build author objects for the event fan-out, mirroring message_send.
    let author: v0::User = user.clone().into(db, Some(&user)).await;

    query.are_we_a_member().await;

    let model_user = user
        .clone()
        .into_known_static(revolt_presence::is_online(&user.id).await)
        .await;
    let model_member: Option<v0::Member> = query
        .member_ref()
        .as_ref()
        .map(|member| member.clone().into_owned().into());

    // Create the post (thread) itself.
    let post = Channel::create_forum_post(
        db,
        &forum,
        &user,
        data.title,
        data.tags,
        data.auto_archive_minutes,
    )
    .await?;
    let post_id = post.id().to_string();

    // Create the starter message inside the post, pinning its id to the
    // post's id. If this fails the post is torn down again so no empty
    // post is left behind (best-effort — a crash between the two inserts
    // still leaves an empty post, which clients render gracefully).
    let message = match Message::create_from_api_with_id(
        db,
        Some(amqp),
        post.clone(),
        data.message,
        v0::MessageAuthor::User(&author),
        Some(model_user.clone()),
        model_member.clone(),
        user.limits().await,
        idempotency,
        permissions.has_channel_permission(ChannelPermission::SendEmbeds),
        allow_mentions,
        Some(post_id.clone()),
        None,
        true,
    )
    .await
    {
        Ok(message) => message,
        Err(error) => {
            post.delete(db).await.ok();
            return Err(error);
        }
    };

    // Bump the forum's activity marker so the existing unread machinery
    // lights up for a new post (replies inside posts intentionally do NOT
    // bump the forum). Only move it forward: two posts created together
    // could otherwise land out of order. The post and starter already exist,
    // so a failed bump must not fail the request — a retry would duplicate
    // the post.
    match db
        .set_last_message_id_if_newer(forum.id(), &message.id, false)
        .await
    {
        Ok(true) => {
            EventV1::ChannelUpdate {
                id: forum.id().to_string(),
                data: PartialChannel {
                    last_message_id: Some(message.id.clone()),
                    ..Default::default()
                }
                .into(),
                clear: vec![],
            }
            .p(server.clone())
            .await;
        }
        // A newer post already moved it (and broadcast it), or the forum is gone.
        Ok(false) => {}
        Err(error) => {
            revolt_config::capture_error(&error);
        }
    }

    // The forum's last_message_id is now at this post or a newer one; ack
    // this post for the author so their own post doesn't light the forum up
    // as unread.
    if user.bot.is_none() {
        if let Err(error) = forum.ack(&user.id, &message.id, amqp).await {
            revolt_config::capture_error(&error);
        }
    }

    Ok(Json(v0::ForumPostResponse {
        post: post.into(),
        message: message.into_model(Some(model_user), model_member),
    }))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{Channel, ForumTag};
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};

    async fn new_forum(harness: &TestHarness, server: &mut revolt_database::Server) -> Channel {
        Channel::create_server_channel(
            &harness.db,
            server,
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Forum,
                name: "forum".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("forum created")
    }

    #[test]
    fn create_post_creates_thread_and_pinned_starter() {
        crate::util::test::rt().block_on(create_post_creates_thread_and_pinned_starter_case())
    }

    async fn create_post_creates_thread_and_pinned_starter_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&user).await;
        let forum = new_forum(&harness, &mut server).await;

        let response = harness
            .client
            .post(format!("/channels/{}/posts", forum.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "title": "My first post",
                    "message": { "content": "hello forum" }
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let body: v0::ForumPostResponse =
            response.into_json().await.expect("forum post response");

        // The post is a thread under the forum.
        let post_id = match &body.post {
            v0::Channel::Thread {
                id, parent_channel, ..
            } => {
                assert_eq!(parent_channel, forum.id());
                id.clone()
            }
            other => panic!("expected a thread, got {:?}", other),
        };

        // The starter message's id is pinned to the post's id.
        assert_eq!(body.message.id, post_id);
        let starter = harness
            .db
            .fetch_message(&post_id)
            .await
            .expect("starter message");
        assert_eq!(starter.channel, post_id);

        // The forum's activity marker was bumped to the starter.
        let forum = harness
            .db
            .fetch_channel(forum.id())
            .await
            .expect("refetch forum");
        assert!(
            matches!(forum, Channel::Forum { last_message_id: Some(ref id), .. } if id == &post_id)
        );
    }

    #[test]
    fn create_post_enforces_tag_rules() {
        crate::util::test::rt().block_on(create_post_enforces_tag_rules_case())
    }

    async fn create_post_enforces_tag_rules_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&user).await;
        let mut forum = new_forum(&harness, &mut server).await;

        // Configure one moderated tag and require tags on every post.
        let tag = ForumTag {
            id: ulid::Ulid::new().to_string(),
            name: "announcements".to_string(),
            emoji: None,
            moderated: true,
        };
        forum
            .update(
                &harness.db,
                revolt_database::PartialChannel {
                    tags: Some(vec![tag.clone()]),
                    require_tag: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("configure forum");

        // Missing tags while require_tag is on → rejected.
        let response = harness
            .client
            .post(format!("/channels/{}/posts", forum.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "title": "untagged", "message": { "content": "hi" } }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Unknown tag id → rejected.
        let response = harness
            .client
            .post(format!("/channels/{}/posts", forum.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "title": "bogus tag",
                    "tags": ["01AAAAAAAAAAAAAAAAAAAAAAAA"],
                    "message": { "content": "hi" }
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // The server owner holds ManageChannel, so the moderated tag is fine.
        let response = harness
            .client
            .post(format!("/channels/{}/posts", forum.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "title": "tagged",
                    "tags": [tag.id],
                    "message": { "content": "hi" }
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    fn direct_message_send_to_forum_is_rejected() {
        crate::util::test::rt().block_on(direct_message_send_to_forum_is_rejected_case())
    }

    async fn direct_message_send_to_forum_is_rejected_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&user).await;
        let forum = new_forum(&harness, &mut server).await;

        let response = harness
            .client
            .post(format!("/channels/{}/messages", forum.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "content": "direct send" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
    }

    /// POST a forum post over HTTP, optionally with an explicit
    /// `auto_archive_minutes`.
    async fn post_forum_post<'c>(
        harness: &'c TestHarness,
        token: &str,
        forum: &Channel,
        title: &str,
        auto_archive_minutes: Option<u32>,
    ) -> rocket::local::asynchronous::LocalResponse<'c> {
        let mut body = json!({ "title": title, "message": { "content": "hi" } });
        if let Some(minutes) = auto_archive_minutes {
            body["auto_archive_minutes"] = json!(minutes);
        }
        harness
            .client
            .post(format!("/channels/{}/posts", forum.id()))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await
    }

    /// Extract `(id, auto_archive_minutes)` from a successful create response.
    async fn post_archive_minutes(
        response: rocket::local::asynchronous::LocalResponse<'_>,
    ) -> (String, u32) {
        assert_eq!(response.status(), Status::Ok);
        let body: v0::ForumPostResponse =
            response.into_json().await.expect("forum post response");
        match body.post {
            v0::Channel::Thread {
                id,
                auto_archive_minutes,
                ..
            } => (id, auto_archive_minutes),
            other => panic!("expected a thread, got {:?}", other),
        }
    }

    /// The stored thread's `auto_archive_minutes`.
    async fn stored_archive_minutes(harness: &TestHarness, id: &str) -> u32 {
        match harness.db.fetch_channel(id).await.expect("stored post") {
            Channel::Thread {
                auto_archive_minutes,
                ..
            } => auto_archive_minutes,
            other => panic!("expected a thread, got {:?}", other),
        }
    }

    #[test]
    fn create_post_uses_forum_default_auto_archive() {
        crate::util::test::rt().block_on(create_post_uses_forum_default_auto_archive_case())
    }

    async fn create_post_uses_forum_default_auto_archive_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&user).await;
        let mut forum = new_forum(&harness, &mut server).await;

        // Fresh forum → the built-in forum default (7 days).
        let response = post_forum_post(&harness, &session.token, &forum, "a", None).await;
        let (id, minutes) = post_archive_minutes(response).await;
        assert_eq!(minutes, 10080);
        assert_eq!(stored_archive_minutes(&harness, &id).await, 10080);

        // Configured forum default is inherited by posts that omit it.
        forum
            .update(
                &harness.db,
                revolt_database::PartialChannel {
                    default_auto_archive_minutes: Some(129600),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("configure forum default");

        let response = post_forum_post(&harness, &session.token, &forum, "b", None).await;
        let (id, minutes) = post_archive_minutes(response).await;
        assert_eq!(minutes, 129600);
        assert_eq!(stored_archive_minutes(&harness, &id).await, 129600);
    }

    #[test]
    fn create_post_validates_explicit_auto_archive() {
        crate::util::test::rt().block_on(create_post_validates_explicit_auto_archive_case())
    }

    async fn create_post_validates_explicit_auto_archive_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&user).await;
        let forum = new_forum(&harness, &mut server).await;

        // 0 = Never, and the new 90-day option, are both accepted and stored.
        for minutes in [0u32, 129600] {
            let response =
                post_forum_post(&harness, &session.token, &forum, "ok", Some(minutes)).await;
            let (id, returned) = post_archive_minutes(response).await;
            assert_eq!(returned, minutes);
            assert_eq!(stored_archive_minutes(&harness, &id).await, minutes);
        }

        // Off-allowlist durations are rejected.
        let response = post_forum_post(&harness, &session.token, &forum, "bad", Some(30)).await;
        assert_eq!(response.status(), Status::BadRequest);
        let error: serde_json::Value = response.into_json().await.expect("error body");
        assert_eq!(error["type"], "InvalidProperty");
    }

    #[test]
    fn create_post_is_exempt_from_thread_cap() {
        crate::util::test::rt().block_on(create_post_is_exempt_from_thread_cap_case())
    }

    async fn create_post_is_exempt_from_thread_cap_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&user).await;
        let forum = new_forum(&harness, &mut server).await;

        // Fill the forum up to the per-channel thread cap directly (the HTTP
        // route is rate-limited), all of them active.
        let cap = revolt_config::config()
            .await
            .features
            .limits
            .global
            .threads_per_channel;
        for i in 0..cap {
            Channel::create_forum_post(
                &harness.db,
                &forum,
                &user,
                format!("post {i}"),
                vec![],
                None,
            )
            .await
            .expect("direct post created");
        }

        // One more post over HTTP still succeeds: forums are uncapped.
        let response = post_forum_post(&harness, &session.token, &forum, "over", None).await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    fn never_archive_post_is_not_an_active_thread() {
        crate::util::test::rt().block_on(never_archive_post_is_not_an_active_thread_case())
    }

    async fn never_archive_post_is_not_an_active_thread_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&user).await;
        let forum = new_forum(&harness, &mut server).await;

        let response = post_forum_post(&harness, &session.token, &forum, "never", Some(0)).await;
        let (never_id, _) = post_archive_minutes(response).await;
        let response = post_forum_post(&harness, &session.token, &forum, "day", Some(1440)).await;
        let (day_id, _) = post_archive_minutes(response).await;

        let active: Vec<String> = harness
            .db
            .fetch_active_threads()
            .await
            .expect("active threads")
            .iter()
            .map(|channel| channel.id().to_string())
            .collect();
        assert!(!active.contains(&never_id));
        assert!(active.contains(&day_id));
    }
}
