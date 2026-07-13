use std::time::Duration;

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
        tags, require_tag, ..
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
    // bump the forum). The post and starter already exist, so a failed bump
    // must not fail the request — a retry would duplicate the post.
    let mut forum = forum;
    if let Err(error) = forum
        .update(
            db,
            PartialChannel {
                last_message_id: Some(message.id.clone()),
                ..Default::default()
            },
            vec![],
        )
        .await
    {
        revolt_config::capture_error(&error);
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

    #[rocket::async_test]
    async fn create_post_creates_thread_and_pinned_starter() {
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

    #[rocket::async_test]
    async fn create_post_enforces_tag_rules() {
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

    #[rocket::async_test]
    async fn direct_message_send_to_forum_is_rejected() {
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
}
