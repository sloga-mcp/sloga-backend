use std::collections::{HashMap, HashSet};

use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, ForumSortOrder, Message, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// Sort key for ordering posts by most recent activity, falling back to the
/// post's own (creation-ordered) id when it has no messages yet.
fn activity_key(channel: &Channel) -> &str {
    match channel {
        Channel::Thread {
            last_message_id,
            id,
            ..
        } => last_message_id.as_deref().unwrap_or(id),
        _ => channel.id(),
    }
}

/// Sort key for ordering posts alphabetically.
///
/// Names are not unique and the cursor pages on this key, so a bare name would
/// let two identically named posts skip or repeat each other across a page
/// boundary. Appending the id makes the key total. NUL sorts below every
/// printable byte, so it can only break ties, never reorder distinct names.
fn alphabetical_key(channel: &Channel) -> String {
    let name = match channel {
        Channel::Thread { name, .. } => name.as_str(),
        _ => "",
    };

    format!("{}\0{}", name.to_lowercase(), channel.id())
}

/// How a forum's posts are ordered.
#[derive(Clone, Copy, PartialEq)]
enum ForumSort {
    LatestActivity,
    CreationDate,
    Alphabetical,
}

/// # Fetch Forum Posts
///
/// Fetch the posts of a forum channel.
///
/// `sort` is `latest_activity` (default), `creation_date` or `alphabetical`;
/// `alphabetical` lists A-Z (ascending), the other two list newest first.
/// A forum with `force_sort` set ignores `sort` and answers in its own
/// `default_sort` — an unreadable `sort` is still rejected, so a client that
/// asks for nonsense hears about it either way.
/// `tag` filters to
/// posts carrying the given tag id; `archived=true` lists archived posts
/// instead of active ones; `before` is a cursor on the sort key, except under
/// `alphabetical` where it is the last post's id; `limit`
/// (1-100, default 50) bounds the page size. Pass `include_starters=true` to
/// also receive each post's starter message (its id equals the post's id).
///
/// Pass `include_stats=true` to also receive each post's reply count and
/// latest message (`stats` and `last_messages`); both need
/// ReadMessageHistory and are absent without it. Pass `include_users=true`
/// to also receive the users (and members) this page refers to: the creator
/// of every post and, with ReadMessageHistory, the authors of the returned
/// starters and latest messages.
#[openapi(tag = "Forums")]
#[get(
    "/<target>/posts?<sort>&<tag>&<archived>&<before>&<limit>&<include_starters>&<include_stats>&<include_users>"
)]
#[allow(clippy::too_many_arguments)]
pub async fn fetch_forum_posts(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    sort: Option<String>,
    tag: Option<String>,
    archived: Option<bool>,
    before: Option<String>,
    limit: Option<u32>,
    include_starters: Option<bool>,
    include_stats: Option<bool>,
    include_users: Option<bool>,
) -> Result<Json<v0::ForumPostsResponse>> {
    let channel = target.as_channel(db).await?;
    if !matches!(channel, Channel::Forum { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    // Post titles and tags are channel metadata, visible with ViewChannel like
    // the channel list. The starter messages are message content, so they
    // follow the same ReadMessageHistory rule as fetching messages does.
    let can_read_history =
        permissions.has_channel_permission(ChannelPermission::ReadMessageHistory);

    let requested = match sort.as_deref() {
        None | Some("latest_activity") => ForumSort::LatestActivity,
        Some("creation_date") => ForumSort::CreationDate,
        Some("alphabetical") => ForumSort::Alphabetical,
        _ => return Err(create_error!(InvalidProperty)),
    };

    // A forum can impose its order on everyone (an info board wants one
    // listing, not a per-member preference). Enforced here rather than left to
    // the client: a forced order that any caller can sort away from is not a
    // forced order. The requested value is still parsed above, so a malformed
    // `sort` is rejected whether or not this forum forces one.
    let order = match &channel {
        Channel::Forum {
            default_sort,
            force_sort: true,
            ..
        } => match default_sort {
            ForumSortOrder::LatestActivity => ForumSort::LatestActivity,
            ForumSortOrder::CreationDate => ForumSort::CreationDate,
            ForumSortOrder::Alphabetical => ForumSort::Alphabetical,
        },
        _ => requested,
    };

    // A-Z reads in ascending order; the time-based orders read newest first.
    let ascending = order == ForumSort::Alphabetical;

    let sort_key = |post: &Channel| -> String {
        match order {
            ForumSort::CreationDate => post.id().to_string(),
            ForumSort::LatestActivity => activity_key(post).to_string(),
            ForumSort::Alphabetical => alphabetical_key(post),
        }
    };

    let want_archived = archived.unwrap_or(false);
    let mut posts: Vec<Channel> = db
        .fetch_threads_by_parent(channel.id())
        .await?
        .into_iter()
        .filter(|post| {
            matches!(post, Channel::Thread { archived, .. } if *archived == want_archived)
        })
        .filter(|post| match (&tag, post) {
            (Some(tag), Channel::Thread { applied_tags, .. }) => applied_tags.contains(tag),
            _ => true,
        })
        .collect();

    // The cursor pages on the same key the list is sorted by, otherwise
    // pagination skips or duplicates entries.
    //
    // For the time-based orders the caller passes that key directly, as it
    // always has. For A-Z it passes the last post's *id* instead, which is
    // resolved to a key here: the alphabetical key embeds a NUL separator and
    // there is no safe way to spell that in a query string. Resolving it here
    // also spares clients from having to reproduce the key format.
    let cursor = match (&before, ascending) {
        (Some(before), true) => posts
            .iter()
            .find(|post| post.id() == before)
            .map(|post| sort_key(post)),
        (Some(before), false) => Some(before.clone()),
        (None, _) => None,
    };

    // An unresolvable A-Z cursor (the post was deleted, or the tag filter
    // excludes it) yields the first page rather than an error, which is the
    // same thing a stale time cursor does.
    if let Some(cursor) = cursor {
        if ascending {
            posts.retain(|post| sort_key(post) > cursor);
        } else {
            posts.retain(|post| sort_key(post) < cursor);
        }
    }

    if ascending {
        posts.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    } else {
        posts.sort_by(|a, b| sort_key(b).cmp(&sort_key(a)));
    }

    let limit = limit.unwrap_or(50).clamp(1, 100) as usize;
    posts.truncate(limit);

    let post_ids: Vec<String> = posts.iter().map(|post| post.id().to_string()).collect();

    // Starter messages are pinned to their post's id, so the whole page
    // resolves in one bulk fetch. A caller without ReadMessageHistory gets an
    // empty list rather than an error, so the post list itself still renders.
    // A starter that was deleted is simply missing from the list.
    let starters: Option<Vec<Message>> = if include_starters.unwrap_or(false) && !can_read_history {
        Some(Vec::new())
    } else if include_starters.unwrap_or(false) {
        Some(db.fetch_messages_by_id(&post_ids).await?)
    } else {
        None
    };

    // Reply counts and latest messages are message history too, so they
    // follow the same rule as the starters, except that a caller without
    // ReadMessageHistory gets no field at all: an empty list would read as
    // "no replies". Computed for this page's posts only, from the messages
    // themselves, so a deleted reply never counts and never shows as the
    // latest one (the stored `last_message_id` that the activity sort uses is
    // not rolled back on delete, so a row can occasionally look out of order).
    let (stats, last_messages) = if include_stats.unwrap_or(false) && can_read_history {
        let mut by_post: HashMap<String, _> = db
            .fetch_thread_stats(&post_ids)
            .await?
            .into_iter()
            .map(|stats| (stats.channel.clone(), stats))
            .collect();

        // Exactly one entry per returned post, even if the driver left one out.
        let stats: Vec<v0::ForumPostStats> = post_ids
            .iter()
            .map(|id| {
                let found = by_post.remove(id);
                v0::ForumPostStats {
                    id: id.clone(),
                    replies: found.as_ref().map_or(0, |stats| stats.replies),
                    last_message_id: found.and_then(|stats| stats.last_message_id),
                }
            })
            .collect();

        let last_ids: Vec<String> = stats
            .iter()
            .filter_map(|stats| stats.last_message_id.clone())
            .collect();
        let page: HashSet<&str> = post_ids.iter().map(String::as_str).collect();
        let last_messages: Vec<Message> = if last_ids.is_empty() {
            Vec::new()
        } else {
            db.fetch_messages_by_id(&last_ids)
                .await?
                .into_iter()
                .filter(|message| page.contains(message.channel.as_str()))
                .collect()
        };

        (Some(stats), Some(last_messages))
    } else {
        (None, None)
    };

    // The creator of a post is channel metadata, shown with ViewChannel like
    // the title, so every post's creator is included. The authors of the
    // starters and latest messages are only included when those messages are
    // in this response, which already required ReadMessageHistory. A webhook
    // message's author id is the webhook's, not a user's, so it is skipped.
    let (users, members) = if include_users.unwrap_or(false) {
        let mut ids: Vec<String> = posts
            .iter()
            .filter_map(|post| match post {
                Channel::Thread { creator, .. } => Some(creator.clone()),
                _ => None,
            })
            .collect();

        if can_read_history {
            let authored: Vec<Message> = starters
                .iter()
                .flatten()
                .chain(last_messages.iter().flatten())
                .filter(|message| message.webhook.is_none())
                .cloned()
                .collect();
            ids.extend(Message::referenced_user_ids(&authored));
        }

        ids.sort();
        ids.dedup();

        let users = User::fetch_many_ids_as_mutuals(db, &user, &ids).await?;
        let members = match &channel {
            Channel::Forum { server, .. } => Some(
                db.fetch_members(server, &ids)
                    .await?
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            ),
            _ => None,
        };

        (Some(users), members)
    } else {
        (None, None)
    };

    Ok(Json(v0::ForumPostsResponse {
        posts: posts.into_iter().map(Into::into).collect(),
        starters: starters.map(|messages| {
            messages
                .into_iter()
                .map(|message| message.into_model(None, None))
                .collect()
        }),
        stats,
        last_messages: last_messages.map(|messages| {
            messages
                .into_iter()
                .map(|message| message.into_model(None, None))
                .collect()
        }),
        users,
        members,
    }))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{Channel, Member, Message, PartialChannel, Server, User};
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use ulid::Ulid;

    #[test]
    fn posts_list_pages_and_inlines_starters() {
        crate::util::test::rt().block_on(posts_list_pages_and_inlines_starters_case())
    }

    async fn posts_list_pages_and_inlines_starters_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&user).await;
        let forum = Channel::create_server_channel(
            &harness.db,
            &mut server,
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Forum,
                name: "forum".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("forum created");

        for index in 0..3 {
            let response = harness
                .client
                .post(format!("/channels/{}/posts", forum.id()))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(
                    json!({
                        "title": format!("post {index}"),
                        "message": { "content": format!("starter {index}") }
                    })
                    .to_string(),
                )
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
        }

        let response = harness
            .client
            .get(format!(
                "/channels/{}/posts?include_starters=true",
                forum.id()
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let body: v0::ForumPostsResponse = response.into_json().await.expect("posts response");
        assert_eq!(body.posts.len(), 3);

        // Every post has its starter inlined, matched by id.
        let starters = body.starters.expect("starters included");
        assert_eq!(starters.len(), 3);
        for post in &body.posts {
            let id = match post {
                v0::Channel::Thread { id, .. } => id,
                other => panic!("expected thread, got {:?}", other),
            };
            assert!(
                starters.iter().any(|starter| &starter.id == id),
                "starter missing for post {}",
                id
            );
        }

        // Paging: limit 2, then cursor past the newest two.
        let response = harness
            .client
            .get(format!("/channels/{}/posts?limit=2", forum.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let page: v0::ForumPostsResponse = response.into_json().await.expect("page 1");
        assert_eq!(page.posts.len(), 2);
    }

    #[test]
    fn starters_need_read_message_history() {
        crate::util::test::rt().block_on(starters_need_read_message_history_case())
    }

    /// The listing used to check ViewChannel only, so a member denied
    /// ReadMessageHistory could read every post's opening message through
    /// `include_starters`.
    async fn starters_need_read_message_history_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&owner).await;
        let mut forum = Channel::create_server_channel(
            &harness.db,
            &mut server,
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Forum,
                name: "forum".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("forum created");
        Member::create(&harness.db, &server, &member, None)
            .await
            .expect("member");

        let response = harness
            .client
            .post(format!("/channels/{}/posts", forum.id()))
            .header(Header::new("x-session-token", owner_session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "title": "rules",
                    "message": { "content": "members-only history" }
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let url = format!("/channels/{}/posts?include_starters=true", forum.id());
        let fetch = |token: String| {
            let client = &harness.client;
            let url = url.clone();
            async move {
                let response = client
                    .get(url)
                    .header(Header::new("x-session-token", token))
                    .dispatch()
                    .await;
                assert_eq!(response.status(), Status::Ok);
                response
                    .into_json::<v0::ForumPostsResponse>()
                    .await
                    .expect("posts response")
            }
        };

        // Control: with the default permissions the member sees the starter.
        let body = fetch(member_session.token.to_string()).await;
        assert_eq!(body.posts.len(), 1);
        assert_eq!(body.starters.expect("starters").len(), 1);

        forum
            .update(
                &harness.db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ReadMessageHistory as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny history");

        // Denied history: the post is still listed, its content is not.
        let body = fetch(member_session.token.to_string()).await;
        assert_eq!(body.posts.len(), 1, "titles stay visible with ViewChannel");
        assert!(
            body.starters.expect("starters requested").is_empty(),
            "starter content must not leak without ReadMessageHistory"
        );

        // Nor through fetching the starter by id: the listing just handed
        // out the post id, and it is also the starter message's id.
        let post_id = match &body.posts[0] {
            v0::Channel::Thread { id, .. } => id.clone(),
            other => panic!("expected thread, got {:?}", other),
        };
        let response = harness
            .client
            .get(format!("/channels/{post_id}/messages/{post_id}"))
            .header(Header::new("x-session-token", member_session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::Forbidden,
            "fetching the starter by id must need ReadMessageHistory too"
        );

        // The owner bypasses the override and still gets it.
        let body = fetch(owner_session.token.to_string()).await;
        assert_eq!(body.starters.expect("starters").len(), 1);
    }
    #[test]
    fn posts_sort_alphabetically() {
        crate::util::test::rt().block_on(posts_sort_alphabetically_case())
    }

    async fn posts_sort_alphabetically_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&user).await;
        let forum = Channel::create_server_channel(
            &harness.db,
            &mut server,
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Forum,
                name: "forum".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("forum created");

        // Created out of alphabetical order and in mixed case, so a pass
        // cannot be explained by creation order or by a case-sensitive sort
        // that happens to agree.
        for title in ["Cherry", "apple", "Banana"] {
            let response = harness
                .client
                .post(format!("/channels/{}/posts", forum.id()))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(
                    json!({
                        "title": title,
                        "message": { "content": "starter" }
                    })
                    .to_string(),
                )
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
        }

        let names = |body: &v0::ForumPostsResponse| -> Vec<String> {
            body.posts
                .iter()
                .map(|post| match post {
                    v0::Channel::Thread { name, .. } => name.clone(),
                    other => panic!("expected thread, got {:?}", other),
                })
                .collect()
        };

        let response = harness
            .client
            .get(format!("/channels/{}/posts?sort=alphabetical", forum.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let body: v0::ForumPostsResponse = response.into_json().await.expect("alphabetical");
        let alphabetical = names(&body);
        assert_eq!(alphabetical, vec!["apple", "Banana", "Cherry"]);

        // Control: the default order is newest-first, so it must NOT match.
        // Without this an always-alphabetical bug would pass the assert above.
        let response = harness
            .client
            .get(format!("/channels/{}/posts", forum.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let body: v0::ForumPostsResponse = response.into_json().await.expect("default order");
        assert_ne!(names(&body), alphabetical);

        // Paging A-Z: the cursor is the last post's id, and the next page must
        // continue rather than repeat.
        let response = harness
            .client
            .get(format!(
                "/channels/{}/posts?sort=alphabetical&limit=2",
                forum.id()
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let body: v0::ForumPostsResponse = response.into_json().await.expect("page 1");
        let page_one = names(&body);
        assert_eq!(page_one, vec!["apple", "Banana"]);

        let last_id = match body.posts.last().expect("a second post") {
            v0::Channel::Thread { id, .. } => id.clone(),
            other => panic!("expected thread, got {:?}", other),
        };

        let response = harness
            .client
            .get(format!(
                "/channels/{}/posts?sort=alphabetical&before={}",
                forum.id(),
                last_id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let body: v0::ForumPostsResponse = response.into_json().await.expect("page 2");
        assert_eq!(names(&body), vec!["Cherry"]);

        // An unknown sort is rejected rather than silently defaulted.
        let response = harness
            .client
            .get(format!("/channels/{}/posts?sort=nonsense", forum.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok);
    }

    #[test]
    fn forced_sort_overrides_what_the_caller_asks_for() {
        crate::util::test::rt().block_on(forced_sort_overrides_what_the_caller_asks_for_case())
    }

    async fn forced_sort_overrides_what_the_caller_asks_for_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&user).await;
        let forum = Channel::create_server_channel(
            &harness.db,
            &mut server,
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Forum,
                name: "forum".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("forum created");

        for title in ["Cherry", "apple", "Banana"] {
            let response = harness
                .client
                .post(format!("/channels/{}/posts", forum.id()))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(
                    json!({
                        "title": title,
                        "message": { "content": "starter" }
                    })
                    .to_string(),
                )
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
        }

        let names = |body: &v0::ForumPostsResponse| -> Vec<String> {
            body.posts
                .iter()
                .map(|post| match post {
                    v0::Channel::Thread { name, .. } => name.clone(),
                    other => panic!("expected thread, got {:?}", other),
                })
                .collect()
        };

        // Control: before the forum forces anything, an explicit
        // `creation_date` is honoured. Without this the assertion below could
        // pass on a forum that was already answering alphabetically.
        let response = harness
            .client
            .get(format!(
                "/channels/{}/posts?sort=creation_date",
                forum.id()
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let body: v0::ForumPostsResponse = response.into_json().await.expect("unforced");
        let unforced = names(&body);
        assert_ne!(unforced, vec!["apple", "Banana", "Cherry"]);

        let response = harness
            .client
            .patch(format!("/channels/{}", forum.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "default_sort": "Alphabetical",
                    "force_sort": true
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // The same request now answers in the forum's order, not the
        // caller's. A forced order a client can sort away from is not forced.
        let response = harness
            .client
            .get(format!(
                "/channels/{}/posts?sort=creation_date",
                forum.id()
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let body: v0::ForumPostsResponse = response.into_json().await.expect("forced");
        assert_eq!(names(&body), vec!["apple", "Banana", "Cherry"]);

        // Forcing an order does not make a malformed one acceptable.
        let response = harness
            .client
            .get(format!("/channels/{}/posts?sort=nonsense", forum.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok);

        // Releasing the lock hands the choice back to the caller.
        let response = harness
            .client
            .patch(format!("/channels/{}", forum.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "force_sort": false }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let response = harness
            .client
            .get(format!(
                "/channels/{}/posts?sort=creation_date",
                forum.id()
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let body: v0::ForumPostsResponse = response.into_json().await.expect("released");
        assert_eq!(names(&body), unforced);
    }

    #[test]
    fn force_sort_is_rejected_on_a_non_forum() {
        crate::util::test::rt().block_on(force_sort_is_rejected_on_a_non_forum_case())
    }

    async fn force_sort_is_rejected_on_a_non_forum_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (mut server, channels) = harness.new_server(&user).await;
        let _ = &mut server;
        let text = channels.first().expect("a default text channel");

        let response = harness
            .client
            .patch(format!("/channels/{}", text.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "force_sort": true }).to_string())
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok);
    }

    async fn new_forum(harness: &TestHarness, owner: &User) -> (Server, Channel) {
        let (mut server, _) = harness.new_server(owner).await;
        let forum = Channel::create_server_channel(
            &harness.db,
            &mut server,
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Forum,
                name: "forum".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("forum created");
        // `Server::create` does not make the owner a member here, while the
        // create-server route does; the members list is checked below.
        Member::create(&harness.db, &server, owner, None)
            .await
            .expect("owner member");
        (server, forum)
    }

    /// Creates a post and returns its id (also its starter message's id).
    async fn create_post(harness: &TestHarness, token: &str, forum: &str, title: &str) -> String {
        let response = harness
            .client
            .post(format!("/channels/{forum}/posts"))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "title": title, "message": { "content": "starter" } }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let body: v0::ForumPostResponse = response.into_json().await.expect("post created");
        match body.post {
            v0::Channel::Thread { id, .. } => id,
            other => panic!("expected thread, got {:?}", other),
        }
    }

    /// Sends a reply into a post and returns the message id.
    async fn reply(harness: &TestHarness, token: &str, post: &str, content: &str) -> String {
        let response = harness
            .client
            .post(format!("/channels/{post}/messages"))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "content": content }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let message: v0::Message = response.into_json().await.expect("reply sent");
        message.id
    }

    async fn list(
        harness: &TestHarness,
        token: &str,
        forum: &str,
        query: &str,
    ) -> v0::ForumPostsResponse {
        let response = harness
            .client
            .get(format!("/channels/{forum}/posts?{query}"))
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        response.into_json().await.expect("posts response")
    }

    fn stats_for<'a>(stats: &'a [v0::ForumPostStats], post: &str) -> &'a v0::ForumPostStats {
        let found: Vec<&v0::ForumPostStats> = stats.iter().filter(|s| s.id == post).collect();
        assert_eq!(found.len(), 1, "exactly one stats entry for post {post}");
        found[0]
    }

    fn sorted(mut ids: Vec<String>) -> Vec<String> {
        ids.sort();
        ids
    }

    fn user_ids(body: &v0::ForumPostsResponse) -> Vec<String> {
        sorted(
            body.users
                .as_ref()
                .expect("users included")
                .iter()
                .map(|user| user.id.clone())
                .collect(),
        )
    }

    fn member_ids(body: &v0::ForumPostsResponse) -> Vec<String> {
        sorted(
            body.members
                .as_ref()
                .expect("members included")
                .iter()
                .map(|member| member.id.user.clone())
                .collect(),
        )
    }

    fn message_ids(messages: &Option<Vec<v0::Message>>) -> Vec<String> {
        sorted(
            messages
                .as_ref()
                .expect("messages included")
                .iter()
                .map(|message| message.id.clone())
                .collect(),
        )
    }

    #[test]
    fn stats_count_replies_and_include_last_authors() {
        crate::util::test::rt().block_on(stats_count_replies_and_include_last_authors_case())
    }

    /// Reply counts leave the starter out, the latest message is the newest
    /// by id, and `include_users` resolves both the creator and the replier.
    async fn stats_count_replies_and_include_last_authors_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (server, forum) = new_forum(&harness, &owner).await;
        Member::create(&harness.db, &server, &member, None)
            .await
            .expect("member");
        let owner_token = owner_session.token.to_string();
        let member_token = member_session.token.to_string();

        let quiet = create_post(&harness, &owner_token, forum.id(), "quiet").await;
        let busy = create_post(&harness, &owner_token, forum.id(), "busy").await;
        let first = reply(&harness, &member_token, &busy, "one").await;
        let second = reply(&harness, &member_token, &busy, "two").await;
        // Ids are ULIDs; two sends in the same millisecond are not ordered by
        // send order, so "newest" means the greatest id.
        let newest = first.clone().max(second.clone());

        let body = list(
            &harness,
            &owner_token,
            forum.id(),
            "include_stats=true&include_users=true",
        )
        .await;
        let stats = body.stats.as_ref().expect("stats included");
        assert_eq!(stats.len(), 2, "one stats entry per returned post");

        let quiet_stats = stats_for(stats, &quiet);
        assert_eq!(quiet_stats.replies, 0, "the starter is not a reply");
        assert_eq!(quiet_stats.last_message_id.as_deref(), Some(quiet.as_str()));

        let busy_stats = stats_for(stats, &busy);
        assert_eq!(busy_stats.replies, 2);
        assert_eq!(busy_stats.last_message_id.as_deref(), Some(newest.as_str()));

        // The latest messages are the starter of the quiet post and the
        // newest reply of the busy one, with their authors resolvable.
        assert_eq!(
            message_ids(&body.last_messages),
            sorted(vec![quiet.clone(), newest.clone()])
        );
        let last = body
            .last_messages
            .as_ref()
            .expect("last messages")
            .iter()
            .find(|message| message.id == newest)
            .expect("newest reply returned");
        assert_eq!(last.author, member.id);

        let expected = sorted(vec![owner.id.clone(), member.id.clone()]);
        assert_eq!(user_ids(&body), expected, "creator and last replier");
        assert_eq!(member_ids(&body), expected);
    }

    #[test]
    fn deleted_last_reply_falls_back_to_the_previous_message() {
        crate::util::test::rt()
            .block_on(deleted_last_reply_falls_back_to_the_previous_message_case())
    }

    /// The stored `last_message_id` is never rolled back on delete; the stats
    /// are computed from the messages, so they must not follow it.
    async fn deleted_last_reply_falls_back_to_the_previous_message_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, forum) = new_forum(&harness, &owner).await;
        let token = session.token.to_string();

        let post = create_post(&harness, &token, forum.id(), "post").await;
        let first = reply(&harness, &token, &post, "one").await;
        let second = reply(&harness, &token, &post, "two").await;
        let newest = first.clone().max(second.clone());
        let survivor = if newest == first { &second } else { &first };
        let fallback = survivor.clone().max(post.clone());

        // What the lagging last_message_id queue would have written.
        harness
            .db
            .set_last_message_id_if_newer(&post, &newest, false)
            .await
            .expect("stored last message");

        let response = harness
            .client
            .delete(format!("/channels/{post}/messages/{newest}"))
            .header(Header::new("x-session-token", token.clone()))
            .dispatch()
            .await;
        assert!(response.status().class().is_success(), "reply deleted");

        // Control: the stored pointer still names the deleted reply, so a
        // route that echoed it would fail the assertions below.
        match harness.db.fetch_channel(&post).await.expect("post") {
            Channel::Thread {
                last_message_id, ..
            } => assert_eq!(last_message_id.as_deref(), Some(newest.as_str())),
            other => panic!("expected thread, got {:?}", other),
        }

        let body = list(&harness, &token, forum.id(), "include_stats=true").await;
        let stats = body.stats.as_ref().expect("stats included");
        let entry = stats_for(stats, &post);
        assert_eq!(entry.replies, 1);
        assert_eq!(entry.last_message_id.as_deref(), Some(fallback.as_str()));
        assert_eq!(message_ids(&body.last_messages), vec![fallback]);
    }

    #[test]
    fn bulk_delete_drops_reply_counts() {
        crate::util::test::rt().block_on(bulk_delete_drops_reply_counts_case())
    }

    async fn bulk_delete_drops_reply_counts_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, forum) = new_forum(&harness, &owner).await;
        let token = session.token.to_string();

        let post = create_post(&harness, &token, forum.id(), "post").await;
        let mut replies = vec![
            reply(&harness, &token, &post, "one").await,
            reply(&harness, &token, &post, "two").await,
            reply(&harness, &token, &post, "three").await,
        ];
        replies.sort();
        // Delete the two newest; the oldest reply and the starter remain.
        let kept = replies[0].clone();
        let deleted = vec![replies[1].clone(), replies[2].clone()];

        let body = list(&harness, &token, forum.id(), "include_stats=true").await;
        assert_eq!(
            stats_for(body.stats.as_ref().expect("stats"), &post).replies,
            3
        );

        let response = harness
            .client
            .delete(format!("/channels/{post}/messages/bulk"))
            .header(Header::new("x-session-token", token.clone()))
            .header(ContentType::JSON)
            .body(json!({ "ids": deleted }).to_string())
            .dispatch()
            .await;
        assert!(response.status().class().is_success(), "bulk delete");

        let body = list(&harness, &token, forum.id(), "include_stats=true").await;
        let entry = stats_for(body.stats.as_ref().expect("stats"), &post);
        assert_eq!(entry.replies, 1, "only the deleted replies are gone");
        assert_eq!(entry.last_message_id.as_deref(), Some(kept.as_str()));
        assert_eq!(message_ids(&body.last_messages), vec![kept]);
    }

    #[test]
    fn stats_need_read_message_history_but_creators_do_not() {
        crate::util::test::rt().block_on(stats_need_read_message_history_but_creators_do_not_case())
    }

    /// Without ReadMessageHistory the stats and latest messages are ABSENT
    /// (an empty list would read as "no replies"), and the users are the
    /// post creators only, never the authors of history the caller cannot
    /// read. The owner bypasses the override and gets everything.
    async fn stats_need_read_message_history_but_creators_do_not_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (server, mut forum) = new_forum(&harness, &owner).await;
        Member::create(&harness.db, &server, &member, None)
            .await
            .expect("member");
        let owner_token = owner_session.token.to_string();
        let member_token = member_session.token.to_string();

        let post = create_post(&harness, &owner_token, forum.id(), "rules").await;
        let answer = reply(&harness, &member_token, &post, "member reply").await;
        let query = "include_stats=true&include_users=true&include_starters=true";

        // Control: with the default permissions the member gets the stats
        // and its own reply's author, so the denial below is what hides them.
        let body = list(&harness, &member_token, forum.id(), query).await;
        assert_eq!(
            stats_for(body.stats.as_ref().expect("stats"), &post).replies,
            1
        );
        assert_eq!(
            user_ids(&body),
            sorted(vec![owner.id.clone(), member.id.clone()])
        );

        forum
            .update(
                &harness.db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ReadMessageHistory as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny history");

        let body = list(&harness, &member_token, forum.id(), query).await;
        assert_eq!(body.posts.len(), 1, "titles stay visible with ViewChannel");
        assert!(body.stats.is_none(), "stats must be absent, not empty");
        assert!(body.last_messages.is_none(), "last messages must be absent");
        assert!(body
            .starters
            .as_ref()
            .expect("starters requested")
            .is_empty());
        assert_eq!(user_ids(&body), vec![owner.id.clone()], "creators only");
        assert_eq!(member_ids(&body), vec![owner.id.clone()]);

        // The owner bypasses the override and gets everything.
        let body = list(&harness, &owner_token, forum.id(), query).await;
        let entry = stats_for(body.stats.as_ref().expect("stats"), &post);
        assert_eq!(entry.replies, 1);
        assert_eq!(entry.last_message_id.as_deref(), Some(answer.as_str()));
        assert_eq!(message_ids(&body.last_messages), vec![answer.clone()]);
        assert_eq!(body.starters.as_ref().expect("starters").len(), 1);
        assert_eq!(
            user_ids(&body),
            sorted(vec![owner.id.clone(), member.id.clone()])
        );
    }

    #[test]
    fn new_fields_are_absent_unless_requested() {
        crate::util::test::rt().block_on(new_fields_are_absent_unless_requested_case())
    }

    /// Existing clients that never ask for stats or users see the response
    /// exactly as before: none of the new keys on the wire.
    async fn new_fields_are_absent_unless_requested_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, forum) = new_forum(&harness, &owner).await;
        let token = session.token.to_string();

        let post = create_post(&harness, &token, forum.id(), "post").await;
        reply(&harness, &token, &post, "reply").await;

        for query in [
            "",
            "include_starters=true",
            "include_stats=false&include_users=false",
        ] {
            let response = harness
                .client
                .get(format!("/channels/{}/posts?{query}", forum.id()))
                .header(Header::new("x-session-token", token.clone()))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
            let body: serde_json::Value = response.into_json().await.expect("json body");
            let object = body.as_object().expect("an object");
            for key in ["stats", "last_messages", "users", "members"] {
                assert!(!object.contains_key(key), "{} present for {:?}", key, query);
            }
            assert_eq!(object["posts"].as_array().expect("posts").len(), 1);
        }

        // Control: asked for, the same keys are on the wire.
        let response = harness
            .client
            .get(format!(
                "/channels/{}/posts?include_stats=true&include_users=true",
                forum.id()
            ))
            .header(Header::new("x-session-token", token.clone()))
            .dispatch()
            .await;
        let body: serde_json::Value = response.into_json().await.expect("json body");
        for key in ["stats", "last_messages", "users", "members"] {
            assert!(body.get(key).is_some(), "{} missing when requested", key);
        }
    }

    #[test]
    fn deleted_starter_does_not_fail_the_listing() {
        crate::util::test::rt().block_on(deleted_starter_does_not_fail_the_listing_case())
    }

    /// A post whose starter is gone (and one with no messages left at all)
    /// still lists, with stats from whatever messages remain.
    async fn deleted_starter_does_not_fail_the_listing_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, forum) = new_forum(&harness, &owner).await;
        let token = session.token.to_string();

        let empty = create_post(&harness, &token, forum.id(), "empty").await;
        let replied = create_post(&harness, &token, forum.id(), "replied").await;
        let answer = reply(&harness, &token, &replied, "reply").await;
        harness
            .db
            .delete_message(&empty)
            .await
            .expect("delete starter");
        harness
            .db
            .delete_message(&replied)
            .await
            .expect("delete starter");

        let body = list(
            &harness,
            &token,
            forum.id(),
            "include_starters=true&include_stats=true&include_users=true",
        )
        .await;
        assert_eq!(body.posts.len(), 2);
        assert!(body.starters.as_ref().expect("starters").is_empty());

        let stats = body.stats.as_ref().expect("stats");
        let entry = stats_for(stats, &empty);
        assert_eq!(entry.replies, 0);
        assert_eq!(entry.last_message_id, None);
        let entry = stats_for(stats, &replied);
        assert_eq!(entry.replies, 1);
        assert_eq!(entry.last_message_id.as_deref(), Some(answer.as_str()));

        assert_eq!(message_ids(&body.last_messages), vec![answer]);
        assert_eq!(user_ids(&body), vec![owner.id.clone()]);
    }

    #[test]
    fn webhook_messages_add_no_users() {
        crate::util::test::rt().block_on(webhook_messages_add_no_users_case())
    }

    /// A webhook message's author id is the webhook's, not a user's, so the
    /// starters and latest messages a webhook wrote add no users or members.
    ///
    /// Through the API a webhook id never names a user, and the user and
    /// member lookups skip ids they cannot find, so a webhook id that reached
    /// them would vanish without a trace. To make the filter observable, the
    /// second post's webhook message carries a real (unrelated) user's id as
    /// its author: only the webhook check keeps that user out of the response.
    async fn webhook_messages_add_no_users_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, _, stranger) = harness.new_user().await;
        let (_, forum) = new_forum(&harness, &owner).await;
        let token = session.token.to_string();
        let webhook = || {
            Some(v0::MessageWebhook {
                name: "Hook".to_string(),
                avatar: None,
            })
        };

        // A webhook wrote the latest reply, under its own (non-user) id. The
        // id is one past the starter's, so it is the newest message for sure.
        let replied = create_post(&harness, &token, forum.id(), "replied").await;
        let hook_reply = Ulid::from_string(&replied)
            .expect("post id is a ULID")
            .increment()
            .expect("room above the starter id")
            .to_string();
        harness
            .db
            .insert_message(&Message {
                id: hook_reply.clone(),
                channel: replied.clone(),
                author: Ulid::new().to_string(),
                webhook: webhook(),
                content: Some("from a webhook".to_string()),
                ..Default::default()
            })
            .await
            .expect("webhook reply");

        // A webhook wrote the starter, which is also the post's only (so
        // latest) message, and its author id collides with a real user's.
        let hooked = create_post(&harness, &token, forum.id(), "hooked").await;
        harness
            .db
            .delete_message(&hooked)
            .await
            .expect("delete starter");
        harness
            .db
            .insert_message(&Message {
                id: hooked.clone(),
                channel: hooked.clone(),
                author: stranger.id.clone(),
                webhook: webhook(),
                content: Some("webhook starter".to_string()),
                ..Default::default()
            })
            .await
            .expect("webhook starter");

        let body = list(
            &harness,
            &token,
            forum.id(),
            "include_starters=true&include_stats=true&include_users=true",
        )
        .await;
        assert_eq!(body.posts.len(), 2);

        // Control: both webhook messages are in this response, as a starter
        // and as latest messages, so their authors were candidates.
        let starter = body
            .starters
            .as_ref()
            .expect("starters")
            .iter()
            .find(|message| message.id == hooked)
            .expect("webhook starter returned");
        assert!(starter.webhook.is_some());
        assert_eq!(starter.author, stranger.id);
        assert_eq!(
            message_ids(&body.last_messages),
            sorted(vec![hook_reply.clone(), hooked.clone()])
        );
        assert!(body
            .last_messages
            .as_ref()
            .expect("last messages")
            .iter()
            .all(|message| message.webhook.is_some()));

        assert_eq!(user_ids(&body), vec![owner.id.clone()], "creator only");
        assert_eq!(member_ids(&body), vec![owner.id.clone()]);
    }

    #[test]
    fn stats_cover_the_returned_page_only() {
        crate::util::test::rt().block_on(stats_cover_the_returned_page_only_case())
    }

    /// `stats` and `last_messages` describe the posts on this page, not every
    /// post in the forum: the work is bounded by `limit`, and a client is not
    /// handed rows for posts it was not shown.
    async fn stats_cover_the_returned_page_only_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, forum) = new_forum(&harness, &owner).await;
        let token = session.token.to_string();

        let first = create_post(&harness, &token, forum.id(), "first").await;
        let second = create_post(&harness, &token, forum.id(), "second").await;
        reply(&harness, &token, &first, "reply").await;
        reply(&harness, &token, &second, "reply").await;

        // Control: unpaged, both posts have stats and a latest message, so
        // the single entries below are the page bound at work.
        let body = list(&harness, &token, forum.id(), "include_stats=true").await;
        assert_eq!(body.posts.len(), 2);
        assert_eq!(body.stats.as_ref().expect("stats").len(), 2);
        assert_eq!(body.last_messages.as_ref().expect("last messages").len(), 2);

        let body = list(&harness, &token, forum.id(), "include_stats=true&limit=1").await;
        assert_eq!(body.posts.len(), 1);
        let shown = match &body.posts[0] {
            v0::Channel::Thread { id, .. } => id.clone(),
            other => panic!("expected thread, got {:?}", other),
        };
        assert!(shown == first || shown == second);

        let stats = body.stats.as_ref().expect("stats");
        assert_eq!(stats.len(), 1, "one stats entry, for the returned post");
        assert_eq!(stats[0].id, shown);

        let last_messages = body.last_messages.as_ref().expect("last messages");
        assert_eq!(last_messages.len(), 1, "latest message of this page only");
        assert_eq!(last_messages[0].channel, shown);
        assert_eq!(
            stats[0].last_message_id.as_deref(),
            Some(last_messages[0].id.as_str())
        );
    }
}
