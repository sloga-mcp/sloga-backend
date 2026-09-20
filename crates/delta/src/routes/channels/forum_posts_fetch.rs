use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, User,
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
/// `tag` filters to
/// posts carrying the given tag id; `archived=true` lists archived posts
/// instead of active ones; `before` is a cursor on the sort key, except under
/// `alphabetical` where it is the last post's id; `limit`
/// (1-100, default 50) bounds the page size. Pass `include_starters=true` to
/// also receive each post's starter message (its id equals the post's id).
#[openapi(tag = "Forums")]
#[get("/<target>/posts?<sort>&<tag>&<archived>&<before>&<limit>&<include_starters>")]
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
) -> Result<Json<v0::ForumPostsResponse>> {
    let channel = target.as_channel(db).await?;
    if !matches!(channel, Channel::Forum { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    let order = match sort.as_deref() {
        None | Some("latest_activity") => ForumSort::LatestActivity,
        Some("creation_date") => ForumSort::CreationDate,
        Some("alphabetical") => ForumSort::Alphabetical,
        _ => return Err(create_error!(InvalidProperty)),
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

    // Starter messages are pinned to their post's id, so the whole page
    // resolves in one bulk fetch.
    let starters = if include_starters.unwrap_or(false) {
        let ids: Vec<String> = posts.iter().map(|post| post.id().to_string()).collect();
        Some(
            db.fetch_messages_by_id(&ids)
                .await?
                .into_iter()
                .map(|message| message.into_model(None, None))
                .collect(),
        )
    } else {
        None
    };

    Ok(Json(v0::ForumPostsResponse {
        posts: posts.into_iter().map(Into::into).collect(),
        starters,
    }))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::Channel;
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};

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
                "starter missing for post {id}"
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
}
