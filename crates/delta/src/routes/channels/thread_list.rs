use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::Result;
use rocket::{serde::json::Json, State};

/// Sort key for ordering threads by most recent activity, falling back to the
/// thread's own (creation-ordered) id when it has no messages yet.
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

/// # Fetch Threads
///
/// Fetch the threads under a server text channel, most-recently-active first.
///
/// Pass `archived=true` to list archived threads instead of active ones. `before`
/// is an id cursor and `limit` (1-100, default 50) bounds the page size.
#[openapi(tag = "Threads")]
#[get("/<target>/threads?<archived>&<before>&<limit>")]
pub async fn fetch_threads(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    archived: Option<bool>,
    before: Option<String>,
    limit: Option<u32>,
) -> Result<Json<Vec<v0::Channel>>> {
    let channel = target.as_channel(db).await?;
    // Visibility of the thread list follows the parent channel.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    let want_archived = archived.unwrap_or(false);
    let mut threads: Vec<Channel> = db
        .fetch_threads_by_parent(channel.id())
        .await?
        .into_iter()
        .filter(|thread| {
            matches!(thread, Channel::Thread { archived, .. } if *archived == want_archived)
        })
        .collect();

    // The cursor pages on the same key the list is sorted by (activity),
    // otherwise pagination skips or duplicates entries.
    if let Some(before) = before {
        threads.retain(|thread| activity_key(thread) < before.as_str());
    }

    threads.sort_by(|a, b| activity_key(b).cmp(activity_key(a)));

    let limit = limit.unwrap_or(50).clamp(1, 100) as usize;
    threads.truncate(limit);

    Ok(Json(threads.into_iter().map(Into::into).collect()))
}
