use revolt_config::config;
use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, ChannelFollow, Database, User, Webhook,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use ulid::Ulid;
use validator::Validate;

/// Truncate a string to at most `max` characters (char-safe).
fn truncate_chars(input: &str, max: usize) -> String {
    input.chars().take(max).collect()
}

/// Current time in milliseconds since the Unix epoch.
#[allow(clippy::disallowed_methods)]
fn now_ms() -> i64 {
    use iso8601_timestamp::Timestamp;
    Timestamp::now_utc()
        .duration_since(Timestamp::UNIX_EPOCH)
        .whole_milliseconds() as i64
}

/// # Follow Announcement Channel
///
/// Follows a source announcement channel from a target channel in another
/// server. Creates a real webhook in the target channel; publishing an
/// announcement then fans a webhook-authored copy into every follower.
///
/// The caller needs `ViewChannel` on the source announcement channel and
/// `ManageWebhooks` on the target channel (the same gate as creating a
/// webhook there — the target server keeps full local control).
#[openapi(tag = "Channel Information")]
#[post("/<source>/follow", data = "<data>")]
pub async fn follow_channel(
    db: &State<Database>,
    user: User,
    source: Reference<'_>,
    data: Json<v0::DataFollowChannel>,
) -> Result<Json<v0::ChannelFollow>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Resolve the source — it must be a server text channel flagged as an
    // announcement channel. (E2EE fail-closed: DMs/groups/saved-messages can
    // never be a follow source.)
    let source_channel = source.as_channel(db).await?;
    let (source_channel_id, source_server_id, source_channel_name, is_announcement) =
        match &source_channel {
            Channel::TextChannel {
                id,
                server,
                name,
                announcement,
                ..
            } => (
                id.clone(),
                server.clone(),
                name.clone(),
                *announcement == Some(true),
            ),
            _ => return Err(create_error!(NotAnAnnouncementChannel)),
        };
    if !is_announcement {
        return Err(create_error!(NotAnAnnouncementChannel));
    }

    // Caller must be able to see the source announcement channel.
    let mut source_query = DatabasePermissionQuery::new(db, &user).channel(&source_channel);
    calculate_channel_permissions(&mut source_query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    // Resolve the target — it must be a server text channel in the given
    // server (fail closed for every E2EE-capable / non-server context).
    let target_channel = Reference::from_unchecked(&data.channel).as_channel(db).await?;
    let (target_channel_id, target_server_id) = match &target_channel {
        Channel::TextChannel { id, server, .. } => (id.clone(), server.clone()),
        _ => return Err(create_error!(InvalidOperation)),
    };
    if target_server_id != data.server {
        return Err(create_error!(InvalidOperation));
    }
    // A channel cannot follow itself.
    if target_channel_id == source_channel_id {
        return Err(create_error!(InvalidOperation));
    }

    // Caller must be able to manage webhooks in the TARGET channel — this is
    // exactly the gate for creating a webhook there, so the target server
    // retains full control (rename / delete via normal webhook settings).
    let mut target_query = DatabasePermissionQuery::new(db, &user).channel(&target_channel);
    calculate_channel_permissions(&mut target_query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageWebhooks)?;

    // Idempotent: an existing (source, target) follow is returned as-is.
    if let Some(existing) = db
        .fetch_follow_by_source_and_target(&source_channel_id, &target_channel_id)
        .await?
    {
        return Ok(Json(existing.into_model()));
    }

    // Enforce the per-source follower cap.
    let cap = config().await.features.limits.global.followers_per_channel;
    if db.count_follows_by_source(&source_channel_id).await? >= cap {
        return Err(create_error!(TooManyFollowers { max: cap }));
    }

    // Name the webhook after the source: "{server} • #{channel}", truncated
    // to the 32-char webhook name limit so a later PATCH via normal webhook
    // settings still validates.
    let source_server_name = db
        .fetch_server(&source_server_id)
        .await
        .map(|server| server.name)
        .unwrap_or_default();
    let webhook_name = truncate_chars(
        &format!("{source_server_name} • #{source_channel_name}"),
        32,
    );

    // Minimal permission bitfield: only what a crosspost copy needs, so the
    // fan-out still respects the target channel's webhook gating.
    let webhook_permissions: u64 = ChannelPermission::SendMessage
        + ChannelPermission::SendEmbeds
        + ChannelPermission::UploadFiles
        + ChannelPermission::Masquerade;

    let webhook = Webhook {
        id: Ulid::new().to_string(),
        name: webhook_name,
        avatar: None,
        creator_id: user.id.clone(),
        channel_id: target_channel_id.clone(),
        permissions: webhook_permissions,
        token: Some(nanoid::nanoid!(64)),
    };
    webhook.create(db).await?;

    let follow = ChannelFollow {
        id: Ulid::new().to_string(),
        source_channel: source_channel_id,
        source_server: source_server_id,
        target_channel: target_channel_id,
        target_server: target_server_id,
        webhook_id: webhook.id.clone(),
        created_by: user.id.clone(),
        created_at: now_ms(),
    };

    if let Err(error) = db.insert_channel_follow(&follow).await {
        // Never leave a dangling webhook if the follow row failed to insert.
        webhook.delete(db).await.ok();
        return Err(error);
    }

    follow.emit_create().await;

    Ok(Json(follow.into_model()))
}
