use revolt_database::{
    events::client::EventV1,
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, User,
};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

/// # Join Thread
///
/// Join the current user to a thread. Requires being able to view the parent
/// channel. Idempotent.
#[openapi(tag = "Threads")]
#[put("/<target>/thread_members/@me")]
pub async fn join_thread(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    let channel = target.as_channel(db).await?;
    let Channel::Thread { server, .. } = &channel else {
        return Err(create_error!(InvalidOperation));
    };
    let server = server.clone();

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    if db.join_thread_if_absent(channel.id(), &user.id).await? {
        EventV1::ThreadMemberJoin {
            id: channel.id().to_string(),
            user: user.id.clone(),
        }
        .p(server)
        .await;
    }

    Ok(EmptyResponse)
}

/// # Leave Thread
///
/// Remove a member from a thread. Pass `@me` (or your own id) to leave
/// yourself; removing anyone else requires `ManageChannel` on the parent.
#[openapi(tag = "Threads")]
#[delete("/<target>/thread_members/<member>")]
pub async fn leave_thread(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    member: String,
) -> Result<EmptyResponse> {
    let channel = target.as_channel(db).await?;
    let Channel::Thread { server, .. } = &channel else {
        return Err(create_error!(InvalidOperation));
    };
    let server = server.clone();

    let target_user = if member == "@me" {
        user.id.clone()
    } else {
        member
    };

    // Removing anyone other than yourself requires ManageChannel on the parent.
    if target_user != user.id {
        let permission_channel = channel.permission_target(db).await?.into_owned();
        let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
        calculate_channel_permissions(&mut query)
            .await
            .throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
    }

    db.leave_thread(channel.id(), &target_user).await?;
    EventV1::ThreadMemberLeave {
        id: channel.id().to_string(),
        user: target_user,
    }
    .p(server)
    .await;

    Ok(EmptyResponse)
}

/// # Fetch Thread Members
///
/// Fetch the ids of the users who have joined a thread.
#[openapi(tag = "Threads")]
#[get("/<target>/thread_members")]
pub async fn fetch_thread_members(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<Vec<String>>> {
    let channel = target.as_channel(db).await?;
    if !matches!(channel, Channel::Thread { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    let members = db.fetch_thread_members(channel.id()).await?;
    Ok(Json(members.into_iter().map(|member| member.id.user).collect()))
}
