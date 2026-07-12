use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, User,
};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::Result;
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Add Reaction to Message
///
/// React to a given message.
#[openapi(tag = "Interactions")]
#[put("/<target>/messages/<msg>/reactions/<emoji>")]
pub async fn react_message(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
    emoji: Reference<'_>,
) -> Result<EmptyResponse> {
    let channel = target.as_channel(db).await?;
    // Threads inherit their parent channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::React)?;

    // Archived/locked threads reject participation.
    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    // Fetch relevant message
    let message = msg.as_message_in_channel(db, channel.id()).await?;

    // Add the reaction
    message
        .add_reaction(db, &user, emoji.id)
        .await
        .map(|_| EmptyResponse)
}
