use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, User,
};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::Result;
use rocket::{serde::json::Json, State};

/// # Fetch Followers
///
/// Lists the follows hanging off a source announcement channel. Source-side
/// admin visibility only — gated on `ManageChannel` on the source channel.
#[openapi(tag = "Channel Information")]
#[get("/<source>/followers")]
pub async fn fetch_followers(
    db: &State<Database>,
    user: User,
    source: Reference<'_>,
) -> Result<Json<Vec<revolt_models::v0::ChannelFollow>>> {
    let source_channel = source.as_channel(db).await?;

    let mut query = DatabasePermissionQuery::new(db, &user).channel(&source_channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;

    let follows = db.fetch_follows_by_source(source_channel.id()).await?;

    Ok(Json(follows.into_iter().map(|f| f.into_model()).collect()))
}
