use revolt_database::{util::permissions::DatabasePermissionQuery, Database, User};
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::Result;

use rocket::State;
use rocket_empty::EmptyResponse;

/// # Delete Sticker
///
/// Delete a sticker by its id.
#[openapi(tag = "Stickers")]
#[delete("/server/<server_id>/stickers/<sticker_id>")]
pub async fn delete_sticker(
    db: &State<Database>,
    user: User,
    server_id: String,
    sticker_id: String,
) -> Result<EmptyResponse> {
    let sticker = db.fetch_sticker(&sticker_id).await?;

    if sticker.server_id != server_id {
        return Err(revolt_result::create_error!(NotFound));
    }

    if sticker.creator_id != user.id {
        let server = db.fetch_server(&server_id).await?;
        let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
        calculate_server_permissions(&mut query)
            .await
            .throw_if_lacking_channel_permission(ChannelPermission::ManageCustomisation)?;
    }

    sticker.delete(db).await.map(|_| EmptyResponse)
}
