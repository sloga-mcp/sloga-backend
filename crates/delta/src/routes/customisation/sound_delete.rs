use revolt_database::{util::permissions::DatabasePermissionQuery, Database, User};
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::Result;

use rocket::State;
use rocket_empty::EmptyResponse;

/// # Delete Soundboard Sound
///
/// Delete a soundboard sound by its id.
#[openapi(tag = "Soundboard")]
#[delete("/server/<server_id>/sounds/<sound_id>")]
pub async fn delete_sound(
    db: &State<Database>,
    user: User,
    server_id: String,
    sound_id: String,
) -> Result<EmptyResponse> {
    let sound = db.fetch_soundboard_sound(&sound_id).await?;

    if sound.server_id != server_id {
        return Err(revolt_result::create_error!(NotFound));
    }

    if sound.creator_id != user.id {
        let server = db.fetch_server(&server_id).await?;
        let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
        calculate_server_permissions(&mut query)
            .await
            .throw_if_lacking_channel_permission(ChannelPermission::ManageCustomisation)?;
    }

    sound.delete(db).await.map(|_| EmptyResponse)
}
