use revolt_database::{
    util::permissions::DatabasePermissionQuery, Database, PartialSoundboardSound, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Edit Soundboard Sound
///
/// Edit a soundboard sound by its id.
#[openapi(tag = "Soundboard")]
#[patch("/server/<server_id>/sounds/<sound_id>", data = "<data>")]
pub async fn edit_sound(
    db: &State<Database>,
    user: User,
    server_id: String,
    sound_id: String,
    data: Json<v0::DataEditSound>,
) -> Result<Json<v0::SoundboardSound>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let mut sound = db.fetch_soundboard_sound(&sound_id).await?;

    if sound.server_id != server_id {
        return Err(create_error!(NotFound));
    }

    let server = db.fetch_server(&server_id).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageCustomisation)?;

    if data.name.is_none() && data.emoji.is_none() {
        return Ok(Json(sound.into()));
    }

    let partial = PartialSoundboardSound {
        name: data.name,
        emoji: data.emoji,
    };
    sound.update(db, partial).await?;

    Ok(Json(sound.into()))
}
