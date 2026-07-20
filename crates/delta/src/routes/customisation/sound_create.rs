use revolt_config::config;
use revolt_database::{
    util::permissions::DatabasePermissionQuery, Database, File, SoundboardSound, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use validator::Validate;

use rocket::{serde::json::Json, State};

/// # Create New Soundboard Sound
///
/// Create a soundboard sound by its Autumn upload id.
#[openapi(tag = "Soundboard")]
#[put("/server/<server_id>/sounds/<sound_id>", data = "<data>")]
pub async fn create_sound(
    db: &State<Database>,
    user: User,
    server_id: String,
    sound_id: String,
    data: Json<v0::DataCreateSound>,
) -> Result<Json<v0::SoundboardSound>> {
    let config = config().await;
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let server = db.fetch_server(&server_id).await?;

    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageCustomisation)?;

    // Boost tiers can raise the global sound cap; with boosts disabled
    // this resolves to the global limit unchanged.
    let max_sounds = config.features.boosts.effective_server_sounds(
        config.features.limits.global.server_sounds,
        server.boost_tier.unwrap_or_default() as u32,
    );
    let sounds = db.fetch_soundboard_sounds_by_server_id(&server.id).await?;
    if sounds.len() >= max_sounds {
        return Err(create_error!(TooManySounds { max: max_sounds }));
    }

    let attachment = File::use_soundboard(db, &sound_id, &sound_id, &user.id).await?;

    let sound = SoundboardSound {
        id: sound_id,
        server_id: server.id,
        creator_id: user.id,
        name: data.name,
        file_id: attachment.id.clone(),
        emoji: data.emoji,
    };

    sound.create(db).await?;
    Ok(Json(sound.into()))
}
