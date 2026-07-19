use revolt_config::config;
use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_result::Result;

use rocket::{serde::json::Json, State};

/// # Fetch Default Soundboard Sounds
///
/// Fetch the global preconfigured soundboard sounds ("Sloga Sounds"),
/// playable in any server voice channel. Defined in server config.
#[openapi(tag = "Soundboard")]
#[get("/sounds/default")]
pub async fn fetch_default_sounds(
    _user: User,
) -> Result<Json<Vec<v0::DefaultSoundboardSound>>> {
    let config = config().await;
    Ok(Json(
        config
            .api
            .soundboard
            .default_sounds
            .iter()
            .map(|sound| v0::DefaultSoundboardSound {
                id: sound.id.clone(),
                name: sound.name.clone(),
                emoji: sound.emoji.clone(),
            })
            .collect(),
    ))
}

/// # Fetch Soundboard Sound
///
/// Fetch a soundboard sound by its id.
#[openapi(tag = "Soundboard")]
#[get("/sounds/<sound_id>")]
pub async fn fetch_sound(
    db: &State<Database>,
    _user: User,
    sound_id: String,
) -> Result<Json<v0::SoundboardSound>> {
    let sound = db.fetch_soundboard_sound(&sound_id).await?;
    Ok(Json(sound.into()))
}

/// # Fetch Server Soundboard Sounds
///
/// Fetch all soundboard sounds for a server.
#[openapi(tag = "Soundboard")]
#[get("/server/<server_id>/sounds")]
pub async fn fetch_server_sounds(
    db: &State<Database>,
    _user: User,
    server_id: String,
) -> Result<Json<Vec<v0::SoundboardSound>>> {
    let sounds = db.fetch_soundboard_sounds_by_server_id(&server_id).await?;
    Ok(Json(sounds.into_iter().map(|s| s.into()).collect()))
}
