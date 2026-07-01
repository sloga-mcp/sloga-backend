use revolt_config::config;
use revolt_database::{util::permissions::DatabasePermissionQuery, Database, File, Sticker, User};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use validator::Validate;

use rocket::{serde::json::Json, State};

/// # Create New Sticker
///
/// Create a sticker by its Autumn upload id.
#[openapi(tag = "Stickers")]
#[put("/server/<server_id>/stickers/<sticker_id>", data = "<data>")]
pub async fn create_sticker(
    db: &State<Database>,
    user: User,
    server_id: String,
    sticker_id: String,
    data: Json<v0::DataCreateSticker>,
) -> Result<Json<v0::Sticker>> {
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

    let stickers = db.fetch_stickers_by_server_id(&server.id).await?;
    if stickers.len() >= config.features.limits.global.server_stickers {
        return Err(create_error!(TooManyStickers {
            max: config.features.limits.global.server_stickers,
        }));
    }

    let attachment = File::use_sticker(db, &sticker_id, &sticker_id, &user.id).await?;

    let format = detect_sticker_format(&attachment.content_type);

    let sticker = Sticker {
        id: sticker_id,
        server_id: server.id,
        creator_id: user.id,
        name: data.name,
        description: data.description,
        file_id: attachment.id.clone(),
        format,
        nsfw: data.nsfw,
    };

    sticker.create(db).await?;
    Ok(Json(sticker.into()))
}

fn detect_sticker_format(content_type: &str) -> revolt_database::StickerFormat {
    match content_type {
        "image/gif" => revolt_database::StickerFormat::GIF,
        "image/apng" | "image/vnd.mozilla.apng" => revolt_database::StickerFormat::APNG,
        "application/json" => revolt_database::StickerFormat::Lottie,
        _ => revolt_database::StickerFormat::PNG,
    }
}
