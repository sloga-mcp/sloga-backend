use revolt_database::{util::permissions::DatabasePermissionQuery, Database, PartialSticker, User};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Edit Sticker
///
/// Edit a sticker by its id.
#[openapi(tag = "Stickers")]
#[patch("/server/<server_id>/stickers/<sticker_id>", data = "<data>")]
pub async fn edit_sticker(
    db: &State<Database>,
    user: User,
    server_id: String,
    sticker_id: String,
    data: Json<v0::DataEditSticker>,
) -> Result<Json<v0::Sticker>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let mut sticker = db.fetch_sticker(&sticker_id).await?;

    if sticker.server_id != server_id {
        return Err(create_error!(NotFound));
    }

    let server = db.fetch_server(&server_id).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageCustomisation)?;

    if data.name.is_none() && data.description.is_none() && data.nsfw.is_none() {
        return Ok(Json(sticker.into()));
    }

    let partial = PartialSticker {
        name: data.name,
        description: data.description,
        nsfw: data.nsfw,
    };
    sticker.update(db, partial).await?;

    Ok(Json(sticker.into()))
}
