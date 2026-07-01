use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_result::Result;

use rocket::{serde::json::Json, State};

/// # Fetch Sticker
///
/// Fetch a sticker by its id.
#[openapi(tag = "Stickers")]
#[get("/stickers/<sticker_id>")]
pub async fn fetch_sticker(
    db: &State<Database>,
    _user: User,
    sticker_id: String,
) -> Result<Json<v0::Sticker>> {
    let sticker = db.fetch_sticker(&sticker_id).await?;
    Ok(Json(sticker.into()))
}

/// # Fetch Server Stickers
///
/// Fetch all stickers for a server.
#[openapi(tag = "Stickers")]
#[get("/server/<server_id>/stickers")]
pub async fn fetch_server_stickers(
    db: &State<Database>,
    _user: User,
    server_id: String,
) -> Result<Json<Vec<v0::Sticker>>> {
    let stickers = db.fetch_stickers_by_server_id(&server_id).await?;
    Ok(Json(stickers.into_iter().map(|s| s.into()).collect()))
}
