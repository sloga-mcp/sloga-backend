use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod emoji_create;
mod emoji_delete;
mod emoji_edit;
mod emoji_fetch;
mod sticker_create;
mod sticker_delete;
mod sticker_edit;
mod sticker_fetch;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        emoji_create::create_emoji,
        emoji_delete::delete_emoji,
        emoji_edit::edit_emoji,
        emoji_fetch::fetch_emoji,
        sticker_create::create_sticker,
        sticker_delete::delete_sticker,
        sticker_edit::edit_sticker,
        sticker_fetch::fetch_sticker,
        sticker_fetch::fetch_server_stickers
    ]
}
