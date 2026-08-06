use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod discord_template;
mod dto;
mod job_active;
mod job_fetch;
mod stickers_start;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        discord_template::import_discord_template,
        job_active::fetch_active_import_job,
        job_fetch::fetch_import_job,
        stickers_start::import_discord_stickers
    ]
}
