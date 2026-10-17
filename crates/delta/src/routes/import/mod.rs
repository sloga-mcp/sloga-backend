use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod challenge;
mod discord_template;
mod dto;
mod job_active;
mod job_fetch;
mod source_server;
mod stickers_start;
mod stoat_source;
mod upstream_throttle;

/// For `GET /`, which advertises exactly the sources these routes accept
pub(crate) use source_server::ImportSource;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        challenge::import_source_challenge,
        challenge::import_unknown_source_challenge,
        discord_template::import_discord_template,
        job_active::fetch_active_import_job,
        job_fetch::fetch_import_job,
        source_server::import_source_server,
        source_server::import_unknown_source_server,
        stickers_start::import_discord_stickers
    ]
}
