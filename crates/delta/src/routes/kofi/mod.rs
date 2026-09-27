use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod admin;
mod webhook;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        webhook::webhook,
        admin::assign_donation,
        admin::revoke_donation,
        admin::import_donations
    ]
}
