use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod check_code;
mod milestones;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        // Public
        check_code::check_code,
        // Staff
        milestones::milestones,
    ]
}
