use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod respond;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![respond::interaction_respond]
}
