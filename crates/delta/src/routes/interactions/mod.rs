use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod autocomplete;
mod modal;
mod modal_submit;
mod respond;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        respond::interaction_respond,
        autocomplete::interaction_autocomplete_respond,
        modal::interaction_modal,
        modal_submit::interaction_modal_submit
    ]
}
