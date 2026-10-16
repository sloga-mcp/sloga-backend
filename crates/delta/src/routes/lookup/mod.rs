//! Lookups that help a user compose a message: the game search behind the
//! composer's `/game`, `/wowitem` and `/champion` commands. A lookup only
//! returns candidates; it never posts anything. Picking a result sends its
//! URL as an ordinary message, and the embed pipeline draws the card.

use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod games;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![games::lookup_games]
}
