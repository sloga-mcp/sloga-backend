use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

pub mod google_authorise;
pub mod google_callback;
pub mod google_complete;

/// Redis key holding the PKCE verifier for an in-flight authorisation
pub fn state_key(state: &str) -> String {
    format!("oauth:google:state:{}", state)
}

/// Redis key holding a serialised ResponseLogin awaiting client pickup
pub fn handoff_key(code: &str) -> String {
    format!("oauth:google:handoff:{}", code)
}

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        google_authorise::google_authorise,
        google_callback::google_callback,
        google_complete::google_complete
    ]
}
