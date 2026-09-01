use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

pub mod apple_authorise;
pub mod apple_callback;
pub mod apple_complete;
pub mod google_authorise;
pub mod google_callback;
pub mod google_complete;
pub mod kick_callback;
pub mod link;
pub mod twitch_callback;
pub mod youtube_callback;

/// Redis key holding the PKCE verifier for an in-flight authorisation
pub fn state_key(provider: &str, state: &str) -> String {
    format!("oauth:{}:state:{}", provider, state)
}

/// Redis key holding a serialised ResponseLogin awaiting client pickup
pub fn handoff_key(provider: &str, code: &str) -> String {
    format!("oauth:{}:handoff:{}", provider, code)
}

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        google_authorise::google_authorise,
        google_callback::google_callback,
        google_complete::google_complete,
        apple_authorise::apple_authorise,
        apple_callback::apple_callback,
        apple_complete::apple_complete,
        twitch_callback::twitch_callback,
        youtube_callback::youtube_callback,
        kick_callback::kick_callback
    ]
}
