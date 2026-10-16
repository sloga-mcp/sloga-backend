use revolt_database::Database;
use revolt_models::v0;
use revolt_result::{create_error, Result};
use revolt_rocket_okapi::gen::OpenApiGenerator;
use revolt_rocket_okapi::response::OpenApiResponderInner;
use revolt_rocket_okapi::revolt_okapi::openapi3::Responses;
use revolt_rocket_okapi::OpenApiError;
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use rocket::{Request, Response, State};

/// `Cache-Control` on every stats response. `public`: the route takes no
/// session and the body is the same for every caller.
pub const CACHE_CONTROL: &str = "public, max-age=30";

/// `Json<CipherStats>` with [`CACHE_CONTROL`] attached (pattern:
/// `discover::streamers_list::CachedStreamers`).
pub struct CachedCipherStats(pub Json<v0::CipherStats>);

impl<'r> Responder<'r, 'static> for CachedCipherStats {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        Response::build_from(self.0.respond_to(req)?)
            .raw_header("Cache-Control", CACHE_CONTROL)
            .ok()
    }
}

impl OpenApiResponderInner for CachedCipherStats {
    fn responses(generator: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        <Json<v0::CipherStats> as OpenApiResponderInner>::responses(generator)
    }
}

/// # Fetch Cipher Sale Stats
///
/// Public, unauthenticated: how many Cipher numbers are claimed, the cap,
/// and whether the sale is open.
#[openapi(tag = "Payments")]
#[get("/cipher/stats")]
pub async fn stats(db: &State<Database>) -> Result<CachedCipherStats> {
    // W3c fills this in
    let _ = db;
    Err(create_error!(PaymentsDisabled))
}
