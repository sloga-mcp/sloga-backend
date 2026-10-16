use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;

/// # Fetch Own Cipher Membership
///
/// The session user's Cipher membership and unfinished checkout, if any.
#[openapi(tag = "Payments")]
#[get("/cipher/@me")]
pub async fn me(db: &State<Database>, user: User) -> Result<Json<v0::CipherMe>> {
    // W3c fills this in
    let _ = (db, user);
    Err(create_error!(PaymentsDisabled))
}
