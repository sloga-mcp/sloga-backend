use std::sync::Arc;

use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_payments::stripe::StripeApi;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;

/// # Start Cipher Checkout
///
/// Create (or reuse) a Stripe Checkout session for a Cipher tier and return
/// the hosted page to send the user to. Prices and upgrades are quoted by the
/// server; the body only names the tier wanted.
#[openapi(tag = "Payments")]
#[post("/cipher/checkout", data = "<data>")]
pub async fn checkout(
    db: &State<Database>,
    stripe: &State<Arc<dyn StripeApi>>,
    user: User,
    data: Json<v0::DataCipherCheckout>,
) -> Result<Json<v0::CipherCheckoutResponse>> {
    // W3a fills this in
    let _ = (db, stripe, user, data);
    Err(create_error!(PaymentsDisabled))
}
