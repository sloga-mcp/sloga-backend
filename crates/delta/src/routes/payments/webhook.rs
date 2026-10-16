use std::sync::Arc;

use revolt_database::Database;
use revolt_payments::stripe::StripeApi;
use revolt_result::{create_error, Error, Result};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::{Data, Request, State};

/// The raw `Stripe-Signature` header (`t=…,v1=…`). Only its presence is
/// checked here; the route verifies it against the raw body.
#[derive(Debug)]
pub struct StripeSignature<'r>(pub &'r str);

impl std::ops::Deref for StripeSignature<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for StripeSignature<'r> {
    type Error = Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("Stripe-Signature") {
            Some(signature) => Outcome::Success(Self(signature)),
            None => Outcome::Error((Status::BadRequest, create_error!(InvalidOperation))),
        }
    }
}

/// # Stripe Webhook
///
/// Unauthenticated: a delivery is trusted only when its `Stripe-Signature`
/// verifies against the raw body. Answers with an empty body; the status
/// alone tells Stripe whether to retry.
#[openapi(skip)]
#[post("/stripe/webhook", data = "<data>")]
pub async fn webhook(
    db: &State<Database>,
    stripe: &State<Arc<dyn StripeApi>>,
    signature: StripeSignature<'_>,
    data: Data<'_>,
) -> Result<Status> {
    // W3b fills this in
    let _ = (db, stripe, signature, data);
    Err(create_error!(PaymentsDisabled))
}
