//! Payments: the Cipher founding sale over Stripe Checkout.
//!
//! The order state machine lives in `revolt_payments`; these routes only
//! authenticate, load `PaymentsSettings` and hand over. The Stripe client is
//! managed state (`Arc<dyn StripeApi>`), so route tests swap in `MockStripe`
//! through `TestHarness::stripe`.
use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod checkout;
mod me;
mod prot;
mod stats;
mod webhook;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        // Session user
        checkout::checkout,
        me::me,
        prot::prot_checkout,
        prot::prot_me,
        // Public
        stats::stats,
        // Stripe
        webhook::webhook,
    ]
}
