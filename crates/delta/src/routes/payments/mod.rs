//! Payments: the Cipher founding sale over Stripe Checkout.
//!
//! The order state machine lives in `revolt_payments`; these routes only
//! authenticate, load `PaymentsSettings` and hand over. The Stripe client is
//! managed state (`Arc<dyn StripeApi>`), so route tests swap in `MockStripe`
//! through `TestHarness::stripe`. In-app Prot (App Store, Google Play) works
//! the same way with `TestHarness::apple` and `TestHarness::play`.
use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod apple_notifications;
mod checkout;
mod me;
mod prot;
mod prot_store;
mod stats;
mod webhook;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        // Session user
        checkout::checkout,
        me::me,
        prot::prot_checkout,
        prot::prot_me,
        prot_store::prot_store_intent,
        prot_store::prot_store_intent_cancel,
        prot_store::prot_store_verify,
        // Public
        stats::stats,
        // Stripe
        webhook::webhook,
        // App Store Server Notifications
        apple_notifications::apple_notifications,
    ]
}
