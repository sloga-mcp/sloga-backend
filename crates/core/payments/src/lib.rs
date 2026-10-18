//! Payments layer: provider-neutral orders and events, with Stripe as the
//! first provider and the Cipher founding sale as the first SKU family.
//!
//! - [`catalog`]: server-owned prices, Prot grants and checkout quotes
//! - [`settings`]: validated view of `[features.payments]` + `[api.stripe]`
//! - [`stripe`]: webhook signatures, the API client and event parsing
//! - [`engine`]: the order state machine (checkout, fulfil, reverse, expire)
//! - [`dispatch`]: webhook event handling and the crond reconcile sweep

pub mod catalog;
pub mod dispatch;
pub mod engine;
pub mod settings;
pub mod stripe;
