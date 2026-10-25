//! Payments layer: provider-neutral orders and events, with Stripe as the
//! first provider and two SKU families: the Cipher founding sale and Prot.
//!
//! - [`catalog`]: server-owned prices, Prot grants, Prot packs and checkout quotes
//! - [`settings`]: validated view of `[features.payments]` + `[api.stripe]`
//!   (and of `[features.boosts.protection]` for Prot)
//! - [`stripe`]: webhook signatures, the API client and event parsing
//! - [`engine`]: the order state machine (checkout, fulfil, reverse, expire);
//!   [`engine::prot`] holds the Prot side (wallet credit, clawback, Cipher grants)
//! - [`dispatch`]: webhook event handling and the crond reconcile sweep

pub mod catalog;
pub mod dispatch;
pub mod engine;
pub mod settings;
pub mod stripe;
