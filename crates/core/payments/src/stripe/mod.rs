//! Stripe provider: webhook signature checks, the REST client and event parsing

pub mod client;
pub mod event;
pub mod signature;

// `client::MockStripe` is `#[cfg(any(test, feature = "test-mock"))]` and
// rides along with the glob under the same condition
pub use client::*;
pub use event::*;
pub use signature::*;
