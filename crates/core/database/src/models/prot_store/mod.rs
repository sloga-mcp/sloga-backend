//! Prot sold as App Store / Google Play in-app purchases (S6): the stored
//! purchase rows, intents and reconcile cursors, the pure purchase-row state
//! machine, and the store's ledger keys. Every Prot movement of a store row
//! goes through `AbstractProtLedger::apply_store_purchase_move` (the row move
//! and its postings in one transaction); the methods here only read rows and
//! do the bookkeeping writes, each of which bumps the row's `version`.

mod model;
mod ops;

pub use model::*;
pub use ops::AbstractProtStore;
