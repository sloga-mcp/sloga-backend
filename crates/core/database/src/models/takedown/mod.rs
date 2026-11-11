mod links;
mod model;
mod ops;
mod resolve;

/// Not glob-exported: `RemovalOutcome` would clash with the server member
/// type of the same name. Reach it as `revolt_database::removal::*`.
pub mod removal;

pub use links::*;
pub use model::*;
pub use ops::AbstractTakedownRequests;
pub use resolve::*;
