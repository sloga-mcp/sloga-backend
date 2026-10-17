//! Which addresses january may connect to on behalf of a user-supplied URL
//!
//! The policy (and its tests) moved to `revolt_gamedata::ip_policy`, so
//! January and the game data client judge addresses with one shared copy.
//! This module keeps the `crate::ip_policy::...` paths working.

pub use revolt_gamedata::ip_policy::*;
