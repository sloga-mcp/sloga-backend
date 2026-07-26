//! Discord server importer.
//!
//! Recreates a Discord community's structure as a new Sloga server the
//! requesting user owns. Delta validates the pasted template link and writes a
//! `Queued` job; this task claims it, does the work, and heart-beats progress
//! over the user's private WebSocket topic.
//!
//! Slice 0 imported the server name, categories and channels; slice 1 adds
//! roles, the `@everyone` → `default_permissions` rule and per-channel
//! permission overwrites. Emojis and the server icon need the optional bot
//! upgrade (slice 2) because guild templates do not carry them.

pub mod mapper;
pub mod permissions;
pub mod template;
mod worker;

pub use worker::task;
