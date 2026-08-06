//! Discord server importer.
//!
//! Recreates a Discord community's structure as a new Sloga server the
//! requesting user owns. Delta validates the pasted template link and writes a
//! `Queued` job; this task claims it, does the work, and heart-beats progress
//! over the user's private WebSocket topic.
//!
//! Slice 0 imported the server name, categories and channels; slice 1 added
//! roles, the `@everyone` → `default_permissions` rule and per-channel
//! permission overwrites. Slice 2 adds the optional bot upgrade: sticker
//! import from the source guild (guild templates carry no stickers — an
//! operator-owned bot the user adds to their guild is the only way to read
//! them). Emojis and the server icon remain future work on the same bot
//! plumbing.

pub mod mapper;
pub mod permissions;
mod stickers;
pub mod template;
mod worker;

pub use worker::task;
