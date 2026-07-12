use std::collections::HashMap;

use revolt_models::v0;
use revolt_result::{create_error, Result};

/// How long an interaction may be responded to after creation.
pub const INTERACTION_TTL_MS: u64 = 15 * 60 * 1000;

/// Length of the response token in bytes (hex-encoded to 64 chars).
pub const INTERACTION_TOKEN_BYTES: usize = 32;

auto_derived!(
    /// What kind of interaction this is
    pub enum InteractionKind {
        /// A slash command invocation
        Command,
        /// A click on a message component (slice 2)
        Component,
        /// An option-autocomplete round-trip (slice 3)
        Autocomplete,
        /// A modal submission (slice 3)
        ModalSubmit,
    }

    /// A transient, single-use interaction row.
    ///
    /// The ULID id doubles as the creation clock: expiry checks parse its
    /// timestamp, and the cleanup sweep deletes by id range — no TTL index
    /// or date field needed, identical behaviour on both drivers.
    pub struct Interaction {
        /// Interaction Id
        #[serde(rename = "_id")]
        pub id: String,
        /// What kind of interaction this is
        pub kind: InteractionKind,
        /// Single-use response token (secret between server and bot)
        pub token: String,
        /// Bot the interaction is addressed to
        pub bot_id: String,
        /// User who triggered the interaction
        pub user_id: String,
        /// Channel the interaction happened in
        pub channel_id: String,
        /// Message the interaction targets (components, slice 2)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub message_id: Option<String>,
        /// Id of the invoked command
        #[serde(skip_serializing_if = "Option::is_none")]
        pub command_id: Option<String>,
        /// Name of the invoked command (convenience copy)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub command_name: Option<String>,
        /// Supplied option values, validated against the command's schema
        #[serde(skip_serializing_if = "HashMap::is_empty", default)]
        pub options: HashMap<String, String>,
        /// Whether the bot has already responded (single-use)
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub responded: bool,
    }

    /// Interaction context carried on a response message ("used /cmd")
    pub struct MessageInteraction {
        /// Id of the interaction this message responds to
        pub id: String,
        /// User who invoked the command
        pub user_id: String,
        /// Name of the invoked command
        pub command_name: String,
    }
);

impl Interaction {
    /// Verify the caller-supplied response token in constant time.
    ///
    /// Deliberately NOT the webhook `assert_token` implementation — that is a
    /// plain string compare and a timing oracle; this XOR-folds the full
    /// buffers so the comparison time is independent of where they differ.
    pub fn assert_token(&self, token: &str) -> Result<()> {
        let ours = self.token.as_bytes();
        let theirs = token.as_bytes();

        // Fold the length difference in rather than early-returning; iterate
        // over OUR token so the loop bound never depends on caller input.
        // (Boolean, not XOR-cast-to-u8: a cast would wrap at 256 and admit
        // candidates exactly 256 bytes longer than the real token.)
        let mut diff = (ours.len() != theirs.len()) as u8;
        for (index, byte) in ours.iter().enumerate() {
            diff |= byte ^ theirs.get(index).copied().unwrap_or(0);
        }

        if diff == 0 {
            Ok(())
        } else {
            Err(create_error!(NotAuthenticated))
        }
    }

    /// Milliseconds since epoch at which this interaction was created,
    /// derived from the ULID id.
    pub fn created_at_ms(&self) -> u64 {
        ulid::Ulid::from_string(&self.id)
            .map(|ulid| ulid.timestamp_ms())
            .unwrap_or(0)
    }

    /// Whether the response window has closed.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.created_at_ms()) > INTERACTION_TTL_MS
    }

    /// Wire representation, delivered ONLY on the bot's private topic
    /// (it carries the response token).
    pub fn into_wire(self) -> v0::Interaction {
        v0::Interaction {
            id: self.id,
            kind: match self.kind {
                InteractionKind::Command => v0::InteractionKind::Command,
                InteractionKind::Component => v0::InteractionKind::Component,
                InteractionKind::Autocomplete => v0::InteractionKind::Autocomplete,
                InteractionKind::ModalSubmit => v0::InteractionKind::ModalSubmit,
            },
            channel_id: self.channel_id,
            user_id: self.user_id,
            bot_id: self.bot_id,
            command_id: self.command_id,
            command_name: self.command_name,
            options: self.options,
            token: self.token,
        }
    }
}

impl From<MessageInteraction> for v0::MessageInteraction {
    fn from(value: MessageInteraction) -> Self {
        v0::MessageInteraction {
            id: value.id,
            user_id: value.user_id,
            command_name: value.command_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interaction(id: &str, token: &str) -> Interaction {
        Interaction {
            id: id.to_string(),
            kind: InteractionKind::Command,
            token: token.to_string(),
            bot_id: "bot".to_string(),
            user_id: "user".to_string(),
            channel_id: "channel".to_string(),
            message_id: None,
            command_id: None,
            command_name: None,
            options: Default::default(),
            responded: false,
        }
    }

    #[test]
    fn token_assertion() {
        let row = interaction("01H000000000000000000000000", "secret-token-value");
        assert!(row.assert_token("secret-token-value").is_ok());
        assert!(row.assert_token("secret-token-valuX").is_err());
        assert!(row.assert_token("secret").is_err());
        assert!(row.assert_token("").is_err());
        assert!(row.assert_token("secret-token-value-plus-suffix").is_err());
    }

    #[test]
    fn expiry_from_ulid_clock() {
        let id = ulid::Ulid::from_parts(1_000_000, 0).to_string();
        let row = interaction(&id, "t");
        assert!(!row.is_expired(1_000_000 + INTERACTION_TTL_MS));
        assert!(row.is_expired(1_000_000 + INTERACTION_TTL_MS + 1));
    }
}
