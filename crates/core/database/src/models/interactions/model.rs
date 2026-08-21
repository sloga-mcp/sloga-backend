use std::collections::HashMap;

use revolt_models::v0;
use revolt_result::{create_error, Result};

/// How long an interaction may be responded to after creation.
pub const INTERACTION_TTL_MS: u64 = 15 * 60 * 1000;

/// How long an autocomplete round-trip stays answerable.
///
/// Far shorter than the general window on purpose: suggestions for a caret
/// that moved on are useless, and autocomplete is the one interaction kind a
/// user creates by typing, so a 15-minute row per keystroke burst would be a
/// needless amount of live state.
pub const AUTOCOMPLETE_TTL_MS: u64 = 60 * 1000;

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
        /// Custom id of the clicked component (Component kind)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub custom_id: Option<String>,
        /// Submitted select values (Component kind, selects only)
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub values: Vec<String>,
        /// Supplied option values. Schema-validated for `Command`; partial
        /// input for `Autocomplete`; submitted fields for `ModalSubmit`.
        #[serde(skip_serializing_if = "HashMap::is_empty", default)]
        pub options: HashMap<String, String>,
        /// Option the user is currently typing (`Autocomplete` kind)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub focused_option: Option<String>,
        /// The form shown to the user (`ModalSubmit` kind).
        ///
        /// Stored so the submission is validated against what the bot
        /// actually asked for, rather than against anything the submitting
        /// client echoes back.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub modal: Option<v0::Modal>,
        /// Values the user typed into the modal.
        ///
        /// A list of pairs rather than a map because the keys are bot-chosen
        /// strings, and a stored map would turn them into document field
        /// names — where a `.` or a leading `$` is a storage hazard. They are
        /// folded back into a map for the bot at wire time.
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub submitted_values: Vec<ModalValue>,
        /// Whether the user has already submitted the modal (single-use)
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub submitted: bool,
        /// Whether the bot has already responded (single-use)
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub responded: bool,
    }

    /// One filled-in modal field
    pub struct ModalValue {
        /// Id of the text input this value came from
        pub custom_id: String,
        /// What the user typed
        pub value: String,
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

    /// How long this interaction stays answerable, by kind.
    pub fn ttl_ms(&self) -> u64 {
        match self.kind {
            InteractionKind::Autocomplete => AUTOCOMPLETE_TTL_MS,
            _ => INTERACTION_TTL_MS,
        }
    }

    /// Whether the response window has closed.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.created_at_ms()) > self.ttl_ms()
    }

    /// Wire representation, delivered ONLY on the bot's private topic
    /// (it carries the response token).
    pub fn into_wire(self) -> v0::Interaction {
        // Modal submissions reach the bot as ordinary option values, keyed by
        // the input ids it chose — the pair-list is a storage detail.
        let mut options = self.options;
        for submitted in self.submitted_values {
            options.insert(submitted.custom_id, submitted.value);
        }

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
            message_id: self.message_id,
            command_id: self.command_id,
            command_name: self.command_name,
            custom_id: self.custom_id,
            values: self.values,
            options,
            focused_option: self.focused_option,
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
            custom_id: None,
            values: Vec::new(),
            options: Default::default(),
            focused_option: None,
            modal: None,
            submitted_values: Vec::new(),
            submitted: false,
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

    #[test]
    fn autocomplete_expires_on_its_own_shorter_clock() {
        let id = ulid::Ulid::from_parts(1_000_000, 0).to_string();
        let mut row = interaction(&id, "t");
        row.kind = InteractionKind::Autocomplete;

        assert!(!row.is_expired(1_000_000 + AUTOCOMPLETE_TTL_MS));
        assert!(row.is_expired(1_000_000 + AUTOCOMPLETE_TTL_MS + 1));

        // Still well inside the window every other kind would be using
        assert!(AUTOCOMPLETE_TTL_MS < INTERACTION_TTL_MS);
        assert!(row.is_expired(1_000_000 + INTERACTION_TTL_MS));
    }
}
