use std::collections::HashMap;

use once_cell::sync::Lazy;
use regex::Regex;

#[cfg(feature = "validator")]
use validator::Validate;

/// Command names are Discord-shaped: lowercase, digits, `_` and `-`.
pub static RE_COMMAND_NAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9_-]+$").unwrap());

/// Maximum number of options on a single command
pub const MAX_COMMAND_OPTIONS: usize = 10;

/// Maximum number of choices on a single command option
pub const MAX_OPTION_CHOICES: usize = 25;

/// Maximum length of a supplied option value
pub const MAX_OPTION_VALUE_LENGTH: usize = 2000;

auto_derived!(
    /// Type of a command option value
    pub enum CommandOptionKind {
        /// Free-form text
        String,
        /// Whole number (validated as i64)
        Integer,
        /// true / false
        Boolean,
        /// A user id
        User,
        /// A channel id
        Channel,
    }

    /// A fixed choice a command option may offer
    pub struct CommandChoice {
        /// Human-readable choice name
        pub name: String,
        /// Value submitted when this choice is picked
        pub value: String,
    }

    /// A typed option (argument) accepted by a command
    pub struct CommandOption {
        /// Option name (same charset rules as command names)
        pub name: String,
        /// What this option is for
        pub description: String,
        /// Type of the value this option accepts
        pub kind: CommandOptionKind,
        /// Whether the option must be supplied on invocation
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub required: bool,
        /// Fixed set of allowed values (String/Integer kinds only)
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub choices: Vec<CommandChoice>,
    }

    /// A slash command registered by a bot
    pub struct ApplicationCommand {
        /// Command Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Bot this command belongs to
        pub bot_id: String,
        /// Server this command is scoped to (None = global)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub server: Option<String>,
        /// Command name (unique per bot+scope)
        pub name: String,
        /// What this command does
        pub description: String,
        /// Typed options accepted by this command
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub options: Vec<CommandOption>,
    }

    /// Register a new slash command
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataCreateCommand {
        /// Command name
        #[cfg_attr(
            feature = "validator",
            validate(length(min = 1, max = 32), regex = "RE_COMMAND_NAME")
        )]
        pub name: String,
        /// What this command does
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 100)))]
        pub description: String,
        /// Server to scope this command to (omit for global)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub server: Option<String>,
        /// Typed options accepted by this command
        #[serde(default)]
        pub options: Vec<CommandOption>,
    }

    /// Edit an existing slash command
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataEditCommand {
        /// New command name
        #[cfg_attr(
            feature = "validator",
            validate(length(min = 1, max = 32), regex = "RE_COMMAND_NAME")
        )]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// New description
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 100)))]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// Replacement option list
        #[serde(skip_serializing_if = "Option::is_none")]
        pub options: Option<Vec<CommandOption>>,
    }

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

    /// A transient interaction, delivered to the bot on its private topic.
    ///
    /// Carries the per-interaction response token — this event must NEVER be
    /// published anywhere except the bot user's private topic.
    pub struct Interaction {
        /// Interaction Id
        #[serde(rename = "_id")]
        pub id: String,
        /// What kind of interaction this is
        pub kind: InteractionKind,
        /// Channel the interaction happened in
        pub channel_id: String,
        /// User who triggered the interaction
        pub user_id: String,
        /// Bot the interaction is addressed to
        pub bot_id: String,
        /// Id of the invoked command
        #[serde(skip_serializing_if = "Option::is_none")]
        pub command_id: Option<String>,
        /// Name of the invoked command (convenience copy)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub command_name: Option<String>,
        /// Supplied option values, validated against the command's schema
        #[serde(skip_serializing_if = "HashMap::is_empty", default)]
        pub options: HashMap<String, String>,
        /// Single-use response token (secret between server and bot)
        pub token: String,
    }

    /// Invoke a slash command in a channel
    pub struct DataCreateInteraction {
        /// Id of the command to invoke
        pub command_id: String,
        /// Option values, keyed by option name
        #[serde(default)]
        pub options: HashMap<String, String>,
    }

    /// Response returned to the invoking user
    pub struct CreateInteractionResponse {
        /// Id of the created interaction
        pub interaction_id: String,
    }

    /// A bot's response to an interaction
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataInteractionRespond {
        /// The interaction's response token (delivered with InteractionCreate)
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
        pub token: String,
        /// Message content to send
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 2000)))]
        pub content: String,
    }

    /// Interaction context carried on a response message ("used /cmd").
    ///
    /// Server-set only — the regular send path never accepts this field, and
    /// the accompanying `Interaction` message flag is rejected from clients,
    /// so its presence proves the message is a genuine command response.
    pub struct MessageInteraction {
        /// Id of the interaction this message responds to
        pub id: String,
        /// User who invoked the command
        pub user_id: String,
        /// Name of the invoked command
        pub command_name: String,
    }
);

impl CommandOption {
    /// Structural validation shared by create/edit routes (validator derive
    /// can't recurse into `Vec<CommandOption>` fields on the DTOs).
    pub fn validate_structure(options: &[CommandOption]) -> std::result::Result<(), String> {
        if options.len() > MAX_COMMAND_OPTIONS {
            return Err(format!("at most {MAX_COMMAND_OPTIONS} options"));
        }

        for (index, option) in options.iter().enumerate() {
            if option.name.is_empty()
                || option.name.len() > 32
                || !RE_COMMAND_NAME.is_match(&option.name)
            {
                return Err(format!("invalid option name `{}`", option.name));
            }

            if options[..index].iter().any(|o| o.name == option.name) {
                return Err(format!("duplicate option name `{}`", option.name));
            }

            if option.description.is_empty() || option.description.len() > 100 {
                return Err(format!("invalid description for `{}`", option.name));
            }

            if option.choices.len() > MAX_OPTION_CHOICES {
                return Err(format!(
                    "at most {MAX_OPTION_CHOICES} choices for `{}`",
                    option.name
                ));
            }

            if !option.choices.is_empty()
                && !matches!(
                    option.kind,
                    CommandOptionKind::String | CommandOptionKind::Integer
                )
            {
                return Err(format!(
                    "choices are only valid on String/Integer options (`{}`)",
                    option.name
                ));
            }

            for choice in &option.choices {
                if choice.name.is_empty()
                    || choice.name.len() > 100
                    || choice.value.is_empty()
                    || choice.value.len() > 100
                {
                    return Err(format!("invalid choice on `{}`", option.name));
                }

                if matches!(option.kind, CommandOptionKind::Integer)
                    && choice.value.parse::<i64>().is_err()
                {
                    return Err(format!(
                        "Integer option `{}` has non-integer choice value",
                        option.name
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validate one supplied value against this option's declared kind.
    pub fn validate_value(&self, value: &str) -> std::result::Result<(), String> {
        if value.len() > MAX_OPTION_VALUE_LENGTH {
            return Err(format!("value for `{}` too long", self.name));
        }

        if !self.choices.is_empty() && !self.choices.iter().any(|c| c.value == value) {
            return Err(format!("value for `{}` is not one of its choices", self.name));
        }

        match self.kind {
            CommandOptionKind::String => Ok(()),
            CommandOptionKind::Integer => value
                .parse::<i64>()
                .map(|_| ())
                .map_err(|_| format!("value for `{}` must be an integer", self.name)),
            CommandOptionKind::Boolean => match value {
                "true" | "false" => Ok(()),
                _ => Err(format!("value for `{}` must be true or false", self.name)),
            },
            CommandOptionKind::User | CommandOptionKind::Channel => {
                if value.len() == 26 && value.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    Ok(())
                } else {
                    Err(format!("value for `{}` must be an id", self.name))
                }
            }
        }
    }
}
