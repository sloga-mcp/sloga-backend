use std::collections::HashMap;

use once_cell::sync::Lazy;
use regex::Regex;

use super::ActionRow;

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

/// Maximum number of text inputs on a single modal
pub const MAX_MODAL_INPUTS: usize = 5;

/// Maximum length of a value typed into a modal text input
pub const MAX_MODAL_VALUE_LENGTH: usize = 4000;

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
        /// Ask the bot for suggestions as the user types this option
        /// (String/Integer kinds only, and mutually exclusive with a fixed
        /// `choices` list — a fixed list is already the complete answer).
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub autocomplete: bool,
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
        /// Message the interaction targets (Component kind)
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
        /// Supplied option values, validated against the command's schema.
        ///
        /// On an `Autocomplete` interaction these are whatever the user has
        /// typed so far, so they are deliberately NOT schema-validated. On a
        /// `ModalSubmit` they are the submitted inputs, keyed by input id.
        #[serde(skip_serializing_if = "HashMap::is_empty", default)]
        pub options: HashMap<String, String>,
        /// Option the user is currently typing (`Autocomplete` kind)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub focused_option: Option<String>,
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

    /// Ask a bot to suggest values for the option being typed
    pub struct DataCreateAutocomplete {
        /// Id of the command being composed
        pub command_id: String,
        /// Name of the option the caret is currently in
        pub focused_option: String,
        /// Everything typed so far, keyed by option name. Partial by
        /// definition, so the server does not schema-check these values.
        #[serde(default)]
        pub options: HashMap<String, String>,
    }

    /// Response returned to the invoking user
    pub struct CreateInteractionResponse {
        /// Id of the created interaction
        pub interaction_id: String,
    }

    /// Visual style of a modal text input
    pub enum TextInputStyle {
        /// Single-line field
        Short,
        /// Multi-line field
        Paragraph,
    }

    /// One text field on a modal
    pub struct ModalTextInput {
        /// Bot-chosen id, echoed back with the submitted value
        pub custom_id: String,
        /// Field label
        pub label: String,
        /// Single- or multi-line
        pub style: TextInputStyle,
        /// Whether the field must be filled in
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub required: bool,
        /// Shortest accepted value
        #[serde(skip_serializing_if = "Option::is_none")]
        pub min_length: Option<u32>,
        /// Longest accepted value
        #[serde(skip_serializing_if = "Option::is_none")]
        pub max_length: Option<u32>,
        /// Hint shown while the field is empty
        #[serde(skip_serializing_if = "Option::is_none")]
        pub placeholder: Option<String>,
        /// Value the field opens with
        #[serde(skip_serializing_if = "Option::is_none")]
        pub value: Option<String>,
    }

    /// A form a bot asks the invoking user to fill in.
    ///
    /// Inputs are a flat list rather than component rows: a modal only ever
    /// holds text inputs, one per row, so rows would carry no information.
    pub struct Modal {
        /// Bot-chosen id, echoed back on submission
        pub custom_id: String,
        /// Heading shown on the form
        pub title: String,
        /// Text fields to collect (1..=5)
        pub inputs: Vec<ModalTextInput>,
    }

    /// A bot's response to an interaction
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataInteractionRespond {
        /// The interaction's response token (delivered with InteractionCreate)
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
        pub token: String,
        /// Message content to send (or replace, when editing).
        ///
        /// Optional since slice 2: a response may carry only components.
        /// When present it must be non-empty.
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 2000)))]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub content: Option<String>,
        /// Components to attach (or replace, when editing)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub components: Option<Vec<ActionRow>>,
        /// Edit the message the component lives on instead of sending a new
        /// message (Component interactions only)
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub edit: bool,
        /// Deliver the response only to the invoking user. Ephemeral
        /// responses are never persisted (gone on reload) and are published
        /// solely on the invoker's private topic. Incompatible with `edit`
        /// and with `components`.
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub ephemeral: bool,
    }

    /// Suggestions a bot returns for an in-flight autocomplete
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataInteractionAutocomplete {
        /// The interaction's response token (delivered with InteractionCreate)
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
        pub token: String,
        /// Suggestions to offer, best first (0..=25). An empty list is a
        /// valid answer meaning "nothing matches".
        pub choices: Vec<CommandChoice>,
    }

    /// A bot's request to open a modal on the invoking user's client
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataInteractionModal {
        /// The interaction's response token (delivered with InteractionCreate)
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
        pub token: String,
        /// The form to show
        pub modal: Modal,
    }

    /// A filled-in modal, submitted by the user the modal was shown to
    pub struct DataModalSubmit {
        /// Submitted values, keyed by text input id
        #[serde(default)]
        pub values: HashMap<String, String>,
    }

    /// Interact with a component on a message
    pub struct DataMessageInteract {
        /// Custom id of the component being interacted with
        pub custom_id: String,
        /// Selected values (selects only; exactly one)
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub values: Vec<String>,
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

impl CommandChoice {
    /// Validate a list of suggestions returned for an autocomplete round-trip.
    ///
    /// An empty list is legal — it is how a bot says "nothing matches".
    pub fn validate_list(choices: &[CommandChoice]) -> std::result::Result<(), String> {
        if choices.len() > MAX_OPTION_CHOICES {
            return Err(format!("at most {MAX_OPTION_CHOICES} choices"));
        }

        for choice in choices {
            if choice.name.is_empty()
                || choice.name.len() > 100
                || choice.value.is_empty()
                || choice.value.len() > 100
            {
                return Err("choice names and values must be 1..=100 characters".to_string());
            }
        }

        Ok(())
    }
}

impl Modal {
    /// Structural validation of a bot-authored modal, run before it is
    /// stored and shown to anyone.
    pub fn validate_structure(&self) -> std::result::Result<(), String> {
        if self.custom_id.is_empty() || self.custom_id.len() > 64 {
            return Err("modal custom_id must be 1..=64 characters".to_string());
        }

        if self.title.is_empty() || self.title.len() > 100 {
            return Err("modal title must be 1..=100 characters".to_string());
        }

        if self.inputs.is_empty() {
            return Err("a modal must have at least one input".to_string());
        }

        if self.inputs.len() > MAX_MODAL_INPUTS {
            return Err(format!("at most {MAX_MODAL_INPUTS} modal inputs"));
        }

        let mut seen_ids: Vec<&str> = Vec::new();

        for input in &self.inputs {
            if input.custom_id.is_empty() || input.custom_id.len() > 64 {
                return Err("input custom_id must be 1..=64 characters".to_string());
            }

            if seen_ids.contains(&input.custom_id.as_str()) {
                return Err(format!("duplicate custom_id `{}`", input.custom_id));
            }
            seen_ids.push(&input.custom_id);

            if input.label.is_empty() || input.label.len() > 80 {
                return Err("input labels must be 1..=80 characters".to_string());
            }

            if let Some(placeholder) = &input.placeholder {
                if placeholder.len() > 100 {
                    return Err("input placeholders must be at most 100 characters".to_string());
                }
            }

            let max_length = input.max_length.unwrap_or(MAX_MODAL_VALUE_LENGTH as u32);
            if max_length == 0 || max_length as usize > MAX_MODAL_VALUE_LENGTH {
                return Err(format!("max_length must be 1..={MAX_MODAL_VALUE_LENGTH}"));
            }

            if let Some(min_length) = input.min_length {
                if min_length as usize > MAX_MODAL_VALUE_LENGTH {
                    return Err(format!("min_length must be at most {MAX_MODAL_VALUE_LENGTH}"));
                }

                if min_length > max_length {
                    return Err(format!(
                        "min_length exceeds max_length on `{}`",
                        input.custom_id
                    ));
                }
            }

            // A prefill the user cannot legally submit unchanged would make
            // the form unsubmittable for anyone who just presses OK.
            if let Some(value) = &input.value {
                let length = value.chars().count();
                if length > max_length as usize {
                    return Err(format!(
                        "prefilled value exceeds max_length on `{}`",
                        input.custom_id
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validate a user's submission against this modal's stored definition.
    ///
    /// The definition is read from the server-side interaction row, never
    /// from the submitting client — otherwise a caller could relax the very
    /// constraints being checked.
    pub fn validate_submission(
        &self,
        values: &HashMap<String, String>,
    ) -> std::result::Result<(), String> {
        for name in values.keys() {
            if !self.inputs.iter().any(|input| &input.custom_id == name) {
                return Err(format!("unknown input `{name}`"));
            }
        }

        for input in &self.inputs {
            let value = values.get(&input.custom_id).map(String::as_str).unwrap_or("");

            if input.required && value.trim().is_empty() {
                return Err(format!("`{}` is required", input.custom_id));
            }

            // Lengths are counted in characters, not bytes: the bot declared
            // these limits expecting what the user sees typed, and a byte
            // count would reject valid CJK or emoji input well under the
            // stated limit.
            let length = value.chars().count();

            if length > MAX_MODAL_VALUE_LENGTH {
                return Err(format!("value for `{}` too long", input.custom_id));
            }

            if let Some(max_length) = input.max_length {
                if length > max_length as usize {
                    return Err(format!("value for `{}` too long", input.custom_id));
                }
            }

            // An omitted optional field is absent, not short — only hold a
            // value that was actually supplied to the minimum.
            if !value.is_empty() {
                if let Some(min_length) = input.min_length {
                    if length < min_length as usize {
                        return Err(format!("value for `{}` too short", input.custom_id));
                    }
                }
            }
        }

        Ok(())
    }
}

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

            if option.autocomplete {
                if !matches!(
                    option.kind,
                    CommandOptionKind::String | CommandOptionKind::Integer
                ) {
                    return Err(format!(
                        "autocomplete is only valid on String/Integer options (`{}`)",
                        option.name
                    ));
                }

                // A fixed choice list is already the complete set of answers;
                // accepting both would leave the client with two competing
                // sources for one dropdown.
                if !option.choices.is_empty() {
                    return Err(format!(
                        "`{}` cannot use both choices and autocomplete",
                        option.name
                    ));
                }
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
