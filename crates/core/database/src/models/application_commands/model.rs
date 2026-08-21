use revolt_models::v0;

/// Maximum number of global commands per bot
pub const MAX_GLOBAL_COMMANDS: usize = 100;

/// Maximum number of commands per bot per server
pub const MAX_SERVER_COMMANDS: usize = 100;

auto_derived!(
    /// Type of a command option value
    pub enum CommandOptionKind {
        String,
        Integer,
        Boolean,
        User,
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
        /// Option name
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
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub autocomplete: bool,
    }
);

auto_derived_partial!(
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
    },
    "PartialApplicationCommand"
);

impl From<v0::CommandOptionKind> for CommandOptionKind {
    fn from(value: v0::CommandOptionKind) -> Self {
        match value {
            v0::CommandOptionKind::String => CommandOptionKind::String,
            v0::CommandOptionKind::Integer => CommandOptionKind::Integer,
            v0::CommandOptionKind::Boolean => CommandOptionKind::Boolean,
            v0::CommandOptionKind::User => CommandOptionKind::User,
            v0::CommandOptionKind::Channel => CommandOptionKind::Channel,
        }
    }
}

impl From<CommandOptionKind> for v0::CommandOptionKind {
    fn from(value: CommandOptionKind) -> Self {
        match value {
            CommandOptionKind::String => v0::CommandOptionKind::String,
            CommandOptionKind::Integer => v0::CommandOptionKind::Integer,
            CommandOptionKind::Boolean => v0::CommandOptionKind::Boolean,
            CommandOptionKind::User => v0::CommandOptionKind::User,
            CommandOptionKind::Channel => v0::CommandOptionKind::Channel,
        }
    }
}

impl From<v0::CommandChoice> for CommandChoice {
    fn from(value: v0::CommandChoice) -> Self {
        CommandChoice {
            name: value.name,
            value: value.value,
        }
    }
}

impl From<CommandChoice> for v0::CommandChoice {
    fn from(value: CommandChoice) -> Self {
        v0::CommandChoice {
            name: value.name,
            value: value.value,
        }
    }
}

impl From<v0::CommandOption> for CommandOption {
    fn from(value: v0::CommandOption) -> Self {
        CommandOption {
            name: value.name,
            description: value.description,
            kind: value.kind.into(),
            required: value.required,
            choices: value.choices.into_iter().map(Into::into).collect(),
            autocomplete: value.autocomplete,
        }
    }
}

impl From<CommandOption> for v0::CommandOption {
    fn from(value: CommandOption) -> Self {
        v0::CommandOption {
            name: value.name,
            description: value.description,
            kind: value.kind.into(),
            required: value.required,
            choices: value.choices.into_iter().map(Into::into).collect(),
            autocomplete: value.autocomplete,
        }
    }
}

impl From<ApplicationCommand> for v0::ApplicationCommand {
    fn from(value: ApplicationCommand) -> Self {
        v0::ApplicationCommand {
            id: value.id,
            bot_id: value.bot_id,
            server: value.server,
            name: value.name,
            description: value.description,
            options: value.options.into_iter().map(Into::into).collect(),
        }
    }
}
