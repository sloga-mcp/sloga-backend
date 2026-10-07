use super::User;

#[cfg(feature = "rocket")]
use rocket::FromForm;

auto_derived!(
    /// One moderation or configuration action taken in a server
    ///
    /// No message content is ever included: entries carry ids plus a bounded
    /// list of typed changes and the moderator's optional reason.
    pub struct AuditLogEntry {
        /// Unique Id (ULID)
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub id: String,
        /// Id of the server the action was taken in
        pub server: String,
        /// Id of the user who took the action (absent = the system)
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub actor: Option<String>,
        /// What kind of action this was
        pub action: AuditLogAction,
        /// Id of the object acted on (a user, channel or role id, or
        /// `"default"` for default permissions), if the action has one
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub target: Option<String>,
        /// Id of the channel the action happened in, if relevant
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub channel: Option<String>,
        /// Typed before/after values for the fields the action changed
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Vec::is_empty", default)
        )]
        pub changes: Vec<AuditLogChange>,
        /// How many objects the action affected (bulk actions only)
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub count: Option<u32>,
        /// The moderator's reason, if one was given
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub reason: Option<String>,
    }

    /// One field an audited action changed
    pub struct AuditLogChange {
        /// Name of the changed field (snake_case)
        pub key: String,
        /// Value before the action, if there was one
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub old: Option<AuditValue>,
        /// Value after the action, if there is one
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub new: Option<AuditValue>,
    }

    /// A typed value inside an audit log change
    #[cfg_attr(feature = "serde", serde(tag = "type", content = "value"))]
    pub enum AuditValue {
        String(String),
        Int(i64),
        Bool(bool),
        StringList(Vec<String>),
    }

    /// Kind of audited action
    #[derive(Copy)]
    #[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
    pub enum AuditLogAction {
        MemberKick,
        MemberBanAdd,
        MemberBanRemove,
        MemberTimeout,
        MemberTimeoutRemove,
        MemberRoleUpdate,
        MemberUpdate,
        MemberVoiceUpdate,
        MemberMove,
        MemberDisconnect,
        MessageDelete,
        MessageBulkDelete,
        ChannelCreate,
        ChannelUpdate,
        ChannelDelete,
        ChannelOverwriteUpdate,
        ServerPermissionsUpdate,
        RoleCreate,
        RoleUpdate,
        RoleDelete,
        RoleRanksUpdate,
        ServerUpdate,
        ServerOwnerTransfer,
        /// An action this build does not know
        #[cfg_attr(feature = "serde", serde(other))]
        Unknown,
    }

    /// Options for fetching a server's audit log
    #[cfg_attr(feature = "rocket", derive(FromForm))]
    pub struct OptionsFetchAuditLog {
        /// Only return entries older than this entry id (26-character ULID)
        pub before: Option<String>,
        /// Maximum number of entries to return (1 to 100, default 50)
        pub limit: Option<i64>,
        /// Only return entries of this action (snake_case action name)
        pub action: Option<String>,
        /// Only return entries taken by this user
        pub user: Option<String>,
    }

    /// One page of a server's audit log
    pub struct AuditLogPage {
        /// Entries, newest first
        pub entries: Vec<AuditLogEntry>,
        /// The users the entries refer to
        pub users: Vec<User>,
    }
);
