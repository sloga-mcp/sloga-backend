use ulid::Ulid;

use crate::Database;

/// How long an audit log entry is kept before the crond prune deletes it.
pub const AUDIT_LOG_RETENTION_DAYS: i64 = 45;

/// The most entries a single audit log fetch may return.
pub const AUDIT_LOG_FETCH_MAX: i64 = 100;

/// How many entries an audit log fetch returns when no limit is given.
pub const AUDIT_LOG_FETCH_DEFAULT: i64 = 50;

auto_derived!(
    /// One moderation or configuration action taken in a server.
    ///
    /// Entries are append-only and keyed by a ULID, which is at once the
    /// timestamp, the pagination cursor and the prune key.
    ///
    /// What an entry stores, and what it never stores:
    /// - No message content is ever stored. A message deletion records the
    ///   message id, its author and its channel, never the text.
    /// - Everything else is ids (actor, target, channel) plus a bounded list
    ///   of typed `changes` and the moderator's optional reason.
    /// - Some change values are free text that can identify a person, such as
    ///   a nickname or a role name. They are not scrubbed when the account is
    ///   deleted; the entry keeps the ids and the user renders as a deleted
    ///   user. The `AUDIT_LOG_RETENTION_DAYS` (45 day) retention is what
    ///   bounds how long that text survives an account deletion.
    pub struct AuditLogEntry {
        /// Unique Id (ULID)
        #[serde(rename = "_id")]
        pub id: String,
        /// Id of the server the action was taken in
        pub server: String,
        /// Id of the user who took the action (`None` = the system)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub actor: Option<String>,
        /// What kind of action this was
        pub action: AuditLogAction,
        /// Id of the object acted on (a user, channel or role id, or
        /// `"default"` for default permissions), if the action has one
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub target: Option<String>,
        /// Id of the channel the action happened in, if relevant
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub channel: Option<String>,
        /// Typed before/after values for the fields the action changed
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub changes: Vec<AuditLogChange>,
        /// How many objects the action affected (bulk actions only)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub count: Option<u32>,
        /// The moderator's reason, if one was given
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub reason: Option<String>,
    }

    /// One field an audited action changed
    pub struct AuditLogChange {
        /// Name of the changed field (snake_case)
        pub key: String,
        /// Value before the action, if there was one
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub old: Option<AuditValue>,
        /// Value after the action, if there is one
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub new: Option<AuditValue>,
    }

    /// A typed value inside an audit log change
    #[serde(tag = "type", content = "value")]
    pub enum AuditValue {
        String(String),
        Int(i64),
        Bool(bool),
        StringList(Vec<String>),
    }

    /// Kind of audited action
    #[derive(Copy)]
    #[serde(rename_all = "snake_case")]
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
        /// A protected channel's seat PUT released or seated users
        /// (protected channels design §7.5). `channel` = the channel;
        /// `changes` = `[{key: "released", new: StringList(user ids)},
        /// {key: "seated", new: StringList(user ids)}]`; `reason` = the
        /// `X-Audit-Log-Reason`. Served only to readers with ViewChannel on
        /// `channel` (#221).
        ProtectedSeatsUpdate,
        /// One seat of a protected channel was released (design §7.5).
        /// `target` = the released user; `channel` = the channel;
        /// `changes` = `[{key: "cause", new: String(<snake_case
        /// SeatReleaseCause>)}]`. Served only to readers with ViewChannel
        /// on `channel` (#221).
        ProtectedSeatRelease,
        /// An action this build does not know. A rolled-back binary reading
        /// entries written by a newer one decodes them to this instead of
        /// failing the whole fetch.
        #[serde(other)]
        Unknown,
    }
);

/// Everything needed to record an audit log entry except its id, which
/// `AuditLogEntry::record` mints.
#[derive(Debug, Clone)]
pub struct AuditLogDraft {
    pub server: String,
    pub actor: Option<String>,
    pub action: AuditLogAction,
    pub target: Option<String>,
    pub channel: Option<String>,
    pub changes: Vec<AuditLogChange>,
    pub count: Option<u32>,
    pub reason: Option<String>,
}

impl Default for AuditLogDraft {
    fn default() -> Self {
        AuditLogDraft {
            server: String::new(),
            actor: None,
            action: AuditLogAction::Unknown,
            target: None,
            channel: None,
            changes: Vec::new(),
            count: None,
            reason: None,
        }
    }
}

impl AuditLogChange {
    /// Build a change for the given field
    pub fn new(key: &str, old: Option<AuditValue>, new: Option<AuditValue>) -> Self {
        AuditLogChange {
            key: key.to_string(),
            old,
            new,
        }
    }
}

impl AuditLogEntry {
    /// Record an audit log entry.
    ///
    /// Best-effort: mints a ULID id and inserts the entry. A failed insert is
    /// logged and swallowed, so this never returns an error and never panics.
    /// Call it only AFTER the audited mutation has succeeded; the mutation
    /// must never fail because its audit entry could not be written.
    pub async fn record(db: &Database, draft: AuditLogDraft) {
        let entry = AuditLogEntry {
            id: Ulid::new().to_string(),
            server: draft.server,
            actor: draft.actor,
            action: draft.action,
            target: draft.target,
            channel: draft.channel,
            changes: draft.changes,
            count: draft.count,
            reason: draft.reason,
        };

        if let Err(error) = db.insert_audit_log_entry(&entry).await {
            error!(
                "Failed to record audit log entry {:?} in server {}: {error:?}",
                entry.action, entry.server
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use revolt_models::v0;

    use super::{AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue};

    #[test]
    fn unknown_action_decodes_to_unknown() {
        let entry: AuditLogEntry = serde_json::from_value(serde_json::json!({
            "_id": "01J00000000000000000000001",
            "server": "01SERVER000000000000000001",
            "action": "something_new"
        }))
        .expect("an unknown action must not fail the decode");

        assert_eq!(entry.action, AuditLogAction::Unknown);
        assert_eq!(entry.actor, None);
        assert!(entry.changes.is_empty());
    }

    #[test]
    fn audit_value_is_adjacently_tagged() {
        assert_eq!(
            serde_json::to_value(AuditValue::Int(5)).unwrap(),
            serde_json::json!({ "type": "Int", "value": 5 })
        );
        assert_eq!(
            serde_json::to_value(AuditValue::StringList(vec!["a".to_string()])).unwrap(),
            serde_json::json!({ "type": "StringList", "value": ["a"] })
        );
    }

    #[test]
    fn action_names_are_snake_case() {
        assert_eq!(
            serde_json::to_value(AuditLogAction::MemberTimeoutRemove).unwrap(),
            serde_json::json!("member_timeout_remove")
        );
        assert_eq!(
            serde_json::from_value::<AuditLogAction>(serde_json::json!("server_owner_transfer"))
                .unwrap(),
            AuditLogAction::ServerOwnerTransfer
        );
    }

    /// S2 (design §7.5): the protected-seat actions round-trip under their
    /// snake_case names on both the stored and the v0 enum, convert both
    /// ways, and an unknown action still decodes to `Unknown` on both
    #[test]
    fn protected_seat_actions_round_trip() {
        for (action, v0_action, wire) in [
            (
                AuditLogAction::ProtectedSeatsUpdate,
                v0::AuditLogAction::ProtectedSeatsUpdate,
                "protected_seats_update",
            ),
            (
                AuditLogAction::ProtectedSeatRelease,
                v0::AuditLogAction::ProtectedSeatRelease,
                "protected_seat_release",
            ),
        ] {
            assert_eq!(serde_json::to_value(action).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<AuditLogAction>(serde_json::json!(wire)).unwrap(),
                action
            );
            assert_eq!(serde_json::to_value(v0_action).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<v0::AuditLogAction>(serde_json::json!(wire)).unwrap(),
                v0_action
            );
            assert_eq!(v0::AuditLogAction::from(action), v0_action);
            assert_eq!(AuditLogAction::from(v0_action), action);

            let document = bson::to_document(&AuditLogEntry {
                id: "01J00000000000000000000001".to_string(),
                server: "01SERVER000000000000000001".to_string(),
                actor: None,
                action,
                target: None,
                channel: None,
                changes: vec![],
                count: None,
                reason: None,
            })
            .unwrap();
            assert_eq!(document.get_str("action").unwrap(), wire);
            assert_eq!(
                bson::from_document::<AuditLogEntry>(document)
                    .unwrap()
                    .action,
                action
            );
        }

        for unknown in ["protected_seat_moved", "ProtectedSeatsUpdate"] {
            assert_eq!(
                serde_json::from_value::<AuditLogAction>(serde_json::json!(unknown)).unwrap(),
                AuditLogAction::Unknown
            );
            assert_eq!(
                serde_json::from_value::<v0::AuditLogAction>(serde_json::json!(unknown)).unwrap(),
                v0::AuditLogAction::Unknown
            );
        }
    }

    /// The v0 wire model must serialize exactly like the stored document.
    #[test]
    fn v0_projection_matches_the_database_shape() {
        let entry = AuditLogEntry {
            id: "01J00000000000000000000001".to_string(),
            server: "01SERVER000000000000000001".to_string(),
            actor: Some("01ACTOR0000000000000000001".to_string()),
            action: AuditLogAction::MemberUpdate,
            target: Some("01TARGET000000000000000001".to_string()),
            channel: None,
            changes: vec![
                AuditLogChange::new(
                    "nickname",
                    Some(AuditValue::String("old".to_string())),
                    None,
                ),
                AuditLogChange::new("avatar", None, Some(AuditValue::Bool(false))),
            ],
            count: Some(3),
            reason: Some("because".to_string()),
        };

        let projected: v0::AuditLogEntry = entry.clone().into();
        assert_eq!(
            serde_json::to_value(&entry).unwrap(),
            serde_json::to_value(&projected).unwrap()
        );

        let back: AuditLogEntry = projected.into();
        assert_eq!(back, entry);
    }
}
