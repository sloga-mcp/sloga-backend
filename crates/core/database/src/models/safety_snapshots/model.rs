use revolt_models::v0::{MessageSort, ReportedMessageSnapshot};
use revolt_result::Result;

use crate::{Database, Message, MessageFilter, MessageQuery, MessageTimePeriod, Server, User};

auto_derived!(
    /// Snapshot of some content
    pub struct Snapshot {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Report parent Id
        pub report_id: String,
        /// Snapshot of content
        pub content: SnapshotContent,
    }

    /// Enum to map into different models
    /// that can be saved in a snapshot
    #[serde(tag = "_type")]
    pub enum SnapshotContent {
        Message {
            /// Context before the message
            #[serde(rename = "_prior_context", default)]
            prior_context: Vec<Message>,

            /// Context after the message
            #[serde(rename = "_leading_context", default)]
            leading_context: Vec<Message>,

            /// Message
            #[serde(flatten)]
            message: Message,
        },
        Server(Server),
        User(User),
        /// Copy of the reported message supplied by the reporter's client;
        /// stands alone so reports work for conversations the server cannot
        /// read (end-to-end encrypted DMs)
        ReporterMessage {
            /// The reported message as seen on the reporter's device
            message: ReportedMessageSnapshot,

            /// Surrounding messages supplied by the reporter, ordered by id
            #[serde(default)]
            context: Vec<ReportedMessageSnapshot>,
        },
    }
);

impl SnapshotContent {
    /// Generate snapshot from a given message
    pub async fn generate_from_message(
        db: &Database,
        message: Message,
    ) -> Result<(SnapshotContent, Vec<String>)> {
        // Collect message attachments
        let files = message
            .attachments
            .as_ref()
            .map(|attachments| attachments.iter().map(|x| x.id.to_string()).collect())
            .unwrap_or_default();

        // Collect prior context
        let prior_context = db
            .fetch_messages(MessageQuery {
                filter: MessageFilter {
                    channel: Some(message.channel.to_string()),
                    ..Default::default()
                },
                limit: Some(15),
                time_period: MessageTimePeriod::Absolute {
                    before: Some(message.id.to_string()),
                    after: None,
                    sort: Some(MessageSort::Latest),
                },
            })
            .await?;

        // Collect leading context
        let leading_context = db
            .fetch_messages(MessageQuery {
                filter: MessageFilter {
                    channel: Some(message.channel.to_string()),
                    ..Default::default()
                },
                limit: Some(15),
                time_period: MessageTimePeriod::Absolute {
                    before: None,
                    after: Some(message.id.to_string()),
                    sort: Some(MessageSort::Oldest),
                },
            })
            .await?;

        Ok((
            SnapshotContent::Message {
                message,
                prior_context: prior_context.into_iter().collect(),
                leading_context: leading_context.into_iter().collect(),
            },
            files,
        ))
    }

    /// Generate snapshot from a given server
    pub fn generate_from_server(server: Server) -> Result<(SnapshotContent, Vec<String>)> {
        // Collect server's icon and banner
        let files = [&server.icon, &server.banner]
            .iter()
            .filter_map(|x| x.as_ref().map(|x| x.id.to_string()))
            .collect();

        Ok((SnapshotContent::Server(server), files))
    }

    /// Generate snapshot from a given user
    pub fn generate_from_user(mut user: User) -> Result<(SnapshotContent, Vec<String>)> {
        // Collect user's avatar and profile background
        let files = [
            user.avatar.as_ref(),
            user.profile
                .as_ref()
                .and_then(|profile| profile.background.as_ref()),
        ]
        .iter()
        .filter_map(|x| x.as_ref().map(|x| x.id.to_string()))
        .collect();

        // Strip donation and referral state; it is not moderation evidence
        // and must not outlive the account's own deletion
        user.supporter = None;
        user.referral_count = None;
        user.referral_pending = None;
        user.welcomed_at = None;

        // Strip the anti-spam pause record; it is private to the server and
        // its fingerprint and report id must never reach a report snapshot
        user.dm_guard = None;

        Ok((SnapshotContent::User(user), files))
    }
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::Timestamp;

    use crate::{DmGuard, SnapshotContent, User};

    #[test]
    fn generate_from_user_strips_dm_guard() {
        let user = User {
            id: ulid::Ulid::new().to_string(),
            username: "spammer".to_string(),
            discriminator: "0001".to_string(),
            dm_guard: Some(DmGuard {
                report_id: "01REPORT00000000000000000000".to_string(),
                flagged_at: Timestamp::now_utc(),
                paused: true,
                cleared_at: None,
                recipients: 3,
                fingerprint: "fingerprint".to_string(),
            }),
            ..Default::default()
        };

        let (content, files) = SnapshotContent::generate_from_user(user.clone()).unwrap();
        assert!(files.is_empty());

        match content {
            SnapshotContent::User(snapshot_user) => {
                assert_eq!(snapshot_user.id, user.id);
                assert!(snapshot_user.dm_guard.is_none());
            }
            content => panic!("expected a user snapshot, got {content:?}"),
        }
    }
}
