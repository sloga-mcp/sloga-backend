use revolt_models::v0;
use revolt_result::Result;

use crate::events::client::EventV1;
use crate::Database;

auto_derived!(
    /// Lifecycle state of a scheduled message.
    ///
    /// The delivery daemon claims rows atomically `Pending` → `Sending`
    /// (the mark-then-send idempotency marker: a second daemon instance or
    /// a re-run can never double-send), then finishes them `Sent` or
    /// `Failed`. Finished rows are retained briefly for debugging and then
    /// swept.
    pub enum ScheduledMessageStatus {
        Pending,
        Sending,
        Sent,
        Failed,
    }

    /// A message scheduled for later delivery.
    ///
    /// Stores the composed wire payload verbatim; at fire time the daemon
    /// re-checks permissions and sends through the normal
    /// `Message::create_from_api` path so validation, mention scrubbing
    /// and event fan-out happen exactly as for a live send.
    pub struct ScheduledMessage {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Id of the scheduling user
        pub author: String,
        /// Id of the target channel
        pub channel: String,
        /// Id of the server, when the channel is a server channel
        #[serde(skip_serializing_if = "Option::is_none")]
        pub server: Option<String>,
        /// When the message should be sent (ms since epoch, UTC)
        pub scheduled_at: i64,
        /// The composed message payload (attachment ids in here are claimed
        /// against THIS row's id until delivery retargets them)
        pub data: v0::DataMessageSend,
        /// Lifecycle state
        #[serde(default)]
        pub status: ScheduledMessageStatus,
        /// Why delivery failed, when status is `Failed`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub failure_reason: Option<String>,
    }
);

impl Default for ScheduledMessageStatus {
    fn default() -> Self {
        ScheduledMessageStatus::Pending
    }
}

impl ScheduledMessage {
    /// Cancel every pending scheduled message in a channel (deletion
    /// cascades — channel delete, thread-child delete, server delete):
    /// remove the rows, release their claimed attachments into the
    /// deletion sweep, and notify each author privately.
    pub async fn cancel_all_for_channel(db: &Database, channel: &str) -> Result<()> {
        for row in db.delete_scheduled_messages_for_channel(channel).await? {
            if let Some(attachments) = &row.data.attachments {
                if !attachments.is_empty() {
                    db.mark_attachments_as_deleted(attachments).await.ok();
                }
            }

            EventV1::MessageScheduleCancelled {
                id: row.id,
                channel: row.channel,
            }
            .private(row.author)
            .await;
        }

        Ok(())
    }

    /// Cancel every pending scheduled message targeting a server
    /// (server-deletion cascade; covers threads too — rows carry
    /// `server`). Same release-and-notify semantics as the channel
    /// cascade.
    pub async fn cancel_all_for_server(db: &Database, server: &str) -> Result<()> {
        for row in db.delete_scheduled_messages_for_server(server).await? {
            if let Some(attachments) = &row.data.attachments {
                if !attachments.is_empty() {
                    db.mark_attachments_as_deleted(attachments).await.ok();
                }
            }

            EventV1::MessageScheduleCancelled {
                id: row.id,
                channel: row.channel,
            }
            .private(row.author)
            .await;
        }

        Ok(())
    }

    /// API model (author-private surfaces only).
    pub fn into_model(self) -> v0::ScheduledMessage {
        v0::ScheduledMessage {
            id: self.id,
            author: self.author,
            channel: self.channel,
            scheduled_at: self.scheduled_at,
            data: self.data,
            status: match self.status {
                ScheduledMessageStatus::Pending => v0::ScheduledMessageStatus::Pending,
                ScheduledMessageStatus::Sending => v0::ScheduledMessageStatus::Sending,
                ScheduledMessageStatus::Sent => v0::ScheduledMessageStatus::Sent,
                ScheduledMessageStatus::Failed => v0::ScheduledMessageStatus::Failed,
            },
            failure_reason: self.failure_reason,
        }
    }
}
