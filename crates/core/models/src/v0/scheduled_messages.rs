#[cfg(feature = "validator")]
use validator::Validate;

use super::DataMessageSend;

/// Minimum lead time for a scheduled message (30 seconds)
pub const MIN_SCHEDULE_LEAD_MS: i64 = 30_000;

/// Maximum scheduling horizon (30 days)
pub const MAX_SCHEDULE_HORIZON_MS: i64 = 30 * 24 * 60 * 60 * 1000;

auto_derived!(
    /// Lifecycle state of a scheduled message
    pub enum ScheduledMessageStatus {
        /// Waiting for its delivery time
        Pending,
        /// Claimed by the delivery daemon (in flight)
        Sending,
        /// Delivered as a normal message
        Sent,
        /// Delivery failed permanently (see `failure_reason`)
        Failed,
    }

    /// A message scheduled for later delivery.
    ///
    /// Strictly author-private: the list route only ever returns the
    /// requesting user's own rows, and the related events are published on
    /// the author's private topic.
    pub struct ScheduledMessage {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Id of the scheduling user
        pub author: String,
        /// Id of the channel the message will be sent to
        pub channel: String,
        /// When the message should be sent (ms since epoch, UTC).
        /// Delivery has up to ~30s of tick jitter.
        pub scheduled_at: i64,
        /// The composed message payload, sent verbatim at fire time
        pub data: DataMessageSend,
        /// Lifecycle state
        pub status: ScheduledMessageStatus,
        /// Why delivery failed, when status is `Failed`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub failure_reason: Option<String>,
    }

    /// Schedule a message for later delivery
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataScheduleMessage {
        /// The message to send
        #[serde(flatten)]
        #[cfg_attr(feature = "validator", validate)]
        pub message: DataMessageSend,

        /// When to send it (ms since epoch, UTC). Must be between 30
        /// seconds and 30 days from now.
        pub scheduled_at: i64,
    }
);

impl Default for ScheduledMessageStatus {
    fn default() -> Self {
        ScheduledMessageStatus::Pending
    }
}
