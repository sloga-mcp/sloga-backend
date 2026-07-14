#[cfg(feature = "validator")]
use validator::Validate;

auto_derived!(
    /// A follow linking a source announcement channel to a target channel in
    /// (usually) another server. Each follow owns a real webhook created in
    /// the target channel — publishing an announcement fans a webhook-authored
    /// copy into every follower channel (Discord-style crosspost).
    pub struct ChannelFollow {
        /// Unique Id
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub id: String,
        /// Id of the source announcement channel
        pub source_channel: String,
        /// Id of the server the source channel belongs to
        pub source_server: String,
        /// Id of the target (follower) channel
        pub target_channel: String,
        /// Id of the server the target channel belongs to
        pub target_server: String,
        /// Id of the webhook created in the target channel to deliver copies
        pub webhook_id: String,
        /// Id of the user who created the follow
        pub created_by: String,
        /// When the follow was created (ms since epoch, UTC)
        pub created_at: i64,
    }

    /// Follow an announcement channel from a target channel in another server
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataFollowChannel {
        /// Id of the server that owns the target (follower) channel
        #[cfg_attr(feature = "validator", validate(length(min = 26, max = 26)))]
        pub server: String,
        /// Id of the target (follower) channel to deliver copies into
        #[cfg_attr(feature = "validator", validate(length(min = 26, max = 26)))]
        pub channel: String,
    }
);
