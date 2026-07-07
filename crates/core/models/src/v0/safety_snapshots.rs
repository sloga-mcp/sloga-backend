use super::{Message, ReportedMessageSnapshot, Server, User};

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

    /// Enum of content that can be saved in a snapshot
    #[serde(tag = "_type")]
    pub enum SnapshotContent {
        Message {
            /// Context before the message
            #[serde(default)]
            prior_context: Vec<Message>,

            /// Context after the message
            #[serde(default)]
            leading_context: Vec<Message>,

            /// Message
            message: Message,
        },
        Server(Server),
        User(User),
        /// Copy of the reported message supplied by the reporter's client;
        /// used as-is when the server cannot read the conversation
        ReporterMessage {
            /// The reported message as seen on the reporter's device
            message: ReportedMessageSnapshot,

            /// Surrounding messages supplied by the reporter, ordered by id
            #[serde(default)]
            context: Vec<ReportedMessageSnapshot>,
        },
    }
);
