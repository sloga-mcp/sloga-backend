#[cfg(feature = "validator")]
use validator::Validate;

use super::User;

/// Maximum number of answers on a poll
pub const MAX_POLL_ANSWERS: usize = 10;

/// Minimum number of answers on a poll
pub const MIN_POLL_ANSWERS: usize = 2;

/// Longest allowed poll duration in hours (32 days, Discord parity)
pub const MAX_POLL_DURATION_HOURS: u32 = 768;

/// Default poll duration in hours when the client does not specify one
pub const DEFAULT_POLL_DURATION_HOURS: u32 = 24;

auto_derived!(
    /// A single answer on a poll
    pub struct PollAnswer {
        /// Answer id, unique within the poll (assigned by the server, 0..n)
        pub id: u8,
        /// Answer text
        pub text: String,
        /// Optional emoji rendered next to the answer
        #[serde(skip_serializing_if = "Option::is_none")]
        pub emoji: Option<String>,
    }

    /// The immutable definition of a poll, embedded in its message.
    ///
    /// Mutable state (counts, closed) lives in the poll object and is
    /// fetched / pushed separately so votes never republish the message.
    pub struct PollDefinition {
        /// Poll id
        pub id: String,
        /// The question being asked
        pub question: String,
        /// The available answers
        pub answers: Vec<PollAnswer>,
        /// Whether voters may pick more than one answer
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub allow_multiselect: bool,
        /// When the poll automatically closes (ms since epoch, UTC —
        /// matches the calendar-events time convention)
        pub expires_at: i64,
    }

    /// Aggregate vote count for one answer
    pub struct PollAnswerCount {
        /// Answer id
        pub answer_id: u8,
        /// Number of votes for this answer
        pub count: i64,
    }

    /// Dynamic poll state.
    ///
    /// `counts` / `total_votes` are omitted unless the requester has voted,
    /// is the poll author, has ManageMessages, or the poll is closed —
    /// results are hidden-by-choice and this is enforced server-side.
    pub struct Poll {
        /// Poll id
        #[serde(rename = "_id")]
        pub id: String,
        /// Id of the message carrying this poll
        pub message_id: String,
        /// Id of the channel the poll was created in
        pub channel_id: String,
        /// Id of the poll author
        pub author_id: String,
        /// Whether the poll is closed (final results)
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub closed: bool,
        /// When the poll automatically closes (ms since epoch, UTC)
        pub expires_at: i64,
        /// Aggregate counts per answer (gated, see struct docs)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub counts: Option<Vec<PollAnswerCount>>,
        /// Total number of ballots cast (gated, see struct docs)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub total_votes: Option<i64>,
        /// The requesting user's own ballot, if they have voted
        #[serde(skip_serializing_if = "Option::is_none")]
        pub my_votes: Option<Vec<u8>>,
    }

    /// One answer supplied when creating a poll
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataPollAnswer {
        /// Answer text
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 100)))]
        pub text: String,
        /// Optional emoji rendered next to the answer
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
        pub emoji: Option<String>,
    }

    /// Create a new poll
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataPollCreate {
        /// Unique token to prevent duplicate message sending
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub nonce: Option<String>,

        /// The question to ask
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 300)))]
        pub question: String,

        /// The available answers (2 to 10). Per-answer field constraints
        /// are validated explicitly by the create route (this validator
        /// version cannot combine `length` with nested validation).
        #[cfg_attr(feature = "validator", validate(length(min = 2, max = 10)))]
        pub answers: Vec<DataPollAnswer>,

        /// Whether voters may pick more than one answer
        #[serde(default)]
        pub allow_multiselect: bool,

        /// How long the poll runs before closing, in hours (1..=768, default 24)
        #[cfg_attr(feature = "validator", validate(range(min = 1, max = 768)))]
        pub duration_hours: Option<u32>,
    }

    /// Cast (or replace) a ballot on a poll
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataPollVote {
        /// Answer ids to vote for. Exactly one unless the poll allows
        /// multi-select; always at least one (use DELETE to retract).
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 10)))]
        pub answer_ids: Vec<u8>,
    }

    /// Bulk-fetch poll state for the polls visible on a page of messages
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataPollsFetch {
        /// Poll ids to fetch (from the messages' embedded definitions)
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 100)))]
        pub ids: Vec<String>,
    }

    /// Voters for one poll answer (author / ManageMessages gated)
    pub struct PollVotersResponse {
        /// Users who voted for the requested answer
        pub users: Vec<User>,
    }
);
