use super::User;

#[cfg(feature = "validator")]
use validator::Validate;

auto_derived!(
    /// Respect — one short compliment on a user's profile wall.
    ///
    /// One per (author, target) pair: giving respect again edits the
    /// existing entry in place. Friends of the target (and the target
    /// themselves) may write one; the target curates their own wall.
    pub struct Respect {
        /// Unique Id
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub id: String,
        /// Id of the user whose wall this entry is on
        pub target_id: String,
        /// Id of the user who wrote it
        pub author_id: String,
        /// The respect text (plain text)
        pub content: String,
        /// When the entry was last written or edited (ms since epoch, UTC)
        pub updated_at: i64,
    }

    /// Give (or rewrite) your respect on a user's wall
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataGiveRespect {
        /// Respect text
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 240)))]
        pub content: String,
    }

    /// A user's respect wall
    pub struct RespectResponse {
        /// Respect entries, newest-edited first
        pub respect: Vec<Respect>,
        /// Authors of the entries
        pub users: Vec<User>,
    }
);
