use iso8601_timestamp::Timestamp;

auto_derived!(
    /// A user's membership of ("joined" state in) a thread
    pub struct ThreadMember {
        /// Composite key pointing to a user's membership of a thread
        #[serde(rename = "_id")]
        pub id: ThreadMemberCompositeKey,

        /// Time at which the user joined the thread
        pub joined_at: Timestamp,
    }

    /// Composite primary key consisting of thread and user id
    #[derive(Hash)]
    pub struct ThreadMemberCompositeKey {
        /// Thread (channel) Id
        pub thread: String,
        /// User Id
        pub user: String,
    }
);
