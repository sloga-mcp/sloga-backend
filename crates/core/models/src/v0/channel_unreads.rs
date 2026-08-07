/// Ceiling applied when counting unread messages — the count query stops here,
/// so a channel with thousands of unread messages costs the same as one with a
/// hundred. Clients render anything at the cap as "99+".
pub const UNREAD_COUNT_CAP: u32 = 100;

#[cfg(feature = "serde")]
fn is_zero(value: &u32) -> bool {
    *value == 0
}

#[cfg(feature = "serde")]
fn is_false(value: &bool) -> bool {
    !*value
}

auto_derived!(
    /// Channel Unread
    pub struct ChannelUnread {
        /// Composite key pointing to a user's view of a channel
        #[serde(rename = "_id")]
        pub id: ChannelCompositeKey,

        /// Id of the last message read in this channel by a user
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub last_id: Option<String>,
        /// Array of message ids that mention the user
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Vec::is_empty", default)
        )]
        pub mentions: Vec<String>,
        /// Number of messages sitting after `last_id`, saturating at
        /// `UNREAD_COUNT_CAP` (clients render the cap as "99+")
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_zero", default))]
        pub count: u32,
        /// Whether any of those unread messages carries an attachment
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_false", default))]
        pub attachments: bool,
    }

    /// Composite primary key consisting of channel and user id
    #[derive(Hash)]
    pub struct ChannelCompositeKey {
        /// Channel Id
        pub channel: String,
        /// User Id
        pub user: String,
    }
);
