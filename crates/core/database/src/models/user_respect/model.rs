use revolt_models::v0;

auto_derived!(
    /// Respect — one short compliment on a user's profile wall.
    ///
    /// One per (author, target) pair, enforced by the unique `target_author`
    /// index: giving respect again edits the existing entry in place. Friends
    /// of the target (and the target themselves) may write one; the target
    /// curates their own wall by deleting anything on it.
    pub struct Respect {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Id of the user whose wall this entry is on
        pub target_id: String,
        /// Id of the user who wrote it
        pub author_id: String,
        /// The respect text (plain text; hygiene + slur filter applied at the route)
        pub content: String,
        /// When the entry was last written or edited (ms since epoch, UTC)
        pub updated_at: i64,
    }
);

impl Respect {
    /// Project into the API model.
    pub fn into_model(self) -> v0::Respect {
        v0::Respect {
            id: self.id,
            target_id: self.target_id,
            author_id: self.author_id,
            content: self.content,
            updated_at: self.updated_at,
        }
    }
}
