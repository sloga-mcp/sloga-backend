use once_cell::sync::Lazy;
use regex::Regex;

#[cfg(feature = "validator")]
use validator::Validate;

/// Regex for valid emoji names
///
/// Alphanumeric (either case) and underscores.
///
/// Case is preserved but never load-bearing: messages reference custom emoji by
/// id (`:<ULID>:`), so the name is only ever a label to display and search on,
/// and both search paths already fold case.
pub static RE_EMOJI: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_]+$").unwrap());

auto_derived!(
    /// Emoji
    pub struct Emoji {
        /// Unique Id
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub id: String,
        /// What owns this emoji
        pub parent: EmojiParent,
        /// Uploader user id
        pub creator_id: String,
        /// Emoji name
        pub name: String,
        /// Whether the emoji is animated
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "crate::if_false", default)
        )]
        pub animated: bool,
        /// Whether the emoji is marked as nsfw
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "crate::if_false", default)
        )]
        pub nsfw: bool,
    }

    /// Parent Id of the emoji
    #[serde(tag = "type")]
    pub enum EmojiParent {
        Server { id: String },
        Detached,
    }

    /// Create a new emoji
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataCreateEmoji {
        /// Server name
        #[validate(length(min = 1, max = 32), regex = "RE_EMOJI")]
        pub name: String,
        /// Parent information
        pub parent: EmojiParent,
        /// Whether the emoji is mature
        #[serde(default)]
        pub nsfw: bool,
    }

    /// Partial emoji representation
    #[derive(Default)]
    pub struct PartialEmoji {
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub name: Option<String>,
    }

    /// Edit emoji information
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataEditEmoji {
        /// Emoji name
        #[cfg_attr(
            feature = "validator",
            validate(length(min = 1, max = 32), regex = "RE_EMOJI")
        )]
        pub name: Option<String>,
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emoji_names_accept_either_case() {
        // uppercase is the common case for acronyms and stream emotes; it used
        // to be rejected, and the only thing the client could show for it was
        // validator's raw error dump
        for name in ["PBG", "pbg", "PogChamp", "party_parrot", "sloga2", "_"] {
            assert!(RE_EMOJI.is_match(name), "{name} should be accepted");
        }
    }

    #[test]
    fn emoji_names_reject_everything_else() {
        for name in ["", "party parrot", "cool-face", "sad.face", "🎉", ":tada:"] {
            assert!(!RE_EMOJI.is_match(name), "{name} should be rejected");
        }
    }
}
