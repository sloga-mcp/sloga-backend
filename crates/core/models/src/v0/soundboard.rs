use once_cell::sync::Lazy;
use regex::Regex;

#[cfg(feature = "validator")]
use validator::Validate;

/// Regex for valid soundboard sound names (mirrors the sticker name rule)
pub static RE_SOUND_NAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[^\x00-\x1F]{1,32}$").unwrap());

auto_derived!(
    /// Soundboard sound — a short per-server audio clip playable in a voice call
    pub struct SoundboardSound {
        /// Unique Id (equals the Autumn file id, like stickers)
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub id: String,
        /// Server this sound belongs to
        pub server_id: String,
        /// Uploader user id
        pub creator_id: String,
        /// Sound name
        pub name: String,
        /// File ID of the audio clip
        pub file_id: String,
        /// Optional emoji shown on the soundboard button
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none")
        )]
        pub emoji: Option<String>,
    }

    /// Create a new soundboard sound
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataCreateSound {
        /// Sound name
        #[cfg_attr(
            feature = "validator",
            validate(length(min = 1, max = 32))
        )]
        pub name: String,
        /// Optional emoji
        #[cfg_attr(
            feature = "validator",
            validate(length(max = 32))
        )]
        pub emoji: Option<String>,
    }

    /// Partial soundboard sound representation
    #[derive(Default)]
    pub struct PartialSoundboardSound {
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub name: Option<String>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub emoji: Option<String>,
    }

    /// Edit soundboard sound information
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataEditSound {
        /// Sound name
        #[cfg_attr(
            feature = "validator",
            validate(length(min = 1, max = 32))
        )]
        pub name: Option<String>,
        /// Emoji
        #[cfg_attr(
            feature = "validator",
            validate(length(max = 32))
        )]
        pub emoji: Option<String>,
    }
);
