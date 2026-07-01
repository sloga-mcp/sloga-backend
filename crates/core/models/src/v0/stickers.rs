use once_cell::sync::Lazy;
use regex::Regex;

#[cfg(feature = "validator")]
use validator::Validate;

/// Regex for valid sticker names
pub static RE_STICKER: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[^\x00-\x1F]{1,32}$").unwrap());

auto_derived!(
    /// Sticker
    pub struct Sticker {
        /// Unique Id
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub id: String,
        /// Server this sticker belongs to
        pub server_id: String,
        /// Uploader user id
        pub creator_id: String,
        /// Sticker name
        pub name: String,
        /// Optional description
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none")
        )]
        pub description: Option<String>,
        /// File ID of the sticker image
        pub file_id: String,
        /// Format of the sticker
        pub format: StickerFormat,
        /// Whether the sticker is marked as nsfw
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "crate::if_false", default)
        )]
        pub nsfw: bool,
    }

    /// Format of the sticker
    pub enum StickerFormat {
        PNG,
        APNG,
        GIF,
        Lottie,
    }

    /// Create a new sticker
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataCreateSticker {
        /// Sticker name
        #[cfg_attr(
            feature = "validator",
            validate(length(min = 1, max = 32))
        )]
        pub name: String,
        /// Optional description
        #[cfg_attr(
            feature = "validator",
            validate(length(max = 200))
        )]
        pub description: Option<String>,
        /// Whether the sticker is mature
        #[cfg_attr(feature = "serde", serde(default))]
        pub nsfw: bool,
    }

    /// Partial sticker representation
    #[derive(Default)]
    pub struct PartialSticker {
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub name: Option<String>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub description: Option<String>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub nsfw: Option<bool>,
    }

    /// Edit sticker information
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataEditSticker {
        /// Sticker name
        #[cfg_attr(
            feature = "validator",
            validate(length(min = 1, max = 32))
        )]
        pub name: Option<String>,
        /// Sticker description
        #[cfg_attr(
            feature = "validator",
            validate(length(max = 200))
        )]
        pub description: Option<String>,
        /// Whether the sticker is mature
        pub nsfw: Option<bool>,
    }
);
