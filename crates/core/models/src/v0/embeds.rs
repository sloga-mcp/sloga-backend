use super::File;

auto_derived!(
    /// Image positioning and size
    pub enum ImageSize {
        /// Show large preview at the bottom of the embed
        Large,
        /// Show small preview to the side of the embed
        Preview,
    }

    /// Image
    pub struct Image {
        /// URL to the original image
        pub url: String,
        /// Width of the image
        pub width: usize,
        /// Height of the image
        pub height: usize,
        /// Positioning and size
        pub size: ImageSize,
    }

    /// Video
    pub struct Video {
        /// URL to the original video
        pub url: String,
        /// Width of the video
        pub width: usize,
        /// Height of the video
        pub height: usize,
    }

    /// Audio
    pub struct Audio {
        /// URL to the original audio file
        pub url: String,
        /// Canonical MIME type of the audio
        pub content_type: String,
        /// Size of the audio file in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        pub size: Option<usize>,
        /// Name of the audio file
        #[serde(skip_serializing_if = "Option::is_none")]
        pub filename: Option<String>,
    }

    /// Type of remote Twitch content
    pub enum TwitchType {
        Channel,
        Video,
        Clip,
    }

    /// Type of remote Lightspeed.tv content
    pub enum LightspeedType {
        Channel,
    }

    /// Type of remote Bandcamp content
    pub enum BandcampType {
        Album,
        Track,
    }

    /// Information about special remote content
    #[serde(tag = "type")]
    pub enum Special {
        /// No remote content
        None,
        /// Content hint that this contains a GIF
        ///
        /// Use metadata to find video or image to play
        GIF,
        /// YouTube video
        YouTube {
            id: String,

            #[serde(skip_serializing_if = "Option::is_none")]
            timestamp: Option<String>,
        },
        /// Lightspeed.tv stream
        Lightspeed {
            content_type: LightspeedType,
            id: String,
        },
        /// Twitch stream or clip
        Twitch {
            content_type: TwitchType,
            id: String,
        },
        /// Spotify track
        Spotify { content_type: String, id: String },
        /// Soundcloud track
        Soundcloud,
        /// Bandcamp track
        Bandcamp {
            content_type: BandcampType,
            id: String,
        },
        AppleMusic {
            album_id: String,

            #[serde(skip_serializing_if = "Option::is_none")]
            track_id: Option<String>,
        },
        /// Streamable Video
        Streamable { id: String },
    }

    /// Website metadata
    pub struct WebsiteMetadata {
        /// Direct URL to web page
        #[serde(skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        /// Original direct URL
        #[serde(skip_serializing_if = "Option::is_none")]
        pub original_url: Option<String>,
        /// Remote content
        #[serde(skip_serializing_if = "Option::is_none")]
        pub special: Option<Special>,

        /// Title of website
        #[serde(skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        /// Description of website
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// Embedded image
        #[serde(skip_serializing_if = "Option::is_none")]
        pub image: Option<Image>,
        /// Embedded video
        #[serde(skip_serializing_if = "Option::is_none")]
        pub video: Option<Video>,

        /// Site name
        #[serde(skip_serializing_if = "Option::is_none")]
        pub site_name: Option<String>,
        /// URL to site icon
        #[serde(skip_serializing_if = "Option::is_none")]
        pub icon_url: Option<String>,
        /// CSS Colour
        #[serde(skip_serializing_if = "Option::is_none")]
        pub colour: Option<String>,
    }

    /// Text Embed
    pub struct Text {
        /// URL to icon
        #[serde(skip_serializing_if = "Option::is_none")]
        pub icon_url: Option<String>,
        /// URL for title
        #[serde(skip_serializing_if = "Option::is_none")]
        pub url: Option<String>,
        /// Title of text embed
        #[serde(skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        /// Description of text embed
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// ID of uploaded autumn file
        #[serde(skip_serializing_if = "Option::is_none")]
        pub media: Option<File>,
        /// CSS Colour
        #[serde(skip_serializing_if = "Option::is_none")]
        pub colour: Option<String>,
    }

    /// Embed
    #[serde(tag = "type")]
    #[derive(Default)]
    pub enum Embed {
        Website(WebsiteMetadata),
        Image(Image),
        Video(Video),
        Text(Text),
        Audio(Audio),
        /// No embed; unknown embed types also decode to this
        #[default]
        #[serde(other)]
        None,
    }
);

impl WebsiteMetadata {
    /// Truncate strings in metadata
    pub fn truncate(&mut self) {
        if let Some(s) = self.url.as_mut() {
            s.truncate(256);
        }

        if let Some(s) = self.original_url.as_mut() {
            s.truncate(256);
        }

        if let Some(s) = self.title.as_mut() {
            s.truncate(100);
        }

        if let Some(s) = self.description.as_mut() {
            s.truncate(1000);
        }

        if let Some(s) = self.site_name.as_mut() {
            s.truncate(32);
        }

        if let Some(s) = self.icon_url.as_mut() {
            s.truncate(256);
        }

        if let Some(s) = self.colour.as_mut() {
            s.truncate(32);
        }
    }

    /// Check if this is considered "empty"
    pub fn is_empty(&self) -> bool {
        (self.title.is_none() || self.title.as_ref().is_some_and(|f| f.is_empty()))
            && (self.description.is_none()
                || self.description.as_ref().is_some_and(|f| f.is_empty()))
            && self.special.is_none()
            && self.video.is_none()
            && self.image.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"{"type":"Audio","url":"https://litter.catbox.moe/swkvyu.mp3","content_type":"audio/mpeg","size":8997375,"filename":"swkvyu.mp3"}"#;
    const BARE: &str = r#"{"type":"Audio","url":"https://litter.catbox.moe/swkvyu.mp3","content_type":"audio/mpeg"}"#;

    fn audio(size: Option<usize>, filename: Option<&str>) -> Embed {
        Embed::Audio(Audio {
            url: "https://litter.catbox.moe/swkvyu.mp3".to_string(),
            content_type: "audio/mpeg".to_string(),
            size,
            filename: filename.map(str::to_string),
        })
    }

    #[test]
    fn audio_embed_serializes_to_pinned_shape() {
        let full = audio(Some(8997375), Some("swkvyu.mp3"));
        assert_eq!(serde_json::to_string(&full).unwrap(), FULL);

        // optional fields are omitted entirely, never sent as null
        let bare = audio(None, None);
        assert_eq!(serde_json::to_string(&bare).unwrap(), BARE);
    }

    #[test]
    fn audio_embed_round_trips() {
        let full: Embed = serde_json::from_str(FULL).unwrap();
        assert_eq!(full, audio(Some(8997375), Some("swkvyu.mp3")));

        let bare: Embed = serde_json::from_str(BARE).unwrap();
        assert_eq!(bare, audio(None, None));

        for embed in [full, bare, audio(Some(1), None), audio(None, Some("a.ogg"))] {
            let wire = serde_json::to_string(&embed).unwrap();
            assert_eq!(serde_json::from_str::<Embed>(&wire).unwrap(), embed);
        }

        // content_type is always present on the wire
        assert!(serde_json::from_str::<Embed>(
            r#"{"type":"Audio","url":"https://litter.catbox.moe/swkvyu.mp3"}"#
        )
        .is_err());
    }

    #[test]
    fn unknown_embed_type_decodes_as_none() {
        // a future embed type must degrade instead of failing the whole message
        let embed: Embed = serde_json::from_str(r#"{"type":"Foo","x":1}"#).unwrap();
        assert_eq!(embed, Embed::None);

        let embeds: Vec<Embed> =
            serde_json::from_str(&format!(r#"[{{"type":"Foo","x":1}},{FULL}]"#)).unwrap();
        assert_eq!(
            embeds,
            vec![Embed::None, audio(Some(8997375), Some("swkvyu.mp3"))]
        );

        let none: Embed = serde_json::from_str(r#"{"type":"None"}"#).unwrap();
        assert_eq!(none, Embed::None);
    }

    #[test]
    fn none_embed_serializes_to_pinned_shape() {
        // `#[serde(other)]` must not change how None goes out on the wire
        assert_eq!(serde_json::to_string(&Embed::None).unwrap(), r#"{"type":"None"}"#);
    }

    #[test]
    fn audio_embed_bson_round_trips() {
        // messages are stored in and read back from Mongo as bson, not JSON
        let full = audio(Some(8997375), Some("swkvyu.mp3"));
        let doc = bson::to_document(&full).unwrap();
        assert_eq!(doc.get_str("type").unwrap(), "Audio");
        assert_eq!(
            doc.get_str("url").unwrap(),
            "https://litter.catbox.moe/swkvyu.mp3"
        );
        assert_eq!(doc.get_str("content_type").unwrap(), "audio/mpeg");
        // bson has no unsigned type: usize is stored as a signed 64-bit integer
        assert_eq!(doc.get("size"), Some(&bson::Bson::Int64(8997375)));
        assert_eq!(doc.get_str("filename").unwrap(), "swkvyu.mp3");
        assert_eq!(doc.len(), 5);
        assert_eq!(bson::from_document::<Embed>(doc).unwrap(), full);

        // optional fields are omitted entirely, never stored as null
        let bare = audio(None, None);
        let doc = bson::to_document(&bare).unwrap();
        assert!(!doc.contains_key("size"));
        assert!(!doc.contains_key("filename"));
        assert_eq!(doc.len(), 3);
        assert_eq!(bson::from_document::<Embed>(doc).unwrap(), bare);

        for embed in [audio(Some(1), None), audio(None, Some("a.ogg"))] {
            let doc = bson::to_document(&embed).unwrap();
            assert_eq!(bson::from_document::<Embed>(doc).unwrap(), embed);
        }

        // a size written by another driver as Int32 still decodes
        let doc = bson::doc! {
            "type": "Audio",
            "url": "https://litter.catbox.moe/swkvyu.mp3",
            "content_type": "audio/mpeg",
            "size": 42_i32,
        };
        assert_eq!(
            bson::from_document::<Embed>(doc).unwrap(),
            audio(Some(42), None)
        );
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn audio_embed_bson_size_range() {
        // the largest size bson can hold survives the round trip
        let max = audio(Some(i64::MAX as usize), None);
        let doc = bson::to_document(&max).unwrap();
        assert_eq!(doc.get("size"), Some(&bson::Bson::Int64(i64::MAX)));
        assert_eq!(bson::from_document::<Embed>(doc).unwrap(), max);

        // anything above i64::MAX is refused by the encoder rather than wrapped
        assert!(bson::to_document(&audio(Some(i64::MAX as usize + 1), None)).is_err());
    }

    #[test]
    fn unknown_embed_type_decodes_as_none_from_bson() {
        let embed: Embed = bson::from_document(bson::doc! { "type": "Foo", "x": 1 }).unwrap();
        assert_eq!(embed, Embed::None);
    }

    #[test]
    fn none_embed_bson_round_trips() {
        let doc = bson::to_document(&Embed::None).unwrap();
        assert_eq!(doc, bson::doc! { "type": "None" });
        assert_eq!(bson::from_document::<Embed>(doc).unwrap(), Embed::None);
    }
}
