use super::{File, Metadata, PublicBot, UserConnection};

auto_derived!(
    /// Sanitized file DTO for fully public (unauthenticated) endpoints.
    ///
    /// `v0::File` serializes `user_id` / `server_id` / `message_id` /
    /// `object_id` when present, and server icons/banners carry the uploading
    /// owner's user id — these must never ship on public routes.
    pub struct PublicFile {
        /// Unique Id
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub id: String,
        /// Tag / bucket this file was uploaded to
        pub tag: String,
        /// Original filename
        pub filename: String,
        /// Parsed metadata of this file
        pub metadata: Metadata,
        /// Raw content type of this file
        pub content_type: String,
        /// Size of this file (in bytes)
        pub size: isize,
    }

    /// Public card for a discoverable server.
    ///
    /// Strict whitelist: never add owner, channels, roles, categories,
    /// system_messages or permissions here.
    pub struct DiscoverableServer {
        /// Server Id
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub id: String,
        /// Server name
        pub name: String,
        /// Server description
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub description: Option<String>,
        /// Server icon
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub icon: Option<PublicFile>,
        /// Server banner
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub banner: Option<PublicFile>,
        /// Server flags
        pub flags: u32,
        /// Number of members
        pub member_count: i64,
        /// Owner user id — populated ONLY on the privileged requests route,
        /// never on public routes
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub owner: Option<String>,
    }

    /// Response for the public discovery listing
    pub struct DiscoverResponse {
        /// Page of discoverable servers
        pub servers: Vec<DiscoverableServer>,
        /// Total number of discoverable servers matching the query
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub total: Option<u64>,
    }

    /// Options for the public discovery listing
    #[cfg_attr(feature = "rocket", derive(rocket::FromForm))]
    pub struct OptionsDiscoverServers {
        /// Case-insensitive substring to match on name/description
        pub query: Option<String>,
        /// Number of entries to skip
        pub skip: Option<u64>,
    }

    /// Options for the privileged discovery-requests listing
    #[cfg_attr(feature = "rocket", derive(rocket::FromForm))]
    pub struct OptionsDiscoverRequests {
        /// Number of entries to skip
        pub skip: Option<u64>,
    }

    /// A curated first-party app-catalog entry ("Add apps" panel).
    ///
    /// `bot` is the existing `PublicBot` whitelist DTO — id, username,
    /// avatar id and description only; never token or owner.
    pub struct AppCatalogEntry {
        /// Short operator-configured tagline
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub tagline: Option<String>,
        /// Public card for the bot
        pub bot: PublicBot,
    }

    /// Response for the curated app catalog
    pub struct AppCatalogResponse {
        /// Catalog entries, in operator-configured order
        pub apps: Vec<AppCatalogEntry>,
    }

    /// Public card for a founding streamer.
    ///
    /// Strict whitelist. The anonymous `GET /discover/streamers` route cannot
    /// reuse the normal user bridge: that bridge gates `connections` behind
    /// `can_see_profile`, which is false for an anonymous perspective, so the
    /// standard payload would ship `connections: []`. This DTO therefore names
    /// every field explicitly — never add relations, flags, badges, status,
    /// bot, e2ee_enabled, privileged, profile_visibility or relationship here.
    pub struct StreamerCard {
        /// User Id
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub id: String,
        /// Username
        pub username: String,
        /// Discriminator
        pub discriminator: String,
        /// Display name
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub display_name: Option<String>,
        /// Avatar attachment
        ///
        /// `PublicFile`, the same whitelist `DiscoverableServer` uses for its
        /// icon — a raw `v0::File` would leak the uploader's `user_id`.
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub avatar: Option<PublicFile>,
        /// Linked streaming channels (Twitch / YouTube / Kick)
        ///
        /// Always serialized, `[]` when empty (no `skip_serializing_if`) —
        /// matching `DiscoverResponse`'s `servers`, so the client never has to
        /// handle an absent key. `default` only makes the deserialize side
        /// tolerant of a `User`-shaped payload; it changes no emitted JSON.
        #[cfg_attr(feature = "serde", serde(default))]
        pub connections: Vec<UserConnection>,
    }

    /// Response for the public founding-streamer listing
    pub struct StreamersResponse {
        /// Founding streamers
        pub streamers: Vec<StreamerCard>,
    }
);

impl From<File> for PublicFile {
    fn from(file: File) -> Self {
        // Deliberately drops user_id / server_id / message_id / object_id /
        // reported / deleted.
        PublicFile {
            id: file.id,
            tag: file.tag,
            filename: file.filename,
            metadata: file.metadata,
            content_type: file.content_type,
            size: file.size,
        }
    }
}
