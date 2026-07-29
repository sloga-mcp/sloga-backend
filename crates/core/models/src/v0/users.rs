use iso8601_timestamp::Timestamp;
use once_cell::sync::Lazy;
use regex::Regex;

use super::File;

#[cfg(feature = "validator")]
use validator::Validate;

/// Regex for valid usernames
///
/// Block zero width space
/// Block lookalike characters
pub static RE_USERNAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(\p{L}|[\d_.-])+$").unwrap());

/// Regex for valid display names
///
/// Block zero width space
/// Block newline and carriage return
pub static RE_DISPLAY_NAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[^\u200B\n\r]+$").unwrap());

auto_derived_partial!(
    /// User
    pub struct User {
        /// Unique Id
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub id: String,
        /// Username
        pub username: String,
        /// Discriminator
        pub discriminator: String,
        /// Display name
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub display_name: Option<String>,
         /// User's pronouns
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub pronouns: Option<String>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        /// Avatar attachment
        pub avatar: Option<File>,
        /// Relationships with other users
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Vec::is_empty", default)
        )]
        pub relations: Vec<Relationship>,

        /// Bitfield of user badges
        ///
        /// https://docs.rs/revolt-models/latest/revolt_models/v0/enum.UserBadges.html
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "crate::if_zero_u32", default)
        )]
        pub badges: u32,
        /// User's current status
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub status: Option<UserStatus>,

        /// Enum of user flags
        ///
        /// https://docs.rs/revolt-models/latest/revolt_models/v0/enum.UserFlags.html
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "crate::if_zero_u32", default)
        )]
        pub flags: u32,
        /// Whether this user is privileged
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "crate::if_false", default)
        )]
        pub privileged: bool,
        /// Bot information
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub bot: Option<BotInformation>,

        /// Whether this user has opted in to E2EE DMs
        ///
        /// UI hint ONLY — clients derive actual E2EE capability from a
        /// fetched, signature-verified key bundle, never from this flag
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "crate::if_false", default)
        )]
        pub e2ee_enabled: bool,

        /// Linked streaming channels (Twitch / YouTube), public by design
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Vec::is_empty", default)
        )]
        pub connections: Vec<UserConnection>,

        /// Current session user's relationship with this user
        pub relationship: RelationshipStatus,
        /// Whether this user is currently online
        pub online: bool,
    },
    "PartialUser"
);

auto_derived!(
    /// Optional fields on user object
    pub enum FieldsUser {
        Avatar,
        StatusText,
        StatusPresence,
        StatusActivity,
        ProfileContent,
        ProfileBackground,
        DisplayName,
        Pronouns,
        Connections,

        /// Internal field, ignore this.
        Internal,
    }

    /// Platform of a linked streaming channel
    pub enum ConnectionPlatform {
        Twitch,
        YouTube,
    }

    /// A streaming channel the user linked via OAuth.
    ///
    /// Public/promotional by design; never carries tokens (those live in a
    /// private collection server-side).
    pub struct UserConnection {
        /// Which platform the channel is on
        pub platform: ConnectionPlatform,
        /// Channel handle (Twitch login / YouTube @handle) used to build the URL
        pub handle: String,
        /// Channel display name
        pub display_name: String,
        /// Whether the channel is currently live
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "crate::if_false", default)
        )]
        pub live: bool,
        /// Title of the current stream, if live
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub live_title: Option<String>,
        /// When the current stream started, if live
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub live_since: Option<Timestamp>,
    }

    /// User's relationship with another user (or themselves)
    #[derive(Default)]
    pub enum RelationshipStatus {
        /// No relationship with other user
        #[default]
        None,
        /// Other user is us
        User,
        /// Friends with the other user
        Friend,
        /// Pending friend request to user
        Outgoing,
        /// Incoming friend request from user
        Incoming,
        /// Blocked this user
        Blocked,
        /// Blocked by this user
        BlockedOther,
    }

    /// Relationship entry indicating current status with other user
    pub struct Relationship {
        /// Other user's Id
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub user_id: String,
        /// Relationship status with them
        pub status: RelationshipStatus,
    }

    /// Presence status
    pub enum Presence {
        /// User is online
        Online,
        /// User is not currently available
        Idle,
        /// User is focusing / will only receive mentions
        Focus,
        /// User is busy / will not receive any notifications
        Busy,
        /// User appears to be offline
        Invisible,
    }

    /// User's active status
    #[derive(Default)]
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct UserStatus {
        /// Custom status text
        #[validate(length(min = 0, max = 128))]
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub text: Option<String>,
        /// Current presence option
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub presence: Option<Presence>,
        /// Game or application the user is currently playing, shown to friends
        #[cfg_attr(feature = "validator", validate)]
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub activity: Option<UserActivity>,
    }

    /// Information about a game or application a user is playing
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct UserActivity {
        /// Name of the game or application being played
        #[validate(length(min = 1, max = 64))]
        pub name: String,
        /// When the user started playing, for "playing for 2h"-style displays.
        /// Set server-side; ignored on input.
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub started_at: Option<Timestamp>,
    }

    /// User's profile
    #[derive(Default)]
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct UserProfile {
        /// Text content on user's profile
        #[validate(length(min = 0, max = 2000))]
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub content: Option<String>,
        /// Background visible on user's profile
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub background: Option<File>,
    }

    /// User badge bitfield
    #[repr(u32)]
    pub enum UserBadges {
        /// Revolt Developer
        Developer = 1,
        /// Helped translate Revolt
        Translator = 2,
        /// Monetarily supported Revolt
        Supporter = 4,
        /// Responsibly disclosed a security issue
        ResponsibleDisclosure = 8,
        /// Revolt Founder
        Founder = 16,
        /// Platform moderator
        PlatformModeration = 32,
        /// Active monetary supporter
        ActiveSupporter = 64,
        /// 🦊🦝
        Paw = 128,
        /// Joined as one of the first 1000 users in 2021
        EarlyAdopter = 256,
        /// Amogus
        ReservedRelevantJokeBadge1 = 512,
        /// Low resolution troll face
        ReservedRelevantJokeBadge2 = 1024,
    }

    /// User flag enum
    #[repr(u32)]
    pub enum UserFlags {
        /// User has been suspended from the platform
        SuspendedUntil = 1,
        /// User has deleted their account
        Deleted = 2,
        /// User was banned off the platform
        Banned = 4,
        /// User was marked as spam and removed from platform
        Spam = 8,
    }

    /// New user profile data
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataUserProfile {
        /// Text to set as user profile description
        #[cfg_attr(feature = "validator", validate(length(min = 0, max = 2000)))]
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub content: Option<String>,
        /// Attachment Id for background
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
        pub background: Option<String>,
    }

    /// New user information
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataEditUser {
        /// New display name
        #[cfg_attr(
            feature = "validator",
            validate(length(min = 2, max = 32), regex = "RE_DISPLAY_NAME")
        )]
        pub display_name: Option<String>,
        /// New pronouns
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 24)))]
        pub pronouns: Option<String>,
        /// Attachment Id for avatar
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
        pub avatar: Option<String>,

        /// New user status
        #[cfg_attr(feature = "validator", validate)]
        pub status: Option<UserStatus>,
        /// New user profile data
        ///
        /// This is applied as a partial.
        #[cfg_attr(feature = "validator", validate)]
        pub profile: Option<DataUserProfile>,

        /// Bitfield of user badges
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub badges: Option<i32>,
        /// Enum of user flags
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub flags: Option<i32>,

        /// Whether this user has opted in to E2EE DMs (UI hint only)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub e2ee_enabled: Option<bool>,

        /// Fields to remove from user object
        #[cfg_attr(feature = "serde", serde(default))]
        pub remove: Vec<FieldsUser>,
    }

    /// Response to beginning a streaming-channel link: the provider
    /// authorize URL the client should navigate to
    pub struct ResponseConnectionAuthorize {
        pub url: String,
    }

    /// Complete a streaming-channel link with the one-time handoff code
    /// issued by the OAuth callback
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataConnectionComplete {
        /// Platform key ("twitch" / "youtube")
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 16)))]
        pub platform: String,
        /// One-time handoff code from the callback redirect
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub code: String,
    }

    /// User flag reponse
    pub struct FlagResponse {
        /// Flags
        pub flags: i32,
    }

    /// Mutual friends, servers, groups and DMs response
    pub struct MutualResponse {
        /// Array of mutual user IDs that both users are friends with
        pub users: Vec<String>,
        /// Array of mutual server IDs that both users are in
        pub servers: Vec<String>,
        /// Array of mutual group and dm IDs that both users are in
        pub channels: Vec<String>,
    }

    /// Bot information for if the user is a bot
    pub struct BotInformation {
        /// Id of the owner of this bot
        #[cfg_attr(feature = "serde", serde(rename = "owner"))]
        pub owner_id: String,
    }

    /// User lookup information
    pub struct DataSendFriendRequest {
        /// Username and discriminator combo separated by #
        pub username: String,
    }
);

auto_derived_partial!(
    /// Voice State information for a user
    pub struct UserVoiceState {
        pub id: String,
        pub joined_at: Timestamp,
        pub is_receiving: bool,
        pub is_publishing: bool,
        /// True while EITHER a screen-video (source 3) or screen-audio
        /// (source 4) track is live — the two are conflated, so this flag can
        /// read true with no video published at all. Kept as-is for wire
        /// back-compat; anything that needs "screen video is actually live"
        /// must gate on `screen_video` instead.
        pub screensharing: bool,
        pub camera: bool,
        /// True only while a screen VIDEO track (source 3) is live. Additive
        /// field (remote-control plan §1): absent in payloads from older
        /// servers, hence the default.
        #[serde(default)]
        pub screen_video: bool,
        /// True while this participant has a local call recording running
        /// (call-recording plan §1). Additive field, hence the default.
        ///
        /// Unlike every other flag here this one is CLIENT-CLAIMED — it is
        /// written by the recording routes, not by voice-ingress, because the
        /// recording happens in the participant's own client and the SFU
        /// cannot observe it. So it is a self-report: true means "this client
        /// said it is recording". A client that records without saying so
        /// leaves this false, and nothing server-side can tell. It rides on
        /// voice state rather than a one-shot event specifically so that a
        /// LATE JOINER learns of an in-progress recording from the same roster
        /// read that tells them who is in the call.
        #[serde(default)]
        pub recording: bool,
    },
    "PartialUserVoiceState"
);

pub trait CheckRelationship {
    fn with(&self, user: &str) -> RelationshipStatus;
}

impl CheckRelationship for Vec<Relationship> {
    fn with(&self, user: &str) -> RelationshipStatus {
        for entry in self {
            if entry.user_id == user {
                return entry.status.clone();
            }
        }

        RelationshipStatus::None
    }
}
