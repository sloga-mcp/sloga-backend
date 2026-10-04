#![allow(deprecated)]
use super::{File, UserVoiceState};

use revolt_permissions::{Override, OverrideField};
use std::collections::{HashMap, HashSet};

#[cfg(feature = "rocket")]
use rocket::FromForm;

auto_derived!(
    /// Channel
    #[serde(tag = "channel_type")]
    pub enum Channel {
        /// Personal "Saved Notes" channel which allows users to save messages
        SavedMessages {
            /// Unique Id
            #[cfg_attr(feature = "serde", serde(rename = "_id"))]
            id: String,
            /// Id of the user this channel belongs to
            user: String,
        },
        /// Direct message channel between two users
        DirectMessage {
            /// Unique Id
            #[cfg_attr(feature = "serde", serde(rename = "_id"))]
            id: String,

            /// Whether this direct message channel is currently open on both sides
            active: bool,
            /// 2-tuple of user ids participating in direct message
            recipients: Vec<String>,
            /// Id of the last message sent in this channel
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            last_message_id: Option<String>,
        },
        /// Group channel between 1 or more participants
        Group {
            /// Unique Id
            #[cfg_attr(feature = "serde", serde(rename = "_id"))]
            id: String,

            /// Display name of the channel
            name: String,
            /// User id of the owner of the group
            owner: String,
            /// Channel description
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            description: Option<String>,
            /// Array of user ids participating in channel
            recipients: Vec<String>,

            /// Custom icon attachment
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            icon: Option<File>,
            /// Id of the last message sent in this channel
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            last_message_id: Option<String>,

            /// Permissions assigned to members of this group
            /// (does not apply to the owner of the group)
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            permissions: Option<i64>,

            /// Whether this group is marked as not safe for work
            #[cfg_attr(
                feature = "serde",
                serde(skip_serializing_if = "crate::if_false", default)
            )]
            nsfw: bool,
            /// Whether clients should hide this group behind a
            /// click-to-reveal spoiler gate
            #[cfg_attr(
                feature = "serde",
                serde(skip_serializing_if = "crate::if_false", default)
            )]
            spoiler: bool,

            /// Voice call configuration for this group (limits, on/off)
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            voice: Option<VoiceInformation>,
        },
        /// Text channel belonging to a server
        TextChannel {
            /// Unique Id
            #[cfg_attr(feature = "serde", serde(rename = "_id"))]
            id: String,
            /// Id of the server this channel belongs to
            server: String,

            /// Display name of the channel
            name: String,
            /// Channel description
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            description: Option<String>,

            /// Custom icon attachment
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            icon: Option<File>,
            /// Id of the last message sent in this channel
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            last_message_id: Option<String>,

            /// Default permissions assigned to users in this channel
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            default_permissions: Option<OverrideField>,
            /// Permissions assigned based on role to this channel
            #[cfg_attr(
                feature = "serde",
                serde(
                    default = "HashMap::<String, OverrideField>::new",
                    skip_serializing_if = "HashMap::<String, OverrideField>::is_empty"
                )
            )]
            role_permissions: HashMap<String, OverrideField>,

            /// Whether this channel is marked as not safe for work
            #[cfg_attr(
                feature = "serde",
                serde(skip_serializing_if = "crate::if_false", default)
            )]
            nsfw: bool,
            /// Whether clients should hide this channel behind a
            /// click-to-reveal spoiler gate
            #[cfg_attr(
                feature = "serde",
                serde(skip_serializing_if = "crate::if_false", default)
            )]
            spoiler: bool,

            /// Voice Information for when this channel is also a voice channel
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            voice: Option<VoiceInformation>,

            /// The channel's slowmode delay in seconds
            #[serde(skip_serializing_if = "Option::is_none")]
            slowmode: Option<u64>,

            /// Whether this text channel is an announcement channel that
            /// other servers' channels can follow (Discord-style
            /// publish/crosspost fan-out). Absent / `None` means an
            /// ordinary text channel.
            #[serde(skip_serializing_if = "Option::is_none")]
            announcement: Option<bool>,
        },
        /// Thread belonging to a server text channel
        Thread {
            /// Unique Id
            #[cfg_attr(feature = "serde", serde(rename = "_id"))]
            id: String,
            /// Id of the server this thread belongs to
            server: String,
            /// Id of the parent text channel this thread hangs off
            parent_channel: String,

            /// Display name of the thread
            name: String,
            /// Id of the user that created this thread
            creator: String,
            /// Id of the message in the parent channel this thread was created from
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            origin_message_id: Option<String>,
            /// Id of the last message sent in this thread
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            last_message_id: Option<String>,

            /// Whether this thread is archived
            #[cfg_attr(
                feature = "serde",
                serde(skip_serializing_if = "crate::if_false", default)
            )]
            archived: bool,
            /// When the archive state of this thread last changed
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            archived_timestamp: Option<String>,
            /// Minutes of inactivity after which this thread auto-archives
            /// (0 = Never, otherwise 1 up to two years)
            #[cfg_attr(
                feature = "serde",
                serde(default = "default_auto_archive_minutes")
            )]
            auto_archive_minutes: u32,

            /// Whether this thread is locked
            #[cfg_attr(
                feature = "serde",
                serde(skip_serializing_if = "crate::if_false", default)
            )]
            locked: bool,

            /// Ids of this forum's tags applied to this thread
            /// (only ever set on threads whose parent is a forum channel)
            #[cfg_attr(
                feature = "serde",
                serde(default, skip_serializing_if = "Vec::is_empty")
            )]
            applied_tags: Vec<String>,
        },
        /// Forum channel belonging to a server; every post is a thread
        Forum {
            /// Unique Id
            #[cfg_attr(feature = "serde", serde(rename = "_id"))]
            id: String,
            /// Id of the server this channel belongs to
            server: String,

            /// Display name of the channel
            name: String,
            /// Channel description
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            description: Option<String>,

            /// Custom icon attachment
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            icon: Option<File>,
            /// Id of the last message sent in a post under this forum
            /// (drives the existing unread / ack machinery unchanged)
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            last_message_id: Option<String>,

            /// Default permissions assigned to users in this channel
            #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
            default_permissions: Option<OverrideField>,
            /// Permissions assigned based on role to this channel
            #[cfg_attr(
                feature = "serde",
                serde(
                    default = "HashMap::<String, OverrideField>::new",
                    skip_serializing_if = "HashMap::<String, OverrideField>::is_empty"
                )
            )]
            role_permissions: HashMap<String, OverrideField>,

            /// Whether this channel is marked as not safe for work
            #[cfg_attr(
                feature = "serde",
                serde(skip_serializing_if = "crate::if_false", default)
            )]
            nsfw: bool,
            /// Whether clients should hide this channel behind a
            /// click-to-reveal spoiler gate
            #[cfg_attr(
                feature = "serde",
                serde(skip_serializing_if = "crate::if_false", default)
            )]
            spoiler: bool,

            /// Tags that can be applied to posts in this forum
            #[cfg_attr(
                feature = "serde",
                serde(default, skip_serializing_if = "Vec::is_empty")
            )]
            tags: Vec<ForumTag>,
            /// Whether every post must carry at least one tag
            #[cfg_attr(
                feature = "serde",
                serde(skip_serializing_if = "crate::if_false", default)
            )]
            require_tag: bool,
            /// Default ordering of the post browse view
            #[cfg_attr(feature = "serde", serde(default))]
            default_sort: ForumSortOrder,
            /// Whether `default_sort` is imposed on every reader rather than
            /// being the order the browse view merely opens on
            #[cfg_attr(
                feature = "serde",
                serde(skip_serializing_if = "crate::if_false", default)
            )]
            force_sort: bool,
            /// How the forum lists its posts by default; readers can override
            /// it for themselves
            #[cfg_attr(feature = "serde", serde(default))]
            default_layout: ForumLayout,
            /// Default auto-archive duration for new posts in this forum, in
            /// minutes (0 = Never, otherwise 1 up to two years; see
            /// `Channel::is_valid_auto_archive_minutes`)
            #[cfg_attr(
                feature = "serde",
                serde(default = "default_forum_auto_archive_minutes")
            )]
            default_auto_archive_minutes: u32,
        },
    }

    /// Tag that can be applied to posts in a forum channel
    pub struct ForumTag {
        /// Unique Id of this tag (server-assigned ulid)
        pub id: String,
        /// Display name of the tag
        pub name: String,
        /// Emoji shown alongside the tag name
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub emoji: Option<String>,
        /// Whether only members with ManageChannel may apply this tag
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "crate::if_false", default)
        )]
        pub moderated: bool,
    }

    /// Default ordering of a forum's post browse view
    #[derive(Default)]
    pub enum ForumSortOrder {
        /// Most recently active post first
        #[default]
        LatestActivity,
        /// Most recently created post first
        CreationDate,
        /// By post title, 0-9 then A-Z
        Alphabetical,
    }

    /// How a forum's post browse view lists its posts
    #[derive(Default)]
    pub enum ForumLayout {
        /// Preview cards (title, starter excerpt, tags)
        #[default]
        Modern,
        /// One row per post: author, title, tags, last reply, reply count
        Classic,
        /// Table with topic, replies and last post columns
        ClassicPlus,
    }

    /// Voice information for a channel
    #[derive(Default)]
    #[cfg_attr(feature = "validator", derive(validator::Validate))]
    pub struct VoiceInformation {
        /// Maximium amount of users allowed in the voice channel at once
        #[cfg_attr(feature = "validator", validate(range(min = 1)))]
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub max_users: Option<usize>,
        /// Whether voice/video calling is turned off for this channel
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "crate::if_false", default)
        )]
        pub disabled: bool,
    }

    /// Partial representation of a channel
    #[derive(Default)]
    pub struct PartialChannel {
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub name: Option<String>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub owner: Option<String>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub description: Option<String>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub icon: Option<File>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub nsfw: Option<bool>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub spoiler: Option<bool>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub active: Option<bool>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub permissions: Option<i64>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub role_permissions: Option<HashMap<String, OverrideField>>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub default_permissions: Option<OverrideField>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub last_message_id: Option<String>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub voice: Option<VoiceInformation>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub slowmode: Option<u64>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub archived: Option<bool>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub archived_timestamp: Option<String>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub tags: Option<Vec<ForumTag>>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub require_tag: Option<bool>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub default_sort: Option<ForumSortOrder>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub force_sort: Option<bool>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub default_layout: Option<ForumLayout>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub auto_archive_minutes: Option<u32>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub default_auto_archive_minutes: Option<u32>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub applied_tags: Option<Vec<String>>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub announcement: Option<bool>,
    }

    /// Optional fields on channel object
    pub enum FieldsChannel {
        Description,
        Icon,
        DefaultPermissions,
        Voice,
        Tags,
    }

    /// New webhook information
    #[cfg_attr(feature = "validator", derive(validator::Validate))]
    pub struct DataEditChannel {
        /// Channel name
        ///
        /// The shared validator allows up to 100 characters (forum post
        /// titles); channel_edit enforces the 32-character limit for every
        /// channel type except forum-post threads.
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 100)))]
        pub name: Option<String>,

        /// Channel description
        #[cfg_attr(feature = "validator", validate(length(min = 0, max = 1024)))]
        pub description: Option<String>,

        /// Group owner
        pub owner: Option<String>,

        /// Icon
        ///
        /// Provide an Autumn attachment Id.
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
        pub icon: Option<String>,

        /// Whether this channel is age-restricted
        pub nsfw: Option<bool>,

        /// Whether clients should hide this channel behind a
        /// click-to-reveal spoiler gate
        pub spoiler: Option<bool>,

        /// Whether this channel is archived
        pub archived: Option<bool>,

        /// Voice Information for voice channels
        pub voice: Option<VoiceInformation>,

        /// The channel's slow mode delay in seconds, up to 6 hours
        #[cfg_attr(feature = "validator", validate(range(min = 0, max = 21600)))]
        pub slowmode: Option<u64>,

        /// Tag definitions for a forum channel (replaces the whole set;
        /// tags without an id are new and get a server-assigned id)
        pub tags: Option<Vec<DataForumTag>>,

        /// Whether every post in a forum must carry at least one tag
        pub require_tag: Option<bool>,

        /// Default ordering of a forum's post browse view
        pub default_sort: Option<ForumSortOrder>,

        /// Whether to impose `default_sort` on every reader of this forum
        /// (forum channels only). An info board is the case this exists for:
        /// the operator wants one listing everybody sees, not a default each
        /// member can sort away from.
        pub force_sort: Option<bool>,

        /// Default layout of a forum's post browse view (forum channels
        /// only); readers can override it for themselves
        pub default_layout: Option<ForumLayout>,

        /// Minutes of inactivity after which this thread / forum post
        /// auto-archives (threads and forum posts only;
        /// 0 = Never, otherwise 1 up to two years)
        pub auto_archive_minutes: Option<u32>,

        /// Default auto-archive duration for new posts in a forum, in minutes
        /// (forum channels only; 0 = Never, otherwise 1 up to two years)
        pub default_auto_archive_minutes: Option<u32>,

        /// Ids of forum tags applied to this post (forum-post threads only;
        /// replaces the whole set)
        pub applied_tags: Option<Vec<String>>,

        /// Whether this text channel is an announcement channel
        /// (server text channels only; ManageChannel required)
        pub announcement: Option<bool>,

        /// Fields to remove from channel
        #[cfg_attr(feature = "serde", serde(default))]
        pub remove: Vec<FieldsChannel>,
    }

    /// Forum tag definition as submitted by a client
    pub struct DataForumTag {
        /// Id of an existing tag to keep/edit; omit for a new tag
        pub id: Option<String>,
        /// Display name of the tag
        pub name: String,
        /// Emoji shown alongside the tag name
        pub emoji: Option<String>,
        /// Whether only members with ManageChannel may apply this tag
        #[cfg_attr(feature = "serde", serde(default))]
        pub moderated: bool,
    }

    /// Create new group
    #[derive(Default)]
    #[cfg_attr(feature = "validator", derive(validator::Validate))]
    pub struct DataCreateGroup {
        /// Group name
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 32)))]
        pub name: String,
        /// Group description
        #[cfg_attr(feature = "validator", validate(length(min = 0, max = 1024)))]
        pub description: Option<String>,
        /// Group icon
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
        pub icon: Option<String>,
        /// Array of user IDs to add to the group
        ///
        /// Must be friends with these users.
        #[cfg_attr(feature = "validator", validate(length(min = 0, max = 49)))]
        #[serde(default)]
        pub users: HashSet<String>,
        /// Whether this group is age-restricted
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nsfw: Option<bool>,
        /// Whether clients should hide this group behind a
        /// click-to-reveal spoiler gate
        #[serde(skip_serializing_if = "Option::is_none")]
        pub spoiler: Option<bool>,
    }

    /// Create new thread
    #[derive(Default)]
    #[cfg_attr(feature = "validator", derive(validator::Validate))]
    pub struct DataCreateThread {
        /// Thread name
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 32)))]
        pub name: String,
        /// Minutes of inactivity after which the thread auto-archives
        /// (0 = Never, otherwise 1 up to two years; omitted = 1440)
        pub auto_archive_minutes: Option<u32>,
    }

    /// Server Channel Type
    #[derive(Default)]
    pub enum LegacyServerChannelType {
        /// Text Channel
        #[default]
        Text,
        /// Voice Channel
        Voice,
        /// Forum Channel
        Forum,
    }

    /// Create a new post in a forum channel
    #[cfg_attr(feature = "validator", derive(validator::Validate))]
    pub struct DataCreateForumPost {
        /// Post title (becomes the thread name)
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 100)))]
        pub title: String,
        /// Ids of forum tags applied to this post
        #[cfg_attr(feature = "serde", serde(default))]
        pub tags: Vec<String>,
        /// Minutes of inactivity after which the post auto-archives
        /// (0 = Never, otherwise 1 up to two years; omitted = the forum's
        /// default_auto_archive_minutes)
        pub auto_archive_minutes: Option<u32>,
        /// Starter message of the post
        pub message: super::DataMessageSend,
    }

    /// A newly created forum post with its starter message
    pub struct ForumPostResponse {
        /// The post (a thread under the forum)
        pub post: Channel,
        /// The starter message (its id equals the post's id)
        pub message: super::Message,
    }

    /// A page of forum posts
    pub struct ForumPostsResponse {
        /// Posts, ordered by the requested sort
        pub posts: Vec<Channel>,
        /// Starter messages for this page's posts (present when
        /// `include_starters` was set; each message's id equals its post's id)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub starters: Option<Vec<super::Message>>,
        /// Reply count and latest message id for each of this page's posts
        /// (present only when requested with `include_stats` and the caller
        /// can read message history)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub stats: Option<Vec<ForumPostStats>>,
        /// Latest message of each of this page's posts (present only when
        /// requested with `include_stats` and the caller can read message
        /// history)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub last_messages: Option<Vec<super::Message>>,
        /// Users referenced by this page (present only when requested with
        /// `include_users`: the creators of every returned post, plus, with
        /// message history, the authors of the starters and last messages)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub users: Option<Vec<super::User>>,
        /// Server members referenced by this page (present only when
        /// requested with `include_users`: the creators of every returned
        /// post, plus, with message history, the authors of the starters and
        /// last messages)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub members: Option<Vec<super::Member>>,
    }

    /// Activity summary of a single forum post
    pub struct ForumPostStats {
        /// Id of the post
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub id: String,
        /// Number of replies in the post; replies exclude the post's
        /// starter message (system messages count as replies)
        pub replies: u32,
        /// Id of the post's latest message (the starter when it has no
        /// replies; absent when the post has no messages at all)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub last_message_id: Option<String>,
    }

    /// Create new server channel
    #[derive(Default)]
    #[cfg_attr(feature = "validator", derive(validator::Validate))]
    pub struct DataCreateServerChannel {
        /// Channel type
        #[serde(rename = "type", default = "LegacyServerChannelType::default")]
        pub channel_type: LegacyServerChannelType,
        /// Channel name
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 32)))]
        pub name: String,
        /// Channel description
        #[cfg_attr(feature = "validator", validate(length(min = 0, max = 1024)))]
        pub description: Option<String>,
        /// Whether this channel is age restricted
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nsfw: Option<bool>,

        /// Whether clients should hide this channel behind a
        /// click-to-reveal spoiler gate
        #[serde(skip_serializing_if = "Option::is_none")]
        pub spoiler: Option<bool>,

        /// Voice Information for when this channel is also a voice channel
        #[serde(skip_serializing_if = "Option::is_none")]
        pub voice: Option<VoiceInformation>,

        /// Whether this text channel is created as an announcement channel
        #[serde(skip_serializing_if = "Option::is_none")]
        pub announcement: Option<bool>,

        /// Whether this channel is created as this server's AFK voice channel
        ///
        /// Voice channels only. A `true` here on a Text or Forum channel is
        /// rejected rather than silently dropped. Requires `ManageServer` on
        /// top of the create-channel route's `ManageChannel`, because the
        /// designation is stored on the SERVER (`Server.afk_channel_id`), not
        /// on the channel.
        ///
        /// This is a route-level field. The DB-layer
        /// `Channel::create_server_channel` never reads it, so every other
        /// caller of that function silently ignores it.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub afk: Option<bool>,

        /// Idle timeout in SECONDS before a member is moved to this channel
        ///
        /// Constrained to `Server::AFK_TIMEOUT_CHOICES`. Only read when
        /// `afk` is `true`; supplied on its own it is ignored, so a request
        /// that does not ask for the AFK designation behaves exactly as it did
        /// before this field existed.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub afk_timeout: Option<u32>,

        /// Designate with NO idle timeout ("Never"), clearing any timeout the
        /// server already has
        ///
        /// Only valid alongside `afk: true` and without `afk_timeout`; any
        /// other combination is rejected. Without this a creation could only
        /// set a timeout or keep the server's existing one, never remove it.
        #[cfg_attr(feature = "serde", serde(default))]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub afk_timeout_never: Option<bool>,
    }

    /// New default permissions
    #[serde(untagged)]
    pub enum DataDefaultChannelPermissions {
        Value {
            /// Permission values to set for members in a `Group`
            permissions: u64,
        },
        Field {
            /// Allow / deny values to set for members in this server channel
            permissions: Override,
        },
    }

    /// New role permissions
    pub struct DataSetRolePermissions {
        /// Allow / deny values to set for this role
        pub permissions: Override,
    }

    /// Options when deleting a channel
    #[cfg_attr(feature = "rocket", derive(FromForm))]
    pub struct OptionsChannelDelete {
        /// Whether to not send a leave message
        pub leave_silently: Option<bool>,
    }

    /// Voice server token response
    pub struct CreateVoiceUserResponse {
        /// Token for authenticating with the voice server
        pub token: String,
        /// Url of the livekit server to connect to
        pub url: String,
    }

    /// Voice state for a channel
    pub struct ChannelVoiceState {
        pub id: String,
        /// The states of the users who are connected to the channel
        pub participants: Vec<UserVoiceState>,
    }

    /// Join a voice channel
    pub struct DataJoinCall {
        /// Name of the node to join
        pub node: Option<String>,
        /// Whether to force disconnect any other existing voice connections
        ///
        /// Useful for disconnecting on another device and joining on a new.
        pub force_disconnect: Option<bool>,
        /// Users which should be notified of the call starting
        ///
        /// Only used when the user is the first one connected.
        pub recipients: Option<Vec<String>>,
        /// E2EE device id joining the call (media E2EE).
        ///
        /// When present (requires media E2EE to be enabled) it must be a
        /// registered E2EE device of the calling user whose session is bound
        /// to it; the LiveKit participant identity then becomes
        /// `{user_id}:{device_id}` so per-device frame keys map injectively
        /// onto SFU participants.
        pub device_id: Option<String>,
        /// Whether this join is the client's own automatic rejoin after a
        /// dropped connection.
        ///
        /// A rejoin must never take the seat back from a connection that is
        /// live in ANOTHER channel (a sibling that was moved while this one
        /// was offline): when set, such a join is refused with
        /// `AlreadyConnected` before anything is disconnected. Absent means
        /// false, the deliberate join, which still force-disconnects as
        /// before.
        #[cfg_attr(feature = "serde", serde(default))]
        pub rejoin: Option<bool>,
    }

    /// Report that this client has been idle in a voice call
    ///
    /// CLIENT-CLAIMED: a self-report the server cannot verify. It grants
    /// nothing; it can only get its own author moved to the AFK channel.
    pub struct DataAfkIdle {
        /// Seconds since this client last saw activity from its user
        ///
        /// Relative, so no client clock travels on the wire: the server
        /// stamps the claim from its own clock and caps it at one hour.
        pub idle_for: u32,
    }

    /// Ask for a token for a native screen-share leg
    ///
    /// The leg is a SECOND, publish-only LiveKit participant owned by the
    /// device that is already in the call: no web runtime on Android exposes
    /// screen capture, and a native MediaProjection capture cannot be handed
    /// to the WebView's WebRTC stack as a track.
    pub struct DataScreenLeg {
        /// E2EE device id the leg is being minted for.
        ///
        /// Must be a registered E2EE device of the calling user whose session
        /// is bound to it, AND must be the device that currently holds the
        /// call's participant identity — the leg identity is derived from the
        /// live primary mapping, never from this field. Absent means the
        /// primary joined without a device id (a bare, non-E2EE identity).
        pub device_id: Option<String>,
    }

    pub struct ChannelSlowmode {
        pub channel_id: String,
        pub duration: u64,
        pub retry_after: u64,
    }
);

/// Default auto-archive duration for threads, in minutes
pub(crate) fn default_auto_archive_minutes() -> u32 {
    1440
}

/// Default auto-archive duration for new posts in a forum, in minutes
pub(crate) fn default_forum_auto_archive_minutes() -> u32 {
    10080
}

impl Channel {
    /// Get a reference to this channel's id
    pub fn id(&self) -> &str {
        match self {
            Channel::DirectMessage { id, .. }
            | Channel::Group { id, .. }
            | Channel::SavedMessages { id, .. }
            | Channel::TextChannel { id, .. }
            | Channel::Thread { id, .. }
            | Channel::Forum { id, .. } => id,
        }
    }

    /// This returns a Result because the recipient name can't be determined here without a db call,
    /// which can't be done since this is models, which can't reference the database crate.
    ///
    /// If it returns None, you need to fetch the name from the db.
    pub fn name(&self) -> Option<&str> {
        match self {
            Channel::DirectMessage { .. } => None,
            Channel::SavedMessages { .. } => Some("Saved Messages"),
            Channel::TextChannel { name, .. }
            | Channel::Group { name, .. }
            | Channel::Thread { name, .. }
            | Channel::Forum { name, .. } => Some(name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DataAfkIdle, DataCreateServerChannel, DataJoinCall};

    /// AFK plan R1 A7: the create route's "Never" flag. It must travel under
    /// exactly this wire key (the client sends `afk_timeout_never: true`), and
    /// an older client that never sends it must still deserialize.
    #[test]
    fn create_channel_afk_timeout_never_is_optional_on_the_wire() {
        let data: DataCreateServerChannel =
            serde_json::from_str(r#"{"type":"Voice","name":"AFK","afk":true}"#).unwrap();
        assert_eq!(data.afk_timeout_never, None);

        let data: DataCreateServerChannel = serde_json::from_str(
            r#"{"type":"Voice","name":"AFK","afk":true,"afk_timeout_never":true}"#,
        )
        .unwrap();
        assert_eq!(data.afk_timeout_never, Some(true));

        // The field carries the file's serde-default attribute.
        let source = include_str!("channels.rs");
        let field = source
            .find("pub afk_timeout_never: Option<bool>,")
            .expect("the field exists");
        let attributes = &source[source[..field].rfind("///").expect("a doc comment")..field];
        assert!(
            attributes.contains("#[cfg_attr(feature = \"serde\", serde(default))]"),
            "afk_timeout_never lost its serde default: {attributes}"
        );
    }

    /// The idle beacon's body is exactly `idle_for` (AFK plan Wave 5b-2 wire
    /// contract). The destructure is exhaustive, so a second field does not
    /// compile; the round trip pins the wire key and the integer type.
    #[test]
    fn afk_idle_body_is_exactly_idle_for() {
        let DataAfkIdle { idle_for } =
            serde_json::from_str::<DataAfkIdle>(r#"{"idle_for":90}"#).unwrap();
        assert_eq!(idle_for, 90);
        assert_eq!(
            serde_json::to_value(DataAfkIdle { idle_for: 90 }).unwrap(),
            serde_json::json!({ "idle_for": 90 })
        );
        for invalid in [r#"{"idle_for":-1}"#, r#"{"idle_for":1.5}"#, r#"{}"#] {
            assert!(
                serde_json::from_str::<DataAfkIdle>(invalid).is_err(),
                "{invalid} must be refused"
            );
        }
    }

    /// Absent `rejoin` is the deliberate join; only an explicit `true` asks
    /// for the rejoin refusal.
    #[test]
    fn join_call_rejoin_defaults_to_absent() {
        let data: DataJoinCall = serde_json::from_str(r#"{"force_disconnect":true}"#).unwrap();
        assert_eq!(data.rejoin, None);
        let data: DataJoinCall =
            serde_json::from_str(r#"{"force_disconnect":true,"rejoin":true}"#).unwrap();
        assert_eq!(data.rejoin, Some(true));
    }
}
