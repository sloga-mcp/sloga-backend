#![allow(deprecated)]
use std::{borrow::Cow, collections::HashMap};

use redis_kiss::get_connection;
use revolt_config::config;
use revolt_models::v0::{self, MessageAuthor};
use revolt_permissions::OverrideField;
use revolt_result::Result;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    events::client::EventV1, Database, File, Message, PartialMessage, PartialServer, Server,
    SystemMessage, User, AMQP,
};

#[cfg(feature = "mongodb")]
use crate::IntoDocumentPath;

auto_derived!(
    #[serde(tag = "channel_type")]
    pub enum Channel {
        /// Personal "Saved Notes" channel which allows users to save messages
        SavedMessages {
            /// Unique Id
            #[serde(rename = "_id")]
            id: String,
            /// Id of the user this channel belongs to
            user: String,
        },
        /// Direct message channel between two users
        DirectMessage {
            /// Unique Id
            #[serde(rename = "_id")]
            id: String,

            /// Whether this direct message channel is currently open on both sides
            active: bool,
            /// 2-tuple of user ids participating in direct message
            recipients: Vec<String>,
            /// Id of the last message sent in this channel
            #[serde(skip_serializing_if = "Option::is_none")]
            last_message_id: Option<String>,
        },
        /// Group channel between 1 or more participants
        Group {
            /// Unique Id
            #[serde(rename = "_id")]
            id: String,

            /// Display name of the channel
            name: String,
            /// User id of the owner of the group
            owner: String,
            /// Channel description
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<String>,
            /// Array of user ids participating in channel
            recipients: Vec<String>,

            /// Custom icon attachment
            #[serde(skip_serializing_if = "Option::is_none")]
            icon: Option<File>,
            /// Id of the last message sent in this channel
            #[serde(skip_serializing_if = "Option::is_none")]
            last_message_id: Option<String>,

            /// Permissions assigned to members of this group
            /// (does not apply to the owner of the group)
            #[serde(skip_serializing_if = "Option::is_none")]
            permissions: Option<i64>,

            /// Whether this group is marked as not safe for work
            #[serde(skip_serializing_if = "crate::if_false", default)]
            nsfw: bool,
            /// Whether clients should hide this group behind a
            /// click-to-reveal spoiler gate
            #[serde(skip_serializing_if = "crate::if_false", default)]
            spoiler: bool,

            /// Voice call configuration for this group (limits, on/off)
            #[serde(skip_serializing_if = "Option::is_none")]
            voice: Option<VoiceInformation>,
        },
        /// Text channel belonging to a server
        TextChannel {
            /// Unique Id
            #[serde(rename = "_id")]
            id: String,
            /// Id of the server this channel belongs to
            server: String,

            /// Display name of the channel
            name: String,
            /// Channel description
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<String>,

            /// Custom icon attachment
            #[serde(skip_serializing_if = "Option::is_none")]
            icon: Option<File>,
            /// Id of the last message sent in this channel
            #[serde(skip_serializing_if = "Option::is_none")]
            last_message_id: Option<String>,

            /// Default permissions assigned to users in this channel
            #[serde(skip_serializing_if = "Option::is_none")]
            default_permissions: Option<OverrideField>,
            /// Permissions assigned based on role to this channel
            #[serde(
                default = "HashMap::<String, OverrideField>::new",
                skip_serializing_if = "HashMap::<String, OverrideField>::is_empty"
            )]
            role_permissions: HashMap<String, OverrideField>,

            /// Whether this channel is marked as not safe for work
            #[serde(skip_serializing_if = "crate::if_false", default)]
            nsfw: bool,
            /// Whether clients should hide this channel behind a
            /// click-to-reveal spoiler gate
            #[serde(skip_serializing_if = "crate::if_false", default)]
            spoiler: bool,

            /// Voice Information for when this channel is also a voice channel
            #[serde(skip_serializing_if = "Option::is_none")]
            voice: Option<VoiceInformation>,

            /// The channel's slowmode delay in seconds
            #[serde(skip_serializing_if = "Option::is_none")]
            slowmode: Option<u64>,

            /// Whether this text channel is an announcement channel that
            /// other servers' channels can follow (crosspost fan-out).
            #[serde(skip_serializing_if = "Option::is_none")]
            announcement: Option<bool>,

            /// Whether this is a protected (end-to-end encrypted) channel.
            ///
            /// One-way: once true it is never false again. Only the protect
            /// route sets it; no client edit can set or clear it (it is not
            /// in `FieldsChannel`), and `Channel::update` refuses a partial
            /// that would lower it.
            #[serde(skip_serializing_if = "crate::if_false", default)]
            protected: bool,
        },
        /// Thread belonging to a server text channel
        Thread {
            /// Unique Id
            #[serde(rename = "_id")]
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
            #[serde(skip_serializing_if = "Option::is_none")]
            origin_message_id: Option<String>,
            /// Id of the last message sent in this thread
            #[serde(skip_serializing_if = "Option::is_none")]
            last_message_id: Option<String>,

            /// Whether this thread is archived
            #[serde(skip_serializing_if = "crate::if_false", default)]
            archived: bool,
            /// When the archive state of this thread last changed
            #[serde(skip_serializing_if = "Option::is_none")]
            archived_timestamp: Option<String>,
            /// Minutes of inactivity after which this thread auto-archives
            /// (0 = Never, otherwise 1 up to two years)
            #[serde(default = "Channel::default_auto_archive_minutes")]
            auto_archive_minutes: u32,

            /// Whether this thread is locked
            #[serde(skip_serializing_if = "crate::if_false", default)]
            locked: bool,

            /// Ids of this forum's tags applied to this thread
            /// (only ever set on threads whose parent is a forum channel)
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            applied_tags: Vec<String>,
        },
        /// Forum channel belonging to a server; every post is a thread
        Forum {
            /// Unique Id
            #[serde(rename = "_id")]
            id: String,
            /// Id of the server this channel belongs to
            server: String,

            /// Display name of the channel
            name: String,
            /// Channel description
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<String>,

            /// Custom icon attachment
            #[serde(skip_serializing_if = "Option::is_none")]
            icon: Option<File>,
            /// Id of the last message sent in a post under this forum
            /// (drives the existing unread / ack machinery unchanged)
            #[serde(skip_serializing_if = "Option::is_none")]
            last_message_id: Option<String>,

            /// Default permissions assigned to users in this channel
            #[serde(skip_serializing_if = "Option::is_none")]
            default_permissions: Option<OverrideField>,
            /// Permissions assigned based on role to this channel
            #[serde(
                default = "HashMap::<String, OverrideField>::new",
                skip_serializing_if = "HashMap::<String, OverrideField>::is_empty"
            )]
            role_permissions: HashMap<String, OverrideField>,

            /// Whether this channel is marked as not safe for work
            #[serde(skip_serializing_if = "crate::if_false", default)]
            nsfw: bool,
            /// Whether clients should hide this channel behind a
            /// click-to-reveal spoiler gate
            #[serde(skip_serializing_if = "crate::if_false", default)]
            spoiler: bool,

            /// Tags that can be applied to posts in this forum
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            tags: Vec<ForumTag>,
            /// Whether every post must carry at least one tag
            #[serde(skip_serializing_if = "crate::if_false", default)]
            require_tag: bool,
            /// Default ordering of the post browse view
            #[serde(default)]
            default_sort: ForumSortOrder,
            /// Whether `default_sort` is imposed on every reader rather than
            /// being the order the browse view merely opens on
            #[serde(skip_serializing_if = "crate::if_false", default)]
            force_sort: bool,
            /// Default layout of the post browse view; readers may override it
            /// locally. Absent on older documents, which load as `Modern`
            #[serde(default)]
            default_layout: ForumLayout,
            /// Auto-archive duration (minutes) applied to new posts that do
            /// not specify one (see `Channel::is_valid_auto_archive_minutes`,
            /// 0 = Never)
            #[serde(default = "Channel::default_forum_auto_archive_minutes")]
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
        #[serde(skip_serializing_if = "Option::is_none")]
        pub emoji: Option<String>,
        /// Whether only members with ManageChannel may apply this tag
        #[serde(skip_serializing_if = "crate::if_false", default)]
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

    /// Default layout of a forum's post browse view
    #[derive(Default)]
    pub enum ForumLayout {
        /// Preview cards
        #[default]
        Modern,
        /// One row per post: author, title, tags, last reply and reply count
        Classic,
        /// Table with topic, replies and last post columns
        ClassicPlus,
    }

    #[derive(Default)]
    pub struct VoiceInformation {
        /// Maximium amount of users allowed in the voice channel at once
        #[serde(skip_serializing_if = "Option::is_none")]
        pub max_users: Option<usize>,
        /// Whether voice/video calling is turned off for this channel
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub disabled: bool,
    }
);

auto_derived!(
    #[derive(Default)]
    pub struct PartialChannel {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub owner: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub icon: Option<File>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nsfw: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub spoiler: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub active: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub permissions: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub role_permissions: Option<HashMap<String, OverrideField>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub default_permissions: Option<OverrideField>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub last_message_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub voice: Option<VoiceInformation>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub slowmode: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub archived: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub archived_timestamp: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tags: Option<Vec<ForumTag>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub require_tag: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub default_sort: Option<ForumSortOrder>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub force_sort: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub default_layout: Option<ForumLayout>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub auto_archive_minutes: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub default_auto_archive_minutes: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub applied_tags: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub announcement: Option<bool>,
        /// Only ever `Some(true)` on the wire: `Channel::update` refuses
        /// `Some(false)` on a protected channel and drops it on any other.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub protected: Option<bool>,
    }

    /// Optional fields on channel object
    pub enum FieldsChannel {
        Description,
        Icon,
        DefaultPermissions,
        Voice,
        Tags,
    }
);

impl PartialChannel {
    /// Whether this partial sets a field a protected channel never takes:
    /// any `voice`, or `announcement: Some(true)` (design 7.4).
    ///
    /// `Channel::update` refuses it against the caller's copy of the
    /// channel, and both drivers' `update_channel` refuse it again against
    /// the STORED channel in the same write, because the caller's copy can
    /// be stale across a concurrent protect.
    pub fn sets_field_refused_on_protected(&self) -> bool {
        self.voice.is_some() || self.announcement == Some(true)
    }
}

/// Opening marker of the line that carries a channel's password hash inside
/// its `description`.
///
/// The password gate is written and enforced by clients; the server only
/// reads it. The source of truth is `PREFIX` in the client's
/// `packages/client/src/lib/channelPassword.ts`, and this must stay
/// byte-identical to it. It is the only place the marker is spelled in the
/// workspace (pinned by a test below): every other reader goes through
/// [`description_has_password_gate`].
pub const CHANNEL_PASSWORD_PREFIX: &str = "[acupass:";

/// Closing marker of the password line; `SUFFIX` in the same client file.
pub const CHANNEL_PASSWORD_SUFFIX: &str = "]";

/// Whether a channel description carries a password gate, decided exactly as
/// the client's `parseChannelPassword` (`channelPassword.ts`) decides it.
///
/// - Only the LAST line counts, split on `\n` alone. This is
///   `split('\n').last()`, deliberately not `lines().last()`: `lines()` also
///   strips a trailing `\r` and ignores a trailing empty line, so a
///   description ending in a newline, or a marker line ending in CRLF, would
///   read as gated here while the client (JS `split("\n")`) shows no gate.
/// - That line must start with [`CHANNEL_PASSWORD_PREFIX`] and end with
///   [`CHANNEL_PASSWORD_SUFFIX`]: case-sensitive, nothing trimmed.
/// - The hash between the two must be non-empty. The client tests
///   `!!passwordHash`, so a marker with nothing between prefix and suffix is
///   not a gate. Both markers are ASCII, so comparing byte lengths is the
///   same test as the client's non-empty slice.
pub fn description_has_password_gate(description: Option<&str>) -> bool {
    let Some(line) = description.and_then(|description| description.split('\n').last()) else {
        return false;
    };

    line.len() > CHANNEL_PASSWORD_PREFIX.len() + CHANNEL_PASSWORD_SUFFIX.len()
        && line.starts_with(CHANNEL_PASSWORD_PREFIX)
        && line.ends_with(CHANNEL_PASSWORD_SUFFIX)
}

/// Whether a channel with these fields sits behind any client gate: age
/// (`nsfw`), spoiler, or password (in the description).
///
/// This is the client's `isChannelGated`
/// (`packages/client/src/interface/channels/channelGates.ts`, fed by
/// `isGatedFor` in the server sidebar) with every per-member unlock treated
/// as not granted. Whether a given member has passed a gate is client-side
/// layout state that the server never sees, so the server can only answer
/// "is there a gate at all". An age gate counts even though an attested
/// member would pass it: the attestation is not visible here either, so this
/// fails closed.
///
/// There is no other gate. Clients read no server-level `nsfw`, and
/// categories carry no gate that channels inherit.
pub fn client_gate_is_set(nsfw: bool, spoiler: bool, description: Option<&str>) -> bool {
    nsfw || spoiler || description_has_password_gate(description)
}

/// `create_thread`'s cleanup after a refused parent hold (W2 audit B1):
/// delete the just-inserted thread row, retrying once
///
/// A row left behind is a thread under a protected parent: the database
/// floor and the routes refuse plaintext into it, but it still names a
/// channel nobody can use, so every failed attempt is reported (ids only,
/// never the thread's name). Returns the last delete error if both fail.
async fn delete_refused_thread<F, Fut>(
    mut delete: F,
    thread_id: &str,
    parent_id: &str,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut attempt = 1;
    loop {
        match delete().await {
            Ok(()) => return Ok(()),
            Err(error) => {
                revolt_config::capture_message(
                    &format!(
                        "create_thread could not delete thread {thread_id} after its parent {parent_id} refused the hold (attempt {attempt} of 2)"
                    ),
                    revolt_config::Level::Error,
                );
                if attempt == 2 {
                    return Err(error);
                }
                attempt += 1;
            }
        }
    }
}

#[allow(clippy::disallowed_methods)]
impl Channel {
    /* /// Create a channel
    pub async fn create(&self, db: &Database) -> Result<()> {
        db.insert_channel(self).await?;

        let event = EventV1::ChannelCreate(self.clone().into());
        match self {
            Self::SavedMessages { user, .. } => event.private(user.clone()).await,
            Self::DirectMessage { recipients, .. } | Self::Group { recipients, .. } => {
                for recipient in recipients {
                    event.clone().private(recipient.clone()).await;
                }
            }
            Self::TextChannel { server, .. } | Self::VoiceChannel { server, .. } => {
                event.p(server.clone()).await;
            }
        }

        Ok(())
    }*/

    /// Create a new server channel
    pub async fn create_server_channel(
        db: &Database,
        server: &mut Server,
        data: v0::DataCreateServerChannel,
        update_server: bool,
    ) -> Result<Channel> {
        let config = config().await;
        if server.channels.len() > config.features.limits.global.server_channels {
            return Err(create_error!(TooManyChannels {
                max: config.features.limits.global.server_channels,
            }));
        };

        let id = ulid::Ulid::new().to_string();
        let channel = match data.channel_type {
            v0::LegacyServerChannelType::Text => Channel::TextChannel {
                id: id.clone(),
                server: server.id.to_owned(),
                name: data.name,
                description: data.description,
                icon: None,
                last_message_id: None,
                default_permissions: None,
                role_permissions: HashMap::new(),
                nsfw: data.nsfw.unwrap_or(false),
                spoiler: data.spoiler.unwrap_or(false),
                voice: data.voice.map(|voice| voice.into()),
                slowmode: None,
                announcement: data.announcement.filter(|v| *v),
                protected: false,
            },
            v0::LegacyServerChannelType::Voice => Channel::TextChannel {
                id: id.clone(),
                server: server.id.to_owned(),
                name: data.name,
                description: data.description,
                icon: None,
                last_message_id: None,
                default_permissions: None,
                role_permissions: HashMap::new(),
                nsfw: data.nsfw.unwrap_or(false),
                spoiler: data.spoiler.unwrap_or(false),
                voice: Some(data.voice.unwrap_or_default().into()),
                slowmode: None,
                announcement: None,
                protected: false,
            },
            v0::LegacyServerChannelType::Forum => Channel::Forum {
                id: id.clone(),
                server: server.id.to_owned(),
                name: data.name,
                description: data.description,
                icon: None,
                last_message_id: None,
                default_permissions: None,
                role_permissions: HashMap::new(),
                nsfw: data.nsfw.unwrap_or(false),
                spoiler: data.spoiler.unwrap_or(false),
                tags: vec![],
                require_tag: false,
                default_sort: ForumSortOrder::default(),
                force_sort: false,
                default_layout: ForumLayout::default(),
                default_auto_archive_minutes: Channel::default_forum_auto_archive_minutes(),
            },
        };

        db.insert_channel(&channel).await?;

        if update_server {
            server
                .update(
                    db,
                    PartialServer {
                        channels: Some([server.channels.clone(), [id].into()].concat()),
                        ..Default::default()
                    },
                    vec![],
                )
                .await?;

            EventV1::ChannelCreate(channel.clone().into())
                .p(server.id.clone())
                .await;
        }

        Ok(channel)
    }

    /// Default auto-archive duration for threads, in minutes
    pub fn default_auto_archive_minutes() -> u32 {
        1440
    }

    /// Default auto-archive duration for new forum posts, in minutes
    /// (used when a forum document predates the per-forum default)
    pub fn default_forum_auto_archive_minutes() -> u32 {
        10080
    }

    /// Sentinel auto-archive duration meaning the thread never auto-archives
    pub const AUTO_ARCHIVE_NEVER: u32 = 0;

    /// Longest auto-archive duration that can be set, in minutes.
    ///
    /// Two years, taking a year as 365 days: 2 * 365 * 24 * 60.
    pub const MAX_AUTO_ARCHIVE_MINUTES: u32 = 1_051_200;

    /// Whether `minutes` is an acceptable auto-archive duration.
    ///
    /// This replaced a fixed allow-list of seven values. Operators asked to be
    /// able to pick any duration between a minute and two years, so the set of
    /// legal values is now a range and the durations a client offers are a
    /// convenience rather than the contract. `0` stays the "never" sentinel,
    /// which is why it is admitted separately instead of widening the range
    /// down to zero.
    pub fn is_valid_auto_archive_minutes(minutes: u32) -> bool {
        minutes == Channel::AUTO_ARCHIVE_NEVER
            || (1..=Channel::MAX_AUTO_ARCHIVE_MINUTES).contains(&minutes)
    }

    /// Create a new thread under a server text channel
    ///
    /// This inserts the channel document directly — threads are intentionally
    /// NEVER pushed into `Server.channels`; clients discover them via the
    /// `parent_channel` pointer instead.
    pub async fn create_thread(
        db: &Database,
        parent: &Channel,
        creator: &User,
        origin_message: Option<&Message>,
        data: v0::DataCreateThread,
    ) -> Result<Channel> {
        // Threads may only exist under server text channels; this is also the
        // E2EE fail-closed gate (encrypted DMs / groups can never host one).
        let (parent_id, server_id) = match parent {
            Channel::TextChannel { id, server, .. } => (id.clone(), server.clone()),
            _ => return Err(create_error!(InvalidOperation)),
        };

        // Enforce the per-channel active thread cap.
        let config = config().await;
        let max_threads = config.features.limits.global.threads_per_channel;
        let active_threads = db
            .fetch_threads_by_parent(&parent_id)
            .await?
            .into_iter()
            .filter(|thread| !matches!(thread, Channel::Thread { archived: true, .. }))
            .count();
        if active_threads >= max_threads {
            return Err(create_error!(TooManyChannels { max: max_threads }));
        }

        // Validate the auto-archive duration.
        let auto_archive_minutes = data
            .auto_archive_minutes
            .unwrap_or_else(Channel::default_auto_archive_minutes);
        if !Channel::is_valid_auto_archive_minutes(auto_archive_minutes) {
            return Err(create_error!(InvalidProperty));
        }

        // Validate the origin message belongs to the parent channel and is not
        // already anchoring another thread.
        if let Some(message) = origin_message {
            if message.channel != parent_id {
                return Err(create_error!(InvalidOperation));
            }

            if message.thread_id.is_some() {
                return Err(create_error!(ThreadAlreadyExists));
            }
        }

        let id = Ulid::new().to_string();
        let channel = Channel::Thread {
            id: id.clone(),
            server: server_id.clone(),
            parent_channel: parent_id.clone(),
            name: data.name.clone(),
            creator: creator.id.clone(),
            origin_message_id: origin_message.map(|message| message.id.clone()),
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes,
            locked: false,
            applied_tags: vec![],
        };

        db.insert_channel(&channel).await?;

        // Hold the parent while it is not protected (decision 13 (W2)),
        // before anything else learns of the thread. A protect that read "no
        // threads" before the insert either conflicts with this hold and
        // then reads the thread, or has already committed, in which case the
        // hold refuses and the row is deleted again: no membership, no
        // event, no stamp, no system message. Bonfire caches every announced
        // thread, so an announcement ahead of the hold would leave a
        // plaintext-named thread under a protected parent until reconnect.
        if let Err(error) = db.hold_thread_parent_unprotected(&parent_id).await {
            delete_refused_thread(|| db.delete_channel(&channel), &id, &parent_id).await?;
            return Err(error);
        }

        // Auto-join the creator.
        db.join_thread_if_absent(&id, &creator.id).await?;

        // Everyone who can see the parent learns about the thread.
        EventV1::ChannelCreate(channel.clone().into())
            .p(server_id.clone())
            .await;

        // Stamp the origin message with the thread id (server-set only).
        if let Some(message) = origin_message {
            let mut message = message.clone();
            message
                .update(
                    db,
                    PartialMessage {
                        thread_id: Some(id.clone()),
                        ..Default::default()
                    },
                    vec![],
                )
                .await?;
        }

        // Post a system message linking the thread into the parent channel.
        SystemMessage::ThreadCreated {
            id: id.clone(),
            by: creator.id.clone(),
            name: data.name,
        }
        .into_message(parent_id)
        .send(
            db,
            None,
            MessageAuthor::System {
                username: &creator.username,
                avatar: creator.avatar.as_ref().map(|file| file.id.as_ref()),
            },
            None,
            None,
            parent,
            false,
        )
        .await
        .ok();

        Ok(channel)
    }

    /// Create a new post (thread) under a forum channel
    ///
    /// Like `create_thread` but for forum parents: no origin message, no
    /// system message into the parent (forums have no message stream), and
    /// the post carries its applied tag ids. The caller is responsible for
    /// creating the starter message and bumping the forum's activity marker.
    pub async fn create_forum_post(
        db: &Database,
        forum: &Channel,
        creator: &User,
        name: String,
        applied_tags: Vec<String>,
        auto_archive_minutes: Option<u32>,
    ) -> Result<Channel> {
        // Posts may only exist under forum channels; this is also the E2EE
        // fail-closed gate (encrypted DMs / groups can never host one).
        let (parent_id, server_id, forum_default_auto_archive_minutes) = match forum {
            Channel::Forum {
                id,
                server,
                default_auto_archive_minutes,
                ..
            } => (id.clone(), server.clone(), *default_auto_archive_minutes),
            _ => return Err(create_error!(InvalidOperation)),
        };

        // Forum posts are intentionally exempt from `threads_per_channel`
        // (user decision); the forum_post_create ratelimit bucket bounds spam.

        // Validate the auto-archive duration (falling back to the forum default).
        let auto_archive_minutes =
            auto_archive_minutes.unwrap_or(forum_default_auto_archive_minutes);
        if !Channel::is_valid_auto_archive_minutes(auto_archive_minutes) {
            return Err(create_error!(InvalidProperty));
        }

        let id = Ulid::new().to_string();
        let channel = Channel::Thread {
            id: id.clone(),
            server: server_id.clone(),
            parent_channel: parent_id,
            name,
            creator: creator.id.clone(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes,
            locked: false,
            applied_tags,
        };

        db.insert_channel(&channel).await?;

        // Auto-join the creator.
        db.join_thread_if_absent(&id, &creator.id).await?;

        // Everyone who can see the forum learns about the post.
        EventV1::ChannelCreate(channel.clone().into())
            .p(server_id)
            .await;

        Ok(channel)
    }

    /// Resolve the channel whose permission overrides apply to this channel.
    ///
    /// Threads delegate their entire permission calculus to their parent
    /// channel (text channel, or forum for forum posts); the parent MUST be
    /// resolved before constructing a `DatabasePermissionQuery` (never
    /// substituted mid-calculation). All other channel types are their own
    /// permission target. Fails closed (NotFound) when a thread's parent is
    /// missing or not a thread-capable channel.
    pub async fn permission_target<'a>(&'a self, db: &Database) -> Result<Cow<'a, Channel>> {
        match self {
            Channel::Thread { parent_channel, .. } => {
                let parent = db.fetch_channel(parent_channel).await?;
                if matches!(
                    parent,
                    Channel::TextChannel { .. } | Channel::Forum { .. }
                ) {
                    Ok(Cow::Owned(parent))
                } else {
                    Err(create_error!(NotFound))
                }
            }
            _ => Ok(Cow::Borrowed(self)),
        }
    }

    /// Create a group
    pub async fn create_group(
        db: &Database,
        mut data: v0::DataCreateGroup,
        owner_id: String,
    ) -> Result<Channel> {
        data.users.insert(owner_id.to_string());

        let config = config().await;
        if data.users.len() > config.features.limits.global.group_size {
            return Err(create_error!(GroupTooLarge {
                max: config.features.limits.global.group_size,
            }));
        }

        let id = ulid::Ulid::new().to_string();

        let icon = if let Some(icon_id) = data.icon {
            Some(File::use_channel_icon(db, &icon_id, &id, &owner_id).await?)
        } else {
            None
        };

        let recipients = data.users.into_iter().collect::<Vec<String>>();
        let channel = Channel::Group {
            id,

            name: data.name,
            owner: owner_id,
            description: data.description,
            recipients: recipients.clone(),

            icon,
            last_message_id: None,

            permissions: None,

            nsfw: data.nsfw.unwrap_or(false),
            spoiler: data.spoiler.unwrap_or(false),

            voice: None,
        };

        db.insert_channel(&channel).await?;

        let event = EventV1::ChannelCreate(channel.clone().into());
        for recipient in recipients {
            event.clone().private(recipient).await;
        }

        Ok(channel)
    }

    /// Create a DM (or return the existing one / saved messages)
    pub async fn create_dm(db: &Database, user_a: &User, user_b: &User) -> Result<Channel> {
        // Try to find existing channel
        if let Ok(channel) = db.find_direct_message_channel(&user_a.id, &user_b.id).await {
            Ok(channel)
        } else {
            let channel = if user_a.id == user_b.id {
                // Create a new saved messages channel
                Channel::SavedMessages {
                    id: Ulid::new().to_string(),
                    user: user_a.id.to_string(),
                }
            } else {
                // Create a new DM channel
                Channel::DirectMessage {
                    id: Ulid::new().to_string(),
                    active: true, // show by default
                    recipients: vec![user_a.id.clone(), user_b.id.clone()],
                    last_message_id: None,
                }
            };

            db.insert_channel(&channel).await?;

            if let Channel::DirectMessage { .. } = &channel {
                let event = EventV1::ChannelCreate(channel.clone().into());
                event.clone().private(user_a.id.clone()).await;
                event.private(user_b.id.clone()).await;
            };

            Ok(channel)
        }
    }

    /// Add user to a group
    pub async fn add_user_to_group(
        &mut self,
        db: &Database,
        amqp: &AMQP,
        user: &User,
        by_id: &str,
    ) -> Result<()> {
        if let Channel::Group { recipients, .. } = self {
            if recipients.contains(&String::from(&user.id)) {
                return Err(create_error!(AlreadyInGroup));
            }

            let config = config().await;
            if recipients.len() >= config.features.limits.global.group_size {
                return Err(create_error!(GroupTooLarge {
                    max: config.features.limits.global.group_size
                }));
            }

            recipients.push(String::from(&user.id));
        }

        match &self {
            Channel::Group { id, .. } => {
                db.add_user_to_group(id, &user.id).await?;

                EventV1::ChannelGroupJoin {
                    id: id.to_string(),
                    user: user.id.to_string(),
                }
                .p(id.to_string())
                .await;

                SystemMessage::UserAdded {
                    id: user.id.to_string(),
                    by: by_id.to_string(),
                }
                .into_message(id.to_string())
                .send(
                    db,
                    Some(amqp),
                    MessageAuthor::System {
                        username: &user.username,
                        avatar: user.avatar.as_ref().map(|file| file.id.as_ref()),
                    },
                    None,
                    None,
                    self,
                    false,
                )
                .await
                .ok();

                EventV1::ChannelCreate(self.clone().into())
                    .private(user.id.to_string())
                    .await;

                Ok(())
            }
            _ => Err(create_error!(InvalidOperation)),
        }
    }

    /// Map out whether it is a direct DM
    pub fn is_direct_dm(&self) -> bool {
        matches!(self, Channel::DirectMessage { .. })
    }

    /// Check whether has a user as a recipient
    pub fn contains_user(&self, user_id: &str) -> bool {
        match self {
            Channel::Group { recipients, .. } | Channel::DirectMessage { recipients, .. } => {
                recipients.iter().any(|recipient| recipient == user_id)
            }
            Channel::SavedMessages { user, .. } => user == user_id,
            _ => false,
        }
    }

    /// Get list of recipients
    pub fn users(&self) -> Result<Vec<String>> {
        match self {
            Channel::Group { recipients, .. } | Channel::DirectMessage { recipients, .. } => {
                Ok(recipients.to_owned())
            }
            _ => Err(create_error!(NotFound)),
        }
    }

    /// Clone this channel's id
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

    /// Clone this channel's server id
    pub fn server(&self) -> Option<&str> {
        match self {
            Channel::TextChannel { server, .. }
            | Channel::Thread { server, .. }
            | Channel::Forum { server, .. } => Some(server),
            _ => None,
        }
    }

    /// Whether this is a protected (end-to-end encrypted) channel. Only a
    /// server `TextChannel` can be one; every other variant answers `false`.
    pub fn is_protected(&self) -> bool {
        matches!(
            self,
            Channel::TextChannel {
                protected: true,
                ..
            }
        )
    }

    /// Hold the protected-channel invariants (design 2.1, 7.4) over a
    /// partial before `update` applies or writes any of it, and return the
    /// partial to write.
    ///
    /// - `protected: Some(false)` on a protected channel is refused
    ///   (`ChannelProtected`). On any other channel the flag is already
    ///   false, so it is dropped rather than written: a caller holding a
    ///   stale copy must never write false over a concurrent protect.
    /// - `protected: Some(true)` is refused (`InvalidOperation`, as the
    ///   protect route) unless this is a server `TextChannel` with no voice
    ///   that is not an announcement channel.
    /// - A channel that is, or becomes, protected refuses any `voice` and
    ///   `announcement: Some(true)` (`ChannelProtected`).
    fn guard_protected_partial(&self, mut partial: PartialChannel) -> Result<PartialChannel> {
        let requested = partial.protected;
        match requested {
            Some(false) if self.is_protected() => return Err(create_error!(ChannelProtected)),
            Some(false) => partial.protected = None,
            Some(true) => match self {
                Channel::TextChannel {
                    voice: None,
                    announcement,
                    ..
                } if *announcement != Some(true) => {}
                _ => return Err(create_error!(InvalidOperation)),
            },
            None => {}
        }

        let protected_after = self.is_protected() || partial.protected == Some(true);
        if protected_after && partial.sets_field_refused_on_protected() {
            return Err(create_error!(ChannelProtected));
        }

        Ok(partial)
    }

    /// Gets this channel's voice information
    pub fn voice(&self) -> Option<Cow<VoiceInformation>> {
        match self {
            // DMs are always call-capable.
            Self::DirectMessage { .. } => Some(Cow::Owned(VoiceInformation::default())),
            // Groups have calling ON by default: an unconfigured group is
            // call-capable with no limit. An owner may set limits via max_users,
            // and setting `disabled` turns calling off while keeping any saved
            // configuration.
            Self::Group { voice, .. } => match voice {
                None => Some(Cow::Owned(VoiceInformation::default())),
                Some(voice) if !voice.disabled => Some(Cow::Borrowed(voice)),
                Some(_) => None,
            },
            // Server channels are voice channels only when voice info is present
            // and not explicitly disabled.
            Self::TextChannel {
                voice: Some(voice), ..
            } if !voice.disabled => Some(Cow::Borrowed(voice)),
            _ => None,
        }
    }

    /// Whether clients put this channel behind an age, spoiler or password
    /// gate: [`client_gate_is_set`] over the channel's own fields.
    ///
    /// - A thread has no gate fields of its own. The client gates it by its
    ///   PARENT's (`gateSource` in `channelGates.ts`), which is not in hand
    ///   here, so a thread answers `true`: fail closed. No current caller
    ///   needs a thread to pass, because a thread is never a voice channel.
    /// - DMs and saved messages carry no gate fields and no client gates
    ///   them.
    ///
    /// Written without a wildcard arm, so a new channel variant has to decide.
    pub fn has_client_gate(&self) -> bool {
        match self {
            Channel::Group {
                nsfw,
                spoiler,
                description,
                ..
            }
            | Channel::TextChannel {
                nsfw,
                spoiler,
                description,
                ..
            }
            | Channel::Forum {
                nsfw,
                spoiler,
                description,
                ..
            } => client_gate_is_set(*nsfw, *spoiler, description.as_deref()),
            Channel::Thread { .. } => true,
            Channel::DirectMessage { .. } | Channel::SavedMessages { .. } => false,
        }
    }

    /// Set role permission on a channel
    pub async fn set_role_permission(
        &mut self,
        db: &Database,
        role_id: &str,
        permissions: OverrideField,
    ) -> Result<()> {
        match self {
            Channel::TextChannel {
                id,
                server,
                role_permissions,
                ..
            }
            | Channel::Forum {
                id,
                server,
                role_permissions,
                ..
            } => {
                db.set_channel_role_permission(id, role_id, permissions)
                    .await?;

                role_permissions.insert(role_id.to_string(), permissions);

                EventV1::ChannelUpdate {
                    id: id.clone(),
                    data: PartialChannel {
                        role_permissions: Some(role_permissions.clone()),
                        ..Default::default()
                    }
                    .into(),
                    clear: vec![],
                }
                .p(server.clone())
                .await;

                Ok(())
            }
            _ => Err(create_error!(InvalidOperation)),
        }
    }

    /// Update channel data
    pub async fn update(
        &mut self,
        db: &Database,
        partial: PartialChannel,
        remove: Vec<FieldsChannel>,
    ) -> Result<()> {
        // Before anything is mutated, written or broadcast.
        let partial = self.guard_protected_partial(partial)?;

        for field in &remove {
            self.remove_field(field);
        }

        self.apply_options(partial.clone());

        let id = self.id().to_string();
        db.update_channel(&id, &partial, remove.clone()).await?;

        EventV1::ChannelUpdate {
            id: id.clone(),
            data: partial.into(),
            clear: remove.into_iter().map(|v| v.into()).collect(),
        }
        .p(match self {
            Self::TextChannel { server, .. }
            | Self::Thread { server, .. }
            | Self::Forum { server, .. } => server.clone(),
            _ => id,
        })
        .await;

        Ok(())
    }

    /// Remove a field from Channel object
    pub fn remove_field(&mut self, field: &FieldsChannel) {
        match field {
            FieldsChannel::Description => match self {
                Self::Group { description, .. }
                | Self::TextChannel { description, .. }
                | Self::Forum { description, .. } => {
                    description.take();
                }
                _ => {}
            },
            FieldsChannel::Icon => match self {
                Self::Group { icon, .. }
                | Self::TextChannel { icon, .. }
                | Self::Forum { icon, .. } => {
                    icon.take();
                }
                _ => {}
            },
            FieldsChannel::DefaultPermissions => match self {
                Self::TextChannel {
                    default_permissions,
                    ..
                }
                | Self::Forum {
                    default_permissions,
                    ..
                } => {
                    default_permissions.take();
                }
                _ => {}
            },
            FieldsChannel::Voice => match self {
                Self::Group { voice, .. } | Self::TextChannel { voice, .. } => {
                    voice.take();
                }
                _ => {}
            },
            FieldsChannel::Tags => match self {
                Self::Forum { tags, .. } => {
                    tags.clear();
                }
                _ => {}
            },
        }
    }

    /// Remove multiple fields from Channel object
    pub fn remove_fields(&mut self, partial: Vec<FieldsChannel>) {
        for field in partial {
            self.remove_field(&field)
        }
    }

    /// Apply partial channel to channel
    #[allow(deprecated)]
    pub fn apply_options(&mut self, partial: PartialChannel) {
        match self {
            Self::SavedMessages { .. } => {}
            Self::DirectMessage { active, .. } => {
                if let Some(v) = partial.active {
                    *active = v;
                }
            }
            Self::Group {
                name,
                owner,
                description,
                icon,
                nsfw,
                spoiler,
                permissions,
                voice,
                ..
            } => {
                if let Some(v) = partial.name {
                    *name = v;
                }

                if let Some(v) = partial.owner {
                    *owner = v;
                }

                if let Some(v) = partial.description {
                    description.replace(v);
                }

                if let Some(v) = partial.icon {
                    icon.replace(v);
                }

                if let Some(v) = partial.nsfw {
                    *nsfw = v;
                }

                if let Some(v) = partial.spoiler {
                    *spoiler = v;
                }

                if let Some(v) = partial.permissions {
                    permissions.replace(v);
                }

                if let Some(v) = partial.voice {
                    voice.replace(v);
                }
            }
            Self::TextChannel {
                name,
                description,
                icon,
                nsfw,
                spoiler,
                default_permissions,
                role_permissions,
                voice,
                slowmode,
                announcement,
                protected,
                ..
            } => {
                if let Some(v) = partial.name {
                    *name = v;
                }

                if let Some(v) = partial.description {
                    description.replace(v);
                }

                if let Some(v) = partial.icon {
                    icon.replace(v);
                }

                if let Some(v) = partial.nsfw {
                    *nsfw = v;
                }

                if let Some(v) = partial.spoiler {
                    *spoiler = v;
                }

                if let Some(v) = partial.role_permissions {
                    *role_permissions = v;
                }

                if let Some(v) = partial.default_permissions {
                    default_permissions.replace(v);
                }

                if let Some(v) = partial.voice {
                    voice.replace(v);
                }

                if let Some(v) = partial.slowmode {
                    slowmode.replace(v);
                }

                if let Some(v) = partial.announcement {
                    *announcement = Some(v);
                }

                // One-way (design 2.1): a partial can raise the flag, never
                // lower it.
                if partial.protected == Some(true) {
                    *protected = true;
                }
            }
            Self::Thread {
                name,
                archived,
                archived_timestamp,
                last_message_id,
                auto_archive_minutes,
                applied_tags,
                ..
            } => {
                if let Some(v) = partial.name {
                    *name = v;
                }

                if let Some(v) = partial.archived {
                    *archived = v;
                }

                if let Some(v) = partial.archived_timestamp {
                    archived_timestamp.replace(v);
                }

                if let Some(v) = partial.last_message_id {
                    last_message_id.replace(v);
                }

                if let Some(v) = partial.auto_archive_minutes {
                    *auto_archive_minutes = v;
                }

                if let Some(v) = partial.applied_tags {
                    *applied_tags = v;
                }
            }
            Self::Forum {
                name,
                description,
                icon,
                nsfw,
                spoiler,
                default_permissions,
                role_permissions,
                last_message_id,
                tags,
                require_tag,
                default_sort,
                force_sort,
                default_layout,
                default_auto_archive_minutes,
                ..
            } => {
                if let Some(v) = partial.name {
                    *name = v;
                }

                if let Some(v) = partial.description {
                    description.replace(v);
                }

                if let Some(v) = partial.icon {
                    icon.replace(v);
                }

                if let Some(v) = partial.nsfw {
                    *nsfw = v;
                }

                if let Some(v) = partial.spoiler {
                    *spoiler = v;
                }

                if let Some(v) = partial.role_permissions {
                    *role_permissions = v;
                }

                if let Some(v) = partial.default_permissions {
                    default_permissions.replace(v);
                }

                if let Some(v) = partial.last_message_id {
                    last_message_id.replace(v);
                }

                if let Some(v) = partial.tags {
                    *tags = v;
                }

                if let Some(v) = partial.require_tag {
                    *require_tag = v;
                }

                if let Some(v) = partial.default_sort {
                    *default_sort = v;
                }

                if let Some(v) = partial.force_sort {
                    *force_sort = v;
                }

                if let Some(v) = partial.default_layout {
                    *default_layout = v;
                }

                if let Some(v) = partial.default_auto_archive_minutes {
                    *default_auto_archive_minutes = v;
                }
            }
        }
    }

    /// Acknowledge a message
    pub async fn ack(&self, user: &str, message: &str, amqp: &AMQP) -> Result<()> {
        EventV1::ChannelAck {
            id: self.id().to_string(),
            user: user.to_string(),
            message_id: message.to_string(),
        }
        .private(user.to_string())
        .await;

        crate::util::acker::ack_channel(user, self.id(), message, amqp).await
    }

    /// Remove user from a group
    pub async fn remove_user_from_group(
        &self,
        db: &Database,
        amqp: &AMQP,
        user: &User,
        by_id: Option<&str>,
        silent: bool,
    ) -> Result<()> {
        match &self {
            Channel::Group {
                id,
                name,
                owner,
                recipients,
                ..
            } => {
                if &user.id == owner {
                    if let Some(new_owner) = recipients.iter().find(|x| *x != &user.id) {
                        db.update_channel(
                            id,
                            &PartialChannel {
                                owner: Some(new_owner.into()),
                                ..Default::default()
                            },
                            vec![],
                        )
                        .await?;

                        SystemMessage::ChannelOwnershipChanged {
                            from: owner.to_string(),
                            to: new_owner.to_string(),
                        }
                        .into_message(id.to_string())
                        .send(
                            db,
                            Some(amqp),
                            MessageAuthor::System {
                                username: name,
                                avatar: None,
                            },
                            None,
                            None,
                            self,
                            false,
                        )
                        .await
                        .ok();
                    } else {
                        return self.delete(db).await;
                    }
                }

                db.remove_user_from_group(id, &user.id).await?;

                EventV1::ChannelGroupLeave {
                    id: id.to_string(),
                    user: user.id.to_string(),
                }
                .p(id.to_string())
                .await;

                if !silent {
                    if let Some(by) = by_id {
                        SystemMessage::UserRemove {
                            id: user.id.to_string(),
                            by: by.to_string(),
                        }
                    } else {
                        SystemMessage::UserLeft {
                            id: user.id.to_string(),
                        }
                    }
                    .into_message(id.to_string())
                    .send(
                        db,
                        Some(amqp),
                        MessageAuthor::System {
                            username: &user.username,
                            avatar: user.avatar.as_ref().map(|file| file.id.as_ref()),
                        },
                        None,
                        None,
                        self,
                        false,
                    )
                    .await
                    .ok();
                }

                Ok(())
            }

            _ => Err(create_error!(InvalidOperation)),
        }
    }

    /// Delete a channel
    pub async fn delete(&self, db: &Database) -> Result<()> {
        let id = self.id().to_string();

        // Cascade: deleting a text or forum channel deletes its child threads
        // first, so no thread is ever orphaned with a dangling parent_channel
        // pointer.
        if let Channel::TextChannel { server, .. } | Channel::Forum { server, .. } = self {
            for thread in db.fetch_threads_by_parent(&id).await? {
                let thread_id = thread.id().to_string();
                db.delete_all_thread_memberships(&thread_id).await?;
                // Polls live per-channel; a thread's polls die with it.
                db.delete_polls_for_channel(&thread_id).await?;
                // So do its soft-res sheets and their reserves.
                db.delete_softres_for_channel(&thread_id).await?;
                // Pending scheduled messages die with it too — cancel them
                // loudly so authors' pending lists stay accurate.
                crate::ScheduledMessage::cancel_all_for_channel(db, &thread_id).await?;

                EventV1::ChannelDelete {
                    id: thread_id.clone(),
                }
                .p(server.clone())
                .await;
                EventV1::ChannelDelete { id: thread_id }
                    .p(thread.id().to_string())
                    .await;

                db.delete_channel(&thread).await?;
            }
        }

        // Deleting a thread removes its membership rows.
        if let Channel::Thread { .. } = self {
            db.delete_all_thread_memberships(&id).await?;
        }

        // Cascade: deleting a channel deletes its polls and their ballots
        // (messages are dropped wholesale, so no per-message cascade runs).
        db.delete_polls_for_channel(&id).await?;

        // Cascade: same rule for soft-res sheets and their reserves.
        db.delete_softres_for_channel(&id).await?;

        // Cascade: pending scheduled messages are cancelled (not fired into
        // a missing channel), their claimed attachments released, and each
        // author notified on their private topic.
        crate::ScheduledMessage::cancel_all_for_channel(db, &id).await?;

        // Cascade: sever announcement follows on BOTH sides (a deleted source
        // loses its followers + their target webhooks; a deleted follower
        // target loses its follows + orphaned webhooks) so nothing can keep
        // injecting crosspost copies.
        crate::ChannelFollow::cleanup_for_deleted_channel(db, &id).await?;

        // Cascade: a channel that is its server's designated AFK channel takes
        // the designation with it. The pointer lives on the SERVER document, so
        // delete_channel has no way to notice; left behind it names a channel
        // that no longer exists, and the idle sweep would move members into
        // nothing. Scoped to TextChannel because that is the only variant that
        // can carry voice information, and so the only one that can ever be
        // designated; the helper no-ops unless the pointer is this channel.
        //
        // Deliberately ABOVE the driver split: Reference::delete_channel does
        // almost none of MongoDb::delete_channel's cleanup (it does not even
        // pull the id out of Server.channels), so a driver-level clear would
        // pass under TEST_DB=MONGODB and silently do nothing under REFERENCE.
        //
        // Runs before the ChannelDelete broadcast and before db.delete_channel,
        // like the cascades above, so a failure aborts the deletion without
        // having announced it.
        if let Channel::TextChannel { server, .. } = self {
            Server::clear_afk_channel_if_pointing_at(db, server, &id).await?;
        }

        // Cascade: the channel's protected data (entitlement, seats, seat
        // list, Text groups closed, their commits and join intents; design
        // 7.5, decision 12 (W2)). Every TextChannel, protected or not: an
        // entitlement is granted before the channel is protected, and may
        // never be used. Last before the broadcast and the row delete, so a
        // failure leaves the channel in place and unannounced, and the
        // delete can be retried.
        if let Channel::TextChannel { .. } = self {
            db.delete_protected_channel_data(&id).await?;
        }

        EventV1::ChannelDelete { id: id.clone() }.p(id).await;
        // TODO: missing functionality:
        // - group invites
        // - channels list / categories list on server
        db.delete_channel(self).await
    }
}

#[cfg(feature = "mongodb")]
impl IntoDocumentPath for FieldsChannel {
    fn as_path(&self) -> Option<&'static str> {
        Some(match self {
            FieldsChannel::Description => "description",
            FieldsChannel::Icon => "icon",
            FieldsChannel::DefaultPermissions => "default_permissions",
            FieldsChannel::Voice => "voice",
            FieldsChannel::Tags => "tags",
        })
    }
}

#[cfg(test)]
mod tests {
    use revolt_permissions::{calculate_channel_permissions, ChannelPermission};

    use crate::{fixture, util::permissions::DatabasePermissionQuery};

    #[tokio::test]
    async fn permissions_group_channel() {
        database_test!(|db| async move {
            fixture!(db, "group_with_members",
                owner user 0
                member1 user 1
                member2 user 2
                channel channel 3);

            let mut query = DatabasePermissionQuery::new(&db, &owner).channel(&channel);
            assert!(calculate_channel_permissions(&mut query)
                .await
                .has_channel_permission(ChannelPermission::SendMessage));

            let mut query = DatabasePermissionQuery::new(&db, &member1).channel(&channel);
            assert!(calculate_channel_permissions(&mut query)
                .await
                .has_channel_permission(ChannelPermission::SendMessage));

            let mut query = DatabasePermissionQuery::new(&db, &member2).channel(&channel);
            assert!(!calculate_channel_permissions(&mut query)
                .await
                .has_channel_permission(ChannelPermission::SendMessage));
        });
    }

    #[tokio::test]
    async fn permissions_text_channel() {
        database_test!(|db| async move {
            fixture!(db, "server_with_roles",
                owner user 0
                moderator user 1
                user user 2
                channel channel 3);

            let mut query = DatabasePermissionQuery::new(&db, &owner).channel(&channel);
            assert!(calculate_channel_permissions(&mut query)
                .await
                .has_channel_permission(ChannelPermission::SendMessage));

            let mut query = DatabasePermissionQuery::new(&db, &moderator).channel(&channel);
            assert!(calculate_channel_permissions(&mut query)
                .await
                .has_channel_permission(ChannelPermission::SendMessage));

            let mut query = DatabasePermissionQuery::new(&db, &user).channel(&channel);
            assert!(!calculate_channel_permissions(&mut query)
                .await
                .has_channel_permission(ChannelPermission::SendMessage));
        });
    }

    #[test]
    fn group_voice_calling_toggle() {
        use crate::{Channel, VoiceInformation};

        let group = |voice| Channel::Group {
            id: "0".to_string(),
            name: "test".to_string(),
            owner: "1".to_string(),
            description: None,
            recipients: vec![],
            icon: None,
            last_message_id: None,
            permissions: None,
            nsfw: false,
            spoiler: false,
            voice,
        };

        // Default group (unconfigured): calling is ON with no limit.
        assert!(group(None).voice().is_some());
        assert_eq!(group(None).voice().unwrap().max_users, None);

        // Clients decide whether to show calls from the `voice` object on the
        // wire, so an unconfigured group must still carry one.
        match revolt_models::v0::Channel::from(group(None)) {
            revolt_models::v0::Channel::Group { voice, .. } => {
                let voice = voice.expect("an unconfigured group reports voice");
                assert!(!voice.disabled);
                assert_eq!(voice.max_users, None);
            }
            _ => unreachable!(),
        }

        // A group whose owner turned calling off reports it as disabled.
        match revolt_models::v0::Channel::from(group(Some(VoiceInformation {
            max_users: None,
            disabled: true,
        }))) {
            revolt_models::v0::Channel::Group { voice, .. } => {
                assert!(voice.expect("a disabled group reports voice").disabled);
            }
            _ => unreachable!(),
        }

        // Owner configures calling explicitly (no limit).
        let enabled = group(Some(VoiceInformation {
            max_users: None,
            disabled: false,
        }));
        assert!(enabled.voice().is_some());
        assert_eq!(enabled.voice().unwrap().max_users, None);

        // On, with a participant limit surfaced to join_call.
        let limited = group(Some(VoiceInformation {
            max_users: Some(5),
            disabled: false,
        }));
        assert_eq!(limited.voice().unwrap().max_users, Some(5));

        // Explicitly disabled (config preserved): not call-capable.
        let off = group(Some(VoiceInformation {
            max_users: Some(5),
            disabled: true,
        }));
        assert!(off.voice().is_none());
    }

    // ---- Protected channels (design 2.1, 7.4) ------------------------------

    fn text_channel(protected: bool) -> crate::Channel {
        crate::Channel::TextChannel {
            id: "T".to_string(),
            server: "S".to_string(),
            name: "text".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: std::collections::HashMap::new(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected,
        }
    }

    fn refused_with(
        result: revolt_result::Result<crate::PartialChannel>,
        want: fn(&revolt_result::ErrorType) -> bool,
    ) -> bool {
        matches!(result, Err(error) if want(&error.error_type))
    }

    /// The flag is one-way: `Some(false)` on a protected channel is refused
    /// with `ChannelProtected`, and `apply_options` never lowers it.
    ///
    /// Controls: the `Some(false) if self.is_protected()` arm removed (the
    /// refusal), `*protected = v` in place of the raise-only apply.
    #[test]
    fn protected_flag_is_one_way() {
        use crate::PartialChannel;
        use revolt_result::ErrorType;

        let lower = || PartialChannel {
            protected: Some(false),
            ..Default::default()
        };

        let protected = text_channel(true);
        assert!(protected.is_protected());
        assert!(refused_with(
            protected.guard_protected_partial(lower()),
            |e| matches!(e, ErrorType::ChannelProtected)
        ));

        // Not protected: false is already the value, and is dropped rather
        // than written over a possibly concurrent protect.
        let open = text_channel(false);
        assert!(!open.is_protected());
        let written = open.guard_protected_partial(lower()).expect("no-op");
        assert_eq!(written.protected, None);

        // Raising is idempotent on a protected channel.
        let raise = || PartialChannel {
            protected: Some(true),
            ..Default::default()
        };
        assert_eq!(
            protected
                .guard_protected_partial(raise())
                .unwrap()
                .protected,
            Some(true)
        );

        // apply_options raises and never lowers.
        let mut channel = text_channel(false);
        channel.apply_options(raise());
        assert!(channel.is_protected());
        channel.apply_options(lower());
        assert!(channel.is_protected(), "apply_options lowered the flag");
    }

    /// Only a server `TextChannel` with no voice that is not an announcement
    /// channel can be protected, and a protected channel takes no voice and
    /// no announcement flag.
    ///
    /// Controls: the `voice: None` pattern widened to `..`, the
    /// `protected_after` check removed.
    #[test]
    fn protected_flag_kind_and_field_rules() {
        use crate::{Channel, PartialChannel, VoiceInformation};
        use revolt_result::ErrorType;

        let raise = || PartialChannel {
            protected: Some(true),
            ..Default::default()
        };
        let invalid = |e: &ErrorType| matches!(e, ErrorType::InvalidOperation);
        let refused = |e: &ErrorType| matches!(e, ErrorType::ChannelProtected);

        assert!(text_channel(false).guard_protected_partial(raise()).is_ok());

        let mut voiced = text_channel(false);
        if let Channel::TextChannel { voice, .. } = &mut voiced {
            *voice = Some(VoiceInformation::default());
        }
        assert!(refused_with(
            voiced.guard_protected_partial(raise()),
            invalid
        ));

        let mut announcing = text_channel(false);
        if let Channel::TextChannel { announcement, .. } = &mut announcing {
            *announcement = Some(true);
        }
        assert!(refused_with(
            announcing.guard_protected_partial(raise()),
            invalid
        ));

        let group = Channel::Group {
            id: "G".to_string(),
            name: "group".to_string(),
            owner: "O".to_string(),
            description: None,
            recipients: vec![],
            icon: None,
            last_message_id: None,
            permissions: None,
            nsfw: false,
            spoiler: false,
            voice: None,
        };
        assert!(!group.is_protected());
        assert!(refused_with(
            group.guard_protected_partial(raise()),
            invalid
        ));

        let dm = Channel::DirectMessage {
            id: "D".to_string(),
            active: true,
            recipients: vec![],
            last_message_id: None,
        };
        assert!(refused_with(dm.guard_protected_partial(raise()), invalid));

        let add_voice = || PartialChannel {
            voice: Some(VoiceInformation::default()),
            ..Default::default()
        };
        let add_announcement = || PartialChannel {
            announcement: Some(true),
            ..Default::default()
        };
        let protected = text_channel(true);
        assert!(refused_with(
            protected.guard_protected_partial(add_voice()),
            refused
        ));
        assert!(refused_with(
            protected.guard_protected_partial(add_announcement()),
            refused
        ));
        // Protecting and adding voice in one partial is refused too.
        assert!(refused_with(
            text_channel(false).guard_protected_partial(PartialChannel {
                protected: Some(true),
                voice: Some(VoiceInformation::default()),
                ..Default::default()
            }),
            refused
        ));
        // An unprotected channel keeps both edits.
        assert!(text_channel(false)
            .guard_protected_partial(add_voice())
            .is_ok());
        assert!(text_channel(false)
            .guard_protected_partial(add_announcement())
            .is_ok());
    }

    /// The stored shape: absent when false (existing documents need no
    /// migration), `true` when set.
    #[test]
    fn protected_flag_serde() {
        let open = serde_json::to_value(text_channel(false)).unwrap();
        assert!(open.get("protected").is_none(), "{open}");
        let back: crate::Channel = serde_json::from_value(open).unwrap();
        assert!(!back.is_protected());

        let set = serde_json::to_value(text_channel(true)).unwrap();
        assert_eq!(set.get("protected"), Some(&serde_json::Value::Bool(true)));
        let back: crate::Channel = serde_json::from_value(set).unwrap();
        assert!(back.is_protected());
    }

    /// The voice / announcement refusal holds against the STORED channel,
    /// not only the caller's copy: an edit holding a stale, unprotected copy
    /// of a channel that was protected meanwhile is refused by the write
    /// itself, and nothing is written. Runs on whichever driver `TEST_DB`
    /// names.
    ///
    /// Controls: the `"protected": { "$ne": true }` filter dropped
    /// (MongoDB), the `is_protected()` re-check dropped (Reference).
    #[tokio::test]
    async fn protected_refusal_holds_against_a_stale_copy() {
        database_test!(|db| async move {
            use crate::{PartialChannel, VoiceInformation};
            use revolt_result::ErrorType;

            let add_voice = || PartialChannel {
                voice: Some(VoiceInformation::default()),
                ..Default::default()
            };
            let add_announcement = || PartialChannel {
                announcement: Some(true),
                ..Default::default()
            };

            // Unprotected: both edits still go through.
            let mut open = text_channel(false);
            db.insert_channel(&open).await.expect("insert");
            open.update(&db, add_voice(), vec![])
                .await
                .expect("voice on an unprotected channel");
            let stored = db.fetch_channel("T").await.expect("fetch");
            assert!(stored.voice().is_some(), "{stored:?}");

            // A second channel. The caller's copy is taken before it is
            // protected; the protect lands in the store only.
            let mut stale = text_channel(false);
            if let crate::Channel::TextChannel { id, .. } = &mut stale {
                *id = "P".to_string();
            }
            db.insert_channel(&stale).await.expect("insert");
            db.update_channel(
                "P",
                &PartialChannel {
                    protected: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("protect");
            assert!(!stale.is_protected(), "the caller's copy is stale");

            for partial in [add_voice(), add_announcement()] {
                let result = stale.clone().update(&db, partial.clone(), vec![]).await;
                assert!(
                    matches!(
                        &result,
                        Err(error) if matches!(error.error_type, ErrorType::ChannelProtected)
                    ),
                    "{partial:?} on a stored-protected channel: {result:?}"
                );
            }

            let stored = db.fetch_channel("P").await.expect("fetch");
            assert!(stored.is_protected(), "{stored:?}");
            let crate::Channel::TextChannel {
                voice,
                announcement,
                ..
            } = &stored
            else {
                panic!("{stored:?}");
            };
            assert_eq!(voice, &None, "voice was written");
            assert_ne!(announcement, &Some(true), "announcement was written");
        });
    }

    // ---- Protected channels: thread race and delete cascade (W2) -----------

    /// The signer's device in every seat list below
    const PC_DEVICE: &str = "00112233445566778899aabbccddeeff";

    fn pc_user(n: u32) -> String {
        format!("01HZX{n:021}")
    }

    fn pc_channel_id(n: u32) -> String {
        format!("01J9Z3K4M5N6P7Q8R9S0T{n:05}")
    }

    /// Fixed, whole-millisecond time (Mongo stores Int64 milliseconds)
    fn pc_now() -> iso8601_timestamp::Timestamp {
        iso8601_timestamp::Timestamp::UNIX_EPOCH
            .checked_add(iso8601_timestamp::Duration::milliseconds(1_790_812_800_000))
            .unwrap()
    }

    /// `server_id`, owned by `owner` (protect claims it), with `owner` as a
    /// member (protect claims the membership of every seated user)
    async fn pc_server(db: &crate::Database, server_id: &str, owner: &str) {
        use crate::{Member, MemberCompositeKey, Server};

        let server: Server = serde_json::from_value(serde_json::json!({
            "_id": server_id,
            "owner": owner,
            "name": "protected",
            "channels": [],
            "default_permissions": 0,
        }))
        .unwrap();
        db.insert_server(&server).await.unwrap();
        db.insert_or_merge_member(&Member {
            id: MemberCompositeKey {
                server: server_id.to_string(),
                user: owner.to_string(),
            },
            ..Default::default()
        })
        .await
        .unwrap();
    }

    /// An unprotected TextChannel of `server_id` with an active entitlement
    async fn pc_entitled_channel(db: &crate::Database, channel_id: &str, server_id: &str) {
        use crate::{ChannelEntitlement, ChannelEntitlementSource, ChannelEntitlementState};

        let mut channel = text_channel(false);
        if let crate::Channel::TextChannel { id, server, .. } = &mut channel {
            *id = channel_id.to_string();
            *server = server_id.to_string();
        }
        db.insert_channel(&channel).await.unwrap();
        db.upsert_channel_entitlement(
            &ChannelEntitlement {
                id: ulid::Ulid::new().to_string(),
                channel_id: channel_id.to_string(),
                server_id: server_id.to_string(),
                source: ChannelEntitlementSource::AdminGrant,
                slot_cap: 10,
                device_cap: None,
                state: ChannelEntitlementState::Active,
                granted_by: "admin".to_string(),
                created_at: pc_now(),
            },
            pc_now(),
        )
        .await
        .unwrap();
    }

    /// The genesis seat list of `channel_id`, seating only its signer
    /// `owner` (the database layer checks the signature's encoding only)
    fn pc_genesis(channel_id: &str, owner: &str) -> crate::SeatListSubmission {
        crate::SeatListSubmission {
            body: crate::SeatListBody {
                channel_id: channel_id.to_string(),
                version: 1,
                device_cap: 5,
                issued_at: 1_790_812_800_000,
                signer_user_id: owner.to_string(),
                signer_device_id: PC_DEVICE.to_string(),
                seats: vec![owner.to_string()],
            }
            .build()
            .unwrap(),
            signature: format!("B{}", "A".repeat(85)),
            signer_device_id: PC_DEVICE.to_string(),
            handover: None,
        }
    }

    /// Every stored thread membership row of `user_id`, whether or not its
    /// thread still exists (`fetch_joined_thread_ids` drops rows whose
    /// thread is gone, so it cannot see a row left behind by a deleted one)
    async fn raw_thread_memberships(db: &crate::Database, user_id: &str) -> Vec<String> {
        match db {
            crate::Database::Reference(reference) => reference
                .thread_members
                .lock()
                .await
                .keys()
                .filter(|key| key.user == user_id)
                .map(|key| key.thread.clone())
                .collect(),
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                use futures::TryStreamExt;

                mongo
                    .col::<bson::Document>("thread_members")
                    .find(doc! { "_id.user": user_id })
                    .await
                    .unwrap()
                    .try_collect::<Vec<bson::Document>>()
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|row| {
                        row.get_document("_id")
                            .and_then(|key| key.get_str("thread"))
                            .unwrap()
                            .to_string()
                    })
                    .collect()
            }
        }
    }

    /// Rounds of the thread race below (fresh channels every round)
    const THREAD_RACE_ROUNDS: u32 = 10;

    /// Channels per round. The protects run through them in order and the
    /// thread creations in reverse, so the two streams cross once per round
    /// without any pacing: the channels the protects reach first end
    /// protected, the rest end with a thread, and the crossing is the race.
    const THREAD_RACE_STREAM: u32 = 8;

    /// Decision 13 (W2) [R#8]: protect racing `create_thread` on the same
    /// parent. Every parent ends either with its thread (and the protect
    /// refused with `InvalidOperation`) or protected (and the creation
    /// refused with `ChannelProtected`), never both and never a
    /// `DatabaseError`. A refused creation leaves no thread row, no thread
    /// membership (raw rows included) and no `ChannelCreate` on the server
    /// topic. Run it under MONGODB (the race is real there); it holds under
    /// REFERENCE too. Needs Redis at `REDIS_URI`.
    ///
    /// Controls: the hold dropped (a protected parent keeps a thread); the
    /// hold moved below the auto-join and the publish (a refused creation
    /// announced its thread, and under REFERENCE left a membership row).
    #[tokio::test]
    async fn create_thread_racing_a_protect_never_leaves_a_thread_under_a_protected_parent() {
        database_test!(|db| async move {
            use crate::{events::client::EventV1, Channel, User};
            use futures::StreamExt;
            use revolt_result::ErrorType;
            use std::time::Duration;

            // A fresh server id is a fresh topic: nothing else publishes to it
            let server_id = ulid::Ulid::new().to_string();
            let owner = pc_user(1);
            pc_server(&db, &server_id, &owner).await;

            let mut pubsub = redis_kiss::open_pubsub_connection()
                .await
                .expect("pubsub connection");
            pubsub.subscribe(&server_id).await.expect("subscribe");

            let mut won_threads: Vec<String> = Vec::new();
            let mut protects_won = 0;
            for round in 0..THREAD_RACE_ROUNDS {
                let mut parents = Vec::new();
                let mut creators = Vec::new();
                for index in 0..THREAD_RACE_STREAM {
                    let channel_id = pc_channel_id(round * 100 + index);
                    pc_entitled_channel(&db, &channel_id, &server_id).await;
                    parents.push(db.fetch_channel(&channel_id).await.unwrap());
                    creators.push(User {
                        id: pc_user(1_000 + round * 100 + index),
                        username: "creator".to_string(),
                        discriminator: "0001".to_string(),
                        ..Default::default()
                    });
                }

                // Back to back, no pacing. The thread stream holds the
                // parent copies read before any protect, as a route would.
                let protects = async {
                    let mut outcomes = Vec::new();
                    for parent in &parents {
                        let genesis = pc_genesis(parent.id(), &owner);
                        outcomes.push(db.protect_channel(parent.id(), &genesis, pc_now()).await);
                    }
                    outcomes
                };
                let threads = async {
                    let mut outcomes: Vec<_> = parents.iter().map(|_| None).collect();
                    for index in (0..parents.len()).rev() {
                        let created = Channel::create_thread(
                            &db,
                            &parents[index],
                            &creators[index],
                            None,
                            revolt_models::v0::DataCreateThread {
                                name: "race".to_string(),
                                auto_archive_minutes: None,
                            },
                        )
                        .await;
                        outcomes[index] = Some(created);
                    }
                    outcomes
                };
                let (protected, created) = if round % 2 == 0 {
                    tokio::join!(protects, threads)
                } else {
                    let (created, protected) = tokio::join!(threads, protects);
                    (protected, created)
                };

                for (index, (protect, create)) in protected.into_iter().zip(created).enumerate() {
                    let parent = parents[index].id();
                    let creator = &creators[index].id;
                    let create = create.expect("every creation ran");
                    let parent_protected = db.fetch_channel(parent).await.unwrap().is_protected();
                    let threads: Vec<String> = db
                        .fetch_threads_by_parent(parent)
                        .await
                        .unwrap()
                        .iter()
                        .map(|thread| thread.id().to_string())
                        .collect();
                    let joined = db
                        .fetch_joined_thread_ids(creator, &server_id)
                        .await
                        .unwrap();
                    let memberships = raw_thread_memberships(&db, creator).await;

                    match (protect, create) {
                        (Err(refused), Ok(thread)) => {
                            assert!(
                                matches!(refused.error_type, ErrorType::InvalidOperation),
                                "round {round} channel {index}: protect lost with {refused:?}"
                            );
                            assert!(!parent_protected, "round {round} channel {index}");
                            let thread_id = vec![thread.id().to_string()];
                            assert_eq!(threads, thread_id, "round {round} channel {index}");
                            assert_eq!(joined, thread_id, "round {round} channel {index}");
                            assert_eq!(memberships, thread_id, "round {round} channel {index}");
                            won_threads.push(thread.id().to_string());
                        }
                        (Ok(_), Err(refused)) => {
                            assert!(
                                matches!(refused.error_type, ErrorType::ChannelProtected),
                                "round {round} channel {index}: creation lost with {refused:?}"
                            );
                            assert!(parent_protected, "round {round} channel {index}");
                            assert!(
                                threads.is_empty(),
                                "round {round} channel {index}: a thread row under a protected parent: {threads:?}"
                            );
                            assert!(
                                joined.is_empty(),
                                "round {round} channel {index}: joined {joined:?}"
                            );
                            assert!(
                                memberships.is_empty(),
                                "round {round} channel {index}: a refused creation left membership rows {memberships:?}"
                            );
                            protects_won += 1;
                        }
                        other => panic!("round {round} channel {index}: {other:?}"),
                    }
                }
            }

            eprintln!(
                "protect vs create_thread: {protects_won} protects won, {} threads won",
                won_threads.len()
            );
            assert!(
                protects_won > 0 && !won_threads.is_empty(),
                "one-sided race: {protects_won} protects won, {} threads won",
                won_threads.len()
            );

            // Every ChannelCreate on the server topic is a thread that won.
            // A marker published last bounds the wait.
            let marker = ulid::Ulid::new().to_string();
            EventV1::ChannelDelete { id: marker.clone() }
                .p(server_id.clone())
                .await;
            let mut announced = Vec::new();
            let mut stream = pubsub.on_message();
            loop {
                let message = tokio::time::timeout(Duration::from_secs(5), stream.next())
                    .await
                    .expect("the marker must arrive within 5 s (is Redis at REDIS_URI up?)")
                    .expect("the subscription ended");
                match redis_kiss::decode_payload::<EventV1>(&message) {
                    Ok(EventV1::ChannelDelete { id }) if id == marker => break,
                    Ok(EventV1::ChannelCreate(channel)) => announced.push(channel.id().to_string()),
                    _ => {}
                }
            }
            announced.sort();
            won_threads.sort();
            assert_eq!(
                announced, won_threads,
                "a ChannelCreate was published for a thread that does not exist"
            );
        });
    }

    /// Decision 12 (W2): deleting a TextChannel removes its protected data
    /// (entitlement, seats, seat list, Text group closed, commits), and so
    /// does deleting an unprotected channel that only holds an entitlement.
    /// Runs on whichever driver `TEST_DB` names.
    ///
    /// Controls: the `delete_protected_channel_data` call skipped; the call
    /// made for protected channels only (the entitled channel keeps its
    /// entitlement).
    #[tokio::test]
    async fn deleting_a_text_channel_removes_its_protected_data() {
        database_test!(|db| async move {
            use crate::{MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupKind, MlsMemberDevice};
            use revolt_result::ErrorType;

            let server_id = ulid::Ulid::new().to_string();
            let owner = pc_user(1);
            pc_server(&db, &server_id, &owner).await;
            let (protected, entitled) = (pc_channel_id(1), pc_channel_id(2));
            pc_entitled_channel(&db, &protected, &server_id).await;
            pc_entitled_channel(&db, &entitled, &server_id).await;
            db.protect_channel(&protected, &pc_genesis(&protected, &owner), pc_now())
                .await
                .unwrap();

            // The owner's open Text group, with one commit
            let owner_device = MlsMemberDevice {
                user_id: owner.clone(),
                device_id: PC_DEVICE.to_string(),
            };
            let group = MlsGroup {
                id: "dd".repeat(32),
                channel_id: protected.clone(),
                open: true,
                created_by: owner_device.clone(),
                created_at: pc_now(),
                current_epoch: 0,
                members: vec![owner_device.clone()],
                closed_at: None,
                superseded_by: None,
                // Server-owned Text fields: create_text_mls_group sets them
                kind: MlsGroupKind::Call,
                generation: Some(0),
                seat_list_ad_sha256: None,
                pending_removals: vec![],
                member_added: vec![],
            };
            db.create_text_mls_group(&group, None).await.unwrap();
            let list = db
                .fetch_seat_list(&protected)
                .await
                .unwrap()
                .expect("the genesis list");
            let commit = MlsCommit {
                id: MlsCommit::composite_id(&group.id, 1),
                group_id: group.id.clone(),
                epoch: 1,
                committer: owner_device.clone(),
                commit: "commit".to_string(),
                size: 6,
                added: vec![],
                removed: vec![],
                created_at: pc_now(),
                rejoin_intents: vec![],
                removed_reasons: vec![],
            };
            let outcome = db
                .insert_mls_text_commit(&commit, &list.commit_ad_sha256().unwrap(), 0)
                .await
                .unwrap();
            assert!(matches!(outcome, MlsCommitOutcome::Won), "{outcome:?}");

            // Everything the cascade must remove is there first
            for channel_id in [&protected, &entitled] {
                assert!(db
                    .fetch_channel_entitlement(channel_id)
                    .await
                    .unwrap()
                    .is_some());
            }
            assert!(!db.fetch_channel_seats(&protected).await.unwrap().is_empty());
            let snapshot = db.fetch_seat_list_snapshot(&protected).await.unwrap();
            assert!(snapshot.list.is_some() && snapshot.text_group.is_some());
            assert_eq!(
                db.fetch_mls_commits_from(&group.id, 0, 10)
                    .await
                    .unwrap()
                    .len(),
                1
            );

            for channel_id in [&protected, &entitled] {
                db.fetch_channel(channel_id)
                    .await
                    .unwrap()
                    .delete(&db)
                    .await
                    .expect("delete");
            }

            for channel_id in [&protected, &entitled] {
                assert!(
                    db.fetch_channel_entitlement(channel_id)
                        .await
                        .unwrap()
                        .is_none(),
                    "{channel_id}: the entitlement survived the delete"
                );
                assert!(db.fetch_channel_seats(channel_id).await.unwrap().is_empty());
                let result = db.fetch_channel(channel_id).await;
                assert!(
                    matches!(&result, Err(error) if matches!(error.error_type, ErrorType::NotFound)),
                    "{channel_id}: {result:?}"
                );
            }
            let snapshot = db.fetch_seat_list_snapshot(&protected).await.unwrap();
            assert!(snapshot.list.is_none(), "the seat list survived the delete");
            assert!(
                snapshot.text_group.is_none(),
                "the Text group is still open"
            );
            // The delete removes the Text group row itself, not just closes it
            assert!(
                matches!(
                    db.fetch_mls_group(&group.id).await,
                    Err(error) if matches!(error.error_type, ErrorType::NotFound)
                ),
                "the Text group row survived the delete"
            );
            assert!(
                db.fetch_mls_commits_from(&group.id, 0, 10)
                    .await
                    .unwrap()
                    .is_empty(),
                "the commits survived the delete"
            );
        });
    }

    // ---- Client gates (wave BG) --------------------------------------------

    /// The server's reading of the password gate is the client's
    /// `parseChannelPassword`, case for case: gated where the client shows a
    /// gate, open where it does not. Failing closed on a case the client
    /// leaves open is still a mismatch, and is caught here.
    ///
    /// Controls: `lines()` in place of `split('\n')` (the trailing newline
    /// and trailing CRLF cases), the first line in place of the last (the
    /// marker after a line of text), the length check dropped (the empty
    /// hash).
    #[test]
    fn password_gate_matches_the_client_parser() {
        use crate::description_has_password_gate as gated;

        for description in [
            "[acupass:ab]",
            "notes\n[acupass:ab]",
            "first\nsecond\n[acupass:0123abcd]",
            "[acupass:\u{e9}]",
            "notes\r\n[acupass:ab]",
        ] {
            assert!(gated(Some(description)), "{description:?} is gated");
        }

        for description in [
            "",
            // The empty hash.
            "[acupass:]",
            // Not the last line.
            "[acupass:ab]\nnotes",
            // A trailing newline makes the last line empty.
            "notes\n[acupass:ab]\n",
            "[acupass:ab]\r\n",
            // A line ending in CR does not end with the suffix.
            "[acupass:ab]\r",
            // No trimming, and the prefix is case-sensitive.
            " [acupass:ab]",
            "[acupass:ab] ",
            "[ACUPASS:ab]",
            // Half a marker.
            "[acupass:ab",
            "acupass:ab]",
        ] {
            assert!(!gated(Some(description)), "{description:?} is not gated");
        }

        assert!(!gated(None));
    }

    /// Each gate, alone, gates each variant that carries gate fields; no gate
    /// leaves them open. A thread fails closed; DMs and saved messages have
    /// no gate. Control: the Thread arm answering `false`.
    #[test]
    fn has_client_gate_per_variant() {
        use crate::{
            client_gate_is_set, Channel, ForumLayout, ForumSortOrder, VoiceInformation,
            CHANNEL_PASSWORD_PREFIX, CHANNEL_PASSWORD_SUFFIX,
        };
        use std::collections::HashMap;

        let password = [CHANNEL_PASSWORD_PREFIX, "ab", CHANNEL_PASSWORD_SUFFIX].concat();
        // (nsfw, spoiler, description): no gate, then each gate on its own.
        let cases = [
            (false, false, None, false),
            (true, false, None, true),
            (false, true, None, true),
            (false, false, Some(password), true),
            // A description that is not a password line is no gate.
            (false, false, Some("about this channel".to_string()), false),
        ];

        for (nsfw, spoiler, description, want) in cases {
            assert_eq!(
                client_gate_is_set(nsfw, spoiler, description.as_deref()),
                want
            );

            let text = Channel::TextChannel {
                id: "T".to_string(),
                server: "S".to_string(),
                name: "voice".to_string(),
                description: description.clone(),
                icon: None,
                last_message_id: None,
                default_permissions: None,
                role_permissions: HashMap::new(),
                nsfw,
                spoiler,
                voice: Some(VoiceInformation::default()),
                slowmode: None,
                announcement: None,
                protected: false,
            };
            let forum = Channel::Forum {
                id: "F".to_string(),
                server: "S".to_string(),
                name: "forum".to_string(),
                description: description.clone(),
                icon: None,
                last_message_id: None,
                default_permissions: None,
                role_permissions: HashMap::new(),
                nsfw,
                spoiler,
                tags: vec![],
                require_tag: false,
                default_sort: ForumSortOrder::default(),
                force_sort: false,
                default_layout: ForumLayout::default(),
                default_auto_archive_minutes: Channel::default_forum_auto_archive_minutes(),
            };
            let group = Channel::Group {
                id: "G".to_string(),
                name: "group".to_string(),
                owner: "O".to_string(),
                description: description.clone(),
                recipients: vec![],
                icon: None,
                last_message_id: None,
                permissions: None,
                nsfw,
                spoiler,
                voice: None,
            };

            for channel in [text, forum, group] {
                assert_eq!(channel.has_client_gate(), want, "{channel:?}");
            }
        }

        let thread = Channel::Thread {
            id: "H".to_string(),
            server: "S".to_string(),
            parent_channel: "T".to_string(),
            name: "thread".to_string(),
            creator: "O".to_string(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: Channel::default_auto_archive_minutes(),
            locked: false,
            applied_tags: vec![],
        };
        assert!(thread.has_client_gate(), "a thread fails closed");

        let dm = Channel::DirectMessage {
            id: "D".to_string(),
            active: true,
            recipients: vec!["A".to_string(), "B".to_string()],
            last_message_id: None,
        };
        assert!(!dm.has_client_gate());

        let saved = Channel::SavedMessages {
            id: "M".to_string(),
            user: "A".to_string(),
        };
        assert!(!saved.has_client_gate());
    }

    /// A forum stored before `default_layout` existed loads as `Modern` (no
    /// migration), and a stored layout round-trips under its wire name.
    /// Control: a `#[default]` other than `Modern`, or the field without
    /// `#[serde(default)]`.
    #[test]
    fn forum_default_layout_is_modern_when_absent() {
        use crate::{Channel, ForumLayout, PartialChannel};

        fn layout(channel: &Channel) -> ForumLayout {
            match channel {
                Channel::Forum { default_layout, .. } => default_layout.clone(),
                other => panic!("expected a forum, got {other:?}"),
            }
        }

        let old: Channel = serde_json::from_value(serde_json::json!({
            "channel_type": "Forum",
            "_id": "F",
            "server": "S",
            "name": "forum",
            "default_sort": "LatestActivity",
        }))
        .expect("a pre-layout forum document deserializes");
        assert_eq!(layout(&old), ForumLayout::Modern);

        let stored: Channel = serde_json::from_value(serde_json::json!({
            "channel_type": "Forum",
            "_id": "F",
            "server": "S",
            "name": "forum",
            "default_layout": "ClassicPlus",
        }))
        .expect("a forum document with a layout deserializes");
        assert_eq!(layout(&stored), ForumLayout::ClassicPlus);
        let value = serde_json::to_value(&stored).expect("serializes");
        assert_eq!(value["default_layout"], "ClassicPlus");
        let again: Channel = serde_json::from_value(value).expect("round-trips");
        assert_eq!(again, stored);

        for (variant, wire) in [
            (ForumLayout::Modern, "Modern"),
            (ForumLayout::Classic, "Classic"),
            (ForumLayout::ClassicPlus, "ClassicPlus"),
        ] {
            assert_eq!(serde_json::to_value(&variant).expect("serializes"), wire);
        }

        let mut forum = old.clone();
        forum.apply_options(PartialChannel {
            default_layout: Some(ForumLayout::Classic),
            ..Default::default()
        });
        assert_eq!(layout(&forum), ForumLayout::Classic);
        forum.apply_options(PartialChannel::default());
        assert_eq!(layout(&forum), ForumLayout::Classic, "None leaves it");
    }

    /// `force_sort` from a partial lands on the forum (the Reference driver,
    /// `Channel::update` and bonfire's cached channel all go through
    /// `apply_options`), and `None` leaves it alone.
    /// Control: drop the `force_sort` arm of `apply_options`.
    #[test]
    fn apply_options_sets_forum_force_sort() {
        use crate::{Channel, PartialChannel};

        fn force_sort(channel: &Channel) -> bool {
            match channel {
                Channel::Forum { force_sort, .. } => *force_sort,
                other => panic!("expected a forum, got {other:?}"),
            }
        }

        let mut forum: Channel = serde_json::from_value(serde_json::json!({
            "channel_type": "Forum",
            "_id": "F",
            "server": "S",
            "name": "forum",
            "force_sort": false,
        }))
        .expect("a forum document deserializes");
        assert!(!force_sort(&forum));

        forum.apply_options(PartialChannel {
            force_sort: Some(true),
            ..Default::default()
        });
        assert!(force_sort(&forum));
        forum.apply_options(PartialChannel::default());
        assert!(force_sort(&forum), "None leaves it");

        forum.apply_options(PartialChannel {
            force_sort: Some(false),
            ..Default::default()
        });
        assert!(!force_sort(&forum));
    }

    /// Same as above through BSON, the format MongoDB actually stores.
    #[cfg(feature = "mongodb")]
    #[test]
    fn forum_default_layout_is_modern_when_absent_bson() {
        use crate::{Channel, ForumLayout};

        let old: Channel = bson::from_document(bson::doc! {
            "channel_type": "Forum",
            "_id": "F",
            "server": "S",
            "name": "forum",
            "default_sort": "LatestActivity",
        })
        .expect("a pre-layout forum document deserializes");
        assert!(
            matches!(
                old,
                Channel::Forum {
                    default_layout: ForumLayout::Modern,
                    ..
                }
            ),
            "{old:?}"
        );

        let stored: Channel = bson::from_document(bson::doc! {
            "channel_type": "Forum",
            "_id": "F",
            "server": "S",
            "name": "forum",
            "default_layout": "ClassicPlus",
        })
        .expect("a forum document with a layout deserializes");
        let document = bson::to_document(&stored).expect("serializes");
        assert_eq!(
            document
                .get_str("default_layout")
                .expect("stored as a string"),
            "ClassicPlus"
        );
        let again: Channel = bson::from_document(document).expect("round-trips");
        assert_eq!(again, stored);
        assert!(matches!(
            again,
            Channel::Forum {
                default_layout: ForumLayout::ClassicPlus,
                ..
            }
        ));
    }

    /// The password marker is spelled once in the whole Rust workspace: in
    /// `CHANNEL_PASSWORD_PREFIX`, in this file's shipping code. Every other
    /// file, test code included, goes through the predicate or the constants.
    /// A second spelling is a second copy of the client contract to drift.
    #[test]
    fn the_password_marker_is_spelled_only_here() {
        use crate::CHANNEL_PASSWORD_PREFIX;
        use std::path::{Path, PathBuf};

        fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("readable directory") {
                let path = entry.expect("directory entry").path();
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_string();
                if path.is_dir() {
                    if name != "target" && !name.starts_with('.') {
                        rust_sources(&path, out);
                    }
                } else if name.ends_with(".rs") {
                    out.push(path);
                }
            }
        }

        const THIS_FILE: &str = "core/database/src/models/channels/model.rs";

        let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        rust_sources(&crates_dir, &mut files);
        assert!(
            files.len() > 300,
            "suspiciously small workspace scan ({} files)",
            files.len()
        );

        let mut seen_this_file = false;
        let mut elsewhere = Vec::new();
        for path in &files {
            let text = std::fs::read_to_string(path).expect("readable source");
            let rel = path
                .strip_prefix(&crates_dir)
                .expect("scanned under crates/")
                .to_string_lossy()
                .replace('\\', "/");

            if rel == THIS_FILE {
                seen_this_file = true;
                let shipping = text
                    .split("#[cfg(test)]")
                    .next()
                    .expect("text before the test module");
                assert_eq!(
                    shipping.matches(CHANNEL_PASSWORD_PREFIX).count(),
                    1,
                    "the marker is spelled once in this file's shipping code"
                );
            } else if text.contains(CHANNEL_PASSWORD_PREFIX) {
                elsewhere.push(rel);
            }
        }

        assert!(seen_this_file, "the scan did not reach {THIS_FILE}");
        assert!(
            elsewhere.is_empty(),
            "the password marker is spelled outside {THIS_FILE}: {elsewhere:?}"
        );
    }

    /// W2 audit B1 (c): `create_thread`'s cleanup after a refused hold
    /// retries a failed delete once and stops after two attempts
    ///
    /// Control: the retry removed (one attempt) → the "fails once" case
    /// returns the error.
    #[tokio::test]
    async fn refused_thread_delete_is_retried_once() {
        use revolt_result::ErrorType;
        use std::cell::Cell;

        for (failures, expect_ok, expect_calls) in [(0, true, 1), (1, true, 2), (2, false, 2)] {
            let calls = Cell::new(0);
            let outcome = super::delete_refused_thread(
                || {
                    calls.set(calls.get() + 1);
                    let call = calls.get();
                    async move {
                        if call <= failures {
                            Err(create_database_error!("delete_one", "channels"))
                        } else {
                            Ok(())
                        }
                    }
                },
                "thread",
                "parent",
            )
            .await;

            assert_eq!(
                outcome.is_ok(),
                expect_ok,
                "{failures} failures: {outcome:?}"
            );
            if let Err(error) = outcome {
                assert!(
                    matches!(error.error_type, ErrorType::DatabaseError { .. }),
                    "{:?}",
                    error.error_type
                );
            }
            assert_eq!(calls.get(), expect_calls, "{failures} failures");
        }
    }

    /// The wiring of the above: in `create_thread` the refused hold deletes
    /// through `delete_refused_thread`, and no bare `delete_channel` is left
    #[test]
    fn create_thread_cleans_up_through_the_retrying_delete() {
        let source = include_str!("model.rs");
        let start = source
            .find("pub async fn create_thread(")
            .expect("create_thread");
        let end = start
            + source[start..]
                .find("pub async fn create_forum_post(")
                .expect("create_forum_post");
        let body = &source[start..end];

        let hold = body
            .find("db.hold_thread_parent_unprotected(&parent_id).await")
            .expect("the hold");
        let cleanup = body
            .find("delete_refused_thread(|| db.delete_channel(&channel), &id, &parent_id).await?;")
            .expect("the retrying cleanup");
        assert!(hold < cleanup, "the cleanup follows the hold");
        assert_eq!(
            body.matches(".delete_channel(").count(),
            1,
            "one delete site"
        );
    }
}
