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
            /// (one of 60 / 1440 / 4320 / 10080)
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
        pub applied_tags: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
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
);

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

    /// Allowed auto-archive durations for threads, in minutes
    pub const ALLOWED_AUTO_ARCHIVE_MINUTES: [u32; 4] = [60, 1440, 4320, 10080];

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
        if !Channel::ALLOWED_AUTO_ARCHIVE_MINUTES.contains(&auto_archive_minutes) {
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
        let (parent_id, server_id) = match forum {
            Channel::Forum { id, server, .. } => (id.clone(), server.clone()),
            _ => return Err(create_error!(InvalidOperation)),
        };

        // Enforce the per-channel active post cap (shared with threads).
        let config = config().await;
        let max_threads = config.features.limits.global.threads_per_channel;
        let active_posts = db
            .fetch_threads_by_parent(&parent_id)
            .await?
            .into_iter()
            .filter(|thread| !matches!(thread, Channel::Thread { archived: true, .. }))
            .count();
        if active_posts >= max_threads {
            return Err(create_error!(TooManyChannels { max: max_threads }));
        }

        // Validate the auto-archive duration.
        let auto_archive_minutes =
            auto_archive_minutes.unwrap_or_else(Channel::default_auto_archive_minutes);
        if !Channel::ALLOWED_AUTO_ARCHIVE_MINUTES.contains(&auto_archive_minutes) {
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

    /// Gets this channel's voice information
    pub fn voice(&self) -> Option<Cow<VoiceInformation>> {
        match self {
            // DMs are always call-capable.
            Self::DirectMessage { .. } => Some(Cow::Owned(VoiceInformation::default())),
            // Groups have calling OFF by default; an owner turns it on (and may
            // set limits via max_users). Setting `disabled` keeps any saved
            // configuration while turning calling back off.
            Self::Group { voice, .. } => match voice {
                Some(voice) if !voice.disabled => Some(Cow::Borrowed(voice)),
                _ => None,
            },
            // Server channels are voice channels only when voice info is present
            // and not explicitly disabled.
            Self::TextChannel {
                voice: Some(voice), ..
            } if !voice.disabled => Some(Cow::Borrowed(voice)),
            _ => None,
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
            }
            Self::Thread {
                name,
                archived,
                archived_timestamp,
                last_message_id,
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

        // Default group (unconfigured): calling is OFF, so join_call is refused.
        assert!(group(None).voice().is_none());

        // Owner turns calling on (no limit).
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
}
