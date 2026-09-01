use iso8601_timestamp::Timestamp;
use revolt_models::v0::*;
use revolt_permissions::{calculate_user_permissions, UserPermission};

use crate::{util::permissions::DatabasePermissionQuery, Database};

impl crate::Bot {
    pub fn into_public_bot(self, user: crate::User) -> PublicBot {
        #[cfg(debug_assertions)]
        assert_eq!(self.id, user.id);

        PublicBot {
            id: self.id,
            username: user.username,
            avatar: user.avatar.map(|x| x.id).unwrap_or_default(),
            description: user
                .profile
                .and_then(|profile| profile.content)
                .unwrap_or_default(),
        }
    }
}

impl From<crate::Bot> for Bot {
    fn from(value: crate::Bot) -> Self {
        Bot {
            id: value.id,
            owner_id: value.owner,
            token: value.token,
            public: value.public,
            analytics: value.analytics,
            discoverable: value.discoverable,
            interactions_url: value.interactions_url,
            terms_of_service_url: value.terms_of_service_url,
            privacy_policy_url: value.privacy_policy_url,
            flags: value.flags.unwrap_or_default() as u32,
        }
    }
}

impl From<FieldsBot> for crate::FieldsBot {
    fn from(value: FieldsBot) -> Self {
        match value {
            FieldsBot::InteractionsURL => crate::FieldsBot::InteractionsURL,
            FieldsBot::Token => crate::FieldsBot::Token,
        }
    }
}

impl From<crate::FieldsBot> for FieldsBot {
    fn from(value: crate::FieldsBot) -> Self {
        match value {
            crate::FieldsBot::InteractionsURL => FieldsBot::InteractionsURL,
            crate::FieldsBot::Token => FieldsBot::Token,
        }
    }
}

impl From<crate::Invite> for Invite {
    fn from(value: crate::Invite) -> Self {
        match value {
            crate::Invite::Group {
                code,
                creator,
                channel,
            } => Invite::Group {
                code,
                creator,
                channel,
            },
            crate::Invite::Server {
                code,
                server,
                creator,
                channel,
            } => Invite::Server {
                code,
                server,
                creator,
                channel,
            },
        }
    }
}

impl From<crate::ChannelUnread> for ChannelUnread {
    fn from(value: crate::ChannelUnread) -> Self {
        ChannelUnread {
            id: value.id.into(),
            last_id: value.last_id,
            mentions: value.mentions.unwrap_or_default(),
            // Counting the unread tail needs the messages collection, so it is
            // stamped on afterwards by `util::unreads::fetch_unreads_with_summary`.
            count: 0,
            attachments: false,
        }
    }
}

impl From<crate::ChannelCompositeKey> for ChannelCompositeKey {
    fn from(value: crate::ChannelCompositeKey) -> Self {
        ChannelCompositeKey {
            channel: value.channel,
            user: value.user,
        }
    }
}

impl From<crate::Webhook> for Webhook {
    fn from(value: crate::Webhook) -> Self {
        Webhook {
            id: value.id,
            name: value.name,
            avatar: value.avatar.map(|file| file.into()),
            creator_id: value.creator_id,
            channel_id: value.channel_id,
            token: value.token,
            permissions: value.permissions,
        }
    }
}

impl From<crate::PartialWebhook> for PartialWebhook {
    fn from(value: crate::PartialWebhook) -> Self {
        PartialWebhook {
            id: value.id,
            name: value.name,
            avatar: value.avatar.map(|file| file.into()),
            creator_id: value.creator_id,
            channel_id: value.channel_id,
            token: value.token,
            permissions: value.permissions,
        }
    }
}

impl From<FieldsWebhook> for crate::FieldsWebhook {
    fn from(_value: FieldsWebhook) -> Self {
        Self::Avatar
    }
}

impl From<crate::FieldsWebhook> for FieldsWebhook {
    fn from(_value: crate::FieldsWebhook) -> Self {
        Self::Avatar
    }
}

impl From<crate::Channel> for Channel {
    #[allow(deprecated)]
    fn from(value: crate::Channel) -> Self {
        match value {
            crate::Channel::SavedMessages { id, user } => Channel::SavedMessages { id, user },
            crate::Channel::DirectMessage {
                id,
                active,
                recipients,
                last_message_id,
            } => Channel::DirectMessage {
                id,
                active,
                recipients,
                last_message_id,
            },
            crate::Channel::Group {
                id,
                name,
                owner,
                description,
                recipients,
                icon,
                last_message_id,
                permissions,
                nsfw,
                spoiler,
                voice,
            } => Channel::Group {
                id,
                name,
                owner,
                description,
                recipients,
                icon: icon.map(|file| file.into()),
                last_message_id,
                permissions,
                nsfw,
                spoiler,
                voice: voice.map(|voice| voice.into()),
            },
            crate::Channel::TextChannel {
                id,
                server,
                name,
                description,
                icon,
                last_message_id,
                default_permissions,
                role_permissions,
                nsfw,
                spoiler,
                voice,
                slowmode,
                announcement,
            } => Channel::TextChannel {
                id,
                server,
                name,
                description,
                icon: icon.map(|file| file.into()),
                last_message_id,
                default_permissions,
                role_permissions,
                nsfw,
                spoiler,
                voice: voice.map(|voice| voice.into()),
                slowmode,
                announcement,
            },
            crate::Channel::Thread {
                id,
                server,
                parent_channel,
                name,
                creator,
                origin_message_id,
                last_message_id,
                archived,
                archived_timestamp,
                auto_archive_minutes,
                locked,
                applied_tags,
            } => Channel::Thread {
                id,
                server,
                parent_channel,
                name,
                creator,
                origin_message_id,
                last_message_id,
                archived,
                archived_timestamp,
                auto_archive_minutes,
                locked,
                applied_tags,
            },
            crate::Channel::Forum {
                id,
                server,
                name,
                description,
                icon,
                last_message_id,
                default_permissions,
                role_permissions,
                nsfw,
                spoiler,
                tags,
                require_tag,
                default_sort,
            } => Channel::Forum {
                id,
                server,
                name,
                description,
                icon: icon.map(|file| file.into()),
                last_message_id,
                default_permissions,
                role_permissions,
                nsfw,
                spoiler,
                tags: tags.into_iter().map(|tag| tag.into()).collect(),
                require_tag,
                default_sort: default_sort.into(),
            },
        }
    }
}

impl From<Channel> for crate::Channel {
    #[allow(deprecated)]
    fn from(value: Channel) -> crate::Channel {
        match value {
            Channel::SavedMessages { id, user } => crate::Channel::SavedMessages { id, user },
            Channel::DirectMessage {
                id,
                active,
                recipients,
                last_message_id,
            } => crate::Channel::DirectMessage {
                id,
                active,
                recipients,
                last_message_id,
            },
            Channel::Group {
                id,
                name,
                owner,
                description,
                recipients,
                icon,
                last_message_id,
                permissions,
                nsfw,
                spoiler,
                voice,
            } => crate::Channel::Group {
                id,
                name,
                owner,
                description,
                recipients,
                icon: icon.map(|file| file.into()),
                last_message_id,
                permissions,
                nsfw,
                spoiler,
                voice: voice.map(|voice| voice.into()),
            },
            Channel::TextChannel {
                id,
                server,
                name,
                description,
                icon,
                last_message_id,
                default_permissions,
                role_permissions,
                nsfw,
                spoiler,
                voice,
                slowmode,
                announcement,
            } => crate::Channel::TextChannel {
                id,
                server,
                name,
                description,
                icon: icon.map(|file| file.into()),
                last_message_id,
                default_permissions,
                role_permissions,
                nsfw,
                spoiler,
                voice: voice.map(|voice| voice.into()),
                slowmode,
                announcement,
            },
            Channel::Thread {
                id,
                server,
                parent_channel,
                name,
                creator,
                origin_message_id,
                last_message_id,
                archived,
                archived_timestamp,
                auto_archive_minutes,
                locked,
                applied_tags,
            } => crate::Channel::Thread {
                id,
                server,
                parent_channel,
                name,
                creator,
                origin_message_id,
                last_message_id,
                archived,
                archived_timestamp,
                auto_archive_minutes,
                locked,
                applied_tags,
            },
            Channel::Forum {
                id,
                server,
                name,
                description,
                icon,
                last_message_id,
                default_permissions,
                role_permissions,
                nsfw,
                spoiler,
                tags,
                require_tag,
                default_sort,
            } => crate::Channel::Forum {
                id,
                server,
                name,
                description,
                icon: icon.map(|file| file.into()),
                last_message_id,
                default_permissions,
                role_permissions,
                nsfw,
                spoiler,
                tags: tags.into_iter().map(|tag| tag.into()).collect(),
                require_tag,
                default_sort: default_sort.into(),
            },
        }
    }
}

impl From<crate::ForumTag> for ForumTag {
    fn from(value: crate::ForumTag) -> Self {
        ForumTag {
            id: value.id,
            name: value.name,
            emoji: value.emoji,
            moderated: value.moderated,
        }
    }
}

impl From<ForumTag> for crate::ForumTag {
    fn from(value: ForumTag) -> Self {
        crate::ForumTag {
            id: value.id,
            name: value.name,
            emoji: value.emoji,
            moderated: value.moderated,
        }
    }
}

impl From<crate::ForumSortOrder> for ForumSortOrder {
    fn from(value: crate::ForumSortOrder) -> Self {
        match value {
            crate::ForumSortOrder::LatestActivity => ForumSortOrder::LatestActivity,
            crate::ForumSortOrder::CreationDate => ForumSortOrder::CreationDate,
        }
    }
}

impl From<ForumSortOrder> for crate::ForumSortOrder {
    fn from(value: ForumSortOrder) -> Self {
        match value {
            ForumSortOrder::LatestActivity => crate::ForumSortOrder::LatestActivity,
            ForumSortOrder::CreationDate => crate::ForumSortOrder::CreationDate,
        }
    }
}

impl From<crate::PartialChannel> for PartialChannel {
    fn from(value: crate::PartialChannel) -> Self {
        PartialChannel {
            name: value.name,
            owner: value.owner,
            description: value.description,
            icon: value.icon.map(|file| file.into()),
            nsfw: value.nsfw,
            spoiler: value.spoiler,
            active: value.active,
            permissions: value.permissions,
            role_permissions: value.role_permissions,
            default_permissions: value.default_permissions,
            last_message_id: value.last_message_id,
            voice: value.voice.map(|voice| voice.into()),
            slowmode: value.slowmode,
            archived: value.archived,
            archived_timestamp: value.archived_timestamp,
            tags: value
                .tags
                .map(|tags| tags.into_iter().map(|tag| tag.into()).collect()),
            require_tag: value.require_tag,
            default_sort: value.default_sort.map(|sort| sort.into()),
            applied_tags: value.applied_tags,
            announcement: value.announcement,
        }
    }
}

impl From<PartialChannel> for crate::PartialChannel {
    fn from(value: PartialChannel) -> crate::PartialChannel {
        crate::PartialChannel {
            name: value.name,
            owner: value.owner,
            description: value.description,
            icon: value.icon.map(|file| file.into()),
            nsfw: value.nsfw,
            spoiler: value.spoiler,
            active: value.active,
            permissions: value.permissions,
            role_permissions: value.role_permissions,
            default_permissions: value.default_permissions,
            last_message_id: value.last_message_id,
            voice: value.voice.map(|voice| voice.into()),
            slowmode: value.slowmode,
            archived: value.archived,
            archived_timestamp: value.archived_timestamp,
            tags: value
                .tags
                .map(|tags| tags.into_iter().map(|tag| tag.into()).collect()),
            require_tag: value.require_tag,
            default_sort: value.default_sort.map(|sort| sort.into()),
            applied_tags: value.applied_tags,
            announcement: value.announcement,
        }
    }
}

impl From<FieldsChannel> for crate::FieldsChannel {
    fn from(value: FieldsChannel) -> Self {
        match value {
            FieldsChannel::Description => crate::FieldsChannel::Description,
            FieldsChannel::Icon => crate::FieldsChannel::Icon,
            FieldsChannel::DefaultPermissions => crate::FieldsChannel::DefaultPermissions,
            FieldsChannel::Voice => crate::FieldsChannel::Voice,
            FieldsChannel::Tags => crate::FieldsChannel::Tags,
        }
    }
}

impl From<crate::FieldsChannel> for FieldsChannel {
    fn from(value: crate::FieldsChannel) -> Self {
        match value {
            crate::FieldsChannel::Description => FieldsChannel::Description,
            crate::FieldsChannel::Icon => FieldsChannel::Icon,
            crate::FieldsChannel::DefaultPermissions => FieldsChannel::DefaultPermissions,
            crate::FieldsChannel::Voice => FieldsChannel::Voice,
            crate::FieldsChannel::Tags => FieldsChannel::Tags,
        }
    }
}

impl From<crate::Emoji> for Emoji {
    fn from(value: crate::Emoji) -> Self {
        Emoji {
            id: value.id,
            parent: value.parent.into(),
            creator_id: value.creator_id,
            name: value.name,
            animated: value.animated,
            nsfw: value.nsfw,
        }
    }
}

impl From<crate::EmojiParent> for EmojiParent {
    fn from(value: crate::EmojiParent) -> Self {
        match value {
            crate::EmojiParent::Detached => EmojiParent::Detached,
            crate::EmojiParent::Server { id } => EmojiParent::Server { id },
        }
    }
}

impl From<EmojiParent> for crate::EmojiParent {
    fn from(value: EmojiParent) -> Self {
        match value {
            EmojiParent::Detached => crate::EmojiParent::Detached,
            EmojiParent::Server { id } => crate::EmojiParent::Server { id },
        }
    }
}

impl From<crate::Sticker> for Sticker {
    fn from(value: crate::Sticker) -> Self {
        Sticker {
            id: value.id,
            server_id: value.server_id,
            creator_id: value.creator_id,
            name: value.name,
            description: value.description,
            file_id: value.file_id,
            format: value.format.into(),
            nsfw: value.nsfw,
        }
    }
}

impl From<crate::SoundboardSound> for SoundboardSound {
    fn from(value: crate::SoundboardSound) -> Self {
        SoundboardSound {
            id: value.id,
            server_id: value.server_id,
            creator_id: value.creator_id,
            name: value.name,
            file_id: value.file_id,
            emoji: value.emoji,
        }
    }
}

impl From<crate::StickerFormat> for StickerFormat {
    fn from(value: crate::StickerFormat) -> Self {
        match value {
            crate::StickerFormat::PNG => StickerFormat::PNG,
            crate::StickerFormat::APNG => StickerFormat::APNG,
            crate::StickerFormat::GIF => StickerFormat::GIF,
            crate::StickerFormat::Lottie => StickerFormat::Lottie,
        }
    }
}

impl From<StickerFormat> for crate::StickerFormat {
    fn from(value: StickerFormat) -> Self {
        match value {
            StickerFormat::PNG => crate::StickerFormat::PNG,
            StickerFormat::APNG => crate::StickerFormat::APNG,
            StickerFormat::GIF => crate::StickerFormat::GIF,
            StickerFormat::Lottie => crate::StickerFormat::Lottie,
        }
    }
}

impl From<crate::File> for File {
    fn from(value: crate::File) -> Self {
        File {
            id: value.id,
            tag: value.tag,
            filename: value.filename,
            metadata: value.metadata.into(),
            content_type: value.content_type,
            size: value.size,
            deleted: value.deleted,
            reported: value.reported,
            message_id: value.message_id,
            user_id: value.user_id,
            server_id: value.server_id,
            object_id: value.object_id,
        }
    }
}

impl From<File> for crate::File {
    fn from(value: File) -> crate::File {
        crate::File {
            id: value.id,
            tag: value.tag,
            filename: value.filename,
            metadata: value.metadata.into(),
            content_type: value.content_type,
            size: value.size,
            deleted: value.deleted,
            reported: value.reported,
            message_id: value.message_id,
            user_id: value.user_id,
            server_id: value.server_id,
            object_id: value.object_id,
            hash: None,
            uploaded_at: None,
            uploader_id: None,
            used_for: None,
        }
    }
}

impl From<crate::Metadata> for Metadata {
    fn from(value: crate::Metadata) -> Self {
        match value {
            crate::Metadata::File => Metadata::File,
            crate::Metadata::Text => Metadata::Text,
            crate::Metadata::Image {
                width,
                height,
                thumbhash,
                animated,
            } => Metadata::Image {
                width: width as usize,
                height: height as usize,
                thumbhash,
                animated,
            },
            crate::Metadata::Video { width, height } => Metadata::Video {
                width: width as usize,
                height: height as usize,
            },
            crate::Metadata::Audio => Metadata::Audio,
        }
    }
}

impl From<Metadata> for crate::Metadata {
    fn from(value: Metadata) -> crate::Metadata {
        match value {
            Metadata::File => crate::Metadata::File,
            Metadata::Text => crate::Metadata::Text,
            Metadata::Image {
                width,
                height,
                thumbhash,
                animated,
            } => crate::Metadata::Image {
                width: width as isize,
                height: height as isize,
                thumbhash,
                animated,
            },
            Metadata::Video { width, height } => crate::Metadata::Video {
                width: width as isize,
                height: height as isize,
            },
            Metadata::Audio => crate::Metadata::Audio,
        }
    }
}

impl crate::Message {
    pub fn into_model(self, user: Option<User>, member: Option<Member>) -> Message {
        Message {
            id: self.id,
            nonce: self.nonce,
            channel: self.channel,
            author: self.author,
            user,
            member,
            webhook: self.webhook,
            content: self.content,
            system: self.system.map(Into::into),
            attachments: self
                .attachments
                .map(|v| v.into_iter().map(|f| f.into()).collect()),
            edited: self.edited,
            embeds: self.embeds,
            mentions: self.mentions,
            role_mentions: self.role_mentions,
            replies: self.replies,
            reactions: self.reactions,
            interactions: self.interactions.into(),
            masquerade: self.masquerade.map(Into::into),
            flags: self.flags.unwrap_or_default(),
            pinned: self.pinned,
            thread_id: self.thread_id,
            command_context: self.command_context.map(Into::into),
            components: self.components,
            sticker_ids: self.sticker_ids,
            poll: self.poll,
            softres: self.softres,
            forwarded: self.forwarded.map(Into::into),
            crosspost: self.crosspost,
        }
    }
}

impl From<crate::ForwardedSnapshot> for ForwardedSnapshot {
    fn from(value: crate::ForwardedSnapshot) -> Self {
        ForwardedSnapshot {
            message_id: value.message_id,
            channel_id: value.channel_id,
            server_id: value.server_id,
            author_id: value.author_id,
            content: value.content,
            attachments: value
                .attachments
                .into_iter()
                .map(Into::into)
                .collect(),
            original_sent_at: value.original_sent_at,
        }
    }
}

impl From<crate::PartialMessage> for PartialMessage {
    fn from(value: crate::PartialMessage) -> Self {
        PartialMessage {
            id: value.id,
            nonce: value.nonce,
            channel: value.channel,
            author: value.author,
            user: None,
            member: None,
            webhook: value.webhook,
            content: value.content,
            system: value.system.map(Into::into),
            attachments: value
                .attachments
                .map(|v| v.into_iter().map(|f| f.into()).collect()),
            edited: value.edited,
            embeds: value.embeds,
            mentions: value.mentions,
            role_mentions: value.role_mentions,
            replies: value.replies,
            reactions: value.reactions,
            interactions: value.interactions.map(Into::into),
            masquerade: value.masquerade.map(Into::into),
            flags: value.flags,
            pinned: value.pinned,
            thread_id: value.thread_id,
            command_context: value.command_context.map(Into::into),
            components: value.components,
            sticker_ids: value.sticker_ids,
            poll: value.poll,
            softres: value.softres,
            forwarded: value.forwarded.map(Into::into),
            crosspost: value.crosspost,
        }
    }
}

impl From<crate::SystemMessage> for SystemMessage {
    fn from(value: crate::SystemMessage) -> Self {
        match value {
            crate::SystemMessage::ChannelDescriptionChanged { by } => {
                Self::ChannelDescriptionChanged { by }
            }
            crate::SystemMessage::ChannelIconChanged { by } => Self::ChannelIconChanged { by },
            crate::SystemMessage::ChannelOwnershipChanged { from, to } => {
                Self::ChannelOwnershipChanged { from, to }
            }
            crate::SystemMessage::ChannelRenamed { name, by } => Self::ChannelRenamed { name, by },
            crate::SystemMessage::Text { content } => Self::Text { content },
            crate::SystemMessage::UserAdded { id, by } => Self::UserAdded { id, by },
            crate::SystemMessage::UserBanned { id } => Self::UserBanned { id },
            crate::SystemMessage::UserJoined { id } => Self::UserJoined { id },
            crate::SystemMessage::UserKicked { id } => Self::UserKicked { id },
            crate::SystemMessage::UserLeft { id } => Self::UserLeft { id },
            crate::SystemMessage::UserRemove { id, by } => Self::UserRemove { id, by },
            crate::SystemMessage::MessagePinned { id, by } => Self::MessagePinned { id, by },
            crate::SystemMessage::MessageUnpinned { id, by } => Self::MessageUnpinned { id, by },
            crate::SystemMessage::CallStarted { by, finished_at } => {
                Self::CallStarted { by, finished_at }
            }
            crate::SystemMessage::ThreadCreated { id, by, name } => {
                Self::ThreadCreated { id, by, name }
            }
            crate::SystemMessage::CallRecordingStarted { by } => {
                Self::CallRecordingStarted { by }
            }
            crate::SystemMessage::CallRecordingStopped { by } => {
                Self::CallRecordingStopped { by }
            }
        }
    }
}

impl From<crate::Interactions> for Interactions {
    fn from(value: crate::Interactions) -> Self {
        Interactions {
            reactions: value
                .reactions
                .map(|reactions| reactions.into_iter().collect()),
            restrict_reactions: value.restrict_reactions,
        }
    }
}

impl From<Interactions> for crate::Interactions {
    fn from(value: Interactions) -> Self {
        crate::Interactions {
            reactions: value
                .reactions
                .map(|reactions| reactions.into_iter().collect()),
            restrict_reactions: value.restrict_reactions,
        }
    }
}

impl From<crate::AppendMessage> for AppendMessage {
    fn from(value: crate::AppendMessage) -> Self {
        AppendMessage {
            embeds: value.embeds,
        }
    }
}

impl From<crate::Masquerade> for Masquerade {
    fn from(value: crate::Masquerade) -> Self {
        Masquerade {
            name: value.name,
            avatar: value.avatar,
            colour: value.colour,
        }
    }
}

impl From<Masquerade> for crate::Masquerade {
    fn from(value: Masquerade) -> Self {
        crate::Masquerade {
            name: value.name,
            avatar: value.avatar,
            colour: value.colour,
        }
    }
}

impl From<crate::PolicyChange> for PolicyChange {
    fn from(value: crate::PolicyChange) -> Self {
        PolicyChange {
            created_time: value.created_time,
            effective_time: value.effective_time,
            description: value.description,
            url: value.url,
        }
    }
}

impl From<crate::Report> for Report {
    fn from(value: crate::Report) -> Self {
        Report {
            id: value.id,
            author_id: value.author_id,
            content: value.content,
            additional_context: value.additional_context,
            status: value.status,
            notes: value.notes,
        }
    }
}

impl crate::Snapshot {
    /// Convert to the v0 API model
    pub async fn into_v0(self) -> Snapshot {
        Snapshot {
            id: self.id,
            report_id: self.report_id,
            content: match self.content {
                crate::SnapshotContent::Message {
                    prior_context,
                    leading_context,
                    message,
                } => SnapshotContent::Message {
                    prior_context: prior_context
                        .into_iter()
                        .map(|message| message.into_model(None, None))
                        .collect(),
                    leading_context: leading_context
                        .into_iter()
                        .map(|message| message.into_model(None, None))
                        .collect(),
                    message: message.into_model(None, None),
                },
                crate::SnapshotContent::Server(server) => SnapshotContent::Server(server.into()),
                crate::SnapshotContent::User(user) => {
                    SnapshotContent::User(user.into_self(false).await)
                }
                crate::SnapshotContent::ReporterMessage { message, context } => {
                    SnapshotContent::ReporterMessage { message, context }
                }
            },
        }
    }
}

impl From<crate::ServerBan> for ServerBan {
    fn from(value: crate::ServerBan) -> Self {
        ServerBan {
            id: value.id.into(),
            reason: value.reason,
        }
    }
}

impl From<crate::Member> for Member {
    fn from(value: crate::Member) -> Self {
        Member {
            id: value.id.into(),
            joined_at: value.joined_at,
            nickname: value.nickname,
            pronouns: value.pronouns,
            avatar: value.avatar.map(|f| f.into()),
            roles: value.roles,
            timeout: value.timeout,
            can_publish: value.can_publish,
            can_receive: value.can_receive,
        }
    }
}

impl From<Member> for crate::Member {
    fn from(value: Member) -> crate::Member {
        crate::Member {
            id: value.id.into(),
            joined_at: value.joined_at,
            nickname: value.nickname,
            pronouns: value.pronouns,
            avatar: value.avatar.map(|f| f.into()),
            roles: value.roles,
            timeout: value.timeout,
            can_publish: value.can_publish,
            can_receive: value.can_receive,
        }
    }
}

impl From<crate::PartialMember> for PartialMember {
    fn from(value: crate::PartialMember) -> Self {
        PartialMember {
            id: value.id.map(|id| id.into()),
            joined_at: value.joined_at,
            nickname: value.nickname,
            pronouns: value.pronouns,
            avatar: value.avatar.map(|f| f.into()),
            roles: value.roles,
            timeout: value.timeout,
            can_publish: value.can_publish,
            can_receive: value.can_receive,
        }
    }
}

impl From<PartialMember> for crate::PartialMember {
    fn from(value: PartialMember) -> crate::PartialMember {
        crate::PartialMember {
            id: value.id.map(|id| id.into()),
            joined_at: value.joined_at,
            nickname: value.nickname,
            pronouns: value.pronouns,
            avatar: value.avatar.map(|f| f.into()),
            roles: value.roles,
            timeout: value.timeout,
            can_publish: value.can_publish,
            can_receive: value.can_receive,
        }
    }
}

impl From<crate::MemberCompositeKey> for MemberCompositeKey {
    fn from(value: crate::MemberCompositeKey) -> Self {
        MemberCompositeKey {
            server: value.server,
            user: value.user,
        }
    }
}

impl From<MemberCompositeKey> for crate::MemberCompositeKey {
    fn from(value: MemberCompositeKey) -> crate::MemberCompositeKey {
        crate::MemberCompositeKey {
            server: value.server,
            user: value.user,
        }
    }
}

impl From<crate::FieldsMember> for FieldsMember {
    fn from(value: crate::FieldsMember) -> Self {
        match value {
            crate::FieldsMember::Avatar => FieldsMember::Avatar,
            crate::FieldsMember::Nickname => FieldsMember::Nickname,
            crate::FieldsMember::Pronouns => FieldsMember::Pronouns,
            crate::FieldsMember::Roles => FieldsMember::Roles,
            crate::FieldsMember::Timeout => FieldsMember::Timeout,
            crate::FieldsMember::CanReceive => FieldsMember::CanReceive,
            crate::FieldsMember::CanPublish => FieldsMember::CanPublish,
            crate::FieldsMember::JoinedAt => FieldsMember::JoinedAt,
            crate::FieldsMember::VoiceChannel => FieldsMember::VoiceChannel,
        }
    }
}

impl From<FieldsMember> for crate::FieldsMember {
    fn from(value: FieldsMember) -> crate::FieldsMember {
        match value {
            FieldsMember::Avatar => crate::FieldsMember::Avatar,
            FieldsMember::Nickname => crate::FieldsMember::Nickname,
            FieldsMember::Pronouns => crate::FieldsMember::Pronouns,
            FieldsMember::Roles => crate::FieldsMember::Roles,
            FieldsMember::Timeout => crate::FieldsMember::Timeout,
            FieldsMember::CanReceive => crate::FieldsMember::CanReceive,
            FieldsMember::CanPublish => crate::FieldsMember::CanPublish,
            FieldsMember::JoinedAt => crate::FieldsMember::JoinedAt,
            FieldsMember::VoiceChannel => crate::FieldsMember::VoiceChannel,
        }
    }
}

impl From<crate::RemovalIntention> for RemovalIntention {
    fn from(value: crate::RemovalIntention) -> Self {
        match value {
            crate::RemovalIntention::Ban => RemovalIntention::Ban,
            crate::RemovalIntention::Kick => RemovalIntention::Kick,
            crate::RemovalIntention::Leave => RemovalIntention::Leave,
        }
    }
}

impl From<crate::Server> for Server {
    fn from(value: crate::Server) -> Self {
        Server {
            id: value.id,
            owner: value.owner,
            name: value.name,
            description: value.description,
            channels: value.channels,
            categories: value
                .categories
                .map(|categories| categories.into_iter().map(|v| v.into()).collect()),
            system_messages: value.system_messages.map(|v| v.into()),
            roles: value
                .roles
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            default_permissions: value.default_permissions,
            icon: value.icon.map(|f| f.into()),
            banner: value.banner.map(|f| f.into()),
            flags: value.flags.unwrap_or_default() as u32,
            nsfw: value.nsfw,
            analytics: value.analytics,
            discoverable: value.discoverable,
            discovery_requested: value.discovery_requested,
            boost_count: value.boost_count.unwrap_or_default() as u32,
            boost_tier: value.boost_tier.unwrap_or_default() as u32,
            voice_region: value.voice_region,
        }
    }
}

impl From<Server> for crate::Server {
    fn from(value: Server) -> crate::Server {
        crate::Server {
            id: value.id,
            owner: value.owner,
            name: value.name,
            description: value.description,
            channels: value.channels,
            categories: value
                .categories
                .map(|categories| categories.into_iter().map(|v| v.into()).collect()),
            system_messages: value.system_messages.map(|v| v.into()),
            roles: value
                .roles
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            default_permissions: value.default_permissions,
            icon: value.icon.map(|f| f.into()),
            banner: value.banner.map(|f| f.into()),
            flags: Some(value.flags as i32),
            nsfw: value.nsfw,
            analytics: value.analytics,
            discoverable: value.discoverable,
            discovery_requested: value.discovery_requested,
            boost_count: Some(value.boost_count as i32),
            boost_tier: Some(value.boost_tier as i32),
            voice_region: value.voice_region,
        }
    }
}

impl From<crate::PartialServer> for PartialServer {
    fn from(value: crate::PartialServer) -> Self {
        PartialServer {
            id: value.id,
            owner: value.owner,
            name: value.name,
            description: value.description,
            channels: value.channels,
            categories: value
                .categories
                .map(|categories| categories.into_iter().map(|v| v.into()).collect()),
            system_messages: value.system_messages.map(|v| v.into()),
            roles: value
                .roles
                .map(|roles| roles.into_iter().map(|(k, v)| (k, v.into())).collect()),
            default_permissions: value.default_permissions,
            icon: value.icon.map(|f| f.into()),
            banner: value.banner.map(|f| f.into()),
            flags: value.flags.map(|v| v as u32),
            nsfw: value.nsfw,
            analytics: value.analytics,
            discoverable: value.discoverable,
            discovery_requested: value.discovery_requested,
            boost_count: value.boost_count.map(|v| v as u32),
            boost_tier: value.boost_tier.map(|v| v as u32),
            voice_region: value.voice_region,
        }
    }
}

impl From<PartialServer> for crate::PartialServer {
    fn from(value: PartialServer) -> crate::PartialServer {
        crate::PartialServer {
            id: value.id,
            owner: value.owner,
            name: value.name,
            description: value.description,
            channels: value.channels,
            categories: value
                .categories
                .map(|categories| categories.into_iter().map(|v| v.into()).collect()),
            system_messages: value.system_messages.map(|v| v.into()),
            roles: value
                .roles
                .map(|roles| roles.into_iter().map(|(k, v)| (k, v.into())).collect()),
            default_permissions: value.default_permissions,
            icon: value.icon.map(|f| f.into()),
            banner: value.banner.map(|f| f.into()),
            flags: value.flags.map(|v| v as i32),
            nsfw: value.nsfw,
            analytics: value.analytics,
            discoverable: value.discoverable,
            discovery_requested: value.discovery_requested,
            boost_count: value.boost_count.map(|v| v as i32),
            boost_tier: value.boost_tier.map(|v| v as i32),
            voice_region: value.voice_region,
        }
    }
}

impl From<crate::FieldsServer> for FieldsServer {
    fn from(value: crate::FieldsServer) -> Self {
        match value {
            crate::FieldsServer::Banner => FieldsServer::Banner,
            crate::FieldsServer::Categories => FieldsServer::Categories,
            crate::FieldsServer::Description => FieldsServer::Description,
            crate::FieldsServer::Icon => FieldsServer::Icon,
            crate::FieldsServer::SystemMessages => FieldsServer::SystemMessages,
            crate::FieldsServer::VoiceRegion => FieldsServer::VoiceRegion,
        }
    }
}

impl From<FieldsServer> for crate::FieldsServer {
    fn from(value: FieldsServer) -> crate::FieldsServer {
        match value {
            FieldsServer::Banner => crate::FieldsServer::Banner,
            FieldsServer::Categories => crate::FieldsServer::Categories,
            FieldsServer::Description => crate::FieldsServer::Description,
            FieldsServer::Icon => crate::FieldsServer::Icon,
            FieldsServer::SystemMessages => crate::FieldsServer::SystemMessages,
            FieldsServer::VoiceRegion => crate::FieldsServer::VoiceRegion,
        }
    }
}

impl From<crate::Category> for Category {
    fn from(value: crate::Category) -> Self {
        Category {
            id: value.id,
            title: value.title,
            channels: value.channels,
        }
    }
}

impl From<Category> for crate::Category {
    fn from(value: Category) -> Self {
        crate::Category {
            id: value.id,
            title: value.title,
            channels: value.channels,
        }
    }
}

impl From<crate::SystemMessageChannels> for SystemMessageChannels {
    fn from(value: crate::SystemMessageChannels) -> Self {
        SystemMessageChannels {
            user_joined: value.user_joined,
            user_left: value.user_left,
            user_kicked: value.user_kicked,
            user_banned: value.user_banned,
        }
    }
}

impl From<SystemMessageChannels> for crate::SystemMessageChannels {
    fn from(value: SystemMessageChannels) -> Self {
        crate::SystemMessageChannels {
            user_joined: value.user_joined,
            user_left: value.user_left,
            user_kicked: value.user_kicked,
            user_banned: value.user_banned,
        }
    }
}

impl From<crate::Role> for Role {
    fn from(value: crate::Role) -> Self {
        Role {
            id: value.id,
            name: value.name,
            permissions: value.permissions,
            colour: value.colour,
            hoist: value.hoist,
            rank: value.rank,
            icon: value.icon.map(|f| f.into()),
        }
    }
}

impl From<Role> for crate::Role {
    fn from(value: Role) -> crate::Role {
        crate::Role {
            id: value.id,
            name: value.name,
            permissions: value.permissions,
            colour: value.colour,
            hoist: value.hoist,
            rank: value.rank,
            icon: value.icon.map(|f| f.into()),
        }
    }
}

impl From<crate::PartialRole> for PartialRole {
    fn from(value: crate::PartialRole) -> Self {
        PartialRole {
            id: value.id,
            name: value.name,
            permissions: value.permissions,
            colour: value.colour,
            hoist: value.hoist,
            rank: value.rank,
            icon: value.icon.map(|f| f.into()),
        }
    }
}

impl From<PartialRole> for crate::PartialRole {
    fn from(value: PartialRole) -> crate::PartialRole {
        crate::PartialRole {
            id: value.id,
            name: value.name,
            permissions: value.permissions,
            colour: value.colour,
            hoist: value.hoist,
            rank: value.rank,
            icon: value.icon.map(|f| f.into()),
        }
    }
}

impl From<crate::FieldsRole> for FieldsRole {
    fn from(value: crate::FieldsRole) -> Self {
        match value {
            crate::FieldsRole::Colour => FieldsRole::Colour,
            crate::FieldsRole::Icon => FieldsRole::Icon,
        }
    }
}

impl From<FieldsRole> for crate::FieldsRole {
    fn from(value: FieldsRole) -> Self {
        match value {
            FieldsRole::Colour => crate::FieldsRole::Colour,
            FieldsRole::Icon => crate::FieldsRole::Icon,
        }
    }
}

impl crate::User {
    pub async fn into<'a, P>(self, db: &Database, perspective: P) -> User
    where
        P: Into<Option<&'a crate::User>>,
    {
        let perspective = perspective.into();
        let (relationship, relationship_note, can_see_profile) = if self.bot.is_some() {
            (RelationshipStatus::None, None, true)
        } else if let Some(perspective) = perspective {
            let mut query = DatabasePermissionQuery::new(db, perspective).user(&self);

            if perspective.id == self.id {
                (RelationshipStatus::User, None, true)
            } else {
                let relation = perspective
                    .relations
                    .as_ref()
                    .and_then(|relations| {
                        relations
                            .iter()
                            .find(|relationship| relationship.id == self.id)
                    });

                (
                    relation
                        .map(|relationship| relationship.status.clone().into())
                        .unwrap_or_default(),
                    relation.and_then(|relationship| relationship.note.clone()),
                    calculate_user_permissions(&mut query)
                        .await
                        .has_user_permission(UserPermission::ViewProfile),
                )
            }
        } else {
            (RelationshipStatus::None, None, false)
        };

        let badges = self.get_badges().await;

        User {
            username: self.username,
            discriminator: self.discriminator,
            display_name: self.display_name,
            pronouns: self.pronouns,
            avatar: self.avatar.map(|file| file.into()),
            relations: if let Some(crate::User { id, .. }) = perspective {
                if id == &self.id {
                    self.relations
                        .unwrap_or_default()
                        .into_iter()
                        .map(|relation| relation.into())
                        .collect()
                } else {
                    vec![]
                }
            } else {
                vec![]
            },
            badges,
            online: can_see_profile
                && revolt_presence::is_online(&self.id).await
                && !matches!(
                    self.status,
                    Some(crate::UserStatus {
                        presence: Some(crate::Presence::Invisible),
                        ..
                    })
                ),
            status: if can_see_profile {
                self.status.and_then(|status| status.into(true))
            } else {
                None
            },
            connections: if can_see_profile {
                self.connections
                    .map(|list| list.into_iter().map(Into::into).collect())
                    .unwrap_or_default()
            } else {
                vec![]
            },
            flags: self.flags.unwrap_or_default() as u32,
            privileged: self.privileged,
            bot: self.bot.map(|bot| bot.into()),
            e2ee_enabled: self.e2ee_enabled,
            profile_visibility: None,
            relationship,
            relationship_note,
            id: self.id,
        }
    }

    /// Convert user object into user model assuming mutual connection
    ///
    /// Relations will never be included, i.e. when we process ourselves
    pub async fn into_known<'a, P>(self, perspective: P, is_online: bool) -> User
    where
        P: Into<Option<&'a crate::User>>,
    {
        let perspective = perspective.into();
        let (relationship, relationship_note, can_see_profile) = if self.bot.is_some() {
            (RelationshipStatus::None, None, true)
        } else if let Some(perspective) = perspective {
            if perspective.id == self.id {
                (RelationshipStatus::User, None, true)
            } else {
                let relation = perspective
                    .relations
                    .as_ref()
                    .and_then(|relations| {
                        relations
                            .iter()
                            .find(|relationship| relationship.id == self.id)
                    });

                let relationship: RelationshipStatus = relation
                    .map(|relationship| relationship.status.clone().into())
                    .unwrap_or_default();

                let can_see_profile = relationship != RelationshipStatus::BlockedOther;
                (
                    relationship,
                    relation.and_then(|relationship| relationship.note.clone()),
                    can_see_profile,
                )
            }
        } else {
            (RelationshipStatus::None, None, false)
        };

        let badges = self.get_badges().await;

        User {
            username: self.username,
            discriminator: self.discriminator,
            display_name: self.display_name,
            pronouns: self.pronouns,
            avatar: self.avatar.map(|file| file.into()),
            relations: vec![],
            badges,
            online: can_see_profile
                && is_online
                && !matches!(
                    self.status,
                    Some(crate::UserStatus {
                        presence: Some(crate::Presence::Invisible),
                        ..
                    })
                ),
            status: if can_see_profile {
                self.status.and_then(|status| status.into(true))
            } else {
                None
            },
            connections: if can_see_profile {
                self.connections
                    .map(|list| list.into_iter().map(Into::into).collect())
                    .unwrap_or_default()
            } else {
                vec![]
            },
            flags: self.flags.unwrap_or_default() as u32,
            privileged: self.privileged,
            bot: self.bot.map(|bot| bot.into()),
            e2ee_enabled: self.e2ee_enabled,
            profile_visibility: None,
            relationship,
            relationship_note,
            id: self.id,
        }
    }

    /// Convert user object into user model without presence information
    pub async fn into_known_static(self, is_online: bool) -> User {
        let badges = self.get_badges().await;

        User {
            username: self.username,
            discriminator: self.discriminator,
            display_name: self.display_name,
            pronouns: self.pronouns,
            avatar: self.avatar.map(|file| file.into()),
            relations: vec![],
            badges,
            online: is_online
                && !matches!(
                    self.status,
                    Some(crate::UserStatus {
                        presence: Some(crate::Presence::Invisible),
                        ..
                    })
                ),
            status: self.status.and_then(|status| status.into(true)),
            connections: self
                .connections
                .map(|list| list.into_iter().map(Into::into).collect())
                .unwrap_or_default(),
            flags: self.flags.unwrap_or_default() as u32,
            privileged: self.privileged,
            bot: self.bot.map(|bot| bot.into()),
            e2ee_enabled: self.e2ee_enabled,
            profile_visibility: None,
            relationship: RelationshipStatus::None, // events client will populate this from cache
            relationship_note: None,
            id: self.id,
        }
    }

    pub async fn into_self(self, force_online: bool) -> User {
        let badges = self.get_badges().await;

        User {
            username: self.username,
            discriminator: self.discriminator,
            display_name: self.display_name,
            pronouns: self.pronouns,
            avatar: self.avatar.map(|file| file.into()),
            relations: self
                .relations
                .map(|relationships| {
                    relationships
                        .into_iter()
                        .map(|relationship| relationship.into())
                        .collect()
                })
                .unwrap_or_default(),
            badges,
            online: (force_online || revolt_presence::is_online(&self.id).await)
                && !matches!(
                    self.status,
                    Some(crate::UserStatus {
                        presence: Some(crate::Presence::Invisible),
                        ..
                    })
                ),
            status: self.status.and_then(|status| status.into(true)),
            connections: self
                .connections
                .map(|list| list.into_iter().map(Into::into).collect())
                .unwrap_or_default(),
            flags: self.flags.unwrap_or_default() as u32,
            privileged: self.privileged,
            bot: self.bot.map(|bot| bot.into()),
            e2ee_enabled: self.e2ee_enabled,
            profile_visibility: self.profile_visibility.map(Into::into),
            relationship: RelationshipStatus::User,
            relationship_note: None,
            id: self.id,
        }
    }

    pub fn as_author_for_system(&self) -> MessageAuthor {
        MessageAuthor::System {
            username: &self.username,
            avatar: self.avatar.as_ref().map(|file| file.id.as_ref()),
        }
    }
}

impl From<User> for crate::User {
    fn from(value: User) -> crate::User {
        crate::User {
            id: value.id,
            username: value.username,
            discriminator: value.discriminator,
            display_name: value.display_name,
            pronouns: value.pronouns,
            avatar: value.avatar.map(Into::into),
            relations: None,
            badges: Some(value.badges as i32),
            status: value.status.map(Into::into),
            profile: None,
            profile_visibility: value.profile_visibility.map(Into::into),
            connections: None,
            flags: Some(value.flags as i32),
            privileged: value.privileged,
            bot: value.bot.map(Into::into),
            e2ee_enabled: value.e2ee_enabled,
            suspended_until: None,
            last_acknowledged_policy_change: Timestamp::UNIX_EPOCH,
        }
    }
}

impl From<crate::PartialUser> for PartialUser {
    fn from(value: crate::PartialUser) -> Self {
        PartialUser {
            username: value.username,
            discriminator: value.discriminator,
            display_name: value.display_name,
            pronouns: value.pronouns,
            avatar: value.avatar.map(|file| file.into()),
            relations: value.relations.map(|relationships| {
                relationships
                    .into_iter()
                    .map(|relationship| relationship.into())
                    .collect()
            }),
            badges: value.badges.map(|badges| badges as u32),
            status: value.status.and_then(|status| status.into(false)),
            connections: value
                .connections
                .map(|list| list.into_iter().map(Into::into).collect()),
            flags: value.flags.map(|flags| flags as u32),
            privileged: value.privileged,
            bot: value.bot.map(|bot| bot.into()),
            e2ee_enabled: value.e2ee_enabled,
            profile_visibility: None,
            relationship: None,
            relationship_note: None,
            online: None,
            id: value.id,
        }
    }
}

impl From<FieldsUser> for crate::FieldsUser {
    fn from(value: FieldsUser) -> Self {
        match value {
            FieldsUser::Avatar => crate::FieldsUser::Avatar,
            FieldsUser::ProfileBackground => crate::FieldsUser::ProfileBackground,
            FieldsUser::ProfileContent => crate::FieldsUser::ProfileContent,
            FieldsUser::ProfileLinks => crate::FieldsUser::ProfileLinks,
            FieldsUser::StatusPresence => crate::FieldsUser::StatusPresence,
            FieldsUser::StatusActivity => crate::FieldsUser::StatusActivity,
            FieldsUser::StatusText => crate::FieldsUser::StatusText,
            FieldsUser::DisplayName => crate::FieldsUser::DisplayName,
            FieldsUser::Pronouns => crate::FieldsUser::Pronouns,
            FieldsUser::Connections => crate::FieldsUser::Connections,

            FieldsUser::Internal => crate::FieldsUser::None,
        }
    }
}

impl From<crate::FieldsUser> for FieldsUser {
    fn from(value: crate::FieldsUser) -> Self {
        match value {
            crate::FieldsUser::Avatar => FieldsUser::Avatar,
            crate::FieldsUser::ProfileBackground => FieldsUser::ProfileBackground,
            crate::FieldsUser::ProfileContent => FieldsUser::ProfileContent,
            crate::FieldsUser::ProfileLinks => FieldsUser::ProfileLinks,
            crate::FieldsUser::StatusPresence => FieldsUser::StatusPresence,
            crate::FieldsUser::StatusActivity => FieldsUser::StatusActivity,
            crate::FieldsUser::StatusText => FieldsUser::StatusText,
            crate::FieldsUser::DisplayName => FieldsUser::DisplayName,
            crate::FieldsUser::Pronouns => FieldsUser::Pronouns,
            crate::FieldsUser::Connections => FieldsUser::Connections,

            crate::FieldsUser::Suspension => FieldsUser::Internal,
            crate::FieldsUser::None => FieldsUser::Internal,
        }
    }
}

impl From<crate::RelationshipStatus> for RelationshipStatus {
    fn from(value: crate::RelationshipStatus) -> Self {
        match value {
            crate::RelationshipStatus::None => RelationshipStatus::None,
            crate::RelationshipStatus::User => RelationshipStatus::User,
            crate::RelationshipStatus::Friend => RelationshipStatus::Friend,
            crate::RelationshipStatus::Outgoing => RelationshipStatus::Outgoing,
            crate::RelationshipStatus::Incoming => RelationshipStatus::Incoming,
            crate::RelationshipStatus::Blocked => RelationshipStatus::Blocked,
            crate::RelationshipStatus::BlockedOther => RelationshipStatus::BlockedOther,
        }
    }
}

impl From<crate::ProfileVisibility> for ProfileVisibility {
    fn from(value: crate::ProfileVisibility) -> Self {
        match value {
            crate::ProfileVisibility::Everyone => ProfileVisibility::Everyone,
            crate::ProfileVisibility::Friends => ProfileVisibility::Friends,
        }
    }
}

impl From<ProfileVisibility> for crate::ProfileVisibility {
    fn from(value: ProfileVisibility) -> Self {
        match value {
            ProfileVisibility::Everyone => crate::ProfileVisibility::Everyone,
            ProfileVisibility::Friends => crate::ProfileVisibility::Friends,
        }
    }
}

impl From<crate::Relationship> for Relationship {
    fn from(value: crate::Relationship) -> Self {
        Self {
            user_id: value.id,
            status: value.status.into(),
            note: value.note,
        }
    }
}

impl From<crate::Presence> for Presence {
    fn from(value: crate::Presence) -> Self {
        match value {
            crate::Presence::Online => Presence::Online,
            crate::Presence::Idle => Presence::Idle,
            crate::Presence::Focus => Presence::Focus,
            crate::Presence::Busy => Presence::Busy,
            crate::Presence::LookingForGroup => Presence::LookingForGroup,
            crate::Presence::LookingForMore => Presence::LookingForMore,
            crate::Presence::Invisible => Presence::Invisible,
        }
    }
}

impl From<Presence> for crate::Presence {
    fn from(value: Presence) -> crate::Presence {
        match value {
            Presence::Online => crate::Presence::Online,
            Presence::Idle => crate::Presence::Idle,
            Presence::Focus => crate::Presence::Focus,
            Presence::Busy => crate::Presence::Busy,
            Presence::LookingForGroup => crate::Presence::LookingForGroup,
            Presence::LookingForMore => crate::Presence::LookingForMore,
            Presence::Invisible => crate::Presence::Invisible,
        }
    }
}

impl crate::UserStatus {
    fn into(self, discard_invisible: bool) -> Option<UserStatus> {
        let status = UserStatus {
            text: self.text,
            presence: self.presence.and_then(|presence| {
                if discard_invisible && presence == crate::Presence::Invisible {
                    None
                } else {
                    Some(presence.into())
                }
            }),
            activity: self.activity.map(|activity| activity.into()),
        };

        if status.text.is_none() && status.presence.is_none() && status.activity.is_none() {
            None
        } else {
            Some(status)
        }
    }
}

impl From<UserStatus> for crate::UserStatus {
    fn from(value: UserStatus) -> crate::UserStatus {
        crate::UserStatus {
            text: value.text,
            presence: value.presence.map(|presence| presence.into()),
            activity: value.activity.map(|activity| activity.into()),
        }
    }
}

impl From<crate::UserActivity> for UserActivity {
    fn from(value: crate::UserActivity) -> Self {
        UserActivity {
            name: value.name,
            started_at: value.started_at,
        }
    }
}

impl From<UserActivity> for crate::UserActivity {
    fn from(value: UserActivity) -> crate::UserActivity {
        crate::UserActivity {
            name: value.name,
            started_at: value.started_at,
        }
    }
}

impl From<crate::ConnectionPlatform> for ConnectionPlatform {
    fn from(value: crate::ConnectionPlatform) -> Self {
        match value {
            crate::ConnectionPlatform::Twitch => ConnectionPlatform::Twitch,
            crate::ConnectionPlatform::YouTube => ConnectionPlatform::YouTube,
            crate::ConnectionPlatform::Kick => ConnectionPlatform::Kick,
        }
    }
}

impl From<ConnectionPlatform> for crate::ConnectionPlatform {
    fn from(value: ConnectionPlatform) -> crate::ConnectionPlatform {
        match value {
            ConnectionPlatform::Twitch => crate::ConnectionPlatform::Twitch,
            ConnectionPlatform::YouTube => crate::ConnectionPlatform::YouTube,
            ConnectionPlatform::Kick => crate::ConnectionPlatform::Kick,
        }
    }
}

impl From<crate::UserConnection> for UserConnection {
    fn from(value: crate::UserConnection) -> Self {
        UserConnection {
            platform: value.platform.into(),
            handle: value.handle,
            display_name: value.display_name,
            live: value.live,
            live_title: value.live_title,
            live_since: value.live_since,
        }
    }
}

impl From<UserConnection> for crate::UserConnection {
    fn from(value: UserConnection) -> crate::UserConnection {
        crate::UserConnection {
            platform: value.platform.into(),
            handle: value.handle,
            display_name: value.display_name,
            live: value.live,
            live_title: value.live_title,
            live_since: value.live_since,
        }
    }
}

impl From<crate::LinkPlatform> for LinkPlatform {
    fn from(value: crate::LinkPlatform) -> Self {
        match value {
            crate::LinkPlatform::Steam => LinkPlatform::Steam,
            crate::LinkPlatform::EpicGames => LinkPlatform::EpicGames,
            crate::LinkPlatform::Rockstar => LinkPlatform::Rockstar,
            crate::LinkPlatform::UbisoftConnect => LinkPlatform::UbisoftConnect,
            crate::LinkPlatform::Activision => LinkPlatform::Activision,
            crate::LinkPlatform::BattleNet => LinkPlatform::BattleNet,
            crate::LinkPlatform::Xbox => LinkPlatform::Xbox,
            crate::LinkPlatform::PlayStation => LinkPlatform::PlayStation,
            crate::LinkPlatform::Nintendo => LinkPlatform::Nintendo,
            crate::LinkPlatform::RiotGames => LinkPlatform::RiotGames,
            crate::LinkPlatform::EaApp => LinkPlatform::EaApp,
            crate::LinkPlatform::Gog => LinkPlatform::Gog,
            crate::LinkPlatform::GrindingGearGames => LinkPlatform::GrindingGearGames,
        }
    }
}

impl From<LinkPlatform> for crate::LinkPlatform {
    fn from(value: LinkPlatform) -> Self {
        match value {
            LinkPlatform::Steam => crate::LinkPlatform::Steam,
            LinkPlatform::EpicGames => crate::LinkPlatform::EpicGames,
            LinkPlatform::Rockstar => crate::LinkPlatform::Rockstar,
            LinkPlatform::UbisoftConnect => crate::LinkPlatform::UbisoftConnect,
            LinkPlatform::Activision => crate::LinkPlatform::Activision,
            LinkPlatform::BattleNet => crate::LinkPlatform::BattleNet,
            LinkPlatform::Xbox => crate::LinkPlatform::Xbox,
            LinkPlatform::PlayStation => crate::LinkPlatform::PlayStation,
            LinkPlatform::Nintendo => crate::LinkPlatform::Nintendo,
            LinkPlatform::RiotGames => crate::LinkPlatform::RiotGames,
            LinkPlatform::EaApp => crate::LinkPlatform::EaApp,
            LinkPlatform::Gog => crate::LinkPlatform::Gog,
            LinkPlatform::GrindingGearGames => crate::LinkPlatform::GrindingGearGames,
        }
    }
}

impl From<crate::ProfileLink> for ProfileLink {
    fn from(value: crate::ProfileLink) -> Self {
        ProfileLink {
            platform: value.platform.into(),
            handle: value.handle,
        }
    }
}

impl From<ProfileLink> for crate::ProfileLink {
    fn from(value: ProfileLink) -> Self {
        crate::ProfileLink {
            platform: value.platform.into(),
            handle: value.handle,
        }
    }
}

impl From<crate::UserProfile> for UserProfile {
    fn from(value: crate::UserProfile) -> Self {
        UserProfile {
            content: value.content,
            background: value.background.map(|file| file.into()),
            links: value.links.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<UserProfile> for crate::UserProfile {
    fn from(value: UserProfile) -> crate::UserProfile {
        crate::UserProfile {
            content: value.content,
            background: value.background.map(|file| file.into()),
            links: value.links.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<crate::BotInformation> for BotInformation {
    fn from(value: crate::BotInformation) -> Self {
        BotInformation {
            owner_id: value.owner,
        }
    }
}

impl From<BotInformation> for crate::BotInformation {
    fn from(value: BotInformation) -> crate::BotInformation {
        crate::BotInformation {
            owner: value.owner_id,
        }
    }
}

impl From<crate::FieldsMessage> for FieldsMessage {
    fn from(value: crate::FieldsMessage) -> Self {
        match value {
            crate::FieldsMessage::Pinned => FieldsMessage::Pinned,
            crate::FieldsMessage::Components => FieldsMessage::Components,
        }
    }
}
impl From<FieldsMessage> for crate::FieldsMessage {
    fn from(value: FieldsMessage) -> Self {
        match value {
            FieldsMessage::Pinned => crate::FieldsMessage::Pinned,
            FieldsMessage::Components => crate::FieldsMessage::Components,
        }
    }
}

impl From<VoiceInformation> for crate::VoiceInformation {
    fn from(value: VoiceInformation) -> Self {
        crate::VoiceInformation {
            max_users: value.max_users,
            disabled: value.disabled,
        }
    }
}

impl From<crate::VoiceInformation> for VoiceInformation {
    fn from(value: crate::VoiceInformation) -> Self {
        VoiceInformation {
            max_users: value.max_users,
            disabled: value.disabled,
        }
    }
}

impl From<crate::Account> for AccountInfo {
    fn from(item: crate::Account) -> Self {
        AccountInfo {
            id: item.id,
            email: item.email,
        }
    }
}

impl From<crate::MFATicket> for MFATicket {
    fn from(value: crate::MFATicket) -> Self {
        MFATicket {
            id: value.id,
            account_id: value.account_id,
            token: value.token,
            validated: value.validated,
            authorised: value.authorised,
            last_totp_code: value.last_totp_code,
        }
    }
}

impl From<crate::MultiFactorAuthentication> for MultiFactorStatus {
    fn from(item: crate::MultiFactorAuthentication) -> Self {
        MultiFactorStatus {
            // email_otp: item.enable_email_otp,
            // trusted_handover: item.enable_trusted_handover,
            // email_mfa: item.enable_email_mfa,
            totp_mfa: !item.totp_token.is_disabled(),
            // security_key_mfa: item.security_key_token.is_some(),
            recovery_active: !item.recovery_codes.is_empty(),
            ..Default::default()
        }
    }
}

impl From<crate::MFAMethod> for MFAMethod {
    fn from(value: crate::MFAMethod) -> Self {
        match value {
            crate::MFAMethod::Password => MFAMethod::Password,
            crate::MFAMethod::Recovery => MFAMethod::Recovery,
            crate::MFAMethod::Totp => MFAMethod::Totp,
        }
    }
}

impl From<crate::Session> for SessionInfo {
    fn from(item: crate::Session) -> Self {
        SessionInfo {
            id: item.id,
            name: item.name,
        }
    }
}

impl From<crate::Session> for Session {
    fn from(value: crate::Session) -> Self {
        Session {
            id: value.id,
            user_id: value.user_id,
            token: value.token,
            name: value.name,
            last_seen: value.last_seen,
            origin: value.origin,
            subscription: value.subscription.map(Into::into),
        }
    }
}

impl From<crate::WebPushSubscription> for WebPushSubscription {
    fn from(value: crate::WebPushSubscription) -> Self {
        WebPushSubscription {
            endpoint: value.endpoint,
            p256dh: value.p256dh,
            auth: value.auth,
        }
    }
}

impl From<WebPushSubscription> for crate::WebPushSubscription {
    fn from(value: WebPushSubscription) -> Self {
        crate::WebPushSubscription {
            endpoint: value.endpoint,
            p256dh: value.p256dh,
            auth: value.auth,
        }
    }
}

impl From<crate::E2EESignedKey> for E2EESignedKey {
    fn from(value: crate::E2EESignedKey) -> Self {
        E2EESignedKey {
            key_id: value.key_id,
            key: value.key,
            signature: value.signature,
        }
    }
}

impl From<E2EESignedKey> for crate::E2EESignedKey {
    fn from(value: E2EESignedKey) -> Self {
        crate::E2EESignedKey {
            key_id: value.key_id,
            key: value.key,
            signature: value.signature,
        }
    }
}

impl From<crate::E2EEContentType> for E2EEContentType {
    fn from(value: crate::E2EEContentType) -> Self {
        match value {
            crate::E2EEContentType::Olm => E2EEContentType::Olm,
            crate::E2EEContentType::MlsCommit => E2EEContentType::MlsCommit,
            crate::E2EEContentType::MlsWelcome => E2EEContentType::MlsWelcome,
            crate::E2EEContentType::MlsCtl => E2EEContentType::MlsCtl,
        }
    }
}

impl From<crate::E2EEEnvelope> for E2EEMessage {
    fn from(value: crate::E2EEEnvelope) -> Self {
        E2EEMessage {
            id: value.id,
            recipient_user_id: value.recipient_user_id,
            recipient_device_id: value.recipient_device_id,
            sender_user_id: value.sender_user_id,
            sender_device_id: value.sender_device_id,
            protocol_version: value.protocol_version,
            sequence: value.sequence,
            ciphertext: value.ciphertext,
            content_type: value.content_type.into(),
            group_id: value.group_id,
            epoch: value.epoch,
        }
    }
}

impl From<crate::BoostSource> for BoostSource {
    fn from(value: crate::BoostSource) -> Self {
        match value {
            crate::BoostSource::AdminGrant => BoostSource::AdminGrant,
            crate::BoostSource::Purchase => BoostSource::Purchase,
            crate::BoostSource::Subscription => BoostSource::Subscription,
        }
    }
}

impl From<crate::ServerBoost> for ServerBoost {
    fn from(value: crate::ServerBoost) -> Self {
        ServerBoost {
            id: value.id,
            user_id: value.user_id,
            server_id: value.server_id,
            source: value.source.into(),
            expires_at: value.expires_at,
            allocated_at: value.allocated_at,
        }
    }
}
