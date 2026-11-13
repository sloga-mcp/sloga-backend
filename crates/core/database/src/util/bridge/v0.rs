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
                // Calling is on for an unconfigured group, and clients read
                // call availability from this object, so always send one.
                voice: Some(voice.unwrap_or_default().into()),
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
                protected,
                protected_history,
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
                protected,
                protected_history: protected_history.map(|history| Box::new((*history).into())),
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
                force_sort,
                default_layout,
                default_auto_archive_minutes,
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
                force_sort,
                default_layout: default_layout.into(),
                default_auto_archive_minutes,
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
                protected,
                protected_history,
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
                protected,
                protected_history: protected_history.map(|history| Box::new((*history).into())),
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
                force_sort,
                default_layout,
                default_auto_archive_minutes,
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
                force_sort,
                default_layout: default_layout.into(),
                default_auto_archive_minutes,
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
            crate::ForumSortOrder::Alphabetical => ForumSortOrder::Alphabetical,
        }
    }
}

impl From<ForumSortOrder> for crate::ForumSortOrder {
    fn from(value: ForumSortOrder) -> Self {
        match value {
            ForumSortOrder::LatestActivity => crate::ForumSortOrder::LatestActivity,
            ForumSortOrder::CreationDate => crate::ForumSortOrder::CreationDate,
            ForumSortOrder::Alphabetical => crate::ForumSortOrder::Alphabetical,
        }
    }
}

impl From<crate::ForumLayout> for ForumLayout {
    fn from(value: crate::ForumLayout) -> Self {
        match value {
            crate::ForumLayout::Modern => ForumLayout::Modern,
            crate::ForumLayout::Classic => ForumLayout::Classic,
            crate::ForumLayout::ClassicPlus => ForumLayout::ClassicPlus,
        }
    }
}

impl From<ForumLayout> for crate::ForumLayout {
    fn from(value: ForumLayout) -> Self {
        match value {
            ForumLayout::Modern => crate::ForumLayout::Modern,
            ForumLayout::Classic => crate::ForumLayout::Classic,
            ForumLayout::ClassicPlus => crate::ForumLayout::ClassicPlus,
        }
    }
}

impl From<crate::ProtectedHistory> for ProtectedHistory {
    fn from(value: crate::ProtectedHistory) -> Self {
        ProtectedHistory {
            boundary: value.boundary,
            wipe: value.wipe.into(),
        }
    }
}

impl From<ProtectedHistory> for crate::ProtectedHistory {
    fn from(value: ProtectedHistory) -> Self {
        crate::ProtectedHistory {
            boundary: value.boundary,
            wipe: value.wipe.into(),
        }
    }
}

impl From<crate::HistoryWipe> for HistoryWipe {
    fn from(value: crate::HistoryWipe) -> Self {
        match value {
            crate::HistoryWipe::None => HistoryWipe::None,
            crate::HistoryWipe::Requested { at, by } => HistoryWipe::Requested { at, by },
            crate::HistoryWipe::Done { at, count } => HistoryWipe::Done { at, count },
        }
    }
}

impl From<HistoryWipe> for crate::HistoryWipe {
    fn from(value: HistoryWipe) -> Self {
        match value {
            HistoryWipe::None => crate::HistoryWipe::None,
            HistoryWipe::Requested { at, by } => crate::HistoryWipe::Requested { at, by },
            HistoryWipe::Done { at, count } => crate::HistoryWipe::Done { at, count },
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
            force_sort: value.force_sort,
            default_layout: value.default_layout.map(|layout| layout.into()),
            auto_archive_minutes: value.auto_archive_minutes,
            default_auto_archive_minutes: value.default_auto_archive_minutes,
            applied_tags: value.applied_tags,
            announcement: value.announcement,
            protected: value.protected,
            protected_history: value
                .protected_history
                .map(|history| Box::new((*history).into())),
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
            force_sort: value.force_sort,
            default_layout: value.default_layout.map(|layout| layout.into()),
            auto_archive_minutes: value.auto_archive_minutes,
            default_auto_archive_minutes: value.default_auto_archive_minutes,
            applied_tags: value.applied_tags,
            announcement: value.announcement,
            protected: value.protected,
            protected_history: value
                .protected_history
                .map(|history| Box::new((*history).into())),
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
            encrypted: self.encrypted.map(Into::into),
        }
    }
}

impl From<crate::EncryptedPayload> for EncryptedPayload {
    fn from(value: crate::EncryptedPayload) -> Self {
        EncryptedPayload {
            v: value.v,
            group_id: value.group_id,
            epoch: value.epoch,
            sender_device_id: value.sender_device_id,
            nonce: value.nonce,
            ciphertext: value.ciphertext,
            sig: value.sig,
            franking: value.franking,
        }
    }
}

impl From<EncryptedPayload> for crate::EncryptedPayload {
    fn from(value: EncryptedPayload) -> Self {
        crate::EncryptedPayload {
            v: value.v,
            group_id: value.group_id,
            epoch: value.epoch,
            sender_device_id: value.sender_device_id,
            nonce: value.nonce,
            ciphertext: value.ciphertext,
            sig: value.sig,
            franking: value.franking,
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
            encrypted: value.encrypted.map(Into::into),
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

impl From<crate::AuditLogEntry> for AuditLogEntry {
    fn from(value: crate::AuditLogEntry) -> Self {
        AuditLogEntry {
            id: value.id,
            server: value.server,
            actor: value.actor,
            action: value.action.into(),
            target: value.target,
            channel: value.channel,
            changes: value.changes.into_iter().map(Into::into).collect(),
            count: value.count,
            reason: value.reason,
        }
    }
}

impl From<AuditLogEntry> for crate::AuditLogEntry {
    fn from(value: AuditLogEntry) -> Self {
        crate::AuditLogEntry {
            id: value.id,
            server: value.server,
            actor: value.actor,
            action: value.action.into(),
            target: value.target,
            channel: value.channel,
            changes: value.changes.into_iter().map(Into::into).collect(),
            count: value.count,
            reason: value.reason,
        }
    }
}

impl From<crate::AuditLogChange> for AuditLogChange {
    fn from(value: crate::AuditLogChange) -> Self {
        AuditLogChange {
            key: value.key,
            old: value.old.map(Into::into),
            new: value.new.map(Into::into),
        }
    }
}

impl From<AuditLogChange> for crate::AuditLogChange {
    fn from(value: AuditLogChange) -> Self {
        crate::AuditLogChange {
            key: value.key,
            old: value.old.map(Into::into),
            new: value.new.map(Into::into),
        }
    }
}

impl From<crate::AuditValue> for AuditValue {
    fn from(value: crate::AuditValue) -> Self {
        match value {
            crate::AuditValue::String(value) => AuditValue::String(value),
            crate::AuditValue::Int(value) => AuditValue::Int(value),
            crate::AuditValue::Bool(value) => AuditValue::Bool(value),
            crate::AuditValue::StringList(value) => AuditValue::StringList(value),
        }
    }
}

impl From<AuditValue> for crate::AuditValue {
    fn from(value: AuditValue) -> Self {
        match value {
            AuditValue::String(value) => crate::AuditValue::String(value),
            AuditValue::Int(value) => crate::AuditValue::Int(value),
            AuditValue::Bool(value) => crate::AuditValue::Bool(value),
            AuditValue::StringList(value) => crate::AuditValue::StringList(value),
        }
    }
}

impl From<crate::AuditLogAction> for AuditLogAction {
    fn from(value: crate::AuditLogAction) -> Self {
        match value {
            crate::AuditLogAction::MemberKick => AuditLogAction::MemberKick,
            crate::AuditLogAction::MemberBanAdd => AuditLogAction::MemberBanAdd,
            crate::AuditLogAction::MemberBanRemove => AuditLogAction::MemberBanRemove,
            crate::AuditLogAction::MemberTimeout => AuditLogAction::MemberTimeout,
            crate::AuditLogAction::MemberTimeoutRemove => AuditLogAction::MemberTimeoutRemove,
            crate::AuditLogAction::MemberRoleUpdate => AuditLogAction::MemberRoleUpdate,
            crate::AuditLogAction::MemberUpdate => AuditLogAction::MemberUpdate,
            crate::AuditLogAction::MemberVoiceUpdate => AuditLogAction::MemberVoiceUpdate,
            crate::AuditLogAction::MemberMove => AuditLogAction::MemberMove,
            crate::AuditLogAction::MemberDisconnect => AuditLogAction::MemberDisconnect,
            crate::AuditLogAction::MessageDelete => AuditLogAction::MessageDelete,
            crate::AuditLogAction::MessageBulkDelete => AuditLogAction::MessageBulkDelete,
            crate::AuditLogAction::ChannelCreate => AuditLogAction::ChannelCreate,
            crate::AuditLogAction::ChannelUpdate => AuditLogAction::ChannelUpdate,
            crate::AuditLogAction::ChannelDelete => AuditLogAction::ChannelDelete,
            crate::AuditLogAction::ChannelOverwriteUpdate => AuditLogAction::ChannelOverwriteUpdate,
            crate::AuditLogAction::ServerPermissionsUpdate => {
                AuditLogAction::ServerPermissionsUpdate
            }
            crate::AuditLogAction::RoleCreate => AuditLogAction::RoleCreate,
            crate::AuditLogAction::RoleUpdate => AuditLogAction::RoleUpdate,
            crate::AuditLogAction::RoleDelete => AuditLogAction::RoleDelete,
            crate::AuditLogAction::RoleRanksUpdate => AuditLogAction::RoleRanksUpdate,
            crate::AuditLogAction::ServerUpdate => AuditLogAction::ServerUpdate,
            crate::AuditLogAction::ServerOwnerTransfer => AuditLogAction::ServerOwnerTransfer,
            crate::AuditLogAction::ProtectedSeatsUpdate => AuditLogAction::ProtectedSeatsUpdate,
            crate::AuditLogAction::ProtectedSeatRelease => AuditLogAction::ProtectedSeatRelease,
            crate::AuditLogAction::ChannelProtect => AuditLogAction::ChannelProtect,
            crate::AuditLogAction::ChannelHistoryWipe => AuditLogAction::ChannelHistoryWipe,
            crate::AuditLogAction::Unknown => AuditLogAction::Unknown,
        }
    }
}

impl From<AuditLogAction> for crate::AuditLogAction {
    fn from(value: AuditLogAction) -> Self {
        match value {
            AuditLogAction::MemberKick => crate::AuditLogAction::MemberKick,
            AuditLogAction::MemberBanAdd => crate::AuditLogAction::MemberBanAdd,
            AuditLogAction::MemberBanRemove => crate::AuditLogAction::MemberBanRemove,
            AuditLogAction::MemberTimeout => crate::AuditLogAction::MemberTimeout,
            AuditLogAction::MemberTimeoutRemove => crate::AuditLogAction::MemberTimeoutRemove,
            AuditLogAction::MemberRoleUpdate => crate::AuditLogAction::MemberRoleUpdate,
            AuditLogAction::MemberUpdate => crate::AuditLogAction::MemberUpdate,
            AuditLogAction::MemberVoiceUpdate => crate::AuditLogAction::MemberVoiceUpdate,
            AuditLogAction::MemberMove => crate::AuditLogAction::MemberMove,
            AuditLogAction::MemberDisconnect => crate::AuditLogAction::MemberDisconnect,
            AuditLogAction::MessageDelete => crate::AuditLogAction::MessageDelete,
            AuditLogAction::MessageBulkDelete => crate::AuditLogAction::MessageBulkDelete,
            AuditLogAction::ChannelCreate => crate::AuditLogAction::ChannelCreate,
            AuditLogAction::ChannelUpdate => crate::AuditLogAction::ChannelUpdate,
            AuditLogAction::ChannelDelete => crate::AuditLogAction::ChannelDelete,
            AuditLogAction::ChannelOverwriteUpdate => crate::AuditLogAction::ChannelOverwriteUpdate,
            AuditLogAction::ServerPermissionsUpdate => {
                crate::AuditLogAction::ServerPermissionsUpdate
            }
            AuditLogAction::RoleCreate => crate::AuditLogAction::RoleCreate,
            AuditLogAction::RoleUpdate => crate::AuditLogAction::RoleUpdate,
            AuditLogAction::RoleDelete => crate::AuditLogAction::RoleDelete,
            AuditLogAction::RoleRanksUpdate => crate::AuditLogAction::RoleRanksUpdate,
            AuditLogAction::ServerUpdate => crate::AuditLogAction::ServerUpdate,
            AuditLogAction::ServerOwnerTransfer => crate::AuditLogAction::ServerOwnerTransfer,
            AuditLogAction::ProtectedSeatsUpdate => crate::AuditLogAction::ProtectedSeatsUpdate,
            AuditLogAction::ProtectedSeatRelease => crate::AuditLogAction::ProtectedSeatRelease,
            AuditLogAction::ChannelProtect => crate::AuditLogAction::ChannelProtect,
            AuditLogAction::ChannelHistoryWipe => crate::AuditLogAction::ChannelHistoryWipe,
            AuditLogAction::Unknown => crate::AuditLogAction::Unknown,
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
            afk_channel_id: value.afk_channel_id,
            afk_timeout: value.afk_timeout,
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
            afk_channel_id: value.afk_channel_id,
            afk_timeout: value.afk_timeout,
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
            afk_channel_id: value.afk_channel_id,
            afk_timeout: value.afk_timeout,
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
            afk_channel_id: value.afk_channel_id,
            afk_timeout: value.afk_timeout,
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
            crate::FieldsServer::AfkChannel => FieldsServer::AfkChannel,
            crate::FieldsServer::AfkTimeout => FieldsServer::AfkTimeout,
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
            FieldsServer::AfkChannel => crate::FieldsServer::AfkChannel,
            FieldsServer::AfkTimeout => crate::FieldsServer::AfkTimeout,
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
        let now = crate::now_ms();
        let name_style = self.filtered_name_style(now);
        let cipher = self.public_cipher();

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
            name_style,
            cipher,
            perks: 0,
            custom_badge: self.custom_badge.map(|badge| CustomBadge {
                image: badge.image.into(),
                label: badge.label,
            }),
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
        let now = crate::now_ms();
        let name_style = self.filtered_name_style(now);
        let cipher = self.public_cipher();

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
            name_style,
            cipher,
            perks: 0,
            custom_badge: self.custom_badge.map(|badge| CustomBadge {
                image: badge.image.into(),
                label: badge.label,
            }),
            profile_visibility: None,
            relationship,
            relationship_note,
            id: self.id,
        }
    }

    /// Convert user object into user model without presence information
    pub async fn into_known_static(self, is_online: bool) -> User {
        let badges = self.get_badges().await;
        let now = crate::now_ms();
        let name_style = self.filtered_name_style(now);
        let cipher = self.public_cipher();

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
            name_style,
            cipher,
            perks: 0,
            custom_badge: self.custom_badge.map(|badge| CustomBadge {
                image: badge.image.into(),
                label: badge.label,
            }),
            profile_visibility: None,
            relationship: RelationshipStatus::None, // events client will populate this from cache
            relationship_note: None,
            id: self.id,
        }
    }

    pub async fn into_self(self, force_online: bool) -> User {
        let badges = self.get_badges().await;
        let now = crate::now_ms();
        let name_style = self.filtered_name_style(now);
        let cipher = self.public_cipher();
        let perks = self.perks(now);

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
            name_style,
            cipher,
            perks,
            custom_badge: self.custom_badge.map(|badge| CustomBadge {
                image: badge.image.into(),
                label: badge.label,
            }),
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
            referral_count: None,
            referral_pending: None,
            welcomed_at: None,
            supporter: None,
            dm_guard: None,
            name_style: value.name_style,
            cipher: value.cipher,
            custom_badge: value.custom_badge.map(|badge| crate::CustomBadge {
                image: badge.image.into(),
                label: badge.label,
            }),
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
            name_style: value.name_style,
            cipher: value.cipher,
            perks: None,
            custom_badge: value.custom_badge.map(|badge| CustomBadge {
                image: badge.image.into(),
                label: badge.label,
            }),
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
            FieldsUser::NameStyle => crate::FieldsUser::NameStyle,
            FieldsUser::CustomBadge => crate::FieldsUser::CustomBadge,
            FieldsUser::Cipher => crate::FieldsUser::Cipher,

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
            crate::FieldsUser::NameStyle => FieldsUser::NameStyle,
            crate::FieldsUser::CustomBadge => FieldsUser::CustomBadge,
            crate::FieldsUser::Cipher => FieldsUser::Cipher,

            crate::FieldsUser::Suspension => FieldsUser::Internal,
            crate::FieldsUser::Supporter => FieldsUser::Internal,
            crate::FieldsUser::ReferralPending => FieldsUser::Internal,
            crate::FieldsUser::WelcomedAt => FieldsUser::Internal,
            crate::FieldsUser::ReferralCount => FieldsUser::Internal,
            crate::FieldsUser::DmGuard => FieldsUser::Internal,
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
            kind: value.kind.map(Into::into),
        }
    }
}

impl From<WebPushSubscription> for crate::WebPushSubscription {
    fn from(value: WebPushSubscription) -> Self {
        crate::WebPushSubscription {
            endpoint: value.endpoint,
            p256dh: value.p256dh,
            auth: value.auth,
            kind: value.kind.map(Into::into),
        }
    }
}

impl From<crate::PushSubscriptionKind> for PushSubscriptionKind {
    fn from(value: crate::PushSubscriptionKind) -> Self {
        match value {
            crate::PushSubscriptionKind::UnifiedPush => PushSubscriptionKind::UnifiedPush,
        }
    }
}

impl From<PushSubscriptionKind> for crate::PushSubscriptionKind {
    fn from(value: PushSubscriptionKind) -> Self {
        match value {
            PushSubscriptionKind::UnifiedPush => crate::PushSubscriptionKind::UnifiedPush,
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
            committer: value.committer.map(Into::into),
            added: value.added.into_iter().map(Into::into).collect(),
            removed: value.removed.into_iter().map(Into::into).collect(),
            rejoin_intents: value.rejoin_intents.into_iter().map(Into::into).collect(),
            removed_reasons: value.removed_reasons.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<crate::MlsRemovalReason> for MlsRemovalReason {
    fn from(value: crate::MlsRemovalReason) -> Self {
        match value {
            crate::MlsRemovalReason::OwnUser => MlsRemovalReason::OwnUser,
            crate::MlsRemovalReason::PendingRemoval => MlsRemovalReason::PendingRemoval,
            crate::MlsRemovalReason::OffList => MlsRemovalReason::OffList,
            crate::MlsRemovalReason::Revoked => MlsRemovalReason::Revoked,
            crate::MlsRemovalReason::Rejoin => MlsRemovalReason::Rejoin,
            crate::MlsRemovalReason::PendingDevice => MlsRemovalReason::PendingDevice,
            crate::MlsRemovalReason::Idle => MlsRemovalReason::Idle,
            crate::MlsRemovalReason::Unknown => MlsRemovalReason::Unknown,
        }
    }
}

impl From<crate::MlsSignerLostCause> for MlsSignerLostCause {
    fn from(value: crate::MlsSignerLostCause) -> Self {
        match value {
            crate::MlsSignerLostCause::DeviceRevoked => MlsSignerLostCause::DeviceRevoked,
        }
    }
}

impl From<crate::MlsRemovedReason> for MlsRemovedReasonInfo {
    fn from(value: crate::MlsRemovedReason) -> Self {
        MlsRemovedReasonInfo {
            user_id: value.user_id,
            device_id: value.device_id,
            reason: value.reason.into(),
        }
    }
}

impl From<crate::MlsEnvelopeRejoinIntent> for MlsRejoinIntentInfo {
    fn from(value: crate::MlsEnvelopeRejoinIntent) -> Self {
        MlsRejoinIntentInfo {
            group_id: value.group_id,
            channel_id: value.channel_id,
            user_id: value.user_id,
            device_id: value.device_id,
            key_package_ref: value.key_package_ref,
            signature: value.signature,
            generation: value.generation,
            issued_at: value.issued_at,
        }
    }
}

impl From<crate::MlsGroupKind> for MlsGroupKind {
    fn from(value: crate::MlsGroupKind) -> Self {
        match value {
            crate::MlsGroupKind::Call => MlsGroupKind::Call,
            crate::MlsGroupKind::Text => MlsGroupKind::Text,
        }
    }
}

impl From<MlsGroupKind> for crate::MlsGroupKind {
    fn from(value: MlsGroupKind) -> Self {
        match value {
            MlsGroupKind::Call => crate::MlsGroupKind::Call,
            MlsGroupKind::Text => crate::MlsGroupKind::Text,
        }
    }
}

impl From<crate::MlsMemberDevice> for MlsMemberDevice {
    fn from(value: crate::MlsMemberDevice) -> Self {
        MlsMemberDevice {
            user_id: value.user_id,
            device_id: value.device_id,
        }
    }
}

impl From<MlsMemberDevice> for crate::MlsMemberDevice {
    fn from(value: MlsMemberDevice) -> Self {
        crate::MlsMemberDevice {
            user_id: value.user_id,
            device_id: value.device_id,
        }
    }
}

impl crate::MlsJoinIntent {
    /// Wire form of a stored join intent carried on a commit (design §8.1).
    /// The stored row has no channel id, so the caller passes the group's
    /// `channel_id`. `_id` and `created_at` are not sent.
    pub fn into_rejoin_intent_info(self, channel_id: &str) -> MlsRejoinIntentInfo {
        MlsRejoinIntentInfo {
            group_id: self.group_id,
            channel_id: channel_id.to_string(),
            user_id: self.user_id,
            device_id: self.device_id,
            key_package_ref: self.key_package_ref,
            signature: self.signature,
            generation: self.generation,
            issued_at: self.issued_at,
        }
    }
}

impl crate::MlsCommit {
    /// Wire form of a stored winning commit. `channel_id` is the commit's
    /// group's channel; it fills each rejoin intent's `channel_id`.
    pub fn into_commit_info(self, channel_id: &str) -> MlsCommitInfo {
        MlsCommitInfo {
            group_id: self.group_id,
            epoch: self.epoch,
            committer: self.committer.into(),
            commit: self.commit,
            added: self.added.into_iter().map(Into::into).collect(),
            removed: self.removed.into_iter().map(Into::into).collect(),
            rejoin_intents: self
                .rejoin_intents
                .into_iter()
                .map(|intent| intent.into_rejoin_intent_info(channel_id))
                .collect(),
            removed_reasons: self.removed_reasons.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<crate::MlsHistoryLink> for HistoryLinkWire {
    /// The GET row (design §3.14.5 "Wire"): `_id`, `size` and `created_at`
    /// are not sent
    fn from(value: crate::MlsHistoryLink) -> Self {
        HistoryLinkWire {
            group_id: value.group_id,
            epoch: value.epoch,
            prev_group_id: value.prev_group_id,
            prev_epoch: value.prev_epoch,
            nonce: value.nonce,
            ciphertext: value.ciphertext,
            writer_user_id: value.writer_user_id,
            writer_device_id: value.writer_device_id,
            signature: value.signature,
        }
    }
}

impl crate::MlsHistoryLink {
    /// The row for a PUT body. The caller supplies what the wire does not
    /// carry: `size` (the decoded ciphertext length it checked) and
    /// `created_at` (server-stamped). `_id` is derived from the body's
    /// holder and writer user. No validation happens here.
    pub fn from_wire(wire: HistoryLinkWire, size: i64, created_at: Timestamp) -> Self {
        crate::MlsHistoryLink {
            id: crate::MlsHistoryLink::composite_id(
                &wire.group_id,
                wire.epoch,
                &wire.writer_user_id,
            ),
            group_id: wire.group_id,
            epoch: wire.epoch,
            prev_group_id: wire.prev_group_id,
            prev_epoch: wire.prev_epoch,
            nonce: wire.nonce,
            ciphertext: wire.ciphertext,
            writer_user_id: wire.writer_user_id,
            writer_device_id: wire.writer_device_id,
            signature: wire.signature,
            size,
            created_at,
        }
    }
}

impl From<crate::MlsPendingRemoval> for MlsPendingRemovalInfo {
    fn from(value: crate::MlsPendingRemoval) -> Self {
        MlsPendingRemovalInfo {
            user_id: value.user_id,
            created_at: value.created_at,
        }
    }
}

impl From<crate::MlsMemberAdded> for MlsMemberAddedInfo {
    fn from(value: crate::MlsMemberAdded) -> Self {
        MlsMemberAddedInfo {
            user_id: value.user_id,
            device_id: value.device_id,
            epoch: value.epoch,
            at: value.at,
        }
    }
}

impl From<crate::MlsPendingDeviceRemoval> for MlsPendingDeviceRemovalInfo {
    fn from(value: crate::MlsPendingDeviceRemoval) -> Self {
        MlsPendingDeviceRemovalInfo {
            user_id: value.user_id,
            device_id: value.device_id,
            created_at: value.created_at,
        }
    }
}

impl From<crate::MlsSignerLost> for MlsSignerLostInfo {
    fn from(value: crate::MlsSignerLost) -> Self {
        MlsSignerLostInfo {
            user_id: value.user_id,
            device_id: value.device_id,
            cause: value.cause.into(),
            at: value.at,
        }
    }
}

impl crate::MlsGroup {
    /// The text-group state response for an UNSEATED caller (protected
    /// channels design §7.2, R24): `join_requests`,
    /// `pending_device_removals` and `signer_lost` stay empty, so the body
    /// is the S1 one whatever the row holds.
    /// `None` unless this is a Text group with a generation, so a Call group
    /// (or a corrupt Text row) can never be served as one.
    pub fn into_text_group_response(self) -> Option<ResponseTextGroup> {
        if self.kind != crate::MlsGroupKind::Text {
            return None;
        }

        Some(ResponseTextGroup {
            group_id: self.id,
            channel_id: self.channel_id,
            generation: self.generation?,
            current_epoch: self.current_epoch,
            members: self.members.into_iter().map(Into::into).collect(),
            pending_removals: self.pending_removals.into_iter().map(Into::into).collect(),
            member_added: self.member_added.into_iter().map(Into::into).collect(),
            join_requests: Vec::new(),
            pending_device_removals: Vec::new(),
            signer_lost: None,
        })
    }

    /// The text-group state response for a SEATED caller (design §6.3
    /// "Async Text join", §7.2): the unseated response plus
    /// `join_requests`, `pending_device_removals` and `signer_lost`.
    ///
    /// The route decides that the caller is seated and passes the stored
    /// intents of seated users that are still outstanding. Of those, only
    /// intents of THIS group that are newer than their device's
    /// `member_added.at` become `join_requests` (an older one is the intent
    /// that Add consumed), with `rejoin` set when the device holds a leaf.
    /// They are sorted by `created_at`, then device id, then user id.
    ///
    /// `signer_account_unavailable` is the route's read-time check of the
    /// signer user's account flags (#222): it reports a stored `signer_lost`
    /// with the cause `account_unavailable` and never creates one.
    pub fn into_text_group_response_for_seated(
        mut self,
        intents: Vec<crate::MlsJoinIntent>,
        signer_account_unavailable: bool,
    ) -> Option<ResponseTextGroup> {
        let mut join_requests: Vec<MlsJoinRequestInfo> = intents
            .into_iter()
            .filter(|intent| intent.group_id == self.id)
            .filter(|intent| {
                !self.member_added.iter().any(|added| {
                    added.user_id == intent.user_id
                        && added.device_id == intent.device_id
                        && added.at >= intent.created_at
                })
            })
            .map(|intent| MlsJoinRequestInfo {
                rejoin: self.has_member(&intent.user_id, &intent.device_id),
                user_id: intent.user_id,
                device_id: intent.device_id,
                generation: intent.generation,
                key_package_ref: intent.key_package_ref,
                signature: intent.signature,
                issued_at: intent.issued_at,
                created_at: intent.created_at,
            })
            .collect();
        join_requests.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.device_id.cmp(&b.device_id))
                .then_with(|| a.user_id.cmp(&b.user_id))
        });

        let pending_device_removals: Vec<MlsPendingDeviceRemovalInfo> =
            std::mem::take(&mut self.pending_device_removals)
                .into_iter()
                .map(Into::into)
                .collect();
        let signer_lost = self.signer_lost.take().map(|lost| {
            let mut info = MlsSignerLostInfo::from(lost);
            if signer_account_unavailable {
                info.cause = MlsSignerLostCause::AccountUnavailable;
            }
            info
        });

        Some(ResponseTextGroup {
            join_requests,
            pending_device_removals,
            signer_lost,
            ..self.into_text_group_response()?
        })
    }
}

impl From<crate::ChannelEntitlementSource> for ChannelEntitlementSource {
    fn from(value: crate::ChannelEntitlementSource) -> Self {
        match value {
            crate::ChannelEntitlementSource::AdminGrant => ChannelEntitlementSource::AdminGrant,
            crate::ChannelEntitlementSource::Prot => ChannelEntitlementSource::Prot,
            crate::ChannelEntitlementSource::Crowdfund => ChannelEntitlementSource::Crowdfund,
        }
    }
}

impl From<crate::ChannelEntitlementState> for ChannelEntitlementState {
    fn from(value: crate::ChannelEntitlementState) -> Self {
        match value {
            crate::ChannelEntitlementState::Active => ChannelEntitlementState::Active,
            crate::ChannelEntitlementState::Grace => ChannelEntitlementState::Grace,
            crate::ChannelEntitlementState::Frozen => ChannelEntitlementState::Frozen,
            crate::ChannelEntitlementState::Deleted => ChannelEntitlementState::Deleted,
        }
    }
}

impl From<crate::ChannelEntitlement> for ChannelEntitlement {
    fn from(value: crate::ChannelEntitlement) -> Self {
        ChannelEntitlement {
            id: value.id,
            channel_id: value.channel_id,
            server_id: value.server_id,
            source: value.source.into(),
            slot_cap: value.slot_cap,
            device_cap: value.device_cap,
            state: value.state.into(),
            granted_by: value.granted_by,
            created_at: value.created_at,
        }
    }
}

impl From<crate::SignedHandover> for SignedHandover {
    fn from(value: crate::SignedHandover) -> Self {
        SignedHandover {
            body: value.body,
            signature: value.signature,
        }
    }
}

impl From<SignedHandover> for crate::SignedHandover {
    fn from(value: SignedHandover) -> Self {
        crate::SignedHandover {
            body: value.body,
            signature: value.signature,
        }
    }
}

impl From<crate::SignedAuthority> for SignedAuthority {
    fn from(value: crate::SignedAuthority) -> Self {
        SignedAuthority {
            body: value.body,
            signature: value.signature,
        }
    }
}

impl From<SignedAuthority> for crate::SignedAuthority {
    fn from(value: SignedAuthority) -> Self {
        crate::SignedAuthority {
            body: value.body,
            signature: value.signature,
        }
    }
}

impl From<DataSeatList> for crate::SeatListSubmission {
    fn from(value: DataSeatList) -> Self {
        crate::SeatListSubmission {
            body: value.body,
            signature: value.signature,
            signer_device_id: value.signer_device_id,
            handover: value.handover.map(Into::into),
            authority: value.authority.map(Into::into),
        }
    }
}

impl From<crate::SeatList> for ChannelSeatListInfo {
    fn from(value: crate::SeatList) -> Self {
        ChannelSeatListInfo {
            version: value.version,
            body: value.body,
            signature: value.signature,
            signer_user_id: value.signer_user_id,
            signer_device_id: value.signer_device_id,
            handovers: value.handovers.into_iter().map(Into::into).collect(),
            authority: value.authority.map(Into::into),
        }
    }
}

impl From<crate::SeatReleaseCause> for SeatReleaseCauseInfo {
    fn from(value: crate::SeatReleaseCause) -> Self {
        match value {
            crate::SeatReleaseCause::OwnerUnseat => SeatReleaseCauseInfo::OwnerUnseat,
            crate::SeatReleaseCause::ServerRemoval => SeatReleaseCauseInfo::ServerRemoval,
            crate::SeatReleaseCause::AccessLost => SeatReleaseCauseInfo::AccessLost,
            crate::SeatReleaseCause::DeviceNeverJoined => SeatReleaseCauseInfo::DeviceNeverJoined,
        }
    }
}

impl crate::ChannelSeat {
    /// An active seat entry. `seated_without_access` is left unset: only the
    /// route can compute it, and only for the server owner (design §7.2).
    pub fn into_seat_info(self) -> ChannelSeatInfo {
        ChannelSeatInfo {
            user_id: self.user_id,
            seated_at: self.seated_at,
            seated_without_access: None,
        }
    }

    /// A cooling seat entry; `None` for a seat that was never released.
    /// `cause` is left unset: it is for the server owner only (design
    /// §7.2), so only [`Self::into_owner_cooling_info`] carries it.
    pub fn into_cooling_info(self) -> Option<ChannelSeatCoolingInfo> {
        Some(ChannelSeatCoolingInfo {
            user_id: self.user_id,
            released_at: self.released_at?,
            cooldown_until: self.cooldown_until?,
            cause: None,
        })
    }

    /// A cooling seat entry for the server owner: [`Self::into_cooling_info`]
    /// with `cause` from the stored `release_cause` (absent on a row
    /// released before S2)
    pub fn into_owner_cooling_info(self) -> Option<ChannelSeatCoolingInfo> {
        let cause = self.release_cause.map(Into::into);
        Some(ChannelSeatCoolingInfo {
            cause,
            ..self.into_cooling_info()?
        })
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

#[cfg(test)]
mod protected_channel_bridge_tests {
    use iso8601_timestamp::Timestamp;
    use revolt_models::v0;

    fn device(user_id: &str, fill: &str) -> crate::MlsMemberDevice {
        crate::MlsMemberDevice {
            user_id: user_id.to_string(),
            device_id: fill.repeat(32),
        }
    }

    fn text_group() -> crate::MlsGroup {
        crate::MlsGroup {
            id: format!("{}1", "0".repeat(63)),
            channel_id: "01JA0000000000000000CHANNEL".to_string(),
            open: true,
            created_by: device("01JA00000000000000000USERA", "a"),
            created_at: Timestamp::UNIX_EPOCH,
            current_epoch: 7,
            members: vec![device("01JA00000000000000000USERA", "a")],
            closed_at: None,
            superseded_by: None,
            kind: crate::MlsGroupKind::Text,
            generation: Some(2),
            seat_list_ad_sha256: Some("f".repeat(64)),
            pending_removals: vec![crate::MlsPendingRemoval {
                user_id: "01JA00000000000000000USERB".to_string(),
                created_at: Timestamp::UNIX_EPOCH,
            }],
            member_added: vec![crate::MlsMemberAdded {
                user_id: "01JA00000000000000000USERA".to_string(),
                device_id: "a".repeat(32),
                epoch: 5,
                at: Timestamp::UNIX_EPOCH,
            }],
            pending_device_removals: vec![],
            signer_lost: None,
            rejoin_readd: vec![],
            history_visible_at_create: None,
        }
    }

    /// S2-D29: a stored Welcome never reaches the wire commit. The
    /// bridged `MlsCommitInfo` has no `welcome` key and carries none of its
    /// bytes, whatever else the row holds
    #[test]
    fn commit_info_never_carries_the_welcome() {
        let welcome = "V0VMQ09NRVNFQ1JFVEJZVEVT".to_string();
        let commit = crate::MlsCommit {
            id: crate::MlsCommit::composite_id(&format!("{}1", "0".repeat(63)), 8),
            group_id: format!("{}1", "0".repeat(63)),
            epoch: 8,
            committer: device("01JA00000000000000000USERA", "a"),
            commit: "Y29tbWl0".to_string(),
            size: 6,
            added: vec![device("01JA00000000000000000USERC", "c")],
            removed: vec![],
            created_at: Timestamp::UNIX_EPOCH,
            rejoin_intents: vec![],
            removed_reasons: vec![],
            welcome: Some(welcome.clone()),
            history_visible: None,
        };
        assert!(serde_json::to_string(&commit).unwrap().contains(&welcome));

        let without = crate::MlsCommit {
            welcome: None,
            ..commit.clone()
        };
        let info = commit.into_commit_info("01JA0000000000000000CHANNEL");
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("welcome"), "{json}");
        assert!(!json.contains(&welcome), "{json}");
        assert_eq!(
            info,
            without.into_commit_info("01JA0000000000000000CHANNEL")
        );
    }

    /// S4 (design §2.5 "S4", DECISION): a commit's `history_visible` is
    /// never on the wire commit. The bridged `MlsCommitInfo` has no such key
    /// and is the same whatever the row holds
    ///
    /// Control: an `MlsCommitInfo.history_visible` filled from the row.
    #[test]
    fn commit_info_never_carries_history_visible() {
        let row = |history_visible| crate::MlsCommit {
            id: crate::MlsCommit::composite_id(&format!("{}1", "0".repeat(63)), 8),
            group_id: format!("{}1", "0".repeat(63)),
            epoch: 8,
            committer: device("01JA00000000000000000USERA", "a"),
            commit: "Y29tbWl0".to_string(),
            size: 6,
            added: vec![device("01JA00000000000000000USERC", "c")],
            removed: vec![],
            created_at: Timestamp::UNIX_EPOCH,
            rejoin_intents: vec![],
            removed_reasons: vec![],
            welcome: None,
            history_visible,
        };
        assert!(serde_json::to_string(&row(Some(true)))
            .unwrap()
            .contains(r#""history_visible":true"#));

        let unset = row(None).into_commit_info("01JA0000000000000000CHANNEL");
        for history_visible in [Some(true), Some(false)] {
            let info = row(history_visible).into_commit_info("01JA0000000000000000CHANNEL");
            let json = serde_json::to_string(&info).unwrap();
            assert!(!json.contains("history_visible"), "{json}");
            assert!(!json.contains("visible"), "{json}");
            assert_eq!(info, unset);
        }
    }

    /// The 5.9 `link_wire_json` vector as a row and back (design §2.8,
    /// §3.14.5): `from_wire` takes `size` and `created_at` from the caller
    /// and derives `_id`; the row bridges back to the identical wire bytes,
    /// without `_id`, `size` or `created_at`
    #[test]
    fn history_link_wire_and_row_convert_both_ways() {
        const LINK_WIRE_JSON: &str = r#"{"group_id":"6036022873e9088d763291333fd3aad4eed2efa4ad97edc74349494d0fa24ac3","epoch":8,"prev_group_id":"6036022873e9088d763291333fd3aad4eed2efa4ad97edc74349494d0fa24ac3","prev_epoch":7,"nonce":"yMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f","ciphertext":"zi8Wt3tUkiiujR/wXPLhtV/pSalw6ozn2nhFJIiSbRQfB3+IOC7lOdWFA7MD2NBTe8KPi9QWSVllGFNAeWpSEXWtQ1MnL2dyEWkzN8ICC60inCX4ZCK0gT5KHCef9fWF1FFBd8futwVIqGdV0qOUGDW2j9odwMCYArWtSBT7ITs3xBK65CWr9vr/Z/qROyQfmZJdq8nTILrpv8CBE/t6S4BsQCy5rDxaSKigsK+q5hDNV85ngjdZFnUYyUAI7PAoslSfLKsEjDuO/O7q1LRRtIfpYAxnDor8WKNEaXPZxEuUmmr9XqgH1tl7fEdLNXMXn133bo6Ji9jeCi2eYQsJua3Ru+aMxOe80c6CV3rKr353Ubn7kg01fmzkSVkSxfEF/Lf8VAG17E31K+Qy3V4zMNd5MeFKMZjJAEliZW6sQFtWCFPjG6dsjX4mTlchItpMrTt9hvs4o1JI3Qv5f8U8U1YFVMgSMvYd6TaWOnNHGWHxHIZaBwLAO0JS7FeXSZ7rgSFc2+LS5jLNFZBKs9MiF5KJeshsOiLbMz9FdSlkl9ehWOHsmkG77lnf6EPZkgPzPBJqnAiJ+PWCeyiEVahWihUw38odspgrVk/13m5KmK3SBADUMg","writer_user_id":"01HZXBBBBBBBBBBBBBBBBBBBBB","writer_device_id":"ffeeddccbbaa99887766554433221100","signature":"axkfh3Uwi6uZMXT6C47i3SBEUCTvDwiqCcWGob94L3B8AmBtYWeyayKENT4QwPPuBy1QzP7aAg92tblg+E73BQ"}"#;

        let wire: v0::HistoryLinkWire = serde_json::from_str(LINK_WIRE_JSON).unwrap();
        let created_at: Timestamp = serde_json::from_str(r#""2026-10-04T12:00:00.000Z""#).unwrap();
        let row = crate::MlsHistoryLink::from_wire(wire.clone(), 469, created_at);
        assert_eq!(
            row.id,
            "6036022873e9088d763291333fd3aad4eed2efa4ad97edc74349494d0fa24ac3:8:01HZXBBBBBBBBBBBBBBBBBBBBB"
        );
        assert_eq!(row.size, 469);
        assert_eq!(row.created_at, created_at);
        assert_eq!(
            (
                row.group_id.as_str(),
                row.epoch,
                row.prev_group_id.as_str(),
                row.prev_epoch,
                row.writer_device_id.as_str()
            ),
            (
                wire.group_id.as_str(),
                8,
                wire.prev_group_id.as_str(),
                7,
                "ffeeddccbbaa99887766554433221100"
            )
        );

        let back = v0::HistoryLinkWire::from(row);
        assert_eq!(back, wire);
        assert_eq!(serde_json::to_string(&back).unwrap(), LINK_WIRE_JSON);
    }

    /// `protected_history` and the wipe state cross the bridge unchanged in
    /// both directions, on the channel and on the partial
    #[test]
    fn protected_history_bridges_both_ways() {
        let at: Timestamp = serde_json::from_str(r#""2026-10-04T12:00:00.000Z""#).unwrap();
        for wipe in [
            crate::HistoryWipe::None,
            crate::HistoryWipe::Requested {
                at,
                by: "01JA00000000000000000USERA".to_string(),
            },
            crate::HistoryWipe::Done { at, count: 7 },
        ] {
            let history = crate::ProtectedHistory {
                boundary: "01J9Z3K4M5N6P7Q8R9S0T1V2W0".to_string(),
                wipe,
            };
            let channel = crate::Channel::TextChannel {
                id: "T".to_string(),
                server: "S".to_string(),
                name: "text".to_string(),
                description: None,
                icon: None,
                last_message_id: None,
                default_permissions: None,
                role_permissions: Default::default(),
                nsfw: false,
                spoiler: false,
                voice: None,
                slowmode: None,
                announcement: None,
                protected: true,
                protected_history: Some(Box::new(history.clone())),
            };
            let wire = v0::Channel::from(channel.clone());
            assert_eq!(
                serde_json::to_value(&wire).unwrap(),
                serde_json::to_value(&channel).unwrap(),
                "the v0 channel serializes like the stored one"
            );
            assert_eq!(crate::Channel::from(wire), channel);

            let partial = crate::PartialChannel {
                protected_history: Some(Box::new(history.clone())),
                ..Default::default()
            };
            let wire = v0::PartialChannel::from(partial.clone());
            assert_eq!(
                wire.protected_history,
                Some(Box::new(v0::ProtectedHistory::from(history)))
            );
            assert_eq!(crate::PartialChannel::from(wire), partial);
        }
    }

    /// New stored enum values map onto their v0 counterparts (W1-0 names)
    #[test]
    fn s2_stored_enums_map_to_v0() {
        for (stored, wire) in [
            (
                crate::MlsRemovalReason::PendingDevice,
                v0::MlsRemovalReason::PendingDevice,
            ),
            (crate::MlsRemovalReason::Idle, v0::MlsRemovalReason::Idle),
            (
                crate::MlsRemovalReason::Unknown,
                v0::MlsRemovalReason::Unknown,
            ),
        ] {
            assert_eq!(v0::MlsRemovalReason::from(stored), wire);
        }
        assert_eq!(
            v0::MlsSignerLostCause::from(crate::MlsSignerLostCause::DeviceRevoked),
            v0::MlsSignerLostCause::DeviceRevoked
        );
        for (stored, wire) in [
            (
                crate::SeatReleaseCause::OwnerUnseat,
                v0::SeatReleaseCauseInfo::OwnerUnseat,
            ),
            (
                crate::SeatReleaseCause::ServerRemoval,
                v0::SeatReleaseCauseInfo::ServerRemoval,
            ),
            (
                crate::SeatReleaseCause::AccessLost,
                v0::SeatReleaseCauseInfo::AccessLost,
            ),
            (
                crate::SeatReleaseCause::DeviceNeverJoined,
                v0::SeatReleaseCauseInfo::DeviceNeverJoined,
            ),
        ] {
            assert_eq!(v0::SeatReleaseCauseInfo::from(stored), wire);
            // Same snake_case value on the stored and the wire enum
            assert_eq!(
                serde_json::to_value(stored).unwrap(),
                serde_json::to_value(wire).unwrap()
            );
        }
    }

    #[test]
    fn only_a_text_group_with_a_generation_is_served_as_one() {
        let response = text_group().into_text_group_response().unwrap();
        assert_eq!(response.group_id, format!("{}1", "0".repeat(63)));
        assert_eq!(response.channel_id, "01JA0000000000000000CHANNEL");
        assert_eq!(response.generation, 2);
        assert_eq!(response.current_epoch, 7);
        assert_eq!(response.members[0].device_id, "a".repeat(32));
        assert_eq!(
            response.pending_removals[0].user_id,
            "01JA00000000000000000USERB"
        );
        assert_eq!(response.member_added[0].epoch, 5);

        let call = crate::MlsGroup {
            kind: crate::MlsGroupKind::Call,
            ..text_group()
        };
        assert_eq!(call.into_text_group_response(), None);

        let corrupt = crate::MlsGroup {
            generation: None,
            ..text_group()
        };
        assert_eq!(corrupt.into_text_group_response(), None);
    }

    #[test]
    fn seat_list_conversions_keep_every_field() {
        let submission: crate::SeatListSubmission = v0::DataSeatList {
            body: "body".to_string(),
            signature: "c2ln".to_string(),
            signer_device_id: "a".repeat(32),
            handover: Some(v0::SignedHandover {
                body: "handover".to_string(),
                signature: "aG8".to_string(),
            }),
            authority: None,
        }
        .into();
        assert_eq!(submission.body, "body");
        assert_eq!(submission.signature, "c2ln");
        assert_eq!(submission.signer_device_id, "a".repeat(32));
        assert_eq!(
            submission.handover,
            Some(crate::SignedHandover {
                body: "handover".to_string(),
                signature: "aG8".to_string(),
            })
        );

        let list: v0::ChannelSeatListInfo = crate::SeatList {
            id: "01JA0000000000000000CHANNEL".to_string(),
            version: 3,
            body: "body".to_string(),
            signer_user_id: "01JA00000000000000000USERA".to_string(),
            signer_device_id: "a".repeat(32),
            signature: "c2ln".to_string(),
            handovers: submission.handover.into_iter().collect(),
            updated_at: Timestamp::UNIX_EPOCH,
            authority: None,
        }
        .into();
        assert_eq!(list.version, 3);
        assert_eq!(list.signer_user_id, "01JA00000000000000000USERA");
        assert_eq!(list.handovers[0].signature, "aG8");

        let seat = crate::ChannelSeat {
            id: crate::ChannelSeat::composite_id(
                "01JA0000000000000000CHANNEL",
                "01JA00000000000000000USERA",
            ),
            channel_id: "01JA0000000000000000CHANNEL".to_string(),
            user_id: "01JA00000000000000000USERA".to_string(),
            seated_at: Timestamp::UNIX_EPOCH,
            released_at: None,
            cooldown_until: None,
            release_cause: None,
            keys_received_at: None,
        };
        assert_eq!(seat.clone().into_seat_info().seated_without_access, None);
        assert_eq!(seat.into_cooling_info(), None);
    }

    #[test]
    fn entitlement_converts_every_field() {
        let entitlement: v0::ChannelEntitlement = crate::ChannelEntitlement {
            id: "01JA00000000000000000000ENT".to_string(),
            channel_id: "01JA0000000000000000CHANNEL".to_string(),
            server_id: "01JA00000000000000000SERVER".to_string(),
            source: crate::ChannelEntitlementSource::AdminGrant,
            slot_cap: 10,
            device_cap: Some(3),
            state: crate::ChannelEntitlementState::Active,
            granted_by: "01JA00000000000000000ADMIN0".to_string(),
            created_at: Timestamp::UNIX_EPOCH,
        }
        .into();
        assert_eq!(entitlement.id, "01JA00000000000000000000ENT");
        assert_eq!(entitlement.source, v0::ChannelEntitlementSource::AdminGrant);
        assert_eq!(entitlement.slot_cap, 10);
        assert_eq!(entitlement.device_cap, Some(3));
        assert_eq!(entitlement.state, v0::ChannelEntitlementState::Active);
        assert_eq!(entitlement.granted_by, "01JA00000000000000000ADMIN0");
    }

    // --- S2-W1-3: join-intent carriers, text group, seat list ----------------

    const CHANNEL: &str = "01JA0000000000000000CHANNEL";
    const USER_A: &str = "01JA00000000000000000USERA";
    const USER_B: &str = "01JA00000000000000000USERB";
    const USER_C: &str = "01JA00000000000000000USERC";
    const USER_D: &str = "01JA00000000000000000USERD";
    const JOIN_ISSUED_AT: i64 = 1_790_812_870_000;

    fn group_id() -> String {
        format!("{}1", "0".repeat(63))
    }

    fn ms(n: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(iso8601_timestamp::Duration::milliseconds(n))
            .unwrap()
    }

    /// A stored join intent; `text` gives it the 3.13 Text join fields
    fn intent(
        group_id: &str,
        user_id: &str,
        fill: &str,
        created_ms: i64,
        text: bool,
    ) -> crate::MlsJoinIntent {
        crate::MlsJoinIntent {
            id: crate::MlsJoinIntent::composite_id(group_id, user_id, &fill.repeat(32)),
            group_id: group_id.to_string(),
            user_id: user_id.to_string(),
            device_id: fill.repeat(32),
            key_package_ref: "a3ByZWY".to_string(),
            signature: "c2ln".to_string(),
            created_at: ms(created_ms),
            generation: text.then_some(2),
            issued_at: text.then_some(JOIN_ISSUED_AT),
            protocol: None,
        }
    }

    /// USER_B's S1 intent on every carrier, exactly as S1 serialized it
    fn s1_intent_json() -> String {
        format!(
            r#"{{"group_id":"{}","channel_id":"{CHANNEL}","user_id":"{USER_B}","device_id":"{}","key_package_ref":"a3ByZWY","signature":"c2ln"}}"#,
            group_id(),
            "b".repeat(32)
        )
    }

    /// The same intent with the Text join fields appended
    fn text_intent_json() -> String {
        format!(
            r#"{{"group_id":"{}","channel_id":"{CHANNEL}","user_id":"{USER_B}","device_id":"{}","key_package_ref":"a3ByZWY","signature":"c2ln","generation":2,"issued_at":{JOIN_ISSUED_AT}}}"#,
            group_id(),
            "b".repeat(32)
        )
    }

    /// 3.13 carrier: the stored intent's `into_rejoin_intent_info` (commit
    /// fetch, `MlsCommitInfo.rejoin_intents`)
    #[test]
    fn commit_rejoin_intent_carries_the_text_join_fields() {
        let s1 = intent(&group_id(), USER_B, "b", 0, false).into_rejoin_intent_info(CHANNEL);
        assert_eq!(serde_json::to_string(&s1).unwrap(), s1_intent_json());

        let text = intent(&group_id(), USER_B, "b", 0, true).into_rejoin_intent_info(CHANNEL);
        assert_eq!(
            (text.generation, text.issued_at),
            (Some(2), Some(JOIN_ISSUED_AT))
        );
        let json = serde_json::to_string(&text).unwrap();
        assert_eq!(json, text_intent_json());
        assert_eq!(
            serde_json::from_str::<v0::MlsRejoinIntentInfo>(&json).unwrap(),
            text
        );
    }

    /// The commit wire form fills its rejoin intents through that carrier
    #[test]
    fn commit_info_carries_the_text_join_fields() {
        let commit = crate::MlsCommit {
            id: crate::MlsCommit::composite_id(&group_id(), 8),
            group_id: group_id(),
            epoch: 8,
            committer: device(USER_A, "a"),
            commit: "Y29tbWl0".to_string(),
            size: 6,
            added: vec![],
            removed: vec![device(USER_B, "b")],
            created_at: Timestamp::UNIX_EPOCH,
            rejoin_intents: vec![intent(&group_id(), USER_B, "b", 0, true)],
            removed_reasons: vec![],
            welcome: None,
            history_visible: None,
        };
        let info = commit.into_commit_info(CHANNEL);
        assert_eq!(
            serde_json::to_string(&info.rejoin_intents[0]).unwrap(),
            text_intent_json()
        );
    }

    /// 3.13 carrier: the queued envelope's `MlsEnvelopeRejoinIntent`, as
    /// stored (JSON and BSON) and as delivered (`MlsRejoinIntentInfo`)
    #[test]
    fn envelope_rejoin_intent_carries_the_text_join_fields() {
        let s1 = crate::MlsEnvelopeRejoinIntent::from_join_intent(
            &intent(&group_id(), USER_B, "b", 0, false),
            CHANNEL,
        );
        assert_eq!(serde_json::to_string(&s1).unwrap(), s1_intent_json());
        let document = bson::to_document(&s1).unwrap();
        let keys: Vec<&str> = document.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "group_id",
                "channel_id",
                "user_id",
                "device_id",
                "key_package_ref",
                "signature"
            ]
        );
        assert_eq!(
            serde_json::to_string(&v0::MlsRejoinIntentInfo::from(s1)).unwrap(),
            s1_intent_json()
        );

        let text = crate::MlsEnvelopeRejoinIntent::from_join_intent(
            &intent(&group_id(), USER_B, "b", 0, true),
            CHANNEL,
        );
        assert_eq!(
            (text.generation, text.issued_at),
            (Some(2), Some(JOIN_ISSUED_AT))
        );
        assert_eq!(serde_json::to_string(&text).unwrap(), text_intent_json());
        let document = bson::to_document(&text).unwrap();
        assert_eq!(
            bson::from_document::<crate::MlsEnvelopeRejoinIntent>(document).unwrap(),
            text
        );
        assert_eq!(
            serde_json::from_str::<crate::MlsEnvelopeRejoinIntent>(&s1_intent_json()).unwrap(),
            crate::MlsEnvelopeRejoinIntent {
                generation: None,
                issued_at: None,
                ..text.clone()
            }
        );
    }

    /// The delivered form of a Text envelope intent keeps both fields
    #[test]
    fn delivered_envelope_intent_carries_the_text_join_fields() {
        let text = crate::MlsEnvelopeRejoinIntent::from_join_intent(
            &intent(&group_id(), USER_B, "b", 0, true),
            CHANNEL,
        );
        let delivered = v0::MlsRejoinIntentInfo::from(text);
        assert_eq!(
            (delivered.generation, delivered.issued_at),
            (Some(2), Some(JOIN_ISSUED_AT))
        );
        assert_eq!(
            serde_json::to_string(&delivered).unwrap(),
            text_intent_json()
        );
    }

    /// The `text_group()` fixture's response exactly as S1 served it
    fn s1_text_group_json() -> String {
        format!(
            r#"{{"group_id":"{}","channel_id":"{CHANNEL}","generation":2,"current_epoch":7,"members":[{{"user_id":"{USER_A}","device_id":"{a}"}}],"pending_removals":[{{"user_id":"{USER_B}","created_at":"1970-01-01T00:00:00.000Z"}}],"member_added":[{{"user_id":"{USER_A}","device_id":"{a}","epoch":5,"at":"1970-01-01T00:00:00.000Z"}}]}}"#,
            group_id(),
            a = "a".repeat(32)
        )
    }

    /// `text_group()` carrying every S2 server list
    fn s2_text_group() -> crate::MlsGroup {
        crate::MlsGroup {
            pending_device_removals: vec![crate::MlsPendingDeviceRemoval {
                user_id: USER_C.to_string(),
                device_id: "c".repeat(32),
                created_at: ms(3),
            }],
            signer_lost: Some(crate::MlsSignerLost {
                user_id: USER_A.to_string(),
                device_id: "e".repeat(32),
                cause: crate::MlsSignerLostCause::DeviceRevoked,
                at: ms(4),
            }),
            rejoin_readd: vec![crate::MlsRejoinReadd {
                user_id: USER_B.to_string(),
                device_id: "b".repeat(32),
                at: ms(5),
            }],
            ..text_group()
        }
    }

    /// R24, #222: the unseated response is the S1 body byte-for-byte, even
    /// over a row holding every S2 list
    #[test]
    fn unseated_text_group_is_the_s1_body() {
        assert_eq!(
            serde_json::to_string(&text_group().into_text_group_response().unwrap()).unwrap(),
            s1_text_group_json()
        );
        assert_eq!(
            serde_json::to_string(&s2_text_group().into_text_group_response().unwrap()).unwrap(),
            s1_text_group_json()
        );
        // A seated caller of a group with nothing pending gets it too
        assert_eq!(
            serde_json::to_string(
                &text_group()
                    .into_text_group_response_for_seated(vec![], true)
                    .unwrap()
            )
            .unwrap(),
            s1_text_group_json()
        );
    }

    /// The seated response serves the pending device removals and the
    /// stored `signer_lost` cause
    #[test]
    fn seated_text_group_carries_the_s2_lists() {
        let response = s2_text_group()
            .into_text_group_response_for_seated(vec![], false)
            .unwrap();
        assert_eq!(
            response.pending_device_removals,
            vec![v0::MlsPendingDeviceRemovalInfo {
                user_id: USER_C.to_string(),
                device_id: "c".repeat(32),
                created_at: ms(3),
            }]
        );
        assert_eq!(
            response.signer_lost,
            Some(v0::MlsSignerLostInfo {
                user_id: USER_A.to_string(),
                device_id: "e".repeat(32),
                cause: v0::MlsSignerLostCause::DeviceRevoked,
                at: ms(4),
            })
        );
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(
            value["pending_device_removals"],
            serde_json::json!([{
                "user_id": USER_C,
                "device_id": "c".repeat(32),
                "created_at": "1970-01-01T00:00:00.003Z",
            }])
        );
        assert_eq!(
            value["signer_lost"],
            serde_json::json!({
                "user_id": USER_A,
                "device_id": "e".repeat(32),
                "cause": "device_revoked",
                "at": "1970-01-01T00:00:00.004Z",
            })
        );
        assert_eq!(
            serde_json::from_value::<v0::ResponseTextGroup>(value).unwrap(),
            response
        );

        // Everything else is the unseated response
        assert_eq!(
            v0::ResponseTextGroup {
                join_requests: vec![],
                pending_device_removals: vec![],
                signer_lost: None,
                ..response
            },
            s2_text_group().into_text_group_response().unwrap()
        );
    }

    /// #222: `account_unavailable` is derived at read time from the
    /// route's flag; it relabels a stored `signer_lost` and never makes one
    #[test]
    fn signer_account_unavailable_relabels_the_stored_cause() {
        let response = s2_text_group()
            .into_text_group_response_for_seated(vec![], true)
            .unwrap();
        let lost = response.signer_lost.expect("the stored signer_lost");
        assert_eq!(lost.cause, v0::MlsSignerLostCause::AccountUnavailable);
        assert_eq!(
            (lost.user_id.as_str(), lost.device_id, lost.at),
            (USER_A, "e".repeat(32), ms(4))
        );
        assert_eq!(
            serde_json::to_value(lost.cause).unwrap(),
            serde_json::json!("account_unavailable")
        );

        let none = text_group()
            .into_text_group_response_for_seated(vec![], true)
            .unwrap();
        assert_eq!(none.signer_lost, None);
    }

    /// #203: join requests come only from THIS group's intents; another
    /// group's intent is never served
    #[test]
    fn join_requests_never_carry_another_groups_intent() {
        let other = format!("{}2", "0".repeat(63));
        let response = text_group()
            .into_text_group_response_for_seated(
                vec![
                    intent(&other, USER_C, "c", 30, true),
                    intent(&group_id(), USER_B, "b", 20, true),
                    intent(&other, USER_D, "d", 10, false),
                ],
                false,
            )
            .unwrap();
        let devices: Vec<&str> = response
            .join_requests
            .iter()
            .map(|request| request.device_id.as_str())
            .collect();
        assert_eq!(devices, ["b".repeat(32)]);
    }

    /// Join requests: every signed field copied, `rejoin` = holds a leaf,
    /// sorted by `created_at`, then device id
    #[test]
    fn join_requests_copy_the_intent_and_sort() {
        let response = text_group()
            .into_text_group_response_for_seated(
                vec![
                    intent(&group_id(), USER_B, "b", 20, true),
                    intent(&group_id(), USER_D, "9", 20, false),
                    // USER_A's member device, after its Add at t = 0
                    intent(&group_id(), USER_A, "a", 10, true),
                ],
                false,
            )
            .unwrap();
        assert_eq!(
            response.join_requests,
            vec![
                v0::MlsJoinRequestInfo {
                    user_id: USER_A.to_string(),
                    device_id: "a".repeat(32),
                    generation: Some(2),
                    key_package_ref: "a3ByZWY".to_string(),
                    signature: "c2ln".to_string(),
                    issued_at: Some(JOIN_ISSUED_AT),
                    created_at: ms(10),
                    rejoin: true,
                },
                v0::MlsJoinRequestInfo {
                    user_id: USER_D.to_string(),
                    device_id: "9".repeat(32),
                    generation: None,
                    key_package_ref: "a3ByZWY".to_string(),
                    signature: "c2ln".to_string(),
                    issued_at: None,
                    created_at: ms(20),
                    rejoin: false,
                },
                v0::MlsJoinRequestInfo {
                    user_id: USER_B.to_string(),
                    device_id: "b".repeat(32),
                    generation: Some(2),
                    key_package_ref: "a3ByZWY".to_string(),
                    signature: "c2ln".to_string(),
                    issued_at: Some(JOIN_ISSUED_AT),
                    created_at: ms(20),
                    rejoin: false,
                },
            ]
        );

        // Exact rows: an S1 intent omits the Text join fields
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(
            value["join_requests"][0],
            serde_json::json!({
                "user_id": USER_A,
                "device_id": "a".repeat(32),
                "generation": 2,
                "key_package_ref": "a3ByZWY",
                "signature": "c2ln",
                "issued_at": JOIN_ISSUED_AT,
                "created_at": "1970-01-01T00:00:00.010Z",
                "rejoin": true,
            })
        );
        assert_eq!(
            value["join_requests"][1],
            serde_json::json!({
                "user_id": USER_D,
                "device_id": "9".repeat(32),
                "key_package_ref": "a3ByZWY",
                "signature": "c2ln",
                "created_at": "1970-01-01T00:00:00.020Z",
                "rejoin": false,
            })
        );
    }

    /// 6.3: an intent no newer than its device's `member_added.at` is the
    /// one that Add consumed and is not a join request
    #[test]
    fn join_requests_skip_intents_the_latest_add_consumed() {
        let group = crate::MlsGroup {
            member_added: vec![crate::MlsMemberAdded {
                user_id: USER_A.to_string(),
                device_id: "a".repeat(32),
                epoch: 5,
                at: ms(10),
            }],
            ..text_group()
        };
        for (created, served) in [(9, false), (10, false), (11, true)] {
            let response = group
                .clone()
                .into_text_group_response_for_seated(
                    vec![intent(&group_id(), USER_A, "a", created, true)],
                    false,
                )
                .unwrap();
            assert_eq!(
                response.join_requests.len(),
                usize::from(served),
                "{created}"
            );
        }
    }

    /// Only a Text group with a generation is served to a seated caller
    #[test]
    fn seated_response_is_none_for_a_call_or_corrupt_group() {
        let intents = || vec![intent(&group_id(), USER_B, "b", 20, true)];
        let call = crate::MlsGroup {
            kind: crate::MlsGroupKind::Call,
            ..s2_text_group()
        };
        assert_eq!(
            call.into_text_group_response_for_seated(intents(), true),
            None
        );
        let corrupt = crate::MlsGroup {
            generation: None,
            ..s2_text_group()
        };
        assert_eq!(
            corrupt.into_text_group_response_for_seated(intents(), true),
            None
        );
    }

    fn signed_authority() -> crate::SignedAuthority {
        crate::SignedAuthority {
            body: "sloga-channel-authority-v1\nv:1".to_string(),
            signature: "YXV0aA".to_string(),
        }
    }

    /// `SignedAuthority` both ways, and the submitted authority reaches the
    /// `SeatListSubmission` the drivers write
    #[test]
    fn seat_list_authority_is_carried_both_ways() {
        let wire: v0::SignedAuthority = signed_authority().into();
        assert_eq!(
            wire,
            v0::SignedAuthority {
                body: "sloga-channel-authority-v1\nv:1".to_string(),
                signature: "YXV0aA".to_string(),
            }
        );
        assert_eq!(
            crate::SignedAuthority::from(wire.clone()),
            signed_authority()
        );

        let submission: crate::SeatListSubmission = v0::DataSeatList {
            body: "body".to_string(),
            signature: "c2ln".to_string(),
            signer_device_id: "a".repeat(32),
            handover: None,
            authority: Some(wire.clone()),
        }
        .into();
        assert_eq!(submission.authority, Some(signed_authority()));

        let stored = crate::SeatList {
            id: CHANNEL.to_string(),
            version: 2,
            body: "body".to_string(),
            signer_user_id: USER_A.to_string(),
            signer_device_id: "a".repeat(32),
            signature: "c2ln".to_string(),
            handovers: vec![],
            updated_at: Timestamp::UNIX_EPOCH,
            authority: Some(signed_authority()),
        };
        let list: v0::ChannelSeatListInfo = stored.clone().into();
        assert_eq!(list.authority, Some(wire));

        // An S1 row serves no `authority` key
        let s1: v0::ChannelSeatListInfo = crate::SeatList {
            authority: None,
            ..stored
        }
        .into();
        assert!(serde_json::to_value(&s1)
            .unwrap()
            .get("authority")
            .is_none());
    }

    /// `cause` is the owner's only: the default cooling entry never carries
    /// it, the owner's carries the stored `release_cause`
    #[test]
    fn cooling_cause_is_only_on_the_owner_entry() {
        let released = crate::ChannelSeat {
            id: crate::ChannelSeat::composite_id(CHANNEL, USER_B),
            channel_id: CHANNEL.to_string(),
            user_id: USER_B.to_string(),
            seated_at: Timestamp::UNIX_EPOCH,
            released_at: Some(ms(1)),
            cooldown_until: Some(ms(2)),
            release_cause: Some(crate::SeatReleaseCause::AccessLost),
            keys_received_at: Some(ms(0)),
        };

        let viewer = released.clone().into_cooling_info().unwrap();
        assert_eq!(viewer.cause, None);
        assert!(serde_json::to_value(&viewer)
            .unwrap()
            .get("cause")
            .is_none());

        let owner = released.clone().into_owner_cooling_info().unwrap();
        assert_eq!(owner.cause, Some(v0::SeatReleaseCauseInfo::AccessLost));
        assert_eq!(
            serde_json::to_value(&owner).unwrap()["cause"],
            serde_json::json!("access_lost")
        );
        assert_eq!(
            v0::ChannelSeatCoolingInfo {
                cause: None,
                ..owner
            },
            viewer
        );

        // A row released before S2 has no cause; a seat never released has
        // no cooling entry at all
        let pre_s2 = crate::ChannelSeat {
            release_cause: None,
            ..released.clone()
        };
        assert_eq!(pre_s2.into_owner_cooling_info().unwrap().cause, None);
        let active = crate::ChannelSeat {
            released_at: None,
            cooldown_until: None,
            ..released
        };
        assert_eq!(active.into_owner_cooling_info(), None);
    }
}

/// 🔴 S2-W1-3: an authority submitted on the v0 `DataSeatList` is converted
/// by the bridge and stored by the seat PUT byte-identical, on both drivers
/// (never run without `TEST_DB`: that is production)
#[cfg(test)]
mod seat_list_authority_driver_tests {
    use std::collections::HashMap;

    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use iso8601_timestamp::Timestamp;
    use revolt_models::v0;

    // Section 5.1 inputs (as in `protected_channels/tests.rs`)
    const CHANNEL: &str = "01J9Z3K4M5N6P7Q8R9S0T1V2W3";
    const SERVER: &str = "01HZXSERVERSERVERSERVERSER";
    const USER_A: &str = "01HZXAAAAAAAAAAAAAAAAAAAAA";
    const DEVICE_A: &str = "00112233445566778899aabbccddeeff";
    const OWNER_IDENTITY_KEY: &str = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
    const GROUP_SALT: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    const ISSUED_AT: i64 = 1_790_812_800_000;

    /// A canonical unpadded b64 encoding of 64 bytes (the database layer
    /// checks only the encoding; the route verifies signatures)
    fn signature(fill: u8) -> String {
        STANDARD_NO_PAD.encode([fill; 64])
    }

    /// Authority `version` over owner device A, chained to `prev`
    fn authority(version: i64, prev: Option<&v0::SignedAuthority>) -> v0::SignedAuthority {
        let body = crate::ChannelAuthority::build(&crate::ChannelAuthorityBody {
            channel_id: CHANNEL.to_string(),
            version,
            owner_user_id: USER_A.to_string(),
            signer_device_id: DEVICE_A.to_string(),
            issued_at: ISSUED_AT + version,
            owner_devices: vec![crate::AuthorityOwnerDevice {
                device_id: DEVICE_A.to_string(),
                identity_key: OWNER_IDENTITY_KEY.to_string(),
            }],
            delegates: vec![],
            delegate_max_device_cap: 0,
            successors: vec![],
            prev: prev.map(|prev| crate::ChannelAuthority::sha256(&prev.body)),
        })
        .unwrap();
        v0::SignedAuthority {
            body,
            signature: signature(0x80 + version as u8),
        }
    }

    /// A list seating A, signed by A's device; `v2` picks the body format
    fn seat_list(
        version: i64,
        v2: bool,
        authority: Option<v0::SignedAuthority>,
    ) -> v0::DataSeatList {
        let lines = crate::SeatListV2Lines {
            authority_sha256: authority
                .as_ref()
                .map(|authority| crate::ChannelAuthority::sha256(&authority.body)),
            history: crate::SeatListHistory::Visible,
            history_boundary: None,
            pre_history: crate::SeatListPreHistory::Kept,
            group_salt: GROUP_SALT.to_string(),
        };
        let body = crate::SeatListBody {
            channel_id: CHANNEL.to_string(),
            version,
            device_cap: 5,
            issued_at: ISSUED_AT,
            signer_user_id: USER_A.to_string(),
            signer_device_id: DEVICE_A.to_string(),
            seats: vec![USER_A.to_string()],
            v2: v2.then_some(lines),
        }
        .build()
        .unwrap();
        v0::DataSeatList {
            body,
            signature: signature(version as u8),
            signer_device_id: DEVICE_A.to_string(),
            handover: None,
            authority,
        }
    }

    async fn setup(db: &crate::Database) {
        let server: crate::Server = serde_json::from_value(serde_json::json!({
            "_id": SERVER,
            "owner": USER_A,
            "name": "protected",
            "channels": [],
            "default_permissions": 0,
        }))
        .unwrap();
        db.insert_server(&server).await.unwrap();
        db.insert_or_merge_member(&crate::Member {
            id: crate::MemberCompositeKey {
                server: SERVER.to_string(),
                user: USER_A.to_string(),
            },
            ..Default::default()
        })
        .await
        .unwrap();
        db.insert_channel(&crate::Channel::TextChannel {
            id: CHANNEL.to_string(),
            server: SERVER.to_string(),
            name: "protected".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: HashMap::new(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected: false,
            protected_history: None,
        })
        .await
        .unwrap();
        db.upsert_channel_entitlement(
            &crate::ChannelEntitlement {
                id: ulid::Ulid::new().to_string(),
                channel_id: CHANNEL.to_string(),
                server_id: SERVER.to_string(),
                source: crate::ChannelEntitlementSource::AdminGrant,
                slot_cap: 10,
                device_cap: None,
                state: crate::ChannelEntitlementState::Active,
                granted_by: "admin".to_string(),
                created_at: Timestamp::now_utc(),
            },
            Timestamp::now_utc(),
        )
        .await
        .unwrap();
    }

    /// Test-only overwrite of the stored genesis with its v2 form: with the
    /// test config's `formats_v2` off, no driver path enters v2
    async fn store_v2_genesis(db: &crate::Database) {
        let genesis = seat_list(1, true, None);
        let row = crate::SeatList {
            id: CHANNEL.to_string(),
            version: 1,
            body: genesis.body,
            signer_user_id: USER_A.to_string(),
            signer_device_id: DEVICE_A.to_string(),
            signature: genesis.signature,
            handovers: vec![],
            updated_at: Timestamp::now_utc(),
            authority: None,
        };
        match db {
            crate::Database::Reference(reference) => {
                reference
                    .channel_seat_lists
                    .lock()
                    .await
                    .insert(row.id.clone(), row);
            }
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                let result = mongo
                    .col::<crate::SeatList>("channel_seat_lists")
                    .replace_one(doc! { "_id": CHANNEL }, &row)
                    .await
                    .unwrap();
                assert_eq!(result.matched_count, 1);
            }
        }
    }

    async fn put(db: &crate::Database, list: v0::DataSeatList) -> crate::SeatList {
        let submission: crate::SeatListSubmission = list.into();
        db.put_seat_list(
            CHANNEL,
            &submission,
            true,
            Timestamp::now_utc(),
            Some("test"),
        )
        .await
        .unwrap();
        db.fetch_seat_list(CHANNEL).await.unwrap().unwrap()
    }

    fn assert_stored(stored: &crate::SeatList, submitted: &v0::SignedAuthority) {
        let authority = stored.authority.as_ref().expect("the stored authority");
        assert_eq!(authority.body.as_bytes(), submitted.body.as_bytes());
        assert_eq!(
            authority.signature.as_bytes(),
            submitted.signature.as_bytes()
        );
        let served: v0::ChannelSeatListInfo = stored.clone().into();
        assert_eq!(served.authority.as_ref(), Some(submitted));
    }

    #[tokio::test]
    async fn a_submitted_authority_is_stored_byte_identical() {
        database_test!(|db| async move {
            let formats_v2 = revolt_config::config()
                .await
                .features
                .protected_channels
                .formats_v2;
            setup(&db).await;
            let genesis: crate::SeatListSubmission = seat_list(1, formats_v2, None).into();
            db.protect_channel(CHANNEL, &genesis, Timestamp::now_utc())
                .await
                .unwrap();
            if !formats_v2 {
                store_v2_genesis(&db).await;
            }
            assert_eq!(
                db.fetch_seat_list(CHANNEL)
                    .await
                    .unwrap()
                    .unwrap()
                    .authority,
                None
            );

            // The first authority
            let first = authority(1, None);
            let stored = put(&db, seat_list(2, true, Some(first.clone()))).await;
            assert_eq!(stored.version, 2);
            assert_stored(&stored, &first);

            // A changed authority (version + 1, `prev` = the stored one)
            let second = authority(2, Some(&first));
            let stored = put(&db, seat_list(3, true, Some(second.clone()))).await;
            assert_eq!(stored.version, 3);
            assert_stored(&stored, &second);
        });
    }
}
