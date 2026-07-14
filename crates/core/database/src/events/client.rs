use revolt_result::Error;
use serde::{Deserialize, Serialize};

use revolt_models::v0::{
    AppendMessage, Channel, ChannelSlowmode, ChannelUnread, ChannelVoiceState, E2EEMessage,
    Emoji, Event, EventRsvp, FieldsChannel, FieldsMember, FieldsMessage, FieldsRole, FieldsServer, FieldsUser,
    FieldsWebhook, Interaction, Member, MemberCompositeKey, Message, PartialChannel, PartialEmoji,
    PartialMember, PartialMessage, PartialRole, PartialServer, PartialSticker, PartialUser,
    PartialUserVoiceState, PartialWebhook, PolicyChange, PollAnswerCount, RemovalIntention,
    Report, ScheduledMessage, Server, Sticker, User, UserSettings, UserVoiceState, Webhook,
};

use crate::{Account, Database, Session};

/// Ping Packet
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Ping {
    Binary(Vec<u8>),
    Number(usize),
}

/// Fields provided in Ready payload
#[derive(PartialEq, Debug, Clone, Deserialize)]
pub struct ReadyPayloadFields {
    pub users: bool,
    pub servers: bool,
    pub channels: bool,
    pub members: bool,
    pub emojis: bool,
    pub voice_states: bool,
    pub user_settings: Vec<String>,
    pub channel_unreads: bool,
    pub policy_changes: bool,
}

impl Default for ReadyPayloadFields {
    fn default() -> Self {
        Self {
            users: true,
            servers: true,
            channels: true,
            members: true,
            emojis: true,
            voice_states: true,
            user_settings: Vec::new(),
            channel_unreads: false,
            policy_changes: true,
        }
    }
}

/// Protocol Events
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum EventV1 {
    /// Multiple events
    Bulk {
        v: Vec<EventV1>,
    },
    /// Error event
    Error {
        data: Error,
    },

    /// Successfully authenticated
    Authenticated,
    /// Logged out
    Logout,
    /// Basic data to cache
    Ready {
        #[serde(skip_serializing_if = "Option::is_none")]
        users: Option<Vec<User>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        servers: Option<Vec<Server>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        channels: Option<Vec<Channel>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        members: Option<Vec<Member>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        emojis: Option<Vec<Emoji>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        stickers: Option<Vec<Sticker>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        voice_states: Option<Vec<ChannelVoiceState>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        user_settings: Option<UserSettings>,
        #[serde(skip_serializing_if = "Option::is_none")]
        channel_unreads: Option<Vec<ChannelUnread>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        policy_changes: Option<Vec<PolicyChange>>,
    },

    /// Ping response
    Pong {
        data: Ping,
    },
    /// New message
    Message(Message),

    /// Update existing message
    MessageUpdate {
        id: String,
        channel: String,
        data: PartialMessage,
        #[serde(default)]
        clear: Vec<FieldsMessage>,
    },

    /// Append information to existing message
    MessageAppend {
        id: String,
        channel: String,
        append: AppendMessage,
    },

    /// Delete message
    MessageDelete {
        id: String,
        channel: String,
    },

    /// New reaction to a message
    MessageReact {
        id: String,
        channel_id: String,
        user_id: String,
        emoji_id: String,
    },

    /// Remove user's reaction from message
    MessageUnreact {
        id: String,
        channel_id: String,
        user_id: String,
        emoji_id: String,
    },

    /// Remove a reaction from message
    MessageRemoveReaction {
        id: String,
        channel_id: String,
        emoji_id: String,
    },

    /// Bulk delete messages
    BulkMessageDelete {
        channel: String,
        ids: Vec<String>,
    },

    /// New server
    ServerCreate {
        id: String,
        server: Server,
        channels: Vec<Channel>,
        emojis: Vec<Emoji>,
        stickers: Vec<Sticker>,
        voice_states: Vec<ChannelVoiceState>,
    },

    /// Update existing server
    ServerUpdate {
        id: String,
        data: PartialServer,
        #[serde(default)]
        clear: Vec<FieldsServer>,
    },

    /// Delete server
    ServerDelete {
        id: String,
    },

    /// Update existing server member
    ServerMemberUpdate {
        id: MemberCompositeKey,
        data: PartialMember,
        #[serde(default)]
        clear: Vec<FieldsMember>,
    },

    /// User joins server
    ServerMemberJoin {
        id: String,
        // Deprecated: use member.id.user
        #[deprecated = "Use member.id.user instead"]
        user: String,
        member: Member,
    },

    /// User left server
    ServerMemberLeave {
        id: String,
        user: String,
        reason: RemovalIntention,
    },

    /// Server role created or updated
    ServerRoleUpdate {
        id: String,
        role_id: String,
        data: PartialRole,
        #[serde(default)]
        clear: Vec<FieldsRole>,
    },

    /// Server role deleted
    ServerRoleDelete {
        id: String,
        role_id: String,
    },

    /// Server roles ranks updated
    ServerRoleRanksUpdate {
        id: String,
        ranks: Vec<String>,
    },

    /// Update existing user
    UserUpdate {
        id: String,
        data: PartialUser,
        #[serde(default)]
        clear: Vec<FieldsUser>,
        event_id: Option<String>,
    },

    /// Relationship with another user changed
    UserRelationship {
        id: String,
        user: User,
    },
    /// Settings updated remotely
    UserSettingsUpdate {
        id: String,
        update: UserSettings,
    },

    /// User has been platform banned or deleted their account
    ///
    /// Clients should remove the following associated data:
    /// - Messages
    /// - DM Channels
    /// - Relationships
    /// - Server Memberships
    ///
    /// User flags are specified to explain why a wipe is occurring though not all reasons will necessarily ever appear.
    UserPlatformWipe {
        user_id: String,
        flags: i32,
    },
    /// New emoji
    EmojiCreate(Emoji),

    /// Update existing emoji
    EmojiUpdate {
        id: String,
        data: PartialEmoji,
    },

    /// Delete emoji
    EmojiDelete {
        id: String,
    },

    /// New sticker
    StickerCreate(Sticker),

    /// Update existing sticker
    StickerUpdate {
        id: String,
        data: PartialSticker,
    },

    /// Delete sticker
    StickerDelete {
        id: String,
    },

    /// New report
    ReportCreate(Report),
    /// New channel
    ChannelCreate(Channel),

    /// Update existing channel
    ChannelUpdate {
        id: String,
        data: PartialChannel,
        #[serde(default)]
        clear: Vec<FieldsChannel>,
    },

    /// Delete channel
    ChannelDelete {
        id: String,
    },

    /// User joins a group
    ChannelGroupJoin {
        id: String,
        user: String,
    },

    /// User leaves a group
    ChannelGroupLeave {
        id: String,
        user: String,
    },

    /// User joins a thread
    ThreadMemberJoin {
        id: String,
        user: String,
    },

    /// User leaves a thread
    ThreadMemberLeave {
        id: String,
        user: String,
    },

    /// User started typing in a channel
    ChannelStartTyping {
        id: String,
        user: String,
    },

    /// User stopped typing in a channel
    ChannelStopTyping {
        id: String,
        user: String,
    },

    /// User acknowledged message in channel
    ChannelAck {
        id: String,
        user: String,
        message_id: String,
    },

    /// New webhook
    WebhookCreate(Webhook),

    /// Update existing webhook
    WebhookUpdate {
        id: String,
        data: PartialWebhook,
        remove: Vec<FieldsWebhook>,
    },

    /// Delete webhook
    WebhookDelete {
        id: String,
    },

    /// A target channel started following a source announcement channel.
    /// Published to the TARGET server topic with the full follow (target
    /// members may see their own channel's follow). The source server only
    /// receives the privacy-trimmed `ChannelFollowersUpdate` refetch signal
    /// so target ids never leak to non-admin source members.
    ChannelFollowCreate {
        follow: ChannelFollow,
    },

    /// A follow was severed (explicit unfollow, webhook deletion, or channel
    /// deletion). Published to the TARGET server topic. The source server
    /// receives `ChannelFollowersUpdate` instead.
    ChannelFollowDelete {
        id: String,
        source_channel: String,
        target_channel: String,
    },

    /// A source announcement channel's follower set changed — a
    /// privacy-trimmed refetch signal published to the SOURCE server topic
    /// (carries no target ids; the full follower list stays behind the
    /// ManageChannel-gated GET /channels/<id>/followers endpoint).
    ChannelFollowersUpdate {
        channel: String,
    },

    /// Auth events
    CreateAccount {
        account: Account,
    },
    CreateSession {
        session: Session,
    },
    DeleteSession {
        user_id: String,
        session_id: String,
    },
    DeleteAllSessions {
        user_id: String,
        exclude_session_id: Option<String>,
    },

    /// Voice events
    VoiceChannelJoin {
        id: String,
        state: UserVoiceState,
    },
    VoiceChannelLeave {
        id: String,
        user: String,
    },
    VoiceChannelMove {
        user: String,
        from: String,
        to: String,
        state: UserVoiceState,
    },
    UserVoiceStateUpdate {
        id: String,
        channel_id: String,
        data: PartialUserVoiceState,
    },
    UserMoveVoiceChannel {
        node: String,
        from: String,
        to: String,
        token: String,
    },
    /// User's active slowmodes
    UserSlowmodes {
        slowmodes: Vec<ChannelSlowmode>,
    },

    /// New E2EE envelope for one of the user's devices
    ///
    /// Pushed on the recipient's private topic; each device keeps envelopes
    /// addressed to its own device id and acknowledges them via E2EEAck.
    /// The envelope ULID is the client's dedup key against the
    /// drain-vs-live-push race.
    E2EEMessage(E2EEMessage),

    /// A user registered a new E2EE device
    ///
    /// Sent to the account's other devices and to DM peers — device-list
    /// changes are loud (both add and remove).
    E2EEDeviceCreate {
        user_id: String,
        device_id: String,
    },

    /// A user's E2EE device was revoked
    E2EEDeviceDelete {
        user_id: String,
        device_id: String,
    },

    /// A device signalled intent to join a call's MLS group (media E2EE).
    ///
    /// Fanned out to each member USER's private topic; member devices verify
    /// the intent signature against their own pins before admitting — the
    /// server relay is never the trust decision (plan §1.4).
    MlsJoinRequested {
        group_id: String,
        channel_id: String,
        user_id: String,
        device_id: String,
        key_package_ref: String,
        signature: String,
        /// The intent came from a device that is ALREADY a group member: its
        /// leaf is stale (the device wiped local state via rejoin-fresh) and
        /// verifying members should REMOVE it so the device's next normal
        /// intent can be admitted. `serde(default)` so a newer bonfire can
        /// relay events from an older delta during rollout.
        #[serde(default)]
        rejoin: bool,
    },

    /// Live push of an MLS commit envelope (media E2EE).
    ///
    /// The envelope is ALSO queued in the device mailbox (queue-first);
    /// clients dedup by envelope ULID exactly like E2EEMessage, and order
    /// per group strictly by consecutive epoch, parking/refetching on gaps.
    MlsCommit(E2EEMessage),

    /// Live push of an MLS Welcome envelope to a newly added device
    /// (media E2EE). Same queue-first + ULID-dedup contract as MlsCommit.
    MlsWelcome(E2EEMessage),

    /// Live push of an MLS application-message envelope (media E2EE) — the
    /// §3.4 downgrade ctl-announce. Same queue-first + ULID-dedup contract
    /// as MlsCommit, but NO epoch ordering: a ctl never parks the drain.
    MlsCtl(E2EEMessage),

    /// Device-claim challenge (connection-local, issued by the events
    /// server; the client signs this with the device Ed25519 identity key)
    E2EEChallenge {
        nonce: String,
    },

    /// Device-claim result (connection-local). Only an accepted claim grants
    /// queue drain and acknowledgement rights.
    E2EEClaimResult {
        device_id: String,
        accepted: bool,
    },

    /// A poll's aggregate counts changed (vote cast, replaced or retracted).
    /// Published on the channel topic — the topic is the authorization
    /// boundary. Deliberately count-only: ballots (voter identities) are
    /// never broadcast; the voters list is REST and author-gated.
    PollVoteUpdate {
        id: String,
        channel_id: String,
        message_id: String,
        counts: Vec<PollAnswerCount>,
        total_votes: i64,
    },

    /// A poll closed (expiry, manual end, or lazy close). Published exactly
    /// once by the close winner with authoritative final results.
    PollClose {
        id: String,
        channel_id: String,
        message_id: String,
        counts: Vec<PollAnswerCount>,
        total_votes: i64,
    },

    /// A calendar event was created. Published on the event's channel topic when
    /// it has a channel (only ViewChannel subscribers receive it), else the server
    /// topic — the topic IS the authorization boundary (finding C1).
    CalendarEventCreate {
        event: Event,
    },

    /// A calendar event was updated (or soft-cancelled — the payload's `cancelled`
    /// flag distinguishes). Same topic rule as create.
    CalendarEventUpdate {
        event: Event,
    },

    /// The current user was specifically invited to a calendar event.
    /// Delivered to the invited user's private topic.
    CalendarEventInvite {
        event: Event,
    },

    /// A user's RSVP to a calendar event changed. Published to the event audience.
    CalendarEventRsvp {
        rsvp: EventRsvp,
    },

    /// A slash command was invoked (later slices: component clicked). The
    /// payload carries the single-use response token, so this event is
    /// published ONLY on the target bot user's private topic — never on a
    /// channel or server topic.
    InteractionCreate {
        interaction: Interaction,
    },

    /// An ephemeral interaction response — a bot message that is NEVER
    /// persisted. Published ONLY on the invoking user's private topic; it
    /// must never reach the channel topic, the database, push
    /// notifications, or unread tracking. Gone on reload by design.
    InteractionEphemeralMessage {
        message: Message,
    },

    /// A message was scheduled for later delivery. Published ONLY on the
    /// author's private topic — pending messages are never visible to
    /// other members. The eventual delivery is a normal `Message` event.
    MessageScheduled {
        message: ScheduledMessage,
    },

    /// A scheduled message was cancelled (by the author, or because its
    /// channel was deleted). Author's private topic only.
    MessageScheduleCancelled {
        id: String,
        channel: String,
    },

    /// A scheduled message could not be delivered (permissions revoked,
    /// channel gone, validation failed at fire time — permanent, never
    /// retried). Author's private topic only.
    ScheduledMessageFailed {
        id: String,
        channel: String,
        reason: String,
    },
}

impl EventV1 {
    /// Publish helper wrapper
    pub async fn p(self, channel: String) {
        #[cfg(not(debug_assertions))]
        redis_kiss::p(channel, self).await;

        #[cfg(debug_assertions)]
        info!("Publishing event to {channel}: {self:?}");

        // Non-panicking like the release path above: a transient Redis
        // hiccup (parallel test runs hit this intermittently) must not
        // take down the caller — the event is simply lost, as in release.
        #[cfg(debug_assertions)]
        if let Err(err) = redis_kiss::publish(channel, self).await {
            error!("Failed to publish event: {err:?}");
        }
    }

    /// Publish user event
    pub async fn p_user(self, id: String, db: &Database) {
        self.clone().p(id.clone()).await;

        // TODO: this should be captured by member list in the future and not immediately fanned out to users
        if let Ok(members) = db.fetch_all_memberships(&id).await {
            for member in members {
                self.clone().server(member.id.server).await;
            }
        }
    }

    /// Publish private event
    pub async fn private(self, id: String) {
        self.p(format!("{id}!")).await;
    }

    /// Publish server member event
    pub async fn server(self, id: String) {
        self.p(format!("{id}u")).await;
    }

    /// Publish internal global event
    pub async fn global(self) {
        self.p("global".to_string()).await;
    }
}
