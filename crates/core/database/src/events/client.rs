use revolt_result::Error;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use revolt_models::v0::{
    AnnotationStroke, AppendMessage, Channel, ChannelFollow, ChannelSlowmode, ChannelUnread, ChannelVoiceState, CommandChoice, E2EEMessage,
    Emoji, Event, EventRsvp, FieldsChannel, FieldsMember, FieldsMessage, FieldsRole, FieldsServer, FieldsUser,
    FieldsWebhook, Interaction, Member, MemberCompositeKey, Message, Modal, PartialChannel, PartialEmoji,
    PartialMember, PartialMessage, PartialRole, PartialServer, PartialSticker, PartialUser,
    PartialSoundboardSound, PartialUserVoiceState, PartialWebhook, PolicyChange, PollAnswerCount,
    RemovalIntention, Report, ScheduledMessage, Server, SoftRes, SoftResReserve, SoundboardSound,
    Sticker, User, UserSettings, UserVoiceState, WatchSession, Webhook,
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

    /// New soundboard sound (server topic — keeps every member's list live)
    SoundboardCreate(SoundboardSound),

    /// Update existing soundboard sound (server topic)
    SoundboardUpdate {
        id: String,
        data: PartialSoundboardSound,
    },

    /// Delete soundboard sound (server topic)
    SoundboardDelete {
        id: String,
    },

    /// A soundboard sound was triggered in a voice call. Published on the
    /// CHANNEL topic (ViewChannel = the authorization boundary); carries no
    /// audio, only the public `sound_id`. Played locally only by clients
    /// currently in the call — the clip never touches the LiveKit/SFU media
    /// path or the call's MLS E2EE (sounds are public per-server assets).
    SoundboardSound {
        /// Sound id (equals the Autumn file id — clients build the clip URL from it)
        id: String,
        channel_id: String,
        server_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        emoji: Option<String>,
    },

    /// One finalized live caption from a speaker in a voice call.
    ///
    /// Fanned to the call's CURRENT PARTICIPANTS over their private topics,
    /// deliberately NOT to the channel topic: the channel topic's
    /// authorization boundary is ViewChannel, so a text-channel lurker who
    /// never joined the call would otherwise receive a live transcript of it.
    /// Same reasoning as the remote-control offer events.
    ///
    /// Transient — never persisted. `identity` is the speaker's SFU identity
    /// (device-qualified on E2EE-capable calls), resolved server-side so a
    /// client can key the caption straight onto the right participant tile
    /// and cannot address someone else's.
    CallCaption {
        channel_id: String,
        /// Speaker's LiveKit identity — what the participant tiles are keyed by
        identity: String,
        /// Speaker's user id (identity minus any device qualifier)
        user_id: String,
        /// Transcript text, clamped to the client's display cap
        text: String,
        /// BCP-47 language the speaker was recognized in
        lang: String,
    },

    /// A batch of annotation strokes drawn on a screen-sharer's surface
    /// (tech-support-mode plan §2).
    ///
    /// OTHER-addressed, unlike `CallCaption` (which describes the sender's
    /// own speech): the annotator draws on the TARGET's surface, so both
    /// ends are stamped/validated server-side — the annotator from the
    /// authenticated caller, the target checked to be a live screen-sharer
    /// who has allowlisted this annotator. Fanned to the call's current
    /// participants over private topics for the same reason captions are.
    /// Transient — strokes are relayed, rendered, faded, never persisted.
    /// A stroke is a picture, never an input event (plan §0.3).
    CallAnnotation {
        channel_id: String,
        /// Annotator's LiveKit identity, resolved server-side — what the
        /// "✏️ is drawing" attribution is keyed by. The server ASSERTS this;
        /// the transport cannot prove it (§0.2 honesty rule), so client copy
        /// must not present it as verified.
        annotator_identity: String,
        /// Annotator's user id (stamped from the authenticated caller)
        annotator_id: String,
        /// Identity of the sharer whose surface is drawn on, resolved
        /// server-side — what receivers key the overlay's tile by
        target_identity: String,
        /// The sharer's user id (validated: live screen-sharer here)
        target_id: String,
        /// Strokes since the annotator's last coalescing tick
        strokes: Vec<AnnotationStroke>,
        /// Batch counter, monotonic within one capture session. Diagnostic
        /// ordering info only — receivers do NOT enforce it (a remounted
        /// capture legitimately restarts at 1); the revoke path drops ink
        /// by consent state, not by sequence.
        seq: u32,
    },

    /// A sharer's draw-consent allowlist changed (tech-support-mode plan
    /// §2.4). `allowed` is the COMPLETE new list: empty means revoked —
    /// receivers drop that sharer's rendered strokes immediately (revoke is
    /// the phishing backstop; the fade is not) and hide the draw affordance.
    /// Fanned to the call's current participants over private topics.
    CallAnnotationConsent {
        channel_id: String,
        sharer_id: String,
        allowed: Vec<String>,
    },

    /// A voice channel's watch-together session was created or its control
    /// state changed (watch-together plan §1.2). Carries the COMPLETE session
    /// every time — idempotent and small; receivers apply it iff
    /// `session.seq` is greater than the last one they applied for the same
    /// `session.id`, and derive the timeline from `position_ms`/`position_at`
    /// (server-stamped). Fanned to the call's current participants over
    /// private topics, never the channel topic — what the call is watching is
    /// call business, not ViewChannel business. Sloga relays only this
    /// control state; the media itself never touches a Sloga server.
    WatchSessionUpdate {
        channel_id: String,
        session: WatchSession,
    },

    /// The watch-together session ended (host stopped it, host left the
    /// call, call ended, or a moderator ended it). Receivers tear the player
    /// down regardless of `id` mismatch — `id` is diagnostic.
    WatchSessionEnd {
        channel_id: String,
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
    /// Back-compat: `data` may carry the additive `screen_video` flag
    /// (screen VIDEO track live, source 3 only) alongside the historical
    /// `screensharing` flag (either screen track live — video OR audio,
    /// semantics unchanged). Consumers that need "there is actually video
    /// to look at" must read `screen_video` and treat its absence as false
    /// (older servers never send it).
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

    /// Remote control (remote-control plan §1): a sharer offered control of
    /// their machine to a named participant. Addressed PRIVATELY to the
    /// target only — the channel topic's authorization boundary is
    /// ViewChannel, not call membership, so offers must never fan out there.
    /// Carries the sharer's ephemeral public key and control-session id as
    /// opaque base64 (slice-3 key agreement; the server never interprets
    /// them). NOTE `EventV1::private` reaches every session of the target,
    /// including off-call devices — the accept route is what enforces that
    /// the responding party is the live participant.
    RemoteControlOffered {
        channel_id: String,
        offer_id: String,
        sharer_id: String,
        target_id: String,
        sharer_ephemeral_pub: String,
        rc_session_id: String,
        /// `kbm` or `gamepad` (couch co-op §2.2). ADVISORY — the class the
        /// two ends actually derive under is bound into their HKDF
        /// transcript; this is what the target's native layer is told to
        /// bind, and if the server lied the two transcripts would simply
        /// not match and the session would fail closed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input_class: Option<String>,
        /// The sharer's control-protocol version. Relayed so the target
        /// refuses a skew at accept time with a legible message rather than
        /// deriving a transcript that can never match. Absent means v1.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol_version: Option<u8>,
    },

    /// Remote control: the target declined an offer. Addressed PRIVATELY to
    /// the sharer only (a public decline would be a shaming vector).
    RemoteControlDeclined {
        channel_id: String,
        offer_id: String,
        sharer_id: String,
        target_id: String,
    },

    /// Remote control: the target accepted and the SFU grant is live.
    /// Addressed PRIVATELY to the SHARER only — this is the return path of
    /// the key exchange (the controller's ephemeral public key rides here;
    /// without it the sharer can never derive the session key, plan §1
    /// rev 8). The sharer's native layer matches it against the
    /// `rc_session_id` it minted. NEVER put this on the channel topic.
    RemoteControlAccepted {
        channel_id: String,
        offer_id: String,
        grant_id: String,
        sharer_id: String,
        controller_id: String,
        controller_ephemeral_pub: String,
        /// The CONTROLLER's control-protocol version, so the sharer can
        /// refuse a skew before its arming dialog and before it burns the
        /// session id. Absent means v1.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        controller_protocol_version: Option<u8>,
        /// The input class the CONTROLLER bound, so the sharer can refuse a
        /// class that moved between the offer and the accept — the one
        /// field this server relays and could therefore have changed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        controller_input_class: Option<String>,
    },

    /// Remote control: REDACTED channel-topic visibility event — third
    /// parties in the channel see that a control session is active and
    /// between whom (§8 third-party visibility), and nothing else: no grant
    /// id, no key material, no actionable fields. Emitted on the channel
    /// topic once per grant (at accept), and re-sent per-socket at Ready
    /// time for any grant still live (`remote_control_active_snapshot`,
    /// sessions whose Ready included `voice_states` only) — clients must
    /// treat re-delivery of the same triple as idempotent.
    /// Keyed per grant by (channel_id, sharer_id) — at most one active
    /// grant per sharer per channel — which is what `RemoteControlEnded`
    /// clears.
    RemoteControlActive {
        channel_id: String,
        sharer_id: String,
        controller_id: String,
        /// `kbm` or `gamepad`, so the channel badge can say which. Purely
        /// cosmetic: this event is already the REDACTED one and carries
        /// nothing actionable. A client that does not recognise the value
        /// must fall back to the classless wording rather than hiding the
        /// badge — a control session it cannot label is still a control
        /// session third parties are entitled to see.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input_class: Option<String>,
    },

    /// Remote control: a grant ended. Channel topic, keyed like
    /// `RemoteControlActive` so clients clear the active indicator by
    /// (channel_id, sharer_id).
    ///
    /// 🔴 `reason` is an OPEN vocabulary — treat it as an opaque string.
    /// Clients MUST clear on any value and must never switch over a fixed
    /// set: this enumeration was stale for several additions before it was
    /// rewritten, and a client that only recognises known values leaves a
    /// stale "X is controlling" claim on screen the first time a new one
    /// appears. The same computed string is stamped into the audit row, so
    /// it is descriptive, not a protocol.
    ///
    /// As of 2026-08-12 the values are, by origin:
    /// - client-informed via `?cause=`, re-validated server-side against a
    ///   fixed allowlist (`release_audit_reason`): "panic",
    ///   "connection_lost", "anti_cheat", "indicator_hidden",
    ///   "max_lifetime", "display_topology_changed", "calibration_rejected",
    ///   "turn_ended" (a "pass the controller" rotation handoff, NOT a yank);
    /// - role defaults when the cause is absent or unrecognised:
    ///   "revoked_by_sharer", "released_by_controller";
    /// - server-decided: "revoked_by_moderator", "screenshare_ended",
    ///   "participant_left", "permissions_changed", "reconnected",
    ///   "call_ended", and from the reaper "expired" / "disabled".
    ///
    /// ("released" is gone — it was the single collapsed value the
    /// sharer/controller split replaced.)
    RemoteControlEnded {
        channel_id: String,
        sharer_id: String,
        reason: String,
    },

    /// Remote control: a call participant asked a streaming participant for
    /// a control turn (pass-the-controller plan §2.4 "ask for a turn").
    /// Addressed PRIVATELY to the SHARER only — a raised hand is between the
    /// asker and the streamer, and the channel topic's boundary is
    /// ViewChannel, not call membership.
    ///
    /// `requester_id` is stamped server-side from the authenticated caller,
    /// never taken from the request body. Even so, the event is a
    /// SUGGESTION: it grants nothing, enters no queue by itself, and every
    /// actual turn still passes the native arm dialog on the sharer's
    /// machine. Like `RemoteControlOffered`, `EventV1::private` reaches
    /// every session of the sharer including off-call devices — receiving
    /// clients must scope to the call they are actually in.
    CallControlRequest {
        channel_id: String,
        requester_id: String,
        sharer_id: String,
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

    /// A soft-reserve sheet's reserve rows changed (set, replaced or
    /// retracted). Published on the channel topic — the topic is the
    /// authorization boundary. For HIDDEN sheets both `reserve` AND
    /// `changed_item_counts` are omitted (`total_reserves` only): the
    /// per-item aggregates are exactly the signal `hidden` hides, and the
    /// channel topic has one audience — leaders refetch over REST. For
    /// visible sheets `changed_item_counts` carries only the CHANGED
    /// items' new absolute counts (the delta the write computed anyway),
    /// which clients merge — never the full map.
    SoftresReserveUpdate {
        id: String,
        channel_id: String,
        message_id: String,
        total_reserves: i64,
        #[serde(skip_serializing_if = "HashMap::is_empty", default)]
        changed_item_counts: HashMap<String, u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reserve: Option<SoftResReserve>,
        #[serde(skip_serializing_if = "Option::is_none")]
        removed_user: Option<String>,
    },

    /// A soft-reserve sheet's settings or lock state changed (edit, lock,
    /// unlock, or event-cancellation lock). The embedded `sheet` is the
    /// PUBLIC-gated model (reserves / item_counts omitted when hidden,
    /// even for the leader, who refetches) — the ungated form must never
    /// reach the channel topic.
    SoftresSheetUpdate {
        id: String,
        channel_id: String,
        message_id: String,
        sheet: SoftRes,
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

    /// Suggestions a bot returned for the option the user is typing.
    /// Published ONLY on the invoking user's private topic — nobody else
    /// has any use for a half-typed argument.
    InteractionAutocompleteResult {
        interaction_id: String,
        choices: Vec<CommandChoice>,
    },

    /// A bot asked the invoking user to fill in a form. Published ONLY on
    /// that user's private topic.
    ///
    /// `interaction_id` is a FRESH interaction to submit the filled form
    /// against — deliberately not the one being answered, whose response
    /// slot this consumed. It carries no response token: the user
    /// authenticates the submission with their own session, and the bot
    /// only receives the token once the form comes back.
    InteractionModalOpen {
        interaction_id: String,
        source_id: String,
        modal: Modal,
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

    /// A Discord import advanced a stage. Published ONLY on the requesting
    /// user's private topic — an in-progress import is nobody else's
    /// business, and the half-built server is not yet visible to anyone.
    /// `stage` is the `ImportStage` variant name.
    DiscordImportProgress {
        job_id: String,
        stage: String,
        done: u32,
        total: u32,
    },

    /// A Discord import finished. Carries the created server and the
    /// invite minted for it. Requesting user's private topic only; the
    /// server itself becomes visible through the normal `ServerCreate`
    /// path, which MUST be emitted before this event.
    DiscordImportComplete {
        job_id: String,
        server_id: String,
        invite_code: String,
    },

    /// A Discord import failed permanently (bad template, provider
    /// unreachable, worker died and the heartbeat sweeper reaped it).
    /// `error` is a user-safe message, never a raw provider/internal
    /// error. Requesting user's private topic only.
    DiscordImportFailed {
        job_id: String,
        error: String,
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
