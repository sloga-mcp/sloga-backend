use std::{collections::HashMap, sync::Arc};

use futures::lock::Mutex;

use crate::{
    Bot, CalendarEvent, Channel, ChannelCompositeKey, ChannelUnread, E2EEBackup, E2EEBlob,
    E2EEEnvelope, E2EEIdentity, E2EEOneTimeKey, Emoji, EventRsvp, EventRsvpKey, File, FileHash,
    Invite, Member, MemberCompositeKey, Message, PolicyChange, RatelimitEvent, ReminderSent,
    ReminderSentKey, Report, Server, ServerBan, Snapshot, Sticker, User, UserSettings, Webhook,
    Account, AccountInvite, Session, MFATicket
};

database_derived!(
    /// Reference implementation
    #[derive(Default, Debug)]
    pub struct ReferenceDb {
        pub bots: Arc<Mutex<HashMap<String, Bot>>>,
        pub calendar_events: Arc<Mutex<HashMap<String, CalendarEvent>>>,
        pub event_rsvps: Arc<Mutex<HashMap<EventRsvpKey, EventRsvp>>>,
        pub event_reminders: Arc<Mutex<HashMap<ReminderSentKey, ReminderSent>>>,
        pub channels: Arc<Mutex<HashMap<String, Channel>>>,
        pub channel_invites: Arc<Mutex<HashMap<String, Invite>>>,
        pub channel_unreads: Arc<Mutex<HashMap<ChannelCompositeKey, ChannelUnread>>>,
        pub channel_webhooks: Arc<Mutex<HashMap<String, Webhook>>>,
        pub emojis: Arc<Mutex<HashMap<String, Emoji>>>,
        pub stickers: Arc<Mutex<HashMap<String, Sticker>>>,
        pub file_hashes: Arc<Mutex<HashMap<String, FileHash>>>,
        pub files: Arc<Mutex<HashMap<String, File>>>,
        pub messages: Arc<Mutex<HashMap<String, Message>>>,
        pub policy_changes: Arc<Mutex<HashMap<String, PolicyChange>>>,
        pub ratelimit_events: Arc<Mutex<HashMap<String, RatelimitEvent>>>,
        pub user_settings: Arc<Mutex<HashMap<String, UserSettings>>>,
        pub users: Arc<Mutex<HashMap<String, User>>>,
        pub server_bans: Arc<Mutex<HashMap<MemberCompositeKey, ServerBan>>>,
        pub server_members: Arc<Mutex<HashMap<MemberCompositeKey, Member>>>,
        pub servers: Arc<Mutex<HashMap<String, Server>>>,
        pub safety_reports: Arc<Mutex<HashMap<String, Report>>>,
        pub safety_snapshots: Arc<Mutex<HashMap<String, Snapshot>>>,
        pub accounts: Arc<Mutex<HashMap<String, Account>>>,
        pub account_invites: Arc<Mutex<HashMap<String, AccountInvite>>>,
        pub sessions: Arc<Mutex<HashMap<String, Session>>>,
        pub tickets: Arc<Mutex<HashMap<String, MFATicket>>>,
        pub e2ee_identities: Arc<Mutex<HashMap<String, E2EEIdentity>>>,
        pub e2ee_one_time_keys: Arc<Mutex<HashMap<String, E2EEOneTimeKey>>>,
        pub e2ee_queue: Arc<Mutex<HashMap<String, E2EEEnvelope>>>,
        pub e2ee_blobs: Arc<Mutex<HashMap<String, E2EEBlob>>>,
        pub e2ee_backups: Arc<Mutex<HashMap<String, E2EEBackup>>>,
    }
);
