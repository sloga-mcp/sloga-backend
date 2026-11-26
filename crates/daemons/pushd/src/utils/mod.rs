mod renderer;
mod consumer;
pub mod protected;

pub use renderer::render_notification_content;
pub use consumer::{Consumer, Delegate};
pub use protected::{is_protected, PROTECTED_PUSH_TITLE};

use std::time::{SystemTime, UNIX_EPOCH};

use revolt_database::{
    events::rabbit::DmCallPayload, iso8601_timestamp::Timestamp, WebPushSubscription,
};
use revolt_models::v0;

/// What a push is about, as far as a session's push preferences care
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushClass {
    /// A message in a direct message, a group or saved notes
    ChatMessage,
    /// A message in a channel that belongs to a server
    ServerMessage,
    /// A mention of many members at once in a server
    MassMention,
    /// An invitation, cancellation or reminder for a server's calendar event
    CalendarEvent,
    /// A friend request, received or accepted
    // No preference silences a friend request or a generic push, so their consumers never
    // ask. The two classes exist so that rule is written down and tested with the others.
    #[allow(dead_code)]
    FriendRequest,
    /// An incoming call ringing
    Call,
    /// Anything else the server sends to one user
    #[allow(dead_code)]
    Generic,
}

/// Whether this session wants a push of this class.
///
/// A session that never set a preference gets everything, exactly as it did before the
/// preferences existed, and only an explicit `true` turns one on. `chats_only` silences
/// what comes from a server and nothing else. `no_ring` silences the ring of an incoming
/// call and nothing else. With `scope_enabled` off (the `push_session_scope` switch) both
/// preferences are ignored.
pub fn session_wants(sub: &WebPushSubscription, class: PushClass, scope_enabled: bool) -> bool {
    if !scope_enabled {
        return true;
    }

    // Every class is named, with no catch-all: a new class has to be placed on purpose.
    match class {
        PushClass::Call => sub.no_ring != Some(true),
        PushClass::ServerMessage | PushClass::MassMention | PushClass::CalendarEvent => {
            sub.chats_only != Some(true)
        }
        PushClass::ChatMessage | PushClass::FriendRequest | PushClass::Generic => true,
    }
}

/// Whether this session wants this call push.
///
/// `no_ring` silences the ring only. The push that says a call is over is what stops a
/// phone that is already ringing, and a ring can be on its way to a session that turns
/// the preference on a moment later, so that push always goes out.
pub fn session_wants_call(
    sub: &WebPushSubscription,
    alert: &DmCallPayload,
    scope_enabled: bool,
) -> bool {
    alert.ended || session_wants(sub, PushClass::Call, scope_enabled)
}

/// Which class a message push falls in, by the channel the message was sent in.
///
/// Every channel type is named, with no catch-all: a new type has to be placed on purpose,
/// because a conversation that lands on the server side by accident loses its pushes for
/// every session that asked for chats only.
pub fn message_push_class(channel: &v0::Channel) -> PushClass {
    match channel {
        v0::Channel::SavedMessages { .. }
        | v0::Channel::DirectMessage { .. }
        | v0::Channel::Group { .. } => PushClass::ChatMessage,
        v0::Channel::TextChannel { .. }
        | v0::Channel::Thread { .. }
        | v0::Channel::Forum { .. } => PushClass::ServerMessage,
    }
}

/// How long a push saying a call is over may wait for its device. Past that, the ring it
/// would have stopped has long given up by itself.
const ENDED_CALL_PUSH_TTL_SECS: u32 = 60;

/// What to do with a call push
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallPushTtl {
    /// The ring is already over: send nothing
    Drop,
    /// Hand it to the push service with this many seconds to live
    Secs(u32),
}

/// How long a call push may live, or that it must not be sent at all.
///
/// A ring is only worth delivering while the call is still ringing: a phone that comes
/// back online a minute later must not start ringing for a call nobody is waiting on. So a
/// ring lives for what is left of the ring time, counted from the `started_at` it carries,
/// and one that is already past it is dropped. A ring whose start is missing or unreadable
/// gets the whole ring time, because a late ring is better than a lost call, and a start
/// that lies in the future (two clocks disagreeing) counts as starting now.
///
/// `ring_secs` is the configured ring length. It goes through `effective_call_ring_secs`
/// once more here: that changes nothing for a caller that already did it, and it keeps a
/// raw zero from cutting every ring down to a single second.
pub fn call_push_ttl(alert: &DmCallPayload, now_unix: i64, ring_secs: usize) -> CallPushTtl {
    if alert.ended {
        return CallPushTtl::Secs(ENDED_CALL_PUSH_TTL_SECS);
    }

    let ring =
        i64::try_from(revolt_config::effective_call_ring_secs(ring_secs)).unwrap_or(i64::MAX);

    let Some(started_unix) = alert.started_at.as_deref().and_then(started_at_unix) else {
        return CallPushTtl::Secs(u32::try_from(ring).unwrap_or(u32::MAX));
    };

    let elapsed = now_unix.saturating_sub(started_unix).max(0);
    if elapsed > ring {
        return CallPushTtl::Drop;
    }

    // A push service reads a lifetime of zero as "deliver now or never", which would lose
    // the last second of the ring for a phone that is only briefly unreachable.
    CallPushTtl::Secs(u32::try_from((ring - elapsed).max(1)).unwrap_or(u32::MAX))
}

/// Unix seconds of a call's `started_at`. The voice service writes it as an ISO 8601 time
/// in UTC with milliseconds, like `2026-09-23T00:00:00.000Z`.
fn started_at_unix(started_at: &str) -> Option<i64> {
    Timestamp::parse(started_at)
        .map(|started| started.duration_since(Timestamp::UNIX_EPOCH).whole_seconds())
}

/// The current time in unix seconds, for [`call_push_ttl`].
///
/// A clock set before 1970 reads as zero. Every ring then looks as if it starts in the
/// future and keeps its whole ring time, so a broken clock delays nothing and drops nothing.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since_epoch| i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use revolt_database::{
        events::rabbit::{DmCallPayload, CALL_REASON_ANSWERED_ELSEWHERE},
        iso8601_timestamp::{Duration, Timestamp},
        WebPushSubscription,
    };
    use revolt_models::v0;
    use serde_json::json;

    use super::{
        call_push_ttl, message_push_class, now_unix, session_wants, session_wants_call,
        CallPushTtl, PushClass,
    };

    /// The three states a stored preference can be in
    const SETTINGS: [Option<bool>; 3] = [None, Some(false), Some(true)];

    /// The two states that must both read as "not set"
    const UNSET: [Option<bool>; 2] = [None, Some(false)];

    /// The preference that can silence a class, if any
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Silencer {
        Nothing,
        ChatsOnly,
        NoRing,
    }

    /// The whole rule, one row per class
    const RULES: [(PushClass, Silencer); 7] = [
        (PushClass::ChatMessage, Silencer::Nothing),
        (PushClass::ServerMessage, Silencer::ChatsOnly),
        (PushClass::MassMention, Silencer::ChatsOnly),
        (PushClass::CalendarEvent, Silencer::ChatsOnly),
        (PushClass::FriendRequest, Silencer::Nothing),
        (PushClass::Call, Silencer::NoRing),
        (PushClass::Generic, Silencer::Nothing),
    ];

    /// The row of `RULES` a class sits in. It stops compiling when a class is added, so a
    /// new class cannot go without a row.
    fn row_of(class: PushClass) -> usize {
        match class {
            PushClass::ChatMessage => 0,
            PushClass::ServerMessage => 1,
            PushClass::MassMention => 2,
            PushClass::CalendarEvent => 3,
            PushClass::FriendRequest => 4,
            PushClass::Call => 5,
            PushClass::Generic => 6,
        }
    }

    fn session(chats_only: Option<bool>, no_ring: Option<bool>) -> WebPushSubscription {
        WebPushSubscription {
            endpoint: "fcm".to_string(),
            p256dh: String::new(),
            auth: "token".to_string(),
            kind: None,
            chats_only,
            no_ring,
        }
    }

    fn channel(value: serde_json::Value) -> v0::Channel {
        serde_json::from_value(value).expect("a channel")
    }

    /// Midnight UTC on 2026-09-23, in unix seconds
    const STARTED_UNIX: i64 = 1_790_121_600;

    /// The same moment, as the voice service writes it into the ring
    const STARTED_AT: &str = "2026-09-23T00:00:00.000Z";

    const RING_SECS: usize = 45;

    fn ring(started_at: Option<&str>) -> DmCallPayload {
        DmCallPayload {
            initiator_id: "01CALLER".to_string(),
            channel_id: "01CHANNEL".to_string(),
            started_at: started_at.map(str::to_string),
            ended: false,
            call_id: Some("01CALL".to_string()),
            ..Default::default()
        }
    }

    fn ended(started_at: Option<&str>) -> DmCallPayload {
        DmCallPayload {
            ended: true,
            reason: Some(CALL_REASON_ANSWERED_ELSEWHERE.to_string()),
            ..ring(started_at)
        }
    }

    /// Every class against every state of both preferences and of the switch.
    #[test]
    fn session_wants_matches_the_rule_for_every_class_preference_and_switch() {
        let mut cases = 0;

        for (class, silencer) in RULES {
            assert_eq!(RULES[row_of(class)].0, class, "{class:?} has its own row");

            for chats_only in SETTINGS {
                for no_ring in SETTINGS {
                    for scope_enabled in [false, true] {
                        let silenced = scope_enabled
                            && match silencer {
                                Silencer::Nothing => false,
                                Silencer::ChatsOnly => chats_only == Some(true),
                                Silencer::NoRing => no_ring == Some(true),
                            };

                        assert_eq!(
                            session_wants(&session(chats_only, no_ring), class, scope_enabled),
                            !silenced,
                            "{class:?}, chats_only {chats_only:?}, no_ring {no_ring:?}, switch {scope_enabled}"
                        );
                        cases += 1;
                    }
                }
            }
        }

        assert_eq!(cases, 7 * 3 * 3 * 2);
    }

    /// The switch is the way back to how pushes worked before the preferences: with it
    /// off, a session that set both still gets everything.
    #[test]
    fn with_the_switch_off_both_preferences_are_ignored() {
        let sub = session(Some(true), Some(true));

        for (class, _) in RULES {
            assert!(session_wants(&sub, class, false), "{class:?}");
        }
    }

    /// Sessions stored before the preferences existed carry neither key, and an app may
    /// send `false`. Both must keep receiving everything.
    #[test]
    fn a_preference_that_is_missing_or_false_silences_nothing() {
        for chats_only in UNSET {
            for no_ring in UNSET {
                let sub = session(chats_only, no_ring);

                for (class, _) in RULES {
                    assert!(
                        session_wants(&sub, class, true),
                        "{class:?}, chats_only {chats_only:?}, no_ring {no_ring:?}"
                    );
                }
            }
        }
    }

    /// `chats_only` is about servers. A direct message, a group message, a friend request,
    /// a call or a generic push must never be lost to it.
    #[test]
    fn chats_only_silences_what_comes_from_a_server_and_nothing_else() {
        for no_ring in UNSET {
            let sub = session(Some(true), no_ring);

            assert!(!session_wants(&sub, PushClass::ServerMessage, true));
            assert!(!session_wants(&sub, PushClass::MassMention, true));
            assert!(!session_wants(&sub, PushClass::CalendarEvent, true));

            assert!(session_wants(&sub, PushClass::ChatMessage, true));
            assert!(session_wants(&sub, PushClass::FriendRequest, true));
            assert!(session_wants(&sub, PushClass::Call, true));
            assert!(session_wants(&sub, PushClass::Generic, true));
        }
    }

    /// `no_ring` is about the ring. Messages, mentions, events and friend requests keep
    /// arriving on a session that must not ring.
    #[test]
    fn no_ring_silences_the_ring_and_nothing_else() {
        for chats_only in UNSET {
            let sub = session(chats_only, Some(true));

            assert!(!session_wants(&sub, PushClass::Call, true));

            assert!(session_wants(&sub, PushClass::ChatMessage, true));
            assert!(session_wants(&sub, PushClass::ServerMessage, true));
            assert!(session_wants(&sub, PushClass::MassMention, true));
            assert!(session_wants(&sub, PushClass::CalendarEvent, true));
            assert!(session_wants(&sub, PushClass::FriendRequest, true));
            assert!(session_wants(&sub, PushClass::Generic, true));
        }
    }

    /// Asked about through `session_wants_call`, a ring still obeys `no_ring` and the switch.
    #[test]
    fn a_ring_is_not_sent_to_a_session_that_must_not_ring() {
        let alert = ring(Some(STARTED_AT));

        assert!(!session_wants_call(&session(None, Some(true)), &alert, true));
        assert!(session_wants_call(&session(None, Some(true)), &alert, false));
        assert!(session_wants_call(&session(None, None), &alert, true));
        assert!(session_wants_call(&session(None, Some(false)), &alert, true));
        assert!(session_wants_call(&session(Some(true), None), &alert, true));
    }

    /// The push that stops a ring has to reach every session the ring may have reached,
    /// including one that turned `no_ring` on while the ring was on its way.
    #[test]
    fn an_ended_call_push_reaches_a_session_that_must_not_ring() {
        let alert = ended(None);

        for chats_only in SETTINGS {
            for no_ring in SETTINGS {
                for scope_enabled in [false, true] {
                    assert!(
                        session_wants_call(&session(chats_only, no_ring), &alert, scope_enabled),
                        "chats_only {chats_only:?}, no_ring {no_ring:?}, switch {scope_enabled}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_message_in_a_conversation_is_a_chat_message() {
        let saved_notes = channel(json!({
            "channel_type": "SavedMessages",
            "_id": "01CHANNEL",
            "user": "01USER",
        }));
        let direct_message = channel(json!({
            "channel_type": "DirectMessage",
            "_id": "01CHANNEL",
            "active": true,
            "recipients": ["01USER", "01OTHER"],
        }));
        let group = channel(json!({
            "channel_type": "Group",
            "_id": "01CHANNEL",
            "name": "Friends",
            "owner": "01USER",
            "recipients": ["01USER", "01OTHER", "01THIRD"],
        }));

        assert!(matches!(saved_notes, v0::Channel::SavedMessages { .. }));
        assert!(matches!(direct_message, v0::Channel::DirectMessage { .. }));
        assert!(matches!(group, v0::Channel::Group { .. }));

        assert_eq!(message_push_class(&saved_notes), PushClass::ChatMessage);
        assert_eq!(message_push_class(&direct_message), PushClass::ChatMessage);
        assert_eq!(message_push_class(&group), PushClass::ChatMessage);
    }

    #[test]
    fn a_message_in_a_server_is_a_server_message() {
        let text_channel = channel(json!({
            "channel_type": "TextChannel",
            "_id": "01CHANNEL",
            "server": "01SERVER",
            "name": "general",
        }));
        let thread = channel(json!({
            "channel_type": "Thread",
            "_id": "01THREAD",
            "server": "01SERVER",
            "parent_channel": "01CHANNEL",
            "name": "thread",
            "creator": "01USER",
        }));
        let forum = channel(json!({
            "channel_type": "Forum",
            "_id": "01FORUM",
            "server": "01SERVER",
            "name": "help",
        }));

        assert!(matches!(text_channel, v0::Channel::TextChannel { .. }));
        assert!(matches!(thread, v0::Channel::Thread { .. }));
        assert!(matches!(forum, v0::Channel::Forum { .. }));

        assert_eq!(message_push_class(&text_channel), PushClass::ServerMessage);
        assert_eq!(message_push_class(&thread), PushClass::ServerMessage);
        assert_eq!(message_push_class(&forum), PushClass::ServerMessage);
    }

    /// The two helpers together, the way the message consumer uses them.
    #[test]
    fn a_chats_only_session_keeps_its_group_messages_and_loses_server_ones() {
        let sub = session(Some(true), None);
        let group = channel(json!({
            "channel_type": "Group",
            "_id": "01CHANNEL",
            "name": "Friends",
            "owner": "01USER",
            "recipients": ["01USER", "01OTHER"],
        }));
        let text_channel = channel(json!({
            "channel_type": "TextChannel",
            "_id": "01CHANNEL",
            "server": "01SERVER",
            "name": "general",
        }));

        assert!(session_wants(&sub, message_push_class(&group), true));
        assert!(!session_wants(&sub, message_push_class(&text_channel), true));
        assert!(session_wants(&sub, message_push_class(&text_channel), false));
    }

    #[test]
    fn a_ring_that_just_started_lives_for_the_whole_ring_time() {
        assert_eq!(
            call_push_ttl(&ring(Some(STARTED_AT)), STARTED_UNIX, RING_SECS),
            CallPushTtl::Secs(45)
        );
    }

    #[test]
    fn a_ring_that_is_half_over_lives_for_the_time_that_is_left() {
        assert_eq!(
            call_push_ttl(&ring(Some(STARTED_AT)), STARTED_UNIX + 20, RING_SECS),
            CallPushTtl::Secs(25)
        );
        assert_eq!(
            call_push_ttl(&ring(Some(STARTED_AT)), STARTED_UNIX + 44, RING_SECS),
            CallPushTtl::Secs(1)
        );
    }

    /// At the last second of the ring the push still goes out, and with one second to
    /// live, never zero.
    #[test]
    fn a_ring_exactly_at_its_end_is_still_sent_with_one_second_to_live() {
        assert_eq!(
            call_push_ttl(&ring(Some(STARTED_AT)), STARTED_UNIX + 45, RING_SECS),
            CallPushTtl::Secs(1)
        );
    }

    #[test]
    fn a_ring_past_its_end_is_dropped() {
        assert_eq!(
            call_push_ttl(&ring(Some(STARTED_AT)), STARTED_UNIX + 46, RING_SECS),
            CallPushTtl::Drop
        );
        assert_eq!(
            call_push_ttl(&ring(Some(STARTED_AT)), STARTED_UNIX + 3_600, RING_SECS),
            CallPushTtl::Drop
        );
    }

    /// The voice service stamps the ring with its own clock. When that clock runs ahead of
    /// this one the ring must not live longer than a ring.
    #[test]
    fn a_ring_that_starts_in_the_future_counts_as_starting_now() {
        assert_eq!(
            call_push_ttl(&ring(Some(STARTED_AT)), STARTED_UNIX - 30, RING_SECS),
            CallPushTtl::Secs(45)
        );
    }

    /// Publishers from before the ring fields may send no start at all, and nothing here
    /// may turn a start it cannot read into a lost call.
    #[test]
    fn a_ring_with_a_missing_or_unreadable_start_lives_for_the_whole_ring_time() {
        // A moment at which every readable start in this list would be long past
        let now = STARTED_UNIX + 3_600;

        assert_eq!(
            call_push_ttl(&ring(None), now, RING_SECS),
            CallPushTtl::Secs(45)
        );

        for unreadable in ["", "not a time", "1790121600", "2026-13-45T99:99:99.000Z"] {
            assert_eq!(
                call_push_ttl(&ring(Some(unreadable)), now, RING_SECS),
                CallPushTtl::Secs(45),
                "{unreadable:?}"
            );
        }
    }

    /// The push that stops a ring is never dropped for being late and never tied to the
    /// ring time, whatever start it carries.
    #[test]
    fn an_ended_call_push_lives_for_a_minute_whatever_its_start() {
        let now = STARTED_UNIX + 3_600;

        assert_eq!(
            call_push_ttl(&ended(None), now, RING_SECS),
            CallPushTtl::Secs(60)
        );
        assert_eq!(
            call_push_ttl(&ended(Some(STARTED_AT)), now, RING_SECS),
            CallPushTtl::Secs(60)
        );
        assert_eq!(
            call_push_ttl(&ended(Some("not a time")), now, RING_SECS),
            CallPushTtl::Secs(60)
        );
        assert_eq!(
            call_push_ttl(&ended(Some(STARTED_AT)), STARTED_UNIX, 120),
            CallPushTtl::Secs(60)
        );
    }

    /// The start is read in the exact form the voice service produces: the join time, in
    /// whole unix seconds, turned into a timestamp and written out with `to_string()`.
    #[test]
    fn the_start_the_voice_service_writes_is_read_back_to_the_same_second() {
        let written = Timestamp::UNIX_EPOCH
            .checked_add(Duration::seconds(STARTED_UNIX))
            .expect("a timestamp")
            .to_string();

        assert_eq!(written, STARTED_AT);
        assert_eq!(
            call_push_ttl(&ring(Some(written.as_str())), STARTED_UNIX + 10, RING_SECS),
            CallPushTtl::Secs(35)
        );
    }

    /// A caller that hands over the raw setting must still get a ring of the agreed
    /// length: zero means the default, and anything else is kept between 5 and 120.
    #[test]
    fn a_raw_ring_setting_is_brought_to_the_agreed_ring_time() {
        assert_eq!(
            call_push_ttl(&ring(Some(STARTED_AT)), STARTED_UNIX, 0),
            CallPushTtl::Secs(45)
        );
        assert_eq!(
            call_push_ttl(&ring(Some(STARTED_AT)), STARTED_UNIX + 46, 0),
            CallPushTtl::Drop
        );
        assert_eq!(
            call_push_ttl(&ring(None), STARTED_UNIX, 100_000),
            CallPushTtl::Secs(120)
        );
    }

    /// The clock is in seconds, like the starts it is compared with. Milliseconds here
    /// would make every ring look years past its end.
    #[test]
    fn the_clock_reads_in_unix_seconds() {
        let now = now_unix();

        // After 2023 and before 2286
        assert!(now > 1_700_000_000, "{now}");
        assert!(now < 10_000_000_000, "{now}");
    }
}
