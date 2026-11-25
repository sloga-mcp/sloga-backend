use std::collections::HashMap;

use revolt_models::v0::PushNotification;
use serde::{Deserialize, Serialize};

use crate::User;

#[derive(Serialize, Deserialize)]
pub struct MessageSentPayload {
    pub notification: PushNotification,
    pub users: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct MassMessageSentPayload {
    pub notifications: Vec<PushNotification>,
    pub server_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FRAcceptedPayload {
    pub accepted_user: User,
    pub user: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FRReceivedPayload {
    pub from_user: User,
    pub user: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GenericPayload {
    pub title: String,
    pub body: String,
    pub icon: Option<String>,
    pub user: User,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct DmCallPayload {
    pub initiator_id: String,
    pub channel_id: String,
    pub started_at: Option<String>,
    pub ended: bool,
    /// Identifies one ring; every later signal about that ring repeats it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// Why the ringing stopped; only ever set together with `ended = true`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether the caller started a video call
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video: Option<bool>,
}

// The values `DmCallPayload::reason` takes. They travel inside push payloads to apps that
// are already installed, so a value that has shipped must never be renamed.
pub const CALL_REASON_ANSWERED_ELSEWHERE: &str = "answered_elsewhere";
pub const CALL_REASON_DECLINED: &str = "declined";
pub const CALL_REASON_CANCELLED: &str = "cancelled";
pub const CALL_REASON_ENDED: &str = "ended";

#[derive(Serialize, Deserialize, Clone)]
pub struct InternalDmCallPayload {
    pub payload: DmCallPayload,
    pub recipients: Option<Vec<String>>,
}

/// Which calendar-event moment a notification is about (design §9).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CalendarEventNotification {
    /// A user was invited to an event
    Invited,
    /// An event the user is Going to was cancelled
    Cancelled,
    /// Reminder that an occurrence is starting soon / now
    Reminder,
}

impl CalendarEventNotification {
    /// Stable client-facing discriminator carried in the push data payload.
    pub fn as_str(&self) -> &'static str {
        match self {
            CalendarEventNotification::Invited => "invited",
            CalendarEventNotification::Cancelled => "cancelled",
            CalendarEventNotification::Reminder => "reminder",
        }
    }
}

/// A per-recipient calendar-event push. Carries only ids + the event title the
/// recipient already saw when invited/RSVPing — never channel contents — so it is
/// safe to deliver to a `Going` attendee who has since lost `ViewChannel`
/// (design §8/§9: pushd is authoritative for `Going` rows, keyed by user id).
#[derive(Serialize, Deserialize, Clone)]
pub struct CalendarEventPayload {
    /// Recipient user id
    pub user: String,
    /// Event id (for client deep-linking)
    pub event_id: String,
    /// Owning server id
    pub server_id: String,
    /// Event title
    pub title: String,
    /// What happened
    pub kind: CalendarEventNotification,
    /// For `Reminder`: the specific occurrence start (ms epoch); absent otherwise
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence_start: Option<i64>,
    /// The event's channel id, when channel-scoped — lets clients deep-link
    /// straight to it (e.g. "Join channel" for a voice-channel event). Still an
    /// opaque id, never channel contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    /// For `Reminder`: the lead offset this firing represents (ms before the
    /// occurrence; 0 = at start). Explicit so wording never guesses from clocks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset_ms: Option<i64>,
}

impl CalendarEventPayload {
    /// Fallback `(title, body)` text for platforms that render server-side (APN/VAPID).
    /// Rich clients instead route on the structured `kind`/`event_id` in the data payload.
    pub fn render(&self) -> (String, String) {
        match self.kind {
            CalendarEventNotification::Invited => (
                "Event invitation".to_string(),
                format!("You're invited to {}", self.title),
            ),
            CalendarEventNotification::Cancelled => (
                "Event cancelled".to_string(),
                format!("{} was cancelled", self.title),
            ),
            CalendarEventNotification::Reminder => match self.offset_ms {
                Some(0) => (
                    "Event started".to_string(),
                    format!("{} has started", self.title),
                ),
                _ => (
                    "Upcoming event".to_string(),
                    format!("{} is starting soon", self.title),
                ),
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
#[allow(clippy::large_enum_variant)]
pub enum PayloadKind {
    MessageNotification(PushNotification),
    FRAccepted(FRAcceptedPayload),
    FRReceived(FRReceivedPayload),
    BadgeUpdate(usize),
    Generic(GenericPayload),
    DmCallStartEnd(DmCallPayload),
    CalendarEvent(CalendarEventPayload),
}

#[derive(Serialize, Deserialize)]
pub struct PayloadToService {
    pub notification: PayloadKind,
    pub user_id: String,
    pub session_id: String,
    pub token: String,
    pub extras: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct AckPayload {
    pub user_id: String,
    pub channel_id: String,
    pub message_id: String,
}

/// This is not the same as the AckPayload above, as the state for this event is stored in redis to allow for state updates while the event is queued.
#[derive(Serialize, Deserialize, Debug)]
pub struct AckEventPayload {
    pub user_id: String,
    pub channel_id: Option<String>,
    pub server_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{DmCallPayload, CALL_REASON_DECLINED};

    /// A push daemon or an app that predates the ring fields must see the payload it has
    /// always seen. An unset new field has to be left out, not sent as `null`: an extra
    /// key is exactly what a strict older reader would trip over.
    #[test]
    fn a_call_payload_without_ring_fields_serializes_to_the_four_original_keys() {
        let payload = DmCallPayload {
            initiator_id: "01USER".to_string(),
            channel_id: "01CHANNEL".to_string(),
            started_at: Some("2026-09-23T00:00:00.000Z".to_string()),
            ended: false,
            call_id: None,
            reason: None,
            video: None,
        };

        assert_eq!(
            serde_json::to_value(&payload).expect("serializes"),
            serde_json::json!({
                "initiator_id": "01USER",
                "channel_id": "01CHANNEL",
                "started_at": "2026-09-23T00:00:00.000Z",
                "ended": false
            })
        );
    }

    /// A call signal queued by a publisher that predates the ring fields is still waiting
    /// in the broker when the consumer restarts on the new code, and has to decode.
    #[test]
    fn a_call_payload_holding_only_the_four_original_keys_still_decodes() {
        let payload: DmCallPayload = serde_json::from_str(
            r#"{"initiator_id":"01USER","channel_id":"01CHANNEL","started_at":null,"ended":true}"#,
        )
        .expect("deserializes");

        assert_eq!(payload.initiator_id, "01USER");
        assert_eq!(payload.channel_id, "01CHANNEL");
        assert_eq!(payload.started_at, None);
        assert!(payload.ended);
        assert_eq!(payload.call_id, None);
        assert_eq!(payload.reason, None);
        assert_eq!(payload.video, None);
    }

    /// The ring fields are only useful if they survive the trip through the queue under
    /// the names the apps read.
    #[test]
    fn a_call_payload_with_every_ring_field_set_round_trips() {
        let payload = DmCallPayload {
            initiator_id: "01USER".to_string(),
            channel_id: "01CHANNEL".to_string(),
            started_at: None,
            ended: true,
            call_id: Some("01CALL".to_string()),
            reason: Some(CALL_REASON_DECLINED.to_string()),
            video: Some(true),
        };

        let wire = serde_json::to_value(&payload).expect("serializes");
        assert_eq!(
            wire,
            serde_json::json!({
                "initiator_id": "01USER",
                "channel_id": "01CHANNEL",
                "started_at": null,
                "ended": true,
                "call_id": "01CALL",
                "reason": "declined",
                "video": true
            })
        );

        let decoded: DmCallPayload = serde_json::from_value(wire).expect("deserializes");
        assert_eq!(decoded.initiator_id, "01USER");
        assert_eq!(decoded.channel_id, "01CHANNEL");
        assert_eq!(decoded.started_at, None);
        assert!(decoded.ended);
        assert_eq!(decoded.call_id.as_deref(), Some("01CALL"));
        assert_eq!(decoded.reason.as_deref(), Some(CALL_REASON_DECLINED));
        assert_eq!(decoded.video, Some(true));
    }
}
