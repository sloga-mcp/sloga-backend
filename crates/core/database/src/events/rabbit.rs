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

#[derive(Serialize, Deserialize, Clone)]
pub struct DmCallPayload {
    pub initiator_id: String,
    pub channel_id: String,
    pub started_at: Option<String>,
    pub ended: bool,
}

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
            CalendarEventNotification::Reminder => (
                "Upcoming event".to_string(),
                format!("{} is starting soon", self.title),
            ),
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
