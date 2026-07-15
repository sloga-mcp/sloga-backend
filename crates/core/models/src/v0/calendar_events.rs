#[cfg(feature = "validator")]
use validator::Validate;

use super::File;

auto_derived!(
    /// How often a recurring event repeats
    pub enum Frequency {
        Daily,
        Weekly,
        Monthly,
    }

    /// Day of week for weekly recurrence
    pub enum Weekday {
        Monday,
        Tuesday,
        Wednesday,
        Thursday,
        Friday,
        Saturday,
        Sunday,
    }

    /// When a recurring series stops — always bounded
    #[serde(tag = "type")]
    pub enum RecurrenceEnd {
        /// After a fixed number of occurrences
        Count { count: u16 },
        /// On/after a specific instant (ms since Unix epoch, UTC)
        Until { timestamp: i64 },
    }

    /// Recurrence rule (bounded subset of RFC-5545)
    pub struct RecurrenceRule {
        /// Repeat frequency
        pub freq: Frequency,
        /// Repeat every N units of `freq`
        pub interval: u16,
        /// For weekly: which weekdays. Empty ⇒ the same weekday as `start`.
        #[serde(default)]
        pub by_weekday: Vec<Weekday>,
        /// Series terminator
        pub end: RecurrenceEnd,
        /// Occurrence-start instants (ms epoch) that are skipped
        #[serde(default)]
        pub exceptions: Vec<i64>,
    }

    /// Response state of an invitee
    pub enum RsvpStatus {
        /// Invited, no answer yet
        Pending,
        /// Accepted
        Going,
        /// Declined or withdrawn
        NotGoing,
    }

    /// A scheduled server calendar event
    pub struct Event {
        /// Unique event id
        #[serde(rename = "_id")]
        pub id: String,
        /// Owning server
        pub server: String,
        /// Optional associated channel
        #[serde(skip_serializing_if = "Option::is_none")]
        pub channel: Option<String>,
        /// Creator user id
        pub creator: String,
        /// Title
        pub title: String,
        /// Description
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// Free-text location
        #[serde(skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        /// UTC instant (ms epoch) of the first/only occurrence
        pub start: i64,
        /// UTC instant (ms epoch) the first/only occurrence ends
        #[serde(skip_serializing_if = "Option::is_none")]
        pub end: Option<i64>,
        /// Whether this is an all-day event
        pub all_day: bool,
        /// IANA timezone id anchoring recurrence
        pub timezone: String,
        /// Recurrence rule
        #[serde(skip_serializing_if = "Option::is_none")]
        pub recurrence: Option<RecurrenceRule>,
        /// Display colour
        #[serde(skip_serializing_if = "Option::is_none")]
        pub color: Option<String>,
        /// Whether the series is cancelled
        pub cancelled: bool,
        /// Files attached to the event; visible to anyone who can view the event
        #[serde(skip_serializing_if = "Option::is_none")]
        pub attachments: Option<Vec<File>>,
        /// Creation time (ms epoch)
        pub created_at: i64,
        /// Last edit time (ms epoch)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub edited_at: Option<i64>,
    }

    /// A user's RSVP to an event
    pub struct EventRsvp {
        /// User id
        pub user: String,
        /// Event id
        pub event: String,
        /// Current response
        pub status: RsvpStatus,
        /// Who invited the user
        pub invited_by: String,
        /// Whether the user ever accepted (distinguishes declined from cancelled-after-accept)
        pub had_accepted: bool,
        /// When the user last responded (ms epoch)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub responded_at: Option<i64>,
    }

    /// Attendee tallies for an event
    pub struct AttendeeCounts {
        pub going: i64,
        pub pending: i64,
        pub not_going: i64,
    }

    /// An event plus the caller's own RSVP and attendee tallies
    pub struct EventWithContext {
        /// The event
        pub event: Event,
        /// The caller's RSVP, if they were invited
        #[serde(skip_serializing_if = "Option::is_none")]
        pub my_rsvp: Option<EventRsvp>,
        /// Attendee counts by status
        pub counts: AttendeeCounts,
    }

    /// An event series plus its occurrence-start instants within the queried window.
    ///
    /// The list route expands recurrence server-side (the single DST-aware engine) and
    /// returns the per-occurrence starts (ms epoch, UTC), so the client renders one grid
    /// entry per occurrence without re-implementing recurrence math.
    pub struct EventWithOccurrences {
        /// The event series
        pub event: Event,
        /// Occurrence-start instants (ms epoch, UTC) overlapping the window, exceptions removed
        pub occurrences: Vec<i64>,
    }

    /// Optional event fields that a PATCH may unset
    pub enum FieldsEvent {
        Channel,
        Description,
        Location,
        End,
        Recurrence,
        Color,
        Attachments,
    }
);

auto_derived!(
    /// New event data
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataCreateEvent {
        /// Title
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 100)))]
        pub title: String,
        /// Optional description
        #[cfg_attr(feature = "validator", validate(length(max = 2000)))]
        #[serde(default)]
        pub description: Option<String>,
        /// Optional free-text location
        #[cfg_attr(feature = "validator", validate(length(max = 200)))]
        #[serde(default)]
        pub location: Option<String>,
        /// UTC instant (ms epoch) of the first/only occurrence
        pub start: i64,
        /// UTC instant (ms epoch) the first/only occurrence ends
        #[serde(default)]
        pub end: Option<i64>,
        /// Whether this is an all-day event
        #[serde(default)]
        pub all_day: bool,
        /// IANA timezone id (validated server-side)
        pub timezone: String,
        /// Optional recurrence rule
        #[serde(default)]
        pub recurrence: Option<RecurrenceRule>,
        /// Optional colour
        #[cfg_attr(feature = "validator", validate(length(max = 32)))]
        #[serde(default)]
        pub color: Option<String>,
        /// Optional associated channel; requires ViewChannel there
        #[serde(default)]
        pub channel: Option<String>,
        /// Optional attachment file ids (uploaded to the `attachments` bucket, claimed
        /// server-side). Capped at `MAX_EVENT_ATTACHMENTS` (10) — must match the constant.
        #[cfg_attr(feature = "validator", validate(length(max = 10)))]
        #[serde(default)]
        pub attachments: Option<Vec<String>>,
    }

    /// Event edit data
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataEditEvent {
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 100)))]
        #[serde(default)]
        pub title: Option<String>,
        #[cfg_attr(feature = "validator", validate(length(max = 2000)))]
        #[serde(default)]
        pub description: Option<String>,
        #[cfg_attr(feature = "validator", validate(length(max = 200)))]
        #[serde(default)]
        pub location: Option<String>,
        #[serde(default)]
        pub start: Option<i64>,
        #[serde(default)]
        pub end: Option<i64>,
        #[serde(default)]
        pub all_day: Option<bool>,
        #[serde(default)]
        pub timezone: Option<String>,
        #[serde(default)]
        pub recurrence: Option<RecurrenceRule>,
        #[cfg_attr(feature = "validator", validate(length(max = 32)))]
        #[serde(default)]
        pub color: Option<String>,
        /// Attachment file ids to ADD (uploaded to the `attachments` bucket, claimed
        /// server-side). The resulting total (kept + added) is capped at
        /// `MAX_EVENT_ATTACHMENTS` server-side; this per-request add-list is capped here.
        #[cfg_attr(feature = "validator", validate(length(max = 10)))]
        #[serde(default)]
        pub attachments: Option<Vec<String>>,
        /// Attachment file ids to DETACH from the event (files are marked deleted)
        #[cfg_attr(feature = "validator", validate(length(max = 10)))]
        #[serde(default)]
        pub remove_attachments: Option<Vec<String>>,
        /// Fields to unset (`Attachments` clears the whole attachment set)
        #[serde(default)]
        pub remove: Vec<FieldsEvent>,
    }

    /// Users and/or roles to invite to an event. At least one of `users`/`roles`
    /// must be non-empty (enforced at the route).
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataInviteToEvent {
        /// User ids to invite
        #[cfg_attr(feature = "validator", validate(length(max = 100)))]
        #[serde(default)]
        pub users: Option<Vec<String>>,
        /// Role ids whose current holders are invited (server-side expansion —
        /// slice F, decision 0.1-A). Unknown roles fail the whole request.
        #[cfg_attr(feature = "validator", validate(length(max = 25)))]
        #[serde(default)]
        pub roles: Option<Vec<String>>,
    }

    /// Result of an invite request
    pub struct InviteResult {
        /// Number of genuinely-new invitees (RSVP rows created)
        pub invited: usize,
        /// Number skipped: non-members, pending-deletion members, invitees without
        /// channel view permission, or users who already had an RSVP row
        pub skipped: usize,
    }

    /// Import legacy `[ACUTEST_EVENT]:`-tagged messages from a channel (design §11)
    pub struct DataImportLegacyEvents {
        /// Channel to scan for tagged messages; must belong to the server and be
        /// viewable by the caller
        pub channel: String,
    }

    /// Result of a legacy import run
    pub struct ImportResult {
        /// Events created
        pub imported: usize,
        /// Tagged messages skipped because they were already imported
        /// (`source_message_id` dedup)
        pub skipped_duplicates: usize,
        /// Tagged messages rejected by validation (bad JSON, title/description
        /// length, unparseable start, end before start)
        pub skipped_invalid: usize,
        /// Messages scanned in total
        pub scanned: usize,
        /// Whether the scan stopped at the message cap before exhausting history
        pub truncated: bool,
    }

    /// Set the caller's RSVP
    pub struct DataSetRsvp {
        /// Target status (`Going` or `NotGoing`; `Pending` is rejected)
        pub status: RsvpStatus,
    }

    /// Paginated attendee list
    pub struct AttendeesResponse {
        /// RSVP rows
        pub attendees: Vec<EventRsvp>,
    }
);
