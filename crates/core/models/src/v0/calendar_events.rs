#[cfg(feature = "validator")]
use validator::Validate;

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

    /// Optional event fields that a PATCH may unset
    pub enum FieldsEvent {
        Channel,
        Description,
        Location,
        End,
        Recurrence,
        Color,
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
        /// Fields to unset
        #[serde(default)]
        pub remove: Vec<FieldsEvent>,
    }

    /// Users to invite to an event
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataInviteToEvent {
        /// User ids to invite
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 100)))]
        pub users: Vec<String>,
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
