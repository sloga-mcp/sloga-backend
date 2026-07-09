use chrono::{
    DateTime, Datelike, Duration, LocalResult, NaiveDate, NaiveDateTime, Offset, TimeZone, Utc,
};
use chrono_tz::Tz;
use revolt_result::{create_error, Result};
use ulid::Ulid;

use crate::Database;

/// Hard upper bound on how many occurrences a recurring series may expand to.
/// Bounds both the (storage-free) window expansion and `series_end` computation,
/// so no rule can ever fan out unbounded (design §4.2, review finding H4).
pub const MAX_OCCURRENCES: usize = 730;

auto_derived!(
    /// How often a recurring event repeats
    pub enum Frequency {
        Daily,
        Weekly,
        Monthly,
    }

    /// Day of week for weekly recurrence (Monday = 0 .. Sunday = 6)
    pub enum Weekday {
        Monday,
        Tuesday,
        Wednesday,
        Thursday,
        Friday,
        Saturday,
        Sunday,
    }

    /// When a recurring series stops — always bounded, never infinite
    #[serde(tag = "type")]
    pub enum RecurrenceEnd {
        /// After a fixed number of occurrences
        Count { count: u16 },
        /// On/after a specific instant (ms since Unix epoch, UTC)
        Until { timestamp: i64 },
    }

    /// Recurrence rule — a deliberately bounded subset of RFC-5545 (design §4.2)
    pub struct RecurrenceRule {
        /// Repeat frequency
        pub freq: Frequency,
        /// Repeat every N units of `freq` (1..=52)
        pub interval: u16,
        /// For weekly: which weekdays. Empty ⇒ the same weekday as `start`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub by_weekday: Vec<Weekday>,
        /// Series terminator (required)
        pub end: RecurrenceEnd,
        /// Occurrence-start instants (ms epoch) that are skipped (single-occurrence cancel).
        /// Cleared automatically on any time-affecting edit (`CalendarEvent::edit`, finding M1).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub exceptions: Vec<i64>,
    }

    /// Composite primary key for an RSVP: one row per (event, user)
    #[derive(Hash, Default)]
    pub struct EventRsvpKey {
        /// Event id
        pub event: String,
        /// User id
        pub user: String,
    }

    /// Response state of an invitee (design §7)
    pub enum RsvpStatus {
        /// Invited, no answer yet
        Pending,
        /// Accepted
        Going,
        /// Declined (never accepted) or withdrawn after accepting
        NotGoing,
    }

    /// A user's RSVP to an event
    pub struct EventRsvp {
        /// Composite (event, user) id
        #[serde(rename = "_id")]
        pub id: EventRsvpKey,
        /// Current response state
        pub status: RsvpStatus,
        /// Id of the user who issued the invite
        pub invited_by: String,
        /// True once this user was ever `Going`; never reset. Lets an organizer
        /// tell "declined" from "accepted then cancelled" (finding L1/§7).
        #[serde(default, skip_serializing_if = "crate::if_false")]
        pub had_accepted: bool,
        /// When the RSVP row was created
        pub created_at: i64,
        /// When the user last responded
        #[serde(skip_serializing_if = "Option::is_none")]
        pub responded_at: Option<i64>,
    }

    /// Fields on a calendar event that may be unset via update
    pub enum FieldsCalendarEvent {
        Channel,
        Description,
        Location,
        End,
        Recurrence,
        Color,
        SourceMessageId,
        EditedAt,
    }
);

auto_derived_partial!(
    /// A scheduled server calendar event (design §4.1)
    pub struct CalendarEvent {
        /// Unique event id (Ulid)
        #[serde(rename = "_id")]
        pub id: String,
        /// Owning server
        pub server: String,
        /// Optional associated channel (e.g. the voice channel to meet in).
        /// Also the permission anchor for who may view the event (design §6/§8).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub channel: Option<String>,
        /// User who created the event
        pub creator: String,
        /// Event title (1..=100)
        pub title: String,
        /// Optional description (0..=2000)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// Optional free-text location (0..=200)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub location: Option<String>,
        /// UTC instant (ms epoch) of the first/only occurrence
        pub start: i64,
        /// UTC instant (ms epoch) the first/only occurrence ends
        #[serde(skip_serializing_if = "Option::is_none")]
        pub end: Option<i64>,
        /// Duration of a single occurrence (ms); applied to every recurring occurrence.
        /// Derived — only ever recomputed via `create`/`edit`, never set directly.
        pub duration_ms: i64,
        /// Denormalised UTC upper bound (ms) of the whole series. Lets the window query
        /// find a recurring series whose first occurrence precedes the window (finding H4).
        /// Derived — only ever recomputed via `create`/`edit`.
        pub series_end: i64,
        /// Whether this is an all-day (date-only) event
        #[serde(default, skip_serializing_if = "crate::if_false")]
        pub all_day: bool,
        /// IANA timezone id anchoring recurrence wall-clock (e.g. "America/New_York")
        pub timezone: String,
        /// Optional recurrence rule
        #[serde(skip_serializing_if = "Option::is_none")]
        pub recurrence: Option<RecurrenceRule>,
        /// Optional display colour
        #[serde(skip_serializing_if = "Option::is_none")]
        pub color: Option<String>,
        /// Whether the whole series has been cancelled (terminal). Rows are retained
        /// so a cancel notification can still reach attendees (finding H6).
        #[serde(default, skip_serializing_if = "crate::if_false")]
        pub cancelled: bool,
        /// Source message id when imported from the legacy tag format (dedup key, finding M5)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub source_message_id: Option<String>,
        /// When the event was created
        pub created_at: i64,
        /// When the event was last edited
        #[serde(skip_serializing_if = "Option::is_none")]
        pub edited_at: Option<i64>,
    },
    "PartialCalendarEvent"
);

impl Weekday {
    /// Days from Monday (Monday = 0 .. Sunday = 6)
    pub fn num_from_monday(&self) -> i64 {
        match self {
            Weekday::Monday => 0,
            Weekday::Tuesday => 1,
            Weekday::Wednesday => 2,
            Weekday::Thursday => 3,
            Weekday::Friday => 4,
            Weekday::Saturday => 5,
            Weekday::Sunday => 6,
        }
    }
}

/// Convert a UTC millisecond instant to a chrono `DateTime<Utc>`.
fn ms_to_utc(ms: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(ms)
        .single()
        .unwrap_or_else(|| Utc.timestamp_millis_opt(0).single().unwrap())
}

/// Resolve a wall-clock local datetime to a UTC millisecond instant, applying the
/// DST edge policy (design §4.2, finding H2): a nonexistent (spring-forward gap)
/// time shifts forward; an ambiguous (fall-back) time takes the earliest instant.
/// Never panics on `LocalResult`.
fn local_to_utc_ms(tz: Tz, naive: NaiveDateTime) -> i64 {
    match tz.from_local_datetime(&naive) {
        LocalResult::Single(dt) => dt.timestamp_millis(),
        LocalResult::Ambiguous(earliest, _latest) => earliest.timestamp_millis(),
        LocalResult::None => {
            // Nonexistent wall-clock (spring-forward gap): interpret it with the
            // pre-transition UTC offset so the instant shifts FORWARD by exactly the gap
            // size (design §4.2, finding H2) — 02:30 -> 03:30 for a 1h gap, +30min for a
            // 30-min gap. Correct for sub-hour DST zones too, without a stepping heuristic.
            let before = naive - Duration::hours(3);
            let offset = match tz.from_local_datetime(&before) {
                LocalResult::Single(dt) => dt.offset().fix(),
                LocalResult::Ambiguous(dt, _) => dt.offset().fix(),
                LocalResult::None => return Utc.from_utc_datetime(&naive).timestamp_millis(),
            };
            offset
                .from_local_datetime(&naive)
                .single()
                .map(|dt| dt.timestamp_millis())
                .unwrap_or_else(|| Utc.from_utc_datetime(&naive).timestamp_millis())
        }
    }
}

/// Last calendar day (28..=31) of a given year/month.
fn last_day_of_month(year: i32, month: u32) -> u32 {
    let (ny, nm) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
    NaiveDate::from_ymd_opt(ny, nm, 1)
        .and_then(|d| d.pred_opt())
        .map(|d| d.day())
        .unwrap_or(28)
}

/// Add `add` months to a (year, month0) pair, wrapping years correctly.
fn add_months(year: i32, month0: i64, add: i64) -> (i32, u32) {
    let total = month0 + add;
    let y = year + total.div_euclid(12) as i32;
    let m0 = total.rem_euclid(12) as u32;
    (y, m0 + 1)
}

/// Push one occurrence, honouring an `Until` terminator. Returns false to stop the series.
fn append_occurrence(out: &mut Vec<i64>, tz: Tz, until_ms: Option<i64>, local: NaiveDateTime) -> bool {
    let ms = local_to_utc_ms(tz, local);
    if let Some(until) = until_ms {
        if ms > until {
            return false;
        }
    }
    out.push(ms);
    true
}

/// Compute every occurrence start (UTC ms) of a series, in chronological order.
/// Always bounded by the rule's `Count`/`Until` and by `MAX_OCCURRENCES`, and uses
/// checked date arithmetic so a hostile interval cannot panic on datetime overflow.
/// A non-recurring event yields a single occurrence at its `start`.
pub fn series_occurrence_starts(event: &CalendarEvent) -> Vec<i64> {
    let Some(rule) = event.recurrence.as_ref() else {
        return vec![event.start];
    };

    let tz: Tz = event.timezone.parse().unwrap_or(chrono_tz::UTC);
    let start_local = ms_to_utc(event.start).with_timezone(&tz).naive_local();
    let interval = (rule.interval.max(1)) as i64;

    let count_cap = match &rule.end {
        RecurrenceEnd::Count { count } => (*count as usize).min(MAX_OCCURRENCES),
        RecurrenceEnd::Until { .. } => MAX_OCCURRENCES,
    };
    let until_ms = match &rule.end {
        RecurrenceEnd::Until { timestamp } => Some(*timestamp),
        RecurrenceEnd::Count { .. } => None,
    };

    let mut out: Vec<i64> = Vec::new();

    match rule.freq {
        Frequency::Daily => {
            let mut n: i64 = 0;
            while out.len() < count_cap {
                let Some(local) = start_local.checked_add_signed(Duration::days(interval * n)) else {
                    break;
                };
                if !append_occurrence(&mut out, tz, until_ms, local) {
                    break;
                }
                n += 1;
            }
        }
        Frequency::Weekly if rule.by_weekday.is_empty() => {
            let mut n: i64 = 0;
            while out.len() < count_cap {
                let Some(local) = start_local.checked_add_signed(Duration::weeks(interval * n)) else {
                    break;
                };
                if !append_occurrence(&mut out, tz, until_ms, local) {
                    break;
                }
                n += 1;
            }
        }
        Frequency::Weekly => {
            let mut weekdays: Vec<i64> = rule.by_weekday.iter().map(|w| w.num_from_monday()).collect();
            weekdays.sort_unstable();
            weekdays.dedup();

            // Monday of the anchor week, at the event's local time-of-day.
            let anchor_offset = start_local.weekday().num_days_from_monday() as i64;
            let week_monday = (start_local.date() - Duration::days(anchor_offset)).and_time(start_local.time());

            let mut block: i64 = 0;
            'outer: while out.len() < count_cap && (block as usize) <= MAX_OCCURRENCES {
                let Some(block_monday) = week_monday.checked_add_signed(Duration::weeks(interval * block)) else {
                    break;
                };
                for &wd in &weekdays {
                    let Some(cand) = block_monday.checked_add_signed(Duration::days(wd)) else {
                        continue;
                    };
                    if cand < start_local {
                        continue; // skip weekdays before the anchor in the first block
                    }
                    if out.len() >= count_cap {
                        break 'outer;
                    }
                    if !append_occurrence(&mut out, tz, until_ms, cand) {
                        break 'outer;
                    }
                }
                block += 1;
            }
        }
        Frequency::Monthly => {
            let base_day = start_local.day();
            let base_time = start_local.time();
            let mut n: i64 = 0;
            while out.len() < count_cap && (n as usize) <= MAX_OCCURRENCES {
                let (y, month) = add_months(start_local.year(), start_local.month0() as i64, interval * n);
                let day = base_day.min(last_day_of_month(y, month));
                let Some(date) = NaiveDate::from_ymd_opt(y, month, day) else {
                    break;
                };
                let local = date.and_time(base_time);
                if !append_occurrence(&mut out, tz, until_ms, local) {
                    break;
                }
                n += 1;
            }
        }
    }

    out
}

/// Occurrence starts (UTC ms) that overlap the window `[from, to]`, with
/// `exceptions` removed. Occurrences before the window still count toward a
/// `Count` terminator but are not returned.
pub fn occurrences_in_window(event: &CalendarEvent, from: i64, to: i64) -> Vec<i64> {
    let duration = event.duration_ms.max(0);
    let exceptions = event
        .recurrence
        .as_ref()
        .map(|r| r.exceptions.clone())
        .unwrap_or_default();

    series_occurrence_starts(event)
        .into_iter()
        .filter(|s| !exceptions.contains(s))
        .filter(|s| {
            let occ_end = s.saturating_add(duration);
            *s <= to && occ_end >= from
        })
        .collect()
}

/// Current time in milliseconds since the Unix epoch.
#[allow(clippy::disallowed_methods)]
fn now_ms() -> i64 {
    use iso8601_timestamp::Timestamp;
    Timestamp::now_utc()
        .duration_since(Timestamp::UNIX_EPOCH)
        .whole_milliseconds() as i64
}

impl CalendarEvent {
    /// Recompute the derived duration from the current `start`/`end`.
    fn recompute_duration(&mut self) {
        self.duration_ms = self.end.map(|e| (e - self.start).max(0)).unwrap_or(0);
    }

    /// Compute the denormalised `series_end` (UTC ms) for this event.
    pub fn compute_series_end(&self) -> i64 {
        let duration = self.duration_ms.max(0);
        match &self.recurrence {
            None => self.end.unwrap_or(self.start),
            Some(_) => {
                let starts = series_occurrence_starts(self);
                let last = starts.last().copied().unwrap_or(self.start);
                last.saturating_add(duration)
            }
        }
    }

    /// Validate invariants the data layer must always uphold. This is a minimal
    /// invariant guard, not the length/format validator — route-level validation
    /// via `validator` is added in slice B and must not lean on this being complete.
    pub fn validate(&self) -> Result<()> {
        let title = self.title.trim();
        if title.is_empty() || self.title.chars().count() > 100 {
            return Err(create_error!(FailedValidation {
                error: "title".to_string()
            }));
        }
        if self.timezone.parse::<Tz>().is_err() {
            return Err(create_error!(FailedValidation {
                error: "timezone".to_string()
            }));
        }
        if let Some(d) = &self.description {
            if d.chars().count() > 2000 {
                return Err(create_error!(FailedValidation {
                    error: "description".to_string()
                }));
            }
        }
        if let Some(l) = &self.location {
            if l.chars().count() > 200 {
                return Err(create_error!(FailedValidation {
                    error: "location".to_string()
                }));
            }
        }
        if let Some(c) = &self.color {
            if c.chars().count() > 32 {
                return Err(create_error!(FailedValidation {
                    error: "color".to_string()
                }));
            }
        }
        if let Some(end) = self.end {
            if end <= self.start {
                return Err(create_error!(FailedValidation {
                    error: "end".to_string()
                }));
            }
        }
        if let Some(rule) = &self.recurrence {
            if !(1..=52).contains(&rule.interval) {
                return Err(create_error!(FailedValidation {
                    error: "interval".to_string()
                }));
            }
            // by_weekday only makes sense for a weekly rule, and (when present) must
            // include the anchor's weekday or the series would silently drop `start`.
            if !rule.by_weekday.is_empty() {
                if !matches!(rule.freq, Frequency::Weekly) {
                    return Err(create_error!(FailedValidation {
                        error: "by_weekday".to_string()
                    }));
                }
                let tz: Tz = self.timezone.parse().unwrap_or(chrono_tz::UTC);
                let start_wd =
                    ms_to_utc(self.start).with_timezone(&tz).weekday().num_days_from_monday() as i64;
                if !rule.by_weekday.iter().any(|w| w.num_from_monday() == start_wd) {
                    return Err(create_error!(FailedValidation {
                        error: "by_weekday_anchor".to_string()
                    }));
                }
            }
            match &rule.end {
                RecurrenceEnd::Count { count } => {
                    if *count < 1 || *count as usize > MAX_OCCURRENCES {
                        return Err(create_error!(FailedValidation {
                            error: "count".to_string()
                        }));
                    }
                }
                RecurrenceEnd::Until { timestamp } => {
                    if *timestamp < self.start {
                        return Err(create_error!(FailedValidation {
                            error: "until".to_string()
                        }));
                    }
                    // Reject an `Until` whose implied occurrence count would blow past the
                    // cap — otherwise the series would be silently truncated and `series_end`
                    // would fall short, dropping the event from the calendar early (finding).
                    if series_occurrence_starts(self).len() >= MAX_OCCURRENCES {
                        return Err(create_error!(FailedValidation {
                            error: "until_range".to_string()
                        }));
                    }
                }
            }
        }
        Ok(())
    }

    /// Create and persist a new calendar event. Validates first, then fills
    /// id/timestamps and the derived `duration_ms`/`series_end`.
    /// (Real-time fan-out is added in slice C; permission checks live at the route in slice B.)
    #[allow(clippy::disallowed_methods)]
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: &Database,
        server: String,
        creator: String,
        title: String,
        description: Option<String>,
        location: Option<String>,
        start: i64,
        end: Option<i64>,
        all_day: bool,
        timezone: String,
        recurrence: Option<RecurrenceRule>,
        color: Option<String>,
        channel: Option<String>,
    ) -> Result<CalendarEvent> {
        let mut event = CalendarEvent {
            id: Ulid::new().to_string(),
            server,
            channel,
            creator,
            title,
            description,
            location,
            start,
            end,
            duration_ms: 0,
            series_end: start,
            all_day,
            timezone,
            recurrence,
            color,
            cancelled: false,
            source_message_id: None,
            created_at: now_ms(),
            edited_at: None,
        };
        event.recompute_duration();
        // Validate BEFORE running the recurrence engine so bad input is rejected
        // with FailedValidation rather than reaching the date math.
        event.validate()?;
        event.series_end = event.compute_series_end();

        db.insert_event(&event).await?;
        Ok(event)
    }

    /// The single sanctioned edit path. Applies a partial + field removals, then
    /// recomputes the derived `duration_ms`/`series_end` and — on any time-affecting
    /// change — clears `exceptions` (findings H4/M1), validates, and persists via a
    /// whole-document replace. Slice B's PATCH route MUST go through this rather than
    /// the raw `update_event`, which does not recompute derived fields.
    #[allow(clippy::disallowed_methods)]
    pub async fn edit(
        &mut self,
        db: &Database,
        partial: PartialCalendarEvent,
        remove: Vec<FieldsCalendarEvent>,
    ) -> Result<()> {
        let time_affecting = partial.start.is_some()
            || partial.end.is_some()
            || partial.timezone.is_some()
            || partial.recurrence.is_some()
            || remove
                .iter()
                .any(|f| matches!(f, FieldsCalendarEvent::End | FieldsCalendarEvent::Recurrence));

        for field in &remove {
            self.remove_field(field);
        }
        self.apply_options(partial);

        self.recompute_duration();
        if time_affecting {
            if let Some(rule) = self.recurrence.as_mut() {
                rule.exceptions.clear();
            }
        }
        self.series_end = self.compute_series_end();
        self.edited_at = Some(now_ms());

        self.validate()?;
        db.replace_event(self).await
    }

    /// Unset an optional field in place (used by the edit + Reference update paths).
    pub fn remove_field(&mut self, field: &FieldsCalendarEvent) {
        match field {
            FieldsCalendarEvent::Channel => self.channel = None,
            FieldsCalendarEvent::Description => self.description = None,
            FieldsCalendarEvent::Location => self.location = None,
            FieldsCalendarEvent::End => self.end = None,
            FieldsCalendarEvent::Recurrence => self.recurrence = None,
            FieldsCalendarEvent::Color => self.color = None,
            FieldsCalendarEvent::SourceMessageId => self.source_message_id = None,
            FieldsCalendarEvent::EditedAt => self.edited_at = None,
        }
    }
}

impl EventRsvp {
    /// Build a fresh `Pending` invite row.
    #[allow(clippy::disallowed_methods)]
    pub fn new_invite(event_id: &str, user_id: &str, invited_by: &str) -> EventRsvp {
        EventRsvp {
            id: EventRsvpKey {
                event: event_id.to_string(),
                user: user_id.to_string(),
            },
            status: RsvpStatus::Pending,
            invited_by: invited_by.to_string(),
            had_accepted: false,
            created_at: now_ms(),
            responded_at: None,
        }
    }

    /// Invite a user to an event, inserting a `Pending` row only if none exists
    /// (insert-if-absent — re-inviting never resets an existing answer, finding H5).
    /// Returns true when a new invite row was created.
    pub async fn invite(
        db: &Database,
        event_id: &str,
        user_id: &str,
        invited_by: &str,
    ) -> Result<bool> {
        let rsvp = EventRsvp::new_invite(event_id, user_id, invited_by);
        db.insert_rsvp_if_absent(&rsvp).await
    }

    /// Apply an RSVP response, enforcing the state machine (design §7, findings L1/H5).
    /// `Pending` is not a client-settable target; accepting sets (and never resets)
    /// `had_accepted`. Pure — the caller persists + fans out.
    pub fn apply_response(&mut self, target: RsvpStatus) -> Result<()> {
        match target {
            RsvpStatus::Pending => {
                return Err(create_error!(InvalidOperation));
            }
            RsvpStatus::Going => {
                self.status = RsvpStatus::Going;
                self.had_accepted = true;
            }
            RsvpStatus::NotGoing => {
                self.status = RsvpStatus::NotGoing;
            }
        }
        self.responded_at = Some(now_ms());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Datelike, TimeZone, Timelike};
    use chrono_tz::America::New_York;
    use chrono_tz::Tz;

    use super::*;

    /// Build an event anchored at a given local wall-clock time in `tz`.
    fn event_at_local(
        tz: Tz,
        y: i32,
        mo: u32,
        d: u32,
        h: u32,
        mi: u32,
        recurrence: Option<RecurrenceRule>,
    ) -> CalendarEvent {
        let start_ms = tz
            .with_ymd_and_hms(y, mo, d, h, mi, 0)
            .single()
            .unwrap()
            .timestamp_millis();
        let mut event = CalendarEvent {
            id: "01EVENT".to_string(),
            server: "01SERVER".to_string(),
            channel: None,
            creator: "01USER".to_string(),
            title: "Standup".to_string(),
            description: None,
            location: None,
            start: start_ms,
            end: Some(start_ms + 30 * 60 * 1000),
            duration_ms: 30 * 60 * 1000,
            series_end: start_ms,
            all_day: false,
            timezone: tz.name().to_string(),
            recurrence,
            color: None,
            cancelled: false,
            source_message_id: None,
            created_at: 0,
            edited_at: None,
        };
        event.series_end = event.compute_series_end();
        event
    }

    fn day_ms(days: i64) -> i64 {
        days * 24 * 60 * 60 * 1000
    }

    #[test]
    fn daily_count_spacing() {
        let rule = RecurrenceRule {
            freq: Frequency::Daily,
            interval: 1,
            by_weekday: vec![],
            end: RecurrenceEnd::Count { count: 5 },
            exceptions: vec![],
        };
        let event = event_at_local(chrono_tz::UTC, 2026, 6, 1, 9, 0, Some(rule));
        let starts = series_occurrence_starts(&event);
        assert_eq!(starts.len(), 5);
        for w in starts.windows(2) {
            assert_eq!(w[1] - w[0], day_ms(1));
        }
    }

    #[test]
    fn weekly_by_weekday_until() {
        // Mon+Wed+Fri, every week, until 15 days out; anchor (Jun 1 2026) is a Monday.
        let start = chrono_tz::UTC.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).single().unwrap();
        let until = start.timestamp_millis() + day_ms(15);
        let rule = RecurrenceRule {
            freq: Frequency::Weekly,
            interval: 1,
            by_weekday: vec![Weekday::Monday, Weekday::Wednesday, Weekday::Friday],
            end: RecurrenceEnd::Until { timestamp: until },
            exceptions: vec![],
        };
        let event = event_at_local(chrono_tz::UTC, 2026, 6, 1, 12, 0, Some(rule));
        let starts = series_occurrence_starts(&event);
        // Mon 1, Wed 3, Fri 5, Mon 8, Wed 10, Fri 12, Mon 15 (<= until), then Wed 17 > until.
        assert_eq!(starts.len(), 7);
        assert!(starts.iter().all(|s| *s <= until));
    }

    #[test]
    fn monthly_clamps_to_last_day() {
        // Jan 31 monthly must clamp to Feb 28 (2026 not a leap year) then Mar 31.
        let rule = RecurrenceRule {
            freq: Frequency::Monthly,
            interval: 1,
            by_weekday: vec![],
            end: RecurrenceEnd::Count { count: 3 },
            exceptions: vec![],
        };
        let event = event_at_local(chrono_tz::UTC, 2026, 1, 31, 10, 0, Some(rule));
        let starts = series_occurrence_starts(&event);
        assert_eq!(starts.len(), 3);
        let days: Vec<u32> = starts.iter().map(|ms| ms_to_utc(*ms).day()).collect();
        assert_eq!(days, vec![31, 28, 31]);
    }

    #[test]
    fn dst_gap_shifts_forward() {
        // 02:30 America/New_York on 2025-03-09 does not exist (spring forward 02:00->03:00).
        let rule = RecurrenceRule {
            freq: Frequency::Daily,
            interval: 1,
            by_weekday: vec![],
            end: RecurrenceEnd::Count { count: 4 },
            exceptions: vec![],
        };
        let event = event_at_local(New_York, 2025, 3, 7, 2, 30, Some(rule));
        let starts = series_occurrence_starts(&event);
        assert_eq!(starts.len(), 4);
        for w in starts.windows(2) {
            assert!(w[1] > w[0]);
        }
        let gap_local = ms_to_utc(starts[2]).with_timezone(&New_York);
        assert_eq!(gap_local.hour(), 3);
        assert_eq!(gap_local.minute(), 30);
    }

    #[test]
    fn weekly_preserves_wall_clock_across_dst() {
        let rule = RecurrenceRule {
            freq: Frequency::Weekly,
            interval: 1,
            by_weekday: vec![],
            end: RecurrenceEnd::Count { count: 3 },
            exceptions: vec![],
        };
        let event = event_at_local(New_York, 2025, 3, 5, 18, 0, Some(rule));
        let starts = series_occurrence_starts(&event);
        assert_eq!(starts.len(), 3);
        for s in &starts {
            let local = ms_to_utc(*s).with_timezone(&New_York);
            assert_eq!(local.hour(), 18, "wall-clock hour drifted across DST");
        }
        assert_ne!(starts[1] - starts[0], starts[2] - starts[1]);
    }

    #[test]
    fn window_returns_series_anchored_before_window() {
        // Finding H4: a weekly series whose first occurrence is before the window
        // must still yield its in-window occurrences.
        let rule = RecurrenceRule {
            freq: Frequency::Weekly,
            interval: 1,
            by_weekday: vec![],
            end: RecurrenceEnd::Count { count: 20 },
            exceptions: vec![],
        };
        let event = event_at_local(chrono_tz::UTC, 2026, 1, 5, 12, 0, Some(rule));
        let from = chrono_tz::UTC.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).single().unwrap().timestamp_millis();
        let to = from + day_ms(7);
        let occ = occurrences_in_window(&event, from, to);
        assert_eq!(occ.len(), 1);
        assert!(occ[0] >= from && occ[0] <= to);
        assert!(event.series_end >= from);
    }

    #[test]
    fn exceptions_are_skipped() {
        let rule = RecurrenceRule {
            freq: Frequency::Daily,
            interval: 1,
            by_weekday: vec![],
            end: RecurrenceEnd::Count { count: 5 },
            exceptions: vec![],
        };
        let mut event = event_at_local(chrono_tz::UTC, 2026, 6, 1, 9, 0, Some(rule));
        let all = series_occurrence_starts(&event);
        if let Some(r) = event.recurrence.as_mut() {
            r.exceptions = vec![all[2]];
        }
        let occ = occurrences_in_window(&event, all[0], all[4]);
        assert_eq!(occ.len(), 4);
        assert!(!occ.contains(&all[2]));
    }

    #[test]
    fn rsvp_state_machine() {
        let mut rsvp = EventRsvp::new_invite("01EVENT", "01USER", "01HOST");
        assert_eq!(rsvp.status, RsvpStatus::Pending);
        assert!(!rsvp.had_accepted);

        assert!(rsvp.apply_response(RsvpStatus::Pending).is_err()); // L1

        rsvp.apply_response(RsvpStatus::Going).unwrap();
        assert_eq!(rsvp.status, RsvpStatus::Going);
        assert!(rsvp.had_accepted);
        assert!(rsvp.responded_at.is_some());

        rsvp.apply_response(RsvpStatus::NotGoing).unwrap();
        assert_eq!(rsvp.status, RsvpStatus::NotGoing);
        assert!(rsvp.had_accepted); // stays true after cancel-after-accept
    }

    #[test]
    fn validate_rejects_bad_input() {
        let mut event = event_at_local(chrono_tz::UTC, 2026, 6, 1, 9, 0, None);
        assert!(event.validate().is_ok());

        event.timezone = "Not/AZone".to_string();
        assert!(event.validate().is_err());
        event.timezone = "UTC".to_string();

        event.end = Some(event.start - 1);
        assert!(event.validate().is_err());
        event.end = Some(event.start + 1000);

        // Until implying more than MAX_OCCURRENCES is rejected (silent-truncation guard).
        event.recurrence = Some(RecurrenceRule {
            freq: Frequency::Daily,
            interval: 1,
            by_weekday: vec![],
            end: RecurrenceEnd::Until {
                timestamp: event.start + day_ms(5000),
            },
            exceptions: vec![],
        });
        assert!(event.validate().is_err());

        // by_weekday on a non-weekly rule is rejected.
        event.recurrence = Some(RecurrenceRule {
            freq: Frequency::Daily,
            interval: 1,
            by_weekday: vec![Weekday::Monday],
            end: RecurrenceEnd::Count { count: 3 },
            exceptions: vec![],
        });
        assert!(event.validate().is_err());
    }

    #[tokio::test]
    async fn driver_round_trip() {
        database_test!(|db| async move {
            let event = CalendarEvent::create(
                &db,
                "01SERVER".to_string(),
                "01HOST".to_string(),
                "Launch".to_string(),
                None,
                None,
                1_900_000_000_000,
                Some(1_900_003_600_000),
                false,
                "UTC".to_string(),
                None,
                None,
                None,
            )
            .await
            .unwrap();

            let fetched = db.fetch_event(&event.id).await.unwrap();
            assert_eq!(fetched.title, "Launch");
            assert_eq!(fetched.series_end, 1_900_003_600_000);

            let in_window = db
                .fetch_events_for_server_in_window("01SERVER", 1_899_000_000_000, 1_901_000_000_000)
                .await
                .unwrap();
            assert_eq!(in_window.len(), 1);

            // Invite is insert-if-absent (finding H5): second invite is a no-op.
            assert!(EventRsvp::invite(&db, &event.id, "01GUEST", "01HOST").await.unwrap());
            assert!(!EventRsvp::invite(&db, &event.id, "01GUEST", "01HOST").await.unwrap());

            let mut rsvp = db.fetch_rsvp(&event.id, "01GUEST").await.unwrap();
            rsvp.apply_response(RsvpStatus::Going).unwrap();
            db.update_rsvp(&rsvp).await.unwrap();
            let after = db.fetch_rsvp(&event.id, "01GUEST").await.unwrap();
            assert_eq!(after.status, RsvpStatus::Going);
            assert!(after.had_accepted);
            // update_rsvp must not have mutated the immutable invite metadata.
            assert_eq!(after.invited_by, "01HOST");
            assert_eq!(after.created_at, rsvp.created_at);

            let all = db.fetch_rsvps_for_event(&event.id).await.unwrap();
            assert_eq!(all.len(), 1);

            db.delete_rsvps_for_event(&event.id).await.unwrap();
            assert!(db.fetch_rsvps_for_event(&event.id).await.unwrap().is_empty());

            db.delete_event(&event.id).await.unwrap();
            assert!(db.fetch_event(&event.id).await.is_err());
        });
    }

    #[tokio::test]
    async fn edit_recomputes_derived_fields_and_clears_exceptions() {
        database_test!(|db| async move {
            let rule = RecurrenceRule {
                freq: Frequency::Weekly,
                interval: 1,
                by_weekday: vec![],
                end: RecurrenceEnd::Count { count: 4 },
                exceptions: vec![],
            };
            let start = 1_900_000_000_000;
            let mut event = CalendarEvent::create(
                &db,
                "01S".to_string(),
                "01H".to_string(),
                "Sync".to_string(),
                None,
                None,
                start,
                Some(start + 3_600_000),
                false,
                "UTC".to_string(),
                Some(rule),
                None,
                None,
            )
            .await
            .unwrap();
            let original_series_end = event.series_end;

            // Pretend an occurrence was previously cancelled.
            if let Some(r) = event.recurrence.as_mut() {
                r.exceptions = vec![start];
            }

            // Move the whole series two weeks later — a time-affecting edit.
            let new_start = start + day_ms(14);
            let partial = PartialCalendarEvent {
                start: Some(new_start),
                end: Some(new_start + 3_600_000),
                ..Default::default()
            };
            event.edit(&db, partial, vec![]).await.unwrap();

            assert_eq!(event.start, new_start);
            assert!(event.series_end > original_series_end, "series_end must move with start (H4)");
            assert!(
                event.recurrence.as_ref().unwrap().exceptions.is_empty(),
                "exceptions cleared on time-affecting edit (M1)"
            );
            assert!(event.edited_at.is_some());

            let refetched = db.fetch_event(&event.id).await.unwrap();
            assert_eq!(refetched.start, new_start);
            assert_eq!(refetched.series_end, event.series_end);
            assert!(refetched.recurrence.as_ref().unwrap().exceptions.is_empty());
        });
    }

    #[tokio::test]
    async fn delete_missing_is_not_found() {
        database_test!(|db| async move {
            assert!(db.delete_event("does-not-exist").await.is_err());
            assert!(db.delete_rsvp("nope", "nobody").await.is_err());
            assert!(db.fetch_rsvp("nope", "nobody").await.is_err());
        });
    }
}
