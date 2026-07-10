use std::collections::HashSet;

use revolt_result::Result;

use crate::{
    CalendarEvent, EventRsvp, FieldsCalendarEvent, PartialCalendarEvent, ReminderSentKey,
};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractCalendarEvents: Sync + Send {
    /// Insert a new calendar event
    async fn insert_event(&self, event: &CalendarEvent) -> Result<()>;

    /// Fetch a calendar event by its id
    async fn fetch_event(&self, id: &str) -> Result<CalendarEvent>;

    /// Fetch events in a server whose series overlaps the window `[from, to]`, INCLUDING
    /// cancelled series (rendered struck-through by clients — slice F decision 0.2-A; the
    /// reminder scan uses the separate `fetch_events_in_reminder_window`, which excludes them).
    /// Returns candidate series (recurrence is expanded by the caller); the query is bounded
    /// by `series_end >= from AND start <= to` so a series anchored before the window is found.
    async fn fetch_events_for_server_in_window(
        &self,
        server_id: &str,
        from: i64,
        to: i64,
    ) -> Result<Vec<CalendarEvent>>;

    /// Update an event with a partial and a list of fields to unset.
    /// NOTE: does NOT recompute derived fields — only for non-time edits. Time/recurrence
    /// changes must go through `CalendarEvent::edit` (which uses `replace_event`).
    async fn update_event(
        &self,
        id: &str,
        partial: &PartialCalendarEvent,
        remove: Vec<FieldsCalendarEvent>,
    ) -> Result<()>;

    /// Replace an existing event document wholesale (used by the sanctioned edit path,
    /// which has already recomputed the derived fields). Errors with `NotFound` if absent.
    async fn replace_event(&self, event: &CalendarEvent) -> Result<()>;

    /// Delete an event by its id
    async fn delete_event(&self, id: &str) -> Result<()>;

    /// Insert an RSVP row only if none exists for (event, user). Returns true if inserted.
    async fn insert_rsvp_if_absent(&self, rsvp: &EventRsvp) -> Result<bool>;

    /// Fetch a single RSVP by (event, user)
    async fn fetch_rsvp(&self, event_id: &str, user_id: &str) -> Result<EventRsvp>;

    /// Fetch all RSVP rows for an event
    async fn fetch_rsvps_for_event(&self, event_id: &str) -> Result<Vec<EventRsvp>>;

    /// Overwrite the mutable fields of an existing RSVP row
    async fn update_rsvp(&self, rsvp: &EventRsvp) -> Result<()>;

    /// Delete a single RSVP by (event, user)
    async fn delete_rsvp(&self, event_id: &str, user_id: &str) -> Result<()>;

    /// Delete every RSVP row for an event (cascade on event delete)
    async fn delete_rsvps_for_event(&self, event_id: &str) -> Result<()>;

    /// Delete every RSVP row a user holds on events of one server (cascade on member
    /// removal — leave/kick/ban all route through `Member::remove`). Zero matches is Ok.
    async fn delete_rsvps_for_member(&self, server_id: &str, user_id: &str) -> Result<()>;

    /// Delete every RSVP row a user holds anywhere (cascade on account deletion —
    /// `User::delete` bypasses `Member::remove`). Zero matches is Ok.
    async fn delete_rsvps_for_user(&self, user_id: &str) -> Result<()>;

    /// Delete all calendar state owned by a server: events, their RSVP rows and their
    /// reminder markers (cascade on server deletion — without this, dead series keep
    /// matching crond's cross-server reminder scan until their `series_end`).
    async fn delete_calendar_for_server(&self, server_id: &str) -> Result<()>;

    /// The `source_message_id`s of every event already imported into a server from the
    /// legacy tag format — the import's dedup set (design §11, finding M5).
    async fn fetch_imported_source_ids(&self, server_id: &str) -> Result<HashSet<String>>;

    /// Fetch non-cancelled events across all servers that the reminder scan must
    /// consider: `start <= start_max AND series_end >= series_end_min`. The caller
    /// (crond) expands occurrences and filters precisely (design §9).
    async fn fetch_events_in_reminder_window(
        &self,
        start_max: i64,
        series_end_min: i64,
    ) -> Result<Vec<CalendarEvent>>;

    /// Record that a reminder was sent for `(event, user, occurrence, offset)` only if
    /// no marker exists yet. Returns true when newly marked — the caller sends the push
    /// exactly then (mark-then-send idempotency, design §9, finding H3).
    async fn mark_reminder_sent_if_absent(&self, key: &ReminderSentKey) -> Result<bool>;

    /// Delete reminder markers for occurrences strictly before `occurrence_before`
    /// (retention sweep). Returns the number removed.
    async fn delete_reminders_sent_before(&self, occurrence_before: i64) -> Result<usize>;
}
