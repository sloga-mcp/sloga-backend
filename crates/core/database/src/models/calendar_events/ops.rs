use revolt_result::Result;

use crate::{CalendarEvent, EventRsvp, FieldsCalendarEvent, PartialCalendarEvent};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractCalendarEvents: Sync + Send {
    /// Insert a new calendar event
    async fn insert_event(&self, event: &CalendarEvent) -> Result<()>;

    /// Fetch a calendar event by its id
    async fn fetch_event(&self, id: &str) -> Result<CalendarEvent>;

    /// Fetch non-cancelled events in a server whose series overlaps the window `[from, to]`.
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
}
