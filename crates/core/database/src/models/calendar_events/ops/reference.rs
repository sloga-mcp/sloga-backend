use revolt_result::Result;

use crate::ReferenceDb;
use crate::{
    CalendarEvent, EventRsvp, EventRsvpKey, FieldsCalendarEvent, PartialCalendarEvent, ReminderSent,
    ReminderSentKey,
};

use super::AbstractCalendarEvents;

#[async_trait]
impl AbstractCalendarEvents for ReferenceDb {
    async fn insert_event(&self, event: &CalendarEvent) -> Result<()> {
        let mut events = self.calendar_events.lock().await;
        if events.contains_key(&event.id) {
            Err(create_database_error!("insert", "calendar_event"))
        } else {
            events.insert(event.id.clone(), event.clone());
            Ok(())
        }
    }

    async fn fetch_event(&self, id: &str) -> Result<CalendarEvent> {
        let events = self.calendar_events.lock().await;
        events
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_events_for_server_in_window(
        &self,
        server_id: &str,
        from: i64,
        to: i64,
    ) -> Result<Vec<CalendarEvent>> {
        let events = self.calendar_events.lock().await;
        Ok(events
            .values()
            .filter(|e| {
                e.server == server_id && !e.cancelled && e.start <= to && e.series_end >= from
            })
            .cloned()
            .collect())
    }

    async fn update_event(
        &self,
        id: &str,
        partial: &PartialCalendarEvent,
        remove: Vec<FieldsCalendarEvent>,
    ) -> Result<()> {
        let mut events = self.calendar_events.lock().await;
        if let Some(event) = events.get_mut(id) {
            for field in remove {
                event.remove_field(&field);
            }
            event.apply_options(partial.clone());
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn replace_event(&self, event: &CalendarEvent) -> Result<()> {
        let mut events = self.calendar_events.lock().await;
        if events.contains_key(&event.id) {
            events.insert(event.id.clone(), event.clone());
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn delete_event(&self, id: &str) -> Result<()> {
        let mut events = self.calendar_events.lock().await;
        if events.remove(id).is_some() {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn insert_rsvp_if_absent(&self, rsvp: &EventRsvp) -> Result<bool> {
        let mut rsvps = self.event_rsvps.lock().await;
        if rsvps.contains_key(&rsvp.id) {
            Ok(false)
        } else {
            rsvps.insert(rsvp.id.clone(), rsvp.clone());
            Ok(true)
        }
    }

    async fn fetch_rsvp(&self, event_id: &str, user_id: &str) -> Result<EventRsvp> {
        let rsvps = self.event_rsvps.lock().await;
        rsvps
            .get(&EventRsvpKey {
                event: event_id.to_string(),
                user: user_id.to_string(),
            })
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_rsvps_for_event(&self, event_id: &str) -> Result<Vec<EventRsvp>> {
        let rsvps = self.event_rsvps.lock().await;
        Ok(rsvps
            .values()
            .filter(|r| r.id.event == event_id)
            .cloned()
            .collect())
    }

    async fn update_rsvp(&self, rsvp: &EventRsvp) -> Result<()> {
        let mut rsvps = self.event_rsvps.lock().await;
        if let Some(existing) = rsvps.get_mut(&rsvp.id) {
            // Overwrite only the mutable fields, matching the Mongo `$set` (never the
            // composite `_id` or the immutable invite metadata).
            existing.status = rsvp.status.clone();
            existing.had_accepted = rsvp.had_accepted;
            existing.responded_at = rsvp.responded_at;
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn delete_rsvp(&self, event_id: &str, user_id: &str) -> Result<()> {
        let mut rsvps = self.event_rsvps.lock().await;
        if rsvps
            .remove(&EventRsvpKey {
                event: event_id.to_string(),
                user: user_id.to_string(),
            })
            .is_some()
        {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn delete_rsvps_for_event(&self, event_id: &str) -> Result<()> {
        let mut rsvps = self.event_rsvps.lock().await;
        rsvps.retain(|k, _| k.event != event_id);
        Ok(())
    }

    async fn fetch_events_in_reminder_window(
        &self,
        start_max: i64,
        series_end_min: i64,
    ) -> Result<Vec<CalendarEvent>> {
        let events = self.calendar_events.lock().await;
        Ok(events
            .values()
            .filter(|e| !e.cancelled && e.start <= start_max && e.series_end >= series_end_min)
            .cloned()
            .collect())
    }

    async fn mark_reminder_sent_if_absent(&self, key: &ReminderSentKey) -> Result<bool> {
        let mut reminders = self.event_reminders.lock().await;
        if reminders.contains_key(key) {
            Ok(false)
        } else {
            reminders.insert(
                key.clone(),
                ReminderSent {
                    id: key.clone(),
                    sent_at: super::super::model::now_ms(),
                },
            );
            Ok(true)
        }
    }

    async fn delete_reminders_sent_before(&self, occurrence_before: i64) -> Result<usize> {
        let mut reminders = self.event_reminders.lock().await;
        let before = reminders.len();
        reminders.retain(|k, _| k.occurrence >= occurrence_before);
        Ok(before - reminders.len())
    }
}
