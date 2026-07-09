use bson::{to_document, Document};
use futures::StreamExt;
use revolt_result::Result;

use crate::MongoDb;
use crate::{
    CalendarEvent, EventRsvp, FieldsCalendarEvent, IntoDocumentPath, PartialCalendarEvent,
    ReminderSent, ReminderSentKey,
};

use super::AbstractCalendarEvents;

static COL_EVENTS: &str = "calendar_events";
static COL_RSVPS: &str = "event_rsvps";
static COL_REMINDERS: &str = "event_reminders_sent";

#[async_trait]
impl AbstractCalendarEvents for MongoDb {
    async fn insert_event(&self, event: &CalendarEvent) -> Result<()> {
        query!(self, insert_one, COL_EVENTS, event).map(|_| ())
    }

    async fn fetch_event(&self, id: &str) -> Result<CalendarEvent> {
        query!(self, find_one_by_id, COL_EVENTS, id)?.ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_events_for_server_in_window(
        &self,
        server_id: &str,
        from: i64,
        to: i64,
    ) -> Result<Vec<CalendarEvent>> {
        Ok(self
            .col::<CalendarEvent>(COL_EVENTS)
            .find(doc! {
                "server": server_id,
                "cancelled": { "$ne": true },
                "start": { "$lte": to },
                "series_end": { "$gte": from },
            })
            .await
            .map_err(|_| create_database_error!("find", COL_EVENTS))?
            .filter_map(|s| async {
                if cfg!(debug_assertions) {
                    Some(s.unwrap())
                } else {
                    s.ok()
                }
            })
            .collect()
            .await)
    }

    async fn update_event(
        &self,
        id: &str,
        partial: &PartialCalendarEvent,
        remove: Vec<FieldsCalendarEvent>,
    ) -> Result<()> {
        query!(
            self,
            update_one_by_id,
            COL_EVENTS,
            id,
            partial,
            remove.iter().map(|x| x as &dyn IntoDocumentPath).collect(),
            None
        )
        .map(|_| ())
    }

    async fn replace_event(&self, event: &CalendarEvent) -> Result<()> {
        let result = self
            .col::<CalendarEvent>(COL_EVENTS)
            .replace_one(doc! { "_id": &event.id }, event)
            .await
            .map_err(|_| create_database_error!("replace_one", COL_EVENTS))?;
        if result.matched_count == 0 {
            Err(create_error!(NotFound))
        } else {
            Ok(())
        }
    }

    async fn delete_event(&self, id: &str) -> Result<()> {
        let result = self
            .col::<Document>(COL_EVENTS)
            .delete_one(doc! { "_id": id })
            .await
            .map_err(|_| create_database_error!("delete_one", COL_EVENTS))?;
        if result.deleted_count == 0 {
            Err(create_error!(NotFound))
        } else {
            Ok(())
        }
    }

    async fn insert_rsvp_if_absent(&self, rsvp: &EventRsvp) -> Result<bool> {
        // Atomic upsert: insert the row only when (event, user) is absent, and never
        // overwrite an existing answer (finding H5). The `_id` is seeded from the filter
        // equality on insert, so it is excluded from `$setOnInsert`.
        let mut on_insert =
            to_document(rsvp).map_err(|_| create_database_error!("serialize", COL_RSVPS))?;
        on_insert.remove("_id");

        let result = self
            .col::<Document>(COL_RSVPS)
            .update_one(
                doc! {
                    "_id.event": &rsvp.id.event,
                    "_id.user": &rsvp.id.user,
                },
                doc! { "$setOnInsert": on_insert },
            )
            .upsert(true)
            .await
            .map_err(|_| create_database_error!("update_one", COL_RSVPS))?;

        Ok(result.upserted_id.is_some())
    }

    async fn fetch_rsvp(&self, event_id: &str, user_id: &str) -> Result<EventRsvp> {
        query!(
            self,
            find_one,
            COL_RSVPS,
            doc! {
                "_id.event": event_id,
                "_id.user": user_id,
            }
        )?
        .ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_rsvps_for_event(&self, event_id: &str) -> Result<Vec<EventRsvp>> {
        Ok(self
            .col::<EventRsvp>(COL_RSVPS)
            .find(doc! {
                "_id.event": event_id,
            })
            .await
            .map_err(|_| create_database_error!("find", COL_RSVPS))?
            .filter_map(|s| async {
                if cfg!(debug_assertions) {
                    Some(s.unwrap())
                } else {
                    s.ok()
                }
            })
            .collect()
            .await)
    }

    async fn update_rsvp(&self, rsvp: &EventRsvp) -> Result<()> {
        // Replace only the mutable fields; never touch the composite `_id` or invite metadata.
        let status =
            bson::to_bson(&rsvp.status).map_err(|_| create_database_error!("serialize", COL_RSVPS))?;
        let mut set = doc! {
            "status": status,
            "had_accepted": rsvp.had_accepted,
        };
        let mut update = doc! {};
        match rsvp.responded_at {
            Some(v) => {
                set.insert("responded_at", v);
            }
            None => {
                update.insert("$unset", doc! { "responded_at": "" });
            }
        }
        update.insert("$set", set);

        let result = self
            .col::<Document>(COL_RSVPS)
            .update_one(
                doc! {
                    "_id.event": &rsvp.id.event,
                    "_id.user": &rsvp.id.user,
                },
                update,
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL_RSVPS))?;
        if result.matched_count == 0 {
            Err(create_error!(NotFound))
        } else {
            Ok(())
        }
    }

    async fn delete_rsvp(&self, event_id: &str, user_id: &str) -> Result<()> {
        let result = self
            .col::<Document>(COL_RSVPS)
            .delete_one(doc! {
                "_id.event": event_id,
                "_id.user": user_id,
            })
            .await
            .map_err(|_| create_database_error!("delete_one", COL_RSVPS))?;
        if result.deleted_count == 0 {
            Err(create_error!(NotFound))
        } else {
            Ok(())
        }
    }

    async fn delete_rsvps_for_event(&self, event_id: &str) -> Result<()> {
        self.col::<Document>(COL_RSVPS)
            .delete_many(doc! {
                "_id.event": event_id,
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL_RSVPS))
    }

    async fn fetch_events_in_reminder_window(
        &self,
        start_max: i64,
        series_end_min: i64,
    ) -> Result<Vec<CalendarEvent>> {
        Ok(self
            .col::<CalendarEvent>(COL_EVENTS)
            .find(doc! {
                "cancelled": { "$ne": true },
                "start": { "$lte": start_max },
                "series_end": { "$gte": series_end_min },
            })
            .await
            .map_err(|_| create_database_error!("find", COL_EVENTS))?
            .filter_map(|s| async {
                if cfg!(debug_assertions) {
                    Some(s.unwrap())
                } else {
                    s.ok()
                }
            })
            .collect()
            .await)
    }

    async fn mark_reminder_sent_if_absent(&self, key: &ReminderSentKey) -> Result<bool> {
        // Atomic insert-if-absent on the composite (event, user, occurrence, offset) key,
        // mirroring `insert_rsvp_if_absent`: the `_id` sub-fields are seeded from the
        // filter equalities on insert, so only `sent_at` goes in `$setOnInsert`.
        let marker = ReminderSent {
            id: key.clone(),
            sent_at: super::super::model::now_ms(),
        };
        let mut on_insert =
            to_document(&marker).map_err(|_| create_database_error!("serialize", COL_REMINDERS))?;
        on_insert.remove("_id");

        let result = self
            .col::<Document>(COL_REMINDERS)
            .update_one(
                doc! {
                    "_id.event": &key.event,
                    "_id.user": &key.user,
                    "_id.occurrence": key.occurrence,
                    "_id.offset": key.offset,
                },
                doc! { "$setOnInsert": on_insert },
            )
            .upsert(true)
            .await
            .map_err(|_| create_database_error!("update_one", COL_REMINDERS))?;

        Ok(result.upserted_id.is_some())
    }

    async fn delete_reminders_sent_before(&self, occurrence_before: i64) -> Result<usize> {
        let result = self
            .col::<Document>(COL_REMINDERS)
            .delete_many(doc! {
                "_id.occurrence": { "$lt": occurrence_before },
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_REMINDERS))?;
        Ok(result.deleted_count as usize)
    }
}

impl IntoDocumentPath for FieldsCalendarEvent {
    fn as_path(&self) -> Option<&'static str> {
        Some(match self {
            FieldsCalendarEvent::Channel => "channel",
            FieldsCalendarEvent::Description => "description",
            FieldsCalendarEvent::Location => "location",
            FieldsCalendarEvent::End => "end",
            FieldsCalendarEvent::Recurrence => "recurrence",
            FieldsCalendarEvent::Color => "color",
            FieldsCalendarEvent::SourceMessageId => "source_message_id",
            FieldsCalendarEvent::EditedAt => "edited_at",
        })
    }
}
