use bson::{to_bson, Bson, Document};
use futures::TryStreamExt;
use revolt_result::Result;

use crate::MongoDb;
use crate::{PaymentEvent, PaymentEventState};

use super::AbstractPaymentEvents;

static COL: &str = "payment_events";

/// A state exactly as the typed insert stores it (unit variants are plain
/// strings, e.g. "Received")
fn state_bson(state: &PaymentEventState) -> Result<Bson> {
    to_bson(state).map_err(|_| create_database_error!("to_bson", COL))
}

/// A row of a list query that failed to read (or decode) fails the whole
/// query: a re-drive sweep that skipped it would never act on that event
fn row_error(error: mongodb::error::Error) -> revolt_result::Error {
    log::error!("{COL}: failed to read a row of a list query: {error}");
    create_database_error!("find", COL)
}

/// Whether a Mongo error is a duplicate key violation
fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    matches!(
        *error.kind,
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
            ref write_error,
        )) if write_error.code == 11000
    )
}

#[async_trait]
impl AbstractPaymentEvents for MongoDb {
    async fn insert_payment_event_if_absent(&self, e: &PaymentEvent) -> Result<bool> {
        // The key is `_id`, whose unique index always exists, so the
        // duplicate key mapping alone settles a concurrent redelivery.
        match self.col::<PaymentEvent>(COL).insert_one(e).await {
            Ok(_) => Ok(true),
            Err(error) if is_duplicate_key(&error) => Ok(false),
            Err(_) => Err(create_database_error!("insert_one", COL)),
        }
    }

    async fn fetch_payment_event(&self, id: &str) -> Result<Option<PaymentEvent>> {
        query!(self, find_one_by_id, COL, id)
    }

    async fn set_payment_event_state(
        &self,
        id: &str,
        state: PaymentEventState,
        last_error: Option<String>,
    ) -> Result<()> {
        let state = to_bson(&state).map_err(|_| create_database_error!("to_bson", COL))?;
        let update = match last_error {
            Some(last_error) => doc! {
                "$set": {
                    "state": state,
                    "last_error": last_error
                },
                "$inc": {
                    "attempts": 1_i32
                }
            },
            None => doc! {
                "$set": {
                    "state": state
                },
                "$unset": {
                    "last_error": 1_i32
                },
                "$inc": {
                    "attempts": 1_i32
                }
            },
        };

        self.col::<Document>(COL)
            .update_one(doc! { "_id": id }, update)
            .await
            .map_err(|_| create_database_error!("update_one", COL))
            .and_then(|result| {
                if result.matched_count == 0 {
                    Err(create_error!(NotFound))
                } else {
                    Ok(())
                }
            })
    }

    async fn fetch_failed_payment_events(
        &self,
        max_attempts: u32,
        limit: i64,
    ) -> Result<Vec<PaymentEvent>> {
        self.col::<PaymentEvent>(COL)
            .find(doc! {
                "state": state_bson(&PaymentEventState::Failed)?,
                "attempts": { "$lt": max_attempts as i64 }
            })
            .sort(doc! { "received_at": 1_i32, "_id": 1_i32 })
            .limit(limit)
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .try_collect()
            .await
            .map_err(row_error)
    }

    async fn fetch_payment_events_by_state(
        &self,
        state: PaymentEventState,
        before: i64,
        limit: i64,
    ) -> Result<Vec<PaymentEvent>> {
        self.col::<PaymentEvent>(COL)
            .find(doc! {
                "state": state_bson(&state)?,
                "received_at": { "$lt": before }
            })
            .sort(doc! { "received_at": 1_i32, "_id": 1_i32 })
            .limit(limit)
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .try_collect()
            .await
            .map_err(row_error)
    }
}

#[cfg(test)]
mod tests {
    use bson::{from_document, to_document};

    use crate::{PaymentEvent, PaymentEventState};

    fn event(last_error: Option<String>) -> PaymentEvent {
        PaymentEvent {
            id: "evt_1".to_string(),
            event_type: "checkout.session.completed".to_string(),
            livemode: false,
            received_at: 1_788_264_000_000,
            state: PaymentEventState::Failed,
            attempts: 3,
            last_error,
        }
    }

    #[test]
    fn stored_shape_omits_a_cleared_error_and_round_trips() {
        let doc = to_document(&event(None)).unwrap();
        assert_eq!(doc.get_str("_id").unwrap(), "evt_1");
        assert_eq!(doc.get_str("state").unwrap(), "Failed");
        // Absent, not null, so `$unset` and an omitted field agree
        assert!(!doc.contains_key("last_error"));
        assert_eq!(from_document::<PaymentEvent>(doc).unwrap(), event(None));

        let failed = event(Some("stripe timeout".to_string()));
        let doc = to_document(&failed).unwrap();
        assert_eq!(doc.get_str("last_error").unwrap(), "stripe timeout");
        assert_eq!(from_document::<PaymentEvent>(doc).unwrap(), failed);
    }

    #[test]
    fn attempts_read_back_after_an_int64_increment() {
        // `$inc` on a stored count can leave an Int32 or an Int64 behind
        let mut doc = to_document(&event(None)).unwrap();
        doc.insert("attempts", 4_i64);
        assert_eq!(
            from_document::<PaymentEvent>(doc.clone()).unwrap().attempts,
            4
        );
        doc.insert("attempts", 5_i32);
        assert_eq!(from_document::<PaymentEvent>(doc).unwrap().attempts, 5);
    }
}
