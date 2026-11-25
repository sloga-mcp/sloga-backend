use bson::{to_raw_document_buf, Bson, Document};
use iso8601_timestamp::Timestamp;
use mongodb::options::FindOptions;
use revolt_result::Result;

use crate::{MongoDb, TakedownRequest};

use super::AbstractTakedownRequests;

static COL: &str = "takedown_requests";

/// Stored names of the open statuses
const OPEN_STATUSES: [&str; 3] = ["Received", "NeedsInfo", "UnderReview"];

/// Fields skipped when `None`. A replace must `$unset` them, or clearing one
/// (a hold released, a decline reason dropped) would leave the old value.
const OPTIONAL_FIELDS: [&str; 6] = [
    "hold_until",
    "decline_reason",
    "first_opened_at",
    "removed_at",
    "closed_at",
    "reviewer_note",
];

/// Typed writes store `Timestamp` as Int64 unix milliseconds; query
/// thresholds must use the same encoding (see `mls/ops/mongodb.rs`)
fn timestamp_ms(at: &Timestamp) -> Bson {
    Bson::Int64(
        at.duration_since(Timestamp::UNIX_EPOCH)
            .whole_milliseconds() as i64,
    )
}

/// Serialize the way a typed insert does, so `$set` writes the same encoding
fn to_stored_document(r: &TakedownRequest) -> Option<Document> {
    to_raw_document_buf(r)
        .ok()
        .and_then(|raw| raw.to_document().ok())
}

impl MongoDb {
    async fn find_takedown_requests(
        &self,
        filter: Document,
        sort: Document,
    ) -> Result<Vec<TakedownRequest>> {
        query!(
            self,
            find_with_options,
            COL,
            filter,
            FindOptions::builder().sort(sort).build()
        )
    }
}

#[async_trait]
impl AbstractTakedownRequests for MongoDb {
    async fn insert_takedown_request(&self, r: &TakedownRequest) -> Result<()> {
        query!(self, insert_one, COL, r).map(|_| ())
    }

    async fn fetch_takedown_request(&self, id: &str) -> Result<TakedownRequest> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_open_takedown_requests(&self) -> Result<Vec<TakedownRequest>> {
        self.find_takedown_requests(
            doc! { "status": { "$in": OPEN_STATUSES.to_vec() } },
            doc! { "deadline_at": 1_i32, "_id": 1_i32 },
        )
        .await
    }

    async fn fetch_recent_takedown_requests(
        &self,
        since: Timestamp,
    ) -> Result<Vec<TakedownRequest>> {
        self.find_takedown_requests(
            doc! { "received_at": { "$gte": timestamp_ms(&since) } },
            doc! { "received_at": -1_i32, "_id": -1_i32 },
        )
        .await
    }

    async fn fetch_takedown_requests_by_contact_since(
        &self,
        contact_fp: &str,
        since: Timestamp,
    ) -> Result<Vec<TakedownRequest>> {
        self.find_takedown_requests(
            doc! {
                "contact_fp": contact_fp,
                "received_at": { "$gte": timestamp_ms(&since) }
            },
            doc! { "received_at": 1_i32, "_id": 1_i32 },
        )
        .await
    }

    async fn fetch_takedown_requests_hold_due(
        &self,
        now: Timestamp,
    ) -> Result<Vec<TakedownRequest>> {
        self.find_takedown_requests(
            doc! {
                "hold_until": { "$lte": timestamp_ms(&now) },
                "held_files.0": { "$exists": true },
                "child_safety": { "$ne": true }
            },
            doc! { "hold_until": 1_i32, "_id": 1_i32 },
        )
        .await
    }

    async fn fetch_takedown_requests_to_purge(
        &self,
        closed_before: Timestamp,
    ) -> Result<Vec<TakedownRequest>> {
        self.find_takedown_requests(
            doc! {
                "closed_at": { "$lte": timestamp_ms(&closed_before) },
                "requester_purged": { "$ne": true }
            },
            doc! { "closed_at": 1_i32, "_id": 1_i32 },
        )
        .await
    }

    async fn replace_takedown_request(&self, r: &mut TakedownRequest) -> Result<()> {
        let expected =
            i64::try_from(r.revision).map_err(|_| create_database_error!("revision", COL))?;
        let next = expected
            .checked_add(1)
            .ok_or_else(|| create_database_error!("revision", COL))?;

        let mut set =
            to_stored_document(r).ok_or_else(|| create_database_error!("to_document", COL))?;
        set.remove("_id");
        set.remove("markers");
        set.insert("revision", Bson::Int64(next));

        let mut unset = Document::new();
        for field in OPTIONAL_FIELDS {
            if !set.contains_key(field) {
                unset.insert(field, "");
            }
        }

        let mut update = doc! { "$set": set };
        if !unset.is_empty() {
            update.insert("$unset", unset);
        }

        // Compare-and-set on the revision. A row written before `revision`
        // existed has no field, which reads as 0.
        let filter = if expected == 0 {
            doc! {
                "_id": r.id.as_str(),
                "$or": [ { "revision": 0_i64 }, { "revision": { "$exists": false } } ]
            }
        } else {
            doc! { "_id": r.id.as_str(), "revision": expected }
        };

        let result = self
            .col::<Document>(COL)
            .update_one(filter, update)
            .await
            .map_err(|_| create_database_error!("update_one", COL))?;

        if result.matched_count == 1 {
            r.revision += 1;
            return Ok(());
        }

        // Nothing matched: either the request is gone or the copy is stale
        let exists = self
            .col::<Document>(COL)
            .find_one(doc! { "_id": r.id.as_str() })
            .await
            .map_err(|_| create_database_error!("find_one", COL))?
            .is_some();

        if exists {
            Err(create_error!(InvalidOperation))
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn claim_takedown_marker(&self, id: &str, marker: &str) -> Result<bool> {
        // The filter and the push are one document update, so of any number
        // of concurrent callers exactly one matches with the marker absent.
        self.col::<Document>(COL)
            .update_one(
                doc! { "_id": id, "markers": { "$ne": marker } },
                doc! { "$push": { "markers": marker } },
            )
            .await
            .map(|result| result.modified_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::Timestamp;

    use super::{to_stored_document, OPTIONAL_FIELDS};
    use crate::{TakedownDeclineReason, TakedownRequest, TakedownSource, TakedownStatus};

    fn request() -> TakedownRequest {
        TakedownRequest {
            id: "01TD0000000000000000000001".to_string(),
            status: TakedownStatus::Received,
            source: TakedownSource::Web,
            received_at: Timestamp::UNIX_EPOCH,
            deadline_at: Timestamp::UNIX_EPOCH,
            sealed: String::new(),
            contact_fp: String::new(),
            status_token_hash: String::new(),
            locations: vec![],
            minor_claimed: false,
            resolved: false,
            targets: vec![],
            linked_request_ids: vec![],
            held_files: vec![],
            auto_hidden_file_ids: vec![],
            hold_until: None,
            child_safety: false,
            bad_faith: false,
            throttled: false,
            decline_reason: None,
            first_opened_at: None,
            removed_at: None,
            closed_at: None,
            requester_purged: false,
            reviewer_note: None,
            revision: 0,
            markers: vec![],
        }
    }

    /// Every field that disappears when `None` must be in `OPTIONAL_FIELDS`,
    /// or a replace could never clear it.
    #[test]
    fn optional_fields_match_the_skipped_keys() {
        let bare = to_stored_document(&request()).unwrap();

        let mut full = request();
        full.hold_until = Some(Timestamp::UNIX_EPOCH);
        full.decline_reason = Some(TakedownDeclineReason::Other);
        full.first_opened_at = Some(Timestamp::UNIX_EPOCH);
        full.removed_at = Some(Timestamp::UNIX_EPOCH);
        full.closed_at = Some(Timestamp::UNIX_EPOCH);
        full.reviewer_note = Some(String::new());
        let full = to_stored_document(&full).unwrap();

        let mut skipped: Vec<&str> = full
            .keys()
            .map(String::as_str)
            .filter(|key| !bare.contains_key(*key))
            .collect();
        skipped.sort();
        let mut expected = OPTIONAL_FIELDS.to_vec();
        expected.sort();
        assert_eq!(skipped, expected);
    }

    /// Range filters compare against Int64 milliseconds; the stored field must
    /// use the same BSON type or `$lte` silently matches nothing.
    #[test]
    fn timestamps_are_stored_as_int64_milliseconds() {
        let mut row = request();
        row.hold_until = Some(Timestamp::UNIX_EPOCH);
        let stored = to_stored_document(&row).unwrap();
        assert!(matches!(
            stored.get("received_at"),
            Some(bson::Bson::Int64(0))
        ));
        assert!(matches!(
            stored.get("hold_until"),
            Some(bson::Bson::Int64(0))
        ));
    }
}
