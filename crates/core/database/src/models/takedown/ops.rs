use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::TakedownRequest;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractTakedownRequests: Sync + Send {
    /// Insert a new request (callers build it with `revision: 0`)
    async fn insert_takedown_request(&self, r: &TakedownRequest) -> Result<()>;

    /// Fetch a request by id (`NotFound` if absent)
    async fn fetch_takedown_request(&self, id: &str) -> Result<TakedownRequest>;

    /// Every open request (Received, NeedsInfo, UnderReview), earliest
    /// deadline first
    async fn fetch_open_takedown_requests(&self) -> Result<Vec<TakedownRequest>>;

    /// Requests received at or after `since`, any status, newest first
    async fn fetch_recent_takedown_requests(
        &self,
        since: Timestamp,
    ) -> Result<Vec<TakedownRequest>>;

    /// Requests from one contact fingerprint received at or after `since`,
    /// oldest first
    async fn fetch_takedown_requests_by_contact_since(
        &self,
        contact_fp: &str,
        since: Timestamp,
    ) -> Result<Vec<TakedownRequest>>;

    /// Requests whose hold has ended: `hold_until <= now`, at least one entry
    /// in `held_files`, and not a child-safety case
    async fn fetch_takedown_requests_hold_due(
        &self,
        now: Timestamp,
    ) -> Result<Vec<TakedownRequest>>;

    /// Closed requests whose requester details are due for purging:
    /// `closed_at <= closed_before` and not yet purged
    async fn fetch_takedown_requests_to_purge(
        &self,
        closed_before: Timestamp,
    ) -> Result<Vec<TakedownRequest>>;

    /// Overwrite every field of a stored request except `markers`, but only
    /// if the stored `revision` still equals `r.revision`.
    ///
    /// On success the stored revision and `r.revision` are both bumped by
    /// one. A stale copy gets `InvalidOperation` (re-read and retry); a
    /// request that does not exist gets `NotFound`.
    async fn replace_takedown_request(&self, r: &mut TakedownRequest) -> Result<()>;

    /// Atomically add `marker` to the request if it is not there yet.
    ///
    /// Returns true only for the one caller that added it; false if it was
    /// already present or the request does not exist.
    async fn claim_takedown_marker(&self, id: &str, marker: &str) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};

    use super::AbstractTakedownRequests;
    use revolt_result::ErrorType;

    use crate::{
        HeldFile, TakedownDeclineReason, TakedownRequest, TakedownSource, TakedownStatus,
        TakedownTarget, UnresolvableKind,
    };

    /// A whole-second timestamp, so it round-trips through Mongo's
    /// millisecond encoding unchanged
    fn at(seconds: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(Duration::seconds(1_800_000_000 + seconds))
            .unwrap()
    }

    /// A 26-character ULID-shaped id that sorts by `n`
    fn id(n: u32) -> String {
        format!("01TD00000000000000000{n:05}")
    }

    fn request(n: u32, status: TakedownStatus, received: i64) -> TakedownRequest {
        TakedownRequest {
            id: id(n),
            status,
            source: TakedownSource::Web,
            received_at: at(received),
            deadline_at: at(received + 48 * 3600),
            sealed: "sealed".to_string(),
            contact_fp: "fp-a".to_string(),
            status_token_hash: "hash".to_string(),
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

    fn held_file(id: &str) -> HeldFile {
        HeldFile {
            id: id.to_string(),
            was_deleted: false,
            was_reported: true,
        }
    }

    fn ids(rows: &[TakedownRequest]) -> Vec<String> {
        rows.iter().map(|row| row.id.clone()).collect()
    }

    #[tokio::test]
    async fn insert_and_fetch_round_trip() {
        database_test!(|db| async move {
            let mut full = request(1, TakedownStatus::Declined, 0);
            full.source = TakedownSource::InApp {
                report_id: "01REPORT000000000000000001".to_string(),
            };
            full.locations = vec!["https://app.sloga.gg/channel/A/B".to_string()];
            full.minor_claimed = true;
            full.resolved = true;
            full.targets = vec![
                TakedownTarget::Message {
                    channel: "C".to_string(),
                    message: "M".to_string(),
                },
                TakedownTarget::File {
                    file: "F".to_string(),
                },
                TakedownTarget::User {
                    user: "U".to_string(),
                },
                TakedownTarget::Server {
                    server: "S".to_string(),
                },
                TakedownTarget::Emoji {
                    emoji: "E".to_string(),
                },
                TakedownTarget::Unresolvable {
                    location_index: 4,
                    kind: UnresolvableKind::External,
                },
            ];
            full.linked_request_ids = vec![id(9)];
            full.held_files = vec![held_file("F")];
            full.auto_hidden_file_ids = vec!["G".to_string()];
            full.hold_until = Some(at(100));
            full.child_safety = true;
            full.bad_faith = true;
            full.throttled = true;
            full.decline_reason = Some(TakedownDeclineReason::BadFaith);
            full.first_opened_at = Some(at(10));
            full.removed_at = Some(at(20));
            full.closed_at = Some(at(30));
            full.requester_purged = true;
            full.reviewer_note = Some("internal".to_string());
            full.revision = 7;
            full.markers = vec!["email:received".to_string()];

            db.insert_takedown_request(&full).await.unwrap();
            db.insert_takedown_request(&request(2, TakedownStatus::Received, 0))
                .await
                .unwrap();

            assert_eq!(db.fetch_takedown_request(&id(1)).await.unwrap(), full);
            assert_eq!(
                db.fetch_takedown_request(&id(2)).await.unwrap(),
                request(2, TakedownStatus::Received, 0)
            );
            assert!(db.fetch_takedown_request(&id(3)).await.is_err());
        });
    }

    #[tokio::test]
    async fn open_requests_are_ordered_by_deadline() {
        database_test!(|db| async move {
            // Inserted out of order; the order must come from the sort.
            let rows = [
                request(1, TakedownStatus::UnderReview, 300),
                request(2, TakedownStatus::Received, 100),
                request(3, TakedownStatus::Removed, 50),
                request(4, TakedownStatus::NeedsInfo, 200),
                request(5, TakedownStatus::Declined, 10),
                request(6, TakedownStatus::Closed, 20),
                request(7, TakedownStatus::PartiallyRemoved, 30),
            ];
            for row in &rows {
                db.insert_takedown_request(row).await.unwrap();
            }

            let open = db.fetch_open_takedown_requests().await.unwrap();
            assert_eq!(ids(&open), vec![id(2), id(4), id(1)]);
        });
    }

    #[tokio::test]
    async fn recent_requests_are_newest_first_any_status() {
        database_test!(|db| async move {
            for row in [
                request(1, TakedownStatus::Closed, 100),
                request(2, TakedownStatus::Received, 300),
                request(3, TakedownStatus::Removed, 200),
                request(4, TakedownStatus::Received, 99),
            ] {
                db.insert_takedown_request(&row).await.unwrap();
            }

            // `since` is inclusive.
            let recent = db.fetch_recent_takedown_requests(at(100)).await.unwrap();
            assert_eq!(ids(&recent), vec![id(2), id(3), id(1)]);
        });
    }

    #[tokio::test]
    async fn by_contact_since_filters_on_fingerprint_and_time() {
        database_test!(|db| async move {
            let mut other = request(3, TakedownStatus::Received, 500);
            other.contact_fp = "fp-b".to_string();
            for row in [
                request(1, TakedownStatus::Declined, 400),
                request(2, TakedownStatus::Received, 200),
                other,
                request(4, TakedownStatus::Received, 50),
            ] {
                db.insert_takedown_request(&row).await.unwrap();
            }

            let a = db
                .fetch_takedown_requests_by_contact_since("fp-a", at(200))
                .await
                .unwrap();
            assert_eq!(ids(&a), vec![id(2), id(1)]);

            let b = db
                .fetch_takedown_requests_by_contact_since("fp-b", at(0))
                .await
                .unwrap();
            assert_eq!(ids(&b), vec![id(3)]);

            let none = db
                .fetch_takedown_requests_by_contact_since("fp-c", at(0))
                .await
                .unwrap();
            assert!(none.is_empty());
        });
    }

    #[tokio::test]
    async fn hold_due_excludes_child_safety_and_empty_holds() {
        database_test!(|db| async move {
            let held = |n: u32, hold: Option<i64>| {
                let mut row = request(n, TakedownStatus::Removed, 0);
                row.hold_until = hold.map(at);
                row.held_files = vec![held_file(&format!("F{n}"))];
                row
            };

            let due = held(1, Some(100));
            let due_exactly_now = held(2, Some(500));
            let not_yet = held(3, Some(501));
            let mut child_safety = held(4, Some(100));
            child_safety.child_safety = true;
            let mut nothing_held = held(5, Some(100));
            nothing_held.held_files = vec![];
            let no_hold = held(6, None);

            for row in [
                not_yet,
                child_safety,
                due_exactly_now,
                nothing_held,
                no_hold,
                due,
            ] {
                db.insert_takedown_request(&row).await.unwrap();
            }

            let mut rows = ids(&db.fetch_takedown_requests_hold_due(at(500)).await.unwrap());
            rows.sort();
            assert_eq!(rows, vec![id(1), id(2)]);
        });
    }

    #[tokio::test]
    async fn to_purge_needs_closed_and_not_purged() {
        database_test!(|db| async move {
            let closed = |n: u32, closed_at: Option<i64>, purged: bool| {
                let mut row = request(n, TakedownStatus::Closed, 0);
                row.closed_at = closed_at.map(at);
                row.requester_purged = purged;
                row
            };

            for row in [
                closed(1, Some(100), false),
                closed(2, Some(1000), false),
                closed(3, Some(100), true),
                closed(4, None, false),
                closed(5, Some(1000), true),
                closed(6, Some(1001), false),
            ] {
                db.insert_takedown_request(&row).await.unwrap();
            }

            let mut rows = ids(&db.fetch_takedown_requests_to_purge(at(1000)).await.unwrap());
            rows.sort();
            assert_eq!(rows, vec![id(1), id(2)]);
        });
    }

    #[tokio::test]
    async fn replace_overwrites_everything_but_markers() {
        database_test!(|db| async move {
            let mut stored = request(1, TakedownStatus::Received, 0);
            stored.hold_until = Some(at(100));
            stored.decline_reason = Some(TakedownDeclineReason::Other);
            stored.first_opened_at = Some(at(1));
            db.insert_takedown_request(&stored).await.unwrap();
            assert!(db.claim_takedown_marker(&id(1), "alert:new").await.unwrap());

            // A stale in-memory copy carries a different marker list; it must
            // not overwrite the stored one. Cleared options must be cleared.
            let mut next = stored.clone();
            next.status = TakedownStatus::Removed;
            next.resolved = true;
            next.targets = vec![TakedownTarget::File {
                file: "F".to_string(),
            }];
            next.held_files = vec![held_file("F")];
            next.hold_until = None;
            next.decline_reason = None;
            next.removed_at = Some(at(50));
            next.reviewer_note = Some("checked".to_string());
            next.markers = vec!["email:outcome".to_string()];
            db.replace_takedown_request(&mut next).await.unwrap();
            assert_eq!(next.revision, 1);

            let fetched = db.fetch_takedown_request(&id(1)).await.unwrap();
            assert_eq!(fetched.markers, vec!["alert:new".to_string()]);
            let mut expected = next.clone();
            expected.markers = vec!["alert:new".to_string()];
            assert_eq!(fetched, expected);
            assert_eq!(fetched.revision, 1);
            assert_eq!(fetched.hold_until, None);
            assert_eq!(fetched.decline_reason, None);
            assert_eq!(fetched.first_opened_at, Some(at(1)));

            // The marker the stale copy carried was never claimed.
            assert!(db
                .claim_takedown_marker(&id(1), "email:outcome")
                .await
                .unwrap());

            // Replacing a request that does not exist is an error, not an insert.
            let mut missing = request(2, TakedownStatus::Received, 0);
            match db.replace_takedown_request(&mut missing).await {
                Err(error) => assert!(matches!(error.error_type, ErrorType::NotFound), "{error:?}"),
                Ok(()) => panic!("replaced a request that does not exist"),
            }
            assert_eq!(missing.revision, 0);
            assert!(db.fetch_takedown_request(&id(2)).await.is_err());
        });
    }

    #[tokio::test]
    async fn replace_refuses_a_stale_copy() {
        database_test!(|db| async move {
            db.insert_takedown_request(&request(1, TakedownStatus::Received, 0))
                .await
                .unwrap();

            // Two workers read the same revision.
            let mut first = db.fetch_takedown_request(&id(1)).await.unwrap();
            let mut second = db.fetch_takedown_request(&id(1)).await.unwrap();
            assert_eq!((first.revision, second.revision), (0, 0));

            first.status = TakedownStatus::UnderReview;
            db.replace_takedown_request(&mut first).await.unwrap();
            assert_eq!(first.revision, 1);

            // The second write is from a stale copy and must not land.
            second.status = TakedownStatus::Declined;
            second.reviewer_note = Some("stale".to_string());
            match db.replace_takedown_request(&mut second).await {
                Err(error) => assert!(
                    matches!(error.error_type, ErrorType::InvalidOperation),
                    "{error:?}"
                ),
                Ok(()) => panic!("a stale copy overwrote a newer revision"),
            }
            assert_eq!(second.revision, 0);

            let stored = db.fetch_takedown_request(&id(1)).await.unwrap();
            assert_eq!(stored.status, TakedownStatus::UnderReview);
            assert_eq!(stored.reviewer_note, None);
            assert_eq!(stored.revision, 1);

            // Re-read and retry succeeds.
            let mut fresh = stored;
            fresh.status = TakedownStatus::Declined;
            db.replace_takedown_request(&mut fresh).await.unwrap();
            assert_eq!(fresh.revision, 2);
            let stored = db.fetch_takedown_request(&id(1)).await.unwrap();
            assert_eq!(stored.status, TakedownStatus::Declined);
            assert_eq!(stored.revision, 2);

            // Replaying the same in-memory copy again is now stale too.
            fresh.revision = 1;
            assert!(db.replace_takedown_request(&mut fresh).await.is_err());
        });
    }

    #[tokio::test]
    async fn concurrent_replaces_have_one_winner() {
        database_test!(|db| async move {
            db.insert_takedown_request(&request(1, TakedownStatus::Received, 0))
                .await
                .unwrap();
            let base = db.fetch_takedown_request(&id(1)).await.unwrap();

            let writes = (0..8).map(|n| {
                let db = db.clone();
                let mut copy = base.clone();
                copy.reviewer_note = Some(format!("writer {n}"));
                async move { db.replace_takedown_request(&mut copy).await.is_ok() }
            });
            let results = futures::future::join_all(writes).await;
            assert_eq!(results.iter().filter(|won| **won).count(), 1);
            assert_eq!(db.fetch_takedown_request(&id(1)).await.unwrap().revision, 1);
        });
    }

    #[tokio::test]
    async fn claim_marker_succeeds_once() {
        database_test!(|db| async move {
            db.insert_takedown_request(&request(1, TakedownStatus::Received, 0))
                .await
                .unwrap();

            assert!(db.claim_takedown_marker(&id(1), "alert:12h").await.unwrap());
            assert!(!db.claim_takedown_marker(&id(1), "alert:12h").await.unwrap());
            assert!(db.claim_takedown_marker(&id(1), "alert:24h").await.unwrap());
            assert!(!db.claim_takedown_marker(&id(1), "alert:24h").await.unwrap());

            // A request that does not exist can't be claimed.
            assert!(!db.claim_takedown_marker(&id(2), "alert:12h").await.unwrap());

            let row = db.fetch_takedown_request(&id(1)).await.unwrap();
            assert_eq!(
                row.markers,
                vec!["alert:12h".to_string(), "alert:24h".to_string()]
            );
        });
    }

    #[tokio::test]
    async fn concurrent_claims_have_one_winner() {
        database_test!(|db| async move {
            db.insert_takedown_request(&request(1, TakedownStatus::Received, 0))
                .await
                .unwrap();

            let claims = (0..8).map(|_| {
                let db = db.clone();
                async move { db.claim_takedown_marker(&id(1), "autohide").await.unwrap() }
            });
            let results = futures::future::join_all(claims).await;
            assert_eq!(results.iter().filter(|won| **won).count(), 1);
        });
    }
}
