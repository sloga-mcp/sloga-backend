use revolt_database::{
    util::takedown_crypto::{open_requester, seal_requester},
    Database, SealedRequester, StaffAuditAction, StaffAuditEntry, TakedownStatus,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::State;
use rocket_empty::EmptyResponse;
use validator::Validate;

use super::{
    fetch_by_reference, invalid_takedown_body, takedown_disabled, token_matches, QuietJson,
    MAX_LOCATIONS,
};

/// Retries after a concurrent change to the same request
const MAX_RETRIES: usize = 3;

/// Most additions one request keeps
const MAX_ADDED_INFO: usize = 20;

/// # Add Information To A Take It Down Request
///
/// Add links or details to an open request, with the reference and token
/// from the status link. A request waiting for more information goes back to
/// the queue.
#[openapi(tag = "User Safety")]
#[post("/info", data = "<data>")]
pub async fn add_info(
    db: &State<Database>,
    data: QuietJson<v0::DataTakedownAddInfo>,
) -> Result<EmptyResponse> {
    let config = revolt_config::config().await;
    let settings = &config.features.takedown;
    if !settings.active() {
        return Err(takedown_disabled());
    }

    let data = data.into_inner()?;
    data.validate().map_err(|_| invalid_takedown_body())?;

    let extra = data.extra.filter(|extra| !extra.trim().is_empty());
    if extra.is_none() && data.locations.is_empty() {
        return Err(invalid_takedown_body());
    }

    let mut request = fetch_by_reference(db, &data.reference, &data.token).await?;

    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            // Another writer got there first: start again from the stored copy
            request = db
                .fetch_takedown_request(&request.id)
                .await
                .map_err(|_| create_error!(NotFound))?;
            if !token_matches(&request, &data.token) {
                return Err(create_error!(NotFound));
            }
        }

        // Only an open request is still read by a reviewer
        if !request.status.is_open() {
            return Err(create_error!(InvalidOperation));
        }

        if request.locations.len() + data.locations.len() > MAX_LOCATIONS {
            return Err(invalid_takedown_body());
        }

        let mut requester: SealedRequester =
            serde_json::from_slice(&open_requester(&settings.data_key, &request.sealed)?)
                .map_err(|_| create_error!(InternalError))?;

        if let Some(extra) = &extra {
            if requester.added_info.len() >= MAX_ADDED_INFO {
                return Err(invalid_takedown_body());
            }
            requester.added_info.push(extra.clone());
        }

        let plaintext = serde_json::to_vec(&requester).map_err(|_| create_error!(InternalError))?;
        request.sealed = seal_requester(&settings.data_key, &plaintext)?;
        request.locations.extend(data.locations.iter().cloned());
        // New links need resolving again
        request.resolved = false;
        if matches!(request.status, TakedownStatus::NeedsInfo) {
            request.status = TakedownStatus::Received;
        }

        match db.replace_takedown_request(&mut request).await {
            Ok(()) => {
                StaffAuditEntry::record(
                    db,
                    None,
                    StaffAuditAction::TakedownInfoAdded,
                    Some(&request.id),
                    vec![],
                    Some(data.locations.len() as u64),
                    Some(if extra.is_some() { "details" } else { "links" }),
                )
                .await;

                return Ok(EmptyResponse);
            }
            Err(error) if matches!(error.error_type, ErrorType::InvalidOperation) => continue,
            Err(error) => return Err(error),
        }
    }

    Err(create_error!(InternalError))
}

#[cfg(test)]
mod test {
    use super::super::test_support::{enable_takedown, insert_request, open};
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{util::takedown_crypto::reference_for, StaffAuditAction, TakedownStatus};
    use rocket::http::{ContentType, Status};
    use serde_json::{json, Value};

    async fn add(harness: &TestHarness, body: Value) -> (Status, String) {
        let response = harness
            .client
            .post("/takedown/info")
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    #[test]
    fn adding_info_appends_and_returns_the_request_to_the_queue() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let request = insert_request(
                &harness.db,
                "info-token",
                TakedownStatus::NeedsInfo,
                vec!["https://app.sloga.gg/user/01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string()],
            )
            .await;

            let (status, text) = add(
                &harness,
                json!({
                    "reference": reference_for(&request.id),
                    "token": "info-token",
                    "locations": ["https://app.sloga.gg/server/01ARZ3NDEKTSV4RRFFQ69G5FAW"],
                    "extra": "ADDED-DETAIL"
                }),
            )
            .await;
            assert_eq!(status, Status::NoContent, "{text}");

            let stored = harness
                .db
                .fetch_takedown_request(&request.id)
                .await
                .expect("request");
            assert!(matches!(stored.status, TakedownStatus::Received));
            assert!(!stored.resolved);
            assert_eq!(stored.revision, 1);
            assert_eq!(stored.locations.len(), 2);
            assert_eq!(
                stored.locations[1],
                "https://app.sloga.gg/server/01ARZ3NDEKTSV4RRFFQ69G5FAW"
            );
            assert!(!stored.sealed.contains("ADDED-DETAIL"));

            let requester = open(&stored);
            assert_eq!(requester.added_info, vec!["ADDED-DETAIL".to_string()]);
            // The original details are untouched
            assert_eq!(requester.description, "test description");

            let audit = harness
                .db
                .fetch_staff_audit_for_request(&request.id)
                .await
                .expect("audit");
            let added = audit
                .iter()
                .find(|entry| matches!(entry.action, StaffAuditAction::TakedownInfoAdded))
                .expect("an info-added entry");
            assert_eq!(added.actor, None);
            assert_eq!(added.count, Some(1));
            assert_eq!(added.note.as_deref(), Some("details"));
        })
    }

    #[test]
    fn under_review_stays_under_review() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let request =
                insert_request(&harness.db, "token", TakedownStatus::UnderReview, vec![]).await;

            let (status, _) = add(
                &harness,
                json!({
                    "reference": reference_for(&request.id),
                    "token": "token",
                    "extra": "more"
                }),
            )
            .await;
            assert_eq!(status, Status::NoContent);

            let stored = harness
                .db
                .fetch_takedown_request(&request.id)
                .await
                .expect("request");
            assert!(matches!(stored.status, TakedownStatus::UnderReview));
            assert!(!stored.resolved);
        })
    }

    #[test]
    fn a_wrong_token_changes_nothing() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let request = insert_request(
                &harness.db,
                "right-token",
                TakedownStatus::NeedsInfo,
                vec![],
            )
            .await;

            let (wrong_status, wrong_text) = add(
                &harness,
                json!({
                    "reference": reference_for(&request.id),
                    "token": "wrong-token",
                    "extra": "more"
                }),
            )
            .await;
            let (unknown_status, unknown_text) = add(
                &harness,
                json!({
                    "reference": "TD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
                    "token": "right-token",
                    "extra": "more"
                }),
            )
            .await;
            assert_eq!(wrong_status, Status::NotFound);
            assert_eq!((wrong_status, wrong_text), (unknown_status, unknown_text));

            let stored = harness
                .db
                .fetch_takedown_request(&request.id)
                .await
                .expect("request");
            assert_eq!(stored.revision, 0);
            assert!(matches!(stored.status, TakedownStatus::NeedsInfo));
            assert!(open(&stored).added_info.is_empty());
        })
    }

    #[test]
    fn locations_stay_within_twenty() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let request = insert_request(
                &harness.db,
                "token",
                TakedownStatus::Received,
                vec!["https://example.com/a".to_string(); 19],
            )
            .await;

            let (status, _) = add(
                &harness,
                json!({
                    "reference": reference_for(&request.id),
                    "token": "token",
                    "locations": ["https://example.com/b", "https://example.com/c"]
                }),
            )
            .await;
            assert_eq!(status, Status::BadRequest);

            let (status, _) = add(
                &harness,
                json!({
                    "reference": reference_for(&request.id),
                    "token": "token",
                    "locations": ["https://example.com/b"]
                }),
            )
            .await;
            assert_eq!(status, Status::NoContent);

            let stored = harness
                .db
                .fetch_takedown_request(&request.id)
                .await
                .expect("request");
            assert_eq!(stored.locations.len(), 20);
        })
    }

    #[test]
    fn a_closed_request_takes_no_more_info() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let request =
                insert_request(&harness.db, "token", TakedownStatus::Declined, vec![]).await;

            let (status, text) = add(
                &harness,
                json!({
                    "reference": reference_for(&request.id),
                    "token": "token",
                    "extra": "more"
                }),
            )
            .await;
            assert_eq!(status, Status::BadRequest);
            assert!(text.contains("InvalidOperation"), "{text}");

            // An empty addition is refused before anything is read
            let (status, _) = add(
                &harness,
                json!({
                    "reference": reference_for(&request.id),
                    "token": "token",
                    "extra": "   "
                }),
            )
            .await;
            assert_eq!(status, Status::BadRequest);
        })
    }

    #[test]
    fn info_lands_on_top_of_a_reviewer_write() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let request =
                insert_request(&harness.db, "token", TakedownStatus::NeedsInfo, vec![]).await;

            // A reviewer wrote since the request was filed; the addition
            // keeps that write and bumps the revision again
            let mut reviewer_copy = harness
                .db
                .fetch_takedown_request(&request.id)
                .await
                .expect("request");
            reviewer_copy.first_opened_at = Some(iso8601_timestamp::Timestamp::now_utc());
            harness
                .db
                .replace_takedown_request(&mut reviewer_copy)
                .await
                .expect("reviewer write");

            let (status, _) = add(
                &harness,
                json!({
                    "reference": reference_for(&request.id),
                    "token": "token",
                    "extra": "more"
                }),
            )
            .await;
            assert_eq!(status, Status::NoContent);

            let stored = harness
                .db
                .fetch_takedown_request(&request.id)
                .await
                .expect("request");
            assert_eq!(stored.revision, 2);
            assert!(stored.first_opened_at.is_some());
            assert_eq!(open(&stored).added_info, vec!["more".to_string()]);
        })
    }
}
