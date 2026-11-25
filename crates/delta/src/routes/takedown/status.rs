use revolt_database::{
    util::takedown_crypto::reference_for, Database, TakedownDeclineReason, TakedownRequest,
    TakedownStatus,
};
use revolt_models::v0;
use revolt_result::Result;
use rocket::{serde::json::Json, State};
use validator::Validate;

use super::{fetch_by_reference, invalid_takedown_body, takedown_disabled, QuietJson};

/// What the status page may show of a stored status
fn public_state(status: &TakedownStatus) -> v0::TakedownPublicState {
    match status {
        TakedownStatus::Received => v0::TakedownPublicState::Received,
        TakedownStatus::NeedsInfo => v0::TakedownPublicState::NeedsInfo,
        TakedownStatus::UnderReview => v0::TakedownPublicState::UnderReview,
        TakedownStatus::Removed => v0::TakedownPublicState::Removed,
        TakedownStatus::PartiallyRemoved => v0::TakedownPublicState::PartiallyRemoved,
        TakedownStatus::Declined => v0::TakedownPublicState::Declined,
        TakedownStatus::Closed => v0::TakedownPublicState::Closed,
    }
}

/// What the status page may show of a decline reason. Bad faith is never
/// named to the requester.
fn public_decline(reason: &TakedownDeclineReason) -> v0::TakedownPublicDecline {
    match reason {
        TakedownDeclineReason::NotIntimate => v0::TakedownPublicDecline::NotIntimate,
        TakedownDeclineReason::NotFound => v0::TakedownPublicDecline::NotFound,
        TakedownDeclineReason::NotOnSloga => v0::TakedownPublicDecline::NotOnSloga,
        TakedownDeclineReason::Duplicate => v0::TakedownPublicDecline::Duplicate,
        TakedownDeclineReason::BadFaith | TakedownDeclineReason::Other => {
            v0::TakedownPublicDecline::Other
        }
    }
}

pub(crate) fn public_status(request: &TakedownRequest) -> v0::TakedownPublicStatus {
    v0::TakedownPublicStatus {
        reference: reference_for(&request.id),
        state: public_state(&request.status),
        decline: request.decline_reason.as_ref().map(public_decline),
        received_at: request.received_at.format().to_string(),
    }
}

/// # Take It Down Request Status
///
/// Look up a request with its reference and the token from the status link.
/// An unknown reference and a wrong token get the same `NotFound`.
#[openapi(tag = "User Safety")]
#[post("/status", data = "<data>")]
pub async fn request_status(
    db: &State<Database>,
    data: QuietJson<v0::DataTakedownLookup>,
) -> Result<Json<v0::TakedownPublicStatus>> {
    let config = revolt_config::config().await;
    if !config.features.takedown.active() {
        return Err(takedown_disabled());
    }

    let data = data.into_inner()?;
    data.validate().map_err(|_| invalid_takedown_body())?;

    let request = fetch_by_reference(db, &data.reference, &data.token).await?;
    Ok(Json(public_status(&request)))
}

#[cfg(test)]
mod test {
    use super::super::test_support::{enable_takedown, insert_request};
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{
        util::takedown_crypto::reference_for, TakedownDeclineReason, TakedownStatus,
    };
    use rocket::http::{ContentType, Status};
    use serde_json::{json, Value};

    async fn lookup(harness: &TestHarness, reference: &str, token: &str) -> (Status, String) {
        let response = harness
            .client
            .post("/takedown/status")
            .header(ContentType::JSON)
            .body(json!({ "reference": reference, "token": token }).to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    #[test]
    fn the_right_token_shows_the_status() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let request = insert_request(
                &harness.db,
                "right-token",
                TakedownStatus::UnderReview,
                vec![],
            )
            .await;
            let reference = reference_for(&request.id);

            let (status, text) = lookup(&harness, &reference, "right-token").await;
            assert_eq!(status, Status::Ok, "{text}");
            let body: Value = serde_json::from_str(&text).expect("json");
            assert_eq!(body["reference"], json!(reference));
            assert_eq!(body["state"], json!("UnderReview"));
            assert!(body["decline"].is_null());
            assert_eq!(
                body["received_at"],
                json!(request.received_at.format().to_string())
            );

            // Nothing about the requester or the targets
            let keys = body.as_object().expect("object");
            assert_eq!(keys.len(), 4, "{body}");
            assert!(!text.contains("Test Person"));
            assert!(!text.contains("example.com"));

            // A lowercase prefix and surrounding spaces still find it
            let loose = format!("  td-{}  ", request.id.to_lowercase());
            let (status, _) = lookup(&harness, &loose, "right-token").await;
            assert_eq!(status, Status::Ok);
        })
    }

    #[test]
    fn wrong_token_unknown_reference_and_purged_look_the_same() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let request =
                insert_request(&harness.db, "right-token", TakedownStatus::Received, vec![]).await;
            let mut purged =
                insert_request(&harness.db, "purged-token", TakedownStatus::Closed, vec![]).await;
            purged.requester_purged = true;
            purged.sealed = String::new();
            harness
                .db
                .replace_takedown_request(&mut purged)
                .await
                .expect("purge");

            let wrong = lookup(&harness, &reference_for(&request.id), "wrong-token").await;
            let unknown = lookup(&harness, "TD-01ARZ3NDEKTSV4RRFFQ69G5FAV", "right-token").await;
            let malformed = lookup(&harness, "not-a-reference", "right-token").await;
            let gone = lookup(&harness, &reference_for(&purged.id), "purged-token").await;

            assert_eq!(wrong.0, Status::NotFound);
            for other in [&unknown, &malformed, &gone] {
                assert_eq!(other, &wrong);
            }
        })
    }

    #[test]
    fn a_bad_faith_decline_shows_as_other() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;

            let mut bad_faith =
                insert_request(&harness.db, "token-a", TakedownStatus::Declined, vec![]).await;
            bad_faith.decline_reason = Some(TakedownDeclineReason::BadFaith);
            bad_faith.bad_faith = true;
            harness
                .db
                .replace_takedown_request(&mut bad_faith)
                .await
                .expect("decline");

            let mut not_intimate =
                insert_request(&harness.db, "token-b", TakedownStatus::Declined, vec![]).await;
            not_intimate.decline_reason = Some(TakedownDeclineReason::NotIntimate);
            harness
                .db
                .replace_takedown_request(&mut not_intimate)
                .await
                .expect("decline");

            let (_, text) = lookup(&harness, &reference_for(&bad_faith.id), "token-a").await;
            let body: Value = serde_json::from_str(&text).expect("json");
            assert_eq!(body["state"], json!("Declined"));
            assert_eq!(body["decline"], json!("Other"));
            assert!(!text.contains("BadFaith"));

            let (_, text) = lookup(&harness, &reference_for(&not_intimate.id), "token-b").await;
            let body: Value = serde_json::from_str(&text).expect("json");
            assert_eq!(body["decline"], json!("NotIntimate"));
        })
    }

    #[test]
    fn status_is_off_with_the_feature() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (status, text) = lookup(&harness, "TD-01ARZ3NDEKTSV4RRFFQ69G5FAV", "token").await;
            assert_eq!(status, Status::BadRequest);
            assert!(text.contains("FeatureDisabled"), "{text}");
        })
    }
}
