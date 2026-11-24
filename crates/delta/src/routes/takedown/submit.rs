use std::time::Duration;

use revolt_database::{
    util::{captcha::check_captcha, email::is_invalid_tld_address},
    Database, SealedRequester, TakedownSource,
};
use revolt_models::v0;
use revolt_result::Result;
use rocket::{serde::json::Json, State};
use tokio::time::sleep;
use validator::Validate;

use super::{
    insert_and_notify, invalid_takedown_body, prepare_request, stored_role, takedown_disabled,
    NewTakedown, QuietJson,
};

/// # Submit Take It Down Request
///
/// File a request to remove an intimate image shared without consent. No
/// account needed. Always stores the request and answers with a new
/// reference; the links are looked at later, never while answering.
#[openapi(tag = "User Safety")]
#[post("/requests", data = "<data>")]
pub async fn submit_request(
    db: &State<Database>,
    data: QuietJson<v0::DataCreateTakedownRequest>,
) -> Result<Json<v0::TakedownSubmitted>> {
    let config = revolt_config::config().await;
    if !config.features.takedown.active() {
        return Err(takedown_disabled());
    }

    let mut data = data.into_inner()?;
    // A pasted address often carries stray spaces; the format check and the
    // stored copy both use the trimmed one
    data.email = data.email.trim().to_string();
    data.validate().map_err(|_| invalid_takedown_body())?;
    if data.description.trim().is_empty() || data.signature.trim().is_empty() {
        return Err(invalid_takedown_body());
    }

    // The contact address is where the answers go. Nothing can be mailed to
    // a `.invalid` address, and the stand-in of an account with no email
    // lives there, so one is refused like any other bad address.
    if is_invalid_tld_address(&data.email) {
        return Err(invalid_takedown_body());
    }

    check_captcha(data.captcha.as_deref()).await?;

    // Random jitter from 0-500ms, so the answer's timing says nothing about
    // earlier requests from the same address
    sleep(Duration::from_millis((rand::random::<f32>() * 500.) as u64)).await;

    let v0::DataCreateTakedownRequest {
        captcha: _,
        role,
        authority_note,
        description,
        locations,
        statement_ack: _,
        extra,
        email,
        name,
        signature,
        signature_ack: _,
        minor,
    } = data;

    let name = name
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| signature.clone());

    let prepared = prepare_request(
        db,
        &config.features.takedown,
        NewTakedown {
            source: TakedownSource::Web,
            requester: SealedRequester {
                role: stored_role(role),
                authority_note: authority_note.filter(|note| !note.trim().is_empty()),
                name,
                signature,
                email,
                description,
                extra: extra.filter(|extra| !extra.trim().is_empty()),
                added_info: vec![],
            },
            locations,
            targets: vec![],
            resolved: false,
            minor_claimed: minor,
        },
    )
    .await?;

    let reference = insert_and_notify(db, prepared, "web", vec![]).await?;
    Ok(Json(v0::TakedownSubmitted { reference }))
}

#[cfg(test)]
mod test {
    use super::super::test_support::{
        enable_takedown, open, recent, wait_for_received_marker, wait_for_submitted_audit,
    };
    use super::super::{MARKER_EMAIL_RECEIVED, NOTE_RECEIVED_SUPPRESSED};
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{
        util::takedown_crypto::id_from_reference, StaffAuditAction, TakedownRequest, TakedownRole,
        TakedownSource, TakedownStatus,
    };
    use rocket::http::{ContentType, Status};
    use serde_json::{json, Value};

    fn body(email: &str, locations: Vec<String>) -> Value {
        json!({
            "role": "Depicted",
            "description": "A photo of me posted in a server",
            "locations": locations,
            "statement_ack": true,
            "email": email,
            "signature": "Jane Q Sample",
            "signature_ack": true
        })
    }

    async fn submit(harness: &TestHarness, body: &Value) -> (Status, Value) {
        let response = harness
            .client
            .post("/takedown/requests")
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        let text = response.into_string().await.unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn fetch_stored(harness: &TestHarness, reference: &str) -> TakedownRequest {
        let id = id_from_reference(reference).expect("a TD- reference");
        harness
            .db
            .fetch_takedown_request(&id)
            .await
            .expect("stored request")
    }

    #[test]
    fn submit_stores_a_sealed_request() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;

            let mut request = body(
                "Jane.Sample@Example.com",
                vec!["https://app.sloga.gg/channel/A/B".to_string()],
            );
            request["minor"] = json!(true);
            request["extra"] = json!("EXTRA-DETAIL");

            let (status, answer) = submit(&harness, &request).await;
            assert_eq!(status, Status::Ok, "{answer}");

            let reference = answer["reference"].as_str().expect("reference");
            assert!(reference.starts_with("TD-"), "{reference}");
            assert_eq!(answer.as_object().expect("object").len(), 1, "{answer}");

            let stored = fetch_stored(&harness, reference).await;
            assert!(matches!(stored.status, TakedownStatus::Received));
            assert!(matches!(stored.source, TakedownSource::Web));
            assert!(stored.minor_claimed);
            assert!(!stored.resolved);
            assert!(stored.targets.is_empty());
            assert!(!stored.throttled);
            assert_eq!(stored.revision, 0);
            assert_eq!(stored.locations, vec!["https://app.sloga.gg/channel/A/B"]);
            assert_eq!(
                stored
                    .deadline_at
                    .checked_sub(iso8601_timestamp::Duration::hours(48)),
                Some(stored.received_at)
            );

            // Personal data only in the sealed blob
            assert!(!stored.sealed.contains("Jane"));
            assert!(!stored.contact_fp.contains("Jane"));
            let requester = open(&stored);
            assert!(matches!(requester.role, TakedownRole::Depicted));
            assert_eq!(requester.email, "Jane.Sample@Example.com");
            assert_eq!(requester.signature, "Jane Q Sample");
            // No name given: the signature stands in
            assert_eq!(requester.name, "Jane Q Sample");
            assert_eq!(requester.extra.as_deref(), Some("EXTRA-DETAIL"));
            assert!(requester.added_info.is_empty());

            // Audit and the received email happen off the request path
            wait_for_received_marker(&harness.db, &stored.id).await;
            let mut audit = vec![];
            for _ in 0..100 {
                audit = harness
                    .db
                    .fetch_staff_audit_for_request(&stored.id)
                    .await
                    .expect("audit");
                if audit
                    .iter()
                    .any(|entry| matches!(entry.action, StaffAuditAction::TakedownSubmitted))
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            let submitted = audit
                .iter()
                .find(|entry| matches!(entry.action, StaffAuditAction::TakedownSubmitted))
                .expect("a submitted entry");
            assert_eq!(submitted.actor, None);
            assert_eq!(submitted.note.as_deref(), Some("web"));
            assert!(submitted.target_ids.is_empty());
        })
    }

    #[test]
    fn real_and_fake_targets_answer_alike() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let (_, _, author) = harness.new_user().await;
            let (server, channels) = harness.new_server(&author).await;
            let (channel, _, message) = harness.new_message(&author, &server, channels).await;

            let real = format!("https://app.sloga.gg/channel/{}/{}", channel.id(), message.id);
            let fake = "https://app.sloga.gg/channel/01ZZZZZZZZZZZZZZZZZZZZZZZZ/01ZZZZZZZZZZZZZZZZZZZZZZZY"
                .to_string();

            let (real_status, real_answer) =
                submit(&harness, &body("real-target@example.com", vec![real])).await;
            let (fake_status, fake_answer) =
                submit(&harness, &body("fake-target@example.com", vec![fake])).await;

            assert_eq!(real_status, Status::Ok);
            assert_eq!(real_status, fake_status);

            // Same shape: one `reference` field, each a fresh TD- reference
            let keys = |answer: &Value| {
                answer
                    .as_object()
                    .expect("object")
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
            };
            assert_eq!(keys(&real_answer), vec!["reference".to_string()]);
            assert_eq!(keys(&real_answer), keys(&fake_answer));

            let real_reference = real_answer["reference"].as_str().expect("reference");
            let fake_reference = fake_answer["reference"].as_str().expect("reference");
            assert_ne!(real_reference, fake_reference);
            assert_eq!(real_reference.len(), fake_reference.len());

            // Neither was resolved while answering
            for reference in [real_reference, fake_reference] {
                let stored = fetch_stored(&harness, reference).await;
                assert!(!stored.resolved);
                assert!(stored.targets.is_empty());
            }
        })
    }

    #[test]
    fn the_same_address_always_gets_a_new_reference() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let request = body("repeat@example.com", vec![]);

            let (_, first) = submit(&harness, &request).await;
            let (_, second) = submit(&harness, &request).await;
            assert_ne!(first["reference"], second["reference"]);
        })
    }

    #[test]
    fn over_the_daily_soft_limit_is_stored_but_gets_no_email() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let request = body("busy-sender@example.com", vec![]);

            // The test config allows 5 a day; the 6th is still accepted and
            // answered exactly like the others
            let mut answers = vec![];
            for _ in 0..6 {
                let (status, answer) = submit(&harness, &request).await;
                assert_eq!(status, Status::Ok, "{answer}");
                answers.push(answer);
            }
            for answer in &answers {
                let keys: Vec<_> = answer.as_object().expect("object").keys().collect();
                assert_eq!(keys, vec!["reference"], "{answer}");
            }

            for (index, answer) in answers.iter().enumerate() {
                let stored = fetch_stored(&harness, answer["reference"].as_str().unwrap()).await;
                let over = index == 5;
                assert_eq!(stored.throttled, over, "request {index}");

                // The audit entry is written before any email is tried, so
                // once it exists the task has made its email decision
                let submitted = wait_for_submitted_audit(&harness.db, &stored.id).await;

                if over {
                    assert_eq!(
                        submitted.note.as_deref(),
                        Some(NOTE_RECEIVED_SUPPRESSED),
                        "request {index}"
                    );

                    // Give a stray send every chance to show up
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    let stored =
                        fetch_stored(&harness, answer["reference"].as_str().unwrap()).await;
                    assert!(
                        !stored.markers.iter().any(|m| m == MARKER_EMAIL_RECEIVED),
                        "no received email may be claimed over the limit"
                    );
                    let audit = harness
                        .db
                        .fetch_staff_audit_for_request(&stored.id)
                        .await
                        .expect("audit");
                    assert!(!audit
                        .iter()
                        .any(|entry| matches!(entry.action, StaffAuditAction::TakedownEmailSent)));
                } else {
                    assert_eq!(submitted.note.as_deref(), Some("web"), "request {index}");
                    wait_for_received_marker(&harness.db, &stored.id).await;
                }
            }
        })
    }

    #[test]
    fn a_bad_faith_history_throttles_new_requests() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let request = body("bad-faith@example.com", vec![]);

            let (_, first) = submit(&harness, &request).await;
            let mut earlier = fetch_stored(&harness, first["reference"].as_str().unwrap()).await;
            earlier.bad_faith = true;
            harness
                .db
                .replace_takedown_request(&mut earlier)
                .await
                .expect("mark bad faith");

            // Same address, different case and spacing: same fingerprint
            let (status, second) = submit(&harness, &body(" Bad-Faith@Example.com", vec![])).await;
            assert_eq!(status, Status::Ok, "{second}");
            let second = fetch_stored(&harness, second["reference"].as_str().unwrap()).await;
            assert!(second.throttled);

            // Bad faith alone only queues it later; under the daily limit
            // the received email still goes out
            let submitted = wait_for_submitted_audit(&harness.db, &second.id).await;
            assert_eq!(submitted.note.as_deref(), Some("web_throttled"));
            wait_for_received_marker(&harness.db, &second.id).await;
        })
    }

    #[test]
    fn feature_off_refuses_and_stores_nothing() {
        crate::util::test::rt().block_on(async {
            // No `enable_takedown`: the shipped config has the feature off
            let harness = TestHarness::new().await;
            let (status, answer) = submit(&harness, &body("feature-off@example.com", vec![])).await;

            assert_eq!(status, Status::BadRequest);
            assert_eq!(answer["type"], json!("FeatureDisabled"));
            assert!(recent(&harness.db).await.is_empty());
        })
    }

    /// Fails if: a body that must be refused is stored or answered with
    /// anything but the one fixed error, the answer repeats something that
    /// was sent, or a `.invalid` contact address (the stand-in domain, or
    /// any other) is accepted.
    #[test]
    fn invalid_bodies_get_one_fixed_error_that_echoes_nothing() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;

            let mut unticked = body("SECRET-ADDRESS@example.com", vec![]);
            unticked["statement_ack"] = json!(false);

            let mut bad_email = body("SECRET-not-an-address", vec![]);
            bad_email["signature"] = json!("SECRET-SIGNATURE");

            let mut blank_signature = body("SECRET-ADDRESS@example.com", vec![]);
            blank_signature["signature"] = json!("   ");

            let mut bad_role = body("SECRET-ADDRESS@example.com", vec![]);
            bad_role["role"] = json!("SECRET-ROLE");

            let mut too_many = body("SECRET-ADDRESS@example.com", vec![]);
            too_many["locations"] = json!(vec!["SECRET-LINK"; 21]);

            let stand_in = body("SECRET-ADDRESS@noemail.invalid", vec![]);
            let invalid_tld = body("SECRET-ADDRESS@Sloga.INVALID", vec![]);
            let padded_invalid_tld = body("  SECRET-ADDRESS@sloga.invalid ", vec![]);

            // The rate limiter runs in the harness: this route is in the
            // "takedown" bucket, 10 requests per 10 s for one address, and
            // every request of this test comes from the same one. The 8
            // cases below and the body that is not JSON make 9. An 11th
            // request would be answered 429 and fail the status check, so
            // a test that needs more cases gets a second harness.
            let cases = [
                unticked,
                bad_email,
                blank_signature,
                bad_role,
                too_many,
                stand_in,
                invalid_tld,
                padded_invalid_tld,
            ];
            let mut answers = vec![];
            for case in &cases {
                let (status, answer) = submit(&harness, case).await;
                assert_eq!(status, Status::BadRequest, "{answer}");
                assert!(!answer.to_string().contains("SECRET"), "{answer}");
                answers.push(answer);
            }

            // Not JSON at all
            let response = harness
                .client
                .post("/takedown/requests")
                .header(ContentType::JSON)
                // `\u{7b}` is the opening brace: a raw one here, never closed,
                // breaks the brace-counting source scan in `voice_join.rs`
                .body("\u{7b}\"email\": \"SECRET-ADDRESS@example.com\", ")
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::BadRequest);
            let text = response.into_string().await.expect("body");
            assert!(!text.contains("SECRET"), "{text}");
            answers.push(serde_json::from_str(&text).expect("json error"));

            assert_eq!(answers[0]["type"], json!("FailedValidation"));
            for answer in &answers {
                assert_eq!(answer, &answers[0]);
            }

            assert!(recent(&harness.db).await.is_empty());
        })
    }
}
