use iso8601_timestamp::Timestamp;
use revolt_database::{Database, User, SYSTEM_USER_ID};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use serde::Deserialize;
use validator::Validate;

use rocket::{serde::json::Json, State};

/// # Review Data
#[derive(Validate, Deserialize, JsonSchema)]
pub struct DataReviewReport {
    /// New status for the report
    status: v0::ReportStatusString,
    /// Reason the report was rejected; required when rejecting
    #[validate(length(min = 0, max = 1000))]
    rejection_reason: Option<String>,
    /// Moderator notes to keep on the report
    #[validate(length(min = 0, max = 4000))]
    notes: Option<String>,
}

/// # Review Report
///
/// Update the status of a report: resolve it, reject it or
/// re-open it for triage. Optionally attach moderator notes.
///
/// Requires a privileged account.
#[openapi(tag = "User Safety")]
#[post("/reports/<report_id>/status", data = "<data>")]
pub async fn report_review(
    db: &State<Database>,
    user: User,
    report_id: String,
    data: Json<DataReviewReport>,
) -> Result<Json<v0::Report>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let mut report = db.fetch_report(&report_id).await?;
    let was_open = matches!(report.status, v0::ReportStatus::Created {});

    report.status = match data.status {
        v0::ReportStatusString::Created => v0::ReportStatus::Created {},
        v0::ReportStatusString::Rejected => {
            let rejection_reason = data
                .rejection_reason
                .filter(|reason| !reason.is_empty())
                .ok_or_else(|| {
                    create_error!(FailedValidation {
                        error: "rejection_reason is required when rejecting a report".to_string()
                    })
                })?;

            v0::ReportStatus::Rejected {
                rejection_reason,
                closed_at: Some(Timestamp::now_utc()),
            }
        }
        v0::ReportStatusString::Resolved => v0::ReportStatus::Resolved {
            closed_at: Some(Timestamp::now_utc()),
        },
    };

    if let Some(notes) = data.notes {
        report.notes = notes;
    }

    // Closing a report the anti-spam detector filed against a user lifts the
    // DM pause it put in place. The op only touches a guard filed under this
    // very report, so closing any other report is a no-op. This runs whatever
    // the anti-spam config says, so staff can always lift a pause.
    //
    // It runs before the report is stored: if it fails, the review fails and
    // the report stays open; if storing the report then fails, staff retry
    // and clearing the same guard again only moves its `cleared_at` forward.
    let closes_open_report = was_open && !matches!(report.status, v0::ReportStatus::Created {});
    if closes_open_report && report.author_id == SYSTEM_USER_ID {
        if let v0::ReportedContent::User { id, .. } = &report.content {
            let cleared = db
                .clear_dm_guard_pause(id, &report.id, Timestamp::now_utc())
                .await?;

            log::info!(
                "AUDIT report review: actor={} report={} user={} dm_pause_cleared={}",
                user.id,
                report.id,
                id,
                cleared
            );
        }
    }

    db.update_report(&report).await?;

    log::info!(
        "AUDIT report review: actor={} report={} status={:?}",
        user.id,
        report.id,
        report.status
    );

    Ok(Json(report.into()))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use iso8601_timestamp::Timestamp;
    use revolt_database::{DmGuard, PartialUser, Report, User, SYSTEM_USER_ID};
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;
    use ulid::Ulid;

    /// Promote a fresh user to staff and return their session token
    async fn new_moderator(harness: &TestHarness) -> String {
        let (_, session, mut moderator) = harness.new_user().await;
        moderator
            .update(
                &harness.db,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("promote moderator");

        session.token.to_string()
    }

    /// Insert an open report about `user_id` filed by `author_id`
    async fn insert_user_report(harness: &TestHarness, author_id: &str, user_id: &str) -> String {
        let report = Report {
            id: Ulid::new().to_string(),
            author_id: author_id.to_string(),
            content: v0::ReportedContent::User {
                id: user_id.to_string(),
                report_reason: v0::UserReportReason::SpamAbuse,
                message_id: None,
            },
            additional_context: String::new(),
            status: v0::ReportStatus::Created {},
            notes: String::new(),
        };

        harness.db.insert_report(&report).await.expect("report");
        report.id
    }

    /// Pause `user`'s DMs under a guard filed for `report_id`
    async fn pause_dms(harness: &TestHarness, user: &User, report_id: &str) {
        let guard = DmGuard {
            report_id: report_id.to_string(),
            flagged_at: Timestamp::now_utc(),
            paused: true,
            cleared_at: None,
            recipients: 3,
            fingerprint: "test".into(),
        };

        assert!(harness
            .db
            .claim_dm_guard(&user.id, &guard, Timestamp::now_utc())
            .await
            .expect("claim guard"));
    }

    async fn review(harness: &TestHarness, token: &str, report_id: &str, body: serde_json::Value) {
        let response = harness
            .client
            .post(format!("/safety/reports/{report_id}/status"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(body.to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
    }

    async fn guard_of(harness: &TestHarness, user: &User) -> DmGuard {
        harness
            .db
            .fetch_user(&user.id)
            .await
            .expect("user")
            .dm_guard
            .expect("guard")
    }

    #[test]
    fn rejecting_system_report_lifts_dm_pause() {
        crate::util::test::rt().block_on(rejecting_system_report_lifts_dm_pause_case())
    }

    async fn rejecting_system_report_lifts_dm_pause_case() {
        let harness = TestHarness::new().await;
        let (_, _, spammer) = harness.new_user().await;
        let token = new_moderator(&harness).await;

        let report_id = insert_user_report(&harness, SYSTEM_USER_ID, &spammer.id).await;
        pause_dms(&harness, &spammer, &report_id).await;
        assert!(harness
            .db
            .fetch_user(&spammer.id)
            .await
            .unwrap()
            .is_dm_paused());

        review(
            &harness,
            &token,
            &report_id,
            json!({ "status": "Rejected", "rejection_reason": "false positive" }),
        )
        .await;

        let guard = guard_of(&harness, &spammer).await;
        assert!(!guard.paused);
        assert!(guard.cleared_at.is_some());
        assert_eq!(guard.report_id, report_id);
        assert!(!harness
            .db
            .fetch_user(&spammer.id)
            .await
            .unwrap()
            .is_dm_paused());
    }

    #[test]
    fn resolving_system_report_lifts_dm_pause() {
        crate::util::test::rt().block_on(resolving_system_report_lifts_dm_pause_case())
    }

    async fn resolving_system_report_lifts_dm_pause_case() {
        let harness = TestHarness::new().await;
        let (_, _, spammer) = harness.new_user().await;
        let token = new_moderator(&harness).await;

        let report_id = insert_user_report(&harness, SYSTEM_USER_ID, &spammer.id).await;
        pause_dms(&harness, &spammer, &report_id).await;

        review(
            &harness,
            &token,
            &report_id,
            json!({ "status": "Resolved" }),
        )
        .await;

        let guard = guard_of(&harness, &spammer).await;
        assert!(!guard.paused);
        assert!(guard.cleared_at.is_some());
        assert!(!harness
            .db
            .fetch_user(&spammer.id)
            .await
            .unwrap()
            .is_dm_paused());
    }

    #[test]
    fn closing_another_system_report_keeps_dm_pause() {
        crate::util::test::rt().block_on(closing_another_system_report_keeps_dm_pause_case())
    }

    async fn closing_another_system_report_keeps_dm_pause_case() {
        let harness = TestHarness::new().await;
        let (_, _, spammer) = harness.new_user().await;
        let token = new_moderator(&harness).await;

        // The guard belongs to the detector's report; the other one is, say,
        // a daily-scan report about the same user
        let guard_report = insert_user_report(&harness, SYSTEM_USER_ID, &spammer.id).await;
        let other_report = insert_user_report(&harness, SYSTEM_USER_ID, &spammer.id).await;
        pause_dms(&harness, &spammer, &guard_report).await;

        review(
            &harness,
            &token,
            &other_report,
            json!({ "status": "Resolved" }),
        )
        .await;

        let guard = guard_of(&harness, &spammer).await;
        assert!(guard.paused);
        assert!(guard.cleared_at.is_none());
        assert_eq!(guard.report_id, guard_report);
        assert!(harness
            .db
            .fetch_user(&spammer.id)
            .await
            .unwrap()
            .is_dm_paused());
    }

    #[test]
    fn closing_human_report_keeps_dm_pause() {
        crate::util::test::rt().block_on(closing_human_report_keeps_dm_pause_case())
    }

    async fn closing_human_report_keeps_dm_pause_case() {
        let harness = TestHarness::new().await;
        let (_, _, reporter) = harness.new_user().await;
        let (_, _, spammer) = harness.new_user().await;
        let token = new_moderator(&harness).await;

        // Even with the guard filed under this very report id, a report a
        // user filed never lifts the pause
        let report_id = insert_user_report(&harness, &reporter.id, &spammer.id).await;
        pause_dms(&harness, &spammer, &report_id).await;

        review(
            &harness,
            &token,
            &report_id,
            json!({ "status": "Resolved" }),
        )
        .await;

        let guard = guard_of(&harness, &spammer).await;
        assert!(guard.paused);
        assert!(guard.cleared_at.is_none());
        assert!(harness
            .db
            .fetch_user(&spammer.id)
            .await
            .unwrap()
            .is_dm_paused());
    }

    #[test]
    fn reclosing_a_closed_system_report_keeps_dm_pause() {
        crate::util::test::rt().block_on(reclosing_a_closed_system_report_keeps_dm_pause_case())
    }

    async fn reclosing_a_closed_system_report_keeps_dm_pause_case() {
        let harness = TestHarness::new().await;
        let (_, _, spammer) = harness.new_user().await;
        let token = new_moderator(&harness).await;

        let report_id = insert_user_report(&harness, SYSTEM_USER_ID, &spammer.id).await;
        review(
            &harness,
            &token,
            &report_id,
            json!({ "status": "Resolved" }),
        )
        .await;

        // Only a move out of `Created` lifts the pause: switching an already
        // closed report between Resolved and Rejected does not
        pause_dms(&harness, &spammer, &report_id).await;
        review(
            &harness,
            &token,
            &report_id,
            json!({ "status": "Rejected", "rejection_reason": "changed my mind" }),
        )
        .await;

        let guard = guard_of(&harness, &spammer).await;
        assert!(guard.paused);
        assert!(guard.cleared_at.is_none());

        // Re-opening and closing it again does
        review(&harness, &token, &report_id, json!({ "status": "Created" })).await;
        assert!(guard_of(&harness, &spammer).await.paused);
        review(
            &harness,
            &token,
            &report_id,
            json!({ "status": "Resolved" }),
        )
        .await;

        let guard = guard_of(&harness, &spammer).await;
        assert!(!guard.paused);
        assert!(guard.cleared_at.is_some());
    }

    #[test]
    fn review_report_flow() {
        crate::util::test::rt().block_on(review_report_flow_case())
    }

    async fn review_report_flow_case() {
        let harness = TestHarness::new().await;
        let (_, reporter_session, reporter) = harness.new_user().await;
        let (_, _, author) = harness.new_user().await;
        let (_, moderator_session, moderator) = harness.new_user().await;

        let mut moderator = moderator;
        moderator
            .update(
                &harness.db,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("promote moderator");

        let (server, channels) = harness.new_server(&author).await;
        let (channel, _, message) = harness.new_message(&author, &server, channels).await;

        // File a report as the reporter
        let response = harness
            .client
            .post("/safety/report")
            .header(ContentType::JSON)
            .header(Header::new(
                "x-session-token",
                reporter_session.token.to_string(),
            ))
            .body(
                json!({
                    "content": {
                        "type": "Message",
                        "id": message.id,
                        "report_reason": "Harassment"
                    },
                    "additional_context": "harassing me in DMs",
                    "message_snapshot": {
                        "message": {
                            "id": message.id,
                            "channel": channel.id(),
                            "author": author.id,
                            "content": "Test message"
                        }
                    }
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        // Regular users cannot access the review queue
        let response = harness
            .client
            .get("/safety/reports")
            .header(Header::new(
                "x-session-token",
                reporter_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        drop(response);

        // Moderator lists open reports
        let response = harness
            .client
            .get("/safety/reports?status=Created")
            .header(Header::new(
                "x-session-token",
                moderator_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let reports: Vec<v0::Report> =
            serde_json::from_str(&response.into_string().await.expect("body")).expect("reports");
        let report = reports
            .iter()
            .find(|report| report.author_id == reporter.id)
            .expect("report in queue");
        let report_id = report.id.clone();

        // Moderator fetches the report with its snapshots
        let response = harness
            .client
            .get(format!("/safety/reports/{report_id}"))
            .header(Header::new(
                "x-session-token",
                moderator_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let details: serde_json::Value =
            serde_json::from_str(&response.into_string().await.expect("body")).expect("details");
        let snapshots = details["snapshots"].as_array().expect("snapshots");
        let reporter_snapshot = snapshots
            .iter()
            .find(|snapshot| snapshot["content"]["_type"] == "ReporterMessage")
            .expect("reporter-supplied snapshot");
        assert_eq!(
            reporter_snapshot["content"]["message"]["content"],
            "Test message"
        );

        // Rejecting without a reason is refused
        let response = harness
            .client
            .post(format!("/safety/reports/{report_id}/status"))
            .header(ContentType::JSON)
            .header(Header::new(
                "x-session-token",
                moderator_session.token.to_string(),
            ))
            .body(json!({ "status": "Rejected" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
        drop(response);

        // Regular users cannot review reports
        let response = harness
            .client
            .post(format!("/safety/reports/{report_id}/status"))
            .header(ContentType::JSON)
            .header(Header::new(
                "x-session-token",
                reporter_session.token.to_string(),
            ))
            .body(json!({ "status": "Resolved" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        drop(response);

        // Moderator resolves the report with notes
        let response = harness
            .client
            .post(format!("/safety/reports/{report_id}/status"))
            .header(ContentType::JSON)
            .header(Header::new(
                "x-session-token",
                moderator_session.token.to_string(),
            ))
            .body(
                json!({
                    "status": "Resolved",
                    "notes": "author suspended"
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let updated: v0::Report =
            serde_json::from_str(&response.into_string().await.expect("body")).expect("report");
        assert!(matches!(
            updated.status,
            v0::ReportStatus::Resolved { closed_at: Some(_) }
        ));
        assert_eq!(updated.notes, "author suspended");

        // Resolved report left the open queue and shows under Resolved
        let response = harness
            .client
            .get("/safety/reports?status=Created")
            .header(Header::new(
                "x-session-token",
                moderator_session.token.to_string(),
            ))
            .dispatch()
            .await;
        let open: Vec<v0::Report> =
            serde_json::from_str(&response.into_string().await.expect("body")).expect("reports");
        assert!(!open.iter().any(|report| report.id == report_id));

        let response = harness
            .client
            .get("/safety/reports?status=Resolved")
            .header(Header::new(
                "x-session-token",
                moderator_session.token.to_string(),
            ))
            .dispatch()
            .await;
        let resolved: Vec<v0::Report> =
            serde_json::from_str(&response.into_string().await.expect("body")).expect("reports");
        assert!(resolved.iter().any(|report| report.id == report_id));
    }
}
