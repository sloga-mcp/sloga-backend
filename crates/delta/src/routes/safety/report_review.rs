use iso8601_timestamp::Timestamp;
use revolt_database::{Database, User};
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
    use revolt_database::PartialUser;
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    #[rocket::async_test]
    async fn review_report_flow() {
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
