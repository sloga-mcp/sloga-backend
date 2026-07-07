use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use serde::Serialize;

use rocket::{serde::json::Json, State};

/// # Report Details
#[derive(Serialize, JsonSchema, Debug)]
pub struct ReportDetailsResponse {
    /// The report itself
    report: v0::Report,
    /// Content snapshots attached to the report
    snapshots: Vec<v0::Snapshot>,
}

/// # Fetch Report
///
/// Fetch a report and the content snapshots attached to it.
///
/// Requires a privileged account.
#[openapi(tag = "User Safety")]
#[get("/reports/<report_id>")]
pub async fn report_fetch(
    db: &State<Database>,
    user: User,
    report_id: String,
) -> Result<Json<ReportDetailsResponse>> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let report = db.fetch_report(&report_id).await?;
    let snapshots = db.fetch_snapshots_by_report(&report_id).await?;

    let mut converted = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        converted.push(snapshot.into_v0().await);
    }

    Ok(Json(ReportDetailsResponse {
        report: report.into(),
        snapshots: converted,
    }))
}
