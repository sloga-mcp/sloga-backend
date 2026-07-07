use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};

/// # List Reports
///
/// Fetch reports made against content on the platform,
/// optionally filtered by status (Created, Rejected or Resolved).
/// Newest reports are returned first.
///
/// Requires a privileged account.
#[openapi(tag = "User Safety")]
#[get("/reports?<status>")]
pub async fn report_list(
    db: &State<Database>,
    user: User,
    status: Option<String>,
) -> Result<Json<Vec<v0::Report>>> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let status = match status.as_deref() {
        None => None,
        Some("Created") => Some(v0::ReportStatusString::Created),
        Some("Rejected") => Some(v0::ReportStatusString::Rejected),
        Some("Resolved") => Some(v0::ReportStatusString::Resolved),
        Some(_) => {
            return Err(create_error!(FailedValidation {
                error: "status must be Created, Rejected or Resolved".to_string()
            }))
        }
    };

    let reports = db.fetch_reports(status.as_ref()).await?;
    Ok(Json(reports.into_iter().map(Into::into).collect()))
}
