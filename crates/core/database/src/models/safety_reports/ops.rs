use revolt_models::v0::ReportStatusString;
use revolt_result::Result;

use crate::Report;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractReport: Sync + Send {
    /// Insert a new report into the database
    async fn insert_report(&self, report: &Report) -> Result<()>;

    /// Fetch a report by its id
    async fn fetch_report(&self, report_id: &str) -> Result<Report>;

    /// Fetch all reports, optionally filtered by status, newest first
    async fn fetch_reports(&self, status: Option<&ReportStatusString>) -> Result<Vec<Report>>;

    /// Update an existing report
    async fn update_report(&self, report: &Report) -> Result<()>;
}
