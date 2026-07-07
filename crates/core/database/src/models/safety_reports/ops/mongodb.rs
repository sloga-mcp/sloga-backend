use mongodb::options::FindOptions;
use revolt_models::v0::ReportStatusString;
use revolt_result::Result;

use crate::MongoDb;
use crate::Report;

use super::AbstractReport;

static COL: &str = "safety_reports";

#[async_trait]
impl AbstractReport for MongoDb {
    /// Insert a new report into the database
    async fn insert_report(&self, report: &Report) -> Result<()> {
        query!(self, insert_one, COL, &report).map(|_| ())
    }

    /// Fetch a report by its id
    async fn fetch_report(&self, report_id: &str) -> Result<Report> {
        query!(self, find_one_by_id, COL, report_id)?.ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch all reports, optionally filtered by status, newest first
    async fn fetch_reports(&self, status: Option<&ReportStatusString>) -> Result<Vec<Report>> {
        let filter = match status {
            Some(ReportStatusString::Created) => doc! { "status": "Created" },
            Some(ReportStatusString::Rejected) => doc! { "status": "Rejected" },
            Some(ReportStatusString::Resolved) => doc! { "status": "Resolved" },
            None => doc! {},
        };

        query!(
            self,
            find_with_options,
            COL,
            filter,
            FindOptions::builder().sort(doc! { "_id": -1 }).build()
        )
    }

    /// Update an existing report
    async fn update_report(&self, report: &Report) -> Result<()> {
        self.col::<Report>(COL)
            .replace_one(doc! { "_id": &report.id }, report)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("replace_one", COL))
    }
}
