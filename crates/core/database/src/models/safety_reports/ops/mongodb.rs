use std::collections::HashSet;

use bson::{Bson, Document};
use futures::StreamExt;
use mongodb::options::FindOptions;
use revolt_models::v0::ReportStatusString;
use revolt_result::Result;

use crate::MongoDb;
use crate::Report;

use super::{collect_file_ids, AbstractReport};

static COL: &str = "safety_reports";
static COL_SNAPSHOTS: &str = "safety_snapshots";

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

    /// Ids of every file embedded in a snapshot of an open report
    async fn fetch_open_report_file_ids(&self) -> Result<HashSet<String>> {
        let mut reports = self
            .col::<Document>(COL)
            .find(doc! { "status": "Created" })
            .projection(doc! { "_id": 1_i32 })
            .await
            .map_err(|_| create_database_error!("find", COL))?;

        let mut report_ids = Vec::new();
        while let Some(row) = reports.next().await {
            let row = row.map_err(|_| create_database_error!("find", COL))?;
            let id = row
                .get_str("_id")
                .map_err(|_| create_database_error!("find", COL))?;
            report_ids.push(id.to_string());
        }

        let mut file_ids = HashSet::new();
        if report_ids.is_empty() {
            return Ok(file_ids);
        }

        // Walked as raw documents, never decoded into `Snapshot`, so an old
        // snapshot shape cannot hide its files
        let mut snapshots = self
            .col::<Document>(COL_SNAPSHOTS)
            .find(doc! {
                "report_id": {
                    "$in": report_ids
                }
            })
            .await
            .map_err(|_| create_database_error!("find", COL_SNAPSHOTS))?;

        while let Some(row) = snapshots.next().await {
            let row = row.map_err(|_| create_database_error!("find", COL_SNAPSHOTS))?;
            collect_file_ids(&Bson::Document(row).into_relaxed_extjson(), &mut file_ids);
        }

        Ok(file_ids)
    }
}
