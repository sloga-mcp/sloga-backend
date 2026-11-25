use std::collections::HashSet;

use revolt_models::v0::{ReportStatus, ReportStatusString};
use revolt_result::Result;

use crate::ReferenceDb;
use crate::Report;

use super::{collect_file_ids, AbstractReport};

#[async_trait]
impl AbstractReport for ReferenceDb {
    /// Insert a new report into the database
    async fn insert_report(&self, report: &Report) -> Result<()> {
        let mut reports = self.safety_reports.lock().await;
        if reports.contains_key(&report.id) {
            Err(create_database_error!("insert", "report"))
        } else {
            reports.insert(report.id.to_string(), report.clone());
            Ok(())
        }
    }

    /// Fetch a report by its id
    async fn fetch_report(&self, report_id: &str) -> Result<Report> {
        let reports = self.safety_reports.lock().await;
        reports
            .get(report_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch all reports, optionally filtered by status, newest first
    async fn fetch_reports(&self, status: Option<&ReportStatusString>) -> Result<Vec<Report>> {
        let reports = self.safety_reports.lock().await;
        let mut reports: Vec<Report> = reports
            .values()
            .filter(|report| match status {
                Some(ReportStatusString::Created) => {
                    matches!(report.status, ReportStatus::Created { .. })
                }
                Some(ReportStatusString::Rejected) => {
                    matches!(report.status, ReportStatus::Rejected { .. })
                }
                Some(ReportStatusString::Resolved) => {
                    matches!(report.status, ReportStatus::Resolved { .. })
                }
                None => true,
            })
            .cloned()
            .collect();

        reports.sort_by(|a, b| b.id.cmp(&a.id));
        Ok(reports)
    }

    /// Update an existing report
    async fn update_report(&self, report: &Report) -> Result<()> {
        let mut reports = self.safety_reports.lock().await;
        if let Some(entry) = reports.get_mut(&report.id) {
            *entry = report.clone();
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Ids of every file embedded in a snapshot of an open report
    async fn fetch_open_report_file_ids(&self) -> Result<HashSet<String>> {
        // One lock at a time: reports first, released before snapshots
        let open: HashSet<String> = {
            let reports = self.safety_reports.lock().await;
            reports
                .values()
                .filter(|report| matches!(report.status, ReportStatus::Created { .. }))
                .map(|report| report.id.clone())
                .collect()
        };

        let mut file_ids = HashSet::new();
        if open.is_empty() {
            return Ok(file_ids);
        }

        // Serialized to the same JSON shape the MongoDB driver walks
        let snapshots = self.safety_snapshots.lock().await;
        for snapshot in snapshots
            .values()
            .filter(|snapshot| open.contains(&snapshot.report_id))
        {
            let value = serde_json::to_value(snapshot).map_err(|_| create_error!(InternalError))?;
            collect_file_ids(&value, &mut file_ids);
        }

        Ok(file_ids)
    }
}
