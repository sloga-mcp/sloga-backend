use revolt_result::Result;

use crate::Snapshot;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractSnapshot: Sync + Send {
    /// Insert a new snapshot into the database
    async fn insert_snapshot(&self, snapshot: &Snapshot) -> Result<()>;

    /// Fetch all snapshots attached to a report
    async fn fetch_snapshots_by_report(&self, report_id: &str) -> Result<Vec<Snapshot>>;
}
