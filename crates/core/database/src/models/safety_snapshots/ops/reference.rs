use revolt_result::Result;

use crate::ReferenceDb;
use crate::Snapshot;

use super::AbstractSnapshot;

#[async_trait]
impl AbstractSnapshot for ReferenceDb {
    /// Insert a new report into the database
    async fn insert_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        let mut snapshots = self.safety_snapshots.lock().await;
        if snapshots.contains_key(&snapshot.id) {
            Err(create_database_error!("insert", "snapshot"))
        } else {
            snapshots.insert(snapshot.id.to_string(), snapshot.clone());
            Ok(())
        }
    }

    /// Fetch all snapshots attached to a report
    async fn fetch_snapshots_by_report(&self, report_id: &str) -> Result<Vec<Snapshot>> {
        let snapshots = self.safety_snapshots.lock().await;
        let mut snapshots: Vec<Snapshot> = snapshots
            .values()
            .filter(|snapshot| snapshot.report_id == report_id)
            .cloned()
            .collect();

        snapshots.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(snapshots)
    }
}
