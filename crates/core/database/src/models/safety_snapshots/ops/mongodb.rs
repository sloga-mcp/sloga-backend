use revolt_result::Result;

use crate::MongoDb;
use crate::Snapshot;

use super::AbstractSnapshot;

static COL: &str = "safety_snapshots";

#[async_trait]
impl AbstractSnapshot for MongoDb {
    /// Insert a new snapshot into the database
    async fn insert_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        query!(self, insert_one, COL, &snapshot).map(|_| ())
    }

    /// Fetch all snapshots attached to a report
    async fn fetch_snapshots_by_report(&self, report_id: &str) -> Result<Vec<Snapshot>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "report_id": report_id
            }
        )
    }
}
