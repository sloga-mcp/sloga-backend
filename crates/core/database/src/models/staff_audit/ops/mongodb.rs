use mongodb::options::FindOptions;
use revolt_result::Result;

use crate::{MongoDb, StaffAuditEntry};

use super::AbstractStaffAudit;

static COL: &str = "staff_audit";

#[async_trait]
impl AbstractStaffAudit for MongoDb {
    async fn insert_staff_audit(&self, e: &StaffAuditEntry) -> Result<()> {
        // Not `query!`: under debug assertions it unwraps the driver error,
        // and `StaffAuditEntry::record` promises never to panic.
        self.col::<StaffAuditEntry>(COL)
            .insert_one(e)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("insert_one", COL))
    }

    async fn fetch_staff_audit_for_request(
        &self,
        request_id: &str,
    ) -> Result<Vec<StaffAuditEntry>> {
        query!(
            self,
            find_with_options,
            COL,
            doc! { "request_id": request_id },
            FindOptions::builder()
                .sort(doc! { "created_at": 1_i32, "_id": 1_i32 })
                .build()
        )
    }
}
