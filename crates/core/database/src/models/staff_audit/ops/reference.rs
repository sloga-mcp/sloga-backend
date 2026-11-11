use revolt_result::Result;

use crate::{ReferenceDb, StaffAuditEntry};

use super::AbstractStaffAudit;

#[async_trait]
impl AbstractStaffAudit for ReferenceDb {
    async fn insert_staff_audit(&self, e: &StaffAuditEntry) -> Result<()> {
        let mut rows = self.staff_audit.lock().await;
        if rows.contains_key(&e.id) {
            Err(create_database_error!("insert", "staff_audit"))
        } else {
            rows.insert(e.id.clone(), e.clone());
            Ok(())
        }
    }

    async fn fetch_staff_audit_for_request(
        &self,
        request_id: &str,
    ) -> Result<Vec<StaffAuditEntry>> {
        let rows = self.staff_audit.lock().await;
        let mut entries: Vec<StaffAuditEntry> = rows
            .values()
            .filter(|entry| entry.request_id.as_deref() == Some(request_id))
            .cloned()
            .collect();
        // Same keys the Mongo impl sorts by; a HashMap has no order
        entries.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        Ok(entries)
    }
}
