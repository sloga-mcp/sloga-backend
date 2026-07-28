use revolt_result::Result;

use crate::{ReferenceDb, RemoteControlAuditEntry};

use super::AbstractRemoteControlAudit;

#[async_trait]
impl AbstractRemoteControlAudit for ReferenceDb {
    async fn insert_remote_control_audit(&self, entry: &RemoteControlAuditEntry) -> Result<()> {
        let mut rows = self.remote_control_audit.lock().await;
        if rows.contains_key(&entry.id) {
            Err(create_database_error!("insert", "remote_control_audit"))
        } else {
            rows.insert(entry.id.clone(), entry.clone());
            Ok(())
        }
    }

    async fn fetch_remote_control_audit_by_channel(
        &self,
        channel_id: &str,
        limit: i64,
    ) -> Result<Vec<RemoteControlAuditEntry>> {
        let rows = self.remote_control_audit.lock().await;
        let mut rows: Vec<RemoteControlAuditEntry> = rows
            .values()
            .filter(|row| row.channel_id == channel_id)
            .cloned()
            .collect();
        // Newest first, on the same key the Mongo impl sorts by
        rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn fetch_remote_control_audit_by_controller(
        &self,
        controller_id: &str,
        limit: i64,
    ) -> Result<Vec<RemoteControlAuditEntry>> {
        let rows = self.remote_control_audit.lock().await;
        let mut rows: Vec<RemoteControlAuditEntry> = rows
            .values()
            .filter(|row| row.controller_id == controller_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        rows.truncate(limit as usize);
        Ok(rows)
    }
}
