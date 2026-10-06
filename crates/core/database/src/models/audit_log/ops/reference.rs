use revolt_result::Result;

use crate::{AuditLogAction, AuditLogEntry, ReferenceDb, AUDIT_LOG_FETCH_MAX};

use super::AbstractAuditLog;

#[async_trait]
impl AbstractAuditLog for ReferenceDb {
    async fn insert_audit_log_entry(&self, entry: &AuditLogEntry) -> Result<()> {
        let mut rows = self.server_audit_log.lock().await;
        if rows.contains_key(&entry.id) {
            Err(create_database_error!("insert", "server_audit_log"))
        } else {
            rows.insert(entry.id.clone(), entry.clone());
            Ok(())
        }
    }

    async fn fetch_audit_log(
        &self,
        server: &str,
        before: Option<&str>,
        limit: i64,
        action: Option<AuditLogAction>,
        user: Option<&str>,
    ) -> Result<Vec<AuditLogEntry>> {
        let rows = self.server_audit_log.lock().await;
        let mut entries: Vec<AuditLogEntry> = rows
            .values()
            .filter(|entry| {
                entry.server == server
                    && before.is_none_or(|before| entry.id.as_str() < before)
                    && action.is_none_or(|action| entry.action == action)
                    && user.is_none_or(|user| entry.actor.as_deref() == Some(user))
            })
            .cloned()
            .collect();

        // Newest first, on the same key the Mongo impl sorts by. A HashMap
        // iterates in arbitrary order, so this sort is not optional.
        entries.sort_by(|a, b| b.id.cmp(&a.id));
        entries.truncate(limit.clamp(1, AUDIT_LOG_FETCH_MAX) as usize);
        Ok(entries)
    }

    async fn prune_audit_log_before(&self, cutoff: &str) -> Result<u64> {
        let mut rows = self.server_audit_log.lock().await;
        let before = rows.len();
        rows.retain(|_, entry| entry.id.as_str() >= cutoff);
        Ok((before - rows.len()) as u64)
    }
}
