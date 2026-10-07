use futures::StreamExt;
use revolt_result::Result;

use crate::{AuditLogAction, AuditLogEntry, MongoDb, AUDIT_LOG_FETCH_MAX};

use super::AbstractAuditLog;

static COL: &str = "server_audit_log";

#[async_trait]
impl AbstractAuditLog for MongoDb {
    async fn insert_audit_log_entry(&self, entry: &AuditLogEntry) -> Result<()> {
        // Not `query!`: under debug assertions it unwraps the driver error,
        // and `AuditLogEntry::record` promises never to panic.
        self.col::<AuditLogEntry>(COL)
            .insert_one(entry)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("insert_one", COL))
    }

    async fn fetch_audit_log(
        &self,
        server: &str,
        before: Option<&str>,
        limit: i64,
        action: Option<AuditLogAction>,
        user: Option<&str>,
    ) -> Result<Vec<AuditLogEntry>> {
        let mut filter = doc! { "server": server };

        if let Some(before) = before {
            filter.insert("_id", doc! { "$lt": before });
        }

        if let Some(action) = action {
            let action =
                bson::to_bson(&action).map_err(|_| create_database_error!("to_bson", "action"))?;
            filter.insert("action", action);
        }

        if let Some(user) = user {
            filter.insert("actor", user);
        }

        Ok(self
            .col::<AuditLogEntry>(COL)
            .find(filter)
            .sort(doc! { "_id": -1_i32 })
            .limit(limit.clamp(1, AUDIT_LOG_FETCH_MAX))
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    async fn prune_audit_log_before(&self, cutoff: &str) -> Result<u64> {
        self.col::<AuditLogEntry>(COL)
            .delete_many(doc! {
                "_id": { "$lt": cutoff }
            })
            .await
            .map(|result| result.deleted_count)
            .map_err(|_| create_database_error!("delete_many", COL))
    }
}
