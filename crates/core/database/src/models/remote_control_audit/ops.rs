pub mod mongodb;
pub mod reference;

use revolt_result::Result;

use crate::RemoteControlAuditEntry;

#[async_trait]
pub trait AbstractRemoteControlAudit: Sync + Send {
    /// Insert a lifecycle audit row
    async fn insert_remote_control_audit(&self, entry: &RemoteControlAuditEntry) -> Result<()>;

    /// Fetch the most recent rows for a channel (newest first)
    async fn fetch_remote_control_audit_by_channel(
        &self,
        channel_id: &str,
        limit: i64,
    ) -> Result<Vec<RemoteControlAuditEntry>>;

    /// Fetch the most recent rows naming a controller (newest first) —
    /// the abuse-lookup axis: "who has this account been given control by"
    async fn fetch_remote_control_audit_by_controller(
        &self,
        controller_id: &str,
        limit: i64,
    ) -> Result<Vec<RemoteControlAuditEntry>>;
}
