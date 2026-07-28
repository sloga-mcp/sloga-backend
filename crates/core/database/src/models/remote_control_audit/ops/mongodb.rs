use mongodb::options::FindOptions;
use revolt_result::Result;

use crate::{MongoDb, RemoteControlAuditEntry};

use super::AbstractRemoteControlAudit;

static COL: &str = "remote_control_audit";

#[async_trait]
impl AbstractRemoteControlAudit for MongoDb {
    async fn insert_remote_control_audit(&self, entry: &RemoteControlAuditEntry) -> Result<()> {
        query!(self, insert_one, COL, &entry).map(|_| ())
    }

    async fn fetch_remote_control_audit_by_channel(
        &self,
        channel_id: &str,
        limit: i64,
    ) -> Result<Vec<RemoteControlAuditEntry>> {
        query!(
            self,
            find_with_options,
            COL,
            doc! { "channel_id": channel_id },
            FindOptions::builder()
                .sort(doc! { "created_at": -1 })
                .limit(limit)
                .build()
        )
    }

    async fn fetch_remote_control_audit_by_controller(
        &self,
        controller_id: &str,
        limit: i64,
    ) -> Result<Vec<RemoteControlAuditEntry>> {
        query!(
            self,
            find_with_options,
            COL,
            doc! { "controller_id": controller_id },
            FindOptions::builder()
                .sort(doc! { "created_at": -1 })
                .limit(limit)
                .build()
        )
    }
}
