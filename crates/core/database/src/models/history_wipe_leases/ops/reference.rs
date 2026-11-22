use std::collections::hash_map::Entry;

use revolt_result::Result;

use crate::{HistoryWipeLease, ReferenceDb};

use super::AbstractHistoryWipeLeases;

/// Each fn takes the `history_wipe_leases` lock alone and never holds it
/// together with another.
#[async_trait]
impl AbstractHistoryWipeLeases for ReferenceDb {
    /// Checked and written under the lock
    async fn claim_history_wipe_lease(
        &self,
        channel_id: &str,
        holder: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<Option<u64>> {
        let mut leases = self.history_wipe_leases.lock().await;
        let expires_at = now_ms.saturating_add(ttl_ms);
        match leases.entry(channel_id.to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(HistoryWipeLease {
                    id: channel_id.to_string(),
                    holder: holder.to_string(),
                    expires_at,
                    count: 0,
                });
                Ok(Some(0))
            }
            Entry::Occupied(mut entry) => {
                let lease = entry.get_mut();
                if lease.expires_at > now_ms && lease.holder != holder {
                    return Ok(None);
                }
                lease.holder = holder.to_string();
                lease.expires_at = expires_at;
                u64::try_from(lease.count)
                    .map(Some)
                    .map_err(|_| create_database_error!("claim", "history_wipe_leases"))
            }
        }
    }

    /// Checked and written under the lock
    async fn advance_history_wipe_lease(
        &self,
        channel_id: &str,
        holder: &str,
        add: u64,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<bool> {
        let add = i64::try_from(add).map_err(|_| create_error!(InternalError))?;
        let mut leases = self.history_wipe_leases.lock().await;
        match leases.get_mut(channel_id) {
            Some(lease) if lease.holder == holder => {
                lease.count = lease.count.saturating_add(add);
                lease.expires_at = now_ms.saturating_add(ttl_ms);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// The count is left alone
    async fn release_history_wipe_lease(&self, channel_id: &str, holder: &str) -> Result<()> {
        let mut leases = self.history_wipe_leases.lock().await;
        if let Some(lease) = leases.get_mut(channel_id) {
            if lease.holder == holder {
                lease.expires_at = 0;
            }
        }
        Ok(())
    }

    /// Delete the row; no row is not an error
    async fn delete_history_wipe_lease(&self, channel_id: &str) -> Result<()> {
        let mut leases = self.history_wipe_leases.lock().await;
        leases.remove(channel_id);
        Ok(())
    }
}
