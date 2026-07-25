use revolt_result::Result;

use crate::ChannelFollow;
use crate::ReferenceDb;

use super::AbstractChannelFollows;

#[async_trait]
impl AbstractChannelFollows for ReferenceDb {
    async fn insert_channel_follow(&self, follow: &ChannelFollow) -> Result<()> {
        let mut rows = self.channel_follows.lock().await;
        // Parity with the Mongo unique {source_channel, target_channel} index:
        // reject a duplicate pair (not just a duplicate id), with the same
        // `NoEffect` domain error the duplicate-key rejection maps to there.
        // Single Mutex = check and insert are atomic, so this is a real
        // guard and not the caller's TOCTOU probe repeated.
        if rows.values().any(|row| {
            row.source_channel == follow.source_channel
                && row.target_channel == follow.target_channel
        }) {
            return Err(create_error!(NoEffect));
        }
        if rows.insert(follow.id.to_string(), follow.clone()).is_some() {
            Err(create_database_error!("insert", "channel_follows"))
        } else {
            Ok(())
        }
    }

    async fn fetch_follow(&self, id: &str) -> Result<ChannelFollow> {
        let rows = self.channel_follows.lock().await;
        rows.get(id).cloned().ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_follow_by_source_and_target(
        &self,
        source_channel: &str,
        target_channel: &str,
    ) -> Result<Option<ChannelFollow>> {
        let rows = self.channel_follows.lock().await;
        Ok(rows
            .values()
            .find(|row| row.source_channel == source_channel && row.target_channel == target_channel)
            .cloned())
    }

    async fn fetch_follows_by_source(&self, source_channel: &str) -> Result<Vec<ChannelFollow>> {
        let rows = self.channel_follows.lock().await;
        Ok(rows
            .values()
            .filter(|row| row.source_channel == source_channel)
            .cloned()
            .collect())
    }

    async fn fetch_follows_by_target(&self, target_channel: &str) -> Result<Vec<ChannelFollow>> {
        let rows = self.channel_follows.lock().await;
        Ok(rows
            .values()
            .filter(|row| row.target_channel == target_channel)
            .cloned()
            .collect())
    }

    async fn fetch_follows_for_server(&self, server_id: &str) -> Result<Vec<ChannelFollow>> {
        let rows = self.channel_follows.lock().await;
        Ok(rows
            .values()
            .filter(|row| row.source_server == server_id || row.target_server == server_id)
            .cloned()
            .collect())
    }

    async fn fetch_follow_by_webhook(&self, webhook_id: &str) -> Result<Option<ChannelFollow>> {
        let rows = self.channel_follows.lock().await;
        Ok(rows.values().find(|row| row.webhook_id == webhook_id).cloned())
    }

    async fn count_follows_by_source(&self, source_channel: &str) -> Result<usize> {
        let rows = self.channel_follows.lock().await;
        Ok(rows
            .values()
            .filter(|row| row.source_channel == source_channel)
            .count())
    }

    async fn delete_channel_follow(&self, id: &str) -> Result<()> {
        // Idempotent: a missing id is a no-op.
        let mut rows = self.channel_follows.lock().await;
        rows.remove(id);
        Ok(())
    }
}
