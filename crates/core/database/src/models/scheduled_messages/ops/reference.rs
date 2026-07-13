use revolt_result::Result;

use crate::ReferenceDb;
use crate::{ScheduledMessage, ScheduledMessageStatus};

use super::AbstractScheduledMessages;

#[async_trait]
impl AbstractScheduledMessages for ReferenceDb {
    /// Insert a new scheduled message.
    async fn insert_scheduled_message(&self, message: &ScheduledMessage) -> Result<()> {
        let mut rows = self.scheduled_messages.lock().await;
        if rows
            .insert(message.id.to_string(), message.clone())
            .is_some()
        {
            Err(create_database_error!("insert", "scheduled_messages"))
        } else {
            Ok(())
        }
    }

    /// Fetch a scheduled message by its id.
    async fn fetch_scheduled_message(&self, id: &str) -> Result<ScheduledMessage> {
        let rows = self.scheduled_messages.lock().await;
        rows.get(id).cloned().ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch one author's PENDING scheduled messages in a channel.
    async fn fetch_scheduled_messages_by_author(
        &self,
        channel: &str,
        author: &str,
    ) -> Result<Vec<ScheduledMessage>> {
        let rows = self.scheduled_messages.lock().await;
        let mut result: Vec<ScheduledMessage> = rows
            .values()
            .filter(|row| {
                row.channel == channel
                    && row.author == author
                    && matches!(row.status, ScheduledMessageStatus::Pending)
            })
            .cloned()
            .collect();
        result.sort_by_key(|row| row.scheduled_at);
        Ok(result)
    }

    /// Count an author's pending scheduled messages.
    async fn count_pending_scheduled_messages(
        &self,
        author: &str,
        channel: Option<&str>,
    ) -> Result<usize> {
        let rows = self.scheduled_messages.lock().await;
        Ok(rows
            .values()
            .filter(|row| {
                row.author == author
                    && matches!(row.status, ScheduledMessageStatus::Pending)
                    && channel.is_none_or(|channel| row.channel == channel)
            })
            .count())
    }

    /// Fetch pending rows whose delivery time has passed.
    async fn fetch_due_scheduled_messages(&self, now_ms: i64) -> Result<Vec<ScheduledMessage>> {
        let rows = self.scheduled_messages.lock().await;
        Ok(rows
            .values()
            .filter(|row| {
                matches!(row.status, ScheduledMessageStatus::Pending)
                    && row.scheduled_at <= now_ms
            })
            .cloned()
            .collect())
    }

    /// Atomically claim a row `Pending` → `Sending`. The mutex makes
    /// check-and-set atomic on this driver.
    async fn claim_scheduled_message(&self, id: &str) -> Result<bool> {
        let mut rows = self.scheduled_messages.lock().await;
        match rows.get_mut(id) {
            Some(row) if matches!(row.status, ScheduledMessageStatus::Pending) => {
                row.status = ScheduledMessageStatus::Sending;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Mark a claimed row as delivered.
    async fn mark_scheduled_message_sent(&self, id: &str) -> Result<()> {
        let mut rows = self.scheduled_messages.lock().await;
        if let Some(row) = rows.get_mut(id) {
            row.status = ScheduledMessageStatus::Sent;
        }
        Ok(())
    }

    /// Mark a claimed row as permanently failed.
    async fn mark_scheduled_message_failed(&self, id: &str, reason: &str) -> Result<()> {
        let mut rows = self.scheduled_messages.lock().await;
        if let Some(row) = rows.get_mut(id) {
            row.status = ScheduledMessageStatus::Failed;
            row.failure_reason = Some(reason.to_string());
        }
        Ok(())
    }

    /// Delete a row only while it is still pending.
    async fn delete_scheduled_message_if_pending(&self, id: &str) -> Result<bool> {
        let mut rows = self.scheduled_messages.lock().await;
        match rows.get(id) {
            Some(row) if matches!(row.status, ScheduledMessageStatus::Pending) => {
                rows.remove(id);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Delete every scheduled message in a channel, returning the pending
    /// rows that were removed.
    async fn delete_scheduled_messages_for_channel(
        &self,
        channel: &str,
    ) -> Result<Vec<ScheduledMessage>> {
        let mut rows = self.scheduled_messages.lock().await;
        let pending: Vec<ScheduledMessage> = rows
            .values()
            .filter(|row| {
                row.channel == channel && matches!(row.status, ScheduledMessageStatus::Pending)
            })
            .cloned()
            .collect();

        rows.retain(|_, row| row.channel != channel);
        Ok(pending)
    }

    /// Delete every scheduled message targeting a server's channels,
    /// returning the pending rows that were removed.
    async fn delete_scheduled_messages_for_server(
        &self,
        server: &str,
    ) -> Result<Vec<ScheduledMessage>> {
        let mut rows = self.scheduled_messages.lock().await;
        let pending: Vec<ScheduledMessage> = rows
            .values()
            .filter(|row| {
                row.server.as_deref() == Some(server)
                    && matches!(row.status, ScheduledMessageStatus::Pending)
            })
            .cloned()
            .collect();

        rows.retain(|_, row| row.server.as_deref() != Some(server));
        Ok(pending)
    }

    /// Sweep finished (non-pending) rows older than the cutoff.
    async fn delete_finished_scheduled_messages_before(
        &self,
        cutoff_ms: i64,
    ) -> Result<Vec<ScheduledMessage>> {
        let mut rows = self.scheduled_messages.lock().await;
        let removed: Vec<ScheduledMessage> = rows
            .values()
            .filter(|row| {
                !matches!(row.status, ScheduledMessageStatus::Pending)
                    && row.scheduled_at < cutoff_ms
            })
            .cloned()
            .collect();

        rows.retain(|_, row| {
            matches!(row.status, ScheduledMessageStatus::Pending) || row.scheduled_at >= cutoff_ms
        });
        Ok(removed)
    }
}
