use bson::Document;
use futures::StreamExt;
use revolt_result::Result;

use crate::MongoDb;
use crate::ScheduledMessage;

use super::AbstractScheduledMessages;

static COL: &str = "scheduled_messages";

#[async_trait]
impl AbstractScheduledMessages for MongoDb {
    /// Insert a new scheduled message.
    async fn insert_scheduled_message(&self, message: &ScheduledMessage) -> Result<()> {
        query!(self, insert_one, COL, &message).map(|_| ())
    }

    /// Fetch a scheduled message by its id.
    async fn fetch_scheduled_message(&self, id: &str) -> Result<ScheduledMessage> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch one author's PENDING scheduled messages in a channel.
    async fn fetch_scheduled_messages_by_author(
        &self,
        channel: &str,
        author: &str,
    ) -> Result<Vec<ScheduledMessage>> {
        Ok(self
            .col::<ScheduledMessage>(COL)
            .find(doc! {
                "channel": channel,
                "author": author,
                "status": "Pending"
            })
            .sort(doc! { "scheduled_at": 1_i32 })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Count an author's pending scheduled messages.
    async fn count_pending_scheduled_messages(
        &self,
        author: &str,
        channel: Option<&str>,
    ) -> Result<usize> {
        let mut filter = doc! {
            "author": author,
            "status": "Pending"
        };
        if let Some(channel) = channel {
            filter.insert("channel", channel);
        }

        query!(self, count_documents, COL, filter).map(|count| count as usize)
    }

    /// Fetch pending rows whose delivery time has passed.
    async fn fetch_due_scheduled_messages(&self, now_ms: i64) -> Result<Vec<ScheduledMessage>> {
        Ok(self
            .col::<ScheduledMessage>(COL)
            .find(doc! {
                "status": "Pending",
                "scheduled_at": { "$lte": now_ms }
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Atomically claim a row `Pending` → `Sending`.
    async fn claim_scheduled_message(&self, id: &str) -> Result<bool> {
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id,
                    "status": "Pending"
                },
                doc! {
                    "$set": { "status": "Sending" }
                },
            )
            .await
            .map(|result| result.modified_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Mark a claimed row as delivered.
    async fn mark_scheduled_message_sent(&self, id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! { "_id": id },
                doc! { "$set": { "status": "Sent" } },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Mark a claimed row as permanently failed.
    async fn mark_scheduled_message_failed(&self, id: &str, reason: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! { "_id": id },
                doc! {
                    "$set": {
                        "status": "Failed",
                        "failure_reason": reason
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Delete a row only while it is still pending.
    async fn delete_scheduled_message_if_pending(&self, id: &str) -> Result<bool> {
        self.col::<Document>(COL)
            .delete_one(doc! {
                "_id": id,
                "status": "Pending"
            })
            .await
            .map(|result| result.deleted_count == 1)
            .map_err(|_| create_database_error!("delete_one", COL))
    }

    /// Delete every scheduled message in a channel, returning the pending
    /// rows that were removed.
    async fn delete_scheduled_messages_for_channel(
        &self,
        channel: &str,
    ) -> Result<Vec<ScheduledMessage>> {
        let pending: Vec<ScheduledMessage> = self
            .col::<ScheduledMessage>(COL)
            .find(doc! {
                "channel": channel,
                "status": "Pending"
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await;

        self.col::<Document>(COL)
            .delete_many(doc! {
                "channel": channel
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL))?;

        Ok(pending)
    }

    /// Delete every scheduled message targeting a server's channels,
    /// returning the pending rows that were removed.
    async fn delete_scheduled_messages_for_server(
        &self,
        server: &str,
    ) -> Result<Vec<ScheduledMessage>> {
        let pending: Vec<ScheduledMessage> = self
            .col::<ScheduledMessage>(COL)
            .find(doc! {
                "server": server,
                "status": "Pending"
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await;

        self.col::<Document>(COL)
            .delete_many(doc! {
                "server": server
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL))?;

        Ok(pending)
    }

    /// Sweep finished (non-pending) rows older than the cutoff.
    async fn delete_finished_scheduled_messages_before(
        &self,
        cutoff_ms: i64,
    ) -> Result<Vec<ScheduledMessage>> {
        let filter = doc! {
            "status": { "$ne": "Pending" },
            "scheduled_at": { "$lt": cutoff_ms }
        };

        let removed: Vec<ScheduledMessage> = self
            .col::<ScheduledMessage>(COL)
            .find(filter.clone())
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await;

        self.col::<Document>(COL)
            .delete_many(filter)
            .await
            .map_err(|_| create_database_error!("delete_many", COL))?;

        Ok(removed)
    }
}
