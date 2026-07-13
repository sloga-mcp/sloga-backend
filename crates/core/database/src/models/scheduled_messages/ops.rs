use revolt_result::Result;

use crate::ScheduledMessage;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractScheduledMessages: Sync + Send {
    /// Insert a new scheduled message.
    async fn insert_scheduled_message(&self, message: &ScheduledMessage) -> Result<()>;

    /// Fetch a scheduled message by its id.
    async fn fetch_scheduled_message(&self, id: &str) -> Result<ScheduledMessage>;

    /// Fetch one author's PENDING scheduled messages in a channel, ordered
    /// by delivery time. Strictly author-scoped — other users' pending
    /// messages are never exposed.
    async fn fetch_scheduled_messages_by_author(
        &self,
        channel: &str,
        author: &str,
    ) -> Result<Vec<ScheduledMessage>>;

    /// Count an author's pending scheduled messages, optionally restricted
    /// to one channel (drives the per-channel / per-user caps).
    async fn count_pending_scheduled_messages(
        &self,
        author: &str,
        channel: Option<&str>,
    ) -> Result<usize>;

    /// Fetch pending rows whose delivery time has passed (daemon scan).
    async fn fetch_due_scheduled_messages(&self, now_ms: i64) -> Result<Vec<ScheduledMessage>>;

    /// Atomically claim a row `Pending` → `Sending`; returns whether THIS
    /// caller won the claim (exactly-once delivery arbitration).
    async fn claim_scheduled_message(&self, id: &str) -> Result<bool>;

    /// Mark a claimed row as delivered.
    async fn mark_scheduled_message_sent(&self, id: &str) -> Result<()>;

    /// Mark a claimed row as permanently failed.
    async fn mark_scheduled_message_failed(&self, id: &str, reason: &str) -> Result<()>;

    /// Delete a row only while it is still pending; returns whether a row
    /// was deleted (author cancel — loses the race against a claim).
    async fn delete_scheduled_message_if_pending(&self, id: &str) -> Result<bool>;

    /// Delete every scheduled message in a channel, returning the pending
    /// rows that were removed (channel-deletion cascade: callers notify
    /// the authors and release claimed attachments).
    async fn delete_scheduled_messages_for_channel(
        &self,
        channel: &str,
    ) -> Result<Vec<ScheduledMessage>>;

    /// Delete every scheduled message targeting a server's channels
    /// (including threads — rows carry `server`), returning the pending
    /// rows that were removed (server-deletion cascade).
    async fn delete_scheduled_messages_for_server(
        &self,
        server: &str,
    ) -> Result<Vec<ScheduledMessage>>;

    /// Sweep finished (non-pending) rows whose delivery time is older than
    /// the cutoff (bounded storage; also collects rows stuck in `Sending`
    /// by a daemon crash). Returns the removed rows so the caller can
    /// release attachments still claimed by crash-stuck rows — but NEVER
    /// those of `Sent` rows, whose files were retargeted to the real
    /// message.
    async fn delete_finished_scheduled_messages_before(
        &self,
        cutoff_ms: i64,
    ) -> Result<Vec<ScheduledMessage>>;
}

#[cfg(test)]
mod tests {
    use super::AbstractScheduledMessages;
    use crate::{ScheduledMessage, ScheduledMessageStatus};
    use revolt_models::v0;

    fn row(id: &str, author: &str, channel: &str, scheduled_at: i64) -> ScheduledMessage {
        ScheduledMessage {
            id: id.to_string(),
            author: author.to_string(),
            channel: channel.to_string(),
            server: None,
            scheduled_at,
            data: v0::DataMessageSend {
                nonce: None,
                content: Some("later!".to_string()),
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            status: ScheduledMessageStatus::Pending,
            failure_reason: None,
        }
    }

    #[tokio::test]
    async fn claim_is_exactly_once_and_scan_finds_due_rows() {
        database_test!(|db| async move {
            let pending = row(
                "01SCHED00000000000000000000",
                "01USER000000000000000000000",
                "01CHAN000000000000000000000",
                1_000,
            );
            db.insert_scheduled_message(&pending).await.unwrap();

            // Due at/after its instant, not before
            let due = db.fetch_due_scheduled_messages(999).await.unwrap();
            assert!(!due.iter().any(|r| r.id == pending.id));
            let due = db.fetch_due_scheduled_messages(1_000).await.unwrap();
            assert!(due.iter().any(|r| r.id == pending.id));

            // First claim wins, second loses
            assert!(db.claim_scheduled_message(&pending.id).await.unwrap());
            assert!(!db.claim_scheduled_message(&pending.id).await.unwrap());

            // Claimed rows leave the scan
            let due = db.fetch_due_scheduled_messages(1_000).await.unwrap();
            assert!(!due.iter().any(|r| r.id == pending.id));

            // Finish + sweep
            db.mark_scheduled_message_sent(&pending.id).await.unwrap();
            db.delete_finished_scheduled_messages_before(2_000)
                .await
                .unwrap();
            assert!(db.fetch_scheduled_message(&pending.id).await.is_err());
        });
    }

    #[tokio::test]
    async fn cancel_only_deletes_pending_rows() {
        database_test!(|db| async move {
            let pending = row(
                "01SCHED00000000000000000001",
                "01USER000000000000000000000",
                "01CHAN000000000000000000000",
                1_000,
            );
            db.insert_scheduled_message(&pending).await.unwrap();

            // Claimed rows can no longer be cancelled
            assert!(db.claim_scheduled_message(&pending.id).await.unwrap());
            assert!(!db
                .delete_scheduled_message_if_pending(&pending.id)
                .await
                .unwrap());

            // Pending rows can
            let pending2 = row(
                "01SCHED00000000000000000002",
                "01USER000000000000000000000",
                "01CHAN000000000000000000000",
                1_000,
            );
            db.insert_scheduled_message(&pending2).await.unwrap();
            assert!(db
                .delete_scheduled_message_if_pending(&pending2.id)
                .await
                .unwrap());
            assert!(db.fetch_scheduled_message(&pending2.id).await.is_err());
        });
    }

    #[tokio::test]
    async fn caps_listing_and_channel_cascade() {
        database_test!(|db| async move {
            let author = "01USER000000000000000000001";
            let channel_a = "01CHANA0000000000000000000A";
            let channel_b = "01CHANB0000000000000000000B";

            db.insert_scheduled_message(&row("01SCHEDA0000000000000000001", author, channel_a, 2_000))
                .await
                .unwrap();
            db.insert_scheduled_message(&row("01SCHEDA0000000000000000002", author, channel_a, 1_000))
                .await
                .unwrap();
            db.insert_scheduled_message(&row("01SCHEDB0000000000000000001", author, channel_b, 1_500))
                .await
                .unwrap();
            // Someone else's row never shows up in the author's surfaces
            db.insert_scheduled_message(&row(
                "01SCHEDC0000000000000000001",
                "01USER000000000000000000002",
                channel_a,
                1_500,
            ))
            .await
            .unwrap();

            // Caps
            assert_eq!(
                db.count_pending_scheduled_messages(author, Some(channel_a))
                    .await
                    .unwrap(),
                2
            );
            assert_eq!(
                db.count_pending_scheduled_messages(author, None)
                    .await
                    .unwrap(),
                3
            );

            // Author-scoped listing, ordered by delivery time
            let listed = db
                .fetch_scheduled_messages_by_author(channel_a, author)
                .await
                .unwrap();
            let ids: Vec<&str> = listed.iter().map(|r| r.id.as_str()).collect();
            assert_eq!(
                ids,
                vec!["01SCHEDA0000000000000000002", "01SCHEDA0000000000000000001"]
            );

            // Channel cascade returns the removed pending rows
            let removed = db
                .delete_scheduled_messages_for_channel(channel_a)
                .await
                .unwrap();
            assert_eq!(removed.len(), 3);
            assert!(db
                .fetch_scheduled_messages_by_author(channel_a, author)
                .await
                .unwrap()
                .is_empty());
            // Other channels untouched
            assert_eq!(
                db.count_pending_scheduled_messages(author, None)
                    .await
                    .unwrap(),
                1
            );
        });
    }

    #[tokio::test]
    async fn server_cascade_returns_pending_rows() {
        database_test!(|db| async move {
            let author = "01USER000000000000000000003";
            let mut in_server = row("01SCHEDSRV000000000000000001", author, "01CHANSRV00000000000000001", 3_000);
            in_server.server = Some("01SERVER0000000000000000001".to_string());
            db.insert_scheduled_message(&in_server).await.unwrap();

            // A thread-targeted row carries the same server id.
            let mut in_thread = row("01SCHEDSRV000000000000000002", author, "01THREADSRV0000000000000001", 3_000);
            in_thread.server = Some("01SERVER0000000000000000001".to_string());
            db.insert_scheduled_message(&in_thread).await.unwrap();

            // A row in a different server is untouched.
            let mut elsewhere = row("01SCHEDSRV000000000000000003", author, "01CHANOTHER000000000000001", 3_000);
            elsewhere.server = Some("01SERVER0000000000000000002".to_string());
            db.insert_scheduled_message(&elsewhere).await.unwrap();

            let removed = db
                .delete_scheduled_messages_for_server("01SERVER0000000000000000001")
                .await
                .unwrap();
            assert_eq!(removed.len(), 2, "both server + thread rows returned");
            assert!(db.fetch_scheduled_message(&in_server.id).await.is_err());
            assert!(db.fetch_scheduled_message(&in_thread.id).await.is_err());
            // The other server's row survives.
            assert!(db.fetch_scheduled_message(&elsewhere.id).await.is_ok());
        });
    }
}
