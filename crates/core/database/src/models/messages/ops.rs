use std::collections::HashMap;
use std::time::SystemTime;
use revolt_result::Result;

use crate::{AppendMessage, FieldsMessage, Message, MessageQuery, PartialMessage};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

/// What a channel's unread tail looks like, for the sidebar badge.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UnreadSummary {
    /// Messages after the read pointer, saturating at `UNREAD_COUNT_CAP`
    pub count: u32,
    /// Whether any of them carries an attachment
    pub attachments: bool,
}

#[async_trait]
pub trait AbstractMessages: Sync + Send {
    /// Insert a new message into the database
    async fn insert_message(&self, message: &Message) -> Result<()>;

    /// Fetch a message by its id
    async fn fetch_message(&self, id: &str) -> Result<Message>;

    /// Fetch multiple messages by given query
    async fn fetch_messages(&self, query: MessageQuery) -> Result<Vec<Message>>;

    /// Fetch multiple messages by given IDs
    async fn fetch_messages_by_id(&self, ids: &[String]) -> Result<Vec<Message>>;

    /// Update a given message with new information
    async fn update_message(&self, id: &str, message: &PartialMessage, remove: Vec<FieldsMessage>) -> Result<()>;

    /// Append information to a given message
    async fn append_message(&self, id: &str, append: &AppendMessage) -> Result<()>;

    /// Remove a single attachment (by file id) from a message's embedded attachment list.
    /// Idempotent: succeeds even if the message or attachment no longer exists.
    async fn remove_message_attachment(&self, message_id: &str, file_id: &str) -> Result<()>;

    /// Add a new reaction to a message
    async fn add_reaction(&self, id: &str, emoji: &str, user: &str) -> Result<()>;

    /// Remove a reaction from a message
    async fn remove_reaction(&self, id: &str, emoji: &str, user: &str) -> Result<()>;

    /// Remove reaction from a message
    async fn clear_reaction(&self, id: &str, emoji: &str) -> Result<()>;

    /// Count published (Crossposted-flagged) messages in a channel whose id
    /// is at or after `min_id` — drives the durable per-channel hourly
    /// publish cap. `channel` + `_id` lead the predicate so the flag bit
    /// filter only scans one hour of one channel.
    async fn count_crossposts_since(&self, channel: &str, min_id: &str) -> Result<usize>;

    /// Summarise the messages sitting after a user's read pointer in a channel:
    /// how many there are (stopping at `UNREAD_COUNT_CAP`) and whether any of
    /// them carries an attachment. `after_id` is exclusive; `None` means the
    /// channel was never acknowledged, so everything counts. `channel` + `_id`
    /// lead the predicate, and the count is capped, so this stays an index-only
    /// scan of at most one cap's worth of entries per channel.
    async fn summarise_unread(
        &self,
        channel: &str,
        after_id: Option<&str>,
    ) -> Result<UnreadSummary>;

    /// Delete a message from the database by its id
    async fn delete_message(&self, id: &str) -> Result<()>;

    /// Delete messages from a channel by their ids and corresponding channel id
    async fn delete_messages(&self, channel: &str, ids: &[String]) -> Result<()>;

    /// Delete all messages from a specific author in a server from a certain ULID onwards
    async fn delete_messages_by_author_since(
        &self,
        channels: &[String],
        author: &str,
        since: SystemTime
    ) -> Result<HashMap<String, Vec<String>>>;

    async fn delete_messages_by_user(&self, user_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use crate::{Message, PartialMessage};
    use revolt_models::v0;

    /// Minimal attachment — only its presence matters to the unread summary.
    fn attachment_file(seed: u64) -> crate::File {
        crate::File {
            id: format!("01FILE{seed:021}"),
            tag: "attachments".to_string(),
            filename: "note.txt".to_string(),
            hash: None,
            uploaded_at: None,
            uploader_id: None,
            used_for: None,
            deleted: None,
            reported: None,
            metadata: crate::Metadata::File,
            content_type: "text/plain".to_string(),
            size: 1,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        }
    }

    fn button(id: &str) -> v0::Component {
        v0::Component::Button {
            custom_id: id.to_string(),
            label: "Click".to_string(),
            style: v0::ButtonStyle::Primary,
            disabled: false,
        }
    }

    #[tokio::test]
    async fn components_survive_insert_and_partial_update() {
        database_test!(|db| async move {
            let message = Message {
                id: "01MESSAGE000000000000000000".to_string(),
                channel: "01CHANNEL000000000000000000".to_string(),
                author: "01BOT0000000000000000000000".to_string(),
                content: Some("pick one".to_string()),
                components: Some(vec![v0::ActionRow {
                    components: vec![button("a")],
                }]),
                ..Default::default()
            };
            db.insert_message(&message).await.unwrap();

            let fetched = db.fetch_message(&message.id).await.unwrap();
            assert_eq!(fetched.components, message.components);

            // A components-carrying partial must not silently drop the
            // field on either driver (component edit-responses depend on
            // update_message fanning the new rows out).
            let partial = PartialMessage {
                components: Some(vec![v0::ActionRow {
                    components: vec![button("b"), button("c")],
                }]),
                ..Default::default()
            };
            db.update_message(&message.id, &partial, vec![])
                .await
                .unwrap();

            let updated = db.fetch_message(&message.id).await.unwrap();
            assert_eq!(updated.components, partial.components);
            assert_eq!(
                updated.content, message.content,
                "unrelated fields must be untouched"
            );
        });
    }

    #[tokio::test]
    async fn count_crossposts_since_scopes_by_channel_time_and_flag() {
        database_test!(|db| async move {
            use revolt_models::v0::MessageFlags;
            let crossposted = 1_u32 << (MessageFlags::Crossposted as u32);
            let is_crosspost = 1_u32 << (MessageFlags::IsCrosspost as u32);

            let channel = "01CHANXPOST0000000000000001";
            let other_channel = "01CHANXPOST0000000000000002";

            // `rand` keeps ids unique even when two rows share a timestamp.
            let mk = |ms: u64, rand: u128, flags: Option<u32>, chan: &str| Message {
                id: ulid::Ulid::from_parts(ms, rand).to_string(),
                channel: chan.to_string(),
                author: "01USER000000000000000000000".to_string(),
                content: Some("published".to_string()),
                flags,
                ..Default::default()
            };

            // 12 published messages at ms 2000, 3000 .. 13000 in the channel.
            for i in 0..12u64 {
                db.insert_message(&mk(2_000 + i * 1_000, 1, Some(crossposted), channel))
                    .await
                    .unwrap();
            }
            // An OLD published message before the window.
            db.insert_message(&mk(500, 2, Some(crossposted), channel))
                .await
                .unwrap();
            // A non-published message in-window (no Crossposted flag).
            db.insert_message(&mk(2_500, 3, None, channel))
                .await
                .unwrap();
            // A delivered crosspost copy (IsCrosspost, NOT Crossposted) must
            // not count toward the source's publish cap.
            db.insert_message(&mk(2_600, 4, Some(is_crosspost), channel))
                .await
                .unwrap();
            // A published message in another channel must not leak in.
            db.insert_message(&mk(3_000, 5, Some(crossposted), other_channel))
                .await
                .unwrap();

            // Window lower bound at ms 1000 catches all 12 (>10 → cap tripped).
            let min_id = ulid::Ulid::from_parts(1_000, 0).to_string();
            assert_eq!(
                db.count_crossposts_since(channel, &min_id).await.unwrap(),
                12
            );

            // A tighter lower bound drops the earliest publishes from the count.
            let tighter = ulid::Ulid::from_parts(8_000, 0).to_string();
            assert_eq!(
                db.count_crossposts_since(channel, &tighter).await.unwrap(),
                6
            );
        });
    }

    #[tokio::test]
    async fn summarise_unread_scopes_by_channel_and_read_pointer() {
        database_test!(|db| async move {
            use revolt_models::v0::UNREAD_COUNT_CAP;

            let channel = "01CHANUNREAD0000000000000001";
            let other_channel = "01CHANUNREAD0000000000000002";

            let mk = |ms: u64, rand: u128, chan: &str, attachment: bool| Message {
                id: ulid::Ulid::from_parts(ms, rand).to_string(),
                channel: chan.to_string(),
                author: "01USER000000000000000000000".to_string(),
                content: Some("hello".to_string()),
                attachments: attachment.then(|| vec![attachment_file(ms)]),
                ..Default::default()
            };

            // Five plain messages at ms 1000, 2000 .. 5000.
            for i in 0..5u64 {
                db.insert_message(&mk(1_000 + i * 1_000, 1, channel, false))
                    .await
                    .unwrap();
            }
            // Another channel's traffic must not leak in.
            db.insert_message(&mk(3_000, 9, other_channel, true))
                .await
                .unwrap();

            // No read pointer — everything in the channel counts.
            let all = db.summarise_unread(channel, None).await.unwrap();
            assert_eq!(all.count, 5);
            assert!(!all.attachments);

            // The pointer is exclusive: acking ms 3000 leaves 4000 and 5000.
            let pointer = ulid::Ulid::from_parts(3_000, 1).to_string();
            let tail = db.summarise_unread(channel, Some(&pointer)).await.unwrap();
            assert_eq!(tail.count, 2);
            assert!(!tail.attachments);

            // An attachment anywhere in the tail raises the flag, and one
            // before the pointer does not.
            db.insert_message(&mk(500, 2, channel, true)).await.unwrap();
            db.insert_message(&mk(4_500, 3, channel, true))
                .await
                .unwrap();
            assert!(
                db.summarise_unread(channel, Some(&pointer))
                    .await
                    .unwrap()
                    .attachments
            );
            let late = ulid::Ulid::from_parts(4_600, 0).to_string();
            assert!(
                !db.summarise_unread(channel, Some(&late))
                    .await
                    .unwrap()
                    .attachments
            );

            // The count saturates rather than walking the whole tail.
            let deep = "01CHANUNREAD0000000000000003";
            for i in 0..(UNREAD_COUNT_CAP as u64 + 5) {
                db.insert_message(&mk(10_000 + i, 1, deep, false))
                    .await
                    .unwrap();
            }
            assert_eq!(
                db.summarise_unread(deep, None).await.unwrap().count,
                UNREAD_COUNT_CAP
            );
        });
    }
}
