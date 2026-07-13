use std::collections::HashMap;
use std::time::SystemTime;
use revolt_result::Result;

use crate::{AppendMessage, FieldsMessage, Message, MessageQuery, PartialMessage};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

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
}
