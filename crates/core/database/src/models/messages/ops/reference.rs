use crate::{
    AppendMessage, FieldsMessage, Message, MessageQuery, MessageTimePeriod, PartialMessage,
    ReferenceDb,
};
use futures::future::try_join_all;
use revolt_models::v0::MessageSort;
use indexmap::IndexSet;
use revolt_result::Result;
use std::collections::HashMap;
use std::time::SystemTime;
use ulid::Ulid;

use super::AbstractMessages;

#[async_trait]
impl AbstractMessages for ReferenceDb {
    /// Insert a new message into the database
    async fn insert_message(&self, message: &Message) -> Result<()> {
        let mut messages = self.messages.lock().await;
        if messages.contains_key(&message.id) {
            Err(create_database_error!("insert", "message"))
        } else {
            messages.insert(message.id.to_string(), message.clone());
            Ok(())
        }
    }

    /// Remove a single attachment (by file id) from a message's embedded attachment list.
    async fn remove_message_attachment(&self, message_id: &str, file_id: &str) -> Result<()> {
        let mut messages = self.messages.lock().await;
        if let Some(message) = messages.get_mut(message_id) {
            if let Some(attachments) = &mut message.attachments {
                attachments.retain(|attachment| attachment.id != file_id);
            }
        }
        // Idempotent: a missing message/attachment is treated as success.
        Ok(())
    }

    /// Fetch a message by its id
    async fn fetch_message(&self, id: &str) -> Result<Message> {
        let messages = self.messages.lock().await;
        messages
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch multiple messages by given query
    async fn fetch_messages(&self, query: MessageQuery) -> Result<Vec<Message>> {
        let messages = self.messages.lock().await;
        let mut matched_messages: Vec<Message> = messages
            .values()
            .filter(|message| {
                if let Some(channel) = &query.filter.channel {
                    if &message.channel != channel {
                        return false;
                    }
                }

                if let Some(author) = &query.filter.author {
                    if &message.author != author {
                        return false;
                    }
                }

                if let Some(query) = &query.filter.query {
                    if let Some(content) = &message.content {
                        if !content.to_lowercase().contains(query) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }

                if let Some(pinned) = query.filter.pinned {
                    if message.pinned.unwrap_or_default() == pinned {
                        return false;
                    }
                }

                true
            })
            .cloned()
            .collect();

        // Ulid message ids are lexicographically chronological, so all ordering and
        // cursor comparisons below work on the id string, matching the Mongo `_id`
        // semantics (messages/ops/mongodb.rs).
        let limit = query.limit.unwrap_or(50).max(0) as usize;

        match query.time_period {
            // FIXME: `Relative { nearby }` is still unsorted/unlimited (no test depends
            // on it under REFERENCE yet). `Absolute` was completed in slice F so the
            // legacy-import pagination tests exercise real before/limit semantics.
            MessageTimePeriod::Relative { .. } => Ok(matched_messages),
            MessageTimePeriod::Absolute {
                before,
                after,
                sort,
            } => {
                if let Some(before) = &before {
                    matched_messages.retain(|m| &m.id < before);
                }
                if let Some(after) = &after {
                    matched_messages.retain(|m| &m.id > after);
                }
                match sort.unwrap_or(MessageSort::Latest) {
                    MessageSort::Oldest => matched_messages.sort_by(|a, b| a.id.cmp(&b.id)),
                    // Relevance falls back to latest-first, as in the Mongo driver
                    // when no text score is available.
                    MessageSort::Latest | MessageSort::Relevance => {
                        matched_messages.sort_by(|a, b| b.id.cmp(&a.id))
                    }
                }
                matched_messages.truncate(limit);
                Ok(matched_messages)
            }
        }

    }

    /// Fetch multiple messages by given IDs
    async fn fetch_messages_by_id(&self, ids: &[String]) -> Result<Vec<Message>> {
        try_join_all(ids.iter().map(|id| self.fetch_message(id))).await
    }

    /// Update a given message with new information
    async fn update_message(
        &self,
        id: &str,
        message: &PartialMessage,
        remove: Vec<FieldsMessage>,
    ) -> Result<()> {
        let mut messages = self.messages.lock().await;
        if let Some(message_data) = messages.get_mut(id) {
            message_data.apply_options(message.to_owned());

            for field in remove {
                #[allow(clippy::disallowed_methods)]
                message_data.remove_field(&field);
            }
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Append information to a given message
    async fn append_message(&self, id: &str, append: &AppendMessage) -> Result<()> {
        let mut messages = self.messages.lock().await;
        if let Some(message_data) = messages.get_mut(id) {
            if let Some(embeds) = &append.embeds {
                if !embeds.is_empty() {
                    if let Some(embeds_data) = &mut message_data.embeds {
                        embeds_data.extend(embeds.clone());
                    } else {
                        message_data.embeds = Some(embeds.clone());
                    }
                }
            }

            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Add a new reaction to a message
    async fn add_reaction(&self, id: &str, emoji: &str, user: &str) -> Result<()> {
        let mut messages = self.messages.lock().await;
        if let Some(message) = messages.get_mut(id) {
            if let Some(users) = message.reactions.get_mut(emoji) {
                users.insert(user.to_string());
            } else {
                message
                    .reactions
                    .insert(emoji.to_string(), IndexSet::from([user.to_string()]));
            }

            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Remove a reaction from a message
    async fn remove_reaction(&self, id: &str, emoji: &str, user: &str) -> Result<()> {
        let mut messages = self.messages.lock().await;
        if let Some(message) = messages.get_mut(id) {
            if let Some(users) = message.reactions.get_mut(emoji) {
                users.swap_remove(&user.to_string());
            }

            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Remove reaction from a message
    async fn clear_reaction(&self, id: &str, emoji: &str) -> Result<()> {
        let mut messages = self.messages.lock().await;
        if let Some(message) = messages.get_mut(id) {
            message.reactions.swap_remove(emoji);
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Delete a message from the database by its id
    async fn delete_message(&self, id: &str) -> Result<()> {
        let mut messages = self.messages.lock().await;
        if messages.remove(id).is_some() {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Delete messages from a channel by their ids and corresponding channel id
    async fn delete_messages(&self, channel: &str, ids: &[String]) -> Result<()> {
        self.messages
            .lock()
            .await
            .retain(|id, message| message.channel != channel && !ids.contains(id));

        Ok(())
    }

    /// Delete all messages from a specific author in a list of channels from a certain ULID onwards
    async fn delete_messages_by_author_since(
        &self,
        channels: &[String],
        author: &str,
        since: SystemTime,
    ) -> Result<HashMap<String, Vec<String>>> {
        let threshold_ulid = Ulid::from_datetime(since).to_string();
        let mut deleted_messages: HashMap<String, Vec<String>> = HashMap::new();
        let mut attachment_ids: Vec<String> = Vec::new();

        let messages = self.messages.lock().await;

        // First pass: collect attachment IDs and message IDs to delete
        for (id, message) in messages.iter() {
            let should_delete = message.author == author
                && channels.contains(&message.channel)
                && id.as_str() >= threshold_ulid.as_str();

            if should_delete {
                // Collect attachment IDs
                if let Some(attachments) = &message.attachments {
                    for attachment in attachments {
                        attachment_ids.push(attachment.id.clone());
                    }
                }

                deleted_messages
                    .entry(message.channel.clone())
                    .or_default()
                    .push(id.clone());
            }
        }
        drop(messages);

        // Mark attachments as deleted
        if !attachment_ids.is_empty() {
            let mut files = self.files.lock().await;
            for attachment_id in attachment_ids {
                if let Some(file) = files.get_mut(&attachment_id) {
                    file.deleted = Some(true);
                }
            }
        }

        // Delete the messages
        self.messages.lock().await.retain(|id, message| {
            let should_keep = !(message.author == author
                && channels.contains(&message.channel)
                && id.as_str() >= threshold_ulid.as_str());
            should_keep
        });

        Ok(deleted_messages)
    }

    async fn delete_messages_by_user(&self, user_id: &str) -> Result<()> {
        let mut messages = self.messages.lock().await;

        messages.retain(|_, message| message.author != user_id);

        // TODO: remove attachments as well

        Ok(())
    }
}
