use crate::{
    AppendMessage, FieldsMessage, Message, MessageQuery, MessageTimePeriod, PartialMessage,
    ReferenceDb,
};
use indexmap::IndexSet;
use revolt_models::v0::{MessageSort, UNREAD_COUNT_CAP};
use revolt_result::Result;
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;
use ulid::Ulid;

use super::{AbstractMessages, ThreadStats, UnreadSummary, UNREAD_SCAN_WINDOW};

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
    ///
    /// Ids with no message are skipped instead of failing the whole call, and
    /// a repeated id yields its message once, matching the MongoDB driver's
    /// `$in` query. Results come back in request order; callers must not rely
    /// on any order, since the MongoDB driver guarantees none. The map lookup
    /// cannot fail, so there is no error to propagate.
    async fn fetch_messages_by_id(&self, ids: &[String]) -> Result<Vec<Message>> {
        let messages = self.messages.lock().await;
        let mut seen = HashSet::with_capacity(ids.len());
        Ok(ids
            .iter()
            .filter(|id| seen.insert(id.as_str()))
            .filter_map(|id| messages.get(id).cloned())
            .collect())
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

    /// Count published (Crossposted-flagged) messages in a channel at/after
    /// `min_id`.
    async fn count_crossposts_since(&self, channel: &str, min_id: &str) -> Result<usize> {
        let mask = 1_u32 << (revolt_models::v0::MessageFlags::Crossposted as u32);
        let messages = self.messages.lock().await;
        Ok(messages
            .values()
            .filter(|message| {
                message.channel == channel
                    && message.id.as_str() >= min_id
                    && message.flags.is_some_and(|flags| flags & mask == mask)
            })
            .count())
    }

    /// Summarise the unread tail of a channel.
    async fn summarise_unread(
        &self,
        channel: &str,
        after_id: Option<&str>,
        user: &str,
    ) -> Result<UnreadSummary> {
        let messages = self.messages.lock().await;
        let mut tail = messages
            .values()
            .filter(|message| {
                message.channel == channel
                    && after_id.is_none_or(|after_id| message.id.as_str() > after_id)
            })
            .collect::<Vec<_>>();

        // ULIDs sort lexicographically by creation time, so this is the same
        // window Mongo's `$sort` + `$limit` sees: bound the scan first, then
        // drop the reader's own messages, then cap what is left.
        tail.sort_by(|a, b| a.id.cmp(&b.id));
        tail.truncate(UNREAD_SCAN_WINDOW as usize);
        tail.retain(|message| message.author != user);
        tail.truncate(UNREAD_COUNT_CAP as usize);

        Ok(UnreadSummary {
            count: tail.len() as u32,
            attachments: tail
                .iter()
                .any(|message| message.attachments.as_ref().is_some_and(|a| !a.is_empty())),
        })
    }

    /// Reply counts and newest message ids for the given threads
    async fn fetch_thread_stats(&self, channel_ids: &[String]) -> Result<Vec<ThreadStats>> {
        // One entry per distinct requested id, so a thread with no messages
        // still reports `0` / `None`. A repeated id collapses into one entry,
        // as it does under the MongoDB driver's `$group`.
        let mut stats: Vec<ThreadStats> = Vec::with_capacity(channel_ids.len());
        let mut slots: HashMap<&str, usize> = HashMap::with_capacity(channel_ids.len());
        for id in channel_ids {
            if !slots.contains_key(id.as_str()) {
                slots.insert(id.as_str(), stats.len());
                stats.push(ThreadStats {
                    channel: id.clone(),
                    ..Default::default()
                });
            }
        }

        // System messages are NOT excluded, in parity with the index-covered
        // MongoDB aggregation (see `ThreadStats`). The starter is the message
        // whose id equals the thread id: it is not a reply, but it is still a
        // candidate for the newest message.
        let messages = self.messages.lock().await;
        for message in messages.values() {
            let Some(&slot) = slots.get(message.channel.as_str()) else {
                continue;
            };
            let entry = &mut stats[slot];
            if message.id != message.channel {
                entry.replies = entry.replies.saturating_add(1);
            }
            if entry
                .last_message_id
                .as_ref()
                .is_none_or(|last| &message.id > last)
            {
                entry.last_message_id = Some(message.id.clone());
            }
        }

        Ok(stats)
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
            .retain(|id, message| message.channel != channel || !ids.contains(id));

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

/// Reference-driver legs of `fetch_thread_stats` and the missing-id
/// tolerance of `fetch_messages_by_id`.
///
/// These call the real methods on a `ReferenceDb`, so they run without any
/// database. The MongoDB driver's cases live in its own lane
/// (`messages/ops/mongodb.rs`) and need `TEST_DB=MONGODB`.
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{AbstractMessages, ThreadStats};
    use crate::{Message, ReferenceDb, SystemMessage};

    const AUTHOR: &str = "01AUTHOR00000000000000000000";

    fn id(ms: u64, rand: u128) -> String {
        ulid::Ulid::from_parts(ms, rand).to_string()
    }

    fn message(id: &str, channel: &str) -> Message {
        Message {
            id: id.to_string(),
            channel: channel.to_string(),
            author: AUTHOR.to_string(),
            content: Some("hello".to_string()),
            ..Default::default()
        }
    }

    /// A thread whose starter's id equals the thread id, plus one reply per
    /// entry of `reply_ms`. Returns the thread id and the reply ids.
    async fn thread(
        db: &ReferenceDb,
        ms: u64,
        rand: u128,
        reply_ms: &[u64],
    ) -> (String, Vec<String>) {
        let thread = id(ms, rand);
        db.insert_message(&message(&thread, &thread)).await.unwrap();
        let mut replies = Vec::new();
        for &reply in reply_ms {
            let reply = id(reply, rand);
            db.insert_message(&message(&reply, &thread)).await.unwrap();
            replies.push(reply);
        }
        (thread, replies)
    }

    async fn stats(db: &ReferenceDb, ids: &[&String]) -> HashMap<String, ThreadStats> {
        let ids: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        let stats = db.fetch_thread_stats(&ids).await.unwrap();
        let by_channel: HashMap<String, ThreadStats> = stats
            .iter()
            .map(|entry| (entry.channel.clone(), entry.clone()))
            .collect();
        assert_eq!(by_channel.len(), stats.len(), "one entry per channel");
        by_channel
    }

    #[tokio::test]
    async fn thread_stats_starter_only_has_no_replies() {
        let db = ReferenceDb::default();
        let (post, _) = thread(&db, 1_000, 1, &[]).await;

        let stats = stats(&db, &[&post]).await;
        assert_eq!(
            stats[&post],
            ThreadStats {
                channel: post.clone(),
                replies: 0,
                last_message_id: Some(post.clone()),
            }
        );
    }

    #[tokio::test]
    async fn thread_stats_count_replies_and_track_the_newest() {
        let db = ReferenceDb::default();
        let (post, replies) = thread(&db, 1_000, 1, &[2_000, 4_000, 3_000]).await;
        // Traffic in another channel must not leak in.
        db.insert_message(&message(&id(9_000, 7), &id(500, 7)))
            .await
            .unwrap();

        let stats = stats(&db, &[&post]).await;
        assert_eq!(stats[&post].replies, 3);
        assert_eq!(stats[&post].last_message_id.as_ref(), Some(&replies[1]));
    }

    #[tokio::test]
    async fn thread_stats_fall_back_when_the_newest_reply_is_deleted() {
        let db = ReferenceDb::default();
        let (post, replies) = thread(&db, 1_000, 1, &[2_000, 3_000, 4_000]).await;
        db.delete_message(&replies[2]).await.unwrap();

        let stats = stats(&db, &[&post]).await;
        assert_eq!(stats[&post].replies, 2);
        assert_eq!(stats[&post].last_message_id.as_ref(), Some(&replies[1]));

        // With every reply gone the starter is the newest message again.
        db.delete_message(&replies[0]).await.unwrap();
        db.delete_message(&replies[1]).await.unwrap();
        let stats = self::stats(&db, &[&post]).await;
        assert_eq!(stats[&post].replies, 0);
        assert_eq!(stats[&post].last_message_id.as_ref(), Some(&post));
    }

    #[tokio::test]
    async fn thread_stats_report_unknown_and_repeated_ids() {
        let db = ReferenceDb::default();
        let (post, _) = thread(&db, 1_000, 1, &[2_000]).await;
        let unknown = id(5_000, 5);

        let raw = db
            .fetch_thread_stats(&[unknown.clone(), post.clone(), unknown.clone()])
            .await
            .unwrap();
        assert_eq!(raw.len(), 2, "a repeated id yields one entry");

        let stats = stats(&db, &[&unknown, &post]).await;
        assert_eq!(
            stats[&unknown],
            ThreadStats {
                channel: unknown.clone(),
                replies: 0,
                last_message_id: None,
            }
        );
        assert_eq!(stats[&post].replies, 1);

        assert!(db.fetch_thread_stats(&[]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn thread_stats_cover_two_threads_at_once() {
        let db = ReferenceDb::default();
        let (first, first_replies) = thread(&db, 1_000, 1, &[2_000, 3_000]).await;
        let (second, second_replies) = thread(&db, 1_500, 2, &[2_500]).await;

        let stats = stats(&db, &[&first, &second]).await;
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[&first].replies, 2);
        assert_eq!(
            stats[&first].last_message_id.as_ref(),
            Some(&first_replies[1])
        );
        assert_eq!(stats[&second].replies, 1);
        assert_eq!(
            stats[&second].last_message_id.as_ref(),
            Some(&second_replies[0])
        );
    }

    /// Parity with the index-covered MongoDB aggregation: system messages
    /// count as replies and can be the newest message.
    #[tokio::test]
    async fn thread_stats_count_system_messages() {
        let db = ReferenceDb::default();
        let (post, _) = thread(&db, 1_000, 1, &[2_000]).await;
        let system = id(3_000, 1);
        db.insert_message(&Message {
            system: Some(SystemMessage::Text {
                content: "renamed".to_string(),
            }),
            content: None,
            ..message(&system, &post)
        })
        .await
        .unwrap();

        let stats = stats(&db, &[&post]).await;
        assert_eq!(stats[&post].replies, 2);
        assert_eq!(stats[&post].last_message_id.as_ref(), Some(&system));
    }

    #[tokio::test]
    async fn fetch_messages_by_id_skips_dangling_ids() {
        let db = ReferenceDb::default();
        let (post, replies) = thread(&db, 1_000, 1, &[2_000]).await;
        let dangling = id(9_000, 9);

        let fetched = db
            .fetch_messages_by_id(&[
                post.clone(),
                dangling.clone(),
                replies[0].clone(),
                post.clone(),
            ])
            .await
            .expect("a dangling id must not fail the whole call");
        let mut ids: Vec<String> = fetched.into_iter().map(|message| message.id).collect();
        ids.sort();
        assert_eq!(ids, vec![post.clone(), replies[0].clone()]);

        // Only dangling ids, or none at all: an empty list, not an error.
        assert!(db
            .fetch_messages_by_id(std::slice::from_ref(&dangling))
            .await
            .unwrap()
            .is_empty());
        assert!(db.fetch_messages_by_id(&[]).await.unwrap().is_empty());
    }

    /// Bulk delete removes only the listed ids inside the given channel, in
    /// parity with the MongoDB driver's `{ channel, _id: { $in: ids } }`.
    #[tokio::test]
    async fn delete_messages_removes_only_listed_ids_in_the_channel() {
        let db = ReferenceDb::default();
        let channel = id(500, 1);
        let other_channel = id(600, 2);
        let first = id(1_000, 1);
        let second = id(2_000, 1);
        let survivor = id(3_000, 1);
        let elsewhere = id(4_000, 2);
        for message_id in [&first, &second, &survivor] {
            db.insert_message(&message(message_id, &channel))
                .await
                .unwrap();
        }
        db.insert_message(&message(&elsewhere, &other_channel))
            .await
            .unwrap();

        // `elsewhere` is listed but lives in another channel, so it must stay.
        db.delete_messages(
            &channel,
            &[first.clone(), second.clone(), elsewhere.clone()],
        )
        .await
        .unwrap();

        assert!(db.fetch_message(&first).await.is_err());
        assert!(db.fetch_message(&second).await.is_err());
        assert_eq!(db.fetch_message(&survivor).await.unwrap().id, survivor);
        assert_eq!(db.fetch_message(&elsewhere).await.unwrap().id, elsewhere);
    }
}
