use bson::{to_bson, Document};
use futures::try_join;
use futures::StreamExt;
use mongodb::options::FindOptions;
use revolt_models::v0::{MessageSort, UNREAD_COUNT_CAP};
use revolt_result::Result;
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;
use ulid::Ulid;

use crate::{
    AppendMessage, DocumentId, FieldsMessage, IntoDocumentPath, Message, MessageQuery,
    MessageTimePeriod, MongoDb, PartialMessage,
};

use super::{AbstractMessages, ThreadStats, UnreadSummary, UNREAD_SCAN_WINDOW};

static COL: &str = "messages";

/// The `fetch_thread_stats` aggregation, kept apart so a test can `explain()`
/// exactly what runs.
///
/// Only `channel` and `_id` survive the match, so the `channel_id_compound`
/// `{channel: 1, _id: 1}` index covers the whole pipeline: an IXSCAN with no
/// FETCH, however long the threads are. Reading any other field (`system`
/// included) would fetch every message of every thread on the page.
fn thread_stats_pipeline(channel_ids: &[String]) -> Vec<Document> {
    vec![
        doc! { "$match": { "channel": { "$in": channel_ids } } },
        doc! { "$project": { "channel": 1_i32, "_id": 1_i32 } },
        doc! { "$group": {
            "_id": "$channel",
            // The starter's id equals the thread id; every other message is a reply.
            "replies": { "$sum": { "$cond": [ { "$ne": [ "$_id", "$channel" ] }, 1_i32, 0_i32 ] } },
            // ULIDs sort by creation time, so the greatest id is the newest message.
            "last": { "$max": "$_id" },
        } },
    ]
}

#[async_trait]
impl AbstractMessages for MongoDb {
    /// Insert a new message into the database
    async fn insert_message(&self, message: &Message) -> Result<()> {
        query!(self, insert_one, COL, &message).map(|_| ())
    }

    /// Fetch a message by its id
    async fn fetch_message(&self, id: &str) -> Result<Message> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch multiple messages by given query
    async fn fetch_messages(&self, query: MessageQuery) -> Result<Vec<Message>> {
        let mut filter = doc! {};

        // 1. Apply message filters
        if let Some(channel) = query.filter.channel {
            filter.insert("channel", channel);
        }

        if let Some(author) = query.filter.author {
            filter.insert("author", author);
        }

        let is_search_query = if let Some(query) = query.filter.query {
            filter.insert(
                "$text",
                doc! {
                    "$search": query
                },
            );

            true
        } else {
            false
        };

        if let Some(pinned) = query.filter.pinned {
            filter.insert("pinned", pinned);
        };

        // 2. Find query limit
        let limit = query.limit.unwrap_or(50);

        // 3. Apply message time period
        match query.time_period {
            MessageTimePeriod::Relative { nearby } => {
                // 3.1. Prepare filters
                let mut older_message_filter = filter.clone();
                let mut newer_message_filter = filter;

                older_message_filter.insert(
                    "_id",
                    doc! {
                        "$lt": &nearby
                    },
                );

                newer_message_filter.insert(
                    "_id",
                    doc! {
                        "$gte": &nearby
                    },
                );

                // 3.2. Execute in both directions
                let (a, b) = try_join!(
                    self.find_with_options::<_, Message>(
                        COL,
                        newer_message_filter,
                        FindOptions::builder()
                            .limit(limit / 2 + 1)
                            .sort(doc! {
                                "_id": 1_i32
                            })
                            .build(),
                    ),
                    self.find_with_options::<_, Message>(
                        COL,
                        older_message_filter,
                        FindOptions::builder()
                            .limit(limit / 2 + 1)
                            .sort(doc! {
                                "_id": -1_i32
                            })
                            .build(),
                    )
                )
                .map_err(|_| create_database_error!("find", COL))?;

                Ok([a, b].concat())
            }
            MessageTimePeriod::Absolute {
                before,
                after,
                sort,
            } => {
                // 3.1. Apply message ID filter
                if let Some(doc) = match (before, after) {
                    (Some(before), Some(after)) => Some(doc! {
                        "$lt": before,
                        "$gt": after
                    }),
                    (Some(before), _) => Some(doc! {
                        "$lt": before
                    }),
                    (_, Some(after)) => Some(doc! {
                        "$gt": after
                    }),
                    _ => None,
                } {
                    filter.insert("_id", doc);
                }

                // 3.2. Execute with given message sort
                self.find_with_options(
                    COL,
                    filter,
                    FindOptions::builder()
                        .limit(limit)
                        .sort(match sort.unwrap_or(MessageSort::Latest) {
                            // Sort by relevance, fallback to latest
                            MessageSort::Relevance => {
                                if is_search_query {
                                    doc! {
                                        "score": {
                                            "$meta": "textScore"
                                        }
                                    }
                                } else {
                                    doc! {
                                        "_id": -1_i32
                                    }
                                }
                            }
                            // Sort by latest first
                            MessageSort::Latest => doc! {
                                "_id": -1_i32
                            },
                            // Sort by oldest first
                            MessageSort::Oldest => doc! {
                                "_id": 1_i32
                            },
                        })
                        .build(),
                )
                .await
                .map_err(|_| create_database_error!("find", COL))
            }
        }
    }

    /// Fetch multiple messages by given IDs
    async fn fetch_messages_by_id(&self, ids: &[String]) -> Result<Vec<Message>> {
        self.find_with_options(
            COL,
            doc! {
                "_id": {
                    "$in": ids
                }
            },
            None,
        )
        .await
        .map_err(|_| create_database_error!("find", COL))
    }

    /// Update a given message with new information
    async fn update_message(
        &self,
        id: &str,
        message: &PartialMessage,
        remove: Vec<FieldsMessage>,
    ) -> Result<()> {
        query!(
            self,
            update_one_by_id,
            COL,
            id,
            message,
            remove.iter().map(|x| x as &dyn IntoDocumentPath).collect(),
            None
        )
        .map(|_| ())
    }

    /// Append information to a given message
    async fn append_message(&self, id: &str, append: &AppendMessage) -> Result<()> {
        let mut query = doc! {};

        if let Some(embeds) = &append.embeds {
            if !embeds.is_empty() {
                query.insert(
                    "$push",
                    doc! {
                        "embeds": {
                            "$each": to_bson(embeds)
                                .map_err(|_| create_database_error!("to_bson", "embeds"))?
                        }
                    },
                );
            }
        }

        if query.is_empty() {
            return Ok(());
        }

        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id
                },
                query,
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL))
            // The message may have been deleted while its embeds were being fetched.
            .and_then(|result| {
                if result.matched_count == 0 {
                    Err(create_error!(NotFound))
                } else {
                    Ok(())
                }
            })
    }

    /// Count published (Crossposted-flagged) messages in a channel at/after
    /// `min_id`. `channel` + `_id` lead so only one hour of one channel is
    /// scanned before the bit filter applies.
    async fn count_crossposts_since(&self, channel: &str, min_id: &str) -> Result<usize> {
        let mask = 1_i64 << (revolt_models::v0::MessageFlags::Crossposted as i64);
        query!(
            self,
            count_documents,
            COL,
            doc! {
                "channel": channel,
                "_id": { "$gte": min_id },
                "flags": { "$bitsAllSet": mask }
            }
        )
        .map(|count| count as usize)
    }

    /// Summarise the unread tail of a channel.
    ///
    /// One aggregation, bounded twice: `channel` + `_id` lead the match so the
    /// sort is served straight off the index, the scan stops after
    /// `UNREAD_SCAN_WINDOW` messages, and the group only ever sees a cap's
    /// worth of the rest — a channel with 50k unread messages costs the same
    /// as one with a thousand.
    async fn summarise_unread(
        &self,
        channel: &str,
        after_id: Option<&str>,
        user: &str,
    ) -> Result<UnreadSummary> {
        let mut filter = doc! { "channel": channel };
        if let Some(after_id) = after_id {
            filter.insert("_id", doc! { "$gt": after_id });
        }

        let mut cursor = self
            .col::<Document>(COL)
            .aggregate(vec![
                doc! { "$match": filter },
                doc! { "$sort": { "_id": 1 } },
                doc! { "$limit": UNREAD_SCAN_WINDOW as i64 },
                // The reader's own messages are never unread to them.
                doc! { "$match": { "author": { "$ne": user } } },
                doc! { "$limit": UNREAD_COUNT_CAP as i64 },
                doc! { "$group": {
                    "_id": null,
                    "count": { "$sum": 1 },
                    "attachments": { "$max": {
                        "$cond": [
                            { "$gt": [ { "$size": { "$ifNull": [ "$attachments", [] ] } }, 0 ] },
                            1,
                            0
                        ]
                    } }
                } },
            ])
            .await
            .map_err(|_| create_database_error!("aggregate", COL))?;

        // Empty tail — the group stage emits nothing at all.
        let Some(doc) = cursor.next().await else {
            return Ok(UnreadSummary::default());
        };

        let doc = doc.map_err(|_| create_database_error!("aggregate", COL))?;

        // `$sum`/`$max` are Int32 at this scale, but read either width rather
        // than silently reporting zero if the server ever widens them.
        let int = |key: &str| {
            doc.get_i32(key)
                .map(i64::from)
                .or_else(|_| doc.get_i64(key))
                .unwrap_or_default()
        };

        Ok(UnreadSummary {
            count: int("count").clamp(0, UNREAD_COUNT_CAP as i64) as u32,
            attachments: int("attachments") > 0,
        })
    }

    /// Reply counts and newest message ids for the given threads
    ///
    /// One index-covered aggregation (see `thread_stats_pipeline`). System
    /// messages are deliberately NOT filtered out: telling them apart means
    /// reading `system`, which forces a document fetch and turns every forum
    /// page load into a scan of whole threads. They are rare in threads and
    /// count as activity (see [`ThreadStats`]).
    ///
    /// Returns one entry per distinct requested id, in first-seen order, like
    /// the reference driver; an id with no messages reports `0` / `None`.
    async fn fetch_thread_stats(&self, channel_ids: &[String]) -> Result<Vec<ThreadStats>> {
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

        if stats.is_empty() {
            return Ok(stats);
        }

        let mut cursor = self
            .col::<Document>(COL)
            .aggregate(thread_stats_pipeline(channel_ids))
            .await
            .map_err(|_| create_database_error!("aggregate", COL))?;

        // A thread with no messages emits no group at all; its entry keeps
        // the defaults. Anything malformed fails the call rather than
        // reporting a plausible-looking zero.
        while let Some(doc) = cursor.next().await {
            let doc = doc.map_err(|_| create_database_error!("aggregate", COL))?;

            let channel = doc
                .get_str("_id")
                .map_err(|_| create_database_error!("aggregate", COL))?;
            let Some(&slot) = slots.get(channel) else {
                continue;
            };

            // `$sum` is Int32 at any realistic size and widens to Int64 past
            // it; read either, then saturate into the u32.
            let replies = doc
                .get_i32("replies")
                .map(i64::from)
                .or_else(|_| doc.get_i64("replies"))
                .map_err(|_| create_database_error!("aggregate", COL))?;
            let last = doc
                .get_str("last")
                .map_err(|_| create_database_error!("aggregate", COL))?;

            stats[slot].replies = u32::try_from(replies.max(0)).unwrap_or(u32::MAX);
            stats[slot].last_message_id = Some(last.to_owned());
        }

        Ok(stats)
    }

    /// Add a new reaction to a message
    async fn add_reaction(&self, id: &str, emoji: &str, user: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id
                },
                doc! {
                    "$addToSet": {
                        format!("reactions.{emoji}"): user
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Remove a reaction from a message
    async fn remove_reaction(&self, id: &str, emoji: &str, user: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id
                },
                doc! {
                    "$pull": {
                        format!("reactions.{emoji}"): user
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Remove reaction from a message
    async fn clear_reaction(&self, id: &str, emoji: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id
                },
                doc! {
                    "$unset": {
                        format!("reactions.{emoji}"): 1
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Delete a message from the database by its id
    async fn delete_message(&self, id: &str) -> Result<()> {
        query!(self, delete_one_by_id, COL, id).map(|_| ())
    }

    /// Delete messages from a channel by their ids and corresponding channel id
    async fn delete_messages(&self, channel: &str, ids: &[String]) -> Result<()> {
        self.col::<Document>(COL)
            .delete_many(doc! {
                "channel": channel,
                "_id": {
                    "$in": ids
                }
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }

    /// Delete all messages from a specific author in a server from a certain ULID onwards
    async fn delete_messages_by_author_since(
        &self,
        channels: &[String],
        author: &str,
        since: SystemTime,
    ) -> Result<HashMap<String, Vec<String>>> {
        let threshold_ulid = Ulid::from_datetime(since).to_string();

        let filter = doc! {
            "author": author,
            "channel": { "$in": channels },
            "_id": { "$gte": &threshold_ulid }
        };

        let pipeline = vec![
            doc! { "$match": filter.clone() },
            doc! {
                "$project": {
                    "channel": 1_i32,
                    "message_id": "$_id",
                    "attachment_ids": {
                        "$map": {
                            "input": { "$ifNull": ["$attachments", Vec::<bson::Bson>::new()] },
                            "as": "a",
                            "in": "$$a._id"
                        }
                    }
                }
            },
            doc! {
                "$group": {
                    "_id": "$channel",
                    "message_ids": { "$push": "$message_id" },
                    "attachment_ids_nested": { "$push": "$attachment_ids" }
                }
            },
            doc! {
                "$project": {
                    "message_ids": 1_i32,
                    "attachment_ids": {
                        "$reduce": {
                            "input": "$attachment_ids_nested",
                            "initialValue": Vec::<bson::Bson>::new(),
                            "in": { "$setUnion": ["$$value", "$$this"] }
                        }
                    }
                }
            },
        ];

        #[derive(serde::Deserialize)]
        struct AggregatedChannel {
            #[serde(rename = "_id")]
            channel: String,
            message_ids: Vec<String>,
            #[serde(default)]
            attachment_ids: Vec<String>,
        }

        let mut cursor = self
            .col::<Document>(COL)
            .aggregate(pipeline)
            .await
            .map_err(|_| create_database_error!("aggregate", COL))?
            .with_type::<AggregatedChannel>();

        let mut deleted_messages: HashMap<String, Vec<String>> = HashMap::new();
        let mut attachment_ids: HashSet<String> = HashSet::new();

        // Drain the whole cursor before any write. A skipped row would still be deleted by
        // the `delete_many` below, with its attachments never marked and no event sent.
        while let Some(result) = cursor.next().await {
            let item = result.map_err(|_| create_database_error!("aggregate", COL))?;
            attachment_ids.extend(item.attachment_ids);
            deleted_messages.insert(item.channel, item.message_ids);
        }

        // Mark attachments as deleted before deleting messages
        if !attachment_ids.is_empty() {
            self.col::<Document>("attachments")
                .update_many(
                    doc! {
                        "_id": {
                            "$in": attachment_ids.into_iter().collect::<Vec<String>>()
                        }
                    },
                    doc! {
                        "$set": {
                            "deleted": true
                        }
                    },
                )
                .await
                .map_err(|_| create_database_error!("update_many", "attachments"))?;
        }

        self.col::<Document>(COL)
            .delete_many(filter)
            .await
            .map_err(|_| create_database_error!("delete_many", COL))?;

        Ok(deleted_messages)
    }

    async fn delete_messages_by_user(&self, user_id: &str) -> Result<()> {
        self.delete_bulk_messages(doc! {
            "author": user_id,
        })
        .await
    }

    async fn remove_message_attachment(&self, message_id: &str, file_id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": message_id
                },
                doc! {
                    // A large-attachment prune must strip the file from
                    // wherever it lives on the message: the ordinary
                    // `attachments` array OR a forwarded snapshot's own
                    // `forwarded.attachments` copies — otherwise the
                    // snapshot renders a 404 for a blob that's been
                    // S3-collected.
                    "$pull": {
                        "attachments": {
                            "_id": file_id
                        },
                        "forwarded.attachments": {
                            "_id": file_id
                        }
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }
}

impl IntoDocumentPath for FieldsMessage {
    fn as_path(&self) -> Option<&'static str> {
        Some(match self {
            FieldsMessage::Pinned => "pinned",
            FieldsMessage::Components => "components",
        })
    }
}

impl MongoDb {
    pub async fn delete_bulk_messages(&self, projection: Document) -> Result<()> {
        let mut for_attachments = projection.clone();
        for_attachments.insert(
            "attachments",
            doc! {
                "$exists": 1_i32
            },
        );

        // Check if there are any attachments we need to delete.
        let message_ids_with_attachments = self
            .find_with_options::<_, DocumentId>(
                COL,
                for_attachments,
                FindOptions::builder()
                    .projection(doc! { "_id": 1_i32 })
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_many", "attachments"))?
            .into_iter()
            .map(|x| x.id)
            .collect::<Vec<String>>();

        // If we found any, mark them as deleted.
        if !message_ids_with_attachments.is_empty() {
            self.col::<Document>("attachments")
                .update_many(
                    doc! {
                        "message_id": {
                            "$in": message_ids_with_attachments
                        }
                    },
                    doc! {
                        "$set": {
                            "deleted": true
                        }
                    },
                )
                .await
                .map_err(|_| create_database_error!("update_many", "attachments"))?;
        }

        // And then delete said messages.
        self.col::<Document>(COL)
            .delete_many(projection)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }
}

#[cfg(test)]
mod tests {
    use bson::{doc, Bson};

    use crate::{Message, SystemMessage, ThreadStats};

    use super::thread_stats_pipeline;

    const AUTHOR: &str = "01AUTHOR0000000000000000000";

    /// `rand` keeps ids unique when two messages share a millisecond.
    fn ulid(ms: u64, rand: u128) -> String {
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

    /// Exactly one entry per requested thread, wherever it sits in the result.
    fn entry<'a>(stats: &'a [ThreadStats], channel: &str) -> &'a ThreadStats {
        let found: Vec<&ThreadStats> = stats.iter().filter(|s| s.channel == channel).collect();
        assert_eq!(found.len(), 1, "one entry for {channel} in {stats:?}");
        found[0]
    }

    #[tokio::test]
    async fn thread_stats_count_replies_and_track_the_newest_message() {
        database_test!(|db| async move {
            // A post's starter shares the post's id.
            let starter_only = ulid(1_000, 1);
            db.insert_message(&message(&starter_only, &starter_only))
                .await
                .unwrap();

            let busy = ulid(1_000, 2);
            db.insert_message(&message(&busy, &busy)).await.unwrap();
            let replies = [ulid(2_000, 1), ulid(3_000, 1), ulid(4_000, 1)];
            for reply in &replies {
                db.insert_message(&message(reply, &busy)).await.unwrap();
            }

            // Newer than everything above, but in a channel nobody asked about.
            db.insert_message(&message(&ulid(9_000, 1), &ulid(1_000, 9)))
                .await
                .unwrap();

            let unknown = ulid(1_000, 3);

            assert!(db.fetch_thread_stats(&[]).await.unwrap().is_empty());

            // Two threads in one call, plus an id with no messages and a repeat.
            let stats = db
                .fetch_thread_stats(&[
                    starter_only.clone(),
                    busy.clone(),
                    unknown.clone(),
                    busy.clone(),
                ])
                .await
                .unwrap();
            assert_eq!(stats.len(), 3, "one entry per distinct id: {stats:?}");

            let only = entry(&stats, &starter_only);
            assert_eq!(only.replies, 0, "the starter is not a reply");
            assert_eq!(only.last_message_id.as_deref(), Some(starter_only.as_str()));

            let busy_stats = entry(&stats, &busy);
            assert_eq!(busy_stats.replies, 3);
            assert_eq!(
                busy_stats.last_message_id.as_deref(),
                Some(replies[2].as_str())
            );

            let missing = entry(&stats, &unknown);
            assert_eq!(missing.replies, 0);
            assert_eq!(missing.last_message_id, None);
        });
    }

    #[tokio::test]
    async fn thread_stats_follow_deletes_and_count_system_messages() {
        database_test!(|db| async move {
            let thread = ulid(1_000, 1);
            db.insert_message(&message(&thread, &thread)).await.unwrap();
            let replies = [ulid(2_000, 1), ulid(3_000, 1), ulid(4_000, 1)];
            for reply in &replies {
                db.insert_message(&message(reply, &thread)).await.unwrap();
            }

            let ids = [thread.clone()];
            let stats = db.fetch_thread_stats(&ids).await.unwrap();
            assert_eq!(stats[0].replies, 3);
            assert_eq!(
                stats[0].last_message_id.as_deref(),
                Some(replies[2].as_str())
            );

            // Deleting the newest reply falls back to the one before it.
            db.delete_message(&replies[2]).await.unwrap();
            let stats = db.fetch_thread_stats(&ids).await.unwrap();
            assert_eq!(stats[0].replies, 2);
            assert_eq!(
                stats[0].last_message_id.as_deref(),
                Some(replies[1].as_str())
            );

            // System messages count as activity, by design: filtering them
            // out would cost the index-covered query.
            let system = ulid(5_000, 1);
            db.insert_message(&Message {
                content: None,
                system: Some(SystemMessage::Text {
                    content: "pinned a message".to_string(),
                }),
                ..message(&system, &thread)
            })
            .await
            .unwrap();
            let stats = db.fetch_thread_stats(&ids).await.unwrap();
            assert_eq!(stats[0].replies, 3);
            assert_eq!(stats[0].last_message_id.as_deref(), Some(system.as_str()));

            // The starter was never counted, so losing it leaves the count alone.
            db.delete_message(&thread).await.unwrap();
            let stats = db.fetch_thread_stats(&ids).await.unwrap();
            assert_eq!(stats[0].replies, 3);
            assert_eq!(stats[0].last_message_id.as_deref(), Some(system.as_str()));
        });
    }

    /// Every `stage` (with its `indexName`) inside any `winningPlan`.
    fn winning_stages(value: &Bson, in_winner: bool, out: &mut Vec<(String, Option<String>)>) {
        match value {
            Bson::Document(doc) => {
                if in_winner {
                    if let Ok(stage) = doc.get_str("stage") {
                        let index = doc.get_str("indexName").ok().map(str::to_owned);
                        out.push((stage.to_owned(), index));
                    }
                }
                for (key, child) in doc {
                    winning_stages(child, in_winner || key == "winningPlan", out);
                }
            }
            Bson::Array(items) => {
                for item in items {
                    winning_stages(item, in_winner, out);
                }
            }
            _ => {}
        }
    }

    /// The stats query must stay covered by `channel_id_compound`: an index
    /// scan that never fetches a document. Mongo-only; a no-op under REFERENCE.
    #[tokio::test]
    async fn thread_stats_pipeline_is_covered_by_the_channel_id_index() {
        database_test!(|db| async move {
            let crate::Database::MongoDb(mongo) = &db else {
                return;
            };

            // `database_test!` hands over an un-migrated database. These two
            // MUST match the `messages` indexes in `init.rs`; the pinned one
            // also leads with `channel`, so the planner has a real choice.
            mongo
                .db()
                .run_command(doc! {
                    "createIndexes": "messages",
                    "indexes": [
                        { "key": { "channel": 1_i32, "_id": 1_i32 }, "name": "channel_id_compound" },
                        { "key": { "channel": 1_i32, "pinned": 1_i32 }, "name": "channel_pinned_compound" },
                    ]
                })
                .await
                .expect("failed to create messages indexes");

            let threads = [ulid(1_000, 1), ulid(1_000, 2)];
            for (n, thread) in threads.iter().enumerate() {
                db.insert_message(&message(thread, thread)).await.unwrap();
                for ms in 0..10_u64 {
                    db.insert_message(&message(&ulid(2_000 + ms, n as u128), thread))
                        .await
                        .unwrap();
                }
            }

            let explain = mongo
                .db()
                .run_command(doc! {
                    "explain": {
                        "aggregate": "messages",
                        "pipeline": thread_stats_pipeline(&threads),
                        "cursor": {},
                    },
                    "verbosity": "queryPlanner",
                })
                .await
                .expect("explain failed");

            let mut stages = Vec::new();
            winning_stages(&Bson::Document(explain.clone()), false, &mut stages);

            assert!(
                stages.iter().any(|(stage, index)| stage == "IXSCAN"
                    && index.as_deref() == Some("channel_id_compound")),
                "expected an IXSCAN on channel_id_compound: {stages:?}\n{explain:?}"
            );
            assert!(
                !stages
                    .iter()
                    .any(|(stage, _)| stage == "FETCH" || stage == "COLLSCAN"),
                "the stats query must not touch documents: {stages:?}\n{explain:?}"
            );
        });
    }
}
