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

use super::{AbstractMessages, UnreadSummary};

static COL: &str = "messages";

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
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
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
    /// One aggregation, bounded by `$limit`: `channel` + `_id` lead the match so
    /// the sort is served straight off the index, and the group only ever sees a
    /// cap's worth of documents — a channel with 50k unread messages costs the
    /// same as one with 100.
    async fn summarise_unread(
        &self,
        channel: &str,
        after_id: Option<&str>,
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

        while let Some(result) = cursor.next().await {
            if let Ok(item) = result {
                for id in item.attachment_ids {
                    attachment_ids.insert(id);
                }
                deleted_messages.insert(item.channel, item.message_ids);
            }
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
        }).await
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
