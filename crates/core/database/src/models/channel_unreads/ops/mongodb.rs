use std::collections::{BTreeSet, HashSet};

use bson::Document;
use futures::TryStreamExt;
use mongodb::options::FindOneAndUpdateOptions;
use mongodb::options::ReadPreference;
use mongodb::options::ReturnDocument;
use mongodb::options::SelectionCriteria;
use mongodb::options::UpdateOptions;
use revolt_result::Result;
use ulid::Ulid;

use crate::ChannelUnread;
use crate::MongoDb;

use super::AbstractChannelUnreads;

static COL: &str = "channel_unreads";
static CHANNELS: &str = "channels";

impl MongoDb {
    /// Delete every unread row for a channel if the channel no longer exists.
    /// Returns true if the channel is gone.
    ///
    /// This runs after the unread write, not before. `delete_channel` purges
    /// unreads, removes the channel doc, then purges again. If this check sees
    /// the channel, our acknowledged write came before the channel doc was
    /// removed, so the second purge removes the row. If it does not, the purge
    /// here removes it. A check before the write could pass and then have the
    /// write land after both purges.
    ///
    /// The read is pinned to the primary because the argument needs the
    /// primary's view of both our write and the channel delete.
    async fn discard_unreads_if_channel_gone(&self, channel_id: &str) -> Result<bool> {
        let exists = self
            .col::<Document>(CHANNELS)
            .find_one(doc! { "_id": channel_id })
            .projection(doc! { "_id": 1_i32 })
            .selection_criteria(SelectionCriteria::ReadPreference(ReadPreference::Primary))
            .await
            .map_err(|_| create_database_error!("find_one", CHANNELS))?
            .is_some();

        if exists {
            return Ok(false);
        }

        self.col::<Document>(COL)
            .delete_many(doc! { "_id.channel": channel_id })
            .await
            .map_err(|_| create_database_error!("delete_many", COL))?;

        warn!("Channel {channel_id} is gone; discarded its unread rows");
        Ok(true)
    }
}

#[async_trait]
impl AbstractChannelUnreads for MongoDb {
    /// Acknowledge a message, and returns updated channel unread.
    async fn acknowledge_message(
        &self,
        channel_id: &str,
        user_id: &str,
        message_id: &str,
    ) -> Result<Option<ChannelUnread>> {
        let unread = self
            .col::<ChannelUnread>(COL)
            .find_one_and_update(
                doc! {
                    "_id.channel": channel_id,
                    "_id.user": user_id,
                },
                doc! {
                    "$pull": {
                        "mentions": {
                            "$lte": message_id
                        }
                    },
                    "$set": {
                        "last_id": message_id
                    }
                },
            )
            .with_options(
                FindOneAndUpdateOptions::builder()
                    .upsert(true)
                    .return_document(ReturnDocument::After)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL))?;

        if self.discard_unreads_if_channel_gone(channel_id).await? {
            return Ok(None);
        }

        Ok(unread)
    }

    /// Acknowledge many channels.
    async fn acknowledge_channels(&self, user_id: &str, channel_ids: &[String]) -> Result<()> {
        // Nothing to acknowledge; `insert_many` rejects an empty list.
        if channel_ids.is_empty() {
            return Ok(());
        }

        let current_time = Ulid::new().to_string();

        self.col::<Document>(COL)
            .delete_many(doc! {
                "_id.channel": {
                    "$in": channel_ids
                },
                "_id.user": user_id
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL))?;

        self.col::<Document>(COL)
            .insert_many(
                channel_ids
                    .iter()
                    .map(|channel_id| {
                        doc! {
                            "_id": {
                                "channel": channel_id,
                                "user": user_id
                            },
                            "last_id": &current_time
                        }
                    })
                    .collect::<Vec<Document>>(),
            )
            .await
            .map_err(|_| create_database_error!("update_many", COL))?;

        // Same post-write check as `discard_unreads_if_channel_gone`, batched
        // into one lookup and one purge.
        let present: HashSet<String> = self
            .col::<Document>(CHANNELS)
            .find(doc! { "_id": { "$in": channel_ids } })
            .projection(doc! { "_id": 1_i32 })
            .selection_criteria(SelectionCriteria::ReadPreference(ReadPreference::Primary))
            .await
            .map_err(|_| create_database_error!("find", CHANNELS))?
            .try_collect::<Vec<Document>>()
            .await
            .map_err(|_| create_database_error!("find", CHANNELS))?
            .into_iter()
            .filter_map(|channel| channel.get_str("_id").ok().map(str::to_owned))
            .collect();

        let missing: BTreeSet<&str> = channel_ids
            .iter()
            .map(String::as_str)
            .filter(|id| !present.contains(*id))
            .collect();

        if missing.is_empty() {
            return Ok(());
        }

        self.col::<Document>(COL)
            .delete_many(doc! {
                "_id.channel": {
                    "$in": missing.iter().copied().collect::<Vec<&str>>()
                }
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL))?;

        for id in missing {
            warn!("Channel {id} is gone; discarded its unread rows");
        }

        Ok(())
    }

    /// Add a mention.
    async fn add_mention_to_unread<'a>(
        &self,
        channel_id: &str,
        user_id: &str,
        message_ids: &[String],
    ) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id.channel": channel_id,
                    "_id.user": user_id,
                },
                doc! {
                    "$push": {
                        "mentions": {
                            "$each": message_ids
                        }
                    }
                },
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await
            .map_err(|_| create_database_error!("update_one", COL))?;

        self.discard_unreads_if_channel_gone(channel_id).await?;
        Ok(())
    }

    /// Add a mention to multiple users.
    async fn add_mention_to_many_unreads<'a>(
        &self,
        channel_id: &str,
        user_ids: &[String],
        message_ids: &[String],
    ) -> Result<()> {
        self.col::<Document>(COL)
            .update_many(
                doc! {
                    "_id.channel": channel_id,
                    "_id.user": {
                        "$in": user_ids
                    },
                },
                doc! {
                    "$push": {
                        "mentions": {
                            "$each": message_ids
                        }
                    }
                },
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await
            .map_err(|_| create_database_error!("update_many", COL))?;

        self.discard_unreads_if_channel_gone(channel_id).await?;
        Ok(())
    }

    /// Fetch all channel unreads for a user.
    async fn fetch_unreads(&self, user_id: &str) -> Result<Vec<ChannelUnread>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "_id.user": user_id
            }
        )
    }

    async fn fetch_unread_mentions(&self, user_id: &str) -> Result<Vec<ChannelUnread>> {
        query! {
            self,
            find,
            COL,
            doc! {
                "_id.user": user_id,
                "mentions": {"$ne": null}
            }
        }
    }

    /// Fetch unread for a specific user in a channel.
    async fn fetch_unread(&self, user_id: &str, channel_id: &str) -> Result<Option<ChannelUnread>> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "_id.user": user_id,
                "_id.channel": channel_id
            }
        )
    }
}
