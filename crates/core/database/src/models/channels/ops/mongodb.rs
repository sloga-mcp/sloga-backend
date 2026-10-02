use super::AbstractChannels;
use crate::{AbstractServers, Channel, FieldsChannel, IntoDocumentPath, MongoDb, PartialChannel, util::ChunkedDatabaseGenerator};
use bson::{Bson, Document};
use futures::{StreamExt, TryStreamExt};
use mongodb::options::ReadConcern;
use revolt_permissions::OverrideField;
use revolt_result::Result;

static COL: &str = "channels";

#[async_trait]
impl AbstractChannels for MongoDb {
    /// Insert a new channel in the database
    async fn insert_channel(&self, channel: &Channel) -> Result<()> {
        query!(self, insert_one, COL, &channel).map(|_| ())
    }

    /// Fetch a channel from the database
    async fn fetch_channel(&self, channel_id: &str) -> Result<Channel> {
        query!(self, find_one_by_id, COL, channel_id)?.ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch all channels from the database
    async fn fetch_channels<'a>(&self, ids: &'a [String]) -> Result<Vec<Channel>> {
        Ok(self
            .col::<Channel>(COL)
            .find(doc! {
                "_id": {
                    "$in": ids
                }
            })
            .await
            .map_err(|_| create_database_error!("fetch", "channels"))?
            .filter_map(|s| async {
                if cfg!(debug_assertions) {
                    Some(s.unwrap())
                } else {
                    s.ok()
                }
            })
            .collect()
            .await)
    }

    /// Fetch all threads hanging off a given parent channel
    async fn fetch_threads_by_parent(&self, parent_id: &str) -> Result<Vec<Channel>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "channel_type": "Thread",
                "parent_channel": parent_id
            }
        )
    }

    /// Fetch the ids of every thread (incl. forum posts, archived and locked ones) whose parent is in `parent_ids`
    async fn fetch_thread_ids_by_parents(&self, parent_ids: &[String]) -> Result<Vec<String>> {
        if parent_ids.is_empty() {
            return Ok(vec![]);
        }

        #[derive(serde::Deserialize)]
        struct ThreadId {
            #[serde(rename = "_id")]
            id: String,
        }

        // A cursor or decode error fails the whole lookup: callers purge by these
        // ids, and a silently short list would leave a partial purge reported as done.
        Ok(self
            .col::<ThreadId>(COL)
            .find(doc! {
                "channel_type": "Thread",
                "parent_channel": { "$in": parent_ids }
            })
            .projection(doc! { "_id": 1_i32 })
            .await
            .map_err(|_| create_database_error!("find", "channels"))?
            .try_collect::<Vec<ThreadId>>()
            .await
            .map_err(|_| create_database_error!("find", "channels"))?
            .into_iter()
            .map(|thread| thread.id)
            .collect())
    }

    /// Fetch every non-archived thread (used by the auto-archive daemon)
    async fn fetch_active_threads(&self) -> Result<Vec<Channel>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "channel_type": "Thread",
                "archived": { "$ne": true },
                // Skip "Never" threads; legacy docs lacking the field still match (default 1440)
                "auto_archive_minutes": { "$ne": Channel::AUTO_ARCHIVE_NEVER as i64 }
            }
        )
    }

    /// Fetch all direct messages for a user
    async fn find_direct_messages(&self, user_id: &str) -> Result<Vec<Channel>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "$or": [
                    {
                        "$or": [
                            {
                                "channel_type": "DirectMessage"
                            },
                            {
                                "channel_type": "Group"
                            }
                        ],
                        "recipients": user_id
                    },
                    {
                        "channel_type": "SavedMessages",
                        "user": user_id
                    }
                ]
            }
        )
    }

    // Fetch all group dms for a user
    async fn find_group_message_channels(&self, user_id: &str) -> Result<ChunkedDatabaseGenerator<Channel>> {
        let mut session = self
            .start_session()
            .await
            .map_err(|_| create_database_error!("start_session", COL))?;

        session
            .start_transaction()
            .read_concern(ReadConcern::snapshot())
            .await
            .map_err(|_| create_database_error!("start_transaction", COL))?;

        let cursor = self.col(COL)
            .find(doc! {
                "channel_type": "Group",
                "recipients": user_id
            })
            .session(&mut session)
            .batch_size(100)
            .await
            .map_err(|_| create_database_error!("find", COL))?;

        Ok(ChunkedDatabaseGenerator::new_mongo(session, cursor))
    }

    // Fetch saved messages channel
    async fn find_saved_messages_channel(&self, user_id: &str) -> Result<Channel> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "channel_type": "SavedMessages",
                "user": user_id
            }
        )?
        .ok_or_else(|| create_error!(InternalError))
    }

    // Fetch direct message channel (DM or Saved Messages)
    async fn find_direct_message_channel(&self, user_a: &str, user_b: &str) -> Result<Channel> {
        let doc = match (user_a, user_b) {
            self_user if self_user.0 == self_user.1 => {
                doc! {
                    "channel_type": "SavedMessages",
                    "user": self_user.0
                }
            }
            users => {
                doc! {
                    "channel_type": "DirectMessage",
                    "recipients": {
                        "$all": [ users.0, users.1 ]
                    }
                }
            }
        };
        query!(self, find_one, COL, doc)?.ok_or_else(|| create_error!(NotFound))
    }

    /// Insert a user to a group
    async fn add_user_to_group(&self, channel: &str, user: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": channel
                },
                doc! {
                    "$push": {
                        "recipients": user
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", "channel"))
    }

    /// Insert channel role permissions
    async fn set_channel_role_permission(
        &self,
        channel: &str,
        role: &str,
        permissions: OverrideField,
    ) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! { "_id": channel },
                doc! {
                "$set": {
                    "role_permissions.".to_owned() + role: permissions
                }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", "channel"))
    }

    // Update channel
    async fn update_channel(
        &self,
        id: &str,
        channel: &PartialChannel,
        remove: Vec<FieldsChannel>,
    ) -> Result<()> {
        // A partial adding voice or the announcement flag is refused on a
        // protected channel. `Channel::update` checked the caller's copy,
        // which can be stale across a concurrent protect, so the write itself
        // is conditional on the STORED flag (design 7.4).
        if channel.sets_field_refused_on_protected() {
            let matched: Result<u64> = query!(
                self,
                update_one,
                COL,
                doc! {
                    "_id": id,
                    "protected": { "$ne": true }
                },
                channel,
                remove.iter().map(|x| x as &dyn IntoDocumentPath).collect(),
                None
            )
            .map(|result| result.matched_count);

            if matched? != 0 {
                return Ok(());
            }

            // Nothing matched: the channel is protected, or it does not
            // exist. Read it back to tell the two apart, as the Reference
            // driver does under its lock.
            return match self.fetch_channel(id).await {
                Ok(stored) if stored.is_protected() => Err(create_error!(ChannelProtected)),
                // Present and unprotected cannot happen while protect is
                // one-way and ids are never reused. Nothing was written, so
                // fail closed.
                Ok(_) => Err(create_database_error!("update_one", "channel")),
                // NotFound for a missing channel; any other error as is.
                Err(error) => Err(error),
            };
        }

        query!(
            self,
            update_one_by_id,
            COL,
            id,
            channel,
            remove.iter().map(|x| x as &dyn IntoDocumentPath).collect(),
            None
        )
        .map(|_| ())
    }

    /// Set last_message_id only if newer; see the trait for semantics.
    async fn set_last_message_id_if_newer(
        &self,
        channel_id: &str,
        message_id: &str,
        reopen_dm: bool,
    ) -> Result<bool> {
        let mut set = doc! { "last_message_id": message_id };
        if reopen_dm {
            set.insert("active", true);
        }

        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": channel_id,
                    "channel_type": { "$ne": "SavedMessages" },
                    // `$not/$gte` matches a missing field, null, or a strictly
                    // older id; a bare `$lt` would never set the first pointer.
                    "last_message_id": { "$not": { "$gte": message_id } }
                },
                doc! { "$set": set },
            )
            .await
            .map(|result| result.modified_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    // Remove a user from a group
    async fn remove_user_from_group(&self, channel: &str, user: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": channel
                },
                doc! {
                    "$pull": {
                        "recipients": user
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", "channels"))
    }

    // Remove a user from all specified groups
    async fn remove_user_from_groups(&self, channel_ids: Vec<String>, user_id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_many(
                doc! {
                    "_id": { "$in": channel_ids },
                },
                doc! {
                    "$pull": {
                        "recipients": user_id
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_many", COL))
    }

    // Delete a channel
    async fn delete_channel(&self, channel: &Channel) -> Result<()> {
        let id = channel.id().to_string();
        let server_id = match channel {
            Channel::TextChannel { server, .. } | Channel::Forum { server, .. } => Some(server),
            _ => None,
        };

        // Delete invites and unreads.
        self.delete_associated_channel_objects(Bson::String(id.to_string()))
            .await?;

        // Delete messages.
        self.delete_bulk_messages(doc! {
            "channel": &id
        })
        .await?;

        // Remove from server object.
        if let Some(server) = server_id {
            let server = self.fetch_server(server).await?;
            let mut update = doc! {
                "$pull": {
                    "channels": &id
                }
            };

            if let Some(sys) = &server.system_messages {
                let mut unset = doc! {};

                if let Some(cid) = &sys.user_joined {
                    if &id == cid {
                        unset.insert("system_messages.user_joined", 1_i32);
                    }
                }

                if let Some(cid) = &sys.user_left {
                    if &id == cid {
                        unset.insert("system_messages.user_left", 1_i32);
                    }
                }

                if let Some(cid) = &sys.user_kicked {
                    if &id == cid {
                        unset.insert("system_messages.user_kicked", 1_i32);
                    }
                }

                if let Some(cid) = &sys.user_banned {
                    if &id == cid {
                        unset.insert("system_messages.user_banned", 1_i32);
                    }
                }

                if !unset.is_empty() {
                    update.insert("$unset", unset);
                }
            }

            self.col::<Document>("servers")
                .update_one(
                    doc! {
                        "_id": server.id
                    },
                    update,
                )
                .await
                .map_err(|_| create_database_error!("update_one", "servers"))?;
        }

        // Delete associated attachments
        self.delete_many_attachments(doc! {
            "used_for.id": &id
        })
        .await?;

        // Delete the channel itself
        query!(self, delete_one_by_id, COL, channel.id())?;

        // Purge unreads a second time, now that the channel is gone.
        // A writer that raced the first purge checks the channel still
        // exists after its write: if it saw the channel, its row was
        // written before this purge and is removed here; if it did not,
        // the writer removes its own row.
        //
        // The channel is already deleted and the caller publishes
        // ChannelDelete next, so a failure here is logged, not returned.
        if let Err(err) = self
            .col::<Document>("channel_unreads")
            .delete_many(doc! {
                "_id.channel": &id
            })
            .await
            .map_err(|_| create_database_error!("delete_many", "channel_unreads"))
        {
            error!("Failed to purge unreads for deleted channel {id}: {err:?}");
            revolt_config::capture_error(&err);
        }

        Ok(())
    }
}

impl MongoDb {
    pub async fn delete_associated_channel_objects(&self, id: Bson) -> Result<()> {
        // Delete all invites to these channels.
        self.col::<Document>("channel_invites")
            .delete_many(doc! {
                "channel": &id
            })
            .await
            .map_err(|_| create_database_error!("delete_many", "channel_invites"))?;

        // Delete unread message objects on channels.
        self.col::<Document>("channel_unreads")
            .delete_many(doc! {
                "_id.channel": &id
            })
            .await
            .map_err(|_| create_database_error!("delete_many", "channel_unreads"))
            .map(|_| ())?;

        // Delete thread membership rows on channels.
        // (covers both deleting a thread itself and bulk channel deletion)
        self.col::<Document>("thread_members")
            .delete_many(doc! {
                "_id.thread": &id
            })
            .await
            .map_err(|_| create_database_error!("delete_many", "thread_members"))?;

        // update many attachments with parent id

        // Delete all webhooks on this channel.
        self.col::<Document>("webhooks")
            .delete_many(doc! {
                "channel": &id
            })
            .await
            .map_err(|_| create_database_error!("delete_many", "webhooks"))
            .map(|_| ())
    }
}

/// `update_channel` with a partial a protected channel refuses (design 7.4).
/// The conditional write above is Mongo's, but the outcomes must match the
/// Reference driver, so these run on whichever driver `TEST_DB` names.
#[cfg(test)]
mod tests {
    use crate::{Channel, PartialChannel, VoiceInformation};
    use revolt_result::ErrorType;

    fn text_channel(id: &str, protected: bool) -> Channel {
        Channel::TextChannel {
            id: id.to_string(),
            server: "S".to_string(),
            name: "text".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: std::collections::HashMap::new(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected,
        }
    }

    fn refused_partials() -> [PartialChannel; 2] {
        [
            PartialChannel {
                voice: Some(VoiceInformation::default()),
                ..Default::default()
            },
            PartialChannel {
                announcement: Some(true),
                ..Default::default()
            },
        ]
    }

    /// A missing channel is `NotFound`, not `ChannelProtected`: the
    /// conditional write matches nothing for a deleted channel too.
    ///
    /// Control: the W1 `matched? == 0 => ChannelProtected` mapping
    /// (MongoDB).
    #[tokio::test]
    async fn refused_field_on_a_missing_channel_is_not_found() {
        database_test!(|db| async move {
            for partial in refused_partials() {
                assert!(partial.sets_field_refused_on_protected());
                let result = db.update_channel("missing", &partial, vec![]).await;
                assert!(
                    matches!(
                        &result,
                        Err(error) if matches!(error.error_type, ErrorType::NotFound)
                    ),
                    "{partial:?} on a missing channel: {result:?}"
                );
            }
        });
    }

    /// A stored-protected channel refuses both fields, and nothing is
    /// written.
    #[tokio::test]
    async fn refused_field_on_a_protected_channel_is_refused() {
        database_test!(|db| async move {
            db.insert_channel(&text_channel("P", true))
                .await
                .expect("insert");

            for partial in refused_partials() {
                let result = db.update_channel("P", &partial, vec![]).await;
                assert!(
                    matches!(
                        &result,
                        Err(error) if matches!(error.error_type, ErrorType::ChannelProtected)
                    ),
                    "{partial:?} on a protected channel: {result:?}"
                );
            }

            let stored = db.fetch_channel("P").await.expect("fetch");
            assert!(stored.is_protected(), "{stored:?}");
            let Channel::TextChannel {
                voice,
                announcement,
                ..
            } = &stored
            else {
                panic!("{stored:?}");
            };
            assert_eq!(voice, &None, "voice was written");
            assert_ne!(announcement, &Some(true), "announcement was written");
        });
    }

    /// An unprotected channel takes both fields.
    #[tokio::test]
    async fn refused_field_on_an_open_channel_is_applied() {
        database_test!(|db| async move {
            db.insert_channel(&text_channel("T", false))
                .await
                .expect("insert");

            for partial in refused_partials() {
                db.update_channel("T", &partial, vec![])
                    .await
                    .unwrap_or_else(|error| panic!("{partial:?}: {error:?}"));
            }

            let stored = db.fetch_channel("T").await.expect("fetch");
            assert!(!stored.is_protected(), "{stored:?}");
            let Channel::TextChannel {
                voice,
                announcement,
                ..
            } = &stored
            else {
                panic!("{stored:?}");
            };
            assert!(voice.is_some(), "voice was not written: {stored:?}");
            assert_eq!(announcement, &Some(true), "announcement was not written");
        });
    }
}
