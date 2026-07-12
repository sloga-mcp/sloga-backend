use bson::Document;
use futures::StreamExt;
use iso8601_timestamp::Timestamp;
use mongodb::options::UpdateOptions;
use revolt_result::Result;

use crate::MongoDb;
use crate::{ThreadMember, ThreadMemberCompositeKey};

use super::AbstractThreadMembers;

static COL: &str = "thread_members";

#[async_trait]
impl AbstractThreadMembers for MongoDb {
    /// Join a user to a thread if they are not already a member (idempotent).
    async fn join_thread_if_absent(&self, thread_id: &str, user_id: &str) -> Result<bool> {
        let member = ThreadMember {
            id: ThreadMemberCompositeKey {
                thread: thread_id.to_string(),
                user: user_id.to_string(),
            },
            joined_at: Timestamp::now_utc(),
        };

        let mut document = bson::to_document(&member)
            .map_err(|_| create_database_error!("to_document", COL))?;
        // The upsert filter already pins `_id` via its dotted subfields
        // (`_id.thread` / `_id.user`); leaving `_id` in `$setOnInsert` as well
        // makes MongoDB reject the upsert ("would create a conflict at '_id'").
        document.remove("_id");

        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id.thread": thread_id,
                    "_id.user": user_id,
                },
                doc! {
                    "$setOnInsert": document
                },
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await
            .map(|result| result.upserted_id.is_some())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Remove a user's membership of a thread.
    async fn leave_thread(&self, thread_id: &str, user_id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .delete_one(doc! {
                "_id.thread": thread_id,
                "_id.user": user_id,
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_one", COL))
    }

    /// Fetch all members of a thread.
    async fn fetch_thread_members(&self, thread_id: &str) -> Result<Vec<ThreadMember>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "_id.thread": thread_id
            }
        )
    }

    /// Fetch the ids of all threads within a given server the user has joined.
    async fn fetch_joined_thread_ids(
        &self,
        user_id: &str,
        server_id: &str,
    ) -> Result<Vec<String>> {
        let memberships: Vec<ThreadMember> = query!(
            self,
            find,
            COL,
            doc! {
                "_id.user": user_id
            }
        )?;

        let thread_ids = memberships
            .into_iter()
            .map(|member| member.id.thread)
            .collect::<Vec<String>>();

        if thread_ids.is_empty() {
            return Ok(vec![]);
        }

        Ok(self
            .col::<Document>("channels")
            .find(doc! {
                "_id": {
                    "$in": thread_ids
                },
                "channel_type": "Thread",
                "server": server_id
            })
            .await
            .map_err(|_| create_database_error!("find", "channels"))?
            .filter_map(|s| async {
                s.map(|d| d.get_str("_id").map(|s| s.to_string()).ok())
                    .ok()
                    .flatten()
            })
            .collect()
            .await)
    }

    /// Delete all membership rows for a thread.
    async fn delete_all_thread_memberships(&self, thread_id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .delete_many(doc! {
                "_id.thread": thread_id
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }
}
