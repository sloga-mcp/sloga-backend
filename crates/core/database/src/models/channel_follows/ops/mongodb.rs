use futures::StreamExt;
use revolt_result::Result;

use crate::ChannelFollow;
use crate::MongoDb;

use super::AbstractChannelFollows;

static COL: &str = "channel_follows";

#[async_trait]
impl AbstractChannelFollows for MongoDb {
    /// Insert a new channel follow, enforcing (source, target) uniqueness.
    async fn insert_channel_follow(&self, follow: &ChannelFollow) -> Result<()> {
        // The unique `source_target` index is what actually serializes
        // concurrent follow requests — delta's fetch-then-insert probe is a
        // TOCTOU and two simultaneous follows of the same source from the
        // same target both pass it. A duplicate-key rejection here is that
        // race resolving, not a database fault, so it becomes `NoEffect`:
        // the follow already exists, so this insert changed nothing.
        //
        // The only unique indexes on this collection are `_id` (a fresh ULID
        // per follow, so it never collides in practice) and `source_target`,
        // which makes 11000 unambiguous.
        self.col::<ChannelFollow>(COL)
            .insert_one(follow)
            .await
            .map(|_| ())
            .map_err(|error| match *error.kind {
                mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
                    ref write_error,
                )) if write_error.code == 11000 => create_error!(NoEffect),
                _ => create_database_error!("insert_one", COL),
            })
    }

    async fn fetch_follow(&self, id: &str) -> Result<ChannelFollow> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_follow_by_source_and_target(
        &self,
        source_channel: &str,
        target_channel: &str,
    ) -> Result<Option<ChannelFollow>> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "source_channel": source_channel,
                "target_channel": target_channel
            }
        )
    }

    async fn fetch_follows_by_source(&self, source_channel: &str) -> Result<Vec<ChannelFollow>> {
        Ok(self
            .col::<ChannelFollow>(COL)
            .find(doc! { "source_channel": source_channel })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    async fn fetch_follows_by_target(&self, target_channel: &str) -> Result<Vec<ChannelFollow>> {
        Ok(self
            .col::<ChannelFollow>(COL)
            .find(doc! { "target_channel": target_channel })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    async fn fetch_follows_for_server(&self, server_id: &str) -> Result<Vec<ChannelFollow>> {
        Ok(self
            .col::<ChannelFollow>(COL)
            .find(doc! {
                "$or": [
                    { "source_server": server_id },
                    { "target_server": server_id }
                ]
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    async fn fetch_follow_by_webhook(&self, webhook_id: &str) -> Result<Option<ChannelFollow>> {
        query!(self, find_one, COL, doc! { "webhook_id": webhook_id })
    }

    async fn count_follows_by_source(&self, source_channel: &str) -> Result<usize> {
        query!(
            self,
            count_documents,
            COL,
            doc! { "source_channel": source_channel }
        )
        .map(|count| count as usize)
    }

    async fn delete_channel_follow(&self, id: &str) -> Result<()> {
        // Idempotent: deleting a missing row is not an error.
        query!(self, delete_one_by_id, COL, id).map(|_| ())
    }
}
