use futures::StreamExt;
use revolt_result::Result;

use crate::MongoDb;
use crate::Respect;

use super::{AbstractUserRespect, RESPECT_FETCH_CAP};

static COL: &str = "user_respect";

#[async_trait]
impl AbstractUserRespect for MongoDb {
    /// Insert a new respect entry, enforcing (target, author) uniqueness.
    async fn insert_respect(&self, respect: &Respect) -> Result<()> {
        // The unique `target_author` index is what actually serializes
        // concurrent first-time writes — delta's fetch-then-insert probe is
        // a TOCTOU and two simultaneous writes from the same author both
        // pass it. A duplicate-key rejection here is that race resolving,
        // not a database fault, so it becomes `NoEffect`: the pair already
        // has an entry, so this insert changed nothing.
        //
        // The only unique indexes on this collection are `_id` (a fresh ULID
        // per entry, so it never collides in practice) and `target_author`,
        // which makes 11000 unambiguous.
        self.col::<Respect>(COL)
            .insert_one(respect)
            .await
            .map(|_| ())
            .map_err(|error| match *error.kind {
                mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
                    ref write_error,
                )) if write_error.code == 11000 => create_error!(NoEffect),
                _ => create_database_error!("insert_one", COL),
            })
    }

    async fn fetch_respect(&self, target_id: &str, author_id: &str) -> Result<Option<Respect>> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "target_id": target_id,
                "author_id": author_id
            }
        )
    }

    async fn update_respect(&self, id: &str, content: &str, updated_at: i64) -> Result<()> {
        self.col::<Respect>(COL)
            .update_one(
                doc! { "_id": id },
                doc! {
                    "$set": {
                        "content": content,
                        "updated_at": updated_at
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    async fn fetch_respect_by_target(&self, target_id: &str) -> Result<Vec<Respect>> {
        Ok(self
            .col::<Respect>(COL)
            .find(doc! { "target_id": target_id })
            .sort(doc! { "updated_at": -1_i32 })
            .limit(RESPECT_FETCH_CAP)
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    async fn delete_respect(&self, id: &str) -> Result<()> {
        // Idempotent: deleting a missing row is not an error.
        query!(self, delete_one_by_id, COL, id).map(|_| ())
    }

    async fn delete_respect_between(&self, user_a: &str, user_b: &str) -> Result<()> {
        self.col::<Respect>(COL)
            .delete_many(doc! {
                "$or": [
                    { "target_id": user_a, "author_id": user_b },
                    { "target_id": user_b, "author_id": user_a }
                ]
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }

    async fn delete_respect_involving(&self, user_id: &str) -> Result<()> {
        self.col::<Respect>(COL)
            .delete_many(doc! {
                "$or": [
                    { "target_id": user_id },
                    { "author_id": user_id }
                ]
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }
}
