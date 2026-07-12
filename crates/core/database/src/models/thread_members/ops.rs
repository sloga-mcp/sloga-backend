use revolt_result::Result;

use crate::ThreadMember;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractThreadMembers: Sync + Send {
    /// Join a user to a thread if they are not already a member (idempotent).
    ///
    /// Returns true if a new membership was created.
    async fn join_thread_if_absent(&self, thread_id: &str, user_id: &str) -> Result<bool>;

    /// Remove a user's membership of a thread.
    async fn leave_thread(&self, thread_id: &str, user_id: &str) -> Result<()>;

    /// Fetch all members of a thread.
    async fn fetch_thread_members(&self, thread_id: &str) -> Result<Vec<ThreadMember>>;

    /// Fetch the ids of all threads within a given server the user has joined.
    async fn fetch_joined_thread_ids(&self, user_id: &str, server_id: &str)
        -> Result<Vec<String>>;

    /// Delete all membership rows for a thread.
    async fn delete_all_thread_memberships(&self, thread_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::AbstractThreadMembers;

    #[tokio::test]
    async fn join_is_idempotent_upsert() {
        database_test!(|db| async move {
            // First join inserts the membership. On the MongoDb driver this is
            // an upsert; a regression where `$setOnInsert` also carried `_id`
            // made Mongo reject it ("would create a conflict at '_id'") while
            // the in-memory reference driver was unaffected — so this must be
            // exercised under TEST_DB=MONGODB to catch it.
            let inserted = db
                .join_thread_if_absent("01THREAD", "01USER")
                .await
                .expect("join must not error on either driver");
            assert!(inserted, "first join should report a new membership");

            // Re-joining is a no-op and must not error.
            let again = db
                .join_thread_if_absent("01THREAD", "01USER")
                .await
                .expect("idempotent re-join must not error");
            assert!(!again, "second join should be idempotent");

            let members = db.fetch_thread_members("01THREAD").await.unwrap();
            assert_eq!(members.len(), 1, "exactly one membership row");
            assert_eq!(members[0].id.user, "01USER");
            assert_eq!(members[0].id.thread, "01THREAD");

            // Leaving removes it and is safe to repeat.
            db.leave_thread("01THREAD", "01USER").await.unwrap();
            assert!(db
                .fetch_thread_members("01THREAD")
                .await
                .unwrap()
                .is_empty());
        });
    }
}
