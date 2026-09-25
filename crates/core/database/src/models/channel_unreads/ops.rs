use revolt_result::Result;

use crate::ChannelUnread;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

/// Channel unread storage.
///
/// The write methods (`acknowledge_message`, `acknowledge_channels`,
/// `add_mention_to_unread` and `add_mention_to_many_unreads`) leave no row
/// for a channel that does not exist and still return `Ok`
/// (`acknowledge_message` returns `Ok(None)`), so a write racing a channel
/// delete cannot resurrect an unread for it.
#[async_trait]
pub trait AbstractChannelUnreads: Sync + Send {
    /// Acknowledge a message, and returns updated channel unread.
    ///
    /// Returns `Ok(None)` if the channel does not exist.
    async fn acknowledge_message(
        &self,
        channel_id: &str,
        user_id: &str,
        message_id: &str,
    ) -> Result<Option<ChannelUnread>>;

    /// Acknowledge many channels.
    async fn acknowledge_channels(&self, user_id: &str, channel_ids: &[String]) -> Result<()>;

    /// Add a mention.
    async fn add_mention_to_unread<'a>(
        &self,
        channel_id: &str,
        user_id: &str,
        message_ids: &[String],
    ) -> Result<()>;

    /// Add a mention.
    async fn add_mention_to_many_unreads<'a>(
        &self,
        channel_id: &str,
        user_ids: &[String],
        message_ids: &[String],
    ) -> Result<()>;

    /// Fetch all unreads with mentions for a user.
    async fn fetch_unread_mentions(&self, user_id: &str) -> Result<Vec<ChannelUnread>>;

    /// Fetch all channel unreads for a user.
    async fn fetch_unreads(&self, user_id: &str) -> Result<Vec<ChannelUnread>>;

    /// Fetch unread for a specific user in a channel.
    async fn fetch_unread(&self, user_id: &str, channel_id: &str) -> Result<Option<ChannelUnread>>;
}

#[cfg(test)]
mod tests {
    use crate::Channel;

    // A thread, because the MongoDB `delete_channel` looks up the server of a
    // text channel (or forum) and these tests have no server.
    fn thread(id: &str) -> Channel {
        Channel::Thread {
            id: id.to_string(),
            server: new_id(),
            parent_channel: new_id(),
            name: "thread".to_string(),
            creator: new_id(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: 0,
            locked: false,
            applied_tags: vec![],
        }
    }

    fn new_id() -> String {
        ulid::Ulid::new().to_string()
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn mention_after_channel_delete_leaves_no_unread() {
        database_test!(|db| async move {
            let id = new_id();
            let user = new_id();
            let channel = thread(&id);
            db.insert_channel(&channel).await.unwrap();
            db.delete_channel(&channel).await.unwrap();

            db.add_mention_to_unread(&id, &user, &[new_id()])
                .await
                .unwrap();

            assert!(db.fetch_unread(&user, &id).await.unwrap().is_none());
            assert!(db.fetch_unread_mentions(&user).await.unwrap().is_empty());
        });
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn many_mentions_after_channel_delete_leave_no_unread() {
        database_test!(|db| async move {
            let id = new_id();
            let user = new_id();
            let channel = thread(&id);
            db.insert_channel(&channel).await.unwrap();
            db.delete_channel(&channel).await.unwrap();

            // One user only: a multi-user `$in` upsert is a separate quirk.
            db.add_mention_to_many_unreads(&id, std::slice::from_ref(&user), &[new_id()])
                .await
                .unwrap();

            assert!(db.fetch_unread(&user, &id).await.unwrap().is_none());
            assert!(db.fetch_unread_mentions(&user).await.unwrap().is_empty());
        });
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn ack_after_channel_delete_leaves_no_unread() {
        database_test!(|db| async move {
            let id = new_id();
            let user = new_id();
            let channel = thread(&id);
            db.insert_channel(&channel).await.unwrap();
            db.delete_channel(&channel).await.unwrap();

            let unread = db.acknowledge_message(&id, &user, &new_id()).await.unwrap();

            assert!(unread.is_none());
            assert!(db.fetch_unread(&user, &id).await.unwrap().is_none());
        });
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn ack_channels_after_channel_delete_leaves_no_unread() {
        database_test!(|db| async move {
            let live = new_id();
            let deleted = new_id();
            let user = new_id();
            db.insert_channel(&thread(&live)).await.unwrap();
            let deleted_channel = thread(&deleted);
            db.insert_channel(&deleted_channel).await.unwrap();
            db.delete_channel(&deleted_channel).await.unwrap();

            db.acknowledge_channels(&user, &[live.clone(), deleted.clone()])
                .await
                .unwrap();

            assert!(db.fetch_unread(&user, &live).await.unwrap().is_some());
            assert!(db.fetch_unread(&user, &deleted).await.unwrap().is_none());
        });
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn first_mention_creates_unread_for_live_channel() {
        database_test!(|db| async move {
            let id = new_id();
            let user = new_id();
            let message = new_id();
            db.insert_channel(&thread(&id)).await.unwrap();

            // A single call: the reference driver replaces mentions while the
            // MongoDB driver appends, so a second call would diverge.
            db.add_mention_to_unread(&id, &user, std::slice::from_ref(&message))
                .await
                .unwrap();

            let unread = db.fetch_unread(&user, &id).await.unwrap();
            assert_eq!(unread.and_then(|u| u.mentions), Some(vec![message]));
        });
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn delete_channel_purges_existing_unreads() {
        database_test!(|db| async move {
            let id = new_id();
            let user = new_id();
            let channel = thread(&id);
            db.insert_channel(&channel).await.unwrap();

            db.add_mention_to_unread(&id, &user, &[new_id()])
                .await
                .unwrap();
            assert!(db.fetch_unread(&user, &id).await.unwrap().is_some());
            db.delete_channel(&channel).await.unwrap();

            assert!(db.fetch_unread(&user, &id).await.unwrap().is_none());
        });
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn ack_creates_unread_for_live_channel() {
        database_test!(|db| async move {
            let id = new_id();
            let user = new_id();
            let message = new_id();
            db.insert_channel(&thread(&id)).await.unwrap();

            let unread = db.acknowledge_message(&id, &user, &message).await.unwrap();
            assert_eq!(unread.and_then(|u| u.last_id), Some(message.clone()));

            let stored = db.fetch_unread(&user, &id).await.unwrap();
            assert_eq!(stored.and_then(|u| u.last_id), Some(message));
        });
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn many_mentions_create_unread_for_live_channel() {
        database_test!(|db| async move {
            let id = new_id();
            let user = new_id();
            let message = new_id();
            db.insert_channel(&thread(&id)).await.unwrap();

            // A single call: the reference driver replaces mentions while the
            // MongoDB driver appends, so a second call would diverge.
            db.add_mention_to_many_unreads(
                &id,
                std::slice::from_ref(&user),
                std::slice::from_ref(&message),
            )
            .await
            .unwrap();

            let unread = db.fetch_unread(&user, &id).await.unwrap();
            assert_eq!(unread.and_then(|u| u.mentions), Some(vec![message]));
        });
    }
}
