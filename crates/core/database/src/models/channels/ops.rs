use crate::{Channel, FieldsChannel, PartialChannel, revolt_result::Result, util::ChunkedDatabaseGenerator};
use revolt_permissions::OverrideField;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractChannels: Sync + Send {
    /// Insert a new channel in the database
    async fn insert_channel(&self, channel: &Channel) -> Result<()>;

    /// Fetch a channel from the database
    async fn fetch_channel(&self, channel_id: &str) -> Result<Channel>;

    /// Fetch all channels from the database
    async fn fetch_channels<'a>(&self, ids: &'a [String]) -> Result<Vec<Channel>>;

    /// Fetch all threads hanging off a given parent channel
    async fn fetch_threads_by_parent(&self, parent_id: &str) -> Result<Vec<Channel>>;

    /// Fetch the ids of every thread (incl. forum posts, archived and locked ones) whose parent is in `parent_ids`
    async fn fetch_thread_ids_by_parents(&self, parent_ids: &[String]) -> Result<Vec<String>>;

    /// Fetch every non-archived thread that can auto-archive; excludes threads set to never auto-archive (`auto_archive_minutes == 0`) (used by the auto-archive daemon)
    async fn fetch_active_threads(&self) -> Result<Vec<Channel>>;

    /// Fetch all direct messages for a user
    async fn find_direct_messages(&self, user_id: &str) -> Result<Vec<Channel>>;

    // Fetch all group dms for a user
    async fn find_group_message_channels(&self, user_id: &str) -> Result<ChunkedDatabaseGenerator<Channel>>;

    // Fetch saved messages channel
    async fn find_saved_messages_channel(&self, user_id: &str) -> Result<Channel>;

    // Fetch direct message channel (DM or Saved Messages)
    async fn find_direct_message_channel(&self, user_a: &str, user_b: &str) -> Result<Channel>;

    /// Insert a user to a group
    async fn add_user_to_group(&self, channel_id: &str, user_id: &str) -> Result<()>;

    /// Insert channel role permissions
    async fn set_channel_role_permission(
        &self,
        channel_id: &str,
        role_id: &str,
        permissions: OverrideField,
    ) -> Result<()>;

    // Update channel
    async fn update_channel(
        &self,
        id: &str,
        channel_id: &PartialChannel,
        remove: Vec<FieldsChannel>,
    ) -> Result<()>;

    /// Set `last_message_id` to `message_id` only if the stored id is missing or strictly older
    /// (ULIDs sort by time as plain strings). When `reopen_dm` is set, the same write also sets
    /// `active: true`. Returns whether this call advanced the pointer; `Ok(false)` when the stored
    /// id is equal or newer, the channel is Saved Messages, or the channel does not exist.
    /// `reopen_dm` is only meaningful for DirectMessage; callers pass it only for DMs.
    async fn set_last_message_id_if_newer(
        &self,
        channel_id: &str,
        message_id: &str,
        reopen_dm: bool,
    ) -> Result<bool>;

    // Remove a user from a group
    async fn remove_user_from_group(&self, channel_id: &str, user_id: &str) -> Result<()>;

    // Remove a user from all specified groups
    async fn remove_user_from_groups(&self, channel_ids: Vec<String>, user_id: &str) -> Result<()>;

    // Delete a channel
    async fn delete_channel(&self, channel_id: &Channel) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use crate::{Channel, PartialChannel};
    use ulid::Ulid;

    /// A ULID string whose timestamp part is `t`, so ids built from a larger `t` sort later.
    fn id(t: u64) -> String {
        Ulid::from_parts(t, 0).to_string()
    }

    /// Ids of three messages sent in order, checked to sort in that order.
    fn ordered_ids() -> (String, String, String) {
        let (id1, id2, id3) = (id(1_000), id(2_000), id(3_000));
        assert!(
            id1 < id2 && id2 < id3,
            "ULIDs must sort by time as plain strings"
        );
        assert!([&id1, &id2, &id3].iter().all(|id| id.len() == 26));
        (id1, id2, id3)
    }

    fn group_last_message_id(channel: Channel) -> Option<String> {
        match channel {
            Channel::Group {
                last_message_id, ..
            } => last_message_id,
            other => panic!("expected a Group channel, got {other:?}"),
        }
    }

    fn dm_state(channel: Channel) -> (bool, Option<String>) {
        match channel {
            Channel::DirectMessage {
                active,
                last_message_id,
                ..
            } => (active, last_message_id),
            other => panic!("expected a DirectMessage channel, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn last_message_id_only_moves_forward() {
        database_test!(|db| async move {
            let (id1, id2, id3) = ordered_ids();
            let group_id = "01LMIDGROUP".to_string();

            db.insert_channel(&Channel::Group {
                id: group_id.clone(),
                name: "test".to_string(),
                owner: "01LMIDOWNER".to_string(),
                description: None,
                recipients: vec!["01LMIDOWNER".to_string()],
                icon: None,
                last_message_id: None,
                permissions: None,
                nsfw: false,
                spoiler: false,
                voice: None,
            })
            .await
            .unwrap();

            // The first id is written into a channel that has none yet.
            assert!(db
                .set_last_message_id_if_newer(&group_id, &id2, false)
                .await
                .unwrap());
            let stored = group_last_message_id(db.fetch_channel(&group_id).await.unwrap());
            assert_eq!(stored.as_deref(), Some(id2.as_str()));

            // An older id loses and leaves the stored id alone.
            assert!(!db
                .set_last_message_id_if_newer(&group_id, &id1, false)
                .await
                .unwrap());
            let stored = group_last_message_id(db.fetch_channel(&group_id).await.unwrap());
            assert_eq!(stored.as_deref(), Some(id2.as_str()));

            // The same id again does not count as an advance.
            assert!(!db
                .set_last_message_id_if_newer(&group_id, &id2, false)
                .await
                .unwrap());

            // A newer id wins.
            assert!(db
                .set_last_message_id_if_newer(&group_id, &id3, false)
                .await
                .unwrap());
            let stored = group_last_message_id(db.fetch_channel(&group_id).await.unwrap());
            assert_eq!(stored.as_deref(), Some(id3.as_str()));
        });
    }

    #[tokio::test]
    async fn last_message_id_dm_reopen_only_when_newer() {
        database_test!(|db| async move {
            let (id1, id2, id3) = ordered_ids();
            let dm_id = "01LMIDDM".to_string();

            db.insert_channel(&Channel::DirectMessage {
                id: dm_id.clone(),
                active: false,
                recipients: vec!["01LMIDUSERA".to_string(), "01LMIDUSERB".to_string()],
                last_message_id: None,
            })
            .await
            .unwrap();

            // A winning id reopens the DM in the same write.
            assert!(db
                .set_last_message_id_if_newer(&dm_id, &id2, true)
                .await
                .unwrap());
            let (active, stored) = dm_state(db.fetch_channel(&dm_id).await.unwrap());
            assert!(active, "a winning id must reopen the DM");
            assert_eq!(stored.as_deref(), Some(id2.as_str()));

            // The user closes the DM.
            db.update_channel(
                &dm_id,
                &PartialChannel {
                    active: Some(false),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();

            // A stale id arriving after the close must not reopen it.
            assert!(!db
                .set_last_message_id_if_newer(&dm_id, &id1, true)
                .await
                .unwrap());
            let (active, stored) = dm_state(db.fetch_channel(&dm_id).await.unwrap());
            assert!(!active, "a losing id must not reopen a closed DM");
            assert_eq!(stored.as_deref(), Some(id2.as_str()));

            // A newer message reopens it.
            assert!(db
                .set_last_message_id_if_newer(&dm_id, &id3, true)
                .await
                .unwrap());
            let (active, stored) = dm_state(db.fetch_channel(&dm_id).await.unwrap());
            assert!(active, "a newer id must reopen the DM");
            assert_eq!(stored.as_deref(), Some(id3.as_str()));
        });
    }

    #[tokio::test]
    async fn last_message_id_skips_missing_and_saved_messages() {
        database_test!(|db| async move {
            let (id1, _, _) = ordered_ids();

            // The `Ok(false)` returns below are the real assertions. Fetching the channel
            // back could not show a stray `last_message_id` key written into a Mongo
            // document, because serde ignores unknown keys when it reads the channel.
            assert!(!db
                .set_last_message_id_if_newer("does-not-exist", &id1, false)
                .await
                .expect("a missing channel is Ok(false), not an error"));

            let saved_id = "01LMIDSAVED".to_string();
            db.insert_channel(&Channel::SavedMessages {
                id: saved_id.clone(),
                user: "01LMIDUSERA".to_string(),
            })
            .await
            .unwrap();

            assert!(!db
                .set_last_message_id_if_newer(&saved_id, &id1, false)
                .await
                .expect("Saved Messages is Ok(false), not an error"));
        });
    }

    fn tidbp_text_channel(id: &str) -> Channel {
        Channel::TextChannel {
            id: id.to_string(),
            server: "01TIDBPSERVER".to_string(),
            name: "text".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: Default::default(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
        }
    }

    fn tidbp_thread(id: &str, parent: &str, archived: bool, locked: bool) -> Channel {
        Channel::Thread {
            id: id.to_string(),
            server: "01TIDBPSERVER".to_string(),
            parent_channel: parent.to_string(),
            name: "thread".to_string(),
            creator: "01TIDBPCREATOR".to_string(),
            origin_message_id: None,
            last_message_id: None,
            archived,
            archived_timestamp: None,
            auto_archive_minutes: Channel::default_auto_archive_minutes(),
            locked,
            applied_tags: vec![],
        }
    }

    #[tokio::test]
    async fn thread_ids_by_parents_includes_archived_locked_and_forum_posts() {
        database_test!(|db| async move {
            let (p1, p2, p3) = ("01TIDBPPARENT1", "01TIDBPPARENT2", "01TIDBPPARENT3");
            let (t1, t2, t3, t4) = (
                "01TIDBPTHREAD1",
                "01TIDBPTHREAD2",
                "01TIDBPTHREAD3",
                "01TIDBPTHREAD4",
            );

            db.insert_channel(&tidbp_text_channel(p1)).await.unwrap();
            db.insert_channel(&Channel::Forum {
                id: p2.to_string(),
                server: "01TIDBPSERVER".to_string(),
                name: "forum".to_string(),
                description: None,
                icon: None,
                last_message_id: None,
                default_permissions: None,
                role_permissions: Default::default(),
                nsfw: false,
                spoiler: false,
                tags: vec![],
                require_tag: false,
                default_sort: Default::default(),
                force_sort: false,
                default_auto_archive_minutes: Channel::default_forum_auto_archive_minutes(),
            })
            .await
            .unwrap();
            db.insert_channel(&tidbp_text_channel(p3)).await.unwrap();

            db.insert_channel(&tidbp_thread(t1, p1, false, false))
                .await
                .unwrap();
            db.insert_channel(&tidbp_thread(t2, p1, true, true))
                .await
                .unwrap();
            db.insert_channel(&tidbp_thread(t3, p2, false, false))
                .await
                .unwrap();
            db.insert_channel(&tidbp_thread(t4, p3, false, false))
                .await
                .unwrap();

            // A dangling parent id must neither error nor match anything.
            let mut got = db
                .fetch_thread_ids_by_parents(&[
                    p1.to_string(),
                    p2.to_string(),
                    "01TIDBPDANGLINGPARENT".to_string(),
                ])
                .await
                .expect("thread id lookup must succeed");
            got.sort();
            assert_eq!(
                got,
                vec![t1.to_string(), t2.to_string(), t3.to_string()],
                "expected every thread under P1 and P2, archived/locked and forum posts included, and nothing under P3"
            );

            assert!(
                db.fetch_thread_ids_by_parents(&[])
                    .await
                    .expect("an empty parent list is Ok, not an error")
                    .is_empty(),
                "an empty parent list must return no ids"
            );
        });
    }
}
