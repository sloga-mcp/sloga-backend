use revolt_result::Result;

use crate::ChannelFollow;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractChannelFollows: Sync + Send {
    /// Insert a new channel follow.
    ///
    /// ENFORCES (source_channel, target_channel) uniqueness: a pair that is
    /// already followed fails with `NoEffect` on BOTH drivers (Mongo's unique
    /// `source_target` index; an explicit guard under the reference driver's
    /// map mutex). delta's `fetch_follow_by_source_and_target` probe is a
    /// friendly idempotent early return, NOT the guard — two concurrent
    /// requests both pass it, and only this insert stops the second one from
    /// minting a duplicate follow and a second fan-out webhook.
    async fn insert_channel_follow(&self, follow: &ChannelFollow) -> Result<()>;

    /// Fetch a follow by its id.
    async fn fetch_follow(&self, id: &str) -> Result<ChannelFollow>;

    /// Fetch the follow linking a given (source, target) channel pair, if any
    /// (the pair is unique — this is the idempotency probe).
    async fn fetch_follow_by_source_and_target(
        &self,
        source_channel: &str,
        target_channel: &str,
    ) -> Result<Option<ChannelFollow>>;

    /// Fetch every follow whose source is the given announcement channel
    /// (the follower list, and the publish fan-out set).
    async fn fetch_follows_by_source(&self, source_channel: &str) -> Result<Vec<ChannelFollow>>;

    /// Fetch every follow whose target is the given channel (target-side
    /// cleanup on channel deletion).
    async fn fetch_follows_by_target(&self, target_channel: &str) -> Result<Vec<ChannelFollow>>;

    /// Fetch every follow that touches a server on EITHER side (its
    /// source_server or target_server matches) — server-deletion cascade.
    async fn fetch_follows_for_server(&self, server_id: &str) -> Result<Vec<ChannelFollow>>;

    /// Fetch the follow that owns a given webhook, if any (target-side
    /// unfollow via webhook deletion).
    async fn fetch_follow_by_webhook(&self, webhook_id: &str) -> Result<Option<ChannelFollow>>;

    /// Count the followers of a source announcement channel (drives the
    /// per-source follower cap).
    async fn count_follows_by_source(&self, source_channel: &str) -> Result<usize>;

    /// Delete a follow by id. Idempotent: a missing id is a no-op (Ok), so
    /// the delete-row-first ordering contract is safe to re-enter.
    async fn delete_channel_follow(&self, id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::AbstractChannelFollows;
    use crate::ChannelFollow;
    use revolt_result::ErrorType;

    fn follow(id: &str, source: &str, target: &str, webhook: &str) -> ChannelFollow {
        ChannelFollow {
            id: id.to_string(),
            source_channel: source.to_string(),
            source_server: "01SERVERSRC000000000000000".to_string(),
            target_channel: target.to_string(),
            target_server: "01SERVERTGT000000000000000".to_string(),
            webhook_id: webhook.to_string(),
            created_by: "01USER000000000000000000000".to_string(),
            created_at: 1_000,
        }
    }

    #[tokio::test]
    async fn crud_and_lookups() {
        database_test!(|db| async move {
            // Mongo's (source, target) uniqueness is an index; `database_test!`
            // hands us an un-migrated database, so install it here.
            create_source_target_index(&db).await;

            let a = follow(
                "01FOLLOWA000000000000000001",
                "01SOURCE0000000000000000001",
                "01TARGETA000000000000000001",
                "01WEBHOOKA00000000000000001",
            );
            let b = follow(
                "01FOLLOWB000000000000000001",
                "01SOURCE0000000000000000001",
                "01TARGETB000000000000000001",
                "01WEBHOOKB00000000000000001",
            );
            db.insert_channel_follow(&a).await.unwrap();
            db.insert_channel_follow(&b).await.unwrap();

            // Fetch by id
            assert_eq!(db.fetch_follow(&a.id).await.unwrap().id, a.id);

            // Two followers of the same source
            assert_eq!(
                db.count_follows_by_source("01SOURCE0000000000000000001")
                    .await
                    .unwrap(),
                2
            );
            let by_source = db
                .fetch_follows_by_source("01SOURCE0000000000000000001")
                .await
                .unwrap();
            assert_eq!(by_source.len(), 2);

            // Idempotency probe on the (source, target) pair
            assert!(db
                .fetch_follow_by_source_and_target(
                    "01SOURCE0000000000000000001",
                    "01TARGETA000000000000000001"
                )
                .await
                .unwrap()
                .is_some());
            assert!(db
                .fetch_follow_by_source_and_target(
                    "01SOURCE0000000000000000001",
                    "01NOPE00000000000000000001"
                )
                .await
                .unwrap()
                .is_none());

            // By target
            let by_target = db
                .fetch_follows_by_target("01TARGETB000000000000000001")
                .await
                .unwrap();
            assert_eq!(by_target.len(), 1);
            assert_eq!(by_target[0].id, b.id);

            // By webhook
            assert_eq!(
                db.fetch_follow_by_webhook("01WEBHOOKA00000000000000001")
                    .await
                    .unwrap()
                    .unwrap()
                    .id,
                a.id
            );
            assert!(db
                .fetch_follow_by_webhook("01NOWEBHOOK000000000000001")
                .await
                .unwrap()
                .is_none());

            // Delete is idempotent
            db.delete_channel_follow(&a.id).await.unwrap();
            db.delete_channel_follow(&a.id).await.unwrap(); // no-op, still Ok
            assert!(db.fetch_follow(&a.id).await.is_err());
            assert_eq!(
                db.count_follows_by_source("01SOURCE0000000000000000001")
                    .await
                    .unwrap(),
                1
            );

            // Duplicate (source, target) pair is rejected on both drivers
            // (Mongo unique index; reference explicit guard) as the same
            // domain error, so the follow route can branch on it instead of
            // reading a raw driver failure.
            let dup = ChannelFollow {
                id: "01FOLLOWDUP00000000000000001".to_string(),
                ..b.clone()
            };
            let error = db
                .insert_channel_follow(&dup)
                .await
                .expect_err("a duplicate (source, target) pair must be rejected");
            assert!(
                matches!(error.error_type, ErrorType::NoEffect),
                "expected NoEffect, got {:?}",
                error.error_type
            );
            assert!(db.fetch_follow(&dup.id).await.is_err());
        });
    }

    #[tokio::test]
    async fn server_cascade_matches_either_side() {
        database_test!(|db| async move {
            // Follow FROM server SRC (source) TO server TGT (target).
            let f = ChannelFollow {
                id: "01FOLLOWSRV00000000000000001".to_string(),
                source_channel: "01SRCCHAN0000000000000000001".to_string(),
                source_server: "01SRCSERVER00000000000000001".to_string(),
                target_channel: "01TGTCHAN0000000000000000001".to_string(),
                target_server: "01TGTSERVER00000000000000001".to_string(),
                webhook_id: "01WEBHOOKSRV0000000000000001".to_string(),
                created_by: "01USER000000000000000000000".to_string(),
                created_at: 1_000,
            };
            db.insert_channel_follow(&f).await.unwrap();

            // Matches when either the source OR the target server is deleted.
            assert_eq!(
                db.fetch_follows_for_server("01SRCSERVER00000000000000001")
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                db.fetch_follows_for_server("01TGTSERVER00000000000000001")
                    .await
                    .unwrap()
                    .len(),
                1
            );
            // An unrelated server matches nothing.
            assert!(db
                .fetch_follows_for_server("01OTHERSERVER0000000000001")
                .await
                .unwrap()
                .is_empty());
        });
    }

    /// Install the unique `source_target` index that makes one follow per
    /// (source, target) pair on MongoDB.
    ///
    /// `database_test!` connects to a fresh database with no migrations run,
    /// so without this the Mongo driver would silently accept a duplicate
    /// follow and the uniqueness contract would go untested. This spec MUST
    /// stay identical to the one in `admin_migrations/ops/mongodb/scripts.rs`
    /// (revision 60) and `init.rs`. The reference driver enforces the same
    /// rule in code, so it needs no setup.
    async fn create_source_target_index(db: &crate::Database) {
        match db {
            crate::Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                mongo
                    .db()
                    .run_command(bson::doc! {
                        "createIndexes": "channel_follows",
                        "indexes": [
                            {
                                "key": {
                                    "source_channel": 1_i32,
                                    "target_channel": 1_i32
                                },
                                "name": "source_target",
                                "unique": true
                            }
                        ]
                    })
                    .await
                    .expect("failed to create source_target index");
            }
        }
    }
}
