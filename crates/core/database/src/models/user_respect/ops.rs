use revolt_result::Result;

use crate::Respect;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

/// The most respect entries a single wall fetch returns (newest first). A
/// wall is bounded by the target's friend count, but a very popular account
/// must not ship thousands of rows (plus a user object per author) on every
/// profile open. Pagination past this cap is a follow-up.
pub const RESPECT_FETCH_CAP: i64 = 100;

#[async_trait]
pub trait AbstractUserRespect: Sync + Send {
    /// Insert a new respect entry.
    ///
    /// ENFORCES (target, author) uniqueness: a pair that already has an
    /// entry fails with `NoEffect` on BOTH drivers (Mongo's unique
    /// `target_author` index; an explicit guard under the reference driver's
    /// map mutex). delta's `fetch_respect` probe is the friendly upsert
    /// branch, NOT the guard — two concurrent first-time writes both pass
    /// it, and only this insert stops the second one from minting a
    /// duplicate row.
    async fn insert_respect(&self, respect: &Respect) -> Result<()>;

    /// Fetch the entry a given author has on a given target's wall, if any
    /// (the pair is unique — this is the upsert probe).
    async fn fetch_respect(&self, target_id: &str, author_id: &str) -> Result<Option<Respect>>;

    /// Rewrite an existing entry's content, bumping its edit time.
    async fn update_respect(&self, id: &str, content: &str, updated_at: i64) -> Result<()>;

    /// Fetch a target's wall: newest-edited first, capped at
    /// `RESPECT_FETCH_CAP`. The sort is part of the contract — the reference
    /// driver iterates a HashMap and MUST sort explicitly too.
    async fn fetch_respect_by_target(&self, target_id: &str) -> Result<Vec<Respect>>;

    /// Delete an entry by id. Idempotent: a missing id is a no-op (Ok).
    async fn delete_respect(&self, id: &str) -> Result<()>;

    /// Delete the respect between two users, BOTH directions — the block
    /// cascade (a block is hostile; neither party's words stay on the
    /// other's wall).
    async fn delete_respect_between(&self, user_a: &str, user_b: &str) -> Result<()>;

    /// Delete every entry a user appears in, either as target or author —
    /// the account-deletion cascade.
    async fn delete_respect_involving(&self, user_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::AbstractUserRespect;
    use crate::Respect;
    use revolt_result::ErrorType;

    fn respect(id: &str, target: &str, author: &str, content: &str, updated_at: i64) -> Respect {
        Respect {
            id: id.to_string(),
            target_id: target.to_string(),
            author_id: author.to_string(),
            content: content.to_string(),
            updated_at,
        }
    }

    #[tokio::test]
    async fn crud_upsert_and_wall_order() {
        database_test!(|db| async move {
            // Mongo's (target, author) uniqueness is an index; `database_test!`
            // hands us an un-migrated database, so install it here.
            create_target_author_index(&db).await;

            let a = respect(
                "01RSPCTA0000000000000000001",
                "01TARGET0000000000000000001",
                "01AUTHORA000000000000000001",
                "first",
                1_000,
            );
            let b = respect(
                "01RSPCTB0000000000000000001",
                "01TARGET0000000000000000001",
                "01AUTHORB000000000000000001",
                "second",
                2_000,
            );
            db.insert_respect(&a).await.unwrap();
            db.insert_respect(&b).await.unwrap();

            // Upsert probe
            assert!(db
                .fetch_respect("01TARGET0000000000000000001", "01AUTHORA000000000000000001")
                .await
                .unwrap()
                .is_some());
            assert!(db
                .fetch_respect("01TARGET0000000000000000001", "01NOBODY0000000000000000001")
                .await
                .unwrap()
                .is_none());

            // Wall is newest-edited first on BOTH drivers.
            let wall = db
                .fetch_respect_by_target("01TARGET0000000000000000001")
                .await
                .unwrap();
            assert_eq!(wall.len(), 2);
            assert_eq!(wall[0].id, b.id);
            assert_eq!(wall[1].id, a.id);

            // Editing bumps an entry to the top and persists the new content.
            db.update_respect(&a.id, "rewritten", 3_000).await.unwrap();
            let wall = db
                .fetch_respect_by_target("01TARGET0000000000000000001")
                .await
                .unwrap();
            assert_eq!(wall[0].id, a.id);
            assert_eq!(wall[0].content, "rewritten");
            assert_eq!(wall[0].updated_at, 3_000);

            // Duplicate (target, author) pair is rejected on both drivers
            // (Mongo unique index; reference explicit guard) as the same
            // domain error, so the set route can branch on it instead of
            // reading a raw driver failure.
            let dup = Respect {
                id: "01RSPCTDUP000000000000000001".to_string(),
                ..a.clone()
            };
            let error = db
                .insert_respect(&dup)
                .await
                .expect_err("a duplicate (target, author) pair must be rejected");
            assert!(
                matches!(error.error_type, ErrorType::NoEffect),
                "expected NoEffect, got {:?}",
                error.error_type
            );

            // Delete is idempotent.
            db.delete_respect(&a.id).await.unwrap();
            db.delete_respect(&a.id).await.unwrap();
            assert!(db
                .fetch_respect("01TARGET0000000000000000001", "01AUTHORA000000000000000001")
                .await
                .unwrap()
                .is_none());
        });
    }

    #[tokio::test]
    async fn block_and_deletion_cascades() {
        database_test!(|db| async move {
            create_target_author_index(&db).await;

            // A and B wrote on each other's walls; B also wrote on C's.
            let ab = respect(
                "01RSPCTAB000000000000000001",
                "01USERA00000000000000000001",
                "01USERB00000000000000000001",
                "b on a",
                1_000,
            );
            let ba = respect(
                "01RSPCTBA000000000000000001",
                "01USERB00000000000000000001",
                "01USERA00000000000000000001",
                "a on b",
                1_000,
            );
            let cb = respect(
                "01RSPCTCB000000000000000001",
                "01USERC00000000000000000001",
                "01USERB00000000000000000001",
                "b on c",
                1_000,
            );
            db.insert_respect(&ab).await.unwrap();
            db.insert_respect(&ba).await.unwrap();
            db.insert_respect(&cb).await.unwrap();

            // Block wipes BOTH directions between the pair, nothing else.
            db.delete_respect_between("01USERA00000000000000000001", "01USERB00000000000000000001")
                .await
                .unwrap();
            assert!(db
                .fetch_respect_by_target("01USERA00000000000000000001")
                .await
                .unwrap()
                .is_empty());
            assert!(db
                .fetch_respect_by_target("01USERB00000000000000000001")
                .await
                .unwrap()
                .is_empty());
            assert_eq!(
                db.fetch_respect_by_target("01USERC00000000000000000001")
                    .await
                    .unwrap()
                    .len(),
                1
            );

            // Account deletion removes the user's rows on BOTH sides.
            db.delete_respect_involving("01USERB00000000000000000001")
                .await
                .unwrap();
            assert!(db
                .fetch_respect_by_target("01USERC00000000000000000001")
                .await
                .unwrap()
                .is_empty());
        });
    }

    /// Install the unique `target_author` index that makes one entry per
    /// (target, author) pair on MongoDB.
    ///
    /// `database_test!` connects to a fresh database with no migrations run,
    /// so without this the Mongo driver would silently accept a duplicate
    /// entry and the uniqueness contract would go untested. This spec MUST
    /// stay identical to the one in `admin_migrations/ops/mongodb/scripts.rs`
    /// (revision 69) and `init.rs`. The reference driver enforces the same
    /// rule in code, so it needs no setup.
    async fn create_target_author_index(db: &crate::Database) {
        match db {
            crate::Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                mongo
                    .db()
                    .run_command(bson::doc! {
                        "createIndexes": "user_respect",
                        "indexes": [
                            {
                                "key": {
                                    "target_id": 1_i32,
                                    "author_id": 1_i32
                                },
                                "name": "target_author",
                                "unique": true
                            }
                        ]
                    })
                    .await
                    .expect("failed to create target_author index");
            }
        }
    }
}
