pub mod mongodb;
pub mod reference;

use revolt_result::Result;

use crate::CipherMembership;

/// Largest `limit` that `fetch_cipher_memberships_page` accepts
const MEMBERSHIPS_PAGE_MAX: i64 = 500;

#[async_trait]
pub trait AbstractCipherMemberships: Sync + Send {
    /// Insert a membership; Ok(true) if inserted, Ok(false) if the user
    /// already has a row (revoked or not). A number already held by another
    /// user's row is an error, never Ok(false).
    async fn insert_cipher_membership(&self, m: &CipherMembership) -> Result<bool>;

    /// Fetch a user's membership, revoked or not
    async fn fetch_cipher_membership(&self, user_id: &str) -> Result<Option<CipherMembership>>;

    /// Fetch the row holding `number`, revoked or not, whoever's it is (the
    /// unique `number` index allows at most one). A number goes back to the
    /// pool only while this is None.
    async fn fetch_cipher_membership_by_number(
        &self,
        number: u32,
    ) -> Result<Option<CipherMembership>>;

    /// Compare-and-swap replace: write `m` in full with
    /// `version = expected + 1` WHERE `_id = m.user_id` AND
    /// `version == expected` (`expected == 0` also matches a row stored
    /// without a version field). The `version` carried by `m` is ignored.
    /// Never upserts.
    ///
    /// Ok(true) if written; Ok(false) if the version moved or there is no
    /// row, and the caller re-reads and retries. Per-order leases do not
    /// serialize writes to a shared membership, so every change (a revoked
    /// row replaced on re-purchase included) goes through this.
    /// A number held by another user's row is an error, as on insert.
    async fn update_cipher_membership_if_version(
        &self,
        m: &CipherMembership,
        expected: u64,
    ) -> Result<bool>;

    /// Account-deletion cascade: delete a user's membership (Ok if absent)
    async fn delete_cipher_membership(&self, user_id: &str) -> Result<()>;

    /// Compare-and-swap delete: remove the user's row WHERE
    /// `version == expected` (`expected == 0` also matches a row stored
    /// without a version field), under the same rule as
    /// `update_cipher_membership_if_version`. Ok(true) if deleted; Ok(false)
    /// if the version moved or there is no row, and the caller re-reads.
    /// Used when a refunded purchase's number goes back to the pool, so a
    /// row the user replaced meanwhile (a new purchase) is never deleted.
    async fn delete_cipher_membership_if_version(
        &self,
        user_id: &str,
        expected: u64,
    ) -> Result<bool>;

    /// One page of memberships, revoked or not, ordered by `_id` (user id)
    /// ascending, only `_id > after_user_id` when given; `limit` 1..=500.
    /// A row that fails to decode fails the page (a sweep must not skip one).
    async fn fetch_cipher_memberships_page(
        &self,
        after_user_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<CipherMembership>>;
}

#[cfg(test)]
mod tests {
    use crate::{CipherMembership, CipherRevokeReason};
    use revolt_models::v0;

    fn membership(user_id: &str, number: u32) -> CipherMembership {
        CipherMembership {
            user_id: user_id.to_string(),
            number,
            tier: v0::CipherTier::T99,
            prot_grant: 16_500,
            orders: vec![format!("order-{user_id}")],
            disputed_orders: vec![],
            granted_at: 1_000_000,
            revoked_at: None,
            revoke_reason: None,
            prot_posted_at: None,
            version: 0,
        }
    }

    /// Install the unique `number` index on MongoDB.
    ///
    /// `database_test!` connects to a fresh database with no migrations run.
    /// This spec MUST stay identical to the one in
    /// `admin_migrations/ops/mongodb/scripts.rs` and `init.rs`. The reference
    /// driver enforces one row per number in code, so it needs no setup.
    async fn create_cipher_membership_indexes(db: &crate::Database) {
        match db {
            crate::Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                mongo
                    .db()
                    .run_command(bson::doc! {
                        "createIndexes": "cipher_memberships",
                        "indexes": [
                            {
                                "key": { "number": 1_i32 },
                                "name": "cipher_memberships_number_unique",
                                "unique": true
                            }
                        ]
                    })
                    .await
                    .expect("failed to create cipher_memberships indexes");
            }
        }
    }

    #[tokio::test]
    async fn insert_fetch_update_delete() {
        database_test!(|db| async move {
            let mut row = membership("01USERA0000000000000000000", 1);
            assert!(db.insert_cipher_membership(&row).await.unwrap());
            assert_eq!(
                db.fetch_cipher_membership(&row.user_id).await.unwrap(),
                Some(row.clone())
            );

            row.tier = v0::CipherTier::T299;
            row.prot_grant = 75_000;
            row.orders.push("order-upgrade".to_string());
            row.disputed_orders.push("order-upgrade".to_string());
            assert!(db
                .update_cipher_membership_if_version(&row, 0)
                .await
                .unwrap());

            // Written in full, with the version bumped by the store
            row.version = 1;
            assert_eq!(
                db.fetch_cipher_membership(&row.user_id).await.unwrap(),
                Some(row.clone())
            );

            // The next writer works from version 1
            row.prot_posted_at = Some(2_000_000);
            assert!(db
                .update_cipher_membership_if_version(&row, 1)
                .await
                .unwrap());
            row.version = 2;
            assert_eq!(
                db.fetch_cipher_membership(&row.user_id).await.unwrap(),
                Some(row.clone())
            );

            db.delete_cipher_membership(&row.user_id).await.unwrap();
            assert_eq!(
                db.fetch_cipher_membership(&row.user_id).await.unwrap(),
                None
            );

            // The account-deletion cascade may run twice
            db.delete_cipher_membership(&row.user_id).await.unwrap();
        });
    }

    #[tokio::test]
    async fn a_stale_version_is_refused_and_the_row_is_unchanged() {
        database_test!(|db| async move {
            let read = membership("01USERF0000000000000000000", 6);
            assert!(db.insert_cipher_membership(&read).await.unwrap());

            // Two writers read version 0; the first one wins
            let mut first = read.clone();
            first.tier = v0::CipherTier::T149;
            first.orders.push("order-upgrade".to_string());
            assert!(db
                .update_cipher_membership_if_version(&first, 0)
                .await
                .unwrap());

            // The second (a revoke built from the old read) loses instead of
            // silently dropping the upgrade
            let mut second = read.clone();
            second.revoked_at = Some(3_000_000);
            second.revoke_reason = Some(CipherRevokeReason::Refund);
            assert!(!db
                .update_cipher_membership_if_version(&second, 0)
                .await
                .unwrap());
            // A version the row has not reached yet never matches either
            assert!(!db
                .update_cipher_membership_if_version(&second, 2)
                .await
                .unwrap());

            first.version = 1;
            assert_eq!(
                db.fetch_cipher_membership(&read.user_id).await.unwrap(),
                Some(first)
            );
        });
    }

    #[tokio::test]
    async fn expected_zero_matches_a_row_stored_without_a_version() {
        database_test!(|db| async move {
            let row = membership("01USERG0000000000000000000", 7);

            match &db {
                // This driver has no absent field: the row reads as 0
                crate::Database::Reference(_) => {
                    assert!(db.insert_cipher_membership(&row).await.unwrap());
                }
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(mongo) => {
                    // A row written before `version` existed
                    let mut raw = bson::to_document(&row).unwrap();
                    raw.remove("version");
                    assert!(!raw.contains_key("version"));
                    mongo
                        .col::<bson::Document>("cipher_memberships")
                        .insert_one(raw)
                        .await
                        .unwrap();
                }
            }

            assert_eq!(
                db.fetch_cipher_membership(&row.user_id)
                    .await
                    .unwrap()
                    .map(|stored| stored.version),
                Some(0)
            );

            let mut updated = row.clone();
            updated.prot_posted_at = Some(2_000_000);
            assert!(db
                .update_cipher_membership_if_version(&updated, 0)
                .await
                .unwrap());

            // Now at 1: the absent-or-zero match no longer applies
            assert!(!db
                .update_cipher_membership_if_version(&row, 0)
                .await
                .unwrap());
            updated.version = 1;
            assert_eq!(
                db.fetch_cipher_membership(&row.user_id).await.unwrap(),
                Some(updated)
            );
        });
    }

    #[tokio::test]
    async fn a_revoked_row_is_replaced_by_compare_and_swap_not_insert() {
        database_test!(|db| async move {
            create_cipher_membership_indexes(&db).await;

            let user_id = "01USERH0000000000000000000";
            let mut revoked = membership(user_id, 8);
            assert!(db.insert_cipher_membership(&revoked).await.unwrap());
            revoked.revoked_at = Some(2_000_000);
            revoked.revoke_reason = Some(CipherRevokeReason::Refund);
            assert!(db
                .update_cipher_membership_if_version(&revoked, 0)
                .await
                .unwrap());
            revoked.version = 1;

            // Re-purchase: the old row is still there, so insert refuses
            let mut fresh = membership(user_id, 9);
            fresh.orders = vec!["order-repurchase".to_string()];
            fresh.granted_at = 4_000_000;
            assert!(!db.insert_cipher_membership(&fresh).await.unwrap());
            assert_eq!(
                db.fetch_cipher_membership(user_id).await.unwrap(),
                Some(revoked.clone())
            );

            // Replacing it from the version just read works
            assert!(db
                .update_cipher_membership_if_version(&fresh, revoked.version)
                .await
                .unwrap());
            let stored = db.fetch_cipher_membership(user_id).await.unwrap().unwrap();
            assert!(stored.is_active());
            assert_eq!(stored.number, 9);
            assert_eq!(stored.version, 2);
            assert_eq!(
                stored,
                CipherMembership {
                    version: 2,
                    ..fresh
                }
            );
        });
    }

    #[tokio::test]
    async fn duplicate_user_returns_false_and_keeps_the_first_row() {
        database_test!(|db| async move {
            let first = membership("01USERB0000000000000000000", 2);
            assert!(db.insert_cipher_membership(&first).await.unwrap());

            let mut second = membership("01USERB0000000000000000000", 3);
            second.tier = v0::CipherTier::T299;
            assert!(!db.insert_cipher_membership(&second).await.unwrap());

            assert_eq!(
                db.fetch_cipher_membership(&first.user_id).await.unwrap(),
                Some(first)
            );
        });
    }

    #[tokio::test]
    async fn number_held_by_another_user_is_an_error() {
        database_test!(|db| async move {
            create_cipher_membership_indexes(&db).await;

            let first = membership("01USERC0000000000000000000", 4);
            assert!(db.insert_cipher_membership(&first).await.unwrap());

            // Not Ok(false): the caller would read that as "this user is
            // already a member" and skip granting anything
            let other = membership("01USERD0000000000000000000", 4);
            assert!(db.insert_cipher_membership(&other).await.is_err());
            assert_eq!(
                db.fetch_cipher_membership(&other.user_id).await.unwrap(),
                None
            );

            // Same on a replace: moving another row onto a held number
            let mut moved = membership("01USERD0000000000000000000", 10);
            assert!(db.insert_cipher_membership(&moved).await.unwrap());
            moved.number = 4;
            assert!(db
                .update_cipher_membership_if_version(&moved, 0)
                .await
                .is_err());
            assert_eq!(
                db.fetch_cipher_membership(&moved.user_id)
                    .await
                    .unwrap()
                    .map(|stored| (stored.number, stored.version)),
                Some((10, 0))
            );
        });
    }

    #[tokio::test]
    async fn compare_and_swap_delete_needs_the_version_read() {
        database_test!(|db| async move {
            create_cipher_membership_indexes(&db).await;

            let user_id = "01USERI0000000000000000000";
            let read = membership(user_id, 11);
            assert!(db.insert_cipher_membership(&read).await.unwrap());

            // The row moved on (e.g. the user bought again): a delete built
            // from the old read is refused and the row is unchanged
            let mut moved = read.clone();
            moved.orders = vec!["order-repurchase".to_string()];
            assert!(db
                .update_cipher_membership_if_version(&moved, 0)
                .await
                .unwrap());
            assert!(!db
                .delete_cipher_membership_if_version(user_id, 0)
                .await
                .unwrap());
            assert!(!db
                .delete_cipher_membership_if_version(user_id, 2)
                .await
                .unwrap());
            assert_eq!(
                db.fetch_cipher_membership(user_id)
                    .await
                    .unwrap()
                    .map(|stored| stored.orders),
                Some(vec!["order-repurchase".to_string()])
            );

            // The version just read deletes it; the number is free again
            assert!(db
                .delete_cipher_membership_if_version(user_id, 1)
                .await
                .unwrap());
            assert_eq!(db.fetch_cipher_membership(user_id).await.unwrap(), None);
            assert!(db
                .insert_cipher_membership(&membership("01USERJ0000000000000000000", 11))
                .await
                .unwrap());

            // A missing row is false, not an error
            assert!(!db
                .delete_cipher_membership_if_version(user_id, 1)
                .await
                .unwrap());

            // Expected 0 also matches a row stored without a version
            let legacy = membership("01USERK0000000000000000000", 12);
            match &db {
                crate::Database::Reference(_) => {
                    assert!(db.insert_cipher_membership(&legacy).await.unwrap());
                }
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(mongo) => {
                    let mut raw = bson::to_document(&legacy).unwrap();
                    raw.remove("version");
                    mongo
                        .col::<bson::Document>("cipher_memberships")
                        .insert_one(raw)
                        .await
                        .unwrap();
                }
            }
            assert!(db
                .delete_cipher_membership_if_version(&legacy.user_id, 0)
                .await
                .unwrap());
            assert_eq!(
                db.fetch_cipher_membership(&legacy.user_id).await.unwrap(),
                None
            );
        });
    }

    #[tokio::test]
    async fn compare_and_swap_on_a_missing_row_is_false_and_never_upserts() {
        database_test!(|db| async move {
            let row = membership("01USERE0000000000000000000", 5);
            assert!(!db
                .update_cipher_membership_if_version(&row, 0)
                .await
                .unwrap());
            assert_eq!(
                db.fetch_cipher_membership(&row.user_id).await.unwrap(),
                None
            );
        });
    }

    #[tokio::test]
    async fn fetch_by_number_finds_the_holder_revoked_or_not() {
        database_test!(|db| async move {
            create_cipher_membership_indexes(&db).await;

            let active = membership("01USERL0000000000000000000", 13);
            let mut revoked = membership("01USERM0000000000000000000", 14);
            assert!(db.insert_cipher_membership(&active).await.unwrap());
            assert!(db.insert_cipher_membership(&revoked).await.unwrap());
            revoked.revoked_at = Some(2_000_000);
            revoked.revoke_reason = Some(CipherRevokeReason::Admin);
            assert!(db
                .update_cipher_membership_if_version(&revoked, 0)
                .await
                .unwrap());
            revoked.version = 1;

            assert_eq!(
                db.fetch_cipher_membership_by_number(13).await.unwrap(),
                Some(active.clone())
            );
            assert_eq!(
                db.fetch_cipher_membership_by_number(14).await.unwrap(),
                Some(revoked)
            );
            assert_eq!(
                db.fetch_cipher_membership_by_number(15).await.unwrap(),
                None
            );

            // Gone once the row is deleted
            db.delete_cipher_membership(&active.user_id).await.unwrap();
            assert_eq!(
                db.fetch_cipher_membership_by_number(13).await.unwrap(),
                None
            );
        });
    }

    /// Run one version bump the way the Prot ledger does: the MongoDB method
    /// in a session of its own (no transaction), or the Reference function on
    /// the locked map, imported by the path `models/prot` uses
    async fn bump_version(db: &crate::Database, user_id: &str, expected: u64) -> bool {
        match db {
            crate::Database::Reference(reference) => {
                let mut memberships = reference.cipher_memberships.lock().await;
                crate::models::cipher_memberships::bump_cipher_membership_version_locked(
                    &mut memberships,
                    user_id,
                    expected,
                )
            }
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                let mut session = mongo.start_session().await.unwrap();
                mongo
                    .bump_cipher_membership_version_in(&mut session, user_id, expected)
                    .await
                    .unwrap()
            }
        }
    }

    fn user_ids(rows: &[CipherMembership]) -> Vec<&str> {
        rows.iter().map(|row| row.user_id.as_str()).collect()
    }

    #[tokio::test]
    async fn memberships_page_walks_every_row_in_user_id_order() {
        database_test!(|db| async move {
            create_cipher_membership_indexes(&db).await;

            // Inserted out of order
            let ids = [
                "01USERPC000000000000000000",
                "01USERPA000000000000000000",
                "01USERPE000000000000000000",
                "01USERPB000000000000000000",
                "01USERPD000000000000000000",
            ];
            for (index, user_id) in ids.iter().enumerate() {
                assert!(db
                    .insert_cipher_membership(&membership(user_id, 100 + index as u32))
                    .await
                    .unwrap());
            }

            // A revoked row is listed like any other
            let mut revoked = membership(ids[3], 103);
            revoked.revoked_at = Some(2_000_000);
            revoked.revoke_reason = Some(CipherRevokeReason::Refund);
            assert!(db
                .update_cipher_membership_if_version(&revoked, 0)
                .await
                .unwrap());
            revoked.version = 1;

            // The sweep's walk: each page starts after the last id of the one before
            let mut walked = Vec::new();
            let mut sizes = Vec::new();
            let mut after: Option<String> = None;
            loop {
                let page = db
                    .fetch_cipher_memberships_page(after.as_deref(), 2)
                    .await
                    .unwrap();
                if page.is_empty() {
                    break;
                }
                sizes.push(page.len());
                after = page.last().map(|row| row.user_id.clone());
                walked.extend(page);
            }
            assert_eq!(sizes, vec![2, 2, 1]);

            let mut sorted = ids.to_vec();
            sorted.sort();
            assert_eq!(user_ids(&walked), sorted);

            // Rows come back whole
            assert!(walked.contains(&revoked));
            assert!(walked.contains(&membership(ids[1], 101)));

            // `after` is exclusive, and need not be a stored id
            let page = db
                .fetch_cipher_memberships_page(Some(ids[3]), 500)
                .await
                .unwrap();
            assert_eq!(user_ids(&page), vec![ids[0], ids[4], ids[2]]);
            let page = db
                .fetch_cipher_memberships_page(Some("01USERPBZ"), 500)
                .await
                .unwrap();
            assert_eq!(user_ids(&page), vec![ids[0], ids[4], ids[2]]);
            assert!(db
                .fetch_cipher_memberships_page(Some(ids[2]), 500)
                .await
                .unwrap()
                .is_empty());
        });
    }

    #[tokio::test]
    async fn memberships_page_refuses_a_limit_outside_1_to_500() {
        database_test!(|db| async move {
            assert!(db
                .insert_cipher_membership(&membership("01USERPF000000000000000000", 110))
                .await
                .unwrap());

            // 0 and negative limits mean something else to MongoDB, and a
            // page is never unbounded
            for limit in [0, -1, 501, i64::MAX, i64::MIN] {
                let error = db
                    .fetch_cipher_memberships_page(None, limit)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error.error_type, revolt_result::ErrorType::InternalError),
                    "limit {limit}"
                );
            }

            for limit in [1, 500] {
                assert_eq!(
                    db.fetch_cipher_memberships_page(None, limit)
                        .await
                        .unwrap()
                        .len(),
                    1
                );
            }
        });
    }

    #[tokio::test]
    async fn memberships_page_fails_on_a_row_that_does_not_decode() {
        database_test!(|db| async move {
            let good = membership("01USERPG000000000000000000", 111);
            assert!(db.insert_cipher_membership(&good).await.unwrap());

            match &db {
                // This driver only holds typed rows
                crate::Database::Reference(_) => {}
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(mongo) => {
                    // A row with a tier this binary does not know
                    let bad = "01USERPH000000000000000000";
                    let mut raw = bson::to_document(&membership(bad, 112)).unwrap();
                    raw.insert("tier", "T0");
                    mongo
                        .col::<bson::Document>("cipher_memberships")
                        .insert_one(raw)
                        .await
                        .unwrap();

                    // An error, not a short page the sweep would read as the end
                    assert!(db.fetch_cipher_memberships_page(None, 500).await.is_err());

                    // Pages that do not reach the row still read
                    assert_eq!(
                        db.fetch_cipher_memberships_page(None, 1).await.unwrap(),
                        vec![good.clone()]
                    );
                    assert!(db
                        .fetch_cipher_memberships_page(Some(bad), 500)
                        .await
                        .unwrap()
                        .is_empty());
                }
            }
        });
    }

    #[tokio::test]
    async fn version_bump_changes_only_the_version() {
        database_test!(|db| async move {
            let user_id = "01USERVA000000000000000000";
            let mut row = membership(user_id, 120);
            row.orders.push("order-upgrade".to_string());
            row.disputed_orders.push("order-upgrade".to_string());
            row.prot_posted_at = Some(1_500_000);
            assert!(db.insert_cipher_membership(&row).await.unwrap());

            assert!(bump_version(&db, user_id, 0).await);
            row.version = 1;
            assert_eq!(
                db.fetch_cipher_membership(user_id).await.unwrap(),
                Some(row.clone())
            );

            // A stale version, or one the row has not reached, changes nothing
            assert!(!bump_version(&db, user_id, 0).await);
            assert!(!bump_version(&db, user_id, 2).await);
            assert_eq!(
                db.fetch_cipher_membership(user_id).await.unwrap(),
                Some(row.clone())
            );

            // It serializes against the engine's compare-and-swap writes: one
            // built from the read before the bump loses
            let mut engine = row.clone();
            engine.tier = v0::CipherTier::T299;
            assert!(!db
                .update_cipher_membership_if_version(&engine, 0)
                .await
                .unwrap());
            assert!(db
                .update_cipher_membership_if_version(&engine, 1)
                .await
                .unwrap());

            // And a bump from before the engine's write loses in turn
            assert!(!bump_version(&db, user_id, 1).await);
            assert!(bump_version(&db, user_id, 2).await);
            engine.version = 3;
            assert_eq!(
                db.fetch_cipher_membership(user_id).await.unwrap(),
                Some(engine)
            );
        });
    }

    #[tokio::test]
    async fn version_bump_on_a_missing_row_is_false_and_never_upserts() {
        database_test!(|db| async move {
            let user_id = "01USERVB000000000000000000";
            assert!(!bump_version(&db, user_id, 0).await);
            assert_eq!(db.fetch_cipher_membership(user_id).await.unwrap(), None);

            // Deleted after it was read (the account-deletion cascade)
            assert!(db
                .insert_cipher_membership(&membership(user_id, 121))
                .await
                .unwrap());
            db.delete_cipher_membership(user_id).await.unwrap();
            assert!(!bump_version(&db, user_id, 0).await);
            assert_eq!(db.fetch_cipher_membership(user_id).await.unwrap(), None);
        });
    }

    #[tokio::test]
    async fn version_bump_expected_zero_matches_a_row_stored_without_a_version() {
        database_test!(|db| async move {
            let row = membership("01USERVC000000000000000000", 122);

            match &db {
                // This driver has no absent field: the row reads as 0
                crate::Database::Reference(_) => {
                    assert!(db.insert_cipher_membership(&row).await.unwrap());
                }
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(mongo) => {
                    // A row written before `version` existed
                    let mut raw = bson::to_document(&row).unwrap();
                    raw.remove("version");
                    mongo
                        .col::<bson::Document>("cipher_memberships")
                        .insert_one(raw)
                        .await
                        .unwrap();
                }
            }

            assert!(bump_version(&db, &row.user_id, 0).await);
            assert_eq!(
                db.fetch_cipher_membership(&row.user_id).await.unwrap(),
                Some(CipherMembership {
                    version: 1,
                    ..row.clone()
                })
            );

            match &db {
                crate::Database::Reference(_) => {}
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(mongo) => {
                    // Stored as Int64, the encoding the compare-and-swap
                    // filters match on
                    let stored = mongo
                        .col::<bson::Document>("cipher_memberships")
                        .find_one(bson::doc! { "_id": &row.user_id })
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(stored.get("version"), Some(&bson::Bson::Int64(1)));
                }
            }

            // Now at 1: the absent-or-zero match no longer applies
            assert!(!bump_version(&db, &row.user_id, 0).await);
        });
    }

    /// The Prot ledger's use of the session methods: the read and the bump
    /// inside one transaction. Transactions need a replica set, as every Prot
    /// write does (the compose file runs `--replSet rs0`).
    #[tokio::test]
    async fn version_bump_in_a_transaction_commits_or_aborts_with_it() {
        database_test!(|db| async move {
            match &db {
                // No sessions here; its twin runs under the map lock
                crate::Database::Reference(_) => {}
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(mongo) => {
                    let user_id = "01USERVD000000000000000000";
                    let row = membership(user_id, 123);
                    assert!(db.insert_cipher_membership(&row).await.unwrap());

                    let mut session = mongo.start_session().await.unwrap();

                    // Aborted: nothing lands
                    session
                        .start_transaction()
                        .read_concern(::mongodb::options::ReadConcern::snapshot())
                        .await
                        .unwrap();
                    assert_eq!(
                        mongo
                            .fetch_cipher_membership_in(&mut session, user_id)
                            .await
                            .unwrap(),
                        Some(row.clone())
                    );
                    assert!(mongo
                        .bump_cipher_membership_version_in(&mut session, user_id, 0)
                        .await
                        .unwrap());
                    assert_eq!(
                        mongo
                            .fetch_cipher_membership_in(&mut session, user_id)
                            .await
                            .unwrap()
                            .map(|stored| stored.version),
                        Some(1)
                    );
                    session.abort_transaction().await.unwrap();
                    assert_eq!(
                        db.fetch_cipher_membership(user_id).await.unwrap(),
                        Some(row.clone())
                    );

                    // Committed: the bump lands
                    session
                        .start_transaction()
                        .read_concern(::mongodb::options::ReadConcern::snapshot())
                        .await
                        .unwrap();
                    assert!(mongo
                        .bump_cipher_membership_version_in(&mut session, user_id, 0)
                        .await
                        .unwrap());
                    session.commit_transaction().await.unwrap();
                    assert_eq!(
                        db.fetch_cipher_membership(user_id).await.unwrap(),
                        Some(CipherMembership {
                            version: 1,
                            ..row.clone()
                        })
                    );

                    // An engine write that commits after the transaction read
                    // the row: the bump is refused, never applied over it. It
                    // is a write conflict, returned with the label that tells
                    // the Prot transaction helper to re-run the transaction.
                    session
                        .start_transaction()
                        .read_concern(::mongodb::options::ReadConcern::snapshot())
                        .await
                        .unwrap();
                    let read = mongo
                        .fetch_cipher_membership_in(&mut session, user_id)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(read.version, 1);
                    let mut engine = read.clone();
                    engine.tier = v0::CipherTier::T299;
                    assert!(db
                        .update_cipher_membership_if_version(&engine, 1)
                        .await
                        .unwrap());
                    let conflict = mongo
                        .bump_cipher_membership_version_in(&mut session, user_id, read.version)
                        .await
                        .expect_err("a write conflict, not a filter miss");
                    assert!(
                        conflict.contains_label(::mongodb::error::TRANSIENT_TRANSACTION_ERROR),
                        "{conflict:?}"
                    );
                    let _ = session.abort_transaction().await;
                    engine.version = 2;
                    assert_eq!(
                        db.fetch_cipher_membership(user_id).await.unwrap(),
                        Some(engine)
                    );

                    // A missing row inside a transaction
                    let missing = "01USERVE000000000000000000";
                    session.start_transaction().await.unwrap();
                    assert_eq!(
                        mongo
                            .fetch_cipher_membership_in(&mut session, missing)
                            .await
                            .unwrap(),
                        None
                    );
                    assert!(!mongo
                        .bump_cipher_membership_version_in(&mut session, missing, 0)
                        .await
                        .unwrap());
                    session.abort_transaction().await.unwrap();
                    assert_eq!(db.fetch_cipher_membership(missing).await.unwrap(), None);
                }
            }
        });
    }
}
