pub mod mongodb;
pub mod reference;

use revolt_result::Result;

use crate::CipherMembership;

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
}
