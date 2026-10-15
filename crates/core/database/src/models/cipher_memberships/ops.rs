pub mod mongodb;
pub mod reference;

use revolt_result::Result;

use crate::CipherMembership;

#[async_trait]
pub trait AbstractCipherMemberships: Sync + Send {
    /// Insert a membership; Ok(true) if inserted, Ok(false) if the user
    /// already has a row. A number already held by another user's row is
    /// an error, never Ok(false).
    async fn insert_cipher_membership(&self, m: &CipherMembership) -> Result<bool>;

    /// Fetch a user's membership, revoked or not
    async fn fetch_cipher_membership(&self, user_id: &str) -> Result<Option<CipherMembership>>;

    /// Replace a membership row in full; NotFound if it does not exist
    async fn update_cipher_membership(&self, m: &CipherMembership) -> Result<()>;

    /// Account-deletion cascade: delete a user's membership (Ok if absent)
    async fn delete_cipher_membership(&self, user_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use crate::CipherMembership;
    use revolt_models::v0;
    use revolt_result::ErrorType;

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
            db.update_cipher_membership(&row).await.unwrap();
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
        });
    }

    #[tokio::test]
    async fn update_of_a_missing_row_is_not_found() {
        database_test!(|db| async move {
            let row = membership("01USERE0000000000000000000", 5);
            let error = db
                .update_cipher_membership(&row)
                .await
                .expect_err("no row to replace");
            assert!(
                matches!(error.error_type, ErrorType::NotFound),
                "expected NotFound, got {:?}",
                error.error_type
            );
        });
    }
}
