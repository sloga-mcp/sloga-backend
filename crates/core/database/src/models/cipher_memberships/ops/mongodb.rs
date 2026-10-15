use bson::Document;
use revolt_result::Result;

use crate::CipherMembership;
use crate::MongoDb;

use super::AbstractCipherMemberships;

static COL: &str = "cipher_memberships";

/// Whether a Mongo error is a duplicate key violation
fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    matches!(
        *error.kind,
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
            ref write_error,
        )) if write_error.code == 11000
    )
}

#[async_trait]
impl AbstractCipherMemberships for MongoDb {
    async fn insert_cipher_membership(&self, m: &CipherMembership) -> Result<bool> {
        match self.col::<CipherMembership>(COL).insert_one(m).await {
            Ok(_) => Ok(true),
            Err(error) if is_duplicate_key(&error) => {
                // Two unique keys can refuse this insert: `_id` (the user
                // already has a row, the expected duplicate) and `number`
                // (another user holds it, a broken invariant that must not
                // read as "already a member").
                let existing = self
                    .col::<Document>(COL)
                    .find_one(doc! {
                        "_id": &m.user_id
                    })
                    .await
                    .map_err(|_| create_database_error!("find_one", COL))?;

                if existing.is_some() {
                    Ok(false)
                } else {
                    Err(create_database_error!("insert_one", COL))
                }
            }
            Err(_) => Err(create_database_error!("insert_one", COL)),
        }
    }

    async fn fetch_cipher_membership(&self, user_id: &str) -> Result<Option<CipherMembership>> {
        query!(self, find_one_by_id, COL, user_id)
    }

    async fn update_cipher_membership_if_version(
        &self,
        m: &CipherMembership,
        expected: u64,
    ) -> Result<bool> {
        let next = expected
            .checked_add(1)
            .ok_or_else(|| create_database_error!("replace_one", COL))?;
        // bson stores a u64 as Int64; Mongo compares numbers across types
        let expected_bson =
            i64::try_from(expected).map_err(|_| create_database_error!("replace_one", COL))?;

        // Filter + replace under one document lock: a writer that read the
        // row before another bumped the version cannot overwrite it. Only
        // one `_id` key (a second one would replace the first).
        let filter = if expected == 0 {
            // A row written before `version` existed has no such field
            doc! {
                "_id": &m.user_id,
                "$or": [
                    { "version": 0_i64 },
                    { "version": { "$exists": false } }
                ]
            }
        } else {
            doc! {
                "_id": &m.user_id,
                "version": expected_bson
            }
        };

        let row = CipherMembership {
            version: next,
            ..m.clone()
        };

        // No upsert, so a missing row is `false`. A number held by another
        // user's row fails on the unique index, as on insert.
        self.col::<CipherMembership>(COL)
            .replace_one(filter, &row)
            .await
            .map(|result| result.matched_count == 1)
            .map_err(|_| create_database_error!("replace_one", COL))
    }

    async fn delete_cipher_membership(&self, user_id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .delete_one(doc! {
                "_id": user_id
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_one", COL))
    }
}
