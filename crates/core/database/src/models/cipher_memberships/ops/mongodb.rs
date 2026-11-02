use bson::Document;
use futures::TryStreamExt;
use revolt_result::Result;

use crate::CipherMembership;
use crate::MongoDb;

use super::AbstractCipherMemberships;
use super::MEMBERSHIPS_PAGE_MAX;

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

/// The compare-and-swap filter: the user's row at version `expected`
/// (`expected == 0` also matches a row stored before `version` existed).
/// Same match as `update_cipher_membership_if_version` and
/// `delete_cipher_membership_if_version`.
fn version_filter(user_id: &str, expected: u64) -> Result<Document> {
    // bson stores a u64 as Int64; Mongo compares numbers across types
    let expected_bson =
        i64::try_from(expected).map_err(|_| create_database_error!("version_filter", COL))?;

    // Only one `_id` key (a second one would replace the first)
    Ok(if expected == 0 {
        doc! {
            "_id": user_id,
            "$or": [
                { "version": 0_i64 },
                { "version": { "$exists": false } }
            ]
        }
    } else {
        doc! {
            "_id": user_id,
            "version": expected_bson
        }
    })
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

    async fn fetch_cipher_membership_by_number(
        &self,
        number: u32,
    ) -> Result<Option<CipherMembership>> {
        // bson stores the u32 as Int64; served by the unique `number` index
        self.col::<CipherMembership>(COL)
            .find_one(doc! {
                "number": i64::from(number)
            })
            .await
            .map_err(|_| create_database_error!("find_one", COL))
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

    async fn delete_cipher_membership_if_version(
        &self,
        user_id: &str,
        expected: u64,
    ) -> Result<bool> {
        let expected_bson =
            i64::try_from(expected).map_err(|_| create_database_error!("delete_one", COL))?;

        // Filter + delete under one document lock, with the same version
        // match as the compare-and-swap replace
        let filter = if expected == 0 {
            doc! {
                "_id": user_id,
                "$or": [
                    { "version": 0_i64 },
                    { "version": { "$exists": false } }
                ]
            }
        } else {
            doc! {
                "_id": user_id,
                "version": expected_bson
            }
        };

        self.col::<Document>(COL)
            .delete_one(filter)
            .await
            .map(|result| result.deleted_count == 1)
            .map_err(|_| create_database_error!("delete_one", COL))
    }

    async fn fetch_cipher_memberships_page(
        &self,
        after_user_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<CipherMembership>> {
        // 0 or a negative value would mean "no limit" or a single batch to
        // Mongo; neither is a page
        if !(1..=MEMBERSHIPS_PAGE_MAX).contains(&limit) {
            return Err(create_error!(InternalError));
        }

        let filter = match after_user_id {
            Some(after) => doc! {
                "_id": { "$gt": after }
            },
            None => doc! {},
        };

        // Walks the `_id` index. Rows are decoded as they are read, so one
        // that does not decode fails the page instead of being skipped.
        self.col::<CipherMembership>(COL)
            .find(filter)
            .sort(doc! { "_id": 1_i32 })
            .limit(limit)
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .try_collect()
            .await
            .map_err(|error| {
                log::error!("{COL}: failed to read a row of a page: {error}");
                create_database_error!("find", COL)
            })
    }
}

/// Session-aware membership reads and writes for the Prot ledger's
/// transactions. Not trait methods: the Reference driver has no session, and
/// uses `bump_cipher_membership_version_locked` on a map it holds instead.
///
/// Both return the driver's own error, so the caller can see its labels: a
/// TransientTransactionError (a write conflict, a failover) means the whole
/// transaction can be re-run from a fresh session, and the Prot transaction
/// helper does that within its time budget.
impl MongoDb {
    /// fetch_cipher_membership inside `session`
    pub(crate) async fn fetch_cipher_membership_in(
        &self,
        session: &mut mongodb::ClientSession,
        user_id: &str,
    ) -> std::result::Result<Option<CipherMembership>, mongodb::error::Error> {
        self.col::<CipherMembership>(COL)
            .find_one(doc! {
                "_id": user_id
            })
            .session(&mut *session)
            .await
    }

    /// Compare-and-swap that changes ONLY the version: `$set: { version: Int64(expected + 1) }`
    /// WHERE `_id = user_id` AND version matches `expected` (expected == 0 also matches a row
    /// without the field: `version_filter`, the same filter as
    /// update_cipher_membership_if_version). Ok(false) when the version moved or the row is gone.
    ///
    /// Inside a transaction, a row another writer changed after the
    /// transaction's snapshot fails with a write conflict (an error labelled
    /// TransientTransactionError) rather than a filter miss; it is returned
    /// as is. A version that does not fit in an Int64 is a custom error,
    /// which carries no label.
    pub(crate) async fn bump_cipher_membership_version_in(
        &self,
        session: &mut mongodb::ClientSession,
        user_id: &str,
        expected: u64,
    ) -> std::result::Result<bool, mongodb::error::Error> {
        // bson stores a u64 as Int64, so the next version must fit in one
        let next = expected
            .checked_add(1)
            .and_then(|next| i64::try_from(next).ok())
            .ok_or_else(|| mongodb::error::Error::custom("cipher_memberships: version overflow"))?;
        let filter = version_filter(user_id, expected)
            .map_err(|_| mongodb::error::Error::custom("cipher_memberships: version overflow"))?;

        // No upsert, so a missing row is `false`. Every other field is left
        // exactly as stored.
        self.col::<Document>(COL)
            .update_one(
                filter,
                doc! {
                    "$set": { "version": next }
                },
            )
            .session(&mut *session)
            .await
            .map(|result| result.matched_count == 1)
    }
}
