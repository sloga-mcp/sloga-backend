use bson::{Bson, Document};
use iso8601_timestamp::Timestamp;
use mongodb::options::FindOptions;
use revolt_result::Result;

use crate::{MongoDb, Passkey};

use super::AbstractPasskeys;

static COL: &str = "passkeys";

/// Typed writes store `Timestamp` as Int64 unix milliseconds; a hand-built
/// `$set` must use the same encoding (see `mls/ops/mongodb.rs`)
fn timestamp_ms(at: &Timestamp) -> Bson {
    Bson::Int64(
        at.duration_since(Timestamp::UNIX_EPOCH)
            .whole_milliseconds() as i64,
    )
}

#[async_trait]
impl AbstractPasskeys for MongoDb {
    async fn insert_passkey(&self, passkey: &Passkey) -> Result<()> {
        // `_id` and `credential_id` are both unique: either collision is an
        // error. The unique `credential_id` index is what refuses a
        // credential that is already registered, on any account.
        self.col::<Passkey>(COL)
            .insert_one(passkey)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("insert_one", COL))
    }

    async fn fetch_passkey(&self, user_id: &str, id: &str) -> Result<Passkey> {
        // The owner is part of the filter, so another user's id is NotFound
        self.col::<Passkey>(COL)
            .find_one(doc! {
                "_id": id,
                "user_id": user_id
            })
            .await
            .map_err(|_| create_database_error!("find_one", COL))?
            .ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_passkeys(&self, user_id: &str) -> Result<Vec<Passkey>> {
        self.find_with_options(
            COL,
            doc! {
                "user_id": user_id
            },
            FindOptions::builder()
                .sort(doc! { "created_at": 1_i32, "_id": 1_i32 })
                .build(),
        )
        .await
        .map_err(|_| create_database_error!("find", COL))
    }

    async fn fetch_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<Passkey>> {
        self.col::<Passkey>(COL)
            .find_one(doc! {
                "credential_id": credential_id
            })
            .await
            .map_err(|_| create_database_error!("find_one", COL))
    }

    async fn count_passkeys(&self, user_id: &str) -> Result<u64> {
        self.col::<Document>(COL)
            .count_documents(doc! {
                "user_id": user_id
            })
            .await
            .map_err(|_| create_database_error!("count_documents", COL))
    }

    async fn update_passkey_after_use(
        &self,
        id: &str,
        expected_credential: &str,
        credential: &str,
        last_used_at: Timestamp,
    ) -> Result<bool> {
        // The expected credential is part of the filter: a row whose state
        // moved on after it was read is not matched, so of two concurrent
        // assertions only one advances the counter. `matched_count`, not
        // `modified_count`: an unchanged counter (0 to 0) is still a use.
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id,
                    "credential": expected_credential
                },
                doc! {
                    "$set": {
                        "credential": credential,
                        "last_used_at": timestamp_ms(&last_used_at)
                    }
                },
            )
            .await
            .map(|result| result.matched_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    async fn rename_passkey(&self, user_id: &str, id: &str, name: &str) -> Result<()> {
        let result = self
            .col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id,
                    "user_id": user_id
                },
                doc! {
                    "$set": {
                        "name": name
                    }
                },
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL))?;

        if result.matched_count == 1 {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn delete_passkey(&self, user_id: &str, id: &str) -> Result<()> {
        let result = self
            .col::<Document>(COL)
            .delete_one(doc! {
                "_id": id,
                "user_id": user_id
            })
            .await
            .map_err(|_| create_database_error!("delete_one", COL))?;

        if result.deleted_count == 1 {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn delete_passkeys_for_user(&self, user_id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .delete_many(doc! { "user_id": user_id })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }
}
