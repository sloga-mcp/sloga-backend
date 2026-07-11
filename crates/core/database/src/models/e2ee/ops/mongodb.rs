use bson::{to_document, Document};
use iso8601_timestamp::Timestamp;
use mongodb::options::FindOptions;
use revolt_result::Result;

use futures::StreamExt;

use crate::{AbstractE2EE, E2EEBackup, E2EEBlob, E2EEEnvelope, E2EEIdentity, E2EEOneTimeKey, MongoDb};

const COL_IDENTITY: &str = "e2ee_identity";
const COL_PREKEYS: &str = "e2ee_prekeys";
const COL_QUEUE: &str = "e2ee_queue";
const COL_BLOBS: &str = "e2ee_blobs";
const COL_BACKUPS: &str = "e2ee_backups";

#[async_trait]
impl AbstractE2EE for MongoDb {
    async fn fetch_e2ee_identity(&self, user_id: &str, device_id: &str) -> Result<E2EEIdentity> {
        query!(
            self,
            find_one,
            COL_IDENTITY,
            doc! {
                "user_id": user_id,
                "device_id": device_id
            }
        )?
        .ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_e2ee_identities(&self, user_id: &str) -> Result<Vec<E2EEIdentity>> {
        query!(
            self,
            find,
            COL_IDENTITY,
            doc! {
                "user_id": user_id
            }
        )
    }

    async fn insert_e2ee_identity(&self, identity: &E2EEIdentity) -> Result<()> {
        // Plain insert: the unique index on (user_id, device_id) and the
        // composite _id both reject a concurrent duplicate publish. Duplicates
        // are an expected race, surfaced as InvalidOperation rather than a
        // database error.
        self.col::<E2EEIdentity>(COL_IDENTITY)
            .insert_one(identity)
            .await
            .map_err(|error| match *error.kind {
                mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
                    ref write_error,
                )) if write_error.code == 11000 => create_error!(InvalidOperation),
                _ => create_database_error!("insert_one", COL_IDENTITY),
            })
            .map(|_| ())
    }

    async fn replace_e2ee_identity(&self, identity: &E2EEIdentity) -> Result<()> {
        self.col::<E2EEIdentity>(COL_IDENTITY)
            .replace_one(doc! { "_id": &identity.id }, identity)
            .await
            .map_err(|_| create_database_error!("replace_one", COL_IDENTITY))
            .and_then(|result| {
                if result.matched_count == 0 {
                    Err(create_error!(NotFound))
                } else {
                    Ok(())
                }
            })
    }

    async fn update_e2ee_identity_session(
        &self,
        user_id: &str,
        device_id: &str,
        session_id: &str,
        at: Timestamp,
    ) -> Result<()> {
        self.col::<E2EEIdentity>(COL_IDENTITY)
            .update_one(
                doc! {
                    "_id": E2EEIdentity::composite_id(user_id, device_id)
                },
                doc! {
                    "$set": {
                        "last_session_id": session_id,
                        "last_seen_at": bson::to_bson(&at)
                            .map_err(|_| create_database_error!("to_bson", COL_IDENTITY))?
                    }
                },
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL_IDENTITY))
            .and_then(|result| {
                if result.matched_count == 0 {
                    Err(create_error!(NotFound))
                } else {
                    Ok(())
                }
            })
    }

    async fn delete_e2ee_device(&self, user_id: &str, device_id: &str) -> Result<bool> {
        let existed = self
            .col::<E2EEIdentity>(COL_IDENTITY)
            .delete_one(doc! {
                "user_id": user_id,
                "device_id": device_id
            })
            .await
            .map_err(|_| create_database_error!("delete_one", COL_IDENTITY))?
            .deleted_count
            > 0;

        self.col::<Document>(COL_PREKEYS)
            .delete_many(doc! {
                "user_id": user_id,
                "device_id": device_id
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_PREKEYS))?;

        self.col::<Document>(COL_QUEUE)
            .delete_many(doc! {
                "recipient_user_id": user_id,
                "recipient_device_id": device_id
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_QUEUE))?;

        Ok(existed)
    }

    async fn delete_all_e2ee_devices(&self, user_id: &str) -> Result<Vec<String>> {
        let device_ids: Vec<String> = self
            .fetch_e2ee_identities(user_id)
            .await?
            .into_iter()
            .map(|identity| identity.device_id)
            .collect();

        for device_id in &device_ids {
            self.delete_e2ee_device(user_id, device_id).await?;
        }

        Ok(device_ids)
    }

    async fn insert_e2ee_one_time_keys(&self, keys: &[E2EEOneTimeKey]) -> Result<()> {
        for key in keys {
            let document = to_document(key)
                .map_err(|_| create_database_error!("to_document", COL_PREKEYS))?;

            self.col::<E2EEOneTimeKey>(COL_PREKEYS)
                .update_one(
                    doc! { "_id": &key.id },
                    doc! { "$set": document },
                )
                .with_options(
                    mongodb::options::UpdateOptions::builder()
                        .upsert(true)
                        .build(),
                )
                .await
                .map_err(|_| create_database_error!("upsert_one", COL_PREKEYS))?;
        }

        Ok(())
    }

    async fn delete_e2ee_one_time_keys(&self, user_id: &str, device_id: &str) -> Result<usize> {
        self.col::<Document>(COL_PREKEYS)
            .delete_many(doc! {
                "user_id": user_id,
                "device_id": device_id
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_PREKEYS))
            .map(|result| result.deleted_count as usize)
    }

    async fn count_e2ee_one_time_keys(&self, user_id: &str, device_id: &str) -> Result<u64> {
        self.col::<E2EEOneTimeKey>(COL_PREKEYS)
            .count_documents(doc! {
                "user_id": user_id,
                "device_id": device_id
            })
            .await
            .map_err(|_| create_database_error!("count_documents", COL_PREKEYS))
    }

    async fn count_e2ee_one_time_keys_among(
        &self,
        user_id: &str,
        device_id: &str,
        key_ids: &[String],
    ) -> Result<u64> {
        let ids: Vec<String> = key_ids
            .iter()
            .map(|key_id| E2EEOneTimeKey::composite_id(user_id, device_id, key_id))
            .collect();

        self.col::<E2EEOneTimeKey>(COL_PREKEYS)
            .count_documents(doc! {
                "_id": { "$in": ids }
            })
            .await
            .map_err(|_| create_database_error!("count_documents", COL_PREKEYS))
    }

    async fn consume_e2ee_one_time_key(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<E2EEOneTimeKey>> {
        // Atomic take: two concurrent fetchers can never receive the same key
        self.col::<E2EEOneTimeKey>(COL_PREKEYS)
            .find_one_and_delete(doc! {
                "user_id": user_id,
                "device_id": device_id
            })
            .await
            .map_err(|_| create_database_error!("find_one_and_delete", COL_PREKEYS))
    }

    async fn insert_e2ee_envelopes(&self, envelopes: &[E2EEEnvelope]) -> Result<()> {
        if envelopes.is_empty() {
            return Ok(());
        }

        self.col::<E2EEEnvelope>(COL_QUEUE)
            .insert_many(envelopes)
            .await
            .map_err(|_| create_database_error!("insert_many", COL_QUEUE))
            .map(|_| ())
    }

    async fn count_e2ee_envelopes(
        &self,
        recipient_user_id: &str,
        recipient_device_id: &str,
    ) -> Result<u64> {
        self.col::<E2EEEnvelope>(COL_QUEUE)
            .count_documents(doc! {
                "recipient_user_id": recipient_user_id,
                "recipient_device_id": recipient_device_id
            })
            .await
            .map_err(|_| create_database_error!("count_documents", COL_QUEUE))
    }

    async fn sum_e2ee_envelope_bytes(
        &self,
        recipient_user_id: &str,
        recipient_device_id: &str,
    ) -> Result<u64> {
        // $strLenBytes on the stored base64 text: the budget is accounted in
        // ENCODED bytes (documented at the enforcement site)
        let mut cursor = self
            .col::<Document>(COL_QUEUE)
            .aggregate(vec![
                doc! {
                    "$match": {
                        "recipient_user_id": recipient_user_id,
                        "recipient_device_id": recipient_device_id
                    }
                },
                doc! {
                    "$group": {
                        "_id": null,
                        "total": { "$sum": { "$strLenBytes": "$ciphertext" } }
                    }
                },
            ])
            .await
            .map_err(|_| create_database_error!("aggregate", COL_QUEUE))?;

        let total = match cursor.next().await {
            Some(Ok(document)) => document
                .get_i64("total")
                .or_else(|_| document.get_i32("total").map(i64::from))
                .unwrap_or(0),
            _ => 0,
        };

        Ok(total.max(0) as u64)
    }

    async fn fetch_e2ee_envelopes(
        &self,
        recipient_user_id: &str,
        recipient_device_id: &str,
        limit: i64,
    ) -> Result<Vec<E2EEEnvelope>> {
        Ok(self
            .col::<E2EEEnvelope>(COL_QUEUE)
            .find(doc! {
                "recipient_user_id": recipient_user_id,
                "recipient_device_id": recipient_device_id
            })
            .with_options(
                FindOptions::builder()
                    .sort(doc! { "_id": 1 })
                    .limit(limit)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find", COL_QUEUE))?
            .filter_map(|s| async { s.ok() })
            .collect::<Vec<E2EEEnvelope>>()
            .await)
    }

    async fn delete_e2ee_envelope(
        &self,
        id: &str,
        recipient_user_id: &str,
        recipient_device_id: &str,
    ) -> Result<bool> {
        self.col::<E2EEEnvelope>(COL_QUEUE)
            .delete_one(doc! {
                "_id": id,
                "recipient_user_id": recipient_user_id,
                "recipient_device_id": recipient_device_id
            })
            .await
            .map_err(|_| create_database_error!("delete_one", COL_QUEUE))
            .map(|result| result.deleted_count > 0)
    }

    async fn delete_e2ee_envelopes_before(&self, threshold_id: &str) -> Result<usize> {
        self.col::<Document>(COL_QUEUE)
            .delete_many(doc! {
                "_id": { "$lt": threshold_id }
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_QUEUE))
            .map(|result| result.deleted_count as usize)
    }

    async fn insert_e2ee_blob(&self, blob: &E2EEBlob) -> Result<()> {
        self.col::<E2EEBlob>(COL_BLOBS)
            .insert_one(blob)
            .await
            .map_err(|_| create_database_error!("insert_one", COL_BLOBS))
            .map(|_| ())
    }

    async fn fetch_e2ee_blob(&self, id: &str) -> Result<E2EEBlob> {
        query!(
            self,
            find_one,
            COL_BLOBS,
            doc! {
                "_id": id
            }
        )?
        .ok_or_else(|| create_error!(NotFound))
    }

    async fn mark_e2ee_blob_fetched(
        &self,
        id: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<E2EEBlob> {
        // Atomic array update: the filter requires a matching recipient
        // entry, so a non-recipient can never flip anything, and the
        // returned (post-update) document decides deletion exactly once
        // per fully-fetched state transition observed by a caller
        self.col::<E2EEBlob>(COL_BLOBS)
            .find_one_and_update(
                doc! {
                    "_id": id,
                    "recipients": {
                        "$elemMatch": {
                            "user_id": user_id,
                            "device_id": device_id
                        }
                    }
                },
                doc! {
                    "$set": { "recipients.$[entry].fetched": true }
                },
            )
            .with_options(
                mongodb::options::FindOneAndUpdateOptions::builder()
                    .array_filters(vec![doc! {
                        "entry.user_id": user_id,
                        "entry.device_id": device_id
                    }])
                    .return_document(mongodb::options::ReturnDocument::After)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_one_and_update", COL_BLOBS))?
            .ok_or_else(|| create_error!(NotFound))
    }

    async fn delete_e2ee_blob(&self, id: &str) -> Result<bool> {
        self.col::<E2EEBlob>(COL_BLOBS)
            .delete_one(doc! { "_id": id })
            .await
            .map_err(|_| create_database_error!("delete_one", COL_BLOBS))
            .map(|result| result.deleted_count > 0)
    }

    async fn fetch_expired_e2ee_blobs(
        &self,
        threshold_id: &str,
        min_size: isize,
    ) -> Result<Vec<E2EEBlob>> {
        Ok(self
            .col::<E2EEBlob>(COL_BLOBS)
            .find(doc! {
                "_id": { "$lt": threshold_id },
                "size": { "$gt": min_size as i64 }
            })
            .with_options(FindOptions::builder().sort(doc! { "_id": 1 }).build())
            .await
            .map_err(|_| create_database_error!("find", COL_BLOBS))?
            .filter_map(|s| async { s.ok() })
            .collect::<Vec<E2EEBlob>>()
            .await)
    }

    async fn fetch_e2ee_backup(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<E2EEBackup>> {
        query!(
            self,
            find_one,
            COL_BACKUPS,
            doc! {
                "user_id": user_id,
                "device_id": device_id
            }
        )
    }

    async fn fetch_e2ee_backups(&self, user_id: &str) -> Result<Vec<E2EEBackup>> {
        query!(
            self,
            find,
            COL_BACKUPS,
            doc! {
                "user_id": user_id
            }
        )
    }

    async fn upsert_e2ee_backup(&self, backup: &E2EEBackup) -> Result<()> {
        let document =
            to_document(backup).map_err(|_| create_database_error!("to_document", COL_BACKUPS))?;

        self.col::<E2EEBackup>(COL_BACKUPS)
            .update_one(
                doc! { "_id": &backup.id },
                doc! { "$set": document },
            )
            .with_options(
                mongodb::options::UpdateOptions::builder()
                    .upsert(true)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("upsert_one", COL_BACKUPS))
            .map(|_| ())
    }

    async fn delete_e2ee_backup(&self, user_id: &str, device_id: &str) -> Result<bool> {
        self.col::<Document>(COL_BACKUPS)
            .delete_one(doc! {
                "user_id": user_id,
                "device_id": device_id
            })
            .await
            .map_err(|_| create_database_error!("delete_one", COL_BACKUPS))
            .map(|result| result.deleted_count > 0)
    }

    async fn delete_all_e2ee_backups(&self, user_id: &str) -> Result<usize> {
        self.col::<Document>(COL_BACKUPS)
            .delete_many(doc! {
                "user_id": user_id
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_BACKUPS))
            .map(|result| result.deleted_count as usize)
    }
}
