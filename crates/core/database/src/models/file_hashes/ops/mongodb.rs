use bson::{Bson, Document};
use revolt_result::Result;

use crate::FileHash;
use crate::MongoDb;

use super::AbstractAttachmentHashes;

static COL: &str = "attachment_hashes";

/// Build the update that points a hash at its stored object.
///
/// Only path, iv and key_id are touched. A `None` key id unsets the field
/// rather than storing an explicit null.
fn storage_update(path: &str, iv: &str, key_id: Option<&str>) -> Document {
    match key_id {
        Some(key_id) => doc! {
            "$set": {
                "path": path,
                "iv": iv,
                "key_id": key_id
            }
        },
        None => doc! {
            "$set": {
                "path": path,
                "iv": iv
            },
            "$unset": {
                "key_id": ""
            }
        },
    }
}

#[async_trait]
impl AbstractAttachmentHashes for MongoDb {
    /// Insert a new attachment hash into the database.
    async fn insert_attachment_hash(&self, hash: &FileHash) -> Result<()> {
        query!(self, insert_one, COL, &hash).map(|_| ())
    }

    /// Fetch an attachment hash entry by sha256 hash.
    async fn fetch_attachment_hash(&self, hash: &str) -> Result<FileHash> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "$or": [
                    {"_id": hash},
                    {"processed_hash": hash}
                ]
            }
        )?
        .ok_or_else(|| create_error!(NotFound))
    }

    /// Point a hash at its stored object (path, iv and key id).
    async fn set_attachment_hash_storage(
        &self,
        hash: &str,
        path: &str,
        iv: &str,
        key_id: Option<&str>,
    ) -> Result<()> {
        self.col::<FileHash>(COL)
            .update_one(
                doc! {
                    "_id": hash
                },
                storage_update(path, iv, key_id),
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL))
            .and_then(|result| {
                if result.matched_count == 0 {
                    Err(create_error!(NotFound))
                } else {
                    Ok(())
                }
            })
    }

    /// Compare-and-swap the storage triple of a hash.
    ///
    /// A `None` old key id filters on null, which matches both a missing
    /// field and an explicit null. Returns whether the row matched.
    async fn swap_attachment_hash_storage(
        &self,
        hash: &str,
        old_path: &str,
        old_iv: &str,
        old_key_id: Option<&str>,
        new_path: &str,
        new_iv: &str,
        new_key_id: Option<&str>,
    ) -> Result<bool> {
        let old_key_id = match old_key_id {
            Some(key_id) => Bson::String(key_id.to_string()),
            None => Bson::Null,
        };

        self.col::<FileHash>(COL)
            .update_one(
                doc! {
                    "_id": hash,
                    "path": old_path,
                    "iv": old_iv,
                    "key_id": old_key_id
                },
                storage_update(new_path, new_iv, new_key_id),
            )
            .await
            .map(|result| result.matched_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Updates the attachments animated metadata value.
    ///
    /// The primary use for this is to update the metadata for existing uploaded files, this
    /// can only be used for images.
    async fn set_attachment_hash_animated(&self, hash: &str, animated: bool) -> Result<()> {
        self.col::<FileHash>(COL)
            .update_one(
                doc! {
                    "_id": hash,
                    "metadata.type": "Image",
                    "metadata.animated": { "$exists": false },
                },
                doc! {
                    "$set": {
                        "metadata.animated": animated
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Delete attachment hash by id.
    async fn delete_attachment_hash(&self, id: &str) -> Result<()> {
        query!(self, delete_one_by_id, COL, id).map(|_| ())
    }
}
