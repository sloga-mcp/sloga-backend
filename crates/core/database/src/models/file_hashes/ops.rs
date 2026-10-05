use revolt_result::Result;

use crate::FileHash;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractAttachmentHashes: Sync + Send {
    /// Insert a new attachment hash into the database.
    async fn insert_attachment_hash(&self, hash: &FileHash) -> Result<()>;

    /// Fetch an attachment hash entry by sha256 hash.
    async fn fetch_attachment_hash(&self, hash: &str) -> Result<FileHash>;

    /// Point a hash at its stored object: $set path + iv; key_id Some => $set,
    /// None => $unset (never an explicit null).
    ///
    /// A missing row is NotFound.
    async fn set_attachment_hash_storage(
        &self,
        hash: &str,
        path: &str,
        iv: &str,
        key_id: Option<&str>,
    ) -> Result<()>;

    /// Compare-and-swap the storage triple.
    ///
    /// Filter {_id, path: old_path, iv: old_iv, key_id: old | Bson::Null}
    /// (Bson::Null matches absent AND explicit null). Update touches ONLY
    /// path/iv/key_id ($unset when new is None). Returns matched_count == 1,
    /// so a missing row or a row that has moved on is `Ok(false)`.
    #[allow(clippy::too_many_arguments)]
    async fn swap_attachment_hash_storage(
        &self,
        hash: &str,
        old_path: &str,
        old_iv: &str,
        old_key_id: Option<&str>,
        new_path: &str,
        new_iv: &str,
        new_key_id: Option<&str>,
    ) -> Result<bool>;

    /// Updates the attachments animated metadata value.
    ///
    /// The primary use for this is to update the metadata for existing uploaded files, this
    /// can only be used for images.
    async fn set_attachment_hash_animated(&self, hash: &str, animated: bool) -> Result<()>;

    /// Delete attachment hash by id.
    async fn delete_attachment_hash(&self, id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::AbstractAttachmentHashes;
    use crate::{FileHash, Metadata};
    use iso8601_timestamp::Timestamp;

    /// A full row; `processed_hash` differs from the id so lookups by id are
    /// unambiguous.
    fn file_hash(id: &str, path: &str, iv: &str, key_id: Option<&str>) -> FileHash {
        FileHash {
            id: id.to_string(),
            processed_hash: format!("processed-{id}"),
            created_at: Timestamp::now_utc(),
            bucket_id: "revolt-uploads".to_string(),
            path: path.to_string(),
            iv: iv.to_string(),
            format_version: Some(2),
            key_id: key_id.map(str::to_string),
            metadata: Metadata::Image {
                width: 640,
                height: 480,
                thumbhash: Some(vec![1, 2, 3]),
                animated: Some(false),
            },
            content_type: "image/png".to_string(),
            size: 4096,
        }
    }

    /// The row as stored, with only the storage triple replaced. Built from a
    /// fetched row so timestamps compare equal after a driver round trip.
    fn with_storage(row: &FileHash, path: &str, iv: &str, key_id: Option<&str>) -> FileHash {
        let mut row = row.clone();
        row.path = path.to_string();
        row.iv = iv.to_string();
        row.key_id = key_id.map(str::to_string);
        row
    }

    /// On MongoDB, assert the stored document has no `key_id` field at all
    /// (an `$unset`, never an explicit null). The reference driver has no raw
    /// document; `key_id: None` is all there is.
    #[cfg_attr(not(feature = "mongodb"), allow(unused_variables))]
    async fn assert_raw_key_id_absent(db: &crate::Database, id: &str) {
        match db {
            crate::Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                let raw = mongo
                    .col::<bson::Document>("attachment_hashes")
                    .find_one(bson::doc! { "_id": id })
                    .await
                    .unwrap()
                    .expect("row exists");
                assert!(
                    !raw.contains_key("key_id"),
                    "key_id must be absent, not null: {raw:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn set_storage_then_clear_key_id() {
        database_test!(|db| async move {
            db.insert_attachment_hash(&file_hash("hash-a", "hash-a", "iv-0", None))
                .await
                .unwrap();
            let original = db.fetch_attachment_hash("hash-a").await.unwrap();

            db.set_attachment_hash_storage("hash-a", "rk/k1/one", "iv-1", Some("k1"))
                .await
                .unwrap();
            let rotated = db.fetch_attachment_hash("hash-a").await.unwrap();
            assert_eq!(
                rotated,
                with_storage(&original, "rk/k1/one", "iv-1", Some("k1"))
            );

            db.set_attachment_hash_storage("hash-a", "rk/legacy/two", "iv-2", None)
                .await
                .unwrap();
            let cleared = db.fetch_attachment_hash("hash-a").await.unwrap();
            assert_eq!(cleared.key_id, None);
            assert_eq!(cleared.path, "rk/legacy/two");
            assert_eq!(cleared.iv, "iv-2");
            assert_eq!(cleared.metadata, original.metadata, "metadata untouched");
            assert_eq!(
                cleared,
                with_storage(&original, "rk/legacy/two", "iv-2", None)
            );
            assert_raw_key_id_absent(&db, "hash-a").await;
        });
    }

    #[tokio::test]
    async fn swap_storage_exact_match_succeeds() {
        database_test!(|db| async move {
            db.insert_attachment_hash(&file_hash("hash-b", "rk/k1/old", "iv-old", Some("k1")))
                .await
                .unwrap();
            let original = db.fetch_attachment_hash("hash-b").await.unwrap();

            assert!(db
                .swap_attachment_hash_storage(
                    "hash-b",
                    "rk/k1/old",
                    "iv-old",
                    Some("k1"),
                    "rk/k2/new",
                    "iv-new",
                    Some("k2"),
                )
                .await
                .unwrap());
            let swapped = db.fetch_attachment_hash("hash-b").await.unwrap();
            assert_eq!(
                swapped,
                with_storage(&original, "rk/k2/new", "iv-new", Some("k2"))
            );

            // Swapping back to legacy unsets the field
            assert!(db
                .swap_attachment_hash_storage(
                    "hash-b",
                    "rk/k2/new",
                    "iv-new",
                    Some("k2"),
                    "rk/legacy/back",
                    "iv-back",
                    None,
                )
                .await
                .unwrap());
            let back = db.fetch_attachment_hash("hash-b").await.unwrap();
            assert_eq!(
                back,
                with_storage(&original, "rk/legacy/back", "iv-back", None)
            );
            assert_raw_key_id_absent(&db, "hash-b").await;
        });
    }

    #[tokio::test]
    async fn swap_storage_stale_triple_is_refused() {
        database_test!(|db| async move {
            db.insert_attachment_hash(&file_hash("hash-c", "rk/k1/cur", "iv-cur", Some("k1")))
                .await
                .unwrap();
            db.insert_attachment_hash(&file_hash("hash-d", "hash-d", "iv-cur", None))
                .await
                .unwrap();
            let before_c = db.fetch_attachment_hash("hash-c").await.unwrap();
            let before_d = db.fetch_attachment_hash("hash-d").await.unwrap();

            // (row, old path, old iv, old key id): each differs from the row in
            // exactly one component
            let stale: [(&str, &str, &str, Option<&str>); 6] = [
                ("hash-c", "rk/k1/stale", "iv-cur", Some("k1")),
                ("hash-c", "rk/k1/cur", "iv-stale", Some("k1")),
                ("hash-c", "rk/k1/cur", "iv-cur", Some("k9")),
                // None must not match a row that carries a key id
                ("hash-c", "rk/k1/cur", "iv-cur", None),
                // A key id must not match a row whose key_id is absent
                ("hash-d", "hash-d", "iv-cur", Some("k1")),
                ("hash-d", "hash-d", "iv-stale", None),
            ];
            for (id, old_path, old_iv, old_key_id) in stale {
                assert!(
                    !db.swap_attachment_hash_storage(
                        id,
                        old_path,
                        old_iv,
                        old_key_id,
                        "rk/k2/new",
                        "iv-new",
                        Some("k2"),
                    )
                    .await
                    .unwrap(),
                    "stale swap applied: {id} {old_path} {old_iv} {old_key_id:?}"
                );
            }

            assert_eq!(db.fetch_attachment_hash("hash-c").await.unwrap(), before_c);
            assert_eq!(db.fetch_attachment_hash("hash-d").await.unwrap(), before_d);
        });
    }

    #[tokio::test]
    async fn swap_storage_from_absent_key_id() {
        database_test!(|db| async move {
            db.insert_attachment_hash(&file_hash("hash-e", "hash-e", "iv-0", None))
                .await
                .unwrap();
            assert_raw_key_id_absent(&db, "hash-e").await;
            let original = db.fetch_attachment_hash("hash-e").await.unwrap();

            assert!(db
                .swap_attachment_hash_storage(
                    "hash-e",
                    "hash-e",
                    "iv-0",
                    None,
                    "rk/k1/fresh",
                    "iv-1",
                    Some("k1"),
                )
                .await
                .unwrap());
            assert_eq!(
                db.fetch_attachment_hash("hash-e").await.unwrap(),
                with_storage(&original, "rk/k1/fresh", "iv-1", Some("k1"))
            );
        });
    }

    #[tokio::test]
    async fn swap_storage_missing_row_is_false() {
        database_test!(|db| async move {
            assert!(!db
                .swap_attachment_hash_storage(
                    "hash-missing",
                    "hash-missing",
                    "iv-0",
                    None,
                    "rk/k1/fresh",
                    "iv-1",
                    Some("k1"),
                )
                .await
                .unwrap());
            assert!(db.fetch_attachment_hash("hash-missing").await.is_err());
        });
    }

    /// A row written with an explicit `key_id: null` (not through this crate,
    /// which never writes one) still counts as legacy for the swap filter.
    /// MongoDB only: the reference driver has no raw document to hold a null.
    #[cfg(feature = "mongodb")]
    #[tokio::test]
    async fn swap_storage_matches_explicit_null_key_id() {
        database_test!(|db| async move {
            let crate::Database::MongoDb(mongo) = &db else {
                return;
            };
            use bson::{doc, Bson, Document};

            let hashes = mongo.col::<Document>("attachment_hashes");
            for id in ["hash-f", "hash-g"] {
                let mut raw = bson::to_document(&file_hash(id, id, "iv-0", None)).unwrap();
                raw.insert("key_id", Bson::Null);
                hashes.insert_one(raw).await.unwrap();
            }

            // Prove the control: the field is stored as an explicit null
            let raw = hashes
                .find_one(doc! { "_id": "hash-f" })
                .await
                .unwrap()
                .expect("row exists");
            assert_eq!(raw.get("key_id"), Some(&Bson::Null));
            let original = db.fetch_attachment_hash("hash-f").await.unwrap();
            assert_eq!(original.key_id, None);

            assert!(db
                .swap_attachment_hash_storage(
                    "hash-f",
                    "hash-f",
                    "iv-0",
                    None,
                    "rk/k1/fresh",
                    "iv-1",
                    Some("k1"),
                )
                .await
                .unwrap());
            let raw = hashes
                .find_one(doc! { "_id": "hash-f" })
                .await
                .unwrap()
                .expect("row exists");
            assert_eq!(raw.get("key_id"), Some(&Bson::String("k1".to_string())));
            assert_eq!(
                db.fetch_attachment_hash("hash-f").await.unwrap(),
                with_storage(&original, "rk/k1/fresh", "iv-1", Some("k1"))
            );

            // Setting legacy storage on an explicit-null row removes the field
            db.set_attachment_hash_storage("hash-g", "rk/legacy/two", "iv-2", None)
                .await
                .unwrap();
            assert_raw_key_id_absent(&db, "hash-g").await;
        });
    }
}
