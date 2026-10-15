//! Copying images from an import source into Sloga's file storage.
//!
//! Shared by every importer that copies images: the Discord sticker worker,
//! and the server icon, banner and emoji of the bot-read sources. Sources
//! hand the worker typed [`PlannedAsset`]s, never URLs; each source supplies
//! an [`AssetFetcher`] that resolves those against its own configured host.

use futures::future::BoxFuture;
use revolt_config::config;
use revolt_database::{iso8601_timestamp::Timestamp, Database, File, FileHash, Metadata};
use revolt_files::{
    delete_from_s3, image_size_vec, is_valid_image, upload_to_s3, FileKeyring,
    AUTHENTICATION_TAG_SIZE_BYTES,
};
use sha2::Digest;

use super::mapper::PlannedAsset;

/// Downloads the bytes of a planned asset from its source.
///
/// Implementations validate `asset.id`, build the URL on the source's
/// configured host only, never follow redirects to another host, and bound
/// what they read. Every failure (invalid id, network, oversize) is `None`:
/// a missing image is a note on the summary, never a failed import.
///
/// Written out as a boxed future rather than with `#[async_trait]` so that
/// `&dyn AssetFetcher` works without adding a dependency to this crate.
/// Implement it as `fn fetch<'a>(&'a self, asset: &'a PlannedAsset) ->
/// BoxFuture<'a, Option<Vec<u8>>> { Box::pin(async move { .. }) }`.
pub(crate) trait AssetFetcher: Send + Sync {
    fn fetch<'a>(&'a self, asset: &'a PlannedAsset) -> BoxFuture<'a, Option<Vec<u8>>>;
}

/// For sources with no images (a Discord template).
pub(crate) struct NoAssets;

impl AssetFetcher for NoAssets {
    fn fetch<'a>(&'a self, _asset: &'a PlannedAsset) -> BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(async { None })
    }
}

/// Why [`store_file`] refused or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreFileError {
    /// The bytes are not a PNG, GIF, JPEG or WebP image that decodes.
    NotAnImage,
    /// Larger than the upload limit configured for the tag.
    TooLarge,
    /// The object store or the database failed.
    Storage,
}

/// Where stored bytes go. Production is S3 through `revolt_files`; the seam
/// exists so the keyring check below can be tested without an object store.
pub(super) trait ObjectStore: Send + Sync {
    /// Id of the file key new objects are encrypted under right now.
    fn primary_key_id(&self) -> BoxFuture<'_, Option<String>>;

    /// Encrypt and upload; returns the IV and the id of the key used.
    fn upload<'a>(
        &'a self,
        bucket_id: &'a str,
        path: &'a str,
        buf: &'a [u8],
    ) -> BoxFuture<'a, Result<(String, Option<String>), ()>>;

    /// Best-effort delete of an object no row points at.
    fn discard<'a>(&'a self, bucket_id: &'a str, path: &'a str) -> BoxFuture<'a, ()>;
}

/// The real object store.
pub(super) struct S3Objects;

impl ObjectStore for S3Objects {
    fn primary_key_id(&self) -> BoxFuture<'_, Option<String>> {
        Box::pin(async {
            let keyring = FileKeyring::global().await;
            keyring.primary_id().map(str::to_string)
        })
    }

    fn upload<'a>(
        &'a self,
        bucket_id: &'a str,
        path: &'a str,
        buf: &'a [u8],
    ) -> BoxFuture<'a, Result<(String, Option<String>), ()>> {
        Box::pin(async move { upload_to_s3(bucket_id, path, buf).await.map_err(|_| ()) })
    }

    fn discard<'a>(&'a self, bucket_id: &'a str, path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if let Err(error) = delete_from_s3(bucket_id, path).await {
                log::warn!("could not delete orphaned import object {path}: {error:?}");
            }
        })
    }
}

/// The content type of an image we accept, from its leading bytes alone.
///
/// A short allow-list on purpose: the formats every Sloga client renders as
/// an icon, emoji or sticker. Anything else (SVG, HTML, an error page served
/// with a 200) is refused before it is stored. APNG sniffs as `image/png`.
fn sniff_image(buf: &[u8]) -> Option<&'static str> {
    if buf.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if buf.starts_with(b"GIF87a") || buf.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if buf.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if buf.len() >= 12 && &buf[..4] == b"RIFF" && &buf[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// Whether `buf` is an image we accept, and its sniffed content type.
///
/// The magic bytes pick the format, and the image must then actually decode
/// as that format (`revolt_files::is_valid_image`, the image crate autumn
/// uses, with its default allocation limits). Decoding is CPU work, so it
/// runs off the async workers.
async fn validate_image(buf: Vec<u8>) -> (Vec<u8>, Option<&'static str>) {
    let Some(mime) = sniff_image(&buf) else {
        return (buf, None);
    };

    match tokio::task::spawn_blocking(move || {
        let valid = is_valid_image(&mut std::io::Cursor::new(&buf), mime);
        (buf, valid)
    })
    .await
    {
        Ok((buf, true)) => (buf, Some(mime)),
        Ok((buf, false)) => (buf, None),
        // The decoder panicked. The bytes went with the task; nothing is
        // stored.
        Err(_) => (Vec::new(), None),
    }
}

/// Store image bytes the way autumn's upload would, under `tag`, and return
/// the unclaimed attachment. The caller attaches it (`File::use_server_icon`,
/// `use_server_banner`, `use_emoji`, `use_sticker`), which also sets
/// `used_for` so the dangling-file pruner never touches it.
///
/// Refuses anything that is not a decodable PNG, GIF, JPEG or WebP, and
/// anything over the tag's upload limit. The stored content type is the
/// sniffed one. `animated` is recorded on the image metadata.
pub(crate) async fn store_file(
    db: &Database,
    uploader_id: &str,
    tag: &str,
    filename: &str,
    buf: Vec<u8>,
    animated: bool,
) -> Result<File, StoreFileError> {
    store_file_in(
        db,
        &S3Objects,
        uploader_id,
        tag,
        filename,
        buf,
        animated,
        None,
    )
    .await
}

/// [`store_file`] against a given object store, optionally recording a
/// content type the caller already knows instead of the sniffed one.
///
/// The sticker worker passes its content type: it comes from Discord's
/// `format_type`, and an APNG has to stay `image/apng` although it sniffs as
/// `image/png`.
///
/// Mirrors autumn's upload and `seed_stickers.rs`: FileHash + S3 object +
/// attachment row. `insert_attachment` is on the disallowed list because
/// attachments are normally minted by autumn's upload route; this IS that
/// route replicated at library level (no session token exists server-side),
/// so the raw insert is the point, same justification as the seeder.
#[allow(clippy::disallowed_methods, clippy::too_many_arguments)]
pub(super) async fn store_file_in(
    db: &Database,
    store: &dyn ObjectStore,
    uploader_id: &str,
    tag: &str,
    filename: &str,
    buf: Vec<u8>,
    animated: bool,
    content_type: Option<&'static str>,
) -> Result<File, StoreFileError> {
    let config = config().await;

    // Downloads are already bounded by their fetchers; this is the per-tag
    // ceiling autumn applies, enforced again because nothing here trusts
    // the caller to have done it.
    if let Some(limit) = config
        .features
        .limits
        .default
        .file_upload_size_limit
        .get(tag)
    {
        if buf.len() > *limit {
            return Err(StoreFileError::TooLarge);
        }
    }

    let (buf, sniffed) = validate_image(buf).await;
    let Some(sniffed) = sniffed else {
        return Err(StoreFileError::NotAnImage);
    };
    let content_type = content_type.unwrap_or(sniffed);

    let hash_hex = format!("{:02x}", sha2::Sha256::digest(&buf));

    // ACCEPTED RESIDUAL: content-addressed reuse means byte-identical media
    // uploaded earlier through autumn keeps ITS hash metadata (e.g. an APNG
    // autumn sniffed as image/png): only serving metadata can be stale, and
    // only for byte-identical prior uploads.
    let file_hash = match db.fetch_attachment_hash(&hash_hex).await {
        Ok(hash) if !hash.iv.is_empty() => hash,
        _ => {
            let (width, height) = image_size_vec(&buf, content_type).unwrap_or((320, 320));
            let fresh = FileHash {
                id: hash_hex.clone(),
                processed_hash: hash_hex.clone(),
                created_at: Timestamp::now_utc(),
                bucket_id: config.files.s3.default_bucket.clone(),
                // Placeholder only: the object itself goes to a fresh `rk/`
                // path below, committed together with its IV and key id.
                // Nothing is ever PUT at the hash id.
                path: hash_hex.clone(),
                iv: String::new(),
                format_version: None, // legacy whole-file GCM format
                key_id: None,
                metadata: Metadata::Image {
                    width: width as isize,
                    height: height as isize,
                    thumbhash: None,
                    animated: animated.then_some(true),
                },
                content_type: content_type.to_owned(),
                size: (buf.len() + AUTHENTICATION_TAG_SIZE_BYTES) as isize,
            };
            // Duplicate-insert errors are IGNORED on purpose, exactly like the
            // seeder: a crashed earlier attempt can leave a `{iv: ""}` hash
            // row behind, and failing here would wedge that file forever —
            // every retry would re-insert, hit the duplicate id, and error.
            // The heal is to fall through and (re)upload + set the storage.
            let _ = db.insert_attachment_hash(&fresh).await;

            // One keyring snapshot per write: the object path, the cipher
            // and the stored key id must all name the same key.
            let kid: Option<String> = store.primary_key_id().await;
            let path = FileHash::new_object_path(kid.as_deref());
            let (iv, rkid) = store
                .upload(&fresh.bucket_id, &path, &buf)
                .await
                .map_err(|_| StoreFileError::Storage)?;
            if rkid != kid {
                log::error!(
                    "import object for hash {hash_hex} was encrypted under an unexpected file key"
                );
                store.discard(&fresh.bucket_id, &path).await;
                return Err(StoreFileError::Storage);
            }

            // Path, IV and key id land together. If the row is gone (or the
            // write fails) the object we just PUT is unreferenced: drop it.
            if db
                .set_attachment_hash_storage(&fresh.id, &path, &iv, rkid.as_deref())
                .await
                .is_err()
            {
                store.discard(&fresh.bucket_id, &path).await;
                return Err(StoreFileError::Storage);
            }
            db.fetch_attachment_hash(&hash_hex)
                .await
                .map_err(|_| StoreFileError::Storage)?
        }
    };

    // Same id scheme as autumn: emoji ids are ULIDs (a message references a
    // custom emoji as `:<ULID>:` and `Emoji::can_use` tells custom from
    // unicode by parsing one), everything else a 42-char nanoid.
    let id = if tag == "emojis" {
        ulid::Ulid::new().to_string()
    } else {
        nanoid::nanoid!(42)
    };

    let file = file_hash.into_file(
        id,
        tag.to_owned(),
        filename.to_owned(),
        uploader_id.to_owned(),
    );
    db.insert_attachment(&file)
        .await
        .map_err(|_| StoreFileError::Storage)?;

    Ok(file)
}

#[cfg(test)]
pub(super) mod tests {
    use std::sync::Mutex;

    use super::*;
    use revolt_database::DatabaseInfo;

    /// A 1x1 RGBA PNG.
    pub(crate) const PNG_1X1: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    /// A 1x1 GIF.
    const GIF_1X1: &[u8] = &[
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xFF, 0xFF, 0xFF, 0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3B,
    ];

    /// An in-memory object store whose key id on upload can be made to
    /// disagree with the snapshot, recording what it was asked to do.
    pub(crate) struct FakeStore {
        pub primary: Option<String>,
        pub encrypted_under: Option<String>,
        pub uploaded: Mutex<Vec<String>>,
        pub discarded: Mutex<Vec<String>>,
    }

    impl FakeStore {
        pub(crate) fn matching() -> FakeStore {
            FakeStore {
                primary: Some("k1".to_string()),
                encrypted_under: Some("k1".to_string()),
                uploaded: Mutex::new(vec![]),
                discarded: Mutex::new(vec![]),
            }
        }
    }

    impl ObjectStore for FakeStore {
        fn primary_key_id(&self) -> BoxFuture<'_, Option<String>> {
            Box::pin(async { self.primary.clone() })
        }

        fn upload<'a>(
            &'a self,
            _bucket_id: &'a str,
            path: &'a str,
            _buf: &'a [u8],
        ) -> BoxFuture<'a, Result<(String, Option<String>), ()>> {
            Box::pin(async move {
                self.uploaded.lock().unwrap().push(path.to_string());
                Ok(("iv".to_string(), self.encrypted_under.clone()))
            })
        }

        fn discard<'a>(&'a self, _bucket_id: &'a str, path: &'a str) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                self.discarded.lock().unwrap().push(path.to_string());
            })
        }
    }

    fn hash_of(buf: &[u8]) -> String {
        format!("{:02x}", sha2::Sha256::digest(buf))
    }

    #[test]
    fn sniffing_accepts_the_four_formats_and_nothing_else() {
        assert_eq!(sniff_image(PNG_1X1), Some("image/png"));
        assert_eq!(sniff_image(GIF_1X1), Some("image/gif"));
        assert_eq!(sniff_image(b"\xff\xd8\xff\xe0rest"), Some("image/jpeg"));
        assert_eq!(sniff_image(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(
            sniff_image(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"),
            None
        );
        assert_eq!(sniff_image(b"<!doctype html><title>404</title>"), None);
        assert_eq!(sniff_image(b"RIFF\0\0\0\0WAVEfmt "), None);
        assert_eq!(sniff_image(b""), None);
    }

    /// Non-image bytes never reach storage: no hash row, no upload, no
    /// attachment. Includes a PNG signature on a body that does not decode.
    #[tokio::test]
    async fn non_image_bytes_are_rejected_before_anything_is_written() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let store = FakeStore::matching();

        let mut truncated = PNG_1X1[..20].to_vec();
        truncated.extend_from_slice(b"not the rest of a png");

        for buf in [
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>".to_vec(),
            b"<!doctype html><title>404</title>".to_vec(),
            truncated,
        ] {
            let hash = hash_of(&buf);
            let result =
                store_file_in(&db, &store, "user", "icons", "x.png", buf, false, None).await;
            assert_eq!(result.err(), Some(StoreFileError::NotAnImage));
            assert!(db.fetch_attachment_hash(&hash).await.is_err());
        }
        assert!(store.uploaded.lock().unwrap().is_empty());
    }

    /// The keyring snapshot is the one the object path names; an upload that
    /// comes back encrypted under any other key is discarded and nothing
    /// points at it.
    #[tokio::test]
    async fn an_object_encrypted_under_the_wrong_key_is_discarded() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let store = FakeStore {
            encrypted_under: Some("k2".to_string()),
            ..FakeStore::matching()
        };

        let result = store_file_in(
            &db,
            &store,
            "user",
            "icons",
            "icon.png",
            PNG_1X1.to_vec(),
            false,
            None,
        )
        .await;
        assert_eq!(result.err(), Some(StoreFileError::Storage));

        let uploaded = store.uploaded.lock().unwrap().clone();
        assert_eq!(uploaded.len(), 1);
        assert!(
            uploaded[0].starts_with("rk/k1/"),
            "the path names the snapshot key"
        );
        assert_eq!(*store.discarded.lock().unwrap(), uploaded);

        // The hash row was never pointed at the discarded object.
        let hash = db.fetch_attachment_hash(&hash_of(PNG_1X1)).await.unwrap();
        assert!(hash.iv.is_empty());
        assert_eq!(hash.key_id, None);
    }

    #[tokio::test]
    async fn stored_file_keeps_animated_type_and_tag() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let store = FakeStore::matching();

        let gif = store_file_in(
            &db,
            &store,
            "user",
            "emojis",
            "party.gif",
            GIF_1X1.to_vec(),
            true,
            None,
        )
        .await
        .unwrap();
        assert_eq!(gif.content_type, "image/gif");
        assert_eq!(gif.tag, "emojis");
        assert_eq!(gif.filename, "party.gif");
        assert_eq!(gif.uploader_id.as_deref(), Some("user"));
        assert!(gif.used_for.is_none(), "the caller attaches it");
        assert!(matches!(
            gif.metadata,
            Metadata::Image {
                width: 1,
                height: 1,
                animated: Some(true),
                ..
            }
        ));
        // Emoji ids are ULIDs, as autumn mints them.
        assert!(ulid::Ulid::from_string(&gif.id).is_ok());
        assert!(store.discarded.lock().unwrap().is_empty());

        let hash = db.fetch_attachment_hash(&hash_of(GIF_1X1)).await.unwrap();
        assert_eq!(hash.key_id.as_deref(), Some("k1"));
        assert_eq!(hash.iv, "iv");

        // Static, and a content type the caller already knows wins over the
        // sniffed one (the sticker worker's APNG case).
        let png = store_file_in(
            &db,
            &store,
            "user",
            "stickers",
            "1.png",
            PNG_1X1.to_vec(),
            false,
            Some("image/apng"),
        )
        .await
        .unwrap();
        assert_eq!(png.content_type, "image/apng");
        assert!(matches!(
            png.metadata,
            Metadata::Image { animated: None, .. }
        ));
        assert_eq!(png.id.len(), 42, "non-emoji ids are nanoids");
    }
}
