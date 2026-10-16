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
    delete_from_s3, sanitize_image, upload_to_s3, FileKeyring, ImageLimits, SanitizeError,
    SanitizedImage, AUTHENTICATION_TAG_SIZE_BYTES,
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
    /// The bytes are not a PNG (or APNG), GIF, JPEG or WebP image that
    /// decodes and can be cleaned.
    NotAnImage,
    /// Larger than the upload limit configured for the tag, before or after
    /// cleaning, or over the import image dimensions.
    TooLarge,
    /// The object store or the database failed.
    Storage,
}

/// Bounds every imported image is cleaned under: icons, banners, emoji and
/// stickers alike.
///
/// Far above anything shown at those sizes, and far below what a hostile
/// header could otherwise make a decoder allocate.
const IMPORT_IMAGE_LIMITS: ImageLimits = ImageLimits {
    max_side: 4096,
    max_pixels: 16 * 1024 * 1024,
    max_alloc: 256 * 1024 * 1024,
};

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

/// Validate an image and strip its metadata (`revolt_files::sanitize_image`).
///
/// The sanitiser pins the format by its magic bytes to PNG (APNG included),
/// GIF, JPEG or WebP: the formats every Sloga client renders as an icon,
/// emoji or sticker. Anything else (SVG, HTML, an error page served with a
/// 200) is refused. Header dimensions are checked before anything decodes,
/// the first frame must decode under [`IMPORT_IMAGE_LIMITS`], and EXIF (with
/// any GPS position in it), XMP, comments and text chunks are removed;
/// animated images keep every frame.
///
/// Decoding and re-encoding are CPU work, so this runs off the async
/// workers. Fails closed: if the sanitiser task dies, nothing is stored.
async fn sanitize(buf: Vec<u8>) -> Result<SanitizedImage, StoreFileError> {
    match tokio::task::spawn_blocking(move || sanitize_image(buf, IMPORT_IMAGE_LIMITS)).await {
        Ok(Ok(image)) => Ok(image),
        Ok(Err(SanitizeError::TooLarge)) => Err(StoreFileError::TooLarge),
        Ok(Err(SanitizeError::NotAnImage | SanitizeError::Decode)) => {
            Err(StoreFileError::NotAnImage)
        }
        // The sanitiser panicked or was cancelled. The bytes went with the
        // task.
        Err(error) => {
            log::warn!("import image sanitiser did not finish: {error}");
            Err(StoreFileError::NotAnImage)
        }
    }
}

/// Store image bytes the way autumn's upload would, under `tag`, and return
/// the unclaimed attachment. The caller attaches it (`File::use_server_icon`,
/// `use_server_banner`, `use_emoji`, `use_sticker`), which also sets
/// `used_for` so the dangling-file pruner never touches it.
///
/// What is stored is the sanitised image, never the downloaded bytes: see
/// [`sanitize`]. Refuses anything the sanitiser refuses, and anything over
/// the tag's upload limit before or after cleaning. The stored content type,
/// dimensions and `animated` flag are the sanitiser's.
///
/// `_animated` is IGNORED: whether an image is animated is read from its
/// bytes, not taken from the source's claim. The parameter stays so callers
/// compile unchanged.
pub(crate) async fn store_file(
    db: &Database,
    uploader_id: &str,
    tag: &str,
    filename: &str,
    buf: Vec<u8>,
    _animated: bool,
) -> Result<File, StoreFileError> {
    store_file_in(db, &S3Objects, uploader_id, tag, filename, buf, false, None).await
}

/// [`store_file`] against a given object store, optionally recording a
/// content type the caller already knows instead of the sanitiser's.
///
/// The sticker worker passes its content type: it comes from Discord's
/// `format_type`, and an APNG has to stay `image/apng` although the
/// sanitiser reports it as `image/png`. Whether it is animated is still the
/// sanitiser's call, from its frames; `_animated` is ignored here too.
#[allow(clippy::too_many_arguments)]
pub(super) async fn store_file_in(
    db: &Database,
    store: &dyn ObjectStore,
    uploader_id: &str,
    tag: &str,
    filename: &str,
    buf: Vec<u8>,
    _animated: bool,
    content_type: Option<&'static str>,
) -> Result<File, StoreFileError> {
    let size_limit = config()
        .await
        .features
        .limits
        .default
        .file_upload_size_limit
        .get(tag)
        .copied();

    store_image(
        db,
        store,
        uploader_id,
        tag,
        filename,
        buf,
        content_type,
        size_limit,
    )
    .await
}

/// [`store_file_in`] with the tag's size limit passed in, so the check on
/// the cleaned bytes can be tested against a limit of the test's choosing.
///
/// Mirrors autumn's upload and `seed_stickers.rs`: FileHash + S3 object +
/// attachment row. `insert_attachment` is on the disallowed list because
/// attachments are normally minted by autumn's upload route; this IS that
/// route replicated at library level (no session token exists server-side),
/// so the raw insert is the point, same justification as the seeder.
#[allow(clippy::disallowed_methods, clippy::too_many_arguments)]
async fn store_image(
    db: &Database,
    store: &dyn ObjectStore,
    uploader_id: &str,
    tag: &str,
    filename: &str,
    buf: Vec<u8>,
    content_type: Option<&'static str>,
    size_limit: Option<usize>,
) -> Result<File, StoreFileError> {
    let config = config().await;
    let within_limit = |len: usize| size_limit.is_none_or(|limit| len <= limit);

    // Downloads are already bounded by their fetchers; this is the per-tag
    // ceiling autumn applies, enforced again because nothing here trusts
    // the caller to have done it. Checked before cleaning, which is the
    // expensive part.
    if !within_limit(buf.len()) {
        return Err(StoreFileError::TooLarge);
    }

    let SanitizedImage {
        bytes: buf,
        mime,
        width,
        height,
        animated,
    } = sanitize(buf).await?;

    // And again on what is actually stored: re-encoding can make a file
    // bigger (a JPEG is written back at a fixed quality).
    if !within_limit(buf.len()) {
        return Err(StoreFileError::TooLarge);
    }

    let content_type = content_type.unwrap_or(mime);

    // Content addressing keys on the CLEANED bytes. A hash row found here was
    // made from these same metadata-free bytes; an object an earlier version
    // of this path stored straight from a download sits under the hash of
    // the download and is never matched (unless the download was already
    // clean, byte for byte).
    let hash_hex = format!("{:02x}", sha2::Sha256::digest(&buf));

    // ACCEPTED RESIDUAL: content-addressed reuse means byte-identical media
    // uploaded earlier through autumn keeps ITS hash row, content type
    // included (e.g. an APNG autumn sniffed as image/png): only serving
    // metadata can be stale, and only for byte-identical prior uploads.
    // Dimensions and `animated` on the attachment are this call's (below).
    let file_hash = match db.fetch_attachment_hash(&hash_hex).await {
        Ok(hash) if !hash.iv.is_empty() => hash,
        _ => {
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

    let mut file = file_hash.into_file(
        id,
        tag.to_owned(),
        filename.to_owned(),
        uploader_id.to_owned(),
    );

    // A reused hash row carries the metadata whoever stored it first wrote,
    // and autumn leaves `animated` unset until the file is first served: a
    // byte-identical animated GIF would come back static and become a static
    // emoji. Dimensions and `animated` are this call's, read from these very
    // bytes. Only the attachment made here gets them; the hash row is left
    // as it is.
    let thumbhash = match &file.metadata {
        Metadata::Image { thumbhash, .. } => thumbhash.clone(),
        _ => None,
    };
    file.metadata = Metadata::Image {
        width: width as isize,
        height: height as isize,
        thumbhash,
        animated: animated.then_some(true),
    };

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

    /// A 1x1 RGBA PNG, exactly as the sanitiser writes it back out.
    ///
    /// Already clean, so cleaning leaves it byte for byte unchanged (pinned
    /// by `png_fixture_is_already_clean`): the worker tests seed a stored
    /// object under the hash of these bytes and rely on it being reused.
    pub(crate) const PNG_1X1: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x10, 0x49, 0x44, 0x41, 0x54, 0x78, 0x01, 0x01, 0x05,
        0x00, 0xFA, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x64, 0x78, 0x95,
        0x38, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    /// A 1x1 GIF.
    const GIF_1X1: &[u8] = &[
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xFF, 0xFF, 0xFF, 0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3B,
    ];

    /// A 655x582 baseline JPEG with an ICC profile and no EXIF, shared with
    /// the file crate's tests.
    const JPEG: &[u8] = include_bytes!("../../../../../core/files/tests/assets/test.jpeg");

    /// A still WebP (extended format), shared with the file crate's tests.
    const WEBP: &[u8] = include_bytes!("../../../../../core/files/tests/assets/dice.webp");

    /// A value no encoder writes by itself: finding it means the GPS IFD
    /// survived.
    const GPS_MARKER: &[u8] = b"GPS-SECRET-48.8584N-2.2945E";

    /// An in-memory object store whose key id on upload can be made to
    /// disagree with the snapshot, recording what it was asked to do.
    pub(crate) struct FakeStore {
        pub primary: Option<String>,
        pub encrypted_under: Option<String>,
        pub uploaded: Mutex<Vec<String>>,
        /// The bytes of each upload, in the same order as `uploaded`.
        pub uploaded_bytes: Mutex<Vec<Vec<u8>>>,
        pub discarded: Mutex<Vec<String>>,
    }

    impl FakeStore {
        pub(crate) fn matching() -> FakeStore {
            FakeStore {
                primary: Some("k1".to_string()),
                encrypted_under: Some("k1".to_string()),
                uploaded: Mutex::new(vec![]),
                uploaded_bytes: Mutex::new(vec![]),
                discarded: Mutex::new(vec![]),
            }
        }

        /// The bytes of the only upload so far.
        fn only_upload(&self) -> Vec<u8> {
            let uploads = self.uploaded_bytes.lock().unwrap();
            assert_eq!(uploads.len(), 1, "expected exactly one upload");
            uploads[0].clone()
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
            buf: &'a [u8],
        ) -> BoxFuture<'a, Result<(String, Option<String>), ()>> {
            Box::pin(async move {
                self.uploaded.lock().unwrap().push(path.to_string());
                self.uploaded_bytes.lock().unwrap().push(buf.to_vec());
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

    /// What the sanitiser makes of `buf`, run directly.
    fn cleaned(buf: &[u8]) -> Vec<u8> {
        sanitize_image(buf.to_vec(), IMPORT_IMAGE_LIMITS)
            .unwrap()
            .bytes
    }

    fn find(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// [`JPEG`] with an EXIF APP1 segment holding a GPS IFD spliced in
    /// straight after the start-of-image marker.
    fn jpeg_with_gps() -> Vec<u8> {
        // Little-endian TIFF. IFD0 at 8 holds one entry, a GPSInfo pointer
        // to the GPS IFD at 8 + 2 + 12 + 4 = 26.
        let mut tiff = b"II\x2a\0".to_vec();
        tiff.extend_from_slice(&8u32.to_le_bytes());
        tiff.extend_from_slice(&1u16.to_le_bytes());
        tiff.extend_from_slice(&0x8825u16.to_le_bytes());
        tiff.extend_from_slice(&4u16.to_le_bytes()); // LONG
        tiff.extend_from_slice(&1u32.to_le_bytes());
        tiff.extend_from_slice(&26u32.to_le_bytes());
        tiff.extend_from_slice(&0u32.to_le_bytes());
        // The GPS IFD holds one entry, GPSMapDatum, an ASCII value stored
        // out of line at 26 + 2 + 12 + 4 = 44.
        tiff.extend_from_slice(&1u16.to_le_bytes());
        tiff.extend_from_slice(&0x0012u16.to_le_bytes());
        tiff.extend_from_slice(&2u16.to_le_bytes()); // ASCII
        tiff.extend_from_slice(&(GPS_MARKER.len() as u32 + 1).to_le_bytes());
        tiff.extend_from_slice(&44u32.to_le_bytes());
        tiff.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(tiff.len(), 44);
        tiff.extend_from_slice(GPS_MARKER);
        tiff.push(0);

        let mut jpeg = JPEG[..2].to_vec();
        jpeg.extend_from_slice(&[0xff, 0xe1]);
        jpeg.extend_from_slice(&((2 + 6 + tiff.len()) as u16).to_be_bytes());
        jpeg.extend_from_slice(b"Exif\0\0");
        jpeg.extend_from_slice(&tiff);
        jpeg.extend_from_slice(&JPEG[2..]);
        jpeg
    }

    /// Bitwise CRC-32 (the PNG polynomial), enough to build test chunks.
    fn crc32(parts: &[&[u8]]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for part in parts {
            for &byte in *part {
                crc ^= u32::from(byte);
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xedb8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
        }
        !crc
    }

    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut chunk = (data.len() as u32).to_be_bytes().to_vec();
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(data);
        chunk.extend_from_slice(&crc32(&[kind, data]).to_be_bytes());
        chunk
    }

    /// Every chunk of a PNG as (type, data), read by structure.
    fn png_chunks(buf: &[u8]) -> Vec<([u8; 4], Vec<u8>)> {
        let mut chunks = Vec::new();
        let mut pos = 8;
        while pos + 12 <= buf.len() {
            let length = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
            let kind: [u8; 4] = buf[pos + 4..pos + 8].try_into().unwrap();
            chunks.push((kind, buf[pos + 8..pos + 8 + length].to_vec()));
            pos += 12 + length;
        }
        chunks
    }

    fn fctl(sequence: u32) -> Vec<u8> {
        let mut data = sequence.to_be_bytes().to_vec();
        data.extend_from_slice(&1u32.to_be_bytes()); // width
        data.extend_from_slice(&1u32.to_be_bytes()); // height
        data.extend_from_slice(&[0; 8]); // x, y
        data.extend_from_slice(&1u16.to_be_bytes()); // delay numerator
        data.extend_from_slice(&10u16.to_be_bytes()); // delay denominator
        data.extend_from_slice(&[0, 0]); // dispose, blend
        png_chunk(b"fcTL", &data)
    }

    /// A two-frame 1x1 APNG built from [`PNG_1X1`], with a text chunk
    /// between the frames.
    fn apng_two_frames() -> Vec<u8> {
        let chunks = png_chunks(PNG_1X1);
        let ihdr = &chunks.iter().find(|(kind, _)| kind == b"IHDR").unwrap().1;
        let idat: Vec<u8> = chunks
            .iter()
            .filter(|(kind, _)| kind == b"IDAT")
            .flat_map(|(_, data)| data.clone())
            .collect();

        let mut actl = 2u32.to_be_bytes().to_vec(); // frames
        actl.extend_from_slice(&0u32.to_be_bytes()); // loop forever
        let mut fdat = 2u32.to_be_bytes().to_vec();
        fdat.extend_from_slice(&idat);

        let mut out = PNG_1X1[..8].to_vec();
        out.extend(png_chunk(b"IHDR", ihdr));
        out.extend(png_chunk(b"acTL", &actl));
        out.extend(fctl(0));
        out.extend(png_chunk(b"IDAT", &idat));
        out.extend(png_chunk(b"tEXt", b"Comment\0STICKER-TEXT-SECRET"));
        out.extend(fctl(1));
        out.extend(png_chunk(b"fdAT", &fdat));
        out.extend(png_chunk(b"IEND", &[]));
        out
    }

    /// One frame of [`GIF_1X1`]: graphic control extension, image
    /// descriptor and image data.
    const GIF_FRAME: std::ops::Range<usize> = 19..42;

    /// The image descriptor of every frame in the GIFs built here.
    const GIF_DESCRIPTOR: &[u8] = &[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0];

    /// [`GIF_1X1`] with its one frame repeated: a two-frame animation.
    fn gif_two_frames() -> Vec<u8> {
        let mut gif = GIF_1X1[..GIF_FRAME.start].to_vec();
        gif.extend_from_slice(&GIF_1X1[GIF_FRAME]);
        gif.extend_from_slice(&GIF_1X1[GIF_FRAME]);
        gif.push(0x3B);
        gif
    }

    /// A PNG whose header claims `width` x `height`, with no image data.
    fn png_header_only(width: u32, height: u32) -> Vec<u8> {
        let mut ihdr = width.to_be_bytes().to_vec();
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        let mut png = PNG_1X1[..8].to_vec();
        png.extend(png_chunk(b"IHDR", &ihdr));
        png.extend(png_chunk(b"IEND", &[]));
        png
    }

    async fn put(
        db: &Database,
        store: &FakeStore,
        tag: &str,
        buf: Vec<u8>,
        animated: bool,
        content_type: Option<&'static str>,
    ) -> Result<File, StoreFileError> {
        store_file_in(db, store, "user", tag, "file", buf, animated, content_type).await
    }

    /// Non-image bytes never reach storage: no hash row, no upload, no
    /// attachment. Includes a PNG signature on a body that does not decode.
    #[tokio::test]
    async fn non_image_bytes_are_rejected_before_anything_is_written() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let store = FakeStore::matching();

        // Cut after the whole IHDR chunk, so the header's 1x1 is read
        // intact and it is the chunk stream that fails. (Cut inside IHDR,
        // the text lands in the height field and is refused as too large.)
        let mut truncated = PNG_1X1[..33].to_vec();
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
        // One frame, so not animated, whatever the caller claimed.
        assert!(matches!(
            gif.metadata,
            Metadata::Image {
                width: 1,
                height: 1,
                animated: None,
                ..
            }
        ));
        // Emoji ids are ULIDs, as autumn mints them.
        assert!(ulid::Ulid::from_string(&gif.id).is_ok());
        assert!(store.discarded.lock().unwrap().is_empty());

        let hash = db
            .fetch_attachment_hash(&hash_of(&cleaned(GIF_1X1)))
            .await
            .unwrap();
        assert_eq!(hash.key_id.as_deref(), Some("k1"));
        assert_eq!(hash.iv, "iv");

        // Static, and a content type the caller already knows wins over the
        // sanitiser's (the sticker worker's APNG case).
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

    /// The worker tests seed a stored object under the hash of `PNG_1X1`
    /// and expect it to be reused, which holds only while cleaning leaves
    /// these bytes as they are.
    #[test]
    fn png_fixture_is_already_clean() {
        assert_eq!(cleaned(PNG_1X1), PNG_1X1);
    }

    /// The four formats are accepted and nothing else is: an SVG, an HTML
    /// error page or another RIFF format never reaches storage.
    #[tokio::test]
    async fn only_the_four_formats_are_accepted() {
        for (buf, mime) in [
            (PNG_1X1, "image/png"),
            (GIF_1X1, "image/gif"),
            (JPEG, "image/jpeg"),
            (WEBP, "image/webp"),
        ] {
            assert_eq!(sanitize(buf.to_vec()).await.unwrap().mime, mime);
        }

        let refused: [&[u8]; 5] = [
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
            b"<!doctype html><title>404</title>",
            b"RIFF\0\0\0\0WAVEfmt ",
            b"definitely not an image",
            b"",
        ];
        for buf in refused {
            assert_eq!(
                sanitize(buf.to_vec()).await.err(),
                Some(StoreFileError::NotAnImage)
            );
        }
    }

    /// The GPS position in a JPEG's EXIF never reaches the object store, and
    /// the stored hash, size and dimensions describe what was stored.
    #[tokio::test]
    async fn exif_is_stripped_before_the_bytes_are_stored() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let store = FakeStore::matching();

        let input = jpeg_with_gps();
        assert!(find(&input, b"Exif\0\0") && find(&input, GPS_MARKER));

        let file = put(&db, &store, "icons", input.clone(), false, None)
            .await
            .unwrap();

        let stored = store.only_upload();
        assert!(!find(&stored, b"Exif\0\0"), "the EXIF segment was stored");
        assert!(!find(&stored, GPS_MARKER), "the GPS position was stored");

        assert_eq!(file.content_type, "image/jpeg");
        assert_eq!(file.hash.as_deref(), Some(hash_of(&stored).as_str()));
        assert_eq!(
            file.size,
            (stored.len() + AUTHENTICATION_TAG_SIZE_BYTES) as isize
        );
        assert!(matches!(
            file.metadata,
            Metadata::Image {
                width: 655,
                height: 582,
                animated: None,
                ..
            }
        ));
        // Nothing was ever recorded under the hash of the download.
        assert!(db.fetch_attachment_hash(&hash_of(&input)).await.is_err());
    }

    /// Two copies of the same download share one stored object, keyed on
    /// the cleaned bytes.
    #[tokio::test]
    async fn the_same_download_dedupes_to_one_cleaned_object() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let store = FakeStore::matching();

        let input = jpeg_with_gps();
        let first = put(&db, &store, "icons", input.clone(), false, None)
            .await
            .unwrap();
        let second = put(&db, &store, "icons", input.clone(), false, None)
            .await
            .unwrap();

        let stored = store.only_upload();
        let clean_hash = hash_of(&stored);
        assert_eq!(clean_hash, hash_of(&cleaned(&input)));
        assert_ne!(clean_hash, hash_of(&input));
        assert_eq!(first.hash.as_deref(), Some(clean_hash.as_str()));
        assert_eq!(second.hash.as_deref(), Some(clean_hash.as_str()));
        assert_ne!(first.id, second.id, "each import gets its own attachment");
    }

    /// An object stored earlier straight from a download (what this path
    /// did before it cleaned anything) is not reused for the same download.
    #[tokio::test]
    async fn an_unstripped_object_with_the_same_source_bytes_is_not_reused() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let store = FakeStore::matching();

        let input = jpeg_with_gps();
        let raw_hash = hash_of(&input);
        db.insert_attachment_hash(&FileHash {
            id: raw_hash.clone(),
            processed_hash: raw_hash.clone(),
            created_at: Timestamp::now_utc(),
            bucket_id: "revolt-uploads".to_string(),
            path: "rk/k1/unstripped".to_string(),
            iv: "old-iv".to_string(),
            format_version: None,
            key_id: Some("k1".to_string()),
            metadata: Metadata::Image {
                width: 655,
                height: 582,
                thumbhash: None,
                animated: None,
            },
            content_type: "image/jpeg".to_string(),
            size: input.len() as isize,
        })
        .await
        .unwrap();

        let file = put(&db, &store, "icons", input, false, None).await.unwrap();

        let stored = store.only_upload();
        assert!(!find(&stored, GPS_MARKER));
        assert_eq!(file.hash.as_deref(), Some(hash_of(&stored).as_str()));
        assert_ne!(file.hash.as_deref(), Some(raw_hash.as_str()));
    }

    /// A sticker the caller labels `image/apng` keeps that label and every
    /// frame, and loses its text chunk.
    #[tokio::test]
    async fn an_apng_sticker_stays_animated() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let store = FakeStore::matching();

        let file = put(
            &db,
            &store,
            "stickers",
            apng_two_frames(),
            true,
            Some("image/apng"),
        )
        .await
        .unwrap();

        assert_eq!(file.content_type, "image/apng");
        assert!(matches!(
            file.metadata,
            Metadata::Image {
                width: 1,
                height: 1,
                animated: Some(true),
                ..
            }
        ));

        let stored = store.only_upload();
        let chunks = png_chunks(&stored);
        let count = |kind: &[u8; 4]| chunks.iter().filter(|(k, _)| k == kind).count();
        let (_, actl) = chunks.iter().find(|(k, _)| k == b"acTL").unwrap();
        assert_eq!(actl[..4], 2u32.to_be_bytes(), "two frames declared");
        assert_eq!(count(b"fcTL"), 2);
        assert_eq!(count(b"IDAT"), 1);
        assert_eq!(count(b"fdAT"), 1);
        assert_eq!(count(b"tEXt"), 0);
        assert!(!find(&stored, b"STICKER-TEXT-SECRET"));
    }

    /// Whether an image is animated comes from its frames, never from the
    /// source's claim.
    #[tokio::test]
    async fn an_animated_gif_claimed_static_is_stored_animated() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let store = FakeStore::matching();

        let file = put(&db, &store, "emojis", gif_two_frames(), false, None)
            .await
            .unwrap();

        assert_eq!(file.content_type, "image/gif");
        assert!(matches!(
            file.metadata,
            Metadata::Image {
                width: 1,
                height: 1,
                animated: Some(true),
                ..
            }
        ));
        let stored = store.only_upload();
        let frames = stored
            .windows(GIF_DESCRIPTOR.len())
            .filter(|window| *window == GIF_DESCRIPTOR)
            .count();
        assert_eq!(frames, 2, "both frames were stored");
    }

    /// A hash row reused for the same cleaned bytes may say nothing about
    /// animation (autumn fills that in only when the file is first served).
    /// The attachment returned, and stored, still says animated, from the
    /// bytes of this call; the hash row is not rewritten.
    #[tokio::test]
    async fn a_reused_hash_row_does_not_make_an_animated_gif_static() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let store = FakeStore::matching();

        let gif = gif_two_frames();
        let clean_hash = hash_of(&cleaned(&gif));
        db.insert_attachment_hash(&FileHash {
            id: clean_hash.clone(),
            processed_hash: clean_hash.clone(),
            created_at: Timestamp::now_utc(),
            bucket_id: "revolt-uploads".to_string(),
            path: "rk/k1/earlier".to_string(),
            iv: "old-iv".to_string(),
            format_version: None,
            key_id: Some("k1".to_string()),
            metadata: Metadata::Image {
                width: 0,
                height: 0,
                thumbhash: None,
                animated: None,
            },
            content_type: "image/gif".to_string(),
            size: 1,
        })
        .await
        .unwrap();

        let file = put(&db, &store, "emojis", gif, false, None).await.unwrap();

        // The existing object was reused: nothing new was uploaded.
        assert!(store.uploaded.lock().unwrap().is_empty());
        assert_eq!(file.hash.as_deref(), Some(clean_hash.as_str()));
        assert!(
            matches!(
                file.metadata,
                Metadata::Image {
                    width: 1,
                    height: 1,
                    animated: Some(true),
                    ..
                }
            ),
            "{:?}",
            file.metadata
        );
        let stored = db.fetch_attachment(&file.tag, &file.id).await.unwrap();
        assert!(matches!(
            stored.metadata,
            Metadata::Image {
                animated: Some(true),
                ..
            }
        ));

        // The hash row keeps what it had.
        let hash = db.fetch_attachment_hash(&clean_hash).await.unwrap();
        assert!(matches!(
            hash.metadata,
            Metadata::Image {
                width: 0,
                height: 0,
                animated: None,
                ..
            }
        ));
        assert_eq!(hash.iv, "old-iv");
    }

    /// Dimensions over the import limits are refused from the header alone,
    /// before anything is written.
    #[tokio::test]
    async fn oversized_dimensions_are_too_large() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let store = FakeStore::matching();

        for (width, height) in [(5000, 5000), (4097, 1), (1, 4097)] {
            let buf = png_header_only(width, height);
            let hash = hash_of(&buf);
            assert_eq!(
                put(&db, &store, "icons", buf, false, None).await.err(),
                Some(StoreFileError::TooLarge),
                "{width}x{height}"
            );
            assert!(db.fetch_attachment_hash(&hash).await.is_err());
        }
        assert!(store.uploaded.lock().unwrap().is_empty());
    }

    /// The size limit is applied to the cleaned bytes as well as to the
    /// download: re-encoding can make a file bigger.
    #[tokio::test]
    async fn cleaned_bytes_over_the_size_limit_are_too_large() {
        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let store = FakeStore::matching();

        let clean = cleaned(JPEG);
        assert!(
            clean.len() > JPEG.len(),
            "fixture should grow when cleaned ({} -> {})",
            JPEG.len(),
            clean.len()
        );

        // The download fits; what would be stored does not.
        let result = store_image(
            &db,
            &store,
            "user",
            "icons",
            "icon",
            JPEG.to_vec(),
            None,
            Some(JPEG.len()),
        )
        .await;
        assert_eq!(result.err(), Some(StoreFileError::TooLarge));
        assert!(store.uploaded.lock().unwrap().is_empty());
        assert!(db.fetch_attachment_hash(&hash_of(&clean)).await.is_err());

        // At exactly the cleaned size it is stored.
        store_image(
            &db,
            &store,
            "user",
            "icons",
            "icon",
            JPEG.to_vec(),
            None,
            Some(clean.len()),
        )
        .await
        .unwrap();
        assert_eq!(store.only_upload(), clean);

        // And the download itself is still checked first.
        assert_eq!(
            store_image(
                &db,
                &store,
                "user",
                "icons",
                "icon",
                JPEG.to_vec(),
                None,
                Some(JPEG.len() - 1),
            )
            .await
            .err(),
            Some(StoreFileError::TooLarge)
        );
    }
}
