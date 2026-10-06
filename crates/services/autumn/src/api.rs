use std::{
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom, Write},
    time::Duration,
};

use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, Method},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use axum_typed_multipart::{FieldData, TryFromMultipart, TypedMultipart};
use lazy_static::lazy_static;
use revolt_config::{config, report_internal_error};
use revolt_database::{iso8601_timestamp::Timestamp, Database, FileHash, Metadata, User};
use revolt_files::{
    create_thumbnail, decode_image, delete_from_s3, fetch_from_s3, is_animated, upload_to_s3,
    FileKeyring, AUTHENTICATION_TAG_SIZE_BYTES, LEGACY_KEY_ID,
};
use revolt_result::{create_error, Error, Result, ToRevoltError};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tempfile::NamedTempFile;
use tokio::time::Instant;
use tower_http::cors::{AllowHeaders, Any, CorsLayer};
use url_escape::encode_component;
use utoipa::ToSchema;

use crate::{
    exif::strip_metadata, metadata::generate_metadata, mime_type::determine_mime_type, AppState,
};

/// Compute the sha256 of a file by streaming it, without loading it into memory
fn hash_file(f: &mut File) -> std::io::Result<sha2::digest::Output<sha2::Sha256>> {
    f.seek(SeekFrom::Start(0))?;

    let mut hasher = sha2::Sha256::new();
    let mut chunk = vec![0u8; 64 * 1024];

    loop {
        let read = f.read(&mut chunk)?;
        if read == 0 {
            break;
        }

        hasher.update(&chunk[..read]);
    }

    Ok(hasher.finalize())
}

/// Build the API router
pub async fn router() -> Router<AppState> {
    let config = config().await;

    let cors = CorsLayer::new()
        // PUT/GET/DELETE are load-bearing for chunked uploads: without them
        // the browser preflight kills every part PUT, status GET and abort
        .allow_methods([Method::POST, Method::PUT, Method::GET, Method::DELETE])
        .allow_headers(AllowHeaders::mirror_request())
        .expose_headers(vec![
            "X-RateLimit-Limit".try_into().unwrap(),
            "X-RateLimit-Bucket".try_into().unwrap(),
            "X-RateLimit-Remaining".try_into().unwrap(),
            "X-RateLimit-Reset-After".try_into().unwrap(),
        ])
        .allow_origin(Any);

    Router::new()
        .route("/", get(root))
        // E2EE blob routes: static segments take precedence over the
        // parameterised tag routes below
        .route(
            "/e2ee",
            post(crate::e2ee::upload_blob)
                .options(options)
                .layer(DefaultBodyLimit::max(crate::e2ee::E2EE_BLOB_BODY_LIMIT)),
        )
        .route("/e2ee/:blob_id", get(crate::e2ee::fetch_blob))
        // Chunked/resumable uploads. The literal `upload` segment wins over
        // the `/:tag/:file_id` parameter route (axum static-over-param
        // precedence), and file ids are 42-char nanoids so `upload` can
        // never be a real file id.
        .route(
            "/:tag/upload/create",
            post(crate::upload::create_upload).options(options),
        )
        .route(
            "/:tag/upload/:session_id",
            get(crate::upload::get_upload_session)
                .delete(crate::upload::abort_upload)
                .options(options),
        )
        .route(
            "/:tag/upload/:session_id/part/:part_number",
            axum::routing::put(crate::upload::upload_part)
                .options(options)
                // One chunk + slack, NOT the multi-GB global limit — a
                // misbehaving client cannot stream an unbounded body here
                .layer(DefaultBodyLimit::max(crate::upload::PART_BODY_LIMIT)),
        )
        .route(
            "/:tag/upload/:session_id/complete",
            post(crate::upload::complete_upload).options(options),
        )
        .route(
            "/:tag",
            post(upload_file)
                .options(options)
                .layer(DefaultBodyLimit::max(
                    config.features.limits.global.body_limit_size,
                )),
        )
        .route("/:tag/:file_id", get(fetch_preview))
        .route("/:tag/:file_id/:file_name", get(fetch_file))
        .layer(cors)
}

lazy_static! {
    /// Short-lived file cache to allow us to populate different CDN regions without increasing bandwidth to S3 provider
    /// Uploads will also be stored here to prevent immediately queued downloads from doing the entire round-trip
    static ref S3_CACHE: moka::future::Cache<String, Result<Vec<u8>>> = moka::future::Cache::builder()
        .weigher(|_key, value: &Result<Vec<u8>>| -> u32 {
            std::mem::size_of::<Result<Vec<u8>>>() as u32 + if let Ok(vec) = value {
                vec.len().try_into().unwrap_or(u32::MAX)
            } else {
                std::mem::size_of::<Error>() as u32
            }
        })
        // TODO config
        // .max_capacity(1024 * 1024 * 1024) // Cache up to 1GiB in memory
        // .max_capacity(512 * 1024 * 1024) // Cache up to 512MiB in memory
        .max_capacity(2 * 1024 * 1024 * 1024) // Cache up to 2GiB in memory
        .time_to_live(Duration::from_secs(5 * 60)) // For up to 5 minutes
        .build();
}

/// Objects above this size are served without inserting into [`S3_CACHE`] —
/// a burst of large legacy fetches must not evict the whole cache. (v2
/// chunked objects never reach this path at all; they stream.)
const CACHE_INSERT_MAX_SIZE: isize = 16 * 1024 * 1024;

/// Retrieve hash information and file data by given hash (LEGACY formats
/// only — v2 objects are streamed by `download::serve_v2`, never buffered)
async fn retrieve_file_by_hash(hash: &FileHash) -> Result<Vec<u8>> {
    if let Some(data) = S3_CACHE.get(&hash.id).await {
        data
    } else {
        let data = fetch_from_s3(
            &hash.bucket_id,
            &hash.path,
            &hash.iv,
            hash.key_id.as_deref(),
        )
        .await;

        // Only successes are cached: a transient S3 or key error must not be
        // served back for the cache's whole lifetime
        if data.is_ok() && hash.size <= CACHE_INSERT_MAX_SIZE {
            S3_CACHE.insert(hash.id.to_owned(), data.clone()).await;
        }
        data
    }
}

/// Successful root response
#[derive(Serialize, Debug, ToSchema)]
pub struct RootResponse {
    autumn: &'static str,
    version: &'static str,
}

/// Capture crate version from Cargo
static CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Root response from service
#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = 200, description = "Echo response", body = RootResponse)
    )
)]
async fn root() -> Json<RootResponse> {
    Json(RootResponse {
        autumn: "Hello, I am a file server!",
        version: CRATE_VERSION,
    })
}

/// Empty handler for OPTIONS routes
async fn options() {}

/// Available tags to upload to
#[derive(Clone, Deserialize, Debug, ToSchema, strum_macros::IntoStaticStr)]
#[allow(non_camel_case_types)]
pub enum Tag {
    attachments,
    avatars,
    backgrounds,
    icons,
    banners,
    emojis,
    stickers,
    soundboard,
}

/// Request body for upload
#[derive(ToSchema, TryFromMultipart)]
pub struct UploadPayload {
    #[schema(format = Binary)]
    #[allow(dead_code)]
    #[form_data(limit = "unlimited")] // handled by axum
    file: FieldData<NamedTempFile>,
}

/// Successful upload response
#[derive(Serialize, Debug, ToSchema)]
pub struct UploadResponse {
    /// ID to attach uploaded file to object
    pub id: String,
}

/// Upload a file
///
/// Available tags and restrictions:
///
/// | Tag | Size | Resolution | Type |
/// | :-: | --: | :-- | :-: |
/// | attachments | 20 MB | - | Any |
/// | avatars | 4 MB | 40 MP or 10,000px | Image |
/// | backgrounds | 6 MB | 40 MP or 10,000px | Image |
/// | icons | 2.5 MB | 40 MP or 10,000px | Image |
/// | banners | 6 MB | 40 MP or 10,000px | Image |
/// | emojis | 500 KB | 40 MP or 10,000px | Image |
#[utoipa::path(
    post,
    path = "/{tag}",
    responses(
        (status = 200, description = "Upload was successful", body = UploadResponse)
    ),
    params(
        ("tag" = Tag, Path, description = "Tag to upload to (e.g. attachments, icons, ...)")
    ),
    request_body(content_type = "multipart/form-data", content = UploadPayload),
    security(
        ("session_token" = []),
        ("bot_token" = [])
    )
)]
async fn upload_file(
    State(db): State<Database>,
    user: User,
    Path(tag): Path<Tag>,
    TypedMultipart(UploadPayload { mut file }): TypedMultipart<UploadPayload>,
) -> Result<Json<UploadResponse>> {
    // Fetch configuration
    let config = config().await;

    // Keep track of processing time
    let now = Instant::now();

    // Extract the filename, or give it a generic name
    let filename = file.metadata.file_name.unwrap_or("unnamed-file".to_owned());

    // Take note of original file size
    //
    // The multipart extractor has already streamed the body to a temp file on
    // disk, so the length comes from there. Everything up to the dedupe check
    // below works off disk too — an oversized, blocked or already-known upload
    // now bails out without ever allocating the file in memory.
    let original_file_size =
        report_internal_error!(file.contents.as_file().metadata())?.len() as usize;

    // Ensure the file is not empty
    if original_file_size < config.files.limit.min_file_size {
        return Err(create_error!(FileTooSmall));
    }

    // Get user's file upload limits
    let limits = user.limits().await;
    let size_limit = *limits
        .file_upload_size_limit
        .get(tag.clone().into())
        .expect("size limit");

    if original_file_size > size_limit {
        return Err(create_error!(FileTooLarge { max: size_limit }));
    }

    // Generate sha256 hash by streaming the file off disk
    let original_hash = report_internal_error!(hash_file(file.contents.as_file_mut()))?;

    // Generate an ID for this file
    let id = if matches!(tag, Tag::emojis) {
        ulid::Ulid::new().to_string()
    } else {
        nanoid::nanoid!(42)
    };

    // Determine the mime type for the file
    let mime_type = determine_mime_type(&mut file.contents, &filename);

    // Check blocklist for mime type
    if config
        .files
        .blocked_mime_types
        .iter()
        .any(|m| m == mime_type)
    {
        return Err(create_error!(FileTypeNotAllowed));
    }

    // Determine metadata for the file
    let metadata = generate_metadata(&file.contents, mime_type);

    // Enforce per-tag content type:
    // - attachments accept anything
    // - soundboard accepts audio only (short voice-call clips)
    // - every other tag is image-only
    match tag {
        Tag::attachments => {}
        Tag::soundboard => {
            if !matches!(metadata, Metadata::Audio) {
                return Err(create_error!(FileTypeNotAllowed));
            }
        }
        _ => {
            if !matches!(metadata, Metadata::Image { .. }) {
                return Err(create_error!(FileTypeNotAllowed));
            }
        }
    }

    // Object a stale-video reprocess replaces, deleted once the new row is in
    let mut superseded_object: Option<(String, String)> = None;

    // Find an existing hash and use that if possible
    let file_hash_exists = if let Ok(file_hash) = db
        .fetch_attachment_hash(&format!("{original_hash:02x}"))
        .await
    {
        // Video hashes recorded before web transcoding existed (or while ffprobe
        // was unavailable) carry a stale `File` classification; reprocess the
        // upload and replace the record instead of inheriting it
        let stale_video = matches!(file_hash.metadata, Metadata::File)
            && file_hash.content_type.starts_with("video/");

        if !file_hash.iv.is_empty() && !stale_video {
            // The stored file may have been transcoded into a different container
            let filename = filename_for_mime(filename, mime_type, &file_hash.content_type);

            let tag: &'static str = tag.into();
            db.insert_attachment(&file_hash.into_file(
                id.clone(),
                tag.to_owned(),
                filename,
                user.id,
            ))
            .await?;

            return Ok(Json(UploadResponse { id }));
        }

        if stale_video {
            // The row is the only reference to its object, and the replacement
            // goes to a fresh path, so note the old one before the row goes
            superseded_object = Some((file_hash.bucket_id.clone(), file_hash.path.clone()));
            db.delete_attachment_hash(&file_hash.id).await?;
            false
        } else {
            true
        }
    } else {
        false
    };

    // Past the dedupe early-exit, so this upload is genuinely new: pull it into
    // memory for metadata stripping and the S3 upload, both of which need the
    // whole thing
    let mut buf = Vec::<u8>::with_capacity(original_file_size);
    report_internal_error!(file.contents.as_file_mut().seek(SeekFrom::Start(0)))?;
    report_internal_error!(file.contents.read_to_end(&mut buf))?;

    // Strip metadata; videos may also be remuxed/transcoded for inline playback,
    // changing their mime type and container
    let (buf, metadata, new_mime_type) =
        strip_metadata(file.contents, buf, metadata, mime_type).await?;
    let filename = filename_for_mime(filename, mime_type, &new_mime_type);
    let mime_type = new_mime_type;

    // Virus scan files if ClamAV is configured
    if matches!(metadata, Metadata::File)
        && (config.files.scan_mime_types.is_empty()
            || config.files.scan_mime_types.iter().any(|v| v == &mime_type))
        && crate::clamav::is_malware(&buf).await?
    {
        return Err(create_error!(InternalError));
    }

    // Print file information for debug purposes
    let new_file_size = buf.len() + AUTHENTICATION_TAG_SIZE_BYTES;
    let processed_hash = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&buf);
        hasher.finalize()
    };
    let process_ratio = new_file_size as f32 / original_file_size as f32;
    let time_to_process = Instant::now() - now;

    tracing::info!("Received file {filename}\nOriginal hash: {original_hash:02x}\nOriginal size: {original_file_size} bytes\nMime type: {mime_type}\nMetadata: {metadata:?}\nProcessed file size: {new_file_size} bytes ({:.2}%).\nProcessed hash: {processed_hash:02x}\nProcessing took {time_to_process:?}", process_ratio * 100.0);

    // Create hash entry in database
    let file_hash = FileHash {
        id: format!("{original_hash:02x}"),
        processed_hash: format!("{processed_hash:02x}"),

        created_at: Timestamp::now_utc(),

        bucket_id: config.files.s3.default_bucket,
        path: format!("{original_hash:02x}"),
        iv: String::new(), // indicates file is not uploaded yet
        format_version: None, // legacy whole-file GCM format
        key_id: None,         // set with the real path and nonce below

        metadata,
        content_type: mime_type,
        size: new_file_size as isize,
    };

    // Add attachment hash if it doesn't exist
    if !file_hash_exists {
        db.insert_attachment_hash(&file_hash).await?;
    }

    // Upload the file to S3 under a fresh object key, then commit its path,
    // nonce and file key id to the database together
    let upload_start = Instant::now();
    let kid: Option<String> = FileKeyring::global().await.primary_id().map(str::to_string);
    let path = FileHash::new_object_path(kid.as_deref());
    let (iv, rkid) = upload_to_s3(&file_hash.bucket_id, &path, &buf).await?;

    // The object must be under the key its path and row will name
    if rkid != kid {
        tracing::error!(
            "file key mismatch uploading {}: expected {}, encrypted under {}",
            file_hash.id,
            kid.as_deref().unwrap_or(LEGACY_KEY_ID),
            rkid.as_deref().unwrap_or(LEGACY_KEY_ID)
        );
        discard_object(&file_hash.bucket_id, &path).await;
        return Err(create_error!(InternalError));
    }

    commit_storage(
        &db,
        &file_hash.bucket_id,
        &file_hash.id,
        &path,
        &iv,
        rkid.as_deref(),
        superseded_object,
    )
    .await?;

    // Debug information
    let time_to_upload = Instant::now() - upload_start;
    tracing::info!("Took {time_to_upload:?} to upload {new_file_size} bytes to S3.");

    // Finally, create the file and return its ID
    let tag: &'static str = tag.into();
    db.insert_attachment(&file_hash.into_file(id.clone(), tag.to_owned(), filename, user.id))
        .await?;

    Ok(Json(UploadResponse { id }))
}

/// Point the hash row at the object just uploaded to `bucket_id`/`path`, then
/// drop the object a stale-video reprocess replaced, if any.
///
/// If the row update fails, nothing references the new object, so it is
/// deleted and the error propagates; the superseded object is left alone. Once
/// the row is in, nothing references the superseded object, so it is deleted
/// (best effort) unless it is the very object the row now names.
async fn commit_storage(
    db: &Database,
    bucket_id: &str,
    file_hash_id: &str,
    path: &str,
    iv: &str,
    rkid: Option<&str>,
    superseded: Option<(String, String)>,
) -> Result<()> {
    if let Err(error) = db
        .set_attachment_hash_storage(file_hash_id, path, iv, rkid)
        .await
    {
        discard_object(bucket_id, path).await;
        return Err(error);
    }

    // Nothing points at the replaced object any more
    if let Some((old_bucket_id, old_path)) = superseded {
        if is_other_object(&old_bucket_id, &old_path, bucket_id, path) {
            discard_object(&old_bucket_id, &old_path).await;
        }
    }

    Ok(())
}

/// Best-effort removal of an object no hash row points at. A failure is
/// logged and never fails the request
async fn discard_object(bucket_id: &str, path: &str) {
    if let Err(error) = delete_from_s3(bucket_id, path).await {
        tracing::warn!("failed to delete unreferenced object {path} from {bucket_id}: {error:?}");
    }
}

/// Whether the old (bucket, path) names a different object from the new one,
/// so deleting it cannot touch the object the row now points at
fn is_other_object(old_bucket_id: &str, old_path: &str, bucket_id: &str, path: &str) -> bool {
    old_bucket_id != bucket_id || old_path != path
}

/// Rewrite a filename's extension when processing moved the file into a
/// different container (e.g. `clip.mkv` transcoded to mp4 becomes `clip.mp4`)
fn filename_for_mime(filename: String, old_mime: &str, new_mime: &str) -> String {
    if old_mime == new_mime {
        return filename;
    }

    let ext = match new_mime {
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        _ => return filename,
    };

    match filename.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => format!("{stem}.{ext}"),
        _ => format!("{filename}.{ext}"),
    }
}

#[cfg(test)]
mod upload_tests {
    use super::{commit_storage, filename_for_mime, is_other_object};
    use revolt_database::{iso8601_timestamp::Timestamp, Database, FileHash, Metadata};
    use revolt_files::{
        delete_from_s3, fetch_from_s3, object_exists_in_s3, upload_to_s3, FileKeyring,
    };
    use sha2::Digest;

    /// The scratch bucket `upload.rs`'s S3-backed tests use; never the prod one
    const TEST_BUCKET: &str = "autumn-upload-tests";

    /// Point the cached global config at [`TEST_BUCKET`], and prove the
    /// override actually reached it (the same check as `upload.rs`). The
    /// prefix is REVOLT__ with a DOUBLE underscore; a single one is dropped
    /// silently and the test would run against the dev bucket. The config is
    /// built once per process, so this holds under nextest (one process per
    /// test).
    async fn test_env() {
        std::env::set_var("REVOLT__FILES__S3__DEFAULT_BUCKET", TEST_BUCKET);
        assert_eq!(
            revolt_config::config().await.files.s3.default_bucket,
            TEST_BUCKET,
            "S3 default_bucket override never reached the config"
        );
    }

    async fn ensure_bucket() {
        use revolt_files::{EncryptionKey, FileStorageRepository, S3Storage};
        let storage = S3Storage::from_config(EncryptionKey::from_config().await).await;
        // Already-exists is fine
        let _ = storage.create_bucket(TEST_BUCKET).await;
    }

    async fn exists(path: &str) -> bool {
        object_exists_in_s3(TEST_BUCKET, path).await.unwrap()
    }

    /// The placeholder row the handler inserts before its PUT (pin d): path
    /// is the hash id and the empty iv means "not uploaded yet"
    fn placeholder_row(id: &str) -> FileHash {
        FileHash {
            id: id.to_string(),
            processed_hash: id.to_string(),
            created_at: Timestamp::now_utc(),
            bucket_id: TEST_BUCKET.to_string(),
            path: id.to_string(),
            iv: String::new(),
            format_version: None,
            key_id: None,
            metadata: Metadata::File,
            content_type: "video/mp4".to_string(),
            size: 0,
        }
    }

    /// The state `commit_storage` sees on a stale-video reprocess
    struct Reprocessed {
        /// The hash id, which is also OLD: a legacy row's object path
        id: String,
        new_path: String,
        new_iv: String,
        new_kid: Option<String>,
        superseded: Option<(String, String)>,
    }

    /// A legacy stale-video row has its object at OLD (its hash-id path). The
    /// handler then notes OLD, drops the row, inserts the placeholder, and
    /// PUTs the replacement to a fresh rk/ path under the primary key (pin a)
    async fn stale_video_reprocessed(db: &Database) -> Reprocessed {
        let id = format!(
            "{:02x}",
            sha2::Sha256::digest(ulid::Ulid::new().to_string())
        );

        let (old_iv, old_kid) = upload_to_s3(TEST_BUCKET, &id, b"old video").await.unwrap();
        db.insert_attachment_hash(&FileHash {
            iv: old_iv,
            key_id: old_kid,
            ..placeholder_row(&id)
        })
        .await
        .unwrap();
        assert!(exists(&id).await, "setup: the old object is in place");

        let old = db.fetch_attachment_hash(&id).await.unwrap();
        let superseded = Some((old.bucket_id.clone(), old.path.clone()));
        db.delete_attachment_hash(&id).await.unwrap();
        db.insert_attachment_hash(&placeholder_row(&id))
            .await
            .unwrap();

        let kid = FileKeyring::global().await.primary_id().map(str::to_string);
        let new_path = FileHash::new_object_path(kid.as_deref());
        let (new_iv, new_kid) = upload_to_s3(TEST_BUCKET, &new_path, b"new video")
            .await
            .unwrap();
        assert_eq!(new_kid, kid, "setup: the new object is under the primary");
        assert_ne!(new_path, id, "setup: the replacement has its own path");

        Reprocessed {
            id,
            new_path,
            new_iv,
            new_kid,
            superseded,
        }
    }

    /// Pin (f): once the replacement row is committed, the superseded object
    /// is deleted and the new one, which the row now names, survives
    #[tokio::test]
    async fn stale_video_commit_deletes_the_superseded_object() {
        test_env().await;
        ensure_bucket().await;
        let db = Database::Reference(Default::default());

        let r = stale_video_reprocessed(&db).await;
        commit_storage(
            &db,
            TEST_BUCKET,
            &r.id,
            &r.new_path,
            &r.new_iv,
            r.new_kid.as_deref(),
            r.superseded,
        )
        .await
        .unwrap();

        let row = db.fetch_attachment_hash(&r.id).await.unwrap();
        assert_eq!(row.path, r.new_path, "the row points at the new object");
        assert_eq!(row.iv, r.new_iv);
        assert_eq!(row.key_id, r.new_kid);
        assert!(
            !exists(&r.id).await,
            "the superseded object must be deleted"
        );
        assert!(exists(&r.new_path).await, "the new object must survive");
        assert_eq!(
            fetch_from_s3(TEST_BUCKET, &row.path, &row.iv, row.key_id.as_deref())
                .await
                .unwrap(),
            b"new video",
            "the row decrypts to the replacement"
        );

        let _ = delete_from_s3(TEST_BUCKET, &r.new_path).await;
    }

    /// Control: with nothing superseded, the commit deletes nothing, and a
    /// superseded entry naming the new object itself never deletes it
    #[tokio::test]
    async fn commit_without_a_distinct_superseded_object_deletes_nothing() {
        test_env().await;
        ensure_bucket().await;
        let db = Database::Reference(Default::default());

        let r = stale_video_reprocessed(&db).await;
        commit_storage(
            &db,
            TEST_BUCKET,
            &r.id,
            &r.new_path,
            &r.new_iv,
            r.new_kid.as_deref(),
            None,
        )
        .await
        .unwrap();
        let row = db.fetch_attachment_hash(&r.id).await.unwrap();
        assert_eq!(row.path, r.new_path, "the row points at the new object");
        assert!(exists(&r.id).await, "nothing superseded, so OLD stays");
        assert!(exists(&r.new_path).await, "the new object survives");

        // Superseded == the object the row now names
        commit_storage(
            &db,
            TEST_BUCKET,
            &r.id,
            &r.new_path,
            &r.new_iv,
            r.new_kid.as_deref(),
            Some((TEST_BUCKET.to_string(), r.new_path.clone())),
        )
        .await
        .unwrap();
        assert!(
            exists(&r.new_path).await,
            "the object the row names is never deleted"
        );

        let _ = delete_from_s3(TEST_BUCKET, &r.id).await;
        let _ = delete_from_s3(TEST_BUCKET, &r.new_path).await;
    }

    /// Pin (e): a missing row is NotFound; the unreferenced new object is
    /// deleted and the error propagates, and a failed commit never deletes
    /// the superseded object
    #[tokio::test]
    async fn commit_to_a_missing_row_discards_the_new_object() {
        test_env().await;
        ensure_bucket().await;
        let db = Database::Reference(Default::default());

        let r = stale_video_reprocessed(&db).await;
        // The row goes before the commit lands (e.g. a concurrent delete)
        db.delete_attachment_hash(&r.id).await.unwrap();

        let error = commit_storage(
            &db,
            TEST_BUCKET,
            &r.id,
            &r.new_path,
            &r.new_iv,
            r.new_kid.as_deref(),
            r.superseded,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error.error_type, revolt_result::ErrorType::NotFound),
            "a missing row must be NotFound, got {error:?}"
        );
        assert!(
            !exists(&r.new_path).await,
            "the unreferenced new object must be deleted"
        );
        assert!(
            exists(&r.id).await,
            "a failed commit leaves the superseded object alone"
        );

        let _ = delete_from_s3(TEST_BUCKET, &r.id).await;
    }

    #[test]
    fn replaced_object_is_deleted_only_when_distinct() {
        // A legacy hash-id object replaced by a fresh rk/ path
        assert!(is_other_object("files", "abc123", "files", "rk/k1/01J0"));
        // Same path in a different bucket is a different object
        assert!(is_other_object("old", "rk/k1/01J0", "files", "rk/k1/01J0"));
        // The object the row now points at is never deleted
        assert!(!is_other_object("files", "rk/k1/01", "files", "rk/k1/01"));
    }

    #[test]
    fn filename_follows_container_change() {
        assert_eq!(
            filename_for_mime("clip.mkv".into(), "video/x-matroska", "video/mp4"),
            "clip.mp4"
        );
        assert_eq!(
            filename_for_mime("archive.tar.mkv".into(), "video/x-matroska", "video/mp4"),
            "archive.tar.mp4"
        );
        assert_eq!(
            filename_for_mime("noext".into(), "video/x-msvideo", "video/mp4"),
            "noext.mp4"
        );
        // Unchanged mime keeps the name untouched
        assert_eq!(
            filename_for_mime("clip.mp4".into(), "video/mp4", "video/mp4"),
            "clip.mp4"
        );
        // Non-video rewrites are ignored
        assert_eq!(
            filename_for_mime("photo.jpeg".into(), "image/jpeg", "image/jpeg"),
            "photo.jpeg"
        );
    }
}

/// Header value used for cache control
pub static CACHE_CONTROL: &str = "public, max-age=604800, must-revalidate";

/// Fetch preview of file
///
/// This route will only return image content. <br>
/// For all other file types, please use the fetch route (you will receive a redirect if you try to use this route anyways!).
///
/// Depending on the given tag, the file will be re-processed to fit the criteria:
///
/// | Tag | Image Resolution <sup>†</sup> | Animations stripped by preview <sup>‡</sup> |
/// | :-: | --- | :-: |
/// | attachments | Up to 1280px on any axis | ❌ |
/// | avatars | Up to 128px on any axis | ✅ |
/// | backgrounds | Up to 1280x720px | ❌ |
/// | icons | Up to 128px on any axis | ✅ |
/// | banners | Up to 480px on any axis | ❌ |
/// | emojis | Up to 128px on any axis | ❌ |
///
/// <sup>†</sup> aspect ratio will always be preserved
///
/// <sup>‡</sup> to fetch animated variant, suffix `/{file_name}` or `/original` to the path
#[utoipa::path(
    get,
    path = "/{tag}/{file_id}",
    responses(
        (status = 200, description = "Generated preview", body = Vec<u8>)
    ),
    params(
        ("tag" = Tag, Path, description = "Tag to fetch from (e.g. attachments, icons, ...)"),
        ("file_id" = String, Path, description = "File identifier")
    ),
)]
async fn fetch_preview(
    State(db): State<Database>,
    Path((tag, file_id)): Path<(Tag, String)>,
) -> Result<Response> {
    let tag_str: &'static str = tag.clone().into();
    let file = db.fetch_attachment(tag_str, &file_id).await?;

    // Ignore deleted files
    if file.deleted.is_some_and(|v| v) {
        return Err(create_error!(NotFound));
    }

    // Ignore files that haven't been attached
    if file.used_for.is_none() {
        return Err(create_error!(NotFound));
    }

    let hash = file.as_hash(&db).await?;

    let mut data = None;

    // If animated is unset, check the file contents to see if it is animated and update the filehash
    let is_animated = match &hash.metadata {
        Metadata::Image {
            animated: Some(value),
            ..
        } => *value,
        Metadata::Image { animated: None, .. } => {
            let file_data = retrieve_file_by_hash(&hash).await?;

            let mut named_file = NamedTempFile::new().to_internal_error()?;
            named_file.write(&file_data).to_internal_error()?;

            data = Some(file_data);

            // If it fails for some reason, set it to not be animated
            let animated = is_animated(&named_file, &hash.content_type).unwrap_or(false);
            db.set_attachment_hash_animated(&hash.id, animated).await?;

            animated
        }
        _ => false,
    };

    // Serve the original (animated) file for non-images and for animated
    // images — except avatars, which keep a static thumbnail on the base URL
    // (the client fetches their animated variant explicitly). Animated *icons*
    // animate on the base URL so server icons play everywhere, including shells
    // that only ever request the base URL (e.g. the bundled desktop app).
    if !matches!(hash.metadata, Metadata::Image { .. })
        || (is_animated && !matches!(tag, Tag::avatars))
    {
        // Relative redirect so it survives a reverse-proxy path prefix (e.g.
        // Caddy serving Autumn under `/media`). An absolute `/{tag}/...`
        // Location loses the prefix and 404s to the SPA. Temporary so clients
        // that cached the old broken 308 recover.
        return Ok(
            Redirect::temporary(&format!("{file_id}/{}", encode_component(&file.filename)))
                .into_response(),
        );
    }

    // Original image data
    let data = if let Some(data) = data {
        data
    } else {
        retrieve_file_by_hash(&hash).await?
    };

    // Read image and create thumbnail
    let data = create_thumbnail(
        decode_image(&mut Cursor::new(data), &file.content_type)?,
        tag_str,
    )
    .await;

    Ok((
        [
            (header::CONTENT_TYPE, "image/webp"),
            (header::CONTENT_DISPOSITION, "inline"),
            (header::CACHE_CONTROL, CACHE_CONTROL),
        ],
        data,
    )
        .into_response())
}

/// Fetch original file
///
/// Content disposition header will be set to 'attachment' to prevent browser from rendering anything.
///
/// Using `original` as the file name parameter will redirect you to the original file.
#[utoipa::path(
    get,
    path = "/{tag}/{file_id}/{file_name}",
    responses(
        (status = 200, description = "Original file", body = Vec<u8>)
    ),
    params(
        ("tag" = Tag, Path, description = "Tag to fetch from (e.g. attachments, icons, ...)"),
        ("file_id" = String, Path, description = "File identifier"),
        ("file_name" = String, Path, description = "File name")
    ),
)]
async fn fetch_file(
    State(db): State<Database>,
    headers: axum::http::HeaderMap,
    Path((tag, file_id, file_name)): Path<(Tag, String, String)>,
) -> Result<Response> {
    let tag: &'static str = tag.clone().into();
    let file = db.fetch_attachment(tag, &file_id).await?;

    // Ignore deleted files
    if file.deleted.is_some_and(|v| v) {
        return Err(create_error!(NotFound));
    }

    // Ignore files that haven't been attached
    if file.used_for.is_none() {
        return Err(create_error!(NotFound));
    }

    // Ensure filename is correct
    if file_name != file.filename {
        if file_name == "original" {
            let safe_filename = encode_component(&file.filename);

            // Relative redirect (sibling of `original`) so it survives a
            // reverse-proxy path prefix (e.g. Caddy serving Autumn under
            // `/media`). An absolute `/{tag}/...` Location loses the prefix and
            // 404s to the SPA, which is why <img src=.../original> renders
            // blank. Temporary so clients that cached the old broken 308 recover.
            return Ok(Redirect::temporary(&safe_filename).into_response());
        }

        return Err(create_error!(NotFound));
    }

    let hash = file.as_hash(&db).await?;
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());

    match hash.format_version {
        // v2 segmented objects stream (multi-GB safe) with Range support
        Some(2) => crate::download::serve_v2(&hash, range).await,
        Some(other) => {
            tracing::error!("unknown FileHash format_version {other} for {}", hash.id);
            Err(create_error!(InternalError))
        }
        // Legacy whole-file objects: buffered exactly as before (bounded
        // ≤ ~100 MB by the historical upload wall), now with Range support
        None => {
            let data = retrieve_file_by_hash(&hash).await?;
            crate::download::serve_legacy_buffer(&hash, data, range)
        }
    }
}
