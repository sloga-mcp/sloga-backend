mod implementation;
mod repositories;

pub use implementation::*;
pub use repositories::*;

use std::io::{BufRead, Read, Seek};

use image::DynamicImage;
use revolt_config::{report_internal_error, Files, FilesLimit, FilesS3};
use revolt_result::Result;

use tempfile::NamedTempFile;

pub const AUTHENTICATION_TAG_SIZE_BYTES: usize = 16;

/// Fetch a file from S3 (and decrypt it)
pub async fn fetch_from_s3(bucket_id: &str, path: &str, iv: &str) -> Result<Vec<u8>> {
    let encryption = implementation::EncryptionKey::from_config().await;
    let storage = implementation::S3Storage::from_config(encryption).await;
    report_internal_error!(storage.fetch_and_decrypt_file(bucket_id, path, iv).await)
}

/// Encrypt and upload a file to S3 (returning its nonce/IV)
pub async fn upload_to_s3(bucket_id: &str, path: &str, buf: &[u8]) -> Result<String> {
    let encryption = implementation::EncryptionKey::from_config().await;
    let storage = implementation::S3Storage::from_config(encryption).await;
    report_internal_error!(storage.encrypt_and_upload_file(bucket_id, path, buf).await)
}

/// Delete a file from S3 by path
pub async fn delete_from_s3(bucket_id: &str, path: &str) -> Result<()> {
    let encryption = implementation::EncryptionKey::from_config().await;
    let storage = implementation::S3Storage::from_config(encryption).await;
    report_internal_error!(storage.delete_file(bucket_id, path).await)
}

async fn storage() -> S3Storage<EncryptionKey> {
    let encryption = implementation::EncryptionKey::from_config().await;
    implementation::S3Storage::from_config(encryption).await
}

/// Begin a multipart upload, returning the S3 upload id to persist
pub async fn create_multipart_in_s3(bucket_id: &str, path: &str) -> Result<String> {
    report_internal_error!(storage().await.create_multipart(bucket_id, path).await)
}

/// Upload one (already-encrypted) part of a multipart upload, returning its ETag
pub async fn upload_part_to_s3(
    bucket_id: &str,
    path: &str,
    upload_id: &str,
    part_number: i32,
    ciphertext: Vec<u8>,
) -> Result<String> {
    report_internal_error!(
        storage()
            .await
            .upload_part(bucket_id, path, upload_id, part_number, ciphertext)
            .await
    )
}

/// Assemble a multipart upload from recorded `(part_number, etag)` pairs
pub async fn complete_multipart_in_s3(
    bucket_id: &str,
    path: &str,
    upload_id: &str,
    parts: &[(i32, String)],
) -> Result<()> {
    report_internal_error!(
        storage()
            .await
            .complete_multipart(bucket_id, path, upload_id, parts)
            .await
    )
}

/// Abort a multipart upload (a missing upload counts as success)
pub async fn abort_multipart_in_s3(bucket_id: &str, path: &str, upload_id: &str) -> Result<()> {
    report_internal_error!(
        storage()
            .await
            .abort_multipart(bucket_id, path, upload_id)
            .await
    )
}

/// Whether an object exists at `path`
pub async fn object_exists_in_s3(bucket_id: &str, path: &str) -> Result<bool> {
    report_internal_error!(storage().await.object_exists(bucket_id, path).await)
}

/// Stream an object's raw (still-encrypted) bytes
pub async fn fetch_stream_from_s3(
    bucket_id: &str,
    path: &str,
) -> Result<aws_sdk_s3::primitives::ByteStream> {
    report_internal_error!(storage().await.fetch_stream(bucket_id, path).await)
}

/// Stream an inclusive byte range of an object's raw bytes
pub async fn fetch_range_from_s3(
    bucket_id: &str,
    path: &str,
    start: u64,
    end_inclusive: u64,
) -> Result<aws_sdk_s3::primitives::ByteStream> {
    report_internal_error!(
        storage()
            .await
            .fetch_range(bucket_id, path, start, end_inclusive)
            .await
    )
}

/// Idempotently apply the abort-incomplete-multipart lifecycle rule to a bucket
pub async fn ensure_bucket_lifecycle(bucket_id: &str) -> Result<()> {
    report_internal_error!(storage().await.ensure_bucket_lifecycle(bucket_id).await)
}

/// Determine size of image at temp file
pub fn image_size(f: &NamedTempFile) -> Option<(usize, usize)> {
    let media = MediaImpl::new(Files {
        blocked_mime_types: Default::default(),
        clamd_host: Default::default(),
        encryption_key: Default::default(),
        limit: FilesLimit {
            max_mega_pixels: 0,
            max_pixel_side: 0,
            min_file_size: 0,
            min_resolution: [0, 0],
        },
        preview: Default::default(),
        s3: FilesS3 {
            access_key_id: Default::default(),
            default_bucket: Default::default(),
            endpoint: Default::default(),
            path_style_buckets: Default::default(),
            region: Default::default(),
            secret_access_key: Default::default(),
        },
        scan_mime_types: Default::default(),
        webp_quality: Default::default(),
    });

    media.image_size(f)
}

/// Determine size of image with buffer
pub fn image_size_vec(v: &[u8], mime: &str) -> Option<(usize, usize)> {
    let media = MediaImpl::new(Files {
        blocked_mime_types: Default::default(),
        clamd_host: Default::default(),
        encryption_key: Default::default(),
        limit: FilesLimit {
            max_mega_pixels: 0,
            max_pixel_side: 0,
            min_file_size: 0,
            min_resolution: [0, 0],
        },
        preview: Default::default(),
        s3: FilesS3 {
            access_key_id: Default::default(),
            default_bucket: Default::default(),
            endpoint: Default::default(),
            path_style_buckets: Default::default(),
            region: Default::default(),
            secret_access_key: Default::default(),
        },
        scan_mime_types: Default::default(),
        webp_quality: Default::default(),
    });

    media.image_size_vec(v, mime)
}

/// Check whether an image file contains animation data
pub fn is_animated(f: &NamedTempFile, mime: &str) -> Option<bool> {
    let media = MediaImpl::new(Files {
        blocked_mime_types: Default::default(),
        clamd_host: Default::default(),
        encryption_key: Default::default(),
        limit: FilesLimit {
            max_mega_pixels: 0,
            max_pixel_side: 0,
            min_file_size: 0,
            min_resolution: [0, 0],
        },
        preview: Default::default(),
        s3: FilesS3 {
            access_key_id: Default::default(),
            default_bucket: Default::default(),
            endpoint: Default::default(),
            path_style_buckets: Default::default(),
            region: Default::default(),
            secret_access_key: Default::default(),
        },
        scan_mime_types: Default::default(),
        webp_quality: Default::default(),
    });

    media.is_animated(f, mime)
}

/// Determine size of video at temp file
pub fn video_size(f: &NamedTempFile) -> Option<(i64, i64)> {
    let media = MediaImpl::new(Files {
        blocked_mime_types: Default::default(),
        clamd_host: Default::default(),
        encryption_key: Default::default(),
        limit: FilesLimit {
            max_mega_pixels: 0,
            max_pixel_side: 0,
            min_file_size: 0,
            min_resolution: [0, 0],
        },
        preview: Default::default(),
        s3: FilesS3 {
            access_key_id: Default::default(),
            default_bucket: Default::default(),
            endpoint: Default::default(),
            path_style_buckets: Default::default(),
            region: Default::default(),
            secret_access_key: Default::default(),
        },
        scan_mime_types: Default::default(),
        webp_quality: Default::default(),
    });

    media.video_size(f)
}

/// Decode image from reader
pub fn decode_image<R: Read + BufRead + Seek>(reader: &mut R, mime: &str) -> Result<DynamicImage> {
    let media = MediaImpl::new(Files {
        blocked_mime_types: Default::default(),
        clamd_host: Default::default(),
        encryption_key: Default::default(),
        limit: FilesLimit {
            max_mega_pixels: 0,
            max_pixel_side: 0,
            min_file_size: 0,
            min_resolution: [0, 0],
        },
        preview: Default::default(),
        s3: FilesS3 {
            access_key_id: Default::default(),
            default_bucket: Default::default(),
            endpoint: Default::default(),
            path_style_buckets: Default::default(),
            region: Default::default(),
            secret_access_key: Default::default(),
        },
        scan_mime_types: Default::default(),
        webp_quality: Default::default(),
    });

    report_internal_error!(media.decode_image(reader, mime))
}

/// Check whether given reader has a valid image
pub fn is_valid_image<R: Read + BufRead + Seek>(reader: &mut R, mime: &str) -> bool {
    let media = MediaImpl::new(Files {
        blocked_mime_types: Default::default(),
        clamd_host: Default::default(),
        encryption_key: Default::default(),
        limit: FilesLimit {
            max_mega_pixels: 0,
            max_pixel_side: 0,
            min_file_size: 0,
            min_resolution: [0, 0],
        },
        preview: Default::default(),
        s3: FilesS3 {
            access_key_id: Default::default(),
            default_bucket: Default::default(),
            endpoint: Default::default(),
            path_style_buckets: Default::default(),
            region: Default::default(),
            secret_access_key: Default::default(),
        },
        scan_mime_types: Default::default(),
        webp_quality: Default::default(),
    });

    media.is_valid_image(reader, mime)
}

/// Create thumbnail from given image
pub async fn create_thumbnail(image: DynamicImage, tag: &str) -> Vec<u8> {
    let media = MediaImpl::from_config().await;
    media.create_thumbnail(image, tag)
}
