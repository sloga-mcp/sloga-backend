use std::io::Write;

use anyhow::Context;
use aws_sdk_s3::{
    config::{Credentials, Region},
    error::SdkError,
    primitives::ByteStream,
    types::{
        AbortIncompleteMultipartUpload, BucketLifecycleConfiguration, CompletedMultipartUpload,
        CompletedPart, ExpirationStatus, LifecycleRule, LifecycleRuleFilter,
    },
    Client, Config,
};
use futures::{stream, StreamExt, TryStreamExt};
use revolt_config::FilesS3;

use crate::{EncryptionRepository, FileStorageRepository};

/// Days after initiation before the bucket lifecycle rule aborts an incomplete
/// multipart upload.
///
/// This is the *last-line* backstop behind the `UploadSession` TTL sweep —
/// it MUST stay strictly longer than the 48 h session TTL, or MinIO will abort
/// still-active resumable uploads out from under their sessions.
pub const LIFECYCLE_ABORT_DAYS: i32 = 3;

/// Objects at or below this size are sent as a single PUT
///
/// Multipart has a fixed round-trip cost (create + complete), so it only pays
/// off once there is enough data to overlap several parts.
const MULTIPART_THRESHOLD: usize = 16 * 1024 * 1024;

/// Size of each part in a multipart upload
///
/// S3 requires every part except the last to be at least 5 MiB.
const MULTIPART_PART_SIZE: usize = 16 * 1024 * 1024;

/// How many parts to keep in flight at once
const MULTIPART_CONCURRENCY: usize = 4;

pub struct S3Storage<ER: EncryptionRepository> {
    client: Client,
    encryption: ER,
}

impl<ER: EncryptionRepository> S3Storage<ER> {
    pub async fn from_config(encryption: ER) -> S3Storage<ER> {
        S3Storage::new(encryption, revolt_config::config().await.files.s3)
    }

    pub fn new(encryption: ER, s3_config: FilesS3) -> S3Storage<ER> {
        let provider_name = "my-creds";
        let creds = Credentials::new(
            s3_config.access_key_id,
            s3_config.secret_access_key,
            None,
            None,
            provider_name,
        );

        let config = Config::builder()
            .region(Region::new(s3_config.region))
            .endpoint_url(s3_config.endpoint)
            .force_path_style(s3_config.path_style_buckets)
            .credentials_provider(creds)
            .build();

        S3Storage {
            client: Client::from_conf(config),
            encryption,
        }
    }

    /// Begin a multipart upload, returning the S3 upload id
    ///
    /// The returned id is what makes the three multipart phases usable across
    /// separate HTTP requests (chunked uploads persist it in an
    /// `UploadSession`); the in-process [`Self::multipart_upload`] path uses
    /// the same primitives within one call.
    pub async fn create_multipart(&self, bucket_id: &str, path: &str) -> anyhow::Result<String> {
        let created = self
            .client
            .create_multipart_upload()
            .bucket(bucket_id)
            .key(path)
            .send()
            .await
            .with_context(|| {
                format!("failed to create multipart upload at {path} in {bucket_id}")
            })?;

        created
            .upload_id()
            .map(str::to_owned)
            .with_context(|| format!("S3 returned no upload id for {path} in {bucket_id}"))
    }

    /// Upload one part of a multipart upload, returning its ETag
    ///
    /// Part numbers are 1-based. Mirrors the builder shape proven against
    /// MinIO on aws-sdk-s3 1.137 (etag + part_number only — no checksum
    /// fields).
    pub async fn upload_part(
        &self,
        bucket_id: &str,
        path: &str,
        upload_id: &str,
        part_number: i32,
        body: Vec<u8>,
    ) -> anyhow::Result<String> {
        let part = self
            .client
            .upload_part()
            .bucket(bucket_id)
            .key(path)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(body.into())
            .send()
            .await
            .with_context(|| {
                format!("failed to upload part {part_number} at {path} in {bucket_id}")
            })?;

        // A missing ETag would otherwise surface as an opaque
        // `InvalidPart` from `complete_multipart_upload`
        part.e_tag()
            .map(str::to_owned)
            .with_context(|| {
                format!("S3 returned no e_tag for part {part_number} at {path} in {bucket_id}")
            })
    }

    /// Assemble a multipart upload from its recorded `(part_number, etag)`
    /// pairs (any order; sorted here — S3 requires ascending)
    pub async fn complete_multipart(
        &self,
        bucket_id: &str,
        path: &str,
        upload_id: &str,
        parts: &[(i32, String)],
    ) -> anyhow::Result<()> {
        let mut parts: Vec<CompletedPart> = parts
            .iter()
            .map(|(part_number, e_tag)| {
                CompletedPart::builder()
                    .e_tag(e_tag)
                    .part_number(*part_number)
                    .build()
            })
            .collect();
        parts.sort_by_key(|part| part.part_number());

        self.client
            .complete_multipart_upload()
            .bucket(bucket_id)
            .key(path)
            .upload_id(upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(parts))
                    .build(),
            )
            .send()
            .await
            .with_context(|| {
                format!("failed to complete multipart upload at {path} in {bucket_id}")
            })?;

        Ok(())
    }

    /// Abort a multipart upload, dropping its stored parts
    ///
    /// A missing upload (already aborted by the lifecycle rule, or already
    /// completed) is success: the goal — no orphaned parts under this id —
    /// is met either way.
    pub async fn abort_multipart(
        &self,
        bucket_id: &str,
        path: &str,
        upload_id: &str,
    ) -> anyhow::Result<()> {
        match self
            .client
            .abort_multipart_upload()
            .bucket(bucket_id)
            .key(path)
            .upload_id(upload_id)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(SdkError::ServiceError(err))
                if err.raw().status().as_u16() == 404 =>
            {
                Ok(())
            }
            Err(err) => Err(err).with_context(|| {
                format!("failed to abort multipart upload at {path} in {bucket_id}")
            }),
        }
    }

    /// Whether an object exists at `path` (HeadObject)
    pub async fn object_exists(&self, bucket_id: &str, path: &str) -> anyhow::Result<bool> {
        match self
            .client
            .head_object()
            .bucket(bucket_id)
            .key(path)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(SdkError::ServiceError(err))
                if err.raw().status().as_u16() == 404 =>
            {
                Ok(false)
            }
            Err(err) => {
                Err(err).with_context(|| format!("failed to head object at {path} in {bucket_id}"))
            }
        }
    }

    /// Stream an object's raw (still-encrypted) bytes
    pub async fn fetch_stream(&self, bucket_id: &str, path: &str) -> anyhow::Result<ByteStream> {
        let object = self
            .client
            .get_object()
            .bucket(bucket_id)
            .key(path)
            .send()
            .await
            .with_context(|| format!("failed to get object at {path} in {bucket_id}"))?;

        Ok(object.body)
    }

    /// Stream an inclusive byte range of an object's raw bytes
    pub async fn fetch_range(
        &self,
        bucket_id: &str,
        path: &str,
        start: u64,
        end_inclusive: u64,
    ) -> anyhow::Result<ByteStream> {
        let object = self
            .client
            .get_object()
            .bucket(bucket_id)
            .key(path)
            .range(format!("bytes={start}-{end_inclusive}"))
            .send()
            .await
            .with_context(|| {
                format!(
                    "failed to get range {start}-{end_inclusive} at {path} in {bucket_id}"
                )
            })?;

        Ok(object.body)
    }

    /// Idempotently ensure incomplete multipart uploads get reaped
    /// server-side after [`LIFECYCLE_ABORT_DAYS`]
    ///
    /// Applied at service startup. Crashed chunked uploads orphan multipart
    /// state by design; the `UploadSession` sweep is the primary reaper and
    /// this is the backstop behind it.
    ///
    /// On AWS-compatible stores this is the `AbortIncompleteMultipartUpload`
    /// lifecycle rule. **MinIO does not support that rule** (rejects the XML
    /// as InvalidArgument — verified live 2026-07-26); its equivalent is the
    /// server-level `api stale_uploads_expiry` setting, which MUST be set
    /// longer than the 48 h session TTL:
    ///
    /// ```text
    /// mc admin config set <alias> api stale_uploads_expiry=72h
    /// ```
    ///
    /// (applied to prod 2026-07-26; the default 24 h would purge *live*
    /// day-2 resumable uploads). An InvalidArgument rejection here is
    /// therefore logged and treated as success.
    pub async fn ensure_bucket_lifecycle(&self, bucket_id: &str) -> anyhow::Result<()> {
        let rule = LifecycleRule::builder()
            .id("abort-incomplete-multipart-uploads")
            .status(ExpirationStatus::Enabled)
            .filter(LifecycleRuleFilter::builder().prefix("").build())
            .abort_incomplete_multipart_upload(
                AbortIncompleteMultipartUpload::builder()
                    .days_after_initiation(LIFECYCLE_ABORT_DAYS)
                    .build(),
            )
            .build()
            .context("failed to build lifecycle rule")?;

        let result = self
            .client
            .put_bucket_lifecycle_configuration()
            .bucket(bucket_id)
            .lifecycle_configuration(
                BucketLifecycleConfiguration::builder()
                    .rules(rule)
                    .build()
                    .context("failed to build lifecycle configuration")?,
            )
            .send()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(SdkError::ServiceError(err))
                if err.err().meta().code() == Some("InvalidArgument") =>
            {
                tracing::info!(
                    "{bucket_id}: store does not accept AbortIncompleteMultipartUpload \
                     lifecycle rules (MinIO); relying on its stale_uploads_expiry setting \
                     — ensure it is set to 72h"
                );
                Ok(())
            }
            Err(err) => Err(err)
                .with_context(|| format!("failed to apply lifecycle configuration to {bucket_id}")),
        }
    }

    /// Upload a buffer as a concurrent multipart upload
    ///
    /// The stored bytes are identical to those a single PUT would produce —
    /// multipart is invisible to `get_object` — so the on-S3 format is
    /// unchanged. Two caveats that are *not* about the bytes:
    ///
    /// - The object's ETag becomes `<md5-of-md5s>-<partcount>` rather than the
    ///   object MD5. Nothing reads ETags today; anything that starts to must not
    ///   treat them as a content hash, or it will be wrong for objects over
    ///   [`MULTIPART_THRESHOLD`] only.
    /// - Aborting is best-effort (see below), so the bucket needs an
    ///   `AbortIncompleteMultipartUpload` lifecycle rule to reap orphaned parts.
    async fn multipart_upload(
        &self,
        bucket_id: &str,
        path: &str,
        buf: &[u8],
    ) -> anyhow::Result<()> {
        let upload_id = self.create_multipart(bucket_id, path).await?;

        match self.upload_parts(bucket_id, path, &upload_id, buf).await {
            Ok(parts) => self.complete_multipart(bucket_id, path, &upload_id, &parts).await,
            Err(err) => {
                // Abandoned parts are billed until they are cleaned up, so make
                // a best effort to abort before surfacing the original failure.
                //
                // This cannot be airtight: dropping the part stream cancels
                // in-flight requests client-side, so a part already in flight
                // can land after the abort and survive it. The key is
                // deterministic, so retries of a failing upload accumulate
                // orphans under it — the bucket lifecycle rule is the backstop.
                if let Err(abort_err) = self.abort_multipart(bucket_id, path, &upload_id).await {
                    tracing::error!(
                        "failed to abort multipart upload at {path} in {bucket_id}: {abort_err}"
                    );
                }

                Err(err)
            }
        }
    }

    /// Upload every part of a multipart upload, a few at a time
    async fn upload_parts(
        &self,
        bucket_id: &str,
        path: &str,
        upload_id: &str,
        buf: &[u8],
    ) -> anyhow::Result<Vec<(i32, String)>> {
        // Indexed rather than `buf.chunks(..)`: a closure taking `&[u8]` binds a
        // fresh lifetime per call, which can't satisfy the higher-ranked bound
        // `buffer_unordered` needs. Taking a plain `usize` sidesteps that.
        let part_count = buf.len().div_ceil(MULTIPART_PART_SIZE);

        let uploads = (0..part_count).map(|index| {
            let start = index * MULTIPART_PART_SIZE;
            let end = usize::min(start + MULTIPART_PART_SIZE, buf.len());
            let chunk = buf[start..end].to_vec();

            async move {
                // S3 part numbers are 1-based
                let part_number = index as i32 + 1;
                let e_tag = self
                    .upload_part(bucket_id, path, upload_id, part_number, chunk)
                    .await?;

                Ok::<_, anyhow::Error>((part_number, e_tag))
            }
        });

        stream::iter(uploads)
            .buffer_unordered(MULTIPART_CONCURRENCY)
            .try_collect::<Vec<_>>()
            .await
    }
}

#[async_trait::async_trait]
impl<ER: EncryptionRepository> FileStorageRepository for S3Storage<ER> {
    async fn create_bucket(&self, bucket_id: &str) -> anyhow::Result<()> {
        self.client
            .create_bucket()
            .bucket(bucket_id)
            .send()
            .await
            .with_context(|| format!("failed to create bucket {bucket_id}"))?;

        Ok(())
    }

    async fn fetch_and_decrypt_file(
        &self,
        bucket_id: &str,
        path: &str,
        iv: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let mut object = self
            .client
            .get_object()
            .bucket(bucket_id)
            .key(path)
            .send()
            .await
            .with_context(|| format!("failed to get object at {path} in {bucket_id}"))?;

        let mut buf = vec![];
        while let Some(bytes) = object.body.next().await {
            let data = bytes?;
            buf.write_all(&data)?;
        }

        if iv.is_empty() {
            Ok(buf)
        } else {
            self.encryption.decrypt_buffer(buf, iv)
        }
    }

    async fn encrypt_and_upload_file(
        &self,
        bucket_id: &str,
        path: &str,
        buf: &[u8],
    ) -> anyhow::Result<String> {
        let (buf, iv) = self.encryption.encrypt_buffer(buf)?;

        if buf.len() > MULTIPART_THRESHOLD {
            self.multipart_upload(bucket_id, path, &buf).await?;
        } else {
            self.client
                .put_object()
                .bucket(bucket_id)
                .key(path)
                .body(buf.into())
                .send()
                .await
                .with_context(|| format!("failed to put object at {path} in {bucket_id}"))?;
        }

        Ok(iv)
    }

    async fn delete_file(&self, bucket_id: &str, path: &str) -> anyhow::Result<()> {
        self.client
            .delete_object()
            .bucket(bucket_id)
            .key(path)
            .send()
            .await
            .with_context(|| format!("failed to delete object at {path} in {bucket_id}"))?;

        Ok(())
    }
}
