use std::io::Write;

use anyhow::Context;
use aws_sdk_s3::{
    config::{Credentials, Region},
    types::{CompletedMultipartUpload, CompletedPart},
    Client, Config,
};
use futures::{stream, StreamExt, TryStreamExt};
use revolt_config::FilesS3;

use crate::{EncryptionRepository, FileStorageRepository};

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

        let upload_id = created
            .upload_id()
            .with_context(|| format!("S3 returned no upload id for {path} in {bucket_id}"))?;

        match self.upload_parts(bucket_id, path, upload_id, buf).await {
            Ok(parts) => {
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
            Err(err) => {
                // Abandoned parts are billed until they are cleaned up, so make
                // a best effort to abort before surfacing the original failure.
                //
                // This cannot be airtight: dropping the part stream cancels
                // in-flight requests client-side, so a part already in flight
                // can land after the abort and survive it. The key is
                // deterministic, so retries of a failing upload accumulate
                // orphans under it — the bucket lifecycle rule is the backstop.
                if let Err(abort_err) = self
                    .client
                    .abort_multipart_upload()
                    .bucket(bucket_id)
                    .key(path)
                    .upload_id(upload_id)
                    .send()
                    .await
                {
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
    ) -> anyhow::Result<Vec<CompletedPart>> {
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

                let part = self
                    .client
                    .upload_part()
                    .bucket(bucket_id)
                    .key(path)
                    .upload_id(upload_id)
                    .part_number(part_number)
                    .body(chunk.into())
                    .send()
                    .await
                    .with_context(|| {
                        format!("failed to upload part {part_number} at {path} in {bucket_id}")
                    })?;

                // A missing ETag would otherwise surface as an opaque
                // `InvalidPart` from `complete_multipart_upload`
                let e_tag = part.e_tag().with_context(|| {
                    format!("S3 returned no e_tag for part {part_number} at {path} in {bucket_id}")
                })?;

                Ok::<_, anyhow::Error>(
                    CompletedPart::builder()
                        .e_tag(e_tag)
                        .part_number(part_number)
                        .build(),
                )
            }
        });

        let mut parts = stream::iter(uploads)
            .buffer_unordered(MULTIPART_CONCURRENCY)
            .try_collect::<Vec<_>>()
            .await?;

        // Parts complete out of order, but S3 requires them listed ascending
        parts.sort_by_key(|part| part.part_number());

        Ok(parts)
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
