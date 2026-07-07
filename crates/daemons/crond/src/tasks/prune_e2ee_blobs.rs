use std::time::{Duration, SystemTime};

use revolt_database::{Database, E2EEBlob, E2EE_LARGE_BLOB_SIZE};
use revolt_files::delete_from_s3;
use revolt_result::Result;
use tokio::time::sleep;
use ulid::Ulid;

/// E2EE attachment blobs are transit storage, not history (slice 3.5 blob
/// lifecycle). The primary deletion happens on the last recipient fetch;
/// these TTLs are the absolute backstop, enforced even under partial
/// delivery — a device that missed the window sees "attachment expired
/// before delivery" (honesty about loss), devices that fetched keep their
/// local copy.
///
/// Large blobs (> 10 MiB) expire 24 hours after upload; everything else
/// follows the 30-day envelope TTL.
const LARGE_BLOB_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const BLOB_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Delete every blob older than `ttl` with size > `min_size` — the S3
/// object first, then the record (so a failed S3 delete keeps the record
/// around for the next sweep instead of orphaning the object).
async fn sweep(db: &Database, ttl: Duration, min_size: isize) -> Result<usize> {
    let threshold = Ulid::from_datetime(SystemTime::now() - ttl).to_string();

    let mut swept = 0;
    for blob in db.fetch_expired_e2ee_blobs(&threshold, min_size).await? {
        match delete_from_s3(&blob.bucket_id, &E2EEBlob::s3_path(&blob.id)).await {
            Ok(()) => {
                db.delete_e2ee_blob(&blob.id).await?;
                swept += 1;
            }
            Err(error) => {
                log::error!(
                    "failed to delete expired E2EE blob {} from S3 (will retry next sweep): {error:?}",
                    blob.id
                );
            }
        }
    }

    Ok(swept)
}

pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    loop {
        let large = sweep(&db, LARGE_BLOB_TTL, E2EE_LARGE_BLOB_SIZE).await?;
        let expired = sweep(&db, BLOB_TTL, 0).await?;
        log::info!("Swept {} expired E2EE blobs", large + expired);

        sleep(Duration::from_secs(60 * 60)).await
    }
}
