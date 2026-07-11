use std::time::Duration;

use iso8601_timestamp::Timestamp;
use revolt_database::Database;
use revolt_result::Result;
use tokio::time::sleep;

/// Hourly sweep of expired MLS KeyPackages (media-E2EE plan §2.5).
/// Lifetimes are set at publish: 30 days for one-time packages (matching
/// the envelope TTL), 7 days for last-resort packages (the Welcome-FS
/// reduction is bounded tightly). Clients replenish on the same low-water
/// trigger as one-time keys.
pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    loop {
        let count = db
            .delete_expired_mls_key_packages(Timestamp::now_utc())
            .await?;
        log::info!("Swept {count} expired MLS key packages");

        sleep(Duration::from_secs(60 * 60)).await
    }
}
