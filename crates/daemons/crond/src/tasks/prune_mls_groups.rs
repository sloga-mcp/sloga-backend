use std::time::Duration;

use iso8601_timestamp::Timestamp;
use revolt_database::Database;
use revolt_result::Result;
use tokio::time::sleep;

/// Closed call groups (call ended / superseded) are swept 24 hours after
/// closing — long enough for stragglers to observe the closure, worthless
/// afterwards (call groups are ephemeral; media-E2EE plan §2.5).
const CLOSED_TTL_HOURS: i64 = 24;

/// Backstop: ANY group older than 7 days is swept regardless of state — a
/// group whose `room_finished` webhook never landed must not live forever.
const CREATED_TTL_DAYS: i64 = 7;

pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    loop {
        let now = Timestamp::now_utc();
        let closed_threshold = now
            .checked_sub(iso8601_timestamp::Duration::hours(CLOSED_TTL_HOURS))
            .expect("subtraction cannot overflow");
        let created_threshold = now
            .checked_sub(iso8601_timestamp::Duration::days(CREATED_TTL_DAYS))
            .expect("subtraction cannot overflow");

        // Sweeps the groups plus their commits and join intents
        let count = db
            .sweep_mls_groups(closed_threshold, created_threshold)
            .await?;
        log::info!("Swept {count} expired MLS call groups");

        sleep(Duration::from_secs(60 * 60)).await
    }
}
