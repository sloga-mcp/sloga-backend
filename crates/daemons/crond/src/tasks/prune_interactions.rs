use std::time::{Duration, SystemTime, UNIX_EPOCH};

use revolt_database::{Database, INTERACTION_TTL_MS};
use revolt_result::Result;
use tokio::time::sleep;

/// Storage hygiene for the transient `interactions` collection.
///
/// Expiry is enforced authoritatively at respond time (the route checks the
/// ULID clock); this sweep only stops expired rows from accumulating. The
/// cutoff is a ULID synthesised from (now - TTL), so deletion is a pure
/// `_id < cutoff` range scan on the primary index.
pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    loop {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);

        let cutoff = ulid::Ulid::from_parts(now_ms.saturating_sub(INTERACTION_TTL_MS), 0);
        db.delete_interactions_before(&cutoff.to_string()).await?;
        log::info!("Pruned expired interactions below {cutoff}");

        sleep(Duration::from_mins(15)).await
    }
}
