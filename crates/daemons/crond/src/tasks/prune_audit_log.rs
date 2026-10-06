use std::time::{Duration, SystemTime, UNIX_EPOCH};

use revolt_database::{Database, AUDIT_LOG_RETENTION_DAYS};
use revolt_result::Result;
use tokio::time::sleep;

/// Retention window in milliseconds. Evaluated at compile time, so an
/// overflowing retention constant fails the build rather than wrapping.
const AUDIT_LOG_RETENTION_MS: u64 = AUDIT_LOG_RETENTION_DAYS as u64 * 24 * 60 * 60 * 1000;

/// The prune cutoff for a given wall clock: a ULID whose timestamp is
/// (now - retention) and whose random part is zero, so every id minted
/// before that millisecond sorts strictly below it and every id minted at or
/// after it sorts at or above it.
fn audit_log_cutoff(now_ms: u64) -> String {
    ulid::Ulid::from_parts(now_ms.saturating_sub(AUDIT_LOG_RETENTION_MS), 0).to_string()
}

/// Retention for the `server_audit_log` collection.
///
/// Entries are keyed by ULID, so the id is the timestamp and deletion is a
/// pure `_id < cutoff` range delete on the primary index, with the cutoff
/// synthesised from (now - `AUDIT_LOG_RETENTION_DAYS`).
///
/// Multi-replica safety: crond has no leader election or lock, so every
/// replica runs this sweep. No claim is needed. The delete is idempotent: two
/// replicas sweeping the same range at once only repeat each other's work,
/// a document can only be deleted once, and nothing at or above the cutoff
/// is ever touched.
pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    loop {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);

        let cutoff = audit_log_cutoff(now_ms);
        let deleted = db.prune_audit_log_before(&cutoff).await?;

        if deleted > 0 {
            log::info!("Pruned {deleted} audit log entries below {cutoff}");
        }

        // Retention is measured in days; an hourly sweep keeps the overshoot
        // to at most an hour past the window.
        sleep(Duration::from_secs(60 * 60)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    const NOW_MS: u64 = 1_790_000_000_000;
    const DAY_MS: u64 = 24 * 60 * 60 * 1000;

    #[test]
    fn retention_is_45_days_in_ms() {
        assert_eq!(AUDIT_LOG_RETENTION_MS, 45 * DAY_MS);
    }

    #[test]
    fn cutoff_timestamp_is_now_minus_retention_with_zero_randomness() {
        let cutoff = Ulid::from_string(&audit_log_cutoff(NOW_MS)).expect("cutoff is a ULID");
        assert_eq!(cutoff.timestamp_ms(), NOW_MS - 45 * DAY_MS);
        assert_eq!(cutoff.random(), 0);
    }

    #[test]
    fn ids_one_ms_either_side_of_the_cutoff_sort_correctly() {
        let cutoff = audit_log_cutoff(NOW_MS);
        let boundary = NOW_MS - 45 * DAY_MS;

        // Worst case below: the highest possible random part one ms early
        // must still be pruned.
        let older = Ulid::from_parts(boundary - 1, u128::MAX).to_string();
        // Worst case above: the lowest possible random part one ms late must
        // be kept.
        let newer = Ulid::from_parts(boundary + 1, 0).to_string();

        assert!(older < cutoff, "{older} should sort below {cutoff}");
        assert!(newer > cutoff, "{newer} should sort above {cutoff}");

        // A real mint in the cutoff millisecond itself is kept, not pruned.
        let same_ms = Ulid::from_parts(boundary, 1).to_string();
        assert!(same_ms > cutoff);
    }

    #[test]
    fn cutoff_saturates_instead_of_underflowing() {
        let cutoff = Ulid::from_string(&audit_log_cutoff(0)).expect("cutoff is a ULID");
        assert_eq!(cutoff.timestamp_ms(), 0);
    }
}
