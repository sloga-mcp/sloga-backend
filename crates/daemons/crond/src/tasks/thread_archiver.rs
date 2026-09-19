use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iso8601_timestamp::Timestamp;
use revolt_database::{Channel, Database, PartialChannel, AMQP};
use revolt_result::Result;
use tokio::time::sleep;
use ulid::Ulid;

/// How often the auto-archive scan runs.
const ARCHIVE_TICK: Duration = Duration::from_secs(60);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Parse a stored ISO-8601 `archived_timestamp` into milliseconds since the
/// Unix epoch. Unparsable or pre-epoch values yield `None`, so the caller falls
/// back to the ULID activity anchor instead of guessing.
fn parse_timestamp_ms(value: &str) -> Option<u64> {
    let ts = Timestamp::parse(value)?;
    u64::try_from(ts.duration_since(Timestamp::UNIX_EPOCH).whole_milliseconds()).ok()
}

/// Whether a thread is due for auto-archive.
///
/// - `minutes == Channel::AUTO_ARCHIVE_NEVER` (0) is never due.
/// - The inactivity window is anchored at the later of the last activity
///   (`activity_ms`) and the last unarchive (`unarchived_ms`), so an unarchive
///   re-opens a full window instead of the thread being re-archived on the
///   next tick.
fn is_due(now_ms: u64, activity_ms: u64, unarchived_ms: Option<u64>, minutes: u32) -> bool {
    if minutes == Channel::AUTO_ARCHIVE_NEVER {
        return false;
    }
    let anchor = activity_ms.max(unarchived_ms.unwrap_or(0));
    now_ms >= anchor.saturating_add((minutes as u64) * 60_000)
}

/// Auto-archive inactive threads.
///
/// Each tick fetches every non-archived thread and archives those whose last
/// activity — the ULID timestamp of the last message, or the thread's own id
/// when it has none — is older than its `auto_archive_minutes`. Reactions and
/// the parent-channel system message do not bump `last_message_id`, so they do
/// not keep a thread alive (matches Discord). The scan is naturally idempotent:
/// it only ever sees non-archived threads, and archiving flips that flag, so a
/// crond re-run can never double-archive.
///
/// Threads set to "Never" (`auto_archive_minutes == Channel::AUTO_ARCHIVE_NEVER`)
/// are skipped here defensively, in addition to being excluded by
/// `fetch_active_threads` at query level.
///
/// Unarchive re-anchors the window: `channel_edit` stamps `archived_timestamp`
/// on both archive and unarchive, so on a non-archived thread it is the last
/// unarchive time. The window runs from the later of that and the last
/// activity; otherwise an idle thread would be re-archived within one tick
/// (<= 60 s) of being unarchived.
///
/// NOTE (v1): this fetches all non-archived threads each tick; if instances grow
/// large this should gain a coarse "last activity older than the shortest
/// auto-archive window" pre-filter in the query.
pub async fn task(db: Database, _amqp: AMQP) -> Result<()> {
    loop {
        let now = now_ms();
        let threads = db.fetch_active_threads().await?;

        let mut archived = 0usize;
        for mut channel in threads {
            let due = if let Channel::Thread {
                id,
                last_message_id,
                auto_archive_minutes,
                archived_timestamp,
                ..
            } = &channel
            {
                let anchor = last_message_id.as_ref().unwrap_or(id);
                let activity_ms = Ulid::from_string(anchor)
                    .map(|ulid| ulid.timestamp_ms())
                    .unwrap_or(now);
                let unarchived_ms = archived_timestamp.as_deref().and_then(parse_timestamp_ms);
                is_due(now, activity_ms, unarchived_ms, *auto_archive_minutes)
            } else {
                false
            };

            if !due {
                continue;
            }

            let partial = PartialChannel {
                archived: Some(true),
                archived_timestamp: Some(Timestamp::now_utc().to_string()),
                ..Default::default()
            };

            // `update` persists the change and publishes ChannelUpdate to the
            // server topic, so live clients (and bonfire) see the archive.
            if let Err(err) = channel.update(&db, partial, vec![]).await {
                revolt_config::capture_error(&err);
            } else {
                archived += 1;
            }
        }

        if archived > 0 {
            log::info!("Auto-archived {archived} inactive thread(s)");
        }

        sleep(ARCHIVE_TICK).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60_000;

    #[test]
    fn never_is_never_due() {
        assert!(!is_due(u64::MAX, 0, None, Channel::AUTO_ARCHIVE_NEVER));
        assert!(!is_due(u64::MAX, 0, Some(0), 0));
    }

    #[test]
    fn ninety_day_boundary() {
        let minutes = 129_600u32;
        let activity = 1_000_000u64;
        let deadline = activity + 129_600 * MIN;
        assert!(!is_due(deadline - 1, activity, None, minutes));
        assert!(is_due(deadline, activity, None, minutes));
    }

    #[test]
    fn sixty_minute_basic() {
        let activity = 5_000_000u64;
        assert!(!is_due(activity + 59 * MIN, activity, None, 60));
        assert!(!is_due(activity + 60 * MIN - 1, activity, None, 60));
        assert!(is_due(activity + 60 * MIN, activity, None, 60));
    }

    #[test]
    fn unarchive_reanchors_window() {
        let activity = 1_000_000u64;
        let unarchived = activity + 10 * 60 * MIN; // 10 h after last activity
        let now = unarchived + 30_000; // 30 s after the unarchive
        // Activity alone is long overdue for a 60-minute window...
        assert!(is_due(now, activity, None, 60));
        // ...but the recent unarchive re-anchors it.
        assert!(!is_due(now, activity, Some(unarchived), 60));
        assert!(!is_due(unarchived + 60 * MIN - 1, activity, Some(unarchived), 60));
        assert!(is_due(unarchived + 60 * MIN, activity, Some(unarchived), 60));
    }

    #[test]
    fn activity_wins_over_older_unarchive() {
        let unarchived = 1_000_000u64;
        let activity = unarchived + 30 * MIN;
        assert!(!is_due(unarchived + 60 * MIN, activity, Some(unarchived), 60));
        assert!(!is_due(activity + 60 * MIN - 1, activity, Some(unarchived), 60));
        assert!(is_due(activity + 60 * MIN, activity, Some(unarchived), 60));
    }

    #[test]
    fn no_overflow_at_extremes() {
        assert!(!is_due(u64::MAX - 1, u64::MAX, None, u32::MAX));
        assert!(is_due(u64::MAX, u64::MAX, None, u32::MAX));
    }

    #[test]
    fn parse_timestamp_ms_valid_and_garbage() {
        assert_eq!(
            parse_timestamp_ms("2024-01-01T00:00:00.000Z"),
            Some(1_704_067_200_000)
        );
        assert_eq!(
            parse_timestamp_ms("2024-01-01T00:00:00.123Z"),
            Some(1_704_067_200_123)
        );
        assert_eq!(parse_timestamp_ms("not a timestamp"), None);
        assert_eq!(parse_timestamp_ms(""), None);
        // Round-trips the exact format the archiver and channel_edit write.
        let now = Timestamp::now_utc();
        let expected = now
            .duration_since(Timestamp::UNIX_EPOCH)
            .whole_milliseconds() as u64;
        assert_eq!(parse_timestamp_ms(&now.to_string()), Some(expected));
    }
}
