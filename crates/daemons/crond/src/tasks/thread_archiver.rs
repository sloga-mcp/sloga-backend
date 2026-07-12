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
                ..
            } = &channel
            {
                let anchor = last_message_id.as_ref().unwrap_or(id);
                let last_ms = Ulid::from_string(anchor)
                    .map(|ulid| ulid.timestamp_ms())
                    .unwrap_or(now);
                now >= last_ms + (*auto_archive_minutes as u64) * 60_000
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
