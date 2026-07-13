use std::time::{Duration, SystemTime, UNIX_EPOCH};

use revolt_database::{Database, AMQP};
use revolt_result::Result;
use tokio::time::sleep;

/// How often the poll expiry scan runs. Lazy close-on-vote/fetch in the
/// delta routes covers the (up to one tick) gap and daemon downtime, and
/// every close path funnels through `Poll::close`'s atomic flip, so the
/// `PollClose` event fires exactly once regardless of who closes first.
const POLL_TICK: Duration = Duration::from_secs(60);

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Close expired polls and publish their final results.
pub async fn task(db: Database, _amqp: AMQP) -> Result<()> {
    loop {
        let due = db.fetch_expired_open_polls(now_ms()).await?;

        let mut closed = 0usize;
        for poll in due {
            match poll.close(&db).await {
                // This tick won the close and published PollClose.
                Ok(Some(_)) => closed += 1,
                // Lost the race to a lazy close — nothing to do.
                Ok(None) => {}
                Err(err) => {
                    revolt_config::capture_error(&err);
                }
            }
        }

        if closed > 0 {
            log::info!("Closed {closed} expired poll(s)");
        }

        sleep(POLL_TICK).await
    }
}
