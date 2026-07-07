use std::time::{Duration, SystemTime};

use revolt_database::Database;
use revolt_result::Result;
use tokio::time::sleep;
use ulid::Ulid;

/// Queued envelopes for devices that never come back are swept after 30
/// days. Receivers detect the resulting sequence gaps ("messages were
/// lost"), rather than silence.
const ENVELOPE_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    loop {
        let threshold = Ulid::from_datetime(SystemTime::now() - ENVELOPE_TTL).to_string();
        let count = db.delete_e2ee_envelopes_before(&threshold).await?;
        log::info!("Swept {count} expired E2EE envelopes");

        sleep(Duration::from_secs(60 * 60)).await
    }
}
