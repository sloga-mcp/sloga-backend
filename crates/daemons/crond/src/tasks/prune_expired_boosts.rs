use std::collections::HashSet;
use std::time::Duration;

use revolt_database::{boost_now_ms, Database, ServerBoost};
use revolt_result::Result;
use tokio::time::sleep;

use log::info;

pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    loop {
        // NOTE: config file sources are frozen at process start — flipping
        // the flag requires restarting crond (documented on BoostFeatures).
        // While disabled, sleep inside the loop: the task wrapper treats a
        // RETURNING task as an error and respawns it every 60s with log
        // spam, so early-return is not a valid no-op.
        if !revolt_config::config().await.features.boosts.enabled {
            sleep(Duration::from_secs(60 * 60)).await;
            continue;
        }

        // 1. Drop expired slots (time-limited grants; later, lapsed
        //    purchases/subscriptions — billing needs no extra expiry logic).
        let removed = db.delete_expired_server_boosts(boost_now_ms()).await?;

        let mut affected: HashSet<String> = removed
            .iter()
            .filter_map(|boost| boost.server_id.clone())
            .collect();

        // 2. Self-heal sweep: recount every server that currently holds any
        //    allocation. recount_for_server skips the write (and the
        //    ServerUpdate fan-out) when nothing changed, so a quiet system
        //    stays quiet; this heals threshold config changes and crashes
        //    between a mutation and its recount.
        for server_id in db.fetch_boosted_server_ids().await? {
            affected.insert(server_id);
        }

        for server_id in &affected {
            ServerBoost::recount_for_server(&db, server_id).await?;
        }

        if !removed.is_empty() {
            info!(
                "Pruned {} expired boost slot(s) across {} server(s)",
                removed.len(),
                affected.len()
            );
        }

        sleep(Duration::from_secs(60 * 60)).await; // run hourly
    }
}
