use std::collections::HashMap;

use revolt_config::Settings;
use revolt_database::{boost_now_ms, Database};
use revolt_models::v0;
use revolt_result::Result;

/// Build the member-facing boost standing for a server: active count,
/// tier, next-tier target, and boosters grouped per user. Deliberately
/// never exposes slot ids, sources or expiry (only the owner/admin
/// inventory route shows those).
pub async fn boost_status(
    db: &Database,
    server_id: &str,
    config: &Settings,
) -> Result<v0::BoostStatus> {
    let now = boost_now_ms();

    let mut per_user: HashMap<String, (u32, i64)> = HashMap::new();
    for boost in db.fetch_server_boosts_by_server(server_id).await? {
        if boost.is_expired(now) {
            continue;
        }

        let since = boost.allocated_at.unwrap_or(now);
        let entry = per_user.entry(boost.user_id).or_insert((0, since));
        entry.0 += 1;
        entry.1 = entry.1.min(since);
    }

    let count: u32 = per_user.values().map(|(boosts, _)| boosts).sum();
    let tier = config.features.boosts.tier_for(count);

    let mut boosters: Vec<v0::BoosterEntry> = per_user
        .into_iter()
        .map(|(user_id, (boosts, since))| v0::BoosterEntry {
            user_id,
            boosts,
            since,
        })
        .collect();
    // Earliest boosters first, id as tiebreak — stable output for clients.
    boosters.sort_by(|a, b| a.since.cmp(&b.since).then(a.user_id.cmp(&b.user_id)));

    Ok(v0::BoostStatus {
        count,
        tier,
        next_tier_at: config.features.boosts.next_tier_at(tier),
        boosters,
    })
}
