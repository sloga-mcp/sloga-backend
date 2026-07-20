use std::collections::HashMap;

use revolt_config::config;
use revolt_database::{boost_now_ms, util::reference::Reference, Database, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};

/// # Fetch Boost Inventory
///
/// Fetch a user's boost slots: totals, availability, allocations and full
/// slot detail. `@me` (or your own id) fetches your own inventory; any
/// other target requires a privileged account (this is also the admin's
/// inventory view for the revoke lever).
#[openapi(tag = "Server Boosts")]
#[get("/<target>/boosts")]
pub async fn fetch_user_boosts(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::UserBoosts>> {
    let config = config().await;
    if !config.features.boosts.enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "boosts".to_string()
        }));
    }

    let target_id = if target.id == "@me" {
        user.id.clone()
    } else {
        target.id.to_string()
    };

    if target_id != user.id && !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let now = boost_now_ms();
    let slots = db.fetch_server_boosts_by_user(&target_id).await?;

    let mut total = 0;
    let mut available = 0;
    let mut allocations: HashMap<String, u32> = HashMap::new();
    for slot in &slots {
        if slot.is_expired(now) {
            continue;
        }
        total += 1;
        match &slot.server_id {
            Some(server_id) => *allocations.entry(server_id.clone()).or_default() += 1,
            None => available += 1,
        }
    }

    let mut allocations: Vec<v0::BoostAllocation> = allocations
        .into_iter()
        .map(|(server_id, count)| v0::BoostAllocation { server_id, count })
        .collect();
    allocations.sort_by(|a, b| a.server_id.cmp(&b.server_id));

    Ok(Json(v0::UserBoosts {
        total,
        available,
        allocations,
        slots: slots.into_iter().map(Into::into).collect(),
    }))
}
