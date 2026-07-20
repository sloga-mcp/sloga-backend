use revolt_config::config;
use revolt_database::{boost_now_ms, util::reference::Reference, Database, ServerBoost, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use validator::Validate;

use rocket::{serde::json::Json, State};

use crate::util::boosts::boost_status;

/// # Boost Server
///
/// Apply boosts from your inventory to a server you are a member of.
/// All-or-nothing: if fewer free slots than requested can be claimed
/// (e.g. a concurrent allocation raced), nothing is spent.
#[openapi(tag = "Server Boosts")]
#[put("/<target>/boosts", data = "<data>")]
pub async fn boost_add(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataAllocateBoosts>,
) -> Result<Json<v0::BoostStatus>> {
    let config = config().await;
    if !config.features.boosts.enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "boosts".to_string()
        }));
    }

    // Boost slots are human entitlements
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let server = target.as_server(db).await?;

    // Must be a member to boost (fetch_member's NotFound doubles as the
    // membership error, matching how other member-gated routes behave)
    db.fetch_member(&server.id, &user.id).await?;

    let now = boost_now_ms();

    // Per-user-per-server sanity cap. Check-then-act with bounded overshoot
    // (≤ one racing call's worth) — accepted in the plan.
    let mine_here = db
        .fetch_server_boosts_by_server(&server.id)
        .await?
        .iter()
        .filter(|boost| boost.user_id == user.id && !boost.is_expired(now))
        .count() as u32;
    let max = config.features.boosts.max_per_user_per_server;
    if mine_here + data.count > max {
        return Err(create_error!(TooManyBoosts { max: max as usize }));
    }

    let available = db.count_unallocated_server_boosts(&user.id, now).await?;
    if available < data.count as u64 {
        return Err(create_error!(NotEnoughBoosts {
            available: available as usize
        }));
    }

    let claimed = db
        .allocate_server_boosts(&user.id, &server.id, data.count, now)
        .await?;
    if (claimed.len() as u32) < data.count {
        // A concurrent allocation won some slots between the check and the
        // claim — roll back so no partial spend surprises the user.
        db.deallocate_server_boosts_by_ids(&claimed).await?;
        return Err(create_error!(NotEnoughBoosts {
            available: claimed.len()
        }));
    }

    // Authoritative recount; persists count/tier and fans out ServerUpdate.
    ServerBoost::recount_for_server(db, &server.id).await?;

    Ok(Json(boost_status(db, &server.id, &config).await?))
}
