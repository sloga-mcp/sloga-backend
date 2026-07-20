use revolt_config::config;
use revolt_database::{util::reference::Reference, Database, ServerBoost, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};

/// # Remove Server Boosts
///
/// Return up to `count` (default 1) of YOUR boosts on this server to your
/// inventory. Deliberately does not require membership or even a live
/// server: users must always be able to reclaim their slots, including
/// after leaving (normally automatic) or if a historical cascade was
/// missed. Tier drops immediately; over-cap emoji/sounds are never
/// deleted, they only block new creates.
#[openapi(tag = "Server Boosts")]
#[delete("/<target>/boosts?<count>")]
pub async fn boost_remove(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    count: Option<u32>,
) -> Result<Json<v0::BoostRemoved>> {
    let config = config().await;
    if !config.features.boosts.enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "boosts".to_string()
        }));
    }

    let count = count
        .unwrap_or(1)
        .clamp(1, config.features.boosts.max_per_user_per_server.max(1));

    // The op's query is keyed on (caller, server) — it can only ever touch
    // the caller's own slots.
    let removed = db
        .deallocate_server_boosts(&user.id, target.id, Some(count))
        .await?;

    if removed == 0 {
        return Err(create_error!(NoEffect));
    }

    // Best-effort: the deallocation above has already committed, so a
    // transient recount failure must not surface as a 500 (the caller's
    // retry would then hit NoEffect). The crond self-heal sweep — which
    // also covers servers left with a stale count and ZERO slots —
    // reconciles anything missed here. NotFound (deleted server) no-ops.
    if let Err(error) = ServerBoost::recount_for_server(db, target.id).await {
        log::warn!("boost_remove: recount failed for {}: {error:?}", target.id);
    }

    Ok(Json(v0::BoostRemoved {
        removed: removed as u32,
    }))
}
