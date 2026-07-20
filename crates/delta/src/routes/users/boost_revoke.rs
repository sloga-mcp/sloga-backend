use revolt_config::config;
use revolt_database::{util::reference::Reference, Database, ServerBoost, User};
use revolt_result::{create_error, Result};
use rocket_empty::EmptyResponse;

use rocket::State;

/// # Revoke Boost
///
/// Delete a specific boost slot from a user's inventory (found via the
/// privileged inventory fetch). Requires a privileged account. This is
/// the refund/abuse lever; if the slot was allocated, the server is
/// recounted immediately.
#[openapi(tag = "Server Boosts")]
#[delete("/<target>/boosts/<boost_id>")]
pub async fn boost_revoke(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    boost_id: String,
) -> Result<EmptyResponse> {
    let config = config().await;
    if !config.features.boosts.enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "boosts".to_string()
        }));
    }

    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let boost = db.fetch_server_boost(&boost_id).await?;

    // The slot must belong to the addressed user — identical NotFound for
    // "no such slot" and "someone else's slot" so ids can't be probed.
    let target_id = if target.id == "@me" {
        user.id.as_str()
    } else {
        target.id
    };
    if boost.user_id != target_id {
        return Err(create_error!(NotFound));
    }

    log::info!(
        "AUDIT boost_revoke: actor={} target={} boost={} server={:?}",
        user.id,
        boost.user_id,
        boost.id,
        boost.server_id
    );

    db.delete_server_boost(&boost.id).await?;

    // Best-effort — the delete has committed; crond's self-heal sweep
    // reconciles a missed recount (including the zero-slots-left case).
    if let Some(server_id) = &boost.server_id {
        if let Err(error) = ServerBoost::recount_for_server(db, server_id).await {
            log::warn!("boost_revoke: recount failed for {server_id}: {error:?}");
        }
    }

    Ok(EmptyResponse)
}
