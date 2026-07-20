use revolt_config::config;
use revolt_database::{util::reference::Reference, Database, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};

use crate::util::boosts::boost_status;

/// # Fetch Server Boosts
///
/// Fetch a server's boost standing: active count, tier, next-tier target
/// and the boosters list (grouped per user; no slot detail). Members only.
#[openapi(tag = "Server Boosts")]
#[get("/<target>/boosts")]
pub async fn boost_fetch(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::BoostStatus>> {
    let config = config().await;
    if !config.features.boosts.enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "boosts".to_string()
        }));
    }

    let server = target.as_server(db).await?;
    db.fetch_member(&server.id, &user.id).await?;

    Ok(Json(boost_status(db, &server.id, &config).await?))
}
