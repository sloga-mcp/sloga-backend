use revolt_config::config;
use revolt_database::{boost_now_ms, util::reference::Reference, Database, ServerBoost, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use validator::Validate;

use rocket::{serde::json::Json, State};

/// # Grant Boosts
///
/// Mint boost slots for a user's inventory. Requires a privileged account.
/// This is the only mint path until billing exists, and remains the
/// support/compensation lever afterwards.
#[openapi(tag = "Server Boosts")]
#[post("/<target>/boosts", data = "<data>")]
pub async fn boost_grant(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataGrantBoosts>,
) -> Result<Json<Vec<v0::ServerBoost>>> {
    let config = config().await;
    if !config.features.boosts.enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "boosts".to_string()
        }));
    }

    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let target_user = target.as_user(db).await?;
    if target_user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // Expiry is server-computed — a client can never smuggle in an
    // arbitrary timestamp.
    let expires_at = data
        .expires_in_days
        .map(|days| boost_now_ms() + i64::from(days) * 86_400_000);

    log::info!(
        "AUDIT boost_grant: actor={} target={} count={} expires_at={:?}",
        user.id,
        target_user.id,
        data.count,
        expires_at
    );

    let minted = ServerBoost::create_granted(db, &target_user.id, data.count, expires_at).await?;
    Ok(Json(minted.into_iter().map(Into::into).collect()))
}
