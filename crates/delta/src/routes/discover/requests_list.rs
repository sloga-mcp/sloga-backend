use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use super::{to_card, MAX_SKIP, PAGE_SIZE};

/// # List Discovery Requests
///
/// Privileged only: page through servers whose owner requested a public
/// listing that has not been approved yet. Cards include the owner id for
/// vetting. Approve via server edit `discoverable: true`; reject via
/// `discovery_requested: false`.
#[openapi(tag = "Discovery")]
#[get("/requests?<options..>")]
pub async fn requests(
    db: &State<Database>,
    user: User,
    options: v0::OptionsDiscoverRequests,
) -> Result<Json<v0::DiscoverResponse>> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let skip = options.skip.unwrap_or(0).min(MAX_SKIP);
    let servers = db.fetch_discovery_requests(skip, PAGE_SIZE).await?;

    let mut cards = Vec::with_capacity(servers.len());
    for server in servers {
        cards.push(to_card(db, server, true).await?);
    }

    Ok(Json(v0::DiscoverResponse {
        servers: cards,
        total: None,
    }))
}
