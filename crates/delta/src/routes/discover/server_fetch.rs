use revolt_database::{util::reference::Reference, Database};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use super::to_card;

/// # Fetch Discoverable Server
///
/// Public, unauthenticated: fetch a single discoverable server's card.
///
/// Returns an identical NotFound for "does not exist" and "not listed" so
/// this route cannot be used to probe private server ids.
#[openapi(tag = "Discovery")]
#[get("/servers/<target>")]
pub async fn fetch(
    db: &State<Database>,
    target: Reference<'_>,
) -> Result<Json<v0::DiscoverableServer>> {
    let server = target.as_server(db).await?;
    if !server.discoverable || server.nsfw {
        return Err(create_error!(NotFound));
    }

    Ok(Json(to_card(db, server, false).await?))
}
