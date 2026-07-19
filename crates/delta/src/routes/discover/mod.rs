use revolt_database::{Database, Server};
use revolt_models::v0;
use revolt_result::Result;
use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod apps_list;
mod requests_list;
mod server_fetch;
mod servers_list;

/// Fixed page size for all discovery listings — never client-supplied.
pub const PAGE_SIZE: i64 = 20;
/// Upper bound on pagination depth (bounds scrape cost).
pub const MAX_SKIP: u64 = 1000;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        servers_list::list,
        server_fetch::fetch,
        requests_list::requests,
        apps_list::apps
    ]
}

/// Build the public discovery card for a server.
///
/// Strict whitelist: icon/banner go through `PublicFile` (drops uploader
/// user_id), and `owner` is populated ONLY for the privileged requests route.
pub async fn to_card(
    db: &Database,
    server: Server,
    include_owner: bool,
) -> Result<v0::DiscoverableServer> {
    let member_count = db.fetch_member_count(&server.id).await? as i64;
    let server: v0::Server = server.into();

    Ok(v0::DiscoverableServer {
        id: server.id,
        name: server.name,
        description: server.description,
        icon: server.icon.map(Into::into),
        banner: server.banner.map(Into::into),
        flags: server.flags,
        member_count,
        owner: if include_owner {
            Some(server.owner)
        } else {
            None
        },
    })
}
