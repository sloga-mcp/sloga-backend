use revolt_database::Database;
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use super::{to_card, MAX_SKIP, PAGE_SIZE};

/// Longest accepted search query (bounds regex cost).
const MAX_QUERY_LENGTH: usize = 64;

/// # List Discoverable Servers
///
/// Public, unauthenticated: list servers that opted in to discovery and were
/// approved by a platform admin. Fixed page size, newest first.
#[openapi(tag = "Discovery")]
#[get("/servers?<options..>")]
pub async fn list(
    db: &State<Database>,
    options: v0::OptionsDiscoverServers,
) -> Result<Json<v0::DiscoverResponse>> {
    let query = options
        .query
        .as_deref()
        .map(str::trim)
        .filter(|q| !q.is_empty());

    if query.is_some_and(|q| q.len() > MAX_QUERY_LENGTH) {
        return Err(create_error!(FailedValidation {
            error: "query too long".to_string()
        }));
    }

    let skip = options.skip.unwrap_or(0).min(MAX_SKIP);
    let (servers, total) = db.fetch_discoverable_servers(query, skip, PAGE_SIZE).await?;

    let mut cards = Vec::with_capacity(servers.len());
    for server in servers {
        cards.push(to_card(db, server, false).await?);
    }

    Ok(Json(v0::DiscoverResponse {
        servers: cards,
        total: Some(total),
    }))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{PartialServer, PartialUser, Server};
    use revolt_models::v0;
    use rocket::http::{Header, Status};

    /// Audit BLOCKER 1 regression: on Mongo, false booleans are ABSENT
    /// fields (`skip_serializing_if = if_false`) — naive `{field: false}`
    /// filters return an empty directory and empty admin queue while the
    /// reference driver stays green. Run under `TEST_DB=MONGODB` (WSL) to
    /// exercise the `$ne` filters against real sparse documents.
    #[test]
    fn directory_and_queue_survive_sparse_booleans() {
        crate::util::test::rt().block_on(directory_and_queue_survive_sparse_booleans_case())
    }

    async fn directory_and_queue_survive_sparse_booleans_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, plain_session, _) = harness.new_user().await;
        let (_, admin_session, mut admin) = harness.new_user().await;

        admin
            .update(
                &harness.db,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("privileged admin");

        // Unique name so query-filtered assertions are isolated from other
        // tests sharing the database.
        let unique = TestHarness::rand_string();
        let (server, _) = Server::create(
            &harness.db,
            v0::DataCreateServer {
                name: format!("Disco {}", unique),
                ..Default::default()
            },
            &owner,
            true,
        )
        .await
        .expect("`Server`");

        // Unlisted: public fetch must be an indistinguishable NotFound.
        let response = harness
            .client
            .get(format!("/discover/servers/{}", server.id))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // Owner requests a listing (freshly created server: `discoverable`
        // is an absent field in Mongo — the exact BLOCKER-1 shape).
        harness
            .db
            .update_server(
                &server.id,
                &PartialServer {
                    discovery_requested: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("request listing");

        // Plain users cannot read the admin queue.
        let response = harness
            .client
            .get("/discover/requests")
            .header(Header::new(
                "x-session-token",
                plain_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);

        // Privileged queue sees the pending request WITH the owner id.
        let queue = harness
            .client
            .get("/discover/requests")
            .header(Header::new(
                "x-session-token",
                admin_session.token.to_string(),
            ))
            .dispatch()
            .await
            .into_json::<v0::DiscoverResponse>()
            .await
            .expect("queue json");
        assert!(queue
            .servers
            .iter()
            .any(|s| s.id == server.id && s.owner.as_deref() == Some(owner.id.as_str())));

        // Not listed yet: the public directory must not contain it.
        let listing = harness
            .client
            .get(format!("/discover/servers?query={}", unique))
            .dispatch()
            .await
            .into_json::<v0::DiscoverResponse>()
            .await
            .expect("listing json");
        assert!(listing.servers.is_empty());

        // Admin approves (request consumed).
        harness
            .db
            .update_server(
                &server.id,
                &PartialServer {
                    discoverable: Some(true),
                    discovery_requested: Some(false),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("approve listing");

        // Public directory now lists it — unauthenticated, no owner leak.
        let listing = harness
            .client
            .get(format!("/discover/servers?query={}", unique))
            .dispatch()
            .await
            .into_json::<v0::DiscoverResponse>()
            .await
            .expect("listing json");
        assert_eq!(listing.servers.len(), 1);
        assert_eq!(listing.total, Some(1));
        assert_eq!(listing.servers[0].id, server.id);
        assert!(listing.servers[0].owner.is_none());

        // Single fetch works too, same whitelist.
        let card = harness
            .client
            .get(format!("/discover/servers/{}", server.id))
            .dispatch()
            .await
            .into_json::<v0::DiscoverableServer>()
            .await
            .expect("card json");
        assert_eq!(card.id, server.id);
        assert!(card.owner.is_none());

        // Approved server left the admin queue.
        let queue = harness
            .client
            .get("/discover/requests")
            .header(Header::new(
                "x-session-token",
                admin_session.token.to_string(),
            ))
            .dispatch()
            .await
            .into_json::<v0::DiscoverResponse>()
            .await
            .expect("queue json");
        assert!(!queue.servers.iter().any(|s| s.id == server.id));

        // Non-matching query finds nothing.
        let listing = harness
            .client
            .get(format!("/discover/servers?query={}zzz", unique))
            .dispatch()
            .await
            .into_json::<v0::DiscoverResponse>()
            .await
            .expect("listing json");
        assert!(listing.servers.is_empty());

        // Over-long query is rejected, not truncated.
        let response = harness
            .client
            .get(format!("/discover/servers?query={}", "a".repeat(65)))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
    }
}
