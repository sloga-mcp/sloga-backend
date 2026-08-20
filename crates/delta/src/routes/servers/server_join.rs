use revolt_database::{util::reference::Reference, Database, Member, User};
use revolt_models::v0::{self, InviteJoinResponse};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Join Discoverable Server
///
/// Join a publicly discoverable server without an invite.
///
/// Returns an identical NotFound for "does not exist" and "not discoverable"
/// so this route cannot be used to probe private server ids. Ban enforcement
/// and the max-servers cap come from `Member::create` / `can_acquire_server`,
/// matching the invite join path exactly.
#[openapi(tag = "Discovery")]
#[post("/<target>/join")]
pub async fn join(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::InviteJoinResponse>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    user.can_acquire_server(db).await?;

    let server = target.as_server(db).await?;
    if !server.discoverable {
        return Err(create_error!(NotFound));
    }

    let (_, channels) = Member::create(db, &server, &user, None).await?;

    Ok(Json(InviteJoinResponse::Server {
        channels: channels.into_iter().map(|c| c.into()).collect(),
        server: server.into(),
    }))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{PartialServer, Server, ServerBan, Session};
    use revolt_models::v0;
    use rocket::http::{Header, Status};

    async fn join(harness: &TestHarness, server_id: &str, session: &Session) -> Status {
        harness
            .client
            .post(format!("/servers/{}/join", server_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await
            .status()
    }

    #[test]
    fn join_gated_on_discoverable_and_bans() {
        crate::util::test::rt().block_on(join_gated_on_discoverable_and_bans_case())
    }

    async fn join_gated_on_discoverable_and_bans_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, joiner_session, joiner) = harness.new_user().await;
        let (_, banned_session, banned_user) = harness.new_user().await;

        let (server, _) = Server::create(
            &harness.db,
            v0::DataCreateServer {
                name: "Joinable".to_string(),
                ..Default::default()
            },
            &owner,
            true,
        )
        .await
        .expect("`Server`");

        // Not discoverable: identical NotFound (no existence probing).
        assert_eq!(
            join(&harness, &server.id, &joiner_session).await,
            Status::NotFound
        );

        harness
            .db
            .update_server(
                &server.id,
                &PartialServer {
                    discoverable: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("approve listing");

        // Banned users are rejected by Member::create.
        ServerBan::create(&harness.db, &server, &banned_user.id, None)
            .await
            .expect("`ServerBan`");
        assert_eq!(
            join(&harness, &server.id, &banned_session).await,
            Status::Forbidden
        );

        // Plain user joins without an invite.
        assert_eq!(
            join(&harness, &server.id, &joiner_session).await,
            Status::Ok
        );
        assert!(harness
            .db
            .fetch_member(&server.id, &joiner.id)
            .await
            .is_ok());

        // Idempotence guard: joining again conflicts instead of duplicating.
        assert_eq!(
            join(&harness, &server.id, &joiner_session).await,
            Status::Conflict
        );
    }

    /// Regression: `can_acquire_server` used `count <= limit`, letting a
    /// user AT the cap join one more (limit+1 servers total).
    #[test]
    fn join_rejected_at_server_cap() {
        crate::util::test::rt().block_on(join_rejected_at_server_cap_case())
    }

    async fn join_rejected_at_server_cap_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, joiner_session, joiner) = harness.new_user().await;

        let limit = joiner.limits().await.servers;

        // Fill the joiner up to the cap (memberships, not ownership —
        // fetch_server_count counts server_members rows).
        for i in 0..limit {
            let (server, _) = Server::create(
                &harness.db,
                v0::DataCreateServer {
                    name: format!("Filler {}", i),
                    ..Default::default()
                },
                &owner,
                false,
            )
            .await
            .expect("`Server`");

            revolt_database::Member::create(&harness.db, &server, &joiner, None)
                .await
                .expect("`Member`");
        }

        // At the cap: acquiring one more must be rejected...
        assert!(joiner.can_acquire_server(&harness.db).await.is_err());

        // ...including through the discover join route.
        let (extra, _) = Server::create(
            &harness.db,
            v0::DataCreateServer {
                name: "One too many".to_string(),
                ..Default::default()
            },
            &owner,
            false,
        )
        .await
        .expect("`Server`");
        harness
            .db
            .update_server(
                &extra.id,
                &PartialServer {
                    discoverable: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("approve listing");

        assert_eq!(
            join(&harness, &extra.id, &joiner_session).await,
            Status::BadRequest
        );
        assert_eq!(
            harness.db.fetch_server_count(&joiner.id).await.unwrap(),
            limit
        );
    }
}
