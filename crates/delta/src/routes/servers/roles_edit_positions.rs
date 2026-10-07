use revolt_database::util::audit_reason::AuditLogReason;
use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference}, voice::{sync_server_voice_permissions, VoiceClient}, Database, User
};
use revolt_database::{AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Edits server roles ranks
///
/// Edit's server role's ranks.
#[openapi(tag = "Server Permissions")]
#[patch("/<target>/roles/ranks", data = "<data>")]
pub async fn edit_role_ranks(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataEditRoleRanks>,
    reason: AuditLogReason,
) -> Result<Json<v0::Server>> {
    // Refuse an over-long reason before anything is reordered.
    let reason = reason.validated()?;

    let data = data.into_inner();

    let mut server = target.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageRole)?;

    let existing_order = server
        .ordered_roles()
        .into_iter()
        .map(|(id, _)| id)
        .collect::<Vec<_>>();

    let new_order = data.ranks.clone().into_iter().collect::<Vec<_>>();

    // Verify all roles are in the new ordering
    if data.ranks.len() != server.roles.len()
        || !server.roles.iter().all(|(id, _)| data.ranks.contains(id))
    {
        return Err(create_error!(InvalidOperation));
    }

    // Don't have to check what the user can't modify if they are the server owner
    if server.owner != user.id {
        let member_top_rank = query.get_member_rank();

        if server
            .roles
            .iter()
            // Find all roles above the member which we should not be able to reorder
            .filter(|(_, role)| {
                if let Some(top_rank) = member_top_rank {
                    role.rank <= top_rank
                } else {
                    true
                }
            })
            // Check if user is trying to reorder roles they can't reorder (as found previously)
            .any(|(id, _)| {
                existing_order
                    .iter()
                    .position(|existing_id| id == existing_id)
                    != new_order.iter().position(|new_id| id == new_id)
            })
        {
            return Err(create_error!(NotElevated));
        }
    }

    // The order to log, or None when every role already holds the rank this
    // request gives it (a resubmitted order writes no entry). Read before the
    // write, which changes `server.roles` in place.
    let logged_ranks = if new_order
        .iter()
        .enumerate()
        .any(|(rank, id)| server.roles.get(id).map(|role| role.rank) != Some(rank as i64))
    {
        Some(new_order.clone())
    } else {
        None
    };

    server.set_role_ordering(db, new_order).await?;

    // Logged between the write and the sync: the sync stays the last step.
    if let Some(ranks) = logged_ranks {
        AuditLogEntry::record(
            db,
            AuditLogDraft {
                server: server.id.clone(),
                actor: Some(user.id.clone()),
                action: AuditLogAction::RoleRanksUpdate,
                changes: vec![AuditLogChange::new(
                    "ranks",
                    None,
                    Some(AuditValue::StringList(ranks)),
                )],
                reason,
                ..Default::default()
            },
        )
        .await;
    }

    // Every channel is tried before the first failure is answered (AFK S-3
    // D-6); `server` already carries the new ranks.
    sync_server_voice_permissions(db, voice_client, &server, None).await?;

    Ok(Json(server.into()))
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use revolt_database::util::audit_reason::{
        AUDIT_LOG_REASON_HEADER, AUDIT_LOG_REASON_MAX_CHARS,
    };
    use revolt_database::{
        fixture, AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, PartialServer, Server,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::Value;

    use crate::util::test::TestHarness;

    #[test]
    fn edit_role_rankings() {
        crate::util::test::rt().block_on(edit_role_rankings_case())
    }

    async fn edit_role_rankings_case() {
        let harness = TestHarness::new().await;

        fixture!(harness.db, "server_with_many_roles",
            owner user 0
            moderator user 1
            server server 4);

        // Moderator can re-order the roles below them
        let (_, moderator_session) = harness.account_from_user(moderator.id).await;
        let mut target_order: Vec<String> = server
            .ordered_roles()
            .into_iter()
            .map(|(id, _)| id)
            .collect();

        // Swap the two lower ranked roles
        target_order.swap(2, 3);

        let response = harness
            .client
            .patch(format!("/servers/{}/roles/ranks", server.id))
            .header(ContentType::JSON)
            .body(
                json!(v0::DataEditRoleRanks {
                    ranks: target_order.clone()
                })
                .to_string(),
            )
            .header(Header::new(
                "x-session-token",
                moderator_session.token.to_string(),
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        drop(response);

        // ... but not above them
        let mut target_order: Vec<String> = server
            .ordered_roles()
            .into_iter()
            .map(|(id, _)| id)
            .collect();

        // Swap the two lower ranked roles
        target_order.swap(0, 1);

        let response = harness
            .client
            .patch(format!("/servers/{}/roles/ranks", server.id))
            .header(ContentType::JSON)
            .body(
                json!(v0::DataEditRoleRanks {
                    ranks: target_order.clone()
                })
                .to_string(),
            )
            .header(Header::new(
                "x-session-token",
                moderator_session.token.to_string(),
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Forbidden);
        drop(response);

        // The owner can set any order they want
        let (_, owner_session) = harness.account_from_user(owner.id).await;

        let response = harness
            .client
            .patch(format!("/servers/{}/roles/ranks", server.id))
            .header(ContentType::JSON)
            .body(
                json!(v0::DataEditRoleRanks {
                    ranks: target_order.clone()
                })
                .to_string(),
            )
            .header(Header::new(
                "x-session-token",
                owner_session.token.to_string(),
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        drop(response);
    }

    // ---- the server-wide voice syncs, pinned on their text (AFK S-3 B7) ----
    //
    // One module for the five role and permission routes of the server, so
    // the adoption of `sync_server_voice_permissions` (D-6) is held in one
    // place: four routes call it once, after their write, and `roles_edit`
    // does not sync at all (F-7).

    const ROLES_EDIT: &str = include_str!("roles_edit.rs");
    const ROLES_DELETE: &str = include_str!("roles_delete.rs");
    const ROLES_EDIT_POSITIONS: &str = include_str!("roles_edit_positions.rs");
    const PERMISSIONS_SET: &str = include_str!("permissions_set.rs");
    const PERMISSIONS_SET_DEFAULT: &str = include_str!("permissions_set_default.rs");

    /// `source` up to its test module, if it has one: the code that ships.
    fn shipping(source: &str) -> &str {
        source.find("#[cfg(test)]").map_or(source, |end| &source[..end])
    }

    /// The body of the handler `definition` in `source`'s shipping code,
    /// comment lines dropped and every run of whitespace collapsed to one
    /// space, so a needle does not depend on rustfmt's line breaks.
    fn route_body(file: &str, source: &str, definition: &str) -> String {
        let shipping = shipping(source);
        let at = shipping
            .find(definition)
            .unwrap_or_else(|| panic!("{} no longer defines `{}`", file, definition));
        let open = at + shipping[at..].find('\u{7b}').expect("a body");
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in shipping[open..].char_indices() {
            match ch {
                '\u{7b}' => depth += 1,
                '\u{7d}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        shipping[open..=close.expect("a closed body")]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    const HELPER: &str = "sync_server_voice_permissions(";

    /// The four syncing routes: file, source, handler, the write the sync
    /// follows, and the sync itself with the role argument it passes.
    const SYNCING_ROUTES: [(&str, &str, &str, &str, &str); 4] = [
        (
            "roles_delete.rs",
            ROLES_DELETE,
            "pub async fn delete(",
            "role.delete(db, &server.id).await?;",
            // F-8: None, never the deleted role (MongoDB has already pulled
            // it from every member, so a role-scoped sync matches nobody).
            "sync_server_voice_permissions(db, voice_client, &server, None).await?;",
        ),
        (
            "roles_edit_positions.rs",
            ROLES_EDIT_POSITIONS,
            "pub async fn edit_role_ranks(",
            "server.set_role_ordering(db, new_order).await?;",
            "sync_server_voice_permissions(db, voice_client, &server, None).await?;",
        ),
        (
            "permissions_set.rs",
            PERMISSIONS_SET,
            "pub async fn set_role_permission(",
            "server .set_role_permission(db, &role_id, data.permissions.into()) .await?;",
            "sync_server_voice_permissions(db, voice_client, &server, Some(&role_id)).await?;",
        ),
        (
            "permissions_set_default.rs",
            PERMISSIONS_SET_DEFAULT,
            "pub async fn set_default_server_permissions(",
            "server .update( db, PartialServer \u{7b} default_permissions: Some(data.permissions as i64), \
             ..Default::default() \u{7d}, vec![], ) .await?;",
            "sync_server_voice_permissions(db, voice_client, &server, None).await?;",
        ),
    ];

    /// AFK S-3 D-6 / F-12: each server-wide route syncs through the helper
    /// exactly once, which tries every channel before answering, and no
    /// longer walks `server.channels` itself (a loop that stopped at the
    /// first channel whose fetch or sync failed). Mutation: the old loop
    /// reinstated in one route.
    #[test]
    fn the_server_wide_routes_sync_through_the_helper() {
        for (file, source, _, _, _) in SYNCING_ROUTES {
            let shipping = shipping(source);
            assert_eq!(
                shipping.matches(HELPER).count(),
                1,
                "{} must call `{}` exactly once",
                file,
                HELPER
            );
            for banned in ["for channel_id in &server.channels", "sync_voice_permissions("] {
                assert!(
                    !shipping.contains(banned),
                    "{} must not carry `{}` any more",
                    file,
                    banned
                );
            }
        }
    }

    /// Each route keeps the role argument it passed before D-6, except
    /// `roles_delete`, which passes None (F-8): `roles_edit_positions` and
    /// `permissions_set_default` None, `permissions_set` its role.
    /// Mutations: `roles_delete` passing its role; `permissions_set` passing
    /// None.
    #[test]
    fn the_server_wide_syncs_keep_their_role_argument() {
        for (file, source, handler, _, sync) in SYNCING_ROUTES {
            let body = route_body(file, source, handler);
            assert_eq!(
                body.matches(sync).count(),
                1,
                "{} must sync with `{}`: {}",
                file,
                sync,
                body
            );
        }
    }

    /// The sync reads the POST-update server document, so it runs after the
    /// route's write, and it is the route's last step before the answer.
    /// Mutation: the sync moved above the write in one route.
    #[test]
    fn the_server_wide_syncs_follow_their_write() {
        for (file, source, handler, write, sync) in SYNCING_ROUTES {
            let body = route_body(file, source, handler);
            assert_eq!(
                body.matches(write).count(),
                1,
                "{} must carry its write `{}` exactly once: {}",
                file,
                write,
                body
            );
            let written = body.find(write).expect("counted above");
            let synced = body.find(sync).unwrap_or_else(|| panic!("{} syncs: {}", file, body));
            assert!(
                written < synced,
                "{} must sync after its write: {}",
                file,
                body
            );
            assert!(
                body[synced + sync.len()..].trim_start().starts_with("Ok("),
                "{} must answer right after the sync: {}",
                file,
                body
            );
        }
    }

    /// AFK S-3 F-7: `roles_edit` has no voice sync at all. Its edit cannot
    /// change a grant, and the in-memory server it holds has had the role
    /// removed, so any sync would treat every holder as lacking it.
    /// Mutation: the sync re-added (the file at 5be5288f).
    #[test]
    fn roles_edit_does_not_sync_voice() {
        let body = route_body("roles_edit.rs", ROLES_EDIT, "pub async fn edit(");
        assert!(body.contains("role.update("), "the handler is found: {}", body);

        let shipping = shipping(ROLES_EDIT);
        for banned in [
            "sync_voice_permissions(",
            HELPER,
            "VoiceClient",
            "voice_client",
        ] {
            assert!(
                !shipping.contains(banned),
                "roles_edit.rs must not carry `{}`",
                banned
            );
        }
    }

    // ---- a server-wide sync over a channel with no call (AFK S-3 F-12) ----

    /// `server_with_many_roles` as its owner, with one more id in the
    /// server's channel list that has no document and no call pinned. The
    /// old per-channel loop fetched every channel first and answered
    /// NotFound; the helper reads the node pin first and skips it. Returns
    /// the owner's session token, the server and a role below the owner.
    async fn owner_of_a_server_with_a_dangling_channel(
        harness: &TestHarness,
    ) -> (String, Server, String) {
        fixture!(harness.db, "server_with_many_roles",
            owner user 0
            server server 4);
        let (_, session) = harness.account_from_user(owner.id).await;

        let mut channels = server.channels.clone();
        channels.push(TestHarness::rand_string());
        harness
            .db
            .update_server(
                &server.id,
                &PartialServer {
                    channels: Some(channels),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("the dangling channel id is appended");
        let server = harness.db.fetch_server(&server.id).await.expect("server");
        assert_eq!(server.channels.len(), 2, "one real channel, one dangling id");

        let role_id = server
            .roles
            .iter()
            .find(|(_, role)| role.name == "Lower Rank 1")
            .map(|(id, _)| id.clone())
            .expect("the fixture's lower role");

        (session.token.to_string(), server, role_id)
    }

    #[test]
    fn a_role_delete_skips_a_channel_with_no_call() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (token, server, role_id) =
                owner_of_a_server_with_a_dangling_channel(&harness).await;

            let response = harness
                .client
                .delete(format!("/servers/{}/roles/{}", server.id, role_id))
                .header(Header::new("x-session-token", token))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::NoContent);
            drop(response);

            let server = harness.db.fetch_server(&server.id).await.expect("server");
            assert!(!server.roles.contains_key(&role_id), "the role is deleted");
        })
    }

    #[test]
    fn a_role_edit_answers_with_a_channel_with_no_call() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (token, server, role_id) =
                owner_of_a_server_with_a_dangling_channel(&harness).await;

            let response = harness
                .client
                .patch(format!("/servers/{}/roles/{}", server.id, role_id))
                .header(ContentType::JSON)
                .body(json!({ "name": "Renamed" }).to_string())
                .header(Header::new("x-session-token", token))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
            drop(response);

            let server = harness.db.fetch_server(&server.id).await.expect("server");
            assert_eq!(server.roles[&role_id].name, "Renamed", "the edit landed");
        })
    }

    #[test]
    fn a_rank_edit_skips_a_channel_with_no_call() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (token, server, _) = owner_of_a_server_with_a_dangling_channel(&harness).await;

            let mut ranks: Vec<String> = server
                .ordered_roles()
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            ranks.swap(2, 3);

            let response = harness
                .client
                .patch(format!("/servers/{}/roles/ranks", server.id))
                .header(ContentType::JSON)
                .body(json!(v0::DataEditRoleRanks { ranks: ranks.clone() }).to_string())
                .header(Header::new("x-session-token", token))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
            drop(response);

            let server = harness.db.fetch_server(&server.id).await.expect("server");
            let now: Vec<String> = server
                .ordered_roles()
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            assert_eq!(now, ranks, "the new ranks landed");
        })
    }

    #[test]
    fn a_role_permission_set_skips_a_channel_with_no_call() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (token, server, role_id) =
                owner_of_a_server_with_a_dangling_channel(&harness).await;

            let response = harness
                .client
                .put(format!("/servers/{}/permissions/{}", server.id, role_id))
                .header(ContentType::JSON)
                .body(json!({ "permissions": { "allow": 1, "deny": 0 } }).to_string())
                .header(Header::new("x-session-token", token))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
            drop(response);

            let server = harness.db.fetch_server(&server.id).await.expect("server");
            assert_eq!(server.roles[&role_id].permissions.a, 1, "the permission landed");
        })
    }

    #[test]
    fn a_default_permission_set_skips_a_channel_with_no_call() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (token, server, _) = owner_of_a_server_with_a_dangling_channel(&harness).await;
            assert_ne!(server.default_permissions, 0, "the fixture starts nonzero");

            let response = harness
                .client
                .put(format!("/servers/{}/permissions/default", server.id))
                .header(ContentType::JSON)
                .body(json!({ "permissions": 0 }).to_string())
                .header(Header::new("x-session-token", token))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
            drop(response);

            let server = harness.db.fetch_server(&server.id).await.expect("server");
            assert_eq!(server.default_permissions, 0, "the default landed");
        })
    }

    // ---- the audit entry of a rank edit (moderation slice 1) ----

    /// PATCH the ranks; returns the status and the raw JSON body (Null when
    /// the body is not JSON).
    async fn edit_ranks(
        harness: &TestHarness,
        token: &str,
        server_id: &str,
        ranks: &[String],
        reason: Option<&str>,
    ) -> (Status, Value) {
        let mut request = harness
            .client
            .patch(format!("/servers/{}/roles/ranks", server_id))
            .header(ContentType::JSON)
            .body(
                json!(v0::DataEditRoleRanks {
                    ranks: ranks.to_vec()
                })
                .to_string(),
            )
            .header(Header::new("x-session-token", token.to_string()));
        if let Some(reason) = reason {
            request = request.header(Header::new(AUDIT_LOG_REASON_HEADER, reason.to_string()));
        }
        let response = request.dispatch().await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        (status, serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    async fn audit_log(harness: &TestHarness, server_id: &str) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(server_id, None, 50, None, None)
            .await
            .expect("fetch audit log")
    }

    /// Every role's stored rank, by role id.
    async fn stored_ranks(harness: &TestHarness, server_id: &str) -> HashMap<String, i64> {
        let server = harness.db.fetch_server(server_id).await.expect("server");
        server
            .roles
            .iter()
            .map(|(id, role)| (id.clone(), role.rank))
            .collect()
    }

    fn ordered_ids(server: &Server) -> Vec<String> {
        server
            .ordered_roles()
            .into_iter()
            .map(|(id, _)| id)
            .collect()
    }

    /// A moderator reorders the roles below them with a percent-encoded
    /// reason: the new order is stored and exactly one `role_ranks_update`
    /// entry is written, actor = the moderator, no target, no channel, no
    /// count, `ranks` = the new order, the reason decoded.
    #[test]
    fn a_rank_edit_writes_one_role_ranks_update_entry() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            fixture!(harness.db, "server_with_many_roles",
                moderator user 1
                server server 4);
            let (_, session) = harness.account_from_user(moderator.id.clone()).await;

            let mut ranks = ordered_ids(&server);
            ranks.swap(2, 3);
            let (status, body) = edit_ranks(
                &harness,
                &session.token,
                &server.id,
                &ranks,
                Some("tidy%20up%3A%20lower%20roles"),
            )
            .await;
            assert_eq!(status, Status::Ok, "body: {}", body);

            let after = harness.db.fetch_server(&server.id).await.expect("server");
            assert_eq!(ordered_ids(&after), ranks, "the new order is stored");

            let entries = audit_log(&harness, &server.id).await;
            assert_eq!(entries.len(), 1, "{:?}", entries);
            let entry = &entries[0];
            assert_eq!(entry.server, server.id);
            assert_eq!(entry.action, AuditLogAction::RoleRanksUpdate);
            assert_eq!(entry.actor.as_deref(), Some(moderator.id.as_str()));
            assert_eq!(entry.target, None);
            assert_eq!(entry.channel, None);
            assert_eq!(entry.count, None);
            assert_eq!(
                entry.changes,
                vec![AuditLogChange::new(
                    "ranks",
                    None,
                    Some(AuditValue::StringList(ranks.clone()))
                )]
            );
            assert_eq!(entry.reason.as_deref(), Some("tidy up: lower roles"));
        })
    }

    /// Resubmitting the order every role already holds succeeds and writes no
    /// entry. The fixture's two lower roles share a rank, so the first edit
    /// (which settles the tie) is a change and is logged; the same order sent
    /// again is not. Mutation: the `logged_ranks` check dropped.
    #[test]
    fn resubmitting_the_stored_order_logs_nothing() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            fixture!(harness.db, "server_with_many_roles",
                owner user 0
                server server 4);
            let (_, session) = harness.account_from_user(owner.id.clone()).await;

            let ranks = ordered_ids(&server);
            let (status, body) =
                edit_ranks(&harness, &session.token, &server.id, &ranks, None).await;
            assert_eq!(status, Status::Ok, "body: {}", body);
            let entries = audit_log(&harness, &server.id).await;
            assert_eq!(
                entries.len(),
                1,
                "settling the tie is logged: {:?}",
                entries
            );

            let before = stored_ranks(&harness, &server.id).await;
            let (status, body) = edit_ranks(
                &harness,
                &session.token,
                &server.id,
                &ranks,
                Some("no%20change"),
            )
            .await;
            assert_eq!(status, Status::Ok, "body: {}", body);
            assert_eq!(stored_ranks(&harness, &server.id).await, before);

            let entries = audit_log(&harness, &server.id).await;
            assert_eq!(
                entries.len(),
                1,
                "the same order is not logged: {:?}",
                entries
            );
            assert_eq!(
                entries[0].reason, None,
                "the logged entry is the first edit"
            );
        })
    }

    /// Refused rank edits write nothing and change nothing: a moderator
    /// reordering roles above them (NotElevated), and an order that leaves a
    /// role out (InvalidOperation).
    #[test]
    fn a_refused_rank_edit_logs_nothing() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            fixture!(harness.db, "server_with_many_roles",
                moderator user 1
                server server 4);
            let (_, session) = harness.account_from_user(moderator.id.clone()).await;
            let before = stored_ranks(&harness, &server.id).await;

            let mut above = ordered_ids(&server);
            above.swap(0, 1);
            let (status, body) = edit_ranks(
                &harness,
                &session.token,
                &server.id,
                &above,
                Some("not%20allowed"),
            )
            .await;
            assert_eq!(status, Status::Forbidden, "body: {}", body);
            assert_eq!(body["type"], "NotElevated", "body: {}", body);

            let mut missing = ordered_ids(&server);
            missing.pop();
            let (status, body) = edit_ranks(
                &harness,
                &session.token,
                &server.id,
                &missing,
                Some("not%20allowed"),
            )
            .await;
            assert_eq!(status, Status::BadRequest, "body: {}", body);
            assert_eq!(body["type"], "InvalidOperation", "body: {}", body);

            assert_eq!(stored_ranks(&harness, &server.id).await, before);
            let entries = audit_log(&harness, &server.id).await;
            assert!(entries.is_empty(), "{:?}", entries);
        })
    }

    /// A reason one char over the limit is refused with
    /// FailedValidation/AuditLogReasonTooLong BEFORE the write: the stored
    /// ranks are unchanged and nothing is logged. Mutation: the
    /// `validated()?` moved below the write.
    #[test]
    fn an_overlong_reason_is_refused_and_the_order_stands() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            fixture!(harness.db, "server_with_many_roles",
                owner user 0
                server server 4);
            let (_, session) = harness.account_from_user(owner.id.clone()).await;
            let before = stored_ranks(&harness, &server.id).await;

            let mut ranks = ordered_ids(&server);
            ranks.swap(2, 3);
            let reason = "a".repeat(AUDIT_LOG_REASON_MAX_CHARS + 1);
            let (status, body) =
                edit_ranks(&harness, &session.token, &server.id, &ranks, Some(&reason)).await;
            assert_eq!(status, Status::BadRequest, "body: {}", body);
            assert_eq!(body["type"], "FailedValidation", "body: {}", body);
            assert_eq!(body["error"], "AuditLogReasonTooLong", "body: {}", body);

            assert_eq!(stored_ranks(&harness, &server.id).await, before);
            let entries = audit_log(&harness, &server.id).await;
            assert!(entries.is_empty(), "{:?}", entries);
        })
    }
}
