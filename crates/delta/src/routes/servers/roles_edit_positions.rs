use revolt_database::util::audit_reason::AuditLogReason;
use revolt_database::util::protected_access::reconcile_server;
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

    // Logged between the write and the sync: the sync stays the last step
    // but for the kept reconcile result.
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

    // Protected channels 6.3 "Hooks" (S2-D11): a new order can flip which of
    // two roles' allow and deny of ViewChannel wins, so the seats it took
    // ViewChannel from are released, in every protected channel of the
    // server. Run on every write, a resubmitted order included, so retrying
    // the same edit repairs a pass that failed. The result is kept until the
    // sync has run and a failure is logged at once, so a failing sync never
    // hides it.
    let reconciled = reconcile_server(db, &server.id).await;
    if let Err(error) = &reconciled {
        log::error!(
            "protected channel reconcile failed after a role rank edit: server={}: {:?}",
            server.id,
            error
        );
    }

    // Every channel is tried before the first failure is answered (AFK S-3
    // D-6); `server` already carries the new ranks.
    sync_server_voice_permissions(db, voice_client, &server, None).await?;

    // The reconcile's own error is answered once the sync has run; the new
    // order stands.
    reconciled?;

    Ok(Json(server.into()))
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use revolt_database::util::audit_reason::{
        AUDIT_LOG_REASON_HEADER, AUDIT_LOG_REASON_MAX_CHARS,
    };
    use revolt_database::{
        fixture, AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, PartialServer, Role,
        Server,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::Value;

    use super::protected_hook::{end_call, hook_world, plain_world, HookWorld};
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
    /// route's write, and it is the route's last step before the answer:
    /// only the kept reconcile result of protected channels 6.3 "Hooks"
    /// (S2-D11) is handed back after it. Before S2 the answer followed the
    /// sync directly; this pin was changed for that hook. Mutations: the
    /// sync moved above the write in one route; the kept result answered
    /// above the sync in one route.
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
            let after = body[synced + sync.len()..].trim_start();
            assert!(
                after.starts_with(KEPT) && after[KEPT.len()..].trim_start().starts_with("Ok("),
                "{} must answer right after the sync and its kept reconcile result: {}",
                file,
                body
            );
        }
    }

    /// The reconcile result the four routes keep across the sync.
    const RECONCILE: &str = "let reconciled = reconcile_server(db, &server.id).await;";
    const KEPT: &str = "reconciled?;";

    /// Protected channels 6.3 "Hooks" (S2-D11): each of the four routes
    /// reconciles the server once, after its write and its audit entry and
    /// before its voice sync, at the top level of its body (so on every
    /// request that wrote, a no-change one included: a retry repairs a
    /// failed pass), and gates it on no feature flag (removal always works).
    /// Mutations: the reconcile run only on a change; the reconcile nested
    /// in a block; the reconcile moved below the sync.
    #[test]
    fn the_server_wide_routes_reconcile_between_their_entry_and_their_sync() {
        for (file, source, handler, write, sync) in SYNCING_ROUTES {
            let body = route_body(file, source, handler);
            for needle in [RECONCILE, "reconcile_server(", KEPT] {
                assert_eq!(
                    body.matches(needle).count(),
                    1,
                    "{} must carry `{}` exactly once: {}",
                    file,
                    needle,
                    body
                );
            }
            let at = |needle: &str| {
                body.find(needle)
                    .unwrap_or_else(|| panic!("{} lacks `{}`: {}", file, needle, body))
            };
            let reconciled = at(RECONCILE);
            assert!(
                at(write) < reconciled && at("AuditLogEntry::record(") < reconciled,
                "{} must reconcile after its write and its entry: {}",
                file,
                body
            );
            assert!(
                reconciled < at(sync),
                "{} must reconcile before its sync: {}",
                file,
                body
            );
            let before = &body[..reconciled];
            assert_eq!(
                before.matches('\u{7b}').count(),
                before.matches('\u{7d}').count() + 1,
                "{} must reconcile at the top level of its body: {}",
                file,
                body
            );
            for flag in ["config(", "protected_channels"] {
                assert!(
                    !body.contains(flag),
                    "{} must not gate the hook on `{}`: {}",
                    file,
                    flag,
                    body
                );
            }
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

    // ---- protected channels: the reconciler hook (6.3 "Hooks", S2-D11) ----
    //
    // The member holds two roles: `sight` allows ViewChannel and `blind`
    // denies it. Roles apply from the lowest-ranked up, so whichever ranks
    // higher wins: `sight` starts above `blind`, and a new order that puts
    // `blind` on top takes ViewChannel away.

    const VIEW: i64 = ChannelPermission::ViewChannel as i64;

    /// The member's two conflicting roles, `sight` on top, written straight
    /// to the store (no hook runs). Returns them.
    async fn conflicting_roles(world: &HookWorld) -> (Role, Role) {
        let sight = world.role(1, OverrideField { a: VIEW, d: 0 }).await;
        let blind = world.role(2, OverrideField { a: 0, d: VIEW }).await;
        world.set_roles(&world.member.id, &[&sight, &blind]).await;
        (sight, blind)
    }

    /// The stored order with `sight` and `blind` swapped, `blind` on top.
    async fn blind_on_top(world: &HookWorld, sight: &Role, blind: &Role) -> Vec<String> {
        let mut ranks = ordered_ids(&world.server().await);
        let position = |id: &str| {
            ranks
                .iter()
                .position(|ranked| ranked == id)
                .expect("a ranked role")
        };
        let (above, below) = (position(sight.id.as_str()), position(blind.id.as_str()));
        assert!(above < below, "precondition: sight ranks above blind");
        ranks.swap(above, below);
        ranks
    }

    /// How many `role_ranks_update` entries the server has.
    async fn rank_entries(world: &HookWorld) -> usize {
        audit_log(&world.harness, &world.server_id)
            .await
            .into_iter()
            .filter(|entry| entry.action == AuditLogAction::RoleRanksUpdate)
            .count()
    }

    #[test]
    fn ranking_a_denying_role_on_top_releases_its_holders_seat() {
        crate::util::test::rt().block_on(async {
            let mut world = hook_world().await;
            let (sight, blind) = conflicting_roles(&world).await;
            assert!(!world.member_lacks_access().await, "precondition: M views");
            let ranks = blind_on_top(&world, &sight, &blind).await;
            let call = world.unreachable_call().await;

            // The owner puts `blind` on top: the hook releases M's seat
            // (`AccessLost`, one entry, the seats event) and the owner, the
            // list signer, keeps theirs. The unreachable call answers its
            // `UnknownNode`, and the seat is released all the same: the
            // reconcile runs BEFORE the sync. Controls: the hook removed; the
            // reconcile moved below the sync.
            let (status, body) = edit_ranks(
                &world.harness,
                &world.owner_session.token,
                &world.server_id,
                &ranks,
                None,
            )
            .await;
            end_call(&call).await;
            assert_eq!(status, Status::BadRequest, "body: {}", body);
            assert_eq!(body["type"], "UnknownNode", "body: {}", body);
            assert_eq!(
                ordered_ids(&world.server().await),
                ranks,
                "the order stands"
            );
            assert!(world.member_lacks_access().await, "M lost ViewChannel");
            world.assert_member_released().await;
        })
    }

    /// The reconcile fails (the protected channel's row is not a server
    /// channel): the new order stands and is logged, the voice sync still
    /// runs (with a call it cannot reach, its own `UnknownNode` is the
    /// answer), and without such a call the reconcile's own error is the
    /// answer (`InternalError`). Resubmitting the same order, which logs
    /// nothing, releases the seat once the row is back.
    /// Controls: the reconcile's error returned before the sync; its error
    /// dropped; the hook run only on a change.
    #[test]
    fn a_failed_reconcile_still_syncs_then_answers_its_error_after_the_write() {
        crate::util::test::rt().block_on(async {
            let mut world = hook_world().await;
            let (sight, blind) = conflicting_roles(&world).await;
            let ranks = blind_on_top(&world, &sight, &blind).await;
            let parked = world.break_reconcile().await;

            // The sync ran after the failed reconcile: its error answers first
            let call = world.unreachable_call().await;
            let (status, body) = edit_ranks(
                &world.harness,
                &world.owner_session.token,
                &world.server_id,
                &ranks,
                Some("hook"),
            )
            .await;
            end_call(&call).await;
            assert_eq!(status, Status::BadRequest, "body: {}", body);
            assert_eq!(body["type"], "UnknownNode", "body: {}", body);
            assert_eq!(
                ordered_ids(&world.server().await),
                ranks,
                "the order stands"
            );
            assert_eq!(rank_entries(&world).await, 1);

            // No call: the kept failure is answered, the write is not undone
            let (status, body) = edit_ranks(
                &world.harness,
                &world.owner_session.token,
                &world.server_id,
                &ranks,
                None,
            )
            .await;
            assert_eq!(status, Status::InternalServerError, "body: {}", body);
            assert_eq!(body["type"], "InternalError", "body: {}", body);
            assert_eq!(
                ordered_ids(&world.server().await),
                ranks,
                "the order stands"
            );
            assert!(
                world.seat(&world.member.id).await.is_active(),
                "a failed reconcile released nothing"
            );
            assert!(world.releases().await.is_empty());

            // Repaired: the same order releases the seat
            world.repair(&parked).await;
            let (status, body) = edit_ranks(
                &world.harness,
                &world.owner_session.token,
                &world.server_id,
                &ranks,
                None,
            )
            .await;
            assert_eq!(status, Status::Ok, "body: {}", body);
            assert_eq!(
                rank_entries(&world).await,
                1,
                "the resubmitted orders are not logged"
            );
            world.assert_member_released().await;
        })
    }

    /// No protected channel in the server: the same rank edit answers as
    /// before S2, with no seat entry and no seats event.
    #[test]
    fn without_a_protected_channel_the_hook_changes_nothing() {
        crate::util::test::rt().block_on(async {
            let mut world = plain_world().await;
            let (sight, blind) = conflicting_roles(&world).await;
            let ranks = blind_on_top(&world, &sight, &blind).await;

            let (status, body) = edit_ranks(
                &world.harness,
                &world.owner_session.token,
                &world.server_id,
                &ranks,
                None,
            )
            .await;
            assert_eq!(status, Status::Ok, "body: {}", body);
            assert_eq!(
                ordered_ids(&world.server().await),
                ranks,
                "the order stands"
            );
            assert_eq!(rank_entries(&world).await, 1);
            assert!(world.releases().await.is_empty());
            world.assert_no_seats_event().await;
        })
    }
}

/// Protected channels 6.3 "Hooks" (S2-D11): the world and the observables
/// the hook tests of the four server-wide role and permission routes share
/// (`roles_delete`, `roles_edit_positions`, `permissions_set`,
/// `permissions_set_default`). Needs RabbitMQ and Redis, like every route
/// test.
#[cfg(test)]
pub(crate) mod protected_hook {
    use revolt_database::{
        events::client::EventV1,
        util::protected_access::seat_holder_lacks_access,
        voice::{delete_channel_node, set_channel_node},
        AuditLogAction, Channel, ChannelSeat, Database, PartialMember, PartialRole, PartialServer,
        Role, SeatReleaseCause, Server, Session, User, PROTECTED_SCOPE_SEATS,
    };
    use revolt_models::v0;
    use revolt_permissions::OverrideField;
    use ulid::Ulid;

    use crate::util::test::TestHarness;

    /// A node name absent from `Revolt.toml`: a voice sync addressed to it
    /// fails with `UnknownNode` before any network.
    const ABSENT_NODE: &str = "test-node-with-no-sfu";

    /// A server owned by `owner`, with `member` joined. In a [`hook_world`]
    /// `channel` is protected, both are seated, `owner` signed the list, and
    /// the member's seat has received the keys (so its release is
    /// `AccessLost` with the cooldown). In a [`plain_world`] nothing is
    /// protected and `channel` is the server's first channel.
    pub(crate) struct HookWorld {
        pub(crate) harness: TestHarness,
        pub(crate) owner: User,
        pub(crate) owner_session: Session,
        pub(crate) member: User,
        pub(crate) server_id: String,
        pub(crate) channel_id: String,
        /// `channel_id`'s document as the world was built (it never changes
        /// here), kept for the access check while it is broken away
        channel: Channel,
    }

    pub(crate) async fn hook_world() -> HookWorld {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let channel = protected.channel;
        harness.mark_keys_received(channel.id(), &member.id).await;

        HookWorld {
            harness,
            owner,
            owner_session,
            member,
            server_id: protected.server.id,
            channel_id: channel.id().to_string(),
            channel,
        }
    }

    pub(crate) async fn plain_world() -> HookWorld {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, member) = harness.new_user().await;
        let (server, channels) = harness.new_server(&owner).await;
        harness.join_server(&server, &owner).await;
        harness.join_server(&server, &member).await;
        let channel = channels
            .into_iter()
            .next()
            .expect("the server's first channel");

        HookWorld {
            harness,
            owner,
            owner_session,
            member,
            server_id: server.id,
            channel_id: channel.id().to_string(),
            channel,
        }
    }

    /// End the call [`HookWorld::unreachable_call`] pinned
    pub(crate) async fn end_call(call: &Channel) {
        delete_channel_node(call.id()).await.expect("node gone");
    }

    impl HookWorld {
        pub(crate) async fn server(&self) -> Server {
            self.harness
                .db
                .fetch_server(&self.server_id)
                .await
                .expect("server")
        }

        /// A role at `rank` with `permissions`; the rank is set after the
        /// creation, which derives one from the server it is given
        pub(crate) async fn role(&self, rank: i64, permissions: OverrideField) -> Role {
            let server = self.server().await;
            let mut role = self
                .harness
                .new_role(&server, rank, Some(permissions))
                .await;
            role.update(
                &self.harness.db,
                &server.id,
                PartialRole {
                    rank: Some(rank),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("role rank");
            role
        }

        /// `user_id`'s roles become `roles`, written straight to the store
        pub(crate) async fn set_roles(&self, user_id: &str, roles: &[&Role]) {
            let mut member = self
                .harness
                .db
                .fetch_member(&self.server_id, user_id)
                .await
                .expect("member");
            member
                .update(
                    &self.harness.db,
                    PartialMember {
                        roles: Some(roles.iter().map(|role| role.id.clone()).collect()),
                        ..Default::default()
                    },
                    Vec::new(),
                )
                .await
                .expect("member roles");
        }

        /// The @everyone default becomes `permissions`, written straight to
        /// the store
        pub(crate) async fn set_default_permissions(&self, permissions: i64) {
            self.harness
                .db
                .update_server(
                    &self.server_id,
                    &PartialServer {
                        default_permissions: Some(permissions),
                        ..Default::default()
                    },
                    vec![],
                )
                .await
                .expect("the default");
        }

        /// The reconciler's own predicate for the member, on fresh reads of
        /// the user, the membership and the server
        pub(crate) async fn member_lacks_access(&self) -> bool {
            let db = &self.harness.db;
            let user = db.fetch_user(&self.member.id).await.expect("user");
            let member = db
                .fetch_member(&self.server_id, &self.member.id)
                .await
                .expect("member");
            let server = self.server().await;
            seat_holder_lacks_access(db, Some(&user), Some(&member), &self.channel, &server).await
        }

        pub(crate) async fn seat(&self, user_id: &str) -> ChannelSeat {
            self.harness
                .db
                .fetch_channel_seats(&self.channel_id)
                .await
                .expect("seats")
                .into_iter()
                .find(|seat| seat.user_id == user_id)
                .expect("a seat row")
        }

        /// `(target, channel)` of every `ProtectedSeatRelease` entry, sorted
        pub(crate) async fn releases(&self) -> Vec<(String, String)> {
            let mut releases: Vec<(String, String)> = self
                .harness
                .db
                .fetch_audit_log(
                    &self.server_id,
                    None,
                    50,
                    Some(AuditLogAction::ProtectedSeatRelease),
                    None,
                )
                .await
                .expect("the audit log")
                .into_iter()
                .map(|entry| {
                    (
                        entry.target.unwrap_or_default(),
                        entry.channel.unwrap_or_default(),
                    )
                })
                .collect();
            releases.sort();
            releases
        }

        /// The reconciler released the member's seat, as `AccessLost`, with
        /// one `ProtectedSeatRelease` entry and the seats event on the
        /// channel topic, and the owner, the list signer, kept theirs
        pub(crate) async fn assert_member_released(&mut self) {
            let seat = self.seat(&self.member.id).await;
            assert!(
                !seat.is_active(),
                "the member's seat is released: {:?}",
                seat
            );
            assert_eq!(seat.release_cause, Some(SeatReleaseCause::AccessLost));
            let owner = self.seat(&self.owner.id).await;
            assert!(
                owner.is_active(),
                "the list signer keeps the seat: {:?}",
                owner
            );
            assert_eq!(
                self.releases().await,
                vec![(self.member.id.clone(), self.channel_id.clone())]
            );

            let channel_id = self.channel_id.clone();
            self.harness
                .wait_for_event(&channel_id, |event| {
                    matches!(event, EventV1::ProtectedChannelChanged { id, scope }
                        if id == &channel_id && *scope == vec![PROTECTED_SCOPE_SEATS.to_string()])
                })
                .await;
        }

        /// No `ProtectedChannelChanged` went out on any channel of the
        /// server. A marker on the owner's private topic is published and
        /// awaited first: the harness reads every topic through ONE
        /// subscription, FIFO, and the route awaited its publishes before it
        /// answered, so anything it published is buffered by then.
        pub(crate) async fn assert_no_seats_event(&mut self) {
            let marker = Ulid::new().to_string();
            EventV1::ChannelAck {
                id: marker.clone(),
                user: self.owner.id.clone(),
                message_id: marker.clone(),
            }
            .private(self.owner.id.clone())
            .await;
            self.harness
                .wait_for_event(&format!("{}!", self.owner.id), |event| match event {
                    EventV1::ChannelAck { message_id, .. } => message_id == &marker,
                    _ => false,
                })
                .await;

            for channel_id in self.server().await.channels {
                self.harness.assert_no_buffered_event(&channel_id, |event| {
                    matches!(event, EventV1::ProtectedChannelChanged { .. })
                });
            }
        }

        /// Make every reconcile of this server fail after the route's write:
        /// the protected channel's stored row becomes a non-server channel
        /// (its seat list, seats and entitlement stay), so the pass answers
        /// `InternalError` reading it (a seat list on anything but a server
        /// TextChannel is corrupt data). A removed row would not do: it is
        /// nothing to reconcile. Returns the row for [`Self::repair`].
        pub(crate) async fn break_reconcile(&self) -> Channel {
            let db = &self.harness.db;
            let channel = db.fetch_channel(&self.channel_id).await.expect("channel");
            self.store_channel(&Channel::SavedMessages {
                id: self.channel_id.clone(),
                user: self.owner.id.clone(),
            })
            .await;
            assert!(
                matches!(
                    db.fetch_channel(&self.channel_id).await,
                    Ok(Channel::SavedMessages { .. })
                ),
                "precondition: the stored row is not a server channel"
            );
            channel
        }

        /// Put back the row [`Self::break_reconcile`] replaced
        pub(crate) async fn repair(&self, channel: &Channel) {
            self.store_channel(channel).await;
        }

        /// Overwrite the stored row of `channel` straight in the store (no
        /// guard, no event); the row must exist
        async fn store_channel(&self, channel: &Channel) {
            match &self.harness.db {
                Database::Reference(reference) => {
                    let replaced = reference
                        .channels
                        .lock()
                        .await
                        .insert(channel.id().to_string(), channel.clone());
                    assert!(replaced.is_some(), "the channel row");
                }
                Database::MongoDb(mongo) => {
                    use revolt_database::mongodb::bson::doc;

                    let result = mongo
                        .col::<Channel>("channels")
                        .replace_one(doc! { "_id": channel.id() }, channel)
                        .await
                        .expect("the channel write");
                    assert_eq!(result.matched_count, 1, "the channel row");
                }
            }
        }

        /// A voice channel of the server whose call is pinned to
        /// [`ABSENT_NODE`], so the route's voice sync reaches it and fails
        /// with `UnknownNode`. Undo with [`end_call`].
        pub(crate) async fn unreachable_call(&self) -> Channel {
            let mut server = self.server().await;
            let channel = Channel::create_server_channel(
                &self.harness.db,
                &mut server,
                v0::DataCreateServerChannel {
                    channel_type: v0::LegacyServerChannelType::Text,
                    name: "Call".to_string(),
                    description: None,
                    nsfw: Some(false),
                    spoiler: None,
                    voice: Some(v0::VoiceInformation {
                        max_users: None,
                        disabled: false,
                    }),
                    announcement: None,
                    ..Default::default()
                },
                true,
            )
            .await
            .expect("voice channel");
            set_channel_node(channel.id(), ABSENT_NODE)
                .await
                .expect("node");
            channel
        }
    }
}
