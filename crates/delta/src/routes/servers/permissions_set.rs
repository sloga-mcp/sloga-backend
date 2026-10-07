use revolt_database::{
    util::{
        audit_reason::AuditLogReason, permissions::DatabasePermissionQuery, reference::Reference,
    },
    voice::{sync_server_voice_permissions, VoiceClient},
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Database, User,
};
use revolt_models::v0;
use revolt_permissions::{
    calculate_server_permissions, ChannelPermission, Override, OverrideField,
};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Set Role Permission
///
/// Sets permissions for the specified role in the server.
#[openapi(tag = "Server Permissions")]
#[put("/<target>/permissions/<role_id>", data = "<data>", rank = 2)]
pub async fn set_role_permission(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
    role_id: String,
    data: Json<v0::DataSetServerRolePermission>,
    reason: AuditLogReason,
) -> Result<Json<v0::Server>> {
    let data = data.into_inner();

    // Refuse an over-long reason before anything is read or written.
    let reason = reason.validated()?;

    let mut server = target.as_server(db).await?;

    let (current_value, rank) = server
        .roles
        .get(&role_id)
        .map(|x| (x.permissions, x.rank))
        .ok_or_else(|| create_error!(NotFound))?;

    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    let permissions = calculate_server_permissions(&mut query).await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::ManagePermissions)?;

    // Prevent us from editing roles above us
    if rank <= query.get_member_rank().unwrap_or(i64::MIN) {
        return Err(create_error!(NotElevated));
    }

    // The stored and requested values, for the audit entry.
    let old_value = current_value;
    let new_value = OverrideField::from(data.permissions.clone());

    // Ensure we have access to grant these permissions forwards
    let current_value: Override = current_value.into();
    permissions
        .throw_permission_override(current_value, &data.permissions)
        .await?;

    server
        .set_role_permission(db, &role_id, data.permissions.into())
        .await?;

    // Recorded after the write and before the sync, which must stay the last
    // step before the answer (`the_server_wide_syncs_follow_their_write`).
    // A PUT of the values already stored changes nothing and is not logged.
    if old_value.a != new_value.a || old_value.d != new_value.d {
        AuditLogEntry::record(
            db,
            AuditLogDraft {
                server: server.id.clone(),
                actor: Some(user.id.clone()),
                action: AuditLogAction::ServerPermissionsUpdate,
                target: Some(role_id.clone()),
                changes: vec![
                    AuditLogChange::new(
                        "allow",
                        Some(AuditValue::Int(old_value.a)),
                        Some(AuditValue::Int(new_value.a)),
                    ),
                    AuditLogChange::new(
                        "deny",
                        Some(AuditValue::Int(old_value.d)),
                        Some(AuditValue::Int(new_value.d)),
                    ),
                ],
                reason,
                ..Default::default()
            },
        )
        .await;
    }

    // Every channel is tried before the first failure is answered (AFK S-3
    // D-6); `server` already carries the new permission.
    sync_server_voice_permissions(db, voice_client, &server, Some(&role_id)).await?;

    Ok(Json(server.into()))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{
        util::audit_reason::{AUDIT_LOG_REASON_HEADER, AUDIT_LOG_REASON_MAX_CHARS},
        AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, Member, PartialMember,
        PartialRole, Role, Server, Session, User,
    };
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::Value;

    // Compile-only without RabbitMQ and Redis: `TestHarness::new` connects
    // to RabbitMQ and the route's voice sync reads Redis, like the other
    // `servers/` route tests, so these run on the shared runtime.

    const VIEW: i64 = ChannelPermission::ViewChannel as i64;
    const SEND: i64 = ChannelPermission::SendMessage as i64;
    const MANAGE_MESSAGES: i64 = ChannelPermission::ManageMessages as i64;
    const MANAGE_PERMISSIONS: i64 = ChannelPermission::ManagePermissions as i64;
    const MANAGE_SERVER: i64 = ChannelPermission::ManageServer as i64;

    /// PUT `allow` / `deny` onto `role_id` as `session`, with the reason
    /// header sent as given (the client percent-encodes it). Returns the
    /// status and the raw JSON body (Null when it is not JSON).
    async fn set_permissions(
        harness: &TestHarness,
        session: &Session,
        server: &Server,
        role_id: &str,
        permissions: OverrideField,
        reason: Option<&str>,
    ) -> (Status, Value) {
        let mut request = harness
            .client
            .put(format!("/servers/{}/permissions/{}", server.id, role_id))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.to_string()))
            .body(
                json!({ "permissions": { "allow": permissions.a, "deny": permissions.d } })
                    .to_string(),
            );
        if let Some(reason) = reason {
            request = request.header(Header::new(AUDIT_LOG_REASON_HEADER, reason.to_string()));
        }
        let response = request.dispatch().await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        let json = serde_json::from_str(&body).unwrap_or(Value::Null);
        (status, json)
    }

    /// Every audit log entry of `server`, newest first.
    async fn audit_log(harness: &TestHarness, server: &Server) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(&server.id, None, 50, None, None)
            .await
            .expect("fetch audit log")
    }

    /// The role's permissions as stored.
    async fn stored(harness: &TestHarness, server: &Server, role_id: &str) -> OverrideField {
        harness
            .db
            .fetch_server(&server.id)
            .await
            .expect("server")
            .roles
            .get(role_id)
            .expect("the role still exists")
            .permissions
    }

    /// A role with an explicit rank and permissions. `Role::create` derives
    /// the rank from the (stale) server passed in, so it is set here instead.
    async fn ranked_role(
        harness: &TestHarness,
        server: &Server,
        rank: i64,
        permissions: OverrideField,
    ) -> Role {
        let mut role = harness.new_role(server, rank, Some(permissions)).await;
        role.update(
            &harness.db,
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

    async fn member_with_role(harness: &TestHarness, server: &Server, user: &User, role: &Role) {
        let (mut member, _) = Member::create(&harness.db, server, user, None)
            .await
            .expect("member");
        member
            .update(
                &harness.db,
                PartialMember {
                    roles: Some(vec![role.id.clone()]),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("role");
    }

    fn change(key: &str, old: i64, new: i64) -> AuditLogChange {
        AuditLogChange::new(key, Some(AuditValue::Int(old)), Some(AuditValue::Int(new)))
    }

    #[test]
    fn a_permission_change_writes_one_server_permissions_update_entry() {
        crate::util::test::rt()
            .block_on(a_permission_change_writes_one_server_permissions_update_entry_case())
    }

    /// The owner changes a role's allow and deny with a percent-encoded
    /// reason header: the new value is stored and exactly one
    /// `server_permissions_update` entry is written, actor = the session
    /// user, target = the role, no channel or count, `allow` and `deny` as
    /// Int old/new, the reason decoded. A second change without the header
    /// records the first change's new value as its old value (the snapshot
    /// is taken before the write) and no reason. A third PUT of the values
    /// already stored succeeds and writes nothing. Mutation: the
    /// changed-values condition dropped.
    async fn a_permission_change_writes_one_server_permissions_update_entry_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let before = OverrideField {
            a: VIEW | SEND,
            d: MANAGE_MESSAGES,
        };
        let after = OverrideField {
            a: VIEW,
            d: SEND | MANAGE_MESSAGES,
        };
        let role = ranked_role(&harness, &server, 5, before).await;
        assert_eq!(stored(&harness, &server, &role.id).await, before);

        let (status, body) = set_permissions(
            &harness,
            &owner_session,
            &server,
            &role.id,
            after,
            Some("tightened%20after%20a%20raid%3A%20rule%203"),
        )
        .await;
        assert_eq!(status, Status::Ok, "body: {}", body);
        assert_eq!(stored(&harness, &server, &role.id).await, after);

        let entries = audit_log(&harness, &server).await;
        assert_eq!(entries.len(), 1, "{:?}", entries);
        let entry = &entries[0];
        assert_eq!(entry.server, server.id);
        assert_eq!(entry.action, AuditLogAction::ServerPermissionsUpdate);
        assert_eq!(entry.actor.as_deref(), Some(owner.id.as_str()));
        assert_eq!(entry.target.as_deref(), Some(role.id.as_str()));
        assert_eq!(entry.channel, None);
        assert_eq!(entry.count, None);
        assert_eq!(
            entry.changes,
            vec![
                change("allow", before.a, after.a),
                change("deny", before.d, after.d),
            ]
        );
        assert_eq!(
            entry.reason.as_deref(),
            Some("tightened after a raid: rule 3")
        );

        let (status, body) =
            set_permissions(&harness, &owner_session, &server, &role.id, before, None).await;
        assert_eq!(status, Status::Ok, "body: {}", body);
        assert_eq!(stored(&harness, &server, &role.id).await, before);

        let entries = audit_log(&harness, &server).await;
        assert_eq!(entries.len(), 2, "{:?}", entries);
        // Picked by reason, not position: two ULIDs minted in the same
        // millisecond do not sort by mint order on the reference driver.
        let second = entries
            .iter()
            .find(|entry| entry.reason.is_none())
            .expect("an entry for the second change");
        assert_eq!(second.action, AuditLogAction::ServerPermissionsUpdate);
        assert_eq!(second.actor.as_deref(), Some(owner.id.as_str()));
        assert_eq!(second.target.as_deref(), Some(role.id.as_str()));
        assert_eq!(
            second.changes,
            vec![
                change("allow", after.a, before.a),
                change("deny", after.d, before.d),
            ]
        );

        let (status, body) = set_permissions(
            &harness,
            &owner_session,
            &server,
            &role.id,
            before,
            Some("no%20change"),
        )
        .await;
        assert_eq!(status, Status::Ok, "body: {}", body);
        assert_eq!(stored(&harness, &server, &role.id).await, before);
        let entries = audit_log(&harness, &server).await;
        assert_eq!(
            entries.len(),
            2,
            "an unchanged PUT logs nothing: {:?}",
            entries
        );
    }

    #[test]
    fn an_overlong_reason_is_refused_and_nothing_changes() {
        crate::util::test::rt().block_on(an_overlong_reason_is_refused_and_nothing_changes_case())
    }

    /// A reason one char over the limit is refused with
    /// FailedValidation/AuditLogReasonTooLong BEFORE the write: the role keeps
    /// its permissions and nothing is logged. Mutation: the `validated()?`
    /// moved below the write.
    async fn an_overlong_reason_is_refused_and_nothing_changes_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let before = OverrideField { a: VIEW, d: 0 };
        let role = ranked_role(&harness, &server, 5, before).await;

        let reason = "a".repeat(AUDIT_LOG_REASON_MAX_CHARS + 1);
        let (status, body) = set_permissions(
            &harness,
            &owner_session,
            &server,
            &role.id,
            OverrideField {
                a: VIEW | SEND,
                d: 0,
            },
            Some(&reason),
        )
        .await;
        assert_eq!(status, Status::BadRequest, "body: {}", body);
        assert_eq!(body["type"], "FailedValidation", "body: {}", body);
        assert_eq!(body["error"], "AuditLogReasonTooLong", "body: {}", body);

        assert_eq!(stored(&harness, &server, &role.id).await, before);
        assert!(audit_log(&harness, &server).await.is_empty());
    }

    #[test]
    fn a_role_at_or_above_the_editor_is_refused_and_nothing_is_logged() {
        crate::util::test::rt()
            .block_on(a_role_at_or_above_the_editor_is_refused_and_nothing_is_logged_case())
    }

    /// A moderator holding ManagePermissions on a rank-2 role cannot edit a
    /// rank-1 role (above them) or their own rank-2 role: both are refused
    /// with NotElevated, neither role changes and nothing is logged.
    async fn a_role_at_or_above_the_editor_is_refused_and_nothing_is_logged_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, moderator_session, moderator) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let moderator_permissions = OverrideField {
            a: MANAGE_PERMISSIONS | VIEW,
            d: 0,
        };
        let senior_permissions = OverrideField { a: VIEW, d: 0 };
        let moderator_role = ranked_role(&harness, &server, 2, moderator_permissions).await;
        let senior_role = ranked_role(&harness, &server, 1, senior_permissions).await;
        member_with_role(&harness, &server, &moderator, &moderator_role).await;

        for (role, before) in [
            (&senior_role, senior_permissions),
            (&moderator_role, moderator_permissions),
        ] {
            let (status, body) = set_permissions(
                &harness,
                &moderator_session,
                &server,
                &role.id,
                OverrideField { a: 0, d: 0 },
                Some("rank"),
            )
            .await;
            assert_eq!(status, Status::Forbidden, "body: {}", body);
            assert_eq!(body["type"], "NotElevated", "body: {}", body);
            assert_eq!(stored(&harness, &server, &role.id).await, before);
        }
        assert!(audit_log(&harness, &server).await.is_empty());
    }

    #[test]
    fn a_refused_permission_check_writes_nothing() {
        crate::util::test::rt().block_on(a_refused_permission_check_writes_nothing_case())
    }

    /// Two permission refusals, neither of which logs: a member without
    /// ManagePermissions (MissingPermission), and a moderator who outranks
    /// the role but tries to grant ManageServer, which they do not hold
    /// (CannotGiveMissingPermissions). The role keeps its permissions.
    async fn a_refused_permission_check_writes_nothing_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, moderator_session, moderator) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        Member::create(&harness.db, &server, &member, None)
            .await
            .expect("member");
        let moderator_role = ranked_role(
            &harness,
            &server,
            1,
            OverrideField {
                a: MANAGE_PERMISSIONS | VIEW,
                d: 0,
            },
        )
        .await;
        member_with_role(&harness, &server, &moderator, &moderator_role).await;
        let before = OverrideField { a: VIEW, d: 0 };
        let role = ranked_role(&harness, &server, 5, before).await;

        let (status, body) = set_permissions(
            &harness,
            &member_session,
            &server,
            &role.id,
            OverrideField { a: 0, d: 0 },
            Some("not%20allowed"),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "body: {}", body);
        assert_eq!(body["type"], "MissingPermission", "body: {}", body);
        assert_eq!(stored(&harness, &server, &role.id).await, before);

        let (status, body) = set_permissions(
            &harness,
            &moderator_session,
            &server,
            &role.id,
            OverrideField {
                a: VIEW | MANAGE_SERVER,
                d: 0,
            },
            Some("escalate"),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "body: {}", body);
        assert_eq!(
            body["type"], "CannotGiveMissingPermissions",
            "body: {}",
            body
        );
        assert_eq!(stored(&harness, &server, &role.id).await, before);

        assert!(audit_log(&harness, &server).await.is_empty());
    }

    // ---- the entry's place in the route, pinned on its text ---------------

    /// `set_role_permission`'s body, comment lines dropped and whitespace
    /// collapsed, so a needle does not depend on rustfmt's line breaks.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("permissions_set.rs");
        let shipping = SOURCE
            .find("#[cfg(test)]")
            .map_or(SOURCE, |end| &SOURCE[..end]);
        let at = shipping
            .find("pub async fn set_role_permission(")
            .expect("the route is defined");
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

    /// The reason is validated before the role is even loaded, the entry is
    /// recorded once, only when a value changed, after the write and before
    /// the voice sync (which stays the last step, see
    /// `the_server_wide_syncs_follow_their_write` in
    /// `roles_edit_positions.rs`). Mutations: the record moved above the
    /// write (a failed write would still be logged); `validated()?` moved
    /// below the write; the changed-values condition dropped.
    #[test]
    fn the_entry_is_recorded_between_the_write_and_the_sync() {
        let body = route_body();
        let find = |needle: &str| {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "`{}` once: {}",
                needle,
                body
            );
            body.find(needle).expect("counted above")
        };
        let validated = find("reason.validated()?;");
        let loaded = find("target.as_server(db).await?;");
        let written = find(".set_role_permission(db, &role_id, data.permissions.into()) .await?;");
        let changed = find("if old_value.a != new_value.a || old_value.d != new_value.d");
        let recorded = find("AuditLogEntry::record(");
        let synced = find("sync_server_voice_permissions(");
        assert!(validated < loaded, "validate first: {}", body);
        assert!(written < changed, "compare after the write: {}", body);
        assert!(changed < recorded, "record only on a change: {}", body);
        assert!(written < recorded, "record after the write: {}", body);
        assert!(recorded < synced, "record before the sync: {}", body);
    }
}
