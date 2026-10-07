use revolt_database::{
    util::{
        audit_reason::AuditLogReason, permissions::DatabasePermissionQuery, reference::Reference,
    },
    voice::{sync_server_voice_permissions, VoiceClient},
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Database, User,
};
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Delete Role
///
/// Delete a server role by its id.
#[openapi(tag = "Server Permissions")]
#[delete("/<target>/roles/<role_id>")]
pub async fn delete(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    role_id: String,
    voice_client: &State<VoiceClient>,
    reason: AuditLogReason,
) -> Result<EmptyResponse> {
    // Validated before anything else: a too-long reason must refuse the
    // deletion, never answer 400 after it.
    let reason = reason.validated()?;

    let mut server = target.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageRole)?;

    let member_rank = query.get_member_rank().unwrap_or(i64::MIN);

    let role = server
        .roles
        .remove(&role_id)
        .ok_or_else(|| create_error!(NotFound))?;

    if role.rank <= member_rank {
        return Err(create_error!(NotElevated));
    }

    // `delete` consumes the role, so its name is kept for the audit entry.
    let name = role.name.clone();
    role.delete(db, &server.id).await?;

    // Recorded once the deletion is durable and BEFORE the voice sync: a
    // failed sync answers an error, but the deletion it follows still
    // happened.
    AuditLogEntry::record(
        db,
        AuditLogDraft {
            server: server.id.clone(),
            actor: Some(user.id.clone()),
            action: AuditLogAction::RoleDelete,
            target: Some(role_id),
            changes: vec![AuditLogChange::new(
                "name",
                Some(AuditValue::String(name)),
                None,
            )],
            reason,
            ..Default::default()
        },
    )
    .await;

    // Everyone in every call re-syncs, not just the role's holders (AFK S-3
    // F-8): on MongoDB `delete_role` has already pulled the role from every
    // member, so a sync scoped to it would match nobody. `server` no longer
    // holds the role, so each grant is computed without it. The helper tries
    // every channel before answering its first failure (D-6).
    sync_server_voice_permissions(db, voice_client, &server, None).await?;

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{
        AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, Member, PartialMember,
        PartialRole, Role, Server, User,
    };
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};

    // ---- behavior (needs RabbitMQ and Redis) ------------------------------
    //
    // Compile-only on a box without those services, like every other route
    // test: the deletion publishes an event and the route ends in the
    // server-wide voice sync, which reads Redis.

    /// `DELETE /servers/<server>/roles/<role>` with an `X-Audit-Log-Reason`
    /// header, sent as given (the client percent-encodes it).
    async fn delete_role<'a>(
        harness: &'a TestHarness,
        token: &str,
        server_id: &str,
        role_id: &str,
        reason: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .delete(format!("/servers/{}/roles/{}", server_id, role_id))
            .header(Header::new("x-session-token", token.to_string()))
            .header(Header::new("X-Audit-Log-Reason", reason.to_string()))
            .dispatch()
            .await
    }

    async fn assert_rejected(
        response: rocket::local::asynchronous::LocalResponse<'_>,
        status: Status,
        error_type: &str,
    ) {
        assert_eq!(response.status(), status);
        let body = response.into_string().await.unwrap_or_default();
        assert!(
            body.contains(error_type),
            "expected a {} error, got: {}",
            error_type,
            body
        );
    }

    /// Every `role_delete` entry of `server_id`. Selected by action, never
    /// by position: entries minted in the same millisecond have no order.
    async fn role_delete_entries(harness: &TestHarness, server_id: &str) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(server_id, None, 50, None, None)
            .await
            .expect("audit log read")
            .into_iter()
            .filter(|entry| entry.action == AuditLogAction::RoleDelete)
            .collect()
    }

    async fn role_exists(harness: &TestHarness, server_id: &str, role_id: &str) -> bool {
        harness
            .db
            .fetch_server(server_id)
            .await
            .expect("server")
            .roles
            .contains_key(role_id)
    }

    /// A role with explicit rank and permissions. `Role::create` derives the
    /// rank from the (stale) server passed in, so it is set here instead.
    async fn ranked_role(harness: &TestHarness, server: &Server, rank: i64, allow: i64) -> Role {
        let mut role = harness
            .new_role(server, rank, Some(OverrideField { a: allow, d: 0 }))
            .await;
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

    async fn member_with_roles(
        harness: &TestHarness,
        server: &Server,
        user: &User,
        roles: Vec<String>,
    ) {
        let (mut member, _) = Member::create(&harness.db, server, user, None)
            .await
            .expect("member");
        member
            .update(
                &harness.db,
                PartialMember {
                    roles: Some(roles),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("roles");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_role_delete_records_the_old_name_and_the_header_reason() {
        crate::util::test::rt()
            .block_on(a_role_delete_records_the_old_name_and_the_header_reason_case())
    }

    /// A deletion writes exactly one `role_delete` entry: the deleter as
    /// actor, the role id as target, no channel or count, the role's name as
    /// the OLD value of `name` (the role is gone, so there is no new one),
    /// and the reason percent-decoded from the header.
    async fn a_role_delete_records_the_old_name_and_the_header_reason_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (server, _channels) = harness.new_server(&user_a).await;
        let role = ranked_role(&harness, &server, 1, 0).await;
        assert!(role_exists(&harness, &server.id, &role.id).await);

        let response = delete_role(
            &harness,
            &session_a.token,
            &server.id,
            &role.id,
            "role%20cleanup",
        )
        .await;
        assert_eq!(
            response.status(),
            Status::NoContent,
            "the deletion succeeds"
        );
        drop(response);
        assert!(
            !role_exists(&harness, &server.id, &role.id).await,
            "the role is deleted"
        );

        let entries = role_delete_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), 1, "exactly one entry: {:?}", entries);
        let entry = &entries[0];
        assert_eq!(entry.server, server.id);
        assert_eq!(entry.action, AuditLogAction::RoleDelete);
        assert_eq!(entry.actor.as_deref(), Some(user_a.id.as_str()));
        assert_eq!(entry.target.as_deref(), Some(role.id.as_str()));
        assert_eq!(entry.channel, None);
        assert_eq!(entry.count, None);
        assert_eq!(
            entry.changes,
            vec![AuditLogChange::new(
                "name",
                Some(AuditValue::String(role.name.clone())),
                None,
            )]
        );
        assert_eq!(entry.reason.as_deref(), Some("role cleanup"));
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_too_long_reason_refuses_the_role_delete() {
        crate::util::test::rt().block_on(a_too_long_reason_refuses_the_role_delete_case())
    }

    /// A 513-character reason is refused with AuditLogReasonTooLong before
    /// anything happens: the role still exists and nothing is recorded.
    /// Mutation: the validation moved below the deletion.
    async fn a_too_long_reason_refuses_the_role_delete_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (server, _channels) = harness.new_server(&user_a).await;
        let role = ranked_role(&harness, &server, 1, 0).await;

        let response = delete_role(
            &harness,
            &session_a.token,
            &server.id,
            &role.id,
            &"a".repeat(513),
        )
        .await;
        assert_rejected(response, Status::BadRequest, "AuditLogReasonTooLong").await;

        assert!(
            role_exists(&harness, &server.id, &role.id).await,
            "a refused deletion must leave the role in place"
        );
        assert!(role_delete_entries(&harness, &server.id).await.is_empty());
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_role_delete_without_manage_role_is_refused_and_records_nothing() {
        crate::util::test::rt()
            .block_on(a_role_delete_without_manage_role_is_refused_and_records_nothing_case())
    }

    /// A member without ManageRole is refused with MissingPermission: the
    /// role still exists and nothing is recorded.
    async fn a_role_delete_without_manage_role_is_refused_and_records_nothing_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, user_a) = harness.new_user().await; // owner
        let (_m, session_m, user_m) = harness.new_user().await; // plain member
        let (server, _channels) = harness.new_server(&user_a).await;
        let role = ranked_role(&harness, &server, 5, 0).await;
        member_with_roles(&harness, &server, &user_m, vec![]).await;

        let response = delete_role(&harness, &session_m.token, &server.id, &role.id, "perm").await;
        assert_rejected(response, Status::Forbidden, "MissingPermission").await;

        assert!(
            role_exists(&harness, &server.id, &role.id).await,
            "a refused deletion must leave the role in place"
        );
        assert!(role_delete_entries(&harness, &server.id).await.is_empty());
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_role_delete_at_or_above_the_deleter_is_refused_and_records_nothing() {
        crate::util::test::rt()
            .block_on(a_role_delete_at_or_above_the_deleter_is_refused_and_records_nothing_case())
    }

    /// A moderator holding ManageRole whose own role ranks below the target
    /// role (a larger rank number) is refused with NotElevated: the role
    /// still exists and nothing is recorded.
    async fn a_role_delete_at_or_above_the_deleter_is_refused_and_records_nothing_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, user_a) = harness.new_user().await; // owner
        let (_m, session_m, user_m) = harness.new_user().await; // moderator
        let (server, _channels) = harness.new_server(&user_a).await;
        let moderator =
            ranked_role(&harness, &server, 5, ChannelPermission::ManageRole as i64).await;
        let senior = ranked_role(&harness, &server, 1, 0).await;
        member_with_roles(&harness, &server, &user_m, vec![moderator.id.clone()]).await;

        let response =
            delete_role(&harness, &session_m.token, &server.id, &senior.id, "rank").await;
        assert_rejected(response, Status::Forbidden, "NotElevated").await;

        assert!(
            role_exists(&harness, &server.id, &senior.id).await,
            "a refused deletion must leave the role in place"
        );
        assert!(role_delete_entries(&harness, &server.id).await.is_empty());
    }

    // ---- the deletion's order, pinned on its text ---------------------------

    /// `delete`'s body in the shipping code, comment lines dropped and
    /// whitespace collapsed.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("roles_delete.rs");
        let shipping = SOURCE
            .find("#[cfg(test)]")
            .map_or(SOURCE, |end| &SOURCE[..end]);
        let at = shipping
            .find("pub async fn delete(")
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

    /// The reason is validated before the server is even read, the entry is
    /// recorded after the deletion, and the voice sync still follows the
    /// entry. Mutations: the validation moved below the deletion; the record
    /// moved above the deletion.
    #[test]
    fn the_role_delete_validates_the_reason_first_and_records_after_the_delete() {
        const VALIDATE: &str = "let reason = reason.validated()?;";
        const READ: &str = "target.as_server(db).await?;";
        const DELETE: &str = "role.delete(db, &server.id).await?;";
        const RECORD: &str = "AuditLogEntry::record(";
        const SYNC: &str = "sync_server_voice_permissions(db, voice_client, &server, None).await?;";

        let body = route_body();
        let at = |needle: &str| {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "`{}` must appear exactly once: {}",
                needle,
                body
            );
            body.find(needle).expect("counted above")
        };
        let (validate, read, delete, record, sync) =
            (at(VALIDATE), at(READ), at(DELETE), at(RECORD), at(SYNC));
        assert!(validate < read, "validate before the read: {}", body);
        assert!(delete < record, "record after the deletion: {}", body);
        assert!(record < sync, "record before the voice sync: {}", body);
    }
}
