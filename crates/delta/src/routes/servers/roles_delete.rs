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
    let permissions = calculate_server_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageRole)?;

    let member_rank = query.get_member_rank().unwrap_or(i64::MIN);

    let role = server
        .roles
        .get(&role_id)
        .cloned()
        .ok_or_else(|| create_error!(NotFound))?;

    if role.rank <= member_rank {
        return Err(create_error!(NotElevated));
    }

    // Deleting the role lifts every deny it carries, for every holder, so the
    // deleter must be able to clear each one (SEC-100). The gate runs while
    // `server` still holds the role: a deleter holding it is judged with it.
    throw_if_deleting_lifts_denies(db, &user, &server, &role, permissions).await?;

    server.roles.remove(&role_id);

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

/// Bits 52-63 name no permission (highest defined is bit 43) and nobody holds
/// them, the owner included; adding a deny is never checked, so unmasked they
/// would make a role undeletable by anyone.
fn lifted_denies(field: &revolt_permissions::OverrideField) -> revolt_permissions::Override {
    revolt_permissions::Override {
        allow: 0,
        deny: field.d as u64 & ChannelPermission::GrantAllSafe as u64,
    }
}

/// Refuse to delete `role` unless `user` could clear each deny it carries,
/// server-wide and on each of `server`'s channels, as a permission edit
/// would require: deleting the role lifts them all, for every holder. Its
/// allows are not checked; removing an allow grants nothing.
async fn throw_if_deleting_lifts_denies(
    db: &Database,
    user: &User,
    server: &revolt_database::Server,
    role: &revolt_database::Role,
    server_permissions: revolt_permissions::PermissionValue,
) -> Result<()> {
    let mut channel_denies = Vec::new();
    // The deny gate reads each channel's override for this role; not the
    // voice-sync loop the roles_edit_positions pin bans. One id at a time:
    // the drivers' fetch_channels disagree on dangling ids.
    for id in server.channels.iter() {
        let channel = match db.fetch_channel(id).await {
            Ok(channel) => channel,
            Err(error) if matches!(error.error_type, revolt_result::ErrorType::NotFound) => {
                continue
            }
            Err(error) => return Err(error),
        };
        let deny = match &channel {
            revolt_database::Channel::TextChannel {
                role_permissions, ..
            }
            | revolt_database::Channel::Forum {
                role_permissions, ..
            } => role_permissions.get(&role.id).map(lifted_denies),
            _ => None,
        };
        if let Some(deny) = deny.filter(|deny| deny.deny != 0) {
            channel_denies.push((channel, deny));
        }
    }

    let server_deny = lifted_denies(&role.permissions);
    if server_deny.deny == 0 && channel_denies.is_empty() {
        return Ok(());
    }

    let cleared = revolt_permissions::Override::default();
    server_permissions.throw_if_lacking_channel_permission(ChannelPermission::ManagePermissions)?;
    server_permissions
        .throw_permission_override(server_deny, &cleared)
        .await?;
    for (channel, deny) in &channel_denies {
        let mut query = DatabasePermissionQuery::new(db, user)
            .channel(channel)
            .server(server);
        let permissions = revolt_permissions::calculate_channel_permissions(&mut query).await;
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ManagePermissions)?;
        permissions
            .throw_permission_override(deny.clone(), &cleared)
            .await?;
    }

    Ok(())
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

#[cfg(test)]
mod deny_lift {
    //! SEC-100: deleting a role lifts every deny it carries, for every
    //! holder, so the delete is gated as clearing those denies by a
    //! permission edit would be. Owner O, moderator M (a rank-1 role) and
    //! holder U of the target (rank 5), on a fresh server per test; at most
    //! 5 requests per actor per server (the "servers" bucket).

    use crate::util::test::{rt, statement_at, without_comments, without_whitespace, TestHarness};
    use revolt_database::{
        AuditLogAction, AuditLogEntry, Channel, Member, PartialChannel, PartialMember, PartialRole,
        Role, Server, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};
    use serde_json::Value;
    use std::collections::HashMap;

    const MANAGE_ROLE: u64 = ChannelPermission::ManageRole as u64;
    const MANAGE_PERMISSIONS: u64 = ChannelPermission::ManagePermissions as u64;
    const MANAGE_MESSAGES: u64 = ChannelPermission::ManageMessages as u64;
    const SEND_MESSAGE: u64 = ChannelPermission::SendMessage as u64;
    const VIEW_CHANNEL: u64 = ChannelPermission::ViewChannel as u64;
    const GRANT_ALL_SAFE: u64 = ChannelPermission::GrantAllSafe as u64;
    /// Names no permission (the highest defined is bit 43).
    const BIT_60: u64 = 1 << 60;

    struct LiftFixture {
        harness: TestHarness,
        server: Server,
        /// The server's default text channel.
        channel: Channel,
        owner_token: String,
        moderator: User,
        moderator_token: String,
        moderator_role: Role,
        holder: User,
    }

    /// A fresh server owned by O, M holding a rank-1 role that allows
    /// `moderator_allow` server-wide, and U as a plain member.
    async fn lift_fixture(moderator_allow: u64) -> LiftFixture {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, moderator_session, moderator) = harness.new_user().await;
        let (_, _, holder) = harness.new_user().await;
        let (server, channels) = harness.new_server(&owner).await;
        for user in [&moderator, &holder] {
            Member::create(&harness.db, &server, user, None)
                .await
                .expect("member");
        }

        let moderator_role = deny_role(&harness, &server, 1, moderator_allow, 0).await;
        grant(&harness, &server, &moderator, &moderator_role).await;
        let channel = channels.into_iter().next().expect("the default channel");

        LiftFixture {
            harness,
            server,
            channel,
            owner_token: owner_session.token,
            moderator,
            moderator_token: moderator_session.token,
            moderator_role,
            holder,
        }
    }

    /// A role at `rank` with the server-level override `allow` / `deny`.
    /// `Role::create` derives the rank from the (stale) server passed in, so
    /// it is set here instead.
    async fn deny_role(
        harness: &TestHarness,
        server: &Server,
        rank: i64,
        allow: u64,
        deny: u64,
    ) -> Role {
        let mut role = harness
            .new_role(
                server,
                rank,
                Some(OverrideField {
                    a: allow as i64,
                    d: deny as i64,
                }),
            )
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

    async fn set_member_roles(
        harness: &TestHarness,
        server: &Server,
        user: &User,
        edit: impl FnOnce(&mut Vec<String>),
    ) {
        let mut member = harness
            .db
            .fetch_member(&server.id, &user.id)
            .await
            .expect("member read");
        let mut roles = member.roles.clone();
        edit(&mut roles);
        member
            .update(
                &harness.db,
                PartialMember {
                    roles: Some(roles),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("member roles");
    }

    async fn grant(harness: &TestHarness, server: &Server, user: &User, role: &Role) {
        set_member_roles(harness, server, user, |roles| roles.push(role.id.clone())).await;
    }

    async fn revoke(harness: &TestHarness, server: &Server, user: &User, role: &Role) {
        set_member_roles(harness, server, user, |roles| {
            roles.retain(|id| id != &role.id)
        })
        .await;
    }

    /// The role overrides of a text channel or a forum.
    fn overrides_of(channel: &Channel) -> &HashMap<String, OverrideField> {
        match channel {
            Channel::TextChannel {
                role_permissions, ..
            }
            | Channel::Forum {
                role_permissions, ..
            } => role_permissions,
            _ => panic!("a text channel or a forum"),
        }
    }

    /// A forum on the server, which is re-read first: the fixture's copy is
    /// stale once roles have been created.
    async fn deny_lift_forum(harness: &TestHarness, server: &Server) -> Channel {
        let mut server = harness
            .db
            .fetch_server(&server.id)
            .await
            .expect("server read");
        Channel::create_server_channel(
            &harness.db,
            &mut server,
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Forum,
                name: "forum".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("forum created")
    }

    /// `role`'s override on `channel` (a text channel or a forum), written
    /// through `update`: the reference driver's `set_channel_role_permission`
    /// only replaces an EXISTING entry.
    async fn set_channel_override(
        harness: &TestHarness,
        channel: &Channel,
        role: &Role,
        allow: u64,
        deny: u64,
    ) {
        let mut channel = harness
            .db
            .fetch_channel(channel.id())
            .await
            .expect("channel read");
        let mut role_permissions = overrides_of(&channel).clone();
        role_permissions.insert(
            role.id.clone(),
            OverrideField {
                a: allow as i64,
                d: deny as i64,
            },
        );
        channel
            .update(
                &harness.db,
                PartialChannel {
                    role_permissions: Some(role_permissions),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("channel override");
    }

    async fn override_on(
        harness: &TestHarness,
        channel: &Channel,
        role: &Role,
    ) -> Option<OverrideField> {
        let channel = harness
            .db
            .fetch_channel(channel.id())
            .await
            .expect("channel read");
        overrides_of(&channel).get(&role.id).copied()
    }

    async fn channel_override_of(f: &LiftFixture, role: &Role) -> Option<OverrideField> {
        override_on(&f.harness, &f.channel, role).await
    }

    /// The server's `role_delete` entries naming `role`. Selected by action
    /// and target, never by position.
    async fn role_delete_entries_of(f: &LiftFixture, role: &Role) -> Vec<AuditLogEntry> {
        f.harness
            .db
            .fetch_audit_log(&f.server.id, None, 50, None, None)
            .await
            .expect("audit log read")
            .into_iter()
            .filter(|entry| {
                entry.action == AuditLogAction::RoleDelete
                    && entry.target.as_deref() == Some(role.id.as_str())
            })
            .collect()
    }

    /// DELETE `role` from the session `token`: the status and the JSON body.
    async fn delete_as(f: &LiftFixture, token: &str, role: &Role) -> (Status, Value) {
        let response = f
            .harness
            .client
            .delete(format!("/servers/{}/roles/{}", f.server.id, role.id))
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        (status, serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    fn assert_missing_manage_permissions(answer: &(Status, Value)) {
        assert_eq!(answer.0, Status::Forbidden, "refused: {}", answer.1);
        assert_eq!(answer.1["type"], "MissingPermission", "{}", answer.1);
        assert_eq!(answer.1["permission"], "ManagePermissions", "{}", answer.1);
    }

    fn assert_cannot_give(answer: &(Status, Value)) {
        assert_eq!(answer.0, Status::Forbidden, "refused: {}", answer.1);
        assert_eq!(
            answer.1["type"], "CannotGiveMissingPermissions",
            "{}",
            answer.1
        );
    }

    fn assert_deleted(answer: &(Status, Value)) {
        assert_eq!(answer.0, Status::NoContent, "deleted: {}", answer.1);
    }

    /// After a refusal: nothing was recorded, the role is still on the
    /// server with its override, U still holds it, and its override on the
    /// default channel is `channel` as it was.
    async fn assert_kept(f: &LiftFixture, role: &Role, channel: Option<OverrideField>) {
        let entries = role_delete_entries_of(f, role).await;
        assert!(
            entries.is_empty(),
            "a refused delete records nothing: {:?}",
            entries
        );
        let server = f
            .harness
            .db
            .fetch_server(&f.server.id)
            .await
            .expect("server");
        assert!(server.roles.contains_key(&role.id), "the role is kept");
        let member = f
            .harness
            .db
            .fetch_member(&f.server.id, &f.holder.id)
            .await
            .expect("member read");
        assert!(member.roles.contains(&role.id), "U still holds the role");
        assert_eq!(
            channel_override_of(f, role).await,
            channel,
            "the channel override is intact"
        );
    }

    /// After a delete: the role is gone from the server, from U and from the
    /// channel, and exactly one `role_delete` entry names it (the positive
    /// control for `assert_kept`'s empty audit log).
    async fn assert_gone(f: &LiftFixture, role: &Role) {
        let entries = role_delete_entries_of(f, role).await;
        assert_eq!(
            entries.len(),
            1,
            "a delete records exactly one entry: {:?}",
            entries
        );
        let server = f
            .harness
            .db
            .fetch_server(&f.server.id)
            .await
            .expect("server");
        assert!(!server.roles.contains_key(&role.id), "the role is deleted");
        let member = f
            .harness
            .db
            .fetch_member(&f.server.id, &f.holder.id)
            .await
            .expect("member read");
        assert!(
            !member.roles.contains(&role.id),
            "U no longer holds the role"
        );
        assert_eq!(
            channel_override_of(f, role).await,
            None,
            "the channel override is gone"
        );
    }

    fn field(allow: u64, deny: u64) -> Option<OverrideField> {
        Some(OverrideField {
            a: allow as i64,
            d: deny as i64,
        })
    }

    /// (a) A server-level deny needs ManagePermissions to lift.
    #[test]
    fn manage_role_alone_cannot_delete_a_role_with_a_server_deny() {
        rt().block_on(async {
            let f = lift_fixture(MANAGE_ROLE).await;
            let muted = deny_role(&f.harness, &f.server, 5, 0, SEND_MESSAGE).await;
            grant(&f.harness, &f.server, &f.holder, &muted).await;

            let answer = delete_as(&f, &f.moderator_token, &muted).await;
            assert_missing_manage_permissions(&answer);
            assert_kept(&f, &muted, None).await;
        })
    }

    /// (b) So does a deny that is only on a channel.
    #[test]
    fn manage_role_alone_cannot_delete_a_role_whose_only_deny_is_on_a_channel() {
        rt().block_on(async {
            let f = lift_fixture(MANAGE_ROLE).await;
            let muted = deny_role(&f.harness, &f.server, 5, 0, 0).await;
            set_channel_override(&f.harness, &f.channel, &muted, 0, SEND_MESSAGE).await;
            grant(&f.harness, &f.server, &f.holder, &muted).await;

            let answer = delete_as(&f, &f.moderator_token, &muted).await;
            assert_missing_manage_permissions(&answer);
            assert_kept(&f, &muted, field(0, SEND_MESSAGE)).await;
        })
    }

    /// (b2) ManagePermissions server-wide is not enough when the deny sits on
    /// a channel the deleter cannot see: there they hold nothing.
    #[test]
    fn a_deny_on_a_channel_the_deleter_cannot_see_blocks_the_delete() {
        rt().block_on(async {
            let f = lift_fixture(MANAGE_ROLE | MANAGE_PERMISSIONS).await;
            set_channel_override(&f.harness, &f.channel, &f.moderator_role, 0, VIEW_CHANNEL).await;
            let muted = deny_role(&f.harness, &f.server, 5, 0, 0).await;
            set_channel_override(&f.harness, &f.channel, &muted, 0, SEND_MESSAGE).await;
            grant(&f.harness, &f.server, &f.holder, &muted).await;

            let answer = delete_as(&f, &f.moderator_token, &muted).await;
            assert_missing_manage_permissions(&answer);
            assert_kept(&f, &muted, field(0, SEND_MESSAGE)).await;
        })
    }

    /// (b3) Nor is it enough where the deleter's own role denies
    /// ManagePermissions on the channel carrying the deny, though they see
    /// that channel and hold the bit it denies there. Mutation: the
    /// channel-loop ManagePermissions check removed.
    #[test]
    fn a_channel_level_manage_permissions_deny_blocks_the_delete() {
        rt().block_on(async {
            let f = lift_fixture(MANAGE_ROLE | MANAGE_PERMISSIONS | SEND_MESSAGE).await;
            set_channel_override(
                &f.harness,
                &f.channel,
                &f.moderator_role,
                0,
                MANAGE_PERMISSIONS,
            )
            .await;
            let muted = deny_role(&f.harness, &f.server, 5, 0, 0).await;
            set_channel_override(&f.harness, &f.channel, &muted, 0, SEND_MESSAGE).await;
            grant(&f.harness, &f.server, &f.holder, &muted).await;

            let answer = delete_as(&f, &f.moderator_token, &muted).await;
            assert_missing_manage_permissions(&answer);
            assert_kept(&f, &muted, field(0, SEND_MESSAGE)).await;
        })
    }

    /// (b4) A deny only on a forum is gated as one on a text channel is:
    /// ManageRole alone is refused, and ManagePermissions server-wide
    /// without the bit the forum denies cannot lift it. Mutation: the gate's
    /// Forum arm dropped.
    #[test]
    fn manage_role_alone_cannot_delete_a_role_whose_only_deny_is_on_a_forum() {
        rt().block_on(async {
            let f = lift_fixture(MANAGE_ROLE).await;
            let muted = deny_role(&f.harness, &f.server, 5, 0, 0).await;
            let forum = deny_lift_forum(&f.harness, &f.server).await;
            set_channel_override(&f.harness, &forum, &muted, 0, MANAGE_MESSAGES).await;
            grant(&f.harness, &f.server, &f.holder, &muted).await;

            let answer = delete_as(&f, &f.moderator_token, &muted).await;
            assert_missing_manage_permissions(&answer);
            assert_kept(&f, &muted, None).await;
            assert_eq!(
                override_on(&f.harness, &forum, &muted).await,
                field(0, MANAGE_MESSAGES),
                "the forum override is intact"
            );

            // M now holds ManagePermissions server-wide, not ManageMessages.
            let mut moderator_role = f.moderator_role.clone();
            moderator_role
                .update(
                    &f.harness.db,
                    &f.server.id,
                    PartialRole {
                        permissions: Some(OverrideField {
                            a: (MANAGE_ROLE | MANAGE_PERMISSIONS) as i64,
                            d: 0,
                        }),
                        ..Default::default()
                    },
                    Vec::new(),
                )
                .await
                .expect("moderator role permissions");

            let answer = delete_as(&f, &f.moderator_token, &muted).await;
            assert_cannot_give(&answer);
            assert_kept(&f, &muted, None).await;
            assert_eq!(
                override_on(&f.harness, &forum, &muted).await,
                field(0, MANAGE_MESSAGES),
                "the forum override is intact"
            );
        })
    }

    /// (c) Lifting a deny on a bit the deleter lacks, server-wide or on a
    /// channel, answers as a permission edit would.
    mod lacking_a_denied_bit_answers_cannot_give_missing_permissions {
        use super::*;

        #[test]
        fn server() {
            rt().block_on(async {
                let f = lift_fixture(MANAGE_ROLE | MANAGE_PERMISSIONS).await;
                let muted = deny_role(&f.harness, &f.server, 5, 0, MANAGE_MESSAGES).await;
                grant(&f.harness, &f.server, &f.holder, &muted).await;

                let answer = delete_as(&f, &f.moderator_token, &muted).await;
                assert_cannot_give(&answer);
                assert_kept(&f, &muted, None).await;
            })
        }

        #[test]
        fn channel() {
            rt().block_on(async {
                let f = lift_fixture(MANAGE_ROLE | MANAGE_PERMISSIONS).await;
                let muted = deny_role(&f.harness, &f.server, 5, 0, 0).await;
                set_channel_override(&f.harness, &f.channel, &muted, 0, MANAGE_MESSAGES).await;
                grant(&f.harness, &f.server, &f.holder, &muted).await;

                let answer = delete_as(&f, &f.moderator_token, &muted).await;
                assert_cannot_give(&answer);
                assert_kept(&f, &muted, field(0, MANAGE_MESSAGES)).await;
            })
        }
    }

    /// (k) M holds the role, so on the channel M lacks the bit it denies;
    /// the gate judges M with the role still on the server. Control: the
    /// same M without the role deletes it.
    #[test]
    fn a_deleter_holding_the_role_cannot_lift_its_deny_onto_themselves() {
        rt().block_on(async {
            let f = lift_fixture(MANAGE_ROLE | MANAGE_PERMISSIONS).await;
            let muted = deny_role(&f.harness, &f.server, 5, 0, 0).await;
            set_channel_override(&f.harness, &f.channel, &muted, 0, SEND_MESSAGE).await;
            grant(&f.harness, &f.server, &f.holder, &muted).await;
            grant(&f.harness, &f.server, &f.moderator, &muted).await;

            let answer = delete_as(&f, &f.moderator_token, &muted).await;
            assert_cannot_give(&answer);
            assert_kept(&f, &muted, field(0, SEND_MESSAGE)).await;

            revoke(&f.harness, &f.server, &f.moderator, &muted).await;
            let answer = delete_as(&f, &f.moderator_token, &muted).await;
            assert_deleted(&answer);
            assert_gone(&f, &muted).await;
        })
    }

    /// (d) Holding ManagePermissions and every denied bit, server-wide and on
    /// the channel, deletes.
    #[test]
    fn holding_every_denied_bit_deletes() {
        rt().block_on(async {
            let f = lift_fixture(MANAGE_ROLE | MANAGE_PERMISSIONS | MANAGE_MESSAGES).await;
            let muted = deny_role(&f.harness, &f.server, 5, 0, MANAGE_MESSAGES).await;
            set_channel_override(
                &f.harness,
                &f.channel,
                &muted,
                0,
                MANAGE_MESSAGES | SEND_MESSAGE,
            )
            .await;
            grant(&f.harness, &f.server, &f.holder, &muted).await;

            let answer = delete_as(&f, &f.moderator_token, &muted).await;
            assert_deleted(&answer);
            assert_gone(&f, &muted).await;
        })
    }

    /// (e) Removing an allow grants nothing, and a deny on a bit no
    /// permission uses lifts nothing: ManageRole alone still deletes both.
    #[test]
    fn an_allow_only_role_still_deletes_with_manage_role_alone() {
        rt().block_on(async {
            let f = lift_fixture(MANAGE_ROLE).await;
            let helper = deny_role(&f.harness, &f.server, 5, MANAGE_MESSAGES, 0).await;
            set_channel_override(&f.harness, &f.channel, &helper, MANAGE_MESSAGES, 0).await;
            grant(&f.harness, &f.server, &f.holder, &helper).await;
            let bit_60 = deny_role(&f.harness, &f.server, 6, 0, BIT_60).await;
            set_channel_override(&f.harness, &f.channel, &bit_60, 0, BIT_60).await;
            grant(&f.harness, &f.server, &f.holder, &bit_60).await;

            let answer = delete_as(&f, &f.moderator_token, &helper).await;
            assert_deleted(&answer);
            assert_gone(&f, &helper).await;

            let answer = delete_as(&f, &f.moderator_token, &bit_60).await;
            assert_deleted(&answer);
            assert_gone(&f, &bit_60).await;
        })
    }

    /// (f) The owner holds every permission there is, so lifts any deny.
    #[test]
    fn the_owner_deletes_a_role_denying_everything() {
        rt().block_on(async {
            let f = lift_fixture(MANAGE_ROLE).await;
            let muted = deny_role(&f.harness, &f.server, 5, 0, GRANT_ALL_SAFE).await;
            set_channel_override(&f.harness, &f.channel, &muted, 0, GRANT_ALL_SAFE).await;
            grant(&f.harness, &f.server, &f.holder, &muted).await;

            let answer = delete_as(&f, &f.owner_token, &muted).await;
            assert_deleted(&answer);
            assert_gone(&f, &muted).await;
        })
    }

    /// (h) Bits 52-63 are held by nobody, the owner included; a deny on them
    /// must not make the role undeletable.
    #[test]
    fn a_deny_above_bit_51_never_locks_the_owner_out() {
        rt().block_on(async {
            let f = lift_fixture(MANAGE_ROLE).await;
            let muted = deny_role(&f.harness, &f.server, 5, 0, (1 << 52) | BIT_60).await;
            set_channel_override(&f.harness, &f.channel, &muted, 0, 1 << 63).await;
            grant(&f.harness, &f.server, &f.holder, &muted).await;

            let answer = delete_as(&f, &f.owner_token, &muted).await;
            assert_deleted(&answer);
            assert_gone(&f, &muted).await;
        })
    }

    /// (g) The gate runs while `server` still holds the role (else a deleter
    /// holding it is judged without its deny), and before the deletion.
    /// Mutation: the removal moved above the gate.
    #[test]
    fn the_deny_gate_precedes_the_role_removal_and_the_deletion() {
        let source = include_str!("roles_delete.rs");
        let shipping = &source[..source.find("#[cfg(test)]").expect("a test module")];
        let code = without_whitespace(&without_comments(shipping));

        let gate = statement_at(
            &code,
            "throw_if_deleting_lifts_denies(db,&user,&server,&role,permissions).await?;",
        );
        let removal = statement_at(&code, "server.roles.remove(&role_id);");
        let deletion = statement_at(&code, "role.delete(db,&server.id).await?;");
        assert!(
            gate < removal,
            "the gate must precede the removal from `server`"
        );
        assert!(removal < deletion, "the removal must precede the deletion");
    }
}
