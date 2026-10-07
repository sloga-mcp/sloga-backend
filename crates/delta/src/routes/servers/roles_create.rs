use revolt_config::config;
use revolt_database::util::audit_reason::AuditLogReason;
use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Database, Role, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Create Role
///
/// Creates a new server role.
#[openapi(tag = "Server Permissions")]
#[post("/<target>/roles", data = "<data>")]
pub async fn create(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataCreateRole>,
    reason: AuditLogReason,
) -> Result<Json<v0::NewRoleResponse>> {
    // Refuse an over-long reason before the role is created.
    let reason = reason.validated()?;

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let server = target.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageRole)?;

    let config = config().await;
    if server.roles.len() >= config.features.limits.global.server_roles {
        return Err(create_error!(TooManyRoles {
            max: config.features.limits.global.server_roles,
        }));
    };

    let role = Role::create(db, &server, data.name).await?;

    AuditLogEntry::record(
        db,
        AuditLogDraft {
            server: server.id.clone(),
            actor: Some(user.id.clone()),
            action: AuditLogAction::RoleCreate,
            target: Some(role.id.clone()),
            changes: vec![AuditLogChange::new(
                "name",
                None,
                Some(AuditValue::String(role.name.clone())),
            )],
            reason,
            ..Default::default()
        },
    )
    .await;

    Ok(Json(v0::NewRoleResponse {
        id: role.id.clone(),
        role: role.into(),
    }))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{
        util::audit_reason::{AUDIT_LOG_REASON_HEADER, AUDIT_LOG_REASON_MAX_CHARS},
        AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, Member, Server, Session,
    };
    use rocket::http::{ContentType, Header, Status};
    use serde_json::Value;

    // Compile-only without RabbitMQ: `TestHarness::new` connects to it, like
    // every other route test. Driven on the shared runtime like the other
    // `servers/` route tests.

    /// POST a new role; returns the status and the raw JSON body (Null when
    /// the answer has no body).
    async fn create_role(
        harness: &TestHarness,
        session: &Session,
        server: &Server,
        name: &str,
        reason: Option<&str>,
    ) -> (Status, Value) {
        let mut request = harness
            .client
            .post(format!("/servers/{}/roles", server.id))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.to_string()))
            .body(serde_json::json!({ "name": name }).to_string());
        if let Some(reason) = reason {
            request = request.header(Header::new(AUDIT_LOG_REASON_HEADER, reason.to_string()));
        }
        let response = request.dispatch().await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        let json = serde_json::from_str(&body).unwrap_or(Value::Null);
        (status, json)
    }

    async fn audit_log(harness: &TestHarness, server: &Server) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(&server.id, None, 50, None, None)
            .await
            .expect("fetch audit log")
    }

    /// The ids of the server's roles, read back from the database, sorted.
    async fn role_ids(harness: &TestHarness, server: &Server) -> Vec<String> {
        let mut ids: Vec<String> = harness
            .db
            .fetch_server(&server.id)
            .await
            .expect("server")
            .roles
            .into_keys()
            .collect();
        ids.sort();
        ids
    }

    #[test]
    fn creating_a_role_writes_one_role_create_entry() {
        crate::util::test::rt().block_on(creating_a_role_writes_one_role_create_entry_case())
    }

    /// The owner creates a role with a percent-encoded reason header: the
    /// role exists and exactly one `role_create` entry is written, actor = the
    /// session user, target = the new role id, no channel, no count, the name
    /// snapshotted in `new`, the reason decoded. A second role created
    /// without the header logs no reason.
    async fn creating_a_role_writes_one_role_create_entry_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;

        let (status, body) = create_role(
            &harness,
            &owner_session,
            &server,
            "Moderators",
            Some("new%20mod%20team%3A%20rule%201"),
        )
        .await;
        assert_eq!(status, Status::Ok, "body: {body}");
        let role_id = body["id"].as_str().expect("the new role id").to_string();
        let role = harness
            .db
            .fetch_server(&server.id)
            .await
            .expect("server")
            .roles
            .remove(&role_id)
            .expect("the role was created");
        assert_eq!(role.name, "Moderators");

        let entries = audit_log(&harness, &server).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        let entry = &entries[0];
        assert_eq!(entry.server, server.id);
        assert_eq!(entry.action, AuditLogAction::RoleCreate);
        assert_eq!(entry.actor.as_deref(), Some(owner.id.as_str()));
        assert_eq!(entry.target.as_deref(), Some(role_id.as_str()));
        assert_eq!(entry.channel, None);
        assert_eq!(entry.count, None);
        assert_eq!(
            entry.changes,
            vec![AuditLogChange::new(
                "name",
                None,
                Some(AuditValue::String("Moderators".to_string()))
            )]
        );
        assert_eq!(entry.reason.as_deref(), Some("new mod team: rule 1"));

        let (status, body) = create_role(&harness, &owner_session, &server, "Helpers", None).await;
        assert_eq!(status, Status::Ok, "body: {body}");
        let second_id = body["id"].as_str().expect("the new role id").to_string();
        let entries = audit_log(&harness, &server).await;
        assert_eq!(entries.len(), 2, "{entries:?}");
        // Picked by target, not position: two ULIDs minted in the same
        // millisecond do not sort by mint order on the reference driver.
        let second = entries
            .iter()
            .find(|entry| entry.target.as_deref() == Some(second_id.as_str()))
            .expect("an entry for the second role");
        assert_eq!(second.action, AuditLogAction::RoleCreate);
        assert_eq!(second.actor.as_deref(), Some(owner.id.as_str()));
        assert_eq!(
            second.changes,
            vec![AuditLogChange::new(
                "name",
                None,
                Some(AuditValue::String("Helpers".to_string()))
            )]
        );
        assert_eq!(second.reason, None, "no header, no reason");
    }

    #[test]
    fn an_overlong_reason_is_refused_and_no_role_is_created() {
        crate::util::test::rt()
            .block_on(an_overlong_reason_is_refused_and_no_role_is_created_case())
    }

    /// A reason one char over the limit is refused with
    /// FailedValidation/AuditLogReasonTooLong BEFORE the insert: the server's
    /// roles are unchanged and nothing is logged. Mutation: the `validated()?`
    /// moved below `Role::create`.
    async fn an_overlong_reason_is_refused_and_no_role_is_created_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let before = role_ids(&harness, &server).await;

        let reason = "a".repeat(AUDIT_LOG_REASON_MAX_CHARS + 1);
        let (status, body) =
            create_role(&harness, &owner_session, &server, "Too Long", Some(&reason)).await;
        assert_eq!(status, Status::BadRequest, "body: {body}");
        assert_eq!(body["type"], "FailedValidation", "body: {body}");
        assert_eq!(body["error"], "AuditLogReasonTooLong", "body: {body}");

        assert_eq!(
            role_ids(&harness, &server).await,
            before,
            "a refused create must not add a role"
        );
        assert!(audit_log(&harness, &server).await.is_empty());
    }

    #[test]
    fn a_member_without_manage_role_is_refused_and_nothing_is_logged() {
        crate::util::test::rt()
            .block_on(a_member_without_manage_role_is_refused_and_nothing_is_logged_case())
    }

    /// A member lacking ManageRole (not in the server default permissions) is
    /// refused with MissingPermission; no role is created and no entry is
    /// written.
    async fn a_member_without_manage_role_is_refused_and_nothing_is_logged_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        Member::create(&harness.db, &server, &member, None)
            .await
            .expect("member");
        let before = role_ids(&harness, &server).await;

        let (status, body) = create_role(
            &harness,
            &member_session,
            &server,
            "Sneaky",
            Some("not%20allowed"),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "body: {body}");
        assert_eq!(body["type"], "MissingPermission", "body: {body}");

        assert_eq!(
            role_ids(&harness, &server).await,
            before,
            "an unauthorized create must not add a role"
        );
        assert!(audit_log(&harness, &server).await.is_empty());
    }
}
