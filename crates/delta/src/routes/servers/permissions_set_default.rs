use revolt_database::{
    util::{
        audit_reason::AuditLogReason, permissions::DatabasePermissionQuery, reference::Reference,
    },
    voice::{sync_server_voice_permissions, VoiceClient},
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Database,
    PartialServer, User,
};
use revolt_models::v0;
use revolt_permissions::{
    calculate_server_permissions, ChannelPermission, DataPermissionsValue, Override,
};
use revolt_result::Result;
use rocket::{serde::json::Json, State};

/// # Set Default Permission
///
/// Sets permissions for the default role in this server.
#[openapi(tag = "Server Permissions")]
#[put("/<target>/permissions/default", data = "<data>", rank = 1)]
pub async fn set_default_server_permissions(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
    data: Json<DataPermissionsValue>,
    reason: AuditLogReason,
) -> Result<Json<v0::Server>> {
    let data = data.into_inner();

    // Validated before anything is read or written, so an over-long reason
    // refuses the change instead of failing after it has landed.
    let reason = reason.validated()?;

    let mut server = target.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    let permissions = calculate_server_permissions(&mut query).await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::ManagePermissions)?;

    // Ensure we have permissions to grant these permissions forwards
    permissions
        .throw_permission_override(
            None,
            &Override {
                allow: data.permissions,
                deny: 0,
            },
        )
        .await?;

    // The audit entry's `old` value, read before the write replaces it.
    let previous_default = server.default_permissions;

    server
        .update(
            db,
            PartialServer {
                default_permissions: Some(data.permissions as i64),
                ..Default::default()
            },
            vec![],
        )
        .await?;

    // Recorded once the write is durable and before the voice sync, which
    // stays the route's last step before the answer. The @everyone default
    // is ONE permission value, not an allow/deny override like a role's, so
    // the entry carries an `allow` change only and never a `deny` key.
    // Re-saving the same value records nothing.
    if previous_default != server.default_permissions {
        AuditLogEntry::record(
            db,
            AuditLogDraft {
                server: server.id.clone(),
                actor: Some(user.id.clone()),
                action: AuditLogAction::ServerPermissionsUpdate,
                target: Some("default".to_string()),
                changes: vec![AuditLogChange::new(
                    "allow",
                    Some(AuditValue::Int(previous_default)),
                    Some(AuditValue::Int(server.default_permissions)),
                )],
                reason,
                ..Default::default()
            },
        )
        .await;
    }

    // Every channel is tried before the first failure is answered (AFK S-3
    // D-6); `server` already carries the new default permissions.
    sync_server_voice_permissions(db, voice_client, &server, None).await?;

    Ok(Json(server.into()))
}

#[cfg(test)]
mod test {
    use crate::util::test::{statement_at, without_comments, without_whitespace, TestHarness};
    use revolt_database::{
        AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, Member, PartialServer, Session,
    };
    use revolt_permissions::ChannelPermission;
    use rocket::http::{ContentType, Header, Status};

    /// PUT the server's default permissions with the optional
    /// `X-Audit-Log-Reason` header. Returns the status and the response body.
    async fn set_default(
        harness: &TestHarness,
        server_id: &str,
        session: &Session,
        permissions: i64,
        reason: Option<&str>,
    ) -> (Status, String) {
        let mut request = harness
            .client
            .put(format!("/servers/{}/permissions/default", server_id))
            .header(ContentType::JSON)
            .body(json!({ "permissions": permissions }).to_string())
            .header(Header::new("x-session-token", session.token.to_string()));
        if let Some(reason) = reason {
            request = request.header(Header::new("X-Audit-Log-Reason", reason.to_string()));
        }

        let response = request.dispatch().await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// The `server_permissions_update` entries of `server_id`. Selected by
    /// action, never by position: entries minted in the same millisecond
    /// have no guaranteed order.
    async fn permission_entries(harness: &TestHarness, server_id: &str) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(server_id, None, 50, None, None)
            .await
            .expect("audit log")
            .into_iter()
            .filter(|entry| entry.action == AuditLogAction::ServerPermissionsUpdate)
            .collect()
    }

    async fn stored_default(harness: &TestHarness, server_id: &str) -> i64 {
        harness
            .db
            .fetch_server(server_id)
            .await
            .expect("server")
            .default_permissions
    }

    /// A change writes exactly one entry: the actor, the literal `"default"`
    /// target, no channel, a single `allow` change with the old and new
    /// values (no `deny` key), and the percent-decoded reason. Saving the
    /// same value again writes nothing more.
    #[test]
    fn a_change_records_one_entry() {
        crate::util::test::rt().block_on(a_change_records_one_entry_case())
    }

    async fn a_change_records_one_entry_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;

        let old = server.default_permissions;
        let new = old ^ ChannelPermission::React as i64;
        assert_ne!(old, new, "the change is real");

        let (status, body) = set_default(
            &harness,
            &server.id,
            &owner_session,
            new,
            Some("permission%20reason"),
        )
        .await;
        assert_eq!(status, Status::Ok, "{}", body);
        assert_eq!(stored_default(&harness, &server.id).await, new);

        let entries = permission_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), 1, "{:?}", entries);
        let entry = &entries[0];
        assert_eq!(entry.server, server.id);
        assert_eq!(entry.actor, Some(owner.id.clone()));
        assert_eq!(entry.target, Some("default".to_string()));
        assert_eq!(entry.channel, None);
        assert_eq!(entry.count, None);
        assert_eq!(
            entry.changes,
            vec![AuditLogChange::new(
                "allow",
                Some(AuditValue::Int(old)),
                Some(AuditValue::Int(new)),
            )]
        );
        assert_eq!(entry.reason, Some("permission reason".to_string()));

        // Unchanged: answered, nothing recorded.
        let (status, body) = set_default(&harness, &server.id, &owner_session, new, None).await;
        assert_eq!(status, Status::Ok, "{}", body);
        assert_eq!(permission_entries(&harness, &server.id).await.len(), 1);
    }

    /// Refused changes write no entry: a member without ManagePermissions,
    /// an account that is not a member, and a member who holds
    /// ManagePermissions but tries to grant ManageServer, which it lacks.
    #[test]
    fn refused_changes_record_nothing() {
        crate::util::test::rt().block_on(refused_changes_record_nothing_case())
    }

    async fn refused_changes_record_nothing_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, member_session, member_user) = harness.new_user().await;
        let (_, outsider_session, _) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        Member::create(&harness.db, &server, &member_user, None)
            .await
            .expect("`Member`");

        let before = server.default_permissions;
        assert_eq!(
            before & ChannelPermission::ManagePermissions as i64,
            0,
            "members start without ManagePermissions"
        );
        for session in [&member_session, &outsider_session] {
            let (status, body) = set_default(
                &harness,
                &server.id,
                session,
                before ^ ChannelPermission::React as i64,
                Some("hostile"),
            )
            .await;
            assert_eq!(status, Status::Forbidden, "{}", body);
        }
        assert_eq!(stored_default(&harness, &server.id).await, before);

        // Hand @everyone ManagePermissions directly, then try to escalate.
        let managing = before | ChannelPermission::ManagePermissions as i64;
        harness
            .db
            .update_server(
                &server.id,
                &PartialServer {
                    default_permissions: Some(managing),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("the default is updated");

        let (status, body) = set_default(
            &harness,
            &server.id,
            &member_session,
            managing | ChannelPermission::ManageServer as i64,
            Some("hostile"),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "{}", body);
        assert!(body.contains("CannotGiveMissingPermissions"), "{}", body);
        assert_eq!(stored_default(&harness, &server.id).await, managing);

        assert_eq!(permission_entries(&harness, &server.id).await, vec![]);
    }

    /// A 513-char reason is refused with `AuditLogReasonTooLong` and the
    /// default does not change.
    #[test]
    fn an_overlong_reason_refuses_the_change() {
        crate::util::test::rt().block_on(an_overlong_reason_refuses_the_change_case())
    }

    async fn an_overlong_reason_refuses_the_change_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;

        let before = server.default_permissions;
        let too_long = "a".repeat(513);
        let (status, body) = set_default(
            &harness,
            &server.id,
            &owner_session,
            before ^ ChannelPermission::React as i64,
            Some(too_long.as_str()),
        )
        .await;
        assert_eq!(status, Status::BadRequest, "{}", body);
        assert!(body.contains("AuditLogReasonTooLong"), "{}", body);
        assert_eq!(stored_default(&harness, &server.id).await, before);
        assert_eq!(permission_entries(&harness, &server.id).await, vec![]);
    }

    /// The route's order: the reason is validated before the write, the
    /// entry is recorded after the write and before the voice sync.
    /// Mutation: the record moved below the sync, or the validation below
    /// the write.
    #[test]
    fn the_reason_is_validated_first_and_recorded_between_write_and_sync() {
        let source = include_str!("permissions_set_default.rs");
        let shipping = &source[..source.find("#[cfg(test)]").expect("a test module")];
        let code = without_whitespace(&without_comments(shipping));

        let validate = statement_at(&code, "letreason=reason.validated()?;");
        assert_eq!(code.matches("server.update(").count(), 1, "{}", code);
        let write = code.find("server.update(").expect("counted above");
        assert_eq!(
            code.matches("AuditLogEntry::record(").count(),
            1,
            "{}",
            code
        );
        let record = code.find("AuditLogEntry::record(").expect("counted above");
        let sync = statement_at(
            &code,
            "sync_server_voice_permissions(db,voice_client,&server,None).await?;",
        );

        assert!(validate < write, "validate before the write: {}", code);
        assert!(write < record, "record after the write: {}", code);
        assert!(record < sync, "record before the sync: {}", code);
    }
}
