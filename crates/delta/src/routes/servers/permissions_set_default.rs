use revolt_database::{
    util::{
        audit_reason::AuditLogReason, permissions::DatabasePermissionQuery,
        protected_access::reconcile_server, reference::Reference,
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
    // stays the route's last step before the answer but for the kept
    // reconcile result. The @everyone default
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

    // Protected channels 6.3 "Hooks" (S2-D11): release the seats this edit
    // took ViewChannel from, in every protected channel of the server. Run
    // on every write, a re-save included, so retrying the same edit repairs
    // a pass that failed. The result is kept until the sync has run and a
    // failure is logged at once, so a failing sync never hides it.
    let reconciled = reconcile_server(db, &server.id).await;
    if let Err(error) = &reconciled {
        log::error!(
            "protected channel reconcile failed after a default permission edit: server={}: {:?}",
            server.id,
            error
        );
    }

    // Every channel is tried before the first failure is answered (AFK S-3
    // D-6); `server` already carries the new default permissions.
    sync_server_voice_permissions(db, voice_client, &server, None).await?;

    // The reconcile's own error is answered once the sync has run; the new
    // default stands.
    reconciled?;

    Ok(Json(server.into()))
}

#[cfg(test)]
mod test {
    use crate::routes::servers::roles_edit_positions::protected_hook::{
        end_call, hook_world, plain_world,
    };
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
    /// Protected channels 6.3 "Hooks" (S2-D11) put the reconcile between the
    /// entry and the sync and answer its kept result after the sync, so this
    /// pin gained those two statements. Mutations: the record moved below
    /// the sync, or the validation below the write; the reconcile moved
    /// below the sync.
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
        let reconcile = statement_at(
            &code,
            "letreconciled=reconcile_server(db,&server.id).await;",
        );
        let kept = statement_at(&code, "reconciled?;");

        assert!(validate < write, "validate before the write: {}", code);
        assert!(write < record, "record after the write: {}", code);
        assert!(record < sync, "record before the sync: {}", code);
        assert!(record < reconcile, "reconcile after the entry: {}", code);
        assert!(reconcile < sync, "reconcile before the sync: {}", code);
        assert!(
            sync < kept,
            "answer the kept result after the sync: {}",
            code
        );
    }

    // ---- protected channels: the reconciler hook (6.3 "Hooks", S2-D11) ----

    const VIEW: i64 = ChannelPermission::ViewChannel as i64;

    #[test]
    fn a_default_without_view_channel_releases_the_seat_of_a_member_without_roles() {
        crate::util::test::rt().block_on(
            a_default_without_view_channel_releases_the_seat_of_a_member_without_roles_case(),
        )
    }

    /// The owner drops ViewChannel from the @everyone default: the hook
    /// releases the seat of the member, who holds no role (`AccessLost`, one
    /// `ProtectedSeatRelease` entry, the seats event on the channel topic),
    /// and the owner, the list signer, keeps theirs. A call the voice sync
    /// cannot reach answers its `UnknownNode`, and the seat is released all
    /// the same: the reconcile runs BEFORE the sync. Controls: the hook
    /// removed; the reconcile moved below the sync.
    async fn a_default_without_view_channel_releases_the_seat_of_a_member_without_roles_case() {
        let mut world = hook_world().await;
        assert!(!world.member_lacks_access().await, "precondition: M views");
        let blind = world.server().await.default_permissions & !VIEW;
        let call = world.unreachable_call().await;

        let (status, body) = set_default(
            &world.harness,
            &world.server_id,
            &world.owner_session,
            blind,
            None,
        )
        .await;
        end_call(&call).await;
        assert_eq!(status, Status::BadRequest, "{}", body);
        assert!(body.contains("UnknownNode"), "{}", body);
        assert_eq!(
            stored_default(&world.harness, &world.server_id).await,
            blind
        );
        assert!(world.member_lacks_access().await, "M lost ViewChannel");
        world.assert_member_released().await;
    }

    #[test]
    fn a_failed_reconcile_still_syncs_then_answers_its_error_after_the_write() {
        crate::util::test::rt()
            .block_on(a_failed_reconcile_still_syncs_then_answers_its_error_after_the_write_case())
    }

    /// The reconcile fails (the protected channel's row is stored as a
    /// SavedMessages channel): the new default stands and is logged, the
    /// voice sync still runs (with a call it cannot reach, its own
    /// `UnknownNode` is the answer), and without such a call the
    /// reconcile's own error is answered unchanged (`InternalError`).
    /// Re-saving the same default, which logs nothing, releases the seat
    /// once the row is back. Controls: the reconcile's error returned
    /// before the sync; its error dropped; the hook run only on a change.
    async fn a_failed_reconcile_still_syncs_then_answers_its_error_after_the_write_case() {
        let mut world = hook_world().await;
        let blind = world.server().await.default_permissions & !VIEW;
        let parked = world.break_reconcile().await;

        // The sync ran after the failed reconcile: its error answers first
        let call = world.unreachable_call().await;
        let (status, body) = set_default(
            &world.harness,
            &world.server_id,
            &world.owner_session,
            blind,
            Some("hook"),
        )
        .await;
        end_call(&call).await;
        assert_eq!(status, Status::BadRequest, "{}", body);
        assert!(body.contains("UnknownNode"), "{}", body);
        assert_eq!(
            stored_default(&world.harness, &world.server_id).await,
            blind
        );
        assert_eq!(
            permission_entries(&world.harness, &world.server_id)
                .await
                .len(),
            1
        );

        // No call: the kept failure is answered, the write is not undone
        let (status, body) = set_default(
            &world.harness,
            &world.server_id,
            &world.owner_session,
            blind,
            None,
        )
        .await;
        assert_eq!(status, Status::InternalServerError, "{}", body);
        assert!(body.contains("InternalError"), "{}", body);
        assert_eq!(
            stored_default(&world.harness, &world.server_id).await,
            blind
        );
        assert!(
            world.seat(&world.member.id).await.is_active(),
            "a failed reconcile released nothing"
        );
        assert!(world.releases().await.is_empty());

        // Repaired: the same re-save releases the seat
        world.repair(&parked).await;
        let (status, body) = set_default(
            &world.harness,
            &world.server_id,
            &world.owner_session,
            blind,
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "{}", body);
        assert_eq!(
            permission_entries(&world.harness, &world.server_id)
                .await
                .len(),
            1,
            "the re-saves are not logged"
        );
        world.assert_member_released().await;
    }

    #[test]
    fn without_a_protected_channel_the_hook_changes_nothing() {
        crate::util::test::rt()
            .block_on(without_a_protected_channel_the_hook_changes_nothing_case())
    }

    /// No protected channel in the server: the same edit answers as before
    /// S2, with no seat entry and no seats event.
    async fn without_a_protected_channel_the_hook_changes_nothing_case() {
        let mut world = plain_world().await;
        let blind = world.server().await.default_permissions & !VIEW;

        let (status, body) = set_default(
            &world.harness,
            &world.server_id,
            &world.owner_session,
            blind,
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "{}", body);
        assert_eq!(
            stored_default(&world.harness, &world.server_id).await,
            blind
        );
        assert_eq!(
            permission_entries(&world.harness, &world.server_id)
                .await
                .len(),
            1
        );
        assert!(world.releases().await.is_empty());
        world.assert_no_seats_event().await;
    }
}
