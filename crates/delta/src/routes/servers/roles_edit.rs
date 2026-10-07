use revolt_database::{
    util::{
        audit_reason::AuditLogReason, permissions::DatabasePermissionQuery, reference::Reference,
    },
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Database, File,
    PartialRole, Role, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Edit Role
///
/// Edit a role by its id.
#[openapi(tag = "Server Permissions")]
#[patch("/<target>/roles/<role_id>", data = "<data>", rank = 1)]
pub async fn edit(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    role_id: String,
    data: Json<v0::DataEditRole>,
    reason: AuditLogReason,
) -> Result<Json<v0::Role>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Validated before anything is read or written, so an over-long reason
    // refuses the whole edit instead of failing after the edit has landed.
    let reason = reason.validated()?;

    let mut server = target.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageRole)?;

    let member_rank = query.get_member_rank().unwrap_or(i64::MIN);

    if let Some(mut role) = server.roles.remove(&role_id) {
        // Prevent us from editing roles above us
        if role.rank <= member_rank {
            return Err(create_error!(NotElevated));
        }

        // The audit log's "before" values. `role.update` applies the edit to
        // `role` in place, so a snapshot taken after it would record the new
        // values as the old ones.
        let role_before_edit = role.clone();

        let v0::DataEditRole {
            name,
            colour,
            hoist,
            icon,
            remove,
            ..
        } = data;

        if remove.contains(&v0::FieldsRole::Icon) {
            if let Some(existing_icon) = &role.icon {
                db.mark_attachment_as_deleted(&existing_icon.id).await?;
            }
        }

        let mut final_icon = None;
        if let Some(icon_id) = icon {
            final_icon = Some(File::use_role_icon(db, &icon_id, &role_id, &user.id).await?);
        }

        let partial = PartialRole {
            name,
            colour,
            hoist,
            icon: final_icon,
            ..Default::default()
        };

        role.update(
            db,
            &server.id,
            partial,
            remove.into_iter().map(Into::into).collect(),
        )
        .await?;

        // Written only once the edit is persisted, and only when it changed
        // something: saving an unchanged role records nothing.
        let changes = role_update_changes(&role_before_edit, &role);
        if !changes.is_empty() {
            AuditLogEntry::record(
                db,
                AuditLogDraft {
                    server: server.id.clone(),
                    actor: Some(user.id.clone()),
                    action: AuditLogAction::RoleUpdate,
                    target: Some(role.id.clone()),
                    changes,
                    reason,
                    ..Default::default()
                },
            )
            .await;
        }

        // No voice permission sync here (AFK S-3 F-7): `DataEditRole` only
        // changes the name, colour, hoist and icon, none of which a grant
        // reads, and `server` no longer holds this role (it was removed from
        // the in-memory document above), so a sync would compute every holder
        // as if they lacked it.

        Ok(Json(role.into()))
    } else {
        Err(create_error!(NotFound))
    }
}

/// The `role_update` changes between a role as loaded before an edit and as
/// persisted after it.
///
/// One change per field whose stored value really differs, so saving an
/// unchanged form records nothing. Value shapes:
/// - `name` (String), `colour` (String), `hoist` (Bool) and `rank` (Int)
///   carry old and new. A colour that was unset has no `old`; a removed one
///   has no `new`.
/// - `icon` carries only `new`: `Bool(true)` when one was set or replaced,
///   `Bool(false)` when it was removed. File ids are not recorded.
///
/// `rank` cannot change through this route today (`DataEditRole::rank` is
/// ignored; ranks move through `roles_edit_positions`, which records its own
/// `role_ranks_update`), so it is listed only should that ever change. The
/// role's permissions are not editable here at all.
fn role_update_changes(before: &Role, after: &Role) -> Vec<AuditLogChange> {
    fn push_if_changed(
        changes: &mut Vec<AuditLogChange>,
        key: &str,
        old: Option<AuditValue>,
        new: Option<AuditValue>,
    ) {
        if old != new {
            changes.push(AuditLogChange::new(key, old, new));
        }
    }

    let icon_id = |role: &Role| role.icon.as_ref().map(|file| file.id.clone());

    let mut changes = Vec::new();
    push_if_changed(
        &mut changes,
        "name",
        Some(AuditValue::String(before.name.clone())),
        Some(AuditValue::String(after.name.clone())),
    );
    push_if_changed(
        &mut changes,
        "colour",
        before.colour.clone().map(AuditValue::String),
        after.colour.clone().map(AuditValue::String),
    );
    push_if_changed(
        &mut changes,
        "hoist",
        Some(AuditValue::Bool(before.hoist)),
        Some(AuditValue::Bool(after.hoist)),
    );
    push_if_changed(
        &mut changes,
        "rank",
        Some(AuditValue::Int(before.rank)),
        Some(AuditValue::Int(after.rank)),
    );
    if icon_id(before) != icon_id(after) {
        changes.push(AuditLogChange::new(
            "icon",
            None,
            Some(AuditValue::Bool(after.icon.is_some())),
        ));
    }

    changes
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{
        fixture,
        util::audit_reason::{AUDIT_LOG_REASON_HEADER, AUDIT_LOG_REASON_MAX_CHARS},
        AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, File, Metadata, PartialRole,
        Role, Server, Session, User,
    };
    use revolt_models::v0;
    use revolt_permissions::OverrideField;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::Value;

    use super::role_update_changes;

    // Every case below runs on the `server_with_many_roles` fixture: user 1
    // is a moderator holding ManageRole at rank 1, user 2 a plain member;
    // "Owner" (rank 0) and "Moderator" (rank 1) are out of the moderator's
    // reach, "Lower Rank 1" (rank 2, no colour, not hoisted) is within it.

    /// PATCH the role with the optional `X-Audit-Log-Reason` header. Returns
    /// the status and the JSON body (Null when there is none).
    async fn edit_role(
        harness: &TestHarness,
        session: &Session,
        server: &Server,
        role_id: &str,
        body: Value,
        reason: Option<&str>,
    ) -> (Status, Value) {
        let mut request = harness
            .client
            .patch(format!("/servers/{}/roles/{}", server.id, role_id))
            .header(ContentType::JSON)
            .body(body.to_string())
            .header(Header::new("x-session-token", session.token.to_string()));
        if let Some(reason) = reason {
            request = request.header(Header::new(AUDIT_LOG_REASON_HEADER, reason.to_string()));
        }
        let response = request.dispatch().await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        (status, serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    async fn audit_log(harness: &TestHarness, server: &Server) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(&server.id, None, 50, None, None)
            .await
            .expect("fetch audit log")
    }

    /// The id of the fixture role called `name`.
    fn role_named(server: &Server, name: &str) -> String {
        server
            .roles
            .iter()
            .find(|(_, role)| role.name == name)
            .map(|(id, _)| id.clone())
            .unwrap_or_else(|| panic!("the fixture has no role `{}`", name))
    }

    /// The role as stored now.
    async fn stored_role(harness: &TestHarness, server: &Server, role_id: &str) -> Role {
        let mut stored = harness
            .db
            .fetch_server(&server.id)
            .await
            .expect("fetch server");
        stored.roles.remove(role_id).expect("the role is stored")
    }

    /// Seed an unclaimed file in the `icons` bucket, as Autumn leaves one
    /// after an upload, so the route can claim it as the role icon.
    async fn upload_icon(harness: &TestHarness, uploader: &User) -> String {
        use iso8601_timestamp::Timestamp;
        let id = ulid::Ulid::new().to_string();
        harness
            .db
            .insert_attachment(&File {
                id: id.clone(),
                tag: "icons".to_string(),
                filename: "icon.png".to_string(),
                hash: None,
                uploaded_at: Some(Timestamp::now_utc()),
                uploader_id: Some(uploader.id.clone()),
                used_for: None,
                deleted: None,
                reported: None,
                metadata: Metadata::File,
                content_type: "image/png".to_string(),
                size: 10,
                message_id: None,
                user_id: None,
                server_id: None,
                object_id: None,
            })
            .await
            .expect("insert icon");
        id
    }

    fn text(value: &str) -> Option<AuditValue> {
        Some(AuditValue::String(value.to_string()))
    }

    #[test]
    fn a_rename_and_recolour_records_one_role_update_with_its_reason() {
        crate::util::test::rt()
            .block_on(a_rename_and_recolour_records_one_role_update_with_its_reason_case())
    }

    /// A moderator renames and recolours a role below them, resending the
    /// hoist it already has, with a percent-encoded reason: exactly one
    /// `role_update` entry, actor = the moderator, target = the role, the
    /// name (old + new) and the newly set colour (new only) as its changes,
    /// the unchanged hoist left out, and the reason decoded.
    async fn a_rename_and_recolour_records_one_role_update_with_its_reason_case() {
        let harness = TestHarness::new().await;
        fixture!(harness.db, "server_with_many_roles",
            moderator user 1
            server server 4);
        let (_, moderator_session) = harness.account_from_user(moderator.id.clone()).await;
        let role_id = role_named(&server, "Lower Rank 1");

        let (status, body) = edit_role(
            &harness,
            &moderator_session,
            &server,
            &role_id,
            json!({ "name": "Renamed", "colour": "#ff0000", "hoist": false }),
            Some("role%20reason"),
        )
        .await;
        assert_eq!(status, Status::Ok, "body: {:?}", body);

        let stored = stored_role(&harness, &server, &role_id).await;
        assert_eq!(stored.name, "Renamed");
        assert_eq!(stored.colour.as_deref(), Some("#ff0000"));

        let entries = audit_log(&harness, &server).await;
        assert_eq!(entries.len(), 1, "{:?}", entries);
        let entry = &entries[0];
        assert_eq!(entry.server, server.id);
        assert_eq!(entry.action, AuditLogAction::RoleUpdate);
        assert_eq!(entry.actor.as_deref(), Some(moderator.id.as_str()));
        assert_eq!(entry.target.as_deref(), Some(role_id.as_str()));
        assert_eq!(entry.channel, None);
        assert_eq!(entry.count, None);
        assert_eq!(entry.reason.as_deref(), Some("role reason"));
        assert_eq!(
            entry.changes,
            vec![
                AuditLogChange::new("name", text("Lower Rank 1"), text("Renamed")),
                AuditLogChange::new("colour", None, text("#ff0000")),
            ]
        );
    }

    #[test]
    fn removing_a_colour_records_its_old_value_only() {
        crate::util::test::rt().block_on(removing_a_colour_records_its_old_value_only_case())
    }

    /// Removing a colour records it with an old value and no new one; a hoist
    /// flip in the same edit records old and new; without the header the
    /// entry has no reason.
    async fn removing_a_colour_records_its_old_value_only_case() {
        let harness = TestHarness::new().await;
        fixture!(harness.db, "server_with_many_roles",
            moderator user 1
            server server 4);
        let (_, moderator_session) = harness.account_from_user(moderator.id.clone()).await;
        let role_id = role_named(&server, "Lower Rank 1");
        harness
            .db
            .update_role(
                &server.id,
                &role_id,
                &PartialRole {
                    colour: Some("#00ff00".to_string()),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("seed a colour");

        let (status, body) = edit_role(
            &harness,
            &moderator_session,
            &server,
            &role_id,
            json!({ "hoist": true, "remove": [v0::FieldsRole::Colour] }),
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "body: {:?}", body);
        assert_eq!(stored_role(&harness, &server, &role_id).await.colour, None);

        let entries = audit_log(&harness, &server).await;
        assert_eq!(entries.len(), 1, "{:?}", entries);
        let entry = &entries[0];
        assert_eq!(entry.action, AuditLogAction::RoleUpdate);
        assert_eq!(entry.target.as_deref(), Some(role_id.as_str()));
        assert_eq!(entry.reason, None, "no header, no reason");
        assert_eq!(
            entry.changes,
            vec![
                AuditLogChange::new("colour", text("#00ff00"), None),
                AuditLogChange::new(
                    "hoist",
                    Some(AuditValue::Bool(false)),
                    Some(AuditValue::Bool(true))
                ),
            ]
        );
    }

    #[test]
    fn setting_and_removing_an_icon_records_only_whether_one_is_set() {
        crate::util::test::rt()
            .block_on(setting_and_removing_an_icon_records_only_whether_one_is_set_case())
    }

    /// Setting an icon records `icon: new = true`, removing it
    /// `icon: new = false`; the file id is never recorded.
    async fn setting_and_removing_an_icon_records_only_whether_one_is_set_case() {
        let harness = TestHarness::new().await;
        fixture!(harness.db, "server_with_many_roles",
            moderator user 1
            server server 4);
        let (_, moderator_session) = harness.account_from_user(moderator.id.clone()).await;
        let role_id = role_named(&server, "Lower Rank 1");
        let icon_id = upload_icon(&harness, &moderator).await;

        let (status, body) = edit_role(
            &harness,
            &moderator_session,
            &server,
            &role_id,
            json!({ "icon": icon_id }),
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "body: {:?}", body);
        let stored = stored_role(&harness, &server, &role_id).await;
        assert!(stored.icon.is_some(), "the icon is set");

        let (status, body) = edit_role(
            &harness,
            &moderator_session,
            &server,
            &role_id,
            json!({ "remove": [v0::FieldsRole::Icon] }),
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "body: {:?}", body);
        let stored = stored_role(&harness, &server, &role_id).await;
        assert!(stored.icon.is_none(), "the icon is removed");

        // Picked by content, not position: two ULIDs minted in the same
        // millisecond do not sort by mint order on the reference driver.
        let entries = audit_log(&harness, &server).await;
        assert_eq!(entries.len(), 2, "{:?}", entries);
        for set in [true, false] {
            let expected = vec![AuditLogChange::new(
                "icon",
                None,
                Some(AuditValue::Bool(set)),
            )];
            let entry = entries
                .iter()
                .find(|entry| entry.changes == expected)
                .unwrap_or_else(|| panic!("no entry with {:?}: {:?}", expected, entries));
            assert_eq!(entry.action, AuditLogAction::RoleUpdate);
            assert_eq!(entry.actor.as_deref(), Some(moderator.id.as_str()));
            assert_eq!(entry.target.as_deref(), Some(role_id.as_str()));
        }
    }

    #[test]
    fn an_edit_that_changes_nothing_records_nothing() {
        crate::util::test::rt().block_on(an_edit_that_changes_nothing_records_nothing_case())
    }

    /// Saving a role unchanged (its own name and hoist, removing a colour and
    /// an icon it does not have) answers 200 and records nothing, reason or
    /// not.
    async fn an_edit_that_changes_nothing_records_nothing_case() {
        let harness = TestHarness::new().await;
        fixture!(harness.db, "server_with_many_roles",
            moderator user 1
            server server 4);
        let (_, moderator_session) = harness.account_from_user(moderator.id.clone()).await;
        let role_id = role_named(&server, "Lower Rank 1");

        let (status, body) = edit_role(
            &harness,
            &moderator_session,
            &server,
            &role_id,
            json!({
                "name": "Lower Rank 1",
                "hoist": false,
                "remove": [v0::FieldsRole::Colour, v0::FieldsRole::Icon]
            }),
            Some("no%20change"),
        )
        .await;
        assert_eq!(status, Status::Ok, "body: {:?}", body);

        let entries = audit_log(&harness, &server).await;
        assert!(entries.is_empty(), "{:?}", entries);
    }

    #[test]
    fn a_refused_edit_records_nothing() {
        crate::util::test::rt().block_on(a_refused_edit_records_nothing_case())
    }

    /// The moderator may not edit a role ranked at or above their own (the
    /// "Owner" role above them, their own "Moderator" role): NotElevated, the
    /// role keeps its name. A member without ManageRole is refused with
    /// MissingPermission. No refusal records anything.
    async fn a_refused_edit_records_nothing_case() {
        let harness = TestHarness::new().await;
        fixture!(harness.db, "server_with_many_roles",
            moderator user 1
            member user 2
            server server 4);
        let (_, moderator_session) = harness.account_from_user(moderator.id.clone()).await;
        let (_, member_session) = harness.account_from_user(member.id.clone()).await;

        for name in ["Owner", "Moderator"] {
            let role_id = role_named(&server, name);
            let (status, body) = edit_role(
                &harness,
                &moderator_session,
                &server,
                &role_id,
                json!({ "name": "Hijacked" }),
                Some("not%20allowed"),
            )
            .await;
            assert_eq!(status, Status::Forbidden, "{}: {:?}", name, body);
            assert_eq!(body["type"], "NotElevated", "{}: {:?}", name, body);
            assert_eq!(stored_role(&harness, &server, &role_id).await.name, name);
        }

        let role_id = role_named(&server, "Lower Rank 1");
        let (status, body) = edit_role(
            &harness,
            &member_session,
            &server,
            &role_id,
            json!({ "name": "Hijacked" }),
            Some("not%20allowed"),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "body: {:?}", body);
        assert_eq!(body["type"], "MissingPermission", "body: {:?}", body);
        assert_eq!(
            stored_role(&harness, &server, &role_id).await.name,
            "Lower Rank 1"
        );

        let entries = audit_log(&harness, &server).await;
        assert!(entries.is_empty(), "{:?}", entries);
    }

    #[test]
    fn an_overlong_reason_is_refused_and_the_role_is_unchanged() {
        crate::util::test::rt()
            .block_on(an_overlong_reason_is_refused_and_the_role_is_unchanged_case())
    }

    /// A reason one char over the limit is FailedValidation /
    /// AuditLogReasonTooLong BEFORE the edit: the role keeps its name and
    /// colour and nothing is recorded. Mutation: the `validated()?` moved
    /// below `role.update`.
    async fn an_overlong_reason_is_refused_and_the_role_is_unchanged_case() {
        let harness = TestHarness::new().await;
        fixture!(harness.db, "server_with_many_roles",
            moderator user 1
            server server 4);
        let (_, moderator_session) = harness.account_from_user(moderator.id.clone()).await;
        let role_id = role_named(&server, "Lower Rank 1");

        let reason = "a".repeat(AUDIT_LOG_REASON_MAX_CHARS + 1);
        let (status, body) = edit_role(
            &harness,
            &moderator_session,
            &server,
            &role_id,
            json!({ "name": "Renamed", "colour": "#ff0000" }),
            Some(&reason),
        )
        .await;
        assert_eq!(status, Status::BadRequest, "body: {:?}", body);
        assert_eq!(body["type"], "FailedValidation", "body: {:?}", body);
        assert_eq!(body["error"], "AuditLogReasonTooLong", "body: {:?}", body);

        let stored = stored_role(&harness, &server, &role_id).await;
        assert_eq!(stored.name, "Lower Rank 1");
        assert_eq!(stored.colour, None);

        let entries = audit_log(&harness, &server).await;
        assert!(entries.is_empty(), "{:?}", entries);
    }

    /// The pure diff: an identical role yields no change, and `rank` (which
    /// the route cannot reach today) is typed as an Int with old and new.
    #[test]
    fn role_update_changes_lists_only_what_differs() {
        let before = Role {
            id: "role".to_string(),
            name: "Role".to_string(),
            permissions: OverrideField { a: 0, d: 0 },
            colour: None,
            hoist: false,
            rank: 2,
            icon: None,
        };
        assert!(role_update_changes(&before, &before.clone()).is_empty());

        let after = Role {
            rank: 3,
            ..before.clone()
        };
        assert_eq!(
            role_update_changes(&before, &after),
            vec![AuditLogChange::new(
                "rank",
                Some(AuditValue::Int(2)),
                Some(AuditValue::Int(3))
            )]
        );
    }
}
