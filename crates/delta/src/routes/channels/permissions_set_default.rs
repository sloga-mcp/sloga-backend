use revolt_database::util::audit_reason::AuditLogReason;
use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    voice::{sync_voice_permissions, VoiceClient},
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Channel, Database,
    PartialChannel, User,
};
use revolt_models::v0::{self, DataDefaultChannelPermissions};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, OverrideField};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Set Default Permission
///
/// Sets permissions for the default role in this channel.
///
/// Channel must be a `Group` or `TextChannel`.
#[openapi(tag = "Channel Permissions")]
#[put("/<target>/permissions/default", data = "<data>", rank = 1)]
pub async fn set_default_channel_permissions(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataDefaultChannelPermissions>,
    reason: AuditLogReason,
) -> Result<Json<v0::Channel>> {
    let data = data.into_inner();

    // Before anything is written: a too-long reason must never surface as a
    // 400 after the default overwrite has already changed.
    let reason = reason.validated()?;

    let mut channel = target.as_channel(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::ManagePermissions)?;

    match &channel {
        // Groups are not server channels and are never audit-logged.
        Channel::Group { .. } => {
            if let DataDefaultChannelPermissions::Value { permissions } = data {
                channel
                    .update(
                        db,
                        PartialChannel {
                            permissions: Some(permissions as i64),
                            ..Default::default()
                        },
                        vec![],
                    )
                    .await?;
            } else {
                return Err(create_error!(InvalidOperation));
            }
        }
        Channel::TextChannel {
            server: server_id,
            default_permissions,
            ..
        }
        | Channel::Forum {
            server: server_id,
            default_permissions,
            ..
        } => {
            if let DataDefaultChannelPermissions::Field { permissions: field } = data {
                permissions
                    .throw_permission_override(default_permissions.map(|x| x.into()), &field)
                    .await?;

                // Snapshot for the audit entry, taken before the write. A
                // channel with no default overwrite yet records no old value
                // (as the channel role-overwrite route does).
                let server_id = server_id.clone();
                let old_default = *default_permissions;
                let new_default: OverrideField = field.into();

                channel
                    .update(
                        db,
                        PartialChannel {
                            default_permissions: Some(new_default),
                            ..Default::default()
                        },
                        vec![],
                    )
                    .await?;

                // After the write, before the voice sync below (which can
                // still fail after the overwrite has landed). Only a real
                // change is logged: an identical re-PUT writes no entry, while
                // a first default (no previous one) always counts.
                if old_default != Some(new_default) {
                    AuditLogEntry::record(
                        db,
                        AuditLogDraft {
                            server: server_id,
                            actor: Some(user.id.clone()),
                            action: AuditLogAction::ChannelOverwriteUpdate,
                            target: Some("default".to_string()),
                            channel: Some(channel.id().to_string()),
                            changes: vec![
                                AuditLogChange::new(
                                    "allow",
                                    old_default.map(|field| AuditValue::Int(field.a)),
                                    Some(AuditValue::Int(new_default.a)),
                                ),
                                AuditLogChange::new(
                                    "deny",
                                    old_default.map(|field| AuditValue::Int(field.d)),
                                    Some(AuditValue::Int(new_default.d)),
                                ),
                            ],
                            reason,
                            ..Default::default()
                        },
                    )
                    .await;
                }
            } else {
                return Err(create_error!(InvalidOperation));
            }
        }
        _ => return Err(create_error!(InvalidOperation)),
    }

    let server = match channel.server() {
        Some(server_id) => Some(Reference::from_unchecked(server_id).as_server(db).await?),
        None => None
    };

    sync_voice_permissions(db, voice_client, &channel, server.as_ref(), None).await?;

    Ok(Json(channel.into()))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{
        mongodb::bson::{doc, Document},
        AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, Channel, Database, Member,
        PartialChannel, PartialMember, Server, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::{json, Value};

    /// The default overwrite every server-channel test starts from, seeded
    /// straight into the database so the route writes the only entry.
    const OLD: OverrideField = OverrideField {
        a: ChannelPermission::SendMessage as i64 | ChannelPermission::React as i64,
        d: ChannelPermission::Masquerade as i64,
    };

    /// The overwrite the tests ask for: every field differs from `OLD`.
    const NEW: OverrideField = OverrideField {
        a: ChannelPermission::SendMessage as i64 | ChannelPermission::UploadFiles as i64,
        d: ChannelPermission::Masquerade as i64 | ChannelPermission::SendEmbeds as i64,
    };

    fn field_body(value: OverrideField) -> Value {
        json!({ "permissions": { "allow": value.a, "deny": value.d } })
    }

    async fn put_default(
        harness: &TestHarness,
        token: &str,
        channel: &str,
        body: Value,
        reason: Option<&str>,
    ) -> (Status, String) {
        let mut request = harness
            .client
            .put(format!("/channels/{channel}/permissions/default"))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(body.to_string());
        if let Some(reason) = reason {
            request = request.header(Header::new("X-Audit-Log-Reason", reason.to_string()));
        }

        let response = request.dispatch().await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        (status, body)
    }

    fn error_body(body: &str) -> Value {
        serde_json::from_str(body).expect("error body")
    }

    /// The stored default overwrite of a server text channel.
    async fn stored_default(harness: &TestHarness, channel: &str) -> Option<OverrideField> {
        match harness.db.fetch_channel(channel).await.expect("channel") {
            Channel::TextChannel {
                default_permissions,
                ..
            } => default_permissions,
            other => panic!("expected a text channel, got {:?}", other),
        }
    }

    async fn server_entries(harness: &TestHarness, server: &str) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(server, None, 50, None, None)
            .await
            .expect("audit log")
    }

    /// How many entries, in ANY server, name `actor` as the actor. A group
    /// has no server to read back by, so a stray entry would land under an
    /// id the test cannot guess; counting by actor finds it anywhere.
    async fn entries_by_actor(harness: &TestHarness, actor: &str) -> u64 {
        match &harness.db {
            Database::Reference(reference) => reference
                .server_audit_log
                .lock()
                .await
                .values()
                .filter(|entry| entry.actor.as_deref() == Some(actor))
                .count() as u64,
            Database::MongoDb(mongo) => mongo
                .col::<Document>("server_audit_log")
                .count_documents(doc! { "actor": actor })
                .await
                .expect("count"),
        }
    }

    struct ServerFixture {
        server: Server,
        channel: String,
        owner: User,
        owner_token: String,
    }

    /// An owner's server with one text channel whose default overwrite is
    /// `seed` (written straight to the database, no route, no entry).
    async fn server_fixture(harness: &TestHarness, seed: Option<OverrideField>) -> ServerFixture {
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let channel = harness.new_channel(&server).await;
        if let Some(seed) = seed {
            harness
                .db
                .update_channel(
                    channel.id(),
                    &PartialChannel {
                        default_permissions: Some(seed),
                        ..Default::default()
                    },
                    vec![],
                )
                .await
                .expect("seed the default overwrite");
        }
        assert_eq!(stored_default(harness, channel.id()).await, seed);

        ServerFixture {
            server,
            channel: channel.id().to_string(),
            owner,
            owner_token: owner_session.token,
        }
    }

    fn overwrite_changes(old: Option<OverrideField>, new: OverrideField) -> Vec<AuditLogChange> {
        vec![
            AuditLogChange::new(
                "allow",
                old.map(|field| AuditValue::Int(field.a)),
                Some(AuditValue::Int(new.a)),
            ),
            AuditLogChange::new(
                "deny",
                old.map(|field| AuditValue::Int(field.d)),
                Some(AuditValue::Int(new.d)),
            ),
        ]
    }

    #[test]
    fn a_server_channel_default_change_writes_one_entry() {
        crate::util::test::rt().block_on(a_server_channel_default_change_writes_one_entry_case())
    }

    /// The owner changes a server channel's default overwrite: one
    /// `channel_overwrite_update` entry naming the owner, the literal target
    /// `"default"`, the channel, the old and new allow / deny as Int, and the
    /// percent-decoded reason.
    async fn a_server_channel_default_change_writes_one_entry_case() {
        let harness = TestHarness::new().await;
        let f = server_fixture(&harness, Some(OLD)).await;

        let (status, body) = put_default(
            &harness,
            &f.owner_token,
            &f.channel,
            field_body(NEW),
            Some("lock%20down%20uploads"),
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(stored_default(&harness, &f.channel).await, Some(NEW));

        let entries = server_entries(&harness, &f.server.id).await;
        let overwrites: Vec<&AuditLogEntry> = entries
            .iter()
            .filter(|entry| {
                entry.action == AuditLogAction::ChannelOverwriteUpdate
                    && entry.target.as_deref() == Some("default")
            })
            .collect();
        assert_eq!(overwrites.len(), 1, "{entries:?}");
        assert_eq!(entries.len(), 1, "nothing else is logged: {entries:?}");

        let entry = overwrites[0];
        assert_eq!(entry.server, f.server.id);
        assert_eq!(entry.actor.as_deref(), Some(f.owner.id.as_str()));
        assert_eq!(entry.channel.as_deref(), Some(f.channel.as_str()));
        assert_eq!(entry.changes, overwrite_changes(Some(OLD), NEW));
        assert_eq!(entry.count, None);
        assert_eq!(entry.reason.as_deref(), Some("lock down uploads"));
    }

    #[test]
    fn a_first_default_overwrite_records_no_old_value() {
        crate::util::test::rt().block_on(a_first_default_overwrite_records_no_old_value_case())
    }

    /// A channel with no default overwrite yet: both keys carry the new
    /// value and no old one. No reason header: the entry has none.
    async fn a_first_default_overwrite_records_no_old_value_case() {
        let harness = TestHarness::new().await;
        let f = server_fixture(&harness, None).await;

        let (status, body) =
            put_default(&harness, &f.owner_token, &f.channel, field_body(NEW), None).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(stored_default(&harness, &f.channel).await, Some(NEW));

        let entries = server_entries(&harness, &f.server.id).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        let entry = &entries[0];
        assert_eq!(entry.action, AuditLogAction::ChannelOverwriteUpdate);
        assert_eq!(entry.target.as_deref(), Some("default"));
        assert_eq!(entry.changes, overwrite_changes(None, NEW));
        assert_eq!(entry.reason, None);
    }

    #[test]
    fn an_identical_re_put_records_nothing_more() {
        crate::util::test::rt().block_on(an_identical_re_put_records_nothing_more_case())
    }

    /// The owner sets a new default (one entry), then PUTs the very same
    /// default again: the second PUT succeeds but changes nothing, so the
    /// entry count stays at one. Re-PUTting the seeded default as the first
    /// call is a no-op too and is checked first.
    async fn an_identical_re_put_records_nothing_more_case() {
        let harness = TestHarness::new().await;
        let f = server_fixture(&harness, Some(OLD)).await;

        let (status, body) = put_default(
            &harness,
            &f.owner_token,
            &f.channel,
            field_body(OLD),
            Some("same%20as%20before"),
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(stored_default(&harness, &f.channel).await, Some(OLD));
        let entries = server_entries(&harness, &f.server.id).await;
        assert!(entries.is_empty(), "{:?}", entries);

        let (status, body) =
            put_default(&harness, &f.owner_token, &f.channel, field_body(NEW), None).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(server_entries(&harness, &f.server.id).await.len(), 1);

        let (status, body) = put_default(
            &harness,
            &f.owner_token,
            &f.channel,
            field_body(NEW),
            Some("again"),
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(stored_default(&harness, &f.channel).await, Some(NEW));

        let entries = server_entries(&harness, &f.server.id).await;
        assert_eq!(entries.len(), 1, "the re-PUT adds nothing: {entries:?}");
        assert_eq!(entries[0].changes, overwrite_changes(Some(OLD), NEW));
        assert_eq!(entries[0].reason, None, "the entry is the first PUT's");
        assert_eq!(entries_by_actor(&harness, &f.owner.id).await, 1);
    }

    #[test]
    fn a_group_default_change_records_nothing() {
        crate::util::test::rt().block_on(a_group_default_change_records_nothing_case())
    }

    /// The group owner sets the group's permissions: the change lands, but a
    /// group is not a server channel and is never audit-logged.
    async fn a_group_default_change_records_nothing_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: "Test Group".to_string(),
                ..Default::default()
            },
            user.id.clone(),
        )
        .await
        .expect("Failed to create group");

        let wanted = ChannelPermission::SendMessage as u64 | ChannelPermission::React as u64;
        let (status, body) = put_default(
            &harness,
            &session.token,
            group.id(),
            json!({ "permissions": wanted }),
            Some("group%20settings"),
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        match harness.db.fetch_channel(group.id()).await.expect("group") {
            Channel::Group { permissions, .. } => assert_eq!(permissions, Some(wanted as i64)),
            other => panic!("expected a group, got {:?}", other),
        }

        assert_eq!(entries_by_actor(&harness, &user.id).await, 0);
    }

    #[test]
    fn a_member_without_manage_permissions_records_nothing() {
        crate::util::test::rt().block_on(a_member_without_manage_permissions_records_nothing_case())
    }

    /// A plain member lacks ManagePermissions: refused, the overwrite is
    /// unchanged, and nothing is logged.
    async fn a_member_without_manage_permissions_records_nothing_case() {
        let harness = TestHarness::new().await;
        let f = server_fixture(&harness, Some(OLD)).await;
        let (_, member_session, member) = harness.new_user().await;
        Member::create(&harness.db, &f.server, &member, None)
            .await
            .expect("member");

        let (status, body) = put_default(
            &harness,
            &member_session.token,
            &f.channel,
            field_body(NEW),
            Some("not%20allowed"),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "{body}");
        assert_eq!(error_body(&body)["type"], "MissingPermission");

        assert_eq!(stored_default(&harness, &f.channel).await, Some(OLD));
        let entries = server_entries(&harness, &f.server.id).await;
        assert!(entries.is_empty(), "{:?}", entries);
        assert_eq!(entries_by_actor(&harness, &member.id).await, 0);
    }

    #[test]
    fn granting_a_missing_permission_records_nothing() {
        crate::util::test::rt().block_on(granting_a_missing_permission_records_nothing_case())
    }

    /// A moderator holds ManagePermissions through a role but not
    /// ManageMessages, and tries to grant ManageMessages to everyone: the
    /// override check refuses it after the permission gate, the overwrite is
    /// unchanged, and nothing is logged.
    async fn granting_a_missing_permission_records_nothing_case() {
        let harness = TestHarness::new().await;
        let f = server_fixture(&harness, Some(OLD)).await;
        let (_, moderator_session, moderator) = harness.new_user().await;
        Member::create(&harness.db, &f.server, &moderator, None)
            .await
            .expect("member");

        let role = harness
            .new_role(
                &f.server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::ManagePermissions as i64,
                    d: 0,
                }),
            )
            .await;
        let mut moderator_member = harness
            .db
            .fetch_member(&f.server.id, &moderator.id)
            .await
            .expect("member");
        moderator_member
            .update(
                &harness.db,
                PartialMember {
                    roles: Some(vec![role.id.clone()]),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("role grant");

        let escalation = OverrideField {
            a: OLD.a | ChannelPermission::ManageMessages as i64,
            d: OLD.d,
        };
        let (status, body) = put_default(
            &harness,
            &moderator_session.token,
            &f.channel,
            field_body(escalation),
            Some("escalate"),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "{body}");
        assert_eq!(error_body(&body)["type"], "CannotGiveMissingPermissions");

        assert_eq!(stored_default(&harness, &f.channel).await, Some(OLD));
        let entries = server_entries(&harness, &f.server.id).await;
        assert!(entries.is_empty(), "{:?}", entries);
        assert_eq!(entries_by_actor(&harness, &moderator.id).await, 0);
    }

    #[test]
    fn a_group_shaped_body_on_a_server_channel_records_nothing() {
        crate::util::test::rt()
            .block_on(a_group_shaped_body_on_a_server_channel_records_nothing_case())
    }

    /// A single permissions value is only valid for groups: on a server
    /// channel it is InvalidOperation, the overwrite is unchanged, and
    /// nothing is logged.
    async fn a_group_shaped_body_on_a_server_channel_records_nothing_case() {
        let harness = TestHarness::new().await;
        let f = server_fixture(&harness, Some(OLD)).await;

        let (status, body) = put_default(
            &harness,
            &f.owner_token,
            &f.channel,
            json!({ "permissions": ChannelPermission::SendMessage as u64 }),
            Some("wrong%20shape"),
        )
        .await;
        assert_eq!(status, Status::BadRequest, "{body}");
        assert_eq!(error_body(&body)["type"], "InvalidOperation");

        assert_eq!(stored_default(&harness, &f.channel).await, Some(OLD));
        let entries = server_entries(&harness, &f.server.id).await;
        assert!(entries.is_empty(), "{:?}", entries);
    }

    #[test]
    fn too_long_reason_is_rejected_before_writing() {
        crate::util::test::rt().block_on(too_long_reason_is_rejected_before_writing_case())
    }

    /// A 513-char reason: 400 AuditLogReasonTooLong, the overwrite is
    /// unchanged, and nothing is logged.
    async fn too_long_reason_is_rejected_before_writing_case() {
        let harness = TestHarness::new().await;
        let f = server_fixture(&harness, Some(OLD)).await;
        let reason = "a".repeat(513);

        let (status, body) = put_default(
            &harness,
            &f.owner_token,
            &f.channel,
            field_body(NEW),
            Some(&reason),
        )
        .await;
        assert_eq!(status, Status::BadRequest, "{body}");
        let error = error_body(&body);
        assert_eq!(error["type"], "FailedValidation");
        assert_eq!(error["error"], "AuditLogReasonTooLong");

        assert_eq!(
            stored_default(&harness, &f.channel).await,
            Some(OLD),
            "the overwrite must not change when the reason is rejected"
        );
        let entries = server_entries(&harness, &f.server.id).await;
        assert!(entries.is_empty(), "{:?}", entries);
    }
}
