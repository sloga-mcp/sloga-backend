use revolt_database::util::audit_reason::AuditLogReason;
use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference}, voice::{sync_voice_permissions, VoiceClient}, Database, User
};
use revolt_database::{
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Channel,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, Override, PermissionQuery};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Set Role Permission
///
/// Sets permissions for the specified role in this channel.
///
/// Channel must be a `TextChannel`.
#[openapi(tag = "Channel Permissions")]
#[put("/<target>/permissions/<role_id>", data = "<data>", rank = 2)]
pub async fn set_role_permissions(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
    role_id: String,
    data: Json<v0::DataSetRolePermissions>,
    reason: AuditLogReason,
) -> Result<Json<v0::Channel>> {
    // Refuse an over-long reason before anything is written.
    let reason = reason.validated()?;

    let channel = target.as_channel(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    let permissions: revolt_permissions::PermissionValue = calculate_channel_permissions(&mut query).await;

    query.set_server_from_channel().await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::ManagePermissions)?;

    if let Some(server) = query.server_ref() {
        if let Some(role) = server.roles.get(&role_id) {
            if server.owner != user.id
                && role.rank <= query.get_member_rank().unwrap_or(i64::MIN)
            {
                return Err(create_error!(NotElevated));
            }

            let current_value: Override = role.permissions.into();
            permissions
                .throw_permission_override(current_value, &data.permissions)
                .await?;

            // The role's overwrite on this channel before the write (None
            // when it had none), for the audit entry.
            let previous = match &channel {
                Channel::TextChannel {
                    role_permissions, ..
                }
                | Channel::Forum {
                    role_permissions, ..
                } => role_permissions.get(&role_id).copied(),
                _ => None,
            };
            let next: revolt_permissions::OverrideField = data.permissions.clone().into();

            let mut new_channel = channel.clone();

            new_channel
                .set_role_permission(db, &role_id, data.permissions.clone().into())
                .await?;

            // Logged only here: this arm is reached only for a server
            // channel, and only after the write succeeded. It sits before the
            // voice sync so a failed sync cannot drop the record of a write
            // that already landed. An identical re-PUT changes nothing and
            // logs nothing; a first overwrite (no previous) always logs.
            if previous != Some(next) {
                AuditLogEntry::record(
                    db,
                    AuditLogDraft {
                        server: server.id.clone(),
                        actor: Some(user.id.clone()),
                        action: AuditLogAction::ChannelOverwriteUpdate,
                        target: Some(role_id.clone()),
                        channel: Some(new_channel.id().to_string()),
                        changes: vec![
                            AuditLogChange::new(
                                "allow",
                                previous.map(|field| AuditValue::Int(field.a)),
                                Some(AuditValue::Int(next.a)),
                            ),
                            AuditLogChange::new(
                                "deny",
                                previous.map(|field| AuditValue::Int(field.d)),
                                Some(AuditValue::Int(next.d)),
                            ),
                        ],
                        reason,
                        ..Default::default()
                    },
                )
                .await;
            }

            sync_voice_permissions(db, voice_client, &new_channel, Some(server), Some(&role_id)).await?;

            Ok(Json(new_channel.into()))
        } else {
            Err(create_error!(NotFound))
        }
    } else {
        Err(create_error!(InvalidOperation))
    }
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{
        util::audit_reason::{AUDIT_LOG_REASON_HEADER, AUDIT_LOG_REASON_MAX_CHARS},
        AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, Channel, Database, Member,
        PartialMember, Server, User,
    };
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::{json, Value};

    // Compile-only without RabbitMQ: `TestHarness::new` connects to it, like
    // every other route test. The route's voice sync reads the channel's
    // node pin from Redis; these channels have no call, so it returns early.

    const ALLOW_FIRST: i64 = ChannelPermission::SendMessage as i64;
    const DENY_FIRST: i64 = ChannelPermission::React as i64;
    const ALLOW_SECOND: i64 = ChannelPermission::UploadFiles as i64;
    const DENY_SECOND: i64 = ChannelPermission::SendEmbeds as i64;

    struct Fixture {
        server: Server,
        channel: String,
        owner: User,
        owner_token: String,
        role: String,
    }

    /// An owner, their server's default text channel and one role with no
    /// overwrite on it yet.
    async fn fixture(harness: &TestHarness) -> Fixture {
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, channels) = harness.new_server(&owner).await;
        let channel = channels
            .into_iter()
            .find(|channel| matches!(channel, Channel::TextChannel { .. }))
            .expect("the server's default text channel");
        let role = harness.new_role(&server, 1, None).await;

        Fixture {
            server,
            channel: channel.id().to_string(),
            owner,
            owner_token: owner_session.token.to_string(),
            role: role.id,
        }
    }

    /// PUT the role overwrite; returns the status and the raw JSON body.
    async fn set_overwrite(
        harness: &TestHarness,
        token: &str,
        channel: &str,
        role: &str,
        (allow, deny): (i64, i64),
        reason: Option<&str>,
    ) -> (Status, Value) {
        let mut request = harness
            .client
            .put(format!("/channels/{}/permissions/{}", channel, role))
            .header(ContentType::JSON)
            .body(json!({ "permissions": { "allow": allow, "deny": deny } }).to_string())
            .header(Header::new("x-session-token", token.to_string()));
        if let Some(reason) = reason {
            request = request.header(Header::new(AUDIT_LOG_REASON_HEADER, reason.to_string()));
        }
        let response = request.dispatch().await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        let json = serde_json::from_str(&body).unwrap_or(Value::Null);
        (status, json)
    }

    /// The role's stored overwrite on the channel, read back from the DB.
    async fn stored_overwrite(
        harness: &TestHarness,
        channel: &str,
        role: &str,
    ) -> Option<OverrideField> {
        match harness.db.fetch_channel(channel).await.expect("channel") {
            Channel::TextChannel {
                role_permissions, ..
            } => role_permissions.get(role).copied(),
            other => panic!("expected the text channel, got {:?}", other),
        }
    }

    async fn audit_log(harness: &TestHarness, server: &Server) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(&server.id, None, 50, None, None)
            .await
            .expect("fetch audit log")
    }

    fn allow_deny(old: Option<(i64, i64)>, (allow, deny): (i64, i64)) -> Vec<AuditLogChange> {
        vec![
            AuditLogChange::new(
                "allow",
                old.map(|(allow, _)| AuditValue::Int(allow)),
                Some(AuditValue::Int(allow)),
            ),
            AuditLogChange::new(
                "deny",
                old.map(|(_, deny)| AuditValue::Int(deny)),
                Some(AuditValue::Int(deny)),
            ),
        ]
    }

    #[test]
    fn setting_an_overwrite_writes_one_entry() {
        crate::util::test::rt().block_on(setting_an_overwrite_writes_one_entry_case())
    }

    /// The owner sets a role overwrite where there was none, with a
    /// percent-encoded reason: the overwrite lands and exactly one
    /// `channel_overwrite_update` entry is written, actor = the session user,
    /// target = the role, channel = the channel, allow/deny with no old value
    /// and the new values, the reason decoded.
    async fn setting_an_overwrite_writes_one_entry_case() {
        let harness = TestHarness::new().await;
        // Mongo-only: REFERENCE cannot add a new overwrite (channels/ops/reference.rs:168-175).
        let Database::MongoDb(_) = &harness.db else {
            return;
        };
        let f = fixture(&harness).await;
        assert_eq!(stored_overwrite(&harness, &f.channel, &f.role).await, None);

        let (status, body) = set_overwrite(
            &harness,
            &f.owner_token,
            &f.channel,
            &f.role,
            (ALLOW_FIRST, DENY_FIRST),
            Some("raid%20lockdown%3A%20rule%203"),
        )
        .await;
        assert_eq!(status, Status::Ok, "body: {body}");
        assert_eq!(
            stored_overwrite(&harness, &f.channel, &f.role).await,
            Some(OverrideField {
                a: ALLOW_FIRST,
                d: DENY_FIRST
            })
        );

        let entries = audit_log(&harness, &f.server).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        let entry = &entries[0];
        assert_eq!(entry.server, f.server.id);
        assert_eq!(entry.action, AuditLogAction::ChannelOverwriteUpdate);
        assert_eq!(entry.actor.as_deref(), Some(f.owner.id.as_str()));
        assert_eq!(entry.target.as_deref(), Some(f.role.as_str()));
        assert_eq!(entry.channel.as_deref(), Some(f.channel.as_str()));
        assert_eq!(entry.changes, allow_deny(None, (ALLOW_FIRST, DENY_FIRST)));
        assert_eq!(entry.count, None);
        assert_eq!(entry.reason.as_deref(), Some("raid lockdown: rule 3"));
    }

    #[test]
    fn changing_an_overwrite_logs_the_previous_values() {
        crate::util::test::rt().block_on(changing_an_overwrite_logs_the_previous_values_case())
    }

    /// The same overwrite set twice: the second entry's old values are the
    /// first write's values, and no header means no reason. Entries are picked
    /// by their new values, not by position: two ULIDs minted in the same
    /// millisecond do not sort by mint order on the reference driver.
    async fn changing_an_overwrite_logs_the_previous_values_case() {
        let harness = TestHarness::new().await;
        // Mongo-only: REFERENCE cannot add a new overwrite (channels/ops/reference.rs:168-175).
        let Database::MongoDb(_) = &harness.db else {
            return;
        };
        let f = fixture(&harness).await;

        for values in [(ALLOW_FIRST, DENY_FIRST), (ALLOW_SECOND, DENY_SECOND)] {
            let (status, body) =
                set_overwrite(&harness, &f.owner_token, &f.channel, &f.role, values, None).await;
            assert_eq!(status, Status::Ok, "body: {body}");
        }
        assert_eq!(
            stored_overwrite(&harness, &f.channel, &f.role).await,
            Some(OverrideField {
                a: ALLOW_SECOND,
                d: DENY_SECOND
            })
        );

        let entries = audit_log(&harness, &f.server).await;
        assert_eq!(entries.len(), 2, "{entries:?}");
        let first = allow_deny(None, (ALLOW_FIRST, DENY_FIRST));
        let second = allow_deny(Some((ALLOW_FIRST, DENY_FIRST)), (ALLOW_SECOND, DENY_SECOND));
        for changes in [&first, &second] {
            let entry = entries
                .iter()
                .find(|entry| &entry.changes == changes)
                .unwrap_or_else(|| panic!("an entry with {:?}: {:?}", changes, entries));
            assert_eq!(entry.action, AuditLogAction::ChannelOverwriteUpdate);
            assert_eq!(entry.actor.as_deref(), Some(f.owner.id.as_str()));
            assert_eq!(entry.target.as_deref(), Some(f.role.as_str()));
            assert_eq!(entry.channel.as_deref(), Some(f.channel.as_str()));
            assert_eq!(entry.reason, None, "no header, no reason");
        }
    }

    #[test]
    fn an_identical_re_put_logs_nothing() {
        crate::util::test::rt().block_on(an_identical_re_put_logs_nothing_case())
    }

    /// The same values PUT a second time, even with a reason, succeed but
    /// change nothing: the entry count stays at the first write's one.
    /// Mutation: the `previous != Some(next)` guard removed.
    async fn an_identical_re_put_logs_nothing_case() {
        let harness = TestHarness::new().await;
        // Mongo-only: REFERENCE cannot add a new overwrite (channels/ops/reference.rs:168-175).
        let Database::MongoDb(_) = &harness.db else {
            return;
        };
        let f = fixture(&harness).await;
        let values = (ALLOW_FIRST, DENY_FIRST);

        let (status, body) =
            set_overwrite(&harness, &f.owner_token, &f.channel, &f.role, values, None).await;
        assert_eq!(status, Status::Ok, "body: {body}");
        assert_eq!(audit_log(&harness, &f.server).await.len(), 1);

        let (status, body) = set_overwrite(
            &harness,
            &f.owner_token,
            &f.channel,
            &f.role,
            values,
            Some("same%20again"),
        )
        .await;
        assert_eq!(status, Status::Ok, "body: {body}");
        assert_eq!(
            stored_overwrite(&harness, &f.channel, &f.role).await,
            Some(OverrideField {
                a: ALLOW_FIRST,
                d: DENY_FIRST
            })
        );

        let entries = audit_log(&harness, &f.server).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].changes, allow_deny(None, values));
        assert_eq!(entries[0].reason, None, "the re-PUT's reason is not logged");
    }

    #[test]
    fn a_refused_overwrite_logs_nothing() {
        crate::util::test::rt().block_on(a_refused_overwrite_logs_nothing_case())
    }

    /// Three refusals, each with a reason header, none of which writes the
    /// overwrite or an entry: a member without ManagePermissions
    /// (MissingPermission); a member with ManagePermissions editing their own,
    /// equally ranked role (NotElevated); the owner naming a role the server
    /// does not have (NotFound).
    async fn a_refused_overwrite_logs_nothing_case() {
        let harness = TestHarness::new().await;
        let f = fixture(&harness).await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, moderator_session, moderator) = harness.new_user().await;
        for user in [&member, &moderator] {
            Member::create(&harness.db, &f.server, user, None)
                .await
                .expect("member");
        }

        let moderator_role = harness
            .new_role(
                &f.server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::ManagePermissions as i64,
                    d: 0,
                }),
            )
            .await;
        harness
            .db
            .fetch_member(&f.server.id, &moderator.id)
            .await
            .expect("member")
            .update(
                &harness.db,
                PartialMember {
                    roles: Some(vec![moderator_role.id.clone()]),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("role grant");

        let (status, body) = set_overwrite(
            &harness,
            &member_session.token,
            &f.channel,
            &f.role,
            (ALLOW_FIRST, DENY_FIRST),
            Some("not%20allowed"),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "body: {body}");
        assert_eq!(body["type"], "MissingPermission", "body: {body}");

        let (status, body) = set_overwrite(
            &harness,
            &moderator_session.token,
            &f.channel,
            &moderator_role.id,
            (ALLOW_FIRST, DENY_FIRST),
            Some("not%20elevated"),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "body: {body}");
        assert_eq!(body["type"], "NotElevated", "body: {body}");

        let missing_role = TestHarness::rand_string();
        let (status, body) = set_overwrite(
            &harness,
            &f.owner_token,
            &f.channel,
            &missing_role,
            (ALLOW_FIRST, DENY_FIRST),
            Some("no%20such%20role"),
        )
        .await;
        assert_eq!(status, Status::NotFound, "body: {body}");
        assert_eq!(body["type"], "NotFound", "body: {body}");

        for role in [&f.role, &moderator_role.id, &missing_role] {
            assert_eq!(
                stored_overwrite(&harness, &f.channel, role).await,
                None,
                "no overwrite for {}",
                role
            );
        }
        let entries = audit_log(&harness, &f.server).await;
        assert!(entries.is_empty(), "{:?}", entries);
    }

    #[test]
    fn an_overlong_reason_is_refused_and_the_overwrite_stands() {
        crate::util::test::rt()
            .block_on(an_overlong_reason_is_refused_and_the_overwrite_stands_case())
    }

    /// A reason one char over the limit is refused with
    /// FailedValidation/AuditLogReasonTooLong BEFORE the write: the earlier
    /// overwrite is unchanged and only the earlier write's entry exists.
    /// Mutation: the `validated()?` moved below the write.
    async fn an_overlong_reason_is_refused_and_the_overwrite_stands_case() {
        let harness = TestHarness::new().await;
        // Mongo-only: REFERENCE cannot add a new overwrite (channels/ops/reference.rs:168-175).
        let Database::MongoDb(_) = &harness.db else {
            return;
        };
        let f = fixture(&harness).await;
        let (status, body) = set_overwrite(
            &harness,
            &f.owner_token,
            &f.channel,
            &f.role,
            (ALLOW_FIRST, DENY_FIRST),
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "body: {body}");

        let reason = "a".repeat(AUDIT_LOG_REASON_MAX_CHARS + 1);
        let (status, body) = set_overwrite(
            &harness,
            &f.owner_token,
            &f.channel,
            &f.role,
            (ALLOW_SECOND, DENY_SECOND),
            Some(&reason),
        )
        .await;
        assert_eq!(status, Status::BadRequest, "body: {body}");
        assert_eq!(body["type"], "FailedValidation", "body: {body}");
        assert_eq!(body["error"], "AuditLogReasonTooLong", "body: {body}");

        assert_eq!(
            stored_overwrite(&harness, &f.channel, &f.role).await,
            Some(OverrideField {
                a: ALLOW_FIRST,
                d: DENY_FIRST
            }),
            "a refused write leaves the overwrite as it was"
        );
        let entries = audit_log(&harness, &f.server).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(
            entries[0].changes,
            allow_deny(None, (ALLOW_FIRST, DENY_FIRST)),
            "only the earlier write is logged"
        );
    }
}
