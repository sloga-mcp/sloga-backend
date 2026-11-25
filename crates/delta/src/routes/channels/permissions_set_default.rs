use revolt_database::util::audit_reason::AuditLogReason;
use revolt_database::{
    util::{
        permissions::DatabasePermissionQuery, protected_access::reconcile_channel,
        reference::Reference,
    },
    voice::{sync_voice_permissions, VoiceClient},
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Channel, Database,
    PartialChannel, User,
};
use revolt_models::v0::{self, DataDefaultChannelPermissions};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, OverrideField};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use super::permissions_set::log_reconcile_failure;

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

    // Protected channels (6.3 "Hooks", S2-D11): a default overwrite can take
    // ViewChannel away, so a server channel is reconciled after the write and
    // its entry and BEFORE the voice sync, on every PUT (retrying the same
    // PUT repairs a failed reconcile). The result is kept: the sync always
    // runs, then a failed reconcile answers 500 with the overwrite in place
    // (the `Member::remove` kept-second-release shape), its error unchanged.
    // A failed sync is answered instead, so the reconcile error is logged
    // here. A group is never protected, and a channel without a seat list is
    // a no-op.
    let reconciled = if channel.server().is_some() {
        log_reconcile_failure(channel.id(), reconcile_channel(db, channel.id()).await)
    } else {
        Ok(Vec::new())
    };

    let server = match channel.server() {
        Some(server_id) => Some(Reference::from_unchecked(server_id).as_server(db).await?),
        None => None
    };

    sync_voice_permissions(db, voice_client, &channel, server.as_ref(), None).await?;

    reconciled?;

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

#[cfg(test)]
mod reconcile_hook {
    //! Protected channels, 6.3 "Hooks" (S2-D11): a default overwrite runs
    //! `reconcile_channel` after the write and its entry and BEFORE the voice
    //! sync; a failed reconcile is answered (500) once the sync ran, with the
    //! overwrite in place. Owner O and target T are seated. Compile-only
    //! without RabbitMQ and Redis, like every other route test.

    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        events::client::EventV1,
        mongodb::bson::{doc, Document},
        voice::{delete_channel_node, set_channel_node},
        AuditLogAction, AuditLogEntry, Channel, ChannelSeat, Database, Session, User,
        PROTECTED_SCOPE_SEATS,
    };
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    const VIEW: i64 = ChannelPermission::ViewChannel as i64;

    /// A node name absent from `Revolt.toml`: the voice sync of a channel
    /// pinned to it fails with `UnknownNode` before any network.
    const ABSENT_NODE: &str = "test-node-with-no-sfu";

    /// PUT the channel's default overwrite (allow nothing, deny `deny`) as
    /// `session`: the status and the raw body.
    async fn put_default(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        deny: i64,
    ) -> (Status, String) {
        let response = harness
            .client
            .put(format!("/channels/{channel_id}/permissions/default"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .body(json!({ "permissions": { "allow": 0, "deny": deny } }).to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    async fn stored_default(harness: &TestHarness, channel_id: &str) -> Option<OverrideField> {
        match harness.db.fetch_channel(channel_id).await.expect("channel") {
            Channel::TextChannel {
                default_permissions,
                ..
            } => default_permissions,
            other => panic!("expected a text channel, got {:?}", other),
        }
    }

    async fn seat_active(harness: &TestHarness, channel_id: &str, user_id: &str) -> bool {
        harness
            .db
            .fetch_channel_seats(channel_id)
            .await
            .expect("the seats read")
            .into_iter()
            .find(|seat| seat.user_id == user_id)
            .expect("a seat row")
            .is_active()
    }

    async fn entries(
        harness: &TestHarness,
        server_id: &str,
        action: AuditLogAction,
    ) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(server_id, None, 50, Some(action), None)
            .await
            .expect("the audit log")
    }

    /// Arm (`{ "released_at": null }`) or lift (`{}`) a validator that
    /// refuses every `channel_seats` row with `released_at` set, so every
    /// seat release fails with a DatabaseError. MONGODB only.
    async fn seat_validator(harness: &TestHarness, validator: Document) {
        let Database::MongoDb(mongo) = &harness.db else {
            panic!("MONGODB only");
        };
        mongo
            .db()
            .run_command(doc! {
                "collMod": "channel_seats",
                "validator": validator,
                "validationLevel": "strict",
                "validationAction": "error",
            })
            .await
            .expect("the seat validator");
    }

    /// An ACTIVE seat row of `user_id` in `channel_id`, written straight to
    /// the store with no seat list
    async fn seat_raw(harness: &TestHarness, channel_id: &str, user_id: &str) {
        let seat = ChannelSeat {
            id: ChannelSeat::composite_id(channel_id, user_id),
            channel_id: channel_id.to_string(),
            user_id: user_id.to_string(),
            seated_at: Timestamp::now_utc(),
            released_at: None,
            cooldown_until: None,
            release_cause: None,
            keys_received_at: None,
        };
        match &harness.db {
            Database::Reference(reference) => {
                reference
                    .channel_seats
                    .lock()
                    .await
                    .insert(seat.id.clone(), seat);
            }
            Database::MongoDb(mongo) => {
                mongo
                    .col::<ChannelSeat>("channel_seats")
                    .insert_one(&seat)
                    .await
                    .expect("raw seat");
            }
        }
    }

    #[test]
    fn a_default_overwrite_that_hides_the_channel_releases_the_seat() {
        crate::util::test::rt().block_on(Box::pin(
            a_default_overwrite_that_hides_the_channel_releases_the_seat_case(),
        ))
    }

    /// The default overwrite denies ViewChannel, so T loses it: the PUT
    /// releases T's seat with its `ProtectedSeatRelease` entry and the seat
    /// event, and O (the owner and list signer) keeps theirs. Control: the
    /// hook deleted.
    async fn a_default_overwrite_that_hides_the_channel_releases_the_seat_case() {
        let mut harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, target) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&target])
            .await;
        let channel_id = protected.channel.id().to_string();
        let server_id = protected.server.id.clone();
        assert!(
            seat_active(&harness, &channel_id, &target.id).await,
            "precondition: T is seated"
        );

        let (status, body) = put_default(&harness, &owner_session, &channel_id, VIEW).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(
            stored_default(&harness, &channel_id).await,
            Some(OverrideField { a: 0, d: VIEW })
        );
        assert!(
            !seat_active(&harness, &channel_id, &target.id).await,
            "T's seat is released"
        );
        assert!(
            seat_active(&harness, &channel_id, &owner.id).await,
            "O keeps their seat"
        );

        let releases = entries(&harness, &server_id, AuditLogAction::ProtectedSeatRelease).await;
        assert_eq!(releases.len(), 1, "{releases:?}");
        assert_eq!(releases[0].target.as_deref(), Some(target.id.as_str()));
        assert_eq!(releases[0].channel.as_deref(), Some(channel_id.as_str()));
        harness
            .wait_for_event(&channel_id, |event| {
                matches!(event, EventV1::ProtectedChannelChanged { id, scope }
                    if id == &channel_id && *scope == vec![PROTECTED_SCOPE_SEATS.to_string()])
            })
            .await;
    }

    #[test]
    fn a_failed_reconcile_still_syncs_voice_then_answers_500() {
        crate::util::test::rt().block_on(Box::pin(
            a_failed_reconcile_still_syncs_voice_then_answers_500_case(),
        ))
    }

    /// Every seat release refused (MONGODB only: the reference store cannot
    /// fail a write). (1) With the voice sync failing too (the channel is
    /// pinned to a node with no SFU), the SYNC's error is answered: it ran
    /// after the failed reconcile. (2) With the sync clean, the kept
    /// reconcile error is answered (500) after the overwrite landed and was
    /// recorded; the identical retry reconciles again. (3) Fault lifted, the
    /// same PUT releases the seat. Controls: `reconcile_channel(..).await?`
    /// ((1) answers DatabaseError, the sync skipped); the kept result
    /// dropped ((2) answers 200).
    async fn a_failed_reconcile_still_syncs_voice_then_answers_500_case() {
        let harness = TestHarness::new().await;
        let Database::MongoDb(_) = &harness.db else {
            return;
        };
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, target) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&target])
            .await;
        let channel_id = protected.channel.id().to_string();
        let server_id = protected.server.id.clone();
        seat_validator(&harness, doc! { "released_at": null }).await;

        set_channel_node(&channel_id, ABSENT_NODE)
            .await
            .expect("node");
        let synced = put_default(&harness, &owner_session, &channel_id, VIEW).await;
        delete_channel_node(&channel_id).await.expect("cleanup");
        let failed = put_default(&harness, &owner_session, &channel_id, VIEW).await;
        let kept_seat = seat_active(&harness, &channel_id, &target.id).await;
        seat_validator(&harness, doc! {}).await;

        assert!(
            synced.1.contains("UnknownNode") && !synced.1.contains("DatabaseError"),
            "the voice sync runs after the failed reconcile: {:?}",
            synced
        );
        assert_eq!(failed.0, Status::InternalServerError, "{:?}", failed);
        assert!(failed.1.contains("DatabaseError"), "{:?}", failed);
        assert!(kept_seat, "the refused release leaves the seat active");
        assert_eq!(
            stored_default(&harness, &channel_id).await,
            Some(OverrideField { a: 0, d: VIEW }),
            "the write is never undone"
        );
        let overwrites =
            entries(&harness, &server_id, AuditLogAction::ChannelOverwriteUpdate).await;
        assert_eq!(overwrites.len(), 1, "recorded once: {overwrites:?}");

        let repaired = put_default(&harness, &owner_session, &channel_id, VIEW).await;
        assert_eq!(repaired.0, Status::Ok, "{:?}", repaired);
        assert!(
            !seat_active(&harness, &channel_id, &target.id).await,
            "the retry releases the seat"
        );
        assert_eq!(
            entries(&harness, &server_id, AuditLogAction::ProtectedSeatRelease)
                .await
                .len(),
            1
        );
    }

    #[test]
    fn an_unprotected_channel_is_left_alone() {
        crate::util::test::rt().block_on(Box::pin(an_unprotected_channel_is_left_alone_case()))
    }

    /// A channel without a seat list: the default overwrite hides it from a
    /// member who has a stray active seat row there, and the PUT answers 200
    /// with only its own entry. The row is untouched: the reconcile of a
    /// channel that is not protected releases nothing.
    async fn an_unprotected_channel_is_left_alone_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, member) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&owner).await;
        harness.join_server(&server, &member).await;
        seat_raw(&harness, channel.id(), &member.id).await;

        let (status, body) = put_default(&harness, &owner_session, channel.id(), VIEW).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert!(
            seat_active(&harness, channel.id(), &member.id).await,
            "a channel without a seat list is not reconciled"
        );
        let all = harness
            .db
            .fetch_audit_log(&server.id, None, 50, None, None)
            .await
            .expect("the audit log");
        assert_eq!(all.len(), 1, "only the overwrite is recorded: {all:?}");
        assert_eq!(all[0].action, AuditLogAction::ChannelOverwriteUpdate);
    }
}
