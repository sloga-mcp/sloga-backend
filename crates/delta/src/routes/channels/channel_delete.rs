use revolt_database::{
    util::{
        audit_reason::AuditLogReason, permissions::DatabasePermissionQuery, reference::Reference,
    },
    voice::{delete_voice_channel, remove_user_from_voice_channel, UserVoiceChannel, VoiceClient},
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Channel, Database,
    PartialChannel, User, AMQP,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result, ToRevoltError};
use rocket::State;
use rocket_empty::EmptyResponse;

/// The `channel_delete` entry a server-channel delete writes, built from the
/// channel as it is BEFORE the delete: the target is the channel, and its
/// `name` and `type` are recorded as `old`.
///
/// `type` uses the vocabulary `channel_create` records (the
/// `DataCreateServerChannel.type` names `"Text"`, `"Voice"`, `"Forum"`), plus
/// `"Thread"`. There is no `VoiceChannel` type: a voice channel is a
/// `TextChannel` carrying voice information, which is how
/// `create_server_channel` stores a `Voice` body, so that is what `"Voice"`
/// reads back here (calls switched off included).
///
/// `None` for saved messages, DMs and groups, which are never logged.
/// Written without a wildcard arm, so a new channel variant has to decide.
fn channel_delete_draft(
    channel: &Channel,
    actor: &str,
    reason: Option<String>,
) -> Option<AuditLogDraft> {
    let (server, name, channel_type) = match channel {
        Channel::TextChannel {
            server,
            name,
            voice: Some(_),
            ..
        } => (server, name, "Voice"),
        Channel::TextChannel {
            server,
            name,
            voice: None,
            ..
        } => (server, name, "Text"),
        Channel::Forum { server, name, .. } => (server, name, "Forum"),
        Channel::Thread { server, name, .. } => (server, name, "Thread"),
        Channel::SavedMessages { .. } | Channel::DirectMessage { .. } | Channel::Group { .. } => {
            return None
        }
    };

    Some(AuditLogDraft {
        server: server.clone(),
        actor: Some(actor.to_string()),
        action: AuditLogAction::ChannelDelete,
        target: Some(channel.id().to_string()),
        changes: vec![
            AuditLogChange::new("name", Some(AuditValue::String(name.clone())), None),
            AuditLogChange::new(
                "type",
                Some(AuditValue::String(channel_type.to_string())),
                None,
            ),
        ],
        reason,
        ..Default::default()
    })
}

/// # Close Channel
///
/// Deletes a server channel, leaves a group or closes a group.
#[openapi(tag = "Channel Information")]
#[delete("/<target>?<options..>")]
pub async fn delete(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    options: v0::OptionsChannelDelete,
    reason: AuditLogReason,
) -> Result<EmptyResponse> {
    // Reject an over-long reason before anything is changed.
    let reason = reason.validated()?;

    let mut channel = target.as_channel(db).await?;

    // Threads delegate their permission calculus to the parent text channel;
    // resolve it BEFORE constructing the query.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    // Snapshotted BEFORE the delete, written only once it has succeeded.
    // `None` for DMs, groups and saved messages, which never log.
    let audit = channel_delete_draft(&channel, &user.id, reason);

    #[allow(deprecated)]
    match &channel {
        Channel::SavedMessages { .. } => Err(create_error!(NoEffect))?,
        Channel::DirectMessage { .. } => {
            channel
                .update(
                    db,
                    PartialChannel {
                        active: Some(false),
                        ..Default::default()
                    },
                    vec![],
                )
                .await?
        }
        Channel::Group { .. } => {
            channel
                .remove_user_from_group(
                    db,
                    amqp,
                    &user,
                    None,
                    options.leave_silently.unwrap_or_default(),
                )
                .await?;

            // The user has already left the group, so a retried leave cannot
            // redo this eviction (AFK S-3 DS-1). A failed eviction is
            // therefore reported (ERROR + Sentry) and the leave still
            // answers success.
            //
            // No Redis-only pre-check in front of it: `is_in_voice_channel`
            // reads only the user's channel set, so it skipped a connection
            // the SFU has and Redis does not. The helper decides for itself
            // whether the user is here at all (the SFU listing, the
            // connection records, the voice state) and runs nothing when they
            // are not.
            let user_voice_channel = UserVoiceChannel::from_channel(&channel);
            if let Err(error) =
                remove_user_from_voice_channel(db, voice_client, &user_voice_channel, &user.id)
                    .await
            {
                log::warn!(
                    "{} left group {}, but evicting them from its call failed: {error:?}",
                    user.id,
                    user_voice_channel.id
                );
                let _ = Err::<(), _>(error).to_internal_error();
            }
        }
        Channel::TextChannel { .. } => {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
            channel.delete(db).await?;

            // The channel is gone: record it before the voice teardown, which
            // can still fail after the delete.
            if let Some(draft) = audit {
                AuditLogEntry::record(db, draft).await;
            }

            delete_voice_channel(db, voice_client, &UserVoiceChannel::from_channel(&channel)).await?;
        }
        Channel::Forum { .. } => {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
            channel.delete(db).await?;

            if let Some(draft) = audit {
                AuditLogEntry::record(db, draft).await;
            }
        }
        Channel::Thread { .. } => {
            // ManageChannel on the PARENT channel is required to delete a thread.
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
            channel.delete(db).await?;

            if let Some(draft) = audit {
                AuditLogEntry::record(db, draft).await;
            }
        }
    };

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{events::client::EventV1, Channel};
    use revolt_models::v0::DataCreateGroup;
    use rocket::http::{Header, Status};

    #[test]
    fn success_delete_group() {
        crate::util::test::rt().block_on(success_delete_group_case())
    }

    async fn success_delete_group_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        let group = Channel::create_group(
            &harness.db,
            DataCreateGroup {
                ..Default::default()
            },
            user.id.clone(),
        )
        .await
        .expect("`Channel`");

        let response = harness
            .client
            .delete(format!("/channels/{}", group.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        harness
            .wait_for_event(group.id(), |event| match event {
                EventV1::ChannelDelete { id, .. } => id == group.id(),
                _ => false,
            })
            .await;
    }

    // TEST: member leaves group (no delete)
    // TEST: no effect with saved messages
    // TEST: DM set to inactive

    #[test]
    fn success_delete_channel() {
        crate::util::test::rt().block_on(success_delete_channel_case())
    }

    async fn success_delete_channel_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, channels) = harness.new_server(&user).await;
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .delete(format!("/channels/{}", channels[0].id())),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        harness
            .wait_for_event(channels[0].id(), |event| match event {
                EventV1::ChannelDelete { id, .. } => id == channels[0].id(),
                _ => false,
            })
            .await;
    }

    // ---- the eviction after a group leave (AFK S-3 DS-1) -------------------
    //
    // Needs RabbitMQ and Redis, as every route test here does.

    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_node, delete_channel_voice_state,
            get_user_voice_channel_in_server, get_voice_channel_members, is_in_voice_channel,
            record_voice_connection, recorded_voice_connections, set_channel_node,
            UserVoiceChannel,
        },
        User,
    };

    /// A node name deliberately absent from `Revolt.toml`: an eviction
    /// addressed to it fails with `UnknownNode` before any network.
    const ABSENT_NODE: &str = "test-node-with-no-sfu";

    /// A group owned by `owner` with `member` in it.
    async fn group_with(harness: &TestHarness, owner: &User, member: &User) -> Channel {
        Channel::create_group(
            &harness.db,
            DataCreateGroup {
                users: vec![member.id.clone()].into_iter().collect(),
                ..Default::default()
            },
            owner.id.clone(),
        )
        .await
        .expect("group")
    }

    /// A join as voice-ingress records it: the connection first, then the
    /// state, created only for the user's first connection.
    async fn join_recorded(uvc: &UserVoiceChannel, user_id: &str, sid: &str, identity: &str) {
        if record_voice_connection(uvc, user_id, sid, identity)
            .await
            .expect("record")
        {
            create_voice_state(uvc, user_id, Timestamp::now_utc())
                .await
                .expect("voice state");
        }
    }

    /// What is left of `user_id` in `uvc`: the number of recorded
    /// connections, then whether it is in the user's channel set, in the
    /// channel's member set, and named by the per-group pointer.
    async fn voice_traces(uvc: &UserVoiceChannel, user_id: &str) -> (usize, bool, bool, bool) {
        let recorded = recorded_voice_connections(uvc, user_id)
            .await
            .expect("recorded read")
            .len();
        let listed = is_in_voice_channel(user_id, uvc).await.expect("vc read");
        let member = get_voice_channel_members(uvc)
            .await
            .expect("members read")
            .is_some_and(|members| members.iter().any(|id| id == user_id));
        let parent = uvc.server_id.as_deref().unwrap_or(&uvc.id);
        let pointer = get_user_voice_channel_in_server(user_id, parent)
            .await
            .expect("pointer read")
            .as_deref()
            == Some(uvc.id.as_str());
        (recorded, listed, member, pointer)
    }

    async fn is_recipient(harness: &TestHarness, group_id: &str, user_id: &str) -> bool {
        match harness.db.fetch_channel(group_id).await.expect("group") {
            Channel::Group { recipients, .. } => recipients.iter().any(|id| id == user_id),
            _ => unreachable!("a group"),
        }
    }

    #[test]
    fn a_failed_eviction_still_leaves_the_group() {
        crate::util::test::rt().block_on(a_failed_eviction_still_leaves_the_group_case())
    }

    /// DS-1: a member in the group call leaves and the eviction fails
    /// (ABSENT_NODE, UnknownNode before any network). The leave is already
    /// durable and cannot be retried, so the route answers success, and the
    /// failed eviction tore nothing down. Mutation: the eviction error
    /// propagated (a non-2xx).
    async fn a_failed_eviction_still_leaves_the_group_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, session, leaver) = harness.new_user().await;
        let group = group_with(&harness, &owner, &leaver).await;
        let uvc = UserVoiceChannel::from_channel(&group);
        join_recorded(&uvc, &leaver.id, "PA_leave_live", &leaver.id).await;
        set_channel_node(group.id(), ABSENT_NODE)
            .await
            .expect("node");

        let response = harness
            .client
            .delete(format!("/channels/{}", group.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        delete_channel_node(group.id()).await.expect("unpin");

        assert_eq!(
            status,
            Status::NoContent,
            "a failed eviction after the leave must answer success: {}",
            body
        );
        assert!(
            !is_recipient(&harness, group.id(), &leaver.id).await,
            "the user has left"
        );
        assert_eq!(
            voice_traces(&uvc, &leaver.id).await,
            (1, true, true, true),
            "a failed eviction tears nothing down"
        );

        delete_channel_voice_state(&uvc, &[leaver.id.clone()])
            .await
            .expect("cleanup");
    }

    #[test]
    fn a_leavers_record_only_ghost_is_torn_down() {
        crate::util::test::rt().block_on(a_leavers_record_only_ghost_is_torn_down_case())
    }

    /// A call that ended without its webhooks (no node pinned) left a
    /// connection record of the leaver and no other voice state, so the
    /// user's channel set does not name the group. The leave still tears the
    /// record down: the helper, not a Redis-only pre-check, decides whether
    /// the user is here. Mutations: the eviction removed; the
    /// `is_in_voice_channel` pre-check reinstated (it skips this user).
    async fn a_leavers_record_only_ghost_is_torn_down_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, session, leaver) = harness.new_user().await;
        let group = group_with(&harness, &owner, &leaver).await;
        let uvc = UserVoiceChannel::from_channel(&group);
        assert!(
            record_voice_connection(&uvc, &leaver.id, "PA_leave_ghost", &leaver.id)
                .await
                .expect("record")
        );
        assert_eq!(
            voice_traces(&uvc, &leaver.id).await,
            (1, false, false, false),
            "the ghost is a record and nothing else"
        );

        let response = harness
            .client
            .delete(format!("/channels/{}", group.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        assert!(!is_recipient(&harness, group.id(), &leaver.id).await);
        assert_eq!(
            voice_traces(&uvc, &leaver.id).await,
            (0, false, false, false),
            "the leaver's ghost must be torn down"
        );
    }

    // ---- the route's text (AFK S-3 DS-1) -----------------------------------

    /// `delete`'s body, comment lines dropped, whitespace collapsed, and the
    /// spaces rustfmt puts inside a wrapped call and before `.await` removed.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("channel_delete.rs");
        let at = SOURCE
            .find("pub async fn delete(")
            .expect("the route is defined");
        let open = at + SOURCE[at..].find('\u{7b}').expect("a body");
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in SOURCE[open..].char_indices() {
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
        SOURCE[open..=close.expect("a closed body")]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .replace("( ", "(")
            .replace(" )", ")")
            .replace(",)", ")")
            .replace(" .await", ".await")
    }

    /// DS-1: in the group arm, the eviction runs AFTER the durable leave,
    /// its error is neither propagated nor silently dropped but reported
    /// through `to_internal_error()`, and no Redis-only pre-check stands in
    /// front of it. The server-channel arm keeps its own teardown.
    /// Mutations: the error propagated; the eviction removed; the pre-check
    /// reinstated.
    #[test]
    fn a_group_leave_evicts_after_it_is_durable_and_reports_a_failure() {
        const GROUP_ARM: &str = "Channel::Group \u{7b} .. \u{7d} =>";
        const DURABLE: &str = ".remove_user_from_group(db, amqp, &user, None, \
             options.leave_silently.unwrap_or_default()).await?;";
        const EVICT: &str = "if let Err(error) = remove_user_from_voice_channel(db, voice_client, \
             &user_voice_channel, &user.id).await \u{7b}";
        const REPORT: &str = "let _ = Err::<(), _>(error).to_internal_error();";
        const NEXT_ARM: &str = "Channel::TextChannel \u{7b} .. \u{7d} =>";

        let body = route_body();
        let mut last = 0;
        for needle in [GROUP_ARM, DURABLE, EVICT, REPORT, NEXT_ARM] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the route must carry `{needle}` exactly once: {body}"
            );
            let at = body.find(needle).expect("counted above");
            assert!(last < at, "`{}` is out of order: {}", needle, body);
            last = at;
        }
        assert_eq!(
            body.matches("remove_user_from_voice_channel(").count(),
            1,
            "one eviction, the one pinned above: {body}"
        );
        assert!(
            body.contains(
                "delete_voice_channel(db, voice_client, &UserVoiceChannel::from_channel(&channel)).await?;"
            ),
            "the server-channel teardown is out of scope and unchanged: {}",
            body
        );
        for banned in [
            "is_in_voice_channel(",
            "let _ = remove_user_from_voice_channel",
            ".ok()",
            "to_internal_error()?",
        ] {
            assert!(
                !body.contains(banned),
                "the route must not carry `{}`: {}",
                banned,
                body
            );
        }
    }

    // ---- the audit log (moderation slice 1) --------------------------------
    //
    // Needs RabbitMQ and Redis, as every route test here does.

    use crate::util::test::{statement_at, without_comments, without_whitespace};
    use revolt_database::{
        mongodb::bson::{doc, Document},
        AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, Database, Member,
    };
    use revolt_models::v0;

    async fn delete_channel<'a>(
        harness: &'a TestHarness,
        token: &str,
        channel: &str,
        reason: Option<&str>,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        let mut request = harness
            .client
            .delete(format!("/channels/{channel}"))
            .header(Header::new("x-session-token", token.to_string()));
        if let Some(reason) = reason {
            request = request.header(Header::new("X-Audit-Log-Reason", reason.to_string()));
        }
        request.dispatch().await
    }

    async fn channel_exists(harness: &TestHarness, id: &str) -> bool {
        harness.db.fetch_channel(id).await.is_ok()
    }

    async fn server_entries(harness: &TestHarness, server: &str) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(server, None, 50, None, None)
            .await
            .expect("audit log")
    }

    /// The `channel_delete` entries in `server` that name `channel`.
    async fn delete_entries(
        harness: &TestHarness,
        server: &str,
        channel: &str,
    ) -> Vec<AuditLogEntry> {
        server_entries(harness, server)
            .await
            .into_iter()
            .filter(|entry| {
                entry.action == AuditLogAction::ChannelDelete
                    && entry.target.as_deref() == Some(channel)
            })
            .collect()
    }

    /// How many entries, in ANY server, name `actor` as the actor. A DM or a
    /// group has no server to read back by, so a stray entry would land under
    /// an id the test cannot guess; counting by actor finds it anywhere.
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

    /// The `name` and `type` changes a delete of `name` / `channel_type`
    /// must carry: both `old`, neither `new`.
    fn old_name_and_type(name: &str, channel_type: &str) -> Vec<AuditLogChange> {
        vec![
            AuditLogChange::new("name", Some(AuditValue::String(name.to_string())), None),
            AuditLogChange::new(
                "type",
                Some(AuditValue::String(channel_type.to_string())),
                None,
            ),
        ]
    }

    /// Every arm of `channel_delete_draft`, with no database: the three
    /// server variants (a text channel with and without voice information
    /// split into "Voice" and "Text") build a draft with the OLD name and
    /// type, the server, the actor, the channel as target and the reason;
    /// saved messages, DMs and groups build none. The channels are decoded
    /// from their stored JSON shape rather than built as struct literals, so
    /// fields added to a variant later (with serde defaults) do not break
    /// this. Mutations: "TextChannel" recorded; voice ignored; a non-server
    /// variant logged; `new` filled instead of `old`.
    #[test]
    fn the_draft_covers_every_channel_variant() {
        fn decode(value: serde_json::Value) -> Channel {
            serde_json::from_value(value).expect("a stored channel")
        }

        let server_channels = [
            (
                serde_json::json!({ "channel_type": "TextChannel", "_id": "C1",
                    "server": "S1", "name": "general" }),
                "general",
                "Text",
            ),
            (
                serde_json::json!({ "channel_type": "TextChannel", "_id": "C1",
                    "server": "S1", "name": "lounge", "voice": {} }),
                "lounge",
                "Voice",
            ),
            (
                serde_json::json!({ "channel_type": "TextChannel", "_id": "C1",
                    "server": "S1", "name": "quiet", "voice": { "disabled": true } }),
                "quiet",
                "Voice",
            ),
            (
                serde_json::json!({ "channel_type": "Forum", "_id": "C1",
                    "server": "S1", "name": "ideas" }),
                "ideas",
                "Forum",
            ),
            (
                serde_json::json!({ "channel_type": "Thread", "_id": "C1",
                    "server": "S1", "parent_channel": "P1", "name": "a thread",
                    "creator": "U9" }),
                "a thread",
                "Thread",
            ),
        ];
        for (value, name, channel_type) in server_channels {
            let channel = decode(value);
            let draft = super::channel_delete_draft(&channel, "U1", Some("why".to_string()))
                .expect("a server channel is logged");
            assert_eq!(draft.server, "S1");
            assert_eq!(draft.actor.as_deref(), Some("U1"));
            assert_eq!(draft.action, AuditLogAction::ChannelDelete);
            assert_eq!(draft.target.as_deref(), Some("C1"));
            assert_eq!(draft.channel, None);
            assert_eq!(draft.changes, old_name_and_type(name, channel_type));
            assert_eq!(draft.count, None);
            assert_eq!(draft.reason.as_deref(), Some("why"));
        }

        for value in [
            serde_json::json!({ "channel_type": "SavedMessages", "_id": "C2", "user": "U1" }),
            serde_json::json!({ "channel_type": "DirectMessage", "_id": "C3",
                "active": true, "recipients": ["U1", "U2"] }),
            serde_json::json!({ "channel_type": "Group", "_id": "C4", "name": "pals",
                "owner": "U1", "recipients": ["U1", "U2"] }),
        ] {
            let channel = decode(value);
            assert!(
                super::channel_delete_draft(&channel, "U1", Some("why".to_string())).is_none(),
                "never logged: {:?}",
                channel
            );
        }
    }

    #[test]
    fn deleting_a_server_channel_writes_one_entry() {
        crate::util::test::rt().block_on(deleting_a_server_channel_writes_one_entry_case())
    }

    /// The owner deletes the server's text channel with a percent-encoded
    /// reason: the channel is gone, and the server holds exactly one entry,
    /// a `channel_delete` naming the owner and the channel, with the OLD name
    /// and type and the decoded reason.
    async fn deleting_a_server_channel_writes_one_entry_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (server, channels) = harness.new_server(&owner).await;
        let text = &channels[0];
        let name = match text {
            Channel::TextChannel { name, .. } => name.clone(),
            _ => unreachable!("the server's default text channel"),
        };

        let response = delete_channel(
            &harness,
            &session.token,
            text.id(),
            Some("old%20channel%3A%20unused"),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        assert!(!channel_exists(&harness, text.id()).await, "deleted");

        let entries = server_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), 1, "exactly one entry: {:?}", entries);
        let entry = &entries[0];
        assert_eq!(entry.server, server.id);
        assert_eq!(entry.action, AuditLogAction::ChannelDelete);
        assert_eq!(entry.actor.as_deref(), Some(owner.id.as_str()));
        assert_eq!(entry.target.as_deref(), Some(text.id()));
        assert_eq!(entry.channel, None);
        assert_eq!(entry.changes, old_name_and_type(&name, "Text"));
        assert_eq!(entry.count, None);
        assert_eq!(entry.reason.as_deref(), Some("old channel: unused"));
    }

    #[test]
    fn deleting_a_thread_or_a_forum_records_its_type() {
        crate::util::test::rt().block_on(deleting_a_thread_or_a_forum_records_its_type_case())
    }

    /// The other two server-channel arms: a thread (whose permissions come
    /// from its parent) and a forum each log one entry under the server,
    /// with their own old name and type, and no header means no reason.
    async fn deleting_a_thread_or_a_forum_records_its_type_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (mut server, channels) = harness.new_server(&owner).await;
        let thread = Channel::create_thread(
            &harness.db,
            &channels[0],
            &owner,
            None,
            v0::DataCreateThread {
                name: "audit-thread".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect("thread");
        let forum = Channel::create_server_channel(
            &harness.db,
            &mut server,
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Forum,
                name: "audit-forum".to_string(),
                ..Default::default()
            },
            false,
        )
        .await
        .expect("forum");

        for (channel, name, channel_type) in [
            (&thread, "audit-thread", "Thread"),
            (&forum, "audit-forum", "Forum"),
        ] {
            let response = delete_channel(&harness, &session.token, channel.id(), None).await;
            assert_eq!(response.status(), Status::NoContent);
            drop(response);
            assert!(!channel_exists(&harness, channel.id()).await, "deleted");

            let entries = delete_entries(&harness, &server.id, channel.id()).await;
            assert_eq!(entries.len(), 1, "exactly one entry: {:?}", entries);
            let entry = &entries[0];
            assert_eq!(entry.server, server.id);
            assert_eq!(entry.actor.as_deref(), Some(owner.id.as_str()));
            assert_eq!(entry.channel, None);
            assert_eq!(entry.changes, old_name_and_type(name, channel_type));
            assert_eq!(entry.reason, None);
        }

        assert_eq!(
            server_entries(&harness, &server.id).await.len(),
            2,
            "one entry per delete and nothing else"
        );
    }

    #[test]
    fn leaving_or_closing_a_group_or_dm_writes_no_entry() {
        crate::util::test::rt().block_on(leaving_or_closing_a_group_or_dm_writes_no_entry_case())
    }

    /// Every non-server arm, each with a reason header: a member leaving a
    /// group, the last member leaving (which deletes the group), closing a
    /// DM, and saved messages (NoEffect). None of them logs anywhere.
    async fn leaving_or_closing_a_group_or_dm_writes_no_entry_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;

        // A member leaves a group.
        let group = group_with(&harness, &owner, &member).await;
        let response =
            delete_channel(&harness, &member_session.token, group.id(), Some("leaving")).await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        assert!(
            !is_recipient(&harness, group.id(), &member.id).await,
            "left"
        );
        assert_eq!(entries_by_actor(&harness, &member.id).await, 0);

        // The last member leaves, which deletes the group.
        let lonely = Channel::create_group(
            &harness.db,
            DataCreateGroup {
                ..Default::default()
            },
            owner.id.clone(),
        )
        .await
        .expect("group");
        let response =
            delete_channel(&harness, &owner_session.token, lonely.id(), Some("closing")).await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        assert!(!channel_exists(&harness, lonely.id()).await, "deleted");
        assert_eq!(entries_by_actor(&harness, &owner.id).await, 0);

        // A DM is closed.
        let dm = Channel::create_dm(&harness.db, &owner, &member)
            .await
            .expect("dm");
        let response =
            delete_channel(&harness, &owner_session.token, dm.id(), Some("closing")).await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        assert!(
            matches!(
                harness.db.fetch_channel(dm.id()).await.expect("dm"),
                Channel::DirectMessage { active: false, .. }
            ),
            "closed"
        );
        assert_eq!(entries_by_actor(&harness, &owner.id).await, 0);

        // Saved messages cannot be closed. A user with no other channel: the
        // Reference driver's DM lookup returns ANY channel holding the user,
        // so `member` would get their DM back instead.
        let (_, loner_session, loner) = harness.new_user().await;
        let saved = Channel::create_dm(&harness.db, &loner, &loner)
            .await
            .expect("saved messages");
        assert!(
            matches!(saved, Channel::SavedMessages { .. }),
            "saved messages"
        );
        let response =
            delete_channel(&harness, &loner_session.token, saved.id(), Some("nope")).await;
        assert_eq!(response.status(), Status::BadRequest);
        let error: serde_json::Value = response.into_json().await.expect("error body");
        assert_eq!(error["type"], "NoEffect");
        assert!(channel_exists(&harness, saved.id()).await, "kept");
        assert_eq!(entries_by_actor(&harness, &loner.id).await, 0);

        for id in [group.id(), lonely.id(), dm.id(), saved.id(), ""] {
            assert!(server_entries(&harness, id).await.is_empty());
        }
    }

    #[test]
    fn a_refused_delete_writes_no_entry() {
        crate::util::test::rt().block_on(a_refused_delete_writes_no_entry_case())
    }

    /// A member without ManageChannel cannot delete a server channel: 403,
    /// the channel survives, nothing is logged.
    async fn a_refused_delete_writes_no_entry_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, session, member) = harness.new_user().await;
        let (server, channels) = harness.new_server(&owner).await;
        Member::create(&harness.db, &server, &member, None)
            .await
            .expect("member");

        let response = delete_channel(
            &harness,
            &session.token,
            channels[0].id(),
            Some("not%20mine"),
        )
        .await;
        assert_eq!(response.status(), Status::Forbidden);
        let error: serde_json::Value = response.into_json().await.expect("error body");
        assert_eq!(error["type"], "MissingPermission");
        assert!(channel_exists(&harness, channels[0].id()).await, "kept");

        assert_eq!(entries_by_actor(&harness, &member.id).await, 0);
        assert!(server_entries(&harness, &server.id).await.is_empty());
    }

    #[test]
    fn an_over_long_reason_is_refused_before_the_delete() {
        crate::util::test::rt().block_on(an_over_long_reason_is_refused_before_the_delete_case())
    }

    /// A 513-char reason is a 400 `AuditLogReasonTooLong` and nothing
    /// happened: the server channel still exists and nothing is logged. The
    /// reason is validated first, so a group leave carrying one is refused
    /// the same way and the member is still in the group.
    async fn an_over_long_reason_is_refused_before_the_delete_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (server, channels) = harness.new_server(&owner).await;
        let group = group_with(&harness, &owner, &member).await;
        let reason = "a".repeat(513);

        for (token, channel) in [
            (&owner_session.token, channels[0].id()),
            (&member_session.token, group.id()),
        ] {
            let response = delete_channel(&harness, token, channel, Some(&reason)).await;
            assert_eq!(response.status(), Status::BadRequest);
            let error: serde_json::Value = response.into_json().await.expect("error body");
            assert_eq!(error["type"], "FailedValidation");
            assert_eq!(error["error"], "AuditLogReasonTooLong");
            assert!(channel_exists(&harness, channel).await, "not deleted");
        }

        assert!(
            is_recipient(&harness, group.id(), &member.id).await,
            "not left"
        );
        assert!(server_entries(&harness, &server.id).await.is_empty());
        assert_eq!(entries_by_actor(&harness, &owner.id).await, 0);
        assert_eq!(entries_by_actor(&harness, &member.id).await, 0);
    }

    /// The reason is validated before the channel is even fetched; the entry
    /// is snapshotted before any delete; and each of the three server arms
    /// records only after its own delete succeeded, the text arm before its
    /// voice teardown. Mutations: validation moved after a delete (a 400
    /// after the channel is gone); the snapshot taken after the delete; an
    /// entry written before its delete (an entry for a delete that failed);
    /// the entry written after the voice teardown (lost when it fails).
    #[test]
    fn the_reason_is_validated_first_and_each_delete_records_after_it_succeeds() {
        const SOURCE: &str = include_str!("channel_delete.rs");
        let source = SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("the route precedes its tests");
        let route = &source[source
            .find("pub async fn delete(")
            .expect("the route is defined")..];
        let code = without_whitespace(&without_comments(route));

        let validated = statement_at(&code, "letreason=reason.validated()?;");
        let fetched = code
            .find("target.as_channel(db)")
            .expect("the channel is fetched");
        let snapshot = statement_at(
            &code,
            "letaudit=channel_delete_draft(&channel,&user.id,reason);",
        );
        assert!(validated < fetched, "validate before anything else");

        const DELETE: &str = "channel.delete(db).await?;";
        const RECORD: &str = "ifletSome(draft)=audit{AuditLogEntry::record(db,draft).await;}";
        let deletes: Vec<usize> = code.match_indices(DELETE).map(|(at, _)| at).collect();
        let records: Vec<usize> = code.match_indices(RECORD).map(|(at, _)| at).collect();
        assert_eq!(deletes.len(), 3, "one delete per server arm: {}", code);
        assert_eq!(records.len(), 3, "one record per server arm: {}", code);
        assert_eq!(
            code.matches("AuditLogEntry::record(").count(),
            3,
            "no record outside the three pinned: {}",
            code
        );
        assert!(snapshot < deletes[0], "snapshot before any delete");
        for arm in 0..3 {
            assert!(
                deletes[arm] < records[arm],
                "arm {}: record after its delete",
                arm
            );
            if let Some(next) = deletes.get(arm + 1) {
                assert!(
                    records[arm] < *next,
                    "arm {}: record inside its own arm",
                    arm
                );
            }
        }

        let text_arm = code
            .find("Channel::TextChannel{..}=>")
            .expect("the text arm");
        let teardown = code
            .find("delete_voice_channel(")
            .expect("the voice teardown");
        assert!(
            text_arm < deletes[0],
            "the first server arm is the text arm"
        );
        assert!(
            records[0] < teardown && teardown < deletes[1],
            "the text arm records before its voice teardown"
        );
    }
}
