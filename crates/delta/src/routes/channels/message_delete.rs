use revolt_database::{
    util::{
        audit_reason::AuditLogReason, permissions::DatabasePermissionQuery, reference::Reference,
    },
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Database, User,
};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::Result;
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Delete Message
///
/// Delete a message you've sent or one you have permission to delete.
#[openapi(tag = "Messaging")]
#[delete("/<target>/messages/<msg>", rank = 2)]
pub async fn delete(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
    reason: AuditLogReason,
) -> Result<EmptyResponse> {
    // Reject an over-long reason before anything is deleted.
    let reason = reason.validated()?;

    let message = msg.as_message_in_channel(db, target.id).await?;

    // The server a moderator's delete is audited in. `None` for your own
    // message, and for DMs, groups and saved messages, which never log.
    let audit_server = if message.author != user.id {
        let channel = target.as_channel(db).await?;
        // Threads inherit their parent channel's permission overrides.
        let permission_channel = channel.permission_target(db).await?.into_owned();
        let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
        calculate_channel_permissions(&mut query)
            .await
            .throw_if_lacking_channel_permission(ChannelPermission::ManageMessages)?;

        // A thread's server is its parent's.
        permission_channel.server().map(String::from)
    } else {
        None
    };

    let message_id = message.id.clone();
    let author = message.author.clone();
    let channel_id = message.channel.clone();
    message.delete(db).await?;

    if let Some(server) = audit_server {
        // Ids only: the message content is never recorded.
        AuditLogEntry::record(
            db,
            AuditLogDraft {
                server,
                actor: Some(user.id.clone()),
                action: AuditLogAction::MessageDelete,
                target: Some(author),
                channel: Some(channel_id),
                changes: vec![AuditLogChange::new(
                    "message",
                    None,
                    Some(AuditValue::String(message_id)),
                )],
                reason,
                ..Default::default()
            },
        )
        .await;
    }

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::util::test::{statement_at, without_comments, without_whitespace, TestHarness};
    use revolt_database::{
        mongodb::bson::{doc, Document},
        AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, Channel, Database, Member,
        Message, PartialMember, Server, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};

    // ---- behavior (needs RabbitMQ and Redis, like every route test) --------

    const CONTENT: &str = "message content the audit log must never hold";

    /// A message stored as it is, with no send path and no events.
    #[allow(clippy::disallowed_methods)] // a test fixture, stored directly like test_fixtures does
    async fn stored_message(harness: &TestHarness, channel: &str, author: &str) -> String {
        let id = ulid::Ulid::new().to_string();
        harness
            .db
            .insert_message(&Message {
                id: id.clone(),
                channel: channel.to_string(),
                author: author.to_string(),
                content: Some(CONTENT.to_string()),
                ..Default::default()
            })
            .await
            .expect("message");
        id
    }

    async fn delete_message<'a>(
        harness: &'a TestHarness,
        token: &str,
        channel: &str,
        message: &str,
        reason: Option<&str>,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        let mut request = harness
            .client
            .delete(format!("/channels/{channel}/messages/{message}"))
            .header(Header::new("x-session-token", token.to_string()));
        if let Some(reason) = reason {
            request = request.header(Header::new("X-Audit-Log-Reason", reason.to_string()));
        }
        request.dispatch().await
    }

    async fn message_exists(harness: &TestHarness, id: &str) -> bool {
        harness.db.fetch_message(id).await.is_ok()
    }

    async fn server_entries(harness: &TestHarness, server: &str) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(server, None, 50, None, None)
            .await
            .expect("audit log")
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

    struct ServerFixture {
        server: Server,
        text: Channel,
        moderator: User,
        moderator_token: String,
        author: User,
        author_token: String,
        member: User,
        member_token: String,
    }

    /// An owner's server with its default text channel; a moderator who holds
    /// ManageMessages through a role and nothing else beyond the defaults;
    /// the author of the messages; and a plain member with the defaults only.
    async fn server_fixture(harness: &TestHarness) -> ServerFixture {
        let (_, _, owner) = harness.new_user().await;
        let (_, moderator_session, moderator) = harness.new_user().await;
        let (_, author_session, author) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (server, channels) = harness.new_server(&owner).await;
        for user in [&moderator, &author, &member] {
            Member::create(&harness.db, &server, user, None)
                .await
                .expect("member");
        }

        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::ManageMessages as i64,
                    d: 0,
                }),
            )
            .await;
        let mut moderator_member = harness
            .db
            .fetch_member(&server.id, &moderator.id)
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

        let text = channels
            .into_iter()
            .find(|channel| matches!(channel, Channel::TextChannel { .. }))
            .expect("the server's default text channel");

        ServerFixture {
            server,
            text,
            moderator,
            moderator_token: moderator_session.token,
            author,
            author_token: author_session.token,
            member,
            member_token: member_session.token,
        }
    }

    #[test]
    fn a_moderator_delete_writes_one_entry() {
        crate::util::test::rt().block_on(a_moderator_delete_writes_one_entry_case())
    }

    /// A moderator deletes another member's message in a server channel: one
    /// `message_delete` entry naming the moderator, the author, the channel
    /// and the message id, with the percent-decoded reason, and no content.
    async fn a_moderator_delete_writes_one_entry_case() {
        let harness = TestHarness::new().await;
        let f = server_fixture(&harness).await;
        let message = stored_message(&harness, f.text.id(), &f.author.id).await;

        let response = delete_message(
            &harness,
            &f.moderator_token,
            f.text.id(),
            &message,
            Some("rule%201%3A%20no%20spam"),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        assert!(!message_exists(&harness, &message).await, "deleted");

        let entries = server_entries(&harness, &f.server.id).await;
        assert_eq!(entries.len(), 1, "exactly one entry: {entries:?}");
        let entry = &entries[0];
        assert_eq!(entry.server, f.server.id);
        assert_eq!(entry.action, AuditLogAction::MessageDelete);
        assert_eq!(entry.actor.as_deref(), Some(f.moderator.id.as_str()));
        assert_eq!(entry.target.as_deref(), Some(f.author.id.as_str()));
        assert_eq!(entry.channel.as_deref(), Some(f.text.id()));
        assert_eq!(
            entry.changes,
            vec![AuditLogChange::new(
                "message",
                None,
                Some(AuditValue::String(message.clone())),
            )]
        );
        assert_eq!(entry.count, None);
        assert_eq!(entry.reason.as_deref(), Some("rule 1: no spam"));
        assert!(
            !serde_json::to_string(entry)
                .expect("serialize")
                .contains(CONTENT),
            "the entry must never hold the message content"
        );
    }

    #[test]
    fn a_moderator_delete_in_a_thread_logs_under_the_server() {
        crate::util::test::rt()
            .block_on(a_moderator_delete_in_a_thread_logs_under_the_server_case())
    }

    /// A message in a thread: the entry lands in the thread's server (found
    /// through the parent channel the route resolves for permissions), its
    /// channel is the thread itself, and no header means no reason.
    async fn a_moderator_delete_in_a_thread_logs_under_the_server_case() {
        let harness = TestHarness::new().await;
        let f = server_fixture(&harness).await;
        let thread = Channel::create_thread(
            &harness.db,
            &f.text,
            &f.author,
            None,
            v0::DataCreateThread {
                name: "audit-thread".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect("thread");
        let message = stored_message(&harness, thread.id(), &f.author.id).await;

        let response =
            delete_message(&harness, &f.moderator_token, thread.id(), &message, None).await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        assert!(!message_exists(&harness, &message).await, "deleted");

        let entries = server_entries(&harness, &f.server.id).await;
        assert_eq!(entries.len(), 1, "exactly one entry: {entries:?}");
        let entry = &entries[0];
        assert_eq!(entry.action, AuditLogAction::MessageDelete);
        assert_eq!(entry.actor.as_deref(), Some(f.moderator.id.as_str()));
        assert_eq!(entry.target.as_deref(), Some(f.author.id.as_str()));
        assert_eq!(entry.channel.as_deref(), Some(thread.id()));
        assert_eq!(
            entry.changes,
            vec![AuditLogChange::new(
                "message",
                None,
                Some(AuditValue::String(message.clone())),
            )]
        );
        assert_eq!(entry.reason, None);
    }

    #[test]
    fn deleting_your_own_message_writes_no_entry() {
        crate::util::test::rt().block_on(deleting_your_own_message_writes_no_entry_case())
    }

    /// Own-message deletes never log, with or without a reason, and whether
    /// or not the deleter holds ManageMessages.
    async fn deleting_your_own_message_writes_no_entry_case() {
        let harness = TestHarness::new().await;
        let f = server_fixture(&harness).await;

        for (user, token) in [
            (&f.author, &f.author_token),
            (&f.moderator, &f.moderator_token),
        ] {
            let message = stored_message(&harness, f.text.id(), &user.id).await;
            let response = delete_message(
                &harness,
                token,
                f.text.id(),
                &message,
                Some("cleaning%20up"),
            )
            .await;
            assert_eq!(response.status(), Status::NoContent);
            drop(response);
            assert!(!message_exists(&harness, &message).await, "deleted");
            assert_eq!(entries_by_actor(&harness, &user.id).await, 0);
        }

        assert!(server_entries(&harness, &f.server.id).await.is_empty());
    }

    #[test]
    fn a_group_delete_writes_no_entry() {
        crate::util::test::rt().block_on(a_group_delete_writes_no_entry_case())
    }

    /// The group owner (GrantAllSafe in their group) deletes a member's
    /// message: the delete succeeds, so this is the actor-is-not-the-author
    /// path, and still nothing is logged anywhere.
    async fn a_group_delete_writes_no_entry_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, author) = harness.new_user().await;
        let group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                users: vec![author.id.clone()].into_iter().collect(),
                ..Default::default()
            },
            owner.id.clone(),
        )
        .await
        .expect("group");
        let message = stored_message(&harness, group.id(), &author.id).await;

        let response = delete_message(
            &harness,
            &owner_session.token,
            group.id(),
            &message,
            Some("group%20cleanup"),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        assert!(!message_exists(&harness, &message).await, "deleted");

        assert_eq!(entries_by_actor(&harness, &owner.id).await, 0);
        assert!(server_entries(&harness, group.id()).await.is_empty());
        assert!(server_entries(&harness, "").await.is_empty());
    }

    #[test]
    fn a_refused_delete_writes_no_entry() {
        crate::util::test::rt().block_on(a_refused_delete_writes_no_entry_case())
    }

    /// A member without ManageMessages cannot delete someone else's message:
    /// 403, the message survives, nothing is logged.
    async fn a_refused_delete_writes_no_entry_case() {
        let harness = TestHarness::new().await;
        let f = server_fixture(&harness).await;
        let message = stored_message(&harness, f.text.id(), &f.author.id).await;

        let response = delete_message(
            &harness,
            &f.member_token,
            f.text.id(),
            &message,
            Some("not%20mine"),
        )
        .await;
        assert_eq!(response.status(), Status::Forbidden);
        let error: serde_json::Value = response.into_json().await.expect("error body");
        assert_eq!(error["type"], "MissingPermission");
        assert!(message_exists(&harness, &message).await, "not deleted");

        assert_eq!(entries_by_actor(&harness, &f.member.id).await, 0);
        assert!(server_entries(&harness, &f.server.id).await.is_empty());
    }

    #[test]
    fn an_over_long_reason_is_refused_before_the_delete() {
        crate::util::test::rt().block_on(an_over_long_reason_is_refused_before_the_delete_case())
    }

    /// A 513-char reason is a 400 `AuditLogReasonTooLong`, and the message
    /// is still there: the reason is validated before the delete. Checked
    /// for the moderator path and the own-message path.
    async fn an_over_long_reason_is_refused_before_the_delete_case() {
        let harness = TestHarness::new().await;
        let f = server_fixture(&harness).await;
        let reason = "a".repeat(513);

        for (author, token) in [
            (&f.author, &f.moderator_token),
            (&f.author, &f.author_token),
        ] {
            let message = stored_message(&harness, f.text.id(), &author.id).await;
            let response =
                delete_message(&harness, token, f.text.id(), &message, Some(&reason)).await;
            assert_eq!(response.status(), Status::BadRequest);
            let error: serde_json::Value = response.into_json().await.expect("error body");
            assert_eq!(error["type"], "FailedValidation");
            assert_eq!(error["error"], "AuditLogReasonTooLong");
            assert!(message_exists(&harness, &message).await, "not deleted");
        }

        assert!(server_entries(&harness, &f.server.id).await.is_empty());
    }

    // ---- the route's text --------------------------------------------------

    /// The reason is validated before the delete, and the entry is written
    /// only after the delete succeeded. Mutations: validation moved after the
    /// delete (a 400 after the message is gone); the entry written first (an
    /// entry for a delete that then failed).
    #[test]
    fn the_reason_is_validated_before_and_the_entry_written_after_the_delete() {
        const SOURCE: &str = include_str!("message_delete.rs");
        let route = SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("the route precedes its tests");
        let code = without_whitespace(&without_comments(route));

        let validated = statement_at(&code, "letreason=reason.validated()?;");
        let fetched = code
            .find("msg.as_message_in_channel(")
            .expect("the message is fetched");
        let deleted = statement_at(&code, "message.delete(db).await?;");
        assert_eq!(code.matches("AuditLogEntry::record(").count(), 1);
        let recorded = code
            .find("AuditLogEntry::record(")
            .expect("the entry is written");

        assert!(validated < fetched, "validate before any work");
        assert!(fetched < deleted);
        assert!(deleted < recorded, "the entry follows a successful delete");
    }
}
