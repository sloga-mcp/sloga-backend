use revolt_database::util::audit_reason::AuditLogReason;
use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    AuditLogAction, AuditLogDraft, AuditLogEntry, Database, User,
};
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::Result;
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Unban user
///
/// Remove a user's ban.
#[openapi(tag = "Server Members")]
#[delete("/<server>/bans/<target>")]
pub async fn unban(
    db: &State<Database>,
    user: User,
    server: Reference<'_>,
    target: Reference<'_>,
    reason: AuditLogReason,
) -> Result<EmptyResponse> {
    // Refuse an over-long reason before anything is removed.
    let reason = reason.validated()?;

    let server = server.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::BanMembers)?;

    let ban = target.as_ban(db, &server.id).await?;
    db.delete_ban(&ban.id).await?;

    if ban.id.user != user.id {
        AuditLogEntry::record(
            db,
            AuditLogDraft {
                server: server.id.clone(),
                actor: Some(user.id.clone()),
                action: AuditLogAction::MemberBanRemove,
                target: Some(ban.id.user.clone()),
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
    use crate::util::test::TestHarness;
    use revolt_database::{
        util::audit_reason::{AUDIT_LOG_REASON_HEADER, AUDIT_LOG_REASON_MAX_CHARS},
        AuditLogAction, AuditLogEntry, Member, Server, ServerBan, Session,
    };
    use revolt_result::ErrorType;
    use rocket::http::{Header, Status};
    use serde_json::Value;

    // Compile-only without RabbitMQ: `TestHarness::new` connects to it, like
    // every other route test. Driven on the shared runtime like the other
    // `servers/` route tests.

    /// DELETE the ban; returns the status and the raw JSON body (Null when
    /// the answer has no body).
    async fn unban(
        harness: &TestHarness,
        session: &Session,
        server: &Server,
        target_id: &str,
        reason: Option<&str>,
    ) -> (Status, Value) {
        let mut request = harness
            .client
            .delete(format!("/servers/{}/bans/{}", server.id, target_id))
            .header(Header::new("x-session-token", session.token.to_string()));
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

    async fn assert_banned(harness: &TestHarness, server: &Server, user_id: &str, what: &str) {
        assert!(
            harness.db.fetch_ban(&server.id, user_id).await.is_ok(),
            "{}: the ban must still exist",
            what
        );
    }

    async fn assert_not_banned(harness: &TestHarness, server: &Server, user_id: &str) {
        let ban = harness.db.fetch_ban(&server.id, user_id).await;
        assert!(
            matches!(&ban, Err(error) if matches!(error.error_type, ErrorType::NotFound)),
            "the ban must be gone: {:?}",
            ban
        );
    }

    #[test]
    fn an_unban_writes_one_member_ban_remove_entry() {
        crate::util::test::rt().block_on(an_unban_writes_one_member_ban_remove_entry_case())
    }

    /// The owner lifts a ban with a percent-encoded reason header: the ban is
    /// gone and exactly one `member_ban_remove` entry is written, actor = the
    /// session user, target = the unbanned user, no channel, no changes, the
    /// reason decoded. A second unban without the header logs no reason.
    async fn an_unban_writes_one_member_ban_remove_entry_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, banned) = harness.new_user().await;
        let (_, _, other) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        for user_id in [&banned.id, &other.id] {
            ServerBan::create(&harness.db, &server, user_id, Some("spam".to_string()))
                .await
                .expect("ban");
        }

        let (status, body) = unban(
            &harness,
            &owner_session,
            &server,
            &banned.id,
            Some("appeal%20accepted%3A%20rule%201"),
        )
        .await;
        assert_eq!(status, Status::NoContent, "body: {body}");
        assert_not_banned(&harness, &server, &banned.id).await;

        let entries = audit_log(&harness, &server).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        let entry = &entries[0];
        assert_eq!(entry.server, server.id);
        assert_eq!(entry.action, AuditLogAction::MemberBanRemove);
        assert_eq!(entry.actor.as_deref(), Some(owner.id.as_str()));
        assert_eq!(entry.target.as_deref(), Some(banned.id.as_str()));
        assert_eq!(entry.channel, None);
        assert!(entry.changes.is_empty(), "{:?}", entry);
        assert_eq!(entry.count, None);
        assert_eq!(entry.reason.as_deref(), Some("appeal accepted: rule 1"));

        let (status, body) = unban(&harness, &owner_session, &server, &other.id, None).await;
        assert_eq!(status, Status::NoContent, "body: {body}");
        let entries = audit_log(&harness, &server).await;
        assert_eq!(entries.len(), 2, "{entries:?}");
        // Picked by target, not position: two ULIDs minted in the same
        // millisecond do not sort by mint order on the reference driver.
        let second = entries
            .iter()
            .find(|entry| entry.target.as_deref() == Some(other.id.as_str()))
            .expect("an entry for the second unban");
        assert_eq!(second.action, AuditLogAction::MemberBanRemove);
        assert_eq!(second.actor.as_deref(), Some(owner.id.as_str()));
        assert_eq!(second.reason, None, "no header, no reason");
    }

    #[test]
    fn an_overlong_reason_is_refused_and_the_ban_stands() {
        crate::util::test::rt().block_on(an_overlong_reason_is_refused_and_the_ban_stands_case())
    }

    /// A reason one char over the limit is refused with
    /// FailedValidation/AuditLogReasonTooLong BEFORE the delete: the ban still
    /// exists and nothing is logged. Mutation: the `validated()?` moved below
    /// the delete.
    async fn an_overlong_reason_is_refused_and_the_ban_stands_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, banned) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        ServerBan::create(&harness.db, &server, &banned.id, None)
            .await
            .expect("ban");

        let reason = "a".repeat(AUDIT_LOG_REASON_MAX_CHARS + 1);
        let (status, body) =
            unban(&harness, &owner_session, &server, &banned.id, Some(&reason)).await;
        assert_eq!(status, Status::BadRequest, "body: {body}");
        assert_eq!(body["type"], "FailedValidation", "body: {body}");
        assert_eq!(body["error"], "AuditLogReasonTooLong", "body: {body}");

        assert_banned(&harness, &server, &banned.id, "a refused unban").await;
        assert!(audit_log(&harness, &server).await.is_empty());
    }

    #[test]
    fn a_member_without_ban_members_is_refused_and_nothing_is_logged() {
        crate::util::test::rt()
            .block_on(a_member_without_ban_members_is_refused_and_nothing_is_logged_case())
    }

    /// A member lacking BanMembers is refused with MissingPermission; the ban
    /// stands and no entry is written.
    async fn a_member_without_ban_members_is_refused_and_nothing_is_logged_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, _, banned) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        Member::create(&harness.db, &server, &member, None)
            .await
            .expect("member");
        ServerBan::create(&harness.db, &server, &banned.id, None)
            .await
            .expect("ban");

        let (status, body) = unban(
            &harness,
            &member_session,
            &server,
            &banned.id,
            Some("not%20allowed"),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "body: {body}");
        assert_eq!(body["type"], "MissingPermission", "body: {body}");

        assert_banned(&harness, &server, &banned.id, "an unauthorized unban").await;
        assert!(audit_log(&harness, &server).await.is_empty());
    }

    #[test]
    fn unbanning_a_user_who_is_not_banned_logs_nothing() {
        crate::util::test::rt().block_on(unbanning_a_user_who_is_not_banned_logs_nothing_case())
    }

    /// No ban to remove: the lookup answers NotFound and no entry is written.
    async fn unbanning_a_user_who_is_not_banned_logs_nothing_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, stranger) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;

        let (status, body) = unban(
            &harness,
            &owner_session,
            &server,
            &stranger.id,
            Some("nothing%20to%20lift"),
        )
        .await;
        assert_eq!(status, Status::NotFound, "body: {body}");
        assert_eq!(body["type"], "NotFound", "body: {body}");
        assert!(audit_log(&harness, &server).await.is_empty());
    }

    #[test]
    fn lifting_a_ban_on_yourself_logs_nothing() {
        crate::util::test::rt().block_on(lifting_a_ban_on_yourself_logs_nothing_case())
    }

    /// Self-actions are not logged. The ban route refuses self-bans, so the
    /// row is seeded directly; the unban still succeeds, without an entry.
    async fn lifting_a_ban_on_yourself_logs_nothing_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        ServerBan::create(&harness.db, &server, &owner.id, None)
            .await
            .expect("ban");

        let (status, body) = unban(&harness, &owner_session, &server, &owner.id, None).await;
        assert_eq!(status, Status::NoContent, "body: {body}");
        assert_not_banned(&harness, &server, &owner.id).await;
        assert!(audit_log(&harness, &server).await.is_empty());
    }
}
