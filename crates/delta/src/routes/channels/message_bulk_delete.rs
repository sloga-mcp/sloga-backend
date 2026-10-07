use std::convert::TryFrom;
use std::time::Duration;

use revolt_database::util::audit_reason::AuditLogReason;
use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    AuditLogAction, AuditLogDraft, AuditLogEntry, Database, Message, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;
use validator::Validate;

/// # Bulk Delete Messages
///
/// Delete multiple messages you've sent or one you have permission to delete.
///
/// This will always require `ManageMessages` permission regardless of whether you own the message or not.
///
/// Messages must have been sent within the past 1 week.
#[openapi(tag = "Messaging")]
#[delete("/<target>/messages/bulk", data = "<options>", rank = 1)]
pub async fn bulk_delete_messages(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    options: Json<v0::OptionsBulkDelete>,
    reason: AuditLogReason,
) -> Result<EmptyResponse> {
    let options = options.into_inner();
    options.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Before anything is deleted: a too-long reason must never surface as a
    // 400 after the messages are already gone.
    let reason = reason.validated()?;

    // The audit count is the number of ids in the validated request (at most
    // 100), NOT the number of messages actually deleted: `Message::bulk_delete`
    // silently skips ids that do not exist or belong to another channel.
    let requested = u32::try_from(options.ids.len()).unwrap_or(u32::MAX);

    for id in &options.ids {
        if ulid::Ulid::from_string(id)
            .map_err(|_| create_error!(InvalidOperation))?
            .datetime()
            .elapsed()
            .expect("Time went backwards")
            > Duration::from_hours(7 * 24)  // 7 days
        {
            return Err(create_error!(InvalidOperation));
        }
    }

    let channel = target.as_channel(db).await?;
    // Threads inherit their parent channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageMessages)?;

    Message::bulk_delete(db, target.id, options.ids).await?;

    // Server channels only (text, thread, forum all carry their server id).
    // DMs, groups and saved messages are never audit-logged.
    if let Some(server) = channel.server() {
        AuditLogEntry::record(
            db,
            AuditLogDraft {
                server: server.to_string(),
                actor: Some(user.id.clone()),
                action: AuditLogAction::MessageBulkDelete,
                channel: Some(channel.id().to_string()),
                count: Some(requested),
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
    use revolt_database::{AuditLogAction, Channel, Member};
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::{json, Value};

    async fn send(harness: &TestHarness, token: &str, channel: &str) -> String {
        let response = harness
            .client
            .post(format!("/channels/{channel}/messages"))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "content": "to be deleted" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let message: v0::Message = response.into_json().await.expect("`Message`");
        message.id
    }

    async fn bulk_delete(
        harness: &TestHarness,
        token: &str,
        channel: &str,
        ids: &[String],
        reason: Option<&str>,
    ) -> (Status, String) {
        let mut request = harness
            .client
            .delete(format!("/channels/{channel}/messages/bulk"))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "ids": ids }).to_string());
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

    #[test]
    fn bulk_delete_records_one_audit_entry() {
        crate::util::test::rt().block_on(bulk_delete_records_one_audit_entry_case())
    }

    async fn bulk_delete_records_one_audit_entry_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let token = session.token.to_string();

        let first = send(&harness, &token, channel.id()).await;
        let second = send(&harness, &token, channel.id()).await;
        let kept = send(&harness, &token, channel.id()).await;
        // A recent, well-formed id that matches no message. It is requested
        // (so it counts) but nothing is deleted for it.
        let missing = ulid::Ulid::new().to_string();

        let (status, body) = bulk_delete(
            &harness,
            &token,
            channel.id(),
            &[first.clone(), second.clone(), missing],
            Some("spam%20cleanup"),
        )
        .await;
        assert_eq!(status, Status::NoContent, "{body}");

        assert!(harness.db.fetch_message(&first).await.is_err());
        assert!(harness.db.fetch_message(&second).await.is_err());
        assert!(harness.db.fetch_message(&kept).await.is_ok());

        let entries = harness
            .db
            .fetch_audit_log(&server.id, None, 50, None, None)
            .await
            .expect("audit log");
        assert_eq!(entries.len(), 1, "{entries:?}");
        let entry = &entries[0];
        assert_eq!(entry.server, server.id);
        assert_eq!(entry.action, AuditLogAction::MessageBulkDelete);
        assert_eq!(entry.actor.as_deref(), Some(user.id.as_str()));
        assert_eq!(entry.target, None);
        assert_eq!(entry.channel.as_deref(), Some(channel.id()));
        // Requested ids, not confirmed deletions: the unknown id counts.
        assert_eq!(entry.count, Some(3));
        assert!(entry.changes.is_empty(), "{:?}", entry.changes);
        assert_eq!(entry.reason.as_deref(), Some("spam cleanup"));
    }

    #[test]
    fn too_long_reason_is_rejected_before_deleting() {
        crate::util::test::rt().block_on(too_long_reason_is_rejected_before_deleting_case())
    }

    async fn too_long_reason_is_rejected_before_deleting_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let token = session.token.to_string();

        let message = send(&harness, &token, channel.id()).await;
        let reason = "a".repeat(513);

        let (status, body) = bulk_delete(
            &harness,
            &token,
            channel.id(),
            &[message.clone()],
            Some(&reason),
        )
        .await;
        assert_eq!(status, Status::BadRequest, "{body}");
        let error = error_body(&body);
        assert_eq!(error["type"], "FailedValidation");
        assert_eq!(error["error"], "AuditLogReasonTooLong");

        assert!(
            harness.db.fetch_message(&message).await.is_ok(),
            "nothing may be deleted when the reason is rejected"
        );
        let entries = harness
            .db
            .fetch_audit_log(&server.id, None, 50, None, None)
            .await
            .expect("audit log");
        assert!(entries.is_empty(), "{entries:?}");
    }

    #[test]
    fn refused_bulk_delete_records_nothing() {
        crate::util::test::rt().block_on(refused_bulk_delete_records_nothing_case())
    }

    async fn refused_bulk_delete_records_nothing_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let channel = harness.new_channel(&server).await;
        Member::create(&harness.db, &server, &member, None)
            .await
            .expect("member");

        let message = send(&harness, &owner_session.token, channel.id()).await;

        // A plain member has no ManageMessages.
        let (status, body) = bulk_delete(
            &harness,
            &member_session.token,
            channel.id(),
            &[message.clone()],
            Some("not%20allowed"),
        )
        .await;
        assert_eq!(status, Status::Forbidden, "{body}");
        assert_eq!(error_body(&body)["type"], "MissingPermission");

        assert!(harness.db.fetch_message(&message).await.is_ok());
        let entries = harness
            .db
            .fetch_audit_log(&server.id, None, 50, None, None)
            .await
            .expect("audit log");
        assert!(entries.is_empty(), "{entries:?}");
    }

    #[test]
    fn group_bulk_delete_records_nothing() {
        crate::util::test::rt().block_on(group_bulk_delete_records_nothing_case())
    }

    async fn group_bulk_delete_records_nothing_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let token = session.token.to_string();
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

        let message = send(&harness, &token, group.id()).await;

        // The group owner holds ManageMessages, so the delete goes through,
        // but a group is not a server channel and is never audit-logged.
        let (status, body) = bulk_delete(
            &harness,
            &token,
            group.id(),
            &[message.clone()],
            Some("group%20cleanup"),
        )
        .await;
        assert_eq!(status, Status::NoContent, "{body}");
        assert!(harness.db.fetch_message(&message).await.is_err());

        let entries = harness
            .db
            .fetch_audit_log(group.id(), None, 50, None, None)
            .await
            .expect("audit log");
        assert!(entries.is_empty(), "{entries:?}");
    }
}
