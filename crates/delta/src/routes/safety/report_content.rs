use revolt_database::{events::client::EventV1, Database, Report, Snapshot, SnapshotContent, User};
use revolt_models::v0::{ReportStatus, ReportedContent, ReportedMessageSnapshot};
use revolt_result::{create_error, Result};
use rocket_empty::EmptyResponse;
use serde::Deserialize;
use ulid::Ulid;
use validator::Validate;

use rocket::{serde::json::Json, State};

/// Maximum number of context messages accepted in a reporter snapshot
const MAX_CONTEXT_MESSAGES: usize = 32;

/// Maximum accepted length of a single snapshotted message's content
const MAX_SNAPSHOT_CONTENT: usize = 8192;

/// # Message Snapshot Data
///
/// Copy of the reported message and surrounding context as seen on the
/// reporter's device. This stands alone from server-side data so reports
/// keep working for conversations the server cannot read (E2EE).
#[derive(Deserialize, JsonSchema)]
pub struct DataMessageSnapshot {
    /// The reported message
    message: ReportedMessageSnapshot,
    /// Surrounding messages (before and after), ordered by id
    #[serde(default)]
    context: Vec<ReportedMessageSnapshot>,
}

/// # Report Data
#[derive(Validate, Deserialize, JsonSchema)]
pub struct DataReportContent {
    /// Content being reported
    content: ReportedContent,
    /// Additional report description
    #[validate(length(min = 0, max = 1000))]
    #[serde(default)]
    additional_context: String,
    /// Reporter-supplied snapshot of the reported message and its context.
    ///
    /// Required when reporting a message; optional supporting context when
    /// reporting a user.
    #[serde(default)]
    message_snapshot: Option<DataMessageSnapshot>,
}

fn validate_snapshot(snapshot: &DataMessageSnapshot) -> Result<()> {
    if snapshot.context.len() > MAX_CONTEXT_MESSAGES {
        return Err(create_error!(FailedValidation {
            error: format!("snapshot context is limited to {MAX_CONTEXT_MESSAGES} messages")
        }));
    }

    if std::iter::once(&snapshot.message)
        .chain(snapshot.context.iter())
        .any(|message| message.content.len() > MAX_SNAPSHOT_CONTENT)
    {
        return Err(create_error!(FailedValidation {
            error: format!("snapshotted message content is limited to {MAX_SNAPSHOT_CONTENT} characters")
        }));
    }

    Ok(())
}

/// # Report Content
///
/// Report a piece of content to the moderation team.
#[openapi(tag = "User Safety")]
#[post("/report", data = "<data>")]
pub async fn report_content(
    db: &State<Database>,
    user: User,
    data: Json<DataReportContent>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    if let Some(snapshot) = &data.message_snapshot {
        validate_snapshot(snapshot)?;
    }

    // Bots cannot create reports
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // Find the content and create a snapshot of it
    // Also retrieve any references to Files
    let (snapshots, files): (Vec<SnapshotContent>, Vec<String>) = match &data.content {
        ReportedContent::Message { id, .. } => {
            // The reporter-supplied snapshot is the authoritative copy: it
            // must be present and must describe the message being reported.
            let client_snapshot = data.message_snapshot.as_ref().ok_or_else(|| {
                create_error!(FailedValidation {
                    error: "message_snapshot is required when reporting a message".to_string()
                })
            })?;

            if &client_snapshot.message.id != id {
                return Err(create_error!(FailedValidation {
                    error: "message_snapshot must describe the reported message".to_string()
                }));
            }

            // Users cannot report themselves
            if client_snapshot.message.author == user.id {
                return Err(create_error!(CannotReportYourself));
            }

            let mut snapshots = vec![SnapshotContent::ReporterMessage {
                message: client_snapshot.message.clone(),
                context: client_snapshot.context.clone(),
            }];

            // Additionally snapshot server-readable content when available.
            // Best-effort: the report must go through even if the server
            // cannot read the message (E2EE) or it was already deleted.
            let mut files = vec![];
            if let Ok(message) = db.fetch_message(id).await {
                if message.author == user.id {
                    return Err(create_error!(CannotReportYourself));
                }

                let (snapshot, message_files) =
                    SnapshotContent::generate_from_message(db, message).await?;
                snapshots.push(snapshot);
                files = message_files;
            }

            (snapshots, files)
        }
        ReportedContent::Server { id, .. } => {
            let server = db.fetch_server(id).await?;

            // Users cannot report their own server
            if server.owner == user.id {
                return Err(create_error!(CannotReportYourself));
            }

            let (snapshot, files) = SnapshotContent::generate_from_server(server)?;
            (vec![snapshot], files)
        }
        ReportedContent::User { id, message_id, .. } => {
            let reported_user = db.fetch_user(id).await?;

            // Users cannot report themselves
            if reported_user.id == user.id {
                return Err(create_error!(CannotReportYourself));
            }

            // Determine if there is a message provided as context
            let message = if let Some(id) = message_id {
                db.fetch_message(id).await.ok()
            } else {
                None
            };

            let (snapshot, files) = SnapshotContent::generate_from_user(reported_user)?;

            let mut snapshots = vec![snapshot];
            let mut files = files;

            // Attach any reporter-supplied message context
            if let Some(client_snapshot) = &data.message_snapshot {
                snapshots.push(SnapshotContent::ReporterMessage {
                    message: client_snapshot.message.clone(),
                    context: client_snapshot.context.clone(),
                });
            }

            if let Some(message) = message {
                let (message_snapshot, message_files) =
                    SnapshotContent::generate_from_message(db, message).await?;
                snapshots.push(message_snapshot);
                files = [files, message_files].concat();
            }

            (snapshots, files)
        }
    };

    // Mark all the attachments as reported
    for file in files {
        db.mark_attachment_as_reported(&file).await?;
    }

    // Generate an id for the report
    let id = Ulid::new().to_string();

    // Insert all new generated snapshots
    for content in snapshots {
        // Save a snapshot of the content
        let snapshot = Snapshot {
            id: Ulid::new().to_string(),
            report_id: id.to_string(),
            content,
        };

        db.insert_snapshot(&snapshot).await?;
    }

    // Save the report
    let report = Report {
        id,
        author_id: user.id,
        content: data.content,
        additional_context: data.additional_context,
        status: ReportStatus::Created {},
        notes: String::new(),
    };

    db.insert_report(&report).await?;

    // Broadcast on the "global" topic. Privileged (moderator) sessions
    // subscribe to this topic in bonfire, so their connected clients receive
    // the report live and can raise a notification + queue badge. The event
    // is content-free beyond the report metadata, safe for E2EE reports.
    EventV1::ReportCreate(report.into()).global().await;

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{PartialUser, SnapshotContent};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    #[test]
    fn report_message_with_reporter_snapshot() {
        crate::util::test::rt().block_on(report_message_with_reporter_snapshot_case())
    }

    async fn report_message_with_reporter_snapshot_case() {
        let harness = TestHarness::new().await;
        let (_, session, reporter) = harness.new_user().await;
        let (_, _, author) = harness.new_user().await;

        let (server, channels) = harness.new_server(&author).await;
        let (channel, _, message) = harness.new_message(&author, &server, channels).await;

        let response = harness
            .client
            .post("/safety/report")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.to_string()))
            .body(
                json!({
                    "content": {
                        "type": "Message",
                        "id": message.id,
                        "report_reason": "SpamAbuse"
                    },
                    "additional_context": "spamming the channel",
                    "message_snapshot": {
                        "message": {
                            "id": message.id,
                            "channel": channel.id(),
                            "author": author.id,
                            "content": "Test message",
                            "encrypted": true
                        },
                        "context": [
                            {
                                "id": "01AAAAAAAAAAAAAAAAAAAAAAAA",
                                "channel": channel.id(),
                                "author": author.id,
                                "content": "earlier message"
                            }
                        ]
                    }
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NoContent);

        let reports = harness.db.fetch_reports(None).await.expect("reports");
        let report = reports
            .iter()
            .find(|report| report.author_id == reporter.id)
            .expect("report to be persisted");

        let snapshots = harness
            .db
            .fetch_snapshots_by_report(&report.id)
            .await
            .expect("snapshots");

        // Reporter-supplied snapshot plus the server-side one
        assert_eq!(snapshots.len(), 2);

        let (reported_message, context) = snapshots
            .iter()
            .find_map(|snapshot| match &snapshot.content {
                SnapshotContent::ReporterMessage { message, context } => {
                    Some((message, context))
                }
                _ => None,
            })
            .expect("reporter-supplied snapshot");

        assert_eq!(reported_message.id, message.id);
        assert_eq!(reported_message.content, "Test message");
        // Reporter-attached plaintext of an E2EE message is flagged as such
        // so moderators know it was never server-visible
        assert!(reported_message.encrypted);
        assert_eq!(context.len(), 1);
        assert!(!context[0].encrypted);

        assert!(snapshots.iter().any(|snapshot| matches!(
            &snapshot.content,
            SnapshotContent::Message { message: server_copy, .. }
                if server_copy.id == message.id
        )));
    }

    #[test]
    fn report_message_requires_snapshot() {
        crate::util::test::rt().block_on(report_message_requires_snapshot_case())
    }

    async fn report_message_requires_snapshot_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        let (_, _, author) = harness.new_user().await;

        let (server, channels) = harness.new_server(&author).await;
        let (_, _, message) = harness.new_message(&author, &server, channels).await;

        let response = harness
            .client
            .post("/safety/report")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.to_string()))
            .body(
                json!({
                    "content": {
                        "type": "Message",
                        "id": message.id,
                        "report_reason": "SpamAbuse"
                    }
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[test]
    fn cannot_report_own_message() {
        crate::util::test::rt().block_on(cannot_report_own_message_case())
    }

    async fn cannot_report_own_message_case() {
        let harness = TestHarness::new().await;
        let (_, session, author) = harness.new_user().await;

        let (server, channels) = harness.new_server(&author).await;
        let (channel, _, message) = harness.new_message(&author, &server, channels).await;

        let response = harness
            .client
            .post("/safety/report")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.to_string()))
            .body(
                json!({
                    "content": {
                        "type": "Message",
                        "id": message.id,
                        "report_reason": "SpamAbuse"
                    },
                    "message_snapshot": {
                        "message": {
                            "id": message.id,
                            "channel": channel.id(),
                            "author": author.id,
                            "content": "Test message"
                        }
                    }
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[test]
    fn report_succeeds_with_moderator_present() {
        crate::util::test::rt().block_on(report_succeeds_with_moderator_present_case())
    }

    async fn report_succeeds_with_moderator_present_case() {
        // Filing a report while a privileged moderator exists must still
        // return NoContent: report notification delivery (the global-topic
        // broadcast consumed by moderator sessions) must never block or fail
        // the report submission itself.
        let harness = TestHarness::new().await;
        let (_, session, _reporter) = harness.new_user().await;
        let (_, _, author) = harness.new_user().await;
        let (_, _, moderator) = harness.new_user().await;

        moderator
            .clone()
            .update(
                &harness.db,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("promote moderator");

        let (server, channels) = harness.new_server(&author).await;
        let (channel, _, message) = harness.new_message(&author, &server, channels).await;

        let response = harness
            .client
            .post("/safety/report")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.to_string()))
            .body(
                json!({
                    "content": {
                        "type": "Message",
                        "id": message.id,
                        "report_reason": "Harassment"
                    },
                    "message_snapshot": {
                        "message": {
                            "id": message.id,
                            "channel": channel.id(),
                            "author": author.id,
                            "content": "Test message"
                        }
                    }
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NoContent);
    }

    #[test]
    fn report_deleted_message_still_accepted() {
        crate::util::test::rt().block_on(report_deleted_message_still_accepted_case())
    }

    async fn report_deleted_message_still_accepted_case() {
        // The reporter-supplied snapshot must stand alone: reporting must
        // work even when the server cannot produce its own copy (deleted
        // message now, E2EE conversations later).
        let harness = TestHarness::new().await;
        let (_, session, reporter) = harness.new_user().await;
        let (_, _, author) = harness.new_user().await;

        let (server, channels) = harness.new_server(&author).await;
        let (channel, _, message) = harness.new_message(&author, &server, channels).await;

        message
            .clone()
            .delete(&harness.db)
            .await
            .expect("message deleted");

        let response = harness
            .client
            .post("/safety/report")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.to_string()))
            .body(
                json!({
                    "content": {
                        "type": "Message",
                        "id": message.id,
                        "report_reason": "Harassment"
                    },
                    "message_snapshot": {
                        "message": {
                            "id": message.id,
                            "channel": channel.id(),
                            "author": author.id,
                            "content": "Test message"
                        }
                    }
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NoContent);

        let reports = harness.db.fetch_reports(None).await.expect("reports");
        let report = reports
            .iter()
            .find(|report| report.author_id == reporter.id)
            .expect("report to be persisted");

        let snapshots = harness
            .db
            .fetch_snapshots_by_report(&report.id)
            .await
            .expect("snapshots");

        // Only the reporter-supplied snapshot; no server-side copy exists
        assert_eq!(snapshots.len(), 1);
        assert!(matches!(
            &snapshots[0].content,
            SnapshotContent::ReporterMessage { .. }
        ));
    }
}
