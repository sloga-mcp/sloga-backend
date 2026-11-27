use revolt_database::{
    events::client::EventV1,
    util::{email::is_invalid_tld_address, permissions::DatabasePermissionQuery},
    Channel, Database, Message, Report, SealedRequester, Snapshot, SnapshotContent,
    TakedownSource, TakedownTarget, UnresolvableKind, User,
};
use revolt_models::v0::{
    ContentReportReason, DataInAppTakedown, ReportStatus, ReportedContent, ReportedMessageSnapshot,
    UserReportReason,
};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, ErrorType, Result};
use rocket_empty::EmptyResponse;
use serde::Deserialize;
use ulid::Ulid;
use validator::Validate;

use rocket::State;

use crate::routes::takedown::{
    insert_and_notify, invalid_takedown_body, prepare_request, stored_role, takedown_disabled,
    NewTakedown, QuietJson,
};

/// Maximum number of context messages accepted in a reporter snapshot
const MAX_CONTEXT_MESSAGES: usize = 32;

/// Maximum accepted length of a single snapshotted message's content
const MAX_SNAPSHOT_CONTENT: usize = 8192;

/// Description stored on a Take It Down request filed from a report; the
/// reviewer reads the linked report instead
const IN_APP_DESCRIPTION: &str = "In-app report";

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
    /// Take It Down fields, only with the "intimate images shared without
    /// consent" reason. They file a linked Take It Down request and never go
    /// into the report or its event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate]
    takedown: Option<DataInAppTakedown>,
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

/// Whether the report is for an intimate image shared without consent
fn is_intimate_image_report(content: &ReportedContent) -> bool {
    matches!(
        content,
        ReportedContent::Message {
            report_reason: ContentReportReason::NonConsensualIntimateImage,
            ..
        } | ReportedContent::Server {
            report_reason: ContentReportReason::NonConsensualIntimateImage,
            ..
        } | ReportedContent::User {
            report_reason: UserReportReason::NonConsensualIntimateImage,
            ..
        }
    )
}

/// Check that `user` can see the reported message, and return the channel
/// it was judged by. Every refusal is `NotFound`, so a probe learns nothing
/// about a channel it cannot see.
///
/// A stored message is judged by its own channel, and the snapshot must name
/// that channel. With no stored message (deleted, end-to-end encrypted, or
/// never existed) the snapshot is all there is: in a DM or group both the
/// reporter and the claimed author must be in it now; in a server channel
/// the reporter needs ViewChannel. The snapshot's `encrypted` flag never
/// relaxes either check.
async fn check_message_visibility(
    db: &Database,
    user: &User,
    snapshot: &ReportedMessageSnapshot,
    row: Option<&Message>,
) -> Result<Channel> {
    let channel_id = match row {
        Some(message) if message.channel != snapshot.channel => {
            return Err(create_error!(NotFound))
        }
        Some(message) => message.channel.as_str(),
        None => snapshot.channel.as_str(),
    };

    let channel = db
        .fetch_channel(channel_id)
        .await
        .map_err(|_| create_error!(NotFound))?;

    let visible = match &channel {
        Channel::DirectMessage { .. } | Channel::Group { .. } | Channel::SavedMessages { .. } => {
            channel.contains_user(&user.id)
                && (row.is_some() || channel.contains_user(&snapshot.author))
        }
        _ => {
            // Threads are judged by their parent channel
            let permission_channel = channel
                .permission_target(db)
                .await
                .map_err(|_| create_error!(NotFound))?
                .into_owned();
            let mut query = DatabasePermissionQuery::new(db, user).channel(&permission_channel);
            calculate_channel_permissions(&mut query)
                .await
                .has_channel_permission(ChannelPermission::ViewChannel)
        }
    };

    if visible {
        Ok(channel)
    } else {
        Err(create_error!(NotFound))
    }
}

/// What a linked Take It Down request points at
struct ReportedObject {
    target: TakedownTarget,
    /// An app link to the object, stored as the request's one location
    location: String,
    /// Object ids for the staff audit entry
    target_ids: Vec<String>,
}

/// # Report Content
///
/// Report a piece of content to the moderation team.
#[openapi(tag = "User Safety")]
#[post("/report", data = "<data>")]
pub async fn report_content(
    db: &State<Database>,
    user: User,
    data: QuietJson<DataReportContent>,
) -> Result<EmptyResponse> {
    let data = data.into_inner()?;
    if let Err(error) = data.validate() {
        // Validator messages quote the submitted values: with Take It Down
        // fields present they would carry the reporter's statement
        return Err(if data.takedown.is_some() {
            invalid_takedown_body()
        } else {
            create_error!(FailedValidation {
                error: error.to_string()
            })
        });
    }

    let DataReportContent {
        content,
        additional_context,
        message_snapshot,
        takedown,
    } = data;

    if let Some(snapshot) = &message_snapshot {
        validate_snapshot(snapshot)?;
    }

    // Bots cannot create reports
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // Take It Down fields only go with the intimate-image reason, and only
    // while the feature is on; refused before anything is stored
    let config = revolt_config::config().await;
    if let Some(takedown) = &takedown {
        if !is_intimate_image_report(&content) || takedown.signature.trim().is_empty() {
            return Err(invalid_takedown_body());
        }
        if !config.features.takedown.active() {
            return Err(takedown_disabled());
        }
    }
    let app = config.hosts.app.trim_end_matches('/');

    // Find the content and create a snapshot of it
    // Also retrieve any references to Files
    let (snapshots, files, object) = match &content {
        ReportedContent::Message { id, .. } => {
            // The reporter-supplied snapshot is the authoritative copy: it
            // must be present and must describe the message being reported.
            let client_snapshot = message_snapshot.as_ref().ok_or_else(|| {
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

            // The server's own copy, when it has one. No copy is normal
            // (deleted, or an end-to-end encrypted conversation); any
            // other failure is not.
            let row = match db.fetch_message(id).await {
                Ok(message) => Some(message),
                Err(error) if matches!(error.error_type, ErrorType::NotFound) => None,
                Err(error) => return Err(error),
            };

            if let Some(message) = &row {
                if message.author == user.id {
                    return Err(create_error!(CannotReportYourself));
                }
            }

            let channel =
                check_message_visibility(db, &user, &client_snapshot.message, row.as_ref()).await?;

            let object = match &row {
                Some(message) => ReportedObject {
                    target: TakedownTarget::Message {
                        channel: message.channel.clone(),
                        message: message.id.clone(),
                    },
                    location: format!("{app}/channel/{}/{}", message.channel, message.id),
                    target_ids: vec![message.id.clone()],
                },
                // Nothing stored to act on. The id is the reporter's own
                // copy, so it is not recorded as a target.
                None => ReportedObject {
                    target: TakedownTarget::Unresolvable {
                        location_index: 0,
                        kind: if matches!(
                            channel,
                            Channel::DirectMessage { .. } | Channel::Group { .. }
                        ) {
                            UnresolvableKind::PrivateConversation
                        } else {
                            UnresolvableKind::NotFound
                        },
                    },
                    location: format!("{app}/channel/{}/{}", channel.id(), id),
                    target_ids: vec![],
                },
            };

            let mut snapshots = vec![SnapshotContent::ReporterMessage {
                message: client_snapshot.message.clone(),
                context: client_snapshot.context.clone(),
            }];

            // Additionally snapshot server-readable content when available.
            // Best-effort: the report must go through even if the server
            // cannot read the message (E2EE) or it was already deleted. A
            // plaintext row stored in a protected channel (R15) gives no
            // server copy, so the report is filed on the reporter's snapshot
            // alone, as for a deleted message.
            let mut files = vec![];
            if let Some(message) = row {
                if let Some((snapshot, message_files)) =
                    SnapshotContent::generate_from_message(db, message).await?
                {
                    snapshots.push(snapshot);
                    files = message_files;
                }
            }

            (snapshots, files, object)
        }
        ReportedContent::Server { id, .. } => {
            let server = db.fetch_server(id).await?;

            // Users cannot report their own server
            if server.owner == user.id {
                return Err(create_error!(CannotReportYourself));
            }

            let object = ReportedObject {
                target: TakedownTarget::Server {
                    server: server.id.clone(),
                },
                location: format!("{app}/server/{}", server.id),
                target_ids: vec![server.id.clone()],
            };

            let (snapshot, files) = SnapshotContent::generate_from_server(server)?;
            (vec![snapshot], files, object)
        }
        ReportedContent::User { id, message_id, .. } => {
            let reported_user = db.fetch_user(id).await?;

            // Users cannot report themselves
            if reported_user.id == user.id {
                return Err(create_error!(CannotReportYourself));
            }

            let object = ReportedObject {
                target: TakedownTarget::User {
                    user: reported_user.id.clone(),
                },
                location: format!("{app}/user/{}", reported_user.id),
                target_ids: vec![reported_user.id.clone()],
            };

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
            if let Some(client_snapshot) = &message_snapshot {
                snapshots.push(SnapshotContent::ReporterMessage {
                    message: client_snapshot.message.clone(),
                    context: client_snapshot.context.clone(),
                });
            }

            // A context message stored as plaintext in a protected channel
            // (R15) gives no server copy; the user report is still filed
            if let Some(message) = message {
                if let Some((message_snapshot, message_files)) =
                    SnapshotContent::generate_from_message(db, message).await?
                {
                    snapshots.push(message_snapshot);
                    files = [files, message_files].concat();
                }
            }

            (snapshots, files, object)
        }
    };

    // Generate an id for the report
    let id = Ulid::new().to_string();

    // Seal the linked Take It Down request before anything is stored, so a
    // failure here leaves no half-filed report
    let takedown = match takedown {
        Some(takedown) => Some(
            prepare_in_app_request(db, &user, &config.features.takedown, takedown, &id, object)
                .await?,
        ),
        None => None,
    };

    // Mark all the attachments as reported
    for file in files {
        db.mark_attachment_as_reported(&file).await?;
    }

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
        content,
        additional_context,
        status: ReportStatus::Created {},
        notes: String::new(),
    };

    db.insert_report(&report).await?;

    // The linked request, its audit entry and its received email. The
    // statement fields live only in its sealed blob.
    if let Some((prepared, target_ids)) = takedown {
        insert_and_notify(db, prepared, "in_app", target_ids).await?;
    }

    // Broadcast on the "global" topic. Privileged (moderator) sessions
    // subscribe to this topic in bonfire, so their connected clients receive
    // the report live and can raise a notification + queue badge. The event
    // is content-free beyond the report metadata, safe for E2EE reports.
    EventV1::ReportCreate(report.into()).global().await;

    Ok(EmptyResponse)
}

/// The answer to a Take It Down report with no usable contact address: the
/// reporter's account has no email and none was typed. Fixed text, nothing
/// from the request.
fn takedown_contact_required() -> revolt_result::Error {
    create_error!(FailedValidation {
        error: "takedown.email is required".to_string()
    })
}

/// Seal the Take It Down request an in-app report files. Contact is the
/// given address or the account's; the signature doubles as the name.
///
/// An account with no email has no address to fall back on, so its report
/// must carry one (`takedown_contact_required` otherwise). The stand-in such
/// an account stores is never used, and a typed `.invalid` address is
/// refused like any other bad address.
async fn prepare_in_app_request(
    db: &Database,
    user: &User,
    settings: &revolt_config::FeaturesTakedown,
    takedown: DataInAppTakedown,
    report_id: &str,
    object: ReportedObject,
) -> Result<(crate::routes::takedown::PreparedTakedown, Vec<String>)> {
    let DataInAppTakedown {
        role,
        authority_note,
        signature,
        signature_ack: _,
        statement_ack: _,
        email,
        extra,
    } = takedown;

    let email = match email.filter(|email| !email.trim().is_empty()) {
        Some(email) if is_invalid_tld_address(&email) => return Err(invalid_takedown_body()),
        Some(email) => email,
        None => match db.fetch_account(&user.id).await?.real_email() {
            Some(email) => email.to_string(),
            None => return Err(takedown_contact_required()),
        },
    };

    let ReportedObject {
        target,
        location,
        target_ids,
    } = object;

    let prepared = prepare_request(
        db,
        settings,
        NewTakedown {
            source: TakedownSource::InApp {
                report_id: report_id.to_string(),
            },
            requester: SealedRequester {
                role: stored_role(role),
                authority_note: authority_note.filter(|note| !note.trim().is_empty()),
                name: signature.clone(),
                signature,
                email,
                description: IN_APP_DESCRIPTION.to_string(),
                extra: extra.filter(|extra| !extra.trim().is_empty()),
                added_info: vec![],
            },
            locations: vec![location],
            targets: vec![target],
            resolved: true,
            minor_claimed: false,
        },
    )
    .await?;

    Ok((prepared, target_ids))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{Channel, Database, PartialUser, SnapshotContent};
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
        // Message reports need a reporter who can see the message
        harness.join_server(&server, &reporter).await;

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
        let (_, session, reporter) = harness.new_user().await;
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
        harness.join_server(&server, &reporter).await;

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
        // No stored copy: the reporter still needs ViewChannel on the
        // channel the snapshot names
        harness.join_server(&server, &reporter).await;

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

    /// Mark `channel_id` protected under its stored plaintext rows, raw, as
    /// the R15 compensation window can leave a stray behind
    async fn protect_under_stored_rows(db: &Database, channel_id: &str) {
        match db {
            Database::Reference(reference) => {
                match reference.channels.lock().await.get_mut(channel_id) {
                    Some(Channel::TextChannel { protected, .. }) => *protected = true,
                    other => panic!("expected a text channel, got {:?}", other),
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let result = mongo
                    .col::<Document>("channels")
                    .update_one(
                        doc! { "_id": channel_id },
                        doc! { "$set": { "protected": true } },
                    )
                    .await
                    .expect("raw protect");
                assert_eq!(result.matched_count, 1);
            }
        }

        assert!(db
            .fetch_channel(channel_id)
            .await
            .expect("channel")
            .is_protected());
    }

    #[test]
    fn report_of_a_stray_plaintext_row_is_filed_without_a_server_copy() {
        crate::util::test::rt()
            .block_on(report_of_a_stray_plaintext_row_is_filed_without_a_server_copy_case())
    }

    async fn report_of_a_stray_plaintext_row_is_filed_without_a_server_copy_case() {
        // R15 backstop, decision 9 (W2) [R#4]: the server never snapshots a
        // plaintext row stored in a protected channel, but the report itself
        // is still filed on the reporter-supplied snapshot.
        let harness = TestHarness::new().await;
        let (_, session, reporter) = harness.new_user().await;
        let (_, _, author) = harness.new_user().await;

        let (server, channels) = harness.new_server(&author).await;
        let (channel, _, message) = harness.new_message(&author, &server, channels).await;
        harness.join_server(&server, &reporter).await;
        protect_under_stored_rows(&harness.db, channel.id()).await;

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

        // Only the reporter-supplied snapshot; the stray is never embedded
        assert_eq!(snapshots.len(), 1);
        assert!(matches!(
            &snapshots[0].content,
            SnapshotContent::ReporterMessage { .. }
        ));
    }

    #[test]
    fn user_report_citing_a_stray_plaintext_row_is_filed_without_it() {
        crate::util::test::rt()
            .block_on(user_report_citing_a_stray_plaintext_row_is_filed_without_it_case())
    }

    async fn user_report_citing_a_stray_plaintext_row_is_filed_without_it_case() {
        let harness = TestHarness::new().await;
        let (_, session, reporter) = harness.new_user().await;
        let (_, _, author) = harness.new_user().await;

        let (server, channels) = harness.new_server(&author).await;
        let (channel, _, message) = harness.new_message(&author, &server, channels).await;
        protect_under_stored_rows(&harness.db, channel.id()).await;

        let response = harness
            .client
            .post("/safety/report")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.to_string()))
            .body(
                json!({
                    "content": {
                        "type": "User",
                        "id": author.id,
                        "report_reason": "SpamAbuse",
                        "message_id": message.id
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

        // The reported user only; the cited stray is never embedded
        assert_eq!(snapshots.len(), 1);
        assert!(matches!(
            &snapshots[0].content,
            SnapshotContent::User(reported) if reported.id == author.id
        ));
    }

    /// Design 7.5 "S4": a plaintext row at or below the boundary of a
    /// channel protected with its history is truthful pre-protect history,
    /// so its report carries the server copy; once the wipe is `Requested`
    /// a report of the same row is filed on the reporter's snapshot alone
    ///
    /// Control: the wipe arm dropped from `is_servable` -> the second report
    /// carries a server copy.
    #[test]
    fn report_of_a_pre_boundary_row_carries_a_server_copy_until_the_wipe() {
        crate::util::test::rt()
            .block_on(report_of_a_pre_boundary_row_carries_a_server_copy_until_the_wipe_case())
    }

    async fn report_of_a_pre_boundary_row_carries_a_server_copy_until_the_wipe_case() {
        use revolt_database::HistoryWipe;

        let harness = TestHarness::new().await;
        let (_, _, author) = harness.new_user().await;
        let (server, channels) = harness.new_server(&author).await;
        let (channel, _, message) = harness.new_message(&author, &server, channels).await;
        protect_under_stored_rows(&harness.db, channel.id()).await;
        harness
            .protect_with_history_raw(channel.id(), &message.id, HistoryWipe::None)
            .await;

        // The snapshots of one message report by a fresh reporter, who joins
        // the server first: a reporter must be able to see the message
        async fn report(
            harness: &TestHarness,
            server: &revolt_database::Server,
            channel: &Channel,
            author_id: &str,
            message_id: &str,
        ) -> Vec<revolt_database::Snapshot> {
            let (_, session, reporter) = harness.new_user().await;
            harness.join_server(server, &reporter).await;
            let response = harness
                .client
                .post("/safety/report")
                .header(ContentType::JSON)
                .header(Header::new("x-session-token", session.token.to_string()))
                .body(
                    json!({
                        "content": {
                            "type": "Message",
                            "id": message_id,
                            "report_reason": "SpamAbuse"
                        },
                        "message_snapshot": {
                            "message": {
                                "id": message_id,
                                "channel": channel.id(),
                                "author": author_id,
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
            harness
                .db
                .fetch_snapshots_by_report(&report.id)
                .await
                .expect("snapshots")
        }

        let snapshots = report(&harness, &server, &channel, &author.id, &message.id).await;
        assert_eq!(
            snapshots.len(),
            2,
            "the reporter's snapshot and the server copy"
        );
        assert!(snapshots.iter().any(|snapshot| matches!(
            &snapshot.content,
            SnapshotContent::Message { message: server_copy, .. }
                if server_copy.id == message.id
                    && server_copy.content.as_deref() == Some("Test message")
        )));

        harness
            .protect_with_history_raw(
                channel.id(),
                &message.id,
                HistoryWipe::Requested {
                    at: iso8601_timestamp::Timestamp::now_utc(),
                    by: author.id.clone(),
                },
            )
            .await;
        let snapshots = report(&harness, &server, &channel, &author.id, &message.id).await;
        assert_eq!(snapshots.len(), 1, "wipe pending: no server copy");
        assert!(matches!(
            &snapshots[0].content,
            SnapshotContent::ReporterMessage { .. }
        ));
    }
}

#[cfg(test)]
mod takedown_test {
    //! Take It Down fields on reports, and who may report a message

    use crate::routes::takedown::test_support::{
        enable_takedown, open, recent, wait_for_received_marker,
    };
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{
        events::client::EventV1, Channel, Message, Report, Session, TakedownRequest,
        TakedownSource, TakedownTarget, UnresolvableKind, User,
    };
    use rocket::http::{ContentType, Header, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    async fn report(harness: &TestHarness, session: &Session, body: Value) -> (Status, String) {
        let response = harness
            .client
            .post("/safety/report")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.to_string()))
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    fn message_report(reason: &str, message: &str, channel: &str, author: &str) -> Value {
        json!({
            "content": {
                "type": "Message",
                "id": message,
                "report_reason": reason
            },
            "message_snapshot": {
                "message": {
                    "id": message,
                    "channel": channel,
                    "author": author,
                    "content": "reported message"
                }
            }
        })
    }

    /// A snapshot that claims end-to-end encryption; the flag must not
    /// relax any check
    fn encrypted_message_report(message: &str, channel: &str, author: &str) -> Value {
        let mut body = message_report("Harassment", message, channel, author);
        body["message_snapshot"]["message"]["encrypted"] = json!(true);
        body
    }

    fn takedown_fields() -> Value {
        json!({
            "role": "Depicted",
            "signature": "SIGNATURE-SECRET",
            "signature_ack": true,
            "statement_ack": true,
            "extra": "EXTRA-SECRET"
        })
    }

    async fn reports_by(harness: &TestHarness, user: &User) -> Vec<Report> {
        harness
            .db
            .fetch_reports(None)
            .await
            .expect("reports")
            .into_iter()
            .filter(|report| report.author_id == user.id)
            .collect()
    }

    async fn linked_request(harness: &TestHarness, report: &Report) -> Option<TakedownRequest> {
        recent(&harness.db).await.into_iter().find(|request| {
            matches!(
                &request.source,
                TakedownSource::InApp { report_id } if report_id == &report.id
            )
        })
    }

    /// A DM between `a` and `b`
    async fn dm(harness: &TestHarness, a: &User, b: &User) -> String {
        let id = Ulid::new().to_string();
        harness
            .db
            .insert_channel(&Channel::DirectMessage {
                id: id.clone(),
                active: true,
                recipients: vec![a.id.clone(), b.id.clone()],
                last_message_id: None,
            })
            .await
            .expect("dm");
        id
    }

    /// A plain message row from `author` in `channel`
    async fn stored_message(harness: &TestHarness, channel: &str, author: &User) -> Message {
        let message = Message {
            id: Ulid::new().to_string(),
            channel: channel.to_string(),
            author: author.id.clone(),
            content: Some("stored message".to_string()),
            ..Default::default()
        };
        harness.db.insert_message(&message).await.expect("message");
        message
    }

    #[test]
    fn intimate_image_report_with_takedown_files_a_linked_request() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let mut harness = TestHarness::new().await;
            let (account, session, reporter) = harness.new_user().await;
            let (_, _, author) = harness.new_user().await;
            let (server, channels) = harness.new_server(&author).await;
            let (channel, _, message) = harness.new_message(&author, &server, channels).await;
            harness.join_server(&server, &reporter).await;

            let mut body = message_report(
                "NonConsensualIntimateImage",
                &message.id,
                channel.id(),
                &author.id,
            );
            body["additional_context"] = json!("plain context");
            body["takedown"] = takedown_fields();

            let (status, text) = report(&harness, &session, body).await;
            assert_eq!(status, Status::NoContent, "{text}");

            // The report carries nothing from the statement
            let reports = reports_by(&harness, &reporter).await;
            assert_eq!(reports.len(), 1);
            let filed = reports[0].clone();
            assert_eq!(filed.additional_context, "plain context");
            let stored = serde_json::to_string(&filed).expect("json");
            assert!(!stored.contains("SECRET"), "{stored}");
            let snapshots = harness
                .db
                .fetch_snapshots_by_report(&filed.id)
                .await
                .expect("snapshots");
            assert!(!format!("{snapshots:?}").contains("SECRET"));

            // Nor does the event every moderator session receives
            let report_id = filed.id.clone();
            let event = harness
                .wait_for_event("global", |event| {
                    matches!(event, EventV1::ReportCreate(created) if created.id == report_id)
                })
                .await;
            let event = serde_json::to_string(&event).expect("json");
            assert!(!event.contains("SECRET"), "{event}");

            // The linked request, already resolved to the reported message
            let request = linked_request(&harness, &filed)
                .await
                .expect("a linked request");
            assert!(request.resolved);
            assert!(!request.minor_claimed);
            assert_eq!(
                request.targets,
                vec![TakedownTarget::Message {
                    channel: channel.id().to_string(),
                    message: message.id.clone(),
                }]
            );
            assert_eq!(request.locations.len(), 1);
            assert!(request.locations[0].ends_with(&format!(
                "/channel/{}/{}",
                channel.id(),
                message.id
            )));
            assert!(!request.sealed.contains("SECRET"));

            let requester = open(&request);
            assert_eq!(requester.signature, "SIGNATURE-SECRET");
            assert_eq!(requester.name, "SIGNATURE-SECRET");
            assert_eq!(requester.email, account.email);
            assert_eq!(requester.description, "In-app report");
            assert_eq!(requester.extra.as_deref(), Some("EXTRA-SECRET"));

            wait_for_received_marker(&harness.db, &request.id).await;
        })
    }

    #[test]
    fn a_user_report_files_against_the_user_with_the_given_address() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let (_, session, reporter) = harness.new_user().await;
            let (_, _, reported) = harness.new_user().await;

            let mut takedown = takedown_fields();
            takedown["email"] = json!("given-contact@example.com");
            takedown["role"] = json!("Authorized");
            takedown["authority_note"] = json!("NOTE-SECRET");

            let (status, text) = report(
                &harness,
                &session,
                json!({
                    "content": {
                        "type": "User",
                        "id": reported.id,
                        "report_reason": "NonConsensualIntimateImage"
                    },
                    "takedown": takedown
                }),
            )
            .await;
            assert_eq!(status, Status::NoContent, "{text}");

            let reports = reports_by(&harness, &reporter).await;
            let request = linked_request(&harness, &reports[0])
                .await
                .expect("a linked request");
            assert_eq!(
                request.targets,
                vec![TakedownTarget::User {
                    user: reported.id.clone()
                }]
            );

            let requester = open(&request);
            assert_eq!(requester.email, "given-contact@example.com");
            assert_eq!(requester.authority_note.as_deref(), Some("NOTE-SECRET"));
            assert!(matches!(
                requester.role,
                revolt_database::TakedownRole::Authorized
            ));
        })
    }

    /// Fails if: a Take It Down report from an account with no email is
    /// filed without a typed contact (the account's stand-in address would
    /// be sealed as the contact, mailed and shown to staff), a typed
    /// `.invalid` address is accepted, a refusal leaves a report or request
    /// behind or echoes an address, or a typed real address stops working
    /// for such an account.
    #[test]
    fn a_no_email_account_must_type_its_takedown_contact() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let (account, session, reporter) = harness.new_no_email_user().await;
            let (_, _, reported) = harness.new_user().await;
            assert!(account.email_absent);
            assert!(account.real_email().is_none());

            let body = |takedown: Value| {
                json!({
                    "content": {
                        "type": "User",
                        "id": reported.id,
                        "report_reason": "NonConsensualIntimateImage"
                    },
                    "takedown": takedown
                })
            };

            // Three reports: exactly the per-window report budget

            // No typed contact: nothing to fall back on
            let (status, text) = report(&harness, &session, body(takedown_fields())).await;
            assert_eq!(status, Status::BadRequest, "{text}");
            assert!(text.contains("FailedValidation"), "{text}");
            assert!(!text.contains(".invalid"), "{text}");
            assert!(!text.contains("SECRET"), "{text}");

            // The stand-in itself, typed in
            let mut stand_in = takedown_fields();
            stand_in["email"] = json!(account.email);
            let (status, text) = report(&harness, &session, body(stand_in)).await;
            assert_eq!(status, Status::BadRequest, "{text}");
            assert!(text.contains("FailedValidation"), "{text}");
            assert!(!text.contains(".invalid"), "{text}");

            assert!(reports_by(&harness, &reporter).await.is_empty());
            assert!(recent(&harness.db).await.is_empty());

            // A typed address files the report and its request
            let mut typed = takedown_fields();
            typed["email"] = json!("typed-contact@example.com");
            let (status, text) = report(&harness, &session, body(typed)).await;
            assert_eq!(status, Status::NoContent, "{text}");

            let reports = reports_by(&harness, &reporter).await;
            assert_eq!(reports.len(), 1);
            let request = linked_request(&harness, &reports[0])
                .await
                .expect("a linked request");
            assert_eq!(recent(&harness.db).await.len(), 1);
            assert_eq!(open(&request).email, "typed-contact@example.com");
        })
    }

    #[test]
    fn intimate_image_report_without_takedown_stays_a_plain_report() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let (_, session, reporter) = harness.new_user().await;
            let (_, _, author) = harness.new_user().await;
            let (server, channels) = harness.new_server(&author).await;
            let (channel, _, message) = harness.new_message(&author, &server, channels).await;
            harness.join_server(&server, &reporter).await;

            let (status, text) = report(
                &harness,
                &session,
                message_report(
                    "NonConsensualIntimateImage",
                    &message.id,
                    channel.id(),
                    &author.id,
                ),
            )
            .await;
            assert_eq!(status, Status::NoContent, "{text}");

            // The legacy combined reason still files a report too
            let (_, _, other) = harness.new_user().await;
            let (other_server, other_channels) = harness.new_server(&other).await;
            let (other_channel, _, other_message) = harness
                .new_message(&other, &other_server, other_channels)
                .await;
            harness.join_server(&other_server, &reporter).await;
            let (status, text) = report(
                &harness,
                &session,
                message_report(
                    "IllegalPornography",
                    &other_message.id,
                    other_channel.id(),
                    &other.id,
                ),
            )
            .await;
            assert_eq!(status, Status::NoContent, "{text}");

            assert_eq!(reports_by(&harness, &reporter).await.len(), 2);
            assert!(recent(&harness.db).await.is_empty());
        })
    }

    #[test]
    fn takedown_fields_need_the_intimate_image_reason_and_both_ticks() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let (_, session, reporter) = harness.new_user().await;
            let (_, _, author) = harness.new_user().await;
            let (server, channels) = harness.new_server(&author).await;
            let (channel, _, message) = harness.new_message(&author, &server, channels).await;
            harness.join_server(&server, &reporter).await;

            let mut other_reason =
                message_report("SpamAbuse", &message.id, channel.id(), &author.id);
            other_reason["takedown"] = takedown_fields();

            let mut unticked = message_report(
                "NonConsensualIntimateImage",
                &message.id,
                channel.id(),
                &author.id,
            );
            unticked["takedown"] = takedown_fields();
            unticked["takedown"]["statement_ack"] = json!(false);

            let mut bad_address = message_report(
                "NonConsensualIntimateImage",
                &message.id,
                channel.id(),
                &author.id,
            );
            bad_address["takedown"] = takedown_fields();
            bad_address["takedown"]["email"] = json!("SECRET-not-an-address");

            // Three reports: exactly the per-window report budget
            for body in [other_reason, unticked, bad_address] {
                let (status, text) = report(&harness, &session, body).await;
                assert_eq!(status, Status::BadRequest, "{text}");
                assert!(text.contains("FailedValidation"), "{text}");
                assert!(!text.contains("SECRET"), "{text}");
            }

            assert!(reports_by(&harness, &reporter).await.is_empty());
            assert!(recent(&harness.db).await.is_empty());
        })
    }

    #[test]
    fn takedown_fields_with_the_feature_off_file_nothing() {
        crate::util::test::rt().block_on(async {
            // No `enable_takedown`: the shipped config has the feature off
            let harness = TestHarness::new().await;
            let (_, session, reporter) = harness.new_user().await;
            let (_, _, author) = harness.new_user().await;
            let (server, channels) = harness.new_server(&author).await;
            let (channel, _, message) = harness.new_message(&author, &server, channels).await;
            harness.join_server(&server, &reporter).await;

            let mut body = message_report(
                "NonConsensualIntimateImage",
                &message.id,
                channel.id(),
                &author.id,
            );
            body["takedown"] = takedown_fields();

            let (status, text) = report(&harness, &session, body).await;
            assert_eq!(status, Status::BadRequest, "{text}");
            assert!(text.contains("FeatureDisabled"), "{text}");
            assert!(reports_by(&harness, &reporter).await.is_empty());
        })
    }

    #[test]
    fn a_dm_outsider_cannot_report_a_stored_dm_message() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, outsider_session, outsider) = harness.new_user().await;
            let (_, recipient_session, recipient) = harness.new_user().await;
            let (_, _, author) = harness.new_user().await;
            let channel = dm(&harness, &author, &recipient).await;
            let message = stored_message(&harness, &channel, &author).await;

            let (status, _) = report(
                &harness,
                &outsider_session,
                encrypted_message_report(&message.id, &channel, &author.id),
            )
            .await;
            assert_eq!(status, Status::NotFound);
            assert!(reports_by(&harness, &outsider).await.is_empty());

            // A recipient can
            let (status, text) = report(
                &harness,
                &recipient_session,
                message_report("Harassment", &message.id, &channel, &author.id),
            )
            .await;
            assert_eq!(status, Status::NoContent, "{text}");
            assert_eq!(reports_by(&harness, &recipient).await.len(), 1);
        })
    }

    #[test]
    fn with_no_stored_dm_message_reporter_and_author_must_both_be_in_it() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, session, reporter) = harness.new_user().await;
            let (_, _, author) = harness.new_user().await;
            let (_, _, third) = harness.new_user().await;

            // The reporter is in it, the claimed author is not
            let without_author = dm(&harness, &reporter, &third).await;
            let (status, _) = report(
                &harness,
                &session,
                encrypted_message_report(&Ulid::new().to_string(), &without_author, &author.id),
            )
            .await;
            assert_eq!(status, Status::NotFound);

            // The claimed author is in it, the reporter is not
            let without_reporter = dm(&harness, &author, &third).await;
            let (status, _) = report(
                &harness,
                &session,
                encrypted_message_report(&Ulid::new().to_string(), &without_reporter, &author.id),
            )
            .await;
            assert_eq!(status, Status::NotFound);
            assert!(reports_by(&harness, &reporter).await.is_empty());

            // Both are in it: filed on the reporter's snapshot alone
            let both = dm(&harness, &reporter, &author).await;
            let (status, text) = report(
                &harness,
                &session,
                encrypted_message_report(&Ulid::new().to_string(), &both, &author.id),
            )
            .await;
            assert_eq!(status, Status::NoContent, "{text}");
            assert_eq!(reports_by(&harness, &reporter).await.len(), 1);
        })
    }

    #[test]
    fn a_server_channel_reporter_needs_view_channel() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, session, reporter) = harness.new_user().await;
            let (_, _, author) = harness.new_user().await;
            let (server, channels) = harness.new_server(&author).await;
            let (channel, _, message) = harness.new_message(&author, &server, channels).await;

            // Not a member: refused with the stored message
            let (status, _) = report(
                &harness,
                &session,
                encrypted_message_report(&message.id, channel.id(), &author.id),
            )
            .await;
            assert_eq!(status, Status::NotFound);

            // ...and with no stored message, naming the same channel
            let (status, _) = report(
                &harness,
                &session,
                encrypted_message_report(&Ulid::new().to_string(), channel.id(), &author.id),
            )
            .await;
            assert_eq!(status, Status::NotFound);
            assert!(reports_by(&harness, &reporter).await.is_empty());

            // A member can (the third report: exactly the per-window budget)
            harness.join_server(&server, &reporter).await;
            let (status, text) = report(
                &harness,
                &session,
                message_report("Harassment", &message.id, channel.id(), &author.id),
            )
            .await;
            assert_eq!(status, Status::NoContent, "{text}");
        })
    }

    #[test]
    fn the_snapshot_must_name_the_stored_message_channel() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, session, reporter) = harness.new_user().await;
            let (_, _, author) = harness.new_user().await;
            let (server, channels) = harness.new_server(&author).await;
            let (_, _, message) = harness.new_message(&author, &server, channels).await;

            // A DM both are in cannot vouch for a server message the
            // reporter cannot see
            let shared_dm = dm(&harness, &reporter, &author).await;
            let (status, _) = report(
                &harness,
                &session,
                encrypted_message_report(&message.id, &shared_dm, &author.id),
            )
            .await;
            assert_eq!(status, Status::NotFound);
            assert!(reports_by(&harness, &reporter).await.is_empty());
        })
    }

    #[test]
    fn a_report_with_no_stored_message_files_an_unresolvable_target() {
        crate::util::test::rt().block_on(async {
            enable_takedown().await;
            let harness = TestHarness::new().await;
            let (_, session, reporter) = harness.new_user().await;
            let (_, _, author) = harness.new_user().await;
            let channel = dm(&harness, &reporter, &author).await;
            let envelope = Ulid::new().to_string();

            let mut body = encrypted_message_report(&envelope, &channel, &author.id);
            body["content"]["report_reason"] = json!("NonConsensualIntimateImage");
            body["takedown"] = takedown_fields();

            let (status, text) = report(&harness, &session, body).await;
            assert_eq!(status, Status::NoContent, "{text}");

            let reports = reports_by(&harness, &reporter).await;
            let request = linked_request(&harness, &reports[0])
                .await
                .expect("a linked request");
            assert!(request.resolved);
            assert_eq!(
                request.targets,
                vec![TakedownTarget::Unresolvable {
                    location_index: 0,
                    kind: UnresolvableKind::PrivateConversation,
                }]
            );
        })
    }
}
