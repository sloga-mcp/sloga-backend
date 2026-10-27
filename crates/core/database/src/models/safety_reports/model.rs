use revolt_models::v0::{ReportStatus, ReportedContent, UserReportReason};
use revolt_result::{ErrorType, Result};
use ulid::Ulid;

use crate::{events::client::EventV1, Database, Snapshot, SnapshotContent, User};

/// Author id of reports filed automatically by the server (anti-spam).
///
/// This is the same sentinel the server stamps on system messages; no real
/// account can ever hold it, so a report with this author was never filed by
/// a user.
pub const SYSTEM_USER_ID: &str = "00000000000000000000000000";

/// Maximum number of messages snapshotted into a system report
const MAX_SYSTEM_REPORT_MESSAGES: usize = 3;

/// Maximum number of distinct message ids looked up for a system report
const MAX_SYSTEM_REPORT_LOOKUPS: usize = 10;

/// Maximum length (in characters) of a report's additional context, matching
/// the limit the report route validates user-filed reports against
const MAX_ADDITIONAL_CONTEXT: usize = 1000;

auto_derived!(
    /// User-generated platform moderation report
    pub struct Report {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Id of the user creating this report
        pub author_id: String,
        /// Reported content
        pub content: ReportedContent,
        /// Additional report context
        pub additional_context: String,
        /// Status of the report
        #[serde(flatten)]
        pub status: ReportStatus,
        /// Additional notes included on the report
        #[serde(default)]
        pub notes: String,
    }
);

impl Report {
    /// File a report against a user on behalf of the server itself
    ///
    /// The report is authored by [`SYSTEM_USER_ID`] and lands in the staff
    /// queue like any user-filed report: a snapshot of the user, a snapshot
    /// of each listed message that still exists (the first three the reported
    /// user wrote, looking at no more than ten ids), then the report itself,
    /// then the `ReportCreate` event to privileged sessions. A message
    /// snapshot's surrounding context keeps only the reported user's own
    /// messages, and the report's `message_id` is the first message kept.
    ///
    /// Messages that can no longer be fetched are skipped rather than failing
    /// the report. Callers must only pass messages the server can read; this
    /// never decides on its own which conversations may be sampled.
    pub async fn create_system(
        db: &Database,
        id: String,
        reported_user: &User,
        message_ids: &[String],
        additional_context: String,
    ) -> Result<Report> {
        // Internal anti-spam state is not moderation evidence
        let mut user = reported_user.clone();
        user.dm_guard = None;

        let (user_snapshot, mut files) = SnapshotContent::generate_from_user(user)?;
        let mut snapshots = vec![user_snapshot];

        // The cap counts snapshots actually kept, so deleted or foreign ids
        // early in the list cannot crowd out live evidence; the number of
        // distinct ids fetched is bounded separately
        let mut seen: Vec<&String> = Vec::with_capacity(MAX_SYSTEM_REPORT_LOOKUPS);
        let mut kept: Vec<String> = Vec::with_capacity(MAX_SYSTEM_REPORT_MESSAGES);
        for message_id in message_ids {
            if kept.len() >= MAX_SYSTEM_REPORT_MESSAGES || seen.len() >= MAX_SYSTEM_REPORT_LOOKUPS {
                break;
            }

            if seen.contains(&message_id) {
                continue;
            }

            seen.push(message_id);

            let message = match db.fetch_message(message_id).await {
                Ok(message) => message,
                Err(err) => {
                    if !matches!(err.error_type, ErrorType::NotFound) {
                        warn!("System report could not fetch message {message_id}: {err:?}");
                    }

                    continue;
                }
            };

            // Never attach someone else's message as evidence against this user
            if message.author != reported_user.id {
                warn!(
                    "System report against {} skipped message {message_id} by another author",
                    reported_user.id
                );
                continue;
            }

            // `None` is a stray plaintext row in a protected channel, which is
            // never evidence; a channel that no longer exists is skipped like
            // a deleted message. Any other failure still aborts the report.
            let (mut message_snapshot, message_files) =
                match SnapshotContent::generate_from_message(db, message).await {
                    Ok(Some(snapshot)) => snapshot,
                    Ok(None) => {
                        warn!(
                            "System report against {} skipped message {message_id}, it cannot be served",
                            reported_user.id
                        );
                        continue;
                    }
                    Err(err) if matches!(err.error_type, ErrorType::NotFound) => continue,
                    Err(err) => return Err(err),
                };

            // Nobody filed this report, so the surrounding context keeps only
            // the reported user's own messages; the other side's DMs are never
            // stored. The returned files are the kept message's attachments.
            if let SnapshotContent::Message {
                prior_context,
                leading_context,
                ..
            } = &mut message_snapshot
            {
                prior_context.retain(|message| message.author == reported_user.id);
                leading_context.retain(|message| message.author == reported_user.id);
            }

            snapshots.push(message_snapshot);
            files.extend(message_files);
            kept.push(message_id.clone());
        }

        // Mark all the attachments as reported so the evidence is kept
        for file in files {
            db.mark_attachment_as_reported(&file).await?;
        }

        // Insert all new generated snapshots
        for content in snapshots {
            let snapshot = Snapshot {
                id: Ulid::new().to_string(),
                report_id: id.clone(),
                content,
            };

            db.insert_snapshot(&snapshot).await?;
        }

        let additional_context = match additional_context
            .char_indices()
            .nth(MAX_ADDITIONAL_CONTEXT)
        {
            Some((index, _)) => additional_context[..index].to_string(),
            None => additional_context,
        };

        let report = Report {
            id,
            author_id: SYSTEM_USER_ID.to_string(),
            content: ReportedContent::User {
                id: reported_user.id.clone(),
                report_reason: UserReportReason::SpamAbuse,
                // Only ever a message that was snapshotted as evidence, never
                // a skipped (deleted or foreign) id
                message_id: kept.into_iter().next(),
            },
            additional_context,
            status: ReportStatus::Created {},
            notes: String::new(),
        };

        db.insert_report(&report).await?;

        // Same "global" topic as user-filed reports: only privileged
        // (moderator) sessions subscribe to it in bonfire
        EventV1::ReportCreate(report.clone().into()).global().await;

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::Timestamp;
    use revolt_models::v0::{ReportStatus, ReportedContent, UserReportReason};

    use crate::{Channel, Database, DmGuard, Message, SnapshotContent, User};

    use super::{Report, SYSTEM_USER_ID};

    #[tokio::test]
    async fn create_system_files_user_report_with_message_snapshots() {
        let db = Database::Reference(Default::default());

        let user = User {
            id: ulid::Ulid::new().to_string(),
            username: "spammer".to_string(),
            discriminator: "0001".to_string(),
            dm_guard: Some(DmGuard {
                report_id: "01REPORT00000000000000000000".to_string(),
                flagged_at: Timestamp::now_utc(),
                paused: true,
                cleared_at: None,
                recipients: 3,
                fingerprint: "fingerprint".to_string(),
            }),
            ..Default::default()
        };

        // Fixed ids so the context order is known. In the first DM: prior
        // messages by both sides, the reported message, then the
        // recipient's reply right after it. The same text then goes to a
        // second DM three more times.
        let channel = "01CHANNEL0000000000000000AA";
        let second_channel = "01CHANNEL0000000000000000BB";
        let other_author = "01OTHERUSER00000000000000AA".to_string();
        let mk = |id: &str, channel: &str, author: &str, content: &str| Message {
            id: id.to_string(),
            channel: channel.to_string(),
            author: author.to_string(),
            content: Some(content.to_string()),
            ..Default::default()
        };

        let prior_own = mk(
            "01MSG0000000000000000000001",
            channel,
            &user.id,
            "hello there",
        );
        let prior_other = mk(
            "01MSG0000000000000000000002",
            channel,
            &other_author,
            "my address is",
        );
        let message = mk(
            "01MSG0000000000000000000003",
            channel,
            &user.id,
            "buy cheap followers",
        );
        // A message by someone else must never become evidence
        let other = mk(
            "01MSG0000000000000000000004",
            channel,
            &other_author,
            "who is this?",
        );
        let own_2 = mk(
            "01MSG0000000000000000000011",
            second_channel,
            &user.id,
            "buy cheap followers",
        );
        let own_3 = mk(
            "01MSG0000000000000000000012",
            second_channel,
            &user.id,
            "buy cheap followers",
        );
        let own_4 = mk(
            "01MSG0000000000000000000013",
            second_channel,
            &user.id,
            "buy cheap followers",
        );

        // The message snapshot reads each message's channel (protected
        // channels), so both DMs must exist
        for id in [channel, second_channel] {
            db.insert_channel(&Channel::DirectMessage {
                id: id.to_string(),
                active: true,
                recipients: vec![user.id.clone(), other_author.clone()],
                last_message_id: None,
            })
            .await
            .unwrap();
        }

        for row in [
            &prior_own,
            &prior_other,
            &message,
            &other,
            &own_2,
            &own_3,
            &own_4,
        ] {
            db.insert_message(row).await.unwrap();
        }

        let missing_id = ulid::Ulid::new().to_string();
        let report_id = ulid::Ulid::new().to_string();

        // Two-byte characters: a byte-index truncation would split one
        let long_context = "\u{e9}".repeat(1200);

        // Skipped ids come first: they must neither use up the cap nor
        // become the report's message_id
        let created = Report::create_system(
            &db,
            report_id.clone(),
            &user,
            &[
                missing_id,
                other.id.clone(),
                message.id.clone(),
                own_2.id.clone(),
                own_3.id.clone(),
                own_4.id.clone(),
            ],
            long_context,
        )
        .await
        .expect("system report is filed even when a message is missing");

        let report = db.fetch_report(&report_id).await.unwrap();
        assert_eq!(report, created);
        assert_eq!(report.author_id, SYSTEM_USER_ID);
        assert_ne!(report.author_id, user.id);
        assert!(matches!(report.status, ReportStatus::Created {}));
        assert_eq!(report.additional_context.chars().count(), 1000);

        match &report.content {
            ReportedContent::User {
                id,
                report_reason,
                message_id,
            } => {
                assert_eq!(id, &user.id);
                assert!(matches!(report_reason, UserReportReason::SpamAbuse));
                assert_eq!(message_id.as_deref(), Some(message.id.as_str()));
            }
            content => panic!("expected a user report, got {content:?}"),
        }

        // One user snapshot plus the first three messages by the reported
        // user; the missing id and the foreign message add none
        let snapshots = db.fetch_snapshots_by_report(&report_id).await.unwrap();
        assert_eq!(snapshots.len(), 4, "{snapshots:?}");

        let snapshot_user = snapshots
            .iter()
            .find_map(|snapshot| match &snapshot.content {
                SnapshotContent::User(user) => Some(user),
                _ => None,
            })
            .expect("user snapshot");
        assert_eq!(snapshot_user.id, user.id);
        assert!(snapshot_user.dm_guard.is_none());

        let snapshot_messages: Vec<(&Message, &Vec<Message>, &Vec<Message>)> = snapshots
            .iter()
            .filter_map(|snapshot| match &snapshot.content {
                SnapshotContent::Message {
                    message,
                    prior_context,
                    leading_context,
                } => Some((message, prior_context, leading_context)),
                _ => None,
            })
            .collect();

        let mut kept_ids: Vec<&str> = snapshot_messages
            .iter()
            .map(|(message, _, _)| message.id.as_str())
            .collect();
        kept_ids.sort();
        assert_eq!(
            kept_ids,
            vec![message.id.as_str(), own_2.id.as_str(), own_3.id.as_str()]
        );

        // The recipient's messages are never stored, in any snapshot's
        // context; the reported user's own context is
        for (_, prior_context, leading_context) in &snapshot_messages {
            assert!(
                prior_context
                    .iter()
                    .chain(leading_context.iter())
                    .all(|context| context.author == user.id),
                "{prior_context:?} {leading_context:?}"
            );
        }

        let (_, prior_context, leading_context) = snapshot_messages
            .iter()
            .find(|(snapshot_message, _, _)| snapshot_message.id == message.id)
            .expect("snapshot of the first kept message");
        assert_eq!(
            prior_context
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            vec![prior_own.id.as_str()]
        );
        assert!(leading_context.is_empty(), "{leading_context:?}");
    }

    /// W2 audit C10: a message whose channel no longer exists is skipped
    /// like a deleted one, and the report is still filed with the next live
    /// message as its evidence. Run under REFERENCE and MONGODB.
    ///
    /// Control: `create_system` fails the report on a skipped snapshot (its
    /// `Ok(None)` and `NotFound` arms returning an error) → this test fails.
    #[tokio::test]
    async fn create_system_skips_a_message_whose_channel_is_gone() {
        database_test!(|db| async move {
            let user = User {
                id: ulid::Ulid::new().to_string(),
                username: "spammer".to_string(),
                discriminator: "0001".to_string(),
                ..Default::default()
            };
            let other_author = ulid::Ulid::new().to_string();
            let live_channel = ulid::Ulid::new().to_string();
            let gone_channel = ulid::Ulid::new().to_string();
            db.insert_channel(&Channel::DirectMessage {
                id: live_channel.clone(),
                active: true,
                recipients: vec![user.id.clone(), other_author],
                last_message_id: None,
            })
            .await
            .unwrap();

            // Inserted while no channel row exists: the floor takes a
            // missing channel as unprotected
            let mk = |channel: &str| Message {
                id: ulid::Ulid::new().to_string(),
                channel: channel.to_string(),
                author: user.id.clone(),
                content: Some("buy cheap followers".to_string()),
                ..Default::default()
            };
            let orphaned = mk(&gone_channel);
            let live = mk(&live_channel);
            for row in [&orphaned, &live] {
                db.insert_message(row).await.unwrap();
            }

            let report_id = ulid::Ulid::new().to_string();
            Report::create_system(
                &db,
                report_id.clone(),
                &user,
                &[orphaned.id.clone(), live.id.clone()],
                String::new(),
            )
            .await
            .expect("the report is filed although a channel is gone");

            let report = db.fetch_report(&report_id).await.unwrap();
            match &report.content {
                ReportedContent::User { message_id, .. } => {
                    assert_eq!(message_id.as_deref(), Some(live.id.as_str()))
                }
                content => panic!("expected a user report, got {content:?}"),
            }

            let snapshots = db.fetch_snapshots_by_report(&report_id).await.unwrap();
            let message_ids: Vec<&str> = snapshots
                .iter()
                .filter_map(|snapshot| match &snapshot.content {
                    SnapshotContent::Message { message, .. } => Some(message.id.as_str()),
                    _ => None,
                })
                .collect();
            assert_eq!(message_ids, vec![live.id.as_str()], "{snapshots:?}");
            assert_eq!(snapshots.len(), 2, "the user and the live message");
        });
    }
}
