use std::collections::HashSet;

use revolt_models::v0::ReportStatusString;
use revolt_result::Result;

use crate::Report;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractReport: Sync + Send {
    /// Insert a new report into the database
    async fn insert_report(&self, report: &Report) -> Result<()>;

    /// Fetch a report by its id
    async fn fetch_report(&self, report_id: &str) -> Result<Report>;

    /// Fetch all reports, optionally filtered by status, newest first
    async fn fetch_reports(&self, status: Option<&ReportStatusString>) -> Result<Vec<Report>>;

    /// Update an existing report
    async fn update_report(&self, report: &Report) -> Result<()>;

    /// Ids of every file embedded in a snapshot of a report whose status is
    /// `Created`. Rejected and resolved reports are ignored. A row that
    /// cannot be read fails the call rather than being skipped, so a hold is
    /// never released on a partial answer.
    async fn fetch_open_report_file_ids(&self) -> Result<HashSet<String>>;
}

/// Collect the id of every file embedded anywhere in `value`.
///
/// A stored `File` is the only object a snapshot holds with both a string
/// `_id` and a string `tag`, so this finds the reported message's
/// attachments, its context messages' attachments, forwarded copies, server
/// icon and banner, role icons and user avatar and background, without a
/// field list to keep in sync. Both drivers walk the same JSON shape.
pub(crate) fn collect_file_ids(value: &serde_json::Value, out: &mut HashSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            if let (Some(serde_json::Value::String(id)), Some(serde_json::Value::String(_))) =
                (map.get("_id"), map.get("tag"))
            {
                out.insert(id.clone());
            }

            for child in map.values() {
                collect_file_ids(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_file_ids(item, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use iso8601_timestamp::Timestamp;
    use revolt_models::v0::{ReportStatus, ReportedContent, UserReportReason};

    use crate::{
        File, ForwardedSnapshot, Message, Metadata, Report, Server, Snapshot, SnapshotContent, User,
    };

    fn file(id: &str, tag: &str) -> File {
        File {
            id: id.to_string(),
            tag: tag.to_string(),
            filename: "image.png".to_string(),
            hash: Some(format!("hash-{id}")),
            uploaded_at: None,
            uploader_id: None,
            used_for: None,
            deleted: None,
            reported: Some(true),
            metadata: Metadata::File,
            content_type: "image/png".to_string(),
            size: 1,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        }
    }

    fn report(id: &str, status: ReportStatus) -> Report {
        Report {
            id: id.to_string(),
            author_id: "01REPORTER0000000000000001".to_string(),
            content: ReportedContent::User {
                id: "01REPORTED0000000000000001".to_string(),
                report_reason: UserReportReason::SpamAbuse,
                message_id: None,
            },
            additional_context: String::new(),
            status,
            notes: String::new(),
        }
    }

    fn message(id: &str, attachments: &[&str], forwarded: &[&str]) -> Message {
        Message {
            id: id.to_string(),
            channel: "01SNAPCHANNEL0000000000001".to_string(),
            author: "01REPORTED0000000000000001".to_string(),
            content: Some("hi".to_string()),
            attachments: (!attachments.is_empty()).then(|| {
                attachments
                    .iter()
                    .map(|id| file(id, "attachments"))
                    .collect()
            }),
            forwarded: (!forwarded.is_empty()).then(|| ForwardedSnapshot {
                message_id: "01SNAPSOURCE00000000000001".to_string(),
                channel_id: "01SNAPSOURCECHANNEL0000001".to_string(),
                server_id: None,
                author_id: None,
                content: None,
                attachments: forwarded.iter().map(|id| file(id, "attachments")).collect(),
                original_sent_at: 0,
            }),
            ..Default::default()
        }
    }

    fn message_snapshot(
        id: &str,
        report_id: &str,
        message: Message,
        prior: Vec<Message>,
    ) -> Snapshot {
        Snapshot {
            id: id.to_string(),
            report_id: report_id.to_string(),
            content: SnapshotContent::Message {
                prior_context: prior,
                leading_context: vec![],
                message,
            },
        }
    }

    fn set(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    #[test]
    fn collect_file_ids_needs_an_id_and_a_tag() {
        let mut out = HashSet::new();
        super::collect_file_ids(
            &serde_json::json!({
                "_id": "not-a-file",
                "nested": [
                    { "_id": "file-1", "tag": "attachments" },
                    { "_id": "no-tag" },
                    { "tag": "no-id" },
                    { "_id": 5, "tag": "attachments" },
                    { "deeper": { "icon": { "_id": "file-2", "tag": "icons" } } }
                ]
            }),
            &mut out,
        );
        assert_eq!(out, set(&["file-1", "file-2"]));
    }

    #[tokio::test]
    async fn open_report_file_ids_ignore_closed_reports() {
        database_test!(|db| async move {
            let open = "01OPENREPORT00000000000001";
            let open_empty = "01OPENREPORT00000000000002";
            let rejected = "01REJECTEDREPORT0000000001";
            let resolved = "01RESOLVEDREPORT0000000001";

            // Nothing open yet
            assert!(db.fetch_open_report_file_ids().await.unwrap().is_empty());

            db.insert_report(&report(open, ReportStatus::Created {}))
                .await
                .unwrap();
            db.insert_report(&report(open_empty, ReportStatus::Created {}))
                .await
                .unwrap();
            db.insert_report(&report(
                rejected,
                ReportStatus::Rejected {
                    rejection_reason: "no".to_string(),
                    closed_at: Some(Timestamp::now_utc()),
                },
            ))
            .await
            .unwrap();
            db.insert_report(&report(
                resolved,
                ReportStatus::Resolved {
                    closed_at: Some(Timestamp::now_utc()),
                },
            ))
            .await
            .unwrap();

            // An open report with no snapshots contributes nothing
            assert!(db.fetch_open_report_file_ids().await.unwrap().is_empty());

            let user = User {
                id: "01REPORTED0000000000000001".to_string(),
                username: "reported".to_string(),
                discriminator: "0001".to_string(),
                avatar: Some(file("01OPENAVATAR00000000000001", "avatars")),
                ..Default::default()
            };
            let server: Server = serde_json::from_value(serde_json::json!({
                "_id": "01SNAPSERVER00000000000001",
                "owner": "01REPORTED0000000000000001",
                "name": "server",
                "channels": [],
                "default_permissions": 0,
                "icon": file("01OPENICON0000000000000001", "icons"),
                "banner": file("01OPENBANNER00000000000001", "banners"),
            }))
            .expect("server");

            let snapshots = [
                message_snapshot(
                    "01SNAPSHOT0000000000000001",
                    open,
                    message(
                        "01SNAPMESSAGE0000000000002",
                        &["01OPENATTACH00000000000001", "01OPENATTACH00000000000002"],
                        &["01OPENFORWARD0000000000001"],
                    ),
                    vec![message(
                        "01SNAPMESSAGE0000000000001",
                        &["01OPENCONTEXT0000000000001"],
                        &[],
                    )],
                ),
                Snapshot {
                    id: "01SNAPSHOT0000000000000002".to_string(),
                    report_id: open.to_string(),
                    content: SnapshotContent::User(user),
                },
                Snapshot {
                    id: "01SNAPSHOT0000000000000003".to_string(),
                    report_id: open.to_string(),
                    content: SnapshotContent::Server(server),
                },
                message_snapshot(
                    "01SNAPSHOT0000000000000004",
                    rejected,
                    message(
                        "01SNAPMESSAGE0000000000003",
                        &["01REJECTEDATTACH0000000001"],
                        &[],
                    ),
                    vec![],
                ),
                message_snapshot(
                    "01SNAPSHOT0000000000000005",
                    resolved,
                    message(
                        "01SNAPMESSAGE0000000000004",
                        &["01RESOLVEDATTACH0000000001"],
                        &[],
                    ),
                    vec![],
                ),
                // A snapshot whose report row is missing is not open
                message_snapshot(
                    "01SNAPSHOT0000000000000006",
                    "01NOSUCHREPORT000000000001",
                    message(
                        "01SNAPMESSAGE0000000000005",
                        &["01ORPHANATTACH000000000001"],
                        &[],
                    ),
                    vec![],
                ),
            ];
            for row in &snapshots {
                db.insert_snapshot(row).await.unwrap();
            }

            assert_eq!(
                db.fetch_open_report_file_ids().await.unwrap(),
                set(&[
                    "01OPENATTACH00000000000001",
                    "01OPENATTACH00000000000002",
                    "01OPENFORWARD0000000000001",
                    "01OPENCONTEXT0000000000001",
                    "01OPENAVATAR00000000000001",
                    "01OPENICON0000000000000001",
                    "01OPENBANNER00000000000001",
                ])
            );

            // Closing the open report releases its files
            let mut closed = db.fetch_report(open).await.unwrap();
            closed.status = ReportStatus::Resolved {
                closed_at: Some(Timestamp::now_utc()),
            };
            db.update_report(&closed).await.unwrap();
            assert!(db.fetch_open_report_file_ids().await.unwrap().is_empty());

            // Reopening a rejected one brings its files in
            let mut reopened = db.fetch_report(rejected).await.unwrap();
            reopened.status = ReportStatus::Created {};
            db.update_report(&reopened).await.unwrap();
            assert_eq!(
                db.fetch_open_report_file_ids().await.unwrap(),
                set(&["01REJECTEDATTACH0000000001"])
            );
        });
    }
}
