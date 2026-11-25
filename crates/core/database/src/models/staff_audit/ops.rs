use revolt_result::Result;

use crate::StaffAuditEntry;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

/// Append-only: there are deliberately no update or delete operations.
#[async_trait]
pub trait AbstractStaffAudit: Sync + Send {
    /// Insert a staff audit entry
    async fn insert_staff_audit(&self, e: &StaffAuditEntry) -> Result<()>;

    /// Every entry for a Take It Down request, oldest first
    async fn fetch_staff_audit_for_request(&self, request_id: &str)
        -> Result<Vec<StaffAuditEntry>>;
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};

    use super::AbstractStaffAudit;
    use crate::{StaffAuditAction, StaffAuditEntry};

    const REQUEST_A: &str = "01TD0000000000000000000001";
    const REQUEST_B: &str = "01TD0000000000000000000002";
    const REVIEWER: &str = "01REVIEWER0000000000000001";

    fn at(seconds: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(Duration::seconds(1_800_000_000 + seconds))
            .unwrap()
    }

    fn entry(n: u32, request: &str, created: i64, action: StaffAuditAction) -> StaffAuditEntry {
        StaffAuditEntry {
            id: format!("01SA00000000000000000{n:05}"),
            created_at: at(created),
            actor: Some(REVIEWER.to_string()),
            action,
            request_id: Some(request.to_string()),
            target_ids: vec!["01FILE00000000000000000001".to_string()],
            count: Some(u64::from(n)),
            note: Some("not_intimate".to_string()),
        }
    }

    #[tokio::test]
    async fn entries_come_back_oldest_first_per_request() {
        database_test!(|db| async move {
            let rows = [
                entry(3, REQUEST_A, 300, StaffAuditAction::TakedownRemoved),
                entry(1, REQUEST_A, 100, StaffAuditAction::TakedownSubmitted),
                entry(4, REQUEST_B, 150, StaffAuditAction::TakedownSubmitted),
                entry(2, REQUEST_A, 200, StaffAuditAction::TakedownViewedRequester),
            ];
            for row in &rows {
                db.insert_staff_audit(row).await.unwrap();
            }

            let a = db.fetch_staff_audit_for_request(REQUEST_A).await.unwrap();
            assert_eq!(a, vec![rows[1].clone(), rows[3].clone(), rows[0].clone()]);

            let b = db.fetch_staff_audit_for_request(REQUEST_B).await.unwrap();
            assert_eq!(b, vec![rows[2].clone()]);

            assert!(db
                .fetch_staff_audit_for_request("01TD0000000000000000000003")
                .await
                .unwrap()
                .is_empty());

            // Ids are unique: a second insert with the same id is refused.
            assert!(db.insert_staff_audit(&rows[0]).await.is_err());
        });
    }

    #[tokio::test]
    async fn record_mints_an_entry() {
        database_test!(|db| async move {
            StaffAuditEntry::record(
                &db,
                None,
                StaffAuditAction::TakedownAlertSent,
                Some(REQUEST_A),
                vec![],
                None,
                Some("alert:12h"),
            )
            .await;

            let entries = db.fetch_staff_audit_for_request(REQUEST_A).await.unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].id.len(), 26);
            assert_eq!(entries[0].actor, None);
            assert_eq!(entries[0].action, StaffAuditAction::TakedownAlertSent);
            assert_eq!(entries[0].request_id.as_deref(), Some(REQUEST_A));
            assert!(entries[0].target_ids.is_empty());
            assert_eq!(entries[0].count, None);
            assert_eq!(entries[0].note.as_deref(), Some("alert:12h"));
        });
    }
}
