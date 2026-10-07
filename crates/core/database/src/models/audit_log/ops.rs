use revolt_result::Result;

use crate::{AuditLogAction, AuditLogEntry};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractAuditLog: Sync + Send {
    /// Insert an audit log entry. Entries are append-only.
    async fn insert_audit_log_entry(&self, entry: &AuditLogEntry) -> Result<()>;

    /// Fetch a server's audit log, newest first (descending `_id`).
    ///
    /// - `before` is an exclusive ULID cursor: only entries with a smaller
    ///   id are returned.
    /// - `action` keeps only entries of that kind.
    /// - `user` keeps only entries whose `actor` is that user.
    /// - `limit` is already clamped by the caller; both drivers clamp it to
    ///   `1..=AUDIT_LOG_FETCH_MAX` again so that a stray 0 cannot mean
    ///   "no limit" on MongoDB and "nothing" on the reference driver.
    ///
    /// The sort is part of the contract: the reference driver iterates a
    /// HashMap and MUST sort explicitly.
    async fn fetch_audit_log(
        &self,
        server: &str,
        before: Option<&str>,
        limit: i64,
        action: Option<AuditLogAction>,
        user: Option<&str>,
    ) -> Result<Vec<AuditLogEntry>>;

    /// Delete every entry, in every server, whose `_id` is strictly below
    /// `cutoff` (a ULID string). Returns how many entries were deleted.
    async fn prune_audit_log_before(&self, cutoff: &str) -> Result<u64>;
}

#[cfg(test)]
mod tests {
    use super::AbstractAuditLog;
    use crate::{
        AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue,
        AUDIT_LOG_FETCH_MAX,
    };

    const SERVER_A: &str = "01SERVERA00000000000000001";
    const SERVER_B: &str = "01SERVERB00000000000000001";
    const MOD_A: &str = "01MODA00000000000000000001";
    const MOD_B: &str = "01MODB00000000000000000001";

    /// A 26-character ULID-shaped id that sorts by `n`.
    fn id(n: u32) -> String {
        format!("01J0000000000000000000{n:04}")
    }

    fn entry(n: u32, server: &str, actor: Option<&str>, action: AuditLogAction) -> AuditLogEntry {
        AuditLogEntry {
            id: id(n),
            server: server.to_string(),
            actor: actor.map(str::to_string),
            action,
            target: Some("01TARGET000000000000000001".to_string()),
            channel: None,
            changes: vec![AuditLogChange::new(
                "timeout",
                None,
                Some(AuditValue::String("2026-10-07T00:00:00Z".to_string())),
            )],
            count: Some(n),
            reason: None,
        }
    }

    fn ids(entries: &[AuditLogEntry]) -> Vec<String> {
        entries.iter().map(|entry| entry.id.clone()).collect()
    }

    #[tokio::test]
    async fn fetch_order_cursor_filters_and_isolation() {
        database_test!(|db| async move {
            // Inserted out of order on purpose: the order a fetch returns
            // must come from the sort, not from insertion order.
            let rows = [
                entry(3, SERVER_A, Some(MOD_A), AuditLogAction::MemberKick),
                entry(1, SERVER_A, Some(MOD_A), AuditLogAction::MemberBanAdd),
                entry(5, SERVER_A, Some(MOD_B), AuditLogAction::MemberKick),
                entry(2, SERVER_A, None, AuditLogAction::RoleUpdate),
                entry(4, SERVER_B, Some(MOD_A), AuditLogAction::MemberKick),
            ];
            for row in &rows {
                db.insert_audit_log_entry(row).await.unwrap();
            }

            // Newest first, server isolated, and the stored fields round-trip.
            let all = db
                .fetch_audit_log(SERVER_A, None, AUDIT_LOG_FETCH_MAX, None, None)
                .await
                .unwrap();
            assert_eq!(ids(&all), vec![id(5), id(3), id(2), id(1)]);
            assert_eq!(all[1], rows[0]);
            assert_eq!(all[2].actor, None);

            // `before` is exclusive.
            let page = db
                .fetch_audit_log(
                    SERVER_A,
                    Some(id(3).as_str()),
                    AUDIT_LOG_FETCH_MAX,
                    None,
                    None,
                )
                .await
                .unwrap();
            assert_eq!(ids(&page), vec![id(2), id(1)]);

            // Limit keeps the newest.
            let limited = db
                .fetch_audit_log(SERVER_A, None, 2, None, None)
                .await
                .unwrap();
            assert_eq!(ids(&limited), vec![id(5), id(3)]);

            // Action filter.
            let kicks = db
                .fetch_audit_log(
                    SERVER_A,
                    None,
                    AUDIT_LOG_FETCH_MAX,
                    Some(AuditLogAction::MemberKick),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(ids(&kicks), vec![id(5), id(3)]);

            // User filter matches the actor only.
            let by_mod_a = db
                .fetch_audit_log(SERVER_A, None, AUDIT_LOG_FETCH_MAX, None, Some(MOD_A))
                .await
                .unwrap();
            assert_eq!(ids(&by_mod_a), vec![id(3), id(1)]);

            // Filters and cursor combine.
            let combined = db
                .fetch_audit_log(
                    SERVER_A,
                    Some(id(5).as_str()),
                    AUDIT_LOG_FETCH_MAX,
                    Some(AuditLogAction::MemberKick),
                    Some(MOD_A),
                )
                .await
                .unwrap();
            assert_eq!(ids(&combined), vec![id(3)]);

            // The other server sees only its own entry.
            let other = db
                .fetch_audit_log(SERVER_B, None, AUDIT_LOG_FETCH_MAX, None, None)
                .await
                .unwrap();
            assert_eq!(ids(&other), vec![id(4)]);
        });
    }

    #[tokio::test]
    async fn prune_deletes_only_entries_below_the_cutoff() {
        database_test!(|db| async move {
            db.insert_audit_log_entry(&entry(1, SERVER_A, Some(MOD_A), AuditLogAction::MemberKick))
                .await
                .unwrap();
            db.insert_audit_log_entry(&entry(2, SERVER_B, Some(MOD_A), AuditLogAction::MemberKick))
                .await
                .unwrap();
            db.insert_audit_log_entry(&entry(3, SERVER_A, Some(MOD_A), AuditLogAction::MemberKick))
                .await
                .unwrap();
            db.insert_audit_log_entry(&entry(4, SERVER_B, Some(MOD_A), AuditLogAction::MemberKick))
                .await
                .unwrap();

            // The cutoff is exclusive and spans every server.
            assert_eq!(db.prune_audit_log_before(&id(3)).await.unwrap(), 2);

            let a = db
                .fetch_audit_log(SERVER_A, None, AUDIT_LOG_FETCH_MAX, None, None)
                .await
                .unwrap();
            assert_eq!(ids(&a), vec![id(3)]);
            let b = db
                .fetch_audit_log(SERVER_B, None, AUDIT_LOG_FETCH_MAX, None, None)
                .await
                .unwrap();
            assert_eq!(ids(&b), vec![id(4)]);

            // Idempotent: nothing left below the cutoff.
            assert_eq!(db.prune_audit_log_before(&id(3)).await.unwrap(), 0);
        });
    }

    #[tokio::test]
    async fn record_mints_an_id_and_stores_the_draft() {
        database_test!(|db| async move {
            AuditLogEntry::record(
                &db,
                AuditLogDraft {
                    server: SERVER_A.to_string(),
                    actor: Some(MOD_A.to_string()),
                    action: AuditLogAction::MessageBulkDelete,
                    channel: Some("01CHANNEL00000000000000001".to_string()),
                    count: Some(12),
                    ..Default::default()
                },
            )
            .await;

            let entries = db
                .fetch_audit_log(SERVER_A, None, AUDIT_LOG_FETCH_MAX, None, None)
                .await
                .unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].id.len(), 26);
            assert_eq!(entries[0].action, AuditLogAction::MessageBulkDelete);
            assert_eq!(entries[0].actor.as_deref(), Some(MOD_A));
            assert_eq!(entries[0].count, Some(12));
            assert_eq!(entries[0].target, None);
            assert!(entries[0].changes.is_empty());

            // The draft default is the Unknown action.
            assert_eq!(AuditLogDraft::default().action, AuditLogAction::Unknown);
        });
    }
}
