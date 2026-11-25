use iso8601_timestamp::Timestamp;
use ulid::Ulid;

use crate::Database;

auto_derived!(
    /// Kind of platform staff action
    #[derive(Copy)]
    pub enum StaffAuditAction {
        TakedownSubmitted,
        TakedownResolved,
        TakedownMerged,
        TakedownViewedRequester,
        TakedownViewedEvidence,
        TakedownRemoved,
        TakedownAutoHidden,
        TakedownUnhidden,
        TakedownDeclined,
        TakedownNeedsInfo,
        TakedownInfoAdded,
        TakedownChildSafety,
        TakedownRestored,
        TakedownClosed,
        TakedownBadFaith,
        TakedownHoldReleased,
        TakedownRequesterPurged,
        TakedownEmailSent,
        TakedownAlertSent,
        TakedownDeadlineMet,
        TakedownDeadlineMissed,
    }

    /// One platform staff (or system) action. Append-only.
    ///
    /// Never holds personal data: no requester details, no content, no
    /// images. Only ids, counts and fixed codes.
    pub struct StaffAuditEntry {
        /// Unique id (ULID)
        #[serde(rename = "_id")]
        pub id: String,
        pub created_at: Timestamp,
        /// User id of the staff member (`None` = the system)
        pub actor: Option<String>,
        pub action: StaffAuditAction,
        pub request_id: Option<String>,
        /// Message, file, user or server ids only
        #[serde(default)]
        pub target_ids: Vec<String>,
        pub count: Option<u64>,
        /// A fixed code or the reviewer's reason header; never personal data
        pub note: Option<String>,
    }
);

impl StaffAuditEntry {
    /// Record a staff audit entry.
    ///
    /// Best-effort: mints the id and timestamp and inserts the entry. A failed
    /// insert is logged and swallowed, so this never returns an error. Call it
    /// after the audited action has succeeded.
    pub async fn record(
        db: &Database,
        actor: Option<&str>,
        action: StaffAuditAction,
        request_id: Option<&str>,
        target_ids: Vec<String>,
        count: Option<u64>,
        note: Option<&str>,
    ) {
        let entry = StaffAuditEntry {
            id: Ulid::new().to_string(),
            created_at: Timestamp::now_utc(),
            actor: actor.map(str::to_string),
            action,
            request_id: request_id.map(str::to_string),
            target_ids,
            count,
            note: note.map(str::to_string),
        };

        if let Err(error) = db.insert_staff_audit(&entry).await {
            error!(
                "Failed to record staff audit entry {:?} for request {:?}: {error:?}",
                entry.action, entry.request_id
            );
        }
    }
}
