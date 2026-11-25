use iso8601_timestamp::Timestamp;
use revolt_database::{
    removal::{acquire_takedown_mutex, TakedownMutexGuard},
    util::{
        audit_reason::AuditLogReason,
        email::{
            email_templates, TAKEDOWN_DECLINE_DUPLICATE, TAKEDOWN_DECLINE_NOT_FOUND,
            TAKEDOWN_DECLINE_NOT_INTIMATE, TAKEDOWN_DECLINE_NOT_ON_SLOGA, TAKEDOWN_DECLINE_OTHER,
        },
    },
    Account, Database, HeldFile, StaffAuditAction, StaffAuditEntry, TakedownDeclineReason,
    TakedownRequest, TakedownStatus, User, ValidatedTicket,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

use super::takedown_common::{
    body, email_requester, ensure_held, fetch_request, hold_end, require_action, save_with,
    settle_auto_hides, take_auto_hides,
};

/// The stored reason and the fixed text the requester gets. Bad faith is
/// stored as such and shown to the requester as "other".
fn decline_reason(data: &v0::DataTakedownDecline) -> (TakedownDeclineReason, &'static str) {
    if data.bad_faith {
        return (TakedownDeclineReason::BadFaith, TAKEDOWN_DECLINE_OTHER);
    }

    match data.reason {
        v0::TakedownPublicDecline::NotIntimate => (
            TakedownDeclineReason::NotIntimate,
            TAKEDOWN_DECLINE_NOT_INTIMATE,
        ),
        v0::TakedownPublicDecline::NotFound => {
            (TakedownDeclineReason::NotFound, TAKEDOWN_DECLINE_NOT_FOUND)
        }
        v0::TakedownPublicDecline::NotOnSloga => (
            TakedownDeclineReason::NotOnSloga,
            TAKEDOWN_DECLINE_NOT_ON_SLOGA,
        ),
        v0::TakedownPublicDecline::Duplicate => {
            (TakedownDeclineReason::Duplicate, TAKEDOWN_DECLINE_DUPLICATE)
        }
        v0::TakedownPublicDecline::Other => (TakedownDeclineReason::Other, TAKEDOWN_DECLINE_OTHER),
    }
}

/// # Decline Take It Down Request
///
/// Decline an open request with a fixed reason the requester is emailed
/// (bad faith is shown to them as "other" and flags their address for later
/// requests). The note stays internal. Files this request auto-hid are shown
/// again unless another request holds them. Runs under the takedown mutex;
/// still busy after 10 s = `TakedownBusy`.
///
/// Requires a reviewer, an MFA ticket and `X-Audit-Log-Reason`.
#[openapi(tag = "Take It Down")]
#[post("/takedown/requests/<id>/decline", data = "<data>")]
pub async fn decline_takedown_request(
    db: &State<Database>,
    user: User,
    account: Account,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    id: String,
    data: Option<Json<v0::DataTakedownDecline>>,
) -> Result<EmptyResponse> {
    let reason = require_action(&user, &account, &ticket, reason).await?;
    let data = body(data)?;
    let (_, text) = decline_reason(&data);

    let lock = acquire_takedown_mutex().await?;
    let declined = decline_locked(db, &lock, &user.id, &reason, &id, &data).await;
    lock.release().await;
    let request = declined?;

    let templates = email_templates().await;
    email_requester(
        db,
        &user.id,
        &request,
        "email:outcome",
        &templates.takedown_declined,
        Some(text),
        "requester_declined",
    )
    .await;

    Ok(EmptyResponse)
}

/// The decline itself, under the takedown mutex
async fn decline_locked(
    db: &Database,
    lock: &TakedownMutexGuard,
    actor: &str,
    reason: &str,
    id: &str,
    data: &v0::DataTakedownDecline,
) -> Result<TakedownRequest> {
    let request = fetch_request(db, id).await?;
    if !request.status.is_open() {
        return Err(create_error!(InvalidOperation));
    }

    let (stored, _) = decline_reason(data);
    let note = data
        .note
        .as_deref()
        .map(str::trim)
        .filter(|note| !note.is_empty())
        .map(str::to_string);

    let now = Timestamp::now_utc();
    let hold_until = hold_end(now).await;
    let mut taken: Vec<HeldFile> = Vec::new();
    ensure_held(lock)?;
    let request = save_with(db, request, |r| {
        if !r.status.is_open() {
            return Err(create_error!(InvalidOperation));
        }
        r.status = TakedownStatus::Declined;
        r.decline_reason = Some(stored.clone());
        r.bad_faith = data.bad_faith;
        r.reviewer_note = note.clone();
        // The deadline check reads `removed_at`, else `closed_at`
        if r.closed_at.is_none() {
            r.closed_at = Some(now);
        }
        // The content stays up, so every auto-hide ends: off the request
        // here, shown again once it is stored
        taken = take_auto_hides(r, &[]);
        // Whatever is still held is released on the normal schedule
        r.hold_until = if r.child_safety || r.held_files.is_empty() {
            None
        } else {
            Some(hold_until)
        };
        Ok(())
    })
    .await?;

    StaffAuditEntry::record(
        db,
        Some(actor),
        StaffAuditAction::TakedownDeclined,
        Some(request.id.as_str()),
        vec![],
        None,
        Some(reason),
    )
    .await;
    if data.bad_faith {
        StaffAuditEntry::record(
            db,
            Some(actor),
            StaffAuditAction::TakedownBadFaith,
            Some(request.id.as_str()),
            vec![],
            None,
            Some(reason),
        )
        .await;
    }
    settle_auto_hides(db, actor, &request.id, &taken, reason, lock).await;

    Ok(request)
}

/// # Ask for More Information
///
/// Move an open request to `NeedsInfo` and email the requester (once per
/// request) to add details from their status link. Auto-hidden files stay
/// hidden. Runs under the takedown mutex; still busy after 10 s =
/// `TakedownBusy`.
///
/// Requires a reviewer, an MFA ticket and `X-Audit-Log-Reason`.
#[openapi(tag = "Take It Down")]
#[post("/takedown/requests/<id>/needs-info")]
pub async fn request_takedown_info(
    db: &State<Database>,
    user: User,
    account: Account,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    id: String,
) -> Result<EmptyResponse> {
    let reason = require_action(&user, &account, &ticket, reason).await?;

    let lock = acquire_takedown_mutex().await?;
    let asked = needs_info_locked(db, &lock, &user.id, &reason, &id).await;
    lock.release().await;
    let request = asked?;

    let templates = email_templates().await;
    email_requester(
        db,
        &user.id,
        &request,
        "email:needs_info",
        &templates.takedown_needs_info,
        None,
        "requester_needs_info",
    )
    .await;

    Ok(EmptyResponse)
}

/// The status change itself, under the takedown mutex
async fn needs_info_locked(
    db: &Database,
    lock: &TakedownMutexGuard,
    actor: &str,
    reason: &str,
    id: &str,
) -> Result<TakedownRequest> {
    let request = fetch_request(db, id).await?;
    ensure_held(lock)?;
    let request = save_with(db, request, |r| {
        if !r.status.is_open() {
            return Err(create_error!(InvalidOperation));
        }
        r.status = TakedownStatus::NeedsInfo;
        Ok(())
    })
    .await?;

    StaffAuditEntry::record(
        db,
        Some(actor),
        StaffAuditAction::TakedownNeedsInfo,
        Some(request.id.as_str()),
        vec![],
        None,
        Some(reason),
    )
    .await;

    Ok(request)
}

/// # Close Take It Down Request
///
/// Close a request. Removed files stay held for `retention_adult_days`
/// after closing, then the normal deletion takes them; a child-safety hold
/// has no end. Auto-hidden files no removal took are shown again, unless
/// another request holds them (never in a child-safety case). Runs under
/// the takedown mutex; still busy after 10 s = `TakedownBusy`.
///
/// Requires a reviewer, an MFA ticket and `X-Audit-Log-Reason`.
#[openapi(tag = "Take It Down")]
#[post("/takedown/requests/<id>/close")]
pub async fn close_takedown_request(
    db: &State<Database>,
    user: User,
    account: Account,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    id: String,
) -> Result<EmptyResponse> {
    let reason = require_action(&user, &account, &ticket, reason).await?;

    let lock = acquire_takedown_mutex().await?;
    let closed = close_locked(db, &lock, &user.id, &reason, &id).await;
    lock.release().await;
    closed?;

    Ok(EmptyResponse)
}

/// The close itself, under the takedown mutex
async fn close_locked(
    db: &Database,
    lock: &TakedownMutexGuard,
    actor: &str,
    reason: &str,
    id: &str,
) -> Result<()> {
    let request = fetch_request(db, id).await?;
    if request.status == TakedownStatus::Closed {
        return Err(create_error!(InvalidOperation));
    }

    let now = Timestamp::now_utc();
    let hold_until = hold_end(now).await;
    let mut taken: Vec<HeldFile> = Vec::new();
    ensure_held(lock)?;
    let request = save_with(db, request, |r| {
        if r.status == TakedownStatus::Closed {
            return Err(create_error!(InvalidOperation));
        }
        r.status = TakedownStatus::Closed;
        r.closed_at = Some(now);
        taken = take_auto_hides(r, &[]);
        r.hold_until = if r.child_safety || r.held_files.is_empty() {
            None
        } else {
            Some(hold_until)
        };
        Ok(())
    })
    .await?;

    StaffAuditEntry::record(
        db,
        Some(actor),
        StaffAuditAction::TakedownClosed,
        Some(request.id.as_str()),
        vec![],
        None,
        Some(reason),
    )
    .await;
    settle_auto_hides(db, actor, &request.id, &taken, reason, lock).await;

    Ok(())
}
