use revolt_config::config;
use revolt_database::{
    removal::{
        acquire_takedown_mutex, hold_files, merge_held_files, restorable_files, takedown_busy,
        target_files, unhide_allowed, TakedownMutexGuard,
    },
    util::audit_reason::AuditLogReason,
    Account, Database, File, HeldFile, StaffAuditAction, StaffAuditEntry, TakedownRequest, User,
    ValidatedTicket,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

use super::takedown_common::{
    approved_after_restore, approved_after_unhide, body, ensure_held, fetch_request,
    held_elsewhere, hide_again, keep_held_files, require_action, save_with, show_files, showable,
};

/// # Move Take It Down Request to Child Safety
///
/// For a request showing a minor: hide every file of every target at once,
/// keep them on an open-ended hold, and never email the uploader or allow a
/// restore or unhide. Copies and the re-upload block need a removal as
/// well. CyberTipline filing stays manual. Runs under the takedown mutex;
/// still busy after 10 s = `TakedownBusy`.
///
/// Requires a reviewer, an MFA ticket and `X-Audit-Log-Reason`.
#[openapi(tag = "Take It Down")]
#[post("/takedown/requests/<id>/child-safety")]
pub async fn move_takedown_to_child_safety(
    db: &State<Database>,
    user: User,
    account: Account,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    id: String,
) -> Result<EmptyResponse> {
    let reason = require_action(&user, &account, &ticket, reason).await?;

    let lock = acquire_takedown_mutex().await?;
    let moved = child_safety_locked(db, &lock, &user.id, &reason, &id).await;
    lock.release().await;
    moved?;

    Ok(EmptyResponse)
}

/// The move itself, under the takedown mutex
async fn child_safety_locked(
    db: &Database,
    lock: &TakedownMutexGuard,
    actor: &str,
    reason: &str,
    id: &str,
) -> Result<()> {
    let request = fetch_request(db, id).await?;

    // Every row is read before anything is hidden, so the held records
    // carry each file's state from before
    let mut files: Vec<File> = Vec::new();
    for target in &request.targets {
        for file in target_files(db, target).await? {
            if !files.iter().any(|known| known.id == file.id) {
                files.push(file);
            }
        }
    }
    let ids: Vec<String> = files.iter().map(|file| file.id.clone()).collect();

    let mut working = request.clone();
    let records_of = |working: &TakedownRequest, ids: &[String]| -> Vec<HeldFile> {
        working
            .held_files
            .iter()
            .filter(|held| ids.contains(&held.id))
            .cloned()
            .collect()
    };

    ensure_held(lock)?;
    let hidden = match hold_files(db, &mut working, &files).await {
        Ok(hidden) => hidden,
        Err(error) => {
            // The hide may have landed in part: all of them hidden again,
            // their records kept
            hide_again(db, &request.id, &ids).await;
            let records = records_of(&working, ids.as_slice());
            keep_held_files(db, working, &records).await;
            return Err(error);
        }
    };
    // The record of every file just hidden (the merge keeps a stored one)
    let new_held = records_of(&working, hidden.as_slice());

    // Lost the mutex since the hide: stop before the save, hidden and on record
    if !lock.is_held() {
        hide_again(db, &request.id, &hidden).await;
        keep_held_files(db, working, &new_held).await;
        return Err(takedown_busy());
    }

    let saved = save_with(db, working.clone(), |r| {
        merge_held_files(&mut r.held_files, &new_held);
        r.child_safety = true;
        r.hold_until = None;
        Ok(())
    })
    .await;
    let request = match saved {
        Ok(request) => request,
        Err(error) => {
            hide_again(db, &request.id, &hidden).await;
            keep_held_files(db, working, &new_held).await;
            return Err(error);
        }
    };

    // Hide again now that the hold is stored (defense in depth)
    hide_again(db, &request.id, &hidden).await;

    StaffAuditEntry::record(
        db,
        Some(actor),
        StaffAuditAction::TakedownChildSafety,
        Some(request.id.as_str()),
        hidden.clone(),
        Some(hidden.len() as u64),
        Some(reason),
    )
    .await;

    Ok(())
}

/// The first half of an unhide: approve auto-hidden `files` of `request`
/// and store that, without showing anything yet.
///
/// Checked first on `request` (which may be stale), so a reviewer gets the
/// refusal at once; then again inside the save on the stored copy, where a
/// removal or another writer that got there first is seen. The files come
/// off `auto_hidden_file_ids` and stay on `held_files` (the hold release
/// clears `reported`). Returns the stored request and the approved ids.
pub(super) async fn approve_unhide(
    db: &Database,
    request: TakedownRequest,
    files: &[String],
) -> Result<(TakedownRequest, Vec<String>)> {
    let ids = unhide_allowed(&request, files)?;
    let elsewhere = held_elsewhere(db, &request.id).await?;
    if showable(db, &ids, &elsewhere).await? != ids {
        return Err(create_error!(InvalidOperation));
    }

    let mut approved: Vec<String> = Vec::new();
    let request = save_with(db, request, |r| {
        approved = unhide_allowed(r, files)?;
        r.auto_hidden_file_ids.retain(|id| !approved.contains(id));
        Ok(())
    })
    .await?;

    Ok((request, approved))
}

/// The second half of an unhide, once approved and stored: show what
/// `showable` still allows (no other request holds it, its parent still
/// shows it), then check it again after the write (`show_files`, which
/// hides them again on any error). Returns the ids that stay shown.
pub(super) async fn show_approved(
    db: &Database,
    request_id: &str,
    approved: &[String],
) -> Result<Vec<String>> {
    let elsewhere = held_elsewhere(db, request_id).await?;
    let shown = showable(db, approved, &elsewhere).await?;
    show_files(db, request_id, &shown, approved_after_unhide).await
}

/// After `show_approved` failed: hide the approved files again (best
/// effort; a file is never left shown unchecked) and put them back on
/// `auto_hidden_file_ids` where the request still holds them as live
/// before, so the unhide can be tried again. Logged as `unhide_failed`.
async fn put_back_auto_hides(
    db: &Database,
    actor: &str,
    request: TakedownRequest,
    approved: &[String],
) {
    let id = request.id.clone();
    log::error!("Take It Down {id}: unhide_failed; the files are hidden again");

    hide_again(db, &id, approved).await;

    let stored = save_with(db, request, |r| {
        for file in approved {
            let held_live = r
                .held_files
                .iter()
                .any(|held| &held.id == file && !held.was_deleted);
            if held_live && !r.auto_hidden_file_ids.contains(file) {
                r.auto_hidden_file_ids.push(file.clone());
            }
        }
        Ok(())
    })
    .await;
    if let Err(error) = stored {
        log::error!(
            "Take It Down {id}: files of a failed unhide were not put back: {:?}",
            error.error_type
        );
    }

    StaffAuditEntry::record(
        db,
        Some(actor),
        StaffAuditAction::TakedownUnhidden,
        Some(id.as_str()),
        approved.to_vec(),
        None,
        Some("unhide_failed"),
    )
    .await;
}

/// Unhide auto-hidden `files` of `request`: `approve_unhide`, then
/// `show_approved`. The route runs it under the takedown mutex and passes
/// the guard: a mutex lost before the save refuses, and one lost before the
/// write puts the files back (`TakedownBusy`). Returns the stored request
/// and the ids shown.
pub(super) async fn unhide_held(
    db: &Database,
    actor: &str,
    request: TakedownRequest,
    files: &[String],
    lock: Option<&TakedownMutexGuard>,
) -> Result<(TakedownRequest, Vec<String>)> {
    let held = || lock.is_none_or(TakedownMutexGuard::is_held);
    if !held() {
        return Err(takedown_busy());
    }
    let (request, approved) = approve_unhide(db, request, files).await?;

    let shown = if held() {
        show_approved(db, &request.id, &approved).await
    } else {
        Err(takedown_busy())
    };
    match shown {
        Ok(shown) => Ok((request, shown)),
        Err(error) => {
            put_back_auto_hides(db, actor, request, &approved).await;
            Err(error)
        }
    }
}

/// # Unhide Take It Down Files
///
/// Show auto-hidden files of this request again (the undo for an
/// auto-hide). Only files it auto-hid that were live before, that no other
/// request holds and whose message, avatar or icon still shows them, never
/// a removed file and never in a child-safety case; any other id refuses
/// the whole call. Runs under the takedown mutex; still busy after 10 s =
/// `TakedownBusy`.
///
/// Requires a reviewer, an MFA ticket and `X-Audit-Log-Reason`.
#[openapi(tag = "Take It Down")]
#[post("/takedown/requests/<id>/unhide", data = "<data>")]
pub async fn unhide_takedown_files(
    db: &State<Database>,
    user: User,
    account: Account,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    id: String,
    data: Option<Json<v0::DataTakedownFileIds>>,
) -> Result<EmptyResponse> {
    let reason = require_action(&user, &account, &ticket, reason).await?;
    let data = body(data)?;

    let lock = acquire_takedown_mutex().await?;
    let unhidden = unhide_locked(db, &lock, &user.id, &reason, &id, &data.files).await;
    lock.release().await;
    unhidden?;

    Ok(EmptyResponse)
}

/// The unhide itself, under the takedown mutex
async fn unhide_locked(
    db: &Database,
    lock: &TakedownMutexGuard,
    actor: &str,
    reason: &str,
    id: &str,
    files: &[String],
) -> Result<()> {
    let request = fetch_request(db, id).await?;
    let (request, shown) = unhide_held(db, actor, request, files, Some(lock)).await?;

    StaffAuditEntry::record(
        db,
        Some(actor),
        StaffAuditAction::TakedownUnhidden,
        Some(request.id.as_str()),
        shown.clone(),
        Some(shown.len() as u64),
        Some(reason),
    )
    .await;

    Ok(())
}

/// # Restore Take It Down Files
///
/// After a successful appeal: show again every file this request hid that
/// was live before, that no other request holds and whose message, avatar
/// or icon still shows it, and lift the request's re-upload blocks. A file
/// a removal took out of its message, avatar or icon is no longer shown
/// there, so it stays hidden; deleted messages stay deleted. Never for a
/// child-safety case. Off unless `[features.takedown] restore_enabled`.
/// Runs under the takedown mutex; still busy after 10 s = `TakedownBusy`.
///
/// Requires a reviewer, an MFA ticket and `X-Audit-Log-Reason`.
#[openapi(tag = "Take It Down")]
#[post("/takedown/requests/<id>/restore")]
pub async fn restore_takedown_files(
    db: &State<Database>,
    user: User,
    account: Account,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    id: String,
) -> Result<EmptyResponse> {
    let reason = require_action(&user, &account, &ticket, reason).await?;

    if !config().await.features.takedown.restore_enabled {
        return Err(create_error!(FeatureDisabled {
            feature: "takedown_restore".to_string()
        }));
    }

    let lock = acquire_takedown_mutex().await?;
    let restored = restore_locked(db, &lock, &user.id, &reason, &id).await;
    lock.release().await;
    restored?;

    Ok(EmptyResponse)
}

/// The restore itself, under the takedown mutex
async fn restore_locked(
    db: &Database,
    lock: &TakedownMutexGuard,
    actor: &str,
    reason: &str,
    id: &str,
) -> Result<()> {
    let request = fetch_request(db, id).await?;
    if request.child_safety {
        return Err(create_error!(InvalidOperation));
    }

    // Decided on the stored copy, acted on once stored
    let mut approved: Vec<String> = Vec::new();
    let mut were_auto_hides: Vec<String> = Vec::new();
    ensure_held(lock)?;
    let request = save_with(db, request, |r| {
        if r.child_safety {
            return Err(create_error!(InvalidOperation));
        }
        approved = restorable_files(r);
        were_auto_hides = r
            .auto_hidden_file_ids
            .iter()
            .filter(|id| approved.contains(id))
            .cloned()
            .collect();
        r.auto_hidden_file_ids.retain(|id| !approved.contains(id));
        Ok(())
    })
    .await?;

    // Lost the mutex before the write: the auto-hides go back on the list
    // (the files are still hidden) and nothing is shown
    if !lock.is_held() {
        put_back_auto_hides(db, actor, request, &were_auto_hides).await;
        return Err(takedown_busy());
    }

    let elsewhere = held_elsewhere(db, &request.id).await?;
    let shown = showable(db, &approved, &elsewhere).await?;
    let shown = show_files(db, &request.id, &shown, approved_after_restore).await?;
    db.delete_upload_hash_blocks_for_request(&request.id)
        .await?;

    StaffAuditEntry::record(
        db,
        Some(actor),
        StaffAuditAction::TakedownRestored,
        Some(request.id.as_str()),
        shown.clone(),
        Some(shown.len() as u64),
        Some(reason),
    )
    .await;

    Ok(())
}
