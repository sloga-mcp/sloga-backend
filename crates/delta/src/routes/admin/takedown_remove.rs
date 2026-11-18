use iso8601_timestamp::Timestamp;
use revolt_config::config;
use revolt_database::{
    removal::{
        acquire_takedown_mutex, execute_removal_tracked, merge_held_files, plan_copy_count,
        takedown_busy, RemovalOutcome, RemovalPlan, TakedownMutexGuard,
    },
    util::{
        audit_reason::AuditLogReason,
        email::{email_templates, TAKEDOWN_PARTIAL_REASON},
    },
    Account, Database, HeldFile, StaffAuditAction, StaffAuditEntry, TakedownRequest,
    TakedownStatus, TakedownTarget, User, ValidatedTicket,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use super::takedown_common::{
    body, email_requester, email_variables, fetch_request, hide_again, hold_end, keep_held_files,
    require_action, save_with, send_once, settle_auto_hides, take_auto_hides,
};

/// What a stored removal hands to the emails sent after the mutex
struct Removed {
    request: TakedownRequest,
    outcome: RemovalOutcome,
    plan: RemovalPlan,
}

/// # Remove Take It Down Targets
///
/// Hide the files of the chosen targets (and, by default, every identical
/// copy on Sloga), take them out of their messages, profiles, servers,
/// emojis and stickers, block re-uploads (by default) and email the
/// requester and each uploader. A message is deleted when nothing is left
/// of it, or when `whole_message` is set. Server audit logs show the deletes
/// as "System". Over `copy_confirm_threshold` copies, `confirm_copies` must
/// equal the copy count or nothing happens (`InvalidOperation`). Runs under
/// the takedown mutex; still busy after 10 s = `TakedownBusy`.
///
/// Requires a reviewer, an MFA ticket and `X-Audit-Log-Reason`.
#[openapi(tag = "Take It Down")]
#[post("/takedown/requests/<id>/remove", data = "<data>")]
pub async fn remove_takedown_targets(
    db: &State<Database>,
    user: User,
    account: Account,
    ticket: ValidatedTicket,
    reason: AuditLogReason,
    id: String,
    data: Option<Json<v0::DataTakedownRemove>>,
) -> Result<Json<v0::TakedownRemoveResult>> {
    let reason = require_action(&user, &account, &ticket, reason).await?;
    let data = body(data)?;

    let lock = acquire_takedown_mutex().await?;
    let removed = remove_locked(db, &lock, &user.id, &reason, &id, &data).await;
    lock.release().await;
    let Removed {
        request,
        outcome,
        plan,
    } = removed?;

    // Emails after the mutex: a slow mail server never holds it

    // Requester: "removed" only for a full removal with copies and the
    // re-upload block, otherwise the fixed partial text
    let templates = email_templates().await;
    if request.status == TakedownStatus::Removed && plan.include_copies && plan.block_reuploads {
        email_requester(
            db,
            &user.id,
            &request,
            "email:outcome",
            &templates.takedown_removed,
            None,
            "requester_removed",
        )
        .await;
    } else {
        email_requester(
            db,
            &user.id,
            &request,
            "email:outcome",
            &templates.takedown_partial,
            Some(TAKEDOWN_PARTIAL_REASON),
            "requester_partial",
        )
        .await;
    }

    // Uploaders: one email each, never in a child-safety case. The marker is
    // per file, so a retry does not email again.
    if !request.child_safety {
        let mut emailed: Vec<String> = Vec::new();
        for file_id in &outcome.removed_files {
            let Ok(file) = db.fetch_attachment_by_id(file_id).await else {
                continue;
            };
            let Some(uploader) = file.uploader_id else {
                continue;
            };
            if emailed.contains(&uploader) {
                continue;
            }
            // Bots and deleted accounts have no address
            let Ok(uploader_account) = db.fetch_account(&uploader).await else {
                continue;
            };

            send_once(
                db,
                &user.id,
                &request.id,
                &format!("email:uploader:{file_id}"),
                &uploader_account.email,
                &templates.takedown_uploader,
                email_variables(&request, None),
                "uploader",
                vec![uploader.clone(), file_id.clone()],
            )
            .await;
            emailed.push(uploader);
        }
    }

    Ok(Json(v0::TakedownRemoveResult {
        removed_files: outcome.removed_files.len(),
        deleted_messages: outcome.deleted_messages.len(),
        copies: outcome.copies,
        blocked: outcome.blocked_keys.len(),
    }))
}

/// The removal itself, under the takedown mutex: read, execute, store, hide
/// again, settle auto-hides, audit
async fn remove_locked(
    db: &Database,
    lock: &TakedownMutexGuard,
    actor: &str,
    reason: &str,
    id: &str,
    data: &v0::DataTakedownRemove,
) -> Result<Removed> {
    let request = fetch_request(db, id).await?;
    if request.status == TakedownStatus::Closed {
        return Err(create_error!(InvalidOperation));
    }

    let plan = RemovalPlan {
        targets: data.targets.clone(),
        whole_message: data.whole_message,
        include_copies: data.include_copies,
        block_reuploads: data.block_reuploads,
    };

    // A large copy count needs the reviewer to confirm the exact number
    let threshold = config().await.features.takedown.copy_confirm_threshold;
    let count = plan_copy_count(db, &request, &plan).await?;
    if count > threshold && data.confirm_copies != Some(count) {
        return Err(create_error!(InvalidOperation));
    }

    let mut working = request.clone();
    let mut hidden: Vec<String> = Vec::new();
    let outcome = match execute_removal_tracked(
        db,
        &mut working,
        &plan,
        actor,
        &mut hidden,
        Some(lock),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            // Exactly the files this run hid: hidden again, records kept
            // (the merge never replaces a stored one)
            hide_again(db, &request.id, &hidden).await;
            let records: Vec<HeldFile> = working
                .held_files
                .iter()
                .filter(|held| hidden.contains(&held.id))
                .cloned()
                .collect();
            keep_held_files(db, working, &records).await;
            return Err(error);
        }
    };

    // Nothing was there to take (a text-only message without
    // `whole_message`, only unresolvable targets): no outcome, no email.
    // Nothing was hidden either, so there is nothing to record.
    if outcome.removed_files.is_empty() && outcome.deleted_messages.is_empty() {
        return Err(create_error!(InvalidOperation));
    }

    // The record of every file just hidden, with its state from before
    let new_held: Vec<HeldFile> = working
        .held_files
        .iter()
        .filter(|held| outcome.removed_files.contains(&held.id))
        .cloned()
        .collect();

    // Partly: a target Sloga can't act on, or one this removal did not take
    let partly = request.targets.iter().enumerate().any(|(index, target)| {
        matches!(target, TakedownTarget::Unresolvable { .. }) || !plan.targets.contains(&index)
    });
    // Lost the mutex since the executor's last check: stop before the save,
    // with every file this run hid hidden again and on record
    if !lock.is_held() {
        hide_again(db, &request.id, &outcome.removed_files).await;
        keep_held_files(db, working, &new_held).await;
        return Err(takedown_busy());
    }

    let now = Timestamp::now_utc();
    let hold_until = hold_end(now).await;
    let mut taken: Vec<HeldFile> = Vec::new();
    let saved = save_with(db, working.clone(), |r| {
        merge_held_files(&mut r.held_files, &new_held);
        // Closed meanwhile: keep that outcome, only add what was hidden
        if r.status != TakedownStatus::Closed {
            r.status = if partly {
                TakedownStatus::PartiallyRemoved
            } else {
                TakedownStatus::Removed
            };
        }
        r.removed_at = Some(now);
        // Auto-hides the reviewer did not remove must not be released into
        // deletion with the removed files: they come off the request here
        // and are shown again once it is stored
        taken = take_auto_hides(r, &outcome.removed_files);
        r.hold_until = if r.child_safety || r.held_files.is_empty() {
            None
        } else {
            Some(hold_until)
        };
        Ok(())
    })
    .await;

    let request: TakedownRequest = match saved {
        Ok(request) => request,
        Err(error) => {
            hide_again(db, &request.id, &outcome.removed_files).await;
            keep_held_files(db, working, &new_held).await;
            return Err(error);
        }
    };

    // Hide again now that the removal is stored (defense in depth: the
    // mutex already keeps every other un-hide out while this runs)
    hide_again(db, &request.id, &outcome.removed_files).await;

    settle_auto_hides(db, actor, &request.id, &taken, reason, lock).await;

    let mut target_ids = outcome.removed_files.clone();
    target_ids.extend(outcome.deleted_messages.iter().cloned());
    StaffAuditEntry::record(
        db,
        Some(actor),
        StaffAuditAction::TakedownRemoved,
        Some(request.id.as_str()),
        target_ids,
        Some(outcome.copies),
        Some(reason),
    )
    .await;

    Ok(Removed {
        request,
        outcome,
        plan,
    })
}
