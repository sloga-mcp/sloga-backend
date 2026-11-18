//! Shared pieces of the Take It Down staff routes: the reviewer gate, body
//! parsing, request storage with retries, the hold bookkeeping and emails.
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;

use iso8601_timestamp::{Duration, Timestamp};
use revolt_config::config;
use revolt_database::{
    removal::{merge_held_files, still_shown, takedown_busy, TakedownMutexGuard},
    util::{
        audit_reason::AuditLogReason,
        email::{send_email_safe, Template},
        takedown_crypto::{id_from_reference, open_requester, reference_for},
    },
    Account, Database, HeldFile, SealedRequester, StaffAuditAction, StaffAuditEntry,
    TakedownRequest, TakedownSource, User, ValidatedTicket,
};
use revolt_models::v0;
use revolt_result::{create_error, Error, ErrorType, Result};
use rocket::serde::json::Json;
use validator::Validate;

/// How often a write is retried after another writer (crond, a second
/// reviewer) stored a newer revision first
const SAVE_RETRIES: usize = 3;

/// Gate for every Take It Down staff route: a privileged account on
/// `[features.takedown] reviewers` with MFA turned on. Not gated on
/// `enabled`: open requests must still be handled while the public form is
/// switched off. Anything else is `NotPrivileged`.
pub(super) async fn require_reviewer(user: &User, account: &Account) -> Result<()> {
    let settings = config().await;
    if !user.privileged
        || account.id != user.id
        || !settings.features.takedown.reviewers.contains(&user.id)
        || !account.mfa.is_active()
    {
        return Err(create_error!(NotPrivileged));
    }
    Ok(())
}

/// Gate for a Take It Down action: the reviewer gate, the MFA ticket bound
/// to this user, and an `X-Audit-Log-Reason`. Returns the reason.
pub(super) async fn require_action(
    user: &User,
    account: &Account,
    ticket: &ValidatedTicket,
    reason: AuditLogReason,
) -> Result<String> {
    require_reviewer(user, account).await?;

    if ticket.account_id != user.id {
        return Err(create_error!(InvalidToken));
    }

    reason.validated()?.ok_or_else(|| {
        create_error!(FailedValidation {
            error: "AuditLogReasonRequired".to_string()
        })
    })
}

/// The one answer for a body that does not parse or validate. Neither the
/// parser's nor the validator's message is used or logged: both can quote
/// what the reviewer typed.
pub(super) fn invalid_body() -> Error {
    create_error!(FailedValidation {
        error: "InvalidBody".to_string()
    })
}

/// A parsed and validated body. Taken as `Option<Json<T>>` so Rocket never
/// logs a failed parse (its log line carries the raw body).
pub(super) fn body<T: Validate>(data: Option<Json<T>>) -> Result<T> {
    let data = data.ok_or_else(invalid_body)?.into_inner();
    data.validate().map_err(|_| invalid_body())?;
    Ok(data)
}

/// A request by its id or its `TD-` reference
pub(super) async fn fetch_request(db: &Database, raw: &str) -> Result<TakedownRequest> {
    let id = id_from_reference(raw)
        .or_else(|| id_from_reference(&reference_for(raw)))
        .ok_or_else(|| create_error!(NotFound))?;
    db.fetch_takedown_request(&id).await
}

/// Apply `change` and store the request. When another writer stored a newer
/// revision first, re-read and apply again, up to three times. `change` runs
/// on every attempt, so it re-checks whatever it relies on, and whatever it
/// records about the request is from the attempt that was stored.
pub(super) async fn save_with<F>(
    db: &Database,
    mut request: TakedownRequest,
    mut change: F,
) -> Result<TakedownRequest>
where
    F: FnMut(&mut TakedownRequest) -> Result<()>,
{
    let mut retries = 0;
    loop {
        change(&mut request)?;
        match db.replace_takedown_request(&mut request).await {
            Ok(()) => return Ok(request),
            Err(error)
                if matches!(error.error_type, ErrorType::InvalidOperation)
                    && retries < SAVE_RETRIES =>
            {
                retries += 1;
                request = db.fetch_takedown_request(&request.id).await?;
            }
            Err(error) => return Err(error),
        }
    }
}

/// End of the hold for files a request keeps hidden from `from` on
pub(super) async fn hold_end(from: Timestamp) -> Timestamp {
    let days = config().await.features.takedown.retention_adult_days;
    let days = i64::try_from(days).unwrap_or(i64::MAX / 86_400).min(36_500);
    from.saturating_add(Duration::days(days))
}

/// Files that a request other than `request_id` holds
pub(super) async fn held_elsewhere(db: &Database, request_id: &str) -> Result<HashSet<String>> {
    Ok(db
        .fetch_recent_takedown_requests(Timestamp::UNIX_EPOCH)
        .await?
        .into_iter()
        .filter(|other| other.id != request_id)
        .flat_map(|other| other.held_files.into_iter().map(|held| held.id))
        .collect())
}

/// Settle a request's auto-hides when a reviewer acts: the files in
/// `removed` stay held but are no longer auto-hides; every other auto-hide
/// comes off `held_files` and `auto_hidden_file_ids`, and its held record is
/// returned so `settle_auto_hides` can undo it once the request is stored. A
/// child-safety case keeps everything held. Runs inside `save_with`.
pub(super) fn take_auto_hides(request: &mut TakedownRequest, removed: &[String]) -> Vec<HeldFile> {
    request
        .auto_hidden_file_ids
        .retain(|id| !removed.contains(id));
    if request.child_safety {
        return vec![];
    }

    let ids = std::mem::take(&mut request.auto_hidden_file_ids);
    let taken = request
        .held_files
        .iter()
        .filter(|held| ids.contains(&held.id))
        .cloned()
        .collect();
    request.held_files.retain(|held| !ids.contains(&held.id));
    taken
}

/// Of `ids`, in order, the files that may be shown again: no other request
/// holds them, and their parent still exists and still shows them. A file
/// whose message, avatar or icon is gone stays hidden: showing it would
/// publish again what its uploader or a moderator took down.
pub(super) async fn showable(
    db: &Database,
    ids: &[String],
    elsewhere: &HashSet<String>,
) -> Result<Vec<String>> {
    let mut shown = Vec::new();
    for id in ids {
        if !elsewhere.contains(id) && still_shown(db, id).await? {
            shown.push(id.clone());
        }
    }
    Ok(shown)
}

/// Whether a stored request still lets a file be shown, judged after the
/// un-hide wrote. Each un-hide path has its own rule.
pub(super) type Approval = fn(&TakedownRequest, &str) -> bool;

/// After an auto-hide undo: the request must not hold the file again (a
/// removal on it merged the file back onto `held_files`)
pub(super) fn approved_after_undo(request: &TakedownRequest, id: &str) -> bool {
    !request.held_files.iter().any(|held| held.id == id)
}

/// After an unhide: still held as a file that was live before, no longer an
/// auto-hide, and not a child-safety case
pub(super) fn approved_after_unhide(request: &TakedownRequest, id: &str) -> bool {
    !request.child_safety
        && !request.auto_hidden_file_ids.iter().any(|known| known == id)
        && request
            .held_files
            .iter()
            .any(|held| held.id == id && !held.was_deleted)
}

/// After a restore: still held as a file that was live before, and not a
/// child-safety case
pub(super) fn approved_after_restore(request: &TakedownRequest, id: &str) -> bool {
    !request.child_safety
        && request
            .held_files
            .iter()
            .any(|held| held.id == id && !held.was_deleted)
}

/// After `unhide_attachments(shown)`: re-read the request and re-hide
/// (`deleted` and `reported`) every file it no longer approves, that another
/// request now holds, or whose parent no longer shows it.
///
/// This closes the race with a removal running at the same time: a removal
/// hides a file, takes it out of its parent, stores, then hides it again.
/// An un-hide that wrote before that last hide is undone by it; one that
/// wrote after it finds the parent no longer shows the file, here. Returns
/// the ids that stay shown, the stored request and the files other
/// requests hold, as read after the write.
async fn verify_shown(
    db: &Database,
    request_id: &str,
    shown: &[String],
    approved: Approval,
) -> Result<(Vec<String>, TakedownRequest, HashSet<String>)> {
    let fresh = db.fetch_takedown_request(request_id).await?;
    let elsewhere = held_elsewhere(db, request_id).await?;

    let mut kept = Vec::new();
    let mut hide_again = Vec::new();
    for id in shown {
        if approved(&fresh, id) && !elsewhere.contains(id) && still_shown(db, id).await? {
            kept.push(id.clone());
        } else {
            hide_again.push(id.clone());
        }
    }

    if !hide_again.is_empty() {
        log::warn!(
            "Take It Down {request_id}: {} file(s) changed while being shown again; hidden again",
            hide_again.len()
        );
        db.hide_attachments(&hide_again).await?;
    }

    Ok((kept, fresh, elsewhere))
}

/// Show `shown` again, then `verify_shown`. If the check can't run, every
/// file in `shown` is hidden again (best effort) before the error returns:
/// a file is never left shown unchecked.
async fn show_checked(
    db: &Database,
    request_id: &str,
    shown: &[String],
    approved: Approval,
) -> Result<(Vec<String>, TakedownRequest, HashSet<String>)> {
    let result = match db.unhide_attachments(shown).await {
        Ok(()) => verify_shown(db, request_id, shown, approved).await,
        // A partial write may have shown some of them
        Err(error) => Err(error),
    };

    if result.is_err() {
        if let Err(hide_error) = db.hide_attachments(shown).await {
            log::error!(
                "Take It Down {request_id}: files shown again could not be checked or hidden: {:?}",
                hide_error.error_type
            );
        }
    }
    result
}

/// `show_checked`, keeping only the ids that stay shown
pub(super) async fn show_files(
    db: &Database,
    request_id: &str,
    shown: &[String],
    approved: Approval,
) -> Result<Vec<String>> {
    Ok(show_checked(db, request_id, shown, approved).await?.0)
}

/// Undo auto-hides that `take_auto_hides` took off the stored request. Each
/// file that was live before is shown again if `showable` allows it, and
/// checked again after the write (`verify_shown`); any other stays hidden.
/// Then `reported` is cleared where this request set it and no open report,
/// other request or later removal on this request needs it, so a file left
/// hidden goes to the deletion sweep, as its uploader intended. Returns the
/// ids shown again.
async fn undo_auto_hides(
    db: &Database,
    request_id: &str,
    taken: &[HeldFile],
    lock: &TakedownMutexGuard,
) -> Result<Vec<String>> {
    if taken.is_empty() {
        return Ok(vec![]);
    }

    let elsewhere = held_elsewhere(db, request_id).await?;
    let live: Vec<String> = taken
        .iter()
        .filter(|held| !held.was_deleted)
        .map(|held| held.id.clone())
        .collect();
    let shown = showable(db, &live, &elsewhere).await?;
    let (kept, fresh, elsewhere) =
        show_checked(db, request_id, &shown, approved_after_undo).await?;

    let reported = db.fetch_open_report_file_ids().await?;
    let release: Vec<String> = taken
        .iter()
        .filter(|held| {
            !held.was_reported
                && !reported.contains(&held.id)
                && !elsewhere.contains(&held.id)
                && approved_after_undo(&fresh, &held.id)
        })
        .map(|held| held.id.clone())
        .collect();
    // A hold lost after the show must not clear `reported` on a file a
    // later removal holds: the sweep would delete held evidence
    ensure_held(lock)?;
    db.release_attachment_hold(&release).await?;

    Ok(kept)
}

/// `Err(takedown_busy())` once `lock` no longer holds the takedown mutex:
/// checked before every save and every batch of file-state writes
pub(super) fn ensure_held(lock: &TakedownMutexGuard) -> Result<()> {
    if lock.is_held() {
        Ok(())
    } else {
        Err(takedown_busy())
    }
}

/// Undo the auto-hides a stored action took off its request, and log it. A
/// failure, or a takedown mutex lost before the undo, leaves the files
/// hidden and kept (never deleted) and is logged as `unhide_failed` for
/// staff to finish by hand.
pub(super) async fn settle_auto_hides(
    db: &Database,
    actor: &str,
    request_id: &str,
    taken: &[HeldFile],
    reason: &str,
    lock: &TakedownMutexGuard,
) {
    if taken.is_empty() {
        return;
    }

    let ids: Vec<String> = taken.iter().map(|held| held.id.clone()).collect();
    let undone = match ensure_held(lock) {
        Ok(()) => undo_auto_hides(db, request_id, taken, lock).await,
        Err(error) => Err(error),
    };
    let (target_ids, note) = match undone {
        Ok(shown) => (shown, reason.to_string()),
        Err(error) => {
            log::error!(
                "Take It Down {request_id}: auto-hides were not undone: {:?}",
                error.error_type
            );
            (ids, "unhide_failed".to_string())
        }
    };
    if target_ids.is_empty() {
        return;
    }

    StaffAuditEntry::record(
        db,
        Some(actor),
        StaffAuditAction::TakedownUnhidden,
        Some(request_id),
        target_ids.clone(),
        Some(target_ids.len() as u64),
        Some(note.as_str()),
    )
    .await;
}

/// Hide `ids` again (`deleted` and `reported`), best effort: a failure is
/// logged, never raised over the error or outcome it follows
pub(super) async fn hide_again(db: &Database, request_id: &str, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    if let Err(error) = db.hide_attachments(ids).await {
        log::error!(
            "Take It Down {request_id}: {} file(s) could not be hidden again: {:?}",
            ids.len(),
            error.error_type
        );
    }
}

/// Merge-only fallback when a removal could not be stored: the files it hid
/// stay on record with their state from before, so a retry and the hold
/// release both see it
pub(super) async fn keep_held_files(
    db: &Database,
    request: TakedownRequest,
    new_held: &[HeldFile],
) {
    if new_held.is_empty() {
        return;
    }

    let id = request.id.clone();
    if let Err(error) = save_with(db, request, |r| {
        merge_held_files(&mut r.held_files, new_held);
        Ok(())
    })
    .await
    {
        log::error!(
            "Take It Down {id}: the files a removal hid were not recorded: {:?}",
            error.error_type
        );
    }
}

/// The requester's details, or `None` once they were purged
pub(super) async fn open_sealed(request: &TakedownRequest) -> Result<Option<SealedRequester>> {
    if request.requester_purged || request.sealed.is_empty() {
        return Ok(None);
    }

    let key = config().await.features.takedown.data_key.clone();
    let opened = open_requester(&key, &request.sealed)
        .ok()
        .and_then(|plain| serde_json::from_slice::<SealedRequester>(&plain).ok());

    match opened {
        Some(requester) => Ok(Some(requester)),
        None => {
            log::error!(
                "Take It Down {}: the requester details could not be opened",
                request.id
            );
            Err(create_error!(InternalError))
        }
    }
}

/// `reference` (and `reason`, when given) for a takedown email
pub(super) fn email_variables(
    request: &TakedownRequest,
    reason: Option<&str>,
) -> HashMap<&'static str, String> {
    let mut variables = HashMap::from([("reference", reference_for(&request.id))]);
    if let Some(reason) = reason {
        variables.insert("reason", reason.to_string());
    }
    variables
}

/// Send one takedown email unless `marker` was claimed before. Never fails
/// the action: a failure is logged by error kind only (never the address)
/// and recorded as `<code>_failed`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_once(
    db: &Database,
    actor: &str,
    request_id: &str,
    marker: &str,
    address: &str,
    template: &Template,
    variables: HashMap<&'static str, String>,
    code: &str,
    target_ids: Vec<String>,
) {
    match db.claim_takedown_marker(request_id, marker).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(error) => {
            log::error!(
                "Take It Down {request_id}: could not claim {marker}: {:?}",
                error.error_type
            );
            return;
        }
    }

    let note = match send_email_safe(address, template, variables).await {
        Ok(()) => code.to_string(),
        Err(error) => {
            log::error!(
                "Take It Down {request_id}: the {code} email was not sent: {:?}",
                error.error_type
            );
            format!("{code}_failed")
        }
    };

    StaffAuditEntry::record(
        db,
        Some(actor),
        StaffAuditAction::TakedownEmailSent,
        Some(request_id),
        target_ids,
        None,
        Some(note.as_str()),
    )
    .await;
}

/// Email the requester, once per `marker`. Nothing is sent once the details
/// were purged.
pub(super) async fn email_requester(
    db: &Database,
    actor: &str,
    request: &TakedownRequest,
    marker: &str,
    template: &Template,
    reason: Option<&str>,
    code: &str,
) {
    let requester = match open_sealed(request).await {
        Ok(Some(requester)) => requester,
        Ok(None) => return,
        Err(_) => {
            StaffAuditEntry::record(
                db,
                Some(actor),
                StaffAuditAction::TakedownEmailSent,
                Some(request.id.as_str()),
                vec![],
                None,
                Some(format!("{code}_failed").as_str()),
            )
            .await;
            return;
        }
    };

    send_once(
        db,
        actor,
        &request.id,
        marker,
        &requester.email,
        template,
        email_variables(request, reason),
        code,
        vec![],
    )
    .await;
}

/// Whether a request with this contact fingerprint was ever declined in
/// bad faith, other than `request` itself
pub(super) async fn bad_faith_history(db: &Database, request: &TakedownRequest) -> Result<bool> {
    if request.contact_fp.is_empty() {
        return Ok(false);
    }

    Ok(db
        .fetch_takedown_requests_by_contact_since(&request.contact_fp, Timestamp::UNIX_EPOCH)
        .await?
        .iter()
        .any(|other| other.id != request.id && other.bad_faith))
}

/// One queue row
pub(super) fn summary(request: &TakedownRequest, bad_faith_history: bool) -> v0::TakedownSummary {
    v0::TakedownSummary {
        id: request.id.clone(),
        reference: reference_for(&request.id),
        status: format!("{:?}", request.status),
        received_at: request.received_at.format().to_string(),
        deadline_at: request.deadline_at.format().to_string(),
        minor_claimed: request.minor_claimed,
        in_app: matches!(request.source, TakedownSource::InApp { .. }),
        targets: request.targets.len(),
        opened: request.first_opened_at.is_some(),
        child_safety: request.child_safety,
        throttled: request.throttled,
        bad_faith_history,
        auto_hidden: request.auto_hidden_file_ids.len(),
    }
}
