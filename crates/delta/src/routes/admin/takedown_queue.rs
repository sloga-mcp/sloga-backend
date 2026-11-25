use std::collections::HashMap;

use iso8601_timestamp::{Duration, Timestamp};
use revolt_database::{
    removal::{copies_of, target_files},
    Account, Database, EmojiParent, File, SealedRequester, StaffAuditAction, StaffAuditEntry,
    TakedownRole, TakedownStatus, TakedownTarget, User,
};
use revolt_models::v0;
use revolt_result::{ErrorType, Result};
use rocket::{serde::json::Json, State};

use super::takedown_common::{
    bad_faith_history, fetch_request, open_sealed, require_reviewer, save_with, summary,
};

/// # List Take It Down Requests
///
/// Every open request and every request received in the last 30 days,
/// earliest deadline first, throttled requests after all others.
///
/// Requires a privileged account on the reviewer list with MFA turned on.
#[openapi(tag = "Take It Down")]
#[get("/takedown/requests")]
pub async fn list_takedown_requests(
    db: &State<Database>,
    user: User,
    account: Account,
) -> Result<Json<Vec<v0::TakedownSummary>>> {
    require_reviewer(&user, &account).await?;

    let since = Timestamp::now_utc()
        .checked_sub(Duration::days(30))
        .unwrap_or(Timestamp::UNIX_EPOCH);
    let mut requests = db.fetch_open_takedown_requests().await?;
    for request in db.fetch_recent_takedown_requests(since).await? {
        if !requests.iter().any(|known| known.id == request.id) {
            requests.push(request);
        }
    }
    // Throttled requests (an address over its daily soft limit) queue
    // behind the rest; each group by deadline
    requests.sort_by(|a, b| {
        a.throttled
            .cmp(&b.throttled)
            .then(a.deadline_at.cmp(&b.deadline_at))
    });

    // One lookup per contact fingerprint: the requests from it that were
    // declined in bad faith
    let mut bad_faith: HashMap<String, Vec<String>> = HashMap::new();
    let mut rows = Vec::with_capacity(requests.len());
    for request in &requests {
        let flagged = if request.contact_fp.is_empty() {
            false
        } else {
            if !bad_faith.contains_key(&request.contact_fp) {
                let ids = db
                    .fetch_takedown_requests_by_contact_since(
                        &request.contact_fp,
                        Timestamp::UNIX_EPOCH,
                    )
                    .await?
                    .into_iter()
                    .filter(|other| other.bad_faith)
                    .map(|other| other.id)
                    .collect();
                bad_faith.insert(request.contact_fp.clone(), ids);
            }
            bad_faith[&request.contact_fp]
                .iter()
                .any(|id| id != &request.id)
        };
        rows.push(summary(request, flagged));
    }

    // The queue shows no requester details; there is no staff audit action
    // for reading it
    log::info!("AUDIT takedown_list: actor={} rows={}", user.id, rows.len());

    Ok(Json(rows))
}

/// # Fetch Take It Down Request
///
/// One request with the requester's details (none once purged), every
/// target resolved to what Sloga holds, and the request's staff log. The
/// first view marks the request opened, and a request still at `Received`
/// moves to `UnderReview`. Each view of the requester's details is logged.
///
/// Requires a privileged account on the reviewer list with MFA turned on.
#[openapi(tag = "Take It Down")]
#[get("/takedown/requests/<id>")]
pub async fn fetch_takedown_request(
    db: &State<Database>,
    user: User,
    account: Account,
    id: String,
) -> Result<Json<v0::TakedownDetail>> {
    require_reviewer(&user, &account).await?;

    let request = fetch_request(db, &id).await?;
    let requester = open_sealed(&request).await?;

    let request = if request.first_opened_at.is_none() || request.status == TakedownStatus::Received
    {
        let now = Timestamp::now_utc();
        save_with(db, request, |r| {
            if r.first_opened_at.is_none() {
                r.first_opened_at = Some(now);
            }
            if r.status == TakedownStatus::Received {
                r.status = TakedownStatus::UnderReview;
            }
            Ok(())
        })
        .await?
    } else {
        request
    };

    if requester.is_some() {
        StaffAuditEntry::record(
            db,
            Some(user.id.as_str()),
            StaffAuditAction::TakedownViewedRequester,
            Some(request.id.as_str()),
            vec![],
            None,
            None,
        )
        .await;
    }

    let mut targets = Vec::with_capacity(request.targets.len());
    for (index, target) in request.targets.iter().enumerate() {
        targets.push(target_view(db, index, target).await?);
    }

    let audit = db
        .fetch_staff_audit_for_request(&request.id)
        .await?
        .into_iter()
        .map(|entry| v0::StaffAuditView {
            id: entry.id,
            created_at: entry.created_at.format().to_string(),
            actor: entry.actor,
            action: format!("{:?}", entry.action),
            target_ids: entry.target_ids,
            count: entry.count,
            note: entry.note,
        })
        .collect();

    Ok(Json(v0::TakedownDetail {
        summary: summary(&request, bad_faith_history(db, &request).await?),
        requester: requester.map(requester_view),
        locations: request.locations.clone(),
        targets,
        linked: request.linked_request_ids.clone(),
        audit,
    }))
}

fn requester_view(requester: SealedRequester) -> v0::TakedownRequesterView {
    v0::TakedownRequesterView {
        role: match requester.role {
            TakedownRole::Depicted => v0::TakedownRole::Depicted,
            TakedownRole::Authorized => v0::TakedownRole::Authorized,
        },
        authority_note: requester.authority_note,
        name: requester.name,
        signature: requester.signature,
        email: requester.email,
        description: requester.description,
        extra: requester.extra,
        added_info: requester.added_info,
    }
}

/// When an object with a ULID id was created
fn created_at(id: &str) -> Option<String> {
    ulid::Ulid::from_string(id)
        .ok()
        .map(|ulid| Timestamp::from(ulid.datetime()).format().to_string())
}

/// Whether an error only says the object is gone
fn is_gone(error: &revolt_result::Error) -> bool {
    matches!(
        error.error_type,
        ErrorType::NotFound
            | ErrorType::UnknownUser
            | ErrorType::UnknownServer
            | ErrorType::UnknownMessage
    )
}

async fn file_view(db: &Database, file: File) -> Result<v0::TakedownFileView> {
    let copies = copies_of(db, std::slice::from_ref(&file))
        .await?
        .iter()
        .filter(|copy| copy.deleted != Some(true))
        .count() as u64;

    Ok(v0::TakedownFileView {
        hidden: file.deleted == Some(true),
        id: file.id,
        tag: file.tag,
        content_type: file.content_type,
        size: file.size,
        copies,
    })
}

fn blank_view(index: usize, kind: &str) -> v0::TakedownTargetView {
    v0::TakedownTargetView {
        index,
        kind: kind.to_string(),
        id: None,
        channel_id: None,
        server_id: None,
        author_id: None,
        created_at: None,
        encrypted: false,
        unresolvable: None,
        files: vec![],
    }
}

/// A target as reviewers see it: resolved server-side, nothing outside
/// Sloga fetched
async fn target_view(
    db: &Database,
    index: usize,
    target: &TakedownTarget,
) -> Result<v0::TakedownTargetView> {
    let mut view = match target {
        TakedownTarget::Message { channel, message } => {
            let mut view = blank_view(index, "Message");
            view.id = Some(message.clone());
            view.channel_id = Some(channel.clone());
            view.created_at = created_at(message);
            match db.fetch_message(message).await {
                Ok(row) if &row.channel == channel => {
                    view.author_id = Some(row.author.clone());
                    view.encrypted = row.encrypted.is_some();
                    view.server_id = db
                        .fetch_channel(&row.channel)
                        .await
                        .ok()
                        .and_then(|channel| channel.server().map(str::to_string));
                }
                Ok(_) => view.unresolvable = Some("NotFound".to_string()),
                Err(error) if is_gone(&error) => view.unresolvable = Some("NotFound".to_string()),
                Err(error) => return Err(error),
            }
            view
        }
        TakedownTarget::File { file } => {
            let mut view = blank_view(index, "File");
            view.id = Some(file.clone());
            match db.fetch_attachment_by_id(file).await {
                Ok(row) => {
                    view.author_id = row.uploader_id.clone();
                    view.created_at = row.uploaded_at.map(|at| at.format().to_string());
                }
                Err(error) if is_gone(&error) => view.unresolvable = Some("NotFound".to_string()),
                Err(error) => return Err(error),
            }
            view
        }
        TakedownTarget::User { user } => {
            let mut view = blank_view(index, "User");
            view.id = Some(user.clone());
            view.created_at = created_at(user);
            view
        }
        TakedownTarget::Server { server } => {
            let mut view = blank_view(index, "Server");
            view.id = Some(server.clone());
            view.server_id = Some(server.clone());
            view
        }
        TakedownTarget::Emoji { emoji } => {
            let mut view = blank_view(index, "Emoji");
            view.id = Some(emoji.clone());
            view.created_at = created_at(emoji);
            match db.fetch_emoji(emoji).await {
                Ok(row) => {
                    view.author_id = Some(row.creator_id.clone());
                    if let EmojiParent::Server { id } = &row.parent {
                        view.server_id = Some(id.clone());
                    }
                }
                Err(error) if is_gone(&error) => {}
                Err(error) => return Err(error),
            }
            view
        }
        TakedownTarget::Unresolvable { kind, .. } => {
            let mut view = blank_view(index, "Unresolvable");
            view.unresolvable = Some(format!("{kind:?}"));
            view
        }
    };

    for file in target_files(db, target).await? {
        view.files.push(file_view(db, file).await?);
    }

    Ok(view)
}
