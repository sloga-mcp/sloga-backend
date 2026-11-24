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
    /// The request had been declined: this removal corrects that decision,
    /// so the requester gets the new outcome under its own marker
    corrected: bool,
}

/// Outcome marker for a removal that corrects a decline (the decline
/// already spent `email:outcome`)
const MARK_OUTCOME_CORRECTED: &str = "email:outcome:corrected";

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
        corrected,
    } = removed?;

    // Emails after the mutex: a slow mail server never holds it

    // Requester: "removed" only for a full removal with copies and the
    // re-upload block, otherwise the fixed partial text
    let templates = email_templates().await;
    let marker = if corrected {
        MARK_OUTCOME_CORRECTED
    } else {
        "email:outcome"
    };
    if request.status == TakedownStatus::Removed && plan.include_copies && plan.block_reuploads {
        email_requester(
            db,
            &user.id,
            &request,
            marker,
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
            marker,
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
            // Nor does an account with no email: no notice, no marker, and
            // the removal stands. Its stand-in address is never mailed.
            let Some(address) = uploader_account.real_email() else {
                emailed.push(uploader);
                continue;
            };

            send_once(
                db,
                &user.id,
                &request.id,
                &format!("email:uploader:{file_id}"),
                address,
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
    let mut corrected = false;
    let mut cleared_bad_faith = false;
    let saved = save_with(db, working.clone(), |r| {
        merge_held_files(&mut r.held_files, &new_held);
        // Removing after a decline corrects it: the decline reason and any
        // bad-faith mark go, or the status page would show both outcomes and
        // the requester's later requests would lose auto-hide
        corrected = r.status == TakedownStatus::Declined;
        cleared_bad_faith = corrected && r.bad_faith;
        if corrected {
            r.decline_reason = None;
            r.bad_faith = false;
        }
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
    if cleared_bad_faith {
        StaffAuditEntry::record(
            db,
            Some(actor),
            StaffAuditAction::TakedownBadFaith,
            Some(request.id.as_str()),
            vec![],
            None,
            Some("cleared_by_removal"),
        )
        .await;
    }

    Ok(Removed {
        request,
        outcome,
        plan,
        corrected,
    })
}

#[cfg(test)]
mod test {
    //! The uploader's notice when the uploader has no email address.
    //!
    //! Sets `[features.takedown]` with `overwrite_config` (once per process:
    //! nextest) and reads the maildev container the other email tests use.
    //! The fixtures follow `takedown_tests.rs`, whose own are private to it.

    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        util::takedown_crypto::{reference_for, seal_requester},
        File, FileHash, FileUsedFor, FileUsedForType, Message, Metadata, PartialUser,
        SealedRequester, Session, StaffAuditAction, TakedownRequest, TakedownRole, TakedownSource,
        TakedownStatus, TakedownTarget, User,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Status};
    use serde_json::json;
    use ulid::Ulid;

    use super::super::tests::with_own_ticket;
    use crate::util::test::TestHarness;

    const DATA_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const MAILDEV_API: &str = "http://localhost:14080/api";

    /// Config first (once per process, before the harness reads it), then
    /// the listed reviewer: privileged, with MFA on
    async fn fixture() -> (TestHarness, Session) {
        let reviewer_id = Ulid::new().to_string();
        let listed = reviewer_id.clone();
        revolt_config::overwrite_config(move |settings| {
            settings.features.takedown.enabled = true;
            settings.features.takedown.data_key = DATA_KEY.to_string();
            settings.features.takedown.reviewers = vec![listed];
            settings.features.takedown.copy_confirm_threshold = 10;
            settings.features.takedown.retention_adult_days = 30;
        })
        .await;
        // A mutex key of this test process's own: nextest runs each test in
        // its own process, all against one Redis
        revolt_database::removal::use_takedown_mutex_key(format!(
            "takedown:mutex:test:{}",
            Ulid::new()
        ));

        let harness = TestHarness::new().await;

        let mut reviewer = User::create(
            &harness.db,
            TestHarness::rand_string(),
            Some(reviewer_id),
            None,
        )
        .await
        .expect("`User`");
        reviewer
            .update(
                &harness.db,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("promote staff");

        let (mut account, session) = harness.account_from_user(reviewer.id.clone()).await;
        account.mfa.totp_token = revolt_database::Totp::Enabled {
            secret: "JBSWY3DPEHPK3PXP".to_string(),
        };
        harness.db.save_account(&account).await.expect("`Account`");

        (harness, session)
    }

    /// A stored request with a sealed requester at `email`
    async fn insert_request(
        harness: &TestHarness,
        targets: Vec<TakedownTarget>,
        email: &str,
    ) -> TakedownRequest {
        let requester = SealedRequester {
            role: TakedownRole::Depicted,
            authority_note: None,
            name: "Requester Name".to_string(),
            signature: "Requester Name".to_string(),
            email: email.to_string(),
            description: "A photo of me".to_string(),
            extra: None,
            added_info: vec![],
        };
        let sealed =
            seal_requester(DATA_KEY, &serde_json::to_vec(&requester).unwrap()).expect("seal");

        let now = Timestamp::now_utc();
        let request = TakedownRequest {
            id: Ulid::new().to_string(),
            status: TakedownStatus::Received,
            source: TakedownSource::Web,
            received_at: now,
            deadline_at: now.checked_add(Duration::hours(48)).unwrap(),
            sealed,
            contact_fp: "fp-no-email".to_string(),
            status_token_hash: "hash".to_string(),
            locations: vec!["https://app.sloga.gg/server/S/channel/C/M".to_string()],
            minor_claimed: false,
            resolved: true,
            targets,
            linked_request_ids: vec![],
            held_files: vec![],
            auto_hidden_file_ids: vec![],
            hold_until: None,
            child_safety: false,
            bad_faith: false,
            throttled: false,
            decline_reason: None,
            first_opened_at: None,
            removed_at: None,
            closed_at: None,
            requester_purged: false,
            reviewer_note: None,
            revision: 0,
            markers: vec![],
        };
        harness
            .db
            .insert_takedown_request(&request)
            .await
            .expect("request");
        request
    }

    /// An image in a captioned message by `uploader` in a server channel.
    /// Returns the target (message) and the image's id.
    #[allow(clippy::disallowed_methods)] // fixtures are stored directly
    async fn image_message(harness: &TestHarness, uploader: &User) -> (TakedownTarget, String) {
        let (_, channels) = harness.new_server(uploader).await;
        let channel = channels[0].id().to_string();
        let hash = format!("hash-{}", Ulid::new());

        harness
            .db
            .insert_attachment_hash(&FileHash {
                id: hash.clone(),
                processed_hash: format!("{hash}-processed"),
                created_at: Timestamp::now_utc(),
                bucket_id: "attachments".to_string(),
                path: hash.clone(),
                iv: String::new(),
                format_version: None,
                key_id: None,
                metadata: Metadata::File,
                content_type: "image/png".to_string(),
                size: 1,
            })
            .await
            .expect("hash");

        let message_id = Ulid::new().to_string();
        let file = File {
            id: Ulid::new().to_string(),
            tag: "attachments".to_string(),
            filename: "image.png".to_string(),
            hash: Some(hash),
            uploaded_at: Some(Timestamp::now_utc()),
            uploader_id: Some(uploader.id.clone()),
            used_for: Some(FileUsedFor {
                object_type: FileUsedForType::Message,
                id: message_id.clone(),
            }),
            deleted: None,
            reported: None,
            metadata: Metadata::File,
            content_type: "image/png".to_string(),
            size: 1,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        };
        harness.db.insert_attachment(&file).await.expect("file");
        harness
            .db
            .insert_message(&Message {
                id: message_id.clone(),
                channel: channel.clone(),
                author: uploader.id.clone(),
                content: Some("caption".to_string()),
                attachments: Some(vec![file.clone()]),
                ..Default::default()
            })
            .await
            .expect("message");

        (
            TakedownTarget::Message {
                channel,
                message: message_id,
            },
            file.id,
        )
    }

    /// How many mails maildev holds for `mailbox`
    async fn mail_count(mailbox: &str) -> usize {
        let mails: Vec<serde_json::Value> = reqwest::Client::new()
            .get(format!("{MAILDEV_API}/email"))
            .send()
            .await
            .expect("maildev unreachable on :14080")
            .json()
            .await
            .expect("maildev list");

        mails
            .iter()
            .filter(|mail| {
                mail["envelope"]["to"]
                    .as_array()
                    .is_some_and(|to| to.iter().any(|to| to["address"] == mailbox))
            })
            .count()
    }

    /// Fails if: the uploader notice is mailed to the stand-in address of an
    /// account with no email (or its marker or audit entry is written as if
    /// it had been), the removal fails or is undone because that uploader has
    /// no address, or an uploader with an email in the same removal stops
    /// getting the notice.
    #[test]
    fn an_uploader_with_no_email_gets_no_notice_and_the_removal_stands() {
        crate::util::test::rt()
            .block_on(an_uploader_with_no_email_gets_no_notice_and_the_removal_stands_case())
    }

    async fn an_uploader_with_no_email_gets_no_notice_and_the_removal_stands_case() {
        let (harness, session) = fixture().await;
        let harness = &harness;

        let (no_email_account, _, no_email_uploader) = harness.new_no_email_user().await;
        let (ordinary_account, _, ordinary_uploader) = harness.new_user().await;
        assert!(no_email_account.real_email().is_none());

        let (no_email_target, no_email_image) = image_message(harness, &no_email_uploader).await;
        let (ordinary_target, ordinary_image) = image_message(harness, &ordinary_uploader).await;
        let requester = format!("{}@smtp.test", TestHarness::rand_string());
        let request =
            insert_request(harness, vec![no_email_target, ordinary_target], &requester).await;

        let post = harness
            .client
            .post(format!("/admin/takedown/requests/{}/remove", request.id))
            .header(ContentType::JSON)
            .body(json!({ "targets": [0, 1] }).to_string());
        let response = with_own_ticket(harness, post, &session, Some("takedown%20review"))
            .await
            .dispatch()
            .await;

        // The removal went through, both files
        assert_eq!(response.status(), Status::Ok);
        let result: v0::TakedownRemoveResult = response.into_json().await.expect("result");
        assert_eq!(result.removed_files, 2);
        for id in [&no_email_image, &ordinary_image] {
            let file = harness.db.fetch_attachment_by_id(id).await.expect("file");
            assert_eq!((file.deleted, file.reported), (Some(true), Some(true)), "{id}");
        }
        let after = harness
            .db
            .fetch_takedown_request(&request.id)
            .await
            .expect("stored");
        assert_eq!(after.status, TakedownStatus::Removed);
        assert_eq!(after.held_files.len(), 2);

        // The uploader with an email was told; its mail arriving proves the
        // sends ran and finished (they are awaited before the response)
        assert!(after
            .markers
            .contains(&format!("email:uploader:{ordinary_image}")));
        let (_, code) = harness.assert_email(&ordinary_account.email).await;
        assert_eq!(code, reference_for(&request.id));
        harness.assert_email(&requester).await;

        // The one without: no marker, no audit entry, nothing mailed
        assert!(!after
            .markers
            .contains(&format!("email:uploader:{no_email_image}")));
        let audit = harness
            .db
            .fetch_staff_audit_for_request(&request.id)
            .await
            .expect("audit");
        assert!(!audit.iter().any(|entry| {
            entry.action == StaffAuditAction::TakedownEmailSent
                && entry.target_ids.contains(&no_email_uploader.id)
        }));
        assert_eq!(mail_count(&no_email_account.email).await, 0);
    }
}
