//! Take It Down staff routes: who may use them and what each action does.
//!
//! Every test sets `[features.takedown]` with `overwrite_config`, which runs
//! once per process before the harness reads the config: these need nextest
//! (one process per test). Email assertions read the maildev container the
//! other email tests use.
use iso8601_timestamp::{Duration, Timestamp};
use revolt_database::{
    util::takedown_crypto::{reference_for, seal_requester},
    Database, File, FileHash, FileUsedFor, FileUsedForType, HeldFile, Message, Metadata,
    PartialUser, SealedRequester, Session, StaffAuditAction, TakedownDeclineReason,
    TakedownRequest, TakedownRole, TakedownSource, TakedownStatus, TakedownTarget,
    UnresolvableKind, User,
};
use revolt_models::v0;
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::LocalResponse;
use serde_json::json;
use ulid::Ulid;

use super::tests::{error_type, validated_ticket, with_own_ticket};
use crate::util::test::TestHarness;

const DATA_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const MAILDEV_API: &str = "http://localhost:14080/api";

struct Fixture {
    harness: TestHarness,
    session: Session,
}

/// Config first (once per process, before the harness reads it), then the
/// listed reviewer: privileged, with MFA on when `mfa` is set
async fn fixture(copy_confirm_threshold: u64, mfa: bool) -> Fixture {
    fixture_with(copy_confirm_threshold, mfa, false).await
}

/// `fixture`, with `[features.takedown] restore_enabled` set as given
async fn fixture_with(copy_confirm_threshold: u64, mfa: bool, restore_enabled: bool) -> Fixture {
    let reviewer_id = Ulid::new().to_string();
    let listed = reviewer_id.clone();
    revolt_config::overwrite_config(move |settings| {
        settings.features.takedown.enabled = true;
        settings.features.takedown.data_key = DATA_KEY.to_string();
        settings.features.takedown.reviewers = vec![listed];
        settings.features.takedown.copy_confirm_threshold = copy_confirm_threshold;
        settings.features.takedown.retention_adult_days = 30;
        settings.features.takedown.restore_enabled = restore_enabled;
    })
    .await;
    // A mutex key of this test process's own: nextest runs each test in its
    // own process, all against one Redis
    revolt_database::removal::use_takedown_mutex_key(format!(
        "takedown:mutex:test:{}",
        Ulid::new()
    ));

    let harness = TestHarness::new().await;
    let (session, _) = staff_user(&harness, Some(reviewer_id), mfa).await;
    Fixture { harness, session }
}

/// A privileged user and their session; `id` fixes the user id
async fn staff_user(harness: &TestHarness, id: Option<String>, mfa: bool) -> (Session, User) {
    let mut user = User::create(&harness.db, TestHarness::rand_string(), id, None)
        .await
        .expect("`User`");
    user.update(
        &harness.db,
        PartialUser {
            privileged: Some(true),
            ..Default::default()
        },
        vec![],
    )
    .await
    .expect("promote staff");

    let (mut account, session) = harness.account_from_user(user.id.clone()).await;
    if mfa {
        account.mfa.totp_token = revolt_database::Totp::Enabled {
            secret: "JBSWY3DPEHPK3PXP".to_string(),
        };
        harness.db.save_account(&account).await.expect("`Account`");
    }

    (session, user)
}

fn requester_address() -> String {
    format!("{}@smtp.test", TestHarness::rand_string())
}

/// A stored request with a sealed requester
async fn insert_request(
    harness: &TestHarness,
    targets: Vec<TakedownTarget>,
    email: &str,
    contact_fp: &str,
    deadline_hours: i64,
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
    let sealed = seal_requester(DATA_KEY, &serde_json::to_vec(&requester).unwrap()).expect("seal");

    let now = Timestamp::now_utc();
    let request = TakedownRequest {
        id: Ulid::new().to_string(),
        status: TakedownStatus::Received,
        source: TakedownSource::Web,
        received_at: now,
        deadline_at: now.checked_add(Duration::hours(deadline_hours)).unwrap(),
        sealed,
        contact_fp: contact_fp.to_string(),
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

fn image(id: &str, hash: &str, message: &str, uploader: &str) -> File {
    File {
        id: id.to_string(),
        tag: "attachments".to_string(),
        filename: "image.png".to_string(),
        hash: Some(hash.to_string()),
        uploaded_at: Some(Timestamp::now_utc()),
        uploader_id: Some(uploader.to_string()),
        used_for: Some(FileUsedFor {
            object_type: FileUsedForType::Message,
            id: message.to_string(),
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
    }
}

/// An image in a captioned message by `uploader` in a server channel, and
/// `copies` re-uploads of the same bytes, each in its own captioned message.
/// Returns the target (message), the image's id and the copies' ids.
#[allow(clippy::disallowed_methods)] // fixtures are stored directly
async fn image_message(
    harness: &TestHarness,
    uploader: &User,
    copies: usize,
) -> (TakedownTarget, String, Vec<String>) {
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

    let mut ids = vec![];
    for _ in 0..=copies {
        let message_id = Ulid::new().to_string();
        let file = image(&Ulid::new().to_string(), &hash, &message_id, &uploader.id);
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
        ids.push((message_id, file.id));
    }

    let (message, file) = ids.remove(0);
    (
        TakedownTarget::Message { channel, message },
        file,
        ids.into_iter().map(|(_, file)| file).collect(),
    )
}

async fn get<'c>(harness: &'c TestHarness, session: &Session, path: &str) -> LocalResponse<'c> {
    harness
        .client
        .get(path.to_string())
        .header(Header::new("x-session-token", session.token.clone()))
        .dispatch()
        .await
}

/// `POST` as `session`'s user with a fresh ticket of their own and a reason
async fn act<'c>(
    harness: &'c TestHarness,
    session: &Session,
    path: &str,
    body: Option<serde_json::Value>,
) -> LocalResponse<'c> {
    let mut request = harness
        .client
        .post(path.to_string())
        .header(ContentType::JSON);
    if let Some(body) = body {
        request = request.body(body.to_string());
    }
    with_own_ticket(harness, request, session, Some("takedown%20review"))
        .await
        .dispatch()
        .await
}

fn path(request: &TakedownRequest, action: &str) -> String {
    format!("/admin/takedown/requests/{}/{}", request.id, action)
}

async fn stored(db: &Database, request: &TakedownRequest) -> TakedownRequest {
    db.fetch_takedown_request(&request.id)
        .await
        .expect("stored")
}

async fn flags(db: &Database, id: &str) -> (Option<bool>, Option<bool>) {
    let file = db.fetch_attachment_by_id(id).await.expect("file");
    (file.deleted, file.reported)
}

async fn audit_actions(db: &Database, request: &TakedownRequest) -> Vec<StaffAuditAction> {
    db.fetch_staff_audit_for_request(&request.id)
        .await
        .expect("audit")
        .into_iter()
        .map(|entry| entry.action)
        .collect()
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

#[test]
fn a_privileged_account_off_the_reviewer_list_is_refused() {
    crate::util::test::rt().block_on(a_privileged_account_off_the_reviewer_list_is_refused_case())
}

async fn a_privileged_account_off_the_reviewer_list_is_refused_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let request = insert_request(harness, vec![], &requester_address(), "fp-a", 48).await;

    // Privileged with MFA, but not on the list
    let (outsider, _) = staff_user(harness, None, true).await;

    let response = get(harness, &outsider, "/admin/takedown/requests").await;
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(error_type(response).await, "NotPrivileged");

    let detail = format!("/admin/takedown/requests/{}", request.id);
    let response = get(harness, &outsider, &detail).await;
    assert_eq!(response.status(), Status::Forbidden);

    let response = act(harness, &outsider, &path(&request, "close"), None).await;
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(error_type(response).await, "NotPrivileged");

    // Nothing was read or changed
    let after = stored(&harness.db, &request).await;
    assert_eq!(after.status, TakedownStatus::Received);
    assert_eq!(after.first_opened_at, None);
    assert!(audit_actions(&harness.db, &request).await.is_empty());

    // Control: the listed reviewer gets in
    let response = get(harness, &fixture.session, "/admin/takedown/requests").await;
    assert_eq!(response.status(), Status::Ok);
}

#[test]
fn a_listed_reviewer_without_mfa_is_refused() {
    crate::util::test::rt().block_on(a_listed_reviewer_without_mfa_is_refused_case())
}

async fn a_listed_reviewer_without_mfa_is_refused_case() {
    let fixture = fixture(25, false).await;
    let harness = &fixture.harness;
    let request = insert_request(harness, vec![], &requester_address(), "fp-a", 48).await;

    let response = get(harness, &fixture.session, "/admin/takedown/requests").await;
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(error_type(response).await, "NotPrivileged");

    // A ticket does not stand in for MFA on the account
    let response = act(harness, &fixture.session, &path(&request, "close"), None).await;
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(error_type(response).await, "NotPrivileged");
    assert_eq!(
        stored(&harness.db, &request).await.status,
        TakedownStatus::Received
    );
}

#[test]
fn actions_need_a_ticket_a_reason_and_never_reuse_one() {
    crate::util::test::rt().block_on(actions_need_a_ticket_a_reason_and_never_reuse_one_case())
}

async fn actions_need_a_ticket_a_reason_and_never_reuse_one_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;
    let request = insert_request(harness, vec![], &requester_address(), "fp-a", 48).await;

    // No ticket: the guard's 401
    let response = harness
        .client
        .post(path(&request, "needs-info"))
        .header(Header::new("x-session-token", session.token.clone()))
        .header(Header::new("X-Audit-Log-Reason", "review"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Unauthorized);

    // A ticket but no reason
    let request_without_reason = harness.client.post(path(&request, "needs-info"));
    let response = with_own_ticket(harness, request_without_reason, session, None)
        .await
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
    assert!(response
        .into_string()
        .await
        .expect("body")
        .contains("AuditLogReasonRequired"));
    assert_eq!(
        stored(&harness.db, &request).await.status,
        TakedownStatus::Received
    );

    // One ticket: the first action claims it, the replay finds none
    let ticket = validated_ticket(harness, &session.user_id).await;
    let mut statuses = vec![];
    for action in ["needs-info", "close"] {
        let response = harness
            .client
            .post(path(&request, action))
            .header(Header::new("x-session-token", session.token.clone()))
            .header(Header::new("x-mfa-ticket", ticket.token.clone()))
            .header(Header::new("X-Audit-Log-Reason", "review"))
            .dispatch()
            .await;
        statuses.push(response.status());
    }
    assert_eq!(statuses, vec![Status::NoContent, Status::Unauthorized]);
    assert_eq!(
        stored(&harness.db, &request).await.status,
        TakedownStatus::NeedsInfo
    );
}

#[test]
fn a_removal_over_the_threshold_needs_the_exact_copy_count() {
    crate::util::test::rt().block_on(a_removal_over_the_threshold_needs_the_exact_copy_count_case())
}

async fn a_removal_over_the_threshold_needs_the_exact_copy_count_case() {
    let fixture = fixture(1, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;

    let (uploader_account, _, uploader) = harness.new_user().await;
    let (target, image_id, copies) = image_message(harness, &uploader, 2).await;
    let requester = requester_address();
    let request = insert_request(harness, vec![target.clone()], &requester, "fp-a", 48).await;

    // Two copies over a threshold of one: no confirmation, or the wrong
    // count, removes nothing
    for body in [
        json!({ "targets": [0] }),
        json!({ "targets": [0], "confirm_copies": 1 }),
    ] {
        let response = act(harness, session, &path(&request, "remove"), Some(body)).await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(error_type(response).await, "InvalidOperation");
    }
    assert_eq!(flags(&harness.db, &image_id).await, (None, None));
    assert!(stored(&harness.db, &request).await.held_files.is_empty());

    // A body that does not parse gets the fixed answer, never an echo
    let response = act(
        harness,
        session,
        &path(&request, "remove"),
        Some(json!({ "targets": "ECHO-THIS-VALUE" })),
    )
    .await;
    assert_eq!(response.status(), Status::BadRequest);
    let text = response.into_string().await.expect("body");
    assert!(text.contains("InvalidBody"), "{}", text);
    assert!(!text.contains("ECHO-THIS-VALUE"), "{}", text);

    // The exact count goes through
    let response = act(
        harness,
        session,
        &path(&request, "remove"),
        Some(json!({ "targets": [0], "confirm_copies": 2 })),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let result: v0::TakedownRemoveResult = response.into_json().await.expect("result");
    assert_eq!(result.removed_files, 3);
    assert_eq!(result.copies, 2);
    assert_eq!(result.deleted_messages, 0);
    assert!(result.blocked >= 2, "orig and proc keys");

    for id in std::iter::once(&image_id).chain(copies.iter()) {
        assert_eq!(
            flags(&harness.db, id).await,
            (Some(true), Some(true)),
            "{}",
            id
        );
    }

    let after = stored(&harness.db, &request).await;
    assert_eq!(after.status, TakedownStatus::Removed);
    assert!(after.removed_at.is_some());
    assert!(after.hold_until.is_some());
    assert_eq!(after.held_files.len(), 3);
    assert!(after.held_files.iter().all(|held| !held.was_deleted));
    assert!(after
        .markers
        .contains(&format!("email:uploader:{image_id}")));
    assert!(after.markers.contains(&"email:outcome".to_string()));
    assert!(audit_actions(&harness.db, &request)
        .await
        .contains(&StaffAuditAction::TakedownRemoved));

    // The captioned message stays, without the image
    if let TakedownTarget::Message { message, .. } = &target {
        let message = harness.db.fetch_message(message).await.expect("message");
        assert!(message.attachments.unwrap_or_default().is_empty());
    }

    // The requester and the uploader were emailed, once each
    let reference = reference_for(&request.id);
    let (_, code) = harness.assert_email(&requester).await;
    assert_eq!(code, reference);
    let (_, code) = harness.assert_email(&uploader_account.email).await;
    assert_eq!(code, reference);

    // A removed file is not an auto-hide: unhide refuses it (restore is the
    // only way back, and it is off)
    let response = act(
        harness,
        session,
        &path(&request, "unhide"),
        Some(json!({ "files": [image_id] })),
    )
    .await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(error_type(response).await, "InvalidOperation");
    assert_eq!(
        flags(&harness.db, &image_id).await,
        (Some(true), Some(true))
    );
}

#[test]
fn an_auto_hide_the_reviewer_did_not_remove_is_never_deleted() {
    crate::util::test::rt()
        .block_on(an_auto_hide_the_reviewer_did_not_remove_is_never_deleted_case())
}

/// Two auto-hidden files, one removed: the other must come back and must
/// never reach the deletion sweep when the hold ends.
///
/// Control: without the auto-hide settling in the remove route, the kept
/// file stays on `held_files` with `deleted` set, and the simulated hold
/// release below hands it to the sweep.
async fn an_auto_hide_the_reviewer_did_not_remove_is_never_deleted_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;

    let (_, _, uploader) = harness.new_user().await;
    let (target, removed, others) = image_message(harness, &uploader, 1).await;
    let kept = others[0].clone();
    let request = insert_request(
        harness,
        vec![target, TakedownTarget::File { file: kept.clone() }],
        &requester_address(),
        "fp-a",
        48,
    )
    .await;

    // Both auto-hidden, as crond leaves them
    harness
        .db
        .hide_attachments(&[removed.clone(), kept.clone()])
        .await
        .expect("hide");
    let mut auto_hidden = stored(&harness.db, &request).await;
    auto_hidden.held_files = [&removed, &kept]
        .iter()
        .map(|id| HeldFile {
            id: id.to_string(),
            was_deleted: false,
            was_reported: false,
        })
        .collect();
    auto_hidden.auto_hidden_file_ids = vec![removed.clone(), kept.clone()];
    harness
        .db
        .replace_takedown_request(&mut auto_hidden)
        .await
        .expect("auto-hide");

    // Remove the first target only, without copies (the kept file is one)
    let response = act(
        harness,
        session,
        &path(&request, "remove"),
        Some(json!({ "targets": [0], "include_copies": false })),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    let after = stored(&harness.db, &request).await;
    assert_eq!(
        after.status,
        TakedownStatus::PartiallyRemoved,
        "one target was not taken"
    );
    assert!(after.auto_hidden_file_ids.is_empty());
    let held: Vec<&str> = after
        .held_files
        .iter()
        .map(|held| held.id.as_str())
        .collect();
    assert_eq!(held, vec![removed.as_str()]);
    assert_eq!(flags(&harness.db, &kept).await, (Some(false), Some(false)));
    assert_eq!(flags(&harness.db, &removed).await, (Some(true), Some(true)));

    let response = act(harness, session, &path(&request, "close"), None).await;
    assert_eq!(response.status(), Status::NoContent);
    let closed = stored(&harness.db, &request).await;
    assert!(closed.hold_until.is_some());

    // The hold ends, as crond releases it: `reported` cleared on every held
    // file that was not reported before
    let release: Vec<String> = closed
        .held_files
        .iter()
        .filter(|held| !held.was_reported)
        .map(|held| held.id.clone())
        .collect();
    harness
        .db
        .release_attachment_hold(&release)
        .await
        .expect("release");

    let sweep: Vec<String> = harness
        .db
        .fetch_deleted_attachments()
        .await
        .expect("sweep")
        .into_iter()
        .map(|file| file.id)
        .collect();
    assert!(sweep.contains(&removed), "the removed file goes");
    assert!(!sweep.contains(&kept), "the kept file must never be swept");
    let kept_row = harness
        .db
        .fetch_attachment_by_id(&kept)
        .await
        .expect("kept");
    assert_ne!(kept_row.deleted, Some(true));
}

#[test]
fn a_removal_that_takes_nothing_is_refused_without_email() {
    crate::util::test::rt().block_on(a_removal_that_takes_nothing_is_refused_without_email_case())
}

#[allow(clippy::disallowed_methods)] // the text-only message is stored directly
async fn a_removal_that_takes_nothing_is_refused_without_email_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;

    let (_, _, author) = harness.new_user().await;
    let (_, channels) = harness.new_server(&author).await;
    let channel = channels[0].id().to_string();
    let message = Ulid::new().to_string();
    harness
        .db
        .insert_message(&Message {
            id: message.clone(),
            channel: channel.clone(),
            author: author.id.clone(),
            content: Some("text only".to_string()),
            ..Default::default()
        })
        .await
        .expect("message");

    let requester = requester_address();
    let request = insert_request(
        harness,
        vec![
            TakedownTarget::Message {
                channel,
                message: message.clone(),
            },
            TakedownTarget::Unresolvable {
                location_index: 1,
                kind: UnresolvableKind::External,
            },
        ],
        &requester,
        "fp-a",
        48,
    )
    .await;

    // Text only without `whole_message`, and an unresolvable target alone
    for body in [json!({ "targets": [0] }), json!({ "targets": [1] })] {
        let response = act(harness, session, &path(&request, "remove"), Some(body)).await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(error_type(response).await, "InvalidOperation");
    }

    let after = stored(&harness.db, &request).await;
    assert_eq!(after.status, TakedownStatus::Received);
    assert_eq!(after.removed_at, None);
    assert!(after.held_files.is_empty());
    assert!(!after.markers.contains(&"email:outcome".to_string()));
    assert!(harness.db.fetch_message(&message).await.is_ok());
    assert!(!audit_actions(&harness.db, &request)
        .await
        .contains(&StaffAuditAction::TakedownRemoved));
    // The responses came after any send would have finished
    assert_eq!(mail_count(&requester).await, 0);
}

#[test]
fn decline_needs_info_and_close_move_the_request_along() {
    crate::util::test::rt().block_on(decline_needs_info_and_close_move_the_request_along_case())
}

async fn decline_needs_info_and_close_move_the_request_along_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;
    let requester = requester_address();
    let request = insert_request(harness, vec![], &requester, "fp-a", 48).await;

    let response = act(harness, session, &path(&request, "needs-info"), None).await;
    assert_eq!(response.status(), Status::NoContent);
    assert_eq!(
        stored(&harness.db, &request).await.status,
        TakedownStatus::NeedsInfo
    );
    let (_, code) = harness.assert_email(&requester).await;
    assert_eq!(code, reference_for(&request.id));

    // A decline body that does not validate changes nothing
    let response = act(
        harness,
        session,
        &path(&request, "decline"),
        Some(json!({ "reason": "Other", "note": "x".repeat(1001) })),
    )
    .await;
    assert_eq!(response.status(), Status::BadRequest);
    assert!(response
        .into_string()
        .await
        .expect("body")
        .contains("InvalidBody"));

    const NOTE: &str = "internal note the audit log must never hold";
    let response = act(
        harness,
        session,
        &path(&request, "decline"),
        Some(json!({ "reason": "NotIntimate", "bad_faith": true, "note": NOTE })),
    )
    .await;
    assert_eq!(response.status(), Status::NoContent);

    let after = stored(&harness.db, &request).await;
    assert_eq!(after.status, TakedownStatus::Declined);
    assert_eq!(after.decline_reason, Some(TakedownDeclineReason::BadFaith));
    assert!(after.bad_faith);
    assert_eq!(after.reviewer_note.as_deref(), Some(NOTE));
    assert!(after.closed_at.is_some(), "the deadline check reads it");

    // Bad faith reads as "other" to the requester
    let (mail, _) = harness.assert_email(&requester).await;
    assert!(mail
        .text
        .contains(revolt_database::util::email::TAKEDOWN_DECLINE_OTHER));

    // Declined is not open: no second decline, no needs-info
    for action in ["decline", "needs-info"] {
        let body = (action == "decline").then(|| json!({ "reason": "Other" }));
        let response = act(harness, session, &path(&request, action), body).await;
        assert_eq!(response.status(), Status::BadRequest, "{}", action);
        assert_eq!(error_type(response).await, "InvalidOperation");
    }

    let response = act(harness, session, &path(&request, "close"), None).await;
    assert_eq!(response.status(), Status::NoContent);
    let closed = stored(&harness.db, &request).await;
    assert_eq!(closed.status, TakedownStatus::Closed);
    assert!(closed.closed_at.is_some());

    let response = act(harness, session, &path(&request, "close"), None).await;
    assert_eq!(response.status(), Status::BadRequest);

    let entries = harness
        .db
        .fetch_staff_audit_for_request(&request.id)
        .await
        .expect("audit");
    let actions: Vec<_> = entries.iter().map(|entry| entry.action).collect();
    for action in [
        StaffAuditAction::TakedownNeedsInfo,
        StaffAuditAction::TakedownDeclined,
        StaffAuditAction::TakedownBadFaith,
        StaffAuditAction::TakedownClosed,
    ] {
        assert!(actions.contains(&action), "{:?}", action);
    }
    // The note stays on the request; the log holds the reason header only
    for entry in &entries {
        assert!(!entry
            .note
            .as_deref()
            .unwrap_or("")
            .contains("internal note"));
    }
}

#[test]
fn a_decline_shows_auto_hidden_files_again() {
    crate::util::test::rt().block_on(a_decline_shows_auto_hidden_files_again_case())
}

async fn a_decline_shows_auto_hidden_files_again_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let (_, _, uploader) = harness.new_user().await;
    let (target, image_id, _) = image_message(harness, &uploader, 0).await;
    let request = insert_request(harness, vec![target], &requester_address(), "fp-a", 48).await;

    // As crond's auto-hide leaves it
    harness
        .db
        .hide_attachments(&[image_id.clone()])
        .await
        .expect("hide");
    let mut auto_hidden = stored(&harness.db, &request).await;
    auto_hidden.held_files = vec![HeldFile {
        id: image_id.clone(),
        was_deleted: false,
        was_reported: false,
    }];
    auto_hidden.auto_hidden_file_ids = vec![image_id.clone()];
    harness
        .db
        .replace_takedown_request(&mut auto_hidden)
        .await
        .expect("auto-hide");

    let response = act(
        harness,
        &fixture.session,
        &path(&request, "decline"),
        Some(json!({ "reason": "NotIntimate" })),
    )
    .await;
    assert_eq!(response.status(), Status::NoContent);

    assert_eq!(
        flags(&harness.db, &image_id).await,
        (Some(false), Some(false))
    );
    let after = stored(&harness.db, &request).await;
    assert!(after.held_files.is_empty());
    assert!(after.auto_hidden_file_ids.is_empty());
    assert_eq!(after.hold_until, None);
}

#[test]
fn child_safety_holds_everything_and_emails_no_uploader() {
    crate::util::test::rt().block_on(child_safety_holds_everything_and_emails_no_uploader_case())
}

async fn child_safety_holds_everything_and_emails_no_uploader_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;

    let (uploader_account, _, uploader) = harness.new_user().await;
    let (target, image_id, _) = image_message(harness, &uploader, 0).await;
    let requester = requester_address();
    let request = insert_request(
        harness,
        vec![
            target,
            TakedownTarget::Unresolvable {
                location_index: 1,
                kind: UnresolvableKind::External,
            },
        ],
        &requester,
        "fp-a",
        48,
    )
    .await;

    let response = act(harness, session, &path(&request, "child-safety"), None).await;
    assert_eq!(response.status(), Status::NoContent);

    assert_eq!(
        flags(&harness.db, &image_id).await,
        (Some(true), Some(true))
    );
    let after = stored(&harness.db, &request).await;
    assert!(after.child_safety);
    assert_eq!(after.hold_until, None);
    assert_eq!(
        after.held_files,
        vec![HeldFile {
            id: image_id.clone(),
            was_deleted: false,
            was_reported: false,
        }]
    );
    assert!(audit_actions(&harness.db, &request)
        .await
        .contains(&StaffAuditAction::TakedownChildSafety));

    // A removal afterwards still emails the requester (partial: one target
    // is outside Sloga), but never the uploader
    let response = act(
        harness,
        session,
        &path(&request, "remove"),
        Some(json!({ "targets": [0] })),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let after = stored(&harness.db, &request).await;
    assert_eq!(after.status, TakedownStatus::PartiallyRemoved);
    assert_eq!(after.hold_until, None, "a child-safety hold has no end");

    // The requester's mail arriving proves the sends ran and finished (they
    // are awaited before the response)
    let (_, code) = harness.assert_email(&requester).await;
    assert_eq!(code, reference_for(&request.id));
    assert_eq!(mail_count(&uploader_account.email).await, 0);
    assert!(!after
        .markers
        .iter()
        .any(|marker| marker.starts_with("email:uploader:")));

    // Never shown again, never restorable
    let response = act(
        harness,
        session,
        &path(&request, "unhide"),
        Some(json!({ "files": [image_id] })),
    )
    .await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(
        flags(&harness.db, &image_id).await,
        (Some(true), Some(true))
    );

    // Closing keeps the hold open-ended
    let response = act(harness, session, &path(&request, "close"), None).await;
    assert_eq!(response.status(), Status::NoContent);
    assert_eq!(stored(&harness.db, &request).await.hold_until, None);
}

#[test]
fn unhide_only_shows_files_that_were_live() {
    crate::util::test::rt().block_on(unhide_only_shows_files_that_were_live_case())
}

async fn unhide_only_shows_files_that_were_live_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;

    let (_, _, uploader) = harness.new_user().await;
    let (target, live, copies) = image_message(harness, &uploader, 2).await;
    let (was_deleted, not_held) = (copies[0].clone(), copies[1].clone());
    let request = insert_request(harness, vec![target], &requester_address(), "fp-a", 48).await;

    harness
        .db
        .hide_attachments(&[live.clone(), was_deleted.clone(), not_held.clone()])
        .await
        .expect("hide");
    let mut held = stored(&harness.db, &request).await;
    held.held_files = vec![
        HeldFile {
            id: live.clone(),
            was_deleted: false,
            was_reported: false,
        },
        HeldFile {
            id: was_deleted.clone(),
            was_deleted: true,
            was_reported: false,
        },
    ];
    held.auto_hidden_file_ids = vec![live.clone(), was_deleted.clone()];
    harness
        .db
        .replace_takedown_request(&mut held)
        .await
        .expect("held");

    // A file that was already deleted, or one this request does not hold,
    // refuses the whole call
    for files in [
        vec![was_deleted.clone()],
        vec![not_held.clone()],
        vec![live.clone(), was_deleted.clone()],
    ] {
        let response = act(
            harness,
            session,
            &path(&request, "unhide"),
            Some(json!({ "files": files })),
        )
        .await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(error_type(response).await, "InvalidOperation");
    }
    for id in [&live, &was_deleted, &not_held] {
        assert_eq!(
            flags(&harness.db, id).await,
            (Some(true), Some(true)),
            "{}",
            id
        );
    }

    let response = act(
        harness,
        session,
        &path(&request, "unhide"),
        Some(json!({ "files": [live] })),
    )
    .await;
    assert_eq!(response.status(), Status::NoContent);
    assert_eq!(flags(&harness.db, &live).await, (Some(false), Some(true)));
    assert_eq!(
        flags(&harness.db, &was_deleted).await,
        (Some(true), Some(true))
    );
    let after = stored(&harness.db, &request).await;
    assert_eq!(after.auto_hidden_file_ids, vec![was_deleted.clone()]);

    // Restore is off unless configured
    let response = act(harness, session, &path(&request, "restore"), None).await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(error_type(response).await, "FeatureDisabled");
}

#[test]
fn the_queue_is_ordered_and_the_detail_view_is_logged() {
    crate::util::test::rt().block_on(the_queue_is_ordered_and_the_detail_view_is_logged_case())
}

async fn the_queue_is_ordered_and_the_detail_view_is_logged_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;

    let later = insert_request(harness, vec![], &requester_address(), "fp-shared", 40).await;
    let sooner = insert_request(harness, vec![], &requester_address(), "fp-other", 10).await;
    let mut earlier_bad_faith =
        insert_request(harness, vec![], &requester_address(), "fp-shared", 48).await;
    earlier_bad_faith.status = TakedownStatus::Declined;
    earlier_bad_faith.bad_faith = true;
    harness
        .db
        .replace_takedown_request(&mut earlier_bad_faith)
        .await
        .expect("bad faith");
    // The earliest deadline of all, but throttled: it queues behind the rest
    let mut throttled = insert_request(harness, vec![], &requester_address(), "fp-flood", 5).await;
    throttled.throttled = true;
    harness
        .db
        .replace_takedown_request(&mut throttled)
        .await
        .expect("throttled");

    let response = get(harness, session, "/admin/takedown/requests").await;
    assert_eq!(response.status(), Status::Ok);
    let rows: Vec<v0::TakedownSummary> = response.into_json().await.expect("rows");
    let ids: Vec<&str> = rows.iter().map(|row| row.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            sooner.id.as_str(),
            later.id.as_str(),
            earlier_bad_faith.id.as_str(),
            throttled.id.as_str()
        ]
    );
    let flagged = |id: &str| {
        rows.iter()
            .find(|row| row.id == id)
            .unwrap()
            .bad_faith_history
    };
    assert!(flagged(&later.id));
    assert!(!flagged(&sooner.id));
    assert!(
        !flagged(&earlier_bad_faith.id),
        "its own decline is not history"
    );

    // The detail view by reference, with the requester opened
    let response = get(
        harness,
        session,
        &format!("/admin/takedown/requests/{}", reference_for(&later.id)),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let detail: v0::TakedownDetail = response.into_json().await.expect("detail");
    let requester = detail.requester.expect("requester");
    assert_eq!(requester.name, "Requester Name");
    assert_eq!(requester.role, v0::TakedownRole::Depicted);

    let after = stored(&harness.db, &later).await;
    assert!(after.first_opened_at.is_some());
    assert_eq!(after.status, TakedownStatus::UnderReview);
    assert!(audit_actions(&harness.db, &later)
        .await
        .contains(&StaffAuditAction::TakedownViewedRequester));

    // Unknown ids are not found
    let response = get(harness, session, "/admin/takedown/requests/not-an-id").await;
    assert_eq!(response.status(), Status::NotFound);
}

/// Put `ids` in the state crond's auto-hide leaves them: hidden and kept,
/// on `held_files` (live and not reported before) and `auto_hidden_file_ids`
async fn auto_hide(harness: &TestHarness, request: &TakedownRequest, ids: &[String]) {
    harness.db.hide_attachments(ids).await.expect("hide");
    let mut stored_request = stored(&harness.db, request).await;
    for id in ids {
        stored_request.held_files.push(HeldFile {
            id: id.clone(),
            was_deleted: false,
            was_reported: false,
        });
        stored_request.auto_hidden_file_ids.push(id.clone());
    }
    harness
        .db
        .replace_takedown_request(&mut stored_request)
        .await
        .expect("auto-hide");
}

fn message_of(target: &TakedownTarget) -> String {
    match target {
        TakedownTarget::Message { message, .. } => message.clone(),
        _ => panic!("not a message target"),
    }
}

async fn swept(harness: &TestHarness) -> Vec<String> {
    harness
        .db
        .fetch_deleted_attachments()
        .await
        .expect("sweep")
        .into_iter()
        .map(|file| file.id)
        .collect()
}

#[test]
fn closing_without_a_removal_shows_auto_hides_again() {
    crate::util::test::rt().block_on(closing_without_a_removal_shows_auto_hides_again_case())
}

/// Control: if close stopped settling auto-hides, the file would stay
/// `deleted` on `held_files`, and the hold release would sweep it.
async fn closing_without_a_removal_shows_auto_hides_again_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;

    let (_, _, uploader) = harness.new_user().await;
    let (target, image, _) = image_message(harness, &uploader, 0).await;
    let request = insert_request(harness, vec![target], &requester_address(), "fp-a", 48).await;
    auto_hide(harness, &request, &[image.clone()]).await;

    let response = act(harness, &fixture.session, &path(&request, "close"), None).await;
    assert_eq!(response.status(), Status::NoContent);

    assert_eq!(flags(&harness.db, &image).await, (Some(false), Some(false)));
    let closed = stored(&harness.db, &request).await;
    assert!(closed.held_files.is_empty());
    assert!(closed.auto_hidden_file_ids.is_empty());
    assert_eq!(closed.hold_until, None);
    assert!(!swept(harness).await.contains(&image));
    assert!(audit_actions(&harness.db, &request)
        .await
        .contains(&StaffAuditAction::TakedownUnhidden));
}

#[test]
fn an_auto_hide_whose_message_was_deleted_stays_down() {
    crate::util::test::rt().block_on(an_auto_hide_whose_message_was_deleted_stays_down_case())
}

/// The uploader deletes the message after the auto-hide. Showing the file
/// again would publish it with no message at all, so it stays deleted.
async fn an_auto_hide_whose_message_was_deleted_stays_down_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;

    let (_, _, uploader) = harness.new_user().await;
    let (closed_target, closed_image, _) = image_message(harness, &uploader, 0).await;
    let (removed_target, removed_image, _) = image_message(harness, &uploader, 0).await;
    let closed_request = insert_request(
        harness,
        vec![closed_target.clone()],
        &requester_address(),
        "fp-a",
        48,
    )
    .await;
    let removed_request = insert_request(
        harness,
        vec![removed_target.clone()],
        &requester_address(),
        "fp-b",
        48,
    )
    .await;
    auto_hide(harness, &closed_request, &[closed_image.clone()]).await;
    auto_hide(harness, &removed_request, &[removed_image.clone()]).await;

    for target in [&closed_target, &removed_target] {
        let message = harness
            .db
            .fetch_message(&message_of(target))
            .await
            .expect("message");
        message.delete(&harness.db).await.expect("delete");
    }

    // Close: not shown again, not held, released to the sweep
    let response = act(harness, session, &path(&closed_request, "close"), None).await;
    assert_eq!(response.status(), Status::NoContent);
    assert_eq!(
        flags(&harness.db, &closed_image).await,
        (Some(true), Some(false))
    );
    assert!(stored(&harness.db, &closed_request)
        .await
        .held_files
        .is_empty());
    assert!(swept(harness).await.contains(&closed_image));

    // Remove of the deleted message: succeeds and takes the auto-hide
    let response = act(
        harness,
        session,
        &path(&removed_request, "remove"),
        Some(json!({ "targets": [0] })),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    let result: v0::TakedownRemoveResult = response.into_json().await.expect("result");
    assert_eq!(result.removed_files, 1);
    assert_eq!(
        flags(&harness.db, &removed_image).await,
        (Some(true), Some(true))
    );
    let after = stored(&harness.db, &removed_request).await;
    assert_eq!(after.status, TakedownStatus::Removed);
    assert!(after.auto_hidden_file_ids.is_empty());
    let held: Vec<&str> = after
        .held_files
        .iter()
        .map(|held| held.id.as_str())
        .collect();
    assert_eq!(held, vec![removed_image.as_str()]);
}

#[test]
fn an_unhide_racing_a_removal_never_shows_the_removed_file() {
    crate::util::test::rt().block_on(an_unhide_racing_a_removal_never_shows_the_removed_file_case())
}

/// An unhide that read the request before a removal (or another writer)
/// stored its result.
///
/// Part 1 (a real removal) is refused by the pre-check on the copy it read:
/// the removal already took the file out of its message, so `showable`
/// refuses it before any save. Part 2 is the real control for the check
/// inside the save: only the bookkeeping moved, so the copy it read still
/// approves, and only the re-check on the stored copy refuses.
async fn an_unhide_racing_a_removal_never_shows_the_removed_file_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;

    let (_, _, uploader) = harness.new_user().await;
    let (target, image, _) = image_message(harness, &uploader, 0).await;
    let (_, other_image, _) = image_message(harness, &uploader, 0).await;
    let request = insert_request(
        harness,
        vec![
            target,
            TakedownTarget::File {
                file: other_image.clone(),
            },
        ],
        &requester_address(),
        "fp-a",
        48,
    )
    .await;
    auto_hide(harness, &request, &[image.clone(), other_image.clone()]).await;

    // The unhide reads first; a removal lands before it saves
    let stale = stored(&harness.db, &request).await;
    let response = act(
        harness,
        &fixture.session,
        &path(&request, "remove"),
        Some(json!({ "targets": [0] })),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(flags(&harness.db, &image).await, (Some(true), Some(true)));

    let reviewer = fixture.session.user_id.clone();
    let refused =
        super::takedown_holds::unhide_held(&harness.db, &reviewer, stale, &[image.clone()], None)
            .await;
    assert!(refused.is_err());
    assert_eq!(flags(&harness.db, &image).await, (Some(true), Some(true)));

    // Same race where only the bookkeeping moved (the file's message still
    // shows it): the copy it read approves, the stored copy refuses
    let (target, third_image, _) = image_message(harness, &uploader, 0).await;
    let request = insert_request(harness, vec![target], &requester_address(), "fp-b", 48).await;
    auto_hide(harness, &request, &[third_image.clone()]).await;
    let stale = stored(&harness.db, &request).await;
    let mut moved = stale.clone();
    moved.auto_hidden_file_ids.clear();
    harness
        .db
        .replace_takedown_request(&mut moved)
        .await
        .expect("concurrent write");

    let refused = super::takedown_holds::unhide_held(
        &harness.db,
        &reviewer,
        stale,
        &[third_image.clone()],
        None,
    )
    .await;
    assert!(refused.is_err());
    assert_eq!(
        flags(&harness.db, &third_image).await,
        (Some(true), Some(true))
    );
}

#[test]
fn an_un_hide_that_writes_after_a_removal_never_shows_the_removed_file() {
    crate::util::test::rt()
        .block_on(an_un_hide_that_writes_after_a_removal_never_shows_the_removed_file_case())
}

/// The un-hide is stored and checked first; a removal runs before the
/// un-hide writes. The steps are called directly to force that order.
///
/// Control: without the check after the write (`verify_shown` in
/// `show_files`), both files end live, removed and served.
async fn an_un_hide_that_writes_after_a_removal_never_shows_the_removed_file_case() {
    use super::takedown_common::{
        approved_after_undo, approved_after_unhide, held_elsewhere, save_with, show_files,
        showable, take_auto_hides,
    };

    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let db = &harness.db;
    let (_, _, uploader) = harness.new_user().await;

    // 1. Unhide: approved and stored, checked, then a removal, then the write
    let (target, image, _) = image_message(harness, &uploader, 0).await;
    let request = insert_request(harness, vec![target], &requester_address(), "fp-a", 48).await;
    auto_hide(harness, &request, &[image.clone()]).await;

    let (_, approved) =
        super::takedown_holds::approve_unhide(db, stored(db, &request).await, &[image.clone()])
            .await
            .expect("approved");
    assert_eq!(approved, vec![image.clone()]);
    let elsewhere = held_elsewhere(db, &request.id).await.expect("elsewhere");
    let shown = showable(db, &approved, &elsewhere).await.expect("check");
    assert_eq!(shown, vec![image.clone()]);

    let response = act(
        harness,
        &fixture.session,
        &path(&request, "remove"),
        Some(json!({ "targets": [0] })),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    let kept = show_files(db, &request.id, &shown, approved_after_unhide)
        .await
        .expect("write");
    assert!(kept.is_empty());
    assert_eq!(flags(db, &image).await.0, Some(true));

    // 2. Decline: the auto-hide is taken off the stored request, checked,
    // then a removal on the same request, then the write
    let (target, declined_image, _) = image_message(harness, &uploader, 0).await;
    let request = insert_request(harness, vec![target], &requester_address(), "fp-b", 48).await;
    auto_hide(harness, &request, &[declined_image.clone()]).await;

    let mut taken = Vec::new();
    save_with(db, stored(db, &request).await, |r| {
        r.status = TakedownStatus::Declined;
        taken = take_auto_hides(r, &[]);
        Ok(())
    })
    .await
    .expect("declined");
    assert_eq!(taken.len(), 1);
    let elsewhere = held_elsewhere(db, &request.id).await.expect("elsewhere");
    let shown = showable(db, &[declined_image.clone()], &elsewhere)
        .await
        .expect("check");
    assert_eq!(shown, vec![declined_image.clone()]);

    let response = act(
        harness,
        &fixture.session,
        &path(&request, "remove"),
        Some(json!({ "targets": [0] })),
    )
    .await;
    assert_eq!(response.status(), Status::Ok);

    let kept = show_files(db, &request.id, &shown, approved_after_undo)
        .await
        .expect("write");
    assert!(kept.is_empty());
    assert_eq!(flags(db, &declined_image).await, (Some(true), Some(true)));
    assert!(stored(db, &request)
        .await
        .held_files
        .iter()
        .any(|held| held.id == declined_image));
}

#[test]
fn a_decline_and_a_removal_at_once_leave_the_removed_file_hidden() {
    crate::util::test::rt()
        .block_on(a_decline_and_a_removal_at_once_leave_the_removed_file_hidden_case())
}

/// Through the takedown mutex the two run one after the other, in either
/// order: the decline first shows the auto-hide again and the removal then
/// hides it; the removal first takes it and the decline is refused.
async fn a_decline_and_a_removal_at_once_leave_the_removed_file_hidden_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;

    let (_, _, uploader) = harness.new_user().await;
    let (target, image, _) = image_message(harness, &uploader, 0).await;
    let request = insert_request(harness, vec![target], &requester_address(), "fp-a", 48).await;
    auto_hide(harness, &request, &[image.clone()]).await;

    let decline_path = path(&request, "decline");
    let remove_path = path(&request, "remove");
    let (declined, removed) = rocket::tokio::join!(
        act(
            harness,
            session,
            &decline_path,
            Some(json!({ "reason": "NotIntimate" })),
        ),
        act(
            harness,
            session,
            &remove_path,
            Some(json!({ "targets": [0] })),
        ),
    );

    assert_eq!(removed.status(), Status::Ok);
    assert!(
        [Status::NoContent, Status::BadRequest].contains(&declined.status()),
        "{:?}",
        declined.status()
    );
    assert_eq!(flags(&harness.db, &image).await, (Some(true), Some(true)));
    assert!(stored(&harness.db, &request)
        .await
        .held_files
        .iter()
        .any(|held| held.id == image));
}

#[test]
fn an_unhide_and_a_removal_at_once_leave_the_removed_file_hidden() {
    crate::util::test::rt()
        .block_on(an_unhide_and_a_removal_at_once_leave_the_removed_file_hidden_case())
}

/// Either order through the mutex: the unhide first and the removal then
/// hides the file again; the removal first and the unhide is refused.
async fn an_unhide_and_a_removal_at_once_leave_the_removed_file_hidden_case() {
    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;

    let (_, _, uploader) = harness.new_user().await;
    let (target, image, _) = image_message(harness, &uploader, 0).await;
    let request = insert_request(harness, vec![target], &requester_address(), "fp-a", 48).await;
    auto_hide(harness, &request, &[image.clone()]).await;

    let unhide_path = path(&request, "unhide");
    let remove_path = path(&request, "remove");
    let (unhidden, removed) = rocket::tokio::join!(
        act(
            harness,
            session,
            &unhide_path,
            Some(json!({ "files": [image] })),
        ),
        act(
            harness,
            session,
            &remove_path,
            Some(json!({ "targets": [0] })),
        ),
    );

    assert_eq!(removed.status(), Status::Ok);
    assert!(
        [Status::NoContent, Status::BadRequest].contains(&unhidden.status()),
        "{:?}",
        unhidden.status()
    );
    assert_eq!(flags(&harness.db, &image).await, (Some(true), Some(true)));
}

#[test]
fn a_busy_mutex_refuses_the_action_and_changes_nothing() {
    crate::util::test::rt().block_on(a_busy_mutex_refuses_the_action_and_changes_nothing_case())
}

async fn a_busy_mutex_refuses_the_action_and_changes_nothing_case() {
    use revolt_database::removal::{try_takedown_mutex, with_takedown_mutex};

    let fixture = fixture(25, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;

    let (_, _, uploader) = harness.new_user().await;
    let (target, image, _) = image_message(harness, &uploader, 0).await;
    let request = insert_request(harness, vec![target], &requester_address(), "fp-a", 48).await;
    auto_hide(harness, &request, &[image.clone()]).await;
    let before = stored(&harness.db, &request).await;

    // Someone else holds it (crond, another reviewer)
    let held = try_takedown_mutex()
        .await
        .expect("redis")
        .expect("the mutex starts free");
    assert!(try_takedown_mutex().await.expect("redis").is_none());

    // The action waits its 10 s, then gives up with the fixed answer
    let response = act(harness, session, &path(&request, "close"), None).await;
    assert_eq!(response.status(), Status::BadRequest);
    let text = response.into_string().await.expect("body");
    assert!(text.contains("FailedValidation"), "{}", text);
    assert!(text.contains("TakedownBusy"), "{}", text);

    let after = stored(&harness.db, &request).await;
    assert_eq!(after.status, before.status);
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.auto_hidden_file_ids, before.auto_hidden_file_ids);
    assert_eq!(flags(&harness.db, &image).await, (Some(true), Some(true)));

    // Released: free again, and the action goes through
    held.release().await;
    let response = act(harness, session, &path(&request, "close"), None).await;
    assert_eq!(response.status(), Status::NoContent);

    // `with_takedown_mutex` releases whatever the work returns
    let value = with_takedown_mutex(|| async { Ok(7) }).await.expect("free");
    assert_eq!(value, 7);
    let failed: revolt_result::Result<()> =
        with_takedown_mutex(|| async { Err(revolt_result::create_error!(InvalidOperation)) }).await;
    assert!(failed.is_err());
    let again = try_takedown_mutex()
        .await
        .expect("redis")
        .expect("released after an error too");
    again.release().await;
}

#[test]
fn every_action_answers_takedown_busy_while_the_mutex_is_held() {
    crate::util::test::rt()
        .block_on(every_action_answers_takedown_busy_while_the_mutex_is_held_case())
}

/// All seven mutating routes wait for the mutex and give up with the fixed
/// answer, leaving the request (and its files) as they were
async fn every_action_answers_takedown_busy_while_the_mutex_is_held_case() {
    use revolt_database::removal::{set_takedown_mutex_timing, try_takedown_mutex};
    use std::time::Duration as StdDuration;

    // A 1 s wait instead of 10 s, so seven refusals fit the test budget
    set_takedown_mutex_timing(
        StdDuration::from_secs(120),
        StdDuration::from_secs(30),
        StdDuration::from_secs(1),
    );
    let fixture = fixture_with(25, true, true).await;
    let harness = &fixture.harness;
    let session = &fixture.session;

    let (_, _, uploader) = harness.new_user().await;
    let (target, image, _) = image_message(harness, &uploader, 0).await;
    let request = insert_request(harness, vec![target], &requester_address(), "fp-a", 48).await;
    auto_hide(harness, &request, &[image.clone()]).await;
    let before = stored(&harness.db, &request).await;

    let held = try_takedown_mutex()
        .await
        .expect("redis")
        .expect("the mutex starts free");

    let actions = [
        ("remove", Some(json!({ "targets": [0] }))),
        ("decline", Some(json!({ "reason": "Other" }))),
        ("needs-info", None),
        ("close", None),
        ("child-safety", None),
        ("unhide", Some(json!({ "files": [image] }))),
        ("restore", None),
    ];
    for (action, body) in actions {
        let response = act(harness, session, &path(&request, action), body).await;
        assert_eq!(response.status(), Status::BadRequest, "{}", action);
        let text = response.into_string().await.expect("body");
        assert!(text.contains("TakedownBusy"), "{}: {}", action, text);

        let now = stored(&harness.db, &request).await;
        assert_eq!(now.revision, before.revision, "{}", action);
        assert_eq!(now.status, before.status, "{}", action);
    }
    assert_eq!(flags(&harness.db, &image).await, (Some(true), Some(true)));

    held.release().await;
}

#[test]
fn the_mutex_is_renewed_while_held_and_notices_when_it_is_lost() {
    crate::util::test::rt()
        .block_on(the_mutex_is_renewed_while_held_and_notices_when_it_is_lost_case())
}

/// Control: without the renewal the hold expires after 1.5 s and the second
/// take succeeds; without the lost flag `is_held()` stays true after the
/// external delete.
async fn the_mutex_is_renewed_while_held_and_notices_when_it_is_lost_case() {
    use revolt_database::removal::{
        set_takedown_mutex_timing, try_takedown_mutex, use_takedown_mutex_key,
    };
    use std::time::Duration as StdDuration;

    // A key this test knows (the fixture's own call is then ignored), and a
    // 1.5 s expiry renewed every 300 ms
    let key = format!("takedown:mutex:test:{}", Ulid::new());
    use_takedown_mutex_key(key.clone());
    set_takedown_mutex_timing(
        StdDuration::from_millis(4000),
        StdDuration::from_millis(300),
        StdDuration::from_secs(10),
    );
    let _fixture = fixture(25, true).await;

    let guard = try_takedown_mutex()
        .await
        .expect("redis")
        .expect("the mutex starts free");
    assert!(guard.is_held());

    // Past twice the first expiry: only the renewal keeps the hold
    rocket::tokio::time::sleep(StdDuration::from_millis(6000)).await;
    assert!(guard.is_held());
    assert!(
        try_takedown_mutex().await.expect("redis").is_none(),
        "the hold expired while its guard lived"
    );

    // Deleted from outside: the next renewal finds the token gone
    let mut conn = redis_kiss::get_connection()
        .await
        .expect("redis")
        .into_inner();
    let deleted: i64 = redis_kiss::redis::cmd("DEL")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .expect("delete");
    assert_eq!(deleted, 1);
    rocket::tokio::time::sleep(StdDuration::from_millis(1200)).await;
    assert!(!guard.is_held());

    guard.release().await;
    let next = try_takedown_mutex()
        .await
        .expect("redis")
        .expect("free once the lost hold is released");
    assert!(next.is_held());
    next.release().await;
}
