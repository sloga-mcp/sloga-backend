//! Take It Down evidence for reviewers (plan 4.3).
//!
//! Serves a file's stored bytes even while the file is hidden, never cached,
//! and records every view in the staff audit log. The guard matches the
//! staff takedown routes: `privileged`, on `features.takedown.reviewers`, and
//! MFA active on the account.

use std::collections::BTreeSet;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue},
    response::Response,
};
use revolt_config::config;
use revolt_database::{
    Account, Database, File, FileUsedForType, Session, StaffAuditAction, StaffAuditEntry,
    TakedownRequest, TakedownTarget, User,
};
use revolt_files::fetch_from_s3;
use revolt_result::{create_error, Result};
use serde::Deserialize;

/// Most files gathered from a request's targets when checking that a file
/// belongs to it; past this the check answers no (a 404), never yes
const MAX_LINKED_FILES: usize = 500;

/// Longest file id looked up (real ids are 26 or 42 characters)
const MAX_FILE_ID_LEN: usize = 64;

#[derive(Deserialize)]
pub struct EvidenceQuery {
    /// Id of the request the view is for (the ULID, not the `TD-` reference).
    /// Required; optional here only so a missing one gets our own error
    /// instead of the extractor's.
    request: Option<String>,
}

/// Fetch a file as Take It Down evidence (reviewers only)
///
/// Session token only; a bot token is never accepted. Hidden files are
/// served too. `?request=<id>` is required and the file must belong to that
/// request, so every view is tied to a request.
pub async fn fetch_evidence(
    State(db): State<Database>,
    session: Session,
    Path(file_id): Path<String>,
    Query(query): Query<EvidenceQuery>,
) -> Result<Response> {
    let reviewers = config().await.features.takedown.reviewers.clone();
    evidence_for(
        &db,
        &reviewers,
        &session.user_id,
        &file_id,
        query.request.as_deref(),
    )
    .await
}

/// Authorize, serve, then record the view
async fn evidence_for(
    db: &Database,
    reviewers: &[String],
    user_id: &str,
    file_id: &str,
    request: Option<&str>,
) -> Result<Response> {
    let (file, request_id) = authorize_evidence(db, reviewers, user_id, file_id, request).await?;
    let response = serve_evidence(db, &file).await?;

    StaffAuditEntry::record(
        db,
        Some(user_id),
        StaffAuditAction::TakedownViewedEvidence,
        Some(request_id.as_str()),
        vec![file.id.clone()],
        None,
        None,
    )
    .await;

    Ok(response)
}

/// The guard first, so nobody learns whether a file exists without passing
/// it; then the request id (required); then the file (any tag, any state),
/// which must belong to that request. Returns the file and the canonical
/// request id.
async fn authorize_evidence(
    db: &Database,
    reviewers: &[String],
    user_id: &str,
    file_id: &str,
    request: Option<&str>,
) -> Result<(File, String)> {
    let user = db.fetch_user(user_id).await?;
    let account = db.fetch_account(user_id).await?;
    if !may_view_evidence(&user, &account, reviewers) {
        return Err(create_error!(NotPrivileged));
    }

    // Missing and malformed are refused alike
    let request_id = parse_request_id(request.unwrap_or_default())?;

    if file_id.len() > MAX_FILE_ID_LEN {
        return Err(create_error!(NotFound));
    }
    let file = db.fetch_attachment_by_id(file_id).await?;

    let request = db.fetch_takedown_request(&request_id).await?;
    if !request_covers_file(db, &request, &file).await {
        return Err(create_error!(NotFound));
    }

    Ok((file, request_id))
}

/// Privileged, on the reviewer list, MFA active, a person (not a bot) and
/// an enabled account
fn may_view_evidence(user: &User, account: &Account, reviewers: &[String]) -> bool {
    user.id == account.id
        && user.bot.is_none()
        && user.privileged
        && !account.disabled
        && account.mfa.is_active()
        && reviewers.iter().any(|reviewer| reviewer == &user.id)
}

fn parse_request_id(raw: &str) -> Result<String> {
    ulid::Ulid::from_string(raw)
        .map(|id| id.to_string())
        .map_err(|_| create_error!(InvalidOperation))
}

/// Whether `file` belongs to `request`: held by it, a target, attached to a
/// target, or an exact copy (same original or processed hash) of a file
/// that is. Lookup failures count as "no".
async fn request_covers_file(db: &Database, request: &TakedownRequest, file: &File) -> bool {
    if request.held_files.iter().any(|held| held.id == file.id)
        || request.auto_hidden_file_ids.iter().any(|id| id == &file.id)
    {
        return true;
    }

    let mut linked: Vec<File> = Vec::new();
    for target in &request.targets {
        if target_owns_file(target, file) {
            return true;
        }

        linked.extend(target_files(db, target).await);
        if linked.len() >= MAX_LINKED_FILES {
            linked.truncate(MAX_LINKED_FILES);
            break;
        }
    }

    if linked.iter().any(|linked| linked.id == file.id) {
        return true;
    }

    is_copy_of_any(db, file, &linked).await
}

/// The file is the target, or `used_for` ties it to the target
fn target_owns_file(target: &TakedownTarget, file: &File) -> bool {
    match target {
        TakedownTarget::File { file: id } => id == &file.id,
        TakedownTarget::Emoji { emoji } => {
            emoji == &file.id
                || used_for(file, emoji, |kind| matches!(kind, FileUsedForType::Emoji))
        }
        TakedownTarget::Message { message, .. } => used_for(file, message, |kind| {
            matches!(kind, FileUsedForType::Message)
        }),
        TakedownTarget::User { user } => used_for(file, user, |kind| {
            matches!(
                kind,
                FileUsedForType::UserAvatar | FileUsedForType::UserProfileBackground
            )
        }),
        TakedownTarget::Server { server } => used_for(file, server, |kind| {
            matches!(
                kind,
                FileUsedForType::ServerIcon | FileUsedForType::ServerBanner
            )
        }),
        TakedownTarget::Unresolvable { .. } => false,
    }
}

/// `file` is used for object `id`, as one of the kinds `kind` accepts
fn used_for(file: &File, id: &str, kind: fn(&FileUsedForType) -> bool) -> bool {
    file.used_for
        .as_ref()
        .is_some_and(|used| used.id == id && kind(&used.object_type))
}

/// The files a target currently shows
async fn target_files(db: &Database, target: &TakedownTarget) -> Vec<File> {
    match target {
        TakedownTarget::File { file: id } | TakedownTarget::Emoji { emoji: id } => {
            db.fetch_attachment_by_id(id).await.into_iter().collect()
        }
        TakedownTarget::Message { message, .. } => match db.fetch_message(message).await {
            Ok(message) => {
                let mut files = message.attachments.unwrap_or_default();
                if let Some(forwarded) = message.forwarded {
                    files.extend(forwarded.attachments);
                }
                files
            }
            Err(_) => Vec::new(),
        },
        TakedownTarget::User { user } => match db.fetch_user(user).await {
            Ok(user) => user
                .avatar
                .into_iter()
                .chain(user.profile.and_then(|profile| profile.background))
                .collect(),
            Err(_) => Vec::new(),
        },
        TakedownTarget::Server { server } => match db.fetch_server(server).await {
            Ok(server) => server.icon.into_iter().chain(server.banner).collect(),
            Err(_) => Vec::new(),
        },
        TakedownTarget::Unresolvable { .. } => Vec::new(),
    }
}

/// Same original hash as one of `linked`, or the same processed hash
async fn is_copy_of_any(db: &Database, file: &File, linked: &[File]) -> bool {
    let Some(hash) = file.hash.as_deref() else {
        return false;
    };

    let linked_hashes: BTreeSet<&str> = linked
        .iter()
        .filter_map(|linked| linked.hash.as_deref())
        .collect();
    if linked_hashes.contains(hash) {
        return true;
    }

    let Ok(own) = db.fetch_attachment_hash(hash).await else {
        return false;
    };
    for linked_hash in linked_hashes {
        if let Ok(row) = db.fetch_attachment_hash(linked_hash).await {
            if row.processed_hash == own.processed_hash {
                return true;
            }
        }
    }

    false
}

/// The stored bytes, decrypted, with no caching anywhere: fetched straight
/// from S3 (never through the shared in-memory cache the public routes
/// read), `no-store`, inline. Anything other than image, video or audio is
/// sent as opaque bytes, and the response may not run script.
async fn serve_evidence(db: &Database, file: &File) -> Result<Response> {
    // Rows from before autumn recorded hashes have no object to find
    let Some(hash_id) = file.hash.as_deref() else {
        return Err(create_error!(NotFound));
    };
    let hash = db.fetch_attachment_hash(hash_id).await?;

    // Never uploaded
    if hash.iv.is_empty() {
        return Err(create_error!(NotFound));
    }

    let mut response = match hash.format_version {
        Some(2) => crate::download::serve_v2(&hash, None).await?,
        Some(other) => {
            tracing::error!("unknown FileHash format_version {other} for {}", hash.id);
            return Err(create_error!(InternalError));
        }
        None => {
            let data = fetch_from_s3(
                &hash.bucket_id,
                &hash.path,
                &hash.iv,
                hash.key_id.as_deref(),
            )
            .await?;
            crate::download::serve_legacy_buffer(&hash, data, None)?
        }
    };

    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    if !is_inline_media(&hash.content_type) {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
    }

    Ok(response)
}

/// Images (except SVG, which can carry script), video and audio
fn is_inline_media(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    (essence.starts_with("image/") && essence != "image/svg+xml")
        || essence.starts_with("video/")
        || essence.starts_with("audio/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use revolt_database::{
        iso8601_timestamp::Timestamp, FileHash, FileUsedFor, HeldFile, Metadata,
    };
    use revolt_result::ErrorType;

    /// The scratch bucket autumn's S3-backed tests use; never the prod one
    const TEST_BUCKET: &str = "autumn-upload-tests";

    /// Same override and proof as the other S3-backed autumn tests: the
    /// prefix is REVOLT__ with a DOUBLE underscore, and the config is built
    /// once per process
    async fn test_env() {
        std::env::set_var("REVOLT__FILES__S3__DEFAULT_BUCKET", TEST_BUCKET);
        assert_eq!(
            revolt_config::config().await.files.s3.default_bucket,
            TEST_BUCKET,
            "S3 default_bucket override never reached the config"
        );
    }

    async fn ensure_bucket() {
        use revolt_files::{EncryptionKey, FileStorageRepository, S3Storage};
        let storage = S3Storage::from_config(EncryptionKey::from_config().await).await;
        // Already-exists is fine
        let _ = storage.create_bucket(TEST_BUCKET).await;
    }

    fn db() -> Database {
        Database::Reference(Default::default())
    }

    fn account(id: &str, mfa: &str, disabled: bool) -> Account {
        let totp = match mfa {
            "enabled" => serde_json::json!({ "status": "Enabled", "secret": "s" }),
            "pending" => serde_json::json!({ "status": "Pending", "secret": "s" }),
            _ => serde_json::json!({ "status": "Disabled" }),
        };
        serde_json::from_value(serde_json::json!({
            "_id": id,
            "email": "reviewer@example.com",
            "email_normalised": "reviewer@example.com",
            "password": "x",
            "disabled": disabled,
            "verification": { "status": "Verified" },
            "mfa": { "totp_token": totp },
        }))
        .expect("test account")
    }

    fn user(id: &str, privileged: bool) -> User {
        User {
            id: id.to_string(),
            username: "reviewer".to_string(),
            discriminator: "0001".to_string(),
            privileged,
            ..Default::default()
        }
    }

    /// A reviewer with every condition met, stored; returns its id
    #[allow(clippy::disallowed_methods)]
    async fn stored_reviewer(db: &Database) -> String {
        let id = ulid::Ulid::new().to_string();
        db.insert_user(&user(&id, true)).await.unwrap();
        db.save_account(&account(&id, "enabled", false))
            .await
            .unwrap();
        id
    }

    fn file(id: &str, hash: &str, used_for: Option<FileUsedFor>) -> File {
        File {
            id: id.to_string(),
            tag: "attachments".to_string(),
            filename: "image.png".to_string(),
            hash: Some(hash.to_string()),
            uploaded_at: None,
            uploader_id: None,
            used_for,
            deleted: None,
            reported: None,
            metadata: Metadata::File,
            content_type: "image/png".to_string(),
            size: 4,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        }
    }

    #[allow(clippy::disallowed_methods)]
    async fn stored_file(db: &Database, file: &File) {
        db.insert_attachment(file).await.unwrap();
    }

    async fn stored_hash_row(db: &Database, id: &str, processed: &str) {
        db.insert_attachment_hash(&FileHash {
            id: id.to_string(),
            processed_hash: processed.to_string(),
            created_at: Timestamp::now_utc(),
            bucket_id: TEST_BUCKET.to_string(),
            path: id.to_string(),
            iv: String::new(),
            format_version: None,
            key_id: None,
            metadata: Metadata::File,
            content_type: "image/png".to_string(),
            size: 0,
        })
        .await
        .unwrap();
    }

    /// A stored request with no targets yet (mutate, then store)
    fn request() -> TakedownRequest {
        let epoch = serde_json::to_value(Timestamp::UNIX_EPOCH).unwrap();
        serde_json::from_value(serde_json::json!({
            "_id": ulid::Ulid::new().to_string(),
            "status": "UnderReview",
            "source": { "type": "Web" },
            "received_at": epoch,
            "deadline_at": epoch,
            "sealed": "",
            "contact_fp": "",
            "status_token_hash": "",
            "locations": [],
            "minor_claimed": false,
        }))
        .expect("test request")
    }

    fn error_type<T>(result: Result<T>) -> ErrorType {
        match result {
            Err(error) => error.error_type,
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn guard_needs_every_condition() {
        let id = "01REVIEWER0000000000000001";
        let other = "01OTHER0000000000000000001";
        let reviewers = vec![id.to_string()];
        let nobody: Vec<String> = Vec::new();
        let someone_else = vec![other.to_string()];

        assert!(may_view_evidence(
            &user(id, true),
            &account(id, "enabled", false),
            &reviewers
        ));

        assert!(
            !may_view_evidence(&user(id, false), &account(id, "enabled", false), &reviewers),
            "not privileged"
        );
        assert!(
            !may_view_evidence(&user(id, true), &account(id, "enabled", false), &nobody),
            "not on the reviewer list"
        );
        assert!(
            !may_view_evidence(
                &user(id, true),
                &account(id, "enabled", false),
                &someone_else
            ),
            "someone else on the list"
        );
        assert!(
            !may_view_evidence(&user(id, true), &account(id, "pending", false), &reviewers),
            "MFA set up but not confirmed"
        );
        assert!(
            !may_view_evidence(&user(id, true), &account(id, "off", false), &reviewers),
            "MFA off"
        );
        assert!(
            !may_view_evidence(&user(id, true), &account(id, "enabled", true), &reviewers),
            "account disabled"
        );
        assert!(
            !may_view_evidence(
                &user(id, true),
                &account(other, "enabled", false),
                &reviewers
            ),
            "account of another user"
        );

        let mut bot = user(id, true);
        bot.bot = Some(revolt_database::BotInformation {
            owner: "01OWNER0000000000000000001".to_string(),
        });
        assert!(
            !may_view_evidence(&bot, &account(id, "enabled", false), &reviewers),
            "a bot"
        );
    }

    /// The guard runs before the request id and file lookups: a non-reviewer
    /// gets NotPrivileged even with no request id and a file that does not
    /// exist, never InvalidOperation or NotFound
    #[allow(clippy::disallowed_methods)]
    #[tokio::test]
    async fn guard_is_checked_before_the_file_lookup() {
        let db = db();
        let id = ulid::Ulid::new().to_string();
        db.insert_user(&user(&id, true)).await.unwrap();
        db.save_account(&account(&id, "off", false)).await.unwrap();
        let reviewers = vec![id.clone()];
        let unknown_request = ulid::Ulid::new().to_string();

        assert!(matches!(
            error_type(authorize_evidence(&db, &reviewers, &id, "no-such-file", None).await),
            ErrorType::NotPrivileged
        ));
        assert!(matches!(
            error_type(
                authorize_evidence(
                    &db,
                    &reviewers,
                    &id,
                    "no-such-file",
                    Some(unknown_request.as_str())
                )
                .await
            ),
            ErrorType::NotPrivileged
        ));

        // The same user once MFA is on: now the file lookup runs
        db.save_account(&account(&id, "enabled", false))
            .await
            .unwrap();
        assert!(matches!(
            error_type(
                authorize_evidence(
                    &db,
                    &reviewers,
                    &id,
                    "no-such-file",
                    Some(unknown_request.as_str())
                )
                .await
            ),
            ErrorType::NotFound
        ));
    }

    /// Hidden (deleted + reported) files are authorized like any other
    #[tokio::test]
    async fn hidden_files_are_authorized() {
        let db = db();
        let reviewer = stored_reviewer(&db).await;
        let reviewers = vec![reviewer.clone()];

        let hidden = file("hidden-file", "hash-hidden", None);
        stored_file(&db, &hidden).await;
        db.hide_attachments(&[hidden.id.clone()]).await.unwrap();

        let mut stored = request();
        stored.targets = vec![TakedownTarget::File {
            file: hidden.id.clone(),
        }];
        db.insert_takedown_request(&stored).await.unwrap();

        let (found, request) = authorize_evidence(
            &db,
            &reviewers,
            &reviewer,
            &hidden.id,
            Some(stored.id.as_str()),
        )
        .await
        .unwrap();
        assert_eq!(found.id, hidden.id);
        assert_eq!(found.deleted, Some(true));
        assert_eq!(request, stored.id);
    }

    /// `?request=` is required and must be a ULID of an existing request
    /// that covers the file: held by it, a target, attached to a target, or
    /// an exact copy of one by original or processed hash. Anything else,
    /// including no request id at all, is refused.
    #[tokio::test]
    async fn request_scope_is_enforced() {
        let db = db();
        let reviewer = stored_reviewer(&db).await;
        let reviewers = vec![reviewer.clone()];
        let authorize = |file_id: &'static str, request: Option<String>| {
            let db = db.clone();
            let reviewers = reviewers.clone();
            let reviewer = reviewer.clone();
            async move {
                authorize_evidence(&db, &reviewers, &reviewer, file_id, request.as_deref()).await
            }
        };

        let target = file("target-file", "hash-target", None);
        let held = file("held-file", "hash-held", None);
        let attached = file(
            "attached-file",
            "hash-attached",
            Some(FileUsedFor {
                object_type: FileUsedForType::Message,
                id: "01MESSAGE00000000000000001".to_string(),
            }),
        );
        let copy = file("copy-file", "hash-target", None);
        let processed_copy = file("processed-copy", "hash-other-original", None);
        let unrelated = file("unrelated-file", "hash-unrelated", None);
        for row in [
            &target,
            &held,
            &attached,
            &copy,
            &processed_copy,
            &unrelated,
        ] {
            stored_file(&db, row).await;
        }
        stored_hash_row(&db, "hash-target", "processed-target").await;
        stored_hash_row(&db, "hash-other-original", "processed-target").await;
        stored_hash_row(&db, "hash-unrelated", "processed-unrelated").await;

        let mut stored = request();
        stored.targets = vec![
            TakedownTarget::File {
                file: target.id.clone(),
            },
            TakedownTarget::Message {
                channel: "01CHANNEL00000000000000001".to_string(),
                message: "01MESSAGE00000000000000001".to_string(),
            },
        ];
        stored.held_files = vec![HeldFile {
            id: held.id.clone(),
            was_deleted: false,
            was_reported: false,
        }];
        db.insert_takedown_request(&stored).await.unwrap();
        let id = stored.id.clone();

        for covered in [
            "target-file",
            "held-file",
            "attached-file",
            "copy-file",
            "processed-copy",
        ] {
            let (_, request) = authorize(covered, Some(id.clone()))
                .await
                .unwrap_or_else(|error| panic!("{covered} is covered: {error:?}"));
            assert_eq!(request, id, "{covered}");
        }

        assert!(matches!(
            error_type(authorize("unrelated-file", Some(id.clone())).await),
            ErrorType::NotFound
        ));

        // No request id: refused like a malformed one, for any file
        for file_id in ["unrelated-file", "target-file", "no-such-file"] {
            assert!(
                matches!(
                    error_type(authorize(file_id, None).await),
                    ErrorType::InvalidOperation
                ),
                "{file_id}"
            );
        }

        // Lowercase is the same ULID
        let lower = Some(stored.id.to_ascii_lowercase());
        let (_, request) = authorize("target-file", lower).await.unwrap();
        assert_eq!(request, id);

        // Malformed and unknown request ids
        assert!(matches!(
            error_type(authorize("target-file", Some("TD-not-an-id".to_string())).await),
            ErrorType::InvalidOperation
        ));
        assert!(matches!(
            error_type(authorize("target-file", Some(String::new())).await),
            ErrorType::InvalidOperation
        ));
        assert!(matches!(
            error_type(authorize("target-file", Some(ulid::Ulid::new().to_string())).await),
            ErrorType::NotFound
        ));
    }

    #[test]
    fn only_media_keeps_its_content_type() {
        assert!(is_inline_media("image/png"));
        assert!(is_inline_media("IMAGE/JPEG"));
        assert!(is_inline_media("video/mp4"));
        assert!(is_inline_media("audio/ogg; codecs=opus"));
        assert!(!is_inline_media("image/svg+xml"));
        assert!(!is_inline_media("Image/SVG+XML; charset=utf-8"));
        assert!(!is_inline_media("text/html"));
        assert!(!is_inline_media("application/pdf"));
        assert!(!is_inline_media(""));
    }

    /// Live MinIO: a hidden file's bytes are served uncached and inline, a
    /// non-media type goes out as opaque bytes, and the view is audited
    /// against the request
    #[tokio::test]
    async fn hidden_evidence_is_served_uncached_and_audited() {
        test_env().await;
        ensure_bucket().await;
        let db = db();
        let reviewer = stored_reviewer(&db).await;
        let reviewers = vec![reviewer.clone()];

        let body = b"<html>evidence</html>".to_vec();
        let hash_id = format!("evidence-{}", ulid::Ulid::new());
        let (iv, key_id) = revolt_files::upload_to_s3(TEST_BUCKET, &hash_id, &body)
            .await
            .unwrap();
        db.insert_attachment_hash(&FileHash {
            id: hash_id.clone(),
            processed_hash: hash_id.clone(),
            created_at: Timestamp::now_utc(),
            bucket_id: TEST_BUCKET.to_string(),
            path: hash_id.clone(),
            iv,
            format_version: None,
            key_id,
            metadata: Metadata::File,
            content_type: "text/html".to_string(),
            size: body.len() as isize,
        })
        .await
        .unwrap();

        let evidence = file(&format!("file-{hash_id}"), &hash_id, None);
        stored_file(&db, &evidence).await;
        db.hide_attachments(&[evidence.id.clone()]).await.unwrap();

        let mut stored = request();
        stored.targets = vec![TakedownTarget::File {
            file: evidence.id.clone(),
        }];
        db.insert_takedown_request(&stored).await.unwrap();

        let response = evidence_for(
            &db,
            &reviewers,
            &reviewer,
            &evidence.id,
            Some(stored.id.as_str()),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let get = |name: header::HeaderName| {
            response
                .headers()
                .get(name)
                .map(|value| value.to_str().unwrap().to_string())
        };
        assert_eq!(
            get(header::CACHE_CONTROL).as_deref(),
            Some("private, no-store")
        );
        assert_eq!(get(header::CONTENT_DISPOSITION).as_deref(), Some("inline"));
        assert_eq!(
            get(header::CONTENT_TYPE).as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(
            get(header::X_CONTENT_TYPE_OPTIONS).as_deref(),
            Some("nosniff")
        );
        let served = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&served[..], &body[..]);

        let audit = db.fetch_staff_audit_for_request(&stored.id).await.unwrap();
        assert_eq!(audit.len(), 1);
        assert!(matches!(
            audit[0].action,
            StaffAuditAction::TakedownViewedEvidence
        ));
        assert_eq!(audit[0].actor.as_deref(), Some(reviewer.as_str()));
        assert_eq!(audit[0].target_ids, vec![evidence.id.clone()]);
        assert_eq!(audit[0].request_id.as_deref(), Some(stored.id.as_str()));

        // Without a request id nothing is served and no view is recorded
        match evidence_for(&db, &reviewers, &reviewer, &evidence.id, None).await {
            Err(error) => assert!(matches!(error.error_type, ErrorType::InvalidOperation)),
            Ok(response) => panic!("served without a request id: {}", response.status()),
        }
        assert_eq!(
            db.fetch_staff_audit_for_request(&stored.id)
                .await
                .unwrap()
                .len(),
            1
        );

        let _ = revolt_files::delete_from_s3(TEST_BUCKET, &hash_id).await;
    }
}
