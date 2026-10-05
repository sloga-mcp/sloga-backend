use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::{middleware::from_fn_with_state, Router};

use axum_macros::FromRef;
use revolt_database::mongodb::bson::{doc, Bson, Document};
use revolt_database::{Database, DatabaseInfo, MongoDb, UploadSessionState};
use revolt_files::{FileKeyring, COMMITTED_DEFAULT_KEY_FP, LEGACY_KEY_ID};
use revolt_ratelimits::axum as ratelimiter;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_scalar::{Scalar, Servable as ScalarServable};

mod api;
pub mod clamav;
mod download;
mod e2ee;
pub mod exif;
pub mod metadata;
pub mod mime_type;
mod ratelimits;
mod upload;
mod utils;
pub mod video;

#[derive(FromRef, Clone)]
struct AppState {
    database: Database,
    ratelimit_storage: ratelimiter::RatelimitStorage,
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // Configure logging and environment
    revolt_config::configure!(files);

    // Build the file keyring before anything serves, so a bad [files] key
    // config stops the process here instead of panicking inside a request
    let keyring = init_file_keyring().await;

    // Wait for ClamAV
    clamav::init().await;

    // Configure API schema
    #[derive(OpenApi)]
    #[openapi(
        modifiers(&SecurityAddon),
        paths(
            api::root,
            api::upload_file,
            api::fetch_preview,
            api::fetch_file,
            upload::create_upload,
            upload::upload_part,
            upload::get_upload_session,
            upload::complete_upload,
            upload::abort_upload,
            e2ee::upload_blob,
            e2ee::fetch_blob
        ),
        components(
            schemas(
                revolt_result::Error,
                revolt_result::ErrorType,
                api::RootResponse,
                api::Tag,
                api::UploadPayload,
                api::UploadResponse,
                upload::CreateUploadPayload,
                upload::CreateUploadResponse,
                upload::UploadSessionStatus,
                e2ee::BlobUploadPayload,
                e2ee::BlobUploadResponse
            )
        ),
        tags(
            // (name = "Files", description = "File uploads API")
        )
    )]
    struct ApiDoc;

    struct SecurityAddon;

    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            if let Some(components) = openapi.components.as_mut() {
                components.add_security_scheme(
                    "bot_token",
                    SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Bot-Token"))),
                );
                components.add_security_scheme(
                    "session_token",
                    SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Session-Token"))),
                );
            }
        }
    }

    // Connect to the database
    let db = DatabaseInfo::Auto.connect().await.unwrap();

    // Refuse to serve without every file key the stored objects need, then
    // prove each needed key really decrypts one of them
    guard_file_keys(&db, &keyring).await;

    let ratelimits = ratelimiter::RatelimitStorage::new(ratelimits::AutumnRatelimits);

    // Ensure orphaned multipart uploads get reaped server-side (ship gate
    // for chunked uploads). On MinIO this is a no-op with a log line — its
    // `api stale_uploads_expiry` setting (72h in prod) is the real backstop.
    {
        let bucket = revolt_config::config().await.files.s3.default_bucket;
        if let Err(error) = revolt_files::ensure_bucket_lifecycle(&bucket).await {
            tracing::warn!("could not apply bucket lifecycle to {bucket}: {error:?}");
        }
    }

    let state = AppState {
        database: db,
        ratelimit_storage: ratelimits,
    };

    // Configure Axum and router
    let app = Router::new()
        .merge(Scalar::with_url("/scalar", ApiDoc::openapi()))
        .nest("/", api::router().await)
        .nest("/", ratelimiter::routes())
        .layer(from_fn_with_state(
            state.clone(),
            ratelimiter::ratelimit_middleware,
        ))
        .with_state(state);

    // Configure TCP listener and bind
    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 14704));
    let listener = TcpListener::bind(&address).await?;
    axum::serve(listener, app.into_make_service()).await
}

/// Stop the process before it serves; `reason` never carries a key value
fn refuse_to_start(reason: &str) -> ! {
    eprintln!("autumn: refusing to start: {reason}");
    tracing::error!("refusing to start: {reason}");
    std::process::exit(1)
}

/// "legacy" names the rows that have no `key_id`; every other id is used as is
fn key_id_option(id: &str) -> Option<&str> {
    if id == LEGACY_KEY_ID {
        None
    } else {
        Some(id)
    }
}

/// Build the process-wide file keyring and log what it holds (ids and
/// fingerprints only). Exits non-zero when the [files] key config is invalid.
async fn init_file_keyring() -> Arc<FileKeyring> {
    let keyring = match FileKeyring::init_global().await {
        Ok(keyring) => keyring,
        // The error names the failed rule and the id, never a key value
        Err(error) => refuse_to_start(&format!("invalid [files] key config: {error:#}")),
    };

    tracing::info!(
        "file keyring: primary id {}",
        keyring.primary_id().unwrap_or(LEGACY_KEY_ID)
    );
    for id in keyring.key_ids() {
        match keyring.fingerprint(key_id_option(&id)) {
            Ok(fingerprint) => tracing::info!("file keyring: id={id} fingerprint={fingerprint}"),
            Err(error) => tracing::error!("file keyring: id={id} has no fingerprint: {error:#}"),
        }
    }

    if matches!(
        keyring.fingerprint(keyring.primary_id()),
        Ok(fingerprint) if fingerprint == COMMITTED_DEFAULT_KEY_FP
    ) {
        tracing::warn!(
            "files.encryption_key is upstream's committed default; \
             anyone with the bucket can decrypt"
        );
    }

    keyring
}

/// Upload session states whose parts may still be written or read back
fn active_session_states() -> Bson {
    Bson::Array(vec![
        Bson::String(UploadSessionState::Pending.as_variant_str().to_string()),
        Bson::String(UploadSessionState::Completing.as_variant_str().to_string()),
    ])
}

/// Every file key id that a stored object or an active upload session still
/// needs. "legacy" stands for rows with no `key_id`.
///
/// `key_id: null` matches an absent field AND an explicit null; the same
/// predicate is used for every collection.
async fn needed_key_ids(mongo: &MongoDb) -> Result<BTreeSet<String>, String> {
    let mut needed = BTreeSet::new();

    let named = doc! { "key_id": { "$ne": Bson::Null } };
    let named_sessions = doc! {
        "key_id": { "$ne": Bson::Null },
        "state": { "$in": active_session_states() },
    };
    for (collection, filter) in [
        ("attachment_hashes", named.clone()),
        ("e2ee_blobs", named),
        ("upload_sessions", named_sessions),
    ] {
        let values = mongo
            .col::<Document>(collection)
            .distinct("key_id", filter)
            .await
            .map_err(|error| format!("distinct key_id in {collection}: {error}"))?;
        for value in values {
            match value {
                Bson::String(id) => {
                    needed.insert(id);
                }
                // No reader can resolve a key_id that is not a string, so it
                // fails closed like a missing key
                other => {
                    return Err(format!(
                        "{collection} holds a key_id of type {:?}",
                        other.element_type()
                    ))
                }
            }
        }
    }

    let legacy = [
        (
            "attachment_hashes",
            doc! { "key_id": Bson::Null, "iv": { "$ne": "" } },
        ),
        (
            "e2ee_blobs",
            doc! { "key_id": Bson::Null, "iv": { "$ne": "" } },
        ),
        (
            "upload_sessions",
            doc! { "key_id": Bson::Null, "state": { "$in": active_session_states() } },
        ),
    ];
    for (collection, filter) in legacy {
        let count = mongo
            .col::<Document>(collection)
            .count_documents(filter)
            .limit(1)
            .await
            .map_err(|error| format!("count legacy rows in {collection}: {error}"))?;
        if count > 0 {
            needed.insert(LEGACY_KEY_ID.to_string());
            break;
        }
    }

    Ok(needed)
}

/// The ids in `needed` that the keyring has no key for, in order
fn missing_key_ids(needed: &BTreeSet<String>, keyring: &FileKeyring) -> Vec<String> {
    needed
        .iter()
        .filter(|id| !keyring.has(key_id_option(id)))
        .cloned()
        .collect()
}

/// Most quarantined hash ids the probe excludes by `_id: {$nin: [...]}`;
/// above this the exclusion is skipped
const MAX_QUARANTINE_EXCLUSION: usize = 10_000;

/// Smallest candidate objects the probe tries per key id
const PROBE_CANDIDATES: i64 = 5;

/// Hash ids the migrator journaled as quarantined in `file_key_migrations`
/// (field `status`, value "quarantine"). Their objects failed decrypt or hash
/// at migration, so a probe must not judge a key by them.
///
/// None = probe without the exclusion (journal unreadable or too large); that
/// can only add a false FAIL, never a false PASS.
async fn quarantined_hash_ids(mongo: &MongoDb) -> Option<Vec<Bson>> {
    let journal = mongo.col::<Document>("file_key_migrations");
    let filter = doc! { "status": "quarantine" };

    // Count first so an oversized set is never loaded; a missing collection
    // counts 0, an empty set
    let count = match journal.count_documents(filter.clone()).await {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(
                "file key probe: could not read file_key_migrations ({error}); \
                 probing without the quarantine exclusion"
            );
            return None;
        }
    };
    if count > MAX_QUARANTINE_EXCLUSION as u64 {
        tracing::warn!(
            "file key probe: {count} quarantined rows exceed {MAX_QUARANTINE_EXCLUSION}; \
             probing without the quarantine exclusion"
        );
        return None;
    }
    if count == 0 {
        return Some(Vec::new());
    }

    match journal.distinct("_id", filter).await {
        Ok(ids) => {
            let len = ids.len();
            let exclusion = capped_exclusion(ids);
            if exclusion.is_none() {
                tracing::warn!(
                    "file key probe: {len} quarantined rows exceed \
                     {MAX_QUARANTINE_EXCLUSION}; probing without the quarantine exclusion"
                );
            }
            exclusion
        }
        Err(error) => {
            tracing::warn!(
                "file key probe: could not read file_key_migrations ({error}); \
                 probing without the quarantine exclusion"
            );
            None
        }
    }
}

/// The exclusion list, or None when it is over the cap
fn capped_exclusion(ids: Vec<Bson>) -> Option<Vec<Bson>> {
    if ids.len() > MAX_QUARANTINE_EXCLUSION {
        None
    } else {
        Some(ids)
    }
}

/// Probe candidates for one key id: v1 rows (no `format_version`) with a
/// non-empty iv under that key, minus the excluded hash ids. "legacy" uses the
/// same `key_id: null` predicate as the guard.
fn probe_filter(id: &str, exclude: Option<&[Bson]>) -> Document {
    let key_filter = match key_id_option(id) {
        Some(id) => Bson::String(id.to_string()),
        None => Bson::Null,
    };
    let mut filter = doc! {
        "key_id": key_filter,
        "iv": { "$ne": "" },
        "format_version": Bson::Null,
    };
    if let Some(ids) = exclude {
        if !ids.is_empty() {
            filter.insert("_id", doc! { "$nin": Bson::Array(ids.to_vec()) });
        }
    }
    filter
}

/// Result of the known-answer probe for one key id
#[derive(Debug)]
enum ProbeOutcome {
    /// The candidate with this hash prefix decrypted and matched its hash
    Pass { hash_prefix: String },
    /// Every candidate failed: (hash prefix, fixed reason) per attempt
    Fail {
        attempts: Vec<(String, &'static str)>,
    },
    /// No candidate row exists for this id
    Skipped,
}

/// Verdict over the attempts made, in order: PASS at the first success, FAIL
/// only when every attempt failed, SKIPPED when nothing was tried.
///
/// Sound because a wrong key cannot pass both the AES-GCM tag check and the
/// sha256 match, so one success proves the key.
fn probe_verdict(attempts: Vec<(String, Result<(), &'static str>)>) -> ProbeOutcome {
    if attempts.is_empty() {
        return ProbeOutcome::Skipped;
    }

    let mut failures = Vec::with_capacity(attempts.len());
    for (hash_prefix, result) in attempts {
        match result {
            Ok(()) => return ProbeOutcome::Pass { hash_prefix },
            Err(reason) => failures.push((hash_prefix, reason)),
        }
    }
    ProbeOutcome::Fail { attempts: failures }
}

/// Decrypt one candidate row and check it against its recorded hash
async fn probe_candidate(row: &Document, id: &str) -> Result<(), &'static str> {
    let (Ok(hash_id), Ok(processed_hash), Ok(bucket_id), Ok(path), Ok(iv)) = (
        row.get_str("_id"),
        row.get_str("processed_hash"),
        row.get_str("bucket_id"),
        row.get_str("path"),
        row.get_str("iv"),
    ) else {
        return Err("row is missing a storage field");
    };

    let Ok(plaintext) = revolt_files::fetch_from_s3(bucket_id, path, iv, key_id_option(id)).await
    else {
        return Err("fetch or decrypt failed");
    };
    let digest = format!("{:02x}", Sha256::digest(&plaintext));

    // Healed rows store the original bytes, so the plaintext may match the
    // row's own id instead of processed_hash
    if digest == processed_hash || digest == hash_id {
        Ok(())
    } else {
        Err("decrypted bytes do not match the recorded hash")
    }
}

/// Try the smallest candidate objects stored under `id`, in order, stopping
/// at the first that decrypts and matches its hash. Logs nothing; the caller
/// logs ids, fingerprints and hash prefixes only, never plaintext, keys or
/// object paths.
async fn probe_file_key(mongo: &MongoDb, id: &str, exclude: Option<&[Bson]>) -> ProbeOutcome {
    let mut attempts = Vec::new();

    let cursor = mongo
        .col::<Document>("attachment_hashes")
        .find(probe_filter(id, exclude))
        .sort(doc! { "size": 1_i32, "_id": 1_i32 })
        .projection(doc! {
            "_id": 1_i32,
            "processed_hash": 1_i32,
            "bucket_id": 1_i32,
            "path": 1_i32,
            "iv": 1_i32,
        })
        .limit(PROBE_CANDIDATES)
        .await;
    let mut cursor = match cursor {
        Ok(cursor) => cursor,
        Err(_) => {
            attempts.push(("-".to_string(), Err("could not read attachment_hashes")));
            return probe_verdict(attempts);
        }
    };

    loop {
        match cursor.advance().await {
            Ok(true) => {}
            Ok(false) => break,
            Err(_) => {
                attempts.push(("-".to_string(), Err("could not read attachment_hashes")));
                break;
            }
        }
        let Ok(row) = cursor.deserialize_current() else {
            attempts.push(("-".to_string(), Err("row could not be decoded")));
            continue;
        };

        let hash_prefix: String = row
            .get_str("_id")
            .unwrap_or_default()
            .chars()
            .take(12)
            .collect();
        let result = probe_candidate(&row, id).await;
        let passed = result.is_ok();
        attempts.push((hash_prefix, result));
        if passed {
            break;
        }
    }

    probe_verdict(attempts)
}

/// [A1] boot guard and [A9] known-answer probe, run before the listener binds.
///
/// Every file key id a stored object or an active upload session needs must
/// be in the keyring, or the process exits. Each needed key then has to
/// decrypt one of the 5 smallest non-quarantined v1 objects stored under it; a
/// failed probe is fatal only when `files.require_rotated_key` is set. Raw
/// Mongo only.
async fn guard_file_keys(db: &Database, keyring: &FileKeyring) {
    let mongo = match db {
        Database::MongoDb(mongo) => mongo,
        Database::Reference(_) => {
            tracing::info!("file key boot guard skipped (reference driver)");
            return;
        }
    };

    // Fail closed when the guard cannot read the database (Mongo down at boot
    // included): exit non-zero and let systemd's Restart= bring autumn back up
    // to try again, rather than serve without the check
    let needed = match needed_key_ids(mongo).await {
        Ok(needed) => needed,
        Err(reason) => refuse_to_start(&format!(
            "file key boot guard could not read the database: {reason}"
        )),
    };

    let missing = missing_key_ids(&needed, keyring);
    if !missing.is_empty() {
        refuse_to_start(&format!(
            "stored files need file key ids missing from the keyring: {missing:?}"
        ));
    }

    let needed_list = needed
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    tracing::info!("file key boot guard: needed ids [{needed_list}] are all in the keyring");

    let exclude = if needed.is_empty() {
        None
    } else {
        quarantined_hash_ids(mongo).await
    };

    let mut failed = Vec::new();
    for id in &needed {
        let fingerprint = keyring
            .fingerprint(key_id_option(id))
            .unwrap_or_else(|_| "unknown".to_string());
        match probe_file_key(mongo, id, exclude.as_deref()).await {
            ProbeOutcome::Pass { hash_prefix } => tracing::info!(
                "file key probe PASS for {id} (fingerprint={fingerprint}, hash {hash_prefix})"
            ),
            ProbeOutcome::Skipped => tracing::warn!(
                "file key probe SKIPPED for {id} (no v1 row) (fingerprint={fingerprint})"
            ),
            ProbeOutcome::Fail { attempts } => {
                let detail = attempts
                    .iter()
                    .map(|(hash_prefix, reason)| format!("hash {hash_prefix}: {reason}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                tracing::error!(
                    "file key probe FAIL for {id} (fingerprint={fingerprint}): \
                     all {} candidates failed ({detail})",
                    attempts.len()
                );
                failed.push(id.as_str());
            }
        }
    }

    if !failed.is_empty() {
        let failed = failed.join(", ");
        if revolt_config::config().await.files.require_rotated_key {
            refuse_to_start(&format!(
                "file key probe failed for {failed} and files.require_rotated_key is set"
            ));
        }
        tracing::error!(
            "file key probe failed for {failed}; continuing because \
             files.require_rotated_key is off"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use base64::{prelude::BASE64_STANDARD, Engine};
    use revolt_database::mongodb::bson::{doc, Bson};
    use revolt_files::FileKeyring;

    use super::{
        capped_exclusion, key_id_option, missing_key_ids, probe_filter, probe_verdict,
        ProbeOutcome, MAX_QUARANTINE_EXCLUSION,
    };

    /// A valid 32-byte key, distinct per `byte`
    fn key(byte: u8) -> String {
        BASE64_STANDARD.encode([byte; 32])
    }

    fn ids(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|id| id.to_string()).collect()
    }

    fn test_keyring(primary_id: &str, decrypt_ids: &[&str]) -> FileKeyring {
        let decrypt: HashMap<String, String> = decrypt_ids
            .iter()
            .enumerate()
            .map(|(index, id)| (id.to_string(), key(index as u8 + 10)))
            .collect();
        FileKeyring::from_parts(&key(1), primary_id, &decrypt, false).expect("valid test keyring")
    }

    #[test]
    fn legacy_needed_and_present_is_ok() {
        let keyring = test_keyring("legacy", &[]);
        assert!(missing_key_ids(&ids(&["legacy"]), &keyring).is_empty());
    }

    #[test]
    fn named_id_missing_from_the_keyring_is_reported() {
        let keyring = test_keyring("legacy", &[]);
        assert_eq!(
            missing_key_ids(&ids(&["k1", "legacy"]), &keyring),
            vec!["k1".to_string()]
        );
    }

    #[test]
    fn legacy_needed_under_a_rotated_primary_without_a_legacy_key_is_reported() {
        let keyring = test_keyring("k1", &[]);
        assert_eq!(
            missing_key_ids(&ids(&["k1", "legacy"]), &keyring),
            vec!["legacy".to_string()]
        );
    }

    #[test]
    fn rotated_primary_with_a_legacy_decrypt_key_covers_both() {
        let keyring = test_keyring("k1", &["legacy"]);
        assert!(missing_key_ids(&ids(&["k1", "legacy"]), &keyring).is_empty());
        assert_eq!(
            missing_key_ids(&ids(&["k1", "k2", "legacy"]), &keyring),
            vec!["k2".to_string()]
        );
    }

    #[test]
    fn nothing_needed_means_nothing_missing() {
        let keyring = test_keyring("k1", &[]);
        assert!(missing_key_ids(&BTreeSet::new(), &keyring).is_empty());
    }

    #[test]
    fn legacy_maps_to_no_key_id() {
        assert_eq!(key_id_option("legacy"), None);
        assert_eq!(key_id_option("k1"), Some("k1"));
    }

    fn attempt(
        prefix: &str,
        result: Result<(), &'static str>,
    ) -> (String, Result<(), &'static str>) {
        (prefix.to_string(), result)
    }

    #[test]
    fn probe_with_no_candidates_is_skipped() {
        assert!(matches!(probe_verdict(Vec::new()), ProbeOutcome::Skipped));
    }

    #[test]
    fn probe_passes_on_the_first_success_after_failures() {
        let verdict = probe_verdict(vec![
            attempt("aaa", Err("fetch or decrypt failed")),
            attempt("bbb", Ok(())),
        ]);
        assert!(
            matches!(&verdict, ProbeOutcome::Pass { hash_prefix } if hash_prefix == "bbb"),
            "{verdict:?}"
        );
    }

    #[test]
    fn probe_fails_only_when_every_candidate_fails() {
        let verdict = probe_verdict(vec![
            attempt("aaa", Err("fetch or decrypt failed")),
            attempt("bbb", Err("decrypted bytes do not match the recorded hash")),
            attempt("ccc", Err("fetch or decrypt failed")),
        ]);
        match verdict {
            ProbeOutcome::Fail { attempts } => assert_eq!(
                attempts,
                vec![
                    ("aaa".to_string(), "fetch or decrypt failed"),
                    (
                        "bbb".to_string(),
                        "decrypted bytes do not match the recorded hash"
                    ),
                    ("ccc".to_string(), "fetch or decrypt failed"),
                ]
            ),
            other => panic!("expected FAIL, got {other:?}"),
        }
    }

    #[test]
    fn probe_filter_uses_the_null_predicate_for_legacy() {
        assert_eq!(
            probe_filter("legacy", None),
            doc! { "key_id": Bson::Null, "iv": { "$ne": "" }, "format_version": Bson::Null }
        );
        let none: [Bson; 0] = [];
        assert_eq!(
            probe_filter("k1", Some(&none[..])),
            doc! { "key_id": "k1", "iv": { "$ne": "" }, "format_version": Bson::Null }
        );
    }

    #[test]
    fn probe_filter_excludes_quarantined_ids() {
        let quarantined = [Bson::String("hash-q".to_string())];
        assert_eq!(
            probe_filter("legacy", Some(&quarantined[..])),
            doc! {
                "key_id": Bson::Null,
                "iv": { "$ne": "" },
                "format_version": Bson::Null,
                "_id": { "$nin": ["hash-q"] },
            }
        );
    }

    #[test]
    fn quarantine_exclusion_is_dropped_over_the_cap() {
        let at_cap = vec![Bson::Null; MAX_QUARANTINE_EXCLUSION];
        assert_eq!(capped_exclusion(at_cap).map(|ids| ids.len()), Some(10_000));
        let over_cap = vec![Bson::Null; MAX_QUARANTINE_EXCLUSION + 1];
        assert!(capped_exclusion(over_cap).is_none());
    }
}
