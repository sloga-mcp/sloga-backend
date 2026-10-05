//! Ops tool: move every legacy-key attachment object onto the primary file
//! key, journaled so a run can be resumed, verified and rolled back until the
//! old objects are purged.
//!
//! Every re-encrypted object goes to a fresh `rk/<primary>/<ulid>` path, and a
//! row only ever moves by a compare-and-swap of its (path, iv, key_id) triple.
//! A row that changes underneath the tool is never clobbered: it is journaled
//! as `lost-race` and only the tool's own new object is deleted. The journal
//! is the `file_key_migrations` collection (`_id` = hash id); its `__lease__`
//! document keeps two mutating runs from overlapping.
//!
//! ```text
//! rekey_files check-config
//! rekey_files plan
//! rekey_files migrate --expect-new-key-pin <sha12> [--concurrency N] [--limit N]
//!                     [--accept-hash-mismatch]
//! rekey_files verify --sample N [--key-file F]
//! rekey_files rollback
//! rekey_files purge-old --dry-run
//! rekey_files purge-old --expect-deletes N
//! ```
//!
//! `purge-old` deletes only after a dry run: the real run recomputes the
//! plan and refuses unless N is exactly the total the dry run printed.
//!
//! Exit codes: 0 success; 1 a check failed, or rows were quarantined, lost a
//! race or errored; 2 usage, config or precondition refusal.
//!
//! The tool refuses to run with `TEST_DB` set: `DatabaseInfo::Auto` would
//! then connect to a fresh, empty database, against which `check-config`
//! passes vacuously and `purge-old` sees every object as an orphan. It prints
//! the database name and the `attachment_hashes` total right after
//! connecting.
//!
//! A `fetch-failed` quarantine is retried by the next `migrate` (the read may
//! have failed transiently), a `hash-mismatch` one only by `migrate
//! --accept-hash-mismatch`; `decrypt-failed` and `v2-layout` are settled.
//! `migrate` prints what is outstanding over the whole journal and exits 0
//! only when no quarantine remains from any run.
//!
//! `REKEY_FILES_SCRATCH_ORPHAN_MIN_AGE_SECS=N` (scratch end-to-end runs only)
//! lowers the 24 h orphan age guard to N seconds. It is refused (exit 2)
//! unless every swept bucket's name starts with `rekey-e2e-`.
//!
//! The config is resolved from the working directory, so run it with the
//! stoatchat root as the cwd wherever the binary lives (e.g. /dev/shm). Needs
//! MongoDB. It never prints a key or plaintext: only key ids, fingerprints,
//! hash-id prefixes and `rk/`/`chunked/` object paths. Do not run
//! `heal_attachment_blob` while `migrate`, `rollback` or `purge-old` runs: it
//! repoints rows without a compare-and-swap.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::{prelude::BASE64_STANDARD, Engine};
use revolt_database::mongodb::bson::{doc, Bson, DateTime, Document};
use revolt_database::mongodb::error::{Error as MongoError, ErrorKind, WriteFailure};
use revolt_database::{Database, DatabaseInfo, FileHash, MongoDb, UploadSessionState};
use revolt_files::{
    abort_multipart_in_s3, complete_multipart_in_s3, create_multipart_in_s3, delete_from_s3,
    fetch_from_s3, fetch_range_from_s3, fetch_stream_from_s3, list_objects_in_s3,
    object_exists_in_s3, upload_part_to_s3, upload_to_s3, EncryptionKey, EncryptionRepository,
    FileKeyring, SegmentedStreamCipher, AUTHENTICATION_TAG_SIZE_BYTES, CHUNK_SIZE,
    COMMITTED_DEFAULT_KEY_FP, LEGACY_KEY_ID, STREAM_NONCE_PREFIX_SIZE, STREAM_SEGMENT_SIZE,
};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tokio::task::{JoinError, JoinSet};

/// Migration journal; `_id` = hash id, plus the `__lease__` document
const JOURNAL: &str = "file_key_migrations";
/// The lease document's `_id`; it never carries a `status` field
const LEASE_ID: &str = "__lease__";

const HASHES: &str = "attachment_hashes";
const BLOBS: &str = "e2ee_blobs";
const SESSIONS: &str = "upload_sessions";

/// Object key prefix of e2ee blobs (`E2EEBlob::s3_path`); never swept
const E2EE_PREFIX: &str = "e2ee_";

const STATUS_PENDING: &str = "pending";
const STATUS_MIGRATED: &str = "migrated";
/// Pinned by DA12: the autumn probe excludes `{status: "quarantine"}` rows
const STATUS_QUARANTINE: &str = "quarantine";
const STATUS_LOST_RACE: &str = "lost-race";
const STATUS_ROLLED_BACK: &str = "rolled-back";

const REASON_DECRYPT: &str = "decrypt-failed";
const REASON_HASH_MISMATCH: &str = "hash-mismatch";
const REASON_FETCH: &str = "fetch-failed";
const REASON_V2_LAYOUT: &str = "v2-layout";

const EXIT_OK: i32 = 0;
const EXIT_FAILED: i32 = 1;
const EXIT_REFUSED: i32 = 2;

/// A lease lives this long unless renewed
const LEASE_TTL_MS: i64 = 5 * 60 * 1000;
/// How often the holder renews its lease
const LEASE_RENEW_EVERY: Duration = Duration::from_secs(60);
/// Stop mutating this long before the last confirmed expiry
const LEASE_SAFETY_MS: i64 = 30 * 1000;
/// Resume leaves a pending entry alone until it has been quiet this long: a
/// younger one may belong to a run whose lease lapsed mid-swap
const RESUME_MIN_AGE_MS: i64 = 2 * LEASE_TTL_MS;

/// Unreferenced objects younger than this are never swept (DA11)
const ORPHAN_MIN_AGE_SECS: i64 = 24 * 60 * 60;
/// Lowers the orphan age guard, for scratch end-to-end runs only
const SCRATCH_AGE_ENV: &str = "REKEY_FILES_SCRATCH_ORPHAN_MIN_AGE_SECS";
/// The override is honored only when every swept bucket has this prefix
const SCRATCH_BUCKET_PREFIX: &str = "rekey-e2e-";

/// A v1 row is read, decrypted and re-encrypted whole in memory (several
/// copies of it), so a row larger than this runs alone
const LARGE_V1_BYTES: i64 = 256 * 1024 * 1024;
/// `verify` checks every migrated object larger than this
const VERIFY_LARGE_OBJECT_BYTES: i64 = 16 * 1024 * 1024;
const MAX_VERIFY_SAMPLE: u64 = 100_000;

const DEFAULT_CONCURRENCY: usize = 4;
const MAX_CONCURRENCY: usize = 16;
/// Legacy rows read per selection query (short queries; no long-lived cursor)
const SELECTION_PAGE: i64 = 200;
/// Attempts per object read before it counts as a fetch failure
const FETCH_ATTEMPTS: u64 = 3;
/// S3's multipart part ceiling
const MAX_V2_PARTS: u64 = 10_000;
/// Example keys a dry run prints per bucket
const EXAMPLE_KEYS: usize = 20;

/// Most quarantined hash ids the probe excludes by `_id: {$nin: [...]}`;
/// above this the exclusion is skipped
const MAX_QUARANTINE_EXCLUSION: usize = 10_000;

/// Smallest candidate objects the probe tries per key id
const PROBE_CANDIDATES: i64 = 5;

const USAGE: &str = "usage:
  rekey_files check-config
  rekey_files plan
  rekey_files migrate --expect-new-key-pin <sha12> [--concurrency N] [--limit N] [--accept-hash-mismatch]
  rekey_files verify --sample N [--key-file F]
  rekey_files rollback
  rekey_files purge-old --dry-run
  rekey_files purge-old --expect-deletes N    (N = the total the dry run printed)
TEST_DB must be unset.
REKEY_FILES_SCRATCH_ORPHAN_MIN_AGE_SECS is honored for rekey-e2e-* buckets only.";

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Command {
    CheckConfig,
    Plan,
    Migrate(MigrateArgs),
    Verify(VerifyArgs),
    Rollback,
    PurgeOld(PurgeMode),
}

/// A purge either only reports, or deletes exactly the count a dry run printed
#[derive(Debug, PartialEq, Eq)]
enum PurgeMode {
    DryRun,
    Delete { expect_deletes: u64 },
}

#[derive(Debug, PartialEq, Eq)]
struct MigrateArgs {
    expect_new_key_pin: String,
    concurrency: usize,
    limit: Option<u64>,
    accept_hash_mismatch: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct VerifyArgs {
    sample: u64,
    key_file: Option<String>,
}

/// Parse the arguments after the program name. Errors never echo an argument
/// back, so a key pasted onto the command line by mistake is not printed.
fn parse_args(args: &[String]) -> Result<Command, String> {
    let Some((subcommand, rest)) = args.split_first() else {
        return Err("missing subcommand".to_string());
    };

    match subcommand.as_str() {
        "check-config" => {
            parse_flags(rest, &[], &[])?;
            Ok(Command::CheckConfig)
        }
        "plan" => {
            parse_flags(rest, &[], &[])?;
            Ok(Command::Plan)
        }
        "migrate" => {
            let mut flags = parse_flags(
                rest,
                &["--expect-new-key-pin", "--concurrency", "--limit"],
                &["--accept-hash-mismatch"],
            )?;
            let expect_new_key_pin = flags
                .remove("--expect-new-key-pin")
                .flatten()
                .ok_or("migrate needs --expect-new-key-pin <sha12>")?;
            if !is_fingerprint(&expect_new_key_pin) {
                return Err("--expect-new-key-pin must be 12 lowercase hex characters".to_string());
            }
            let concurrency = match flags.remove("--concurrency").flatten() {
                Some(value) => {
                    parse_number(&value, "--concurrency", 1, MAX_CONCURRENCY as u64)? as usize
                }
                None => DEFAULT_CONCURRENCY,
            };
            let limit = flags
                .remove("--limit")
                .flatten()
                .map(|value| parse_number(&value, "--limit", 1, u64::MAX))
                .transpose()?;
            Ok(Command::Migrate(MigrateArgs {
                expect_new_key_pin,
                concurrency,
                limit,
                accept_hash_mismatch: flags.contains_key("--accept-hash-mismatch"),
            }))
        }
        "verify" => {
            let mut flags = parse_flags(rest, &["--sample", "--key-file"], &[])?;
            let sample = flags
                .remove("--sample")
                .flatten()
                .ok_or("verify needs --sample N")?;
            Ok(Command::Verify(VerifyArgs {
                sample: parse_number(&sample, "--sample", 0, MAX_VERIFY_SAMPLE)?,
                key_file: flags.remove("--key-file").flatten(),
            }))
        }
        "rollback" => {
            parse_flags(rest, &[], &[])?;
            Ok(Command::Rollback)
        }
        "purge-old" => {
            let mut flags = parse_flags(rest, &["--expect-deletes"], &["--dry-run"])?;
            let expect_deletes = flags
                .remove("--expect-deletes")
                .flatten()
                .map(|value| parse_number(&value, "--expect-deletes", 0, u64::MAX))
                .transpose()?;
            match (flags.contains_key("--dry-run"), expect_deletes) {
                (true, None) => Ok(Command::PurgeOld(PurgeMode::DryRun)),
                (false, Some(expect_deletes)) => {
                    Ok(Command::PurgeOld(PurgeMode::Delete { expect_deletes }))
                }
                (true, Some(_)) => {
                    Err("--expect-deletes is for the real run, not --dry-run".to_string())
                }
                (false, None) => Err(
                    "purge-old needs --dry-run, or --expect-deletes N with the total the dry \
                     run printed"
                        .to_string(),
                ),
            }
        }
        _ => Err("unknown subcommand".to_string()),
    }
}

/// `--name value` options and `--switch`es, each allowed at most once
fn parse_flags(
    rest: &[String],
    valued: &[&str],
    switches: &[&str],
) -> Result<HashMap<String, Option<String>>, String> {
    let mut flags = HashMap::new();
    let mut iter = rest.iter().enumerate();
    while let Some((index, arg)) = iter.next() {
        let name = arg.as_str();
        let value = if valued.contains(&name) {
            match iter.next() {
                Some((_, value)) if !value.starts_with("--") => Some(value.clone()),
                _ => return Err(format!("{name} needs a value")),
            }
        } else if switches.contains(&name) {
            None
        } else {
            return Err(format!("unexpected argument at position {}", index + 2));
        };
        if flags.insert(name.to_string(), value).is_some() {
            return Err(format!("{name} given more than once"));
        }
    }
    Ok(flags)
}

fn parse_number(value: &str, flag: &str, min: u64, max: u64) -> Result<u64, String> {
    match value.parse::<u64>() {
        Ok(number) if (min..=max).contains(&number) => Ok(number),
        _ => Err(format!("{flag} must be a whole number from {min} to {max}")),
    }
}

/// A key fingerprint as printed by the keyring: 12 lowercase hex characters
fn is_fingerprint(value: &str) -> bool {
    value.len() == 12
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse_args(&args) {
        Ok(command) => command,
        Err(reason) => {
            eprintln!("rekey_files: {reason}\n{USAGE}");
            std::process::exit(EXIT_REFUSED);
        }
    };

    std::process::exit(run(command).await);
}

async fn run(command: Command) -> i32 {
    // Before anything else: with TEST_DB set, `DatabaseInfo::Auto` connects
    // to a fresh EMPTY database on the configured server, and an empty
    // database makes every stored object look like an orphan
    if let Some(reason) = test_db_refusal(std::env::var_os("TEST_DB").as_deref()) {
        return refuse(reason);
    }

    // The keyring first, so a bad [files] key config stops here with the
    // failed rule (never a key value)
    let Some(keyring) = init_keyring().await else {
        return EXIT_REFUSED;
    };

    let db = match DatabaseInfo::Auto.connect().await {
        Ok(db) => db,
        Err(error) => return refuse(&format!("could not connect to the database: {error}")),
    };
    let mongo = match &db {
        Database::MongoDb(mongo) => mongo.clone(),
        Database::Reference(_) => {
            eprintln!("rekey_files needs MongoDB");
            return EXIT_REFUSED;
        }
    };

    // Say which database this is, so a mis-pointed config is visible
    println!("database: {}", mongo.1);
    let hash_total = match count_docs(&mongo, HASHES, doc! {}).await {
        Ok(total) => total,
        Err(error) => return refuse(&format!("could not count {HASHES} ({error})")),
    };
    println!("database: {HASHES} total {hash_total}");
    if let Some(reason) = empty_database_reason(hash_total) {
        eprintln!("WARN: {reason}");
    }

    // The scratch age override is refused outright unless every bucket a
    // sweep would cover is a scratch bucket; scan_all_buckets checks it again
    match scratch_age_override() {
        Ok(None) => {}
        Ok(Some(value)) => {
            let buckets = match sweep_buckets(&mongo).await {
                Ok(buckets) => buckets,
                Err(error) => {
                    return refuse(&format!(
                        "{SCRATCH_AGE_ENV} is set and the swept buckets are unknown ({error})"
                    ))
                }
            };
            if let Err(reason) = resolve_orphan_min_age(Some(value.as_str()), &buckets) {
                return refuse(&reason);
            }
        }
        Err(reason) => return refuse(&reason),
    }

    match command {
        Command::CheckConfig => check_config(&mongo, &keyring, hash_total).await,
        Command::Plan => plan(&mongo).await,
        Command::Migrate(args) => migrate(&db, &mongo, &keyring, args).await,
        Command::Verify(args) => verify(&mongo, &keyring, args).await,
        Command::Rollback => rollback(&db, &mongo).await,
        Command::PurgeOld(mode) => purge_old(&mongo, hash_total, mode).await,
    }
}

/// Print a refusal and return the refusal exit code
fn refuse(reason: &str) -> i32 {
    eprintln!("rekey_files: refusing: {reason}");
    EXIT_REFUSED
}

/// Why the tool must not run, given the value of `TEST_DB` (read by `run`
/// only; tests pass values in). Any value counts, empty included, because
/// `DatabaseInfo::Auto` only asks whether the variable is set.
fn test_db_refusal(test_db: Option<&OsStr>) -> Option<&'static str> {
    test_db.map(|_| {
        "TEST_DB is set: refusing to run against a throwaway database (unset it and point \
         Revolt.toml at the real one)"
    })
}

/// An empty `attachment_hashes` means the config names the wrong database
fn empty_database_reason(hash_total: u64) -> Option<&'static str> {
    (hash_total == 0).then_some("no attachment_hashes rows: wrong database?")
}

/// Build the process-wide keyring and print what it holds: ids and
/// fingerprints only
async fn init_keyring() -> Option<Arc<FileKeyring>> {
    let keyring = match FileKeyring::init_global().await {
        Ok(keyring) => keyring,
        Err(error) => {
            // The error names the failed rule and the id, never a key value
            eprintln!("rekey_files: invalid [files] key config: {error:#}");
            return None;
        }
    };

    match std::env::current_dir() {
        Ok(cwd) => println!("config resolved from cwd {}", cwd.display()),
        Err(_) => println!("config resolved from an unreadable cwd"),
    }
    println!(
        "file keyring: primary={}",
        keyring.primary_id().unwrap_or(LEGACY_KEY_ID)
    );
    for id in keyring.key_ids() {
        match keyring.fingerprint(key_id_option(&id)) {
            Ok(fingerprint) => println!("file keyring: id={id} fingerprint={fingerprint}"),
            Err(error) => println!("file keyring: id={id} fingerprint unavailable: {error:#}"),
        }
    }
    let committed_default = keyring
        .fingerprint(keyring.primary_id())
        .is_ok_and(|fingerprint| fingerprint == COMMITTED_DEFAULT_KEY_FP);
    println!(
        "file keyring: primary is the committed default: {}",
        if committed_default { "YES" } else { "no" }
    );
    if committed_default {
        eprintln!(
            "WARN: files.encryption_key is upstream's committed default; \
             anyone with the bucket can decrypt"
        );
    }

    Some(keyring)
}

// ---------------------------------------------------------------------------
// Shared predicates (identical to the autumn boot guard, w2 pin 4)
// ---------------------------------------------------------------------------

/// "legacy" names the rows that have no `key_id`; every other id is used as is
fn key_id_option(id: &str) -> Option<&str> {
    if id == LEGACY_KEY_ID {
        None
    } else {
        Some(id)
    }
}

/// Upload session states whose parts may still be written or read back
fn active_session_states() -> Bson {
    Bson::Array(vec![
        Bson::String(UploadSessionState::Pending.as_variant_str().to_string()),
        Bson::String(UploadSessionState::Completing.as_variant_str().to_string()),
    ])
}

/// LEGACY_ROW: an object under the legacy key. `key_id: null` matches an
/// absent field AND an explicit null; `iv: ""` placeholders are excluded.
fn legacy_row_filter() -> Document {
    doc! { "key_id": Bson::Null, "iv": { "$ne": "" } }
}

/// Rows that name a key id
fn named_row_filter() -> Document {
    doc! { "key_id": { "$ne": Bson::Null } }
}

/// Upload sessions that are still Pending or Completing
fn live_session_filter() -> Document {
    doc! { "state": { "$in": active_session_states() } }
}

/// Migrated journal entries whose old object has not been purged
fn unpurged_migrated_filter() -> Document {
    doc! { "status": STATUS_MIGRATED, "purged_at": Bson::Null }
}

/// Journal entries whose old object has been purged
fn purged_filter() -> Document {
    doc! { "_id": { "$ne": LEASE_ID }, "purged_at": { "$ne": Bson::Null } }
}

fn bson_strings(values: &[&str]) -> Bson {
    Bson::Array(
        values
            .iter()
            .map(|value| Bson::String(value.to_string()))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Rows and journal entries
// ---------------------------------------------------------------------------

/// The `attachment_hashes` fields the tool reads
#[derive(Debug, Clone)]
struct HashRow {
    id: String,
    processed_hash: String,
    bucket_id: String,
    path: String,
    iv: String,
    key_id: Option<String>,
    format_version: Option<i64>,
    /// Plaintext size; required for v2 rows only
    size: Option<i64>,
}

impl HashRow {
    fn from_doc(row: &Document) -> Result<HashRow, String> {
        let text = |key: &str| -> Result<String, String> {
            row.get_str(key)
                .map(str::to_string)
                .map_err(|_| format!("row has no string {key}"))
        };
        let format_version = match row.get("format_version") {
            None | Some(Bson::Null) => None,
            value => Some(bson_i64(value).ok_or("format_version is not an integer")?),
        };

        Ok(HashRow {
            id: text("_id")?,
            processed_hash: text("processed_hash")?,
            bucket_id: text("bucket_id")?,
            path: text("path")?,
            iv: text("iv")?,
            key_id: optional_string(row, "key_id")?,
            format_version,
            size: bson_i64(row.get("size")),
        })
    }
}

/// One `file_key_migrations` entry (never the lease)
#[derive(Debug, Clone)]
struct JournalEntry {
    id: String,
    bucket_id: String,
    old_path: String,
    old_iv: String,
    new_path: String,
    new_iv: Option<String>,
    new_key_id: Option<String>,
    format_version: Option<i64>,
    hash_mismatch: bool,
    /// Last write to the entry (ms); None if absent or not a date
    updated_at_ms: Option<i64>,
}

impl JournalEntry {
    fn from_doc(entry: &Document) -> Result<JournalEntry, String> {
        let id = entry
            .get_str("_id")
            .map_err(|_| "journal entry without a string _id".to_string())?
            .to_string();
        let label = short(&id);
        let text = |key: &str| -> Result<String, String> {
            entry
                .get_str(key)
                .map(str::to_string)
                .map_err(|_| format!("journal entry {label} has no string {key}"))
        };

        let bucket_id = text("bucket_id")?;
        let old_path = text("old_path")?;
        let old_iv = text("old_iv")?;
        let new_path = text("new_path")?;
        let new_iv = optional_string(entry, "new_iv")?;
        let new_key_id = optional_string(entry, "new_key_id")?;
        let format_version = bson_i64(entry.get("format_version"));
        let hash_mismatch = entry.get_bool("hash_mismatch").unwrap_or(false);
        let updated_at_ms = entry
            .get_datetime("updated_at")
            .ok()
            .map(|updated_at| updated_at.timestamp_millis());

        Ok(JournalEntry {
            id,
            bucket_id,
            old_path,
            old_iv,
            new_path,
            new_iv,
            new_key_id,
            format_version,
            hash_mismatch,
            updated_at_ms,
        })
    }
}

fn bson_i64(value: Option<&Bson>) -> Option<i64> {
    match value? {
        Bson::Int32(value) => Some(i64::from(*value)),
        Bson::Int64(value) => Some(*value),
        Bson::Double(value) if value.is_finite() && value.fract() == 0.0 => Some(*value as i64),
        _ => None,
    }
}

/// An absent or null field is None; a field of any other non-string type is an error
fn optional_string(row: &Document, key: &str) -> Result<Option<String>, String> {
    match row.get(key) {
        None | Some(Bson::Null) => Ok(None),
        Some(Bson::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(format!("{key} has type {:?}", other.element_type())),
    }
}

/// A hash id (or object key) cut to the 12 characters the logs may show
fn short(id: &str) -> String {
    id.chars().take(12).collect()
}

/// How an object key may be printed: `rk/` and `chunked/` paths in full,
/// anything else (hash ids included) as a 12-character prefix
fn display_key(key: &str) -> String {
    if key.starts_with("rk/") || key.starts_with("chunked/") {
        key.to_string()
    } else {
        format!("{}...", short(key))
    }
}

fn now_ms() -> i64 {
    DateTime::now().timestamp_millis()
}

// ---------------------------------------------------------------------------
// Hash rules
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:02x}", Sha256::digest(bytes))
}

/// Which recorded hash an object's digest matched
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashMatch {
    Processed,
    /// Healed rows (and sticker writers) store bytes that hash to the row's id
    OwnId,
    Mismatch,
}

/// The acceptance rule: the digest equals `processed_hash` or the row's own id
fn hash_match(digest: &str, processed_hash: &str, hash_id: &str) -> HashMatch {
    if digest == processed_hash {
        HashMatch::Processed
    } else if digest == hash_id {
        HashMatch::OwnId
    } else {
        HashMatch::Mismatch
    }
}

/// The v2 composite hash, duplicated verbatim from `upload.rs` `composite_hash`:
/// `sloga-chunked-v2` || chunk_size LE || total_size LE || each part's hex sha256
fn composite_hash_v2(chunk_size: i64, total_size: i64, part_sha256_hex: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sloga-chunked-v2");
    hasher.update(chunk_size.to_le_bytes());
    hasher.update(total_size.to_le_bytes());
    for sha256 in part_sha256_hex {
        hasher.update(sha256.as_bytes());
    }
    format!("{:02x}", hasher.finalize())
}

/// The same hex string with the lowest bit of its last digit flipped (still hex)
fn corrupt_hex_one_bit(hex: &str) -> String {
    let mut chars: Vec<char> = hex.chars().collect();
    match chars.last_mut() {
        Some(last) => {
            *last = match last
                .to_digit(16)
                .and_then(|nibble| char::from_digit(nibble ^ 1, 16))
            {
                Some(flipped) => flipped,
                None if *last == 'x' => 'y',
                None => 'x',
            };
        }
        None => chars.push('x'),
    }
    chars.into_iter().collect()
}

/// 32 random bytes from the OS RNG (the stream cipher's prefix generator), base64
fn random_key_b64() -> String {
    let mut key = Vec::with_capacity(35);
    while key.len() < 32 {
        key.extend_from_slice(&SegmentedStreamCipher::generate_prefix());
    }
    key.truncate(32);
    BASE64_STANDARD.encode(key)
}

// ---------------------------------------------------------------------------
// v2 (segmented) layout
// ---------------------------------------------------------------------------

/// What a v2 row's object must look like
#[derive(Debug, PartialEq, Eq)]
struct V2Layout {
    prefix: [u8; STREAM_NONCE_PREFIX_SIZE],
    total_size: u64,
    /// Plaintext size of each part, in order
    part_sizes: Vec<u64>,
}

impl V2Layout {
    fn of(iv: &str, size: Option<i64>) -> Result<V2Layout, &'static str> {
        let prefix = decode_prefix(iv)?;
        let size = size.ok_or("row has no size")?;
        let part_sizes = v2_part_sizes(size)?;
        Ok(V2Layout {
            prefix,
            total_size: size as u64,
            part_sizes,
        })
    }
}

fn decode_prefix(iv: &str) -> Result<[u8; STREAM_NONCE_PREFIX_SIZE], &'static str> {
    let bytes = BASE64_STANDARD
        .decode(iv)
        .map_err(|_| "nonce prefix is not base64")?;
    <[u8; STREAM_NONCE_PREFIX_SIZE]>::try_from(bytes.as_slice())
        .map_err(|_| "nonce prefix has the wrong length")
}

/// Full `CHUNK_SIZE` parts, then the tail
fn v2_part_sizes(total_size: i64) -> Result<Vec<u64>, &'static str> {
    if total_size <= 0 {
        return Err("size must be positive");
    }
    let total = total_size as u64;
    let chunk = CHUNK_SIZE as u64;
    let parts = total.div_ceil(chunk);
    if parts > MAX_V2_PARTS {
        return Err("too many parts");
    }

    let mut sizes = vec![chunk; parts as usize];
    if let Some(last) = sizes.last_mut() {
        *last = total - chunk * (parts - 1);
    }
    Ok(sizes)
}

/// Stored bytes of a v2 run of `plaintext_len` bytes: one tag per segment
fn ciphertext_len_of(plaintext_len: u64) -> u64 {
    plaintext_len
        + plaintext_len.div_ceil(STREAM_SEGMENT_SIZE as u64) * AUTHENTICATION_TAG_SIZE_BYTES as u64
}

/// [A25] R2 rejects a multipart upload whose non-final parts differ in size
/// (MinIO does not), so every non-final part must be exactly `CHUNK_SIZE` and
/// the final one 1..=`CHUNK_SIZE` bytes
fn check_upload_part(
    part_number: u64,
    total_parts: u64,
    plaintext_len: usize,
) -> Result<(), String> {
    if part_number == 0 || part_number > total_parts {
        return Err(format!(
            "part {part_number} of {total_parts} is out of range"
        ));
    }
    if part_number < total_parts {
        if plaintext_len != CHUNK_SIZE {
            return Err(format!(
                "non-final part {part_number} is {plaintext_len} bytes, not {CHUNK_SIZE}"
            ));
        }
    } else if plaintext_len == 0 || plaintext_len > CHUNK_SIZE {
        return Err(format!(
            "final part {part_number} is {plaintext_len} bytes, not 1..={CHUNK_SIZE}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Object reads
// ---------------------------------------------------------------------------

/// A key to read objects with: a keyring and the id inside it (None = its
/// "legacy" entry)
#[derive(Clone)]
struct KeyRef {
    keyring: Arc<FileKeyring>,
    key_id: Option<String>,
}

/// Why reading an object failed
#[derive(Debug, PartialEq, Eq)]
enum ReadFailure {
    Fetch,
    Decrypt,
    Layout(&'static str),
}

impl ReadFailure {
    /// The journal's quarantine reason for this failure
    fn reason(&self) -> &'static str {
        match self {
            ReadFailure::Fetch => REASON_FETCH,
            ReadFailure::Decrypt => REASON_DECRYPT,
            ReadFailure::Layout(_) => REASON_V2_LAYOUT,
        }
    }

    /// The reason plus, for a layout failure, which assumption failed
    fn describe(&self) -> String {
        match self {
            ReadFailure::Layout(detail) => format!("{REASON_V2_LAYOUT}: {detail}"),
            other => other.reason().to_string(),
        }
    }
}

/// An object's raw (still encrypted) bytes, or an inclusive byte range of
/// them; retried, since one transient error must not quarantine a row
async fn fetch_bytes(bucket_id: &str, path: &str, range: Option<(u64, u64)>) -> Option<Vec<u8>> {
    for attempt in 1..=FETCH_ATTEMPTS {
        if let Some(bytes) = fetch_bytes_once(bucket_id, path, range).await {
            return Some(bytes);
        }
        if attempt < FETCH_ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(2 * attempt)).await;
        }
    }
    None
}

async fn fetch_bytes_once(
    bucket_id: &str,
    path: &str,
    range: Option<(u64, u64)>,
) -> Option<Vec<u8>> {
    let fetched = match range {
        None => fetch_stream_from_s3(bucket_id, path).await,
        Some((start, end_inclusive)) => {
            fetch_range_from_s3(bucket_id, path, start, end_inclusive).await
        }
    };
    let mut body = fetched.ok()?;

    let mut bytes = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.ok()?;
        bytes.extend_from_slice(&chunk);
    }
    Some(bytes)
}

/// sha256 of a v1 object's plaintext under `key`
async fn read_v1_digest(
    bucket_id: &str,
    path: &str,
    iv: &str,
    key: &KeyRef,
) -> Result<String, ReadFailure> {
    let ciphertext = fetch_bytes(bucket_id, path, None)
        .await
        .ok_or(ReadFailure::Fetch)?;
    let plaintext = EncryptionKey::new(key.keyring.clone())
        .decrypt_buffer(ciphertext, iv, key.key_id.as_deref())
        .map_err(|_| ReadFailure::Decrypt)?;
    Ok(sha256_hex(&plaintext))
}

/// The stored object must be exactly as long as the layout says
async fn check_v2_stored_length(
    bucket_id: &str,
    path: &str,
    total_size: u64,
) -> Result<(), ReadFailure> {
    let listed = list_objects_in_s3(bucket_id, Some(path))
        .await
        .map_err(|_| ReadFailure::Fetch)?;
    let Some(object) = listed.iter().find(|object| object.key == path) else {
        return Err(ReadFailure::Fetch);
    };
    if u64::try_from(object.size).ok() != Some(ciphertext_len_of(total_size)) {
        return Err(ReadFailure::Layout(
            "stored length differs from the v2 layout",
        ));
    }
    Ok(())
}

/// Fetch and decrypt one part (1-based) of a v2 object
async fn read_v2_part(
    bucket_id: &str,
    path: &str,
    cipher: &SegmentedStreamCipher,
    part_sizes: &[u64],
    part_number: u64,
) -> Result<Vec<u8>, ReadFailure> {
    let index = part_number
        .checked_sub(1)
        .ok_or(ReadFailure::Layout("part numbers start at 1"))?;
    let Some(&plaintext_len) = part_sizes.get(index as usize) else {
        return Err(ReadFailure::Layout("part out of range"));
    };

    // Every part before this one is a full CHUNK_SIZE part
    let start = index * ciphertext_len_of(CHUNK_SIZE as u64);
    let length = ciphertext_len_of(plaintext_len);
    let ciphertext = fetch_bytes(bucket_id, path, Some((start, start + length - 1)))
        .await
        .ok_or(ReadFailure::Fetch)?;
    if ciphertext.len() as u64 != length {
        return Err(ReadFailure::Layout("short part"));
    }

    let segments_per_part = (CHUNK_SIZE / STREAM_SEGMENT_SIZE) as u64;
    let first_segment = u32::try_from(index * segments_per_part)
        .map_err(|_| ReadFailure::Layout("segment counter overflow"))?;
    let is_final = part_number == part_sizes.len() as u64;
    let plaintext = cipher
        .decrypt_segments(first_segment, is_final, &ciphertext)
        .map_err(|_| ReadFailure::Decrypt)?;
    if plaintext.len() as u64 != plaintext_len {
        return Err(ReadFailure::Layout("decrypted part has the wrong size"));
    }
    Ok(plaintext)
}

/// The composite hash of a v2 object's plaintext under `key`, part by part
async fn read_v2_digest(
    bucket_id: &str,
    path: &str,
    iv: &str,
    size: Option<i64>,
    key: &KeyRef,
) -> Result<String, ReadFailure> {
    let layout = V2Layout::of(iv, size).map_err(ReadFailure::Layout)?;
    check_v2_stored_length(bucket_id, path, layout.total_size).await?;

    let cipher = key
        .keyring
        .cipher(key.key_id.as_deref())
        .map_err(|_| ReadFailure::Decrypt)?;
    let cipher = SegmentedStreamCipher::from_cipher(cipher, layout.prefix);

    let mut part_hashes = Vec::with_capacity(layout.part_sizes.len());
    for part_number in 1..=layout.part_sizes.len() as u64 {
        let plaintext =
            read_v2_part(bucket_id, path, &cipher, &layout.part_sizes, part_number).await?;
        part_hashes.push(sha256_hex(&plaintext));
    }
    Ok(composite_hash_v2(
        CHUNK_SIZE as i64,
        layout.total_size as i64,
        &part_hashes,
    ))
}

/// The digest a row's hash check compares: v1 sha256 or v2 composite
async fn read_digest(row: &HashRow, key: &KeyRef) -> Result<String, ReadFailure> {
    match row.format_version {
        None => read_v1_digest(&row.bucket_id, &row.path, &row.iv, key).await,
        Some(2) => read_v2_digest(&row.bucket_id, &row.path, &row.iv, row.size, key).await,
        Some(_) => Err(ReadFailure::Layout("unknown format_version")),
    }
}

// ---------------------------------------------------------------------------
// Mongo helpers
// ---------------------------------------------------------------------------

async fn count_docs(mongo: &MongoDb, collection: &str, filter: Document) -> Result<u64, String> {
    mongo
        .col::<Document>(collection)
        .count_documents(filter)
        .await
        .map_err(|error| format!("count {collection}: {error}"))
}

/// Every string value of `field` over the rows matching `filter`
async fn string_field_set(
    mongo: &MongoDb,
    collection: &str,
    filter: Document,
    field: &str,
) -> Result<HashSet<String>, String> {
    let mut projection = Document::new();
    projection.insert(field, 1_i32);
    let mut cursor = mongo
        .col::<Document>(collection)
        .find(filter)
        .projection(projection)
        .await
        .map_err(|error| format!("read {collection}: {error}"))?;

    let mut values = HashSet::new();
    while cursor
        .advance()
        .await
        .map_err(|error| format!("read {collection}: {error}"))?
    {
        let row = cursor
            .deserialize_current()
            .map_err(|error| format!("decode {collection}: {error}"))?;
        if let Ok(value) = row.get_str(field) {
            values.insert(value.to_string());
        }
    }
    Ok(values)
}

async fn fetch_hash_row(mongo: &MongoDb, id: &str) -> Result<Option<HashRow>, String> {
    match mongo
        .col::<Document>(HASHES)
        .find_one(doc! { "_id": id })
        .await
    {
        Ok(Some(row)) => HashRow::from_doc(&row).map(Some),
        Ok(None) => Ok(None),
        Err(error) => Err(format!("read {HASHES}: {error}")),
    }
}

/// Whether the row still holds exactly the storage triple it was read with
async fn row_unchanged(mongo: &MongoDb, row: &HashRow) -> Result<bool, String> {
    Ok(match fetch_hash_row(mongo, &row.id).await? {
        Some(current) => {
            current.path == row.path && current.iv == row.iv && current.key_id == row.key_id
        }
        None => false,
    })
}

/// Journal entries matching `filter`, oldest id first; never the lease
async fn load_journal(mongo: &MongoDb, filter: Document) -> Result<Vec<JournalEntry>, String> {
    let mut filter = filter;
    filter.insert("_id", doc! { "$ne": LEASE_ID });
    let mut cursor = mongo
        .col::<Document>(JOURNAL)
        .find(filter)
        .sort(doc! { "_id": 1_i32 })
        .await
        .map_err(|error| format!("read {JOURNAL}: {error}"))?;

    let mut entries = Vec::new();
    while cursor
        .advance()
        .await
        .map_err(|error| format!("read {JOURNAL}: {error}"))?
    {
        let entry = cursor
            .deserialize_current()
            .map_err(|error| format!("decode {JOURNAL}: {error}"))?;
        entries.push(JournalEntry::from_doc(&entry)?);
    }
    Ok(entries)
}

/// One claim of one row: `new_path` is a fresh ULID per claim, so a write
/// pinned to it can never touch a later claim of the same row
fn claim_filter(id: &str, new_path: &str, status: &str) -> Document {
    doc! { "_id": id, "new_path": new_path, "status": status }
}

/// Move one journal entry on, but only from the claim and status the caller
/// expects. Returns whether it matched.
async fn journal_move(
    mongo: &MongoDb,
    id: &str,
    new_path: &str,
    from_status: &str,
    set: Document,
) -> Result<bool, String> {
    let mut set = set;
    set.insert("updated_at", DateTime::now());
    mongo
        .col::<Document>(JOURNAL)
        .update_one(
            claim_filter(id, new_path, from_status),
            doc! { "$set": set },
        )
        .await
        .map(|result| result.matched_count == 1)
        .map_err(|error| format!("update {JOURNAL}: {error}"))
}

/// Whether a journal entry, as just re-read, is still exactly one claim: the
/// expected status and `new_path`, and not purged. The lease is not a fence:
/// after a lease overlap another run's resume may have dropped this claim and
/// deleted its new object, so a swap must follow only a positive re-read.
fn claim_is_current(entry: Option<&Document>, status: &str, new_path: &str) -> bool {
    let Some(entry) = entry else {
        return false;
    };
    matches!(entry.get_str("status"), Ok(current) if current == status)
        && matches!(entry.get_str("new_path"), Ok(current) if current == new_path)
        && matches!(entry.get("purged_at"), None | Some(Bson::Null))
}

/// Re-read one journal entry right before a swap (see `claim_is_current`)
async fn claim_still_current(
    mongo: &MongoDb,
    id: &str,
    status: &str,
    new_path: &str,
) -> Result<bool, String> {
    let entry = mongo
        .col::<Document>(JOURNAL)
        .find_one(doc! { "_id": id })
        .await
        .map_err(|error| format!("read {JOURNAL}: {error}"))?;
    Ok(claim_is_current(entry.as_ref(), status, new_path))
}

/// Resume settles a pending entry only once nothing has written it for two
/// lease lifetimes; an undated entry is never settled automatically
fn pending_entry_settleable(updated_at_ms: Option<i64>, now_ms: i64) -> bool {
    updated_at_ms.is_some_and(|updated_at| now_ms.saturating_sub(updated_at) > RESUME_MIN_AGE_MS)
}

fn is_duplicate_key(error: &MongoError) -> bool {
    matches!(
        &*error.kind,
        ErrorKind::Write(WriteFailure::WriteError(write)) if write.code == 11000
    ) || error.to_string().contains("E11000")
}

/// Delete an object only if no `attachment_hashes` row references it, counted
/// right before the delete [A2]. Returns whether it was deleted.
async fn delete_if_unreferenced(
    mongo: &MongoDb,
    bucket_id: &str,
    path: &str,
) -> Result<bool, String> {
    let references =
        count_docs(mongo, HASHES, doc! { "bucket_id": bucket_id, "path": path }).await?;
    if references > 0 {
        return Ok(false);
    }
    delete_from_s3(bucket_id, path)
        .await
        .map_err(|_| format!("could not delete {}", display_key(path)))?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Lease
// ---------------------------------------------------------------------------

/// The `__lease__` claim of one mutating run
struct Lease {
    mongo: MongoDb,
    holder: String,
    /// Expiry (ms) of the last successful take or renewal
    valid_until_ms: AtomicI64,
    /// Set when a renewal found another holder
    lost: AtomicBool,
}

impl Lease {
    /// Whether this run may still mutate anything
    fn held(&self) -> bool {
        !self.lost.load(Ordering::SeqCst)
            && now_ms() + LEASE_SAFETY_MS < self.valid_until_ms.load(Ordering::SeqCst)
    }
}

struct HeldLease {
    lease: Arc<Lease>,
    renewal: tokio::task::JoinHandle<()>,
}

impl HeldLease {
    async fn release(self) {
        self.renewal.abort();
        match self
            .lease
            .mongo
            .col::<Document>(JOURNAL)
            .delete_one(lease_holder_filter(&self.lease.holder))
            .await
        {
            Ok(_) => println!("lease: released"),
            Err(error) => eprintln!(
                "WARN: could not release the lease ({error}); it expires on its own within \
                 5 minutes"
            ),
        }
    }
}

/// `hostname:pid`
fn lease_holder() -> String {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|host| host.trim().to_string())
        .filter(|host| !host.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown-host".to_string());
    format!("{host}:{}", std::process::id())
}

/// Matches the lease document only once it has expired; with upsert, a
/// missing document is created, and a live one makes the insert collide
/// (duplicate `_id`), so taking the lease is one atomic step
fn lease_acquire_filter(now: i64) -> Document {
    doc! { "_id": LEASE_ID, "expires_at": { "$lt": DateTime::from_millis(now) } }
}

fn lease_take_update(holder: &str, subcommand: &str, expires_ms: i64) -> Document {
    doc! {
        "$set": {
            "holder": holder,
            "subcommand": subcommand,
            "expires_at": DateTime::from_millis(expires_ms),
        }
    }
}

fn lease_holder_filter(holder: &str) -> Document {
    doc! { "_id": LEASE_ID, "holder": holder }
}

async fn describe_lease(mongo: &MongoDb) -> String {
    match mongo
        .col::<Document>(JOURNAL)
        .find_one(doc! { "_id": LEASE_ID })
        .await
    {
        Ok(None) => "no lease".to_string(),
        Ok(Some(lease)) => {
            let holder = lease.get_str("holder").unwrap_or("?");
            let subcommand = lease.get_str("subcommand").unwrap_or("?");
            match lease.get_datetime("expires_at") {
                Ok(expires) => {
                    let state = if expires.timestamp_millis() > now_ms() {
                        "LIVE"
                    } else {
                        "expired"
                    };
                    let at = expires
                        .try_to_rfc3339_string()
                        .unwrap_or_else(|_| expires.timestamp_millis().to_string());
                    format!("held by {holder} ({subcommand}), {state}, expires {at}")
                }
                Err(_) => format!("held by {holder} ({subcommand}), no valid expiry"),
            }
        }
        Err(error) => format!("lease unreadable ({error})"),
    }
}

async fn acquire_lease(mongo: &MongoDb, subcommand: &str) -> Result<Arc<Lease>, String> {
    let holder = lease_holder();
    let now = now_ms();
    let expires = now + LEASE_TTL_MS;
    let journal = mongo.col::<Document>(JOURNAL);

    if let Err(error) = journal
        .update_one(
            lease_acquire_filter(now),
            lease_take_update(&holder, subcommand, expires),
        )
        .upsert(true)
        .await
    {
        let current = describe_lease(mongo).await;
        return Err(if is_duplicate_key(&error) {
            format!("another run holds it: {current}")
        } else {
            format!("{error}; {current}")
        });
    }

    // Proceed only if the document now names this run
    match journal.find_one(doc! { "_id": LEASE_ID }).await {
        Ok(Some(lease)) if matches!(lease.get_str("holder"), Ok(name) if name == holder) => {}
        _ => {
            return Err(format!(
                "the lease does not name this run: {}",
                describe_lease(mongo).await
            ))
        }
    }

    Ok(Arc::new(Lease {
        mongo: mongo.clone(),
        holder,
        valid_until_ms: AtomicI64::new(expires),
        lost: AtomicBool::new(false),
    }))
}

/// Renew every minute for another 5; a renewal that finds another holder
/// marks the lease lost, and every mutation checks `held()` first
fn spawn_renewal(lease: Arc<Lease>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(LEASE_RENEW_EVERY).await;
            let expires = now_ms() + LEASE_TTL_MS;
            let renewed = lease
                .mongo
                .col::<Document>(JOURNAL)
                .update_one(
                    lease_holder_filter(&lease.holder),
                    doc! { "$set": { "expires_at": DateTime::from_millis(expires) } },
                )
                .await;
            match renewed {
                Ok(result) if result.matched_count == 1 => {
                    lease.valid_until_ms.store(expires, Ordering::SeqCst)
                }
                Ok(_) => {
                    lease.lost.store(true, Ordering::SeqCst);
                    eprintln!("LEASE LOST: another run took the lease; stopping all mutation");
                    return;
                }
                Err(error) => eprintln!("WARN: lease renewal failed ({error}); retrying"),
            }
        }
    })
}

/// Take the lease for a mutating subcommand, or refuse (exit 2)
async fn take_lease(mongo: &MongoDb, subcommand: &str) -> Result<HeldLease, i32> {
    match acquire_lease(mongo, subcommand).await {
        Ok(lease) => {
            println!("lease: taken by {} for {subcommand}", lease.holder);
            println!(
                "do not run heal_attachment_blob while this runs: it repoints rows without a \
                 compare-and-swap"
            );
            let renewal = spawn_renewal(lease.clone());
            Ok(HeldLease { lease, renewal })
        }
        Err(reason) => Err(refuse(&format!("could not take the lease: {reason}"))),
    }
}

// ---------------------------------------------------------------------------
// check-config: the autumn boot guard [A1] and known-answer probe [A9]
//
// needed_key_ids .. probe_file_key are duplicated verbatim from
// crates/services/autumn/src/main.rs (logging goes to stdout/stderr here)
// ---------------------------------------------------------------------------

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
            eprintln!(
                "WARN: file key probe: could not read file_key_migrations ({error}); \
                 probing without the quarantine exclusion"
            );
            return None;
        }
    };
    if count > MAX_QUARANTINE_EXCLUSION as u64 {
        eprintln!(
            "WARN: file key probe: {count} quarantined rows exceed {MAX_QUARANTINE_EXCLUSION}; \
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
                eprintln!(
                    "WARN: file key probe: {len} quarantined rows exceed \
                     {MAX_QUARANTINE_EXCLUSION}; probing without the quarantine exclusion"
                );
            }
            exclusion
        }
        Err(error) => {
            eprintln!(
                "WARN: file key probe: could not read file_key_migrations ({error}); \
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

    let Ok(plaintext) = fetch_from_s3(bucket_id, path, iv, key_id_option(id)).await else {
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

/// Read-only: the same guard and probe autumn runs at boot. Exit 1 on any
/// missing needed id or any probe FAIL, whatever `require_rotated_key` says,
/// and on an empty `attachment_hashes` (an empty database needs no key, so
/// every check would pass vacuously).
async fn check_config(mongo: &MongoDb, keyring: &FileKeyring, hash_total: u64) -> i32 {
    if let Some(reason) = empty_database_reason(hash_total) {
        eprintln!("FAIL: {reason}");
        return EXIT_FAILED;
    }

    let needed = match needed_key_ids(mongo).await {
        Ok(needed) => needed,
        Err(reason) => {
            eprintln!("FAIL: the file key guard could not read the database: {reason}");
            return EXIT_FAILED;
        }
    };
    let needed_list = needed
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    println!("file key guard: needed ids [{needed_list}]");

    let mut failed = false;
    let missing = missing_key_ids(&needed, keyring);
    if missing.is_empty() {
        println!("file key guard: every needed id is in the keyring");
    } else {
        eprintln!(
            "FAIL: stored files need file key ids missing from the keyring: {missing:?} \
             (autumn would refuse to start)"
        );
        failed = true;
    }

    let exclude = if needed.is_empty() {
        None
    } else {
        quarantined_hash_ids(mongo).await
    };

    let mut probe_failed = Vec::new();
    for id in &needed {
        if missing.contains(id) {
            println!("file key probe not run for {id} (missing from the keyring)");
            continue;
        }
        let fingerprint = keyring
            .fingerprint(key_id_option(id))
            .unwrap_or_else(|_| "unknown".to_string());
        match probe_file_key(mongo, id, exclude.as_deref()).await {
            ProbeOutcome::Pass { hash_prefix } => println!(
                "file key probe PASS for {id} (fingerprint={fingerprint}, hash {hash_prefix})"
            ),
            ProbeOutcome::Skipped => {
                println!("file key probe SKIPPED for {id} (no v1 row) (fingerprint={fingerprint})")
            }
            ProbeOutcome::Fail { attempts } => {
                let detail = attempts
                    .iter()
                    .map(|(hash_prefix, reason)| format!("hash {hash_prefix}: {reason}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                eprintln!(
                    "file key probe FAIL for {id} (fingerprint={fingerprint}): \
                     all {} candidates failed ({detail})",
                    attempts.len()
                );
                probe_failed.push(id.as_str());
            }
        }
    }

    if !probe_failed.is_empty() {
        failed = true;
        let require = revolt_config::config().await.files.require_rotated_key;
        eprintln!(
            "FAIL: file key probe failed for {}; autumn would {} \
             (files.require_rotated_key = {require})",
            probe_failed.join(", "),
            if require {
                "refuse to start"
            } else {
                "log an ERROR and keep serving"
            }
        );
    }

    if failed {
        EXIT_FAILED
    } else {
        println!("check-config: OK");
        EXIT_OK
    }
}

// ---------------------------------------------------------------------------
// plan (read-only)
// ---------------------------------------------------------------------------

/// Print one count; a failed query marks the plan incomplete
fn show(ok: &mut bool, label: &str, result: Result<u64, String>) -> u64 {
    match result {
        Ok(count) => {
            println!("  {label}: {count}");
            count
        }
        Err(error) => {
            eprintln!("  {label}: unavailable ({error})");
            *ok = false;
            0
        }
    }
}

/// Count per named key id over the rows matching `base`
async fn named_counts(
    mongo: &MongoDb,
    collection: &str,
    base: Document,
) -> Result<Vec<(String, u64)>, String> {
    let mut filter = named_row_filter();
    for (key, value) in base.clone() {
        filter.insert(key, value);
    }
    let ids = mongo
        .col::<Document>(collection)
        .distinct("key_id", filter)
        .await
        .map_err(|error| format!("distinct key_id in {collection}: {error}"))?;

    let mut counts = Vec::new();
    for id in ids {
        let id = match id {
            Bson::String(id) => id,
            other => {
                return Err(format!(
                    "{collection} holds a key_id of type {:?}",
                    other.element_type()
                ))
            }
        };
        let mut filter = base.clone();
        filter.insert("key_id", id.as_str());
        counts.push((id, count_docs(mongo, collection, filter).await?));
    }
    counts.sort();
    Ok(counts)
}

async fn show_named(ok: &mut bool, mongo: &MongoDb, collection: &str, base: Document) {
    match named_counts(mongo, collection, base).await {
        Ok(counts) if counts.is_empty() => println!("  named key ids: none"),
        Ok(counts) => {
            for (id, count) in counts {
                println!("  key_id {id}: {count}");
            }
        }
        Err(error) => {
            eprintln!("  named key ids: unavailable ({error})");
            *ok = false;
        }
    }
}

/// The largest numeric `size` over the rows matching `filter`
async fn max_size(
    mongo: &MongoDb,
    collection: &str,
    filter: Document,
) -> Result<Option<i64>, String> {
    let mut cursor = mongo
        .col::<Document>(collection)
        .find(filter)
        .sort(doc! { "size": -1_i32 })
        .projection(doc! { "size": 1_i32 })
        .limit(1)
        .await
        .map_err(|error| format!("read {collection}: {error}"))?;
    if !cursor
        .advance()
        .await
        .map_err(|error| format!("read {collection}: {error}"))?
    {
        return Ok(None);
    }
    let row = cursor
        .deserialize_current()
        .map_err(|error| format!("decode {collection}: {error}"))?;
    Ok(bson_i64(row.get("size")))
}

/// Run an aggregation whose output rows are `{_id, count}`
async fn grouped_counts(
    mongo: &MongoDb,
    collection: &str,
    pipeline: Vec<Document>,
) -> Result<Vec<(Bson, u64)>, String> {
    let mut cursor = mongo
        .col::<Document>(collection)
        .aggregate(pipeline)
        .await
        .map_err(|error| format!("aggregate {collection}: {error}"))?;

    let mut groups = Vec::new();
    while cursor
        .advance()
        .await
        .map_err(|error| format!("aggregate {collection}: {error}"))?
    {
        let group = cursor
            .deserialize_current()
            .map_err(|error| format!("decode {collection}: {error}"))?;
        let count = bson_i64(group.get("count")).unwrap_or(0).max(0) as u64;
        groups.push((group.get("_id").cloned().unwrap_or(Bson::Null), count));
    }
    Ok(groups)
}

/// Rows by where their object lives: at the hash id, `chunked/`, `rk/<id>/`, other
fn path_class_pipeline() -> Vec<Document> {
    vec![
        doc! {
            "$project": {
                "class": {
                    "$switch": {
                        "branches": [
                            { "case": { "$eq": ["$path", "$_id"] }, "then": "== _id" },
                            {
                                "case": { "$eq": [{ "$substrCP": ["$path", 0_i32, 8_i32] }, "chunked/"] },
                                "then": "chunked/",
                            },
                            {
                                "case": { "$eq": [{ "$substrCP": ["$path", 0_i32, 3_i32] }, "rk/"] },
                                "then": {
                                    "$concat": [
                                        "rk/",
                                        { "$arrayElemAt": [{ "$split": ["$path", "/"] }, 1_i32] },
                                        "/",
                                    ]
                                },
                            },
                        ],
                        "default": "other",
                    }
                }
            }
        },
        doc! { "$group": { "_id": "$class", "count": { "$sum": 1_i32 } } },
        doc! { "$sort": { "_id": 1_i32 } },
    ]
}

/// Journal entries by (status, reason); the lease is not an entry
fn journal_status_pipeline() -> Vec<Document> {
    vec![
        doc! { "$match": { "_id": { "$ne": LEASE_ID } } },
        doc! {
            "$group": {
                "_id": { "status": "$status", "reason": "$reason" },
                "count": { "$sum": 1_i32 },
            }
        },
        doc! { "$sort": { "_id.status": 1_i32, "_id.reason": 1_i32 } },
    ]
}

/// Read-only counts for the C0/C5/C8 gates
async fn plan(mongo: &MongoDb) -> i32 {
    let mut ok = true;

    println!("attachment_hashes:");
    show(&mut ok, "total", count_docs(mongo, HASHES, doc! {}).await);
    let legacy_hashes = show(
        &mut ok,
        "legacy rows {key_id: null, iv != \"\"}",
        count_docs(mongo, HASHES, legacy_row_filter()).await,
    );
    let mut legacy_v2 = legacy_row_filter();
    legacy_v2.insert("format_version", 2_i32);
    show(
        &mut ok,
        "  of which v2 (format_version 2)",
        count_docs(mongo, HASHES, legacy_v2).await,
    );
    show(
        &mut ok,
        "placeholders {iv: \"\"}",
        count_docs(mongo, HASHES, doc! { "iv": "" }).await,
    );
    show_named(&mut ok, mongo, HASHES, doc! {}).await;
    show(
        &mut ok,
        "format_version none",
        count_docs(mongo, HASHES, doc! { "format_version": Bson::Null }).await,
    );
    show(
        &mut ok,
        "format_version 2",
        count_docs(mongo, HASHES, doc! { "format_version": 2_i32 }).await,
    );
    show(
        &mut ok,
        "format_version other",
        count_docs(
            mongo,
            HASHES,
            doc! { "format_version": { "$nin": [Bson::Null, 2_i32] } },
        )
        .await,
    );
    match grouped_counts(mongo, HASHES, path_class_pipeline()).await {
        Ok(groups) => {
            for (class, count) in groups {
                let class = match class {
                    Bson::String(class) => class,
                    other => format!("{other}"),
                };
                println!("  path {class}: {count}");
            }
        }
        Err(error) => {
            eprintln!("  path classes: unavailable ({error})");
            ok = false;
        }
    }

    // migrate holds a v1 object whole in memory, several copies at once
    let mut legacy_v1 = legacy_row_filter();
    legacy_v1.insert("format_version", Bson::Null);
    match max_size(mongo, HASHES, legacy_v1.clone()).await {
        Ok(Some(size)) => println!(
            "  largest legacy v1 size: {size} bytes ({} MiB)",
            size / (1024 * 1024)
        ),
        Ok(None) => println!("  largest legacy v1 size: none"),
        Err(error) => {
            eprintln!("  largest legacy v1 size: unavailable ({error})");
            ok = false;
        }
    }
    let mut large_v1 = legacy_v1.clone();
    large_v1.insert("size", doc! { "$gt": LARGE_V1_BYTES });
    show(
        &mut ok,
        "legacy v1 rows over 256 MiB (migrate runs each alone)",
        count_docs(mongo, HASHES, large_v1).await,
    );
    let mut unsized_v1 = legacy_v1;
    unsized_v1.insert("size", Bson::Null);
    show(
        &mut ok,
        "legacy v1 rows with no size (migrate runs each alone)",
        count_docs(mongo, HASHES, unsized_v1).await,
    );

    println!("e2ee_blobs:");
    let legacy_blobs = show(
        &mut ok,
        "legacy {key_id: null, iv != \"\"}",
        count_docs(mongo, BLOBS, legacy_row_filter()).await,
    );
    show(
        &mut ok,
        "placeholders {iv: \"\"}",
        count_docs(mongo, BLOBS, doc! { "iv": "" }).await,
    );
    show_named(&mut ok, mongo, BLOBS, doc! {}).await;

    println!("upload_sessions (Pending/Completing):");
    let mut legacy_sessions_filter = live_session_filter();
    legacy_sessions_filter.insert("key_id", Bson::Null);
    let legacy_sessions = show(
        &mut ok,
        "legacy {key_id: null}",
        count_docs(mongo, SESSIONS, legacy_sessions_filter).await,
    );
    show_named(&mut ok, mongo, SESSIONS, live_session_filter()).await;

    println!(
        "rows that still need the legacy key: hashes {legacy_hashes}, blobs {legacy_blobs}, \
         live sessions {legacy_sessions}"
    );

    println!("file_key_migrations:");
    match grouped_counts(mongo, JOURNAL, journal_status_pipeline()).await {
        Ok(groups) if groups.is_empty() => println!("  no entries"),
        Ok(groups) => {
            for (group, count) in groups {
                let (status, reason) = match &group {
                    Bson::Document(group) => (
                        group.get_str("status").unwrap_or("(no status)").to_string(),
                        group.get_str("reason").ok().map(str::to_string),
                    ),
                    other => (format!("{other}"), None),
                };
                match reason {
                    Some(reason) => println!("  {status} ({reason}): {count}"),
                    None => println!("  {status}: {count}"),
                }
            }
        }
        Err(error) => {
            eprintln!("  journal counts: unavailable ({error})");
            ok = false;
        }
    }
    show(
        &mut ok,
        "quarantine fetch-failed (retried by the next migrate)",
        count_docs(mongo, JOURNAL, retryable_quarantine_filter(false)).await,
    );
    show(
        &mut ok,
        "quarantine hash-mismatch (retried only by migrate --accept-hash-mismatch)",
        count_docs(
            mongo,
            JOURNAL,
            doc! { "status": STATUS_QUARANTINE, "reason": REASON_HASH_MISMATCH },
        )
        .await,
    );
    show(
        &mut ok,
        "quarantine settled (decrypt-failed, v2-layout or no reason; never retried)",
        count_docs(mongo, JOURNAL, settled_quarantine_filter(true)).await,
    );
    println!("  lease: {}", describe_lease(mongo).await);

    println!("DA11 orphan candidates (what purge-old would sweep):");
    match scan_all_buckets(mongo).await {
        Ok(scans) => {
            for scan in &scans {
                print_scan(scan, false);
            }
        }
        Err(error) => {
            eprintln!("  orphan scan: unavailable ({error})");
            ok = false;
        }
    }

    if ok {
        EXIT_OK
    } else {
        EXIT_FAILED
    }
}

// ---------------------------------------------------------------------------
// Orphan predicate (DA11) shared by plan, verify and purge-old
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum OrphanClass {
    Rk,
    Chunked,
    Other,
}

impl OrphanClass {
    fn label(self) -> &'static str {
        match self {
            OrphanClass::Rk => "rk/",
            OrphanClass::Chunked => "chunked/",
            OrphanClass::Other => "other (hash-id or unknown)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum KeepReason {
    Referenced,
    E2eeBlob,
    UploadSession,
    PendingNewPath,
    UnpurgedOldPath,
    TooYoung,
    UnknownAge,
}

impl KeepReason {
    fn label(self) -> &'static str {
        match self {
            KeepReason::Referenced => "referenced by attachment_hashes",
            KeepReason::E2eeBlob => "e2ee blob",
            KeepReason::UploadSession => "path of an upload session",
            KeepReason::PendingNewPath => "new path of a pending migration",
            KeepReason::UnpurgedOldPath => "old path of an unpurged migration",
            KeepReason::TooYoung => "younger than the orphan minimum age",
            KeepReason::UnknownAge => "no last-modified time",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum OrphanVerdict {
    Delete(OrphanClass),
    Keep(KeepReason),
}

/// What a sweep must never delete, for one bucket
#[derive(Default)]
struct OrphanExclusions {
    /// `path` of every `attachment_hashes` row in this bucket
    referenced: HashSet<String>,
    /// `path` of every `upload_sessions` row, in any state (w2 pin 6)
    session_paths: HashSet<String>,
    /// `new_path` of every pending journal entry
    pending_new_paths: HashSet<String>,
    /// `old_path` of every migrated entry not yet purged: step 1 of purge-old
    /// owns it, and rollback needs it while `purged_at` is unset
    unpurged_old_paths: HashSet<String>,
}

fn orphan_class(key: &str) -> OrphanClass {
    if key.starts_with("rk/") {
        OrphanClass::Rk
    } else if key.starts_with("chunked/") {
        OrphanClass::Chunked
    } else {
        OrphanClass::Other
    }
}

/// A listed key is deletable iff no row references it, it is not an e2ee
/// blob, not exactly an upload session's path, not a pending migration's new
/// path, not an unpurged migration's old path, and it is older than
/// `min_age_secs` (24 h, unless the scratch override is in force)
fn orphan_verdict(
    key: &str,
    last_modified_unix: Option<i64>,
    now_unix: i64,
    min_age_secs: i64,
    exclusions: &OrphanExclusions,
) -> OrphanVerdict {
    if exclusions.referenced.contains(key) {
        return OrphanVerdict::Keep(KeepReason::Referenced);
    }
    if key.starts_with(E2EE_PREFIX) {
        return OrphanVerdict::Keep(KeepReason::E2eeBlob);
    }
    if exclusions.session_paths.contains(key) {
        return OrphanVerdict::Keep(KeepReason::UploadSession);
    }
    if exclusions.pending_new_paths.contains(key) {
        return OrphanVerdict::Keep(KeepReason::PendingNewPath);
    }
    if exclusions.unpurged_old_paths.contains(key) {
        return OrphanVerdict::Keep(KeepReason::UnpurgedOldPath);
    }
    match last_modified_unix {
        None => OrphanVerdict::Keep(KeepReason::UnknownAge),
        Some(modified) if now_unix.saturating_sub(modified) <= min_age_secs => {
            OrphanVerdict::Keep(KeepReason::TooYoung)
        }
        Some(_) => OrphanVerdict::Delete(orphan_class(key)),
    }
}

/// The orphan age guard in force for one sweep
#[derive(Debug, PartialEq, Eq)]
enum OrphanMinAge {
    /// 24 h
    Default,
    /// `REKEY_FILES_SCRATCH_ORPHAN_MIN_AGE_SECS`, every bucket a scratch bucket
    ScratchOverride(i64),
}

impl OrphanMinAge {
    fn secs(&self) -> i64 {
        match self {
            OrphanMinAge::Default => ORPHAN_MIN_AGE_SECS,
            OrphanMinAge::ScratchOverride(secs) => *secs,
        }
    }
}

/// The age guard for a sweep over `buckets`, given the override's value.
/// The override exists so the scratch end-to-end can reach a sweep delete
/// (MinIO cannot backdate an object); it is honored only when EVERY bucket
/// the sweep covers is a `rekey-e2e-` bucket, so it can never shorten the
/// guard on a production bucket. Anything else with it set is an error.
fn resolve_orphan_min_age(
    override_value: Option<&str>,
    buckets: &[String],
) -> Result<OrphanMinAge, String> {
    let Some(value) = override_value else {
        return Ok(OrphanMinAge::Default);
    };
    let secs = value
        .parse::<u64>()
        .ok()
        .and_then(|secs| i64::try_from(secs).ok())
        .ok_or_else(|| format!("{SCRATCH_AGE_ENV} must be a non-negative whole number"))?;
    if buckets.is_empty() {
        return Err(format!(
            "{SCRATCH_AGE_ENV} is set, but there are no buckets to prove scratch"
        ));
    }
    if let Some(bucket) = buckets
        .iter()
        .find(|bucket| !bucket.starts_with(SCRATCH_BUCKET_PREFIX))
    {
        return Err(format!(
            "{SCRATCH_AGE_ENV} is set, but bucket {bucket} is not a scratch bucket \
             ({SCRATCH_BUCKET_PREFIX}*); it is for scratch end-to-end runs only"
        ));
    }
    Ok(OrphanMinAge::ScratchOverride(secs))
}

/// The override's raw value: None when unset
fn scratch_age_override() -> Result<Option<String>, String> {
    match std::env::var(SCRATCH_AGE_ENV) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{SCRATCH_AGE_ENV} is not valid UTF-8"))
        }
    }
}

/// One bucket's sweep candidates
struct BucketScan {
    bucket: String,
    listed: usize,
    deletable: Vec<(String, OrphanClass)>,
    kept: BTreeMap<KeepReason, u64>,
}

impl BucketScan {
    fn deletable_by_class(&self) -> BTreeMap<OrphanClass, u64> {
        let mut counts = BTreeMap::new();
        for (_, class) in &self.deletable {
            *counts.entry(*class).or_insert(0) += 1;
        }
        counts
    }
}

/// The configured default bucket plus every bucket a hash row names
async fn sweep_buckets(mongo: &MongoDb) -> Result<Vec<String>, String> {
    let mut buckets = BTreeSet::new();
    buckets.insert(revolt_config::config().await.files.s3.default_bucket);

    let values = mongo
        .col::<Document>(HASHES)
        .distinct("bucket_id", doc! {})
        .await
        .map_err(|error| format!("distinct bucket_id in {HASHES}: {error}"))?;
    for value in values {
        match value {
            Bson::String(bucket) => {
                buckets.insert(bucket);
            }
            other => eprintln!(
                "WARN: {HASHES} holds a bucket_id of type {:?}; not swept",
                other.element_type()
            ),
        }
    }
    Ok(buckets.into_iter().collect())
}

async fn load_exclusions(mongo: &MongoDb, bucket: &str) -> Result<OrphanExclusions, String> {
    Ok(OrphanExclusions {
        referenced: string_field_set(mongo, HASHES, doc! { "bucket_id": bucket }, "path").await?,
        session_paths: string_field_set(mongo, SESSIONS, doc! {}, "path").await?,
        pending_new_paths: string_field_set(
            mongo,
            JOURNAL,
            doc! { "status": STATUS_PENDING },
            "new_path",
        )
        .await?,
        unpurged_old_paths: string_field_set(
            mongo,
            JOURNAL,
            unpurged_migrated_filter(),
            "old_path",
        )
        .await?,
    })
}

/// The exclusions are read before the listing, so an object written after
/// them is at most minutes old and the 24 h age guard keeps it
async fn scan_bucket(
    mongo: &MongoDb,
    bucket: &str,
    now_unix: i64,
    min_age_secs: i64,
) -> Result<BucketScan, String> {
    let exclusions = load_exclusions(mongo, bucket).await?;
    let objects = list_objects_in_s3(bucket, None)
        .await
        .map_err(|_| format!("could not list bucket {bucket}"))?;

    let mut scan = BucketScan {
        bucket: bucket.to_string(),
        listed: objects.len(),
        deletable: Vec::new(),
        kept: BTreeMap::new(),
    };
    for object in &objects {
        match orphan_verdict(
            &object.key,
            object.last_modified_unix,
            now_unix,
            min_age_secs,
            &exclusions,
        ) {
            OrphanVerdict::Delete(class) => scan.deletable.push((object.key.clone(), class)),
            OrphanVerdict::Keep(reason) => *scan.kept.entry(reason).or_insert(0) += 1,
        }
    }
    scan.deletable
        .sort_by(|(a_key, a_class), (b_key, b_class)| (a_class, a_key).cmp(&(b_class, b_key)));
    Ok(scan)
}

async fn scan_all_buckets(mongo: &MongoDb) -> Result<Vec<BucketScan>, String> {
    let now_unix = now_ms() / 1000;
    let buckets = sweep_buckets(mongo).await?;
    // Re-checked against the buckets this scan really covers
    let min_age = resolve_orphan_min_age(scratch_age_override()?.as_deref(), &buckets)?;
    if let OrphanMinAge::ScratchOverride(secs) = min_age {
        eprintln!(
            "!!! SCRATCH OVERRIDE ACTIVE: {SCRATCH_AGE_ENV}={secs}; orphans older than {secs} s \
             (not 24 h) are sweep candidates in scratch buckets [{}] !!!",
            buckets.join(", ")
        );
    }
    let mut scans = Vec::new();
    for bucket in &buckets {
        scans.push(scan_bucket(mongo, bucket, now_unix, min_age.secs()).await?);
    }
    Ok(scans)
}

fn print_scan(scan: &BucketScan, examples: bool) {
    println!("  bucket {}: {} objects listed", scan.bucket, scan.listed);
    let by_class = scan.deletable_by_class();
    for class in [OrphanClass::Rk, OrphanClass::Chunked, OrphanClass::Other] {
        println!(
            "    orphan candidates {}: {}",
            class.label(),
            by_class.get(&class).copied().unwrap_or(0)
        );
    }
    for (reason, count) in &scan.kept {
        println!("    kept ({}): {count}", reason.label());
    }
    if examples {
        for (key, class) in scan.deletable.iter().take(EXAMPLE_KEYS) {
            println!("    example {}: {}", class.label(), display_key(key));
        }
    }
}

/// Re-check every exclusion that can change, right before a sweep delete
async fn orphan_still_deletable(mongo: &MongoDb, bucket: &str, key: &str) -> Result<bool, String> {
    let rows = count_docs(mongo, HASHES, doc! { "bucket_id": bucket, "path": key }).await?;
    let sessions = count_docs(mongo, SESSIONS, doc! { "path": key }).await?;
    let pending = count_docs(
        mongo,
        JOURNAL,
        doc! { "status": STATUS_PENDING, "new_path": key },
    )
    .await?;
    let mut unpurged = unpurged_migrated_filter();
    unpurged.insert("old_path", key);
    let unpurged = count_docs(mongo, JOURNAL, unpurged).await?;
    Ok(rows == 0 && sessions == 0 && pending == 0 && unpurged == 0)
}

// ---------------------------------------------------------------------------
// migrate
// ---------------------------------------------------------------------------

struct MigrateCtx {
    db: Database,
    mongo: MongoDb,
    keyring: Arc<FileKeyring>,
    /// The primary key id; every new object and row uses it
    primary: String,
    accept_hash_mismatch: bool,
    lease: Arc<Lease>,
}

/// How one row ended
enum RowOutcome {
    Migrated {
        hash_mismatch: bool,
        /// The row moved but its journal entry is still `pending`
        journal_stale: bool,
    },
    Quarantined(&'static str),
    LostRace,
    Skipped,
    Error,
}

/// Why a row's migration stopped short of the swap
enum Stop {
    /// Reading the legacy object failed or its bytes did not match (steps
    /// 2-3): re-read the row, then quarantine or lost-race
    Source(&'static str),
    /// Writing or reading back the new object failed: delete our new object
    /// and drop the claim, so the next run retries the row
    Write(String),
    /// The outcome is uncertain (lease lost, DB error): leave the entry
    /// `pending` for the next run's resume
    LeavePending(String),
}

/// A verified new object, ready to swap in
struct Prepared {
    new_iv: String,
    hash_mismatch: bool,
}

#[derive(Default)]
struct MigrateTally {
    migrated: u64,
    hash_mismatch_accepted: u64,
    journal_stale: u64,
    quarantined: BTreeMap<&'static str, u64>,
    lost_race: u64,
    skipped: u64,
    errors: u64,
}

impl MigrateTally {
    fn record(&mut self, joined: Result<RowOutcome, JoinError>) {
        match joined {
            Ok(RowOutcome::Migrated {
                hash_mismatch,
                journal_stale,
            }) => {
                self.migrated += 1;
                self.hash_mismatch_accepted += u64::from(hash_mismatch);
                self.journal_stale += u64::from(journal_stale);
                if self.migrated % 100 == 0 {
                    println!("progress: {} migrated", self.migrated);
                }
            }
            Ok(RowOutcome::Quarantined(reason)) => {
                *self.quarantined.entry(reason).or_insert(0) += 1
            }
            Ok(RowOutcome::LostRace) => self.lost_race += 1,
            Ok(RowOutcome::Skipped) => self.skipped += 1,
            Ok(RowOutcome::Error) => self.errors += 1,
            Err(_) => {
                eprintln!("a row task panicked; its journal entry stays pending for the next run");
                self.errors += 1;
            }
        }
    }

    fn quarantined_total(&self) -> u64 {
        self.quarantined.values().sum()
    }

    fn print(&self) {
        println!("migrated: {}", self.migrated);
        println!(
            "  of which with an accepted hash mismatch: {}",
            self.hash_mismatch_accepted
        );
        println!(
            "  of which with a stale journal entry: {}",
            self.journal_stale
        );
        println!("quarantined this run: {}", self.quarantined_total());
        for (reason, count) in &self.quarantined {
            println!("  {reason}: {count}");
        }
        println!("lost-race: {}", self.lost_race);
        println!("skipped (already settled or journaled): {}", self.skipped);
        println!("errors (left for the next run): {}", self.errors);
    }

    /// No lost race, error or stale journal entry in this run. Quarantines
    /// are judged over the whole journal (`migrate_exit_code`), not here.
    fn run_clean(&self) -> bool {
        self.lost_race == 0 && self.errors == 0 && self.journal_stale == 0
    }
}

/// migrate's exit code. Every quarantine in the journal counts, from any
/// run, so a re-run cannot report success while rows are still quarantined;
/// an unreadable count (None) fails closed.
fn migrate_exit_code(outstanding_quarantine: Option<u64>, run_clean: bool) -> i32 {
    match outstanding_quarantine {
        Some(0) if run_clean => EXIT_OK,
        _ => EXIT_FAILED,
    }
}

/// Legacy rows a later migrate would still select: not covered by a settled
/// journal entry
fn selectable_count(legacy_ids: &HashSet<String>, settled_ids: &HashSet<String>) -> u64 {
    legacy_ids.difference(settled_ids).count() as u64
}

/// Journal quarantines by reason, over the whole journal
fn quarantine_by_reason_pipeline() -> Vec<Document> {
    vec![
        doc! { "$match": { "_id": { "$ne": LEASE_ID }, "status": STATUS_QUARANTINE } },
        doc! { "$group": { "_id": "$reason", "count": { "$sum": 1_i32 } } },
        doc! { "$sort": { "_id": 1_i32 } },
    ]
}

/// Print what is still outstanding after a migrate run, over the whole
/// journal; returns the total quarantine count, None if it could not be read
async fn print_outstanding(mongo: &MongoDb, accept_hash_mismatch: bool) -> Option<u64> {
    println!("outstanding (whole journal, every run):");
    let quarantine = match grouped_counts(mongo, JOURNAL, quarantine_by_reason_pipeline()).await {
        Ok(groups) => {
            let total: u64 = groups.iter().map(|(_, count)| count).sum();
            println!("  quarantine: {total}");
            for (reason, count) in groups {
                let reason = match reason {
                    Bson::String(reason) => reason,
                    Bson::Null => "(no reason)".to_string(),
                    other => format!("{other}"),
                };
                let retry = if quarantine_retryable(Some(reason.as_str()), false) {
                    "retried by the next migrate"
                } else if quarantine_retryable(Some(reason.as_str()), true) {
                    "retried only by migrate --accept-hash-mismatch"
                } else {
                    "settled; never retried"
                };
                println!("    {reason}: {count} ({retry})");
            }
            Some(total)
        }
        Err(error) => {
            eprintln!("  quarantine: unavailable ({error})");
            None
        }
    };

    let legacy = string_field_set(mongo, HASHES, legacy_row_filter(), "_id").await;
    let settled =
        string_field_set(mongo, JOURNAL, settled_filter(accept_hash_mismatch), "_id").await;
    match (legacy, settled) {
        (Ok(legacy), Ok(settled)) => println!(
            "  legacy rows still selectable: {}",
            selectable_count(&legacy, &settled)
        ),
        (Err(error), _) | (_, Err(error)) => {
            eprintln!("  legacy rows still selectable: unavailable ({error})")
        }
    }
    quarantine
}

async fn migrate(
    db: &Database,
    mongo: &MongoDb,
    keyring: &Arc<FileKeyring>,
    args: MigrateArgs,
) -> i32 {
    // Preconditions: each is a refusal (exit 2)
    let Some(primary) = keyring.primary_id().map(str::to_string) else {
        return refuse("the primary file key is legacy; configure the new key first");
    };
    let fingerprint = match keyring.fingerprint(Some(primary.as_str())) {
        Ok(fingerprint) => fingerprint,
        Err(error) => return refuse(&format!("no fingerprint for the primary: {error:#}")),
    };
    if fingerprint == COMMITTED_DEFAULT_KEY_FP {
        return refuse("the primary file key is upstream's committed default");
    }
    if fingerprint != args.expect_new_key_pin {
        return refuse(&format!(
            "the primary {primary} has fingerprint {fingerprint}, not the expected {}",
            args.expect_new_key_pin
        ));
    }
    if !keyring.has(None) {
        return refuse("the keyring has no legacy key, so legacy objects cannot be read");
    }

    let held = match take_lease(mongo, "migrate").await {
        Ok(held) => held,
        Err(code) => return code,
    };
    let ctx = Arc::new(MigrateCtx {
        db: db.clone(),
        mongo: mongo.clone(),
        keyring: keyring.clone(),
        primary,
        accept_hash_mismatch: args.accept_hash_mismatch,
        lease: held.lease.clone(),
    });
    let code = migrate_under_lease(ctx, &args).await;
    held.release().await;
    code
}

async fn migrate_under_lease(ctx: Arc<MigrateCtx>, args: &MigrateArgs) -> i32 {
    // Resume: settle every entry an earlier run left pending
    let resume = reconcile_pending(&ctx.mongo, &ctx.lease).await;
    resume.print();

    // Rows already settled are never selected again; a fetch-failed
    // quarantine is not settled, so it is retried, and neither is a
    // hash-mismatch one under --accept-hash-mismatch
    let settled = match string_field_set(
        &ctx.mongo,
        JOURNAL,
        settled_filter(args.accept_hash_mismatch),
        "_id",
    )
    .await
    {
        Ok(settled) => settled,
        Err(error) => {
            eprintln!("FAIL: could not read the journal ({error})");
            return EXIT_FAILED;
        }
    };

    let mut tally = MigrateTally::default();
    let mut tasks: JoinSet<RowOutcome> = JoinSet::new();
    let mut after: Option<Bson> = None;
    let mut selected: u64 = 0;
    // One permit per worker; a large v1 row takes them all, so it runs alone
    // (the semaphore is fair, so later rows wait behind it)
    let workers = Arc::new(Semaphore::new(args.concurrency.max(1)));

    'pages: loop {
        if !ctx.lease.held() {
            eprintln!("lease lost; no more rows are selected");
            tally.errors += 1;
            break;
        }
        let page = match select_page(&ctx.mongo, after.as_ref()).await {
            Ok(page) => page,
            Err(error) => {
                eprintln!("could not select legacy rows ({error}); stopping");
                tally.errors += 1;
                break;
            }
        };
        // An empty page ends the selection; paging always moves forward
        let Some(next) = page.last().and_then(|last| last.get("_id").cloned()) else {
            break;
        };
        after = Some(next);

        for row in page {
            if args.limit.is_some_and(|limit| selected >= limit) {
                break 'pages;
            }
            let row = match HashRow::from_doc(&row) {
                Ok(row) => row,
                Err(error) => {
                    let label = short(row.get_str("_id").unwrap_or("?"));
                    eprintln!("hash {label}: unreadable row ({error})");
                    tally.errors += 1;
                    continue;
                }
            };
            if settled.contains(&row.id) {
                tally.skipped += 1;
                continue;
            }

            selected += 1;
            while tasks.len() >= args.concurrency {
                match tasks.join_next().await {
                    Some(joined) => tally.record(joined),
                    None => break,
                }
            }
            let ctx = ctx.clone();
            let workers = workers.clone();
            let permits = row_permits(row.format_version, row.size, args.concurrency);
            tasks.spawn(async move {
                let Ok(_permits) = workers.acquire_many_owned(permits).await else {
                    eprintln!("hash {}: no worker permit; row not started", short(&row.id));
                    return RowOutcome::Error;
                };
                migrate_row(&ctx, row).await
            });
        }
    }
    while let Some(joined) = tasks.join_next().await {
        tally.record(joined);
    }

    println!("selected this run: {selected}");
    tally.print();
    let outstanding = print_outstanding(&ctx.mongo, args.accept_hash_mismatch).await;
    migrate_exit_code(outstanding, tally.run_clean() && resume.clean())
}

/// Worker permits one row takes: 1, or all of them for a v1 row over 256 MiB
/// (or of unknown size), which migrate holds whole in memory several times
/// over. v2 rows stream part by part and always take 1.
fn row_permits(format_version: Option<i64>, size: Option<i64>, concurrency: usize) -> u32 {
    let all = u32::try_from(concurrency.max(1)).unwrap_or(u32::MAX);
    match (format_version, size) {
        (None, Some(size)) if size <= LARGE_V1_BYTES => 1,
        (None, _) => all,
        (Some(_), _) => 1,
    }
}

/// The next page of LEGACY_ROW rows after `after`, by `_id`. Placeholders
/// (`iv: ""`) are never selected.
async fn select_page(mongo: &MongoDb, after: Option<&Bson>) -> Result<Vec<Document>, String> {
    let mut filter = legacy_row_filter();
    if let Some(after) = after {
        filter.insert("_id", doc! { "$gt": after.clone() });
    }
    let mut cursor = mongo
        .col::<Document>(HASHES)
        .find(filter)
        .sort(doc! { "_id": 1_i32 })
        .limit(SELECTION_PAGE)
        .await
        .map_err(|error| format!("read {HASHES}: {error}"))?;

    let mut page = Vec::new();
    while cursor
        .advance()
        .await
        .map_err(|error| format!("read {HASHES}: {error}"))?
    {
        page.push(
            cursor
                .deserialize_current()
                .map_err(|error| format!("decode {HASHES}: {error}"))?,
        );
    }
    Ok(page)
}

/// A pending entry: the old triple as read, and the new path chosen now
fn pending_entry(row: &HashRow, new_path: &str, new_key_id: &str) -> Document {
    let format_version = match row.format_version {
        Some(version) => Bson::Int64(version),
        None => Bson::Null,
    };
    doc! {
        "_id": row.id.as_str(),
        "status": STATUS_PENDING,
        "bucket_id": row.bucket_id.as_str(),
        "old_path": row.path.as_str(),
        "old_iv": row.iv.as_str(),
        "old_key_id": Bson::Null,
        "new_path": new_path,
        "new_key_id": new_key_id,
        "format_version": format_version,
        "hash_mismatch": false,
        "updated_at": DateTime::now(),
    }
}

/// Quarantine reasons a migrate run retries:
/// - `fetch-failed` always: the read may have failed transiently;
/// - `hash-mismatch` only under `--accept-hash-mismatch`, which is the run
///   that can migrate such a row (journaled `hash_mismatch: true`);
/// - `decrypt-failed` and `v2-layout` never.
fn retryable_reasons(accept_hash_mismatch: bool) -> Vec<&'static str> {
    if accept_hash_mismatch {
        vec![REASON_FETCH, REASON_HASH_MISMATCH]
    } else {
        vec![REASON_FETCH]
    }
}

/// Whether a quarantine with this reason is retried (the rule the filters
/// below encode; a quarantine with no reason is settled)
fn quarantine_retryable(reason: Option<&str>, accept_hash_mismatch: bool) -> bool {
    reason.is_some_and(|reason| retryable_reasons(accept_hash_mismatch).contains(&reason))
}

/// A retryable quarantine. It keeps `status: "quarantine"` until it is
/// re-claimed, so the autumn probe still excludes it meanwhile.
fn retryable_quarantine_filter(accept_hash_mismatch: bool) -> Document {
    doc! {
        "status": STATUS_QUARANTINE,
        "reason": { "$in": bson_strings(&retryable_reasons(accept_hash_mismatch)) },
    }
}

/// A quarantine for any other reason (or none): settled, not retried
fn settled_quarantine_filter(accept_hash_mismatch: bool) -> Document {
    doc! {
        "status": STATUS_QUARANTINE,
        "reason": { "$nin": bson_strings(&retryable_reasons(accept_hash_mismatch)) },
    }
}

/// Journal entries whose rows the selection skips
fn settled_filter(accept_hash_mismatch: bool) -> Document {
    doc! {
        "$or": [
            { "status": STATUS_MIGRATED },
            settled_quarantine_filter(accept_hash_mismatch),
        ]
    }
}

/// A row may be (re-)journaled unless it is already pending, migrated or
/// quarantined; a retryable quarantine may be re-claimed, and the claim
/// replaces it. With upsert, any other entry makes the insert collide on
/// `_id`, so two claims of one row can never both succeed.
fn pending_claim_filter(id: &str, accept_hash_mismatch: bool) -> Document {
    doc! {
        "_id": id,
        "$or": [
            {
                "status": {
                    "$nin": bson_strings(&[STATUS_PENDING, STATUS_MIGRATED, STATUS_QUARANTINE])
                }
            },
            retryable_quarantine_filter(accept_hash_mismatch),
        ],
    }
}

enum ClaimError {
    AlreadyJournaled,
    Db(String),
}

async fn claim_row(
    mongo: &MongoDb,
    row: &HashRow,
    new_path: &str,
    primary: &str,
    accept_hash_mismatch: bool,
) -> Result<(), ClaimError> {
    match mongo
        .col::<Document>(JOURNAL)
        .replace_one(
            pending_claim_filter(&row.id, accept_hash_mismatch),
            pending_entry(row, new_path, primary),
        )
        .upsert(true)
        .await
    {
        Ok(result) if result.matched_count == 1 || result.upserted_id.is_some() => Ok(()),
        Ok(_) => Err(ClaimError::Db("the claim matched nothing".to_string())),
        Err(error) if is_duplicate_key(&error) => Err(ClaimError::AlreadyJournaled),
        Err(error) => Err(ClaimError::Db(error.to_string())),
    }
}

/// Steps 1-7 for one row. Every failure is recorded on the row; nothing here
/// ends the run.
async fn migrate_row(ctx: &MigrateCtx, row: HashRow) -> RowOutcome {
    let label = short(&row.id);

    // The selection guarantees a legacy row with an iv; never act on anything else
    if row.key_id.is_some() || row.iv.is_empty() {
        return RowOutcome::Skipped;
    }
    if !ctx.lease.held() {
        eprintln!("hash {label}: lease not held; row not started");
        return RowOutcome::Error;
    }

    // 1. Journal FIRST, with the new path chosen before any PUT [A11]
    let new_path = FileHash::new_object_path(Some(ctx.primary.as_str()));
    match claim_row(
        &ctx.mongo,
        &row,
        &new_path,
        &ctx.primary,
        ctx.accept_hash_mismatch,
    )
    .await
    {
        Ok(()) => {}
        Err(ClaimError::AlreadyJournaled) => {
            println!("hash {label}: already journaled; skipped");
            return RowOutcome::Skipped;
        }
        Err(ClaimError::Db(error)) => {
            eprintln!("hash {label}: could not journal the row ({error})");
            return RowOutcome::Error;
        }
    }

    // 2-6
    let prepared = match row.format_version {
        None => migrate_v1(ctx, &row, &new_path).await,
        Some(2) => migrate_v2(ctx, &row, &new_path).await,
        Some(_) => Err(Stop::Source(REASON_V2_LAYOUT)),
    };

    match prepared {
        // 7
        Ok(prepared) => swap_row(ctx, &row, &new_path, prepared).await,
        // 4
        Err(Stop::Source(reason)) => settle_source_failure(ctx, &row, &new_path, reason).await,
        Err(Stop::Write(detail)) => {
            eprintln!("hash {label}: {detail}; removing the new object {new_path}");
            release_claim(ctx, &row, &new_path).await;
            RowOutcome::Error
        }
        Err(Stop::LeavePending(detail)) => {
            eprintln!("hash {label}: {detail}; left pending for the next run to reconcile");
            RowOutcome::Error
        }
    }
}

/// Step 3: Ok(false) on a match, Ok(true) for a mismatch accepted with
/// --accept-hash-mismatch (journaled as `hash_mismatch: true`)
async fn accept_source_hash(
    ctx: &MigrateCtx,
    row: &HashRow,
    new_path: &str,
    digest: &str,
) -> Result<bool, Stop> {
    match hash_match(digest, &row.processed_hash, &row.id) {
        HashMatch::Processed | HashMatch::OwnId => Ok(false),
        HashMatch::Mismatch if ctx.accept_hash_mismatch => {
            // Re-read first even here: a moved row is a lost race
            match row_unchanged(&ctx.mongo, row).await {
                Ok(true) => {}
                Ok(false) => return Err(Stop::Source(REASON_HASH_MISMATCH)),
                Err(error) => {
                    return Err(Stop::LeavePending(format!(
                        "the row could not be re-read ({error})"
                    )))
                }
            }
            match journal_move(
                &ctx.mongo,
                &row.id,
                new_path,
                STATUS_PENDING,
                doc! { "hash_mismatch": true },
            )
            .await
            {
                Ok(true) => {
                    println!(
                        "hash {}: hash mismatch accepted (--accept-hash-mismatch)",
                        short(&row.id)
                    );
                    Ok(true)
                }
                _ => Err(Stop::LeavePending(
                    "could not journal the accepted hash mismatch".to_string(),
                )),
            }
        }
        HashMatch::Mismatch => Err(Stop::Source(REASON_HASH_MISMATCH)),
    }
}

/// Record the new object's iv on the pending entry once it is known
async fn record_new_iv(
    ctx: &MigrateCtx,
    row: &HashRow,
    new_path: &str,
    new_iv: &str,
) -> Result<(), Stop> {
    match journal_move(
        &ctx.mongo,
        &row.id,
        new_path,
        STATUS_PENDING,
        doc! { "new_iv": new_iv },
    )
    .await
    {
        Ok(true) => Ok(()),
        _ => Err(Stop::Write("could not journal new_iv".to_string())),
    }
}

/// Steps 2-6 for a v1 (whole-file) row
async fn migrate_v1(ctx: &MigrateCtx, row: &HashRow, new_path: &str) -> Result<Prepared, Stop> {
    // 2. Fetch, then decrypt with the legacy key. Separate steps (rather than
    // fetch_from_s3) so a fetch failure and a decrypt failure stay distinct.
    let ciphertext = fetch_bytes(&row.bucket_id, &row.path, None)
        .await
        .ok_or(Stop::Source(REASON_FETCH))?;
    let plaintext = EncryptionKey::new(ctx.keyring.clone())
        .decrypt_buffer(ciphertext, &row.iv, None)
        .map_err(|_| Stop::Source(REASON_DECRYPT))?;

    // 3. The plaintext must be the bytes the row was hashed from
    let digest = sha256_hex(&plaintext);
    let hash_mismatch = accept_source_hash(ctx, row, new_path, &digest).await?;

    // 5. Re-encrypt under the primary with a fresh IV, at the journaled path
    if !ctx.lease.held() {
        return Err(Stop::LeavePending(
            "lease lost before the upload".to_string(),
        ));
    }
    let (new_iv, written_key_id) = upload_to_s3(&row.bucket_id, new_path, &plaintext)
        .await
        .map_err(|_| Stop::Write("upload failed".to_string()))?;
    drop(plaintext);
    if written_key_id.as_deref() != Some(ctx.primary.as_str()) {
        return Err(Stop::Write(format!(
            "the upload was encrypted under {}, not the primary {}",
            written_key_id.as_deref().unwrap_or(LEGACY_KEY_ID),
            ctx.primary
        )));
    }
    record_new_iv(ctx, row, new_path, &new_iv).await?;

    // 6. Read back under the primary: same plaintext sha
    let stored = fetch_bytes(&row.bucket_id, new_path, None)
        .await
        .ok_or_else(|| Stop::Write("read-back fetch failed".to_string()))?;
    let readback = EncryptionKey::new(ctx.keyring.clone())
        .decrypt_buffer(stored, &new_iv, Some(ctx.primary.as_str()))
        .map_err(|_| Stop::Write("read-back decrypt failed".to_string()))?;
    if sha256_hex(&readback) != digest {
        return Err(Stop::Write("read-back plaintext differs".to_string()));
    }

    Ok(Prepared {
        new_iv,
        hash_mismatch,
    })
}

/// Steps 2-6 for a v2 (segmented) row, one part at a time: each part is
/// decrypted with the legacy key, re-sealed under the primary with a fresh
/// prefix and uploaded as one multipart part. The upload is completed only
/// after the composite hash matched, so nothing exists at the new path for a
/// row that fails steps 2-3.
async fn migrate_v2(ctx: &MigrateCtx, row: &HashRow, new_path: &str) -> Result<Prepared, Stop> {
    let layout = V2Layout::of(&row.iv, row.size).map_err(|_| Stop::Source(REASON_V2_LAYOUT))?;
    check_v2_stored_length(&row.bucket_id, &row.path, layout.total_size)
        .await
        .map_err(|failure| Stop::Source(failure.reason()))?;
    let source = SegmentedStreamCipher::from_config(layout.prefix, None)
        .await
        .map_err(|_| Stop::Source(REASON_DECRYPT))?;
    if source.ciphertext_len(layout.total_size) != ciphertext_len_of(layout.total_size) {
        return Err(Stop::Source(REASON_V2_LAYOUT));
    }

    let new_prefix = SegmentedStreamCipher::generate_prefix();
    let new_iv = BASE64_STANDARD.encode(new_prefix);
    let target = SegmentedStreamCipher::from_cipher(ctx.keyring.primary_cipher(), new_prefix);

    if !ctx.lease.held() {
        return Err(Stop::LeavePending(
            "lease lost before the upload".to_string(),
        ));
    }
    let upload_id = create_multipart_in_s3(&row.bucket_id, new_path)
        .await
        .map_err(|_| Stop::Write("could not start the multipart upload".to_string()))?;

    let (composite, parts) =
        match copy_v2_parts(ctx, row, new_path, &upload_id, &layout, &source, &target).await {
            Ok(copied) => copied,
            Err(stop) => {
                abort_upload(row, new_path, &upload_id).await;
                return Err(stop);
            }
        };

    // 3. The plaintext parts must hash to the row's composite id
    let hash_mismatch = match accept_source_hash(ctx, row, new_path, &composite).await {
        Ok(hash_mismatch) => hash_mismatch,
        Err(stop) => {
            abort_upload(row, new_path, &upload_id).await;
            return Err(stop);
        }
    };

    if !ctx.lease.held() {
        abort_upload(row, new_path, &upload_id).await;
        return Err(Stop::LeavePending(
            "lease lost before completing the upload".to_string(),
        ));
    }
    if complete_multipart_in_s3(&row.bucket_id, new_path, &upload_id, &parts)
        .await
        .is_err()
    {
        abort_upload(row, new_path, &upload_id).await;
        return Err(Stop::Write(
            "could not complete the multipart upload".to_string(),
        ));
    }
    record_new_iv(ctx, row, new_path, &new_iv).await?;

    // 6. Read back under the primary: same composite
    let primary = KeyRef {
        keyring: ctx.keyring.clone(),
        key_id: Some(ctx.primary.clone()),
    };
    match read_v2_digest(&row.bucket_id, new_path, &new_iv, row.size, &primary).await {
        Ok(readback) if readback == composite => Ok(Prepared {
            new_iv,
            hash_mismatch,
        }),
        Ok(_) => Err(Stop::Write("read-back composite differs".to_string())),
        Err(failure) => Err(Stop::Write(format!(
            "read-back failed ({})",
            failure.describe()
        ))),
    }
}

/// Decrypt, re-seal and upload every part; returns the composite hash of the
/// plaintext and the uploaded `(part number, etag)` list
async fn copy_v2_parts(
    ctx: &MigrateCtx,
    row: &HashRow,
    new_path: &str,
    upload_id: &str,
    layout: &V2Layout,
    source: &SegmentedStreamCipher,
    target: &SegmentedStreamCipher,
) -> Result<(String, Vec<(i32, String)>), Stop> {
    let total_parts = layout.part_sizes.len() as u64;
    let mut part_hashes = Vec::with_capacity(layout.part_sizes.len());
    let mut parts = Vec::with_capacity(layout.part_sizes.len());

    for part_number in 1..=total_parts {
        if !ctx.lease.held() {
            return Err(Stop::LeavePending("lease lost mid-object".to_string()));
        }
        let plaintext = read_v2_part(
            &row.bucket_id,
            &row.path,
            source,
            &layout.part_sizes,
            part_number,
        )
        .await
        .map_err(|failure| Stop::Source(failure.reason()))?;
        part_hashes.push(sha256_hex(&plaintext));

        // [A25] equal non-final parts, asserted here because MinIO won't
        check_upload_part(part_number, total_parts, plaintext.len())
            .map_err(|error| Stop::Write(format!("[A25] {error}")))?;

        let (Ok(s3_part), Ok(cipher_part)) =
            (i32::try_from(part_number), u32::try_from(part_number))
        else {
            return Err(Stop::Source(REASON_V2_LAYOUT));
        };
        let sealed = target
            .encrypt_part(cipher_part, part_number == total_parts, &plaintext)
            .map_err(|_| Stop::Write(format!("could not encrypt part {part_number}")))?;
        drop(plaintext);
        let etag = upload_part_to_s3(&row.bucket_id, new_path, upload_id, s3_part, sealed)
            .await
            .map_err(|_| Stop::Write(format!("could not upload part {part_number}")))?;
        parts.push((s3_part, etag));
    }

    Ok((
        composite_hash_v2(CHUNK_SIZE as i64, layout.total_size as i64, &part_hashes),
        parts,
    ))
}

async fn abort_upload(row: &HashRow, new_path: &str, upload_id: &str) {
    if abort_multipart_in_s3(&row.bucket_id, new_path, upload_id)
        .await
        .is_err()
    {
        eprintln!(
            "hash {}: could not abort the multipart upload at {new_path}; the bucket \
             lifecycle reaps it",
            short(&row.id)
        );
    }
}

/// Step 4: re-read the row FIRST. A row that moved or vanished is a lost
/// race, not a broken object.
async fn settle_source_failure(
    ctx: &MigrateCtx,
    row: &HashRow,
    new_path: &str,
    reason: &'static str,
) -> RowOutcome {
    let label = short(&row.id);
    match row_unchanged(&ctx.mongo, row).await {
        Ok(true) => {
            match journal_move(
                &ctx.mongo,
                &row.id,
                new_path,
                STATUS_PENDING,
                doc! { "status": STATUS_QUARANTINE, "reason": reason },
            )
            .await
            {
                Ok(true) => {
                    eprintln!("hash {label}: QUARANTINE ({reason})");
                    RowOutcome::Quarantined(reason)
                }
                _ => {
                    eprintln!("hash {label}: {reason}, but the quarantine was not journaled; left pending");
                    RowOutcome::Error
                }
            }
        }
        Ok(false) => match journal_move(
            &ctx.mongo,
            &row.id,
            new_path,
            STATUS_PENDING,
            doc! { "status": STATUS_LOST_RACE },
        )
        .await
        {
            Ok(true) => {
                println!("hash {label}: lost-race (the row changed while it was read)");
                RowOutcome::LostRace
            }
            _ => {
                eprintln!("hash {label}: lost a race, but it was not journaled; left pending");
                RowOutcome::Error
            }
        },
        Err(error) => {
            eprintln!(
                "hash {label}: {reason}, and the row could not be re-read ({error}); left pending"
            );
            RowOutcome::Error
        }
    }
}

/// After a write-side failure: delete our new object (no row points at it),
/// then drop the claim so the next run retries the row. Anything uncertain
/// stays pending for the next run's resume.
async fn release_claim(ctx: &MigrateCtx, row: &HashRow, new_path: &str) {
    let label = short(&row.id);
    match delete_if_unreferenced(&ctx.mongo, &row.bucket_id, new_path).await {
        Ok(true) => {
            if let Err(error) = ctx
                .mongo
                .col::<Document>(JOURNAL)
                .delete_one(claim_filter(&row.id, new_path, STATUS_PENDING))
                .await
            {
                eprintln!("hash {label}: could not drop the claim ({error}); left pending");
            }
        }
        Ok(false) => eprintln!("hash {label}: a row references {new_path}; left pending"),
        Err(error) => eprintln!("hash {label}: {error}; left pending for the next run"),
    }
}

/// Step 7: the compare-and-swap against the exact triple that was read
async fn swap_row(
    ctx: &MigrateCtx,
    row: &HashRow,
    new_path: &str,
    prepared: Prepared,
) -> RowOutcome {
    let label = short(&row.id);
    if !ctx.lease.held() {
        eprintln!("hash {label}: lease lost before the swap; removing the new object");
        release_claim(ctx, row, new_path).await;
        return RowOutcome::Error;
    }

    // Fence: if another run (after a lease overlap) resumed this claim, it
    // may have deleted our new object. Swap only while the entry is still
    // exactly our pending claim; otherwise touch nothing, delete nothing.
    match claim_still_current(&ctx.mongo, &row.id, STATUS_PENDING, new_path).await {
        Ok(true) => {}
        Ok(false) => {
            eprintln!(
                "hash {label}: lost-race (the journal entry is no longer this run's pending \
                 claim); not swapped, nothing deleted"
            );
            return RowOutcome::LostRace;
        }
        Err(error) => {
            eprintln!(
                "hash {label}: could not re-read the journal entry ({error}); not swapped, left \
                 pending for the next run"
            );
            return RowOutcome::Error;
        }
    }

    let swapped = ctx
        .db
        .swap_attachment_hash_storage(
            &row.id,
            &row.path,
            &row.iv,
            None,
            new_path,
            &prepared.new_iv,
            Some(ctx.primary.as_str()),
        )
        .await;

    match swapped {
        Ok(true) => {
            mark_migrated(ctx, row, new_path, &prepared.new_iv, prepared.hash_mismatch).await
        }
        Ok(false) => match fetch_hash_row(&ctx.mongo, &row.id).await {
            // A retried write landed after all: the row is ours
            Ok(Some(current)) if current.path == new_path => {
                mark_migrated(ctx, row, new_path, &current.iv, prepared.hash_mismatch).await
            }
            Ok(_) => {
                // Lost the race: delete only our own object, if still unreferenced
                match delete_if_unreferenced(&ctx.mongo, &row.bucket_id, new_path).await {
                    Ok(true) => {}
                    Ok(false) => {
                        eprintln!("hash {label}: a row references {new_path}; not deleted")
                    }
                    Err(error) => {
                        eprintln!("hash {label}: {error}; the orphan sweep removes it later")
                    }
                }
                match journal_move(
                    &ctx.mongo,
                    &row.id,
                    new_path,
                    STATUS_PENDING,
                    doc! { "status": STATUS_LOST_RACE },
                )
                .await
                {
                    Ok(true) => {
                        println!("hash {label}: lost-race (the row changed before the swap)");
                        RowOutcome::LostRace
                    }
                    _ => {
                        eprintln!(
                            "hash {label}: lost a race, but it was not journaled; left pending"
                        );
                        RowOutcome::Error
                    }
                }
            }
            Err(error) => {
                eprintln!(
                    "hash {label}: the swap matched nothing and the row could not be re-read \
                     ({error}); left pending"
                );
                RowOutcome::Error
            }
        },
        // The swap may or may not have landed: never delete, let resume decide
        Err(error) => {
            eprintln!("hash {label}: swap failed ({error:?}); left pending for the next run");
            RowOutcome::Error
        }
    }
}

async fn mark_migrated(
    ctx: &MigrateCtx,
    row: &HashRow,
    new_path: &str,
    new_iv: &str,
    hash_mismatch: bool,
) -> RowOutcome {
    match journal_move(
        &ctx.mongo,
        &row.id,
        new_path,
        STATUS_PENDING,
        doc! { "status": STATUS_MIGRATED, "new_iv": new_iv, "hash_mismatch": hash_mismatch },
    )
    .await
    {
        Ok(true) => RowOutcome::Migrated {
            hash_mismatch,
            journal_stale: false,
        },
        _ => {
            eprintln!(
                "hash {}: migrated, but the journal still says pending; the next run's resume \
                 marks it",
                short(&row.id)
            );
            RowOutcome::Migrated {
                hash_mismatch,
                journal_stale: true,
            }
        }
    }
}

#[derive(Default)]
struct ResumeTally {
    pending: u64,
    migrated: u64,
    dropped: u64,
    /// Written too recently (or undated) to settle; left for a later run
    too_recent: u64,
    errors: u64,
}

impl ResumeTally {
    fn print(&self) {
        println!(
            "resume: {} pending entries; {} were swapped (now migrated), {} dropped for retry, \
             {} left (updated in the last {} minutes, or undated), {} errors",
            self.pending,
            self.migrated,
            self.dropped,
            self.too_recent,
            RESUME_MIN_AGE_MS / 60_000,
            self.errors
        );
        if self.too_recent > 0 {
            eprintln!(
                "resume: {} pending entries were left alone; re-run in {} minutes to settle them",
                self.too_recent,
                RESUME_MIN_AGE_MS / 60_000
            );
        }
    }

    /// Exit 0 needs every pending entry settled
    fn clean(&self) -> bool {
        self.errors == 0 && self.too_recent == 0
    }
}

/// Settle every `pending` entry an interrupted run left:
/// - an entry written in the last two lease lifetimes (or undated) is left
///   alone: its run may still be in flight after a lease overlap;
/// - the row points at `new_path`: the swap happened, so mark it migrated
///   with the row's iv;
/// - otherwise our object (if any) is unreferenced: delete it and drop the
///   entry so the row is retried.
async fn reconcile_pending(mongo: &MongoDb, lease: &Lease) -> ResumeTally {
    let mut tally = ResumeTally::default();
    let entries = match load_journal(mongo, doc! { "status": STATUS_PENDING }).await {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("resume: could not read pending entries ({error})");
            tally.errors += 1;
            return tally;
        }
    };
    tally.pending = entries.len() as u64;

    for entry in entries {
        if !lease.held() {
            eprintln!("resume: lease lost; stopping");
            tally.errors += 1;
            break;
        }
        let label = short(&entry.id);

        if !pending_entry_settleable(entry.updated_at_ms, now_ms()) {
            eprintln!(
                "resume: hash {label}: pending entry updated in the last {} minutes (or undated); \
                 left for a later run",
                RESUME_MIN_AGE_MS / 60_000
            );
            tally.too_recent += 1;
            continue;
        }

        let current = match fetch_hash_row(mongo, &entry.id).await {
            Ok(current) => current,
            Err(error) => {
                eprintln!("resume: hash {label}: could not re-read the row ({error})");
                tally.errors += 1;
                continue;
            }
        };
        if let Some(row) = current.filter(|row| row.path == entry.new_path) {
            match journal_move(
                mongo,
                &entry.id,
                &entry.new_path,
                STATUS_PENDING,
                doc! { "status": STATUS_MIGRATED, "new_iv": row.iv.as_str() },
            )
            .await
            {
                Ok(true) => {
                    println!("resume: hash {label}: swapped earlier; marked migrated");
                    tally.migrated += 1;
                }
                _ => {
                    eprintln!(
                        "resume: hash {label}: swapped earlier, but the journal was not updated"
                    );
                    tally.errors += 1;
                }
            }
            continue;
        }

        // The swap never happened, so no row points at our object
        match object_exists_in_s3(&entry.bucket_id, &entry.new_path).await {
            Ok(false) => {}
            Ok(true) => {
                match delete_if_unreferenced(mongo, &entry.bucket_id, &entry.new_path).await {
                    Ok(true) => println!(
                        "resume: hash {label}: deleted the unswapped {}",
                        entry.new_path
                    ),
                    Ok(false) => {
                        eprintln!(
                            "resume: hash {label}: a row references {}; kept",
                            entry.new_path
                        );
                        tally.errors += 1;
                        continue;
                    }
                    Err(error) => {
                        eprintln!("resume: hash {label}: {error}");
                        tally.errors += 1;
                        continue;
                    }
                }
            }
            Err(_) => {
                eprintln!("resume: hash {label}: could not check {}", entry.new_path);
                tally.errors += 1;
                continue;
            }
        }
        match mongo
            .col::<Document>(JOURNAL)
            .delete_one(claim_filter(&entry.id, &entry.new_path, STATUS_PENDING))
            .await
        {
            Ok(_) => tally.dropped += 1,
            Err(error) => {
                eprintln!("resume: hash {label}: could not drop the entry ({error})");
                tally.errors += 1;
            }
        }
    }
    tally
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// A sample that decrypted (and matched, when `strong`)
struct SampleProof {
    row: HashRow,
    digest: String,
    /// The full hash check ran (false: mismatch accepted at migration)
    strong: bool,
}

/// [A5] offline custody check: a keyring holding only the key file's key,
/// registered under the primary id
fn key_file_key(keyring: &FileKeyring, path: &str) -> Result<KeyRef, i32> {
    let Some(primary) = keyring.primary_id() else {
        return Err(refuse(
            "--key-file checks the rotated primary, but the primary is legacy",
        ));
    };
    let contents =
        std::fs::read_to_string(path).map_err(|_| refuse("could not read the --key-file"))?;
    let file_keyring =
        FileKeyring::from_parts(contents.trim_end(), primary, &HashMap::new(), false).map_err(
            |error| {
                refuse(&format!(
                    "the --key-file does not hold a valid file key: {error:#}"
                ))
            },
        )?;
    drop(contents);

    let file_fingerprint = file_keyring
        .fingerprint(Some(primary))
        .unwrap_or_else(|_| "unknown".to_string());
    let primary_fingerprint = keyring
        .fingerprint(Some(primary))
        .unwrap_or_else(|_| "unknown".to_string());
    println!(
        "key file: fingerprint={file_fingerprint} ({} the configured primary {primary})",
        if file_fingerprint == primary_fingerprint {
            "matches"
        } else {
            "DIFFERS from"
        }
    );

    Ok(KeyRef {
        keyring: Arc::new(file_keyring),
        key_id: Some(primary.to_string()),
    })
}

async fn verify(mongo: &MongoDb, keyring: &Arc<FileKeyring>, args: VerifyArgs) -> i32 {
    let key_file = match &args.key_file {
        None => None,
        Some(path) => match key_file_key(keyring, path) {
            Ok(key) => Some(key),
            Err(code) => return code,
        },
    };

    let migrated: HashMap<String, JournalEntry> =
        match load_journal(mongo, doc! { "status": STATUS_MIGRATED }).await {
            Ok(entries) => entries
                .into_iter()
                .map(|entry| (entry.id.clone(), entry))
                .collect(),
            Err(error) => {
                eprintln!("FAIL: could not read the journal ({error})");
                return EXIT_FAILED;
            }
        };
    let samples = match choose_samples(mongo, &migrated, args.sample).await {
        Ok(samples) => samples,
        Err(error) => {
            eprintln!("FAIL: could not choose samples ({error})");
            return EXIT_FAILED;
        }
    };
    if samples.is_empty() {
        eprintln!("FAIL: zero samples to verify");
        return EXIT_FAILED;
    }
    println!("verify: {} samples", samples.len());

    let mut failed = 0_usize;
    let mut proof: Option<SampleProof> = None;
    for id in &samples {
        let Some(entry) = migrated.get(id) else {
            continue;
        };
        match verify_sample(mongo, entry, key_file.as_ref(), keyring).await {
            Ok(sample) => {
                if proof.is_none() && sample.strong {
                    proof = Some(sample);
                }
            }
            Err(reason) => {
                eprintln!("hash {}: FAIL ({reason})", short(id));
                failed += 1;
            }
        }
    }
    println!(
        "samples: {} passed, {failed} failed",
        samples.len().saturating_sub(failed)
    );

    let controls_ok = match &proof {
        Some(proof) => run_controls(proof, keyring).await,
        None => {
            eprintln!("FAIL: no sample passed a full hash check, so the controls cannot run");
            false
        }
    };
    let orphans_ok = check_orphans_after_purge(mongo).await;

    if failed == 0 && controls_ok && orphans_ok {
        println!("verify: PASS");
        EXIT_OK
    } else {
        eprintln!("verify: FAIL");
        EXIT_FAILED
    }
}

/// N random migrated rows, then every migrated object over 16 MiB, then every
/// migrated v2 row; each id once
async fn choose_samples(
    mongo: &MongoDb,
    migrated: &HashMap<String, JournalEntry>,
    random: u64,
) -> Result<Vec<String>, String> {
    let mut order = Vec::new();
    let mut seen = HashSet::new();

    if random > 0 {
        let size = random as i64;
        let pipeline = vec![
            doc! { "$match": { "status": STATUS_MIGRATED, "_id": { "$ne": LEASE_ID } } },
            doc! { "$sample": { "size": size } },
            doc! { "$project": { "_id": 1_i32 } },
        ];
        let mut cursor = mongo
            .col::<Document>(JOURNAL)
            .aggregate(pipeline)
            .await
            .map_err(|error| format!("sample {JOURNAL}: {error}"))?;
        while cursor
            .advance()
            .await
            .map_err(|error| format!("sample {JOURNAL}: {error}"))?
        {
            let sampled = cursor
                .deserialize_current()
                .map_err(|error| format!("decode {JOURNAL}: {error}"))?;
            if let Ok(id) = sampled.get_str("_id") {
                if seen.insert(id.to_string()) {
                    order.push(id.to_string());
                }
            }
        }
    }

    let mut large: Vec<String> = string_field_set(
        mongo,
        HASHES,
        doc! { "size": { "$gt": VERIFY_LARGE_OBJECT_BYTES } },
        "_id",
    )
    .await?
    .into_iter()
    .filter(|id| migrated.contains_key(id))
    .collect();
    large.sort();

    let mut v2: Vec<String> = migrated
        .values()
        .filter(|entry| entry.format_version == Some(2))
        .map(|entry| entry.id.clone())
        .collect();
    v2.sort();

    for id in large.into_iter().chain(v2) {
        if seen.insert(id.clone()) {
            order.push(id);
        }
    }
    Ok(order)
}

/// Decrypt one migrated row's CURRENT object under its own key (or the key
/// file) and apply the migrate hash rule
async fn verify_sample(
    mongo: &MongoDb,
    entry: &JournalEntry,
    key_file: Option<&KeyRef>,
    keyring: &Arc<FileKeyring>,
) -> Result<SampleProof, String> {
    let row = fetch_hash_row(mongo, &entry.id)
        .await?
        .ok_or("the row is gone")?;
    let Some(row_key_id) = row.key_id.clone() else {
        return Err("the row is not under a named key (rolled back or rewritten)".to_string());
    };
    if row.path != entry.new_path {
        println!(
            "hash {}: the row has moved since migration; checking its current object",
            short(&row.id)
        );
    }

    let key = match key_file {
        Some(key) => {
            if key.key_id.as_deref() != Some(row_key_id.as_str()) {
                return Err(format!(
                    "the row is under key {row_key_id}, the key file is for {}",
                    key.key_id.as_deref().unwrap_or(LEGACY_KEY_ID)
                ));
            }
            key.clone()
        }
        None => KeyRef {
            keyring: keyring.clone(),
            key_id: Some(row_key_id),
        },
    };

    let digest = read_digest(&row, &key)
        .await
        .map_err(|failure| failure.describe())?;
    if entry.hash_mismatch {
        println!(
            "hash {}: decrypts; hash check waived (mismatch accepted at migration)",
            short(&row.id)
        );
        return Ok(SampleProof {
            row,
            digest,
            strong: false,
        });
    }
    match hash_match(&digest, &row.processed_hash, &row.id) {
        HashMatch::Mismatch => Err("decrypted bytes do not match the recorded hash".to_string()),
        HashMatch::Processed | HashMatch::OwnId => Ok(SampleProof {
            row,
            digest,
            strong: true,
        }),
    }
}

/// A control that passes is a FAIL
fn control_must_fail(name: &str, passed: bool) -> bool {
    if passed {
        eprintln!("control {name}: PASSED, which must not happen: FAIL");
        false
    } else {
        println!("control {name}: failed, as required");
        true
    }
}

/// The three known-bad controls, on the first sample that passed in full
async fn run_controls(proof: &SampleProof, keyring: &Arc<FileKeyring>) -> bool {
    println!("controls on hash {}:", short(&proof.row.id));
    let mut ok = true;

    // 1. The legacy key must not open a migrated object
    if keyring.has(None) {
        let legacy = KeyRef {
            keyring: keyring.clone(),
            key_id: None,
        };
        ok &= control_must_fail("legacy key", read_digest(&proof.row, &legacy).await.is_ok());
    } else {
        println!("control legacy key: SKIPPED (no legacy key in the keyring)");
    }

    // 2. Nor a random key
    match FileKeyring::from_parts(&random_key_b64(), LEGACY_KEY_ID, &HashMap::new(), false) {
        Ok(random) => {
            let random = KeyRef {
                keyring: Arc::new(random),
                key_id: None,
            };
            ok &= control_must_fail("random key", read_digest(&proof.row, &random).await.is_ok());
        }
        Err(_) => {
            eprintln!("control random key: could not build a random key: FAIL");
            ok = false;
        }
    }

    // 3. A 1-bit-corrupted expected hash must not be accepted
    let corrupted = hash_match(
        &proof.digest,
        &corrupt_hex_one_bit(&proof.row.processed_hash),
        &corrupt_hex_one_bit(&proof.row.id),
    );
    ok &= control_must_fail("corrupted hash", corrupted != HashMatch::Mismatch);

    ok
}

/// DA11: once purge-old has run, the orphan sweep must find nothing
async fn check_orphans_after_purge(mongo: &MongoDb) -> bool {
    let purged = count_docs(mongo, JOURNAL, purged_filter()).await;
    let scans = scan_all_buckets(mongo).await;
    match (purged, scans) {
        (Ok(purged), Ok(scans)) => {
            let orphans: usize = scans.iter().map(|scan| scan.deletable.len()).sum();
            println!("DA11 orphan candidates: {orphans}");
            if purged > 0 && orphans > 0 {
                eprintln!("FAIL: purge-old has run, but {orphans} orphan candidates remain");
                false
            } else {
                true
            }
        }
        (Ok(0), Err(error)) => {
            eprintln!("WARN: orphan scan unavailable ({error}); purge-old has not run, so it does not gate");
            true
        }
        (Ok(_), Err(error)) | (Err(error), _) => {
            eprintln!("FAIL: the orphan check could not run ({error})");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// rollback
// ---------------------------------------------------------------------------

async fn rollback(db: &Database, mongo: &MongoDb) -> i32 {
    let held = match take_lease(mongo, "rollback").await {
        Ok(held) => held,
        Err(code) => return code,
    };
    let code = rollback_under_lease(db, mongo, &held.lease).await;
    held.release().await;
    code
}

/// Swap every migrated, unpurged row back from its journaled NEW triple
/// (never unconditionally), then delete the new object
async fn rollback_under_lease(db: &Database, mongo: &MongoDb, lease: &Lease) -> i32 {
    match count_docs(mongo, JOURNAL, purged_filter()).await {
        Ok(0) => {}
        Ok(purged) => {
            return refuse(&format!(
                "{purged} journal entries have purged_at: their old objects are gone"
            ))
        }
        Err(error) => return refuse(&format!("could not read the journal ({error})")),
    }

    // A pending entry may already be swapped; settle those first
    let resume = reconcile_pending(mongo, lease).await;
    resume.print();

    let entries = match load_journal(mongo, unpurged_migrated_filter()).await {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("FAIL: could not read the journal ({error})");
            return EXIT_FAILED;
        }
    };

    let (mut rolled_back, mut diverged, mut lost_race, mut errors) =
        (0_u64, 0_u64, 0_u64, resume.errors + resume.too_recent);
    for entry in &entries {
        if !lease.held() {
            eprintln!("lease lost; stopping");
            errors += 1;
            break;
        }
        let label = short(&entry.id);
        let (Some(new_iv), Some(new_key_id)) =
            (entry.new_iv.as_deref(), entry.new_key_id.as_deref())
        else {
            eprintln!(
                "hash {label}: DIVERGED (the journal lacks new_iv or new_key_id); left as is"
            );
            diverged += 1;
            continue;
        };

        // Fence, as in migrate: swap back only while the entry is still this
        // migrated, unpurged claim
        match claim_still_current(mongo, &entry.id, STATUS_MIGRATED, &entry.new_path).await {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "hash {label}: lost-race (the journal entry is no longer this migrated, \
                     unpurged claim); not swapped"
                );
                lost_race += 1;
                continue;
            }
            Err(error) => {
                eprintln!("hash {label}: could not re-read the journal entry ({error})");
                errors += 1;
                continue;
            }
        }

        // The old object must still be there, or the swap back would point
        // the row at nothing
        match object_exists_in_s3(&entry.bucket_id, &entry.old_path).await {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "hash {label}: DIVERGED (the old object {} is missing); the row stays on \
                     {new_key_id}",
                    display_key(&entry.old_path)
                );
                diverged += 1;
                continue;
            }
            Err(_) => {
                eprintln!(
                    "hash {label}: could not check the old object {}; not swapped",
                    display_key(&entry.old_path)
                );
                errors += 1;
                continue;
            }
        }

        let swapped = db
            .swap_attachment_hash_storage(
                &entry.id,
                &entry.new_path,
                new_iv,
                Some(new_key_id),
                &entry.old_path,
                &entry.old_iv,
                None,
            )
            .await;
        match swapped {
            Ok(true) => {}
            Ok(false) => match fetch_hash_row(mongo, &entry.id).await {
                // An earlier rollback swapped it but did not journal it
                Ok(Some(row))
                    if row.path == entry.old_path
                        && row.iv == entry.old_iv
                        && row.key_id.is_none() => {}
                Ok(_) => {
                    eprintln!("hash {label}: DIVERGED (the row no longer holds the migrated triple); left as is");
                    diverged += 1;
                    continue;
                }
                Err(error) => {
                    eprintln!("hash {label}: could not re-read the row ({error})");
                    errors += 1;
                    continue;
                }
            },
            Err(error) => {
                eprintln!("hash {label}: swap back failed ({error:?}); re-run rollback");
                errors += 1;
                continue;
            }
        }

        // The row is back on its old object
        rolled_back += 1;
        if !matches!(
            journal_move(
                mongo,
                &entry.id,
                &entry.new_path,
                STATUS_MIGRATED,
                doc! { "status": STATUS_ROLLED_BACK },
            )
            .await,
            Ok(true)
        ) {
            eprintln!("hash {label}: rolled back, but the journal still says migrated");
            errors += 1;
        }
        match delete_if_unreferenced(mongo, &entry.bucket_id, &entry.new_path).await {
            Ok(true) => {}
            Ok(false) => eprintln!("hash {label}: a row references {}; kept", entry.new_path),
            Err(error) => eprintln!("hash {label}: {error}; the orphan sweep removes it later"),
        }
    }

    println!("rolled back: {rolled_back}");
    println!("diverged (left as is): {diverged}");
    println!("lost-race (journal changed; left as is): {lost_race}");
    println!("errors (including pending entries resume left): {errors}");
    if diverged == 0 && lost_race == 0 && errors == 0 {
        EXIT_OK
    } else {
        EXIT_FAILED
    }
}

// ---------------------------------------------------------------------------
// purge-old
// ---------------------------------------------------------------------------

async fn purge_old(mongo: &MongoDb, hash_total: u64, mode: PurgeMode) -> i32 {
    // An empty attachment_hashes makes every stored object look unreferenced
    if let Some(reason) = empty_database_reason(hash_total) {
        return refuse(reason);
    }
    let subcommand = match mode {
        PurgeMode::DryRun => "purge-old --dry-run",
        PurgeMode::Delete { .. } => "purge-old",
    };
    let held = match take_lease(mongo, subcommand).await {
        Ok(held) => held,
        Err(code) => return code,
    };
    let code = purge_under_lease(mongo, &held.lease, mode).await;
    held.release().await;
    code
}

/// The real run deletes only if the plan it recomputed has exactly the
/// total the operator copied from the dry run
fn check_expected_deletes(expected: u64, planned: u64) -> Result<(), String> {
    if expected == planned {
        Ok(())
    } else {
        Err(format!(
            "the plan has {planned} deletions, but --expect-deletes is {expected}; nothing \
             deleted (re-run purge-old --dry-run and review it)"
        ))
    }
}

/// Everything one purge-old run would delete, computed the same way by the
/// dry run and the real run
struct PurgePlan {
    /// Unpurged migrated entries looked at
    entries: usize,
    /// Step 1: entries whose old object is unreferenced
    journaled: Vec<JournalEntry>,
    /// Entries whose old object is still referenced (or looks wrong)
    kept: u64,
    /// Entries that could not be checked; the plan is then incomplete
    errors: u64,
    /// Step 2: the DA11 sweep candidates per bucket
    scans: Vec<BucketScan>,
}

impl PurgePlan {
    fn orphan_total(&self) -> u64 {
        self.scans
            .iter()
            .map(|scan| scan.deletable.len() as u64)
            .sum()
    }

    /// The `--expect-deletes` value: journaled old paths plus orphans, all buckets
    fn delete_total(&self) -> u64 {
        self.journaled.len() as u64 + self.orphan_total()
    }
}

/// Compute the plan. The journaled old paths are excluded from the sweep
/// (unpurged), so nothing is counted twice. Err = the sweep scan failed.
async fn build_purge_plan(mongo: &MongoDb, lease: &Lease) -> Result<PurgePlan, String> {
    let entries = load_journal(mongo, unpurged_migrated_filter()).await?;
    let mut plan = PurgePlan {
        entries: entries.len(),
        journaled: Vec::new(),
        kept: 0,
        errors: 0,
        scans: Vec::new(),
    };
    for entry in entries {
        if !lease.held() {
            eprintln!("lease lost; stopping");
            plan.errors += 1;
            break;
        }
        let label = short(&entry.id);
        if entry.old_path == entry.new_path || entry.old_path.starts_with(E2EE_PREFIX) {
            eprintln!("hash {label}: unexpected journaled old path; kept");
            plan.kept += 1;
            continue;
        }
        match old_object_referenced(mongo, &entry).await {
            Ok(false) => plan.journaled.push(entry),
            Ok(true) => {
                eprintln!("hash {label}: the old object is still referenced; kept");
                plan.kept += 1;
            }
            Err(error) => {
                eprintln!("hash {label}: {error}");
                plan.errors += 1;
            }
        }
    }
    plan.scans = scan_all_buckets(mongo).await?;
    Ok(plan)
}

/// Whether anything still points at a journaled old object
async fn old_object_referenced(mongo: &MongoDb, entry: &JournalEntry) -> Result<bool, String> {
    let rows = count_docs(
        mongo,
        HASHES,
        doc! { "bucket_id": entry.bucket_id.as_str(), "path": entry.old_path.as_str() },
    )
    .await?;
    let sessions = count_docs(mongo, SESSIONS, doc! { "path": entry.old_path.as_str() }).await?;
    Ok(rows > 0 || sessions > 0)
}

/// Step 1 for one entry. `purged_at` is written FIRST, so rollback is refused
/// even if the delete then fails; the references are counted right before
/// the delete [A2], and a reference that appeared in between undoes the mark.
/// Returns whether the old object was deleted.
async fn purge_journaled_old(mongo: &MongoDb, entry: &JournalEntry) -> Result<bool, String> {
    if !journal_move(
        mongo,
        &entry.id,
        &entry.new_path,
        STATUS_MIGRATED,
        doc! { "purged_at": DateTime::now() },
    )
    .await?
    {
        return Err("the journal entry changed".to_string());
    }

    if old_object_referenced(mongo, entry).await? {
        mongo
            .col::<Document>(JOURNAL)
            .update_one(
                claim_filter(&entry.id, &entry.new_path, STATUS_MIGRATED),
                doc! { "$unset": { "purged_at": "" } },
            )
            .await
            .map_err(|error| format!("referenced again, and purged_at stays set ({error})"))?;
        return Ok(false);
    }

    delete_from_s3(&entry.bucket_id, &entry.old_path)
        .await
        .map_err(|_| {
            "delete failed; purged_at is set, so the orphan sweep removes it".to_string()
        })?;
    Ok(true)
}

/// Both modes compute the same plan first. The dry run prints it with the
/// exact `--expect-deletes` value; the real run deletes nothing unless its
/// recomputed total equals that value, then deletes only what the plan holds
/// (each delete re-checked right before it), so it never deletes more than N.
async fn purge_under_lease(mongo: &MongoDb, lease: &Lease, mode: PurgeMode) -> i32 {
    match count_docs(mongo, JOURNAL, doc! { "status": STATUS_PENDING }).await {
        Ok(0) => {}
        Ok(pending) => {
            return refuse(&format!(
                "{pending} pending journal entries; run migrate first (it resumes them)"
            ))
        }
        Err(error) => return refuse(&format!("could not read the journal ({error})")),
    }
    let dry_run = mode == PurgeMode::DryRun;
    if dry_run {
        println!("purge-old: DRY RUN, nothing is deleted");
    }

    let plan = match build_purge_plan(mongo, lease).await {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("FAIL: could not compute the purge plan ({error}); nothing deleted");
            return EXIT_FAILED;
        }
    };

    println!("journaled old objects: {} entries", plan.entries);
    println!("  unreferenced (step 1 deletes): {}", plan.journaled.len());
    println!("  kept: {}", plan.kept);
    println!("  errors: {}", plan.errors);
    if dry_run {
        for entry in plan.journaled.iter().take(EXAMPLE_KEYS) {
            println!("  example: {}", display_key(&entry.old_path));
        }
    }
    println!("DA11 orphan sweep:");
    for scan in &plan.scans {
        print_scan(scan, dry_run);
    }
    let total = plan.delete_total();
    println!(
        "purge plan: {} journaled old objects + {} orphans = {total} deletions",
        plan.journaled.len(),
        plan.orphan_total()
    );
    let mut ok = plan.kept == 0 && plan.errors == 0;

    let expect_deletes = match mode {
        PurgeMode::DryRun => {
            if plan.errors == 0 {
                println!("to delete exactly these: rekey_files purge-old --expect-deletes {total}");
            } else {
                eprintln!(
                    "the plan is incomplete ({} errors); fix them and dry-run again",
                    plan.errors
                );
            }
            return if ok { EXIT_OK } else { EXIT_FAILED };
        }
        PurgeMode::Delete { expect_deletes } => expect_deletes,
    };
    if plan.errors > 0 {
        eprintln!(
            "FAIL: the plan is incomplete ({} errors); nothing deleted",
            plan.errors
        );
        return EXIT_FAILED;
    }
    if let Err(reason) = check_expected_deletes(expect_deletes, total) {
        return refuse(&reason);
    }

    // 1. Journaled old objects, from the plan only
    let (mut deleted, mut kept, mut errors) = (0_u64, 0_u64, 0_u64);
    for entry in &plan.journaled {
        if !lease.held() {
            eprintln!("lease lost; stopping");
            errors += 1;
            break;
        }
        let label = short(&entry.id);
        match purge_journaled_old(mongo, entry).await {
            Ok(true) => deleted += 1,
            Ok(false) => {
                eprintln!("hash {label}: the old object became referenced; kept");
                kept += 1;
            }
            Err(error) => {
                eprintln!("hash {label}: {error}");
                errors += 1;
            }
        }
    }
    println!(
        "journaled old objects: deleted {deleted}, kept (became referenced) {kept}, \
         errors {errors}"
    );
    if kept > 0 || errors > 0 {
        ok = false;
    }

    // 2. DA11 orphan sweeps: rk/ orphans and non-rk/ old-key leftovers, from
    // the plan only
    for scan in &plan.scans {
        println!("  bucket {}:", scan.bucket);
        let (mut swept, mut skipped, mut failed) = (0_u64, 0_u64, 0_u64);
        for (key, _) in &scan.deletable {
            if !lease.held() {
                eprintln!("lease lost; stopping");
                failed += 1;
                break;
            }
            match orphan_still_deletable(mongo, &scan.bucket, key).await {
                Ok(true) => match delete_from_s3(&scan.bucket, key).await {
                    Ok(()) => swept += 1,
                    Err(_) => {
                        eprintln!("could not delete {}", display_key(key));
                        failed += 1;
                    }
                },
                Ok(false) => skipped += 1,
                Err(error) => {
                    eprintln!("could not re-check {} ({error})", display_key(key));
                    failed += 1;
                }
            }
        }
        println!("    swept: {swept}, skipped (became referenced): {skipped}, errors: {failed}");
        if failed > 0 {
            ok = false;
        }
    }

    if ok {
        EXIT_OK
    } else {
        EXIT_FAILED
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap, HashSet};

    use base64::{prelude::BASE64_STANDARD, Engine};
    use revolt_database::mongodb::bson::{doc, Bson};
    use revolt_files::{FileKeyring, SegmentedStreamCipher, CHUNK_SIZE};

    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| arg.to_string()).collect()
    }

    const PIN: &str = "0123456789ab";

    // ---- argument parsing ----

    #[test]
    fn every_subcommand_parses() {
        assert_eq!(
            parse_args(&args(&["check-config"])),
            Ok(Command::CheckConfig)
        );
        assert_eq!(parse_args(&args(&["plan"])), Ok(Command::Plan));
        assert_eq!(parse_args(&args(&["rollback"])), Ok(Command::Rollback));
        assert_eq!(
            parse_args(&args(&["purge-old", "--dry-run"])),
            Ok(Command::PurgeOld(PurgeMode::DryRun))
        );
        assert_eq!(
            parse_args(&args(&["purge-old", "--expect-deletes", "42"])),
            Ok(Command::PurgeOld(PurgeMode::Delete { expect_deletes: 42 }))
        );
        assert_eq!(
            parse_args(&args(&["verify", "--sample", "50"])),
            Ok(Command::Verify(VerifyArgs {
                sample: 50,
                key_file: None
            }))
        );
        assert_eq!(
            parse_args(&args(&[
                "verify",
                "--key-file",
                "/dev/shm/k",
                "--sample",
                "1"
            ])),
            Ok(Command::Verify(VerifyArgs {
                sample: 1,
                key_file: Some("/dev/shm/k".to_string())
            }))
        );
    }

    #[test]
    fn migrate_parses_with_defaults_and_overrides() {
        assert_eq!(
            parse_args(&args(&["migrate", "--expect-new-key-pin", PIN])),
            Ok(Command::Migrate(MigrateArgs {
                expect_new_key_pin: PIN.to_string(),
                concurrency: 4,
                limit: None,
                accept_hash_mismatch: false,
            }))
        );
        assert_eq!(
            parse_args(&args(&[
                "migrate",
                "--concurrency",
                "8",
                "--accept-hash-mismatch",
                "--limit",
                "10",
                "--expect-new-key-pin",
                PIN,
            ])),
            Ok(Command::Migrate(MigrateArgs {
                expect_new_key_pin: PIN.to_string(),
                concurrency: 8,
                limit: Some(10),
                accept_hash_mismatch: true,
            }))
        );
    }

    #[test]
    fn bad_usage_is_rejected() {
        let bad: &[&[&str]] = &[
            &[],
            &["frobnicate"],
            &["plan", "--dry-run"],
            &["check-config", "extra"],
            &["rollback", "--force"],
            &["purge-old", "--dry-run", "--dry-run"],
            &["migrate"],
            &["migrate", "--expect-new-key-pin"],
            &["migrate", "--expect-new-key-pin", "--limit", "1"],
            &["migrate", "--expect-new-key-pin", PIN, "--concurrency", "0"],
            &[
                "migrate",
                "--expect-new-key-pin",
                PIN,
                "--concurrency",
                "17",
            ],
            &["migrate", "--expect-new-key-pin", PIN, "--limit", "0"],
            &["migrate", "--expect-new-key-pin", PIN, "--limit", "-1"],
            &[
                "migrate",
                "--expect-new-key-pin",
                PIN,
                "--expect-new-key-pin",
                PIN,
            ],
            &["verify"],
            &["verify", "--sample"],
            &["verify", "--sample", "many"],
            &["verify", "--sample", "1", "--key-file"],
        ];
        for case in bad {
            assert!(parse_args(&args(case)).is_err(), "{case:?} parsed");
        }
    }

    #[test]
    fn the_real_purge_needs_expect_deletes() {
        // Known-good: a dry run, and a real run with a count (0 included)
        assert_eq!(
            parse_args(&args(&["purge-old", "--dry-run"])),
            Ok(Command::PurgeOld(PurgeMode::DryRun))
        );
        assert_eq!(
            parse_args(&args(&["purge-old", "--expect-deletes", "0"])),
            Ok(Command::PurgeOld(PurgeMode::Delete { expect_deletes: 0 }))
        );
        assert_eq!(
            parse_args(&args(&["purge-old", "--expect-deletes", "3898"])),
            Ok(Command::PurgeOld(PurgeMode::Delete {
                expect_deletes: 3898
            }))
        );

        // Known-bad: the flag missing, without a value, not a number, or
        // combined with --dry-run
        let bad: &[&[&str]] = &[
            &["purge-old"],
            &["purge-old", "--expect-deletes"],
            &["purge-old", "--expect-deletes", "many"],
            &["purge-old", "--expect-deletes", "-1"],
            &["purge-old", "--expect-deletes", "1.5"],
            &["purge-old", "--expect-deletes", ""],
            &[
                "purge-old",
                "--expect-deletes",
                "3",
                "--expect-deletes",
                "3",
            ],
            &["purge-old", "--dry-run", "--expect-deletes", "3"],
            &["purge-old", "--expect-deletes", "3", "--dry-run"],
        ];
        for case in bad {
            assert!(parse_args(&args(case)).is_err(), "{case:?} parsed");
        }
    }

    #[test]
    fn the_real_purge_needs_the_exact_planned_count() {
        assert!(check_expected_deletes(7, 7).is_ok());
        assert!(check_expected_deletes(0, 0).is_ok());
        // Known-bad: one more or one fewer than planned is refused
        assert!(check_expected_deletes(7, 8).is_err());
        assert!(check_expected_deletes(8, 7).is_err());
        // The empty-database case: a big expected count against a plan that
        // saw everything as one huge sweep is refused
        assert!(check_expected_deletes(12, 3891).is_err());
    }

    #[test]
    fn test_db_set_is_refused() {
        // Known-good: unset runs
        assert_eq!(test_db_refusal(None), None);
        // Known-bad: any value, empty included, is refused
        for value in ["REFERENCE", "MONGODB", ""] {
            assert!(
                test_db_refusal(Some(OsStr::new(value))).is_some(),
                "{value:?} not refused"
            );
        }
    }

    #[test]
    fn an_empty_hash_collection_means_the_wrong_database() {
        assert_eq!(
            empty_database_reason(0),
            Some("no attachment_hashes rows: wrong database?")
        );
        // Known-good control: one row is enough
        assert_eq!(empty_database_reason(1), None);
        assert_eq!(empty_database_reason(3898), None);
    }

    fn buckets(list: &[&str]) -> Vec<String> {
        list.iter().map(|bucket| bucket.to_string()).collect()
    }

    #[test]
    fn the_scratch_age_override_is_honored_for_scratch_buckets_only() {
        // Unset: the 24 h default, whatever the buckets
        assert_eq!(
            resolve_orphan_min_age(None, &buckets(&["revolt-uploads"])),
            Ok(OrphanMinAge::Default)
        );
        assert_eq!(OrphanMinAge::Default.secs(), 24 * 60 * 60);

        // Set, every bucket a scratch bucket: honored
        assert_eq!(
            resolve_orphan_min_age(Some("0"), &buckets(&["rekey-e2e-a"])),
            Ok(OrphanMinAge::ScratchOverride(0))
        );
        assert_eq!(
            resolve_orphan_min_age(Some("90"), &buckets(&["rekey-e2e-a", "rekey-e2e-b"])),
            Ok(OrphanMinAge::ScratchOverride(90))
        );
        assert_eq!(OrphanMinAge::ScratchOverride(90).secs(), 90);

        // Known-bad: any non-scratch bucket refuses, the prod one included
        for list in [
            &["revolt-uploads"][..],
            &["rekey-e2e-a", "revolt-uploads"][..],
            &["revolt-uploads", "rekey-e2e-a"][..],
            &["xrekey-e2e-a"][..],
            &["rekey-e2e"][..],
            &[][..],
        ] {
            assert!(
                resolve_orphan_min_age(Some("90"), &buckets(list)).is_err(),
                "{list:?} honored"
            );
        }

        // Known-bad: a value that is not a non-negative whole number
        for value in ["-1", "1.5", "", "24h", " 90"] {
            assert!(
                resolve_orphan_min_age(Some(value), &buckets(&["rekey-e2e-a"])).is_err(),
                "{value:?} accepted"
            );
        }
    }

    #[test]
    fn the_age_guard_follows_the_resolved_minimum() {
        let ex = exclusions();
        let lowered = OrphanMinAge::ScratchOverride(60).secs();
        assert_eq!(
            orphan_verdict("rk/k1/NEW", Some(NOW - 61), NOW, lowered, &ex),
            OrphanVerdict::Delete(OrphanClass::Rk)
        );
        // Known-bad control: the same object under the default is kept
        assert_eq!(
            orphan_verdict(
                "rk/k1/NEW",
                Some(NOW - 61),
                NOW,
                OrphanMinAge::Default.secs(),
                &ex
            ),
            OrphanVerdict::Keep(KeepReason::TooYoung)
        );
        // Every other exclusion still holds under the override
        assert_eq!(
            orphan_verdict("chunked/S1", OLD, NOW, 0, &ex),
            OrphanVerdict::Keep(KeepReason::UploadSession)
        );
        assert_eq!(
            orphan_verdict("e2ee_01HBLOB", OLD, NOW, 0, &ex),
            OrphanVerdict::Keep(KeepReason::E2eeBlob)
        );
        assert_eq!(
            orphan_verdict("rk/k1/NEW", None, NOW, 0, &ex),
            OrphanVerdict::Keep(KeepReason::UnknownAge)
        );
    }

    #[test]
    fn a_swap_needs_the_entry_to_still_be_this_claim() {
        let ours = doc! { "_id": "abc", "status": "pending", "new_path": "rk/k1/A" };
        assert!(claim_is_current(Some(&ours), STATUS_PENDING, "rk/k1/A"));
        let migrated = doc! {
            "_id": "abc",
            "status": "migrated",
            "new_path": "rk/k1/A",
            "purged_at": Bson::Null,
        };
        assert!(claim_is_current(
            Some(&migrated),
            STATUS_MIGRATED,
            "rk/k1/A"
        ));

        // Known-bad: dropped by another run's resume, re-claimed under a new
        // path, settled to another status, or purged
        assert!(!claim_is_current(None, STATUS_PENDING, "rk/k1/A"));
        assert!(!claim_is_current(Some(&ours), STATUS_PENDING, "rk/k1/B"));
        assert!(!claim_is_current(Some(&ours), STATUS_MIGRATED, "rk/k1/A"));
        let lost = doc! { "_id": "abc", "status": "lost-race", "new_path": "rk/k1/A" };
        assert!(!claim_is_current(Some(&lost), STATUS_PENDING, "rk/k1/A"));
        let purged = doc! {
            "_id": "abc",
            "status": "migrated",
            "new_path": "rk/k1/A",
            "purged_at": DateTime::from_millis(1),
        };
        assert!(!claim_is_current(Some(&purged), STATUS_MIGRATED, "rk/k1/A"));
        let no_path = doc! { "_id": "abc", "status": "pending" };
        assert!(!claim_is_current(Some(&no_path), STATUS_PENDING, "rk/k1/A"));
    }

    #[test]
    fn resume_leaves_recent_or_undated_pending_entries_alone() {
        let now = 10_000_000_000_i64;
        assert_eq!(RESUME_MIN_AGE_MS, 10 * 60 * 1000);
        // Known-good: quiet for more than two lease lifetimes
        assert!(pending_entry_settleable(
            Some(now - RESUME_MIN_AGE_MS - 1),
            now
        ));
        assert!(pending_entry_settleable(Some(0), now));
        // Known-bad: just written, exactly at the boundary, from the future
        // (clock skew), or undated
        assert!(!pending_entry_settleable(Some(now), now));
        assert!(!pending_entry_settleable(
            Some(now - RESUME_MIN_AGE_MS),
            now
        ));
        assert!(!pending_entry_settleable(Some(now + 60_000), now));
        assert!(!pending_entry_settleable(None, now));

        // A freshly written pending entry carries a readable updated_at
        let row = HashRow {
            id: "hash".to_string(),
            processed_hash: "processed".to_string(),
            bucket_id: "bucket".to_string(),
            path: "hash".to_string(),
            iv: "iv".to_string(),
            key_id: None,
            format_version: None,
            size: Some(3),
        };
        let entry = JournalEntry::from_doc(&pending_entry(&row, "rk/k1/X", "k1"))
            .expect("a pending entry parses");
        let written = entry.updated_at_ms.expect("updated_at is a date");
        assert!(!pending_entry_settleable(Some(written), written + 1));
        assert!(pending_entry_settleable(
            Some(written),
            written + RESUME_MIN_AGE_MS + 1
        ));
    }

    #[test]
    fn quarantine_retry_follows_the_reason_and_the_flag() {
        // fetch-failed: retried with or without the flag
        assert!(quarantine_retryable(Some(REASON_FETCH), false));
        assert!(quarantine_retryable(Some(REASON_FETCH), true));
        // hash-mismatch: retried only under --accept-hash-mismatch
        assert!(quarantine_retryable(Some(REASON_HASH_MISMATCH), true));
        // Known-bad: hash-mismatch without the flag stays settled
        assert!(!quarantine_retryable(Some(REASON_HASH_MISMATCH), false));
        // Known-bad: decrypt-failed, v2-layout, an unknown reason and no
        // reason are settled always
        for accept in [false, true] {
            for reason in [REASON_DECRYPT, REASON_V2_LAYOUT, "something-else"] {
                assert!(
                    !quarantine_retryable(Some(reason), accept),
                    "{reason} retried (accept={accept})"
                );
            }
            assert!(!quarantine_retryable(None, accept));
        }
        assert_eq!(retryable_reasons(false), vec!["fetch-failed"]);
        assert_eq!(
            retryable_reasons(true),
            vec!["fetch-failed", "hash-mismatch"]
        );
    }

    #[test]
    fn the_selection_and_claim_filters_encode_the_retry_rule() {
        // Without the flag: only fetch-failed is retryable
        assert_eq!(
            retryable_quarantine_filter(false),
            doc! { "status": "quarantine", "reason": { "$in": ["fetch-failed"] } }
        );
        assert_eq!(
            settled_filter(false),
            doc! {
                "$or": [
                    { "status": "migrated" },
                    { "status": "quarantine", "reason": { "$nin": ["fetch-failed"] } },
                ]
            }
        );
        // With the flag: hash-mismatch joins it, in the selection and the claim
        assert_eq!(
            settled_filter(true),
            doc! {
                "$or": [
                    { "status": "migrated" },
                    {
                        "status": "quarantine",
                        "reason": { "$nin": ["fetch-failed", "hash-mismatch"] },
                    },
                ]
            }
        );
        assert_eq!(
            pending_claim_filter("abc", true),
            doc! {
                "_id": "abc",
                "$or": [
                    { "status": { "$nin": ["pending", "migrated", "quarantine"] } },
                    {
                        "status": "quarantine",
                        "reason": { "$in": ["fetch-failed", "hash-mismatch"] },
                    },
                ],
            }
        );
        // Known-bad: without the flag neither filter admits hash-mismatch,
        // and no filter ever admits decrypt-failed or v2-layout
        let admitted = |filter: Document| -> Vec<String> {
            let reasons = filter
                .get_document("reason")
                .and_then(|reason| reason.get_array("$in"))
                .expect("$in list");
            reasons
                .iter()
                .filter_map(|reason| reason.as_str().map(str::to_string))
                .collect()
        };
        assert!(!admitted(retryable_quarantine_filter(false)).contains(&"hash-mismatch".into()));
        for accept in [false, true] {
            let reasons = admitted(retryable_quarantine_filter(accept));
            assert!(!reasons.contains(&REASON_DECRYPT.to_string()));
            assert!(!reasons.contains(&REASON_V2_LAYOUT.to_string()));
            // The retry keeps status "quarantine" (the probe excludes by status)
            assert_eq!(
                retryable_quarantine_filter(accept).get_str("status"),
                Ok(STATUS_QUARANTINE)
            );
        }
    }

    #[test]
    fn migrate_exits_zero_only_with_no_quarantine_anywhere() {
        assert_eq!(migrate_exit_code(Some(0), true), EXIT_OK);
        // Known-bad: a quarantine left by ANY run (the E2E's re-run saw 2
        // outstanding with 0 quarantined this run), a lost race or error this
        // run, or an unreadable count
        assert_eq!(migrate_exit_code(Some(2), true), EXIT_FAILED);
        assert_eq!(migrate_exit_code(Some(1), true), EXIT_FAILED);
        assert_eq!(migrate_exit_code(Some(0), false), EXIT_FAILED);
        assert_eq!(migrate_exit_code(None, true), EXIT_FAILED);

        let tally = MigrateTally::default();
        assert!(tally.run_clean());
        let lost = MigrateTally {
            lost_race: 1,
            ..MigrateTally::default()
        };
        assert!(!lost.run_clean());
        let errored = MigrateTally {
            errors: 1,
            ..MigrateTally::default()
        };
        assert!(!errored.run_clean());
        let stale = MigrateTally {
            journal_stale: 1,
            ..MigrateTally::default()
        };
        assert!(!stale.run_clean());
    }

    #[test]
    fn selectable_legacy_rows_exclude_settled_ids() {
        let set = |items: &[&str]| -> HashSet<String> {
            items.iter().map(|item| item.to_string()).collect()
        };
        assert_eq!(selectable_count(&set(&["a", "b", "c"]), &set(&["b"])), 2);
        assert_eq!(selectable_count(&set(&["a"]), &set(&["a", "z"])), 0);
        // Known-bad: settled ids that are not legacy rows do not subtract
        assert_eq!(selectable_count(&set(&["a", "b"]), &set(&["x", "y"])), 2);
    }

    #[test]
    fn large_or_unsized_v1_rows_take_every_worker() {
        let big = LARGE_V1_BYTES + 1;
        // Known-good: small v1, a v1 at the limit, any v2
        assert_eq!(row_permits(None, Some(1), 4), 1);
        assert_eq!(row_permits(None, Some(LARGE_V1_BYTES), 4), 1);
        assert_eq!(row_permits(Some(2), Some(big * 8), 4), 1);
        // Known-bad: a v1 over 256 MiB, or of unknown size, runs alone
        assert_eq!(row_permits(None, Some(big), 4), 4);
        assert_eq!(row_permits(None, Some(big), 16), 16);
        assert_eq!(row_permits(None, None, 4), 4);

        // While a large row holds its permits nothing else starts; a small
        // row leaves room for the others
        let workers = Semaphore::new(4);
        let large = workers
            .try_acquire_many(row_permits(None, Some(big), 4))
            .expect("all permits free");
        assert!(workers.try_acquire().is_err());
        drop(large);
        let small = workers
            .try_acquire_many(row_permits(None, Some(1), 4))
            .expect("a permit is free");
        assert!(workers.try_acquire_many(3).is_ok());
        drop(small);
    }

    #[test]
    fn the_new_key_pin_must_be_a_fingerprint() {
        // Known-good control first, so the rejections below are not vacuous
        assert!(parse_args(&args(&["migrate", "--expect-new-key-pin", PIN])).is_ok());
        for pin in [
            "0123456789a",
            "0123456789abc",
            "0123456789AB",
            "0123456789ag",
            "",
        ] {
            assert!(
                parse_args(&args(&["migrate", "--expect-new-key-pin", pin])).is_err(),
                "{pin:?} accepted"
            );
        }
    }

    #[test]
    fn usage_errors_never_echo_an_argument() {
        let secret = "XkbJ8gBzrouQ+15Ri23xCC81+aZE26Z6+gXzglFxOD4=";
        for case in [
            vec!["plan", secret],
            vec![secret],
            vec!["migrate", "--expect-new-key-pin", secret],
        ] {
            let error = parse_args(&args(&case)).expect_err("must not parse");
            assert!(!error.contains(secret), "{error}");
        }
    }

    // ---- hash rules ----

    #[test]
    fn composite_hash_matches_an_independent_vector() {
        // Computed with python's hashlib: sha256(b"sloga-chunked-v2" +
        // pack("<q", CHUNK) + pack("<q", CHUNK + 1000) + hex(p1) + hex(p2))
        let parts = vec![
            "0543cf94c5dce225bc7708829029e777b6a73381cda354ca07bd81199e4ddcca".to_string(),
            "2bb41b3bc344d2a5c1f31d662d86d78d7e98198b1eef7be3209d4f85da4ef14d".to_string(),
        ];
        assert_eq!(parts[0], sha256_hex(b"part-1"));
        assert_eq!(parts[1], sha256_hex(b"part-2"));
        let chunk = CHUNK_SIZE as i64;
        assert_eq!(
            composite_hash_v2(chunk, chunk + 1000, &parts),
            "71ca0c7bc0e6f6471a9346a482a49a295913ec5a4605d31913924627d85c8896"
        );

        // Known-bad controls: a 1-byte-different total size, and a part
        // hash with one changed character, give different composites
        assert_eq!(
            composite_hash_v2(chunk, chunk + 1001, &parts),
            "acef97467d3d925c2deae916716b643e0893b2034ea65b3ac51c01746b3635a0"
        );
        let mut changed = parts.clone();
        changed[1] = corrupt_hex_one_bit(&changed[1]);
        assert_ne!(
            composite_hash_v2(chunk, chunk + 1000, &changed),
            "71ca0c7bc0e6f6471a9346a482a49a295913ec5a4605d31913924627d85c8896"
        );
    }

    #[test]
    fn the_hash_rule_accepts_processed_or_own_id_only() {
        let digest = sha256_hex(b"hello");
        assert_eq!(
            digest,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(
            hash_match(&digest, &digest, "other-id"),
            HashMatch::Processed
        );
        assert_eq!(
            hash_match(&digest, "stale-processed", &digest),
            HashMatch::OwnId
        );
        assert_eq!(
            hash_match(&digest, "stale-processed", "other-id"),
            HashMatch::Mismatch
        );
        // Known-bad control: one flipped bit in either recorded hash is a mismatch
        assert_eq!(
            hash_match(
                &digest,
                &corrupt_hex_one_bit(&digest),
                &corrupt_hex_one_bit(&digest)
            ),
            HashMatch::Mismatch
        );
    }

    #[test]
    fn corrupting_a_hash_flips_exactly_one_bit_and_stays_hex() {
        let digest = sha256_hex(b"hello");
        let corrupted = corrupt_hex_one_bit(&digest);
        assert_ne!(corrupted, digest);
        assert_eq!(corrupted.len(), digest.len());
        assert!(corrupted.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let (a, b) = (
            u8::from_str_radix(&digest[63..], 16).unwrap(),
            u8::from_str_radix(&corrupted[63..], 16).unwrap(),
        );
        assert_eq!((a ^ b).count_ones(), 1);
        assert_eq!(&corrupted[..63], &digest[..63]);
        assert_ne!(corrupt_hex_one_bit(""), "");
    }

    // ---- v2 layout and the [A25] equal-part assertion ----

    #[test]
    fn v2_parts_are_full_chunks_then_the_tail() {
        let chunk = CHUNK_SIZE as u64;
        assert_eq!(
            v2_part_sizes(CHUNK_SIZE as i64 + 1000),
            Ok(vec![chunk, 1000])
        );
        assert_eq!(v2_part_sizes(2 * CHUNK_SIZE as i64), Ok(vec![chunk, chunk]));
        assert_eq!(v2_part_sizes(5), Ok(vec![5]));
        assert!(v2_part_sizes(0).is_err());
        assert!(v2_part_sizes(-1).is_err());
        assert!(v2_part_sizes(CHUNK_SIZE as i64 * 10_001).is_err());
    }

    #[test]
    fn equal_part_assertion_rejects_unequal_parts() {
        // Known-good: full non-final parts and a short tail
        assert!(check_upload_part(1, 3, CHUNK_SIZE).is_ok());
        assert!(check_upload_part(2, 3, CHUNK_SIZE).is_ok());
        assert!(check_upload_part(3, 3, 1).is_ok());
        assert!(check_upload_part(1, 1, CHUNK_SIZE).is_ok());

        // Known-bad: a non-final part one byte short or long (MinIO accepts
        // this; R2 rejects it at complete)
        assert!(check_upload_part(1, 3, CHUNK_SIZE - 1).is_err());
        assert!(check_upload_part(2, 3, CHUNK_SIZE + 1).is_err());
        // A final part that is empty or over a chunk
        assert!(check_upload_part(3, 3, 0).is_err());
        assert!(check_upload_part(3, 3, CHUNK_SIZE + 1).is_err());
        // Out of range
        assert!(check_upload_part(0, 3, CHUNK_SIZE).is_err());
        assert!(check_upload_part(4, 3, 1).is_err());
    }

    #[test]
    fn ciphertext_length_matches_the_stream_cipher() {
        let keyring = FileKeyring::from_parts(
            &BASE64_STANDARD.encode([7u8; 32]),
            "legacy",
            &HashMap::new(),
            false,
        )
        .expect("valid test keyring");
        let cipher = SegmentedStreamCipher::from_cipher(keyring.primary_cipher(), [1; 7]);
        for len in [
            1_u64,
            1024 * 1024,
            1024 * 1024 + 1,
            CHUNK_SIZE as u64,
            CHUNK_SIZE as u64 * 3 + 5,
        ] {
            assert_eq!(ciphertext_len_of(len), cipher.ciphertext_len(len), "{len}");
        }
        // Control: one tag per started segment, so one byte past a segment adds a tag
        assert_eq!(
            ciphertext_len_of(1024 * 1024 + 1) - ciphertext_len_of(1024 * 1024),
            1 + 16
        );
    }

    #[test]
    fn the_nonce_prefix_must_be_seven_bytes_of_base64() {
        assert_eq!(
            decode_prefix(&BASE64_STANDARD.encode([9u8; 7])),
            Ok([9u8; 7])
        );
        assert!(decode_prefix(&BASE64_STANDARD.encode([9u8; 6])).is_err());
        assert!(decode_prefix(&BASE64_STANDARD.encode([9u8; 12])).is_err());
        assert!(decode_prefix("not base64!").is_err());
        assert!(V2Layout::of(&BASE64_STANDARD.encode([9u8; 7]), None).is_err());
        assert!(V2Layout::of(&BASE64_STANDARD.encode([9u8; 7]), Some(10)).is_ok());
    }

    #[test]
    fn random_keys_are_valid_and_distinct() {
        let (a, b) = (random_key_b64(), random_key_b64());
        assert_ne!(a, b);
        assert_eq!(BASE64_STANDARD.decode(&a).map(|key| key.len()), Ok(32));
        assert!(FileKeyring::from_parts(&a, "legacy", &HashMap::new(), false).is_ok());
    }

    // ---- predicates (identical to the autumn guard) ----

    #[test]
    fn the_predicates_match_the_guard() {
        assert_eq!(
            legacy_row_filter(),
            doc! { "key_id": Bson::Null, "iv": { "$ne": "" } }
        );
        assert_eq!(named_row_filter(), doc! { "key_id": { "$ne": Bson::Null } });
        assert_eq!(
            live_session_filter(),
            doc! { "state": { "$in": ["Pending", "Completing"] } }
        );
    }

    #[test]
    fn a_settled_row_is_never_claimed_again() {
        // A pending, migrated or quarantined entry blocks a claim, except a
        // fetch-failed quarantine, which a later run may re-claim (replace)
        assert_eq!(
            pending_claim_filter("abc", false),
            doc! {
                "_id": "abc",
                "$or": [
                    { "status": { "$nin": ["pending", "migrated", "quarantine"] } },
                    { "status": "quarantine", "reason": { "$in": ["fetch-failed"] } },
                ],
            }
        );
    }

    #[test]
    fn journal_writes_are_pinned_to_one_claim() {
        assert_eq!(
            claim_filter("abc", "rk/k1/A", "pending"),
            doc! { "_id": "abc", "new_path": "rk/k1/A", "status": "pending" }
        );
        // Control: a later claim of the same row (new ULID path) is a different filter
        assert_ne!(
            claim_filter("abc", "rk/k1/A", "pending"),
            claim_filter("abc", "rk/k1/B", "pending")
        );
    }

    #[test]
    fn the_lease_is_taken_only_once_expired_and_never_has_a_status() {
        assert_eq!(
            lease_acquire_filter(1_000),
            doc! { "_id": "__lease__", "expires_at": { "$lt": DateTime::from_millis(1_000) } }
        );
        let update = lease_take_update("host:1", "migrate", 2_000);
        let set = update.get_document("$set").expect("$set");
        assert_eq!(set.get_str("holder"), Ok("host:1"));
        assert!(!set.contains_key("status"));
        assert!(!lease_acquire_filter(1_000).contains_key("status"));
    }

    #[test]
    fn the_pending_entry_carries_the_old_triple_and_the_new_path() {
        let row = HashRow {
            id: "hash".to_string(),
            processed_hash: "processed".to_string(),
            bucket_id: "bucket".to_string(),
            path: "hash".to_string(),
            iv: "iv".to_string(),
            key_id: None,
            format_version: None,
            size: Some(3),
        };
        let entry = pending_entry(&row, "rk/k1/X", "k1");
        assert_eq!(entry.get_str("status"), Ok("pending"));
        assert_eq!(entry.get_str("old_path"), Ok("hash"));
        assert_eq!(entry.get_str("old_iv"), Ok("iv"));
        assert_eq!(entry.get("old_key_id"), Some(&Bson::Null));
        assert_eq!(entry.get_str("new_path"), Ok("rk/k1/X"));
        assert_eq!(entry.get_str("new_key_id"), Ok("k1"));
        assert!(!entry.contains_key("new_iv"));
        assert!(!entry.contains_key("purged_at"));
    }

    #[test]
    fn display_key_truncates_hash_ids_only() {
        assert_eq!(display_key("rk/k1/01ABC"), "rk/k1/01ABC");
        assert_eq!(display_key("chunked/01ABC"), "chunked/01ABC");
        assert_eq!(
            display_key("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
            "2cf24dba5fb0..."
        );
    }

    // ---- orphan predicate (DA11) ----

    const NOW: i64 = 2_000_000_000;
    const OLD: Option<i64> = Some(NOW - 2 * ORPHAN_MIN_AGE_SECS);
    /// The default orphan age guard
    const DAY: i64 = ORPHAN_MIN_AGE_SECS;

    fn exclusions() -> OrphanExclusions {
        fn set(items: &[&str]) -> HashSet<String> {
            items.iter().map(|item| item.to_string()).collect()
        }
        OrphanExclusions {
            referenced: set(&["aaaa", "rk/k1/LIVE"]),
            session_paths: set(&["chunked/S1"]),
            pending_new_paths: set(&["rk/k1/PENDING"]),
            unpurged_old_paths: set(&["bbbb"]),
        }
    }

    #[test]
    fn unreferenced_old_objects_are_swept_in_every_class() {
        let ex = exclusions();
        assert_eq!(
            orphan_verdict("rk/k1/ORPHAN", OLD, NOW, DAY, &ex),
            OrphanVerdict::Delete(OrphanClass::Rk)
        );
        assert_eq!(
            orphan_verdict("chunked/S2", OLD, NOW, DAY, &ex),
            OrphanVerdict::Delete(OrphanClass::Chunked)
        );
        assert_eq!(
            orphan_verdict("cccc", OLD, NOW, DAY, &ex),
            OrphanVerdict::Delete(OrphanClass::Other)
        );
    }

    #[test]
    fn referenced_objects_are_kept() {
        let ex = exclusions();
        assert_eq!(
            orphan_verdict("aaaa", OLD, NOW, DAY, &ex),
            OrphanVerdict::Keep(KeepReason::Referenced)
        );
        assert_eq!(
            orphan_verdict("rk/k1/LIVE", OLD, NOW, DAY, &ex),
            OrphanVerdict::Keep(KeepReason::Referenced)
        );
        // Known-bad control: a near-identical unreferenced key is swept
        assert_eq!(
            orphan_verdict("aaab", OLD, NOW, DAY, &ex),
            OrphanVerdict::Delete(OrphanClass::Other)
        );
    }

    #[test]
    fn e2ee_blobs_are_kept() {
        let ex = exclusions();
        assert_eq!(
            orphan_verdict("e2ee_01HBLOB", OLD, NOW, DAY, &ex),
            OrphanVerdict::Keep(KeepReason::E2eeBlob)
        );
        // Control: the prefix must be at the start
        assert_eq!(
            orphan_verdict("xe2ee_01HBLOB", OLD, NOW, DAY, &ex),
            OrphanVerdict::Delete(OrphanClass::Other)
        );
    }

    #[test]
    fn upload_session_paths_are_kept_by_exact_match_only() {
        let ex = exclusions();
        assert_eq!(
            orphan_verdict("chunked/S1", OLD, NOW, DAY, &ex),
            OrphanVerdict::Keep(KeepReason::UploadSession)
        );
        // Control: not a prefix rule; pre-rotation chunked/ orphans are swept
        assert_eq!(
            orphan_verdict("chunked/S1x", OLD, NOW, DAY, &ex),
            OrphanVerdict::Delete(OrphanClass::Chunked)
        );
        assert_eq!(
            orphan_verdict("chunked/S", OLD, NOW, DAY, &ex),
            OrphanVerdict::Delete(OrphanClass::Chunked)
        );
    }

    #[test]
    fn pending_new_paths_are_kept() {
        let ex = exclusions();
        assert_eq!(
            orphan_verdict("rk/k1/PENDING", OLD, NOW, DAY, &ex),
            OrphanVerdict::Keep(KeepReason::PendingNewPath)
        );
        assert_eq!(
            orphan_verdict("rk/k1/PENDING2", OLD, NOW, DAY, &ex),
            OrphanVerdict::Delete(OrphanClass::Rk)
        );
    }

    #[test]
    fn unpurged_old_paths_are_kept_for_rollback() {
        let ex = exclusions();
        assert_eq!(
            orphan_verdict("bbbb", OLD, NOW, DAY, &ex),
            OrphanVerdict::Keep(KeepReason::UnpurgedOldPath)
        );
        let empty = OrphanExclusions::default();
        assert_eq!(
            orphan_verdict("bbbb", OLD, NOW, DAY, &empty),
            OrphanVerdict::Delete(OrphanClass::Other)
        );
    }

    #[test]
    fn young_or_undated_objects_are_kept() {
        let ex = exclusions();
        let day = ORPHAN_MIN_AGE_SECS;
        assert_eq!(
            orphan_verdict("rk/k1/NEW", Some(NOW - day + 60), NOW, DAY, &ex),
            OrphanVerdict::Keep(KeepReason::TooYoung)
        );
        assert_eq!(
            orphan_verdict("rk/k1/NEW", Some(NOW - day), NOW, DAY, &ex),
            OrphanVerdict::Keep(KeepReason::TooYoung)
        );
        assert_eq!(
            orphan_verdict("rk/k1/NEW", Some(NOW + 3600), NOW, DAY, &ex),
            OrphanVerdict::Keep(KeepReason::TooYoung)
        );
        assert_eq!(
            orphan_verdict("rk/k1/NEW", None, NOW, DAY, &ex),
            OrphanVerdict::Keep(KeepReason::UnknownAge)
        );
        // Control: one second past 24 h is swept
        assert_eq!(
            orphan_verdict("rk/k1/NEW", Some(NOW - day - 1), NOW, DAY, &ex),
            OrphanVerdict::Delete(OrphanClass::Rk)
        );
    }

    // ---- guard and probe (mirroring autumn main.rs) ----

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
        ]);
        match verdict {
            ProbeOutcome::Fail { attempts } => assert_eq!(attempts.len(), 2),
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
