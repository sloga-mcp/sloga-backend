//! One-off ops tool: re-upload an attachment's S3 blob from a local copy of
//! the ORIGINAL bytes and point its FileHash row at the fresh object —
//! healing a row whose stored nonce no longer matches the encrypted blob
//! (e.g. something re-encrypted the blob but wrote the nonce elsewhere).
//!
//! The bytes go to a fresh `rk/<key_id|legacy>/<ulid>` object under the
//! primary file key; the row's path, nonce and key id are set together. The
//! previous object is never overwritten; it is deleted (best effort) only
//! after the row points at the new one. v2 (chunked) rows are refused.
//!
//! Content-addressed safety: refuses to run unless sha256(file) equals the
//! attachment's hash id, so it can only ever restore the exact bytes the row
//! was created from. Same sanctioned pattern as `seed_stickers`.
//!
//! Usage: heal_attachment_blob <attachment_id> <original_file_path>
//! Run from the stoatchat root so Revolt.toml / Revolt.overrides.toml resolve.

use revolt_database::{DatabaseInfo, FileHash};
use revolt_files::{
    delete_from_s3, upload_to_s3, FileKeyring, COMMITTED_DEFAULT_KEY_FP, LEGACY_KEY_ID,
};
use sha2::Digest;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let attachment_id = args
        .next()
        .expect("usage: heal_attachment_blob <attachment_id> <original_file_path>");
    let file_path = args.next().expect("missing original file path");

    // Build the file keyring before any work, so a bad key config stops the
    // tool here with the failed rule (never a key value)
    let keyring = match FileKeyring::init_global().await {
        Ok(keyring) => keyring,
        Err(error) => {
            eprintln!("file keyring config is invalid: {error:#}");
            std::process::exit(1);
        }
    };
    println!(
        "file keyring: primary={}",
        keyring.primary_id().unwrap_or(LEGACY_KEY_ID)
    );
    for id in keyring.key_ids() {
        let key_id = (id != LEGACY_KEY_ID).then_some(id.as_str());
        match keyring.fingerprint(key_id) {
            Ok(fingerprint) => println!("file keyring: id={id} fingerprint={fingerprint}"),
            Err(error) => println!("file keyring: id={id} fingerprint unavailable: {error:#}"),
        }
    }
    if keyring
        .fingerprint(keyring.primary_id())
        .is_ok_and(|fingerprint| fingerprint == COMMITTED_DEFAULT_KEY_FP)
    {
        eprintln!(
            "WARN: files.encryption_key is upstream's committed default; \
             anyone with the bucket can decrypt"
        );
    }

    let db = DatabaseInfo::Auto.connect().await.expect("database");

    let attachment = db
        .fetch_attachment("stickers", &attachment_id)
        .await
        .expect("fetch attachment");
    let hash = db
        .fetch_attachment_hash(&attachment.hash.clone().expect("attachment has no hash"))
        .await
        .expect("fetch attachment hash");

    // This tool writes v1 whole-file objects only; pointing a segmented (v2)
    // row at one would leave the row unreadable
    if let Some(version) = hash.format_version {
        eprintln!(
            "REFUSING: hash {} has format_version {version} (chunked upload); \
             this tool only heals v1 whole-file rows",
            hash.id
        );
        std::process::exit(1);
    }

    let buf = std::fs::read(&file_path).expect("read original file");
    let digest = format!("{:02x}", sha2::Sha256::digest(&buf));
    assert_eq!(
        digest, hash.id,
        "REFUSING: file content does not match the row's content hash — this tool \
         may only restore the exact original bytes"
    );

    println!(
        "healing hash {} in bucket {} ({} bytes)",
        hash.id,
        hash.bucket_id,
        buf.len()
    );

    // One keyring snapshot for the whole write: the object path, the
    // encryption key and the row's key id must all name the same key
    let kid: Option<String> = keyring.primary_id().map(str::to_string);
    let path = FileHash::new_object_path(kid.as_deref());

    // The row's current object, captured before anything is written
    let old_bucket_id = hash.bucket_id.clone();
    let old_path = hash.path.clone();

    let (iv, rkid) = upload_to_s3(&hash.bucket_id, &path, &buf)
        .await
        .expect("s3 upload");
    if rkid != kid {
        eprintln!(
            "upload was encrypted under key {}, expected {}; not pointing the row at it",
            rkid.as_deref().unwrap_or(LEGACY_KEY_ID),
            kid.as_deref().unwrap_or(LEGACY_KEY_ID)
        );
        delete_new_object(&hash.bucket_id, &path).await;
        std::process::exit(1);
    }

    if let Err(error) = db
        .set_attachment_hash_storage(&hash.id, &path, &iv, rkid.as_deref())
        .await
    {
        eprintln!("set storage failed: {error:?}");
        delete_new_object(&hash.bucket_id, &path).await;
        std::process::exit(1);
    }

    // Now that the row points at the new object, delete the broken blob it
    // replaced. Nothing else references it: a hash-id path belongs to its
    // own row only and an `rk/` path is unique by ULID. Neither the migrator
    // journal nor its `rk/` orphan sweep would ever find an old hash-id
    // object, so leaving it would leak old-key ciphertext past the purge.
    let old_kind = if old_path == hash.id {
        "hash-id path"
    } else if old_path.starts_with("rk/") {
        "rk/ path"
    } else {
        "other path"
    };
    let hash_prefix = hash.id.get(..12).unwrap_or(hash.id.as_str());
    if old_bucket_id != hash.bucket_id || old_path != path {
        match delete_from_s3(&old_bucket_id, &old_path).await {
            Ok(()) => println!("old object deleted: {old_kind} of hash {hash_prefix}…"),
            Err(error) => eprintln!(
                "WARN: failed to delete the old object {old_path} ({old_kind} of hash \
                 {hash_prefix}…) in bucket {old_bucket_id}: {error:?}; delete it by hand"
            ),
        }
    }

    println!(
        "done — blob re-uploaded to a fresh object under key {}; path, nonce and \
         key id updated together.",
        kid.as_deref().unwrap_or(LEGACY_KEY_ID)
    );
}

/// Best-effort delete of the object this run just wrote, before exiting
async fn delete_new_object(bucket_id: &str, path: &str) {
    if let Err(error) = delete_from_s3(bucket_id, path).await {
        eprintln!(
            "failed to delete the new object {path} in bucket {bucket_id}: {error:?}; \
             delete it by hand"
        );
    }
}
