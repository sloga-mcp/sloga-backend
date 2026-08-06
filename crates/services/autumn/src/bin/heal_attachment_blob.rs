//! One-off ops tool: re-upload an attachment's S3 blob from a local copy of
//! the ORIGINAL bytes and stamp the fresh nonce onto its FileHash row —
//! healing a row whose stored nonce no longer matches the encrypted blob
//! (e.g. something re-encrypted the blob but wrote the nonce elsewhere).
//!
//! Content-addressed safety: refuses to run unless sha256(file) equals the
//! attachment's hash id, so it can only ever restore the exact bytes the row
//! was created from. Same sanctioned pattern as `seed_stickers`.
//!
//! Usage: heal_attachment_blob <attachment_id> <original_file_path>
//! Run from the stoatchat root so Revolt.toml / Revolt.overrides.toml resolve.

use revolt_database::DatabaseInfo;
use revolt_files::upload_to_s3;
use sha2::Digest;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let attachment_id = args
        .next()
        .expect("usage: heal_attachment_blob <attachment_id> <original_file_path>");
    let file_path = args.next().expect("missing original file path");

    let db = DatabaseInfo::Auto.connect().await.expect("database");

    let attachment = db
        .fetch_attachment("stickers", &attachment_id)
        .await
        .expect("fetch attachment");
    let hash = db
        .fetch_attachment_hash(&attachment.hash.clone().expect("attachment has no hash"))
        .await
        .expect("fetch attachment hash");

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

    let nonce = upload_to_s3(&hash.bucket_id, &hash.id, &buf)
        .await
        .expect("s3 upload");
    db.set_attachment_hash_nonce(&hash.id, &nonce)
        .await
        .expect("set nonce");

    println!("done — blob re-uploaded and nonce updated together.");
}
