//! One-off ops tool: seed a default sticker pack onto a server without going
//! through the HTTP API (no session token required — runs with server-side
//! config/S3 credentials). Mirrors the autumn upload path (FileHash + S3 +
//! attachment) followed by the delta create_sticker route semantics.
//!
//! Usage: seed_stickers <pack_dir> <server_id> <creator_id>
//! Run from the stoatchat root so Revolt.toml / Revolt.overrides.toml resolve.

use std::collections::HashMap;

use revolt_database::{
    iso8601_timestamp::Timestamp, DatabaseInfo, File, FileHash, Metadata, Sticker, StickerFormat,
};
use revolt_files::{image_size_vec, upload_to_s3, AUTHENTICATION_TAG_SIZE_BYTES};
use sha2::Digest;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let pack_dir = args.next().expect("usage: seed_stickers <pack_dir> <server_id> <creator_id>");
    let server_id = args.next().expect("missing server id");
    let creator_id = args.next().expect("missing creator id");

    let config = revolt_config::config().await;
    let db = DatabaseInfo::Auto.connect().await.expect("database");

    let existing: Vec<String> = db
        .fetch_stickers_by_server_id(&server_id)
        .await
        .expect("fetch existing stickers")
        .into_iter()
        .map(|s| s.name)
        .collect();

    let names: HashMap<&str, &str> = [
        ("joy", "Joy"),
        ("rofl", "ROFL"),
        ("heart", "Heart"),
        ("heart_eyes", "Heart Eyes"),
        ("thumbs_up", "Thumbs Up"),
        ("fire", "Fire"),
        ("party", "Party"),
        ("skull", "Skull"),
        ("thinking", "Thinking"),
        ("wave", "Wave"),
        ("clap", "Clap"),
        ("hundred", "100"),
        ("eyes", "Eyes"),
        ("sob", "Sob"),
        ("rage", "Rage"),
        ("cool", "Cool"),
        ("tada", "Tada"),
        ("rocket", "Rocket"),
        ("crown", "Crown"),
        ("ghost", "Ghost"),
        ("pray", "Pray"),
        ("sweat_smile", "Sweat Smile"),
        ("mind_blown", "Mind Blown"),
        ("salute", "Salute"),
    ]
    .into_iter()
    .collect();

    let mut entries: Vec<_> = std::fs::read_dir(&pack_dir)
        .expect("read pack dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "webp"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let stem = path
            .file_stem()
            .expect("file stem")
            .to_string_lossy()
            .to_string();
        let name = names
            .get(stem.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| stem.clone());

        if existing.contains(&name) {
            println!("skip {name} (already on server)");
            continue;
        }

        let buf = std::fs::read(&path).expect("read sticker file");
        let hash_hex = format!("{:02x}", sha2::Sha256::digest(&buf));

        // Ensure the content-addressed hash entry exists and the blob is on S3
        let file_hash = match db.fetch_attachment_hash(&hash_hex).await {
            Ok(h) if !h.iv.is_empty() => h,
            _ => {
                let (w, h) = image_size_vec(&buf, "image/webp").unwrap_or((288, 288));
                let fh = FileHash {
                    id: hash_hex.clone(),
                    processed_hash: hash_hex.clone(),
                    created_at: Timestamp::now_utc(),
                    bucket_id: config.files.s3.default_bucket.clone(),
                    path: hash_hex.clone(),
                    iv: String::new(),
                    metadata: Metadata::Image {
                        width: w as isize,
                        height: h as isize,
                        thumbhash: None,
                        animated: Some(true),
                    },
                    content_type: "image/webp".to_owned(),
                    size: (buf.len() + AUTHENTICATION_TAG_SIZE_BYTES) as isize,
                };
                let _ = db.insert_attachment_hash(&fh).await;
                let nonce = upload_to_s3(&fh.bucket_id, &fh.id, &buf)
                    .await
                    .expect("s3 upload");
                db.set_attachment_hash_nonce(&fh.id, &nonce)
                    .await
                    .expect("set nonce");
                db.fetch_attachment_hash(&hash_hex)
                    .await
                    .expect("refetch hash")
            }
        };

        // Attachment + sticker rows, matching delta's create_sticker route
        // (sticker id == attachment id; used_for set immediately so the
        // dangling-file pruner never touches it)
        let id = nanoid::nanoid!(42);
        db.insert_attachment(&file_hash.into_file(
            id.clone(),
            "stickers".to_owned(),
            format!("{stem}.webp"),
            creator_id.clone(),
        ))
        .await
        .expect("insert attachment");

        let attachment = File::use_sticker(&db, &id, &id, &creator_id)
            .await
            .expect("use sticker");

        let sticker = Sticker {
            id: id.clone(),
            server_id: server_id.clone(),
            creator_id: creator_id.clone(),
            name: name.clone(),
            description: Some("Sloga default sticker — Noto Animated Emoji".to_owned()),
            file_id: attachment.id,
            format: StickerFormat::PNG,
            nsfw: false,
        };
        db.insert_sticker(&sticker).await.expect("insert sticker");

        println!("seeded {name} -> {id}");
    }

    println!("done.");
}
