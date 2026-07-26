//! Cross-request multipart against live MinIO.
//!
//! Every phase uses a *fresh* `S3Storage` to prove no in-memory state spans
//! phases — the persisted `upload_id` is sufficient, which is the property
//! chunked uploads depend on. Parts are plaintext here: crypto correctness is
//! covered by the stream_cipher unit tests, and multipart mechanics are
//! byte-agnostic. Non-final parts must respect S3's 5 MiB minimum.

use revolt_files::{EncryptionKey, FileStorageRepository, S3Storage};

const PART_1_SIZE: usize = 5 * 1024 * 1024;
const PART_2_SIZE: usize = 1000;

async fn storage() -> S3Storage<EncryptionKey> {
    S3Storage::from_config(EncryptionKey::from_config().await).await
}

#[tokio::test]
async fn test_cross_request_multipart_out_of_order() {
    let bucket_id = uuid::Uuid::new_v4().to_string();
    let path = "/chunked-file";
    storage().await.create_bucket(&bucket_id).await.unwrap();

    let upload_id = storage()
        .await
        .create_multipart(&bucket_id, path)
        .await
        .unwrap();

    // Upload the final part first — order must not matter
    let etag_2 = storage()
        .await
        .upload_part(&bucket_id, path, &upload_id, 2, vec![2u8; PART_2_SIZE])
        .await
        .unwrap();
    let etag_1 = storage()
        .await
        .upload_part(&bucket_id, path, &upload_id, 1, vec![1u8; PART_1_SIZE])
        .await
        .unwrap();

    // Recorded in arrival order; complete_multipart sorts ascending itself
    storage()
        .await
        .complete_multipart(&bucket_id, path, &upload_id, &[(2, etag_2), (1, etag_1)])
        .await
        .unwrap();

    // Assembled object comes back whole (iv = "" is plaintext passthrough)
    let buf = storage()
        .await
        .fetch_and_decrypt_file(&bucket_id, path, "")
        .await
        .unwrap();
    assert_eq!(buf.len(), PART_1_SIZE + PART_2_SIZE);
    assert_eq!(buf[0], 1);
    assert_eq!(buf[PART_1_SIZE - 1], 1);
    assert_eq!(buf[PART_1_SIZE], 2);
    assert_eq!(buf[buf.len() - 1], 2);

    // Range fetch returns exactly the tail part
    let range = storage()
        .await
        .fetch_range(
            &bucket_id,
            path,
            PART_1_SIZE as u64,
            (PART_1_SIZE + PART_2_SIZE - 1) as u64,
        )
        .await
        .unwrap()
        .collect()
        .await
        .unwrap()
        .into_bytes();
    assert_eq!(range.len(), PART_2_SIZE);
    assert!(range.iter().all(|byte| *byte == 2));

    assert!(storage()
        .await
        .object_exists(&bucket_id, path)
        .await
        .unwrap());
    assert!(!storage()
        .await
        .object_exists(&bucket_id, "/no-such-object")
        .await
        .unwrap());
}

#[tokio::test]
async fn test_abort_multipart_is_idempotent() {
    let bucket_id = uuid::Uuid::new_v4().to_string();
    let path = "/aborted-file";
    storage().await.create_bucket(&bucket_id).await.unwrap();

    let upload_id = storage()
        .await
        .create_multipart(&bucket_id, path)
        .await
        .unwrap();
    storage()
        .await
        .upload_part(&bucket_id, path, &upload_id, 1, vec![9u8; PART_1_SIZE])
        .await
        .unwrap();

    storage()
        .await
        .abort_multipart(&bucket_id, path, &upload_id)
        .await
        .unwrap();
    // Second abort of a gone upload is success, not an error — the sweep
    // relies on this when racing the lifecycle rule
    storage()
        .await
        .abort_multipart(&bucket_id, path, &upload_id)
        .await
        .unwrap();

    assert!(!storage()
        .await
        .object_exists(&bucket_id, path)
        .await
        .unwrap());
}

#[tokio::test]
async fn test_ensure_bucket_lifecycle_is_idempotent() {
    let bucket_id = uuid::Uuid::new_v4().to_string();
    storage().await.create_bucket(&bucket_id).await.unwrap();

    storage()
        .await
        .ensure_bucket_lifecycle(&bucket_id)
        .await
        .unwrap();
    storage()
        .await
        .ensure_bucket_lifecycle(&bucket_id)
        .await
        .unwrap();
}

/// The v2 storage story end-to-end at real (if small) scale: encrypt parts
/// out of order with SegmentedStreamCipher layout math, store them as S3
/// parts, assemble, then decrypt a mid-file segment run via a range fetch.
/// Uses a 5 MiB+ ciphertext so both parts clear S3's minimum.
#[tokio::test]
async fn test_encrypted_multipart_range_round_trip() {
    use revolt_files::{SegmentedStreamCipher, STREAM_SEGMENT_SIZE};

    // 6 MiB plaintext = 6 segments; part 1 carries 5 segments (5 MiB + tags
    // ≥ S3 minimum), part 2 the final segment. This mirrors production's
    // "part = whole number of segments" invariant without 32 MiB of debug-
    // build crypto.
    const SEGMENTS_PART_1: usize = 5;
    let plaintext: Vec<u8> = (0..6 * STREAM_SEGMENT_SIZE)
        .map(|index| (index % 251) as u8)
        .collect();

    let prefix = SegmentedStreamCipher::generate_prefix();
    let cipher = SegmentedStreamCipher::from_config(prefix).await;

    let split = SEGMENTS_PART_1 * STREAM_SEGMENT_SIZE;
    // encrypt_part's contract requires full 32 MiB parts, which would be
    // minutes of debug-build crypto — so seal segment runs directly through
    // the same underlying primitive: part 1 = segments 0..5 (non-final),
    // part 2 = segment 5 (final).
    let ct_1 = {
        let mut out = vec![];
        for (offset, segment) in plaintext[..split].chunks(STREAM_SEGMENT_SIZE).enumerate() {
            out.extend(cipher.encrypt_segment(offset as u32, false, segment).unwrap());
        }
        out
    };
    let ct_2 = cipher
        .encrypt_segment(SEGMENTS_PART_1 as u32, true, &plaintext[split..])
        .unwrap();

    let bucket_id = uuid::Uuid::new_v4().to_string();
    let path = "/encrypted-chunked";
    storage().await.create_bucket(&bucket_id).await.unwrap();
    let upload_id = storage()
        .await
        .create_multipart(&bucket_id, path)
        .await
        .unwrap();

    let etag_2 = storage()
        .await
        .upload_part(&bucket_id, path, &upload_id, 2, ct_2)
        .await
        .unwrap();
    let etag_1 = storage()
        .await
        .upload_part(&bucket_id, path, &upload_id, 1, ct_1)
        .await
        .unwrap();
    storage()
        .await
        .complete_multipart(&bucket_id, path, &upload_id, &[(1, etag_1), (2, etag_2)])
        .await
        .unwrap();

    // Plaintext range spanning segments 4..=5 (crosses the part boundary)
    let start = (4 * STREAM_SEGMENT_SIZE + 123) as u64;
    let end = (5 * STREAM_SEGMENT_SIZE + 456) as u64;
    let (ct_start, ct_end, first_segment, includes_final, skip) = cipher
        .plaintext_range_to_ciphertext(start, end, plaintext.len() as u64)
        .unwrap();

    let ciphertext = storage()
        .await
        .fetch_range(&bucket_id, path, ct_start, ct_end)
        .await
        .unwrap()
        .collect()
        .await
        .unwrap()
        .into_bytes();

    let decrypted = cipher
        .decrypt_segments(first_segment, includes_final, &ciphertext)
        .unwrap();
    let wanted = &decrypted[skip as usize..skip as usize + (end - start + 1) as usize];
    assert_eq!(wanted, &plaintext[start as usize..=end as usize]);
}
