use std::time::{SystemTime, UNIX_EPOCH};

use revolt_files::{EncryptionKey, FileStorageRepository, S3ObjectInfo, S3Storage};

#[tokio::test]
async fn test_upload_and_download() {
    let encryption = EncryptionKey::from_config().await;
    let s3 = S3Storage::from_config(encryption).await;

    let buf = [67];
    let bucket_id = uuid::Uuid::new_v4().to_string();

    s3.create_bucket(&bucket_id).await.unwrap();

    let (iv, key_id) = s3
        .encrypt_and_upload_file(&bucket_id, "/my-file", &buf)
        .await
        .unwrap();

    let buf = s3
        .fetch_and_decrypt_file(&bucket_id, "/my-file", &iv, key_id.as_deref())
        .await
        .unwrap();

    assert_eq!(buf.len(), 1);
    assert_eq!(buf[0], 67);
}

#[tokio::test]
async fn test_upload_and_delete() {
    let encryption = EncryptionKey::from_config().await;
    let s3 = S3Storage::from_config(encryption).await;

    let buf = [67];
    let bucket_id = uuid::Uuid::new_v4().to_string();

    s3.create_bucket(&bucket_id).await.unwrap();

    let (_iv, _key_id) = s3
        .encrypt_and_upload_file(&bucket_id, "/my-file", &buf)
        .await
        .unwrap();

    s3.delete_file(&bucket_id, "/my-file").await.unwrap();
}

fn sorted_keys(objects: &[S3ObjectInfo]) -> Vec<String> {
    let mut keys: Vec<String> = objects.iter().map(|object| object.key.clone()).collect();
    keys.sort();
    keys
}

#[tokio::test]
async fn test_list_objects_with_and_without_prefix() {
    let encryption = EncryptionKey::from_config().await;
    let s3 = S3Storage::from_config(encryption).await;

    let paths = ["a/one", "a/two", "b/three"];
    let bucket_id = uuid::Uuid::new_v4().to_string();

    s3.create_bucket(&bucket_id).await.unwrap();

    for path in paths {
        let (_iv, _key_id) = s3
            .encrypt_and_upload_file(&bucket_id, path, path.as_bytes())
            .await
            .unwrap();
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let day = 24 * 60 * 60;

    // No prefix: every object, each with a size and a timestamp in whole
    // seconds (a milliseconds value would fall far outside the window)
    let all = s3.list_objects(&bucket_id, None).await.unwrap();
    assert_eq!(sorted_keys(&all), vec!["a/one", "a/two", "b/three"]);
    for object in &all {
        assert!(object.size > 0, "{object:?} has no size");
        let modified = object
            .last_modified_unix
            .unwrap_or_else(|| panic!("{object:?} has no last_modified_unix"));
        assert!(
            (now - day..=now + day).contains(&modified),
            "{object:?} is not within a day of {now}"
        );
    }

    // A prefix narrows the listing to the keys under it
    let under_a = s3.list_objects(&bucket_id, Some("a/")).await.unwrap();
    assert_eq!(sorted_keys(&under_a), vec!["a/one", "a/two"]);

    // Known-bad control: a prefix with nothing under it lists nothing, rather
    // than erroring or falling back to the whole bucket
    let under_zzz = s3.list_objects(&bucket_id, Some("zzz/")).await.unwrap();
    assert!(under_zzz.is_empty(), "{under_zzz:?}");

    for path in paths {
        s3.delete_file(&bucket_id, path).await.unwrap();
    }

    assert!(s3.list_objects(&bucket_id, None).await.unwrap().is_empty());
}
