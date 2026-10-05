use anyhow::Result;

#[async_trait::async_trait]
pub trait FileStorageRepository: Send + Sync + 'static {
    async fn create_bucket(&self, bucket_id: &str) -> anyhow::Result<()>;

    /// Fetch an object and decrypt it with the key `key_id` names (None => "legacy").
    /// An empty `iv` means the object is stored as plaintext.
    async fn fetch_and_decrypt_file(
        &self,
        bucket_id: &str,
        path: &str,
        iv: &str,
        key_id: Option<&str>,
    ) -> Result<Vec<u8>>;

    /// Encrypt with the primary key and upload; returns (base64 iv, key_id of the
    /// primary key, None when it is "legacy")
    async fn encrypt_and_upload_file(
        &self,
        bucket_id: &str,
        path: &str,
        buf: &[u8],
    ) -> Result<(String, Option<String>)>;

    async fn delete_file(&self, bucket_id: &str, path: &str) -> Result<()>;
}
