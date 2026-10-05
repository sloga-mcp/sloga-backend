pub trait EncryptionRepository: Send + Sync + 'static {
    /// Decrypt `buf` with the base64 `iv` under `key_id` (None = the "legacy" key)
    fn decrypt_buffer(
        &self,
        buf: Vec<u8>,
        iv: &str,
        key_id: Option<&str>,
    ) -> anyhow::Result<Vec<u8>>;
    /// Encrypt under the primary key: (ciphertext, base64 iv, primary key_id; None when legacy)
    fn encrypt_buffer(&self, buf: &[u8]) -> anyhow::Result<(Vec<u8>, String, Option<String>)>;
}
