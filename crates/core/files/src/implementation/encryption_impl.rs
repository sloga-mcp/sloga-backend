use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, AeadCore, AeadMutInPlace, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{prelude::BASE64_STANDARD, Engine};

use super::keyring::FileKeyring;
use crate::EncryptionRepository;

/// AES-GCM nonce length in bytes (U12)
const IV_SIZE: usize = 12;

pub struct EncryptionKey {
    keyring: Arc<FileKeyring>,
}

impl EncryptionKey {
    pub async fn from_config() -> EncryptionKey {
        EncryptionKey::new(FileKeyring::global().await)
    }

    pub fn new(keyring: Arc<FileKeyring>) -> EncryptionKey {
        EncryptionKey { keyring }
    }
}

impl EncryptionRepository for EncryptionKey {
    fn decrypt_buffer(
        &self,
        mut buf: Vec<u8>,
        iv: &str,
        key_id: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        let iv = BASE64_STANDARD
            .decode(iv)
            .map_err(|_| anyhow::anyhow!("EncryptionRepository: iv is not valid base64"))?;

        if iv.len() != IV_SIZE {
            anyhow::bail!("EncryptionRepository: iv must be 12 bytes");
        }

        // Length checked above, so this conversion cannot panic
        let iv: &Nonce<typenum::consts::U12> = iv.as_slice().into();

        self.keyring
            .cipher(key_id)?
            .decrypt_in_place(iv, b"", &mut buf)
            .map_err(|error| {
                tracing::error!("{}", error);
                anyhow::anyhow!("EncryptionRepository: decryption failed")
            })?;

        Ok(buf)
    }

    fn encrypt_buffer(&self, buf: &[u8]) -> anyhow::Result<(Vec<u8>, String, Option<String>)> {
        let iv = Aes256Gcm::generate_nonce(&mut OsRng);

        let buf = self
            .keyring
            .primary_cipher()
            .encrypt(&iv, buf)
            .map_err(|error| {
                tracing::error!("{}", error);
                anyhow::anyhow!("EncryptionRepository: encryption failed")
            })?;

        Ok((
            buf,
            BASE64_STANDARD.encode(iv),
            self.keyring.primary_id().map(str::to_string),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const KEY_A: &str = "XkbJ8gBzrouQ+15Ri23xCC81+aZE26Z6+gXzglFxOD4=";
    const KEY_B: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    fn encryption(primary_id: &str, decrypt_keys: &[(&str, &str)]) -> EncryptionKey {
        let decrypt_keys: HashMap<String, String> = decrypt_keys
            .iter()
            .map(|(id, key)| (id.to_string(), key.to_string()))
            .collect();

        let keyring = FileKeyring::from_parts(KEY_A, primary_id, &decrypt_keys, false)
            .expect("valid test keyring");
        EncryptionKey::new(Arc::new(keyring))
    }

    #[test]
    fn test_encrypt_and_decrypt() {
        let encryption = encryption("legacy", &[]);

        let buf: Vec<u8> = vec![67];
        let (ciphertext, iv, key_id) = encryption.encrypt_buffer(&buf[..]).unwrap();
        assert_eq!(ciphertext.len(), 17);
        assert_eq!(key_id, None);

        let plaintext = encryption
            .decrypt_buffer(ciphertext, &iv, key_id.as_deref())
            .unwrap();
        assert_eq!(plaintext.len(), 1);
        assert_eq!(plaintext[0], 67);
    }

    #[test]
    fn test_encrypt_reports_rotated_primary_id() {
        let encryption = encryption("k1", &[]);

        let (ciphertext, iv, key_id) = encryption.encrypt_buffer(b"hello").unwrap();
        assert_eq!(key_id.as_deref(), Some("k1"));

        let plaintext = encryption
            .decrypt_buffer(ciphertext, &iv, key_id.as_deref())
            .unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn test_bad_iv_is_err() {
        let encryption = encryption("legacy", &[]);
        let (ciphertext, _, _) = encryption.encrypt_buffer(b"hello").unwrap();

        for iv in [
            "not base64!".to_string(),
            String::new(),
            BASE64_STANDARD.encode([0u8; 11]),
            BASE64_STANDARD.encode([0u8; 13]),
        ] {
            assert!(encryption
                .decrypt_buffer(ciphertext.clone(), &iv, None)
                .is_err());
        }
    }

    #[test]
    fn test_wrong_key_id_is_err() {
        // Primary k1 is KEY_A; "legacy" is registered for reads only, as KEY_B
        let encryption = encryption("k1", &[("legacy", KEY_B)]);
        let (ciphertext, iv, key_id) = encryption.encrypt_buffer(b"hello").unwrap();
        assert_eq!(key_id.as_deref(), Some("k1"));

        // Registered but wrong key: authentication fails
        assert!(encryption
            .decrypt_buffer(ciphertext.clone(), &iv, None)
            .is_err());

        // Unknown key id
        assert!(encryption
            .decrypt_buffer(ciphertext.clone(), &iv, Some("k2"))
            .is_err());

        // The right key id still decrypts the same ciphertext
        let plaintext = encryption
            .decrypt_buffer(ciphertext, &iv, Some("k1"))
            .unwrap();
        assert_eq!(plaintext, b"hello");
    }
}
