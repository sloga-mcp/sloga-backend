//! Server file keys: the primary (write) key plus older keys kept for reads.
//!
//! Every stored object records the id of the key it is encrypted under; no
//! `key_id` means [`LEGACY_KEY_ID`], the key that encrypted everything written
//! before rotation existed. Key values never leave this module except inside a
//! cipher. Only fingerprints may be logged.

use std::{collections::HashMap, fmt, sync::Arc};

use aes_gcm::{Aes256Gcm, KeyInit};
use base64::{prelude::BASE64_STANDARD, Engine};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;

/// Reserved id of the key that rows with no `key_id` are encrypted under
pub const LEGACY_KEY_ID: &str = "legacy";

/// Fingerprint of the `encryption_key` committed to the public `Revolt.toml`
pub const COMMITTED_DEFAULT_KEY_FP: &str = "ad21cbfc7d98";

/// Longest key id; every id other than "legacy" is 1-16 of `[a-z0-9]`
const MAX_KEY_ID_LEN: usize = 16;

/// Hex characters of the sha256 kept in a fingerprint
const FINGERPRINT_LEN: usize = 12;

/// Process-wide keyring shared by [`FileKeyring::global`] and
/// [`FileKeyring::init_global`]
static GLOBAL: OnceCell<Arc<FileKeyring>> = OnceCell::const_new();

struct KeyEntry {
    cipher: Aes256Gcm,
    fingerprint: String,
}

/// Every server file key this process can use, by id
///
/// Deliberately not `derive(Debug)`: the manual impl prints ids and
/// fingerprints only.
pub struct FileKeyring {
    primary_id: String,
    primary: Aes256Gcm,
    keys: HashMap<String, KeyEntry>,
}

impl FileKeyring {
    /// Pure constructor + validation (unit-testable; no config, no I/O)
    ///
    /// The primary key is registered under `primary_id` ("legacy" included).
    /// Errors name the failed rule and the id, never a key value.
    pub fn from_parts(
        primary_key_b64: &str,
        primary_id: &str,
        decrypt_keys: &HashMap<String, String>,
        require_rotated_key: bool,
    ) -> anyhow::Result<FileKeyring> {
        // Sorted so the first error reported is the same on every boot
        let mut decrypt: Vec<(&String, &String)> = decrypt_keys.iter().collect();
        decrypt.sort_by(|a, b| a.0.cmp(b.0));

        check_key_id(primary_id, "encryption_key_id")?;
        for (id, _) in &decrypt {
            check_key_id(id, "decrypt_keys")?;
        }

        // Also covers "legacy" in decrypt_keys while the primary is "legacy"
        if decrypt_keys.contains_key(primary_id) {
            anyhow::bail!(
                "file keyring: decrypt_keys duplicates the primary id {primary_id:?}; \
                 the primary key is registered under encryption_key_id only"
            );
        }

        if require_rotated_key && primary_id == LEGACY_KEY_ID {
            anyhow::bail!(
                "file keyring: require_rotated_key forbids the legacy primary id \
                 {LEGACY_KEY_ID:?}; give the rotated key its own encryption_key_id"
            );
        }

        let primary = load_key(primary_id, primary_key_b64)?;
        let mut keys = HashMap::with_capacity(decrypt.len() + 1);
        for (id, key_b64) in decrypt {
            keys.insert(id.clone(), load_key(id, key_b64)?);
        }

        if require_rotated_key && primary.fingerprint == COMMITTED_DEFAULT_KEY_FP {
            anyhow::bail!(
                "file keyring: require_rotated_key forbids the committed default key \
                 (fingerprint {COMMITTED_DEFAULT_KEY_FP}) as the primary key {primary_id:?}"
            );
        }

        let primary_cipher = primary.cipher.clone();
        keys.insert(primary_id.to_string(), primary);

        Ok(FileKeyring {
            primary_id: primary_id.to_string(),
            primary: primary_cipher,
            keys,
        })
    }

    /// Build from revolt_config::config().await.files
    pub async fn from_config() -> anyhow::Result<FileKeyring> {
        let files = revolt_config::config().await.files;
        FileKeyring::from_parts(
            &files.encryption_key,
            &files.encryption_key_id,
            &files.decrypt_keys.0,
            files.require_rotated_key,
        )
    }

    /// Process-wide keyring (tokio::sync::OnceCell). Builds on first use; PANICS with a
    /// message naming the failed rule (never a key) if the config is invalid.
    pub async fn global() -> Arc<FileKeyring> {
        match FileKeyring::init_global().await {
            Ok(keyring) => keyring,
            Err(error) => panic!("invalid [files] key config: {error:#}"),
        }
    }

    /// Boot entry point: same OnceCell, but returns the error instead of panicking.
    pub async fn init_global() -> anyhow::Result<Arc<FileKeyring>> {
        GLOBAL
            .get_or_try_init(|| async { FileKeyring::from_config().await.map(Arc::new) })
            .await
            .cloned()
    }

    /// None when the primary id is "legacy"
    pub fn primary_id(&self) -> Option<&str> {
        if self.primary_id == LEGACY_KEY_ID {
            None
        } else {
            Some(self.primary_id.as_str())
        }
    }

    /// None => the key registered as "legacy". Unknown id => Err. Never panics.
    pub fn cipher(&self, key_id: Option<&str>) -> anyhow::Result<Aes256Gcm> {
        self.entry(key_id).map(|entry| entry.cipher.clone())
    }

    /// The primary (write) cipher
    pub fn primary_cipher(&self) -> Aes256Gcm {
        self.primary.clone()
    }

    /// sha256 hex [..12] of the key's base64 string; None => "legacy"; unknown => Err
    pub fn fingerprint(&self, key_id: Option<&str>) -> anyhow::Result<String> {
        self.entry(key_id).map(|entry| entry.fingerprint.clone())
    }

    /// Whether a key is registered under this id (None => "legacy")
    pub fn has(&self, key_id: Option<&str>) -> bool {
        self.keys.contains_key(key_id.unwrap_or(LEGACY_KEY_ID))
    }

    /// All registered ids, sorted (primary included; "legacy" included when registered)
    pub fn key_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.keys.keys().cloned().collect();
        ids.sort();
        ids
    }

    fn entry(&self, key_id: Option<&str>) -> anyhow::Result<&KeyEntry> {
        let id = key_id.unwrap_or(LEGACY_KEY_ID);
        self.keys.get(id).ok_or_else(|| {
            anyhow::anyhow!(
                "file keyring: no key registered under id {}",
                describe_id(id)
            )
        })
    }
}

impl fmt::Debug for FileKeyring {
    /// Ids and fingerprints only, e.g.
    /// `FileKeyring { primary_id: "k1", keys: [("k1", "0668b5a09cbd")] }`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut keys: Vec<(&str, &str)> = self
            .keys
            .iter()
            .map(|(id, entry)| (id.as_str(), entry.fingerprint.as_str()))
            .collect();
        keys.sort();

        f.debug_struct("FileKeyring")
            .field("primary_id", &self.primary_id)
            .field("keys", &keys)
            .finish()
    }
}

/// "legacy", or 1-16 of `[a-z0-9]` (lowercase: config-rs lowercases map keys)
fn is_valid_key_id(id: &str) -> bool {
    id == LEGACY_KEY_ID
        || (!id.is_empty()
            && id.len() <= MAX_KEY_ID_LEN
            && id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()))
}

fn check_key_id(id: &str, field: &str) -> anyhow::Result<()> {
    if is_valid_key_id(id) {
        Ok(())
    } else {
        anyhow::bail!(
            "file keyring: invalid key id {} in {field}; an id is \"legacy\" or \
             1-{MAX_KEY_ID_LEN} characters of [a-z0-9]",
            describe_id(id)
        )
    }
}

/// An id as it may appear in an error: quoted, or withheld when it is longer
/// than any valid id, so a key pasted into the id slot is never echoed
fn describe_id(id: &str) -> String {
    let length = id.chars().count();
    if length <= MAX_KEY_ID_LEN {
        format!("{id:?}")
    } else {
        format!("<{length} characters, not shown>")
    }
}

/// Decode one key; the base64 error is dropped on purpose (it can quote a key byte)
fn load_key(id: &str, key_b64: &str) -> anyhow::Result<KeyEntry> {
    let bytes = BASE64_STANDARD
        .decode(key_b64)
        .map_err(|_| bad_key(id, "not valid base64".to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(&bytes)
        .map_err(|_| bad_key(id, format!("decodes to {} bytes", bytes.len())))?;

    Ok(KeyEntry {
        cipher,
        fingerprint: fingerprint_of(key_b64),
    })
}

fn bad_key(id: &str, detail: String) -> anyhow::Error {
    anyhow::anyhow!(
        "file keyring: key {id:?} must be STANDARD base64 of exactly 32 bytes ({detail})"
    )
}

/// Lowercase hex sha256 of the base64 string exactly as configured, first 12 chars
fn fingerprint_of(key_b64: &str) -> String {
    let digest = Sha256::digest(key_b64.as_bytes());
    let mut hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hex.truncate(FINGERPRINT_LEN);
    hex
}

#[cfg(test)]
mod tests {
    use aes_gcm::{aead::Aead, Nonce};

    use super::*;

    /// Test key, shared with encryption_impl's tests; plays the "legacy" key
    const LEGACY_TEST_KEY: &str = "XkbJ8gBzrouQ+15Ri23xCC81+aZE26Z6+gXzglFxOD4=";
    /// Computed outside Rust: printf %s '<key>' | sha256sum | cut -c1-12
    const LEGACY_TEST_KEY_FP: &str = "6e74e88f4cf3";
    /// Test key from `openssl rand -base64 32`; plays the rotated key "k1"
    const K1_TEST_KEY: &str = "qyqLB76aivuQnmIBwO3QETAvkmxMRdlN/+nA+niIIbQ=";
    /// Computed outside Rust, as above
    const K1_TEST_KEY_FP: &str = "0668b5a09cbd";

    /// A blob as the pre-keyring `EncryptionKey` stored it: AES-256-GCM, empty
    /// AAD, LEGACY_TEST_KEY, under FIXTURE_NONCE (stored iv FIXTURE_IV_B64).
    /// Computed outside Rust with python3 `cryptography` AESGCM.
    const FIXTURE_NONCE: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    const FIXTURE_IV_B64: &str = "AQIDBAUGBwgJCgsM";
    const FIXTURE_PLAINTEXT: &[u8] = b"sloga legacy file fixture";
    const FIXTURE_CIPHERTEXT: [u8; 41] = [
        0x16, 0x4b, 0x29, 0xd9, 0x4c, 0x2e, 0x6d, 0x0e, 0xe8, 0x3a, 0x80, 0xd1, 0x96, 0x24, 0x74,
        0x84, 0xf7, 0x0f, 0xc2, 0x53, 0xba, 0x57, 0x46, 0x38, 0xec, 0x8f, 0xc2, 0xf7, 0x9a, 0x2f,
        0xec, 0x64, 0x07, 0x1a, 0xea, 0xd5, 0xfd, 0x3b, 0xd8, 0xd7, 0x97,
    ];

    // One distinct marker per from_parts rule
    const RULE_BAD_KEY: &str = "base64 of exactly 32 bytes";
    const RULE_BAD_ID: &str = "invalid key id";
    const RULE_DUPLICATE_ID: &str = "duplicates the primary id";
    const RULE_LEGACY_PRIMARY: &str = "forbids the legacy primary id";
    const RULE_DEFAULT_KEY: &str = "forbids the committed default key";
    const RULES: [&str; 5] = [
        RULE_BAD_KEY,
        RULE_BAD_ID,
        RULE_DUPLICATE_ID,
        RULE_LEGACY_PRIMARY,
        RULE_DEFAULT_KEY,
    ];

    fn decrypt_keys(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(id, key)| (id.to_string(), key.to_string()))
            .collect()
    }

    /// The rotated layout: primary "k1", the old key kept as "legacy"
    fn rotated() -> FileKeyring {
        FileKeyring::from_parts(
            K1_TEST_KEY,
            "k1",
            &decrypt_keys(&[(LEGACY_KEY_ID, LEGACY_TEST_KEY)]),
            true,
        )
        .expect("the rotated test keyring is valid")
    }

    /// The error text of a result that must have failed (Aes256Gcm is not Debug,
    /// so `unwrap_err` is unavailable)
    fn err_of<T>(result: anyhow::Result<T>) -> String {
        match result {
            Ok(_) => panic!("expected an error, got Ok"),
            Err(error) => format!("{error:#}"),
        }
    }

    /// `error` carries `rule`'s marker and no other's, and quotes no key
    fn assert_rule(error: &str, rule: &str) {
        // Checked before anything prints the error
        for key in [LEGACY_TEST_KEY, K1_TEST_KEY] {
            assert!(
                !error.contains(key),
                "error for {rule:?} quotes a key value"
            );
        }
        for marker in RULES {
            assert_eq!(
                error.contains(marker),
                marker == rule,
                "expected only {rule:?}, got: {error}"
            );
        }
    }

    fn raw_cipher(key_b64: &str) -> Aes256Gcm {
        let key = BASE64_STANDARD.decode(key_b64).expect("test key is base64");
        Aes256Gcm::new_from_slice(&key).expect("test key is 32 bytes")
    }

    /// Deterministic probe: which key a cipher holds, as comparable bytes
    fn seal(cipher: &Aes256Gcm) -> Vec<u8> {
        cipher
            .encrypt(
                Nonce::<typenum::consts::U12>::from_slice(&FIXTURE_NONCE),
                FIXTURE_PLAINTEXT,
            )
            .expect("encrypt")
    }

    fn open_fixture(cipher: &Aes256Gcm) -> Result<Vec<u8>, aes_gcm::Error> {
        cipher.decrypt(
            Nonce::<typenum::consts::U12>::from_slice(&FIXTURE_NONCE),
            &FIXTURE_CIPHERTEXT[..],
        )
    }

    // (a) happy path

    #[test]
    fn rotated_keyring_resolves_every_id() {
        let keyring = rotated();

        assert_eq!(keyring.primary_id(), Some("k1"));
        assert!(keyring.has(None));
        assert!(keyring.has(Some(LEGACY_KEY_ID)));
        assert!(keyring.has(Some("k1")));
        assert!(!keyring.has(Some("k2")));
        assert_eq!(keyring.key_ids(), vec!["k1", "legacy"]);

        let legacy = seal(&raw_cipher(LEGACY_TEST_KEY));
        let k1 = seal(&raw_cipher(K1_TEST_KEY));
        assert_ne!(legacy, k1, "the two test keys must differ");

        assert_eq!(
            seal(&keyring.cipher(None).expect("legacy registered")),
            legacy
        );
        assert_eq!(
            seal(&keyring.cipher(Some("k1")).expect("k1 registered")),
            k1
        );
        assert_eq!(seal(&keyring.primary_cipher()), k1);

        assert_eq!(keyring.fingerprint(None).unwrap(), LEGACY_TEST_KEY_FP);
        assert_eq!(keyring.fingerprint(Some("k1")).unwrap(), K1_TEST_KEY_FP);
    }

    #[test]
    fn legacy_primary_is_registered_as_legacy() {
        let keyring =
            FileKeyring::from_parts(LEGACY_TEST_KEY, LEGACY_KEY_ID, &HashMap::new(), false)
                .expect("a legacy-only keyring is valid without require_rotated_key");
        let legacy = seal(&raw_cipher(LEGACY_TEST_KEY));

        assert_eq!(keyring.primary_id(), None);
        assert_eq!(keyring.key_ids(), vec!["legacy"]);
        assert_eq!(seal(&keyring.primary_cipher()), legacy);
        assert_eq!(seal(&keyring.cipher(None).unwrap()), legacy);
    }

    #[test]
    fn key_ids_are_sorted() {
        let keyring = FileKeyring::from_parts(
            K1_TEST_KEY,
            "k1",
            &decrypt_keys(&[
                ("z9", LEGACY_TEST_KEY),
                (LEGACY_KEY_ID, LEGACY_TEST_KEY),
                ("a0", LEGACY_TEST_KEY),
                ("0123456789abcdef", LEGACY_TEST_KEY),
            ]),
            false,
        )
        .expect("valid ids, including a 16-character one");

        assert_eq!(
            keyring.key_ids(),
            vec!["0123456789abcdef", "a0", "k1", "legacy", "z9"]
        );
    }

    // (b) one test per rejection rule

    #[test]
    fn rule_1_rejects_keys_that_are_not_32_bytes_of_base64() {
        let sixteen_bytes = BASE64_STANDARD.encode([7u8; 16]);
        let with_newline = format!("{K1_TEST_KEY}\n");
        let bad_keys = [
            "",
            "not base64!!",
            sixteen_bytes.as_str(),
            with_newline.as_str(),
        ];

        for bad in bad_keys {
            // As the primary
            let error = err_of(FileKeyring::from_parts(bad, "k1", &HashMap::new(), false));
            assert_rule(&error, RULE_BAD_KEY);
            assert!(error.contains("\"k1\""), "names the id: {error}");

            // As a decrypt key
            let error = err_of(FileKeyring::from_parts(
                K1_TEST_KEY,
                "k1",
                &decrypt_keys(&[(LEGACY_KEY_ID, bad)]),
                false,
            ));
            assert_rule(&error, RULE_BAD_KEY);
            assert!(error.contains("\"legacy\""), "names the id: {error}");
        }
    }

    #[test]
    fn rule_2_rejects_malformed_ids() {
        let bad_ids = [
            "",
            "K1",
            "k-1",
            "k_1",
            "legacy ",
            "k1\n",
            "abcdefghijklmnopq",
        ];

        for bad in bad_ids {
            let error = err_of(FileKeyring::from_parts(
                K1_TEST_KEY,
                bad,
                &HashMap::new(),
                false,
            ));
            assert_rule(&error, RULE_BAD_ID);
            assert!(
                error.contains("encryption_key_id"),
                "names the field: {error}"
            );

            let error = err_of(FileKeyring::from_parts(
                K1_TEST_KEY,
                "k1",
                &decrypt_keys(&[(bad, LEGACY_TEST_KEY)]),
                false,
            ));
            assert_rule(&error, RULE_BAD_ID);
            assert!(error.contains("decrypt_keys"), "names the field: {error}");
        }
    }

    #[test]
    fn rule_2_never_echoes_a_key_pasted_as_an_id() {
        // id and value swapped in [files.decrypt_keys]
        let error = err_of(FileKeyring::from_parts(
            LEGACY_TEST_KEY,
            LEGACY_KEY_ID,
            &decrypt_keys(&[(K1_TEST_KEY, "k1")]),
            false,
        ));
        assert_rule(&error, RULE_BAD_ID);
        assert!(error.contains("44 characters, not shown"), "{error}");
    }

    #[test]
    fn rule_3_rejects_the_primary_id_in_decrypt_keys() {
        let error = err_of(FileKeyring::from_parts(
            K1_TEST_KEY,
            "k1",
            &decrypt_keys(&[("k1", LEGACY_TEST_KEY)]),
            false,
        ));
        assert_rule(&error, RULE_DUPLICATE_ID);
        assert!(error.contains("\"k1\""), "names the id: {error}");

        // "legacy" in decrypt_keys while the primary is "legacy"
        let error = err_of(FileKeyring::from_parts(
            LEGACY_TEST_KEY,
            LEGACY_KEY_ID,
            &decrypt_keys(&[(LEGACY_KEY_ID, K1_TEST_KEY)]),
            false,
        ));
        assert_rule(&error, RULE_DUPLICATE_ID);
        assert!(error.contains("\"legacy\""), "names the id: {error}");
    }

    #[test]
    fn rule_4_require_rotated_key_rejects_a_legacy_primary() {
        let error = err_of(FileKeyring::from_parts(
            K1_TEST_KEY,
            LEGACY_KEY_ID,
            &HashMap::new(),
            true,
        ));
        assert_rule(&error, RULE_LEGACY_PRIMARY);

        // Control: the same parts pass without the flag
        FileKeyring::from_parts(K1_TEST_KEY, LEGACY_KEY_ID, &HashMap::new(), false)
            .expect("a legacy primary is allowed without require_rotated_key");
    }

    #[tokio::test]
    async fn rule_5_require_rotated_key_rejects_the_committed_default_primary() {
        // Read from the compiled config rather than pasted into a second file
        let committed = revolt_config::config().await.files.encryption_key;
        // Precondition, or the rejection below proves nothing
        assert!(
            fingerprint_of(&committed) == COMMITTED_DEFAULT_KEY_FP,
            "the test config's encryption_key is not the committed default"
        );

        let error = err_of(FileKeyring::from_parts(
            &committed,
            "k1",
            &HashMap::new(),
            true,
        ));
        assert!(!error.contains(&committed), "error quotes a key value");
        assert_rule(&error, RULE_DEFAULT_KEY);

        // Controls: the same key passes without the flag, and the flag still
        // allows it as a decrypt key (how old rows stay readable after rotation)
        FileKeyring::from_parts(&committed, "k1", &HashMap::new(), false)
            .expect("the committed key is a valid primary without the flag");
        let keyring = FileKeyring::from_parts(
            K1_TEST_KEY,
            "k1",
            &decrypt_keys(&[(LEGACY_KEY_ID, committed.as_str())]),
            true,
        )
        .expect("the committed key is allowed as a decrypt key");
        assert_eq!(keyring.fingerprint(None).unwrap(), COMMITTED_DEFAULT_KEY_FP);
    }

    // (c) unknown ids are errors, not panics

    #[test]
    fn unknown_ids_are_errors() {
        let keyring = rotated();

        let error = err_of(keyring.cipher(Some("k2")));
        assert!(error.contains("\"k2\""), "names the id: {error}");
        let error = err_of(keyring.fingerprint(Some("k2")));
        assert!(error.contains("\"k2\""), "names the id: {error}");

        // An over-long id read from a row is not echoed
        let long_id = "x".repeat(64);
        let error = err_of(keyring.cipher(Some(long_id.as_str())));
        assert!(!error.contains(&long_id), "echoes the id: {error}");

        // Fully rotated: with no "legacy" key registered, None is unknown too
        let keyring = FileKeyring::from_parts(K1_TEST_KEY, "k1", &HashMap::new(), true)
            .expect("a k1-only keyring is valid");
        assert!(!keyring.has(None));
        assert!(err_of(keyring.cipher(None)).contains("\"legacy\""));
        assert!(err_of(keyring.fingerprint(None)).contains("\"legacy\""));
    }

    // (d) fingerprint known answers

    #[test]
    fn fingerprint_known_answers() {
        assert_eq!(fingerprint_of(LEGACY_TEST_KEY), LEGACY_TEST_KEY_FP);
        assert_eq!(fingerprint_of(K1_TEST_KEY), K1_TEST_KEY_FP);
        // The string exactly as configured: no trimming
        let with_newline = format!("{LEGACY_TEST_KEY}\n");
        assert_ne!(fingerprint_of(&with_newline), LEGACY_TEST_KEY_FP);
    }

    #[test]
    fn debug_prints_ids_and_fingerprints_only() {
        let debug = format!("{:?}", rotated());

        assert!(
            !debug.contains(LEGACY_TEST_KEY),
            "Debug leaks the legacy key"
        );
        assert!(!debug.contains(K1_TEST_KEY), "Debug leaks the k1 key");
        assert!(debug.contains(LEGACY_TEST_KEY_FP), "{debug}");
        assert!(debug.contains(K1_TEST_KEY_FP), "{debug}");
        assert!(debug.contains("primary_id: \"k1\""), "{debug}");
    }

    // (e) known-answer fixture written by the pre-keyring EncryptionKey

    #[test]
    fn legacy_fixture_decrypts_under_legacy_only() {
        // The fixture is what the old code wrote: one-shot Aes256Gcm, empty AAD
        assert_eq!(
            BASE64_STANDARD.decode(FIXTURE_IV_B64).unwrap(),
            FIXTURE_NONCE.to_vec()
        );
        assert_eq!(
            seal(&raw_cipher(LEGACY_TEST_KEY)),
            FIXTURE_CIPHERTEXT.to_vec()
        );

        let keyring = rotated();
        let legacy = keyring.cipher(None).expect("legacy is registered");
        let plaintext = open_fixture(&legacy).expect("a row with no key_id decrypts under legacy");
        assert_eq!(plaintext, FIXTURE_PLAINTEXT);

        // Control: the primary must not open it
        assert!(open_fixture(&keyring.cipher(Some("k1")).unwrap()).is_err());
        assert!(open_fixture(&keyring.primary_cipher()).is_err());
    }

    // (f) the compiled config

    #[tokio::test]
    async fn from_config_is_the_committed_legacy_key() {
        let keyring = FileKeyring::from_config()
            .await
            .expect("the compiled config builds a keyring");

        assert_eq!(keyring.primary_id(), None);
        assert_eq!(keyring.fingerprint(None).unwrap(), COMMITTED_DEFAULT_KEY_FP);
        assert_eq!(keyring.key_ids(), vec!["legacy"]);
    }

    #[tokio::test]
    async fn global_and_init_global_share_one_keyring() {
        let first = FileKeyring::init_global()
            .await
            .expect("the compiled config builds a keyring");
        let second = FileKeyring::global().await;

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(second.fingerprint(None).unwrap(), COMMITTED_DEFAULT_KEY_FP);
    }
}
