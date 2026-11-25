//! Sealing and lookup keys for Take It Down requests.
//!
//! Requester details are stored only as `seal_requester` output, under the
//! `[features.takedown] data_key` (64 hex characters, 32 bytes). Nothing here
//! logs its input or puts it in an error.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use revolt_result::Result;
use sha2::{Digest, Sha256};

/// Prefix of the public request reference
const REFERENCE_PREFIX: &str = "TD-";
/// Domain separator for the contact fingerprint key
const FINGERPRINT_DOMAIN: &[u8] = b"sloga-takedown-fp-v1";
/// AES-GCM nonce length (96 bits)
const NONCE_LEN: usize = 12;
/// AES-GCM tag length
const TAG_LEN: usize = 16;

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// The 32-byte key, or `None` unless `key_hex` is exactly 64 hex characters
fn parse_key(key_hex: &str) -> Option<[u8; 32]> {
    let digits = key_hex.as_bytes();
    if digits.len() != 64 {
        return None;
    }

    let mut key = [0u8; 32];
    for (index, pair) in digits.chunks_exact(2).enumerate() {
        key[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }

    Some(key)
}

fn cipher(key_hex: &str) -> Result<Aes256Gcm> {
    let key = parse_key(key_hex).ok_or_else(|| create_error!(InternalError))?;
    Aes256Gcm::new_from_slice(&key).map_err(|_| create_error!(InternalError))
}

/// AES-256-GCM under a random 96-bit nonce; returns base64(nonce || ciphertext)
pub fn seal_requester(key_hex: &str, plaintext: &[u8]) -> Result<String> {
    let cipher = cipher(key_hex)?;

    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| create_error!(InternalError))?;

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| create_error!(InternalError))?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(sealed))
}

/// Reverse of `seal_requester`; a wrong key or altered input is an error
pub fn open_requester(key_hex: &str, sealed: &str) -> Result<Vec<u8>> {
    let cipher = cipher(key_hex)?;

    let raw = STANDARD
        .decode(sealed)
        .map_err(|_| create_error!(InternalError))?;
    if raw.len() < NONCE_LEN + TAG_LEN {
        return Err(create_error!(InternalError));
    }

    let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| create_error!(InternalError))
}

/// Hex HMAC-SHA256 of the trimmed, lowercased email, keyed with
/// SHA-256(`sloga-takedown-fp-v1` || key bytes).
///
/// Callers check `FeaturesTakedown::active()` first. A malformed key never
/// panics: its raw text stands in for the key bytes.
pub fn contact_fingerprint(key_hex: &str, email: &str) -> String {
    let mut derive = Sha256::new();
    derive.update(FINGERPRINT_DOMAIN);
    match parse_key(key_hex) {
        Some(key) => derive.update(key),
        None => derive.update(key_hex.as_bytes()),
    }
    let fp_key = derive.finalize();

    // Fully qualified: `KeyInit` (in scope for AES) has a `new_from_slice` too
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&fp_key).expect("HMAC accepts keys of any length");
    mac.update(email.trim().to_lowercase().as_bytes());
    to_hex(&mac.finalize().into_bytes())
}

/// 32 random bytes, base64url without padding (43 characters)
pub fn new_status_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hex SHA-256 of a status token
pub fn hash_status_token(token: &str) -> String {
    to_hex(&Sha256::digest(token.as_bytes()))
}

/// Public reference of a request id
pub fn reference_for(id: &str) -> String {
    format!("{REFERENCE_PREFIX}{id}")
}

/// Request id of a public reference, or `None` unless it is `TD-` followed by
/// a ULID. The id comes back in canonical (uppercase) form.
pub fn id_from_reference(reference: &str) -> Option<String> {
    let reference = reference.trim();
    let id = reference
        .strip_prefix(REFERENCE_PREFIX)
        .or_else(|| reference.strip_prefix("td-"))?;

    // `from_string` drops overflowing high bits (a leading digit above 7)
    // instead of failing, so the canonical form must round-trip
    let canonical = ulid::Ulid::from_string(id).ok()?.to_string();
    (canonical == id.to_ascii_uppercase()).then_some(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// bytes 0x00..=0x1f
    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const OTHER_KEY: &str = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";

    /// Computed outside Rust (python3 `cryptography` AESGCM): KEY, nonce bytes
    /// 100..=111, plaintext `sloga takedown fixture`, empty AAD
    const SEALED_FIXTURE: &str =
        "ZGVmZ2hpamtsbW5vO3exARjJIv9VBzuHrQtKmyu6cn/5CTodVqVADkjn764i4pVBZpY=";

    /// Computed outside Rust (python3 hashlib + hmac) for KEY and
    /// `alice@example.com`
    const FINGERPRINT_FIXTURE: &str =
        "3e4a0557d2c63d475017f1399873bbf1052c9b128b80b26d0262de3912eadba2";

    #[test]
    fn seal_then_open_round_trips() {
        let sealed = seal_requester(KEY, b"requester details").unwrap();
        assert_eq!(open_requester(KEY, &sealed).unwrap(), b"requester details");
    }

    #[test]
    fn seal_uses_a_fresh_nonce_each_time() {
        assert_ne!(
            seal_requester(KEY, b"same").unwrap(),
            seal_requester(KEY, b"same").unwrap()
        );
    }

    #[test]
    fn opens_a_blob_sealed_outside_rust() {
        assert_eq!(
            open_requester(KEY, SEALED_FIXTURE).unwrap(),
            b"sloga takedown fixture"
        );
    }

    #[test]
    fn open_with_the_wrong_key_fails() {
        let sealed = seal_requester(KEY, b"requester details").unwrap();
        assert!(open_requester(OTHER_KEY, &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let sealed = seal_requester(KEY, b"requester details").unwrap();
        let mut raw = STANDARD.decode(&sealed).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        assert!(open_requester(KEY, &STANDARD.encode(&raw)).is_err());

        let mut raw = STANDARD.decode(&sealed).unwrap();
        raw[NONCE_LEN] ^= 0x80;
        assert!(open_requester(KEY, &STANDARD.encode(&raw)).is_err());

        assert!(open_requester(KEY, "not base64 !").is_err());
        assert!(open_requester(KEY, &STANDARD.encode([0u8; NONCE_LEN + TAG_LEN - 1])).is_err());
        assert!(open_requester(KEY, "").is_err());
    }

    #[test]
    fn a_malformed_key_is_an_error_not_a_panic() {
        let long = format!("{KEY}0");
        let not_hex = format!("{}zz", &KEY[..62]);
        // 64 bytes, but the first character is two of them
        let multibyte = format!("é{}", &KEY[2..]);
        assert_eq!(multibyte.len(), 64);
        for key in [
            "",
            "00",
            &KEY[..63],
            long.as_str(),
            not_hex.as_str(),
            multibyte.as_str(),
        ] {
            assert!(seal_requester(key, b"x").is_err(), "{key:?}");
            assert!(open_requester(key, SEALED_FIXTURE).is_err(), "{key:?}");
            assert_eq!(contact_fingerprint(key, "a@example.com").len(), 64);
        }
    }

    #[test]
    fn upper_case_key_is_the_same_key() {
        let sealed = seal_requester(&KEY.to_uppercase(), b"x").unwrap();
        assert_eq!(open_requester(KEY, &sealed).unwrap(), b"x");
    }

    #[test]
    fn fingerprint_matches_the_outside_computation() {
        assert_eq!(
            contact_fingerprint(KEY, "alice@example.com"),
            FINGERPRINT_FIXTURE
        );
    }

    #[test]
    fn fingerprint_ignores_case_and_surrounding_whitespace() {
        let fp = contact_fingerprint(KEY, "alice@example.com");
        assert_eq!(contact_fingerprint(KEY, "  Alice@Example.COM\n"), fp);
        assert_eq!(contact_fingerprint(KEY, "\tALICE@EXAMPLE.COM "), fp);
        assert_ne!(contact_fingerprint(KEY, "bob@example.com"), fp);
    }

    #[test]
    fn fingerprint_differs_per_key() {
        assert_ne!(
            contact_fingerprint(KEY, "alice@example.com"),
            contact_fingerprint(OTHER_KEY, "alice@example.com")
        );
    }

    #[test]
    fn status_token_is_43_base64url_characters() {
        let token = new_status_token();
        assert_eq!(token.len(), 43);
        assert!(token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_eq!(URL_SAFE_NO_PAD.decode(&token).unwrap().len(), 32);
        assert_ne!(token, new_status_token());
    }

    #[test]
    fn token_hash_is_hex_sha256() {
        assert_eq!(
            hash_status_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let hash = hash_status_token(&new_status_token());
        assert_eq!(hash.len(), 64);
        assert!(hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn reference_round_trips() {
        let id = ulid::Ulid::new().to_string();
        let reference = reference_for(&id);
        assert_eq!(reference, format!("TD-{id}"));
        assert_eq!(id_from_reference(&reference), Some(id.clone()));
        assert_eq!(
            id_from_reference(&format!(" {reference}\n")),
            Some(id.clone())
        );
        assert_eq!(
            id_from_reference(&reference.to_lowercase()),
            Some(id.clone())
        );
    }

    #[test]
    fn reference_rejects_garbage() {
        let id = ulid::Ulid::new().to_string();
        for bad in [
            String::new(),
            "TD-".to_string(),
            id.clone(),
            format!("XX-{id}"),
            format!("TD-{}", &id[..25]),
            format!("TD-{id}0"),
            format!("TD-{}U", &id[..25]),
            format!("TD-8{}", &id[1..]),
            format!("TD- {id}"),
            "TD-../../etc/passwd".to_string(),
            "TD-ééééééééééééééééééééééééé".to_string(),
        ] {
            assert_eq!(id_from_reference(&bad), None, "{bad:?}");
        }
    }
}
