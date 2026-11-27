//! Apple JWS verifier (S6 contracts section 10).
//!
//! StoreKit 2 transactions, App Store Server Notifications and Get Transaction Info answers are JWS
//! (compact serialization) signed by Apple with an `x5c` chain `[leaf, intermediate, root]` that ends
//! at Apple Root CA - G3. [`verify_apple_jws`] runs the pinned check list in order, each check with its
//! own [`AppleJwsError`], and returns the payload bytes; callers decode them into the typed structs.
//!
//! | Check | Function | Error |
//! |---|---|---|
//! | 1. size, three non-empty base64url (no padding) segments | `split_segments`, `decode_segment` | `Malformed` |
//! | 2. `alg` = ES256, no `crit`/`jku`/`jwk`/`x5u`; `x5c` = 3 strings | `read_header` | `Algorithm`, `ChainShape` |
//! | 3. SHA-256 of the root DER = the pinned hash | `check_root_pin` | `RootMismatch` |
//! | 4. the three certificates parse; raw leaf + intermediate TBS | `parse_chain`, `raw_tbs` | `Malformed` |
//! | 5. Apple OIDs by position | `check_apple_oids` | `MissingOid` |
//! | 6. basicConstraints cA on intermediate + root, not on the leaf | `check_ca_flags` | `NotCa` |
//! | 7. issuer = subject up the chain (DER) | `check_issuers` | `IssuerMismatch` |
//! | 8. leaf and intermediate signatures (P-256/P-384, SHA-256/SHA-384) | `check_chain_signature` | `UnsupportedKey`, `ChainSignature` |
//! | 9. `signedDate` present; every certificate valid AT `signedDate` | `read_signed_date`, `check_validity` | `Malformed`, `Validity` |
//! | 10. P-256 leaf; ES256 r||s signature over `header.payload` | `check_jws_signature` | `UnsupportedKey`, `Signature` |
//!
//! Interpretations where section 10 names no error (all fail closed): a header or payload that is not a
//! JSON object, or that repeats a known member, is `Malformed`; an `x5c` entry that is not standard
//! base64 is `Malformed` (the shape check, `ChainShape`, runs first); a basicConstraints extension that
//! does not decode, or appears twice, is `NotCa`; a certificate signature algorithm other than
//! ecdsa-with-SHA256/SHA384 is `ChainSignature`.
//!
//! No revocation check (Apple's own library does none); the engine's freshness lookup covers a JWS
//! whose purchase was refunded after it was signed. Nothing is ever fetched.
//!
//! Chain signatures are verified over the ORIGINAL TBS bytes sliced from the input DER (`raw_tbs`),
//! never over a re-encoding: `x509-cert` sorts a SET OF on decode, so a re-encoded TBS can differ
//! from the bytes the issuer signed (S6 contracts, section 36, R36).
//!
//! Genuine chain (curve, digest) pairs: root G3 = P-384, self-signed ecdsa-with-SHA384 (confirmed
//! from the committed certificate). Intermediate and leaf NOT YET RECORDED; expected from W0 research:
//! intermediate (WWDR) P-384, signed by the root with ecdsa-with-SHA384; leaf P-256, signed by the
//! intermediate with ecdsa-with-SHA384; JWS ES256. Record and pin the real pairs once the captured
//! sandbox fixture verifies (`genuine_apple_sandbox_jws_verifies`; a ship gate per section 36).

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use const_oid::ObjectIdentifier;
use der::{asn1::AnyRef, Decode, Encode, Reader, SliceReader};
use ecdsa::signature::{hazmat::PrehashVerifier, Verifier};
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha384};
use x509_cert::{
    ext::pkix::BasicConstraints, name::Name, spki::SubjectPublicKeyInfoOwned, Certificate,
};

pub const APPLE_OID_RECEIPT_SIGNER: &str = "1.2.840.113635.100.6.11.1"; // leaf
pub const APPLE_OID_WWDR_INTERMEDIATE: &str = "1.2.840.113635.100.6.2.1"; // intermediate
/// SHA-256 of the DER of Apple Root CA - G3.
///
/// CONFIRMED 2026-11-02 (S6 contracts, section 36) against the Mac mini's system root store
/// (`security find-certificate -c "Apple Root CA - G3" -p /System/Library/Keychains/SystemRootCertificates.keychain
/// | openssl x509 -outform der | shasum -a 256`): P-384, ecdsa-with-SHA384, valid to 2039-04-30. That public
/// certificate is committed as `fixtures/AppleRootCA-G3.cer` and the test
/// `pinned_root_matches_the_committed_g3_certificate` hashes it against this constant.
pub const APPLE_ROOT_G3_SHA256_HEX: &str =
    "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleJwsError {
    Malformed,
    Algorithm,
    ChainShape,
    RootMismatch,
    MissingOid,
    NotCa,
    IssuerMismatch,
    UnsupportedKey,
    ChainSignature,
    Validity,
    Signature,
}

pub struct VerifiedJws {
    pub payload: Vec<u8>,
    pub signed_date_ms: i64,
}

/// Largest JWS accepted (check 1)
const MAX_JWS_LEN: usize = 65_536;

const OID_RECEIPT_SIGNER: ObjectIdentifier = ObjectIdentifier::new_unwrap(APPLE_OID_RECEIPT_SIGNER);
const OID_WWDR_INTERMEDIATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap(APPLE_OID_WWDR_INTERMEDIATE);
/// id-ecPublicKey
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// prime256v1 / secp256r1
const OID_CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// secp384r1
const OID_CURVE_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// Verify an Apple-signed JWS (StoreKit 2 transaction, notification, Get Transaction Info answer).
pub fn verify_apple_jws(jws: &str, root_sha256: &[u8; 32]) -> Result<VerifiedJws, AppleJwsError> {
    // 1. size and segments
    let [header_b64, payload_b64, signature_b64] = split_segments(jws)?;
    let header = decode_segment(header_b64)?;
    let payload = decode_segment(payload_b64)?;
    let signature = decode_segment(signature_b64)?;

    // 2. header: algorithm, forbidden members, x5c shape
    let chain_der = read_header(&header)?;

    // 3. root pin (never trust a leaf alone; never fetch)
    check_root_pin(&chain_der[2], root_sha256)?;

    // 4. parse
    let chain = parse_chain(&chain_der)?;
    let [leaf, intermediate, root] = &chain;
    let leaf_tbs = raw_tbs(&chain_der[0])?;
    let intermediate_tbs = raw_tbs(&chain_der[1])?;

    // 5. Apple OIDs, positions fixed
    check_apple_oids(leaf, intermediate)?;

    // 6. CA flags
    check_ca_flags(leaf, intermediate, root)?;

    // 7. issuer names
    check_issuers(leaf, intermediate, root)?;

    // 8. chain signatures
    check_chain_signature(leaf, leaf_tbs, intermediate)?;
    check_chain_signature(intermediate, intermediate_tbs, root)?;

    // 9. validity at signedDate, never at now
    let signed_date_ms = read_signed_date(&payload)?;
    check_validity(&chain, signed_date_ms)?;

    // 10. the JWS signature itself
    check_jws_signature(leaf, header_b64, payload_b64, &signature)?;

    Ok(VerifiedJws {
        payload,
        signed_date_ms,
    })
}

/// Check 1: at most `MAX_JWS_LEN` bytes, exactly three non-empty `.`-separated segments.
fn split_segments(jws: &str) -> Result<[&str; 3], AppleJwsError> {
    if jws.len() > MAX_JWS_LEN {
        return Err(AppleJwsError::Malformed);
    }

    let mut parts = jws.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AppleJwsError::Malformed);
    };

    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(AppleJwsError::Malformed);
    }

    Ok([header, payload, signature])
}

/// Check 1: base64url without padding (`URL_SAFE_NO_PAD` refuses `=` and non-canonical trailing bits).
fn decode_segment(segment: &str) -> Result<Vec<u8>, AppleJwsError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| AppleJwsError::Malformed)
}

/// Decode a JSON OBJECT into `T`. The object guard comes first because a derived struct also accepts
/// a JSON array (field by field, in order); a repeated known member is a serde `duplicate field` error.
fn json_object<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, AppleJwsError> {
    serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(bytes)
        .map_err(|_| AppleJwsError::Malformed)?;
    serde_json::from_slice(bytes).map_err(|_| AppleJwsError::Malformed)
}

/// A header member whose mere presence (any value, `null` included) refuses the JWS
#[derive(Default)]
struct Present(bool);

impl<'de> Deserialize<'de> for Present {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(Present(true))
    }
}

/// JOSE header members the verifier reads; others (`kid`, `typ`, ...) are ignored. A repeated known
/// member is a serde `duplicate field` error, so a header cannot carry two `alg` values.
#[derive(Deserialize)]
struct JwsHeader {
    #[serde(default)]
    alg: Option<serde_json::Value>,
    #[serde(default)]
    x5c: Option<serde_json::Value>,
    #[serde(default)]
    crit: Present,
    #[serde(default)]
    jku: Present,
    #[serde(default)]
    jwk: Present,
    #[serde(default)]
    x5u: Present,
}

/// Check 2: `alg` exactly `"ES256"`, no `crit`/`jku`/`jwk`/`x5u`, `x5c` an array of exactly 3 strings
/// (standard base64 DER, RFC 7515 section 4.1.6). Returns the three DER certificates in x5c order.
fn read_header(header: &[u8]) -> Result<[Vec<u8>; 3], AppleJwsError> {
    let header: JwsHeader = json_object(header)?;

    match &header.alg {
        Some(serde_json::Value::String(alg)) if alg == "ES256" => {}
        _ => return Err(AppleJwsError::Algorithm),
    }

    if header.crit.0 || header.jku.0 || header.jwk.0 || header.x5u.0 {
        return Err(AppleJwsError::Algorithm);
    }

    let Some(serde_json::Value::Array(x5c)) = &header.x5c else {
        return Err(AppleJwsError::ChainShape);
    };

    if x5c.len() != 3 {
        return Err(AppleJwsError::ChainShape);
    }

    let mut entries = Vec::with_capacity(3);
    for entry in x5c {
        let serde_json::Value::String(entry) = entry else {
            return Err(AppleJwsError::ChainShape);
        };
        entries.push(entry);
    }

    let mut certs = Vec::with_capacity(3);
    for entry in entries {
        certs.push(
            STANDARD
                .decode(entry)
                .map_err(|_| AppleJwsError::Malformed)?,
        );
    }

    certs.try_into().map_err(|_| AppleJwsError::ChainShape)
}

/// Check 3: the third certificate is the pinned root, byte for byte.
fn check_root_pin(root_der: &[u8], root_sha256: &[u8; 32]) -> Result<(), AppleJwsError> {
    if Sha256::digest(root_der).as_slice() == root_sha256.as_slice() {
        Ok(())
    } else {
        Err(AppleJwsError::RootMismatch)
    }
}

/// Check 4: strict DER parse of `[leaf, intermediate, root]`.
fn parse_chain(chain_der: &[Vec<u8>; 3]) -> Result<[Certificate; 3], AppleJwsError> {
    let parse = |bytes: &[u8]| Certificate::from_der(bytes).map_err(|_| AppleJwsError::Malformed);
    Ok([
        parse(&chain_der[0])?,
        parse(&chain_der[1])?,
        parse(&chain_der[2])?,
    ])
}

/// Check 4 (R36): the ORIGINAL `tbsCertificate` TLV of a certificate, sliced from its input DER. The
/// chain signature is verified over these bytes, never over a re-encoding of the parsed TBS.
fn raw_tbs(cert_der: &[u8]) -> Result<&[u8], AppleJwsError> {
    let mut reader = SliceReader::new(cert_der).map_err(|_| AppleJwsError::Malformed)?;
    let tbs = reader
        .sequence(|certificate| {
            let tbs = certificate.tlv_bytes()?;
            certificate.decode::<AnyRef<'_>>()?; // signatureAlgorithm
            certificate.decode::<AnyRef<'_>>()?; // signatureValue
            Ok(tbs)
        })
        .map_err(|_| AppleJwsError::Malformed)?;
    reader.finish(tbs).map_err(|_| AppleJwsError::Malformed)
}

fn has_extension(cert: &Certificate, oid: ObjectIdentifier) -> bool {
    cert.tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .any(|extension| extension.extn_id == oid)
}

/// Check 5: the leaf is a receipt signer and the intermediate a WWDR CA, by position.
fn check_apple_oids(leaf: &Certificate, intermediate: &Certificate) -> Result<(), AppleJwsError> {
    if has_extension(leaf, OID_RECEIPT_SIGNER) && has_extension(intermediate, OID_WWDR_INTERMEDIATE)
    {
        Ok(())
    } else {
        Err(AppleJwsError::MissingOid)
    }
}

/// basicConstraints `cA`; absent = false. Undecodable or repeated = refused.
fn is_ca(cert: &Certificate) -> Result<bool, AppleJwsError> {
    match cert.tbs_certificate.get::<BasicConstraints>() {
        Ok(Some((_, constraints))) => Ok(constraints.ca),
        Ok(None) => Ok(false),
        Err(_) => Err(AppleJwsError::NotCa),
    }
}

/// Check 6: intermediate and root are CAs; the leaf is not.
fn check_ca_flags(
    leaf: &Certificate,
    intermediate: &Certificate,
    root: &Certificate,
) -> Result<(), AppleJwsError> {
    if is_ca(intermediate)? && is_ca(root)? && !is_ca(leaf)? {
        Ok(())
    } else {
        Err(AppleJwsError::NotCa)
    }
}

fn same_name(a: &Name, b: &Name) -> Result<bool, AppleJwsError> {
    let a = a.to_der().map_err(|_| AppleJwsError::IssuerMismatch)?;
    let b = b.to_der().map_err(|_| AppleJwsError::IssuerMismatch)?;
    Ok(a == b)
}

/// Check 7: leaf issuer = intermediate subject, intermediate issuer = root subject (DER equality).
fn check_issuers(
    leaf: &Certificate,
    intermediate: &Certificate,
    root: &Certificate,
) -> Result<(), AppleJwsError> {
    if same_name(
        &leaf.tbs_certificate.issuer,
        &intermediate.tbs_certificate.subject,
    )? && same_name(
        &intermediate.tbs_certificate.issuer,
        &root.tbs_certificate.subject,
    )? {
        Ok(())
    } else {
        Err(AppleJwsError::IssuerMismatch)
    }
}

/// An EC public key on one of the two accepted curves
enum EcKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
}

/// id-ecPublicKey with namedCurve P-256 or P-384, else `UnsupportedKey`.
fn ec_key(spki: &SubjectPublicKeyInfoOwned) -> Result<EcKey, AppleJwsError> {
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(AppleJwsError::UnsupportedKey);
    }

    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or(AppleJwsError::UnsupportedKey)?
        .decode_as::<ObjectIdentifier>()
        .map_err(|_| AppleJwsError::UnsupportedKey)?;

    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or(AppleJwsError::UnsupportedKey)?;

    if curve == OID_CURVE_P256 {
        p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map(EcKey::P256)
            .map_err(|_| AppleJwsError::UnsupportedKey)
    } else if curve == OID_CURVE_P384 {
        p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map(EcKey::P384)
            .map_err(|_| AppleJwsError::UnsupportedKey)
    } else {
        Err(AppleJwsError::UnsupportedKey)
    }
}

/// Check 8: `child_tbs` (the child's ORIGINAL TBS bytes, from `raw_tbs`) is signed by `issuer`'s key
/// with the digest named by `child.signature_algorithm`.
fn check_chain_signature(
    child: &Certificate,
    child_tbs: &[u8],
    issuer: &Certificate,
) -> Result<(), AppleJwsError> {
    let key = ec_key(&issuer.tbs_certificate.subject_public_key_info)?;

    let algorithm = child.signature_algorithm.oid;
    let digest = if algorithm == OID_ECDSA_WITH_SHA256 {
        Sha256::digest(child_tbs).to_vec()
    } else if algorithm == OID_ECDSA_WITH_SHA384 {
        Sha384::digest(child_tbs).to_vec()
    } else {
        return Err(AppleJwsError::ChainSignature);
    };

    let signature = child
        .signature
        .as_bytes()
        .ok_or(AppleJwsError::ChainSignature)?;

    match key {
        EcKey::P256(key) => {
            let signature = p256::ecdsa::Signature::from_der(signature)
                .map_err(|_| AppleJwsError::ChainSignature)?;
            key.verify_prehash(&digest, &signature)
                .map_err(|_| AppleJwsError::ChainSignature)
        }
        EcKey::P384(key) => {
            let signature = p384::ecdsa::Signature::from_der(signature)
                .map_err(|_| AppleJwsError::ChainSignature)?;
            key.verify_prehash(&digest, &signature)
                .map_err(|_| AppleJwsError::ChainSignature)
        }
    }
}

/// The one payload member the verifier reads
#[derive(Deserialize)]
struct SignedDateOnly {
    #[serde(rename = "signedDate", default)]
    signed_date: Option<i64>,
}

/// Check 9: the payload is a JSON object with an integer `signedDate` (epoch ms).
fn read_signed_date(payload: &[u8]) -> Result<i64, AppleJwsError> {
    let payload: SignedDateOnly = json_object(payload)?;
    payload.signed_date.ok_or(AppleJwsError::Malformed)
}

/// Check 9: `notBefore <= signedDate <= notAfter` for all three certificates. Validity is judged at
/// `signedDate`, NEVER at the wall clock: a transaction signed while the chain was valid stays
/// verifiable after the leaf expires. Compared in whole seconds (certificate times have second
/// resolution): `signedDate` is floored with `div_euclid(1000)`, so any millisecond inside a bound's
/// second is inside the window.
fn check_validity(chain: &[Certificate; 3], signed_date_ms: i64) -> Result<(), AppleJwsError> {
    let at = signed_date_ms.div_euclid(1000);

    for cert in chain {
        let validity = &cert.tbs_certificate.validity;
        let not_before = i64::try_from(validity.not_before.to_unix_duration().as_secs())
            .map_err(|_| AppleJwsError::Validity)?;
        let not_after = i64::try_from(validity.not_after.to_unix_duration().as_secs())
            .map_err(|_| AppleJwsError::Validity)?;

        if at < not_before || at > not_after {
            return Err(AppleJwsError::Validity);
        }
    }

    Ok(())
}

/// Check 10: a P-256 leaf key, and a 64-byte r||s ES256 signature over ASCII `header_b64.payload_b64`.
fn check_jws_signature(
    leaf: &Certificate,
    header_b64: &str,
    payload_b64: &str,
    signature: &[u8],
) -> Result<(), AppleJwsError> {
    let EcKey::P256(key) = ec_key(&leaf.tbs_certificate.subject_public_key_info)? else {
        return Err(AppleJwsError::UnsupportedKey);
    };

    let signature =
        p256::ecdsa::Signature::from_slice(signature).map_err(|_| AppleJwsError::Signature)?;

    let signing_input = format!("{header_b64}.{payload_b64}");
    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| AppleJwsError::Signature)
}

#[cfg(test)]
mod tests {
    //! Every chain here is generated at test time: keys are derived from fixed labels (SHA-256 /
    //! SHA-384 of the label as the secret scalar), certificates are assembled with `x509-cert` and
    //! signed with RFC 6979 deterministic ECDSA, so no key or certificate file is committed and every
    //! run builds the same bytes. Dates are fixed calendar dates, never relative to the wall clock.

    use super::*;

    use std::str::FromStr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use const_oid::AssociatedOid;
    use der::asn1::{BitString, OctetString, UtcTime};
    use der::{Any, DateTime};
    use ecdsa::signature::{hazmat::PrehashSigner, Signer};
    use hmac::{Hmac, Mac};
    use p256::elliptic_curve::ff::PrimeField;
    use x509_cert::{
        ext::Extension,
        name::{RdnSequence, RelativeDistinguishedName},
        serial_number::SerialNumber,
        spki::AlgorithmIdentifierOwned,
        time::{Time, Validity},
        TbsCertificate, Version,
    };

    const ROOT_DN: &str = "CN=Sloga Test Root CA - G3,O=Sloga Test";
    const INTERMEDIATE_DN: &str = "CN=Sloga Test WWDR CA,O=Sloga Test";
    const LEAF_DN: &str = "CN=Sloga Test Receipt Signer,O=Sloga Test";

    /// secp256k1: a well-formed EC curve the verifier does not accept
    const OID_CURVE_SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
    /// rsaEncryption
    const OID_RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    /// ecdsa-with-SHA512
    const OID_ECDSA_WITH_SHA512: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

    /// Seconds since the epoch of a UTC midnight
    fn day(year: u16, month: u8, date: u8) -> u64 {
        DateTime::new(year, month, date, 0, 0, 0)
            .expect("valid calendar date")
            .unix_duration()
            .as_secs()
    }

    fn day_ms(year: u16, month: u8, date: u8) -> i64 {
        i64::try_from(day(year, month, date) * 1000).expect("fits i64")
    }

    #[derive(Clone)]
    enum TestKey {
        P256(p256::ecdsa::SigningKey),
        P384(p384::ecdsa::SigningKey),
    }

    impl TestKey {
        fn p256(label: &str) -> Self {
            TestKey::P256(
                p256::ecdsa::SigningKey::from_slice(&Sha256::digest(label.as_bytes()))
                    .expect("label hashes to a P-256 scalar"),
            )
        }

        fn p384(label: &str) -> Self {
            TestKey::P384(
                p384::ecdsa::SigningKey::from_slice(&Sha384::digest(label.as_bytes()))
                    .expect("label hashes to a P-384 scalar"),
            )
        }

        fn point(&self) -> Vec<u8> {
            match self {
                TestKey::P256(key) => key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
                TestKey::P384(key) => key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            }
        }

        fn spki(&self) -> SubjectPublicKeyInfoOwned {
            match self {
                TestKey::P256(_) => ec_spki(OID_CURVE_P256, &self.point()),
                TestKey::P384(_) => ec_spki(OID_CURVE_P384, &self.point()),
            }
        }

        /// The natural certificate signature algorithm of the key (as Apple pairs them)
        fn signature_algorithm(&self) -> ObjectIdentifier {
            match self {
                TestKey::P256(_) => OID_ECDSA_WITH_SHA256,
                TestKey::P384(_) => OID_ECDSA_WITH_SHA384,
            }
        }

        /// DER ECDSA signature over `message` with the key's natural digest
        fn sign_der(&self, message: &[u8]) -> Vec<u8> {
            match self {
                TestKey::P256(key) => {
                    let signature: p256::ecdsa::Signature = key
                        .sign_prehash(&Sha256::digest(message))
                        .expect("P-256 signs");
                    signature.to_der().as_bytes().to_vec()
                }
                TestKey::P384(key) => {
                    let signature: p384::ecdsa::Signature = key
                        .sign_prehash(&Sha384::digest(message))
                        .expect("P-384 signs");
                    signature.to_der().as_bytes().to_vec()
                }
            }
        }
    }

    fn ec_spki_with(
        algorithm: ObjectIdentifier,
        curve: ObjectIdentifier,
        point: &[u8],
    ) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: algorithm,
                parameters: Some(Any::encode_from(&curve).expect("OID encodes")),
            },
            subject_public_key: BitString::from_bytes(point).expect("point fits a BIT STRING"),
        }
    }

    fn ec_spki(curve: ObjectIdentifier, point: &[u8]) -> SubjectPublicKeyInfoOwned {
        ec_spki_with(OID_EC_PUBLIC_KEY, curve, point)
    }

    fn utc(seconds: u64) -> Time {
        Time::UtcTime(
            UtcTime::from_unix_duration(Duration::from_secs(seconds)).expect("UTCTime range"),
        )
    }

    /// The JWS signing key: the private half of the genuine test leaf
    fn jws_key() -> p256::ecdsa::SigningKey {
        match TestKey::p256("leaf") {
            TestKey::P256(key) => key,
            TestKey::P384(_) => unreachable!(),
        }
    }

    struct CertSpec<'a> {
        subject: &'a str,
        issuer: &'a str,
        spki: SubjectPublicKeyInfoOwned,
        signer: &'a TestKey,
        signature_algorithm: ObjectIdentifier,
        validity: (u64, u64),
        ca: Option<bool>,
        oids: &'a [ObjectIdentifier],
        serial: u8,
    }

    fn certificate(spec: CertSpec<'_>) -> Vec<u8> {
        let mut extensions: Vec<Extension> = Vec::new();
        if let Some(ca) = spec.ca {
            extensions.push(Extension {
                extn_id: BasicConstraints::OID,
                critical: true,
                extn_value: OctetString::new(
                    BasicConstraints {
                        ca,
                        path_len_constraint: None,
                    }
                    .to_der()
                    .expect("basicConstraints encodes"),
                )
                .expect("octet string"),
            });
        }
        for oid in spec.oids {
            extensions.push(Extension {
                extn_id: *oid,
                critical: false,
                // DER NULL, as Apple's marker extensions carry
                extn_value: OctetString::new(vec![0x05, 0x00]).expect("octet string"),
            });
        }

        let algorithm = AlgorithmIdentifierOwned {
            oid: spec.signature_algorithm,
            parameters: None,
        };

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[spec.serial]).expect("serial"),
            signature: algorithm.clone(),
            issuer: Name::from_str(spec.issuer).expect("issuer DN"),
            validity: Validity {
                not_before: utc(spec.validity.0),
                not_after: utc(spec.validity.1),
            },
            subject: Name::from_str(spec.subject).expect("subject DN"),
            subject_public_key_info: spec.spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: if extensions.is_empty() {
                None
            } else {
                Some(extensions)
            },
        };

        let signature = spec.signer.sign_der(&tbs.to_der().expect("TBS encodes"));

        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: algorithm,
            signature: BitString::from_bytes(&signature).expect("signature BIT STRING"),
        }
        .to_der()
        .expect("certificate encodes")
    }

    /// One knob per forgery; `genuine()` is the well-formed test chain.
    struct ChainSpec {
        root_key: TestKey,
        intermediate_key: TestKey,
        leaf_key: TestKey,
        /// None = signed by `root_key`
        intermediate_signer: Option<TestKey>,
        /// None = signed by `intermediate_key`
        leaf_signer: Option<TestKey>,
        root_ca: Option<bool>,
        intermediate_ca: Option<bool>,
        leaf_ca: Option<bool>,
        intermediate_oids: Vec<ObjectIdentifier>,
        leaf_oids: Vec<ObjectIdentifier>,
        root_validity: (u64, u64),
        intermediate_validity: (u64, u64),
        leaf_validity: (u64, u64),
        intermediate_issuer: &'static str,
        leaf_issuer: &'static str,
        /// Replaces the intermediate's SPKI (the intermediate still signs with `intermediate_key`)
        intermediate_spki: Option<SubjectPublicKeyInfoOwned>,
        /// Replaces the algorithm the leaf certificate declares (the signer's digest is unchanged)
        leaf_signature_algorithm: Option<ObjectIdentifier>,
    }

    impl ChainSpec {
        fn genuine() -> Self {
            ChainSpec {
                root_key: TestKey::p384("root"),
                intermediate_key: TestKey::p384("intermediate"),
                leaf_key: TestKey::p256("leaf"),
                intermediate_signer: None,
                leaf_signer: None,
                root_ca: Some(true),
                intermediate_ca: Some(true),
                leaf_ca: None,
                intermediate_oids: vec![OID_WWDR_INTERMEDIATE],
                leaf_oids: vec![OID_RECEIPT_SIGNER],
                root_validity: (day(2020, 1, 1), day(2049, 1, 1)),
                intermediate_validity: (day(2020, 1, 1), day(2049, 1, 1)),
                leaf_validity: (day(2024, 1, 1), day(2049, 1, 1)),
                intermediate_issuer: ROOT_DN,
                leaf_issuer: INTERMEDIATE_DN,
                intermediate_spki: None,
                leaf_signature_algorithm: None,
            }
        }

        /// `[leaf, intermediate, root]` DER
        fn build(&self) -> [Vec<u8>; 3] {
            let root = certificate(CertSpec {
                subject: ROOT_DN,
                issuer: ROOT_DN,
                spki: self.root_key.spki(),
                signer: &self.root_key,
                signature_algorithm: self.root_key.signature_algorithm(),
                validity: self.root_validity,
                ca: self.root_ca,
                oids: &[],
                serial: 1,
            });

            let intermediate_signer = self.intermediate_signer.as_ref().unwrap_or(&self.root_key);
            let intermediate = certificate(CertSpec {
                subject: INTERMEDIATE_DN,
                issuer: self.intermediate_issuer,
                spki: self
                    .intermediate_spki
                    .clone()
                    .unwrap_or_else(|| self.intermediate_key.spki()),
                signer: intermediate_signer,
                signature_algorithm: intermediate_signer.signature_algorithm(),
                validity: self.intermediate_validity,
                ca: self.intermediate_ca,
                oids: &self.intermediate_oids,
                serial: 2,
            });

            let leaf_signer = self.leaf_signer.as_ref().unwrap_or(&self.intermediate_key);
            let leaf = certificate(CertSpec {
                subject: LEAF_DN,
                issuer: self.leaf_issuer,
                spki: self.leaf_key.spki(),
                signer: leaf_signer,
                signature_algorithm: self
                    .leaf_signature_algorithm
                    .unwrap_or_else(|| leaf_signer.signature_algorithm()),
                validity: self.leaf_validity,
                ca: self.leaf_ca,
                oids: &self.leaf_oids,
                serial: 3,
            });

            [leaf, intermediate, root]
        }
    }

    fn sha256_of(der: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(der));
        out
    }

    /// The pin the tests trust: the genuine test root
    fn test_root_sha256() -> [u8; 32] {
        sha256_of(&ChainSpec::genuine().build()[2])
    }

    /// Default `signedDate`: inside every genuine validity window
    fn default_signed_ms() -> i64 {
        day_ms(2026, 1, 1)
    }

    fn payload_json(signed_date_ms: i64) -> String {
        format!(
            r#"{{"transactionId":"2000000000000001","productId":"gg.sloga.prot.p5","type":"Consumable","signedDate":{signed_date_ms}}}"#
        )
    }

    fn x5c(chain: &[Vec<u8>]) -> Vec<String> {
        chain.iter().map(|der| STANDARD.encode(der)).collect()
    }

    fn header_json(alg: &str, chain: &[Vec<u8>]) -> String {
        serde_json::json!({ "alg": alg, "x5c": x5c(chain) }).to_string()
    }

    fn signing_input(header: &str, payload: &str) -> String {
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        )
    }

    /// Compact JWS, ES256-signed with the genuine test leaf key
    fn es256_jws(header: &str, payload: &str) -> String {
        let input = signing_input(header, payload);
        let signature: p256::ecdsa::Signature = jws_key().sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    /// The JWS of `spec`'s chain over the default payload at `signed_date_ms`, plus the hash of the
    /// chain's own root (so a forgery is judged by the checks after the root pin)
    fn signed(spec: &ChainSpec, signed_date_ms: i64) -> (String, [u8; 32]) {
        let chain = spec.build();
        let jws = es256_jws(&header_json("ES256", &chain), &payload_json(signed_date_ms));
        (jws, sha256_of(&chain[2]))
    }

    fn refusal(spec: &ChainSpec, signed_date_ms: i64) -> Option<AppleJwsError> {
        let (jws, root) = signed(spec, signed_date_ms);
        verify_apple_jws(&jws, &root).err()
    }

    fn refusal_of(jws: &str) -> Option<AppleJwsError> {
        verify_apple_jws(jws, &test_root_sha256()).err()
    }

    /// Replace one `.`-separated segment of a compact JWS
    fn with_segment(jws: &str, index: usize, segment: &str) -> String {
        let mut parts: Vec<&str> = jws.split('.').collect();
        parts[index] = segment;
        parts.join(".")
    }

    fn hex32(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64, "a SHA-256 is 64 hex digits");
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).expect("hex digit");
        }
        out
    }

    /// The JWS of an explicit `[leaf, intermediate, root]` DER chain, plus the hash of its own root
    fn chain_jws(chain: &[Vec<u8>; 3], signed_date_ms: i64) -> (String, [u8; 32]) {
        let jws = es256_jws(&header_json("ES256", chain), &payload_json(signed_date_ms));
        (jws, sha256_of(&chain[2]))
    }

    /// Minimal DER length octets
    fn der_length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![u8::try_from(len).unwrap()]
        } else if len <= 0xff {
            vec![0x81, u8::try_from(len).unwrap()]
        } else {
            let [high, low] = u16::try_from(len)
                .expect("test certificates stay under 64 KiB")
                .to_be_bytes();
            vec![0x82, high, low]
        }
    }

    fn der_sequence(content: &[u8]) -> Vec<u8> {
        [vec![0x30], der_length(content.len()), content.to_vec()].concat()
    }

    /// The content of an outer SEQUENCE TLV
    fn sequence_content(der: &[u8]) -> &[u8] {
        assert_eq!(der[0], 0x30);
        let header_len = match der[1] {
            0x81 => 3,
            0x82 => 4,
            short if short < 0x80 => 2,
            other => panic!("unexpected length octet {other:#x}"),
        };
        &der[header_len..]
    }

    /// The same certificate with a non-minimal outer length (0x83, three length octets)
    fn long_form_length(der: &[u8]) -> Vec<u8> {
        let content = sequence_content(der);
        let [high, low] = u16::try_from(content.len()).unwrap().to_be_bytes();
        [vec![0x30, 0x83, 0x00, high, low], content.to_vec()].concat()
    }

    /// The same certificate with an indefinite outer length (BER, never DER)
    fn indefinite_length(der: &[u8]) -> Vec<u8> {
        [
            vec![0x30, 0x80],
            sequence_content(der).to_vec(),
            vec![0x00, 0x00],
        ]
        .concat()
    }

    /// The genuine chain with the leaf's TBS edited, then re-signed by the intermediate
    fn resign_leaf(edit: impl FnOnce(&mut TbsCertificate)) -> [Vec<u8>; 3] {
        let mut chain = ChainSpec::genuine().build();
        let mut leaf = Certificate::from_der(&chain[0]).expect("genuine leaf parses");
        edit(&mut leaf.tbs_certificate);
        let signature = TestKey::p384("intermediate")
            .sign_der(&leaf.tbs_certificate.to_der().expect("TBS encodes"));
        leaf.signature = BitString::from_bytes(&signature).expect("signature BIT STRING");
        chain[0] = leaf.to_der().expect("certificate encodes");
        chain
    }

    // ---- the genuine test chain ----

    #[test]
    fn genuine_test_chain_verifies() {
        let signed_date = default_signed_ms();
        let (jws, root) = signed(&ChainSpec::genuine(), signed_date);
        assert_eq!(root, test_root_sha256());

        let verified = verify_apple_jws(&jws, &root).expect("the genuine test chain verifies");
        assert_eq!(verified.signed_date_ms, signed_date);
        assert_eq!(verified.payload, payload_json(signed_date).into_bytes());
    }

    #[test]
    fn genuine_chain_is_refused_under_another_pin() {
        let (jws, root) = signed(&ChainSpec::genuine(), default_signed_ms());
        let mut other = root;
        other[0] ^= 0x01;
        assert_eq!(
            verify_apple_jws(&jws, &other).err(),
            Some(AppleJwsError::RootMismatch)
        );
    }

    // ---- check 1: size and segments ----

    #[test]
    fn oversize_jws_is_malformed() {
        assert_eq!(
            refusal_of(&"a".repeat(MAX_JWS_LEN + 1)),
            Some(AppleJwsError::Malformed)
        );
    }

    /// A genuine JWS whose total length is exactly `target`, by padding the payload and a `kid`
    fn genuine_jws_of_length(target: usize) -> String {
        let b64_len = |bytes: usize| (bytes * 4).div_ceil(3);
        let chain = ChainSpec::genuine().build();
        let signed_date = default_signed_ms();
        let payload_base = format!(r#"{{"signedDate":{signed_date},"pad":""}}"#);

        for kid_len in 0..8 {
            let header = serde_json::json!({
                "alg": "ES256",
                "kid": "k".repeat(kid_len),
                "x5c": x5c(&chain),
            })
            .to_string();
            let fixed = b64_len(header.len()) + 1 + 1 + 86;
            for pad in 0..MAX_JWS_LEN {
                if fixed + b64_len(payload_base.len() + pad) == target {
                    let payload = format!(
                        r#"{{"signedDate":{signed_date},"pad":"{}"}}"#,
                        "x".repeat(pad)
                    );
                    let jws = es256_jws(&header, &payload);
                    assert_eq!(jws.len(), target);
                    return jws;
                }
            }
        }
        panic!("no padding reaches {target} bytes");
    }

    #[test]
    fn size_limit_is_inclusive() {
        let at_limit = genuine_jws_of_length(MAX_JWS_LEN);
        assert!(verify_apple_jws(&at_limit, &test_root_sha256()).is_ok());

        let over_limit = genuine_jws_of_length(MAX_JWS_LEN + 1);
        assert_eq!(refusal_of(&over_limit), Some(AppleJwsError::Malformed));
    }

    #[test]
    fn wrong_segment_count_or_empty_segment_is_malformed() {
        let (jws, _) = signed(&ChainSpec::genuine(), default_signed_ms());
        let parts: Vec<&str> = jws.split('.').collect();

        for broken in [
            format!("{}.{}", parts[0], parts[1]),
            format!("{jws}.{}", parts[2]),
            format!(".{}.{}", parts[1], parts[2]),
            format!("{}..{}", parts[0], parts[2]),
            format!("{}.{}.", parts[0], parts[1]),
            String::new(),
        ] {
            assert_eq!(
                refusal_of(&broken),
                Some(AppleJwsError::Malformed),
                "{broken:.40}"
            );
        }
    }

    #[test]
    fn padded_or_non_url_base64_is_malformed() {
        let (jws, _) = signed(&ChainSpec::genuine(), default_signed_ms());
        let parts: Vec<&str> = jws.split('.').collect();

        // padding
        assert_eq!(
            refusal_of(&with_segment(&jws, 2, &format!("{}==", parts[2]))),
            Some(AppleJwsError::Malformed)
        );
        // standard-alphabet characters in a base64url segment
        let standard_header = STANDARD.encode(URL_SAFE_NO_PAD.decode(parts[0]).unwrap());
        let standard_header = format!("{}+/", standard_header.trim_end_matches('='));
        assert_eq!(
            refusal_of(&with_segment(&jws, 0, &standard_header)),
            Some(AppleJwsError::Malformed)
        );
        // whitespace
        assert_eq!(
            refusal_of(&with_segment(&jws, 1, &format!(" {}", parts[1]))),
            Some(AppleJwsError::Malformed)
        );
    }

    // ---- check 2: header ----

    #[test]
    fn non_object_or_duplicate_header_is_malformed() {
        let chain = ChainSpec::genuine().build();
        let payload = payload_json(default_signed_ms());
        let entries = serde_json::to_string(&x5c(&chain)).unwrap();

        for header in [
            "not json".to_string(),
            "[\"ES256\"]".to_string(),
            format!(r#"{{"alg":"none","alg":"ES256","x5c":{entries}}}"#),
        ] {
            assert_eq!(
                refusal_of(&es256_jws(&header, &payload)),
                Some(AppleJwsError::Malformed),
                "{header:.40}"
            );
        }
    }

    #[test]
    fn alg_none_is_refused() {
        let chain = ChainSpec::genuine().build();
        let jws = es256_jws(
            &header_json("none", &chain),
            &payload_json(default_signed_ms()),
        );
        assert_eq!(refusal_of(&jws), Some(AppleJwsError::Algorithm));
    }

    #[test]
    fn hs256_with_the_public_key_is_refused() {
        // The classic algorithm-confusion forgery: HMAC-SHA256 keyed with the leaf's public key bytes
        // (the uncompressed SEC1 point, exactly the SPKI BIT STRING content).
        let chain = ChainSpec::genuine().build();
        let input = signing_input(
            &header_json("HS256", &chain),
            &payload_json(default_signed_ms()),
        );
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&TestKey::p256("leaf").point())
            .expect("HMAC takes any key length");
        Mac::update(&mut mac, input.as_bytes());
        let tag = mac.finalize().into_bytes();
        let jws = format!("{input}.{}", URL_SAFE_NO_PAD.encode(tag));

        assert_eq!(refusal_of(&jws), Some(AppleJwsError::Algorithm));
    }

    #[test]
    fn other_or_missing_alg_is_refused() {
        let chain = ChainSpec::genuine().build();
        let payload = payload_json(default_signed_ms());
        let entries = x5c(&chain);

        for header in [
            serde_json::json!({ "alg": "ES384", "x5c": entries }),
            serde_json::json!({ "alg": "HS512", "x5c": entries }),
            serde_json::json!({ "alg": "es256", "x5c": entries }),
            serde_json::json!({ "alg": "ES256 ", "x5c": entries }),
            serde_json::json!({ "alg": null, "x5c": entries }),
            serde_json::json!({ "alg": ["ES256"], "x5c": entries }),
            serde_json::json!({ "x5c": entries }),
        ] {
            assert_eq!(
                refusal_of(&es256_jws(&header.to_string(), &payload)),
                Some(AppleJwsError::Algorithm),
                "{header}"
            );
        }
    }

    #[test]
    fn crit_jku_jwk_x5u_are_refused() {
        let chain = ChainSpec::genuine().build();
        let payload = payload_json(default_signed_ms());

        for member in ["crit", "jku", "jwk", "x5u"] {
            for value in [
                serde_json::json!(["exp"]),
                serde_json::json!("https://example.invalid/"),
                serde_json::Value::Null,
            ] {
                let mut header = serde_json::json!({ "alg": "ES256", "x5c": x5c(&chain) });
                header[member] = value.clone();
                assert_eq!(
                    refusal_of(&es256_jws(&header.to_string(), &payload)),
                    Some(AppleJwsError::Algorithm),
                    "{member} = {value}"
                );
            }
        }
    }

    #[test]
    fn leaf_only_x5c_is_refused() {
        let chain = ChainSpec::genuine().build();
        let jws = es256_jws(
            &header_json("ES256", &chain[..1]),
            &payload_json(default_signed_ms()),
        );
        assert_eq!(refusal_of(&jws), Some(AppleJwsError::ChainShape));
    }

    #[test]
    fn two_cert_x5c_missing_intermediate_is_refused() {
        let chain = ChainSpec::genuine().build();
        let two = [chain[0].clone(), chain[2].clone()];
        let jws = es256_jws(
            &header_json("ES256", &two),
            &payload_json(default_signed_ms()),
        );
        assert_eq!(refusal_of(&jws), Some(AppleJwsError::ChainShape));
    }

    #[test]
    fn other_x5c_shapes_are_refused() {
        let chain = ChainSpec::genuine().build();
        let payload = payload_json(default_signed_ms());
        let entries = x5c(&chain);
        let four = vec![
            entries[0].clone(),
            entries[1].clone(),
            entries[1].clone(),
            entries[2].clone(),
        ];

        for header in [
            serde_json::json!({ "alg": "ES256" }),
            serde_json::json!({ "alg": "ES256", "x5c": null }),
            serde_json::json!({ "alg": "ES256", "x5c": entries[0] }),
            serde_json::json!({ "alg": "ES256", "x5c": four }),
            serde_json::json!({ "alg": "ES256", "x5c": [] }),
            serde_json::json!({ "alg": "ES256", "x5c": [entries[0], entries[1], 7] }),
            serde_json::json!({ "alg": "ES256", "x5c": [entries[0], null, entries[2]] }),
        ] {
            assert_eq!(
                refusal_of(&es256_jws(&header.to_string(), &payload)),
                Some(AppleJwsError::ChainShape),
                "{header:.60}"
            );
        }
    }

    #[test]
    fn non_standard_base64_x5c_entry_is_malformed() {
        let chain = ChainSpec::genuine().build();
        let payload = payload_json(default_signed_ms());
        let entries = x5c(&chain);
        let url_safe_leaf = URL_SAFE_NO_PAD.encode(&chain[0]);
        // premise: the URL-safe form really differs ('-'/'_' sextets or no padding)
        assert_ne!(url_safe_leaf, entries[0]);

        for leaf in [
            "!!!!".to_string(),
            format!("{} ", entries[0]),
            url_safe_leaf,
        ] {
            let header = serde_json::json!({
                "alg": "ES256",
                "x5c": [leaf, entries[1], entries[2]],
            });
            assert_eq!(
                refusal_of(&es256_jws(&header.to_string(), &payload)),
                Some(AppleJwsError::Malformed),
                "{leaf:.40}"
            );
        }
    }

    // ---- check 3: root pin ----

    #[test]
    fn wrong_root_is_refused() {
        // A self-consistent chain (correct OIDs, CA flags, names and signatures) under an attacker root
        let forged = ChainSpec {
            root_key: TestKey::p384("attacker root"),
            ..ChainSpec::genuine()
        };
        let (jws, forged_root) = signed(&forged, default_signed_ms());
        assert_ne!(forged_root, test_root_sha256());
        assert_eq!(refusal_of(&jws), Some(AppleJwsError::RootMismatch));
    }

    #[test]
    fn genuine_root_in_the_wrong_position_is_refused() {
        // [root, intermediate, leaf]: the pinned root is present but not third
        let chain = ChainSpec::genuine().build();
        let reversed = [chain[2].clone(), chain[1].clone(), chain[0].clone()];
        let jws = es256_jws(
            &header_json("ES256", &reversed),
            &payload_json(default_signed_ms()),
        );
        assert_eq!(refusal_of(&jws), Some(AppleJwsError::RootMismatch));
    }

    // ---- check 4: parse ----

    #[test]
    fn unparseable_certificate_is_malformed() {
        let chain = ChainSpec::genuine().build();
        let mut trailing = chain[0].clone();
        trailing.push(0x00);

        for leaf in [b"not a certificate".to_vec(), trailing] {
            let broken = [leaf, chain[1].clone(), chain[2].clone()];
            let jws = es256_jws(
                &header_json("ES256", &broken),
                &payload_json(default_signed_ms()),
            );
            assert_eq!(refusal_of(&jws), Some(AppleJwsError::Malformed));
        }
    }

    // ---- check 5: Apple OIDs ----

    #[test]
    fn missing_intermediate_oid_is_refused() {
        let forged = ChainSpec {
            intermediate_oids: vec![],
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&forged, default_signed_ms()),
            Some(AppleJwsError::MissingOid)
        );
    }

    #[test]
    fn missing_leaf_oid_is_refused() {
        let forged = ChainSpec {
            leaf_oids: vec![],
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&forged, default_signed_ms()),
            Some(AppleJwsError::MissingOid)
        );
    }

    #[test]
    fn swapped_oids_are_refused() {
        // Everything else is valid: only the two marker OIDs trade places
        let forged = ChainSpec {
            intermediate_oids: vec![OID_RECEIPT_SIGNER],
            leaf_oids: vec![OID_WWDR_INTERMEDIATE],
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&forged, default_signed_ms()),
            Some(AppleJwsError::MissingOid)
        );
    }

    // ---- check 6: CA flags ----

    #[test]
    fn intermediate_without_ca_is_refused() {
        for intermediate_ca in [None, Some(false)] {
            let forged = ChainSpec {
                intermediate_ca,
                ..ChainSpec::genuine()
            };
            assert_eq!(
                refusal(&forged, default_signed_ms()),
                Some(AppleJwsError::NotCa),
                "{intermediate_ca:?}"
            );
        }
    }

    #[test]
    fn root_without_ca_is_refused() {
        for root_ca in [None, Some(false)] {
            let forged = ChainSpec {
                root_ca,
                ..ChainSpec::genuine()
            };
            assert_eq!(
                refusal(&forged, default_signed_ms()),
                Some(AppleJwsError::NotCa),
                "{root_ca:?}"
            );
        }
    }

    #[test]
    fn leaf_ca_flag() {
        let ca_leaf = ChainSpec {
            leaf_ca: Some(true),
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&ca_leaf, default_signed_ms()),
            Some(AppleJwsError::NotCa)
        );

        // an explicit cA = false on the leaf is fine
        let plain_leaf = ChainSpec {
            leaf_ca: Some(false),
            ..ChainSpec::genuine()
        };
        assert_eq!(refusal(&plain_leaf, default_signed_ms()), None);
    }

    // ---- check 7: issuer names ----

    #[test]
    fn issuer_mismatch_is_refused() {
        let leaf_issuer = ChainSpec {
            leaf_issuer: "CN=Sloga Test Other CA,O=Sloga Test",
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&leaf_issuer, default_signed_ms()),
            Some(AppleJwsError::IssuerMismatch)
        );

        let intermediate_issuer = ChainSpec {
            intermediate_issuer: "CN=Sloga Test Other Root,O=Sloga Test",
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&intermediate_issuer, default_signed_ms()),
            Some(AppleJwsError::IssuerMismatch)
        );
    }

    // ---- check 8: chain signatures ----

    #[test]
    fn leaf_signed_by_a_stranger_is_refused() {
        let forged = ChainSpec {
            leaf_signer: Some(TestKey::p384("stranger")),
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&forged, default_signed_ms()),
            Some(AppleJwsError::ChainSignature)
        );
    }

    #[test]
    fn intermediate_signed_by_a_stranger_is_refused() {
        let forged = ChainSpec {
            intermediate_signer: Some(TestKey::p384("stranger")),
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&forged, default_signed_ms()),
            Some(AppleJwsError::ChainSignature)
        );
    }

    #[test]
    fn undeclared_digest_is_refused() {
        // ecdsa-with-SHA512 declared: not one of the two accepted algorithms
        let sha512 = ChainSpec {
            leaf_signature_algorithm: Some(OID_ECDSA_WITH_SHA512),
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&sha512, default_signed_ms()),
            Some(AppleJwsError::ChainSignature)
        );

        // SHA-256 declared, SHA-384 used: the digests disagree
        let mismatched = ChainSpec {
            leaf_signature_algorithm: Some(OID_ECDSA_WITH_SHA256),
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&mismatched, default_signed_ms()),
            Some(AppleJwsError::ChainSignature)
        );
    }

    #[test]
    fn unsupported_issuer_key_is_refused() {
        let point = TestKey::p384("intermediate").point();
        for spki in [
            ec_spki(OID_CURVE_SECP256K1, &point),
            ec_spki_with(OID_RSA_ENCRYPTION, OID_CURVE_P384, &point),
            ec_spki(OID_CURVE_P384, &point[..point.len() - 1]),
        ] {
            let forged = ChainSpec {
                intermediate_spki: Some(spki),
                ..ChainSpec::genuine()
            };
            assert_eq!(
                refusal(&forged, default_signed_ms()),
                Some(AppleJwsError::UnsupportedKey)
            );
        }
    }

    // ---- check 9: signedDate and validity ----

    #[test]
    fn missing_or_non_integer_signed_date_is_malformed() {
        let chain = ChainSpec::genuine().build();
        let header = header_json("ES256", &chain);

        for payload in [
            r#"{"transactionId":"2000000000000001"}"#.to_string(),
            r#"{"signedDate":null}"#.to_string(),
            r#"{"signedDate":"1767225600000"}"#.to_string(),
            r#"{"signedDate":1767225600000.5}"#.to_string(),
            r#"{"signedDate":1,"signedDate":1767225600000}"#.to_string(),
            "[1767225600000]".to_string(),
            "not json".to_string(),
        ] {
            assert_eq!(
                refusal_of(&es256_jws(&header, &payload)),
                Some(AppleJwsError::Malformed),
                "{payload}"
            );
        }
    }

    #[test]
    fn valid_at_signed_date_expired_now_is_accepted() {
        // The leaf expired on 2025-01-01; the transaction was signed on 2024-06-01.
        let leaf_not_after = day(2025, 1, 1);
        let spec = ChainSpec {
            leaf_validity: (day(2023, 1, 1), leaf_not_after),
            ..ChainSpec::genuine()
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_secs();
        assert!(
            now > leaf_not_after,
            "premise: the leaf is expired by the wall clock"
        );

        let signed_date = day_ms(2024, 6, 1);
        let (jws, root) = signed(&spec, signed_date);
        let verified = verify_apple_jws(&jws, &root).expect("valid at signedDate is accepted");
        assert_eq!(verified.signed_date_ms, signed_date);
    }

    #[test]
    fn not_yet_valid_at_signed_date_is_refused() {
        // signedDate 2023-06-01 is before the leaf's notBefore (2024-01-01); the leaf is valid now.
        assert_eq!(
            refusal(&ChainSpec::genuine(), day_ms(2023, 6, 1)),
            Some(AppleJwsError::Validity)
        );
    }

    #[test]
    fn expired_intermediate_at_signed_date_is_refused() {
        // The intermediate expires 2048-01-01 and the transaction claims 2048-06-01. The intermediate is
        // valid by the wall clock (until 2048), so a verifier that checks "now" accepts this JWS.
        let spec = ChainSpec {
            intermediate_validity: (day(2020, 1, 1), day(2048, 1, 1)),
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&spec, day_ms(2048, 6, 1)),
            Some(AppleJwsError::Validity)
        );
    }

    #[test]
    fn root_outside_validity_at_signed_date_is_refused() {
        let spec = ChainSpec {
            root_validity: (day(2025, 1, 1), day(2049, 1, 1)),
            leaf_validity: (day(2020, 1, 1), day(2049, 1, 1)),
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&spec, day_ms(2024, 6, 1)),
            Some(AppleJwsError::Validity)
        );
    }

    #[test]
    fn validity_bounds_are_inclusive() {
        let (not_before, not_after) = (day(2024, 1, 1), day(2030, 1, 1));
        let spec = ChainSpec {
            leaf_validity: (not_before, not_after),
            ..ChainSpec::genuine()
        };
        let not_before_ms = i64::try_from(not_before * 1000).unwrap();
        let not_after_ms = i64::try_from(not_after * 1000).unwrap();

        assert_eq!(refusal(&spec, not_before_ms), None);
        assert_eq!(refusal(&spec, not_after_ms), None);
        // whole seconds (section 36, NIT 6): the notAfter second is inside to its last millisecond
        assert_eq!(refusal(&spec, not_after_ms + 999), None);
        assert_eq!(
            refusal(&spec, not_before_ms - 1),
            Some(AppleJwsError::Validity)
        );
        assert_eq!(
            refusal(&spec, not_after_ms + 1000),
            Some(AppleJwsError::Validity)
        );
        assert_eq!(refusal(&spec, -1), Some(AppleJwsError::Validity));
    }

    #[test]
    fn signed_date_extremes_and_seconds_are_refused() {
        // far future but inside every window: the verifier accepts it (the freshness bound is the caller's)
        assert_eq!(refusal(&ChainSpec::genuine(), day_ms(2048, 12, 31)), None);
        assert_eq!(
            refusal(&ChainSpec::genuine(), i64::MAX),
            Some(AppleJwsError::Validity)
        );
        assert_eq!(
            refusal(&ChainSpec::genuine(), i64::MIN),
            Some(AppleJwsError::Validity)
        );
        // seconds instead of ms: 2026-01-01 in seconds reads as 1970-01-21
        assert_eq!(
            refusal(&ChainSpec::genuine(), day_ms(2026, 1, 1) / 1000),
            Some(AppleJwsError::Validity)
        );
    }

    // ---- check 10: the JWS signature ----

    #[test]
    fn tampered_payload_is_refused() {
        let (jws, _) = signed(&ChainSpec::genuine(), default_signed_ms());
        let forged_payload = payload_json(default_signed_ms()).replace("prot.p5", "prot.p99");
        let jws = with_segment(&jws, 1, &URL_SAFE_NO_PAD.encode(forged_payload));
        assert_eq!(refusal_of(&jws), Some(AppleJwsError::Signature));
    }

    #[test]
    fn tampered_signature_is_refused() {
        let (jws, _) = signed(&ChainSpec::genuine(), default_signed_ms());
        let parts: Vec<&str> = jws.split('.').collect();
        let original = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(original.len(), 64);

        // one bit flipped in r, then in s
        for index in [0, 63] {
            let mut flipped = original.clone();
            flipped[index] ^= 0x01;
            let forged = with_segment(&jws, 2, &URL_SAFE_NO_PAD.encode(&flipped));
            assert_eq!(
                refusal_of(&forged),
                Some(AppleJwsError::Signature),
                "byte {index}"
            );
        }

        // the same signature in DER form instead of r||s
        let der = p256::ecdsa::Signature::from_slice(&original)
            .unwrap()
            .to_der()
            .as_bytes()
            .to_vec();
        let forged = with_segment(&jws, 2, &URL_SAFE_NO_PAD.encode(der));
        assert_eq!(refusal_of(&forged), Some(AppleJwsError::Signature));

        // truncated
        let forged = with_segment(&jws, 2, &URL_SAFE_NO_PAD.encode(&original[..63]));
        assert_eq!(refusal_of(&forged), Some(AppleJwsError::Signature));
    }

    #[test]
    fn signature_by_another_p256_key_is_refused() {
        // the chain is genuine; the JWS is signed by a key that is not the leaf's
        let chain = ChainSpec::genuine().build();
        let input = signing_input(
            &header_json("ES256", &chain),
            &payload_json(default_signed_ms()),
        );
        let TestKey::P256(stranger) = TestKey::p256("stranger") else {
            unreachable!()
        };
        let signature: p256::ecdsa::Signature = stranger.sign(input.as_bytes());
        let jws = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        assert_eq!(refusal_of(&jws), Some(AppleJwsError::Signature));
    }

    #[test]
    fn p384_leaf_is_unsupported() {
        let spec = ChainSpec {
            leaf_key: TestKey::p384("leaf"),
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&spec, default_signed_ms()),
            Some(AppleJwsError::UnsupportedKey)
        );
    }

    // ---- order ----

    #[test]
    fn checks_run_in_the_pinned_order() {
        let genuine = ChainSpec::genuine;

        // 1 before 2: a padded segment under `alg: none` is Malformed
        let chain = genuine().build();
        let jws = es256_jws(
            &header_json("none", &chain),
            &payload_json(default_signed_ms()),
        );
        let parts: Vec<&str> = jws.split('.').collect();
        let jws = with_segment(&jws, 2, &format!("{}==", parts[2]));
        assert_eq!(refusal_of(&jws), Some(AppleJwsError::Malformed));

        // 2 before 2 (shape): a bad alg with a one-certificate chain is Algorithm
        let jws = es256_jws(
            &header_json("HS256", &chain[..1]),
            &payload_json(default_signed_ms()),
        );
        assert_eq!(refusal_of(&jws), Some(AppleJwsError::Algorithm));

        // 3 before 5: an attacker root and no leaf OID is RootMismatch
        let spec = ChainSpec {
            root_key: TestKey::p384("attacker root"),
            leaf_oids: vec![],
            ..genuine()
        };
        let (jws, _) = signed(&spec, default_signed_ms());
        assert_eq!(refusal_of(&jws), Some(AppleJwsError::RootMismatch));

        // 4 before 5: a leaf without its OID, in non-minimal DER, is Malformed
        let mut chain = ChainSpec {
            leaf_oids: vec![],
            ..genuine()
        }
        .build();
        chain[0] = long_form_length(&chain[0]);
        let (jws, root) = chain_jws(&chain, default_signed_ms());
        assert_eq!(
            verify_apple_jws(&jws, &root).err(),
            Some(AppleJwsError::Malformed)
        );

        // 5 before 6
        let spec = ChainSpec {
            leaf_oids: vec![],
            intermediate_ca: None,
            ..genuine()
        };
        assert_eq!(
            refusal(&spec, default_signed_ms()),
            Some(AppleJwsError::MissingOid)
        );

        // 6 before 7
        let spec = ChainSpec {
            intermediate_ca: None,
            leaf_issuer: "CN=Sloga Test Other CA,O=Sloga Test",
            ..genuine()
        };
        assert_eq!(
            refusal(&spec, default_signed_ms()),
            Some(AppleJwsError::NotCa)
        );

        // 7 before 8
        let spec = ChainSpec {
            leaf_issuer: "CN=Sloga Test Other CA,O=Sloga Test",
            leaf_signer: Some(TestKey::p384("stranger")),
            ..genuine()
        };
        assert_eq!(
            refusal(&spec, default_signed_ms()),
            Some(AppleJwsError::IssuerMismatch)
        );

        // 8 before 9
        let spec = ChainSpec {
            leaf_signer: Some(TestKey::p384("stranger")),
            ..genuine()
        };
        assert_eq!(
            refusal(&spec, day_ms(2019, 1, 1)),
            Some(AppleJwsError::ChainSignature)
        );

        // 9 before 10: an out-of-window signedDate under a tampered signature is Validity
        let (jws, _) = signed(&genuine(), day_ms(2019, 1, 1));
        let parts: Vec<&str> = jws.split('.').collect();
        let mut flipped = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        flipped[10] ^= 0x01;
        let jws = with_segment(&jws, 2, &URL_SAFE_NO_PAD.encode(&flipped));
        assert_eq!(refusal_of(&jws), Some(AppleJwsError::Validity));
    }

    // ---- section 36 additions ----

    #[test]
    fn unsorted_multi_valued_rdn_leaf_verifies() {
        // DER sorts a SET OF, and x509-cert also SORTS one on decode. A leaf whose issuer signed an
        // unsorted multi-valued RDN is still the issuer's signature, carried only by the ORIGINAL TBS
        // bytes (R36); a verifier that re-encodes the parsed TBS refuses it with ChainSignature.
        let mut chain = ChainSpec::genuine().build();
        let leaf = Certificate::from_der(&chain[0]).expect("genuine leaf parses");

        let rdn = RelativeDistinguishedName::from_str("CN=Sloga Test Receipt Signer+O=Sloga Test")
            .expect("multi-valued RDN");
        let mut tbs = leaf.tbs_certificate.clone();
        tbs.subject = RdnSequence(vec![rdn.clone()]);
        let sorted_tbs = tbs.to_der().expect("TBS encodes");

        // swap the two members of the encoded SET
        let sorted_set = rdn.to_der().expect("RDN encodes");
        let members: Vec<Vec<u8>> = rdn
            .0
            .iter()
            .map(|member| member.to_der().expect("member encodes"))
            .collect();
        assert_eq!(members.len(), 2);
        let header_len = sorted_set.len() - members[0].len() - members[1].len();
        let unsorted_set = [
            sorted_set[..header_len].to_vec(),
            members[1].clone(),
            members[0].clone(),
        ]
        .concat();
        assert_ne!(unsorted_set, sorted_set);
        let at = sorted_tbs
            .windows(sorted_set.len())
            .position(|window| window == sorted_set.as_slice())
            .expect("the subject RDN is in the TBS");
        let unsorted_tbs = [
            sorted_tbs[..at].to_vec(),
            unsorted_set,
            sorted_tbs[at + sorted_set.len()..].to_vec(),
        ]
        .concat();

        let signature = TestKey::p384("intermediate").sign_der(&unsorted_tbs);
        chain[0] = der_sequence(
            &[
                unsorted_tbs.clone(),
                leaf.signature_algorithm
                    .to_der()
                    .expect("algorithm encodes"),
                BitString::from_bytes(&signature)
                    .expect("signature BIT STRING")
                    .to_der()
                    .expect("BIT STRING encodes"),
            ]
            .concat(),
        );

        // premise: it parses, its parsed TBS re-encodes to OTHER bytes than were signed, and
        // `raw_tbs` returns the signed ones
        let reparsed = Certificate::from_der(&chain[0]).expect("an unsorted SET OF still parses");
        assert_ne!(reparsed.tbs_certificate.to_der().unwrap(), unsorted_tbs);
        assert_eq!(raw_tbs(&chain[0]), Ok(unsorted_tbs.as_slice()));

        let (jws, root) = chain_jws(&chain, default_signed_ms());
        assert!(
            verify_apple_jws(&jws, &root).is_ok(),
            "signature checked over the original TBS bytes"
        );
    }

    #[test]
    fn non_minimal_and_indefinite_der_lengths_are_malformed() {
        let chain = ChainSpec::genuine().build();
        for index in 0..3 {
            for broken in [
                long_form_length(&chain[index]),
                indefinite_length(&chain[index]),
            ] {
                let mut forged = chain.clone();
                forged[index] = broken;
                // the hash of the forged root is passed, so a forged root reaches the parse too
                let (jws, root) = chain_jws(&forged, default_signed_ms());
                assert_eq!(
                    verify_apple_jws(&jws, &root).err(),
                    Some(AppleJwsError::Malformed),
                    "certificate {index}"
                );
            }
        }
    }

    #[test]
    fn duplicate_or_undecodable_basic_constraints_is_not_ca() {
        let constraints = Extension {
            extn_id: BasicConstraints::OID,
            critical: true,
            extn_value: OctetString::new(
                BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                }
                .to_der()
                .expect("basicConstraints encodes"),
            )
            .expect("octet string"),
        };
        let duplicate = constraints.clone();
        let chain = resign_leaf(move |tbs| {
            let extensions = tbs.extensions.get_or_insert_with(Vec::new);
            extensions.push(constraints);
            extensions.push(duplicate);
        });
        let (jws, root) = chain_jws(&chain, default_signed_ms());
        assert_eq!(
            verify_apple_jws(&jws, &root).err(),
            Some(AppleJwsError::NotCa)
        );

        // an OCTET STRING where the SEQUENCE belongs
        let chain = resign_leaf(|tbs| {
            tbs.extensions.get_or_insert_with(Vec::new).push(Extension {
                extn_id: BasicConstraints::OID,
                critical: true,
                extn_value: OctetString::new(vec![0x04, 0x00]).expect("octet string"),
            });
        });
        let (jws, root) = chain_jws(&chain, default_signed_ms());
        assert_eq!(
            verify_apple_jws(&jws, &root).err(),
            Some(AppleJwsError::NotCa)
        );
    }

    #[test]
    fn leaf_signed_directly_by_the_root_is_refused() {
        // three certificates, but the root signed the leaf: the intermediate's key does not verify it
        let spec = ChainSpec {
            leaf_signer: Some(TestKey::p384("root")),
            ..ChainSpec::genuine()
        };
        assert_eq!(
            refusal(&spec, default_signed_ms()),
            Some(AppleJwsError::ChainSignature)
        );
    }

    #[test]
    fn all_zero_and_all_ff_signatures_are_refused() {
        let (jws, _) = signed(&ChainSpec::genuine(), default_signed_ms());
        for signature in [vec![0x00u8; 64], vec![0xffu8; 64]] {
            let forged = with_segment(&jws, 2, &URL_SAFE_NO_PAD.encode(&signature));
            assert_eq!(refusal_of(&forged), Some(AppleJwsError::Signature));
        }
    }

    #[test]
    fn high_s_jws_signature_is_accepted() {
        // Low-S is NOT enforced (section 36: Apple emits high-S signatures; the caller keys
        // idempotency on transactionId, never on JWS bytes). Both forms of one signature verify.
        let (jws, root) = signed(&ChainSpec::genuine(), default_signed_ms());
        let parts: Vec<&str> = jws.split('.').collect();
        let signature =
            p256::ecdsa::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        let low = signature.normalize_s().unwrap_or(signature);
        let (r, s) = low.split_scalars();
        let r: p256::Scalar = *r.as_ref();
        let s: p256::Scalar = *s.as_ref();
        let high = p256::ecdsa::Signature::from_scalars(r.to_repr(), (-s).to_repr()).unwrap();
        assert!(
            high.normalize_s().is_some(),
            "premise: the signature is high-S"
        );
        assert!(
            low.normalize_s().is_none(),
            "premise: the signature is low-S"
        );

        for form in [&low, &high] {
            let forged = with_segment(&jws, 2, &URL_SAFE_NO_PAD.encode(form.to_bytes()));
            assert!(verify_apple_jws(&forged, &root).is_ok());
        }
    }

    #[test]
    fn pinned_root_matches_the_committed_g3_certificate() {
        // The public Apple Root CA - G3 certificate (DER), confirmed 2026-11-02 against the Mac
        // mini's system root store (section 36).
        let g3: &[u8] = include_bytes!("fixtures/AppleRootCA-G3.cer");
        assert_eq!(sha256_of(g3), hex32(APPLE_ROOT_G3_SHA256_HEX));

        let cert = Certificate::from_der(g3).expect("Apple Root CA - G3 parses");
        assert!(matches!(
            ec_key(&cert.tbs_certificate.subject_public_key_info),
            Ok(EcKey::P384(_))
        ));
        assert_eq!(cert.signature_algorithm.oid, OID_ECDSA_WITH_SHA384);
        assert_eq!(is_ca(&cert), Ok(true));
        assert_eq!(
            cert.tbs_certificate.issuer.to_der().unwrap(),
            cert.tbs_certificate.subject.to_der().unwrap()
        );
        // self-signed: its signature verifies over its own raw TBS
        assert_eq!(
            check_chain_signature(&cert, raw_tbs(g3).unwrap(), &cert),
            Ok(())
        );
        assert_eq!(
            cert.tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
            DateTime::new(2039, 4, 30, 18, 19, 6)
                .unwrap()
                .unix_duration()
                .as_secs()
        );
    }

    // ---- constants ----

    #[test]
    fn pinned_constants_are_well_formed() {
        assert!(APPLE_ROOT_G3_SHA256_HEX
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        let pin = hex32(APPLE_ROOT_G3_SHA256_HEX);
        assert_eq!(pin[0], 0x63);
        assert_eq!(pin[31], 0x79);

        assert_eq!(
            ObjectIdentifier::new(APPLE_OID_RECEIPT_SIGNER).unwrap(),
            OID_RECEIPT_SIGNER
        );
        assert_eq!(
            ObjectIdentifier::new(APPLE_OID_WWDR_INTERMEDIATE).unwrap(),
            OID_WWDR_INTERMEDIATE
        );
    }

    // ---- the genuine Apple chain ----

    /// TODO(S6 section 33, capture step): on the test stack, make the first Sandbox purchase of a Prot
    /// pack from the iOS build, save the `signedTransactionInfo` JWS the app posts to
    /// `POST /payments/prot/store/verify` (or the Get Transaction Info answer for that transaction id)
    /// as `src/store/fixtures/apple_sandbox_transaction.jws`, run
    /// `cargo test -p revolt-payments genuine_apple_sandbox_jws -- --ignored`, then record the chain's
    /// (curve, digest) pairs in this module's doc comment and drop the `#[ignore]`.
    #[test]
    #[ignore = "needs a captured sandbox JWS"]
    fn genuine_apple_sandbox_jws_verifies() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/store/fixtures/apple_sandbox_transaction.jws"
        );
        let jws = std::fs::read_to_string(path).expect("captured sandbox JWS present");

        let verified = verify_apple_jws(jws.trim(), &hex32(APPLE_ROOT_G3_SHA256_HEX))
            .expect("a genuine Apple sandbox JWS verifies under the pinned G3 root");
        assert!(verified.signed_date_ms > 0);

        let payload: serde_json::Value =
            serde_json::from_slice(&verified.payload).expect("payload is JSON");
        assert_eq!(payload["environment"], "Sandbox");
        assert_eq!(payload["signedDate"], verified.signed_date_ms);
    }
}
