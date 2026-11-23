//! Software passkey authenticator for the verifier tests (`util/passkey.rs`).
//! Test builds only.
//!
//! It plays both the authenticator and the client (browser, Android Credential
//! Manager, iOS ASAuthorization): it takes the BARE `publicKey` options object
//! the server sends and returns the `PublicKeyCredential.toJSON()` shape the
//! server receives.
//!
//! Deliberately small: ES256 only, attestation `none`, AAGUID zeros, no
//! extensions unless a test injects raw CBOR. Everything hostile a test needs
//! is a public knob on [`SoftPasskey`]; whatever the signature does not cover
//! (`userHandle`, `clientExtensionResults`, top-level members) is tampered
//! with by editing the returned JSON.
//!
//! Signing is `p256` 0.14 (the generation the WebAuthn library itself links).
//! Hashing and randomness are plain bytes in and out, so they use the `sha2`
//! and `rand` versions delta already depends on. CBOR and base64url are
//! hand-rolled so the helper pulls nothing else in.

#![allow(dead_code)]

use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// authenticatorData flag bits (WebAuthn L3 6.1).
pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_BE: u8 = 0x08;
pub const FLAG_BS: u8 = 0x10;
pub const FLAG_AT: u8 = 0x40;
pub const FLAG_ED: u8 = 0x80;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url, no padding.
pub fn b64u(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 4 + 2) / 3);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(n & 63) as usize] as char);
        }
    }
    out
}

/// base64url decode; padding optional. Panics on a character outside the
/// url-safe alphabet (a test bug, not a runtime condition).
pub fn b64u_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v: u32 = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'-' => 62,
            b'_' => 63,
            other => panic!("not base64url: byte {:#x} in {:?}", other, s),
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u32 << bits) - 1;
        }
    }
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

/// CBOR head for major types 2 (bytes), 3 (text), 5 (map) with a definite length.
fn cbor_head(major: u8, len: usize, out: &mut Vec<u8>) {
    let m = major << 5;
    if len < 24 {
        out.push(m | len as u8);
    } else if len < 256 {
        out.push(m | 24);
        out.push(len as u8);
    } else {
        assert!(len < 65536, "cbor length {} too large for this helper", len);
        out.push(m | 25);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

fn cbor_text(s: &str, out: &mut Vec<u8>) {
    cbor_head(3, s.len(), out);
    out.extend_from_slice(s.as_bytes());
}

fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, b.len(), out);
    out.extend_from_slice(b);
}

/// One software passkey: one ES256 key pair bound to whatever RP `create` saw.
pub struct SoftPasskey {
    key: SigningKey,
    /// Credential id (32 random bytes).
    pub cred_id: Vec<u8>,
    /// User handle; captured from `user.id` by `create`, returned by `get`.
    pub user_handle: Option<Vec<u8>>,
    /// Signature counter reported verbatim in authenticatorData. Never
    /// auto-increments: synced passkeys always report 0.
    pub counter: u32,
    /// User present flag.
    pub up: bool,
    /// User verified flag.
    pub uv: bool,
    /// Backup eligible flag (true for a synced passkey).
    pub be: bool,
    /// Backup state flag (true for a synced passkey).
    pub bs: bool,
    /// Hash this RP ID into authenticatorData instead of the one in the options.
    pub rp_id_override: Option<String>,
    /// Put this in clientDataJSON.type instead of webauthn.create / webauthn.get.
    pub client_data_type_override: Option<String>,
    /// Answer a `get` even when allowCredentials does not list this credential.
    pub ignore_allow_list: bool,
    /// Raw CBOR map appended to authenticatorData as signed extensions (sets ED).
    pub signed_extensions_cbor: Option<Vec<u8>>,
    /// Extra top-level members of the attestation object `create` builds:
    /// `(text key, raw CBOR value)`, appended after `authData`.
    pub attestation_extra: Vec<(String, Vec<u8>)>,
}

impl SoftPasskey {
    /// A synced-passkey-shaped authenticator: UP, UV, BE and BS set, counter 0.
    pub fn new() -> Self {
        let key = loop {
            let bytes: [u8; 32] = rand::random();
            if let Ok(key) = SigningKey::from_slice(&bytes) {
                break key;
            }
        };
        let cred_id: [u8; 32] = rand::random();
        SoftPasskey {
            key,
            cred_id: cred_id.to_vec(),
            user_handle: None,
            counter: 0,
            up: true,
            uv: true,
            be: true,
            bs: true,
            rp_id_override: None,
            client_data_type_override: None,
            ignore_allow_list: false,
            signed_extensions_cbor: None,
            attestation_extra: Vec::new(),
        }
    }

    /// A device-bound authenticator: BE and BS clear.
    pub fn new_device_bound() -> Self {
        let mut soft = Self::new();
        soft.be = false;
        soft.bs = false;
        soft
    }

    /// The CBOR map `{"hmac-secret": true}`: a signed extension output no
    /// ceremony here ever asks for.
    pub fn unsolicited_hmac_secret() -> Vec<u8> {
        let mut ext = vec![0xA1];
        cbor_text("hmac-secret", &mut ext);
        ext.push(0xF5);
        ext
    }

    fn public_xy(&self) -> ([u8; 32], [u8; 32]) {
        let point = self.key.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        assert_eq!(bytes.len(), 65, "uncompressed SEC1 point");
        assert_eq!(bytes[0], 0x04, "uncompressed SEC1 tag");
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        (x, y)
    }

    /// COSE_Key for ES256 / P-256: {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
    fn cose_public_key(&self) -> Vec<u8> {
        let (x, y) = self.public_xy();
        let mut out = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
        cbor_bytes(&x, &mut out);
        out.push(0x22);
        cbor_bytes(&y, &mut out);
        out
    }

    fn flags(&self, attested: bool) -> u8 {
        let mut flags = 0u8;
        if self.up {
            flags |= FLAG_UP;
        }
        if self.uv {
            flags |= FLAG_UV;
        }
        if self.be {
            flags |= FLAG_BE;
        }
        if self.bs {
            flags |= FLAG_BS;
        }
        if attested {
            flags |= FLAG_AT;
        }
        if self.signed_extensions_cbor.is_some() {
            flags |= FLAG_ED;
        }
        flags
    }

    /// rpIdHash | flags | signCount | [attestedCredentialData] | [extensions]
    fn authenticator_data(&self, rp_id: &str, attested: bool) -> Vec<u8> {
        let hashed_rp = self.rp_id_override.as_deref().unwrap_or(rp_id);
        let mut out = Vec::new();
        out.extend_from_slice(&sha256(hashed_rp.as_bytes()));
        out.push(self.flags(attested));
        out.extend_from_slice(&self.counter.to_be_bytes());
        if attested {
            out.extend_from_slice(&[0u8; 16]); // AAGUID
            out.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
            out.extend_from_slice(&self.cred_id);
            out.extend_from_slice(&self.cose_public_key());
        }
        if let Some(ext) = &self.signed_extensions_cbor {
            out.extend_from_slice(ext);
        }
        out
    }

    fn client_data_json(&self, default_type: &str, challenge_b64u: &str, origin: &str) -> Vec<u8> {
        let ty = self
            .client_data_type_override
            .as_deref()
            .unwrap_or(default_type);
        // A real client decodes the challenge to bytes and re-encodes it.
        let challenge = b64u(&b64u_decode(challenge_b64u));
        serde_json::to_vec(&serde_json::json!({
            "type": ty,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        }))
        .expect("clientDataJSON serialises")
    }

    /// `navigator.credentials.create()`: `options` is the BARE `publicKey` object.
    pub fn create(&mut self, options: &Value, origin: &str) -> Value {
        assert!(
            options.get("publicKey").is_none(),
            "pass the bare publicKey object, not the wrapper around it"
        );
        let rp_id = options["rp"]["id"]
            .as_str()
            .expect("creation options carry rp.id")
            .to_string();
        let challenge = options["challenge"]
            .as_str()
            .expect("creation options carry a base64url challenge");
        let user_id = options["user"]["id"]
            .as_str()
            .expect("creation options carry a base64url user.id");
        let es256_offered = options["pubKeyCredParams"]
            .as_array()
            .map(|params| params.iter().any(|p| p["alg"].as_i64() == Some(-7)))
            .unwrap_or(false);
        assert!(es256_offered, "pubKeyCredParams must offer ES256 (-7)");

        self.user_handle = Some(b64u_decode(user_id));

        let client_data = self.client_data_json("webauthn.create", challenge, origin);
        let auth_data = self.authenticator_data(&rp_id, true);

        // {"fmt": "none", "attStmt": {}, "authData": <bytes>} + any extras
        let mut att_obj = Vec::new();
        cbor_head(5, 3 + self.attestation_extra.len(), &mut att_obj);
        cbor_text("fmt", &mut att_obj);
        cbor_text("none", &mut att_obj);
        cbor_text("attStmt", &mut att_obj);
        att_obj.push(0xA0);
        cbor_text("authData", &mut att_obj);
        cbor_bytes(&auth_data, &mut att_obj);
        for (key, value) in &self.attestation_extra {
            cbor_text(key, &mut att_obj);
            att_obj.extend_from_slice(value);
        }

        let id = b64u(&self.cred_id);
        serde_json::json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(&client_data),
                "attestationObject": b64u(&att_obj),
            },
            "clientExtensionResults": {},
        })
    }

    /// `navigator.credentials.get()`: `options` is the BARE `publicKey` object.
    pub fn get(&self, options: &Value, origin: &str) -> Value {
        assert!(
            options.get("publicKey").is_none(),
            "pass the bare publicKey object, not the wrapper around it"
        );
        let rp_id = options["rpId"]
            .as_str()
            .expect("request options carry rpId");
        let challenge = options["challenge"]
            .as_str()
            .expect("request options carry a base64url challenge");
        let id = b64u(&self.cred_id);

        if !self.ignore_allow_list {
            if let Some(allow) = options["allowCredentials"].as_array() {
                if !allow.is_empty() {
                    let listed = allow.iter().any(|c| c["id"].as_str() == Some(id.as_str()));
                    assert!(listed, "allowCredentials does not list this credential");
                }
            }
        }

        let client_data = self.client_data_json("webauthn.get", challenge, origin);
        let auth_data = self.authenticator_data(rp_id, false);

        let mut signed = auth_data.clone();
        signed.extend_from_slice(&sha256(&client_data));
        let signature: DerSignature = self.key.sign(&signed);

        let user_handle = self.user_handle.as_ref().map(|h| b64u(h));
        serde_json::json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(&client_data),
                "authenticatorData": b64u(&auth_data),
                "signature": b64u(signature.as_bytes()),
                "userHandle": user_handle,
            },
            "clientExtensionResults": {},
        })
    }
}
