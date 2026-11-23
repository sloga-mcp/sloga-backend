//! Passkey (WebAuthn) verifier: the three ceremonies and their challenge state.
//!
//! Everything a client could forge is decided here, on the server:
//!
//! * a challenge lives in Redis under a random id for five minutes, is bound
//!   to its purpose and (where they exist) to the account and the session
//!   that started it, and is consumed by the first finish that names it,
//!   whether that finish succeeds or not;
//! * sign-in passkeys never use an extension (plan rule R1): the options sent
//!   out carry none, and a response that carries any extension output, signed
//!   or unsigned, is refused. The one exception is `credProps` on a creation
//!   response, which password managers add unasked: it is dropped unread;
//! * a credential is identified by the credential id the library verified,
//!   never by the `id` string or the user handle the client sent;
//! * a successful assertion advances the stored credential with a
//!   compare-and-swap, and a lost swap is a refusal.
//!
//! Nothing here reads or writes lockout state, creates a session or mints a
//! ticket: the routes decide that.

use std::convert::TryFrom;
use std::sync::OnceLock;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use iso8601_timestamp::Timestamp;
use redis_kiss::{get_connection, redis};
use revolt_config::{config, PasskeyFeatures};
use revolt_database::{Account, Database, Passkey};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication,
    Passkey as WebauthnPasskey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder,
};

/// Most passkeys one account may hold
pub const MAX_PASSKEYS_PER_ACCOUNT: u64 = 10;

/// Longest passkey name, in characters
pub const MAX_PASSKEY_NAME_LEN: usize = 64;

/// Name of a passkey registered without one
const DEFAULT_PASSKEY_NAME: &str = "Passkey";

/// Relying party name shown by the platform's passkey sheet
const RP_NAME: &str = "Sloga";

/// How long a started ceremony may take. Also the timeout the options carry
/// (the library default, 300 s).
const CHALLENGE_TTL_SECS: u64 = 300;

/// How long the user handle chosen for an account's first registration stays
/// pinned in Redis. Renewed by every start that reads it, and longer than a
/// challenge lives, so every challenge issued under one pin carries one handle.
const HANDLE_PIN_TTL_SECS: u64 = 900;

/// How long a session stays marked as minted by a Google or Apple sign-in
const OAUTH_MARK_TTL_SECS: u64 = 600;

/// Origin form Android's Credential Manager reports
const ANDROID_ORIGIN_PREFIX: &str = "android:apk-key-hash:";

/// The only top-level members an attestation object may have
const ATTESTATION_MEMBERS: [&[u8]; 3] = [b"fmt", b"attStmt", b"authData"];

/// authenticatorData flag: signed extension data follows
const FLAG_EXTENSION_DATA: u8 = 0x80;

/// Offset of the flags byte in authenticatorData (after the 32-byte RP ID hash)
const FLAGS_OFFSET: usize = 32;

/// Members that must never appear anywhere in options sent to a client: every
/// extension input the library can emit, the extensions plan rule R1 bans by
/// name, and the two members of the library's wrapper object
const FORBIDDEN_OPTION_MEMBERS: &[&str] = &[
    "extensions",
    "prf",
    "hmac-secret",
    "hmacCreateSecret",
    "hmacGetSecret",
    "largeBlob",
    "credProps",
    "credentialProtectionPolicy",
    "enforceCredentialProtectionPolicy",
    "uvm",
    "mediation",
    "publicKey",
];

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// The library instance for the configured relying party
struct Verifier {
    webauthn: Webauthn,
    rp_id: String,
}

/// Ok for exactly `https://<rp_id or a subdomain of it>` (no port, path,
/// query, fragment, credentials or trailing slash), or for exactly
/// `android:apk-key-hash:` followed by the 43 base64url characters of a
/// 32-byte certificate hash.
///
/// The rule itself lives in `revolt_config`, where the database crate can
/// reach it too.
pub fn validate_origin(rp_id: &str, origin: &str) -> std::result::Result<(), &'static str> {
    revolt_config::validate_passkey_origin(rp_id, origin)
}

/// Build the library instance from `[features.passkeys]`, or say why not.
///
/// Whether the config may be used at all is `PasskeyFeatures::usable`, the
/// same answer every other surface reads. The first https origin is the
/// primary one, every other origin is added as an exact extra. Subdomain and
/// any-port matching are never switched on.
fn build_verifier(features: &PasskeyFeatures) -> std::result::Result<Verifier, &'static str> {
    if !features.usable() {
        return Err(features
            .config_fault()
            .unwrap_or("passkeys are switched off"));
    }

    let mut origins = Vec::with_capacity(features.origins.len());
    for origin in &features.origins {
        let url = Url::parse(origin).map_err(|_| "an origin is not a URL")?;

        // The library compares origins as parsed URLs, so the parsed form
        // must be the configured one: an https origin exactly, an app origin
        // byte for byte
        let unchanged = if origin.starts_with(ANDROID_ORIGIN_PREFIX) {
            url.as_str() == origin.as_str()
        } else {
            url.origin().ascii_serialization() == origin.as_str()
        };
        if !unchanged {
            return Err("an origin does not survive URL parsing unchanged");
        }

        origins.push(url);
    }

    let primary_at = origins
        .iter()
        .position(|url| url.scheme() == "https")
        .ok_or("the origin list has no https origin")?;
    let primary = origins.remove(primary_at);

    let mut builder = WebauthnBuilder::new(&features.rp_id, &primary)
        .map_err(|_| "the library refused the relying party id and primary origin")?;
    for origin in &origins {
        builder = builder.append_allowed_origin(origin);
    }

    let webauthn = builder
        .rp_name(RP_NAME)
        .build()
        .map_err(|_| "the library refused the configuration")?;

    Ok(Verifier {
        webauthn,
        rp_id: features.rp_id.clone(),
    })
}

/// Built once per process, from the config as it is at the first passkey
/// call. None when passkeys are off or the config cannot be used; a config
/// change needs a restart either way.
static VERIFIER: OnceLock<Option<Verifier>> = OnceLock::new();

/// The verifier for this process, or `FeatureDisabled`
async fn verifier() -> Result<&'static Verifier> {
    let built = match VERIFIER.get() {
        Some(built) => built,
        None => {
            let config = config().await;
            let features = &config.features.passkeys;

            VERIFIER.get_or_init(|| match build_verifier(features) {
                Ok(verifier) => Some(verifier),
                Err(reason) => {
                    // Said once: this runs once per process. The reason is a
                    // fixed sentence and carries no configured value.
                    if features.available {
                        log::error!(
                            "PASSKEYS ARE REFUSED: [features.passkeys] available = true but \
                             the configuration is invalid: {reason}. Fix rp_id / origins and \
                             restart delta."
                        );
                    }

                    None
                }
            })
        }
    };

    built.as_ref().ok_or_else(feature_disabled)
}

fn feature_disabled() -> revolt_result::Error {
    create_error!(FeatureDisabled {
        feature: "passkeys".to_string()
    })
}

/// Err unless passkeys are usable (`PasskeyFeatures::usable`: switched on
/// and a valid rp_id / origin list) and the library took that config.
pub async fn assert_available() -> Result<()> {
    verifier().await.map(|_| ())
}

// ---------------------------------------------------------------------------
// OAuth session marker
// ---------------------------------------------------------------------------

fn oauth_session_key(session_id: &str) -> String {
    format!("passkey:oauth-session:{session_id}")
}

/// Session ids are ULIDs; nothing else is ever put in a key or looked up
fn is_session_id(session_id: &str) -> bool {
    ulid::Ulid::from_string(session_id).is_ok()
}

/// Mark `session_id` as a session a Google or Apple sign-in just created.
/// The mark lasts ten minutes.
///
/// Best effort: a failure is logged and never fails the sign-in. Without the
/// mark the session simply needs a ticket to add a passkey.
pub async fn mark_oauth_session(session_id: &str) {
    if !is_session_id(session_id) {
        log::error!("passkeys: not marking an OAuth session: the session id is malformed");
        return;
    }

    let Ok(conn) = get_connection().await else {
        log::error!("passkeys: could not mark an OAuth session: no Redis connection");
        return;
    };
    let mut conn = conn.into_inner();

    let set: std::result::Result<Option<String>, _> = redis::cmd("SET")
        .arg(oauth_session_key(session_id))
        .arg("1")
        .arg("EX")
        .arg(OAUTH_MARK_TTL_SECS)
        .query_async(&mut conn)
        .await;

    if !matches!(set, Ok(Some(_))) {
        log::error!("passkeys: could not mark an OAuth session: the Redis write failed");
    }
}

/// Whether `session_id` carries the mark `mark_oauth_session` wrote.
///
/// False for a malformed id, a missing or expired mark, any other value, and
/// any Redis failure.
pub async fn is_oauth_session(session_id: &str) -> bool {
    if !is_session_id(session_id) {
        return false;
    }

    let Ok(conn) = get_connection().await else {
        return false;
    };
    let mut conn = conn.into_inner();

    let mark: std::result::Result<Option<String>, _> = redis::cmd("GET")
        .arg(oauth_session_key(session_id))
        .query_async(&mut conn)
        .await;

    matches!(mark, Ok(Some(value)) if value == "1")
}

// ---------------------------------------------------------------------------
// Challenge state
// ---------------------------------------------------------------------------

/// What a challenge was started for, with the library state of that ceremony.
/// The purpose and the state cannot disagree: they are one value.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
enum Ceremony {
    /// Adding a passkey to an account
    Register {
        state: PasskeyRegistration,
        /// The user handle the options carried (a UUID)
        user_handle: String,
    },
    /// Sign-in with a discoverable passkey; no account is known yet
    Login { state: DiscoverableAuthentication },
    /// A passkey assertion as a ticket factor
    Ticket {
        state: PasskeyAuthentication,
        /// `(credential_id, stored credential text)` of every row the state
        /// was built from. A row that changed since is refused at finish: the
        /// library checked the signature counter against these copies.
        snapshot: Vec<(String, String)>,
    },
}

/// The blob stored in Redis under `passkey:challenge:<challenge_id>`.
///
/// Holds server-made values only; nothing a client sent is ever stored.
#[derive(Serialize, Deserialize)]
struct StoredChallenge {
    /// Account the challenge was started for (None for sign-in)
    account_id: Option<String>,
    /// Session that started the challenge (None for sign-in)
    session_id: Option<String>,
    ceremony: Ceremony,
}

fn challenge_key(challenge_id: &str) -> String {
    format!("passkey:challenge:{challenge_id}")
}

/// 32 random bytes, lower-case hex
fn new_challenge_id() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_challenge_id(challenge_id: &str) -> bool {
    challenge_id.len() == 64
        && challenge_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Store a challenge under a fresh id (`SET NX EX`) and return the id
async fn store_challenge(stored: &StoredChallenge) -> Result<String> {
    let text = serde_json::to_string(stored).map_err(|_| create_error!(InternalError))?;
    let challenge_id = new_challenge_id();

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let set: Option<String> = redis::cmd("SET")
        .arg(challenge_key(&challenge_id))
        .arg(text)
        .arg("NX")
        .arg("EX")
        .arg(CHALLENGE_TTL_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    if set.is_none() {
        return Err(create_error!(InternalError));
    }

    Ok(challenge_id)
}

/// Consume a challenge (`GETDEL`): whatever happens next, this id is spent.
///
/// None when the id is malformed, unknown, expired, already used, or holds
/// something this build cannot read.
async fn take_challenge(challenge_id: &str) -> Result<Option<StoredChallenge>> {
    if !is_challenge_id(challenge_id) {
        return Ok(None);
    }

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let text: Option<String> = redis::cmd("GETDEL")
        .arg(challenge_key(challenge_id))
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    Ok(text.and_then(|text| serde_json::from_str(&text).ok()))
}

fn handle_pin_key(account_id: &str) -> String {
    format!("passkey:handle:{account_id}")
}

/// The user handle for an account that has no passkey yet.
///
/// The first start pins a fresh random handle in Redis; every start after it
/// (a second tab, a retry, a concurrent request) reads the same one and
/// renews the pin, so two first registrations racing each other still end up
/// with one handle.
async fn pinned_user_handle(account_id: &str) -> Result<Uuid> {
    let key = handle_pin_key(account_id);
    let fresh = Uuid::new_v4();

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    // Whether this call or an earlier one set it is read back below
    let _set: Option<String> = redis::cmd("SET")
        .arg(&key)
        .arg(fresh.to_string())
        .arg("NX")
        .arg("EX")
        .arg(HANDLE_PIN_TTL_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    let pinned: Option<String> = redis::cmd("GETEX")
        .arg(&key)
        .arg("EX")
        .arg(HANDLE_PIN_TTL_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    pinned
        .and_then(|text| Uuid::parse_str(&text).ok())
        .ok_or_else(|| create_error!(InternalError))
}

// ---------------------------------------------------------------------------
// Options sent to clients
// ---------------------------------------------------------------------------

/// The first forbidden member name found anywhere in `value`, if any
fn forbidden_member(value: &Value) -> Option<&'static str> {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                if let Some(name) = FORBIDDEN_OPTION_MEMBERS
                    .iter()
                    .find(|name| **name == key.as_str())
                {
                    return Some(*name);
                }

                if let Some(name) = forbidden_member(inner) {
                    return Some(name);
                }
            }

            None
        }
        Value::Array(items) => items.iter().find_map(forbidden_member),
        _ => None,
    }
}

/// The bare `publicKey` creation options for a client.
///
/// The library's wrapper is dropped, its extension inputs are removed (R1),
/// a discoverable credential is required (sign-in here is discoverable-only;
/// the library asks for "discouraged"), and the account's existing credential
/// ids are excluded. The finish side does not compare the options with its
/// state, so the rewrite is safe.
fn creation_options(
    response: &CreationChallengeResponse,
    rp_id: &str,
    exclude: &[String],
) -> Result<Value> {
    let mut options =
        serde_json::to_value(&response.public_key).map_err(|_| create_error!(InternalError))?;

    {
        let object = options
            .as_object_mut()
            .ok_or_else(|| create_error!(InternalError))?;

        object.remove("extensions");

        if !exclude.is_empty() {
            object.insert(
                "excludeCredentials".to_string(),
                Value::Array(
                    exclude
                        .iter()
                        .map(|id| serde_json::json!({ "type": "public-key", "id": id }))
                        .collect(),
                ),
            );
        }

        let selection = object
            .get_mut("authenticatorSelection")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| create_error!(InternalError))?;
        selection.insert("residentKey".to_string(), Value::from("required"));
        selection.insert("requireResidentKey".to_string(), Value::Bool(true));
    }

    // Fail closed if a library upgrade ever changes what it emits
    let user_verification = options["authenticatorSelection"]["userVerification"].as_str();
    let relying_party = options["rp"]["id"].as_str();
    if user_verification != Some("required")
        || relying_party != Some(rp_id)
        || forbidden_member(&options).is_some()
    {
        return Err(create_error!(InternalError));
    }

    Ok(options)
}

/// The bare `publicKey` request options for a client: the wrapper (and with
/// it `mediation`) is dropped and the extension inputs are removed (R1).
fn request_options(response: &RequestChallengeResponse, rp_id: &str) -> Result<Value> {
    let mut options =
        serde_json::to_value(&response.public_key).map_err(|_| create_error!(InternalError))?;

    options
        .as_object_mut()
        .ok_or_else(|| create_error!(InternalError))?
        .remove("extensions");

    // Fail closed if a library upgrade ever changes what it emits. The phone
    // apps refuse options without the pinned RP ID.
    if options["userVerification"].as_str() != Some("required")
        || options["rpId"].as_str() != Some(rp_id)
        || forbidden_member(&options).is_some()
    {
        return Err(create_error!(InternalError));
    }

    Ok(options)
}

// ---------------------------------------------------------------------------
// Responses from clients
// ---------------------------------------------------------------------------

/// Which call a response answers: `create()` or `get()`
#[derive(Clone, Copy, PartialEq)]
enum ResponseKind {
    Create,
    Get,
}

/// `credProps` exactly as a client may send it unasked: `{}` or
/// `{"rk": <bool>}`
fn cred_props_is_plain(value: &Value) -> bool {
    match value.as_object() {
        Some(members) => match members.len() {
            0 => true,
            1 => matches!(members.get("rk"), Some(Value::Bool(_))),
            _ => false,
        },
        None => false,
    }
}

/// The R1 gate on the raw JSON, before the typed parse (which silently drops
/// unknown extension outputs): an object, no top-level `extensions` member,
/// and `clientExtensionResults` absent or an object with no keys.
///
/// A creation response may also carry `credProps`, alone and in the plain
/// shape above: password managers add it without being asked. It is removed
/// here, unread, so the typed parse sees no extension output at all. A
/// `get()` response gets no such allowance.
fn clean_raw_credential(credential: &mut Value, kind: ResponseKind) -> bool {
    let Some(object) = credential.as_object_mut() else {
        return false;
    };

    if object.contains_key("extensions") {
        return false;
    }

    match object.get_mut("clientExtensionResults") {
        None => true,
        Some(Value::Object(outputs)) => {
            if kind == ResponseKind::Create
                && outputs.len() == 1
                && outputs.get("credProps").map_or(false, cred_props_is_plain)
            {
                outputs.clear();
            }

            outputs.is_empty()
        }
        Some(_) => false,
    }
}

/// Read one CBOR head at `*at`: `(major type, argument)`. None for an
/// indefinite length, a reserved encoding, or truncated input.
fn cbor_head(data: &[u8], at: &mut usize) -> Option<(u8, usize)> {
    let first = *data.get(*at)?;
    *at += 1;

    let extra = match first & 0x1f {
        info @ 0..=23 => return Some((first >> 5, info as usize)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };

    let bytes = data.get(*at..at.checked_add(extra)?)?;
    *at += extra;

    let mut argument: u64 = 0;
    for byte in bytes {
        argument = (argument << 8) | u64::from(*byte);
    }

    Some((first >> 5, usize::try_from(argument).ok()?))
}

/// Step over one CBOR item of any type
fn cbor_skip(data: &[u8], at: &mut usize, depth: usize) -> Option<()> {
    if depth > 16 {
        return None;
    }

    let (major, argument) = cbor_head(data, at)?;
    match major {
        // Integers, and simple values / floats (whose payload is the argument)
        0 | 1 | 7 => {}
        // Byte and text strings
        2 | 3 => {
            let end = at.checked_add(argument)?;
            data.get(*at..end)?;
            *at = end;
        }
        // Array. Every item is at least one byte, so a huge count runs out of
        // input instead of looping.
        4 => {
            for _ in 0..argument {
                cbor_skip(data, at, depth + 1)?;
            }
        }
        // Map
        5 => {
            for _ in 0..argument {
                cbor_skip(data, at, depth + 1)?;
                cbor_skip(data, at, depth + 1)?;
            }
        }
        // Tag: the tagged item follows
        6 => cbor_skip(data, at, depth + 1)?,
        _ => return None,
    }

    Some(())
}

/// The `authData` byte string of a CBOR attestation object. None when the
/// object is not a definite-length map with exactly one such member, or has
/// a top-level member other than `fmt`, `attStmt` and `authData` (the
/// library would read `epAtt` and `largeBlobKey` and say nothing), or names
/// one of the three twice.
fn attestation_auth_data(attestation_object: &[u8]) -> Option<&[u8]> {
    let mut at = 0;
    let (major, entries) = cbor_head(attestation_object, &mut at)?;
    if major != 5 || entries > ATTESTATION_MEMBERS.len() {
        return None;
    }

    let mut seen = [false; ATTESTATION_MEMBERS.len()];
    let mut found = None;
    for _ in 0..entries {
        let (key_major, key_len) = cbor_head(attestation_object, &mut at)?;
        if key_major != 3 {
            return None;
        }

        let key_end = at.checked_add(key_len)?;
        let key = attestation_object.get(at..key_end)?;
        at = key_end;

        let member = ATTESTATION_MEMBERS
            .iter()
            .position(|allowed| *allowed == key)?;
        if std::mem::replace(&mut seen[member], true) {
            return None;
        }

        if key == b"authData" {
            let (value_major, value_len) = cbor_head(attestation_object, &mut at)?;
            if value_major != 2 || found.is_some() {
                return None;
            }

            let value_end = at.checked_add(value_len)?;
            found = Some(attestation_object.get(at..value_end)?);
            at = value_end;
        } else {
            cbor_skip(attestation_object, &mut at, 0)?;
        }
    }

    found
}

/// True when authenticator data is long enough to carry flags and those say
/// no signed extension data follows
fn no_signed_extensions(authenticator_data: &[u8]) -> bool {
    matches!(
        authenticator_data.get(FLAGS_OFFSET),
        Some(flags) if flags & FLAG_EXTENSION_DATA == 0
    )
}

/// A registration response that passed the R1 gates, or None.
///
/// The value is consumed and dropped here: it is never stored or logged.
fn parse_registration(mut credential: Value) -> Option<RegisterPublicKeyCredential> {
    if !clean_raw_credential(&mut credential, ResponseKind::Create) {
        return None;
    }

    let registration: RegisterPublicKeyCredential = serde_json::from_value(credential).ok()?;

    let auth_data = attestation_auth_data(&registration.response.attestation_object)?;
    if !no_signed_extensions(auth_data) {
        return None;
    }

    Some(registration)
}

/// An assertion response that passed the R1 gates, or None.
///
/// The value is consumed and dropped here: it is never stored or logged.
fn parse_assertion(mut credential: Value) -> Option<PublicKeyCredential> {
    if !clean_raw_credential(&mut credential, ResponseKind::Get) {
        return None;
    }

    let assertion: PublicKeyCredential = serde_json::from_value(credential).ok()?;

    if !no_signed_extensions(&assertion.response.authenticator_data) {
        return None;
    }

    Some(assertion)
}

// ---------------------------------------------------------------------------
// Stored credentials
// ---------------------------------------------------------------------------

/// Canonical text form of a credential id: unpadded base64url of its bytes
fn credential_id_text(credential_id: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(credential_id)
}

/// The library credential stored on a row
fn stored_credential(row: &Passkey) -> Option<WebauthnPasskey> {
    serde_json::from_str(&row.credential).ok()
}

/// Advance a row after a verified assertion: apply the result to the
/// credential that was verified and write it back, but only while the row
/// still holds the text that credential was read from.
///
/// `InvalidCredentials` when the result is for another credential or the
/// compare-and-swap is lost (another assertion got there first, or the row is
/// gone). The caller must treat that as a failed assertion.
async fn commit_use(
    db: &Database,
    row: &Passkey,
    mut credential: WebauthnPasskey,
    result: &AuthenticationResult,
) -> Result<()> {
    if credential.update_credential(result).is_none() {
        return Err(create_error!(InvalidCredentials));
    }

    let text = serde_json::to_string(&credential).map_err(|_| create_error!(InternalError))?;

    if db
        .update_passkey_after_use(&row.id, &row.credential, &text, Timestamp::now_utc())
        .await?
    {
        Ok(())
    } else {
        Err(create_error!(InvalidCredentials))
    }
}

/// The API model of a stored passkey. The credential itself never leaves the
/// server.
///
/// A function and not `impl From<Passkey> for v0::PasskeyInfo`: both types
/// are foreign to this crate, so the orphan rule forbids the impl here.
pub fn passkey_info(passkey: &Passkey) -> v0::PasskeyInfo {
    v0::PasskeyInfo {
        id: passkey.id.clone(),
        name: passkey.name.clone(),
        created_at: passkey.created_at,
        last_used_at: passkey.last_used_at,
    }
}

/// The stored form of a passkey name: trimmed, "Passkey" when empty or
/// absent, `FailedValidation` when longer than `MAX_PASSKEY_NAME_LEN`
/// characters or holding a control character.
pub fn normalise_passkey_name(name: Option<&str>) -> Result<String> {
    let name = name.map(str::trim).unwrap_or("");

    if name.is_empty() {
        return Ok(DEFAULT_PASSKEY_NAME.to_string());
    }

    if name.chars().count() > MAX_PASSKEY_NAME_LEN {
        return Err(create_error!(FailedValidation {
            error: "passkey name is too long".to_string()
        }));
    }

    if name.chars().any(char::is_control) {
        return Err(create_error!(FailedValidation {
            error: "passkey name holds a control character".to_string()
        }));
    }

    Ok(name.to_string())
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Register: options for `account` to create a new passkey. Bound to
/// (Register, account.id, session_id).
///
/// `InvalidOperation` when the account already holds
/// `MAX_PASSKEYS_PER_ACCOUNT` passkeys.
pub async fn start_registration(
    db: &Database,
    account: &Account,
    session_id: &str,
) -> Result<v0::ResponsePasskeyOptions> {
    let verifier = verifier().await?;

    if session_id.is_empty() {
        return Err(create_error!(InvalidSession));
    }

    let rows = db.fetch_passkeys(&account.id).await?;
    if rows.len() as u64 >= MAX_PASSKEYS_PER_ACCOUNT {
        return Err(create_error!(InvalidOperation));
    }

    // One random handle per account, never the public user id: reuse the one
    // on the account's passkeys, else the one pinned for its first
    // registration
    let user_handle = match rows.first() {
        Some(row) => Uuid::parse_str(&row.user_handle).map_err(|_| create_error!(InternalError))?,
        None => pinned_user_handle(&account.id).await?,
    };

    // What the platform's passkey sheet shows for this entry. An account with
    // no user profile yet still gets a label.
    let (user_name, display_name) = match db.fetch_user(&account.id).await {
        Ok(user) => (
            format!("{}#{}", user.username, user.discriminator),
            user.display_name.unwrap_or(user.username),
        ),
        Err(_) => ("Sloga account".to_string(), "Sloga account".to_string()),
    };

    // No exclude list is handed to the library: its finish would then refuse
    // a re-registered credential of THIS account with its own error, while
    // one held by another account reaches the duplicate check below. The list
    // goes into the options only, and every duplicate gets one fixed error.
    let (response, state) = verifier
        .webauthn
        .start_passkey_registration(user_handle, &user_name, &display_name, None)
        .map_err(|_| create_error!(InternalError))?;

    let exclude: Vec<String> = rows.iter().map(|row| row.credential_id.clone()).collect();
    let options = creation_options(&response, &verifier.rp_id, &exclude)?;

    let challenge_id = store_challenge(&StoredChallenge {
        account_id: Some(account.id.clone()),
        session_id: Some(session_id.to_string()),
        ceremony: Ceremony::Register {
            state,
            user_handle: user_handle.to_string(),
        },
    })
    .await?;

    Ok(v0::ResponsePasskeyOptions {
        challenge_id,
        options,
    })
}

/// Verifies and STORES the new passkey; returns the stored row.
///
/// Errors: `FailedValidation` for a bad name (checked BEFORE the challenge is
/// consumed, so the same response can be sent again with another name);
/// `InvalidCredentials` for every ceremony failure (unknown, used, expired or
/// foreign challenge, extension outputs, failed verification);
/// `InvalidOperation` at the passkey cap; `NoEffect` when the credential is
/// already registered, on this account or any other.
pub async fn finish_registration(
    db: &Database,
    account: &Account,
    session_id: &str,
    challenge_id: &str,
    credential: Value,
    name: Option<String>,
) -> Result<Passkey> {
    let verifier = verifier().await?;
    let name = normalise_passkey_name(name.as_deref())?;

    let (state, user_handle) = match take_challenge(challenge_id).await? {
        Some(StoredChallenge {
            account_id: Some(for_account),
            session_id: Some(for_session),
            ceremony: Ceremony::Register { state, user_handle },
        }) if for_account == account.id && for_session == session_id => (state, user_handle),
        _ => return Err(create_error!(InvalidCredentials)),
    };

    let registration =
        parse_registration(credential).ok_or_else(|| create_error!(InvalidCredentials))?;

    let verified = verifier
        .webauthn
        .finish_passkey_registration(&registration, &state)
        .map_err(|_| create_error!(InvalidCredentials))?;

    // From the verified attestation, never the `id` string the client sent
    let credential_id = credential_id_text(verified.cred_id().as_slice());

    let rows = db.fetch_passkeys(&account.id).await?;
    if rows.len() as u64 >= MAX_PASSKEYS_PER_ACCOUNT {
        return Err(create_error!(InvalidOperation));
    }

    // The account got passkeys under another handle since this challenge
    // started (the Redis pin was lost): one handle per account, start again
    if rows.iter().any(|row| row.user_handle != user_handle) {
        return Err(create_error!(InvalidOperation));
    }

    // `insert_passkey` reports a duplicate credential id and a database
    // outage as the same error, so look before and after the insert. One
    // fixed answer, whoever holds the credential.
    if db
        .fetch_passkey_by_credential_id(&credential_id)
        .await?
        .is_some()
    {
        return Err(create_error!(NoEffect));
    }

    let text = serde_json::to_string(&verified).map_err(|_| create_error!(InternalError))?;
    let row = Passkey::new(
        account.id.clone(),
        credential_id.clone(),
        user_handle,
        text,
        name,
    );

    if let Err(error) = db.insert_passkey(&row).await {
        // Lost a race with another registration of the same credential?
        return match db.fetch_passkey_by_credential_id(&credential_id).await {
            Ok(Some(_)) => Err(create_error!(NoEffect)),
            _ => Err(error),
        };
    }

    // The checks above and the insert are not one transaction. Two finishes
    // racing each other can both pass them, so look again now that the row is
    // in: over the cap, or beside a row with another handle, this row goes.
    // (Both racers may withdraw; neither stays wrongly.)
    let rows = db.fetch_passkeys(&account.id).await?;
    let over_cap = rows.len() as u64 > MAX_PASSKEYS_PER_ACCOUNT;
    let split_handle = rows
        .iter()
        .any(|other| other.user_handle != row.user_handle);
    if over_cap || split_handle {
        // One retry. The refusal stands whatever the delete does: if both
        // attempts fail the row may remain, and the log line names it.
        let mut withdrawn = db.delete_passkey(&account.id, &row.id).await.is_ok();
        if !withdrawn {
            withdrawn = db.delete_passkey(&account.id, &row.id).await.is_ok();
        }
        if !withdrawn {
            log::error!(
                "passkeys: could not withdraw passkey row {} that lost a registration race; \
                 the row may remain",
                row.id
            );
        }

        return Err(create_error!(InvalidOperation));
    }

    Ok(row)
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

/// Sign-in, discoverable only, no account known yet. Bound to (Login).
pub async fn start_login() -> Result<v0::ResponsePasskeyOptions> {
    let verifier = verifier().await?;

    let (response, state) = verifier
        .webauthn
        .start_discoverable_authentication()
        .map_err(|_| create_error!(InternalError))?;

    let options = request_options(&response, &verifier.rp_id)?;

    let challenge_id = store_challenge(&StoredChallenge {
        account_id: None,
        session_id: None,
        ceremony: Ceremony::Login { state },
    })
    .await?;

    Ok(v0::ResponsePasskeyOptions {
        challenge_id,
        options,
    })
}

/// Verifies the assertion, advances the stored credential, returns the
/// owner's account id.
///
/// Every failure (unknown credential, bad signature, orphan row, stale
/// challenge, lost CAS) is the SAME error: InvalidCredentials. Only a Redis
/// or database outage, which does not depend on what was sent, says otherwise.
pub async fn finish_login(db: &Database, challenge_id: &str, credential: Value) -> Result<String> {
    let verifier = verifier().await?;

    let state = match take_challenge(challenge_id).await? {
        Some(StoredChallenge {
            account_id: None,
            session_id: None,
            ceremony: Ceremony::Login { state },
        }) => state,
        _ => return Err(create_error!(InvalidCredentials)),
    };

    let assertion = parse_assertion(credential).ok_or_else(|| create_error!(InvalidCredentials))?;

    // Both values are UNSIGNED claims at this point
    let (claimed_handle, claimed_credential) = verifier
        .webauthn
        .identify_discoverable_authentication(&assertion)
        .map_err(|_| create_error!(InvalidCredentials))?;

    // The row is found by credential id alone; the handle picks nothing
    let row = db
        .fetch_passkey_by_credential_id(&credential_id_text(claimed_credential))
        .await?
        .ok_or_else(|| create_error!(InvalidCredentials))?;

    let stored = stored_credential(&row).ok_or_else(|| create_error!(InvalidCredentials))?;

    // Signature, challenge, origin, RP ID hash, user verification and the
    // signature counter, against the row's own public key
    let result = verifier
        .webauthn
        .finish_discoverable_authentication_v2(&assertion, state, &stored)
        .map_err(|_| create_error!(InvalidCredentials))?;

    // The handle is not covered by the signature, so it proves nothing; a
    // response that names another account's handle is still refused
    if Uuid::parse_str(&row.user_handle).ok() != Some(claimed_handle) {
        return Err(create_error!(InvalidCredentials));
    }

    // A row whose account is gone signs nobody in
    if let Err(error) = db.fetch_account(&row.user_id).await {
        return Err(match error.error_type {
            ErrorType::UnknownUser | ErrorType::NotFound => create_error!(InvalidCredentials),
            _ => error,
        });
    }

    commit_use(db, &row, stored, &result).await?;

    Ok(row.user_id)
}

// ---------------------------------------------------------------------------
// Ticket factor
// ---------------------------------------------------------------------------

/// Ticket factor: options listing this account's passkeys. Bound to
/// (Ticket, account.id, session_id).
///
/// `InvalidOperation` when the account has no passkey: nothing is started
/// (with an empty list the library would emit a discoverable request).
pub async fn start_assertion(
    db: &Database,
    account: &Account,
    session_id: &str,
) -> Result<v0::ResponsePasskeyOptions> {
    let verifier = verifier().await?;

    if session_id.is_empty() {
        return Err(create_error!(InvalidSession));
    }

    let rows = db.fetch_passkeys(&account.id).await?;

    let mut credentials = Vec::with_capacity(rows.len());
    let mut snapshot = Vec::with_capacity(rows.len());
    for row in &rows {
        // A row this build cannot read is left out, not fatal
        if let Some(credential) = stored_credential(row) {
            credentials.push(credential);
            snapshot.push((row.credential_id.clone(), row.credential.clone()));
        }
    }

    if credentials.is_empty() {
        return Err(create_error!(InvalidOperation));
    }

    let (response, state) = verifier
        .webauthn
        .start_passkey_authentication(&credentials)
        .map_err(|_| create_error!(InternalError))?;

    let options = request_options(&response, &verifier.rp_id)?;

    // Belt and braces for the rule above: a ticket request always names its
    // credentials
    if options["allowCredentials"]
        .as_array()
        .map_or(true, |allowed| allowed.is_empty())
    {
        return Err(create_error!(InternalError));
    }

    let challenge_id = store_challenge(&StoredChallenge {
        account_id: Some(account.id.clone()),
        session_id: Some(session_id.to_string()),
        ceremony: Ceremony::Ticket { state, snapshot },
    })
    .await?;

    Ok(v0::ResponsePasskeyOptions {
        challenge_id,
        options,
    })
}

/// Verifies an assertion for a ticket; Ok(()) only for a passkey of this
/// account, challenge started by this session.
///
/// Every refusal is `InvalidCredentials`.
pub async fn finish_assertion(
    db: &Database,
    account: &Account,
    session_id: &str,
    challenge_id: &str,
    credential: Value,
) -> Result<()> {
    let verifier = verifier().await?;

    let (state, snapshot) = match take_challenge(challenge_id).await? {
        Some(StoredChallenge {
            account_id: Some(for_account),
            session_id: Some(for_session),
            ceremony: Ceremony::Ticket { state, snapshot },
        }) if for_account == account.id && for_session == session_id => (state, snapshot),
        _ => return Err(create_error!(InvalidCredentials)),
    };

    let assertion = parse_assertion(credential).ok_or_else(|| create_error!(InvalidCredentials))?;

    // Verified against the credentials the state was built from: only this
    // account's, as they were when the challenge started
    let result = verifier
        .webauthn
        .finish_passkey_authentication(&assertion, &state)
        .map_err(|_| create_error!(InvalidCredentials))?;

    // The row, among THIS account's rows only
    let credential_id = credential_id_text(result.cred_id().as_slice());
    let rows = db.fetch_passkeys(&account.id).await?;
    let row = rows
        .iter()
        .find(|row| row.credential_id == credential_id)
        .ok_or_else(|| create_error!(InvalidCredentials))?;

    // The library compared the signature counter with the copy taken at
    // start. If the row has moved on since (another assertion advanced it),
    // that comparison was against stale state: refuse, as for a lost swap.
    let unchanged = snapshot
        .iter()
        .any(|(id, text)| *id == row.credential_id && *text == row.credential);
    if !unchanged {
        return Err(create_error!(InvalidCredentials));
    }

    let stored = stored_credential(row).ok_or_else(|| create_error!(InvalidCredentials))?;

    commit_use(db, row, stored, &result).await
}

#[cfg(test)]
mod tests {
    //! Every test that touches config sets it with `overwrite_config`, which
    //! works once per process: run these under nextest (one process per test).
    //!
    //! Each test says, under "Fails if", the one change to the code above that
    //! turns it red.

    use redis_kiss::{get_connection, redis};
    use revolt_config::PasskeyFeatures;
    use revolt_database::{Account, Database, Passkey};
    use revolt_result::Result;
    use serde_json::{json, Value};
    use ulid::Ulid;
    use webauthn_rs::prelude::{PublicKeyCredential, Uuid};

    use super::*;
    use crate::util::passkey_soft::{b64u, b64u_decode, SoftPasskey};
    use crate::util::test::{rt, TestHarness};

    const RP_ID: &str = "app.sloga.gg";
    const WEB_ORIGIN: &str = "https://app.sloga.gg";

    /// What every ceremony refusal looks like
    const REFUSED: &str = "InvalidCredentials";

    /// `android:apk-key-hash:` + base64url of a 32-byte certificate hash
    fn android_origin() -> String {
        let hash: Vec<u8> = (0u8..32).collect();
        format!("android:apk-key-hash:{}", b64u(&hash))
    }

    fn features(origins: &[&str]) -> PasskeyFeatures {
        PasskeyFeatures {
            available: true,
            rp_id: RP_ID.to_string(),
            origins: origins.iter().map(|origin| origin.to_string()).collect(),
            ..Default::default()
        }
    }

    /// Passkeys on, web origin + one Android origin, then a harness
    async fn setup() -> TestHarness {
        revolt_config::overwrite_config(|settings| {
            settings.features.passkeys.available = true;
            settings.features.passkeys.rp_id = RP_ID.to_string();
            settings.features.passkeys.origins = vec![WEB_ORIGIN.to_string(), android_origin()];
        })
        .await;

        TestHarness::new().await
    }

    /// "Ok", or the error type as `Debug` prints it
    fn outcome<T>(result: Result<T>) -> String {
        match result {
            Ok(_) => "Ok".to_string(),
            Err(error) => format!("{:?}", error.error_type),
        }
    }

    fn untouched(_: &mut Value) {}

    /// A whole registration; `tamper` edits the response before it is sent
    async fn register_with(
        db: &Database,
        account: &Account,
        session_id: &str,
        soft: &mut SoftPasskey,
        origin: &str,
        tamper: fn(&mut Value),
    ) -> Result<Passkey> {
        let started = start_registration(db, account, session_id).await?;
        let mut credential = soft.create(&started.options, origin);
        tamper(&mut credential);
        finish_registration(
            db,
            account,
            session_id,
            &started.challenge_id,
            credential,
            None,
        )
        .await
    }

    async fn register(
        db: &Database,
        account: &Account,
        session_id: &str,
        soft: &mut SoftPasskey,
    ) -> Passkey {
        register_with(db, account, session_id, soft, WEB_ORIGIN, untouched)
            .await
            .expect("registration")
    }

    /// A whole sign-in
    async fn login_with(
        db: &Database,
        soft: &SoftPasskey,
        origin: &str,
        tamper: fn(&mut Value),
    ) -> Result<String> {
        let started = start_login().await?;
        let mut credential = soft.get(&started.options, origin);
        tamper(&mut credential);
        finish_login(db, &started.challenge_id, credential).await
    }

    async fn login(db: &Database, soft: &SoftPasskey) -> Result<String> {
        login_with(db, soft, WEB_ORIGIN, untouched).await
    }

    /// A whole ticket assertion
    async fn ticket_with(
        db: &Database,
        account: &Account,
        session_id: &str,
        soft: &SoftPasskey,
        origin: &str,
        tamper: fn(&mut Value),
    ) -> Result<()> {
        let started = start_assertion(db, account, session_id).await?;
        let mut credential = soft.get(&started.options, origin);
        tamper(&mut credential);
        finish_assertion(db, account, session_id, &started.challenge_id, credential).await
    }

    async fn ticket(
        db: &Database,
        account: &Account,
        session_id: &str,
        soft: &SoftPasskey,
    ) -> Result<()> {
        ticket_with(db, account, session_id, soft, WEB_ORIGIN, untouched).await
    }

    /// A row without `created_at`: MongoDB keeps milliseconds, so a row read
    /// back differs there from the one `finish_registration` returned
    fn sans_created_at(row: &Passkey) -> Passkey {
        Passkey {
            created_at: Timestamp::UNIX_EPOCH,
            ..row.clone()
        }
    }

    /// The one row of an account that has one passkey
    async fn only_row(db: &Database, account: &Account) -> Passkey {
        let mut rows = db.fetch_passkeys(&account.id).await.expect("rows");
        assert_eq!(rows.len(), 1, "one passkey expected");
        rows.remove(0)
    }

    /// The signature counter inside a stored credential
    fn stored_counter(row: &Passkey) -> u64 {
        let value: Value = serde_json::from_str(&row.credential).expect("stored credential");
        value["cred"]["counter"].as_u64().expect("counter")
    }

    /// Every member name anywhere in a JSON value. Written apart from
    /// `forbidden_member` on purpose: the tests must not trust the guard.
    fn member_names(value: &Value, into: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map {
                    into.push(key.clone());
                    member_names(inner, into);
                }
            }
            Value::Array(items) => {
                for item in items {
                    member_names(item, into);
                }
            }
            _ => {}
        }
    }

    fn assert_no_extension_members(options: &Value, what: &str) {
        let mut names = Vec::new();
        member_names(options, &mut names);
        for banned in [
            "extensions",
            "prf",
            "hmac-secret",
            "hmacCreateSecret",
            "hmacGetSecret",
            "largeBlob",
            "credProps",
            "uvm",
            "credentialProtectionPolicy",
            "publicKey",
            "mediation",
        ] {
            assert!(
                !names.iter().any(|name| name == banned),
                "{} options carry `{}`: {}",
                what,
                banned,
                options
            );
        }
    }

    fn sorted_keys(value: &Value) -> Vec<String> {
        let mut keys: Vec<String> = value
            .as_object()
            .map(|object| object.keys().cloned().collect())
            .unwrap_or_default();
        keys.sort();
        keys
    }

    // -----------------------------------------------------------------------
    // Pure pieces (no config, no database)
    // -----------------------------------------------------------------------

    /// Fails if: `validate_origin` stops forwarding to the config crate's
    /// rule, or that rule drops any one of its checks (scheme, no port, host
    /// suffix with the dot, exact-origin spelling, hash length, alphabet, the
    /// 32-byte decode).
    #[test]
    fn validate_origin_table() {
        let android = android_origin();
        let good = [
            "https://app.sloga.gg",
            "https://sub.app.sloga.gg",
            android.as_str(),
        ];
        for origin in good {
            assert_eq!(validate_origin(RP_ID, origin), Ok(()), "{origin}");
        }

        let hash = &android[ANDROID_ORIGIN_PREFIX.len()..];
        // 43 characters whose last one carries stray bits: decodes to nothing
        let stray_bits = format!("{ANDROID_ORIGIN_PREFIX}{}B", &hash[..42]);
        let bad = [
            String::new(),
            "app.sloga.gg".to_string(),
            "http://app.sloga.gg".to_string(),
            "https://app.sloga.gg/".to_string(),
            "https://app.sloga.gg/path".to_string(),
            "https://app.sloga.gg?x=1".to_string(),
            "https://app.sloga.gg#frag".to_string(),
            "https://user@app.sloga.gg".to_string(),
            // Any explicit port, the default one included
            "https://app.sloga.gg:443".to_string(),
            "https://app.sloga.gg:8443".to_string(),
            "https://sub.app.sloga.gg:8443".to_string(),
            "https://APP.sloga.gg".to_string(),
            "https://sloga.gg".to_string(),
            "https://evilapp.sloga.gg".to_string(),
            "https://app.sloga.gg.evil.example".to_string(),
            "https://evil.example".to_string(),
            "https://127.0.0.1".to_string(),
            "wss://app.sloga.gg".to_string(),
            "capacitor://localhost".to_string(),
            "ios:bundle-id:gg.sloga.app".to_string(),
            "android:apk-key-hash:".to_string(),
            format!("{ANDROID_ORIGIN_PREFIX}{}", &hash[..42]),
            format!("{android}A"),
            format!("{android}="),
            format!("{ANDROID_ORIGIN_PREFIX}{}+", &hash[..42]),
            format!("{ANDROID_ORIGIN_PREFIX}{}/", &hash[..42]),
            stray_bits,
            format!("android:apk-key-hash-sha256:{hash}"),
            format!("Android:apk-key-hash:{hash}"),
            format!(" {android}"),
        ];
        for origin in &bad {
            assert!(
                validate_origin(RP_ID, origin).is_err(),
                "accepted {:?}",
                origin
            );
        }

        // An empty RP ID accepts no https origin
        assert!(validate_origin("", "https://app.sloga.gg").is_err());

        // One rule, two names
        for origin in good.iter().copied().chain(bad.iter().map(String::as_str)) {
            assert_eq!(
                validate_origin(RP_ID, origin),
                revolt_config::validate_passkey_origin(RP_ID, origin),
                "{origin:?}"
            );
        }
    }

    /// Fails if: `build_verifier` stops deciding through
    /// `PasskeyFeatures::usable` (the switch, the RP ID, an empty list, each
    /// origin, the need for one https origin).
    #[test]
    fn build_verifier_fails_closed_on_bad_config() {
        let android = android_origin();

        let android = android.as_str();

        let good = build_verifier(&features(&[WEB_ORIGIN, android])).expect("good config");
        assert_eq!(good.rp_id, RP_ID);
        assert_eq!(good.webauthn.get_allowed_origins().len(), 2);

        // The Android origin first: the https one is still the primary
        let reordered = build_verifier(&features(&[android, WEB_ORIGIN])).expect("reordered");
        assert_eq!(reordered.webauthn.get_allowed_origins().len(), 2);
        assert_eq!(
            reordered.webauthn.get_allowed_origins()[0].scheme(),
            "https"
        );

        assert!(build_verifier(&features(&[])).is_err(), "empty list");
        assert!(
            build_verifier(&features(&[android])).is_err(),
            "no https origin"
        );
        assert!(
            build_verifier(&features(&[WEB_ORIGIN, "https://evil.example"])).is_err(),
            "one foreign origin poisons the list"
        );
        assert!(
            build_verifier(&features(&[WEB_ORIGIN, "http://app.sloga.gg"])).is_err(),
            "plain http"
        );
        assert!(
            build_verifier(&features(&[WEB_ORIGIN, "https://app.sloga.gg:8443"])).is_err(),
            "an explicit port"
        );

        let mut off = features(&[WEB_ORIGIN]);
        off.available = false;
        assert!(build_verifier(&off).is_err(), "switched off");

        // The builder and the shared predicate agree, row by row
        for (origins, usable) in [
            (vec![WEB_ORIGIN, android], true),
            (vec![android, WEB_ORIGIN], true),
            (vec![], false),
            (vec![android], false),
            (vec![WEB_ORIGIN, "https://evil.example"], false),
            (vec![WEB_ORIGIN, "https://app.sloga.gg:8443"], false),
        ] {
            let config = features(&origins);
            assert_eq!(config.usable(), usable, "{origins:?}");
            assert_eq!(build_verifier(&config).is_ok(), usable, "{origins:?}");
        }

        for rp_id in [
            "",
            "APP.sloga.gg",
            "app.sloga.gg:443",
            "https://app.sloga.gg",
            "a b",
        ] {
            let mut bad = features(&[WEB_ORIGIN]);
            bad.rp_id = rp_id.to_string();
            assert!(build_verifier(&bad).is_err(), "rp id {:?}", rp_id);
        }
    }

    /// The `credProps` shapes a creation response may carry
    fn plain_cred_props() -> [Value; 3] {
        [
            json!({ "credProps": {} }),
            json!({ "credProps": { "rk": true } }),
            json!({ "credProps": { "rk": false } }),
        ]
    }

    /// `clientExtensionResults` values that name `credProps` and are refused
    /// everywhere
    fn odd_cred_props() -> Vec<Value> {
        vec![
            json!({ "credProps": null }),
            json!({ "credProps": true }),
            json!({ "credProps": [] }),
            json!({ "credProps": "rk" }),
            json!({ "credProps": { "rk": null } }),
            json!({ "credProps": { "rk": 1 } }),
            json!({ "credProps": { "rk": "true" } }),
            json!({ "credProps": { "rk": true, "authenticatorDisplayName": "Key" } }),
            json!({ "credProps": { "authenticatorDisplayName": "Key" } }),
            json!({ "credProps": { "RK": true } }),
            // Any other key beside it
            json!({ "credProps": {}, "prf": {} }),
            json!({ "credProps": { "rk": true }, "largeBlob": { "supported": true } }),
            json!({ "credProps": { "rk": true }, "x": null }),
            json!({ "credprops": {} }),
        ]
    }

    /// Fails if: `clean_raw_credential` lets through a non-object, a
    /// top-level `extensions`, any `clientExtensionResults` but `{}` on a
    /// `get()`, anything but `{}` or a lone plain `credProps` on a
    /// `create()`, or leaves `credProps` in place for the typed parse.
    #[test]
    fn raw_credential_gate() {
        for kind in [ResponseKind::Create, ResponseKind::Get] {
            for mut clean in [
                json!({ "id": "x" }),
                json!({ "id": "x", "clientExtensionResults": {} }),
            ] {
                let before = clean.clone();
                assert!(clean_raw_credential(&mut clean, kind), "refused {before}");
                assert_eq!(clean, before, "a clean response is left as it was");
            }

            let mut dirty = vec![
                json!("text"),
                json!([]),
                Value::Null,
                json!({ "extensions": {} }),
                json!({ "extensions": null }),
                json!({ "clientExtensionResults": null }),
                json!({ "clientExtensionResults": [] }),
                json!({ "clientExtensionResults": "x" }),
                json!({ "clientExtensionResults": { "prf": { "results": { "first": "AA" } } } }),
                json!({ "clientExtensionResults": { "hmacGetSecret": { "output1": "AA" } } }),
                json!({ "clientExtensionResults": { "largeBlob": { "supported": true } } }),
                json!({ "clientExtensionResults": {}, "extensions": {} }),
                json!({ "clientExtensionResults": { "credProps": {} }, "extensions": {} }),
            ];
            dirty.extend(
                odd_cred_props()
                    .into_iter()
                    .map(|outputs| json!({ "clientExtensionResults": outputs })),
            );
            for mut dirty in dirty {
                let before = dirty.clone();
                assert!(!clean_raw_credential(&mut dirty, kind), "accepted {before}");
            }
        }

        for outputs in plain_cred_props() {
            // On a create it is taken out, leaving no extension output
            let mut create = json!({ "id": "x", "clientExtensionResults": outputs.clone() });
            assert!(
                clean_raw_credential(&mut create, ResponseKind::Create),
                "refused {outputs}"
            );
            assert_eq!(create, json!({ "id": "x", "clientExtensionResults": {} }));

            // On a get it is an extension output like any other
            let mut get = json!({ "id": "x", "clientExtensionResults": outputs.clone() });
            assert!(
                !clean_raw_credential(&mut get, ResponseKind::Get),
                "accepted {outputs} on a get"
            );
        }
    }

    /// Fails if: `forbidden_member` stops recursing or loses a name.
    #[test]
    fn forbidden_member_finds_nested_members() {
        assert_eq!(
            forbidden_member(&json!({ "rpId": "x", "challenge": "y" })),
            None
        );
        assert_eq!(
            forbidden_member(&json!({ "extensions": { "uvm": true } })),
            Some("extensions")
        );
        assert_eq!(
            forbidden_member(&json!({ "a": [{ "b": { "prf": {} } }] })),
            Some("prf")
        );
        assert_eq!(
            forbidden_member(&json!({ "a": { "hmac-secret": true } })),
            Some("hmac-secret")
        );
        assert_eq!(
            forbidden_member(&json!({ "a": { "largeBlob": {} } })),
            Some("largeBlob")
        );
        assert_eq!(
            forbidden_member(&json!({ "publicKey": {} })),
            Some("publicKey")
        );
    }

    /// Fails if: the CBOR walker mis-steps over a nested `attStmt`, accepts a
    /// duplicate / non-bytes `authData`, or reads past truncated input.
    #[test]
    fn attestation_auth_data_walker() {
        // {"fmt": "packed", "attStmt": {"alg": -7, "sig": h'0102', "x5c": [h'AA', h'BB']},
        //  "authData": h'DEADBEEF'}
        let mut object = vec![0xA3];
        object.extend_from_slice(&[0x63, b'f', b'm', b't']);
        object.extend_from_slice(&[0x66, b'p', b'a', b'c', b'k', b'e', b'd']);
        object.extend_from_slice(&[0x67, b'a', b't', b't', b'S', b't', b'm', b't']);
        object.push(0xA3);
        object.extend_from_slice(&[0x63, b'a', b'l', b'g', 0x26]);
        object.extend_from_slice(&[0x63, b's', b'i', b'g', 0x42, 0x01, 0x02]);
        object.extend_from_slice(&[0x63, b'x', b'5', b'c', 0x82, 0x41, 0xAA, 0x41, 0xBB]);
        object.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']);
        object.extend_from_slice(&[0x44, 0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            attestation_auth_data(&object),
            Some(&[0xDE, 0xAD, 0xBE, 0xEF][..])
        );

        // Truncated anywhere: never a panic, never a value
        for cut in 0..object.len() {
            assert_eq!(attestation_auth_data(&object[..cut]), None, "cut at {cut}");
        }

        // Not a map; authData as text; authData twice; indefinite-length map
        assert_eq!(attestation_auth_data(&[0x80]), None);
        let mut text = vec![0xA1];
        text.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']);
        text.extend_from_slice(&[0x61, b'x']);
        assert_eq!(attestation_auth_data(&text), None);
        let mut twice = vec![0xA2];
        for _ in 0..2 {
            twice.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']);
            twice.extend_from_slice(&[0x41, 0x00]);
        }
        assert_eq!(attestation_auth_data(&twice), None);
        assert_eq!(attestation_auth_data(&[0xBF, 0xFF]), None);

        // A fourth top-level member, in any position: the good object with
        // its count raised and the member put first or last
        let large_blob_key: &[u8] = &[
            0x6C, b'l', b'a', b'r', b'g', b'e', b'B', b'l', b'o', b'b', b'K', b'e', b'y', 0x42,
            0x01, 0x02,
        ];
        let ep_att: &[u8] = &[0x65, b'e', b'p', b'A', b't', b't', 0xF5];
        let unknown: &[u8] = &[0x61, b'x', 0x00];
        for extra in [large_blob_key, ep_att, unknown] {
            let mut last = vec![0xA4];
            last.extend_from_slice(&object[1..]);
            last.extend_from_slice(extra);
            assert_eq!(attestation_auth_data(&last), None, "last: {extra:02x?}");

            let mut first = vec![0xA4];
            first.extend_from_slice(extra);
            first.extend_from_slice(&object[1..]);
            assert_eq!(attestation_auth_data(&first), None, "first: {extra:02x?}");
        }

        // Three members, one of them not allowed: the name is what is
        // checked, not only the count
        for extra in [large_blob_key, ep_att, unknown] {
            let mut swapped = vec![0xA3];
            swapped.extend_from_slice(&[0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']);
            swapped.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']);
            swapped.extend_from_slice(&[0x41, 0x00]);
            swapped.extend_from_slice(extra);
            assert_eq!(attestation_auth_data(&swapped), None, "{extra:02x?}");
        }

        // `fmt` twice, and a key that is not text
        let mut fmt_twice = vec![0xA3];
        for _ in 0..2 {
            fmt_twice.extend_from_slice(&[0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']);
        }
        fmt_twice.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']);
        fmt_twice.extend_from_slice(&[0x41, 0x00]);
        assert_eq!(attestation_auth_data(&fmt_twice), None);
        assert_eq!(attestation_auth_data(&[0xA1, 0x01, 0x41, 0x00]), None);

        // The control for the rows above: two members, both allowed
        let mut small = vec![0xA2];
        small.extend_from_slice(&[0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']);
        small.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']);
        small.extend_from_slice(&[0x41, 0x07]);
        assert_eq!(attestation_auth_data(&small), Some(&[0x07][..]));

        // The flag test itself
        let mut auth_data = vec![0u8; 37];
        assert!(no_signed_extensions(&auth_data));
        auth_data[32] = 0x80 | 0x05;
        assert!(!no_signed_extensions(&auth_data));
        assert!(
            !no_signed_extensions(&[0u8; 32]),
            "too short to carry flags"
        );
    }

    /// Fails if: the name is not trimmed, the default changes, the limit
    /// counts bytes instead of characters, or the limit is off by one.
    #[test]
    fn passkey_name_rules() {
        assert_eq!(normalise_passkey_name(None).unwrap(), "Passkey");
        assert_eq!(normalise_passkey_name(Some("")).unwrap(), "Passkey");
        assert_eq!(normalise_passkey_name(Some("   ")).unwrap(), "Passkey");
        assert_eq!(normalise_passkey_name(Some("  Phone ")).unwrap(), "Phone");

        // 64 two-byte characters are 64 characters
        let longest = "é".repeat(MAX_PASSKEY_NAME_LEN);
        assert_eq!(normalise_passkey_name(Some(&longest)).unwrap(), longest);

        let too_long = "a".repeat(MAX_PASSKEY_NAME_LEN + 1);
        assert!(outcome(normalise_passkey_name(Some(&too_long))).starts_with("FailedValidation"));
        assert!(outcome(normalise_passkey_name(Some("a\u{7}b"))).starts_with("FailedValidation"));
    }

    // -----------------------------------------------------------------------
    // Configuration switches
    // -----------------------------------------------------------------------

    /// Fails if: any of the seven entry points stops calling `verifier()`
    /// first, or `verifier()` stops checking `available`.
    #[test]
    fn feature_off_refuses_every_entry_point() {
        rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.passkeys.available = false;
                settings.features.passkeys.rp_id = RP_ID.to_string();
                settings.features.passkeys.origins = vec![WEB_ORIGIN.to_string()];
            })
            .await;
            let harness = TestHarness::new().await;
            let (account, session, _) = harness.new_user().await;
            let db = &harness.db;
            let id = "0".repeat(64);
            let off = "FeatureDisabled";

            assert!(outcome(assert_available().await).starts_with(off));
            assert!(outcome(start_registration(db, &account, &session.id).await).starts_with(off));
            assert!(outcome(
                finish_registration(db, &account, &session.id, &id, json!({}), None).await
            )
            .starts_with(off));
            assert!(outcome(start_login().await).starts_with(off));
            assert!(outcome(finish_login(db, &id, json!({})).await).starts_with(off));
            assert!(outcome(start_assertion(db, &account, &session.id).await).starts_with(off));
            assert!(
                outcome(finish_assertion(db, &account, &session.id, &id, json!({})).await)
                    .starts_with(off)
            );
        })
    }

    /// Fails if: `verifier()` uses the config without `build_verifier`'s
    /// origin validation (one bad origin must switch the whole feature off).
    #[test]
    fn invalid_origin_in_config_switches_passkeys_off() {
        rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.passkeys.available = true;
                settings.features.passkeys.rp_id = RP_ID.to_string();
                settings.features.passkeys.origins =
                    vec![WEB_ORIGIN.to_string(), "https://evil.example".to_string()];
            })
            .await;

            assert!(outcome(assert_available().await).starts_with("FeatureDisabled"));
            assert!(outcome(start_login().await).starts_with("FeatureDisabled"));
        })
    }

    /// Fails if: `verifier()` accepts an empty origin list.
    #[test]
    fn empty_origin_list_switches_passkeys_off() {
        rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.passkeys.available = true;
                settings.features.passkeys.rp_id = RP_ID.to_string();
                settings.features.passkeys.origins = Vec::new();
            })
            .await;

            assert!(outcome(assert_available().await).starts_with("FeatureDisabled"));
            assert!(outcome(start_login().await).starts_with("FeatureDisabled"));
        })
    }

    /// Fails if: an explicit port is accepted again (`validate_passkey_origin`
    /// in the config crate), so a listed `:8443` origin no longer switches
    /// passkeys off.
    #[test]
    fn an_origin_with_a_port_in_config_switches_passkeys_off() {
        rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.passkeys.available = true;
                settings.features.passkeys.rp_id = RP_ID.to_string();
                settings.features.passkeys.origins = vec![
                    WEB_ORIGIN.to_string(),
                    "https://app.sloga.gg:8443".to_string(),
                ];
            })
            .await;

            assert!(outcome(assert_available().await).starts_with("FeatureDisabled"));
            assert!(outcome(start_login().await).starts_with("FeatureDisabled"));
        })
    }

    /// Fails if: `verifier()` builds a new library instance per call instead
    /// of handing out the one in `VERIFIER`.
    #[test]
    fn the_verifier_is_built_once_per_process() {
        rt().block_on(async {
            let _harness = setup().await;

            let first = verifier().await.expect("verifier");
            let second = verifier().await.expect("verifier");
            assert!(std::ptr::eq(first, second));
            assert_eq!(first.rp_id, RP_ID);
            assert_eq!(outcome(assert_available().await), "Ok");
        })
    }

    // -----------------------------------------------------------------------
    // OAuth session marker
    // -----------------------------------------------------------------------

    /// Fails if: `mark_oauth_session` writes another key, another value or no
    /// expiry; or `is_oauth_session` answers true for an unmarked session, a
    /// value other than "1", or an id that is not a session id.
    #[test]
    fn the_oauth_session_marker_is_per_session_and_expires() {
        rt().block_on(async {
            // The harness reads the config, which tells Redis where to be found
            let _harness = TestHarness::new().await;
            let mut conn = get_connection().await.expect("redis").into_inner();

            let marked = Ulid::new().to_string();
            let other = Ulid::new().to_string();
            let key = format!("passkey:oauth-session:{marked}");
            assert_eq!(oauth_session_key(&marked), key);

            // Unknown, then set, then another session id
            assert!(!is_oauth_session(&marked).await, "never marked");
            mark_oauth_session(&marked).await;
            assert!(is_oauth_session(&marked).await, "marked");
            assert!(!is_oauth_session(&other).await, "another session");

            // Exactly "1", for at most ten minutes
            let value: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .expect("GET");
            assert_eq!(value.as_deref(), Some("1"));
            let ttl: i64 = redis::cmd("TTL")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .expect("TTL");
            assert!((1..=600).contains(&ttl), "ttl {}", ttl);

            // Any other value is not the mark
            for wrong in ["0", "true", ""] {
                let _: () = redis::cmd("SET")
                    .arg(&key)
                    .arg(wrong)
                    .arg("EX")
                    .arg(60)
                    .query_async(&mut conn)
                    .await
                    .expect("SET");
                assert!(!is_oauth_session(&marked).await, "value {wrong:?}");
            }

            // Expired is deleted
            mark_oauth_session(&marked).await;
            assert!(is_oauth_session(&marked).await, "marked again");
            let _: i64 = redis::cmd("DEL")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .expect("DEL");
            assert!(!is_oauth_session(&marked).await, "expired");

            // Not a session id: nothing is written, and a key planted under
            // such an id is never read
            let run = Ulid::new().to_string();
            for malformed in [
                String::new(),
                "x".to_string(),
                format!("{run}:x"),
                format!("{run} "),
                format!("not-a-session-{run}"),
            ] {
                let planted = format!("passkey:oauth-session:{malformed}");

                mark_oauth_session(&malformed).await;
                let exists: i64 = redis::cmd("EXISTS")
                    .arg(&planted)
                    .query_async(&mut conn)
                    .await
                    .expect("EXISTS");
                assert_eq!(exists, 0, "marked {malformed:?}");

                let _: () = redis::cmd("SET")
                    .arg(&planted)
                    .arg("1")
                    .arg("EX")
                    .arg(60)
                    .query_async(&mut conn)
                    .await
                    .expect("SET");
                assert!(!is_oauth_session(&malformed).await, "read {malformed:?}");
                let _: i64 = redis::cmd("DEL")
                    .arg(&planted)
                    .query_async(&mut conn)
                    .await
                    .expect("DEL");
            }
        })
    }

    // -----------------------------------------------------------------------
    // Round trips
    // -----------------------------------------------------------------------

    async fn round_trip(origin: &str) {
        let harness = setup().await;
        let db = &harness.db;
        let (account, session, _) = harness.new_user().await;
        assert_eq!(outcome(assert_available().await), "Ok");

        // Register
        let mut soft = SoftPasskey::new();
        let started = start_registration(db, &account, &session.id)
            .await
            .expect("start registration");
        let credential = soft.create(&started.options, origin);
        let row = finish_registration(
            db,
            &account,
            &session.id,
            &started.challenge_id,
            credential,
            Some("  Phone ".to_string()),
        )
        .await
        .expect("finish registration");

        assert_eq!(row.user_id, account.id);
        assert_eq!(row.name, "Phone");
        assert_eq!(row.credential_id, b64u(&soft.cred_id));
        assert_eq!(row.last_used_at, None);
        assert_eq!(
            sans_created_at(&only_row(db, &account).await),
            sans_created_at(&row),
            "the returned row is the stored row"
        );
        assert_eq!(stored_counter(&row), 0);

        let info = passkey_info(&row);
        assert_eq!(
            (info.id, info.name, info.created_at, info.last_used_at),
            (row.id.clone(), row.name.clone(), row.created_at, None)
        );

        // Sign in, twice: a synced passkey reports counter 0 forever
        for _ in 0..2 {
            assert_eq!(
                login_with(db, &soft, origin, untouched)
                    .await
                    .expect("sign-in"),
                account.id
            );
        }
        let used = only_row(db, &account).await;
        assert!(used.last_used_at.is_some(), "the use was recorded");
        assert_eq!(stored_counter(&used), 0);

        // Ticket
        ticket_with(db, &account, &session.id, &soft, origin, untouched)
            .await
            .expect("ticket assertion");
    }

    /// Fails if: `build_verifier` does not make the https origin the primary
    /// allowed origin (or any step of the three ceremonies breaks).
    #[test]
    fn web_round_trip_register_sign_in_ticket() {
        rt().block_on(round_trip(WEB_ORIGIN))
    }

    /// Fails if: `build_verifier` drops the `append_allowed_origin` loop (the
    /// Android origin is only ever an appended extra).
    #[test]
    fn android_round_trip_register_sign_in_ticket() {
        rt().block_on(async {
            round_trip(&android_origin()).await;
        })
    }

    /// Fails if: the origin were bound to the credential instead of the
    /// ceremony (a passkey made on the phone must sign in on the web and back).
    #[test]
    fn a_passkey_made_on_android_works_on_the_web_and_back() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;
            let android = android_origin();

            let mut phone = SoftPasskey::new();
            register_with(db, &account, &session.id, &mut phone, &android, untouched)
                .await
                .expect("android registration");
            assert_eq!(login(db, &phone).await.expect("web sign-in"), account.id);
            ticket(db, &account, &session.id, &phone)
                .await
                .expect("web ticket");

            let mut browser = SoftPasskey::new();
            register(db, &account, &session.id, &mut browser).await;
            assert_eq!(
                login_with(db, &browser, &android, untouched)
                    .await
                    .expect("android sign-in"),
                account.id
            );
        })
    }

    // -----------------------------------------------------------------------
    // Options
    // -----------------------------------------------------------------------

    /// Fails if: `creation_options` / `request_options` keep `extensions`,
    /// return the wrapper, skip the `residentKey` rewrite, or
    /// `start_registration` stops building the exclude list.
    #[test]
    fn options_are_bare_extension_free_and_pin_the_rp() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;

            // Creation, first passkey
            let creation = start_registration(db, &account, &session.id)
                .await
                .expect("start registration")
                .options;
            assert_no_extension_members(&creation, "creation");
            assert_eq!(
                sorted_keys(&creation),
                [
                    "attestation",
                    "authenticatorSelection",
                    "challenge",
                    "pubKeyCredParams",
                    "rp",
                    "timeout",
                    "user",
                ]
            );
            assert_eq!(creation["rp"]["id"], json!(RP_ID));
            assert_eq!(
                creation["authenticatorSelection"],
                json!({
                    "residentKey": "required",
                    "requireResidentKey": true,
                    "userVerification": "required",
                })
            );
            assert_eq!(creation["attestation"], json!("none"));
            assert_eq!(creation["timeout"], json!(300000));
            assert!(creation["pubKeyCredParams"]
                .as_array()
                .expect("pubKeyCredParams")
                .iter()
                .any(|param| param["alg"] == json!(-7)));

            // Creation, second passkey: the first is excluded
            let mut soft = SoftPasskey::new();
            let row = register(db, &account, &session.id, &mut soft).await;
            let creation = start_registration(db, &account, &session.id)
                .await
                .expect("start registration")
                .options;
            assert_no_extension_members(&creation, "second creation");
            assert_eq!(
                creation["excludeCredentials"],
                json!([{ "type": "public-key", "id": row.credential_id }])
            );
            assert_eq!(creation["rp"]["id"], json!(RP_ID));
            assert_eq!(
                creation["authenticatorSelection"]["residentKey"],
                json!("required")
            );

            // Sign-in: discoverable, no credential list
            let request = start_login().await.expect("start login").options;
            assert_no_extension_members(&request, "sign-in");
            assert_eq!(
                sorted_keys(&request),
                [
                    "allowCredentials",
                    "challenge",
                    "rpId",
                    "timeout",
                    "userVerification"
                ]
            );
            assert_eq!(request["rpId"], json!(RP_ID));
            assert_eq!(request["allowCredentials"], json!([]));
            assert_eq!(request["userVerification"], json!("required"));

            // Ticket: names this account's credentials
            let request = start_assertion(db, &account, &session.id)
                .await
                .expect("start assertion")
                .options;
            assert_no_extension_members(&request, "ticket");
            assert_eq!(
                sorted_keys(&request),
                [
                    "allowCredentials",
                    "challenge",
                    "rpId",
                    "timeout",
                    "userVerification"
                ]
            );
            assert_eq!(request["rpId"], json!(RP_ID));
            assert_eq!(
                request["allowCredentials"],
                json!([{ "type": "public-key", "id": row.credential_id }])
            );
            assert_eq!(request["userVerification"], json!("required"));
        })
    }

    // -----------------------------------------------------------------------
    // Challenge state
    // -----------------------------------------------------------------------

    /// Fails if: `store_challenge` drops `EX` (no TTL) or `take_challenge`
    /// reads with GET instead of GETDEL (the key would survive a finish).
    #[test]
    fn a_challenge_has_a_ttl_holds_its_binding_and_is_deleted_on_use() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;

            let started = start_registration(db, &account, &session.id)
                .await
                .expect("start registration");
            assert!(is_challenge_id(&started.challenge_id));
            let key = challenge_key(&started.challenge_id);
            assert_eq!(key, format!("passkey:challenge:{}", started.challenge_id));

            let mut conn = get_connection().await.expect("redis").into_inner();
            let ttl: i64 = redis::cmd("TTL")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .expect("TTL");
            assert!((1..=300).contains(&ttl), "ttl {}", ttl);

            let blob: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .expect("GET");
            let blob: Value = serde_json::from_str(&blob.expect("blob")).expect("json");
            assert_eq!(blob["account_id"], json!(account.id));
            assert_eq!(blob["session_id"], json!(session.id));
            assert!(blob["ceremony"].get("Register").is_some(), "{}", blob);

            // A finish that fails still deletes the key
            let failed = finish_registration(
                db,
                &account,
                &session.id,
                &started.challenge_id,
                json!({}),
                None,
            )
            .await;
            assert_eq!(outcome(failed), REFUSED);
            let exists: i64 = redis::cmd("EXISTS")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .expect("EXISTS");
            assert_eq!(exists, 0);
        })
    }

    /// Fails if: `finish_registration` drops the account or the session from
    /// its match guard, accepts another `Ceremony` variant, or the challenge
    /// stops being consumed by a failed finish.
    #[test]
    fn a_registration_challenge_is_bound_and_single_use() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (alice, alice_session, _) = harness.new_user().await;
            let (bob, bob_session, _) = harness.new_user().await;

            // Another account (with its own session) cannot finish it, and the
            // attempt burns it for its owner too
            let mut soft = SoftPasskey::new();
            let started = start_registration(db, &alice, &alice_session.id)
                .await
                .expect("start");
            let credential = soft.create(&started.options, WEB_ORIGIN);
            let by_bob = finish_registration(
                db,
                &bob,
                &bob_session.id,
                &started.challenge_id,
                credential.clone(),
                None,
            )
            .await;
            assert_eq!(outcome(by_bob), REFUSED, "wrong account");
            let after_failure = finish_registration(
                db,
                &alice,
                &alice_session.id,
                &started.challenge_id,
                credential,
                None,
            )
            .await;
            assert_eq!(
                outcome(after_failure),
                REFUSED,
                "burned by the failed finish"
            );

            // The same account from another session
            let started = start_registration(db, &alice, &alice_session.id)
                .await
                .expect("start");
            let credential = soft.create(&started.options, WEB_ORIGIN);
            let other_session = finish_registration(
                db,
                &alice,
                &bob_session.id,
                &started.challenge_id,
                credential,
                None,
            )
            .await;
            assert_eq!(outcome(other_session), REFUSED, "wrong session");

            // A sign-in challenge and a ticket challenge cannot finish a
            // registration (alice needs a passkey for the ticket start)
            let mut first = SoftPasskey::new();
            register(db, &alice, &alice_session.id, &mut first).await;
            let login_id = start_login().await.expect("start login").challenge_id;
            let ticket_id = start_assertion(db, &alice, &alice_session.id)
                .await
                .expect("start assertion")
                .challenge_id;
            for (what, foreign_id) in [("sign-in", login_id), ("ticket", ticket_id)] {
                let started = start_registration(db, &alice, &alice_session.id)
                    .await
                    .expect("start");
                let credential = SoftPasskey::new().create(&started.options, WEB_ORIGIN);
                let crossed = finish_registration(
                    db,
                    &alice,
                    &alice_session.id,
                    &foreign_id,
                    credential,
                    None,
                )
                .await;
                assert_eq!(outcome(crossed), REFUSED, "{what} challenge");
            }

            // Unknown and malformed ids
            let started = start_registration(db, &alice, &alice_session.id)
                .await
                .expect("start");
            let credential = SoftPasskey::new().create(&started.options, WEB_ORIGIN);
            for id in [
                "f".repeat(64),
                "x".to_string(),
                String::new(),
                "F".repeat(64),
            ] {
                let unknown = finish_registration(
                    db,
                    &alice,
                    &alice_session.id,
                    &id,
                    credential.clone(),
                    None,
                )
                .await;
                assert_eq!(outcome(unknown), REFUSED, "id {id:?}");
            }

            // Success, then the same id and response again
            let mut second = SoftPasskey::new();
            let started = start_registration(db, &alice, &alice_session.id)
                .await
                .expect("start");
            let credential = second.create(&started.options, WEB_ORIGIN);
            finish_registration(
                db,
                &alice,
                &alice_session.id,
                &started.challenge_id,
                credential.clone(),
                None,
            )
            .await
            .expect("first finish");
            let replay = finish_registration(
                db,
                &alice,
                &alice_session.id,
                &started.challenge_id,
                credential,
                None,
            )
            .await;
            assert_eq!(outcome(replay), REFUSED, "replay");

            assert_eq!(db.count_passkeys(&alice.id).await.unwrap(), 2);
            assert_eq!(db.count_passkeys(&bob.id).await.unwrap(), 0);
        })
    }

    /// Fails if: `finish_assertion` drops the account or the session from its
    /// match guard, accepts another `Ceremony` variant, or looks the row up
    /// outside this account's rows.
    #[test]
    fn a_ticket_challenge_is_bound_and_single_use() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (alice, alice_session, _) = harness.new_user().await;
            let (bob, bob_session, _) = harness.new_user().await;
            let mut alice_key = SoftPasskey::new();
            register(db, &alice, &alice_session.id, &mut alice_key).await;
            let mut bob_key = SoftPasskey::new();
            register(db, &bob, &bob_session.id, &mut bob_key).await;

            // Bob cannot finish alice's challenge, even with alice's response
            let started = start_assertion(db, &alice, &alice_session.id)
                .await
                .expect("start");
            let credential = alice_key.get(&started.options, WEB_ORIGIN);
            let by_bob = finish_assertion(
                db,
                &bob,
                &bob_session.id,
                &started.challenge_id,
                credential.clone(),
            )
            .await;
            assert_eq!(outcome(by_bob), REFUSED, "wrong account");
            let after_failure = finish_assertion(
                db,
                &alice,
                &alice_session.id,
                &started.challenge_id,
                credential,
            )
            .await;
            assert_eq!(
                outcome(after_failure),
                REFUSED,
                "burned by the failed finish"
            );

            // Alice from another session
            let started = start_assertion(db, &alice, &alice_session.id)
                .await
                .expect("start");
            let credential = alice_key.get(&started.options, WEB_ORIGIN);
            let other_session = finish_assertion(
                db,
                &alice,
                &bob_session.id,
                &started.challenge_id,
                credential,
            )
            .await;
            assert_eq!(outcome(other_session), REFUSED, "wrong session");

            // Bob's passkey cannot answer alice's ticket
            bob_key.ignore_allow_list = true;
            assert_eq!(
                outcome(ticket(db, &alice, &alice_session.id, &bob_key).await),
                REFUSED,
                "another account's passkey"
            );

            // A registration challenge and a sign-in challenge cannot finish
            // a ticket
            let register_id = start_registration(db, &alice, &alice_session.id)
                .await
                .expect("start registration")
                .challenge_id;
            let login_started = start_login().await.expect("start login");
            let login_response = alice_key.get(&login_started.options, WEB_ORIGIN);
            let crossed = finish_assertion(
                db,
                &alice,
                &alice_session.id,
                &login_started.challenge_id,
                login_response,
            )
            .await;
            assert_eq!(outcome(crossed), REFUSED, "sign-in challenge");
            let started = start_assertion(db, &alice, &alice_session.id)
                .await
                .expect("start");
            let credential = alice_key.get(&started.options, WEB_ORIGIN);
            let crossed =
                finish_assertion(db, &alice, &alice_session.id, &register_id, credential).await;
            assert_eq!(outcome(crossed), REFUSED, "registration challenge");

            // Unknown id
            let started = start_assertion(db, &alice, &alice_session.id)
                .await
                .expect("start");
            let credential = alice_key.get(&started.options, WEB_ORIGIN);
            let unknown = finish_assertion(
                db,
                &alice,
                &alice_session.id,
                &"e".repeat(64),
                credential.clone(),
            )
            .await;
            assert_eq!(outcome(unknown), REFUSED, "unknown id");

            // The control, then a replay of it
            finish_assertion(
                db,
                &alice,
                &alice_session.id,
                &started.challenge_id,
                credential.clone(),
            )
            .await
            .expect("own challenge, own session, own passkey");
            let replay = finish_assertion(
                db,
                &alice,
                &alice_session.id,
                &started.challenge_id,
                credential,
            )
            .await;
            assert_eq!(outcome(replay), REFUSED, "replay");
        })
    }

    /// Fails if: `finish_login` accepts a `Ceremony` other than `Login`, or
    /// `take_challenge` stops deleting what it reads.
    #[test]
    fn a_sign_in_challenge_is_single_use_and_login_only() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;
            let mut soft = SoftPasskey::new();
            register(db, &account, &session.id, &mut soft).await;

            // Success, then a replay
            let started = start_login().await.expect("start");
            let credential = soft.get(&started.options, WEB_ORIGIN);
            assert_eq!(
                finish_login(db, &started.challenge_id, credential.clone())
                    .await
                    .expect("sign-in"),
                account.id
            );
            assert_eq!(
                outcome(finish_login(db, &started.challenge_id, credential).await),
                REFUSED,
                "replay"
            );

            // A failed finish burns the challenge for the honest response
            let started = start_login().await.expect("start");
            let credential = soft.get(&started.options, WEB_ORIGIN);
            assert_eq!(
                outcome(finish_login(db, &started.challenge_id, json!({})).await),
                REFUSED
            );
            assert_eq!(
                outcome(finish_login(db, &started.challenge_id, credential).await),
                REFUSED,
                "burned by the failed finish"
            );

            // A ticket challenge (same response shape) and a registration
            // challenge cannot sign in
            let ticket_started = start_assertion(db, &account, &session.id)
                .await
                .expect("start assertion");
            let ticket_response = soft.get(&ticket_started.options, WEB_ORIGIN);
            assert_eq!(
                outcome(finish_login(db, &ticket_started.challenge_id, ticket_response).await),
                REFUSED,
                "ticket challenge"
            );
            let register_id = start_registration(db, &account, &session.id)
                .await
                .expect("start registration")
                .challenge_id;
            let started = start_login().await.expect("start");
            let credential = soft.get(&started.options, WEB_ORIGIN);
            assert_eq!(
                outcome(finish_login(db, &register_id, credential.clone()).await),
                REFUSED,
                "registration challenge"
            );

            // Unknown and malformed ids
            for id in ["d".repeat(64), "nope".to_string(), String::new()] {
                assert_eq!(
                    outcome(finish_login(db, &id, credential.clone()).await),
                    REFUSED,
                    "id {id:?}"
                );
            }

            // An expired challenge is a deleted key
            let mut conn = get_connection().await.expect("redis").into_inner();
            let deleted: i64 = redis::cmd("DEL")
                .arg(challenge_key(&started.challenge_id))
                .query_async(&mut conn)
                .await
                .expect("DEL");
            assert_eq!(deleted, 1);
            assert_eq!(
                outcome(finish_login(db, &started.challenge_id, credential).await),
                REFUSED,
                "expired"
            );
        })
    }

    // -----------------------------------------------------------------------
    // R1: extension outputs
    // -----------------------------------------------------------------------

    /// Fails if: `parse_registration` / `parse_assertion` skip
    /// `clean_raw_credential` (the typed parse drops these silently and the
    /// library then verifies the response).
    #[test]
    fn client_extension_outputs_are_refused_in_every_ceremony() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;
            let mut soft = SoftPasskey::new();
            register(db, &account, &session.id, &mut soft).await;

            let tampers: [(&str, fn(&mut Value)); 6] = [
                ("prf output", |credential| {
                    credential["clientExtensionResults"] =
                        json!({ "prf": { "results": { "first": "AAAA" } } })
                }),
                ("hmacGetSecret output", |credential| {
                    credential["clientExtensionResults"] =
                        json!({ "hmacGetSecret": { "output1": "AAAA" } })
                }),
                ("largeBlob output", |credential| {
                    credential["clientExtensionResults"] =
                        json!({ "largeBlob": { "supported": true } })
                }),
                // A plain `credProps` is allowed on a creation response only:
                // see the two credProps tests below
                ("credProps beside another output", |credential| {
                    credential["clientExtensionResults"] =
                        json!({ "credProps": { "rk": true }, "prf": {} })
                }),
                ("null outputs", |credential| {
                    credential["clientExtensionResults"] = Value::Null
                }),
                ("top-level extensions", |credential| {
                    let object = credential.as_object_mut().expect("object");
                    object.remove("clientExtensionResults");
                    object.insert("extensions".to_string(), json!({}));
                }),
            ];

            for (what, tamper) in tampers {
                let mut fresh = SoftPasskey::new();
                assert_eq!(
                    outcome(
                        register_with(db, &account, &session.id, &mut fresh, WEB_ORIGIN, tamper)
                            .await
                    ),
                    REFUSED,
                    "registration with {what}"
                );
                assert_eq!(
                    outcome(login_with(db, &soft, WEB_ORIGIN, tamper).await),
                    REFUSED,
                    "sign-in with {what}"
                );
                assert_eq!(
                    outcome(
                        ticket_with(db, &account, &session.id, &soft, WEB_ORIGIN, tamper).await
                    ),
                    REFUSED,
                    "ticket with {what}"
                );
            }

            // A response that is not an object at all
            let started = start_login().await.expect("start");
            assert_eq!(
                outcome(finish_login(db, &started.challenge_id, json!("credential")).await),
                REFUSED
            );

            // Nothing was stored by the refused registrations, and the
            // untouched response still works
            assert_eq!(db.count_passkeys(&account.id).await.unwrap(), 1);
            assert_eq!(login(db, &soft).await.expect("clean sign-in"), account.id);
            ticket(db, &account, &session.id, &soft)
                .await
                .expect("clean ticket");
        })
    }

    /// Fails if: `clean_raw_credential` stops allowing a lone plain
    /// `credProps` on a creation response, or allows any other shape. (That
    /// it is removed before the typed parse is pinned by
    /// `raw_credential_gate`: the library would read it without complaint.)
    #[test]
    fn cred_props_on_a_creation_response_is_dropped_and_the_passkey_registers() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;

            let mut allowed = vec![json!({})];
            allowed.extend(plain_cred_props());
            let expected = allowed.len() as u64;

            for outputs in allowed {
                let mut soft = SoftPasskey::new();
                let started = start_registration(db, &account, &session.id)
                    .await
                    .expect("start");
                let mut credential = soft.create(&started.options, WEB_ORIGIN);
                credential["clientExtensionResults"] = outputs.clone();
                let registered = finish_registration(
                    db,
                    &account,
                    &session.id,
                    &started.challenge_id,
                    credential,
                    None,
                )
                .await;
                assert_eq!(outcome(registered), "Ok", "registration with {outputs}");
                assert_eq!(login(db, &soft).await.expect("sign-in"), account.id);
            }
            assert_eq!(db.count_passkeys(&account.id).await.unwrap(), expected);

            for outputs in odd_cred_props() {
                let mut soft = SoftPasskey::new();
                let started = start_registration(db, &account, &session.id)
                    .await
                    .expect("start");
                let mut credential = soft.create(&started.options, WEB_ORIGIN);
                credential["clientExtensionResults"] = outputs.clone();
                let refused = finish_registration(
                    db,
                    &account,
                    &session.id,
                    &started.challenge_id,
                    credential,
                    None,
                )
                .await;
                assert_eq!(outcome(refused), REFUSED, "registration with {outputs}");
            }
            assert_eq!(db.count_passkeys(&account.id).await.unwrap(), expected);
        })
    }

    /// Fails if: `parse_assertion` passes `ResponseKind::Create` (the
    /// `credProps` allowance is for creation responses only).
    #[test]
    fn cred_props_on_a_sign_in_or_a_ticket_is_refused() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;
            let mut soft = SoftPasskey::new();
            register(db, &account, &session.id, &mut soft).await;

            let mut every_shape = plain_cred_props().to_vec();
            every_shape.extend(odd_cred_props());

            for outputs in every_shape {
                let started = start_login().await.expect("start login");
                let mut credential = soft.get(&started.options, WEB_ORIGIN);
                credential["clientExtensionResults"] = outputs.clone();
                assert_eq!(
                    outcome(finish_login(db, &started.challenge_id, credential).await),
                    REFUSED,
                    "sign-in with {outputs}"
                );

                let started = start_assertion(db, &account, &session.id)
                    .await
                    .expect("start assertion");
                let mut credential = soft.get(&started.options, WEB_ORIGIN);
                credential["clientExtensionResults"] = outputs.clone();
                assert_eq!(
                    outcome(
                        finish_assertion(
                            db,
                            &account,
                            &session.id,
                            &started.challenge_id,
                            credential
                        )
                        .await
                    ),
                    REFUSED,
                    "ticket with {outputs}"
                );
            }

            // The control: the same passkey with no extension output
            assert_eq!(login(db, &soft).await.expect("clean sign-in"), account.id);
            ticket(db, &account, &session.id, &soft)
                .await
                .expect("clean ticket");
        })
    }

    /// Fails if: `attestation_auth_data` stops refusing a top-level member
    /// other than `fmt`, `attStmt` and `authData` (the library reads `epAtt`
    /// and `largeBlobKey` and then verifies the response).
    #[test]
    fn an_attestation_object_with_another_member_is_refused() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;

            // h'00..1f' (32 bytes), and `true`
            let mut blob_key = vec![0x58, 0x20];
            blob_key.extend(0u8..32);
            let extras: [(&str, Vec<u8>); 3] = [
                ("largeBlobKey", blob_key),
                ("epAtt", vec![0xF5]),
                ("somethingElse", vec![0x00]),
            ];

            for (member, value) in extras {
                let mut soft = SoftPasskey::new();
                soft.attestation_extra = vec![(member.to_string(), value)];
                assert_eq!(
                    outcome(
                        register_with(db, &account, &session.id, &mut soft, WEB_ORIGIN, untouched)
                            .await
                    ),
                    REFUSED,
                    "attestation object with {member}"
                );
            }
            assert_eq!(db.count_passkeys(&account.id).await.unwrap(), 0);

            // The control: the same authenticator with no extra member
            let mut soft = SoftPasskey::new();
            register(db, &account, &session.id, &mut soft).await;
        })
    }

    /// Fails if: `parse_registration` / `parse_assertion` skip
    /// `no_signed_extensions` (the library parses signed extension outputs
    /// and then discards them).
    #[test]
    fn the_signed_extension_flag_is_refused_in_every_ceremony() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;

            let mut flagged = SoftPasskey::new();
            flagged.signed_extensions_cbor = Some(SoftPasskey::unsolicited_hmac_secret());
            assert_eq!(
                outcome(
                    register_with(
                        db,
                        &account,
                        &session.id,
                        &mut flagged,
                        WEB_ORIGIN,
                        untouched
                    )
                    .await
                ),
                REFUSED,
                "registration"
            );
            assert_eq!(db.count_passkeys(&account.id).await.unwrap(), 0);

            let mut soft = SoftPasskey::new();
            register(db, &account, &session.id, &mut soft).await;
            soft.signed_extensions_cbor = Some(SoftPasskey::unsolicited_hmac_secret());
            assert_eq!(outcome(login(db, &soft).await), REFUSED, "sign-in");
            assert_eq!(
                outcome(ticket(db, &account, &session.id, &soft).await),
                REFUSED,
                "ticket"
            );

            // The control: the same passkey without the flag
            soft.signed_extensions_cbor = None;
            assert_eq!(login(db, &soft).await.expect("sign-in"), account.id);
            ticket(db, &account, &session.id, &soft)
                .await
                .expect("ticket");
        })
    }

    // -----------------------------------------------------------------------
    // What the library checks, proven through this layer
    // -----------------------------------------------------------------------

    /// Fails if: a ceremony were started with a user-verification policy other
    /// than required (R6), e.g. through the library's security-key functions.
    #[test]
    fn user_verification_zero_is_refused_in_every_ceremony() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;

            let mut no_uv = SoftPasskey::new();
            no_uv.uv = false;
            assert_eq!(
                outcome(
                    register_with(db, &account, &session.id, &mut no_uv, WEB_ORIGIN, untouched)
                        .await
                ),
                REFUSED,
                "registration"
            );

            let mut soft = SoftPasskey::new();
            register(db, &account, &session.id, &mut soft).await;
            soft.uv = false;
            assert_eq!(outcome(login(db, &soft).await), REFUSED, "sign-in");
            assert_eq!(
                outcome(ticket(db, &account, &session.id, &soft).await),
                REFUSED,
                "ticket"
            );

            // User presence is required too
            soft.uv = true;
            soft.up = false;
            assert_eq!(outcome(login(db, &soft).await), REFUSED, "no user presence");

            soft.up = true;
            assert_eq!(login(db, &soft).await.expect("control"), account.id);
            assert_eq!(db.count_passkeys(&account.id).await.unwrap(), 1);
        })
    }

    /// Fails if: `build_verifier` calls `allow_subdomains(true)` or
    /// `allow_any_port(true)`, or appends an origin that is not configured.
    #[test]
    fn an_origin_that_is_not_configured_is_refused_in_every_ceremony() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;
            let mut soft = SoftPasskey::new();
            register(db, &account, &session.id, &mut soft).await;

            let android = android_origin();
            let other_hash = format!("android:apk-key-hash:{}", b64u(&[0xAAu8; 32]));
            let lowercased = android.to_lowercase();
            assert_ne!(
                lowercased, android,
                "the test hash has upper-case characters"
            );

            for bad in [
                "https://evil.example",
                "https://app.sloga.gg.evil.example",
                "https://evilapp.sloga.gg",
                "https://sub.app.sloga.gg",
                "https://sloga.gg",
                "http://app.sloga.gg",
                "https://app.sloga.gg:8443",
                "ios:bundle-id:gg.sloga.app",
                other_hash.as_str(),
                lowercased.as_str(),
            ] {
                let mut fresh = SoftPasskey::new();
                assert_eq!(
                    outcome(
                        register_with(db, &account, &session.id, &mut fresh, bad, untouched).await
                    ),
                    REFUSED,
                    "registration from {bad}"
                );
                assert_eq!(
                    outcome(login_with(db, &soft, bad, untouched).await),
                    REFUSED,
                    "sign-in from {bad}"
                );
                assert_eq!(
                    outcome(ticket_with(db, &account, &session.id, &soft, bad, untouched).await),
                    REFUSED,
                    "ticket from {bad}"
                );
            }

            assert_eq!(db.count_passkeys(&account.id).await.unwrap(), 1);
        })
    }

    /// Fails if: the library were built with an RP ID other than the
    /// configured `rp_id` (the hash in authenticatorData is the only binding
    /// of a credential to this relying party).
    #[test]
    fn a_wrong_rp_id_hash_is_refused_in_every_ceremony() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;

            let mut wrong = SoftPasskey::new();
            wrong.rp_id_override = Some("evil.example".to_string());
            assert_eq!(
                outcome(
                    register_with(db, &account, &session.id, &mut wrong, WEB_ORIGIN, untouched)
                        .await
                ),
                REFUSED,
                "registration"
            );

            let mut soft = SoftPasskey::new();
            register(db, &account, &session.id, &mut soft).await;
            // The parent domain is a different relying party
            soft.rp_id_override = Some("sloga.gg".to_string());
            assert_eq!(outcome(login(db, &soft).await), REFUSED, "sign-in");
            assert_eq!(
                outcome(ticket(db, &account, &session.id, &soft).await),
                REFUSED,
                "ticket"
            );

            soft.rp_id_override = None;
            assert_eq!(login(db, &soft).await.expect("control"), account.id);
        })
    }

    // -----------------------------------------------------------------------
    // Sign-in specifics
    // -----------------------------------------------------------------------

    /// Fails if: `finish_login` drops the handle comparison, or resolves the
    /// account from the claimed handle instead of the row.
    #[test]
    fn a_user_handle_that_is_not_the_rows_is_refused() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (alice, alice_session, _) = harness.new_user().await;
            let (bob, bob_session, _) = harness.new_user().await;
            let mut alice_key = SoftPasskey::new();
            register(db, &alice, &alice_session.id, &mut alice_key).await;
            let mut bob_key = SoftPasskey::new();
            let bob_row = register(db, &bob, &bob_session.id, &mut bob_key).await;

            // Alice's signature, bob's handle: not alice, and never bob
            let bob_handle = Uuid::parse_str(&bob_row.user_handle).expect("uuid");
            let started = start_login().await.expect("start");
            let mut credential = alice_key.get(&started.options, WEB_ORIGIN);
            credential["response"]["userHandle"] = json!(b64u(bob_handle.as_bytes()));
            assert_eq!(
                outcome(finish_login(db, &started.challenge_id, credential).await),
                REFUSED,
                "another account's handle"
            );

            // A random handle, no handle, a handle that is not 16 bytes
            let tampers: [(&str, fn(&mut Value)); 3] = [
                ("random handle", |credential| {
                    credential["response"]["userHandle"] = json!(b64u(Uuid::new_v4().as_bytes()))
                }),
                ("no handle", |credential| {
                    credential["response"]["userHandle"] = Value::Null
                }),
                ("short handle", |credential| {
                    credential["response"]["userHandle"] = json!(b64u(b"not-a-uuid"))
                }),
            ];
            for (what, tamper) in tampers {
                assert_eq!(
                    outcome(login_with(db, &alice_key, WEB_ORIGIN, tamper).await),
                    REFUSED,
                    "{what}"
                );
            }

            // The control: each honest passkey signs its own account in
            assert_eq!(login(db, &alice_key).await.expect("alice"), alice.id);
            assert_eq!(login(db, &bob_key).await.expect("bob"), bob.id);
        })
    }

    /// Fails if: `finish_login` looked the credential up by anything but the
    /// credential id, verified against a key from the response, or skipped the
    /// account lookup for the row's owner.
    #[test]
    fn unknown_credentials_forged_signatures_and_orphan_rows_are_refused_alike() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;
            let mut soft = SoftPasskey::new();
            let row = register(db, &account, &session.id, &mut soft).await;

            // A passkey this server never saw
            let mut stranger = SoftPasskey::new();
            stranger.user_handle = Some(Uuid::new_v4().as_bytes().to_vec());
            assert_eq!(
                outcome(login(db, &stranger).await),
                REFUSED,
                "unknown credential"
            );

            // Another key pair claiming the registered credential id and handle
            let mut forger = SoftPasskey::new();
            forger.cred_id = soft.cred_id.clone();
            forger.user_handle = soft.user_handle.clone();
            assert_eq!(
                outcome(login(db, &forger).await),
                REFUSED,
                "forged signature"
            );
            forger.ignore_allow_list = true;
            assert_eq!(
                outcome(ticket(db, &account, &session.id, &forger).await),
                REFUSED,
                "forged signature on a ticket"
            );

            // A row whose account does not exist
            let ghost = Account {
                id: Ulid::new().to_string(),
                ..account.clone()
            };
            let mut ghost_key = SoftPasskey::new();
            register(db, &ghost, &session.id, &mut ghost_key).await;
            assert_eq!(outcome(login(db, &ghost_key).await), REFUSED, "orphan row");

            // None of it advanced or marked the real row
            assert_eq!(
                sans_created_at(&only_row(db, &account).await),
                sans_created_at(&row)
            );
            assert_eq!(login(db, &soft).await.expect("control"), account.id);
        })
    }

    // -----------------------------------------------------------------------
    // Signature counter and the compare-and-swap
    // -----------------------------------------------------------------------

    /// Fails if: `commit_use` stops calling `update_credential` or stops
    /// writing the row (the regression is then invisible: the library compares
    /// with the stored copy).
    #[test]
    fn a_counter_regression_is_refused_because_the_counter_is_persisted() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;
            let mut soft = SoftPasskey::new();
            register(db, &account, &session.id, &mut soft).await;

            // 0 -> 5: accepted and stored
            soft.counter = 5;
            assert_eq!(login(db, &soft).await.expect("0 -> 5"), account.id);
            assert_eq!(stored_counter(&only_row(db, &account).await), 5);

            // 5 -> 3, 5 -> 5 and 5 -> 0: refused, in both ceremonies
            for stale in [3, 5, 0] {
                soft.counter = stale;
                assert_eq!(
                    outcome(login(db, &soft).await),
                    REFUSED,
                    "sign-in at {stale}"
                );
                assert_eq!(
                    outcome(ticket(db, &account, &session.id, &soft).await),
                    REFUSED,
                    "ticket at {stale}"
                );
            }
            assert_eq!(stored_counter(&only_row(db, &account).await), 5);

            // 5 -> 6 by ticket, then 6 -> 7 by sign-in
            soft.counter = 6;
            ticket(db, &account, &session.id, &soft)
                .await
                .expect("5 -> 6");
            assert_eq!(stored_counter(&only_row(db, &account).await), 6);
            soft.counter = 7;
            assert_eq!(login(db, &soft).await.expect("6 -> 7"), account.id);
            assert_eq!(stored_counter(&only_row(db, &account).await), 7);
        })
    }

    /// Fails if: `commit_use` ignores the `false` from
    /// `update_passkey_after_use`, or passes anything but the text it read as
    /// the expected credential.
    #[test]
    fn a_lost_compare_and_swap_is_a_refusal() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;
            let mut soft = SoftPasskey::new();
            register(db, &account, &session.id, &mut soft).await;

            // A verified assertion, made with the library directly so the
            // moment between "verified" and "stored" can be held open
            let verifier = verifier().await.expect("verifier");
            let (response, state) = verifier
                .webauthn
                .start_discoverable_authentication()
                .expect("start");
            let options = request_options(&response, &verifier.rp_id).expect("options");
            soft.counter = 4;
            let assertion: PublicKeyCredential =
                serde_json::from_value(soft.get(&options, WEB_ORIGIN)).expect("assertion");
            let read = only_row(db, &account).await;
            let credential = stored_credential(&read).expect("stored credential");
            let result = verifier
                .webauthn
                .finish_discoverable_authentication_v2(&assertion, state, &credential)
                .expect("verified");

            // Another assertion gets there first and advances the row
            soft.counter = 9;
            assert_eq!(login(db, &soft).await.expect("the winner"), account.id);
            let advanced = only_row(db, &account).await;
            assert_ne!(advanced.credential, read.credential);

            // The loser still holds what it read: refused, nothing written
            let lost = commit_use(db, &read, credential.clone(), &result).await;
            assert_eq!(outcome(lost), REFUSED);
            assert_eq!(only_row(db, &account).await, advanced);
            assert_eq!(stored_counter(&advanced), 9);

            // A result for another credential is refused before any write
            let mut other = SoftPasskey::new();
            let other_row = register(db, &account, &session.id, &mut other).await;
            let other_credential = stored_credential(&other_row).expect("stored credential");
            let wrong = commit_use(db, &other_row, other_credential, &result).await;
            assert_eq!(outcome(wrong), REFUSED);

            // The control: the same helper on a row nobody else touched
            let fresh = db
                .fetch_passkey(&account.id, &other_row.id)
                .await
                .expect("row");
            let (response, state) = verifier
                .webauthn
                .start_discoverable_authentication()
                .expect("start");
            let options = request_options(&response, &verifier.rp_id).expect("options");
            let assertion: PublicKeyCredential =
                serde_json::from_value(other.get(&options, WEB_ORIGIN)).expect("assertion");
            let credential = stored_credential(&fresh).expect("stored credential");
            let result = verifier
                .webauthn
                .finish_discoverable_authentication_v2(&assertion, state, &credential)
                .expect("verified");
            commit_use(db, &fresh, credential, &result)
                .await
                .expect("an uncontended swap");
        })
    }

    /// Fails if: `finish_assertion` drops the snapshot comparison (the library
    /// checked the counter against the copy taken at start, so a row that has
    /// moved on must not be accepted).
    #[test]
    fn a_ticket_started_before_the_row_advanced_is_refused() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;
            let mut soft = SoftPasskey::new();
            register(db, &account, &session.id, &mut soft).await;

            // Start a ticket while the stored counter is 0
            let started = start_assertion(db, &account, &session.id)
                .await
                .expect("start");

            // A sign-in moves the row to 7
            soft.counter = 7;
            assert_eq!(login(db, &soft).await.expect("sign-in"), account.id);

            // Counter 3 passes the library (3 > the 0 in the stale state) but
            // is a regression against the row
            soft.counter = 3;
            let credential = soft.get(&started.options, WEB_ORIGIN);
            let stale =
                finish_assertion(db, &account, &session.id, &started.challenge_id, credential)
                    .await;
            assert_eq!(outcome(stale), REFUSED);
            assert_eq!(stored_counter(&only_row(db, &account).await), 7);

            // The control: a ticket started now, with a higher counter
            soft.counter = 8;
            ticket(db, &account, &session.id, &soft)
                .await
                .expect("fresh ticket");
        })
    }

    // -----------------------------------------------------------------------
    // Registration rules
    // -----------------------------------------------------------------------

    /// Fails if: `start_registration` uses the user id (or anything derived
    /// from it) as the handle, stops reusing the stored handle, or drops the
    /// Redis pin for a first registration.
    #[test]
    fn one_random_user_handle_per_account() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (alice, alice_session, _) = harness.new_user().await;
            let (bob, bob_session, _) = harness.new_user().await;

            // Two starts before any passkey exists: one handle
            let first = start_registration(db, &alice, &alice_session.id)
                .await
                .expect("start");
            let second = start_registration(db, &alice, &alice_session.id)
                .await
                .expect("start");
            let handle = first.options["user"]["id"].as_str().expect("user.id");
            assert_eq!(second.options["user"]["id"], json!(handle));

            // 16 random bytes, not the user id in any encoding
            let bytes = b64u_decode(handle);
            assert_eq!(bytes.len(), 16);
            assert_ne!(handle, alice.id);
            assert_ne!(handle, b64u(alice.id.as_bytes()));
            assert_ne!(Some(bytes.as_slice()), alice.id.as_bytes().get(..16));

            // Another account gets another handle
            let other = start_registration(db, &bob, &bob_session.id)
                .await
                .expect("start");
            assert_ne!(other.options["user"]["id"], json!(handle));

            // Both started challenges finish, under the one handle
            let mut soft_a = SoftPasskey::new();
            let mut soft_b = SoftPasskey::new();
            let row_a = finish_registration(
                db,
                &alice,
                &alice_session.id,
                &first.challenge_id,
                soft_a.create(&first.options, WEB_ORIGIN),
                None,
            )
            .await
            .expect("first finish");
            let row_b = finish_registration(
                db,
                &alice,
                &alice_session.id,
                &second.challenge_id,
                soft_b.create(&second.options, WEB_ORIGIN),
                None,
            )
            .await
            .expect("second finish");
            let stored = Uuid::from_slice(&bytes).expect("uuid").to_string();
            assert_eq!(row_a.user_handle, stored);
            assert_eq!(row_b.user_handle, stored);
            assert_eq!(row_a.name, "Passkey", "the default name");

            // A later registration reuses it from the rows
            let third = start_registration(db, &alice, &alice_session.id)
                .await
                .expect("start");
            assert_eq!(third.options["user"]["id"], json!(handle));
        })
    }

    /// Fails if: either cap check in `start_registration` /
    /// `finish_registration` is removed or compares with `>` instead of `>=`.
    #[test]
    fn an_eleventh_passkey_is_refused_at_start_and_at_finish() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;

            for _ in 0..(MAX_PASSKEYS_PER_ACCOUNT - 1) {
                let mut soft = SoftPasskey::new();
                register(db, &account, &session.id, &mut soft).await;
            }

            // Two challenges while one slot is left
            let tenth = start_registration(db, &account, &session.id)
                .await
                .expect("start");
            let eleventh = start_registration(db, &account, &session.id)
                .await
                .expect("start");

            finish_registration(
                db,
                &account,
                &session.id,
                &tenth.challenge_id,
                SoftPasskey::new().create(&tenth.options, WEB_ORIGIN),
                None,
            )
            .await
            .expect("the tenth passkey");

            let over = finish_registration(
                db,
                &account,
                &session.id,
                &eleventh.challenge_id,
                SoftPasskey::new().create(&eleventh.options, WEB_ORIGIN),
                None,
            )
            .await;
            assert_eq!(outcome(over), "InvalidOperation", "cap at finish");

            assert_eq!(
                outcome(start_registration(db, &account, &session.id).await),
                "InvalidOperation",
                "cap at start"
            );
            assert_eq!(
                db.count_passkeys(&account.id).await.unwrap(),
                MAX_PASSKEYS_PER_ACCOUNT
            );
        })
    }

    /// Fails if: `finish_registration` consumes the challenge before it checks
    /// the name, or stops calling `normalise_passkey_name`.
    #[test]
    fn a_long_name_is_refused_without_spending_the_challenge() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;
            let mut soft = SoftPasskey::new();

            let started = start_registration(db, &account, &session.id)
                .await
                .expect("start");
            let credential = soft.create(&started.options, WEB_ORIGIN);

            let too_long = finish_registration(
                db,
                &account,
                &session.id,
                &started.challenge_id,
                credential.clone(),
                Some("n".repeat(MAX_PASSKEY_NAME_LEN + 1)),
            )
            .await;
            assert!(outcome(too_long).starts_with("FailedValidation"));
            assert_eq!(db.count_passkeys(&account.id).await.unwrap(), 0);

            // The passkey already exists on the device: the same response
            // with a shorter name must still be accepted
            let row = finish_registration(
                db,
                &account,
                &session.id,
                &started.challenge_id,
                credential,
                Some("n".repeat(MAX_PASSKEY_NAME_LEN)),
            )
            .await
            .expect("the same response with a valid name");
            assert_eq!(row.name.chars().count(), MAX_PASSKEY_NAME_LEN);
        })
    }

    /// Fails if: `start_registration` hands the exclude list to the library
    /// (own duplicates then fail differently from foreign ones), or the
    /// duplicate pre-check is removed.
    #[test]
    fn a_duplicate_credential_id_gets_one_answer_whoever_holds_it() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (alice, alice_session, _) = harness.new_user().await;
            let (bob, bob_session, _) = harness.new_user().await;
            let mut soft = SoftPasskey::new();
            let row = register(db, &alice, &alice_session.id, &mut soft).await;

            // The same credential again, on its own account and on another.
            // (A real authenticator would mint a new id; this one is asked to
            // answer with the id it already has.)
            let own = register_with(
                db,
                &alice,
                &alice_session.id,
                &mut soft,
                WEB_ORIGIN,
                untouched,
            )
            .await;
            let foreign =
                register_with(db, &bob, &bob_session.id, &mut soft, WEB_ORIGIN, untouched).await;
            let own = outcome(own);
            assert_eq!(own, "NoEffect");
            assert_eq!(outcome(foreign), own, "one answer for both");

            // A client-chosen `id` string does not matter: the id comes from
            // the verified attestation
            let started = start_registration(db, &bob, &bob_session.id)
                .await
                .expect("start");
            let mut credential = soft.create(&started.options, WEB_ORIGIN);
            credential["id"] = json!("AAAA");
            credential["rawId"] = json!("AAAA");
            let renamed = finish_registration(
                db,
                &bob,
                &bob_session.id,
                &started.challenge_id,
                credential,
                None,
            )
            .await;
            assert_eq!(outcome(renamed), "NoEffect", "the verified id decides");

            // The first row stands, nothing else was stored
            assert_eq!(only_row(db, &alice).await.id, row.id);
            assert_eq!(db.count_passkeys(&bob.id).await.unwrap(), 0);
        })
    }

    /// Fails if: `finish_registration` took `credential_id` from the client's
    /// `id` / `rawId` instead of the verified attestation.
    #[test]
    fn the_stored_credential_id_is_the_verified_one_not_the_clients() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;
            let mut soft = SoftPasskey::new();

            let started = start_registration(db, &account, &session.id)
                .await
                .expect("start");
            let mut credential = soft.create(&started.options, WEB_ORIGIN);
            let claimed = b64u(&[0x42u8; 32]);
            credential["id"] = json!(claimed);
            credential["rawId"] = json!(claimed);
            let row = finish_registration(
                db,
                &account,
                &session.id,
                &started.challenge_id,
                credential,
                None,
            )
            .await
            .expect("registration");

            assert_eq!(row.credential_id, b64u(&soft.cred_id));
            assert_ne!(row.credential_id, claimed);
            assert!(db
                .fetch_passkey_by_credential_id(&claimed)
                .await
                .unwrap()
                .is_none());
            assert_eq!(login(db, &soft).await.expect("sign-in"), account.id);
        })
    }

    /// Fails if: `start_assertion` starts a ceremony for an account with no
    /// passkey (the library would emit a discoverable request for anyone).
    #[test]
    fn a_ticket_for_an_account_without_passkeys_is_never_started() {
        rt().block_on(async {
            let harness = setup().await;
            let db = &harness.db;
            let (account, session, _) = harness.new_user().await;

            assert_eq!(
                outcome(start_assertion(db, &account, &session.id).await),
                "InvalidOperation"
            );

            // An empty session id is refused at both starts
            assert_eq!(
                outcome(start_assertion(db, &account, "").await),
                "InvalidSession"
            );
            assert_eq!(
                outcome(start_registration(db, &account, "").await),
                "InvalidSession"
            );
        })
    }
}
