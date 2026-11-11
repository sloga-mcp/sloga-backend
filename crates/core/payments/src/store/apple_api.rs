//! App Store Server API client (S6 contracts 11.2, 11.3).
//!
//! The host follows the TRANSACTION's environment (R23): Production
//! `https://api.storekit.itunes.apple.com`, Sandbox `https://api.storekit-sandbox.itunes.apple.com`.
//! - Get Transaction Info: `GET /inApps/v1/transactions/{transactionId}` → `{signedTransactionInfo}`
//! - Get Notification History: `POST /inApps/v1/notifications/history?paginationToken=..` with body
//!   `{"startDate": ms, "endDate": ms}` → `{notificationHistory: [{signedPayload}], hasMore,
//!   paginationToken}`
//!
//! Every request carries `Authorization: Bearer <JWT>`, header `{alg: ES256, kid: key_id, typ: JWT}`,
//! claims `{iss: issuer_id, iat, exp: iat + 1200, aud: "appstoreconnect-v1", bid: bundle_id}`, signed
//! with the In-App Purchase key (PKCS#8 EC P-256 PEM). One JWT serves both hosts and is reused until
//! 5 minutes before it expires; a 401 drops it, so the next call signs a fresh one.
//!
//! The key is checked when the client is built, by signing a first JWT: a key that does not parse or
//! cannot sign ES256 leaves the client unconfigured (`configured()` false, logged
//! `PROT_STORE_CONFIG_INVALID`), so the intent gate closes instead of selling packs that cannot be
//! verified.

use std::{
    fmt,
    sync::{Mutex, PoisonError},
};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{Method, Url};
use revolt_models::v0;
use serde::{Deserialize, Serialize};

use super::{
    build_request, decode_json, environment_name, exchange, store_log, unix_now_s,
    url_with_segments, AppleHistoryPage, AppleStoreApi, HttpSend, ReqwestSend, StoreApiError,
    REDACTED,
};
use crate::settings::AppleStoreConfig;

/// App Store Server API, Production
pub const APPLE_API_PRODUCTION: &str = "https://api.storekit.itunes.apple.com";
/// App Store Server API, Sandbox
pub const APPLE_API_SANDBOX: &str = "https://api.storekit-sandbox.itunes.apple.com";
/// `aud` of every App Store Server API JWT
pub const APPLE_JWT_AUDIENCE: &str = "appstoreconnect-v1";

/// JWT lifetime (Apple accepts at most 60 minutes)
const JWT_TTL_S: i64 = 1200;
/// A cached JWT is replaced this long before it expires
const JWT_REFRESH_BEFORE_S: i64 = 300;

const STORE: &str = "apple";

/// The API host for a transaction's environment
pub fn apple_api_host(env: v0::ProtStoreEnvironment) -> &'static str {
    match env {
        v0::ProtStoreEnvironment::Production => APPLE_API_PRODUCTION,
        v0::ProtStoreEnvironment::Sandbox => APPLE_API_SANDBOX,
    }
}

/// Apple transaction ids are 1..=20 ASCII digits, a UInt64 (section 4); anything else is `NotFound`
/// without a request
pub(crate) fn check_transaction_id(transaction_id: &str) -> Result<(), StoreApiError> {
    if (1..=20).contains(&transaction_id.len())
        && transaction_id.bytes().all(|b| b.is_ascii_digit())
        && transaction_id.parse::<u64>().is_ok()
    {
        Ok(())
    } else {
        Err(StoreApiError::NotFound)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct AppleJwtClaims {
    iss: String,
    iat: i64,
    exp: i64,
    aud: String,
    bid: String,
}

/// Signs the API JWTs
struct JwtSigner {
    issuer_id: String,
    key_id: String,
    bundle_id: String,
    key: EncodingKey,
}

impl JwtSigner {
    fn header(&self) -> Header {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        header.typ = Some("JWT".to_string());
        header
    }

    fn claims(&self, iat: i64) -> AppleJwtClaims {
        AppleJwtClaims {
            iss: self.issuer_id.clone(),
            iat,
            exp: iat + JWT_TTL_S,
            aud: APPLE_JWT_AUDIENCE.to_string(),
            bid: self.bundle_id.clone(),
        }
    }

    /// `None` when the key cannot sign ES256
    fn sign(&self, iat: i64) -> Option<String> {
        jsonwebtoken::encode(&self.header(), &self.claims(iat), &self.key).ok()
    }
}

struct CachedJwt {
    jwt: String,
    issued_at: i64,
}

/// A configured client: usable credentials and an HTTP transport
struct AppleClient {
    signer: JwtSigner,
    jwt: Mutex<Option<CachedJwt>>,
    send: Box<dyn HttpSend>,
}

impl AppleClient {
    /// The cached JWT while `now_s` is in `[iat, exp - 5 min)`, else a fresh one
    fn jwt(&self, now_s: i64) -> Result<String, StoreApiError> {
        let mut cached = self.jwt.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = cached.as_ref() {
            let fresh_until = entry.issued_at + JWT_TTL_S - JWT_REFRESH_BEFORE_S;
            if (entry.issued_at..fresh_until).contains(&now_s) {
                return Ok(entry.jwt.clone());
            }
        }
        match self.signer.sign(now_s) {
            Some(jwt) => {
                *cached = Some(CachedJwt {
                    jwt: jwt.clone(),
                    issued_at: now_s,
                });
                Ok(jwt)
            }
            None => {
                *cached = None;
                store_log(
                    log::Level::Error,
                    "PROT_STORE_CONFIG_INVALID store=apple: could not sign the API JWT",
                );
                Err(StoreApiError::NotConfigured)
            }
        }
    }

    fn forget_jwt(&self) {
        *self.jwt.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    fn has_jwt(&self) -> bool {
        self.jwt
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    async fn call(
        &self,
        op: &str,
        subject: Option<&str>,
        method: Method,
        url: Url,
        body: Option<(Vec<u8>, &'static str)>,
    ) -> Result<Vec<u8>, StoreApiError> {
        let jwt = self.jwt(unix_now_s())?;
        let request = build_request(method, url, &jwt, body)?;
        let result = exchange(self.send.as_ref(), STORE, op, subject, request).await;
        if matches!(result, Err(StoreApiError::Rejected { status: 401 })) {
            self.forget_jwt();
        }
        result
    }
}

/// [`AppleStoreApi`] over HTTPS. `Debug` redacts the key and the JWT.
pub struct ReqwestAppleStore {
    /// `None`: no credentials, unusable credentials, or no HTTP client; every call is
    /// `NotConfigured` and nothing is sent
    client: Option<AppleClient>,
}

impl fmt::Debug for ReqwestAppleStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(client) = self.client.as_ref() else {
            return f
                .debug_struct("ReqwestAppleStore")
                .field("configured", &false)
                .finish();
        };
        f.debug_struct("ReqwestAppleStore")
            .field("configured", &true)
            .field("issuer_id", &client.signer.issuer_id)
            .field("key_id", &client.signer.key_id)
            .field("bundle_id", &client.signer.bundle_id)
            .field("private_key", &REDACTED)
            .field("jwt", &if client.has_jwt() { REDACTED } else { "<none>" })
            .finish()
    }
}

impl ReqwestAppleStore {
    /// `None` → `configured()` false and every call `NotConfigured`. In production
    /// `configured()` ≡ `config.is_some()` with a key that signs (section 9.3, audit N4).
    pub fn new(config: Option<AppleStoreConfig>) -> Self {
        let Some(config) = config else {
            return ReqwestAppleStore { client: None };
        };
        let Some(send) = ReqwestSend::new(STORE) else {
            return ReqwestAppleStore { client: None };
        };
        Self::build(
            &config.issuer_id,
            &config.key_id,
            &config.private_key,
            &config.bundle_id,
            Box::new(send),
            unix_now_s(),
        )
    }

    fn build(
        issuer_id: &str,
        key_id: &str,
        private_key: &str,
        bundle_id: &str,
        send: Box<dyn HttpSend>,
        now_s: i64,
    ) -> Self {
        let refuse = |why: &str| {
            store_log(
                log::Level::Error,
                &format!("PROT_STORE_CONFIG_INVALID store=apple: {why}"),
            );
            ReqwestAppleStore { client: None }
        };
        if issuer_id.is_empty() || key_id.is_empty() || bundle_id.is_empty() {
            return refuse("issuer_id, key_id and bundle_id must all be set");
        }
        let Ok(key) = EncodingKey::from_ec_pem(private_key.as_bytes()) else {
            return refuse("private_key is not a PKCS#8 EC PEM");
        };
        let signer = JwtSigner {
            issuer_id: issuer_id.to_string(),
            key_id: key_id.to_string(),
            bundle_id: bundle_id.to_string(),
            key,
        };
        // A key that parses but cannot sign ES256 (another curve) is refused here, not at the
        // first purchase
        let Some(jwt) = signer.sign(now_s) else {
            return refuse("private_key cannot sign ES256 (a P-256 key is required)");
        };
        ReqwestAppleStore {
            client: Some(AppleClient {
                signer,
                jwt: Mutex::new(Some(CachedJwt {
                    jwt,
                    issued_at: now_s,
                })),
                send,
            }),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionInfoAnswer {
    signed_transaction_info: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryRequest {
    start_date: i64,
    end_date: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryAnswer {
    #[serde(default)]
    notification_history: Vec<HistoryItem>,
    #[serde(default)]
    has_more: bool,
    pagination_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryItem {
    signed_payload: String,
}

#[async_trait]
impl AppleStoreApi for ReqwestAppleStore {
    fn configured(&self) -> bool {
        self.client.is_some()
    }

    async fn transaction_info(
        &self,
        env: v0::ProtStoreEnvironment,
        transaction_id: &str,
    ) -> Result<String, StoreApiError> {
        let client = self.client.as_ref().ok_or(StoreApiError::NotConfigured)?;
        check_transaction_id(transaction_id)?;
        let url = url_with_segments(
            apple_api_host(env),
            &["inApps", "v1", "transactions", transaction_id],
        )?;
        let subject = format!("transaction={transaction_id} env={}", environment_name(env));
        let body = client
            .call("transaction_info", Some(&subject), Method::GET, url, None)
            .await?;
        let answer: TransactionInfoAnswer = decode_json(STORE, "transaction_info", &body)?;
        Ok(answer.signed_transaction_info)
    }

    async fn notification_history(
        &self,
        env: v0::ProtStoreEnvironment,
        start_ms: i64,
        end_ms: i64,
        pagination_token: Option<&str>,
    ) -> Result<AppleHistoryPage, StoreApiError> {
        let client = self.client.as_ref().ok_or(StoreApiError::NotConfigured)?;
        let mut url = url_with_segments(
            apple_api_host(env),
            &["inApps", "v1", "notifications", "history"],
        )?;
        if let Some(token) = pagination_token.filter(|t| !t.is_empty()) {
            url.query_pairs_mut().append_pair("paginationToken", token);
        }
        let body = serde_json::to_vec(&HistoryRequest {
            start_date: start_ms,
            end_date: end_ms,
        })
        .map_err(|_| StoreApiError::Transient("could not build the request".to_string()))?;
        let subject = format!("env={}", environment_name(env));
        let reply = client
            .call(
                "notification_history",
                Some(&subject),
                Method::POST,
                url,
                Some((body, "application/json")),
            )
            .await?;
        let answer: HistoryAnswer = decode_json(STORE, "notification_history", &reply)?;
        let pagination_token = answer.pagination_token.filter(|t| !t.is_empty());
        if answer.has_more && pagination_token.is_none() {
            // Paging on would restart from the first page forever
            let error = StoreApiError::Transient("unexpected response body".to_string());
            super::log_failure(STORE, "notification_history", Some(&subject), &error);
            return Err(error);
        }
        Ok(AppleHistoryPage {
            signed_payloads: answer
                .notification_history
                .into_iter()
                .map(|item| item.signed_payload)
                .collect(),
            has_more: answer.has_more,
            pagination_token,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! A configured client over a [`FakeSend`], signing with a test key derived from a fixed label
    //! (no key is committed)

    use base64::{engine::general_purpose::STANDARD, Engine};
    use sha2::{Digest, Sha256};

    use super::ReqwestAppleStore;
    use crate::store::test_support::FakeSend;

    pub(crate) const ISSUER_ID: &str = "57246542-96fe-1a63-e053-0824d011072a";
    pub(crate) const KEY_ID: &str = "2X9R4HXF34";
    pub(crate) const BUNDLE_ID: &str = "gg.sloga.app";

    /// The P-256 secret scalar of the test key
    pub(crate) fn test_scalar() -> [u8; 32] {
        let mut scalar = [0_u8; 32];
        scalar.copy_from_slice(&Sha256::digest(b"sloga-test-appstore-key"));
        scalar
    }

    /// DER as a PEM block of `label`
    pub(crate) fn pem(label: &str, der: &[u8]) -> String {
        let b64 = STANDARD.encode(der);
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
            .collect();
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            lines.join("\n")
        )
    }

    /// The test key as PKCS#8 (an RFC 5915 ECPrivateKey on P-256, without the optional public key)
    pub(crate) fn test_key_pem() -> String {
        let mut der = vec![
            0x30, 0x41, // PrivateKeyInfo
            0x02, 0x01, 0x00, // version 0
            0x30, 0x13, // AlgorithmIdentifier
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1
            0x04, 0x27, // privateKey OCTET STRING
            0x30, 0x25, // ECPrivateKey
            0x02, 0x01, 0x01, // version 1
            0x04, 0x20, // the 32-byte scalar follows
        ];
        der.extend_from_slice(&test_scalar());
        pem("PRIVATE KEY", &der)
    }

    pub(crate) fn store_at(fake: &FakeSend, now_s: i64) -> ReqwestAppleStore {
        ReqwestAppleStore::build(
            ISSUER_ID,
            KEY_ID,
            &test_key_pem(),
            BUNDLE_ID,
            Box::new(fake.clone()),
            now_s,
        )
    }

    pub(crate) fn store(fake: &FakeSend) -> ReqwestAppleStore {
        store_at(fake, super::unix_now_s())
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, SigningKey};
    use sha2::{Digest, Sha384};

    use super::tests_support::{
        pem, store, store_at, test_key_pem, test_scalar, BUNDLE_ID, ISSUER_ID, KEY_ID,
    };
    use super::*;
    use crate::store::{log_capture, test_support::FakeSend};

    const NOW_S: i64 = 1_762_000_000;
    const TX: &str = "2000000812345678";

    fn segment_json(segment: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
    }

    #[test]
    fn hosts_follow_the_transaction_environment() {
        assert_eq!(
            apple_api_host(v0::ProtStoreEnvironment::Production),
            "https://api.storekit.itunes.apple.com"
        );
        assert_eq!(
            apple_api_host(v0::ProtStoreEnvironment::Sandbox),
            "https://api.storekit-sandbox.itunes.apple.com"
        );
    }

    #[test]
    fn api_jwt_carries_the_pinned_header_and_claims() {
        let fake = FakeSend::new();
        let apple = store_at(&fake, NOW_S);
        assert!(apple.configured());
        let jwt = apple.client.as_ref().unwrap().jwt(NOW_S).unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            segment_json(parts[0]),
            serde_json::json!({"alg": "ES256", "kid": KEY_ID, "typ": "JWT"})
        );
        assert_eq!(
            segment_json(parts[1]),
            serde_json::json!({
                "iss": ISSUER_ID,
                "iat": NOW_S,
                "exp": NOW_S + 1200,
                "aud": "appstoreconnect-v1",
                "bid": BUNDLE_ID,
            })
        );

        // ES256: 64-byte r||s over `header.claims`, verifiable with the key's public half
        let signing_key = SigningKey::from_slice(&test_scalar()).unwrap();
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        signing_key
            .verifying_key()
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
        assert!(fake.sent().is_empty(), "signing sends nothing");
    }

    #[test]
    fn api_jwt_is_reused_until_five_minutes_before_expiry() {
        let fake = FakeSend::new();
        let apple = store_at(&fake, NOW_S);
        let client = apple.client.as_ref().unwrap();
        let first = client.jwt(NOW_S).unwrap();
        assert_eq!(client.jwt(NOW_S + 899).unwrap(), first);

        let renewed = client.jwt(NOW_S + 900).unwrap();
        assert_ne!(renewed, first);
        let claims = segment_json(renewed.split('.').nth(1).unwrap());
        assert_eq!(claims["iat"], NOW_S + 900);
        assert_eq!(claims["exp"], NOW_S + 900 + 1200);

        // A clock that went back signs again rather than sending a JWT from the future
        let back = client.jwt(NOW_S).unwrap();
        assert_eq!(segment_json(back.split('.').nth(1).unwrap())["iat"], NOW_S);
    }

    #[tokio::test]
    async fn transaction_info_request_and_answer() {
        let fake = FakeSend::new();
        let apple = store(&fake);
        fake.reply(
            200,
            r#"{"signedTransactionInfo": "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"}"#,
        );
        assert_eq!(
            apple
                .transaction_info(v0::ProtStoreEnvironment::Sandbox, TX)
                .await,
            Ok("eyJhbGciOiJFUzI1NiJ9.e30.c2ln".to_string())
        );

        let sent = fake.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].method, "GET");
        assert_eq!(
            sent[0].url,
            "https://api.storekit-sandbox.itunes.apple.com/inApps/v1/transactions/2000000812345678"
        );
        let authorization = sent[0].authorization.as_deref().unwrap();
        let jwt = authorization.strip_prefix("Bearer ").unwrap();
        assert_eq!(jwt.split('.').count(), 3);
        assert_eq!(sent[0].content_type, None);
        assert_eq!(sent[0].body, None);

        fake.reply(200, r#"{"signedTransactionInfo": "x.y.z"}"#);
        apple
            .transaction_info(v0::ProtStoreEnvironment::Production, TX)
            .await
            .unwrap();
        assert_eq!(
            fake.sent()[1].url,
            "https://api.storekit.itunes.apple.com/inApps/v1/transactions/2000000812345678"
        );
    }

    #[tokio::test]
    async fn notification_history_request_and_pages() {
        let fake = FakeSend::new();
        let apple = store(&fake);
        fake.reply(
            200,
            r#"{"notificationHistory": [
                    {"signedPayload": "p1.a.b", "sendAttemptResults": []},
                    {"signedPayload": "p2.a.b"}],
                "hasMore": true, "paginationToken": "page-2"}"#,
        );
        let page = apple
            .notification_history(
                v0::ProtStoreEnvironment::Production,
                1_000,
                2_000,
                Some("tok 1/+"),
            )
            .await
            .unwrap();
        assert_eq!(
            page,
            AppleHistoryPage {
                signed_payloads: vec!["p1.a.b".to_string(), "p2.a.b".to_string()],
                has_more: true,
                pagination_token: Some("page-2".to_string()),
            }
        );
        let sent = &fake.sent()[0];
        assert_eq!(sent.method, "POST");
        assert_eq!(
            sent.url,
            "https://api.storekit.itunes.apple.com/inApps/v1/notifications/history?paginationToken=tok+1%2F%2B"
        );
        assert_eq!(sent.content_type.as_deref(), Some("application/json"));
        let body: serde_json::Value =
            serde_json::from_slice(sent.body.as_deref().unwrap()).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"startDate": 1_000, "endDate": 2_000})
        );

        // Last page; no token sent on the first call
        fake.reply(200, r#"{"notificationHistory": [], "hasMore": false}"#);
        let page = apple
            .notification_history(v0::ProtStoreEnvironment::Sandbox, 1, 2, None)
            .await
            .unwrap();
        assert_eq!(
            page,
            AppleHistoryPage {
                signed_payloads: vec![],
                has_more: false,
                pagination_token: None,
            }
        );
        assert_eq!(
            fake.sent()[1].url,
            "https://api.storekit-sandbox.itunes.apple.com/inApps/v1/notifications/history"
        );

        // More pages without a token cannot be followed
        fake.reply(200, r#"{"notificationHistory": [], "hasMore": true}"#);
        assert_eq!(
            apple
                .notification_history(v0::ProtStoreEnvironment::Production, 1, 2, None)
                .await,
            Err(StoreApiError::Transient(
                "unexpected response body".to_string()
            ))
        );
    }

    #[tokio::test]
    async fn apple_errors_map_per_contract() {
        let fake = FakeSend::new();
        let apple = store(&fake);
        let env = v0::ProtStoreEnvironment::Production;
        log_capture::take();

        fake.reply(404, r#"{"errorCode": 4040010}"#);
        assert_eq!(
            apple.transaction_info(env, TX).await,
            Err(StoreApiError::NotFound)
        );
        fake.reply(400, r#"{"errorCode": 4000006}"#);
        assert_eq!(
            apple.transaction_info(env, TX).await,
            Err(StoreApiError::Rejected { status: 400 })
        );
        fake.reply(500, "");
        assert_eq!(
            apple.transaction_info(env, TX).await,
            Err(StoreApiError::Transient("HTTP 500".to_string()))
        );
        fake.reply(200, "<html>");
        assert_eq!(
            apple.transaction_info(env, TX).await,
            Err(StoreApiError::Transient(
                "unexpected response body".to_string()
            ))
        );
        fake.fail(StoreApiError::Transient("request timed out".to_string()));
        assert_eq!(
            apple.transaction_info(env, TX).await,
            Err(StoreApiError::Transient("request timed out".to_string()))
        );

        // A 401 is logged for the operator and drops the cached JWT
        assert!(apple.client.as_ref().unwrap().has_jwt());
        fake.reply(401, "");
        assert_eq!(
            apple.transaction_info(env, TX).await,
            Err(StoreApiError::Rejected { status: 401 })
        );
        assert!(!apple.client.as_ref().unwrap().has_jwt());
        let lines = log_capture::take();
        assert!(
            lines.iter().any(|line| line
                == "PROT_STORE_API_AUTH store=apple op=transaction_info transaction=2000000812345678 env=Production status=401"),
            "{lines:?}"
        );
        let jwts: Vec<String> = fake
            .sent()
            .iter()
            .filter_map(|s| s.authorization.clone())
            .collect();
        for line in &lines {
            assert!(!jwts.iter().any(|jwt| line.contains(&jwt[7..])), "{line}");
        }
    }

    #[tokio::test]
    async fn malformed_transaction_id_is_not_found_without_a_request() {
        let fake = FakeSend::new();
        let apple = store(&fake);
        for bad in [
            "",
            "abc",
            "12/34",
            "1.2",
            "123456789012345678901",
            "99999999999999999999",
        ] {
            assert_eq!(
                apple
                    .transaction_info(v0::ProtStoreEnvironment::Production, bad)
                    .await,
                Err(StoreApiError::NotFound),
                "{bad:?}"
            );
        }
        assert!(fake.sent().is_empty());
    }

    #[tokio::test]
    async fn unconfigured_apple_store_sends_nothing() {
        let apple = ReqwestAppleStore::new(None);
        assert!(!apple.configured());
        assert_eq!(
            apple
                .transaction_info(v0::ProtStoreEnvironment::Production, TX)
                .await,
            Err(StoreApiError::NotConfigured)
        );
        assert_eq!(
            apple
                .notification_history(v0::ProtStoreEnvironment::Production, 1, 2, None)
                .await,
            Err(StoreApiError::NotConfigured)
        );
        assert_eq!(
            format!("{apple:?}"),
            "ReqwestAppleStore { configured: false }"
        );
    }

    #[test]
    fn unusable_keys_leave_the_client_unconfigured() {
        let fake = FakeSend::new();
        log_capture::take();

        // Not a PEM at all, through the public constructor (section 9.1's config)
        let apple = ReqwestAppleStore::new(Some(AppleStoreConfig {
            issuer_id: ISSUER_ID.to_string(),
            key_id: KEY_ID.to_string(),
            private_key: "not-a-pem-secret-material".to_string(),
            bundle_id: BUNDLE_ID.to_string(),
            app_apple_id: 6_809_989_506,
            environment: v0::ProtStoreEnvironment::Production,
            root_g3_sha256: [0; 32],
        }));
        assert!(!apple.configured());

        // A P-384 key parses as an EC PEM but cannot sign ES256
        let mut der = vec![
            0x30, 0x4e, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
            0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x37, 0x30, 0x35, 0x02,
            0x01, 0x01, 0x04, 0x30,
        ];
        der.extend_from_slice(&Sha384::digest(b"sloga-test-p384-key"));
        let p384 = pem("PRIVATE KEY", &der);
        let apple = ReqwestAppleStore::build(
            ISSUER_ID,
            KEY_ID,
            &p384,
            BUNDLE_ID,
            Box::new(fake.clone()),
            NOW_S,
        );
        assert!(!apple.configured());

        // Missing ids
        let apple = ReqwestAppleStore::build(
            "",
            KEY_ID,
            &test_key_pem(),
            BUNDLE_ID,
            Box::new(fake.clone()),
            NOW_S,
        );
        assert!(!apple.configured());

        let lines = log_capture::take();
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.starts_with("PROT_STORE_CONFIG_INVALID store=apple: "))
                .count(),
            3,
            "{lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("secret-material")),
            "{lines:?}"
        );
        assert!(fake.sent().is_empty());
    }

    #[test]
    fn apple_store_debug_redacts_the_key() {
        let fake = FakeSend::new();
        let apple = store_at(&fake, NOW_S);
        let jwt = apple.client.as_ref().unwrap().jwt(NOW_S).unwrap();
        let debug = format!("{apple:?}");
        assert!(debug.contains(ISSUER_ID), "{debug}");
        assert!(debug.contains(KEY_ID), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
        let key_body: String = test_key_pem()
            .lines()
            .nth(1)
            .unwrap()
            .chars()
            .take(24)
            .collect();
        assert!(!debug.contains(&key_body), "{debug}");
        let signature = jwt.rsplit('.').next().unwrap();
        assert!(!debug.contains(signature), "{debug}");
    }
}
