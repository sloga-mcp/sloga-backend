//! Google service-account OAuth2 for the Play clients (S6 contracts 11.3): the JWT-bearer grant
//! (RFC 7523), no yup-oauth2.
//!
//! Assertion: header `{alg: RS256, typ: JWT}`, claims `{iss: client_email, scope: "<androidpublisher>
//! <pubsub>", aud: token_uri, iat, exp: iat + 3600}`, signed with the service-account key (PKCS#8 RSA
//! PEM). `POST token_uri`, form `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=..`
//! → `{access_token, expires_in}`. The access token is reused until `expires_in` − 300 s (~55 min)
//! and dropped on a 401 from the API.
//!
//! The token endpoint has no "not found": every refusal there (any non-2xx other than 408, 429 and
//! 5xx) is `Rejected` and logged `PROT_STORE_API_AUTH`, so a broken grant is never read as a missing
//! purchase.

use std::{
    fmt,
    sync::{Mutex, PoisonError},
};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{
    header::{HeaderValue, ACCEPT, CONTENT_TYPE},
    Method, Url,
};
use serde::{Deserialize, Serialize};

use super::{decode_json, log_failure, store_log, HttpSend, StoreApiError, REDACTED};

/// Both scopes the Play clients need, space-separated (11.3)
pub const GOOGLE_OAUTH_SCOPES: &str =
    "https://www.googleapis.com/auth/androidpublisher https://www.googleapis.com/auth/pubsub";
/// RFC 7523 grant type
pub const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Assertion lifetime (Google's maximum)
const ASSERTION_TTL_S: i64 = 3600;
/// A cached access token is replaced this long before it expires
const TOKEN_REFRESH_BEFORE_S: i64 = 300;

const STORE: &str = "play";
const OP: &str = "oauth_token";

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct AssertionClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: i64,
    exp: i64,
}

enum AssertionSigner {
    Rsa(EncodingKey),
    /// Tests: a fixed assertion (no RSA key is generated or committed)
    #[cfg(test)]
    Fixed(String),
}

struct CachedToken {
    access_token: String,
    issued_at: i64,
    fresh_until: i64,
}

#[derive(Deserialize)]
struct TokenAnswer {
    access_token: String,
    expires_in: Option<i64>,
}

/// The service account's access token. `Debug` redacts the key and the token.
pub struct GoogleAuth {
    client_email: String,
    token_uri: Url,
    signer: AssertionSigner,
    token: Mutex<Option<CachedToken>>,
}

impl fmt::Debug for GoogleAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let has_token = self
            .token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        f.debug_struct("GoogleAuth")
            .field("client_email", &self.client_email)
            .field("token_uri", &self.token_uri.as_str())
            .field("private_key", &REDACTED)
            .field("access_token", &if has_token { REDACTED } else { "<none>" })
            .finish()
    }
}

/// `application/x-www-form-urlencoded` value: everything but `A-Z a-z 0-9 - . _ ~` percent-encoded
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl GoogleAuth {
    /// `None` (logged `PROT_STORE_CONFIG_INVALID`) when `client_email` is empty, `token_uri` is
    /// not an https URL, or the key cannot sign RS256 (checked by signing a first assertion)
    pub fn new(client_email: &str, private_key: &str, token_uri: &str) -> Option<Self> {
        let refuse = |why: &str| -> Option<Self> {
            store_log(
                log::Level::Error,
                &format!("PROT_STORE_CONFIG_INVALID store=play: {why}"),
            );
            None
        };
        if client_email.is_empty() {
            return refuse("client_email must be set");
        }
        let Some(token_uri) = Url::parse(token_uri)
            .ok()
            .filter(|url| url.scheme() == "https" && url.host_str().is_some())
        else {
            return refuse("token_uri must be an https URL");
        };
        let Ok(key) = EncodingKey::from_rsa_pem(private_key.as_bytes()) else {
            return refuse("private_key is not an RSA PEM");
        };
        let auth = GoogleAuth {
            client_email: client_email.to_string(),
            token_uri,
            signer: AssertionSigner::Rsa(key),
            token: Mutex::new(None),
        };
        if auth.assertion(super::unix_now_s()).is_none() {
            return refuse("private_key cannot sign RS256");
        }
        Some(auth)
    }

    #[cfg(test)]
    pub(crate) fn with_fixed_assertion(
        client_email: &str,
        token_uri: &str,
        assertion: &str,
    ) -> Self {
        GoogleAuth {
            client_email: client_email.to_string(),
            token_uri: Url::parse(token_uri).expect("test token_uri"),
            signer: AssertionSigner::Fixed(assertion.to_string()),
            token: Mutex::new(None),
        }
    }

    fn claims(&self, iat: i64) -> AssertionClaims {
        AssertionClaims {
            iss: self.client_email.clone(),
            scope: GOOGLE_OAUTH_SCOPES.to_string(),
            aud: self.token_uri.as_str().to_string(),
            iat,
            exp: iat + ASSERTION_TTL_S,
        }
    }

    /// `None` when the key cannot sign
    fn assertion(&self, now_s: i64) -> Option<String> {
        match &self.signer {
            AssertionSigner::Rsa(key) => {
                jsonwebtoken::encode(&Header::new(Algorithm::RS256), &self.claims(now_s), key).ok()
            }
            #[cfg(test)]
            AssertionSigner::Fixed(assertion) => Some(assertion.clone()),
        }
    }

    fn token_request(&self, assertion: &str) -> reqwest::Request {
        let body = format!(
            "grant_type={}&assertion={}",
            form_encode(JWT_BEARER_GRANT_TYPE),
            form_encode(assertion)
        );
        let mut request = reqwest::Request::new(Method::POST, self.token_uri.clone());
        let headers = request.headers_mut();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        *request.body_mut() = Some(body.into_bytes().into());
        request
    }

    fn cached(&self, now_s: i64) -> Option<String> {
        let cached = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        cached
            .as_ref()
            .filter(|entry| (entry.issued_at..entry.fresh_until).contains(&now_s))
            .map(|entry| entry.access_token.clone())
    }

    /// Drop the cached token (the API answered 401)
    pub(crate) fn forget(&self) {
        *self.token.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// The cached access token, or a new one from the token endpoint
    pub(crate) async fn access_token(
        &self,
        send: &dyn HttpSend,
        now_s: i64,
    ) -> Result<String, StoreApiError> {
        if let Some(token) = self.cached(now_s) {
            return Ok(token);
        }
        let Some(assertion) = self.assertion(now_s) else {
            store_log(
                log::Level::Error,
                "PROT_STORE_CONFIG_INVALID store=play: could not sign the OAuth assertion",
            );
            return Err(StoreApiError::NotConfigured);
        };

        let reply = match send.send(self.token_request(&assertion)).await {
            Ok(reply) => reply,
            Err(error) => {
                log_failure(STORE, OP, None, &error);
                return Err(error);
            }
        };
        match reply.status {
            200..=299 => {}
            408 | 429 | 500..=599 => {
                let error = StoreApiError::Transient(format!("HTTP {}", reply.status));
                log_failure(STORE, OP, None, &error);
                return Err(error);
            }
            status => {
                store_log(
                    log::Level::Error,
                    &format!("PROT_STORE_API_AUTH store={STORE} op={OP} status={status}"),
                );
                return Err(StoreApiError::Rejected { status });
            }
        }

        let answer: TokenAnswer = decode_json(STORE, OP, &reply.body)?;
        if answer.access_token.is_empty() {
            let error = StoreApiError::Transient("unexpected response body".to_string());
            log_failure(STORE, OP, None, &error);
            return Err(error);
        }
        // Cached only when it lives longer than the refresh margin
        if let Some(expires_in) = answer
            .expires_in
            .filter(|seconds| *seconds > TOKEN_REFRESH_BEFORE_S)
        {
            *self.token.lock().unwrap_or_else(PoisonError::into_inner) = Some(CachedToken {
                access_token: answer.access_token.clone(),
                issued_at: now_s,
                fresh_until: now_s + expires_in - TOKEN_REFRESH_BEFORE_S,
            });
        }
        Ok(answer.access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        apple_api::tests_support::test_key_pem, log_capture, test_support::FakeSend,
    };

    const NOW_S: i64 = 1_762_000_000;
    const EMAIL: &str = "play-api@sloga-test.iam.gserviceaccount.com";
    const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
    const ACCESS_TOKEN: &str = "ya29.secret-access-token";

    fn auth() -> GoogleAuth {
        GoogleAuth::with_fixed_assertion(EMAIL, TOKEN_URI, "assertion.header.sig")
    }

    fn token_body(expires_in: Option<i64>) -> String {
        match expires_in {
            Some(seconds) => format!(
                r#"{{"access_token": "{ACCESS_TOKEN}", "expires_in": {seconds}, "token_type": "Bearer"}}"#
            ),
            None => format!(r#"{{"access_token": "{ACCESS_TOKEN}", "token_type": "Bearer"}}"#),
        }
    }

    #[test]
    fn assertion_claims_are_pinned() {
        assert_eq!(
            auth().claims(NOW_S),
            AssertionClaims {
                iss: EMAIL.to_string(),
                scope: "https://www.googleapis.com/auth/androidpublisher https://www.googleapis.com/auth/pubsub"
                    .to_string(),
                aud: TOKEN_URI.to_string(),
                iat: NOW_S,
                exp: NOW_S + 3600,
            }
        );
        assert_eq!(Header::new(Algorithm::RS256).typ.as_deref(), Some("JWT"));
    }

    #[test]
    fn token_request_is_the_jwt_bearer_form() {
        let request = auth().token_request("aaa.bbb_-.ccc");
        assert_eq!(request.method(), &Method::POST);
        assert_eq!(request.url().as_str(), TOKEN_URI);
        assert_eq!(
            request.headers().get(CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded"
        );
        assert!(request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .is_none());
        assert_eq!(
            request.body().and_then(|b| b.as_bytes()).unwrap(),
            b"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=aaa.bbb_-.ccc"
        );
        assert_eq!(form_encode("a+b/c= d"), "a%2Bb%2Fc%3D%20d");
    }

    #[tokio::test]
    async fn access_token_is_cached_until_five_minutes_before_expiry() {
        let fake = FakeSend::new();
        fake.token_endpoint(TOKEN_URI, 200, &token_body(Some(3599)));
        let auth = auth();

        assert_eq!(auth.access_token(&fake, NOW_S).await.unwrap(), ACCESS_TOKEN);
        assert_eq!(fake.sent().len(), 1);
        assert_eq!(fake.sent()[0].method, "POST");
        assert_eq!(fake.sent()[0].url, TOKEN_URI);
        assert_eq!(
            fake.sent()[0].content_type.as_deref(),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(fake.sent()[0].authorization, None);

        auth.access_token(&fake, NOW_S + 3298).await.unwrap();
        assert_eq!(fake.sent().len(), 1, "cached");
        auth.access_token(&fake, NOW_S + 3299).await.unwrap();
        assert_eq!(fake.sent().len(), 2, "renewed 5 minutes before expiry");

        auth.forget();
        auth.access_token(&fake, NOW_S + 3300).await.unwrap();
        assert_eq!(fake.sent().len(), 3, "a forgotten token is fetched again");
    }

    #[tokio::test]
    async fn short_lived_or_undated_tokens_are_not_cached() {
        for expires_in in [None, Some(300), Some(0)] {
            let fake = FakeSend::new();
            fake.token_endpoint(TOKEN_URI, 200, &token_body(expires_in));
            let auth = auth();
            auth.access_token(&fake, NOW_S).await.unwrap();
            auth.access_token(&fake, NOW_S).await.unwrap();
            assert_eq!(fake.sent().len(), 2, "{expires_in:?}");
        }
    }

    #[tokio::test]
    async fn token_endpoint_failures_never_read_as_not_found() {
        log_capture::take();
        for (status, expected) in [
            (400, StoreApiError::Rejected { status: 400 }),
            (401, StoreApiError::Rejected { status: 401 }),
            (404, StoreApiError::Rejected { status: 404 }),
            (429, StoreApiError::Transient("HTTP 429".to_string())),
            (503, StoreApiError::Transient("HTTP 503".to_string())),
        ] {
            let fake = FakeSend::new();
            fake.token_endpoint(TOKEN_URI, status, r#"{"error": "invalid_grant"}"#);
            assert_eq!(
                auth().access_token(&fake, NOW_S).await,
                Err(expected),
                "{status}"
            );
        }
        for body in [
            "{}",
            r#"{"access_token": "", "expires_in": 3599}"#,
            "<html>",
        ] {
            let fake = FakeSend::new();
            fake.token_endpoint(TOKEN_URI, 200, body);
            assert_eq!(
                auth().access_token(&fake, NOW_S).await,
                Err(StoreApiError::Transient(
                    "unexpected response body".to_string()
                )),
                "{body}"
            );
        }
        let lines = log_capture::take();
        for status in [400, 401, 404] {
            let line = format!("PROT_STORE_API_AUTH store=play op=oauth_token status={status}");
            assert!(lines.contains(&line), "{lines:?}");
        }
        assert!(
            !lines.iter().any(|l| l.contains("assertion.header.sig")),
            "{lines:?}"
        );
    }

    #[test]
    fn unusable_service_accounts_are_refused() {
        log_capture::take();
        assert!(GoogleAuth::new("", "pem", TOKEN_URI).is_none());
        assert!(GoogleAuth::new(EMAIL, "not-a-pem-secret-material", TOKEN_URI).is_none());
        // An EC key is not an RSA key
        assert!(GoogleAuth::new(EMAIL, &test_key_pem(), TOKEN_URI).is_none());
        assert!(GoogleAuth::new(EMAIL, "pem", "http://oauth2.googleapis.com/token").is_none());
        assert!(GoogleAuth::new(EMAIL, "pem", "not a url").is_none());
        let lines = log_capture::take();
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.starts_with("PROT_STORE_CONFIG_INVALID store=play: "))
                .count(),
            5,
            "{lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("secret-material")),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn google_auth_debug_redacts_the_token() {
        let fake = FakeSend::new();
        fake.token_endpoint(TOKEN_URI, 200, &token_body(Some(3599)));
        let auth = auth();
        assert!(format!("{auth:?}").contains("access_token: \"<none>\""));
        auth.access_token(&fake, NOW_S).await.unwrap();
        let debug = format!("{auth:?}");
        assert!(!debug.contains(ACCESS_TOKEN), "{debug}");
        assert!(debug.contains("private_key: \"<redacted>\""), "{debug}");
        assert!(debug.contains(EMAIL), "{debug}");
    }
}
