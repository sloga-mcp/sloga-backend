//! App Store and Google Play clients for in-app Prot (S6 contracts, section 11).
//!
//! - [`apple_jws`]: the Apple JWS verifier (section 10)
//! - [`apple_api`]: [`ReqwestAppleStore`], the App Store Server API (Get Transaction Info, Get
//!   Notification History) behind an ES256 JWT signed with the In-App Purchase key
//! - [`play_api`]: [`ReqwestPlayStore`], the Google Play Developer API (productsv2 purchase, consume,
//!   voided purchases) and the Pub/Sub pull of real-time developer notifications
//! - [`google_auth`]: the service account's OAuth2 JWT-bearer grant, its access token cached
//! - `mock` (tests and the `test-mock` feature): `MockAppleStore` and `MockPlayStore`
//!
//! The engine sees only [`AppleStoreApi`] and [`PlayStoreApi`]. Answers are returned as the stores
//! sent them (an Apple JWS is returned unverified; the caller runs [`apple_jws::verify_apple_jws`]).
//!
//! HTTP mapping (11.3): 404 → `NotFound`; 401/403 → `Rejected` (logged `PROT_STORE_API_AUTH`);
//! 408, 429, 5xx, timeouts and transport failures → `Transient`; any other non-2xx → `Rejected`; a
//! 2xx answer that does not decode → `Transient`. An id or token that no store could hold (empty,
//! only dots, a `/`, `\`, `?`, `#` or `%`, a non-graphic byte) is `NotFound` without a request.
//!
//! Secrets: the In-App Purchase key, the service-account key, App Store JWTs, OAuth access tokens
//! and Play purchase tokens never appear in an error, a log line or a `Debug` string. Logs name a
//! Play purchase `play:{sha256hex}` (its purchase id, section 4), never its token. Every log line
//! of this module goes through `store_log`.

use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use reqwest::{
    header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    Method, Url,
};
use revolt_models::v0;
use serde::{de::DeserializeOwned, Deserialize};
use sha2::{Digest, Sha256};

pub mod apple_api;
pub mod apple_jws;
pub mod google_auth;
#[cfg(any(test, feature = "test-mock"))]
pub mod mock;
pub mod play_api;

pub use apple_api::ReqwestAppleStore;
#[cfg(any(test, feature = "test-mock"))]
pub use mock::{MockAppleStore, MockPlayStore};
pub use play_api::ReqwestPlayStore;

/// Upper bound on one store call, connect to last byte (11.3)
pub const STORE_TIMEOUT: Duration = Duration::from_secs(10);

/// productsv2 `purchaseStateContext.purchaseState` values (W0 research, 11.3)
pub const PLAY_PURCHASE_STATE_PURCHASED: &str = "PURCHASED";
pub const PLAY_PURCHASE_STATE_CANCELLED: &str = "CANCELLED";
pub const PLAY_PURCHASE_STATE_PENDING: &str = "PENDING";
/// productsv2 `productOfferDetails.consumptionState` values (W0 research, 11.3)
pub const PLAY_CONSUMPTION_STATE_YET_TO_BE_CONSUMED: &str = "CONSUMPTION_STATE_YET_TO_BE_CONSUMED";
pub const PLAY_CONSUMPTION_STATE_CONSUMED: &str = "CONSUMPTION_STATE_CONSUMED";

/// Longest id, token or product id put in a store URL path
const MAX_SEGMENT_LEN: usize = 4096;

/// Why a store call failed (11.2; the engine maps it in section 9.4 step 2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreApiError {
    /// No usable credentials on this deployment; nothing was sent
    NotConfigured,
    /// The store has no such transaction or purchase (HTTP 404, or an id no store could hold)
    NotFound,
    /// Worth retrying: 408, 429, 5xx, a timeout or transport failure, an answer that does not
    /// decode. The text is a fixed description, never a URL or a response body.
    Transient(String),
    /// Refused: 401/403 (credentials) or any other non-2xx status
    Rejected { status: u16 },
}

impl fmt::Display for StoreApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreApiError::NotConfigured => write!(f, "store credentials are not configured"),
            StoreApiError::NotFound => write!(f, "not found at the store"),
            StoreApiError::Transient(message) => write!(f, "store call failed: {message}"),
            StoreApiError::Rejected { status } => {
                write!(f, "store refused the call: HTTP {status}")
            }
        }
    }
}

impl std::error::Error for StoreApiError {}

/// Decoded payload of an Apple transaction JWS (`JWSTransactionDecodedPayload`; 11.1). Unknown
/// fields are ignored. `Debug` redacts `app_account_token` (the intent token).
#[derive(Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppleTransaction {
    pub transaction_id: String,
    pub original_transaction_id: String,
    pub bundle_id: String,
    pub product_id: String,
    pub r#type: String,
    pub quantity: u32,
    pub purchase_date: i64,
    pub signed_date: i64,
    pub environment: String,
    pub app_account_token: Option<String>,
    pub storefront: Option<String>,
    pub revocation_date: Option<i64>,
    pub revocation_reason: Option<i64>,
}

/// Decoded payload of an App Store Server Notification V2 (`responseBodyV2DecodedPayload`; 11.1)
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppleNotification {
    pub notification_type: String,
    pub subtype: Option<String>,
    /// Apple spells it `notificationUUID`, which `camelCase` would not produce
    #[serde(rename = "notificationUUID")]
    pub notification_uuid: String,
    pub data: Option<AppleNotificationData>,
    pub signed_date: i64,
}

/// `data` of an [`AppleNotification`]. `Debug` redacts the transaction JWS.
#[derive(Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppleNotificationData {
    pub app_apple_id: Option<u64>,
    pub bundle_id: String,
    pub environment: String,
    pub signed_transaction_info: Option<String>,
}

/// A Play purchase (`purchases.productsv2` `ProductPurchaseV2`; 11.1). Unknown fields are ignored.
/// `Debug` redacts `obfuscated_external_account_id` (the intent token).
#[derive(Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlayPurchase {
    #[serde(default)]
    pub product_line_item: Vec<PlayLineItem>,
    pub purchase_state_context: PlayStateContext,
    /// Present only for a test purchase (R10)
    pub test_purchase_context: Option<serde_json::Value>,
    pub order_id: Option<String>,
    pub obfuscated_external_account_id: Option<String>,
    pub region_code: Option<String>,
    pub purchase_completion_time: Option<String>,
    pub acknowledgement_state: Option<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlayLineItem {
    pub product_id: String,
    #[serde(default)]
    pub product_offer_details: PlayOfferDetails,
}

#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlayOfferDetails {
    pub quantity: Option<u32>,
    pub refundable_quantity: Option<u32>,
    pub consumption_state: Option<String>,
}

impl PlayOfferDetails {
    /// The purchased quantity; absent → 1 (11.1)
    pub fn quantity_or_one(&self) -> u32 {
        self.quantity.unwrap_or(1)
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlayStateContext {
    pub purchase_state: String,
}

/// One page of Get Notification History. `Debug` prints the count, never a JWS.
#[derive(Clone, PartialEq, Eq)]
pub struct AppleHistoryPage {
    pub signed_payloads: Vec<String>,
    pub has_more: bool,
    pub pagination_token: Option<String>,
}

/// One voided Play purchase. `Debug` redacts the purchase token.
#[derive(Clone, PartialEq, Eq)]
pub struct PlayVoided {
    pub purchase_token: String,
    pub order_id: Option<String>,
    pub voided_time_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayVoidedPage {
    pub voided: Vec<PlayVoided>,
    pub next_page_token: Option<String>,
}

/// One pulled Pub/Sub message; `data` is the base64-decoded payload (an RTDN JSON, which carries a
/// purchase token). `Debug` prints its length only.
#[derive(Clone, PartialEq, Eq)]
pub struct PubSubMessage {
    pub ack_id: String,
    pub data: Vec<u8>,
    pub message_id: String,
}

#[async_trait]
pub trait AppleStoreApi: Send + Sync {
    fn configured(&self) -> bool;
    /// Get Transaction Info → its signedTransactionInfo JWS (unverified; the caller verifies it)
    async fn transaction_info(
        &self,
        env: v0::ProtStoreEnvironment,
        transaction_id: &str,
    ) -> Result<String, StoreApiError>;
    async fn notification_history(
        &self,
        env: v0::ProtStoreEnvironment,
        start_ms: i64,
        end_ms: i64,
        pagination_token: Option<&str>,
    ) -> Result<AppleHistoryPage, StoreApiError>;
}

#[async_trait]
pub trait PlayStoreApi: Send + Sync {
    fn configured(&self) -> bool;
    fn pubsub_configured(&self) -> bool;
    async fn product_purchase(&self, purchase_token: &str) -> Result<PlayPurchase, StoreApiError>;
    async fn consume(&self, product_id: &str, purchase_token: &str) -> Result<(), StoreApiError>;
    async fn voided_purchases(
        &self,
        start_ms: i64,
        page_token: Option<&str>,
    ) -> Result<PlayVoidedPage, StoreApiError>;
    async fn pull(&self, max_messages: u32) -> Result<Vec<PubSubMessage>, StoreApiError>;
    async fn acknowledge(&self, ack_ids: &[String]) -> Result<(), StoreApiError>;
}

const REDACTED: &str = "<redacted>";

/// `Some("<redacted>")` / `None`, so a `Debug` string still tells whether the field was set
fn redacted_option(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| REDACTED)
}

impl fmt::Debug for AppleTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let AppleTransaction {
            transaction_id,
            original_transaction_id,
            bundle_id,
            product_id,
            r#type,
            quantity,
            purchase_date,
            signed_date,
            environment,
            app_account_token,
            storefront,
            revocation_date,
            revocation_reason,
        } = self;
        f.debug_struct("AppleTransaction")
            .field("transaction_id", transaction_id)
            .field("original_transaction_id", original_transaction_id)
            .field("bundle_id", bundle_id)
            .field("product_id", product_id)
            .field("type", r#type)
            .field("quantity", quantity)
            .field("purchase_date", purchase_date)
            .field("signed_date", signed_date)
            .field("environment", environment)
            .field("app_account_token", &redacted_option(app_account_token))
            .field("storefront", storefront)
            .field("revocation_date", revocation_date)
            .field("revocation_reason", revocation_reason)
            .finish()
    }
}

impl fmt::Debug for AppleNotificationData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let AppleNotificationData {
            app_apple_id,
            bundle_id,
            environment,
            signed_transaction_info,
        } = self;
        f.debug_struct("AppleNotificationData")
            .field("app_apple_id", app_apple_id)
            .field("bundle_id", bundle_id)
            .field("environment", environment)
            .field(
                "signed_transaction_info",
                &redacted_option(signed_transaction_info),
            )
            .finish()
    }
}

impl fmt::Debug for PlayPurchase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let PlayPurchase {
            product_line_item,
            purchase_state_context,
            test_purchase_context,
            order_id,
            obfuscated_external_account_id,
            region_code,
            purchase_completion_time,
            acknowledgement_state,
        } = self;
        f.debug_struct("PlayPurchase")
            .field("product_line_item", product_line_item)
            .field("purchase_state_context", purchase_state_context)
            .field("test_purchase_context", test_purchase_context)
            .field("order_id", order_id)
            .field(
                "obfuscated_external_account_id",
                &redacted_option(obfuscated_external_account_id),
            )
            .field("region_code", region_code)
            .field("purchase_completion_time", purchase_completion_time)
            .field("acknowledgement_state", acknowledgement_state)
            .finish()
    }
}

impl fmt::Debug for AppleHistoryPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppleHistoryPage")
            .field("signed_payloads", &self.signed_payloads.len())
            .field("has_more", &self.has_more)
            .field("pagination_token", &self.pagination_token)
            .finish()
    }
}

impl fmt::Debug for PlayVoided {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlayVoided")
            .field("purchase_token", &REDACTED)
            .field("order_id", &self.order_id)
            .field("voided_time_ms", &self.voided_time_ms)
            .finish()
    }
}

impl fmt::Debug for PubSubMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PubSubMessage")
            .field("ack_id", &self.ack_id)
            .field("data_len", &self.data.len())
            .field("message_id", &self.message_id)
            .finish()
    }
}

// --- shared plumbing for the two clients -----------------------------------

/// One HTTP answer
pub(crate) struct HttpReply {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

/// Sends one request. The reqwest transport in production; a scripted one in tests.
#[async_trait]
pub(crate) trait HttpSend: Send + Sync {
    /// A transport failure is `Transient` with a fixed description (never reqwest's text, which
    /// can carry the URL and so a purchase token)
    async fn send(&self, request: reqwest::Request) -> Result<HttpReply, StoreApiError>;
}

/// [`HttpSend`] over HTTPS: the 10 s timeout, no redirects, https only (these clients carry
/// credentials and must never be walked to another scheme or host)
pub(crate) struct ReqwestSend {
    http: reqwest::Client,
}

impl ReqwestSend {
    /// `None` (logged) when the client cannot be built; the store client is then unconfigured
    pub(crate) fn new(store: &str) -> Option<Self> {
        match reqwest::Client::builder()
            .timeout(STORE_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()
        {
            Ok(http) => Some(ReqwestSend { http }),
            Err(_) => {
                store_log(
                    log::Level::Error,
                    &format!(
                        "PROT_STORE_CONFIG_INVALID store={store}: could not build the HTTP client"
                    ),
                );
                None
            }
        }
    }
}

#[async_trait]
impl HttpSend for ReqwestSend {
    async fn send(&self, request: reqwest::Request) -> Result<HttpReply, StoreApiError> {
        let response = self
            .http
            .execute(request)
            .await
            .map_err(|error| StoreApiError::Transient(transport_kind(&error).to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|error| StoreApiError::Transient(transport_kind(&error).to_string()))?;
        Ok(HttpReply {
            status,
            body: body.to_vec(),
        })
    }
}

/// `Transient` text of a client-side timeout (no response). Pub/Sub `:pull` reads it as an idle
/// subscription (R55).
pub(crate) const TIMED_OUT: &str = "request timed out";

/// A fixed description of a transport failure (the `stripe::client` rule: reqwest's own text can
/// carry the URL)
fn transport_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        TIMED_OUT
    } else if error.is_connect() {
        "could not connect"
    } else if error.is_builder() {
        "could not build the request"
    } else if error.is_redirect() {
        "unexpected redirect"
    } else if error.is_body() || error.is_decode() {
        "could not read the response"
    } else {
        "request failed"
    }
}

/// The error for a non-2xx status (11.3); `None` for 2xx
pub(crate) fn status_error(status: u16) -> Option<StoreApiError> {
    match status {
        200..=299 => None,
        404 => Some(StoreApiError::NotFound),
        408 | 429 | 500..=599 => Some(StoreApiError::Transient(format!("HTTP {status}"))),
        _ => Some(StoreApiError::Rejected { status }),
    }
}

/// Refuse a path input no store could hold (see the module doc): `NotFound`, nothing sent
pub(crate) fn check_segment(value: &str) -> Result<(), StoreApiError> {
    let well_formed = !value.is_empty()
        && value.len() <= MAX_SEGMENT_LEN
        && !value.bytes().all(|b| b == b'.')
        && value
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'/' | b'\\' | b'?' | b'#' | b'%'));
    if well_formed {
        Ok(())
    } else {
        Err(StoreApiError::NotFound)
    }
}

/// `base` + path segments, each percent-encoded by `url` (callers run [`check_segment`] first)
pub(crate) fn url_with_segments(base: &str, segments: &[&str]) -> Result<Url, StoreApiError> {
    let unbuildable = || StoreApiError::Transient("could not build the request".to_string());
    let mut url = Url::parse(base).map_err(|_| unbuildable())?;
    url.path_segments_mut()
        .map_err(|_| unbuildable())?
        .pop_if_empty()
        .extend(segments);
    Ok(url)
}

/// A request with the bearer credential (header marked sensitive) and an optional body with its
/// content type
pub(crate) fn build_request(
    method: Method,
    url: Url,
    bearer: &str,
    body: Option<(Vec<u8>, &'static str)>,
) -> Result<reqwest::Request, StoreApiError> {
    let mut authorization = HeaderValue::from_str(&format!("Bearer {bearer}"))
        .map_err(|_| StoreApiError::Transient("could not build the request".to_string()))?;
    authorization.set_sensitive(true);

    let mut request = reqwest::Request::new(method, url);
    let headers = request.headers_mut();
    headers.insert(AUTHORIZATION, authorization);
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    if let Some((bytes, content_type)) = body {
        if !content_type.is_empty() {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        *request.body_mut() = Some(bytes.into());
    }
    Ok(request)
}

/// Send `request` and map the status (11.3). `subject` names the object in log lines (an Apple
/// transaction id, a Play purchase id `play:{sha256hex}`), never a token.
pub(crate) async fn exchange(
    send: &dyn HttpSend,
    store: &str,
    op: &str,
    subject: Option<&str>,
    request: reqwest::Request,
) -> Result<Vec<u8>, StoreApiError> {
    let reply = match send.send(request).await {
        Ok(reply) => reply,
        Err(error) => {
            log_failure(store, op, subject, &error);
            return Err(error);
        }
    };
    map_reply(store, op, subject, reply)
}

/// Map an answer's status (11.3), logging a failure
pub(crate) fn map_reply(
    store: &str,
    op: &str,
    subject: Option<&str>,
    reply: HttpReply,
) -> Result<Vec<u8>, StoreApiError> {
    if let Some(error) = status_error(reply.status) {
        log_failure(store, op, subject, &error);
        return Err(error);
    }
    Ok(reply.body)
}

/// Decode a 2xx answer; a shape we do not know is `Transient` (logged without the body)
pub(crate) fn decode_json<T: DeserializeOwned>(
    store: &str,
    op: &str,
    body: &[u8],
) -> Result<T, StoreApiError> {
    serde_json::from_slice(body).map_err(|_| {
        let error = StoreApiError::Transient("unexpected response body".to_string());
        log_failure(store, op, None, &error);
        error
    })
}

/// One log line per failed call
pub(crate) fn log_failure(store: &str, op: &str, subject: Option<&str>, error: &StoreApiError) {
    let subject = subject.map(|s| format!(" {s}")).unwrap_or_default();
    match error {
        StoreApiError::Rejected {
            status: status @ (401 | 403),
        } => store_log(
            log::Level::Error,
            &format!("PROT_STORE_API_AUTH store={store} op={op}{subject} status={status}"),
        ),
        StoreApiError::Rejected { status } => store_log(
            log::Level::Warn,
            &format!("PROT_STORE_API store={store} op={op}{subject} rejected status={status}"),
        ),
        StoreApiError::Transient(message) => store_log(
            log::Level::Warn,
            &format!("PROT_STORE_API store={store} op={op}{subject} transient: {message}"),
        ),
        StoreApiError::NotFound => store_log(
            log::Level::Info,
            &format!("PROT_STORE_API store={store} op={op}{subject} not found"),
        ),
        StoreApiError::NotConfigured => store_log(
            log::Level::Debug,
            &format!("PROT_STORE_API store={store} op={op}{subject} not configured"),
        ),
    }
}

/// Every log line of the store clients. Tests read the lines of their own thread back.
pub(crate) fn store_log(level: log::Level, line: &str) {
    #[cfg(test)]
    log_capture::push(line);
    log::log!(level, "{line}");
}

#[cfg(test)]
pub(crate) mod log_capture {
    use std::cell::RefCell;

    thread_local! {
        static LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn push(line: &str) {
        LINES.with(|lines| lines.borrow_mut().push(line.to_string()));
    }

    /// Lines logged on this thread since the last call
    pub(crate) fn take() -> Vec<String> {
        LINES.with(|lines| std::mem::take(&mut *lines.borrow_mut()))
    }
}

/// Lowercase hex SHA-256 of `value`
pub(crate) fn sha256_hex(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The purchase id of a Play purchase token (`play:{sha256hex}`, section 4): what logs name
pub(crate) fn play_purchase_id(purchase_token: &str) -> String {
    format!("play:{}", sha256_hex(purchase_token))
}

pub(crate) fn environment_name(env: v0::ProtStoreEnvironment) -> &'static str {
    match env {
        v0::ProtStoreEnvironment::Production => "Production",
        v0::ProtStoreEnvironment::Sandbox => "Sandbox",
    }
}

/// Seconds since the Unix epoch (0 if the clock is before it)
pub(crate) fn unix_now_s() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A scripted [`HttpSend`]: answers the OAuth token endpoint itself and every other request
    //! from a queue, recording what was sent.

    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex, PoisonError},
    };

    use async_trait::async_trait;

    use super::{HttpReply, HttpSend, StoreApiError};

    /// What a request carried
    #[derive(Debug, Clone)]
    pub(crate) struct Sent {
        pub(crate) method: String,
        pub(crate) url: String,
        pub(crate) authorization: Option<String>,
        pub(crate) content_type: Option<String>,
        pub(crate) body: Option<Vec<u8>>,
        /// The request's own timeout (`None`: the client's 10 s)
        pub(crate) timeout: Option<std::time::Duration>,
    }

    #[derive(Default)]
    struct State {
        token_uri: Option<String>,
        token_reply: Option<(u16, String)>,
        replies: VecDeque<Result<(u16, String), StoreApiError>>,
        sent: Vec<Sent>,
    }

    #[derive(Clone, Default)]
    pub(crate) struct FakeSend(Arc<Mutex<State>>);

    impl FakeSend {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// Requests to `token_uri` are answered with (`status`, `body`), outside the queue
        pub(crate) fn token_endpoint(&self, token_uri: &str, status: u16, body: &str) {
            let mut state = self.state();
            state.token_uri = Some(token_uri.to_string());
            state.token_reply = Some((status, body.to_string()));
        }

        /// Queue the answer to the next (non-token) request
        pub(crate) fn reply(&self, status: u16, body: &str) {
            self.state()
                .replies
                .push_back(Ok((status, body.to_string())));
        }

        /// Queue a transport failure
        pub(crate) fn fail(&self, error: StoreApiError) {
            self.state().replies.push_back(Err(error));
        }

        /// Queue a client-side timeout (no response), as [`super::ReqwestSend`] reports it
        pub(crate) fn time_out(&self) {
            self.fail(StoreApiError::Transient(super::TIMED_OUT.to_string()));
        }

        pub(crate) fn sent(&self) -> Vec<Sent> {
            self.state().sent.clone()
        }

        fn state(&self) -> std::sync::MutexGuard<'_, State> {
            self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }

    #[async_trait]
    impl HttpSend for FakeSend {
        async fn send(&self, request: reqwest::Request) -> Result<HttpReply, StoreApiError> {
            let header = |name: reqwest::header::HeaderName| {
                request
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let sent = Sent {
                method: request.method().to_string(),
                url: request.url().to_string(),
                authorization: header(reqwest::header::AUTHORIZATION),
                content_type: header(reqwest::header::CONTENT_TYPE),
                body: request
                    .body()
                    .and_then(|b| b.as_bytes())
                    .map(<[u8]>::to_vec),
                timeout: request.timeout().copied(),
            };
            let mut state = self.state();
            let is_token = state.token_uri.as_deref() == Some(sent.url.as_str());
            state.sent.push(sent);
            let answer = if is_token {
                state.token_reply.clone().map(Ok)
            } else {
                state.replies.pop_front()
            };
            match answer {
                Some(Ok((status, body))) => Ok(HttpReply {
                    status,
                    body: body.into_bytes(),
                }),
                Some(Err(error)) => Err(error),
                None => Err(StoreApiError::Transient("no scripted reply".to_string())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A decoded StoreKit 2 transaction as Apple documents it (`JWSTransactionDecodedPayload`), with
    /// fields the engine does not read
    const APPLE_TRANSACTION_JSON: &str = r#"{
        "transactionId": "2000000812345678",
        "originalTransactionId": "2000000812345678",
        "bundleId": "gg.sloga.app",
        "productId": "gg.sloga.prot.p5",
        "purchaseDate": 1762000000000,
        "originalPurchaseDate": 1762000000000,
        "quantity": 1,
        "type": "Consumable",
        "appAccountToken": "6f1c2d3e-4a5b-4c6d-8e7f-001122334455",
        "inAppOwnershipType": "PURCHASED",
        "signedDate": 1762000000500,
        "environment": "Sandbox",
        "transactionReason": "PURCHASE",
        "storefront": "USA",
        "storefrontId": "143441",
        "price": 5990,
        "currency": "USD",
        "appTransactionId": "704512345678901234"
    }"#;

    /// A decoded ONE_TIME_CHARGE notification (`responseBodyV2DecodedPayload`)
    const APPLE_NOTIFICATION_JSON: &str = r#"{
        "notificationType": "ONE_TIME_CHARGE",
        "notificationUUID": "002e14d5-51f5-4503-b5a8-c3a1af68eb20",
        "data": {
            "appAppleId": 6809989506,
            "bundleId": "gg.sloga.app",
            "bundleVersion": "70",
            "environment": "Production",
            "signedTransactionInfo": "eyJhbGciOiJFUzI1NiJ9.e30.c2ln",
            "status": 1
        },
        "version": "2.0",
        "signedDate": 1762000001000
    }"#;

    /// `purchases.productsv2.getproductpurchasev2` answer for a test purchase
    const PLAY_PURCHASE_JSON: &str = r#"{
        "kind": "androidpublisher#productPurchaseV2",
        "productLineItem": [
            {
                "productId": "gg.sloga.prot.p10",
                "productOfferDetails": {
                    "offerTags": [],
                    "offerId": "",
                    "purchaseOptionId": "legacy-base",
                    "offerToken": "offer-token-1",
                    "quantity": 2,
                    "refundableQuantity": 2,
                    "consumptionState": "CONSUMPTION_STATE_YET_TO_BE_CONSUMED"
                }
            }
        ],
        "purchaseStateContext": { "purchaseState": "PURCHASED" },
        "testPurchaseContext": { "fopType": "TEST" },
        "orderId": "GPA.3312-4456-7890-12345",
        "obfuscatedExternalAccountId": "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5",
        "regionCode": "BR",
        "purchaseCompletionTime": "2026-11-01T12:00:00.123Z",
        "acknowledgementState": "ACKNOWLEDGEMENT_STATE_PENDING"
    }"#;

    #[test]
    fn apple_transaction_decodes_the_documented_payload() {
        let tx: AppleTransaction = serde_json::from_str(APPLE_TRANSACTION_JSON).unwrap();
        assert_eq!(tx.transaction_id, "2000000812345678");
        assert_eq!(tx.original_transaction_id, "2000000812345678");
        assert_eq!(tx.bundle_id, "gg.sloga.app");
        assert_eq!(tx.product_id, "gg.sloga.prot.p5");
        assert_eq!(tx.r#type, "Consumable");
        assert_eq!(tx.quantity, 1);
        assert_eq!(tx.purchase_date, 1_762_000_000_000);
        assert_eq!(tx.signed_date, 1_762_000_000_500);
        assert_eq!(tx.environment, "Sandbox");
        assert_eq!(
            tx.app_account_token.as_deref(),
            Some("6f1c2d3e-4a5b-4c6d-8e7f-001122334455")
        );
        assert_eq!(tx.storefront.as_deref(), Some("USA"));
        assert_eq!(tx.revocation_date, None);
        assert_eq!(tx.revocation_reason, None);
    }

    #[test]
    fn apple_transaction_reads_a_revocation() {
        let json = APPLE_TRANSACTION_JSON.replacen(
            "\"type\"",
            "\"revocationDate\": 1762100000000, \"revocationReason\": 1, \"type\"",
            1,
        );
        let tx: AppleTransaction = serde_json::from_str(&json).unwrap();
        assert_eq!(tx.revocation_date, Some(1_762_100_000_000));
        assert_eq!(tx.revocation_reason, Some(1));
    }

    #[test]
    fn apple_transaction_without_a_required_field_is_refused() {
        let json = APPLE_TRANSACTION_JSON.replacen("\"bundleId\": \"gg.sloga.app\",", "", 1);
        assert!(serde_json::from_str::<AppleTransaction>(&json).is_err());
    }

    #[test]
    fn apple_notification_reads_notification_uuid_as_apple_spells_it() {
        let n: AppleNotification = serde_json::from_str(APPLE_NOTIFICATION_JSON).unwrap();
        assert_eq!(n.notification_type, "ONE_TIME_CHARGE");
        assert_eq!(n.subtype, None);
        assert_eq!(n.notification_uuid, "002e14d5-51f5-4503-b5a8-c3a1af68eb20");
        assert_eq!(n.signed_date, 1_762_000_001_000);
        let data = n.data.unwrap();
        assert_eq!(data.app_apple_id, Some(6_809_989_506));
        assert_eq!(data.bundle_id, "gg.sloga.app");
        assert_eq!(data.environment, "Production");
        assert_eq!(
            data.signed_transaction_info.as_deref(),
            Some("eyJhbGciOiJFUzI1NiJ9.e30.c2ln")
        );

        // camelCase alone would look for `notificationUuid`
        let json = APPLE_NOTIFICATION_JSON.replace("notificationUUID", "notificationUuid");
        assert!(serde_json::from_str::<AppleNotification>(&json).is_err());
    }

    #[test]
    fn apple_summary_notification_has_no_data() {
        let n: AppleNotification = serde_json::from_str(
            r#"{"notificationType": "TEST", "notificationUUID": "u-1", "signedDate": 5,
                "summary": {"requestIdentifier": "r"}}"#,
        )
        .unwrap();
        assert_eq!(n.data, None);
    }

    #[test]
    fn play_purchase_decodes_the_documented_payload() {
        let p: PlayPurchase = serde_json::from_str(PLAY_PURCHASE_JSON).unwrap();
        assert_eq!(p.product_line_item.len(), 1);
        let item = &p.product_line_item[0];
        assert_eq!(item.product_id, "gg.sloga.prot.p10");
        assert_eq!(item.product_offer_details.quantity, Some(2));
        assert_eq!(item.product_offer_details.quantity_or_one(), 2);
        assert_eq!(item.product_offer_details.refundable_quantity, Some(2));
        assert_eq!(
            item.product_offer_details.consumption_state.as_deref(),
            Some(PLAY_CONSUMPTION_STATE_YET_TO_BE_CONSUMED)
        );
        assert_eq!(
            p.purchase_state_context.purchase_state,
            PLAY_PURCHASE_STATE_PURCHASED
        );
        assert_eq!(
            p.test_purchase_context,
            Some(serde_json::json!({"fopType": "TEST"}))
        );
        assert_eq!(p.order_id.as_deref(), Some("GPA.3312-4456-7890-12345"));
        assert_eq!(
            p.obfuscated_external_account_id.as_deref(),
            Some("Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5")
        );
        assert_eq!(p.region_code.as_deref(), Some("BR"));
        assert_eq!(
            p.purchase_completion_time.as_deref(),
            Some("2026-11-01T12:00:00.123Z")
        );
        assert_eq!(
            p.acknowledgement_state.as_deref(),
            Some("ACKNOWLEDGEMENT_STATE_PENDING")
        );
    }

    #[test]
    fn play_quantity_absent_is_one_and_production_has_no_test_context() {
        let p: PlayPurchase = serde_json::from_str(
            r#"{"productLineItem": [{"productId": "gg.sloga.prot.p5",
                    "productOfferDetails": {"consumptionState": "CONSUMPTION_STATE_CONSUMED"}},
                  {"productId": "gg.sloga.prot.p10"}],
                "purchaseStateContext": {"purchaseState": "PENDING"}}"#,
        )
        .unwrap();
        assert_eq!(p.product_line_item.len(), 2);
        assert_eq!(p.product_line_item[0].product_offer_details.quantity, None);
        assert_eq!(
            p.product_line_item[0]
                .product_offer_details
                .quantity_or_one(),
            1
        );
        assert_eq!(
            p.product_line_item[1].product_offer_details,
            PlayOfferDetails::default()
        );
        assert_eq!(p.test_purchase_context, None);
        assert_eq!(p.obfuscated_external_account_id, None);
        assert_eq!(
            p.purchase_state_context.purchase_state,
            PLAY_PURCHASE_STATE_PENDING
        );
    }

    #[test]
    fn play_purchase_without_line_items_decodes_to_none() {
        // The engine refuses `productLineItem.len() != 1`; a missing list must reach it as empty
        let p: PlayPurchase =
            serde_json::from_str(r#"{"purchaseStateContext": {"purchaseState": "CANCELLED"}}"#)
                .unwrap();
        assert!(p.product_line_item.is_empty());
        assert_eq!(
            p.purchase_state_context.purchase_state,
            PLAY_PURCHASE_STATE_CANCELLED
        );
    }

    #[test]
    fn status_mapping_follows_the_contract() {
        for status in [200, 201, 204] {
            assert_eq!(status_error(status), None, "{status}");
        }
        assert_eq!(status_error(404), Some(StoreApiError::NotFound));
        for status in [401, 403, 400, 409, 410, 422] {
            assert_eq!(
                status_error(status),
                Some(StoreApiError::Rejected { status }),
                "{status}"
            );
        }
        for status in [408, 429, 500, 502, 503, 504] {
            assert!(
                matches!(status_error(status), Some(StoreApiError::Transient(_))),
                "{status}"
            );
        }
    }

    #[tokio::test]
    async fn rate_limited_lookup_is_transient() {
        // Apple Get Transaction Info
        let fake = test_support::FakeSend::new();
        let apple = apple_api::tests_support::store(&fake);
        fake.reply(
            429,
            r#"{"errorCode": 4290000, "errorMessage": "Rate limit exceeded."}"#,
        );
        assert_eq!(
            apple
                .transaction_info(v0::ProtStoreEnvironment::Production, "2000000812345678")
                .await,
            Err(StoreApiError::Transient("HTTP 429".to_string()))
        );

        // Play productsv2
        let fake = test_support::FakeSend::new();
        let play = play_api::tests_support::store(&fake);
        fake.reply(
            429,
            r#"{"error": {"code": 429, "status": "RESOURCE_EXHAUSTED"}}"#,
        );
        assert_eq!(
            play.product_purchase("purchase-token-429").await,
            Err(StoreApiError::Transient("HTTP 429".to_string()))
        );
        assert_eq!(fake.sent().len(), 2, "token grant + the lookup");
    }

    #[test]
    fn path_inputs_no_store_could_hold_are_refused() {
        for bad in [
            "", ".", "..", "...", "a/b", "a\\b", "a?b", "a#b", "a%2Fb", "a b", "a\tb",
        ] {
            assert_eq!(check_segment(bad), Err(StoreApiError::NotFound), "{bad:?}");
        }
        assert_eq!(
            check_segment(&"a".repeat(MAX_SEGMENT_LEN + 1)),
            Err(StoreApiError::NotFound)
        );
        for good in [
            "2000000812345678",
            "gg.sloga.prot.p5",
            "aobdmhfbfjgmadpbhmhgfgel.AO-J1OzExampleToken_0123",
            "a.b",
        ] {
            assert_eq!(check_segment(good), Ok(()), "{good:?}");
        }
    }

    #[test]
    fn segments_are_percent_encoded_after_the_base_path() {
        let url = url_with_segments(
            "https://example.test/v3",
            &["applications", "gg.sloga.app", "tokens", "t:consume"],
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://example.test/v3/applications/gg.sloga.app/tokens/t:consume"
        );
        let url = url_with_segments("https://example.test", &["a", "b c"]).unwrap();
        assert_eq!(url.as_str(), "https://example.test/a/b%20c");
    }

    #[test]
    fn purchase_id_is_the_section_4_shape() {
        let id = play_purchase_id("token");
        assert_eq!(
            id,
            "play:3c469e9d6c5875d37a43f353d4f88e61fcf812c66eee3457465a40b0da4153e0"
        );
        assert_eq!(id.len(), 5 + 64);
    }

    #[test]
    fn payload_debug_redacts_tokens_and_jws() {
        let tx: AppleTransaction = serde_json::from_str(APPLE_TRANSACTION_JSON).unwrap();
        let debug = format!("{tx:?}");
        assert!(!debug.contains("6f1c2d3e"), "{debug}");
        assert!(debug.contains("2000000812345678"), "{debug}");

        let n: AppleNotification = serde_json::from_str(APPLE_NOTIFICATION_JSON).unwrap();
        let debug = format!("{n:?}");
        assert!(!debug.contains("eyJhbGciOiJFUzI1NiJ9"), "{debug}");
        assert!(debug.contains("ONE_TIME_CHARGE"), "{debug}");

        let p: PlayPurchase = serde_json::from_str(PLAY_PURCHASE_JSON).unwrap();
        let debug = format!("{p:?}");
        assert!(!debug.contains("Zm9vYmFy"), "{debug}");
        assert!(debug.contains("GPA.3312-4456-7890-12345"), "{debug}");

        let page = AppleHistoryPage {
            signed_payloads: vec!["eyJhbGciOiJFUzI1NiJ9.history.sig".to_string()],
            has_more: true,
            pagination_token: Some("page-2".to_string()),
        };
        let debug = format!("{page:?}");
        assert!(!debug.contains("eyJhbGciOiJFUzI1NiJ9"), "{debug}");

        let voided = PlayVoided {
            purchase_token: "voided-secret-token".to_string(),
            order_id: Some("GPA.1".to_string()),
            voided_time_ms: 7,
        };
        let debug = format!(
            "{:?}",
            PlayVoidedPage {
                voided: vec![voided],
                next_page_token: None
            }
        );
        assert!(!debug.contains("voided-secret-token"), "{debug}");
        assert!(debug.contains("GPA.1"), "{debug}");

        let message = PubSubMessage {
            ack_id: "ack-1".to_string(),
            data: br#"{"purchaseToken": "rtdn-secret-token"}"#.to_vec(),
            message_id: "m-1".to_string(),
        };
        let debug = format!("{message:?}");
        assert!(!debug.contains("rtdn-secret-token"), "{debug}");
    }

    #[test]
    fn errors_never_carry_more_than_a_fixed_text() {
        assert_eq!(
            StoreApiError::Rejected { status: 401 }.to_string(),
            "store refused the call: HTTP 401"
        );
        assert_eq!(
            StoreApiError::Transient("HTTP 503".to_string()).to_string(),
            "store call failed: HTTP 503"
        );
    }
}
