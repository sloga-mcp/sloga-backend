//! Stripe REST client
//!
//! [`StripeApi`] is the narrow slice of the Stripe API the payment engine
//! uses: create and read Checkout Sessions, read Payment Intents, Events and
//! Disputes, and refund. [`ReqwestStripe`] talks to `https://api.stripe.com/v1`;
//! `MockStripe` (tests and the `test-mock` feature) mirrors the parts of
//! Stripe's behavior the engine depends on, idempotency keys included.
//!
//! Secrets: the API key only ever travels in the `Authorization` header. It
//! is never put in an error, a log line or a `Debug` string, and request
//! bodies are never echoed either. Error text that Stripe sends back is
//! scrubbed of the key (and anything shaped like a key) before it is kept.
use std::{fmt, time::Duration};

use async_trait::async_trait;
use serde_json::Value;

use super::event::{
    event_from_value, obj_bool, obj_expandable_id, obj_i64, obj_metadata_order_id, obj_str,
    StripeEvent,
};

/// `Stripe-Version` sent with every request. `""` omits the header, so the
/// account's default API version applies. Set it once the version of the
/// webhook endpoint is known, so the REST and webhook shapes agree.
pub const STRIPE_API_VERSION: &str = "";

/// Base URL of the Stripe REST API
pub const STRIPE_API_BASE: &str = "https://api.stripe.com/v1";

/// Upper bound on one Stripe call, connect to last byte
pub const STRIPE_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest id or idempotency key accepted (Stripe's own limit is 255)
const MAX_ID_LEN: usize = 255;

/// Error text from Stripe is cut to this many characters
const MAX_ERROR_MESSAGE_CHARS: usize = 500;

/// Prefixes of Stripe secrets. Anything starting with one is redacted from
/// error text, even when it is not our key (or Stripe already masked it).
const SECRET_PREFIXES: [&str; 5] = ["sk_live_", "sk_test_", "rk_live_", "rk_test_", "whsec_"];

/// Why a Stripe call failed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StripeError {
    /// The request did not complete: no key configured, connect failure,
    /// timeout, unreadable response. The outcome on Stripe's side is
    /// unknown, so a mutating call must be retried with the same
    /// idempotency key.
    Transport(String),
    /// Stripe answered with a non-2xx status. `code` and `message` come from
    /// Stripe's `error` object (scrubbed and truncated).
    Api {
        status: u16,
        code: Option<String>,
        message: String,
    },
    /// The input or the response did not have the expected shape (a
    /// malformed id, invalid JSON, a missing required field)
    Decode(String),
}

impl fmt::Display for StripeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StripeError::Transport(message) => write!(f, "Stripe transport error: {message}"),
            StripeError::Api {
                status,
                code: Some(code),
                message,
            } => write!(f, "Stripe API error {status} ({code}): {message}"),
            StripeError::Api {
                status,
                code: None,
                message,
            } => write!(f, "Stripe API error {status}: {message}"),
            StripeError::Decode(message) => write!(f, "Stripe decode error: {message}"),
        }
    }
}

impl std::error::Error for StripeError {}

/// Inputs for one Checkout Session. Everything here is server-derived (the
/// stored order and the catalog), never taken from the client, so a retry
/// sends identical parameters under the same idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutSessionParams {
    /// Our order id (`metadata[order_id]`, also on the payment intent)
    pub order_id: String,
    /// Buyer (`client_reference_id`)
    pub user_id: String,
    /// Price in the smallest currency unit
    pub amount_cents: i64,
    /// ISO currency code, lowercase (`"usd"`)
    pub currency: String,
    /// Line item name shown on the Checkout page
    pub product_name: String,
    pub success_url: String,
    pub cancel_url: String,
    /// Session expiry, seconds since the Unix epoch
    pub expires_at_secs: i64,
}

/// A Checkout Session as Stripe reports it
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckoutSession {
    pub id: String,
    /// Hosted Checkout URL (`null` once the session is complete or expired)
    pub url: Option<String>,
    /// `open` | `complete` | `expired`
    pub status: Option<String>,
    /// `paid` | `unpaid` | `no_payment_required`
    pub payment_status: Option<String>,
    /// Payment intent id, once the session has one
    pub payment_intent: Option<String>,
    pub amount_total: Option<i64>,
    pub currency: Option<String>,
    pub livemode: bool,
    pub client_reference_id: Option<String>,
    /// `metadata.order_id`
    pub metadata_order_id: Option<String>,
    /// Seconds since the Unix epoch
    pub expires_at: Option<i64>,
}

/// A Payment Intent as Stripe reports it
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaymentIntent {
    pub id: String,
    pub livemode: bool,
    pub amount: Option<i64>,
    pub currency: Option<String>,
    pub status: Option<String>,
    /// `metadata.order_id`, copied from `payment_intent_data[metadata]`
    pub metadata_order_id: Option<String>,
}

/// A Refund as Stripe reports it
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refund {
    pub id: String,
    /// `pending` | `requires_action` | `succeeded` | `failed` | `canceled`
    pub status: Option<String>,
}

/// A Dispute as Stripe reports it
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dispute {
    pub id: String,
    /// `warning_needs_response` | `warning_under_review` | `warning_closed`
    /// | `needs_response` | `under_review` | `won` | `lost` | `prevented`
    pub status: Option<String>,
    /// Payment intent of the disputed charge
    pub payment_intent: Option<String>,
}

impl CheckoutSession {
    /// Map a Checkout Session JSON object (an API response, or `data.object`
    /// of a `checkout.session.*` event). Requires a well-formed `id` and a
    /// boolean `livemode`; everything else is optional and read only when
    /// it has the expected type.
    pub fn from_stripe_json(value: &Value) -> Result<Self, StripeError> {
        expect_object(value, "checkout.session")?;
        Ok(CheckoutSession {
            id: required_id(value)?,
            url: opt_string(value, "url"),
            status: opt_string(value, "status"),
            payment_status: opt_string(value, "payment_status"),
            payment_intent: obj_expandable_id(value, "payment_intent").map(str::to_string),
            amount_total: obj_i64(value, "amount_total"),
            currency: opt_string(value, "currency"),
            livemode: required_livemode(value)?,
            client_reference_id: opt_string(value, "client_reference_id"),
            metadata_order_id: obj_metadata_order_id(value),
            expires_at: obj_i64(value, "expires_at"),
        })
    }
}

impl PaymentIntent {
    /// Map a Payment Intent JSON object. Requires a well-formed `id` and a
    /// boolean `livemode`.
    pub fn from_stripe_json(value: &Value) -> Result<Self, StripeError> {
        expect_object(value, "payment_intent")?;
        Ok(PaymentIntent {
            id: required_id(value)?,
            livemode: required_livemode(value)?,
            amount: obj_i64(value, "amount"),
            currency: opt_string(value, "currency"),
            status: opt_string(value, "status"),
            metadata_order_id: obj_metadata_order_id(value),
        })
    }
}

impl Refund {
    /// Map a Refund JSON object. Requires a well-formed `id`.
    pub fn from_stripe_json(value: &Value) -> Result<Self, StripeError> {
        expect_object(value, "refund")?;
        Ok(Refund {
            id: required_id(value)?,
            status: opt_string(value, "status"),
        })
    }
}

impl Dispute {
    /// Map a Dispute JSON object. Requires a well-formed `id`.
    pub fn from_stripe_json(value: &Value) -> Result<Self, StripeError> {
        expect_object(value, "dispute")?;
        Ok(Dispute {
            id: required_id(value)?,
            status: opt_string(value, "status"),
            payment_intent: obj_expandable_id(value, "payment_intent").map(str::to_string),
        })
    }
}

/// The Stripe operations the payment engine uses
#[async_trait]
pub trait StripeApi: Send + Sync {
    /// `POST /v1/checkout/sessions`. Replaying the same idempotency key with
    /// the same parameters returns the original session.
    async fn create_checkout_session(
        &self,
        p: &CheckoutSessionParams,
        idempotency_key: &str,
    ) -> Result<CheckoutSession, StripeError>;

    /// `GET /v1/checkout/sessions/{id}`
    async fn get_checkout_session(&self, id: &str) -> Result<CheckoutSession, StripeError>;

    /// `GET /v1/payment_intents/{id}`
    async fn get_payment_intent(&self, id: &str) -> Result<PaymentIntent, StripeError>;

    /// `GET /v1/events/{id}` (re-drive; Stripe keeps events for 30 days)
    async fn get_event(&self, id: &str) -> Result<StripeEvent, StripeError>;

    /// `POST /v1/refunds` for the full amount of `payment_intent`
    async fn create_refund(
        &self,
        payment_intent: &str,
        idempotency_key: &str,
    ) -> Result<Refund, StripeError>;

    /// `GET /v1/disputes/{id}`: a dispute's current status, so dispute
    /// events delivered out of order converge on where the dispute is now
    async fn get_dispute(&self, id: &str) -> Result<Dispute, StripeError>;
}

/// Form body for `POST /v1/checkout/sessions`, in Stripe's bracket notation.
/// Card only: no delayed payment methods, so `checkout.session.completed`
/// with `payment_status=paid` is the single success signal.
pub fn checkout_form(p: &CheckoutSessionParams) -> Vec<(String, String)> {
    [
        ("mode", "payment".to_string()),
        ("payment_method_types[0]", "card".to_string()),
        ("line_items[0][quantity]", "1".to_string()),
        ("line_items[0][price_data][currency]", p.currency.clone()),
        (
            "line_items[0][price_data][unit_amount]",
            p.amount_cents.to_string(),
        ),
        (
            "line_items[0][price_data][product_data][name]",
            p.product_name.clone(),
        ),
        ("client_reference_id", p.user_id.clone()),
        ("metadata[order_id]", p.order_id.clone()),
        (
            "payment_intent_data[metadata][order_id]",
            p.order_id.clone(),
        ),
        ("success_url", p.success_url.clone()),
        ("cancel_url", p.cancel_url.clone()),
        ("expires_at", p.expires_at_secs.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value))
    .collect()
}

/// Whether `id` is safe to place in a request path: 1 to 255 characters,
/// ASCII letters, digits and `_` only. Every Stripe object id (`cs_...`,
/// `pi_...`, `evt_...`, `re_...`, `du_...`) has this shape. Anything else is refused rather
/// than percent-encoded, so no id can walk the path (`../`, `?`, `%2F`).
pub fn is_valid_stripe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// An idempotency key is 1 to 255 visible ASCII characters (it travels in
/// a header). An empty key is refused: a mutating call without one could
/// charge or refund twice on a retry.
fn is_valid_idempotency_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= MAX_ID_LEN && key.bytes().all(|b| b.is_ascii_graphic())
}

fn check_id(id: &str) -> Result<(), StripeError> {
    if is_valid_stripe_id(id) {
        Ok(())
    } else {
        Err(decode("bad id"))
    }
}

fn check_idempotency_key(key: &str) -> Result<(), StripeError> {
    if is_valid_idempotency_key(key) {
        Ok(())
    } else {
        Err(decode("bad idempotency key"))
    }
}

/// The `Stripe-Version` header value, if one should be sent
fn api_version_header(version: &str) -> Option<&str> {
    (!version.is_empty()).then_some(version)
}

fn decode(message: &str) -> StripeError {
    StripeError::Decode(message.to_string())
}

/// `value` must be a JSON object, and when it names its type (`object`),
/// that type must be `kind`
fn expect_object(value: &Value, kind: &str) -> Result<(), StripeError> {
    if !value.is_object() {
        return Err(decode("response is not a JSON object"));
    }
    match value.get("object") {
        None => Ok(()),
        Some(object) if object.as_str() == Some(kind) => Ok(()),
        Some(_) => Err(StripeError::Decode(format!("expected a {kind} object"))),
    }
}

fn required_id(value: &Value) -> Result<String, StripeError> {
    obj_str(value, "id")
        .filter(|id| is_valid_stripe_id(id))
        .map(str::to_string)
        .ok_or_else(|| decode("object has no valid id"))
}

fn required_livemode(value: &Value) -> Result<bool, StripeError> {
    obj_bool(value, "livemode").ok_or_else(|| decode("object has no livemode"))
}

fn opt_string(value: &Value, key: &str) -> Option<String> {
    obj_str(value, key).map(str::to_string)
}

/// Replace anything that starts like a Stripe secret, up to the end of the
/// token, with `[redacted]`
fn redact_key_like(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = SECRET_PREFIXES.iter().filter_map(|p| rest.find(*p)).min() {
        out.push_str(&rest[..start]);
        let token = &rest[start..];
        let end = token
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '*'))
            .unwrap_or(token.len());
        out.push_str("[redacted]");
        rest = &token[end..];
    }
    out.push_str(rest);
    out
}

/// Make Stripe-provided error text safe to keep: our key and key-shaped
/// tokens removed, control characters flattened, length capped
fn sanitize_message(text: &str, secret: &str) -> String {
    let text = if secret.is_empty() {
        text.to_string()
    } else {
        text.replace(secret, "[redacted]")
    };
    let text: String = redact_key_like(&text)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if text.chars().count() > MAX_ERROR_MESSAGE_CHARS {
        let mut cut: String = text.chars().take(MAX_ERROR_MESSAGE_CHARS).collect();
        cut.push_str("...");
        cut
    } else {
        text
    }
}

/// Map a non-2xx response to [`StripeError::Api`]. Stripe's error body is
/// `{"error": {"type", "code"?, "message"?, "param"?, ...}}`; when it is
/// missing or unreadable the message says so, without quoting the body.
fn api_error_from_body(status: u16, body: &[u8], secret: &str) -> StripeError {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let error = parsed.as_ref().and_then(|value| value.get("error"));

    let code = error
        .and_then(|e| obj_str(e, "code"))
        .filter(|code| !code.is_empty())
        .map(|code| sanitize_message(code, secret));

    let message = error
        .and_then(|e| obj_str(e, "message").or_else(|| obj_str(e, "type")))
        .filter(|message| !message.is_empty())
        .map(|message| sanitize_message(message, secret))
        .unwrap_or_else(|| format!("HTTP {status} without a Stripe error body"));

    StripeError::Api {
        status,
        code,
        message,
    }
}

/// A fixed description of a transport failure. `reqwest::Error`'s own text
/// is not used: it can carry the URL and the underlying cause verbatim.
fn transport_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "request timed out"
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

/// [`StripeApi`] over HTTPS with reqwest
pub struct ReqwestStripe {
    /// `None` when the client could not be built; every call then fails
    /// with [`StripeError::Transport`] instead of panicking or falling back
    /// to a client without the timeout
    http: Option<reqwest::Client>,
    secret_key: String,
}

impl fmt::Debug for ReqwestStripe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReqwestStripe")
            .field("secret_key", &"[redacted]")
            .field("key_configured", &!self.secret_key.is_empty())
            .field("http", &self.http.is_some())
            .finish()
    }
}

impl ReqwestStripe {
    /// A client for `secret_key`. An empty key is accepted here so startup
    /// never fails, but every call then fails closed without touching the
    /// network.
    pub fn new(secret_key: String) -> Self {
        // https only and no redirects: this client carries the API key and
        // must never be walked to another scheme or host
        let http = match reqwest::Client::builder()
            .timeout(STRIPE_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()
        {
            Ok(client) => Some(client),
            Err(_) => {
                log::error!("stripe: could not build the HTTP client; every Stripe call will fail");
                None
            }
        };

        ReqwestStripe { http, secret_key }
    }

    /// One request. `label` names the operation in logs and errors; ids,
    /// bodies and the key never appear there.
    async fn call(
        &self,
        label: &'static str,
        method: reqwest::Method,
        path: &str,
        form: Option<&[(String, String)]>,
        idempotency_key: Option<&str>,
    ) -> Result<Value, StripeError> {
        if self.secret_key.is_empty() {
            return Err(StripeError::Transport(
                "Stripe secret key is not configured".to_string(),
            ));
        }
        let Some(http) = self.http.as_ref() else {
            return Err(StripeError::Transport(
                "HTTP client unavailable".to_string(),
            ));
        };

        let mut request = http
            .request(method, format!("{STRIPE_API_BASE}{path}"))
            .bearer_auth(&self.secret_key);
        if let Some(version) = api_version_header(STRIPE_API_VERSION) {
            request = request.header("Stripe-Version", version);
        }
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        if let Some(form) = form {
            request = request.form(form);
        }

        let response = request.send().await.map_err(|error| {
            let kind = transport_kind(&error);
            log::warn!("stripe {label}: {kind}");
            StripeError::Transport(kind.to_string())
        })?;

        let status = response.status();
        let body = response.bytes().await.map_err(|error| {
            let kind = transport_kind(&error);
            log::warn!("stripe {label}: {kind}");
            StripeError::Transport(kind.to_string())
        })?;

        if !status.is_success() {
            let error = api_error_from_body(status.as_u16(), &body, &self.secret_key);
            if let StripeError::Api { status, code, .. } = &error {
                log::warn!("stripe {label}: HTTP {status}, code {code:?}");
            }
            return Err(error);
        }

        serde_json::from_slice(&body)
            .map_err(|_| StripeError::Decode(format!("{label}: response is not valid JSON")))
    }
}

/// A GET must answer for the object that was asked for
fn check_same_id(requested: &str, returned: &str) -> Result<(), StripeError> {
    if requested == returned {
        Ok(())
    } else {
        Err(decode("response is for a different id"))
    }
}

#[async_trait]
impl StripeApi for ReqwestStripe {
    async fn create_checkout_session(
        &self,
        p: &CheckoutSessionParams,
        idempotency_key: &str,
    ) -> Result<CheckoutSession, StripeError> {
        check_idempotency_key(idempotency_key)?;
        let form = checkout_form(p);
        let value = self
            .call(
                "create_checkout_session",
                reqwest::Method::POST,
                "/checkout/sessions",
                Some(form.as_slice()),
                Some(idempotency_key),
            )
            .await?;
        CheckoutSession::from_stripe_json(&value)
    }

    async fn get_checkout_session(&self, id: &str) -> Result<CheckoutSession, StripeError> {
        check_id(id)?;
        let value = self
            .call(
                "get_checkout_session",
                reqwest::Method::GET,
                &format!("/checkout/sessions/{id}"),
                None,
                None,
            )
            .await?;
        let session = CheckoutSession::from_stripe_json(&value)?;
        check_same_id(id, &session.id)?;
        Ok(session)
    }

    async fn get_payment_intent(&self, id: &str) -> Result<PaymentIntent, StripeError> {
        check_id(id)?;
        let value = self
            .call(
                "get_payment_intent",
                reqwest::Method::GET,
                &format!("/payment_intents/{id}"),
                None,
                None,
            )
            .await?;
        let intent = PaymentIntent::from_stripe_json(&value)?;
        check_same_id(id, &intent.id)?;
        Ok(intent)
    }

    async fn get_event(&self, id: &str) -> Result<StripeEvent, StripeError> {
        check_id(id)?;
        let value = self
            .call(
                "get_event",
                reqwest::Method::GET,
                &format!("/events/{id}"),
                None,
                None,
            )
            .await?;
        let event = event_from_value(&value)?;
        check_same_id(id, &event.id)?;
        Ok(event)
    }

    async fn create_refund(
        &self,
        payment_intent: &str,
        idempotency_key: &str,
    ) -> Result<Refund, StripeError> {
        check_id(payment_intent)?;
        check_idempotency_key(idempotency_key)?;
        let form = vec![("payment_intent".to_string(), payment_intent.to_string())];
        let value = self
            .call(
                "create_refund",
                reqwest::Method::POST,
                "/refunds",
                Some(form.as_slice()),
                Some(idempotency_key),
            )
            .await?;
        Refund::from_stripe_json(&value)
    }

    async fn get_dispute(&self, id: &str) -> Result<Dispute, StripeError> {
        check_id(id)?;
        let value = self
            .call(
                "get_dispute",
                reqwest::Method::GET,
                &format!("/disputes/{id}"),
                None,
                None,
            )
            .await?;
        let dispute = Dispute::from_stripe_json(&value)?;
        check_same_id(id, &dispute.id)?;
        Ok(dispute)
    }
}

#[cfg(any(test, feature = "test-mock"))]
pub use mock::MockStripe;

#[cfg(any(test, feature = "test-mock"))]
mod mock {
    use std::{
        collections::{HashMap, VecDeque},
        sync::{Mutex, MutexGuard, PoisonError},
    };

    use async_trait::async_trait;

    use super::{
        check_id, check_idempotency_key, checkout_form, CheckoutSession, CheckoutSessionParams,
        Dispute, PaymentIntent, Refund, StripeApi, StripeError, StripeEvent,
    };

    const CREATE_CHECKOUT_SESSION: &str = "create_checkout_session";
    const GET_CHECKOUT_SESSION: &str = "get_checkout_session";
    const GET_PAYMENT_INTENT: &str = "get_payment_intent";
    const GET_EVENT: &str = "get_event";
    const CREATE_REFUND: &str = "create_refund";
    const GET_DISPUTE: &str = "get_dispute";

    const METHODS: [&str; 6] = [
        CREATE_CHECKOUT_SESSION,
        GET_CHECKOUT_SESSION,
        GET_PAYMENT_INTENT,
        GET_EVENT,
        CREATE_REFUND,
        GET_DISPUTE,
    ];

    /// A scripted failure. `after_effect` means the call takes effect on
    /// "Stripe's side" and then reports the error, like a timeout after
    /// Stripe has already acted.
    #[derive(Debug)]
    struct Scripted {
        error: StripeError,
        after_effect: bool,
    }

    #[derive(Debug, Default)]
    struct State {
        livemode: bool,
        calls: Vec<(String, String, Option<String>)>,
        failures: HashMap<&'static str, VecDeque<Scripted>>,
        sessions: HashMap<String, CheckoutSession>,
        /// idempotency key -> (form sent, original response)
        checkout_keys: HashMap<String, (Vec<(String, String)>, CheckoutSession)>,
        checkout_params: Vec<CheckoutSessionParams>,
        next_session: u64,
        payment_intents: HashMap<String, PaymentIntent>,
        events: HashMap<String, StripeEvent>,
        /// Refunds that exist, as (payment intent, refund)
        refunds: Vec<(String, Refund)>,
        /// idempotency key -> (payment intent, refund)
        refund_keys: HashMap<String, (String, Refund)>,
        next_refund: u64,
        disputes: HashMap<String, Dispute>,
    }

    impl State {
        /// Record the call and take its next scripted failure, if any
        fn begin(
            &mut self,
            method: &'static str,
            detail: &str,
            idempotency_key: Option<&str>,
        ) -> Option<Scripted> {
            self.calls.push((
                method.to_string(),
                detail.to_string(),
                idempotency_key.map(str::to_string),
            ));
            self.failures.get_mut(method).and_then(VecDeque::pop_front)
        }
    }

    fn not_found(kind: &str, id: &str) -> StripeError {
        StripeError::Api {
            status: 404,
            code: Some("resource_missing".to_string()),
            message: format!("No such {kind}: '{id}'"),
        }
    }

    fn idempotency_error() -> StripeError {
        StripeError::Api {
            status: 400,
            code: Some("idempotency_error".to_string()),
            message: "Keys for idempotent requests can only be used with the same parameters \
                      they were first used with."
                .to_string(),
        }
    }

    /// Apply a scripted failure around `effect`: a plain failure stops the
    /// call before it does anything; an after-effect failure lets it run and
    /// then reports the error instead of its result
    fn finish<T>(
        scripted: Option<Scripted>,
        effect: impl FnOnce() -> Result<T, StripeError>,
    ) -> Result<T, StripeError> {
        match scripted {
            Some(Scripted {
                error,
                after_effect: false,
            }) => Err(error),
            Some(Scripted {
                error,
                after_effect: true,
            }) => {
                let _ = effect();
                Err(error)
            }
            None => effect(),
        }
    }

    /// In-memory [`StripeApi`] for tests.
    ///
    /// Mirrors the Stripe behavior the engine relies on:
    /// - `create_checkout_session` creates `cs_test_<n>` (url
    ///   `https://checkout.stripe.test/<n>`, `open` / `unpaid`, amount,
    ///   currency, `client_reference_id` and `metadata_order_id` from the
    ///   params). Replaying an idempotency key with the same params returns
    ///   the original response; with different params it is a 400
    ///   `idempotency_error`.
    /// - `create_refund` creates `re_test_<n>` (`succeeded`). Replaying a key
    ///   returns the same refund without creating another; refunding a
    ///   payment intent that already has a refund under a different key is a
    ///   400 `charge_already_refunded` (every refund here is a full refund).
    ///   Payment intents need not be registered to be refunded.
    /// - Gets of unknown ids are a 404 `resource_missing`; malformed ids and
    ///   keys fail exactly as they do on [`super::ReqwestStripe`].
    ///
    /// Every call is recorded as `(method, detail, idempotency key)`, where
    /// `detail` is the order id for `create_checkout_session`, the payment
    /// intent for `create_refund`, and the requested id otherwise.
    #[derive(Debug, Default)]
    pub struct MockStripe {
        state: Mutex<State>,
    }

    impl MockStripe {
        pub fn new() -> Self {
            Self::default()
        }

        fn state(&self) -> MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn script(&self, method: &str, error: StripeError, after_effect: bool) {
            let Some(method) = METHODS.iter().copied().find(|m| *m == method) else {
                panic!("MockStripe: unknown method {method:?}, expected one of {METHODS:?}");
            };
            self.state()
                .failures
                .entry(method)
                .or_default()
                .push_back(Scripted {
                    error,
                    after_effect,
                });
        }

        /// The next call to `method` fails with `error` and has no effect.
        /// Queued: call it twice to fail the next two calls. Panics on an
        /// unknown method name, so a typo cannot script nothing.
        pub fn fail_next(&self, method: &str, error: StripeError) {
            self.script(method, error, false);
        }

        /// The next call to `method` takes effect and then fails with
        /// `error` (a timeout after Stripe already acted)
        pub fn fail_next_after_effect(&self, method: &str, error: StripeError) {
            self.script(method, error, true);
        }

        /// `livemode` of sessions created from now on (default false)
        pub fn set_livemode(&self, livemode: bool) {
            self.state().livemode = livemode;
        }

        /// Insert or replace a session (e.g. mark one `complete` / `paid`
        /// with a payment intent). Responses already recorded under an
        /// idempotency key are not changed, as on Stripe.
        pub fn set_session(&self, session: CheckoutSession) {
            self.state().sessions.insert(session.id.clone(), session);
        }

        /// The current state of a session
        pub fn session(&self, id: &str) -> Option<CheckoutSession> {
            self.state().sessions.get(id).cloned()
        }

        /// Insert or replace a payment intent
        pub fn set_payment_intent(&self, intent: PaymentIntent) {
            self.state()
                .payment_intents
                .insert(intent.id.clone(), intent);
        }

        /// Insert or replace an event for `get_event`
        pub fn set_event(&self, event: StripeEvent) {
            self.state().events.insert(event.id.clone(), event);
        }

        /// Insert or replace a dispute (its current status) for
        /// `get_dispute`
        pub fn set_dispute(&self, dispute: Dispute) {
            self.state().disputes.insert(dispute.id.clone(), dispute);
        }

        /// Every call so far, in order: `(method, detail, idempotency key)`
        pub fn calls(&self) -> Vec<(String, String, Option<String>)> {
            self.state().calls.clone()
        }

        /// How many calls were made to `method`, failed ones included
        pub fn call_count(&self, method: &str) -> usize {
            self.state()
                .calls
                .iter()
                .filter(|(m, _, _)| m == method)
                .count()
        }

        /// Params of every session actually created, in order
        pub fn checkout_params(&self) -> Vec<CheckoutSessionParams> {
            self.state().checkout_params.clone()
        }

        /// Refunds that exist for `payment_intent` (idempotent replays and
        /// failed attempts do not count)
        pub fn refund_count_for(&self, payment_intent: &str) -> usize {
            self.state()
                .refunds
                .iter()
                .filter(|(pi, _)| pi == payment_intent)
                .count()
        }

        /// Refunds that exist, across all payment intents
        pub fn refund_count(&self) -> usize {
            self.state().refunds.len()
        }

        fn create_checkout_session_now(
            &self,
            p: &CheckoutSessionParams,
            idempotency_key: &str,
        ) -> Result<CheckoutSession, StripeError> {
            let mut state = self.state();
            let scripted = state.begin(CREATE_CHECKOUT_SESSION, &p.order_id, Some(idempotency_key));
            finish(scripted, || {
                check_idempotency_key(idempotency_key)?;
                let form = checkout_form(p);

                if let Some((sent, original)) = state.checkout_keys.get(idempotency_key) {
                    return if *sent == form {
                        Ok(original.clone())
                    } else {
                        Err(idempotency_error())
                    };
                }

                state.next_session += 1;
                let n = state.next_session;
                let session = CheckoutSession {
                    id: format!("cs_test_{n}"),
                    url: Some(format!("https://checkout.stripe.test/{n}")),
                    status: Some("open".to_string()),
                    payment_status: Some("unpaid".to_string()),
                    payment_intent: None,
                    amount_total: Some(p.amount_cents),
                    currency: Some(p.currency.clone()),
                    livemode: state.livemode,
                    client_reference_id: Some(p.user_id.clone()),
                    metadata_order_id: Some(p.order_id.clone()),
                    expires_at: Some(p.expires_at_secs),
                };
                state.sessions.insert(session.id.clone(), session.clone());
                state
                    .checkout_keys
                    .insert(idempotency_key.to_string(), (form, session.clone()));
                state.checkout_params.push(p.clone());
                Ok(session)
            })
        }

        fn get_checkout_session_now(&self, id: &str) -> Result<CheckoutSession, StripeError> {
            let mut state = self.state();
            let scripted = state.begin(GET_CHECKOUT_SESSION, id, None);
            finish(scripted, || {
                check_id(id)?;
                state
                    .sessions
                    .get(id)
                    .cloned()
                    .ok_or_else(|| not_found("checkout.session", id))
            })
        }

        fn get_payment_intent_now(&self, id: &str) -> Result<PaymentIntent, StripeError> {
            let mut state = self.state();
            let scripted = state.begin(GET_PAYMENT_INTENT, id, None);
            finish(scripted, || {
                check_id(id)?;
                state
                    .payment_intents
                    .get(id)
                    .cloned()
                    .ok_or_else(|| not_found("payment_intent", id))
            })
        }

        fn get_event_now(&self, id: &str) -> Result<StripeEvent, StripeError> {
            let mut state = self.state();
            let scripted = state.begin(GET_EVENT, id, None);
            finish(scripted, || {
                check_id(id)?;
                state
                    .events
                    .get(id)
                    .cloned()
                    .ok_or_else(|| not_found("event", id))
            })
        }

        fn create_refund_now(
            &self,
            payment_intent: &str,
            idempotency_key: &str,
        ) -> Result<Refund, StripeError> {
            let mut state = self.state();
            let scripted = state.begin(CREATE_REFUND, payment_intent, Some(idempotency_key));
            finish(scripted, || {
                check_id(payment_intent)?;
                check_idempotency_key(idempotency_key)?;

                if let Some((pi, refund)) = state.refund_keys.get(idempotency_key) {
                    return if pi == payment_intent {
                        Ok(refund.clone())
                    } else {
                        Err(idempotency_error())
                    };
                }

                if state.refunds.iter().any(|(pi, _)| pi == payment_intent) {
                    return Err(StripeError::Api {
                        status: 400,
                        code: Some("charge_already_refunded".to_string()),
                        message: format!(
                            "The charge for payment intent {payment_intent} has already been \
                             refunded."
                        ),
                    });
                }

                state.next_refund += 1;
                let refund = Refund {
                    id: format!("re_test_{}", state.next_refund),
                    status: Some("succeeded".to_string()),
                };
                state
                    .refunds
                    .push((payment_intent.to_string(), refund.clone()));
                state.refund_keys.insert(
                    idempotency_key.to_string(),
                    (payment_intent.to_string(), refund.clone()),
                );
                Ok(refund)
            })
        }

        fn get_dispute_now(&self, id: &str) -> Result<Dispute, StripeError> {
            let mut state = self.state();
            let scripted = state.begin(GET_DISPUTE, id, None);
            finish(scripted, || {
                check_id(id)?;
                state
                    .disputes
                    .get(id)
                    .cloned()
                    .ok_or_else(|| not_found("dispute", id))
            })
        }
    }

    // Each method does its work in a synchronous helper, so no lock guard
    // ever lives inside the (Send) future
    #[async_trait]
    impl StripeApi for MockStripe {
        async fn create_checkout_session(
            &self,
            p: &CheckoutSessionParams,
            idempotency_key: &str,
        ) -> Result<CheckoutSession, StripeError> {
            self.create_checkout_session_now(p, idempotency_key)
        }

        async fn get_checkout_session(&self, id: &str) -> Result<CheckoutSession, StripeError> {
            self.get_checkout_session_now(id)
        }

        async fn get_payment_intent(&self, id: &str) -> Result<PaymentIntent, StripeError> {
            self.get_payment_intent_now(id)
        }

        async fn get_event(&self, id: &str) -> Result<StripeEvent, StripeError> {
            self.get_event_now(id)
        }

        async fn create_refund(
            &self,
            payment_intent: &str,
            idempotency_key: &str,
        ) -> Result<Refund, StripeError> {
            self.create_refund_now(payment_intent, idempotency_key)
        }

        async fn get_dispute(&self, id: &str) -> Result<Dispute, StripeError> {
            self.get_dispute_now(id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> CheckoutSessionParams {
        CheckoutSessionParams {
            order_id: "01JA0000000000000000000ORD".to_string(),
            user_id: "01JA0000000000000000000USR".to_string(),
            amount_cents: 9900,
            currency: "usd".to_string(),
            product_name: "Cipher founding supporter ($99)".to_string(),
            success_url: "https://sloga.gg/cipher/thanks".to_string(),
            cancel_url: "https://sloga.gg/cipher".to_string(),
            expires_at_secs: 1_729_002_100,
        }
    }

    fn pairs(form: &[(String, String)]) -> Vec<(&str, &str)> {
        form.iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }

    #[test]
    fn checkout_form_has_exactly_the_contract_keys() {
        let form = checkout_form(&params());
        assert_eq!(
            pairs(&form),
            vec![
                ("mode", "payment"),
                ("payment_method_types[0]", "card"),
                ("line_items[0][quantity]", "1"),
                ("line_items[0][price_data][currency]", "usd"),
                ("line_items[0][price_data][unit_amount]", "9900"),
                (
                    "line_items[0][price_data][product_data][name]",
                    "Cipher founding supporter ($99)"
                ),
                ("client_reference_id", "01JA0000000000000000000USR"),
                ("metadata[order_id]", "01JA0000000000000000000ORD"),
                (
                    "payment_intent_data[metadata][order_id]",
                    "01JA0000000000000000000ORD"
                ),
                ("success_url", "https://sloga.gg/cipher/thanks"),
                ("cancel_url", "https://sloga.gg/cipher"),
                ("expires_at", "1729002100"),
            ]
        );
    }

    #[test]
    fn checkout_form_is_deterministic() {
        assert_eq!(checkout_form(&params()), checkout_form(&params()));
        let mut other = params();
        other.expires_at_secs += 1;
        assert_ne!(checkout_form(&params()), checkout_form(&other));
    }

    #[test]
    fn maps_a_stripe_error_body() {
        let body = br#"{
          "error": {
            "code": "resource_missing",
            "doc_url": "https://stripe.com/docs/error-codes/resource-missing",
            "message": "No such checkout.session: 'cs_test_missing'",
            "param": "session",
            "request_log_url": "https://dashboard.stripe.com/test/logs/req_x",
            "type": "invalid_request_error"
          }
        }"#;
        assert_eq!(
            api_error_from_body(404, body, "sk_test_abc123"),
            StripeError::Api {
                status: 404,
                code: Some("resource_missing".to_string()),
                message: "No such checkout.session: 'cs_test_missing'".to_string(),
            }
        );
    }

    #[test]
    fn maps_an_error_without_code_or_message() {
        let body = br#"{"error": {"type": "api_error"}}"#;
        assert_eq!(
            api_error_from_body(500, body, "sk_test_abc123"),
            StripeError::Api {
                status: 500,
                code: None,
                message: "api_error".to_string(),
            }
        );

        let html = b"<html><body>Bad Gateway sk_test_abc123</body></html>";
        match api_error_from_body(502, html, "sk_test_abc123") {
            StripeError::Api {
                status: 502,
                code: None,
                message,
            } => {
                assert_eq!(message, "HTTP 502 without a Stripe error body");
            }
            other => panic!("unexpected {other:?}"),
        }

        assert!(matches!(
            api_error_from_body(429, b"", ""),
            StripeError::Api {
                status: 429,
                code: None,
                ..
            }
        ));
    }

    #[test]
    fn error_text_never_carries_the_key() {
        // Built at runtime so the repo secret scanner does not flag a fake key.
        let secret = &format!("sk_{}_51AbCdEfGhIjKlMnOpQrStUv", "live");
        let body = format!(
            r#"{{"error": {{"type": "invalid_request_error", "code": "api_key_expired",
                "message": "Expired API Key provided: {secret}. Also rk_test_zzz9 and sk_test_****1234\n!"}}}}"#
        );
        let error = api_error_from_body(401, body.as_bytes(), secret);
        let text = format!("{error} {error:?}");
        assert!(!text.contains(secret));
        assert!(!text.contains("sk_live_"));
        assert!(!text.contains("rk_test_"));
        assert!(!text.contains("sk_test_"));
        assert!(!text.contains('\n'));
        match error {
            StripeError::Api { code, message, .. } => {
                assert_eq!(code.as_deref(), Some("api_key_expired"));
                assert_eq!(
                    message,
                    "Expired API Key provided: [redacted]. Also [redacted] and [redacted] !"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn long_error_text_is_capped() {
        let long = "x".repeat(5000);
        let message = sanitize_message(&long, "");
        assert_eq!(message.chars().count(), MAX_ERROR_MESSAGE_CHARS + 3);
        assert!(message.ends_with("..."));
        // multi-byte text is cut on a character boundary
        let wide = "\u{e9}".repeat(1000);
        assert_eq!(
            sanitize_message(&wide, "").chars().count(),
            MAX_ERROR_MESSAGE_CHARS + 3
        );
    }

    #[test]
    fn id_validation() {
        for good in [
            "cs_test_a1B2c3D4e5F6",
            "pi_3QAbCdEfGhIjKlMn0",
            "evt_1QAbCdEfGhIjKlMn",
            "re_1",
            "x",
        ] {
            assert!(is_valid_stripe_id(good), "{good}");
        }
        let too_long = "a".repeat(MAX_ID_LEN + 1);
        for bad in [
            "",
            "../events",
            "cs_test/1",
            "cs_test%2F1",
            "cs test",
            "cs_test?expand=x",
            "cs-test",
            "cs.test",
            "cs_t\u{e9}st",
            "cs_test\n",
            too_long.as_str(),
        ] {
            assert!(!is_valid_stripe_id(bad), "{bad:?}");
            assert_eq!(
                check_id(bad),
                Err(StripeError::Decode("bad id".to_string()))
            );
        }
        assert!(is_valid_stripe_id(&"a".repeat(MAX_ID_LEN)));
    }

    #[test]
    fn idempotency_key_validation() {
        assert!(is_valid_idempotency_key("01JA0000000000000000000ORD"));
        assert!(is_valid_idempotency_key("void-01JA0000000000000000000ORD"));
        assert!(!is_valid_idempotency_key(""));
        assert!(!is_valid_idempotency_key("has space"));
        assert!(!is_valid_idempotency_key("line\nbreak"));
        assert!(!is_valid_idempotency_key("\u{e9}"));
        assert!(!is_valid_idempotency_key(&"k".repeat(MAX_ID_LEN + 1)));
    }

    #[test]
    fn version_header_only_when_set() {
        assert_eq!(api_version_header(""), None);
        assert_eq!(api_version_header("2024-06-20"), Some("2024-06-20"));
    }

    #[test]
    fn debug_redacts_the_key() {
        let client = ReqwestStripe::new("sk_test_supersecret123".to_string());
        let text = format!("{client:?}");
        assert!(!text.contains("supersecret"), "{text}");
        assert!(text.contains("[redacted]"));
    }

    #[tokio::test]
    async fn reqwest_client_refuses_bad_input_before_the_network() {
        let client = ReqwestStripe::new("sk_test_supersecret123".to_string());
        let bad_id = StripeError::Decode("bad id".to_string());
        let bad_key = StripeError::Decode("bad idempotency key".to_string());
        assert_eq!(
            client.get_checkout_session("../events").await.unwrap_err(),
            bad_id
        );
        assert_eq!(
            client.get_payment_intent("pi_1/x").await.unwrap_err(),
            bad_id
        );
        assert_eq!(client.get_event("evt 1").await.unwrap_err(), bad_id);
        assert_eq!(client.get_dispute("du_1/../x").await.unwrap_err(), bad_id);
        assert_eq!(
            client.get_dispute("du_1?expand=x").await.unwrap_err(),
            bad_id
        );
        assert_eq!(
            client.create_refund("", "void-1").await.unwrap_err(),
            bad_id
        );
        assert_eq!(client.create_refund("pi_1", "").await.unwrap_err(), bad_key);
        assert_eq!(
            client
                .create_checkout_session(&params(), "")
                .await
                .unwrap_err(),
            bad_key
        );
    }

    #[tokio::test]
    async fn reqwest_client_without_a_key_fails_closed() {
        let client = ReqwestStripe::new(String::new());
        assert!(matches!(
            client.get_event("evt_1").await,
            Err(StripeError::Transport(_))
        ));
        assert!(matches!(
            client.create_refund("pi_1", "void-1").await,
            Err(StripeError::Transport(_))
        ));
        assert!(matches!(
            client.get_dispute("du_1").await,
            Err(StripeError::Transport(_))
        ));
    }

    #[test]
    fn maps_a_dispute_response() {
        let value = serde_json::json!({
            "id": "du_1QAbCdEfGhIjKlMn",
            "object": "dispute",
            "amount": 9900,
            "charge": "ch_3QAbCdEfGhIjKlMn0",
            "payment_intent": "pi_3QAbCdEfGhIjKlMn0",
            "reason": "fraudulent",
            "status": "lost",
            "livemode": false
        });
        assert_eq!(
            Dispute::from_stripe_json(&value).unwrap(),
            Dispute {
                id: "du_1QAbCdEfGhIjKlMn".to_string(),
                status: Some("lost".to_string()),
                payment_intent: Some("pi_3QAbCdEfGhIjKlMn0".to_string()),
            }
        );

        let expanded = serde_json::json!({
            "id": "du_2", "object": "dispute", "status": "won",
            "payment_intent": {"id": "pi_9", "object": "payment_intent"}
        });
        assert_eq!(
            Dispute::from_stripe_json(&expanded)
                .unwrap()
                .payment_intent
                .as_deref(),
            Some("pi_9")
        );

        // Another object type, or no usable id, is refused
        assert!(Dispute::from_stripe_json(
            &serde_json::json!({"id": "ch_1", "object": "charge", "status": "lost"})
        )
        .is_err());
        assert!(Dispute::from_stripe_json(&serde_json::json!({"status": "lost"})).is_err());
        assert!(
            Dispute::from_stripe_json(&serde_json::json!({"id": "du/1", "status": "lost"}))
                .is_err()
        );
    }

    #[tokio::test]
    async fn mock_disputes_report_what_the_test_set() {
        let stripe = MockStripe::new();
        assert!(matches!(
            stripe.get_dispute("du_1").await,
            Err(StripeError::Api { status: 404, code: Some(ref c), .. }) if c == "resource_missing"
        ));

        let dispute = Dispute {
            id: "du_1".to_string(),
            status: Some("under_review".to_string()),
            payment_intent: Some("pi_1".to_string()),
        };
        stripe.set_dispute(dispute.clone());
        assert_eq!(stripe.get_dispute("du_1").await.unwrap(), dispute);

        let timeout = StripeError::Transport("request timed out".to_string());
        stripe.fail_next("get_dispute", timeout.clone());
        assert_eq!(stripe.get_dispute("du_1").await, Err(timeout));
        assert_eq!(
            stripe.get_dispute("du/1").await,
            Err(StripeError::Decode("bad id".to_string()))
        );
        assert_eq!(stripe.call_count("get_dispute"), 4);
    }

    #[test]
    fn maps_a_checkout_session_response() {
        let value = serde_json::json!({
            "id": "cs_test_a1",
            "object": "checkout.session",
            "url": "https://checkout.stripe.com/c/pay/cs_test_a1",
            "status": "open",
            "payment_status": "unpaid",
            "payment_intent": null,
            "amount_total": 9900,
            "currency": "usd",
            "livemode": false,
            "client_reference_id": "user1",
            "metadata": {"order_id": "order1"},
            "expires_at": 1729002100
        });
        assert_eq!(
            CheckoutSession::from_stripe_json(&value).unwrap(),
            CheckoutSession {
                id: "cs_test_a1".to_string(),
                url: Some("https://checkout.stripe.com/c/pay/cs_test_a1".to_string()),
                status: Some("open".to_string()),
                payment_status: Some("unpaid".to_string()),
                payment_intent: None,
                amount_total: Some(9900),
                currency: Some("usd".to_string()),
                livemode: false,
                client_reference_id: Some("user1".to_string()),
                metadata_order_id: Some("order1".to_string()),
                expires_at: Some(1729002100),
            }
        );

        let expanded = serde_json::json!({
            "id": "cs_test_a1", "livemode": true,
            "payment_intent": {"id": "pi_1", "object": "payment_intent"},
            "amount_total": "9900"
        });
        let session = CheckoutSession::from_stripe_json(&expanded).unwrap();
        assert_eq!(session.payment_intent.as_deref(), Some("pi_1"));
        assert!(session.livemode);
        // a mistyped field is absent, never coerced
        assert_eq!(session.amount_total, None);
    }

    #[test]
    fn rejects_unusable_responses() {
        let is_decode =
            |r: Result<CheckoutSession, StripeError>| matches!(r, Err(StripeError::Decode(_)));
        assert!(is_decode(CheckoutSession::from_stripe_json(
            &serde_json::json!({"id": "pi_1", "object": "payment_intent", "livemode": false})
        )));
        assert!(is_decode(CheckoutSession::from_stripe_json(
            &serde_json::json!({"id": "cs_1"})
        )));
        assert!(is_decode(CheckoutSession::from_stripe_json(
            &serde_json::json!({"id": "cs/1", "livemode": false})
        )));
        assert!(is_decode(CheckoutSession::from_stripe_json(
            &serde_json::json!({"livemode": false})
        )));
        assert!(is_decode(CheckoutSession::from_stripe_json(
            &serde_json::json!([])
        )));
    }

    #[test]
    fn maps_payment_intent_and_refund_responses() {
        let intent = serde_json::json!({
            "id": "pi_3Q", "object": "payment_intent", "amount": 14900,
            "currency": "usd", "livemode": true, "status": "succeeded",
            "metadata": {"order_id": "order7"}
        });
        assert_eq!(
            PaymentIntent::from_stripe_json(&intent).unwrap(),
            PaymentIntent {
                id: "pi_3Q".to_string(),
                livemode: true,
                amount: Some(14900),
                currency: Some("usd".to_string()),
                status: Some("succeeded".to_string()),
                metadata_order_id: Some("order7".to_string()),
            }
        );
        assert!(PaymentIntent::from_stripe_json(&serde_json::json!({"id": "pi_3Q"})).is_err());

        let refund = serde_json::json!({
            "id": "re_3Q", "object": "refund", "amount": 9900,
            "payment_intent": "pi_3Q", "status": "pending"
        });
        assert_eq!(
            Refund::from_stripe_json(&refund).unwrap(),
            Refund {
                id: "re_3Q".to_string(),
                status: Some("pending".to_string()),
            }
        );
        assert!(Refund::from_stripe_json(&serde_json::json!({"object": "refund"})).is_err());
        assert!(
            Refund::from_stripe_json(&serde_json::json!({"id": "ch_1", "object": "charge"}))
                .is_err()
        );
    }

    #[tokio::test]
    async fn mock_creates_sessions_and_honors_idempotency_keys() {
        let stripe = MockStripe::new();
        let p = params();

        let first = stripe
            .create_checkout_session(&p, &p.order_id)
            .await
            .unwrap();
        assert_eq!(first.id, "cs_test_1");
        assert_eq!(first.url.as_deref(), Some("https://checkout.stripe.test/1"));
        assert_eq!(first.status.as_deref(), Some("open"));
        assert_eq!(first.payment_status.as_deref(), Some("unpaid"));
        assert_eq!(first.amount_total, Some(9900));
        assert_eq!(first.currency.as_deref(), Some("usd"));
        assert_eq!(
            first.client_reference_id.as_deref(),
            Some(p.user_id.as_str())
        );
        assert_eq!(
            first.metadata_order_id.as_deref(),
            Some(p.order_id.as_str())
        );
        assert_eq!(first.expires_at, Some(p.expires_at_secs));
        assert!(!first.livemode);

        // Same key, same params: the original session, nothing new created
        let replay = stripe
            .create_checkout_session(&p, &p.order_id)
            .await
            .unwrap();
        assert_eq!(replay, first);
        assert_eq!(stripe.checkout_params().len(), 1);

        // Same key, different params: rejected like Stripe does
        let mut changed = p.clone();
        changed.expires_at_secs += 60;
        assert!(matches!(
            stripe.create_checkout_session(&changed, &p.order_id).await,
            Err(StripeError::Api { status: 400, code: Some(ref c), .. }) if c == "idempotency_error"
        ));

        // A new key is a new session
        let second = stripe
            .create_checkout_session(&p, "other-key")
            .await
            .unwrap();
        assert_eq!(second.id, "cs_test_2");

        // The test can move a session along; gets see it
        let mut paid = first.clone();
        paid.status = Some("complete".to_string());
        paid.payment_status = Some("paid".to_string());
        paid.payment_intent = Some("pi_1".to_string());
        stripe.set_session(paid.clone());
        assert_eq!(
            stripe.get_checkout_session("cs_test_1").await.unwrap(),
            paid
        );

        let calls = stripe.calls();
        assert_eq!(calls.len(), 5);
        assert_eq!(
            calls[0],
            (
                "create_checkout_session".to_string(),
                p.order_id.clone(),
                Some(p.order_id.clone())
            )
        );
        assert_eq!(
            calls[4],
            (
                "get_checkout_session".to_string(),
                "cs_test_1".to_string(),
                None
            )
        );
        assert_eq!(stripe.call_count("create_checkout_session"), 4);
    }

    #[tokio::test]
    async fn mock_scripted_failures() {
        let stripe = MockStripe::new();
        let p = params();
        let timeout = StripeError::Transport("request timed out".to_string());

        // Before effect: nothing is created
        stripe.fail_next("create_checkout_session", timeout.clone());
        assert_eq!(
            stripe.create_checkout_session(&p, &p.order_id).await,
            Err(timeout.clone())
        );
        assert!(stripe.checkout_params().is_empty());
        let created = stripe
            .create_checkout_session(&p, &p.order_id)
            .await
            .unwrap();
        assert_eq!(created.id, "cs_test_1");

        // After effect: the refund exists although the call failed; the
        // retry with the same key returns it without a second refund
        stripe.fail_next_after_effect("create_refund", timeout.clone());
        assert_eq!(
            stripe.create_refund("pi_1", "void-order1").await,
            Err(timeout.clone())
        );
        assert_eq!(stripe.refund_count_for("pi_1"), 1);
        let refund = stripe.create_refund("pi_1", "void-order1").await.unwrap();
        assert_eq!(refund.id, "re_test_1");
        assert_eq!(stripe.refund_count_for("pi_1"), 1);

        // Queued failures are consumed in order
        stripe.fail_next("get_event", timeout.clone());
        stripe.fail_next("get_event", timeout.clone());
        assert_eq!(stripe.get_event("evt_1").await, Err(timeout.clone()));
        assert_eq!(stripe.get_event("evt_1").await, Err(timeout));
        assert!(matches!(
            stripe.get_event("evt_1").await,
            Err(StripeError::Api { status: 404, .. })
        ));
    }

    #[test]
    #[should_panic(expected = "unknown method")]
    fn mock_rejects_unknown_method_names() {
        MockStripe::new().fail_next("create_session", StripeError::Decode("x".to_string()));
    }

    #[tokio::test]
    async fn mock_refunds_and_lookups() {
        let stripe = MockStripe::new();

        let refund = stripe.create_refund("pi_1", "void-order1").await.unwrap();
        assert_eq!(refund.status.as_deref(), Some("succeeded"));
        // a second refund of the same intent under another key
        assert!(matches!(
            stripe.create_refund("pi_1", "dashboard").await,
            Err(StripeError::Api { status: 400, code: Some(ref c), .. }) if c == "charge_already_refunded"
        ));
        // a key reused for another intent
        assert!(matches!(
            stripe.create_refund("pi_2", "void-order1").await,
            Err(StripeError::Api { status: 400, code: Some(ref c), .. }) if c == "idempotency_error"
        ));
        assert_eq!(stripe.refund_count_for("pi_1"), 1);
        assert_eq!(stripe.refund_count_for("pi_2"), 0);
        assert_eq!(stripe.refund_count(), 1);
        assert_eq!(
            stripe.create_refund("pi/1", "k").await,
            Err(StripeError::Decode("bad id".to_string()))
        );

        assert!(matches!(
            stripe.get_payment_intent("pi_1").await,
            Err(StripeError::Api { status: 404, code: Some(ref c), .. }) if c == "resource_missing"
        ));
        let intent = PaymentIntent {
            id: "pi_1".to_string(),
            metadata_order_id: Some("order1".to_string()),
            ..Default::default()
        };
        stripe.set_payment_intent(intent.clone());
        assert_eq!(stripe.get_payment_intent("pi_1").await.unwrap(), intent);

        let event = StripeEvent {
            id: "evt_1".to_string(),
            event_type: "charge.refunded".to_string(),
            livemode: false,
            created: 1,
            object: serde_json::json!({"payment_intent": "pi_1"}),
        };
        stripe.set_event(event.clone());
        assert_eq!(stripe.get_event("evt_1").await.unwrap(), event);
        assert_eq!(
            stripe.get_checkout_session("../x").await,
            Err(StripeError::Decode("bad id".to_string()))
        );
    }
}
