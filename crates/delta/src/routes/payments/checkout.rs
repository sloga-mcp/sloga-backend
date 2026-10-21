use std::sync::Arc;

use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_payments::engine;
use revolt_payments::settings::PaymentsSettings;
use revolt_payments::stripe::StripeApi;
use revolt_result::{create_error, Result};
use revolt_rocket_okapi::gen::OpenApiGenerator;
use revolt_rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};
use rocket::request::{FromRequest, Outcome};
use rocket::serde::json::Json;
use rocket::{Request, State};

use crate::util::polls::now_ms;

/// Header Cloudflare sets to the country it places the client in
const CF_IP_COUNTRY: &str = "CF-IPCountry";

/// The caller's country as Cloudflare reports it (`CF-IPCountry`), read
/// only when `[api.security] trust_cloudflare` is on: the same rule as the
/// client IP (`revolt_database::util::ip`), because without Cloudflare in
/// front any client could send the header. `None` when not trusted, absent,
/// or not a two-character code.
pub struct RequestCountry(pub Option<String>);

#[async_trait]
impl<'r> FromRequest<'r> for RequestCountry {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let trust = revolt_config::config().await.api.security.trust_cloudflare;
        Outcome::Success(Self(request_country(
            trust,
            request.headers().get_one(CF_IP_COUNTRY),
        )))
    }
}

/// Set by Cloudflare, not the client: nothing to document
impl OpenApiFromRequest<'_> for RequestCountry {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> revolt_rocket_okapi::Result<RequestHeaderInput> {
        Ok(RequestHeaderInput::None)
    }
}

/// [`RequestCountry`] from the trust switch and the raw header, uppercased.
/// Cloudflare sends `XX` (unknown) and `T1` (Tor) as well; neither is ever
/// in the blocked list, so they pass, and fulfilment checks the billing
/// country anyway.
fn request_country(trust_cloudflare: bool, header: Option<&str>) -> Option<String> {
    if !trust_cloudflare {
        return None;
    }
    header
        .filter(|code| code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(str::to_ascii_uppercase)
}

/// Refuse a checkout from a country Cipher is not sold to
/// (`cipher_blocked_countries`). An unknown country passes: fulfilment
/// voids and refunds a payment billed to a blocked one.
fn refuse_blocked_region(settings: &PaymentsSettings, country: Option<&str>) -> Result<()> {
    match country {
        Some(country) if settings.region_blocked(country) => {
            Err(create_error!(CipherRegionUnavailable))
        }
        _ => Ok(()),
    }
}

/// # Start Cipher Checkout
///
/// Create (or reuse) a Stripe Checkout session for a Cipher tier and return
/// the hosted page to send the user to. Prices and upgrades are quoted by the
/// server; the body only names the tier wanted. Bots cannot buy. Refused
/// with `CipherRegionUnavailable` from a country Cipher is not sold to.
#[openapi(tag = "Payments")]
#[post("/cipher/checkout", data = "<data>")]
pub async fn checkout(
    db: &State<Database>,
    stripe: &State<Arc<dyn StripeApi>>,
    user: User,
    country: RequestCountry,
    data: Json<v0::DataCipherCheckout>,
) -> Result<Json<v0::CipherCheckoutResponse>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // A config that fails validation (bad close date, cap out of range, a
    // malformed blocked country) refuses the request rather than selling
    // under a default
    let settings = PaymentsSettings::load().await?;
    refuse_blocked_region(&settings, country.0.as_deref())?;
    let data = data.into_inner();

    // The engine owns every other gate: payments enabled, sale open, the
    // quote (new or upgrade, never a downgrade), no upgrade while disputed,
    // and one live Pending order per user (an unexpired one returns its URL)
    let stripe: &dyn StripeApi = &**stripe.inner();
    let url = engine::create_cipher_checkout(
        db,
        stripe,
        &settings,
        &user.id,
        data.tier,
        data.return_to,
        now_ms(),
    )
    .await?;

    Ok(Json(v0::CipherCheckoutResponse { url }))
}

#[cfg(test)]
mod test {
    use revolt_database::{Bot, Database, OrderState};
    use revolt_models::v0::{CipherReturnTo, CipherTier};
    use revolt_payments::engine;
    use revolt_payments::settings::PaymentsSettings;
    use revolt_payments::stripe::StripeError;
    use revolt_result::ErrorType;
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::LocalResponse;
    use serde_json::json;

    use crate::util::polls::now_ms;
    use crate::util::test::TestHarness;

    const CREATE_SESSION: &str = "create_checkout_session";

    const ALL_STATES: [OrderState; 8] = [
        OrderState::Creating,
        OrderState::Pending,
        OrderState::SessionFailed,
        OrderState::Paid,
        OrderState::Fulfilled,
        OrderState::Expired,
        OrderState::Refunded,
        OrderState::Voided,
    ];

    fn body(tier: &str, return_to: &str) -> String {
        json!({ "tier": tier, "return_to": return_to }).to_string()
    }

    fn session_auth(token: &str) -> Option<Header<'static>> {
        Some(Header::new("x-session-token", token.to_string()))
    }

    async fn checkout_with<'c>(
        harness: &'c TestHarness,
        auth: Option<Header<'static>>,
        body: String,
    ) -> LocalResponse<'c> {
        let mut request = harness
            .client
            .post("/payments/cipher/checkout")
            .header(ContentType::JSON)
            .body(body);
        if let Some(auth) = auth {
            request = request.header(auth);
        }
        request.dispatch().await
    }

    async fn assert_refused(response: LocalResponse<'_>, status: Status, error_type: &str) {
        assert_eq!(response.status(), status);
        let error: serde_json::Value = response.into_json().await.expect("error body");
        assert_eq!(error["type"], error_type, "{error}");
    }

    async fn url_of(response: LocalResponse<'_>) -> String {
        assert_eq!(response.status(), Status::Ok);
        let body: serde_json::Value = response.into_json().await.expect("checkout body");
        body["url"].as_str().expect("`url`").to_string()
    }

    async fn orders_of(db: &Database, user_id: &str) -> usize {
        db.fetch_payment_orders_by_user(user_id, &ALL_STATES)
            .await
            .expect("orders")
            .len()
    }

    /// The route returns the session URL the provider created, stores it on
    /// a Pending order, and makes exactly one Stripe call whose idempotency
    /// key is that order's id. The price and return URLs come from the server.
    #[test]
    fn checkout_returns_the_session_url() {
        crate::util::test::rt().block_on(checkout_returns_the_session_url_case())
    }

    async fn checkout_returns_the_session_url_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let settings = PaymentsSettings::load().await.expect("settings");

        let response =
            checkout_with(&harness, session_auth(&session.token), body("T99", "web")).await;
        let url = url_of(response).await;

        let pending = harness
            .db
            .fetch_payment_orders_by_user(&user.id, &[OrderState::Pending])
            .await
            .expect("orders");
        assert_eq!(pending.len(), 1);
        assert_eq!(orders_of(&harness.db, &user.id).await, 1);
        let order = &pending[0];
        assert_eq!(order.checkout_url.as_deref(), Some(url.as_str()));
        assert_eq!(order.amount_cents, 9900);

        let session_id = order.checkout_session_id.clone().expect("session id");
        let stripe_session = harness.stripe.session(&session_id).expect("mock session");
        assert_eq!(stripe_session.url.as_deref(), Some(url.as_str()));

        assert_eq!(harness.stripe.call_count(CREATE_SESSION), 1);
        assert_eq!(
            harness.stripe.calls(),
            vec![(
                CREATE_SESSION.to_string(),
                order.id.clone(),
                Some(order.id.clone())
            )]
        );

        let params = harness.stripe.checkout_params();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].order_id, order.id);
        assert_eq!(params[0].user_id, user.id);
        assert_eq!(params[0].amount_cents, 9900);
        assert_eq!(params[0].success_url, settings.success_url_web);
        assert_eq!(params[0].cancel_url, settings.cancel_url_web);
    }

    /// A bot authenticates with its token and is refused before anything is
    /// stored or sent to Stripe
    #[test]
    fn bot_is_refused() {
        crate::util::test::rt().block_on(bot_is_refused_case())
    }

    async fn bot_is_refused_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("`Bot`");

        let response = checkout_with(
            &harness,
            Some(Header::new("x-bot-token", bot.token.clone())),
            body("T99", "web"),
        )
        .await;
        assert_refused(response, Status::BadRequest, "IsBot").await;

        assert_eq!(harness.stripe.call_count(CREATE_SESSION), 0);
        assert_eq!(orders_of(&harness.db, &bot.id).await, 0);
    }

    /// No session: 401, and nothing reaches Stripe
    #[test]
    fn unauthenticated_is_refused() {
        crate::util::test::rt().block_on(unauthenticated_is_refused_case())
    }

    async fn unauthenticated_is_refused_case() {
        let harness = TestHarness::new().await;

        let response = checkout_with(&harness, None, body("T99", "web")).await;
        assert_eq!(response.status(), Status::Unauthorized);

        assert!(harness.stripe.calls().is_empty());
    }

    /// While an order is Pending and unexpired, asking again for the same
    /// tier returns the stored URL without a second Stripe call or a second
    /// order
    #[test]
    fn pending_order_returns_the_same_url() {
        crate::util::test::rt().block_on(pending_order_returns_the_same_url_case())
    }

    async fn pending_order_returns_the_same_url_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        let first = url_of(
            checkout_with(&harness, session_auth(&session.token), body("T149", "web")).await,
        )
        .await;
        let second = url_of(
            checkout_with(&harness, session_auth(&session.token), body("T149", "web")).await,
        )
        .await;

        assert_eq!(first, second);
        assert_eq!(harness.stripe.call_count(CREATE_SESSION), 1);
        assert_eq!(orders_of(&harness.db, &user.id).await, 1);
    }

    /// While an order is Pending, a checkout for a different tier is refused
    /// (it would be a second live order) and nothing reaches Stripe
    #[test]
    fn pending_order_blocks_another_tier() {
        crate::util::test::rt().block_on(pending_order_blocks_another_tier_case())
    }

    async fn pending_order_blocks_another_tier_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        url_of(checkout_with(&harness, session_auth(&session.token), body("T99", "web")).await)
            .await;

        let response =
            checkout_with(&harness, session_auth(&session.token), body("T299", "web")).await;
        assert_refused(response, Status::Conflict, "PaymentPending").await;

        assert_eq!(harness.stripe.call_count(CREATE_SESSION), 1);
        assert_eq!(orders_of(&harness.db, &user.id).await, 1);
    }

    /// A Stripe failure answers PaymentProviderError and leaves the order
    /// SessionFailed; that order does not block a retry, which stores a new
    /// order (its own idempotency key) and succeeds. The retry asks for the
    /// shell return, so this also shows `return_to` picks the URLs.
    #[test]
    fn stripe_failure_then_retry_succeeds() {
        crate::util::test::rt().block_on(stripe_failure_then_retry_succeeds_case())
    }

    async fn stripe_failure_then_retry_succeeds_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let settings = PaymentsSettings::load().await.expect("settings");

        harness.stripe.fail_next(
            CREATE_SESSION,
            StripeError::Transport("connection reset".to_string()),
        );
        let response =
            checkout_with(&harness, session_auth(&session.token), body("T99", "web")).await;
        assert_refused(response, Status::BadGateway, "PaymentProviderError").await;

        let failed = harness
            .db
            .fetch_payment_orders_by_user(&user.id, &[OrderState::SessionFailed])
            .await
            .expect("orders");
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].checkout_url, None);

        let url = url_of(
            checkout_with(&harness, session_auth(&session.token), body("T99", "shell")).await,
        )
        .await;

        let pending = harness
            .db
            .fetch_payment_orders_by_user(&user.id, &[OrderState::Pending])
            .await
            .expect("orders");
        assert_eq!(pending.len(), 1);
        assert_ne!(pending[0].id, failed[0].id);
        assert_eq!(pending[0].checkout_url.as_deref(), Some(url.as_str()));
        assert_eq!(orders_of(&harness.db, &user.id).await, 2);

        // Both attempts were sent, each under its own order's key
        assert_eq!(
            harness.stripe.calls(),
            vec![
                (
                    CREATE_SESSION.to_string(),
                    failed[0].id.clone(),
                    Some(failed[0].id.clone())
                ),
                (
                    CREATE_SESSION.to_string(),
                    pending[0].id.clone(),
                    Some(pending[0].id.clone())
                ),
            ]
        );

        // Only the retry created a session, with the shell return URLs
        let params = harness.stripe.checkout_params();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].success_url, settings.success_url_shell);
        assert_eq!(params[0].cancel_url, settings.cancel_url_shell);
    }

    /// Payments off, or the sale closed: refused before any order is stored
    /// or Stripe is called.
    ///
    /// The route reads the config through `PaymentsSettings::load()`, and the
    /// test config has payments on; `overwrite_config` works once per
    /// process, so it cannot be flipped for one test. This drives the engine
    /// call the route makes, with the loaded settings altered, on the
    /// harness's database and mock Stripe.
    #[test]
    fn disabled_or_closed_is_refused() {
        crate::util::test::rt().block_on(disabled_or_closed_is_refused_case())
    }

    async fn disabled_or_closed_is_refused_case() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let loaded = PaymentsSettings::load().await.expect("settings");
        assert!(
            loaded.sales_open_at(now_ms()),
            "the test config must have the sale open, or the route tests above prove nothing"
        );

        let mut disabled = loaded.clone();
        disabled.enabled = false;

        let mut not_open = loaded.clone();
        not_open.sales_open = false;

        let mut past_close = loaded.clone();
        past_close.close_at_ms = Some(now_ms() - 1);

        for (settings, expected) in [
            (disabled, "PaymentsDisabled"),
            (not_open, "CipherSalesClosed"),
            (past_close, "CipherSalesClosed"),
        ] {
            let result = engine::create_cipher_checkout(
                &harness.db,
                &*harness.stripe,
                &settings,
                &user.id,
                CipherTier::T99,
                CipherReturnTo::Web,
                now_ms(),
            )
            .await;

            match result {
                Err(err) => match (&err.error_type, expected) {
                    (ErrorType::PaymentsDisabled, "PaymentsDisabled")
                    | (ErrorType::CipherSalesClosed, "CipherSalesClosed") => {}
                    (other, _) => panic!("expected {}, got {:?}", expected, other),
                },
                Ok(url) => panic!("expected {}, got a checkout URL {}", expected, url),
            }
        }

        assert!(harness.stripe.calls().is_empty());
        assert_eq!(orders_of(&harness.db, &user.id).await, 0);
    }

    /// Without `trust_cloudflare` (the test config, as the shipped one) the
    /// `CF-IPCountry` header is the client's word: a blocked country in it
    /// is ignored and the checkout goes ahead
    #[test]
    fn country_header_is_ignored_without_trust_cloudflare() {
        crate::util::test::rt().block_on(country_header_is_ignored_without_trust_cloudflare_case())
    }

    async fn country_header_is_ignored_without_trust_cloudflare_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        assert!(
            !revolt_config::config().await.api.security.trust_cloudflare,
            "the test config must not trust Cloudflare, or this test proves nothing"
        );
        let settings = PaymentsSettings::load().await.expect("settings");
        assert!(settings.region_blocked("DE"));

        let response = harness
            .client
            .post("/payments/cipher/checkout")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .header(Header::new("CF-IPCountry", "DE"))
            .body(body("T99", "web"))
            .dispatch()
            .await;
        url_of(response).await;
        assert_eq!(harness.stripe.call_count(CREATE_SESSION), 1);
        assert_eq!(orders_of(&harness.db, &user.id).await, 1);
    }

    /// With `trust_cloudflare` on, a blocked country refuses the checkout
    /// (`CipherRegionUnavailable`); anything else, or no header, goes
    /// ahead. The route refuses before the engine runs, so nothing is
    /// stored or sent to Stripe.
    ///
    /// The config is loaded once per process and the test config does not
    /// trust Cloudflare, so this drives the two steps the route takes, the
    /// header read and the refusal, with the switch passed in.
    #[test]
    fn a_trusted_blocked_country_is_refused() {
        crate::util::test::rt().block_on(a_trusted_blocked_country_is_refused_case())
    }

    async fn a_trusted_blocked_country_is_refused_case() {
        let settings = PaymentsSettings::load().await.expect("settings");
        let refused = |trust: bool, header: Option<&str>| {
            super::refuse_blocked_region(
                &settings,
                super::request_country(trust, header).as_deref(),
            )
            .err()
            .map(|err| err.error_type)
        };

        for header in ["DE", "de", "Fr", "GB", "IE", "SE"] {
            assert!(
                matches!(
                    refused(true, Some(header)),
                    Some(ErrorType::CipherRegionUnavailable)
                ),
                "{}",
                header
            );
            // Not trusted: the header is never read
            assert!(refused(false, Some(header)).is_none(), "{}", header);
        }
        for header in [
            None,
            Some("US"),
            Some("BR"),
            Some("XX"),
            Some("T1"),
            Some(""),
        ] {
            assert!(refused(true, header).is_none(), "{:?}", header);
        }
        // Not a two-character code: treated as unknown
        for header in ["DEU", "D", " DE", "D-"] {
            assert_eq!(
                super::request_country(true, Some(header)),
                None,
                "{}",
                header
            );
        }
        assert_eq!(
            super::request_country(true, Some("de")).as_deref(),
            Some("DE")
        );
        assert_eq!(super::request_country(false, Some("DE")), None);

        // The refusal carries its own type (its 400 is pinned in
        // revolt-result)
        let error = super::refuse_blocked_region(&settings, Some("DE")).unwrap_err();
        let value = serde_json::to_value(&error).unwrap();
        assert_eq!(value, json!({ "type": "CipherRegionUnavailable" }));
    }
}
