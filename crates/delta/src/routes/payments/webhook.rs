use std::sync::Arc;

use revolt_config::ApiStripe;
use revolt_database::Database;
use revolt_payments::dispatch::{handle_event, EventOutcome};
use revolt_payments::settings::PaymentsSettings;
use revolt_payments::stripe::{parse_event, verify, SignatureError, StripeApi};
use revolt_result::{create_error, Error, Result};
use rocket::data::ToByteUnit;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::{Data, Request, State};

/// Largest delivery read. Stripe event payloads are a few KiB; anything
/// past this is refused unread rather than truncated.
const BODY_LIMIT_MIB: u64 = 1;

/// Type prefix of the events that fulfil or expire an order
const CHECKOUT_SESSION_PREFIX: &str = "checkout.session.";

/// The raw `Stripe-Signature` header (`t=…,v1=…`). Only its presence is
/// checked here; the route verifies it against the raw body.
#[derive(Debug)]
pub struct StripeSignature<'r>(pub &'r str);

impl std::ops::Deref for StripeSignature<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for StripeSignature<'r> {
    type Error = Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("Stripe-Signature") {
            Some(signature) => Outcome::Success(Self(signature)),
            None => Outcome::Error((Status::BadRequest, create_error!(InvalidOperation))),
        }
    }
}

/// # Stripe Webhook
///
/// Unauthenticated: a delivery is trusted only when its `Stripe-Signature`
/// verifies against the raw body. A handled delivery is answered 200 with an
/// empty body; the status alone tells Stripe whether to retry.
///
/// - 400: no signature header, a body over 1 MiB, a signature that does not
///   verify (wrong secret, tampered body, stale or malformed header), or a
///   signed body that is not a Stripe event
/// - 500: the payments config is unusable, no webhook secret is configured,
///   or handling failed or the order is busy (Stripe retries; the reconcile
///   sweep re-drives the event too)
/// - 200: processed, ignored (another livemode, not ours, a type we do not
///   act on) or already handled
///
/// Deliveries are handled whenever the signature verifies, whatever
/// `features.payments.enabled` says: that switch gates new checkouts only,
/// never the settling of money already taken, so a refund after the kill
/// switch is flipped still revokes.
///
/// A `[features.payments]` table that does not validate (cap, close date)
/// does not stop refunds and disputes either: they are handled with the
/// sale fields at their defaults and the configured `[api.stripe]`, as the
/// account-deletion cascade does. `checkout.session.*` events read the cap
/// and the close date, so they are answered 500 until the config is fixed
/// (Stripe retries them for days, and the reconcile sweep checks paid
/// sessions too).
#[openapi(skip)]
#[post("/stripe/webhook", data = "<data>")]
pub async fn webhook(
    db: &State<Database>,
    stripe: &State<Arc<dyn StripeApi>>,
    signature: StripeSignature<'_>,
    data: Data<'_>,
) -> Result<Status> {
    // The exact bytes Stripe signed: never re-serialized before verifying
    let body = data
        .open(BODY_LIMIT_MIB.mebibytes())
        .into_bytes()
        .await
        .map_err(|_| {
            log::warn!("payments webhook: could not read the request body");
            create_error!(InvalidOperation)
        })?;
    if !body.is_complete() {
        log::warn!("payments webhook: refused a body larger than {BODY_LIMIT_MIB} MiB");
        return Err(create_error!(InvalidOperation));
    }
    let body = body.into_inner();

    // `from_config` logs what is wrong with the config; the secrets are
    // never printed
    let config = revolt_config::config().await;
    let (settings, sale) =
        webhook_settings(PaymentsSettings::from_config(&config), &config.api.stripe)?;

    let now_ms = chrono::Utc::now().timestamp_millis();
    handle_delivery(
        db,
        &**stripe.inner(),
        &settings,
        sale,
        signature.0,
        &body,
        now_ms,
    )
    .await
}

/// Whether the sale fields of the payments config validated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaleConfig {
    Valid,
    /// The settings are the settlement fallback: refunds and disputes only
    Invalid,
}

/// The settings a delivery is handled with: the loaded ones, or the
/// settlement fallback when `[features.payments]` does not validate
fn webhook_settings(
    loaded: Result<PaymentsSettings>,
    stripe: &ApiStripe,
) -> Result<(PaymentsSettings, SaleConfig)> {
    match loaded {
        Ok(settings) => Ok((settings, SaleConfig::Valid)),
        Err(_) => {
            log::error!(
                "payments webhook: the payments sale config is invalid; handling refunds and \
                 disputes only"
            );
            let settings = PaymentsSettings::for_settlement(stripe).map_err(|_| {
                log::error!("payments webhook: no usable payments settings; refusing delivery");
                create_error!(InternalError)
            })?;
            Ok((settings, SaleConfig::Invalid))
        }
    }
}

/// Everything after the body is read and the settings are loaded: the secret
/// check, the signature, the event, and the answer for Stripe.
///
/// Logs carry the failure kind and the event id at most, never the header or
/// the body (the body can hold buyer details).
async fn handle_delivery(
    db: &Database,
    stripe: &dyn StripeApi,
    settings: &PaymentsSettings,
    sale: SaleConfig,
    header: &str,
    body: &[u8],
    now_ms: i64,
) -> Result<Status> {
    // An HMAC keyed with an empty string is forgeable by anyone: refuse
    // before computing one
    if settings.webhook_secret.is_empty() {
        log::error!("payments webhook: webhook secret not configured; refusing delivery");
        return Err(create_error!(InternalError));
    }

    let now_secs = now_ms.div_euclid(1000);
    if let Err(error) = verify(
        header,
        body,
        &settings.webhook_secret,
        now_secs,
        settings.tolerance_secs,
    ) {
        return Err(match error {
            SignatureError::EmptySecret => {
                log::error!("payments webhook: webhook secret not configured; refusing delivery");
                create_error!(InternalError)
            }
            SignatureError::Malformed | SignatureError::Stale | SignatureError::NoMatch => {
                log::warn!("payments webhook: refused a delivery, signature {error:?}");
                create_error!(InvalidOperation)
            }
        });
    }

    let event = match parse_event(body) {
        Ok(event) => event,
        Err(error) => {
            // Decode errors never quote the payload
            log::warn!("payments webhook: refused a signed delivery: {error}");
            return Err(create_error!(InvalidOperation));
        }
    };

    // Fulfilment and expiry read the cap and the close date, which the
    // fallback does not carry: not recorded, so Stripe's retry finds it new
    if sale == SaleConfig::Invalid && event.event_type.starts_with(CHECKOUT_SESSION_PREFIX) {
        log::error!(
            "payments webhook: event {} ({}) needs the payments sale config, which is invalid; \
             answered 500 for a retry",
            event.id,
            event.event_type
        );
        return Err(create_error!(InternalError));
    }

    match handle_event(db, stripe, settings, &event, now_ms).await {
        Ok(EventOutcome::Processed | EventOutcome::Ignored | EventOutcome::Duplicate) => {
            Ok(Status::Ok)
        }
        // Dispatch has marked the event Failed and logged why
        Ok(EventOutcome::Retry) => {
            log::info!(
                "payments webhook: event {} ({}) answered 500 for a retry",
                event.id,
                event.event_type
            );
            Err(create_error!(InternalError))
        }
        Err(error) => {
            log::error!(
                "payments webhook: event {} ({}) could not be recorded: {:?}",
                event.id,
                event.event_type,
                error.error_type
            );
            Err(create_error!(InternalError))
        }
    }
}

#[cfg(test)]
mod test {
    use revolt_database::{OrderState, PaymentEventState};
    use revolt_models::v0::{CipherReturnTo, CipherTier};
    use revolt_payments::engine::{
        create_cipher_checkout, fulfil_order, REFUND_GRACE_MS, REFUND_RELEASE_WINDOW_MS,
    };
    use revolt_payments::settings::PaymentsSettings;
    use revolt_payments::stripe::{sign_for_tests, CheckoutSession, PaymentIntent, StripeError};
    use revolt_result::create_error;
    use revolt_result::ErrorType;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::Value;

    use super::{handle_delivery, webhook_settings, SaleConfig, BODY_LIMIT_MIB};
    use crate::util::test::TestHarness;

    const WEBHOOK: &str = "/payments/stripe/webhook";

    fn now_ms() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    fn now_secs() -> i64 {
        now_ms().div_euclid(1000)
    }

    /// The settings the route loads (Revolt.test.toml: a dummy webhook
    /// secret, test mode)
    async fn settings() -> PaymentsSettings {
        let s = PaymentsSettings::load().await.expect("payments settings");
        assert!(
            !s.webhook_secret.is_empty(),
            "Revolt.test.toml configures a webhook secret"
        );
        assert!(!s.expect_livemode, "the tests run in test mode");
        s
    }

    /// A Stripe event envelope, serialized once: these exact bytes are signed
    /// and sent
    fn event_body(id: &str, event_type: &str, livemode: bool, object: Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "object": "event",
            "type": event_type,
            "livemode": livemode,
            "created": now_secs(),
            "data": { "object": object }
        }))
        .unwrap()
    }

    /// An event type the engine does not act on: handled as Ignored without
    /// a Stripe call
    fn unhandled_body(id: &str) -> Vec<u8> {
        event_body(
            id,
            "customer.created",
            false,
            serde_json::json!({ "id": "cus_webhook_1", "object": "customer" }),
        )
    }

    async fn deliver(harness: &TestHarness, signature: Option<String>, body: Vec<u8>) -> Status {
        let mut request = harness
            .client
            .post(WEBHOOK)
            .header(ContentType::JSON)
            .body(body);
        if let Some(signature) = signature {
            request = request.header(Header::new("Stripe-Signature", signature));
        }
        request.dispatch().await.status()
    }

    /// Deliver `body` signed now with `secret`
    async fn deliver_signed(harness: &TestHarness, secret: &str, body: Vec<u8>) -> Status {
        let signature = sign_for_tests(&body, secret, now_secs());
        deliver(harness, Some(signature), body).await
    }

    async fn event_state(harness: &TestHarness, id: &str) -> Option<PaymentEventState> {
        harness
            .db
            .fetch_payment_event(id)
            .await
            .unwrap()
            .map(|row| row.state)
    }

    #[test]
    fn a_bad_signature_is_refused() {
        crate::util::test::rt().block_on(a_bad_signature_is_refused_case())
    }

    async fn a_bad_signature_is_refused_case() {
        let harness = TestHarness::new().await;
        let s = settings().await;
        let body = unhandled_body("evt_webhook_badsig");

        // Signed with another endpoint's secret
        assert_eq!(
            deliver_signed(&harness, "whsec_not_this_endpoint", body.clone()).await,
            Status::BadRequest
        );

        // Our secret, but over different bytes than the ones sent
        let signature = sign_for_tests(&body, &s.webhook_secret, now_secs());
        let mut tampered = body.clone();
        tampered.push(b' ');
        assert_eq!(
            deliver(&harness, Some(signature), tampered).await,
            Status::BadRequest
        );

        // Not a signature header at all
        assert_eq!(
            deliver(&harness, Some("garbage".to_string()), body.clone()).await,
            Status::BadRequest
        );

        // Nothing was recorded and Stripe was never asked
        assert_eq!(event_state(&harness, "evt_webhook_badsig").await, None);
        assert!(harness.stripe.calls().is_empty());

        // Control: the same bytes signed with our secret are accepted
        assert_eq!(
            deliver_signed(&harness, &s.webhook_secret, body).await,
            Status::Ok
        );
        assert_eq!(
            event_state(&harness, "evt_webhook_badsig").await,
            Some(PaymentEventState::Ignored)
        );
    }

    #[test]
    fn a_missing_signature_header_is_refused() {
        crate::util::test::rt().block_on(a_missing_signature_header_is_refused_case())
    }

    async fn a_missing_signature_header_is_refused_case() {
        let harness = TestHarness::new().await;

        let body = unhandled_body("evt_webhook_nosig");
        assert_eq!(deliver(&harness, None, body).await, Status::BadRequest);

        assert_eq!(event_state(&harness, "evt_webhook_nosig").await, None);
        assert!(harness.stripe.calls().is_empty());
    }

    #[test]
    fn a_stale_signature_is_refused() {
        crate::util::test::rt().block_on(a_stale_signature_is_refused_case())
    }

    async fn a_stale_signature_is_refused_case() {
        let harness = TestHarness::new().await;
        let s = settings().await;
        let tolerance = s.tolerance_secs as i64;
        let body = unhandled_body("evt_webhook_stale");

        // A captured delivery replayed after the tolerance, and one stamped
        // too far ahead: both validly signed with our secret
        for t in [now_secs() - tolerance - 60, now_secs() + tolerance + 60] {
            let signature = sign_for_tests(&body, &s.webhook_secret, t);
            assert_eq!(
                deliver(&harness, Some(signature), body.clone()).await,
                Status::BadRequest,
                "t = {t}"
            );
        }

        assert_eq!(event_state(&harness, "evt_webhook_stale").await, None);
        assert!(harness.stripe.calls().is_empty());
    }

    #[test]
    fn an_oversized_body_is_refused() {
        crate::util::test::rt().block_on(an_oversized_body_is_refused_case())
    }

    async fn an_oversized_body_is_refused_case() {
        let harness = TestHarness::new().await;
        let s = settings().await;
        let limit = (BODY_LIMIT_MIB * 1024 * 1024) as usize;

        // Trailing whitespace keeps the JSON valid and the signature good:
        // only the size is wrong
        let mut body = unhandled_body("evt_webhook_huge");
        body.resize(limit + 1, b' ');
        assert_eq!(
            deliver_signed(&harness, &s.webhook_secret, body).await,
            Status::BadRequest
        );
        assert_eq!(event_state(&harness, "evt_webhook_huge").await, None);

        // Control: the same event padded to just under the limit is accepted
        let mut body = unhandled_body("evt_webhook_big");
        body.resize(limit - 1024, b' ');
        assert_eq!(
            deliver_signed(&harness, &s.webhook_secret, body).await,
            Status::Ok
        );
        assert_eq!(
            event_state(&harness, "evt_webhook_big").await,
            Some(PaymentEventState::Ignored)
        );
    }

    #[test]
    fn a_signed_body_that_is_not_an_event_is_refused() {
        crate::util::test::rt().block_on(a_signed_body_that_is_not_an_event_is_refused_case())
    }

    async fn a_signed_body_that_is_not_an_event_is_refused_case() {
        let harness = TestHarness::new().await;
        let s = settings().await;

        let bodies: [&[u8]; 3] = [
            b"not json",
            br#"{"hello":"world"}"#,
            // An envelope whose id could walk a Stripe API path
            br#"{"id":"evt_../x","type":"customer.created","livemode":false,"created":1,"data":{"object":{}}}"#,
        ];
        for body in bodies {
            assert_eq!(
                deliver_signed(&harness, &s.webhook_secret, body.to_vec()).await,
                Status::BadRequest
            );
        }
        assert!(harness.stripe.calls().is_empty());
    }

    #[test]
    fn a_livemode_mismatch_is_acknowledged_and_ignored() {
        crate::util::test::rt().block_on(a_livemode_mismatch_is_acknowledged_and_ignored_case())
    }

    async fn a_livemode_mismatch_is_acknowledged_and_ignored_case() {
        let harness = TestHarness::new().await;
        let s = settings().await;

        // A live-mode refund delivered to this test-mode deployment
        let body = event_body(
            "evt_webhook_live",
            "charge.refunded",
            true,
            serde_json::json!({
                "id": "ch_webhook_live",
                "object": "charge",
                "payment_intent": "pi_webhook_live"
            }),
        );
        assert_eq!(
            deliver_signed(&harness, &s.webhook_secret, body).await,
            Status::Ok
        );

        let row = harness
            .db
            .fetch_payment_event("evt_webhook_live")
            .await
            .unwrap()
            .expect("the event is recorded");
        assert_eq!(row.state, PaymentEventState::Ignored);
        assert!(row.livemode);
        assert!(harness.stripe.calls().is_empty());
    }

    #[test]
    fn foreign_payments_are_acknowledged_and_ignored() {
        crate::util::test::rt().block_on(foreign_payments_are_acknowledged_and_ignored_case())
    }

    async fn foreign_payments_are_acknowledged_and_ignored_case() {
        let harness = TestHarness::new().await;
        let s = settings().await;

        // A checkout session we never created, whatever its metadata claims:
        // no order has it, so Stripe is not even asked about it
        let body = event_body(
            "evt_webhook_cs_foreign",
            "checkout.session.completed",
            false,
            serde_json::json!({
                "id": "cs_webhook_foreign",
                "object": "checkout.session",
                "metadata": { "order_id": "01J00000000000000000000000" }
            }),
        );
        assert_eq!(
            deliver_signed(&harness, &s.webhook_secret, body).await,
            Status::Ok
        );
        assert_eq!(
            event_state(&harness, "evt_webhook_cs_foreign").await,
            Some(PaymentEventState::Ignored)
        );
        assert_eq!(harness.stripe.call_count("get_checkout_session"), 0);

        // A refund of some other payment on the account: its intent carries
        // no order metadata
        harness.stripe.set_payment_intent(PaymentIntent {
            id: "pi_webhook_foreign".to_string(),
            livemode: false,
            metadata_order_id: None,
            ..Default::default()
        });
        // ... and one Stripe does not know at all (404)
        for (id, payment_intent) in [
            ("evt_webhook_pi_foreign", "pi_webhook_foreign"),
            ("evt_webhook_pi_nowhere", "pi_webhook_nowhere"),
        ] {
            let body = event_body(
                id,
                "charge.refunded",
                false,
                serde_json::json!({
                    "id": "ch_webhook_foreign",
                    "object": "charge",
                    "payment_intent": payment_intent
                }),
            );
            assert_eq!(
                deliver_signed(&harness, &s.webhook_secret, body).await,
                Status::Ok,
                "{payment_intent}"
            );
            assert_eq!(
                event_state(&harness, id).await,
                Some(PaymentEventState::Ignored),
                "{payment_intent}"
            );
        }
        assert_eq!(harness.stripe.call_count("get_payment_intent"), 2);
        assert_eq!(harness.stripe.refund_count(), 0);
    }

    #[test]
    fn a_paid_checkout_is_retried_then_fulfilled_once() {
        crate::util::test::rt().block_on(a_paid_checkout_is_retried_then_fulfilled_once_case())
    }

    async fn a_paid_checkout_is_retried_then_fulfilled_once_case() {
        let harness = TestHarness::new().await;
        let s = settings().await;
        let (_, _, user) = harness.new_user().await;
        harness.db.seed_cipher_numbers(s.cap).await.unwrap();

        // A real order, through the engine and the mock
        let url = create_cipher_checkout(
            &harness.db,
            &*harness.stripe,
            &s,
            &user.id,
            CipherTier::T99,
            CipherReturnTo::Web,
            now_ms(),
        )
        .await
        .expect("checkout");
        let order = harness
            .db
            .fetch_payment_orders_by_user(&user.id, &[OrderState::Pending])
            .await
            .unwrap()
            .pop()
            .expect("a pending order");
        assert_eq!(order.checkout_url.as_deref(), Some(url.as_str()));
        let session_id = order.checkout_session_id.clone().expect("a session");

        // The buyer pays
        let session = harness.stripe.session(&session_id).expect("mock session");
        harness.stripe.set_session(CheckoutSession {
            status: Some("complete".to_string()),
            payment_status: Some("paid".to_string()),
            payment_intent: Some("pi_webhook_paid".to_string()),
            ..session
        });

        let body = event_body(
            "evt_webhook_paid",
            "checkout.session.completed",
            false,
            serde_json::json!({ "id": session_id, "object": "checkout.session" }),
        );

        // First delivery: Stripe cannot be reached to confirm the session.
        // 500 so Stripe retries; nothing is granted
        harness.stripe.fail_next(
            "get_checkout_session",
            StripeError::Transport("timed out".to_string()),
        );
        assert_eq!(
            deliver_signed(&harness, &s.webhook_secret, body.clone()).await,
            Status::InternalServerError
        );
        assert_eq!(
            event_state(&harness, "evt_webhook_paid").await,
            Some(PaymentEventState::Failed)
        );
        let stored = harness
            .db
            .fetch_payment_order(&order.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.state, OrderState::Pending);
        assert_eq!(harness.db.fetch_user(&user.id).await.unwrap().cipher, None);

        // Stripe redelivers: fulfilled
        assert_eq!(
            deliver_signed(&harness, &s.webhook_secret, body.clone()).await,
            Status::Ok
        );
        assert_eq!(
            event_state(&harness, "evt_webhook_paid").await,
            Some(PaymentEventState::Processed)
        );
        let stored = harness
            .db
            .fetch_payment_order(&order.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.state, OrderState::Fulfilled);
        assert_eq!(stored.payment_intent_id.as_deref(), Some("pi_webhook_paid"));

        let membership = harness
            .db
            .fetch_cipher_membership(&user.id)
            .await
            .unwrap()
            .expect("a membership");
        assert_eq!(membership.orders, vec![order.id.clone()]);
        assert_eq!(membership.tier, CipherTier::T99);
        assert!(membership.revoked_at.is_none());
        let badge = harness
            .db
            .fetch_user(&user.id)
            .await
            .unwrap()
            .cipher
            .expect("the public badge");
        assert_eq!(badge.number, membership.number);
        assert_eq!(badge.tier, CipherTier::T99);

        // A duplicate delivery is acknowledged without acting again
        let lookups = harness.stripe.call_count("get_checkout_session");
        assert_eq!(
            deliver_signed(&harness, &s.webhook_secret, body).await,
            Status::Ok
        );
        assert_eq!(harness.stripe.call_count("get_checkout_session"), lookups);
        assert_eq!(
            event_state(&harness, "evt_webhook_paid").await,
            Some(PaymentEventState::Processed)
        );
        assert_eq!(
            harness
                .db
                .fetch_cipher_membership(&user.id)
                .await
                .unwrap()
                .expect("a membership"),
            membership
        );
        assert_eq!(harness.stripe.refund_count(), 0);
    }

    #[test]
    fn an_unconfigured_secret_refuses_every_delivery() {
        crate::util::test::rt().block_on(an_unconfigured_secret_refuses_every_delivery_case())
    }

    async fn an_unconfigured_secret_refuses_every_delivery_case() {
        let harness = TestHarness::new().await;
        let configured = settings().await;
        let unconfigured = PaymentsSettings {
            webhook_secret: String::new(),
            ..configured.clone()
        };
        let body = unhandled_body("evt_webhook_nosecret");

        // Even a header really made with the empty key is refused, as a
        // server error: the deployment is broken, not the delivery
        let signature = sign_for_tests(&body, "", now_secs());
        let result = handle_delivery(
            &harness.db,
            &*harness.stripe,
            &unconfigured,
            SaleConfig::Valid,
            &signature,
            &body,
            now_ms(),
        )
        .await;
        assert!(matches!(
            result.map_err(|error| error.error_type),
            Err(ErrorType::InternalError)
        ));
        assert_eq!(event_state(&harness, "evt_webhook_nosecret").await, None);
        assert!(harness.stripe.calls().is_empty());

        // Control: the configured secret accepts the same event
        let signature = sign_for_tests(&body, &configured.webhook_secret, now_secs());
        let result = handle_delivery(
            &harness.db,
            &*harness.stripe,
            &configured,
            SaleConfig::Valid,
            &signature,
            &body,
            now_ms(),
        )
        .await;
        assert_eq!(result.ok(), Some(Status::Ok));
        assert_eq!(
            event_state(&harness, "evt_webhook_nosecret").await,
            Some(PaymentEventState::Ignored)
        );
    }

    #[test]
    fn an_invalid_sale_config_still_settles_refunds_but_not_checkouts() {
        // Two whole purchase-and-refund flows polled straight from this
        // thread (`block_on`, no HTTP hop) overflow the default 2 MiB test
        // stack in a debug build on MongoDB: run the boxed case on a thread
        // with room. A panic in the case still fails the test.
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                crate::util::test::rt().block_on(Box::pin(
                    an_invalid_sale_config_still_settles_refunds_but_not_checkouts_case(),
                ))
            })
            .expect("test thread")
            .join()
            .expect("the case passes")
    }

    async fn an_invalid_sale_config_still_settles_refunds_but_not_checkouts_case() {
        let harness = TestHarness::new().await;
        let s = settings().await;
        let (_, _, user) = harness.new_user().await;
        harness.db.seed_cipher_numbers(s.cap).await.unwrap();

        // A fulfilled member, through the engine and the mock, who paid more
        // than 14 days (plus the 3-day grace) ago: the full refund below
        // revokes and retires the number
        let paid_at = now_ms() - REFUND_RELEASE_WINDOW_MS - REFUND_GRACE_MS - 60_000;
        let url = create_cipher_checkout(
            &harness.db,
            &*harness.stripe,
            &s,
            &user.id,
            CipherTier::T99,
            CipherReturnTo::Web,
            paid_at,
        )
        .await
        .expect("checkout");
        let order = harness
            .db
            .fetch_payment_orders_by_user(&user.id, &[OrderState::Pending])
            .await
            .unwrap()
            .pop()
            .expect("a pending order");
        assert_eq!(order.checkout_url.as_deref(), Some(url.as_str()));
        let session_id = order.checkout_session_id.clone().expect("a session");
        let session = harness.stripe.session(&session_id).expect("mock session");
        let paid = CheckoutSession {
            status: Some("complete".to_string()),
            payment_status: Some("paid".to_string()),
            payment_intent: Some("pi_webhook_fallback".to_string()),
            ..session
        };
        harness.stripe.set_session(paid.clone());
        fulfil_order(&harness.db, &*harness.stripe, &s, &order.id, &paid, paid_at)
            .await
            .expect("fulfilled");
        assert!(harness
            .db
            .fetch_user(&user.id)
            .await
            .unwrap()
            .cipher
            .is_some());

        // [features.payments] stops validating (e.g. a bad close date): the
        // route falls back to the configured [api.stripe]
        let stripe_section = revolt_config::config().await.api.stripe;
        let (fallback, sale) =
            webhook_settings(Err(create_error!(InternalError)), &stripe_section).unwrap();
        assert_eq!(sale, SaleConfig::Invalid);
        assert_eq!(fallback.webhook_secret, s.webhook_secret);
        assert!(!fallback.enabled);
        // A valid config is used as loaded
        let (loaded, sale) = webhook_settings(Ok(s.clone()), &stripe_section).unwrap();
        assert_eq!(sale, SaleConfig::Valid);
        assert_eq!(loaded.cap, s.cap);

        let deliver = |body: Vec<u8>| {
            let signature = sign_for_tests(&body, &fallback.webhook_secret, now_secs());
            let db = harness.db.clone();
            let stripe = harness.stripe.clone();
            let fallback = fallback.clone();
            async move {
                handle_delivery(
                    &db,
                    &*stripe,
                    &fallback,
                    SaleConfig::Invalid,
                    &signature,
                    &body,
                    now_ms(),
                )
                .await
                .map_err(|error| error.error_type)
            }
        };

        // A checkout event is not handled on the fallback: 500, not recorded
        let completed = event_body(
            "evt_webhook_fallback_cs",
            "checkout.session.completed",
            false,
            serde_json::json!({ "id": session_id, "object": "checkout.session" }),
        );
        assert!(matches!(
            deliver(completed).await,
            Err(ErrorType::InternalError)
        ));
        assert_eq!(event_state(&harness, "evt_webhook_fallback_cs").await, None);

        // The refund is: past the window and the grace, the membership is revoked,
        // the number retired and the badge cleared
        let refunded = event_body(
            "evt_webhook_fallback_refund",
            "charge.refunded",
            false,
            serde_json::json!({
                "id": "ch_webhook_fallback",
                "object": "charge",
                "payment_intent": "pi_webhook_fallback",
                "amount": 9900,
                "amount_refunded": 9900,
                "refunded": true
            }),
        );
        let answered = deliver(refunded).await;
        assert_eq!(answered.as_ref().ok(), Some(&Status::Ok), "{answered:?}");
        assert_eq!(
            event_state(&harness, "evt_webhook_fallback_refund").await,
            Some(PaymentEventState::Processed)
        );
        let stored = harness
            .db
            .fetch_payment_order(&order.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.state, OrderState::Refunded);
        let membership = harness
            .db
            .fetch_cipher_membership(&user.id)
            .await
            .unwrap()
            .expect("a membership");
        assert!(membership.revoked_at.is_some());
        assert_eq!(harness.db.fetch_user(&user.id).await.unwrap().cipher, None);
        assert_eq!(
            harness
                .db
                .fetch_cipher_number_by_order(&order.id)
                .await
                .unwrap(),
            Some(membership.number),
            "the number stays retired"
        );

        // A second member, refunded within 14 days, under the same fallback:
        // the membership is deleted and the number goes back to the pool
        let (_, _, recent) = harness.new_user().await;
        create_cipher_checkout(
            &harness.db,
            &*harness.stripe,
            &s,
            &recent.id,
            CipherTier::T99,
            CipherReturnTo::Web,
            now_ms(),
        )
        .await
        .expect("checkout");
        let recent_order = harness
            .db
            .fetch_payment_orders_by_user(&recent.id, &[OrderState::Pending])
            .await
            .unwrap()
            .pop()
            .expect("a pending order");
        let recent_session = harness
            .stripe
            .session(
                recent_order
                    .checkout_session_id
                    .as_deref()
                    .expect("a session"),
            )
            .expect("mock session");
        let recent_paid = CheckoutSession {
            status: Some("complete".to_string()),
            payment_status: Some("paid".to_string()),
            payment_intent: Some("pi_webhook_fallback_recent".to_string()),
            ..recent_session
        };
        harness.stripe.set_session(recent_paid.clone());
        fulfil_order(
            &harness.db,
            &*harness.stripe,
            &s,
            &recent_order.id,
            &recent_paid,
            now_ms(),
        )
        .await
        .expect("fulfilled");
        let number = harness
            .db
            .fetch_cipher_number_by_order(&recent_order.id)
            .await
            .unwrap()
            .expect("a claimed number");

        let refunded = event_body(
            "evt_webhook_fallback_refund_recent",
            "charge.refunded",
            false,
            serde_json::json!({
                "id": "ch_webhook_fallback_recent",
                "object": "charge",
                "payment_intent": "pi_webhook_fallback_recent",
                "amount": 9900,
                "amount_refunded": 9900,
                "refunded": true
            }),
        );
        let answered = deliver(refunded).await;
        assert_eq!(answered.as_ref().ok(), Some(&Status::Ok), "{answered:?}");
        assert_eq!(
            event_state(&harness, "evt_webhook_fallback_refund_recent").await,
            Some(PaymentEventState::Processed)
        );
        assert_eq!(
            harness
                .db
                .fetch_payment_order(&recent_order.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            OrderState::Refunded
        );
        assert_eq!(
            harness
                .db
                .fetch_cipher_membership(&recent.id)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            harness
                .db
                .fetch_cipher_number_by_order(&recent_order.id)
                .await
                .unwrap(),
            None,
            "number {number} is back in the pool"
        );
        assert_eq!(
            harness.db.fetch_user(&recent.id).await.unwrap().cipher,
            None
        );
    }
}
