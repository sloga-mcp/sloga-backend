use revolt_database::{now_ms, Database};
use revolt_models::v0;
use revolt_payments::engine;
use revolt_payments::settings::PaymentsSettings;
use revolt_result::Result;
use revolt_rocket_okapi::gen::OpenApiGenerator;
use revolt_rocket_okapi::response::OpenApiResponderInner;
use revolt_rocket_okapi::revolt_okapi::openapi3::Responses;
use revolt_rocket_okapi::OpenApiError;
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use rocket::{Request, Response, State};

/// `Cache-Control` on every stats response. `public`: the route takes no
/// session and the body is the same for every caller.
pub const CACHE_CONTROL: &str = "public, max-age=30";

/// `Json<CipherStats>` with [`CACHE_CONTROL`] attached (pattern:
/// `discover::streamers_list::CachedStreamers`).
pub struct CachedCipherStats(pub Json<v0::CipherStats>);

impl<'r> Responder<'r, 'static> for CachedCipherStats {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        Response::build_from(self.0.respond_to(req)?)
            .raw_header("Cache-Control", CACHE_CONTROL)
            .ok()
    }
}

impl OpenApiResponderInner for CachedCipherStats {
    fn responses(generator: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        <Json<v0::CipherStats> as OpenApiResponderInner>::responses(generator)
    }
}

/// # Fetch Cipher Sale Stats
///
/// Public, unauthenticated: how many Cipher numbers are claimed, the cap,
/// and whether the sale is open.
#[openapi(tag = "Payments")]
#[get("/cipher/stats")]
pub async fn stats(db: &State<Database>) -> Result<CachedCipherStats> {
    // Served with payments disabled too (the counter then reads `open:
    // false`). A config that does not validate is an error, never a guess.
    let settings = PaymentsSettings::load().await?;

    // `open` is `enabled && sales_open && now < close date`, the same test
    // checkout applies; `claimed` counts retired numbers too
    let stats = engine::cipher_stats(db, &settings, now_ms()).await?;
    Ok(CachedCipherStats(Json(stats)))
}

#[cfg(test)]
mod tests {
    use crate::util::test::TestHarness;
    use revolt_database::{now_ms, Database, OrderState};
    use revolt_models::v0;
    use revolt_payments::catalog::CIPHER_CAP_MAX;
    use revolt_payments::engine::{self, FulfilOutcome};
    use revolt_payments::settings::PaymentsSettings;
    use rocket::http::Status;

    /// `GET /payments/cipher/stats` with no session; must answer 200 with
    /// the shared-cache header
    async fn fetch_stats(harness: &TestHarness) -> v0::CipherStats {
        let response = harness
            .client
            .get("/payments/cipher/stats")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.headers().get_one("Cache-Control"),
            Some(super::CACHE_CONTROL)
        );
        response
            .into_json::<v0::CipherStats>()
            .await
            .expect("`CipherStats`")
    }

    #[test]
    fn cache_control_is_public_30s() {
        assert_eq!(super::CACHE_CONTROL, "public, max-age=30");
    }

    #[test]
    fn stats_without_session() {
        crate::util::test::rt().block_on(stats_without_session_case())
    }

    async fn stats_without_session_case() {
        let harness = TestHarness::new().await;

        // Mongo: a fresh database runs init, which seeds 1..=1000 unclaimed;
        // the reference driver starts with an empty table
        let rows = harness.db.count_cipher_numbers().await.expect("count");
        match &harness.db {
            Database::Reference(_) => assert_eq!(rows, 0),
            Database::MongoDb(_) => assert_eq!(rows, CIPHER_CAP_MAX),
        }

        let stats = fetch_stats(&harness).await;
        assert_eq!(stats.claimed, 0);
        assert_eq!(stats.cap, 1000);
        // Revolt.test.toml enables payments, opens the sale and sets no
        // close date
        assert!(stats.open);
        assert_eq!(stats.closes_at, None);

        let s = PaymentsSettings::load().await.expect("payments settings");
        assert_eq!(stats.open, s.sales_open_at(now_ms()));
    }

    #[test]
    fn stats_counts_claimed_numbers() {
        crate::util::test::rt().block_on(stats_counts_claimed_numbers_case())
    }

    async fn stats_counts_claimed_numbers_case() {
        let harness = TestHarness::new().await;
        let s = PaymentsSettings::load().await.expect("payments settings");
        harness
            .db
            .seed_cipher_numbers(s.cap)
            .await
            .expect("seed cipher_numbers");

        // A real purchase: checkout, the buyer pays, fulfilment claims #1
        let (_, _, buyer) = harness.new_user().await;
        let url = engine::create_cipher_checkout(
            &harness.db,
            &*harness.stripe,
            &s,
            &buyer.id,
            v0::CipherTier::T299,
            v0::CipherReturnTo::Shell,
            now_ms(),
        )
        .await
        .expect("checkout");
        let order = harness
            .db
            .fetch_payment_orders_by_user(&buyer.id, &[OrderState::Pending])
            .await
            .expect("orders")
            .into_iter()
            .find(|o| o.checkout_url.as_deref() == Some(url.as_str()))
            .expect("the checkout's Pending order");

        let checkout_session = order.checkout_session_id.clone().expect("session id");
        let mut paid = harness.stripe.session(&checkout_session).expect("session");
        paid.status = Some("complete".to_string());
        paid.payment_status = Some("paid".to_string());
        paid.payment_intent = Some("pi_test_stats_1".to_string());
        harness.stripe.set_session(paid.clone());

        let outcome = engine::fulfil_order(
            &harness.db,
            &*harness.stripe,
            &s,
            &order.id,
            &paid,
            now_ms(),
        )
        .await
        .expect("fulfil");
        assert_eq!(outcome, FulfilOutcome::Fulfilled);

        // And two numbers held by orders outside this flow (a retired
        // number keeps its order_id, so it still counts)
        for order_id in ["01STATSORDER0000000000000A", "01STATSORDER0000000000000B"] {
            assert!(harness
                .db
                .claim_cipher_number(order_id, s.cap)
                .await
                .expect("claim")
                .is_some());
        }

        let stats = fetch_stats(&harness).await;
        assert_eq!(stats.claimed, 3);
        assert_eq!(stats.cap, 1000);
    }
}
