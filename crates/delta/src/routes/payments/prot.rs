use std::sync::Arc;

use revolt_database::{now_ms, Database, User};
use revolt_models::v0;
use revolt_payments::catalog::ProtChoice;
use revolt_payments::engine;
use revolt_payments::settings::{PaymentsSettings, ProtSalesSettings};
use revolt_payments::stripe::StripeApi;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

use super::checkout::RequestCountry;

/// Refuse a checkout from a country Prot is not sold to
/// (`prot_blocked_countries`). An unknown country passes: fulfilment voids
/// and refunds a payment billed to a blocked one.
fn refuse_blocked_prot_region(ps: &ProtSalesSettings, country: Option<&str>) -> Result<()> {
    match country {
        Some(country) if ps.region_blocked(country) => Err(create_error!(ProtRegionUnavailable)),
        _ => Ok(()),
    }
}

/// What the body asks for: exactly one of a pack id or a pay-exact amount.
/// Both or neither is refused; the engine's quote checks the pack id and
/// the amount's bounds.
fn prot_choice(data: &v0::DataProtCheckout) -> Result<ProtChoice> {
    match (&data.pack, data.exact_cents) {
        (Some(pack), None) => Ok(ProtChoice::Pack(pack.clone())),
        (None, Some(cents)) => Ok(ProtChoice::ExactCents(cents)),
        _ => Err(create_error!(ProtPackInvalid)),
    }
}

/// # Start Prot Checkout
///
/// Create (or reuse) a Stripe Checkout session for a Prot pack or a
/// pay-exact amount and return the hosted page to send the user to. The
/// server prices the order from its own config; the body only names the
/// pack or the amount. Bots cannot buy. Refused with `ProtRegionUnavailable`
/// from a country Prot is not sold to.
#[openapi(tag = "Payments")]
#[post("/prot/checkout", data = "<data>")]
pub async fn prot_checkout(
    db: &State<Database>,
    stripe: &State<Arc<dyn StripeApi>>,
    user: User,
    country: RequestCountry,
    data: Json<v0::DataProtCheckout>,
) -> Result<Json<v0::ProtCheckoutResponse>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // A config that fails validation refuses the request rather than
    // selling under a default
    let settings = PaymentsSettings::load().await?;
    let ps = ProtSalesSettings::load().await?;
    refuse_blocked_prot_region(&ps, country.0.as_deref())?;
    let choice = prot_choice(&data)?;

    // The engine owns every other gate: payments and Prot enabled, the sale
    // open, no open dispute, the quote, the wallet cap, and one live Prot
    // order per user (an unexpired one for the same pack returns its URL)
    let stripe: &dyn StripeApi = &**stripe.inner();
    let url = engine::prot::create_prot_checkout(
        db,
        stripe,
        &settings,
        &ps,
        &user.id,
        choice,
        data.return_to,
        now_ms(),
    )
    .await?;

    Ok(Json(v0::ProtCheckoutResponse { url }))
}

/// # Fetch Own Prot Wallet
///
/// The session user's Prot balance, the part of it still under the purchase
/// hold, their unfinished Prot checkout if any, and the 20 newest ledger
/// rows of their wallet.
#[openapi(tag = "Payments")]
#[get("/prot/@me")]
pub async fn prot_me(db: &State<Database>, user: User) -> Result<Json<v0::ProtMe>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // Gated on `[features.boosts.protection] enabled` (the engine answers
    // ProtDisabled). Only the session user's own wallet is read.
    let ps = ProtSalesSettings::load().await?;
    Ok(Json(
        engine::prot::prot_me(db, &ps, &user.id, now_ms()).await?,
    ))
}

#[cfg(test)]
mod tests {
    use revolt_database::{now_ms, Bot, Database, OrderState, PaymentOrder};
    use revolt_models::v0;
    use revolt_payments::catalog::ProtChoice;
    use revolt_payments::engine;
    use revolt_payments::settings::{PaymentsSettings, ProtSalesSettings};
    use revolt_result::ErrorType;
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::LocalResponse;
    use serde_json::json;

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

    fn session_auth(token: &str) -> Option<Header<'static>> {
        Some(Header::new("x-session-token", token.to_string()))
    }

    /// Prot settings as the routes load them; `Revolt.test.toml` turns Prot
    /// on and opens the sale
    async fn open_prot_settings() -> ProtSalesSettings {
        let payments = PaymentsSettings::load().await.expect("payments settings");
        let ps = ProtSalesSettings::load().await.expect("prot settings");
        assert!(
            ps.checkout_open(&payments),
            "Revolt.test.toml must enable payments and Prot and open the Prot sale, \
             or the route tests below prove nothing"
        );
        ps
    }

    async fn prot_checkout_with<'c>(
        harness: &'c TestHarness,
        auth: Option<Header<'static>>,
        body: serde_json::Value,
    ) -> LocalResponse<'c> {
        let mut request = harness
            .client
            .post("/payments/prot/checkout")
            .header(ContentType::JSON)
            .body(body.to_string());
        if let Some(auth) = auth {
            request = request.header(auth);
        }
        request.dispatch().await
    }

    async fn prot_me_with<'c>(
        harness: &'c TestHarness,
        auth: Option<Header<'static>>,
    ) -> LocalResponse<'c> {
        let mut request = harness.client.get("/payments/prot/@me");
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

    async fn pending_of(db: &Database, user_id: &str) -> Vec<PaymentOrder> {
        db.fetch_payment_orders_by_user(user_id, &[OrderState::Pending])
            .await
            .expect("orders")
    }

    #[test]
    fn prot_routes_require_a_session() {
        crate::util::test::rt().block_on(prot_routes_require_a_session_case())
    }

    async fn prot_routes_require_a_session_case() {
        let harness = TestHarness::new().await;

        let response =
            prot_checkout_with(&harness, None, json!({ "pack": "p25", "return_to": "web" })).await;
        assert_eq!(response.status(), Status::Unauthorized);

        let response = prot_me_with(&harness, None).await;
        assert_eq!(response.status(), Status::Unauthorized);

        assert!(harness.stripe.calls().is_empty());
    }

    /// A bot authenticates with its token and is refused on both routes
    /// before anything is stored or sent to Stripe
    #[test]
    fn prot_routes_refuse_bots() {
        crate::util::test::rt().block_on(prot_routes_refuse_bots_case())
    }

    async fn prot_routes_refuse_bots_case() {
        let harness = TestHarness::new().await;
        open_prot_settings().await;
        let (_, _, owner) = harness.new_user().await;
        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("`Bot`");
        let bot_auth = || Some(Header::new("x-bot-token", bot.token.clone()));

        let response = prot_checkout_with(
            &harness,
            bot_auth(),
            json!({ "pack": "p25", "return_to": "web" }),
        )
        .await;
        assert_refused(response, Status::BadRequest, "IsBot").await;

        let response = prot_me_with(&harness, bot_auth()).await;
        assert_refused(response, Status::BadRequest, "IsBot").await;

        assert_eq!(harness.stripe.call_count(CREATE_SESSION), 0);
        assert_eq!(orders_of(&harness.db, &bot.id).await, 0);
    }

    /// A pack is priced from the server's config: price and Prot fields the
    /// client adds to the body are ignored. The order is Pending with the
    /// stamped pack SKU, Stripe is called once under the order's id, and the
    /// web return uses the Prot success and cancel URLs.
    #[test]
    fn prot_checkout_prices_a_pack_on_the_server() {
        crate::util::test::rt().block_on(prot_checkout_prices_a_pack_on_the_server_case())
    }

    async fn prot_checkout_prices_a_pack_on_the_server_case() {
        let harness = TestHarness::new().await;
        let ps = open_prot_settings().await;
        let pack = ps.pack("p25").expect("the default p25 pack").clone();
        let (_, session, user) = harness.new_user().await;

        let response = prot_checkout_with(
            &harness,
            session_auth(&session.token),
            json!({
                "pack": "p25",
                "return_to": "web",
                // Forged: never read
                "cents": 1,
                "prot": 999_999,
                "amount_cents": 1,
                "sku": { "type": "ProtExact", "prot": 999_999 }
            }),
        )
        .await;
        let url = url_of(response).await;

        let pending = pending_of(&harness.db, &user.id).await;
        assert_eq!(pending.len(), 1);
        assert_eq!(orders_of(&harness.db, &user.id).await, 1);
        let order = &pending[0];
        assert_eq!(order.checkout_url.as_deref(), Some(url.as_str()));
        assert_eq!(
            order.sku,
            v0::Sku::ProtPack {
                pack: "p25".to_string(),
                prot: pack.prot,
                cents: pack.cents,
            }
        );
        assert_eq!(order.amount_cents, pack.cents);

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
        assert_eq!(params[0].amount_cents, pack.cents);
        assert_eq!(params[0].success_url, ps.success_url);
        assert_eq!(params[0].cancel_url, ps.cancel_url);
    }

    /// Pay-exact: `exact_cents` buys that many Prot for that many cents, and
    /// the shell return sends both outcomes to the shell return page
    #[test]
    fn prot_checkout_buys_an_exact_amount_with_the_shell_return() {
        crate::util::test::rt()
            .block_on(prot_checkout_buys_an_exact_amount_with_the_shell_return_case())
    }

    async fn prot_checkout_buys_an_exact_amount_with_the_shell_return_case() {
        let harness = TestHarness::new().await;
        let ps = open_prot_settings().await;
        let (_, session, user) = harness.new_user().await;
        let cents = ps.exact_min_cents + 1;
        assert!(cents <= ps.exact_max_cents);

        let response = prot_checkout_with(
            &harness,
            session_auth(&session.token),
            json!({ "exact_cents": cents, "return_to": "shell" }),
        )
        .await;
        let url = url_of(response).await;

        let pending = pending_of(&harness.db, &user.id).await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].checkout_url.as_deref(), Some(url.as_str()));
        assert_eq!(pending[0].sku, v0::Sku::ProtExact { prot: cents });
        assert_eq!(pending[0].amount_cents, cents);

        let params = harness.stripe.checkout_params();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].amount_cents, cents);
        assert_eq!(params[0].success_url, ps.shell_return_url);
        assert_eq!(params[0].cancel_url, ps.shell_return_url);
    }

    /// Both a pack and an amount, or neither: ProtPackInvalid, refused
    /// before anything is stored or sent to Stripe
    #[test]
    fn prot_checkout_needs_exactly_one_of_pack_or_amount() {
        crate::util::test::rt().block_on(prot_checkout_needs_exactly_one_of_pack_or_amount_case())
    }

    async fn prot_checkout_needs_exactly_one_of_pack_or_amount_case() {
        let harness = TestHarness::new().await;
        let ps = open_prot_settings().await;
        let (_, session, user) = harness.new_user().await;

        for body in [
            json!({ "pack": "p25", "exact_cents": ps.exact_min_cents, "return_to": "web" }),
            json!({ "return_to": "web" }),
            json!({ "pack": null, "exact_cents": null, "return_to": "web" }),
        ] {
            let response = prot_checkout_with(&harness, session_auth(&session.token), body).await;
            assert_refused(response, Status::BadRequest, "ProtPackInvalid").await;
        }

        assert!(harness.stripe.calls().is_empty());
        assert_eq!(orders_of(&harness.db, &user.id).await, 0);
    }

    /// An unknown pack and an amount outside the configured bounds are
    /// refused by the server's quote; a pack id outside 1..=16 characters
    /// fails validation first. Nothing is stored or sent to Stripe.
    #[test]
    fn prot_checkout_refuses_unknown_packs_and_out_of_range_amounts() {
        crate::util::test::rt()
            .block_on(prot_checkout_refuses_unknown_packs_and_out_of_range_amounts_case())
    }

    async fn prot_checkout_refuses_unknown_packs_and_out_of_range_amounts_case() {
        let harness = TestHarness::new().await;
        let ps = open_prot_settings().await;
        assert!(ps.pack("p7").is_none());

        // A new user and session for each request: the checkout bucket
        // ("payments") allows 3 requests per 10 s per session
        let mut users = vec![];
        for body in [
            json!({ "pack": "p7", "return_to": "web" }),
            json!({ "pack": "p25x", "return_to": "web" }),
            json!({ "exact_cents": ps.exact_min_cents - 1, "return_to": "web" }),
            json!({ "exact_cents": ps.exact_max_cents + 1, "return_to": "web" }),
            json!({ "exact_cents": 0, "return_to": "web" }),
            json!({ "exact_cents": -500, "return_to": "web" }),
        ] {
            let (_, session, user) = harness.new_user().await;
            let response = prot_checkout_with(&harness, session_auth(&session.token), body).await;
            assert_refused(response, Status::BadRequest, "ProtPackInvalid").await;
            users.push(user);
        }

        for pack in ["", "p0000000000000000"] {
            let (_, session, user) = harness.new_user().await;
            let response = prot_checkout_with(
                &harness,
                session_auth(&session.token),
                json!({ "pack": pack, "return_to": "web" }),
            )
            .await;
            assert_refused(response, Status::BadRequest, "FailedValidation").await;
            users.push(user);
        }

        assert!(harness.stripe.calls().is_empty());
        for user in &users {
            assert_eq!(orders_of(&harness.db, &user.id).await, 0);
        }
    }

    /// While a Prot order is Pending and unexpired, the same pack returns
    /// the stored URL (one Stripe call, one order); a different pack would
    /// be a second live Prot order and is refused
    #[test]
    fn prot_pending_order_returns_its_url_and_blocks_another_pack() {
        crate::util::test::rt()
            .block_on(prot_pending_order_returns_its_url_and_blocks_another_pack_case())
    }

    async fn prot_pending_order_returns_its_url_and_blocks_another_pack_case() {
        let harness = TestHarness::new().await;
        open_prot_settings().await;
        let (_, session, user) = harness.new_user().await;
        let auth = || session_auth(&session.token);
        let body = json!({ "pack": "p10", "return_to": "web" });

        let first = url_of(prot_checkout_with(&harness, auth(), body.clone()).await).await;
        let second = url_of(prot_checkout_with(&harness, auth(), body).await).await;
        assert_eq!(first, second);
        assert_eq!(harness.stripe.call_count(CREATE_SESSION), 1);
        assert_eq!(orders_of(&harness.db, &user.id).await, 1);

        let response = prot_checkout_with(
            &harness,
            session_auth(&session.token),
            json!({ "pack": "p50", "return_to": "web" }),
        )
        .await;
        assert_refused(response, Status::Conflict, "PaymentPending").await;

        assert_eq!(harness.stripe.call_count(CREATE_SESSION), 1);
        assert_eq!(orders_of(&harness.db, &user.id).await, 1);
    }

    /// One live order per family: a Pending Cipher checkout does not block
    /// a Prot one, and the Prot one does not block the Cipher one
    #[test]
    fn a_pending_cipher_checkout_does_not_block_a_prot_pack() {
        crate::util::test::rt()
            .block_on(a_pending_cipher_checkout_does_not_block_a_prot_pack_case())
    }

    async fn a_pending_cipher_checkout_does_not_block_a_prot_pack_case() {
        let harness = TestHarness::new().await;
        open_prot_settings().await;
        let (_, session, user) = harness.new_user().await;

        let cipher = harness
            .client
            .post("/payments/cipher/checkout")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .body(json!({ "tier": "T99", "return_to": "web" }).to_string())
            .dispatch()
            .await;
        let cipher_url = url_of(cipher).await;

        let prot_url = url_of(
            prot_checkout_with(
                &harness,
                session_auth(&session.token),
                json!({ "pack": "p5", "return_to": "web" }),
            )
            .await,
        )
        .await;
        assert_ne!(cipher_url, prot_url);

        // The Cipher one is still reusable: the Prot order did not replace it
        let again = harness
            .client
            .post("/payments/cipher/checkout")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .body(json!({ "tier": "T99", "return_to": "web" }).to_string())
            .dispatch()
            .await;
        assert_eq!(url_of(again).await, cipher_url);

        let pending = pending_of(&harness.db, &user.id).await;
        assert_eq!(pending.len(), 2);
        assert_eq!(harness.stripe.call_count(CREATE_SESSION), 2);
    }

    /// No account yet: zeros, an empty list, and no `pending_order` key
    #[test]
    fn prot_me_without_a_wallet_is_empty() {
        crate::util::test::rt().block_on(prot_me_without_a_wallet_is_empty_case())
    }

    async fn prot_me_without_a_wallet_is_empty_case() {
        let harness = TestHarness::new().await;
        open_prot_settings().await;
        let (_, session, _) = harness.new_user().await;

        let response = prot_me_with(&harness, session_auth(&session.token)).await;
        assert_eq!(response.status(), Status::Ok);
        let body: serde_json::Value = response.into_json().await.expect("`ProtMe`");
        assert_eq!(
            body,
            json!({ "balance": 0, "held": 0, "version": 0, "recent": [] })
        );
    }

    /// The session user's unfinished Prot checkout shows on their @me;
    /// another user's never does, and a Cipher checkout is not a Prot one
    #[test]
    fn prot_me_shows_only_the_own_pending_prot_checkout() {
        crate::util::test::rt().block_on(prot_me_shows_only_the_own_pending_prot_checkout_case())
    }

    async fn prot_me_shows_only_the_own_pending_prot_checkout_case() {
        let harness = TestHarness::new().await;
        let ps = open_prot_settings().await;
        let (_, session, user) = harness.new_user().await;
        let (_, other_session, _) = harness.new_user().await;
        let (_, cipher_session, _) = harness.new_user().await;

        url_of(
            prot_checkout_with(
                &harness,
                session_auth(&session.token),
                json!({ "exact_cents": ps.exact_min_cents, "return_to": "web" }),
            )
            .await,
        )
        .await;
        url_of(
            prot_checkout_with(
                &harness,
                session_auth(&other_session.token),
                json!({ "pack": "p100", "return_to": "web" }),
            )
            .await,
        )
        .await;
        let cipher = harness
            .client
            .post("/payments/cipher/checkout")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", cipher_session.token.clone()))
            .body(json!({ "tier": "T99", "return_to": "web" }).to_string())
            .dispatch()
            .await;
        url_of(cipher).await;

        let order = pending_of(&harness.db, &user.id)
            .await
            .into_iter()
            .next()
            .expect("the Prot order");

        let response = prot_me_with(&harness, session_auth(&session.token)).await;
        assert_eq!(response.status(), Status::Ok);
        let me: v0::ProtMe = response.into_json().await.expect("`ProtMe`");
        assert_eq!(me.balance, 0);
        assert_eq!(me.held, 0);
        assert!(me.recent.is_empty());
        let pending = me.pending_order.expect("the pending Prot checkout");
        assert_eq!(pending.order_id, order.id);
        assert_eq!(
            pending.sku,
            v0::Sku::ProtExact {
                prot: ps.exact_min_cents
            }
        );
        assert_eq!(Some(pending.expires_at), order.session_expires_at);
        assert!(pending.expires_at > now_ms());

        // A Cipher checkout is never shown as a pending Prot one
        let response = prot_me_with(&harness, session_auth(&cipher_session.token)).await;
        assert_eq!(response.status(), Status::Ok);
        let me: v0::ProtMe = response.into_json().await.expect("`ProtMe`");
        assert_eq!(me.pending_order, None);
    }

    /// Payments off, Prot off, or the Prot sale closed: refused before any
    /// order is stored or Stripe is called, and @me answers ProtDisabled
    /// while Prot is off.
    ///
    /// The routes read the config through `load()`, and `overwrite_config`
    /// works once per process, so it cannot be flipped for one test. This
    /// drives the engine calls the routes make, with the loaded settings
    /// altered, on the harness's database and mock Stripe.
    #[test]
    fn prot_disabled_or_closed_is_refused() {
        crate::util::test::rt().block_on(prot_disabled_or_closed_is_refused_case())
    }

    async fn prot_disabled_or_closed_is_refused_case() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let payments = PaymentsSettings::load().await.expect("payments settings");
        let ps = open_prot_settings().await;

        let mut payments_off = payments.clone();
        payments_off.enabled = false;
        let mut prot_off = ps.clone();
        prot_off.enabled = false;
        let mut closed = ps.clone();
        closed.sales_open = false;

        for (s, p, expected) in [
            (&payments_off, &ps, "PaymentsDisabled"),
            (&payments, &prot_off, "ProtDisabled"),
            (&payments, &closed, "ProtSalesClosed"),
        ] {
            let result = engine::prot::create_prot_checkout(
                &harness.db,
                &*harness.stripe,
                s,
                p,
                &user.id,
                ProtChoice::Pack("p25".to_string()),
                v0::CipherReturnTo::Web,
                now_ms(),
            )
            .await;
            match result {
                Err(err) => match (&err.error_type, expected) {
                    (ErrorType::PaymentsDisabled, "PaymentsDisabled")
                    | (ErrorType::ProtDisabled, "ProtDisabled")
                    | (ErrorType::ProtSalesClosed, "ProtSalesClosed") => {}
                    (other, _) => panic!("expected {}, got {:?}", expected, other),
                },
                Ok(url) => panic!("expected {}, got a checkout URL {}", expected, url),
            }
        }

        match engine::prot::prot_me(&harness.db, &prot_off, &user.id, now_ms()).await {
            Err(err) => assert!(
                matches!(err.error_type, ErrorType::ProtDisabled),
                "{:?}",
                err.error_type
            ),
            Ok(me) => panic!("expected ProtDisabled, got {:?}", me),
        }

        assert!(harness.stripe.calls().is_empty());
        assert_eq!(orders_of(&harness.db, &user.id).await, 0);
    }

    /// Without `trust_cloudflare` (the test config, as the shipped one) the
    /// `CF-IPCountry` header is the client's word: a blocked country in it
    /// is ignored and the checkout goes ahead
    #[test]
    fn prot_country_header_is_ignored_without_trust_cloudflare() {
        crate::util::test::rt()
            .block_on(prot_country_header_is_ignored_without_trust_cloudflare_case())
    }

    async fn prot_country_header_is_ignored_without_trust_cloudflare_case() {
        let harness = TestHarness::new().await;
        let ps = open_prot_settings().await;
        let (_, session, user) = harness.new_user().await;
        assert!(
            !revolt_config::config().await.api.security.trust_cloudflare,
            "the test config must not trust Cloudflare, or this test proves nothing"
        );
        assert!(ps.region_blocked("DE"));

        let response = harness
            .client
            .post("/payments/prot/checkout")
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .header(Header::new("CF-IPCountry", "DE"))
            .body(json!({ "pack": "p25", "return_to": "web" }).to_string())
            .dispatch()
            .await;
        url_of(response).await;
        assert_eq!(harness.stripe.call_count(CREATE_SESSION), 1);
        assert_eq!(orders_of(&harness.db, &user.id).await, 1);
    }

    /// A country (as `RequestCountry` hands it over, already uppercased) in
    /// `prot_blocked_countries` is refused with ProtRegionUnavailable, never
    /// the Cipher error; anything else, or no country, goes ahead.
    ///
    /// The test config does not trust Cloudflare, so this drives the
    /// refusal the route makes with the country passed in.
    #[test]
    fn a_blocked_country_is_refused_for_prot() {
        crate::util::test::rt().block_on(a_blocked_country_is_refused_for_prot_case())
    }

    async fn a_blocked_country_is_refused_for_prot_case() {
        let ps = ProtSalesSettings::load().await.expect("prot settings");
        let refused = |country: Option<&str>| {
            super::refuse_blocked_prot_region(&ps, country)
                .err()
                .map(|err| err.error_type)
        };

        for country in ["DE", "FR", "GB", "IE", "SE"] {
            assert!(
                matches!(
                    refused(Some(country)),
                    Some(ErrorType::ProtRegionUnavailable)
                ),
                "{}",
                country
            );
        }
        for country in [None, Some("US"), Some("BR"), Some("XX"), Some("T1")] {
            assert!(refused(country).is_none(), "{:?}", country);
        }

        let error = super::refuse_blocked_prot_region(&ps, Some("DE")).unwrap_err();
        let value = serde_json::to_value(&error).unwrap();
        assert_eq!(value, json!({ "type": "ProtRegionUnavailable" }));
    }

    /// The body maps to exactly one choice
    #[test]
    fn prot_choice_takes_exactly_one_of_pack_or_amount() {
        let body = |pack: Option<&str>, exact_cents: Option<i64>| v0::DataProtCheckout {
            pack: pack.map(str::to_string),
            exact_cents,
            return_to: v0::CipherReturnTo::Web,
        };

        assert_eq!(
            super::prot_choice(&body(Some("p25"), None)).ok(),
            Some(ProtChoice::Pack("p25".to_string()))
        );
        assert_eq!(
            super::prot_choice(&body(None, Some(1234))).ok(),
            Some(ProtChoice::ExactCents(1234))
        );
        for (pack, exact) in [(Some("p25"), Some(1234)), (None, None)] {
            let err = super::prot_choice(&body(pack, exact)).unwrap_err();
            assert!(
                matches!(err.error_type, ErrorType::ProtPackInvalid),
                "{:?}",
                err.error_type
            );
        }
    }
}
