use revolt_database::{now_ms, Database, User};
use revolt_models::v0;
use revolt_payments::engine;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;

/// # Fetch Own Cipher Membership
///
/// The session user's Cipher membership and unfinished checkout, if any.
#[openapi(tag = "Payments")]
#[get("/cipher/@me")]
pub async fn me(db: &State<Database>, user: User) -> Result<Json<v0::CipherMe>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // Deliberately NOT gated on `[features.payments]`: a buyer keeps seeing
    // the membership they paid for (and a checkout they already started)
    // after the kill switch is thrown or while that config is unreadable.
    // Only the session user's own rows are read, and the owner-only
    // `disputed` flag never leaves this route.
    Ok(Json(engine::cipher_me(db, &user.id, now_ms()).await?))
}

#[cfg(test)]
mod tests {
    use crate::util::test::TestHarness;
    use revolt_database::{now_ms, Bot, OrderState, PaymentOrder, Session};
    use revolt_models::v0;
    use revolt_payments::catalog;
    use revolt_payments::engine::{self, FulfilOutcome};
    use revolt_payments::settings::PaymentsSettings;
    use rocket::http::{Header, Status};

    /// Payments settings as the routes load them; `Revolt.test.toml`
    /// enables payments and opens the sale
    async fn open_settings() -> PaymentsSettings {
        let s = PaymentsSettings::load().await.expect("payments settings");
        assert!(
            s.sales_open_at(now_ms()),
            "Revolt.test.toml must enable payments and open the sale"
        );
        s
    }

    /// Start a checkout for `user_id` through the engine (the harness's
    /// MockStripe stands in for Stripe); the Pending order it created
    async fn start_checkout(
        harness: &TestHarness,
        s: &PaymentsSettings,
        user_id: &str,
        tier: v0::CipherTier,
    ) -> PaymentOrder {
        let url = engine::create_cipher_checkout(
            &harness.db,
            &*harness.stripe,
            s,
            user_id,
            tier,
            v0::CipherReturnTo::Web,
            now_ms(),
        )
        .await
        .expect("checkout");

        harness
            .db
            .fetch_payment_orders_by_user(user_id, &[OrderState::Pending])
            .await
            .expect("orders")
            .into_iter()
            .find(|o| o.checkout_url.as_deref() == Some(url.as_str()))
            .expect("the checkout's Pending order")
    }

    /// `GET /payments/cipher/@me` as `session`; must answer 200
    async fn fetch_me(harness: &TestHarness, session: Session) -> v0::CipherMe {
        let response =
            TestHarness::with_session(session, harness.client.get("/payments/cipher/@me")).await;
        assert_eq!(response.status(), Status::Ok);
        response
            .into_json::<v0::CipherMe>()
            .await
            .expect("`CipherMe`")
    }

    #[test]
    fn me_requires_session() {
        crate::util::test::rt().block_on(me_requires_session_case())
    }

    async fn me_requires_session_case() {
        let harness = TestHarness::new().await;

        let response = harness.client.get("/payments/cipher/@me").dispatch().await;
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[test]
    fn me_refuses_bots() {
        crate::util::test::rt().block_on(me_refuses_bots_case())
    }

    async fn me_refuses_bots_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("`Bot`");

        let response = harness
            .client
            .get("/payments/cipher/@me")
            .header(Header::new("x-bot-token", bot.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
        let body = response.into_string().await.expect("body");
        assert!(body.contains("IsBot"), "expected IsBot, got {}", body);
    }

    #[test]
    fn me_without_membership_is_empty() {
        crate::util::test::rt().block_on(me_without_membership_is_empty_case())
    }

    async fn me_without_membership_is_empty_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let response =
            TestHarness::with_session(session, harness.client.get("/payments/cipher/@me")).await;
        assert_eq!(response.status(), Status::Ok);

        // Both fields skip when absent: the body is exactly `{}`
        let body = response.into_string().await.expect("body");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({})
        );
    }

    #[test]
    fn me_shows_pending_checkout() {
        crate::util::test::rt().block_on(me_shows_pending_checkout_case())
    }

    async fn me_shows_pending_checkout_case() {
        let harness = TestHarness::new().await;
        let s = open_settings().await;
        let (_, session, user) = harness.new_user().await;
        let (_, _, other) = harness.new_user().await;

        let order = start_checkout(&harness, &s, &user.id, v0::CipherTier::T149).await;
        // Another user's checkout never shows on this user's @me
        start_checkout(&harness, &s, &other.id, v0::CipherTier::T299).await;

        let me = fetch_me(&harness, session).await;
        assert_eq!(me.membership, None);

        let pending = me.pending.expect("pending checkout");
        assert_eq!(pending.order_id, order.id);
        assert_eq!(
            pending.sku,
            v0::Sku::CipherNew {
                tier: v0::CipherTier::T149
            }
        );
        assert_eq!(Some(pending.expires_at), order.session_expires_at);
        assert!(pending.expires_at > now_ms());
    }

    #[test]
    fn me_shows_membership_after_fulfilment() {
        crate::util::test::rt().block_on(me_shows_membership_after_fulfilment_case())
    }

    async fn me_shows_membership_after_fulfilment_case() {
        let harness = TestHarness::new().await;
        let s = open_settings().await;
        // Mongo: init already seeded the table; reference: seed it here
        // (idempotent, so a no-op on Mongo)
        harness
            .db
            .seed_cipher_numbers(s.cap)
            .await
            .expect("seed cipher_numbers");
        let (_, session, user) = harness.new_user().await;

        // Checkout, then the buyer pays and Stripe reports the session paid
        let order = start_checkout(&harness, &s, &user.id, v0::CipherTier::T99).await;
        let session_id = order.checkout_session_id.clone().expect("session id");
        let mut paid = harness.stripe.session(&session_id).expect("session");
        paid.status = Some("complete".to_string());
        paid.payment_status = Some("paid".to_string());
        paid.payment_intent = Some("pi_test_me_1".to_string());
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

        let me = fetch_me(&harness, session).await;
        // The paid order is no longer an unfinished checkout
        assert_eq!(me.pending, None);
        let membership = me.membership.expect("membership");
        assert_eq!(membership.number, 1);
        assert_eq!(membership.tier, v0::CipherTier::T99);
        assert!(!membership.disputed);
        assert_eq!(
            membership.prot_grant,
            catalog::tier_prot(v0::CipherTier::T99)
        );
    }
}
