//! In-app Prot (S6): App Store and Google Play purchases.
//!
//! The engine (`revolt_payments::engine::prot_store`) owns every gate, the
//! store lookups and the money; these routes authenticate, validate the body,
//! load the settings and hand over. The store clients are managed state
//! (`Arc<dyn AppleStoreApi>`, `Arc<dyn PlayStoreApi>`), so route tests swap in
//! the mocks through `TestHarness::apple` and `TestHarness::play`.
use std::sync::Arc;

use revolt_database::{now_ms, Database, User};
use revolt_models::v0;
use revolt_payments::engine;
use revolt_payments::settings::{PaymentsSettings, ProtSalesSettings, ProtStoreSettings};
use revolt_payments::store::{AppleStoreApi, PlayStoreApi};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use rocket_empty::EmptyResponse;
use validator::Validate;

use super::checkout::RequestCountry;

/// # Start In-App Prot Purchase
///
/// Issue the one-time token the app hands to the App Store
/// (`appAccountToken`) or Google Play (`obfuscatedAccountId`), binding the
/// purchase to this account. The Prot is priced from the server's product
/// table; the body only names the store and the product. Bots cannot buy.
/// Refused with `ProtStoreUnavailable` when the store is not configured on
/// this server, `ProtStoreClosed` when it is not open to the caller,
/// `ProtStoreProductUnknown` for a product not on sale, `PaymentPending`
/// with three open intents and `ProtWalletCap` over the wallet cap.
#[openapi(tag = "Payments")]
#[post("/prot/store/intent", data = "<data>")]
pub async fn prot_store_intent(
    db: &State<Database>,
    apple: &State<Arc<dyn AppleStoreApi>>,
    play: &State<Arc<dyn PlayStoreApi>>,
    user: User,
    country: RequestCountry,
    data: Json<v0::DataProtStoreIntent>,
) -> Result<Json<v0::ProtStoreIntentResponse>> {
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
    let st = ProtStoreSettings::load().await?;

    let response = engine::prot_store::create_store_intent(
        db,
        &settings,
        &ps,
        &st,
        &**play.inner(),
        &**apple.inner(),
        &user.id,
        &data,
        country.0.as_deref(),
        now_ms(),
    )
    .await?;

    Ok(Json(response))
}

/// # Verify In-App Prot Purchase
///
/// Report a store purchase for crediting: the App Store's signed
/// transaction, or Google Play's product id and purchase token. The server
/// checks it with the store and credits the account the purchase's token
/// binds, at most once. Answers 200 with `credited` or `already_credited`
/// (balance and ledger row), `pending` (not paid yet, or recorded while
/// credits are paused) or `rejected` with a reason; a purchase bound to
/// another account is `rejected` / `wrong_account` and nothing is written.
/// Works whether or not the store is open. Bots cannot verify.
#[openapi(tag = "Payments")]
#[post("/prot/store/verify", data = "<data>")]
pub async fn prot_store_verify(
    db: &State<Database>,
    apple: &State<Arc<dyn AppleStoreApi>>,
    play: &State<Arc<dyn PlayStoreApi>>,
    user: User,
    data: Json<v0::DataProtStoreVerify>,
) -> Result<Json<v0::ProtStoreVerifyResponse>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Never the Stripe and Cipher settings (R56), and the Prot sale settings
    // fall back to the shipped defaults, logged (R60): the store already took
    // the money, and an unconsumed Play purchase refunds itself after 3
    // days, so a web-sale config typo must not stop the credit. A store
    // config that does not validate credits nothing under a default.
    let ps = ProtSalesSettings::load_or_closed().await;
    let st = ProtStoreSettings::load().await?;

    let response = engine::prot_store::verify_store_purchase(
        db,
        &ps,
        &st,
        &**apple.inner(),
        &**play.inner(),
        &user.id,
        &data,
        now_ms(),
    )
    .await?;

    Ok(Json(response))
}

/// # Cancel In-App Prot Purchase
///
/// The caller's own open intent, Open → Expired. An Expired intent still
/// binds a late purchase, so a cancel never refuses money that arrives
/// anyway; it frees the slot, but its Prot counts toward the wallet cap
/// until it expires (R62). Another user's intent, or one that does not exist,
/// is `NotFound`; a used one is `InvalidOperation`; an already expired one
/// answers 204 again. Not gated on the store switches.
#[openapi(tag = "Payments")]
#[post("/prot/store/intent/<intent_id>/cancel")]
pub async fn prot_store_intent_cancel(
    db: &State<Database>,
    user: User,
    intent_id: String,
) -> Result<EmptyResponse> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    engine::prot_store::cancel_store_intent(db, &user.id, &intent_id).await?;
    Ok(EmptyResponse)
}

#[cfg(test)]
mod tests {
    use revolt_config::FeaturePayments;
    use revolt_database::{now_ms, Account, Bot, Database};
    use revolt_models::v0;
    use revolt_payments::engine;
    use revolt_payments::settings::{PaymentsSettings, ProtSalesSettings, ProtStoreSettings};
    use revolt_payments::store::PlayPurchase;
    use revolt_result::ErrorType;
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::LocalResponse;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    use crate::util::test::TestHarness;

    const INTENT: &str = "/payments/prot/store/intent";
    const VERIFY: &str = "/payments/prot/store/verify";
    const P5: &str = "gg.sloga.prot.p5";
    const P10: &str = "gg.sloga.prot.p10";
    const P25: &str = "gg.sloga.prot.p25";

    fn session_auth(token: &str) -> Option<Header<'static>> {
        Some(Header::new("x-session-token", token.to_string()))
    }

    /// Another session of the same account: the "payments" bucket allows 3
    /// requests per 10 s per session
    async fn another_session(harness: &TestHarness, account: &Account) -> String {
        account
            .create_session(&harness.db, String::new())
            .await
            .expect("`Session`")
            .token
    }

    async fn post<'c>(
        harness: &'c TestHarness,
        auth: Option<Header<'static>>,
        path: String,
        body: Option<Value>,
    ) -> LocalResponse<'c> {
        let mut request = harness.client.post(path);
        if let Some(body) = body {
            request = request.header(ContentType::JSON).body(body.to_string());
        }
        if let Some(auth) = auth {
            request = request.header(auth);
        }
        request.dispatch().await
    }

    async fn ok_json(response: LocalResponse<'_>) -> Value {
        assert_eq!(response.status(), Status::Ok);
        response.into_json().await.expect("a JSON body")
    }

    async fn assert_refused(response: LocalResponse<'_>, status: Status, error_type: &str) {
        assert_eq!(response.status(), status);
        let error: Value = response.into_json().await.expect("error body");
        assert_eq!(error["type"], error_type, "{error}");
    }

    fn cancel_path(intent_id: &str) -> String {
        format!("{INTENT}/{intent_id}/cancel")
    }

    /// `play:{sha256 hex of the token}` (contracts section 4)
    fn play_purchase_id(token: &str) -> String {
        format!("play:{:x}", Sha256::digest(token.as_bytes()))
    }

    /// A purchase token no other test uses
    fn purchase_token() -> String {
        format!("route-test-token.{}", TestHarness::rand_string())
    }

    /// What the productsv2 lookup answers for one unit of `product`
    fn play_purchase(product: &str, account_token: Option<&str>, state: &str) -> PlayPurchase {
        serde_json::from_value(json!({
            "productLineItem": [{
                "productId": product,
                "productOfferDetails": {
                    "quantity": 1,
                    "refundableQuantity": 1,
                    "consumptionState": "CONSUMPTION_STATE_YET_TO_BE_CONSUMED"
                }
            }],
            "purchaseStateContext": { "purchaseState": state },
            "orderId": "GPA.3300-0000-0000-00001",
            "obfuscatedExternalAccountId": account_token,
            "regionCode": "US"
        }))
        .expect("`PlayPurchase`")
    }

    /// Store settings as the routes load them. `Revolt.test.toml` opens both
    /// stores and carries no store credentials: the managed mocks report
    /// `configured()`, the App Store root config is absent.
    async fn open_store_settings() -> ProtStoreSettings {
        let payments = PaymentsSettings::load().await.expect("payments settings");
        let ps = ProtSalesSettings::load().await.expect("prot settings");
        let st = ProtStoreSettings::load().await.expect("store settings");
        assert!(
            payments.enabled && ps.enabled && st.apple_open && st.play_open,
            "Revolt.test.toml must enable payments and Prot and open both stores, or the \
             route tests below prove nothing"
        );
        assert!(
            st.apple.is_none() && st.play.is_none(),
            "Revolt.test.toml must carry no store credentials (the route tests run on the \
             managed mocks)"
        );
        st
    }

    async fn start_intent(
        harness: &TestHarness,
        auth: Option<Header<'static>>,
        store: &str,
        product: &str,
    ) -> v0::ProtStoreIntentResponse {
        let body = ok_json(
            post(
                harness,
                auth,
                INTENT.to_string(),
                Some(json!({ "store": store, "product_id": product })),
            )
            .await,
        )
        .await;
        serde_json::from_value(body).expect("`ProtStoreIntentResponse`")
    }

    async fn intent_state(db: &Database, id: &str) -> v0::ProtStoreIntentState {
        db.fetch_prot_store_intent(id)
            .await
            .expect("intent")
            .expect("the intent row")
            .state
    }

    /// Without a session every store route is 401, and no store is asked
    #[test]
    fn prot_store_routes_require_a_session() {
        crate::util::test::rt().block_on(prot_store_routes_require_a_session_case())
    }

    async fn prot_store_routes_require_a_session_case() {
        let harness = TestHarness::new().await;

        let response = post(
            &harness,
            None,
            INTENT.to_string(),
            Some(json!({ "store": "play", "product_id": P5 })),
        )
        .await;
        assert_eq!(response.status(), Status::Unauthorized);

        let response = post(
            &harness,
            None,
            VERIFY.to_string(),
            Some(json!({ "store": "play", "product_id": P5, "purchase_token": "t" })),
        )
        .await;
        assert_eq!(response.status(), Status::Unauthorized);

        let response = post(
            &harness,
            None,
            cancel_path(&ulid::Ulid::new().to_string()),
            None,
        )
        .await;
        assert_eq!(response.status(), Status::Unauthorized);

        assert!(harness.apple.calls().is_empty());
        assert!(harness.play.calls().is_empty());
    }

    /// A bot authenticates with its token and is refused IsBot by the route
    /// itself, before the body is validated: a body that fails validation
    /// still answers IsBot (control 28: drop the route's bot check and the
    /// first request answers FailedValidation). Nothing is asked of Play and
    /// nothing is written.
    #[test]
    fn bots_cannot_verify() {
        crate::util::test::rt().block_on(bots_cannot_verify_case())
    }

    async fn bots_cannot_verify_case() {
        let harness = TestHarness::new().await;
        open_store_settings().await;
        let (_, _, owner) = harness.new_user().await;
        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("`Bot`");
        let bot_auth = || Some(Header::new("x-bot-token", bot.token.clone()));
        let token = purchase_token();
        harness
            .play
            .set_purchase(&token, Ok(play_purchase(P5, None, "PURCHASED")));

        // Fails validation (an empty purchase token)
        let response = post(
            &harness,
            bot_auth(),
            VERIFY.to_string(),
            Some(json!({ "store": "play", "product_id": P5, "purchase_token": "" })),
        )
        .await;
        assert_refused(response, Status::BadRequest, "IsBot").await;

        let response = post(
            &harness,
            bot_auth(),
            VERIFY.to_string(),
            Some(json!({ "store": "play", "product_id": P5, "purchase_token": token })),
        )
        .await;
        assert_refused(response, Status::BadRequest, "IsBot").await;

        assert!(harness.play.calls().is_empty());
        assert!(harness
            .db
            .fetch_prot_store_purchase(&play_purchase_id(&token))
            .await
            .expect("purchase")
            .is_none());
    }

    /// A bot cannot start an intent (refused before validation, as on
    /// verify) nor cancel one, even a real intent id
    #[test]
    fn bots_cannot_start_or_cancel_a_store_purchase() {
        crate::util::test::rt().block_on(bots_cannot_start_or_cancel_a_store_purchase_case())
    }

    async fn bots_cannot_start_or_cancel_a_store_purchase_case() {
        let harness = TestHarness::new().await;
        open_store_settings().await;
        let (_, session, owner) = harness.new_user().await;
        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("`Bot`");
        let bot_auth = || Some(Header::new("x-bot-token", bot.token.clone()));
        let intent = start_intent(&harness, session_auth(&session.token), "play", P5).await;

        let response = post(
            &harness,
            bot_auth(),
            INTENT.to_string(),
            Some(json!({ "store": "play", "product_id": "" })),
        )
        .await;
        assert_refused(response, Status::BadRequest, "IsBot").await;

        let response = post(&harness, bot_auth(), cancel_path(&intent.intent_id), None).await;
        assert_refused(response, Status::BadRequest, "IsBot").await;

        assert!(harness
            .db
            .fetch_open_prot_store_intents(&bot.id, now_ms())
            .await
            .expect("intents")
            .is_empty());
        assert_eq!(
            intent_state(&harness.db, &intent.intent_id).await,
            v0::ProtStoreIntentState::Open
        );
    }

    /// Play, end to end on the mocks: the intent's token is 43 characters of
    /// base64url; the purchase Play reports with it is credited to the buyer
    /// once, under `purchase:{id}`, and consumed after the credit. A replay
    /// answers already_credited with the same ledger row and balance, and the
    /// used intent can no longer be cancelled.
    #[test]
    fn play_intent_then_verify_credits_the_buyer() {
        crate::util::test::rt().block_on(play_intent_then_verify_credits_the_buyer_case())
    }

    async fn play_intent_then_verify_credits_the_buyer_case() {
        let harness = TestHarness::new().await;
        let st = open_store_settings().await;
        let prot = st
            .product(v0::ProtStore::Play, P5)
            .expect("the default Play p5 product")
            .prot;
        let (account, session, user) = harness.new_user().await;

        let intent = start_intent(&harness, session_auth(&session.token), "play", P5).await;
        assert_eq!(intent.product_id, P5);
        assert_eq!(intent.prot, prot);
        assert!(intent.expires_at > now_ms());
        assert_eq!(intent.token.len(), 43, "base64url of 32 bytes, no padding");
        assert!(intent
            .token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));

        let token = purchase_token();
        let id = play_purchase_id(&token);
        harness.play.set_purchase(
            &token,
            Ok(play_purchase(P5, Some(&intent.token), "PURCHASED")),
        );
        let verify = json!({ "store": "play", "product_id": P5, "purchase_token": token });

        let first = ok_json(
            post(
                &harness,
                session_auth(&session.token),
                VERIFY.to_string(),
                Some(verify.clone()),
            )
            .await,
        )
        .await;
        assert_eq!(first["status"], "credited", "{first}");
        assert_eq!(first["purchase_id"], id.as_str());
        assert_eq!(first["balance"], prot);
        let ledger_id = first["ledger_id"]
            .as_str()
            .expect("`ledger_id`")
            .to_string();
        assert!(first.get("reason").is_none(), "{}", first);

        let row = harness
            .db
            .fetch_prot_store_purchase(&id)
            .await
            .expect("purchase")
            .expect("the purchase row");
        assert_eq!(row.state, v0::ProtStoreState::Credited);
        assert_eq!(row.user_id.as_deref(), Some(user.id.as_str()));
        assert_eq!(row.prot, prot);
        assert_eq!(
            intent_state(&harness.db, &intent.intent_id).await,
            v0::ProtStoreIntentState::Used
        );
        let consume = format!("consume {P5} {:x}", Sha256::digest(token.as_bytes()));
        let consumed = |calls: Vec<String>| calls.iter().filter(|c| **c == consume).count();
        assert_eq!(consumed(harness.play.calls()), 1);
        // No purchase token in the recorded calls, only its hash
        assert!(harness.play.calls().iter().all(|c| !c.contains(&token)));

        // A replay from another session of the same buyer: nothing more
        let second_session = another_session(&harness, &account).await;
        let again = ok_json(
            post(
                &harness,
                session_auth(&second_session),
                VERIFY.to_string(),
                Some(verify),
            )
            .await,
        )
        .await;
        assert_eq!(again["status"], "already_credited", "{again}");
        assert_eq!(again["ledger_id"], ledger_id.as_str());
        assert_eq!(again["balance"], prot);

        let response = post(
            &harness,
            session_auth(&second_session),
            cancel_path(&intent.intent_id),
            None,
        )
        .await;
        assert_refused(response, Status::BadRequest, "InvalidOperation").await;
    }

    /// R56: verify never reads the Stripe and Cipher settings. With
    /// `[features.payments]` broken for Cipher (`cipher_cap = 0`, so no
    /// `PaymentsSettings` builds) the Prot and store settings still build,
    /// and the call the verify route makes credits a Play purchase on the
    /// mocks. The routes read the config through `load()`, and
    /// `overwrite_config` works once per process, so the route itself is
    /// pinned by its source: its body names no `PaymentsSettings` (control:
    /// re-add the load and this fails).
    #[test]
    fn verify_credits_while_the_stripe_settings_are_invalid() {
        crate::util::test::rt()
            .block_on(verify_credits_while_the_stripe_settings_are_invalid_case())
    }

    async fn verify_credits_while_the_stripe_settings_are_invalid_case() {
        let source = include_str!("prot_store.rs");
        let start = source
            .find("pub async fn prot_store_verify(")
            .expect("the verify route");
        let end = start
            + source[start..]
                .find("/// # Cancel In-App Prot Purchase")
                .expect("the route after it");
        let route: Vec<&str> = source[start..end]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();
        let route = route.join("\n");
        assert!(
            route.contains("ProtStoreSettings::load()"),
            "the scan must cover the verify route's body"
        );
        assert!(
            !route.contains("PaymentsSettings"),
            "the verify route must not load or validate PaymentsSettings (R56)"
        );

        let harness = TestHarness::new().await;
        open_store_settings().await;
        let config = revolt_config::config().await;
        let broken = FeaturePayments {
            cipher_cap: 0,
            ..(*config.features.payments).clone()
        };
        assert!(
            PaymentsSettings::from_parts(&broken, &config.api.stripe).is_err(),
            "cipher_cap = 0 must make the payments settings invalid, or this proves nothing"
        );
        let ps = ProtSalesSettings::from_parts(&broken, &config.features.boosts.protection)
            .expect("prot settings");
        let st =
            ProtStoreSettings::from_parts(&broken, &config.api.appstore, &config.api.googleplay)
                .expect("store settings");
        let prot = st
            .product(v0::ProtStore::Play, P5)
            .expect("the default Play p5 product")
            .prot;

        let (_, session, user) = harness.new_user().await;
        let intent = start_intent(&harness, session_auth(&session.token), "play", P5).await;
        let token = purchase_token();
        harness.play.set_purchase(
            &token,
            Ok(play_purchase(P5, Some(&intent.token), "PURCHASED")),
        );
        let data = v0::DataProtStoreVerify {
            store: v0::ProtStore::Play,
            signed_transaction: None,
            product_id: Some(P5.to_string()),
            purchase_token: Some(token.clone()),
        };
        let answer = match engine::prot_store::verify_store_purchase(
            &harness.db,
            &ps,
            &st,
            &*harness.apple,
            &*harness.play,
            &user.id,
            &data,
            now_ms(),
        )
        .await
        {
            Ok(answer) => answer,
            Err(err) => panic!("expected a credit, got {:?}", err.error_type),
        };
        assert_eq!(answer.status, v0::ProtStoreVerifyStatus::Credited);
        assert_eq!(answer.balance, Some(prot));
        assert_eq!(answer.purchase_id, Some(play_purchase_id(&token)));
    }

    /// The code of one route: `source` from `start` to the first `end` after
    /// it, comment lines dropped
    fn route_code(file: &str, source: &str, start: &str, end: &str) -> String {
        let from = source
            .find(start)
            .unwrap_or_else(|| panic!("{}: no {:?}", file, start));
        let to = from
            + source[from..]
                .find(end)
                .unwrap_or_else(|| panic!("{}: no {:?} after {:?}", file, end, start));
        let lines: Vec<&str> = source[from..to]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();
        lines.join("\n")
    }

    /// R60: a web-sale config typo never stops a store credit or refund. The
    /// two routes that settle store money (verify, App Store notifications)
    /// take the Prot sale settings through `load_or_closed()`, pinned by
    /// their source (control: back to `load()?` and this fails), and the
    /// call verify makes credits a Play purchase under that fallback (the
    /// shipped defaults, sales closed).
    #[test]
    fn store_settlement_survives_an_invalid_sale_config() {
        crate::util::test::rt().block_on(store_settlement_survives_an_invalid_sale_config_case())
    }

    async fn store_settlement_survives_an_invalid_sale_config_case() {
        for (file, source, start, end) in [
            (
                "prot_store.rs",
                include_str!("prot_store.rs"),
                "pub async fn prot_store_verify(",
                "/// # Cancel In-App Prot Purchase",
            ),
            (
                "apple_notifications.rs",
                include_str!("apple_notifications.rs"),
                "pub async fn apple_notifications(",
                "fn notification_status(",
            ),
        ] {
            let code = route_code(file, source, start, end);
            assert!(
                code.contains("ProtSalesSettings::load_or_closed()"),
                "{}: the route must take the Prot sale settings through load_or_closed (R60)",
                file
            );
            assert!(
                !code.contains("ProtSalesSettings::load()"),
                "{}: an invalid sale config must not refuse a store credit or refund (R60)",
                file
            );
        }

        let harness = TestHarness::new().await;
        let st = open_store_settings().await;
        let closed = ProtSalesSettings::closed();
        assert!(!closed.sales_open);
        let prot = st
            .product(v0::ProtStore::Play, P10)
            .expect("the default Play p10 product")
            .prot;

        let (_, session, user) = harness.new_user().await;
        let intent = start_intent(&harness, session_auth(&session.token), "play", P10).await;
        let token = purchase_token();
        harness.play.set_purchase(
            &token,
            Ok(play_purchase(P10, Some(&intent.token), "PURCHASED")),
        );
        let data = v0::DataProtStoreVerify {
            store: v0::ProtStore::Play,
            signed_transaction: None,
            product_id: Some(P10.to_string()),
            purchase_token: Some(token.clone()),
        };
        let answer = match engine::prot_store::verify_store_purchase(
            &harness.db,
            &closed,
            &st,
            &*harness.apple,
            &*harness.play,
            &user.id,
            &data,
            now_ms(),
        )
        .await
        {
            Ok(answer) => answer,
            Err(err) => panic!("expected a credit, got {:?}", err.error_type),
        };
        assert_eq!(answer.status, v0::ProtStoreVerifyStatus::Credited);
        assert_eq!(answer.balance, Some(prot));
    }

    /// App Store: the intent's token is a lowercase UUID v4 (the
    /// `appAccountToken`). A verify needs the signed transaction alone, and
    /// without `[api.appstore]` (the test config, as any server with no App
    /// Store credentials) no JWS is ever checked: ProtStoreUnavailable,
    /// nothing asked of Apple. The credit leg of an App Store purchase needs
    /// a JWS signed by a pinned chain and is the engine's test
    /// (`engine::prot_store` tests, `apple_credit`).
    #[test]
    fn apple_intent_then_verify_without_appstore_config() {
        crate::util::test::rt().block_on(apple_intent_then_verify_without_appstore_config_case())
    }

    async fn apple_intent_then_verify_without_appstore_config_case() {
        let harness = TestHarness::new().await;
        let st = open_store_settings().await;
        let prot = st
            .product(v0::ProtStore::Apple, P25)
            .expect("the default App Store p25 product")
            .prot;
        let (_, session, _) = harness.new_user().await;
        let auth = || session_auth(&session.token);

        let intent = start_intent(&harness, auth(), "apple", P25).await;
        assert_eq!(intent.prot, prot);
        let token = intent.token.as_bytes();
        assert_eq!(token.len(), 36, "a hyphenated UUID");
        for (i, b) in token.iter().enumerate() {
            match i {
                8 | 13 | 18 | 23 => assert_eq!(*b, b'-'),
                _ => assert!(
                    b.is_ascii_digit() || (b'a'..=b'f').contains(b),
                    "lowercase hex"
                ),
            }
        }
        assert_eq!(token[14], b'4', "UUID version 4");

        // The body shape is checked first: a Play token is not an App Store
        // purchase
        let response = post(
            &harness,
            auth(),
            VERIFY.to_string(),
            Some(json!({ "store": "apple", "purchase_token": "t" })),
        )
        .await;
        assert_refused(response, Status::BadRequest, "FailedValidation").await;

        let response = post(
            &harness,
            auth(),
            VERIFY.to_string(),
            Some(json!({ "store": "apple", "signed_transaction": "a.b.c" })),
        )
        .await;
        assert_refused(response, Status::ServiceUnavailable, "ProtStoreUnavailable").await;

        assert!(harness.apple.calls().is_empty());
    }

    /// A Play purchase bound to another account's intent: 200 `rejected` /
    /// `wrong_account` with no purchase id, nothing written, nothing
    /// consumed, the intent still open. The buyer's own verify then credits
    /// it to the buyer.
    #[test]
    fn verify_of_another_accounts_purchase_is_rejected_and_writes_nothing() {
        crate::util::test::rt()
            .block_on(verify_of_another_accounts_purchase_is_rejected_and_writes_nothing_case())
    }

    async fn verify_of_another_accounts_purchase_is_rejected_and_writes_nothing_case() {
        let harness = TestHarness::new().await;
        let st = open_store_settings().await;
        let prot = st
            .product(v0::ProtStore::Play, P10)
            .expect("the default Play p10 product")
            .prot;
        let (_, buyer_session, buyer) = harness.new_user().await;
        let (_, other_session, _) = harness.new_user().await;

        let intent = start_intent(&harness, session_auth(&buyer_session.token), "play", P10).await;
        let token = purchase_token();
        let id = play_purchase_id(&token);
        harness.play.set_purchase(
            &token,
            Ok(play_purchase(P10, Some(&intent.token), "PURCHASED")),
        );
        let verify = json!({ "store": "play", "product_id": P10, "purchase_token": token });

        let refused = ok_json(
            post(
                &harness,
                session_auth(&other_session.token),
                VERIFY.to_string(),
                Some(verify.clone()),
            )
            .await,
        )
        .await;
        assert_eq!(
            refused,
            json!({ "status": "rejected", "reason": "wrong_account" })
        );
        assert!(harness
            .db
            .fetch_prot_store_purchase(&id)
            .await
            .expect("purchase")
            .is_none());
        assert_eq!(
            intent_state(&harness.db, &intent.intent_id).await,
            v0::ProtStoreIntentState::Open
        );
        assert!(harness
            .play
            .calls()
            .iter()
            .all(|c| !c.starts_with("consume ")));

        let response = harness
            .client
            .get("/payments/prot/@me")
            .header(Header::new("x-session-token", other_session.token.clone()))
            .dispatch()
            .await;
        assert_eq!(ok_json(response).await["balance"], 0);

        let credited = ok_json(
            post(
                &harness,
                session_auth(&buyer_session.token),
                VERIFY.to_string(),
                Some(verify),
            )
            .await,
        )
        .await;
        assert_eq!(credited["status"], "credited", "{credited}");
        assert_eq!(credited["balance"], prot);
        let row = harness
            .db
            .fetch_prot_store_purchase(&id)
            .await
            .expect("purchase")
            .expect("the purchase row");
        assert_eq!(row.user_id.as_deref(), Some(buyer.id.as_str()));
    }

    /// The managed client decides whether a store is sold through (audit
    /// N4): a Play client without RTDN, or an App Store client without
    /// credentials, refuses new intents with ProtStoreUnavailable (503),
    /// while the other store still sells
    #[test]
    fn store_intent_needs_a_configured_client() {
        crate::util::test::rt().block_on(store_intent_needs_a_configured_client_case())
    }

    async fn store_intent_needs_a_configured_client_case() {
        let harness = TestHarness::new().await;
        open_store_settings().await;
        let (_, session, user) = harness.new_user().await;
        let auth = || session_auth(&session.token);

        harness.play.no_pubsub();
        let response = post(
            &harness,
            auth(),
            INTENT.to_string(),
            Some(json!({ "store": "play", "product_id": P5 })),
        )
        .await;
        assert_refused(response, Status::ServiceUnavailable, "ProtStoreUnavailable").await;

        start_intent(&harness, auth(), "apple", P5).await;

        harness.apple.unconfigured();
        let response = post(
            &harness,
            auth(),
            INTENT.to_string(),
            Some(json!({ "store": "apple", "product_id": P5 })),
        )
        .await;
        assert_refused(response, Status::ServiceUnavailable, "ProtStoreUnavailable").await;

        let open = harness
            .db
            .fetch_open_prot_store_intents(&user.id, now_ms())
            .await
            .expect("intents");
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].store, v0::ProtStore::Apple);
    }

    /// A closed store refuses new intents with ProtStoreClosed unless the
    /// caller is on the preview list, who also reads `store_preview`.
    ///
    /// The routes read the config through `load()`, and `overwrite_config`
    /// works once per process, so it cannot be closed for one test. This
    /// drives the engine call the intent route makes, with the loaded
    /// settings altered, on the harness's database and managed mocks.
    #[test]
    fn closed_store_is_refused_unless_previewed() {
        crate::util::test::rt().block_on(closed_store_is_refused_unless_previewed_case())
    }

    async fn closed_store_is_refused_unless_previewed_case() {
        let harness = TestHarness::new().await;
        let st = open_store_settings().await;
        let payments = PaymentsSettings::load().await.expect("payments settings");
        let ps = ProtSalesSettings::load().await.expect("prot settings");
        let (_, _, user) = harness.new_user().await;
        let (_, _, previewer) = harness.new_user().await;

        let mut closed = st.clone();
        closed.apple_open = false;
        closed.play_open = false;
        closed.preview_user_ids = vec![previewer.id.clone()];

        for (store, product) in [(v0::ProtStore::Apple, P5), (v0::ProtStore::Play, P5)] {
            let data = v0::DataProtStoreIntent {
                store,
                product_id: product.to_string(),
            };
            let result = engine::prot_store::create_store_intent(
                &harness.db,
                &payments,
                &ps,
                &closed,
                &*harness.play,
                &*harness.apple,
                &user.id,
                &data,
                None,
                now_ms(),
            )
            .await;
            match result {
                Err(err) => assert!(
                    matches!(err.error_type, ErrorType::ProtStoreClosed),
                    "{:?}",
                    err.error_type
                ),
                Ok(_) => panic!("expected ProtStoreClosed for {:?}", store),
            }

            let previewed = engine::prot_store::create_store_intent(
                &harness.db,
                &payments,
                &ps,
                &closed,
                &*harness.play,
                &*harness.apple,
                &previewer.id,
                &data,
                None,
                now_ms(),
            )
            .await;
            if let Err(err) = previewed {
                panic!(
                    "expected an intent for the previewer, got {:?}",
                    err.error_type
                );
            }
        }

        assert!(engine::prot_store::store_preview(&closed, &previewer.id));
        assert!(!engine::prot_store::store_preview(&closed, &user.id));
        assert!(harness
            .db
            .fetch_open_prot_store_intents(&user.id, now_ms())
            .await
            .expect("intents")
            .is_empty());
    }

    /// Only the caller's own intent is cancelled: another user's, a missing
    /// one and a malformed id are all NotFound and change nothing. Open →
    /// Expired answers 204, and again 204 once Expired.
    #[test]
    fn cancel_frees_only_the_callers_own_open_intent() {
        crate::util::test::rt().block_on(cancel_frees_only_the_callers_own_open_intent_case())
    }

    async fn cancel_frees_only_the_callers_own_open_intent_case() {
        let harness = TestHarness::new().await;
        open_store_settings().await;
        let (_, session, user) = harness.new_user().await;
        let (_, other_session, _) = harness.new_user().await;

        let intent = start_intent(&harness, session_auth(&session.token), "apple", P10).await;

        for id in [
            intent.intent_id.clone(),
            ulid::Ulid::new().to_string(),
            "not-an-intent".to_string(),
        ] {
            let response = post(
                &harness,
                session_auth(&other_session.token),
                cancel_path(&id),
                None,
            )
            .await;
            assert_refused(response, Status::NotFound, "NotFound").await;
        }
        assert_eq!(
            intent_state(&harness.db, &intent.intent_id).await,
            v0::ProtStoreIntentState::Open
        );

        for _ in 0..2 {
            let response = post(
                &harness,
                session_auth(&session.token),
                cancel_path(&intent.intent_id),
                None,
            )
            .await;
            assert_eq!(response.status(), Status::NoContent);
        }
        assert_eq!(
            intent_state(&harness.db, &intent.intent_id).await,
            v0::ProtStoreIntentState::Expired
        );
        assert!(harness
            .db
            .fetch_open_prot_store_intents(&user.id, now_ms())
            .await
            .expect("intents")
            .is_empty());
    }
}
