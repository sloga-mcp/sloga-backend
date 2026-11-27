//! In-memory store clients for tests and the `test-mock` feature (S6 contracts 11.2), the
//! `stripe::MockStripe` pattern.
//!
//! [`MockAppleStore`] and [`MockPlayStore`] answer what a test scripted and record every call as one
//! line, purchase tokens as their SHA-256 hex (`calls()`):
//! - `transaction_info {Production|Sandbox} {transactionId}`
//! - `notification_history {env} {start_ms} {end_ms} {paginationToken|-}`
//! - `product_purchase {sha256 of token}`
//! - `consume {productId} {sha256 of token}`, e.g. `consume gg.sloga.prot.p5 <sha256 of token>`
//! - `voided_purchases {start_ms} {pageToken|-}`
//! - `pull {max_messages}` and `acknowledge {ackId,ackId,..}`
//!
//! `configured()` is true unless `unconfigured()` was called; `pubsub_configured()` is true unless
//! `no_pubsub()` or `unconfigured()` was called. An unconfigured client (and `pull` / `acknowledge`
//! without Pub/Sub) answers `NotConfigured`; the call is still recorded, so a test sees a gate that
//! should have stopped it. Ids and tokens no store could hold are `NotFound`, as on the reqwest
//! clients.
//!
//! Behaviour:
//! - `transaction_info` / `product_purchase` answer what `set_transaction_info` / `set_purchase`
//!   set for that id or token (every time), else `NotFound`
//! - `notification_history` / `voided_purchases` serve the pages of `set_history` / `set_voided`
//!   in order, then an empty last page
//! - `consume` fails with what `fail_consume` set for the token (every time); otherwise it succeeds
//!   and, as on Play, a purchase set for the token then reads `CONSUMPTION_STATE_CONSUMED`
//! - `pull` returns up to `max_messages` pushed messages that are not acknowledged yet: a message
//!   is redelivered by every pull until `acknowledge` names its ack id

use std::{
    collections::{HashMap, VecDeque},
    sync::{Mutex, MutexGuard, PoisonError},
};

use async_trait::async_trait;
use revolt_models::v0;

use super::{
    apple_api::check_transaction_id, check_segment, environment_name, sha256_hex, AppleHistoryPage,
    AppleStoreApi, PlayPurchase, PlayStoreApi, PlayVoidedPage, PubSubMessage, StoreApiError,
    PLAY_CONSUMPTION_STATE_CONSUMED,
};

#[derive(Default)]
struct AppleState {
    unconfigured: bool,
    calls: Vec<String>,
    transactions: HashMap<String, Result<String, StoreApiError>>,
    history: VecDeque<Result<AppleHistoryPage, StoreApiError>>,
}

/// In-memory [`AppleStoreApi`] (see the module doc)
#[derive(Default)]
pub struct MockAppleStore {
    state: Mutex<AppleState>,
}

impl MockAppleStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, AppleState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `configured()` false from now on; every call answers `NotConfigured`
    pub fn unconfigured(&self) {
        self.state().unconfigured = true;
    }

    /// What Get Transaction Info answers for `transaction_id` (a JWS, or an error)
    pub fn set_transaction_info(
        &self,
        transaction_id: &str,
        answer: Result<String, StoreApiError>,
    ) {
        self.state()
            .transactions
            .insert(transaction_id.to_string(), answer);
    }

    /// The pages Get Notification History serves, in order
    pub fn set_history(&self, pages: Vec<Result<AppleHistoryPage, StoreApiError>>) {
        self.state().history = pages.into();
    }

    /// Every call so far, one line each
    pub fn calls(&self) -> Vec<String> {
        self.state().calls.clone()
    }
}

#[async_trait]
impl AppleStoreApi for MockAppleStore {
    fn configured(&self) -> bool {
        !self.state().unconfigured
    }

    async fn transaction_info(
        &self,
        env: v0::ProtStoreEnvironment,
        transaction_id: &str,
    ) -> Result<String, StoreApiError> {
        let mut state = self.state();
        state.calls.push(format!(
            "transaction_info {} {transaction_id}",
            environment_name(env)
        ));
        if state.unconfigured {
            return Err(StoreApiError::NotConfigured);
        }
        check_transaction_id(transaction_id)?;
        state
            .transactions
            .get(transaction_id)
            .cloned()
            .unwrap_or(Err(StoreApiError::NotFound))
    }

    async fn notification_history(
        &self,
        env: v0::ProtStoreEnvironment,
        start_ms: i64,
        end_ms: i64,
        pagination_token: Option<&str>,
    ) -> Result<AppleHistoryPage, StoreApiError> {
        let mut state = self.state();
        state.calls.push(format!(
            "notification_history {} {start_ms} {end_ms} {}",
            environment_name(env),
            pagination_token.unwrap_or("-")
        ));
        if state.unconfigured {
            return Err(StoreApiError::NotConfigured);
        }
        state.history.pop_front().unwrap_or_else(|| {
            Ok(AppleHistoryPage {
                signed_payloads: Vec::new(),
                has_more: false,
                pagination_token: None,
            })
        })
    }
}

#[derive(Default)]
struct PlayState {
    unconfigured: bool,
    no_pubsub: bool,
    calls: Vec<String>,
    purchases: HashMap<String, Result<PlayPurchase, StoreApiError>>,
    consume_failures: HashMap<String, StoreApiError>,
    voided: VecDeque<Result<PlayVoidedPage, StoreApiError>>,
    /// Pushed and not yet acknowledged, in push order
    messages: Vec<PubSubMessage>,
    acked: Vec<String>,
}

impl PlayState {
    fn pubsub_ready(&self) -> Result<(), StoreApiError> {
        if self.unconfigured || self.no_pubsub {
            Err(StoreApiError::NotConfigured)
        } else {
            Ok(())
        }
    }
}

/// In-memory [`PlayStoreApi`] (see the module doc)
#[derive(Default)]
pub struct MockPlayStore {
    state: Mutex<PlayState>,
}

impl MockPlayStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, PlayState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `configured()` and `pubsub_configured()` false from now on; every call answers
    /// `NotConfigured`
    pub fn unconfigured(&self) {
        self.state().unconfigured = true;
    }

    /// `pubsub_configured()` false from now on; `pull` and `acknowledge` answer `NotConfigured`
    pub fn no_pubsub(&self) {
        self.state().no_pubsub = true;
    }

    /// What the productsv2 lookup answers for `purchase_token`
    pub fn set_purchase(&self, purchase_token: &str, answer: Result<PlayPurchase, StoreApiError>) {
        self.state()
            .purchases
            .insert(purchase_token.to_string(), answer);
    }

    /// Every consume of `purchase_token` fails with `error`
    pub fn fail_consume(&self, purchase_token: &str, error: StoreApiError) {
        self.state()
            .consume_failures
            .insert(purchase_token.to_string(), error);
    }

    /// The pages `voided_purchases` serves, in order
    pub fn set_voided(&self, pages: Vec<Result<PlayVoidedPage, StoreApiError>>) {
        self.state().voided = pages.into();
    }

    /// A message for `pull` (redelivered until acknowledged)
    pub fn push_message(&self, message: PubSubMessage) {
        self.state().messages.push(message);
    }

    /// Ack ids acknowledged so far, in order
    pub fn acked(&self) -> Vec<String> {
        self.state().acked.clone()
    }

    /// Every call so far, one line each (tokens as their SHA-256 hex)
    pub fn calls(&self) -> Vec<String> {
        self.state().calls.clone()
    }
}

#[async_trait]
impl PlayStoreApi for MockPlayStore {
    fn configured(&self) -> bool {
        !self.state().unconfigured
    }

    fn pubsub_configured(&self) -> bool {
        self.state().pubsub_ready().is_ok()
    }

    async fn product_purchase(&self, purchase_token: &str) -> Result<PlayPurchase, StoreApiError> {
        let mut state = self.state();
        state
            .calls
            .push(format!("product_purchase {}", sha256_hex(purchase_token)));
        if state.unconfigured {
            return Err(StoreApiError::NotConfigured);
        }
        check_segment(purchase_token)?;
        state
            .purchases
            .get(purchase_token)
            .cloned()
            .unwrap_or(Err(StoreApiError::NotFound))
    }

    async fn consume(&self, product_id: &str, purchase_token: &str) -> Result<(), StoreApiError> {
        let mut state = self.state();
        state.calls.push(format!(
            "consume {product_id} {}",
            sha256_hex(purchase_token)
        ));
        if state.unconfigured {
            return Err(StoreApiError::NotConfigured);
        }
        check_segment(product_id)?;
        check_segment(purchase_token)?;
        if let Some(error) = state.consume_failures.get(purchase_token) {
            return Err(error.clone());
        }
        if let Some(Ok(purchase)) = state.purchases.get_mut(purchase_token) {
            for item in &mut purchase.product_line_item {
                item.product_offer_details.consumption_state =
                    Some(PLAY_CONSUMPTION_STATE_CONSUMED.to_string());
            }
        }
        Ok(())
    }

    async fn voided_purchases(
        &self,
        start_ms: i64,
        page_token: Option<&str>,
    ) -> Result<PlayVoidedPage, StoreApiError> {
        let mut state = self.state();
        state.calls.push(format!(
            "voided_purchases {start_ms} {}",
            page_token.unwrap_or("-")
        ));
        if state.unconfigured {
            return Err(StoreApiError::NotConfigured);
        }
        state.voided.pop_front().unwrap_or_else(|| {
            Ok(PlayVoidedPage {
                voided: Vec::new(),
                next_page_token: None,
            })
        })
    }

    async fn pull(&self, max_messages: u32) -> Result<Vec<PubSubMessage>, StoreApiError> {
        let mut state = self.state();
        state.calls.push(format!("pull {max_messages}"));
        state.pubsub_ready()?;
        let max = usize::try_from(max_messages).unwrap_or(usize::MAX);
        Ok(state.messages.iter().take(max).cloned().collect())
    }

    async fn acknowledge(&self, ack_ids: &[String]) -> Result<(), StoreApiError> {
        let mut state = self.state();
        state
            .calls
            .push(format!("acknowledge {}", ack_ids.join(",")));
        state.pubsub_ready()?;
        state
            .messages
            .retain(|message| !ack_ids.contains(&message.ack_id));
        state.acked.extend(ack_ids.iter().cloned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{PlayLineItem, PlayOfferDetails, PlayStateContext, PlayVoided};

    const TOKEN: &str = "mock-purchase-token.AO-J1Oz";
    const PROD: v0::ProtStoreEnvironment = v0::ProtStoreEnvironment::Production;

    fn purchase(product_id: &str) -> PlayPurchase {
        PlayPurchase {
            product_line_item: vec![PlayLineItem {
                product_id: product_id.to_string(),
                product_offer_details: PlayOfferDetails {
                    quantity: Some(1),
                    refundable_quantity: Some(1),
                    consumption_state: Some(
                        crate::store::PLAY_CONSUMPTION_STATE_YET_TO_BE_CONSUMED.to_string(),
                    ),
                },
            }],
            purchase_state_context: PlayStateContext {
                purchase_state: crate::store::PLAY_PURCHASE_STATE_PURCHASED.to_string(),
            },
            test_purchase_context: None,
            order_id: Some("GPA.1".to_string()),
            obfuscated_external_account_id: Some("intent-token".to_string()),
            region_code: Some("US".to_string()),
            purchase_completion_time: None,
            acknowledgement_state: None,
        }
    }

    fn message(ack_id: &str) -> PubSubMessage {
        PubSubMessage {
            ack_id: ack_id.to_string(),
            data: b"{}".to_vec(),
            message_id: format!("m-{ack_id}"),
        }
    }

    #[tokio::test]
    async fn mock_switches_follow_the_contract() {
        let apple = MockAppleStore::new();
        assert!(apple.configured());
        apple.unconfigured();
        assert!(!apple.configured());
        assert_eq!(
            apple.transaction_info(PROD, "1").await,
            Err(StoreApiError::NotConfigured)
        );
        assert_eq!(
            apple.notification_history(PROD, 1, 2, None).await,
            Err(StoreApiError::NotConfigured)
        );
        assert_eq!(
            apple.calls().len(),
            2,
            "calls are recorded even when unconfigured"
        );

        let play = MockPlayStore::new();
        assert!(play.configured());
        assert!(play.pubsub_configured());
        play.no_pubsub();
        assert!(play.configured());
        assert!(!play.pubsub_configured());
        assert_eq!(play.pull(10).await, Err(StoreApiError::NotConfigured));
        assert_eq!(
            play.acknowledge(&["a".to_string()]).await,
            Err(StoreApiError::NotConfigured)
        );
        play.set_purchase(TOKEN, Ok(purchase("gg.sloga.prot.p5")));
        assert!(play.product_purchase(TOKEN).await.is_ok());

        let play = MockPlayStore::new();
        play.unconfigured();
        assert!(!play.configured());
        assert!(!play.pubsub_configured());
        play.set_purchase(TOKEN, Ok(purchase("gg.sloga.prot.p5")));
        assert_eq!(
            play.product_purchase(TOKEN).await,
            Err(StoreApiError::NotConfigured)
        );
        assert_eq!(
            play.consume("gg.sloga.prot.p5", TOKEN).await,
            Err(StoreApiError::NotConfigured)
        );
        assert_eq!(
            play.voided_purchases(1, None).await,
            Err(StoreApiError::NotConfigured)
        );
        assert_eq!(play.pull(10).await, Err(StoreApiError::NotConfigured));
    }

    #[tokio::test]
    async fn mock_apple_answers_what_was_scripted() {
        let apple = MockAppleStore::new();
        apple.set_transaction_info("2000000000000001", Ok("a.b.c".to_string()));
        apple.set_transaction_info(
            "2000000000000002",
            Err(StoreApiError::Transient("HTTP 503".to_string())),
        );
        assert_eq!(
            apple.transaction_info(PROD, "2000000000000001").await,
            Ok("a.b.c".to_string())
        );
        assert_eq!(
            apple.transaction_info(PROD, "2000000000000001").await,
            Ok("a.b.c".to_string()),
            "answers every time"
        );
        assert_eq!(
            apple.transaction_info(PROD, "2000000000000002").await,
            Err(StoreApiError::Transient("HTTP 503".to_string()))
        );
        assert_eq!(
            apple.transaction_info(PROD, "2000000000000003").await,
            Err(StoreApiError::NotFound)
        );
        assert_eq!(
            apple.transaction_info(PROD, "not-a-transaction").await,
            Err(StoreApiError::NotFound)
        );

        let page = |payload: &str, token: Option<&str>| AppleHistoryPage {
            signed_payloads: vec![payload.to_string()],
            has_more: token.is_some(),
            pagination_token: token.map(str::to_string),
        };
        apple.set_history(vec![
            Ok(page("p1", Some("t2"))),
            Err(StoreApiError::Transient("HTTP 500".to_string())),
            Ok(page("p2", None)),
        ]);
        assert_eq!(
            apple.notification_history(PROD, 10, 20, None).await,
            Ok(page("p1", Some("t2")))
        );
        assert!(apple
            .notification_history(PROD, 10, 20, Some("t2"))
            .await
            .is_err());
        assert_eq!(
            apple
                .notification_history(v0::ProtStoreEnvironment::Sandbox, 10, 20, Some("t2"))
                .await,
            Ok(page("p2", None))
        );
        assert_eq!(
            apple.notification_history(PROD, 10, 20, None).await,
            Ok(AppleHistoryPage {
                signed_payloads: vec![],
                has_more: false,
                pagination_token: None,
            })
        );
        assert_eq!(
            apple.calls(),
            vec![
                "transaction_info Production 2000000000000001",
                "transaction_info Production 2000000000000001",
                "transaction_info Production 2000000000000002",
                "transaction_info Production 2000000000000003",
                "transaction_info Production not-a-transaction",
                "notification_history Production 10 20 -",
                "notification_history Production 10 20 t2",
                "notification_history Sandbox 10 20 t2",
                "notification_history Production 10 20 -",
            ]
        );
    }

    #[tokio::test]
    async fn mock_play_answers_what_was_scripted() {
        let play = MockPlayStore::new();
        play.set_purchase(TOKEN, Ok(purchase("gg.sloga.prot.p5")));
        play.set_purchase("gone-token", Err(StoreApiError::Rejected { status: 410 }));
        play.fail_consume(
            "stuck-token",
            StoreApiError::Transient("HTTP 503".to_string()),
        );

        assert_eq!(
            play.product_purchase(TOKEN).await,
            Ok(purchase("gg.sloga.prot.p5"))
        );
        assert_eq!(
            play.product_purchase("gone-token").await,
            Err(StoreApiError::Rejected { status: 410 })
        );
        assert_eq!(
            play.product_purchase("unknown-token").await,
            Err(StoreApiError::NotFound)
        );
        assert_eq!(
            play.product_purchase("a/b").await,
            Err(StoreApiError::NotFound)
        );

        // A consume succeeds and the purchase then reads consumed
        assert_eq!(play.consume("gg.sloga.prot.p5", TOKEN).await, Ok(()));
        let consumed = play.product_purchase(TOKEN).await.unwrap();
        assert_eq!(
            consumed.product_line_item[0]
                .product_offer_details
                .consumption_state
                .as_deref(),
            Some(PLAY_CONSUMPTION_STATE_CONSUMED)
        );
        for _ in 0..2 {
            assert_eq!(
                play.consume("gg.sloga.prot.p5", "stuck-token").await,
                Err(StoreApiError::Transient("HTTP 503".to_string()))
            );
        }

        let calls = play.calls();
        let hash = sha256_hex(TOKEN);
        assert_eq!(calls[0], format!("product_purchase {hash}"));
        assert!(calls.contains(&format!("consume gg.sloga.prot.p5 {hash}")));
        assert!(
            !calls.iter().any(|call| call.contains(TOKEN)
                || call.contains("stuck-token")
                || call.contains("gone-token")),
            "{calls:?}"
        );
    }

    #[tokio::test]
    async fn mock_voided_pages_are_served_in_order() {
        let play = MockPlayStore::new();
        let voided = PlayVoided {
            purchase_token: TOKEN.to_string(),
            order_id: None,
            voided_time_ms: 5,
        };
        play.set_voided(vec![
            Ok(PlayVoidedPage {
                voided: vec![voided.clone()],
                next_page_token: Some("n2".to_string()),
            }),
            Err(StoreApiError::Transient("HTTP 500".to_string())),
        ]);
        assert_eq!(
            play.voided_purchases(1, None).await.unwrap().voided,
            vec![voided]
        );
        assert!(play.voided_purchases(1, Some("n2")).await.is_err());
        assert_eq!(
            play.voided_purchases(1, None).await,
            Ok(PlayVoidedPage {
                voided: vec![],
                next_page_token: None
            })
        );
        assert_eq!(
            play.calls(),
            vec![
                "voided_purchases 1 -",
                "voided_purchases 1 n2",
                "voided_purchases 1 -"
            ]
        );
    }

    #[tokio::test]
    async fn mock_pubsub_redelivers_until_acked() {
        let play = MockPlayStore::new();
        for ack_id in ["a1", "a2", "a3"] {
            play.push_message(message(ack_id));
        }
        assert_eq!(
            play.pull(2).await.unwrap(),
            vec![message("a1"), message("a2")]
        );
        assert_eq!(play.acknowledge(&["a1".to_string()]).await, Ok(()));
        // a2 was pulled but not acked: delivered again
        assert_eq!(
            play.pull(10).await.unwrap(),
            vec![message("a2"), message("a3")]
        );
        assert_eq!(
            play.acknowledge(&["a2".to_string(), "a3".to_string()])
                .await,
            Ok(())
        );
        assert_eq!(play.pull(10).await.unwrap(), vec![]);
        assert_eq!(play.acked(), vec!["a1", "a2", "a3"]);
        assert_eq!(
            play.calls(),
            vec![
                "pull 2",
                "acknowledge a1",
                "pull 10",
                "acknowledge a2,a3",
                "pull 10"
            ]
        );
    }
}
