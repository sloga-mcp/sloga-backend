//! Google Play Developer API and Pub/Sub client (S6 contracts 11.2, 11.3).
//!
//! With `PLAY` = `https://androidpublisher.googleapis.com/androidpublisher/v3` and `PUBSUB` =
//! `https://pubsub.googleapis.com/v1`:
//! - purchase: `GET PLAY/applications/{packageName}/purchases/productsv2/tokens/{token}` →
//!   `ProductPurchaseV2` (`purchases.productsv2.getproductpurchasev2`)
//! - consume: `POST PLAY/applications/{packageName}/purchases/products/{productId}/tokens/{token}:consume`
//!   (empty body)
//! - voids: `GET PLAY/applications/{packageName}/purchases/voidedpurchases?startTime={ms}&type=0&token={pageToken}`
//! - RTDN: `POST PUBSUB/{subscription}:pull` body `{"maxMessages": n}` and
//!   `POST PUBSUB/{subscription}:acknowledge` body `{"ackIds": [..]}`, `subscription` =
//!   `projects/{p}/subscriptions/{s}` from config (empty: RTDN is not pulled and
//!   `pubsub_configured()` is false; malformed: the same, logged `PROT_STORE_CONFIG_INVALID`)
//!
//! The bearer is the service account's access token ([`GoogleAuth`]); a 401 drops it. A purchase
//! token only ever travels in the URL path, percent-encoded; log lines name the purchase
//! `play:{sha256hex}`.

use std::{fmt, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{Method, Url};
use serde::Deserialize;

use super::{
    build_request, check_segment, decode_json, exchange, google_auth::GoogleAuth, log_failure,
    map_reply, play_purchase_id, store_log, unix_now_s, url_with_segments, HttpSend, PlayPurchase,
    PlayStoreApi, PlayVoided, PlayVoidedPage, PubSubMessage, ReqwestSend, StoreApiError, TIMED_OUT,
};
use crate::settings::PlayStoreConfig;

/// Google Play Developer API v3
pub const PLAY_API_BASE: &str = "https://androidpublisher.googleapis.com/androidpublisher/v3";
/// Cloud Pub/Sub v1
pub const PUBSUB_API_BASE: &str = "https://pubsub.googleapis.com/v1";
/// Request timeout of Pub/Sub `:pull` (R55; every other call has the 10 s of `STORE_TIMEOUT`)
pub const PUBSUB_PULL_TIMEOUT: Duration = Duration::from_secs(30);

const STORE: &str = "play";

/// `projects/{p}/subscriptions/{s}`, each name non-empty, not only dots, of `A-Z a-z 0-9 - _ . ~ +`
fn is_subscription_path(subscription: &str) -> bool {
    let name_ok = |name: &str| {
        !name.is_empty()
            && !name.bytes().all(|b| b == b'.')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'+'))
    };
    let parts: Vec<&str> = subscription.split('/').collect();
    parts.len() == 4
        && parts[0] == "projects"
        && parts[2] == "subscriptions"
        && name_ok(parts[1])
        && name_ok(parts[3])
}

/// A configured client
struct PlayClient {
    package_name: String,
    /// `None`: RTDN is not pulled
    subscription: Option<String>,
    auth: GoogleAuth,
    send: Box<dyn HttpSend>,
}

impl PlayClient {
    async fn call(
        &self,
        op: &str,
        subject: Option<&str>,
        method: Method,
        url: Url,
        body: Option<(Vec<u8>, &'static str)>,
    ) -> Result<Vec<u8>, StoreApiError> {
        let token = self
            .auth
            .access_token(self.send.as_ref(), unix_now_s())
            .await?;
        let request = build_request(method, url, &token, body)?;
        let result = exchange(self.send.as_ref(), STORE, op, subject, request).await;
        if matches!(result, Err(StoreApiError::Rejected { status: 401 })) {
            self.auth.forget();
        }
        result
    }

    /// `call` for Pub/Sub `:pull` (R55): a 30 s request timeout, and a client-side timeout (no
    /// response) is an idle subscription, `Ok(None)`, not a failure. Server errors and auth
    /// failures map as everywhere else.
    async fn call_pull(&self, url: Url, body: Vec<u8>) -> Result<Option<Vec<u8>>, StoreApiError> {
        let token = self
            .auth
            .access_token(self.send.as_ref(), unix_now_s())
            .await?;
        let mut request =
            build_request(Method::POST, url, &token, Some((body, "application/json")))?;
        *request.timeout_mut() = Some(PUBSUB_PULL_TIMEOUT);
        let reply = match self.send.send(request).await {
            Ok(reply) => reply,
            Err(StoreApiError::Transient(kind)) if kind == TIMED_OUT => {
                store_log(
                    log::Level::Debug,
                    "PROT_STORE_API store=play op=pull idle: no message before the timeout",
                );
                return Ok(None);
            }
            Err(error) => {
                log_failure(STORE, "pull", None, &error);
                return Err(error);
            }
        };
        let result = map_reply(STORE, "pull", None, reply);
        if matches!(result, Err(StoreApiError::Rejected { status: 401 })) {
            self.auth.forget();
        }
        result.map(Some)
    }

    fn pubsub_url(&self, action: &str) -> Result<Url, StoreApiError> {
        let subscription = self
            .subscription
            .as_deref()
            .ok_or(StoreApiError::NotConfigured)?;
        Url::parse(&format!("{PUBSUB_API_BASE}/{subscription}:{action}"))
            .map_err(|_| StoreApiError::Transient("could not build the request".to_string()))
    }
}

/// [`PlayStoreApi`] over HTTPS. `Debug` redacts the key and the access token.
pub struct ReqwestPlayStore {
    /// `None`: no credentials, unusable credentials, or no HTTP client; every call is
    /// `NotConfigured` and nothing is sent
    client: Option<PlayClient>,
}

impl fmt::Debug for ReqwestPlayStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(client) = self.client.as_ref() else {
            return f
                .debug_struct("ReqwestPlayStore")
                .field("configured", &false)
                .finish();
        };
        f.debug_struct("ReqwestPlayStore")
            .field("configured", &true)
            .field("package_name", &client.package_name)
            .field("pubsub_subscription", &client.subscription)
            .field("auth", &client.auth)
            .finish()
    }
}

impl ReqwestPlayStore {
    /// `None` → `configured()` false and every call `NotConfigured`
    pub fn new(config: Option<PlayStoreConfig>) -> Self {
        let Some(config) = config else {
            return ReqwestPlayStore { client: None };
        };
        let Some(send) = ReqwestSend::new(STORE) else {
            return ReqwestPlayStore { client: None };
        };
        let Some(auth) =
            GoogleAuth::new(&config.client_email, &config.private_key, &config.token_uri)
        else {
            return ReqwestPlayStore { client: None };
        };
        Self::build(
            &config.package_name,
            &config.pubsub_subscription,
            auth,
            Box::new(send),
        )
    }

    fn build(
        package_name: &str,
        subscription: &str,
        auth: GoogleAuth,
        send: Box<dyn HttpSend>,
    ) -> Self {
        if check_segment(package_name).is_err() {
            store_log(
                log::Level::Error,
                "PROT_STORE_CONFIG_INVALID store=play: package_name must be set",
            );
            return ReqwestPlayStore { client: None };
        }
        let subscription = if subscription.is_empty() {
            None
        } else if is_subscription_path(subscription) {
            Some(subscription.to_string())
        } else {
            store_log(
                log::Level::Error,
                "PROT_STORE_CONFIG_INVALID store=play: pubsub_subscription is not \
                 projects/{p}/subscriptions/{s}; RTDN is not pulled",
            );
            None
        };
        ReqwestPlayStore {
            client: Some(PlayClient {
                package_name: package_name.to_string(),
                subscription,
                auth,
                send,
            }),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VoidedAnswer {
    #[serde(default)]
    voided_purchases: Vec<VoidedItem>,
    token_pagination: Option<TokenPagination>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenPagination {
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VoidedItem {
    purchase_token: String,
    order_id: Option<String>,
    voided_time_millis: GoogleInt64,
}

/// Google's JSON sends int64 as a string; a number is accepted too
#[derive(Deserialize)]
#[serde(untagged)]
enum GoogleInt64 {
    Number(i64),
    Text(String),
}

impl GoogleInt64 {
    fn value(&self) -> Option<i64> {
        match self {
            GoogleInt64::Number(n) => Some(*n),
            GoogleInt64::Text(s) => s.parse().ok(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PullAnswer {
    #[serde(default)]
    received_messages: Vec<ReceivedMessage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReceivedMessage {
    ack_id: String,
    message: PubSubPayload,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PubSubPayload {
    #[serde(default)]
    data: String,
    #[serde(default)]
    message_id: String,
}

#[async_trait]
impl PlayStoreApi for ReqwestPlayStore {
    fn configured(&self) -> bool {
        self.client.is_some()
    }

    fn pubsub_configured(&self) -> bool {
        self.client
            .as_ref()
            .is_some_and(|client| client.subscription.is_some())
    }

    async fn product_purchase(&self, purchase_token: &str) -> Result<PlayPurchase, StoreApiError> {
        let client = self.client.as_ref().ok_or(StoreApiError::NotConfigured)?;
        check_segment(purchase_token)?;
        let url = url_with_segments(
            PLAY_API_BASE,
            &[
                "applications",
                &client.package_name,
                "purchases",
                "productsv2",
                "tokens",
                purchase_token,
            ],
        )?;
        let subject = play_purchase_id(purchase_token);
        let body = match client
            .call("product_purchase", Some(&subject), Method::GET, url, None)
            .await
        {
            Ok(body) => body,
            // R51 (section 42): Play answers an invalid or expired token 400 / 410; for this lookup
            // only, that is "no such purchase" (consume, voids and Pub/Sub keep 400 = Rejected)
            Err(StoreApiError::Rejected {
                status: status @ (400 | 410),
            }) => {
                store_log(
                    log::Level::Warn,
                    &format!(
                        "PROT_STORE_API store=play op=product_purchase {subject} invalid token \
                         status={status}"
                    ),
                );
                return Err(StoreApiError::NotFound);
            }
            Err(error) => return Err(error),
        };
        decode_json(STORE, "product_purchase", &body)
    }

    async fn consume(&self, product_id: &str, purchase_token: &str) -> Result<(), StoreApiError> {
        let client = self.client.as_ref().ok_or(StoreApiError::NotConfigured)?;
        check_segment(product_id)?;
        check_segment(purchase_token)?;
        let url = url_with_segments(
            PLAY_API_BASE,
            &[
                "applications",
                &client.package_name,
                "purchases",
                "products",
                product_id,
                "tokens",
                &format!("{purchase_token}:consume"),
            ],
        )?;
        let subject = play_purchase_id(purchase_token);
        client
            .call(
                "consume",
                Some(&subject),
                Method::POST,
                url,
                Some((Vec::new(), "")),
            )
            .await?;
        Ok(())
    }

    async fn voided_purchases(
        &self,
        start_ms: i64,
        page_token: Option<&str>,
    ) -> Result<PlayVoidedPage, StoreApiError> {
        let client = self.client.as_ref().ok_or(StoreApiError::NotConfigured)?;
        let mut url = url_with_segments(
            PLAY_API_BASE,
            &[
                "applications",
                &client.package_name,
                "purchases",
                "voidedpurchases",
            ],
        )?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("startTime", &start_ms.to_string());
            query.append_pair("type", "0");
            if let Some(token) = page_token.filter(|t| !t.is_empty()) {
                query.append_pair("token", token);
            }
        }
        let body = client
            .call("voided_purchases", None, Method::GET, url, None)
            .await?;
        let answer: VoidedAnswer = decode_json(STORE, "voided_purchases", &body)?;

        let mut voided = Vec::with_capacity(answer.voided_purchases.len());
        for item in answer.voided_purchases {
            let Some(voided_time_ms) = item.voided_time_millis.value() else {
                // Skipping one would lose its clawback; the whole page is retried
                let error = StoreApiError::Transient("unexpected response body".to_string());
                log_failure(STORE, "voided_purchases", None, &error);
                return Err(error);
            };
            voided.push(PlayVoided {
                purchase_token: item.purchase_token,
                order_id: item.order_id,
                voided_time_ms,
            });
        }
        Ok(PlayVoidedPage {
            voided,
            next_page_token: answer
                .token_pagination
                .and_then(|p| p.next_page_token)
                .filter(|t| !t.is_empty()),
        })
    }

    async fn pull(&self, max_messages: u32) -> Result<Vec<PubSubMessage>, StoreApiError> {
        let client = self.client.as_ref().ok_or(StoreApiError::NotConfigured)?;
        let url = client.pubsub_url("pull")?;
        let body = serde_json::to_vec(&serde_json::json!({ "maxMessages": max_messages }))
            .map_err(|_| StoreApiError::Transient("could not build the request".to_string()))?;
        let Some(reply) = client.call_pull(url, body).await? else {
            return Ok(Vec::new());
        };
        let answer: PullAnswer = decode_json(STORE, "pull", &reply)?;
        Ok(answer
            .received_messages
            .into_iter()
            .map(|received| {
                // An undecodable payload is handed on empty: the RTDN handler cannot parse it,
                // logs it and acknowledges it (section 43), so it is not redelivered forever
                let data = STANDARD
                    .decode(received.message.data.as_bytes())
                    .unwrap_or_else(|_| {
                        store_log(
                            log::Level::Warn,
                            &format!(
                                "PROT_STORE_API store=play op=pull message={} data is not base64",
                                received.message.message_id
                            ),
                        );
                        Vec::new()
                    });
                PubSubMessage {
                    ack_id: received.ack_id,
                    data,
                    message_id: received.message.message_id,
                }
            })
            .collect())
    }

    async fn acknowledge(&self, ack_ids: &[String]) -> Result<(), StoreApiError> {
        let client = self.client.as_ref().ok_or(StoreApiError::NotConfigured)?;
        let url = client.pubsub_url("acknowledge")?;
        if ack_ids.is_empty() {
            return Ok(());
        }
        let body = serde_json::to_vec(&serde_json::json!({ "ackIds": ack_ids }))
            .map_err(|_| StoreApiError::Transient("could not build the request".to_string()))?;
        client
            .call(
                "acknowledge",
                None,
                Method::POST,
                url,
                Some((body, "application/json")),
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! A configured client over a [`FakeSend`] whose token endpoint always grants

    use super::ReqwestPlayStore;
    use crate::store::{google_auth::GoogleAuth, test_support::FakeSend};

    pub(crate) const PACKAGE: &str = "gg.sloga.app";
    pub(crate) const SUBSCRIPTION: &str = "projects/sloga-test/subscriptions/play-rtdn";
    pub(crate) const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
    pub(crate) const ACCESS_TOKEN: &str = "ya29.test-access-token";
    pub(crate) const ASSERTION: &str = "eyJhbGciOiJSUzI1NiJ9.test-assertion.sig";

    pub(crate) fn store_with(fake: &FakeSend, subscription: &str) -> ReqwestPlayStore {
        fake.token_endpoint(
            TOKEN_URI,
            200,
            &format!(
                r#"{{"access_token": "{ACCESS_TOKEN}", "expires_in": 3599, "token_type": "Bearer"}}"#
            ),
        );
        let auth = GoogleAuth::with_fixed_assertion(
            "play-api@sloga-test.iam.gserviceaccount.com",
            TOKEN_URI,
            ASSERTION,
        );
        ReqwestPlayStore::build(PACKAGE, subscription, auth, Box::new(fake.clone()))
    }

    pub(crate) fn store(fake: &FakeSend) -> ReqwestPlayStore {
        store_with(fake, SUBSCRIPTION)
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{store, store_with, ACCESS_TOKEN, ASSERTION, TOKEN_URI};
    use super::*;
    use crate::store::{log_capture, test_support::FakeSend, PLAY_PURCHASE_STATE_PURCHASED};

    const TOKEN: &str = "aobdmhfbfjgmadpbhmhgfgel.AO-J1OzSecretPurchaseToken_0123456789";
    const PURCHASE_URL: &str = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/gg.sloga.app/purchases/productsv2/tokens/aobdmhfbfjgmadpbhmhgfgel.AO-J1OzSecretPurchaseToken_0123456789";

    const PURCHASE_JSON: &str = r#"{
        "kind": "androidpublisher#productPurchaseV2",
        "productLineItem": [{"productId": "gg.sloga.prot.p5",
            "productOfferDetails": {"quantity": 1, "consumptionState": "CONSUMPTION_STATE_YET_TO_BE_CONSUMED"}}],
        "purchaseStateContext": {"purchaseState": "PURCHASED"},
        "orderId": "GPA.3312-4456-7890-12345",
        "obfuscatedExternalAccountId": "intent-token-43-chars-aaaaaaaaaaaaaaaaaaaa",
        "regionCode": "US"
    }"#;

    fn bearer() -> String {
        format!("Bearer {ACCESS_TOKEN}")
    }

    #[tokio::test]
    async fn product_purchase_request_and_answer() {
        let fake = FakeSend::new();
        let play = store(&fake);
        fake.reply(200, PURCHASE_JSON);
        let purchase = play.product_purchase(TOKEN).await.unwrap();
        assert_eq!(purchase.product_line_item[0].product_id, "gg.sloga.prot.p5");
        assert_eq!(
            purchase.purchase_state_context.purchase_state,
            PLAY_PURCHASE_STATE_PURCHASED
        );
        assert_eq!(
            purchase.obfuscated_external_account_id.as_deref(),
            Some("intent-token-43-chars-aaaaaaaaaaaaaaaaaaaa")
        );

        let sent = fake.sent();
        assert_eq!(sent.len(), 2);
        // The grant, then the lookup with its token
        assert_eq!(sent[0].url, TOKEN_URI);
        let grant = String::from_utf8(sent[0].body.clone().unwrap()).unwrap();
        assert!(
            grant.ends_with(&format!("&assertion={ASSERTION}")),
            "{grant}"
        );
        assert_eq!(sent[1].method, "GET");
        assert_eq!(sent[1].url, PURCHASE_URL);
        assert_eq!(sent[1].authorization, Some(bearer()));
        assert_eq!(sent[1].body, None);

        // The access token is reused
        fake.reply(200, PURCHASE_JSON);
        play.product_purchase(TOKEN).await.unwrap();
        assert_eq!(fake.sent().len(), 3);
        assert_eq!(fake.sent()[2].url, PURCHASE_URL);
    }

    #[tokio::test]
    async fn consume_request() {
        let fake = FakeSend::new();
        let play = store(&fake);
        fake.reply(200, "");
        assert_eq!(play.consume("gg.sloga.prot.p5", TOKEN).await, Ok(()));
        let sent = &fake.sent()[1];
        assert_eq!(sent.method, "POST");
        assert_eq!(
            sent.url,
            "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/gg.sloga.app/purchases/products/gg.sloga.prot.p5/tokens/aobdmhfbfjgmadpbhmhgfgel.AO-J1OzSecretPurchaseToken_0123456789:consume"
        );
        assert_eq!(sent.authorization, Some(bearer()));
        assert_eq!(sent.content_type, None);
        assert_eq!(sent.body.as_deref(), Some(&[][..]));
    }

    #[tokio::test]
    async fn voided_purchases_request_and_page() {
        let fake = FakeSend::new();
        let play = store(&fake);
        fake.reply(
            200,
            r#"{
                "pageInfo": {"totalResults": 2, "resultPerPage": 2, "startIndex": 0},
                "tokenPagination": {"nextPageToken": "next-1"},
                "voidedPurchases": [
                    {"kind": "androidpublisher#voidedPurchase", "purchaseToken": "tok-a",
                     "purchaseTimeMillis": "1761000000000", "voidedTimeMillis": "1762000000000",
                     "orderId": "GPA.1", "voidedSource": 0, "voidedReason": 1, "voidedQuantity": 1},
                    {"purchaseToken": "tok-b", "voidedTimeMillis": 1762000000001}
                ]
            }"#,
        );
        let page = play
            .voided_purchases(1_761_000_000_000, Some("page 1"))
            .await
            .unwrap();
        assert_eq!(
            page,
            PlayVoidedPage {
                voided: vec![
                    PlayVoided {
                        purchase_token: "tok-a".to_string(),
                        order_id: Some("GPA.1".to_string()),
                        voided_time_ms: 1_762_000_000_000,
                    },
                    PlayVoided {
                        purchase_token: "tok-b".to_string(),
                        order_id: None,
                        voided_time_ms: 1_762_000_000_001,
                    },
                ],
                next_page_token: Some("next-1".to_string()),
            }
        );
        let sent = &fake.sent()[1];
        assert_eq!(sent.method, "GET");
        assert_eq!(
            sent.url,
            "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/gg.sloga.app/purchases/voidedpurchases?startTime=1761000000000&type=0&token=page+1"
        );

        // Last page, no page token sent
        fake.reply(200, "{}");
        let page = play.voided_purchases(5, None).await.unwrap();
        assert_eq!(
            page,
            PlayVoidedPage {
                voided: vec![],
                next_page_token: None
            }
        );
        assert_eq!(
            fake.sent()[2].url,
            "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/gg.sloga.app/purchases/voidedpurchases?startTime=5&type=0"
        );

        // A void time we cannot read fails the page instead of dropping the void
        fake.reply(
            200,
            r#"{"voidedPurchases": [{"purchaseToken": "tok-c", "voidedTimeMillis": "soon"}]}"#,
        );
        assert_eq!(
            play.voided_purchases(5, None).await,
            Err(StoreApiError::Transient(
                "unexpected response body".to_string()
            ))
        );
    }

    #[tokio::test]
    async fn pubsub_pull_and_acknowledge() {
        let fake = FakeSend::new();
        let play = store(&fake);
        assert!(play.pubsub_configured());
        let rtdn = br#"{"version": "1.0", "packageName": "gg.sloga.app", "eventTimeMillis": "1762000000000",
            "oneTimeProductNotification": {"version": "1.0", "notificationType": 1,
            "purchaseToken": "rtdn-token", "sku": "gg.sloga.prot.p5"}}"#;
        fake.reply(
            200,
            &format!(
                r#"{{"receivedMessages": [{{"ackId": "ack-1", "deliveryAttempt": 1,
                    "message": {{"data": "{}", "messageId": "m-1", "publishTime": "2026-11-01T12:00:00Z"}}}}]}}"#,
                STANDARD.encode(rtdn)
            ),
        );
        assert_eq!(
            play.pull(100).await.unwrap(),
            vec![PubSubMessage {
                ack_id: "ack-1".to_string(),
                data: rtdn.to_vec(),
                message_id: "m-1".to_string(),
            }]
        );
        let sent = &fake.sent()[1];
        assert_eq!(sent.method, "POST");
        assert_eq!(
            sent.url,
            "https://pubsub.googleapis.com/v1/projects/sloga-test/subscriptions/play-rtdn:pull"
        );
        assert_eq!(sent.content_type.as_deref(), Some("application/json"));
        let body: serde_json::Value =
            serde_json::from_slice(sent.body.as_deref().unwrap()).unwrap();
        assert_eq!(body, serde_json::json!({"maxMessages": 100}));

        // Nothing waiting
        fake.reply(200, "{}");
        assert_eq!(play.pull(100).await.unwrap(), vec![]);

        // An undecodable payload is handed on empty, with its ack id
        fake.reply(
            200,
            r#"{"receivedMessages": [{"ackId": "ack-2", "message": {"data": "%%%", "messageId": "m-2"}}]}"#,
        );
        let messages = play.pull(100).await.unwrap();
        assert_eq!(messages[0].ack_id, "ack-2");
        assert!(messages[0].data.is_empty());

        fake.reply(200, "{}");
        assert_eq!(
            play.acknowledge(&["ack-1".to_string(), "ack-2".to_string()])
                .await,
            Ok(())
        );
        let sent = fake.sent().last().cloned().unwrap();
        assert_eq!(
            sent.url,
            "https://pubsub.googleapis.com/v1/projects/sloga-test/subscriptions/play-rtdn:acknowledge"
        );
        let body: serde_json::Value =
            serde_json::from_slice(sent.body.as_deref().unwrap()).unwrap();
        assert_eq!(body, serde_json::json!({"ackIds": ["ack-1", "ack-2"]}));

        // Nothing to acknowledge sends nothing
        let before = fake.sent().len();
        assert_eq!(play.acknowledge(&[]).await, Ok(()));
        assert_eq!(fake.sent().len(), before);
    }

    #[tokio::test]
    async fn pubsub_needs_a_well_formed_subscription() {
        log_capture::take();
        for subscription in [
            "",
            "projects/sloga-test/topics/play-rtdn",
            "projects/../subscriptions/x",
            "projects/p/subscriptions/s/extra",
        ] {
            let fake = FakeSend::new();
            let play = store_with(&fake, subscription);
            assert!(play.configured(), "{subscription:?}");
            assert!(!play.pubsub_configured(), "{subscription:?}");
            assert_eq!(play.pull(100).await, Err(StoreApiError::NotConfigured));
            assert_eq!(
                play.acknowledge(&["a".to_string()]).await,
                Err(StoreApiError::NotConfigured)
            );
            assert!(fake.sent().is_empty(), "{subscription:?}");
        }
        let lines = log_capture::take();
        assert_eq!(
            lines
                .iter()
                .filter(
                    |l| l.starts_with("PROT_STORE_CONFIG_INVALID store=play: pubsub_subscription")
                )
                .count(),
            3,
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn play_errors_map_per_contract() {
        let fake = FakeSend::new();
        let play = store(&fake);
        log_capture::take();

        fake.reply(404, "{}");
        assert_eq!(
            play.product_purchase(TOKEN).await,
            Err(StoreApiError::NotFound)
        );
        fake.reply(409, "{}");
        assert_eq!(
            play.product_purchase(TOKEN).await,
            Err(StoreApiError::Rejected { status: 409 })
        );
        fake.reply(503, "{}");
        assert_eq!(
            play.product_purchase(TOKEN).await,
            Err(StoreApiError::Transient("HTTP 503".to_string()))
        );
        fake.reply(404, "{}");
        assert_eq!(
            play.consume("gg.sloga.prot.p5", TOKEN).await,
            Err(StoreApiError::NotFound)
        );
        fake.reply(403, "{}");
        assert_eq!(
            play.consume("gg.sloga.prot.p5", TOKEN).await,
            Err(StoreApiError::Rejected { status: 403 })
        );
        let grants = |fake: &FakeSend| fake.sent().iter().filter(|s| s.url == TOKEN_URI).count();
        assert_eq!(grants(&fake), 1);

        // A 401 drops the access token: the next call is granted a new one
        fake.reply(401, "{}");
        assert_eq!(
            play.product_purchase(TOKEN).await,
            Err(StoreApiError::Rejected { status: 401 })
        );
        fake.reply(200, PURCHASE_JSON);
        play.product_purchase(TOKEN).await.unwrap();
        assert_eq!(grants(&fake), 2);

        let lines = log_capture::take();
        let id = play_purchase_id(TOKEN);
        for line in [
            format!("PROT_STORE_API_AUTH store=play op=consume {id} status=403"),
            format!("PROT_STORE_API_AUTH store=play op=product_purchase {id} status=401"),
        ] {
            assert!(lines.contains(&line), "{line} in {lines:?}");
        }
    }

    #[tokio::test]
    async fn invalid_token_lookup_is_not_found_but_other_400s_are_rejected() {
        // R51: only the productsv2 lookup reads 400 / 410 as "no such purchase"
        let fake = FakeSend::new();
        let play = store(&fake);
        log_capture::take();
        for status in [400, 410] {
            fake.reply(
                status,
                r#"{"error": {"code": 400, "status": "INVALID_ARGUMENT"}}"#,
            );
            assert_eq!(
                play.product_purchase(TOKEN).await,
                Err(StoreApiError::NotFound),
                "{status}"
            );
        }
        fake.reply(400, "{}");
        assert_eq!(
            play.consume("gg.sloga.prot.p5", TOKEN).await,
            Err(StoreApiError::Rejected { status: 400 })
        );
        fake.reply(410, "{}");
        assert_eq!(
            play.consume("gg.sloga.prot.p5", TOKEN).await,
            Err(StoreApiError::Rejected { status: 410 })
        );
        fake.reply(400, "{}");
        assert_eq!(
            play.voided_purchases(1, None).await,
            Err(StoreApiError::Rejected { status: 400 })
        );
        fake.reply(400, "{}");
        assert_eq!(
            play.pull(100).await,
            Err(StoreApiError::Rejected { status: 400 })
        );
        fake.reply(400, "{}");
        assert_eq!(
            play.acknowledge(&["ack-1".to_string()]).await,
            Err(StoreApiError::Rejected { status: 400 })
        );

        let lines = log_capture::take();
        let id = play_purchase_id(TOKEN);
        for status in [400, 410] {
            let line = format!(
                "PROT_STORE_API store=play op=product_purchase {id} invalid token status={status}"
            );
            assert!(lines.contains(&line), "{line} in {lines:?}");
        }
        assert!(!lines.iter().any(|line| line.contains(TOKEN)), "{lines:?}");
    }

    #[tokio::test]
    async fn idle_pull_timeout_is_an_empty_tick() {
        // R55: a client-side timeout on `:pull` is an idle subscription, not a failure
        let fake = FakeSend::new();
        let play = store(&fake);
        fake.time_out();
        assert_eq!(play.pull(100).await, Ok(vec![]));
        let pull = fake.sent().last().cloned().unwrap();
        assert!(pull.url.ends_with(":pull"), "{}", pull.url);
        assert_eq!(pull.timeout, Some(std::time::Duration::from_secs(30)));

        // Every other call keeps the timeout as a failure, and the client's 10 s
        let timed_out = Err(StoreApiError::Transient(TIMED_OUT.to_string()));
        fake.time_out();
        assert_eq!(
            play.acknowledge(&["ack-1".to_string()]).await,
            timed_out.clone()
        );
        fake.time_out();
        assert_eq!(play.product_purchase(TOKEN).await.map(|_| ()), timed_out);
        let ack_and_lookup: Vec<_> = fake.sent().into_iter().rev().take(2).collect();
        assert!(ack_and_lookup.iter().all(|sent| sent.timeout.is_none()));

        // Server errors and auth failures on `:pull` map as everywhere else
        fake.reply(503, "{}");
        assert_eq!(
            play.pull(100).await,
            Err(StoreApiError::Transient("HTTP 503".to_string()))
        );
        fake.reply(403, "{}");
        assert_eq!(
            play.pull(100).await,
            Err(StoreApiError::Rejected { status: 403 })
        );
        fake.fail(StoreApiError::Transient("could not connect".to_string()));
        assert_eq!(
            play.pull(100).await,
            Err(StoreApiError::Transient("could not connect".to_string()))
        );
    }

    #[tokio::test]
    async fn odd_tokens_are_refused_without_a_request() {
        let fake = FakeSend::new();
        let play = store(&fake);
        for bad in ["", "..", "a/b", "a?b", "a%2Fb"] {
            assert_eq!(
                play.product_purchase(bad).await,
                Err(StoreApiError::NotFound),
                "{bad:?}"
            );
            assert_eq!(
                play.consume("gg.sloga.prot.p5", bad).await,
                Err(StoreApiError::NotFound),
                "{bad:?}"
            );
            assert_eq!(
                play.consume(bad, TOKEN).await,
                Err(StoreApiError::NotFound),
                "{bad:?}"
            );
        }
        assert!(fake.sent().is_empty());
    }

    #[tokio::test]
    async fn unconfigured_play_store_sends_nothing() {
        let play = ReqwestPlayStore::new(None);
        assert!(!play.configured());
        assert!(!play.pubsub_configured());
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
        assert_eq!(play.pull(100).await, Err(StoreApiError::NotConfigured));
        assert_eq!(
            play.acknowledge(&[]).await,
            Err(StoreApiError::NotConfigured)
        );
        assert_eq!(
            format!("{play:?}"),
            "ReqwestPlayStore { configured: false }"
        );

        // Section 9.1's config with a key that is not an RSA PEM
        let play = ReqwestPlayStore::new(Some(PlayStoreConfig {
            package_name: "gg.sloga.app".to_string(),
            client_email: "play-api@sloga-test.iam.gserviceaccount.com".to_string(),
            private_key: "not-a-pem".to_string(),
            token_uri: TOKEN_URI.to_string(),
            pubsub_subscription: tests_support::SUBSCRIPTION.to_string(),
        }));
        assert!(!play.configured());
        assert!(!play.pubsub_configured());
    }

    #[tokio::test]
    async fn play_store_debug_redacts_key_and_token() {
        let fake = FakeSend::new();
        let play = store(&fake);
        fake.reply(200, PURCHASE_JSON);
        play.product_purchase(TOKEN).await.unwrap();
        let debug = format!("{play:?}");
        assert!(!debug.contains(ACCESS_TOKEN), "{debug}");
        assert!(!debug.contains(TOKEN), "{debug}");
        assert!(debug.contains("gg.sloga.app"), "{debug}");
        assert!(debug.contains("private_key: \"<redacted>\""), "{debug}");
        assert!(debug.contains("access_token: \"<redacted>\""), "{debug}");
    }

    /// Lines of `source` before its test module that call a `log` macro directly (they would
    /// bypass `store_log`, so nothing here could see them)
    fn direct_log_calls(source: &str) -> usize {
        let code = source.split("\nmod tests {").next().unwrap();
        let mut needles: Vec<String> = ["error", "warn", "info", "debug", "trace", "log"]
            .iter()
            .map(|level| format!("{}::{level}!", "log"))
            .collect();
        needles.extend(
            ["error", "warn", "info", "debug", "trace"]
                .iter()
                .map(|level| format!("{level}!(")),
        );
        needles.push(format!("{} log", "use"));
        code.lines()
            .filter(|line| needles.iter().any(|needle| line.contains(needle.as_str())))
            .count()
    }

    #[tokio::test]
    async fn play_client_never_logs_the_token() {
        let fake = FakeSend::new();
        let play = store(&fake);
        log_capture::take();
        let echo = format!(r#"{{"error": {{"message": "purchase token {TOKEN} is invalid"}}}}"#);
        let mut answers: Vec<String> = Vec::new();

        // Every failure of the two calls that carry the token, with bodies that echo it
        for status in [401, 403, 404, 400, 410, 429, 500, 503] {
            fake.reply(status, &echo);
            answers.push(format!("{:?}", play.product_purchase(TOKEN).await));
            fake.reply(status, &echo);
            answers.push(format!(
                "{:?}",
                play.consume("gg.sloga.prot.p5", TOKEN).await
            ));
        }
        fake.fail(StoreApiError::Transient("request timed out".to_string()));
        answers.push(format!("{:?}", play.product_purchase(TOKEN).await));
        fake.reply(200, &format!(r#"{{"unexpected": "{TOKEN}"}}"#));
        answers.push(format!("{:?}", play.product_purchase(TOKEN).await));

        // Answers that carry the token: a void page, an RTDN message
        fake.reply(
            200,
            &format!(r#"{{"voidedPurchases": [{{"purchaseToken": "{TOKEN}", "voidedTimeMillis": "soon"}}]}}"#),
        );
        answers.push(format!("{:?}", play.voided_purchases(1, None).await));
        fake.reply(
            200,
            &format!(r#"{{"voidedPurchases": [{{"purchaseToken": "{TOKEN}", "voidedTimeMillis": "7"}}]}}"#),
        );
        answers.push(format!("{:?}", play.voided_purchases(1, None).await));
        let rtdn = format!(r#"{{"oneTimeProductNotification": {{"purchaseToken": "{TOKEN}"}}}}"#);
        fake.reply(
            200,
            &format!(
                r#"{{"receivedMessages": [{{"ackId": "a", "message": {{"data": "{}", "messageId": "m"}}}}]}}"#,
                STANDARD.encode(rtdn.as_bytes())
            ),
        );
        answers.push(format!("{:?}", play.pull(10).await));
        answers.push(format!("{play:?}"));

        let lines = log_capture::take();
        // The failures were logged, naming the purchase by its id
        let id = play_purchase_id(TOKEN);
        assert!(
            lines.iter().filter(|line| line.contains(&id)).count() >= 17,
            "{lines:?}"
        );
        for text in lines.iter().chain(answers.iter()) {
            assert!(!text.contains(TOKEN), "{text}");
            assert!(!text.contains("SecretPurchaseToken"), "{text}");
            assert!(!text.contains(ACCESS_TOKEN), "{text}");
            assert!(!text.contains(ASSERTION), "{text}");
        }

        // Every log line of the Play path goes through `store_log`, the one `log` call in mod.rs
        assert_eq!(direct_log_calls(include_str!("play_api.rs")), 0);
        assert_eq!(direct_log_calls(include_str!("google_auth.rs")), 0);
        assert_eq!(direct_log_calls(include_str!("apple_api.rs")), 0);
        assert_eq!(direct_log_calls(include_str!("mock.rs")), 0);
        assert_eq!(direct_log_calls(include_str!("mod.rs")), 1);
    }
}
