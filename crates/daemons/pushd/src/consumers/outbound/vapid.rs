use std::{
    collections::HashMap,
    future::Future,
    io::Cursor,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
    time::Duration,
};

use crate::utils::Consumer;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use base64::{
    engine::{self},
    Engine as _,
};
use isahc::{
    config::{Configurable, RedirectPolicy},
    HttpClient,
};
use lapin::{message::Delivery, Channel as AMQPChannel, Connection};
use log::{error, info, warn};
use revolt_database::{events::rabbit::*, util::format_display_name, Database};
use revolt_models::v0::push_endpoint_allowed;
use sha2::{Digest, Sha256};
use web_push::{
    ContentEncoding, IsahcWebPushClient, SubscriptionInfo, SubscriptionKeys, VapidSignature,
    VapidSignatureBuilder, WebPushClient, WebPushError, WebPushMessageBuilder,
};

/// Upstream Revolt's committed default public key (unpadded). Its private half is public,
/// so a pushd signing with it must be rotated.
pub(crate) const UPSTREAM_DEFAULT_VAPID_PUBLIC: &str =
    "BGcvgR-i2z4IQ5Mw841vJvkLjt8wY-FjmWrw83jOLCY52qcGZS0OF7nfLzuYbjsQISwVO2HXrmf18gLWVX3Kwfw";

/// Trims, maps the standard alphabet to base64url and strips padding
pub(crate) fn normalize_b64url(s: &str) -> String {
    s.trim()
        .chars()
        .filter(|c| *c != '=')
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect()
}

/// First 12 lowercase hex chars of the sha256 of `s`, for logging key identities
pub(crate) fn sha256_prefix(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Decodes a config key exactly as `create()` does: unpadded base64url, nothing normalized
fn decode_private_key(private_b64url: &str) -> Result<Vec<u8>, String> {
    engine::general_purpose::URL_SAFE_NO_PAD
        .decode(private_b64url)
        .map_err(|_| "not unpadded base64url".to_string())
}

/// Derives the unpadded base64url public point (87 chars) of a config private key
pub(crate) fn derive_public_b64url(private_b64url: &str) -> Result<String, String> {
    derive_public_from_pem(&decode_private_key(private_b64url)?)
}

fn derive_public_from_pem(pem: &[u8]) -> Result<String, String> {
    // sec1_decode panics on explicit-parameter curves instead of returning an error. The panic
    // hook still runs (printed, and sent to Sentry once configured; `--check-config` prints only
    // its location); it is caught only so one bad key fails the self-check, not the process
    let point = catch_unwind(AssertUnwindSafe(|| {
        VapidSignatureBuilder::from_pem_no_sub(Cursor::new(pem))
            .map(|builder| builder.get_public_key())
    }))
    .map_err(|_| "key parser panicked".to_string())?
    .map_err(|err| format!("not a usable key ({})", err.short_description()))?;

    if point.len() != 65 || point[0] != 0x04 {
        return Err("not an uncompressed P-256 point".to_string());
    }

    Ok(engine::general_purpose::URL_SAFE_NO_PAD.encode(point))
}

/// Startup self-check of the configured keys. Holds PEM bytes: never Debug-print it.
struct KeyCheck {
    /// Public point derived from `private_key`, or why it could not be derived
    primary_public: Result<String, String>,
    /// `private_key` derives the configured `public_key`
    primary_matches: bool,
    /// `None` when `legacy_private_key` is empty, else its PEM and public point
    legacy: Option<Result<(Vec<u8>, String), String>>,
    /// A 401 may be our own key's fault, so it must not delete subscriptions
    suppress_401_removal: bool,
}

fn check_keys(private_key: &str, public_key: &str, legacy_private_key: &str) -> KeyCheck {
    let primary_public = derive_public_b64url(private_key);
    let primary_matches =
        matches!(&primary_public, Ok(public) if *public == normalize_b64url(public_key));

    let legacy = if legacy_private_key.is_empty() {
        None
    } else {
        Some(decode_private_key(legacy_private_key).and_then(|pem| {
            let public = derive_public_from_pem(&pem)?;
            Ok((pem, public))
        }))
    };

    let suppress_401_removal = !primary_matches || matches!(legacy, Some(Err(_)));

    KeyCheck {
        primary_public,
        primary_matches,
        legacy,
        suppress_401_removal,
    }
}

fn report(message: &str) {
    error!("{message}");
    revolt_config::capture_message(message, revolt_config::Level::Error);
}

/// Logs the self-check: sha256 prefixes only, never a key
fn log_key_check(check: &KeyCheck, public_key: &str) {
    match &check.primary_public {
        Ok(public) => {
            info!("vapid: primary public sha256 {}", sha256_prefix(public));

            if public == UPSTREAM_DEFAULT_VAPID_PUBLIC {
                error!("pushd.vapid is upstream's committed default; rotate it");
            }

            if !check.primary_matches {
                report(&format!(
                    "vapid: private_key does not derive the configured public_key (configured sha256 {}); 401 removal suppressed",
                    sha256_prefix(&normalize_b64url(public_key))
                ));
            }
        }
        Err(reason) => report(&format!(
            "vapid: private_key does not parse ({reason}); 401 removal suppressed"
        )),
    }

    match &check.legacy {
        Some(Ok((_, public))) => info!(
            "vapid: legacy fallback armed (public sha256 {})",
            sha256_prefix(public)
        ),
        Some(Err(reason)) => {
            report(&format!(
                "vapid: legacy_private_key does not parse ({reason}); fallback disabled, 401 removal suppressed"
            ));
            info!("vapid: legacy fallback disabled");
        }
        None => info!("vapid: legacy fallback disabled"),
    }
}

/// How the push service answered one attempt
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Delivered,
    /// 401: Mozilla's answer to a key mismatch, also a dead subscription
    Unauthorized,
    /// 403, exactly: FCM's and Apple's answer to a key mismatch
    Forbidden,
    /// 404/410: the subscription is permanently gone
    Gone,
    /// Anything else (5xx, 400, 413, 429, transport, signing): kept, never retried
    Failed,
}

impl Outcome {
    /// A key rejection the legacy key may get past
    pub(crate) fn retries_with_legacy(self) -> bool {
        matches!(self, Outcome::Unauthorized | Outcome::Forbidden)
    }

    /// Whether the FINAL attempt means the stored subscription should be removed.
    /// A 403 never removes: it is what an old-key subscription gets once no key matches.
    pub(crate) fn removes_subscription(self, suppress_401_removal: bool) -> bool {
        match self {
            Outcome::Gone => true,
            Outcome::Unauthorized => !suppress_401_removal,
            Outcome::Delivered | Outcome::Forbidden | Outcome::Failed => false,
        }
    }
}

pub(crate) fn classify(result: &Result<(), WebPushError>) -> Outcome {
    match result {
        Ok(()) => Outcome::Delivered,
        Err(WebPushError::Unauthorized) => Outcome::Unauthorized,
        Err(WebPushError::Other(status)) if status == "403" => Outcome::Forbidden,
        Err(WebPushError::EndpointNotValid | WebPushError::EndpointNotFound) => Outcome::Gone,
        Err(_) => Outcome::Failed,
    }
}

/// Sends with the primary key (`send(false)`) and, only on a 401/403 and only when the
/// legacy key is armed, once more with the legacy key (`send(true)`). Returns the final
/// attempt's result and whether that attempt used the legacy key.
async fn deliver<F, Fut>(legacy_armed: bool, mut send: F) -> (Result<(), WebPushError>, bool)
where
    F: FnMut(bool) -> Fut,
    Fut: Future<Output = Result<(), WebPushError>>,
{
    let first = send(false).await;

    if legacy_armed && classify(&first).retries_with_legacy() {
        (send(true).await, true)
    } else {
        (first, false)
    }
}

/// Longest a single push-service request may take, connect included
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest the TCP + TLS connect may take
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The HTTP client for web-push sends.
///
/// `IsahcWebPushClient::new()` never times out, so one endpoint that accepts
/// the connection and never answers held a send (and its connection) forever.
/// Redirects are never followed: a push service answers directly, and a
/// redirect is the one way an allowed host could send us somewhere else.
fn web_push_client(timeout: Duration, connect_timeout: Duration) -> IsahcWebPushClient {
    HttpClient::builder()
        .timeout(timeout)
        .connect_timeout(connect_timeout)
        .redirect_policy(RedirectPolicy::None)
        .build()
        .map(IsahcWebPushClient::from)
        .expect("web-push HTTP client")
}

/// Parses the PEM and signs for this subscription, without panicking on a bad key
fn sign(pem: &[u8], subscription: &SubscriptionInfo) -> Result<VapidSignature, WebPushError> {
    // The panic hook still runs, so a caught parser panic is still printed and sent to Sentry
    // by the default panic integration; it is caught only so one bad key can't kill the consumer
    catch_unwind(AssertUnwindSafe(|| {
        VapidSignatureBuilder::from_pem(Cursor::new(pem), subscription)?.build()
    }))
    .unwrap_or(Err(WebPushError::InvalidCryptoKeys))
}

#[derive(Clone)]
#[allow(unused)]
pub struct VapidOutboundConsumer {
    db: Database,
    connection: Arc<Connection>,
    channel: Arc<AMQPChannel>,
    client: IsahcWebPushClient,
    pkey: Arc<Vec<u8>>,
    /// PEM of the previous key, tried once on a 401/403; only set when it parsed at startup
    legacy_pkey: Option<Arc<Vec<u8>>>,
    suppress_401_removal: bool,
}

impl VapidOutboundConsumer {
    fn key(&self, legacy: bool) -> &[u8] {
        match (legacy, &self.legacy_pkey) {
            (true, Some(legacy_pkey)) => legacy_pkey.as_slice(),
            _ => self.pkey.as_slice(),
        }
    }

    async fn attempt(
        &self,
        pem: &[u8],
        subscription: &SubscriptionInfo,
        payload_body: &[u8],
    ) -> Result<(), WebPushError> {
        let mut builder = WebPushMessageBuilder::new(subscription);
        builder.set_vapid_signature(sign(pem, subscription)?);
        builder.set_payload(ContentEncoding::AesGcm, payload_body);

        self.client.send(builder.build()?).await
    }
}

#[async_trait]
impl Consumer for VapidOutboundConsumer {
    async fn create(db: Database, connection: Arc<Connection>, channel: Arc<AMQPChannel>) -> Self {
        let config = revolt_config::config().await;
        let vapid = &config.pushd.vapid;

        if vapid.private_key.is_empty() || vapid.public_key.is_empty() {
            panic!("no Vapid keys present");
        }

        let web_push_private_key = Arc::new(
            engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&vapid.private_key)
                .expect("valid `VAPID_PRIVATE_KEY`"),
        );

        let check = check_keys(
            &vapid.private_key,
            &vapid.public_key,
            &vapid.legacy_private_key,
        );
        log_key_check(&check, &vapid.public_key);

        Self {
            db,
            connection,
            channel,
            client: web_push_client(SEND_TIMEOUT, CONNECT_TIMEOUT),
            pkey: web_push_private_key,
            legacy_pkey: match check.legacy {
                Some(Ok((pem, _))) => Some(Arc::new(pem)),
                _ => None,
            },
            suppress_401_removal: check.suppress_401_removal,
        }
    }

    fn channel(&self) -> &Arc<AMQPChannel> {
        &self.channel
    }

    async fn consume(&self, delivery: Delivery) -> Result<()> {
        let payload: PayloadToService = serde_json::from_slice(&delivery.data)?;

        let endpoint = payload
            .extras
            .get("endpoint")
            .ok_or_else(|| anyhow!("missing endpoint"))?;

        // delta refuses these at /push/subscribe; this catches anything stored
        // before that check existed, so a stored subscription can never make
        // this host POST to an internal address. The endpoint itself carries
        // the subscription's secret, so it is never logged.
        if !push_endpoint_allowed(endpoint) {
            warn!(
                "vapid: refusing a stored endpoint outside the push-service allowlist (session {})",
                payload.session_id
            );
            return Ok(());
        }

        let subscription = SubscriptionInfo {
            endpoint: endpoint.clone(),
            keys: SubscriptionKeys {
                auth: payload.token,
                p256dh: payload
                    .extras
                    .get("p256dh")
                    .ok_or_else(|| anyhow!("missing p256dh"))?
                    .clone(),
            },
        };

        let payload_body = match payload.notification {
            PayloadKind::FRReceived(alert) => {
                let name = alert
                    .from_user
                    .display_name
                    .or(Some(format!(
                        "{}#{}",
                        alert.from_user.username, alert.from_user.discriminator
                    )))
                    .clone()
                    .ok_or_else(|| anyhow!("missing name"))?;

                let mut body = HashMap::new();
                body.insert("body", format!("{} sent you a friend request", name));

                serde_json::to_string(&body)?
            }
            PayloadKind::FRAccepted(alert) => {
                let name = alert
                    .accepted_user
                    .display_name
                    .or(Some(format!(
                        "{}#{}",
                        alert.accepted_user.username, alert.accepted_user.discriminator
                    )))
                    .clone()
                    .ok_or_else(|| anyhow!("missing name"))?;

                let mut body = HashMap::new();
                body.insert("body", format!("{} accepted your friend request", name));

                serde_json::to_string(&body)?
            }
            PayloadKind::Generic(alert) => serde_json::to_string(&alert)?,
            PayloadKind::MessageNotification(alert) => serde_json::to_string(&alert)?,
            PayloadKind::DmCallStartEnd(alert) => {
                let initiator_name = if let Some(server_id) =
                    self.db.fetch_channel(&alert.channel_id).await?.server()
                {
                    format_display_name(&self.db, &alert.initiator_id, Some(server_id)).await
                } else {
                    format_display_name(&self.db, &alert.initiator_id, None).await
                }?;

                let channel = self.db.fetch_channel(&alert.channel_id).await?;
                let mut body = HashMap::new();

                match channel {
                    revolt_database::Channel::DirectMessage { .. } => {
                        body.insert("body", format!("{} is calling you", initiator_name));
                    }
                    revolt_database::Channel::Group { name, .. } => {
                        body.insert(
                            "body",
                            format!("{} is calling your group, {}", initiator_name, name),
                        );
                    }
                    _ => bail!("Invalid DmCallStart/End channel type"),
                }

                serde_json::to_string(&body)?
            }
            PayloadKind::CalendarEvent(alert) => {
                let (title, body) = alert.render();
                serde_json::to_string(&serde_json::json!({
                    "title": title,
                    "body": body,
                    "event_id": alert.event_id,
                    "server_id": alert.server_id,
                    "kind": alert.kind.as_str(),
                    "occurrence_start": alert.occurrence_start,
                    "channel_id": alert.channel_id,
                    "offset_ms": alert.offset_ms,
                }))?
            }
            PayloadKind::BadgeUpdate(_) => {
                bail!("Vapid cannot handle badge updates and they should not be sent here.");
            }
        };

        let this = self;
        let subscription_ref = &subscription;
        let body = payload_body.as_bytes();
        let (result, used_legacy) = deliver(self.legacy_pkey.is_some(), move |legacy| {
            this.attempt(this.key(legacy), subscription_ref, body)
        })
        .await;

        let outcome = classify(&result);
        if used_legacy && outcome == Outcome::Delivered {
            info!("vapid: legacy fallback delivered");
        }

        // EndpointNotValid/EndpointNotFound are the push service saying
        // this subscription is permanently gone (browser profile cleared,
        // subscription expired) — without removal, pushd re-sends to the
        // dead endpoint on every notification forever. Removal is keyed on
        // the endpoint too, so a stale queued push to an old endpoint cannot
        // delete the new subscription of a client that has since re-subscribed.
        if outcome.removes_subscription(self.suppress_401_removal) {
            if let Err(err) = self
                .db
                .remove_push_subscription_if_endpoint(&payload.session_id, &subscription.endpoint)
                .await
            {
                revolt_config::capture_error(&err);
            }

            return Ok(());
        }

        // Only the final attempt's failure is reported
        result?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed default config; keys are read from it at runtime, never as literals
    const DEFAULT_CONFIG: &str = include_str!("../../../../../core/config/Revolt.toml");

    /// Reads `key` from `[pushd.vapid]` of the embedded default config
    fn default_vapid(key: &str) -> String {
        let mut in_table = false;
        for line in DEFAULT_CONFIG.lines().map(str::trim) {
            if line.starts_with('[') {
                in_table = line == "[pushd.vapid]";
            } else if in_table && !line.starts_with('#') {
                if let Some((name, value)) = line.split_once('=') {
                    if name.trim() == key {
                        return value.trim().trim_matches('"').to_string();
                    }
                }
            }
        }

        panic!("`{key}` missing from [pushd.vapid]");
    }

    /// DER of the `[0]` parameters field: the named curve prime256v1
    const NAMED_CURVE: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    /// DER of the `[0]` parameters field: a SEQUENCE, the shape of explicit curve parameters
    const EXPLICIT_PARAMETERS: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];

    /// A synthetic SEC1 key over the non-secret scalar 0x11..11, in the config encoding
    /// (unpadded base64url of the PEM)
    fn synthetic_key(parameters: &[u8]) -> String {
        let mut body = vec![0x02, 0x01, 0x01, 0x04, 0x20];
        // Synthetic, trivially known, non-secret test scalar (0x11 x 32): not a real key and
        // not upstream's key. Test-only.
        body.extend_from_slice(&[0x11; 32]);
        body.push(0xa0);
        body.push(parameters.len() as u8);
        body.extend_from_slice(parameters);

        let mut der = vec![0x30, body.len() as u8];
        der.extend(body);

        let pem = format!(
            "-----BEGIN EC PRIVATE KEY-----\n{}\n-----END EC PRIVATE KEY-----\n",
            engine::general_purpose::STANDARD.encode(der)
        );

        engine::general_purpose::URL_SAFE_NO_PAD.encode(pem)
    }

    /// Public point of the synthetic scalar, derived independently with openssl
    const SYNTHETIC_PUBLIC: &str =
        "BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q";

    /// Runs `deliver` against scripted push-service answers; returns the final result,
    /// whether it used the legacy key, and the key used by each attempt
    async fn run(
        legacy_armed: bool,
        answers: Vec<Result<(), WebPushError>>,
    ) -> (Result<(), WebPushError>, bool, Vec<bool>) {
        let mut answers = answers.into_iter();
        let mut keys = Vec::new();
        let (result, used_legacy) = deliver(legacy_armed, |legacy| {
            keys.push(legacy);
            std::future::ready(answers.next().expect("no answer scripted for this attempt"))
        })
        .await;

        (result, used_legacy, keys)
    }

    fn status_403() -> Result<(), WebPushError> {
        Err(WebPushError::Other("403".to_string()))
    }

    #[tokio::test]
    async fn vapid_401_retries_then_removes() {
        let (result, used_legacy, keys) = run(
            true,
            vec![
                Err(WebPushError::Unauthorized),
                Err(WebPushError::Unauthorized),
            ],
        )
        .await;
        assert_eq!(keys, vec![false, true]);
        assert!(used_legacy);
        assert_eq!(classify(&result), Outcome::Unauthorized);
        assert!(classify(&result).removes_subscription(false));

        let (result, used_legacy, keys) =
            run(true, vec![Err(WebPushError::Unauthorized), Ok(())]).await;
        assert_eq!(keys, vec![false, true]);
        assert!(used_legacy);
        assert_eq!(classify(&result), Outcome::Delivered);
        assert!(!classify(&result).removes_subscription(false));
    }

    #[tokio::test]
    async fn vapid_403_retries_and_never_removes() {
        let (result, used_legacy, keys) = run(true, vec![status_403(), status_403()]).await;
        assert_eq!(keys, vec![false, true]);
        assert!(used_legacy);
        assert_eq!(classify(&result), Outcome::Forbidden);
        assert!(!classify(&result).removes_subscription(false));
        assert!(!classify(&result).removes_subscription(true));

        let (result, used_legacy, keys) = run(true, vec![status_403(), Ok(())]).await;
        assert_eq!(keys, vec![false, true]);
        assert!(used_legacy);
        assert_eq!(classify(&result), Outcome::Delivered);

        // Disarmed: a 403 is final and still kept
        let (result, used_legacy, keys) = run(false, vec![status_403()]).await;
        assert_eq!(keys, vec![false]);
        assert!(!used_legacy);
        assert!(!classify(&result).removes_subscription(false));
    }

    #[tokio::test]
    async fn vapid_gone_removes_without_retry() {
        for gone in [
            WebPushError::EndpointNotValid,
            WebPushError::EndpointNotFound,
        ] {
            let (result, used_legacy, keys) = run(true, vec![Err(gone)]).await;
            assert_eq!(keys, vec![false]);
            assert!(!used_legacy);
            assert_eq!(classify(&result), Outcome::Gone);
            assert!(classify(&result).removes_subscription(false));
            assert!(classify(&result).removes_subscription(true));
        }
    }

    #[tokio::test]
    async fn vapid_server_errors_are_final_and_kept() {
        for failure in [
            WebPushError::ServerError(None),
            WebPushError::Unspecified,
            WebPushError::BadRequest(None),
            WebPushError::Other("429".to_string()),
            WebPushError::Other("4030".to_string()),
        ] {
            let (result, used_legacy, keys) = run(true, vec![Err(failure)]).await;
            assert_eq!(keys, vec![false]);
            assert!(!used_legacy);
            assert_eq!(classify(&result), Outcome::Failed);
            assert!(!classify(&result).removes_subscription(false));
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn vapid_401_with_suppression_is_kept() {
        let (result, _, keys) = run(
            true,
            vec![
                Err(WebPushError::Unauthorized),
                Err(WebPushError::Unauthorized),
            ],
        )
        .await;
        assert_eq!(keys, vec![false, true]);
        assert!(!classify(&result).removes_subscription(true));

        // Disarmed: no retry, the first 401 is final
        let (result, used_legacy, keys) = run(false, vec![Err(WebPushError::Unauthorized)]).await;
        assert_eq!(keys, vec![false]);
        assert!(!used_legacy);
        assert!(classify(&result).removes_subscription(false));
        assert!(!classify(&result).removes_subscription(true));
    }

    #[test]
    fn vapid_normalize_and_derive_round_trip() {
        let derived = derive_public_b64url(&synthetic_key(NAMED_CURVE)).expect("synthetic key");
        assert_eq!(derived, SYNTHETIC_PUBLIC);
        assert_eq!(derived.len(), 87);

        let point = engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&derived)
            .expect("unpadded base64url");
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);

        let padded_standard = engine::general_purpose::STANDARD.encode(&point);
        assert!(padded_standard.ends_with('='));
        assert_eq!(normalize_b64url(&format!(" {padded_standard}\n")), derived);
        assert_eq!(normalize_b64url(&derived), derived);
    }

    #[test]
    fn vapid_upstream_default_is_detected() {
        assert_eq!(UPSTREAM_DEFAULT_VAPID_PUBLIC.len(), 87);
        assert_eq!(sha256_prefix(UPSTREAM_DEFAULT_VAPID_PUBLIC), "23e02a5cc63d");
        assert_eq!(
            normalize_b64url(&default_vapid("public_key")),
            UPSTREAM_DEFAULT_VAPID_PUBLIC
        );

        let check = check_keys(
            &default_vapid("private_key"),
            &default_vapid("public_key"),
            "",
        );
        assert_eq!(
            check.primary_public.as_deref(),
            Ok(UPSTREAM_DEFAULT_VAPID_PUBLIC)
        );
        assert!(check.primary_matches);
        assert!(check.legacy.is_none());
        // The default is a valid pair: flagged by the log, not by suppression
        assert!(!check.suppress_401_removal);
    }

    #[test]
    fn vapid_mismatched_pair_is_flagged() {
        let check = check_keys(
            &synthetic_key(NAMED_CURVE),
            UPSTREAM_DEFAULT_VAPID_PUBLIC,
            "",
        );
        assert_eq!(check.primary_public.as_deref(), Ok(SYNTHETIC_PUBLIC));
        assert!(!check.primary_matches);
        assert!(check.suppress_401_removal);

        let check = check_keys(&synthetic_key(NAMED_CURVE), SYNTHETIC_PUBLIC, "");
        assert!(check.primary_matches);
        assert!(!check.suppress_401_removal);
    }

    #[test]
    fn vapid_legacy_key_arms_or_suppresses() {
        let check = check_keys(
            &synthetic_key(NAMED_CURVE),
            SYNTHETIC_PUBLIC,
            &default_vapid("private_key"),
        );
        assert!(matches!(
            &check.legacy,
            Some(Ok((_, public))) if public == UPSTREAM_DEFAULT_VAPID_PUBLIC
        ));
        assert!(!check.suppress_401_removal);

        let explicit = synthetic_key(EXPLICIT_PARAMETERS);
        for unparseable in ["not a key", "bm90IGEga2V5", explicit.as_str()] {
            let check = check_keys(&synthetic_key(NAMED_CURVE), SYNTHETIC_PUBLIC, unparseable);
            assert!(matches!(check.legacy, Some(Err(_))));
            assert!(check.suppress_401_removal);
        }
    }

    /// A bare web-push message to a local test endpoint
    fn local_message(port: u16) -> web_push::WebPushMessage {
        let subscription = SubscriptionInfo::new(
            format!("http://127.0.0.1:{port}/push"),
            SYNTHETIC_PUBLIC.to_string(),
            "c2VjcmV0c2VjcmV0c2VjcmV0".to_string(),
        );
        WebPushMessageBuilder::new(&subscription)
            .build()
            .expect("message")
    }

    #[tokio::test]
    async fn vapid_send_gives_up_on_a_silent_endpoint() {
        // Accepts the connection, then never writes a byte
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let _held: Vec<_> = listener.incoming().take(1).collect();
            std::thread::sleep(Duration::from_secs(30));
        });

        let client = web_push_client(Duration::from_millis(500), Duration::from_millis(500));
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(10), client.send(local_message(port)))
            .await
            .expect("the client must time out on its own");

        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn vapid_send_never_follows_a_redirect() {
        // Where a redirect would lead; nothing may ever connect here
        let target = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let target_port = target.local_addr().expect("addr").port();
        target.set_nonblocking(true).expect("nonblocking");

        let redirector = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = redirector.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Some(Ok(mut stream)) = redirector.incoming().next() {
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                let _ = write!(
                    stream,
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{target_port}/push\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
        });

        let client = web_push_client(Duration::from_secs(5), Duration::from_secs(5));
        let result = tokio::time::timeout(Duration::from_secs(15), client.send(local_message(port)))
            .await
            .expect("the client must answer on its own");

        assert!(result.is_err());
        assert!(matches!(
            target.accept(),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn vapid_explicit_parameters_do_not_panic() {
        let key = synthetic_key(EXPLICIT_PARAMETERS);
        let pem = engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&key)
            .expect("unpadded base64url");

        // Control: the parser itself panics on this input
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _ = VapidSignatureBuilder::from_pem_no_sub(Cursor::new(&pem));
        }))
        .is_err());

        assert!(derive_public_b64url(&key).is_err());

        let subscription = SubscriptionInfo::new(
            "https://push.example.com/endpoint",
            SYNTHETIC_PUBLIC,
            "c2VjcmV0c2VjcmV0c2VjcmV0",
        );
        assert!(matches!(
            sign(&pem, &subscription),
            Err(WebPushError::InvalidCryptoKeys)
        ));
    }
}
