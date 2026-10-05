use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::{
    consumers::outbound::fcm::{notification_data, NotificationData},
    utils::Consumer,
};

use super::up_limiter::{Admit, Bucket, DestKey, Offender, Rejected, SubKey, UpLimiter};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{
    engine::{self},
    Engine as _,
};
use isahc::{
    config::{Configurable, Dialer, RedirectPolicy},
    http::{Request, Uri},
    AsyncBody, HttpClient, RequestExt,
};
use lapin::{message::Delivery, Channel as AMQPChannel, Connection};
use log::{error, info, warn};
use revolt_database::{events::rabbit::*, Database};
use serde_json::Value;
use web_push::{
    request_builder::{build_request, parse_response},
    ContentEncoding, SubscriptionInfo, SubscriptionKeys, Urgency, VapidSignature,
    VapidSignatureBuilder, WebPushError, WebPushMessage, WebPushMessageBuilder,
};

/// Longest `body` we forward, in UTF-8 bytes.
const MAX_BODY_BYTES: usize = 1000;

/// web-push refuses plaintext above this many bytes (http_ece.rs).
const MAX_PAYLOAD_BYTES: usize = 3052;

/// TTL for everything except call rings: one day.
const DEFAULT_TTL_SECS: u32 = 86400;

/// Ring TTL if `call_ring_duration` does not fit in a u32.
const FALLBACK_RING_TTL_SECS: u32 = 30;

/// Longest a send waits, in all, while every rejection token of its
/// destination is reserved by sends in flight. Past it, the push is dropped.
const SLOT_WAIT: Duration = Duration::from_secs(10);

/// Least time between two "waited for a send slot" log lines.
const SLOT_TIMEOUT_LOG_EVERY: Duration = Duration::from_secs(60);

/// What a send result means for the stored subscription.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Delivered,
    /// The distributor says the endpoint is gone for good.
    Prune,
    /// Failed, but nothing about it is permanent for the endpoint.
    Keep,
}

#[derive(Clone)]
#[allow(unused)]
pub struct UnifiedPushOutboundConsumer {
    db: Database,
    connection: Arc<Connection>,
    channel: Arc<AMQPChannel>,
    client: HttpClient,
    pkey: Arc<Vec<u8>>,
    /// Shared by every clone, so the limits hold across deliveries.
    limiter: Arc<UpLimiter>,
    /// Shared by every clone, like the limiter.
    slot_timeouts: Arc<LogThrottle>,
}

/// What happened to a send that went through the rate limiter.
#[derive(Debug)]
enum Gated {
    /// Over a limit: nothing was signed or sent.
    Denied { first: bool, bucket: Bucket },
    /// Sends in flight held every rejection token for the whole wait:
    /// nothing was signed or sent.
    SlotTimeout,
    /// Admitted, but signing or encrypting the message failed.
    BuildFailed(anyhow::Error),
    /// Admitted and sent; the push server's answer, and what it did to the
    /// destination's rejection budget if it was an HTTP rejection.
    Sent {
        result: Result<(), WebPushError>,
        rejected: Option<Rejected>,
    },
}

/// Where a send may go, or why it may not.
#[derive(Debug, PartialEq, Eq)]
enum Destination {
    /// Not an https URL with a host.
    Invalid,
    /// An ntfy.sh endpoint that is not a UnifiedPush topic URL.
    NotNtfyTopic { host: String },
    /// Does not resolve to only public addresses.
    NotPublic { host: String },
    /// Send to `host`, connecting only to `addr`.
    Checked { host: String, addr: SocketAddr },
}

/// Lets a log line through at most once per `every`, across every clone of
/// the consumer.
struct LogThrottle {
    epoch: Instant,
    every: Duration,
    /// Whole seconds from `epoch` to the last line let through, plus one, so
    /// 0 means none yet.
    last: AtomicU64,
}

impl LogThrottle {
    fn new(every: Duration) -> Self {
        LogThrottle {
            epoch: Instant::now(),
            every,
            last: AtomicU64::new(0),
        }
    }

    /// Whether a line may be logged at `now`. Of several callers racing for
    /// the same slot, only one gets it.
    fn ready(&self, now: Instant) -> bool {
        let now_secs = now.saturating_duration_since(self.epoch).as_secs() + 1;
        let last = self.last.load(Ordering::Relaxed);
        if last != 0 && now_secs < last.saturating_add(self.every.as_secs()) {
            return false;
        }

        self.last
            .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }
}

#[async_trait]
impl Consumer for UnifiedPushOutboundConsumer {
    async fn create(db: Database, connection: Arc<Connection>, channel: Arc<AMQPChannel>) -> Self {
        let config = revolt_config::config().await;

        if config.pushd.vapid.private_key.is_empty() || config.pushd.vapid.public_key.is_empty() {
            panic!("no Vapid keys present");
        }

        let web_push_private_key = Arc::new(
            engine::general_purpose::URL_SAFE_NO_PAD
                .decode(config.pushd.vapid.private_key)
                .expect("valid `VAPID_PRIVATE_KEY`"),
        );

        // One client for every send: each one spawns an agent thread.
        Self {
            db,
            connection,
            channel,
            client: http_client(),
            pkey: web_push_private_key,
            limiter: Arc::new(UpLimiter::new()),
            slot_timeouts: Arc::new(LogThrottle::new(SLOT_TIMEOUT_LOG_EVERY)),
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
            .ok_or_else(|| anyhow!("missing endpoint"))?
            .clone();

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

        let Some(data) = notification_data(payload.notification).await? else {
            return Ok(());
        };

        let (ty, bytes) = encode_payload(data)?;
        if exceeds_payload_cap(&bytes) {
            warn!(
                "Dropping UnifiedPush {} for session {}: payload is {} bytes",
                ty,
                payload.session_id,
                bytes.len()
            );

            return Ok(());
        }

        let sub = SubKey::new(&payload.session_id, &endpoint);

        // The endpoint is client-supplied, so check where it points right
        // before we POST to it. The endpoint itself is never logged: it is a
        // bearer capability for the device.
        let destination = resolve_destination(&endpoint, |host, port| async move {
            checked_address(&host, port).await
        })
        .await;

        let (host, addr) = match destination {
            Destination::Invalid => {
                warn!(
                    "Refusing UnifiedPush for session {}: endpoint is not a valid https URL",
                    payload.session_id
                );

                return Ok(());
            }
            Destination::NotNtfyTopic { host } => {
                // The subscription is kept, so every push to it ends up
                // here: log it once per subscription per hour.
                if self.limiter.first_refusal(sub, Instant::now()) {
                    warn!(
                        "Refusing UnifiedPush for session {} (user: {}): {} endpoint is not a UnifiedPush topic URL",
                        payload.session_id, payload.user_id, host
                    );
                }

                return Ok(());
            }
            Destination::NotPublic { host } => {
                warn!(
                    "Refusing UnifiedPush for session {}: {} does not resolve to only public addresses",
                    payload.session_id, host
                );

                return Ok(());
            }
            Destination::Checked { host, addr } => (host, addr),
        };

        let key = limit_key(&host, addr.ip());

        // Read before the gate: the message is built in a sync closure.
        let ring_secs = revolt_config::config().await.api.livekit.call_ring_duration;

        // Signing and encryption run only once the send is admitted.
        let gated = gated_send(
            &self.limiter,
            &self.client,
            &payload.user_id,
            sub,
            key,
            addr,
            SLOT_WAIT,
            || {
                let signature = VapidSignatureBuilder::from_pem(
                    std::io::Cursor::new(self.pkey.as_ref()),
                    &subscription,
                )?
                .build()?;

                Ok(build_message(
                    &subscription,
                    Some(signature),
                    &bytes,
                    &ty,
                    ring_secs,
                )?)
            },
        )
        .await;

        let (result, rejected) = match gated {
            Gated::Denied { first, bucket } => {
                // Once per empty episode of that bucket, so a flood of drops
                // does not become a flood of log lines. A paused destination
                // and a cooled subscription stay quiet: the pause is logged
                // once, when it trips.
                if first {
                    match bucket {
                        Bucket::Ip => warn!(
                            "{}",
                            destination_limit_line(
                                &self.limiter,
                                &host,
                                key,
                                &payload.session_id,
                                &payload.user_id
                            )
                        ),
                        Bucket::User => warn!(
                            "Dropping UnifiedPush for session {} (user: {}) to {} [{}]: per-user limit",
                            payload.session_id,
                            payload.user_id,
                            host,
                            key_label(key)
                        ),
                        Bucket::Paused | Bucket::Subscription => {}
                    }
                }

                return Ok(());
            }
            Gated::SlotTimeout => {
                if self.slot_timeouts.ready(Instant::now()) {
                    warn!(
                        "UnifiedPush to {} [{}] waited {} s for a send slot (this push: session {}, user {}, dropped)",
                        host,
                        key_label(key),
                        SLOT_WAIT.as_secs(),
                        payload.session_id,
                        payload.user_id
                    );
                }

                return Ok(());
            }
            Gated::BuildFailed(err) => return Err(err),
            Gated::Sent { result, rejected } => (result, rejected),
        };

        // The rejection that spent the budget names who spent it.
        if let Some(Rejected::Paused { top, others }) = rejected {
            warn!(
                "UnifiedPush rejection budget spent for {} [{}], sends paused (top offenders: {}; others: {})",
                host,
                key_label(key),
                offender_list(&top),
                others
            );
        }

        match outcome(&result) {
            Outcome::Delivered => {}
            // Only drop the endpoint if it is still the stored one, so a late
            // failure cannot wipe a subscription the device has since replaced.
            Outcome::Prune => {
                info!(
                    "Removing UnifiedPush subscription id {:} (user: {:}) due to a gone endpoint",
                    &payload.session_id, &payload.user_id
                );

                if let Err(err) = self
                    .db
                    .remove_push_subscription_if_endpoint(&payload.session_id, &endpoint)
                    .await
                {
                    revolt_config::capture_error(&err);
                }
            }
            Outcome::Keep => {
                // 401 means our VAPID key does not match the one the device
                // subscribed with; that is a server problem, not a dead
                // endpoint.
                if let Err(WebPushError::Unauthorized) = result {
                    error!(
                        "UnifiedPush VAPID rejected for session {} (subscription kept)",
                        payload.session_id
                    );
                } else if should_drain(&result) {
                    // Rate limited by the push server: gated_send has already
                    // backed this user off for that destination. Logged on its
                    // own so a 429 never hides behind the generic error text.
                    warn!(
                        "UnifiedPush {} for session {} (user: {}) rate limited by {} (429)",
                        ty, payload.session_id, payload.user_id, host
                    );
                } else if let Err(err) = result {
                    warn!(
                        "UnifiedPush {} for session {} failed: {} ({:?})",
                        ty, payload.session_id, err, err
                    );
                }
            }
        };

        Ok(())
    }
}

/// The HTTP client for every send. isahc never times out on its own, and the
/// endpoint is client-supplied, so a stalled server would pin a consumer task.
/// Redirects are never followed: a push server answers directly.
fn http_client() -> HttpClient {
    HttpClient::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .redirect_policy(RedirectPolicy::None)
        .build()
        .expect("isahc HttpClient")
}

/// POST a message to its endpoint, connecting only to `addr`. Returns the
/// result and, if the server answered, its HTTP status: web-push folds every
/// 5xx into `ServerError`, and the limiter must tell a 503 from a 507.
async fn send_pinned(
    client: &HttpClient,
    message: WebPushMessage,
    addr: SocketAddr,
) -> (Result<(), WebPushError>, Option<u16>) {
    let Ok(request) = pinned_request(message, addr) else {
        return (Err(WebPushError::Unspecified), None);
    };

    // A transport error becomes WebPushError::Unspecified, as it does in
    // web-push's IsahcWebPushClient (isahc_client.rs, error.rs).
    let response = match client.send_async(request).await {
        Ok(response) => response,
        Err(err) => return (Err(err.into()), None),
    };

    // The body is never read: there is no capped reader without a new
    // dependency, it only carries error detail, and every error except
    // 404/410 is kept anyway. Dropping the response aborts the transfer.
    let status = response.status();
    (parse_response(status, Vec::new()), Some(status.as_u16()))
}

/// Admit, build, send, then settle the ticket and back off on a 429, in
/// that order. `make_msg` (VAPID signing and encryption) runs only once the
/// send is admitted. While every rejection token of the destination is
/// reserved by sends in flight, wait for one of them to finish, for at most
/// `slot_wait` in all. Every limiter call is synchronous, so its lock is
/// never held across an await.
#[allow(clippy::too_many_arguments)]
async fn gated_send<F>(
    limiter: &UpLimiter,
    client: &HttpClient,
    user_id: &str,
    sub: SubKey,
    key: DestKey,
    addr: SocketAddr,
    slot_wait: Duration,
    make_msg: F,
) -> Gated
where
    F: FnOnce() -> Result<WebPushMessage>,
{
    let deadline = Instant::now() + slot_wait;
    let ticket = loop {
        // Made before admit, so a release between the two still wakes it.
        let released = limiter.released();

        match limiter.admit(user_id, sub, key, Instant::now()) {
            Admit::Allowed(ticket) => break ticket,
            Admit::Denied { first, bucket } => return Gated::Denied { first, bucket },
            Admit::Wait => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() || tokio::time::timeout(left, released).await.is_err() {
                    return Gated::SlotTimeout;
                }
            }
        }
    };

    // Returning drops the ticket, which only releases its reservation.
    let message = match make_msg() {
        Ok(message) => message,
        Err(err) => return Gated::BuildFailed(err),
    };

    let (result, status) = send_pinned(client, message, addr).await;

    let rejected = if result.is_ok() {
        ticket.success();
        None
    } else if is_http_rejection(&result) {
        let prunes = outcome(&result) == Outcome::Prune;
        Some(ticket.rejected(prunes, status, Instant::now()))
    } else {
        // The request never got an answer, so the push server has nothing
        // to count against us: release the reservation, spend nothing.
        drop(ticket);
        None
    };

    // ntfy charges UnifiedPush topics to the subscriber, so a 429 is about
    // this user's pushes to this destination, not everyone's.
    if should_drain(&result) {
        limiter.drain_user(user_id, key, Instant::now());
    }

    Gated::Sent { result, rejected }
}

/// Check an endpoint in the order that costs least: its URL, then the
/// ntfy.sh shape rule, and only then the address lookup `resolve` does.
async fn resolve_destination<R, F>(endpoint: &str, resolve: R) -> Destination
where
    R: FnOnce(String, u16) -> F,
    F: Future<Output = Option<SocketAddr>>,
{
    let Some((host, port)) = endpoint_host_port(endpoint) else {
        return Destination::Invalid;
    };

    // Before the lookup, so a refused endpoint costs no DNS and no tokens.
    if !ntfy_endpoint_allowed(endpoint) {
        return Destination::NotNtfyTopic { host };
    }

    // The send connects only to this address, so a DNS server cannot pass
    // the check and then answer differently for the connection.
    match resolve(host.clone(), port).await {
        Some(addr) => Destination::Checked { host, addr },
        None => Destination::NotPublic { host },
    }
}

/// Whether `host` is ntfy.sh or one of its subdomains, however it is
/// spelled: DNS ignores case and a trailing dot.
fn is_ntfy_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let host = host.trim_end_matches('.');

    host == "ntfy.sh" || host.ends_with(".ntfy.sh")
}

/// Whether an endpoint may be sent to. Every host but ntfy.sh passes. On
/// ntfy.sh only the URL its app registers does: `/up` plus 12 topic
/// characters, optionally `?up=1`, on the default port. A publish anywhere
/// else there is not a UnifiedPush message, and every rejection it earns
/// counts toward a ban of our IP.
fn ntfy_endpoint_allowed(endpoint: &str) -> bool {
    let Ok(uri) = endpoint.parse::<Uri>() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    if !is_ntfy_host(authority.host()) {
        return true;
    }

    // ntfy's own test for a UnifiedPush topic, plus the leading slash.
    let topic_ok = uri
        .path()
        .strip_prefix("/up")
        .is_some_and(|id| id.len() == 12 && id.bytes().all(is_topic_byte));

    // No userinfo, the default port, no query but `up=1`, and no fragment.
    // http::Uri drops a fragment while parsing, so the raw string is checked.
    !authority.as_str().contains('@')
        && !matches!(uri.port_u16(), Some(port) if port != 443)
        && topic_ok
        && matches!(uri.query(), None | Some("up=1"))
        && !endpoint.contains('#')
}

/// A byte ntfy allows in a topic name: `[-_A-Za-z0-9]`.
fn is_topic_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Truncate `s` to at most `max` bytes without splitting a character.
fn truncate_utf8(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }

    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }

    s.truncate(end);
}

/// Whether a serialized payload is too large to encrypt.
fn exceeds_payload_cap(bytes: &[u8]) -> bool {
    bytes.len() > MAX_PAYLOAD_BYTES
}

/// The notification type and the JSON we encrypt for it, with `body`
/// truncated to `MAX_BODY_BYTES`.
fn encode_payload(data: NotificationData) -> Result<(String, Vec<u8>)> {
    let ty = data.get_type().to_string();
    let mut map = data.into_payload();
    map.insert("type".to_string(), Value::String(ty.clone()));

    if let Some(Value::String(body)) = map.get_mut("body") {
        truncate_utf8(body, MAX_BODY_BYTES);
    }

    let bytes = serde_json::to_vec(&map)?;
    Ok((ty, bytes))
}

/// Urgency and TTL for a notification type. A ring is useless once the call
/// has stopped ringing, and it should wake a dozing device.
fn delivery_params(ty: &str, call_ring_duration: usize) -> (Urgency, u32) {
    if ty == "push.dm.call" {
        (
            Urgency::High,
            u32::try_from(call_ring_duration).unwrap_or(FALLBACK_RING_TTL_SECS),
        )
    } else {
        (Urgency::Normal, DEFAULT_TTL_SECS)
    }
}

/// Encrypt a payload into the message we POST to the endpoint.
fn build_message(
    subscription: &SubscriptionInfo,
    signature: Option<VapidSignature>,
    payload: &[u8],
    ty: &str,
    call_ring_duration: usize,
) -> Result<WebPushMessage, WebPushError> {
    let (urgency, ttl) = delivery_params(ty, call_ring_duration);

    let mut builder = WebPushMessageBuilder::new(subscription);
    if let Some(signature) = signature {
        builder.set_vapid_signature(signature);
    }

    // UnifiedPush (spec AND_3) requires RFC 8291 aes128gcm, not the
    // legacy aesgcm that vapid.rs sends to browsers.
    builder.set_payload(ContentEncoding::Aes128Gcm, payload);
    builder.set_ttl(ttl);
    builder.set_urgency(urgency);
    // No Topic: it travels to the push server in the clear.

    builder.build()
}

/// Map a send result to what happens to the subscription. Only 404 and 410
/// prune. A 401 or a key-mismatch 403 (which web-push reports as
/// `Other("403")`) is our problem, and web-push maps every 5xx to
/// `ServerError`, so none of those say anything permanent about the endpoint.
fn outcome(result: &Result<(), WebPushError>) -> Outcome {
    match result {
        Ok(()) => Outcome::Delivered,
        Err(WebPushError::EndpointNotFound | WebPushError::EndpointNotValid) => Outcome::Prune,
        Err(_) => Outcome::Keep,
    }
}

/// Whether the push server told us to slow down. web-push reports a 429 as
/// `Other("429")` (request_builder.rs).
fn should_drain(result: &Result<(), WebPushError>) -> bool {
    matches!(result, Err(WebPushError::Other(status)) if status == "429")
}

/// Whether a send result is an HTTP answer other than success, which the
/// push server may count against our IP. No `_` arm: a web-push upgrade that
/// adds a variant has to be classified here before it builds.
fn is_http_rejection(result: &Result<(), WebPushError>) -> bool {
    let Err(err) = result else {
        return false;
    };

    match err {
        // What parse_response makes of a non-2xx status; a 3xx ends up in
        // `Other`, since redirects are never followed.
        WebPushError::Unauthorized
        | WebPushError::BadRequest(_)
        | WebPushError::ServerError(_)
        | WebPushError::EndpointNotValid
        | WebPushError::EndpointNotFound
        | WebPushError::PayloadTooLarge
        | WebPushError::Other(_) => true,
        // Only from parsing a response body, which send_pinned never reads.
        // There was an answer, so it counts.
        WebPushError::InvalidResponse => true,
        // No request reached the server: a transport error, or building the
        // message or the request failed.
        WebPushError::Unspecified
        | WebPushError::NotImplemented
        | WebPushError::InvalidUri
        | WebPushError::TlsError
        | WebPushError::SslError
        | WebPushError::IoError
        | WebPushError::InvalidPackageName
        | WebPushError::InvalidTtl
        | WebPushError::InvalidTopic
        | WebPushError::MissingCryptoKeys
        | WebPushError::InvalidCryptoKeys
        | WebPushError::InvalidClaims => false,
    }
}

/// Host and port to resolve for an endpoint. Only https is accepted.
fn endpoint_host_port(endpoint: &str) -> Option<(String, u16)> {
    let uri: Uri = endpoint.parse().ok()?;
    if uri.scheme_str() != Some("https") {
        return None;
    }

    // http::Uri keeps the brackets around an IPv6 literal.
    let host = uri.host()?.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }

    Some((host.to_string(), uri.port_u16().unwrap_or(443)))
}

/// Resolve the host and require every address to be public. Returns the
/// address the send must connect to. A lookup that fails or returns nothing
/// is treated as not public. An IP literal is not looked up, only checked.
async fn checked_address(host: &str, port: u16) -> Option<SocketAddr> {
    let addrs = tokio::net::lookup_host((host, port)).await.ok()?;
    first_if_all_public(addrs)
}

/// The first address, if there is one and none of them is forbidden.
fn first_if_all_public(addrs: impl IntoIterator<Item = SocketAddr>) -> Option<SocketAddr> {
    let mut first = None;
    for addr in addrs {
        if is_forbidden_address(addr.ip()) {
            return None;
        }

        first.get_or_insert(addr);
    }

    first
}

/// The request for a message, pinned to `addr` (CURLOPT_CONNECT_TO) and
/// never sent through a proxy. The URI is unchanged, so TLS SNI and `Host`
/// stay the endpoint's hostname.
fn pinned_request(
    message: WebPushMessage,
    addr: SocketAddr,
) -> Result<Request<AsyncBody>, isahc::http::Error> {
    let request = build_request::<AsyncBody>(message);

    request
        .to_builder()
        .dial(Dialer::ip_socket(addr))
        .proxy(None)
        .body(request.into_body())
}

/// Addresses a push endpoint must never point at: loopback, private,
/// link-local, shared, reserved, unspecified, broadcast and multicast,
/// including when an IPv6 address carries one of them as an embedded IPv4.
fn is_forbidden_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();

            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                // 0.0.0.0/8 ("this network"), as january blocks it too.
                || a == 0
                // 100.64.0.0/10, carrier-grade NAT.
                || (a == 100 && (b & 0xc0) == 64)
                // 198.18.0.0/15, benchmarking.
                || (a == 198 && (b & 0xfe) == 18)
                // 192.0.0.0/24, IETF protocol assignments.
                || (a == 192 && b == 0 && c == 0)
                // 240.0.0.0/4, reserved (includes 255.255.255.255).
                || a >= 240
        }
        IpAddr::V6(v6) => {
            // First, so :: and ::1 never reach the IPv4-compatible case.
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }

            let segments = v6.segments();
            if v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                // fec0::/10, the deprecated site-local range.
                || (segments[0] & 0xffc0) == 0xfec0
                // 64:ff9b:1::/48, local-use NAT64. Where the IPv4 sits
                // depends on the operator's prefix length, so refuse it all.
                || matches!(segments, [0x64, 0xff9b, 1, ..])
                // 2001::/32, Teredo. Its IPv4 is obfuscated, so refuse it all.
                || matches!(segments, [0x2001, 0, ..])
            {
                return true;
            }

            // Otherwise a private IPv4 address would slip past inside one.
            embedded_ipv4(v6).is_some_and(|v4| is_forbidden_address(IpAddr::V4(v4)))
        }
    }
}

/// The IPv4 address inside an IPv4-mapped (`::ffff:a.b.c.d`),
/// IPv4-translated (`::ffff:0:a.b.c.d`), IPv4-compatible (`::a.b.c.d`),
/// NAT64 (`64:ff9b::a.b.c.d`) or 6to4 (`2002:aabb:ccdd::/48`) address.
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }

    let o = v6.octets();
    match v6.segments() {
        [0, 0, 0, 0, 0, 0, _, _]
        | [0, 0, 0, 0, 0xffff, 0, _, _]
        | [0x64, 0xff9b, 0, 0, 0, 0, _, _] => Some(Ipv4Addr::new(o[12], o[13], o[14], o[15])),
        [0x2002, ..] => Some(Ipv4Addr::new(o[2], o[3], o[4], o[5])),
        _ => None,
    }
}

/// The rate-limit key for a checked destination. ntfy.sh counts as one
/// destination by name, so more addresses in its DNS cannot multiply its
/// budgets: a ban there is per our IP, across all of its frontends. Any
/// other host counts by address. An IPv6 address that carries an IPv4 one
/// counts as that IPv4, and any other IPv6 address counts as its /64, so
/// rotating addresses inside one /64 or spelling one IPv4 address several
/// ways does not buy a destination more allowances.
fn limit_key(host: &str, ip: IpAddr) -> DestKey {
    if is_ntfy_host(host) {
        return DestKey::Ntfy;
    }

    DestKey::Ip(match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match embedded_ipv4(v6) {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut segments = v6.segments();
                segments[4..].fill(0);
                IpAddr::V6(Ipv6Addr::from(segments))
            }
        },
    })
}

/// How a limit key appears in log lines.
fn key_label(key: DestKey) -> String {
    match key {
        DestKey::Ntfy => "ntfy.sh".to_string(),
        DestKey::Ip(ip) => ip.to_string(),
    }
}

/// The first line for an empty destination send bucket. The push that found
/// it empty is rarely the one that emptied it, so the line names who sent
/// the most to `key` since the last such line, then this push. Reading the
/// top senders clears them.
fn destination_limit_line(
    limiter: &UpLimiter,
    host: &str,
    key: DestKey,
    session_id: &str,
    user_id: &str,
) -> String {
    let (top, others) = limiter.top_senders(key);
    let senders = if top.is_empty() {
        "none".to_string()
    } else {
        // For top_senders, `rejections` holds the number of admitted sends.
        top.iter()
            .map(|sender| format!("{} ({})", sender.user_id, sender.rejections))
            .collect::<Vec<_>>()
            .join(", ")
    };

    format!(
        "UnifiedPush destination limit reached for {} [{}]: top senders {}, {} other users (this push: session {}, user {})",
        host,
        key_label(key),
        senders,
        others,
        session_id,
        user_id
    )
}

/// The offenders a pause names, as "user x3, user x1".
fn offender_list(top: &[Offender]) -> String {
    if top.is_empty() {
        return "none".to_string();
    }

    top.iter()
        .map(|offender| format!("{} x{}", offender.user_id, offender.rejections))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
    };

    use isahc::http::StatusCode;

    use crate::consumers::outbound::up_limiter::{DestLimits, UpLimits};

    /// web-push's own test subscription (request_builder.rs tests). Only the
    /// public key exists here, which is all encryption needs.
    fn test_subscription() -> SubscriptionInfo {
        SubscriptionInfo::new(
            "https://push.example.org/up/abc",
            "BGa4N1PI79lboMR_YrwCiCsgp35DRvedt7opHcf0yM3iOBTSoQYqQLwWxAfRKE6tsDnReWmhsImkhDF_DBdkNSU",
            "EvcWjEgzr4rbvhfi3yds0A",
        )
    }

    fn cjk_message() -> NotificationData {
        NotificationData::Message {
            message: "01J8Z3Q4X5Y6Z7A8B9C0D1E2F3".to_string(),
            body: "中".repeat(4000),
            image: "https://cdn.example.org/avatars/01J8Z3Q4X5Y6Z7A8B9C0D1E2F4".to_string(),
            channel: "01J8Z3Q4X5Y6Z7A8B9C0D1E2F5".to_string(),
            author: "01J8Z3Q4X5Y6Z7A8B9C0D1E2F6".to_string(),
            author_name: "名".repeat(32),
        }
    }

    #[test]
    fn truncates_body_at_a_char_boundary() {
        let mut body = "中".repeat(4000);
        truncate_utf8(&mut body, MAX_BODY_BYTES);

        assert!(body.len() <= MAX_BODY_BYTES);
        assert_eq!(body.len(), 999);
        assert!(std::str::from_utf8(body.as_bytes()).is_ok());
        assert!(body.chars().all(|c| c == '中'));
    }

    #[test]
    fn leaves_short_body_alone() {
        let mut body = "hello".to_string();
        truncate_utf8(&mut body, MAX_BODY_BYTES);

        assert_eq!(body, "hello");
    }

    #[test]
    fn payload_cap_is_web_push_limit() {
        assert!(!exceeds_payload_cap(&vec![b'a'; MAX_PAYLOAD_BYTES]));
        assert!(exceeds_payload_cap(&vec![b'a'; MAX_PAYLOAD_BYTES + 1]));
    }

    #[test]
    fn call_rings_are_urgent_and_short_lived() {
        assert_eq!(delivery_params("push.dm.call", 30), (Urgency::High, 30));
        assert_eq!(delivery_params("push.dm.call", 45), (Urgency::High, 45));
    }

    #[test]
    fn other_types_are_normal_for_a_day() {
        for ty in [
            "push.message",
            "push.generic",
            "push.fr.receive",
            "push.fr.accept",
            "push.calendar",
        ] {
            assert_eq!(delivery_params(ty, 30), (Urgency::Normal, DEFAULT_TTL_SECS));
        }
    }

    #[test]
    fn endpoint_must_be_https() {
        assert_eq!(
            endpoint_host_port("https://push.example.org/up/abc"),
            Some(("push.example.org".to_string(), 443))
        );
        assert_eq!(
            endpoint_host_port("https://push.example.org:8443/up/abc"),
            Some(("push.example.org".to_string(), 8443))
        );
        assert_eq!(
            endpoint_host_port("https://[2001:db8::1]/up"),
            Some(("2001:db8::1".to_string(), 443))
        );
        assert_eq!(endpoint_host_port("http://push.example.org/up/abc"), None);
        assert_eq!(endpoint_host_port("not a url"), None);
    }

    #[test]
    fn rejects_internal_addresses() {
        for addr in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(is_forbidden_address(ip), "{addr} should be rejected");
        }
    }

    #[test]
    fn accepts_public_addresses() {
        for addr in [
            "1.1.1.1",
            "93.184.216.34",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "::ffff:1.1.1.1",
            // Just outside the ranges below.
            "100.63.255.255",
            "100.128.0.1",
            "198.17.255.255",
            "198.20.0.1",
            "192.0.1.1",
            "223.255.255.254",
            // Embedded public IPv4.
            "::1.1.1.1",
            "64:ff9b::1.1.1.1",
            "64:ff9b::808:808",
            "2002:101:101::1",
            "::ffff:0:1.1.1.1",
            // Next to Teredo.
            "2001:4860:4860::8888",
            "2001:1::1",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(!is_forbidden_address(ip), "{addr} should be accepted");
        }
    }

    #[test]
    fn rejects_shared_and_reserved_v4() {
        for addr in [
            "100.64.0.1",
            "100.127.255.254",
            "198.18.0.1",
            "198.19.255.254",
            "192.0.0.8",
            "240.0.0.1",
            "255.255.255.254",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(is_forbidden_address(ip), "{addr} should be rejected");
        }
    }

    #[test]
    fn rejects_site_local_v6() {
        for addr in ["fec0::1", "feff:ffff::1"] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(is_forbidden_address(ip), "{addr} should be rejected");
        }
    }

    #[test]
    fn rejects_embedded_internal_v4() {
        for addr in [
            // IPv4-mapped, now with the new v4 ranges.
            "::ffff:100.64.0.1",
            // IPv4-compatible.
            "::10.0.0.1",
            "::127.0.0.1",
            "::240.0.0.1",
            // NAT64 well-known prefix.
            "64:ff9b::10.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::169.254.169.254",
            // Local-use NAT64, refused whole.
            "64:ff9b:1::10.0.0.1",
            "64:ff9b:1::1.1.1.1",
            // 6to4.
            "2002:a00:1::1",
            "2002:7f00:1::",
            "2002:c0a8:101::1",
            "2002:a9fe:a9fe::1",
            // IPv4-translated.
            "::ffff:0:10.0.0.1",
            "::ffff:0:127.0.0.1",
            // Teredo, refused whole.
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001::1",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(is_forbidden_address(ip), "{addr} should be rejected");
        }
    }

    fn socket_addrs(addrs: &[&str]) -> Vec<SocketAddr> {
        addrs.iter().map(|addr| addr.parse().unwrap()).collect()
    }

    #[test]
    fn pins_the_first_checked_address() {
        assert_eq!(
            first_if_all_public(socket_addrs(&["1.1.1.1:443", "[2606:4700:4700::1111]:443"])),
            Some("1.1.1.1:443".parse().unwrap())
        );
        assert_eq!(
            first_if_all_public(socket_addrs(&[
                "[2606:4700:4700::1111]:8443",
                "1.1.1.1:8443",
                "1.0.0.1:8443",
            ])),
            Some("[2606:4700:4700::1111]:8443".parse().unwrap())
        );
    }

    #[test]
    fn refuses_if_any_address_is_forbidden() {
        for addrs in [
            &["1.1.1.1:443", "10.0.0.1:443"][..],
            &["[::1]:443", "1.1.1.1:443"][..],
            &["1.1.1.1:443", "[64:ff9b::7f00:1]:443"][..],
            &[][..],
        ] {
            assert_eq!(first_if_all_public(socket_addrs(addrs)), None, "{addrs:?}");
        }
    }

    #[test]
    fn pinned_request_keeps_the_hostname_and_headers() {
        let subscription = test_subscription();
        let msg = build_message(&subscription, None, b"{}", "push.message", 30).unwrap();
        let expected = build_request::<AsyncBody>(
            build_message(&subscription, None, b"{}", "push.message", 30).unwrap(),
        );

        let request = pinned_request(msg, "[2606:4700:4700::1111]:443".parse().unwrap()).unwrap();

        // The pin itself lives in isahc's private RequestConfig, so only what
        // must NOT change is checked here: the URI (SNI and Host) and headers.
        assert_eq!(request.method(), expected.method());
        assert_eq!(request.uri(), expected.uri());
        assert_eq!(request.uri().host(), Some("push.example.org"));
        assert_eq!(request.headers(), expected.headers());
        assert_eq!(request.body().len(), expected.body().len());
    }

    #[test]
    fn only_gone_endpoints_are_pruned() {
        assert_eq!(outcome(&Ok(())), Outcome::Delivered);

        for err in [
            WebPushError::EndpointNotFound,
            WebPushError::EndpointNotValid,
        ] {
            assert_eq!(outcome(&Err(err.clone())), Outcome::Prune, "{err:?}");
        }

        for err in [
            WebPushError::Unauthorized,
            WebPushError::Other("403".to_string()),
            WebPushError::ServerError(None),
            WebPushError::BadRequest(None),
            WebPushError::PayloadTooLarge,
            WebPushError::Unspecified,
        ] {
            assert_eq!(outcome(&Err(err.clone())), Outcome::Keep, "{err:?}");
        }
    }

    #[test]
    fn status_codes_map_through_web_push_to_the_right_outcome() {
        // A key-mismatch 403 reaches us as Other("403").
        assert_eq!(
            parse_response(StatusCode::FORBIDDEN, vec![]),
            Err(WebPushError::Other("403".to_string()))
        );

        for (status, expected) in [
            (200, Outcome::Delivered),
            (201, Outcome::Delivered),
            (404, Outcome::Prune),
            (410, Outcome::Prune),
            (400, Outcome::Keep),
            (401, Outcome::Keep),
            (403, Outcome::Keep),
            (413, Outcome::Keep),
            (429, Outcome::Keep),
            (500, Outcome::Keep),
            (503, Outcome::Keep),
            (507, Outcome::Keep),
        ] {
            let result = parse_response(StatusCode::from_u16(status).unwrap(), vec![]);
            assert_eq!(outcome(&result), expected, "status {status}");
        }
    }

    #[test]
    fn request_is_aes128gcm_without_topic() {
        let subscription = test_subscription();
        let msg = build_message(&subscription, None, b"{}", "push.message", 30).unwrap();

        // The same builder IsahcWebPushClient::send uses.
        let request = build_request::<isahc::AsyncBody>(msg);
        let headers = request.headers();

        assert_eq!(
            headers.get("Content-Encoding").unwrap().to_str().unwrap(),
            "aes128gcm"
        );
        assert!(headers.get("Topic").is_none());
        assert_eq!(headers.get("TTL").unwrap().to_str().unwrap(), "86400");
        assert_eq!(headers.get("Urgency").unwrap().to_str().unwrap(), "normal");
    }

    #[test]
    fn call_ring_request_is_urgent_and_short_lived() {
        let subscription = test_subscription();
        let msg = build_message(&subscription, None, b"{}", "push.dm.call", 45).unwrap();

        let request = build_request::<isahc::AsyncBody>(msg);
        let headers = request.headers();

        assert_eq!(headers.get("TTL").unwrap().to_str().unwrap(), "45");
        assert_eq!(headers.get("Urgency").unwrap().to_str().unwrap(), "high");
    }

    #[test]
    fn long_cjk_body_goes_through_the_real_builder() {
        let (ty, bytes) = encode_payload(cjk_message()).unwrap();
        assert_eq!(ty, "push.message");
        assert!(
            !exceeds_payload_cap(&bytes),
            "payload is {} bytes",
            bytes.len()
        );

        let json: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["type"], "push.message");
        assert_eq!(json["body"].as_str().unwrap().len(), 999);

        let subscription = test_subscription();
        let msg = build_message(&subscription, None, &bytes, &ty, 30).unwrap();
        let payload = msg.payload.expect("encrypted payload");

        assert_eq!(payload.content_encoding, ContentEncoding::Aes128Gcm);
        // One aes128gcm record: an 86-byte header, the plaintext padded to a
        // multiple of 128 bytes and a 16-byte tag. RFC 8030 push servers
        // take 4096.
        assert!(
            payload.content.len() <= 4096,
            "encrypted body is {} bytes",
            payload.content.len()
        );
    }

    /// Longest any test waits on a send, a lookup or a listener. Longer than
    /// the client's own 10 s timeout, so a broken send fails instead of hangs.
    const WAIT: Duration = Duration::from_secs(15);

    /// How long a test listener keeps accepting connections.
    const LISTEN_FOR: Duration = Duration::from_secs(20);

    /// A local push server on a background thread.
    struct TestServer {
        addr: SocketAddr,
        /// Every connection it accepted.
        connections: Arc<AtomicUsize>,
        /// The head of each request, in order.
        requests: mpsc::Receiver<String>,
    }

    /// Answers every connection with `status` plus `headers` (each ending in
    /// CRLF) and an empty body, until `LISTEN_FOR` has passed.
    fn serve(status: &str, headers: &str) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        let response =
            format!("HTTP/1.1 {status}\r\n{headers}Content-Length: 0\r\nConnection: close\r\n\r\n");

        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        let (requests_tx, requests) = mpsc::channel();
        std::thread::spawn(move || {
            let deadline = Instant::now() + LISTEN_FOR;
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let _ = requests_tx.send(read_request(&mut stream));
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });

        TestServer {
            addr,
            connections,
            requests,
        }
    }

    /// Reads one request through the end of its headers, then its body, so
    /// closing the socket afterwards cannot reset the connection under the
    /// client. Returns the request head.
    fn read_request(stream: &mut TcpStream) -> String {
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

        let mut data = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }

            match stream.read(&mut chunk) {
                Ok(n) if n > 0 && data.len() < 65536 => data.extend_from_slice(&chunk[..n]),
                _ => return String::from_utf8_lossy(&data).into_owned(),
            }
        };

        let head = String::from_utf8_lossy(&data[..head_end]).into_owned();
        let body_len = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);

        let mut read = data.len() - head_end;
        while read < body_len {
            match stream.read(&mut chunk) {
                Ok(n) if n > 0 => read += n,
                _ => break,
            }
        }

        head
    }

    /// A message for `http://pin-test.invalid:9{path}`. That host never
    /// resolves, so only a pinned connect can reach a local listener.
    fn pin_test_message(path: &str) -> WebPushMessage {
        let mut subscription = test_subscription();
        subscription.endpoint = format!("http://pin-test.invalid:9{path}");

        build_message(&subscription, None, b"{}", "push.message", 30).unwrap()
    }

    /// A `make_msg` for `gated_send` that counts how often it ran.
    fn counted_message(builds: &AtomicUsize) -> impl FnOnce() -> Result<WebPushMessage> + '_ {
        move || {
            builds.fetch_add(1, Ordering::SeqCst);
            Ok(pin_test_message("/up/abc"))
        }
    }

    #[tokio::test]
    async fn send_connects_only_to_the_pinned_address() {
        // Premise: nothing but the pin can take the send to the listener.
        let lookup = tokio::time::timeout(WAIT, tokio::net::lookup_host(("pin-test.invalid", 9)))
            .await
            .expect("the lookup must answer");
        assert!(lookup.is_err(), "pin-test.invalid must not resolve");

        let server = serve("201 Created", "");
        let (result, status) = tokio::time::timeout(
            WAIT,
            send_pinned(&http_client(), pin_test_message("/up/abc"), server.addr),
        )
        .await
        .expect("the send must answer on its own");
        assert_eq!(result, Ok(()));
        assert_eq!(status, Some(201));

        let head = server.requests.recv_timeout(WAIT).expect("a request");
        assert!(head.starts_with("POST /up/abc HTTP/1.1\r\n"), "{head}");
        // Port 9 is not the listener's, so the pin replaced only the connect:
        // the request still names the endpoint's own host and port.
        assert!(
            head.to_ascii_lowercase()
                .contains("\r\nhost: pin-test.invalid:9\r\n"),
            "{head}"
        );
    }

    #[tokio::test]
    async fn send_never_follows_a_redirect() {
        // Where the redirect points; nothing may ever connect here.
        let target = TcpListener::bind("127.0.0.1:0").expect("bind");
        let target_port = target.local_addr().expect("addr").port();
        target.set_nonblocking(true).expect("nonblocking");

        let redirector = serve(
            "302 Found",
            &format!("Location: http://127.0.0.1:{target_port}/x\r\n"),
        );
        let (result, status) = tokio::time::timeout(
            WAIT,
            send_pinned(&http_client(), pin_test_message("/up/abc"), redirector.addr),
        )
        .await
        .expect("the send must answer on its own");

        assert_eq!(result, Err(WebPushError::Other("302".to_string())));
        assert_eq!(status, Some(302));
        assert_eq!(outcome(&result), Outcome::Keep);
        // A followed redirect keeps the pin, so it would come back to the
        // redirector rather than reach the target: count the redirector.
        assert_eq!(redirector.connections.load(Ordering::SeqCst), 1);
        assert!(matches!(
            target.accept(),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[tokio::test]
    async fn checked_address_refuses_local_and_unresolvable_hosts() {
        for host in [
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "localhost",
            "pin-test.invalid",
        ] {
            let addr = tokio::time::timeout(WAIT, checked_address(host, 443))
                .await
                .expect("the lookup must answer");
            assert_eq!(addr, None, "{host}");
        }
    }

    #[test]
    fn limit_key_folds_each_destination_into_one_key() {
        let ip = |addr: &str| addr.parse::<IpAddr>().unwrap();
        let key = |addr: &str| limit_key("push.example.org", ip(addr));

        assert_eq!(key("1.2.3.4"), DestKey::Ip(ip("1.2.3.4")));
        for addr in [
            "::ffff:1.2.3.4",
            "::ffff:0:1.2.3.4",
            "64:ff9b::102:304",
            "2002:102:304::1",
        ] {
            assert_eq!(key(addr), DestKey::Ip(ip("1.2.3.4")), "{addr}");
        }

        // One /64, whatever the low bits.
        assert_eq!(
            key("2606:4700:4700::1111"),
            DestKey::Ip(ip("2606:4700:4700::"))
        );
        assert_eq!(
            key("2001:db8:1:2:aaaa:bbbb:cccc:dddd"),
            key("2001:db8:1:2::1")
        );

        // Different /64s stay apart.
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_ne!(key("2606:4700:4700::1111"), key("2606:4700:4700:1::1111"));
    }

    #[test]
    fn limit_key_keys_ntfy_by_name() {
        let ip = |addr: &str| addr.parse::<IpAddr>().unwrap();

        for host in [
            "ntfy.sh",
            "NTFY.SH",
            "ntfy.sh.",
            "push.ntfy.sh",
            "Push.Ntfy.Sh.",
        ] {
            for addr in ["159.203.148.75", "2604:a880:400:d0::1", "203.0.113.9"] {
                assert_eq!(limit_key(host, ip(addr)), DestKey::Ntfy, "{host} at {addr}");
            }
        }

        for host in [
            "push.example.org",
            "notntfy.sh",
            "ntfy.sh.example.org",
            "ntfy.shop",
        ] {
            assert_eq!(
                limit_key(host, ip("159.203.148.75")),
                DestKey::Ip(ip("159.203.148.75")),
                "{host}"
            );
        }
    }

    /// A topic name the ntfy app would register: `up` plus 12 characters.
    const TOPIC: &str = "upAbCdEfGhIjKl";

    #[test]
    fn ntfy_endpoints_must_be_up_topic_urls() {
        for endpoint in [
            format!("https://ntfy.sh/{TOPIC}?up=1"),
            format!("https://ntfy.sh/{TOPIC}"),
            format!("https://NTFY.SH/{TOPIC}?up=1"),
            format!("https://ntfy.sh./{TOPIC}?up=1"),
            format!("https://push.ntfy.sh/{TOPIC}?up=1"),
            format!("https://ntfy.sh:443/{TOPIC}?up=1"),
            "https://ntfy.sh/up-_0123456789?up=1".to_string(),
        ] {
            assert!(ntfy_endpoint_allowed(&endpoint), "{endpoint} should pass");
        }

        for endpoint in [
            "https://ntfy.sh/mytopic".to_string(),
            "https://NTFY.SH/mytopic".to_string(),
            "https://Push.Ntfy.Sh./mytopic".to_string(),
            "https://ntfy.sh/up".to_string(),
            "https://ntfy.sh/".to_string(),
            "https://ntfy.sh".to_string(),
            // 15 and 13 characters.
            format!("https://ntfy.sh/{TOPIC}M"),
            "https://ntfy.sh/upAbCdEfGhIjK".to_string(),
            "https://ntfy.sh/UPAbCdEfGhIjKl".to_string(),
            "https://ntfy.sh/upAbCdEfGhIj.l".to_string(),
            format!("https://ntfy.sh/{TOPIC}/seq"),
            format!("https://ntfy.sh/{TOPIC}/publish"),
            format!("https://ntfy.sh/{TOPIC}/"),
            format!("https://ntfy.sh/{TOPIC}?"),
            format!("https://ntfy.sh/{TOPIC}?up=1&email=a@b.c"),
            format!("https://ntfy.sh/{TOPIC}?email=a@b.c"),
            format!("https://ntfy.sh/{TOPIC}?up=2"),
            format!("https://ntfy.sh/{TOPIC}?up=1#frag"),
            format!("https://ntfy.sh/{TOPIC}#frag"),
            "https://ntfy.sh/upAbCdEfGhIj%4Bl".to_string(),
            "https://ntfy.sh/%75pAbCdEfGhIjKl".to_string(),
            format!("https://ntfy.sh:8443/{TOPIC}?up=1"),
            format!("https://user:pass@ntfy.sh/{TOPIC}?up=1"),
            format!("https://user@push.ntfy.sh/{TOPIC}"),
        ] {
            // Premise: the URL itself is fine, so only the ntfy rule refuses.
            assert!(endpoint_host_port(&endpoint).is_some(), "{endpoint}");
            assert!(
                !ntfy_endpoint_allowed(&endpoint),
                "{endpoint} should be refused"
            );
        }
    }

    #[test]
    fn other_distributors_are_left_alone() {
        for endpoint in [
            "https://push.example.org/up/abc",
            // NextPush, autopush and Gotify.
            "https://cloud.example.org/index.php/apps/uppush/push/abc123",
            "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABk",
            "https://gotify.example.org/UP?token=abc",
            // A self-hosted ntfy, and names that only look like ntfy.sh.
            "https://ntfy.example.org/mytopic?email=a@b.c",
            "https://notntfy.sh/mytopic",
            "https://ntfy.sh.example.org/mytopic",
            "https://user@push.example.org:8443/x?y#z",
        ] {
            assert!(ntfy_endpoint_allowed(endpoint), "{endpoint} should pass");
        }
    }

    /// A stand-in for `checked_address` that counts its calls and answers
    /// `addr`.
    fn counting_resolver(
        lookups: &AtomicUsize,
        addr: SocketAddr,
    ) -> impl FnOnce(String, u16) -> std::future::Ready<Option<SocketAddr>> + '_ {
        move |_, _| {
            lookups.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Some(addr))
        }
    }

    #[tokio::test]
    async fn refused_ntfy_endpoint_stops_before_the_lookup() {
        let lookups = AtomicUsize::new(0);
        let addr: SocketAddr = "203.0.113.7:443".parse().unwrap();

        let refused =
            resolve_destination("https://ntfy.sh/mytopic", counting_resolver(&lookups, addr)).await;
        assert_eq!(
            refused,
            Destination::NotNtfyTopic {
                host: "ntfy.sh".to_string()
            }
        );
        assert_eq!(lookups.load(Ordering::SeqCst), 0);

        let invalid =
            resolve_destination("http://ntfy.sh/mytopic", counting_resolver(&lookups, addr)).await;
        assert_eq!(invalid, Destination::Invalid);
        assert_eq!(lookups.load(Ordering::SeqCst), 0);

        // The same resolver is reached for a topic URL and for other hosts.
        let topic = format!("https://ntfy.sh/{TOPIC}?up=1");
        let checked = resolve_destination(&topic, counting_resolver(&lookups, addr)).await;
        assert_eq!(
            checked,
            Destination::Checked {
                host: "ntfy.sh".to_string(),
                addr
            }
        );
        assert_eq!(lookups.load(Ordering::SeqCst), 1);

        let other = resolve_destination(
            "https://push.example.org/mytopic",
            counting_resolver(&lookups, addr),
        )
        .await;
        assert_eq!(
            other,
            Destination::Checked {
                host: "push.example.org".to_string(),
                addr
            }
        );
        assert_eq!(lookups.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn only_http_answers_are_rejections() {
        assert!(!is_http_rejection(&Ok(())));

        for err in [
            WebPushError::Unauthorized,
            WebPushError::BadRequest(None),
            WebPushError::BadRequest(Some("bad".to_string())),
            WebPushError::ServerError(None),
            WebPushError::ServerError(Some(Duration::from_secs(5))),
            WebPushError::EndpointNotValid,
            WebPushError::EndpointNotFound,
            WebPushError::PayloadTooLarge,
            WebPushError::Other("302".to_string()),
            WebPushError::Other("403".to_string()),
            WebPushError::Other("429".to_string()),
            WebPushError::InvalidResponse,
        ] {
            assert!(is_http_rejection(&Err(err.clone())), "{err:?}");
        }

        for err in [
            WebPushError::Unspecified,
            WebPushError::NotImplemented,
            WebPushError::InvalidUri,
            WebPushError::TlsError,
            WebPushError::SslError,
            WebPushError::IoError,
            WebPushError::InvalidPackageName,
            WebPushError::InvalidTtl,
            WebPushError::InvalidTopic,
            WebPushError::MissingCryptoKeys,
            WebPushError::InvalidCryptoKeys,
            WebPushError::InvalidClaims,
        ] {
            assert!(!is_http_rejection(&Err(err.clone())), "{err:?}");
        }

        for status in [200, 201, 202] {
            let result = parse_response(StatusCode::from_u16(status).unwrap(), vec![]);
            assert!(!is_http_rejection(&result), "status {status}");
        }

        for status in [
            301, 302, 307, 400, 401, 403, 404, 410, 413, 429, 500, 502, 503, 507,
        ] {
            let result = parse_response(StatusCode::from_u16(status).unwrap(), vec![]);
            assert!(is_http_rejection(&result), "status {status}");
        }
    }

    #[test]
    fn slot_timeout_log_is_throttled() {
        let t0 = Instant::now();
        let throttle = LogThrottle {
            epoch: t0,
            every: Duration::from_secs(60),
            last: AtomicU64::new(0),
        };
        let at = |secs: u64| t0 + Duration::from_secs(secs);

        assert!(throttle.ready(at(0)));
        assert!(!throttle.ready(at(1)));
        assert!(!throttle.ready(at(59)));
        assert!(throttle.ready(at(60)));
        assert!(!throttle.ready(at(61)));
        assert!(throttle.ready(at(500)));
    }

    /// The default limits, except for the generic destination's.
    fn generic_limiter(generic: DestLimits) -> UpLimiter {
        UpLimiter::with(UpLimits {
            generic,
            ..UpLimits::default()
        })
    }

    fn default_generic() -> DestLimits {
        UpLimits::default().generic
    }

    /// A `make_msg` for `gated_send` that builds a pin-test message.
    fn plain_message() -> Result<WebPushMessage> {
        Ok(pin_test_message("/up/abc"))
    }

    #[tokio::test]
    async fn gated_send_denies_before_signing_or_sending() {
        let server = serve("201 Created", "");
        let limiter = generic_limiter(DestLimits {
            send_burst: 1.0,
            send_refill_per_sec: 0.0,
            ..default_generic()
        });
        let client = http_client();
        let builds = AtomicUsize::new(0);
        let key = DestKey::Ip(server.addr.ip());

        let sent = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &client,
                "A",
                SubKey(1),
                key,
                server.addr,
                SLOT_WAIT,
                counted_message(&builds),
            ),
        )
        .await
        .expect("the send must answer on its own");
        assert!(
            matches!(
                sent,
                Gated::Sent {
                    result: Ok(()),
                    rejected: None
                }
            ),
            "{sent:?}"
        );

        let denied = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &client,
                "A",
                SubKey(1),
                key,
                server.addr,
                SLOT_WAIT,
                counted_message(&builds),
            ),
        )
        .await
        .expect("the send must answer on its own");
        assert!(
            matches!(denied, Gated::Denied { first: true, .. }),
            "{denied:?}"
        );

        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn destination_limit_line_names_the_top_sender() {
        let server = serve("201 Created", "");
        let limiter = generic_limiter(DestLimits {
            send_burst: 2.0,
            send_refill_per_sec: 0.0,
            ..default_generic()
        });
        let client = http_client();
        let key = DestKey::Ip(server.addr.ip());

        // A empties the destination bucket; B is the one who finds it empty.
        for (user, sub) in [("A", 1), ("A", 2), ("B", 3)] {
            let gated = tokio::time::timeout(
                WAIT,
                gated_send(
                    &limiter,
                    &client,
                    user,
                    SubKey(sub),
                    key,
                    server.addr,
                    SLOT_WAIT,
                    plain_message,
                ),
            )
            .await
            .expect("the send must answer on its own");

            if user == "A" {
                assert!(
                    matches!(
                        gated,
                        Gated::Sent {
                            result: Ok(()),
                            rejected: None
                        }
                    ),
                    "{gated:?}"
                );
            } else {
                assert!(
                    matches!(
                        gated,
                        Gated::Denied {
                            first: true,
                            bucket: Bucket::Ip
                        }
                    ),
                    "{gated:?}"
                );
            }
        }
        assert_eq!(server.connections.load(Ordering::SeqCst), 2);

        let line = destination_limit_line(&limiter, "push.example.org", key, "S", "B");
        assert!(line.contains(": top senders A (2), "), "{line}");
        assert!(line.ends_with("(this push: session S, user B)"), "{line}");
    }

    #[tokio::test]
    async fn gated_send_backs_off_only_the_user_a_429_names() {
        let server = serve("429 Too Many Requests", "");
        let limiter = generic_limiter(DestLimits {
            send_burst: 5.0,
            send_refill_per_sec: 0.0,
            ..default_generic()
        });
        let builds = AtomicUsize::new(0);
        let key = DestKey::Ip(server.addr.ip());

        let sent = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &http_client(),
                "A",
                SubKey(1),
                key,
                server.addr,
                SLOT_WAIT,
                counted_message(&builds),
            ),
        )
        .await
        .expect("the send must answer on its own");
        assert!(
            matches!(&sent, Gated::Sent { result: Err(WebPushError::Other(status)), .. } if status == "429"),
            "{sent:?}"
        );

        // A is drained for this destination (asked on a subscription the
        // 429 did not cool); B still has its own allowance, and the shared
        // destination bucket still has tokens.
        let now = Instant::now();
        assert!(matches!(
            limiter.admit("A", SubKey(2), key, now),
            Admit::Denied {
                bucket: Bucket::User,
                ..
            }
        ));
        assert!(matches!(
            limiter.admit("B", SubKey(3), key, now),
            Admit::Allowed(_)
        ));
    }

    #[tokio::test]
    async fn transport_error_costs_no_rejection_token() {
        let server = serve("201 Created", "");
        // A port nothing listens on: the send fails before any HTTP answer.
        let closed = TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr");
        assert_ne!(closed, server.addr);

        // One rejection token and no refill, so a single strike would pause
        // the destination.
        let limiter = generic_limiter(DestLimits {
            reject_burst: 1.0,
            reject_refill_per_sec: 0.0,
            ..default_generic()
        });
        let client = http_client();
        let key = DestKey::Ip(closed.ip());
        assert_eq!(key, DestKey::Ip(server.addr.ip()));

        let failed = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &client,
                "A",
                SubKey(1),
                key,
                closed,
                SLOT_WAIT,
                plain_message,
            ),
        )
        .await
        .expect("the send must answer on its own");
        assert!(
            matches!(
                failed,
                Gated::Sent {
                    result: Err(WebPushError::Unspecified),
                    rejected: None
                }
            ),
            "{failed:?}"
        );

        // Same user, subscription and destination: neither paused nor cooled.
        let sent = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &client,
                "A",
                SubKey(1),
                key,
                server.addr,
                SLOT_WAIT,
                plain_message,
            ),
        )
        .await
        .expect("the send must answer on its own");
        assert!(
            matches!(
                sent,
                Gated::Sent {
                    result: Ok(()),
                    rejected: None
                }
            ),
            "{sent:?}"
        );
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn gated_rejection_cools_the_subscription() {
        let server = serve("507 Insufficient Storage", "");
        let limiter = UpLimiter::new();
        let client = http_client();
        let builds = AtomicUsize::new(0);
        let key = DestKey::Ip(server.addr.ip());

        let first = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &client,
                "A",
                SubKey(1),
                key,
                server.addr,
                SLOT_WAIT,
                counted_message(&builds),
            ),
        )
        .await
        .expect("the send must answer on its own");
        assert!(
            matches!(
                first,
                Gated::Sent {
                    result: Err(WebPushError::ServerError(None)),
                    rejected: Some(Rejected::Counted)
                }
            ),
            "{first:?}"
        );

        let second = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &client,
                "A",
                SubKey(1),
                key,
                server.addr,
                SLOT_WAIT,
                counted_message(&builds),
            ),
        )
        .await
        .expect("the send must answer on its own");
        assert!(
            matches!(
                second,
                Gated::Denied {
                    bucket: Bucket::Subscription,
                    ..
                }
            ),
            "{second:?}"
        );

        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn gated_rejections_pause_the_destination() {
        let server = serve("507 Insufficient Storage", "");
        let limiter = generic_limiter(DestLimits {
            reject_burst: 2.0,
            reject_refill_per_sec: 0.0,
            ..default_generic()
        });
        let client = http_client();
        let key = DestKey::Ip(server.addr.ip());

        let mut results = Vec::new();
        for (user, sub) in [("A", 1), ("B", 2), ("C", 3)] {
            let gated = tokio::time::timeout(
                WAIT,
                gated_send(
                    &limiter,
                    &client,
                    user,
                    SubKey(sub),
                    key,
                    server.addr,
                    SLOT_WAIT,
                    plain_message,
                ),
            )
            .await
            .expect("the send must answer on its own");
            results.push(gated);
        }

        assert!(
            matches!(
                results[0],
                Gated::Sent {
                    rejected: Some(Rejected::Counted),
                    ..
                }
            ),
            "{:?}",
            results[0]
        );
        let Gated::Sent {
            rejected: Some(Rejected::Paused { top, .. }),
            ..
        } = &results[1]
        else {
            panic!("the second rejection must pause: {:?}", results[1]);
        };
        for user in ["A", "B"] {
            assert!(top.iter().any(|o| o.user_id == user), "{user} in {top:?}");
        }
        assert!(
            matches!(
                results[2],
                Gated::Denied {
                    bucket: Bucket::Paused,
                    ..
                }
            ),
            "{:?}",
            results[2]
        );

        assert_eq!(server.connections.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_sends_wait_for_a_slot_instead_of_dropping() {
        // Premise: ntfy.sh allows fewer sends in flight than this.
        assert!(UpLimits::default().ntfy.max_in_flight < 10);

        let server = serve("201 Created", "");
        let limiter = Arc::new(UpLimiter::new());
        let client = http_client();
        let addr = server.addr;

        let tasks: Vec<_> = (0..10u64)
            .map(|i| {
                let limiter = limiter.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    let user = format!("user{i}");
                    gated_send(
                        &limiter,
                        &client,
                        &user,
                        SubKey(i),
                        DestKey::Ntfy,
                        addr,
                        SLOT_WAIT,
                        plain_message,
                    )
                    .await
                })
            })
            .collect();

        for task in tasks {
            let gated = tokio::time::timeout(WAIT, task)
                .await
                .expect("the send must answer on its own")
                .expect("the send must not panic");
            assert!(
                matches!(
                    gated,
                    Gated::Sent {
                        result: Ok(()),
                        rejected: None
                    }
                ),
                "{gated:?}"
            );
        }

        assert_eq!(server.connections.load(Ordering::SeqCst), 10);
    }

    #[tokio::test]
    async fn waiting_send_is_woken_by_a_release() {
        let server = serve("201 Created", "");
        let limiter = generic_limiter(DestLimits {
            reject_burst: 1.0,
            reject_refill_per_sec: 0.0,
            ..default_generic()
        });
        let client = http_client();
        let key = DestKey::Ip(server.addr.ip());

        // Another send holds the only rejection token.
        let Admit::Allowed(held) = limiter.admit("X", SubKey(9), key, Instant::now()) else {
            panic!("the first send must be admitted");
        };
        assert!(matches!(
            limiter.admit("A", SubKey(1), key, Instant::now()),
            Admit::Wait
        ));

        let started = Instant::now();
        let (gated, ()) = tokio::time::timeout(WAIT, async {
            tokio::join!(
                gated_send(
                    &limiter,
                    &client,
                    "A",
                    SubKey(1),
                    key,
                    server.addr,
                    SLOT_WAIT,
                    plain_message,
                ),
                async move {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    held.success();
                }
            )
        })
        .await
        .expect("the send must answer on its own");
        let waited = started.elapsed();

        assert!(
            matches!(
                gated,
                Gated::Sent {
                    result: Ok(()),
                    rejected: None
                }
            ),
            "{gated:?}"
        );
        assert!(waited >= Duration::from_millis(300), "{waited:?}");
        assert!(waited < SLOT_WAIT, "{waited:?}");
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn waiting_send_gives_up_after_slot_wait() {
        let server = serve("201 Created", "");
        let limiter = generic_limiter(DestLimits {
            reject_burst: 1.0,
            reject_refill_per_sec: 0.0,
            ..default_generic()
        });
        let client = http_client();
        let builds = AtomicUsize::new(0);
        let key = DestKey::Ip(server.addr.ip());
        let slot_wait = Duration::from_millis(300);

        let Admit::Allowed(held) = limiter.admit("X", SubKey(9), key, Instant::now()) else {
            panic!("the first send must be admitted");
        };

        let started = Instant::now();
        let gated = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &client,
                "A",
                SubKey(1),
                key,
                server.addr,
                slot_wait,
                counted_message(&builds),
            ),
        )
        .await
        .expect("the send must answer on its own");
        let waited = started.elapsed();

        assert!(matches!(gated, Gated::SlotTimeout), "{gated:?}");
        assert!(waited >= slot_wait, "{waited:?}");
        assert!(waited < WAIT, "{waited:?}");
        assert_eq!(builds.load(Ordering::SeqCst), 0);
        assert_eq!(server.connections.load(Ordering::SeqCst), 0);

        // With the slot free again, the same send goes out.
        drop(held);
        let sent = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &client,
                "A",
                SubKey(1),
                key,
                server.addr,
                slot_wait,
                counted_message(&builds),
            ),
        )
        .await
        .expect("the send must answer on its own");
        assert!(
            matches!(
                sent,
                Gated::Sent {
                    result: Ok(()),
                    rejected: None
                }
            ),
            "{sent:?}"
        );
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ntfy_429_does_not_pause_other_users() {
        let throttled = serve("429 Too Many Requests", "");
        let open = serve("201 Created", "");
        let limiter = UpLimiter::new();
        let client = http_client();

        let first = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &client,
                "A",
                SubKey(1),
                DestKey::Ntfy,
                throttled.addr,
                SLOT_WAIT,
                plain_message,
            ),
        )
        .await
        .expect("the send must answer on its own");
        assert!(
            matches!(
                &first,
                Gated::Sent {
                    result: Err(WebPushError::Other(status)),
                    rejected: Some(Rejected::Counted)
                } if status == "429"
            ),
            "{first:?}"
        );

        let second = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &client,
                "B",
                SubKey(2),
                DestKey::Ntfy,
                open.addr,
                SLOT_WAIT,
                plain_message,
            ),
        )
        .await
        .expect("the send must answer on its own");
        assert!(
            matches!(
                second,
                Gated::Sent {
                    result: Ok(()),
                    rejected: None
                }
            ),
            "{second:?}"
        );
        assert_eq!(open.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ntfy_503_pauses_at_once() {
        // Premise: without the 503 rule, one strike would not pause.
        assert!(UpLimits::default().ntfy.reject_burst >= 2.0);

        let server = serve("503 Service Unavailable", "");
        let limiter = UpLimiter::new();
        let client = http_client();

        let first = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &client,
                "A",
                SubKey(1),
                DestKey::Ntfy,
                server.addr,
                SLOT_WAIT,
                plain_message,
            ),
        )
        .await
        .expect("the send must answer on its own");
        let Gated::Sent {
            result: Err(WebPushError::ServerError(None)),
            rejected: Some(Rejected::Paused { top, .. }),
        } = &first
        else {
            panic!("a 503 from ntfy.sh must pause: {first:?}");
        };
        assert!(top.iter().any(|o| o.user_id == "A"), "{top:?}");

        let second = tokio::time::timeout(
            WAIT,
            gated_send(
                &limiter,
                &client,
                "B",
                SubKey(2),
                DestKey::Ntfy,
                server.addr,
                SLOT_WAIT,
                plain_message,
            ),
        )
        .await
        .expect("the send must answer on its own");
        assert!(
            matches!(
                second,
                Gated::Denied {
                    bucket: Bucket::Paused,
                    ..
                }
            ),
            "{second:?}"
        );
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }
}
