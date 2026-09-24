use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use crate::{
    consumers::outbound::fcm::{notification_data, NotificationData},
    utils::Consumer,
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{
    engine::{self},
    Engine as _,
};
use isahc::{
    config::{Configurable, Dialer},
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

        // isahc never times out on its own, and the endpoint is
        // client-supplied, so a stalled server would pin a consumer task.
        // isahc does not follow redirects by default, which we rely on too.
        // One client for every send: each one spawns an agent thread.
        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("isahc HttpClient");

        Self {
            db,
            connection,
            channel,
            client: http_client,
            pkey: web_push_private_key,
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

        // The endpoint is client-supplied, so check where it points right
        // before we POST to it. The endpoint itself is never logged: it is a
        // bearer capability for the device.
        let Some((host, port)) = endpoint_host_port(&endpoint) else {
            warn!(
                "Refusing UnifiedPush for session {}: endpoint is not a valid https URL",
                payload.session_id
            );

            return Ok(());
        };

        // The send connects only to this address, so a DNS server cannot
        // pass the check and then answer differently for the connection.
        let Some(addr) = checked_address(&host, port).await else {
            warn!(
                "Refusing UnifiedPush for session {}: {} does not resolve to only public addresses",
                payload.session_id, host
            );

            return Ok(());
        };

        let ring_secs = revolt_config::config().await.api.livekit.call_ring_duration;

        let signature = VapidSignatureBuilder::from_pem(
            std::io::Cursor::new(self.pkey.as_ref()),
            &subscription,
        )?
        .build()?;

        let msg = build_message(&subscription, Some(signature), &bytes, &ty, ring_secs)?;

        let result = self.post(msg, addr).await;
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
                } else if let Err(err) = result {
                    warn!(
                        "UnifiedPush {} for session {} failed: {}",
                        ty, payload.session_id, err
                    );
                }
            }
        };

        Ok(())
    }
}

impl UnifiedPushOutboundConsumer {
    /// POST a message to its endpoint, connecting only to `addr`.
    async fn post(&self, message: WebPushMessage, addr: SocketAddr) -> Result<(), WebPushError> {
        let request = pinned_request(message, addr).map_err(|_| WebPushError::Unspecified)?;

        // A transport error becomes WebPushError::Unspecified, as it does in
        // web-push's IsahcWebPushClient (isahc_client.rs, error.rs).
        let response = self.client.send_async(request).await?;

        // The body is never read: there is no capped reader without a new
        // dependency, it only carries error detail, and every error except
        // 404/410 is kept anyway. Dropping the response aborts the transfer.
        parse_response(response.status(), Vec::new())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    use isahc::http::StatusCode;

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
}
