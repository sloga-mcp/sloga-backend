use std::{net::IpAddr, sync::Arc, time::Duration};

use crate::{consumers::outbound::fcm::notification_data, utils::Consumer};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{
    engine::{self},
    Engine as _,
};
use isahc::{config::Configurable, http::Uri, HttpClient};
use lapin::{message::Delivery, Channel as AMQPChannel, Connection};
use log::{error, info, warn};
use revolt_database::{events::rabbit::*, Database};
use serde_json::Value;
use web_push::{
    ContentEncoding, IsahcWebPushClient, SubscriptionInfo, SubscriptionKeys, Urgency,
    VapidSignatureBuilder, WebPushClient, WebPushError, WebPushMessageBuilder,
};

/// Longest `body` we forward, in UTF-8 bytes.
const MAX_BODY_BYTES: usize = 1000;

/// web-push refuses plaintext above this many bytes (http_ece.rs).
const MAX_PAYLOAD_BYTES: usize = 3052;

/// TTL for everything except call rings: one day.
const DEFAULT_TTL_SECS: u32 = 86400;

/// Ring TTL if `call_ring_duration` does not fit in a u32.
const FALLBACK_RING_TTL_SECS: u32 = 30;

#[derive(Clone)]
#[allow(unused)]
pub struct UnifiedPushOutboundConsumer {
    db: Database,
    connection: Arc<Connection>,
    channel: Arc<AMQPChannel>,
    client: IsahcWebPushClient,
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

        // IsahcWebPushClient never times out on its own, and the endpoint is
        // client-supplied, so a stalled server would pin a consumer task.
        // isahc does not follow redirects by default, which we rely on too.
        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("isahc HttpClient");

        Self {
            db,
            connection,
            channel,
            client: IsahcWebPushClient::from(http_client),
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

        let ty = data.get_type().to_string();
        let mut map = data.into_payload();
        map.insert("type".to_string(), Value::String(ty.clone()));

        if let Some(Value::String(body)) = map.get_mut("body") {
            truncate_utf8(body, MAX_BODY_BYTES);
        }

        let bytes = serde_json::to_vec(&map)?;
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

        if !resolves_to_public_addresses(&host, port).await {
            warn!(
                "Refusing UnifiedPush for session {}: {} does not resolve to only public addresses",
                payload.session_id, host
            );

            return Ok(());
        }

        let ring_secs = revolt_config::config().await.api.livekit.call_ring_duration;
        let (urgency, ttl) = delivery_params(&ty, ring_secs);

        let signature = VapidSignatureBuilder::from_pem(
            std::io::Cursor::new(self.pkey.as_ref()),
            &subscription,
        )?
        .build()?;

        let mut builder = WebPushMessageBuilder::new(&subscription);
        builder.set_vapid_signature(signature);

        // UnifiedPush (spec AND_3) requires RFC 8291 aes128gcm, not the
        // legacy aesgcm that vapid.rs sends to browsers.
        builder.set_payload(ContentEncoding::Aes128Gcm, &bytes);
        builder.set_ttl(ttl);
        builder.set_urgency(urgency);
        // No Topic: it travels to the push server in the clear.

        let msg = builder.build()?;

        match self.client.send(msg).await {
            Ok(()) => {}
            // 404/410: the distributor says this endpoint is gone for good.
            // Only drop it if it is still the stored one, so a late failure
            // cannot wipe a subscription the device has since replaced.
            Err(WebPushError::EndpointNotFound | WebPushError::EndpointNotValid) => {
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
            // 401 means our VAPID key does not match the one the device
            // subscribed with; that is a server problem, not a dead endpoint.
            Err(WebPushError::Unauthorized) => {
                error!(
                    "UnifiedPush VAPID rejected for session {} (subscription kept)",
                    payload.session_id
                );
            }
            // web-push maps every 5xx to ServerError, so none of these say
            // anything permanent about the endpoint.
            Err(err) => {
                warn!(
                    "UnifiedPush {} for session {} failed: {}",
                    ty, payload.session_id, err
                );
            }
        };

        Ok(())
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

/// Resolve the host and require every address to be public. A lookup that
/// fails or returns nothing is treated as not public.
async fn resolves_to_public_addresses(host: &str, port: u16) -> bool {
    let Ok(addrs) = tokio::net::lookup_host((host, port)).await else {
        return false;
    };

    let mut any = false;
    for addr in addrs {
        if is_forbidden_address(addr.ip()) {
            return false;
        }

        any = true;
    }

    any
}

/// Addresses a push endpoint must never point at: loopback, private,
/// link-local, unspecified, broadcast and multicast.
fn is_forbidden_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                // 0.0.0.0/8 ("this network"), as january blocks it too.
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            // ::ffff:a.b.c.d would otherwise slip a private v4 address past.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_forbidden_address(IpAddr::V4(v4));
            }

            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(!is_forbidden_address(ip), "{addr} should be accepted");
        }
    }
}
