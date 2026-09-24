use base64::{
    alphabet,
    engine::{
        general_purpose::{GeneralPurpose, GeneralPurposeConfig},
        DecodePaddingMode,
    },
    Engine,
};
use revolt_database::{Database, Session};
use revolt_models::v0;
use revolt_result::{create_database_error, create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

/// The allowlist lives in revolt-models so pushd re-checks the same list before
/// every send.
pub use revolt_models::v0::push_endpoint_allowed;

/// Longest UnifiedPush endpoint accepted, in bytes
const UNIFIEDPUSH_ENDPOINT_MAX_LEN: usize = 1000;

/// URL-safe base64 that decodes keys with or without padding
const URL_SAFE_ANY_PAD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Decode a base64url subscription key, padded or not.
fn decode_key(field: &str, value: &str) -> Result<Vec<u8>> {
    URL_SAFE_ANY_PAD.decode(value).map_err(|_| {
        create_error!(FailedValidation {
            error: format!("{field} must be base64url")
        })
    })
}

/// Check the shape of a UnifiedPush subscription before it is saved: an
/// https endpoint of at most 1000 bytes, a 65-byte uncompressed P-256
/// public key and a 16-byte auth secret (RFC 8291). Shape only; the
/// endpoint's address is checked when pushd sends to it.
fn validate_unifiedpush(data: &v0::WebPushSubscription) -> Result<()> {
    if data.endpoint.len() > UNIFIEDPUSH_ENDPOINT_MAX_LEN {
        return Err(create_error!(FailedValidation {
            error: format!("endpoint must be at most {UNIFIEDPUSH_ENDPOINT_MAX_LEN} bytes")
        }));
    }

    // Printable ASCII only, checked before parsing: the URL parser drops
    // tabs and encodes spaces, controls and non-ASCII hosts, so the stored
    // string could otherwise differ from what pushd's HTTP client sees.
    if !data
        .endpoint
        .bytes()
        .all(|byte| matches!(byte, 0x21..=0x7E))
    {
        return Err(create_error!(FailedValidation {
            error: "endpoint must be printable ASCII without spaces".to_string()
        }));
    }

    let endpoint = url::Url::parse(&data.endpoint).map_err(|_| {
        create_error!(FailedValidation {
            error: "endpoint must be a valid URL".to_string()
        })
    })?;

    if endpoint.scheme() != "https" {
        return Err(create_error!(FailedValidation {
            error: "endpoint must use https".to_string()
        }));
    }

    let p256dh = decode_key("p256dh", &data.p256dh)?;
    if p256dh.len() != 65 || p256dh[0] != 0x04 {
        return Err(create_error!(FailedValidation {
            error: "p256dh must be a 65-byte uncompressed P-256 public key".to_string()
        }));
    }

    let auth = decode_key("auth", &data.auth)?;
    if auth.len() != 16 {
        return Err(create_error!(FailedValidation {
            error: "auth must decode to exactly 16 bytes".to_string()
        }));
    }

    Ok(())
}

/// # Push Subscribe
///
/// Create a new Web Push subscription.
///
/// UnifiedPush subscriptions (`kind: "unifiedpush"`) must use an https
/// endpoint and base64url-encoded `p256dh` and `auth` keys; pushd checks the
/// endpoint's address before every send. Any other subscription must be
/// "fcm", "apn" or an https endpoint on a browser's push service.
///
/// If an existing subscription exists on this session, it will be removed.
#[openapi(tag = "Web Push")]
#[post("/subscribe", data = "<data>")]
pub async fn subscribe(
    db: &State<Database>,
    mut session: Session,
    data: Json<v0::WebPushSubscription>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();
    if data.kind == Some(v0::PushSubscriptionKind::UnifiedPush) {
        validate_unifiedpush(&data)?;
    } else if !push_endpoint_allowed(&data.endpoint) {
        return Err(create_error!(FailedValidation {
            error: "endpoint is not a supported push service".to_string()
        }));
    }

    session.subscription = Some(data.into());
    session
        .save(db)
        .await
        .map(|_| EmptyResponse)
        .map_err(|_| create_database_error!("save", "session"))
}

#[cfg(test)]
mod tests {
    use super::{push_endpoint_allowed, validate_unifiedpush};
    use base64::{
        engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
        Engine,
    };
    use revolt_models::v0;
    use revolt_result::ErrorType;

    #[test]
    fn accepts_every_endpoint_shape_seen_in_prod() {
        for endpoint in [
            "fcm",
            "apn",
            "https://fcm.googleapis.com/fcm/send/abc:def",
            "https://android.googleapis.com/gcm/send/abc",
            "https://jmt17.google.com/fcm/send/abc",
            "https://updates.push.services.mozilla.com/wpush/v2/abc",
            "https://web.push.apple.com/QAbc",
            "https://wns2-bn3p.notify.windows.com/w/?token=abc",
            "https://fcm.googleapis.com:443/fcm/send/abc",
            "https://FCM.GoogleAPIs.com/fcm/send/abc",
        ] {
            assert!(push_endpoint_allowed(endpoint), "{endpoint} must be accepted");
        }
    }

    #[test]
    fn rejects_anything_that_could_reach_an_internal_address() {
        for endpoint in [
            "http://fcm.googleapis.com/fcm/send/abc",
            "https://127.0.0.1/push",
            "https://[::1]/push",
            "https://10.0.0.5/push",
            "https://169.254.169.254/latest/meta-data",
            "https://localhost/push",
            "https://heart1.sloga.gg/push",
            "https://fcm.googleapis.com:8080/fcm/send/abc",
            "https://user:pw@fcm.googleapis.com/fcm/send/abc",
            "https://fcm.googleapis.com.attacker.example/fcm/send/abc",
            "https://notgoogle.com/push",
            "https://evilpush.apple.com.example/push",
            "file:///etc/passwd",
            "not a url",
            "",
            "FCM",
        ] {
            assert!(!push_endpoint_allowed(endpoint), "{endpoint:?} must be refused");
        }
    }

    const ENDPOINT: &str = "https://push.example.com/UP?token=abc";

    fn p256dh() -> Vec<u8> {
        let mut key = vec![0x42; 65];
        key[0] = 0x04;
        key
    }

    fn subscription(endpoint: &str, p256dh: &str, auth: &str) -> v0::WebPushSubscription {
        v0::WebPushSubscription {
            endpoint: endpoint.to_string(),
            p256dh: p256dh.to_string(),
            auth: auth.to_string(),
            kind: Some(v0::PushSubscriptionKind::UnifiedPush),
        }
    }

    fn valid() -> v0::WebPushSubscription {
        subscription(
            ENDPOINT,
            &URL_SAFE_NO_PAD.encode(p256dh()),
            &URL_SAFE_NO_PAD.encode([7u8; 16]),
        )
    }

    fn assert_rejected(data: &v0::WebPushSubscription) {
        let error = validate_unifiedpush(data).expect_err("subscription should be rejected");
        assert!(
            matches!(error.error_type, ErrorType::FailedValidation { .. }),
            "unexpected error: {:?}",
            error.error_type
        );
    }

    #[test]
    fn accepts_unpadded_keys() {
        assert!(validate_unifiedpush(&valid()).is_ok());
    }

    #[test]
    fn accepts_padded_keys() {
        let data = subscription(
            ENDPOINT,
            &URL_SAFE.encode(p256dh()),
            &URL_SAFE.encode([7u8; 16]),
        );
        assert!(data.p256dh.ends_with('=') && data.auth.ends_with("=="));
        assert!(validate_unifiedpush(&data).is_ok());
    }

    #[test]
    fn accepts_endpoint_at_length_limit() {
        let mut endpoint = "https://push.example.com/".to_string();
        endpoint.push_str(&"a".repeat(1000 - endpoint.len()));
        assert_eq!(endpoint.len(), 1000);

        let data = v0::WebPushSubscription {
            endpoint,
            ..valid()
        };
        assert!(validate_unifiedpush(&data).is_ok());
    }

    #[test]
    fn rejects_endpoint_over_length_limit() {
        let mut endpoint = "https://push.example.com/".to_string();
        endpoint.push_str(&"a".repeat(1001 - endpoint.len()));
        assert_eq!(endpoint.len(), 1001);

        assert_rejected(&v0::WebPushSubscription {
            endpoint,
            ..valid()
        });
    }

    #[test]
    fn rejects_unparseable_endpoint() {
        assert_rejected(&v0::WebPushSubscription {
            endpoint: "not-a-url".to_string(),
            ..valid()
        });
    }

    #[test]
    fn rejects_endpoint_with_space() {
        assert_rejected(&v0::WebPushSubscription {
            endpoint: "https://push.example.com/U P?token=abc".to_string(),
            ..valid()
        });
    }

    #[test]
    fn rejects_endpoint_with_tab() {
        assert_rejected(&v0::WebPushSubscription {
            endpoint: "https://push.example.com/U\tP?token=abc".to_string(),
            ..valid()
        });
    }

    #[test]
    fn rejects_endpoint_with_delete_control() {
        assert_rejected(&v0::WebPushSubscription {
            endpoint: "https://push.example.com/U\u{7f}P?token=abc".to_string(),
            ..valid()
        });
    }

    #[test]
    fn rejects_endpoint_with_non_ascii_host() {
        assert_rejected(&v0::WebPushSubscription {
            endpoint: "https://ex\u{e4}mple.com/x".to_string(),
            ..valid()
        });
    }

    #[test]
    fn rejects_non_https_endpoint() {
        assert_rejected(&v0::WebPushSubscription {
            endpoint: "http://push.example.com/UP?token=abc".to_string(),
            ..valid()
        });
    }

    #[test]
    fn rejects_p256dh_that_is_not_base64url() {
        assert_rejected(&v0::WebPushSubscription {
            p256dh: "not base64!".to_string(),
            ..valid()
        });
    }

    #[test]
    fn rejects_p256dh_of_wrong_length() {
        assert_rejected(&v0::WebPushSubscription {
            p256dh: URL_SAFE_NO_PAD.encode(&p256dh()[..64]),
            ..valid()
        });
    }

    #[test]
    fn rejects_p256dh_without_uncompressed_prefix() {
        let mut key = p256dh();
        key[0] = 0x02;
        assert_rejected(&v0::WebPushSubscription {
            p256dh: URL_SAFE_NO_PAD.encode(key),
            ..valid()
        });
    }

    #[test]
    fn rejects_auth_that_is_not_base64url() {
        assert_rejected(&v0::WebPushSubscription {
            auth: "not base64!".to_string(),
            ..valid()
        });
    }

    #[test]
    fn rejects_auth_of_wrong_length() {
        for len in [15, 17] {
            assert_rejected(&v0::WebPushSubscription {
                auth: URL_SAFE_NO_PAD.encode(vec![7u8; len]),
                ..valid()
            });
        }
    }
}
