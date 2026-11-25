use base64::{
    alphabet,
    engine::{
        general_purpose::{GeneralPurpose, GeneralPurposeConfig},
        DecodePaddingMode,
    },
    Engine,
};
use revolt_database::{is_invalid_session, Database, Session, User};
use revolt_models::v0;
use revolt_result::{create_database_error, create_error, Error, Result};
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

/// Tidy the two per-session preferences before they are stored.
///
/// Only an explicit `true` turns a preference on. `false` says the same as
/// leaving the field out, so it is stored as absent and a saved subscription
/// never carries a `false` that some later reader could take for a choice.
///
/// `privileged` drops `chats_only`: a staff account must always receive
/// server notifications, because moderation depends on them. `no_ring` is
/// left to staff like to anyone else. Nothing else in the subscription is
/// touched.
fn sanitize_push_preferences(
    mut data: v0::WebPushSubscription,
    privileged: bool,
) -> v0::WebPushSubscription {
    data.chats_only = data.chats_only.filter(|on| *on);
    data.no_ring = data.no_ring.filter(|on| *on);

    if privileged {
        data.chats_only = None;
    }

    data
}

/// Whether `chats_only` has to be dropped for this request. It is kept only
/// when the user that was resolved is the owner of the session and is not
/// staff.
///
/// The `User` guard prefers an `x-bot-token` header over the session, so the
/// user it hands over is not always the session's owner. Such a user says
/// nothing about the owner, and reading it as "not staff" would let a staff
/// account keep the preference by sending a bot token along.
fn must_drop_chats_only(user: &User, session: &Session) -> bool {
    user.privileged || user.id != session.user_id
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
/// `chats_only` (direct messages, groups, friend requests and calls only) and
/// `no_ring` (never ring this session for a call) are optional and count only
/// when `true`. `chats_only` is not kept for a staff account.
///
/// If an existing subscription exists on this session, it will be removed,
/// together with the preferences it carried.
#[openapi(tag = "Web Push")]
#[post("/subscribe", data = "<data>")]
pub async fn subscribe(
    db: &State<Database>,
    mut session: Session,
    user: std::result::Result<User, Error>,
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

    // The user is looked at only for the staff rule; the session alone still
    // decides who may subscribe, as it did before the preferences existed
    let drop_chats_only = match user {
        Ok(user) => must_drop_chats_only(&user, &session),
        // No user behind this request (onboarding has not run yet, or an
        // unknown bot token came along): nobody can say the account is not
        // staff, so the preference is not kept. The subscription itself is
        // still saved, as it always was for such a session
        Err(error) if is_invalid_session(&error) => true,
        // A failed lookup is reported instead of guessed around, so the app
        // retries rather than believing a preference was saved
        Err(error) => return Err(error),
    };

    session.subscription = Some(sanitize_push_preferences(data, drop_chats_only).into());
    session
        .save(db)
        .await
        .map(|_| EmptyResponse)
        .map_err(|_| create_database_error!("save", "session"))
}

#[cfg(test)]
mod tests {
    use super::{push_endpoint_allowed, sanitize_push_preferences, validate_unifiedpush};
    use base64::{
        engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
        Engine,
    };
    use revolt_database::{Bot, PartialUser, Session};
    use revolt_models::v0;
    use revolt_result::ErrorType;

    use crate::util::test::TestHarness;
    use revolt_result::Error;
    use rocket::http::{ContentType, Header, Status};

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
            chats_only: None,
            no_ring: None,
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

    /// A ntfy-style UnifiedPush endpoint on a host no browser pushes through
    const UNIFIEDPUSH_ENDPOINT: &str = "https://ntfy.sh/upAbC123?up=1";

    const BROWSER_ENDPOINT: &str = "https://fcm.googleapis.com/fcm/send/abc:def";

    fn subscribe_body(endpoint: &str, kind: Option<&str>) -> serde_json::Value {
        let mut body = json!({
            "endpoint": endpoint,
            "p256dh": URL_SAFE_NO_PAD.encode(p256dh()),
            "auth": URL_SAFE_NO_PAD.encode([7u8; 16]),
        });
        if let Some(kind) = kind {
            body["kind"] = json!(kind);
        }
        body
    }

    /// POST `body` to the route as the session holding `token`, returning
    /// the status and the response body.
    async fn post_subscribe(
        harness: &TestHarness,
        token: &str,
        body: serde_json::Value,
    ) -> (Status, String) {
        let res = harness
            .client
            .post("/push/subscribe")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", token.to_string()))
            .body(body.to_string())
            .dispatch()
            .await;
        let status = res.status();
        (status, res.into_string().await.unwrap_or_default())
    }

    async fn stored_subscription(
        harness: &TestHarness,
        session_id: &str,
    ) -> Option<revolt_database::WebPushSubscription> {
        harness
            .db
            .fetch_session(session_id)
            .await
            .expect("session should exist")
            .subscription
    }

    fn assert_failed_validation(status: Status, body: &str, message: &str) {
        assert_eq!(status, Status::BadRequest, "unexpected response: {}", body);
        let error: Error = serde_json::from_str(body).expect("error body should be an Error");
        match error.error_type {
            ErrorType::FailedValidation { error } => assert_eq!(error, message),
            other => panic!("expected FailedValidation, got {:?}", other),
        }
    }

    #[test]
    fn unifiedpush_on_a_non_browser_host_is_accepted() {
        crate::util::test::rt().block_on(unifiedpush_on_a_non_browser_host_is_accepted_case())
    }

    async fn unifiedpush_on_a_non_browser_host_is_accepted_case() {
        // The allowlist refuses this host, so a 204 proves `kind` routed the
        // subscription around the allowlist rather than through it.
        assert!(
            !push_endpoint_allowed(UNIFIEDPUSH_ENDPOINT),
            "{} must not be on the allowlist",
            UNIFIEDPUSH_ENDPOINT
        );

        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let (status, body) = post_subscribe(
            &harness,
            &session.token,
            subscribe_body(UNIFIEDPUSH_ENDPOINT, Some("unifiedpush")),
        )
        .await;
        assert_eq!(status, Status::NoContent, "unexpected response: {}", body);

        let stored = stored_subscription(&harness, &session.id)
            .await
            .expect("subscription should be stored");
        assert_eq!(stored.endpoint, UNIFIEDPUSH_ENDPOINT);
        assert_eq!(
            stored.kind,
            Some(revolt_database::PushSubscriptionKind::UnifiedPush)
        );
    }

    #[test]
    fn same_endpoint_without_kind_is_refused() {
        crate::util::test::rt().block_on(same_endpoint_without_kind_is_refused_case())
    }

    async fn same_endpoint_without_kind_is_refused_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let (status, body) = post_subscribe(
            &harness,
            &session.token,
            subscribe_body(UNIFIEDPUSH_ENDPOINT, None),
        )
        .await;
        assert_failed_validation(status, &body, "endpoint is not a supported push service");
        assert_eq!(stored_subscription(&harness, &session.id).await, None);
    }

    #[test]
    fn unifiedpush_over_http_is_refused() {
        crate::util::test::rt().block_on(unifiedpush_over_http_is_refused_case())
    }

    async fn unifiedpush_over_http_is_refused_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let (status, body) = post_subscribe(
            &harness,
            &session.token,
            subscribe_body("http://ntfy.sh/upAbC123?up=1", Some("unifiedpush")),
        )
        .await;
        assert_failed_validation(status, &body, "endpoint must use https");
        assert_eq!(stored_subscription(&harness, &session.id).await, None);
    }

    #[test]
    fn browser_subscribe_is_unchanged() {
        crate::util::test::rt().block_on(browser_subscribe_is_unchanged_case())
    }

    async fn browser_subscribe_is_unchanged_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let (status, body) = post_subscribe(
            &harness,
            &session.token,
            subscribe_body(BROWSER_ENDPOINT, None),
        )
        .await;
        assert_eq!(status, Status::NoContent, "unexpected response: {}", body);

        let stored = stored_subscription(&harness, &session.id)
            .await
            .expect("subscription should be stored");
        assert_eq!(stored.endpoint, BROWSER_ENDPOINT);
        assert_eq!(stored.kind, None);
    }

    const ON: Option<bool> = Some(true);
    const OFF: Option<bool> = Some(false);

    /// Every combination of the two preferences, for a plain account and for
    /// a staff one. Only `Some(true)` survives, staff never keep
    /// `chats_only`, staff do keep `no_ring`, and the rest of the
    /// subscription comes back as it went in
    #[test]
    fn sanitize_push_preferences_truth_table() {
        // ((chats_only, no_ring, privileged), (chats_only, no_ring))
        type Row = ((Option<bool>, Option<bool>, bool), (Option<bool>, Option<bool>));
        let table: [Row; 18] = [
            ((None, None, false), (None, None)),
            ((None, OFF, false), (None, None)),
            ((None, ON, false), (None, ON)),
            ((OFF, None, false), (None, None)),
            ((OFF, OFF, false), (None, None)),
            ((OFF, ON, false), (None, ON)),
            ((ON, None, false), (ON, None)),
            ((ON, OFF, false), (ON, None)),
            ((ON, ON, false), (ON, ON)),
            ((None, None, true), (None, None)),
            ((None, OFF, true), (None, None)),
            ((None, ON, true), (None, ON)),
            ((OFF, None, true), (None, None)),
            ((OFF, OFF, true), (None, None)),
            ((OFF, ON, true), (None, ON)),
            ((ON, None, true), (None, None)),
            ((ON, OFF, true), (None, None)),
            ((ON, ON, true), (None, ON)),
        ];

        for ((chats_only, no_ring, privileged), (kept_chats_only, kept_no_ring)) in table {
            let sanitized = sanitize_push_preferences(
                v0::WebPushSubscription {
                    chats_only,
                    no_ring,
                    ..valid()
                },
                privileged,
            );
            assert_eq!(
                sanitized,
                v0::WebPushSubscription {
                    chats_only: kept_chats_only,
                    no_ring: kept_no_ring,
                    ..valid()
                },
                "chats_only {chats_only:?}, no_ring {no_ring:?}, privileged {privileged}"
            );
        }
    }

    /// A browser subscription body carrying whichever preferences are given;
    /// `None` leaves the key out of the JSON altogether
    fn preferences_body(chats_only: Option<bool>, no_ring: Option<bool>) -> serde_json::Value {
        let mut body = subscribe_body(BROWSER_ENDPOINT, None);
        if let Some(chats_only) = chats_only {
            body["chats_only"] = json!(chats_only);
        }
        if let Some(no_ring) = no_ring {
            body["no_ring"] = json!(no_ring);
        }
        body
    }

    /// Subscribe `session` with the given preferences and return the two as
    /// they were stored: `(chats_only, no_ring)`
    async fn stored_preferences(
        harness: &TestHarness,
        session: &Session,
        chats_only: Option<bool>,
        no_ring: Option<bool>,
    ) -> (Option<bool>, Option<bool>) {
        let (status, body) = post_subscribe(
            harness,
            &session.token,
            preferences_body(chats_only, no_ring),
        )
        .await;
        assert_eq!(status, Status::NoContent, "unexpected response: {}", body);

        let stored = stored_subscription(harness, &session.id)
            .await
            .expect("subscription should be stored");
        assert_eq!(stored.endpoint, BROWSER_ENDPOINT);
        (stored.chats_only, stored.no_ring)
    }

    /// The session of a fresh user promoted to staff
    async fn new_staff_session(harness: &TestHarness) -> Session {
        let (_, session, mut staff) = harness.new_user().await;
        staff
            .update(
                &harness.db,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("promote staff");
        assert!(
            harness
                .db
                .fetch_user(&session.user_id)
                .await
                .expect("staff user")
                .privileged
        );
        session
    }

    #[test]
    fn preferences_round_trip_for_a_plain_account() {
        crate::util::test::rt().block_on(preferences_round_trip_for_a_plain_account_case())
    }

    async fn preferences_round_trip_for_a_plain_account_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        // Each subscribe replaces the one before it on the same session
        for (chats_only, no_ring) in [(ON, ON), (ON, None), (None, ON)] {
            assert_eq!(
                stored_preferences(&harness, &session, chats_only, no_ring).await,
                (chats_only, no_ring)
            );
        }
    }

    /// A `false` is the same as leaving the field out, and is stored that way
    #[test]
    fn false_preferences_are_stored_as_absent() {
        crate::util::test::rt().block_on(false_preferences_are_stored_as_absent_case())
    }

    async fn false_preferences_are_stored_as_absent_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        assert_eq!(
            stored_preferences(&harness, &session, OFF, OFF).await,
            (None, None)
        );
        assert_eq!(
            stored_preferences(&harness, &session, OFF, ON).await,
            (None, ON)
        );
        assert_eq!(
            stored_preferences(&harness, &session, ON, OFF).await,
            (ON, None)
        );
    }

    /// Staff must keep getting server notifications, so their `chats_only`
    /// never reaches the session. Whether a call rings is still theirs to
    /// choose
    #[test]
    fn staff_chats_only_is_dropped_and_no_ring_kept() {
        crate::util::test::rt().block_on(staff_chats_only_is_dropped_and_no_ring_kept_case())
    }

    async fn staff_chats_only_is_dropped_and_no_ring_kept_case() {
        let harness = TestHarness::new().await;
        let session = new_staff_session(&harness).await;

        assert_eq!(
            stored_preferences(&harness, &session, ON, ON).await,
            (None, ON)
        );
        assert_eq!(
            stored_preferences(&harness, &session, ON, None).await,
            (None, None)
        );
    }

    /// An app that knows nothing of the preferences stores none, and its
    /// subscribe clears whatever an earlier one had set
    #[test]
    fn a_body_without_preferences_stores_neither() {
        crate::util::test::rt().block_on(a_body_without_preferences_stores_neither_case())
    }

    async fn a_body_without_preferences_stores_neither_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;
        assert!(preferences_body(None, None).get("chats_only").is_none());
        assert!(preferences_body(None, None).get("no_ring").is_none());

        assert_eq!(
            stored_preferences(&harness, &session, None, None).await,
            (None, None)
        );

        assert_eq!(
            stored_preferences(&harness, &session, ON, ON).await,
            (ON, ON)
        );
        assert_eq!(
            stored_preferences(&harness, &session, None, None).await,
            (None, None)
        );

        let staff = new_staff_session(&harness).await;
        assert_eq!(
            stored_preferences(&harness, &staff, None, None).await,
            (None, None)
        );
    }

    /// The `User` guard answers with the bot when a bot token is sent along,
    /// and a bot is never staff. The staff rule follows the owner of the
    /// session, so the extra header does not let a staff session keep
    /// `chats_only`
    #[test]
    fn a_bot_token_does_not_keep_chats_only_for_staff() {
        crate::util::test::rt().block_on(a_bot_token_does_not_keep_chats_only_for_staff_case())
    }

    async fn a_bot_token_does_not_keep_chats_only_for_staff_case() {
        let harness = TestHarness::new().await;
        let session = new_staff_session(&harness).await;

        let (_, _, owner) = harness.new_user().await;
        let (bot, bot_user) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("bot");
        assert!(!bot_user.privileged);

        let res = harness
            .client
            .post("/push/subscribe")
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", session.token.to_string()))
            .header(Header::new("x-bot-token", bot.token.to_string()))
            .body(preferences_body(ON, ON).to_string())
            .dispatch()
            .await;
        assert_eq!(res.status(), Status::NoContent);

        let stored = stored_subscription(&harness, &session.id)
            .await
            .expect("subscription should be stored");
        assert_eq!((stored.chats_only, stored.no_ring), (None, ON));
    }

    /// A session whose user does not exist yet (onboarding has not run)
    /// could always subscribe, and still can. Nobody can vouch that it is
    /// not staff, so `chats_only` is not kept for it
    #[test]
    fn a_session_without_a_user_still_subscribes() {
        crate::util::test::rt().block_on(a_session_without_a_user_still_subscribes_case())
    }

    async fn a_session_without_a_user_still_subscribes_case() {
        let harness = TestHarness::new().await;
        let id = ulid::Ulid::new().to_string();
        let (_, session) = harness.account_from_user(id.clone()).await;
        assert!(harness.db.fetch_user(&id).await.is_err());

        assert_eq!(
            stored_preferences(&harness, &session, ON, ON).await,
            (None, ON)
        );
    }
}
