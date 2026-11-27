use std::sync::Arc;

use revolt_database::{now_ms, Database};
use revolt_payments::engine::prot_store::{handle_apple_notification, AppleNotificationOutcome};
use revolt_payments::settings::{ProtSalesSettings, ProtStoreSettings};
use revolt_payments::store::AppleStoreApi;
use rocket::data::ToByteUnit;
use rocket::http::Status;
use rocket::{Data, State};

/// Largest body read (64 KiB); Apple notification payloads are a few KiB
const BODY_LIMIT_BYTES: u64 = 65_536;

/// # App Store Server Notifications
///
/// Unauthenticated: a notification (V2, `{"signedPayload": "<JWS>"}`) is
/// trusted only when its JWS verifies against the pinned Apple root. The
/// status alone tells Apple whether to send it again; the body is empty.
///
/// - 400: a body over 64 KiB or unreadable, a body that is not a
///   notification, or a JWS that does not verify
/// - 500: the store config is unusable, the App Store is not configured, or
///   handling failed (a store lookup or the database): Apple retries, and
///   the reconcile replays its notification history
/// - 200: handled, or ignored (another app, a type not acted on)
///
/// Handled whatever the store switches say: they gate new intents only, so a
/// refund after a store is closed still claws back.
#[openapi(skip)]
#[post("/apple/notifications", data = "<data>")]
pub async fn apple_notifications(
    db: &State<Database>,
    apple: &State<Arc<dyn AppleStoreApi>>,
    data: Data<'_>,
) -> Status {
    // The exact bytes Apple sent: never re-serialized before verifying
    let body = match data.open(BODY_LIMIT_BYTES.bytes()).into_bytes().await {
        Ok(body) => body,
        Err(_) => {
            log::warn!("payments: App Store notification: could not read the request body");
            return Status::BadRequest;
        }
    };
    if !body.is_complete() {
        log::warn!(
            "payments: App Store notification: refused a body larger than {BODY_LIMIT_BYTES} bytes"
        );
        return Status::BadRequest;
    }
    let body = body.into_inner();

    // The Prot sale settings fall back to the shipped defaults, logged (R60):
    // a web-sale config typo must never stop a refund or a credit. A store
    // config that does not validate settles nothing under a default: 500,
    // and Apple sends it again once the config is fixed (`load` logs what is
    // wrong, never a key).
    let ps = ProtSalesSettings::load_or_closed().await;
    let Ok(st) = ProtStoreSettings::load().await else {
        log::error!(
            "payments: PROT_STORE_CONFIG_INVALID: an App Store notification is answered 500 for \
             a retry"
        );
        return Status::InternalServerError;
    };

    notification_status(
        handle_apple_notification(db, &ps, &st, &**apple.inner(), &body, now_ms()).await,
    )
}

/// What Apple is answered for each outcome of the engine
fn notification_status(outcome: AppleNotificationOutcome) -> Status {
    match outcome {
        AppleNotificationOutcome::Handled | AppleNotificationOutcome::Ignored => Status::Ok,
        AppleNotificationOutcome::BadSignature => Status::BadRequest,
        AppleNotificationOutcome::Retry => Status::InternalServerError,
    }
}

#[cfg(test)]
mod tests {
    use revolt_config::ApiAppStore;
    use revolt_database::now_ms;
    use revolt_payments::engine::prot_store::{
        handle_apple_notification, AppleNotificationOutcome,
    };
    use revolt_payments::settings::{ProtSalesSettings, ProtStoreSettings};
    use rocket::http::{ContentType, Status};
    use serde_json::json;

    use super::{notification_status, BODY_LIMIT_BYTES};
    use crate::util::test::TestHarness;

    const PATH: &str = "/payments/apple/notifications";

    async fn notify(harness: &TestHarness, body: Vec<u8>) -> Status {
        harness
            .client
            .post(PATH)
            .header(ContentType::JSON)
            .body(body)
            .dispatch()
            .await
            .status()
    }

    /// A notification-shaped body padded with trailing whitespace (valid
    /// JSON) to exactly `len` bytes: any 64 KiB prefix of it parses too
    fn padded_body(len: usize) -> Vec<u8> {
        let mut body = json!({ "signedPayload": "a.b.c" }).to_string().into_bytes();
        body.resize(len, b' ');
        body
    }

    /// The test config has no `[api.appstore]` credentials, so a notification
    /// that reaches the engine is answered Retry (500): the config failure
    /// leg of 12.2. Asserted, or the statuses below would mean something else.
    async fn assert_no_appstore_config() {
        let st = ProtStoreSettings::load().await.expect("store settings");
        assert!(
            st.apple.is_none(),
            "Revolt.test.toml must carry no App Store credentials, or the tests below prove \
             nothing"
        );
    }

    /// The route reads at most 64 KiB and refuses a larger body unread (400)
    /// rather than truncating it: a body of exactly 64 KiB reaches the
    /// engine (500 here, see `assert_no_appstore_config`), one byte more is
    /// 400. The padding is whitespace, so a read that went on with the first
    /// 64 KiB, or a `Json<..>` guard (1 MiB), would reach the engine with it
    /// too and answer 500.
    #[test]
    fn apple_notification_body_over_64_kib_is_refused_unread() {
        crate::util::test::rt()
            .block_on(apple_notification_body_over_64_kib_is_refused_unread_case())
    }

    async fn apple_notification_body_over_64_kib_is_refused_unread_case() {
        let harness = TestHarness::new().await;
        assert_no_appstore_config().await;
        let limit = BODY_LIMIT_BYTES as usize;
        assert_eq!(limit, 64 * 1024);

        let at_limit = padded_body(limit);
        assert_eq!(at_limit.len(), limit);
        assert_eq!(
            notify(&harness, at_limit).await,
            Status::InternalServerError
        );

        let over = padded_body(limit + 1);
        assert_eq!(over.len(), limit + 1);
        assert_eq!(notify(&harness, over).await, Status::BadRequest);

        assert!(harness.apple.calls().is_empty());
    }

    /// The route hands the engine the bytes exactly as received; the engine
    /// alone decides what they are. A body that is JSON but not a
    /// notification is the engine's BadSignature (400), never a body guard's
    /// own answer (a `Json<..>` read answers those 422 before any check, and
    /// re-serializes what it parsed); a notification-shaped body reaches the
    /// signature check (500 here: no App Store root is configured).
    ///
    /// The App Store signature itself sits inside the body, over the JWS
    /// text, so the forged-signature leg is
    /// `apple_notification_with_a_bad_signature_is_400`.
    #[test]
    fn apple_notification_signature_is_over_the_raw_body() {
        crate::util::test::rt().block_on(apple_notification_signature_is_over_the_raw_body_case())
    }

    async fn apple_notification_signature_is_over_the_raw_body_case() {
        let harness = TestHarness::new().await;
        assert_no_appstore_config().await;

        for body in [json!({}), json!({ "signedPayload": 5 })] {
            assert_eq!(
                notify(&harness, body.to_string().into_bytes()).await,
                Status::BadRequest,
                "{body}"
            );
        }
        assert_eq!(
            notify(
                &harness,
                json!({ "signedPayload": "a.b.c" }).to_string().into_bytes()
            )
            .await,
            Status::InternalServerError
        );
        assert!(harness.apple.calls().is_empty());
    }

    /// With the App Store configured and the shipped root pin, a JWS that
    /// does not chain to it is 400 and nothing is asked of Apple.
    ///
    /// The routes read the config through `load()`, and `overwrite_config`
    /// works once per process, so App Store credentials cannot be added for
    /// one test. This drives the engine call the route makes, and the
    /// route's answer for it, with credentials added to the loaded settings.
    #[test]
    fn apple_notification_with_a_bad_signature_is_400() {
        crate::util::test::rt().block_on(apple_notification_with_a_bad_signature_is_400_case())
    }

    async fn apple_notification_with_a_bad_signature_is_400_case() {
        let harness = TestHarness::new().await;
        let config = revolt_config::config().await;
        let ps = ProtSalesSettings::load().await.expect("prot settings");
        let st = ProtStoreSettings::from_parts(
            &config.features.payments,
            &ApiAppStore {
                issuer_id: "ISSUER".to_string(),
                key_id: "KEYID".to_string(),
                private_key: "never used: no request is made".to_string(),
                ..config.api.appstore.clone()
            },
            &config.api.googleplay,
        )
        .expect("store settings");
        assert!(st.apple.is_some());

        // A JWS-shaped forgery: an ES256 header with an x5c no chain builds
        // from, any payload, any signature
        let forged = format!(
            "{}.{}.{}",
            base64_url(&json!({ "alg": "ES256", "x5c": ["AAAA", "AAAA", "AAAA"] }).to_string()),
            base64_url(&json!({ "notificationType": "REFUND" }).to_string()),
            base64_url("signature")
        );
        for signed in ["a.b.c".to_string(), forged] {
            let body = json!({ "signedPayload": signed }).to_string().into_bytes();
            let outcome =
                handle_apple_notification(&harness.db, &ps, &st, &*harness.apple, &body, now_ms())
                    .await;
            assert_eq!(outcome, AppleNotificationOutcome::BadSignature);
            assert_eq!(notification_status(outcome), Status::BadRequest);
        }
        assert!(harness.apple.calls().is_empty());
    }

    fn base64_url(text: &str) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        URL_SAFE_NO_PAD.encode(text)
    }

    /// Apple retries on anything but 2xx: handled and ignored notifications
    /// (another app, REFUND_DECLINED, TEST, an unknown type) are 200, a
    /// notification that does not verify is 400, a failure to handle one is
    /// 500. Which notification is which outcome is the engine's test
    /// (`apple_notification_checks_the_signature_and_the_app`).
    #[test]
    fn apple_notification_outcomes_map_to_statuses() {
        for (outcome, status) in [
            (AppleNotificationOutcome::Handled, Status::Ok),
            (AppleNotificationOutcome::Ignored, Status::Ok),
            (AppleNotificationOutcome::BadSignature, Status::BadRequest),
            (AppleNotificationOutcome::Retry, Status::InternalServerError),
        ] {
            assert_eq!(notification_status(outcome), status, "{outcome:?}");
        }
    }
}
