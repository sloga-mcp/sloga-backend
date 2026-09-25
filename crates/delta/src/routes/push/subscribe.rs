use revolt_database::{Database, Session};
use revolt_models::v0;
use revolt_result::{create_database_error, create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

/// Hosts a browser's push service hands out endpoints on, matched as the host
/// itself or any subdomain of it. Every web-push subscription on prod
/// (2026-09-24) sits on one of these.
const WEB_PUSH_HOSTS: &[&str] = &[
    // Chrome and the other Chromium browsers; android.* is the legacy GCM form
    "fcm.googleapis.com",
    "android.googleapis.com",
    // Chrome's newer endpoints (jmt17.google.com seen in prod)
    "google.com",
    // Firefox (updates.push.services.mozilla.com)
    "push.services.mozilla.com",
    // Safari (web.push.apple.com)
    "push.apple.com",
    // Edge on Windows (WNS, *.notify.windows.com)
    "notify.windows.com",
];

/// Whether `endpoint` is one pushd may deliver to.
///
/// pushd sends anything that is not "fcm" or "apn" to the web-push sender,
/// which POSTs to the endpoint URL as given. That URL used to be accepted
/// verbatim, so any logged-in client could point it at an internal address
/// (a blind SSRF from the push host). A browser's PushManager only ever
/// returns an https URL on its vendor's push service, so web endpoints are
/// held to that list; the native apps register the literal "fcm" or "apn".
pub fn push_endpoint_allowed(endpoint: &str) -> bool {
    if endpoint == "fcm" || endpoint == "apn" {
        return true;
    }

    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };

    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
    {
        return false;
    }

    // A domain, never an IP literal: `host()` separates the two.
    let Some(url::Host::Domain(host)) = url.host() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    WEB_PUSH_HOSTS
        .iter()
        .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
}

/// # Push Subscribe
///
/// Create a new Web Push subscription.
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
    if !push_endpoint_allowed(&data.endpoint) {
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
    use super::push_endpoint_allowed;

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
}
