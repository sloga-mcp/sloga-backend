use iso8601_timestamp::Timestamp;

use crate::v0::{MFAMethod, MFAResponse};

auto_derived!(
    pub struct Session {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,

        /// User Id
        pub user_id: String,

        /// Session token
        pub token: String,

        /// Display name
        pub name: String,

        /// When the session was last logged in
        pub last_seen: Timestamp,

        /// Where the session is originating from
        #[serde(skip_serializing_if = "Option::is_none")]
        pub origin: Option<String>,

        /// Web Push subscription
        #[serde(skip_serializing_if = "Option::is_none")]
        pub subscription: Option<WebPushSubscription>,
    }

    /// Web Push subscription
    pub struct WebPushSubscription {
        pub endpoint: String,
        pub p256dh: String,
        pub auth: String,
    }

    /// # Edit Data
    pub struct DataEditSession {
        /// Session friendly name
        pub friendly_name: String,
    }

    pub struct SessionInfo {
        #[serde(rename = "_id")]
        pub id: String,
        pub name: String,
    }

    /// # Login Data
    #[serde(untagged)]
    pub enum DataLogin {
        Email {
            /// Email
            email: String,
            /// Password
            password: String,
            /// Friendly name used for the session
            friendly_name: Option<String>,
        },
        MFA {
            /// Unvalidated or authorised MFA ticket
            ///
            /// Used to resolve the correct account
            mfa_ticket: String,
            /// Valid MFA response
            ///
            /// This will take precedence over the `password` field where applicable
            mfa_response: Option<MFAResponse>,
            /// Friendly name used for the session
            friendly_name: Option<String>,
        },
    }

    #[serde(tag = "result")]
    pub enum ResponseLogin {
        Success(Session),
        MFA {
            ticket: String,
            allowed_methods: Vec<MFAMethod>,
        },
        Disabled {
            user_id: String,
            /// When the suspension lifts, if this is a timed suspension
            #[serde(skip_serializing_if = "Option::is_none")]
            suspended_until: Option<Timestamp>,
        },
    }

);

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
///
/// delta checks this when a subscription is stored and pushd checks it again
/// before every send, so one list governs both.
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