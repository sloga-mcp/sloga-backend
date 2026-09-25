use revolt_database::{Database, Session};
use revolt_models::v0;
use revolt_result::{create_database_error, create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

/// The allowlist lives in revolt-models so pushd re-checks the same list before
/// every send.
pub use revolt_models::v0::push_endpoint_allowed;

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
