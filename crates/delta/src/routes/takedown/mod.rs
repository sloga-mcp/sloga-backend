//! Public Take It Down routes: the request form, the status page and adding
//! information later. Sessionless; the status token is the only credential.
//!
//! Nothing here logs a request body or puts requester data in an error: the
//! bodies are read through `QuietJson`, and every parse or validation failure
//! answers with the same fixed error.

use std::collections::HashMap;

use iso8601_timestamp::{Duration, Timestamp};
use revolt_config::FeaturesTakedown;
use revolt_database::{
    util::{
        email::{email_templates, send_email_safe},
        takedown_crypto::{
            contact_fingerprint, hash_status_token, id_from_reference, new_status_token,
            reference_for, seal_requester,
        },
    },
    Database, SealedRequester, StaffAuditAction, StaffAuditEntry, TakedownRequest, TakedownRole,
    TakedownSource, TakedownStatus, TakedownTarget,
};
use revolt_models::v0;
use revolt_result::{create_error, Error, Result};
use revolt_rocket_okapi::{
    gen::OpenApiGenerator, request::OpenApiFromData, revolt_okapi::openapi3::OpenApi,
    revolt_okapi::openapi3::RequestBody,
};
use rocket::{
    data::{Data, FromData, Outcome, ToByteUnit},
    serde::json::Json,
    Request, Route,
};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use subtle::ConstantTimeEq;
use ulid::Ulid;

mod add_info;
mod config;
mod status;
mod submit;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        config::takedown_config,
        submit::submit_request,
        status::request_status,
        add_info::add_info,
    ]
}

/// Marker claimed by whoever sends the "request received" email
pub(crate) const MARKER_EMAIL_RECEIVED: &str = "email:received";

/// Hours from receipt to the removal deadline
const DEADLINE_HOURS: i64 = 48;

/// Most locations one request may hold, including ones added later
pub(crate) const MAX_LOCATIONS: usize = 20;

/// The one answer for a takedown body that does not parse or validate. Fixed
/// text: parser and validator messages can quote the submitted values.
pub(crate) fn invalid_takedown_body() -> Error {
    create_error!(FailedValidation {
        error: "invalid request body".to_string()
    })
}

/// The feature switch as the public routes see it
pub(crate) fn takedown_disabled() -> Error {
    create_error!(FeatureDisabled {
        feature: "takedown".to_string()
    })
}

/// A JSON body that never reaches a log.
///
/// Rocket's `Json` guard logs a failed parse with the raw body (the error
/// carries it), which would put requester details in the server log. This
/// guard always succeeds and hands the route `Err(invalid_takedown_body())`
/// instead, with nothing of the body in it.
pub struct QuietJson<T>(pub Result<T>);

impl<T> QuietJson<T> {
    pub fn into_inner(self) -> Result<T> {
        self.0
    }
}

#[rocket::async_trait]
impl<'r, T: DeserializeOwned> FromData<'r> for QuietJson<T> {
    type Error = std::convert::Infallible;

    async fn from_data(request: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self> {
        let limit = request
            .limits()
            .get("json")
            .unwrap_or_else(|| 1.mebibytes());
        let parsed = match data.open(limit).into_string().await {
            Ok(body) if body.is_complete() => {
                serde_json::from_str::<T>(&body).map_err(|_| invalid_takedown_body())
            }
            _ => Err(invalid_takedown_body()),
        };

        Outcome::Success(QuietJson(parsed))
    }
}

impl<'r, T: JsonSchema + DeserializeOwned> OpenApiFromData<'r> for QuietJson<T> {
    fn request_body(gen: &mut OpenApiGenerator) -> revolt_rocket_okapi::Result<RequestBody> {
        // Documented exactly as the `Json` body it replaces
        <Json<T> as OpenApiFromData<'r>>::request_body(gen)
    }
}

/// The stored role for a submitted one
pub(crate) fn stored_role(role: v0::TakedownRole) -> TakedownRole {
    match role {
        v0::TakedownRole::Depicted => TakedownRole::Depicted,
        v0::TakedownRole::Authorized => TakedownRole::Authorized,
    }
}

/// Whether `token` opens `request`. Constant-time on the hashes; a purged
/// request opens for nobody.
pub(crate) fn token_matches(request: &TakedownRequest, token: &str) -> bool {
    let presented = hash_status_token(token);
    let equal: bool = presented
        .as_bytes()
        .ct_eq(request.status_token_hash.as_bytes())
        .into();
    equal && !request.requester_purged
}

/// The request a reference and token open, or `NotFound` for an unknown
/// reference, a wrong token and a purged request alike
pub(crate) async fn fetch_by_reference(
    db: &Database,
    reference: &str,
    token: &str,
) -> Result<TakedownRequest> {
    let Some(id) = id_from_reference(reference) else {
        // Hash anyway so an unknown reference costs what a known one does
        let _ = hash_status_token(token);
        return Err(create_error!(NotFound));
    };

    let request = match db.fetch_takedown_request(&id).await {
        Ok(request) => request,
        Err(_) => {
            let _ = hash_status_token(token);
            return Err(create_error!(NotFound));
        }
    };

    if token_matches(&request, token) {
        Ok(request)
    } else {
        Err(create_error!(NotFound))
    }
}

/// What a new request is made of, before it is sealed
pub(crate) struct NewTakedown {
    pub source: TakedownSource,
    pub requester: SealedRequester,
    pub locations: Vec<String>,
    pub targets: Vec<TakedownTarget>,
    pub resolved: bool,
    pub minor_claimed: bool,
}

/// A sealed request ready to insert, with what the received email needs
pub(crate) struct PreparedTakedown {
    pub request: TakedownRequest,
    pub token: String,
    pub email: String,
    /// The contact address is over its daily soft limit: the request is
    /// stored, but no received email goes out, so the form cannot be used
    /// to send one address unlimited mail
    pub over_daily_limit: bool,
}

/// Seal a new request and work out whether it is throttled. Reads only the
/// earlier requests from the same contact address; never the targets.
pub(crate) async fn prepare_request(
    db: &Database,
    settings: &FeaturesTakedown,
    new: NewTakedown,
) -> Result<PreparedTakedown> {
    let NewTakedown {
        source,
        requester,
        locations,
        targets,
        resolved,
        minor_claimed,
    } = new;

    let key = settings.data_key.as_str();
    let email = requester.email.trim().to_string();
    let contact_fp = contact_fingerprint(key, &email);

    let plaintext = serde_json::to_vec(&requester).map_err(|_| create_error!(InternalError))?;
    let sealed = seal_requester(key, &plaintext)?;

    let now = Timestamp::now_utc();
    let deadline_at = now
        .checked_add(Duration::hours(DEADLINE_HOURS))
        .ok_or_else(|| create_error!(InternalError))?;
    let day_ago = now
        .checked_sub(Duration::hours(24))
        .ok_or_else(|| create_error!(InternalError))?;

    // Over the per-address soft limit, or from an address with a bad-faith
    // decline on record: still stored, but queued behind the rest. Never
    // refused. Only the daily limit also stops the received email.
    let earlier = db
        .fetch_takedown_requests_by_contact_since(&contact_fp, Timestamp::UNIX_EPOCH)
        .await?;
    let recent = earlier
        .iter()
        .filter(|request| request.received_at >= day_ago)
        .count() as u64;
    let over_daily_limit = recent >= settings.per_address_daily_soft_limit;
    let throttled = over_daily_limit || earlier.iter().any(|request| request.bad_faith);

    let token = new_status_token();

    let request = TakedownRequest {
        id: Ulid::new().to_string(),
        status: TakedownStatus::Received,
        source,
        received_at: now,
        deadline_at,
        sealed,
        contact_fp,
        status_token_hash: hash_status_token(&token),
        locations,
        minor_claimed,
        resolved,
        targets,
        linked_request_ids: vec![],
        held_files: vec![],
        auto_hidden_file_ids: vec![],
        hold_until: None,
        child_safety: false,
        bad_faith: false,
        throttled,
        decline_reason: None,
        first_opened_at: None,
        removed_at: None,
        closed_at: None,
        requester_purged: false,
        reviewer_note: None,
        revision: 0,
        markers: vec![],
    };

    Ok(PreparedTakedown {
        request,
        token,
        email,
        over_daily_limit,
    })
}

/// Audit note for a request whose received email was withheld because its
/// contact address is over the daily soft limit
pub(crate) const NOTE_RECEIVED_SUPPRESSED: &str = "received_suppressed";

/// Store a prepared request, then (detached, after the caller has answered)
/// audit it and send the received email with the status link. Returns the
/// public reference.
///
/// Over the daily soft limit the email is not sent (no marker is claimed)
/// and the audit note is `received_suppressed`; the answer is the same.
///
/// `note` is a fixed code for the audit entry; `target_ids` are object ids
/// only.
pub(crate) async fn insert_and_notify(
    db: &Database,
    prepared: PreparedTakedown,
    note: &'static str,
    target_ids: Vec<String>,
) -> Result<String> {
    let PreparedTakedown {
        request,
        token,
        email,
        over_daily_limit,
    } = prepared;

    db.insert_takedown_request(&request).await?;

    let reference = reference_for(&request.id);
    let db = db.clone();
    let id = request.id;
    let throttled = request.throttled;
    tokio::spawn(async move {
        let note = if over_daily_limit {
            NOTE_RECEIVED_SUPPRESSED
        } else if throttled && note == "web" {
            "web_throttled"
        } else {
            note
        };
        StaffAuditEntry::record(
            &db,
            None,
            StaffAuditAction::TakedownSubmitted,
            Some(&id),
            target_ids,
            None,
            Some(note),
        )
        .await;

        if !over_daily_limit {
            send_received_email(&db, &id, &email, &token).await;
        }
    });

    Ok(reference)
}

/// Claim `email:received` and send the received email. Failures are logged
/// by reference only; the address and token never reach a log.
async fn send_received_email(db: &Database, id: &str, email: &str, token: &str) {
    let reference = reference_for(id);

    match db.claim_takedown_marker(id, MARKER_EMAIL_RECEIVED).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(_) => {
            log::error!("Take It Down {reference}: could not claim the received-email marker");
            return;
        }
    }

    let templates = email_templates().await;
    let url = format!(
        "{}#{}.{}",
        templates.takedown_received.url, reference, token
    );

    let mut variables = HashMap::new();
    variables.insert("reference", reference.clone());
    variables.insert("url", url);

    // With no SMTP host `send_email_safe` sends nothing and still answers
    // Ok; the audit must not claim an email went out
    if revolt_config::config().await.api.smtp.host.is_empty() {
        log::warn!("Take It Down {reference}: no SMTP host, the received email was not sent");
        return;
    }

    match send_email_safe(email, &templates.takedown_received, variables).await {
        Ok(()) => {
            StaffAuditEntry::record(
                db,
                None,
                StaffAuditAction::TakedownEmailSent,
                Some(id),
                vec![],
                None,
                Some("received"),
            )
            .await;
        }
        Err(_) => {
            log::error!("Take It Down {reference}: the received email was not sent");
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared by the takedown route tests and the report route's tests

    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        util::takedown_crypto::{hash_status_token, open_requester},
        Database, SealedRequester, TakedownRequest, TakedownSource, TakedownStatus,
    };

    /// 64 hex characters; only ever used by tests
    pub const TEST_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// Turn the feature on for this test process (once per process: nextest)
    pub async fn enable_takedown() {
        revolt_config::overwrite_config(|settings| {
            settings.features.takedown.enabled = true;
            settings.features.takedown.data_key = TEST_KEY.to_string();
            settings.features.takedown.per_address_daily_soft_limit = 5;
            settings.api.security.captcha.hcaptcha_key = String::new();
        })
        .await;
    }

    pub fn open(request: &TakedownRequest) -> SealedRequester {
        serde_json::from_slice(&open_requester(TEST_KEY, &request.sealed).expect("opens"))
            .expect("requester json")
    }

    /// Requests received in the last hour, newest first
    pub async fn recent(db: &Database) -> Vec<TakedownRequest> {
        db.fetch_recent_takedown_requests(
            Timestamp::now_utc()
                .checked_sub(Duration::hours(1))
                .expect("an hour ago"),
        )
        .await
        .expect("recent requests")
    }

    /// Store a sealed web request whose status token is `token`
    pub async fn insert_request(
        db: &Database,
        token: &str,
        status: TakedownStatus,
        locations: Vec<String>,
    ) -> TakedownRequest {
        let requester = SealedRequester {
            role: revolt_database::TakedownRole::Depicted,
            authority_note: None,
            name: "Test Person".to_string(),
            signature: "Test Person".to_string(),
            email: "test-person@example.com".to_string(),
            description: "test description".to_string(),
            extra: None,
            added_info: vec![],
        };
        let now = Timestamp::now_utc();
        let request = TakedownRequest {
            id: ulid::Ulid::new().to_string(),
            status,
            source: TakedownSource::Web,
            received_at: now,
            deadline_at: now.checked_add(Duration::hours(48)).expect("deadline"),
            sealed: revolt_database::util::takedown_crypto::seal_requester(
                TEST_KEY,
                &serde_json::to_vec(&requester).expect("json"),
            )
            .expect("seals"),
            contact_fp: revolt_database::util::takedown_crypto::contact_fingerprint(
                TEST_KEY,
                &requester.email,
            ),
            status_token_hash: hash_status_token(token),
            locations,
            minor_claimed: false,
            resolved: true,
            targets: vec![],
            linked_request_ids: vec![],
            held_files: vec![],
            auto_hidden_file_ids: vec![],
            hold_until: None,
            child_safety: false,
            bad_faith: false,
            throttled: false,
            decline_reason: None,
            first_opened_at: None,
            removed_at: None,
            closed_at: None,
            requester_purged: false,
            reviewer_note: None,
            revision: 0,
            markers: vec![],
        };
        db.insert_takedown_request(&request)
            .await
            .expect("insert request");
        request
    }

    /// Poll until the detached task has written the request's
    /// `TakedownSubmitted` entry, and return it
    pub async fn wait_for_submitted_audit(
        db: &Database,
        id: &str,
    ) -> revolt_database::StaffAuditEntry {
        for _ in 0..100 {
            let entry = db
                .fetch_staff_audit_for_request(id)
                .await
                .expect("audit")
                .into_iter()
                .find(|entry| {
                    matches!(
                        entry.action,
                        revolt_database::StaffAuditAction::TakedownSubmitted
                    )
                });
            if let Some(entry) = entry {
                return entry;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("the submitted audit entry was never written");
    }

    /// Poll until the detached task has claimed the received-email marker
    pub async fn wait_for_received_marker(db: &Database, id: &str) {
        for _ in 0..100 {
            let request = db.fetch_takedown_request(id).await.expect("request");
            if request
                .markers
                .iter()
                .any(|marker| marker == super::MARKER_EMAIL_RECEIVED)
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("the received-email marker was never claimed");
    }
}
