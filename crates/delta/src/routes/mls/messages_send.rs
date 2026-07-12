use std::collections::HashMap;
use std::sync::Mutex;

use iso8601_timestamp::Timestamp;
use revolt_database::{
    events::client::EventV1, is_valid_device_id, Database, E2EEContentType, E2EEEnvelope,
    Session, User, E2EE_PROTOCOL_VERSION,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;
use ulid::Ulid;

use crate::routes::e2ee::{MAX_QUEUE_BYTES, MAX_QUEUE_DEPTH};

use super::{encoded_len, CTL_BURST, CTL_INTERVAL_SECONDS, MAX_MLS_CTL_RAW_SIZE};

/// In-memory per-(group, sender-user) ctl rate limiter (plan §3.4 fold
/// ME-5): a legitimate announce is ~once per interlude plus one re-announce
/// per epoch change, so a small burst budget suffices. A ctl flood must
/// never crowd commit envelopes out of the per-recipient mailbox budgets.
/// Process-local state is sufficient — delta is a single logical process
/// and the limit is an abuse bound, not an accounting guarantee.
static CTL_SENDS: Mutex<Option<HashMap<String, Vec<Timestamp>>>> = Mutex::new(None);

/// Returns `Err(InSlowmode)` when the (group, user) pair exceeded
/// `CTL_BURST` sends within the trailing `CTL_INTERVAL_SECONDS` window.
fn ctl_rate_limit(group_id: &str, user_id: &str) -> Result<()> {
    let now = Timestamp::now_utc();
    let key = format!("{group_id}:{user_id}");
    let mut guard = CTL_SENDS.lock().expect("ctl rate limiter poisoned");
    let map = guard.get_or_insert_with(HashMap::new);

    // Drop expired windows globally so the map cannot grow unbounded across
    // many groups/users (calls are ephemeral).
    map.retain(|_, sends| {
        sends.retain(|sent| {
            now.duration_since(*sent).whole_seconds() < CTL_INTERVAL_SECONDS
        });
        !sends.is_empty()
    });

    let sends = map.entry(key).or_default();
    if sends.len() >= CTL_BURST {
        let oldest = sends[0];
        let retry_after =
            CTL_INTERVAL_SECONDS - now.duration_since(oldest).whole_seconds();
        return Err(create_error!(InSlowmode {
            retry_after: retry_after.max(1) as u64
        }));
    }
    sends.push(now);
    Ok(())
}

/// # Send MLS Application Message
///
/// Relay an opaque MLS application message (the §3.4 downgrade
/// ctl-announce) to every member device of the group except the sender's.
/// The ciphertext is group-encrypted and group-authenticated — the trust
/// decision is each receiver's native verification of the sender leaf; the
/// server only enforces membership, size, and rate.
///
/// Never advances an epoch, never arbitrates: this is NOT the commits pipe.
/// Sender identity is stamped server-side from the session (invariant 5).
#[openapi(tag = "MLS")]
#[post("/groups/<group_id>/messages", data = "<data>")]
pub async fn send_message(
    db: &State<Database>,
    user: User,
    session: Session,
    group_id: String,
    data: Json<v0::DataSendMlsMessage>,
) -> Result<EmptyResponse> {
    super::require_media_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();

    if !is_valid_device_id(&data.device_id) {
        return Err(create_error!(FailedValidation {
            error: "device_id must be 128 bits of lowercase hex".to_string()
        }));
    }

    if data.ciphertext.is_empty() || data.ciphertext.len() > encoded_len(MAX_MLS_CTL_RAW_SIZE) {
        return Err(create_error!(FailedValidation {
            error: "ctl ciphertext empty or over size cap".to_string()
        }));
    }

    // The sending session must be bound to the registered device
    let identity = db
        .fetch_e2ee_identity(&user.id, &data.device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "sending device is not registered".to_string()
            })
        })?;
    identity.assert_bound_session(&session.id)?;

    // Group must exist, be open, its channel accessible — and the sending
    // DEVICE must be a member (user-level auth + device membership: only a
    // member can mint decryptable group ciphertext anyway; this check just
    // refuses obvious garbage early).
    let (group, _channel) = super::fetch_authorized_group(db, &user, &group_id).await?;
    if !group.open {
        return Err(create_error!(NotFound));
    }
    let is_member_device = group
        .members
        .iter()
        .any(|member| member.user_id == user.id && member.device_id == data.device_id);
    if !is_member_device {
        return Err(create_error!(FailedValidation {
            error: "sending device is not a member of this group".to_string()
        }));
    }

    ctl_rate_limit(&group.id, &user.id)?;

    // Fan out to every member device except the sender's, through the same
    // per-recipient mailbox budgets as commits (an over-budget recipient is
    // skipped — availability-only; a lost ctl converges via mix detection).
    let mut accepted: Vec<E2EEEnvelope> = Vec::new();
    for member in &group.members {
        if member.user_id == user.id && member.device_id == data.device_id {
            continue;
        }

        let depth = db
            .count_e2ee_envelopes(&member.user_id, &member.device_id)
            .await?;
        let bytes = db
            .sum_e2ee_envelope_bytes(&member.user_id, &member.device_id)
            .await?;
        if depth >= MAX_QUEUE_DEPTH
            || bytes + data.ciphertext.len() as u64 > MAX_QUEUE_BYTES
        {
            log::debug!(
                "mls ctl fan-out skipped for {}:{} (queue depth {depth}, bytes {bytes})",
                member.user_id,
                member.device_id
            );
            continue;
        }

        accepted.push(E2EEEnvelope {
            id: Ulid::new().to_string(),
            recipient_user_id: member.user_id.clone(),
            recipient_device_id: member.device_id.clone(),
            // Sender stamped from the session, never from the payload
            sender_user_id: user.id.clone(),
            sender_device_id: data.device_id.clone(),
            protocol_version: E2EE_PROTOCOL_VERSION,
            // Ctl messages carry no per-group ordering: sequence stays 0 and
            // epoch is None — receivers must never park on them
            sequence: 0,
            ciphertext: data.ciphertext.clone(),
            timestamp: Timestamp::now_utc(),
            content_type: E2EEContentType::MlsCtl,
            group_id: Some(group.id.clone()),
            epoch: None,
        });
    }

    // Queue first, then push live (clients dedup by envelope ULID)
    db.insert_e2ee_envelopes(&accepted).await?;
    for envelope in accepted {
        let recipient_user_id = envelope.recipient_user_id.clone();
        EventV1::MlsCtl(envelope.into())
            .private(recipient_user_id)
            .await;
    }

    Ok(EmptyResponse)
}
