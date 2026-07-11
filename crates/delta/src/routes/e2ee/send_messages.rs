use std::collections::{HashMap, HashSet};

use iso8601_timestamp::Timestamp;
use revolt_database::{
    events::client::EventV1, Database, E2EEEnvelope, Session, User, AMQP, E2EE_PROTOCOL_VERSION,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use ulid::Ulid;

use super::{MAX_CIPHERTEXT_LENGTH, MAX_ENVELOPES_PER_REQUEST, MAX_QUEUE_DEPTH};

/// # Send E2EE Messages
///
/// Submit encrypted envelopes for relay — one per recipient device (fan-out
/// includes the sender's other devices so all devices see sent messages).
///
/// The sender identity on every envelope is stamped server-side from the
/// authenticated session; the sending device must be one of the sender's
/// registered devices. Envelopes are queued until the recipient device
/// acknowledges delivery over the events connection, and swept by TTL for
/// dead devices.
///
/// Returns a per-envelope receipt: senders MUST tear down sessions to
/// devices reported as unknown (events alone cannot reach offline peers).
#[openapi(tag = "E2EE")]
#[post("/messages", data = "<data>")]
pub async fn send_messages(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    session: Session,
    data: Json<v0::DataSendE2EEMessages>,
) -> Result<Json<v0::ResponseSendE2EEMessages>> {
    super::require_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();

    if data.protocol_version != E2EE_PROTOCOL_VERSION {
        return Err(create_error!(FailedValidation {
            error: format!("unsupported protocol version (expected {E2EE_PROTOCOL_VERSION})")
        }));
    }

    if data.envelopes.is_empty() || data.envelopes.len() > MAX_ENVELOPES_PER_REQUEST {
        return Err(create_error!(FailedValidation {
            error: format!("between 1 and {MAX_ENVELOPES_PER_REQUEST} envelopes per request")
        }));
    }

    if data
        .envelopes
        .iter()
        .any(|envelope| envelope.ciphertext.is_empty() || envelope.ciphertext.len() > MAX_CIPHERTEXT_LENGTH)
    {
        return Err(create_error!(PayloadTooLarge));
    }

    // The sending device must be registered to the authenticated sender,
    // AND the calling session must be bound to that device (design §8:
    // web/stolen session tokens cannot act as an E2EE device)
    let sending_identity = db
        .fetch_e2ee_identity(&user.id, &data.device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "sending device is not registered".to_string()
            })
        })?;
    sending_identity.assert_bound_session(&session.id)?;

    // Every distinct recipient user must be DM-eligible (a blocked sender
    // can neither deliver envelopes nor probe device inventories); sending
    // to your own devices is always permitted
    let recipient_user_ids: HashSet<String> = data
        .envelopes
        .iter()
        .map(|envelope| envelope.recipient_user_id.clone())
        .filter(|id| id != &user.id)
        .collect();

    let mut recipient_users = HashMap::new();
    for recipient_id in &recipient_user_ids {
        let recipient = db.fetch_user(recipient_id).await?;

        // Friend-eligible OR shared-group co-member (slice 5). DELIVERY
        // allows blocked co-members (E2EE must not be weaker OR stronger
        // than plaintext group behaviour); bundle/device FETCH between
        // blocked pairs stays refused in fetch_keys/fetch_devices (§2.6).
        super::require_e2ee_deliver_eligible(db, &user, &recipient).await?;

        recipient_users.insert(recipient_id.clone(), recipient);
    }

    let mut receipts = vec![];
    let mut accepted = vec![];

    // Queue depths seeded from the database once per recipient device, then
    // tracked across the request — the cap must hold against envelopes
    // accepted earlier in this same request, not just already-queued ones
    let mut queue_depths: HashMap<(String, String), u64> = HashMap::new();

    for envelope in data.envelopes {
        // Unknown / revoked recipient device: report it so the sender tears
        // down the session (invariant: device changes are loud)
        if db
            .fetch_e2ee_identity(&envelope.recipient_user_id, &envelope.recipient_device_id)
            .await
            .is_err()
        {
            receipts.push(v0::E2EEDeliveryReceipt {
                recipient_user_id: envelope.recipient_user_id,
                recipient_device_id: envelope.recipient_device_id,
                status: v0::E2EEDeliveryStatus::UnknownDevice,
            });
            continue;
        }

        // Per-device queue-depth cap: a dead device fills its own queue
        // without affecting the user's live devices
        let depth_key = (
            envelope.recipient_user_id.clone(),
            envelope.recipient_device_id.clone(),
        );

        if !queue_depths.contains_key(&depth_key) {
            let stored = db
                .count_e2ee_envelopes(&envelope.recipient_user_id, &envelope.recipient_device_id)
                .await?;
            queue_depths.insert(depth_key.clone(), stored);
        }

        let depth = queue_depths
            .get_mut(&depth_key)
            .expect("seeded immediately above");

        if *depth >= MAX_QUEUE_DEPTH {
            receipts.push(v0::E2EEDeliveryReceipt {
                recipient_user_id: envelope.recipient_user_id,
                recipient_device_id: envelope.recipient_device_id,
                status: v0::E2EEDeliveryStatus::QueueFull,
            });
            continue;
        }

        *depth += 1;

        let queued = E2EEEnvelope {
            id: Ulid::new().to_string(),
            recipient_user_id: envelope.recipient_user_id.clone(),
            recipient_device_id: envelope.recipient_device_id.clone(),
            // Sender stamped from the session, never from the payload
            sender_user_id: user.id.clone(),
            sender_device_id: data.device_id.clone(),
            protocol_version: data.protocol_version,
            sequence: envelope.sequence,
            ciphertext: envelope.ciphertext,
            timestamp: Timestamp::now_utc(),
            // Client envelope submission is olm-only: MLS envelope types are
            // minted exclusively by the /mls commit fan-out (server-side)
            content_type: revolt_database::E2EEContentType::Olm,
            group_id: None,
            epoch: None,
        };

        receipts.push(v0::E2EEDeliveryReceipt {
            recipient_user_id: envelope.recipient_user_id,
            recipient_device_id: envelope.recipient_device_id,
            status: v0::E2EEDeliveryStatus::Queued {
                id: queued.id.clone(),
            },
        });

        accepted.push(queued);
    }

    // Queue first, then push live: an envelope is never push-only. Clients
    // dedup the drain-vs-live-push race by envelope id.
    db.insert_e2ee_envelopes(&accepted).await?;

    let mut notified = HashSet::new();
    for envelope in accepted {
        let recipient_user_id = envelope.recipient_user_id.clone();

        EventV1::E2EEMessage(envelope.into())
            .private(recipient_user_id.clone())
            .await;

        // Push notification with no preview — "New message" only. Offline
        // recipients only; own devices are not notified about own sends.
        if recipient_user_id != user.id
            && notified.insert(recipient_user_id.clone())
            && !revolt_presence::is_online(&recipient_user_id).await
        {
            if let Some(recipient) = recipient_users.get(&recipient_user_id) {
                amqp.generic_message(
                    recipient,
                    "Acutest".to_string(),
                    "New message".to_string(),
                    None,
                )
                .await
                .ok();
            }
        }
    }

    Ok(Json(v0::ResponseSendE2EEMessages { receipts }))
}
