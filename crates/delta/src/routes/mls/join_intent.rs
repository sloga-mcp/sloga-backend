use std::collections::HashSet;

use iso8601_timestamp::Timestamp;
use revolt_database::{
    events::client::EventV1, is_valid_device_id, is_valid_key_package_ref,
    mls_join_intent_payload, Database, MlsJoinIntent, Session, User, MAX_MLS_GROUP_MEMBERS,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

use crate::routes::e2ee::MAX_SIGNATURE_LENGTH;

use super::MIN_JOIN_INTENT_INTERVAL_SECONDS;

/// # Signal MLS Join Intent
///
/// Store a signed join intent for a call group and fan out
/// `MlsJoinRequested` to member devices (plan §1.4 step 1).
///
/// The signature — Ed25519 by the device identity key over the canonical
/// `acutest:e2ee:mls-join:v1` payload — is verified server-side as defense
/// in depth; the REAL trust decision is each admitting member's client-side
/// re-verification against its own pinned identity for this device. The
/// server can never grow a roster: an Add is only ever issued by a member
/// that verified this intent itself.
#[openapi(tag = "MLS")]
#[post("/groups/<group_id>/join_intent", data = "<data>")]
pub async fn join_intent(
    db: &State<Database>,
    user: User,
    session: Session,
    group_id: String,
    data: Json<v0::DataMlsJoinIntent>,
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

    if !is_valid_key_package_ref(&data.key_package_ref) {
        return Err(create_error!(FailedValidation {
            error: "invalid key package reference".to_string()
        }));
    }

    if data.signature.len() > MAX_SIGNATURE_LENGTH {
        return Err(create_error!(FailedValidation {
            error: "invalid signature encoding".to_string()
        }));
    }

    // The joining session must be bound to the registered device
    let identity = db
        .fetch_e2ee_identity(&user.id, &data.device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "joining device is not registered".to_string()
            })
        })?;
    identity.assert_bound_session(&session.id)?;

    // Group must exist, be open, and its channel accessible to the joiner.
    // (fetch_authorized_group validates group_id shape implicitly — an
    // unknown id is NotFound either way.)
    let (group, _channel) = super::fetch_authorized_group(db, &user, &group_id).await?;
    if !group.open {
        return Err(create_error!(NotFound));
    }

    // Defense-in-depth signature verification (clients re-verify — that is
    // the real check; plan §2.3). Runs BEFORE the membership branch so the
    // rejoin and solo-close arms below are only reachable by the
    // authenticated signing device (rejoin plan AUD-LOW-1).
    let payload = mls_join_intent_payload(&user.id, &data.device_id, &group.id, &data.key_package_ref);
    if !identity.verify_payload(&payload, &data.signature) {
        return Err(create_error!(FailedValidation {
            error: "invalid join intent signature".to_string()
        }));
    }

    // One device per user per call (plan §1.5), enforced at the DS — two
    // native layers on two devices share no state; only the DS sees both.
    // SAME device already a member = a REJOIN: the device wiped its local
    // group state (rejoin-fresh) but its stale leaf is still in the roster,
    // and it can never remove itself (RFC 9420 forbids self-removal). Fan
    // the intent out flagged `rejoin` so verifying members remove the stale
    // leaf; the device's next normal intent then rides the unchanged
    // admit path (rejoin-affordance plan §3.1).
    let mut rejoin = false;
    if let Some(existing) = group.member_device_of(&user.id) {
        if existing.device_id != data.device_id {
            return Err(create_error!(FailedValidation {
                error: "another device of this user is already in the call group".to_string()
            }));
        }
        if group.members.len() == 1 {
            // The sole member IS the stale self: no other leaf-holder exists
            // to serve the rejoin, and the sole member's group secrets are
            // wiped by definition — the group is unrecoverable. Close it so
            // the device's next establish takes the CREATE path.
            db.close_mls_group(&group.id).await?;
            return Ok(EmptyResponse);
        }
        rejoin = true;
    }

    // Roster ceiling for NEW members only (plan A3, 6.5 fold ME-3): the
    // call stays E2EE and the overflow joiner is refused loudly BEFORE
    // burning the claim/admit round-trip. Rejoins are exempt — a stale-leaf
    // member's own leaf occupies a slot and blocking its recovery would
    // permanently lock it out of a full call. The commit-CAS ceiling
    // (`create_mls_commit`, both drivers) remains the hard guarantee.
    if !rejoin && group.members.len() >= MAX_MLS_GROUP_MEMBERS {
        return Err(create_error!(MlsCallFull {
            max: MAX_MLS_GROUP_MEMBERS
        }));
    }

    let intent = MlsJoinIntent {
        id: MlsJoinIntent::composite_id(&group.id, &user.id, &data.device_id),
        group_id: group.id.clone(),
        user_id: user.id.clone(),
        device_id: data.device_id.clone(),
        key_package_ref: data.key_package_ref.clone(),
        signature: data.signature.clone(),
        created_at: Timestamp::now_utc(),
    };

    // Rate limit per (group, user, device): the joiner-side retry runs at
    // 10 s (plan §1.4), so a shorter re-broadcast is never legitimate
    if let Some(previous) = db.upsert_mls_join_intent(&intent).await? {
        let elapsed = intent
            .created_at
            .duration_since(previous.created_at)
            .whole_seconds();
        if elapsed < MIN_JOIN_INTENT_INTERVAL_SECONDS {
            return Err(create_error!(InSlowmode {
                retry_after: (MIN_JOIN_INTENT_INTERVAL_SECONDS - elapsed).max(1) as u64
            }));
        }
    }

    // Fan out to each member USER's private topic; member devices filter
    // and self-schedule admission with leaf-index staggered timers
    let member_users: HashSet<String> = group
        .members
        .iter()
        .map(|member| member.user_id.clone())
        .collect();

    for member_user in member_users {
        EventV1::MlsJoinRequested {
            group_id: group.id.clone(),
            channel_id: group.channel_id.clone(),
            user_id: user.id.clone(),
            device_id: data.device_id.clone(),
            key_package_ref: data.key_package_ref.clone(),
            signature: data.signature.clone(),
            rejoin,
        }
        .private(member_user)
        .await;
    }

    Ok(EmptyResponse)
}
