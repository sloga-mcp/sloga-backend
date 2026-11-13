use std::collections::HashSet;

use iso8601_timestamp::Timestamp;
use revolt_database::{
    events::client::EventV1, is_valid_device_id, is_valid_key_package_ref, mls_join_intent_payload,
    mls_text_enforced_device_cap, ChannelEntitlement, Database, E2EEIdentity, MlsGroup,
    MlsJoinIntent, MlsMemberDevice, SeatList, SeatListBody, Session, TextJoinPayload, User,
    MAX_MLS_GROUP_MEMBERS,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

use crate::routes::e2ee::MAX_SIGNATURE_LENGTH;

use super::{
    GroupDispatch, TextGate, MIN_JOIN_INTENT_INTERVAL_SECONDS, REJOIN_OUTSTANDING_WINDOW_SECONDS,
};

/// Whether EVERY member device of the group holds an outstanding join
/// intent — i.e. every member is itself mid-rejoin, so no member is left
/// who could serve anyone (the dual-reload deadlock, rejoin plan §5).
/// "Outstanding" = (re)broadcast within [`REJOIN_OUTSTANDING_WINDOW_SECONDS`]
/// of `now`; `created_at` is upserted on every re-broadcast, so an actively
/// rejoining device always qualifies and an abandoned row ages out.
pub(crate) fn all_member_devices_rejoining(
    members: &[MlsMemberDevice],
    intents: &[MlsJoinIntent],
    now: Timestamp,
) -> bool {
    members.iter().all(|member| {
        intents.iter().any(|intent| {
            intent.user_id == member.user_id
                && intent.device_id == member.device_id
                && now.duration_since(intent.created_at).whole_seconds()
                    <= REJOIN_OUTSTANDING_WINDOW_SECONDS
        })
    })
}

/// # Signal MLS Join Intent
///
/// Store a signed join intent for a call group and fan out
/// `MlsJoinRequested` to member devices (plan §1.4 step 1).
///
/// The signature — Ed25519 by the device identity key over the canonical
/// `acutest:e2ee:mls-join:v1` payload (on a protected channel whose list is
/// v2, the Text join payload, design §3.13) — is verified server-side as
/// defense in depth; the REAL trust decision is each admitting member's
/// client-side re-verification against its own pinned identity for this
/// device. The server can never grow a roster: an Add is only ever issued
/// by a member that verified this intent itself.
///
/// A protected channel's Text group takes its own path (protected channels
/// design §6.1 "Join intent"): the caller must be seated, a user may join
/// with several devices up to the enforced device cap, recovery intents
/// pass with the growth flag off, and the route never closes the group.
#[openapi(tag = "MLS")]
#[post("/groups/<group_id>/join_intent", data = "<data>")]
pub async fn join_intent(
    db: &State<Database>,
    user: User,
    session: Session,
    group_id: String,
    data: Json<v0::DataMlsJoinIntent>,
) -> Result<EmptyResponse> {
    // Kind dispatch on the stored group, first (decision 1 (W2)). No request
    // validation runs before a branch: an unknown id answers exactly what a
    // hidden Text group answers, and a Call group keeps its own order.
    match super::dispatch_group(db, &group_id).await? {
        GroupDispatch::CallOrUnknown(None) => {
            super::as_unknown_group(db, &user, Some(&session)).await
        }
        GroupDispatch::CallOrUnknown(Some(_)) => {
            call_join_intent(db, user, session, group_id, data.into_inner()).await
        }
        GroupDispatch::Text(group) => {
            text_join_intent(db, &user, &session, group, data.into_inner()).await
        }
    }
}

/// The call path, unchanged by protected channels
async fn call_join_intent(
    db: &Database,
    user: User,
    session: Session,
    group_id: String,
    data: v0::DataMlsJoinIntent,
) -> Result<EmptyResponse> {
    super::require_media_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    validate_join_intent(&data)?;

    // The joining session must be bound to the registered device
    let identity = bound_identity(db, &user.id, &session, &data.device_id).await?;

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
    verify_join_signature(&identity, &user.id, &group.id, &data)?;

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

    let intent = join_intent_row(&group, &user.id, &data, None, None);
    store_join_intent(db, &intent).await?;

    // Dual-reload deadlock (rejoin plan §5): a rejoin is only ever served
    // by a member that still HOLDS the group — but if every member device
    // is itself mid-rejoin (each wiped its local state), nobody is left to
    // serve anyone and the group is unrecoverable. Generalize the
    // solo-close above: close the group so each device's next establish
    // takes the CREATE path. Checked after the upsert (this device's own
    // fresh intent must count) and after slowmode (a replay cannot probe
    // faster than a legitimate re-broadcast).
    if rejoin {
        let intents = db.fetch_mls_join_intents_for_group(&group.id).await?;
        if all_member_devices_rejoining(&group.members, &intents, intent.created_at) {
            db.close_mls_group(&group.id).await?;
            return Ok(EmptyResponse);
        }
    }

    fan_out_join_requested(&group, &intent, rejoin).await;

    Ok(EmptyResponse)
}

/// The Text path (protected channels design §6.1), in decision 1 (W2)
/// order: the group's channel and ViewChannel, where any failure answers
/// [`super::as_unknown_group`] so a hidden or deleted channel's group is
/// indistinguishable from an unknown id; the shared caller checks; request
/// validation; the recovery or growth gate; the caller's seat; then the
/// join rules.
///
/// The gate follows the operation, never a client flag (§6.3 "Recovery
/// gates", S2-D32, #213, #220). A rejoin (this device is already a member)
/// and the signer user's replacement device while recovery is open
/// ([`signer_replacement`]) are RECOVERY: the available gate and an
/// entitlement that allows text traffic ([`allows_text_traffic`]), so they
/// pass with the growth flag off. Any other new device is growth: the
/// growth gate, and the same entitlement predicate at the cap check.
///
/// On a channel whose stored list is v2 the intent is signed over the Text
/// join payload and its `generation` and `issued_at` are stored and fanned
/// out (§3.13, #218); a v1 channel keeps the S1 payload and S1 rows.
///
/// A Text intent stays outstanding for `text_rejoin_window_secs` (24 h),
/// measured from the row's server-stamped `created_at` by the driver's rule
/// 6 and the routes that read intents; the signed `issued_at` is only
/// bounds-checked (§3.13). The 30 s window of
/// [`all_member_devices_rejoining`] is the Call plane's alone.
///
/// Two call rules do not apply. A user may hold several member devices, up
/// to the enforced device cap. And this route never closes the group (§2.5
/// "Close paths touch Call groups only"): when every member has wiped its
/// state, the owner's device creates a successor instead (§6.3).
async fn text_join_intent(
    db: &Database,
    user: &User,
    session: &Session,
    group: MlsGroup,
    data: v0::DataMlsJoinIntent,
) -> Result<EmptyResponse> {
    let Ok(channel) = db.fetch_channel(&group.channel_id).await else {
        return super::as_unknown_group(db, user, Some(session)).await;
    };
    if super::require_channel_access(db, user, &channel)
        .await
        .is_err()
    {
        return super::as_unknown_group(db, user, Some(session)).await;
    }
    super::require_mls_caller(db, user, Some(session)).await?;
    validate_join_intent(&data)?;

    // Device-aware: THIS device already a member is a rejoin (members
    // remove its stale leaf under the rejoin case, §3.12.2, and re-Add it).
    // Any other device is a NEW device of a user who may already have some
    let rejoin = group.has_member(&user.id, &data.device_id);
    let seat_list = db.fetch_seat_list(&group.channel_id).await?;
    let recovery = rejoin || signer_replacement(db, &group, seat_list.as_ref(), &user.id).await?;
    let gate = if recovery {
        TextGate::Available
    } else {
        TextGate::Growth
    };
    super::require_text_gate(gate).await?;
    super::require_seated(db, &group.channel_id, &user.id).await?;

    // A superseded group takes no joins; its successor does
    if !group.open {
        return Err(create_error!(NotFound));
    }

    // The session must be bound to the joining device itself, and the
    // intent signed by it, before anything below is reachable. The payload
    // depends on the stored list's format, so a Text group without one
    // takes no intent at all
    let identity = bound_identity(db, &user.id, session, &data.device_id).await?;
    let seat_list = seat_list.ok_or_else(|| create_error!(InvalidOperation))?;
    let (generation, issued_at) =
        verify_text_join_signature(&identity, &user.id, &group, &seat_list, &data)?;

    // A rejoin is exempt from the cap (it is not new), but it is recovery,
    // which still needs an entitlement that allows text traffic. A new
    // device is refused once the user's counted member devices reach the
    // enforced cap. The Text commit transaction enforces the cap again on
    // the Add, counting every post-commit leaf; this refusal only spares
    // the admit round trip and tells the joiner why.
    if rejoin {
        require_text_traffic(db, &group.channel_id).await?;
    } else {
        let max = enforced_device_cap(db, &group.channel_id).await?;
        if max != 0 && capped_device_count(&group, &user.id) >= max as usize {
            return Err(create_error!(DeviceCapReached { max: max as usize }));
        }
    }

    let intent = join_intent_row(&group, &user.id, &data, generation, issued_at);
    store_join_intent(db, &intent).await?;

    fan_out_join_requested(&group, &intent, rejoin).await;

    Ok(EmptyResponse)
}

/// Whether a NEW device of `user_id` is the signer user's replacement
/// device while recovery is open (§6.1 "S2 additions", widened in #213):
/// `user_id` is the stored list's signer user, and the open group carries
/// `signer_lost` OR the list's signer device has no registered E2EE
/// identity. The second is the server's own directory, so recovery never
/// depends on `signer_lost` having been written. A read error other than
/// an absent identity is returned, so it refuses (fails closed).
async fn signer_replacement(
    db: &Database,
    group: &MlsGroup,
    seat_list: Option<&SeatList>,
    user_id: &str,
) -> Result<bool> {
    let Some(seat_list) = seat_list else {
        return Ok(false);
    };
    if seat_list.signer_user_id != user_id {
        return Ok(false);
    }
    if group.signer_lost.is_some() {
        return Ok(true);
    }

    match db
        .fetch_e2ee_identity(&seat_list.signer_user_id, &seat_list.signer_device_id)
        .await
    {
        Ok(_) => Ok(false),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => Ok(true),
        Err(error) => Err(error),
    }
}

/// The entitlement predicate every Text join needs, a new device and a
/// recovery intent alike (design §6.3 "Recovery gates", #220): S5's
/// `allows_text_traffic()`, which before S5 lands is `Active` only. S5b's
/// `ChannelEntitlement::allows_text_traffic` (`Active` or `Grace`, S2-D32
/// amended) replaces this at its merge.
fn allows_text_traffic(entitlement: &ChannelEntitlement) -> bool {
    entitlement.is_active()
}

/// The entitlement half of the recovery gate for a rejoin (§6.3 "Recovery
/// gates"): a missing entitlement, or one that does not allow text
/// traffic, refuses it with `InvalidOperation`, as it refuses a new device
async fn require_text_traffic(db: &Database, channel_id: &str) -> Result<()> {
    db.fetch_channel_entitlement(channel_id)
        .await?
        .filter(allows_text_traffic)
        .ok_or_else(|| create_error!(InvalidOperation))?;

    Ok(())
}

/// The user's member devices that count against the enforced cap at the
/// join intent (§6.1 "S2 additions", #212): every member device of the
/// user, a revoked device whose leaf is still there and a lost signer
/// device included, EXCEPT one listed in `pending_device_removals`. The Add
/// that follows must remove those in the same commit (Add-clears-pending),
/// so they never coexist with the new device. That is the only exclusion:
/// the commit transaction counts every post-commit leaf, as every receiver
/// does.
fn capped_device_count(group: &MlsGroup, user_id: &str) -> usize {
    group
        .member_devices_of(user_id)
        .filter(|device| {
            !group.pending_device_removals.iter().any(|pending| {
                pending.user_id == device.user_id && pending.device_id == device.device_id
            })
        })
        .count()
}

/// The enforced per-user device cap of a channel's Text group (§2.5,
/// W0-fix3): `min(signed-list device_cap, effective entitlement cap)`, `0`
/// meaning unlimited in either operand, so `0` here is unlimited too.
///
/// A new device is an Add to come, and an Add of a seated member's new
/// device needs an entitlement that allows text traffic
/// ([`allows_text_traffic`]; §6.1 errors, §6.3 "Recovery gates"), so a
/// missing or inactive one refuses the new device here rather than at the
/// admitter's commit. The signer user's replacement device meets the same
/// check under the recovery gate.
async fn enforced_device_cap(db: &Database, channel_id: &str) -> Result<u32> {
    let entitlement = db
        .fetch_channel_entitlement(channel_id)
        .await?
        .filter(allows_text_traffic)
        .ok_or_else(|| create_error!(InvalidOperation))?;
    let seat_list = db
        .fetch_seat_list(channel_id)
        .await?
        .ok_or_else(|| create_error!(InvalidOperation))?;
    let signed = SeatListBody::parse(&seat_list.body)?;
    let config = revolt_config::config().await;

    Ok(mls_text_enforced_device_cap(
        signed.device_cap,
        super::effective_device_cap(&entitlement, &config.features.protected_channels),
    ))
}

/// Shape checks on the request body
fn validate_join_intent(data: &v0::DataMlsJoinIntent) -> Result<()> {
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

    Ok(())
}

/// The joining device's identity, which `session` must be bound to
async fn bound_identity(
    db: &Database,
    user_id: &str,
    session: &Session,
    device_id: &str,
) -> Result<E2EEIdentity> {
    let identity = db
        .fetch_e2ee_identity(user_id, device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "joining device is not registered".to_string()
            })
        })?;
    identity.assert_bound_session(&session.id)?;

    Ok(identity)
}

/// Verify the intent's signature by the joining device
fn verify_join_signature(
    identity: &E2EEIdentity,
    user_id: &str,
    group_id: &str,
    data: &v0::DataMlsJoinIntent,
) -> Result<()> {
    let payload =
        mls_join_intent_payload(user_id, &data.device_id, group_id, &data.key_package_ref);
    if !identity.verify_payload(&payload, &data.signature) {
        return Err(create_error!(FailedValidation {
            error: "invalid join intent signature".to_string()
        }));
    }

    Ok(())
}

/// Verify a Text intent's signature by the joining device and return the
/// signed `(generation, issued_at)` to store and fan out (design §3.13).
///
/// On a channel whose stored list is v2 (#218, whatever `formats_v2` says)
/// both fields are required, `generation` must be the stored group's, and
/// the signature must verify over the Text join payload built from the
/// server's own group id and channel; `issued_at` is only bounds-checked.
/// Every refusal is `FailedValidation`.
///
/// On a v1 channel the S1 payload is verified and the two fields are
/// IGNORED, never stored or fanned out, so the channel behaves exactly as
/// in S1 (§3.13: "on a v1 channel the S1 payload is used and the two
/// fields are ignored"). Relaying them would be wrong, not just redundant:
/// admitters choose the payload by the carrier (both fields present means
/// the Text payload), so they would refuse an intent the server accepted
/// over the S1 payload.
fn verify_text_join_signature(
    identity: &E2EEIdentity,
    user_id: &str,
    group: &MlsGroup,
    seat_list: &SeatList,
    data: &v0::DataMlsJoinIntent,
) -> Result<(Option<u32>, Option<i64>)> {
    if !seat_list.is_v2() {
        verify_join_signature(identity, user_id, &group.id, data)?;
        return Ok((None, None));
    }

    let (Some(generation), Some(issued_at)) = (data.generation, data.issued_at) else {
        return Err(create_error!(FailedValidation {
            error: "a join intent on a v2 channel needs generation and issued_at".to_string()
        }));
    };
    if group.generation != Some(generation) {
        return Err(create_error!(FailedValidation {
            error: "join intent generation is not the group's".to_string()
        }));
    }

    let payload = TextJoinPayload {
        user_id: user_id.to_string(),
        device_id: data.device_id.clone(),
        channel_id: group.channel_id.clone(),
        generation,
        group_id: group.id.clone(),
        key_package_ref: data.key_package_ref.clone(),
        issued_at,
    }
    .build()?;
    if !identity.verify_payload(&payload, &data.signature) {
        return Err(create_error!(FailedValidation {
            error: "invalid join intent signature".to_string()
        }));
    }

    Ok((Some(generation), Some(issued_at)))
}

/// The stored intent row, stamped now. `generation` and `issued_at` are
/// the verified Text join payload fields (`None` on Call and v1 intents).
fn join_intent_row(
    group: &MlsGroup,
    user_id: &str,
    data: &v0::DataMlsJoinIntent,
    generation: Option<u32>,
    issued_at: Option<i64>,
) -> MlsJoinIntent {
    MlsJoinIntent {
        id: MlsJoinIntent::composite_id(&group.id, user_id, &data.device_id),
        group_id: group.id.clone(),
        user_id: user_id.to_string(),
        device_id: data.device_id.clone(),
        key_package_ref: data.key_package_ref.clone(),
        signature: data.signature.clone(),
        created_at: Timestamp::now_utc(),
        generation,
        issued_at,
        protocol: None,
    }
}

/// Store the intent, rate limited per (group, user, device): the
/// joiner-side retry runs at 10 s (plan §1.4), so a shorter re-broadcast is
/// never legitimate
async fn store_join_intent(db: &Database, intent: &MlsJoinIntent) -> Result<()> {
    if let Some(previous) = db.upsert_mls_join_intent(intent).await? {
        let elapsed = intent
            .created_at
            .duration_since(previous.created_at)
            .whole_seconds();
        if elapsed < MIN_JOIN_INTENT_INTERVAL_SECONDS {
            // Restore the previous row: a slowmode-REJECTED re-broadcast
            // must not refresh the freshness stamp the call's dual-reload
            // close reads, or a member spamming sub-interval intents could
            // keep its own row perpetually "outstanding" and steer a peer's
            // legitimate rejoin into a group close. (Griefing only — the
            // peers converge encrypted via CREATE — but cheap to refuse.)
            // A row has a single writer (its own device), so this restore
            // can only race that device's own requests.
            db.upsert_mls_join_intent(&previous).await?;
            return Err(create_error!(InSlowmode {
                retry_after: (MIN_JOIN_INTENT_INTERVAL_SECONDS - elapsed).max(1) as u64
            }));
        }
    }

    Ok(())
}

/// Fan out to each member USER's private topic; member devices filter
/// and self-schedule admission with leaf-index staggered timers. The event
/// carries the stored row's signed fields, so an admitter rebuilds the
/// payload the server verified (§3.13 "Carriers").
async fn fan_out_join_requested(group: &MlsGroup, intent: &MlsJoinIntent, rejoin: bool) {
    let member_users: HashSet<String> = group
        .members
        .iter()
        .map(|member| member.user_id.clone())
        .collect();

    for member_user in member_users {
        EventV1::MlsJoinRequested {
            group_id: group.id.clone(),
            channel_id: group.channel_id.clone(),
            user_id: intent.user_id.clone(),
            device_id: intent.device_id.clone(),
            key_package_ref: intent.key_package_ref.clone(),
            signature: intent.signature.clone(),
            rejoin,
            generation: intent.generation,
            issued_at: intent.issued_at,
        }
        .private(member_user)
        .await;
    }
}

/// The Text path (W2 decisions 1, 5 and 7, design §6.1 "Join intent").
/// Every flag case is its own `#[test]`: `overwrite_config` runs once per
/// process, BEFORE the harness primes the config cache, so these need
/// nextest (one process per test). The test config has every flag on
/// except `formats_v2`, which the v2 cases turn on.
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        events::client::EventV1, mls_join_intent_payload, Account, BotInformation,
        ChannelEntitlementState, Database, MlsCommit, MlsCommitOutcome, MlsGroup, MlsMemberDevice,
        PartialChannel, SeatListBody, SeatListHistory, SeatListPreHistory, SeatListV2Lines,
        Session, TextJoinPayload, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::Result;
    use rocket::{serde::json::Json, State};
    use rocket_empty::EmptyResponse;
    use ulid::Ulid;

    use super::super::{dispatch_group, require_channel_access, GroupDispatch};
    use super::join_intent;
    use crate::util::test::{
        ProtectedChannel, TestE2EEDevice, TestHarness, FIXTURE_DEVICE_CAP, FIXTURE_ISSUED_AT,
        FIXTURE_SLOT_CAP, MEMBER_DEVICE_SEED, NEW_OWNER_DEVICE_SEED, OWNER_DEVICE_SEED,
    };

    /// Call the route as rocket does
    async fn post(
        db: &Database,
        user: &User,
        session: &Session,
        group_id: &str,
        data: v0::DataMlsJoinIntent,
    ) -> Result<EmptyResponse> {
        join_intent(
            <&State<Database>>::from(db),
            user.clone(),
            session.clone(),
            group_id.to_string(),
            Json(data),
        )
        .await
    }

    /// A join intent by `device` for `group_id`, signed by it
    fn signed_intent(
        device: &TestE2EEDevice,
        group_id: &str,
        key_package_ref: &str,
    ) -> v0::DataMlsJoinIntent {
        let payload = mls_join_intent_payload(
            &device.user_id,
            &device.device_id,
            group_id,
            key_package_ref,
        );
        v0::DataMlsJoinIntent {
            device_id: device.device_id.clone(),
            key_package_ref: key_package_ref.to_string(),
            signature: device.sign(&payload),
            generation: None,
            issued_at: None,
            protocol: None,
        }
    }

    /// The Text join payload (design §3.13) of `device` for `group`
    fn text_payload(
        device: &TestE2EEDevice,
        group: &MlsGroup,
        key_package_ref: &str,
        generation: u32,
        issued_at: i64,
    ) -> String {
        TextJoinPayload {
            user_id: device.user_id.clone(),
            device_id: device.device_id.clone(),
            channel_id: group.channel_id.clone(),
            generation,
            group_id: group.id.clone(),
            key_package_ref: key_package_ref.to_string(),
            issued_at,
        }
        .build()
        .expect("a text join payload")
    }

    /// A v2 join intent by `device` for `group`: the Text join payload at
    /// the group's generation, signed by it, carrying both signed fields
    fn signed_text_intent(
        device: &TestE2EEDevice,
        group: &MlsGroup,
        key_package_ref: &str,
        issued_at: i64,
    ) -> v0::DataMlsJoinIntent {
        let generation = group.generation.expect("a Text group generation");
        v0::DataMlsJoinIntent {
            device_id: device.device_id.clone(),
            key_package_ref: key_package_ref.to_string(),
            signature: device.sign(&text_payload(
                device,
                group,
                key_package_ref,
                generation,
                issued_at,
            )),
            generation: Some(generation),
            issued_at: Some(issued_at),
            protocol: None,
        }
    }

    /// `device` as a group member entry
    fn leaf(device: &TestE2EEDevice) -> MlsMemberDevice {
        MlsMemberDevice {
            user_id: device.user_id.clone(),
            device_id: device.device_id.clone(),
        }
    }

    /// A leaf of a device of `user` registered with the key for `seed` and
    /// bound to no session: an Add requires a registered identity (S2-D17c)
    async fn registered_leaf(harness: &TestHarness, user: &User, seed: u8) -> MlsMemberDevice {
        let device = harness
            .new_e2ee_device(user, &Ulid::new().to_string(), seed)
            .await;
        leaf(&device)
    }

    /// A fresh session of `account`, with a new device bound to it
    async fn new_bound_device(
        harness: &TestHarness,
        account: &Account,
        user: &User,
        seed: u8,
    ) -> (Session, TestE2EEDevice) {
        let session = account
            .create_session(&harness.db, String::new())
            .await
            .expect("`Session`");
        let device = harness.new_e2ee_device(user, &session.id, seed).await;
        (session, device)
    }

    /// Add `added` to the open Text group `group_id` in one won commit by
    /// `committer`, through the database primitive. The AD hash is the
    /// stored seat list's; the entitlement operand is unlimited, so the
    /// signed list's cap applies.
    async fn add_to_group(
        harness: &TestHarness,
        group_id: &str,
        committer: &TestE2EEDevice,
        added: Vec<MlsMemberDevice>,
    ) -> MlsGroup {
        let db = &harness.db;
        let group = db.fetch_mls_group(group_id).await.expect("the group");
        let hash = db
            .fetch_seat_list(&group.channel_id)
            .await
            .expect("seat list read")
            .expect("a seat list")
            .commit_ad_sha256()
            .expect("the AD hash");
        let epoch = group.current_epoch + 1;
        let outcome = db
            .insert_mls_text_commit(
                &MlsCommit {
                    id: MlsCommit::composite_id(group_id, epoch),
                    group_id: group_id.to_string(),
                    epoch,
                    committer: leaf(committer),
                    commit: STANDARD_NO_PAD.encode(b"opaque add commit"),
                    size: 17,
                    added: added.clone(),
                    removed: vec![],
                    created_at: Timestamp::now_utc(),
                    rejoin_intents: vec![],
                    removed_reasons: vec![],
                    welcome: None,
                    history_visible: None,
                },
                &hash,
                0,
            )
            .await
            .expect("the add commit");
        assert!(matches!(outcome, MlsCommitOutcome::Won), "{:?}", outcome);

        let group = db.fetch_mls_group(group_id).await.expect("the group");
        for device in &added {
            assert!(group.has_member(&device.user_id, &device.device_id));
        }
        group
    }

    /// One Text commit by `committer` at the next epoch of `group_id`,
    /// adding `added` and removing `removed`, stamped `created_at`, through
    /// the database primitive (the AD hash is the stored seat list's; the
    /// entitlement operand is unlimited). Rule 6 measures the Text window
    /// back from `created_at`, so a later stamp ages every stored intent.
    async fn commit_at(
        harness: &TestHarness,
        group_id: &str,
        committer: &TestE2EEDevice,
        added: Vec<MlsMemberDevice>,
        removed: Vec<MlsMemberDevice>,
        created_at: Timestamp,
    ) -> Result<MlsCommitOutcome> {
        let db = &harness.db;
        let group = db.fetch_mls_group(group_id).await.expect("the group");
        let hash = db
            .fetch_seat_list(&group.channel_id)
            .await
            .expect("seat list read")
            .expect("a seat list")
            .commit_ad_sha256()
            .expect("the AD hash");
        let epoch = group.current_epoch + 1;
        let commit = b"opaque text commit";
        db.insert_mls_text_commit(
            &MlsCommit {
                id: MlsCommit::composite_id(group_id, epoch),
                group_id: group_id.to_string(),
                epoch,
                committer: leaf(committer),
                commit: STANDARD_NO_PAD.encode(commit),
                size: commit.len() as i64,
                added,
                removed,
                created_at,
                rejoin_intents: vec![],
                removed_reasons: vec![],
                welcome: None,
                history_visible: None,
            },
            &hash,
            0,
        )
        .await
    }

    /// The refusal's response body; panics when the request was accepted or
    /// refused with another error type
    #[track_caller]
    fn refused<T>(result: Result<T>, kind: &str, case: &str) -> serde_json::Value {
        match result {
            Err(error) => {
                let body = serde_json::to_value(&error).expect("an error body");
                assert_eq!(body["type"], kind, "{}: {}", case, body);
                body
            }
            Ok(_) => panic!("{}: expected {}, accepted", case, kind),
        }
    }

    /// The group is still open, with exactly these members
    async fn assert_open_with(db: &Database, group_id: &str, members: &[MlsMemberDevice]) {
        let group = db.fetch_mls_group(group_id).await.expect("the group");
        assert!(group.open, "the Text group was closed");
        assert!(group.closed_at.is_none());
        assert_eq!(group.members, members);
    }

    /// The stored intent rows of `group_id`, as (user, device), sorted
    async fn stored_intents(db: &Database, group_id: &str) -> Vec<(String, String)> {
        let mut rows: Vec<(String, String)> = db
            .fetch_mls_join_intents_for_group(group_id)
            .await
            .expect("intents")
            .into_iter()
            .map(|intent| (intent.user_id, intent.device_id))
            .collect();
        rows.sort();
        rows
    }

    struct Text {
        harness: TestHarness,
        owner: User,
        owner_account: Account,
        owner_session: Session,
        member: User,
        member_account: Account,
        member_session: Session,
        /// The member's device bound to `member_session` (not in the group)
        member_device: TestE2EEDevice,
        protected: ProtectedChannel,
        /// Generation 0; members: the owner's device only
        group: MlsGroup,
    }

    /// A protected channel seating the owner and a member (genesis list cap
    /// [`FIXTURE_DEVICE_CAP`], entitlement cap the configured default 5),
    /// and its generation-0 Text group created by the owner's device
    async fn text_fixture() -> Text {
        let harness = TestHarness::new().await;
        let (owner_account, owner_session, owner) = harness.new_user().await;
        let (member_account, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        assert_eq!(group.members, vec![leaf(&protected.owner_device)]);

        Text {
            harness,
            owner,
            owner_account,
            owner_session,
            member,
            member_account,
            member_session,
            member_device,
            protected,
            group,
        }
    }

    /// The 3.1.1 group salt of the v2 fixture list
    fn v2_group_salt() -> String {
        "ab".repeat(32)
    }

    /// As [`text_fixture`], but the genesis list is a v2 list (§4.1.1, no
    /// authority, `history: hidden`, `pre_history: kept`). Needs
    /// `formats_v2` on: protect takes a v2 genesis only then (#218).
    async fn text_v2_fixture() -> Text {
        let harness = TestHarness::new().await;
        let (owner_account, owner_session, owner) = harness.new_user().await;
        let (member_account, member_session, member) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&owner).await;
        let entitlement = harness
            .grant_entitlement(&channel, FIXTURE_SLOT_CAP, None)
            .await;
        let owner_device = harness
            .new_e2ee_device(&owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;
        harness.join_server(&server, &member).await;

        let body = SeatListBody {
            channel_id: channel.id().to_string(),
            version: 1,
            device_cap: FIXTURE_DEVICE_CAP,
            issued_at: FIXTURE_ISSUED_AT,
            signer_user_id: owner.id.clone(),
            signer_device_id: owner_device.device_id.clone(),
            seats: vec![owner.id.clone(), member.id.clone()],
            v2: Some(SeatListV2Lines {
                authority_sha256: None,
                history: SeatListHistory::Hidden,
                history_boundary: None,
                pre_history: SeatListPreHistory::Kept,
                group_salt: v2_group_salt(),
            }),
        }
        .build()
        .expect("a canonical v2 seat list body");
        let protect = v0::DataProtectChannel {
            seat_list: v0::DataSeatList {
                signature: owner_device.sign(&body),
                body,
                signer_device_id: owner_device.device_id.clone(),
                handover: None,
                authority: None,
            },
            wipe_history: None,
        };
        harness.protect_with_db(&channel, &protect).await;
        let channel = harness
            .db
            .fetch_channel(channel.id())
            .await
            .expect("the protected channel");
        assert!(harness
            .db
            .fetch_seat_list(channel.id())
            .await
            .expect("seat list read")
            .expect("a seat list")
            .is_v2());

        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        let group = harness
            .new_text_group(&channel, &owner_device, 0, None)
            .await;
        assert_eq!(group.members, vec![leaf(&owner_device)]);

        Text {
            harness,
            owner,
            owner_account,
            owner_session,
            member,
            member_account,
            member_session,
            member_device,
            protected: ProtectedChannel {
                server,
                channel,
                entitlement,
                owner_device,
                seat_list: protect.seat_list,
            },
            group,
        }
    }

    /// The `MlsJoinRequested` on `topic_user`'s private topic for `device`
    /// and `key_package_ref`; returns its signed Text payload fields and
    /// its `rejoin` flag, `(generation, issued_at, rejoin)`
    async fn join_request_carriers(
        harness: &mut TestHarness,
        topic_user: &str,
        group_id: &str,
        device: &TestE2EEDevice,
        key_package_ref: &str,
    ) -> (Option<u32>, Option<i64>, bool) {
        let event = harness
            .wait_for_event(&format!("{topic_user}!"), |event| {
                matches!(
                    event,
                    EventV1::MlsJoinRequested {
                        group_id: event_group,
                        device_id,
                        key_package_ref: event_ref,
                        ..
                    } if event_group == group_id
                        && *device_id == device.device_id
                        && event_ref == key_package_ref
                )
            })
            .await;
        match event {
            EventV1::MlsJoinRequested {
                user_id,
                rejoin,
                generation,
                issued_at,
                ..
            } => {
                assert_eq!(user_id, device.user_id);
                (generation, issued_at, rejoin)
            }
            other => panic!("not a join request: {:?}", other),
        }
    }

    /// As [`join_request_carriers`]; returns its `rejoin` flag
    async fn join_requested(
        harness: &mut TestHarness,
        topic_user: &str,
        group_id: &str,
        device: &TestE2EEDevice,
        key_package_ref: &str,
    ) -> bool {
        join_request_carriers(harness, topic_user, group_id, device, key_package_ref)
            .await
            .2
    }

    #[test]
    fn a_seated_member_joins_with_several_devices() {
        crate::util::test::rt().block_on(a_seated_member_joins_with_several_devices_case())
    }

    async fn a_seated_member_joins_with_several_devices_case() {
        let mut text = text_fixture().await;
        let group_id = text.group.id.clone();
        let owner_id = text.owner.id.clone();

        // A seated member's first device: stored and fanned out, not a rejoin
        post(
            &text.harness.db,
            &text.member,
            &text.member_session,
            &group_id,
            signed_intent(&text.member_device, &group_id, "m1"),
        )
        .await
        .expect("the first device's intent");
        assert_eq!(
            stored_intents(&text.harness.db, &group_id).await,
            vec![(text.member.id.clone(), text.member_device.device_id.clone())]
        );
        assert!(
            !join_requested(
                &mut text.harness,
                &owner_id,
                &group_id,
                &text.member_device,
                "m1"
            )
            .await
        );

        // An immediate re-broadcast is rate limited, as on calls
        refused(
            post(
                &text.harness.db,
                &text.member,
                &text.member_session,
                &group_id,
                signed_intent(&text.member_device, &group_id, "m1"),
            )
            .await,
            "InSlowmode",
            "re-broadcast",
        );

        // Admitted. The member's SECOND device is not refused: no call
        // one-device rule on Text
        let group = add_to_group(
            &text.harness,
            &group_id,
            &text.protected.owner_device,
            vec![leaf(&text.member_device)],
        )
        .await;
        let (second_session, second_device) = new_bound_device(
            &text.harness,
            &text.member_account,
            &text.member,
            MEMBER_DEVICE_SEED + 1,
        )
        .await;
        post(
            &text.harness.db,
            &text.member,
            &second_session,
            &group_id,
            signed_intent(&second_device, &group_id, "m2"),
        )
        .await
        .expect("the second device's intent");
        assert!(
            !join_requested(
                &mut text.harness,
                &owner_id,
                &group_id,
                &second_device,
                "m2"
            )
            .await
        );

        // The member device itself again: device-aware, so a rejoin
        post(
            &text.harness.db,
            &text.member,
            &text.member_session,
            &group_id,
            signed_intent(&text.member_device, &group_id, "m3"),
        )
        .await
        .expect("the rejoin intent");
        assert!(
            join_requested(
                &mut text.harness,
                &owner_id,
                &group_id,
                &text.member_device,
                "m3"
            )
            .await
        );
        assert_open_with(&text.harness.db, &group_id, &group.members).await;
    }

    #[test]
    fn the_joining_device_is_authenticated() {
        crate::util::test::rt().block_on(the_joining_device_is_authenticated_case())
    }

    async fn the_joining_device_is_authenticated_case() {
        let text = text_fixture().await;
        let db = &text.harness.db;
        let group_id = &text.group.id;

        // A malformed body from a seated viewer
        let mut malformed = signed_intent(&text.member_device, group_id, "m1");
        malformed.device_id = "not-a-device".to_string();
        refused(
            post(db, &text.member, &text.member_session, group_id, malformed).await,
            "FailedValidation",
            "malformed",
        );

        // A device that is not registered
        let unregistered = TestE2EEDevice::new(
            &text.member.id,
            &format!("{:032x}", 0xabcdef),
            0x60,
            &text.member_session.id,
        );
        refused(
            post(
                db,
                &text.member,
                &text.member_session,
                group_id,
                signed_intent(&unregistered, group_id, "m1"),
            )
            .await,
            "FailedValidation",
            "unregistered",
        );

        // A device of the member that this session is not bound to
        let (_, other_device) = new_bound_device(
            &text.harness,
            &text.member_account,
            &text.member,
            MEMBER_DEVICE_SEED + 1,
        )
        .await;
        refused(
            post(
                db,
                &text.member,
                &text.member_session,
                group_id,
                signed_intent(&other_device, group_id, "m1"),
            )
            .await,
            "NotAuthenticated",
            "another device's session",
        );

        // A forged signature
        let mut forged = signed_intent(&text.member_device, group_id, "m1");
        forged.signature = STANDARD_NO_PAD.encode([0u8; 64]);
        refused(
            post(db, &text.member, &text.member_session, group_id, forged).await,
            "FailedValidation",
            "forged",
        );

        assert!(stored_intents(db, group_id).await.is_empty());
    }

    #[test]
    fn the_device_cap_is_enforced() {
        crate::util::test::rt().block_on(the_device_cap_is_enforced_case())
    }

    async fn the_device_cap_is_enforced_case() {
        let text = text_fixture().await;
        let harness = &text.harness;
        let db = &harness.db;
        let group_id = text.group.id.clone();
        let owner_device = &text.protected.owner_device;
        assert_eq!(FIXTURE_DEVICE_CAP, 5);

        // The owner holds 4 member devices: a fifth is accepted
        let mut owner_leaves = Vec::new();
        for seed in 0x01..=0x03 {
            owner_leaves.push(registered_leaf(harness, &text.owner, seed).await);
        }
        let group = add_to_group(harness, &group_id, owner_device, owner_leaves).await;
        assert_eq!(group.member_devices_of(&text.owner.id).count(), 4);
        let (fifth_session, fifth) =
            new_bound_device(harness, &text.owner_account, &text.owner, 0x05).await;
        post(
            db,
            &text.owner,
            &fifth_session,
            &group_id,
            signed_intent(&fifth, &group_id, "o5"),
        )
        .await
        .expect("the fifth device, under the cap");

        // At 5 member devices the sixth is refused
        let group = add_to_group(harness, &group_id, owner_device, vec![leaf(&fifth)]).await;
        assert_eq!(group.member_devices_of(&text.owner.id).count(), 5);
        let (sixth_session, sixth) =
            new_bound_device(harness, &text.owner_account, &text.owner, 0x06).await;
        let body = refused(
            post(
                db,
                &text.owner,
                &sixth_session,
                &group_id,
                signed_intent(&sixth, &group_id, "o6"),
            )
            .await,
            "DeviceCapReached",
            "the sixth device",
        );
        assert_eq!(body["max"], 5, "{}", body);
        assert!(!stored_intents(db, &group_id)
            .await
            .contains(&(text.owner.id.clone(), sixth.device_id.clone())));

        // A member device at the cap may still rejoin (it is not new)
        post(
            db,
            &text.owner,
            &text.owner_session,
            &group_id,
            signed_intent(owner_device, &group_id, "o1"),
        )
        .await
        .expect("a rejoin at the cap");
        assert_open_with(db, &group_id, &group.members).await;

        // The entitlement operand: its cap 2 is below the signed 5. The
        // member holds 2 devices, so a third is refused with max 2
        let group = add_to_group(
            harness,
            &group_id,
            owner_device,
            vec![
                leaf(&text.member_device),
                registered_leaf(harness, &text.member, 0x21).await,
            ],
        )
        .await;
        assert_eq!(group.member_devices_of(&text.member.id).count(), 2);
        harness
            .grant_entitlement(&text.protected.channel, FIXTURE_SLOT_CAP, Some(2))
            .await;
        let (third_session, third) =
            new_bound_device(harness, &text.member_account, &text.member, 0x23).await;
        let third_intent = || signed_intent(&third, &group_id, "m3");
        let body = refused(
            post(db, &text.member, &third_session, &group_id, third_intent()).await,
            "DeviceCapReached",
            "the entitlement cap",
        );
        assert_eq!(body["max"], 2, "{}", body);

        // The signed operand: list cap 3 under an unlimited (0) entitlement
        // governs, so the third is accepted and a fourth refused with max 3
        harness
            .grant_entitlement(&text.protected.channel, FIXTURE_SLOT_CAP, Some(0))
            .await;
        let seats = [text.owner.id.clone(), text.member.id.clone()];
        harness
            .put_seats_with_db(
                &text.protected.channel,
                &owner_device.seat_list(text.protected.channel.id(), 2, 3, &seats),
            )
            .await;
        post(db, &text.member, &third_session, &group_id, third_intent())
            .await
            .expect("the third device under the signed cap 3");
        add_to_group(harness, &group_id, owner_device, vec![leaf(&third)]).await;
        let (fourth_session, fourth) =
            new_bound_device(harness, &text.member_account, &text.member, 0x24).await;
        let fourth_intent = || signed_intent(&fourth, &group_id, "m4");
        let body = refused(
            post(
                db,
                &text.member,
                &fourth_session,
                &group_id,
                fourth_intent(),
            )
            .await,
            "DeviceCapReached",
            "the signed cap",
        );
        assert_eq!(body["max"], 3, "{}", body);

        // Both operands 0: unlimited
        harness
            .put_seats_with_db(
                &text.protected.channel,
                &owner_device.seat_list(text.protected.channel.id(), 3, 0, &seats),
            )
            .await;
        post(
            db,
            &text.member,
            &fourth_session,
            &group_id,
            fourth_intent(),
        )
        .await
        .expect("no cap at 0 and 0");
    }

    /// Mark the channel's entitlement Frozen, raw (S1 has no route for it)
    async fn freeze_entitlement(db: &Database, channel_id: &str) {
        match db {
            Database::Reference(reference) => {
                for entitlement in reference.channel_entitlements.lock().await.values_mut() {
                    if entitlement.channel_id == channel_id {
                        entitlement.state = ChannelEntitlementState::Frozen;
                    }
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let result = mongo
                    .col::<Document>("channel_entitlements")
                    .update_one(
                        doc! { "channel_id": channel_id },
                        doc! { "$set": { "state": "Frozen" } },
                    )
                    .await
                    .expect("raw freeze");
                assert_eq!(result.matched_count, 1);
            }
        }

        let entitlement = db
            .fetch_channel_entitlement(channel_id)
            .await
            .expect("entitlement read")
            .expect("an entitlement");
        assert_eq!(entitlement.state, ChannelEntitlementState::Frozen);
    }

    /// S1 took a rejoin here ("a rejoin only needs a Remove"). S2 makes a
    /// rejoin a recovery operation (S2-D32, §6.3 "Recovery gates"): the
    /// available gate AND an entitlement that allows text traffic, which
    /// Frozen does not, so the rejoin is refused as the new device is
    #[test]
    fn a_frozen_entitlement_refuses_new_devices_and_rejoins() {
        crate::util::test::rt().block_on(inactive_entitlement_refuses_joins(None))
    }

    /// Deleted refuses a new device as Frozen does, and a rejoin with it.
    /// (S5b's `a_deleted_entitlement_refuses_new_devices_only` takes the
    /// rejoin, under the S1 rule that S2-D32 replaces.)
    #[test]
    fn a_deleted_entitlement_refuses_new_devices_and_rejoins() {
        crate::util::test::rt().block_on(inactive_entitlement_refuses_joins(Some(
            ChannelEntitlementState::Deleted,
        )))
    }

    /// `state` `None` = Frozen through [`freeze_entitlement`]
    async fn inactive_entitlement_refuses_joins(state: Option<ChannelEntitlementState>) {
        let text = text_fixture().await;
        let db = &text.harness.db;
        let group_id = &text.group.id;

        match state {
            None => freeze_entitlement(db, text.protected.channel.id()).await,
            Some(state) => set_entitlement_state(db, text.protected.channel.id(), state).await,
        }

        // A new device would need an Add, and an Add of a seated member's
        // new device needs an entitlement that allows text traffic
        refused(
            post(
                db,
                &text.member,
                &text.member_session,
                group_id,
                signed_intent(&text.member_device, group_id, "m1"),
            )
            .await,
            "InvalidOperation",
            "a new device",
        );

        // A rejoin is recovery, which needs the same predicate
        refused(
            post(
                db,
                &text.owner,
                &text.owner_session,
                group_id,
                signed_intent(&text.protected.owner_device, group_id, "o1"),
            )
            .await,
            "InvalidOperation",
            "a rejoin",
        );
        assert!(stored_intents(db, group_id).await.is_empty());
    }

    /// Set the channel's entitlement state, raw (S1 has no primitive for it)
    async fn set_entitlement_state(
        db: &Database,
        channel_id: &str,
        state: ChannelEntitlementState,
    ) {
        match db {
            Database::Reference(reference) => {
                let mut found = 0;
                for entitlement in reference.channel_entitlements.lock().await.values_mut() {
                    if entitlement.channel_id == channel_id {
                        entitlement.state = state.clone();
                        found += 1;
                    }
                }
                assert_eq!(found, 1);
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, to_bson, Document};

                let result = mongo
                    .col::<Document>("channel_entitlements")
                    .update_one(
                        doc! { "channel_id": channel_id },
                        doc! { "$set": { "state": to_bson(&state).expect("a state") } },
                    )
                    .await
                    .expect("raw state write");
                assert_eq!(result.matched_count, 1);
            }
        }

        let entitlement = db
            .fetch_channel_entitlement(channel_id)
            .await
            .expect("entitlement read")
            .expect("an entitlement");
        assert_eq!(entitlement.state, state);
    }

    #[test]
    fn an_unseated_viewer_is_refused() {
        crate::util::test::rt().block_on(an_unseated_viewer_is_refused_case())
    }

    async fn an_unseated_viewer_is_refused_case() {
        let text = text_fixture().await;
        let harness = &text.harness;
        let db = &harness.db;
        let group_id = &text.group.id;

        // A server member who can view the channel, with a bound device, on
        // no seat list
        let (_, viewer_session, viewer) = harness.new_user().await;
        harness.join_server(&text.protected.server, &viewer).await;
        let viewer_device = harness
            .new_e2ee_device(&viewer, &viewer_session.id, 0x40)
            .await;
        assert!(require_channel_access(db, &viewer, &text.protected.channel)
            .await
            .is_ok());

        refused(
            post(
                db,
                &viewer,
                &viewer_session,
                group_id,
                signed_intent(&viewer_device, group_id, "v1"),
            )
            .await,
            "NotSeated",
            "unseated viewer",
        );

        // A released seat is not a seat either
        db.release_channel_seats_for_user(
            &text.member.id,
            Some(&text.protected.server.id),
            Timestamp::now_utc(),
        )
        .await
        .expect("release");
        refused(
            post(
                db,
                &text.member,
                &text.member_session,
                group_id,
                signed_intent(&text.member_device, group_id, "m1"),
            )
            .await,
            "NotSeated",
            "released seat",
        );
        assert!(stored_intents(db, group_id).await.is_empty());
    }

    #[test]
    fn a_text_join_never_closes_the_group() {
        crate::util::test::rt().block_on(a_text_join_never_closes_the_group_case())
    }

    async fn a_text_join_never_closes_the_group_case() {
        let text = text_fixture().await;
        let db = &text.harness.db;
        let group_id = text.group.id.clone();
        let owner_device = &text.protected.owner_device;

        // The sole member rejoins: a call closes here (the solo-stale case)
        post(
            db,
            &text.owner,
            &text.owner_session,
            &group_id,
            signed_intent(owner_device, &group_id, "o1"),
        )
        .await
        .expect("the sole member's rejoin");
        assert_open_with(db, &group_id, &text.group.members).await;

        // Every member device mid-rejoin: a call closes here (dual reload)
        let group = add_to_group(
            &text.harness,
            &group_id,
            owner_device,
            vec![leaf(&text.member_device)],
        )
        .await;
        post(
            db,
            &text.member,
            &text.member_session,
            &group_id,
            signed_intent(&text.member_device, &group_id, "m1"),
        )
        .await
        .expect("the second rejoin");
        assert_eq!(
            stored_intents(db, &group_id).await.len(),
            2,
            "both member devices hold a fresh intent, the dual-reload shape"
        );
        assert_open_with(db, &group_id, &group.members).await;
    }

    #[test]
    fn a_superseded_text_group_takes_no_joins() {
        crate::util::test::rt().block_on(a_superseded_text_group_takes_no_joins_case())
    }

    async fn a_superseded_text_group_takes_no_joins_case() {
        let text = text_fixture().await;
        let db = &text.harness.db;
        let successor = text
            .harness
            .new_text_group(
                &text.protected.channel,
                &text.protected.owner_device,
                1,
                Some(&text.group.id),
            )
            .await;
        assert!(!db.fetch_mls_group(&text.group.id).await.expect("old").open);

        refused(
            post(
                db,
                &text.member,
                &text.member_session,
                &text.group.id,
                signed_intent(&text.member_device, &text.group.id, "m1"),
            )
            .await,
            "NotFound",
            "superseded",
        );
        post(
            db,
            &text.member,
            &text.member_session,
            &successor.id,
            signed_intent(&text.member_device, &successor.id, "m1"),
        )
        .await
        .expect("the successor");
    }

    /// The flag cases: a seated member's new device (growth) and the owner's
    /// rejoin (recovery, S2-D32). Each refusal is the expected
    /// `FeatureDisabled` feature, `None` = served.
    async fn text_join_under_flags(new_device_refusal: Option<&str>, rejoin_refusal: Option<&str>) {
        let text = text_fixture().await;
        let db = &text.harness.db;
        let group_id = &text.group.id;

        let new_device = post(
            db,
            &text.member,
            &text.member_session,
            group_id,
            signed_intent(&text.member_device, group_id, "m1"),
        )
        .await;
        let rejoin = post(
            db,
            &text.owner,
            &text.owner_session,
            group_id,
            signed_intent(&text.protected.owner_device, group_id, "o1"),
        )
        .await;

        let mut served = 0;
        for (case, result, refusal) in [
            ("new device", new_device, new_device_refusal),
            ("rejoin", rejoin, rejoin_refusal),
        ] {
            match refusal {
                None => {
                    result.expect(case);
                    served += 1;
                }
                Some(feature) => {
                    let body = refused(result, "FeatureDisabled", case);
                    assert_eq!(body["feature"], feature, "{}: {}", case, body);
                }
            }
        }
        assert_eq!(stored_intents(db, group_id).await.len(), served);
        assert_open_with(db, group_id, &text.group.members).await;
    }

    #[test]
    fn a_text_join_with_every_flag_on_is_accepted() {
        crate::util::test::rt().block_on(text_join_under_flags(None, None))
    }

    /// S1 refused the rejoin here too; S2 makes it recovery (S2-D32, §7.1
    /// flag-off table #220), so growth off stops the new device only
    #[test]
    fn a_text_join_with_growth_off_refuses_new_devices_only() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            text_join_under_flags(Some("protected_channels"), None).await
        })
    }

    #[test]
    fn a_text_join_with_e2ee_off_is_refused() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            text_join_under_flags(Some("e2ee"), Some("e2ee")).await
        })
    }

    #[test]
    fn a_text_join_ignores_the_media_flag() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            text_join_under_flags(None, None).await
        })
    }

    /// v2 (§3.13, #218): a seated member's new device and the owner's
    /// rejoin sign the Text join payload; both signed fields are stored and
    /// fanned out
    #[test]
    fn a_v2_intent_verifies_over_the_text_join_payload() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.formats_v2 = true;
            })
            .await;
            a_v2_intent_verifies_over_the_text_join_payload_case().await
        })
    }

    async fn a_v2_intent_verifies_over_the_text_join_payload_case() {
        let mut text = text_v2_fixture().await;
        let group_id = text.group.id.clone();
        let owner_id = text.owner.id.clone();

        post(
            &text.harness.db,
            &text.member,
            &text.member_session,
            &group_id,
            signed_text_intent(&text.member_device, &text.group, "m1", FIXTURE_ISSUED_AT),
        )
        .await
        .expect("a new device's v2 intent");
        let stored = text
            .harness
            .db
            .fetch_mls_join_intents_for_group(&group_id)
            .await
            .expect("intents");
        assert_eq!(stored.len(), 1);
        assert_eq!(
            (stored[0].generation, stored[0].issued_at),
            (Some(0), Some(FIXTURE_ISSUED_AT))
        );
        assert_eq!(
            join_request_carriers(
                &mut text.harness,
                &owner_id,
                &group_id,
                &text.member_device,
                "m1"
            )
            .await,
            (Some(0), Some(FIXTURE_ISSUED_AT), false)
        );

        let owner_device = &text.protected.owner_device;
        post(
            &text.harness.db,
            &text.owner,
            &text.owner_session,
            &group_id,
            signed_text_intent(owner_device, &text.group, "o1", FIXTURE_ISSUED_AT + 1),
        )
        .await
        .expect("the owner's v2 rejoin");
        assert_eq!(
            join_request_carriers(&mut text.harness, &owner_id, &group_id, owner_device, "o1")
                .await,
            (Some(0), Some(FIXTURE_ISSUED_AT + 1), true)
        );
    }

    /// v2 (§3.13, #218): an intent without `generation` or `issued_at`,
    /// signed over the S1 payload (with or without the two fields), at
    /// another generation, or with an out-of-range `issued_at` is
    /// `FailedValidation`, and nothing is stored
    #[test]
    fn a_v2_channel_refuses_an_intent_without_the_text_payload() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.formats_v2 = true;
            })
            .await;
            a_v2_channel_refuses_an_intent_without_the_text_payload_case().await
        })
    }

    async fn a_v2_channel_refuses_an_intent_without_the_text_payload_case() {
        let text = text_v2_fixture().await;
        let db = &text.harness.db;
        let group = &text.group;
        let group_id = &group.id;
        let device = &text.member_device;
        let good = || signed_text_intent(device, group, "m1", FIXTURE_ISSUED_AT);

        let mut no_generation = good();
        no_generation.generation = None;
        let mut no_issued_at = good();
        no_issued_at.issued_at = None;
        let s1 = signed_intent(device, group_id, "m1");
        let mut s1_with_fields = signed_intent(device, group_id, "m1");
        s1_with_fields.generation = Some(0);
        s1_with_fields.issued_at = Some(FIXTURE_ISSUED_AT);
        let mut other_generation = good();
        other_generation.generation = Some(1);
        other_generation.signature =
            device.sign(&text_payload(device, group, "m1", 1, FIXTURE_ISSUED_AT));
        let mut out_of_range = good();
        out_of_range.issued_at = Some(-1);

        for (case, body) in [
            ("no generation", no_generation),
            ("no issued_at", no_issued_at),
            ("the S1 payload", s1),
            ("the S1 payload with both fields", s1_with_fields),
            ("another generation", other_generation),
            ("issued_at out of range", out_of_range),
        ] {
            refused(
                post(db, &text.member, &text.member_session, group_id, body).await,
                "FailedValidation",
                case,
            );
        }
        assert!(stored_intents(db, group_id).await.is_empty());

        post(db, &text.member, &text.member_session, group_id, good())
            .await
            .expect("the Text join payload");
    }

    /// v1 (§3.13): the S1 payload is verified and `generation`/`issued_at`
    /// are ignored, never stored or fanned out; an intent signed over the
    /// Text payload is refused
    #[test]
    fn a_v1_channel_ignores_the_text_fields() {
        crate::util::test::rt().block_on(a_v1_channel_ignores_the_text_fields_case())
    }

    async fn a_v1_channel_ignores_the_text_fields_case() {
        let mut text = text_fixture().await;
        let group_id = text.group.id.clone();
        let owner_id = text.owner.id.clone();

        let mut with_fields = signed_intent(&text.member_device, &group_id, "m1");
        with_fields.generation = Some(0);
        with_fields.issued_at = Some(FIXTURE_ISSUED_AT);
        post(
            &text.harness.db,
            &text.member,
            &text.member_session,
            &group_id,
            with_fields,
        )
        .await
        .expect("the S1 payload on a v1 channel");
        let stored = text
            .harness
            .db
            .fetch_mls_join_intents_for_group(&group_id)
            .await
            .expect("intents");
        assert_eq!(stored.len(), 1);
        assert_eq!((stored[0].generation, stored[0].issued_at), (None, None));
        assert_eq!(
            join_request_carriers(
                &mut text.harness,
                &owner_id,
                &group_id,
                &text.member_device,
                "m1"
            )
            .await,
            (None, None, false)
        );

        let (second_session, second) = new_bound_device(
            &text.harness,
            &text.member_account,
            &text.member,
            MEMBER_DEVICE_SEED + 1,
        )
        .await;
        refused(
            post(
                &text.harness.db,
                &text.member,
                &second_session,
                &group_id,
                signed_text_intent(&second, &text.group, "m2", FIXTURE_ISSUED_AT),
            )
            .await,
            "FailedValidation",
            "the Text payload on a v1 channel",
        );
    }

    /// S2-D28: a Text intent the route stored stays outstanding for
    /// `text_rejoin_window_secs` (24 h by default), measured from its
    /// server `created_at`: the rule-6 eviction it justifies is refused
    /// 25 h on and admitted 23 h on, never at the 30 s Call window
    #[test]
    fn a_text_intent_stays_outstanding_for_the_text_window() {
        crate::util::test::rt().block_on(a_text_intent_stays_outstanding_for_the_text_window_case())
    }

    async fn a_text_intent_stays_outstanding_for_the_text_window_case() {
        let text = text_fixture().await;
        let harness = &text.harness;
        let db = &harness.db;
        let group_id = text.group.id.clone();
        let owner_device = &text.protected.owner_device;
        let member_leaf = leaf(&text.member_device);

        // Added a minute ago, so the rejoin intent is newer than the Add, as
        // rule 6 requires
        let added_at = Timestamp::now_utc()
            .checked_sub(Duration::seconds(60))
            .expect("a time");
        let added = commit_at(
            harness,
            &group_id,
            owner_device,
            vec![member_leaf.clone()],
            vec![],
            added_at,
        )
        .await;
        assert!(matches!(added, Ok(MlsCommitOutcome::Won)), "{:?}", added);
        post(
            db,
            &text.member,
            &text.member_session,
            &group_id,
            signed_intent(&text.member_device, &group_id, "m1"),
        )
        .await
        .expect("the rejoin intent");
        let intent = db
            .fetch_mls_join_intents_for_group(&group_id)
            .await
            .expect("intents")
            .into_iter()
            .find(|intent| intent.device_id == member_leaf.device_id)
            .expect("the stored intent");
        let later = |hours: i64| {
            intent
                .created_at
                .checked_add(Duration::hours(hours))
                .expect("a time")
        };
        let is_member =
            |group: &MlsGroup| group.has_member(&member_leaf.user_id, &member_leaf.device_id);

        // 25 h on: past the window, so no rule admits the Remove
        refused(
            commit_at(
                harness,
                &group_id,
                owner_device,
                vec![],
                vec![member_leaf.clone()],
                later(25),
            )
            .await,
            "FailedValidation",
            "a 25 h old intent",
        );
        assert!(is_member(
            &db.fetch_mls_group(&group_id).await.expect("the group")
        ));

        // 23 h on: still outstanding, so it evicts (rule 6, recorded for the
        // recovery re-Add) and is consumed
        let evicted = commit_at(
            harness,
            &group_id,
            owner_device,
            vec![],
            vec![member_leaf.clone()],
            later(23),
        )
        .await;
        assert!(
            matches!(evicted, Ok(MlsCommitOutcome::Won)),
            "{:?}",
            evicted
        );
        let group = db.fetch_mls_group(&group_id).await.expect("the group");
        assert!(!is_member(&group));
        assert!(group.rejoin_readd.iter().any(|entry| {
            entry.user_id == member_leaf.user_id && entry.device_id == member_leaf.device_id
        }));
        assert!(stored_intents(db, &group_id).await.is_empty());
    }

    /// #212: the join intent's cap count leaves out a device listed in
    /// `pending_device_removals` (the Add that follows must remove it in
    /// the same commit), and nothing else
    #[test]
    fn the_device_cap_excludes_pending_device_removals_only() {
        crate::util::test::rt()
            .block_on(the_device_cap_excludes_pending_device_removals_only_case())
    }

    async fn the_device_cap_excludes_pending_device_removals_only_case() {
        let text = text_fixture().await;
        let harness = &text.harness;
        let db = &harness.db;
        let group_id = text.group.id.clone();
        let owner_device = &text.protected.owner_device;

        // Entitlement cap 2, and the member holds 2 member devices
        harness
            .grant_entitlement(&text.protected.channel, FIXTURE_SLOT_CAP, Some(2))
            .await;
        let second = registered_leaf(harness, &text.member, 0x21).await;
        add_to_group(
            harness,
            &group_id,
            owner_device,
            vec![leaf(&text.member_device), second.clone()],
        )
        .await;
        let (third_session, third) =
            new_bound_device(harness, &text.member_account, &text.member, 0x23).await;
        let third_intent = || signed_intent(&third, &group_id, "m3");
        let body = refused(
            post(db, &text.member, &third_session, &group_id, third_intent()).await,
            "DeviceCapReached",
            "at the cap",
        );
        assert_eq!(body["max"], 2, "{}", body);

        // The second device is queued for removal, so it no longer counts
        let channels = db
            .add_pending_device_removal(&second.user_id, &second.device_id, Timestamp::now_utc())
            .await
            .expect("the pending entry");
        assert_eq!(channels, vec![text.protected.channel.id().to_string()]);
        post(db, &text.member, &third_session, &group_id, third_intent())
            .await
            .expect("under the cap once the pending device is left out");
        assert!(stored_intents(db, &group_id)
            .await
            .contains(&(text.member.id.clone(), third.device_id.clone())));
    }

    /// How the list signer's device was lost
    enum SignerLoss {
        /// The open group carries `signer_lost`; the identity is still there
        Flagged,
        /// The identity is gone and nothing set `signer_lost`
        IdentityGone,
    }

    /// #213 with the growth flag off: the signer user's replacement device
    /// is growth until the signer device is lost, then recovery; the lost
    /// device's leaf still counts toward the cap (#212); a seated member's
    /// new device stays growth throughout
    async fn the_signer_users_replacement_is_recovery(loss: SignerLoss) {
        let text = text_fixture().await;
        let harness = &text.harness;
        let db = &harness.db;
        let group_id = text.group.id.clone();
        let owner_device = &text.protected.owner_device;
        let (replacement_session, replacement) = new_bound_device(
            harness,
            &text.owner_account,
            &text.owner,
            NEW_OWNER_DEVICE_SEED,
        )
        .await;
        let replacement_intent = || signed_intent(&replacement, &group_id, "r1");

        let body = refused(
            post(
                db,
                &text.owner,
                &replacement_session,
                &group_id,
                replacement_intent(),
            )
            .await,
            "FeatureDisabled",
            "before the loss",
        );
        assert_eq!(body["feature"], "protected_channels", "{}", body);

        match loss {
            SignerLoss::Flagged => {
                let channels = db
                    .add_pending_device_removal(
                        &owner_device.user_id,
                        &owner_device.device_id,
                        Timestamp::now_utc(),
                    )
                    .await
                    .expect("signer_lost");
                assert_eq!(channels, vec![text.protected.channel.id().to_string()]);
                let group = db.fetch_mls_group(&group_id).await.expect("the group");
                assert!(group.signer_lost.is_some());
                db.fetch_e2ee_identity(&owner_device.user_id, &owner_device.device_id)
                    .await
                    .expect("the signer identity is still registered");
            }
            SignerLoss::IdentityGone => {
                assert!(db
                    .delete_e2ee_device(&owner_device.user_id, &owner_device.device_id)
                    .await
                    .expect("the identity delete"));
                let group = db.fetch_mls_group(&group_id).await.expect("the group");
                assert!(group.signer_lost.is_none());
            }
        }

        // The lost device still holds its leaf: at cap 1 the replacement is
        // refused, and recovery goes through a successor instead (§6.3)
        harness
            .grant_entitlement(&text.protected.channel, FIXTURE_SLOT_CAP, Some(1))
            .await;
        let body = refused(
            post(
                db,
                &text.owner,
                &replacement_session,
                &group_id,
                replacement_intent(),
            )
            .await,
            "DeviceCapReached",
            "the lost leaf counts",
        );
        assert_eq!(body["max"], 1, "{}", body);

        harness
            .grant_entitlement(&text.protected.channel, FIXTURE_SLOT_CAP, None)
            .await;
        post(
            db,
            &text.owner,
            &replacement_session,
            &group_id,
            replacement_intent(),
        )
        .await
        .expect("the replacement device, growth off");
        assert!(stored_intents(db, &group_id)
            .await
            .contains(&(text.owner.id.clone(), replacement.device_id.clone())));

        let body = refused(
            post(
                db,
                &text.member,
                &text.member_session,
                &group_id,
                signed_intent(&text.member_device, &group_id, "m1"),
            )
            .await,
            "FeatureDisabled",
            "a member's new device",
        );
        assert_eq!(body["feature"], "protected_channels", "{}", body);
    }

    #[test]
    fn growth_off_admits_the_signer_users_replacement_while_signer_lost() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            the_signer_users_replacement_is_recovery(SignerLoss::Flagged).await
        })
    }

    #[test]
    fn growth_off_admits_the_signer_users_replacement_when_its_identity_is_gone() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            the_signer_users_replacement_is_recovery(SignerLoss::IdentityGone).await
        })
    }

    /// One caller class of the oracle
    struct Caller {
        class: &'static str,
        user: User,
        session: Session,
        /// Its device, when it has one
        device: Option<TestE2EEDevice>,
    }

    impl Caller {
        /// A well-formed intent for `group_id` (signed when the caller has a
        /// device), or a malformed one (a bad device id)
        fn body(&self, group_id: &str, malformed: bool) -> v0::DataMlsJoinIntent {
            let mut body = match &self.device {
                Some(device) => signed_intent(device, group_id, "k1"),
                None => v0::DataMlsJoinIntent {
                    device_id: format!("{:032x}", 0xb07),
                    key_package_ref: "k1".to_string(),
                    signature: STANDARD_NO_PAD.encode([1u8; 64]),
                    generation: None,
                    issued_at: None,
                    protocol: None,
                },
            };
            if malformed {
                body.device_id = "not-a-device".to_string();
            }
            body
        }
    }

    struct Oracle {
        harness: TestHarness,
        owner: User,
        owner_session: Session,
        owner_device: TestE2EEDevice,
        callers: Vec<Caller>,
        hidden_group_id: String,
        hidden_channel_id: String,
        deleted_group_id: String,
        unknown_group_id: String,
    }

    /// As the `routes::mls` gate oracle: a protected channel whose Text
    /// group exists but which members cannot view (`@everyone` denied
    /// ViewChannel), a second protected channel deleted under its Text
    /// group, and one caller of each class: a member with a bound device, a
    /// bot (a member, no device) and a member whose session is bound to
    /// none of its devices
    async fn oracle_fixture() -> Oracle {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, bot_session, mut bot) = harness.new_user().await;
        let (_, unbound_session, unbound) = harness.new_user().await;

        let hidden = harness
            .new_protected_channel(&owner, &owner_session, &[])
            .await;
        for user in [&member, &bot, &unbound] {
            harness.join_server(&hidden.server, user).await;
        }
        bot.bot = Some(BotInformation {
            owner: owner.id.clone(),
        });
        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, 41)
            .await;
        let unbound_device = harness
            .new_e2ee_device(&unbound, &Ulid::new().to_string(), 42)
            .await;
        let mut hidden_channel = hidden.channel.clone();
        hidden_channel
            .update(
                db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ViewChannel as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny view");
        let hidden_group = harness
            .new_text_group(&hidden.channel, &hidden.owner_device, 0, None)
            .await;

        let (_, other_owner_session, other_owner) = harness.new_user().await;
        let deleted = harness
            .new_protected_channel(&other_owner, &other_owner_session, &[])
            .await;
        let deleted_group = harness
            .new_text_group(&deleted.channel, &deleted.owner_device, 0, None)
            .await;
        db.delete_channel(&deleted.channel)
            .await
            .expect("delete the channel");
        assert!(db.fetch_channel(deleted.channel.id()).await.is_err());

        Oracle {
            harness,
            owner,
            owner_session,
            owner_device: hidden.owner_device,
            callers: vec![
                Caller {
                    class: "member",
                    user: member,
                    session: member_session,
                    device: Some(member_device),
                },
                Caller {
                    class: "bot",
                    user: bot,
                    session: bot_session,
                    device: None,
                },
                Caller {
                    class: "unbound",
                    user: unbound,
                    session: unbound_session,
                    device: Some(unbound_device),
                },
            ],
            hidden_group_id: hidden_group.id,
            hidden_channel_id: hidden.channel.id().to_string(),
            deleted_group_id: deleted_group.id,
            unknown_group_id: format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0),
        }
    }

    /// The response body a refusal serializes to
    #[track_caller]
    fn refusal_body(result: Result<EmptyResponse>, case: &str) -> String {
        match result {
            Err(error) => serde_json::to_string(&error).expect("an error body"),
            Ok(_) => panic!("{}: accepted", case),
        }
    }

    /// WA#1, RR#1, RR2#1: for every caller class and a valid or malformed
    /// body, a Text group whose channel the caller cannot view, and one
    /// whose channel was deleted, answer EXACTLY as a group id the server
    /// does not know (the full serialized body, which carries no `location`)
    async fn hidden_and_deleted_text_groups_answer_as_unknown() {
        let oracle = oracle_fixture().await;
        let db = &oracle.harness.db;
        let media = revolt_database::voice::media_e2ee_enabled().await;
        let features = revolt_config::config().await.features;

        // Both are stored Text groups, so the oracle compares a real Text
        // path with the unknown path
        for group_id in [&oracle.hidden_group_id, &oracle.deleted_group_id] {
            assert!(matches!(
                dispatch_group(db, group_id).await,
                Ok(GroupDispatch::Text(_))
            ));
        }
        let channel = db
            .fetch_channel(&oracle.hidden_channel_id)
            .await
            .expect("the hidden channel");

        // The owner (a viewer, seated, bound) reaches the join rules. Its
        // device holds the group's leaf, so its intent is a rejoin, which is
        // recovery (S2-D32): served whenever E2EE is on, growth or media
        // flag or not
        let owner_answer = post(
            db,
            &oracle.owner,
            &oracle.owner_session,
            &oracle.hidden_group_id,
            signed_intent(&oracle.owner_device, &oracle.hidden_group_id, "o1"),
        )
        .await;
        if features.e2ee_enabled {
            owner_answer.expect("the owner is served");
        } else {
            let body = refused(owner_answer, "FeatureDisabled", "the owner, E2EE off");
            assert_eq!(body["feature"], "e2ee", "{}", body);
        }

        for caller in &oracle.callers {
            assert!(
                require_channel_access(db, &caller.user, &channel)
                    .await
                    .is_err(),
                "{} views the hidden channel",
                caller.class
            );
            for (shape, malformed) in [("valid", false), ("malformed", true)] {
                let case = format!("{} {}", caller.class, shape);
                let unknown = refusal_body(
                    post(
                        db,
                        &caller.user,
                        &caller.session,
                        &oracle.unknown_group_id,
                        caller.body(&oracle.unknown_group_id, malformed),
                    )
                    .await,
                    &format!("unknown {case}"),
                );

                // Each class gets its own answer, so the classes are real
                let value: serde_json::Value = serde_json::from_str(&unknown).expect("JSON");
                let expected = match (media, caller.class) {
                    (false, _) => "FeatureDisabled",
                    (true, "bot") => "IsBot",
                    (true, "unbound") => "NotAuthenticated",
                    (true, _) => "NotFound",
                };
                assert_eq!(value["type"], expected, "{}: {}", case, unknown);
                if !media {
                    assert_eq!(value["feature"], "media_e2ee", "{}: {}", case, unknown);
                }

                for (target, group_id) in [
                    ("hidden", &oracle.hidden_group_id),
                    ("deleted", &oracle.deleted_group_id),
                ] {
                    let answer = refusal_body(
                        post(
                            db,
                            &caller.user,
                            &caller.session,
                            group_id,
                            caller.body(group_id, malformed),
                        )
                        .await,
                        &format!("{target} {case}"),
                    );
                    assert_eq!(answer, unknown, "{} {}", target, case);
                }
            }
        }

        // Nothing a non-viewer sent was stored
        for group_id in [&oracle.hidden_group_id, &oracle.deleted_group_id] {
            for (user_id, _) in stored_intents(db, group_id).await {
                assert_eq!(user_id, oracle.owner.id);
            }
        }
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_every_flag_on() {
        crate::util::test::rt().block_on(hidden_and_deleted_text_groups_answer_as_unknown())
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_answer_as_unknown().await
        })
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_answer_as_unknown().await
        })
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_answer_as_unknown().await
        })
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_growth_and_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_answer_as_unknown().await
        })
    }
}
