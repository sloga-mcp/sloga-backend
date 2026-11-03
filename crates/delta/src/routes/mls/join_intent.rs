use std::collections::HashSet;

use iso8601_timestamp::Timestamp;
use revolt_database::voice::{get_channel_node, is_screen_leg, VoiceClient};
use revolt_database::{
    events::client::EventV1, is_valid_device_id, is_valid_key_package_ref, mls_join_intent_payload,
    mls_text_enforced_device_cap, Database, E2EEIdentity, MlsGroup, MlsJoinIntent, MlsMemberDevice,
    SeatListBody, Session, User, MAX_MLS_GROUP_MEMBERS,
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

/// What the call path does with a join intent from a user whose OTHER
/// device holds the group's only leaf
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SiblingVerdict {
    /// The plain "another device" 400
    Refuse,
    /// Close the group: its only leaf-holder has left the call
    CloseUnservable,
}

/// The sibling close's decision (sibling-device plan §3), pure. `live` is
/// the call's SFU-live member devices as (user, device), `None` when the
/// SFU gave no answer to act on: an unanswered SFU never closes. A sibling
/// still in the call refuses too (two live seats, a failed eviction).
pub(crate) fn sibling_verdict(
    user_id: &str,
    sibling_device_id: &str,
    live: Option<&HashSet<(String, String)>>,
) -> SiblingVerdict {
    match live {
        None => SiblingVerdict::Refuse,
        Some(live) if live.contains(&(user_id.to_string(), sibling_device_id.to_string())) => {
            SiblingVerdict::Refuse
        }
        Some(_) => SiblingVerdict::CloseUnservable,
    }
}

/// Whether the sibling's registration read says its identity row is gone,
/// by error type. A read error is no evidence either way. Pure.
pub(crate) fn sibling_registration_gone<T>(registration: &Result<T>) -> bool {
    matches!(registration, Err(error) if matches!(error.error_type, ErrorType::NotFound))
}

/// The member devices among SFU participant identities, as (user, device).
/// A screen leg is a helper of its owner, never a member, and a bare
/// identity names no device, so neither counts; only an identity of exactly
/// two non-empty `:` segments does. Pure.
pub(crate) fn live_member_devices(
    identities: impl IntoIterator<Item = String>,
) -> HashSet<(String, String)> {
    identities
        .into_iter()
        .filter(|identity| !is_screen_leg(identity))
        .filter_map(|identity| {
            let mut segments = identity.split(':');
            match (segments.next(), segments.next(), segments.next()) {
                (Some(user), Some(device), None) if !user.is_empty() && !device.is_empty() => {
                    Some((user.to_string(), device.to_string()))
                }
                _ => None,
            }
        })
        .collect()
}

/// The call's SFU-live member devices, or `None` when there is no answer
/// to act on: no node pinned for the channel, a Redis failure, no such room
/// on the SFU, or a failed listing. Never an error; the caller refuses on
/// `None`.
async fn live_call_devices(
    voice_client: &VoiceClient,
    channel_id: &str,
) -> Option<HashSet<(String, String)>> {
    let node = get_channel_node(channel_id).await.ok().flatten()?;
    match voice_client
        .list_participants_if_present(&node, channel_id)
        .await
    {
        Ok(Some(participants)) => Some(live_member_devices(
            participants
                .into_iter()
                .map(|participant| participant.identity),
        )),
        Ok(None) | Err(_) => None,
    }
}

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
///
/// A protected channel's Text group takes its own path (protected channels
/// design §6.1 "Join intent"): the caller must be seated, a user may join
/// with several devices up to the enforced device cap, and the route never
/// closes the group.
#[openapi(tag = "MLS")]
#[post("/groups/<group_id>/join_intent", data = "<data>")]
pub async fn join_intent(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
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
            call_join_intent(db, voice_client, user, session, group_id, data.into_inner()).await
        }
        GroupDispatch::Text(group) => {
            text_join_intent(db, &user, &session, group, data.into_inner()).await
        }
    }
}

/// The call path, unchanged by protected channels
async fn call_join_intent(
    db: &Database,
    voice_client: &VoiceClient,
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
    // A user holds one seat in a call: a second device's join
    // force-disconnects the first, so a second leaf of one user is only
    // ever a stale one.
    // ANOTHER device of the user as the SOLE member = a stale sibling
    // (sibling-device plan §3): the only leaf-holder is this user's own
    // device, evicted by this newer join, so nobody is left to admit
    // anyone. Mirroring the solo-stale close below, close the group, on
    // positive evidence only: the sibling's registration is gone (a removed
    // device, checked before the SFU is asked), or the SFU answered and the
    // sibling is not in the call. NotFound sends the joiner straight to
    // CREATE through the client's not_found arm. Anything else, a failed
    // registration read included, keeps the 400.
    // SAME device already a member = a REJOIN: the device wiped its local
    // group state (rejoin-fresh) but its stale leaf is still in the roster,
    // and it can never remove itself (RFC 9420 forbids self-removal). Fan
    // the intent out flagged `rejoin` so verifying members remove the stale
    // leaf; the device's next normal intent then rides the unchanged
    // admit path (rejoin-affordance plan §3.1).
    let mut rejoin = false;
    if let Some(existing) = group.member_device_of(&user.id) {
        if existing.device_id != data.device_id {
            if revolt_config::config().await.features.mls_sibling_close && group.members.len() == 1
            {
                let registration = db.fetch_e2ee_identity(&user.id, &existing.device_id).await;
                if sibling_registration_gone(&registration) {
                    db.close_mls_group(&group.id).await?;
                    log::info!(
                        "mls: closed call group {} in channel {}: sole leaf was a removed sibling",
                        group.id,
                        group.channel_id
                    );
                    return Err(create_error!(NotFound));
                }

                let live = live_call_devices(voice_client, &group.channel_id).await;
                if sibling_verdict(&user.id, &existing.device_id, live.as_ref())
                    == SiblingVerdict::CloseUnservable
                {
                    db.close_mls_group(&group.id).await?;
                    log::info!(
                        "mls: closed call group {} in channel {}: sole leaf was a stale sibling",
                        group.id,
                        group.channel_id
                    );
                    return Err(create_error!(NotFound));
                }
            }
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

    let intent = join_intent_row(&group, &user.id, &data);
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

    fan_out_join_requested(&group, &user.id, &data, rejoin).await;

    Ok(EmptyResponse)
}

/// The Text path (protected channels design §6.1), in decision 1 (W2)
/// order: the group's channel and ViewChannel, where any failure answers
/// [`super::as_unknown_group`] so a hidden or deleted channel's group is
/// indistinguishable from an unknown id; the shared caller checks; request
/// validation; the growth gate (a join is growth, decision 5 (W2)); the
/// caller's seat; then the join rules.
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
    super::require_text_gate(TextGate::Growth).await?;
    super::require_seated(db, &group.channel_id, &user.id).await?;

    // A superseded group takes no joins; its successor does
    if !group.open {
        return Err(create_error!(NotFound));
    }

    // The session must be bound to the joining device itself, and the
    // intent signed by it, before anything below is reachable
    let identity = bound_identity(db, &user.id, session, &data.device_id).await?;
    verify_join_signature(&identity, &user.id, &group.id, &data)?;

    // Device-aware: THIS device already a member is a rejoin (members
    // remove its stale leaf under the rejoin case, §3.12.2, and its next
    // intent is admitted as a new device). Any other device is a NEW device
    // of a user who may already have some, refused once the user's member
    // devices reach the enforced cap. The Text commit transaction enforces
    // the same cap on the Add; this refusal only spares the admit round
    // trip and tells the joiner why.
    let rejoin = group.has_member(&user.id, &data.device_id);
    if !rejoin {
        let max = enforced_device_cap(db, &group.channel_id).await?;
        if max != 0 && group.member_devices_of(&user.id).count() >= max as usize {
            return Err(create_error!(DeviceCapReached { max: max as usize }));
        }
    }

    let intent = join_intent_row(&group, &user.id, &data);
    store_join_intent(db, &intent).await?;

    fan_out_join_requested(&group, &user.id, &data, rejoin).await;

    Ok(EmptyResponse)
}

/// The enforced per-user device cap of a channel's Text group (§2.5,
/// W0-fix3): `min(signed-list device_cap, effective entitlement cap)`, `0`
/// meaning unlimited in either operand, so `0` here is unlimited too.
///
/// A new device is an Add to come, and an Add needs an Active entitlement
/// (§6.1 errors), so a missing or inactive one refuses the new device here
/// rather than at the admitter's commit.
async fn enforced_device_cap(db: &Database, channel_id: &str) -> Result<u32> {
    let entitlement = db
        .fetch_channel_entitlement(channel_id)
        .await?
        .filter(|entitlement| entitlement.is_active())
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

/// The stored intent row, stamped now
fn join_intent_row(group: &MlsGroup, user_id: &str, data: &v0::DataMlsJoinIntent) -> MlsJoinIntent {
    MlsJoinIntent {
        id: MlsJoinIntent::composite_id(&group.id, user_id, &data.device_id),
        group_id: group.id.clone(),
        user_id: user_id.to_string(),
        device_id: data.device_id.clone(),
        key_package_ref: data.key_package_ref.clone(),
        signature: data.signature.clone(),
        created_at: Timestamp::now_utc(),
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
/// and self-schedule admission with leaf-index staggered timers
async fn fan_out_join_requested(
    group: &MlsGroup,
    user_id: &str,
    data: &v0::DataMlsJoinIntent,
    rejoin: bool,
) {
    let member_users: HashSet<String> = group
        .members
        .iter()
        .map(|member| member.user_id.clone())
        .collect();

    for member_user in member_users {
        EventV1::MlsJoinRequested {
            group_id: group.id.clone(),
            channel_id: group.channel_id.clone(),
            user_id: user_id.to_string(),
            device_id: data.device_id.clone(),
            key_package_ref: data.key_package_ref.clone(),
            signature: data.signature.clone(),
            rejoin,
        }
        .private(member_user)
        .await;
    }
}

/// The Text path (W2 decisions 1, 5 and 7, design §6.1 "Join intent").
/// Every flag case is its own `#[test]`: `overwrite_config` runs once per
/// process, BEFORE the harness primes the config cache, so these need
/// nextest (one process per test). The test config has every flag on.
#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        events::client::EventV1, mls_join_intent_payload, Account, BotInformation,
        ChannelEntitlementState, Database, MlsCommit, MlsCommitOutcome, MlsGroup, MlsMemberDevice,
        PartialChannel, Session, User,
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
        ProtectedChannel, TestE2EEDevice, TestHarness, FIXTURE_DEVICE_CAP, FIXTURE_SLOT_CAP,
        MEMBER_DEVICE_SEED,
    };

    /// Call the route as rocket does
    async fn post(
        db: &Database,
        user: &User,
        session: &Session,
        group_id: &str,
        data: v0::DataMlsJoinIntent,
    ) -> Result<EmptyResponse> {
        use revolt_database::voice::VoiceClient;
        use std::collections::HashMap;

        // No SFU nodes: the Text path never lists, and on a call group the
        // sibling close gets no SFU answer, so it refuses
        let voice_client = VoiceClient::new(HashMap::new());
        join_intent(
            <&State<Database>>::from(db),
            <&State<VoiceClient>>::from(&voice_client),
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
        }
    }

    /// `device` as a group member entry
    fn leaf(device: &TestE2EEDevice) -> MlsMemberDevice {
        MlsMemberDevice {
            user_id: device.user_id.clone(),
            device_id: device.device_id.clone(),
        }
    }

    /// A device id of `user` that is in no directory (a leaf only)
    fn synthetic_device(user: &User, index: u32) -> MlsMemberDevice {
        MlsMemberDevice {
            user_id: user.id.clone(),
            device_id: format!("{:032x}", 0xd0_0000 + index),
        }
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

    /// The `MlsJoinRequested` on `topic_user`'s private topic for `device`
    /// and `key_package_ref`; returns its `rejoin` flag
    async fn join_requested(
        harness: &mut TestHarness,
        topic_user: &str,
        group_id: &str,
        device: &TestE2EEDevice,
        key_package_ref: &str,
    ) -> bool {
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
                user_id, rejoin, ..
            } => {
                assert_eq!(user_id, device.user_id);
                rejoin
            }
            other => panic!("not a join request: {:?}", other),
        }
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
        let group = add_to_group(
            harness,
            &group_id,
            owner_device,
            (1..=3).map(|i| synthetic_device(&text.owner, i)).collect(),
        )
        .await;
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
            vec![leaf(&text.member_device), synthetic_device(&text.member, 1)],
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

    #[test]
    fn an_inactive_entitlement_refuses_new_devices_only() {
        crate::util::test::rt().block_on(an_inactive_entitlement_refuses_new_devices_only_case())
    }

    async fn an_inactive_entitlement_refuses_new_devices_only_case() {
        let text = text_fixture().await;
        let db = &text.harness.db;
        let group_id = &text.group.id;

        freeze_entitlement(db, text.protected.channel.id()).await;

        // A new device would need an Add, and Adds need an Active entitlement
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

        // A rejoin only needs a Remove, which never needs the entitlement
        post(
            db,
            &text.owner,
            &text.owner_session,
            group_id,
            signed_intent(&text.protected.owner_device, group_id, "o1"),
        )
        .await
        .expect("a rejoin");
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

    /// The flag cases: a seated member's new device, and the owner's rejoin.
    /// `refusal` is the expected `FeatureDisabled` feature, `None` = served.
    async fn text_join_under_flags(refusal: Option<&str>) {
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

        match refusal {
            None => {
                new_device.expect("a new device");
                rejoin.expect("a rejoin");
                assert_eq!(stored_intents(db, group_id).await.len(), 2);
            }
            Some(feature) => {
                for (case, result) in [("new device", new_device), ("rejoin", rejoin)] {
                    let body = refused(result, "FeatureDisabled", case);
                    assert_eq!(body["feature"], feature, "{}: {}", case, body);
                }
                assert!(stored_intents(db, group_id).await.is_empty());
            }
        }
        assert_open_with(db, group_id, &text.group.members).await;
    }

    #[test]
    fn a_text_join_with_every_flag_on_is_accepted() {
        crate::util::test::rt().block_on(text_join_under_flags(None))
    }

    #[test]
    fn a_text_join_with_growth_off_is_refused() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            text_join_under_flags(Some("protected_channels")).await
        })
    }

    #[test]
    fn a_text_join_with_e2ee_off_is_refused() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            text_join_under_flags(Some("e2ee")).await
        })
    }

    #[test]
    fn a_text_join_ignores_the_media_flag() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            text_join_under_flags(None).await
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

        // The owner (a viewer, seated, bound) reaches the join rules: served
        // whenever the growth gate passes, media flag or not
        let owner_answer = post(
            db,
            &oracle.owner,
            &oracle.owner_session,
            &oracle.hidden_group_id,
            signed_intent(&oracle.owner_device, &oracle.hidden_group_id, "o1"),
        )
        .await;
        if features.e2ee_enabled && features.protected_channels.enabled {
            owner_answer.expect("the owner is served");
        } else {
            refused(owner_answer, "FeatureDisabled", "the owner, a gate off");
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

    /// The call path's sibling close (sibling-device plan §3, §4): the
    /// user's device B joins a call group whose only leaf is the same
    /// user's device A. The call path is driven directly with a
    /// `VoiceClient` whose one node is a loopback stub answering as a
    /// LiveKit Twirp endpoint does, and the channel is pinned to that node
    /// in Redis as `join_call` pins it. The flag case is its own `#[test]`,
    /// as above.
    mod sibling_close {
        use std::{
            collections::HashMap,
            io::{Read, Write},
            net::{SocketAddr, TcpListener, TcpStream},
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc, Mutex, PoisonError,
            },
            thread::JoinHandle,
            time::Duration,
        };

        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
        use iso8601_timestamp::Timestamp;
        use revolt_config::LiveKitNode;
        use revolt_database::{
            voice::{delete_channel_node, screen_leg_identity, set_channel_node, VoiceClient},
            Database, MlsGroup, MlsGroupCreateOutcome, MlsGroupKind, MlsMemberDevice, Session,
            User,
        };
        use revolt_models::v0;
        use revolt_result::{create_database_error, create_error, Result};
        use rocket_empty::EmptyResponse;
        use ulid::Ulid;

        use super::super::{call_join_intent, sibling_registration_gone};
        use super::{leaf, new_bound_device, refused, signed_intent, stored_intents};
        use crate::util::test::{TestE2EEDevice, TestHarness};

        /// The node the stub is registered under (in no `Revolt.toml`)
        const NODE: &str = "sibling-close-stub-node";

        /// The one SFU call the sibling close makes
        const LIST: &str = "/twirp/livekit.RoomService/ListParticipants";

        /// The refusal the client cites, unchanged by the sibling close
        const SIBLING_REFUSAL: &str = "another device of this user is already in the call group";

        /// (status line, content type, body)
        type Reply = (&'static str, &'static str, Vec<u8>);

        /// A Twirp 200 carrying a protobuf `ListParticipantsResponse`
        fn listed(body: Vec<u8>) -> Reply {
            ("HTTP/1.1 200 OK", "application/protobuf", body)
        }

        /// The SFU's structured "no such room": `Ok(None)` to the listing
        fn no_such_room() -> Reply {
            (
                "HTTP/1.1 404 Not Found",
                "application/json",
                br#"{"code":"not_found","msg":"stub: not found"}"#.to_vec(),
            )
        }

        /// A real SFU failure: `Err` to the listing
        fn internal() -> Reply {
            (
                "HTTP/1.1 500 Internal Server Error",
                "application/json",
                br#"{"code":"internal","msg":"stub: boom"}"#.to_vec(),
            )
        }

        fn encode_varint(mut value: usize, out: &mut Vec<u8>) {
            while value >= 0x80 {
                out.push((value as u8 & 0x7f) | 0x80);
                value >>= 7;
            }
            out.push(value as u8);
        }

        fn length_delimited(tag: u8, payload: &[u8]) -> Vec<u8> {
            let mut out = vec![(tag << 3) | 2];
            encode_varint(payload.len(), &mut out);
            out.extend_from_slice(payload);
            out
        }

        /// Protobuf wire bytes of a `ListParticipantsResponse` listing each
        /// identity: `participants` = field 1, ParticipantInfo `identity` =
        /// field 2, the layout `revolt-database`'s
        /// `sfu_stub::list_participants_response` encodes (its decoding
        /// test reads it back through the real client). No identities = an
        /// empty body, a room with nobody in it.
        fn listing(identities: &[&str]) -> Vec<u8> {
            identities
                .iter()
                .flat_map(|identity| length_delimited(1, &length_delimited(2, identity.as_bytes())))
                .collect()
        }

        /// A `VoiceClient` with one node, [`NODE`], at `url`
        fn stub_client(url: &str) -> VoiceClient {
            VoiceClient::new(HashMap::from([(
                NODE.to_string(),
                LiveKitNode {
                    url: url.to_string(),
                    lat: 0.0,
                    lon: 0.0,
                    key: "stubkey".to_string(),
                    secret: "stubsecret-stubsecret-stubsecret".to_string(),
                    private: true,
                    remote: false,
                },
            )]))
        }

        /// A loopback SFU answering its n-th request with the n-th reply,
        /// and any request past them with [`internal`]
        struct Stub {
            url: String,
            addr: SocketAddr,
            stop: Arc<AtomicBool>,
            /// Every request read, as (path, body)
            seen: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
            thread: Option<JoinHandle<()>>,
        }

        impl Stub {
            fn serve(replies: Vec<Reply>) -> Stub {
                let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
                let addr = listener.local_addr().expect("local addr");
                let stop = Arc::new(AtomicBool::new(false));
                let seen = Arc::new(Mutex::new(Vec::new()));

                let thread = {
                    let (stop, seen) = (stop.clone(), seen.clone());
                    std::thread::spawn(move || {
                        let mut replies = replies.into_iter();
                        for stream in listener.incoming() {
                            if stop.load(Ordering::SeqCst) {
                                break;
                            }
                            let Ok(mut stream) = stream else { continue };
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                            let Some((head, body)) = read_request(&mut stream) else {
                                continue;
                            };
                            let path = head
                                .split_whitespace()
                                .nth(1)
                                .unwrap_or_default()
                                .to_string();
                            seen.lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .push((path, body));
                            let reply = replies.next().unwrap_or_else(internal);
                            let _ = write_response(&mut stream, &reply);
                        }
                    })
                };

                Stub {
                    url: format!("http://{addr}"),
                    addr,
                    stop,
                    seen,
                    thread: Some(thread),
                }
            }

            /// Stop the stub and return every request it read, in order
            fn finish(mut self) -> Vec<(String, Vec<u8>)> {
                if let Some(thread) = self.stop_thread() {
                    thread.join().expect("the SFU stub thread panicked");
                }
                self.seen
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()
            }

            fn stop_thread(&mut self) -> Option<JoinHandle<()>> {
                let thread = self.thread.take()?;
                self.stop.store(true, Ordering::SeqCst);
                // Wake the blocking accept; the loop sees `stop` and ends
                let _ = TcpStream::connect(self.addr);
                Some(thread)
            }
        }

        impl Drop for Stub {
            fn drop(&mut self) {
                if let Some(thread) = self.stop_thread() {
                    let _ = thread.join();
                }
            }
        }

        /// Read one whole HTTP request (head plus `content-length` body, so
        /// closing never resets an unread request). `None` if the peer
        /// closed or stalled first.
        fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let read = stream.read(&mut chunk).ok()?;
                if read == 0 {
                    return None;
                }
                request.extend_from_slice(&chunk[..read]);

                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&request[..end]).to_string();
                    let length = head
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|value| value.trim().to_string())
                        })
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(0);

                    if request.len() >= end + 4 + length {
                        let body = request[end + 4..end + 4 + length].to_vec();
                        return Some((head, body));
                    }
                }
            }
        }

        /// Write one reply and let the connection close
        fn write_response(stream: &mut TcpStream, reply: &Reply) -> std::io::Result<()> {
            let (status_line, content_type, body) = reply;
            let mut response = format!(
                "{status_line}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(body);
            stream.write_all(&response)
        }

        struct Sibling {
            harness: TestHarness,
            user: User,
            /// Bound to `joiner`
            session: Session,
            /// Device A, bound to the user's first session: the leaf
            sibling: TestE2EEDevice,
            /// Device B, which joins
            joiner: TestE2EEDevice,
            channel_id: String,
        }

        /// A user owning a server channel, with two registered devices
        async fn sibling_fixture() -> Sibling {
            let harness = TestHarness::new().await;
            let (account, first_session, user) = harness.new_user().await;
            let (_, channel) = harness.new_protectable_channel(&user).await;
            let sibling = harness
                .new_e2ee_device(&user, &first_session.id, 0x50)
                .await;
            let (session, joiner) = new_bound_device(&harness, &account, &user, 0x51).await;
            assert_ne!(sibling.device_id, joiner.device_id);

            Sibling {
                harness,
                user,
                session,
                sibling,
                joiner,
                channel_id: channel.id().to_string(),
            }
        }

        /// An open call group in the fixture's channel holding `members`
        /// (the first is its creator), stored through the database primitive
        async fn call_group(fixture: &Sibling, members: Vec<MlsMemberDevice>) -> MlsGroup {
            let db = &fixture.harness.db;
            let group = MlsGroup {
                id: format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0),
                channel_id: fixture.channel_id.clone(),
                open: true,
                created_by: members[0].clone(),
                created_at: Timestamp::now_utc(),
                current_epoch: 0,
                members,
                closed_at: None,
                superseded_by: None,
                kind: MlsGroupKind::Call,
                generation: None,
                seat_list_ad_sha256: None,
                pending_removals: vec![],
                member_added: vec![],
            };
            assert!(matches!(
                db.create_mls_group(&group, None).await.expect("call group"),
                MlsGroupCreateOutcome::Created
            ));
            db.fetch_mls_group(&group.id).await.expect("the call group")
        }

        /// `data` through the call path as the fixture's user on B's
        /// session, against a stub SFU answering `replies`, with the
        /// group's channel pinned to the stub's node when `pinned` (and
        /// unpinned before returning). Returns the answer and every request
        /// the SFU read, as (path, whether it names the channel as the room).
        async fn join(
            fixture: &Sibling,
            group: &MlsGroup,
            data: v0::DataMlsJoinIntent,
            pinned: bool,
            replies: Vec<Reply>,
        ) -> (Result<EmptyResponse>, Vec<(String, bool)>) {
            let stub = Stub::serve(replies);
            let voice_client = stub_client(&stub.url);
            if pinned {
                set_channel_node(&group.channel_id, NODE)
                    .await
                    .expect("pin the node");
            }
            let result = call_join_intent(
                &fixture.harness.db,
                &voice_client,
                fixture.user.clone(),
                fixture.session.clone(),
                group.id.clone(),
                data,
            )
            .await;
            if pinned {
                delete_channel_node(&group.channel_id)
                    .await
                    .expect("unpin the node");
            }

            let room = group.channel_id.as_bytes();
            let seen = stub
                .finish()
                .into_iter()
                .map(|(path, body)| {
                    let names_room = body.windows(room.len()).any(|window| window == room);
                    (path, names_room)
                })
                .collect();
            (result, seen)
        }

        /// B's valid intent for `group`
        fn intent(fixture: &Sibling, group: &MlsGroup) -> v0::DataMlsJoinIntent {
            signed_intent(&fixture.joiner, &group.id, "b1")
        }

        /// The listing the SFU really answers once the sibling has gone:
        /// B itself is live (it sends the intent from inside the call), A's
        /// screen leg lingers, another user holds a seat, and A's own seat
        /// is absent
        fn stale_sibling_listing(fixture: &Sibling) -> Vec<u8> {
            let joiner = format!("{}:{}", fixture.user.id, fixture.joiner.device_id);
            let sibling = format!("{}:{}", fixture.user.id, fixture.sibling.device_id);
            let sibling_leg = screen_leg_identity(&sibling);
            let other = format!("{}:{:032x}", Ulid::new(), 0xf0_0002);
            listing(&[joiner.as_str(), sibling_leg.as_str(), other.as_str()])
        }

        /// The one listing of the group's room
        fn one_listing() -> Vec<(String, bool)> {
            vec![(LIST.to_string(), true)]
        }

        /// The plain "another device" 400, message and all
        #[track_caller]
        fn assert_sibling_refusal(result: Result<EmptyResponse>, case: &str) {
            let body = refused(result, "FailedValidation", case);
            assert_eq!(body["error"], SIBLING_REFUSAL, "{}: {}", case, body);
        }

        /// Whether the group is open (and `closed_at` agrees)
        async fn is_open(db: &Database, group_id: &str) -> bool {
            let group = db.fetch_mls_group(group_id).await.expect("the group");
            assert_eq!(group.open, group.closed_at.is_none(), "{:?}", group);
            group.open
        }

        /// The closing answer, then the group closed with no intent stored
        async fn assert_closed(db: &Database, group: &MlsGroup, result: Result<EmptyResponse>) {
            refused(result, "NotFound", "a sole stale sibling");
            assert!(!is_open(db, &group.id).await, "the group was left open");
            assert!(stored_intents(db, &group.id).await.is_empty());
        }

        /// Delete A's identity row (and its keys) through the driver
        /// primitive, the state a device removal leaves behind
        async fn remove_sibling(fixture: &Sibling) {
            let db = &fixture.harness.db;
            let (user_id, device_id) = (&fixture.user.id, &fixture.sibling.device_id);
            assert!(db
                .delete_e2ee_device(user_id, device_id)
                .await
                .expect("delete the sibling's row"));
            refused(
                db.fetch_e2ee_identity(user_id, device_id).await,
                "NotFound",
                "the removed sibling's row",
            );
        }

        #[test]
        fn a_sole_stale_sibling_closes_the_group() {
            crate::util::test::rt().block_on(a_sole_stale_sibling_closes_the_group_case())
        }

        async fn a_sole_stale_sibling_closes_the_group_case() {
            let fixture = sibling_fixture().await;
            let db = &fixture.harness.db;
            let group = call_group(&fixture, vec![leaf(&fixture.sibling)]).await;

            // The SFU answers for the room, and the sibling is not in it:
            // only its screen leg is, beside the live joiner and another
            // user. A verdict on the joiner's seat would see B live and
            // refuse.
            let (result, seen) = join(
                &fixture,
                &group,
                intent(&fixture, &group),
                true,
                vec![listed(stale_sibling_listing(&fixture))],
            )
            .await;
            assert_eq!(seen, one_listing());
            assert_closed(db, &group, result).await;
        }

        #[test]
        fn a_live_sibling_is_refused() {
            crate::util::test::rt().block_on(a_live_sibling_is_refused_case())
        }

        async fn a_live_sibling_is_refused_case() {
            let fixture = sibling_fixture().await;
            let db = &fixture.harness.db;
            let group = call_group(&fixture, vec![leaf(&fixture.sibling)]).await;

            // The sibling is still registered: its row is no evidence, and
            // the listing decides
            assert!(db
                .fetch_e2ee_identity(&fixture.user.id, &fixture.sibling.device_id)
                .await
                .is_ok());

            // The sibling still holds its seat (a failed eviction) and the
            // joiner is not listed, so only the sibling's own seat can
            // refuse: a verdict on the joiner's seat would close
            let sibling = format!("{}:{}", fixture.user.id, fixture.sibling.device_id);
            let (result, seen) = join(
                &fixture,
                &group,
                intent(&fixture, &group),
                true,
                vec![listed(listing(&[sibling.as_str()]))],
            )
            .await;
            assert_eq!(seen, one_listing());
            assert_sibling_refusal(result, "a live sibling");
            assert!(is_open(db, &group.id).await);
            assert!(stored_intents(db, &group.id).await.is_empty());
        }

        #[test]
        fn a_sibling_beside_another_member_is_refused() {
            crate::util::test::rt().block_on(a_sibling_beside_another_member_is_refused_case())
        }

        async fn a_sibling_beside_another_member_is_refused_case() {
            let fixture = sibling_fixture().await;
            let db = &fixture.harness.db;
            let other = MlsMemberDevice {
                user_id: Ulid::new().to_string(),
                device_id: format!("{:032x}", 0xf0_0001),
            };
            let group = call_group(&fixture, vec![leaf(&fixture.sibling), other]).await;

            // Every member absent from the SFU: another user's leaf may
            // still hold the group, so this is never a sibling close, and
            // the SFU is not even asked
            let (result, seen) = join(
                &fixture,
                &group,
                intent(&fixture, &group),
                true,
                vec![listed(listing(&[]))],
            )
            .await;
            assert_eq!(seen, vec![]);
            assert_sibling_refusal(result, "a sibling beside another member");
            assert!(is_open(db, &group.id).await);
            assert!(stored_intents(db, &group.id).await.is_empty());
        }

        #[test]
        fn a_forged_sibling_intent_never_closes() {
            crate::util::test::rt().block_on(a_forged_sibling_intent_never_closes_case())
        }

        async fn a_forged_sibling_intent_never_closes_case() {
            let fixture = sibling_fixture().await;
            let db = &fixture.harness.db;
            let group = call_group(&fixture, vec![leaf(&fixture.sibling)]).await;

            // A closable group, but the intent is not signed by B: refused
            // by the signature check, before the SFU is asked
            let mut forged = intent(&fixture, &group);
            forged.signature = STANDARD_NO_PAD.encode([0u8; 64]);
            let (result, seen) = join(
                &fixture,
                &group,
                forged,
                true,
                vec![listed(stale_sibling_listing(&fixture))],
            )
            .await;
            assert_eq!(seen, vec![]);
            let body = refused(result, "FailedValidation", "a forged intent");
            assert_eq!(body["error"], "invalid join intent signature", "{}", body);
            assert!(
                is_open(db, &group.id).await,
                "a forged intent closed the group"
            );
            assert!(stored_intents(db, &group.id).await.is_empty());

            // Control: B's genuine intent on the same setup closes it
            let (result, seen) = join(
                &fixture,
                &group,
                intent(&fixture, &group),
                true,
                vec![listed(stale_sibling_listing(&fixture))],
            )
            .await;
            assert_eq!(seen, one_listing());
            assert_closed(db, &group, result).await;
        }

        #[test]
        fn an_unpinned_channel_is_refused() {
            crate::util::test::rt().block_on(an_unpinned_channel_is_refused_case())
        }

        async fn an_unpinned_channel_is_refused_case() {
            let fixture = sibling_fixture().await;
            let db = &fixture.harness.db;
            let group = call_group(&fixture, vec![leaf(&fixture.sibling)]).await;

            // No node pinned for the channel: no SFU to ask, no answer
            let (result, seen) = join(
                &fixture,
                &group,
                intent(&fixture, &group),
                false,
                vec![listed(stale_sibling_listing(&fixture))],
            )
            .await;
            assert_eq!(seen, vec![]);
            assert_sibling_refusal(result, "no node pinned");
            assert!(is_open(db, &group.id).await);
            assert!(stored_intents(db, &group.id).await.is_empty());

            // Control: pinned, the same intent closes it
            let (result, seen) = join(
                &fixture,
                &group,
                intent(&fixture, &group),
                true,
                vec![listed(stale_sibling_listing(&fixture))],
            )
            .await;
            assert_eq!(seen, one_listing());
            assert_closed(db, &group, result).await;
        }

        #[test]
        fn an_unanswered_listing_is_refused() {
            crate::util::test::rt().block_on(an_unanswered_listing_is_refused_case())
        }

        async fn an_unanswered_listing_is_refused_case() {
            let fixture = sibling_fixture().await;
            let db = &fixture.harness.db;
            let group = call_group(&fixture, vec![leaf(&fixture.sibling)]).await;

            // The SFU has no such room (`Ok(None)`), or the listing fails
            // (`Err`): neither is an answer to close on
            for (case, reply) in [
                ("no such room", no_such_room()),
                ("a failed listing", internal()),
            ] {
                let (result, seen) = join(
                    &fixture,
                    &group,
                    intent(&fixture, &group),
                    true,
                    vec![reply],
                )
                .await;
                assert_eq!(seen, one_listing(), "{}", case);
                assert_sibling_refusal(result, case);
                assert!(is_open(db, &group.id).await, "{}", case);
            }
            assert!(stored_intents(db, &group.id).await.is_empty());

            // Control: an answered listing without the sibling closes it
            let (result, seen) = join(
                &fixture,
                &group,
                intent(&fixture, &group),
                true,
                vec![listed(stale_sibling_listing(&fixture))],
            )
            .await;
            assert_eq!(seen, one_listing());
            assert_closed(db, &group, result).await;
        }

        #[test]
        fn the_sibling_close_off_keeps_the_refusal() {
            crate::util::test::rt().block_on(async {
                revolt_config::overwrite_config(|settings| {
                    settings.features.mls_sibling_close = false;
                })
                .await;

                let fixture = sibling_fixture().await;
                let db = &fixture.harness.db;
                let group = call_group(&fixture, vec![leaf(&fixture.sibling)]).await;

                // A sole stale sibling, which closes with the flag on
                let (result, seen) = join(
                    &fixture,
                    &group,
                    intent(&fixture, &group),
                    true,
                    vec![listed(stale_sibling_listing(&fixture))],
                )
                .await;
                assert_eq!(seen, vec![]);
                assert_sibling_refusal(result, "the kill switch off");
                assert!(is_open(db, &group.id).await);
                assert!(stored_intents(db, &group.id).await.is_empty());
            })
        }

        #[test]
        fn only_a_missing_row_reads_as_a_removed_sibling() {
            assert!(sibling_registration_gone::<()>(&Err(create_error!(
                NotFound
            ))));
            assert!(!sibling_registration_gone(&Ok(())));
            assert!(!sibling_registration_gone::<()>(&Err(
                create_database_error!("find_one", "e2ee_identities")
            )));
            assert!(!sibling_registration_gone::<()>(&Err(create_error!(
                InternalError
            ))));
        }

        #[test]
        fn a_sole_removed_sibling_closes_the_group() {
            crate::util::test::rt().block_on(a_sole_removed_sibling_closes_the_group_case())
        }

        async fn a_sole_removed_sibling_closes_the_group_case() {
            let fixture = sibling_fixture().await;
            let db = &fixture.harness.db;
            let group = call_group(&fixture, vec![leaf(&fixture.sibling)]).await;
            remove_sibling(&fixture).await;

            // No node pinned, so the SFU has no answer to give: the missing
            // registration alone closes the group, and the SFU is not asked
            let (result, seen) = join(
                &fixture,
                &group,
                intent(&fixture, &group),
                false,
                vec![listed(stale_sibling_listing(&fixture))],
            )
            .await;
            assert_eq!(seen, vec![]);
            assert_closed(db, &group, result).await;

            // Pinned, with the sibling's seat still listed (a listing alone
            // would refuse): the missing registration closes it first, and
            // the SFU is still not asked
            let group = call_group(&fixture, vec![leaf(&fixture.sibling)]).await;
            let sibling = format!("{}:{}", fixture.user.id, fixture.sibling.device_id);
            let (result, seen) = join(
                &fixture,
                &group,
                intent(&fixture, &group),
                true,
                vec![listed(listing(&[sibling.as_str()]))],
            )
            .await;
            assert_eq!(seen, vec![]);
            assert_closed(db, &group, result).await;
        }

        #[test]
        fn a_removed_sibling_beside_another_member_is_refused() {
            crate::util::test::rt()
                .block_on(a_removed_sibling_beside_another_member_is_refused_case())
        }

        async fn a_removed_sibling_beside_another_member_is_refused_case() {
            let fixture = sibling_fixture().await;
            let db = &fixture.harness.db;
            let other = MlsMemberDevice {
                user_id: Ulid::new().to_string(),
                device_id: format!("{:032x}", 0xf0_0003),
            };
            let group = call_group(&fixture, vec![leaf(&fixture.sibling), other]).await;
            remove_sibling(&fixture).await;

            // Another user's leaf still holds the group, which members
            // repair by removing the sibling's leaf: never a close
            let (result, seen) = join(
                &fixture,
                &group,
                intent(&fixture, &group),
                true,
                vec![listed(listing(&[]))],
            )
            .await;
            assert_eq!(seen, vec![]);
            assert_sibling_refusal(result, "a removed sibling beside another member");
            assert!(is_open(db, &group.id).await);
            assert!(stored_intents(db, &group.id).await.is_empty());
        }

        #[test]
        fn the_sibling_close_off_keeps_the_refusal_for_a_removed_sibling() {
            crate::util::test::rt().block_on(async {
                revolt_config::overwrite_config(|settings| {
                    settings.features.mls_sibling_close = false;
                })
                .await;

                let fixture = sibling_fixture().await;
                let db = &fixture.harness.db;
                let group = call_group(&fixture, vec![leaf(&fixture.sibling)]).await;
                remove_sibling(&fixture).await;

                // A sole removed sibling, which closes with the flag on
                let (result, seen) = join(
                    &fixture,
                    &group,
                    intent(&fixture, &group),
                    false,
                    vec![listed(stale_sibling_listing(&fixture))],
                )
                .await;
                assert_eq!(seen, vec![]);
                assert_sibling_refusal(result, "the kill switch off, a removed sibling");
                assert!(is_open(db, &group.id).await);
                assert!(stored_intents(db, &group.id).await.is_empty());
            })
        }
    }
}
