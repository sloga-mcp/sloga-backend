//! Remote-control grant lifecycle (remote-control plan §1, slice 1).
//!
//! Redis store for the sharer-initiated "Give control" handshake: pending
//! offers, active grants, and the indexes that make revocation findable.
//! The governing principle (plan §1): the grant record here is a
//! *bookkeeping artifact* — the only real authority is the SFU participant
//! permission, and the only revoke that cannot silently fail is ejecting
//! the participant from the room. Every expiry path has an ACTOR (the crond
//! reaper, a route, a release hook); passive Redis TTL is never used for
//! grants, because a key expiring fires no callback and with the record
//! gone nothing could find the grant to revoke it.
//!
//! Uniqueness invariants, all enforced with SETNX (never SET):
//! - at most one PENDING OFFER per (channel, sharer) — a second offer must
//!   not silently overwrite the first while the target's dialog is open;
//! - at most one GRANT per (channel, sharer);
//! - at most one GRANT per CONTROLLER across all channels (cross-channel
//!   index — a controller in one call must not accumulate a second grant
//!   from a sharer in another).
//!
//! Expiry is driven by an explicit ZSET index (`rc_grant_expiry`), never a
//! SCAN over a key pattern (the ghost-room lesson: a key-pattern scan can
//! silently miss entries). The ZSET member is self-contained
//! (`grant:channel:sharer:controller`) so that even if the grant record is
//! lost, the reaper can still fail CLOSED by ejecting the controller.

use iso8601_timestamp::Timestamp;
use redis_kiss::AsyncCommands;
use revolt_result::{Result, ToRevoltError};

use crate::{events::client::EventV1, Database, RemoteControlAuditEntry};

use super::{get_connection, UserVoiceChannel, VoiceClient};

/// How long a pending offer lives before the target's dialog goes stale.
/// Offers are pure bookkeeping (no SFU capability exists yet), so passive
/// Redis TTL is acceptable HERE — unlike grants.
pub const REMOTE_CONTROL_OFFER_TTL_SECS: i64 = 90;

/// Heartbeat-refreshed grant lifetime. SHARER-driven: the party whose OS is
/// at risk continuously re-asserts consent, and going dark expires the
/// grant within single-digit seconds (plan §1 — a controller-driven
/// heartbeat would keep the grant alive precisely when the sharer is gone).
pub const REMOTE_CONTROL_HEARTBEAT_TTL_SECS: i64 = 8;

/// Grace given at accept time before the first heartbeat must land.
pub const REMOTE_CONTROL_INITIAL_TTL_SECS: i64 = 2 * REMOTE_CONTROL_HEARTBEAT_TTL_SECS;

/// Explicit expiry index (ZSET keyed by expiry epoch millis)
const EXPIRY_INDEX_KEY: &str = "rc_grant_expiry";

fn offer_key(offer_id: &str) -> String {
    format!("rc_offer:{offer_id}")
}

fn pending_key(channel_id: &str, sharer_id: &str) -> String {
    format!("rc_offer_pending:{channel_id}:{sharer_id}")
}

fn grant_key(channel_id: &str, sharer_id: &str) -> String {
    format!("rc_grant:{channel_id}:{sharer_id}")
}

fn grant_id_key(grant_id: &str) -> String {
    format!("rc_grant_id:{grant_id}")
}

fn controller_key(controller_id: &str) -> String {
    format!("rc_controller:{controller_id}")
}

fn channel_grants_key(channel_id: &str) -> String {
    format!("rc_channel_grants:{channel_id}")
}

fn now_ms() -> i64 {
    Timestamp::now_utc()
        .duration_since(Timestamp::UNIX_EPOCH)
        .whole_milliseconds() as i64
}

/// A pending control offer (no SFU capability attached)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteControlOffer {
    /// Offer id (ULID)
    pub id: String,
    pub channel_id: String,
    /// Present for server channels (needed to rebuild `UserVoiceChannel`,
    /// whose per-member voice flags key by server id there)
    pub server_id: Option<String>,
    /// The party offering control of their own machine
    pub sharer_id: String,
    /// The named participant being offered control
    pub target_id: String,
    /// Opaque base64: the sharer's ephemeral public key (slice 3 derives
    /// from it; slice 1 only transports it)
    pub sharer_ephemeral_pub: String,
    /// Opaque base64: control-session id minted by the sharer's native layer
    pub rc_session_id: String,
    /// `kbm` or `gamepad` (couch co-op §2.2). Defaulted rather than
    /// `Option` so every consumer reads a class: records written before the
    /// field existed deserialize as `kbm`, which is what they were.
    ///
    /// 🔴 **ADVISORY. DISPLAY-ONLY. NEVER AN ENFORCEMENT INPUT.** The
    /// authoritative class is bound into the two ends' HKDF transcript and
    /// covered by the verification code they compare. This copy exists so
    /// the channel can show the right badge, and the server being able to
    /// lie about it changes nothing on either end — that is the design.
    #[serde(default = "default_input_class")]
    pub input_class: String,
    /// The sharer's control-protocol version, relayed so the target can
    /// refuse a skew legibly at accept time. Absent means v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u8>,
}

/// Serde default for [`RemoteControlOffer::input_class`] and
/// [`RemoteControlGrant::input_class`]: a record with no class predates the
/// field, and every such record is mouse-and-keyboard.
fn default_input_class() -> String {
    INPUT_CLASS_KBM.to_string()
}

/// The two classes the server will relay. Unknown values are refused at the
/// route rather than passed through: this string is fanned out to every
/// client in the channel, and the authoritative copy lives in the
/// transcript anyway, so there is nothing to gain by relaying strings we
/// cannot name.
pub const INPUT_CLASS_KBM: &str = "kbm";
pub const INPUT_CLASS_GAMEPAD: &str = "gamepad";

/// Is this a class this server knows how to relay?
pub fn is_known_input_class(value: &str) -> bool {
    matches!(value, INPUT_CLASS_KBM | INPUT_CLASS_GAMEPAD)
}

/// An active control grant — the record tracking a live scoped
/// `can_publish_data: true` SFU capability held by `controller_id`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteControlGrant {
    /// Grant id (ULID) — distinct from the offer id it came from
    pub id: String,
    pub channel_id: String,
    pub server_id: Option<String>,
    /// LiveKit node the room lives on, captured at accept time
    pub node: String,
    pub sharer_id: String,
    pub controller_id: String,
    /// The EXACT SFU participant identity of the controller captured at
    /// accept time. `get_voice_participant_identity` falls back to the bare
    /// user id and only log::debug!s on a miss — resolving at revoke time
    /// could therefore silently no-op for a device-qualified participant,
    /// so the revoke path must address the identity stored here.
    pub controller_identity: String,
    /// Carried from the offer so the Ready-time snapshot can rebuild the
    /// classed badge for a client that connects mid-session. Advisory and
    /// display-only, exactly like the offer's copy.
    #[serde(default = "default_input_class")]
    pub input_class: String,
}

impl RemoteControlGrant {
    pub fn user_voice_channel(&self) -> UserVoiceChannel {
        UserVoiceChannel {
            id: self.channel_id.clone(),
            server_id: self.server_id.clone(),
        }
    }

    /// Self-contained expiry-index member: parseable even when the grant
    /// record itself has been lost (ULIDs never contain ':').
    ///
    /// The last field is the controller's full SFU IDENTITY, not their bare
    /// user id — the reaper's fail-closed path must eject by the identity
    /// captured at accept time, and re-resolving it there is exactly the
    /// silent no-op the plan warns about (by then the ingress mapping is
    /// usually already deleted). The identity may itself contain ':'
    /// (`{user}:{device}`), so it is parsed as the remainder, and the bare
    /// controller id is recovered from its first segment.
    fn expiry_member(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.id, self.channel_id, self.sharer_id, self.controller_identity
        )
    }
}

/// Parsed form of an expiry-index member
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteControlExpiryMember {
    pub grant_id: String,
    pub channel_id: String,
    pub sharer_id: String,
    /// Full SFU participant identity captured at accept time
    pub controller_identity: String,
}

impl RemoteControlExpiryMember {
    /// Bare user id of the controller (identities are `{user}[:{device}]`)
    pub fn controller_id(&self) -> &str {
        super::user_id_from_participant_identity(&self.controller_identity)
    }
}

pub fn parse_expiry_member(member: &str) -> Option<RemoteControlExpiryMember> {
    let mut parts = member.splitn(4, ':');
    Some(RemoteControlExpiryMember {
        grant_id: parts.next()?.to_string(),
        channel_id: parts.next()?.to_string(),
        sharer_id: parts.next()?.to_string(),
        controller_identity: parts.next()?.to_string(),
    })
}

/// Store a pending offer. Returns `false` when the sharer already has a
/// pending offer in this channel (SETNX on the pending marker — the offer
/// must not silently overwrite one whose dialog is open on another screen).
pub async fn create_remote_control_offer(offer: &RemoteControlOffer) -> Result<bool> {
    use redis_kiss::redis::{ExistenceCheck, SetExpiry, SetOptions};

    let mut conn = get_connection().await?;

    // ONE atomic `SET … NX EX`, never SETNX-then-EXPIRE: a crash or a
    // transient error between the two would leave the pending marker with
    // NO TTL and no offer body — and since nothing reaps offer keys and
    // clearing the marker requires the offer struct, that sharer could
    // never offer control in this channel again.
    let nx_with_ttl = || {
        SetOptions::default()
            .conditional_set(ExistenceCheck::NX)
            .with_expiration(SetExpiry::EX(REMOTE_CONTROL_OFFER_TTL_SECS as usize))
    };

    let pending = pending_key(&offer.channel_id, &offer.sharer_id);
    let claimed: Option<String> = conn
        .set_options(&pending, &offer.id, nx_with_ttl())
        .await
        .to_internal_error()?;
    if claimed.is_none() {
        return Ok(false);
    }

    let serialized = serde_json::to_string(offer).to_internal_error()?;
    let key = offer_key(&offer.id);
    let stored: Option<String> = conn
        .set_options(&key, serialized, nx_with_ttl())
        .await
        .to_internal_error()?;
    if stored.is_none() {
        // A ULID collision is not reachable in practice, but returning
        // "created" with nothing stored would strand the pending marker
        // until its TTL — release it and report the refusal.
        conn.del::<_, ()>(&pending).await.to_internal_error()?;
        return Ok(false);
    }

    Ok(true)
}

pub async fn fetch_remote_control_offer(offer_id: &str) -> Result<Option<RemoteControlOffer>> {
    let raw: Option<String> = get_connection()
        .await?
        .get(offer_key(offer_id))
        .await
        .to_internal_error()?;

    Ok(raw.and_then(|raw| serde_json::from_str(&raw).ok()))
}

/// Drop an offer and its pending marker (decline, accept, or failed grant)
pub async fn delete_remote_control_offer(offer: &RemoteControlOffer) -> Result<()> {
    get_connection()
        .await?
        .del(&[
            offer_key(&offer.id),
            pending_key(&offer.channel_id, &offer.sharer_id),
        ])
        .await
        .to_internal_error()
}

/// Outcome of a grant-store insert
#[derive(Debug, PartialEq, Eq)]
pub enum RemoteControlGrantOutcome {
    Created,
    /// The sharer already has an active grant in this channel
    SharerBusy,
    /// The controller already holds a grant (this or any other channel)
    ControllerBusy,
}

/// Record a grant. SETNX on both the (channel, sharer) key and the
/// cross-channel controller index; the loser of either race gets a clean
/// refusal and no partial state. The expiry-index entry is written in the
/// same breath so a crash can never leave a grant the reaper cannot see.
///
/// NOTE the caller applies the SFU capability AFTER this returns Created —
/// record-first ordering fails closed (a record without a capability is
/// harmless; a capability without a record is unrevocable).
pub async fn create_remote_control_grant(
    grant: &RemoteControlGrant,
) -> Result<RemoteControlGrantOutcome> {
    let mut conn = get_connection().await?;

    let serialized = serde_json::to_string(grant).to_internal_error()?;
    let key = grant_key(&grant.channel_id, &grant.sharer_id);

    let claimed: bool = conn.set_nx(&key, serialized).await.to_internal_error()?;
    if !claimed {
        return Ok(RemoteControlGrantOutcome::SharerBusy);
    }

    // Reaper visibility BEFORE the remaining bookkeeping: from this point a
    // crash leaves at worst an expiry entry whose record the reaper fails
    // closed on (ejection), never an invisible grant. If the index write
    // itself fails, roll the grant key back — grant keys carry no TTL by
    // design and the reaper is index-driven, so a key with no index entry
    // would wedge this sharer as permanently "busy" with nothing able to
    // clean it up.
    if let Err(error) = conn
        .zadd::<_, _, _, ()>(
            EXPIRY_INDEX_KEY,
            grant.expiry_member(),
            now_ms() + REMOTE_CONTROL_INITIAL_TTL_SECS * 1000,
        )
        .await
    {
        let _ = conn.del::<_, ()>(&key).await;
        return Err(error).to_internal_error();
    }

    let controller = controller_key(&grant.controller_id);
    let claimed: bool = conn
        .set_nx(
            &controller,
            format!("{}:{}", grant.channel_id, grant.sharer_id),
        )
        .await
        .to_internal_error()?;
    if !claimed {
        // Roll back — the controller already holds a grant elsewhere. The
        // index entry MUST go even if the key delete fails: an orphan
        // expiry member would make the reaper's fail-closed path eject
        // this controller from the channel where they lost the race and
        // are only an ordinary participant. So neither leg uses `?`.
        if let Err(error) = conn
            .zrem::<_, _, ()>(EXPIRY_INDEX_KEY, grant.expiry_member())
            .await
        {
            log::error!(
                "remote control: failed to roll back expiry index for refused grant {}: {error:?}",
                grant.id
            );
        }
        if let Err(error) = conn.del::<_, ()>(&key).await {
            log::error!(
                "remote control: failed to roll back grant key for refused grant {}: {error:?}",
                grant.id
            );
        }
        return Ok(RemoteControlGrantOutcome::ControllerBusy);
    }

    conn.set::<_, _, ()>(
        grant_id_key(&grant.id),
        format!("{}:{}", grant.channel_id, grant.sharer_id),
    )
    .await
    .to_internal_error()?;
    conn.sadd::<_, _, ()>(channel_grants_key(&grant.channel_id), &grant.sharer_id)
        .await
        .to_internal_error()?;

    Ok(RemoteControlGrantOutcome::Created)
}

pub async fn fetch_remote_control_grant(
    channel_id: &str,
    sharer_id: &str,
) -> Result<Option<RemoteControlGrant>> {
    let raw: Option<String> = get_connection()
        .await?
        .get(grant_key(channel_id, sharer_id))
        .await
        .to_internal_error()?;

    Ok(raw.and_then(|raw| serde_json::from_str(&raw).ok()))
}

pub async fn fetch_remote_control_grant_by_id(
    grant_id: &str,
) -> Result<Option<RemoteControlGrant>> {
    let pointer: Option<String> = get_connection()
        .await?
        .get(grant_id_key(grant_id))
        .await
        .to_internal_error()?;

    let Some(pointer) = pointer else {
        return Ok(None);
    };
    let Some((channel_id, sharer_id)) = pointer.split_once(':') else {
        return Ok(None);
    };

    // The pointer and the record can desync (partial teardown crash) —
    // verify the record is the grant the pointer claims.
    Ok(fetch_remote_control_grant(channel_id, sharer_id)
        .await?
        .filter(|grant| grant.id == grant_id))
}

/// The grant (if any) currently held BY a controller, in any channel
pub async fn fetch_remote_control_grant_for_controller(
    controller_id: &str,
) -> Result<Option<RemoteControlGrant>> {
    let pointer: Option<String> = get_connection()
        .await?
        .get(controller_key(controller_id))
        .await
        .to_internal_error()?;

    let Some(pointer) = pointer else {
        return Ok(None);
    };
    let Some((channel_id, sharer_id)) = pointer.split_once(':') else {
        return Ok(None);
    };

    Ok(fetch_remote_control_grant(channel_id, sharer_id)
        .await?
        .filter(|grant| grant.controller_id == controller_id))
}

/// Whether either party is already involved in an active grant — the offer
/// route's advisory pre-check (the accept path's SETNX is the enforcement)
pub async fn remote_control_party_busy(
    channel_id: &str,
    sharer_id: &str,
    target_id: &str,
) -> Result<bool> {
    Ok(fetch_remote_control_grant(channel_id, sharer_id)
        .await?
        .is_some()
        || fetch_remote_control_grant_for_controller(target_id)
            .await?
            .is_some())
}

/// SHARER-driven consent re-assertion: push the grant's expiry out by one
/// heartbeat TTL. The member is stable, so this is a plain ZADD score
/// update.
pub async fn heartbeat_remote_control_grant(grant: &RemoteControlGrant) -> Result<()> {
    get_connection()
        .await?
        .zadd(
            EXPIRY_INDEX_KEY,
            grant.expiry_member(),
            now_ms() + REMOTE_CONTROL_HEARTBEAT_TTL_SECS * 1000,
        )
        .await
        .to_internal_error()
}

/// Remove every record of a grant (all five keys). Bookkeeping only — the
/// SFU capability is the caller's problem (`end_remote_control_grant`).
pub async fn delete_remote_control_grant_records(grant: &RemoteControlGrant) -> Result<()> {
    let mut conn = get_connection().await?;

    conn.del::<_, ()>(&[
        grant_key(&grant.channel_id, &grant.sharer_id),
        grant_id_key(&grant.id),
        controller_key(&grant.controller_id),
    ])
    .await
    .to_internal_error()?;
    conn.srem::<_, _, ()>(channel_grants_key(&grant.channel_id), &grant.sharer_id)
        .await
        .to_internal_error()?;
    conn.zrem::<_, _, ()>(EXPIRY_INDEX_KEY, grant.expiry_member())
        .await
        .to_internal_error()?;

    Ok(())
}

/// Whether a channel holds ANY active grant — a single O(1) EXISTS used to
/// skip the release hooks entirely on the ~all calls that have none
pub async fn channel_has_remote_control_grants(channel_id: &str) -> Result<bool> {
    get_connection()
        .await?
        .exists(channel_grants_key(channel_id))
        .await
        .to_internal_error()
}

/// Every active grant in a channel (room_finished / channel deletion)
pub async fn remote_control_grants_in_channel(
    channel_id: &str,
) -> Result<Vec<RemoteControlGrant>> {
    let sharers: Vec<String> = get_connection()
        .await?
        .smembers(channel_grants_key(channel_id))
        .await
        .to_internal_error()?;

    let mut grants = Vec::with_capacity(sharers.len());
    for sharer_id in sharers {
        if let Some(grant) = fetch_remote_control_grant(channel_id, &sharer_id).await? {
            grants.push(grant);
        }
    }

    Ok(grants)
}

/// Redacted snapshot of the live grants across a set of channels, as
/// re-sendable `RemoteControlActive` events — the Ready-time backfill for
/// the channel-topic visibility pair. The event is otherwise emitted only
/// once, at accept, so a session that connects after that moment (or
/// reconnects — clients deliberately drop their visibility state with the
/// socket) would see nothing until the next grant. Re-delivering the same
/// redacted shape lets clients rebuild idempotently.
///
/// Best-effort by design: a Redis hiccup here must never cost the caller a
/// connection, so per-channel failures are logged and skipped (the cost is
/// a missing badge until the next event — the fail-safe direction). The
/// caller is responsible for having applied the ViewChannel visibility
/// filter to `channel_ids` before asking.
pub async fn remote_control_active_snapshot(channel_ids: &[&str]) -> Vec<EventV1> {
    let mut events = Vec::new();

    for channel_id in channel_ids {
        // O(1) EXISTS gate first — ~all live calls hold no grant.
        match channel_has_remote_control_grants(channel_id).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                log::warn!(
                    "remote control: snapshot grant-set probe failed for {channel_id}: {error:?}"
                );
                continue;
            }
        }

        match remote_control_grants_in_channel(channel_id).await {
            Ok(grants) => {
                for grant in grants {
                    events.push(EventV1::RemoteControlActive {
                        channel_id: grant.channel_id,
                        sharer_id: grant.sharer_id,
                        controller_id: grant.controller_id,
                        // The backfill has to carry the class too, or a
                        // client that reconnects mid-session rebuilds a
                        // badge that says the wrong thing about what is
                        // being shared.
                        input_class: Some(grant.input_class),
                    });
                }
            }
            Err(error) => log::warn!(
                "remote control: snapshot grant enumeration failed for {channel_id}: {error:?}"
            ),
        }
    }

    events
}

/// Expiry-index members whose deadline has passed (the reaper's work list)
pub async fn expired_remote_control_members(now: i64) -> Result<Vec<String>> {
    get_connection()
        .await?
        .zrangebyscore(EXPIRY_INDEX_KEY, i64::MIN, now)
        .await
        .to_internal_error()
}

/// EVERY expiry-index member regardless of deadline — the mass-revoke path
/// the reaper takes when the operator has turned the config flag off
pub async fn all_remote_control_members() -> Result<Vec<String>> {
    get_connection()
        .await?
        .zrangebyscore(EXPIRY_INDEX_KEY, i64::MIN, i64::MAX)
        .await
        .to_internal_error()
}

/// Drop an expiry-index member directly (used by the reaper's fail-closed
/// path, where no grant record exists to hand `delete_..._records`)
pub async fn remove_expiry_member(member: &str) -> Result<()> {
    get_connection()
        .await?
        .zrem(EXPIRY_INDEX_KEY, member)
        .await
        .to_internal_error()
}

/// Push an expiry-index member's deadline out by `backoff_ms` so the next
/// sweep retries it. Used when a fail-closed ejection did not succeed: the
/// member is then the only remaining trace of an SFU capability nobody has
/// managed to revoke, so it must be retried rather than retired.
pub async fn requeue_expiry_member(member: &str, backoff_ms: i64) -> Result<()> {
    get_connection()
        .await?
        .zadd(EXPIRY_INDEX_KEY, member, now_ms() + backoff_ms)
        .await
        .to_internal_error()
}

/// End a grant, as an ACTOR: revoke the SFU capability (when asked to),
/// delete the records, tell the channel, and write the audit row.
///
/// `revoke_capability` is false only when the controller's SFU capability
/// is already gone with certainty — the controller left / was ejected, or
/// the whole room finished. In every other path the capability must be
/// actively revoked, and a failed revoke ESCALATES TO EJECTION
/// (`remove_participant`) — the one revoke that cannot silently fail.
///
/// Revocation recomputes the FULL permission set for the controller and
/// flips only `can_publish_data`: `UpdateParticipantOptions` replaces the
/// entire `ParticipantPermission` message, so a partial message would mute
/// and deafen them (plan §1). When the full recompute is impossible
/// (channel or user gone mid-teardown), it degrades straight to ejection
/// rather than guessing at a permission set.
pub async fn end_remote_control_grant(
    db: &Database,
    voice_client: &VoiceClient,
    grant: &RemoteControlGrant,
    reason: &str,
    revoke_capability: bool,
) {
    if revoke_capability {
        if let Err(error) = revoke_controller_capability(db, voice_client, grant).await {
            log::warn!(
                "remote control: permission revoke failed for grant {} (controller {} in {}), ejecting: {error:?}",
                grant.id,
                grant.controller_id,
                grant.channel_id
            );
            if let Err(error) = voice_client
                .remove_identity(&grant.node, &grant.controller_identity, &grant.channel_id)
                .await
            {
                // Both legs failed. The records are still deleted below,
                // and deliberately so: keeping them would leak a grant
                // nothing ever clears while the sharer's indicator stayed
                // lit forever. A controller that had already left never
                // gets here (the revoke push answers that case as done, see
                // `revoke_controller_capability`); one that leaves between
                // the push and this ejection still can, and the SFU then
                // errors on the unknown identity. The residual risk is
                // bounded — the other way both legs fail is the node being
                // unreachable, and a controller cannot use a data-channel
                // capability on an SFU that is not routing for them either.
                log::error!(
                    "remote control: ejection ALSO failed for grant {} (controller {} in {}): {error:?}",
                    grant.id,
                    grant.controller_id,
                    grant.channel_id
                );
            }
        }
    }

    if let Err(error) = delete_remote_control_grant_records(grant).await {
        log::error!(
            "remote control: failed to delete records for grant {}: {error:?}",
            grant.id
        );
    }

    EventV1::RemoteControlEnded {
        channel_id: grant.channel_id.clone(),
        sharer_id: grant.sharer_id.clone(),
        reason: reason.to_string(),
    }
    .p(grant.channel_id.clone())
    .await;

    let audit = RemoteControlAuditEntry {
        id: ulid::Ulid::new().to_string(),
        channel_id: grant.channel_id.clone(),
        server_id: grant.server_id.clone(),
        sharer_id: grant.sharer_id.clone(),
        controller_id: grant.controller_id.clone(),
        offer_id: None,
        grant_id: Some(grant.id.clone()),
        action: "ended".to_string(),
        reason: Some(reason.to_string()),
        created_at: Timestamp::now_utc(),
    };
    if let Err(error) = db.insert_remote_control_audit(&audit).await {
        log::warn!(
            "remote control: failed to write audit row for grant {}: {error:?}",
            grant.id
        );
    }
}

/// Recompute the controller's full permission set and push it with
/// `can_publish_data: false` — the active revoke leg of teardown.
///
/// The SFU answering that the controller is not in the room is `Ok`: the
/// capability is held by that participant and ended with it, so there is
/// nothing left to revoke, and escalating to an ejection would only be a
/// second guaranteed-failing call after an ERROR log and a Sentry event
/// (AFK S-3 D-7). Any other failure is still an `Err`, reported by the
/// push exactly as before, and the caller still escalates it to ejection.
async fn revoke_controller_capability(
    db: &Database,
    voice_client: &VoiceClient,
    grant: &RemoteControlGrant,
) -> Result<()> {
    use crate::util::{permissions::DatabasePermissionQuery, reference::Reference};
    use revolt_permissions::{calculate_channel_permissions, ChannelPermission};

    let channel = Reference::from_unchecked(&grant.channel_id)
        .as_channel(db)
        .await?;
    let controller = Reference::from_unchecked(&grant.controller_id)
        .as_user(db)
        .await?;

    let mut query = DatabasePermissionQuery::new(db, &controller).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    let limits = controller.limits().await;
    // AFK gate (plan D2 / audit CRITICAL-1). This is the RC teardown leg: it
    // RE-PUSHES a freshly recomputed source set, so an ungated recompute here
    // would hand every publish source back the moment control was revoked —
    // the mute defeated by revoking the very thing that defeated it. No server
    // document is in hand, so the gate fetches its own.
    let allowed_sources = super::get_allowed_sources(
        &limits,
        permissions,
        super::AfkGate::resolve(db, &channel, None).await?,
    );
    let can_listen = permissions.has_channel_permission(ChannelPermission::Listen);

    let pushed = voice_client
        .update_permissions_identity_if_present(
            &grant.node,
            &grant.controller_identity,
            &grant.channel_id,
            super::voice_participant_permissions(can_listen, &allowed_sources),
        )
        .await?;
    if !pushed {
        log::info!(
            "remote control: controller {} of grant {} had already left {}, nothing to revoke",
            grant.controller_identity,
            grant.id,
            grant.channel_id
        );
    }

    Ok(())
}

/// Release hook: end any grant involving `user_id` in `channel` — as sharer
/// or as controller — whichever of the user's connections holds it.
///
/// This is the WHOLE-USER release, for paths that take every connection of
/// the user out of the call (or end the share itself). A single connection
/// leaving (the `participant_left` webhook) goes through
/// [`release_remote_control_for_connection`] instead, which leaves a
/// controller grant held by a DIFFERENT, still-connected connection alone.
///
/// `participant_already_gone` may only be `true` when the SFU has already
/// told us that the connection holding the controller capability is gone:
/// the capability then died with that participant, so revoking it would
/// only produce a guaranteed-failing round trip. Every other caller must
/// pass `false`, INCLUDING the delta-initiated removals that are about
/// to eject the user — those call `remove_user` best-effort (errors
/// discarded, and the identity re-resolution behind it can silently no-op
/// for a device-qualified participant), so deleting the records first on
/// the assumption the removal will work is exactly how a capability
/// survives with nothing left able to revoke it.
pub async fn release_remote_control_for_user(
    db: &Database,
    voice_client: &VoiceClient,
    channel: &UserVoiceChannel,
    user_id: &str,
    reason: &str,
    participant_already_gone: bool,
) {
    release_remote_control(
        db,
        voice_client,
        channel,
        user_id,
        reason,
        ControllerRelease::WholeUser {
            participant_already_gone,
        },
    )
    .await;
}

/// Release hook for ONE connection of `user_id` leaving `channel` (the
/// `participant_left` webhook, where `identity` is the SFU identity that
/// left). AFK S-3 D-7.
///
/// - **As SHARER:** the user's grant in this channel is ended, WITH an
///   active revoke, whichever of their connections left. The grant records
///   no sharer identity to be finer with, and server state may only ever
///   revoke a session, never sustain one — so a sharer with two devices
///   loses the session when EITHER leaves (decision DS-3). Their
///   controller's capability is live whatever happened to the sharer's
///   participant, hence the revoke.
/// - **As CONTROLLER:** the grant is ended only when `identity` is the
///   grant's `controller_identity`, the exact connection that holds the
///   capability, and then WITHOUT a revoke: that participant is gone and
///   the capability went with it. Any other connection of the same user
///   leaving leaves the grant untouched — the controlling connection is
///   still live, and ending the record while skipping the revoke would
///   strand a `can_publish_data` capability nothing could find to revoke
///   (Stage 1 F-9).
pub async fn release_remote_control_for_connection(
    db: &Database,
    voice_client: &VoiceClient,
    channel: &UserVoiceChannel,
    user_id: &str,
    identity: &str,
    reason: &str,
) {
    release_remote_control(
        db,
        voice_client,
        channel,
        user_id,
        reason,
        ControllerRelease::Connection { identity },
    )
    .await;
}

/// Which of a user's CONTROLLER grants a release ends, and how.
#[derive(Debug, Clone, Copy)]
enum ControllerRelease<'a> {
    /// Every connection of the user: end the grant whichever connection
    /// holds it, revoking unless the SFU already reported that participant
    /// gone.
    WholeUser { participant_already_gone: bool },
    /// One connection, by its SFU identity, which the SFU reported gone.
    Connection { identity: &'a str },
}

impl ControllerRelease<'_> {
    /// Whether this release ends `grant`, a controller grant of the user in
    /// the released channel.
    fn ends(&self, grant: &RemoteControlGrant) -> bool {
        match self {
            Self::WholeUser { .. } => true,
            Self::Connection { identity } => *identity == grant.controller_identity,
        }
    }

    /// Whether ending it must actively revoke the capability.
    fn revokes(&self) -> bool {
        match self {
            Self::WholeUser {
                participant_already_gone,
            } => !participant_already_gone,
            Self::Connection { .. } => false,
        }
    }
}

/// The body both release hooks share: the sharer arm always ends WITH a
/// revoke; the controller arm is decided by `controller`.
async fn release_remote_control(
    db: &Database,
    voice_client: &VoiceClient,
    channel: &UserVoiceChannel,
    user_id: &str,
    reason: &str,
    controller: ControllerRelease<'_>,
) {
    // Cheap short-circuit: the overwhelming majority of calls are for
    // channels with no grant at all, and this hook sits in the permission-
    // sync request path (once per member of the call).
    match channel_has_remote_control_grants(&channel.id).await {
        Ok(false) => return,
        Ok(true) => {}
        Err(error) => log::warn!(
            "remote control: grant-set probe failed for {}: {error:?}",
            channel.id
        ),
    }

    // Grants where the user is the SHARER of this channel's session. Their
    // controller's capability is live regardless of what happens to the
    // sharer's own participant, so this leg always actively revokes.
    match fetch_remote_control_grant(&channel.id, user_id).await {
        Ok(Some(grant)) => {
            end_remote_control_grant(db, voice_client, &grant, reason, true).await;
        }
        Ok(None) => {}
        Err(error) => log::warn!(
            "remote control: sharer-grant lookup failed for {user_id} in {}: {error:?}",
            channel.id
        ),
    }

    // Grants where the user is the CONTROLLER (cross-channel index, filter
    // to this channel)
    match fetch_remote_control_grant_for_controller(user_id).await {
        Ok(Some(grant)) if grant.channel_id == channel.id && controller.ends(&grant) => {
            end_remote_control_grant(db, voice_client, &grant, reason, controller.revokes()).await;
        }
        Ok(_) => {}
        Err(error) => log::warn!(
            "remote control: controller-grant lookup failed for {user_id}: {error:?}"
        ),
    }
}

/// Release hook for whole-room teardown: end every grant in the channel.
///
/// `revoke_capability` is false ONLY for the `room_finished` webhook, where
/// the SFU has already told us the room is gone and every capability with
/// it. A caller that is merely *about to* delete the room must pass true —
/// the delete can fail.
pub async fn release_remote_control_for_channel(
    db: &Database,
    voice_client: &VoiceClient,
    channel_id: &str,
    reason: &str,
    revoke_capability: bool,
) {
    match remote_control_grants_in_channel(channel_id).await {
        Ok(grants) => {
            for grant in grants {
                end_remote_control_grant(db, voice_client, &grant, reason, revoke_capability)
                    .await;
            }
        }
        Err(error) => log::warn!(
            "remote control: channel-grant enumeration failed for {channel_id}: {error:?}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The voice module's shared Redis-test runtime (see `voice::tests::rt`
    /// for why a second runtime poisons the global connection pool).
    fn rt() -> &'static tokio::runtime::Runtime {
        super::super::tests::rt()
    }

    fn offer(suffix: &str) -> RemoteControlOffer {
        RemoteControlOffer {
            id: format!("OFFER{suffix}"),
            channel_id: format!("chan{suffix}"),
            server_id: Some(format!("srv{suffix}")),
            sharer_id: format!("sharer{suffix}"),
            target_id: format!("target{suffix}"),
            sharer_ephemeral_pub: "c2hhcmVyLXB1Yg".to_string(),
            rc_session_id: "c2Vzc2lvbi1pZA".to_string(),
            input_class: INPUT_CLASS_GAMEPAD.to_string(),
            protocol_version: Some(2),
        }
    }

    fn grant(suffix: &str) -> RemoteControlGrant {
        RemoteControlGrant {
            id: format!("GRANT{suffix}"),
            channel_id: format!("chan{suffix}"),
            server_id: Some(format!("srv{suffix}")),
            node: "worldwide".to_string(),
            sharer_id: format!("sharer{suffix}"),
            controller_id: format!("ctl{suffix}"),
            controller_identity: format!("ctl{suffix}:deadbeef"),
            input_class: INPUT_CLASS_GAMEPAD.to_string(),
        }
    }

    /// 🔴 **Records written before couch co-op existed must still
    /// deserialize, and they must read as `kbm`.**
    ///
    /// The grant and offer records are JSON in Redis with no migration
    /// step, so a session that was live across the deploy comes back
    /// through `serde` with no `input_class` at all. Defaulting is what
    /// keeps the reaper and the snapshot working on those rows — and `kbm`
    /// is not a guess, it is what every one of them factually is.
    #[test]
    fn records_without_a_class_deserialize_as_kbm() {
        let legacy_grant = r#"{
            "id": "GRANTLEGACY",
            "channel_id": "chan",
            "server_id": null,
            "node": "worldwide",
            "sharer_id": "sharer",
            "controller_id": "ctl",
            "controller_identity": "ctl:deadbeef"
        }"#;
        let parsed: RemoteControlGrant = serde_json::from_str(legacy_grant).expect("legacy grant");
        assert_eq!(parsed.input_class, INPUT_CLASS_KBM);

        let legacy_offer = r#"{
            "id": "OFFERLEGACY",
            "channel_id": "chan",
            "server_id": null,
            "sharer_id": "sharer",
            "target_id": "target",
            "sharer_ephemeral_pub": "c2hhcmVyLXB1Yg",
            "rc_session_id": "c2Vzc2lvbi1pZA"
        }"#;
        let parsed: RemoteControlOffer = serde_json::from_str(legacy_offer).expect("legacy offer");
        assert_eq!(parsed.input_class, INPUT_CLASS_KBM);
        // Absent version is v1 by construction — v1 is exactly the set of
        // builds that could not send it.
        assert_eq!(parsed.protocol_version, None);
    }

    /// Only the two classes this server knows are relayable. The route
    /// refuses anything else rather than fanning an unrecognised string out
    /// to every client in the channel.
    #[test]
    fn only_known_input_classes_are_relayable() {
        assert!(is_known_input_class(INPUT_CLASS_KBM));
        assert!(is_known_input_class(INPUT_CLASS_GAMEPAD));
        for unknown in ["", "KBM", "pad", "gamepad ", "kbm\u{0000}"] {
            assert!(!is_known_input_class(unknown), "{unknown:?} was relayable");
        }
    }

    #[test]
    fn expiry_member_roundtrip() {
        let grant = grant("X");
        let parsed = parse_expiry_member(&grant.expiry_member()).expect("parse");
        assert_eq!(parsed.grant_id, grant.id);
        assert_eq!(parsed.channel_id, grant.channel_id);
        assert_eq!(parsed.sharer_id, grant.sharer_id);
        // The member carries the full SFU identity; the bare controller id
        // is recovered from its first segment.
        assert_eq!(parsed.controller_identity, grant.controller_identity);
        assert_eq!(parsed.controller_id(), grant.controller_id);
    }

    // Redis-backed: the SETNX uniqueness invariants and index bookkeeping.
    #[test]
    fn offer_pending_marker_refuses_second_offer() {
        rt().block_on(async {
            let suffix = ulid::Ulid::new().to_string();
            let first = offer(&suffix);

            assert!(create_remote_control_offer(&first).await.unwrap());
            // A second offer by the same sharer in the same channel is
            // refused while the first is pending — never overwritten.
            let mut second = offer(&suffix);
            second.id = format!("OFFER2{suffix}");
            second.target_id = format!("othertarget{suffix}");
            assert!(!create_remote_control_offer(&second).await.unwrap());

            // The stored offer is still the FIRST one.
            let stored = fetch_remote_control_offer(&first.id).await.unwrap();
            assert_eq!(stored, Some(first.clone()));
            assert_eq!(
                fetch_remote_control_offer(&second.id).await.unwrap(),
                None
            );

            // Deleting clears the marker; a new offer may then be made.
            delete_remote_control_offer(&first).await.unwrap();
            assert!(create_remote_control_offer(&second).await.unwrap());
            delete_remote_control_offer(&second).await.unwrap();
        })
    }

    #[test]
    fn snapshot_reflects_live_grants_only() {
        rt().block_on(async {
            let suffix = ulid::Ulid::new().to_string();
            let grant = grant(&suffix);
            let channel_id = grant.channel_id.as_str();

            // No grant yet — and a channel Redis has never seen contributes
            // nothing rather than erroring.
            assert!(remote_control_active_snapshot(&[channel_id]).await.is_empty());

            assert_eq!(
                create_remote_control_grant(&grant).await.unwrap(),
                RemoteControlGrantOutcome::Created
            );

            let events =
                remote_control_active_snapshot(&[channel_id, "nosuchchannel"]).await;
            assert_eq!(events.len(), 1);
            match &events[0] {
                EventV1::RemoteControlActive {
                    channel_id,
                    sharer_id,
                    controller_id,
                    input_class,
                } => {
                    assert_eq!(channel_id, &grant.channel_id);
                    assert_eq!(sharer_id, &grant.sharer_id);
                    // The redacted event carries the bare controller id,
                    // never the SFU identity or the grant id.
                    assert_eq!(controller_id, &grant.controller_id);
                    // …and the class survives the Redis round trip, which
                    // is the whole reason the grant record carries it: a
                    // client that connects mid-session rebuilds its badge
                    // from here and from nothing else.
                    assert_eq!(input_class.as_deref(), Some(INPUT_CLASS_GAMEPAD));
                }
                other => panic!("expected RemoteControlActive, got {other:?}"),
            }

            // Record teardown empties the snapshot with it.
            delete_remote_control_grant_records(&grant).await.unwrap();
            assert!(remote_control_active_snapshot(&[channel_id]).await.is_empty());
        })
    }

    #[test]
    fn grant_uniqueness_per_sharer_and_per_controller() {
        rt().block_on(async {
            let suffix = ulid::Ulid::new().to_string();
            let first = grant(&suffix);

            assert_eq!(
                create_remote_control_grant(&first).await.unwrap(),
                RemoteControlGrantOutcome::Created
            );

            // Same (channel, sharer) → SharerBusy.
            let mut second = grant(&suffix);
            second.id = format!("GRANT2{suffix}");
            second.controller_id = format!("ctl2{suffix}");
            assert_eq!(
                create_remote_control_grant(&second).await.unwrap(),
                RemoteControlGrantOutcome::SharerBusy
            );

            // Same controller from a DIFFERENT channel → ControllerBusy
            // (the cross-channel index), and the loser leaves no partial
            // state behind.
            let mut cross = grant(&suffix);
            cross.id = format!("GRANT3{suffix}");
            cross.channel_id = format!("chan2{suffix}");
            cross.sharer_id = format!("sharer2{suffix}");
            assert_eq!(
                create_remote_control_grant(&cross).await.unwrap(),
                RemoteControlGrantOutcome::ControllerBusy
            );
            assert_eq!(
                fetch_remote_control_grant(&cross.channel_id, &cross.sharer_id)
                    .await
                    .unwrap(),
                None
            );

            // Lookups resolve through every index.
            assert_eq!(
                fetch_remote_control_grant_by_id(&first.id).await.unwrap(),
                Some(first.clone())
            );
            assert_eq!(
                fetch_remote_control_grant_for_controller(&first.controller_id)
                    .await
                    .unwrap(),
                Some(first.clone())
            );
            assert_eq!(
                remote_control_grants_in_channel(&first.channel_id)
                    .await
                    .unwrap(),
                vec![first.clone()]
            );

            // The expiry index carries the grant with its initial deadline
            // in the future; heartbeat pushes it further out.
            let horizon = now_ms() + REMOTE_CONTROL_INITIAL_TTL_SECS * 1000 + 1000;
            assert!(expired_remote_control_members(horizon)
                .await
                .unwrap()
                .contains(&first.expiry_member()));
            assert!(!expired_remote_control_members(now_ms())
                .await
                .unwrap()
                .contains(&first.expiry_member()));

            heartbeat_remote_control_grant(&first).await.unwrap();

            // Full record teardown clears every key and index.
            delete_remote_control_grant_records(&first).await.unwrap();
            assert_eq!(
                fetch_remote_control_grant(&first.channel_id, &first.sharer_id)
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(
                fetch_remote_control_grant_by_id(&first.id).await.unwrap(),
                None
            );
            assert_eq!(
                fetch_remote_control_grant_for_controller(&first.controller_id)
                    .await
                    .unwrap(),
                None
            );
            assert!(remote_control_grants_in_channel(&first.channel_id)
                .await
                .unwrap()
                .is_empty());
            assert!(!expired_remote_control_members(horizon)
                .await
                .unwrap()
                .contains(&first.expiry_member()));
        })
    }

    // ---- connection-scoped release (AFK S-3 D-7) ----
    //
    // The real release against the Reference driver, live Redis and the
    // mock SFU. Every stub answers a path it was not given with a 500 and
    // records every request, so "no revoke" and "no ejection" are read off
    // the requests the SFU actually received.

    use super::super::voice_client::sfu_stub::{
        self, internal, not_found, ok, routes, Stub, NODE, REMOVE, UPDATE,
    };

    /// A device suffix for a device-qualified SFU identity.
    const DEVICE: &str = "DEVICEA";

    fn requests(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(path, identity)| (path.to_string(), identity.to_string()))
            .collect()
    }

    /// A server voice channel with a controller who is a member of it, and
    /// an UNSTORED grant in it held by that controller's device-qualified
    /// connection. The revoke recomputes the controller's permissions from
    /// the channel, the user and the server, so all three are real.
    async fn release_fixture() -> (Database, UserVoiceChannel, RemoteControlGrant) {
        use crate::{Channel, Member, Server, User};
        use revolt_models::v0::{
            DataCreateServer, DataCreateServerChannel, LegacyServerChannelType,
        };

        let db = Database::Reference(Default::default());
        let owner = User::create(&db, "RcReleaseOwner".to_string(), None, None)
            .await
            .expect("`User`");
        let mut server = Server::create(
            &db,
            DataCreateServer {
                name: "RcReleaseServer".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .expect("`Server`")
        .0;
        let channel = Channel::create_server_channel(
            &db,
            &mut server,
            DataCreateServerChannel {
                channel_type: LegacyServerChannelType::Voice,
                name: "Lounge".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("`Channel`");
        let controller = User::create(&db, "RcReleaseController".to_string(), None, None)
            .await
            .expect("`User`");
        Member::create(&db, &server, &controller, None)
            .await
            .expect("`Member`");

        let channel = UserVoiceChannel::from_channel(&channel);
        let grant = RemoteControlGrant {
            id: ulid::Ulid::new().to_string(),
            channel_id: channel.id.clone(),
            server_id: Some(server.id.clone()),
            node: NODE.to_string(),
            sharer_id: format!("sharer{}", ulid::Ulid::new()),
            controller_id: controller.id.clone(),
            controller_identity: format!("{}:{DEVICE}", controller.id),
            input_class: INPUT_CLASS_KBM.to_string(),
        };

        (db, channel, grant)
    }

    async fn store(grant: &RemoteControlGrant) {
        assert_eq!(
            create_remote_control_grant(grant).await.unwrap(),
            RemoteControlGrantOutcome::Created
        );
    }

    /// Whether the grant is still findable through the sharer key, the
    /// controller index and the channel's grant set.
    async fn grant_present(grant: &RemoteControlGrant) -> [bool; 3] {
        [
            fetch_remote_control_grant(&grant.channel_id, &grant.sharer_id)
                .await
                .unwrap()
                .as_ref()
                == Some(grant),
            fetch_remote_control_grant_for_controller(&grant.controller_id)
                .await
                .unwrap()
                .as_ref()
                == Some(grant),
            remote_control_grants_in_channel(&grant.channel_id)
                .await
                .unwrap()
                .contains(grant),
        ]
    }

    /// F-9: a connection of the controller USER that is not the connection
    /// holding the capability leaving — a second device, or the bare
    /// identity — ends nothing and sends nothing. Ending the record here
    /// without a revoke would leave the still-connected controller holding
    /// `can_publish_data` with no record left to revoke it through.
    #[test]
    fn a_non_controller_connection_leaving_keeps_the_controller_grant() {
        rt().block_on(async {
            let (db, channel, grant) = release_fixture().await;
            store(&grant).await;

            let stub = Stub::serve(routes(vec![]));
            let voice_client = sfu_stub::voice_client(stub.url());

            for identity in [
                grant.controller_id.clone(),
                format!("{}:OTHERDEVICE", grant.controller_id),
            ] {
                assert_ne!(identity, grant.controller_identity);
                release_remote_control_for_connection(
                    &db,
                    &voice_client,
                    &channel,
                    &grant.controller_id,
                    &identity,
                    "participant_left",
                )
                .await;
                assert_eq!(
                    grant_present(&grant).await,
                    [true; 3],
                    "{identity} is not the controlling connection, so the \
                     grant must survive its leave"
                );
            }

            assert_eq!(
                stub.finish(),
                requests(&[]),
                "no revoke and no ejection may reach the SFU for a live controller"
            );

            delete_remote_control_grant_records(&grant).await.unwrap();
        })
    }

    /// The controlling connection leaving ends the grant everywhere, with
    /// NO revoke and NO ejection: that participant, and the capability it
    /// held, are already gone.
    #[test]
    fn the_controller_connection_leaving_ends_the_grant_without_a_revoke() {
        rt().block_on(async {
            let (db, channel, grant) = release_fixture().await;
            store(&grant).await;

            let stub = Stub::serve(routes(vec![]));
            let voice_client = sfu_stub::voice_client(stub.url());

            release_remote_control_for_connection(
                &db,
                &voice_client,
                &channel,
                &grant.controller_id,
                &grant.controller_identity,
                "participant_left",
            )
            .await;

            assert_eq!(grant_present(&grant).await, [false; 3]);
            assert_eq!(
                stub.finish(),
                requests(&[]),
                "the departed controller must not be revoked or ejected"
            );
        })
    }

    /// DS-3: ANY connection of the sharer leaving — bare or device-qualified,
    /// whatever device the share came from — ends the sharer's grant WITH an
    /// active revoke of the controller's capability, which is still live.
    /// The revoke is the full sync set with data publishing off, addressed
    /// to the controller identity captured at accept.
    #[test]
    fn any_sharer_connection_leaving_ends_the_grant_with_a_revoke() {
        rt().block_on(async {
            let (db, channel, template) = release_fixture().await;

            for leaving in [
                template.sharer_id.clone(),
                format!("{}:{DEVICE}", template.sharer_id),
                format!("{}:OTHERDEVICE", template.sharer_id),
            ] {
                let grant = RemoteControlGrant {
                    id: ulid::Ulid::new().to_string(),
                    ..template.clone()
                };
                store(&grant).await;

                let pushed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                let stub = {
                    let pushed = pushed.clone();
                    Stub::serve(move |path, body| match path {
                        UPDATE => {
                            pushed.lock().unwrap().push(sfu_stub::permission(body));
                            ok(Vec::new())
                        }
                        _ => internal(),
                    })
                };
                let voice_client = sfu_stub::voice_client(stub.url());

                release_remote_control_for_connection(
                    &db,
                    &voice_client,
                    &channel,
                    &grant.sharer_id,
                    &leaving,
                    "participant_left",
                )
                .await;

                assert_eq!(
                    grant_present(&grant).await,
                    [false; 3],
                    "{leaving} leaving must end the sharer's grant"
                );
                assert_eq!(
                    stub.finish(),
                    requests(&[(UPDATE, &grant.controller_identity)]),
                    "{leaving} leaving must revoke the controller, once, by \
                     the identity captured at accept"
                );
                let pushed = pushed.lock().unwrap();
                assert_eq!(pushed.len(), 1);
                let permission = pushed[0].as_ref().expect("a permission was pushed");
                assert!(
                    !permission.can_publish_data,
                    "the revoke must turn data off"
                );
            }
        })
    }

    /// The revoke push addressed to a controller who has ALREADY left: the
    /// SFU's not_found is the answer "nothing left to revoke" — the revoke
    /// is `Ok`, no ejection follows, and the grant is still cleaned up.
    #[test]
    fn a_revoke_of_a_departed_controller_is_done_not_escalated() {
        rt().block_on(async {
            let (db, channel, grant) = release_fixture().await;

            // The revoke on its own: Ok, one push, nothing else.
            let stub = Stub::serve(routes(vec![
                (UPDATE, not_found()),
                (REMOVE, ok(Vec::new())),
            ]));
            let voice_client = sfu_stub::voice_client(stub.url());
            let revoked = revoke_controller_capability(&db, &voice_client, &grant).await;
            assert!(
                revoked.is_ok(),
                "a controller that already left has nothing to revoke: {revoked:?}"
            );
            assert_eq!(
                stub.finish(),
                requests(&[(UPDATE, &grant.controller_identity)])
            );

            // Through the release: the sharer leaves, the revoke finds the
            // controller gone, and no ejection is sent.
            store(&grant).await;
            let stub = Stub::serve(routes(vec![
                (UPDATE, not_found()),
                (REMOVE, ok(Vec::new())),
            ]));
            let voice_client = sfu_stub::voice_client(stub.url());
            release_remote_control_for_connection(
                &db,
                &voice_client,
                &channel,
                &grant.sharer_id,
                &grant.sharer_id,
                "participant_left",
            )
            .await;

            assert_eq!(grant_present(&grant).await, [false; 3]);
            assert_eq!(
                stub.finish(),
                requests(&[(UPDATE, &grant.controller_identity)]),
                "a departed controller must not be ejected after the revoke"
            );
        })
    }

    /// Control for the case above: a REAL revoke failure is still an error
    /// and still escalates to ejecting the controller (fail closed).
    #[test]
    fn a_failed_revoke_still_escalates_to_ejection() {
        rt().block_on(async {
            let (db, channel, grant) = release_fixture().await;

            let stub = Stub::serve(routes(vec![(REMOVE, ok(Vec::new()))]));
            let voice_client = sfu_stub::voice_client(stub.url());
            assert!(revoke_controller_capability(&db, &voice_client, &grant)
                .await
                .is_err());
            assert_eq!(
                stub.finish(),
                requests(&[(UPDATE, &grant.controller_identity)])
            );

            store(&grant).await;
            let stub = Stub::serve(routes(vec![(REMOVE, ok(Vec::new()))]));
            let voice_client = sfu_stub::voice_client(stub.url());
            release_remote_control_for_connection(
                &db,
                &voice_client,
                &channel,
                &grant.sharer_id,
                &grant.sharer_id,
                "participant_left",
            )
            .await;

            assert_eq!(grant_present(&grant).await, [false; 3]);
            assert_eq!(
                stub.finish(),
                requests(&[
                    (UPDATE, &grant.controller_identity),
                    (REMOVE, &grant.controller_identity),
                ]),
                "a revoke that really failed must still eject the controller"
            );
        })
    }
}
