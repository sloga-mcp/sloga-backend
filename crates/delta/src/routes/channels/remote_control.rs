//! Remote-control consent handshake (remote-control plan §1, slice 1).
//!
//! Sharer-initiated "Give control": a user publishing screen VIDEO offers
//! control of their own machine to one named participant, who accepts or
//! declines. Slice 1 transports the parties' ephemeral public keys as
//! OPAQUE bytes and manages the grant lifecycle; no input ever flows here
//! (the input channel, crypto and native consent dialogs are slices 2/3).
//!
//! Modeled on the soundboard route (REST validates → EventV1 → bonfire
//! fan-out), NOT on the incoming-call ring — control needs real,
//! server-recorded accept/decline signals. Offer and decline events are
//! PRIVATE (the channel topic's authorization boundary is ViewChannel, not
//! call membership); only the redacted active/ended states go to the
//! channel topic.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use iso8601_timestamp::Timestamp;
use revolt_database::{
    events::client::EventV1,
    util::{permissions::perms, reference::Reference},
    voice::{
        get_allowed_sources, get_channel_node, get_voice_participant_identity, get_voice_state,
        is_in_voice_channel,
        remote_control::{
            create_remote_control_grant, create_remote_control_offer,
            delete_remote_control_grant_records, delete_remote_control_offer,
            end_remote_control_grant, fetch_remote_control_grant, fetch_remote_control_grant_by_id,
            fetch_remote_control_offer, heartbeat_remote_control_grant, remote_control_party_busy,
            RemoteControlGrant, RemoteControlGrantOutcome, RemoteControlOffer,
        },
        remote_control_participant_permissions, voice_participant_permissions, UserVoiceChannel,
        VoiceClient,
    },
    Channel, Database, RemoteControlAuditEntry, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

/// All remote-control routes sit behind the operator feature flag. NOT a
/// kill switch: `config()` is cached, so flipping the flag off makes these
/// routes refuse (`FeatureDisabled`, 400) on restart but revokes nothing —
/// the crond reaper does the mass revoke when it observes the flag off.
pub(crate) async fn require_remote_control_enabled() -> Result<()> {
    if !revolt_config::config().await.features.remote_control {
        return Err(create_error!(FeatureDisabled {
            feature: "remote_control".to_string()
        }));
    }

    Ok(())
}

/// Decode an opaque wire key: unpadded standard base64, EXACTLY 32 bytes.
/// Hard reject — never an `Option` "for compat": the typed stoat-api client
/// sends `{}` for routes it does not know, and a silently-dropped key would
/// leave slice 3 unable to complete the exchange.
fn require_opaque_32(field: &str, value: &str) -> Result<Vec<u8>> {
    let decoded = STANDARD_NO_PAD.decode(value).map_err(|_| {
        create_error!(FailedValidation {
            error: format!("{field} must be unpadded base64")
        })
    })?;

    if decoded.len() != 32 {
        return Err(create_error!(FailedValidation {
            error: format!("{field} must decode to exactly 32 bytes")
        }));
    }

    Ok(decoded)
}

/// The FULL offer predicate (plan §1). Run on offer, and re-run in its
/// entirety on accept — a user-paced dialog sits between the two and any
/// term can change in that window.
///
/// Eligibility is a three-row rule by channel type:
///
/// | Channel type   | Gate                                              |
/// |----------------|---------------------------------------------------|
/// | DM             | config flag only (DM permissions are one instance-
/// |                | wide constant; there is no per-DM override)       |
/// | Group DM       | config flag only — deliberately NOT gated on the
/// |                | bit: non-owners of existing groups hold only
/// |                | ViewChannel + ReadMessageHistory (the default
/// |                | predates bit 41), so a bit check would pass for the
/// |                | group owner and fail for every other member       |
/// | Server channel | config flag + `UseRemoteControl` on the SHARER    |
///
/// Honesty note: the bit stops ordinary members only. Server owners and
/// privileged/staff accounts receive `GrantAllSafe` before the channel-type
/// match and always pass — under the sharer-initiated model that is a
/// self-risk decision (it governs offering their OWN machine), not
/// third-party exposure.
async fn assert_offer_predicate(
    db: &Database,
    channel: &Channel,
    sharer: &User,
    target: &User,
) -> Result<UserVoiceChannel> {
    require_remote_control_enabled().await?;

    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    // Bots are rejected on BOTH sides: `raise_if_in_voice` permits a bot in
    // unlimited voice channels, and per-member voice flags key
    // `{user}:{server}` for server channels — a bot in two voice channels
    // of one server has COLLIDING voice state, so any screenshare-gated
    // feature is unsound for bots by construction (plan §1).
    if sharer.bot.is_some() || target.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // Reject a self-offer explicitly: every other check passes when a
    // sharer names themselves, and accepting your own offer would mint
    // `can_publish_data: true` for your own participant — a self-service
    // grant of the exact capability this repo denies at three points. The
    // SFU grant is per-IDENTITY, not per-topic, so it would also unlock
    // every other data topic, including "captions".
    if sharer.id == target.id {
        return Err(create_error!(InvalidOperation));
    }

    match channel {
        Channel::DirectMessage { .. } | Channel::Group { .. } => {
            // Config flag only — see the table above.
        }
        _ if channel.server().is_some() => {
            let mut query = perms(db, sharer).channel(channel);
            let permissions = calculate_channel_permissions(&mut query).await;
            permissions
                .throw_if_lacking_channel_permission(ChannelPermission::UseRemoteControl)?;
        }
        _ => return Err(create_error!(NotAVoiceChannel)),
    }

    let user_voice_channel = UserVoiceChannel::from_channel(channel);

    // Both parties must be LIVE participants of this call. Voice state has
    // no TTL, so a missed webhook can leave these reading true for a user
    // in no call — that fails OPEN here (a spurious offer) but CLOSED at
    // the accept path, which treats the SFU grant result as the authority.
    if !is_in_voice_channel(&sharer.id, &user_voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }
    if !is_in_voice_channel(&target.id, &user_voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }

    // The sharer must be publishing screen VIDEO right now, verified
    // server-side from Redis voice state (written only by voice-ingress —
    // never client-claimed). Gate on `screen_video` (source 3 only), NOT
    // the legacy `screensharing` flag, which conflates screen video with
    // screen audio: after the video track ends, a routine screen-audio
    // unmute flips the conflated flag true with nothing to look at, and
    // "blind control" is worse than no control (plan §1 blocker B-2).
    let publishing_screen_video = get_voice_state(&user_voice_channel, &sharer.id)
        .await?
        .is_some_and(|state| state.screen_video);
    if !publishing_screen_video {
        return Err(create_error!(FailedValidation {
            error: "sharer is not publishing screen video".to_string()
        }));
    }

    Ok(user_voice_channel)
}

fn audit_row(
    channel: &Channel,
    sharer_id: &str,
    controller_id: &str,
    offer_id: Option<String>,
    grant_id: Option<String>,
    action: &str,
) -> RemoteControlAuditEntry {
    RemoteControlAuditEntry {
        id: ulid::Ulid::new().to_string(),
        channel_id: channel.id().to_string(),
        server_id: channel.server().map(str::to_string),
        sharer_id: sharer_id.to_string(),
        controller_id: controller_id.to_string(),
        offer_id,
        grant_id,
        action: action.to_string(),
        reason: None,
        created_at: Timestamp::now_utc(),
    }
}

/// # Offer Remote Control
///
/// Offer control of one's own machine to a named participant of this call.
/// The caller must be publishing screen video right now; the target
/// receives a private `RemoteControlOffered` event. No capability is
/// granted until the target accepts.
#[openapi(tag = "Remote Control")]
#[post("/<target>/control/offer", data = "<data>")]
pub async fn control_offer(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataRemoteControlOffer>,
) -> Result<Json<v0::RemoteControlOfferResponse>> {
    let data = data.into_inner();

    require_opaque_32("sharer_ephemeral_pub", &data.sharer_ephemeral_pub)?;
    require_opaque_32("rc_session_id", &data.rc_session_id)?;

    let channel = target.as_channel(db).await?;
    let target_user = Reference::from_unchecked(&data.target).as_user(db).await?;

    assert_offer_predicate(db, &channel, &user, &target_user).await?;

    // Advisory pre-check (the accept path's SETNX is the enforcement): a
    // party already in an active grant cannot enter another handshake.
    if remote_control_party_busy(channel.id(), &user.id, &target_user.id).await? {
        return Err(create_error!(RemoteControlGrantActive));
    }

    let offer = RemoteControlOffer {
        id: ulid::Ulid::new().to_string(),
        channel_id: channel.id().to_string(),
        server_id: channel.server().map(str::to_string),
        sharer_id: user.id.clone(),
        target_id: target_user.id.clone(),
        sharer_ephemeral_pub: data.sharer_ephemeral_pub,
        rc_session_id: data.rc_session_id,
    };

    if !create_remote_control_offer(&offer).await? {
        return Err(create_error!(RemoteControlOfferPending));
    }

    db.insert_remote_control_audit(&audit_row(
        &channel,
        &user.id,
        &target_user.id,
        Some(offer.id.clone()),
        None,
        "offered",
    ))
    .await?;

    // PRIVATE to the target only — never the channel topic (ViewChannel is
    // its authorization boundary, not call membership).
    EventV1::RemoteControlOffered {
        channel_id: offer.channel_id.clone(),
        offer_id: offer.id.clone(),
        sharer_id: offer.sharer_id.clone(),
        target_id: offer.target_id.clone(),
        sharer_ephemeral_pub: offer.sharer_ephemeral_pub.clone(),
        rc_session_id: offer.rc_session_id.clone(),
    }
    .private(target_user.id.clone())
    .await;

    Ok(Json(v0::RemoteControlOfferResponse { offer_id: offer.id }))
}

/// # Respond To Control Offer
///
/// Accept or decline a control offer. Target only, and OFFER-addressed: a
/// target can hold pending offers from several sharers at once, so a bare
/// respond would be ambiguous. Accepting re-runs the full offer predicate —
/// a user-paced dialog sits between offer and accept — and treats the SFU
/// grant result as the authority: a refused grant deletes the offer rather
/// than leaving it stuck.
#[openapi(tag = "Remote Control")]
#[put("/<target>/control/offers/<offer_id>/respond", data = "<data>")]
pub async fn control_respond(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
    offer_id: String,
    data: Json<v0::DataRemoteControlRespond>,
) -> Result<Json<v0::RemoteControlRespondResponse>> {
    require_remote_control_enabled().await?;

    let data = data.into_inner();
    let channel = target.as_channel(db).await?;

    let offer = fetch_remote_control_offer(&offer_id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;

    // Offer must belong to this channel, and only its named target may
    // respond — anyone else learns nothing beyond 404.
    if offer.channel_id != channel.id() || offer.target_id != user.id {
        return Err(create_error!(NotFound));
    }

    let sharer = Reference::from_unchecked(&offer.sharer_id)
        .as_user(db)
        .await?;

    if !data.accept {
        delete_remote_control_offer(&offer).await?;

        db.insert_remote_control_audit(&audit_row(
            &channel,
            &offer.sharer_id,
            &user.id,
            Some(offer.id.clone()),
            None,
            "declined",
        ))
        .await?;

        // PRIVATE to the sharer only — a public decline is a shaming vector.
        EventV1::RemoteControlDeclined {
            channel_id: offer.channel_id.clone(),
            offer_id: offer.id.clone(),
            sharer_id: offer.sharer_id.clone(),
            target_id: offer.target_id.clone(),
        }
        .private(offer.sharer_id.clone())
        .await;

        return Ok(Json(v0::RemoteControlRespondResponse { grant_id: None }));
    }

    // Accepting: the controller's ephemeral public key is REQUIRED (hard
    // reject — without it slice 3's key agreement can never complete).
    let controller_ephemeral_pub = data.controller_ephemeral_pub.ok_or_else(|| {
        create_error!(FailedValidation {
            error: "controller_ephemeral_pub is required to accept".to_string()
        })
    })?;
    require_opaque_32("controller_ephemeral_pub", &controller_ephemeral_pub)?;

    // Re-run the FULL offer predicate with the roles fixed as recorded:
    // sharer still publishing screen video, both still live participants,
    // sharer still holds the bit, feature still on.
    assert_offer_predicate(db, &channel, &sharer, &user).await?;

    let node = get_channel_node(channel.id())
        .await?
        .ok_or_else(|| create_error!(NotInVoiceChannel))?;

    // Capture the EXACT SFU participant identity now, at accept time, and
    // store it in the grant: resolving again at revoke time can fall back
    // to the bare user id and silently no-op for a device-qualified
    // participant — precisely the unrevocable-capability failure the plan
    // forbids.
    let controller_identity = get_voice_participant_identity(channel.id(), &user.id).await?;

    let grant = RemoteControlGrant {
        id: ulid::Ulid::new().to_string(),
        channel_id: channel.id().to_string(),
        server_id: channel.server().map(str::to_string),
        node: node.clone(),
        sharer_id: offer.sharer_id.clone(),
        controller_id: user.id.clone(),
        controller_identity,
    };

    // Record-first ordering fails closed: a record without a capability is
    // harmless, a capability without a record is unrevocable.
    match create_remote_control_grant(&grant).await? {
        RemoteControlGrantOutcome::Created => {}
        RemoteControlGrantOutcome::SharerBusy | RemoteControlGrantOutcome::ControllerBusy => {
            return Err(create_error!(RemoteControlGrantActive));
        }
    }

    // The SFU grant is the authority. Recompute the controller's FULL
    // permission set and flip only `can_publish_data` —
    // `UpdateParticipantOptions` replaces the entire permission message, so
    // a partial one would mute and deafen the controller on grant.
    let mut query = perms(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    let limits = user.limits().await;
    let allowed_sources = get_allowed_sources(&limits, permissions);
    let can_listen = permissions.has_channel_permission(ChannelPermission::Listen);

    if let Err(error) = voice_client
        .update_permissions_identity(
            &node,
            &grant.controller_identity,
            channel.id(),
            remote_control_participant_permissions(can_listen, &allowed_sources),
        )
        .await
    {
        // Failed grant → delete the records AND the offer rather than
        // leaving a pending offer stuck against ghost voice state (voice
        // state has no TTL; the SFU answer is the truth).
        delete_remote_control_grant_records(&grant).await?;
        delete_remote_control_offer(&offer).await?;

        db.insert_remote_control_audit(&audit_row(
            &channel,
            &offer.sharer_id,
            &user.id,
            Some(offer.id.clone()),
            Some(grant.id.clone()),
            "grant_failed",
        ))
        .await?;

        return Err(error);
    }

    // Compare-and-set against a teardown that raced the SFU round trip: a
    // release hook (moderator disconnect, sharer leaving, permission sync)
    // that ran between the record write and here would have found the
    // fresh record, revoked a capability still set to false, deleted every
    // record and already emitted RemoteControlEnded. The capability we
    // just granted would then be live with nothing able to revoke it and
    // no UI showing it. If the record is gone, undo the grant.
    if fetch_remote_control_grant_by_id(&grant.id).await?.is_none() {
        log::warn!(
            "remote control: grant {} was torn down while the SFU update was in flight; revoking",
            grant.id
        );

        if voice_client
            .update_permissions_identity(
                &node,
                &grant.controller_identity,
                channel.id(),
                voice_participant_permissions(can_listen, &allowed_sources),
            )
            .await
            .is_err()
        {
            let _ = voice_client
                .remove_identity(&node, &grant.controller_identity, channel.id())
                .await;
        }

        delete_remote_control_offer(&offer).await?;
        return Err(create_error!(RemoteControlGrantActive));
    }

    delete_remote_control_offer(&offer).await?;

    db.insert_remote_control_audit(&audit_row(
        &channel,
        &offer.sharer_id,
        &user.id,
        Some(offer.id.clone()),
        Some(grant.id.clone()),
        "accepted",
    ))
    .await?;

    // PRIVATE accept event to the SHARER — the return path of the key
    // exchange (plan §1 rev 8: without it the sharer never receives the
    // controller's ephemeral public and can never derive the session key).
    EventV1::RemoteControlAccepted {
        channel_id: grant.channel_id.clone(),
        offer_id: offer.id.clone(),
        grant_id: grant.id.clone(),
        sharer_id: grant.sharer_id.clone(),
        controller_id: grant.controller_id.clone(),
        controller_ephemeral_pub,
    }
    .private(grant.sharer_id.clone())
    .await;

    // REDACTED channel-topic event for third-party visibility: who is
    // controlling whom, and nothing actionable — no grant id, no keys.
    // Emitted once per grant; keyed by (channel, sharer) which
    // RemoteControlEnded clears.
    EventV1::RemoteControlActive {
        channel_id: grant.channel_id.clone(),
        sharer_id: grant.sharer_id.clone(),
        controller_id: grant.controller_id.clone(),
    }
    .p(grant.channel_id.clone())
    .await;

    Ok(Json(v0::RemoteControlRespondResponse {
        grant_id: Some(grant.id),
    }))
}

/// Map the client-supplied teardown cause onto the fixed audit vocabulary.
///
/// The live matrix found `released` conflating five materially different
/// events — sharer revoke, controller release, panic key, connection loss,
/// process kill — leaving the audit unable to say whether the machine's
/// owner yanked control back or someone hit the kill switch. The party
/// ending its own session is the only one that knows why, so the cause is
/// client-INFORMED — but server-CONTROLLED: only these exact strings are
/// accepted, anything else falls back to the caller's role, and nothing a
/// client sends is ever echoed into the audit verbatim.
fn release_audit_reason(cause: Option<&str>, is_sharer: bool) -> &'static str {
    match cause {
        Some("panic") => "panic",
        Some("connection_lost") => "connection_lost",
        Some("anti_cheat") => "anti_cheat",
        Some("indicator_hidden") => "indicator_hidden",
        Some("max_lifetime") => "max_lifetime",
        Some("display_topology_changed") => "display_topology_changed",
        Some("calibration_rejected") => "calibration_rejected",
        // A rotation handoff ("pass the controller"), not a yank. Without
        // its own cause a turn ending would fall back to
        // `revoked_by_sharer`, which is the string that means the machine's
        // owner took control back — so the audit could not tell a friendly
        // handoff from someone pulling the plug on a controller. The
        // streamer's client sends this on turn expiry and on "Next".
        Some("turn_ended") => "turn_ended",
        _ if is_sharer => "revoked_by_sharer",
        _ => "released_by_controller",
    }
}

/// # Release Control Grant
///
/// End an active control grant. Grant-addressed; either party may release,
/// and a moderator holding `MuteMembers` in the channel may revoke (the
/// explicit moderator override — revoking a data-publish capability is a
/// mute-shaped action).
///
/// `cause` refines the audit reason (see [`release_audit_reason`]); absent
/// or unrecognised, the reason defaults by the caller's role.
#[openapi(tag = "Remote Control")]
#[delete("/<target>/control/<grant_id>?<cause>")]
pub async fn control_release(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
    grant_id: String,
    cause: Option<&str>,
) -> Result<EmptyResponse> {
    require_remote_control_enabled().await?;

    let channel = target.as_channel(db).await?;

    let grant = fetch_remote_control_grant_by_id(&grant_id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;

    if grant.channel_id != channel.id() {
        return Err(create_error!(NotFound));
    }

    let reason = if user.id == grant.sharer_id || user.id == grant.controller_id {
        release_audit_reason(cause, user.id == grant.sharer_id)
    } else {
        let mut query = perms(db, &user).channel(&channel);
        let permissions = calculate_channel_permissions(&mut query).await;
        permissions.throw_if_lacking_channel_permission(ChannelPermission::MuteMembers)?;
        "revoked_by_moderator"
    };

    end_remote_control_grant(db, voice_client, &grant, reason, true).await;

    Ok(EmptyResponse)
}

/// # Control Heartbeat
///
/// SHARER-driven consent re-assertion (never controller-driven: the party
/// whose OS is at risk is the one who must keep saying yes — a
/// controller-driven heartbeat would keep the grant alive precisely when
/// the sharer has gone dark). Missing heartbeats expire the grant within
/// single-digit seconds via the crond reaper.
///
/// The heartbeat also re-checks that the sharer is still publishing screen
/// VIDEO. Without that, a sharer could end the share and keep the session
/// alive indefinitely just by heartbeating — the controller driving a
/// machine they can no longer see, which the plan calls worse than no
/// control at all, and the exact inverse of the conflated-flag bug the
/// offer gate fixes.
#[openapi(tag = "Remote Control")]
#[post("/<target>/control/heartbeat")]
pub async fn control_heartbeat(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    require_remote_control_enabled().await?;

    let channel = target.as_channel(db).await?;

    let grant = fetch_remote_control_grant(channel.id(), &user.id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;

    let user_voice_channel = UserVoiceChannel::from_channel(&channel);
    let publishing_screen_video = get_voice_state(&user_voice_channel, &user.id)
        .await?
        .is_some_and(|state| state.screen_video);

    if !publishing_screen_video {
        end_remote_control_grant(db, voice_client, &grant, "screenshare_ended", true).await;

        return Err(create_error!(FailedValidation {
            error: "sharer is not publishing screen video".to_string()
        }));
    }

    heartbeat_remote_control_grant(&grant).await?;

    Ok(EmptyResponse)
}

// Route tests live alongside the harness-driven suites: they exercise the
// predicate legs that do not need a live SFU. The accept path's SFU leg is
// covered by pinning the channel to a node absent from the test config
// (`UnknownNode` — the same ABSENT_NODE technique member_edit's tests use),
// which drives the fail-closed branch deterministically.
#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_voice_state,
            remote_control::{
                fetch_remote_control_grant, fetch_remote_control_offer,
                REMOTE_CONTROL_OFFER_TTL_SECS,
            },
            set_channel_node, update_voice_state, UserVoiceChannel,
        },
        Channel, Member, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};

    // 32 zero bytes, unpadded standard base64
    const KEY32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// Pure predicate — no DB. The audit vocabulary is a fixed allowlist;
    /// anything a client invents must collapse to the caller's role, or the
    /// audit trail becomes client-authored prose.
    #[test]
    fn release_audit_reason_maps_causes_and_defaults_by_role() {
        use super::release_audit_reason;

        // Role defaults — the split `released` never made.
        assert_eq!(release_audit_reason(None, true), "revoked_by_sharer");
        assert_eq!(release_audit_reason(None, false), "released_by_controller");

        // The refinements either party may assert about its own teardown.
        for cause in [
            "panic",
            "connection_lost",
            "anti_cheat",
            "indicator_hidden",
            "max_lifetime",
            "display_topology_changed",
            "calibration_rejected",
            "turn_ended",
        ] {
            assert_eq!(release_audit_reason(Some(cause), true), cause);
            assert_eq!(release_audit_reason(Some(cause), false), cause);
        }

        // Unknown strings NEVER pass through — including the old collapsed
        // value, prose, and near-misses.
        // `turn_ended ` / `Turn_ended` are here for the same reason `panic `
        // is: the client must send the EXACT literal or the rotation is
        // recorded as a revoke, and a near-miss is the likeliest way for
        // that to happen silently.
        for junk in [
            "released",
            "expired",
            "Panic",
            "panic ",
            "owned lol",
            "",
            "turn_ended ",
            "Turn_ended",
            "turnended",
        ] {
            assert_eq!(release_audit_reason(Some(junk), true), "revoked_by_sharer");
            assert_eq!(
                release_audit_reason(Some(junk), false),
                "released_by_controller"
            );
        }
    }

    async fn voice_channel(
        harness: &TestHarness,
        server: &revolt_database::Server,
        name: &str,
    ) -> Channel {
        Channel::create_server_channel(
            &harness.db,
            &mut server.clone(),
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: name.to_string(),
                description: None,
                nsfw: Some(false),
                spoiler: None,
                voice: Some(v0::VoiceInformation {
                    max_users: None,
                    disabled: false,
                }),
                announcement: None,
            },
            true,
        )
        .await
        .expect("voice channel")
    }

    /// Connect a user to the call, optionally publishing screen video
    async fn connect(channel: &Channel, user: &User, screen_video: bool) -> UserVoiceChannel {
        let uvc = UserVoiceChannel::from_channel(channel);
        create_voice_state(&uvc, &user.id, Timestamp::now_utc())
            .await
            .expect("voice state");
        if screen_video {
            update_voice_state(
                &uvc,
                &user.id,
                &v0::PartialUserVoiceState {
                    screen_video: Some(true),
                    screensharing: Some(true),
                    ..Default::default()
                },
            )
            .await
            .expect("screen video flag");
        }
        uvc
    }

    async fn offer<'a>(
        harness: &'a TestHarness,
        token: &str,
        channel_id: &str,
        target_id: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .post(format!("/channels/{channel_id}/control/offer"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(
                serde_json::json!({
                    "target": target_id,
                    "sharer_ephemeral_pub": KEY32,
                    "rc_session_id": KEY32,
                })
                .to_string(),
            )
            .dispatch()
            .await
    }

    async fn respond<'a>(
        harness: &'a TestHarness,
        token: &str,
        channel_id: &str,
        offer_id: &str,
        accept: bool,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .put(format!(
                "/channels/{channel_id}/control/offers/{offer_id}/respond"
            ))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(
                serde_json::json!({
                    "accept": accept,
                    "controller_ephemeral_pub": KEY32,
                })
                .to_string(),
            )
            .dispatch()
            .await
    }

    async fn offer_id_of(response: rocket::local::asynchronous::LocalResponse<'_>) -> String {
        assert_eq!(response.status(), Status::Ok);
        serde_json::from_str::<v0::RemoteControlOfferResponse>(
            &response.into_string().await.unwrap(),
        )
        .unwrap()
        .offer_id
    }

    async fn assert_error(
        response: rocket::local::asynchronous::LocalResponse<'_>,
        status: Status,
        needle: &str,
    ) {
        assert_eq!(response.status(), status);
        assert!(
            response.into_string().await.unwrap().contains(needle),
            "expected the {needle} error"
        );
    }

    /// Server-channel harness: owner (auto-holds bit 41 via GrantAllSafe)
    /// + two plain members in a voice call
    async fn server_call() -> (
        TestHarness,
        revolt_database::Server,
        Channel,
        UserVoiceChannel,
        (String, User),
        (String, User),
        (String, User),
    ) {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner/sharer
        let (_b, session_b, user_b) = harness.new_user().await; // target
        let (_c, session_c, user_c) = harness.new_user().await; // third party
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");
        Member::create(&harness.db, &server, &user_c, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = connect(&channel, &user_a, true).await;
        connect(&channel, &user_b, false).await;
        connect(&channel, &user_c, false).await;
        // A node ABSENT from the test config: the accept path's SFU update
        // then fails deterministically with UnknownNode (no network stall).
        set_channel_node(channel.id(), "test-node-with-no-sfu")
            .await
            .expect("node");

        (
            harness,
            server,
            channel,
            uvc,
            (session_a.token, user_a),
            (session_b.token, user_b),
            (session_c.token, user_c),
        )
    }

    async fn cleanup(uvc: &UserVoiceChannel, users: &[&User]) {
        let ids: Vec<String> = users.iter().map(|u| u.id.clone()).collect();
        delete_channel_voice_state(uvc, &ids).await.expect("cleanup");
    }

    // NB: `remote_control_offer` is a 2-per-10s bucket keyed by (user,
    // channel), so no test may make more than two offer requests as the
    // same user in the same channel — REJECTED requests count too. That is
    // why these legs are split across tests rather than chained.

    #[test]
    fn offer_rejects_self_and_a_target_outside_the_call() {
        crate::util::test::rt().block_on(offer_rejects_self_and_a_target_outside_the_call_case())
    }

    async fn offer_rejects_self_and_a_target_outside_the_call_case() {
        let (harness, _server, channel, uvc, (token_a, user_a), (_, user_b), (_, user_c)) =
            server_call().await;

        // Self-offer is refused outright: every other check passes when a
        // sharer names themselves, and accepting would be a self-service
        // `can_publish_data` grant.
        let response = offer(&harness, &token_a, channel.id(), &user_a.id).await;
        assert_error(response, Status::BadRequest, "InvalidOperation").await;

        // A target who is not a live participant is refused.
        let (_d, _session_d, user_d) = harness.new_user().await;
        let response = offer(&harness, &token_a, channel.id(), &user_d.id).await;
        assert_error(response, Status::BadRequest, "NotInVoiceChannel").await;

        cleanup(&uvc, &[&user_a, &user_b, &user_c]).await;
    }

    #[test]
    fn offer_gates_on_screen_video_not_the_conflated_flag() {
        crate::util::test::rt().block_on(offer_gates_on_screen_video_not_the_conflated_flag_case())
    }

    async fn offer_gates_on_screen_video_not_the_conflated_flag_case() {
        let (harness, _server, channel, uvc, (token_a, user_a), (_, user_b), (_, user_c)) =
            server_call().await;

        // The B-2 regression leg: screen audio unmuted after the video
        // track ended leaves the legacy `screensharing` flag true with
        // `screen_video` false. The offer must be refused — control over a
        // screen with no video is the "blind control" state.
        update_voice_state(
            &uvc,
            &user_a.id,
            &v0::PartialUserVoiceState {
                screensharing: Some(true),
                screen_video: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let response = offer(&harness, &token_a, channel.id(), &user_b.id).await;
        assert_error(response, Status::BadRequest, "not publishing screen video").await;

        // The inverse leg: screen audio stopped while the video track is
        // still live must NOT block the offer.
        update_voice_state(
            &uvc,
            &user_a.id,
            &v0::PartialUserVoiceState {
                screensharing: Some(false),
                screen_video: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let response = offer(&harness, &token_a, channel.id(), &user_b.id).await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "a live screen-video track must satisfy the gate on its own"
        );

        cleanup(&uvc, &[&user_a, &user_b, &user_c]).await;
    }

    #[test]
    fn offer_pending_uniqueness_and_decline_flow() {
        crate::util::test::rt().block_on(offer_pending_uniqueness_and_decline_flow_case())
    }

    async fn offer_pending_uniqueness_and_decline_flow_case() {
        let (harness, _server, channel, uvc, (token_a, user_a), (token_b, user_b), (token_c, user_c)) =
            server_call().await;

        let first = offer(&harness, &token_a, channel.id(), &user_b.id).await;
        let offer_id = offer_id_of(first).await;

        // A second offer while one is pending is refused, not overwritten.
        let response = offer(&harness, &token_a, channel.id(), &user_c.id).await;
        assert_error(response, Status::Conflict, "RemoteControlOfferPending").await;

        // Only the named target may respond — a third party gets 404.
        let response = respond(&harness, &token_c, channel.id(), &offer_id, true).await;
        assert_eq!(response.status(), Status::NotFound);

        // Decline clears the offer record (and with it the pending slot).
        let response = respond(&harness, &token_b, channel.id(), &offer_id, false).await;
        assert_eq!(response.status(), Status::Ok);
        assert!(fetch_remote_control_offer(&offer_id).await.unwrap().is_none());

        cleanup(&uvc, &[&user_a, &user_b, &user_c]).await;
    }

    #[test]
    fn declining_frees_the_sharers_pending_slot() {
        crate::util::test::rt().block_on(declining_frees_the_sharers_pending_slot_case())
    }

    async fn declining_frees_the_sharers_pending_slot_case() {
        let (harness, _server, channel, uvc, (token_a, user_a), (token_b, user_b), (_, user_c)) =
            server_call().await;

        let response = offer(&harness, &token_a, channel.id(), &user_b.id).await;
        let offer_id = offer_id_of(response).await;

        let response = respond(&harness, &token_b, channel.id(), &offer_id, false).await;
        assert_eq!(response.status(), Status::Ok);

        // The pending marker is keyed (channel, sharer) — a decline must
        // release it, or one ignored dialog would lock the sharer out of
        // offering control in this channel until the TTL.
        let response = offer(&harness, &token_a, channel.id(), &user_c.id).await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "a declined offer must free the sharer's pending slot"
        );

        cleanup(&uvc, &[&user_a, &user_b, &user_c]).await;
    }

    #[test]
    fn accept_fails_closed_when_sfu_refuses() {
        crate::util::test::rt().block_on(accept_fails_closed_when_sfu_refuses_case())
    }

    async fn accept_fails_closed_when_sfu_refuses_case() {
        let (harness, _server, channel, uvc, (token_a, user_a), (token_b, user_b), (_, user_c)) =
            server_call().await;

        let response = offer(&harness, &token_a, channel.id(), &user_b.id).await;
        let offer_id = offer_id_of(response).await;

        // The channel's node is absent from the test config, so the SFU
        // permission update fails — the accept must fail CLOSED: no grant
        // record left behind, and the offer deleted rather than stuck.
        let response = respond(&harness, &token_b, channel.id(), &offer_id, true).await;
        assert_ne!(response.status(), Status::Ok);
        assert!(
            fetch_remote_control_grant(channel.id(), &user_a.id)
                .await
                .unwrap()
                .is_none(),
            "a refused SFU grant must delete the grant record"
        );
        assert!(
            fetch_remote_control_offer(&offer_id).await.unwrap().is_none(),
            "a refused SFU grant must delete the offer rather than leave it pending"
        );

        cleanup(&uvc, &[&user_a, &user_b, &user_c]).await;
    }

    #[test]
    fn server_channel_gates_the_sharer_on_the_bit() {
        crate::util::test::rt().block_on(server_channel_gates_the_sharer_on_the_bit_case())
    }

    async fn server_channel_gates_the_sharer_on_the_bit_case() {
        let (harness, server, channel, uvc, (_token_a, user_a), (token_b, user_b), (_, user_c)) =
            server_call().await;

        // user_b (a plain member, no bit 41) starts publishing screen
        // video; DEFAULT_PERMISSION does not include UseRemoteControl, so
        // their offer must be refused on the permission.
        connect(&channel, &user_b, true).await;
        let response = offer(&harness, &token_b, channel.id(), &user_c.id).await;
        assert_error(response, Status::Forbidden, "MissingPermission").await;

        // Granting the bit via a role turns the same offer into a success.
        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::UseRemoteControl as i64,
                    d: 0,
                }),
            )
            .await;
        let mut member = harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .expect("member");
        member
            .update(
                &harness.db,
                revolt_database::PartialMember {
                    roles: Some(vec![role.id.clone()]),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("role grant");

        let response = offer(&harness, &token_b, channel.id(), &user_c.id).await;
        assert_eq!(response.status(), Status::Ok);

        cleanup(&uvc, &[&user_a, &user_b, &user_c]).await;
    }

    #[test]
    fn group_dm_does_not_gate_on_the_bit() {
        crate::util::test::rt().block_on(group_dm_does_not_gate_on_the_bit_case())
    }

    async fn group_dm_does_not_gate_on_the_bit_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // group OWNER
        let (_b, session_b, user_b) = harness.new_user().await; // plain member

        let mut group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: "Call".to_string(),
                description: None,
                icon: None,
                users: [user_b.id.clone()].into(),
                nsfw: None,
                spoiler: None,
            },
            user_a.id.clone(),
        )
        .await
        .expect("group");

        // Groups have calling OFF by default; the owner turns it on.
        group
            .update(
                &harness.db,
                revolt_database::PartialChannel {
                    voice: Some(revolt_database::VoiceInformation {
                        max_users: None,
                        disabled: false,
                    }),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("enable group calling");

        let uvc = connect(&group, &user_a, false).await;
        // The NON-OWNER shares their screen and offers control: non-owners
        // of existing groups hold only ViewChannel + ReadMessageHistory, so
        // gating on bit 41 would pass for the owner and fail for everyone
        // else — the rule is config-flag only in groups (plan §1 H-5).
        connect(&group, &user_b, true).await;

        let response = offer(&harness, &session_b.token, group.id(), &user_a.id).await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "a non-owner group member must be able to offer control"
        );

        // ...and the offer is respondable by the owner up until the SFU
        // leg (no node is set on this fresh group call → NotInVoiceChannel
        // from node resolution, NOT a permission refusal).
        let offer_id = offer_id_of(response).await;
        let response = respond(&harness, &session_a.token, group.id(), &offer_id, true).await;
        assert_ne!(response.status(), Status::Forbidden);

        cleanup(&uvc, &[&user_a, &user_b]).await;
    }

    #[test]
    fn offers_expire_with_the_pending_marker() {
        crate::util::test::rt().block_on(offers_expire_with_the_pending_marker_case())
    }

    async fn offers_expire_with_the_pending_marker_case() {
        // Not a live-expiry test (90s is too long for a suite) — assert the
        // constant stays "short" per the plan so a stalled dialog cannot
        // hold the sharer's pending slot indefinitely.
        assert!(REMOTE_CONTROL_OFFER_TTL_SECS <= 120);
    }
}
