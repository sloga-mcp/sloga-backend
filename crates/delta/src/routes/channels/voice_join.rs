use revolt_config::config;
use revolt_database::{
    util::{permissions::perms, reference::Reference},
    voice::{
        assert_call_caps_admit, drop_voice_participant_session, get_channel_node,
        get_user_voice_channel_in_server, get_user_voice_channels, get_voice_channel_members,
        join_call_occupancy_refuses, raise_if_in_voice, recorded_voice_connections,
        set_call_notification_recipients, set_channel_node, set_voice_participant_session,
        tear_down_removed_connections, EvictionFailure, UserVoiceChannel, VoiceClient,
    },
    Database, Session, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result, ToRevoltError};

use rocket::{serde::json::Json, State};

/// Device-qualified join (media E2EE, plan Q4): the claimed device must be a
/// registered E2EE device of the calling user AND the calling session must be
/// bound to it — a stolen web token cannot then impersonate a device identity
/// on the SFU. A bare join (no device id) is the pre-E2EE path and passes.
///
/// Shared by `join_call` and `screen_leg` (android-screen-share plan §2.1
/// step 5) rather than copied: a duplicated security check drifts, and the
/// leg's identity is derived from a device claim exactly as the primary's is.
pub(crate) async fn assert_device_bound_session(
    db: &Database,
    user: &User,
    session: &Session,
    device_id: Option<&str>,
) -> Result<()> {
    let Some(device_id) = device_id else {
        return Ok(());
    };

    crate::routes::mls::require_media_e2ee_enabled().await?;

    let identity = db
        .fetch_e2ee_identity(&user.id, device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "joining device is not registered".to_string()
            })
        })?;

    identity.assert_bound_session(&session.id)
}

/// # Join Call
///
/// Asks the voice server for a token to join the call.
#[openapi(tag = "Voice")]
#[post("/<target>/join_call", data = "<data>")]
pub async fn call(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    session: Session,
    target: Reference<'_>,
    data: Json<v0::DataJoinCall>,
) -> Result<Json<v0::CreateVoiceUserResponse>> {
    if !voice_client.is_enabled() {
        return Err(create_error!(LiveKitUnavailable));
    }

    let v0::DataJoinCall {
        node,
        force_disconnect,
        recipients,
        device_id,
        rejoin,
    } = data.into_inner();

    if user.bot.is_some() && force_disconnect == Some(true) {
        return Err(create_error!(IsBot));
    }

    assert_device_bound_session(db, &user, &session, device_id.as_deref()).await?;

    let channel = target.as_channel(db).await?;

    let Some(voice_info) = channel.voice() else {
        return Err(create_error!(NotAVoiceChannel));
    };

    let mut permissions = perms(db, &user).channel(&channel);

    let current_permissions = calculate_channel_permissions(&mut permissions).await;
    current_permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;

    let user_voice_channel = UserVoiceChannel::from_channel(&channel);

    // The occupancy rule is the database crate's, the one a tokenless move
    // asks before it sends its target here (merge slice M2B-1, RRB-5), so the
    // two can never disagree about whether this channel is full for this
    // joiner.
    let members = get_voice_channel_members(&user_voice_channel).await?;
    if join_call_occupancy_refuses(
        members.as_deref(),
        voice_info.max_users,
        current_permissions.has(ChannelPermission::ManageChannel as u64),
    ) {
        return Err(create_error!(CannotJoinCall));
    }

    // Call-admission caps (D12 video-participant cap + T-20 MLS SFU-token
    // coupling), enforced against THIS channel for the joining user. This is
    // the shared front-door check (`assert_call_caps_admit`); the moderator
    // voice-move path enforces the identical caps so a privileged door cannot
    // bypass them. Both run OUTSIDE the E2EE device block above (which is
    // gated by require_media_e2ee_enabled), so a non-E2EE / downgraded client
    // that omits device_id cannot bypass them. The only reconnect exemption is
    // server-written membership (same-channel voice state for D12, MLS group
    // membership by user_id for T-20) — NEVER the client-controlled
    // `force_disconnect`, which the real client always sends (6.6 blocker).
    assert_call_caps_admit(db, &user_voice_channel, &user.id).await?;

    let existing_node = get_channel_node(channel.id()).await?;
    let has_existing_node = existing_node.is_some(); // we move existing_node in the next statement so this is the quickest way to know if we need to set it.

    let config = config().await;

    // A server-level voice region only decides where a room is OPENED; it
    // must never move a live room out from under its participants.
    let server_region = match channel.server() {
        Some(server_id) if !has_existing_node => {
            db.fetch_server(server_id).await?.voice_region
        }
        _ => None,
    };

    let node = resolve_join_node(existing_node, server_region, node, |candidate| {
        config.hosts.livekit.contains_key(candidate)
    })
    .ok_or_else(|| create_error!(UnknownNode))?;

    let node_host = config
        .hosts
        .livekit
        .get(&node)
        .ok_or_else(|| create_error!(UnknownNode))?
        .clone();

    // An automatic rejoin must not take the seat back from a connection
    // that is live in another channel (AFK plan Wave 5b-2 S-b, Stage 1
    // I-10): a sibling that was offline when this user was moved would
    // otherwise force-disconnect the moved seat out of its destination.
    // Checked before anything below is torn down. `vc:{user}` alone can be
    // stale after a lost `participant_left` (P2-3), so a listed channel only
    // counts while its `{user}:{server}` pointer still names it; that
    // pointer is keyed by the channel id itself for a DM or group
    // (`create_voice_state`).
    if rejoin == Some(true) {
        let mut previous = Vec::new();
        for previous_channel in get_user_voice_channels(&user.id).await? {
            let pointer = get_user_voice_channel_in_server(
                &user.id,
                previous_channel
                    .server_id
                    .as_deref()
                    .unwrap_or(&previous_channel.id),
            )
            .await?;
            previous.push((previous_channel.id, pointer));
        }

        if rejoin_conflict(&previous, channel.id()) {
            return Err(create_error!(AlreadyConnected));
        }
    }

    if force_disconnect == Some(true) {
        // Finds and disconnects any existing voice connections by the user,
        // should only ever loop once but just to cover our backs. Every
        // channel is tried: a failure in one never stops the next.
        //
        // Each channel follows the same removal rule as
        // `remove_user_from_voice_channel` in the database crate (AFK S-3
        // D-2, amended by WA-R / RA2-1): every connection of the user the SFU
        // lists is evicted, then EXACTLY the connection records this removal
        // knows about are deleted, through the set mode of the teardown
        // script. It is spelled out here because this route's failures are
        // best-effort: a channel whose removal cannot be decided is left as
        // it is and the join still proceeds, so a dead SFU node or a stale
        // entry can never lock a user out of rejoining.
        //
        // ORDERING RULE: the recorded connections are read BEFORE the SFU
        // listing, never after. Read after, a sibling that records between
        // the listing and the read looks stale (recorded but not listed) and
        // is deleted while live (S-3 WA-1). Read before, such a sibling is in
        // neither set, and `delete_voice_connections`' survivor scan keeps
        // its state. This path decides from a listing, so it NEVER runs the
        // whole-user `delete_voice_state`: that would erase the late
        // sibling's state.
        for previous_channel in get_user_voice_channels(&user.id).await? {
            // The kicked participant's session no longer owns anything here,
            // and the record written below is for THIS channel only, which
            // may not be this one. Dropped before the removal, so a move in
            // flight out of this channel fails its re-check instead of
            // handing the session this join kicks a token for the
            // destination (lane 6a4). A kick is not a reconnect: the reason
            // a leave keeps the record does not apply.
            //
            // A failed drop skips THIS channel, as a failed record read or
            // eviction below does: nothing of it is released, evicted or torn
            // down, and the join proceeds (merge slice M2A-2). Evicting
            // anyway would be the unsafe direction: the kicked session would
            // keep a record a move could still hand a token to. What the
            // record that could not be dropped names then depends on where
            // this join goes (merge slice SEC6-4 / S6A-13):
            //
            // - into ANOTHER channel: that record is left alone and still
            //   names a session that is still connected here, because it was
            //   not kicked, so a later move out of here reaches a live owner.
            // - into THIS same channel: the record written at the end of this
            //   join replaces it and hands ownership to the new session,
            //   while the old seat, never kicked, survives beside it. No
            //   token can reach that old seat (a move is announced to the
            //   recorded session alone), and the next move out of the channel
            //   evicts it with every other connection of the user there.
            if let Err(error) = drop_voice_participant_session(&previous_channel.id, &user.id).await
            {
                log::warn!(
                    "force-disconnect of {} from {}: the session record could not be \
                     dropped, so nothing there is evicted or torn down: {error:?}",
                    user.id,
                    previous_channel.id
                );
                continue;
            }

            // Reconnect ends any remote-control grant (plan §1): this path
            // removes the participant and the fresh token below is minted
            // with `can_publish_data: false`, so a controller's capability
            // silently dies here while Redis would keep reading "active".
            // Terminate explicitly — and never "helpfully" re-grant on
            // rejoin.
            revolt_database::voice::remote_control::release_remote_control_for_user(
                db,
                voice_client,
                &previous_channel,
                &user.id,
                "reconnected",
                // The old participant is still connected here — the
                // removal below is best-effort (a failed eviction leaves it
                // in place and the join proceeds), so the capability must
                // be revoked rather than assumed gone.
                false,
            )
            .await;

            // 1. The recorded sids, first. A failed read is never taken for
            //    an empty set: nothing of this channel is evicted or torn
            //    down (ERROR + Sentry through `to_internal_error`), and the
            //    remaining channels are still tried. It is not propagated,
            //    because the failure is this channel's cleanup, not the join
            //    itself: whatever of it is live stays as it was, visible.
            let recorded: Vec<String> =
                match recorded_voice_connections(&previous_channel, &user.id)
                    .await
                    .to_internal_error()
                {
                    Ok(recorded) => recorded.into_iter().map(|(sid, _)| sid).collect(),
                    Err(error) => {
                        log::warn!(
                            "force-disconnect of {} from {}: the connection records could not \
                             be read, so nothing there is evicted or torn down: {error:?}",
                            user.id,
                            previous_channel.id
                        );
                        continue;
                    }
                };

            // 2. ONE listing of the channel's room, every connection of the
            //    user in it evicted (primaries and screen legs). `Ok(None)`:
            //    the SFU has no such room. `Ok(Some(sids))`: the primaries
            //    it listed and evicted, empty when it listed nothing of the
            //    user. `Err`: a listed connection may still be live, so
            //    NOTHING of this channel is torn down, and the survivor stays
            //    visible and syncable. A failure of the SFU itself was
            //    already reported (ERROR + Sentry) where it arose; a node
            //    name no configuration knows (`UnknownNode`) is reported only
            //    by the WARN below. Either way the join proceeds, as it always
            //    has on a failed eviction here, so whether the room was
            //    listed (`EvictionFailure`, AFK S-3 WBR-3) changes nothing
            //    on this path and both cases map back to the plain error. No
            //    node pinned: the call has ended, there is nothing to evict,
            //    and its ghost is torn down below from the recorded sids.
            let evicted = match get_channel_node(&previous_channel.id).await? {
                Some(node) => match voice_client
                    .remove_user_if_present_sids(&node, &user.id, &previous_channel.id)
                    .await
                    .map_err(EvictionFailure::into_error)
                {
                    Ok(evicted) => evicted,
                    Err(error) => {
                        log::warn!(
                            "force-disconnect of {} from {}: the eviction failed, so nothing \
                             there is torn down and the join proceeds: {error:?}",
                            user.id,
                            previous_channel.id
                        );
                        continue;
                    }
                },
                None => None,
            };

            // 3. `returned ∪ (recorded − returned)`: every sid the eviction
            //    returned, then every sid recorded BEFORE the listing that it
            //    did not list (stale), each once. With no listing (no node,
            //    or no room), the recorded sids alone. An EMPTY set is the
            //    script's pure survivor check: with nothing of the user
            //    recorded it is `Last` and the full teardown, which a legacy
            //    connection or a ghost with state and no record needs. A
            //    connection recorded after step 1 that the listing did not
            //    see is in neither set, so the script answers `Survivor` and
            //    it keeps its state. The channel came from `vc:{user}`, so
            //    the user holds state here and the teardown always runs.
            //
            //    The teardown is the database crate's own
            //    (`tear_down_removed_connections`, AFK S-3 WC-3), shared with
            //    `remove_user_from_voice_channel` and the moderator
            //    disconnect: the union (`removal_teardown_sids`, WB-6), the
            //    set delete, and the `VoiceChannelLeave` of a `Last` that no
            //    webhook will announce (WB-8). That is a ghost of an ended
            //    call (no node, so nothing evicted): without the Leave every
            //    other client kept it on the roster. `recorded` was read in
            //    step 1, BEFORE the listing, as that function requires.
            tear_down_removed_connections(&previous_channel, &user.id, evicted, recorded).await?;
        }
    } else {
        raise_if_in_voice(&user, &user_voice_channel).await?;
    }

    let token = voice_client
        .create_token(
            &node,
            db,
            &user,
            current_permissions,
            &channel,
            device_id.as_deref(),
        )
        .await?;

    let room = voice_client.create_room(&node, &channel).await?;

    if !has_existing_node {
        set_channel_node(channel.id(), &node).await?;
    }

    log::debug!("Created room {}", room.name);

    if let Some(recipients) = recipients {
        if room.num_participants == 0 && !recipients.is_empty() {
            set_call_notification_recipients(channel.id(), &user.id, &recipients).await?;
        }
    }

    // This session now owns the user's participant in this channel. A move
    // event goes to it alone, so a session this join kicked above cannot be
    // told to rejoin somewhere (media-e2ee final audit F1). The record also
    // names the seat the token above was minted for, from the same
    // `device_id`: `Some(device)` for the identity `{user}:{device}`, `None`
    // for the bare `{user}`. A move mints exactly the recorded seat kind
    // (merge slice RRB-1, Option A), so a record naming any other seat would
    // mint a moved session an identity it never joined as. Recorded last,
    // once nothing else can refuse the join.
    set_voice_participant_session(channel.id(), &user.id, &session.id, device_id.as_deref())
        .await?;

    Ok(Json(v0::CreateVoiceUserResponse {
        token,
        url: node_host.clone(),
    }))
}

/// Whether a rejoin to `target` would take the seat from a live connection
/// elsewhere. `prev` is every channel in `vc:{user}` with the value of its
/// `{user}:{server}` pointer. A channel is a conflict only when it is not the
/// target AND its pointer still names it: an entry whose pointer is gone, or
/// names another channel, is a stale leftover of a lost leave.
fn rejoin_conflict(prev: &[(String, Option<String>)], target: &str) -> bool {
    prev.iter().any(|(channel_id, pointer)| {
        channel_id != target && pointer.as_deref() == Some(channel_id.as_str())
    })
}

/// Which LiveKit node a join lands on, in priority order:
/// 1. the node the room is already pinned to (first joiner decided),
/// 2. the server's configured voice region — only if that node is still
///    configured, so a region naming a decommissioned node degrades to
///    Auto instead of bricking the server's voice channels,
/// 3. the client's latency pick.
pub(crate) fn resolve_join_node(
    existing_node: Option<String>,
    server_region: Option<String>,
    requested: Option<String>,
    is_configured: impl Fn(&str) -> bool,
) -> Option<String> {
    existing_node
        .or_else(|| server_region.filter(|region| is_configured(region)))
        .or(requested)
}

// NB: these tests share the process-global redis_kiss connection, so (like
// the routes::mls suite) they are only reliable one-per-process — nextest,
// the repo's canonical runner, isolates them; under plain `cargo test` run
// with `--test-threads=1`.
#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        events::client::EventV1,
        voice::{
            create_voice_state, delete_channel_node, delete_channel_voice_state, get_channel_node,
            get_user_voice_channel_in_server, get_user_voice_channels, get_voice_channel_members,
            is_in_voice_channel, mls_cap_would_refuse, record_voice_connection,
            recorded_voice_connections, set_channel_node, update_voice_state,
            video_roster_over_cap, UserVoiceChannel, MAX_VIDEO_PARTICIPANTS,
        },
        Channel, Member, MlsGroup, MlsGroupCreateOutcome, MlsMemberDevice, User,
        MAX_MLS_GROUP_MEMBERS,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};

    /// A server voice channel owned by `owner` with `members` added
    async fn voice_channel(harness: &TestHarness, owner: &User, members: &[&User]) -> Channel {
        let (server, _channels) = harness.new_server(owner).await;

        let channel = Channel::create_server_channel(
            &harness.db,
            &mut server.clone(),
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: "Voice".to_string(),
                description: None,
                nsfw: Some(false),
                spoiler: None,
                voice: Some(v0::VoiceInformation {
                    max_users: None,
                    disabled: false,
                }),
                announcement: None,
                ..Default::default()
            },
            true,
        )
        .await
        .expect("voice channel");

        for member in members {
            Member::create(&harness.db, &server, member, None)
                .await
                .expect("member");
        }

        channel
    }

    /// POST join_call with NO node: a request that passes the cap checks then
    /// fails deterministically at node resolution (400 UnknownNode) — the
    /// caps refuse with 409 BEFORE that point, so the two outcomes cleanly
    /// distinguish "cap fired" from "cap exempted" without a live LiveKit.
    async fn join_call<'a>(
        harness: &'a TestHarness,
        session_token: &str,
        channel_id: &str,
        force_disconnect: bool,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .post(format!("/channels/{channel_id}/join_call"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session_token.to_string()))
            .body(
                serde_json::to_string(&v0::DataJoinCall {
                    node: None,
                    force_disconnect: Some(force_disconnect),
                    recipients: None,
                    device_id: None,
                    rejoin: None,
                })
                .unwrap(),
            )
            .dispatch()
            .await
    }

    async fn assert_refused(
        response: rocket::local::asynchronous::LocalResponse<'_>,
        error_type: &str,
    ) {
        assert_eq!(response.status(), Status::Conflict);
        assert!(
            response.into_string().await.unwrap().contains(error_type),
            "the refusal must be the distinguishable {error_type} error"
        );
    }

    async fn assert_past_caps(response: rocket::local::asynchronous::LocalResponse<'_>) {
        assert_eq!(response.status(), Status::BadRequest);
        assert!(
            response.into_string().await.unwrap().contains("UnknownNode"),
            "an exempt join must get past the caps to node resolution"
        );
    }

    #[test]
    fn video_cap_refuses_overflow_join_despite_force_disconnect() {
        crate::util::test::rt().block_on(video_cap_refuses_overflow_join_despite_force_disconnect_case())
    }

    async fn video_cap_refuses_overflow_join_despite_force_disconnect_case() {
        let harness = TestHarness::new().await;
        let (_account_a, _session_a, user_a) = harness.new_user().await;
        let (_account_b, session_b, user_b) = harness.new_user().await;
        let (_account_c, session_c, user_c) = harness.new_user().await;

        let channel = voice_channel(&harness, &user_a, &[&user_b, &user_c]).await;
        let voice_channel = UserVoiceChannel::from_channel(&channel);

        // Roster at EXACTLY the cap: B (a real member who will reconnect)
        // plus synthetic members, one of which has its camera on — the
        // voice-ingress-shaped Redis state the cap check reads
        create_voice_state(&voice_channel, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state");
        let synthetic_ids: Vec<String> = (0..MAX_VIDEO_PARTICIPANTS - 1)
            .map(|index| format!("0SYNTHVOICEUSER{index:011}"))
            .collect();
        for user_id in &synthetic_ids {
            create_voice_state(&voice_channel, user_id, Timestamp::now_utc())
                .await
                .expect("voice state");
        }
        update_voice_state(
            &voice_channel,
            &synthetic_ids[0],
            &v0::PartialUserVoiceState {
                camera: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("camera flag");

        // The real client ALWAYS sends force_disconnect:true — the flag must
        // not void the cap (6.6 live-proof blocker)
        let response = join_call(&harness, &session_c.token, channel.id(), true).await;
        assert_refused(response, "VideoCallFull").await;

        // ...and the non-force path stays refused
        let response = join_call(&harness, &session_c.token, channel.id(), false).await;
        assert_refused(response, "VideoCallFull").await;

        // B already holds voice state in THIS channel: a genuine same-channel
        // reconnect at the cap is exempt (it never grows the roster)
        let response = join_call(&harness, &session_b.token, channel.id(), true).await;
        assert_past_caps(response).await;

        // Redis is shared and the synthetic ids are fixed strings — drop the
        // seeded voice state so it does not accumulate across runs
        let mut seeded = synthetic_ids;
        seeded.push(user_b.id.clone());
        delete_channel_voice_state(&voice_channel, &seeded)
            .await
            .expect("cleanup");
    }

    #[test]
    fn mls_cap_refuses_overflow_join_despite_force_disconnect() {
        crate::util::test::rt().block_on(mls_cap_refuses_overflow_join_despite_force_disconnect_case())
    }

    async fn mls_cap_refuses_overflow_join_despite_force_disconnect_case() {
        let harness = TestHarness::new().await;
        let (_account_a, _session_a, user_a) = harness.new_user().await;
        let (_account_b, session_b, user_b) = harness.new_user().await;
        let (_account_c, session_c, user_c) = harness.new_user().await;

        let channel = voice_channel(&harness, &user_a, &[&user_b, &user_c]).await;

        // Open MLS group at EXACTLY the roster cap, seeded at the DB layer
        // (the cap check reads the members mirror; no enrollment needed) —
        // B is a group member, C is not
        let mut members: Vec<MlsMemberDevice> = (0..MAX_MLS_GROUP_MEMBERS - 1)
            .map(|index| MlsMemberDevice {
                user_id: format!("0SYNTHETICUSER{index:012}"),
                device_id: format!("{index:032x}"),
            })
            .collect();
        members.push(MlsMemberDevice {
            user_id: user_b.id.clone(),
            device_id: "bb".repeat(16),
        });
        let outcome = harness
            .db
            .create_mls_group(
                &MlsGroup {
                    id: "11".repeat(32),
                    channel_id: channel.id().to_string(),
                    open: true,
                    created_by: members[0].clone(),
                    created_at: Timestamp::now_utc(),
                    current_epoch: 1,
                    members,
                    closed_at: None,
                    superseded_by: None,
                    kind: revolt_database::MlsGroupKind::Call,
                    generation: None,
                    seat_list_ad_sha256: None,
                    pending_removals: vec![],
                    member_added: vec![],
                },
                None,
            )
            .await
            .expect("group seed");
        assert!(matches!(outcome, MlsGroupCreateOutcome::Created));

        // A non-member at the ceiling is refused the SFU token even with
        // force_disconnect:true (T-20 / CR-HIGH-2; 6.6 live-proof blocker)
        let response = join_call(&harness, &session_c.token, channel.id(), true).await;
        assert_refused(response, "MlsCallFull").await;

        // An existing group member (any device) rejoining at the ceiling is
        // exempt — blocking it would lock a crashed member out of a full call
        let response = join_call(&harness, &session_b.token, channel.id(), true).await;
        assert_past_caps(response).await;
    }

    /// The voice-ingress TOCTOU backstop predicates (`video_roster_over_cap` /
    /// `mls_cap_would_refuse`): after a join is recorded they must detect the
    /// overflow the check-then-act join leg could let race past — but stay
    /// inert at/below the cap so the legitimate cap-th member is never evicted.
    #[test]
    fn ingress_backstop_predicates_fire_only_over_cap() {
        crate::util::test::rt().block_on(ingress_backstop_predicates_fire_only_over_cap_case())
    }

    async fn ingress_backstop_predicates_fire_only_over_cap_case() {
        let harness = TestHarness::new().await;
        let (_account_a, _session_a, user_a) = harness.new_user().await;
        let (_account_b, _session_b, user_b) = harness.new_user().await;

        let channel = voice_channel(&harness, &user_a, &[&user_b]).await;
        let voice_channel = UserVoiceChannel::from_channel(&channel);

        // Seed the roster to EXACTLY the cap with one camera on (video active).
        let at_cap: Vec<String> = (0..MAX_VIDEO_PARTICIPANTS)
            .map(|index| format!("0SYNTHVIDEOUSER{index:011}"))
            .collect();
        for user_id in &at_cap {
            create_voice_state(&voice_channel, user_id, Timestamp::now_utc())
                .await
                .expect("voice state");
        }
        update_voice_state(
            &voice_channel,
            &at_cap[0],
            &v0::PartialUserVoiceState {
                camera: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("camera flag");

        // At exactly the cap: NOT over (strict `>`) — the cap-th member stays.
        assert!(
            !video_roster_over_cap(&voice_channel).await.unwrap(),
            "roster at the cap must not be flagged over-cap"
        );

        // One more (the raced overflow) → over cap.
        create_voice_state(&voice_channel, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state");
        assert!(
            video_roster_over_cap(&voice_channel).await.unwrap(),
            "roster past the cap must be flagged over-cap"
        );

        // No open MLS group → the ghost predicate never fires.
        assert!(!mls_cap_would_refuse(&harness.db, channel.id(), &user_b.id)
            .await
            .unwrap());

        // Open group at the roster cap: a non-member is a ghost (refuse), an
        // existing member is not.
        let mut members: Vec<MlsMemberDevice> = (0..MAX_MLS_GROUP_MEMBERS - 1)
            .map(|index| MlsMemberDevice {
                user_id: format!("0SYNTHETICUSER{index:012}"),
                device_id: format!("{index:032x}"),
            })
            .collect();
        members.push(MlsMemberDevice {
            user_id: user_a.id.clone(),
            device_id: "aa".repeat(16),
        });
        harness
            .db
            .create_mls_group(
                &MlsGroup {
                    id: "22".repeat(32),
                    channel_id: channel.id().to_string(),
                    open: true,
                    created_by: members[0].clone(),
                    created_at: Timestamp::now_utc(),
                    current_epoch: 1,
                    members,
                    closed_at: None,
                    superseded_by: None,
                    kind: revolt_database::MlsGroupKind::Call,
                    generation: None,
                    seat_list_ad_sha256: None,
                    pending_removals: vec![],
                    member_added: vec![],
                },
                None,
            )
            .await
            .expect("group seed");
        assert!(
            mls_cap_would_refuse(&harness.db, channel.id(), &user_b.id)
                .await
                .unwrap(),
            "a non-member at the ceiling is a ghost the backstop must evict"
        );
        assert!(
            !mls_cap_would_refuse(&harness.db, channel.id(), &user_a.id)
                .await
                .unwrap(),
            "an existing member is exempt"
        );

        let mut seeded = at_cap;
        seeded.push(user_b.id.clone());
        delete_channel_voice_state(&voice_channel, &seeded)
            .await
            .expect("cleanup");
    }

    // ---- rejoin preemption (AFK plan Wave 5b-2 S-b) ----------------------

    #[test]
    fn rejoin_conflict_counts_only_a_live_other_channel() {
        use super::rejoin_conflict;
        let entry = |id: &str, pointer: Option<&str>| (id.to_string(), pointer.map(str::to_string));

        // Live in another channel: the seat a moderator or the sweep moved.
        assert!(rejoin_conflict(&[entry("B", Some("B"))], "A"));
        // The target itself is never a conflict (a same-channel reconnect).
        assert!(!rejoin_conflict(&[entry("A", Some("A"))], "A"));
        // In no channel at all.
        assert!(!rejoin_conflict(&[], "A"));
        // P2-3: a stale `vc:` entry whose pointer already names the target
        // (the moved seat's own rejoin after a lost leave of `from`).
        assert!(!rejoin_conflict(&[entry("B", Some("A"))], "A"));
        assert!(!rejoin_conflict(
            &[entry("B", Some("A")), entry("A", Some("A"))],
            "A"
        ));
        // An entry whose pointer is gone.
        assert!(!rejoin_conflict(&[entry("B", None)], "A"));
        // One live conflict among stale entries is still a conflict.
        assert!(rejoin_conflict(
            &[entry("C", None), entry("B", Some("B"))],
            "A"
        ));
    }

    /// `call`'s body, comment lines dropped and whitespace collapsed.
    fn call_body() -> String {
        const SOURCE: &str = include_str!("voice_join.rs");
        let at = SOURCE
            .find("pub async fn call(")
            .expect("voice_join.rs no longer defines `call`");
        let open = at + SOURCE[at..].find('\u{7b}').expect("a body");
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in SOURCE[open..].char_indices() {
            match ch {
                '\u{7b}' => depth += 1,
                '\u{7d}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        SOURCE[open..=close.expect("a closed body")]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// S-b: the rejoin refusal runs before anything is torn down. Moved
    /// below the force branch, a sibling's rejoin would already have kicked
    /// the moved seat out of its destination by the time it was refused.
    #[test]
    fn rejoin_check_precedes_every_side_effect() {
        let body = call_body();
        let at = |needle: &str| {
            body.find(needle)
                .unwrap_or_else(|| panic!("`call` lost `{}`: {}", needle, body))
        };

        let guard = at("if rejoin == Some(true)");
        // P2-3: the pointer is read per listed channel, keyed by its server
        // (or by the channel itself for a DM or group).
        let pointer = at(
            "get_user_voice_channel_in_server( &user.id, previous_channel \
             .server_id .as_deref() .unwrap_or(&previous_channel.id), )",
        );
        let check = at("if rejoin_conflict(&previous, channel.id())");
        let refuse = at("return Err(create_error!(AlreadyConnected));");
        assert!(
            guard < pointer && pointer < check && check < refuse,
            "{}",
            body
        );

        // The force-disconnect's side effects (AFK S-3 B5): the session
        // record's drop, the record read, the eviction and the set teardown
        // all come after the refusal.
        for effect in [
            "if force_disconnect == Some(true)",
            "drop_voice_participant_session(",
            "release_remote_control_for_user(",
            "recorded_voice_connections(",
            "remove_user_if_present_sids(",
            "tear_down_removed_connections(",
            "create_token(",
            "create_room(",
            "set_channel_node(",
            "set_call_notification_recipients(",
        ] {
            assert!(
                refuse < at(effect),
                "`{}` runs before the rejoin refusal: {}",
                effect,
                body
            );
        }
    }

    // ---- force-disconnect (AFK S-3 B5) ----------------------------------

    /// The force-disconnect block of `call`, as `call_body` flattens it.
    fn force_disconnect_block() -> String {
        let body = call_body();
        let start = body
            .find("if force_disconnect == Some(true)")
            .expect("`call` lost its force-disconnect block");
        let end = start
            + body[start..]
                .find("else \u{7b} raise_if_in_voice(")
                .expect("the force-disconnect block lost its else arm");
        body[start..end].to_string()
    }

    /// AFK S-3 D-2 (amended by WA-R / RA2-1) for the force-disconnect, per
    /// previous channel: the remote-control release, then the recorded
    /// connections, read BEFORE the one SFU listing the eviction takes, then
    /// the set teardown of the evicted sids plus the recorded ones. Read
    /// after the listing, a sibling that records in between would look stale
    /// and be deleted while live (WA-1). A listing-decided path never runs
    /// the whole-user teardown, never the bool eviction that cannot name the
    /// sids it evicted, and never reads the per-server pointer.
    ///
    /// Both failure arms skip THIS channel and go on to the next: a failed
    /// record read or a failed eviction tears nothing of the channel down
    /// (no teardown on Err), and neither may leave the loop early.
    ///
    /// The listed arms (`Ok(Some)`, `Ok(None)`) need a live SFU and are
    /// pinned here by text only. The no-node and eviction-Err arms are
    /// driven for real in the two tests below.
    ///
    /// AFK S-3 WC-3: the teardown is the database crate's shared
    /// `tear_down_removed_connections`, which also publishes the Leave no
    /// webhook will. A bare `delete_voice_connections(` here would skip that
    /// Leave, so it is banned. S6B-3: the release passes
    /// `participant_already_gone: false`: the eviction below is best-effort,
    /// and `true` would end a controller's grant without revoking a
    /// capability that a failed eviction left live (F-9). Mutations: the
    /// teardown put back to the bare set delete; the release's `false`
    /// turned `true`.
    #[test]
    fn force_disconnect_removes_only_what_it_knows_about() {
        let block = force_disconnect_block();
        let once = |needle: &str| {
            assert_eq!(
                block.matches(needle).count(),
                1,
                "`{}` must appear exactly once in the force-disconnect block: {}",
                needle,
                block
            );
            block.find(needle).unwrap()
        };

        let loop_head = once("for previous_channel in get_user_voice_channels(&user.id).await?");
        let release = once("release_remote_control_for_user(");
        once(
            "release_remote_control_for_user( db, voice_client, &previous_channel, &user.id, \
             \"reconnected\", false, ) .await;",
        );
        let recorded = once(
            "recorded_voice_connections(&previous_channel, &user.id) .await .to_internal_error()",
        );
        let evict = once(
            "remove_user_if_present_sids(&node, &user.id, &previous_channel.id) .await \
             .map_err(EvictionFailure::into_error)",
        );
        // AFK S-3 WC-3: the teardown (and, inside it, the WB-6 union) is the
        // database crate's own, not a copy of it.
        let teardown = once(
            "tear_down_removed_connections(&previous_channel, &user.id, evicted, recorded).await?;",
        );
        assert!(
            loop_head < release && release < recorded && recorded < evict && evict < teardown,
            "the order must be release, recorded read, eviction, set teardown: {}",
            block
        );

        // `remove_user_if_present(` (the bool answer, which cannot name the
        // sids the set teardown needs) replaces the `.remove_user(` ban,
        // which went vacuous when the S-3 cleanup deleted that method.
        for banned in [
            "delete_voice_state(",
            "delete_voice_connections(",
            "remove_user_if_present(",
            "get_user_voice_channel_in_server(",
        ] {
            assert!(
                !block.contains(banned),
                "the force-disconnect decides from a listing and must not call `{}`: {}",
                banned,
                block
            );
        }

        // Each failure arm: an Err arm between its step and the next one,
        // whose only exit is `continue;`, reached before that next step.
        for (step, next, what) in [
            (recorded, evict, "record read"),
            (evict, teardown, "eviction"),
        ] {
            let arm = step
                + block[step..]
                    .find("Err(error) =>")
                    .unwrap_or_else(|| panic!("the {} lost its Err arm: {}", what, block));
            let skip = arm
                + block[arm..].find("continue;").unwrap_or_else(|| {
                    panic!("the failed {} no longer skips the channel: {}", what, block)
                });
            assert!(
                arm < next && skip < next,
                "the failed {} must skip to the next channel before anything after it: {}",
                what,
                block
            );
            let arm_text = &block[arm + "Err(error) =>".len()..skip];
            for banned in [
                "=>",
                "tear_down_removed_connections(",
                "break",
                "return",
                ".await?",
            ] {
                assert!(
                    !arm_text.contains(banned),
                    "the failed {} arm must hold `{}` nowhere: {}",
                    what,
                    banned,
                    arm_text
                );
            }
        }
    }

    /// The observable end state of `user_id` in `uvc`: its connection
    /// records, then whether it is in the user's channel set, in the
    /// channel's member set, and named by the per-server pointer.
    async fn voice_traces(
        uvc: &UserVoiceChannel,
        user_id: &str,
    ) -> (Vec<(String, String)>, bool, bool, bool) {
        let recorded = recorded_voice_connections(uvc, user_id)
            .await
            .expect("recorded read");
        let listed = is_in_voice_channel(user_id, uvc).await.expect("vc read");
        let member = get_voice_channel_members(uvc)
            .await
            .expect("members read")
            .is_some_and(|members| members.iter().any(|id| id == user_id));
        let pointer = get_user_voice_channel_in_server(
            user_id,
            uvc.server_id.as_deref().expect("a server channel"),
        )
        .await
        .expect("pointer read")
        .as_deref()
            == Some(uvc.id.as_str());
        (recorded, listed, member, pointer)
    }

    /// A join as voice-ingress records it: the connection first, then the
    /// state, created only for the user's first connection.
    async fn join_recorded(uvc: &UserVoiceChannel, user_id: &str, sid: &str, identity: &str) {
        if record_voice_connection(uvc, user_id, sid, identity)
            .await
            .expect("record")
        {
            create_voice_state(uvc, user_id, Timestamp::now_utc())
                .await
                .expect("voice state");
        }
    }

    /// A node name no configuration knows: every SFU call addressed to it
    /// fails with `UnknownNode` before any network.
    const ABSENT_NODE: &str = "test-node-with-no-sfu";

    /// The node of the workspace `Revolt.toml`, configured in both
    /// `hosts.livekit` and `api.livekit.nodes`, so a join pinned to it gets
    /// past node resolution and past the force-disconnect. Its SFU address
    /// does not resolve from a test run, so the join then fails at
    /// `create_room` with 500, after everything these tests assert on.
    const JOINABLE_NODE: &str = "worldwide";

    /// POST join_call with force_disconnect into `target`, pinned to
    /// JOINABLE_NODE. Asserts the answer came from past the force-disconnect
    /// (the unreachable SFU's 500) and not from an error raised in it: an
    /// eviction error there answers 400 `UnknownNode`.
    async fn force_join_past_the_disconnect(
        harness: &TestHarness,
        session_token: &str,
        target: &Channel,
    ) {
        set_channel_node(target.id(), JOINABLE_NODE)
            .await
            .expect("pin the target");
        let response = join_call(harness, session_token, target.id(), true).await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        delete_channel_node(target.id())
            .await
            .expect("unpin the target");
        assert_eq!(
            status,
            Status::InternalServerError,
            "the join must get past the force-disconnect to the (unreachable) SFU: {}",
            body
        );
        assert!(!body.contains("UnknownNode"), "{}", body);
    }

    // Needs RabbitMQ and Redis, as every route test in this module does.
    #[test]
    fn force_disconnect_clears_the_ghost_of_every_ended_call() {
        crate::util::test::rt().block_on(force_disconnect_clears_the_ghost_of_every_ended_call_case())
    }

    /// Two calls that ended without their webhooks (no node pinned) leave
    /// the user on both rosters: one with two recorded connections, one
    /// legacy (state, no record, which the empty set tears down as `Last`).
    /// A force-disconnect join elsewhere tears both down from the recorded
    /// sids, as the whole-user teardown did before. Mutations: the recorded
    /// sids dropped from the set (the records survive, the script answers
    /// `Survivor`, the first ghost stays); the teardown skipped.
    ///
    /// AFK S-3 WC-3: each teardown publishes the user's `VoiceChannelLeave`
    /// on that channel's topic. No node is pinned, so nothing is evicted and
    /// no `participant_left` webhook will ever announce the departure;
    /// without it every other client kept the ghost on its roster. Mutation:
    /// the teardown put back to the bare `delete_voice_connections` (the
    /// wait times out).
    async fn force_disconnect_clears_the_ghost_of_every_ended_call_case() {
        let mut harness = TestHarness::new().await;
        let (_account, session, user) = harness.new_user().await;

        let recorded_call = voice_channel(&harness, &user, &[]).await;
        let legacy_call = voice_channel(&harness, &user, &[]).await;
        let target = voice_channel(&harness, &user, &[]).await;
        let recorded_uvc = UserVoiceChannel::from_channel(&recorded_call);
        let legacy_uvc = UserVoiceChannel::from_channel(&legacy_call);

        join_recorded(&recorded_uvc, &user.id, "PA_ghost_bare", &user.id).await;
        join_recorded(
            &recorded_uvc,
            &user.id,
            "PA_ghost_device",
            &format!("{}:DEV", user.id),
        )
        .await;
        create_voice_state(&legacy_uvc, &user.id, Timestamp::now_utc())
            .await
            .expect("legacy voice state");

        // The fixture holds what it claims to, and no node is pinned.
        let (recorded, listed, member, pointer) = voice_traces(&recorded_uvc, &user.id).await;
        assert_eq!(recorded.len(), 2, "two recorded connections");
        assert!(listed && member && pointer, "the recorded ghost has state");
        let (recorded, listed, member, pointer) = voice_traces(&legacy_uvc, &user.id).await;
        assert!(recorded.is_empty(), "the legacy ghost has no record");
        assert!(listed && member && pointer, "the legacy ghost has state");
        for call in [&recorded_call, &legacy_call] {
            assert!(
                get_channel_node(call.id())
                    .await
                    .expect("node read")
                    .is_none(),
                "the call has ended: no node"
            );
        }

        force_join_past_the_disconnect(&harness, &session.token, &target).await;

        for uvc in [&recorded_uvc, &legacy_uvc] {
            let (recorded, listed, member, pointer) = voice_traces(uvc, &user.id).await;
            assert!(
                recorded.is_empty() && !listed && !member && !pointer,
                "the ghost in {} must be torn down, left: recorded {:?}, vc {}, \
                 vc_members {}, pointer {}",
                uvc.id,
                recorded,
                listed,
                member,
                pointer
            );
        }

        for uvc in [&recorded_uvc, &legacy_uvc] {
            harness
                .wait_for_event(&uvc.id, |event| {
                    matches!(
                        event,
                        EventV1::VoiceChannelLeave { id, user: left }
                            if id == &uvc.id && left == &user.id
                    )
                })
                .await;
        }

        for uvc in [&recorded_uvc, &legacy_uvc] {
            delete_channel_voice_state(uvc, &[user.id.clone()])
                .await
                .expect("cleanup");
        }
    }

    // Needs RabbitMQ and Redis, as every route test in this module does.
    #[test]
    fn a_failed_force_disconnect_eviction_tears_nothing_down() {
        crate::util::test::rt().block_on(a_failed_force_disconnect_eviction_tears_nothing_down_case())
    }

    /// An eviction that fails may have left a listed connection live, so
    /// NOTHING of that channel is torn down, and the join still proceeds: a
    /// dead SFU node must not lock the user out of rejoining. The other
    /// channel is still cleared. ABSENT_NODE makes the eviction fail with
    /// `UnknownNode` before any network.
    ///
    /// The failing channel is the one the user's channel set lists FIRST
    /// (the route walks it in the same order), so an early exit on the
    /// failure cannot reach the second channel. Mutations: a teardown on the
    /// Err arm (the failed channel's record and state go); `break` on it (the
    /// second channel's ghost stays); `?` on it (400 `UnknownNode`).
    ///
    /// The session records go in BOTH channels (lane 6a4, merge slice M2a):
    /// the kick drops a channel's record before it tries the eviction, so a
    /// record in the failing channel is gone even though its participant is
    /// not. A move out of it then reaches nobody, the safe direction; a kept
    /// record would still name the session this join kicked. Mutation: the
    /// drop moved after the eviction (the failing channel's record stays).
    async fn a_failed_force_disconnect_eviction_tears_nothing_down_case() {
        use revolt_database::voice::{
            get_voice_participant_session, set_voice_participant_session,
        };

        let harness = TestHarness::new().await;
        let (_account, session, user) = harness.new_user().await;

        let first = voice_channel(&harness, &user, &[]).await;
        let second = voice_channel(&harness, &user, &[]).await;
        let target = voice_channel(&harness, &user, &[]).await;
        join_recorded(
            &UserVoiceChannel::from_channel(&first),
            &user.id,
            "PA_first",
            &user.id,
        )
        .await;
        join_recorded(
            &UserVoiceChannel::from_channel(&second),
            &user.id,
            "PA_second",
            &user.id,
        )
        .await;

        // Assign the roles by the order the route will walk: the set's order
        // is the server's, not the insertion order.
        let walked = get_user_voice_channels(&user.id).await.expect("vc read");
        assert_eq!(walked.len(), 2, "the user is in both calls");
        let (failing, cleared) = (walked[0].clone(), walked[1].clone());
        set_channel_node(&failing.id, ABSENT_NODE)
            .await
            .expect("node");
        let failing_sid = if failing.id == first.id() {
            "PA_first"
        } else {
            "PA_second"
        };
        // Both connections are the bare identity, so both records are bare.
        for channel in [&failing, &cleared] {
            set_voice_participant_session(&channel.id, &user.id, &session.id, None)
                .await
                .expect("record");
        }

        force_join_past_the_disconnect(&harness, &session.token, &target).await;

        for channel in [&failing, &cleared] {
            assert_eq!(
                get_voice_participant_session(&channel.id, &user.id)
                    .await
                    .expect("record read"),
                None,
                "the kick drops the record in {} before its eviction, failed or not",
                channel.id
            );
        }

        let (recorded, listed, member, pointer) = voice_traces(&failing, &user.id).await;
        assert_eq!(
            recorded,
            vec![(failing_sid.to_string(), user.id.clone())],
            "a failed eviction must leave the record in place"
        );
        assert!(
            listed && member && pointer,
            "a failed eviction must leave the voice state in place: vc {}, vc_members {}, \
             pointer {}",
            listed,
            member,
            pointer
        );

        let (recorded, listed, member, pointer) = voice_traces(&cleared, &user.id).await;
        assert!(
            recorded.is_empty() && !listed && !member && !pointer,
            "the channel after the failed one must still be cleared, left: recorded {:?}, \
             vc {}, vc_members {}, pointer {}",
            recorded,
            listed,
            member,
            pointer
        );

        delete_channel_node(&failing.id).await.expect("unpin");
        for uvc in [&failing, &cleared] {
            delete_channel_voice_state(uvc, &[user.id.clone()])
                .await
                .expect("cleanup");
        }
    }

    // ---- server voice region -------------------------------------------

    /// Pure resolution order: pinned room > server region > client pick,
    /// with a region naming an unconfigured node degrading to the client
    /// pick rather than failing the join.
    #[test]
    fn resolve_join_node_priority() {
        use super::resolve_join_node;
        let configured = |node: &str| node == "brazil" || node == "worldwide";
        let s = |v: &str| Some(v.to_string());

        // no room yet: the server's region beats the client's latency pick
        assert_eq!(
            resolve_join_node(None, s("brazil"), s("worldwide"), configured),
            s("brazil")
        );
        // a live room keeps its node even against a (newer) server region
        assert_eq!(
            resolve_join_node(s("worldwide"), s("brazil"), s("brazil"), configured),
            s("worldwide")
        );
        // no region (Auto): the client's pick
        assert_eq!(
            resolve_join_node(None, None, s("brazil"), configured),
            s("brazil")
        );
        // region names a decommissioned node: fall through to the client
        assert_eq!(
            resolve_join_node(None, s("moon"), s("worldwide"), configured),
            s("worldwide")
        );
        // nothing to go on at all
        assert_eq!(resolve_join_node(None, None, None, configured), None);
    }

    async fn edit_server_region(
        harness: &TestHarness,
        session_token: &str,
        server_id: &str,
        body: serde_json::Value,
    ) -> (Status, String) {
        let response = harness
            .client
            .patch(format!("/servers/{server_id}"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session_token.to_string()))
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// The server region only applies where a room is OPENED: with no room
    /// the join lands on the region's node; with a pinned room the pin wins
    /// and the region is ignored. A fake node on a closed port makes the
    /// "region won" outcome observable without a live LiveKit: the join gets
    /// past node resolution (no 400 UnknownNode) and fails on the SFU call
    /// instead, while the pinned bogus node fails AT resolution.
    #[test]
    fn server_region_decides_where_a_room_opens() {
        crate::util::test::rt().block_on(server_region_decides_where_a_room_opens_case())
    }

    async fn server_region_decides_where_a_room_opens_case() {
        // overwrite_config is once-per-process and must run BEFORE the
        // harness primes the config cache (nextest isolates processes)
        revolt_config::overwrite_config(|settings| {
            settings.api.livekit.nodes.insert(
                "testregion".to_string(),
                revolt_config::LiveKitNode {
                    url: "http://127.0.0.1:1".to_string(),
                    lat: 0.0,
                    lon: 0.0,
                    key: "testkey".to_string(),
                    secret: "testsecret-testsecret-testsecret".to_string(),
                    private: true,
                    remote: false,
                },
            );
            settings
                .hosts
                .livekit
                .insert("testregion".to_string(), "ws://127.0.0.1:1".to_string());
        })
        .await;

        let mut harness = TestHarness::new().await;
        let (_account, session, owner) = harness.new_user().await;
        let channel = voice_channel(&harness, &owner, &[]).await;
        let server_id = channel.server().expect("server channel").to_string();

        // unknown region is rejected on edit, and nothing is stored
        let (status, body) = edit_server_region(
            &harness,
            &session.token,
            &server_id,
            serde_json::json!({ "voice_region": "atlantis" }),
        )
        .await;
        assert_eq!(status, Status::BadRequest);
        assert!(body.contains("UnknownNode"), "{}", body);
        assert_eq!(
            harness.db.fetch_server(&server_id).await.unwrap().voice_region,
            None
        );

        // a configured region is stored, returned, and fanned out
        let (status, body) = edit_server_region(
            &harness,
            &session.token,
            &server_id,
            serde_json::json!({ "voice_region": "testregion" }),
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        let returned: v0::Server = serde_json::from_str(&body).unwrap();
        assert_eq!(returned.voice_region.as_deref(), Some("testregion"));
        harness
            .wait_for_event(&server_id, |event| {
                matches!(
                    event,
                    revolt_database::events::client::EventV1::ServerUpdate { data, .. }
                        if data.voice_region.as_deref() == Some("testregion")
                )
            })
            .await;

        // no room yet + no client node: the region decides, so the join
        // gets PAST node resolution and dies on the (unreachable) SFU
        {
            let response = join_call(&harness, &session.token, &channel.id(), false).await;
            assert_eq!(
                response.status(),
                Status::InternalServerError,
                "region must resolve the node when no room exists"
            );
        }

        // a room pinned elsewhere keeps its node: the bogus pin is not a
        // configured host, so resolution itself fails — proving the region
        // was NOT consulted
        revolt_database::voice::set_channel_node(channel.id(), "pinned-elsewhere")
            .await
            .expect("pin");
        {
            let response = join_call(&harness, &session.token, &channel.id(), false).await;
            assert_past_caps(response).await;
        }
        revolt_database::voice::delete_channel_node(channel.id())
            .await
            .expect("unpin");

        // removing the field returns the server to Auto
        let (status, body) = edit_server_region(
            &harness,
            &session.token,
            &server_id,
            serde_json::json!({ "remove": ["VoiceRegion"] }),
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        let returned: v0::Server = serde_json::from_str(&body).unwrap();
        assert_eq!(returned.voice_region, None);
        harness
            .wait_for_event(&server_id, |event| {
                matches!(
                    event,
                    revolt_database::events::client::EventV1::ServerUpdate { clear, .. }
                        if clear.contains(&v0::FieldsServer::VoiceRegion)
                )
            })
            .await;

        // back on Auto with no client pick there is nothing to resolve
        let response = join_call(&harness, &session.token, &channel.id(), false).await;
        assert_past_caps(response).await;
    }

    /// ManageServer gates the region like every other server setting.
    #[test]
    fn server_region_requires_manage_server() {
        crate::util::test::rt().block_on(server_region_requires_manage_server_case())
    }

    async fn server_region_requires_manage_server_case() {
        let harness = TestHarness::new().await;
        let (_account, _owner_session, owner) = harness.new_user().await;
        let (_account_b, member_session, member) = harness.new_user().await;
        let channel = voice_channel(&harness, &owner, &[&member]).await;
        let server_id = channel.server().expect("server channel").to_string();

        let (status, _) = edit_server_region(
            &harness,
            &member_session.token,
            &server_id,
            serde_json::json!({ "voice_region": "worldwide" }),
        )
        .await;
        assert_eq!(status, Status::Forbidden);
    }

    /// `join_call`'s shipping source, comments and whitespace stripped
    /// (`crate::util::test::{without_comments, without_whitespace}`).
    fn join_call_body() -> String {
        use crate::util::test::{without_comments, without_whitespace};

        let source = include_str!("voice_join.rs");
        let shipping = without_whitespace(&without_comments(
            &source[..source.find("#[cfg(test)]").expect("test module")],
        ));
        let start = shipping
            .find("pubasyncfncall(")
            .expect("join_call left voice_join.rs");
        let end = start
            + shipping[start..]
                .find("pub(crate)fnresolve_join_node(")
                .expect("the fn after join_call");
        shipping[start..end].to_string()
    }

    /// The block that opens at the first `\u{7b}` at or after `from` in the
    /// whitespace-free `code`: its text without the braces, and the index
    /// just past its closing brace. Textual brace matching, which holds for
    /// `join_call`'s shipping text: its literals keep their braces paired.
    fn block_from(code: &str, from: usize) -> (&str, usize) {
        let open = from + code[from..].find('\u{7b}').expect("a block");
        let mut depth = 0usize;
        for (i, ch) in code[open..].char_indices() {
            match ch {
                '\u{7b}' => depth += 1,
                '\u{7d}' => {
                    depth -= 1;
                    if depth == 0 {
                        return (&code[open + 1..open + i], open + i + 1);
                    }
                }
                _ => {}
            }
        }
        panic!("an unclosed block at byte {}: {}", open, code);
    }

    /// The top-level arguments of the ONE call of `callee` (its name with
    /// the opening parenthesis) in the whitespace-free `code`, a trailing
    /// comma dropped, and the index just past its closing parenthesis.
    fn only_call_args<'a>(code: &'a str, callee: &str) -> (Vec<&'a str>, usize) {
        assert!(callee.ends_with('('), "`{}` is not a call", callee);
        assert_eq!(
            code.matches(callee).count(),
            1,
            "`{callee}` must be called exactly once: {code}"
        );
        let open = code.find(callee).expect("counted above") + callee.len() - 1;
        let (mut depth, mut start, mut args) = (0usize, open + 1, Vec::new());
        for (i, ch) in code[open..].char_indices() {
            let at = open + i;
            match ch {
                '(' | '[' | '\u{7b}' => depth += 1,
                ')' | ']' | '\u{7d}' => {
                    depth -= 1;
                    if depth == 0 {
                        if start < at {
                            args.push(&code[start..at]);
                        }
                        return (args, at + 1);
                    }
                }
                ',' if depth == 1 => {
                    args.push(&code[start..at]);
                    start = at + 1;
                }
                _ => {}
            }
        }
        panic!("an unclosed call of `{}`: {}", callee, code);
    }

    /// `join_call`'s kick in `join_call_body`: the byte range of the
    /// `force_disconnect` branch's body, and inside it the range of the body
    /// of its loop over the user's channels. The loop is looked for FROM the
    /// branch, never from the top of `call`: the rejoin check above walks the
    /// same channels with an identical loop head (merge slice RT-8), and a
    /// pin that found the first head would hold a drop moved into the rejoin
    /// loop, where it kicks nothing.
    fn kick(body: &str) -> (std::ops::Range<usize>, std::ops::Range<usize>) {
        const BRANCH: &str = "ifforce_disconnect==Some(true)";
        const HEAD: &str = "forprevious_channelinget_user_voice_channels(&user.id).await?";

        assert_eq!(
            body.matches(BRANCH).count(),
            1,
            "join_call has one force_disconnect branch: {body}"
        );
        let branch_at = body.find(BRANCH).expect("counted above");
        let (branch, branch_end) = block_from(body, branch_at);
        let branch_start = branch_end - 1 - branch.len();
        assert!(
            body[branch_end..].starts_with("else\u{7b}raise_if_in_voice("),
            "the force_disconnect branch lost its else arm: {}",
            body
        );

        assert!(
            branch.starts_with(HEAD) && branch.matches(HEAD).count() == 1,
            "the force_disconnect branch is its one loop over the user's channels: {}",
            branch
        );
        let (kick_loop, loop_end) = block_from(body, branch_start);
        let loop_start = loop_end - 1 - kick_loop.len();
        assert!(
            branch_start < loop_start && loop_end < branch_end,
            "the kick loop lies inside the branch"
        );
        (branch_start..branch_end - 1, loop_start..loop_end - 1)
    }

    /// The statement `join_call` records its session with (merge slice
    /// R2-M2b, "P4 MUST pin"), whitespace stripped.
    const RECORD: &str =
        "set_voice_participant_session(channel.id(),&user.id,&session.id,device_id.as_deref()).await?;";

    /// Every join records its session as the participant's owner, which is
    /// where a move event goes (media-e2ee final audit F1). A route test
    /// cannot see it: without a live LiveKit, `create_room` fails first. So
    /// the whole statement is pinned textually, comments stripped: made
    /// exactly once, on its own with its `.await?`, with THIS request's
    /// session and seat, after the device check, the kick loop and
    /// `create_room` (a refused join must not take the record over), and as
    /// the LAST statement before the response. Controls VJ (the line
    /// commented out), VJLET (`let _ = …;`), VJTRAIL (a statement with the
    /// record in a trailing comment), AB (the line deleted), REC-EARLY (the
    /// record moved above `.create_token(`).
    #[test]
    fn join_call_records_the_joining_session_after_every_refusal() {
        use crate::util::test::statement_at;

        let body = join_call_body();
        assert_eq!(
            body.matches("set_voice_participant_session(").count(),
            1,
            "join_call records the session exactly once"
        );
        let recorded_at = statement_at(&body, RECORD);

        let (branch, _) = kick(&body);
        assert!(
            branch.end < recorded_at,
            "the session is recorded only after the kick loop"
        );
        for earlier in [
            "assert_device_bound_session(",
            "raise_if_in_voice(",
            ".create_token(",
            ".create_room(",
            "set_call_notification_recipients(",
        ] {
            let at = body
                .find(earlier)
                .unwrap_or_else(|| panic!("`{}` left join_call", earlier));
            assert!(
                at < recorded_at,
                "the session is recorded only after `{}`",
                earlier
            );
        }

        assert!(
            body[recorded_at + RECORD.len()..].starts_with("Ok(Json(v0::CreateVoiceUserResponse"),
            "the record is the last statement before the response: {}",
            &body[recorded_at..]
        );
    }

    /// Merge slice RRB-1 (Option A): the record names the seat the join
    /// MINTED, because a move mints exactly the recorded seat kind. The
    /// request's `device_id` is bound ONCE, by the destructure, and never
    /// rebound, and that one binding is what the device check admits, what
    /// the token is minted for (`Some(device)` = `{user}:{device}`, `None` =
    /// the bare `{user}`) and what the record stores. A second binding (a
    /// `let`, a shadowing pattern, a closure parameter) would add a mention
    /// of `device_id` and fails the count. No route test can see the seat:
    /// the record is written after `create_room`, which fails without a live
    /// LiveKit. Controls REC-NONE (`None` as the fourth argument), REC-OTHER
    /// (`Some(session.id.as_str())` as the fourth argument), REC-EARLY.
    #[test]
    fn the_record_names_the_seat_the_join_minted() {
        use crate::util::test::statement_at;

        const SEAT: &str = "device_id.as_deref()";

        let body = join_call_body();
        statement_at(
            &body,
            "letv0::DataJoinCall\u{7b}node,force_disconnect,recipients,device_id,rejoin,\u{7d}=data.into_inner();",
        );
        assert_eq!(
            body.matches(SEAT).count(),
            3,
            "the device check, the token and the record each read the request's device: {body}"
        );
        assert_eq!(
            body.matches("device_id").count(),
            1 + 3,
            "`device_id` is the destructure's binding and its three reads, nothing else: {body}"
        );

        let checked_at = statement_at(
            &body,
            "assert_device_bound_session(db,&user,&session,device_id.as_deref()).await?;",
        );
        let (minted, _) = only_call_args(&body, ".create_token(");
        assert_eq!(
            minted,
            [
                "&node",
                "db",
                "&user",
                "current_permissions",
                "&channel",
                SEAT
            ],
            "the token is minted for the request's device"
        );
        let (recorded, _) = only_call_args(&body, "set_voice_participant_session(");
        assert_eq!(
            recorded,
            ["channel.id()", "&user.id", "&session.id", SEAT],
            "the record names this channel, this user, this session and the minted seat"
        );

        let minted_at = body.find(".create_token(").expect("pinned above");
        let recorded_at = statement_at(&body, RECORD);
        assert!(
            checked_at < minted_at && minted_at < recorded_at,
            "the device check, then the token, then the record: {}",
            body
        );
    }

    /// Merge slice RRB-5: `join_call` refuses a full channel through the
    /// database crate's own occupancy rule, the one a tokenless move asks
    /// before it sends its target here, called once with exactly the three
    /// things the inline rule read: the roster of THIS channel, its cap and
    /// THIS joiner's ManageChannel, and the same refusal at the same place
    /// (after Connect, before the caps). The rule's values are the database
    /// crate's (`the_tokenless_move_asks_join_calls_own_occupancy_rule`).
    /// Controls OCC-EXEMPT (`|| true` on the ManageChannel flag), OCC-TWICE
    /// (a second call), OCC-ARGS (`None` for the cap).
    #[test]
    fn join_call_asks_the_shared_occupancy_rule_for_this_joiner() {
        use crate::util::test::statement_at;

        let body = join_call_body();
        let connect_at = statement_at(
            &body,
            "current_permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;",
        );
        statement_at(
            &body,
            "letcurrent_permissions=calculate_channel_permissions(&mutpermissions).await;",
        );
        statement_at(
            &body,
            "letuser_voice_channel=UserVoiceChannel::from_channel(&channel);",
        );
        let read_at = statement_at(
            &body,
            "letmembers=get_voice_channel_members(&user_voice_channel).await?;",
        );
        for binding in ["current_permissions=", "user_voice_channel=", "members="] {
            assert_eq!(
                body.matches(binding).count(),
                1,
                "`{binding}` is bound once: {body}"
            );
        }

        let (args, end) = only_call_args(&body, "join_call_occupancy_refuses(");
        assert_eq!(
            args,
            [
                "members.as_deref()",
                "voice_info.max_users",
                "current_permissions.has(ChannelPermission::ManageChannelasu64)",
            ],
            "the roster read, the channel's cap and this joiner's ManageChannel"
        );
        let asked_at = body.find("join_call_occupancy_refuses(").expect("counted");
        assert!(
            body[..asked_at].ends_with(";if")
                && body[end..].starts_with("\u{7b}returnErr(create_error!(CannotJoinCall));\u{7d}"),
            "a full channel is refused with CannotJoinCall and nothing else: {}",
            body
        );

        let caps_at = body
            .find("assert_call_caps_admit(")
            .expect("join_call's caps");
        assert!(
            connect_at < read_at && read_at < asked_at && asked_at < caps_at,
            "Connect, then the roster, then the occupancy rule, then the caps: {}",
            body
        );
    }

    /// The force-disconnect loop drops the kicked channel's session record
    /// FIRST, before it releases, reads, evicts or tears down anything there
    /// (lane 6a4), and only there: in the KICK loop (merge slice RT-8, never
    /// the rejoin loop above it, found by `kick`), bounded by the loop's
    /// closing brace (RRB-2). A failed drop skips the channel through an arm
    /// that logs and continues and does nothing else (M2A-2): never `?`,
    /// which fails the join, and never on to the eviction, which would leave
    /// the kicked session a record. The route tests below see the record go
    /// but cannot see the order, nor a drop that fails. Controls NODROP (the
    /// drop deleted), DROPLOOP (moved into the rejoin loop), DROPLATE (after
    /// the channel's teardown), DROPAFTER (just after the kick loop),
    /// DROP-QMARK (the old `.await?;` statement).
    #[test]
    fn a_kick_drops_the_kicked_channels_record_before_the_removal() {
        const DROP: &str =
            "ifletErr(error)=drop_voice_participant_session(&previous_channel.id,&user.id).await";

        let body = join_call_body();
        assert_eq!(
            body.matches("drop_voice_participant_session(").count(),
            1,
            "join_call drops a record only in the kick loop: {body}"
        );
        let (branch, lp) = kick(&body);
        let kick_loop = &body[lp.clone()];
        let dropped_at = body
            .find("drop_voice_participant_session(")
            .expect("counted above");
        assert!(
            lp.start < dropped_at && dropped_at < lp.end && lp.end < branch.end,
            "the drop lies inside the kick loop: {}",
            body
        );

        assert!(
            kick_loop.starts_with(DROP) && kick_loop[DROP.len()..].starts_with('\u{7b}'),
            "the drop is the kick loop's first statement, its failure handled on the spot: {}",
            kick_loop
        );
        let (arm, arm_end) = block_from(kick_loop, DROP.len());
        let logged = arm
            .strip_prefix("log::warn!(")
            .and_then(|rest| rest.strip_suffix(");continue;"))
            .unwrap_or_else(|| {
                panic!(
                    "a failed drop logs, then skips the channel, and nothing else: {}",
                    arm
                )
            });
        assert!(
            !logged.contains(';') && logged.contains("error:?"),
            "the arm is one WARN naming the error, then `continue`: {}",
            arm
        );
        assert!(
            !kick_loop[arm_end..].starts_with("else"),
            "a drop that succeeded goes on to the removal: {}",
            kick_loop
        );

        for later in [
            "release_remote_control_for_user(",
            "recorded_voice_connections(",
            "remove_user_if_present_sids(",
            "tear_down_removed_connections(",
        ] {
            let at = kick_loop
                .find(later)
                .unwrap_or_else(|| panic!("`{}` left the kick loop", later));
            assert!(
                arm_end <= at,
                "the record is dropped before `{}`: {kick_loop}",
                later
            );
        }
    }

    /// Every shipping Rust source of this crate as (`src`-relative path,
    /// text), comments and then `#[cfg(test)]` items stripped. Comments are
    /// cut first (`util::test::without_comments`), so neither a comment that
    /// names the attribute nor a brace in a comment matters. The items are
    /// then matched on that text with the older algorithm, NOT the database
    /// crate's workspace scan (which reads both the attribute and the braces
    /// off text with the literals blanked too): every `#[cfg(test)]`
    /// occurrence counts, one inside a string literal and one in the middle
    /// of a line included, followed by a brace-matched body or a bodyless
    /// item ending in `;`, and braces are counted raw, so a brace inside a
    /// string or char literal moves the match (the S6RM-5 and S6F3A-2 shapes
    /// are still open here, HD re-audit HDA-6). An item that never closes is
    /// a panic, never a silent truncation of the shipping text below it.
    fn delta_shipping_sources() -> Vec<(String, String)> {
        fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read the source directory") {
                let path = entry.expect("read a source directory entry").path();
                if path.is_dir() {
                    rust_sources(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    out.push(path);
                }
            }
        }

        fn strip_test_items(rel: &str, source: &str) -> String {
            const ATTR: &str = "#[cfg(test)]";
            let mut shipping = String::with_capacity(source.len());
            let mut rest = source;
            while let Some(attr) = rest.find(ATTR) {
                shipping.push_str(&rest[..attr]);
                let after = &rest[attr + ATTR.len()..];
                let mut depth = 0usize;
                let mut item_end = None;
                for (i, ch) in after.char_indices() {
                    match ch {
                        ';' if depth == 0 => {
                            item_end = Some(i + 1);
                            break;
                        }
                        '\u{7b}' => depth += 1,
                        '\u{7d}' => {
                            depth = depth.checked_sub(1).unwrap_or_else(|| {
                                panic!("unbalanced braces after {} in {}", ATTR, rel)
                            });
                            if depth == 0 {
                                item_end = Some(i + 1);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let item_end =
                    item_end.unwrap_or_else(|| panic!("a {} item in {} never closes", ATTR, rel));
                rest = &after[item_end..];
            }
            shipping.push_str(rest);
            shipping
        }

        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_sources(&src, &mut files);
        assert!(
            files.len() > 100,
            "suspiciously small scan of {} ({} files): asserting over nothing",
            src.display(),
            files.len()
        );
        files
            .iter()
            .map(|path| {
                let text = std::fs::read_to_string(path)
                    .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
                let rel = path
                    .strip_prefix(&src)
                    .expect("scanned file outside src/")
                    .to_string_lossy()
                    .replace('\\', "/");
                let shipping = strip_test_items(&rel, &crate::util::test::without_comments(&text));
                (rel, shipping)
            })
            .collect()
    }

    /// Merge slice R2-M2b ("P4 MUST pin"): in this crate only `join_call`
    /// writes a session record, at ONE call site. The other mint paths, the
    /// Android screen leg (`create_screen_leg_token`) and remote control
    /// (`update_permissions_identity`), never do: a record written there
    /// would name a session, or a seat, that no `join_call` admitted, and a
    /// move would mint for it. The name is counted too, so an alias or a
    /// function pointer cannot hide a second writer.
    #[test]
    fn only_join_call_writes_a_session_record_in_this_crate() {
        const JOIN: &str = "routes/channels/voice_join.rs";
        const WRITER: &str = "set_voice_participant_session";

        let sources = delta_shipping_sources();
        let mentions: Vec<(&str, usize, usize)> = sources
            .iter()
            .map(|(rel, shipping)| {
                (
                    rel.as_str(),
                    shipping.matches(WRITER).count(),
                    shipping.matches(&format!("{WRITER}(")).count(),
                )
            })
            .filter(|(_, named, _)| *named > 0)
            .collect();
        assert_eq!(
            mentions,
            [(JOIN, 2, 1)],
            "only {JOIN} names the writer (its import and its one call): {mentions:?}"
        );
        assert_eq!(
            join_call_body().matches(&format!("{WRITER}(")).count(),
            1,
            "the one call is join_call's"
        );

        for (rel, mint) in [
            (
                "routes/channels/voice_screen_leg.rs",
                ".create_screen_leg_token(",
            ),
            (
                "routes/channels/remote_control.rs",
                ".update_permissions_identity(",
            ),
        ] {
            let shipping = &sources
                .iter()
                .find(|(path, _)| path == rel)
                .unwrap_or_else(|| panic!("{} left the crate", rel))
                .1;
            assert!(
                shipping.contains(mint),
                "{} no longer calls `{}`, so this pin checks nothing there",
                rel,
                mint
            );
            assert!(
                !shipping.contains(WRITER),
                "{} writes a session record",
                rel
            );
        }
    }

    /// A move in flight out of channel A must not reach a session a join
    /// into ANOTHER channel kicked (lane 6a4): the kick drops A's record, so
    /// the move's re-check refuses it, and another user's record in A stays,
    /// seat kind and all. Recast for the merge (RT-8): the old shape pinned A
    /// to a configured node, so the kick's eviction there asked an SFU no
    /// test run reaches, failed, and (AFK S-3) tore nothing of A down, which
    /// turned its "the voice state in A is gone" assertion red. A holds no
    /// node here, as a call whose room is gone: nothing is evicted, the
    /// teardown runs from A's records, and the join into X gets past the
    /// kick (`force_join_past_the_disconnect`). The seats recorded match the
    /// identities connected (merge slice SEC4-5): the user bare, the other
    /// user as a device. Control NODROP.
    #[test]
    fn a_kick_from_a_join_elsewhere_drops_the_kicked_channels_record() {
        crate::util::test::rt().block_on(a_kick_from_a_join_elsewhere_case())
    }

    async fn a_kick_from_a_join_elsewhere_case() {
        use revolt_database::voice::{
            get_voice_participant_session, get_voice_participant_session_seat,
            set_voice_participant_session, SeatKind,
        };

        let harness = TestHarness::new().await;
        let (_account, session_w, user) = harness.new_user().await;
        let (_account_o, _session_o, other) = harness.new_user().await;

        let kicked = voice_channel(&harness, &user, &[&other]).await;
        let joined = voice_channel(&harness, &user, &[]).await;
        let kicked_voice = UserVoiceChannel::from_channel(&kicked);
        let joined_voice = UserVoiceChannel::from_channel(&joined);

        // The user's desktop session "DESKTOP" owns the user's bare seat in
        // A, and the other user's session owns their device seat there.
        join_recorded(&kicked_voice, &user.id, "PA_kicked_user", &user.id).await;
        join_recorded(
            &kicked_voice,
            &other.id,
            "PA_kicked_other",
            &format!("{}:ODEV", other.id),
        )
        .await;
        set_voice_participant_session(kicked.id(), &user.id, "DESKTOP", None)
            .await
            .expect("record");
        set_voice_participant_session(kicked.id(), &other.id, "OTHER", Some("ODEV"))
            .await
            .expect("record");
        assert!(
            get_channel_node(kicked.id())
                .await
                .expect("node read")
                .is_none(),
            "A's room is gone: no node"
        );

        // Session W joins X with force_disconnect.
        force_join_past_the_disconnect(&harness, &session_w.token, &joined).await;

        let (recorded, listed, member, pointer) = voice_traces(&kicked_voice, &user.id).await;
        assert!(
            recorded.is_empty() && !listed && !member && !pointer,
            "the kick loop ran: the user's state in A is gone, left: recorded {:?}, vc {}, \
             vc_members {}, pointer {}",
            recorded,
            listed,
            member,
            pointer
        );
        assert_eq!(
            get_voice_participant_session(kicked.id(), &user.id)
                .await
                .unwrap(),
            None,
            "the kick must drop A's record, or a move out of A still reaches DESKTOP"
        );
        assert_eq!(
            get_voice_participant_session_seat(kicked.id(), &other.id)
                .await
                .unwrap(),
            Some(("OTHER".to_string(), SeatKind::Device("ODEV".to_string()))),
            "only the kicked user's record goes"
        );
        assert_eq!(
            get_voice_participant_session(joined.id(), &user.id)
                .await
                .unwrap(),
            None,
            "a join that failed at the SFU records nothing in X"
        );

        for voice in [&kicked_voice, &joined_voice] {
            delete_channel_voice_state(voice, &[user.id.clone(), other.id.clone()])
                .await
                .expect("cleanup");
        }
    }
}
