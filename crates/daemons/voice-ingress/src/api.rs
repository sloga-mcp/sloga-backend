use livekit_api::{access_token::TokenVerifier, webhooks::WebhookReceiver};
use livekit_protocol::{ParticipantInfo, TrackType};
use revolt_database::{
    events::client::EventV1,
    iso8601_timestamp::{Duration, Timestamp},
    util::reference::Reference,
    voice::{
        clear_voice_participant_identities, create_voice_state, delete_channel_voice_state,
        delete_voice_connection, delete_voice_connections, get_user_moved_to_voice,
        get_user_voice_channels, get_voice_channel_members,
        get_screen_leg_sid, get_voice_state, is_screen_leg, is_screenshare_video, is_video_source,
        mls_cap_would_refuse, record_screen_leg, record_voice_connection,
        recorded_voice_connections, remove_user_from_voice_channel, screen_leg_identity,
        screen_leg_left, set_voice_participant_identity, update_voice_state,
        update_voice_state_tracks, user_id_from_participant_identity, video_roster_over_cap,
        voice_connect_still_allowed, ConnectionLeave, RoomMetadata, UserVoiceChannel,
        VoiceClient, MAX_VIDEO_PARTICIPANTS,
    },
    Database, AMQP,
};
use revolt_models::v0::{PartialUserVoiceState, UserVoiceState};
use revolt_result::{Result, ToRevoltError};
use rocket::{post, State};
use rocket_empty::EmptyResponse;

use crate::guard::AuthHeader;

/// Aspect-ratio sanity band for SCREENSHARE video, used instead of the
/// configured `video_aspect_ratio` (which is sized for cameras).
///
/// A screenshare is whatever shape the user's monitor or window is, and the
/// camera band — `[0.3, 2.5]` in production — rejects perfectly ordinary
/// hardware: a 32:9 ultrawide is 3.56, and so is any side-by-side two-monitor
/// share (3840x1080). Five 16:9 displays in a row is 8.89. This band exists
/// only to reject the degenerate shapes the check was written for; the
/// pixel-area limit is what actually bounds cost, and it still applies.
const SCREENSHARE_ASPECT_MIN: f32 = 0.1;
const SCREENSHARE_ASPECT_MAX: f32 = 10.0;

#[post("/<node>", data = "<body>")]
pub async fn ingress(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    amqp: &State<AMQP>,
    node: &str,
    auth_header: AuthHeader<'_>,
    body: &str,
) -> Result<EmptyResponse> {
    log::debug!("received event: {body:?}");

    let config = revolt_config::config().await;

    let node_info = config
        .api
        .livekit
        .nodes
        .get(node)
        .to_internal_error()
        .inspect_err(|_| {
            log::error!("Unknown node {node}, make sure livekit has the correct node name set and matches `hosts.livekit` and `api.livekit.nodes` in the Revolt config.")
        })?;

    let webhook_receiver = WebhookReceiver::new(TokenVerifier::with_api_key(
        &node_info.key,
        &node_info.secret,
    ));

    let event = webhook_receiver
        .receive(body, &auth_header)
        .to_internal_error()?;

    let channel_id = event.room.as_ref().map(|r| &r.name);
    // Participant identities may be device-qualified ({user_id}:{device_id},
    // media E2EE) — everything downstream keys on the bare user id
    let identity = event.participant.as_ref().map(|r| &r.identity);
    let user_id = identity.map(|i| user_id_from_participant_identity(i).to_string());
    let user_id = user_id.as_ref();
    // Track events arrive with an empty room.metadata — treat as absent
    // instead of failing to parse (was causing 500s + endless retries).
    let room_metadata = match event.room.as_ref() {
        Some(room) if !room.metadata.is_empty() => {
            Some(serde_json::from_str::<RoomMetadata>(&room.metadata).to_internal_error()?)
        }
        _ => None,
    };

    // A SCREEN LEG (identity `{user}:{device}:screen`, android-screen-share
    // plan §2.3) is a HELPER of the user it belongs to, never a member of the
    // call: no voice state, no identity mapping (that map is per USER, and
    // the remote-control, annotation, caption and screen-leg routes resolve
    // the user's connection through it — a leg writing there would point
    // them at the phone), no connection record, no roster slot, no
    // join/leave events and no ring. Everything it
    // touches hangs off its OWNER's voice state, which is why every branch
    // below checks that state first.
    //
    // Deliberately NOT gated on `features.screen_leg`: the route ships dark
    // while the viewer-side rollout lands, but a hand-minted probe leg still
    // has to be handled correctly (plan §0.8).
    if identity.is_some_and(|identity| is_screen_leg(identity)) {
        let identity = identity.to_internal_error()?;
        let channel_id = channel_id.to_internal_error()?;
        let user_id = user_id.to_internal_error()?;

        match event.event.as_str() {
            "participant_joined" => {
                let channel = UserVoiceChannel {
                    id: channel_id.clone(),
                    server_id: room_metadata.to_internal_error()?.server,
                };

                // Orphan sanity check. The route refuses to mint a leg for a
                // user who is not in the call, so an owner with no voice state
                // here means a stale or hand-minted leg — eject it rather than
                // leave a participant nobody can attribute (viewer-side it
                // reads as a non-enrolled stranger and downgrades the call).
                // Nothing else is touched: the owner may be in another channel.
                if get_voice_state(&channel, user_id).await?.is_none() {
                    log::warn!("Removing orphan screen leg {identity} from channel {channel_id}: owner has no voice state here.");
                    let _ = voice_client
                        .remove_identity(node, identity, channel_id)
                        .await;
                    return Ok(EmptyResponse);
                }

                let sid = &event.participant.as_ref().to_internal_error()?.sid;

                record_screen_leg(channel_id, user_id, sid).await?;
            }
            "participant_left" => {
                let channel = UserVoiceChannel {
                    id: channel_id.clone(),
                    server_id: room_metadata.to_internal_error()?.server,
                };

                let sid = &event.participant.as_ref().to_internal_error()?.sid;

                // This is what actually clears the "X is sharing" badge:
                // LiveKit does not reliably emit `track_unpublished` for a
                // participant that simply vanished (process death, swipe-away,
                // SFU timeout). Both guards — owner voice state FIRST, then
                // the sid — live in `screen_leg_left`; `None` means the event
                // must be ignored entirely. No `delete_voice_state` (the owner
                // is still in the call) and no remote-control release (their
                // primary is still connected).
                if let Some(partial) = screen_leg_left(&channel, user_id, sid).await? {
                    EventV1::UserVoiceStateUpdate {
                        id: user_id.clone(),
                        channel_id: channel_id.clone(),
                        data: partial,
                    }
                    .p(channel_id.clone())
                    .await;
                }
            }
            "track_published" | "track_unpublished" | "track_unmuted" | "track_muted" => {
                let track = event.track.as_ref().to_internal_error()?;

                // Track events carry no room metadata; recover the channel
                // from the OWNER's voice state. Unrecoverable means there is
                // nothing to update — answer 200, because a 500 here buys a
                // LiveKit retry storm and no useful state.
                let channel = match room_metadata {
                    Some(metadata) => UserVoiceChannel {
                        id: channel_id.clone(),
                        server_id: metadata.server,
                    },
                    None => match get_user_voice_channels(user_id)
                        .await?
                        .into_iter()
                        .find(|channel| &channel.id == channel_id)
                    {
                        Some(channel) => channel,
                        None => return Ok(EmptyResponse),
                    },
                };

                // Voice-state guard, as on every leg path: with the owner gone
                // `update_voice_state_tracks` would SET `screensharing:` /
                // `screen_video:` for a user who has left, and nothing would
                // ever clean those keys up (plan §0-R.13).
                if get_voice_state(&channel, user_id).await?.is_none() {
                    return Ok(EmptyResponse);
                }

                // Sid guard, the same one `screen_leg_left` applies and in the
                // same order (voice state first, then the sid). A user's leg
                // marker is per USER, so a NEWER leg overwrites it while an
                // older one may still be draining: without this, the old leg's
                // `track_unpublished` on its way out runs
                // `update_voice_state_tracks(.., false, ..)` and blanks
                // `screensharing`/`screen_video` for a share that is still
                // live on the new leg — announcing it to the channel, and
                // tripping the remote-control release hook, which keys on
                // `screen_video == Some(false)`.
                //
                // Found by the §10.1 live leg (plan §13.4 F1), which isolated
                // it with a matched pair: a stale leg that HAD published drove
                // the flags to 0/0 mid-share, while one that never published —
                // and so emitted no track event — left them at 1/1 because
                // `screen_leg_left` already guards this way.
                // A marker that is ABSENT deliberately allows the event
                // through. Webhook delivery is not ordered — a leg's first
                // `track_published` can beat its own `participant_joined`, and
                // `record_screen_leg` runs in the latter — so refusing on
                // `None` would mean a share whose join webhook was merely slow
                // never lights the badge at all. Only a marker naming a
                // DIFFERENT participant proves this event came from a leg that
                // has already been superseded.
                let sid = &event.participant.as_ref().to_internal_error()?.sid;

                if get_screen_leg_sid(channel_id, user_id)
                    .await?
                    .is_some_and(|marker| marker != *sid)
                {
                    return Ok(EmptyResponse);
                }

                let user = Reference::from_unchecked(user_id).as_user(db).await?;

                let user_limits = user.limits().await;

                // The SAME limit rules as a primary publisher — but every
                // remedy addresses the LEG identity, so enforcement can never
                // eject or mute the MEMBER over what their phone published.
                if event.event == "track_published" {
                    let mut disconnect = false;
                    let mut mute_offending = false;

                    if track.r#type == TrackType::Data as i32 {
                        log::warn!("Screen leg {identity} published data — removing it from channel {channel_id}.");
                        disconnect = true;
                    };

                    if track.r#type != TrackType::Audio as i32
                        && track.source == 0
                    /* TrackSource::Unknown */
                    {
                        log::warn!("Screen leg {identity} published a non-audio track on the whisper source — removing it from channel {channel_id}.");
                        disconnect = true;
                    };

                    if track.r#type == TrackType::Video as i32 {
                        let area = track.width as u64 * track.height as u64;
                        let limit_area = user_limits.video_resolution[0] as u64
                            * user_limits.video_resolution[1] as u64;

                        if user_limits.video_resolution[0] != 0
                            && user_limits.video_resolution[1] != 0
                            && area > limit_area
                        {
                            log::warn!(
                                "Screen leg {identity} published video over the resolution limit ({}x{}) — removing it from channel {channel_id}.",
                                track.width,
                                track.height
                            );
                            disconnect = true;
                        };

                        if track.width > 0 && track.height > 0 {
                            let aspect = track.width as f32 / track.height as f32;

                            // A phone panel is 20:9 in landscape and 9:20 in
                            // portrait (0.45), both comfortably inside the
                            // screenshare band — which is why the leg's own
                            // quality table caps the long side rather than
                            // relying on this.
                            if is_screenshare_video(track.source) {
                                if !(SCREENSHARE_ASPECT_MIN..=SCREENSHARE_ASPECT_MAX)
                                    .contains(&aspect)
                                {
                                    log::warn!(
                                        "Muting screen leg {identity} in channel {channel_id}: aspect {aspect} outside {SCREENSHARE_ASPECT_MIN}..={SCREENSHARE_ASPECT_MAX} ({}x{}).",
                                        track.width,
                                        track.height
                                    );
                                    mute_offending = true;
                                };
                            } else if user_limits.video_aspect_ratio[0]
                                != user_limits.video_aspect_ratio[1]
                                && !(user_limits.video_aspect_ratio[0]
                                    ..=user_limits.video_aspect_ratio[1])
                                    .contains(&aspect)
                            {
                                log::warn!("Screen leg {identity} published video with out of bounds aspect ratio ({aspect}) — removing it from channel {channel_id}.");
                                disconnect = true;
                            };
                        };
                    };

                    if disconnect {
                        // Eject the LEG, never the member. No
                        // `delete_voice_state` — the user never left the call
                        // — and no remote-control release, since their primary
                        // is still connected and may still be sharing from it.
                        let _ = voice_client
                            .remove_identity(node, identity, channel_id)
                            .await;

                        return Ok(EmptyResponse);
                    };

                    if mute_offending {
                        let _ = voice_client
                            .mute_track_identity(node, identity, channel_id, &track.sid)
                            .await;

                        return Ok(EmptyResponse);
                    };

                    // D12 video cap. A leg never reaches `vc_members`, so it
                    // consumes no roster slot of its own — the count it is
                    // measured against is the same one the route checked.
                    if is_video_source(track.source) {
                        let members = get_voice_channel_members(&channel)
                            .await?
                            .map(|m| m.len())
                            .unwrap_or(0);
                        if members > MAX_VIDEO_PARTICIPANTS {
                            log::debug!("Muting over-cap screen leg track {} for {identity} in channel {channel_id} (>{MAX_VIDEO_PARTICIPANTS} present).", track.sid);
                            let _ = voice_client
                                .mute_track_identity(node, identity, channel_id, &track.sid)
                                .await;
                            return Ok(EmptyResponse);
                        };
                    };
                };

                // The leg's tracks ARE the user's share: this sets
                // `screen_video` / `screensharing` on the OWNER's voice state,
                // which is the "X is sharing" signal every client renders. One
                // slot per user, exactly as for a desktop share.
                let partial = update_voice_state_tracks(
                    &channel,
                    user_id,
                    event.event == "track_published" || event.event == "track_unmuted",
                    track.source,
                )
                .await?;

                // Unchanged from the primary path: control over a screen the
                // controller can no longer see is worse than no control.
                if partial.screen_video == Some(false) {
                    revolt_database::voice::remote_control::release_remote_control_for_user(
                        db,
                        voice_client,
                        &channel,
                        user_id,
                        "screenshare_ended",
                        false,
                    )
                    .await;
                }

                EventV1::UserVoiceStateUpdate {
                    id: user_id.clone(),
                    channel_id: channel_id.clone(),
                    data: partial,
                }
                .p(channel_id.clone())
                .await;
            }
            _ => {}
        };

        return Ok(EmptyResponse);
    };

    match event.event.as_str() {
        // User joined a channel
        "participant_joined" => {
            let channel_id = channel_id.to_internal_error()?;
            let user_id = user_id.to_internal_error()?;
            let server_id = room_metadata.to_internal_error()?.server;
            let channel = UserVoiceChannel {
                id: channel_id.clone(),
                server_id: server_id.clone(),
            };

            let identity = identity.to_internal_error()?;
            let sid = &event.participant.as_ref().to_internal_error()?.sid;

            let joined_at = event_joined_at(event.created_at);

            // Connect re-check (AFK S-3 D-3), FIRST, before anything is
            // written. A join token lives for seconds, so a ban, kick or
            // Connect denial that lands between the mint and the SFU join is
            // otherwise never seen: the connection arrives carrying a grant
            // minted before the change. A refused connection is evicted by
            // its exact identity and leaves no trace: no mapping, no record,
            // no voice state, no event.
            //
            // A failed permission read fails CLOSED (decision DS-2): the
            // connection is evicted exactly as a refused one, and the failure
            // is reported. If the EVICTION fails, the `?` answers 500 so
            // LiveKit retries this webhook (P2-7): answering 200 would leave
            // a live connection nothing has recorded.
            let allowed = match voice_connect_still_allowed(db, channel_id, user_id).await {
                Ok(allowed) => allowed,
                Err(error) => {
                    log::error!("Connect re-check for {identity} in {channel_id} failed ({error}); failing closed and evicting the connection.");
                    // ERROR + Sentry with the cause; the answer is decided
                    // here, so the converted error is discarded.
                    let _ = Err::<(), _>(error).to_internal_error();
                    false
                }
            };
            if !allowed {
                voice_client
                    .remove_connection_if_present(node, identity, channel_id)
                    .await?;
                // Drain any pending move marker for THIS channel, as the cap
                // backstop below does, so a later join within its TTL isn't
                // mis-announced as a move.
                let _ = get_user_moved_to_voice(channel_id, user_id).await;
                log::info!("Evicted {identity} from {channel_id}: not confirmed allowed to connect.");
                return Ok(EmptyResponse);
            }

            // Record THIS connection by its sid (S-3 D-1). `true` means the
            // user had no voice state in this channel: a real join, which
            // resets the flags and is announced. `false` means the user
            // already holds voice state here, which the record tells apart
            // below (AFK S-3 WB-1).
            let first_connection = record_voice_connection(&channel, user_id, sid, identity).await?;

            // Record the full (possibly device-qualified) identity so
            // server-side participant operations can address the SFU
            set_voice_participant_identity(channel_id, user_id, identity).await?;

            // A `false` answer is either a second connection or LiveKit
            // retrying THIS join (WB-1): any 500 after the state is written
            // below (a cap read, the backstop's eviction or teardown, the
            // move marker) is retried, and the retry finds the state the
            // first attempt wrote. Returning on every `false` left a live
            // user no roster shows, with no ring and no cap backstop.
            //
            // `retried_join` decides (WBR-1), from the state and the record
            // read after this sid was recorded:
            // - A state whose `joined_at` is THIS event's: a retry. Only
            //   `create_voice_state` writes `joined_at`, from the
            //   `created_at` of the event that created the state, and a
            //   retry resends the same event. It holds whatever else was
            //   recorded meanwhile: a sibling that joined between the failed
            //   attempt and its retry, the over-cap sibling a failed
            //   backstop removal left behind, or a stale sid.
            // - A state with any other `joined_at`: another connection
            //   created it, and this is a second connection. A state from
            //   before the record existed, or a ghost, is one of these too.
            // - No state (a teardown between the record and this read, or a
            //   state missing a key `get_voice_state` needs; the roster
            //   membership the record checks is written LAST, RA2-5): a
            //   retry only when this sid is the user's ONLY recorded
            //   connection (`retried_first_connection`).
            //
            // A retry runs the backstop and is announced, on the state the
            // first attempt wrote. That state is read, not re-created: track
            // events may have set flags since, and the reset would wipe them
            // (F-15). Only a missing state is created. A second connection
            // refreshes only the mapping hint above: no flag reset, no
            // second Join/Move or ring, and no backstop, since both caps are
            // membership-based and a second connection of a member adds no
            // member.
            //
            // `created_at` is in whole seconds, so a sibling whose own join
            // event was created in the same second as the first connection's
            // reads as a retry: a duplicate Join (or Move) and ring on a
            // state every roster already shows, and a second run of the cap
            // backstop, which removes the user only if the roster is over a
            // cap at that moment (a residual, as narrow as that window).
            // Correctness also rests on LiveKit resending an identical body
            // on a retry (release blocker WB-5).
            let existing_state = if first_connection {
                None
            } else {
                let recorded = recorded_voice_connections(&channel, user_id).await?;
                let state = get_voice_state(&channel, user_id).await?;
                if !retried_join(state.as_ref(), joined_at, &recorded, sid) {
                    return Ok(EmptyResponse);
                }
                state
            };

            let voice_state = match existing_state {
                Some(voice_state) => voice_state,
                None => create_voice_state(&channel, user_id, joined_at).await?,
            };

            // TOCTOU backstop (6.6 review finding 1): the join-leg caps in
            // join_call / member_edit are check-then-act — a burst of joins at
            // the ceiling can each read below-cap and all mint a token, so
            // overflow the front door meant to refuse still reaches the SFU.
            // Now that this join is RECORDED, re-check and evict anyone the caps
            // would have refused, BEFORE announcing them. T-20 (a non-enrolled
            // MLS ghost, the CR-HIGH-2 downgrade-DoS) is membership-based so the
            // join-leg predicate applies directly; D12 uses a strict `>` on the
            // post-join roster so the legitimate cap-th member is kept and only
            // genuine excess is dropped. Inert below the ceiling — normal calls
            // never hit this.
            if video_roster_over_cap(&channel).await?
                || mls_cap_would_refuse(db, channel_id, user_id).await?
            {
                log::debug!("Evicting over-cap participant {user_id} from {channel_id} (join-leg admission-race backstop).");
                // THIS connection, by its exact identity and sid (S-3 D-2).
                // A failed eviction answers 500 with NO teardown: tearing the
                // record down would leave a live connection nothing tracks.
                // The retried webhook finds this sid the user's only recorded
                // connection, so it re-runs this backstop (WB-1).
                voice_client
                    .remove_connection_if_present(node, identity, channel_id)
                    .await?;
                // Both caps are per USER (WB-3). A sibling connection that
                // recorded meanwhile keeps the state (`Survivor`), and would
                // stay in the call over the cap, never announced. So a
                // `Survivor` removes the user from this channel as moderation
                // does, by the ordering rule: the record read first, then the
                // listing, then the set delete, never the whole-user
                // `delete_voice_state`. Nothing is announced. A failure
                // answers 500; its retry records this sid again next to the
                // sibling's, but the state still carries this event's
                // `joined_at`, so it reads as a retry and re-runs this
                // backstop (WBR-1).
                match delete_voice_connection(&channel, user_id, sid).await? {
                    ConnectionLeave::Last => {}
                    ConnectionLeave::Survivor => {
                        remove_user_from_voice_channel(db, voice_client, &channel, user_id).await?;
                    }
                }
                // Drain any pending move marker for THIS channel so a rejoin
                // within its TTL isn't mis-announced as a VoiceChannelMove from
                // the old channel.
                let _ = get_user_moved_to_voice(channel_id, user_id).await;
                return Ok(EmptyResponse);
            }

            // A join the voice move marked is announced as a move from the
            // source. The source's Leave has already gone out on its own
            // (see `participant_left`), and a Move after it is harmless.
            if let Some(source_channel) = get_user_moved_to_voice(channel_id, user_id).await? {
                EventV1::VoiceChannelMove {
                    user: user_id.to_string(),
                    from: source_channel.id,
                    to: channel_id.to_string(),
                    state: voice_state,
                }
                .p(channel_id.to_string())
                .await;
            } else {
                EventV1::VoiceChannelJoin {
                    id: channel_id.to_string(),
                    state: voice_state,
                }
                .p(channel_id.to_string())
                .await;
            };

            // Ring other recipients via push notification when the first
            // participant starts the call. Uses our own voice state (not
            // LiveKit's `num_participants`, which is unreliable — see #457).
            //
            // Nothing after the announce above may answer 500 (WBR-2): the
            // retry would announce the join a second time (a Move as a Join,
            // since this attempt drained the marker), ring again, and re-run
            // the cap backstop after the join went out. So a failed roster
            // read is reported (ERROR + Sentry) and the ring is skipped: with
            // the roster unknown, ringing could repeat on every join, and a
            // missed ring costs less.
            match get_voice_channel_members(&channel).await {
                Ok(members) => {
                    if members.map_or(0, |m| m.len()) <= 1 {
                        let now = joined_at.to_string();
                        if let Err(e) = amqp
                            .dm_call_updated(user_id, channel_id, Some(&now), false, None)
                            .await
                        {
                            log::error!("failed to publish call ring push: {e:?}");
                        }
                    }
                }
                Err(error) => {
                    log::error!("Roster read after announcing {identity} in {channel_id} failed ({error}); the call ring is skipped.");
                    // ERROR + Sentry with the cause; the join is already
                    // announced, so the converted error is discarded.
                    let _ = Err::<(), _>(error).to_internal_error();
                }
            }

            // TODO: fix `num_participants` being incorrect sometimes see (#457)
            // First user who joined - send call started system message.
            // if event.room.as_ref().unwrap().num_participants == 1 {
            //     let user = Reference::from_unchecked(user_id).as_user(db).await?;

            //     let message_id =
            //         Ulid::from_datetime(DateTime::from_timestamp_secs(event.created_at).unwrap())
            //             .to_string();

            //     let mut call_started_message = SystemMessage::CallStarted {
            //         by: user_id.to_string(),
            //         finished_at: None,
            //     }
            //     .into_message(channel.id().to_string());

            //     call_started_message.id = message_id;

            //     set_channel_call_started_system_message(channel.id(), &call_started_message.id)
            //         .await?;

            //     call_started_message
            //         .send(
            //             db,
            //             Some(amqp),
            //             v0::MessageAuthor::System {
            //                 username: &user.username,
            //                 avatar: user.avatar.as_ref().map(|file| file.id.as_ref()),
            //             },
            //             None,
            //             None,
            //             &channel,
            //             false,
            //         )
            //         .await?;

            //     let recipients = get_call_notification_recipients(&channel_id, &user_id).await?;
            //     let now = joined_at.format_short().to_string();

            //     if let Err(e) = amqp
            //         .dm_call_updated(&user.id, channel.id(), Some(&now), false, recipients)
            //         .await
            //     {
            //         revolt_config::capture_error(&e);
            //     }
            // }
        }
        // User left a channel
        "participant_left" => {
            let channel_id = channel_id.to_internal_error()?;
            let user_id = user_id.to_internal_error()?;
            let server_id = room_metadata.to_internal_error()?.server;
            let channel = UserVoiceChannel {
                id: channel_id.clone(),
                server_id: server_id.clone(),
            };
            let identity = identity.to_internal_error()?;
            let sid = &event.participant.as_ref().to_internal_error()?.sid;

            // Remote-control release hook (plan §1), scoped to THIS
            // connection (S-3 D-7): a sharer grant ends, with a revoke, on
            // any connection leave of the sharer; a controller grant ends,
            // without one, only if `identity` is the connection that held it.
            // It runs BEFORE the teardown so it still runs when the
            // teardown's `?` fails.
            revolt_database::voice::remote_control::release_remote_control_for_connection(
                db,
                voice_client,
                &channel,
                user_id,
                identity,
                "participant_left",
            )
            .await;

            // A phone leg must not outlive the WebView that owns it. This
            // addresses the SFU with a target derived from the EVENT identity,
            // so it still works when the identity MAPPING is already gone —
            // the documented gap in the derive-from-mapping path (plan §2.2),
            // which makes this hook load-bearing rather than redundant.
            //
            // 🔴 There is no grace here: a WebView full reconnect (wifi →
            // cellular) fires this event, so it also ends the share. The phone
            // reports `stopped{disconnected}` and offers "share again" (plan
            // §7.5); an ingress leave grace is a follow-up, not v1.
            //
            // 🔴 Only the LEG, never the event identity itself: a bare
            // `{user}` reconnect reuses the identity, so evicting it on a
            // late leave would kick the NEW live connection.
            //
            // `remove_identity_if_present` answers "not found" as `Ok(false)`
            // with no log, and a real failure at WARN only. Every ordinary
            // leave reaches here and almost nobody has a leg, so an ERROR per
            // leave would bury real errors (plan §13.4 F2). The result is
            // discarded: the leg is best-effort.
            let _ = voice_client
                .remove_identity_if_present(node, &screen_leg_identity(identity), channel_id)
                .await;

            // THIS connection leaves the record (S-3 D-1). The mapping is not
            // HDELed here: the script does that on `Last`, and on `Survivor`
            // it has re-pointed the mapping at the surviving connection, which
            // an HDEL here would undo (P2-4).
            let mut leave = delete_voice_connection(&channel, user_id, sid).await?;

            // A `Survivor` answer can rest on a stale sid (a connection whose
            // own leave never arrived), so it is confirmed against the SFU
            // (P2-1, amended by WA-R/RA2-1).
            //
            // 🔴 ORDERING: the record is read BEFORE the SFU listing, never
            // after. Read after, a sibling that records between the listing
            // and the read looks stale and is deleted while live (WA-1).
            // Read before, such a sibling is in neither set, is never named,
            // and the set delete's survivor scan keeps its state. And never a
            // whole-user teardown here: that is exactly the WA-1 erasure.
            //
            // A failed read or listing answers 500 so LiveKit retries the
            // webhook (RA2-2). The retry is idempotent: this sid is no longer
            // recorded, so it answers `Survivor` again and re-confirms.
            // Evidence for the retry: the deployed SFU is the stoatchat fork
            // `ghcr.io/stoatchat/livekit-server:v1.9.13` (compose.yml), built
            // on upstream livekit v1.9.0, whose go.mod pins livekit/protocol
            // v1.39.1-0.20250604205715-2227c44329ee and go-retryablehttp
            // v0.7.7. At that commit `webhook/url_notifier.go` sends through
            // `retryablehttp.NewClient()` and never inspects the status, so
            // the library's DefaultRetryPolicy retries connection errors and
            // every 5xx except 501, RetryMax 4, backoff 1 s to 30 s.
            // livekit.example.yml sets no webhook retry option (only
            // `api_key` and `urls`). The FORK's own source was not checked.
            // Once the retries run out (or the notifier's DropWhenFull queue
            // drops the event) the stale connection stays a ghost until
            // `room_finished` or the reconcile sweep: a recorded residual.
            if leave == ConnectionLeave::Survivor {
                let recorded = recorded_voice_connections(&channel, user_id).await?;
                let listed = voice_client
                    .list_participants_reported(node, channel_id)
                    .await?
                    // No such room: nothing is connected to it.
                    .unwrap_or_default();

                let stale = stale_connections(&recorded, &listed);
                if !stale.is_empty() {
                    log::info!("Dropping {} stale connection record(s) of {user_id} in {channel_id} the SFU no longer lists.", stale.len());
                    leave = delete_voice_connections(&channel, user_id, &stale).await?;

                    // The confirmation turned `Survivor` into `Last` (WB-10):
                    // the stale connections were the user's only others, so
                    // nothing of theirs is left in the call. The release at
                    // the top of this arm ends a controller grant only when
                    // THIS connection held it; one held by a stale
                    // connection names that connection's identity, and would
                    // outlive the user. So the whole-user release runs here.
                    // It revokes (`participant_already_gone: false`): the
                    // listing shows the recorded connections gone, not the
                    // grant's controller identity (a bare `{user}` reconnect
                    // reuses it), and revoking a participant who is gone
                    // answers Ok (D-7). A failed set delete answers 500 before
                    // this; the retry answers `Survivor` again and gets here.
                    if leave == ConnectionLeave::Last {
                        revolt_database::voice::remote_control::release_remote_control_for_user(
                            db,
                            voice_client,
                            &channel,
                            user_id,
                            "participant_left",
                            false,
                        )
                        .await;
                    }
                }

                // Still a survivor: the departed connection's camera/share/mic
                // flags must not stick, and LiveKit does not reliably send
                // `track_unpublished` for a participant that vanished. So the
                // flags are recomputed from what the survivors publish in the
                // SAME listing (P2-5).
                if leave == ConnectionLeave::Survivor {
                    let partial = survivor_track_flags(&listed, user_id, sid);
                    update_voice_state(&channel, user_id, &partial).await?;

                    EventV1::UserVoiceStateUpdate {
                        id: user_id.clone(),
                        channel_id: channel_id.clone(),
                        data: partial,
                    }
                    .p(channel_id.clone())
                    .await;
                }
            }

            if leave == ConnectionLeave::Last {
                // Everyone left — dismiss the ring notification on recipients
                let members = get_voice_channel_members(&channel).await?;
                if members.is_none_or(|m| m.is_empty()) {
                    if let Err(e) = amqp
                        .dm_call_updated(user_id, channel_id, None, true, None)
                        .await
                    {
                        log::error!("failed to publish call end push: {e:?}");
                    }
                }

                // Published on EVERY last leave, a voice move's included
                // (Wave 5b-2 M4-b); only a surviving connection of the same
                // user withholds it (S-3 D-1), since the user is still in the
                // call. A move used to suppress this and leave the
                // destination's Move event to take the user off the source
                // roster, so when no destination join followed (a dropped
                // event, a refused connect, a session that never redeemed its
                // token) every other client kept a ghost in the source
                // channel. Redis was already right; only the event was
                // missing. The cost is a brief Leave-then-Move on the other
                // clients' rosters (stoat.js applies a Leave per channel, and
                // a Move after it is idempotent: Wave 5b-2 Stage 2).
                EventV1::VoiceChannelLeave {
                    id: channel_id.clone(),
                    user: user_id.clone(),
                }
                .p(channel_id.clone())
                .await;
            }

            // See above for why this is commented out

            // // Update CallStarted system message if everyone has left with the end time
            // let members = get_voice_channel_members(channel_id).await?;

            // if members.is_none_or(|m| m.is_empty()) {
            //     // The channel is empty so send out an "end" message for ringing
            //     if let Err(e) = amqp
            //         .dm_call_updated(user_id, channel_id, None, true, None)
            //         .await
            //     {
            //         revolt_config::capture_internal_error!(&e);
            //     }

            //     if let Some(system_message_id) =
            //         take_channel_call_started_system_message(channel_id).await?
            //     {
            //         // Could have been deleted
            //         if let Ok(mut message) = Reference::from_unchecked(&system_message_id)
            //             .as_message(db)
            //             .await
            //         {
            //             if let Some(SystemMessage::CallStarted { finished_at, .. }) =
            //                 &mut message.system
            //             {
            //                 *finished_at = Some(Timestamp::now_utc());

            //                 message
            //                     .update(
            //                         db,
            //                         PartialMessage {
            //                             system: message.system.clone(),
            //                             ..Default::default()
            //                         },
            //                         Vec::new(),
            //                     )
            //                     .await?;
            //             } else {
            //                 log::error!("Broken State: Call started message ID ({}) does not contain a CallStarted system message.", &message.id)
            //             }
            //         };
            //     };
            // }
        }
        // Audio/video track was started/stopped/unmuted/muted
        "track_published" | "track_unpublished" | "track_unmuted" | "track_muted" => {
            let channel_id = channel_id.to_internal_error()?;
            let user_id = user_id.to_internal_error()?;
            // Every remedy below addresses the EVENT connection, by its exact
            // identity and sid (S-3 D-2/SR-2), never another connection of
            // the same user and never through the identity mapping.
            let identity = identity.to_internal_error()?;
            let track = event.track.as_ref().to_internal_error()?;
            // Track events carry no room metadata; recover the channel from
            // the user's stored voice state instead.
            let channel = match room_metadata {
                Some(metadata) => UserVoiceChannel {
                    id: channel_id.clone(),
                    server_id: metadata.server,
                },
                None => get_user_voice_channels(user_id)
                    .await?
                    .into_iter()
                    .find(|c| &c.id == channel_id)
                    .to_internal_error()?,
            };

            let user = Reference::from_unchecked(user_id).as_user(db).await?;

            let user_limits = user.limits().await;

            // forbid any size which goes over the limit and also limit the aspect ratio to stop people from making too tall or too wide and bypassing the limit.
            // TODO: figure out how to track audio stream quality

            if event.event == "track_published" {
                let mut disconnect = false;
                let mut mute_offending = false;

                if track.r#type == TrackType::Data as i32 {
                    log::warn!(
                        "User {user_id} published data — removing from channel {channel_id}."
                    );
                    disconnect = true;
                };

                // The `unknown` (0) source is granted to speakers ONLY to carry
                // the whisper AUDIO track (a second audio track fenced to one
                // recipient by subscription permissions). A non-audio track
                // declaring source `unknown` is a bypass attempt: the video-cap
                // and per-source permission gates below key on the declared
                // source (`is_video_source` excludes 0), so an `unknown`-source
                // VIDEO track would otherwise dodge both the roster cap and the
                // Video-permission requirement, and it is invisible in voice
                // state (source 0 → default partial). No stock client ever does
                // this, so treat it like a data publish and eject.
                if track.source == 0 /* TrackSource::Unknown */
                    && track.r#type != TrackType::Audio as i32
                {
                    log::warn!(
                        "User {user_id} published a non-audio track on the whisper source — removing from channel {channel_id}."
                    );
                    disconnect = true;
                };

                if track.r#type == TrackType::Video as i32 {
                    // Widened before multiplying: both sides are u32, and a
                    // client-declared 65536x65536 wraps to exactly 0 in
                    // release, clearing this check and the aspect band below
                    // (its ratio is a perfectly ordinary 1.0).
                    let area = track.width as u64 * track.height as u64;
                    let limit_area = user_limits.video_resolution[0] as u64
                        * user_limits.video_resolution[1] as u64;

                    if user_limits.video_resolution[0] != 0
                        && user_limits.video_resolution[1] != 0
                        && area > limit_area
                    {
                        log::warn!(
                            "User {user_id} published video over the resolution limit ({}x{}) — removing from channel {channel_id}.",
                            track.width,
                            track.height
                        );
                        disconnect = true;
                    };

                    // A zero on either axis makes `aspect` NaN, and NaN lies
                    // outside every RangeInclusive, so a track that arrives
                    // without dimensions would read as a violation and eject
                    // its publisher. Missing dimensions are not evidence of a
                    // bad shape — skip the band rather than guess.
                    if track.width > 0 && track.height > 0 {
                        let aspect = track.width as f32 / track.height as f32;

                        // A screenshare's aspect ratio is whatever the user's
                        // DISPLAY is, so holding it to the camera band ejects
                        // people for owning an ultrawide or spanning two monitors
                        // — both 3.56 against a 2.5 ceiling. That is not abuse,
                        // and it removed a real user from two calls ~60ms after
                        // publish on 2026-08-08. Screenshares get the wide sanity
                        // band instead, and a violation MUTES the track rather
                        // than removing the member from the call: the same
                        // remedy, for the same reason, as the video cap below.
                        if is_screenshare_video(track.source) {
                            if !(SCREENSHARE_ASPECT_MIN..=SCREENSHARE_ASPECT_MAX).contains(&aspect) {
                                log::warn!(
                                    "Muting screenshare from user {user_id} in channel {channel_id}: aspect {aspect} outside {SCREENSHARE_ASPECT_MIN}..={SCREENSHARE_ASPECT_MAX} ({}x{}).",
                                    track.width,
                                    track.height
                                );
                                mute_offending = true;
                            };
                        } else if user_limits.video_aspect_ratio[0]
                            != user_limits.video_aspect_ratio[1]
                            && !(user_limits.video_aspect_ratio[0]
                                ..=user_limits.video_aspect_ratio[1])
                                .contains(&aspect)
                        {
                            log::warn!(
                                "User {user_id} published camera video with out of bounds aspect ratio ({aspect}) — removing from channel {channel_id}."
                            );
                            disconnect = true;
                        };
                    };
                };

                if disconnect {
                    log::debug!("Removing user {user_id} from channel {channel_id} {event:?} due to forbidden track.");

                    // This removal is ingress-initiated and may fail (its
                    // error answers 500 just below), so the capability is
                    // actively revoked rather than assumed moot.
                    revolt_database::voice::remote_control::release_remote_control_for_user(
                        db,
                        voice_client,
                        &channel,
                        user_id,
                        "participant_left",
                        false,
                    )
                    .await;

                    // THIS connection only. A failed eviction answers 500
                    // with NO teardown, so LiveKit retries the event and the
                    // still-live connection keeps its record and its state.
                    let sid = &event.participant.as_ref().to_internal_error()?.sid;
                    voice_client
                        .remove_connection_if_present(node, identity, channel_id)
                        .await?;
                    delete_voice_connection(&channel, user_id, sid).await?;

                    return Ok(EmptyResponse);
                };

                // Out-of-band screenshare: refuse the TRACK, keep the MEMBER.
                // Muting enforces the limit just as well (the track is never
                // forwarded) without the disproportionate remedy of ejecting
                // someone mid-call over the shape of their monitor.
                if mute_offending {
                    let _ = voice_client
                        .mute_track_identity(node, identity, channel_id, &track.sid)
                        .await;

                    return Ok(EmptyResponse);
                };

                // D12 / A3(b) video-cap ENABLE leg (plan §0.2 ">30 present ⇒
                // video enable refused"): once the call exceeds
                // MAX_VIDEO_PARTICIPANTS members, a new camera/screenshare-video
                // publish is refused by server-side MUTE — the member stays
                // connected audio-only (matching the client's "video is full,
                // you're still connected" toast), NOT disconnected. Product gate
                // over all calls. Audio-only screenshare (source 4) is exempt.
                if is_video_source(track.source) {
                    let members = get_voice_channel_members(&channel)
                        .await?
                        .map(|m| m.len())
                        .unwrap_or(0);
                    if members > MAX_VIDEO_PARTICIPANTS {
                        log::debug!("Muting over-cap video track {} for user {user_id} in channel {channel_id} (>{MAX_VIDEO_PARTICIPANTS} present).", track.sid);
                        let _ = voice_client
                            .mute_track_identity(node, identity, channel_id, &track.sid)
                            .await;
                        return Ok(EmptyResponse);
                    };
                };
            };

            let partial = update_voice_state_tracks(
                &channel,
                user_id,
                event.event == "track_published" || event.event == "track_unmuted", // to avoid duplicating this entire case twice
                track.source,
            )
            .await?;

            // Remote control: the sharer's screen VIDEO track just ended
            // (source 3 only — a screen-AUDIO event never touches this
            // flag). Control over a screen the controller can no longer
            // see is worse than no control, so end the grant here rather
            // than waiting for the sharer's heartbeat to notice. This is
            // the server-authoritative signal; the heartbeat re-check is
            // the backstop for a sharer who simply stops heartbeating.
            if partial.screen_video == Some(false) {
                revolt_database::voice::remote_control::release_remote_control_for_user(
                    db,
                    voice_client,
                    &channel,
                    user_id,
                    "screenshare_ended",
                    false,
                )
                .await;
            }

            EventV1::UserVoiceStateUpdate {
                id: user_id.clone(),
                channel_id: channel_id.clone(),
                data: partial,
            }
            .p(channel_id.clone())
            .await;
        }
        "room_finished" => {
            let channel_id = channel_id.to_internal_error()?;
            let server_id = room_metadata.to_internal_error()?.server;
            let channel = UserVoiceChannel {
                id: channel_id.clone(),
                server_id: server_id.clone(),
            };

            // Remote-control release hook: the room is gone, so no SFU
            // capability survives — end every grant in the channel (records
            // + events). This is also the backstop against grants leaked by
            // missed participant_left webhooks.
            revolt_database::voice::remote_control::release_remote_control_for_channel(
                db,
                voice_client,
                channel_id,
                "call_ended",
                // The SFU has told us the room is finished: every
                // capability in it is already gone, so records and events
                // only. This is the only caller that may skip the revoke.
                false,
            )
            .await;

            delete_channel_voice_state(&channel, &[]).await?;
            clear_voice_participant_identities(channel_id).await?;

            // Media E2EE: the call ended — close the channel's open MLS
            // group so members wipe state and the crond sweep reclaims it
            // (plan §1.4 end-of-call / §2.5)
            if let Some(group) = db.fetch_open_mls_group_for_channel(channel_id).await? {
                db.close_mls_group(&group.id).await?;
            }
        }
        _ => {}
    };

    Ok(EmptyResponse)
}

/// The sids of `recorded` connections (this user's, from
/// `recorded_voice_connections`) that the SFU does not list in `listed`:
/// the connections whose own leave never arrived, which a `Survivor`
/// confirmation deletes (S-3 D-1, WA-R). Only primaries are ever recorded,
/// so a listed leg can never shield or name one. Pure.
///
/// `recorded` must have been read BEFORE `listed` was taken (the WA-R
/// ordering rule): a connection recorded after the listing is then in
/// neither set, so it is never named here.
fn stale_connections(recorded: &[(String, String)], listed: &[ParticipantInfo]) -> Vec<String> {
    recorded
        .iter()
        .filter(|(sid, _)| !listed.iter().any(|participant| &participant.sid == sid))
        .map(|(sid, _)| sid.clone())
        .collect()
}

/// The `joined_at` a `participant_joined` stamps on the voice state it
/// creates: the event's `created_at`, in unix SECONDS, as a timestamp.
///
/// `create_voice_state` stores it as whole milliseconds and
/// `get_voice_state` reads those back, so a whole-second value survives the
/// round trip exactly, and a retried event (the same body, the same
/// `created_at`) compares equal to the state its first attempt wrote
/// ([`retried_join`], WBR-1). Anything finer than a millisecond added here
/// would make that comparison never hold. Pure.
fn event_joined_at(created_at: i64) -> Timestamp {
    Timestamp::UNIX_EPOCH
        .checked_add(Duration::seconds(created_at))
        .unwrap()
}

/// Whether a `participant_joined` for the connection `sid`, whose record
/// answered `false` (the user already holds voice state in the channel), is
/// LiveKit retrying the join that created that state rather than a second
/// connection (AFK S-3 WB-1, WBR-1). `state` is the user's voice state in
/// the channel, `joined_at` this event's ([`event_joined_at`]), and
/// `recorded` the user's `recorded_voice_connections`, both read after `sid`
/// was recorded. Pure.
///
/// - A state decides alone: a retry exactly when its `joined_at` is this
///   event's. Only `create_voice_state` writes `joined_at`, from the event
///   that created the state, and a retry resends that event, so whatever
///   else the record holds (a sibling recorded between the failed attempt
///   and its retry, an over-cap sibling a failed backstop removal left, a
///   stale sid) cannot hide a retry. A state some other event created (a
///   sibling's, a state from before the record existed, a ghost) makes this
///   a second connection, whatever the record holds.
/// - No state: [`retried_first_connection`] decides from the record.
fn retried_join(
    state: Option<&UserVoiceState>,
    joined_at: Timestamp,
    recorded: &[(String, String)],
    sid: &str,
) -> bool {
    match state {
        Some(state) => state.joined_at == joined_at,
        None => retried_first_connection(recorded, sid),
    }
}

/// Whether a `participant_joined` for the connection `sid`, whose record
/// answered `false`, is a retry of the user's FIRST connection when NO voice
/// state is left to compare against (a teardown between the record and the
/// read, or a state missing a key `get_voice_state` needs); [`retried_join`]
/// consults it only then.
/// `recorded` is this user's `recorded_voice_connections`, read after `sid`
/// was recorded. Pure.
///
/// A retry is `sid` as the user's ONLY recorded connection: no other
/// connection can hold the state, so the state is created and the join
/// announced. Any other recorded sid is a sibling. A record without `sid` (a
/// teardown removed it since) is neither, and is not announced.
fn retried_first_connection(recorded: &[(String, String)], sid: &str) -> bool {
    matches!(recorded, [(only, _)] if only == sid)
}

/// The `camera` / `screensharing` / `screen_video` / `is_publishing` flags of
/// `user_id` recomputed from what their SURVIVING connections publish in the
/// SFU's `listed` participants, after the connection `departed_sid` left
/// (S-3 D-1, P2-5). Pure.
///
/// Survivors are the user's listed primaries other than `departed_sid`. A
/// screen leg counts for the survivor it derives from
/// (`screen_leg_identity`), because the leg track handler writes a leg's
/// tracks onto its OWNER's flags; the departed connection's leg does not
/// count unless a survivor shares its identity.
///
/// The source-to-flag mapping is `update_voice_state_tracks`' own: camera
/// (1) sets `camera`, microphone (2) `is_publishing`, screen video (3) both
/// `screensharing` and `screen_video`, screen audio (4) `screensharing`
/// only, and the whisper source (0) nothing. A MUTED track counts as off,
/// as `track_muted` turns its flag off. Every flag is set, so a flag no
/// survivor backs is written `false`.
fn survivor_track_flags(
    listed: &[ParticipantInfo],
    user_id: &str,
    departed_sid: &str,
) -> PartialUserVoiceState {
    let survivors: Vec<&ParticipantInfo> = listed
        .iter()
        .filter(|participant| {
            !is_screen_leg(&participant.identity)
                && user_id_from_participant_identity(&participant.identity) == user_id
                && participant.sid != departed_sid
        })
        .collect();
    let legs = listed.iter().filter(|participant| {
        is_screen_leg(&participant.identity)
            && survivors
                .iter()
                .any(|survivor| screen_leg_identity(&survivor.identity) == participant.identity)
    });

    let (mut camera, mut is_publishing, mut screensharing, mut screen_video) =
        (false, false, false, false);
    for track in survivors
        .iter()
        .copied()
        .chain(legs)
        .flat_map(|participant| &participant.tracks)
        .filter(|track| !track.muted)
    {
        match track.source {
            /* TrackSource::Camera */
            1 => camera = true,
            /* TrackSource::Microphone */
            2 => is_publishing = true,
            /* TrackSource::ScreenShare */
            3 => {
                screensharing = true;
                screen_video = true;
            }
            /* TrackSource::ScreenShareAudio */
            4 => screensharing = true,
            _ => {}
        }
    }

    PartialUserVoiceState {
        camera: Some(camera),
        is_publishing: Some(is_publishing),
        screensharing: Some(screensharing),
        screen_video: Some(screen_video),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    /// This file as it ships: everything above its test module.
    fn shipping() -> &'static str {
        const SOURCE: &str = include_str!("api.rs");
        let tests_at = SOURCE
            .find("#[cfg(test)]\nmod tests")
            .expect("api.rs has a test module");
        &SOURCE[..tests_at]
    }

    /// The shipping code with every whole-line comment (`//`, `///`) dropped,
    /// so a comment can neither satisfy nor trip a pin.
    fn code() -> String {
        shipping()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// [`code`] with ALL whitespace removed, for call-shape pins that must
    /// not depend on how rustfmt wraps a call.
    fn dense() -> String {
        code().split_whitespace().collect()
    }

    /// The body of the MEMBER arm for `event`, between its braces, with
    /// whitespace collapsed to single spaces. The member arm is the LAST
    /// `"<event>" =>` arm in the file; the first belongs to the screen-leg
    /// branch. (No brace characters in comments here: the db crate's
    /// workspace scan strips test modules by brace matching.)
    fn member_arm(event: &str) -> String {
        let code = code();
        let arm = code
            .rfind(&format!("\"{event}\" => {}", '\u{7b}'))
            .unwrap_or_else(|| panic!("the member {event} arm"));
        let open = arm + code[arm..].find('\u{7b}').unwrap();
        let mut depth = 0i64;
        let mut body_end = None;
        for (i, ch) in code[open..].char_indices() {
            match ch {
                '\u{7b}' => depth += 1,
                '\u{7d}' => {
                    depth -= 1;
                    if depth == 0 {
                        body_end = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        code[open + 1..body_end.expect("a closed arm")]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The position of the ONE occurrence of `needle` in `body`.
    fn once(body: &str, needle: &str) -> usize {
        assert_eq!(
            body.matches(needle).count(),
            1,
            "expected exactly one `{needle}`: {body}"
        );
        body.find(needle).unwrap()
    }

    /// The argument lists of every call to `callee` (which ends in `(`) in
    /// the whitespace-free `dense` text, each split on its commas.
    fn call_args(dense: &str, callee: &str) -> Vec<Vec<String>> {
        dense
            .match_indices(callee)
            .map(|(at, _)| {
                let args = &dense[at + callee.len()..];
                let close = args.find(')').expect("a closed call");
                args[..close].split(',').map(str::to_string).collect()
            })
            .collect()
    }

    /// M4-b (Wave 5b-2), narrowed by AFK S-3 D-1: the MEMBER
    /// `participant_left` arm publishes its `VoiceChannelLeave` under exactly
    /// ONE condition, `leave == ConnectionLeave::Last` — the user's last
    /// connection in the channel left. A surviving connection of the same
    /// user withholds it, since the user is still in the call; nothing else
    /// may, and no early `return` may skip it.
    ///
    /// Mutations this catches: the Leave put back under any other
    /// conditional (the old `moved_from` check, or any other), which brings
    /// back the ghost a move left on every other client's roster when no
    /// destination join followed; and the Leave made unconditional again,
    /// which would announce a departure for a user whose other device is
    /// still connected. The `?`s ahead of it are deliberate: a failed
    /// teardown or confirmation answers 500 and LiveKit retries the webhook.
    #[test]
    fn a_member_leave_is_always_published() {
        assert!(
            !shipping().contains("moved_from"),
            "the moved_from marker is back in the ingress"
        );

        let body = member_arm("participant_left");
        let leave = body
            .find("EventV1::VoiceChannelLeave")
            .expect("the member arm must publish a VoiceChannelLeave");
        let before = &body[..leave];

        // The braces still open at the Leave: exactly one, and the text that
        // opens it (back to the previous statement boundary) is the `Last`
        // condition and nothing else.
        let mut open = Vec::new();
        for (i, ch) in before.char_indices() {
            match ch {
                '\u{7b}' => open.push(i),
                '\u{7d}' => {
                    open.pop().expect("balanced braces");
                }
                _ => {}
            }
        }
        assert_eq!(
            open.len(),
            1,
            "the Leave must sit exactly one block deep, under the `Last` \
             condition alone: {body}"
        );
        let opener = open[0];
        let from = before[..opener]
            .rfind([';', '\u{7b}', '\u{7d}'])
            .map_or(0, |at| at + 1);
        assert_eq!(
            before[from..opener].trim(),
            "if leave == ConnectionLeave::Last",
            "the ONLY condition allowed on the Leave is the `Last` answer: {body}"
        );
        assert!(
            !before.contains("return"),
            "nothing before the Leave may return early and skip it: {body}"
        );

        assert!(
            body[leave..].starts_with(
                "EventV1::VoiceChannelLeave \u{7b} id: channel_id.clone(), \
                 user: user_id.clone(), \u{7d} .p(channel_id.clone()) .await;"
            ),
            "the Leave must be published to the channel it names: {body}"
        );
    }

    /// WA-R ordering rule (S-3 WA-1): a `Survivor` answer is confirmed by
    /// reading the record FIRST and listing the SFU AFTER. Mutation this
    /// catches: the listing moved ahead of the record read, which names a
    /// sibling that records in between as stale and deletes it while live.
    #[test]
    fn a_member_leave_reads_the_record_before_listing_the_sfu() {
        let body = member_arm("participant_left");
        let recorded = once(&body, "recorded_voice_connections(");
        let listed = once(&body, "list_participants_reported(");
        assert!(
            recorded < listed,
            "the record must be read BEFORE the SFU listing: {body}"
        );
        // The stale set is what the set delete is handed.
        let stale = once(&body, "stale_connections(&recorded, &listed)");
        let deleted = once(&body, "delete_voice_connections(&channel, user_id, &stale)");
        assert!(listed < stale && stale < deleted, "{body}");
    }

    /// WB-4 (the Wave B audit's N3): the `Survivor` confirmation propagates a
    /// failed record read AND a failed listing with `?`, so the webhook
    /// answers 500 and LiveKit retries it. Mutations this catches: either
    /// call's `?` swapped for `.unwrap_or_default()`, which compiles. A
    /// failed listing then reads as an empty room, every recorded sibling as
    /// stale, and the set delete tears a live sibling down (WA-1 again). A
    /// failed record read reads as nothing recorded, which keeps the stale
    /// sid the confirmation exists to find.
    #[test]
    fn a_member_leave_propagates_a_failed_record_read_or_listing() {
        let body = member_arm("participant_left");
        once(
            &body,
            "let recorded = recorded_voice_connections(&channel, user_id).await?;",
        );
        once(
            &body,
            "let listed = voice_client .list_participants_reported(node, channel_id) \
             .await? .unwrap_or_default();",
        );
    }

    /// RA2-1: the leave path never tears the WHOLE user down, since it is
    /// decided by an SFU listing that a later sibling is absent from.
    /// Mutation this catches: the stale delete swapped for the whole-user
    /// `delete_voice_state`, which erases a sibling recorded after the
    /// listing (WA-1).
    #[test]
    fn a_member_leave_never_tears_down_the_whole_user() {
        let body = member_arm("participant_left");
        assert!(
            !body.contains("delete_voice_state("),
            "no whole-user teardown on the leave path: {body}"
        );
        once(&body, "delete_voice_connection(&channel, user_id, sid)");
    }

    /// P2-4: the leave path does not HDEL the identity mapping. The script
    /// drops it on `Last`, and on `Survivor` has re-pointed it at the
    /// surviving connection, which an HDEL would undo. Mutation this
    /// catches: the old unconditional `delete_voice_participant_identity`
    /// put back.
    #[test]
    fn a_member_leave_never_drops_the_identity_mapping() {
        let body = member_arm("participant_left");
        assert!(
            !body.contains("delete_voice_participant_identity("),
            "the leave path must not HDEL the mapping: {body}"
        );
    }

    /// D-7 / P2-5: the connection-scoped remote-control release runs BEFORE
    /// the teardown, so it still runs when the teardown's `?` fails, and the
    /// whole-user release is never what a single connection's leave runs: it
    /// appears once, after the `Survivor` confirmation's set delete (WB-10,
    /// pinned in full below). Mutations this catches: the release moved after
    /// `delete_voice_connection`, and the whole-user release put back at the
    /// top of the arm, which ends a controller grant held by the user's
    /// OTHER, still-live connection.
    #[test]
    fn a_member_leave_releases_remote_control_before_the_teardown() {
        let body = member_arm("participant_left");
        let release = once(&body, "release_remote_control_for_connection(");
        let teardown = once(&body, "delete_voice_connection(");
        assert!(
            release < teardown,
            "the release must run before the teardown: {body}"
        );
        let whole_user = once(&body, "release_remote_control_for_user(");
        let set_delete = once(&body, "delete_voice_connections(&channel, user_id, &stale)");
        assert!(
            set_delete < whole_user,
            "the whole-user release runs only after the set delete: {body}"
        );
    }

    /// WB-10: when the `Survivor` confirmation's set delete answers `Last`,
    /// no connection of the user is left, so the WHOLE-USER release runs
    /// (with a revoke), under that condition alone and right after the set
    /// delete. The per-connection release at the top of the arm ends a
    /// controller grant only when the departing connection held it; one held
    /// by a stale connection would otherwise outlive the user. Mutations this
    /// catches: the release dropped, run without the `Last` condition (which
    /// ends grants of a user still in the call), and told the participant is
    /// already gone (which skips the revoke).
    #[test]
    fn a_survivor_confirmed_as_last_releases_remote_control_for_the_whole_user() {
        let body = member_arm("participant_left");
        once(
            &body,
            "leave = delete_voice_connections(&channel, user_id, &stale).await?; \
             if leave == ConnectionLeave::Last \u{7b} \
             revolt_database::voice::remote_control::release_remote_control_for_user( \
             db, voice_client, &channel, user_id, \"participant_left\", false, ) .await; \
             \u{7d} \u{7d}",
        );
    }

    /// WBR-2: once the join is announced, nothing in the member join may
    /// answer 500, since the retry would announce it again (a Move as a
    /// Join), ring again and re-run the cap backstop after the announce. The
    /// ring's roster read is matched, never `?`-propagated, and its failure
    /// is reported through `to_internal_error` (ERROR + Sentry). Mutation
    /// this catches: `get_voice_channel_members(&channel).await?` put back.
    #[test]
    fn nothing_after_the_join_announce_answers_500() {
        let body = member_arm("participant_joined");
        let announce = once(
            &body,
            "if let Some(source_channel) = get_user_moved_to_voice(channel_id, user_id).await? \u{7b}",
        );
        let after = &body[announce..];
        let after = &after[after.find('\u{7b}').unwrap()..];
        assert!(
            !after.contains(".await?") && !after.contains(")?"),
            "a `?` after the announce answers 500 and re-announces on retry: {after}"
        );
        let read = once(
            after,
            "match get_voice_channel_members(&channel).await \u{7b} Ok(members) => \u{7b}",
        );
        let failed = once(after, "Err(error) => \u{7b}");
        let reported = once(after, "let _ = Err::<(), _>(error).to_internal_error();");
        assert!(read < failed && failed < reported, "{after}");
    }

    /// The leg cleanup on a leave addresses ONLY the leg derived from the
    /// event identity. A bare `{user}` reconnect reuses the identity, so
    /// evicting the event identity itself on a late leave would kick the new
    /// live connection. Mutation this catches: the cleanup addressed to
    /// `identity`.
    #[test]
    fn a_member_leave_evicts_only_the_screen_leg() {
        let body = member_arm("participant_left");
        let dense: String = body.split_whitespace().collect();
        once(&dense, "remove_identity_if_present(");
        once(
            &dense,
            "remove_identity_if_present(node,&screen_leg_identity(identity),channel_id)",
        );
        assert!(
            !dense.contains("remove_connection_if_present("),
            "a leave evicts no primary: {body}"
        );
    }

    /// D-3: the Connect re-check runs FIRST in the member join, before the
    /// mapping, the record or the voice state is written. Mutation this
    /// catches: the re-check moved after `set_voice_participant_identity`,
    /// which leaves a refused connection's mapping behind.
    #[test]
    fn a_member_join_rechecks_connect_before_writing_anything() {
        let body = member_arm("participant_joined");
        let recheck = once(&body, "voice_connect_still_allowed(");
        for write in [
            "set_voice_participant_identity(",
            "record_voice_connection(",
            "create_voice_state(",
        ] {
            assert!(
                recheck < once(&body, write),
                "the Connect re-check must precede `{write}`: {body}"
            );
        }
    }

    /// DS-2: a failed Connect re-check fails CLOSED — the connection is
    /// treated exactly as a refused one. Mutation this catches: the error
    /// arm answering `true`, which admits every connection while the
    /// permission read is failing.
    #[test]
    fn a_failed_connect_recheck_fails_closed() {
        let body = member_arm("participant_joined");
        let recheck = once(&body, "voice_connect_still_allowed(");
        let guard = once(&body, "if !allowed \u{7b}");
        let decision = &body[recheck..guard];
        assert!(
            decision.contains("Ok(allowed) => allowed, Err(error) => \u{7b}"),
            "{decision}"
        );
        assert!(
            decision.trim_end().ends_with("false \u{7d} \u{7d};"),
            "a failed re-check must answer `false` (evict): {decision}"
        );
    }

    /// D-1 / F-15, amended by WB-1: only a FIRST connection
    /// (`record_voice_connection` answered `true`) resets the flags. A retry
    /// of it reads the state its first attempt wrote, and creates one only
    /// when none exists; a second connection never reaches the reset.
    /// Mutations this catches: `create_voice_state` run unconditionally,
    /// which resets a live sibling's camera/share/mic flags on every extra
    /// device, and run on the retry path, which wipes the flags track events
    /// set since the first attempt.
    #[test]
    fn a_member_join_resets_state_only_for_the_first_connection() {
        let body = member_arm("participant_joined");
        let record = once(
            &body,
            "let first_connection = record_voice_connection(&channel, user_id, sid, identity).await?;",
        );
        let first = once(
            &body,
            "let existing_state = if first_connection \u{7b} None \u{7d} else \u{7b}",
        );
        let reuse = once(
            &body,
            "let state = get_voice_state(&channel, user_id).await?;",
        );
        once(&body, "return Ok(EmptyResponse); \u{7d} state \u{7d};");
        let create = once(
            &body,
            "let voice_state = match existing_state \u{7b} \
             Some(voice_state) => voice_state, \
             None => create_voice_state(&channel, user_id, joined_at).await?, \u{7d};",
        );
        once(&body, "create_voice_state(");
        let backstop = once(&body, "video_roster_over_cap(");
        assert!(
            record < first && first < reuse && reuse < create && create < backstop,
            "the state is created only when none was read, before the \
             backstop: {body}"
        );
    }

    /// WB-1 as amended by WBR-1: a `false` record answer is decided by
    /// `retried_join`, handed the state, THIS event's `joined_at` (the one
    /// `event_joined_at` derives, the value `create_voice_state` stores), the
    /// record and the sid. A retry runs the cap backstop and is announced.
    /// Only a second connection returns early, and that is the ONLY early
    /// return between the record and the backstop. Mutations this catches:
    /// the unconditional early return restored (`if !first_connection`), the
    /// decision inverted at the call site, and the route deciding by
    /// `retried_first_connection` alone, which reads a retry with anything
    /// else recorded as a sibling (the re-audit's residuals a, b and c-prime)
    /// and a legacy or ghost state as a retry (residual c).
    #[test]
    fn a_retried_first_join_is_announced_and_runs_the_backstop() {
        let body = member_arm("participant_joined");
        let stamped = once(&body, "let joined_at = event_joined_at(event.created_at);");
        assert_eq!(body.matches("let joined_at").count(), 1, "{body}");
        let record = once(
            &body,
            "let first_connection = record_voice_connection(&channel, user_id, sid, identity).await?;",
        );
        let decision = once(
            &body,
            "let existing_state = if first_connection \u{7b} None \u{7d} else \u{7b} \
             let recorded = recorded_voice_connections(&channel, user_id).await?; \
             let state = get_voice_state(&channel, user_id).await?; \
             if !retried_join(state.as_ref(), joined_at, &recorded, sid) \u{7b} \
             return Ok(EmptyResponse); \u{7d} \
             state \u{7d};",
        );
        assert!(
            !body.contains("retried_first_connection("),
            "the route decides through `retried_join` only: {body}"
        );
        assert!(stamped < record, "{body}");
        let backstop = once(&body, "video_roster_over_cap(");
        let announce = once(&body, "EventV1::VoiceChannelJoin");
        assert!(
            record < decision && decision < backstop && backstop < announce,
            "{body}"
        );
        assert_eq!(
            body[record..backstop].matches("return").count(),
            1,
            "the sibling return is the only exit between the record and the \
             backstop: {body}"
        );
    }

    /// WB-3: both caps are per USER. When the backstop's teardown of THIS
    /// connection answers `Survivor` (a sibling recorded meanwhile), the user
    /// is removed from the channel by `remove_user_from_voice_channel`, the
    /// ordering-rule removal, and nothing is announced. Mutation this
    /// catches: the `Survivor` arm emptied, which leaves the sibling in the
    /// call over the cap and never announced.
    #[test]
    fn the_cap_backstop_removes_the_user_when_a_sibling_survives() {
        let body = member_arm("participant_joined");
        let backstop = once(&body, "video_roster_over_cap(");
        let evict = backstop
            + body[backstop..]
                .find("remove_connection_if_present(node, identity, channel_id) .await?;")
                .expect("the backstop evicts this connection");
        let teardown = once(
            &body,
            "match delete_voice_connection(&channel, user_id, sid).await? \u{7b} \
             ConnectionLeave::Last => \u{7b}\u{7d} ConnectionLeave::Survivor => \u{7b} \
             remove_user_from_voice_channel(db, voice_client, &channel, user_id).await?; \
             \u{7d} \u{7d}",
        );
        let removal = once(&body, "remove_user_from_voice_channel(");
        let exit = teardown
            + body[teardown..]
                .find("return Ok(EmptyResponse);")
                .expect("the backstop returns");
        let announce = once(&body, "EventV1::VoiceChannelJoin");
        assert!(
            backstop < evict
                && evict < teardown
                && teardown < removal
                && removal < exit
                && exit < announce,
            "{body}"
        );
        assert!(
            !body[backstop..exit].contains("EventV1::"),
            "the backstop announces nothing: {body}"
        );
        assert!(
            !body.contains("delete_voice_state("),
            "no whole-user teardown on the join path: {body}"
        );
    }

    /// No ingress path resolves a connection through the identity mapping,
    /// which names at most one connection of the user (S-3 D-1/D-2): every
    /// remedy addresses the event's own identity, and the one whole-user
    /// removal goes through `remove_user_from_voice_channel`, which reads
    /// the record BEFORE it lists the SFU (the WA-R ordering rule). Mutations
    /// this catches: a mapping read put back (`get_voice_participant_identity`),
    /// and a direct `remove_user_if_present` / `remove_user_if_present_sids`
    /// call, which lists and evicts with no record read ahead of it. (The
    /// methods this test used to ban, `VoiceClient::remove_user` and
    /// `mute_track`, no longer exist, so banning them here pinned nothing.)
    #[test]
    fn no_ingress_path_resolves_a_connection_through_the_mapping() {
        let dense = dense();
        assert!(
            !dense.contains("get_voice_participant_identity("),
            "a mapping read is back"
        );
        assert!(
            !dense.contains("remove_user_if_present"),
            "a direct whole-user SFU removal is back"
        );
    }

    /// Every SFU call goes behind `VoiceClient` (S-3 D-2/D-5: its timeout and
    /// breaker). `RoomClient.client` is private now, so the old route to the
    /// raw client is closed; what is left is this crate building its own
    /// LiveKit room client. Mutations this catches: a `RoomClient` named here,
    /// and a raw `remove_participant` call.
    #[test]
    fn no_ingress_path_calls_the_room_client_directly() {
        let dense = dense();
        assert!(!dense.contains("RoomClient"), "a raw room client is back");
        assert!(
            !dense.contains(".remove_participant("),
            "a raw `remove_participant` is back"
        );
    }

    /// S-3 D-2/SR-2: every connection eviction and every track mute addresses
    /// the EVENT `identity`, and an eviction's failure is never discarded (it
    /// answers 500, so LiveKit retries). Mutations this catches: a mute
    /// addressed to `user_id`, and an eviction whose error is dropped.
    #[test]
    fn every_ingress_enforcement_addresses_the_event_identity() {
        let dense = dense();
        let removals = call_args(&dense, "remove_connection_if_present(");
        let mutes = call_args(&dense, "mute_track_identity(");
        assert_eq!(removals.len(), 3, "the three member eviction sites");
        assert_eq!(mutes.len(), 4, "two leg mutes and two member mutes");
        for args in removals.iter().chain(&mutes) {
            assert_eq!(args[1], "identity", "{args:?}");
        }
        assert_eq!(
            dense
                .matches("remove_connection_if_present(node,identity,channel_id).await?;")
                .count(),
            removals.len(),
            "every eviction must propagate its error"
        );
    }

    use super::{
        create_voice_state, delete_channel_voice_state, event_joined_at, get_voice_state,
        record_voice_connection, recorded_voice_connections, retried_first_connection,
        retried_join, stale_connections, survivor_track_flags, UserVoiceChannel,
    };
    use livekit_protocol::{ParticipantInfo, TrackInfo};
    use revolt_models::v0::{PartialUserVoiceState, UserVoiceState};

    /// A listed participant publishing `(source, muted)` tracks.
    fn participant(identity: &str, sid: &str, tracks: &[(i32, bool)]) -> ParticipantInfo {
        ParticipantInfo {
            identity: identity.to_string(),
            sid: sid.to_string(),
            tracks: tracks
                .iter()
                .map(|&(source, muted)| TrackInfo {
                    source,
                    muted,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    /// `(camera, is_publishing, screensharing, screen_video)`.
    fn flags(partial: &PartialUserVoiceState) -> [Option<bool>; 4] {
        [
            partial.camera,
            partial.is_publishing,
            partial.screensharing,
            partial.screen_video,
        ]
    }

    const OFF: [Option<bool>; 4] = [Some(false); 4];

    #[test]
    fn stale_connections_are_the_recorded_sids_the_sfu_does_not_list() {
        let recorded = vec![
            ("PA_a".to_string(), "u:A".to_string()),
            ("PA_b".to_string(), "u:B".to_string()),
            ("PA_c".to_string(), "u".to_string()),
        ];
        let listed = vec![
            participant("u:A", "PA_a", &[]),
            participant("u", "PA_c", &[]),
            participant("u:A:screen", "PA_leg", &[]),
            participant("v", "PA_v", &[]),
        ];
        assert_eq!(stale_connections(&recorded, &listed), vec!["PA_b".to_string()]);
        assert_eq!(
            stale_connections(&recorded, &[]),
            vec!["PA_a".to_string(), "PA_b".to_string(), "PA_c".to_string()],
            "a room the SFU no longer has lists nothing"
        );
        assert!(stale_connections(&[], &listed).is_empty());
    }

    /// This user's recorded connections, as `recorded_voice_connections`
    /// returns them: `(sid, identity)`, ordered by sid.
    fn record(sids: &[&str]) -> Vec<(String, String)> {
        sids.iter()
            .map(|sid| (sid.to_string(), format!("u:{sid}")))
            .collect()
    }

    #[test]
    fn only_this_sid_recorded_is_a_retry_of_the_first_connection() {
        assert!(retried_first_connection(&record(&["PA_a"]), "PA_a"));
    }

    #[test]
    fn a_recorded_sibling_makes_a_second_connection() {
        let both = record(&["PA_a", "PA_b"]);
        assert!(!retried_first_connection(&both, "PA_a"));
        assert!(!retried_first_connection(&both, "PA_b"));
    }

    #[test]
    fn a_sid_the_record_no_longer_holds_is_not_announced() {
        assert!(!retried_first_connection(&record(&[]), "PA_a"));
        assert!(!retried_first_connection(&record(&["PA_b"]), "PA_a"));
    }

    /// The `created_at` (unix seconds) of the join event that created the
    /// state, and of a later join event.
    const FIRST: i64 = 1_790_000_000;
    const LATER: i64 = FIRST + 7;

    /// A voice state as `create_voice_state` writes it for a join event
    /// created at `created_at`.
    fn state_of(created_at: i64) -> UserVoiceState {
        UserVoiceState {
            id: "u".to_string(),
            joined_at: event_joined_at(created_at),
            is_receiving: true,
            is_publishing: false,
            screensharing: false,
            camera: false,
            screen_video: false,
            recording: false,
            rc_capable: false,
            watching: false,
        }
    }

    #[test]
    fn a_retry_matches_the_joined_at_its_first_attempt_wrote() {
        let state = state_of(FIRST);
        assert!(retried_join(
            Some(&state),
            event_joined_at(FIRST),
            &record(&["PA_a"]),
            "PA_a"
        ));
    }

    /// Residual (a) of the Wave B re-audit: the backstop's removal after a
    /// `Survivor` failed, so the over-cap sibling is still recorded next to
    /// the retried connection. The retry must re-run the backstop.
    #[test]
    fn a_retry_after_a_failed_backstop_removal_is_still_a_retry() {
        let state = state_of(FIRST);
        assert!(retried_join(
            Some(&state),
            event_joined_at(FIRST),
            &record(&["PA_a", "PA_b"]),
            "PA_a"
        ));
    }

    /// Residual (b): a sibling recorded between the first attempt's failure
    /// and its retry. The retry is announced; the sibling's own join, a
    /// later event, is not a retry.
    #[test]
    fn a_sibling_recorded_before_the_retry_does_not_hide_it() {
        let state = state_of(FIRST);
        let both = record(&["PA_a", "PA_b"]);
        assert!(retried_join(
            Some(&state),
            event_joined_at(FIRST),
            &both,
            "PA_a"
        ));
        assert!(!retried_join(
            Some(&state),
            event_joined_at(LATER),
            &both,
            "PA_b"
        ));
    }

    /// Residual (c-prime): a stale sid (a connection whose own leave never
    /// arrived) recorded next to the retried connection.
    #[test]
    fn a_stale_recorded_sid_does_not_hide_a_retry() {
        let state = state_of(FIRST);
        assert!(retried_join(
            Some(&state),
            event_joined_at(FIRST),
            &record(&["PA_a", "PA_stale"]),
            "PA_a"
        ));
    }

    /// Residual (c): a state no connection in the record created (one from
    /// before the record existed, or a ghost), with this sid the only one
    /// recorded. That is a second connection of a user every roster already
    /// shows: not announced again, and the state's flags are not reset.
    #[test]
    fn a_legacy_or_ghost_state_is_not_a_retry() {
        let ghost = state_of(FIRST);
        assert!(!retried_join(
            Some(&ghost),
            event_joined_at(LATER),
            &record(&["PA_c"]),
            "PA_c"
        ));
        assert!(!retried_join(
            Some(&ghost),
            event_joined_at(LATER),
            &record(&[]),
            "PA_c"
        ));
    }

    #[test]
    fn a_second_connection_is_not_a_retry() {
        let state = state_of(FIRST);
        assert!(!retried_join(
            Some(&state),
            event_joined_at(LATER),
            &record(&["PA_a", "PA_b"]),
            "PA_b"
        ));
        assert!(!retried_join(
            Some(&state),
            event_joined_at(FIRST - 1),
            &record(&["PA_b"]),
            "PA_b"
        ));
    }

    /// With no state left to compare against, the record decides
    /// (`retried_first_connection`).
    #[test]
    fn with_no_state_the_record_decides() {
        let at = event_joined_at(FIRST);
        assert!(retried_join(None, at, &record(&["PA_a"]), "PA_a"));
        assert!(!retried_join(None, at, &record(&["PA_a", "PA_b"]), "PA_a"));
        assert!(!retried_join(None, at, &record(&["PA_b"]), "PA_a"));
        assert!(!retried_join(None, at, &record(&[]), "PA_a"));
    }

    /// One process-lifetime runtime for the Redis-backed test below.
    /// `redis_kiss` pools connections globally, and a pooled connection made
    /// on a runtime that has since shut down is dead; the db crate's voice
    /// tests share one runtime for the same reason.
    fn rt() -> &'static rocket::tokio::runtime::Runtime {
        static RT: std::sync::OnceLock<rocket::tokio::runtime::Runtime> =
            std::sync::OnceLock::new();
        RT.get_or_init(|| {
            rocket::tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap()
        })
    }

    /// WBR-1 through the REAL storage path, on live Redis: the `joined_at` a
    /// retried event derives (`event_joined_at`, seconds) compares EQUAL to
    /// the one `create_voice_state` stored (milliseconds) and
    /// `get_voice_state` read back, so the retry rule can hold; a sibling's
    /// later event does not. Also WBR-7 (the Wave B audit's N1): recording
    /// the same sid again once its first attempt wrote the state answers
    /// `false` and leaves ONE record entry. Needs Redis, like the db crate's
    /// voice tests. Everything is read before the cleanup and asserted
    /// after it, so a failure leaves no keys behind.
    #[test]
    fn a_retried_join_matches_the_state_its_first_attempt_stored_in_redis() {
        rt().block_on(async {
            let channel = UserVoiceChannel {
                id: format!("C2TEST{}", ulid::Ulid::new()),
                server_id: None,
            };
            let user = format!("C2USER{}", ulid::Ulid::new());
            let sibling = format!("{user}:B");
            let created_at: i64 = 1_790_000_000;

            // The first attempt: recorded with no state yet, then the state.
            let first = record_voice_connection(&channel, &user, "PA_a", &user).await;
            let created = create_voice_state(&channel, &user, event_joined_at(created_at)).await;
            // Its retry records the same sid again; then a sibling records.
            let retried = record_voice_connection(&channel, &user, "PA_a", &user).await;
            let recorded_once = recorded_voice_connections(&channel, &user).await;
            let second = record_voice_connection(&channel, &user, "PA_b", &sibling).await;
            let recorded = recorded_voice_connections(&channel, &user).await;
            let state = get_voice_state(&channel, &user).await;

            let cleanup = delete_channel_voice_state(&channel, std::slice::from_ref(&user)).await;
            let state_after = get_voice_state(&channel, &user).await;
            let recorded_after = recorded_voice_connections(&channel, &user).await;

            assert!(first.unwrap(), "no state yet: a first connection");
            assert_eq!(created.unwrap().joined_at, event_joined_at(created_at));
            assert!(!retried.unwrap(), "the retry finds the state (WBR-7)");
            assert_eq!(
                recorded_once.unwrap(),
                vec![("PA_a".to_string(), user.clone())],
                "the same sid recorded twice is ONE entry"
            );
            assert!(!second.unwrap(), "the sibling finds the state");

            let recorded = recorded.unwrap();
            assert_eq!(recorded.len(), 2, "{recorded:?}");
            let state = state.unwrap().expect("the state the first attempt wrote");
            assert_eq!(
                state.joined_at,
                event_joined_at(created_at),
                "the stored joined_at must read back exactly"
            );
            assert!(
                retried_join(Some(&state), event_joined_at(created_at), &recorded, "PA_a"),
                "the retry is a retry, sibling recorded or not"
            );
            assert!(
                !retried_join(
                    Some(&state),
                    event_joined_at(created_at + 1),
                    &recorded,
                    "PA_b"
                ),
                "a sibling created a second later is not"
            );

            cleanup.unwrap();
            assert!(state_after.unwrap().is_none(), "the state is cleaned up");
            assert!(
                recorded_after.unwrap().is_empty(),
                "the record is cleaned up"
            );
        });
    }

    #[test]
    fn survivor_flags_a_camera_sets_camera_only() {
        let listed = vec![participant("u:A", "PA_a", &[(1, false)])];
        assert_eq!(
            flags(&survivor_track_flags(&listed, "u", "PA_gone")),
            [Some(true), Some(false), Some(false), Some(false)]
        );
    }

    #[test]
    fn survivor_flags_a_microphone_sets_is_publishing_only() {
        let listed = vec![participant("u:A", "PA_a", &[(2, false)])];
        assert_eq!(
            flags(&survivor_track_flags(&listed, "u", "PA_gone")),
            [Some(false), Some(true), Some(false), Some(false)]
        );
    }

    #[test]
    fn survivor_flags_screen_video_sets_screensharing_and_screen_video() {
        let listed = vec![participant("u", "PA_a", &[(3, false)])];
        assert_eq!(
            flags(&survivor_track_flags(&listed, "u", "PA_gone")),
            [Some(false), Some(false), Some(true), Some(true)]
        );
    }

    #[test]
    fn survivor_flags_screen_audio_is_screensharing_but_not_screen_video() {
        let listed = vec![participant("u:A", "PA_a", &[(4, false), (0, false)])];
        assert_eq!(
            flags(&survivor_track_flags(&listed, "u", "PA_gone")),
            [Some(false), Some(false), Some(true), Some(false)]
        );
    }

    #[test]
    fn survivor_flags_a_muted_track_is_off() {
        let listed = vec![participant(
            "u:A",
            "PA_a",
            &[(1, true), (2, true), (3, true), (4, true)],
        )];
        assert_eq!(flags(&survivor_track_flags(&listed, "u", "PA_gone")), OFF);
    }

    #[test]
    fn survivor_flags_every_flag_is_written_when_nothing_survives() {
        assert_eq!(flags(&survivor_track_flags(&[], "u", "PA_gone")), OFF);
    }

    #[test]
    fn survivor_flags_the_departed_connection_does_not_count() {
        let listed = vec![
            participant("u:B", "PA_gone", &[(1, false), (3, false)]),
            participant("u:A", "PA_a", &[(2, false)]),
        ];
        assert_eq!(
            flags(&survivor_track_flags(&listed, "u", "PA_gone")),
            [Some(false), Some(true), Some(false), Some(false)]
        );
    }

    #[test]
    fn survivor_flags_another_user_does_not_count() {
        let listed = vec![
            participant("uu:A", "PA_x", &[(1, false), (2, false), (3, false)]),
            participant("v", "PA_v", &[(4, false)]),
        ];
        assert_eq!(flags(&survivor_track_flags(&listed, "u", "PA_gone")), OFF);
    }

    #[test]
    fn survivor_flags_a_survivors_leg_counts_and_the_departed_leg_does_not() {
        // The survivor's leg shares a screen: it is the owner's share.
        let listed = vec![
            participant("u:A", "PA_a", &[]),
            participant("u:A:screen", "PA_leg_a", &[(3, false)]),
        ];
        assert_eq!(
            flags(&survivor_track_flags(&listed, "u", "PA_gone")),
            [Some(false), Some(false), Some(true), Some(true)]
        );

        // A leg of the connection that left (still listed) is not.
        let listed = vec![
            participant("u", "PA_a", &[]),
            participant("u:B:screen", "PA_leg_b", &[(3, false), (4, false)]),
        ];
        assert_eq!(flags(&survivor_track_flags(&listed, "u", "PA_gone")), OFF);
    }

    #[test]
    fn survivor_flags_a_leg_is_never_a_survivor() {
        // Only the departed connection's leg is listed: nothing survives.
        let listed = vec![participant("u:B:screen", "PA_leg_b", &[(3, false)])];
        assert_eq!(flags(&survivor_track_flags(&listed, "u", "PA_gone")), OFF);
    }
}
