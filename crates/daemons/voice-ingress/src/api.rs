use livekit_api::{access_token::TokenVerifier, webhooks::WebhookReceiver};
use livekit_protocol::TrackType;
use revolt_database::{
    events::client::EventV1,
    iso8601_timestamp::{Duration, Timestamp},
    util::reference::Reference,
    voice::{
        clear_voice_participant_identities, create_voice_state, delete_channel_voice_state,
        delete_voice_state, delete_voice_participant_identity, get_user_moved_from_voice,
        get_user_moved_to_voice, get_user_voice_channels, get_voice_channel_members,
        get_voice_state, is_screen_leg, is_screenshare_video, is_video_source,
        mls_cap_would_refuse, record_screen_leg, screen_leg_identity, screen_leg_left,
        set_voice_participant_identity,
        update_voice_state_tracks, user_id_from_participant_identity, video_roster_over_cap,
        RoomMetadata, UserVoiceChannel, VoiceClient, MAX_VIDEO_PARTICIPANTS,
    },
    Database, AMQP,
};
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
    // call: no voice state, no identity mapping (that map is per USER and
    // `remove_user` / `update_permissions` / the RC revoke all resolve through
    // it — a leg writing there would redirect every moderation action at the
    // phone), no roster slot, no join/leave events and no ring. Everything it
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

            let joined_at = Timestamp::UNIX_EPOCH
                .checked_add(Duration::seconds(event.created_at))
                .unwrap();

            // Record the full (possibly device-qualified) identity so
            // server-side participant operations can address the SFU
            set_voice_participant_identity(
                channel_id,
                user_id,
                identity.to_internal_error()?,
            )
            .await?;

            let voice_state = create_voice_state(&channel, user_id, joined_at).await?;

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
                let _ = voice_client.remove_user(node, user_id, channel_id).await;
                delete_voice_state(&channel, user_id).await?;
                delete_voice_participant_identity(channel_id, user_id).await?;
                // Drain any pending move marker for THIS channel so a rejoin
                // within its TTL isn't mis-announced as a VoiceChannelMove from
                // the old channel (the moved_from marker belongs to the old
                // channel's participant_left, so it is left untouched).
                let _ = get_user_moved_to_voice(channel_id, user_id).await;
                return Ok(EmptyResponse);
            }

            // Only publish one event when a user is moved from one channel to another.
            if let Some(moved_from) = get_user_moved_to_voice(channel_id, user_id).await? {
                EventV1::VoiceChannelMove {
                    user: user_id.to_string(),
                    from: moved_from.id,
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
            let members = get_voice_channel_members(&channel).await?;
            if members.map_or(0, |m| m.len()) <= 1 {
                let now = joined_at.to_string();
                if let Err(e) = amqp
                    .dm_call_updated(user_id, channel_id, Some(&now), false, None)
                    .await
                {
                    log::error!("failed to publish call ring push: {e:?}");
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

            // Remote-control release hook (plan §1). This is the ONE path
            // that may skip the controller-side revoke: the SFU has told
            // us the participant is already gone, so their capability went
            // with it and a revoke would be a guaranteed-failing round
            // trip. As SHARER their controller is still connected, and
            // that leg always revokes regardless.
            revolt_database::voice::remote_control::release_remote_control_for_user(
                db,
                voice_client,
                &channel,
                user_id,
                "participant_left",
                true,
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
            if let Some(identity) = identity {
                let _ = voice_client
                    .remove_identity(node, &screen_leg_identity(identity), channel_id)
                    .await;
            };

            delete_voice_state(&channel, user_id).await?;
            delete_voice_participant_identity(channel_id, user_id).await?;

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

            // Dont send leave event when a user is moved
            if get_user_moved_from_voice(channel_id, user_id)
                .await?
                .is_none()
            {
                EventV1::VoiceChannelLeave {
                    id: channel_id.clone(),
                    user: user_id.clone(),
                }
                .p(channel_id.clone())
                .await;
            };

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

                    // This removal is ingress-initiated and best-effort
                    // (its error is discarded just below), so the
                    // capability is actively revoked rather than assumed
                    // moot.
                    revolt_database::voice::remote_control::release_remote_control_for_user(
                        db,
                        voice_client,
                        &channel,
                        user_id,
                        "participant_left",
                        false,
                    )
                    .await;

                    let _ = voice_client.remove_user(node, user_id, channel_id).await;
                    delete_voice_state(&channel, user_id).await?;

                    return Ok(EmptyResponse);
                };

                // Out-of-band screenshare: refuse the TRACK, keep the MEMBER.
                // Muting enforces the limit just as well (the track is never
                // forwarded) without the disproportionate remedy of ejecting
                // someone mid-call over the shape of their monitor.
                if mute_offending {
                    let _ = voice_client
                        .mute_track(node, user_id, channel_id, &track.sid)
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
                            .mute_track(node, user_id, channel_id, &track.sid)
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
