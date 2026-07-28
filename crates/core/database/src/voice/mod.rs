use std::fmt::{Display, Write};

use crate::{
    events::client::EventV1,
    models::{Channel, User},
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, Server, MAX_MLS_GROUP_MEMBERS,
};
use iso8601_timestamp::{Duration, Timestamp};
use livekit_protocol::{ParticipantPermission, TrackSource};
use redis_kiss::{
    get_connection as _get_connection,
    redis::{FromRedisValue, Pipeline, RedisError, RedisWrite, ToRedisArgs, Value},
    AsyncCommands, Conn,
};
use revolt_config::FeaturesLimits;
use revolt_models::v0::{self, PartialUserVoiceState, UserVoiceState};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result, ToRevoltError};

pub mod remote_control;
mod voice_client;
pub use voice_client::VoiceClient;

async fn get_connection() -> Result<Conn> {
    _get_connection()
        .await
        .map_err(|_| create_error!(InternalError))
}

/// Product gate (media E2EE plan §0.2 / A3(b), D12): the maximum number of
/// call participants that may have video (camera or screenshare) active at
/// once. Independent of E2EE — applies to ALL calls. The client mirrors this
/// as `MAX_VIDEO_PARTICIPANTS = 30` in `state.tsx`; keep the two in lockstep.
pub const MAX_VIDEO_PARTICIPANTS: usize = 30;

/// Whether a LiveKit `TrackSource` int is a VIDEO source subject to the video
/// cap's enable leg. Camera = 1, ScreenShare(video) = 3. ScreenShareAudio = 4
/// maps to the `screensharing` flag too (see `count_video_participants`) but is
/// audio-only, so it is NOT refused by the enable leg — a deliberate asymmetry.
/// Source 3 alone drives the `screen_video` flag, which exists precisely
/// because `screensharing` conflates the two (remote-control plan §1).
pub fn is_video_source(source: i32) -> bool {
    matches!(source, 1 /* Camera */ | 3 /* ScreenShare */)
}

/// Count the current members of a voice channel who have video active — camera
/// OR screensharing. Reads the per-member Redis flags under the SAME key
/// composition the rest of this module uses: `{user_id}:{server_id | channel_id}`
/// (the members SET is keyed by channel id, but the per-member flags are keyed
/// by server id for server voice channels — composing `{user}:{channel_id}` on a
/// server channel misses every flag and the count reads 0, failing the cap OPEN).
///
/// NB: the `screensharing` flag is set for BOTH screen-video (source 3) and
/// screen-audio (source 4), so an audio-only screenshare conservatively consumes
/// a video slot here. That is the safe direction (cap slightly stricter).
/// Deliberately NOT switched to the stricter `screen_video` flag: states
/// created before that key existed lack it, and the conservative over-count
/// is the desired behaviour for the cap anyway.
pub async fn count_video_participants(channel: &UserVoiceChannel) -> Result<usize> {
    let Some(members) = get_voice_channel_members(channel).await? else {
        return Ok(0);
    };

    let parent_id = channel.server_id.as_ref().unwrap_or(&channel.id);
    let mut conn = get_connection().await?;
    let mut count = 0;

    for user_id in members {
        let unique_key = format!("{user_id}:{parent_id}");
        let (camera, screensharing): (Option<bool>, Option<bool>) = conn
            .mget(&[
                format!("camera:{unique_key}"),
                format!("screensharing:{unique_key}"),
            ])
            .await
            .to_internal_error()?;
        if camera.unwrap_or(false) || screensharing.unwrap_or(false) {
            count += 1;
        }
    }

    Ok(count)
}

/// Whether the D12 video-participant cap would REFUSE admitting `user_id` to
/// this channel's call right now (the join / moderator-move leg). The cap only
/// bites a call that is video-active AND already at `MAX_VIDEO_PARTICIPANTS`
/// members; a user who already holds voice state in this channel is exempt (a
/// reconnect / move within the same channel never grows the roster). The
/// `vc_members` set is written only by voice-ingress, so this exemption cannot
/// be forged by a client-supplied flag (the 6.6 `force_disconnect` fix).
pub async fn video_cap_would_refuse(channel: &UserVoiceChannel, user_id: &str) -> Result<bool> {
    let members = get_voice_channel_members(channel).await?.unwrap_or_default();
    Ok(!members.iter().any(|member| member == user_id)
        && members.len() >= MAX_VIDEO_PARTICIPANTS
        && count_video_participants(channel).await? > 0)
}

/// Whether the T-20 MLS SFU-token coupling would REFUSE admitting `user_id`:
/// the channel has an open MLS group at `MAX_MLS_GROUP_MEMBERS` and `user_id`
/// is not already one of its members (any device of theirs = rejoin is exempt).
/// Non-E2EE calls (no open group) never refuse. Without this an overflow joiner
/// sits as a non-enrolled SFU ghost tripping every member's loud-downgrade
/// banner (audit CR-HIGH-2).
pub async fn mls_cap_would_refuse(db: &Database, channel_id: &str, user_id: &str) -> Result<bool> {
    Ok(match db.fetch_open_mls_group_for_channel(channel_id).await? {
        Some(group) => {
            group.members.len() >= MAX_MLS_GROUP_MEMBERS
                && !group.members.iter().any(|member| member.user_id == user_id)
        }
        None => false,
    })
}

/// Enforce BOTH call-admission caps for a NEW join / moderator move (D12 then
/// T-20), raising the distinguishable 409 the cap owns. This is the single
/// source of truth for the join-leg caps: `join_call` and the moderator
/// voice-move path both call it, so a privileged door cannot bypass a cap the
/// front door enforces (6.6 review findings). It is check-then-act — the
/// voice-ingress backstop (`video_roster_over_cap` / `mls_cap_would_refuse`)
/// re-checks once the join is recorded to close the admission race.
pub async fn assert_call_caps_admit(
    db: &Database,
    channel: &UserVoiceChannel,
    user_id: &str,
) -> Result<()> {
    if video_cap_would_refuse(channel, user_id).await? {
        return Err(create_error!(VideoCallFull {
            max: MAX_VIDEO_PARTICIPANTS
        }));
    }
    if mls_cap_would_refuse(db, &channel.id, user_id).await? {
        return Err(create_error!(MlsCallFull {
            max: MAX_MLS_GROUP_MEMBERS
        }));
    }
    Ok(())
}

/// TOCTOU backstop predicate for voice-ingress `participant_joined`: once a
/// join is RECORDED (the user is already in `vc_members`), is the video roster
/// OVER the cap — i.e. this participant is overflow that the join leg let race
/// past? Uses a strict `>` on the post-join roster so the legitimate cap-th
/// member is kept and only genuine excess is kicked. Pairs with
/// `mls_cap_would_refuse` (membership-based, unaffected by the SFU join) for
/// the non-enrolled-ghost case.
pub async fn video_roster_over_cap(channel: &UserVoiceChannel) -> Result<bool> {
    let members = get_voice_channel_members(channel)
        .await?
        .map(|m| m.len())
        .unwrap_or(0);
    Ok(members > MAX_VIDEO_PARTICIPANTS && count_video_participants(channel).await? > 0)
}

pub async fn raise_if_in_voice(user: &User, channel: &UserVoiceChannel) -> Result<()> {
    let mut conn = get_connection().await?;

    if user.bot.is_some() {
        // bots can be in as many voice channels as it wants so we just check if its already connected to the one its trying to connect to
        if conn
            .sismember(format!("vc:{}", &user.id), channel)
            .await
            .to_internal_error()?
        {
            return Err(create_error!(AlreadyConnected));
        };
    } else if conn
        .scard::<_, u32>(format!("vc:{}", &user.id)) // check if the current vc set is empty
        .await
        .to_internal_error()?
        > 0
    {
        return Err(create_error!(AlreadyConnected));
    };

    Ok(())
}

/// LiveKit participant identities may be device-qualified
/// (`{user_id}:{device_id}`, media-E2EE plan Q4), but server-side voice
/// operations address participants by user id. voice-ingress records each
/// participant's full identity here (a hash per channel) so
/// `update_participant`/`remove_participant` can resolve the identity the
/// SFU actually knows. User ids are ULIDs and never contain `:`, so the
/// user id is always the segment before the first `:`.
///
/// The map is keyed per USER (not per device): this is correct because the
/// MLS delivery service enforces one device per user per call (plan §1.5),
/// so a user has at most one participant identity in a channel at a time.
/// Reconciling the map against the live SFU participant set (for the
/// Redis-eviction / missed-webhook case, where a stale/absent mapping makes
/// a kick target a bare id the SFU no longer knows) is the roster-
/// reconciliation work in 6.4; until then `get_voice_participant_identity`
/// logs when it falls back so a silently-missed moderation action is at
/// least visible in logs.
pub fn user_id_from_participant_identity(identity: &str) -> &str {
    identity
        .split(':')
        .next()
        .expect("split always yields at least one segment")
}

/// Record a participant's full LiveKit identity (voice-ingress, on join)
pub async fn set_voice_participant_identity(
    channel_id: &str,
    user_id: &str,
    identity: &str,
) -> Result<()> {
    get_connection()
        .await?
        .hset(format!("voice_identity:{channel_id}"), user_id, identity)
        .await
        .to_internal_error()
}

/// Resolve the LiveKit identity for a user in a channel; falls back to the
/// bare user id (web / pre-E2EE participants join with an unqualified
/// identity, and so do participants whose mapping is gone)
pub async fn get_voice_participant_identity(channel_id: &str, user_id: &str) -> Result<String> {
    let stored: Option<String> = get_connection()
        .await?
        .hget(format!("voice_identity:{channel_id}"), user_id)
        .await
        .to_internal_error()?;

    Ok(stored.unwrap_or_else(|| {
        // No recorded identity: fall back to the bare user id. This is
        // correct for non-E2EE participants (their SFU identity IS the bare
        // user id), but for a device-qualified participant whose mapping was
        // evicted/never-written it means a kick/permission update will match
        // no SFU participant and silently no-op — surface it (plan §1.5,
        // 6.4 roster reconciliation).
        log::debug!(
            "voice identity mapping missing for {user_id} in {channel_id}; using bare user id (moderation of a device-qualified participant may not apply)"
        );
        user_id.to_string()
    }))
}

/// Forget a participant's identity mapping (voice-ingress, on leave)
pub async fn delete_voice_participant_identity(channel_id: &str, user_id: &str) -> Result<()> {
    get_connection()
        .await?
        .hdel(format!("voice_identity:{channel_id}"), user_id)
        .await
        .to_internal_error()
}

/// Drop every identity mapping for a channel (voice-ingress, room_finished —
/// the backstop against mappings leaked by missed participant_left events)
pub async fn clear_voice_participant_identities(channel_id: &str) -> Result<()> {
    get_connection()
        .await?
        .del(format!("voice_identity:{channel_id}"))
        .await
        .to_internal_error()
}

pub async fn set_channel_node(channel_id: &str, node: &str) -> Result<()> {
    get_connection()
        .await?
        .set(format!("node:{channel_id}"), node)
        .await
        .to_internal_error()
}

pub async fn get_channel_node(channel_id: &str) -> Result<Option<String>> {
    get_connection()
        .await?
        .get(format!("node:{channel_id}"))
        .await
        .to_internal_error()
}

pub async fn delete_channel_node(channel_id: &str) -> Result<()> {
    get_connection()
        .await?
        .del(format!("node:{channel_id}"))
        .await
        .to_internal_error()
}

pub async fn get_user_voice_channels(user_id: &str) -> Result<Vec<UserVoiceChannel>> {
    get_connection()
        .await?
        .smembers(format!("vc:{user_id}"))
        .await
        .to_internal_error()
}

pub async fn set_user_moved_from_voice(
    old_channel_id: &str,
    new_channel: &UserVoiceChannel,
    user_id: &str,
) -> Result<()> {
    get_connection()
        .await?
        .set_ex(
            format!("moved_from:{user_id}:{old_channel_id}"),
            new_channel,
            10,
        )
        .await
        .to_internal_error()
}

pub async fn get_user_moved_from_voice(channel_id: &str, user_id: &str) -> Result<Option<String>> {
    get_connection()
        .await?
        .get_del(format!("moved_from:{user_id}:{channel_id}"))
        .await
        .to_internal_error()
}

pub async fn set_user_moved_to_voice(
    new_channel_id: &str,
    old_channel: &UserVoiceChannel,
    user_id: &str,
) -> Result<()> {
    get_connection()
        .await?
        .set_ex(
            format!("moved_to:{user_id}:{new_channel_id}"),
            old_channel,
            10,
        )
        .await
        .to_internal_error()
}

pub async fn get_user_moved_to_voice(
    channel_id: &str,
    user_id: &str,
) -> Result<Option<UserVoiceChannel>> {
    get_connection()
        .await?
        .get_del(format!("moved_to:{user_id}:{channel_id}"))
        .await
        .to_internal_error()
}

pub async fn is_in_voice_channel(user_id: &str, channel: &UserVoiceChannel) -> Result<bool> {
    get_connection()
        .await?
        .sismember(format!("vc:{user_id}"), channel)
        .await
        .to_internal_error()
}

pub async fn get_user_voice_channel_in_server(
    user_id: &str,
    server_id: &str,
) -> Result<Option<String>> {
    let mut conn = get_connection().await?;

    let unique_key = format!("{user_id}:{server_id}");

    conn.get(&unique_key).await.to_internal_error()
}

pub fn get_allowed_sources(
    limits: &FeaturesLimits,
    permissions: PermissionValue,
) -> Vec<TrackSource> {
    let mut allowed_sources = Vec::new();

    if permissions.has(ChannelPermission::Speak as u64) {
        allowed_sources.push(TrackSource::Microphone)
    };

    if permissions.has(ChannelPermission::Video as u64) && limits.video {
        allowed_sources.extend([
            TrackSource::Camera,
            TrackSource::ScreenShare,
            TrackSource::ScreenShareAudio,
        ]);
    };

    allowed_sources
}

/// The wire name a `TrackSource` takes in a join token's `canPublishSources`
/// claim — LiveKit's `sourceToString` (auth/grants.go), NOT `as_str_name`,
/// whose UPPER_CASE protobuf names the server won't match.
pub fn track_source_grant_name(source: TrackSource) -> &'static str {
    match source {
        TrackSource::Camera => "camera",
        TrackSource::Microphone => "microphone",
        TrackSource::ScreenShare => "screen_share",
        TrackSource::ScreenShareAudio => "screen_share_audio",
        TrackSource::Unknown => "unknown",
    }
}

pub async fn create_voice_state(
    channel: &UserVoiceChannel,
    user_id: &str,
    joined_at: Timestamp,
) -> Result<UserVoiceState> {
    let unique_key = format!(
        "{}:{}",
        &user_id,
        channel.server_id.as_ref().unwrap_or(&channel.id)
    );

    let voice_state = UserVoiceState {
        joined_at,
        id: user_id.to_string(),
        is_receiving: true,
        is_publishing: false,
        screensharing: false,
        camera: false,
        screen_video: false,
    };

    Pipeline::new()
        .sadd(format!("vc_members:{}", &channel.id), user_id)
        .sadd(format!("vc:{user_id}"), channel)
        .set(&unique_key, &channel.id)
        .set(
            format!("joined_at:{unique_key}"),
            joined_at
                .duration_since(Timestamp::UNIX_EPOCH)
                .whole_milliseconds() as i64,
        )
        .set(
            format!("is_publishing:{unique_key}"),
            voice_state.is_publishing,
        )
        .set(
            format!("is_receiving:{unique_key}"),
            voice_state.is_receiving,
        )
        .set(
            format!("screensharing:{unique_key}"),
            voice_state.screensharing,
        )
        .set(format!("camera:{unique_key}"), voice_state.camera)
        .set(
            format!("screen_video:{unique_key}"),
            voice_state.screen_video,
        )
        .query_async::<_, ()>(&mut get_connection().await?.into_inner())
        .await
        .to_internal_error()?;

    Ok(voice_state)
}

pub async fn delete_voice_state(channel: &UserVoiceChannel, user_id: &str) -> Result<()> {
    let unique_key = format!(
        "{}:{}",
        &user_id,
        channel.server_id.as_ref().unwrap_or(&channel.id)
    );

    Pipeline::new()
        .srem(format!("vc_members:{}", &channel.id), user_id)
        .srem(format!("vc:{user_id}"), channel)
        .del(&[
            format!("joined_at:{unique_key}"),
            format!("is_publishing:{unique_key}"),
            format!("is_receiving:{unique_key}"),
            format!("screensharing:{unique_key}"),
            format!("camera:{unique_key}"),
            format!("screen_video:{unique_key}"),
            unique_key.clone(),
        ])
        .query_async(&mut get_connection().await?.into_inner())
        .await
        .to_internal_error()
}

pub async fn delete_channel_voice_state(
    channel: &UserVoiceChannel,
    user_ids: &[String],
) -> Result<()> {
    let parent_id = channel.server_id.as_ref().unwrap_or(&channel.id);

    let mut pipeline = Pipeline::new();
    pipeline.del(format!("vc_members:{}", &channel.id));
    pipeline.del(format!("node:{}", &channel.id));

    for user_id in user_ids {
        let unique_key = format!("{user_id}:{parent_id}");

        pipeline.srem(format!("vc:{user_id}"), channel).del(&[
            format!("joined_at:{unique_key}"),
            format!("is_publishing:{unique_key}"),
            format!("is_receiving:{unique_key}"),
            format!("screensharing:{unique_key}"),
            format!("camera:{unique_key}"),
            format!("screen_video:{unique_key}"),
            unique_key.clone(),
        ]);
    }

    pipeline
        .query_async(&mut get_connection().await?.into_inner())
        .await
        .to_internal_error()
}

pub async fn update_voice_state_tracks(
    channel: &UserVoiceChannel,
    user_id: &str,
    added: bool,
    track: i32,
) -> Result<PartialUserVoiceState> {
    let partial = match track {
        /* TrackSource::Unknown */ 0 => PartialUserVoiceState::default(),
        /* TrackSource::Camera */
        1 => PartialUserVoiceState {
            camera: Some(added),
            ..Default::default()
        },
        /* TrackSource::Microphone */
        2 => PartialUserVoiceState {
            is_publishing: Some(added),
            ..Default::default()
        },
        // `screensharing` keeps its historical conflated meaning (either
        // screen track flips it), so existing consumers see no change. The
        // additive `screen_video` flag tracks source 3 ONLY: without it, a
        // screen-audio unmute after the video track ended reads as "still
        // screensharing" with nothing to see, and stopping only screen audio
        // flips the flag false mid-share (remote-control plan §1 blocker).
        /* TrackSource::ScreenShare */
        3 => PartialUserVoiceState {
            screensharing: Some(added),
            screen_video: Some(added),
            ..Default::default()
        },
        /* TrackSource::ScreenShareAudio */
        4 => PartialUserVoiceState {
            screensharing: Some(added),
            ..Default::default()
        },
        _ => unreachable!(),
    };

    update_voice_state(channel, user_id, &partial).await?;

    Ok(partial)
}

pub async fn update_voice_state(
    channel: &UserVoiceChannel,
    user_id: &str,
    partial: &PartialUserVoiceState,
) -> Result<()> {
    let unique_key = format!(
        "{}:{}",
        &user_id,
        channel.server_id.as_ref().unwrap_or(&channel.id)
    );

    let mut pipeline = Pipeline::new();

    if let Some(camera) = &partial.camera {
        pipeline.set(format!("camera:{unique_key}"), camera);
    };

    if let Some(is_publishing) = &partial.is_publishing {
        pipeline.set(format!("is_publishing:{unique_key}"), is_publishing);
    }

    if let Some(is_receiving) = &partial.is_receiving {
        pipeline.set(format!("is_receiving:{unique_key}"), is_receiving);
    }

    if let Some(screensharing) = &partial.screensharing {
        pipeline.set(format!("screensharing:{unique_key}"), screensharing);
    }

    if let Some(screen_video) = &partial.screen_video {
        pipeline.set(format!("screen_video:{unique_key}"), screen_video);
    }

    pipeline
        .query_async(&mut get_connection().await?.into_inner())
        .await
        .to_internal_error()
}

pub async fn get_voice_channel_members(channel: &UserVoiceChannel) -> Result<Option<Vec<String>>> {
    get_connection()
        .await?
        .smembers::<_, Option<Vec<String>>>(format!("vc_members:{}", &channel.id))
        .await
        .to_internal_error()
        .map(|opt| opt.and_then(|v| if v.is_empty() { None } else { Some(v) }))
}

pub async fn get_voice_state(
    channel: &UserVoiceChannel,
    user_id: &str,
) -> Result<Option<UserVoiceState>> {
    let unique_key = format!(
        "{}:{}",
        &user_id,
        channel.server_id.as_ref().unwrap_or(&channel.id)
    );

    let (joined_at, is_publishing, is_receiving, screensharing, camera, screen_video): (
        Option<i64>,
        Option<bool>,
        Option<bool>,
        Option<bool>,
        Option<bool>,
        Option<bool>,
    ) = get_connection()
        .await?
        .mget(&[
            format!("joined_at:{unique_key}"),
            format!("is_publishing:{unique_key}"),
            format!("is_receiving:{unique_key}"),
            format!("screensharing:{unique_key}"),
            format!("camera:{unique_key}"),
            format!("screen_video:{unique_key}"),
        ])
        .await
        .to_internal_error()?;

    match (
        joined_at,
        is_publishing,
        is_receiving,
        screensharing,
        camera,
    ) {
        (
            Some(joined_at),
            Some(is_publishing),
            Some(is_receiving),
            Some(screensharing),
            Some(camera),
        ) => Ok(Some(v0::UserVoiceState {
            joined_at: Timestamp::UNIX_EPOCH
                .checked_add(Duration::milliseconds(joined_at))
                .unwrap(),
            id: user_id.to_string(),
            is_receiving,
            is_publishing,
            screensharing,
            camera,
            // States created before this key existed lack it; a missing key
            // must NOT invalidate the whole state (get_channel_voice_state
            // deletes states it cannot read), so it defaults false rather
            // than joining the required tuple above.
            screen_video: screen_video.unwrap_or(false),
        })),
        _ => Ok(None),
    }
}

pub async fn get_channel_voice_state(
    channel: &UserVoiceChannel,
) -> Result<Option<v0::ChannelVoiceState>> {
    let members = get_voice_channel_members(channel).await?;

    if let Some(members) = members {
        let mut participants = Vec::with_capacity(members.len());

        for user_id in members {
            if let Some(voice_state) = get_voice_state(channel, &user_id).await? {
                participants.push(voice_state);
            } else {
                log::info!("Voice state not found but member in voice channel members, removing.");

                delete_voice_state(channel, &user_id).await?;
            }
        }

        // In case a user voice state failed to be fetched, the vec's capacity will be larger than the length, shrink it
        participants.shrink_to_fit();

        Ok(Some(v0::ChannelVoiceState {
            id: channel.id.clone(),
            participants,
        }))
    } else {
        Ok(None)
    }
}

pub async fn move_user(user: &str, from_channel_id: &str, to_channel_id: &str) -> Result<()> {
    get_connection()
        .await?
        .smove(
            format!("vc_members:{from_channel_id}"),
            format!("vc_members:{to_channel_id}"),
            user,
        )
        .await
        .to_internal_error()
}

pub async fn sync_voice_permissions(
    db: &Database,
    voice_client: &VoiceClient,
    channel: &Channel,
    server: Option<&Server>,
    role_id: Option<&str>,
) -> Result<()> {
    let user_voice_channel = UserVoiceChannel::from_channel(channel);

    let Some(node) = get_channel_node(channel.id()).await? else {
        return Ok(());
    };

    for user_id in get_voice_channel_members(&user_voice_channel)
        .await?
        .iter()
        .flatten()
    {
        let user = Reference::from_unchecked(user_id).as_user(db).await?;

        sync_user_voice_permissions(db, voice_client, &node, &user, channel, server, role_id)
            .await?;
    }

    Ok(())
}

/// The LiveKit participant permissions a channel-permission sync grants.
///
/// Data publishing stays revoked UNCONDITIONALLY: the join token grants
/// `can_publish_data: false` (voice_client.rs) and the LiveKit data channel
/// is an untrusted injection surface for E2EE call machinery (media-E2EE
/// plan §0.4) — a permission sync must never silently re-grant it. This
/// previously re-granted `can_speak` on every sync.
///
/// `can_publish_sources` must carry the SAME source list the join token
/// computes (`get_allowed_sources`): LiveKit treats an EMPTY list as "no
/// restriction" (`VideoGrant.GetCanPublishSource`, auth/grants.go), and
/// `UpdateFromPermission` replaces the whole grant — so the previous
/// `..Default::default()` empty vec silently re-granted camera and
/// screenshare to Video-less members on every sync. For the same reason an
/// empty list may only ever be sent alongside `can_publish: false`.
pub fn voice_participant_permissions(
    can_listen: bool,
    allowed_sources: &[TrackSource],
) -> ParticipantPermission {
    ParticipantPermission {
        can_subscribe: can_listen,
        can_publish: !allowed_sources.is_empty(),
        can_publish_data: false,
        can_publish_sources: allowed_sources.iter().map(|s| *s as i32).collect(),
        ..Default::default()
    }
}

/// The ONE sanctioned exception to the rule above: the permission set a
/// remote-control grant pushes for the CONTROLLER identity (remote-control
/// plan §0.3(A)) — the full recomputed set with only `can_publish_data`
/// flipped. `UpdateParticipantOptions` replaces the entire
/// `ParticipantPermission` message, so building this from
/// `..Default::default()` instead would mute and deafen the controller the
/// instant they are granted control.
///
/// Scope caveat (plan §0.3/H-2): the SFU grant is per-IDENTITY, not
/// per-topic — the granted participant can publish on ANY data topic,
/// including "captions". That is why the offer route hard-rejects
/// `target == caller` (a self-offer would be a self-service grant) and why
/// every teardown path must actively revoke.
pub fn remote_control_participant_permissions(
    can_listen: bool,
    allowed_sources: &[TrackSource],
) -> ParticipantPermission {
    ParticipantPermission {
        can_publish_data: true,
        ..voice_participant_permissions(can_listen, allowed_sources)
    }
}

#[cfg(test)]
mod permission_tests {
    use livekit_protocol::TrackSource;
    use revolt_config::FeaturesLimits;
    use revolt_permissions::{ChannelPermission, PermissionValue};

    use super::{
        get_allowed_sources, user_id_from_participant_identity, voice_participant_permissions,
    };

    fn limits_with_video(video: bool) -> FeaturesLimits {
        FeaturesLimits {
            outgoing_friend_requests: 0,
            bots: 0,
            message_length: 0,
            message_attachments: 0,
            servers: 0,
            voice_quality: 0,
            video,
            video_resolution: [0, 0],
            video_aspect_ratio: [0.0, 0.0],
            file_upload_size_limit: Default::default(),
        }
    }

    #[test]
    fn participant_identity_parse_recovers_user_id() {
        // ULIDs contain no ':', so the user id is the first segment for
        // both bare and device-qualified identities (media-E2EE plan Q4)
        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let device = "4208aa7e9ff58761b2d7a5d6c45f7383";

        assert_eq!(user_id_from_participant_identity(user), user);
        assert_eq!(
            user_id_from_participant_identity(&format!("{user}:{device}")),
            user
        );
    }

    #[test]
    fn remote_control_grant_carries_full_set_and_flips_only_data() {
        use super::remote_control_participant_permissions;

        // UpdateParticipantOptions replaces the WHOLE ParticipantPermission
        // message: the grant path must differ from the sync path in exactly
        // one field, or the controller goes mute/deaf on grant.
        for can_listen in [false, true] {
            for sources in [
                &[][..],
                &[TrackSource::Microphone][..],
                &[
                    TrackSource::Microphone,
                    TrackSource::Camera,
                    TrackSource::ScreenShare,
                    TrackSource::ScreenShareAudio,
                ][..],
            ] {
                let granted = remote_control_participant_permissions(can_listen, sources);
                let baseline = voice_participant_permissions(can_listen, sources);

                assert!(granted.can_publish_data);
                assert_eq!(
                    livekit_protocol::ParticipantPermission {
                        can_publish_data: false,
                        ..granted
                    },
                    baseline,
                    "the grant may differ from the sync baseline ONLY in can_publish_data"
                );
            }
        }
    }

    #[test]
    fn permission_sync_never_regrants_data_publishing() {
        for can_listen in [false, true] {
            for sources in [&[][..], &[TrackSource::Microphone][..]] {
                let permissions = voice_participant_permissions(can_listen, sources);
                assert!(
                    !permissions.can_publish_data,
                    "data publishing must stay revoked (media-E2EE plan §0.4)"
                );
                assert_eq!(permissions.can_subscribe, can_listen);
                assert_eq!(permissions.can_publish, !sources.is_empty());
            }
        }
    }

    #[test]
    fn permission_sync_never_regrants_video_publishing() {
        for can_speak in [false, true] {
            for has_video_permission in [false, true] {
                for video_limit in [false, true] {
                    let mut bits = ChannelPermission::Listen as u64;
                    if can_speak {
                        bits |= ChannelPermission::Speak as u64;
                    }
                    if has_video_permission {
                        bits |= ChannelPermission::Video as u64;
                    }

                    let sources = get_allowed_sources(
                        &limits_with_video(video_limit),
                        PermissionValue::from_raw(bits),
                    );
                    let permissions = voice_participant_permissions(true, &sources);

                    let can_video = has_video_permission && video_limit;
                    for video_source in [
                        TrackSource::Camera,
                        TrackSource::ScreenShare,
                        TrackSource::ScreenShareAudio,
                    ] {
                        assert_eq!(
                            permissions
                                .can_publish_sources
                                .contains(&(video_source as i32)),
                            can_video,
                            "sync must grant {video_source:?} iff Video permission + limit \
                             (speak={can_speak}, video_perm={has_video_permission}, limit={video_limit})"
                        );
                    }
                    assert_eq!(
                        permissions
                            .can_publish_sources
                            .contains(&(TrackSource::Microphone as i32)),
                        can_speak
                    );

                    // LiveKit reads an empty can_publish_sources as "no
                    // restriction", so an empty list may only ever ship
                    // behind can_publish: false
                    assert_eq!(permissions.can_publish, !sources.is_empty());
                    if permissions.can_publish_sources.is_empty() {
                        assert!(!permissions.can_publish);
                    }
                }
            }
        }
    }
}

pub async fn sync_user_voice_permissions(
    db: &Database,
    voice_client: &VoiceClient,
    node: &str,
    user: &User,
    channel: &Channel,
    server: Option<&Server>,
    role_id: Option<&str>,
) -> Result<()> {
    let channel_id = channel.id();
    let server_id = server.as_ref().map(|s| s.id.as_str());

    let member = match server_id {
        Some(server_id) => Some(
            Reference::from_unchecked(&user.id)
                .as_member(db, server_id)
                .await?,
        ),
        None => None,
    };

    if role_id.is_none_or(|role_id| {
        member
            .as_ref()
            .is_none_or(|member| member.roles.iter().any(|r| r == role_id))
    }) {
        let user_voice_channel = UserVoiceChannel::from_channel(channel);

        let Some(voice_state) = get_voice_state(&user_voice_channel, &user.id).await? else {
            return Ok(());
        };

        let mut query = DatabasePermissionQuery::new(db, user)
            .channel(channel)
            .user(user);

        if let (Some(server), Some(member)) = (server, member.as_ref()) {
            query = query.member(member).server(server)
        }

        let permissions = calculate_channel_permissions(&mut query).await;
        let limits = user.limits().await;

        let mut update_event = PartialUserVoiceState {
            id: Some(user.id.clone()),
            ..Default::default()
        };

        let before = update_event.clone();

        let can_video =
            limits.video && permissions.has_channel_permission(ChannelPermission::Video);
        let can_speak = permissions.has_channel_permission(ChannelPermission::Speak);
        let can_listen = permissions.has_channel_permission(ChannelPermission::Listen);
        let allowed_sources = get_allowed_sources(&limits, permissions);

        update_event.camera = voice_state.camera.then_some(can_video);
        update_event.screensharing = voice_state.screensharing.then_some(can_video);
        update_event.screen_video = voice_state.screen_video.then_some(can_video);
        update_event.is_publishing = voice_state.is_publishing.then_some(can_speak);

        update_voice_state(&user_voice_channel, &user.id, &update_event).await?;

        voice_client
            .update_permissions(
                node,
                user,
                channel_id,
                voice_participant_permissions(can_listen, &allowed_sources),
            )
            .await?;

        // Remote-control sync-teardown hook (plan §1): the push above sends
        // `can_publish_data: false` unconditionally, so if this user is the
        // CONTROLLER of an active grant their SFU capability was just
        // killed — and if they are the SHARER, their eligibility may have
        // changed. Either way Redis must not keep reading "active" while
        // the capability is gone or suspect (the sharer's indicator would
        // lie about who has access to their machine): tear the grant down
        // and tell the channel. Server-asserted state may only ever REVOKE
        // a session, never sustain one, so tearing down on every
        // permission-affecting sync is the safe direction by design.
        remote_control::release_remote_control_for_user(
            db,
            voice_client,
            &user_voice_channel,
            &user.id,
            "permissions_changed",
            false,
        )
        .await;

        if update_event != before {
            EventV1::UserVoiceStateUpdate {
                id: user.id.clone(),
                channel_id: channel_id.to_string(),
                data: update_event,
            }
            .p(channel_id.to_string())
            .await;
        };
    };

    Ok(())
}

pub async fn set_channel_call_started_system_message(
    channel_id: &str,
    message_id: &str,
) -> Result<()> {
    get_connection()
        .await?
        .set(format!("call_started_message:{channel_id}"), message_id)
        .await
        .to_internal_error()
}

pub async fn take_channel_call_started_system_message(channel_id: &str) -> Result<Option<String>> {
    get_connection()
        .await?
        .get_del(format!("call_started_message:{channel_id}"))
        .await
        .to_internal_error()
}

pub async fn set_call_notification_recipients(
    channel_id: &str,
    user_id: &str,
    recipients: &[String],
) -> Result<()> {
    get_connection()
        .await?
        .set_ex(
            format!("call_notification_recipients:{channel_id}-{user_id}"),
            recipients,
            10,
        )
        .await
        .to_internal_error()
}

pub async fn get_call_notification_recipients(
    channel_id: &str,
    user_id: &str,
) -> Result<Option<Vec<String>>> {
    get_connection()
        .await?
        .get_del(format!(
            "call_notification_recipients:{channel_id}-{user_id}"
        ))
        .await
        .to_internal_error()
}

pub async fn remove_user_from_voice_channels(
    db: &Database,
    voice_client: &VoiceClient,
    user_id: &str,
) -> Result<()> {
    for channel in get_user_voice_channels(user_id).await? {
        remove_user_from_voice_channel(db, voice_client, &channel, user_id).await?;
    }

    Ok(())
}

pub async fn remove_user_from_voice_channel(
    db: &Database,
    voice_client: &VoiceClient,
    channel: &UserVoiceChannel,
    user_id: &str,
) -> Result<()> {
    // Remote-control release hook (plan §1): these admin paths remove the
    // participant INSIDE delta and would race a webhook-only hook, so any
    // grant involving this user is ended here, before the removal.
    //
    // `false`: the removal below is best-effort (its error is discarded,
    // it is skipped entirely when the channel has no node, and the
    // identity it resolves can silently no-op for a device-qualified
    // participant). Assuming it works and merely deleting the records
    // would be how a `can_publish_data` capability outlives everything
    // able to revoke it — so the capability is actively revoked first.
    remote_control::release_remote_control_for_user(
        db,
        voice_client,
        channel,
        user_id,
        "participant_left",
        false,
    )
    .await;

    if let Some(node) = get_channel_node(&channel.id).await? {
        let _ = voice_client.remove_user(&node, user_id, &channel.id).await;
    }

    delete_voice_state(channel, user_id).await?;

    Ok(())
}

pub async fn delete_voice_channel(
    db: &Database,
    voice_client: &VoiceClient,
    channel: &UserVoiceChannel,
) -> Result<()> {
    if let Some(users) = get_voice_channel_members(channel).await? {
        // The whole room is going away — end every grant in it first. The
        // room still EXISTS at this point and `delete_room` below can
        // fail, so the capabilities are actively revoked rather than
        // assumed moot: "the room is about to go" is not the same as "the
        // room is gone".
        remote_control::release_remote_control_for_channel(
            db,
            voice_client,
            &channel.id,
            "call_ended",
            true,
        )
        .await;

        let node = get_channel_node(&channel.id).await?.unwrap();
        voice_client.delete_room(&node, &channel.id).await?;

        delete_channel_voice_state(channel, &users).await?;
    };

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomMetadata {
    pub server: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserVoiceChannel {
    pub id: String,
    pub server_id: Option<String>,
}

impl UserVoiceChannel {
    pub fn from_string(input: String) -> Self {
        let mut parts = input.splitn(2, '-');

        Self {
            id: parts.next().unwrap().to_string(),
            server_id: parts.next().map(ToString::to_string),
        }
    }

    pub fn from_channel(channel: &Channel) -> Self {
        Self {
            id: channel.id().to_string(),
            server_id: channel.server().map(ToString::to_string),
        }
    }
}

impl Display for UserVoiceChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.id)?;

        if let Some(server_id) = &self.server_id {
            f.write_char('-')?;
            f.write_str(server_id)?
        };

        Ok(())
    }
}

impl ToRedisArgs for UserVoiceChannel {
    fn write_redis_args<W: ?Sized + RedisWrite>(&self, out: &mut W) {
        out.write_arg_fmt(self);
    }
}

impl FromRedisValue for UserVoiceChannel {
    fn from_redis_value(v: &Value) -> Result<Self, RedisError> {
        String::from_redis_value(v).map(UserVoiceChannel::from_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iso8601_timestamp::Timestamp;

    /// One runtime shared by every Redis-backed test in this module.
    /// `redis_kiss` pools connections in a GLOBAL mobc pool, but each
    /// `#[tokio::test]` spins up its own runtime — a connection created on
    /// test A's runtime goes back to the pool when A finishes, its I/O
    /// registration dies with A's runtime, and test B then draws a dead
    /// connection (intermittent `InternalError` from any mget). Driving all
    /// Redis tests on one process-lifetime runtime removes that failure mode.
    fn rt() -> &'static tokio::runtime::Runtime {
        static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap()
        })
    }

    // Redis-backed (mirrors the mls delta-test pattern, which also drives live
    // Redis voice state). Verifies count_video_participants over the ACTUAL key
    // composition — including the SERVER voice channel case (server_id present),
    // where the per-member flags key by server id, not channel id (audit
    // ME-MED-2: composing `{user}:{channel_id}` there would miss every flag and
    // read 0, failing the D12 cap OPEN).
    #[test]
    fn count_video_participants_counts_camera_or_screenshare_on_server_channel() {
        rt().block_on(count_video_participants_case())
    }

    async fn count_video_participants_case() {
        // Unique ids so parallel test runs don't collide on shared Redis.
        let suffix = ulid::Ulid::new().to_string();
        let channel = UserVoiceChannel {
            id: format!("chan{suffix}"),
            server_id: Some(format!("srv{suffix}")), // server channel: flags key by server id
        };
        let users: Vec<String> = (0..4).map(|i| format!("user{i}{suffix}")).collect();

        // Clean seed.
        for user in &users {
            create_voice_state(&channel, user, Timestamp::now_utc())
                .await
                .expect("seed voice state");
        }

        // No video yet ⇒ 0.
        assert_eq!(count_video_participants(&channel).await.unwrap(), 0);

        // user0 turns on camera (track 1); user1 turns on screenshare (track 3);
        // user2 turns on the mic only (track 2 = is_publishing, NOT video);
        // user3 stays idle.
        update_voice_state_tracks(&channel, &users[0], true, 1)
            .await
            .unwrap();
        update_voice_state_tracks(&channel, &users[1], true, 3)
            .await
            .unwrap();
        update_voice_state_tracks(&channel, &users[2], true, 2)
            .await
            .unwrap();

        // Exactly the two video publishers count.
        assert_eq!(count_video_participants(&channel).await.unwrap(), 2);

        // user0 turns camera back off ⇒ back to 1.
        update_voice_state_tracks(&channel, &users[0], false, 1)
            .await
            .unwrap();
        assert_eq!(count_video_participants(&channel).await.unwrap(), 1);

        // Cleanup.
        delete_channel_voice_state(&channel, &users)
            .await
            .expect("cleanup");
        assert_eq!(count_video_participants(&channel).await.unwrap(), 0);
    }

    // The remote-control plan §1 blocker sequence: `screensharing` conflates
    // screen VIDEO (source 3) with screen AUDIO (source 4), so after the video
    // track ends, a routine screen-audio unmute reads as "screensharing" with
    // nothing published to look at. `screen_video` must track source 3 only —
    // in BOTH directions (audio-only events never set OR clear it).
    #[test]
    fn screen_video_tracks_video_source_only() {
        rt().block_on(screen_video_case())
    }

    async fn screen_video_case() {
        let suffix = ulid::Ulid::new().to_string();
        let channel = UserVoiceChannel {
            id: format!("chan{suffix}"),
            server_id: Some(format!("srv{suffix}")),
        };
        let user = format!("user{suffix}");

        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .expect("seed voice state");

        let state = get_voice_state(&channel, &user).await.unwrap().unwrap();
        assert!(!state.screensharing);
        assert!(!state.screen_video);

        // Share screen with audio: both tracks publish.
        update_voice_state_tracks(&channel, &user, true, 3)
            .await
            .unwrap();
        update_voice_state_tracks(&channel, &user, true, 4)
            .await
            .unwrap();
        let state = get_voice_state(&channel, &user).await.unwrap().unwrap();
        assert!(state.screensharing);
        assert!(state.screen_video);

        // The screen VIDEO track ends...
        update_voice_state_tracks(&channel, &user, false, 3)
            .await
            .unwrap();
        // ...then the screen AUDIO track unmutes, which LiveKit does
        // routinely. The conflated flag reads true again — no video is live.
        update_voice_state_tracks(&channel, &user, true, 4)
            .await
            .unwrap();
        let state = get_voice_state(&channel, &user).await.unwrap().unwrap();
        assert!(state.screensharing, "historical conflated flag: unchanged");
        assert!(
            !state.screen_video,
            "audio unmute must not resurrect the video flag"
        );

        // Inverse leg: with a healthy video+audio share, stopping ONLY the
        // screen audio flips the conflated flag false; the video flag must
        // keep reporting the still-live video track.
        update_voice_state_tracks(&channel, &user, true, 3)
            .await
            .unwrap();
        update_voice_state_tracks(&channel, &user, false, 4)
            .await
            .unwrap();
        let state = get_voice_state(&channel, &user).await.unwrap().unwrap();
        assert!(!state.screensharing, "historical conflated flag: unchanged");
        assert!(
            state.screen_video,
            "stopping screen audio must not clear the video flag"
        );

        // Back-compat: a voice state created before the key existed (delete
        // it to simulate) still hydrates, with screen_video defaulting false
        // rather than invalidating the whole state.
        let unique_key = format!("{user}:srv{suffix}");
        get_connection()
            .await
            .unwrap()
            .del::<_, ()>(format!("screen_video:{unique_key}"))
            .await
            .unwrap();
        let state = get_voice_state(&channel, &user)
            .await
            .unwrap()
            .expect("missing screen_video key must not invalidate the state");
        assert!(!state.screen_video);

        delete_voice_state(&channel, &user).await.expect("cleanup");
        assert!(get_voice_state(&channel, &user).await.unwrap().is_none());
    }
}
